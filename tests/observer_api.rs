//! Observer API integration tests.
//!
//! A recording `EngineObserver` is installed through `Engine::builder` and the
//! tests assert the events the engine reports for static rules (slow and
//! fast path), response cache hits and misses (fresh and stale), rule cache
//! lookups and replays, rule evaluation and decisions, upstream attempts,
//! shared in-flight queries, cancelled requests and configuration reloads.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use kixdns::config::{Transport, parse_config};
use kixdns::doh_server::{DohCertificate, run_doh};
use kixdns::engine::{Engine, FastPathResponse, UnreadableQuery};
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::observe::{
    CacheHit, CacheHitKind, ClientTransport, ConfigLoaded, ConfigReloadFailed, DecisionDetail,
    DecisionKind, DecisionMade, EngineObserver, RequestContext, RequestOutcome, RequestStatus,
    RuleAnswer, RuleCacheLookup, RuleEvaluated, RuleMatched, RulePhase, UpstreamAttempt,
    UpstreamOutcome, UpstreamResult,
};

#[ctor::ctor]
fn init() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// ============================================================================
// Recording observer / 记录型观察者
// ============================================================================

/// Owned copy of a `DecisionDetail`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Detail {
    Static {
        rcode: ResponseCode,
        answers: usize,
    },
    Forward {
        upstream: String,
        transport: Option<Transport>,
    },
    Jump {
        pipeline: String,
    },
}

impl From<DecisionDetail<'_>> for Detail {
    fn from(detail: DecisionDetail<'_>) -> Self {
        match detail {
            DecisionDetail::Static { rcode, answers } => Detail::Static { rcode, answers },
            DecisionDetail::Forward {
                upstream,
                transport,
            } => Detail::Forward {
                upstream: upstream.to_string(),
                transport,
            },
            DecisionDetail::Jump { pipeline } => Detail::Jump {
                pipeline: pipeline.to_string(),
            },
            _ => unreachable!("unknown decision detail"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Started {
        id: u64,
        qname: String,
        listener: String,
        client: SocketAddr,
        transport: Option<ClientTransport>,
        background: bool,
    },
    Finished {
        id: u64,
        status: RequestStatus,
    },
    Pipeline {
        id: u64,
        pipeline: String,
    },
    RuleCacheLookup {
        id: u64,
        pipeline: String,
        hit: bool,
        matched_rules: usize,
    },
    RuleEvaluated {
        id: u64,
        pipeline: String,
        rule: String,
        phase: RulePhase,
        matched: bool,
        matchers: usize,
    },
    Rule {
        id: u64,
        pipeline: String,
        rule: String,
        phase: RulePhase,
        decision: DecisionKind,
        fast_path: bool,
    },
    Decision {
        id: u64,
        pipeline: String,
        rule: Option<String>,
        phase: RulePhase,
        detail: Detail,
    },
    CacheLookup {
        id: u64,
    },
    CacheHit {
        id: u64,
        kind: CacheHitKind,
        has_remaining_ttl: bool,
        original_ttl: Option<Duration>,
    },
    CacheMiss {
        id: u64,
    },
    InflightJoined {
        id: u64,
    },
    UpstreamAttempt {
        id: u64,
        upstream: String,
        transport: Transport,
    },
    UpstreamResult {
        id: u64,
        upstream: String,
        transport: Transport,
        via: Transport,
        outcome: UpstreamOutcome,
        rcode: Option<ResponseCode>,
        truncated: Option<bool>,
        has_error: bool,
    },
    ConfigLoaded {
        generation: u64,
        path: Option<PathBuf>,
        source: Option<String>,
    },
    ConfigReloadFailed {
        path: PathBuf,
        error: String,
    },
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
    /// `request_finished` payloads, kept apart from `events` so the lifecycle
    /// sequences asserted elsewhere stay unchanged.
    /// request_finished 的载荷，与 events 分开记录，其他用例断言的生命周期序列保持不变。
    outcomes: Mutex<Vec<Outcome>>,
    /// `CacheHit::source` per request, kept apart for the same reason.
    /// 每个请求的 CacheHit::source，同样分开记录。
    cache_sources: Mutex<Vec<(u64, Option<String>)>>,
}

#[derive(Debug, Clone, PartialEq)]
struct Outcome {
    id: u64,
    status: RequestStatus,
    response: Option<Vec<u8>>,
    error: Option<String>,
}

impl Recorder {
    fn push(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    fn outcome(&self, id: u64) -> Outcome {
        let outcomes = self.outcomes.lock().unwrap();
        outcomes
            .iter()
            .find(|outcome| outcome.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("no request_finished for {id}: {outcomes:#?}"))
    }

    fn cache_sources(&self) -> Vec<(u64, Option<String>)> {
        self.cache_sources.lock().unwrap().clone()
    }

    /// Remove and return everything recorded so far.
    fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    /// Poll until `predicate` holds for the recorded events or `timeout` elapses.
    async fn wait_for(&self, timeout: Duration, predicate: impl Fn(&[Event]) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if predicate(&self.events()) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl EngineObserver for Recorder {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        self.push(Event::Started {
            id: ctx.request_id,
            qname: ctx.qname.to_string(),
            listener: ctx.listener_label.to_string(),
            client: ctx.client,
            transport: ctx.transport,
            background: ctx.background_refresh,
        });
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome<'_>) {
        self.push(Event::Finished {
            id: ctx.request_id,
            status: outcome.status,
        });
        self.outcomes.lock().unwrap().push(Outcome {
            id: ctx.request_id,
            status: outcome.status,
            response: outcome.response.map(<[u8]>::to_vec),
            error: outcome.error.map(str::to_string),
        });
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        self.push(Event::Pipeline {
            id: ctx.request_id,
            pipeline: pipeline.to_string(),
        });
    }

    fn rule_cache_lookup(&self, ctx: &RequestContext<'_>, event: &RuleCacheLookup<'_>) {
        self.push(Event::RuleCacheLookup {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            hit: event.hit,
            matched_rules: event.matched_rules,
        });
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        self.push(Event::RuleEvaluated {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.to_string(),
            phase: event.phase,
            matched: event.matched,
            matchers: event.matchers,
        });
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        self.push(Event::Rule {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.to_string(),
            phase: event.phase,
            decision: event.decision,
            fast_path: event.fast_path,
        });
    }

    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        self.push(Event::Decision {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.map(str::to_string),
            phase: event.phase,
            detail: event.detail.into(),
        });
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        self.push(Event::CacheLookup { id: ctx.request_id });
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
        self.cache_sources
            .lock()
            .unwrap()
            .push((ctx.request_id, event.source.map(str::to_string)));
        self.push(Event::CacheHit {
            id: ctx.request_id,
            kind: event.kind,
            has_remaining_ttl: event.remaining_ttl.is_some(),
            original_ttl: event.original_ttl,
        });
    }

    fn cache_miss(&self, ctx: &RequestContext<'_>) {
        self.push(Event::CacheMiss { id: ctx.request_id });
    }

    fn inflight_joined(&self, ctx: &RequestContext<'_>) {
        self.push(Event::InflightJoined { id: ctx.request_id });
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        self.push(Event::UpstreamAttempt {
            id: ctx.request_id,
            upstream: event.upstream.to_string(),
            transport: event.transport,
        });
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        self.push(Event::UpstreamResult {
            id: ctx.request_id,
            upstream: event.upstream.to_string(),
            transport: event.transport,
            via: event.via,
            outcome: event.outcome,
            rcode: event.rcode,
            truncated: event.truncated,
            has_error: event.error.is_some(),
        });
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        self.push(Event::ConfigLoaded {
            generation: event.generation,
            path: event.path.map(Path::to_path_buf),
            source: event.source.map(str::to_string),
        });
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        self.push(Event::ConfigReloadFailed {
            path: event.path.to_path_buf(),
            error: event.error.to_string(),
        });
    }
}

// ============================================================================
// Helpers / 辅助函数
// ============================================================================

const PEER: &str = "127.0.0.1:53000";

fn peer() -> SocketAddr {
    PEER.parse().unwrap()
}

fn runtime_config(raw: &str) -> RuntimePipelineConfig {
    RuntimePipelineConfig::from_config(parse_config(raw).expect("parse config"))
        .expect("compile config")
}

fn observed_engine(raw: &str) -> (Engine, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(runtime_config(raw))
        .listener_label("edge")
        .observer(recorder.clone())
        .build()
        .expect("build engine");
    (engine, recorder)
}

fn query(qname: &str) -> Vec<u8> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(qname).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

/// 换一种问法：名字照原样写（`Name::from_str` 会转成小写），带 EDNS，DO 位为 `dnssec_ok`
/// Asked another way: the name written as given (`Name::from_str` would lowercase it),
/// with EDNS and the DO bit `dnssec_ok`
fn query_asked_otherwise(qname: &str, dnssec_ok: bool) -> Vec<u8> {
    let mut message = Message::new(0x4321, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(qname).unwrap(),
        RecordType::A,
    ));
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    message.to_vec().unwrap()
}

/// 应答的问题名（照写法）和 DO 位（没有 OPT 时为 None）/ A reply's question name, as
/// written, and its DO bit (None without an OPT)
fn asked_as(bytes: &[u8]) -> (String, Option<bool>) {
    let message = Message::from_bytes(bytes).unwrap();
    (
        message.queries[0].name().to_string(),
        message.edns.map(|edns| edns.flags().dnssec_ok),
    )
}

fn rcode_of(bytes: &[u8]) -> ResponseCode {
    Message::from_bytes(bytes).unwrap().metadata.response_code
}

/// One A record of the given TTL for the query's question.
/// 为查询的问题生成一条给定 TTL 的 A 记录应答。
fn echo_answer(query: &[u8], ttl: u32) -> Option<Vec<u8>> {
    let request = Message::from_bytes(query).ok()?;
    let question = request.queries.first()?.clone();
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.add_query(question.clone());
    response.add_answer(Record::from_rdata(
        question.name().clone(),
        ttl,
        RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
    ));
    response.to_vec().ok()
}

/// Minimal UDP upstream that answers every query with one A record of the
/// given TTL. Aborting the returned task closes its socket.
/// 最小 UDP 上游：以给定 TTL 的一条 A 记录应答所有查询；中止返回的任务即关闭其 socket。
async fn spawn_echo_upstream(ttl: u32) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            if let Some(response) = echo_answer(&buf[..n], ttl) {
                let _ = socket.send_to(&response, peer).await;
            }
        }
    });
    (addr, task)
}

/// As [`spawn_echo_upstream`], receiving but no longer answering once `answering` is set to
/// false. The port stays taken: ending the task would free it, and a test running alongside
/// could bind the same port number and answer in its place.
/// 同 [`spawn_echo_upstream`]，`answering` 置为 false 以后照收不答。端口一直占着：结束任务会放掉端口，
/// 并行跑的别的测试可能正好绑到同一个端口号、替它作答。
async fn spawn_silenceable_echo_upstream(ttl: u32) -> (String, Arc<std::sync::atomic::AtomicBool>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let still_answering = Arc::clone(&answering);
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            if still_answering.load(std::sync::atomic::Ordering::SeqCst)
                && let Some(response) = echo_answer(&buf[..n], ttl)
            {
                let _ = socket.send_to(&response, peer).await;
            }
        }
    });
    (addr, answering)
}

/// UDP upstream that holds every answer until `release` fires, then answers
/// what it holds and everything after. It counts the queries it receives.
/// 扣住所有应答直到 `release` 触发，之后应答已收到的和此后的查询；统计收到的查询数。
struct HeldUpstream {
    addr: String,
    queries: Arc<std::sync::atomic::AtomicUsize>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HeldUpstream {
    async fn spawn() -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (release, mut released) = tokio::sync::oneshot::channel::<()>();
        let counter = queries.clone();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            let mut open = false;
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    received = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = received else { return };
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let Some(response) = echo_answer(&buf[..n], 60) else { continue };
                        if open {
                            let _ = socket.send_to(&response, peer).await;
                        } else {
                            held.push((response, peer));
                        }
                    }
                    _ = &mut released, if !open => {
                        open = true;
                        for (response, peer) in held.drain(..) {
                            let _ = socket.send_to(&response, peer).await;
                        }
                    }
                }
            }
        });
        Self {
            addr,
            queries,
            release: Some(release),
            task,
        }
    }

    fn release(&mut self) {
        let _ = self.release.take().unwrap().send(());
    }

    fn queries(&self) -> usize {
        self.queries.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for HeldUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Request id of the first `Started` event whose query name matches.
fn request_id_for(events: &[Event], qname: &str) -> u64 {
    events
        .iter()
        .find_map(|event| match event {
            Event::Started {
                id, qname: name, ..
            } if name == qname => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no request_started for {qname}: {events:#?}"))
}

fn events_of(events: &[Event], request_id: u64) -> Vec<Event> {
    events
        .iter()
        .filter(|event| match event {
            Event::Started { id, .. }
            | Event::Finished { id, .. }
            | Event::Pipeline { id, .. }
            | Event::RuleCacheLookup { id, .. }
            | Event::RuleEvaluated { id, .. }
            | Event::Rule { id, .. }
            | Event::Decision { id, .. }
            | Event::CacheLookup { id }
            | Event::CacheHit { id, .. }
            | Event::CacheMiss { id }
            | Event::InflightJoined { id }
            | Event::UpstreamAttempt { id, .. }
            | Event::UpstreamResult { id, .. } => *id == request_id,
            Event::ConfigLoaded { .. } | Event::ConfigReloadFailed { .. } => false,
        })
        .cloned()
        .collect()
}

fn started(id: u64, qname: &str) -> Event {
    Event::Started {
        id,
        qname: qname.into(),
        listener: "edge".into(),
        client: peer(),
        transport: None,
        background: false,
    }
}

fn finished(id: u64) -> Event {
    Event::Finished {
        id,
        status: RequestStatus::Completed,
    }
}

fn static_config(ip: &str) -> String {
    serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "static",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": ip }]
            }]
        }]
    })
    .to_string()
}

fn atomically_replace(path: &Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).expect("write tmp config");
    std::fs::rename(&tmp, path).expect("rename config");
}

// ============================================================================
// Tests / 测试
// ============================================================================

#[tokio::test]
async fn builder_defaults_match_engine_new() {
    let raw = static_config("192.0.2.1");
    let plain = Engine::new(runtime_config(&raw), "default".to_string()).unwrap();
    assert!(plain.observer().is_none());
    assert_eq!(plain.config_generation(), 1);

    let built = Engine::builder(runtime_config(&raw)).build().unwrap();
    assert!(built.observer().is_none());
    assert_eq!(built.listener_label.as_ref(), "default");

    let (observed, _) = observed_engine(&raw);
    assert!(observed.observer().is_some());
    assert_eq!(observed.listener_label.as_ref(), "edge");
    observed.reload(runtime_config(&raw));
    assert_eq!(observed.config_generation(), 2);
}

#[tokio::test]
async fn reload_events_carry_the_generation_they_allocated() {
    let v1 = static_config("192.0.2.1");
    let v2 = static_config("192.0.2.2");
    let v3 = static_config("192.0.2.3");
    let path = Path::new("/etc/kixdns/pipeline.json");
    let (engine, recorder) = observed_engine(&v1);
    assert_eq!(
        recorder.drain(),
        vec![Event::ConfigLoaded {
            generation: 1,
            path: None,
            source: None,
        }],
        "build reports the initial configuration"
    );

    engine.reload_from(runtime_config(&v2), path, &v2);
    assert_eq!(engine.config_generation(), 2);
    engine.reload_from(runtime_config(&v3), path, &v3);
    assert_eq!(engine.config_generation(), 3);
    engine.reload(runtime_config(&v1));
    assert_eq!(engine.config_generation(), 4);

    assert_eq!(
        recorder.drain(),
        vec![
            Event::ConfigLoaded {
                generation: 2,
                path: Some(path.to_path_buf()),
                source: Some(v2),
            },
            Event::ConfigLoaded {
                generation: 3,
                path: Some(path.to_path_buf()),
                source: Some(v3),
            },
            Event::ConfigLoaded {
                generation: 4,
                path: None,
                source: None,
            },
        ]
    );
}

/// 每份生效的配置里有哪些 pipeline、规则和上游 / The pipelines, rules and upstreams of each
/// configuration taking effect
type Names = (Vec<String>, Vec<(String, String)>, Vec<(String, Transport)>);

#[derive(Default)]
struct ConfigNames(Mutex<Vec<Names>>);

impl EngineObserver for ConfigNames {
    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        self.0.lock().unwrap().push((
            event.pipelines.iter().map(|id| id.to_string()).collect(),
            event
                .rules
                .iter()
                .map(|&(pipeline, rule)| (pipeline.to_string(), rule.to_string()))
                .collect(),
            event
                .upstreams
                .iter()
                .map(|&(address, transport)| (address.to_string(), transport))
                .collect(),
        ));
    }
}

/// 每份生效的配置都告诉观察者它的 pipeline、规则和上游，名字和请求的事件里报的一样：上游是去掉前缀的地址和问它的
/// 传输，各一次，回答阶段的转发和没写上游、问默认上游的也算；没有 pipeline 的配置报 `default`
/// Every configuration taking effect tells the observer its pipelines, rules and upstreams,
/// named as the request events name them: an upstream is its address short of the prefix and
/// the transport it is asked over, each once, answer-phase forwards and those naming no
/// upstream, which ask the default one, included; a configuration with no pipelines reports
/// `default`
#[tokio::test]
async fn a_loaded_configuration_names_its_pipelines_rules_and_upstreams() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "1.1.1.1:53" },
        "pipelines": [
            { "id": "main", "rules": [
                { "name": "encrypted", "matchers": [{ "type": "domain_suffix", "value": "a.test" }],
                  "actions": [{ "type": "forward", "upstream": "tls://dns.example, 9.9.9.9:53" }] },
                { "name": "checked", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": null, "transport": "tcp" }],
                  "response_matchers": [{ "type": "response_rcode", "value": "SERVFAIL" }],
                  "response_actions_on_match": [{ "type": "forward", "upstream": "https://doh.example/dns-query" }] },
                { "name": "again", "matchers": [{ "type": "domain_suffix", "value": "b.test" }],
                  "actions": [{ "type": "forward", "upstream": "9.9.9.9:53" }] }
            ] },
            { "id": "other", "rules": [] }
        ]
    })
    .to_string();
    let names = Arc::new(ConfigNames::default());
    let engine = Engine::builder(runtime_config(&raw))
        .observer(names.clone())
        .build()
        .expect("build engine");
    engine.reload(runtime_config(
        r#"{ "settings": { "default_upstream": "1.1.1.1:53" } }"#,
    ));

    // 上游各报一次，顺序不定 / Each upstream is reported once, in no set order
    let upstreams = |loaded: &Names| {
        let set: HashSet<_> = loaded.2.iter().cloned().collect();
        assert_eq!(set.len(), loaded.2.len(), "an upstream reported twice");
        set
    };
    let set = |items: &[(&str, Transport)]| {
        items
            .iter()
            .map(|&(address, transport)| (address.to_string(), transport))
            .collect::<HashSet<_>>()
    };
    let loaded = names.0.lock().unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].0, ["main", "other"]);
    assert_eq!(
        loaded[0].1,
        [
            ("main", "encrypted"),
            ("main", "checked"),
            ("main", "again")
        ]
        .map(|(pipeline, rule)| (pipeline.to_string(), rule.to_string()))
    );
    assert_eq!(
        upstreams(&loaded[0]),
        set(&[
            ("1.1.1.1:53", Transport::Udp),
            ("dns.example", Transport::Dot),
            ("9.9.9.9:53", Transport::Udp),
            ("1.1.1.1:53", Transport::Tcp),
            ("doh.example/dns-query", Transport::Doh),
        ])
    );
    assert_eq!(loaded[1].0, ["default"]);
    assert!(loaded[1].1.is_empty());
    assert_eq!(
        upstreams(&loaded[1]),
        set(&[("1.1.1.1:53", Transport::Udp)])
    );
}

/// 每个请求说的开始时刻和上报方式，以及报的耗时 / When each request says it started and how it is
/// reported, and the latency reported
#[derive(Default)]
struct Moments {
    started: Mutex<Vec<(Instant, bool)>>,
    latencies: Mutex<Vec<Duration>>,
}

impl EngineObserver for Moments {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        self.started
            .lock()
            .unwrap()
            .push((ctx.started, ctx.reported_at_once));
    }

    fn request_finished(&self, _ctx: &RequestContext<'_>, outcome: &RequestOutcome<'_>) {
        self.latencies.lock().unwrap().push(outcome.latency);
    }
}

#[tokio::test]
async fn a_request_says_when_it_started_and_how_it_is_reported() {
    let (upstream, _task) = spawn_echo_upstream(300).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "forward",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }]
        }]
    })
    .to_string();
    let moments = Arc::new(Moments::default());
    let engine = Engine::builder(runtime_config(&raw))
        .observer(moments.clone())
        .build()
        .expect("build engine");

    let before = Instant::now();
    engine
        .handle_packet(&query("a.cached.test"), peer())
        .await
        .unwrap();
    let slow = Instant::now();
    let fast = engine.handle_packet_fast(&query("a.cached.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::CacheHit { .. })));
    let after = Instant::now();

    let seen = moments.started.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(before <= seen[0].0 && seen[0].0 <= slow);
    assert!(!seen[0].1, "the full path reports as it goes");
    assert!(slow <= seen[1].0 && seen[1].0 <= after);
    assert!(seen[1].1, "the fast path reports at once after answering");
    // 耗时从开始那一刻算到答完 / The latency runs from that moment to the answer
    let latencies = moments.latencies.lock().unwrap().clone();
    assert_eq!(latencies.len(), 2);
    assert!(Duration::ZERO < latencies[0] && latencies[0] <= slow - before);
    assert!(Duration::ZERO < latencies[1] && latencies[1] <= after - slow);
}

/// 把缓存命中整个接过去的观察者 / An observer taking cache hits whole
#[derive(Default)]
struct TakesHitsWhole {
    whole: Mutex<Vec<(String, String, Option<ResponseCode>)>>,
    started: Mutex<Vec<String>>,
    finished: Mutex<Vec<String>>,
}

impl EngineObserver for TakesHitsWhole {
    fn answered_from_cache(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        hit: &CacheHit<'_>,
        outcome: &RequestOutcome<'_>,
    ) -> bool {
        assert_eq!(hit.kind, CacheHitKind::Fresh);
        assert!(outcome.latency > Duration::ZERO);
        self.whole.lock().unwrap().push((
            ctx.qname.to_string(),
            pipeline.to_string(),
            outcome.response.map(rcode_of),
        ));
        true
    }

    fn request_started(&self, ctx: &RequestContext<'_>) {
        self.started.lock().unwrap().push(ctx.qname.to_string());
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, _outcome: &RequestOutcome<'_>) {
        self.finished.lock().unwrap().push(ctx.qname.to_string());
    }
}

/// 接过去了就不再发分开的事件；只有缓存命中才这样，规则直接答的照旧
/// Once taken whole there are no separate events; only a cache hit goes this way, and a rule's own
/// answer on the fast path is reported as ever
#[tokio::test]
async fn an_observer_can_take_a_cache_hit_whole() {
    let (upstream, _task) = spawn_echo_upstream(300).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "block",
                    "matchers": [{ "type": "domain_suffix", "value": "blocked.test" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                },
                {
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream }]
                }
            ]
        }]
    })
    .to_string();
    let observer = Arc::new(TakesHitsWhole::default());
    let engine = Engine::builder(runtime_config(&raw))
        .observer(observer.clone())
        .build()
        .expect("build engine");

    engine
        .handle_packet(&query("a.cached.test"), peer())
        .await
        .unwrap();
    assert!(observer.whole.lock().unwrap().is_empty());
    assert_eq!(observer.started.lock().unwrap().len(), 1);

    let fast = engine.handle_packet_fast(&query("a.cached.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::CacheHit { .. })));
    assert_eq!(
        *observer.whole.lock().unwrap(),
        vec![(
            "a.cached.test".to_string(),
            "main".to_string(),
            Some(ResponseCode::NoError)
        )]
    );
    assert_eq!(
        observer.started.lock().unwrap().len(),
        1,
        "no separate events"
    );
    assert_eq!(
        observer.finished.lock().unwrap().len(),
        1,
        "no separate events"
    );

    let fast = engine.handle_packet_fast(&query("b.blocked.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    assert_eq!(observer.whole.lock().unwrap().len(), 1);
    assert_eq!(observer.started.lock().unwrap().len(), 2);
    assert_eq!(observer.finished.lock().unwrap().len(), 2);
}

/// 把规则回答整个接过去的观察者 / An observer taking rules' answers whole
/// 接过去的一条：域名、命中的规则、是不是规则定的、响应码、回答条数、应答的响应码
/// One taken: the name, the matched rules, whether a rule decided, the response code, how many answers,
/// and the response code of the reply
type RuleAnswerTaken = (
    String,
    Vec<String>,
    bool,
    ResponseCode,
    usize,
    Option<ResponseCode>,
);

#[derive(Default)]
struct TakesRuleAnswersWhole {
    whole: Mutex<Vec<RuleAnswerTaken>>,
    started: Mutex<Vec<String>>,
}

impl EngineObserver for TakesRuleAnswersWhole {
    fn answered_by_rule(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        answer: &RuleAnswer<'_>,
        outcome: &RequestOutcome<'_>,
    ) -> bool {
        assert_eq!(pipeline, "main");
        assert!(outcome.latency > Duration::ZERO);
        self.whole.lock().unwrap().push((
            ctx.qname.to_string(),
            answer.rules.iter().map(ToString::to_string).collect(),
            answer.decided_by_rule,
            answer.rcode,
            answer.answers,
            outcome.response.map(rcode_of),
        ));
        true
    }

    fn request_started(&self, ctx: &RequestContext<'_>) {
        self.started.lock().unwrap().push(ctx.qname.to_string());
    }
}

/// 规则直接答的两条路都能整个接过去，接过去就没有分开的事件：编译好的规则和规则缓存
/// Both ways of a rule's answer can be taken whole, with no separate events then: compiled rules and the
/// rule cache
#[tokio::test]
async fn an_observer_can_take_a_rule_answer_whole() {
    let engine_with = |pipelines: serde_json::Value| {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": pipelines,
        })
        .to_string();
        let observer = Arc::new(TakesRuleAnswersWhole::default());
        let engine = Engine::builder(runtime_config(&raw))
            .observer(observer.clone())
            .build()
            .expect("build engine");
        (engine, observer)
    };
    let answer = serde_json::json!([{ "type": "static_ip_response", "ip": "192.0.2.1,192.0.2.2" }]);

    // 编译好的规则当场答 / A compiled rule answers on the spot
    let (engine, observer) = engine_with(serde_json::json!([{
        "id": "main",
        "rules": [{ "name": "ip", "matchers": [{ "type": "any" }], "actions": answer }]
    }]));
    let fast = engine.handle_packet_fast(&query("a.ip.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    assert_eq!(
        *observer.whole.lock().unwrap(),
        vec![(
            "a.ip.test".to_string(),
            vec!["ip".to_string()],
            true,
            ResponseCode::NoError,
            2,
            Some(ResponseCode::NoError)
        )]
    );
    assert!(observer.started.lock().unwrap().is_empty());

    // 先命中一条快速路径不当场决定的规则（这里 continue），第一次走完整路径，之后由规则缓存答 / A rule the fast
    // path does not decide on the spot matching first (a continue here), the full path answers the first time and
    // the rule cache after that
    let (engine, observer) = engine_with(serde_json::json!([{
        "id": "main",
        "rules": [
            { "name": "audit", "matchers": [{ "type": "any" }], "actions": [{ "type": "continue" }] },
            { "name": "ip", "matchers": [{ "type": "any" }], "actions": answer },
        ]
    }]));
    engine
        .handle_packet(&query("a.ip.test"), peer())
        .await
        .unwrap();
    assert!(observer.whole.lock().unwrap().is_empty());
    assert_eq!(observer.started.lock().unwrap().len(), 1);
    let fast = engine.handle_packet_fast(&query("b.ip.test"), peer());
    assert!(
        matches!(fast, Some(FastPathResponse::AsyncNeeded(_))),
        "another name is not cached"
    );
    let fast = engine.handle_packet_fast(&query("a.ip.test"), peer());
    assert!(!matches!(fast, Some(FastPathResponse::AsyncNeeded(_))));
    assert_eq!(
        observer.started.lock().unwrap().len(),
        1,
        "no separate events"
    );
    assert_eq!(
        *observer.whole.lock().unwrap(),
        vec![(
            "a.ip.test".to_string(),
            vec!["audit".to_string(), "ip".to_string()],
            true,
            ResponseCode::NoError,
            2,
            Some(ResponseCode::NoError)
        )]
    );
}

/// 快速路径上规则按配置答地址，上报的回答条数就是这个查询实际得到的条数
/// A rule answering addresses from the config on the fast path reports how many answers this
/// query really got
#[tokio::test]
async fn a_rules_addresses_are_counted_for_the_type_asked() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "ip",
                "matchers": [{ "type": "domain_suffix", "value": "ip.test" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1,192.0.2.2,2001:db8::1" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let fast = engine.handle_packet_fast(&query("a.ip.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let answers: Vec<usize> = recorder
        .drain()
        .into_iter()
        .filter_map(|event| match event {
            Event::Decision {
                detail: Detail::Static { answers, .. },
                ..
            } => Some(answers),
            _ => None,
        })
        .collect();
    assert_eq!(answers, [2]);
}

#[tokio::test]
async fn static_rule_is_reported_on_slow_and_fast_paths() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 60 },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "block",
                "matchers": [{ "type": "domain_suffix", "value": "blocked.test" }],
                "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    // Slow path: full request pipeline / 完整请求路径
    let response = engine
        .handle_packet(&query("a.blocked.test"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NXDomain);
    let events = recorder.drain();
    let id = request_id_for(&events, "a.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "a.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("block".into()),
                phase: RulePhase::Request,
                detail: Detail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
            finished(id),
        ]
    );

    // Fast path, compiled static rule for a name not in the response cache
    // 快速路径：响应缓存中没有的名字命中编译后的静态规则
    let fast = engine.handle_packet_fast(&query("b.blocked.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let events = recorder.drain();
    let id = request_id_for(&events, "b.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "b.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: true,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("block".into()),
                phase: RulePhase::Request,
                detail: Detail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
            finished(id),
        ]
    );

    // Fast path again for the name the full path answered: a rule's own answer stays out of
    // the response cache even with min_ttl, and the decision the full path kept in the rule
    // cache answers it, looked at before the compiled rules as on the full path
    // 快速路径再问完整路径答过的名字：规则直接给的应答开着 min_ttl 也不进响应缓存，由完整路径存进规则缓存的决定作答，
    // 和完整路径一样先看规则缓存、再看编译后的规则
    let fast = engine.handle_packet_fast(&query("a.blocked.test"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let events = recorder.drain();
    let id = request_id_for(&events, "a.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "a.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: true,
                matched_rules: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: true,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("block".into()),
                phase: RulePhase::Request,
                detail: Detail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
            finished(id),
        ]
    );
}

#[tokio::test]
async fn rule_cache_hits_replay_matched_rules() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "audit",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "continue" }]
                },
                {
                    "name": "block",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let rule_events = |events: &[Event], id: u64| -> Vec<(String, DecisionKind, bool)> {
        events_of(events, id)
            .into_iter()
            .filter_map(|event| match event {
                Event::Rule {
                    rule,
                    decision,
                    fast_path,
                    ..
                } => Some((rule, decision, fast_path)),
                _ => None,
            })
            .collect()
    };
    let decision = |id: u64| Event::Decision {
        id,
        pipeline: "main".into(),
        rule: Some("block".into()),
        phase: RulePhase::Request,
        detail: Detail::Static {
            rcode: ResponseCode::NXDomain,
            answers: 0,
        },
    };

    // First evaluation: both candidate rules are evaluated and match
    // 首次求值：两条候选规则都被求值并命中
    engine
        .handle_packet(&query("x.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "x.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            // rule_matched is reported once the pipeline's decision is known,
            // after every candidate was evaluated / 规则命中在管线决策确定后统一上报
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Continue,
                fast_path: false,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            decision(id),
            finished(id),
        ]
    );

    // min_ttl = 0 keeps the static answer out of the response cache, so the
    // next slow-path request reaches the rule cache: the recorded rules are
    // replayed and the decision is reported without re-evaluating anything.
    // min_ttl = 0 使静态应答不进入响应缓存，下一次慢路径请求到达规则缓存：
    // 回放记录的规则并上报决策，不再重新求值。
    engine
        .handle_packet(&query("x.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "x.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: true,
                matched_rules: 2,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Continue,
                fast_path: false,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            decision(id),
            finished(id),
        ]
    );

    // The fast path reaches the same rule cache entry and replays it too
    // 快速路径到达同一规则缓存条目并同样回放
    let fast = engine.handle_packet_fast(&query("x.example"), peer());
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::RuleCacheLookup {
        id,
        pipeline: "main".into(),
        hit: true,
        matched_rules: 2,
    }));
    assert!(
        !mine
            .iter()
            .any(|event| matches!(event, Event::RuleEvaluated { .. })),
        "rule cache replays must not report rule_evaluated: {mine:#?}"
    );
    assert_eq!(
        rule_events(&events, id),
        vec![
            ("audit".to_string(), DecisionKind::Continue, true),
            ("block".to_string(), DecisionKind::Static, true),
        ]
    );
    assert!(mine.contains(&decision(id)));
}

#[tokio::test]
async fn upstream_success_then_fresh_and_stale_cache_hits() {
    let (upstream, _echo) = spawn_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    // Miss: evaluated by the rules and forwarded to the echo upstream
    // 未命中：经规则求值后转发到回显上游
    let response = engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "cache.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Forward,
                fast_path: false,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("fwd".into()),
                phase: RulePhase::Request,
                detail: Detail::Forward {
                    upstream: upstream.clone(),
                    transport: Some(Transport::Udp),
                },
            },
            Event::UpstreamAttempt {
                id,
                upstream: upstream.clone(),
                transport: Transport::Udp,
            },
            Event::UpstreamResult {
                id,
                upstream: upstream.clone(),
                transport: Transport::Udp,
                via: Transport::Udp,
                outcome: UpstreamOutcome::Success,
                rcode: Some(ResponseCode::NoError),
                truncated: Some(false),
                has_error: false,
            },
            finished(id),
        ]
    );

    // Fresh hit within the 1s TTL / TTL 内的新鲜命中
    engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "cache.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheHit {
                id,
                kind: CacheHitKind::Fresh,
                has_remaining_ttl: true,
                original_ttl: Some(Duration::from_secs(1)),
            },
            finished(id),
        ]
    );

    // Stale hit after the TTL expired (RFC 8767) / TTL 过期后的过期命中
    tokio::time::sleep(Duration::from_millis(1200)).await;
    engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    let mine = events_of(&events, id);
    assert!(
        mine.contains(&Event::CacheHit {
            id,
            kind: CacheHitKind::Stale,
            has_remaining_ttl: false,
            original_ttl: Some(Duration::from_secs(1)),
        }),
        "{mine:#?}"
    );
    assert!(
        !mine
            .iter()
            .any(|event| matches!(event, Event::CacheMiss { .. })),
        "a stale hit is not a miss: {mine:#?}"
    );
    assert!(mine.contains(&finished(id)));
}

#[tokio::test]
async fn background_refresh_reports_no_cache_events() {
    // A stale entry whose upstream has stopped answering: the foreground request is
    // served stale and spawns a background refresh, whose forward fails.
    // 上游已不再回答的过期条目：前台请求返回过期缓存并触发后台刷新，刷新转发失败。
    let (upstream, answering) = spawn_silenceable_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0,
            "upstream_timeout_ms": 200,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    // The stale request arrives through a listener's handle; the refresh it
    // schedules is the engine's own query and names no transport.
    // 过期请求经由监听器的句柄到达；它安排的刷新是引擎自己的查询，不带传输。
    let engine = engine.with_client_transport(ClientTransport::Udp);

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    answering.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    recorder.drain();

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    // Wait for the background refresh to run to completion / 等待后台刷新结束
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::Finished { id, .. }
                            if events.iter().any(|started| matches!(
                                started,
                                Event::Started { id: sid, background: true, .. } if sid == id
                            ))
                    )
                })
            })
            .await,
        "background refresh must finish: {:#?}",
        recorder.events()
    );

    let events = recorder.drain();
    let foreground = request_id_for(&events, "stale.example");
    let background = events
        .iter()
        .find_map(|event| match event {
            Event::Started {
                id,
                background: true,
                ..
            } => Some(*id),
            _ => None,
        })
        .expect("background refresh request");
    assert_ne!(foreground, background);
    let transport_of = |request| {
        events.iter().find_map(|event| match event {
            Event::Started { id, transport, .. } if *id == request => Some(*transport),
            _ => None,
        })
    };
    assert_eq!(transport_of(foreground), Some(Some(ClientTransport::Udp)));
    assert_eq!(transport_of(background), Some(None));

    let foreground_events = events_of(&events, foreground);
    assert!(foreground_events.contains(&Event::CacheLookup { id: foreground }));
    assert!(foreground_events.iter().any(|event| matches!(
        event,
        Event::CacheHit {
            kind: CacheHitKind::Stale,
            ..
        }
    )));

    let background_events = events_of(&events, background);
    assert!(
        background_events.iter().any(|event| matches!(
            event,
            Event::UpstreamResult {
                outcome: UpstreamOutcome::Error,
                ..
            }
        )),
        "the refresh forward must fail: {background_events:#?}"
    );
    assert!(
        !background_events.iter().any(|event| matches!(
            event,
            Event::CacheLookup { .. } | Event::CacheHit { .. } | Event::CacheMiss { .. }
        )),
        "a background refresh must report no cache events: {background_events:#?}"
    );
}

#[tokio::test]
async fn a_background_refresh_reports_its_response_rules() {
    // A refresh acts on the response rules as a client query does, so it
    // reports them too, flagged as a background refresh.
    // 刷新和客户端请求一样按响应规则行事，所以同样上报，并标为后台刷新。
    let (upstream, _echo) = spawn_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0,
            "upstream_timeout_ms": 500,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "checked",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }],
                "response_matchers": [{ "type": "upstream_equals", "value": upstream }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    engine
        .handle_packet(&query("refresh.example"), peer())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    recorder.drain();

    // Served stale; the refresh it spawns forwards and checks the answer.
    // 返回过期缓存；它触发的刷新会转发并检查应答。
    engine
        .handle_packet(&query("refresh.example"), peer())
        .await
        .unwrap();
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::Finished { id, .. }
                            if events.iter().any(|started| matches!(
                                started,
                                Event::Started { id: sid, background: true, .. } if sid == id
                            ))
                    )
                })
            })
            .await,
        "background refresh must finish: {:#?}",
        recorder.events()
    );

    let events = recorder.drain();
    let background = events
        .iter()
        .find_map(|event| match event {
            Event::Started {
                id,
                background: true,
                ..
            } => Some(*id),
            _ => None,
        })
        .expect("background refresh request");
    let background_events = events_of(&events, background);
    assert!(
        background_events.iter().any(|event| matches!(
            event,
            Event::RuleEvaluated {
                rule,
                phase: RulePhase::Response,
                matched: true,
                ..
            } if rule == "checked"
        )),
        "the refresh must report its answer check: {background_events:#?}"
    );
    assert!(
        background_events.iter().any(|event| matches!(
            event,
            Event::Rule {
                rule,
                phase: RulePhase::Response,
                ..
            } if rule == "checked"
        )),
        "the refresh must report the response rule it matched: {background_events:#?}"
    );
}

#[tokio::test]
async fn concurrent_upstreams_report_the_loser_as_aborted() {
    // One upstream answers at once, the other never does / 一个立即应答，一个黑洞
    let (echo, _echo_task) = spawn_echo_upstream(60).await;
    let blackhole_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole = blackhole_socket.local_addr().unwrap().to_string();
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "enable_tcp_fallback": false },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "race",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": format!("{echo},{blackhole}"),
                    "transport": "udp"
                }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let response = engine
        .handle_packet(&query("race.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "race.example");
    let mine = events_of(&events, id);

    let attempts: Vec<String> = mine
        .iter()
        .filter_map(|event| match event {
            Event::UpstreamAttempt { upstream, .. } => Some(upstream.clone()),
            _ => None,
        })
        .collect();
    let results: Vec<(String, UpstreamOutcome)> = mine
        .iter()
        .filter_map(|event| match event {
            Event::UpstreamResult {
                upstream, outcome, ..
            } => Some((upstream.clone(), *outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(attempts, vec![echo.clone(), blackhole.clone()]);
    assert_eq!(results.len(), 2, "one result per attempt: {mine:#?}");
    assert!(results.contains(&(echo.clone(), UpstreamOutcome::Success)));
    assert!(results.contains(&(blackhole.clone(), UpstreamOutcome::Aborted)));
    drop(blackhole_socket);
}

/// 请求在上游回答之前被放下（客户端走了、超时了），转发半路停下：每次尝试照样有一个结果，报成 Aborted，只问一个上游的和
/// 几个上游一起问的都一样。以前这些尝试只报了 upstream_attempt，没有配对的 upstream_result
/// A request given up before its upstream answers (its client gone, a timeout) stops the forward
/// halfway: each attempt still gets one result, reported as Aborted, for a single upstream and a
/// set asked together alike. These attempts used to report an upstream_attempt with no
/// upstream_result to pair it
#[tokio::test]
async fn attempts_of_a_request_given_up_halfway_are_reported_as_aborted() {
    // 收下查询、从不回答的上游 / Upstreams that take queries and never answer
    let blackhole = || async { tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap() };
    let blackholes = [blackhole().await, blackhole().await, blackhole().await];
    let [single, first, second] = blackholes
        .each_ref()
        .map(|socket| socket.local_addr().unwrap().to_string());
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 5000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "single",
                    "matchers": [{ "type": "domain_exact", "value": "single.example" }],
                    "actions": [{ "type": "forward", "upstream": single, "transport": "udp" }]
                },
                {
                    "name": "set",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": format!("{first},{second}"),
                        "transport": "udp"
                    }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    for (qname, asked) in [
        ("single.example", vec![single.clone()]),
        ("set.example", vec![first.clone(), second.clone()]),
    ] {
        let given_up = tokio::time::timeout(
            Duration::from_millis(200),
            engine.handle_packet(&query(qname), peer()),
        )
        .await;
        assert!(given_up.is_err(), "the upstreams never answer");
        let events = recorder.drain();
        let mine = events_of(&events, request_id_for(&events, qname));
        let attempts: Vec<String> = mine
            .iter()
            .filter_map(|event| match event {
                Event::UpstreamAttempt { upstream, .. } => Some(upstream.clone()),
                _ => None,
            })
            .collect();
        let results: Vec<(String, UpstreamOutcome)> = mine
            .iter()
            .filter_map(|event| match event {
                Event::UpstreamResult {
                    upstream, outcome, ..
                } => Some((upstream.clone(), *outcome)),
                _ => None,
            })
            .collect();
        assert_eq!(attempts, asked, "{mine:#?}");
        assert_eq!(
            results,
            asked
                .iter()
                .map(|upstream| (upstream.clone(), UpstreamOutcome::Aborted))
                .collect::<Vec<_>>(),
            "one result per attempt: {mine:#?}"
        );
    }
}

#[tokio::test]
async fn decision_made_reports_no_transport_for_prefixed_upstreams() {
    let forward_of = |events: &[Event], id: u64| -> (Option<Transport>, Transport) {
        let mine = events_of(events, id);
        let decided = mine
            .iter()
            .find_map(|event| match event {
                Event::Decision {
                    detail: Detail::Forward { transport, .. },
                    ..
                } => Some(*transport),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no forward decision: {mine:#?}"));
        let attempted = mine
            .iter()
            .find_map(|event| match event {
                Event::UpstreamAttempt { transport, .. } => Some(*transport),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no upstream attempt: {mine:#?}"));
        (decided, attempted)
    };

    // Default upstream with a dot:// prefix and no pipeline at all
    // 带 dot:// 前缀的默认上游，且没有任何 pipeline
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "dot://127.0.0.1:9",
            "upstream_timeout_ms": 300,
            "enable_tcp_fallback": false
        },
        "pipelines": []
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let _ = engine.handle_packet(&query("dot.example"), peer()).await;
    let events = recorder.drain();
    let id = request_id_for(&events, "dot.example");
    assert_eq!(forward_of(&events, id), (None, Transport::Dot));
    assert!(events_of(&events, id).iter().any(|event| matches!(
        event,
        Event::Decision { rule: None, detail: Detail::Forward { upstream, .. }, .. }
            if upstream == "dot://127.0.0.1:9"
    )));

    // forward action with a tcp:// prefix and no transport field
    // 带 tcp:// 前缀且省略 transport 字段的 forward 动作
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 300,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "tcp://127.0.0.1:9" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let _ = engine.handle_packet(&query("tcp.example"), peer()).await;
    let events = recorder.drain();
    let id = request_id_for(&events, "tcp.example");
    assert_eq!(forward_of(&events, id), (None, Transport::Tcp));

    // Control: a bare address keeps the configured (default UDP) transport
    // 对照：裸地址保留配置的传输（默认 UDP）
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 300,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let _ = engine.handle_packet(&query("udp.example"), peer()).await;
    let events = recorder.drain();
    let id = request_id_for(&events, "udp.example");
    assert_eq!(
        forward_of(&events, id),
        (Some(Transport::Udp), Transport::Udp)
    );
}

/// DNS-over-TCP responder that answers every query with one A record.
/// 对每个查询以一条 A 记录应答的 DNS-over-TCP 服务。
async fn spawn_tcp_dns_server(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let Ok(request) = Message::from_bytes(&frame) else {
                    return;
                };
                let Some(question) = request.queries.first().cloned() else {
                    return;
                };
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(question.clone());
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                ));
                let bytes = response.to_vec().unwrap();
                let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&bytes);
                let _ = stream.write_all(&out).await;
            });
        }
    })
}

#[tokio::test]
async fn tcp_fallback_reports_the_transport_that_answered() {
    // UDP never answers; a DNS-over-TCP responder listens on the same port
    // UDP 只收不回；同一端口上有 DNS-over-TCP 应答者
    // The TCP port of the UDP socket's number can be taken already (by another
    // test's connection, say): take another pair then
    // 和 UDP 同号的 TCP 端口可能已被占用（例如被别的测试的连接占着）：那就换一对
    let mut tries = 0;
    let (silent_udp, listener) = loop {
        tries += 1;
        assert!(
            tries <= 20,
            "port conflict: no port free for both UDP and TCP in 20 tries"
        );
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => break (udp, listener),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => panic!("bind tcp on the udp port: {err}"),
        }
    };
    let port = silent_udp.local_addr().unwrap().port();
    let _tcp = spawn_tcp_dns_server(listener).await;
    let upstream = format!("127.0.0.1:{port}");
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 300 },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let response = engine
        .handle_packet(&query("fallback.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "fallback.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::UpstreamAttempt {
        id,
        upstream: upstream.clone(),
        transport: Transport::Udp,
    }));
    assert!(
        mine.contains(&Event::UpstreamResult {
            id,
            upstream: upstream.clone(),
            transport: Transport::Udp,
            via: Transport::Tcp,
            outcome: UpstreamOutcome::Success,
            rcode: Some(ResponseCode::NoError),
            truncated: Some(false),
            has_error: false,
        }),
        "{mine:#?}"
    );
    drop(silent_udp);
}

/// Self-signed certificate and key PEM files for a DoH listener; the files
/// live as long as the returned directory. / DoH 监听用的自签名证书与密钥 PEM 文件。
fn make_doh_cert() -> (tempfile::TempDir, String, String) {
    use rcgen::{CertificateParams, KeyPair, SanType};

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let key_pair = KeyPair::generate().expect("generate key pair");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let dir = tempfile::TempDir::new().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (
        dir,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Start a DoH listener for `engine` on an ephemeral port; returns the port
/// and the certificate directory that must outlive the server.
/// 在临时端口上为 `engine` 启动 DoH 监听；返回端口与需存活的证书目录。
async fn start_doh(engine: Engine) -> (u16, tempfile::TempDir) {
    let (dir, cert_path, key_path) = make_doh_cert();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind doh listener");
    let port = listener.local_addr().unwrap().port();
    let certificate = DohCertificate::load(&cert_path, &key_path).expect("load certificate");
    tokio::spawn(run_doh(listener, certificate, engine, "/dns-query".into()));
    (port, dir)
}

/// POST a DNS query through the DoH listener (RFC 8484 §4.1) and return the
/// wire response. / 通过 DoH 监听以 POST 发送查询并返回线上应答。
async fn doh_query(client: &reqwest::Client, port: u16, qname: &str) -> Vec<u8> {
    let response = client
        .post(format!("https://127.0.0.1:{port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(query(qname))
        .send()
        .await
        .expect("doh request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    response.bytes().await.expect("doh body").to_vec()
}

#[tokio::test]
async fn doh_listener_reports_the_same_lifecycle_as_in_process_requests() {
    let (upstream, _echo) = spawn_echo_upstream(60).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let (port, _cert_dir) = start_doh(engine.clone()).await;
    let client = reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client");
    recorder.drain();

    // Cache miss over DoH: the DoH listener uses the fast path first and
    // falls through to the async path, which reports the full lifecycle
    // exactly as an in-process handle_packet does.
    // DoH 上的缓存未命中：监听器先走快速路径再回落到异步路径，生命周期与进程内 handle_packet 一致。
    let response = doh_query(&client, port, "doh.example").await;
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "doh.example");
    let mine = events_of(&events, id);
    let Some(Event::Started {
        qname,
        transport,
        background,
        ..
    }) = mine.first()
    else {
        panic!("first event must be request_started: {mine:#?}");
    };
    assert_eq!(qname, "doh.example");
    assert_eq!(*transport, Some(ClientTransport::Doh));
    assert!(!background);
    assert_eq!(
        mine[1..],
        [
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Forward,
                fast_path: false,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("fwd".into()),
                phase: RulePhase::Request,
                detail: Detail::Forward {
                    upstream: upstream.clone(),
                    transport: Some(Transport::Udp),
                },
            },
            Event::UpstreamAttempt {
                id,
                upstream: upstream.clone(),
                transport: Transport::Udp,
            },
            Event::UpstreamResult {
                id,
                upstream: upstream.clone(),
                transport: Transport::Udp,
                via: Transport::Udp,
                outcome: UpstreamOutcome::Success,
                rcode: Some(ResponseCode::NoError),
                truncated: Some(false),
                has_error: false,
            },
            finished(id),
        ]
    );
    // Exactly one request was reported for this query / 该查询只上报了一个请求
    let started = events
        .iter()
        .filter(|event| matches!(event, Event::Started { qname, .. } if qname == "doh.example"))
        .count();
    let finished_count = events
        .iter()
        .filter(|event| matches!(event, Event::Finished { id: fid, .. } if *fid == id))
        .count();
    assert_eq!((started, finished_count), (1, 1), "{events:#?}");

    // Cache hit over DoH is answered on the fast path and reported in one batch
    // DoH 上的缓存命中由快速路径应答，一次性上报
    let response = doh_query(&client, port, "doh.example").await;
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "doh.example");
    let mine = events_of(&events, id);
    assert!(matches!(
        mine.first(),
        Some(Event::Started {
            transport: Some(ClientTransport::Doh),
            ..
        })
    ));
    assert_eq!(
        mine[1..],
        [
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheHit {
                id,
                kind: CacheHitKind::Fresh,
                has_remaining_ttl: true,
                original_ttl: Some(Duration::from_secs(60)),
            },
            finished(id),
        ]
    );
}

#[tokio::test]
async fn failed_upstream_is_reported_with_error() {
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 100,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let response = engine
        .handle_packet(&query("down.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::ServFail);
    let events = recorder.drain();
    let id = request_id_for(&events, "down.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::UpstreamAttempt {
        id,
        upstream: "127.0.0.1:9".into(),
        transport: Transport::Udp,
    }));
    assert!(
        mine.contains(&Event::UpstreamResult {
            id,
            upstream: "127.0.0.1:9".into(),
            transport: Transport::Udp,
            via: Transport::Udp,
            outcome: UpstreamOutcome::Error,
            rcode: None,
            truncated: None,
            has_error: true,
        }),
        "{mine:#?}"
    );
    assert_eq!(mine.last(), Some(&finished(id)));
}

#[tokio::test]
async fn cancelled_request_is_reported() {
    // An upstream that never answers / 永不应答的上游
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = silent.local_addr().unwrap().to_string();
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 5000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let packet = query("slow.example");
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        engine.handle_packet(&packet, peer()),
    )
    .await;
    assert!(
        result.is_err(),
        "the listener timeout must drop the request"
    );

    let events = recorder.drain();
    let id = request_id_for(&events, "slow.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::UpstreamAttempt {
        id,
        upstream: upstream.clone(),
        transport: Transport::Udp,
    }));
    assert_eq!(
        mine.last(),
        Some(&Event::Finished {
            id,
            status: RequestStatus::Cancelled
        }),
        "{mine:#?}"
    );
    drop(silent);
}

#[tokio::test]
async fn request_finished_lends_the_response_the_engine_produced() {
    // Static rule, answered on the slow path and on the fast path.
    // 静态规则，分别由慢路径与快速路径应答。
    let (engine, recorder) = observed_engine(&static_config("192.0.2.7"));
    let slow = engine
        .handle_packet(&query("slow.example"), peer())
        .await
        .unwrap();
    let Some(FastPathResponse::Direct(fast)) =
        engine.handle_packet_fast(&query("fast.example"), peer())
    else {
        panic!("a static rule must answer on the fast path");
    };
    // Asked another way, the static answer is lent as it goes to that client
    // 换一种问法，静态回答按发给那个客户端的样子出借
    let Some(FastPathResponse::Direct(otherwise)) =
        engine.handle_packet_fast(&query_asked_otherwise("Other.EXAMPLE", true), peer())
    else {
        panic!("a static rule must answer on the fast path");
    };
    assert_eq!(
        asked_as(&otherwise),
        ("Other.EXAMPLE.".to_string(), Some(true))
    );
    let events = recorder.events();
    for (qname, sent) in [
        ("slow.example", &slow[..]),
        ("fast.example", &fast[..]),
        ("other.example", &otherwise[..]),
    ] {
        let outcome = recorder.outcome(request_id_for(&events, qname));
        assert_eq!(outcome.status, RequestStatus::Completed);
        assert_eq!(outcome.response.as_deref(), Some(sent), "{qname}");
        assert_eq!(outcome.error, None, "{qname}");
    }

    // Upstream answer, then a fresh cache hit on the fast path, which is
    // lent as stored.
    // 上游应答，随后快速路径的新鲜缓存命中按存储原样出借。
    let (upstream, task) = spawn_echo_upstream(300).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": upstream, "enable_tcp_fallback": false },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let answered = engine
        .handle_packet(&query("cached.example"), peer())
        .await
        .unwrap();
    let Some(FastPathResponse::CacheHit { cached, .. }) =
        engine.handle_packet_fast(&query("cached.example"), peer())
    else {
        panic!("the second query must be a fast-path cache hit");
    };
    let events = recorder.events();
    let ids: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            Event::Started { id, qname, .. } if qname == "cached.example" => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 2, "{events:#?}");
    let first = recorder.outcome(ids[0]);
    assert_eq!(first.response.as_deref(), Some(&answered[..]));
    assert_eq!(
        rcode_of(first.response.as_deref().unwrap()),
        ResponseCode::NoError
    );
    assert_eq!(
        recorder.outcome(ids[1]).response.as_deref(),
        Some(&cached[..])
    );
    // Asked another way, the cached answer is lent as it goes to that client (DO=1 would
    // be another cache key)
    // 换一种问法，缓存里的应答按发给那个客户端的样子出借（DO=1 就是另一个缓存键了）
    let Some(FastPathResponse::CacheHit {
        cached: otherwise, ..
    }) = engine.handle_packet_fast(&query_asked_otherwise("CACHED.Example", false), peer())
    else {
        panic!("a query asked another way must be a fast-path cache hit");
    };
    assert_eq!(
        asked_as(&otherwise),
        ("CACHED.Example.".to_string(), Some(false))
    );
    let events = recorder.events();
    let last = events
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Started { id, qname, .. } if qname == "cached.example" => Some(*id),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        recorder.outcome(last).response.as_deref(),
        Some(&otherwise[..])
    );
    task.abort();
}

#[tokio::test]
async fn failed_and_cancelled_requests_lend_no_response() {
    // A request the engine answers ends with an answer, a SERVFAIL of its own
    // included; what fails is a background refresh whose upstream fails, which has no
    // client to answer: a stale entry whose upstream has stopped answering.
    // 引擎作答的请求都以应答结束，它自己的 SERVFAIL 也是；失败的是上游失败的后台刷新，它没有
    // 要回答的客户端：上游已不再回答的过期条目。
    let (upstream, answering) = spawn_silenceable_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "serve_stale": true,
            "upstream_timeout_ms": 200,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    engine
        .handle_packet(&query("broken.example"), peer())
        .await
        .unwrap();
    answering.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    recorder.drain();
    engine
        .handle_packet(&query("broken.example"), peer())
        .await
        .unwrap();
    let refresh = |events: &[Event]| {
        events.iter().find_map(|event| match event {
            Event::Started {
                id,
                background: true,
                ..
            } => Some(*id),
            _ => None,
        })
    };
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                refresh(events).is_some_and(|refresh| {
                    events
                        .iter()
                        .any(|event| matches!(event, Event::Finished { id, .. } if *id == refresh))
                })
            })
            .await,
        "the background refresh must finish: {:#?}",
        recorder.events()
    );
    let failed = recorder.outcome(refresh(&recorder.events()).unwrap());
    assert_eq!(failed.status, RequestStatus::Failed);
    assert_eq!(failed.response, None);
    assert!(failed.error.is_some());

    // A dropped request never produced a message and did not fail.
    // 被丢弃的请求既没有产出应答，也不算失败。
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = silent.local_addr().unwrap().to_string();
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 5000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let dropped = tokio::time::timeout(
        Duration::from_millis(100),
        engine.handle_packet(&query("dropped.example"), peer()),
    )
    .await;
    assert!(
        dropped.is_err(),
        "the listener timeout must drop the request"
    );
    let cancelled = recorder.outcome(request_id_for(&recorder.events(), "dropped.example"));
    assert_eq!(cancelled.status, RequestStatus::Cancelled);
    assert_eq!(cancelled.response, None);
    assert_eq!(cancelled.error, None);
    drop(silent);
}

#[tokio::test]
async fn cache_hits_name_the_upstream_whose_answer_was_cached() {
    let (upstream, task) = spawn_echo_upstream(300).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": upstream, "enable_tcp_fallback": false },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    engine
        .handle_packet(&query("cached.example"), peer())
        .await
        .unwrap();
    // A cache hit on the async path, then one on the fast path.
    // 先是异步路径的缓存命中，再是快速路径的。
    engine
        .handle_packet(&query("cached.example"), peer())
        .await
        .unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&query("cached.example"), peer()),
        Some(FastPathResponse::CacheHit { .. })
    ));
    let sources = recorder.cache_sources();
    assert_eq!(sources.len(), 2, "{sources:#?}");
    // The same address `upstream_result` reported, without the transport prefix.
    // 与 upstream_result 报告的地址相同，不带传输前缀。
    assert!(
        sources
            .iter()
            .all(|(_, source)| source.as_deref() == Some(upstream.as_str())),
        "{sources:#?}"
    );
    assert!(recorder.events().contains(&Event::UpstreamAttempt {
        id: request_id_for(&recorder.events(), "cached.example"),
        upstream: upstream.clone(),
        transport: Transport::Udp,
    }));
    task.abort();

    // A rule's answer given on an upstream's answer is cached too; it has no upstream.
    // 规则在上游的回答上给出的应答也进缓存；它没有上游。
    let (upstream, task) = spawn_echo_upstream(300).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "static",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }],
                "response_actions_on_match": [{ "type": "static_ip_response", "ip": "192.0.2.7" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    for _ in 0..2 {
        engine
            .handle_packet(&query("static.example"), peer())
            .await
            .unwrap();
    }
    let sources = recorder.cache_sources();
    assert_eq!(sources.len(), 1, "{sources:#?}");
    assert_eq!(sources[0].1, None);
    task.abort();
}

/// 配置文件读完以后、监视开始重载之前改了：监视在读之前装好，这次改动排着队，开始以后照样重载。以前读完配置、建好引擎才装
/// 监视，这中间的改动丢了，内核一直用着旧配置
/// The configuration file changing after it was read and before the watch starts reloading:
/// the watch is installed before the read, so the change waits in line and is reloaded once it
/// starts. The watch used to go in only once the configuration was read and the engine built,
/// and a change in between was lost, the kernel keeping the old configuration
#[tokio::test]
async fn a_config_change_made_before_the_watch_starts_is_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let v1 = static_config("192.0.2.1");
    std::fs::write(&path, &v1).unwrap();

    let watch = kixdns::watcher::ConfigWatch::new(&path);
    let (config, source) = kixdns::config::load_config_with_source(&path).expect("load");
    let v2 = static_config("192.0.2.2");
    atomically_replace(&path, &v2);

    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(RuntimePipelineConfig::from_config(config).expect("compile"))
        .observer(recorder.clone())
        .config_source(&path, &source)
        .build()
        .expect("build engine");
    let _watching = watch.start(engine.clone(), source).expect("start");

    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::ConfigLoaded { generation: 2, source, .. }
                            if source.as_deref() == Some(v2.as_str())
                    )
                })
            })
            .await,
        "the change made before the start must be reloaded: {:#?}",
        recorder.events()
    );
}

/// 写 `contents`，修改时间定成 `modified` / Writes `contents`, the modification time set to `modified`
fn write_modified_at(path: &Path, contents: &str, modified: std::time::SystemTime) {
    std::fs::write(path, contents).expect("write config");
    std::fs::File::options()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(modified))
        .expect("set modification time");
}

/// 监视装好、读完配置以后报来一次改动，监视开始以后读出启动时读到的那份 `read`，交回引擎和它的观察者。`write` 在读完
/// 以后、开始之前改文件，参数是读之前的修改时间
/// The watch installed and the configuration read, a change is reported, and once the watch
/// starts it reads what startup read as `read`; the engine and its observer are handed back.
/// `write` changes the file after the read and before the start, given the modification time
/// from before the read
fn watch_started_after(
    path: &Path,
    read: &str,
    write: impl FnOnce(std::time::SystemTime),
) -> (Engine, Arc<Recorder>, kixdns::watcher::FileWatch) {
    std::fs::write(path, read).unwrap();
    let modified = std::fs::metadata(path).unwrap().modified().unwrap();
    let watch = kixdns::watcher::ConfigWatch::new(path);
    let (config, source) = kixdns::config::load_config_with_source(path).expect("load");
    write(modified);
    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(RuntimePipelineConfig::from_config(config).expect("compile"))
        .observer(recorder.clone())
        .config_source(path, &source)
        .build()
        .expect("build engine");
    let watching = watch.start(engine.clone(), source).expect("start");
    (engine, recorder, watching)
}

/// 报来的改动之后文件还是读之前的样子、内容和启动时读到的一字不差：不重载，代数还是 1。macOS 的 FSEvents 会把装监视
/// 之前不久的写入这样报给刚装上的监视（这里装监视之前刚写过）；inotify 这里报的是打开来写、一个字没写就关上。以前同一份
/// 配置在启动以后又重载一次，配置里有问题时多记一条重载失败
/// The file, after the change reported, looking as it did before it was read and holding word
/// for word what startup read: no reload, the generation still 1. macOS's FSEvents reports a
/// write made shortly before the watch was installed this way to the watch just installed
/// (here it was written just before); what inotify reports here is the file opened for writing
/// and closed with nothing written. The same configuration used to be reloaded once more after
/// startup, a failed reload logged besides for a configuration with a problem
#[tokio::test]
async fn a_change_reported_to_the_config_as_read_at_startup_is_not_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let v1 = static_config("192.0.2.1");
    let (engine, recorder, _watching) = watch_started_after(&path, &v1, |_| {
        drop(std::fs::File::options().write(true).open(&path).unwrap());
    });

    // 比读到写完的最长等待（0.3 秒不再写）久得多 / Far longer than the longest wait for a write to
    // be over (0.3 seconds without writing)
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(engine.config_generation(), 1, "{:#?}", recorder.events());
}

/// 启动以后一字不差地再存一次，这是开始以后的头一次改动，照样重载：存过以后文件就不是读之前的样子了，跳过的只是还是那个
/// 样子的（见 `watcher::ConfigWatch::start_reporting`）
/// Saved again word for word after startup, the first change since the start, it is reloaded
/// all the same: once saved the file no longer looks as it did before the read, and only one
/// still looking so is skipped (see `watcher::ConfigWatch::start_reporting`)
#[tokio::test]
async fn the_config_saved_again_word_for_word_after_startup_is_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let v1 = static_config("192.0.2.1");
    let (_engine, recorder, _watching) = watch_started_after(&path, &v1, |_| {});

    // 一秒以后存的那样，修改时间往后挪了 / As saved a second later, the modification time moved on
    let later = std::fs::metadata(&path).unwrap().modified().unwrap() + Duration::from_secs(1);
    write_modified_at(&path, &v1, later);
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events
                    .iter()
                    .any(|event| matches!(event, Event::ConfigLoaded { generation: 2, .. }))
            })
            .await,
        "saved again, the config must be reloaded: {:#?}",
        recorder.events()
    );
}

/// 修改时间只精确到秒的文件系统上，读完以后同一秒里改成一样长的别的内容，修改时间和长度都没变，照样重载：内容对不上
/// On a file system keeping the modification time to the second, other content of the same
/// length written within the second after the read, its time and length unchanged, is
/// reloaded all the same: the content differs
#[tokio::test]
async fn a_change_of_the_same_length_and_time_after_the_read_is_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let (v1, v2) = (static_config("192.0.2.1"), static_config("192.0.2.2"));
    assert_eq!(v1.len(), v2.len());
    let (_engine, recorder, _watching) = watch_started_after(&path, &v1, |modified| {
        write_modified_at(&path, &v2, modified)
    });

    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::ConfigLoaded { generation: 2, source, .. }
                            if source.as_deref() == Some(v2.as_str())
                    )
                })
            })
            .await,
        "the change must be reloaded: {:#?}",
        recorder.events()
    );
}

/// 跳过只管头一次重载之前：重载过以后文件又变回启动时读之前的样子（`cp -p` 从备份还原：内容、长度、修改时间都和那时
/// 一样），照样重载。不然内核一直跑着改过的那份，文件却已经还原了
/// The skip holds only until the first reload: once reloaded, the file put back as it was
/// before startup read it (restored from a backup with `cp -p`: content, length and
/// modification time all as then) is reloaded all the same. Else the kernel would keep
/// running the changed configuration with the file already restored
#[tokio::test]
async fn the_config_restored_as_read_at_startup_after_a_reload_is_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let (v1, v2) = (static_config("192.0.2.1"), static_config("192.0.2.2"));
    let (_engine, recorder, _watching) = watch_started_after(&path, &v1, |_| {});
    /// 重载到了第 `at_least` 代以后、读的是 `wanted` / Reloaded to generation `at_least` or later, reading `wanted`
    fn loaded(at_least: u64, wanted: &str) -> impl Fn(&[Event]) -> bool + '_ {
        move |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    Event::ConfigLoaded { generation, source, .. }
                        if *generation >= at_least && source.as_deref() == Some(wanted)
                )
            })
        }
    }

    let before_read = std::fs::metadata(&path).unwrap().modified().unwrap();
    write_modified_at(&path, &v2, before_read + Duration::from_secs(1));
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), loaded(2, &v2))
            .await,
        "the change must be reloaded: {:#?}",
        recorder.events()
    );
    let backup = dir.path().join("pipeline.json.bak");
    write_modified_at(&backup, &v1, before_read);
    std::fs::rename(&backup, &path).unwrap();
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), loaded(3, &v1))
            .await,
        "the restored config must be reloaded: {:#?}",
        recorder.events()
    );
}

#[tokio::test]
async fn hot_reload_reports_success_and_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let v1 = static_config("192.0.2.1");
    std::fs::write(&path, &v1).unwrap();

    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(runtime_config(&v1))
        .listener_label("edge")
        .observer(recorder.clone())
        .config_source(&path, &v1)
        .build()
        .expect("build engine");
    assert_eq!(
        recorder.drain(),
        vec![Event::ConfigLoaded {
            generation: 1,
            path: Some(path.clone()),
            source: Some(v1.clone()),
        }]
    );

    let _watch = kixdns::watcher::ConfigWatch::new(&path)
        .start(engine.clone(), v1.clone())
        .expect("start");

    // Successful reload: re-swap until the watcher reports the new generation.
    // 成功重载：重复替换直到 watcher 上报新的代数。
    let v2 = static_config("192.0.2.2");
    let mut reloaded = false;
    for _ in 0..20 {
        atomically_replace(&path, &v2);
        if recorder
            .wait_for(Duration::from_millis(500), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::ConfigLoaded { generation, path: p, source }
                            if *generation >= 2
                                && p.as_deref() == Some(path.as_path())
                                && source.as_deref() == Some(v2.as_str())
                    )
                })
            })
            .await
        {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "config_loaded must be reported after a hot reload"
    );
    assert!(engine.config_generation() >= 2);
    let response = engine
        .handle_packet(&query("reload.example"), peer())
        .await
        .unwrap();
    let answer = Message::from_bytes(&response).unwrap();
    assert!(matches!(
        answer.answers.first().map(|record| &record.data),
        Some(RData::A(address)) if address.0 == std::net::Ipv4Addr::new(192, 0, 2, 2)
    ));
    let generation_after_success = engine.config_generation();
    recorder.drain();

    // Failed reload: invalid JSON keeps the previous configuration and is
    // reported once the bounded retries are exhausted.
    // 失败重载：无效 JSON 保留旧配置，重试耗尽后上报。
    let mut failed = false;
    for _ in 0..10 {
        atomically_replace(&path, "{ \"pipelines\": [");
        if recorder
            .wait_for(Duration::from_secs(2), |events| {
                events.iter().any(|event| {
                    matches!(event, Event::ConfigReloadFailed { path: p, error } if p == &path && error.contains("line"))
                })
            })
            .await
        {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "config_reload_failed must be reported: {:#?}",
        recorder.events()
    );
    assert!(
        !recorder
            .events()
            .iter()
            .any(|event| matches!(event, Event::ConfigLoaded { .. })),
        "a rejected configuration must not be reported as loaded"
    );
    assert_eq!(engine.config_generation(), generation_after_success);
}

/// Two clients the inflight tests tell apart: `LEADER` sends first.
/// inflight 测试区分的两个客户端：`LEADER` 先发。
const LEADER: &str = "127.0.0.1:53000";
const FOLLOWER: &str = "127.0.0.2:53000";

/// Request id of the `Started` event from `client`.
fn request_id_from(events: &[Event], client: &str) -> u64 {
    let client: SocketAddr = client.parse().unwrap();
    events
        .iter()
        .find_map(|event| match event {
            Event::Started { id, client: c, .. } if *c == client => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no request_started from {client}: {events:#?}"))
}

/// Send the query to the held upstream with a `forward` or an `allow`
/// action (`allow` forwards to the default upstream), either straight from
/// the entry pipeline or after a response jump. With the jump, each client has
/// its own entry pipeline, so the two requests only meet in "shared".
/// 用 `forward` 或 `allow`（`allow` 转发到默认上游）把查询发往扣住应答的上游：
/// 或直接在入口 pipeline，或经响应跳转之后。
/// 跳转时两个客户端各有自己的入口 pipeline，两个请求只在 "shared" 相遇。
fn inflight_config(held: &str, echo: &str, action: &str, via_jump: bool) -> String {
    let held_action = if action == "forward" {
        serde_json::json!({ "type": "forward", "upstream": held, "transport": "udp" })
    } else {
        serde_json::json!({ "type": action })
    };
    let settings = serde_json::json!({
        "default_upstream": held,
        "upstream_timeout_ms": 5000,
        "enable_tcp_fallback": false
    });
    let held_rule = serde_json::json!({
        "name": "held",
        "matchers": [{ "type": "any" }],
        "actions": [held_action]
    });
    if !via_jump {
        return serde_json::json!({
            "settings": settings,
            "pipelines": [{ "id": "main", "rules": [held_rule] }]
        })
        .to_string();
    }
    // 跟随者等在领头者响应跳转之前登记的条目上，领头者跳过去拿到最终的应答再交给它
    // The follower waits on the entry the leader registered before its response jump, which
    // the leader hands the final answer it gets over there
    serde_json::json!({
        "settings": settings,
        "pipelines": [
            {
                "id": "entry",
                "rules": [{
                    "name": "echo-then-jump",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": echo, "transport": "udp" }],
                    "response_matchers": [{ "type": "upstream_equals", "value": echo }],
                    "response_actions_on_match": [
                        { "type": "jump_to_pipeline", "pipeline": "shared" }
                    ]
                }]
            },
            { "id": "shared", "rules": [held_rule] }
        ]
    })
    .to_string()
}

/// Send the same query from `LEADER`, then from `FOLLOWER` once the leader's
/// query is at the held upstream and the follower has had time to reach it.
/// 先由 `LEADER` 发出查询，待其到达上游、且跟随者有时间赶上后，再由 `FOLLOWER` 发同一查询。
async fn start_leader_and_follower(
    engine: &Engine,
    recorder: &Recorder,
    held: &HeldUpstream,
) -> (
    tokio::task::JoinHandle<Result<bytes::Bytes, UnreadableQuery>>,
    tokio::task::JoinHandle<Result<bytes::Bytes, UnreadableQuery>>,
) {
    let send = |client: &str| {
        let engine = engine.clone();
        let client: SocketAddr = client.parse().unwrap();
        tokio::spawn(async move { engine.handle_packet(&query("shared.example"), client).await })
    };
    let leader = send(LEADER);
    let at_upstream = recorder
        .wait_for(Duration::from_secs(2), |events| {
            events.iter().any(|event| {
                matches!(event, Event::UpstreamAttempt { upstream, .. } if *upstream == held.addr)
            })
        })
        .await;
    assert!(at_upstream, "{:#?}", recorder.events());
    let follower = send(FOLLOWER);
    tokio::time::sleep(Duration::from_millis(200)).await;
    (leader, follower)
}

#[tokio::test]
async fn a_request_that_takes_an_inflight_result_reports_joining_it() {
    let (echo, echo_task) = spawn_echo_upstream(60).await;
    // Each row reaches a different place the engine shares in-flight results:
    // `forward` and `allow`, from the entry pipeline and after a response jump.
    // 每行对应引擎共享 in-flight 结果的一处：`forward` 与 `allow`，入口 pipeline 与响应跳转之后。
    for (action, via_jump) in [
        ("forward", false),
        ("allow", false),
        ("forward", true),
        ("allow", true),
    ] {
        let mut held = HeldUpstream::spawn().await;
        let raw = inflight_config(&held.addr, &echo, action, via_jump);
        let (engine, recorder) = observed_engine(&raw);
        let (leader, follower) = start_leader_and_follower(&engine, &recorder, &held).await;
        held.release();
        let leader = leader.await.unwrap().unwrap();
        let follower = follower.await.unwrap().unwrap();
        assert_eq!(rcode_of(&leader), ResponseCode::NoError);
        assert_eq!(rcode_of(&follower), ResponseCode::NoError);

        let case = format!("{action} via_jump={via_jump}");
        assert_eq!(held.queries(), 1, "{case}: one query reached the upstream");
        let events = recorder.events();
        let leader_events = events_of(&events, request_id_from(&events, LEADER));
        let follower_id = request_id_from(&events, FOLLOWER);
        let follower_events = events_of(&events, follower_id);
        assert!(
            !leader_events.contains(&Event::InflightJoined {
                id: request_id_from(&events, LEADER)
            }),
            "{case}: {leader_events:#?}"
        );
        assert!(
            follower_events.contains(&Event::InflightJoined { id: follower_id }),
            "{case}: {follower_events:#?}"
        );
        assert!(
            !follower_events.iter().any(|event| {
                matches!(event, Event::UpstreamAttempt { upstream, .. } if *upstream == held.addr)
            }),
            "{case}: the follower sent no query of its own: {follower_events:#?}"
        );
        assert_eq!(
            follower_events.last(),
            Some(&finished(follower_id)),
            "{case}"
        );
    }
    echo_task.abort();
}

#[tokio::test]
async fn a_request_whose_inflight_query_is_dropped_queries_by_itself() {
    let mut held = HeldUpstream::spawn().await;
    let raw = inflight_config(&held.addr, "127.0.0.1:9", "forward", false);
    let (engine, recorder) = observed_engine(&raw);
    let (leader, follower) = start_leader_and_follower(&engine, &recorder, &held).await;
    // The leader goes away before its query is answered.
    // 领头的请求在其查询得到应答之前离开。
    leader.abort();
    let leader_gone = recorder
        .wait_for(Duration::from_secs(2), |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    Event::Finished {
                        status: RequestStatus::Cancelled,
                        ..
                    }
                )
            })
        })
        .await;
    assert!(leader_gone, "{:#?}", recorder.events());
    held.release();
    let follower = follower.await.unwrap().unwrap();
    assert_eq!(rcode_of(&follower), ResponseCode::NoError);

    assert_eq!(held.queries(), 2, "the follower sent its own query");
    let events = recorder.events();
    let follower_id = request_id_from(&events, FOLLOWER);
    let follower_events = events_of(&events, follower_id);
    assert!(
        !follower_events.contains(&Event::InflightJoined { id: follower_id }),
        "{follower_events:#?}"
    );
    assert!(
        follower_events.contains(&Event::UpstreamAttempt {
            id: follower_id,
            upstream: held.addr.clone(),
            transport: Transport::Udp,
        }),
        "{follower_events:#?}"
    );
}

#[tokio::test]
async fn a_tagged_handle_reports_its_transport_on_both_paths() {
    let (engine, recorder) = observed_engine(&static_config("192.0.2.1"));
    let tcp = engine.clone().with_client_transport(ClientTransport::Tcp);

    tcp.handle_packet(&query("tagged.example"), peer())
        .await
        .unwrap();
    assert!(matches!(
        tcp.handle_packet_fast(&query("tagged.example"), peer()),
        Some(FastPathResponse::Direct(_))
    ));
    // The handle it was cloned from is untouched.
    // 被克隆的原句柄不受影响。
    engine
        .handle_packet(&query("untagged.example"), peer())
        .await
        .unwrap();

    let transports: Vec<(String, Option<ClientTransport>)> = recorder
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Started {
                qname, transport, ..
            } => Some((qname, transport)),
            _ => None,
        })
        .collect();
    assert_eq!(
        transports,
        [
            ("tagged.example".to_string(), Some(ClientTransport::Tcp)),
            ("tagged.example".to_string(), Some(ClientTransport::Tcp)),
            ("untagged.example".to_string(), None),
        ]
    );
}

/// 入口只跳转、目标转发的配置 / A config whose entry only jumps and whose target forwards
fn jump_config(upstream: &str, settings: serde_json::Value) -> String {
    serde_json::json!({
        "settings": settings,
        "pipelines": [
            {
                "id": "main",
                "rules": [{
                    "name": "to-group",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                }]
            },
            {
                "id": "group",
                "rules": [{
                    "name": "fwd",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
                }]
            }
        ]
    })
    .to_string()
}

/// 一个请求选中的 pipeline、响应缓存的查找结果和上游尝试，按发生顺序
/// The pipelines a request selected, its response-cache lookups and outcomes, and
/// its upstream attempts, in order
fn cache_trail(events: &[Event], request_id: u64) -> Vec<String> {
    events_of(events, request_id)
        .into_iter()
        .filter_map(|event| match event {
            Event::Pipeline { pipeline, .. } => Some(format!("pipeline {pipeline}")),
            Event::CacheLookup { .. } => Some("lookup".to_owned()),
            Event::CacheMiss { .. } => Some("miss".to_owned()),
            Event::CacheHit { kind, .. } => Some(format!("hit {kind:?}")),
            Event::UpstreamAttempt { .. } => Some("upstream".to_owned()),
            _ => None,
        })
        .collect()
}

/// 跳转过的请求按入口和目标各查一次响应缓存，每次查找都恰好跟一个命中或未命中。
/// 第二次查同一个名字时，目标那次查找命中，请求不再去问上游。
/// A request that jumps looks in the response cache once for its entry pipeline and
/// once for its target, and each lookup is followed by exactly one hit or miss.
/// Asking for the same name again hits on the target lookup and goes nowhere upstream.
#[tokio::test]
async fn a_jumped_request_looks_up_the_cache_again_for_its_target() {
    let (upstream, _echo) = spawn_echo_upstream(300).await;
    let raw = jump_config(
        &upstream,
        serde_json::json!({ "default_upstream": "127.0.0.1:9", "min_ttl": 0 }),
    );
    let (engine, recorder) = observed_engine(&raw);

    engine
        .handle_packet(&query("jumped.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "jumped.example");
    assert_eq!(
        cache_trail(&events, id),
        [
            "pipeline main",
            "lookup",
            "miss",
            "pipeline group",
            "lookup",
            "miss",
            "upstream"
        ]
    );

    engine
        .handle_packet(&query("jumped.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "jumped.example");
    assert_eq!(
        cache_trail(&events, id),
        [
            "pipeline main",
            "lookup",
            "miss",
            "pipeline group",
            "lookup",
            "hit Fresh"
        ]
    );
}

/// 跳转后找到的过期应答和不跳转时一样按 serve_stale 处理：立刻给出过期应答，由后台去刷新，
/// 请求本身不去问上游。以前跳转过的请求要先等上游，上游失败了才拿到过期应答。
/// An expired answer found after a jump is handled per serve_stale just as without a
/// jump: the stale answer goes out at once and a background refresh renews it, while
/// the request itself does not go upstream. A request that jumped used to wait for
/// the upstream and only got the stale answer when that failed.
#[tokio::test]
async fn an_expired_answer_found_after_a_jump_is_served_stale() {
    let (upstream, _echo) = spawn_echo_upstream(1).await;
    let raw = jump_config(
        &upstream,
        serde_json::json!({
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0
        }),
    );
    let (engine, recorder) = observed_engine(&raw);

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    recorder.drain();
    tokio::time::sleep(Duration::from_millis(1200)).await;

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "stale.example");
    assert_eq!(
        cache_trail(&events, id),
        [
            "pipeline main",
            "lookup",
            "miss",
            "pipeline group",
            "lookup",
            "hit Stale"
        ]
    );
}

/// 一个请求走过的路：选中的 pipeline、响应缓存的查找和结果、命中的请求阶段规则和作出的决定，按发生顺序。快速路径没有的不算：
/// 它不另报规则缓存的查找，命中也记着是不是在快速路径上
/// The way a request went: the pipelines it selected, its response-cache lookups and
/// outcomes, the request-phase rules that matched and the decisions made, in order. What the
/// fast path has no counterpart of is left out: it reports no rule cache lookup of its own,
/// and a match tells whether it came on the fast path
fn way_of(events: &[Event], request_id: u64) -> Vec<String> {
    events_of(events, request_id)
        .into_iter()
        .filter_map(|event| match event {
            Event::Pipeline { pipeline, .. } => Some(format!("pipeline {pipeline}")),
            Event::CacheLookup { .. } => Some("lookup".to_owned()),
            Event::CacheMiss { .. } => Some("miss".to_owned()),
            Event::CacheHit { kind, .. } => Some(format!("hit {kind:?}")),
            Event::Rule {
                pipeline,
                rule,
                decision,
                ..
            } => Some(format!("rule {pipeline}/{rule} {decision:?}")),
            Event::Decision {
                pipeline,
                rule,
                detail,
                ..
            } => Some(format!("decision {pipeline}/{rule:?} {detail:?}")),
            _ => None,
        })
        .collect()
}

/// 快速路径跟着跳转在目标的缓存里答上的请求，上报的路和完整路径答它时一样：两个 pipeline 都选中过，入口的缓存查过没查到，
/// 跳转规则命中、决定跳走，目标的缓存命中。以前快速路径遇到跳转就交给异步路径
/// A request the fast path answers from the target's cache after following a jump reports
/// the way the full path reports when it answers: both pipelines selected, the entry's cache
/// looked in and missed, the jump rule matched and deciding the jump, the target's cache hit.
/// The fast path used to hand a jump to the async path
#[tokio::test]
async fn a_jump_followed_on_the_fast_path_is_reported_as_on_the_full_path() {
    let (upstream, _echo) = spawn_echo_upstream(300).await;
    let raw = jump_config(
        &upstream,
        serde_json::json!({ "default_upstream": "127.0.0.1:9", "min_ttl": 0 }),
    );
    let (engine, recorder) = observed_engine(&raw);
    engine
        .handle_packet(&query("jumped.example"), peer())
        .await
        .unwrap();
    recorder.drain();

    engine
        .handle_packet(&query("jumped.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let full = way_of(&events, request_id_for(&events, "jumped.example"));
    assert_eq!(
        full,
        [
            "pipeline main",
            "lookup",
            "miss",
            "rule main/to-group Jump",
            "decision main/Some(\"to-group\") Jump { pipeline: \"group\" }",
            "pipeline group",
            "lookup",
            "hit Fresh"
        ]
    );

    assert!(matches!(
        engine.handle_packet_fast(&query("jumped.example"), peer()),
        Some(FastPathResponse::CacheHit { .. })
    ));
    let events = recorder.drain();
    assert_eq!(
        way_of(&events, request_id_for(&events, "jumped.example")),
        full
    );
}

/// Response-phase decisions of `id`: what its answer checks decided.
/// 请求 `id` 的响应阶段决定：回答检查作出的决定。
fn response_decisions(events: &[Event], id: u64) -> Vec<(String, Option<String>, Detail)> {
    events_of(events, id)
        .into_iter()
        .filter_map(|event| match event {
            Event::Decision {
                pipeline,
                rule,
                phase: RulePhase::Response,
                detail,
                ..
            } => Some((pipeline, rule, detail)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn response_actions_report_the_decision_they_make() {
    let (echo, upstream_task) = spawn_echo_upstream(60).await;
    // The echo upstream answers 127.0.0.1, which every check below matches.
    // 回声上游回 127.0.0.1，下面的检查都会命中它。
    let check = |name: &str, domain: &str, actions: serde_json::Value| {
        serde_json::json!({
            "name": name,
            "matchers": [{ "type": "domain_suffix", "value": domain }],
            "actions": [{ "type": "forward", "upstream": echo, "transport": "udp" }],
            "response_matchers": [{ "type": "response_answer_ip", "cidr": "127.0.0.0/8" }],
            "response_actions_on_match": actions
        })
    };
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 200,
            "enable_tcp_fallback": false
        },
        "pipelines": [
            {
                "id": "main",
                "rules": [
                    check("deny", "deny.example", serde_json::json!([{ "type": "deny" }])),
                    check("jump", "jump.example", serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "local" }])),
                    check("keep", "keep.example", serde_json::json!([{ "type": "log" }])),
                    check("pass", "pass.example", serde_json::json!([{ "type": "continue" }])),
                    {
                        "name": "rescue",
                        "matchers": [{ "type": "domain_suffix", "value": "dead.example" }],
                        "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "transport": "udp" }],
                        "response_actions_on_miss": [{ "type": "static_ip_response", "ip": "10.9.9.9" }]
                    },
                    {
                        "name": "rest",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }]
                    }
                ]
            },
            {
                "id": "local",
                "rules": [{
                    "name": "answer",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "10.0.0.1" }]
                }]
            }
        ]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    for name in [
        "deny.example",
        "jump.example",
        "keep.example",
        "pass.example",
        "dead.example",
    ] {
        let _ = engine.handle_packet(&query(name), peer()).await.unwrap();
    }
    let events = recorder.drain();
    let decided = |qname: &str| response_decisions(&events, request_id_for(&events, qname));

    assert_eq!(
        decided("deny.example"),
        [(
            "main".to_owned(),
            Some("deny".to_owned()),
            Detail::Static {
                rcode: ResponseCode::Refused,
                answers: 0
            }
        )]
    );
    assert_eq!(
        decided("jump.example"),
        [(
            "main".to_owned(),
            Some("jump".to_owned()),
            Detail::Jump {
                pipeline: "local".into()
            }
        )]
    );
    // Keeping the upstream's answer names the upstream that gave it.
    // 沿用上游应答时写的是给出应答的那个上游。
    assert_eq!(
        decided("keep.example"),
        [(
            "main".to_owned(),
            Some("keep".to_owned()),
            Detail::Forward {
                upstream: echo.clone(),
                transport: Some(Transport::Udp)
            }
        )]
    );
    // `continue` decides nothing; the next rule's request-phase decision answers.
    // `continue` 不作决定；由下一条规则在请求阶段作出决定。
    assert!(decided("pass.example").is_empty());
    let pass = request_id_for(&events, "pass.example");
    assert!(events_of(&events, pass).iter().any(|event| matches!(
        event,
        Event::Decision { rule: Some(rule), phase: RulePhase::Request, .. } if rule == "rest"
    )));
    // A failed upstream with `response_actions_on_miss`: the miss actions answer.
    // 上游失败、规则有 `response_actions_on_miss`：由 on_miss 动作应答。
    assert_eq!(
        decided("dead.example"),
        [(
            "main".to_owned(),
            Some("rescue".to_owned()),
            Detail::Static {
                rcode: ResponseCode::NoError,
                answers: 1
            }
        )]
    );
    upstream_task.abort();
}

#[tokio::test]
async fn a_kept_answer_names_the_transport_that_carried_it() {
    // The address carries its own `tcp://` prefix and the rule names no transport.
    // 地址自带 `tcp://` 前缀，规则不写 transport。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = spawn_tcp_dns_server(listener).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 300 },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "keep",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": format!("tcp://{address}") }],
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "127.0.0.0/8" }],
                "response_actions_on_match": [{ "type": "log" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let _ = engine
        .handle_packet(&query("carried.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "carried.example");
    assert_eq!(
        response_decisions(&events, id),
        [(
            "main".to_owned(),
            Some("keep".to_owned()),
            Detail::Forward {
                upstream: address,
                transport: Some(Transport::Tcp)
            }
        )]
    );
    server.abort();
}

/// A pipeline whose one rule forwards to `upstream` and, when the answer comes
/// from it, jumps to `target`.
/// 只有一条规则的 pipeline：转发给 `upstream`，应答来自它时跳到 `target`。
fn forward_then_jump(id: &str, upstream: &str, target: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "rules": [{
            "name": format!("{id}-check"),
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }],
            "response_matchers": [{ "type": "upstream_equals", "value": upstream }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": target }]
        }]
    })
}

#[tokio::test]
async fn a_check_that_jumps_back_into_a_visited_pipeline_does_not_hang() {
    let (echo, echo_task) = spawn_echo_upstream(60).await;
    // Back into a pipeline the jump path already went through, and back into
    // the one the request entered by, whose entry the caller registered.
    // 跳回跳转路上走过的 pipeline，以及跳回请求进来时的那个（它的条目由调用方登记）。
    for (case, pipelines) in [
        (
            "jump path",
            [
                forward_then_jump("main", &echo, "loop"),
                forward_then_jump("loop", &echo, "loop"),
            ],
        ),
        (
            "entry",
            [
                forward_then_jump("main", &echo, "loop"),
                forward_then_jump("loop", &echo, "main"),
            ],
        ),
    ] {
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 500,
                "response_jump_limit": 3
            },
            "pipelines": pipelines
        })
        .to_string();
        let (engine, recorder) = observed_engine(&raw);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            engine.handle_packet(&query("again.example"), peer()),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: the query hung"))
        .unwrap();
        // The jump limit ends the loop / 由跳转上限结束循环
        assert_eq!(rcode_of(&response), ResponseCode::ServFail, "{case}");
        let events = recorder.drain();
        let id = request_id_for(&events, "again.example");
        assert!(
            !events_of(&events, id).contains(&Event::InflightJoined { id }),
            "{case}: the request never joins its own query"
        );
    }
    echo_task.abort();
}

#[tokio::test]
async fn a_continue_inside_a_jump_target_enters_it_once() {
    let (echo, echo_task) = spawn_echo_upstream(60).await;
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 500 },
        "pipelines": [
            forward_then_jump("main", &echo, "second"),
            {
                "id": "second",
                "rules": [
                    {
                        "name": "pass",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": echo, "transport": "udp" }],
                        "response_matchers": [{ "type": "upstream_equals", "value": echo }],
                        "response_actions_on_match": [{ "type": "continue" }]
                    },
                    {
                        "name": "rest",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }]
                    }
                ]
            }
        ]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    let _ = engine
        .handle_packet(&query("once.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "once.example");
    let entered: Vec<String> = events_of(&events, id)
        .into_iter()
        .filter_map(|event| match event {
            Event::Pipeline { pipeline, .. } => Some(pipeline),
            _ => None,
        })
        .collect();
    assert_eq!(entered, ["main", "second"]);
    echo_task.abort();
}

#[tokio::test]
async fn a_continue_after_the_last_jump_does_not_count_as_a_jump() {
    let (echo, echo_task) = spawn_echo_upstream(60).await;
    // `main`'s check jumps to `second` (one of two jumps left), whose rule-level
    // jump to `third` uses the last one; `third` continues past an answer and
    // its next rule answers.
    // `main` 的检查跳到 `second`（两次跳转剩一次），`second` 的规则级跳转用掉最后一次进入
    // `third`；`third` 越过一个应答，由下一条规则回答。
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 500,
            "response_jump_limit": 2
        },
        "pipelines": [
            forward_then_jump("main", &echo, "second"),
            {
                "id": "second",
                "rules": [{
                    "name": "onward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "jump_to_pipeline", "pipeline": "third" }]
                }]
            },
            {
                "id": "third",
                "rules": [
                    {
                        "name": "pass",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": echo, "transport": "udp" }],
                        "response_matchers": [{ "type": "upstream_equals", "value": echo }],
                        "response_actions_on_match": [{ "type": "continue" }]
                    },
                    {
                        "name": "rest",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }]
                    }
                ]
            }
        ]
    })
    .to_string();
    let (engine, _recorder) = observed_engine(&raw);
    let response = engine
        .handle_packet(&query("last.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let answer = Message::from_bytes(&response).unwrap();
    assert_eq!(answer.answers.len(), 1, "{answer:?}");
    echo_task.abort();
}

/// UDP upstream that answers every query like `spawn_echo_upstream`, after `delay`.
/// 像 `spawn_echo_upstream` 一样应答每个查询，但先等 `delay`。
async fn spawn_slow_upstream(delay: Duration) -> (String, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let socket = Arc::clone(&socket);
            let query = buf[..n].to_vec();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Some(response) = echo_answer(&query, 60) {
                    let _ = socket.send_to(&response, peer).await;
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn requests_that_jump_into_each_others_pipeline_do_not_wait_forever() {
    // Each client enters its own pipeline, and each pipeline's check jumps into
    // the other: each request holds its entry pipeline's query and finds the
    // other's in flight where it lands.
    // 两个客户端各进各的 pipeline，两边的检查互相跳进对方：每个请求握着自己入口 pipeline
    // 的查询，落脚处又碰上对方正在进行的那个。
    let (slow, slow_task) = spawn_slow_upstream(Duration::from_millis(200)).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 300,
            "response_jump_limit": 2
        },
        "pipeline_select": [
            {
                "pipeline": "p",
                "matchers": [{ "type": "client_ip", "cidr": "127.0.0.1/32" }]
            },
            { "pipeline": "q", "matchers": [{ "type": "any" }] }
        ],
        "pipelines": [
            forward_then_jump("p", &slow, "q"),
            forward_then_jump("q", &slow, "p")
        ]
    })
    .to_string();
    let (engine, _recorder) = observed_engine(&raw);
    let send = |client: &str| {
        let engine = engine.clone();
        let client: SocketAddr = client.parse().unwrap();
        tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(3),
                engine.handle_packet(&query("each.example"), client),
            )
            .await
        })
    };
    let (first, second) = (send(LEADER), send(FOLLOWER));
    for (client, outcome) in [
        (LEADER, first.await.unwrap()),
        (FOLLOWER, second.await.unwrap()),
    ] {
        let response = outcome
            .unwrap_or_else(|_| panic!("{client}: waited on the other request for good"))
            .unwrap();
        // Both loop until the jump limit / 两个都一直跳到跳转上限
        assert_eq!(rcode_of(&response), ResponseCode::ServFail, "{client}");
    }
    slow_task.abort();
}

/// 开着 serve_stale_client_timeout_ms 时，过期应答在客户端等待时间里等不到刷新回来，就当作 stale
/// 提供，按 StaleClientTimeout 上报，不是 Stale
/// With serve_stale_client_timeout_ms on, an expired answer whose refresh does not come
/// back within the client wait is served stale and reported as StaleClientTimeout, not
/// Stale
#[tokio::test]
async fn a_stale_answer_after_the_client_wait_is_reported_as_a_client_timeout() {
    let (upstream, answering) = spawn_silenceable_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 200
        },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "fwd",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
        }] }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);
    engine
        .handle_packet(&query("wait.example"), peer())
        .await
        .unwrap();
    // 上游不再应答，刷新回不来 / The upstream answers no more, so no refresh comes back
    answering.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    recorder.drain();

    engine
        .handle_packet(&query("wait.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "wait.example");
    assert_eq!(
        cache_trail(&events, id),
        ["pipeline main", "lookup", "hit StaleClientTimeout"]
    );
}

/// 先各问一遍写进缓存；一秒之后各从完整路径和快速路径命中一次。应答的 TTL 是 60 秒、刷新阈值
/// 99% 时，这时刚好到了刷新时机（还剩 59 秒）
/// Ask each once into the cache; a second later hit each once from the full and once
/// from the fast path. With a 60-second TTL and a 99% threshold the refresh is just due
/// then (59 seconds left)
async fn ask_then_hit_on_both_paths(engine: &Engine, qnames: [&str; 2]) {
    for qname in qnames {
        engine.handle_packet(&query(qname), peer()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for qname in qnames {
        engine.handle_packet(&query(qname), peer()).await.unwrap();
        engine.handle_packet_fast(&query(qname), peer());
    }
}

/// 为 `qname` 发起过的后台刷新 / The background refreshes started for `qname`
fn background_refreshes(events: &[Event], qname: &str) -> usize {
    events
        .iter()
        .filter(|event| {
            matches!(event, Event::Started { qname: name, background: true, .. } if name == qname)
        })
        .count()
}

/// 规则直接给出的静态应答不进响应缓存，再问时也就不发起后台刷新，完整路径和快速路径一样。同一份
/// 设置下，上游来的应答照常刷新，说明刷新时机确实到了。
/// A static answer the rules give outright stays out of the response cache, so asking
/// again starts no background refresh, on the full and the fast path alike. With the same
/// settings an upstream's answer is refreshed, so the refresh was due.
#[tokio::test]
async fn a_cached_static_answer_starts_no_background_refresh() {
    let (upstream, _echo) = spawn_echo_upstream(60).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            // 开着 min_ttl 也不缓存规则直接给出的 / Not cached for min_ttl either
            "min_ttl": 60,
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 99,
            "cache_refresh_min_ttl": 0
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "static",
                    "matchers": [{ "type": "domain_suffix", "value": "static.test" }],
                    "actions": [{ "type": "static_txt_response", "text": ["hello"] }]
                },
                {
                    "name": "fwd",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    ask_then_hit_on_both_paths(&engine, ["static.test", "forwarded.test"]).await;
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                background_refreshes(events, "forwarded.test") > 0
            })
            .await,
        "the upstream's answer is refreshed: {:#?}",
        recorder.events()
    );
    assert_eq!(background_refreshes(&recorder.events(), "static.test"), 0);
}

/// 可刷新的 TTL 低于 `cache_refresh_min_ttl` 的应答，命中时不发起后台刷新，完整路径和快速路径
/// 一样；不低于它的照常刷新。
/// An answer whose refreshable TTL is below `cache_refresh_min_ttl` starts no background
/// refresh when hit, on the full and the fast path alike; one not below it is refreshed.
#[tokio::test]
async fn an_answer_below_the_refresh_minimum_starts_no_background_refresh() {
    let (short, _short) = spawn_echo_upstream(20).await;
    let (long, _long) = spawn_echo_upstream(60).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 99,
            "cache_refresh_min_ttl": 40
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "short",
                    "matchers": [{ "type": "domain_suffix", "value": "short.test" }],
                    "actions": [{ "type": "forward", "upstream": short, "transport": "udp" }]
                },
                {
                    "name": "long",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": long, "transport": "udp" }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    ask_then_hit_on_both_paths(&engine, ["short.test", "long.test"]).await;
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                background_refreshes(events, "long.test") > 0
            })
            .await,
        "the answer at the minimum is refreshed: {:#?}",
        recorder.events()
    );
    assert_eq!(background_refreshes(&recorder.events(), "short.test"), 0);
}

/// 剩余 TTL 还没降到阈值以下的命中不发起后台刷新：阈值 50%、TTL 60 秒的应答，一秒之后还剩 59
/// 秒，不刷新；TTL 2 秒的应答一秒之后只剩 1 秒，照常刷新。完整路径和快速路径一样。
/// A hit whose remaining TTL is still above the threshold starts no background refresh:
/// with a 50% threshold, an answer of TTL 60 has 59 seconds left a second later and is not
/// refreshed, while one of TTL 2 has 1 second left and is. The same on both paths.
#[tokio::test]
async fn a_hit_above_the_refresh_threshold_starts_no_background_refresh() {
    let (early, _early) = spawn_echo_upstream(60).await;
    let (due, _due) = spawn_echo_upstream(2).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 50,
            "cache_refresh_min_ttl": 0
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "due",
                    "matchers": [{ "type": "domain_suffix", "value": "due.test" }],
                    "actions": [{ "type": "forward", "upstream": due, "transport": "udp" }]
                },
                {
                    "name": "early",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": early, "transport": "udp" }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    ask_then_hit_on_both_paths(&engine, ["early.test", "due.test"]).await;
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                background_refreshes(events, "due.test") > 0
            })
            .await,
        "the answer past its threshold is refreshed: {:#?}",
        recorder.events()
    );
    assert_eq!(background_refreshes(&recorder.events(), "early.test"), 0);
}

/// 一段超过 255 字节、总长超过 65535 字节的静态 TXT / Static TXT with a segment over 255
/// bytes, and with a total over 65535 bytes
fn oversize_txt_config() -> String {
    serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "segment",
                    "matchers": [{ "type": "domain_suffix", "value": "segment.test" }],
                    "actions": [{ "type": "static_txt_response", "text": ["x".repeat(256)] }]
                },
                {
                    "name": "total",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_txt_response", "text": vec!["y".repeat(250); 300] }]
                }
            ]
        }]
    })
    .to_string()
}

/// 装不进一条记录的静态 TXT，请求阶段和响应阶段一样回 SERVFAIL：引擎自己答，请求照常结束。以前
/// 请求阶段遇到超长的一段时请求以错误结束（观察者看到 Failed），SERVFAIL 由监听器自己构造；总长
/// 超长时拼出一个 NOERROR、TC 置位、没有答案的应答，后面跟着一大段没人认的字节。
/// A static TXT that does not fit a record is answered SERVFAIL in the request phase as in
/// the response phase: by the engine, the request completing as usual. A segment that was
/// too long used to end the request with an error (Failed to the observer), the listener
/// building the SERVFAIL itself; a total that was too long gave a NOERROR answer with TC
/// set and no records, trailed by a run of bytes nobody reads.
#[tokio::test]
async fn a_static_txt_that_does_not_fit_a_record_is_answered_servfail() {
    let (engine, recorder) = observed_engine(&oversize_txt_config());
    for qname in ["segment.test", "total.test"] {
        let answer = engine
            .handle_packet(&query(qname), peer())
            .await
            .unwrap_or_else(|error| panic!("{qname}: {error:#}"));
        let message = Message::from_bytes(&answer).unwrap();
        assert_eq!(
            message.metadata.response_code,
            ResponseCode::ServFail,
            "{qname}"
        );
        assert!(!message.metadata.truncation, "{qname}");
        assert!(message.answers.is_empty(), "{qname}");
    }
    let finished: Vec<RequestStatus> = recorder
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Finished { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    assert_eq!(finished, [RequestStatus::Completed; 2]);
}

/// 请求阶段的静态 TXT 没写 ttl 时，记录的 TTL 是 300 秒 / A request-phase static TXT without
/// a ttl answers with a TTL of 300 seconds
#[tokio::test]
async fn a_static_txt_without_a_ttl_answers_for_300_seconds() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "txt",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_txt_response", "text": ["hello"] }]
            }]
        }]
    })
    .to_string();
    let (engine, _recorder) = observed_engine(&raw);
    // 静态 TXT 只答 TXT 和 ANY 查询 / A static TXT answers only TXT and ANY queries
    let mut txt = Message::new(0x1234, MessageType::Query, OpCode::Query);
    txt.metadata.recursion_desired = true;
    txt.add_query(Query::query(
        Name::from_str("txt.test").unwrap(),
        RecordType::TXT,
    ));
    let answer = engine
        .handle_packet(&txt.to_vec().unwrap(), peer())
        .await
        .unwrap();
    let message = Message::from_bytes(&answer).unwrap();
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].ttl, 300);
}
