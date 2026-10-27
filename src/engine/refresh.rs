use std::sync::Arc;
use std::time::Instant;

use hickory_proto::rr::{DNSClass, RecordType};
use tracing::{debug, error, warn};

use crate::ecs_scope::EcsReach;
use crate::engine::Engine;
use crate::engine::types::EngineInner;
use crate::engine::utils::RefreshingGuard;
use crate::matcher::Requester;

/// 后台刷新要更新的缓存条目：它所在的槽位，以及它适用的请求方
/// The cache entry a background refresh renews: its slot, and the requesters it
/// applies to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTarget {
    pub slot: u64,
    /// The pipeline the slot belongs to / 槽位所属的 pipeline
    pub pipeline: Arc<str>,
    pub reach: EcsReach,
    /// 被刷新那份应答取得的时刻（见 `CacheEntry::fetched_at`）：据此认出它
    /// When the renewed answer was fetched (see `CacheEntry::fetched_at`): it is
    /// recognised by this
    pub fetched_at: Instant,
    /// 刷新开始的时刻：之后取得的应答来自刷新本身或别的请求
    /// When the refresh started: answers fetched later come from the refresh or other requests
    pub started: Instant,
    /// 被刷新的请求自己带的 ECS 选项，按缓存看到的样子。读不懂的选项放不回重放的包里，所以刷新
    /// 按这一项判断，而不是从重放的包里读
    /// The ECS option the renewed request carried itself, as the cache saw it. One
    /// nobody can read cannot be put back into the replayed packet, so the refresh
    /// judges by this rather than by what it reads out of that packet
    pub client_ecs: Option<crate::ecs::EcsKey>,
}

impl RefreshTarget {
    pub fn new(slot: u64, pipeline: Arc<str>, reach: EcsReach, fetched_at: Instant) -> Self {
        Self {
            slot,
            pipeline,
            reach,
            fetched_at,
            started: Instant::now(),
            client_ecs: None,
        }
    }

    /// 同上，带着被刷新请求自己的 ECS 选项（见 `client_ecs`）
    /// The same, with the renewed request's own ECS option (see `client_ecs`)
    pub fn with_client_ecs(mut self, client_ecs: Option<crate::ecs::EcsKey>) -> Self {
        self.client_ecs = client_ecs;
        self
    }

    /// 刷新标记的键：每个条目各一个，同一槽位里不同子网的条目可以同时刷新
    /// The key of the refresh mark: one per entry, so entries for different subnets
    /// in one slot refresh independently
    pub fn mark(&self) -> u64 {
        Self::mark_of(self.slot, &self.reach)
    }

    /// 槽位 `slot` 里适用于 `reach` 的条目的刷新标记 / The refresh mark of the entry for `reach` in slot `slot`
    pub fn mark_of(slot: u64, reach: &EcsReach) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        slot.hash(&mut hasher);
        reach.hash(&mut hasher);
        hasher.finish()
    }
}

/// spawn_background_refresh spawns a task to refresh a DNS record in the background.
///
/// 防止无限循环的保护措施：
/// Protection against infinite loops:
/// 1. 打得上刷新标记才刷新（`RefreshingGuard::try_new`）
/// 2. 后台请求设置 skip_cache=true
/// 3. RefreshingGuard 确保刷新标记在任务完成后被清除
///
/// `peer_ip` is the original client IP from the request that triggered this refresh.
/// It must be the real client IP — not loopback — so that:
/// - ECS injection (RFC 7871) uses the correct client subnet
/// - Pipeline selection matches the original request path
///
/// `peer_ip` 是触发刷新的原始请求的客户端 IP。
/// 必须使用真实客户端 IP 而非回环地址，以确保：
/// - ECS 注入 (RFC 7871) 使用正确的客户端子网
/// - Pipeline 选择与原始请求路径一致
///
/// `renewed` is the cached answer to renew, in slot `slot`: its question
/// (pipeline, name, type) is the one replayed, in class `qclass`.
/// `renewed` 是槽位 `slot` 里要更新的那份应答：重放的就是它的问题（pipeline、名字、类型），
/// 类别为 `qclass`。
pub fn spawn_background_refresh(
    engine: &Engine,
    state: Arc<EngineInner>,
    renewed: &crate::cache::CacheEntry,
    slot: u64,
    qclass: DNSClass,
    requester: Requester,
) {
    let (pipeline_id, qname) = (renewed.pipeline_id.as_ref(), renewed.qname.as_ref());
    let qtype = RecordType::from(renewed.qtype);
    // 先打上刷新标记，打不上就是已经有人在刷新（见 `RefreshingGuard::try_new`）；guard 在任务
    // 结束时清掉标记，下面提前返回时也一样
    // Set the refresh mark first; failing that, someone is refreshing already (see
    // `RefreshingGuard::try_new`). The guard clears the mark when the task ends, and on
    // the early return below too
    let mark = RefreshTarget::mark_of(slot, &renewed.reach);
    let Some(guard) =
        RefreshingGuard::try_new(&engine.refreshing_bitmap, &engine.refreshing_set, mark)
    else {
        return;
    };
    let target = RefreshTarget::new(
        slot,
        renewed.pipeline_id.clone(),
        renewed.reach.clone(),
        renewed.fetched_at,
    )
    .with_client_ecs(requester.ecs);

    // Step 1: Construct standard DNS query packet
    // 步骤 1：构造标准 DNS 查询包
    // Replay the request as its client sent it, as far as routing, ECS and the cache
    // can tell: from the same address, with or without EDNS, with the client's own
    // ECS and its query bits (see `QueryFlags`). Pipeline selection and rules can
    // depend on the first two, a forward without `ecs` passes the ECS upstream, the
    // query bits change the answer and are part of its key, and the answer is
    // stored in the slot the request looked up.
    // 按客户端发来的样子重放，以路由、ECS 和缓存能分辨的为限：同一个地址，带或不带 EDNS，带着
    // 客户端自己的 ECS 和它的查询位（见 `QueryFlags`）。pipeline 的选择和规则都可能取决于前两项，
    // 不写 `ecs` 的转发会把 ECS 转给上游，查询位会改变应答、也是它的键的一部分，而应答会存进请求
    // 查过的那个槽位。
    let packet = match engine.construct_dns_packet(
        qname,
        qtype,
        qclass,
        requester.edns,
        requester.ecs.as_ref(),
        renewed.flags,
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                event = "background_refresh_construct_packet_failed",
                qname = %qname,
                qtype = ?qtype,
                error = %format_args!("{e:#}"),
                "Failed to construct DNS packet for background refresh"
            );
            return;
        }
    };

    // Step 2: Spawn the background task, which holds the refresh mark's guard
    // 步骤 2：生成后台任务，刷新标记的 guard 交给它
    let engine = engine.clone();
    let qname_owned = qname.to_string();
    let pipeline_id_owned = pipeline_id.to_string();

    tokio::spawn(async move {
        // Move guard into the async task so it clears when task completes
        // 将 guard 移动到异步任务中，这样任务完成时会清除标记
        let _guard = guard;

        // Use original client peer IP for correct ECS injection (RFC 7871) and pipeline selection.
        // Port is irrelevant — only .ip() is consumed downstream.
        //
        // 使用原始客户端 peer IP 确保正确的 ECS 注入 (RFC 7871) 和 pipeline 选择。
        // 端口无关 — 下游仅消费 .ip()。
        let peer_addr = std::net::SocketAddr::new(requester.address, 53);

        // Call handle_packet_internal with skip_cache=true and the entry it renews.
        // Together with the original peer_ip, this ensures the background refresh
        // both writes to the correct cache slot AND injects the correct ECS (RFC 7871).
        //
        // 调用 handle_packet_internal 并设置 skip_cache=true，传入要更新的条目。
        // 配合原始 peer_ip，确保后台刷新既写入正确的缓存槽，又注入正确的 ECS (RFC 7871)。
        let result = engine
            .handle_packet_internal(&packet, peer_addr, true, None, Some(target), Some(state))
            .await;

        match result {
            Ok(_resp_bytes) => {
                debug!(
                    event = "background_refresh_success",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    "Background refresh completed successfully"
                );
            }
            // The refresh mark is released as soon as the task ends, failure or not. A
            // stale hit starts a refresh only while the mark is clear, and with
            // serve_stale_client_timeout_ms the request then waits for that refresh, so
            // holding the mark for a backoff would leave it waiting for a refresh that
            // never starts.
            // 无论成败，任务一结束就释放刷新标记。过期命中只在标记空闲时才发起刷新，
            // 开着 serve_stale_client_timeout_ms 时请求随后就等这次刷新；退避期间占着
            // 标记，请求等的就是一个根本没有发起的刷新。
            Err(e) => {
                warn!(
                    event = "background_refresh_failed",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    error = %format_args!("{e:#}"),
                    "Background refresh failed"
                );
            }
        }
        // _guard dropped here, automatically clearing the refresh mark
        // _guard 在此处 drop，自动清除刷新标记
    });
}
