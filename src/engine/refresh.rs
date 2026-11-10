use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use hickory_proto::rr::{DNSClass, RecordType};
use tracing::{debug, error, warn};

use crate::cache::CacheEntry;
use crate::config::GlobalSettings;
use crate::ecs_scope::EcsReach;
use crate::engine::Engine;
use crate::engine::types::EngineInner;
use crate::engine::utils::RefreshingGuard;
use crate::matcher::Requester;

/// 一条缓存命中的刷新时机。后台刷新开着、应答来自上游、可刷新的 TTL 不低于下限时才有；剩余的
/// TTL 不超过阈值时，就到了刷新的时候
/// When a cache hit is due for a background refresh. There is one only with background
/// refresh on, for an answer from an upstream whose refreshable TTL is not below the
/// minimum; it is due once the remaining TTL is at most the threshold
#[derive(Clone, Copy)]
pub(crate) struct RefreshCheck {
    /// 可刷新的 TTL 还剩几秒 / Seconds left of the refreshable TTL
    pub(crate) remaining_ttl: u32,
    /// 剩到几秒以内就刷新 / Refresh once this many seconds or fewer are left
    pub(crate) threshold: u64,
}

impl RefreshCheck {
    pub(crate) fn of(
        settings: &GlobalSettings,
        hit: &CacheEntry,
        elapsed_secs: u32,
    ) -> Option<Self> {
        (settings.cache_background_refresh
            && hit.upstream.is_some()
            && hit.refresh_ttl >= settings.cache_refresh_min_ttl)
            .then(|| Self {
                remaining_ttl: hit.refresh_ttl.saturating_sub(elapsed_secs),
                threshold: (hit.refresh_ttl as u64
                    * settings.cache_refresh_threshold_percent as u64)
                    / 100,
            })
    }

    pub(crate) fn due(&self) -> bool {
        self.remaining_ttl as u64 <= self.threshold
    }
}

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

    /// 槽位 `slot` 里适用于 `reach` 的条目的刷新标记：每个条目各一个，同一槽位里不同子网的条目可以
    /// 同时刷新
    /// The refresh mark of the entry for `reach` in slot `slot`: one per entry, so entries
    /// for different subnets in one slot refresh independently
    pub fn mark_of(slot: u64, reach: &EcsReach) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        slot.hash(&mut hasher);
        reach.hash(&mut hasher);
        hasher.finish()
    }
}

/// RFC 8767 第 5 节的失败复查时间：一份应答刷新失败以后，这么久之内不再为它发起刷新，命中它的请求直接拿过期应答，
/// 开着 `serve_stale_client_timeout_ms` 也不等。过了这段时间，头一次命中再试一次
/// The failure recheck time of RFC 8767 section 5: once an answer's refresh fails, no refresh
/// is started for it for this long, and requests hitting it get the stale answer at once,
/// without waiting even with `serve_stale_client_timeout_ms`. After that, the first hit tries
/// again
pub(crate) const REFRESH_FAILURE_RECHECK: Duration = Duration::from_secs(30);

/// 表里的失败多到这么多条，就清掉过了复查时间的 / Once the table holds this many failures, those past the
/// recheck time are cleared out
const REFRESH_FAILURES_PRUNED_AT: usize = 4096;

/// 一次刷新失败 / One failed refresh
#[derive(Debug, Clone, Copy)]
pub(crate) struct RefreshFailure {
    /// 失败的是哪一份应答：它取得的时刻（见 `CacheEntry::fetched_at`）。之后重新取得的应答不受影响
    /// Which answer failed: the moment it was fetched (see `CacheEntry::fetched_at`). An
    /// answer fetched again later is not affected
    pub(crate) fetched_at: Instant,
    /// 什么时候失败的 / When it failed
    pub(crate) failed_at: Instant,
}

/// 最近刷新失败的应答，按刷新标记（见 [`RefreshTarget::mark_of`]）记。只记在这张表里、不记在缓存条目上：条目上
/// 没有多余的空位，每条应答都多占一份内存不值得。表里只有复查时间之内的失败有用，过多时清掉其余的
/// The answers whose refresh failed lately, by refresh mark (see [`RefreshTarget::mark_of`]).
/// They live in this table, not on the cache entries: an entry has no room to spare, and
/// more memory for every answer is not worth it. Only failures within the recheck time
/// matter, and the rest are cleared out when the table grows
#[derive(Debug)]
pub(crate) struct RefreshFailures {
    pub(crate) map: DashMap<u64, RefreshFailure>,
    /// 下次清理时的条数：清完以后的两倍，至少 [`REFRESH_FAILURES_PRUNED_AT`]，清理的代价按次数摊开
    /// The size at which the next clearing happens: twice what is left after one, at
    /// least [`REFRESH_FAILURES_PRUNED_AT`], so clearing costs little per insert
    prune_at: AtomicUsize,
}

impl Default for RefreshFailures {
    fn default() -> Self {
        Self {
            map: DashMap::new(),
            prune_at: AtomicUsize::new(REFRESH_FAILURES_PRUNED_AT),
        }
    }
}

impl RefreshFailures {
    /// 标记为 `mark`、在 `fetched_at` 取得的那份应答，是否在复查时间之内刷新失败过
    /// Whether the answer with refresh mark `mark`, fetched at `fetched_at`, failed a
    /// refresh within the recheck time
    pub(crate) fn failed_recently(&self, mark: u64, fetched_at: Instant) -> bool {
        let Some(failure) = self.map.get(&mark).map(|failure| *failure) else {
            return false;
        };
        if failure.fetched_at != fetched_at {
            return false;
        }
        if failure.failed_at.elapsed() < REFRESH_FAILURE_RECHECK {
            return true;
        }
        self.map
            .remove_if(&mark, |_, current| current.failed_at == failure.failed_at);
        false
    }

    /// 记下这份应答的刷新刚刚失败 / Notes that this answer's refresh just failed
    fn record(&self, mark: u64, fetched_at: Instant) {
        if self.map.len() >= self.prune_at.load(Ordering::Relaxed) {
            self.map
                .retain(|_, failure| failure.failed_at.elapsed() < REFRESH_FAILURE_RECHECK);
            self.prune_at.store(
                (self.map.len() * 2).max(REFRESH_FAILURES_PRUNED_AT),
                Ordering::Relaxed,
            );
        }
        self.map.insert(
            mark,
            RefreshFailure {
                fetched_at,
                failed_at: Instant::now(),
            },
        );
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
/// `requester` is who sent the request that triggered this refresh: its real address
/// (not loopback), whether it sent EDNS, and its own ECS, so that ECS (RFC 7871) and
/// pipeline selection go as they did for that request.
///
/// `requester` 是触发刷新的那个请求的发送方：它的真实地址（不是回环地址）、带没带 EDNS、它自己的
/// ECS，这样 ECS（RFC 7871）和 pipeline 选择都和那个请求一样。
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
    // 这份应答刚刷新失败过：复查时间之内不再刷新（RFC 8767 第 5 节），故障期间不必每次命中都去问坏掉的上游
    // This answer's refresh failed lately: no refresh within the recheck time (RFC 8767
    // section 5), so a broken upstream is not asked on every hit during an outage
    if engine
        .refresh_failures
        .failed_recently(mark, renewed.fetched_at)
    {
        return;
    }
    let Some(guard) = RefreshingGuard::try_new(&engine.refreshing_set, mark) else {
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
    let fetched_at = renewed.fetched_at;
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
            // never starts. The backoff lives in `RefreshFailures` instead, which a stale
            // hit checks before it waits.
            // 无论成败，任务一结束就释放刷新标记。过期命中只在标记空闲时才发起刷新，
            // 开着 serve_stale_client_timeout_ms 时请求随后就等这次刷新；退避期间占着
            // 标记，请求等的就是一个根本没有发起的刷新。退避因此另记在 `RefreshFailures`
            // 里，过期命中在等之前先查它。
            Err(e) => {
                // 标记放开之前记下：看到标记放开的请求也就看得到这次失败
                // Noted before the mark is let go: a request that sees the mark gone sees
                // this failure too
                engine.refresh_failures.record(mark, fetched_at);
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

#[cfg(test)]
mod refresh_failures_tests {
    use super::*;

    /// 表里多到 [`REFRESH_FAILURES_PRUNED_AT`] 条时，清掉过了复查时间的、留下还在时间之内的，下次清理的门槛是清完以后的两倍
    /// Once the table reaches [`REFRESH_FAILURES_PRUNED_AT`] entries, those past the recheck
    /// time go and those within it stay, and the next clearing waits for twice what is left
    #[test]
    fn a_full_table_keeps_only_failures_within_the_recheck_time() {
        let failures = RefreshFailures::default();
        let now = Instant::now();
        let long_ago = now
            .checked_sub(REFRESH_FAILURE_RECHECK + Duration::from_secs(1))
            .expect("the clock is far enough from its start");
        let recent = REFRESH_FAILURES_PRUNED_AT as u64 * 3 / 4;
        for mark in 0..REFRESH_FAILURES_PRUNED_AT as u64 {
            let failed_at = if mark < recent { now } else { long_ago };
            failures.map.insert(
                mark,
                RefreshFailure {
                    fetched_at: now,
                    failed_at,
                },
            );
        }
        failures.record(u64::MAX, now);
        assert_eq!(failures.map.len() as u64, recent + 1);
        assert!((0..recent).all(|mark| failures.failed_recently(mark, now)));
        assert!(failures.failed_recently(u64::MAX, now));
        assert_eq!(
            failures.prune_at.load(Ordering::Relaxed),
            (recent as usize * 2).max(REFRESH_FAILURES_PRUNED_AT)
        );
    }
}
