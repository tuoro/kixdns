use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use moka::sync::Cache;
use smallvec::SmallVec;

use crate::ecs_scope::{EcsReach, EcsView};
use crate::proto_utils::QueryFlags;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub rcode: ResponseCode,
    /// Upstream that provided this response / 提供此响应的上游服务器
    pub upstream: Option<Arc<str>>,
    // Store validation fields to handle hash collisions / 存储验证字段以处理哈希冲突
    pub qname: Arc<str>,
    pub pipeline_id: Arc<str>,
    pub qtype: u16,
    pub flags: QueryFlags,
    /// RFC 1035 §5.2: Record insertion time for TTL decrement / RFC 1035 §5.2：记录插入时间用于TTL递减
    pub inserted_at: Instant,
    /// Original minimum TTL from upstream response / 上游响应的原始最小TTL
    /// Used for cache expiration and TTL patching / 用于缓存过期与 TTL 修正
    pub original_ttl: u32,
    /// Original maximum TTL from upstream response / 上游响应的原始最大TTL
    /// Used for background refresh decisions / 用于后台刷新决策
    pub refresh_ttl: u32,
    /// 这份应答适用于槽位里的哪些请求方（RFC 7871 第 7.3 节）
    /// Which requesters of its slot this answer applies to (RFC 7871 section 7.3)
    pub reach: EcsReach,
    /// 写进缓存的时刻。缓存的 `time_to_live`（`cache_max_ttl`）按它计：这个上限原本由缓存按键
    /// 执行，而槽位每写入一次都会让键重新计时。`inserted_at` 在过期应答续期时会往前调，不能用。
    /// When it was written into the cache. The cache's `time_to_live`
    /// (`cache_max_ttl`) counts from here: the cache used to enforce that limit per
    /// key, and every write to a slot restarts the key's clock. `inserted_at` is
    /// moved back when a stale answer is renewed, so it cannot serve.
    pub stored_at: Instant,
    /// 这份应答从上游（或规则）得到的时刻，过期续用时照抄：后台刷新据此认出它要更新的那份。
    /// `inserted_at` 续用时往前调，`stored_at` 续用时重新计，都不能用。
    /// When this answer came from the upstream (or the rules), copied when a stale
    /// answer is renewed: a background refresh recognises the answer it renews by
    /// it. `inserted_at` is moved back and `stored_at` restarts on renewal, so
    /// neither can serve.
    pub fetched_at: Instant,
}

impl CacheEntry {
    /// Build a cache entry from a DNS response and its cache/refresh TTLs.
    pub fn from_response(
        bytes: Bytes,
        rcode: ResponseCode,
        upstream: Option<Arc<str>>,
        qname: &str,
        pipeline_id: Arc<str>,
        qtype: u16,
        flags: QueryFlags,
        ttls: (u32, u32),
    ) -> Self {
        Self {
            bytes,
            rcode,
            upstream,
            qname: Arc::from(qname),
            pipeline_id,
            qtype,
            flags,
            inserted_at: Instant::now(),
            original_ttl: ttls.0,
            refresh_ttl: ttls.1,
            reach: EcsReach::default(),
            stored_at: Instant::now(),
            fetched_at: Instant::now(),
        }
    }

    /// 同一份条目，适用于 `reach` / The same entry, applying to `reach`
    pub fn with_reach(mut self, reach: EcsReach) -> Self {
        self.reach = reach;
        self
    }

    /// 还在 TTL 之内 / Still within its TTL
    pub fn is_fresh(&self) -> bool {
        self.inserted_at.elapsed().as_secs() < u64::from(self.original_ttl)
    }

    fn same_question(&self, other: &Self) -> bool {
        self.qtype == other.qtype
            && self.flags == other.flags
            && self.qname == other.qname
            && self.pipeline_id == other.pipeline_id
    }

    /// 存了 `max_age` 以上：单独存放时缓存本来就会淘汰它
    /// Stored `max_age` or longer ago: the cache would have evicted it stored alone
    fn outlived(&self, max_age: Option<Duration>, now: Instant) -> bool {
        max_age.is_some_and(|max| now.saturating_duration_since(self.stored_at) >= max)
    }

    /// Clone entry with a refreshed `inserted_at` for serve-stale TTL reset / 克隆条目并刷新 inserted_at 用于过期缓存 TTL 重置
    /// Sets `inserted_at` to `now - original_ttl` so the entry appears freshly expired / 将 inserted_at 设置为 now - original_ttl，使条目看上去刚刚过期
    pub fn clone_with_refreshed_ttl(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            rcode: self.rcode,
            upstream: self.upstream.clone(),
            qname: self.qname.clone(),
            pipeline_id: self.pipeline_id.clone(),
            qtype: self.qtype,
            flags: self.flags,
            inserted_at: Instant::now() - Duration::from_secs(self.original_ttl as u64),
            original_ttl: self.original_ttl,
            refresh_ttl: self.refresh_ttl,
            reach: self.reach.clone(),
            // A renewed entry is written again, which restarted the key's clock before
            // slots existed / 续期的条目重新写入，在有槽位之前这会让键重新计时
            stored_at: Instant::now(),
            fetched_at: self.fetched_at,
        }
    }
}

/// 缓存条目要回答的问题，用来排除哈希冲突 / The question a cached entry must answer, to rule out hash collisions
#[derive(Debug, Clone, Copy)]
pub struct CachedQuestion<'a> {
    pub qname: &'a str,
    pub pipeline_id: &'a str,
    pub qtype: u16,
    pub flags: QueryFlags,
}

impl CachedQuestion<'_> {
    pub fn matches(&self, entry: &CacheEntry) -> bool {
        entry.qtype == self.qtype
            && entry.flags == self.flags
            && entry.qname.as_ref() == self.qname
            && entry.pipeline_id.as_ref() == self.pipeline_id
    }
}

/// 一个槽位最多存多少个网段的应答（RFC 7871 第 11.3 节建议限制每个查询的网段数）
/// How many networks' answers one slot keeps at most (RFC 7871 section 11.3 asks
/// for a limit on networks per query)
pub const MAX_NETWORKS_PER_SLOT: usize = 64;

/// 一个问题在一个 pipeline 里的所有应答，每份适用于一部分请求方（见 `CacheEntry::reach`）。
/// 绝大多数槽位只有一份。
/// Every answer to one question in one pipeline, each applying to some of the
/// requesters (see `CacheEntry::reach`). Nearly every slot holds one.
#[derive(Debug, Clone, Default)]
pub struct CacheSlot {
    entries: SmallVec<[Arc<CacheEntry>; 1]>,
}

impl CacheSlot {
    /// 适用于 `view`、且是 `question` 的那份应答：前缀最长的优先，其次最新的（RFC 7871 第
    /// 7.3.2 节的最长前缀匹配）。新鲜与否不参与挑选：更具体的应答过期了，就由它的过期处理
    /// 决定（续用或重新转发），而不是退回更宽的旧应答。存了 `max_age` 以上的不算。
    /// The answer to `question` that applies to `view`: the longest prefix first,
    /// then the newest (the longest-prefix match of RFC 7871 section 7.3.2).
    /// Freshness does not take part: when the more specific answer has expired, its
    /// expiry handling decides (serve stale or forward again) rather than falling
    /// back to a wider, older answer. Answers stored `max_age` or longer ago do not
    /// count.
    pub fn select(
        &self,
        view: &EcsView,
        question: impl Fn(&CacheEntry) -> bool,
        max_age: Option<Duration>,
        now: Instant,
    ) -> Option<Arc<CacheEntry>> {
        self.entries
            .iter()
            .filter(|entry| {
                question(entry) && !entry.outlived(max_age, now) && entry.reach.admits(view)
            })
            .max_by_key(|entry| (entry.reach.specificity(), entry.inserted_at))
            .cloned()
    }

    /// 存入 `entry` 后的槽位。它取代同一问题下适用于同样请求方的旧应答，去掉存了 `max_age`
    /// 以上的应答；满了先淘汰只适用于一部分子网的应答（过期的先、早的先），只按带不带 ECS
    /// 区分的应答（见 `EcsReach::is_broad`）最后才淘汰，免得一个客户端用一串 ECS 子网挤掉
    /// 其他所有人共用的那份。
    /// The slot after storing `entry`. It replaces an older answer to the same
    /// question for the same requesters, and drops answers stored `max_age` or
    /// longer ago. When full it evicts answers for some subnets first (expired,
    /// then oldest first), and answers told apart only by whether ECS is sent (see
    /// `EcsReach::is_broad`) last, so one client cannot push out the answer
    /// everyone else shares with a run of ECS subnets.
    pub fn with(&self, entry: Arc<CacheEntry>, max_age: Option<Duration>) -> Self {
        let now = Instant::now();
        let mut entries: SmallVec<[Arc<CacheEntry>; 1]> = self
            .entries
            .iter()
            .filter(|old| {
                !(old.same_question(&entry) && old.reach == entry.reach)
                    && !old.outlived(max_age, now)
            })
            .cloned()
            .collect();
        while entries.len() >= MAX_NETWORKS_PER_SLOT {
            let evicted = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, old)| (old.reach.is_broad(), old.is_fresh(), old.inserted_at))
                .map(|(index, _)| index)
                .unwrap_or(0);
            entries.remove(evicted);
        }
        entries.push(entry);
        Self { entries }
    }

    /// 把 `old` 这一份换成 `new` 后的槽位；`old` 已经不在时为 None
    /// The slot with `old` itself replaced by `new`; None when `old` is gone
    pub fn replacing(&self, old: &Arc<CacheEntry>, new: Arc<CacheEntry>) -> Option<Self> {
        let index = self
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(entry, old))?;
        let mut entries = self.entries.clone();
        entries[index] = new;
        Some(Self { entries })
    }

    /// 刷新之后的槽位：刷新写进了一份适用范围不同的新应答（`written`，例如上游的作用范围
    /// 变窄了），它就不会取代被刷新的那份（`renewed`）；那份留着，每次命中都会再发起一次
    /// 刷新。上游最新的说法已经在新应答里，所以去掉它，它适用的请求方各自重新查询。刷新什么
    /// 都没写时，它照旧留着。None 表示不用改动。
    /// The slot after a refresh. A refresh that wrote a new answer with another
    /// reach (`written`; the upstream narrowed its scope, say) does not replace the
    /// answer it renewed (`renewed`); left in place, that one would start another
    /// refresh on every hit. The upstream's latest word is in the new answer, so the
    /// renewed one goes and its requesters ask again. When the refresh wrote
    /// nothing, it stays as it was. None means nothing changes.
    pub fn after_refresh(
        &self,
        question: &CachedQuestion<'_>,
        renewed: &EcsReach,
        renewed_fetched_at: Instant,
        written: &EcsReach,
        started: Instant,
    ) -> Option<Self> {
        if written == renewed {
            return None;
        }
        let rewritten = self.entries.iter().any(|entry| {
            question.matches(entry) && entry.fetched_at >= started && entry.reach == *written
        });
        if !rewritten {
            return None;
        }
        self.without(|entry| {
            question.matches(entry)
                && entry.reach == *renewed
                && entry.fetched_at == renewed_fetched_at
        })
    }

    /// 去掉 `remove` 选中的应答后的槽位；什么都没去掉时为 None
    /// The slot without the answers `remove` picks; None when it picks none
    pub fn without(&self, remove: impl Fn(&CacheEntry) -> bool) -> Option<Self> {
        if !self.entries.iter().any(|entry| remove(entry)) {
            return None;
        }
        Some(Self {
            entries: self
                .entries
                .iter()
                .filter(|entry| !remove(entry))
                .cloned()
                .collect(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &Arc<CacheEntry>> {
        self.entries.iter()
    }
}

/// Use u64 hash as key to avoid allocation during lookup / 使用 u64 哈希作为键以避免查找时的内存分配
///  Slots and answers are behind `Arc`s, so a cache hit clones no entry fields
///  槽位和应答都在 `Arc` 后面，缓存命中不复制条目的字段
pub type DnsCache = Cache<u64, Arc<CacheSlot>>;

/// 创建带 TTL 的 DNS 缓存。容量按应答份数计：每个槽位按它存的应答份数计重。
/// Create DNS cache with TTL. Capacity counts answers: each slot weighs as many
/// as it holds.
#[inline]
pub fn new_cache(max_capacity: u64, ttl_secs: u64) -> DnsCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .weigher(|_, slot: &Arc<CacheSlot>| slot.len().max(1) as u32)
        .time_to_live(Duration::from_secs(ttl_secs))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecs::EcsKey;
    use crate::ecs_scope::{EcsSource, ForwardEcs, ReplyEcs, Sent};

    const QUESTION: CachedQuestion<'static> = CachedQuestion {
        flags: crate::proto_utils::QueryFlags::RECURSIVE,
        qname: "example.com",
        pipeline_id: "main",
        qtype: 1,
    };

    fn subnet(text: &str) -> EcsKey {
        let (address, prefix) = text.split_once('/').unwrap();
        let prefix: u8 = prefix.parse().unwrap();
        EcsKey::from_ip(address.parse().unwrap(), prefix, prefix)
    }

    fn view(client: &str) -> EcsView {
        EcsView {
            peer: "10.0.0.1".parse().unwrap(),
            client: Some(subnet(client)),
        }
    }

    /// 透传的 /24 子网拿到作用范围 `scope` 的应答后的范围（None：应答不带 ECS）
    /// The reach of a passed-through /24 whose reply has scope `scope` (None: no ECS)
    fn reach(client: &str, scope: Option<u8>) -> EcsReach {
        let mut reach = EcsReach::default();
        let reply = match scope {
            Some(scope) => ReplyEcs::Subnet {
                subnet: subnet(client),
                scope,
            },
            None => ReplyEcs::Absent,
        };
        reach.record(
            ForwardEcs {
                source: EcsSource::Client,
                sent: Sent::Subnet(subnet(client)),
            },
            reply,
            true,
        );
        reach
    }

    fn entry(reach: EcsReach, ttl: u32, age: Duration) -> Arc<CacheEntry> {
        let mut entry = CacheEntry::from_response(
            Bytes::new(),
            ResponseCode::NoError,
            None,
            "example.com",
            Arc::from("main"),
            1,
            crate::proto_utils::QueryFlags::RECURSIVE,
            (ttl, ttl),
        )
        .with_reach(reach);
        entry.inserted_at -= age;
        entry.stored_at -= age;
        entry.fetched_at -= age;
        Arc::new(entry)
    }

    fn select(slot: &CacheSlot, client: &str) -> Option<Arc<CacheEntry>> {
        slot.select(
            &view(client),
            |entry| QUESTION.matches(entry),
            None,
            Instant::now(),
        )
    }

    /// 查询位不同的应答各存各的：新应答不取代另一种查询位的，查找也只认自己那几位
    /// Answers for other query bits are kept apart: a new answer does not replace
    /// one for other bits, and a lookup only takes its own
    #[test]
    fn an_answer_is_only_for_its_own_query_bits() {
        let for_bits = |flags| {
            Arc::new(
                CacheEntry::from_response(
                    Bytes::new(),
                    ResponseCode::NoError,
                    None,
                    "example.com",
                    Arc::from("main"),
                    1,
                    flags,
                    (300, 300),
                )
                .with_reach(reach("198.51.100.0/24", None)),
            )
        };
        let dnssec = QueryFlags::new(true, false, true);
        let (plain_answer, dnssec_answer) = (for_bits(QueryFlags::RECURSIVE), for_bits(dnssec));
        let slot = CacheSlot::default()
            .with(plain_answer.clone(), None)
            .with(dnssec_answer.clone(), None);
        assert_eq!(slot.len(), 2);
        for (flags, answer) in [
            (QueryFlags::RECURSIVE, &plain_answer),
            (dnssec, &dnssec_answer),
        ] {
            let question = CachedQuestion { flags, ..QUESTION };
            let selected = slot
                .select(
                    &view("198.51.100.0/24"),
                    |entry| question.matches(entry),
                    None,
                    Instant::now(),
                )
                .expect("its own answer");
            assert!(Arc::ptr_eq(&selected, answer), "{flags:?}");
        }
        let unanswered = CachedQuestion {
            flags: QueryFlags::new(true, true, false),
            ..QUESTION
        };
        assert!(!slot.entries().any(|entry| unanswered.matches(entry)));
    }

    #[test]
    fn the_longest_prefix_wins_even_when_it_has_expired() {
        let wide = entry(reach("198.51.100.0/24", Some(16)), 300, Duration::ZERO);
        let narrow = entry(
            reach("198.51.100.0/24", Some(24)),
            1,
            Duration::from_secs(5),
        );
        let slot = CacheSlot::default()
            .with(wide.clone(), None)
            .with(narrow.clone(), None);
        assert!(Arc::ptr_eq(
            &select(&slot, "198.51.100.0/24").unwrap(),
            &narrow
        ));
        assert!(Arc::ptr_eq(&select(&slot, "198.51.7.0/24").unwrap(), &wide));
        assert!(select(&slot, "203.0.113.0/24").is_none());
    }

    #[test]
    fn a_new_answer_replaces_only_the_one_for_the_same_requesters() {
        let wide = entry(reach("198.51.100.0/24", Some(16)), 300, Duration::ZERO);
        let narrow = entry(reach("198.51.100.0/24", Some(24)), 300, Duration::ZERO);
        let newer_wide = entry(reach("198.51.100.0/24", Some(16)), 300, Duration::ZERO);
        let slot = CacheSlot::default()
            .with(wide.clone(), None)
            .with(narrow.clone(), None)
            .with(newer_wide.clone(), None);
        assert_eq!(slot.len(), 2);
        assert!(slot.entries().any(|entry| Arc::ptr_eq(entry, &newer_wide)));
        assert!(slot.entries().any(|entry| Arc::ptr_eq(entry, &narrow)));
    }

    /// 续期只换掉那一份，不碰更新、更具体的应答 / Renewing replaces that one only, never a newer, more specific answer
    #[test]
    fn renewing_a_stale_answer_leaves_the_others_alone() {
        let wide = entry(
            reach("198.51.100.0/24", Some(16)),
            1,
            Duration::from_secs(5),
        );
        let narrow = entry(reach("198.51.100.0/24", Some(24)), 300, Duration::ZERO);
        let slot = CacheSlot::default()
            .with(wide.clone(), None)
            .with(narrow.clone(), None);
        let renewed = Arc::new(wide.clone_with_refreshed_ttl());
        let slot = slot.replacing(&wide, renewed.clone()).expect("still there");
        assert_eq!(slot.len(), 2);
        assert!(slot.entries().any(|entry| Arc::ptr_eq(entry, &renewed)));
        assert!(slot.entries().any(|entry| Arc::ptr_eq(entry, &narrow)));
        assert!(slot.replacing(&wide, renewed).is_none());
    }

    #[test]
    fn answers_past_the_cache_time_to_live_do_not_count() {
        let old = entry(
            reach("198.51.100.0/24", Some(16)),
            9000,
            Duration::from_secs(120),
        );
        let slot = CacheSlot::default().with(old, None);
        let max_age = Some(Duration::from_secs(60));
        assert!(
            slot.select(
                &view("198.51.100.0/24"),
                |entry| QUESTION.matches(entry),
                max_age,
                Instant::now()
            )
            .is_none()
        );
        let fresh = entry(reach("203.0.113.0/24", Some(24)), 300, Duration::ZERO);
        assert_eq!(slot.with(fresh, max_age).len(), 1);
    }

    /// 槽位满了，最后才淘汰按「带不带 ECS」区分、大家共用的那份
    /// A full slot evicts the shared answer told apart only by whether ECS is sent last
    #[test]
    fn a_full_slot_evicts_the_shared_answer_last() {
        let shared = entry(reach("198.51.100.0/24", None), 300, Duration::from_secs(10));
        let mut slot = CacheSlot::default().with(shared.clone(), None);
        for third in 0..MAX_NETWORKS_PER_SLOT {
            let client = format!("203.0.{third}.0/24");
            slot = slot.with(entry(reach(&client, Some(24)), 300, Duration::ZERO), None);
        }
        assert_eq!(slot.len(), MAX_NETWORKS_PER_SLOT);
        assert!(slot.entries().any(|entry| Arc::ptr_eq(entry, &shared)));
        // The shared answer still serves that subnet, but its own answer went
        // 那个子网仍由共用的那份应答服务，它自己的那份淘汰了
        let oldest = reach("203.0.0.0/24", Some(24));
        assert!(
            slot.entries().all(|entry| entry.reach != oldest),
            "the oldest subnet went"
        );
        assert!(Arc::ptr_eq(
            &select(&slot, "203.0.0.0/24").unwrap(),
            &shared
        ));
    }

    /// 刷新写进了适用范围不同的新应答，被刷新的那份就让位；什么都没写时它留着
    /// A refresh that wrote an answer with another reach retires the one it renewed;
    /// one that wrote nothing leaves it
    #[test]
    fn a_refresh_with_another_reach_retires_the_renewed_answer() {
        let renewed = entry(
            reach("198.51.100.0/24", Some(16)),
            300,
            Duration::from_secs(1),
        );
        let started = Instant::now();
        let slot = CacheSlot::default().with(renewed.clone(), None);
        let narrower = entry(reach("198.51.100.0/24", Some(24)), 300, Duration::ZERO);
        assert!(
            slot.after_refresh(
                &QUESTION,
                &renewed.reach,
                renewed.fetched_at,
                &narrower.reach,
                started,
            )
            .is_none(),
            "the refresh wrote nothing"
        );
        // Another client's answer written meanwhile is not the refresh's
        // 这期间别的客户端写入的应答不是刷新写的
        let other = entry(reach("203.0.113.0/24", Some(24)), 300, Duration::ZERO);
        let with_other = slot.with(other, None);
        assert!(
            with_other
                .after_refresh(
                    &QUESTION,
                    &renewed.reach,
                    renewed.fetched_at,
                    &narrower.reach,
                    started,
                )
                .is_none()
        );
        let slot = with_other.with(narrower.clone(), None);
        let settled = slot
            .after_refresh(
                &QUESTION,
                &renewed.reach,
                renewed.fetched_at,
                &narrower.reach,
                started,
            )
            .expect("the renewed answer goes");
        assert_eq!(settled.len(), 2);
        assert!(settled.entries().any(|entry| Arc::ptr_eq(entry, &narrower)));
        assert!(settled.entries().all(|entry| entry.reach != renewed.reach));
        // A stale renewal of the renewed answer during the refresh is still that answer
        // 刷新期间对被刷新那份的过期续用，仍是那一份
        let copy = Arc::new(renewed.clone_with_refreshed_ttl());
        let with_copy = slot.replacing(&renewed, copy).expect("still there");
        let settled = with_copy
            .after_refresh(
                &QUESTION,
                &renewed.reach,
                renewed.fetched_at,
                &narrower.reach,
                started,
            )
            .expect("the renewed copy goes");
        assert!(settled.entries().all(|entry| entry.reach != renewed.reach));
    }
}
