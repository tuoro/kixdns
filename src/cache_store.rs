//! 响应缓存底下的存储：分片的哈希表，按 S3-FIFO 淘汰。
//!
//! 键是已经算好的 64 位槽位号，再用带随机密钥的 SipHash 散一遍才定分片和桶：槽位号出自不带密钥的
//! 哈希，请求方能凑出一串落在同一处的名字，带密钥的这一遍让它们照样分散开。
//!
//! 每个分片一把读写锁。读只拿读锁，给条目的访问计数加一，不动队列；写拿写锁。淘汰按 S3-FIFO
//! （Yang 等，SOSP 2023）：新条目先进小队列，在里面再被读到过才进主队列，没读到过的直接淘汰，
//! 只记下它的哈希（幽灵队列）；幽灵队列里有的条目再来时直接进主队列。主队列像 CLOCK：读到过的
//! 计数减一放回队尾，计数为零的淘汰。只问一次的名字因此挤不掉常用的。
//!
//! 容量按条目的计重算（响应缓存里见 `Arc<CacheSlot>` 的 [`Cached::weight`]），平分给各分片；一个
//! 分片整个都放不下的条目不存。条目存了 `max_age` 以上就不能再用（见 [`Cached::outlived`]）；写入时
//! 每个分片每隔 `max_age` 的 1/16（至少一分钟）清扫一轮，把这样的条目去掉，它们占的内存就退回去了，
//! 分片自己的表和队列则按用过的最大量留着。一轮清扫分到多次写入里做，每次至多走
//! `SWEEP_PLACES` 个位置，不会长时间占着写锁。
//!
//! The store under the response cache: a sharded hash table with S3-FIFO eviction.
//!
//! Keys are precomputed 64-bit slot numbers, hashed again with a randomly keyed
//! SipHash to pick the shard and bucket: slot numbers come from an unkeyed hash,
//! so a requester can make up a run of names that land in one place, and the keyed
//! pass spreads them out regardless.
//!
//! Each shard has one read-write lock. A read takes the read lock and bumps the
//! entry's access count without touching the queues; a write takes the write lock.
//! Eviction follows S3-FIFO (Yang et al., SOSP 2023): a new entry joins the small
//! queue and moves to the main queue only if it is read again while there; one
//! that was not is evicted at once, leaving only its hash behind (the ghost
//! queue), and an entry the ghost queue remembers goes straight to the main queue
//! when it comes back. The main queue works like CLOCK: an entry read since its
//! last turn has its count lowered and goes to the back, one at zero is evicted.
//! Names asked once therefore cannot push out the ones in regular use.
//!
//! Capacity counts entry weights (in the response cache, see [`Cached::weight`] of
//! `Arc<CacheSlot>`) and is split evenly across the shards; an entry too heavy for a
//! whole shard is not stored. An entry stored `max_age` or longer ago can no longer
//! serve (see [`Cached::outlived`]); on writes each shard sweeps such entries out
//! once every sixteenth of `max_age` (at least a minute), which gives their memory
//! back, while the shard's own table and queues stay at the most they ever used. A
//! round of sweeping is spread over writes, at most `SWEEP_PLACES` places each, so
//! it never holds the write lock for long.

use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use hashbrown::HashTable;

use crate::lock::RwLock;

/// 缓存里存的值 / A value kept in the cache
pub trait Cached: Clone {
    /// 计重，至少 1 / Weight, at least 1
    fn weight(&self) -> u32;
    /// 存了 `max_age` 以上、整个都不能再用了 / Stored `max_age` or longer ago, none of it usable any more
    fn outlived(&self, max_age: Duration, now: Instant) -> bool;
}

/// [`CacheStore::compute`] 的结果 / What [`CacheStore::compute`] does
pub enum Op<V> {
    /// 不改 / Leave it
    Nop,
    /// 写入这个值 / Store this value
    Put(V),
    /// 去掉 / Remove it
    Remove,
}

/// 每个分片至少分到的容量；容量小时分片少些，免得每片只剩一两个 / The least capacity per shard; a small
/// cache gets fewer shards, so no shard is left with one or two entries
const MIN_SHARD_CAPACITY: u64 = 64;
const MAX_SHARDS: u64 = 64;
/// 访问计数的上限 / Cap on the access count
const MAX_FREQ: u8 = 3;
/// 一个分片两轮清扫之间至少隔多久 / The least time between two rounds of sweeping one shard
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// 条目能存 `max_age` 时，这段时间里清扫几轮：能存一天的条目不必每分钟查一遍
/// Rounds of sweeping per `max_age`: entries that may stay a day need no look every minute
const SWEEPS_PER_MAX_AGE: u32 = 16;
/// 一次写入至多替清扫走这么多个位置，冷的时候不到 100 µs，分片再大也不会更久地占着写锁
/// The most places one write walks for the sweep, under 100 µs when cold, so the write
/// lock is held no longer however large the shard
const SWEEP_PLACES: u32 = 256;
/// 分片号取哈希的这几位：低位留给分片里的桶，最高 7 位是 hashbrown 的标签，两者都要分散
/// The hash bits that pick the shard: the low bits pick the bucket inside the shard and
/// the top 7 are hashbrown's tag, and both must stay spread
const SHARD_BITS_AT: u32 = 40;
/// 去掉了还排在队列里的位置多过存着的条目（至少这么多）时，整理一次队列把它们收回来；缓存没满时
/// 队列不动，不整理的话这样的位置会越积越多
/// When the places removed but still queued outnumber the stored entries (and at least
/// this many), the queues are tidied once to reclaim them; while the cache has room the
/// queues do not move, and without tidying such places would keep piling up
const DEAD_SLACK: u64 = 64;

pub struct CacheStore<V> {
    shards: Box<[RwLock<Shard<V>>]>,
    hasher: RandomState,
    max_age: Duration,
    sweep_every: Duration,
}

impl<V: Cached> CacheStore<V> {
    /// 计重总共不超过 `capacity`、存了 `max_age` 以上的条目不再用的缓存
    /// A cache holding at most `capacity` in weight, whose entries stop serving once stored `max_age` ago
    pub fn new(capacity: u64, max_age: Duration) -> Self {
        let shards = (capacity / MIN_SHARD_CAPACITY).clamp(1, MAX_SHARDS);
        // 取不超过它的 2 的幂，分片号就是哈希的几位 / The power of two at or below it, so a shard number is some hash bits
        let shards = 1u64 << (63 - shards.leading_zeros());
        let now = Instant::now();
        Self {
            shards: (0..shards)
                .map(|index| {
                    // 除不尽的余数分给前几片，合起来正好是 capacity / The remainder goes to the first shards, so they add up to capacity
                    let share = capacity / shards + u64::from(index < capacity % shards);
                    RwLock::new(Shard::new(share, now))
                })
                .collect(),
            hasher: RandomState::new(),
            max_age,
            sweep_every: SWEEP_EVERY.max(max_age / SWEEPS_PER_MAX_AGE),
        }
    }

    fn locate(&self, key: u64) -> (u64, &RwLock<Shard<V>>) {
        let hash = self.hasher.hash_one(key);
        let index = (hash >> SHARD_BITS_AT) as usize & (self.shards.len() - 1);
        (hash, &self.shards[index])
    }

    /// `key` 的值；读到算一次访问 / The value of `key`; a read counts as an access
    pub fn get(&self, key: u64) -> Option<V> {
        let (hash, shard) = self.locate(key);
        let shard = shard.read();
        let node = &shard.nodes[shard.find(hash, key)? as usize];
        let freq = node.freq.load(Ordering::Relaxed);
        if freq < MAX_FREQ {
            // 几个读者同时加可能少加一次，计数本来就是近似的 / Readers adding at once may lose a bump; the count is approximate anyway
            node.freq.store(freq + 1, Ordering::Relaxed);
        }
        node.value.clone()
    }

    /// 在分片的写锁里读出 `key` 的值、按 `f` 改：读和写之间不会插进别的写入
    /// Read the value of `key` and change it as `f` says, under the shard's write lock: no
    /// other write comes between the read and the write
    pub fn compute(&self, key: u64, f: impl FnOnce(Option<&V>) -> Op<V>) {
        let (hash, shard) = self.locate(key);
        let mut shard = shard.write();
        let now = Instant::now();
        if shard.sweeping.is_none()
            && now.saturating_duration_since(shard.swept_at) >= self.sweep_every
        {
            shard.swept_at = now;
            shard.sweeping = Some(0);
        }
        if shard.sweeping.is_some() {
            shard.sweep_some(self.max_age, now);
        }
        let found = shard.find(hash, key);
        let current = found.and_then(|index| shard.nodes[index as usize].value.as_ref());
        match (f(current), found) {
            (Op::Nop, _) | (Op::Remove, None) => {}
            (Op::Remove, Some(index)) => shard.remove(index),
            (Op::Put(value), found) => {
                let weight = value.weight().max(1);
                // 整个分片都放不下：存了也会马上淘汰，还要先把别的条目都挤掉。这个键原来的值已经不对了，也去掉
                // Too heavy for the whole shard: stored, it would soon go, after pushing out
                // all the others first. The key's old value is out of date by now and goes too
                if u64::from(weight) > shard.capacity {
                    if let Some(index) = found {
                        shard.remove(index);
                    }
                } else if let Some(index) = found {
                    shard.replace(index, value, weight);
                } else {
                    shard.insert(hash, key, value, weight);
                }
            }
        }
    }

    /// 写入 `key` 的值 / Store the value of `key`
    pub fn insert(&self, key: u64, value: V) {
        self.compute(key, |_| Op::Put(value));
    }

    /// 去掉 `key` / Remove `key`
    pub fn remove(&self, key: u64) {
        self.compute(key, |_| Op::Remove);
    }

    /// 去掉所有条目。旧条目在写锁外释放，读这个分片的请求不用等 / Remove every entry. The old entries
    /// are freed outside the write lock, so requests reading the shard do not wait for it
    pub fn invalidate_all(&self) {
        for shard in self.shards.iter() {
            let mut shard = shard.write();
            let (capacity, swept_at) = (shard.capacity, shard.swept_at);
            let old = std::mem::replace(&mut *shard, Shard::new(capacity, swept_at));
            drop(shard);
            drop(old);
        }
    }

    /// 存着几个键 / How many keys are stored
    pub fn entry_count(&self) -> u64 {
        self.shards.iter().map(|shard| shard.read().live).sum()
    }

    /// 存着的计重合计 / The total weight stored
    pub fn weighted_size(&self) -> u64 {
        self.shards
            .iter()
            .map(|shard| {
                let shard = shard.read();
                shard.small_weight + shard.main_weight
            })
            .sum()
    }

    /// 测试用：`key` 的访问计数，读它不算一次访问 / For tests: the access count of `key`, not counting as an access
    #[cfg(test)]
    pub(crate) fn access_count(&self, key: u64) -> Option<u8> {
        let (hash, shard) = self.locate(key);
        let shard = shard.read();
        let index = shard.find(hash, key)?;
        Some(shard.nodes[index as usize].freq.load(Ordering::Relaxed))
    }

    /// 测试用：存着的所有值 / For tests: every stored value
    #[cfg(test)]
    pub(crate) fn values(&self) -> Vec<V> {
        self.shards
            .iter()
            .flat_map(|shard| {
                let shard = shard.read();
                shard
                    .nodes
                    .iter()
                    .filter_map(|node| node.value.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// 测试用：每个分片的账都对得上 / For tests: every shard's books balance
    #[cfg(test)]
    pub(crate) fn check(&self) {
        for shard in self.shards.iter() {
            shard.read().check();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Queue {
    Small,
    Main,
}

struct Node<V> {
    key: u64,
    hash: u64,
    /// None：已经去掉，还排在队列里，轮到时才回收这个位置
    /// None: removed but still queued; the place is reclaimed when its turn comes
    value: Option<V>,
    weight: u32,
    freq: AtomicU8,
    queue: Queue,
}

struct Shard<V> {
    /// 键到 `nodes` 下标，只含还在的条目 / Key to index into `nodes`, live entries only
    table: HashTable<u32>,
    nodes: Vec<Node<V>>,
    /// 不在任何队列里、可以复用的位置 / Places in no queue, free for reuse
    free: Vec<u32>,
    small: VecDeque<u32>,
    main: VecDeque<u32>,
    /// 从小队列淘汰的哈希，值是它进幽灵队列的序号 / Hashes evicted from the small queue, each with its ghost sequence number
    ghost: HashTable<(u64, u32)>,
    ghost_order: VecDeque<(u64, u32)>,
    ghost_seq: u32,
    small_weight: u64,
    main_weight: u64,
    live: u64,
    /// 去掉了、还排在队列里的位置 / Places removed but still queued
    dead: u64,
    capacity: u64,
    swept_at: Instant,
    /// 这一轮清扫走到了哪个位置；None：这一轮走完了 / The place this round of sweeping has got to; None: the round is over
    sweeping: Option<u32>,
}

impl<V: Cached> Shard<V> {
    fn new(capacity: u64, swept_at: Instant) -> Self {
        Self {
            table: HashTable::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost: HashTable::new(),
            ghost_order: VecDeque::new(),
            ghost_seq: 0,
            small_weight: 0,
            main_weight: 0,
            live: 0,
            dead: 0,
            capacity,
            swept_at,
            sweeping: None,
        }
    }

    fn find(&self, hash: u64, key: u64) -> Option<u32> {
        self.table
            .find(hash, |&index| self.nodes[index as usize].key == key)
            .copied()
    }

    fn queue_weight(&mut self, queue: Queue) -> &mut u64 {
        match queue {
            Queue::Small => &mut self.small_weight,
            Queue::Main => &mut self.main_weight,
        }
    }

    fn insert(&mut self, hash: u64, key: u64, value: V, weight: u32) {
        // 幽灵队列记得的直接进主队列 / One the ghost queue remembers goes straight to the main queue
        let queue = match self.ghost.find_entry(hash, |&(ghost, _)| ghost == hash) {
            Ok(entry) => {
                entry.remove();
                Queue::Main
            }
            Err(_) => Queue::Small,
        };
        let node = Node {
            key,
            hash,
            value: Some(value),
            weight,
            freq: AtomicU8::new(0),
            queue,
        };
        let index = match self.free.pop() {
            Some(index) => {
                self.nodes[index as usize] = node;
                index
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        let nodes = &self.nodes;
        self.table
            .insert_unique(hash, index, |&other| nodes[other as usize].hash);
        match queue {
            Queue::Small => self.small.push_back(index),
            Queue::Main => self.main.push_back(index),
        }
        *self.queue_weight(queue) += u64::from(weight);
        self.live += 1;
        self.evict();
    }

    fn replace(&mut self, index: u32, value: V, weight: u32) {
        let node = &mut self.nodes[index as usize];
        let (queue, old) = (node.queue, node.weight);
        node.value = Some(value);
        node.weight = weight;
        let total = self.queue_weight(queue);
        *total = *total - u64::from(old) + u64::from(weight);
        self.evict();
    }

    /// 去掉还在的条目：出表、减重，位置留在队列里等轮到时回收
    /// Remove a live entry: out of the table and its weight off, its place left
    /// queued until its turn comes
    fn remove(&mut self, index: u32) {
        self.unlink(index);
        self.dead += 1;
        if self.dead > self.live.max(DEAD_SLACK) {
            self.reclaim_dead();
        }
    }

    /// 把去掉了还排着的位置从队列里拿出来，放回可复用的位置
    /// Take the places removed but still queued out of the queues, back among the free ones
    fn reclaim_dead(&mut self) {
        let (nodes, free) = (&self.nodes, &mut self.free);
        for queue in [&mut self.small, &mut self.main] {
            queue.retain(|&index| {
                let live = nodes[index as usize].value.is_some();
                if !live {
                    free.push(index);
                }
                live
            });
        }
        self.dead = 0;
    }

    /// 条目出表、减重；它的位置由调用方处理 / The entry leaves the table and its weight goes;
    /// the caller sees to its place
    fn unlink(&mut self, index: u32) {
        let node = &mut self.nodes[index as usize];
        node.value = None;
        let (hash, queue, weight) = (node.hash, node.queue, node.weight);
        if let Ok(entry) = self.table.find_entry(hash, |&other| other == index) {
            entry.remove();
        }
        *self.queue_weight(queue) -= u64::from(weight);
        self.live -= 1;
    }

    fn remember(&mut self, hash: u64) {
        self.ghost_seq = self.ghost_seq.wrapping_add(1);
        let seq = self.ghost_seq;
        match self.ghost.find_entry(hash, |&(ghost, _)| ghost == hash) {
            Ok(mut entry) => entry.get_mut().1 = seq,
            Err(_) => {
                self.ghost
                    .insert_unique(hash, (hash, seq), |&(ghost, _)| ghost);
            }
        }
        self.ghost_order.push_back((hash, seq));
        // 幽灵队列记得的个数和容量一样多 / The ghost queue remembers as many as the capacity
        while self.ghost_order.len() as u64 > self.capacity.max(1) {
            let (old, old_seq) = self
                .ghost_order
                .pop_front()
                .expect("over capacity, not empty");
            // 后来又记过一次的，按后来那次算 / One remembered again later counts from the later time
            if let Ok(entry) = self
                .ghost
                .find_entry(old, |&(ghost, seq)| ghost == old && seq == old_seq)
            {
                entry.remove();
            }
        }
    }

    fn evict(&mut self) {
        let small_target = (self.capacity / 10).max(1);
        while self.small_weight + self.main_weight > self.capacity {
            if self.small_weight >= small_target || self.main_weight == 0 {
                self.evict_small();
            } else {
                self.evict_main();
            }
        }
    }

    fn evict_small(&mut self) {
        let Some(index) = self.small.pop_front() else {
            return;
        };
        let node = &mut self.nodes[index as usize];
        if node.value.is_none() {
            self.dead -= 1;
            self.free.push(index);
        } else if *node.freq.get_mut() > 0 {
            // 在小队列里又被读到过：进主队列 / Read again while in the small queue: to the main queue
            *node.freq.get_mut() = 0;
            node.queue = Queue::Main;
            let weight = u64::from(node.weight);
            self.small_weight -= weight;
            self.main_weight += weight;
            self.main.push_back(index);
        } else {
            let hash = node.hash;
            self.unlink(index);
            self.free.push(index);
            self.remember(hash);
        }
    }

    fn evict_main(&mut self) {
        let Some(index) = self.main.pop_front() else {
            return;
        };
        let node = &mut self.nodes[index as usize];
        let freq = node.freq.get_mut();
        if node.value.is_none() {
            self.dead -= 1;
            self.free.push(index);
        } else if *freq > 0 {
            *freq -= 1;
            self.main.push_back(index);
        } else {
            self.unlink(index);
            self.free.push(index);
        }
    }

    /// 这一轮清扫接着走至多 `SWEEP_PLACES` 个位置，去掉存了 `max_age` 以上的条目
    /// Walk on at most `SWEEP_PLACES` places of this round of sweeping, removing the
    /// entries stored `max_age` or longer ago
    #[cold]
    #[inline(never)]
    fn sweep_some(&mut self, max_age: Duration, now: Instant) {
        let Some(start) = self.sweeping else {
            return;
        };
        let places = self.nodes.len() as u32;
        let end = start.saturating_add(SWEEP_PLACES).min(places);
        for index in start..end {
            if self.nodes[index as usize]
                .value
                .as_ref()
                .is_some_and(|value| value.outlived(max_age, now))
            {
                self.remove(index);
            }
        }
        self.sweeping = (end < places).then_some(end);
    }

    #[cfg(test)]
    fn check(&self) {
        let mut weights = [0u64; 2];
        let mut queued = vec![0u8; self.nodes.len()];
        let mut dead = 0;
        for (queue, indexes) in [(Queue::Small, &self.small), (Queue::Main, &self.main)] {
            for &index in indexes {
                queued[index as usize] += 1;
                let node = &self.nodes[index as usize];
                assert_eq!(node.queue, queue, "node {index} sits in the other queue");
                dead += u64::from(node.value.is_none());
                if node.value.is_some() {
                    weights[queue as usize] += u64::from(node.weight);
                    assert_eq!(
                        self.find(node.hash, node.key),
                        Some(index),
                        "live node {index} not in the table"
                    );
                }
            }
        }
        for &index in &self.free {
            queued[index as usize] += 1;
            assert!(
                self.nodes[index as usize].value.is_none(),
                "free place {index} holds a value"
            );
        }
        assert!(
            queued.iter().all(|&n| n == 1),
            "every place is in exactly one queue or the free list"
        );
        assert_eq!(weights, [self.small_weight, self.main_weight]);
        let live = self
            .nodes
            .iter()
            .filter(|node| node.value.is_some())
            .count() as u64;
        assert_eq!(live, self.live);
        assert_eq!(self.table.len() as u64, self.live);
        assert!(self.small_weight + self.main_weight <= self.capacity);
        assert_eq!(dead, self.dead);
        assert!(
            self.dead <= self.capacity.max(DEAD_SLACK),
            "{} removed places still queued",
            self.dead
        );
        assert!(self.ghost.len() <= self.ghost_order.len());
        assert!(
            self.ghost_order.len() as u64 <= self.capacity.max(1),
            "the ghost queue remembers no more than the capacity"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 测试用的值：计重和存入时刻 / A test value: its weight and when it was stored
    #[derive(Clone, Debug, PartialEq)]
    struct Value {
        id: u64,
        weight: u32,
        stored_at: Instant,
    }

    impl Cached for Value {
        fn weight(&self) -> u32 {
            self.weight
        }
        fn outlived(&self, max_age: Duration, now: Instant) -> bool {
            now.saturating_duration_since(self.stored_at) >= max_age
        }
    }

    fn value(id: u64) -> Value {
        weighted(id, 1)
    }

    fn weighted(id: u64, weight: u32) -> Value {
        Value {
            id,
            weight,
            stored_at: Instant::now(),
        }
    }

    fn put(store: &CacheStore<Value>, key: u64, value: Value) {
        store.compute(key, |_| Op::Put(value));
    }

    const DAY: Duration = Duration::from_secs(86400);

    #[test]
    fn weight_never_exceeds_the_capacity() {
        let store = CacheStore::new(1000, DAY);
        for key in 0..20_000u64 {
            put(&store, key, weighted(key, 1 + (key % 5) as u32));
            if key % 3 == 0 {
                store.get(key / 2);
            }
        }
        store.check();
        assert!(store.weighted_size() <= 1000);
        assert!(
            store.weighted_size() > 900,
            "a full cache stays nearly full"
        );
    }

    #[test]
    fn small_capacities_get_fewer_shards_and_still_hold_their_capacity() {
        for (capacity, shards) in [
            (1, 1),
            (2, 1),
            (64, 1),
            (127, 1),
            (128, 2),
            (300, 4),
            (10_000, 64),
        ] {
            let store = CacheStore::new(capacity, DAY);
            assert_eq!(store.shards.len(), shards, "capacity {capacity}");
            for key in 0..20_000 {
                put(&store, key, value(key));
            }
            store.check();
            assert_eq!(store.weighted_size(), capacity, "capacity {capacity}");
        }
    }

    #[test]
    fn capacity_is_split_across_shards_without_loss() {
        for capacity in [128, 1000, 10_000, 1_000_001] {
            let store = CacheStore::<Value>::new(capacity, DAY);
            let total: u64 = store.shards.iter().map(|shard| shard.read().capacity).sum();
            assert_eq!(total, capacity);
            assert!(store.shards.len().is_power_of_two() && store.shards.len() <= 64);
        }
    }

    #[test]
    fn names_asked_once_do_not_push_out_one_in_use() {
        let store = CacheStore::new(1000, DAY);
        put(&store, 7, value(7));
        for key in 1_000_000..1_050_000u64 {
            // 常用的那个时不时被读到 / The one in use is read now and then
            if key % 50 == 0 {
                assert!(
                    store.get(7).is_some(),
                    "the name in use was evicted by key {key}"
                );
            }
            put(&store, key, value(key));
        }
        store.check();
    }

    #[test]
    fn an_entry_never_read_again_is_evicted_first() {
        // 一个分片：顺序完全由队列决定 / One shard, so the queues alone decide the order
        let store = CacheStore::new(10, DAY);
        for key in 0..10 {
            put(&store, key, value(key));
        }
        for key in 1..10 {
            store.get(key);
        }
        put(&store, 100, value(100));
        assert!(
            store.get(0).is_none(),
            "the one entry never read again goes first"
        );
        for key in 1..10 {
            assert!(store.get(key).is_some(), "key {key} was read and stays");
        }
        store.check();
    }

    #[test]
    fn a_name_evicted_unread_comes_back_into_the_main_queue() {
        let store = CacheStore::new(10, DAY);
        put(&store, 0, value(0));
        for key in 1..=10 {
            put(&store, key, value(key));
        }
        assert!(store.get(0).is_none(), "evicted unread");
        put(&store, 0, value(0));
        let (hash, shard) = store.locate(0);
        let shard = shard.read();
        let index = shard.find(hash, 0).expect("stored again");
        assert_eq!(shard.nodes[index as usize].queue, Queue::Main);
        shard.check();
    }

    #[test]
    fn compute_sees_the_current_value_and_can_keep_replace_or_remove_it() {
        let store = CacheStore::new(100, DAY);
        store.compute(1, |current| {
            assert!(current.is_none());
            Op::Nop
        });
        assert_eq!(store.entry_count(), 0);
        put(&store, 1, weighted(1, 3));
        store.compute(1, |current| {
            assert_eq!(current.map(|value| value.id), Some(1));
            Op::Nop
        });
        assert_eq!(store.weighted_size(), 3);
        put(&store, 1, weighted(2, 5));
        assert_eq!(store.get(1).map(|value| value.id), Some(2));
        assert_eq!((store.entry_count(), store.weighted_size()), (1, 5));
        store.compute(1, |_| Op::Remove);
        assert!(store.get(1).is_none());
        assert_eq!((store.entry_count(), store.weighted_size()), (0, 0));
        // 去掉不存在的键什么都不做 / Removing a missing key does nothing
        store.compute(2, |_| Op::Remove);
        store.check();
    }

    #[test]
    fn a_removed_place_is_reused_only_after_its_turn() {
        // 去掉又写回同一个键：旧位置还排在队列里，不能和新条目混在一起
        // Remove a key and store it again: the old place is still queued and must not mix with the new entry
        let store = CacheStore::new(20, DAY);
        for round in 0..2000u64 {
            let key = round % 37;
            match round % 3 {
                0 => store.compute(key, |_| Op::Remove),
                _ => put(&store, key, weighted(round, 1 + (round % 3) as u32)),
            }
            if round % 5 == 0 {
                store.get(key);
            }
            store.check();
        }
    }

    #[test]
    fn removed_entries_do_not_pile_up_while_the_cache_has_room() {
        // 缓存远没满，队列一直不动：去掉的位置要靠整理收回来
        // The cache is far from full, so the queues never move: removed places are reclaimed by tidying
        let store = CacheStore::new(10_000, DAY);
        for round in 0..100_000u64 {
            let key = round % 10;
            put(&store, key, value(round));
            store.compute(key, |_| Op::Remove);
        }
        store.check();
        for shard in store.shards.iter() {
            let places = shard.read().nodes.len() as u64;
            assert!(
                places <= 2 * DEAD_SLACK,
                "{places} places for at most 10 keys"
            );
        }
    }

    #[test]
    fn invalidate_all_empties_every_shard() {
        let store = CacheStore::new(1000, DAY);
        for key in 0..500 {
            put(&store, key, value(key));
        }
        store.invalidate_all();
        assert_eq!((store.entry_count(), store.weighted_size()), (0, 0));
        assert!(store.get(1).is_none());
        put(&store, 1, value(1));
        assert!(store.get(1).is_some());
        store.check();
    }

    #[test]
    fn a_write_sweeps_out_entries_past_their_age_at_most_once_a_minute() {
        let store = CacheStore::new(100, Duration::from_secs(30));
        let old = Value {
            id: 1,
            weight: 1,
            stored_at: Instant::now() - Duration::from_secs(40),
        };
        put(&store, 1, old);
        put(&store, 2, value(2));
        // 还没到清扫的时候：过期的照样在（查找方自己会认出它过期了）
        // Not time to sweep yet: the outlived entry stays (lookups tell it is outlived themselves)
        assert_eq!(store.entry_count(), 2);
        for shard in store.shards.iter() {
            shard.write().swept_at -= SWEEP_EVERY;
        }
        put(&store, 3, value(3));
        assert!(store.get(1).is_none(), "swept out");
        assert!(store.get(2).is_some() && store.get(3).is_some());
        store.check();
    }

    /// 存了 `age` 的值 / A value stored `age` ago
    fn aged(id: u64, age: Duration) -> Value {
        Value {
            id,
            weight: 1,
            stored_at: Instant::now() - age,
        }
    }

    /// 一轮清扫走完整个分片，但每次至多走 `SWEEP_PLACES` 个位置
    /// A round of sweeping covers the whole shard, at most `SWEEP_PLACES` places at a time
    #[test]
    fn a_round_of_sweeping_walks_a_limited_stretch_at_a_time() {
        let (max_age, now) = (Duration::from_secs(30), Instant::now());
        let count = u64::from(SWEEP_PLACES) * 2 + 10;
        let mut shard = Shard::new(count, now);
        for key in 0..count {
            shard.insert(key, key, aged(key, Duration::from_secs(40)), 1);
        }
        shard.sweeping = Some(0);
        shard.sweep_some(max_age, now);
        assert_eq!(shard.live, count - u64::from(SWEEP_PLACES));
        assert_eq!(shard.sweeping, Some(SWEEP_PLACES));
        shard.sweep_some(max_age, now);
        assert_eq!(shard.live, 10);
        assert_eq!(shard.sweeping, Some(SWEEP_PLACES * 2));
        shard.sweep_some(max_age, now);
        assert_eq!(shard.live, 0);
        assert_eq!(shard.sweeping, None, "the round is over");
        shard.check();
        // 这一轮结束了就不再走 / A round that is over walks no further
        shard.insert(1, 1, aged(1, Duration::from_secs(40)), 1);
        shard.sweep_some(max_age, now);
        assert_eq!(shard.live, 1);
    }

    /// 第一个分片里存着 `stored` 个已经存过头的条目，再给几个同一分片的键，接下来写入用
    /// `stored` outlived entries in the first shard, and some more keys of that shard for
    /// the writes to come
    fn outlived_in_first_shard(stored: u64) -> (CacheStore<Value>, Vec<u64>) {
        let store = CacheStore::new(64 * 4 * u64::from(SWEEP_PLACES), Duration::from_secs(30));
        let mut keys: Vec<u64> = (0u64..)
            .filter(|key| std::ptr::eq(store.locate(*key).1, &store.shards[0]))
            .take(stored as usize + 8)
            .collect();
        let spare = keys.split_off(stored as usize);
        for key in keys {
            put(&store, key, aged(key, Duration::from_secs(40)));
        }
        assert_eq!(store.shards[0].read().live, stored, "not time to sweep yet");
        (store, spare)
    }

    /// 轮到清扫的写入开始一轮，之后的写入不等下一次轮到就接着走完；走完之后要等下一次轮到才再开始
    /// The write whose turn has come starts a round and later ones finish it without waiting
    /// for another turn; once finished, the next round waits for its turn
    #[test]
    fn writes_carry_a_round_of_sweeping_through() {
        let places = u64::from(SWEEP_PLACES);
        let (store, mut spare) = outlived_in_first_shard(places * 2);
        let live = || store.shards[0].read().live;
        let sweeping = || store.shards[0].read().sweeping;
        store.shards[0].write().swept_at -= SWEEP_EVERY;
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(live(), places + 1, "started");
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(live(), 2, "carried on without another turn");
        // 新条目排在这一轮走到的位置后面，再写一次这一轮才结束 / A new entry sits past where the round has
        // got to, and one more write ends it
        assert!(sweeping().is_some());
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(sweeping(), None, "the round is over");
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(sweeping(), None, "the next round waits for its turn");
        store.check();
    }

    /// 一轮还没走完又轮到了：接着走，不从头来，否则写得慢时这一轮永远走不完
    /// Another turn coming before a round is over: it carries on rather than starting again,
    /// or with slow writes the round would never end
    #[test]
    fn a_turn_coming_on_the_way_does_not_restart_the_round() {
        let places = u64::from(SWEEP_PLACES);
        let (store, mut spare) = outlived_in_first_shard(places * 2);
        store.shards[0].write().swept_at -= SWEEP_EVERY;
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(store.shards[0].read().live, places + 1);
        store.shards[0].write().swept_at -= SWEEP_EVERY;
        put(&store, spare.pop().unwrap(), value(0));
        assert_eq!(
            store.shards[0].read().live,
            2,
            "carried on, not from the start"
        );
        store.check();
    }

    /// 条目能存得久的，清扫也隔得久；能存得短的，也至少隔一分钟
    /// Entries that may stay long are swept less often; those that may not, a minute apart at least
    #[test]
    fn the_longer_entries_may_stay_the_less_often_they_are_swept() {
        let short = CacheStore::<Value>::new(100, Duration::from_secs(30));
        assert_eq!(short.sweep_every, SWEEP_EVERY);
        let store = CacheStore::new(100, DAY);
        assert_eq!(store.sweep_every, DAY / 16);
        put(&store, 1, aged(1, DAY * 2));
        store.shards[0].write().swept_at -= SWEEP_EVERY;
        put(&store, 2, value(2));
        assert_eq!(store.entry_count(), 2, "a minute is not long enough");
        store.shards[0].write().swept_at -= DAY / 16;
        put(&store, 3, value(3));
        assert!(store.get(1).is_none(), "swept out");
    }

    /// 清空时旧条目在写锁外释放
    /// Emptying the cache frees the old entries outside the write lock
    #[test]
    fn invalidate_all_frees_the_entries_outside_the_lock() {
        #[derive(Clone)]
        struct Probe {
            store: Arc<std::sync::OnceLock<std::sync::Weak<CacheStore<Probe>>>>,
            freed: Arc<[std::sync::atomic::AtomicU32; 2]>,
        }
        impl Cached for Probe {
            fn weight(&self) -> u32 {
                1
            }
            fn outlived(&self, _max_age: Duration, _now: Instant) -> bool {
                false
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                if let Some(store) = self.store.get().and_then(std::sync::Weak::upgrade) {
                    let locked = store.shards[0].try_read().is_none();
                    self.freed[usize::from(locked)].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let store = Arc::new(CacheStore::new(8, DAY));
        let handle = Arc::new(std::sync::OnceLock::new());
        let freed = Arc::new([const { std::sync::atomic::AtomicU32::new(0) }; 2]);
        handle.set(Arc::downgrade(&store)).unwrap();
        for key in 0..8 {
            let probe = Probe {
                store: Arc::clone(&handle),
                freed: Arc::clone(&freed),
            };
            store.compute(key, |_| Op::Put(probe));
        }
        store.invalidate_all();
        assert_eq!(store.entry_count(), 0);
        assert_eq!(
            freed[0].load(Ordering::Relaxed),
            8,
            "freed with the lock free"
        );
        assert_eq!(freed[1].load(Ordering::Relaxed), 0, "freed under the lock");
    }

    /// 整个分片都放不下的不存，也不挤掉别的；正好放得下的存
    /// One too heavy for the whole shard is not stored and pushes nothing out; one that
    /// just fits is stored
    #[test]
    fn an_entry_too_heavy_for_its_shard_is_not_stored_and_pushes_nothing_out() {
        let store = CacheStore::new(64, DAY);
        for key in 0..50 {
            put(&store, key, value(key));
        }
        put(&store, 100, weighted(100, 65));
        assert!(store.get(100).is_none());
        assert_eq!(store.entry_count(), 50);
        put(&store, 1, weighted(1, 65));
        assert!(
            store.get(1).is_none(),
            "the old value is out of date by now"
        );
        assert_eq!(store.entry_count(), 49);
        store.check();
        put(&store, 100, weighted(100, 64));
        assert_eq!(store.get(100).map(|value| value.weight), Some(64));
        store.check();
    }

    /// 写回一个还在的键：留在原来的队列，访问计数也不变（规则缓存的决策过期后就这样写回）
    /// Writing over a key still there keeps its queue and its access count (the way a rule
    /// cache decision is written back once it has expired)
    #[test]
    fn writing_over_an_entry_keeps_its_queue_and_access_count() {
        let store = CacheStore::new(64, DAY);
        put(&store, 0, value(0));
        store.get(0);
        store.get(0);
        // 小队列满了，读到过的这个进主队列 / The small queue fills up and this one, read since, goes to the main queue
        for key in 1..=64 {
            put(&store, key, value(key));
        }
        let state = || {
            let mut shard = store.shards[0].write();
            let index = shard.find(store.locate(0).0, 0).unwrap();
            let node = &mut shard.nodes[index as usize];
            (node.queue, *node.freq.get_mut())
        };
        assert_eq!(state().0, Queue::Main);
        store.get(0);
        let before = state();
        put(&store, 0, value(100));
        assert_eq!(state(), before);
        assert_eq!(store.get(0).map(|value| value.id), Some(100));
        store.check();
    }

    #[test]
    fn concurrent_reads_and_writes_keep_the_books() {
        let store = Arc::new(CacheStore::new(2000, DAY));
        let threads: Vec<_> = (0..4u64)
            .map(|thread| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut state = thread + 1;
                    for _ in 0..50_000 {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        let key = state % 5000;
                        match state % 7 {
                            0 => store.compute(key, |_| Op::Remove),
                            1 | 2 => put(&store, key, weighted(key, 1 + (state % 4) as u32)),
                            _ => {
                                if let Some(found) = store.get(key) {
                                    assert_eq!(found.id, key);
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        store.check();
        assert!(store.weighted_size() <= 2000);
    }
}
