//! 过载时按设备轮流处理：每台设备各排各的队，轮到谁就处理谁的一个。发得再多也只是自己的队排得长，
//! 排不下的直接丢掉，发得少的设备不受影响。不用判断谁算「重」，也不用知道这台机器处理得了多少。
//! Under overload devices are taken in turn: each has its own queue and each turn handles one
//! query from one device. Sending more only makes a device's own queue longer, and what does
//! not fit is dropped, leaving the devices that send little alone. There is no judging who
//! counts as heavy and no need to know how much this machine can handle.

use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;

/// 队列的份数。设备按哈希落到其中一份，哈希每次启动都不同，外面算不出谁和谁落在一起；同一份的设备一起算一台
/// How many queues there are. A device lands in one by a hash that differs at each start, so
/// nobody outside can work out who lands together; devices in the same queue count as one
const QUEUES: usize = 1024;

/// 一台设备：IPv4 按地址，IPv6 按 /64，一个 IPv6 网段通常就是一户
/// A device: by address for IPv4 and by /64 for IPv6, one such network usually being one home
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Device {
    V4(u32),
    V6(u64),
}

impl Device {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(u32::from(v4)),
            IpAddr::V6(v6) => Self::V6((u128::from(v6) >> 64) as u64),
        }
    }
}

/// 按设备轮流的队列，`P` 是回答时要用的对端 / A queue taking devices in turn, `P` being the peer to answer
pub struct FairQueue<P> {
    queues: Vec<VecDeque<(Box<[u8]>, P)>>,
    /// 还有查询排着的队列，下一个轮到的在最前面 / The queues holding queries, the next in turn first
    turns: VecDeque<usize>,
    /// 一共排多少个查询，有几台设备就各占一份 / How many queries are held in all, each device taking its share
    room: usize,
    hasher: RandomState,
}

impl<P> FairQueue<P> {
    pub fn new(room: usize) -> Self {
        Self {
            queues: (0..QUEUES).map(|_| VecDeque::new()).collect(),
            turns: VecDeque::new(),
            room,
            hasher: RandomState::new(),
        }
    }

    pub fn set_room(&mut self, room: usize) {
        self.room = room;
    }

    fn index_of(&self, device: Device) -> usize {
        (self.hasher.hash_one(device) % QUEUES as u64) as usize
    }

    /// 排进去；这台设备排满了自己那一份就丢掉，返回 false。队列是空的总能排进去，发得少的设备不会被挡
    /// Queues a query; with the device's share full it is dropped and this gives false. An empty
    /// queue always takes it, so a device sending little is not kept out
    pub fn offer(&mut self, packet: &[u8], device: Device, peer: P) -> bool {
        let index = self.index_of(device);
        let queue = &mut self.queues[index];
        if queue.is_empty() {
            self.turns.push_back(index);
        } else if queue.len() >= self.room / self.turns.len() {
            return false;
        }
        queue.push_back((packet.into(), peer));
        true
    }

    /// 下一个轮到的查询，以及这台设备后面还排没排着别的 / The next query in turn, and whether this device
    /// has more queued behind it
    pub fn next_in_turn(&mut self) -> Option<(Box<[u8]>, P, bool)> {
        let index = self.turns.pop_front()?;
        let queue = &mut self.queues[index];
        let (packet, peer) = queue.pop_front()?;
        let more_queued = !queue.is_empty();
        if more_queued {
            self.turns.push_back(index);
        }
        Some((packet, peer, more_queued))
    }

    pub fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }

    /// 现在有几台设备在排队 / How many devices are queued right now
    pub fn devices(&self) -> usize {
        self.turns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: u32) -> Device {
        Device::V4(n)
    }

    /// 和 `first` 不在同一份队列的另一台设备 / Another device, not in the same queue as `first`
    fn other_device(queue: &FairQueue<u32>, first: Device) -> Device {
        (1..)
            .map(device)
            .find(|other| queue.index_of(*other) != queue.index_of(first))
            .unwrap()
    }

    fn taken(queue: &mut FairQueue<u32>) -> Vec<u32> {
        std::iter::from_fn(|| queue.next_in_turn().map(|(_, peer, _)| peer)).collect()
    }

    #[test]
    fn devices_take_turns_whoever_sends_more() {
        let mut queue = FairQueue::new(100);
        let heavy = device(0);
        let light = other_device(&queue, heavy);
        for id in [1, 2, 3, 4] {
            assert!(queue.offer(b"q", heavy, id));
        }
        assert!(queue.offer(b"q", light, 10));
        assert_eq!(queue.devices(), 2);
        assert_eq!(taken(&mut queue), [1, 10, 2, 3, 4]);
        assert!(queue.is_empty());
        assert_eq!(queue.devices(), 0);
    }

    #[test]
    fn the_query_comes_back_as_it_was_sent() {
        let mut queue = FairQueue::new(100);
        queue.offer(b"query", device(0), 7);
        queue.offer(b"more", device(0), 8);
        let (packet, peer, more_queued) = queue.next_in_turn().unwrap();
        assert_eq!(&*packet, b"query");
        assert_eq!(peer, 7);
        assert!(more_queued);
        let (packet, peer, more_queued) = queue.next_in_turn().unwrap();
        assert_eq!(&*packet, b"more");
        assert_eq!(peer, 8);
        assert!(!more_queued);
        assert!(queue.next_in_turn().is_none());
    }

    #[test]
    fn a_device_holds_no_more_than_its_share() {
        let mut queue = FairQueue::new(10);
        let heavy = device(0);
        let accepted = (0..20).filter(|&id| queue.offer(b"q", heavy, id)).count();
        assert_eq!(accepted, 10, "alone it may fill the room");

        // 来了第二台，第一台的那一份变成一半，第二台照样排得进 / With a second one the first's share is
        // half and the second still gets in
        let light = other_device(&queue, heavy);
        assert!(queue.offer(b"q", light, 100));
        assert!(!queue.offer(b"q", heavy, 21));
        for _ in 0..6 {
            queue.next_in_turn();
        }
        assert!(
            queue.offer(b"q", heavy, 22),
            "there is room in its share again"
        );
    }

    /// 地址全不相同时队列数也有上限，再多也占不了更多内存：空队列总收一个，不空的只收到自己那一份，各份加起来
    /// 是 room。撞进同一份的地址算一台设备，在份额内本来就能多排，所以上限是份数加 room，不是份数
    /// With every address different the queues still set a limit, so however many there are they
    /// hold no more memory: an empty queue always takes one and one in use takes only up to its
    /// share, the shares adding up to the room. Addresses landing in one queue count as one device
    /// and may queue more within its share, so the limit is the queues plus the room, not the queues
    #[test]
    fn different_addresses_cannot_grow_it_past_the_queues() {
        let room = 10;
        let mut queue = FairQueue::new(room);
        let accepted = (0..100_000)
            .filter(|&id| queue.offer(b"q", device(id), id))
            .count();
        assert_eq!(queue.devices(), QUEUES, "every queue is in use");
        assert!(accepted <= QUEUES + room, "{accepted}");
    }

    /// 已经排着的设备比份额还多时，空队列里新来的一台照样排得进——发得少的不会因为设备多就被挡在外面
    /// With more devices already queued than the room, a new one whose queue is empty still gets
    /// in: a device sending little is not shut out just because there are many devices
    #[test]
    fn a_new_device_always_gets_its_first_turn() {
        let mut queue = FairQueue::new(2);
        // 挑落在不同份的几台设备，数目超过 room / Pick devices in distinct queues, more than the room
        let mut seen = std::collections::HashSet::new();
        let devices: Vec<Device> = (0..)
            .map(device)
            .filter(|&one| seen.insert(queue.index_of(one)))
            .take(8)
            .collect();
        for (peer, &one) in devices.iter().enumerate() {
            assert!(
                queue.offer(b"q", one, peer as u32),
                "an empty queue is taken, with {} already queued",
                queue.devices()
            );
        }
        assert_eq!(queue.devices(), 8);
    }

    #[test]
    fn a_device_is_an_ipv4_address_or_an_ipv6_network() {
        let of = |text: &str| Device::of(text.parse().unwrap());
        assert_eq!(of("192.0.2.1"), of("192.0.2.1"));
        assert_ne!(of("192.0.2.1"), of("192.0.2.2"));
        assert_eq!(
            of("192.0.2.1"),
            of("::ffff:192.0.2.1"),
            "the same on a dual-stack socket"
        );
        assert_eq!(of("2001:db8:0:1::1"), of("2001:db8:0:1:ffff::2"));
        assert_ne!(of("2001:db8:0:1::1"), of("2001:db8:0:2::1"));
        assert_ne!(of("0.0.0.1"), of("0:0:0:1::"), "families do not mix");
    }
}
