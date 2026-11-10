//! 过载时按设备轮流处理：每台设备各排各的队，轮到谁就处理谁的一个。发得再多也只是自己的队排得长，
//! 排不下的直接丢掉，发得少的设备不受影响。不用判断谁算「重」，也不用知道这台机器处理得了多少。
//! Under overload devices are taken in turn: each has its own queue and each turn handles one
//! query from one device. Sending more only makes a device's own queue longer, and what does
//! not fit is dropped, leaving the devices that send little alone. There is no judging who
//! counts as heavy and no need to know how much this machine can handle.

use std::collections::{HashMap, VecDeque};
use std::hash::RandomState;
use std::net::IpAddr;

/// 最多这么多台设备同时排队，再来的新设备丢掉。每台设备有自己的队列，不和别的设备共用；这个上限管住一共能压多少（见
/// `the_queues_hold_at_most_each_device_filling_its_share_in_turn`），伪造来源地址的洪泛每个地址只排得进一个，也压不出更多
/// At most this many devices are queued at once, and a new one past it is dropped. Each device
/// has a queue of its own, shared with no other; this limit bounds how much may be held in all
/// (see `the_queues_hold_at_most_each_device_filling_its_share_in_turn`), so a flood with forged
/// source addresses, each getting one in, holds no more
const MAX_QUEUED_DEVICES: usize = 4096;

/// 空出来的队列留这么多个下次再用，省得每台新设备都分配一次 / This many emptied queues are kept for reuse,
/// sparing an allocation for every new device
const SPARE_QUEUES: usize = 256;

/// 一台设备：IPv4 按地址，公网 IPv6 按 /64，一个这样的网段通常就是一户。局域网里的 IPv6 地址（链路本地、ULA）
/// 按完整地址：同一网段的主机都在一个 /64 里，用链路本地地址的更是全在 fe80::/64，按 /64 算就成了一台
/// A device: by address for IPv4 and by /64 for global IPv6, one such network usually being
/// one home. IPv6 addresses of a LAN (link-local, ULA) go by the whole address: the hosts of a
/// segment share one /64, and all hosts using link-local addresses share fe80::/64, so by /64
/// they would be one device
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Device {
    V4(u32),
    V6(u64),
    V6Host(u128),
}

impl Device {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(u32::from(v4)),
            IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.is_unique_local() => {
                Self::V6Host(u128::from(v6))
            }
            IpAddr::V6(v6) => Self::V6((u128::from(v6) >> 64) as u64),
        }
    }
}

/// 按设备轮流的队列，`P` 是回答时要用的对端 / A queue taking devices in turn, `P` being the peer to answer
pub struct FairQueue<P> {
    /// 每台排着队的设备自己的队列；哈希每次启动都不同，外面算不出表里的布局
    /// Each queued device's own queue; the hash differs at each start, so nobody outside can work
    /// out the table's layout
    queues: HashMap<Device, VecDeque<(Box<[u8]>, P)>, RandomState>,
    /// 还有查询排着的设备，下一个轮到的在最前面 / The devices holding queries, the next in turn first
    turns: VecDeque<Device>,
    /// 一台设备排进去时能排到多少：它除以那一刻在排队的设备数。排着的不收回，一共能排多少见
    /// `the_queues_hold_at_most_each_device_filling_its_share_in_turn`
    /// How far a device may queue as it offers a query: this divided by how many devices are queued
    /// at that moment. What is queued is not taken back; for how much may be held in all see
    /// `the_queues_hold_at_most_each_device_filling_its_share_in_turn`
    room: usize,
    /// 空出来留着再用的队列 / Emptied queues kept for reuse
    spare: Vec<VecDeque<(Box<[u8]>, P)>>,
}

impl<P> FairQueue<P> {
    pub fn new(room: usize) -> Self {
        Self {
            queues: HashMap::default(),
            turns: VecDeque::new(),
            room,
            spare: Vec::new(),
        }
    }

    pub fn set_room(&mut self, room: usize) {
        self.room = room;
    }

    /// 排进去；这台设备排满了自己那一份就丢掉，返回 false。还没排着的设备总能排进去，发得少的设备不会被挡；只有已经有
    /// [`MAX_QUEUED_DEVICES`] 台在排队时，新来的才丢
    /// Queues a query; with the device's share full it is dropped and this gives false. A device not
    /// queued yet always gets in, so a device sending little is not kept out; only with
    /// [`MAX_QUEUED_DEVICES`] already queued is a new one dropped
    pub fn offer(&mut self, packet: &[u8], device: Device, peer: P) -> bool {
        if let Some(queue) = self.queues.get_mut(&device) {
            if queue.len() >= self.room / self.turns.len() {
                return false;
            }
            queue.push_back((packet.into(), peer));
            return true;
        }
        if self.turns.len() >= MAX_QUEUED_DEVICES {
            return false;
        }
        let mut queue = self.spare.pop().unwrap_or_default();
        queue.push_back((packet.into(), peer));
        self.queues.insert(device, queue);
        self.turns.push_back(device);
        true
    }

    /// 下一个轮到的查询，以及这台设备后面还排没排着别的 / The next query in turn, and whether this device
    /// has more queued behind it
    pub fn next_in_turn(&mut self) -> Option<(Box<[u8]>, P, bool)> {
        let device = self.turns.pop_front()?;
        let queue = self.queues.get_mut(&device)?;
        let (packet, peer) = queue.pop_front()?;
        let more_queued = !queue.is_empty();
        if more_queued {
            self.turns.push_back(device);
        } else if let Some(emptied) = self.queues.remove(&device)
            && self.spare.len() < SPARE_QUEUES
        {
            self.spare.push(emptied);
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

    /// 和 `first` 不同的另一台设备 / Another device than `first`
    fn other_device(_queue: &FairQueue<u32>, first: Device) -> Device {
        (1..).map(device).find(|other| *other != first).unwrap()
    }

    /// 设备不和别的设备共用队列：一台洪泛的排满了自己那一份，再来几千台各发一个，都排得进。以前设备按哈希落进 1024 份，
    /// 来源一多，正常设备和洪泛的落在同一份就被丢
    /// A device shares its queue with no other: with one flooding device at its share, thousands
    /// more sending one each all get in. Devices used to land in 1024 queues by hash, so with many
    /// sources a normal device landing with a flooding one was dropped
    #[test]
    fn devices_never_share_a_queue() {
        let mut queue = FairQueue::new(10);
        while queue.offer(b"q", device(0), 0) {}
        let taken_in = (1..=3000)
            .filter(|&n| queue.offer(b"q", device(n), n))
            .count();
        assert_eq!(taken_in, 3000);
    }

    /// 一台设备排空以后再来，照样排得进、轮得到 / A device that ran empty and comes back gets in and
    /// gets its turn all the same
    #[test]
    fn a_device_that_ran_empty_queues_again() {
        let mut queue = FairQueue::new(10);
        assert!(queue.offer(b"q", device(1), 1));
        assert_eq!(taken(&mut queue), [1]);
        assert!(queue.is_empty());
        assert!(queue.offer(b"q", device(1), 2));
        assert!(queue.offer(b"q", device(2), 3));
        assert_eq!(taken(&mut queue), [2, 3]);
        assert_eq!(queue.devices(), 0);
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

    /// 一共能排多少：份额只在排进去那一刻按当时排着的设备数算，排着的不收回。按最后一次排进去的先后数，第 k 台排进去时，
    /// 前面那些从各自最后一次排进去以后没再收过、也还没排空，都还排着，所以它最多排到 max(1, ⌊room/k⌋)，一共最多
    /// Σ max(1, ⌊room/k⌋)（k 从 1 到 `MAX_QUEUED_DEVICES`），大约 room × ln(room) 加设备上限。一台接一台各排满自己那一份
    /// 正好到这个数；地址再多，过了设备上限的新设备也排不进，占不了更多内存
    /// How much may be held in all: a share is set only as a query is queued, by how many devices are
    /// queued then, and what is queued is not taken back. Counting devices by when they last queued,
    /// the k-th one finds the earlier ones still queued, as none has taken anything since and none
    /// has run empty, so it holds at most max(1, ⌊room/k⌋), and all at most Σ max(1, ⌊room/k⌋) for k
    /// from 1 to `MAX_QUEUED_DEVICES`, about room × ln(room) plus the device limit. Device after
    /// device filling its share reaches exactly that; however many addresses there are, new devices
    /// past the limit do not get in, and hold no more memory
    #[test]
    fn the_queues_hold_at_most_each_device_filling_its_share_in_turn() {
        for room in [10, 64, 205, 4000] {
            let limit: usize = (1..=MAX_QUEUED_DEVICES).map(|k| (room / k).max(1)).sum();

            let mut queue = FairQueue::new(room);
            let mut held = 0;
            for one in (0..MAX_QUEUED_DEVICES as u32).map(device) {
                while queue.offer(b"q", one, 0) {
                    held += 1;
                }
            }
            assert_eq!(held, limit, "room {room}");
            assert!(
                !(0..10_000).any(|id| queue.offer(b"q", device(id), id)),
                "nobody gets in past it, new devices included"
            );

            // 地址各不相同、边排边答也到不了 / Nor with every address different and turns taken meanwhile
            let mut queue = FairQueue::new(room);
            let mut held = 0;
            for id in 0..200_000 {
                if id % 7 == 0 && queue.next_in_turn().is_some() {
                    held -= 1;
                }
                if queue.offer(b"q", device(id), id) {
                    held += 1;
                }
                assert!(held <= limit, "{held} with room {room}");
            }
        }
    }

    /// 已经排着的设备比份额还多时，空队列里新来的一台照样排得进——发得少的不会因为设备多就被挡在外面
    /// With more devices already queued than the room, a new one whose queue is empty still gets
    /// in: a device sending little is not shut out just because there are many devices
    #[test]
    fn a_new_device_always_gets_its_first_turn() {
        let mut queue = FairQueue::new(2);
        // 几台设备，数目超过 room / Several devices, more than the room
        let devices: Vec<Device> = (0..8).map(device).collect();
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

    /// 链路本地地址和 ULA 按完整地址算：局域网里一个网段的 IPv6 主机不算一台设备；公网地址照旧按 /64。以前同一个
    /// 局域网的 IPv6 主机都算一台，其中一台洪泛，别的跟着被削
    /// Link-local addresses and ULAs count by the whole address: the IPv6 hosts on one LAN
    /// segment are not one device; global addresses still go by /64. Every IPv6 host of one LAN
    /// used to count as one device, so when one flooded the others were cut along with it
    #[test]
    fn hosts_on_a_lan_are_devices_of_their_own() {
        let of = |text: &str| Device::of(text.parse().unwrap());
        assert_ne!(of("fe80::1"), of("fe80::abcd:1234"), "link-local");
        assert_ne!(of("fd00:1:2:3::10"), of("fd00:1:2:3::99"), "unique local");
        assert_ne!(of("fc00::1"), of("fc00::2"), "unique local, fc00::/8");
        assert_eq!(of("fe80::1"), of("fe80::1"));
        assert_eq!(
            of("2001:db8:0:1::1"),
            of("2001:db8:0:1::2"),
            "global, by /64"
        );
    }
}
