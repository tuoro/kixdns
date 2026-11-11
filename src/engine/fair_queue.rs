//! 过载时按设备轮流处理：每台设备各排各的队，轮到谁就处理谁的一个。发得再多也只是自己的队排得长，
//! 排不下的直接丢掉，发得少的设备不受影响。不用判断谁算「重」，也不用知道这台机器处理得了多少。
//! Under overload devices are taken in turn: each has its own queue and each turn handles one
//! query from one device. Sending more only makes a device's own queue longer, and what does
//! not fit is dropped, leaving the devices that send little alone. There is no judging who
//! counts as heavy and no need to know how much this machine can handle.

use std::collections::{HashMap, VecDeque};
use std::hash::RandomState;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::concurrency::SHARE_AT_LEAST;

/// 最多这么多台设备同时排队，再来的新设备丢掉。每台设备有自己的队列，不和别的设备共用；这个上限管住一共能压多少（见
/// `the_queues_hold_at_most_each_device_filling_its_share_in_turn`），伪造来源地址的洪泛每个地址只排得进一个，也压不出更多
/// At most this many devices are queued at once, and a new one past it is dropped. Each device
/// has a queue of its own, shared with no other; this limit bounds how much may be held in all
/// (see `the_queues_hold_at_most_each_device_filling_its_share_in_turn`), so a flood with forged
/// source addresses, each getting one in, holds no more
pub(crate) const MAX_QUEUED_DEVICES: usize = 4096;

/// 有新设备因为排队的设备到了 [`MAX_QUEUED_DEVICES`] 被挡在外面以后，这么久里每台只排得进一个，见
/// [`FairQueue::begin_batch`]。被挡的设备要过一阵才再问：客户端等不到回答，一般过一到五秒重发
/// For this long after a new device was turned away for [`MAX_QUEUED_DEVICES`] being queued,
/// each device gets only one in, see [`FairQueue::begin_batch`]. A device turned away asks again
/// only some time later: a client getting no answer usually asks again one to five seconds on
pub(crate) const TURNED_AWAY_KEPT: Duration = Duration::from_secs(10);

/// 空出来的队列留这么多个下次再用，省得每台新设备都分配一次 / This many emptied queues are kept for reuse,
/// sparing an allocation for every new device
const SPARE_QUEUES: usize = 256;

/// 一台设备：IPv4 按地址，公网 IPv6 按 /64，一个这样的网段通常就是一户。局域网里的 IPv6 地址按完整地址：链路本地、ULA、
/// 站点本地，以及和内核在同一个 /64 里的公网地址（见 [`note_local_networks`]）——同一网段的主机都在一个 /64 里，家里的
/// 局域网主机用的是运营商下发的同一个 /64，按 /64 算就成了一台。64:ff9b::/96 的地址是翻译过来的 IPv4 客户端，按里面的
/// IPv4 地址算
/// A device: by address for IPv4 and by /64 for global IPv6, one such network usually being
/// one home. IPv6 addresses of a LAN go by the whole address: link-local, ULA, site-local, and
/// global ones in a /64 the kernel itself is on (see [`note_local_networks`]); the hosts of a
/// segment share one /64, the hosts of a home LAN the /64 its provider handed out, so by /64
/// they would be one device. An address in 64:ff9b::/96 is an IPv4 client translated, and goes
/// by that IPv4 address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Device {
    V4(u32),
    V6(u64),
    V6Host(u128),
}

/// NAT64 的知名前缀 64:ff9b::/96 / The well-known NAT64 prefix 64:ff9b::/96
const NAT64: u128 = 0x0064_ff9b << 96;

impl Device {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(u32::from(v4)),
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let network = (bits >> 64) as u64;
                if bits & !u128::from(u32::MAX) == NAT64 {
                    Self::V4(bits as u32)
                } else if v6.is_unicast_link_local()
                    || v6.is_unique_local()
                    || is_site_local(v6)
                    || is_local_network(network)
                {
                    Self::V6Host(bits)
                } else {
                    Self::V6(network)
                }
            }
        }
    }
}

/// fec0::/10，已经废弃、局域网里偶尔还有 / fec0::/10, deprecated and now and then still on a LAN
fn is_site_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfec0
}

/// 最多记这么多个本机所在的 IPv6 网段 / At most this many networks the machine is on are noted
const LOCAL_NETWORKS: usize = 16;

/// 本机网卡上公网 IPv6 地址所在的 /64（地址的高 64 位），见 [`note_local_networks`] / The /64s (the high 64 bits)
/// of the global IPv6 addresses on this machine's interfaces, see [`note_local_networks`]
static LOCAL_NETWORK: [AtomicU64; LOCAL_NETWORKS] = [const { AtomicU64::new(0) }; LOCAL_NETWORKS];

/// 记了几个 / How many are noted
static LOCAL_NETWORKS_NOTED: AtomicUsize = AtomicUsize::new(0);

/// 记下本机网卡上公网 IPv6 地址所在的 /64（见 `socket_utils::local_ipv6_networks`），多出的不记。来源在这些网段里的，是和
/// 内核在同一个网段上的主机：对公网上的服务，一户的地址都在一个 /64 里；部署在局域网时，客户端和内核在同一个 /64，要按完整
/// 地址分开。换了网段（比如重新拨号后运营商下发了新的）再记一次就换掉
/// Notes the /64s of the global IPv6 addresses on this machine's interfaces (see
/// `socket_utils::local_ipv6_networks`), any past the limit left out. A source in one of them is
/// a host on the kernel's own network: for a service on the internet one home's addresses are in
/// one /64, while deployed on a LAN the clients share the kernel's /64 and are told apart by
/// the whole address. A new network (a provider handing out another after redialling, say) is
/// noted again and replaces it
pub fn note_local_networks(networks: &[u64]) {
    let noted = networks.len().min(LOCAL_NETWORKS);
    for (slot, &network) in LOCAL_NETWORK.iter().zip(&networks[..noted]) {
        slot.store(network, Ordering::Relaxed);
    }
    LOCAL_NETWORKS_NOTED.store(noted, Ordering::Relaxed);
}

fn is_local_network(network: u64) -> bool {
    let noted = LOCAL_NETWORKS_NOTED.load(Ordering::Relaxed);
    LOCAL_NETWORK[..noted.min(LOCAL_NETWORKS)]
        .iter()
        .any(|slot| slot.load(Ordering::Relaxed) == network)
}

/// 一台设备排着的查询和回答时要用的对端 / A device's queued queries and the peers to answer
type Queued<P> = VecDeque<(Box<[u8]>, P)>;

/// 按设备轮流的队列，`P` 是回答时要用的对端 / A queue taking devices in turn, `P` being the peer to answer
pub struct FairQueue<P> {
    /// 每台排着队的设备自己的队列；哈希每次启动都不同，外面算不出表里的布局
    /// Each queued device's own queue; the hash differs at each start, so nobody outside can work
    /// out the table's layout
    queues: HashMap<Device, Queued<P>, RandomState>,
    /// 还有查询排着的设备，下一个轮到的在最前面 / The devices holding queries, the next in turn first
    turns: VecDeque<Device>,
    /// 一台设备排进去时能排到多少：它除以那一刻在排队的设备数，至少 [`Self::begin_batch`] 定下的数，平常是
    /// [`SHARE_AT_LEAST`]。排着的不收回，一共能排多少见 `the_queues_hold_at_most_each_device_filling_its_share_in_turn`
    /// How far a device may queue as it offers a query: this divided by how many devices are queued
    /// at that moment, at least what [`Self::begin_batch`] set, [`SHARE_AT_LEAST`] as a rule. What
    /// is queued is not taken back; for how much may be held in all see
    /// `the_queues_hold_at_most_each_device_filling_its_share_in_turn`
    room: usize,
    /// 一共排着多少个 / How many are queued in all
    queued: usize,
    /// 空出来留着再用的队列 / Emptied queues kept for reuse
    spare: Vec<Queued<P>>,
    /// 每台设备至少排得进几个，见 [`Self::begin_batch`] / How many each device may at least queue,
    /// see [`Self::begin_batch`]
    at_least: usize,
    /// 这一批开始以后有没有新设备因为排队的设备到了 [`MAX_QUEUED_DEVICES`] 被挡在外面 / Whether a new device
    /// was turned away for [`MAX_QUEUED_DEVICES`] being queued since this batch began
    turned_away: bool,
    /// 上一次有新设备被挡在外面以后，下一批是什么时候开始的 / When the batch after a new device was last
    /// turned away began
    turned_away_at: Option<Instant>,
}

impl<P> FairQueue<P> {
    pub fn new(room: usize) -> Self {
        Self {
            queues: HashMap::default(),
            turns: VecDeque::new(),
            room,
            queued: 0,
            spare: Vec::new(),
            at_least: SHARE_AT_LEAST,
            turned_away: false,
            turned_away_at: None,
        }
    }

    /// 答一批之前：`room` 同 [`Self::new`]，`now` 是这一批开始的时刻。也定下每台设备至少排得进几个：平常是
    /// [`SHARE_AT_LEAST`]；[`TURNED_AWAY_KEPT`] 里有新设备因为排队的设备到了 [`MAX_QUEUED_DEVICES`] 被挡在外面时是 1，挡的那一刻起
    /// 就是。来源比设备上限还多时，洪泛的设备每轮到一次只取走一个，这一圈里又到了几个，每台排得进几个的话队列一直不空，先排进去的
    /// 那些一直占着位置，后来的设备一个都排不进；每台只排得进一个时，轮到一次就排空、让出位置，后来的才赶得上空位。记的是时间不是
    /// 轮数：被挡的设备过一阵才再问，一圈有多长却跟着处理速度变；来源正好是上限那么多时，被挡的只有这台设备，只记一圈的话等它再问时
    /// 早过了，各台又排满了，它一次都排不进
    /// Before a batch is answered: `room` as for [`Self::new`] and `now` when the batch begins.
    /// This also sets how many each device may at least queue: [`SHARE_AT_LEAST`] as a rule, and 1
    /// when within [`TURNED_AWAY_KEPT`] a new device was turned away for [`MAX_QUEUED_DEVICES`]
    /// being queued, from the moment it was. With more sources than the device limit, a flooding
    /// device has one taken each turn and several more arriving within the round, so with a few
    /// each its queue never runs empty, those queued first keep their places for good and a device
    /// coming later never gets in; with one each, a turn empties it and gives up the place, and a
    /// later device has a chance at it. Time is kept rather than turns: a device turned away asks
    /// again some time later, while how long a round takes goes with the handling speed; with
    /// exactly as many sources as the limit only this device is turned away, and remembering a
    /// round would have it long over by the time it asked again, every device full once more, so
    /// it would never get in
    pub fn begin_batch(&mut self, room: usize, now: Instant) {
        self.room = room;
        if std::mem::take(&mut self.turned_away) {
            self.turned_away_at = Some(now);
        }
        self.at_least = match self.turned_away_at {
            Some(at) if now.saturating_duration_since(at) < TURNED_AWAY_KEPT => 1,
            _ => SHARE_AT_LEAST,
        };
    }

    /// 排进去；这台设备排满了自己那一份就丢掉，返回 false。份额至少是 [`Self::begin_batch`] 定下的数：设备多到平分下来每台不到一个时，
    /// 发得少的设备一次问几个也排得进。还没排着的设备总能排进去，发得少的设备不会被挡；只有已经有 [`MAX_QUEUED_DEVICES`] 台在
    /// 排队时，新来的才丢
    /// Queues a query; with the device's share full it is dropped and this gives false. A share is
    /// at least what [`Self::begin_batch`] set: with devices so many that each would get less than one, a
    /// device sending little asking a few at once still gets them in. A device not queued yet
    /// always gets in, so a device sending little is not kept out; only with
    /// [`MAX_QUEUED_DEVICES`] already queued is a new one dropped
    pub fn offer(&mut self, packet: &[u8], device: Device, peer: P) -> bool {
        if let Some(queue) = self.queues.get_mut(&device) {
            if queue.len() >= (self.room / self.turns.len()).max(self.at_least) {
                return false;
            }
            queue.push_back((packet.into(), peer));
            self.queued += 1;
            return true;
        }
        if self.turns.len() >= MAX_QUEUED_DEVICES {
            self.turned_away = true;
            self.at_least = 1;
            return false;
        }
        let mut queue = self.spare.pop().unwrap_or_default();
        queue.push_back((packet.into(), peer));
        self.queued += 1;
        self.queues.insert(device, queue);
        self.turns.push_back(device);
        true
    }

    /// 下一个轮到的查询，以及这台设备后面排着的是不是不比各设备平均少，而且至少是 [`Self::begin_batch`] 定下的那么多个（排得更少的不算）。
    /// 一次问好几个的设备后面也排着几个，但比一直在发的少得多，不算；设备多到每台只排几个时，后面排着不到这么多个的也不算，那是
    /// 每台都排得进的份
    /// The next query in turn, and whether this device has no fewer queued behind it than the
    /// average across devices, and at least what [`Self::begin_batch`] set (one with fewer does not). A
    /// device asking several at once has a few behind it too, but far fewer than one sending on
    /// and on, and does not count; with devices so many that each queues only a few, one with
    /// fewer than that behind does not count either, that being the share every device gets in
    pub fn next_in_turn(&mut self) -> Option<(Box<[u8]>, P, bool)> {
        let device = self.turns.pop_front()?;
        let queue = self.queues.get_mut(&device)?;
        let (packet, peer) = queue.pop_front()?;
        self.queued -= 1;
        let left = queue.len();
        if left > 0 {
            self.turns.push_back(device);
        } else if let Some(emptied) = self.queues.remove(&device)
            && self.spare.len() < SPARE_QUEUES
        {
            self.spare.push(emptied);
        }
        let queues_its_share = left >= self.at_least && left * self.turns.len() >= self.queued;
        Some((packet, peer, queues_its_share))
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

    /// 轮到的设备后面排着的不比各设备平均少、至少 4 个，才算占着自己那一份：一台排了 100 个、一台一次来了 4 个，轮到前者算，
    /// 轮到后者不算；只剩一台在排时它就是平均，排到后面不到 4 个时不算
    /// A device in turn holds its share only with no fewer queued behind it than the average, and
    /// at least 4: with one having queued 100 and another 4 at once, the first does and the second
    /// does not; once it is the only one queued it is the average, and with fewer than 4 behind it
    /// does not
    #[test]
    fn a_device_queueing_no_less_than_the_average_holds_its_share() {
        let mut queue = FairQueue::new(1000);
        let (heavy, light) = (device(1), device(2));
        for id in 0..100 {
            assert!(queue.offer(b"q", heavy, id));
        }
        for id in 100..104 {
            assert!(queue.offer(b"q", light, id));
        }
        let shares: Vec<_> = std::iter::from_fn(|| queue.next_in_turn())
            .map(|(_, peer, share)| (peer, share))
            .collect();
        assert_eq!(shares.len(), 104);
        assert!(
            shares
                .iter()
                .filter(|(peer, _)| *peer >= 100)
                .all(|(_, share)| !share),
            "the one asking a few at once"
        );
        assert!(
            shares
                .iter()
                .filter(|(peer, _)| *peer < 96)
                .all(|(_, share)| *share),
            "the one sending on and on"
        );
        assert!(
            shares
                .iter()
                .filter(|(peer, _)| (96..100).contains(peer))
                .all(|(_, share)| !share),
            "fewer than 4 behind"
        );
    }

    #[test]
    fn the_query_comes_back_as_it_was_sent() {
        let mut queue = FairQueue::new(100);
        queue.offer(b"query", device(0), 7);
        for peer in 8..12 {
            queue.offer(b"more", device(0), peer);
        }
        let (packet, peer, holds_its_share) = queue.next_in_turn().unwrap();
        assert_eq!(&*packet, b"query");
        assert_eq!(peer, 7);
        assert!(holds_its_share, "alone, with four behind");
        let (packet, peer, holds_its_share) = queue.next_in_turn().unwrap();
        assert_eq!(&*packet, b"more");
        assert_eq!(peer, 8);
        assert!(!holds_its_share, "three behind");
        assert_eq!(taken(&mut queue), [9, 10, 11]);
    }

    /// 设备多到平分下来每台不到一个时，每台照样排得进 4 个：一千台各排满，发得少的设备一次问 3 个都排得进，轮到时也都不算占着
    /// 份额，跟不上时不丢。以前每台只排得进一个，同一批来的第二个起就丢
    /// With devices so many that each would get less than one, each still gets 4 in: with a
    /// thousand at their share, a device sending little asking 3 at once gets all in, and none of
    /// them counts as holding its share in turn, so falling behind drops none. Each used to get one
    /// in, the second of a batch onwards dropped
    #[test]
    fn many_devices_each_queue_a_few() {
        let mut queue = FairQueue::new(100);
        for n in 0..1000 {
            while queue.offer(b"q", device(n), n) {}
        }
        assert_eq!(queue.queues[&device(999)].len(), SHARE_AT_LEAST);
        let light = device(5000);
        for id in 0..3 {
            assert!(queue.offer(b"q", light, 5000 + id), "{id}");
        }
        let light_turns: Vec<_> = std::iter::from_fn(|| queue.next_in_turn())
            .filter(|(_, peer, _)| *peer >= 5000)
            .map(|(_, _, share)| share)
            .collect();
        assert_eq!(light_turns, [false, false, false]);
    }

    /// 排队的设备到了上限、又有新设备被挡在外面以后，挡的那一刻起每台只排得进一个，后面排着一个、不比平均少的就算占着份额，
    /// 和以前一样；`TURNED_AWAY_KEPT` 里一直这样，过了又是至少 4 个
    /// Once the queued devices are at the limit and a new device has been turned away, each gets
    /// only one in from that moment, and one with one behind and no fewer than the average holds
    /// its share, as it used to; so it stays for `TURNED_AWAY_KEPT`, and past that it is at least
    /// 4 again
    #[test]
    fn past_the_device_limit_each_queues_one_again() {
        let mut queue = FairQueue::new(100);
        let start = Instant::now();
        queue.begin_batch(100, start);
        let limit = MAX_QUEUED_DEVICES as u32;
        for n in 0..limit {
            assert!(queue.offer(b"q", device(n), n));
        }
        assert!(
            queue.offer(b"q", device(0), 0),
            "at the limit with nobody turned away, at least 4 each"
        );
        assert!(!queue.offer(b"q", device(limit), limit), "past the limit");
        assert!(!queue.offer(b"q", device(1), 1), "then one each");
        let (_, peer, holds_its_share) = queue.next_in_turn().unwrap();
        assert_eq!(peer, 0);
        assert!(holds_its_share, "one behind and no fewer than the average");
        for _ in 1..limit {
            queue.next_in_turn();
        }
        assert_eq!(queue.devices(), 1, "all but the one holding two ran empty");
        // 设备多到平分下来每台一个都没有：记着的时候每台只排得进一个，过了又是 4 个 / With devices so
        // many that each would get none: one each while it is kept, and 4 again past that
        let noted = start + Duration::from_millis(1);
        queue.begin_batch(100, noted);
        queue.begin_batch(100, noted + TURNED_AWAY_KEPT - Duration::from_millis(1));
        for n in 1..1000 {
            assert!(queue.offer(b"q", device(n), n));
        }
        assert!(!queue.offer(b"q", device(5), 1), "still kept, one each");
        queue.begin_batch(100, noted + TURNED_AWAY_KEPT);
        for id in 1..SHARE_AT_LEAST as u32 {
            assert!(queue.offer(b"q", device(5), id), "no longer kept, {id}");
        }
        assert!(!queue.offer(b"q", device(5), 9), "and no more");
    }

    /// 来源比设备上限还多、一直在发时，问一个等一个的设备也排得进：每台只排得进一个，轮到一次就排空、让出位置。以前每台排得进
    /// 4 个，先排进去的那些一直占着位置，它答上一次以后再也排不进
    /// With more sources than the device limit sending on and on, a device asking one at a time
    /// still gets in: each gets one in, so a turn empties it and gives up the place. With 4 each,
    /// those queued first kept their places for good, and once answered it never got in again
    #[test]
    fn a_device_sending_little_gets_in_past_the_device_limit() {
        let mut queue = FairQueue::new(100);
        let sources = MAX_QUEUED_DEVICES as u32 + 900;
        let light = device(sources);
        let start = Instant::now();
        let (mut waiting, mut answered) = (false, 0);
        for round in 0..40u32 {
            // 每轮各发一个，先后打乱；它夹在中间 / Each sends one a round in a shuffled order, it somewhere among them
            let light_at = round * 997 % sources;
            for k in 0..sources {
                if k == light_at && !waiting {
                    waiting = queue.offer(b"q", light, sources);
                }
                let n = (k * 7919 + round * 31) % sources;
                queue.offer(b"q", device(n), n);
            }
            queue.begin_batch(100, start + Duration::from_millis(50 * u64::from(round)));
            for _ in 0..1000 {
                if let Some((_, peer, _)) = queue.next_in_turn()
                    && peer == sources
                {
                    waiting = false;
                    answered += u32::from(round >= 10);
                }
            }
        }
        assert!(answered >= 5, "{answered}");
    }

    /// 来源正好是设备上限那么多、一直在发时，隔一秒才问一个的设备也排得进：被挡以后每台只排得进一个，记十秒，这些来源排空了让出
    /// 位置，它下次问时赶得上。以前只记一圈，被挡的只有它，等它再问时早过了，各台又排满了，一次都排不进；少一个来源时本来就排得进
    /// With exactly as many sources as the device limit sending on and on, a device asking once a
    /// second still gets in: once it is turned away each gets one in, kept for ten seconds, so the
    /// sources run empty and give up places in time for its next ask. Only a round used to be
    /// kept, and with it alone turned away that was long over when it asked again, every device
    /// full once more, so it never got in; with a source fewer it always did
    #[test]
    fn a_device_asking_now_and_then_gets_in_with_sources_at_the_device_limit() {
        let limit = MAX_QUEUED_DEVICES as u32;
        for sources in [limit - 1, limit] {
            let mut queue = FairQueue::new(100);
            let light = device(sources);
            let start = Instant::now();
            let (mut waiting, mut asked, mut answered) = (false, 0, 0);
            // 一轮 50 毫秒：来源一共发 3000 个，轮到 1000 个；它每 20 轮（一秒）问一个，上一个还排着就不问，数第 200 轮以后的
            // A round is 50 ms: the sources send 3000 in all and 1000 get their turn; it asks one
            // every 20 rounds (a second) unless one is still queued, counted from round 200 on
            for round in 0..1400u32 {
                let light_at = round * 997 % 3000;
                for k in 0..3000u32 {
                    if k == light_at && !waiting && round % 20 == 0 {
                        asked += u32::from(round >= 200);
                        waiting = queue.offer(b"q", light, sources);
                    }
                    let n = (u64::from(round * 3000 + k) * 7919 % u64::from(sources)) as u32;
                    queue.offer(b"q", device(n), n);
                }
                queue.begin_batch(100, start + Duration::from_millis(50 * u64::from(round)));
                for _ in 0..1000 {
                    if let Some((_, peer, _)) = queue.next_in_turn()
                        && peer == sources
                    {
                        waiting = false;
                        answered += u32::from(round >= 200);
                    }
                }
            }
            assert!(
                answered * 10 >= asked * 8,
                "{answered} of {asked}, {sources} sources"
            );
        }
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
    /// 前面那些从各自最后一次排进去以后没再收过、也还没排空，都还排着，所以它最多排到 max(4, ⌊room/k⌋)，一共最多
    /// Σ max(4, ⌊room/k⌋)（k 从 1 到 `MAX_QUEUED_DEVICES`，4 是 `SHARE_AT_LEAST`），大约 room × ln(room) 加设备上限的 4 倍。
    /// 一台接一台各排满自己那一份正好到这个数；地址再多，过了设备上限的新设备也排不进，占不了更多内存
    /// How much may be held in all: a share is set only as a query is queued, by how many devices are
    /// queued then, and what is queued is not taken back. Counting devices by when they last queued,
    /// the k-th one finds the earlier ones still queued, as none has taken anything since and none
    /// has run empty, so it holds at most max(4, ⌊room/k⌋), and all at most Σ max(4, ⌊room/k⌋) for k
    /// from 1 to `MAX_QUEUED_DEVICES` (4 being `SHARE_AT_LEAST`), about room × ln(room) plus four
    /// times the device limit. Device after device filling its share reaches exactly that; however
    /// many addresses there are, new devices past the limit do not get in, and hold no more memory
    #[test]
    fn the_queues_hold_at_most_each_device_filling_its_share_in_turn() {
        for room in [10, 64, 205, 4000] {
            let limit: usize = (1..=MAX_QUEUED_DEVICES)
                .map(|k| (room / k).max(SHARE_AT_LEAST))
                .sum();

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
        assert_ne!(of("fec0::1:10"), of("fec0::1:99"), "site-local");
        assert_eq!(of("fe80::1"), of("fe80::1"));
        assert_eq!(
            of("2001:db8:0:1::1"),
            of("2001:db8:0:1::2"),
            "global, by /64"
        );
    }

    /// 和内核在同一个 /64 里的公网地址按完整地址算：家里的局域网主机用的是运营商下发的同一个 /64。别的公网地址照旧按
    /// /64；内核换了网段，原来那个网段又按 /64 算。以前这样的局域网主机都算一台
    /// Global addresses in a /64 the kernel is on go by the whole address: the hosts of a home LAN
    /// share the /64 their provider handed out. Other global addresses still go by /64, and once
    /// the kernel moves to another network the old one goes by /64 again. Such LAN hosts used to
    /// count as one device
    #[test]
    fn hosts_on_the_kernels_own_network_are_devices_of_their_own() {
        let of = |text: &str| Device::of(text.parse().unwrap());
        let ours = (u128::from("2001:db8:4c4c:4c4c::".parse::<Ipv6Addr>().unwrap()) >> 64) as u64;
        note_local_networks(&[ours]);
        assert_ne!(
            of("2001:db8:4c4c:4c4c::10"),
            of("2001:db8:4c4c:4c4c:1234:5678:9abc:def0")
        );
        assert_eq!(of("2001:db8:4c4c:4c4d::10"), of("2001:db8:4c4c:4c4d::99"));
        note_local_networks(&[]);
        assert_eq!(
            of("2001:db8:4c4c:4c4c::10"),
            of("2001:db8:4c4c:4c4c:1234:5678:9abc:def0"),
            "no longer ours"
        );
    }

    /// 64:ff9b::/96 的地址按里面的 IPv4 地址算：翻译过来的 IPv4 客户端各是各的，和直接来的同一个地址是同一台
    /// An address in 64:ff9b::/96 goes by its IPv4 address: translated IPv4 clients are each their
    /// own, and the same as that address arriving directly
    #[test]
    fn a_translated_ipv4_client_is_its_ipv4_address() {
        let of = |text: &str| Device::of(text.parse().unwrap());
        assert_ne!(of("64:ff9b::c000:201"), of("64:ff9b::c633:6401"));
        assert_eq!(of("64:ff9b::c000:201"), of("192.0.2.1"));
        assert_eq!(
            of("64:ff9b:0:0:1::1"),
            of("64:ff9b:0:0:1::2"),
            "outside the /96, by /64"
        );
    }
}
