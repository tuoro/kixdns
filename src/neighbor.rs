//! 本机的邻居表：和 KixDNS 在同一个局域网上的设备的 IP 地址和 MAC 地址，`client_mac` 匹配器按它认出客户端（见
//! `matcher::RuntimeMatcher::ClientMac`）。Linux 上 IPv4 的读 /proc/net/arp，IPv6 的经 rtnetlink 读（RTM_GETNEIGH 转储），
//! 还在解析、解析失败的条目略过。读一遍要几十微秒，不每个查询都读：留着最近读到的一份，旧过 [`REREAD_AFTER`] 才在下一次
//! 查找时重读，一秒至多读一次，刚出现的设备一秒之内就认得出来。别的系统上什么也读不到；表里没有的地址（回环、不在同一个
//! 网段上的客户端、经 NAT 进来的）都查不到，client_mac 也就不命中
//! The host's neighbor table: the IP and MAC addresses of the devices on the LAN KixDNS is on,
//! by which the `client_mac` matcher knows a client (see `matcher::RuntimeMatcher::ClientMac`).
//! On Linux IPv4 neighbors are read from /proc/net/arp and IPv6 ones over rtnetlink (an
//! RTM_GETNEIGH dump), entries still resolving or failed to resolve left out. A read takes some
//! tens of microseconds, so not every query reads: the copy read last is kept and read again on
//! the next lookup once older than [`REREAD_AFTER`], at most once a second, so a device just
//! come is known within a second. Other systems read nothing; an address not in the table
//! (loopback, a client off the LAN, one come in through NAT) is found nowhere, and client_mac
//! does not match

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use rustc_hash::FxHashMap;

/// 一个 MAC 地址（EUI-48）/ A MAC address (EUI-48)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac([u8; 6]);

impl Mac {
    /// 写成六段两位十六进制数的 MAC，段间都用 `:` 或者都用 `-`，大小写不论：`aa:bb:cc:dd:ee:ff`、`AA-BB-CC-DD-EE-FF`；
    /// 别的写法为 None
    /// A MAC written as six two-digit hexadecimal numbers, all separated by `:` or all by `-`, in
    /// any case: `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`; None for anything else
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.as_bytes();
        let separator = *text.get(2)?;
        if text.len() != 17 || !matches!(separator, b':' | b'-') {
            return None;
        }
        let digit = |at: usize| char::from(text[at]).to_digit(16).map(|digit| digit as u8);
        let mut mac = [0; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            let at = i * 3;
            if i > 0 && text[at - 1] != separator {
                return None;
            }
            *byte = digit(at)? << 4 | digit(at + 1)?;
        }
        Some(Self(mac))
    }

    /// 全零：还没解析出来的条目就是这样 / All zeros, as an entry not resolved yet is
    #[cfg(any(target_os = "linux", test))]
    fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }
}

/// 写成 `aa:bb:cc:dd:ee:ff` / Written as `aa:bb:cc:dd:ee:ff`
impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// 读出来的邻居：每个地址的 MAC / The neighbors as read: the MAC of each address
pub type Neighbors = FxHashMap<IpAddr, Mac>;

/// 一份旧过这么久，下一次查找就重读 / A copy older than this is read again on the next lookup
pub const REREAD_AFTER: Duration = Duration::from_secs(1);

/// 邻居表：从哪里读，最近读到的一份。引擎带着一个（见 `Engine::client_mac`），配置里有 client_mac 匹配器时，每个请求在
/// 开头查一次客户端的地址
/// The neighbor table: where it is read from, and the copy read last. The engine holds one (see
/// `Engine::client_mac`), and with a client_mac matcher in the configuration each request looks
/// up its client's address once, at its start
pub struct NeighborTable {
    /// 读一遍表 / Reads the table once
    read: Box<dyn Fn() -> Neighbors + Send + Sync>,
    /// 一份旧过这么久就重读，本机的表是 [`REREAD_AFTER`] / A copy older than this is read
    /// again, [`REREAD_AFTER`] for the host's table
    reread_after: Duration,
    /// 最近读到的一份 / The copy read last
    snapshot: ArcSwap<Snapshot>,
    /// 读着的时候拿着：同一时刻只有一个线程在读 / Held while reading: one thread reads at a time
    reading: parking_lot::Mutex<()>,
}

/// 读到的一份 / One copy as read
#[derive(Default)]
struct Snapshot {
    /// 什么时候读的，还一次都没读过时为 None / When it was read, None before the first read
    read_at: Option<Instant>,
    neighbors: Neighbors,
}

impl NeighborTable {
    /// 本机的邻居表（见 [`read_host`]）/ The host's neighbor table (see [`read_host`])
    pub fn host() -> Self {
        Self::reading(read_host, REREAD_AFTER)
    }

    /// 每次重读调一遍 `read`、一份旧过 `reread_after` 就重读的表；测试用它换上一张假的表
    /// A table calling `read` for every read, read again once a copy is older than
    /// `reread_after`; tests put a fake table in place by it
    pub fn reading(
        read: impl Fn() -> Neighbors + Send + Sync + 'static,
        reread_after: Duration,
    ) -> Self {
        Self {
            read: Box::new(read),
            reread_after,
            snapshot: ArcSwap::default(),
            reading: parking_lot::Mutex::new(()),
        }
    }

    /// `address` 的 MAC，IPv4 映射形式的地址按它背后的 IPv4 地址查；表里没有时为 None。手上这一份旧了先重读：还一次没读过
    /// 时等着读完，读过了就由拿得到锁的那一个线程去读，别的线程照手上这一份查，不等
    /// The MAC of `address`, an IPv4-mapped address looked up by the IPv4 address it carries;
    /// None when the table has none. A copy grown old is read again first: before the first
    /// read every lookup waits for it, and after that the one thread that gets the lock reads
    /// while the others look in the copy in hand without waiting
    pub fn mac_of(&self, address: IpAddr) -> Option<Mac> {
        let address = address.to_canonical();
        let snapshot = self.snapshot.load();
        if self.is_old(&snapshot) {
            let never_read = snapshot.read_at.is_none();
            drop(snapshot);
            self.read_again(never_read);
        }
        self.snapshot.load().neighbors.get(&address).copied()
    }

    fn is_old(&self, snapshot: &Snapshot) -> bool {
        snapshot
            .read_at
            .is_none_or(|read_at| read_at.elapsed() >= self.reread_after)
    }

    /// 重读一遍；`wait` 时等着别的线程读完，不然别的线程在读就算了 / Read the table again;
    /// with `wait`, waiting for another thread reading it, otherwise leaving it to that one
    fn read_again(&self, wait: bool) {
        let _reading = if wait {
            self.reading.lock()
        } else {
            match self.reading.try_lock() {
                Some(reading) => reading,
                None => return,
            }
        };
        // 等锁的时候别的线程可能刚读完 / Another thread may have read it while the lock was awaited
        if !self.is_old(&self.snapshot.load()) {
            return;
        }
        let neighbors = (self.read)();
        self.snapshot.store(Arc::new(Snapshot {
            read_at: Some(Instant::now()),
            neighbors,
        }));
    }
}

/// 读一遍本机的邻居表。读不了的那一部分（没有 /proc、netlink 被挡住）记一条告警（隔一阵才记一条，见 `warn_sparse!`），
/// 照读得到的给
/// Read the host's neighbor table once. A part that cannot be read (no /proc, netlink kept
/// out) logs a warning (once in a while, see `warn_sparse!`), and what could be read is given
#[cfg(target_os = "linux")]
pub fn read_host() -> Neighbors {
    let mut neighbors = Neighbors::default();
    match std::fs::read_to_string(ARP_TABLE) {
        Ok(table) => read_arp(&table, &mut neighbors),
        Err(error) => crate::warn_sparse!(
            event = "neighbor_table_unreadable",
            table = ARP_TABLE,
            error = %error,
            "the IPv4 neighbor table cannot be read, so client_mac matches no IPv4 client"
        ),
    }
    if let Err(error) = rtnetlink::read_ipv6(&mut neighbors) {
        crate::warn_sparse!(
            event = "neighbor_table_unreadable",
            table = "rtnetlink",
            error = %error,
            "the IPv6 neighbor table cannot be read, so client_mac matches no IPv6 client"
        );
    }
    neighbors
}

/// Linux 以外的系统什么也不读 / Systems other than Linux read nothing
#[cfg(not(target_os = "linux"))]
pub fn read_host() -> Neighbors {
    Neighbors::default()
}

/// Linux 的 IPv4 邻居表 / Linux's IPv4 neighbor table
#[cfg(target_os = "linux")]
const ARP_TABLE: &str = "/proc/net/arp";

/// ARP 条目已经解析出 MAC 的标志（linux/if_arp.h）/ The flag of an ARP entry whose MAC is
/// resolved (linux/if_arp.h)
#[cfg(any(target_os = "linux", test))]
const ATF_COM: u32 = 0x02;

#[cfg(target_os = "linux")]
const _: () = assert!(ATF_COM as libc::c_int == libc::ATF_COM);

/// /proc/net/arp 的内容记进 `into`：第一行是表头，之后每行一个邻居，`IP 地址 硬件类型 标志 MAC 掩码 网卡`。标志里没有
/// ATF_COM 的还在解析或者解析失败了，MAC 是全零，略过；读不懂的行也略过。同一个地址在几张网卡上都有时取先读到的
/// The contents of /proc/net/arp written into `into`: a heading first, then a neighbor a line,
/// `IP-address HW-type Flags HW-address Mask Device`. An entry without ATF_COM in its flags is
/// still resolving or failed to, its MAC all zeros, and is left out, as is a line that cannot be
/// read. An address on several interfaces takes the first read
#[cfg(any(target_os = "linux", test))]
fn read_arp(table: &str, into: &mut Neighbors) {
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(address), Some(_kind), Some(flags), Some(mac)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(address), Some(mac)) = (address.parse::<std::net::Ipv4Addr>(), Mac::parse(mac))
        else {
            continue;
        };
        let resolved = flags
            .strip_prefix("0x")
            .and_then(|flags| u32::from_str_radix(flags, 16).ok())
            .is_some_and(|flags| flags & ATF_COM != 0);
        if resolved && !mac.is_zero() {
            into.entry(IpAddr::V4(address)).or_insert(mac);
        }
    }
}

/// 经 rtnetlink 读 IPv6 邻居：要一次 RTM_GETNEIGH 转储，读回来的报文按 Linux 的 ABI 解析（linux/netlink.h、
/// linux/rtnetlink.h、linux/neighbour.h）。解析不碰系统调用，哪里都编译、都测得了；只有收发是 Linux 的
/// IPv6 neighbors read over rtnetlink: one RTM_GETNEIGH dump asked for, the messages read back
/// parsed by Linux's ABI (linux/netlink.h, linux/rtnetlink.h, linux/neighbour.h). Parsing makes
/// no system call, so it compiles and is tested anywhere; only sending and receiving is Linux's
#[cfg(any(target_os = "linux", test))]
mod rtnetlink {
    use std::io;
    use std::net::{IpAddr, Ipv6Addr};

    use super::{Mac, Neighbors};

    /// nlmsghdr 的长度 / The length of nlmsghdr
    const HEADER: usize = 16;
    /// ndmsg 的长度 / The length of ndmsg
    const NDMSG: usize = 12;
    const RTM_NEWNEIGH: u16 = 28;
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 0x01;
    /// NLM_F_ROOT | NLM_F_MATCH
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_ERROR: u16 = 0x02;
    const NLMSG_DONE: u16 = 0x03;
    /// Linux 的 AF_INET6 / Linux's AF_INET6
    const AF_INET6: u8 = 10;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    /// 代答的条目，不是邻居自己 / A proxy entry, not the neighbor itself
    const NTF_PROXY: u8 = 0x08;
    const NUD_REACHABLE: u16 = 0x02;
    const NUD_STALE: u16 = 0x04;
    const NUD_DELAY: u16 = 0x08;
    const NUD_PROBE: u16 = 0x10;
    const NUD_PERMANENT: u16 = 0x80;
    /// MAC 已经解析出来的状态；INCOMPLETE、FAILED、NOARP、NONE 都不算 / The states whose MAC is
    /// resolved; INCOMPLETE, FAILED, NOARP and NONE are not among them
    const RESOLVED: u16 = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT;
    /// 一次转储的序号：每次读都开一个新的套接字，收到的只有这一次的 / The sequence number of a
    /// dump: every read opens a socket of its own, which receives this dump alone
    const SEQUENCE: u32 = 1;

    #[cfg(target_os = "linux")]
    const _: () = {
        assert!(RTM_NEWNEIGH == libc::RTM_NEWNEIGH);
        assert!(RTM_GETNEIGH == libc::RTM_GETNEIGH);
        assert!(NLM_F_REQUEST as libc::c_int == libc::NLM_F_REQUEST);
        assert!(NLM_F_DUMP as libc::c_int == libc::NLM_F_DUMP);
        assert!(NLMSG_ERROR as libc::c_int == libc::NLMSG_ERROR);
        assert!(NLMSG_DONE as libc::c_int == libc::NLMSG_DONE);
        assert!(AF_INET6 as libc::c_int == libc::AF_INET6);
        assert!(NDA_DST == libc::NDA_DST);
        assert!(NDA_LLADDR == libc::NDA_LLADDR);
        assert!(NTF_PROXY == libc::NTF_PROXY);
        assert!(NUD_REACHABLE == libc::NUD_REACHABLE);
        assert!(NUD_STALE == libc::NUD_STALE);
        assert!(NUD_DELAY == libc::NUD_DELAY);
        assert!(NUD_PROBE == libc::NUD_PROBE);
        assert!(NUD_PERMANENT == libc::NUD_PERMANENT);
    };

    /// 要 IPv6 邻居表转储的请求：nlmsghdr，后面一个只写了地址族的 ndmsg，都按本机字节序
    /// The request for a dump of the IPv6 neighbor table: nlmsghdr, then an ndmsg naming the
    /// address family alone, all in host byte order
    pub(super) fn dump_request(sequence: u32) -> [u8; HEADER + NDMSG] {
        let mut request = [0; HEADER + NDMSG];
        request[0..4].copy_from_slice(&((HEADER + NDMSG) as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[HEADER] = AF_INET6;
        request
    }

    /// 读完一个报文以后转储到了哪里 / Where the dump is once a datagram is read
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Dump {
        /// 后面还有 / More is to come
        More,
        /// 转储结束 / The dump is over
        Done,
    }

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes([bytes[at], bytes[at + 1]])
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    /// 补齐到 4 字节（NLMSG_ALIGN、RTA_ALIGN）/ Padded to 4 bytes (NLMSG_ALIGN, RTA_ALIGN)
    fn aligned(length: usize) -> usize {
        length.div_ceil(4) * 4
    }

    /// 序号为 `sequence` 的转储里一次读到的报文 `datagram`：里面的 IPv6 邻居记进 `into`（同一个地址取先读到的），读到
    /// NLMSG_DONE 为 [`Dump::Done`]；内核报错（NLMSG_ERROR）、报文长度说不通时是错误
    /// The datagram `datagram` read once in the dump numbered `sequence`: the IPv6 neighbors in
    /// it go into `into` (an address taking the first read), and NLMSG_DONE gives
    /// [`Dump::Done`]; the kernel reporting an error (NLMSG_ERROR), or a length that makes no
    /// sense, is an error
    pub(super) fn read_dump(
        datagram: &[u8],
        sequence: u32,
        into: &mut Neighbors,
    ) -> io::Result<Dump> {
        let mut rest = datagram;
        while rest.len() >= HEADER {
            let length = u32_at(rest, 0) as usize;
            if length < HEADER || length > rest.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("a netlink message of {length} bytes in {} left", rest.len()),
                ));
            }
            let (kind, payload) = (u16_at(rest, 4), &rest[HEADER..length]);
            if u32_at(rest, 8) == sequence {
                match kind {
                    NLMSG_DONE => return Ok(Dump::Done),
                    // 内核报的是负的 errno，0 是确认 / The kernel reports a negative errno, 0
                    // being an acknowledgement
                    NLMSG_ERROR if payload.len() >= 4 => {
                        return match u32_at(payload, 0) as i32 {
                            0 => Ok(Dump::Done),
                            errno => Err(io::Error::from_raw_os_error(errno.saturating_neg())),
                        };
                    }
                    RTM_NEWNEIGH => read_neighbor(payload, into),
                    _ => {}
                }
            }
            rest = rest.get(aligned(length)..).unwrap_or_default();
        }
        Ok(Dump::More)
    }

    /// 一个 RTM_NEWNEIGH 的内容：ndmsg，后面是属性。IPv6 的、MAC 已经解析出来的、不是代答的条目才记下
    /// One RTM_NEWNEIGH's payload: ndmsg, then its attributes. Only an IPv6 entry whose MAC is
    /// resolved, and which is no proxy entry, is noted
    fn read_neighbor(payload: &[u8], into: &mut Neighbors) {
        if payload.len() < NDMSG
            || payload[0] != AF_INET6
            || u16_at(payload, 8) & RESOLVED == 0
            || payload[10] & NTF_PROXY != 0
        {
            return;
        }
        let (mut address, mut mac) = (None, None);
        let mut attributes = &payload[NDMSG..];
        while attributes.len() >= 4 {
            let length = usize::from(u16_at(attributes, 0));
            if length < 4 || length > attributes.len() {
                return;
            }
            let value = &attributes[4..length];
            match u16_at(attributes, 2) {
                NDA_DST => address = <[u8; 16]>::try_from(value).ok().map(Ipv6Addr::from),
                NDA_LLADDR => mac = <[u8; 6]>::try_from(value).ok().map(Mac),
                _ => {}
            }
            attributes = attributes.get(aligned(length)..).unwrap_or_default();
        }
        if let (Some(address), Some(mac)) = (address, mac)
            && !mac.is_zero()
        {
            into.entry(IpAddr::V6(address)).or_insert(mac);
        }
    }

    /// 等内核回话最多这么久：它总是马上答，万一不答，查询也不一直等下去 / How long the kernel's
    /// reply is waited for at most: it answers at once, and should it not, the query does not
    /// wait on and on
    #[cfg(target_os = "linux")]
    const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

    /// 一次转储的报文最长多少：内核一个报文至多 32 KiB / The longest datagram of a dump: the
    /// kernel's are 32 KiB at most
    #[cfg(target_os = "linux")]
    const DATAGRAM: usize = 64 * 1024;

    /// 向内核要一次 IPv6 邻居表的转储，读完记进 `into` / Ask the kernel for a dump of the IPv6
    /// neighbor table and read it all into `into`
    #[cfg(target_os = "linux")]
    pub(super) fn read_ipv6(into: &mut Neighbors) -> io::Result<()> {
        use std::io::Read;

        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(
            Domain::from(libc::AF_NETLINK),
            Type::from(libc::SOCK_RAW),
            Some(Protocol::from(libc::NETLINK_ROUTE)),
        )?;
        socket.set_read_timeout(Some(REPLY_TIMEOUT))?;
        // 没连接的 netlink 套接字发给端口 0，也就是内核 / An unconnected netlink socket sends to
        // port 0, the kernel
        socket.send(&dump_request(SEQUENCE))?;
        let mut datagram = vec![0; DATAGRAM];
        loop {
            let read = (&socket).read(&mut datagram)?;
            if read_dump(&datagram[..read], SEQUENCE, into)? == Dump::Done {
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// 一个 RTM_NEWNEIGH：地址族、状态、标志，和属性 / One RTM_NEWNEIGH: family, state, flags,
        /// and attributes
        fn neighbor(family: u8, state: u16, flags: u8, attributes: &[(u16, &[u8])]) -> Vec<u8> {
            let mut payload = vec![0; NDMSG];
            payload[0] = family;
            payload[8..10].copy_from_slice(&state.to_ne_bytes());
            payload[10] = flags;
            for (kind, value) in attributes {
                payload.extend(((4 + value.len()) as u16).to_ne_bytes());
                payload.extend(kind.to_ne_bytes());
                payload.extend(*value);
                payload.resize(aligned(payload.len()), 0);
            }
            message(RTM_NEWNEIGH, SEQUENCE, &payload)
        }

        /// 地址和 MAC 两个属性 / The address and MAC attributes
        fn both<'a>(address: &'a [u8], mac: &'a [u8]) -> [(u16, &'a [u8]); 2] {
            [(NDA_DST, address), (NDA_LLADDR, mac)]
        }

        fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
            let mut message = Vec::new();
            message.extend(((HEADER + payload.len()) as u32).to_ne_bytes());
            message.extend(kind.to_ne_bytes());
            message.extend(0x2u16.to_ne_bytes());
            message.extend(sequence.to_ne_bytes());
            message.extend(0u32.to_ne_bytes());
            message.extend(payload);
            message.resize(aligned(message.len()), 0);
            message
        }

        const ADDRESS: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        /// 请求是 nlmsghdr 加一个只写了 AF_INET6 的 ndmsg，按本机字节序，要的是转储
        /// The request is nlmsghdr and an ndmsg naming AF_INET6 alone, in host byte order,
        /// asking for a dump
        #[test]
        fn the_request_asks_for_a_dump_of_ipv6_neighbors() {
            let request = dump_request(7);
            assert_eq!(u32_at(&request, 0), 28);
            assert_eq!(u16_at(&request, 4), RTM_GETNEIGH);
            assert_eq!(u16_at(&request, 6), NLM_F_REQUEST | NLM_F_DUMP);
            assert_eq!(u32_at(&request, 8), 7);
            assert_eq!(request[HEADER], AF_INET6);
            assert!(request[HEADER + 1..].iter().all(|&byte| byte == 0));
        }

        /// 解析出 MAC 的条目记下，还在解析的、解析失败的、代答的、全零 MAC 的、IPv4 的、缺地址或 MAC 的略过；别的序号的
        /// 报文不管；NLMSG_DONE 结束转储
        /// An entry with its MAC resolved is noted, while one still resolving, failed, a proxy
        /// entry, one with an all-zero MAC, an IPv4 one and one lacking its address or MAC are
        /// left out; messages of another sequence number are ignored; NLMSG_DONE ends the dump
        #[test]
        fn resolved_ipv6_neighbors_are_read_and_the_rest_left_out() {
            let other = |last: u8| {
                let mut address = ADDRESS;
                address[15] = last;
                address
            };
            let (two, three, four, five, six, seven, eight) = (
                other(2),
                other(3),
                other(4),
                other(5),
                other(6),
                other(7),
                other(8),
            );
            let mut datagram = Vec::new();
            for message in [
                neighbor(AF_INET6, NUD_STALE, 0, &both(&ADDRESS, &MAC)),
                // INCOMPLETE、FAILED / INCOMPLETE, FAILED
                neighbor(AF_INET6, 0x01, 0, &both(&two, &MAC)),
                neighbor(AF_INET6, 0x20, 0, &both(&three, &MAC)),
                neighbor(AF_INET6, NUD_REACHABLE, NTF_PROXY, &both(&four, &MAC)),
                neighbor(AF_INET6, NUD_REACHABLE, 0, &both(&five, &[0; 6])),
                neighbor(2, NUD_REACHABLE, 0, &both(&[10, 0, 0, 1], &MAC)),
                neighbor(AF_INET6, NUD_REACHABLE, 0, &[(NDA_DST, &six[..])]),
                neighbor(AF_INET6, NUD_REACHABLE, 0, &[(NDA_LLADDR, &MAC[..])]),
                neighbor(
                    AF_INET6,
                    NUD_PERMANENT,
                    0,
                    &both(&seven, &[1, 2, 3, 4, 5, 6]),
                ),
            ] {
                datagram.extend(message);
            }
            let mut stray = neighbor(AF_INET6, NUD_REACHABLE, 0, &both(&eight, &MAC));
            stray[8..12].copy_from_slice(&9u32.to_ne_bytes());
            datagram.extend(stray);

            let mut into = Neighbors::default();
            assert_eq!(
                read_dump(&datagram, SEQUENCE, &mut into).unwrap(),
                Dump::More
            );
            assert_eq!(
                into,
                Neighbors::from_iter([
                    (IpAddr::V6(Ipv6Addr::from(ADDRESS)), Mac(MAC)),
                    (IpAddr::V6(Ipv6Addr::from(seven)), Mac([1, 2, 3, 4, 5, 6])),
                ])
            );
            let done = message(NLMSG_DONE, SEQUENCE, &0i32.to_ne_bytes());
            assert_eq!(read_dump(&done, SEQUENCE, &mut into).unwrap(), Dump::Done);
        }

        /// 内核报的错原样交出，长度说不通的报文也是错误 / An error the kernel reports is handed
        /// on as it is, and a message whose length makes no sense is an error too
        #[test]
        fn errors_and_broken_lengths_end_the_read() {
            let refused = message(NLMSG_ERROR, SEQUENCE, &(-1i32).to_ne_bytes());
            let error = read_dump(&refused, SEQUENCE, &mut Neighbors::default()).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(1));
            let mut broken = neighbor(AF_INET6, NUD_STALE, 0, &both(&ADDRESS, &MAC));
            broken[0..4].copy_from_slice(&1000u32.to_ne_bytes());
            assert!(read_dump(&broken, SEQUENCE, &mut Neighbors::default()).is_err());
        }

        /// 在 Linux 上真的问一次内核：读得了，读到的 MAC 都不是全零
        /// On Linux the kernel is really asked once: the read works, and no MAC read is all zeros
        #[cfg(target_os = "linux")]
        #[test]
        fn the_kernel_gives_its_ipv6_neighbors() {
            let mut into = Neighbors::default();
            read_ipv6(&mut into).expect("the IPv6 neighbor table reads");
            assert!(into.values().all(|mac| !mac.is_zero()), "{into:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MAC: Mac = Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    /// 两种分隔符、大小写都认；段数、位数、分隔符混用、不是十六进制的（连带 `from_str_radix` 认的 `+`）、前后多空白的
    /// 都不认
    /// Either separator and either case are read; a wrong number of parts or digits, mixed
    /// separators, what is not hexadecimal (`from_str_radix`'s `+` included) and surrounding
    /// blanks are not
    #[test]
    fn a_mac_is_six_hex_pairs_split_by_one_kind_of_separator() {
        for written in [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "Aa-bB-cC-Dd-eE-Ff",
        ] {
            assert_eq!(Mac::parse(written), Some(MAC), "{written}");
        }
        assert_eq!(
            Mac::parse("00:11:22:33:44:55"),
            Some(Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        for written in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:f",
            "a:bb:cc:dd:ee:ff0",
            "aa:bb-cc:dd:ee:ff",
            "aa.bb.cc.dd.ee.ff",
            "aabb.ccdd.eeff",
            "aabbccddeeff",
            "gg:bb:cc:dd:ee:ff",
            "+a:bb:cc:dd:ee:ff",
            " aa:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:ff ",
            "aa:bb:cc:dd:ee:ｆ",
        ] {
            assert_eq!(Mac::parse(written), None, "{written:?}");
        }
    }

    /// /proc/net/arp 里解析出来的条目记下；还在解析的（标志 0x0、MAC 全零）、读不懂的行略过；同一个地址取先读到的
    /// Resolved entries of /proc/net/arp are noted; one still resolving (flags 0x0, an all-zero
    /// MAC) and lines that cannot be read are left out; an address takes the first read
    #[test]
    fn resolved_arp_entries_are_read_and_the_rest_left_out() {
        let table = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        br-lan
192.168.1.11     0x1         0x0         00:00:00:00:00:00     *        br-lan
192.168.1.12     0x1         0x6         00:11:22:33:44:55     *        br-lan
192.168.1.13     0x1         0x2         00:00:00:00:00:00     *        br-lan
192.168.1.10     0x1         0x2         00:11:22:33:44:55     *        eth1
192.168.1.14     0x1         nope        00:11:22:33:44:55     *        br-lan
not-an-address   0x1         0x2         00:11:22:33:44:55     *        br-lan
192.168.1.15
";
        let mut into = Neighbors::default();
        read_arp(table, &mut into);
        assert_eq!(
            into,
            Neighbors::from_iter([
                (IpAddr::from([192, 168, 1, 10]), MAC),
                (
                    IpAddr::from([192, 168, 1, 12]),
                    Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55])
                ),
            ])
        );
    }

    /// 一张数着读了几次的假表 / A fake table counting how often it is read
    fn counted(neighbors: Neighbors, reread_after: Duration) -> (NeighborTable, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let table = NeighborTable::reading(
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                neighbors.clone()
            },
            reread_after,
        );
        (table, reads)
    }

    /// IPv4、IPv6 的地址照表查，IPv4 映射形式的按它背后的 IPv4 地址查，表里没有的为 None
    /// IPv4 and IPv6 addresses are looked up as they are, an IPv4-mapped one by the IPv4
    /// address it carries, and one not in the table gives None
    #[test]
    fn addresses_are_looked_up_canonical() {
        let v6: IpAddr = "fd00::5".parse().unwrap();
        let other = Mac([2, 0, 0, 0, 0, 1]);
        let (table, _) = counted(
            Neighbors::from_iter([(IpAddr::from([192, 168, 1, 10]), MAC), (v6, other)]),
            REREAD_AFTER,
        );
        assert_eq!(table.mac_of(IpAddr::from([192, 168, 1, 10])), Some(MAC));
        assert_eq!(
            table.mac_of("::ffff:192.168.1.10".parse().unwrap()),
            Some(MAC)
        );
        assert_eq!(table.mac_of(v6), Some(other));
        assert_eq!(table.mac_of(IpAddr::from([192, 168, 1, 11])), None);
        assert_eq!(table.mac_of("fd00::6".parse().unwrap()), None);
    }

    /// 一份没旧，命中也好、查不到也好都不重读：一秒至多读一次 / A copy not grown old is not
    /// read again, whether the lookup finds the address or not: at most one read a second
    #[test]
    fn a_fresh_copy_is_not_read_again() {
        let (table, reads) = counted(
            Neighbors::from_iter([(IpAddr::from([192, 168, 1, 10]), MAC)]),
            Duration::from_secs(3600),
        );
        for _ in 0..3 {
            assert_eq!(table.mac_of(IpAddr::from([192, 168, 1, 10])), Some(MAC));
            assert_eq!(table.mac_of(IpAddr::from([192, 168, 1, 11])), None);
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    /// 一份旧了，下一次查找先重读：刚出现的设备查得到，换了设备的地址查到的是新的 MAC
    /// A copy grown old is read again on the next lookup: a device just come is found, and an
    /// address now another device's gives the new MAC
    #[test]
    fn an_old_copy_is_read_again_on_the_next_lookup() {
        let now = Arc::new(parking_lot::Mutex::new(Neighbors::default()));
        let current = Arc::clone(&now);
        let table = NeighborTable::reading(move || current.lock().clone(), Duration::ZERO);
        let address = IpAddr::from([192, 168, 1, 10]);
        assert_eq!(table.mac_of(address), None);
        now.lock().insert(address, MAC);
        assert_eq!(table.mac_of(address), Some(MAC));
        let other = Mac([2, 0, 0, 0, 0, 1]);
        now.lock().insert(address, other);
        assert_eq!(table.mac_of(address), Some(other));
    }

    /// 在 Linux 上真的读一次本机的表：读到的 MAC 都不是全零（容器里可能一个邻居都没有）
    /// On Linux the host's table is really read once: no MAC read is all zeros (in a container
    /// there may be no neighbor at all)
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_table_reads() {
        let neighbors = read_host();
        assert!(
            neighbors.values().all(|mac| !mac.is_zero()),
            "{neighbors:?}"
        );
    }
}
