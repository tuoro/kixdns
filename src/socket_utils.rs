// Socket utility functions with safe wrappers for FFI calls
// Socket 工具函数，为 FFI 调用提供安全封装

#[cfg(unix)]
use socket2::Socket;
use std::io;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;

/// How long an accept loop waits after an accept error before accepting again.
///
/// An accept loop must not end on an error: the listener would stop for good
/// while the process lives on (UDP still answers), so nothing restarts it.
/// Running out of descriptors or memory lasts a while, so the loop backs off
/// 100 ms instead of spinning; other errors (a peer that reset before the
/// accept, for instance) wait 10 ms, short enough not to matter and long enough
/// not to spin on an error that keeps coming back.
///
/// 接受连接出错以后，等多久再接着接受。接受循环不能因为出错就退出：监听口会从此停掉，进程却还活着
/// （UDP 照答），没有谁会把它重启。句柄、内存用光会持续一阵，等 100 毫秒，不空转；别的错误（对端在
/// 接受前就断了等）等 10 毫秒，短到无所谓，又不会在反复出现的错误上空转。
pub fn accept_retry_delay(err: &io::Error) -> Duration {
    #[cfg(unix)]
    let exhausted = matches!(
        err.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    );
    // WSAEMFILE, WSAENOBUFS
    #[cfg(windows)]
    let exhausted = matches!(err.raw_os_error(), Some(10024 | 10055));
    #[cfg(not(any(unix, windows)))]
    let exhausted = {
        let _ = err;
        true
    };
    if exhausted {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(10)
    }
}

/// Safely set IPV6_V6ONLY option on a socket
/// 安全地设置 socket 的 IPV6_V6ONLY 选项
///
/// # Arguments
/// * `socket` - The socket to configure
/// * `enabled` - Whether to enable IPV6_V6ONLY (true = IPv6 only, false = dual-stack)
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option (non-fatal, logged as warning)
#[cfg(unix)]
#[inline]
pub fn set_ipv6_v6only(socket: &Socket, enabled: bool) -> io::Result<()> {
    use libc::{IPPROTO_IPV6, IPV6_V6ONLY, c_int, setsockopt, socklen_t};

    let val: c_int = if enabled { 1 } else { 0 };
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        setsockopt(
            fd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Safely set SO_REUSEPORT option on a socket
/// 安全地设置 socket 的 SO_REUSEPORT 选项
///
/// # Arguments
/// * `socket` - The socket to configure
/// * `enabled` - Whether to enable SO_REUSEPORT
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option or not supported
#[cfg(unix)]
#[inline]
pub fn set_reuseport(socket: &Socket, enabled: bool) -> io::Result<()> {
    use libc::{SO_REUSEPORT, SOL_SOCKET, c_int, setsockopt, socklen_t};

    let val: c_int = if enabled { 1 } else { 0 };
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set SO_REUSEPORT with kernel-level load balancing for multi-worker UDP.
/// 为多 worker UDP 设置带内核级负载均衡的 SO_REUSEPORT。
///
/// On FreeBSD, `SO_REUSEPORT` allows multiple sockets to bind to the same port
/// but does NOT distribute incoming packets — all traffic goes to one socket.
/// `SO_REUSEPORT_LB` (0x00010000) is FreeBSD's separate option that enables
/// hash-based packet distribution across sockets in the reuseport group.
/// FreeBSD 上，`SO_REUSEPORT` 允许多个 socket 绑定同一个端口，但不分发收到的包——流量全进一个
/// socket。`SO_REUSEPORT_LB`（0x00010000）是 FreeBSD 另设的选项，在 reuseport 组的 socket 之间
/// 按哈希分发。
///
/// On Linux, `SO_REUSEPORT` already includes hash-based distribution, so we
/// use it directly.
/// 在 Linux 上，`SO_REUSEPORT` 已包含哈希分发功能，直接使用即可。
///
/// # Arguments
/// * `socket` - The socket to configure
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option or not supported
#[cfg(unix)]
#[inline]
pub fn set_reuseport_lb(socket: &Socket) -> io::Result<()> {
    // FreeBSD: SO_REUSEPORT_LB (0x00010000) enables hash-based load balancing
    // FreeBSD: SO_REUSEPORT_LB (0x00010000) 启用基于哈希的负载均衡
    #[cfg(target_os = "freebsd")]
    {
        use libc::{SOL_SOCKET, c_int, setsockopt, socklen_t};

        const SO_REUSEPORT_LB: c_int = 0x00010000;
        let val: c_int = 1;
        let fd = socket.as_raw_fd();
        let ret = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEPORT_LB,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as socklen_t,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        // Fall back to plain SO_REUSEPORT if LB variant fails
        // 如果 LB 变体失败，回退到普通 SO_REUSEPORT
    }

    // Linux and fallback: plain SO_REUSEPORT already does load balancing on Linux
    // Linux 和回退：普通 SO_REUSEPORT 在 Linux 上已自带负载均衡
    set_reuseport(socket, true)
}

#[cfg(not(unix))]
#[inline]
pub fn set_reuseport_lb(_socket: &socket2::Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT_LB not supported on this platform",
    ))
}

/// Non-Unix stub implementations (Windows and other platforms)
/// 非 Unix 系统的存根实现（Windows 和其他平台）
/// 这个 socket 因为接收缓冲满丢过多少报文；读不到时是 None
/// How many datagrams this socket has dropped for a full receive buffer; None when that cannot be read
#[cfg(target_os = "linux")]
pub fn udp_receive_drops(socket: &tokio::net::UdpSocket) -> Option<u32> {
    // 只要到丢包这一项，内核按给的长度填 / Only as far as the drops; the kernel fills what the length allows
    let mut info = [0u32; libc::SK_MEMINFO_DROPS as usize + 1];
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: the buffer and its length are valid for the call, which only writes within them
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (ret == 0).then(|| info[libc::SK_MEMINFO_DROPS as usize])
}

/// 这个 socket 的接收缓冲现在记着多少字节、最多记多少（内核翻过倍的大小）；读不到时是 None
/// How many bytes this socket's receive buffer is charged with now and at most (the size the
/// kernel doubled); None when that cannot be read
#[cfg(target_os = "linux")]
pub fn udp_receive_queue(socket: &tokio::net::UdpSocket) -> Option<(u32, u32)> {
    let mut info = [0u32; libc::SK_MEMINFO_RCVBUF as usize + 1];
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: the buffer and its length are valid for the call, which only writes within them
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (ret == 0).then(|| {
        (
            info[libc::SK_MEMINFO_RMEM_ALLOC as usize],
            info[libc::SK_MEMINFO_RCVBUF as usize],
        )
    })
}

/// 别的系统读不到，接收缓冲就一直不收小 / Other systems cannot read it, so the receive buffer never shrinks there
#[cfg(not(target_os = "linux"))]
pub fn udp_receive_drops(_socket: &tokio::net::UdpSocket) -> Option<u32> {
    None
}

/// 本机网卡上公网 IPv6 地址所在的 /64（地址的高 64 位），去重排好；读不到时是空的。流控用它认出和内核在同一个网段上的主机
/// The /64s (the high 64 bits) of the global IPv6 addresses on this machine's interfaces,
/// sorted without repeats; empty when they cannot be read. Flow control tells the hosts on the
/// kernel's own network by them
pub fn local_ipv6_networks() -> Vec<u64> {
    global_networks(local_ipv6_addresses())
}

/// 这些地址里公网的（2000::/3）所在的 /64，去重排好 / The /64s of those addresses that are global
/// (2000::/3), sorted without repeats
fn global_networks(addresses: impl IntoIterator<Item = std::net::Ipv6Addr>) -> Vec<u64> {
    let mut networks: Vec<u64> = addresses
        .into_iter()
        .filter(|ip| ip.segments()[0] & 0xe000 == 0x2000)
        .map(|ip| (u128::from(ip) >> 64) as u64)
        .collect();
    networks.sort_unstable();
    networks.dedup();
    networks
}

#[cfg(test)]
mod local_network_tests {
    use super::*;

    /// 只留公网地址的 /64：回环、链路本地、ULA 都不算，同一个 /64 的几个地址只记一次
    /// Only the /64s of global addresses: loopback, link-local and ULA do not count, and several
    /// addresses of one /64 are noted once
    #[test]
    fn only_global_addresses_give_networks() {
        let parse = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap();
        let networks = global_networks(
            [
                "::1",
                "fe80::1",
                "fd00:1:2:3::10",
                "2001:db8:0:1::10",
                "2001:db8:0:1:ffff::2",
                "2408:8207:1e:5a00::10",
            ]
            .map(parse),
        );
        let network = |text: &str| (u128::from(parse(text)) >> 64) as u64;
        assert_eq!(
            networks,
            [network("2001:db8:0:1::"), network("2408:8207:1e:5a00::")]
        );
    }

    /// 这台机器上读得出来，读到的都是公网的 / It reads on this machine, and what it reads is global
    #[test]
    fn this_machines_networks_are_global() {
        for network in local_ipv6_networks() {
            assert_eq!(network >> 61, 1, "{network:x}");
        }
    }
}

#[cfg(unix)]
fn local_ipv6_addresses() -> Vec<std::net::Ipv6Addr> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 填好一张链表，用完由 freeifaddrs 释放 / getifaddrs fills a list freed by freeifaddrs
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: 链表里的每一项在 freeifaddrs 之前都有效；地址的族是 AF_INET6 时它就是 sockaddr_in6
        // SAFETY: every entry of the list is valid until freeifaddrs; an address of family
        // AF_INET6 is a sockaddr_in6
        unsafe {
            let ifa = &*entry;
            if !ifa.ifa_addr.is_null() && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET6 {
                let addr = &*ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                found.push(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr));
            }
            entry = ifa.ifa_next;
        }
    }
    // SAFETY: list 来自上面成功的 getifaddrs / list comes from the successful getifaddrs above
    unsafe { libc::freeifaddrs(list) };
    found
}

#[cfg(windows)]
fn local_ipv6_addresses() -> Vec<std::net::Ipv6Addr> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    // 按 8 字节对齐的缓冲 / A buffer aligned to 8 bytes
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buffer.resize((size as usize).div_ceil(8), 0);
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: 缓冲有 size 字节，放不下时返回 ERROR_BUFFER_OVERFLOW 并给出要多大
        // SAFETY: the buffer holds size bytes; when too small it gives ERROR_BUFFER_OVERFLOW and the size needed
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET6),
                flags,
                std::ptr::null(),
                first,
                &mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if result != NO_ERROR {
            return Vec::new();
        }
        let mut found = Vec::new();
        let mut adapter = first.cast_const();
        // SAFETY: 链表在缓冲里，缓冲一直活着；地址的族是 AF_INET6 时它就是 SOCKADDR_IN6
        // SAFETY: the lists live in the buffer, which stays alive; an address of family
        // AF_INET6 is a SOCKADDR_IN6
        unsafe {
            while !adapter.is_null() {
                let mut unicast = (*adapter).FirstUnicastAddress.cast_const();
                while !unicast.is_null() {
                    let sockaddr = (*unicast).Address.lpSockaddr;
                    if !sockaddr.is_null() && (*sockaddr).sa_family == AF_INET6 {
                        let v6 = &*sockaddr.cast::<SOCKADDR_IN6>();
                        found.push(std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte));
                    }
                    unicast = (*unicast).Next.cast_const();
                }
                adapter = (*adapter).Next.cast_const();
            }
        }
        return found;
    }
    Vec::new()
}

#[cfg(not(any(unix, windows)))]
fn local_ipv6_addresses() -> Vec<std::net::Ipv6Addr> {
    Vec::new()
}

#[cfg(not(unix))]
#[allow(dead_code)] // Stub implementations for cross-platform compatibility
#[inline]
pub fn set_ipv6_v6only(_socket: &socket2::Socket, _enabled: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPV6_V6ONLY not supported on this platform",
    ))
}

#[cfg(not(unix))]
#[allow(dead_code)] // Stub implementation for cross-platform compatibility
#[inline]
pub fn set_reuseport(_socket: &socket2::Socket, _enabled: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT not supported on this platform",
    ))
}

/// 一个 UDP 报文发到的本机地址。监听在通配地址上时，回答要从它发出：内核自己挑的源地址在有几个地址的机器上
/// 可能是另一个，客户端不认从别的地址来的回答。只有 Linux 的批量收发读得到它（见 `udp_batch`），别的系统上总是没有
/// The local address a UDP datagram was sent to. Listening on the wildcard address, the reply has
/// to leave from it: the source the kernel picks by itself may be another on a machine with
/// several addresses, and a client refuses a reply from an address it did not ask. Only Linux's
/// batched receive reads it (see `udp_batch`); on other systems there is never one
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAddr {
    V4(std::net::Ipv4Addr),
    /// 地址，和链路本地地址所在的网卡号（别的地址是 0）：链路本地地址离了网卡号发不出去
    /// The address, and for a link-local one the interface it is on (0 for any other): a
    /// link-local address cannot be sent from without its interface
    V6(std::net::Ipv6Addr, u32),
}

/// 批量收发 UDP 报文（Linux 的 recvmmsg / sendmmsg）。满负荷时一次系统调用收发多个报文，省下每个报文
/// 进出内核的那一趟；空闲时一批只有一个，和单收单发一样。
/// Batched UDP receive and send (Linux recvmmsg / sendmmsg). Under full load one system call takes
/// or sends many datagrams, saving each one its own trip into the kernel; when idle a batch holds
/// one, the same as single receives and sends.
#[cfg(target_os = "linux")]
pub mod udp_batch {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::RawFd;

    use bytes::BytesMut;

    use super::LocalAddr;

    /// 一批最多这么多个报文 / The most datagrams in one batch
    pub const BATCH: usize = 32;
    /// 一个报文的控制消息缓冲：按 8 字节对齐，放得下一条本机地址的消息（IPv6 的占 40 字节）
    /// One datagram's control message buffer: aligned to 8 bytes, with room for one local
    /// address message (40 bytes for IPv6)
    type Control = [u64; 8];

    /// 让内核把每个报文发到的本机地址一起交上来（IPv4 的 IP_PKTINFO，IPv6 的 IPV6_RECVPKTINFO）。监听在通配
    /// 地址上才需要，见 [`LocalAddr`]
    /// Has the kernel hand over the local address each datagram was sent to (IP_PKTINFO for
    /// IPv4, IPV6_RECVPKTINFO for IPv6). Needed only when listening on the wildcard address, see
    /// [`LocalAddr`]
    pub fn receive_local_addresses(fd: RawFd, v6: bool) -> io::Result<()> {
        let on: libc::c_int = 1;
        let (level, option) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
        } else {
            (libc::IPPROTO_IP, libc::IP_PKTINFO)
        };
        // SAFETY: 选项的值是一个 c_int，活到调用结束 / SAFETY: the option's value is a c_int that outlives the call
        let ret = unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                (&on as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// 让一个报文从 `local` 发出的控制消息，和它占的长度
    /// The control message that has a datagram leave from `local`, and the length it takes
    fn source_control(local: LocalAddr) -> (Control, usize) {
        let mut control: Control = [0; 8];
        let cmsg = control.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: `control` 按 8 字节对齐、有 64 字节，放得下 cmsghdr 和后面的数据（最多 CMSG_SPACE(20) = 40 字节）；
        // 数据用 write_unaligned 写。pktinfo 是普通 C 结构，全零是合法值
        // SAFETY: `control` is aligned to 8 bytes and 64 bytes long, enough for a cmsghdr and the
        // data after it (CMSG_SPACE(20) = 40 bytes at most); the data is written with
        // write_unaligned. The pktinfo structs are plain C structs, all zeroes valid
        let len = unsafe {
            match local {
                LocalAddr::V4(addr) => {
                    let mut info: libc::in_pktinfo = zeroed();
                    info.ipi_spec_dst.s_addr = u32::from(addr).to_be();
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as _;
                    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                    libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as u32)
                }
                LocalAddr::V6(addr, interface) => {
                    let mut info: libc::in6_pktinfo = zeroed();
                    info.ipi6_addr.s6_addr = addr.octets();
                    info.ipi6_ifindex = interface as _;
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as _;
                    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                    libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as u32)
                }
            }
        };
        (control, len as usize)
    }

    /// 不等待地把 `data` 发给 `peer`，带着本机地址的从那个地址发出；发送缓冲满时是 `WouldBlock`
    /// Sends `data` to `peer` without waiting, from the local address it carries if any;
    /// `WouldBlock` when the send buffer is full
    pub fn send_one(fd: RawFd, data: &[u8], peer: &Peer) -> io::Result<usize> {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        // SAFETY: 普通 C 结构，全零是合法值 / SAFETY: a plain C struct, all zeroes is valid
        let mut hdr: libc::msghdr = unsafe { zeroed() };
        hdr.msg_name = (&peer.raw as *const libc::sockaddr_storage)
            .cast_mut()
            .cast();
        hdr.msg_namelen = peer.raw_len;
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        let mut control;
        if let Some(local) = peer.local {
            let len;
            (control, len) = source_control(local);
            hdr.msg_control = control.as_mut_ptr().cast();
            hdr.msg_controllen = len as _;
        }
        // SAFETY: 内核只读这些缓冲和地址，它们活到调用结束 / SAFETY: the kernel only reads these buffers and addresses, alive for the call
        let sent = unsafe { libc::sendmsg(fd, &hdr, libc::MSG_DONTWAIT) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sent as usize)
    }
    /// 每个报文的接收缓冲，和单收时一样大，更长的报文被截断 / Each datagram's receive buffer, as
    /// large as for single receives; a longer datagram is cut
    pub const RECV_SIZE: usize = 4096;

    /// 对端：内核给的原始地址发回时原样交回，`addr` 给引擎和日志用
    /// A peer: the kernel's own address, handed back as it is to reply, and `addr` for the engine and logs
    #[derive(Clone, Copy)]
    pub struct Peer {
        raw: libc::sockaddr_storage,
        raw_len: libc::socklen_t,
        addr: SocketAddr,
        /// 它的报文发到的本机地址：有的话回答从这个地址发出，没有就由内核挑
        /// The local address its datagram was sent to: the reply leaves from it when there is
        /// one, and from the address the kernel picks when not
        local: Option<LocalAddr>,
    }

    impl Peer {
        /// `addr` 这个对端：转发回来的回答不是这一批收到的，按地址建出内核要的形式
        /// The peer at `addr`: a reply that came back from a forward was not received in this
        /// batch, so the kernel's form is built from the address
        pub fn of(addr: SocketAddr) -> Self {
            // SAFETY: 普通 C 结构，全零是合法值 / SAFETY: a plain C struct, all zeroes is valid
            let mut raw: libc::sockaddr_storage = unsafe { zeroed() };
            let raw_len = match addr {
                SocketAddr::V4(v4) => {
                    // SAFETY: sockaddr_storage 对 sockaddr_in 够大、对齐 / SAFETY: sockaddr_storage is large and aligned enough for a sockaddr_in
                    let sin = unsafe {
                        &mut *(&mut raw as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                    };
                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                    sin.sin_port = v4.port().to_be();
                    sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                    size_of::<libc::sockaddr_in>()
                }
                SocketAddr::V6(v6) => {
                    // SAFETY: 同上，sockaddr_in6 / SAFETY: as above, for a sockaddr_in6
                    let sin6 = unsafe {
                        &mut *(&mut raw as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                    };
                    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    sin6.sin6_port = v6.port().to_be();
                    sin6.sin6_flowinfo = v6.flowinfo();
                    sin6.sin6_addr.s6_addr = v6.ip().octets();
                    sin6.sin6_scope_id = v6.scope_id();
                    size_of::<libc::sockaddr_in6>()
                }
            };
            Self {
                raw,
                raw_len: raw_len as libc::socklen_t,
                addr,
                local: None,
            }
        }

        /// 回答从 `local` 发出；没有就由内核挑 / The reply leaves from `local`, or from the
        /// address the kernel picks when there is none
        pub fn from_local(mut self, local: Option<LocalAddr>) -> Self {
            self.local = local;
            self
        }

        pub fn addr(&self) -> SocketAddr {
            self.addr
        }

        pub fn local(&self) -> Option<LocalAddr> {
            self.local
        }
    }

    /// 内核给的地址换成 `SocketAddr`；不是 IPv4、IPv6 的没有 / The kernel's address as a
    /// `SocketAddr`; none for a family other than IPv4 and IPv6
    fn socket_addr(raw: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match libc::c_int::from(raw.ss_family) {
            libc::AF_INET => {
                // SAFETY: ss_family 是 AF_INET，存的就是 sockaddr_in；sockaddr_storage 对任何地址都够大、对齐
                // SAFETY: with ss_family AF_INET it holds a sockaddr_in; sockaddr_storage is large and aligned for any address
                let v4 =
                    unsafe { &*(raw as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)),
                    u16::from_be(v4.sin_port),
                )))
            }
            libc::AF_INET6 => {
                // SAFETY: 同上，AF_INET6 存的是 sockaddr_in6 / SAFETY: as above, AF_INET6 holds a sockaddr_in6
                let v6 = unsafe {
                    &*(raw as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(v6.sin6_addr.s6_addr),
                    u16::from_be(v6.sin6_port),
                    v6.sin6_flowinfo,
                    v6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }

    /// 一批收到的报文 / One batch of received datagrams
    pub struct Received {
        bufs: Box<[u8]>,
        lens: [usize; BATCH],
        raw: [libc::sockaddr_storage; BATCH],
        raw_lens: [libc::socklen_t; BATCH],
        /// 每个报文的控制消息，里面是它发到的本机地址；不要本机地址时没有（见 `with_local_addresses`）
        /// Each datagram's control messages, which hold the local address it was sent to; none
        /// when local addresses are not wanted (see `with_local_addresses`)
        controls: Option<Box<[Control; BATCH]>>,
        control_lens: [usize; BATCH],
        count: usize,
    }

    impl Default for Received {
        fn default() -> Self {
            Self {
                // 页按用到才占内存：空闲时只碰第一个报文的缓冲 / Pages take memory only once touched: an idle worker touches the first buffer only
                bufs: vec![0; BATCH * RECV_SIZE].into_boxed_slice(),
                lens: [0; BATCH],
                // SAFETY: sockaddr_storage 是普通 C 结构，全零是合法值 / SAFETY: a plain C struct, all zeroes is valid
                raw: unsafe { zeroed() },
                raw_lens: [0; BATCH],
                controls: None,
                control_lens: [0; BATCH],
                count: 0,
            }
        }
    }

    impl Received {
        /// 连同每个报文发到的本机地址一起收；socket 上要先开 [`receive_local_addresses`]
        /// Receives each datagram's local address along with it; the socket needs
        /// [`receive_local_addresses`] first
        pub fn with_local_addresses(mut self) -> Self {
            self.controls = Some(Box::new([[0; 8]; BATCH]));
            self
        }

        /// 不等待地收一批，返回收到几个；一个都没有时是 `WouldBlock`
        /// Receives one batch without waiting and returns how many came; `WouldBlock` when none did
        pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
            self.count = 0;
            // SAFETY: iovec 和 mmsghdr 是普通 C 结构，全零是合法值 / SAFETY: plain C structs, all zeroes is valid
            let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
            let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
            let (bufs, _) = self.bufs.as_chunks_mut::<RECV_SIZE>();
            for (k, buf) in bufs.iter_mut().enumerate() {
                iovs[k] = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: RECV_SIZE,
                };
                let hdr = &mut hdrs[k].msg_hdr;
                hdr.msg_name = (&mut self.raw[k] as *mut libc::sockaddr_storage).cast();
                hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                hdr.msg_iov = &mut iovs[k];
                hdr.msg_iovlen = 1;
                if let Some(controls) = &mut self.controls {
                    hdr.msg_control = controls[k].as_mut_ptr().cast();
                    hdr.msg_controllen = size_of::<Control>() as _;
                }
            }
            // SAFETY: 每个头指向的缓冲和地址都属于 self，活到调用结束；内核最多写 BATCH 个
            // SAFETY: every header points at buffers and addresses owned by self that outlive the call; the kernel fills at most BATCH
            let got = unsafe {
                libc::recvmmsg(
                    fd,
                    hdrs.as_mut_ptr(),
                    BATCH as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            let got = got as usize;
            for (k, hdr) in hdrs[..got].iter().enumerate() {
                self.lens[k] = hdr.msg_len as usize;
                self.raw_lens[k] = hdr.msg_hdr.msg_namelen;
                // msg_controllen 在 glibc 上是 usize，在 musl 上是 u32 / msg_controllen is a usize on
                // glibc and a u32 on musl
                #[allow(clippy::unnecessary_cast)]
                {
                    self.control_lens[k] = hdr.msg_hdr.msg_controllen as usize;
                }
            }
            self.count = got;
            Ok(got)
        }

        /// 收到的第 `k` 个报文和它的对端；对端不是 IPv4、IPv6 的没有
        /// The `k`-th datagram received and its peer; none for a peer other than IPv4 and IPv6
        pub fn get(&self, k: usize) -> Option<(&[u8], Peer)> {
            if k >= self.count {
                return None;
            }
            let addr = socket_addr(&self.raw[k])?;
            let start = k * RECV_SIZE;
            Some((
                &self.bufs[start..start + self.lens[k].min(RECV_SIZE)],
                Peer {
                    raw: self.raw[k],
                    raw_len: self.raw_lens[k],
                    addr,
                    local: self.local_of(k),
                },
            ))
        }

        /// 第 `k` 个报文发到的本机地址，从它的控制消息里读；没要、内核没给时没有
        /// The local address the `k`-th datagram was sent to, read from its control messages;
        /// none when it was not asked for or the kernel gave none
        fn local_of(&self, k: usize) -> Option<LocalAddr> {
            let control = &self.controls.as_ref()?[k];
            // SAFETY: 普通 C 结构，全零是合法值 / SAFETY: a plain C struct, all zeroes is valid
            let mut hdr: libc::msghdr = unsafe { zeroed() };
            hdr.msg_control = control.as_ptr().cast_mut().cast();
            hdr.msg_controllen = self.control_lens[k].min(size_of::<Control>()) as _;
            // SAFETY: msg_control 指向这个报文自己的控制缓冲，msg_controllen 是内核写进去的长度、不超过缓冲；
            // CMSG_* 只在这个范围里走。缓冲按 8 字节对齐，读得了 cmsghdr；数据用 read_unaligned 读，读之前
            // 查过这条消息够长
            // SAFETY: msg_control points at this datagram's own control buffer and
            // msg_controllen is the length the kernel wrote, within the buffer; the CMSG_*
            // macros walk inside that range only. The buffer is aligned to 8 bytes, so a
            // cmsghdr can be read; the data is read with read_unaligned, after checking that
            // the message is long enough
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
                while !cmsg.is_null() {
                    let (level, kind, len) = (
                        (*cmsg).cmsg_level,
                        (*cmsg).cmsg_type,
                        (*cmsg).cmsg_len as usize,
                    );
                    let holds = |size: usize| len >= libc::CMSG_LEN(size as u32) as usize;
                    if level == libc::IPPROTO_IP
                        && kind == libc::IP_PKTINFO
                        && holds(size_of::<libc::in_pktinfo>())
                    {
                        let info: libc::in_pktinfo =
                            std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                        // ipi_spec_dst 是能拿来当源地址的那个：单播时就是报文发到的地址，广播、组播时
                        // 是内核按路由挑的本机地址。报文在 socket 开这个选项之前就排进来时内核没记它
                        // （全零），这时用报文头里的目的地址，它是单播地址才用得上
                        // ipi_spec_dst is the one usable as a source: the address the datagram
                        // was sent to for unicast, and for broadcast or multicast the local
                        // address the kernel picks by the route. For a datagram queued before
                        // the socket turned the option on the kernel noted none (all zeroes),
                        // and the destination in its header serves, if that is a unicast address
                        let noted = Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr));
                        let addr = if noted.is_unspecified() {
                            Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr))
                        } else {
                            noted
                        };
                        let usable =
                            !(addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast());
                        return usable.then_some(LocalAddr::V4(addr));
                    }
                    if level == libc::IPPROTO_IPV6
                        && kind == libc::IPV6_PKTINFO
                        && holds(size_of::<libc::in6_pktinfo>())
                    {
                        let info: libc::in6_pktinfo =
                            std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                        let addr = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                        // 组播地址当不了源地址，由内核挑 / A multicast address cannot be a
                        // source, so the kernel picks
                        if addr.is_multicast() {
                            return None;
                        }
                        let link_local = addr.segments()[0] & 0xffc0 == 0xfe80;
                        let interface = if link_local {
                            info.ipi6_ifindex as u32
                        } else {
                            0
                        };
                        return Some(LocalAddr::V6(addr, interface));
                    }
                    cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
                }
            }
            None
        }

        pub fn len(&self) -> usize {
            self.count
        }

        pub fn is_empty(&self) -> bool {
            self.count == 0
        }
    }

    /// 一批要发的回答 / One batch of replies to send
    pub struct Replies {
        bufs: Vec<BytesMut>,
        /// 和 `bufs` 的前几个一一对应 / One for each of the first `bufs`
        peers: Vec<Peer>,
    }

    impl Default for Replies {
        fn default() -> Self {
            Self {
                bufs: (0..BATCH).map(|_| BytesMut::with_capacity(512)).collect(),
                peers: Vec::with_capacity(BATCH),
            }
        }
    }

    impl Replies {
        /// 下一个回答写进这里；一批最多 `BATCH` 个（见 `is_full`）
        /// The next reply is written here; a batch holds at most `BATCH` (see `is_full`)
        pub fn next_buf(&mut self) -> &mut BytesMut {
            &mut self.bufs[self.peers.len()]
        }

        /// 刚写好的回答发给 `peer` / The reply just written goes to `peer`
        pub fn push(&mut self, peer: Peer) {
            self.peers.push(peer);
        }

        /// 第 `k` 个回答和它的对端 / The `k`-th reply and its peer
        pub fn get(&self, k: usize) -> Option<(&[u8], SocketAddr)> {
            Some((&self.bufs[k], self.peers.get(k)?.addr))
        }

        pub fn len(&self) -> usize {
            self.peers.len()
        }

        pub fn is_empty(&self) -> bool {
            self.peers.is_empty()
        }

        /// 一批已经放满 / The batch holds as many as it can
        pub fn is_full(&self) -> bool {
            self.peers.len() == BATCH
        }

        pub fn clear(&mut self) {
            self.peers.clear();
        }

        /// 从第 `from` 个起不等待地发出去，返回这次发出几个；发送缓冲满时是 `WouldBlock`，其余错误属于第 `from` 个
        /// Sends from the `from`-th on without waiting and returns how many went this time; `WouldBlock`
        /// when the send buffer is full, and any other error belongs to the `from`-th reply
        pub fn send(&self, fd: RawFd, from: usize) -> io::Result<usize> {
            let peers = self.peers.get(from..).unwrap_or_default();
            if peers.is_empty() {
                return Ok(0);
            }
            // SAFETY: 普通 C 结构，全零是合法值 / SAFETY: plain C structs, all zeroes is valid
            let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
            let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
            // 只有带着本机地址的回答才写控制消息，别的不碰这块内存
            // Only a reply carrying a local address has its control message written; the
            // others leave this memory untouched
            let mut controls = [const { std::mem::MaybeUninit::<Control>::uninit() }; BATCH];
            for (k, (buf, peer)) in self.bufs[from..].iter().zip(peers).enumerate() {
                iovs[k] = libc::iovec {
                    iov_base: buf.as_ptr().cast_mut().cast(),
                    iov_len: buf.len(),
                };
                let hdr = &mut hdrs[k].msg_hdr;
                hdr.msg_name = (&peer.raw as *const libc::sockaddr_storage)
                    .cast_mut()
                    .cast();
                hdr.msg_namelen = peer.raw_len;
                hdr.msg_iov = &mut iovs[k];
                hdr.msg_iovlen = 1;
                if let Some(local) = peer.local {
                    let (control, len) = source_control(local);
                    hdr.msg_control = controls[k].write(control).as_mut_ptr().cast();
                    hdr.msg_controllen = len as _;
                }
            }
            // SAFETY: 内核只读这些缓冲和地址，它们属于 self，活到调用结束
            // SAFETY: the kernel only reads these buffers and addresses, owned by self and alive for the call
            let sent = unsafe {
                libc::sendmmsg(fd, hdrs.as_mut_ptr(), peers.len() as libc::c_uint, 0 as _)
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(sent as usize)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod udp_batch_tests {
    use super::udp_batch::{BATCH, RECV_SIZE, Received, Replies};
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    /// 等到第一个报文到了：本机回环上先发的先到 / Waits for the first datagram: on loopback, what was sent first arrives first
    fn wait_readable(socket: &UdpSocket) {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.peek_from(&mut [0u8; 1]).expect("a datagram arrives");
    }

    fn recv_one(socket: &UdpSocket) -> Vec<u8> {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = socket.recv_from(&mut buf).expect("a reply arrives");
        buf[..len].to_vec()
    }

    /// 监听在通配地址上的 socket 收到一个报文，连同它发到的本机地址；回答带着这个地址发出，就从这个地址走。
    /// 回环上 127.0.0.0/8 都是本机地址：客户端问哪个地址，回答就从哪个地址来。成批发和单个发都是
    /// A socket on the wildcard address receives a datagram along with the local address it
    /// was sent to, and a reply carrying that address leaves from it. All of 127.0.0.0/8 is
    /// local on loopback: whichever address a client asks, the reply comes from. So for a
    /// batched send and for a single one
    #[test]
    fn a_reply_carrying_the_local_address_leaves_from_it() {
        use super::LocalAddr;
        use super::udp_batch::{Peer, receive_local_addresses, send_one};
        use std::net::{Ipv4Addr, SocketAddr};

        let server = UdpSocket::bind("0.0.0.0:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let fd = server.as_raw_fd();
        receive_local_addresses(fd, false).unwrap();
        let port = server.local_addr().unwrap().port();
        let mut received = Received::default().with_local_addresses();
        let mut replies = Replies::default();

        for asked in [
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 9, 9, 9),
            Ipv4Addr::LOCALHOST,
        ] {
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client.send_to(b"query", (asked, port)).unwrap();
            wait_readable(&server);
            assert_eq!(received.recv(fd).unwrap(), 1);
            let (data, peer) = received.get(0).unwrap();
            assert_eq!(data, b"query");
            assert_eq!(peer.local(), Some(LocalAddr::V4(asked)));

            // 成批发 / A batched send
            replies.clear();
            replies.next_buf().clear();
            replies.next_buf().extend_from_slice(b"batched");
            replies.push(peer);
            assert_eq!(replies.send(fd, 0).unwrap(), 1);
            // 单个发：对端按地址重建，再带上本机地址 / A single send: the peer rebuilt from its
            // address, then given the local address
            let rebuilt = Peer::of(peer.addr()).from_local(peer.local());
            assert_eq!(send_one(fd, b"single", &rebuilt).unwrap(), 6);

            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 64];
            for expected in [&b"batched"[..], b"single"] {
                let (len, from) = client.recv_from(&mut buf).expect("a reply arrives");
                assert_eq!(&buf[..len], expected);
                assert_eq!(from, SocketAddr::from((asked, port)), "{expected:?}");
            }
        }
    }

    /// 报文在 socket 要本机地址之前就排进来了：内核没给它记下，用报文头里的目的地址
    /// A datagram queued before the socket asked for local addresses: the kernel noted none
    /// for it, and the destination in its header serves
    #[test]
    fn a_datagram_queued_before_asking_still_gives_its_address() {
        use super::LocalAddr;
        use super::udp_batch::receive_local_addresses;
        use std::net::Ipv4Addr;

        let server = UdpSocket::bind("0.0.0.0:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let asked = Ipv4Addr::new(127, 0, 0, 2);
        client.send_to(b"query", (asked, port)).unwrap();
        wait_readable(&server);

        receive_local_addresses(server.as_raw_fd(), false).unwrap();
        let mut received = Received::default().with_local_addresses();
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 1);
        assert_eq!(
            received.get(0).unwrap().1.local(),
            Some(LocalAddr::V4(asked))
        );
    }

    /// IPv6 也一样：通配地址上收到的报文带着它发到的地址，回答从那个地址发出。不是链路本地地址时不带网卡号
    /// The same for IPv6: a datagram received on the wildcard address carries the address it
    /// was sent to, and the reply leaves from it. No interface goes with an address that is
    /// not link-local
    #[test]
    fn an_ipv6_reply_leaves_from_the_address_the_datagram_came_to() {
        use super::LocalAddr;
        use super::udp_batch::receive_local_addresses;
        use std::net::Ipv6Addr;

        // 没有 IPv6 的机器上绑不了，不测 / Cannot bind on a machine without IPv6: not tested there
        let (Ok(server), Ok(client)) = (UdpSocket::bind("[::]:0"), UdpSocket::bind("[::1]:0"))
        else {
            return;
        };
        server.set_nonblocking(true).unwrap();
        let fd = server.as_raw_fd();
        receive_local_addresses(fd, true).unwrap();
        let port = server.local_addr().unwrap().port();
        client.connect((Ipv6Addr::LOCALHOST, port)).unwrap();
        client.send(b"query").unwrap();
        wait_readable(&server);

        let mut received = Received::default().with_local_addresses();
        assert_eq!(received.recv(fd).unwrap(), 1);
        let (_, peer) = received.get(0).unwrap();
        assert_eq!(peer.local(), Some(LocalAddr::V6(Ipv6Addr::LOCALHOST, 0)));

        let mut replies = Replies::default();
        replies.next_buf().extend_from_slice(b"reply");
        replies.push(peer);
        assert_eq!(replies.send(fd, 0).unwrap(), 1);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(client.recv(&mut buf).expect("a reply arrives"), 5);
    }

    /// 没要本机地址的 socket，和以前一样：对端不带本机地址，回答由内核挑源地址
    /// A socket not asked for local addresses is as before: the peer carries none, and the
    /// kernel picks the reply's source
    #[test]
    fn without_asking_no_local_address_is_carried() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(b"query", server.local_addr().unwrap())
            .unwrap();
        wait_readable(&server);
        let mut received = Received::default();
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 1);
        assert_eq!(received.get(0).unwrap().1.local(), None);
    }

    #[test]
    fn nothing_to_read_is_would_block() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = Received::default().recv(server.as_raw_fd()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    /// 一批里每个报文带着自己的对端，回答原样发回各自的对端，IPv4 和 IPv6 都一样
    /// Each datagram in a batch carries its own peer and each reply goes back to it, over IPv4 and IPv6 alike
    #[test]
    fn each_reply_goes_back_to_its_own_sender() {
        for local in ["127.0.0.1:0", "[::1]:0"] {
            let server = UdpSocket::bind(local).unwrap();
            let target = server.local_addr().unwrap();
            let a = UdpSocket::bind(local).unwrap();
            let b = UdpSocket::bind(local).unwrap();
            let senders = [&a, &b, &a];
            for (k, sender) in senders.iter().enumerate() {
                sender.send_to(&[k as u8; 3], target).unwrap();
            }
            wait_readable(&server);
            let mut received = Received::default();
            assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 3, "{local}");
            let mut replies = Replies::default();
            for (k, sender) in senders.iter().enumerate() {
                let (packet, peer) = received.get(k).unwrap();
                assert_eq!(packet, [k as u8; 3]);
                assert_eq!(peer.addr(), sender.local_addr().unwrap(), "{local}");
                let reply = replies.next_buf();
                reply.clear();
                reply.extend_from_slice(&[10 + k as u8; 5]);
                replies.push(peer);
            }
            assert!(received.get(3).is_none());
            assert_eq!(replies.send(server.as_raw_fd(), 0).unwrap(), 3);
            assert_eq!(recv_one(&a), [10; 5]);
            assert_eq!(recv_one(&b), [11; 5]);
            assert_eq!(recv_one(&a), [12; 5]);
        }
    }

    /// 超过一批的留给下一次收，一个不丢；没有了就是 WouldBlock
    /// What does not fit in a batch waits for the next receive, none lost; then it is WouldBlock
    #[test]
    fn more_than_a_batch_waits_for_the_next_receive() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        for k in 0..BATCH + 3 {
            client
                .send_to(&(k as u16).to_be_bytes(), server.local_addr().unwrap())
                .unwrap();
        }
        wait_readable(&server);
        let mut received = Received::default();
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), BATCH);
        assert_eq!(
            received.get(BATCH - 1).unwrap().0,
            (BATCH as u16 - 1).to_be_bytes()
        );
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 3);
        assert_eq!(received.get(0).unwrap().0, (BATCH as u16).to_be_bytes());
        assert!(received.get(3).is_none());
        let error = received.recv(server.as_raw_fd()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(received.is_empty());
    }

    /// 比接收缓冲长的报文截到缓冲那么长，和单收时一样 / A datagram longer than the buffer is cut to it, as for single receives
    #[test]
    fn a_long_datagram_is_cut_to_the_buffer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&vec![7u8; RECV_SIZE + 100], server.local_addr().unwrap())
            .unwrap();
        wait_readable(&server);
        let mut received = Received::default();
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 1);
        assert_eq!(received.get(0).unwrap().0, vec![7u8; RECV_SIZE]);
    }

    /// 从中间接着发只发剩下的：发送缓冲满过一次以后从这里继续
    /// Sending from the middle sends only the rest: where sending resumes after the buffer was full
    #[test]
    fn sending_from_the_middle_sends_only_the_rest() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        for k in 0..3u8 {
            client.send_to(&[k], server.local_addr().unwrap()).unwrap();
        }
        wait_readable(&server);
        let mut received = Received::default();
        assert_eq!(received.recv(server.as_raw_fd()).unwrap(), 3);
        let mut replies = Replies::default();
        for k in 0..3 {
            let (packet, peer) = received.get(k).unwrap();
            let reply = replies.next_buf();
            reply.clear();
            reply.extend_from_slice(packet);
            replies.push(peer);
        }
        assert_eq!(replies.send(server.as_raw_fd(), 1).unwrap(), 2);
        assert_eq!(replies.send(server.as_raw_fd(), 3).unwrap(), 0);
        assert_eq!(recv_one(&client), [1]);
        assert_eq!(recv_one(&client), [2]);
        client.set_nonblocking(true).unwrap();
        assert!(client.recv_from(&mut [0u8; 8]).is_err());
    }
}
