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

    /// 一批最多这么多个报文 / The most datagrams in one batch
    pub const BATCH: usize = 32;
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
    }

    impl Peer {
        pub fn addr(&self) -> SocketAddr {
            self.addr
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
                count: 0,
            }
        }
    }

    impl Received {
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
                },
            ))
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
        /// 下一个回答写进这里；一批最多 `BATCH` 个，不比收到的多
        /// The next reply is written here; a batch holds at most `BATCH`, no more than were received
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
