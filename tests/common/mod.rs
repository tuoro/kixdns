//! What the integration tests that run the real binary share.
//!
//! 跑真程序的集成测试共用的部分。

// Each test binary uses its own part of this / 每个测试程序只用到其中一部分
#![allow(dead_code)]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::process::Child;
use std::sync::atomic::{AtomicU32, Ordering};

/// A local port free for both TCP and UDP / 本机上 TCP 和 UDP 都空着的端口
///
/// 挑在系统分配临时端口的范围之下（Linux 从 32768 起）。范围内的端口查完以后到内核绑定之前是空着的，
/// 这期间任何新开的 socket 都可能拿走它，包括内核自己的上游 socket，内核就起不来了。起点从进程号算，
/// 同时跑的测试程序不容易挑到同一个；一个测试程序里不会挑到两次。最多试 200 次。
/// Picked below the range the system hands out ephemeral ports from (32768 up on Linux). A port in that
/// range sits free between this check and the kernel binding it, and any new socket may take it
/// meanwhile, the kernel's own upstream sockets included, and the kernel does not start. The starting
/// point comes from the process id, so test binaries running together rarely pick the same; one binary
/// never picks a port twice. At most 200 tries.
pub fn free_port() -> u16 {
    const FIRST: u32 = 20_000;
    const PORTS: u32 = 12_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let start = std::process::id().wrapping_mul(61);
    for _ in 0..200 {
        let next = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = (FIRST + start.wrapping_add(next) % PORTS) as u16;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port));
        if udp.is_ok() && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("port conflict: no port free for both UDP and TCP in 200 tries");
}

/// The running binary, ended when the test ends, a failing one too
/// 跑着的程序，测试结束时（失败也一样）结束它
pub struct Kernel(pub Child);

impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether the control socket at `path` answers /v1/health with 200
/// 控制通道 `path` 对 /v1/health 回不回 200
#[cfg(unix)]
pub fn control_answers(path: &std::path::Path) -> bool {
    use std::io::{Read, Write};
    let attempt = || -> std::io::Result<bool> {
        let mut stream = std::os::unix::net::UnixStream::connect(path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: kixdns\r\nConnection: close\r\n\r\n")?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head)?;
        Ok(head.starts_with(b"HTTP/1.1 200"))
    };
    attempt().unwrap_or(false)
}
