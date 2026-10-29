//! What the integration tests that run the real binary share.
//!
//! 跑真程序的集成测试共用的部分。

// Each test binary uses its own part of this / 每个测试程序只用到其中一部分
#![allow(dead_code)]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::process::Child;

/// A local port free for both TCP and UDP / 本机上 TCP 和 UDP 都空着的端口
///
/// 先拿 UDP 端口再看同号的 TCP：TCP 挑临时端口时不看 UDP 的占用，反过来更容易撞上别的测试占着的
/// UDP 端口。最多试 20 次。
/// The UDP port first, then TCP on the same number: the TCP ephemeral allocator does
/// not look at UDP, so the other order runs into UDP ports other tests hold more often.
/// At most 20 tries.
pub fn free_port() -> u16 {
    for _ in 0..20 {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = udp.local_addr().unwrap().port();
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("port conflict: no port free for both UDP and TCP in 20 tries");
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
