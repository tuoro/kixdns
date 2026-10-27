//! The control socket drops a client that stops part way through a request.
//!
//! Runs the real binary with its control socket and opens three connections:
//! - one that sends half a request head;
//! - one that sends a whole head but only the start of the body it announced;
//! - one that sends nothing at all.
//!
//! Each has to be closed within the read timeout, the late body answered 408,
//! while the socket keeps answering others. They all used to stay open for good,
//! each holding a task and a descriptor.
//!
//! 控制通道断开请求发到一半就不动的客户端：在真的程序上开三条连接，一条只发半个请求头，一条发完
//! 请求头、正文只发开头，一条什么都不发。每条都要在读取时限内被断开，正文迟到的那条回 408，其间
//! 控制通道照常回答别人。以前它们会一直开着，各占一个任务和一个句柄。
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{Kernel, control_answers, free_port};

/// Everything the server sends until it closes, and how long that took; None
/// when it is still open after `limit`
fn read_until_closed(stream: &mut UnixStream, limit: Duration) -> Option<(Vec<u8>, Duration)> {
    let started = Instant::now();
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    while started.elapsed() < limit {
        match stream.read(&mut buf) {
            Ok(0) => return Some((received, started.elapsed())),
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Some((received, started.elapsed())),
        }
    }
    None
}

#[test]
fn the_control_socket_drops_a_request_that_stops_part_way() {
    let dir = tempfile::TempDir::new().unwrap();
    let control = dir.path().join("control.sock");
    let port = free_port();
    let config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{ "id": "main", "rules": [] }],
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let _kernel = Kernel(
        Command::new(env!("CARGO_BIN_EXE_kixdns"))
            .args(["run", "--config"])
            .arg(&config_path)
            .arg("--admin-socket")
            .arg(&control)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while !control_answers(&control) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "kernel did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut half_head = UnixStream::connect(&control).unwrap();
    half_head
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: kixdns\r\n")
        .unwrap();
    let mut half_body = UnixStream::connect(&control).unwrap();
    half_body
        .write_all(
            b"POST /v1/config/validate HTTP/1.1\r\nHost: kixdns\r\nContent-Length: 100\r\n\r\n{",
        )
        .unwrap();
    let mut silent = UnixStream::connect(&control).unwrap();

    // 等着的时候，控制通道照常回答别人 / Meanwhile the control socket answers others as usual
    assert!(control_answers(&control));

    // 三条一起等，最多 15 秒 / All three waited on together, 15 s at most
    let limit = Duration::from_secs(15);
    let (head, body, nothing) = std::thread::scope(|scope| {
        let head = scope.spawn(|| read_until_closed(&mut half_head, limit));
        let body = scope.spawn(|| read_until_closed(&mut half_body, limit));
        let nothing = scope.spawn(|| read_until_closed(&mut silent, limit));
        (
            head.join().unwrap(),
            body.join().unwrap(),
            nothing.join().unwrap(),
        )
    });
    assert!(head.is_some(), "half a request head is dropped");
    assert!(
        nothing.is_some(),
        "a connection that sends nothing is dropped"
    );
    let (reply, _) = body.expect("a late body is dropped");
    assert!(
        reply.starts_with(b"HTTP/1.1 408"),
        "a late body is answered 408: {}",
        String::from_utf8_lossy(&reply)
    );
    assert!(
        control_answers(&control),
        "the control socket still answers"
    );
}
