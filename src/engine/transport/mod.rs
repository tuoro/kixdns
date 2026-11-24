//! 上游传输：UDP（`udp`）、TCP 和 DoT（`stream`）、DoH（`doh`）、DoQ（`doq`），它们共用的建连、老化和连接池
//! （`connect`），以及上游地址的读法（`address`）。各传输的客户端、多路复用器和连接池都从这里拿
//! The upstream transports: UDP (`udp`), TCP and DoT (`stream`), DoH (`doh`) and DoQ (`doq`),
//! the connecting, aging and pooling they share (`connect`), and how upstream addresses are read
//! (`address`). Each transport's client, multiplexer and pool is reached from here

mod address;
mod connect;
mod doh;
mod doq;
mod stream;
#[cfg(test)]
mod test_support;
mod udp;

pub use connect::ConnectionPool;
pub use doh::DohClient;
pub use doq::{DoqClient, DoqConnectionPool, DoqMuxClient};
pub use stream::{
    Dot, DotConnectionPool, DotMultiplexer, DotMuxClient, StreamConnectionPool, StreamMultiplexer,
    StreamMuxClient, StreamTransport, Tcp, TcpConnectionPool, TcpMultiplexer, TcpMuxClient,
};
pub use udp::UdpClient;

pub(crate) use address::{check_upstream_address, host_name};
pub(in crate::engine) use connect::{Aging, Connect, Wear, connect_tcp, forget};
pub(crate) use connect::{InFlight, least_busy};
#[cfg(test)]
pub(crate) use doh::DOH_MEDIA_TYPE;
pub(crate) use doh::throttle_of;
pub(crate) use udp::UdpExchange;

use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// 一条连接上同时有这么多查询还没答完就算忙，再来的查询换下一条：TCP、DoT 的连接池和 DoH 的连接位都这样挑
/// （见 [`least_busy`]）。一阵子几十个以内的查询（比如打开一个网页）都留在第一条连接上，用不着的连接不去连，
/// 常用的那条也不会因为隔太久没轮到而被当作空闲关掉、下个查询再重新连；一直有这么多在途时才分到后面的连接，
/// 各条连接的收发落到不同的核上
/// A connection with this many queries unanswered at once counts as busy, and further queries go
/// to the next one: the TCP and DoT pools and the DoH slots all pick this way (see
/// [`least_busy`]). A burst of a few dozen queries at most (a web page opening, say) stays on the
/// first connection, so connections nothing needs are not made, and the one in use is never left
/// unvisited long enough to be closed as idle and made again for the next query; only steadily
/// this many in flight spreads queries over the later connections, whose I/O then lands on
/// different cores
pub(crate) const BUSY_AT: usize = 32;

/// Least budget worth spending on a transparent retry over a fresh connection.
/// A retry has to reconnect (SYN, plus a TLS handshake for DoT and DoH) and
/// then wait for an answer; with less than this left it cannot complete on a
/// realistic path and would only add a second failure after the caller's
/// deadline. The caller's deadline itself is never extended.
/// 值得为透明重试花的最小剩余预算。重试要先重连（SYN，DoT/DoH 还有 TLS 握手）再等应答，
/// 剩余不足这个值时现实路径上跑不完，只会在调用方截止后再失败一次。绝不延长调用方的截止。
const MIN_RETRY_BUDGET: Duration = Duration::from_millis(50);

/// 从 `started` 起有 `budget` 的查询还剩多少，够一次透明重试（见 [`MIN_RETRY_BUDGET`]）时给出来；TCP、DoT、DoH 和
/// DoQ 都按它定重不重试
/// What is left of a query's `budget` from `started`, given when it is enough for a transparent
/// retry (see [`MIN_RETRY_BUDGET`]); TCP, DoT, DoH and DoQ all decide on a retry by it
pub(super) fn retry_budget(budget: Duration, started: tokio::time::Instant) -> Option<Duration> {
    Some(budget.saturating_sub(started.elapsed())).filter(|left| *left >= MIN_RETRY_BUDGET)
}

/// 等着一个在途条目的回答的那一头：回答从 `rx` 来。放手时（拿到了回答、超时、取消、提前返回、panic）把 `map` 里
/// `id` 下已经没人等的条目删掉：先关掉自己这一头再删，所以自己的条目一定删得掉。回答到了、读取任务把条目拿走以后，
/// 这个 ID 可能已经分给了后来的查询，那一条有人等着，不动：按 ID 不管是谁都删的话，会把它带走，它的回答到了找不到
/// 条目，只能等到超时
/// The end that waits for an in-flight entry's answer, which comes on `rx`. On letting go (with
/// the answer, at a timeout, on cancellation, an early return or a panic) it removes the entry
/// under `id` in `map` if nobody waits on it any more: its own end is closed first, so its own
/// entry always goes. Once an answer has come and the reader has taken the entry, the ID may
/// have gone to a later query, whose entry is waited on and stays: removing by ID whatever is
/// there would take it along, its answer finding no entry and the query waiting out its timeout
pub(super) struct Waiting<V> {
    rx: oneshot::Receiver<anyhow::Result<Bytes>>,
    map: Arc<DashMap<u16, V, FxBuildHasher>>,
    id: u16,
    /// 这个条目的回答是不是没人等了 / Whether nobody waits for this entry's answer any more
    abandoned: fn(&V) -> bool,
}

impl<V> Drop for Waiting<V> {
    fn drop(&mut self) {
        self.rx.close();
        self.map
            .remove_if(&self.id, |_, entry| (self.abandoned)(entry));
    }
}

pub(super) const MAX_DNS_MESSAGE_SIZE: usize = 65_535;
