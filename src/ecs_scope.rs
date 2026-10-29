//! 按 ECS 作用范围缓存应答（RFC 7871 第 7.3 节）
//! Caching answers by the network their ECS scope covers (RFC 7871 section 7.3)
//!
//! 转发给上游的 ECS 子网（SOURCE）和上游应答里的作用范围（SCOPE）决定一份应答适用于
//! 哪些请求方。缓存为每个问题保留一组应答，每份都带着它适用的范围；查找时只取适用于
//! 当前请求方的那些，再按最长前缀挑一份。
//! The ECS subnet sent upstream (SOURCE) and the scope in the upstream's reply
//! (SCOPE) decide which requesters an answer applies to. The cache keeps a set of
//! answers per question, each with the reach it applies to; a lookup takes only
//! the ones that apply to the requester and picks one by longest prefix.

use std::net::IpAddr;

use smallvec::SmallVec;

use crate::config::EcsMode;
use crate::ecs::{EcsKey, EcsPlan, plan};

/// 转发发给上游的 ECS / The ECS a forward sends upstream
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sent {
    /// 不带 ECS 选项 / No ECS option
    Absent,
    /// 这个子网 / This subnet
    Subnet(EcsKey),
}

impl Sent {
    /// 按 `plan` 转发 `view` 的请求时发出的 ECS / The ECS sent for `view`'s request under `plan`
    pub(crate) fn of(plan: EcsPlan, view: &EcsView) -> Self {
        match plan {
            EcsPlan::Strip => Self::Absent,
            EcsPlan::Keep => view.client.map_or(Self::Absent, Self::Subnet),
            EcsPlan::Set(subnet) => Self::Subnet(subnet),
        }
    }
}

/// 缓存在 ECS 方面能分辨的请求方：来源地址，和客户端自己带的 ECS
/// What the cache can tell about a requester as far as ECS goes: its address,
/// and the ECS option the client sent itself
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcsView {
    pub peer: IpAddr,
    pub client: Option<EcsKey>,
}

/// 转发的 ECS 怎样取决于请求方，与 `crate::ecs::plan` 一致
/// How a forward's ECS depends on the requester, as `crate::ecs::plan` decides it
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EcsSource {
    /// 客户端自己带的 ECS：转发没写 `ecs`，或者固定 IP 无效
    /// The client's own ECS: the forward has no `ecs`, or its static IP is invalid
    Client,
    /// `from_client_ip`：客户端自己带了 ECS 时，它的子网按这些前缀截短；读不懂时什么也不发；没带或者
    /// 是私有网段时，来源地址按这些前缀取子网，私有地址则不加（见 `crate::ecs::plan`）
    /// `from_client_ip`: the client's own subnet cut to these prefixes when it sent
    /// ECS; nothing when it sent one nobody can read; when it sent none or a private
    /// network, the address's subnet at these prefixes, or nothing for a private
    /// address (see `crate::ecs::plan`)
    Peer { prefix_v4: u8, prefix_v6: u8 },
    /// 与请求方无关：`clear`，或有效的固定 IP
    /// Independent of the requester: `clear`, or a valid static IP
    Fixed,
}

impl EcsSource {
    pub fn of(mode: Option<&EcsMode>) -> Self {
        match mode {
            None => Self::Client,
            Some(EcsMode::Clear) => Self::Fixed,
            Some(EcsMode::FromClientIp {
                prefix_v4,
                prefix_v6,
            }) => Self::Peer {
                prefix_v4: *prefix_v4,
                prefix_v6: *prefix_v6,
            },
            Some(EcsMode::Static { ip, .. }) => {
                if ip.parse::<IpAddr>().is_ok() {
                    Self::Fixed
                } else {
                    Self::Client
                }
            }
        }
    }

    /// 这样的转发为 `view` 的请求发出的 ECS；`Fixed` 不取决于请求方，这里没有答案
    /// The ECS such a forward sends for `view`'s request; `Fixed` does not depend
    /// on the requester and has no answer here
    fn sent(&self, view: &EcsView) -> Option<Sent> {
        match *self {
            Self::Client => Some(Sent::of(EcsPlan::Keep, view)),
            Self::Peer {
                prefix_v4,
                prefix_v6,
            } => {
                let mode = EcsMode::FromClientIp {
                    prefix_v4,
                    prefix_v6,
                };
                Some(Sent::of(
                    plan(Some(&mode), view.peer, view.client.as_ref()),
                    view,
                ))
            }
            Self::Fixed => None,
        }
    }

    /// 这样的转发为 `view` 的请求发出的 ECS 是否取自客户端自己带的（原样或截短）
    /// Whether the ECS such a forward sends for `view`'s request comes from the
    /// client's own, as it is or cut short
    fn sends_client_subnet(&self, view: &EcsView) -> bool {
        match *self {
            Self::Client => true,
            Self::Peer { .. } => crate::ecs::forwards_own_ecs(view.peer, view.client.as_ref()),
            Self::Fixed => false,
        }
    }
}

/// 一次转发的 ECS：怎样取得，以及为这个请求发出了什么。响应跳转路径上的转发原样发送
/// 跳转前那次转发的包，所以沿用它的这一份。
/// One forward's ECS: how it is derived, and what it sends for this request. A
/// forward on the response-jump path sends the packet of the forward before the
/// jump as it is, so it keeps that one's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ForwardEcs {
    pub source: EcsSource,
    pub sent: Sent,
}

impl ForwardEcs {
    /// 带 `mode`（None 表示没写 `ecs`）的转发为 `view` 的请求发送的 ECS
    /// The ECS a forward with `mode` (None: no `ecs`) sends for `view`'s request
    pub fn of(mode: Option<&EcsMode>, view: &EcsView) -> Self {
        Self {
            source: EcsSource::of(mode),
            sent: Sent::of(plan(mode, view.peer, view.client.as_ref()), view),
        }
    }
}

/// 上游应答里的 ECS / The ECS in an upstream's reply
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyEcs {
    /// 没有 ECS 选项 / No ECS option
    Absent,
    /// FAMILY、SOURCE PREFIX-LENGTH、ADDRESS 和 SCOPE PREFIX-LENGTH
    /// FAMILY, SOURCE PREFIX-LENGTH, ADDRESS and SCOPE PREFIX-LENGTH
    Subnet { subnet: EcsKey, scope: u8 },
    /// 应答读不出来 / The reply could not be read
    Unreadable,
}

/// 一份应答适用于哪些请求方：它们以同样方式取得的 ECS 要满足的条件（RFC 7871 第 7.3.1 节）
/// Which requesters an answer applies to: what the ECS they would send the same
/// way must satisfy (RFC 7871 section 7.3.1)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reach {
    /// 发出时没有 ECS：只适用于同样不带 ECS 的请求
    /// Sent without ECS: only for requests that send none either
    NoEcs,
    /// 作用范围为 0，或者应答不带 ECS（RFC 7871 第 7.3 节按作用范围 0 处理）：适用于每个发出
    /// ECS 子网的请求。不发 ECS 的请求发给上游的是另一种查询（`from_client_ip` 还会给它补上 OPT），
    /// 所以不包括它们。
    /// Scope 0, or a reply without ECS (which RFC 7871 section 7.3 counts as scope
    /// 0): every request that sends an ECS subnet. A request that sends none asks
    /// the upstream a different kind of query (`from_client_ip` even adds an OPT
    /// record for it), so it is left out.
    AnySubnet,
    /// 作用范围不超过发出的前缀：发出的子网落在这个网段内（前缀至少一样长）的请求
    /// Scope no longer than the prefix sent: requests whose subnet lies inside this
    /// network (a prefix at least as long)
    Within(EcsKey),
    /// 只适用于发出完全相同子网的请求：作用范围比发出的前缀还长、发出的前缀是 0、应答回显的
    /// 子网与发出的对不上，或者应答是错误而不是回答
    /// Only for requests that send exactly this subnet: the scope is longer than
    /// the prefix sent, the prefix sent is 0, the reply echoes another subnet, or
    /// the reply is an error rather than an answer
    Exactly(EcsKey),
}

impl Reach {
    fn admits(&self, sent: &Sent) -> bool {
        match (self, sent) {
            (Self::NoEcs, Sent::Absent) => true,
            (Self::AnySubnet, Sent::Subnet(subnet)) => !subnet.is_opaque(),
            (Self::Within(net), Sent::Subnet(subnet)) => {
                subnet.family == net.family
                    && subnet.source_prefix >= net.source_prefix
                    && subnet.truncated(net.source_prefix) == *net
            }
            (Self::Exactly(exact), Sent::Subnet(subnet)) => subnet == exact,
            _ => false,
        }
    }

    /// 最长前缀匹配用的具体程度：前缀越长越具体，前缀相同时完全相同的子网比网段具体
    /// How specific, for longest-prefix matching: longer prefixes are more specific,
    /// and at the same prefix the exact subnet beats the network
    fn specificity(&self) -> u32 {
        match self {
            Self::NoEcs | Self::AnySubnet => 0,
            Self::Within(subnet) => 2 * u32::from(subnet.source_prefix) + 1,
            Self::Exactly(subnet) => 2 * u32::from(subnet.source_prefix) + 2,
        }
    }
}

/// 最终应答依赖的一次转发：它的 ECS 怎样取得，应答适用于谁
/// One forward the final answer depends on: how its ECS was derived, and whom
/// its answer applies to
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Step {
    source: EcsSource,
    reach: Reach,
    /// 回给带 ECS 的客户端时报的作用范围 / The scope reported to a client that sent ECS
    scope: u8,
}

/// 一份应答适用的请求方：每一步都接受的请求方。没有步骤时，适用于同一槽位的所有请求方。
/// The requesters an answer applies to: those every step admits. Without steps it
/// applies to every requester of its slot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcsReach {
    steps: SmallVec<[Step; 1]>,
    /// 实际发出的 ECS 与 `crate::ecs::plan` 推算的不一样（客户端的 ECS 选项读不懂、改写失败
    /// 而原样发出等）：拿不准应答适用于谁，不缓存
    /// The ECS actually sent differs from what `crate::ecs::plan` works out (a client
    /// ECS option that cannot be read, a rewrite that failed and sent the packet as
    /// it was, and so on): whom the answer applies to is unknown, so it is not cached
    uncacheable: bool,
}

impl EcsReach {
    /// 带着 `ecs` 的一次转发拿到了带 `reply` 的应答；`answered` 表示应答的 RCODE 是
    /// NOERROR 或 NXDOMAIN，即上游作答了，而不是报错。
    /// A forward that sent `ecs` got a reply carrying `reply`; `answered` means the
    /// reply's RCODE is NOERROR or NXDOMAIN, so the upstream answered rather than
    /// reported an error.
    pub fn record(&mut self, ecs: ForwardEcs, reply: ReplyEcs, answered: bool) {
        let ForwardEcs { source, sent } = ecs;
        if source == EcsSource::Fixed {
            return;
        }
        if let Some((reach, scope)) = reach_of(sent, reply, answered) {
            self.push(Step {
                source,
                reach,
                scope,
            });
        }
    }

    /// 带着 `ecs` 的一次转发拿到了应答 `reply`（整个报文）/ A forward that sent `ecs` got the reply `reply` (the whole message)
    pub fn record_reply(&mut self, ecs: ForwardEcs, reply: &[u8]) {
        let (reply_ecs, answered) = crate::proto_utils::reply_ecs(reply);
        self.record(ecs, reply_ecs, answered);
    }

    /// 同上，但这次转发没拿到应答：不知道失败（以及失败后得到的应答）对别的子网是否
    /// 也一样，所以只适用于发出同样 ECS 的请求。
    /// The same for a forward that got no reply: whether the failure, and the
    /// answer reached after it, holds for other subnets is unknown, so it applies
    /// only to requests that send the same ECS.
    /// 和读不懂 ECS 的报错应答一样，见 `reach_of` / As an error reply whose ECS cannot be read,
    /// see `reach_of`
    pub fn record_failure(&mut self, ecs: ForwardEcs) {
        self.record(ecs, ReplyEcs::Unreadable, false);
    }

    /// 实际发出的 ECS 与推算的不一样，见 `uncacheable` / The ECS actually sent differs, see `uncacheable`
    pub fn mark_uncacheable(&mut self) {
        self.uncacheable = true;
    }

    pub fn is_uncacheable(&self) -> bool {
        self.uncacheable
    }

    fn push(&mut self, step: Step) {
        if !self.steps.contains(&step) {
            self.steps.push(step);
        }
    }

    /// 应答是否适用于 `view` / Whether the answer applies to `view`
    pub fn admits(&self, view: &EcsView) -> bool {
        self.steps.iter().all(|step| {
            step.source
                .sent(view)
                .is_some_and(|sent| step.reach.admits(&sent))
        })
    }

    /// 最长前缀匹配用的具体程度 / How specific, for longest-prefix matching
    pub fn specificity(&self) -> u32 {
        self.steps.iter().map(|step| step.reach.specificity()).sum()
    }

    /// 只按「带不带 ECS」区分的应答：适用于一整类请求方，槽位满了时最后才淘汰
    /// An answer told apart only by whether ECS is sent: it serves a whole class of
    /// requesters, so a full slot evicts it last
    pub fn is_broad(&self) -> bool {
        self.steps
            .iter()
            .all(|step| matches!(step.reach, Reach::NoEcs | Reach::AnySubnet))
    }

    /// 回给带着 ECS 的 `view` 时报的作用范围：应答依赖它自己那份 ECS 的多少位
    /// The scope to report to `view`, which sent ECS: how many bits of its own ECS
    /// the answer depends on
    pub fn echo_scope(&self, view: &EcsView) -> u8 {
        self.steps
            .iter()
            .filter(|step| step.source.sends_client_subnet(view))
            .map(|step| step.scope)
            .max()
            .unwrap_or(0)
    }

    /// 适用于槽位里的所有请求方 / Applies to every requester of its slot
    pub fn is_universal(&self) -> bool {
        self.steps.is_empty()
    }
}

/// 发出 `sent`、应答带 `reply` 时，应答适用的范围和要报的作用范围；None 表示适用于所有人。
/// The reach of an answer to a query sent with `sent` whose reply carries `reply`,
/// and the scope to report; None means everyone.
fn reach_of(sent: Sent, reply: ReplyEcs, answered: bool) -> Option<(Reach, u8)> {
    let Sent::Subnet(subnet) = sent else {
        return Some((Reach::NoEcs, 0));
    };
    let exactly = Some((Reach::Exactly(subnet), subnet.source_prefix));
    if subnet.source_prefix == 0 {
        // 前缀为 0 的查询拿到的应答，只给同样前缀为 0 的查询（第 7.3.1 节），不论应答怎样
        // An answer to a query with prefix 0 serves only queries with prefix 0
        // (section 7.3.1), whatever the reply says
        return exactly;
    }
    match reply {
        // RFC 7871 第 7.3 节：带 ECS 的查询得到不带 ECS 的应答，按作用范围 0 处理。报错的应答
        // （SERVFAIL、REFUSED 等）说的是发出的这个子网，不推广到别处。
        // RFC 7871 section 7.3: a reply without ECS to a query with it counts as
        // scope 0. An error reply (SERVFAIL, REFUSED and so on) speaks of the subnet
        // sent and goes no further.
        ReplyEcs::Absent if answered => Some((Reach::AnySubnet, 0)),
        ReplyEcs::Absent | ReplyEcs::Unreadable => exactly,
        ReplyEcs::Subnet {
            subnet: echoed,
            scope,
        } => {
            if echoed != subnet {
                // RFC 7871 第 7.3 节要求丢弃这样的应答。这里照常使用，只是不让它适用于别的子网。
                // RFC 7871 section 7.3 says to drop such a reply. It is used as usual
                // here, only kept from any other subnet.
                exactly
            } else if scope == 0 {
                if answered {
                    Some((Reach::AnySubnet, 0))
                } else {
                    exactly
                }
            } else if scope <= subnet.source_prefix {
                Some((Reach::Within(subnet.truncated(scope)), scope))
            } else {
                // 作用范围比发出的前缀长：只给前缀相同的同一子网（第 7.3.1 节）
                // A scope longer than the prefix sent: only the same subnet at the same
                // prefix (section 7.3.1)
                Some((Reach::Exactly(subnet), scope))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecs::subnet;

    fn view(peer: &str, client: Option<&str>) -> EcsView {
        EcsView {
            peer: peer.parse().unwrap(),
            client: client.map(subnet),
        }
    }

    fn echoed(text: &str, scope: u8) -> ReplyEcs {
        ReplyEcs::Subnet {
            subnet: subnet(text),
            scope,
        }
    }

    fn sent(source: EcsSource, text: &str) -> ForwardEcs {
        ForwardEcs {
            source,
            sent: Sent::Subnet(subnet(text)),
        }
    }

    const PEER: EcsSource = EcsSource::Peer {
        prefix_v4: 24,
        prefix_v6: 56,
    };

    /// 透传客户端 ECS 的一次转发拿到应答 `reply`（作答而非报错）后的范围
    /// The reach after a pass-through forward got the answer `reply`
    fn passed_through(client: &str, reply: ReplyEcs) -> EcsReach {
        let mut reach = EcsReach::default();
        reach.record(sent(EcsSource::Client, client), reply, true);
        reach
    }

    #[test]
    fn a_reply_without_ecs_or_with_scope_zero_serves_every_subnet() {
        for reach in [
            passed_through("198.51.100.0/24", ReplyEcs::Absent),
            passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 0)),
        ] {
            assert!(reach.admits(&view("10.0.0.1", Some("203.0.113.0/24"))));
            assert!(reach.admits(&view("10.0.0.1", Some("2001:db8::/56"))));
            // 不发 ECS 的请求是另一种查询 / A request sending no ECS is another kind of query
            assert!(!reach.admits(&view("10.0.0.1", None)));
            assert!(reach.is_broad());
        }
    }

    #[test]
    fn an_error_without_ecs_stays_with_the_subnet_sent() {
        for reply in [ReplyEcs::Absent, echoed("198.51.100.0/24", 0)] {
            let mut reach = EcsReach::default();
            reach.record(sent(EcsSource::Client, "198.51.100.0/24"), reply, false);
            assert!(reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
            assert!(!reach.admits(&view("10.0.0.1", Some("203.0.113.0/24"))));
        }
    }

    #[test]
    fn a_scope_covers_the_network_it_names() {
        let reach = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 16));
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.7.0/24"))));
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.7.9/32"))));
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.0.0/16"))));
        // 前缀更短，子网就不在这个网段内 / A shorter prefix does not lie inside the network
        assert!(!reach.admits(&view("10.0.0.1", Some("198.0.0.0/8"))));
        assert!(!reach.admits(&view("10.0.0.1", Some("203.0.113.0/24"))));
        assert!(!reach.admits(&view("10.0.0.1", None)));
        assert!(!reach.admits(&view("10.0.0.1", Some("2001:db8::/56"))));
    }

    #[test]
    fn a_scope_longer_than_the_source_takes_the_same_prefix() {
        let reach = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 28));
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
        assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/28"))));
        assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/25"))));
    }

    #[test]
    fn a_source_of_zero_answers_only_source_zero() {
        for reply in [echoed("0.0.0.0/0", 0), ReplyEcs::Absent] {
            let reach = passed_through("0.0.0.0/0", reply);
            assert!(reach.admits(&view("10.0.0.1", Some("0.0.0.0/0"))));
            assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
            assert!(!reach.admits(&view("10.0.0.1", None)));
        }
    }

    #[test]
    fn a_mismatched_or_unreadable_echo_answers_only_the_subnet_sent() {
        for reply in [echoed("203.0.113.0/24", 16), ReplyEcs::Unreadable] {
            let reach = passed_through("198.51.100.0/24", reply);
            assert!(reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
            assert!(!reach.admits(&view("10.0.0.1", Some("198.51.7.0/24"))));
            assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/25"))));
        }
    }

    #[test]
    fn nothing_sent_answers_only_requests_that_send_nothing() {
        let mut reach = EcsReach::default();
        reach.record(
            ForwardEcs {
                source: EcsSource::Client,
                sent: Sent::Absent,
            },
            ReplyEcs::Absent,
            true,
        );
        assert!(reach.admits(&view("10.0.0.1", None)));
        assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
        assert!(reach.is_broad());
    }

    #[test]
    fn from_client_ip_judges_each_requester_by_what_it_would_send() {
        let mut reach = EcsReach::default();
        reach.record(
            sent(PEER, "198.51.100.0/24"),
            echoed("198.51.100.0/24", 24),
            true,
        );
        assert!(reach.admits(&view("198.51.100.200", None)));
        assert!(!reach.admits(&view("198.51.101.1", None)));
        // 私有地址的客户端发的是自己带的 ECS / A private client sends its own ECS
        assert!(reach.admits(&view("192.168.1.2", Some("198.51.100.0/24"))));
        assert!(!reach.admits(&view("192.168.1.2", None)));
        // 作用范围为 0 时，私有地址又没带 ECS 的客户端发的是另一种查询
        // At scope 0, a private client without ECS still sends another kind of query
        let mut shared = EcsReach::default();
        shared.record(sent(PEER, "198.51.100.0/24"), ReplyEcs::Absent, true);
        assert!(shared.admits(&view("203.0.113.9", None)));
        assert!(!shared.admits(&view("192.168.1.2", None)));
    }

    #[test]
    fn a_fixed_ecs_records_nothing() {
        let mut reach = EcsReach::default();
        reach.record(
            sent(EcsSource::Fixed, "203.0.113.0/24"),
            echoed("203.0.113.0/24", 24),
            true,
        );
        reach.record_failure(ForwardEcs {
            source: EcsSource::Fixed,
            sent: Sent::Absent,
        });
        assert!(reach.is_universal());
    }

    #[test]
    fn a_failure_holds_only_for_the_same_ecs() {
        let mut reach = EcsReach::default();
        reach.record_failure(sent(EcsSource::Client, "198.51.100.0/24"));
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
        assert!(!reach.admits(&view("10.0.0.1", Some("198.51.100.0/25"))));
        let mut nothing = EcsReach::default();
        nothing.record_failure(ForwardEcs {
            source: EcsSource::Client,
            sent: Sent::Absent,
        });
        assert!(nothing.admits(&view("10.0.0.1", None)));
        assert!(!nothing.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
    }

    #[test]
    fn every_step_must_admit() {
        let mut reach = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 16));
        reach.record(
            sent(EcsSource::Client, "198.51.100.0/24"),
            echoed("198.51.100.0/24", 24),
            true,
        );
        assert!(reach.admits(&view("10.0.0.1", Some("198.51.100.0/24"))));
        assert!(!reach.admits(&view("10.0.0.1", Some("198.51.7.0/24"))));
    }

    #[test]
    fn an_opaque_client_ecs_matches_no_shared_answer() {
        let reach = passed_through("198.51.100.0/24", ReplyEcs::Absent);
        let opaque = EcsView {
            peer: "10.0.0.1".parse().unwrap(),
            client: Some(EcsKey::opaque(&[0, 8, 0, 3, 0, 3, 24, 0])),
        };
        assert!(!reach.admits(&opaque));
    }

    #[test]
    fn longer_prefixes_are_more_specific() {
        let wide = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 16));
        let narrow = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 24));
        let exact = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 28));
        let shared = passed_through("198.51.100.0/24", ReplyEcs::Absent);
        assert!(exact.specificity() > narrow.specificity());
        assert!(narrow.specificity() > wide.specificity());
        assert!(wide.specificity() > shared.specificity());
        assert!(!narrow.is_broad());
    }

    #[test]
    fn the_echo_reports_the_bits_of_the_clients_own_ecs() {
        let reach = passed_through("198.51.100.0/24", echoed("198.51.100.0/24", 16));
        assert_eq!(
            reach.echo_scope(&view("10.0.0.1", Some("198.51.7.0/24"))),
            16
        );
        let mut by_peer = EcsReach::default();
        by_peer.record(
            sent(PEER, "198.51.100.0/24"),
            echoed("198.51.100.0/24", 24),
            true,
        );
        // 带了 ECS 的客户端，公网的也一样，发出的是它自己的子网（RFC 7871 第 7.1 节）
        // A client that sent ECS, public or not, has its own subnet sent (RFC 7871
        // section 7.1)
        assert_eq!(
            by_peer.echo_scope(&view("198.51.100.9", Some("198.51.100.0/24"))),
            24
        );
        // 带着读不懂的 ECS 选项的公网客户端，发出的是来源地址的子网，与那个选项无关
        // A public client carrying an ECS option nobody can read sends its address's
        // subnet, whatever the option says
        let unreadable = EcsView {
            peer: "198.51.100.9".parse().unwrap(),
            client: Some(EcsKey::opaque(b"not an ECS option")),
        };
        assert_eq!(by_peer.echo_scope(&unreadable), 0);
        // 带着私有网段的公网客户端也是：私有网段不发给上游（RFC 7871 第 11.3 节）
        // So does a public client carrying a private network, which does not go
        // upstream (RFC 7871 section 11.3)
        assert_eq!(
            by_peer.echo_scope(&view("198.51.100.9", Some("10.1.2.0/24"))),
            0
        );
        assert_eq!(
            by_peer.echo_scope(&view("192.168.1.2", Some("198.51.100.0/24"))),
            24
        );
        assert_eq!(
            EcsReach::default().echo_scope(&view("10.0.0.1", Some("198.51.100.0/24"))),
            0
        );
    }

    #[test]
    fn a_subnet_read_off_the_wire_equals_the_one_built_from_an_address() {
        assert_eq!(
            EcsKey::from_wire(1, 24, &[198, 51, 100]),
            subnet("198.51.100.0/24")
        );
        // 前缀之后的位不算 / Bits beyond the prefix do not count
        assert_eq!(
            EcsKey::from_wire(1, 20, &[198, 51, 0x7f]),
            subnet("198.51.112.0/20")
        );
        assert_eq!(
            EcsKey::from_wire(2, 56, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0x12]),
            subnet("2001:db8:0:1200::/56")
        );
        assert_eq!(
            subnet("198.51.100.0/24").truncated(16),
            subnet("198.51.0.0/16")
        );
        assert_ne!(EcsKey::opaque(&[1, 2, 3]), EcsKey::opaque(&[1, 2, 4]));
    }
}
