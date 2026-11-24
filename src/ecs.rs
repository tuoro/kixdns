//! EDNS 客户端子网（ECS，RFC 7871）：转发对请求的 ECS 做什么（[`plan`] 定下，[`apply_ecs_for`] 照线上格式改写），
//! 子网的键 [`EcsKey`]（缓存和合并的请求按它分开），以及哪些客户端地址不带给上游（[`withheld_from_ecs`]）。快速路径
//! 也用 [`plan`]：规则按 `from_client_ip` 发出的子网区分请求方时，缓存键里要有这个子网（见 `matcher::requester`）。
//! 报文里 ECS 选项的读写在 `proto_utils`
//! EDNS Client Subnet (ECS, RFC 7871): what a forward does with a request's ECS ([`plan`]
//! decides, [`apply_ecs_for`] rewrites it on the wire), the subnet's key [`EcsKey`] that the
//! cache and merged requests are kept apart by, and which client addresses no ECS carries
//! upstream ([`withheld_from_ecs`]). The fast path uses [`plan`] too: with rules telling requesters
//! apart by the subnet `from_client_ip` sends, that subnet is part of the cache key (see
//! `matcher::requester`). Reading and writing the ECS option of a message is in `proto_utils`

use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

use serde::{Deserialize, Serialize};

use crate::config::EcsMode;

/// The family `EcsKey::opaque` uses: not one RFC 7871 or IANA defines
/// `EcsKey::opaque` 用的地址族：RFC 7871 和 IANA 都没有定义
const OPAQUE_FAMILY: u16 = u16::MAX;

/// Default IPv4 source prefix length (RFC 7871 §11.1 recommendation)
/// 默认 IPv4 源前缀长度（RFC 7871 §11.1 建议）
pub const DEFAULT_PREFIX_V4: u8 = 24;

/// Default IPv6 source prefix length
/// 默认 IPv6 源前缀长度
pub const DEFAULT_PREFIX_V6: u8 = 56;

/// `static` 模式写的 ECS 地址（见 `EcsMode::Static`），读配置时就解析好，转发时不再解析。写的不是 IP 地址时留着原文：
/// 配置检查报出它（见 `config::problems`），这样的转发不换上固定的子网，包原样发出，客户端自己带的 ECS 照样转给上游（见
/// [`plan`]）。按原文读写，写出来的再读回去还是它
/// The ECS address the `static` mode writes (see `EcsMode::Static`), parsed as the configuration
/// is read and not again on a forward. One that is no IP address keeps its text: the
/// configuration check raises it (see `config::problems`), and such a forward sets no fixed
/// subnet, sending the packet as it is, so the client's own ECS, if any, goes upstream (see
/// [`plan`]). It is read and written as text, and what it writes reads back as itself
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum StaticEcsIp {
    Ip(IpAddr),
    /// 写的不是 IP 地址：原文 / Not an IP address: the text as written
    NotAnIp(String),
}

impl From<String> for StaticEcsIp {
    fn from(text: String) -> Self {
        text.parse().map_or(Self::NotAnIp(text), Self::Ip)
    }
}

impl From<StaticEcsIp> for String {
    fn from(ip: StaticEcsIp) -> Self {
        match ip {
            StaticEcsIp::Ip(ip) => ip.to_string(),
            StaticEcsIp::NotAnIp(text) => text,
        }
    }
}

/// 对查询报文执行 `mode` 的 ECS 改写（见 [`plan`]），请求自己的 ECS 选项 `client` 由调用方给：后台刷新重放的包带不了
/// 读不懂的选项（见 `RefreshTarget::client_ecs`），所以不从报文里读。改写照线上格式做，和交给客户端的应答换上、去掉 ECS
/// 是同一套（见 `proto_utils::echo_ecs`、`proto_utils::ecs_removed`）；不用改、改不了（读不出的报文、TSIG 签过的查询：
/// 改了签名就不对了）时借着原包，不复制
/// Rewrites a query's ECS as `mode` has it (see [`plan`]), the request's own ECS option
/// `client` given by the caller: a background refresh replays a packet that cannot carry an
/// option nobody can read (see `RefreshTarget::client_ecs`), so it is not read off the packet.
/// The rewrite is done on the wire, by the same code that sets or takes out the ECS of a reply
/// for a client (see `proto_utils::echo_ecs`, `proto_utils::ecs_removed`); with nothing to
/// change, or no way to change it (a message that cannot be read, a query signed with TSIG,
/// whose signature a change would break), the packet is borrowed as it is, uncopied
pub(crate) fn apply_ecs_for<'a>(
    packet: &'a [u8],
    mode: &EcsMode,
    peer_ip: IpAddr,
    client: Option<&EcsKey>,
) -> Cow<'a, [u8]> {
    let rewritten = match plan(Some(mode), peer_ip, client) {
        EcsPlan::Strip => crate::proto_utils::ecs_removed(packet),
        EcsPlan::Keep => None,
        // 查询里的 SCOPE 必须为 0（RFC 7871 第 6 节）/ A query's SCOPE must be 0 (RFC 7871 section 6)
        EcsPlan::Set(subnet) => crate::proto_utils::echo_ecs(packet, &subnet, 0),
    };
    rewritten.map_or(Cow::Borrowed(packet), Cow::Owned)
}

/// What a forward does with the ECS option of the packet it sends.
/// 转发对它发出的包里的 ECS 选项做什么。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcsPlan {
    /// Remove it / 去掉
    Strip,
    /// Leave the packet as it is, so the client's own ECS, if any, goes upstream
    /// 包原样不动，客户端自己带的 ECS（如果有）照样发给上游
    Keep,
    /// Send this subnet / 发送这个子网
    Set(EcsKey),
}

/// The plan of a forward with `ecs` (None: the forward has no `ecs` setting) for a
/// request from `peer_ip` carrying the ECS option `client` (see
/// `proto_utils::client_subnet`). `apply_ecs_for` carries it out; the response cache
/// reads it to know what the upstream was asked with.
/// 带 `ecs`（None 表示转发没写 `ecs`）的转发对来自 `peer_ip`、带着 ECS 选项 `client`（见
/// `proto_utils::client_subnet`）的请求怎么处理 ECS。`apply_ecs_for` 照此执行；响应缓存据此知道
/// 上游被问的是什么。
pub(crate) fn plan(mode: Option<&EcsMode>, peer_ip: IpAddr, client: Option<&EcsKey>) -> EcsPlan {
    match mode {
        None => EcsPlan::Keep,
        Some(EcsMode::Clear) => EcsPlan::Strip,
        Some(EcsMode::FromClientIp {
            prefix_v4,
            prefix_v6,
        }) => match own_ecs(client) {
            // RFC 7871 section 7.1: a client that sent ECS itself decides how much of
            // its address goes upstream. Its own subnet goes on, cut to the prefix set
            // here when it is longer; a prefix of 0, which asks for no address at all,
            // goes on as it is.
            // RFC 7871 第 7.1 节：客户端自己带了 ECS，就由它决定给上游多少地址。转发它自己的
            // 子网，比这里设置的前缀长时截短；前缀为 0 表示不要任何地址，原样转发。
            OwnEcs::Forwarded(own) => {
                let limit = if own.family == 1 {
                    *prefix_v4
                } else {
                    *prefix_v6
                };
                if own.source_prefix <= limit {
                    EcsPlan::Keep
                } else {
                    EcsPlan::Set(own.truncated(limit))
                }
            }
            // How much of its address the client lets go upstream cannot be read, so
            // none goes, and neither does the option itself (section 7.1)
            // 读不出客户端允许给上游多少地址，所以一点也不给，选项本身也不转发（第 7.1 节）
            OwnEcs::Unreadable => EcsPlan::Strip,
            // A private client's packet goes as it came, less a private network
            // 私有地址客户端的包原样发出，只去掉私有网段
            OwnEcs::Private if withheld_from_ecs(peer_ip) => EcsPlan::Strip,
            OwnEcs::Private | OwnEcs::Absent if !withheld_from_ecs(peer_ip) => {
                EcsPlan::Set(EcsKey::from_ip(peer_ip, *prefix_v4, *prefix_v6))
            }
            OwnEcs::Private | OwnEcs::Absent => EcsPlan::Keep,
        },
        Some(EcsMode::Static { ip, prefix }) => match ip {
            StaticEcsIp::Ip(ip) => EcsPlan::Set(EcsKey::from_ip(*ip, *prefix, *prefix)),
            // 配置检查报过它（见 `config::problems`），这里不再报 / The configuration check reported
            // it (see `config::problems`), so it is not reported again here
            StaticEcsIp::NotAnIp(_) => EcsPlan::Keep,
        },
    }
}

/// What `from_client_ip` makes of the ECS option a client sent itself
/// `from_client_ip` 怎么看客户端自己带的 ECS 选项
enum OwnEcs<'a> {
    /// A subnet to pass on (RFC 7871 section 7.1): well-formed, and either /0 or
    /// a public network
    /// 要转发的子网（RFC 7871 第 7.1 节）：合规，并且是 /0 或公网网段
    Forwarded(&'a EcsKey),
    /// A private network, or an IPv4-mapped one (RFC 6890 lists ::ffff:0:0/96 as
    /// not globally reachable), which section 11.3 says to take as the resolver's
    /// own identity: it says nothing about where the client is, and does not go
    /// upstream
    /// 私有网段，或 IPv4 映射形式的网段（RFC 6890 把 ::ffff:0:0/96 列为不可全球路由）：
    /// 第 11.3 节说按解析器自己的身份对待，它说明不了客户端在哪里，不发给上游
    Private,
    /// An option nobody can read (see `EcsKey::opaque`) / 读不懂的选项（见 `EcsKey::opaque`）
    Unreadable,
    /// No option / 没带
    Absent,
}

fn own_ecs(client: Option<&EcsKey>) -> OwnEcs<'_> {
    match client {
        Some(own) if own.is_opaque() => OwnEcs::Unreadable,
        Some(own) if own.source_prefix > 0 && own.ip().is_none_or(is_unroutable) => OwnEcs::Private,
        Some(own) => OwnEcs::Forwarded(own),
        None => OwnEcs::Absent,
    }
}

/// A network address an ECS option should not carry upstream: a private one, or
/// an IPv4-mapped one / ECS 选项不该带给上游的网段地址：私有地址，或 IPv4 映射形式的地址
fn is_unroutable(ip: IpAddr) -> bool {
    withheld_from_ecs(ip) || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

/// Whether `from_client_ip` sends a request's own ECS (`client`, from `peer_ip`):
/// its subnet as it is or cut short, or the packet as the client sent it
/// `from_client_ip` 是否发出请求自己的 ECS（来自 `peer_ip` 的 `client`）：它的子网原样或截短，
/// 或者包按客户端发来的原样发出
pub(crate) fn forwards_own_ecs(peer_ip: IpAddr, client: Option<&EcsKey>) -> bool {
    match own_ecs(client) {
        OwnEcs::Forwarded(_) => true,
        OwnEcs::Private | OwnEcs::Unreadable => false,
        OwnEcs::Absent => withheld_from_ecs(peer_ip),
    }
}

/// 把报文 OPT 里的 ECS 换成 `subnet`；没有 OPT 时新建一个，负载上限 1232 字节。hickory-proto
/// 0.26 的 OPT 用 Vec 存选项，insert() 总是追加，所以先去掉已有的 ECS，免得重复。
/// Make `subnet` the ECS of the message's OPT, creating one with a 1232-byte payload
/// when there is none. hickory-proto 0.26 keeps OPT options in a Vec whose insert()
/// always appends, so any existing ECS is removed first to avoid duplicates.
pub(crate) fn set_ecs_option(msg: &mut Message, subnet: ClientSubnet) {
    let edns = msg.edns.get_or_insert_with(|| {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        edns
    });
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut().insert(EdnsOption::Subnet(subnet));
}

/// ECS 不带给上游的客户端地址：`geoip_private` 算作内网的那些（见 `geoip::is_private_ip`，两边只用这一份），再加上两段
/// 不可全球路由、拿它算出的子网说明不了客户端在哪里的地址：本地用的转换前缀 64:ff9b:1::/48（RFC 8215）整个，不论嵌着
/// 哪个 IPv4 地址；基准测试的 198.18.0.0/15（RFC 2544）。`geoip_private` 不算这两段，理由都在回答上：64:ff9b:1::/48
/// 嵌着公网地址的是 DNS64 的寻常回答，198.18.0.0/15 是 fake-ip 上游的寻常回答
/// The client addresses ECS does not carry upstream: those `geoip_private` counts as local
/// network ones (see `geoip::is_private_ip`, the one list both use), and two ranges more that
/// are not globally routable, so a subnet worked out from one says nothing about where the
/// client is: the local-use translation prefix 64:ff9b:1::/48 (RFC 8215) whole, whatever IPv4
/// address it embeds, and benchmarking's 198.18.0.0/15 (RFC 2544). `geoip_private` counts
/// neither, for reasons that lie in answers: one of 64:ff9b:1::/48 embedding a public address
/// is an ordinary DNS64 answer, and one of 198.18.0.0/15 an ordinary answer of a fake-ip
/// upstream
pub(crate) fn withheld_from_ecs(ip: IpAddr) -> bool {
    crate::matcher::geoip::is_private_ip(ip)
        || match ip {
            IpAddr::V4(v4) => matches!(v4.octets(), [198, b, ..] if b & 0xfe == 18),
            IpAddr::V6(v6) => v6.segments()[..3] == [0x64, 0xff9b, 1],
        }
}

// ============================================================================
// EcsKey — Cache isolation identifier (RFC 7871)
// EcsKey — 缓存隔离标识 (RFC 7871)
// ============================================================================

/// ECS subnet identifier for cache hash, zero-alloc on stack.
/// 用于 cache hash 的 ECS 子网标识，栈上零分配。
///
/// Used to isolate cache entries by client subnet so that different
/// geographic regions get distinct cached responses.
/// 用于按客户端子网隔离缓存条目，使不同地理区域获得不同的缓存响应。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcsKey {
    /// Address family: 1=IPv4, 2=IPv6 / 地址族：1=IPv4, 2=IPv6
    pub family: u16,
    /// Source prefix length / 源前缀长度
    pub source_prefix: u8,
    /// Address bytes (up to 16 for IPv6) / 地址字节（IPv6 最多 16 字节）
    pub addr: [u8; 16],
    /// Number of valid bytes in `addr` / `addr` 中有效字节数
    pub addr_len: u8,
}

impl EcsKey {
    /// Build EcsKey from an IP address with prefix masking.
    /// 从 IP 地址和前缀掩码构建 EcsKey。
    pub(crate) fn from_ip(ip: IpAddr, prefix_v4: u8, prefix_v6: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::from_wire(1, prefix_v4.min(32), &v4.octets()),
            IpAddr::V6(v6) => Self::from_wire(2, prefix_v6.min(128), &v6.octets()),
        }
    }

    /// The ECS option a query or reply carries: FAMILY, SOURCE PREFIX-LENGTH and
    /// ADDRESS as sent, the caller having checked that the family is 1 or 2, the prefix
    /// within its bits and the address at most 16 octets (see `from_ip` and
    /// `proto_utils::EcsOption::address_bits`). The address is masked to the prefix
    /// (RFC 7871 section 6 requires the bits beyond it to be zero, and whatever they
    /// are, the subnet is the prefix's), so two options that name the same subnet make
    /// equal keys.
    /// 查询或应答携带的 ECS 选项：原样的 FAMILY、SOURCE PREFIX-LENGTH 和 ADDRESS，地址族是 1 或 2、
    /// 前缀不超过它的位数、地址不超过 16 个字节由调用方查过（见 `from_ip`、
    /// `proto_utils::EcsOption::address_bits`）。地址按前缀掩码（RFC 7871 第 6 节要求前缀之后的位为零；
    /// 不管它们是什么，子网都由前缀决定），所以指同一个子网的两个选项得到相同的键。
    pub(crate) fn from_wire(family: u16, source_prefix: u8, address: &[u8]) -> Self {
        let mut addr = [0u8; 16];
        addr[..address.len()].copy_from_slice(address);
        mask_address(&mut addr, source_prefix);
        Self {
            family,
            source_prefix,
            addr,
            addr_len: source_prefix.div_ceil(8),
        }
    }

    /// 说不出是哪个子网的 ECS 选项：查询里 SCOPE 不为 0 的（它必须为 0，RFC 7871 第 6 节却没要求为此回
    /// FORMERR，见 `proto_utils::query_subnet`），以及 `proto_utils::client_subnet` 读不出的报文和选项。
    /// 从监听器进来的查询里读不出的选项到不了这里：照线上格式读得出的报文里 OPT 的选项不合规的当场回 FORMERR（见
    /// `Engine::on_the_spot`）。读不出的报文还会到这里：hickory 读得了、照线上格式却读不了的（比如压缩指针跳了超过
    /// 16 次）走完整路径。透传客户端 ECS 的转发把这样的选项原样发给上游，应答适用于谁说不准（`from_client_ip`
    /// 会去掉它）；键由原始字节决定，不会和任何真实子网相等。
    /// An ECS option that names no subnet one can tell: a nonzero SCOPE in a query (it
    /// must be 0, but RFC 7871 section 6 asks no FORMERR for it, see
    /// `proto_utils::query_subnet`), and a message or option `proto_utils::client_subnet`
    /// cannot read. From a listener, an option that cannot be read does not get here: in a
    /// message that can be read on the wire, improper OPT options are answered FORMERR on the
    /// spot (see `Engine::on_the_spot`). A message that cannot be read still does: one hickory
    /// reads but the wire walk cannot (a compression pointer followed more than 16 times, say)
    /// takes the full path. A forward that passes the client's ECS on sends such an option as
    /// it is, and whom the answer applies to is unclear (`from_client_ip` removes it); its key
    /// comes from the raw bytes and never equals a real subnet.
    pub(crate) fn opaque(raw: &[u8]) -> Self {
        let mut addr = [0u8; 16];
        for (half, seed) in addr.chunks_mut(8).zip([1u8, 2u8]) {
            let mut hasher = rustc_hash::FxHasher::default();
            seed.hash(&mut hasher);
            raw.hash(&mut hasher);
            half.copy_from_slice(&hasher.finish().to_be_bytes());
        }
        Self {
            family: OPAQUE_FAMILY,
            source_prefix: 0,
            addr,
            addr_len: 16,
        }
    }

    /// 见 `opaque` / See `opaque`
    pub(crate) fn is_opaque(&self) -> bool {
        self.family == OPAQUE_FAMILY
    }

    /// The subnet's first `prefix` bits, as the subnet `prefix` long: the network
    /// an upstream's SCOPE PREFIX-LENGTH names. `prefix` is at most the key's own.
    /// 子网的前 `prefix` 位组成的长 `prefix` 的子网：上游的 SCOPE PREFIX-LENGTH 所指的
    /// 网段。`prefix` 不超过键自己的前缀。
    pub(crate) fn truncated(&self, prefix: u8) -> Self {
        let prefix = prefix.min(self.source_prefix);
        let mut addr = self.addr;
        mask_address(&mut addr, prefix);
        Self {
            family: self.family,
            source_prefix: prefix,
            addr,
            addr_len: (prefix as usize).div_ceil(8).min(self.addr_len as usize) as u8,
        }
    }

    /// The subnet's address as an IP address, for the two families ECS defines.
    /// 子网地址转成 IP 地址，限 ECS 定义的两个地址族。
    pub(crate) fn ip(&self) -> Option<IpAddr> {
        match self.family {
            1 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&self.addr[..4]);
                Some(IpAddr::V4(octets.into()))
            }
            2 => Some(IpAddr::V6(self.addr.into())),
            _ => None,
        }
    }

    /// Feed all identifying fields into a hasher for cache deduplication.
    /// 将所有标识字段喂入 hasher 以进行缓存去重。
    #[inline]
    pub fn hash_into<H: Hasher>(&self, h: &mut H) {
        self.family.hash(h);
        self.source_prefix.hash(h);
        h.write(&self.addr[..self.addr_len as usize]);
    }
}

/// Mask a 16-byte address buffer to the given prefix length (in-place).
/// 将 16 字节的地址缓冲区掩码到指定前缀长度（原地操作）。
fn mask_address(addr: &mut [u8; 16], prefix: u8) {
    if prefix >= 128 {
        return;
    }
    let p = prefix as usize;
    let bytes_used = p.div_ceil(8);
    let bit = p % 8;
    if bit > 0 {
        addr[bytes_used - 1] &= 0xFF << (8 - bit);
    }
    for b in &mut addr[bytes_used..] {
        *b = 0;
    }
}

/// 测试辅助：对查询执行 `mode` 的 ECS 改写（见 [`apply_ecs_for`]），客户端自己带的 ECS 从报文里读
/// Test helper: rewrites a query's ECS as `mode` has it (see [`apply_ecs_for`]), the client's own
/// ECS read off the packet
#[cfg(test)]
pub(crate) fn apply_ecs<'a>(packet: &'a [u8], mode: &EcsMode, peer_ip: IpAddr) -> Cow<'a, [u8]> {
    let client = crate::proto_utils::client_subnet(packet);
    apply_ecs_for(packet, mode, peer_ip, client.as_ref())
}

/// 测试辅助：`"地址/前缀"` 写的子网 / Test helper: the subnet written `"address/prefix"`
#[cfg(test)]
pub(crate) fn subnet(text: &str) -> EcsKey {
    let (address, prefix) = text.split_once('/').unwrap();
    let prefix: u8 = prefix.parse().unwrap();
    EcsKey::from_ip(address.parse().unwrap(), prefix, prefix)
}

/// Trivial test helper: check if ECS exists in a wire packet.
/// 简单测试辅助：检查 wire 包中是否存在 ECS。
#[cfg(test)]
pub(crate) fn has_ecs(packet: &[u8]) -> bool {
    let msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return false,
    };
    msg.edns
        .as_ref()
        .and_then(|e| e.options().get(EdnsCode::Subnet))
        .is_some()
}

/// Extract ECS subnet info from a wire packet (for testing): its address, SOURCE and
/// SCOPE. The packet must be a valid message.
/// hickory-proto 0.26+ exposes ClientSubnet fields via accessors.
///
/// 从 wire 包中提取 ECS 子网信息（用于测试）：地址、SOURCE、SCOPE。报文必须读得出来。
/// hickory-proto 0.26+ 通过访问器暴露 ClientSubnet 字段。
#[cfg(test)]
pub(crate) fn extract_ecs_info(packet: &[u8]) -> Option<(IpAddr, u8, u8)> {
    let msg = Message::from_vec(packet).expect("a valid message");
    let edns = msg.edns.as_ref()?;
    let cs = match edns.options().get(EdnsCode::Subnet)? {
        EdnsOption::Subnet(cs) => cs,
        _ => return None,
    };
    Some((cs.addr(), cs.source_prefix(), cs.scope_prefix()))
}

// ============================================================================
// Tests / 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 前缀比地址还长时按地址的长度算：IPv4 最多 32 位、IPv6 最多 128 位（例如静态 ECS 写成
    /// `/33`）
    /// A prefix longer than the address counts as the address's length: at most 32 bits
    /// for IPv4 and 128 for IPv6 (a static ECS written `/33`, for one)
    #[test]
    fn a_prefix_longer_than_the_address_is_capped_at_its_length() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(EcsKey::from_ip(v4, 33, 0), EcsKey::from_ip(v4, 32, 0));
        assert_eq!(EcsKey::from_ip(v4, 33, 0).source_prefix, 32);
        assert_eq!(EcsKey::from_ip(v6, 0, 129), EcsKey::from_ip(v6, 0, 128));
        assert_eq!(EcsKey::from_ip(v6, 0, 129).source_prefix, 128);
    }

    /// 查询没有 OPT 时为 ECS 新建一个，负载上限 1232 字节 / A query without an OPT gets one
    /// for its ECS, advertising 1232 bytes
    #[test]
    fn an_opt_made_for_the_ecs_advertises_1232_bytes() {
        let query = make_query("example.com", 0x1234);
        assert!(Message::from_vec(&query).unwrap().edns.is_none());
        let modified = with_static_ecs(&query, "203.0.113.5", 24);
        let edns = Message::from_vec(&modified).unwrap().edns.expect("an OPT");
        assert_eq!(edns.max_payload(), 1232);
    }
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    /// Build a minimal DNS query wire packet for testing.
    /// 构建最小化 DNS 查询 wire 包用于测试。
    fn make_query(domain: &str, txid: u16) -> Vec<u8> {
        let mut msg = Message::new(txid, hickory_proto::op::MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    /// Build a DNS query with an existing OPT record (no ECS).
    /// 构建带 OPT 记录（无 ECS）的 DNS 查询。
    fn make_query_with_opt(domain: &str, txid: u16) -> Vec<u8> {
        let mut msg = Message::new(txid, hickory_proto::op::MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        msg.edns = Some(edns);
        msg.to_vec().unwrap()
    }

    /// `static` 模式发 `ip`/`prefix` 的查询 / The query a `static` mode sends for `ip`/`prefix`
    fn with_static_ecs(packet: &[u8], ip: &str, prefix: u8) -> Vec<u8> {
        let mode = EcsMode::Static {
            ip: ip.to_string().into(),
            prefix,
        };
        apply_ecs(packet, &mode, "192.0.2.1".parse().unwrap()).into_owned()
    }

    // ---- set / 加上 ----

    #[test]
    fn test_inject_ecs_into_plain_query() {
        let query = make_query("example.com", 0x1234);
        let modified = with_static_ecs(&query, "203.0.113.5", 24);

        assert!(has_ecs(&modified), "ECS should be present after injection");
        let (addr, src_prefix, scope) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(src_prefix, 24);
        assert_eq!(scope, 0, "query scope must be 0 / 查询 scope 必须为 0");
    }

    #[test]
    fn test_inject_ecs_into_query_with_existing_opt() {
        let query = make_query_with_opt("example.com", 0x1234);
        let modified = with_static_ecs(&query, "203.0.113.5", 24);

        assert!(has_ecs(&modified));
        let (addr, _, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
    }

    #[test]
    fn test_inject_ecs_v6() {
        let query = make_query("example.com", 0x1234);
        let modified = with_static_ecs(&query, "2001:db8:abcd:1234::5", 56);

        assert!(has_ecs(&modified));
        let (addr, src_prefix, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(src_prefix, 56);
        // Address should be truncated to /56 (first 7 bytes)
        // 地址应截断为 /56（前 7 字节）
        match addr {
            IpAddr::V6(v6_addr) => {
                let octets = v6_addr.octets();
                assert_eq!(&octets[..7], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12]);
            }
            _ => panic!("expected IPv6 address"),
        }
    }

    #[test]
    fn test_inject_ecs_replaces_existing() {
        // First inject
        // 第一次注入
        let query = make_query("example.com", 0x1234);
        let modified = with_static_ecs(&query, "203.0.113.5", 24);
        assert!(has_ecs(&modified));

        // Inject again with different subnet — should replace, not duplicate
        // 用不同子网再次注入 — 应替换而非重复
        let re_modified = with_static_ecs(&modified, "198.51.100.5", 24);
        let (addr, _, _) = extract_ecs_info(&re_modified).unwrap();
        assert_eq!(addr, IpAddr::V4("198.51.100.0".parse().unwrap()));
        let edns = Message::from_vec(&re_modified).unwrap().edns.unwrap();
        assert_eq!(edns.options().get_all(EdnsCode::Subnet).len(), 1);
    }

    // ---- clear / 去掉 ----

    #[test]
    fn test_strip_ecs_removes_ecs() {
        let injected = with_static_ecs(&make_query("example.com", 0x1234), "203.0.113.5", 24);
        assert!(has_ecs(&injected));

        let stripped = apply_ecs(&injected, &EcsMode::Clear, "127.0.0.1".parse().unwrap());
        assert!(!has_ecs(&stripped), "ECS should be removed / ECS 应被移除");
    }

    /// `static` 的地址读配置时就解析好，转发时不再解析；不是 IP 地址的留着原文，写出来再读回去还是它
    /// A `static` address is parsed as the configuration is read, not on a forward; one that is
    /// no IP address keeps its text, and what is written reads back as itself
    #[test]
    fn a_static_address_is_parsed_as_the_configuration_is_read() {
        let read = |ip: &str| {
            serde_json::from_value::<EcsMode>(serde_json::json!({"mode": "static", "ip": ip}))
                .unwrap()
        };
        assert_eq!(
            read("2001:db8::1"),
            EcsMode::Static {
                ip: StaticEcsIp::Ip("2001:db8::1".parse().unwrap()),
                prefix: 24,
            }
        );
        assert_eq!(
            read("not.an.ip"),
            EcsMode::Static {
                ip: StaticEcsIp::NotAnIp("not.an.ip".to_string()),
                prefix: 24,
            }
        );
        for mode in [read("203.0.113.0"), read("not.an.ip")] {
            let written = serde_json::to_value(&mode).unwrap();
            assert_eq!(serde_json::from_value::<EcsMode>(written).unwrap(), mode);
        }
    }

    /// 没有 ECS 可去、客户端自己的 ECS 原样转发、静态地址不是 IP 地址时，都借着原包，不复制
    /// With no ECS to take out, the client's own ECS going on as it is, or a static address that
    /// is no IP address, the packet is borrowed as it is, uncopied
    #[test]
    fn an_unchanged_query_is_borrowed() {
        let query = make_query_with_opt("example.com", 0x1234);
        let peer: IpAddr = "203.0.113.42".parse().unwrap();
        assert!(matches!(
            apply_ecs(&query, &EcsMode::Clear, peer),
            Cow::Borrowed(_)
        ));
        let from_client = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let own = subnet("198.51.100.0/24");
        assert!(matches!(
            apply_ecs_for(&query, &from_client, peer, Some(&own)),
            Cow::Borrowed(_)
        ));
        let not_an_ip = EcsMode::Static {
            ip: "not.an.ip".to_string().into(),
            prefix: 24,
        };
        assert!(matches!(
            apply_ecs(&query, &not_an_ip, peer),
            Cow::Borrowed(_)
        ));
    }

    /// 线上格式改写的结果和交给 hickory 重新编码的逐字节相同：没有 OPT、OPT 里没有选项、已经带着别的子网、还带着
    /// cookie 和 DO 位的查询，问题名大小写混写、带 RD 和 CD，各种子网都一样；OPT 后面还有记录时本来就交给 hickory
    /// The rewrite on the wire comes out byte for byte as hickory encodes it again: for a query
    /// without an OPT, with an empty one, already carrying another subnet, and with a cookie and
    /// the DO bit too, its name in mixed case with RD and CD set, for every subnet; with records
    /// after the OPT it goes to hickory anyway
    #[test]
    fn the_rewrite_on_the_wire_matches_hickory_byte_for_byte() {
        let with_options = |options: Vec<EdnsOption>, dnssec_ok: bool| {
            let mut msg = Message::from_vec(&make_query("WwW.ExAmple.CoM", 0x4321)).unwrap();
            msg.metadata.recursion_desired = true;
            msg.metadata.checking_disabled = true;
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(4096);
            edns.set_dnssec_ok(dnssec_ok);
            for option in options {
                edns.options_mut().insert(option);
            }
            msg.edns = Some(edns);
            msg
        };
        let other = EdnsOption::Subnet(ClientSubnet::new("198.51.100.0".parse().unwrap(), 24, 0));
        let cookie = EdnsOption::Unknown(10, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        // OPT 后面再跟一条 A 记录：hickory 编码时总把 OPT 放在最后，所以照线上格式接上 / An A record after
        // the OPT: hickory always puts the OPT last as it encodes, so it is appended on the wire
        let mut records_after_opt = with_options(vec![other.clone()], false).to_vec().unwrap();
        records_after_opt[11] += 1;
        records_after_opt
            .extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9]);
        let queries = [
            make_query("example.com", 0x1234),
            with_options(Vec::new(), false).to_vec().unwrap(),
            with_options(vec![other.clone()], false).to_vec().unwrap(),
            with_options(vec![cookie.clone(), other, cookie], true)
                .to_vec()
                .unwrap(),
            records_after_opt,
        ];
        // 原先的做法：hickory 读出整个报文、换上或去掉 ECS 再编码 / How it used to be done: hickory
        // reads the whole message, sets or takes out the ECS and encodes it again
        let by_hickory = |query: &[u8], subnet: Option<EcsKey>| {
            let mut msg = Message::from_vec(query).unwrap();
            match subnet {
                Some(subnet) => set_ecs_option(
                    &mut msg,
                    ClientSubnet::new(subnet.ip().unwrap(), subnet.source_prefix, 0),
                ),
                None => msg
                    .edns
                    .as_mut()
                    .unwrap()
                    .options_mut()
                    .remove(EdnsCode::Subnet),
            }
            msg.to_vec().unwrap()
        };
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for query in &queries {
            let cleared = apply_ecs(query, &EcsMode::Clear, peer);
            if has_ecs(query) {
                assert_eq!(*cleared, by_hickory(query, None));
            } else {
                assert!(matches!(cleared, Cow::Borrowed(_)));
            }
            for (ip, prefix) in [
                ("203.0.113.77", 24),
                ("203.0.113.255", 20),
                ("2001:db8:abcd:ef01::1", 56),
                ("192.0.2.1", 0),
            ] {
                let sent = with_static_ecs(query, ip, prefix);
                let subnet = EcsKey::from_ip(ip.parse().unwrap(), prefix, prefix);
                assert_eq!(sent, by_hickory(query, Some(subnet)), "{ip}/{prefix}");
                let cleared = apply_ecs(&sent, &EcsMode::Clear, peer);
                assert_eq!(*cleared, by_hickory(&sent, None), "{ip}/{prefix}");
            }
        }
    }

    /// TSIG 签过的查询（RFC 8945）改了哪一位签名都失效：ECS 加不上也去不掉，原样发出，不交给 hickory 重新编码
    /// A query signed with TSIG (RFC 8945) has its signature broken by any change: its ECS is
    /// neither set nor taken out, and it goes as it came, not encoded again by hickory
    #[test]
    fn a_signed_query_goes_as_it_came() {
        let signed = |options: &[u8]| {
            let mut packet = make_query("example.com", 0x1234);
            packet[11] = 2;
            packet.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
            packet.extend_from_slice(&(options.len() as u16).to_be_bytes());
            packet.extend_from_slice(options);
            // 一条 TSIG：属主 key.、类型 250、类别 ANY / A TSIG: owner key., type 250, class ANY
            packet.extend_from_slice(b"\x03key\x00");
            packet.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
            assert!(crate::proto_utils::last_record_is_tsig(&packet));
            packet
        };
        let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];
        let peer: IpAddr = "203.0.113.42".parse().unwrap();
        let fixed = EcsMode::Static {
            ip: "203.0.113.0".to_string().into(),
            prefix: 24,
        };
        for packet in [signed(&[]), signed(&ecs)] {
            for mode in [&EcsMode::Clear, &fixed] {
                assert!(matches!(
                    apply_ecs(&packet, mode, peer),
                    Cow::Borrowed(sent) if sent == packet.as_slice()
                ));
            }
        }
    }

    // ---- apply_ecs (integration) ----

    #[test]
    fn test_apply_ecs_clear_mode() {
        let injected = with_static_ecs(&make_query("example.com", 0x1234), "203.0.113.5", 24);

        let mode = EcsMode::Clear;
        let result = apply_ecs(&injected, &mode, "127.0.0.1".parse().unwrap());
        assert!(!has_ecs(&result));
    }

    #[test]
    fn test_apply_ecs_from_client_ip_v4() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let peer: IpAddr = "203.0.113.42".parse().unwrap();
        let result = apply_ecs(&query, &mode, peer);

        assert!(has_ecs(&result));
        let (addr, prefix, _) = extract_ecs_info(&result).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_apply_ecs_masks_unaligned_v4_prefix() {
        // RFC 7871 §6: ADDRESS is truncated to SOURCE PREFIX-LENGTH bits and
        // zero-padded to the last octet. hickory only truncates whole octets,
        // so the bits past a /20 must be cleared here: 203.0.113.255/20 is
        // 203.0.112.0, not 203.0.113.0 (113 = 0x71 keeps its high nibble).
        // RFC 7871 §6：ADDRESS 必须按 SOURCE PREFIX-LENGTH 截断并零填充到字节边界。
        // hickory 只按整字节截断，非对齐的 /20 需要在这里清掉多余位。
        let query = make_query("example.com", 0x2001);
        let mode = EcsMode::FromClientIp {
            prefix_v4: 20,
            prefix_v6: 56,
        };
        let modified = apply_ecs(&query, &mode, IpAddr::V4("203.0.113.255".parse().unwrap()));

        let (addr, src_prefix, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(src_prefix, 20);
        assert_eq!(
            addr,
            IpAddr::V4("203.0.112.0".parse().unwrap()),
            "bits beyond the /20 must be zero"
        );
    }

    #[test]
    fn test_apply_ecs_masks_unaligned_v6_prefix() {
        // Same for IPv6 through the Static path: 2001:db8:abcd:ef01::1/52 is
        // 2001:db8:abcd:e000::, the low nibble of 0xef must go.
        // IPv6 走 Static 路径同样处理：/52 之后的位必须清零。
        let query = make_query("example.com", 0x2002);
        let mode = EcsMode::Static {
            ip: "2001:db8:abcd:ef01::1".to_string().into(),
            prefix: 52,
        };
        let modified = apply_ecs(&query, &mode, IpAddr::V4("192.0.2.1".parse().unwrap()));

        let (addr, src_prefix, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(src_prefix, 52);
        assert_eq!(
            addr,
            IpAddr::V6("2001:db8:abcd:e000::".parse().unwrap()),
            "bits beyond the /52 must be zero"
        );
    }

    #[test]
    fn test_apply_ecs_from_client_ip_private_skipped() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };

        // RFC 1918 私有地址、回环，和基准测试网段 — 不应注入
        // RFC 1918 private, loopback and the benchmarking range — should not inject
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "198.18.0.1",
        ] {
            let peer: IpAddr = ip.parse().unwrap();
            let result = apply_ecs(&query, &mode, peer);
            assert!(
                !has_ecs(&result),
                "private IP {ip} should not get ECS / 私有 IP 不应注入 ECS"
            );
        }

        // IPv6 ULA — should not inject
        // IPv6 ULA — 不应注入
        let ula: IpAddr = "fd00::1".parse().unwrap();
        let result = apply_ecs(&query, &mode, ula);
        assert!(
            !has_ecs(&result),
            "ULA should not get ECS / ULA 不应注入 ECS"
        );

        // IPv6 loopback
        let lo: IpAddr = "::1".parse().unwrap();
        let result = apply_ecs(&query, &mode, lo);
        assert!(!has_ecs(&result), "::1 should not get ECS");
    }

    #[test]
    fn test_apply_ecs_static_mode() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::Static {
            ip: "203.0.113.0".to_string().into(),
            prefix: 24,
        };
        let result = apply_ecs(&query, &mode, "127.0.0.1".parse().unwrap());

        assert!(has_ecs(&result));
        let (addr, prefix, _) = extract_ecs_info(&result).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_apply_ecs_static_invalid_ip_skipped() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::Static {
            ip: "not.an.ip.addr".to_string().into(),
            prefix: 24,
        };
        let result = apply_ecs(&query, &mode, "8.8.8.8".parse().unwrap());
        assert!(
            !has_ecs(&result),
            "invalid IP should not inject / 无效 IP 不应注入"
        );
    }

    #[test]
    fn test_apply_ecs_malformed_packet_passes_through() {
        let garbage = [0x00; 5];
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let result = apply_ecs(&garbage, &mode, "8.8.8.8".parse().unwrap());
        assert_eq!(
            result,
            garbage.to_vec(),
            "malformed packet should pass through / 畸形包应原样通过"
        );
    }

    // ---- withheld_from_ecs ----

    #[test]
    fn test_withheld_from_ecs() {
        // Private v4
        assert!(withheld_from_ecs("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("169.254.1.1".parse::<IpAddr>().unwrap()));

        // Public v4
        assert!(!withheld_from_ecs("8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!withheld_from_ecs("203.0.113.1".parse::<IpAddr>().unwrap()));

        // Private v6
        assert!(withheld_from_ecs("::1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("fd00::1".parse::<IpAddr>().unwrap()));
        assert!(withheld_from_ecs("fe80::1".parse::<IpAddr>().unwrap()));

        // 运营商级 NAT、站点本地、本地用的转换前缀里嵌着公网地址的，和基准测试网段的两头 / Carrier-grade
        // NAT, site-local, the local-use translation prefix embedding a public address, and either
        // end of the benchmarking range
        for address in [
            "100.64.0.1",
            "fec0::1",
            "64:ff9b:1::808:808",
            "198.18.0.0",
            "198.19.255.255",
        ] {
            assert!(withheld_from_ecs(address.parse().unwrap()), "{address}");
        }

        // Public v6
        assert!(!withheld_from_ecs(
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
        assert!(!withheld_from_ecs("64:ff9b::808:808".parse().unwrap()));
        // 基准测试网段两边紧挨着的 / Those right outside the benchmarking range
        assert!(!withheld_from_ecs("198.17.255.255".parse().unwrap()));
        assert!(!withheld_from_ecs("198.20.0.0".parse().unwrap()));
        assert!(!withheld_from_ecs(
            "2606:4700::1111".parse::<IpAddr>().unwrap()
        ));
    }

    // ---- plan: the subnet a forward sends ----

    /// The subnet `plan` sets, if any / `plan` 设置的子网（如有）
    fn planned(mode: &EcsMode, peer: IpAddr) -> Option<EcsKey> {
        match plan(Some(mode), peer, None) {
            EcsPlan::Set(subnet) => Some(subnet),
            EcsPlan::Strip | EcsPlan::Keep => None,
        }
    }

    /// RFC 7871 第 7.1 节：客户端自己带的 ECS 决定给上游多少地址，公网和私有地址的客户端都一样
    /// RFC 7871 section 7.1: the client's own ECS decides how much of its address
    /// goes upstream, for public and private clients alike
    #[test]
    fn from_client_ip_follows_the_clients_own_ecs() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let own =
            |address: &str, prefix: u8| EcsKey::from_ip(address.parse().unwrap(), prefix, prefix);
        let public: IpAddr = "198.51.100.7".parse().unwrap();
        let private: IpAddr = "192.168.1.10".parse().unwrap();
        for peer in [public, private] {
            // 前缀 0 表示不要地址；不比设置长的原样转发
            // A prefix of 0 asks for no address; one no longer than the setting goes on as it is
            for kept in [
                own("0.0.0.0", 0),
                own("203.0.0.0", 16),
                own("203.0.113.0", 24),
            ] {
                assert_eq!(plan(Some(&mode), peer, Some(&kept)), EcsPlan::Keep);
            }
            // 更长的截短到设置的前缀 / A longer one is cut to the setting
            assert_eq!(
                plan(Some(&mode), peer, Some(&own("203.0.113.9", 32))),
                EcsPlan::Set(own("203.0.113.0", 24))
            );
            assert_eq!(
                plan(Some(&mode), peer, Some(&own("2001:db8:1:2::", 64))),
                EcsPlan::Set(own("2001:db8:1::", 56))
            );
        }
        // 读不懂的选项：读不出客户端允许给多少地址，所以去掉选项，也不加来源地址的子网
        // An option nobody can read: how much address the client allows cannot be
        // read, so the option goes and no subnet of the source address is added
        let opaque = EcsKey::opaque(b"not an ECS option");
        assert_eq!(plan(Some(&mode), public, Some(&opaque)), EcsPlan::Strip);
        assert_eq!(plan(Some(&mode), private, Some(&opaque)), EcsPlan::Strip);
        assert!(!forwards_own_ecs(public, Some(&opaque)));
        assert!(!forwards_own_ecs(private, Some(&opaque)));
    }

    /// RFC 7871 第 11.3 节：客户端自己带的私有网段按解析器自己的身份对待，不发给上游：公网
    /// 客户端照样发来源地址的子网，私有地址的客户端什么也不发
    /// RFC 7871 section 11.3: a private network in the client's own ECS is taken as
    /// the resolver's own identity and does not go upstream: a public client gets its
    /// address's subnet as usual, and a private client gets nothing
    #[test]
    fn from_client_ip_does_not_pass_on_a_private_network() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let own =
            |address: &str, prefix: u8| EcsKey::from_ip(address.parse().unwrap(), prefix, prefix);
        let public: IpAddr = "198.51.100.7".parse().unwrap();
        let private: IpAddr = "192.168.1.10".parse().unwrap();
        for network in [
            own("10.1.2.0", 24),
            own("fd00:1::", 48),
            own("127.0.0.0", 8),
            own("198.18.0.0", 24),
            // IPv4 映射形式的网段，私有的和公网的都不发 / IPv4-mapped networks, private and public alike
            own("::ffff:10.1.2.0", 120),
            own("::ffff:203.0.113.0", 120),
        ] {
            assert_eq!(
                plan(Some(&mode), public, Some(&network)),
                EcsPlan::Set(own("198.51.100.0", 24))
            );
            assert_eq!(plan(Some(&mode), private, Some(&network)), EcsPlan::Strip);
            assert!(!forwards_own_ecs(public, Some(&network)));
            assert!(!forwards_own_ecs(private, Some(&network)));
        }
        // 前缀 0 不带地址，不算私有网段 / A prefix of 0 carries no address and is no private network
        assert!(forwards_own_ecs(public, Some(&own("0.0.0.0", 0))));
        assert!(forwards_own_ecs(public, Some(&own("203.0.0.0", 16))));
        // 没带 ECS：只有私有地址的客户端，包按原样发出
        // No ECS: only a private client's packet goes as it was sent
        assert!(!forwards_own_ecs(public, None));
        assert!(forwards_own_ecs(private, None));
    }

    #[test]
    fn test_ecs_key_from_client_ip_v4() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let key = planned(&mode, "203.0.113.42".parse().unwrap()).unwrap();

        assert_eq!(key.family, 1);
        assert_eq!(key.source_prefix, 24);
        // /24 means first 3 bytes are significant
        assert_eq!(key.addr_len, 3);
        assert_eq!(&key.addr[..3], &[203, 0, 113]);
    }

    #[test]
    fn test_ecs_key_from_client_ip_v6() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let peer: IpAddr = "2001:db8:abcd:1234::5".parse().unwrap();
        let key = planned(&mode, peer).unwrap();

        assert_eq!(key.family, 2);
        assert_eq!(key.source_prefix, 56);
        // /56 means first 7 bytes are significant
        assert_eq!(key.addr_len, 7);
        assert_eq!(&key.addr[..7], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12]);
    }

    #[test]
    fn test_ecs_key_from_client_ip_private_returns_none() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        // Private IPs should not produce an ECS key (privacy protection)
        // 私有 IP 不应产生 ECS key（隐私保护）
        assert!(planned(&mode, "10.0.0.1".parse().unwrap()).is_none());
        assert!(planned(&mode, "127.0.0.1".parse().unwrap()).is_none());
        assert!(planned(&mode, "192.168.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_ecs_key_clear_returns_none() {
        let mode = EcsMode::Clear;
        let key = planned(&mode, "8.8.8.8".parse().unwrap());
        assert!(
            key.is_none(),
            "Clear mode should not produce ECS key / Clear 模式不应产生 ECS key"
        );
    }

    #[test]
    fn test_ecs_key_static_mode() {
        let mode = EcsMode::Static {
            ip: "203.0.113.0".to_string().into(),
            prefix: 24,
        };
        let key = planned(&mode, "127.0.0.1".parse().unwrap()).unwrap();

        assert_eq!(key.family, 1);
        assert_eq!(key.source_prefix, 24);
        assert_eq!(&key.addr[..3], &[203, 0, 113]);
    }

    #[test]
    fn test_ecs_key_static_invalid_ip_returns_none() {
        let mode = EcsMode::Static {
            ip: "not.an.ip".to_string().into(),
            prefix: 24,
        };
        let key = planned(&mode, "8.8.8.8".parse().unwrap());
        assert!(key.is_none());
    }

    #[test]
    fn test_ecs_key_cache_hash_isolation() {
        use rustc_hash::FxHasher;
        use std::hash::Hasher;

        // Same IP, different /24 subnets should produce different EcsKeys
        // 相同 IP 段，不同 /24 子网应产生不同的 EcsKey
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };

        let key1 = planned(&mode, "203.0.113.5".parse().unwrap()).unwrap();
        let key2 = planned(&mode, "203.0.113.100".parse().unwrap()).unwrap();
        let key3 = planned(&mode, "203.0.200.5".parse().unwrap()).unwrap();

        // Same /24 → same key
        assert_eq!(key1.addr[..3], key2.addr[..3]);

        // Different /24 → different key
        assert_ne!(key1.addr[..3], key3.addr[..3]);

        // Different EcsKeys → different hashes
        let mut h1 = FxHasher::default();
        key1.hash_into(&mut h1);
        let mut h3 = FxHasher::default();
        key3.hash_into(&mut h3);
        assert_ne!(
            h1.finish(),
            h3.finish(),
            "Different /24 subnets must produce different hashes / 不同 /24 子网必须产生不同的哈希"
        );
    }

    #[test]
    fn test_ecs_key_prefix_masking() {
        // /20 prefix: first 2 bytes + masked 3rd byte
        // /20 前缀：前 2 字节完整 + 第 3 字节掩码
        let mode = EcsMode::FromClientIp {
            prefix_v4: 20,
            prefix_v6: 56,
        };
        let key = planned(&mode, "203.0.113.5".parse().unwrap()).unwrap();

        // /20 = 20 bits = 2.5 bytes → 3 bytes used, 3rd byte masked to top 4 bits
        assert_eq!(key.addr_len, 3);
        assert_eq!(key.addr[0], 203);
        assert_eq!(key.addr[1], 0);
        // 113 & 0xF0 = 112 (0x70)
        assert_eq!(key.addr[2], 112);
    }
}
