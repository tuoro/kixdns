//! EDNS Client Subnet (ECS) wire manipulation — RFC 7871
//! EDNS 客户端子网 (ECS) wire 操作 — RFC 7871
//!
//! Provides request-side ECS injection/stripping for the `Forward` action.
//! Only runs on cache-miss path (inside `handle_forward_decision`), so the
//! hot path (cache hit / static response) is never affected.
//!
//! 为 `Forward` 动作提供请求侧 ECS 注入/剥离。
//! 仅在缓存未命中路径（`handle_forward_decision` 内部）执行，
//! 热路径（缓存命中 / 静态响应）完全不受影响。

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

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

/// Apply ECS transformation to a DNS wire packet, returning modified bytes.
/// 对 DNS wire 包应用 ECS 变换，返回修改后的字节。
///
/// Returns the original packet bytes if:
/// - Mode is `Clear` but no ECS exists (no-op)
/// - Mode is `FromClientIp` and the client's own ECS goes on as it is, or the client
///   sent none and its IP is private (privacy protection, RFC 1918/ULA/loopback);
///   see `plan`
/// - Static IP is invalid
/// - Message parsing fails (malformed query)
///
/// 以下情况返回原始包字节：
/// - 模式为 `Clear` 但不存在 ECS（无需操作）
/// - 模式为 `FromClientIp`，客户端自己的 ECS 原样转发，或者客户端没带 ECS 而 IP 为私有地址
///   （隐私保护，RFC 1918/ULA/loopback）；见 `plan`
/// - 静态 IP 无效
/// - 消息解析失败（畸形查询）
pub fn apply_ecs(packet: &[u8], mode: &EcsMode, peer_ip: IpAddr) -> Vec<u8> {
    let client = match mode {
        EcsMode::FromClientIp { .. } => crate::proto_utils::client_subnet(packet),
        _ => None,
    };
    apply_ecs_for(packet, mode, peer_ip, client.as_ref())
}

/// [`apply_ecs`] for a request whose own ECS option the caller already holds, as
/// the engine does: a background refresh replays a packet that cannot carry an
/// option nobody can read (see `RefreshTarget::client_ecs`).
/// 调用方已经拿着请求自己 ECS 选项时的 [`apply_ecs`]，引擎就是这样：后台刷新重放的包带不了
/// 读不懂的选项（见 `RefreshTarget::client_ecs`）。
pub(crate) fn apply_ecs_for(
    packet: &[u8],
    mode: &EcsMode,
    peer_ip: IpAddr,
    client: Option<&EcsKey>,
) -> Vec<u8> {
    match plan(Some(mode), peer_ip, client) {
        EcsPlan::Strip => strip_ecs(packet),
        EcsPlan::Keep => packet.to_vec(),
        EcsPlan::Set(subnet) => inject_ecs(packet, subnet),
    }
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
/// `proto_utils::client_subnet`). `apply_ecs` carries it out; the response cache
/// reads it to know what the upstream was asked with.
/// 带 `ecs`（None 表示转发没写 `ecs`）的转发对来自 `peer_ip`、带着 ECS 选项 `client`（见
/// `proto_utils::client_subnet`）的请求怎么处理 ECS。`apply_ecs` 照此执行；响应缓存据此知道
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
            OwnEcs::Private if is_private_ip(&peer_ip) => EcsPlan::Strip,
            OwnEcs::Private | OwnEcs::Absent if !is_private_ip(&peer_ip) => {
                EcsPlan::Set(EcsKey::from_ip(peer_ip, *prefix_v4, *prefix_v6))
            }
            OwnEcs::Private | OwnEcs::Absent => EcsPlan::Keep,
        },
        Some(EcsMode::Static { ip, prefix }) => match ip.parse::<IpAddr>() {
            Ok(parsed) => EcsPlan::Set(EcsKey::from_ip(parsed, *prefix, *prefix)),
            Err(_) => {
                tracing::warn!(ip = %ip, "invalid static ECS IP, skipping injection / 静态 ECS IP 无效，跳过注入");
                EcsPlan::Keep
            }
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
    is_private_ip(&ip) || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

/// Whether `from_client_ip` sends a request's own ECS (`client`, from `peer_ip`):
/// its subnet as it is or cut short, or the packet as the client sent it
/// `from_client_ip` 是否发出请求自己的 ECS（来自 `peer_ip` 的 `client`）：它的子网原样或截短，
/// 或者包按客户端发来的原样发出
pub(crate) fn forwards_own_ecs(peer_ip: IpAddr, client: Option<&EcsKey>) -> bool {
    match own_ecs(client) {
        OwnEcs::Forwarded(_) => true,
        OwnEcs::Private | OwnEcs::Unreadable => false,
        OwnEcs::Absent => is_private_ip(&peer_ip),
    }
}

/// Inject (or replace) ECS OPT option into a DNS wire packet.
/// 向 DNS wire 包注入（或替换）ECS OPT 选项。
///
/// Uses hickory-proto `Message` round-trip for correctness — OPT pseudo-record
/// manipulation involves variable-length TLV encoding and ARCOUNT updates that
/// are error-prone at wire level. This only runs on cache-miss path.
///
/// 使用 hickory-proto `Message` 往返保证正确性 — OPT 伪记录操作涉及变长 TLV
/// 编码和 ARCOUNT 更新，在 wire 层操作容易出错。此函数仅在缓存未命中路径执行。
fn inject_ecs(packet: &[u8], subnet: EcsKey) -> Vec<u8> {
    let mut msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "ECS inject: failed to parse message, forwarding as-is / ECS 注入：解析消息失败，原样转发");
            return packet.to_vec();
        }
    };

    // RFC 7871 §6: ADDRESS carries only SOURCE PREFIX-LENGTH bits, zero-padded
    // to the last octet. hickory emits ceil(prefix / 8) octets of the address
    // as given, so a prefix that is not a multiple of 8 would leak the client's
    // extra bits and produce an option strict upstreams reject as FORMERR.
    // RFC 7871 §6：ADDRESS 只能带 SOURCE PREFIX-LENGTH 位，其余零填充。hickory 按
    // 原样输出 ceil(prefix/8) 字节，非 8 的倍数前缀会泄露客户端多余位，且严格的
    // 上游会回 FORMERR。
    // `EcsKey` holds the address already masked to its prefix, which is capped at the
    // family's length.
    // `EcsKey` 里的地址已经按前缀掩码，前缀也已按地址族的长度封顶。
    let Some(addr) = subnet.ip() else {
        return packet.to_vec();
    };
    let subnet = ClientSubnet::new(addr, subnet.source_prefix, 0);

    // Insert or replace ECS option in the EDNS extensions.
    // hickory-proto 0.26 OPT uses Vec (not HashMap): insert() always pushes,
    // so we must explicitly remove any existing Subnet to avoid duplicates.
    //
    // 在 EDNS 扩展中插入或替换 ECS 选项。
    // hickory-proto 0.26 的 OPT 使用 Vec（非 HashMap）：insert() 总是追加，
    // 因此必须先显式移除已有的 Subnet 以避免重复。
    match &mut msg.edns {
        Some(edns) => {
            edns.options_mut().remove(EdnsCode::Subnet);
            edns.options_mut().insert(EdnsOption::Subnet(subnet));
        }
        None => {
            // No existing OPT record — create one with default EDNS parameters and insert ECS
            // 不存在 OPT 记录 — 创建默认 EDNS 参数并插入 ECS
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            edns.options_mut().insert(EdnsOption::Subnet(subnet));
            msg.edns = Some(edns);
        }
    }

    match msg.to_vec() {
        Ok(buf) => buf,
        Err(e) => {
            tracing::debug!(error = %e, "ECS inject: failed to re-encode message, forwarding as-is / ECS 注入：重新编码消息失败，原样转发");
            packet.to_vec()
        }
    }
}

/// Strip ECS OPT option from a DNS wire packet.
/// 从 DNS wire 包中剥离 ECS OPT 选项。
///
/// If no ECS option exists, returns the original packet unchanged.
/// 如果不存在 ECS 选项，原样返回原始包。
///
/// The options are cut out of the OPT record as they stand, so one hickory cannot
/// decode (an unknown family, a prefix too long) goes too; hickory only steps in
/// when records follow the OPT record (see `proto_utils::without_ecs`).
/// 选项按报文原样从 OPT 记录里删掉，所以 hickory 解不开的选项（地址族未知、前缀过长）也能删；
/// 只有 OPT 后面还有记录时才交给 hickory（见 `proto_utils::without_ecs`）。
fn strip_ecs(packet: &[u8]) -> Vec<u8> {
    if let Ok(stripped) = crate::proto_utils::without_ecs(bytes::Bytes::copy_from_slice(packet)) {
        return stripped.to_vec();
    }
    let mut msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return packet.to_vec(),
    };

    let has_ecs = msg
        .edns
        .as_ref()
        .and_then(|e| e.options().get(EdnsCode::Subnet))
        .is_some();

    if !has_ecs {
        return packet.to_vec();
    }

    if let Some(edns) = &mut msg.edns {
        edns.options_mut().remove(EdnsCode::Subnet);
    }

    match msg.to_vec() {
        Ok(buf) => buf,
        Err(_) => packet.to_vec(),
    }
}

/// Check if an IP address is private/internal (RFC 1918, ULA, loopback, link-local).
/// 检查 IP 地址是否为私有/内网地址 (RFC 1918, ULA, loopback, link-local)。
///
/// Private addresses must never be leaked via ECS.
/// 私有地址绝不能通过 ECS 泄露。
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()       // RFC 1918: 10/8, 172.16/12, 192.168/16
            || v4.is_loopback()   // 127/8
            || v4.is_link_local() // 169.254/16
            || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                    // ::1
            || v6.is_unspecified()              // ::
            || is_ula_v6(v6)                    // fc00::/7 (RFC 4193)
            || v6.is_unicast_link_local() // fe80::/10
        }
    }
}

/// Check if IPv6 address is Unique Local Address (ULA, fc00::/7).
/// 检查 IPv6 地址是否为唯一本地地址 (ULA, fc00::/7)。
fn is_ula_v6(v6: &Ipv6Addr) -> bool {
    // ULA range: fc00::/7 — check first byte's top 7 bits
    // ULA 范围：fc00::/7 — 检查首字节的高 7 位
    let octets = v6.octets();
    (octets[0] & 0xFE) == 0xFC
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
            IpAddr::V4(v4) => {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&v4.octets());
                let p = prefix_v4.min(32);
                mask_address(&mut addr, p, 32);
                let bytes_used = (p as usize).div_ceil(8);
                Self {
                    family: 1,
                    source_prefix: p,
                    addr,
                    addr_len: bytes_used.min(4) as u8,
                }
            }
            IpAddr::V6(v6) => {
                let mut addr = v6.octets();
                let p = prefix_v6.min(128);
                mask_address(&mut addr, p, 128);
                let bytes_used = (p as usize).div_ceil(8);
                Self {
                    family: 2,
                    source_prefix: p,
                    addr,
                    addr_len: bytes_used.min(16) as u8,
                }
            }
        }
    }

    /// The ECS option a query or reply carries: FAMILY, SOURCE PREFIX-LENGTH and
    /// ADDRESS as sent. The address is cut to its first 16 octets and masked to
    /// the prefix (RFC 7871 section 6 requires the bits beyond it to be zero, and
    /// whatever they are, the subnet is the prefix's), so two options that name
    /// the same subnet make equal keys.
    /// 查询或应答携带的 ECS 选项：原样的 FAMILY、SOURCE PREFIX-LENGTH 和 ADDRESS。
    /// 地址最多取前 16 个字节，并按前缀掩码（RFC 7871 第 6 节要求前缀之后的位为零；
    /// 不管它们是什么，子网都由前缀决定），所以指同一个子网的两个选项得到相同的键。
    pub(crate) fn from_wire(family: u16, source_prefix: u8, address: &[u8]) -> Self {
        let mut addr = [0u8; 16];
        let given = address.len().min(16);
        addr[..given].copy_from_slice(&address[..given]);
        let total_bits = match family {
            1 => 32,
            2 => 128,
            _ => (given * 8) as u8,
        };
        let bits = source_prefix.min(total_bits);
        mask_address(&mut addr, bits, 128);
        Self {
            family,
            source_prefix,
            addr,
            addr_len: (bits as usize).div_ceil(8) as u8,
        }
    }

    /// 读不懂、或不完全符合 RFC 7871 第 6 节的 ECS 选项（地址族未知、前缀超长、地址长度不对、
    /// 前缀之后的位不为零、查询里 SCOPE 不为 0、不止一个 ECS 选项）。透传客户端 ECS 的转发会把
    /// 这样的选项原样发给上游，应答适用于谁说不准（`from_client_ip` 会去掉它）；键由选项的原始
    /// 字节决定，不会和任何真实子网相等。
    /// An ECS option that cannot be read, or does not follow RFC 7871 section 6 to
    /// the letter (an unknown family, a prefix too long, the wrong address length,
    /// bits set beyond the prefix, a nonzero SCOPE in a query, more than one ECS
    /// option). A forward that passes the client's ECS on sends such an option as it
    /// is, and whom the answer applies to is unclear (`from_client_ip` removes it);
    /// its key comes from the option's raw bytes and never equals a real subnet.
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
        mask_address(&mut addr, prefix, 128);
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

/// Mask an address buffer to the given prefix length (in-place).
/// 将地址缓冲区掩码到指定前缀长度（原地操作）。
fn mask_address(addr: &mut [u8], prefix: u8, total_bits: u8) {
    if prefix >= total_bits {
        return;
    }
    let p = prefix as usize;
    let bytes_used = p.div_ceil(8);
    let bit = p % 8;
    if bit > 0 && bytes_used > 0 {
        addr[bytes_used - 1] &= 0xFF << (8 - bit);
    }
    // Compute end index before mutable borrow to avoid borrow checker conflict
    // 在可变借用前计算结束索引以避免借用检查器冲突
    let end = (total_bits as usize / 8).min(addr.len());
    for b in &mut addr[bytes_used..end] {
        *b = 0;
    }
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

/// Extract ECS subnet info from a wire packet (for testing).
/// hickory-proto 0.26+ exposes ClientSubnet fields via accessors.
///
/// 从 wire 包中提取 ECS 子网信息（用于测试）。
/// hickory-proto 0.26+ 通过访问器暴露 ClientSubnet 字段。
#[cfg(test)]
pub(crate) fn extract_ecs_info(packet: &[u8]) -> Option<(IpAddr, u8, u8)> {
    let msg = Message::from_vec(packet).ok()?;
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

    // ---- inject_ecs ----

    #[test]
    fn test_inject_ecs_into_plain_query() {
        let query = make_query("example.com", 0x1234);
        let modified = inject_ecs(
            &query,
            EcsKey::from_ip(IpAddr::V4("203.0.113.5".parse().unwrap()), 24, 24),
        );

        assert!(has_ecs(&modified), "ECS should be present after injection");
        let (addr, src_prefix, scope) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(src_prefix, 24);
        assert_eq!(scope, 0, "query scope must be 0 / 查询 scope 必须为 0");
    }

    #[test]
    fn test_inject_ecs_into_query_with_existing_opt() {
        let query = make_query_with_opt("example.com", 0x1234);
        let modified = inject_ecs(
            &query,
            EcsKey::from_ip(IpAddr::V4("203.0.113.5".parse().unwrap()), 24, 24),
        );

        assert!(has_ecs(&modified));
        let (addr, _, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
    }

    #[test]
    fn test_inject_ecs_v6() {
        let query = make_query("example.com", 0x1234);
        let v6: Ipv6Addr = "2001:db8:abcd:1234::5".parse().unwrap();
        let modified = inject_ecs(&query, EcsKey::from_ip(IpAddr::V6(v6), 56, 56));

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
        let modified = inject_ecs(
            &query,
            EcsKey::from_ip(IpAddr::V4("203.0.113.5".parse().unwrap()), 24, 24),
        );
        assert!(has_ecs(&modified));

        // Inject again with different subnet — should replace, not duplicate
        // 用不同子网再次注入 — 应替换而非重复
        let re_modified = inject_ecs(
            &modified,
            EcsKey::from_ip(IpAddr::V4("198.51.100.5".parse().unwrap()), 24, 24),
        );
        let (addr, _, _) = extract_ecs_info(&re_modified).unwrap();
        assert_eq!(addr, IpAddr::V4("198.51.100.0".parse().unwrap()));
    }

    // ---- strip_ecs ----

    #[test]
    fn test_strip_ecs_removes_ecs() {
        let query = make_query("example.com", 0x1234);
        let injected = inject_ecs(
            &query,
            EcsKey::from_ip(IpAddr::V4("203.0.113.5".parse().unwrap()), 24, 24),
        );
        assert!(has_ecs(&injected));

        let stripped = strip_ecs(&injected);
        assert!(!has_ecs(&stripped), "ECS should be removed / ECS 应被移除");
    }

    #[test]
    fn test_strip_ecs_no_ecs_is_noop() {
        let query = make_query("example.com", 0x1234);
        assert!(!has_ecs(&query));

        let result = strip_ecs(&query);
        assert!(!has_ecs(&result));
    }

    // ---- apply_ecs (integration) ----

    #[test]
    fn test_apply_ecs_clear_mode() {
        let query = make_query("example.com", 0x1234);
        let injected = inject_ecs(
            &query,
            EcsKey::from_ip(IpAddr::V4("203.0.113.5".parse().unwrap()), 24, 24),
        );

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
            ip: "2001:db8:abcd:ef01::1".to_string(),
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

        // RFC 1918 private — should not inject
        // RFC 1918 私有地址 — 不应注入
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"] {
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
            ip: "203.0.113.0".to_string(),
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
            ip: "not.an.ip.addr".to_string(),
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

    // ---- is_private_ip ----

    #[test]
    fn test_is_private_ip() {
        // Private v4
        assert!(is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse::<IpAddr>().unwrap()));

        // Public v4
        assert!(!is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(&"203.0.113.1".parse::<IpAddr>().unwrap()));

        // Private v6
        assert!(is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse::<IpAddr>().unwrap()));

        // Public v6
        assert!(!is_private_ip(
            &"2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_private_ip(
            &"2606:4700::1111".parse::<IpAddr>().unwrap()
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
            ip: "203.0.113.0".to_string(),
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
            ip: "not.an.ip".to_string(),
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
