use std::hash::Hasher;

use bytes::{Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

/// 快速解析结果，零拷贝实现 / Quick parse result with zero-copy implementation
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    pub qname_bytes: &'a [u8], // 零拷贝：直接引用已小写化的缓冲区
    pub qtype: u16,
    pub qclass: u16,
    pub edns_present: bool,
    /// 请求 OPT 里的 EDNS 版本，没有 OPT 时为 0 / The EDNS version in the request's OPT, 0 without one
    pub edns_version: u8,
    /// 客户端自己带的 ECS 选项 / The ECS option the client carries itself
    pub client_subnet: Option<crate::ecs::EcsKey>,
    /// 问题之外还决定应答的查询位（见 [`QueryFlags`]）/ The query bits besides the question that
    /// decide the answer (see [`QueryFlags`])
    pub flags: QueryFlags,
}

/// 问题之外还决定应答的查询位：RD（要求递归）、CD（不做验证，RFC 4035 第 3.2.2 节）和 EDNS 的 DO
/// 位（要 DNSSEC 记录，RFC 3225）。上游对这几位不同的请求给的应答不同，所以缓存和合并都把它们分开。
/// The query bits besides the question that decide the answer: RD (recursion desired), CD
/// (checking disabled, RFC 4035 section 3.2.2) and the EDNS DO bit (DNSSEC records wanted,
/// RFC 3225). An upstream answers requests that differ in them differently, so the cache and
/// the merging of requests keep them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct QueryFlags(u8);

impl QueryFlags {
    const RECURSION_DESIRED: u8 = 1;
    const CHECKING_DISABLED: u8 = 2;
    const DNSSEC_OK: u8 = 4;

    /// 普通的递归查询：RD 置位，CD 和 DO 都没有（多数客户端发的就是这样）
    /// A plain recursive query: RD set, neither CD nor DO (what most clients send)
    pub const RECURSIVE: Self = Self(Self::RECURSION_DESIRED);

    pub fn new(recursion_desired: bool, checking_disabled: bool, dnssec_ok: bool) -> Self {
        let bit = |set: bool, bit: u8| if set { bit } else { 0 };
        Self(
            bit(recursion_desired, Self::RECURSION_DESIRED)
                | bit(checking_disabled, Self::CHECKING_DISABLED)
                | bit(dnssec_ok, Self::DNSSEC_OK),
        )
    }

    /// 从查询报文读出，和 `parse_quick` 读出的一样 / Read off a query packet, as `parse_quick` reads them
    pub fn of(query: &[u8]) -> Self {
        let dnssec_ok = matches!(find_opt(query), Ok(Some(opt)) if query[opt.extended_rcode_at + 2] & 0x80 != 0);
        Self::new(
            query.get(2).is_some_and(|byte| byte & 0x01 != 0),
            query.get(3).is_some_and(|byte| byte & 0x10 != 0),
            dnssec_ok,
        )
    }

    pub fn recursion_desired(self) -> bool {
        self.0 & Self::RECURSION_DESIRED != 0
    }

    pub fn checking_disabled(self) -> bool {
        self.0 & Self::CHECKING_DISABLED != 0
    }

    pub fn dnssec_ok(self) -> bool {
        self.0 & Self::DNSSEC_OK != 0
    }

    /// 写进缓存键的值 / The value hashed into cache keys
    pub fn bits(self) -> u8 {
        self.0
    }
}

/// Check the fixed DNS header fields required by KixDNS's standard query path.
/// This cheap ingress guard must run before cache/static fast paths so response
/// packets cannot be reflected as normal answers.
#[inline]
pub fn is_standard_query_header(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        return false;
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);

    flags & 0x8000 == 0 && flags & 0x7800 == 0 && qd_count == 1 && an_count == 0 && ns_count == 0
}

/// 仅解析 DNS 头部和第一个 Query，用于快速缓存查找 / Parse only DNS header and first query for quick cache lookup
/// 避免 hickory-proto Message::from_bytes 的全量解析和分配开销 / Avoid full parsing and allocation overhead of hickory-proto Message::from_bytes
/// buf: 用于存储归一化（小写）域名的缓冲区，建议至少 256 字节 / buf: buffer for storing normalized (lowercase) domain name, recommend at least 256 bytes
pub fn parse_quick<'a>(packet: &[u8], buf: &'a mut [u8]) -> Option<QuickQuery<'a>> {
    if !is_standard_query_header(packet) {
        return None;
    }

    // 1. Transaction ID / 事务ID
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

    // 2. Counts / 计数
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

    // 3. Parse QName (start at offset 12) / 解析查询名称（从偏移量 12 开始）
    let mut pos = 12;
    let mut buf_pos = 0;

    let mut jumped = false;
    let mut max_jumps = 5;
    let mut current_pos = pos;
    let packet_len = packet.len();

    loop {
        if current_pos >= packet_len {
            return None;
        }
        let len = packet[current_pos];

        if len == 0 {
            // End of name / 名称结束
            if !jumped {
                pos = current_pos + 1;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer / 压缩指针
            if packet_len < current_pos + 2 {
                return None;
            }
            if !jumped {
                pos = current_pos + 2;
                jumped = true;
            }
            let offset = (((len as u16) & 0x3F) << 8) | (packet[current_pos + 1] as u16);
            // RFC 1035 section 4.1.4: a pointer refers to a prior occurrence, so it must
            // point before itself (hickory refuses others too). One pointing forward could
            // land on bytes that move when the packet is rewritten, and the name sent
            // upstream would no longer be the one routed on.
            // RFC 1035 第 4.1.4 节：指针指向前面出现过的名字，必须指在自己前面（hickory 也拒绝
            // 别的）。指向后面的指针可能落在改写报文时会挪动的字节上，发给上游的名字就不再是
            // 路由时看到的那个。
            if offset as usize >= current_pos {
                return None;
            }
            current_pos = offset as usize;
            max_jumps -= 1;
            if max_jumps == 0 {
                return None; // Loop detection / 循环检测
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }

        // Label / 标签
        let label_len = len as usize;
        current_pos += 1;
        if packet_len < current_pos + label_len {
            return None;
        }

        if buf_pos > 0 {
            if buf_pos >= buf.len() {
                return None;
            }
            buf[buf_pos] = b'.';
            buf_pos += 1;
        }

        let label_bytes = &packet[current_pos..current_pos + label_len];

        // A byte the name's text writes escaped (see `name_text`) leaves the query to the full
        // parser, so both parsers give every name the same text. The bytes taken here are
        // printable ASCII, safe in structured logs too.
        // 名字文本里要转义的字节（见 `name_text`）留给完整解析，两个解析器给每个名字的文本才一样。
        // 这里收下的都是可打印 ASCII，写进结构化日志也安全。
        if !label_bytes.iter().all(|&b| is_plain_name_byte(b)) {
            return None;
        }

        // Performance optimization: Check if label needs lowercasing
        // Most DNS labels are already lowercase, so we can avoid the copy in common case
        // Use simple loop for better cache locality and early break
        let mut needs_lowercase = false;
        for &b in label_bytes {
            if b.is_ascii_uppercase() {
                needs_lowercase = true;
                break;
            }
        }

        // Copy label bytes to buffer
        if buf_pos + label_len > buf.len() {
            return None;
        }

        if needs_lowercase {
            // Only lowercase if necessary
            for &b in label_bytes {
                buf[buf_pos] = b.to_ascii_lowercase();
                buf_pos += 1;
            }
        } else {
            // Zero-copy: just copy the bytes as-is
            buf[buf_pos..buf_pos + label_len].copy_from_slice(label_bytes);
            buf_pos += label_len;
        }

        current_pos += label_len;
    }

    // 4. QType / 查询类型
    if packet.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;

    // 5. Validate every declared Additional record and detect EDNS.
    // Fail closed before cache/static fast paths on any malformed wire structure.
    //
    // Trade-off vs the old fast-path scan: this always walks the full Additional
    // section and rejects trailing data, where the old code broke early on OPT and
    // tolerated truncation. Full validation is required so malformed packets cannot
    // reach cache/static paths; the cost is bounded by ARCOUNT records.
    //
    // 权衡：总是遍历完整 Additional 段并拒绝尾随数据（旧代码找到 OPT 即提前退出、容忍截断）。
    // 完整校验是为了让畸形包无法到达 cache/static 路径；成本以 ARCOUNT 记录数为界。
    let mut edns_present = false;
    let mut edns_version = 0;
    let mut dnssec_ok = false;
    let mut client_subnet = None;
    let mut ar_pos = pos;
    for _ in 0..ar_count {
        let owner_start = ar_pos;
        let next_pos = skip_name(packet, ar_pos)?;
        let fixed_end = next_pos.checked_add(10)?;
        if fixed_end > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[next_pos], packet[next_pos + 1]]);
        let rd_len = u16::from_be_bytes([packet[next_pos + 8], packet[next_pos + 9]]) as usize;
        let rdata_end = fixed_end.checked_add(rd_len)?;
        if rdata_end > packet.len() {
            return None;
        }

        if rr_type == 41 {
            // RFC 6891: OPT owner name must be the root and only one OPT is valid.
            if edns_present || packet.get(owner_start) != Some(&0) {
                return None;
            }
            validate_edns_options(packet, fixed_end, rdata_end)?;
            edns_present = true;
            // TTL 字段依次是扩展 RCODE、版本和标志 / The TTL field holds the extended RCODE, the version and the flags
            edns_version = packet[next_pos + 5];
            dnssec_ok = packet[next_pos + 6] & 0x80 != 0;
            client_subnet = query_subnet(packet, fixed_end..rdata_end);
        }
        ar_pos = rdata_end;
    }
    if ar_pos != packet.len() {
        return None;
    }

    // Return slice of buf as zero-copy reference
    // Performance optimization: ASCII-only validation (10x faster than UTF-8)
    // 性能优化：仅 ASCII 验证（比 UTF-8 快 10 倍）
    // RFC 1035: DNS labels are LDH (Letters, Digits, Hyphen) + dots, which is ASCII subset
    // RFC 1035：DNS 标签是 LDH（字母、数字、连字符）+ 点号，属于 ASCII 子集
    // Strategy: Reject non-ASCII for performance (similar to Unbound)
    // 策略：为性能拒绝非 ASCII（类似 Unbound）
    // Trade-off: 0.001% queries rejected for 10% performance gain
    // 权衡：拒绝 0.001% 的查询以获得 10% 的性能提升
    // The buf already contains the lowercased domain name from the parsing loop above.
    Some(QuickQuery {
        tx_id,
        qname_bytes: &buf[..buf_pos], // 零拷贝：直接引用已小写化的缓冲区
        qtype,
        qclass,
        edns_present,
        edns_version,
        client_subnet,
        flags: QueryFlags::new(packet[2] & 0x01 != 0, packet[3] & 0x10 != 0, dnssec_ok),
    })
}

/// The text a query name is matched, cached and logged under: its labels lowercased and
/// joined with '.', without the trailing dot, and every label byte that is not printable
/// ASCII, or is a '.' or '\' inside a label, written as `\DDD` (decimal, as in zone files,
/// RFC 1035 section 5.1). `parse_quick` builds the same text for the names it takes, which
/// need no escape; every other name gets it from here. So whichever parser read the query,
/// the text is the same, and so are the rules it meets and the cache entry it finds.
/// 查询名用来匹配规则、查缓存和记日志的文本：各标签转成小写、用 '.' 连起来，不带结尾的点；
/// 标签里不是可打印 ASCII 的字节，以及标签内部的 '.' 和 '\'，写成 `\DDD`（十进制，同区域文件，
/// RFC 1035 第 5.1 节）。`parse_quick` 收下的名字都不需要转义，它拼出的就是这段文本；其余名字
/// 从这里得到。所以不论哪个解析器读的查询，文本都一样，遇到的规则和找到的缓存也一样。
pub fn name_text(name: &hickory_proto::rr::Name) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(name.len());
    for (index, label) in name.iter().enumerate() {
        if index > 0 {
            text.push('.');
        }
        for &byte in label {
            if is_plain_name_byte(byte) {
                text.push(byte.to_ascii_lowercase() as char);
            } else {
                let _ = write!(text, "\\{byte:03}");
            }
        }
    }
    text
}

/// The name `name_text` wrote `text` for (upper case and a trailing dot are taken too).
/// None for text it never writes: an empty label, a broken escape, a byte it would have
/// escaped. Answers built for a query name start from here: the text holds every label
/// byte, so the name comes back exactly.
/// `name_text` 为它写出 `text` 的那个名字（大写和结尾的点也接受）。不是它会写出的文本为 None：
/// 空标签、坏掉的转义、它本该转义的字节。为查询名构造的应答都从这里取名字：文本保存了标签的
/// 每个字节，名字可以原样还原。
pub fn name_from_text(text: &str) -> Option<hickory_proto::rr::Name> {
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() {
        return Some(hickory_proto::rr::Name::root());
    }
    let bytes = text.as_bytes();
    let mut labels = vec![Vec::new()];
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'.' => labels.push(Vec::new()),
            b'\\' => {
                let digits = bytes.get(index + 1..index + 4)?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                let value: u8 = std::str::from_utf8(digits).ok()?.parse().ok()?;
                labels.last_mut()?.push(value);
                index += 3;
            }
            byte if is_plain_name_byte(byte) => labels.last_mut()?.push(byte),
            _ => return None,
        }
        index += 1;
    }
    if labels.iter().any(Vec::is_empty) {
        return None;
    }
    hickory_proto::rr::Name::from_labels(labels.iter().map(Vec::as_slice)).ok()
}

/// A label byte the name's text holds as it is (see `name_text`) / 名字文本原样保存的标签字节
fn is_plain_name_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && byte != b'.' && byte != b'\\'
}

/// 请求的 EDNS 版本不受支持时的回答（RFC 6891 第 6.1.3 节）：RCODE 为 BADVERS（16：头部写低 4 位的
/// 0，OPT 里的扩展 RCODE 写 1），OPT 写 KixDNS 支持的版本 0，问题段照抄。请求读不出问题段时为 None。
/// The answer when the request's EDNS version is not supported (RFC 6891 section 6.1.3):
/// RCODE BADVERS (16: 0 in the header's low 4 bits, extended RCODE 1 in the OPT), an OPT
/// carrying version 0, the one KixDNS supports, and the question copied. None when the
/// question cannot be read.
pub fn badvers_response(query: &[u8]) -> Option<Bytes> {
    let question_end = skip_name(query, 12)?.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    let mut out = Vec::with_capacity(question_end + 11);
    out.extend_from_slice(&query[..2]);
    // QR、操作码 QUERY，照抄 RD；RA，照抄 CD / QR, opcode QUERY, RD copied; RA, CD copied
    out.push(0x80 | (query[2] & 0x01));
    out.push(0x80 | (query[3] & 0x10));
    // 一个问题、一条附加记录（OPT）/ One question, one additional record (the OPT)
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(&query[12..question_end]);
    // 根名、TYPE OPT、CLASS 即 UDP 载荷大小、扩展 RCODE 1、版本 0、标志 0
    // Root owner, TYPE OPT, CLASS as the UDP payload size, extended RCODE 1, version 0, flags 0
    out.push(0);
    out.extend_from_slice(&41u16.to_be_bytes());
    out.extend_from_slice(&1232u16.to_be_bytes());
    out.extend_from_slice(&[1, 0, 0, 0]);
    out.extend_from_slice(&0u16.to_be_bytes());
    Some(Bytes::from(out))
}

/// Whether `response` answers `query`: RFC 5452 §9.1 requires the question
/// section of a reply to match the query before the reply is accepted, in
/// addition to the ID and the source address. The name is compared ignoring
/// ASCII case so 0x20 case-randomizing upstreams still match; QTYPE and QCLASS
/// must be identical.
///
/// A reply with no question section is accepted only when it carries no
/// records at all (ANCOUNT, NSCOUNT and ARCOUNT all zero): some upstreams
/// answer FORMERR or NOTIMP that way, and such a reply cannot poison anything
/// because there is nothing in it to cache, so the fast failure is kept. A
/// reply that omits the question but carries records has no legitimate reason
/// to and is rejected.
/// Zero-copy: two name walks and a bounded byte comparison, no allocation.
/// 判断 `response` 是否应答 `query`：RFC 5452 §9.1 要求应答的 question 段与查询一致
/// 才能接受（ID 和源地址之外的第三道校验）。名称比较忽略 ASCII 大小写（兼容 0x20
/// 随机化的上游），QTYPE/QCLASS 必须相同。
///
/// 没有 question 段的应答仅在不携带任何记录（ANCOUNT/NSCOUNT/ARCOUNT 全为 0）时
/// 接受：有些上游对 FORMERR/NOTIMP 这样回，这种应答无记录可入缓存、无法投毒，
/// 保留它就保留了上游快速报错的路径；不回显 question 却带记录的应答没有正当理由，拒绝。
/// 零拷贝：两次名称遍历加一次有界字节比较，无分配。
pub(crate) fn question_matches(query: &[u8], response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }
    match u16::from_be_bytes([response[4], response[5]]) {
        0 => return response[6..12].iter().all(|&count| count == 0),
        1 => {}
        _ => return false,
    }
    let (Some(query_name_end), Some(response_name_end)) =
        (skip_name(query, 12), skip_name(response, 12))
    else {
        return false;
    };
    let query_end = query_name_end + 4;
    let response_end = response_name_end + 4;
    query_end <= query.len()
        && response_end <= response.len()
        && query_name_end == response_name_end
        && query[query_name_end..query_end] == response[response_name_end..response_end]
        && query[12..query_name_end].eq_ignore_ascii_case(&response[12..response_name_end])
}

/// 交给客户端的应答，按标准要求照抄查询的部分都照 `query` 写：问题名的写法（见
/// [`question_as_asked`]）、RD 和 CD 位（见 [`header_as_asked`]）、带不带 OPT 和 DO 位（见
/// [`edns_as_asked`]）。缓存里的、合并的在途查询拿到的应答都是别的客户端问的样子，KixDNS 自己
/// 构造的回答（静态回答、SERVFAIL）也不一定照抄了这些。什么都不用改时不复制。
/// The reply for a client, with what the standards have copied from the query
/// written as `query` has it: the question name's spelling (see
/// [`question_as_asked`]), the RD and CD bits (see [`header_as_asked`]), and whether an
/// OPT comes back and its DO bit (see [`edns_as_asked`]). An answer from the cache or
/// handed to a merged inflight query is shaped as another client asked, and answers
/// KixDNS builds itself (static answers, SERVFAIL) do not always copy these either.
/// Nothing is copied when nothing changes.
pub(crate) fn reply_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    edns_as_asked(
        header_as_asked(question_as_asked(reply, query), query),
        query,
    )
}

/// 应答的 RD 位（RFC 1035 第 4.1.1 节）和 CD 位（RFC 4035 第 3.2.2 节）照抄查询的
/// The reply with the query's RD bit (RFC 1035 section 4.1.1) and CD bit (RFC 4035
/// section 3.2.2)
fn header_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    if reply.len() < 12 || query.len() < 12 {
        return reply;
    }
    let (rd, cd) = (query[2] & 0x01, query[3] & 0x10);
    if reply[2] & 0x01 == rd && reply[3] & 0x10 == cd {
        return reply;
    }
    let mut copy = BytesMut::from(&reply[..]);
    copy[2] = (copy[2] & !0x01) | rd;
    copy[3] = (copy[3] & !0x10) | cd;
    copy.freeze()
}

/// 应答的 EDNS 跟着查询走（RFC 6891）：查询带 OPT，应答就带（第 6.1.1 节），没有时在末尾补一条；
/// 查询不带，应答就不带（第 7 节），有就去掉；DO 位照抄查询（RFC 3225 第 3 节）。应答的 OPT 带着
/// 扩展 RCODE 时不去掉，去掉就改了 RCODE；读不出的报文、TSIG 签过的应答原样返回。
/// The reply's EDNS following the query (RFC 6891): a query with an OPT gets one back
/// (section 6.1.1), appended when the reply has none; a query without gets none
/// (section 7), so one is taken out; the DO bit is the query's (RFC 3225 section 3).
/// An OPT carrying an extended RCODE stays, since taking it out would change the
/// RCODE; a message that cannot be read, or a reply signed with TSIG, is left as it is.
pub(crate) fn edns_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    let asked_dnssec_ok = match find_opt(query) {
        Ok(Some(opt)) => Some(query[opt.extended_rcode_at + 2] & 0x80 != 0),
        Ok(None) => None,
        Err(()) => return reply,
    };
    let Ok(opt) = find_opt(&reply) else {
        return reply;
    };
    let changed = match (asked_dnssec_ok, opt) {
        (Some(dnssec_ok), None) => with_opt(&reply, dnssec_ok),
        (Some(dnssec_ok), Some(opt)) => {
            let flags_at = opt.extended_rcode_at + 2;
            ((reply[flags_at] & 0x80 != 0) != dnssec_ok).then(|| {
                let mut copy = reply.to_vec();
                copy[flags_at] ^= 0x80;
                copy
            })
        }
        (None, Some(opt)) if reply[opt.extended_rcode_at] == 0 => without_opt(&reply, &opt),
        (None, _) => None,
    };
    changed.map_or(reply, Bytes::from)
}

/// 末尾补一条 OPT 的报文：根名、载荷大小 1232、扩展 RCODE 和版本 0、DO 位为 `dnssec_ok`、没有
/// 选项。读不出或最后一条是 TSIG（它必须排在最后）时为 None。
/// The message with an OPT appended: root owner, payload size 1232, extended RCODE and
/// version 0, the DO bit `dnssec_ok`, no options. None when it cannot be read or its
/// last record is a TSIG, which must stay last.
fn with_opt(message: &[u8], dnssec_ok: bool) -> Option<Vec<u8>> {
    let end = valid_message_len(message)?;
    if last_record_is_tsig(message) {
        return None;
    }
    let ar_count = u16::from_be_bytes([message[10], message[11]]).checked_add(1)?;
    let mut out = Vec::with_capacity(end + 11);
    out.extend_from_slice(&message[..end]);
    out.push(0);
    out.extend_from_slice(&41u16.to_be_bytes());
    out.extend_from_slice(&1232u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, if dnssec_ok { 0x80 } else { 0 }, 0]);
    out.extend_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&ar_count.to_be_bytes());
    Some(out)
}

/// 去掉 OPT 的报文。OPT 是最后一条记录时直接截掉（见 `OptRecord::last`），否则由 hickory 重新编码；
/// 读不了、写不出，或者最后一条是 TSIG 时为 None。
/// The message without its OPT: cut off when it is the last record (see
/// `OptRecord::last`), encoded again through hickory otherwise. None when it cannot be
/// read or written, or its last record is a TSIG.
fn without_opt(message: &[u8], opt: &OptRecord) -> Option<Vec<u8>> {
    if last_record_is_tsig(message) {
        return None;
    }
    if !opt.last {
        let mut msg = Message::from_vec(message).ok()?;
        msg.edns = None;
        return msg.to_vec().ok();
    }
    let ar_count = u16::from_be_bytes([message[10], message[11]]).checked_sub(1)?;
    let mut out = Vec::with_capacity(message.len());
    out.extend_from_slice(&message[..opt.start]);
    out[10..12].copy_from_slice(&ar_count.to_be_bytes());
    Some(out)
}

/// 应答的问题名照客户端发来的写法（RFC 1035 第 4.1.1 节：问题段由查询照抄）。两者忽略大小写
/// 相同（RFC 4343）而写法不同时，把查询里的名字抄进应答：缓存里存的、合并的在途查询拿到的
/// 都是别的客户端问的写法，静态回答写的是小写，有的上游也会改写大小写，而用 0x20 打乱大小写
/// 的客户端要核对它。名字不同、或者读不出不压缩的名字时原样返回；写法本来就一样时不复制。
/// The reply with its question name written as the client wrote it (RFC 1035 section
/// 4.1.1: the question is copied from the query). When the two are equal ignoring case
/// (RFC 4343) but written differently, the query's name is copied into the reply: a
/// cached answer or one handed to a merged inflight query carries another client's
/// spelling, a static answer is written in lowercase, some upstreams rewrite the case,
/// and a client randomizing the case (0x20) checks it. Another name, or one that cannot
/// be read uncompressed, leaves the reply as it is; so does the same spelling, uncopied.
pub(crate) fn question_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    let Some(end) = question_name_end(query) else {
        return reply;
    };
    let asked = &query[12..end];
    if question_name_end(&reply) != Some(end)
        || reply[12..end] == *asked
        || !reply[12..end].eq_ignore_ascii_case(asked)
    {
        return reply;
    }
    let mut copy = BytesMut::from(&reply[..]);
    copy[12..end].copy_from_slice(asked);
    copy.freeze()
}

/// 第一个问题名（不压缩，从偏移 12 开始）结束的位置；没有问题段时为 None
/// Where the first question name ends, written uncompressed from offset 12; None
/// without a question
fn question_name_end(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 || packet[4..6] == [0, 0] {
        return None;
    }
    let mut pos = 12;
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// 跳过 DNS 名称并返回下一个位置 / Skip DNS name and return next position
#[inline]
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let packet_len = packet.len();
    let mut encoded_end = None;
    let mut jumps = 0usize;

    loop {
        let len = *packet.get(pos)?;
        if len == 0 {
            return Some(encoded_end.unwrap_or(pos + 1));
        }
        if (len & 0xC0) == 0xC0 {
            let pointer_end = pos.checked_add(2)?;
            if pointer_end > packet_len {
                return None;
            }
            encoded_end.get_or_insert(pointer_end);
            let offset = (((len & 0x3F) as usize) << 8) | packet[pos + 1] as usize;
            // Only to a prior occurrence (RFC 1035 section 4.1.4), as in `parse_quick`
            // 只能指向前面出现过的名字（RFC 1035 第 4.1.4 节），同 `parse_quick`
            if offset >= pos {
                return None;
            }
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            pos = offset;
            continue;
        }
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }

        let next = pos.checked_add(1 + len as usize)?;
        if next > packet_len {
            return None;
        }
        pos = next;
    }
}

/// 报文里 OPT 记录的位置 / Where a message's OPT record sits
struct OptRecord {
    /// 记录开头（属主名）的偏移 / Offset of the record's start (its owner name)
    start: usize,
    /// 扩展 RCODE（TTL 字段的第一个字节）的偏移 / Offset of the extended RCODE (the TTL field's first byte)
    extended_rcode_at: usize,
    /// RDLENGTH 字段的偏移 / Offset of the RDLENGTH field
    rdlen_at: usize,
    /// RDATA（选项）的范围 / Range of the RDATA (the options)
    rdata: std::ops::Range<usize>,
    /// 是不是报文的最后一条记录。改动 OPT 的长度会挪动它后面的所有字节，后面记录里的压缩
    /// 指针可能因此指错地方，所以只改最后一条 OPT。
    /// Whether it is the message's last record. Changing the OPT's length moves
    /// every byte after it, and compression pointers in later records may then
    /// point to the wrong place, so only a last OPT is changed.
    last: bool,
}

/// 走到报文 Additional 段里的 OPT 记录。报文结构不对、OPT 不止一条或出现在 Additional
/// 以外时为 Err（RFC 6891 第 6.1.1 节：这样的报文是 FORMERR）。
/// Walk a message to the OPT record in its Additional section. Err when the
/// message is malformed, or has more than one OPT record or one outside
/// Additional (RFC 6891 section 6.1.1: such a message is FORMERR).
fn find_opt(packet: &[u8]) -> Result<Option<OptRecord>, ()> {
    if packet.len() < 12 {
        return Err(());
    }
    let count = |at: usize| u16::from_be_bytes([packet[at], packet[at + 1]]) as usize;
    let (qd_count, before_additional) = (count(4), count(6) + count(8));
    let ar_count = count(10);
    let mut pos = 12usize;
    for _ in 0..qd_count {
        pos = skip_name(packet, pos).ok_or(())?;
        pos = pos.checked_add(4).ok_or(())?;
    }
    let mut found = None;
    for index in 0..before_additional + ar_count {
        let start = pos;
        pos = skip_name(packet, pos).ok_or(())?;
        let fixed_end = pos.checked_add(10).ok_or(())?;
        if fixed_end > packet.len() {
            return Err(());
        }
        let rr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        let rdata_end = fixed_end.checked_add(rd_len).ok_or(())?;
        if rdata_end > packet.len() {
            return Err(());
        }
        if rr_type == 41 {
            if index < before_additional || found.is_some() {
                return Err(());
            }
            found = Some(OptRecord {
                start,
                extended_rcode_at: pos + 4,
                rdlen_at: pos + 8,
                rdata: fixed_end..rdata_end,
                last: index + 1 == before_additional + ar_count,
            });
        }
        pos = rdata_end;
    }
    Ok(found)
}

/// OPT 里的一个 ECS 选项 / An ECS option inside OPT
struct EcsOption {
    /// 整个选项（含代码和长度）的范围 / Range of the whole option, code and length included
    bytes: std::ops::Range<usize>,
    family: u16,
    source_prefix: u8,
    scope: u8,
    /// ADDRESS 的范围 / Range of the ADDRESS
    address: std::ops::Range<usize>,
}

impl EcsOption {
    /// 是否完全符合 RFC 7871 第 6 节：已知的地址族、前缀不超过地址长度、ADDRESS 恰好
    /// ceil(前缀/8) 个字节、前缀之后的位为零，SCOPE 也不超过地址长度。
    /// Whether it follows RFC 7871 section 6 to the letter: a known family, a
    /// prefix within the address length, an ADDRESS of exactly ceil(prefix/8)
    /// octets with zero bits beyond the prefix, and a SCOPE within the address
    /// length too.
    fn is_well_formed(&self, packet: &[u8]) -> bool {
        let bits = match self.family {
            1 => 32,
            2 => 128,
            _ => return false,
        };
        let address = &packet[self.address.clone()];
        let spare = self.source_prefix % 8;
        self.source_prefix <= bits
            && self.scope <= bits
            && address.len() == (self.source_prefix as usize).div_ceil(8)
            && (spare == 0
                || address
                    .last()
                    .is_some_and(|last| last & (0xFF >> spare) == 0))
    }

    fn subnet(&self, packet: &[u8]) -> crate::ecs::EcsKey {
        crate::ecs::EcsKey::from_wire(
            self.family,
            self.source_prefix,
            &packet[self.address.clone()],
        )
    }
}

/// OPT 的 RDATA 里的 ECS 选项（RFC 7871 第 6 节）。选项结构不对、或者不止一个 ECS 选项时为 Err。
/// The ECS option in an OPT record's RDATA (RFC 7871 section 6). Err when the
/// options are malformed or there is more than one ECS option.
fn ecs_option(packet: &[u8], rdata: std::ops::Range<usize>) -> Result<Option<EcsOption>, ()> {
    let mut found = None;
    let mut pos = rdata.start;
    while pos < rdata.end {
        let header_end = pos.checked_add(4).ok_or(())?;
        if header_end > rdata.end {
            return Err(());
        }
        let code = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        let end = header_end.checked_add(len).ok_or(())?;
        if end > rdata.end {
            return Err(());
        }
        if code == 8 {
            if len < 4 || found.is_some() {
                return Err(());
            }
            found = Some(EcsOption {
                bytes: pos..end,
                family: u16::from_be_bytes([packet[header_end], packet[header_end + 1]]),
                source_prefix: packet[header_end + 2],
                scope: packet[header_end + 3],
                address: header_end + 4..end,
            });
        }
        pos = end;
    }
    Ok(found)
}

/// 查询（OPT 的 RDATA 在 `rdata`）里客户端自己带的 ECS。不完全合规的选项得到
/// `EcsKey::opaque`：它照样会被原样转给上游，应答却说不准适用于谁。
/// The ECS a query carries itself, its OPT RDATA at `rdata`. An option that does
/// not follow the rules to the letter gets an `EcsKey::opaque`: it still goes
/// upstream as it is, but whom the answer applies to is unclear.
fn query_subnet(packet: &[u8], rdata: std::ops::Range<usize>) -> Option<crate::ecs::EcsKey> {
    match ecs_option(packet, rdata.clone()) {
        Ok(None) => None,
        Ok(Some(option)) if option.scope == 0 && option.is_well_formed(packet) => {
            Some(option.subnet(packet))
        }
        _ => Some(crate::ecs::EcsKey::opaque(&packet[rdata])),
    }
}

/// 查询报文里客户端自己带的 ECS（见 `query_subnet`）。报文读不出来时也按读不懂的选项算。
/// The ECS a query message carries itself (see `query_subnet`). A message that
/// cannot be read counts as an option that cannot be read too.
pub(crate) fn client_subnet(packet: &[u8]) -> Option<crate::ecs::EcsKey> {
    match find_opt(packet) {
        Ok(None) => None,
        Ok(Some(opt)) => query_subnet(packet, opt.rdata),
        Err(()) => Some(crate::ecs::EcsKey::opaque(packet)),
    }
}

/// 一次转发实际发给上游的 ECS / The ECS a forward actually sends upstream
pub(crate) fn sent_subnet(packet: &[u8]) -> crate::ecs_scope::Sent {
    client_subnet(packet).map_or(
        crate::ecs_scope::Sent::Absent,
        crate::ecs_scope::Sent::Subnet,
    )
}

/// 上游应答里的 ECS（RFC 7871 第 7.3 节据此决定应答适用于谁），以及上游是作答了（RCODE 为
/// NOERROR 或 NXDOMAIN）还是报错。
/// The ECS in an upstream's reply, which decides whom the answer applies to (RFC
/// 7871 section 7.3), and whether the upstream answered (RCODE NOERROR or
/// NXDOMAIN) rather than reported an error.
pub(crate) fn reply_ecs(reply: &[u8]) -> (crate::ecs_scope::ReplyEcs, bool) {
    use crate::ecs_scope::ReplyEcs;
    let rcode = reply.get(3).map_or(u8::MAX, |flags| flags & 0x0F);
    let Ok(opt) = find_opt(reply) else {
        return (ReplyEcs::Unreadable, false);
    };
    let Some(opt) = opt else {
        return (ReplyEcs::Absent, rcode == 0 || rcode == 3);
    };
    // 扩展 RCODE 不为 0（例如 BADVERS）就不是 NOERROR / A nonzero extended RCODE (BADVERS, say) is no NOERROR
    let answered = (rcode == 0 || rcode == 3) && reply[opt.extended_rcode_at] == 0;
    let ecs = match ecs_option(reply, opt.rdata) {
        Ok(None) => ReplyEcs::Absent,
        Ok(Some(option)) if option.is_well_formed(reply) => ReplyEcs::Subnet {
            subnet: option.subnet(reply),
            scope: option.scope,
        },
        _ => ReplyEcs::Unreadable,
    };
    (ecs, answered)
}

/// 去掉 ECS 选项后的应答：缓存的应答可能交给别的子网的请求方，不能带着原来那个请求方的
/// 子网。没有 ECS 选项时原样交回；报文或选项读不出来、或者 ECS 选项去不掉（OPT 后面还有
/// 记录，见 `OptRecord::last`）时以 Err 原样交回，这样的应答不缓存。
/// The reply without its ECS options: a cached reply may go to requesters in other
/// subnets and must not carry the subnet of the one it was fetched for. Handed
/// back as it is when it has none; handed back as it is in Err when the message
/// or its options cannot be read, or the ECS option cannot be taken out (records
/// follow the OPT, see `OptRecord::last`), and such a reply is not cached.
pub(crate) fn without_ecs(reply: Bytes) -> Result<Bytes, Bytes> {
    let opt = match find_opt(&reply) {
        Ok(Some(opt)) => opt,
        Ok(None) => return Ok(reply),
        Err(()) => return Err(reply),
    };
    if !opt.last {
        // Nothing to move round when there is no ECS option; otherwise see
        // `OptRecord::last`. A client that sent ECS gets its echo through hickory then
        // (see `echo_ecs`), so a reply hickory cannot read is not kept either: it would
        // go to such clients without an echo.
        // 没有 ECS 选项就不用挪动；否则见 `OptRecord::last`。这时带 ECS 的客户端要经 hickory
        // 拿到回显（见 `echo_ecs`），所以 hickory 读不了的应答也不保留：它会不带回显地交给
        // 这样的客户端。
        return match ecs_option(&reply, opt.rdata.clone()) {
            Ok(None) if Message::from_vec(&reply).is_ok() => Ok(reply),
            _ => Err(reply),
        };
    }
    match without_option(&reply, &opt, 8) {
        Ok(Some(out)) => Ok(Bytes::from(out)),
        Ok(None) => Ok(reply),
        Err(()) => Err(reply),
    }
}

/// 去掉 OPT 里代码为 `code` 的选项之后的报文。OPT 必须是最后一条记录（见 `OptRecord::last`）。
/// 没有这个选项时为 Ok(None)，选项结构不对时为 Err。
/// The message without the options coded `code` in its OPT, which must be the
/// last record (see `OptRecord::last`). Ok(None) when there is no such option,
/// Err when the options are malformed.
fn without_option(message: &[u8], opt: &OptRecord, code: u16) -> Result<Option<Vec<u8>>, ()> {
    debug_assert!(opt.last, "only a last OPT can change its length");
    let mut kept = Vec::new();
    let mut found = false;
    let mut pos = opt.rdata.start;
    while pos < opt.rdata.end {
        let end = pos
            .checked_add(4)
            .filter(|&header_end| header_end <= opt.rdata.end)
            .map(|header_end| {
                header_end + u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize
            })
            .filter(|&end| end <= opt.rdata.end)
            .ok_or(())?;
        if u16::from_be_bytes([message[pos], message[pos + 1]]) == code {
            found = true;
        } else {
            kept.push(pos..end);
        }
        pos = end;
    }
    if !found {
        return Ok(None);
    }
    let rd_len: usize = kept.iter().map(|option| option.len()).sum();
    let mut out = Vec::with_capacity(message.len());
    out.extend_from_slice(&message[..opt.rdata.start]);
    for option in kept {
        out.extend_from_slice(&message[option]);
    }
    out.extend_from_slice(&message[opt.rdata.end..]);
    out[opt.rdlen_at..opt.rdlen_at + 2].copy_from_slice(&(rd_len as u16).to_be_bytes());
    Ok(Some(out))
}

/// RFC 7873 的 COOKIE 选项代码 / The COOKIE option code of RFC 7873
const COOKIE: u16 = 10;

/// OPT 的 RDATA（在 `rdata`）里有没有代码为 `code` 的选项；选项结构不对时为 false
/// Whether the OPT RDATA at `rdata` has an option coded `code`; false when the
/// options are malformed
fn has_option(message: &[u8], rdata: std::ops::Range<usize>, code: u16) -> bool {
    let mut pos = rdata.start;
    while let Some(end) = pos
        .checked_add(4)
        .filter(|&header_end| header_end <= rdata.end)
        .map(|header_end| {
            header_end + u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize
        })
        .filter(|&end| end <= rdata.end)
    {
        if u16::from_be_bytes([message[pos], message[pos + 1]]) == code {
            return true;
        }
        pos = end;
    }
    false
}

/// 报文去掉 DNS cookie 之后的样子。没有 cookie，或者去不掉（OPT 后面还有记录、最后一条是
/// TSIG：改了签名就不对了；或者 hickory 读不了）时为 None。
/// The message without its DNS cookie. None when it has none, or when it cannot
/// be taken out: records follow the OPT and the last one is a TSIG, which a
/// change would invalidate, or hickory cannot read the message.
fn cookie_removed(message: &[u8]) -> Option<Vec<u8>> {
    let opt = find_opt(message).ok()??;
    if opt.last {
        return without_option(message, &opt, COOKIE).ok().flatten();
    }
    // 改 OPT 的长度会挪动它后面的记录（见 `OptRecord::last`），确有 cookie 时交给 hickory 重新编码
    // Changing the OPT's length would move the records after it (see
    // `OptRecord::last`), so hickory encodes the message again when a cookie is there
    if !has_option(message, opt.rdata, COOKIE) || last_record_is_tsig(message) {
        return None;
    }
    let mut msg = Message::from_vec(message).ok()?;
    msg.edns
        .as_mut()?
        .options_mut()
        .remove(hickory_proto::rr::rdata::opt::EdnsCode::Cookie);
    msg.to_vec().ok()
}

/// 发往上游的查询去掉 DNS cookie。cookie 只在相邻两跳之间有效（RFC 7873）：客户端的
/// cookie 是它和 KixDNS 之间的，转给上游的话，上游会把它带回来，随应答进缓存，再交给别的
/// 客户端。没有 cookie 或者去不掉时原样交回（见 `cookie_removed`）。
/// The query for an upstream without its DNS cookie. A cookie holds between two
/// neighbouring hops only (RFC 7873): a client's cookie belongs between it and
/// KixDNS, and forwarded it comes back from the upstream, enters the cache with
/// the answer and goes to other clients. Handed back as it is when it has none or
/// the cookie cannot be taken out (see `cookie_removed`).
pub(crate) fn query_without_cookie(query: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    cookie_removed(query).map_or(std::borrow::Cow::Borrowed(query), std::borrow::Cow::Owned)
}

/// 上游应答去掉 DNS cookie。KixDNS 不发也不核对自己的 cookie，应答里的 cookie 只可能是上游
/// 自己塞的（查询已经不带了），不该进缓存、也不该交给客户端。去不掉时原样交回。
/// An upstream reply without its DNS cookie. KixDNS neither sends nor checks a
/// cookie of its own, so one in a reply can only be the upstream's own addition
/// (queries no longer carry any), which belongs neither in the cache nor in a
/// client's reply. Handed back as it is when it cannot be taken out.
pub(crate) fn reply_without_cookie(reply: Bytes) -> Bytes {
    cookie_removed(&reply).map_or(reply, Bytes::from)
}

/// 给缓存里的应答换上回显客户端自己 ECS 的选项，作用范围为 `scope`（RFC 7871 第 7.2.2 节：
/// 查询带 ECS，应答就要带），取代它原有的 ECS 选项；应答没有 OPT 时补一条。报文读不出来、
/// OPT 后面还有记录（见 `OptRecord::last`），或者最后一条记录是 TSIG（OPT 不能排在它后面）
/// 时为 None。
/// Give a cached reply an option echoing the client's own ECS with `scope`
/// (RFC 7871 section 7.2.2: a query with ECS gets a reply with it), in place of
/// any ECS option it has, adding an OPT record when the reply has none. None
/// when the message cannot be read, records follow its OPT (see
/// `OptRecord::last`), or its last record is a TSIG, which OPT may not follow.
pub(crate) fn with_ecs_echo(
    stored: &[u8],
    subnet: &crate::ecs::EcsKey,
    scope: u8,
) -> Option<Vec<u8>> {
    let address = &subnet.addr[..subnet.addr_len as usize];
    let mut option = Vec::with_capacity(8 + address.len());
    option.extend_from_slice(&8u16.to_be_bytes());
    option.extend_from_slice(&(4 + address.len() as u16).to_be_bytes());
    option.extend_from_slice(&subnet.family.to_be_bytes());
    option.push(subnet.source_prefix);
    option.push(scope);
    option.extend_from_slice(address);

    match find_opt(stored).ok()? {
        // See `OptRecord::last` / 见 `OptRecord::last`
        Some(opt) if !opt.last => None,
        Some(opt) => {
            // 已有的 ECS 选项换成这一个 / An ECS option already there is replaced by this one
            let kept = match ecs_option(stored, opt.rdata.clone()).ok()? {
                Some(existing) => existing.bytes,
                None => opt.rdata.end..opt.rdata.end,
            };
            let rd_len = u16::try_from(opt.rdata.len() - kept.len() + option.len()).ok()?;
            let mut out = Vec::with_capacity(stored.len() + option.len());
            out.extend_from_slice(&stored[..kept.start]);
            out.extend_from_slice(&stored[kept.end..opt.rdata.end]);
            out.extend_from_slice(&option);
            out.extend_from_slice(&stored[opt.rdata.end..]);
            out[opt.rdlen_at..opt.rdlen_at + 2].copy_from_slice(&rd_len.to_be_bytes());
            Some(out)
        }
        None => {
            let end = valid_message_len(stored)?;
            if last_record_is_tsig(stored) {
                return None;
            }
            let ar_count = u16::from_be_bytes([stored[10], stored[11]]).checked_add(1)?;
            let mut out = Vec::with_capacity(end + 11 + option.len());
            out.extend_from_slice(&stored[..end]);
            // 根名、TYPE OPT、CLASS 即 UDP 载荷大小、扩展 RCODE 与标志全 0
            // Root owner, TYPE OPT, CLASS as the UDP payload size, extended RCODE and flags all 0
            out.push(0);
            out.extend_from_slice(&41u16.to_be_bytes());
            out.extend_from_slice(&1232u16.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&(option.len() as u16).to_be_bytes());
            out.extend_from_slice(&option);
            out[10..12].copy_from_slice(&ar_count.to_be_bytes());
            Some(out)
        }
    }
}

/// 同 `with_ecs_echo`，它不肯改写时（OPT 后面还有记录）改由 hickory 读出整个报文、换上回显
/// 再重新编码（OPT 放到最后）。读不了、写不出，或者最后一条记录是 TSIG 时为 None。
/// As `with_ecs_echo`, falling back, where that declines (records after the OPT),
/// to reading the whole message with hickory, setting the echo and encoding it
/// again (OPT last). None when it cannot be read or written, or its last record
/// is a TSIG.
pub(crate) fn echo_ecs(stored: &[u8], subnet: &crate::ecs::EcsKey, scope: u8) -> Option<Vec<u8>> {
    with_ecs_echo(stored, subnet, scope).or_else(|| rewrite_ecs(stored, Some((subnet, scope))))
}

/// 应答去掉 ECS 选项后交给客户端：`without_ecs` 去不掉时（OPT 后面还有记录）改由 hickory
/// 重新编码。都不行时原样交回。
/// The reply without its ECS option, for a client: where `without_ecs` cannot take
/// it out (records after the OPT), hickory encodes it again. Handed back as it is
/// when neither can.
pub(crate) fn ecs_removed(reply: Bytes) -> Bytes {
    without_ecs(reply).unwrap_or_else(|kept| rewrite_ecs(&kept, None).map_or(kept, Bytes::from))
}

/// 用 hickory 改写报文里的 ECS 选项：`echo` 为 Some 时换成这个回显，None 时去掉
/// Rewrite a message's ECS option through hickory: the echo `echo` names, or none
fn rewrite_ecs(message: &[u8], echo: Option<(&crate::ecs::EcsKey, u8)>) -> Option<Vec<u8>> {
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    if last_record_is_tsig(message) {
        return None;
    }
    let mut msg = Message::from_vec(message).ok()?;
    match echo {
        Some((subnet, scope)) => {
            let address = subnet.ip()?;
            let edns = msg.edns.get_or_insert_with(|| {
                let mut edns = hickory_proto::op::Edns::new();
                edns.set_max_payload(1232);
                edns
            });
            edns.options_mut().remove(EdnsCode::Subnet);
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    address,
                    subnet.source_prefix,
                    scope,
                )));
        }
        None => {
            msg.edns.as_mut()?.options_mut().remove(EdnsCode::Subnet);
        }
    }
    msg.to_vec().ok()
}

/// 报文最后一条记录是不是 TSIG（RFC 8945 要求它排在最后）
/// Whether a message's last record is a TSIG (RFC 8945 keeps it last)
fn last_record_is_tsig(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        return false;
    }
    let count = |at: usize| u16::from_be_bytes([packet[at], packet[at + 1]]) as usize;
    let mut pos = 12usize;
    for _ in 0..count(4) {
        let Some(next) = skip_name(packet, pos) else {
            return false;
        };
        pos = next + 4;
    }
    let mut last_type = None;
    for _ in 0..count(6) + count(8) + count(10) {
        let Some(next) = skip_name(packet, pos) else {
            return false;
        };
        if next + 10 > packet.len() {
            return false;
        }
        last_type = Some(u16::from_be_bytes([packet[next], packet[next + 1]]));
        pos = next + 10 + u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
    }
    last_type == Some(250)
}

/// Byte length of the last complete record, or `None` on malformed structure.
///
/// hickory's bounded encoder rolls back its write offset but not the backing
/// buffer when a record does not fit, so truncated output can carry partial
/// bytes from the failed record past the (corrected) header counts. Re-walking
/// the emitted sections yields the exact valid boundary so the response stays
/// within RFC 1035 §4.2.1 record boundaries.
fn valid_message_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut pos = 12usize;
    // Questions: NAME + QTYPE + QCLASS.
    for _ in 0..qd_count {
        pos = skip_name(packet, pos)?;
        pos = pos.checked_add(4)?;
    }
    // Resource records: NAME + TYPE/CLASS/TTL/RDLENGTH + RDATA.
    for _ in 0..an_count + ns_count + ar_count {
        pos = skip_name(packet, pos)?;
        let fixed_end = pos.checked_add(10)?;
        if fixed_end > packet.len() {
            return None;
        }
        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos = fixed_end.checked_add(rd_len)?;
    }
    (pos <= packet.len()).then_some(pos)
}

fn validate_edns_options(packet: &[u8], mut pos: usize, end: usize) -> Option<()> {
    while pos < end {
        let header_end = pos.checked_add(4)?;
        if header_end > end {
            return None;
        }
        let option_len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        pos = header_end.checked_add(option_len)?;
        if pos > end {
            return None;
        }
    }
    (pos == end).then_some(())
}

impl QuickQuery<'_> {
    /// 检查 qname 是否匹配指定的域名（忽略大小写）
    /// Check if qname matches the specified domain name (case-insensitive)
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false, edns_version: 0, client_subnet: None, flags: Default::default() };
    /// assert!(query.qname_matches("google.com"));  // 完全匹配
    /// assert!(query.qname_matches("GOOGLE.COM"));  // 大写匹配
    /// assert!(!query.qname_matches("example.com"));  // 不匹配
    /// ```
    ///
    /// # Performance
    /// This function is optimized for hot path usage:
    /// - No allocation / 无分配
    /// - Early exit on length mismatch / 长度不匹配时提前退出
    /// - Byte-by-byte comparison with ASCII lowercasing / 逐字节比较并转为小写
    #[inline]
    pub fn qname_matches(&self, pattern: &str) -> bool {
        // Fast path: length check / 快速路径：长度检查
        if self.qname_bytes.len() != pattern.len() {
            return false;
        }

        // Byte-by-byte comparison with ASCII lowercasing / 逐字节比较并转为小写
        // qname_bytes is already lowercased from parse_quick() / qname_bytes 在 parse_quick() 中已经转为小写
        // So we only need to lowercase the pattern bytes / 所以我们只需要将 pattern 字节转为小写
        self.qname_bytes
            .iter()
            .zip(pattern.as_bytes())
            .all(|(a, b)| *a == b.to_ascii_lowercase())
    }

    /// 获取 qname 的字符串表示（用于调试和日志）
    /// Get string representation of qname (for debugging and logging)
    ///
    /// # Performance Warning
    /// This function allocates a new String. Use sparingly in hot paths.
    /// 此函数分配新的 String。在热路径中谨慎使用。
    ///
    /// # Safety
    /// qname_bytes is guaranteed to be valid ASCII (and thus UTF-8) by parse_quick().
    /// parse_quick() validates ASCII before returning QuickQuery.
    /// ASCII is always valid UTF-8, so from_utf8_unchecked is safe.
    /// qname_bytes 由 parse_quick() 保证为有效的 ASCII（因此也是 UTF-8）。
    /// parse_quick() 在返回 QuickQuery 之前验证 ASCII。
    /// ASCII 始终是有效的 UTF-8，所以 from_utf8_unchecked 是安全的。
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false, edns_version: 0, client_subnet: None, flags: Default::default() };
    /// println!("qname: {}", query.qname_str());  // "google.com"
    /// ```
    #[inline]
    pub fn qname_str(&self) -> String {
        // SAFETY: qname_bytes is validated ASCII from parse_quick()
        // ASCII is always valid UTF-8
        // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
        // ASCII 始终是有效的 UTF-8
        //
        // In debug builds, we validate to catch any issues early
        // 在 debug 构建中，我们验证以尽早发现问题
        #[cfg(debug_assertions)]
        {
            std::str::from_utf8(self.qname_bytes)
                .expect("qname_bytes should be valid UTF-8")
                .to_string()
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            std::str::from_utf8_unchecked(self.qname_bytes).to_string()
        }
    }

    /// 获取 qname 的 &str 表示（零分配，但受生命周期限制）
    /// Get &str representation of qname (zero-allocation, but lifetime-bound)
    ///
    /// # Performance
    /// This is the preferred method for string operations in hot paths.
    /// 这是热路径中字符串操作的首选方法。
    ///
    /// # Safety
    /// qname_bytes is guaranteed to be valid ASCII (and thus UTF-8) by parse_quick().
    /// parse_quick() validates ASCII before returning QuickQuery.
    /// If parse_quick() succeeds, qname_bytes is always valid ASCII/UTF-8.
    /// In debug builds, we validate to catch any issues early.
    /// qname_bytes 由 parse_quick() 保证为有效的 ASCII（因此也是 UTF-8）。
    /// parse_quick() 在返回 QuickQuery 之前验证 ASCII。
    /// 如果 parse_quick() 成功，qname_bytes 始终是有效的 ASCII/UTF-8。
    /// 在 debug 构建中，我们验证以尽早发现问题。
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false, edns_version: 0, client_subnet: None, flags: Default::default() };
    /// let qname_str = query.qname_str_unchecked();  // &str
    /// ```
    #[inline]
    pub fn qname_str_unchecked(&self) -> &str {
        // SAFETY: qname_bytes is validated ASCII from parse_quick()
        // ASCII is always valid UTF-8
        // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
        // ASCII 始终是有效的 UTF-8
        //
        // In debug builds, we validate to catch any issues early
        // 在 debug 构建中，我们验证以尽早发现问题
        #[cfg(debug_assertions)]
        {
            std::str::from_utf8(self.qname_bytes).expect("qname_bytes should be valid UTF-8")
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            std::str::from_utf8_unchecked(self.qname_bytes)
        }
    }

    /// 获取 qname 的哈希值（用于缓存键计算）
    /// Get hash value of qname (for cache key calculation)
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false, edns_version: 0, client_subnet: None, flags: Default::default() };
    /// let hash = query.qname_hash();
    /// ```
    #[inline]
    pub fn qname_hash(&self) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        h.write(self.qname_bytes);
        h.finish()
    }
}

/// 快速解析响应包，仅提取 RCODE、TC 标志和 TTL 范围 / Quick parse response packet, extracting only RCODE, TC flag and TTL range
/// 避免全量解析 Message / Avoid full Message parsing
#[derive(Debug, Clone)]
pub struct QuickResponse {
    pub rcode: hickory_proto::op::ResponseCode,
    pub min_ttl: u32,
    /// 最大 TTL，用于后台刷新触发决策 / Maximum TTL, used for background refresh trigger decision
    pub max_ttl: u32,
    /// TC (Truncated) flag - 响应被截断，应使用 TCP 重试 / Response was truncated, retry with TCP
    #[allow(dead_code)]
    pub truncated: bool,
}

/// Extract negative caching TTL from SOA in the authority section at the wire level (RFC 2308 §5).
/// Returns min(SOA.minimum, SOA.record_ttl), or None if no SOA is found or parsing fails.
/// This avoids a full `Message::from_bytes` parse for the common negative-response path.
///
/// 在 wire 层级从 authority 的 SOA 记录提取负缓存 TTL (RFC 2308 §5)。
/// 返回 min(SOA.minimum, SOA.record_ttl)，无 SOA 或解析失败时返回 None。
/// 避免对常见的否定响应路径进行完整的 `Message::from_bytes` 解析。
///
/// SAFETY: Reads raw DNS wire format. All bounds are checked. Returns None on any parse error.
/// 安全性：读取原始 DNS wire 格式。所有边界均已检查。解析错误时返回 None。
fn extract_soa_negative_ttl_wire(packet: &[u8], qd_count: u16, ns_count: u16) -> Option<u32> {
    let packet_len = packet.len();
    let mut pos = 12usize; // Start after header / 从 header 之后开始

    // Skip Question section / 跳过 Question 部分
    for _ in 0..qd_count {
        pos = skip_dns_name_wire(packet, pos)?;
        pos += 4; // QTYPE(2) + QCLASS(2)
        if pos > packet_len {
            return None;
        }
    }

    // Walk Authority section looking for SOA (type 6) / 遍历 Authority 部分查找 SOA (type 6)
    for _ in 0..ns_count {
        pos = skip_dns_name_wire(packet, pos)?;
        if pos + 10 > packet_len {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

        if rtype == 6 {
            // SOA record found — extract MINIMUM field from rdata
            // SOA rdata: MNAME RNAME SERIAL(4) REFRESH(4) RETRY(4) EXPIRE(4) MINIMUM(4)
            // SOA 记录 — 从 rdata 提取 MINIMUM 字段
            let rdata_end = pos + rdlength;
            if rdata_end > packet_len {
                return None;
            }
            // Skip MNAME (domain name in rdata, may use compression pointers)
            // 跳过 MNAME（rdata 中的域名，可能使用压缩指针）
            let after_mname = skip_dns_name_wire(packet, pos)?;
            // Skip RNAME (domain name in rdata)
            // 跳过 RNAME（rdata 中的域名）
            let after_rname = skip_dns_name_wire(packet, after_mname)?;
            // 5 × u32 = 20 bytes: SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
            let fixed_fields_start = after_rname;
            if fixed_fields_start + 20 > rdata_end {
                return None;
            }
            // MINIMUM is the last 4 bytes of the fixed fields
            // MINIMUM 是固定字段的最后 4 字节
            let minimum = u32::from_be_bytes([
                packet[fixed_fields_start + 16],
                packet[fixed_fields_start + 17],
                packet[fixed_fields_start + 18],
                packet[fixed_fields_start + 19],
            ]);
            // RFC 2308 §5: negative TTL = min(SOA.minimum, SOA.ttl)
            return Some(minimum.min(ttl));
        }

        // Skip rdata for non-SOA records / 跳过非 SOA 记录的 rdata
        pos += rdlength;
    }

    None
}

/// Skip a DNS name at the given position, following compression pointers.
/// Returns the position after the name, or None on parse error.
///
/// 跳过指定位置的 DNS 名称，处理压缩指针。
/// 返回名称之后的位置，解析错误时返回 None。
#[inline]
fn skip_dns_name_wire(packet: &[u8], mut pos: usize) -> Option<usize> {
    let packet_len = packet.len();
    loop {
        if pos >= packet_len {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes total / 压缩指针：共 2 字节
            if pos + 2 > packet_len {
                return None;
            }
            return Some(pos + 2);
        }
        // Regular label / 常规标签
        let jump = 1 + len as usize;
        if pos + jump > packet_len {
            return None;
        }
        pos += jump;
    }
}

pub fn parse_response_quick(packet: &[u8]) -> Option<QuickResponse> {
    if packet.len() < 12 {
        return None;
    }

    // 1. Flags (Byte 2-3) / 标志位（字节 2-3）
    // Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
    // Byte 3: RA(1) Z(3) RCODE(4)
    let flags_byte2 = packet[2];
    let truncated = (flags_byte2 & 0x02) != 0; // TC bit at position 1

    let rcode_u8 = packet[3] & 0x0F;
    let rcode = hickory_proto::op::ResponseCode::from(0, rcode_u8);

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    // We don't strictly need NS and AR counts for TTL, but we iterate through them if we want to be thorough. / 对于 TTL，我们并不严格需要 NS 和 AR 计数，但如果想彻底，可以遍历它们
    // For caching, we usually care about Answer section TTLs. / 对于缓存，我们通常关心 Answer 部分的 TTL

    if an_count == 0 {
        // RFC 2308 §5: For negative responses (NXDOMAIN/NODATA), the negative
        // cache TTL is min(SOA.minimum, SOA.ttl) from the authority section.
        // If no SOA is present, return TTL=0 (must not be cached per RFC 2308 §4).
        //
        // RFC 2308 §5: 对于否定响应 (NXDOMAIN/NODATA)，负缓存 TTL 为 authority 中
        // SOA 的 min(SOA.minimum, SOA.ttl)。无 SOA 时返回 TTL=0（按 RFC 2308 §4 不可缓存）。
        if ns_count > 0
            && let Some(neg_ttl) = extract_soa_negative_ttl_wire(packet, qd_count, ns_count)
        {
            return Some(QuickResponse {
                rcode,
                min_ttl: neg_ttl,
                max_ttl: neg_ttl,
                truncated,
            });
        }
        return Some(QuickResponse {
            rcode,
            min_ttl: 0,
            max_ttl: 0,
            truncated,
        });
    }

    let mut pos = 12;
    let packet_len = packet.len();

    // Skip Questions / 跳过问题部分
    for _ in 0..qd_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len {
                return None;
            }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 2 > packet_len {
                    return None;
                }
                pos += 2;
                break;
            }
            let jump_len = 1 + (len as usize);
            if pos + jump_len > packet_len {
                return None;
            }
            pos += jump_len;
        }
        // Skip Type(2) + Class(2) / 跳过类型(2) + 类别(2)
        if pos + 4 > packet_len {
            return None;
        }
        pos += 4;
    }

    let mut min_ttl = u32::MAX;
    let mut max_ttl = u32::MIN;

    // Scan Answers / 扫描应答部分
    for _ in 0..an_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len {
                return None;
            }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 2 > packet_len {
                    return None;
                }
                pos += 2;
                break;
            }
            let jump_len = 1 + (len as usize);
            if pos + jump_len > packet_len {
                return None;
            }
            pos += jump_len;
        }

        if pos + 10 > packet_len {
            return None;
        }

        // Type(2) Class(2) TTL(4) RDLen(2) / 类型(2) 类别(2) TTL(4) 数据长度(2)
        // Offset 0: Type / 偏移量 0：类型
        // Offset 2: Class / 偏移量 2：类别
        // Offset 4: TTL / 偏移量 4：TTL
        // Offset 8: RDLen / 偏移量 8：数据长度

        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        if ttl < min_ttl {
            min_ttl = ttl;
        }
        if ttl > max_ttl {
            max_ttl = ttl;
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rd_len;
    }

    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    if max_ttl == u32::MIN {
        max_ttl = 0;
    }

    Some(QuickResponse {
        rcode,
        min_ttl,
        max_ttl,
        truncated,
    })
}

/// Whether a DNS message is a response with the TC (truncated) bit set. TC only means
/// something in a response, so a message without QR is never truncated.
/// DNS 报文是否是带 TC（截断）位的应答。TC 只在应答里有意义，所以没有 QR 位的报文不算截断。
pub fn truncated_response(message: &[u8]) -> bool {
    message
        .get(2)
        .is_some_and(|flags| flags & 0x80 != 0 && flags & 0x02 != 0)
}

/// Re-encode an oversized downstream UDP response so it respects the payload size
/// advertised by the client (RFC 6891). Queries without EDNS are limited to the
/// classic 512-byte DNS/UDP payload.
///
/// Hickory's bounded encoder emits as many complete records as fit, fixes the
/// section counts, and sets TC=1 when records are omitted. `None` means the
/// original response already fits and can be sent without allocation.
///
/// Trade-off: oversized responses (>512B, or > the client EDNS payload) are
/// re-parsed and re-encoded on every send. This is intentional — truncation
/// must happen at DNS record boundaries (RFC 1035 §4.2.1) and the correct TC
/// bit + counts can only be produced by a full re-encode. The overwhelmingly
/// common small-response path returns `None` before any parsing, so the cost
/// only applies to responses that would otherwise break the UDP size limit.
///
/// 权衡：超限响应（>512B 或超过客户端 EDNS 载荷）每次发送都会重新解析并重编码。
/// 这是有意的——截断必须发生在 DNS 记录边界（RFC 1035 §4.2.1），且正确的 TC 位
/// 和计数只能由完整重编码产生。绝大多数小响应路径在解析前就返回 None，因此该
/// 开销只作用于那些会突破 UDP 大小限制的响应。
pub fn truncate_udp_response(request_packet: &[u8], response_packet: &[u8]) -> Option<Bytes> {
    const CLASSIC_DNS_UDP_PAYLOAD: usize = 512;

    // Avoid parsing the request on the overwhelmingly common small-response path.
    if response_packet.len() <= CLASSIC_DNS_UDP_PAYLOAD {
        return None;
    }

    // hickory's Message::max_payload() already clamps to >= 512, so the extra
    // max() below is defensive only.
    let max_payload = Message::from_bytes(request_packet)
        .map(|request| request.max_payload() as usize)
        .unwrap_or(CLASSIC_DNS_UDP_PAYLOAD)
        .max(CLASSIC_DNS_UDP_PAYLOAD);

    if response_packet.len() <= max_payload {
        return None;
    }

    if let Ok(mut response) = Message::from_bytes(response_packet) {
        // Do not advertise a larger UDP payload in the response than the client
        // offered in its request.
        if let Some(edns) = response.edns.as_mut() {
            edns.set_max_payload(max_payload as u16);
        }

        let mut out = Vec::with_capacity(max_payload);
        let encoded = {
            let mut encoder = BinEncoder::new(&mut out);
            encoder.set_max_size(max_payload as u16);
            response.emit(&mut encoder)
        };
        if encoded.is_ok() && out.len() <= max_payload {
            // hickory's rollback does not shrink the backing buffer, so the
            // output can carry partial bytes from the record that did not fit.
            // Trim to the last complete record boundary from the corrected
            // header counts; fall back to the raw output if the walk fails.
            if let Some(valid_len) = valid_message_len(&out) {
                out.truncate(valid_len);
            }
            return Some(Bytes::from(out));
        }
    }

    // Internal responses should always parse, but never send an oversized UDP
    // datagram if a malformed response reaches this boundary. Fall back to a
    // minimal TC=1 response containing the original Question section.
    Some(build_minimal_truncated_response(
        request_packet,
        response_packet,
        max_payload,
    ))
}

fn build_minimal_truncated_response(
    request_packet: &[u8],
    response_packet: &[u8],
    max_payload: usize,
) -> Bytes {
    let mut question_end = 12usize;
    let mut copied_questions = false;

    if request_packet.len() >= 12 {
        let qd_count = u16::from_be_bytes([request_packet[4], request_packet[5]]);
        let mut pos = 12usize;
        let mut valid = true;
        for _ in 0..qd_count {
            let Some(name_end) = skip_name(request_packet, pos) else {
                valid = false;
                break;
            };
            let Some(next) = name_end.checked_add(4) else {
                valid = false;
                break;
            };
            if next > request_packet.len() {
                valid = false;
                break;
            }
            pos = next;
        }
        if valid && pos <= max_payload {
            question_end = pos;
            copied_questions = true;
        }
    }

    let header_source = if response_packet.len() >= 12 {
        response_packet
    } else {
        request_packet
    };
    let mut out = if header_source.len() >= 12 {
        header_source[..12].to_vec()
    } else {
        vec![0u8; 12]
    };

    // QR=1 and TC=1; preserve the remaining response flags and RCODE.
    out[2] |= 0x82;
    if copied_questions {
        out[4..6].copy_from_slice(&request_packet[4..6]);
        out.extend_from_slice(&request_packet[12..question_end]);
    } else {
        out[4..6].copy_from_slice(&0u16.to_be_bytes());
    }
    out[6..12].fill(0);
    Bytes::from(out)
}

/// Saturating conversion for DNS TTLs and elapsed seconds.
/// DNS TTL fields are u32, while Duration and configuration calculations use u64.
#[inline]
pub fn saturating_u64_to_u32(value: u64) -> u32 {
    value.min(u32::MAX as u64) as u32
}

/// 批量修正 DNS 响应包中的 TTL 值 / Batch patch TTL values in a DNS response packet
/// decrement: 需要减少的秒数 / seconds to decrement
pub fn patch_all_ttls(packet: &mut [u8], decrement: u32) {
    if decrement == 0 {
        return;
    }
    // RFC 1035: Decrement TTL, floor at 0
    map_record_ttls(packet, |ttl| ttl.saturating_sub(decrement));
}

/// Set all record TTLs in a DNS packet to an absolute value.
/// Used by RFC 8767 stale serving to set TTL to serve_stale_ttl.
/// 将 DNS 报文中所有记录的 TTL 设为绝对值。
/// 用于 RFC 8767 stale 服务，将 TTL 设置为 serve_stale_ttl。
pub fn set_all_ttls(packet: &mut [u8], new_ttl: u32) {
    map_record_ttls(packet, |_| new_ttl);
}

/// 上游应答的每条记录 TTL 都收进 `floor..=cap`，两者冲突时以 `cap` 为准。只有一处持有这份应答时
/// 原地改写，不复制。最后一条是 TSIG 的应答原样交回：改了签名就不对了。
/// An upstream reply with the TTL of every record brought into `floor..=cap`,
/// `cap` winning when the two cross. Rewritten in place, uncopied, when nothing
/// else holds the reply. A reply whose last record is a TSIG is handed back as it
/// is, since a change would invalidate the signature.
pub(crate) fn reply_within_ttls(reply: Bytes, floor: u32, cap: u32) -> Bytes {
    if last_record_is_tsig(&reply) {
        return reply;
    }
    let mut reply = BytesMut::from(reply);
    map_record_ttls(&mut reply, |ttl| ttl.max(floor).min(cap));
    reply.freeze()
}

/// 用 `f` 改写报文里每条记录的 TTL；遇到放不下的记录就停。OPT（类型 41）伪记录跳过：它的 TTL
/// 字段装的是 EDNS 扩展 RCODE 和标志（包括 DO 位），不是 TTL。
/// Rewrites the TTL of every record in `packet` with `f`, stopping at the first
/// record that does not fit. OPT (type 41) pseudo-records are skipped: their TTL
/// field holds the EDNS extended RCODE and flags (the DO bit among them), not a TTL.
fn map_record_ttls(packet: &mut [u8], mut f: impl FnMut(u32) -> u32) {
    if packet.len() < 12 {
        return;
    }

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

    let mut pos = 12;
    let packet_len = packet.len();

    // 1. Skip Questions
    for _ in 0..qd_count {
        if let Some(next) = skip_name(packet, pos) {
            pos = next + 4;
        } else {
            return;
        }
    }

    // 2. Answer, Authority, and Additional sections
    let total_records = an_count as usize + ns_count as usize + ar_count as usize;
    for _ in 0..total_records {
        if let Some(next) = skip_name(packet, pos) {
            pos = next;
        } else {
            return;
        }

        if pos + 10 > packet_len {
            return;
        }

        // Type(2) Class(2) TTL(4) RDLen(2)
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        if rtype != 41 {
            let ttl_offset = pos + 4;
            let old_ttl = u32::from_be_bytes([
                packet[ttl_offset],
                packet[ttl_offset + 1],
                packet[ttl_offset + 2],
                packet[ttl_offset + 3],
            ]);
            packet[ttl_offset..ttl_offset + 4].copy_from_slice(&f(old_ttl).to_be_bytes());
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;

        // Ensure the entire record (10 bytes header + RData) fits within remaining packet
        // and handle potential overflow for the next iteration's position
        let record_total_len = 10usize.saturating_add(rd_len);
        if pos.saturating_add(record_total_len) > packet_len {
            return;
        }

        pos += record_total_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个回答：两条 A 记录（TTL 5 和 100000），外加一条带 DO 位的 OPT
    /// An answer of two A records (TTLs 5 and 100000) and an OPT with the DO bit set
    fn answer_with_ttls_and_opt() -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::str::FromStr;
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for (ttl, last) in [(5, 1), (100_000, 2)] {
            msg.add_answer(Record::from_rdata(
                name.clone(),
                ttl,
                RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, last)),
            ));
        }
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
        msg.to_vec().unwrap()
    }

    #[test]
    fn reply_within_ttls_brings_every_record_in_and_leaves_opt_alone() {
        let ttls = |bytes: &[u8]| {
            let msg = Message::from_vec(bytes).unwrap();
            let dnssec_ok = msg.edns.as_ref().unwrap().flags().dnssec_ok;
            (
                msg.answers.iter().map(|r| r.ttl).collect::<Vec<_>>(),
                dnssec_ok,
            )
        };
        let answer = Bytes::from(answer_with_ttls_and_opt());
        assert_eq!(
            ttls(&reply_within_ttls(answer.clone(), 60, 3600)),
            (vec![60, 3600], true)
        );
        // 两者冲突时以上限为准 / The cap wins when the two cross
        assert_eq!(
            ttls(&reply_within_ttls(answer.clone(), 600, 300)),
            (vec![300, 300], true)
        );
        assert_eq!(
            ttls(&reply_within_ttls(answer, 0, u32::MAX)),
            (vec![5, 100_000], true)
        );
    }

    #[test]
    fn reply_within_ttls_leaves_a_signed_reply_alone() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::str::FromStr;
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            5,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
        ));
        let mut signed = msg.to_vec().unwrap();
        // 末尾一条 TSIG（根名、类型 250、类别 ANY、TTL 0、空 RDATA）
        // A trailing TSIG (root name, type 250, class ANY, TTL 0, empty RDATA)
        signed[11] = 1;
        signed.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
        let reply = Bytes::from(signed);
        assert_eq!(reply_within_ttls(reply.clone(), 60, 3600), reply);
    }

    fn query_with_label(label: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        packet
    }

    #[test]
    fn parse_quick_rejects_qname_control_characters() {
        let packet = query_with_label(b"bad\nlabel");
        let mut qname = [0u8; 256];

        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_accepts_regular_ascii_qname() {
        let packet = query_with_label(b"example");
        let mut qname = [0u8; 256];

        assert!(parse_quick(&packet, &mut qname).is_some());
    }

    #[test]
    fn parse_quick_leaves_names_that_need_escapes_to_the_full_parser() {
        let mut qname = [0u8; 256];
        for label in [&b"a.b"[..], b"a\\b", b"a b", b"\xff", b"caf\xc3\xa9"] {
            assert!(
                parse_quick(&query_with_label(label), &mut qname).is_none(),
                "{label:?}"
            );
        }
    }

    #[test]
    fn name_text_is_what_parse_quick_builds_and_escapes_the_rest() {
        let name_of = |packet: &[u8]| Message::from_vec(packet).unwrap().queries[0].name().clone();
        let mut qname = [0u8; 256];
        for label in [&b"Example"[..], b"x-y_z", b"A1~!*"] {
            let packet = query_with_label(label);
            let quick = parse_quick(&packet, &mut qname)
                .expect("a plain name")
                .qname_bytes
                .to_vec();
            assert_eq!(name_text(&name_of(&packet)).as_bytes(), quick, "{label:?}");
        }
        for (label, text) in [
            (&b"a.b"[..], r"a\046b"),
            (b"a\\b", r"a\092b"),
            (b"A b", r"a\032b"),
            (b"\xffZ", r"\255z"),
        ] {
            assert_eq!(name_text(&name_of(&query_with_label(label))), text);
        }
        let name = hickory_proto::rr::Name::from_ascii("WWW.Example.COM.").unwrap();
        assert_eq!(name_text(&name), "www.example.com");
        assert_eq!(name_text(&hickory_proto::rr::Name::root()), "");
    }

    #[test]
    fn name_from_text_gives_back_the_name_name_text_wrote() {
        use hickory_proto::rr::Name;
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5000 {
            let labels: Vec<Vec<u8>> = (0..1 + next() % 4)
                .map(|_| (0..1 + next() % 20).map(|_| next() as u8).collect())
                .collect();
            let name = Name::from_labels(labels.iter().map(Vec::as_slice)).unwrap();
            let back = name_from_text(&name_text(&name)).expect("round trip");
            let lower =
                |n: &Name| -> Vec<Vec<u8>> { n.iter().map(|l| l.to_ascii_lowercase()).collect() };
            assert_eq!(lower(&back), lower(&name), "{labels:?}");
        }
        assert_eq!(
            name_from_text("example.com."),
            name_from_text("example.com")
        );
        assert_eq!(name_from_text(""), Some(Name::root()));
        assert_eq!(name_from_text("."), Some(Name::root()));
        for broken in [
            "a..b", r"a\04", r"a\2x5b", r"a\256", "a b", "a\u{1}b", "café",
        ] {
            assert_eq!(name_from_text(broken), None, "{broken}");
        }
    }

    fn encode_message(message: &Message) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder).expect("encode DNS message");
        bytes
    }

    fn txt_query(max_payload: Option<u16>) -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("cloudflare.com.").unwrap(),
            RecordType::TXT,
        ));
        if let Some(max_payload) = max_payload {
            let mut edns = Edns::new();
            edns.set_max_payload(max_payload);
            message.set_edns(edns);
        }
        encode_message(&message)
    }

    fn large_txt_response(answer_count: usize) -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
        use std::str::FromStr;

        let name = Name::from_str("cloudflare.com.").unwrap();
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.recursion_available = true;
        message.add_query(Query::query(name.clone(), RecordType::TXT));
        for index in 0..answer_count {
            let text = format!("verification-{index:02}-{}", "x".repeat(180));
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        message.set_edns(edns);
        encode_message(&message)
    }

    #[test]
    fn truncated_response_needs_both_qr_and_tc() {
        // byte 2 holds QR (0x80) and TC (0x02) / 第 3 个字节里是 QR（0x80）和 TC（0x02）
        assert!(truncated_response(&[0, 0, 0x82, 0]));
        assert!(truncated_response(&[0, 0, 0x83, 0x80]));
        assert!(
            !truncated_response(&[0, 0, 0x80, 0]),
            "a response without TC"
        );
        assert!(
            !truncated_response(&[0, 0, 0x02, 0]),
            "TC without QR is not a response"
        );
        assert!(!truncated_response(&[0, 0]), "too short to carry the flags");
    }

    #[test]
    fn truncate_udp_response_uses_512_without_edns() {
        let request = txt_query(None);
        let response = large_txt_response(20);
        assert!(response.len() > 512);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        assert!(truncated.len() <= 512);

        let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
        assert!(decoded.metadata.truncation);
        assert_eq!(decoded.metadata.id, 0x1234);
        assert_eq!(decoded.queries.len(), 1);
    }

    #[test]
    fn truncate_udp_response_has_no_trailing_bytes() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
        use std::str::FromStr;

        let request = txt_query(None);
        // No EDNS in the response: the failed answer's partial bytes are not
        // overwritten by a later OPT record, so hickory's bounded encoder
        // leaves them as trailing garbage past the last complete record.
        let name = Name::from_str("cloudflare.com.").unwrap();
        let mut response = Message::new(0x1234, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.add_query(Query::query(name.clone(), RecordType::TXT));
        for index in 0..20 {
            let text = format!("verification-{index:02}-{}", "x".repeat(180));
            response.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let response = encode_message(&response);
        assert!(response.len() > 512);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        // Truncation must respect RFC 1035 §4.2.1 record boundaries with no
        // trailing data beyond the last complete record.
        assert_eq!(
            valid_message_len(&truncated),
            Some(truncated.len()),
            "truncated response must end exactly at a record boundary"
        );
    }

    #[test]
    fn truncate_udp_response_respects_edns_payload_size() {
        let request = txt_query(Some(1232));
        let response = large_txt_response(20);
        assert!(response.len() > 1232);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        assert!(truncated.len() <= 1232);

        let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
        assert!(decoded.metadata.truncation);
        assert_eq!(decoded.queries.len(), 1);
        if let Some(edns) = decoded.edns {
            assert_eq!(edns.max_payload(), 1232);
        }
    }

    #[test]
    fn truncate_udp_response_keeps_response_that_fits_client_limit() {
        let request = txt_query(Some(4096));
        let response = large_txt_response(8);
        assert!(response.len() > 512);
        assert!(response.len() <= 4096);

        assert!(truncate_udp_response(&request, &response).is_none());
    }

    #[test]
    fn truncate_udp_response_skips_small_responses_without_parsing_request() {
        let response = vec![0u8; 128];
        assert!(truncate_udp_response(b"not a dns request", &response).is_none());
    }

    fn query_with_additional(additional: &[u8]) -> Vec<u8> {
        let mut packet = query_with_label(b"example");
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(additional);
        packet
    }

    #[test]
    fn parse_quick_rejects_missing_declared_additional_record() {
        let packet = query_with_additional(&[]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_rejects_truncated_edns_rdata() {
        let packet = query_with_additional(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 4, 0, 1]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_rejects_invalid_additional_compression_pointer() {
        let packet = query_with_additional(&[0xC0, 0xFF, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_accepts_valid_empty_edns_record() {
        let packet = query_with_additional(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        let mut qname = [0u8; 256];
        let query = parse_quick(&packet, &mut qname).expect("valid EDNS query");
        assert!(query.edns_present);
    }

    /// `parse_quick` 和 `QueryFlags::of` 读出同样的查询位，别的头部位不算在内；快速解析读不了
    /// 的查询，`QueryFlags::of` 照样读得出
    /// `parse_quick` and `QueryFlags::of` read the same query bits, and no other header
    /// bit counts; `QueryFlags::of` reads them off a query the fast parser cannot read
    #[test]
    fn parse_quick_reads_the_query_bits_as_query_flags_of_does() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut qname = [0u8; 256];
        for recursion_desired in [false, true] {
            for checking_disabled in [false, true] {
                for edns in [None, Some(false), Some(true)] {
                    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
                    msg.metadata.recursion_desired = recursion_desired;
                    msg.metadata.checking_disabled = checking_disabled;
                    // AD in a query only asks for the AD bit back (RFC 6840 section 5.7)
                    // 查询里的 AD 只是要应答带回 AD 位（RFC 6840 第 5.7 节）
                    msg.metadata.authentic_data = true;
                    msg.add_query(Query::query(
                        Name::from_str("example.com.").unwrap(),
                        RecordType::A,
                    ));
                    if let Some(dnssec_ok) = edns {
                        let mut opt = Edns::new();
                        opt.set_dnssec_ok(dnssec_ok);
                        msg.set_edns(opt);
                    }
                    let mut packet = msg.to_vec().unwrap();
                    let expected =
                        QueryFlags::new(recursion_desired, checking_disabled, edns == Some(true));
                    let case =
                        format!("RD {recursion_desired}, CD {checking_disabled}, EDNS {edns:?}");
                    let quick = parse_quick(&packet, &mut qname).expect(&case).flags;
                    assert_eq!(quick, expected, "{case}");
                    assert_eq!(QueryFlags::of(&packet), expected, "{case}");
                    packet.push(0);
                    assert!(parse_quick(&packet, &mut qname).is_none(), "{case}");
                    assert_eq!(QueryFlags::of(&packet), expected, "{case}, trailing byte");
                }
            }
        }
    }

    /// 只差大小写时抄成查询的写法，别的都不动；写法一样时不复制
    /// Only a difference in case is copied over from the query, nothing else; the same
    /// spelling is not copied
    #[test]
    fn question_as_asked_copies_only_the_case() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        // `Name::from_ascii` keeps the case, `Name::from_str` would lowercase it
        // `Name::from_ascii` 保留大小写，`Name::from_str` 会转成小写
        let message = |name: &str, kind: MessageType| {
            let name = Name::from_ascii(name).unwrap();
            let mut msg = Message::new(0x1234, kind, OpCode::Query);
            msg.add_query(Query::query(name.clone(), RecordType::A));
            if kind == MessageType::Response {
                msg.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
                ));
            }
            msg.to_vec().unwrap()
        };
        let query = message("Example.COM.", MessageType::Query);
        let reply = Bytes::from(message("example.com.", MessageType::Response));
        assert_ne!(reply[12..25], query[12..25]);
        let echoed = question_as_asked(reply.clone(), &query);
        assert_eq!(echoed[12..25], query[12..25]);
        let mut expected = reply.to_vec();
        expected[12..25].copy_from_slice(&query[12..25]);
        assert_eq!(echoed, expected, "nothing else changes");

        let same = Bytes::from(message("Example.COM.", MessageType::Response));
        assert_eq!(
            question_as_asked(same.clone(), &query).as_ptr(),
            same.as_ptr()
        );
        // Another name of the same length / 长度相同的另一个名字
        let other = Bytes::from(message("examplf.com.", MessageType::Response));
        assert_eq!(question_as_asked(other.clone(), &query), other);
        // A reply without a question, and queries that cannot be read
        // 没有问题段的应答，以及读不出来的查询
        let mut no_question = reply.to_vec();
        no_question[5] = 0;
        let no_question = Bytes::from(no_question);
        assert_eq!(question_as_asked(no_question.clone(), &query), no_question);
        let mut compressed = query[..12].to_vec();
        compressed.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        for unreadable in [&query[..20], &query[..11], &compressed[..]] {
            assert_eq!(question_as_asked(reply.clone(), unreadable), reply);
        }
    }

    /// 一个 A 查询或应答，`edns` 为 Some(DO 位) 时带 OPT / An A query or reply, with an OPT
    /// when `edns` is Some(the DO bit)
    fn edns_message(kind: hickory_proto::op::MessageType, edns: Option<bool>) -> Vec<u8> {
        use hickory_proto::op::{Edns, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        let name = Name::from_ascii("example.com.").unwrap();
        let mut msg = Message::new(0x1234, kind, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        if kind == hickory_proto::op::MessageType::Response {
            msg.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
            ));
        }
        if let Some(dnssec_ok) = edns {
            let mut opt = Edns::new();
            opt.set_max_payload(1232);
            opt.set_dnssec_ok(dnssec_ok);
            msg.set_edns(opt);
        }
        msg.to_vec().unwrap()
    }

    /// 应答带不带 OPT、DO 位是什么（None：没有 OPT）/ Whether a reply has an OPT and its DO bit
    fn reply_edns(reply: &[u8]) -> Option<bool> {
        Message::from_vec(reply)
            .expect("a readable reply")
            .edns
            .map(|edns| edns.flags().dnssec_ok)
    }

    /// 查询带 OPT 时应答补上，DO 照抄；不带时去掉；已经一样时不复制
    /// A query with an OPT gets one appended with its DO; one without gets it taken out;
    /// nothing is copied when they already agree
    #[test]
    fn edns_as_asked_follows_the_query() {
        use hickory_proto::op::MessageType::{Query, Response};
        for query_edns in [None, Some(false), Some(true)] {
            let query = edns_message(Query, query_edns);
            for reply_edns_was in [None, Some(false), Some(true)] {
                let reply = Bytes::from(edns_message(Response, reply_edns_was));
                let out = edns_as_asked(reply.clone(), &query);
                let case = format!("query {query_edns:?}, reply {reply_edns_was:?}");
                assert_eq!(reply_edns(&out), query_edns, "{case}");
                assert_eq!(
                    out.as_ptr() == reply.as_ptr(),
                    query_edns == reply_edns_was,
                    "{case}: copied only when changed"
                );
                // Exactly the OPT changes: the same message as one built that way
                // 只有 OPT 变了：和直接这样构造的报文一样
                assert_eq!(out, edns_message(Response, query_edns), "{case}");
            }
        }
    }

    /// OPT 后面还有记录时，经 hickory 去掉 OPT，别的记录都留着
    /// With records after the OPT, hickory takes the OPT out and keeps the rest
    #[test]
    fn edns_as_asked_takes_out_an_opt_that_is_not_last() {
        use hickory_proto::op::MessageType::{Query, Response};
        let mut reply = edns_message(Response, Some(false));
        // An A record after the OPT, its owner pointing at the question
        // OPT 后面的一条 A 记录，属主指向问题名
        reply[11] += 1;
        reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9]);
        let out = edns_as_asked(Bytes::from(reply), &edns_message(Query, None));
        let msg = Message::from_vec(&out).unwrap();
        assert!(msg.edns.is_none());
        assert_eq!(msg.additionals.len(), 1);
        assert_eq!(msg.answers.len(), 1);
    }

    /// 带扩展 RCODE 的 OPT 不去掉，TSIG 签过的应答不动，读不出的查询也不动
    /// An OPT with an extended RCODE stays, a TSIG-signed reply is left alone, and so is
    /// everything when the query cannot be read
    #[test]
    fn edns_as_asked_leaves_what_it_must_not_change() {
        use hickory_proto::op::MessageType::{Query, Response};
        let plain_query = edns_message(Query, None);
        let edns_query = edns_message(Query, Some(true));
        // BADVERS: extended RCODE 1 in the OPT / BADVERS：OPT 里的扩展 RCODE 为 1
        let badvers = badvers_response(&edns_query).unwrap();
        assert_eq!(edns_as_asked(badvers.clone(), &plain_query), badvers);
        // A TSIG hickory reads (RFC 8945 section 4.2): key name `key.`, algorithm
        // hmac-sha256, a 32-byte MAC, the original ID, no error, no other data
        // 一条 hickory 读得了的 TSIG（RFC 8945 第 4.2 节）：密钥名 `key.`、算法 hmac-sha256、
        // 32 字节的 MAC、原始 ID、没有错误、没有其他数据
        let tsig = |mut message: Vec<u8>| {
            let mut rdata = vec![11];
            rdata.extend_from_slice(b"hmac-sha256");
            rdata.push(0);
            rdata.extend_from_slice(&[0, 0, 0x65, 0, 0, 0, 1, 44, 0, 32]);
            rdata.extend_from_slice(&[0xAB; 32]);
            rdata.extend_from_slice(&[0x12, 0x34, 0, 0, 0, 0]);
            message[11] += 1;
            message.extend_from_slice(b"\x03key\x00");
            message.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
            message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            message.extend_from_slice(&rdata);
            assert!(
                Message::from_vec(&message).is_ok(),
                "hickory reads the TSIG"
            );
            Bytes::from(message)
        };
        let signed_with_opt = tsig(edns_message(Response, Some(false)));
        assert_eq!(
            edns_as_asked(signed_with_opt.clone(), &plain_query),
            signed_with_opt
        );
        let signed_without_opt = tsig(edns_message(Response, None));
        assert_eq!(
            edns_as_asked(signed_without_opt.clone(), &edns_query),
            signed_without_opt
        );
        let reply = Bytes::from(edns_message(Response, Some(false)));
        assert_eq!(edns_as_asked(reply.clone(), &edns_query[..20]), reply);
    }

    /// RD 和 CD 照抄查询的，其余头部位不动；已经一样时不复制
    /// RD and CD are the query's and no other header bit changes; nothing is copied when
    /// they already agree
    #[test]
    fn header_as_asked_copies_rd_and_cd() {
        let reply = Bytes::from(edns_message(hickory_proto::op::MessageType::Response, None));
        for (byte2, byte3) in [(0x00, 0x00), (0x01, 0x00), (0x00, 0x10), (0x01, 0x10)] {
            let mut query = edns_message(hickory_proto::op::MessageType::Query, None);
            // AA and AD in the query are not copied / 查询里的 AA 和 AD 不照抄
            query[2] = byte2 | 0x04;
            query[3] = byte3 | 0x20;
            let out = header_as_asked(reply.clone(), &query);
            assert_eq!(out[2] & 0x01, byte2);
            assert_eq!(out[3] & 0x10, byte3);
            assert_eq!(out[2] & !0x01, reply[2] & !0x01);
            assert_eq!(out[3] & !0x10, reply[3] & !0x10);
            assert_eq!(out[4..], reply[4..]);
            assert_eq!(
                out.as_ptr() == reply.as_ptr(),
                (byte2, byte3) == (reply[2] & 0x01, reply[3] & 0x10)
            );
        }
    }

    #[test]
    fn saturating_u64_to_u32_caps_large_values() {
        assert_eq!(saturating_u64_to_u32(42), 42);
        assert_eq!(saturating_u64_to_u32(u64::MAX), u32::MAX);
    }

    // ---- question_matches ----

    fn question_matches_query(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    #[test]
    fn question_matches_ignores_ascii_case_only() {
        let query = question_matches_query("example.com.");
        let mut response = question_matches_query("ExAmPlE.CoM.");
        response[2] |= 0x80;
        assert!(question_matches(&query, &response), "0x20 case must match");

        let mut other = question_matches_query("example.org.");
        other[2] |= 0x80;
        assert!(
            !question_matches(&query, &other),
            "different name must not match"
        );

        let mut other_type = response.clone();
        let type_pos = other_type.len() - 4;
        other_type[type_pos + 1] = 28; // AAAA
        assert!(
            !question_matches(&query, &other_type),
            "different QTYPE must not match"
        );
    }

    #[test]
    fn question_matches_reply_without_question_only_when_empty() {
        let query = question_matches_query("example.com.");
        // Header-only FORMERR with QDCOUNT = 0 and no records: accepted, it
        // cannot poison anything and keeps the upstream's fast failure.
        let mut bare_error = query[..12].to_vec();
        bare_error[2] |= 0x80;
        bare_error[3] = 0x01; // RCODE = FORMERR
        bare_error[5] = 0;
        assert!(
            question_matches(&query, &bare_error),
            "record-less reply without a question must be accepted"
        );
        // QDCOUNT = 0 but ANCOUNT = 1: records without a question, rejected.
        let mut with_records = bare_error.clone();
        with_records[3] = 0x00;
        with_records[7] = 1;
        assert!(
            !question_matches(&query, &with_records),
            "reply carrying records without a question must be rejected"
        );
        // Truncated question
        assert!(!question_matches(&query, &query[..20]));
    }

    mod ecs_wire {
        use super::super::*;
        use crate::ecs::EcsKey;
        use crate::ecs_scope::ReplyEcs;
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::net::IpAddr;
        use std::str::FromStr;

        fn subnet(address: &str, prefix: u8) -> EcsKey {
            EcsKey::from_ip(address.parse().unwrap(), prefix, prefix)
        }

        /// 一条 A 记录的应答；`opt` 为假时不带 OPT，`ecs` 是其中的 ECS（地址、SOURCE、SCOPE），
        /// `extra` 再加一个别的选项
        /// A reply with one A record; no OPT unless `opt`, `ecs` its ECS (address,
        /// SOURCE, SCOPE), `extra` one more option
        fn reply(opt: bool, ecs: Option<(&str, u8, u8)>, extra: bool) -> Vec<u8> {
            let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
            let name = Name::from_str("example.com.").unwrap();
            msg.add_query(Query::query(name.clone(), RecordType::A));
            msg.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A("192.0.2.1".parse().unwrap())),
            ));
            if opt {
                let mut edns = Edns::new();
                edns.set_max_payload(1232);
                if extra {
                    edns.options_mut()
                        .insert(EdnsOption::Unknown(65001, vec![1, 2, 3, 4]));
                }
                if let Some((address, source, scope)) = ecs {
                    edns.options_mut()
                        .insert(EdnsOption::Subnet(ClientSubnet::new(
                            address.parse().unwrap(),
                            source,
                            scope,
                        )));
                }
                msg.edns = Some(edns);
            }
            msg.to_vec().unwrap()
        }

        fn parsed_ecs(packet: &[u8]) -> Option<(IpAddr, u8, u8)> {
            let msg = Message::from_vec(packet).expect("still a valid message");
            match msg.edns.as_ref()?.options().get(EdnsCode::Subnet)? {
                EdnsOption::Subnet(subnet) => {
                    Some((subnet.addr(), subnet.source_prefix(), subnet.scope_prefix()))
                }
                _ => None,
            }
        }

        #[test]
        fn reply_ecs_reads_the_option() {
            assert_eq!(
                reply_ecs(&reply(false, None, false)),
                (ReplyEcs::Absent, true)
            );
            assert_eq!(
                reply_ecs(&reply(true, None, true)),
                (ReplyEcs::Absent, true)
            );
            assert_eq!(
                reply_ecs(&reply(true, Some(("198.51.100.0", 24, 16)), true)),
                (
                    ReplyEcs::Subnet {
                        subnet: subnet("198.51.100.0", 24),
                        scope: 16
                    },
                    true
                )
            );
            let mut servfail = reply(true, None, false);
            servfail[3] = (servfail[3] & 0xF0) | 2;
            assert_eq!(reply_ecs(&servfail), (ReplyEcs::Absent, false));
            let packet = reply(true, Some(("198.51.100.0", 24, 16)), false);
            assert_eq!(
                reply_ecs(&packet[..packet.len() - 1]),
                (ReplyEcs::Unreadable, false)
            );
        }

        /// 两条 OPT，或 OPT 出现在 Additional 以外：报文不合规（RFC 6891），读不出 ECS，
        /// 也不缓存
        /// Two OPT records, or OPT outside Additional: the message is malformed (RFC
        /// 6891), its ECS cannot be read, and it is not cached
        #[test]
        fn a_second_or_misplaced_opt_makes_the_reply_unreadable() {
            let packet = reply(true, Some(("198.51.100.0", 24, 24)), false);
            // The reply is the question, one answer, then the OPT record
            // 应答依次是问题、一条回答、OPT 记录
            let question_end = skip_name(&packet, 12).unwrap() + 4;
            let answer_fixed = skip_name(&packet, question_end).unwrap();
            let answer_end = answer_fixed
                + 10
                + u16::from_be_bytes([packet[answer_fixed + 8], packet[answer_fixed + 9]]) as usize;
            let opt = packet[answer_end..].to_vec();
            // A second OPT at the end / 末尾再加一条 OPT
            let mut twice = packet.clone();
            twice.extend_from_slice(&opt);
            twice[11] += 1;
            assert_eq!(reply_ecs(&twice), (ReplyEcs::Unreadable, false));
            let twice = Bytes::from(twice);
            assert_eq!(without_ecs(twice.clone()), Err(twice));
            // The OPT counted as an Authority record / 把 OPT 当作 Authority 记录
            let mut misplaced = packet.clone();
            misplaced[9] = 1;
            misplaced[11] = 0;
            assert_eq!(reply_ecs(&misplaced), (ReplyEcs::Unreadable, false));
        }

        #[test]
        fn without_ecs_drops_only_the_ecs_option() {
            let packet = Bytes::from(reply(true, Some(("198.51.100.0", 24, 16)), true));
            let stripped = without_ecs(packet).expect("readable");
            assert_eq!(parsed_ecs(&stripped), None);
            let msg = Message::from_vec(&stripped).unwrap();
            assert_eq!(msg.answers.len(), 1);
            assert!(
                msg.edns
                    .as_ref()
                    .unwrap()
                    .options()
                    .get(EdnsCode::Unknown(65001))
                    .is_some()
            );
            let plain = Bytes::from(reply(true, None, true));
            assert_eq!(without_ecs(plain.clone()), Ok(plain));
        }

        #[test]
        fn the_echo_carries_the_clients_subnet_and_the_scope() {
            let client = subnet("203.0.113.0", 24);
            for stored in [reply(true, None, true), reply(false, None, false)] {
                let echoed = with_ecs_echo(&stored, &client, 16).expect("echo");
                assert_eq!(
                    parsed_ecs(&echoed),
                    Some(("203.0.113.0".parse().unwrap(), 24, 16))
                );
                assert_eq!(Message::from_vec(&echoed).unwrap().answers.len(), 1);
            }
            // 已有的 ECS 被取代 / An ECS option already there is replaced
            let other = reply(true, Some(("198.51.100.0", 24, 24)), true);
            let echoed = with_ecs_echo(&other, &client, 0).expect("echo");
            assert_eq!(
                parsed_ecs(&echoed),
                Some(("203.0.113.0".parse().unwrap(), 24, 0))
            );
            let v6 = subnet("2001:db8:aa00::", 40);
            let echoed = with_ecs_echo(&reply(true, None, false), &v6, 40).expect("echo");
            assert_eq!(
                parsed_ecs(&echoed),
                Some(("2001:db8:aa00::".parse().unwrap(), 40, 40))
            );
        }

        /// OPT 后面还有记录时不改动它：后面记录的压缩指针会指错地方。这样的应答去不掉
        /// ECS（不缓存），也不加回显
        /// An OPT with records after it is left alone, since their compression
        /// pointers would point to the wrong place: the reply keeps its ECS (and is
        /// not cached) and gets no echo
        #[test]
        fn an_opt_followed_by_records_is_left_alone() {
            let packet = reply(true, Some(("198.51.100.0", 24, 24)), false);
            // An A record named by a pointer to the question, after the OPT
            // OPT 之后一条名字指向问题的 A 记录
            let mut after = packet.clone();
            after.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            after[11] += 1;
            assert!(Message::from_vec(&after).is_ok());
            let after = Bytes::from(after);
            assert_eq!(without_ecs(after.clone()), Err(after.clone()));
            assert_eq!(with_ecs_echo(&after, &subnet("203.0.113.0", 24), 0), None);
            // Without ECS there is nothing to move, so it is stored as it is
            // 没有 ECS 就不用挪动，原样存放
            let plain = Bytes::from(reply(true, None, true));
            let mut plain_after = plain.to_vec();
            plain_after.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            plain_after[11] += 1;
            let plain_after = Bytes::from(plain_after);
            assert_eq!(without_ecs(plain_after.clone()), Ok(plain_after));
            // unless hickory cannot read it: then no echo could be written for it
            // 除非 hickory 读不了它：那就没法给它写回显
            let mut unreadable = plain.to_vec();
            // A NULL record with empty RDATA, which hickory refuses / 一条 RDATA 为空的 NULL 记录，hickory 拒收
            unreadable.extend_from_slice(&[0xC0, 12, 0, 10, 0, 1, 0, 0, 0, 60, 0, 0]);
            unreadable[11] += 1;
            assert!(Message::from_vec(&unreadable).is_err());
            let unreadable = Bytes::from(unreadable);
            assert_eq!(without_ecs(unreadable.clone()), Err(unreadable));
        }

        /// 查询里 SCOPE 不为 0 的 ECS 选项不合规（RFC 7871 第 6 节）
        /// An ECS option with a nonzero SCOPE in a query does not follow RFC 7871 section 6
        #[test]
        fn a_query_ecs_with_a_scope_is_opaque() {
            let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_str("example.com.").unwrap(),
                RecordType::A,
            ));
            let mut edns = Edns::new();
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    "198.51.100.0".parse().unwrap(),
                    24,
                    8,
                )));
            query.edns = Some(edns);
            let packet = query.to_vec().unwrap();
            let mut buf = [0u8; 256];
            let parsed = parse_quick(&packet, &mut buf)
                .unwrap()
                .client_subnet
                .unwrap();
            assert!(parsed.is_opaque());
            assert_eq!(client_subnet(&packet), Some(parsed));
        }

        /// 太短的报文不会让改写出错 / A message too short to read never trips the rewriting
        #[test]
        fn short_messages_are_left_alone() {
            for short in [Vec::new(), vec![0u8; 5], vec![0u8; 11]] {
                assert_eq!(
                    ecs_removed(Bytes::from(short.clone())),
                    Bytes::from(short.clone())
                );
                assert_eq!(echo_ecs(&short, &subnet("203.0.113.0", 24), 0), None);
                assert!(!last_record_is_tsig(&short));
            }
        }

        /// OPT 不能排在 TSIG 之后，带 TSIG 的报文不加回显
        /// OPT may not follow a TSIG, so a message ending in one gets no echo
        #[test]
        fn no_echo_is_added_after_a_tsig() {
            let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
            let name = Name::from_str("example.com.").unwrap();
            msg.add_query(Query::query(name.clone(), RecordType::A));
            let mut packet = msg.to_vec().unwrap();
            // A TSIG-typed record at the end of Additional / Additional 末尾一条 TSIG 类型的记录
            packet.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
            packet[11] = 1;
            assert_eq!(with_ecs_echo(&packet, &subnet("203.0.113.0", 24), 0), None);
            packet[11] = 0;
            packet.truncate(packet.len() - 11);
            assert!(with_ecs_echo(&packet, &subnet("203.0.113.0", 24), 0).is_some());
        }

        #[test]
        fn parse_quick_reads_the_clients_ecs() {
            let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_str("example.com.").unwrap(),
                RecordType::A,
            ));
            let plain = query.to_vec().unwrap();
            let mut edns = Edns::new();
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    "198.51.100.7".parse().unwrap(),
                    24,
                    0,
                )));
            query.edns = Some(edns);
            let with_ecs = query.to_vec().unwrap();
            let mut buf = [0u8; 256];
            assert_eq!(parse_quick(&plain, &mut buf).unwrap().client_subnet, None);
            let mut buf = [0u8; 256];
            assert_eq!(
                parse_quick(&with_ecs, &mut buf).unwrap().client_subnet,
                Some(subnet("198.51.100.0", 24))
            );
        }
    }

    mod cookie_wire {
        use super::super::*;
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
        use hickory_proto::rr::{Name, RecordType};
        use std::borrow::Cow;
        use std::str::FromStr;

        /// 查询 example.com A；`cookie` 时带一个 8 字节的客户端 cookie，`ecs` 时再带一个 ECS 选项，
        /// 两者都没有就不带 OPT
        /// A query for example.com A; an 8-byte client cookie when `cookie`, an ECS
        /// option as well when `ecs`, and no OPT when neither
        fn query(cookie: bool, ecs: bool) -> Vec<u8> {
            let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
            msg.add_query(Query::query(
                Name::from_str("example.com.").unwrap(),
                RecordType::A,
            ));
            if cookie || ecs {
                let mut edns = Edns::new();
                edns.set_max_payload(1232);
                if ecs {
                    edns.options_mut()
                        .insert(EdnsOption::Subnet(ClientSubnet::new(
                            "198.51.100.0".parse().unwrap(),
                            24,
                            0,
                        )));
                }
                if cookie {
                    edns.options_mut()
                        .insert(EdnsOption::Unknown(COOKIE, b"CLIENT-1".to_vec()));
                }
                msg.edns = Some(edns);
            }
            msg.to_vec().unwrap()
        }

        fn has_cookie(packet: &[u8]) -> bool {
            Message::from_vec(packet)
                .expect("still a valid message")
                .edns
                .is_some_and(|edns| edns.options().get(EdnsCode::Cookie).is_some())
        }

        #[test]
        fn a_message_without_a_cookie_is_handed_back_untouched() {
            for packet in [query(false, false), query(false, true)] {
                assert!(matches!(query_without_cookie(&packet), Cow::Borrowed(_)));
                let reply = Bytes::from(packet);
                assert_eq!(reply_without_cookie(reply.clone()).as_ptr(), reply.as_ptr());
            }
        }

        #[test]
        fn the_cookie_is_taken_out_and_the_other_options_kept() {
            let packet = query(true, true);
            let stripped = query_without_cookie(&packet);
            assert!(!has_cookie(&stripped));
            assert_eq!(
                stripped.len(),
                packet.len() - 12,
                "the option header and 8 bytes go"
            );
            let msg = Message::from_vec(&stripped).expect("still a valid message");
            let edns = msg.edns.expect("the OPT record stays");
            assert!(edns.options().get(EdnsCode::Subnet).is_some(), "ECS stays");
            assert_eq!(edns.max_payload(), 1232);
            // 只有 cookie 一个选项时，OPT 留下，选项为空 / With the cookie alone, the OPT stays empty
            let alone = query_without_cookie(&query(true, false)).into_owned();
            assert!(!has_cookie(&alone));
            assert!(Message::from_vec(&alone).unwrap().edns.is_some());
        }

        /// OPT 后面还有记录时挪不动它，交给 hickory 重新编码；后面的记录照样在
        /// Records after the OPT cannot be moved, so hickory encodes the message
        /// again, and those records are still there
        #[test]
        fn a_cookie_before_later_records_is_taken_out_through_hickory() {
            let mut packet = query(true, false);
            // An A record named by a pointer to the question, after the OPT
            // OPT 之后一条名字指向问题的 A 记录
            packet.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            packet[11] += 1;
            assert!(has_cookie(&packet));
            let stripped = reply_without_cookie(Bytes::from(packet));
            assert!(!has_cookie(&stripped));
            assert_eq!(
                Message::from_vec(&stripped).unwrap().additionals.len(),
                1,
                "the record after the OPT stays"
            );
        }

        /// 最后一条是 TSIG 时不动：改了报文签名就不对了
        /// A message ending in a TSIG is left alone: any change would break the signature
        #[test]
        fn a_cookie_before_a_tsig_is_left_alone() {
            let mut packet = query(true, false);
            // A TSIG-typed record at the end of Additional / Additional 末尾一条 TSIG 类型的记录
            packet.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
            packet[11] += 1;
            assert!(matches!(query_without_cookie(&packet), Cow::Borrowed(_)));
        }
    }
}
