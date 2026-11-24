use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

/// 快速解析结果，零拷贝实现 / Quick parse result with zero-copy implementation
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    /// 问题名，已经小写，只有 ASCII：引用调用方给的缓冲区，不分配 / The question name, lowercased
    /// and ASCII only: it refers to the buffer the caller gave, allocating nothing
    pub qname: &'a str,
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
        let dnssec_ok = matches!(find_opt(query), Ok(Some(opt)) if opt.dnssec_ok(query));
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

/// 读不了的查询的 FORMERR：只有请求头，问题读得出来就带上问题（见 [`short_reply`]），查询带着读得出的 OPT 时也带 OPT（见
/// [`reply_as_asked`]，RFC 6891 第 7 节）
/// The FORMERR for a query that cannot be read: the header alone, with the question when that
/// can be read (see [`short_reply`]), and an OPT when the query carries one that can be read
/// (see [`reply_as_asked`], RFC 6891 section 7)
pub fn formerr_reply(query: &[u8]) -> Bytes {
    reply_as_asked(short_reply(query, ResponseCode::FormErr, true), query)
}

/// 一个查询的 SERVFAIL，三个监听器过载拒绝和超时时都回它：照线上格式拼（见 [`short_reply`]），不必解析查询，再照查询规整
/// （见 [`reply_as_asked`]），查询带着 OPT 就带回 OPT。以前三个监听器各写一套，TCP 和 DoH 过载时还要把查询整个解析一遍，
/// UDP 过载时快速解析读不了的查询不回
/// The SERVFAIL for a query, which all three listeners answer when refusing under overload and
/// on a timeout: put together on the wire (see [`short_reply`]) with no parse of the query,
/// then shaped as the query asks (see [`reply_as_asked`]), an OPT coming back for a query with
/// one. The three listeners used to write one each, TCP and DoH parsing the whole query under
/// overload, and UDP under overload answering nothing to a query the quick parse could not read
pub fn servfail_reply(query: &[u8]) -> Bytes {
    reply_as_asked(short_reply(query, ResponseCode::ServFail, true), query)
}

/// 不读完请求就给得出的应答：请求头带着它的 ID、操作码、RD 和 CD，QR、RA 置位，RCODE 为 `rcode`；`question` 为 true 时
/// 问题读得出不压缩的写法（见 [`question_name_end`]）、类型和类别也在报文里就带上，各段计数都是 0。不比请求长，伪造来源也
/// 放大不了流量。请求至少 12 字节，由调用方查过
/// A reply given without reading the request through: the request's header with its ID,
/// opcode, RD and CD, QR and RA set, RCODE `rcode`; with `question` true, the question when its
/// name can be read uncompressed (see [`question_name_end`]) and its type and class are in the
/// message, every other count 0. It is no longer than the request, so a forged source gains no
/// amplification. The request has at least 12 bytes, as the caller has checked
fn short_reply(request: &[u8], rcode: ResponseCode, question: bool) -> Bytes {
    let question_end = question
        .then(|| question_name_end(request))
        .flatten()
        .map(|end| end + 4)
        .filter(|&end| end <= request.len());
    let mut reply = Vec::with_capacity(question_end.unwrap_or(12));
    reply.extend_from_slice(&request[..2]);
    reply.push(0x80 | (request[2] & 0x79));
    reply.push(0x80 | (request[3] & 0x10) | rcode.low());
    reply.extend_from_slice(&[0, u8::from(question_end.is_some()), 0, 0, 0, 0, 0, 0]);
    if let Some(end) = question_end {
        reply.extend_from_slice(&request[12..end]);
    }
    Bytes::from(reply)
}

/// 请求头不是 KixDNS 回答的标准查询（见 [`is_standard_query_header`]）时的应答。只有请求头，带着它的 ID、
/// 操作码、RD 和 CD，请求带着读得出的 OPT 时再加一条 OPT（RFC 6891 第 7 节：带 OPT 的请求，应答也要带）：不比请求长，
/// 伪造来源也放大不了流量；别的操作码下各段的意思不同，也不往应答里抄。以前从不带 OPT，经 DoH 问时请求带了填充才碰巧带上
/// - 操作码不是 QUERY（NOTIFY、UPDATE 这些 KixDNS 不做的）：NOTIMP（RFC 1035 第 4.1.1 节）。
/// - 操作码是 QUERY，但问题数不是 1，或者带着回答、授权记录：FORMERR（RFC 9619）。RFC 7873 第 5.4 节那种
///   只带 cookie、没有问题的探测，也由此得到回答。
///
/// 应答（QR=1）和不足 12 字节的报文没有这样的应答，为 None：回应答会让两个服务器一直互相回下去。
/// 以前除了 NOTIMP，这些都被丢掉（UDP）或者断开连接（TCP）。
///
/// The reply to a request whose header is not the standard query KixDNS answers (see
/// [`is_standard_query_header`]). The header alone, with its ID, opcode, RD and CD, and an OPT
/// added when the request carries one that can be read (RFC 6891 section 7: a request with an
/// OPT gets one back): no longer than the request, a forged source gains no amplification, and
/// the sections, meaning other things under other opcodes, are not copied. It never carried an
/// OPT before, except by chance over DoH when the request was padded.
/// - An opcode other than QUERY (NOTIFY, UPDATE and the like, which KixDNS does not do) gets
///   NOTIMP (RFC 1035 section 4.1.1).
/// - A QUERY with a question count other than 1, or carrying answer or authority records,
///   gets FORMERR (RFC 9619). The cookie-only probe of RFC 7873 section 5.4, with no
///   question, is answered so too.
///
/// A response (QR=1) and a message shorter than 12 bytes have no such reply, None: answering a
/// response would have two servers answer each other on and on. All but NOTIMP used to be
/// dropped (UDP) or have the connection closed (TCP).
pub fn header_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.get(..12)?[2] & 0x80 != 0 {
        return None;
    }
    let rcode = if packet[2] & 0x78 != 0 {
        ResponseCode::NotImp
    } else {
        ResponseCode::FormErr
    };
    Some(reply_as_asked(short_reply(packet, rcode, false), packet))
}

/// DNS 报文头的长度 / The length of a DNS header
const HEADER_LEN: usize = 12;

/// 一个名字编码出来最多这么多字节，连同压缩指针跳过去读到的部分（RFC 1035 第 2.3.4 节）。读名字的每个函数都守
/// 这一条
/// The most bytes a name takes encoded, what a compression pointer leads to included (RFC
/// 1035 section 2.3.4). Every function that reads a name keeps to it
const MAX_NAME_LEN: usize = 255;

/// 我们自己收发 UDP 的载荷上限，回答里的 OPT 都通告它；给客户端的 UDP 回答也不超过它，超过的截断、让客户端改用 TCP。
/// 1232 是 DNS Flag Day 2020 定的值：再大的报文在常见的路径上就要在 IP 层分片，分片容易丢，也给伪造回包留了口子
/// The UDP payload this server sends and receives at most, which every OPT in its replies
/// advertises; no UDP reply to a client goes beyond it either, a longer one being truncated for the
/// client to retry over TCP. 1232 is the value DNS Flag Day 2020 settled on: anything larger is
/// fragmented at the IP layer on common paths, and fragments get lost and open a way for forged
/// replies
pub const UDP_PAYLOAD: u16 = 1232;

/// 客户端发来的一个查询最长多少字节：UDP 一次收这么多，再长的被截断、答 FORMERR；TCP 上声明更长的关掉连接，DoH 的请求
/// 正文也到此为止。真实的查询远没有这么长（按 RFC 8467 填充也只填到 128 字节的整数倍），定这个数是不让一个客户端凭一个
/// 长度前缀或请求头就让内核为每条连接、每个请求留下 64 KiB
/// The longest query a client may send, in bytes: UDP takes this much at a time, a longer one
/// cut and answered FORMERR; over TCP a longer one declared closes the connection, and the body
/// of a DoH request ends here too. Real queries are nowhere near this long (padded to a
/// multiple of 128 bytes under RFC 8467), and the bound keeps a client from having the kernel
/// set aside 64 KiB per connection or request on the strength of a length prefix or a header
pub const MAX_QUERY_LEN: usize = 4096;

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

    // 3. 问题名照 `question_name_end` 读，文本照 `plain_name_text` 拼 / The question name, read as
    // `question_name_end` reads it, its text built as `plain_name_text` builds it
    let mut pos = question_name_end(packet)?;
    let qname = plain_name_text(&packet[HEADER_LEN..pos - 1], buf)?;

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
        let next_pos = strict_name_end(packet, ar_pos)?;
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
            edns_options(packet, fixed_end..rdata_end)
                .all(|option| option.is_ok())
                .then_some(())?;
            edns_present = true;
            // TTL 字段依次是扩展 RCODE、版本和标志 / The TTL field holds the extended RCODE, the version and the flags
            edns_version = packet[next_pos + 5];
            dnssec_ok = packet[next_pos + 6] & 0x80 != 0;
            // ECS 不合规的查询留给 `Engine::on_the_spot` 回 FORMERR / A query with an improper ECS is left
            // for `Engine::on_the_spot` to answer FORMERR
            client_subnet = query_subnet(packet, fixed_end..rdata_end).ok()?;
        }
        ar_pos = rdata_end;
    }
    if ar_pos != packet.len() {
        return None;
    }

    Some(QuickQuery {
        tx_id,
        qname,
        qtype,
        qclass,
        edns_present,
        edns_version,
        client_subnet,
        flags: QueryFlags::new(packet[2] & 0x01 != 0, packet[3] & 0x10 != 0, dnssec_ok),
    })
}

/// 问题名在 [`parse_quick`] 里的文本（同 [`name_text`]）：各标签小写、用 '.' 连起来，写进 `buf`。`labels` 是问题名
/// 不带结尾根标签的编码，由 [`question_name_end`] 读过、不压缩。有要转义的字节（见 [`is_plain_name_byte`]）或 `buf` 放
/// 不下时为 None：这样的名字留给完整解析，两个解析器给每个名字的文本才一样。只放过可打印 ASCII，所以转成 &str 一定成功，
/// 照常检查、不用 unsafe
/// The question name's text in [`parse_quick`] (as [`name_text`] writes it): its labels
/// lowercased and joined with '.', written into `buf`. `labels` is the name's encoding without
/// the root label at its end, read by [`question_name_end`] and uncompressed. None for a byte
/// that needs an escape (see [`is_plain_name_byte`]) or when `buf` is too short: such a name is
/// left to the full parse, so both parsers give every name the same text. Only printable ASCII
/// gets through, so the conversion to &str always succeeds; it is checked as usual, without unsafe
fn plain_name_text<'a>(mut labels: &[u8], buf: &'a mut [u8]) -> Option<&'a str> {
    let mut len = 0;
    while let Some((&label_len, rest)) = labels.split_first() {
        let (label, rest) = rest.split_at(usize::from(label_len));
        if len > 0 {
            *buf.get_mut(len)? = b'.';
            len += 1;
        }
        if !label.iter().all(|&byte| is_plain_name_byte(byte)) {
            return None;
        }
        let text = buf.get_mut(len..len + label.len())?;
        for (text, byte) in text.iter_mut().zip(label) {
            *text = byte.to_ascii_lowercase();
        }
        len += label.len();
        labels = rest;
    }
    std::str::from_utf8(&buf[..len]).ok()
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
    let labels = labels_from_text(text)?;
    if labels.is_empty() {
        return Some(hickory_proto::rr::Name::root());
    }
    hickory_proto::rr::Name::from_labels(labels.iter().map(Vec::as_slice)).ok()
}

/// [`name_from_text`] 读出的各个标签，还没组成名字；组成名字时才查每个标签不超过 63 字节、整个
/// 名字在线上不超过 255 字节。根名没有标签。
/// The labels [`name_from_text`] reads, before they make up a name, which is where a
/// label is held to 63 bytes and the whole name to 255 on the wire. The root has none.
pub(crate) fn labels_from_text(text: &str) -> Option<Vec<Vec<u8>>> {
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() {
        return Some(Vec::new());
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
    Some(labels)
}

/// A label byte the name's text holds as it is (see `name_text`) / 名字文本原样保存的标签字节
fn is_plain_name_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && byte != b'.' && byte != b'\\'
}

/// 报文带的 EDNS 版本（OPT 的 TTL 字段第二个字节）；没有 OPT 或报文读不出来时为 None
/// The EDNS version a message carries (the second byte of the OPT's TTL field); None
/// without an OPT, or when the message cannot be read
pub(crate) fn edns_version(packet: &[u8]) -> Option<u8> {
    let opt = find_opt(packet).ok()??;
    Some(packet[opt.extended_rcode_at + 1])
}

/// 请求的 EDNS 版本不受支持时的回答（RFC 6891 第 6.1.3 节）：RCODE 为 BADVERS（16：头部写低 4 位的
/// 0，OPT 里的扩展 RCODE 写 1），OPT 写 KixDNS 支持的版本 0，问题段照抄。请求读不出问题段时为 None。
/// The answer when the request's EDNS version is not supported (RFC 6891 section 6.1.3):
/// RCODE BADVERS (16: 0 in the header's low 4 bits, extended RCODE 1 in the OPT), an OPT
/// carrying version 0, the one KixDNS supports, and the question copied. None when the
/// question cannot be read.
pub fn badvers_response(query: &[u8]) -> Option<Bytes> {
    let question_end = strict_name_end(query, 12)?.checked_add(4)?;
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
    // 扩展 RCODE 1 / Extended RCODE 1
    push_opt(&mut out, 1, false, &[]);
    Some(Bytes::from(out))
}

/// Whether `response` answers `query`. RFC 1035 section 4.1.1: a reply has QR set
/// and carries the query's opcode; a message without QR (the query itself coming
/// back, say) or with another opcode answers nothing. RFC 5452 §9.1 requires the
/// question section of a reply to match the query before the reply is accepted, in
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
/// 判断 `response` 是否应答 `query`。RFC 1035 第 4.1.1 节：应答的 QR 置位、opcode 和查询的
/// 一样；没有 QR 的报文（比如查询原样弹了回来）或 opcode 不同的报文什么都没回答。
/// RFC 5452 §9.1 要求应答的 question 段与查询一致
/// 才能接受（ID 和源地址之外的第三道校验）。名称比较忽略 ASCII 大小写（兼容 0x20
/// 随机化的上游），QTYPE/QCLASS 必须相同。
///
/// 没有 question 段的应答仅在不携带任何记录（ANCOUNT/NSCOUNT/ARCOUNT 全为 0）时
/// 接受：有些上游对 FORMERR/NOTIMP 这样回，这种应答无记录可入缓存、无法投毒，
/// 保留它就保留了上游快速报错的路径；不回显 question 却带记录的应答没有正当理由，拒绝。
/// 零拷贝：两次名称遍历加一次有界字节比较，无分配。
pub(crate) fn answers_query(query: &[u8], response: &[u8]) -> bool {
    if response.len() < 12 || query.len() < 12 {
        return false;
    }
    // QR set, and the opcode (bits 3-6 of the third byte) the query's
    // QR 置位，opcode（第三个字节的第 3～6 位）和查询的一样
    if response[2] & 0x80 == 0 || (response[2] ^ query[2]) & 0x78 != 0 {
        return false;
    }
    match u16::from_be_bytes([response[4], response[5]]) {
        0 => return response[6..12].iter().all(|&count| count == 0),
        1 => {}
        _ => return false,
    }
    let (Some(query_name_end), Some(response_name_end)) =
        (strict_name_end(query, 12), strict_name_end(response, 12))
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
/// 构造的回答（静态回答、SERVFAIL）也不一定照抄了这些。什么都不用改时不复制；TSIG 签过的应答
/// 原样返回：它不进缓存，也不交给等待者（见 `Engine::insert_dns_cache_entry`、
/// `InflightCleanupGuard::hand_over`），所以只会是这个客户端自己那次转发拿到的。
/// The reply for a client, with what the standards have copied from the query
/// written as `query` has it: the question name's spelling (see
/// [`question_as_asked`]), the RD and CD bits (see [`header_as_asked`]), and whether an
/// OPT comes back and its DO bit (see [`edns_as_asked`]). An answer from the cache or
/// handed to a merged inflight query is shaped as another client asked, and answers
/// KixDNS builds itself (static answers, SERVFAIL) do not always copy these either.
/// Nothing is copied when nothing changes, and a TSIG-signed reply is returned as it is:
/// it is never cached or handed to waiters (see `Engine::insert_dns_cache_entry`,
/// `InflightCleanupGuard::hand_over`), so it is always this client's own forward's.
pub(crate) fn reply_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    // 查询的 OPT 只找一次：它的 DO 位既决定应答留不留 AD，也决定应答的 OPT
    // The query's OPT is looked for once: its DO bit decides both whether the reply keeps
    // AD and the reply's OPT
    shaped_as_asked(reply, query, asked_dnssec_ok(query))
}

/// [`reply_as_asked`]，查询带不带 OPT、DO 位是什么已经知道（快速解析读过它）：`asked_dnssec_ok` 有 OPT 时是它的 DO 位，
/// 没有时是 None。缓存命中不必为此再把查询走一遍
/// [`reply_as_asked`] with whether the query carries an OPT, and its DO bit, known already (the
/// quick parse read it): `asked_dnssec_ok` is the DO bit with an OPT and None without one. A
/// cache hit need not walk the query again for it
pub(crate) fn reply_as_asked_knowing(
    reply: Bytes,
    query: &[u8],
    asked_dnssec_ok: Option<bool>,
) -> Bytes {
    shaped_as_asked(reply, query, Ok(asked_dnssec_ok))
}

/// [`reply_as_asked`]，查询的 DO 位（见 [`asked_dnssec_ok`]）已经找过 / [`reply_as_asked`] with the query's
/// DO bit (see [`asked_dnssec_ok`]) looked for already
fn shaped_as_asked(reply: Bytes, query: &[u8], asked_dnssec_ok: Result<Option<bool>, ()>) -> Bytes {
    // 应答的记录只走一遍：问题名的写法和 RD、CD 位改的都是原位的字节，记录的位置不动，后面找 OPT 用的就是这一遍
    // The reply's records are walked once: the question name's spelling and the RD and CD
    // bits change bytes in place without moving any record, so the OPT is taken from this walk
    let walk = walk_records(&reply);
    // TSIG 的 MAC 盖着整个报文（RFC 8945 第 4.3 节），改哪一位签名都失效：签过的应答原样交出
    // A TSIG's MAC covers the whole message (RFC 8945 section 4.3) and any change breaks
    // it, so a signed reply goes out as it is
    if walk.last_is_tsig {
        return reply;
    }
    edns_as_asked_with(
        header_as_asked(question_as_asked(reply, query), query, asked_dnssec_ok),
        asked_dnssec_ok,
        walk.opt,
    )
}

/// 查询的 DO 位：有 OPT 时是 Some，没有 OPT 时是 None，读不出来时是 Err
/// The query's DO bit: Some with an OPT, None without one, Err when it cannot be read
fn asked_dnssec_ok(query: &[u8]) -> Result<Option<bool>, ()> {
    find_opt(query).map(|opt| opt.map(|opt| opt.dnssec_ok(query)))
}

/// 应答的 RD 位（RFC 1035 第 4.1.1 节）和 CD 位（RFC 4035 第 3.2.2 节）照抄查询的。查询既没带 AD
/// 也没带 DO 时应答不带 AD（RFC 6840 第 5.8 节）：转发时 AD 一律是带着的（见 [`query_asking_ad`]），
/// 所以缓存里的应答带着上游验证的结论，交给每个客户端时再按它自己问的样子去掉
/// The reply with the query's RD bit (RFC 1035 section 4.1.1) and CD bit (RFC 4035
/// section 3.2.2). When the query has neither AD nor DO the reply carries no AD (RFC 6840
/// section 5.8): forwards always ask with AD (see [`query_asking_ad`]), so a cached reply
/// carries what the upstream validated, and each client has it taken off as it asked
fn header_as_asked(reply: Bytes, query: &[u8], asked_dnssec_ok: Result<Option<bool>, ()>) -> Bytes {
    if reply.len() < 12 || query.len() < 12 {
        return reply;
    }
    let (rd, cd) = (query[2] & 0x01, query[3] & 0x10);
    let keeps_ad = query[3] & 0x20 != 0 || asked_dnssec_ok == Ok(Some(true));
    let ad = if keeps_ad { reply[3] & 0x20 } else { 0 };
    if reply[2] & 0x01 == rd && reply[3] & 0x10 == cd && reply[3] & 0x20 == ad {
        return reply;
    }
    let mut copy = BytesMut::from(&reply[..]);
    copy[2] = (copy[2] & !0x01) | rd;
    copy[3] = (copy[3] & !0x30) | cd | ad;
    copy.freeze()
}

/// 发给上游的查询带上 AD 位（RFC 6840 第 5.7 节：带 AD 表示听得懂应答里的 AD），验证型上游给的应答就带着
/// 它验证的结论，不论客户端问时带没带 AD。缓存和合并因此不必按 AD 分开，客户端拿到的 AD 也不再取决于谁先把
/// 缓存填上（见 [`header_as_asked`]）。签过名的查询不改，改了签名就失效
/// A query sent upstream with the AD bit set (RFC 6840 section 5.7: AD says the asker
/// understands AD in the reply), so a validating upstream's reply carries its verdict
/// whether or not the client asked with AD. The cache and merged requests then need not be
/// kept apart by AD, and the AD a client gets no longer depends on who filled the cache
/// (see [`header_as_asked`]). A signed query is left alone: a change would break its signature
pub(crate) fn query_asking_ad(query: std::borrow::Cow<'_, [u8]>) -> std::borrow::Cow<'_, [u8]> {
    if query.len() < 12 || query[3] & 0x20 != 0 || last_record_is_tsig(&query) {
        return query;
    }
    let mut asking = query.into_owned();
    asking[3] |= 0x20;
    std::borrow::Cow::Owned(asking)
}

/// 上游应答去掉 AA 位：AA 说的是作答的服务器是权威（RFC 1035 第 4.1.1 节），KixDNS 转交别人的数据，
/// 从缓存里取出的更不是。签过名的应答不改
/// An upstream reply without its AA bit: AA says the responding server is an authority
/// (RFC 1035 section 4.1.1), and KixDNS hands on others' data, less so from its cache. A
/// signed reply is left alone
pub(crate) fn reply_without_aa(reply: Bytes) -> Bytes {
    if reply.len() < 12 || reply[2] & 0x04 == 0 || last_record_is_tsig(&reply) {
        return reply;
    }
    let mut copy = BytesMut::from(&reply[..]);
    copy[2] &= !0x04;
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
#[cfg(test)]
fn edns_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    let opt = find_opt(&reply);
    edns_as_asked_with(reply, asked_dnssec_ok(query), opt)
}

/// [`edns_as_asked`]，应答的 OPT（[`find_opt`] 的结论）和查询的 DO 位（[`asked_dnssec_ok`]）都已经
/// 找过 / [`edns_as_asked`] with the reply's OPT (what [`find_opt`] concludes) and the query's
/// DO bit (see [`asked_dnssec_ok`]) already looked for
fn edns_as_asked_with(
    reply: Bytes,
    asked_dnssec_ok: Result<Option<bool>, ()>,
    opt: Result<Option<OptRecord>, ()>,
) -> Bytes {
    let Ok(asked_dnssec_ok) = asked_dnssec_ok else {
        return reply;
    };
    let Ok(opt) = opt else {
        return reply;
    };
    let changed = match (asked_dnssec_ok, opt) {
        (Some(dnssec_ok), None) => with_opt(&reply, dnssec_ok, &[]),
        (Some(dnssec_ok), Some(opt)) => (opt.dnssec_ok(&reply) != dnssec_ok).then(|| {
            let mut copy = reply.to_vec();
            copy[opt.extended_rcode_at + 2] ^= 0x80;
            copy
        }),
        (None, Some(opt)) if reply[opt.extended_rcode_at] == 0 => without_opt(&reply, &opt),
        (None, _) => None,
    };
    changed.map_or(reply, Bytes::from)
}

/// 末尾补一条 OPT 的报文（扩展 RCODE 0，见 [`push_opt`]），带着选项 `options`。读不出或最后
/// 一条是 TSIG（它必须排在最后）时为 None。
/// The message with an OPT appended (extended RCODE 0, see [`push_opt`]) carrying
/// `options`. None when it cannot be read or its last record is a TSIG, which must stay
/// last.
fn with_opt(message: &[u8], dnssec_ok: bool, options: &[u8]) -> Option<Vec<u8>> {
    let end = valid_message_len(message)?;
    if last_record_is_tsig(message) {
        return None;
    }
    let ar_count = u16::from_be_bytes([message[10], message[11]]).checked_add(1)?;
    let mut out = Vec::with_capacity(end + 11 + options.len());
    out.extend_from_slice(&message[..end]);
    push_opt(&mut out, 0, dnssec_ok, options);
    out[10..12].copy_from_slice(&ar_count.to_be_bytes());
    Some(out)
}

/// 在 `out` 末尾写一条 OPT 记录：根名、TYPE OPT、CLASS 即 UDP 载荷大小 [`UDP_PAYLOAD`]、扩展 RCODE
/// `extended_rcode`、版本 0、DO 位为 `dnssec_ok` 的标志、选项 `options`。选项不超过 65535 字节。
/// Write an OPT record at the end of `out`: root owner, TYPE OPT, CLASS as the UDP
/// payload size [`UDP_PAYLOAD`], extended RCODE `extended_rcode`, version 0, flags with the DO bit
/// `dnssec_ok`, and `options`, at most 65535 bytes of them.
fn push_opt(out: &mut Vec<u8>, extended_rcode: u8, dnssec_ok: bool, options: &[u8]) {
    out.push(0);
    out.extend_from_slice(&41u16.to_be_bytes());
    out.extend_from_slice(&UDP_PAYLOAD.to_be_bytes());
    out.extend_from_slice(&[extended_rcode, 0, if dnssec_ok { 0x80 } else { 0 }, 0]);
    out.extend_from_slice(&(options.len() as u16).to_be_bytes());
    out.extend_from_slice(options);
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
fn question_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
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

/// 第一个问题名结束的位置，照 [`strict_name_end`] 读；没有问题段或者名字读不了时为 None，名字之后的类型和类别在不在报文
/// 里由调用方查。问题名从偏移 12 开始，压缩指针只能指在它那段的开头之前、又不能指进报文头，所以读得了的问题名都不压缩：
/// 照字节抄进应答、和应答里的比较、逐个标签拼出文本（见 [`plain_name_text`]）都行。hickory 许指针指进报文头，快速解析
/// 读不了、要交给 hickory 的查询先过这一关
/// Where the first question name ends, read as [`strict_name_end`] reads names; None without a
/// question or with a name that cannot be read, whether the type and class after the name are in
/// the message being the caller's to check. The question name starts at offset 12, and a
/// compression pointer can point only before the start of its part and not into the header, so
/// a question name that can be read is uncompressed: it can be copied byte for byte into a
/// reply, compared with the reply's, and have its text built label by label (see
/// [`plain_name_text`]). hickory lets a pointer point into the header, so a query the quick
/// parse cannot read passes this before it goes to hickory
pub(crate) fn question_name_end(packet: &[u8]) -> Option<usize> {
    if packet.get(4..6)? == [0, 0] {
        return None;
    }
    strict_name_end(packet, HEADER_LEN)
}

/// 报文里 OPT 记录的位置 / Where a message's OPT record sits
#[cfg_attr(test, derive(Debug, PartialEq))]
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

impl OptRecord {
    /// 这条 OPT 的 DO 位（TTL 字段第三个字节的最高位，RFC 3225 第 3 节） / This OPT's DO bit (the
    /// top bit of the TTL field's third byte, RFC 3225 section 3)
    fn dnssec_ok(&self, message: &[u8]) -> bool {
        message[self.extended_rcode_at + 2] & 0x80 != 0
    }

    /// 这条 OPT 声明的 UDP 载荷大小（CLASS 字段，就在 TTL 前面，RFC 6891 第 6.1.2 节）/ The UDP payload
    /// size this OPT declares (its CLASS field, right before the TTL, RFC 6891 section 6.1.2)
    fn udp_payload(&self, message: &[u8]) -> u16 {
        u16::from_be_bytes([
            message[self.extended_rcode_at - 2],
            message[self.extended_rcode_at - 1],
        ])
    }
}

/// 报文头里第 `index` 段（0 问题、1 Answer、2 Authority、3 Additional）的计数；报文至少 12 字节
/// The count of section `index` (0 questions, 1 Answer, 2 Authority, 3 Additional) in
/// a message header; the message holds at least 12 bytes
fn section_count(packet: &[u8], index: usize) -> usize {
    u16::from_be_bytes([packet[4 + 2 * index], packet[5 + 2 * index]]) as usize
}

/// 跳过从 12 字节处开始的 `count` 个问题（名字加上类型和类别的 4 个字节），返回其后的位置。
/// 名字读不出时为 None；问题的末尾超出报文不在这里检查，下一个名字读不出、或调用方自己会查到。
/// Skips `count` questions from byte 12 on (each a name plus 4 bytes of type and class)
/// and returns the position after them. None when a name cannot be read; a question
/// ending past the message is not checked here: the next name then cannot be read, or
/// the caller checks.
fn skip_questions(packet: &[u8], count: usize) -> Option<usize> {
    (0..count).try_fold(12usize, |pos, _| {
        strict_name_end(packet, pos)?.checked_add(4)
    })
}

/// 报文里 `start` 处的一条记录：属主名之后的 10 个固定字节必须在报文之内，RDATA 只算出范围、
/// 不检查它是否超出报文，要不要查由调用方定
/// One record of a message, at `start`: the 10 fixed bytes after its owner name must be
/// inside the message; the RDATA's range is only worked out, not checked against the
/// message's end, which the caller checks or not
struct RecordAt {
    /// 固定字段（类型、类别、TTL、RDLENGTH）的开头 / Start of the fixed fields (type, class, TTL, RDLENGTH)
    fixed: usize,
    rr_type: u16,
    rdata: std::ops::Range<usize>,
}

fn record_at(packet: &[u8], start: usize) -> Option<RecordAt> {
    let fixed = strict_name_end(packet, start)?;
    let header = packet.get(fixed..fixed.checked_add(10)?)?;
    let rdata_start = fixed + 10;
    let rd_len = u16::from_be_bytes([header[8], header[9]]) as usize;
    Some(RecordAt {
        fixed,
        rr_type: u16::from_be_bytes([header[0], header[1]]),
        rdata: rdata_start..rdata_start.checked_add(rd_len)?,
    })
}

/// 走到报文 Additional 段里的 OPT 记录。报文结构不对、OPT 不止一条或出现在 Additional
/// 以外时为 Err（RFC 6891 第 6.1.1 节：这样的报文是 FORMERR）。
/// Walk a message to the OPT record in its Additional section. Err when the
/// message is malformed, or has more than one OPT record or one outside
/// Additional (RFC 6891 section 6.1.1: such a message is FORMERR).
fn find_opt(packet: &[u8]) -> Result<Option<OptRecord>, ()> {
    walk_records(packet).opt
}

/// 把报文的记录走一遍，同时得出 [`find_opt`] 和 [`last_record_is_tsig`] 两者的结论：照应答规整时
/// 两样都要，同一份应答不必走两遍
/// Walks a message's records once for what [`find_opt`] and [`last_record_is_tsig`] each
/// conclude: shaping a reply needs both, and one walk serves them
struct RecordsWalk {
    opt: Result<Option<OptRecord>, ()>,
    last_is_tsig: bool,
}

fn walk_records(packet: &[u8]) -> RecordsWalk {
    const UNREADABLE: RecordsWalk = RecordsWalk {
        opt: Err(()),
        last_is_tsig: false,
    };
    if packet.len() < 12 {
        return UNREADABLE;
    }
    let before_additional = section_count(packet, 1) + section_count(packet, 2);
    let records = before_additional + section_count(packet, 3);
    let Some(mut pos) = skip_questions(packet, section_count(packet, 0)) else {
        return UNREADABLE;
    };
    let mut opt = Ok(None);
    let mut last_type = None;
    for index in 0..records {
        let Some(record) = record_at(packet, pos) else {
            return UNREADABLE;
        };
        // RDATA 超出报文的记录让 OPT 读不成；最后一条这样的记录照样算作最后一条（原来如此）
        // A record whose RDATA runs past the message leaves the OPT unreadable; as the last
        // record it still counts as the last one (as it always has)
        if record.rdata.end > packet.len() {
            opt = Err(());
        } else if record.rr_type == 41
            && let Ok(found) = &mut opt
        {
            if index < before_additional || found.is_some() {
                opt = Err(());
            } else {
                *found = Some(OptRecord {
                    start: pos,
                    extended_rcode_at: record.fixed + 4,
                    rdlen_at: record.fixed + 8,
                    rdata: record.rdata.clone(),
                    last: index + 1 == records,
                });
            }
        }
        last_type = Some(record.rr_type);
        pos = record.rdata.end;
    }
    RecordsWalk {
        opt,
        last_is_tsig: last_type == Some(250),
    }
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
    /// 是否完全符合 RFC 7871 第 6 节：地址合规（见 [`Self::address_bits`]），SCOPE 也不超过地址长度。
    /// Whether it follows RFC 7871 section 6 to the letter: a proper address (see
    /// [`Self::address_bits`]), and a SCOPE within the address length too.
    fn is_well_formed(&self, packet: &[u8]) -> bool {
        self.address_bits(packet)
            .is_some_and(|bits| self.scope <= bits)
    }

    /// 地址合规时是地址族的位数：已知的地址族、前缀不超过地址长度、ADDRESS 恰好 ceil(前缀/8) 个字节、前缀之后的位为零。
    /// 不合规的查询要回 FORMERR（RFC 7871 第 6 节、第 7.2.1 节）
    /// The family's bit count when the address is proper: a known family, a prefix within the
    /// address length, an ADDRESS of exactly ceil(prefix/8) octets with zero bits beyond the
    /// prefix. A query with an improper one is answered FORMERR (RFC 7871 sections 6 and 7.2.1)
    fn address_bits(&self, packet: &[u8]) -> Option<u8> {
        let bits = match self.family {
            1 => 32,
            2 => 128,
            _ => return None,
        };
        let address = &packet[self.address.clone()];
        let spare = self.source_prefix % 8;
        (self.source_prefix <= bits
            && address.len() == (self.source_prefix as usize).div_ceil(8)
            && (spare == 0
                || address
                    .last()
                    .is_some_and(|last| last & (0xFF >> spare) == 0)))
        .then_some(bits)
    }

    fn subnet(&self, packet: &[u8]) -> crate::ecs::EcsKey {
        crate::ecs::EcsKey::from_wire(
            self.family,
            self.source_prefix,
            &packet[self.address.clone()],
        )
    }
}

/// OPT 的 RDATA（在 `rdata`）里的选项，依次给出代码和整个选项（含 4 字节的头）的范围。选项结构
/// 不对（头或内容超出 RDATA）时给出一个 Err，之后就结束。
/// The options in the OPT RDATA at `rdata`, in order, each its code and the range
/// of the whole option (its 4-byte header included). A malformed option (its header
/// or content past the RDATA) gives one Err, and then the options end.
fn edns_options(
    packet: &[u8],
    rdata: std::ops::Range<usize>,
) -> impl Iterator<Item = Result<(u16, std::ops::Range<usize>), ()>> + '_ {
    let mut pos = rdata.start;
    std::iter::from_fn(move || {
        if pos >= rdata.end {
            return None;
        }
        let option = pos
            .checked_add(4)
            .filter(|&header_end| header_end <= rdata.end)
            .and_then(|header_end| {
                header_end
                    .checked_add(u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize)
            })
            .filter(|&end| end <= rdata.end)
            .map(|end| (u16::from_be_bytes([packet[pos], packet[pos + 1]]), pos..end));
        pos = option.as_ref().map_or(rdata.end, |(_, bytes)| bytes.end);
        Some(option.ok_or(()))
    })
}

/// OPT 的 RDATA 里的 ECS 选项（RFC 7871 第 6 节）。选项结构不对、或者不止一个 ECS 选项时为 Err。
/// The ECS option in an OPT record's RDATA (RFC 7871 section 6). Err when the
/// options are malformed or there is more than one ECS option.
fn ecs_option(packet: &[u8], rdata: std::ops::Range<usize>) -> Result<Option<EcsOption>, ()> {
    let mut found = None;
    for option in edns_options(packet, rdata) {
        let (code, bytes) = option?;
        if code == 8 {
            let header_end = bytes.start + 4;
            if bytes.end - header_end < 4 || found.is_some() {
                return Err(());
            }
            found = Some(EcsOption {
                family: u16::from_be_bytes([packet[header_end], packet[header_end + 1]]),
                source_prefix: packet[header_end + 2],
                scope: packet[header_end + 3],
                address: header_end + 4..bytes.end,
                bytes,
            });
        }
    }
    Ok(found)
}

/// 查询（OPT 的 RDATA 在 `rdata`）里客户端自己带的 ECS。地址不合规（见 `EcsOption::address_bits`）或者不止一个 ECS
/// 选项时为 Err，这样的查询回 FORMERR（见 [`malformed_ecs`]）；SCOPE 不为 0 的得到 `EcsKey::opaque`（查询里它必须为 0，
/// RFC 7871 第 6 节却没要求为此回 FORMERR）：它照样会被原样转给上游，应答却说不准适用于谁。
/// The ECS a query carries itself, its OPT RDATA at `rdata`. Err for an improper address (see
/// `EcsOption::address_bits`) or more than one ECS option, and such a query is answered FORMERR
/// (see [`malformed_ecs`]); a nonzero SCOPE gets an `EcsKey::opaque` (it must be 0 in a query,
/// but RFC 7871 section 6 asks no FORMERR for it): it still goes upstream as it is, but whom
/// the answer applies to is unclear.
fn query_subnet(
    packet: &[u8],
    rdata: std::ops::Range<usize>,
) -> Result<Option<crate::ecs::EcsKey>, ()> {
    let Some(option) = ecs_option(packet, rdata.clone())? else {
        return Ok(None);
    };
    option.address_bits(packet).ok_or(())?;
    Ok(Some(if option.scope == 0 {
        option.subnet(packet)
    } else {
        crate::ecs::EcsKey::opaque(&packet[rdata])
    }))
}

/// 查询里的 ECS 选项不合规，要回 FORMERR（RFC 7871 第 6 节、第 7.2.1 节，见 `query_subnet`）。快速解析不收这样的查询，
/// 所以只为快速解析读不了的查询看一遍
/// Whether the query's ECS option is improper and to be answered FORMERR (RFC 7871 sections 6
/// and 7.2.1, see `query_subnet`). The quick parse takes no such query, so only a query it
/// cannot read is looked at for this
pub(crate) fn malformed_ecs(query: &[u8]) -> bool {
    matches!(find_opt(query), Ok(Some(opt)) if query_subnet(query, opt.rdata.clone()).is_err())
}

/// 查询报文里客户端自己带的 ECS（见 `query_subnet`）。报文或选项读不出来时按读不懂的选项算。
/// The ECS a query message carries itself (see `query_subnet`). A message or an option that
/// cannot be read counts as an option that cannot be read.
pub(crate) fn client_subnet(packet: &[u8]) -> Option<crate::ecs::EcsKey> {
    match find_opt(packet) {
        Ok(None) => None,
        Ok(Some(opt)) => query_subnet(packet, opt.rdata.clone())
            .unwrap_or_else(|()| Some(crate::ecs::EcsKey::opaque(&packet[opt.rdata]))),
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
    match without_options(&reply, &opt, &[8]) {
        Ok(Some(out)) => Ok(Bytes::from(out)),
        Ok(None) => Ok(reply),
        Err(()) => Err(reply),
    }
}

/// 去掉 OPT 里代码在 `codes` 之中的选项之后的报文。OPT 必须是最后一条记录（见 `OptRecord::last`）。
/// 没有这样的选项时为 Ok(None)，选项结构不对时为 Err。
/// The message without the options in its OPT coded one of `codes`, the OPT being the
/// last record (see `OptRecord::last`). Ok(None) when there is no such option,
/// Err when the options are malformed.
fn without_options(message: &[u8], opt: &OptRecord, codes: &[u16]) -> Result<Option<Vec<u8>>, ()> {
    debug_assert!(opt.last, "only a last OPT can change its length");
    let mut kept = Vec::new();
    let mut found = false;
    for option in edns_options(message, opt.rdata.clone()) {
        let (option_code, bytes) = option?;
        if codes.contains(&option_code) {
            found = true;
        } else {
            kept.push(bytes);
        }
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

/// RFC 7830 的 PADDING 选项代码 / The PADDING option code of RFC 7830
const PADDING: u16 = 12;

/// RFC 7828 的 edns-tcp-keepalive 选项代码 / The edns-tcp-keepalive option code of RFC 7828
const TCP_KEEPALIVE: u16 = 11;

/// 只在相邻两跳之间有意义的选项：cookie 是两跳之间的（RFC 7873），填充的长短按那一跳的传输来，明文传输上
/// 不许用（RFC 7830 第 6 节），edns-tcp-keepalive 说的是那一跳的 TCP 连接，UDP 上不许带（RFC 7828 第 3.2 节）
/// The options that mean something between two neighbouring hops only: a cookie belongs
/// between two hops (RFC 7873), padding is sized for one hop's transport and must not be used
/// over a cleartext one (RFC 7830 section 6), and edns-tcp-keepalive speaks of that hop's TCP
/// connection and must not be sent over UDP (RFC 7828 section 3.2)
const HOP_BY_HOP: [u16; 3] = [COOKIE, PADDING, TCP_KEEPALIVE];

/// OPT 的 RDATA（在 `rdata`）里有没有代码在 `codes` 之中的选项；选项结构不对时为 false
/// Whether the OPT RDATA at `rdata` has an option coded one of `codes`; false when the
/// options are malformed
fn has_option(message: &[u8], rdata: std::ops::Range<usize>, codes: &[u16]) -> bool {
    edns_options(message, rdata)
        .map_while(Result::ok)
        .any(|(option_code, _)| codes.contains(&option_code))
}

/// 报文去掉只在两跳之间有意义的选项（[`HOP_BY_HOP`]）之后的样子。没有这些选项，或者去不掉（OPT 后面还有
/// 记录、最后一条是 TSIG：改了签名就不对了；或者 hickory 读不了）时为 None。
/// The message without the options meaning something between two hops only (see
/// [`HOP_BY_HOP`]). None when it has none, or when they cannot be taken out: records
/// follow the OPT and the last one is a TSIG, which a change would invalidate, or
/// hickory cannot read the message.
fn hop_options_removed(message: &[u8]) -> Option<Vec<u8>> {
    let opt = find_opt(message).ok()??;
    if opt.last {
        return without_options(message, &opt, &HOP_BY_HOP).ok().flatten();
    }
    // 改 OPT 的长度会挪动它后面的记录（见 `OptRecord::last`），确有这些选项时交给 hickory 重新编码
    // Changing the OPT's length would move the records after it (see
    // `OptRecord::last`), so hickory encodes the message again when such an option is there
    if !has_option(message, opt.rdata, &HOP_BY_HOP) || last_record_is_tsig(message) {
        return None;
    }
    let mut msg = Message::from_vec(message).ok()?;
    let options = msg.edns.as_mut()?.options_mut();
    for code in HOP_BY_HOP {
        options.remove(hickory_proto::rr::rdata::opt::EdnsCode::from(code));
    }
    msg.to_vec().ok()
}

/// 发往上游的查询去掉只在两跳之间有意义的选项。客户端的 cookie 是它和 KixDNS 之间的，转给上游的话，
/// 上游会把它带回来，随应答进缓存，再交给别的客户端；客户端的填充是按它到 KixDNS 这一跳补的，到上游
/// 这一跳要么不该填充（明文），要么按这一跳重新补（见 [`padded_query`]）。没有这些选项或者去不掉时原样
/// 交回（见 `hop_options_removed`）。
/// The query for an upstream without the options meaning something between two hops
/// only. A client's cookie belongs between it and KixDNS, and forwarded it comes back
/// from the upstream, enters the cache with the answer and goes to other clients; a
/// client's padding was sized for its hop to KixDNS, and the hop to the upstream either
/// takes none (cleartext) or its own (see [`padded_query`]). Handed back as it is when it
/// has none or they cannot be taken out (see `hop_options_removed`).
pub(crate) fn query_without_hop_options(query: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    hop_options_removed(query).map_or(std::borrow::Cow::Borrowed(query), std::borrow::Cow::Owned)
}

/// 上游应答去掉只在两跳之间有意义的选项。KixDNS 不发也不核对自己的 cookie，应答里的 cookie 只可能是
/// 上游自己塞的（查询已经不带了）；上游的填充是按它到 KixDNS 这一跳补的，应答进了缓存会经明文传输交给
/// 客户端。两样都不该进缓存、也不该交给客户端。去不掉时原样交回。
/// An upstream reply without the options meaning something between two hops only.
/// KixDNS neither sends nor checks a cookie of its own, so one in a reply can only be the
/// upstream's own addition (queries no longer carry any); the upstream's padding was sized
/// for its hop to KixDNS, and a cached reply goes to clients over cleartext transports.
/// Neither belongs in the cache or in a client's reply. Handed back as it is when they
/// cannot be taken out.
pub(crate) fn reply_without_hop_options(reply: Bytes) -> Bytes {
    hop_options_removed(&reply).map_or(reply, Bytes::from)
}

/// 加密传输上的查询补齐到的块长（RFC 8467 第 4.1 节）/ The block length a query over an encrypted
/// transport is padded to (RFC 8467 section 4.1)
const QUERY_BLOCK: usize = 128;

/// 加密传输上的应答补齐到的块长（RFC 8467 第 4.1 节）/ The block length a reply over an encrypted
/// transport is padded to (RFC 8467 section 4.1)
const REPLY_BLOCK: usize = 468;

/// 经加密传输（DoT、DoH、DoQ）发往上游的查询：OPT 的末尾加一个全是零的 PADDING 选项（RFC 7830），整个
/// 查询补到 [`QUERY_BLOCK`] 的整数倍（RFC 8467 第 4.1 节），密文的长度就看不出问的是什么。没有 OPT 的
/// 查询补一条带这个选项的 OPT：RFC 9250 第 5.4 节要求 DoQ 的每个查询都填充，上游也只给带 EDNS 的查询填充
/// 应答（RFC 7830 第 4 节）。签过名的、OPT 后面还有记录的（见 `OptRecord::last`）、读不出的和补了就超过
/// 65535 字节的查询原样交回。查询里原有的填充已经去掉了（见 [`query_without_hop_options`]）
/// A query for an upstream over an encrypted transport (DoT, DoH, DoQ): a PADDING option of
/// zeros (RFC 7830) ends its OPT, bringing the whole query to a multiple of [`QUERY_BLOCK`]
/// (RFC 8467 section 4.1), so the length of the ciphertext does not tell what is asked. A
/// query without an OPT gets one carrying the option: RFC 9250 section 5.4 has every DoQ
/// query padded, and an upstream pads its reply only to a query with EDNS (RFC 7830
/// section 4). A signed query, one with records after its OPT (see `OptRecord::last`), one
/// that cannot be read and one that padding would take past 65535 bytes are handed back as
/// they are. Any padding the query had is already gone (see [`query_without_hop_options`])
pub(crate) fn padded_query(query: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    padding_added(query, QUERY_BLOCK)
        .map_or(std::borrow::Cow::Borrowed(query), std::borrow::Cow::Owned)
}

/// 经入站 DoH 交回的应答：查询带了 PADDING 选项时补到 [`REPLY_BLOCK`] 的整数倍（RFC 8467 第 4.1 节），
/// 补法同 [`padded_query`]，RFC 7830 第 4 节要求这样的查询得到填充过的应答。查询没带时原样交回：交给客户端
/// 的应答本身不带填充（见 [`reply_without_hop_options`]）
/// A reply handed back over inbound DoH: padded to a multiple of [`REPLY_BLOCK`] (RFC 8467
/// section 4.1) the way [`padded_query`] pads when the query carried a PADDING option, as RFC
/// 7830 section 4 requires for such a query. Without one it is handed back as it is: a reply
/// for a client carries no padding of its own (see [`reply_without_hop_options`])
pub(crate) fn reply_padded_as_asked(reply: Bytes, query: &[u8]) -> Bytes {
    let asked = find_opt(query)
        .ok()
        .flatten()
        .is_some_and(|opt| has_option(query, opt.rdata, &[PADDING]));
    if !asked {
        return reply;
    }
    padding_added(&reply, REPLY_BLOCK).map_or(reply, Bytes::from)
}

/// 补到 `block` 的整数倍的报文（见 [`padded_query`]）；原样交回时为 None / The message padded to a
/// multiple of `block` (see [`padded_query`]); None when it is handed back as it is
fn padding_added(message: &[u8], block: usize) -> Option<Vec<u8>> {
    let walk = walk_records(message);
    if walk.last_is_tsig {
        return None;
    }
    // 填充选项接在最后一条记录 OPT 的末尾；没有 OPT 时末尾补一条空的，它的 RDLENGTH 是最后两个字节
    // The padding option goes at the end of the OPT as the last record; without an OPT an
    // empty one is appended, its RDLENGTH being the last two bytes
    let (mut out, rdlen_at) = match walk.opt.ok()? {
        Some(opt) if opt.last => {
            let mut out = Vec::with_capacity(opt.rdata.end + 4 + block);
            out.extend_from_slice(&message[..opt.rdata.end]);
            (out, opt.rdlen_at)
        }
        Some(_) => return None,
        None => {
            let out = with_opt(message, false, &[])?;
            let rdlen_at = out.len() - 2;
            (out, rdlen_at)
        }
    };
    let padded = (out.len() + 4).next_multiple_of(block);
    if padded > usize::from(u16::MAX) {
        return None;
    }
    let pad = padded - out.len() - 4;
    let rd_len = u16::from_be_bytes([out[rdlen_at], out[rdlen_at + 1]]) + 4 + pad as u16;
    out[rdlen_at..rdlen_at + 2].copy_from_slice(&rd_len.to_be_bytes());
    out.extend_from_slice(&PADDING.to_be_bytes());
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.resize(padded, 0);
    Some(out)
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
        None => with_opt(stored, false, &option),
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
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode};
    if last_record_is_tsig(message) {
        return None;
    }
    let mut msg = Message::from_vec(message).ok()?;
    match echo {
        Some((subnet, scope)) => {
            let address = subnet.ip()?;
            crate::ecs::set_ecs_option(
                &mut msg,
                ClientSubnet::new(address, subnet.source_prefix, scope),
            );
        }
        None => {
            msg.edns.as_mut()?.options_mut().remove(EdnsCode::Subnet);
        }
    }
    msg.to_vec().ok()
}

/// 报文最后一条记录是不是 TSIG（RFC 8945 要求它排在最后）
/// Whether a message's last record is a TSIG (RFC 8945 keeps it last)
pub(crate) fn last_record_is_tsig(packet: &[u8]) -> bool {
    walk_records(packet).last_is_tsig
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

    let mut pos = skip_questions(packet, section_count(packet, 0))?;
    for _ in 0..(1..4).map(|index| section_count(packet, index)).sum() {
        pos = record_at(packet, pos)?.rdata.end;
    }
    (pos <= packet.len()).then_some(pos)
}

/// 快速解析响应包，仅提取 RCODE、TC 标志和 TTL 范围 / Quick parse response packet, extracting only RCODE, TC flag and TTL range
/// 避免全量解析 Message / Avoid full Message parsing
#[derive(Debug, Clone)]
pub struct QuickResponse {
    pub rcode: hickory_proto::op::ResponseCode,
    pub min_ttl: u32,
    /// TC (Truncated) flag - 响应被截断，应使用 TCP 重试 / Response was truncated, retry with TCP
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
        pos = strict_name_end(packet, pos)?;
        pos += 4; // QTYPE(2) + QCLASS(2)
        if pos > packet_len {
            return None;
        }
    }

    soa_negative_ttl_at(packet, pos, ns_count)
}

/// `pos` 是 Authority 段的开头 / `pos` is where the Authority section starts
fn soa_negative_ttl_at(packet: &[u8], mut pos: usize, ns_count: u16) -> Option<u32> {
    let packet_len = packet.len();

    // Walk Authority section looking for SOA (type 6) / 遍历 Authority 部分查找 SOA (type 6)
    for _ in 0..ns_count {
        pos = strict_name_end(packet, pos)?;
        if pos + 10 > packet_len {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let ttl = received_ttl(u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]));
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
            let after_mname = strict_name_end(packet, pos)?;
            // Skip RNAME (domain name in rdata)
            // 跳过 RNAME（rdata 中的域名）
            let after_rname = strict_name_end(packet, after_mname)?;
            // 5 × u32 = 20 bytes: SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
            let fixed_fields_start = after_rname;
            if fixed_fields_start + 20 > rdata_end {
                return None;
            }
            // MINIMUM is the last 4 bytes of the fixed fields
            // MINIMUM 是固定字段的最后 4 字节
            // MINIMUM serves as the negative answer's TTL, so it is read as one too
            // MINIMUM 用作否定应答的 TTL，所以也按 TTL 读
            let minimum = received_ttl(u32::from_be_bytes([
                packet[fixed_fields_start + 16],
                packet[fixed_fields_start + 17],
                packet[fixed_fields_start + 18],
                packet[fixed_fields_start + 19],
            ]));
            // RFC 2308 §5: negative TTL = min(SOA.minimum, SOA.ttl)
            return Some(minimum.min(ttl));
        }

        // Skip rdata for non-SOA records / 跳过非 SOA 记录的 rdata
        pos += rdlength;
    }

    None
}

/// 应答的记录结构经得起完整走一遍，可以照快速解析的结果缓存：
/// - 每个名字都是规范的标签（不超过 63 字节），整个名字不超过 255 字节，压缩指针只往前指（见
///   [`strict_name_end`]）；
/// - 每条记录的 RDATA 都在报文之内；
/// - 记录都是这里逐字节检查过的类型：A、AAAA 的长度对；NS、CNAME、PTR、DNAME、MX、SOA、SRV 里的
///   名字恰好填满 RDATA；TXT 的字符串、HINFO 的两个字符串恰好填满 RDATA；OPT 只在 Additional 段、
///   最多一条、属主是根名，选项结构完整，ECS 选项合乎 RFC 7871 第 6 节。
///
/// 不合格不等于读不了：别的类型（HTTPS、DNSSEC 记录、TSIG 等）hickory 会细读内容，这里不照搬，
/// 调用方改由 hickory 读，hickory 也读不了的不缓存。
/// Whether a reply's record structure holds up to a complete walk, so it can be
/// cached as the quick parse read it:
/// - every name is made of proper labels (at most 63 bytes), at most 255 bytes in all,
///   with compression pointers that only point back (see [`strict_name_end`]);
/// - every record's RDATA lies within the message;
/// - every record is of a type checked here byte by byte: A and AAAA of the right
///   length; NS, CNAME, PTR, DNAME, MX, SOA and SRV with names that fill their RDATA
///   exactly; TXT strings and the two HINFO strings filling it exactly; OPT only in
///   Additional, at most once, owned by the root, with whole options and an ECS option
///   as RFC 7871 section 6 has it.
///
/// Failing this does not mean unreadable: hickory reads the contents of other types
/// (HTTPS, the DNSSEC records, TSIG and so on) in detail, which is not repeated here.
/// The caller has hickory read the reply instead, and caches nothing hickory cannot
/// read either.
pub(crate) fn well_formed_reply(packet: &[u8]) -> bool {
    well_formed_records(packet).is_some()
}

fn well_formed_records(packet: &[u8]) -> Option<()> {
    let count = |at: usize| {
        packet
            .get(at..at + 2)
            .map(|n| u16::from_be_bytes([n[0], n[1]]) as usize)
    };
    let (before_additional, additional) = (count(6)? + count(8)?, count(10)?);
    let mut pos = 12usize;
    for _ in 0..count(4)? {
        pos = strict_name_end(packet, pos)?.checked_add(4)?;
        if pos > packet.len() {
            return None;
        }
    }
    let mut opt_seen = false;
    for index in 0..before_additional + additional {
        let owner = pos;
        pos = strict_name_end(packet, pos)?;
        let fixed_end = pos.checked_add(10)?;
        let header = packet.get(pos..fixed_end)?;
        let rr_type = u16::from_be_bytes([header[0], header[1]]);
        let rd_len = u16::from_be_bytes([header[8], header[9]]) as usize;
        let rdata = fixed_end..fixed_end.checked_add(rd_len)?;
        if rdata.end > packet.len() {
            return None;
        }
        if rr_type == 41 {
            if index < before_additional || opt_seen || packet[owner] != 0 {
                return None;
            }
            opt_seen = true;
            // 选项结构不对时 `ecs_option` 也是 Err / `ecs_option` is Err for malformed options too
            match ecs_option(packet, rdata.clone()) {
                Ok(None) => {}
                Ok(Some(ecs)) if ecs.is_well_formed(packet) => {}
                _ => return None,
            }
        } else {
            well_formed_rdata(packet, rr_type, rdata.clone())?;
        }
        pos = rdata.end;
    }
    Some(())
}

/// 一条记录的 RDATA 结构对不对；不在这里检查的类型都算不对（见 [`well_formed_reply`]）
/// Whether one record's RDATA is well formed; a type not checked here is not (see
/// [`well_formed_reply`])
fn well_formed_rdata(packet: &[u8], rr_type: u16, rdata: std::ops::Range<usize>) -> Option<()> {
    // A name starting at `at` that ends exactly where the RDATA does
    // 从 `at` 开始、恰好在 RDATA 结尾处结束的名字
    let last_name =
        |at: usize| (at < rdata.end && strict_name_end(packet, at)? == rdata.end).then_some(());
    // How many character strings, each with its length byte, fill the RDATA exactly
    // 恰好填满 RDATA 的字符串（各带长度字节）有几个
    let strings = || {
        let (mut at, mut count) = (rdata.start, 0usize);
        while at < rdata.end {
            at += 1 + packet[at] as usize;
            count += 1;
        }
        (at == rdata.end).then_some(count)
    };
    match rr_type {
        1 => (rdata.len() == 4).then_some(()),
        28 => (rdata.len() == 16).then_some(()),
        // NS, CNAME, PTR, DNAME
        2 | 5 | 12 | 39 => last_name(rdata.start),
        // MX: preference, exchange / MX：优先级、交换主机
        15 => last_name(rdata.start + 2),
        // SRV: priority, weight, port, target / SRV：优先级、权重、端口、目标
        33 => last_name(rdata.start + 6),
        // SOA: MNAME, RNAME, five 32-bit fields / SOA：MNAME、RNAME、五个 32 位字段
        6 => {
            let after_rname = strict_name_end(packet, strict_name_end(packet, rdata.start)?)?;
            (after_rname.checked_add(20)? == rdata.end).then_some(())
        }
        // HINFO: CPU and OS / HINFO：CPU 和操作系统
        13 => (strings()? == 2).then_some(()),
        // TXT: one or more strings / TXT：一个或多个字符串
        16 => (strings()? >= 1).then_some(()),
        _ => None,
    }
}

/// 读一个名字，返回它在 `start` 处的编码结束的位置；读名字、跳过名字的地方都用它（问题名见 [`question_name_end`]）。标签
/// 不超过 63 字节，整个名字连同压缩指针跳过去读到的部分不超过 [`MAX_NAME_LEN`]；压缩指针跳过去以后读到的每个字节都在指针
/// 所在那段的开头之前，所以指针只能往前指，不会绕圈，也不会读进跳出来的那段（和 hickory 的规则一样）；指针也不能指进报文头
/// （偏移 12 以前），那里不会有名字，报文头一改（换事务 ID）名字就跟着变；最多跳 16 次。长度和跳数不数的话，许多条记录的
/// 属主名指着一长串标签或者一长串指针时，每个名字都要把它走一遍，走一遍报文的步数是报文长度的平方
/// Reads a name and returns where its encoding at `start` ends; wherever names are read or
/// skipped this is used (for the question name see [`question_name_end`]). Labels of at most 63
/// bytes, and at most [`MAX_NAME_LEN`] in all, what compression pointers lead to included;
/// everything read after a pointer lies before the start of the part the pointer is in, so a
/// pointer can only point back, cannot loop, and cannot read into the part it jumped from
/// (hickory's rule too); nor can a pointer point into the header (before offset 12), where no
/// name starts and where the name would change with the header (a new transaction ID); at most
/// 16 jumps. Without counting the length and the jumps, a long run of labels or of pointers that
/// the owners of many records point into is walked for each of them, and one walk of the
/// message takes the square of its length in steps
fn strict_name_end(packet: &[u8], start: usize) -> Option<usize> {
    let (mut pos, mut part_start, mut limit) = (start, start, usize::MAX);
    let (mut end, mut length, mut jumps) = (None, 1usize, 0);
    loop {
        if pos >= limit {
            return None;
        }
        let len = *packet.get(pos)? as usize;
        match len {
            0 => return Some(end.unwrap_or(pos + 1)),
            1..=63 => {
                length += 1 + len;
                if length > MAX_NAME_LEN {
                    return None;
                }
                pos += 1 + len;
            }
            0xC0..=0xFF => {
                let target = (len & 0x3F) << 8 | *packet.get(pos + 1)? as usize;
                jumps += 1;
                if target < HEADER_LEN || jumps > 16 {
                    return None;
                }
                end.get_or_insert(pos + 2);
                (pos, limit, part_start) = (target, part_start, target);
            }
            _ => return None,
        }
    }
}

/// 读到的 TTL 当作多少秒：最高位为 1 的值当作 0（RFC 2181 第 8 节：TTL 只用低 31 位，最高位
/// 置位的值整个按 0 处理）。
/// What a TTL as received counts as: a value with the top bit set counts as 0 (RFC 2181
/// section 8: a TTL uses the low 31 bits, and a value with the most significant bit set
/// is treated as if the entire value were zero).
#[inline]
pub(crate) fn received_ttl(raw: u32) -> u32 {
    if raw & 0x8000_0000 != 0 { 0 } else { raw }
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

    // RFC 6891 section 6.1.3: the OPT's extended RCODE holds the upper 8 bits of the
    // 12-bit RCODE, the header the lower 4
    // RFC 6891 第 6.1.3 节：12 位 RCODE 的高 8 位在 OPT 的扩展 RCODE 里，低 4 位在头部
    let extended_rcode = match find_opt(packet) {
        Ok(Some(opt)) => packet[opt.extended_rcode_at],
        _ => 0,
    };
    let rcode = hickory_proto::op::ResponseCode::from(extended_rcode, packet[3] & 0x0F);

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);

    if an_count == 0 {
        // RFC 2308 §5: For negative responses (NXDOMAIN/NODATA), the negative
        // cache TTL is min(SOA.minimum, SOA.ttl) from the authority section.
        // If no SOA is present, return TTL=0 (must not be cached per RFC 2308 §4).
        //
        // RFC 2308 §5: 对于否定响应 (NXDOMAIN/NODATA)，负缓存 TTL 为 authority 中
        // SOA 的 min(SOA.minimum, SOA.ttl)。无 SOA 时返回 TTL=0（按 RFC 2308 §4 不可缓存）。
        let ttl = (ns_count > 0)
            .then(|| extract_soa_negative_ttl_wire(packet, qd_count, ns_count))
            .flatten()
            .unwrap_or(0);
        return Some(QuickResponse {
            rcode,
            min_ttl: ttl,
            truncated,
        });
    }

    let mut pos = 12;
    let packet_len = packet.len();
    let mut asked = None;

    // Skip Questions / 跳过问题部分
    for _ in 0..qd_count {
        // Skip Name / 跳过名称
        pos = strict_name_end(packet, pos)?;
        // Skip Type(2) + Class(2) / 跳过类型(2) + 类别(2)
        if pos + 4 > packet_len {
            return None;
        }
        asked.get_or_insert(u16::from_be_bytes([packet[pos], packet[pos + 1]]));
        pos += 4;
    }

    // 至少有一条应答记录（上面已返回 an_count 为 0 的情况），所以它会被下面设过
    // There is at least one answer record (an_count 0 returned above), so it gets set below
    let mut min_ttl = u32::MAX;
    let mut only_aliases = true;

    // Scan Answers / 扫描应答部分
    for _ in 0..an_count {
        // Skip Name / 跳过名称
        pos = strict_name_end(packet, pos)?;

        if pos + 10 > packet_len {
            return None;
        }

        // Type(2) Class(2) TTL(4) RDLen(2) / 类型(2) 类别(2) TTL(4) 数据长度(2)
        // Offset 0: Type / 偏移量 0：类型
        // Offset 2: Class / 偏移量 2：类别
        // Offset 4: TTL / 偏移量 4：TTL
        // Offset 8: RDLen / 偏移量 8：数据长度

        only_aliases &=
            only_points_elsewhere(u16::from_be_bytes([packet[pos], packet[pos + 1]]), asked);
        let ttl = received_ttl(u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]));
        min_ttl = min_ttl.min(ttl);

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rd_len;
    }

    if says_no_despite_answers(rcode, only_aliases) {
        let negative = soa_negative_ttl_at(packet, pos, ns_count).unwrap_or(0);
        min_ttl = min_ttl.min(negative);
    }

    Some(QuickResponse {
        rcode,
        min_ttl,
        truncated,
    })
}

/// 这条答案记录只把问题指向别处（CNAME、DNAME 和它们的签名），不是在回答问的类型
/// This answer record only points the question elsewhere (a CNAME, a DNAME, or their
/// signature) rather than answering the type asked
#[inline]
pub(crate) fn only_points_elsewhere(record_type: u16, asked: Option<u16>) -> bool {
    const CNAME: u16 = 5;
    const DNAME: u16 = 39;
    const RRSIG: u16 = 46;
    const ANY: u16 = 255;
    matches!(record_type, CNAME | DNAME | RRSIG)
        && asked.is_some_and(|asked| asked != record_type && asked != ANY)
}

/// 带答案的应答说的还是「没有」：NXDOMAIN，或者 NOERROR 但答案全是别名，没有问的类型
/// （RFC 2308 第 2 节）。答案段里的别名可以留到自己的 TTL，这个否定事实只能留到 SOA 的负缓存
/// TTL（第 5 节），没有 SOA 就不能缓存（第 4 节），整份应答照短的算。
/// A reply with answers that still says no: NXDOMAIN, or NOERROR whose answers are all
/// aliases with none of the type asked (RFC 2308 section 2). The aliases may stay for
/// their own TTLs, but the negative fact only for the SOA's negative TTL (section 5) and
/// not at all without an SOA (section 4), so the reply as a whole goes by the shorter.
#[inline]
pub(crate) fn says_no_despite_answers(
    rcode: hickory_proto::op::ResponseCode,
    only_aliases: bool,
) -> bool {
    use hickory_proto::op::ResponseCode;
    rcode == ResponseCode::NXDomain || (rcode == ResponseCode::NoError && only_aliases)
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

    // 客户端声明的载荷大小，不超过我们自己的（见 UDP_PAYLOAD），不小于 512（RFC 6891 第 6.2.5 节）；不带 OPT 或读不了
    // 的是 512。OPT 直接从报文里读，不必为一个数把请求整个解析一遍
    // The payload size the client declares, no more than our own (see UDP_PAYLOAD) and no less
    // than 512 (RFC 6891 section 6.2.5); 512 without an OPT or with one that cannot be read. The
    // OPT is read off the packet, with no need to parse the whole request for one number
    let max_payload = match find_opt(request_packet) {
        Ok(Some(opt)) => usize::from(opt.udp_payload(request_packet))
            .clamp(CLASSIC_DNS_UDP_PAYLOAD, usize::from(UDP_PAYLOAD)),
        _ => CLASSIC_DNS_UDP_PAYLOAD,
    };

    if response_packet.len() <= max_payload {
        return None;
    }

    if let Ok(mut response) = Message::from_bytes(response_packet) {
        // 客户端带了 OPT 的查询，应答也要带（RFC 6891 第 6.1.1 节）。hickory 把 OPT 放在最后，放不下
        // 就整条丢掉，所以先单独编好，给它留出位置，其余的记录能放多少放多少。
        // A query with an OPT needs one in its reply (RFC 6891 section 6.1.1). hickory
        // emits the OPT last and drops it whole when it does not fit, so it is encoded
        // apart first and its room kept, the other records taking what is left.
        let opt = response.edns.take().and_then(|mut edns| {
            // 和别的回答一样通告我们自己的载荷大小 / Our own payload size is advertised, as in every other reply
            edns.set_max_payload(UDP_PAYLOAD);
            let mut wire = Vec::new();
            Record::from(&edns)
                .emit(&mut BinEncoder::new(&mut wire))
                .ok()
                .map(|()| wire)
        });
        let opt = opt.unwrap_or_default();
        let room = max_payload.saturating_sub(opt.len());

        let mut out = Vec::with_capacity(max_payload);
        let encoded = {
            let mut encoder = BinEncoder::new(&mut out);
            encoder.set_max_size(room as u16);
            response.emit(&mut encoder)
        };
        if encoded.is_ok() && out.len() <= room {
            // 回答段、授权段都还在，只是 Additional 放不下时不置 TC，放不下的 RRset 整个省掉（RFC 2181 第 9 节，见
            // [`whole_rrsets`]）：客户端改用 TCP 拿到的也只多几条附加记录，用不着为它重问一遍。上游自己置了 TC 的照旧，
            // 截开的 RRset 也就留着前一截
            // With the answer and authority sections whole and only Additional cut, TC is
            // not set and an RRset that does not fit is left out whole (RFC 2181 section 9,
            // see [`whole_rrsets`]): retrying over TCP would bring only a few more additional
            // records, not worth asking again for. A TC the upstream set stays, and with it
            // the first part of an RRset cut through
            if out[6..10] == response_packet[6..10] && response_packet[2] & 0x02 == 0 {
                let whole = whole_rrsets(&response.additionals, section_count(&out, 3));
                out[10..12].copy_from_slice(&(whole as u16).to_be_bytes());
                out[2] &= !0x02;
            }
            // hickory's rollback does not shrink the backing buffer, so the
            // output can carry partial bytes from the record that did not fit.
            // Trim to the last complete record boundary from the corrected
            // header counts; fall back to the raw output if the walk fails.
            if let Some(valid_len) = valid_message_len(&out) {
                out.truncate(valid_len);
            }
            if !opt.is_empty() {
                out.extend_from_slice(&opt);
                let additional = section_count(&out, 3) as u16 + 1;
                out[10..12].copy_from_slice(&additional.to_be_bytes());
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

/// Additional 段的记录 `records` 只发得出前 `sent` 条时，留下前多少条才不会截开哪个 RRset：留下的每一条，它那个
/// RRset 的成员都在留下的里面（RFC 2181 第 9 节：放不下的 RRset 整个省掉）。成员不挨着排的 RRset 也一样，夹在它们中间
/// 的 RRset 整个跟着省掉。`sent` 不少于记录数时什么都没截，原样返回
/// How many of the Additional records `records` stay, when only the first `sent` of them go
/// out, so that no RRset is cut through: each record kept has all of its RRset kept with it (RFC
/// 2181 section 9: an RRset that does not fit is left out whole). So too for an RRset whose
/// members are not next to each other, the RRsets in between going whole with it. With `sent`
/// no less than the records, nothing was cut, and it is returned as it is
fn whole_rrsets(records: &[Record], sent: usize) -> usize {
    if sent >= records.len() {
        return sent;
    }
    // 每个 RRset 的最后一条排在哪 / Where each RRset's last record sits
    let last: std::collections::HashMap<_, _> = records
        .iter()
        .enumerate()
        .map(|(at, record)| (rrset_of(record), at))
        .collect();
    // 到 `at` 为止开始的 RRset 最远排到哪；正好是 `at` 时，前面的都在这一条或之前排完
    // How far the RRsets begun up to `at` reach; exactly `at`, and all before end here or earlier
    let (mut reach, mut whole) = (0, 0);
    for (at, record) in records[..sent].iter().enumerate() {
        reach = reach.max(last[&rrset_of(record)]);
        if reach == at {
            whole = at + 1;
        }
    }
    whole
}

/// 一条记录属于哪个 RRset：属主、类别和类型相同的算一个（RFC 2181 第 5 节），RRSIG 算进它签的那个类型（RFC 4034
/// 第 3.1.1 节的 Type Covered），签名和它签的记录一起留、一起省。属主名不分大小写（hickory 的 `Name` 就这样比较、
/// 这样算哈希）
/// Which RRset a record belongs to: records with the same owner, class and type make one (RFC
/// 2181 section 5), and an RRSIG counts with the type it covers (Type Covered, RFC 4034 section
/// 3.1.1), so a signature stays or goes with what it signs. Owners are compared ignoring case
/// (as hickory's `Name` compares and hashes)
fn rrset_of(record: &Record) -> (&Name, DNSClass, RecordType) {
    let covered = match &record.data {
        RData::Unknown {
            code: RecordType::RRSIG,
            rdata,
        } => rdata
            .anything
            .get(..2)
            .map(|covered| RecordType::from(u16::from_be_bytes([covered[0], covered[1]]))),
        _ => None,
    };
    (
        &record.name,
        record.dns_class,
        covered.unwrap_or(record.record_type()),
    )
}

fn build_minimal_truncated_response(
    request_packet: &[u8],
    response_packet: &[u8],
    max_payload: usize,
) -> Bytes {
    let mut question_end = 12usize;
    let mut copied_questions = false;

    if request_packet.len() >= 12 {
        // 中间某个问题超出报文时，下一个名字读不出；最后一个由 `pos <= len` 查到
        // A question in the middle running past the message leaves the next name
        // unreadable; the last one is caught by `pos <= len`
        if let Some(pos) = skip_questions(request_packet, section_count(request_packet, 0))
            && pos <= request_packet.len()
            && pos <= max_payload
        {
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

/// 用 `f` 改写报文里每条记录的 TTL（`f` 拿到的是 [`received_ttl`] 读出的值）；遇到放不下的记录
/// 就停。OPT（类型 41）伪记录跳过：它的 TTL 字段装的是 EDNS 扩展 RCODE 和标志（包括 DO 位），
/// 不是 TTL。
/// Rewrites the TTL of every record in `packet` with `f` (which gets the value
/// [`received_ttl`] reads), stopping at the first record that does not fit. OPT (type
/// 41) pseudo-records are skipped: their TTL field holds the EDNS extended RCODE and
/// flags (the DO bit among them), not a TTL.
fn map_record_ttls(packet: &mut [u8], mut f: impl FnMut(u32) -> u32) {
    let mut fields = TtlFields::of(packet);
    while let Some(at) = fields.next(packet) {
        let ttl = at..at + 4;
        let old_ttl = u32::from_be_bytes(packet[ttl.clone()].try_into().unwrap());
        packet[ttl].copy_from_slice(&f(received_ttl(old_ttl)).to_be_bytes());
    }
}

/// 把缓存里的应答 `cached` 接在 `buf` 后面，每条记录的 TTL 一边拷一边调低 `elapsed` 秒（同 [`patch_all_ttls`]）：拷和改是
/// 同一遍。以前先整个拷过去，再走一遍改 TTL
/// Appends the cached answer `cached` to `buf`, lowering every record's TTL by `elapsed`
/// seconds as it is copied (as [`patch_all_ttls`] does): copying and changing are one pass. It
/// used to be copied whole first and walked again for the TTLs
pub(crate) fn extend_aged(buf: &mut BytesMut, cached: &[u8], elapsed: u32) {
    let mut copied = 0;
    if elapsed > 0 {
        let mut fields = TtlFields::of(cached);
        while let Some(at) = fields.next(cached) {
            let old_ttl = u32::from_be_bytes(cached[at..at + 4].try_into().unwrap());
            buf.extend_from_slice(&cached[copied..at]);
            buf.extend_from_slice(&received_ttl(old_ttl).saturating_sub(elapsed).to_be_bytes());
            copied = at + 4;
        }
    }
    buf.extend_from_slice(&cached[copied..]);
}

/// 依次走到报文里每条记录的 TTL 字段；OPT（类型 41）伪记录跳过，见 [`map_record_ttls`]。自己不借着报文，所以边走边改 TTL
/// 也行。遇到读不出的记录就停；RDATA 超出报文的那条也给出它的 TTL，到它为止（原来如此）
/// Walks to the TTL field of each record of a message in turn; OPT (type 41) pseudo-records are
/// skipped, see [`map_record_ttls`]. It holds no borrow of the message, so TTLs may be changed
/// along the way. It stops at a record that cannot be read; one whose RDATA runs past the
/// message still gives its TTL and is the last (as it always has been)
struct TtlFields {
    pos: usize,
    records: usize,
}

impl TtlFields {
    fn of(packet: &[u8]) -> Self {
        let first = (packet.len() >= 12)
            .then(|| skip_questions(packet, section_count(packet, 0)))
            .flatten();
        match first {
            Some(pos) => Self {
                pos,
                records: (1..4).map(|index| section_count(packet, index)).sum(),
            },
            None => Self { pos: 0, records: 0 },
        }
    }

    fn next(&mut self, packet: &[u8]) -> Option<usize> {
        while self.records > 0 {
            let Some(record) = record_at(packet, self.pos) else {
                self.records = 0;
                return None;
            };
            self.records = if record.rdata.end > packet.len() {
                0
            } else {
                self.records - 1
            };
            self.pos = record.rdata.end;
            if record.rr_type != 41 {
                return Some(record.fixed + 4);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个查询的请求头：ID 0x1234，RD、CD 置位，`qd` 个问题 / A query's header: ID 0x1234, RD and CD
    /// set, `qd` questions
    fn query_header(qd: u8) -> Vec<u8> {
        vec![0x12, 0x34, 0x01, 0x10, 0, qd, 0, 0, 0, 0, 0, 0]
    }

    /// 线上格式的 SERVFAIL 带回 ID、RD、CD 和问题，QR、RA 置位；查询带 OPT 时带回 OPT，DO 位照抄
    /// The wire SERVFAIL brings back the ID, RD, CD and question, with QR and RA set; a query
    /// with an OPT gets one back with its DO bit
    #[test]
    fn a_servfail_on_the_wire_copies_the_header_and_the_question() {
        let question = [4, b'D', b'a', b't', b'a', 0, 0, 28, 0, 1];
        let query = [query_header(1), question.to_vec()].concat();
        let servfail = servfail_reply(&query);
        assert_eq!(
            servfail[..12],
            [0x12, 0x34, 0x81, 0x92, 0, 1, 0, 0, 0, 0, 0, 0],
            "ID, QR and RD, RA and CD and SERVFAIL, one question"
        );
        assert_eq!(servfail[12..], question);

        let mut with_opt = query.clone();
        with_opt[11] = 1;
        push_opt(&mut with_opt, 0, true, &[]);
        let servfail = servfail_reply(&with_opt);
        assert_eq!(servfail[10..12], [0, 1], "one additional record");
        let opt = find_opt(&servfail).unwrap().expect("an OPT");
        assert!(opt.dnssec_ok(&servfail));
        assert_eq!(
            servfail[12..opt.start],
            question,
            "the question, then the OPT"
        );
    }

    /// 读不了的查询回 FORMERR：问题抄得过来就带上，抄不过来就只有请求头
    /// A query that cannot be read gets FORMERR: its question when that can be copied, the
    /// header alone otherwise
    #[test]
    fn a_formerr_carries_the_question_only_when_it_can_be_copied() {
        let question = [1, b'a', 0, 0, 1, 0, 1];
        let formerr = formerr_reply(&[query_header(1), question.to_vec()].concat());
        assert_eq!(formerr[..2], [0x12, 0x34]);
        assert_eq!(formerr[2], 0x81, "QR and RD");
        assert_eq!(formerr[3], 0x91, "RA, CD and FORMERR");
        assert_eq!(formerr[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(formerr[12..], question);

        let mut name_too_long = query_header(1);
        for _ in 0..5 {
            name_too_long.push(63);
            name_too_long.extend_from_slice(&[b'a'; 63]);
        }
        name_too_long.extend_from_slice(&[0, 0, 1, 0, 1]);
        // 指针后面的字节够多，当成长度为 192 的标签也读得下去，只有查标签长度才拦得住
        // Enough bytes follow the pointer to read on as a label of length 192, so only
        // checking the label's length stops it
        let mut pointer_with_room = query_header(1);
        pointer_with_room.push(0xC0);
        pointer_with_room.extend_from_slice(&[b'a'; 192]);
        pointer_with_room.extend_from_slice(&[0, 0, 1, 0, 1]);
        for (case, packet) in [
            (
                "label past the end",
                [query_header(1), vec![63, b'a', 0, 0, 1, 0, 1]].concat(),
            ),
            (
                "compression pointer",
                [query_header(1), vec![0xC0, 0x0C, 0, 1, 0, 1]].concat(),
            ),
            (
                "no room for type and class",
                [query_header(1), vec![0, 0, 1]].concat(),
            ),
            ("no question bytes", query_header(1)),
            (
                "compression pointer with bytes behind it",
                pointer_with_room,
            ),
            ("name over 255 bytes", name_too_long),
        ] {
            let formerr = formerr_reply(&packet);
            assert_eq!(formerr.len(), 12, "{case}");
            assert_eq!(formerr[3], 0x91, "{case}");
            assert_eq!(formerr[4..6], [0, 0], "{case}");
        }
    }

    /// 一个名字最多跳 16 次指针：一串指针一个指着前一个，许多名字指着它的末尾时，每个都要把整串走一遍。以前跳过名字的那份数着，
    /// 校验应答的那份不数，一份上游的应答能让它走上报文长度的平方那么多步
    /// A name takes at most 16 pointer jumps: with a run of pointers each pointing at the one
    /// before and many names pointing at its end, each walks the whole run. The walker that
    /// skipped names counted them and the one checking replies did not, so an upstream's reply
    /// could have it take the square of the message's length in steps
    #[test]
    fn a_name_takes_at_most_sixteen_jumps() {
        // 偏移 12 是名字 a，之后每个指针指着前一个 / The name a at offset 12, then each pointer
        // pointing at the one before
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&[1, b'a', 0]);
        packet.extend_from_slice(&[0xC0, 12]);
        for at in (15..).step_by(2).take(16) {
            packet.extend_from_slice(&[0xC0, at as u8]);
        }
        let jumps_from = |jumps: usize| 15 + 2 * (jumps - 1);
        assert_eq!(
            strict_name_end(&packet, jumps_from(16)),
            Some(jumps_from(16) + 2)
        );
        assert_eq!(strict_name_end(&packet, jumps_from(17)), None);
    }

    /// UDP 回答只是 Additional 放不下时不置 TC（RFC 2181 第 9 节），回答段照样整个带上，放不下的 RRset 整个省掉；
    /// 回答段放不下时照旧置 TC
    /// A UDP reply with only Additional cut sets no TC (RFC 2181 section 9), the answer section
    /// whole and the RRset that does not fit left out whole; with the answer section cut it sets
    /// TC as before
    #[test]
    fn cutting_only_additional_records_sets_no_tc() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
        let name = Name::from_ascii("glue.example.").unwrap();
        let a = |n: u32| {
            Record::from_rdata(
                name.clone(),
                300,
                RData::A(A::from(std::net::Ipv4Addr::from(n))),
            )
        };
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name.clone(), RecordType::A));
        let mut reply = query.clone();
        reply.metadata.message_type = MessageType::Response;
        reply.add_answer(a(1));
        reply.add_additionals((0..60).map(a));
        let reply = reply.to_vec().unwrap();
        let cut = Message::from_bytes(
            &truncate_udp_response(&query.to_vec().unwrap(), &reply).expect("cut to 512"),
        )
        .unwrap();
        assert_eq!(cut.answers.len(), 1);
        assert!(
            cut.additionals.is_empty(),
            "the 60 A records are one RRset, which does not fit"
        );
        assert!(!cut.metadata.truncation, "only Additional was cut");

        let mut long = query.clone();
        long.metadata.message_type = MessageType::Response;
        long.add_answers((0..60).map(a));
        let cut = Message::from_bytes(
            &truncate_udp_response(&query.to_vec().unwrap(), &long.to_vec().unwrap())
                .expect("cut to 512"),
        )
        .unwrap();
        assert!(cut.answers.len() < 60);
        assert!(cut.metadata.truncation, "answers were cut");
    }

    /// 只截 Additional 时留下的是放得下的、不截开任何 RRset 的最长一段：RRSIG 跟它签的类型算一个 RRset，属主不分
    /// 大小写，成员不挨着排的 RRset 连同夹在中间的一起省掉。每个载荷都和逐个试出来的结果比
    /// With only Additional cut, what stays is the longest run that fits and cuts no RRset
    /// through: an RRSIG counts with the type it covers, owners ignore case, and an RRset whose
    /// members are apart goes with what lies between them. Every payload is checked against the
    /// result found by trying each length
    #[test]
    fn cutting_additional_records_leaves_out_whole_rrsets() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::{A, NULL};
        let name = |text: &str| Name::from_ascii(text).unwrap();
        let a = |owner: &str, last: u8| {
            Record::from_rdata(name(owner), 300, RData::A(A::new(192, 0, 2, last)))
        };
        let rrsig = |owner: &str, covered: RecordType| {
            let rdata = [&u16::from(covered).to_be_bytes()[..], &[0; 40]].concat();
            Record::from_rdata(
                name(owner),
                300,
                RData::Unknown {
                    code: RecordType::RRSIG,
                    rdata: NULL::with(rdata),
                },
            )
        };
        let mut additionals = Vec::new();
        for server in 0..16 {
            let owner = format!("ns{server}.example.");
            additionals.extend([a(&owner, 1), a(&owner, 2), rrsig(&owner, RecordType::A)]);
        }
        // x 的 A 记录不挨着排，大写的 X 也是它；y 的签名签的是 AAAA，自成一组
        // x's A records are apart, the upper-case X being x too; y's signature covers AAAA,
        // a set of its own
        additionals.splice(
            6..6,
            [a("x.example.", 1), a("y.example.", 1), a("X.example.", 2)],
        );
        additionals.splice(
            12..12,
            [rrsig("y.example.", RecordType::AAAA), a("x.example.", 3)],
        );
        let rrset_of = |record: &Record| {
            let covered = match &record.data {
                RData::Unknown { rdata, .. } => {
                    u16::from_be_bytes([rdata.anything[0], rdata.anything[1]]).into()
                }
                _ => record.record_type(),
            };
            (record.name.clone(), covered)
        };
        let reply = |additionals: &[Record]| {
            let mut reply = Message::new(0x1234, MessageType::Response, OpCode::Query);
            reply.add_query(Query::query(name("www.example."), RecordType::A));
            reply.add_answers((0..4).map(|last| a("www.example.", last)));
            reply.add_additionals(additionals.iter().cloned());
            let mut edns = Edns::new();
            edns.set_max_payload(UDP_PAYLOAD);
            reply.set_edns(edns);
            reply.to_vec().unwrap()
        };
        let full = reply(&additionals);
        assert!(full.len() > usize::from(UDP_PAYLOAD));
        for payload in 512..=UDP_PAYLOAD {
            let cut = Message::from_bytes(
                &truncate_udp_response(&txt_query(Some(payload)), &full).expect("must cut"),
            )
            .unwrap();
            let kept = (0..=additionals.len())
                .rev()
                .find(|&kept| {
                    let (before, after) = additionals.split_at(kept);
                    reply(before).len() <= usize::from(payload)
                        && before.iter().all(|record| {
                            after
                                .iter()
                                .all(|later| rrset_of(record) != rrset_of(later))
                        })
                })
                .unwrap();
            assert_eq!(cut.answers.len(), 4, "payload {payload}");
            assert!(!cut.metadata.truncation, "payload {payload}");
            assert_eq!(cut.additionals, additionals[..kept], "payload {payload}");
        }
    }

    /// 带着读得出的 OPT 的请求，NOTIMP 和 FORMERR 也带 OPT，DO 位照抄（RFC 6891 第 7 节）；不带 OPT 的照旧不带
    /// A request carrying an OPT that can be read gets one back with NOTIMP and FORMERR too, its DO
    /// bit copied (RFC 6891 section 7); one without stays without
    #[test]
    fn notimp_and_formerr_carry_an_opt_for_a_request_with_one() {
        // OPT 里的选项说有 10 字节、实际一个字节都没有：完整解析读不了，OPT 照样找得到
        // An option in the OPT declaring 10 bytes and holding none: the full parse cannot read
        // it, yet the OPT is found
        let mut unreadable = vec![
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1,
        ];
        push_opt(&mut unreadable, 0, true, &[0, 15, 0, 10]);
        assert!(Message::from_bytes(&unreadable).is_err());
        let mut notify = vec![0x56, 0x78, 0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
        push_opt(&mut notify, 0, true, &[]);
        for (case, reply) in [
            ("FORMERR", formerr_reply(&unreadable)),
            ("NOTIMP", header_reply(&notify).unwrap()),
        ] {
            assert_eq!(reply[10..12], [0, 1], "{case}: one additional record");
            let opt = find_opt(&reply).unwrap().expect("an OPT");
            assert!(opt.dnssec_ok(&reply), "{case}: DO copied");
        }
        let without = [0x56, 0x78, 0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(header_reply(&without).unwrap().len(), 12);
    }

    /// 一边拷一边调低 TTL，和先拷再调低的结果一样，OPT 的标志不动；没过一秒时照拷
    /// Lowering the TTLs while copying gives what copying and then lowering gives, the OPT's
    /// flags untouched; under a second it is copied as it is
    #[test]
    fn aging_while_copying_matches_copying_then_aging() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
        let name = Name::from_ascii("aged.example.").unwrap();
        let mut reply = Message::new(7, MessageType::Response, OpCode::Query);
        reply.add_query(Query::query(name.clone(), RecordType::A));
        for (n, ttl) in [(1, 300), (2, 5), (3, 0x8000_0001)] {
            reply.add_answer(Record::from_rdata(
                name.clone(),
                ttl,
                RData::A(A::from(std::net::Ipv4Addr::from(n))),
            ));
        }
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        reply.edns = Some(edns);
        let cached = reply.to_vec().unwrap();
        for elapsed in [0, 10] {
            let mut copied_then_aged = cached.clone();
            patch_all_ttls(&mut copied_then_aged, elapsed);
            let mut aged = BytesMut::from(&b"prefix"[..]);
            extend_aged(&mut aged, &cached, elapsed);
            assert_eq!(&aged[6..], &copied_then_aged[..], "{elapsed}");
        }
    }

    /// 各段计数为 `counts`（问题、Answer、Authority、Additional）的应答报文头
    /// A reply header with section counts `counts` (questions, Answer, Authority, Additional)
    fn header_with(counts: [u16; 4]) -> Vec<u8> {
        let mut header = vec![0x12, 0x34, 0x81, 0x80];
        for count in counts {
            header.extend_from_slice(&count.to_be_bytes());
        }
        header
    }

    /// a.test 的线上格式 / a.test on the wire
    const A_TEST: [u8; 8] = [1, b'a', 4, b't', b'e', b's', b't', 0];

    /// 最后一条记录的类型是 TSIG 就算，它的 RDATA 超出报文也一样；固定字段不全时不算。
    /// 这是现有的行为，记录遍历合并后照旧
    /// The last record counts as a TSIG by its type, even when its RDATA runs past the
    /// message; not when its fixed fields are cut. This is the current behaviour, kept
    /// as it is by the shared record walk
    #[test]
    fn a_last_tsig_counts_even_when_its_rdata_runs_past_the_message() {
        let record = |rr_type: u8, rd_len: u8, rdata: &[u8]| {
            let mut packet = header_with([0, 0, 0, 1]);
            packet.push(0);
            packet.extend_from_slice(&[0, rr_type, 0, 255, 0, 0, 0, 0, 0, rd_len]);
            packet.extend_from_slice(rdata);
            packet
        };
        assert!(last_record_is_tsig(&record(250, 2, &[1, 2])));
        assert!(last_record_is_tsig(&record(250, 9, &[1, 2])));
        assert!(!last_record_is_tsig(&record(1, 2, &[1, 2])));
        let mut cut = record(250, 2, &[1, 2]);
        cut.truncate(12 + 1 + 8);
        assert!(!last_record_is_tsig(&cut));
    }

    /// 改写 TTL 时，放不下的那条记录也先改了 TTL，然后才停下：后面的记录不再看。
    /// 这是现有的行为，记录遍历合并后照旧
    /// While rewriting TTLs, the record that does not fit has its TTL rewritten too
    /// before the walk stops, and the records after it are not looked at. This is the
    /// current behaviour, kept as it is by the shared record walk
    #[test]
    fn a_record_that_does_not_fit_has_its_ttl_rewritten_before_the_walk_stops() {
        let mut packet = header_with([1, 3, 0, 0]);
        packet.extend_from_slice(&A_TEST);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        let fits_ttl = packet.len() + 2 + 4;
        packet.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
        let cut_ttl = packet.len() + 2 + 4;
        // RDLENGTH 20，只带了 4 个字节 / RDLENGTH 20 with 4 bytes carried
        packet.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 20, 192, 0, 2, 2]);
        map_record_ttls(&mut packet, |_| 7);
        assert_eq!(packet[fits_ttl..fits_ttl + 4], 7u32.to_be_bytes());
        assert_eq!(packet[cut_ttl..cut_ttl + 4], 7u32.to_be_bytes());
    }

    /// 问题段在报文末尾被截断、又没有记录时，`find_opt` 不报错，只说没有 OPT；有记录时报错。
    /// 这是现有的行为，记录遍历合并后照旧
    /// With the question section cut at the end of the message and no records, `find_opt`
    /// reports no OPT rather than an error; with a record it is an error. This is the
    /// current behaviour, kept as it is by the shared record walk
    #[test]
    fn a_cut_question_without_records_finds_no_opt() {
        let cut = |counts: [u16; 4]| {
            let mut packet = header_with(counts);
            packet.extend_from_slice(&A_TEST);
            packet.extend_from_slice(&[0, 1]);
            packet
        };
        assert!(matches!(find_opt(&cut([1, 0, 0, 0])), Ok(None)));
        assert!(find_opt(&cut([1, 0, 0, 1])).is_err());
    }

    /// 兜底的截断应答只抄完整的问题：最后一个问题超出请求、或者问题数比请求里的多时，一个也不抄
    /// The fallback truncated reply copies only whole questions: when the last question
    /// runs past the request, or the request counts more questions than it carries,
    /// none is copied
    #[test]
    fn a_truncated_reply_copies_no_question_running_past_the_request() {
        let request = |count: u16, tail: &[u8]| {
            let mut packet = header_with([count, 0, 0, 0]);
            packet[2] = 0x01;
            packet[3] = 0x00;
            packet.extend_from_slice(&A_TEST);
            packet.extend_from_slice(tail);
            packet
        };
        let response = header_with([1, 0, 0, 0]);
        let whole = request(1, &[0, 1, 0, 1]);
        let reply = build_minimal_truncated_response(&whole, &response, 512);
        assert_eq!(reply[4..6], 1u16.to_be_bytes());
        assert_eq!(reply[12..], whole[12..]);
        for broken in [request(1, &[0, 1]), request(2, &[0, 1, 0, 1])] {
            let reply = build_minimal_truncated_response(&broken, &response, 512);
            assert_eq!(reply.len(), 12);
            assert_eq!(reply[4..6], 0u16.to_be_bytes());
            assert_eq!(reply[2] & 0x02, 0x02, "TC");
        }
    }

    /// 末尾加一条类型为 TSIG 的记录（根名、类别 ANY、TTL 0、空 RDATA），记进 Additional 的计数
    /// Append a TSIG-typed record (root name, class ANY, TTL 0, empty RDATA), counted in
    /// Additional
    fn push_bare_tsig(message: &mut Vec<u8>) {
        message.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
        message[11] += 1;
    }

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
        push_bare_tsig(&mut signed);
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

    /// 头部（附加段 `additional` 条记录）加问题 `a.`（A/IN）
    /// A header (with `additional` records in the additional section) and the question `a.` (A/IN)
    fn query_with_additional_count(additional: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&additional.to_be_bytes());
        packet.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        packet
    }

    /// `labels` 个单字节标签加根：编码长 `2 * labels + 1` 字节 / `labels` one-byte labels and the
    /// root: `2 * labels + 1` bytes encoded
    fn label_run(labels: usize) -> Vec<u8> {
        let mut run: Vec<u8> = std::iter::repeat_n([1u8, b'x'], labels).flatten().collect();
        run.push(0);
        run
    }

    /// 一个名字连同压缩指针跳过去读到的部分，总共不超过 255 字节（RFC 1035 第 2.3.4 节）。跳过名字的那份以前不数：
    /// 一条记录的 RDATA 里放一长串标签，后面每条记录的属主名都指进去，每个名字都要把这一长串走一遍。64 KiB 的
    /// TCP 或 DoH 报文里放两千多条这样的记录，走一遍报文就是几千万步，一个查询要走好几遍
    /// A name is at most 255 bytes in all, what a compression pointer leads to included (RFC 1035
    /// section 2.3.4). The walker skipping names did not count it: with a long run of labels in
    /// one record's RDATA and the owner of every later record pointing into it, each name walked
    /// the whole run. Over two thousand such records in a 64 KiB TCP or DoH message made one walk
    /// of the message tens of millions of steps, and a query is walked several times
    #[test]
    fn a_name_is_at_most_255_bytes_through_pointers_too() {
        // 第一条附加记录的 RDATA 是一串标签，第二条的属主名指进去 / The first additional record's RDATA
        // is a run of labels, and the second one's owner points into it
        let pointing_into_a_run_of = |labels: usize| {
            let mut packet = query_with_additional_count(2);
            let run = label_run(labels);
            packet.push(0);
            packet.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 0]);
            packet.extend_from_slice(&(run.len() as u16).to_be_bytes());
            let run_at = packet.len();
            packet.extend_from_slice(&run);
            let second = packet.len();
            packet.extend_from_slice(&[0xC0 | (run_at >> 8) as u8, run_at as u8]);
            packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
            (packet, second)
        };
        // 127 个标签加根正好 255 字节 / 127 labels and the root come to exactly 255 bytes
        let (packet, second) = pointing_into_a_run_of(127);
        assert_eq!(strict_name_end(&packet, second), Some(second + 2));
        assert_eq!(find_opt(&packet), Ok(None));

        let (packet, second) = pointing_into_a_run_of(128);
        assert_eq!(strict_name_end(&packet, second), None);
        assert!(find_opt(&packet).is_err());

        // 不经指针、直接写在原地的也一样 / The same for one written in place, with no pointer
        let in_place = |labels: usize| {
            let mut packet = query_with_additional_count(1);
            let owner = packet.len();
            packet.extend_from_slice(&label_run(labels));
            packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
            (packet, owner)
        };
        let (packet, owner) = in_place(127);
        assert_eq!(strict_name_end(&packet, owner), Some(owner + 255));
        let (packet, owner) = in_place(128);
        assert_eq!(strict_name_end(&packet, owner), None);

        // 正好 256 字节：126 个单字节标签、一个两字节的标签，加根
        // Exactly 256 bytes: 126 one-byte labels, one of two bytes, and the root
        let mut packet = query_with_additional_count(1);
        let owner = packet.len();
        packet.extend_from_slice(&label_run(126)[..252]);
        packet.extend_from_slice(&[2, b'y', b'y', 0]);
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
        assert_eq!(strict_name_end(&packet, owner), None);
    }

    #[test]
    fn parse_quick_accepts_regular_ascii_qname() {
        let packet = query_with_label(b"example");
        let mut qname = [0u8; 256];

        assert!(parse_quick(&packet, &mut qname).is_some());
    }

    /// 问题名的文本是各标签的小写、用点连起来，根名是空串；问题名里的压缩指针无处可指（指不到它那段前面，又不能指进报文头），
    /// 带指针的问题名读不了
    /// The question name's text is its labels lowercased and joined with dots, the root's being
    /// empty; a compression pointer in the question name has nowhere to point (not before its
    /// part, nor into the header), so a question name with one cannot be read
    #[test]
    fn parse_quick_reads_the_question_name_uncompressed() {
        let mut text = [0u8; 256];
        for (wire, expected) in [
            (&b"\x03WwW\x07ExAmple\x03CoM\x00"[..], "www.example.com"),
            (b"\x00", ""),
        ] {
            let packet = [&query_header(1), wire, &[0, 1, 0, 1]].concat();
            assert_eq!(question_name_end(&packet), Some(12 + wire.len()));
            assert_eq!(parse_quick(&packet, &mut text).unwrap().qname, expected);
        }
        for target in 12..=18 {
            let packet = [
                &query_header(1)[..],
                b"\x02ab\x02cd\xC0",
                &[target, 0, 1, 0, 1],
            ]
            .concat();
            assert_eq!(question_name_end(&packet), None, "pointer to {target}");
            assert!(
                parse_quick(&packet, &mut text).is_none(),
                "pointer to {target}"
            );
        }
    }

    #[test]
    fn parse_quick_leaves_names_that_need_escapes_to_the_full_parser() {
        let mut qname = [0u8; 256];
        for label in [
            &b"a.b"[..],
            b"a\\b",
            b"a b",
            b"bad\nlabel",
            b"\xff",
            b"caf\xc3\xa9",
        ] {
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
                .qname
                .to_owned();
            assert_eq!(name_text(&name_of(&packet)), quick, "{label:?}");
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

    /// 客户端带 OPT 时，截断的应答不管放得下几条记录都带 OPT，载荷写客户端声明的，也不超过它
    /// A reply truncated for a client that sent an OPT carries one however many records
    /// fit, staying within the payload the client declared and giving our own, as every
    /// other reply does (see UDP_PAYLOAD)
    #[test]
    fn a_truncated_reply_keeps_its_opt() {
        for payload in [512u16, 513, 523, 600, 1232] {
            let request = txt_query(Some(payload));
            for answers in 3..30 {
                let response = large_txt_response(answers);
                if response.len() <= payload as usize {
                    continue;
                }
                let truncated = truncate_udp_response(&request, &response).expect("must truncate");
                let case = format!("payload {payload}, {answers} answers");
                assert!(truncated.len() <= payload as usize, "{case}");
                assert_eq!(
                    valid_message_len(&truncated),
                    Some(truncated.len()),
                    "{case}"
                );
                let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
                assert!(decoded.metadata.truncation, "{case}");
                assert_eq!(section_count(&truncated, 3), 1, "{case}");
                let edns = decoded
                    .edns
                    .as_ref()
                    .unwrap_or_else(|| panic!("{case}: no OPT"));
                assert_eq!(edns.max_payload(), UDP_PAYLOAD, "{case}");
            }
        }
    }

    /// 记录小到能把载荷填到只差几个字节时，也给 OPT 留出了位置
    /// With records small enough to fill the payload to within a few bytes, the OPT's room is
    /// still kept
    #[test]
    fn a_truncated_reply_keeps_room_for_its_opt_when_small_records_fill_it() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, RecordType};
        use std::str::FromStr;

        let name = Name::from_str("cloudflare.com.").unwrap();
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::TXT));
        for last in 0..=99 {
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(A::new(192, 0, 2, last)),
            ));
        }
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        message.set_edns(edns);
        let response = encode_message(&message);

        // 一条 A 记录 16 字节，这个范围把离上限还差几个字节的情况都走到了
        // An A record takes 16 bytes, so this range meets every distance from the limit
        for payload in 512u16..=540 {
            let truncated =
                truncate_udp_response(&txt_query(Some(payload)), &response).expect("must truncate");
            assert!(truncated.len() <= payload as usize, "payload {payload}");
            let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
            assert!(decoded.metadata.truncation, "payload {payload}");
            assert_eq!(
                decoded.edns.as_ref().map(|edns| edns.max_payload()),
                Some(UDP_PAYLOAD)
            );
            assert!(
                truncated.len() + 16 > payload as usize,
                "payload {payload}: room for another record went unused ({} bytes)",
                truncated.len()
            );
        }
    }

    /// 扩展 RCODE 在 OPT 里，截断时不能丢 / The extended RCODE lives in the OPT, and truncating keeps it
    #[test]
    fn a_truncated_reply_keeps_its_extended_rcode() {
        use hickory_proto::op::ResponseCode;
        let mut response = Message::from_bytes(&large_txt_response(20)).unwrap();
        response.metadata.response_code = ResponseCode::BADVERS;
        let truncated = truncate_udp_response(&txt_query(Some(512)), &encode_message(&response))
            .expect("must truncate");
        let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
        assert_eq!(u16::from(decoded.metadata.response_code), 16);
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
        let response = large_txt_response(4);
        assert!(response.len() > 512);
        assert!(response.len() <= usize::from(UDP_PAYLOAD));

        assert!(truncate_udp_response(&request, &response).is_none());
    }

    /// 客户端声明的载荷比我们的大，UDP 回答也不超过我们的：更长的截断，让客户端改用 TCP，不在 IP 层分片
    /// With the client declaring a larger payload than ours, a UDP reply still stays within ours: a
    /// longer one is truncated for the client to retry over TCP, rather than fragmented at the IP layer
    #[test]
    fn a_reply_over_our_payload_is_truncated_whatever_the_client_allows() {
        let request = txt_query(Some(4096));
        let response = large_txt_response(8);
        assert!(response.len() > usize::from(UDP_PAYLOAD));
        assert!(response.len() <= 4096);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        assert!(truncated.len() <= usize::from(UDP_PAYLOAD));
        assert!(Message::from_bytes(&truncated).unwrap().metadata.truncation);
    }

    /// 线上 255 字节的名字快速解析照收，256 字节的不收，和完整解析一样
    /// A name of 255 bytes on the wire passes the quick parse and one of 256 does not, as for the
    /// full parse
    #[test]
    fn the_quick_parse_takes_names_up_to_255_bytes_on_the_wire() {
        // 四个 62 字节的标签加一个 n 字节的：线上 4 × 63 + (n + 1) + 1 字节 / Four labels of 62 bytes
        // and one of n: 4 × 63 + (n + 1) + 1 bytes on the wire
        let name = |last: usize| {
            let mut wire = Vec::new();
            for _ in 0..4 {
                wire.push(62u8);
                wire.extend(std::iter::repeat_n(b'a', 62));
            }
            wire.push(last as u8);
            wire.extend(std::iter::repeat_n(b'b', last));
            wire.push(0);
            wire
        };
        let query = |wire: &[u8]| {
            let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            packet.extend_from_slice(wire);
            packet.extend_from_slice(&[0, 1, 0, 1]);
            packet
        };
        let mut text = [0u8; 256];
        let fits = query(&name(1));
        assert_eq!(name(1).len(), MAX_NAME_LEN);
        assert!(parse_quick(&fits, &mut text).is_some());
        assert!(Message::from_bytes(&fits).is_ok());
        let over = query(&name(2));
        assert!(parse_quick(&over, &mut text).is_none());
        assert!(Message::from_bytes(&over).is_err());
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

    /// 末尾加上一条 hickory 读得了的 TSIG（RFC 8945 第 4.2 节）：密钥名 `key.`、算法 hmac-sha256、
    /// 32 字节的 MAC、原始 ID、没有错误、没有其他数据
    /// The message with a TSIG hickory reads appended (RFC 8945 section 4.2): key name
    /// `key.`, algorithm hmac-sha256, a 32-byte MAC, the original ID, no error, no other data
    fn signed(mut message: Vec<u8>) -> Bytes {
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
    }

    /// TSIG 签过的应答一位都不改：MAC 盖着整个报文（RFC 8945 第 4.3 节），改哪一位签名都失效。DO
    /// 位、RD 和 CD 位、问题名的写法都不照查询改；没签过的同一份应答照常改
    /// A TSIG-signed reply has not a bit changed: the MAC covers the whole message (RFC
    /// 8945 section 4.3), so any change breaks the signature. Neither the DO bit, RD and
    /// CD, nor the question's spelling follows the query; the same reply unsigned does
    #[test]
    fn a_signed_reply_is_not_rewritten_at_all() {
        use hickory_proto::op::MessageType::{Query, Response};
        let mut query = edns_message(Query, Some(true));
        query[2] |= 0x01;
        query[3] |= 0x10;
        query[13] = b'E';
        let unsigned = Bytes::from(edns_message(Response, Some(false)));
        assert_ne!(reply_as_asked(unsigned.clone(), &query), unsigned);
        let reply = signed(edns_message(Response, Some(false)));
        assert_eq!(reply_as_asked(reply.clone(), &query), reply);
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
        let signed_with_opt = signed(edns_message(Response, Some(false)));
        assert_eq!(
            edns_as_asked(signed_with_opt.clone(), &plain_query),
            signed_with_opt
        );
        let signed_without_opt = signed(edns_message(Response, None));
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
            let out = header_as_asked(reply.clone(), &query, asked_dnssec_ok(&query));
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

    /// 应答的 AD 只在查询带 AD 或 DO 时留着（照上游给的），两样都没带时去掉（RFC 6840 第 5.8 节）
    /// A reply keeps its AD (as the upstream gave it) only for a query with AD or DO, and
    /// loses it for a query with neither (RFC 6840 section 5.8)
    #[test]
    fn header_as_asked_keeps_ad_only_for_a_query_with_ad_or_do() {
        use hickory_proto::op::MessageType::{Query, Response};
        for reply_ad in [false, true] {
            let mut reply = edns_message(Response, None);
            if reply_ad {
                reply[3] |= 0x20;
            }
            let reply = Bytes::from(reply);
            for (query_ad, query_do, keeps) in [
                (false, None, false),
                (false, Some(false), false),
                (true, None, true),
                (false, Some(true), true),
                (true, Some(true), true),
            ] {
                let mut query = edns_message(Query, query_do);
                query[3] = if query_ad {
                    query[3] | 0x20
                } else {
                    query[3] & !0x20
                };
                let out = header_as_asked(reply.clone(), &query, asked_dnssec_ok(&query));
                assert_eq!(
                    out[3] & 0x20 != 0,
                    keeps && reply_ad,
                    "reply AD {reply_ad}, query AD {query_ad} DO {query_do:?}"
                );
            }
        }
    }

    /// 发给上游的查询带上 AD；已经带着的原样不复制；签过名的不改
    /// A query sent upstream gets AD; one that has it is handed back uncopied; a signed one is
    /// left alone
    #[test]
    fn query_asking_ad_sets_ad_except_on_a_signed_query() {
        use hickory_proto::op::MessageType::Query;
        let plain = edns_message(Query, None);
        assert_eq!(plain[3] & 0x20, 0);
        let asking = query_asking_ad(std::borrow::Cow::Borrowed(&plain));
        assert_eq!(asking[3] & 0x20, 0x20);
        assert_eq!(asking[..3], plain[..3]);
        assert_eq!(asking[3] & !0x20, plain[3]);
        assert_eq!(asking[4..], plain[4..]);
        assert!(matches!(
            query_asking_ad(std::borrow::Cow::Borrowed(&asking)),
            std::borrow::Cow::Borrowed(_)
        ));
        let signed_query = signed(edns_message(Query, None));
        assert_eq!(
            query_asking_ad(std::borrow::Cow::Borrowed(&signed_query)).as_ref(),
            &signed_query[..]
        );
    }

    /// 上游应答的 AA 去掉，其余不动；没有 AA 时原样不复制；签过名的不改
    /// An upstream reply loses its AA and nothing else; without AA it is handed back
    /// uncopied; a signed one is left alone
    #[test]
    fn reply_without_aa_clears_only_aa() {
        use hickory_proto::op::MessageType::Response;
        let mut authoritative = edns_message(Response, None);
        authoritative[2] |= 0x04;
        let out = reply_without_aa(Bytes::from(authoritative.clone()));
        assert_eq!(out[2], authoritative[2] & !0x04);
        assert_eq!(out[..2], authoritative[..2]);
        assert_eq!(out[3..], authoritative[3..]);
        let plain = Bytes::from(edns_message(Response, None));
        assert_eq!(reply_without_aa(plain.clone()).as_ptr(), plain.as_ptr());
        let signed_reply = signed(authoritative);
        assert_eq!(reply_without_aa(signed_reply.clone()), signed_reply);
    }

    /// 最高位为 1 的 TTL 按 0 算：快速解析的最小、最大 TTL，否定应答的 SOA（TTL 和 MINIMUM），以及
    /// 改写 TTL 的时候
    /// A TTL with the top bit set counts as 0: in the quick parse's least and greatest
    /// TTL, in a negative answer's SOA (its TTL and MINIMUM), and when TTLs are rewritten
    #[test]
    fn a_ttl_with_the_top_bit_set_counts_as_zero() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::{A, SOA};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        assert_eq!(received_ttl(0x7FFF_FFFF), 0x7FFF_FFFF);
        assert_eq!(received_ttl(0x8000_0000), 0);
        assert_eq!(received_ttl(u32::MAX), 0);
        let name = Name::from_ascii("example.com.").unwrap();
        let reply = |answers: &[u32], soa: Option<(u32, u32)>| {
            let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
            msg.add_query(Query::query(name.clone(), RecordType::A));
            for ttl in answers {
                msg.add_answer(Record::from_rdata(
                    name.clone(),
                    *ttl,
                    RData::A(A::new(192, 0, 2, 1)),
                ));
            }
            if let Some((ttl, minimum)) = soa {
                let soa = SOA::new(name.clone(), name.clone(), 1, 60, 60, 60, minimum);
                msg.add_authority(Record::from_rdata(name.clone(), ttl, RData::SOA(soa)));
            }
            msg.to_vec().unwrap()
        };
        let quick = parse_response_quick(&reply(&[300, 0x8000_0001], None)).unwrap();
        assert_eq!(quick.min_ttl, 0);
        for soa in [(0x8000_0000, 60), (300, 0x8000_0000)] {
            let quick = parse_response_quick(&reply(&[], Some(soa))).unwrap();
            assert_eq!(quick.min_ttl, 0, "{soa:x?}");
        }
        let rewritten = |floor, cap| {
            let out = reply_within_ttls(Bytes::from(reply(&[300, 0x8000_0001], None)), floor, cap);
            Message::from_vec(&out)
                .unwrap()
                .answers
                .iter()
                .map(|record| record.ttl)
                .collect::<Vec<_>>()
        };
        assert_eq!(rewritten(0, 86400), [300, 0]);
        assert_eq!(rewritten(60, 86400), [300, 60]);
    }

    /// 快速解析的 RCODE 带上 OPT 里的扩展部分（RFC 6891 第 6.1.3 节）
    /// The quick parse's RCODE includes the OPT's extended part (RFC 6891 section 6.1.3)
    #[test]
    fn parse_response_quick_reads_the_extended_rcode() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        for code in [
            ResponseCode::NoError,
            ResponseCode::ServFail,
            ResponseCode::BADVERS,
            ResponseCode::BADTIME,
            ResponseCode::BADALG,
            ResponseCode::BADCOOKIE,
        ] {
            let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
            msg.add_query(Query::query(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
            ));
            msg.metadata.response_code = code;
            msg.set_edns(Edns::new());
            let reply = msg.to_vec().unwrap();
            // Compared as numbers: 16 is both BADVERS and BADSIG, and hickory reads BADSIG
            // 按数值比较：16 既是 BADVERS 也是 BADSIG，hickory 读成 BADSIG
            assert_eq!(
                u16::from(parse_response_quick(&reply).unwrap().rcode),
                u16::from(code)
            );
        }
    }

    /// 结构经得起检查的应答：常见的各种类型；以及经不起的：每种毛病各一个
    /// Replies whose structure holds up, of the usual types, and ones that do not, one
    /// for each fault
    #[test]
    fn well_formed_reply_walks_the_whole_structure() {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
        use hickory_proto::rr::rdata::{A, AAAA, CNAME, HINFO, MX, NS, SOA, SRV, TXT};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        let name = Name::from_ascii("www.example.com.").unwrap();
        let other = Name::from_ascii("cdn.example.net.").unwrap();
        let record = |data: RData| Record::from_rdata(name.clone(), 300, data);
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::ANY));
        msg.add_answer(record(RData::CNAME(CNAME(other.clone()))));
        msg.add_answer(record(RData::A(A::new(192, 0, 2, 1))));
        msg.add_answer(record(RData::AAAA(AAAA::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
        ))));
        msg.add_answer(record(RData::MX(MX::new(10, other.clone()))));
        msg.add_answer(record(RData::SRV(SRV::new(1, 2, 443, other.clone()))));
        msg.add_answer(record(RData::TXT(TXT::new(vec!["a".into(), "bc".into()]))));
        msg.add_answer(record(RData::HINFO(HINFO::new(
            "RFC8482".into(),
            String::new(),
        ))));
        msg.add_authority(record(RData::NS(NS(other.clone()))));
        msg.add_authority(record(RData::SOA(SOA::new(
            other.clone(),
            name.clone(),
            1,
            60,
            60,
            60,
            60,
        ))));
        msg.add_additional(Record::from_rdata(
            other.clone(),
            300,
            RData::A(A::new(192, 0, 2, 9)),
        ));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                24,
            )));
        msg.set_edns(edns);
        let good = msg.to_vec().unwrap();
        assert!(well_formed_reply(&good));
        let bare = {
            let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
            msg.add_query(Query::query(name.clone(), RecordType::A));
            msg.add_answer(record(RData::A(A::new(192, 0, 2, 1))));
            msg.to_vec().unwrap()
        };
        assert!(well_formed_reply(&bare));
        // The answer's A record in `bare` starts right after the question
        // `bare` 里应答的 A 记录紧跟在问题后面
        let a_at = 12 + 17 + 4;
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("cut short", good[..good.len() - 3].to_vec()),
            ("a pointer forward", {
                let mut m = bare.clone();
                m[a_at + 1] = (a_at + 2) as u8;
                m
            }),
            ("a pointer to itself", {
                let mut m = bare.clone();
                m[a_at + 1] = a_at as u8;
                m
            }),
            ("a reserved label type", {
                let mut m = bare.clone();
                m[12] = 0x43;
                m
            }),
            ("an A record of 3 bytes", {
                let mut m = bare.clone();
                m[a_at + 11] = 3;
                m.pop();
                m
            }),
            ("a type it does not check", {
                let mut m = bare.clone();
                m[a_at + 3] = 99;
                m
            }),
            ("an OPT owned by the root, in the answer section", {
                let mut m = bare[..a_at].to_vec();
                m.extend_from_slice(&[0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0]);
                m
            }),
            ("an OPT not owned by the root", {
                let mut m = bare.clone();
                m[7] = 0;
                m[11] = 1;
                m[a_at + 3] = 41;
                m
            }),
            ("a CNAME whose name stops short of its RDATA", {
                let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
                msg.add_query(Query::query(name.clone(), RecordType::CNAME));
                msg.add_answer(record(RData::CNAME(CNAME(other.clone()))));
                let mut m = msg.to_vec().unwrap();
                let rd_len_at = m.len() - 2 - 17;
                m[rd_len_at + 1] += 1;
                m.push(0);
                m
            }),
            ("a TXT string past its RDATA", {
                let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
                msg.add_query(Query::query(name.clone(), RecordType::TXT));
                msg.add_answer(record(RData::TXT(TXT::new(vec!["abc".into()]))));
                let mut m = msg.to_vec().unwrap();
                let at = m.len() - 4;
                m[at] = 9;
                m
            }),
            ("an ECS option with an unknown family", {
                let mut m = good.clone();
                let ecs = m.windows(4).position(|w| w == [0, 8, 0, 7]).unwrap();
                m[ecs + 5] = 3;
                m
            }),
            ("two OPT records", {
                let mut m = good.clone();
                m[11] += 1;
                m.extend_from_slice(&[0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0]);
                m
            }),
        ];
        for (fault, message) in bad {
            assert!(!well_formed_reply(&message), "{fault}");
        }
        // Found by a randomized run: a pointer into the middle of the question's first
        // label, whose bytes then read as labels running into the name the pointer is
        // in. hickory refuses both (overlapping labels)
        // 随机测试找到的：指针指进问题名第一个标签的中间，从那里按标签读下去会读进指针所在的这个
        // 名字。hickory 两个都不读（标签重叠）
        let unhex = |hex: &str| {
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        for hex in [
            "6a518180000100010000000101330a7050614b385562337a42096b54564b565f4351583f324b65756c6b31485034434e4f454d6a59423364626d48774966394b3330506558786f6b3749506f56763135725f626b787177536c5a4b6e656b5050376f420541565832610000410001c00d001c00010001524b001009a57000f619b9dee7acb9daf542f451000029ffff0000000000240008000600020f000c7e000a00169ee4cbb461593ffdca6fd9e689f475d15cc4bb44f441",
            "fee9819000010004000000010c336c76397a4268326268767507455237674d456e0c38756a57686a6c4d6b365132047570315600000f0001c00c00050001000034190002c00dc00c001000010000ecfd0007067457514a3377c00c0006000100014ddd00420177055448647a39016402543700045f52475f02704e0b704f633335416a57624737016908445f4341785837780000000395000091ee0000781400012de700012157c00c000600010000c2fb003e054432346c41000a7947785749465635337a0c5242337577513634543032320948725541375037704400000027630000f09700015abe000121cb00008dcc0000291000000100000000",
        ] {
            let message = unhex(hex);
            assert!(Message::from_vec(&message).is_err());
            assert!(!well_formed_reply(&message), "{hex}");
        }
        // A name of 255 bytes is the most a name may be / 名字最长 255 字节
        let long = |last: usize| {
            let mut m = bare[..12].to_vec();
            m[7] = 0;
            for len in [63, 63, 63, last] {
                m.push(len as u8);
                m.extend(std::iter::repeat_n(b'a', len));
            }
            m.push(0);
            m.extend_from_slice(&[0, 1, 0, 1]);
            m
        };
        assert!(well_formed_reply(&long(61)), "255 bytes");
        assert!(!well_formed_reply(&long(62)), "256 bytes");
    }

    #[test]
    fn saturating_u64_to_u32_caps_large_values() {
        assert_eq!(saturating_u64_to_u32(42), 42);
        assert_eq!(saturating_u64_to_u32(u64::MAX), u32::MAX);
    }

    // ---- answers_query ----

    fn a_query_for(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    #[test]
    fn answers_query_ignores_ascii_case_only() {
        let query = a_query_for("example.com.");
        let mut response = a_query_for("ExAmPlE.CoM.");
        response[2] |= 0x80;
        assert!(answers_query(&query, &response), "0x20 case must match");

        let mut other = a_query_for("example.org.");
        other[2] |= 0x80;
        assert!(
            !answers_query(&query, &other),
            "different name must not match"
        );

        let mut other_type = response.clone();
        let type_pos = other_type.len() - 4;
        other_type[type_pos + 1] = 28; // AAAA
        assert!(
            !answers_query(&query, &other_type),
            "different QTYPE must not match"
        );
    }

    #[test]
    fn answers_query_reply_without_question_only_when_empty() {
        let query = a_query_for("example.com.");
        // Header-only FORMERR with QDCOUNT = 0 and no records: accepted, it
        // cannot poison anything and keeps the upstream's fast failure.
        let mut bare_error = query[..12].to_vec();
        bare_error[2] |= 0x80;
        bare_error[3] = 0x01; // RCODE = FORMERR
        bare_error[5] = 0;
        assert!(
            answers_query(&query, &bare_error),
            "record-less reply without a question must be accepted"
        );
        // QDCOUNT = 0 but ANCOUNT = 1: records without a question, rejected.
        let mut with_records = bare_error.clone();
        with_records[3] = 0x00;
        with_records[7] = 1;
        assert!(
            !answers_query(&query, &with_records),
            "reply carrying records without a question must be rejected"
        );
        // Truncated question
        assert!(!answers_query(&query, &query[..20]));
    }

    #[test]
    fn answers_query_needs_qr_and_the_querys_opcode() {
        let query = a_query_for("example.com.");
        let mut reply = query.clone();
        reply[2] |= 0x80;
        assert!(answers_query(&query, &reply));
        assert!(
            !answers_query(&query, &query),
            "the query itself, QR not set"
        );
        for opcode in [1u8, 2, 4, 5, 15] {
            let mut other = reply.clone();
            other[2] = (other[2] & !0x78) | (opcode << 3);
            assert!(!answers_query(&query, &other), "opcode {opcode}");
        }
        // The same holds for a reply without a question / 没有问题段的应答也一样
        let mut bare_error = reply[..12].to_vec();
        bare_error[3] = 0x01;
        bare_error[5] = 0;
        assert!(answers_query(&query, &bare_error));
        bare_error[2] &= !0x80;
        assert!(!answers_query(&query, &bare_error));
        bare_error[2] |= 0x80 | (2 << 3);
        assert!(!answers_query(&query, &bare_error));
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
            crate::ecs::extract_ecs_info(packet)
        }

        /// 把 `options` 原样放进 `message` 的 OPT：OPT 必须是最后一条记录，RDATA 为空
        /// Put `options` as they are into `message`'s OPT, which must be the last record
        /// and have empty RDATA
        fn with_raw_options(mut message: Vec<u8>, options: &[u8]) -> Vec<u8> {
            let rdlen_at = message.len() - 2;
            assert_eq!(message[rdlen_at..], [0, 0], "an OPT with empty RDATA last");
            message[rdlen_at..].copy_from_slice(&(options.len() as u16).to_be_bytes());
            message.extend_from_slice(options);
            message
        }

        /// 带 OPT、OPT 里没有选项的 example.com A 查询 / A query for example.com A with an
        /// OPT that has no options
        fn query_with_opt() -> Vec<u8> {
            let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
            msg.add_query(Query::query(
                Name::from_str("example.com.").unwrap(),
                RecordType::A,
            ));
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            msg.edns = Some(edns);
            msg.to_vec().unwrap()
        }

        /// 198.51.100.0/24 的 ECS 选项，SCOPE 0 / The ECS option for 198.51.100.0/24, SCOPE 0
        const ECS: [u8; 11] = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];
        /// 一个结构正确的别的选项 / Another, well-formed option
        const OTHER: [u8; 6] = [0xFD, 0xE9, 0, 2, 7, 7];
        /// 头只有两个字节的选项 / An option with only two bytes of header
        const CUT_HEADER: [u8; 2] = [0, 10];
        /// 说有 9 个字节、只带了 2 个的选项 / An option claiming 9 bytes and carrying 2
        const OVERRUN: [u8; 6] = [0, 10, 0, 9, 1, 2];

        /// 结构不对的选项：不止一个 ECS、ECS 不足 4 个字节，或者某个选项的头或内容超出了 RDATA
        /// （不论在 ECS 之前还是之后）
        /// Malformed options: more than one ECS, an ECS of fewer than 4 bytes, or an
        /// option whose header or content runs past the RDATA (before the ECS or after it)
        fn malformed_options() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("two ECS options", [ECS, ECS].concat()),
                ("an ECS of 3 bytes", vec![0, 8, 0, 3, 0, 1, 24]),
                (
                    "a cut header after the ECS",
                    [&ECS[..], &CUT_HEADER].concat(),
                ),
                ("an overrun after the ECS", [&ECS[..], &OVERRUN].concat()),
                ("a cut header alone", CUT_HEADER.to_vec()),
                ("an overrun alone", OVERRUN.to_vec()),
            ]
        }

        /// 应答的选项结构不对时，它的 ECS 读不出来；结构对的照常读出
        /// A reply whose options are malformed has an ECS that cannot be read; well-formed
        /// ones are read as usual
        #[test]
        fn malformed_options_make_the_replys_ecs_unreadable() {
            let reply_with = |options: &[u8]| with_raw_options(reply(true, None, false), options);
            for (what, options) in malformed_options() {
                assert_eq!(
                    reply_ecs(&reply_with(&options)),
                    (ReplyEcs::Unreadable, true),
                    "{what}"
                );
            }
            let read = ReplyEcs::Subnet {
                subnet: subnet("198.51.100.0", 24),
                scope: 0,
            };
            assert_eq!(reply_ecs(&reply_with(&ECS)), (read, true));
            assert_eq!(
                reply_ecs(&reply_with(&[&OTHER[..], &ECS, &OTHER].concat())),
                (read, true)
            );
            assert_eq!(reply_ecs(&reply_with(&OTHER)), (ReplyEcs::Absent, true));
        }

        /// 选项的头或内容超出 OPT 的 RDATA 时，应答去不掉 ECS，原样以 Err 交回（不论坏选项在 ECS 之前
        /// 还是之后）。结构对的去掉每一个 ECS 选项（两个也好、不足 4 个字节也好），留下别的选项
        /// A reply whose options' header or content runs past the OPT's RDATA cannot lose
        /// its ECS and is handed back in Err, whether the bad option comes before the ECS
        /// or after it. A well-formed one loses every ECS option (two of them, or one of
        /// fewer than 4 bytes, as well) and keeps the others
        #[test]
        fn a_reply_whose_options_run_past_the_opt_is_not_kept() {
            let reply_with = |options: &[u8]| with_raw_options(reply(true, None, false), options);
            for (what, options) in [
                (
                    "a cut header after the ECS",
                    [&ECS[..], &CUT_HEADER].concat(),
                ),
                ("an overrun after the ECS", [&ECS[..], &OVERRUN].concat()),
                ("a cut header alone", CUT_HEADER.to_vec()),
                ("an overrun alone", OVERRUN.to_vec()),
            ] {
                let packet = Bytes::from(reply_with(&options));
                assert_eq!(without_ecs(packet.clone()), Err(packet), "{what}");
            }
            let without = |options: &[u8]| without_ecs(Bytes::from(reply_with(options)));
            assert_eq!(
                without(&[&OTHER[..], &ECS, &OTHER].concat()),
                Ok(Bytes::from(reply_with(&[OTHER, OTHER].concat())))
            );
            assert_eq!(
                without(&[ECS, ECS].concat()),
                Ok(Bytes::from(reply_with(&[])))
            );
            assert_eq!(
                without(&[0, 8, 0, 3, 0, 1, 24]),
                Ok(Bytes::from(reply_with(&[])))
            );
        }

        /// 查询的选项头或内容超出 OPT 的 RDATA 时，查询读不出来；结构对的照常读出
        /// A query whose options' header or content runs past the OPT's RDATA cannot be
        /// read; a well-formed one is read as usual
        #[test]
        fn a_query_whose_options_run_past_the_opt_is_not_read() {
            let mut buf = [0u8; 256];
            for (what, options) in [
                ("a cut header", CUT_HEADER.to_vec()),
                ("an overrun", OVERRUN.to_vec()),
                (
                    "a cut header after another",
                    [&OTHER[..], &CUT_HEADER].concat(),
                ),
                ("an overrun after another", [&OTHER[..], &OVERRUN].concat()),
            ] {
                assert!(
                    parse_quick(&with_raw_options(query_with_opt(), &options), &mut buf).is_none(),
                    "{what}"
                );
            }
            let query = with_raw_options(query_with_opt(), &[OTHER, OTHER].concat());
            assert!(parse_quick(&query, &mut buf).is_some());
        }

        /// 选项结构不对的应答不算结构完整；结构对的算
        /// A reply whose options are malformed is not well formed; a well-formed one is
        #[test]
        fn a_reply_with_malformed_options_is_not_well_formed() {
            let reply_with = |options: &[u8]| with_raw_options(reply(true, None, false), options);
            for (what, options) in malformed_options() {
                assert!(!well_formed_reply(&reply_with(&options)), "{what}");
            }
            assert!(well_formed_reply(&reply_with(&[&OTHER[..], &ECS].concat())));
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
            let question_end = strict_name_end(&packet, 12).unwrap() + 4;
            let answer_fixed = strict_name_end(&packet, question_end).unwrap();
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
            super::push_bare_tsig(&mut packet);
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
                assert!(matches!(
                    query_without_hop_options(&packet),
                    Cow::Borrowed(_)
                ));
                let reply = Bytes::from(packet);
                assert_eq!(
                    reply_without_hop_options(reply.clone()).as_ptr(),
                    reply.as_ptr()
                );
            }
        }

        #[test]
        fn the_cookie_is_taken_out_and_the_other_options_kept() {
            let packet = query(true, true);
            let stripped = query_without_hop_options(&packet);
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
            let alone = query_without_hop_options(&query(true, false)).into_owned();
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
            let stripped = reply_without_hop_options(Bytes::from(packet));
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
            super::push_bare_tsig(&mut packet);
            assert!(matches!(
                query_without_hop_options(&packet),
                Cow::Borrowed(_)
            ));
        }
    }

    mod padding_wire {
        use super::super::*;
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
        use hickory_proto::rr::{Name, RecordType};
        use std::borrow::Cow;

        /// 问 `name` 的 A 记录；`option` 为 Some 时带 EDNS 和这个长的未知选项，None 时 EDNS 也不带
        /// An A query for `name`; with EDNS and an unknown option this long for Some, no EDNS at
        /// all for None
        fn query(name: &str, option: Option<usize>) -> Vec<u8> {
            let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
            msg.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            if let Some(len) = option {
                let mut edns = Edns::new();
                edns.options_mut()
                    .insert(EdnsOption::Unknown(65001, vec![7; len]));
                msg.edns = Some(edns);
            }
            msg.to_vec().unwrap()
        }

        /// 名字越来越长，补到的长度跨过几个块，有的正好不用补字节：每次都补到下一个 128 的整数倍，原有的选项
        /// 留在前面，填充排在最后、全是零；没有 OPT 的查询补一条 DO 位为零的 OPT
        /// With ever longer names the padded length crosses several blocks, some needing no
        /// padding bytes at all: each is padded to the next multiple of 128, the option already
        /// there stays ahead, the padding comes last and is all zeros; a query without an OPT
        /// gets one with the DO bit clear
        #[test]
        fn a_query_is_padded_to_the_next_multiple_of_128() {
            for labels in 1..40 {
                let name = format!("{}example.", "a.".repeat(labels));
                for option in [None, Some(3)] {
                    let packet = query(&name, option);
                    let padded = padded_query(&packet);
                    assert_eq!(padded.len() % QUERY_BLOCK, 0, "{name} {option:?}");
                    let room = if option.is_some() { 4 } else { 15 };
                    assert!(padded.len() - packet.len() < QUERY_BLOCK + room);
                    let msg = Message::from_vec(&padded).expect("still a valid message");
                    let edns = msg.edns.expect("an OPT");
                    assert!(!edns.flags().dnssec_ok);
                    let options = &edns.options().options;
                    assert_eq!(options.len(), 1 + usize::from(option.is_some()));
                    match options.last() {
                        Some((EdnsCode::Padding, EdnsOption::Unknown(_, zeros))) => {
                            assert!(zeros.iter().all(|&byte| byte == 0))
                        }
                        other => panic!("{other:?}"),
                    }
                }
            }
        }

        /// 签过名的查询不补：改了签名就不对了；补了就超过 65535 字节的也不补
        /// A signed query is not padded, as any change would break the signature; nor is one
        /// padding would take past 65535 bytes
        #[test]
        fn a_query_padding_would_break_is_sent_as_it_is() {
            let mut signed = query("example.", Some(3));
            super::push_bare_tsig(&mut signed);
            assert!(matches!(padded_query(&signed), Cow::Borrowed(_)));
            let long = query("example.", Some(65_440));
            assert!(long.len() > 65_408);
            assert!(matches!(padded_query(&long), Cow::Borrowed(_)));
        }
    }
}

/// 一遍走完记录（[`walk_records`]）和原来分开走的两遍结论一样：原来的两个函数原样留在这里对照，
/// 拿一批真实形状的报文和它们截断、改字节、改计数以后的样子逐个比
/// One walk over the records ([`walk_records`]) concludes what the two separate walks used
/// to: the two former functions stay here as they were, and each of a set of real-shaped
/// messages, truncated, with bytes changed and with counts changed, is compared
#[cfg(test)]
mod one_walk_tests {
    use super::*;
    use hickory_proto::op::{Edns, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    // 原来的 find_opt / The former find_opt
    fn reference_find_opt(packet: &[u8]) -> Result<Option<OptRecord>, ()> {
        if packet.len() < 12 {
            return Err(());
        }
        let before_additional = section_count(packet, 1) + section_count(packet, 2);
        let records = before_additional + section_count(packet, 3);
        let mut pos = skip_questions(packet, section_count(packet, 0)).ok_or(())?;
        let mut found = None;
        for index in 0..records {
            let record = record_at(packet, pos).ok_or(())?;
            if record.rdata.end > packet.len() {
                return Err(());
            }
            if record.rr_type == 41 {
                if index < before_additional || found.is_some() {
                    return Err(());
                }
                found = Some(OptRecord {
                    start: pos,
                    extended_rcode_at: record.fixed + 4,
                    rdlen_at: record.fixed + 8,
                    rdata: record.rdata.clone(),
                    last: index + 1 == records,
                });
            }
            pos = record.rdata.end;
        }
        Ok(found)
    }

    // 原来的 last_record_is_tsig / The former last_record_is_tsig
    fn reference_last_record_is_tsig(packet: &[u8]) -> bool {
        if packet.len() < 12 {
            return false;
        }
        let Some(mut pos) = skip_questions(packet, section_count(packet, 0)) else {
            return false;
        };
        let mut last_type = None;
        for _ in 0..(1..4).map(|index| section_count(packet, index)).sum() {
            // 最后一条的 RDATA 超出报文也照样算（原来如此）/ A last record whose RDATA runs
            // past the message still counts (as it always has)
            let Some(record) = record_at(packet, pos) else {
                return false;
            };
            last_type = Some(record.rr_type);
            pos = record.rdata.end;
        }
        last_type == Some(250)
    }

    /// 真实形状的报文：查询和应答、带不带 OPT、几条回答、CNAME 链带压缩指针、Authority 段、末尾的 TSIG
    /// Real-shaped messages: queries and replies, with and without OPT, several answers, a
    /// CNAME chain with compression pointers, an Authority section, a trailing TSIG
    fn seeds() -> Vec<Vec<u8>> {
        let name = Name::from_ascii("www.Example.com.").unwrap();
        let target = Name::from_ascii("edge.example.net.").unwrap();
        let mut seeds = Vec::new();
        for (kind, edns, do_bit, answers) in [
            (MessageType::Query, false, false, 0),
            (MessageType::Query, true, false, 0),
            (MessageType::Query, true, true, 0),
            (MessageType::Response, false, false, 1),
            (MessageType::Response, true, false, 1),
            (MessageType::Response, true, true, 4),
        ] {
            let mut m = Message::new(0x1234, kind, OpCode::Query);
            m.add_query(Query::query(name.clone(), RecordType::A));
            if answers > 0 {
                m.add_answer(Record::from_rdata(
                    name.clone(),
                    60,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                ));
                for i in 0..answers {
                    m.add_answer(Record::from_rdata(
                        target.clone(),
                        300,
                        RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, i)),
                    ));
                }
                m.add_authority(Record::from_rdata(
                    Name::from_ascii("example.net.").unwrap(),
                    300,
                    RData::NS(hickory_proto::rr::rdata::NS(target.clone())),
                ));
            }
            if edns {
                let mut e = Edns::new();
                e.set_max_payload(1232);
                e.set_dnssec_ok(do_bit);
                m.edns = Some(e);
            }
            seeds.push(m.to_vec().unwrap());
        }
        // 末尾补一条 TSIG（类型 250）/ A TSIG (type 250) appended at the end
        for base in seeds.clone() {
            let mut signed = base;
            let ar = u16::from_be_bytes([signed[10], signed[11]]) + 1;
            signed[10..12].copy_from_slice(&ar.to_be_bytes());
            signed.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 3, 1, 2, 3]);
            seeds.push(signed);
        }
        seeds
    }

    /// 截断、改一个字节、改各段计数、把记录类型改成 OPT 或 TSIG 以后的样子
    /// Each message truncated, with one byte changed, with section counts changed, and with
    /// record types turned into OPT or TSIG
    fn variants() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for seed in seeds() {
            for len in 0..=seed.len() {
                out.push(seed[..len].to_vec());
            }
            for _ in 0..400 {
                let mut changed = seed.clone();
                let at = next() as usize % changed.len();
                changed[at] = match next() % 4 {
                    0 => 41,
                    1 => 250,
                    2 => 0,
                    _ => next() as u8,
                };
                out.push(changed);
            }
            for _ in 0..200 {
                let mut changed = seed.clone();
                let at = 4 + (next() as usize % 8);
                changed[at] = (next() % 4) as u8;
                out.push(changed);
            }
            out.push(seed);
        }
        out
    }

    #[test]
    fn one_walk_concludes_what_the_two_walks_did() {
        let messages = variants();
        assert!(messages.len() > 5000);
        for message in &messages {
            let walk = walk_records(message);
            assert_eq!(walk.opt, reference_find_opt(message), "{message:?}");
            assert_eq!(
                walk.last_is_tsig,
                reference_last_record_is_tsig(message),
                "{message:?}"
            );
        }
    }

    /// 照应答规整时只走一遍应答：结果和问题名、RD/CD 改完以后再找一遍 OPT 一样
    /// Shaping a reply walks it once, with the result of looking for the OPT again after
    /// the question name and RD/CD were changed
    #[test]
    fn shaping_a_reply_with_one_walk_matches_walking_it_again() {
        let messages = variants();
        let queries: Vec<Vec<u8>> = seeds()
            .into_iter()
            .filter(|m| m[2] & 0x80 == 0)
            .flat_map(|q| {
                let mut lower = q.clone();
                lower[12..].make_ascii_lowercase();
                let mut flags = q.clone();
                flags[2] ^= 0x01;
                flags[3] ^= 0x10;
                [q, lower, flags]
            })
            .collect();
        for reply in &messages {
            for query in &queries {
                let reply = Bytes::from(reply.clone());
                let expected = if reference_last_record_is_tsig(&reply) {
                    reply.clone()
                } else {
                    edns_as_asked(
                        header_as_asked(
                            question_as_asked(reply.clone(), query),
                            query,
                            asked_dnssec_ok(query),
                        ),
                        query,
                    )
                };
                assert_eq!(
                    reply_as_asked(reply.clone(), query),
                    expected,
                    "{reply:?} {query:?}"
                );
            }
        }
    }
}
