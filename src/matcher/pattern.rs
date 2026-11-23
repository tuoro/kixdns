//! 规则里的正则：按 ASCII 编译、限制编译后的大小。域名正则照写的区分大小写（写了 `(?i)` 才不分），规则看到的名字
//! 已转成小写（见 `proto_utils::name_text`），所以不带 `(?i)` 写成大写的字母不会命中
//! The regexes in rules: compiled for ASCII with a bound on their compiled size. A domain regex
//! is case-sensitive as written (ignoring case only under `(?i)`), and the names rules see are
//! lowercased already (see `proto_utils::name_text`), so without `(?i)` a letter written in
//! capitals never matches

use super::*;
/// 正则写得比 `max` 字节长时的报错 / The error for a regex written longer than `max` bytes
pub(crate) fn regex_within(pattern: &str, max: usize) -> anyhow::Result<()> {
    if pattern.len() > max {
        anyhow::bail!(
            "regex pattern too long: {} bytes (max {max})",
            pattern.len()
        );
    }
    Ok(())
}

/// 一条域名正则（GeoSite 数据的和配置的）实际要编译的写法：照写的解析，每个字符类只留 ASCII 的部分、词边界按 ASCII 分（见
/// [`ascii_hir`]），再写回正则；写错了返回语法错误，比 [`MAX_REGEX_LEN`] 长的不解析，直接返回错误。规则看到的名字只有 ASCII
/// （见 `proto_utils::name_text`），匹配结果和照写的相同，`\w`、`\d`、`\s`、`\b` 也正是 Go（v2ray）的含义。照写的按
/// Unicode 编译，一个 `\pL` 是上千个状态：256 条 `^\pL{20}…` 合成的集合占 670 MB、比一个名字要 7 µs，只留 ASCII 后 3 MB、
/// 1 ns；`.` 和取反的字符类也小一半、快一倍。只检查语法、不编译：GeoSite 数据文件里一个 tag 的正则读完以后合成一个集合，
/// 只编译这一次（见 `geosite::Regexes::new`）。
/// The pattern a domain regex (of GeoSite data, or of a configuration) actually compiles as:
/// parsed as written, every class kept to its ASCII part and word boundaries drawn the ASCII
/// way (see [`ascii_hir`]), then written back out; a syntax error when written wrong, and one
/// longer than [`MAX_REGEX_LEN`] is an error without being parsed. The names rules see are
/// ASCII alone (see `proto_utils::name_text`), so they match as written, and `\w`, `\d`, `\s`
/// and `\b` take just their Go (v2ray) meaning. Compiled as written, as Unicode, one `\pL` is
/// over a thousand states: 256 regexes `^\pL{20}…` combined took 670 MB and 7 µs a name, and
/// kept to ASCII 3 MB and 1 ns; `.` and negated classes come out half the size and twice as
/// fast too. Only the syntax is checked, nothing compiles: a GeoSite data file's regexes for
/// one tag are combined into one set once read, which is the only compile (see
/// `geosite::Regexes::new`).
pub(super) fn ascii_regex_pattern(pattern: &str) -> anyhow::Result<String> {
    regex_within(pattern, MAX_REGEX_LEN)?;
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .map_err(Box::new)?;
    // 写出的正则解析回来就是这棵树 / The pattern written out parses back into this very tree
    Ok(ascii_hir(hir).to_string())
}

/// `hir` 只留 ASCII 的部分：字符类和 ASCII 取交集，词边界换成按 ASCII 的 `\w` 分的
/// `hir` kept to its ASCII part: classes intersected with ASCII, word boundaries the ones drawn
/// by the ASCII `\w`
fn ascii_hir(hir: regex_syntax::hir::Hir) -> regex_syntax::hir::Hir {
    use regex_syntax::hir::{Class, ClassUnicode, ClassUnicodeRange, Hir, HirKind, Look};
    match hir.into_kind() {
        HirKind::Class(Class::Unicode(mut class)) => {
            class.intersect(&ClassUnicode::new([ClassUnicodeRange::new('\0', '\x7f')]));
            Hir::class(Class::Unicode(class))
        }
        // 字节类只能是 ASCII：照写的解析不收匹配得到非 UTF-8 的正则 / A byte class can only be ASCII:
        // a pattern that could match beyond UTF-8 does not parse
        HirKind::Class(class) => Hir::class(class),
        HirKind::Look(look) => Hir::look(match look {
            Look::WordUnicode => Look::WordAscii,
            Look::WordUnicodeNegate => Look::WordAsciiNegate,
            Look::WordStartUnicode => Look::WordStartAscii,
            Look::WordEndUnicode => Look::WordEndAscii,
            Look::WordStartHalfUnicode => Look::WordStartHalfAscii,
            Look::WordEndHalfUnicode => Look::WordEndHalfAscii,
            other => other,
        }),
        HirKind::Repetition(mut repetition) => {
            repetition.sub = Box::new(ascii_hir(*repetition.sub));
            Hir::repetition(repetition)
        }
        HirKind::Capture(mut capture) => {
            capture.sub = Box::new(ascii_hir(*capture.sub));
            Hir::capture(capture)
        }
        HirKind::Concat(subs) => Hir::concat(subs.into_iter().map(ascii_hir).collect()),
        HirKind::Alternation(subs) => Hir::alternation(subs.into_iter().map(ascii_hir).collect()),
        HirKind::Literal(literal) => Hir::literal(literal.0),
        HirKind::Empty => Hir::empty(),
    }
}

/// 域名的正则（规则和入口的 `domain_regex`、回答条件的 `request_domain_regex`）：最长 [`MAX_REGEX_LEN`] 字节，按写的
/// 长度在解析之前查；照写的得是对的正则，字符类只留 ASCII 的部分，和 GeoSite 的正则一样（见 [`ascii_regex_pattern`]）；
/// 编译后限 1 MB（见 [`limited_regex`]）
/// A name regex (`domain_regex` in rules and entries, `request_domain_regex` in answer
/// conditions): at most [`MAX_REGEX_LEN`] bytes as written, checked before it is parsed; valid
/// as written, with every class kept to its ASCII part, as in GeoSite regexes (see
/// [`ascii_regex_pattern`]); and within 1 MB compiled (see [`limited_regex`])
pub(super) fn domain_regex(pattern: &str) -> anyhow::Result<Regex> {
    Ok(limited_regex(&ascii_regex_pattern(pattern)?)?)
}

/// 匹配器的正则（域名的，和 TXT 内容的）编译时状态空间和 DFA 各限 1 MB，防止复杂度攻击
/// A matcher's regex (for names, and for TXT content) compiled with the state space and the
/// DFA each capped at 1 MB against complexity attacks
pub(super) fn limited_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(1_000_000)
        .dfa_size_limit(1_000_000)
        .build()
}
