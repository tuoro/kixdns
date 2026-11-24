//! V2Ray GeoIP .dat 文件里条目的 protobuf 结构，用 prost 按 protobuf 的规矩解：字段不论先后，不认识的字段按线上类型
//! 跳过，长度越出消息就是坏数据。文件顶层的 `repeated GeoIP entry = 1` 不交给 prost 一次解完，而是一个个条目读（见
//! `GeoIpManager::parse_dat_entries`），不把整个文件读进内存
//! The protobuf structures of the entries in a V2Ray GeoIP .dat file, decoded by protobuf's
//! rules with prost: fields come in any order, unknown fields are skipped by wire type, and a
//! length running past its message means broken data. The file's top level, `repeated GeoIP
//! entry = 1`, is not handed to prost whole but read entry by entry (see
//! `GeoIpManager::parse_dat_entries`), without reading the whole file into memory

use prost::Message;

/// GeoIPList：V2Ray .dat 的顶层结构，`repeated GeoIP entry = 1`。运行时不用它，按条目读（见
/// `GeoIpManager::parse_dat_entries`）；只有测试拿它写 .dat
/// GeoIPList: the top level of a V2Ray .dat, `repeated GeoIP entry = 1`. The runtime does not
/// use it and reads entry by entry (see `GeoIpManager::parse_dat_entries`); only tests write a
/// .dat with it
#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
pub struct GeoIPList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIP>,
}

/// GeoIP：一个国家或标签的条目，`string country_code = 1; repeated CIDR cidr = 2`
/// GeoIP: the entry of one country or tag, `string country_code = 1; repeated CIDR cidr = 2`
#[derive(Clone, PartialEq, Message)]
pub struct GeoIP {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
}

/// GeoIP 条目里只取国家代码，其余字段跳过不解：先用它判断条目要不要，要的再按 [`GeoIP`] 整个解
/// Just a GeoIP entry's country code, the other fields skipped undecoded: it decides whether
/// an entry is wanted, and wanted entries are then decoded whole as [`GeoIP`]
#[derive(Clone, PartialEq, Message)]
pub struct GeoIPCode {
    #[prost(string, tag = "1")]
    pub country_code: String,
}

/// Cidr：`bytes ip = 1; uint32 prefix = 2`（ip 是 4 字节的 IPv4 或 16 字节的 IPv6）
/// Cidr: `bytes ip = 1; uint32 prefix = 2` (ip is 4 bytes of IPv4 or 16 of IPv6)
#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes, tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}
