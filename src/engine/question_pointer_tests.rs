//! 问题名里的压缩指针不能指进报文头（偏移 12 以前）：那里不会有名字，转发时报文头一变（事务 ID 换成随机数），
//! 上游读到的名字就不是路由时看到的那个。这样的查询读不了，监听器回 FORMERR，不转发。
//! A compression pointer in the question name may not point into the header (before offset
//! 12): no name starts there, and once the header changes on the way out (the transaction ID
//! replaced with a random one) the name the upstream reads is not the one routed on. Such a
//! query cannot be read: the listener answers FORMERR and nothing is forwarded.

use crate::engine::test_support::{answering_upstream, counting_settings, engine_from, peer};
use serde_json::json;

/// 问 `safe.example` 的 A 记录，名字用一个指向偏移 `target` 的指针收尾，不写结尾的 0。事务 ID 的高字节是 0：
/// 指针指到偏移 0 时，读到的就是名字结束
/// An A query for `safe.example` whose name ends in a pointer to offset `target` instead of
/// the closing 0. The transaction ID's high byte is 0: with the pointer at offset 0, what is
/// read there is the name's end
fn pointing_at(target: u8) -> Vec<u8> {
    let mut query = vec![0x00, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x04safe\x07example");
    query.extend_from_slice(&[0xC0, target]);
    query.extend_from_slice(&[0, 1, 0, 1]);
    query
}

/// 指向报文头的问题名：快速路径读不了，完整路径也读不了，不会转发给上游。以前两条路都把它读成 safe.example，
/// 按它路由、缓存，转发出去的报文换了 ID，上游读到的名字面目全非
/// A question name pointing into the header: neither the fast path nor the full path reads
/// it, and nothing goes upstream. Both used to read it as safe.example, routing and caching
/// on it, while the forwarded packet carried another ID and the upstream read a mangled name
#[tokio::test]
async fn a_question_name_pointing_into_the_header_is_not_forwarded() {
    let upstream = answering_upstream(std::net::Ipv4Addr::new(192, 0, 2, 1), 300).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream.address }]
        }]}]
    }));
    for target in [0, 2, 11] {
        let packet = pointing_at(target);
        assert!(
            matches!(engine.handle_packet_fast(&packet, peer()), Ok(None)),
            "pointer to {target}: the fast path does not read it"
        );
        let full = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            engine.handle_packet(&packet, peer()),
        )
        .await
        .expect("in time");
        assert!(
            full.is_err(),
            "pointer to {target}: the full path refuses it"
        );
        let failure = crate::engine::engine_helpers::try_build_listener_failure_from_wire(&packet)
            .expect("a standard query header gets an answer");
        assert_eq!(
            failure[3] & 0x0F,
            1,
            "pointer to {target}: the listener answers FORMERR"
        );
    }
    assert_eq!(upstream.queries(), 0, "nothing was forwarded");
}
