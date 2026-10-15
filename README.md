# KixDNS

**简体中文** | [English](./README.en.md)

KixDNS 是用 Rust 写的异步、非递归 DNS 转发服务器：接收 UDP、TCP 查询（可选 DoH），按有序的 Pipeline 规则转发给上游，或直接构造响应。

本仓库是 [olicesx/kixdns](https://github.com/olicesx/kixdns) 的 fork：在上游代码上加了我们的修复和面板接口，按日期版本发布（见 [Releases](https://github.com/tuoro/kixdns/releases)），由 [KixDNS 面板](https://github.com/tuoro/kixdns-panel) 安装和更新。

> 注意：本项目完全由 AI 构建（内容、文档与初始实现均由 AI 生成）。

## 用面板管理

推荐配合 [KixDNS 面板](https://github.com/tuoro/kixdns-panel) 使用：一条命令装好面板和本内核，之后在浏览器里编辑配置（保存前校验，热加载失败自动回滚）、查看运行概览、做 DNS 诊断、更新内核。安装方法见面板的[安装说明](https://github.com/tuoro/kixdns-panel#安装)。

## 功能

- **入站**：DNS over UDP、TCP，可选 DoH（RFC 8484）。
- **上游**：UDP、TCP、TCP 与 UDP 同时发、DoH、DoT、DoQ（RFC 9250）；可以写多个上游，并发查询，取第一个可用的应答。
- **路由**：按监听器标签、客户端地址、域名、查询类型和类别、EDNS、GeoIP、GeoSite 选择 Pipeline 和规则；匹配器可用 and、or、and_not、or_not 组合。
- **按应答处理**：按应答 IP、RCODE、记录类型、TXT 内容等判断，回退到别的上游、过滤或替换应答、跳转到别的 Pipeline。
- **静态应答**：RCODE、A/AAAA、CNAME、TXT。
- **缓存**：容量、TTL 上下限、并发未命中合并、后台刷新、过期兜底（RFC 8767）；按 ECS 作用范围保存应答（RFC 7871）。
- **GeoIP 与 GeoSite**：MaxMind MMDB、V2Ray GeoIP 和 GeoSite 数据；自带把 GeoIP `.dat` 转成 MMDB 的命令。
- **热加载**：配置、GeoSite 和 GeoIP `.dat` 数据、DoH 证书文件更新后自动生效；新配置或新证书无效时继续用旧的。
- **性能**：基于 tokio 的异步 I/O，UDP 按 worker 分 socket，规则用不到时转发路径不完整解析报文，可选自适应流控。

## 单独运行

不用面板时：

~~~bash
cargo build --release
./target/release/kixdns run -c config/pipeline.json
~~~

默认在 UDP 和 TCP `0.0.0.0:5353` 上监听，上游是 `1.1.1.1:53`。需要支持 Rust edition 2024 的工具链。

## 文档

- [运行](docs/usage.md)：构建、命令行参数、日志和响应统计、systemd、测试
- [配置参考](docs/configuration.md)：配置文件结构、全局设置、Pipeline 和规则、匹配器、动作、ECS、网络协议、配置示例、缓存和重载行为

## 许可证

[GPL-3.0](LICENSE)
