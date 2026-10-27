# 配置参考

**简体中文** | [English](configuration.en.md)

本文档以当前 main 分支代码为准。配置类型可以反序列化但运行引擎尚未读取的字段会明确标注。

## 配置文件

配置格式为 JSON：

~~~json
{
  "version": "1.0",
  "settings": {},
  "pipeline_select": [],
  "pipelines": []
}
~~~

version 可省略。settings、pipeline_select 和 pipelines 省略时分别使用默认/空值。没有 Pipeline selector 匹配时使用第一个 Pipeline；没有 Pipeline 时使用全局默认上游。

### 全局设置

| 字段 | 默认值 | 说明 |
|---|---:|---|
| min_ttl | 0 | 上游回答的 TTL 下限，单位秒：回答里每条记录的 TTL 至少提高到这个值，缓存也至少留这么久。 |
| bind_udp | 0.0.0.0:5353 | UDP 监听地址。 |
| bind_tcp | 0.0.0.0:5353 | TCP 监听地址。 |
| bind_doh | null | 入站 DoH 监听地址；null 表示禁用。 |
| doh_tls_cert | null | PEM 证书路径；设置 bind_doh 时必需。 |
| doh_tls_key | null | PEM 私钥路径；设置 bind_doh 时必需。 |
| doh_path | /dns-query | 入站 DoH 请求路径。 |
| default_upstream | 1.1.1.1:53 | 默认上游；支持逗号分隔列表。 |
| upstream_timeout_ms | 9000 | 单次上游操作超时；必须大于 0。 |
| request_timeout_ms | null | 整体请求超时；为 null 时使用 upstream_timeout_ms * 2.5，且不能小于 upstream_timeout_ms。 |
| response_jump_limit | 10 | 响应阶段 Pipeline 跳转上限。 |
| udp_pool_size | 64 | 出站 UDP socket 池大小。 |
| tcp_pool_size | 64 | 每个上游的 TCP 连接池大小。 |
| doh_pool_size | 8 | 每个上游最多保留的 DoH 空闲连接数。 |
| dot_pool_size | 64 | 每个上游的 DoT 连接池大小。 |
| doq_pool_size | 16 | 每个上游的 DoQ 连接池大小。 |
| tcp_health_check_error_threshold | 3 | 连续错误达到该次数后重置 TCP/DoT 连接；0 禁用。 |
| tcp_connection_max_age_seconds | 300 | TCP/DoT 连接最大存活时间；0 禁用。 |
| tcp_connection_idle_timeout_seconds | 60 | TCP/DoT 空闲超时；0 禁用。 |
| doq_connection_idle_timeout_seconds | 60 | DoQ 空闲超时；0 禁用。 |
| doq_keepalive_interval_ms | 15000 | DoQ keepalive 间隔；0 禁用。 |
| doq_enable_0rtt | true | 全局 DoQ 0-RTT 设置。 |
| enable_tcp_fallback | true | UDP 失败或截断时用 TCP 重试。 |
| flow_control_enabled | false | 启用基于 permits 的自适应流控。 |
| flow_control_initial_permits | 500 | 启用流控时的初始 permits。 |
| flow_control_min_permits | 100 | 启用流控时的最小 permits。 |
| flow_control_max_permits | 800 | 启用流控时的最大 permits。 |
| flow_control_latency_threshold_ms | 100 | 自适应流控使用的延迟阈值。 |
| flow_control_adjustment_interval_secs | 5 | permits 调整间隔。 |
| cache_capacity | 10000 | DNS 响应缓存最多存放的应答数；必须大于 0。 |
| cache_max_ttl | 86400 | DNS 缓存条目的最大生存时间，单位秒；必须大于 0。上游回答里每条记录的 TTL 也不超过它，和 min_ttl 冲突时以它为准。 |
| dashmap_shards | 0 | 内部分片设置；0 使用 DashMap 默认值，否则必须是 2 的幂。 |
| cache_background_refresh | false | 在 TTL 过期前刷新条目。 |
| cache_refresh_threshold_percent | 10 | 按剩余 TTL 百分比触发刷新；必须小于 100，取 100 时每次缓存命中都会刷新上游。 |
| cache_refresh_min_ttl | 5 | 参与后台刷新的最小 TTL。 |
| serve_stale | false | 按 RFC 8767 行为保留并返回过期条目。 |
| serve_stale_ttl | 30 | 过期响应中写入的 TTL。 |
| serve_stale_expire_ttl | 86400 | 允许返回过期条目的最大时间，单位秒；0 表示不限制过期时间。 |
| serve_stale_ttl_reset | true | 返回过期数据时重置过期时间窗口。 |
| serve_stale_client_timeout_ms | 0 | 0 表示立即返回过期数据；大于 0 时先尝试上游最多指定毫秒数，并受 request_timeout_ms 剩余预算截断，保证过期应答来得及返回。 |
| geoip_db_path | null | MaxMind MMDB 路径。 |
| geoip_dat_path | null | V2Ray GeoIP 数据文件路径：可以是 protobuf `.dat`，也可以是下文说明的兼容 JSON。 |
| geosite_data_paths | [] | V2Ray GeoSite .dat 或 JSON 路径列表；支持多个文件。 |

当前配置类型会反序列化 geoip_auto_convert 和 geoip_filter_countries，但运行引擎没有读取它们，因此它们不会改变运行行为。转换时的国家过滤请使用 convert-geo-ip 的 --filter。顶层 background_refresh_rule 也会被读取，但当前运行时配置编译会忽略它。

### Pipeline 选择

pipeline_select 的每项包含 Pipeline id、可选的匹配器列表和可选的 matcher_operator。数组按顺序评估；第一个匹配且 id 存在的项选择对应 Pipeline。

### Pipeline 和规则

每个 Pipeline 包含 id、可选的 rules 数组和可选的 Pipeline 级 ecs。Pipeline 级 ecs 是旧配置用来区分缓存的，现在不再影响缓存（改动它时，热加载后该 Pipeline 的缓存仍会重新开始）。规则按配置顺序处理。空匹配器列表视为匹配。规则内的匹配器按从左到右形成链；每个匹配器可以携带自己的 operator，或者在所有匹配器都省略 operator 时由规则级 matcher_operator 设置。

响应阶段使用同样的 response_matchers、response_matcher_operator、response_actions_on_match 和 response_actions_on_miss。Forward 得到响应后执行响应动作；配置了 miss 动作时，上游尝试全部失败后也会进入 miss 路径。

### Pipeline selector 和请求匹配器

| 类型 | 字段 |
|---|---|
| any | 无 |
| listener_label | value |
| client_ip | cidr |
| domain_suffix | value |
| domain_regex | value |
| qclass | value：IN、CH/CHAOS 或 HS |
| edns_present | expect：布尔值 |
| geo_site | value：GeoSite tag |
| geo_site_not | value：GeoSite tag |
| geoip_country | country_codes：字符串数组 |
| geoip_private | expect：布尔值 |
| qtype | value：A、AAAA、CNAME、MX、TXT、NS、PTR、SOA、SRV 或 OPT |

Pipeline selector 支持上表全部类型；请求规则支持除 listener_label 之外的全部类型。

#### GeoIP 数据源与标签

- `geoip_db_path` 加载 MaxMind MMDB，用于 `CN`、`US` 等两位国家代码。
- `geoip_dat_path` 加载 V2Ray protobuf `.dat` 或兼容 JSON。这里的 JSON 是 GeoIP 数据文件，不是 KixDNS 主配置文件；格式示例：`{"entries":[{"country_code":"CLOUDFLARE","ips":["1.1.1.0/24"]}]}`。
- V2Ray 数据既可以包含国家代码，也可以包含 `CLOUDFLARE`、`NETFLIX`、`TELEGRAM` 等命名标签；同一 IP 可以属于多个标签。
- 同时配置两种数据源时，两位国家代码以 MMDB 为准；命名标签仍从 `geoip_dat_path` 读取。
- 只读入规则用到的国家代码和标签。MMDB 只在规则用到两位国家代码时读入；`geoip_dat_path` 只读入规则用到、又不由 MMDB 判断的标签，所以配置了 MMDB、规则只用两位国家代码时，这个文件不读。规则用到的标签不在文件里时会记一条告警，这样的规则不会命中。
- 标签匹配不区分大小写。`country_codes` 建议使用 JSON 字符串数组，例如 `["CN", "cloudflare"]`；为兼容旧配置，也接受单个字符串或逗号分隔字符串。

域名后缀和 GeoSite 标签匹配也不区分大小写。domain_suffix 和 request_domain_suffix 按整段域名比较：`example.com` 命中它本身和 `www.example.com` 这样的子域名，`.example.com` 只命中子域名；两种写法都不命中 `notexample.com`。domain_regex 和 request_domain_regex 使用 Rust 正则语法。

#### GeoSite 条目

- 写法与 V2Ray 的域名列表（domain-list-community）相同。`domain:example.com` 和不带前缀的 `example.com` 按整段匹配域名本身及其所有子域名（不匹配 `notexample.com`）；和 domain_suffix 不同，这里开头加点不改变含义。
- `full:example.com` 只匹配域名本身，`keyword:`、`regexp:` 按关键词、正则匹配，不带前缀且含 `*` 的值按通配符匹配。
- `.dat` 文件里的标签可以带属性键，写作 `tag@attr`（如 `google@cn`），和 V2Ray 一样按字面键匹配：`google@!cn` 选的是标记为 `!cn` 的域名。不带属性的域名用 `geo_site: google` 加上 `geo_site_not: google@cn` 选出。
- JSON 里前缀不认识、没有值或正则无效的条目会跳过并给出警告。

### 响应匹配器

| 类型 | 字段 |
|---|---|
| upstream_equals | value；按运行时上游标签做字符串精确比较 |
| request_domain_suffix | value |
| request_domain_regex | value |
| response_upstream_ip | cidr；支持逗号分隔 CIDR |
| response_answer_ip | cidr；支持逗号分隔 CIDR |
| response_type | value；优先检查第一个 Answer 记录，没有 Answer 时使用查询类型 |
| response_rcode | value：NOERROR、FORMERR、SERVFAIL、NXDOMAIN、NOTIMP、REFUSED；未知值作为 OTHER 回退匹配 |
| response_qclass | value |
| response_edns_present | expect：布尔值 |
| response_answer_ip_geoip_country | country_codes：字符串数组 |
| response_answer_ip_geoip_private | expect：布尔值 |
| response_request_domain_geo_site | value：GeoSite tag |
| response_request_domain_geo_site_not | value：GeoSite tag |
| response_txt_content | mode：exact、prefix 或 regex；value 为文本/模式 |

响应地址匹配范围如下：

- `response_answer_ip_geoip_country` 只检查 Answer；每个包含地址的 Answer 都必须命中请求的某个 GeoIP 标签。
- `response_answer_ip` 和 `response_answer_ip_geoip_private` 同时检查 Answer 与 Additional，只要任一地址匹配即可。
- 匹配器会检查 A/AAAA 地址以及 HTTPS/SVCB 的 `ipv4hint`/`ipv6hint`。同一 HTTPS/SVCB 记录中的 hints 是候选端点，任一 hint 匹配即可。

这些匹配器只读取已有记录，不会创建或改写 HTTPS/SVCB 记录。

当前成功上游标签包含传输前缀，例如 udp:1.1.1.1:53 或 tcp:1.1.1.1:53。因此 upstream_equals 的 value 必须包含该前缀。response_upstream_ip 当前解析原始 IP 或 host:port，不会剥离传输前缀。

### 逻辑运算符

运算符从左到右计算，第一个匹配器作为初始结果。

| 运算符 | 含义 |
|---|---|
| and | 下一个匹配器必须为 true，默认值。 |
| or | 累积结果为 false 时，使用下一个匹配器结果。 |
| and_not | 累积结果为 true 时，下一个匹配器必须为 false。 |
| or_not | 累积结果为 false 时，下一个匹配器必须为 false。 |
| not | 反序列化时作为 and_not 的别名。 |

同时接受 and-not、andnot、or-not 和 ornot 别名。

### 动作

| 类型 | 字段 | 行为 |
|---|---|---|
| log | level（可选） | 输出匹配规则的 tracing 事件；支持 trace、debug、info、warn、error。 |
| static_response | rcode | 返回 NOERROR、FORMERR、SERVFAIL、NXDOMAIN、NOTIMP 或 REFUSED。 |
| static_ip_response | ip | 按查询类型返回 A 或 AAAA 记录（ANY 查询返回两者）；HTTPS、SVCB 等其他查询类型返回 NODATA，且不会合成 IP hints。`ip` 支持单个地址或逗号分隔的 IPv4/IPv6 地址列表（例如 `192.0.2.1,2001:db8::1`）。地址列表原样返回；列表过大时响应可能超过 UDP 大小限制。 |
| static_cname_response | target、ttl（可选） | 对所有查询类型返回将查询域名映射到 `target` 的 CNAME 记录；ttl 默认 300。服务端不会继续解析目标域名，也不会附带目标地址记录，客户端或解析器必须自行追踪别名；不能追踪裸 CNAME 的客户端可能返回无数据。查询域名或目标域名无效时返回 SERVFAIL。 |
| static_txt_response | text、ttl（可选） | 返回 TXT 响应；text 支持字符串或字符串数组，ttl 默认 300。 |
| jump_to_pipeline | pipeline | 开始处理指定 Pipeline。 |
| allow | 无 | 请求阶段：使用全局默认 UDP 上游；响应阶段：保留当前上游响应。 |
| deny | 无 | 返回 REFUSED。 |
| forward | upstream（可选）、transport（可选）、ecs（可选） | 转发到指定上游；缺少 upstream 时使用 default_upstream。 |
| continue | 无 | 继续处理下一个请求规则，或继续响应流程中的下一个 Pipeline 决策。 |
| replace_txt_response | text | 响应阶段替换当前响应中的 TXT 记录；请求阶段不会产生响应。 |

### ECS

ECS 配置在 Forward 动作中：

~~~json
{
  "type": "forward",
  "upstream": "8.8.8.8:53",
  "ecs": {
    "mode": "from_client_ip",
    "prefix_v4": 24,
    "prefix_v6": 56
  }
}
~~~

支持的模式：

- clear：移除请求中的 ECS 选项；
- from_client_ip：客户端自己带了 ECS 时，转发它自己的子网，前缀比这里设置的长就截短到设置的长度，前缀为 0 的原样转发、不加地址（RFC 7871 第 7.1 节）；客户端带的是私有网段或 IPv4 映射形式（`::ffff:a.b.c.d`）的网段时当作没带，不发给上游（第 11.3 节）；带的选项读不懂时去掉，也不加来源地址的子网。没带时根据客户端地址生成子网，IPv4 默认 /24、IPv6 默认 /56，私有地址、回环地址和 ULA 地址不注入；
- static：使用配置的 IP 和前缀注入。

不写 ecs 的转发把客户端自己带的 ECS 选项原样发往上游。

缓存的应答遵循 RFC 7871 第 7.3 节。每份应答只给它适用的请求方，依据是转发实际发出的 ECS，以及上游应答里的 SCOPE PREFIX-LENGTH（作用范围）：

- 作用范围为 0，或者带 ECS 的查询得到不带 ECS 选项的应答（按作用范围 0 处理），适用于每个转发时发送 ECS 子网的请求；不发送 ECS 的请求问上游的是另一种查询，单独保存自己的应答；
- 作用范围不超过发出的前缀时，适用于子网落在该网段内的请求；作用范围更长时，只适用于前缀相同的同一子网；
- 不带 ECS 发出的查询，应答只给同样不带 ECS 的请求；前缀为 0 发出的，只给同样前缀为 0 的请求；
- 不带 ECS 的报错应答（NOERROR、NXDOMAIN 以外的 RCODE）、回显了别的子网的应答，以及转发失败，都只对同一个子网有效；
- 客户端的 ECS 选项不完全符合 RFC 7871 第 6 节时，应答不缓存。

查找时在适用的应答中取前缀最长的一份。同一个问题最多保存 64 个网段的应答；满了时先淘汰只适用于单个子网的应答，同一类请求方共用的应答最后淘汰。并发未命中去重只合并发送相同子网的请求。没带 ECS 的客户端拿到的应答不带 ECS 选项，不论是否来自缓存；带了 ECS 的客户端拿回自己的子网，作用范围不短于 KixDNS 保存这份应答所用的范围。Pipeline 级 ecs 仍可写在配置里，但不再影响缓存。

## 网络协议

### 入站

UDP 和 TCP 监听器分别由 settings.bind_udp 和 settings.bind_tcp 创建。

入站监听器行为：

- 只处理标准单 question 的 QUERY 消息。畸形包、非 QUERY opcode 和 DNS 响应包会被静默丢弃。
- 监听器处理错误、整体请求超时或流控 permit 耗尽时，对合法查询返回 SERVFAIL。
- 大于客户端声明大小（EDNS 载荷大小；无 EDNS 时为 512 字节）的 UDP 响应会在记录边界截断并置 TC 位，客户端可据此改用 TCP 重试。
- 双栈套接字（例如监听 `[::]` 的入站 DoH）把 IPv4 客户端报成 `::ffff:a.b.c.d`。规则、GeoIP、ECS 和缓存都按它背后的 IPv4 地址判断，client_ip 照常写 IPv4 网段；写成 `::ffff:a.b.c.d/n` 的网段按它所指的 IPv4 网段处理。

只有设置 settings.bind_doh 后才会启用入站 DoH。启用时必须同时设置 settings.doh_tls_cert 和 settings.doh_tls_key，且路径指向 PEM 文件。路径默认为 /dns-query，可通过 settings.doh_path 修改。

入站 DoH 处理器：

- 接收配置路径上的 POST 请求，并读取 DNS wire message 请求体；
- 接收配置路径上的 GET 请求，并读取 dns 查询参数中的无填充 base64url 数据；
- 拒绝大于 64 KiB 的 DNS 请求体；
- 成功处理后返回 application/dns-message。

DoT 和 DoQ 只作为出站传输实现，代码没有入站 DoT/DoQ 监听器。

### 出站

Forward 动作的 transport 字段可选以下值：

| 值 | 传输 |
|---|---|
| udp | DNS over UDP |
| tcp | DNS over TCP |
| tcp_udp | 同时发送 TCP 和 UDP，使用第一个可接受的响应 |
| doh | DNS over HTTPS |
| dot | DNS over TLS |
| doq | DNS over QUIC |

upstream 支持字符串、逗号分隔字符串或 JSON 字符串数组。多个上游会并发查询并返回第一个可接受的响应；在多个上游选择时，SERVFAIL 和 REFUSED 响应不会被接受。

以下协议前缀会覆盖 transport 字段：

| 前缀 | 传输 | 别名 |
|---|---|---|
| udp:// | UDP | |
| tcp:// | TCP | |
| tcp+udp://、udp+tcp:// | TCP+UDP | |
| doh:// | DoH | https:// |
| dot:// | DoT | tls:// |
| doq:// | DoQ | quic:// |

没有协议前缀时，省略 transport 默认为 UDP。没有路径的 DoH URL 使用 /dns-query。DoH 支持使用 host 查询参数覆盖 HTTP Host；该参数不会继续发送给上游。DoH 只接受状态为成功、媒体类型为 application/dns-message、不超过 65535 字节的回答；跳转（3xx）不跟随，和其他错误状态一样算这个上游失败。

DoT 未提供端口时使用 853。可通过 sni 或 servername 查询参数设置 TLS 名称，且 DoT 上游不能包含 DNS path。

DoQ 未提供端口时使用 853。可通过 sni/servername 和 0rtt/enable_0rtt 查询参数配置。使用 IP 字面量的 DoQ 上游必须显式设置 SNI。0-RTT 默认全局启用，也可以按上游覆盖；用了 0-RTT 的连接超时或被拒绝后，会在进程重启前对该上游的所有连接禁用 0-RTT。被拒绝既包括明确报告拒绝，也包括对端直接关闭或重置连接——拒收早期数据的服务器常常是这么回应的；没用 0-RTT 的连接超时只算回答慢，不影响 0-RTT。

上游的回答必须是这次查询的问题（名称不分大小写，类型和类别相同）才收：UDP、TCP、DoT 上对不上的回答丢掉，继续等真正的回答；DoH、DoQ 上一个查询只有一个回答，对不上就算这个上游失败。没有问题段、也不带任何记录的错误回答（有些上游这样回 FORMERR、NOTIMP）照收。

UDP 转发失败或 UDP 响应被截断时，TCP fallback 默认启用，可通过 settings.enable_tcp_fallback 禁用。该 fallback 属于转发路径，不是额外监听器。

## 配置示例

### 基本路由和静态响应

~~~json
{
  "version": "1.0",
  "settings": {
    "bind_udp": "0.0.0.0:5353",
    "bind_tcp": "0.0.0.0:5353",
    "default_upstream": "1.1.1.1:53"
  },
  "pipeline_select": [
    {
      "pipeline": "internal",
      "matchers": [
        { "type": "listener_label", "value": "edge-internal" }
      ]
    }
  ],
  "pipelines": [
    {
      "id": "internal",
      "rules": [
        {
          "name": "internal-dns",
          "matchers": [
            { "type": "domain_suffix", "value": ".internal" }
          ],
          "actions": [
            { "type": "forward", "upstream": "10.0.0.53:53", "transport": "tcp" }
          ]
        }
      ]
    },
    {
      "id": "default",
      "rules": [
        {
          "name": "block-example",
          "matchers": [
            { "type": "domain_suffix", "value": ".blocked.example" }
          ],
          "actions": [
            { "type": "static_response", "rcode": "NXDOMAIN" }
          ]
        },
        {
          "name": "default-forward",
          "matchers": [ { "type": "any" } ],
          "actions": [
            { "type": "forward", "upstream": null }
          ]
        }
      ]
    }
  ]
}
~~~

### 响应阶段回退

~~~json
{
  "settings": {
    "default_upstream": "223.5.5.5:53"
  },
  "pipelines": [
    {
      "id": "fallback",
      "rules": [
        {
          "name": "reject-polluted-answer",
          "matchers": [ { "type": "any" } ],
          "actions": [
            { "type": "forward", "upstream": "223.5.5.5:53", "transport": "udp" }
          ],
          "response_matchers": [
            { "type": "response_answer_ip", "cidr": "127.0.0.0/8,0.0.0.0/8" }
          ],
          "response_actions_on_match": [
            { "type": "continue" }
          ],
          "response_actions_on_miss": [
            { "type": "allow" }
          ]
        },
        {
          "name": "backup",
          "matchers": [ { "type": "any" } ],
          "actions": [
            { "type": "forward", "upstream": "8.8.4.4:53", "transport": "tcp" }
          ]
        }
      ]
    }
  ]
}
~~~

### 入站 DoH

~~~json
{
  "settings": {
    "bind_doh": "0.0.0.0:8443",
    "doh_tls_cert": "/etc/kixdns/cert.pem",
    "doh_tls_key": "/etc/kixdns/key.pem",
    "doh_path": "/dns-query"
  },
  "pipelines": [
    {
      "id": "default",
      "rules": [
        {
          "name": "forward-all",
          "matchers": [ { "type": "any" } ],
          "actions": [ { "type": "forward", "upstream": "1.1.1.1:53" } ]
        }
      ]
    }
  ]
}
~~~

## 缓存和重载行为

上游回答交出去、写进缓存之前，每条记录的 TTL 先收进 min_ttl 到 cache_max_ttl 之间（两者冲突时以 cache_max_ttl 为准），客户端留一份回答的时间就和缓存一样长。DNS 响应缓存使用回答的最小 TTL，否定响应在存在 SOA 时使用 SOA 负缓存 TTL，同样收进这个范围，并受 cache_capacity 限制；没有 SOA 的否定响应不缓存（RFC 2308 第 4 节）。相同的进行中缓存未命中会共享一次上游操作。

Pipeline 的应答可能因请求方而不同时，响应缓存、并发未命中去重和规则缓存会按规则对请求方的判定把它们分开，而不是按地址：客户端地址是否在各个 client_ip 网段内，是否为私有地址（geoip_private），GeoIP 国家或标签是否匹配（geoip_country），查询是否带 EDNS（edns_present、response_edns_present）。转发取自客户端的子网用来分开并发未命中的请求，缓存的应答则按 ECS 作用范围区分（见 ECS）。判定相同的请求方共用条目。Pipeline 的回答检查开始的响应跳转路径上的规则也算在内，因为请求在应答之前会运行它们。这条路径转发的是跳转前那次转发准备的包，连同 ECS，所以它的并发未命中条目和直接进入该 Pipeline 的请求分开；这条路径上得到的应答不写缓存，因为没有哪次查找用它的键。规则缓存保存的是 Pipeline 自身规则的决策，因此只按该 Pipeline 的请求匹配器判定；开启 cache_background_refresh 时还按客户端地址区分，与以前相同。规则不判定任何请求方信息的 Pipeline 照旧在所有客户端之间共享。后台刷新从同一个客户端地址重放请求，原请求带 EDNS、带客户端自己的 ECS 选项时也一样带上（不符合 RFC 7871 第 6 节的 ECS 选项不带），因此 Pipeline 选择、请求规则和发往上游的 ECS 都与那次请求相同。刷新得到的应答适用的请求方与被刷新的条目不同时（例如上游的作用范围变窄了），那个条目会被删掉，它的请求方各自重新查询。

启用 cache_background_refresh 后，接近过期的条目可以触发异步刷新。刷新和客户端请求一样执行规则，包括响应规则及其动作。上游给出应答时，规则接受的应答替换这个条目；规则的结果不缓存在这个条目下时（不缓存的静态应答，或经跳转得到的应答），条目会被删除，由下一个客户端请求自己执行规则。上游失败（包括跳转目标的上游失败；失败之后由 on_miss 动作或后面的规则兜底的也算，之后又越过一个新应答的不算）或规则没找到应答时，除非规则得出的结果缓存在这个条目下，否则条目保留。刷新以 SERVFAIL 结束时（跳转超过上限、跳转目标不存在、静态 SERVFAIL 等）同样算失败：日志里记为刷新失败，SERVFAIL 也不写进缓存；只拿到被截断的应答时也算失败。启用 serve_stale 后，可以返回过期条目，并使用 serve_stale_ttl 作为响应 TTL，同时受 serve_stale_expire_ttl 和 serve_stale_client_timeout_ms 限制。该客户端等待还会被本次请求 request_timeout_ms 的剩余预算截断，配得比请求预算还长也不会把过期应答拖过截止时刻。

主配置 watcher 使用按 Pipeline 划分的缓存命名空间重载有效 JSON。发生变化的 Pipeline 会立即停止访问旧配置产生的响应缓存、规则缓存和进行中请求；未变化的 Pipeline 会保留热缓存。任意全局设置变化都会轮换所有 Pipeline 的缓存命名空间。旧命名空间中的条目不会被同步删除，而是继续受现有缓存容量和 TTL 策略限制。包括后台刷新和响应阶段跳转在内，每个请求都会保持选择其缓存命名空间时的配置快照，因此重载前启动的任务无法写入当前生效的缓存代际。无效的重载会保留旧配置。

下面这些写法以前能加载，却会悄悄做成别的事：读不懂的上游地址（端口不对、UDP 上游不是 IP 地址、不认识的前缀如 `http://`、IP 字面量的 DoQ 没写 SNI）、拼错的 rcode（以前回 NXDOMAIN）、无效的静态 IP 或 CNAME 目标、装不进一条记录的 TXT（以前回 SERVFAIL）、跳到不存在的 Pipeline（跳转动作或 pipeline_select），以及空的 domain_suffix 或 domain_regex（以前匹配所有域名）。启动时遇到它们只在日志里记警告、照旧加载，已经在用的配置升级以后行为不变；热重载和控制通道的配置校验会拒绝，并一次列出全部问题，所以下一次改配置时要把它们改掉。

下面这些全局设置只在启动时读取，重载不会让它们生效，修改后要重启服务：`bind_udp`、`bind_tcp`、`bind_doh`、`doh_path`、`doh_tls_cert`、`doh_tls_key`、`cache_capacity`、`cache_max_ttl`、`dashmap_shards`、`udp_pool_size`、`tcp_pool_size`、`doh_pool_size`、`doh_health_check_error_threshold`、`dot_pool_size`、`doq_pool_size`、`tcp_health_check_error_threshold`、`tcp_connection_max_age_seconds`、`tcp_connection_idle_timeout_seconds`、`doq_connection_idle_timeout_seconds`、`doq_keepalive_interval_ms`、`doq_enable_0rtt` 和全部 `flow_control_*`。其余全局设置重载即生效。重载后，配置里改过、还在等重启的设置会出现在控制通道 `config` 结果的 `restart_pending` 里；改回启动时的值，或者重启以后，它就不再出现。UDP worker 数量由命令行指定，同样只在启动时生效。DoH TLS 证书/私钥 PEM 文件续期后会热更新生效，但修改配置中的证书路径仍需重启。

重载后，配置里不再出现的上游会关闭它们的 TCP、DoT、DoQ 连接；正在使用这些连接的请求处理完之后才会关闭。

geosite_data_paths 中的 GeoSite 文件和 geoip_dat_path 指定的 GeoIP 文件会被监控，文件变了就重新读入；geoip_db_path 指定的 MMDB 不监控。GeoSite 的 `.dat` 只读入规则用到的标签，一个都没用到时既不读也不监控；GeoIP 数据只读入规则（geoip_country、response_answer_ip_geoip_country）用到的国家代码和标签（见上文 GeoIP 数据源与标签），不读的文件也不监控。热加载改变了规则用到的 GeoSite 或 GeoIP 标签，或这几个文件路径时，会按新配置重新读入 Geo 数据，并改为监控新的文件；新数据读完才替换旧数据，新规则从第一个请求起就用新数据。配置里写了、当时还不存在的文件，出现以后的下一次热加载会读入。被监控的文件重新读出来以后，规则用到的标签一个都没有了、而它此前提供过（比如下载失败留下的空文件），这次不替换，正在用的数据保留到文件下次改动。规则用到、却没有一个 GeoSite 数据文件提供的标签会记一条告警，和 GeoIP 一样。
