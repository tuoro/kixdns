# 配置问题和提醒的代号

**简体中文** | [English](message-codes.en.md)

内核经控制通道报给面板的配置问题、告警、拒掉配置的原因和 Geo 数据的问题，每条除了一句英文原话，还带着一个固定的代号和参数，面板按代号用自己的说法讲，认不出的代号照原话显示。哪些字段带这些话、内核从哪一版起有（运行时能力 `message_codes_v1`），见面板仓库的控制协议文档 `docs/control-protocol-v1.md`；这里只列代号。

代号和参数在内核源码 `src/notice.rs` 里每种写一次，英文原话也是从那里来的。库里的 `kixdns::notice::CODES` 是全部代号和各自的参数名，顺序和下面的表一样；面板的检查工具拿它核对每个代号都有中文说法。

## 每一条的样子

~~~json
{
  "place": "pipelines[0].rules[2].matchers[1]",
  "code": "matches_every_name",
  "args": { "matcher": "domain_suffix", "value": "." },
  "text": "pipelines[0].rules[2].matchers[1]: domain_suffix \".\" matches every name"
}
~~~

- `place`：说的是配置里哪一处，写成路径（`settings.bootstrap`、`pipeline_select[0]`、`pipelines[0].rules[2].matchers[1]`、内核不读的键的路径）。按位置说，因为规则名可以重复。Geo 数据的问题没有位置，为 `null`。
- `text`：英文原话，和旁边那份字符串列表里对应的一条一字不差。有位置时是位置、冒号、空格和英文，没有位置时只有英文。字符串列表截到 2048 字的，这里也截到一样长。
- `code`：下面表里的代号，每条都有。更新的内核可能加新代号，认不出的照 `text` 显示。
- `args`：参数，名字见下表。参数不截。值是下面几种之一：
  - 文字：配置里写的值（`value`、`upstream`、`pipeline` 等）、路径（`path`），或者库和系统给的错误文字（`error`，见下）；
  - 数：`value`、`most`、`bytes`、`times` 这类；
  - 文字的列表：`tags`（Geo 标签）、`capitals`（正则里照写命不中的大写部分，按正则的写法，不带引号）；
  - 固定的几个词：`matcher` 是匹配器的种类（配置里 `type` 的写法，如 `domain_suffix`），`transport` 是传输（`udp`、`tcp`、`tcp+udp`、`doh`、`dot`、`doq`），`operator` 是 `and_not` 或 `or_not`，`matchers` 是 `matchers` 或 `response_matchers`，`file` 是 Geo 数据文件的种类：`geosite`（GeoSite 数据文件）、`geoip`（GeoIP 数据文件）、`mmdb`（GeoIP 数据库）；
  - 套着的原因：`{code, args, text}`，没有 `place`，代号也在下表里。只有三处：`upstream_unusable` 和 `bootstrap_server_unusable` 的 `reason`、`default_upstream_over` 的 `problem`。原因的 `text` 就在外面那句原话里，认不出它的代号时照它的 `text`。

## 哪些没有代号

- 库和系统给的错误文字没有代号，作为参数 `error` 原样给出：标准库读 IP 地址、端口时的错误，url、rustls、ipnet、regex 的错误，文件监视（notify）的错误，读 Geo 数据文件时的错误（文件读不了、内容解不开）。这些文字由依赖的库写，随库的版本变，说不出固定的种类，面板照原样显示。
- 读不成配置的错误（JSON 写错了、类型不对、文件读不了）不在逐条的原因里：这时拒掉的原因列表是空的，只有一句错误，由 serde 和系统写，没有代号。
- 控制通道里单独一句的系统错误：`watch_error`（配置文件为什么监视不了）和 `doh_error`（入站 DoH 为什么没起来），照旧是一句话。

## 代号

| 代号 | 参数 | 什么时候出现 |
| --- | --- | --- |
| `no_upstream` | — | 问题：`settings.default_upstream`，或者规则里一个 forward，一个上游也没写 |
| `upstream_unknown_prefix` | `upstream`, `prefix` | 问题：上游地址的前缀（`prefix://` 里的 `prefix`）不认识 |
| `upstream_unusable` | `upstream`, `reason` | 问题：上游地址按它的传输读不懂，`reason` 是为什么（下面的原因之一） |
| `default_upstream_over` | `transport`, `problem` | 问题：不写上游的 forward 经 `transport` 问 `settings.default_upstream`，经这种传输问不了；`problem` 是 `upstream_unusable` |
| `bootstrap_server_unusable` | `server`, `reason` | 问题：`settings.bootstrap` 里的一个服务器不是 IP 和端口，`reason` 是为什么 |
| `address_not_ip_port` | `error` | 原因：UDP 上游不是 IP 地址和端口 |
| `port_zero` | — | 原因：端口是 0 |
| `address_not_host_port` | — | 原因：TCP 上游不是主机和端口 |
| `port_invalid` | `error` | 原因：端口不是数，或者大于 65535 |
| `host_invalid` | `host` | 原因：TCP 上游的主机名里有不该有的字符 |
| `doh_second_prefix` | `prefix` | 原因：DoH 上游的前缀后面又写了一个前缀（`doh://http://…`） |
| `doh_url_invalid` | `error` | 原因：DoH 上游读不成 URL |
| `tls_server_name_invalid` | `error` | 原因：DoT、DoQ 的 TLS 服务器名（SNI）做不成 |
| `second_prefix` | `prefix` | 原因：DoT、DoQ 上游的前缀后面又写了一个前缀（`dot://tcp://…`） |
| `tls_url_invalid` | `transport`, `error` | 原因：DoT、DoQ 上游读不成 URL |
| `tls_host_missing` | `transport` | 原因：DoT、DoQ 上游没写主机 |
| `tls_path_given` | `transport` | 原因：DoT、DoQ 上游写了路径 |
| `zero_rtt_invalid` | `key`, `value` | 原因：DoQ 上游的 `0rtt`、`enable_0rtt` 参数值读不懂 |
| `tls_parameter_unknown` | `transport`, `key` | 原因：DoT、DoQ 上游写了这种传输不读的参数 |
| `doq_ip_needs_sni` | — | 原因：写成 IP 的 DoQ 上游没写 `sni` |
| `doh_path_without_slash` | `path` | 问题：`settings.doh_path` 不以 `/` 开头 |
| `setting_over_limit` | `value`, `most` | 问题：设置超过上限，启动时按上限用；位置是那个设置 |
| `listen_address_invalid` | `value`, `error` | 问题：监听地址（`bind_udp`、`bind_tcp`、`bind_doh`）不是 IP 地址和端口 |
| `doh_setting_missing` | `bind_doh` | 问题：设了 `bind_doh`，却没设 DoH 要的 `doh_tls_cert` 或 `doh_tls_key`；位置是没设的那个 |
| `cache_capacity_zero` | — | 问题：`settings.cache_capacity` 是 0 |
| `cache_max_ttl_zero` | — | 问题：`settings.cache_max_ttl` 是 0 |
| `refresh_threshold_too_high` | `value` | 问题：`settings.cache_refresh_threshold_percent` 不小于 100 |
| `upstream_timeout_zero` | — | 问题：`settings.upstream_timeout_ms` 是 0 |
| `dashmap_shards_invalid` | `value`, `most` | 问题：`settings.dashmap_shards` 既不是 0 也不是 2 到 `most` 之间 2 的幂 |
| `doq_idle_timeout_too_long` | `value` | 问题：`settings.doq_connection_idle_timeout_seconds` 大得 QUIC 装不下 |
| `request_timeout_below_upstream` | `value`, `upstream` | 问题：`settings.request_timeout_ms` 小于 `settings.upstream_timeout_ms`（`upstream`） |
| `select_pipeline_missing` | `pipeline` | 问题：pipeline_select 的一条选的 pipeline 不存在 |
| `negation_on_first` | `operator`, `matchers` | 问题：一串匹配器的第一个（或者只有一个时规则级）写了取反，白写 |
| `pipeline_id_repeated` | `times`, `id` | 问题：几个 pipeline 写了同一个 id，只有第一个生效；在第一个的位置报一次 |
| `key_not_read` | — | 问题：内核不读这个键（多半拼错或写错地方）；位置是这个键 |
| `forward_ecs_differ` | — | 问题：一条规则里合成一次转发的几个 forward 的 ecs 写得不一样 |
| `ecs_ip_not_ip` | `ip` | 问题：forward 的静态 ECS 地址不是 IP |
| `rcode_unknown` | `rcode` | 问题：`static_response` 的 rcode 拼错了 |
| `static_ip_invalid` | `ip` | 问题：`static_ip_response` 的地址不是逗号分隔的 IP |
| `cname_target_invalid` | `target` | 问题：`static_cname_response` 的目标不是域名 |
| `txt_no_string` | — | 问题：TXT 应答一段文字都没写 |
| `txt_segment_too_long` | `bytes`, `most` | 问题：TXT 应答有一段超过 255 字节 |
| `txt_too_long` | `bytes`, `most` | 问题：TXT 应答装不进一个回答 |
| `log_level_unknown` | `level` | 问题：`log` 动作的级别拼错了 |
| `jump_target_missing` | `pipeline` | 问题：跳转的 pipeline 不存在 |
| `matches_every_name` | `matcher`, `value` | 问题：匹配器的值写成空（或者一个点），什么名字都匹配 |
| `matches_only_root` | `matcher` | 问题：`domain_exact`、`request_domain_exact` 写成空，只匹配根名字 |
| `txt_empty_matches_every_answer` | `mode` | 问题：`response_txt_content` 在前缀或正则模式下值写成空，带 TXT 的回答都匹配 |
| `response_rcode_unknown` | `rcode` | 问题：`response_rcode` 拼错了 |
| `never_matches` | `matcher`, `value` | 告警：匹配器的值写成空，永远不命中 |
| `no_country_code` | `matcher` | 告警：GeoIP 国家匹配器一个国家代码也没写，永远不命中 |
| `regex_capitals` | `matcher`, `pattern`, `capitals` | 告警：域名正则不在 `(?i)` 下写了大写字母，照写命不中 |
| `listener_label_outside_select` | — | 问题：`listener_label` 写在规则里，它只在 pipeline_select 里用得上 |
| `network_invalid` | `value`, `error` | 问题：网段写错了 |
| `regex_too_long` | `bytes`, `most` | 问题：正则写得太长 |
| `regex_invalid` | `error` | 问题：域名正则写错了或者编译后太大；原话就是正则库的错误 |
| `txt_regex_invalid` | `error` | 问题：`response_txt_content` 的正则写错了或者编译后太大 |
| `qclass_unknown` | `qclass` | 问题：查询类别不认识 |
| `qtype_unknown` | `qtype` | 问题：查询类型不认识 |
| `txt_mode_unknown` | `mode` | 问题：`response_txt_content` 的模式不是 exact、prefix、regex |
| `background_refresh_rule_unused` | — | 告警：写了不再起作用的 `background_refresh_rule` |
| `setting_retired` | — | 告警：写了退役的设置；位置是那个设置 |
| `cache_capacity_large` | `value` | 告警：`settings.cache_capacity` 大于 100 万 |
| `request_timeout_short` | `value`, `upstream` | 告警：`settings.request_timeout_ms` 短于上游超时（`upstream`）的 2.5 倍 |
| `jump_cycle` | `target`, `back_to` | 告警：跳到 `target` 一路跳下去回到 `back_to`（这条规则所在的 pipeline） |
| `geosite_tags_without_data` | `tags` | 告警：规则用到 GeoSite 标签，`settings.geosite_data_paths` 却是空的 |
| `geoip_tags_without_data` | `tags` | 告警：规则用到 GeoIP 标签，`settings.geoip_dat_path` 和 `settings.geoip_db_path` 都没设 |
| `geoip_tags_beyond_mmdb` | `tags` | 告警：规则用到不是两个字母的 GeoIP 标签，只设了 `settings.geoip_db_path`，没设 `settings.geoip_dat_path` |
| `host_names_without_bootstrap` | `host` | 告警：没设 `settings.bootstrap`，却有写成主机名的上游 |
| `data_file_missing` | `file`, `path` | Geo 数据：配置的文件不存在 |
| `data_file_unreadable` | `file`, `path`, `error` | Geo 数据：配置的文件读不了 |
| `data_file_tags_gone` | `file`, `path`, `tags` | Geo 数据：文件读得出来，却没有规则用到的标签了，`tags` 留着先前从它读进来的数据 |
| `data_watch_failed` | `file`, `error` | Geo 数据：这种数据（`file` 是 `geosite` 或 `geoip`）的监视线程起不来 |
| `data_file_partly_watched` | `file`, `path`, `error` | Geo 数据：文件有位置监视不上，那里的改动由每 10 秒一次的核对察觉 |
| `geosite_tags_unprovided` | `tags` | Geo 数据：规则用到的 GeoSite 标签哪个数据文件里都没有 |
| `geoip_tags_unprovided` | `tags` | Geo 数据：规则用到的 GeoIP 标签哪份 GeoIP 数据里都没有 |

「问题」在配置的 `problems`、重载和校验拒掉时的原因里，「告警」在 `warnings` 里，「原因」只套在别的话的参数里，「Geo 数据」在 `data_warnings` 里。编译时才查出来的问题（监听地址、说不通的设置、编译不了的匹配器）只在拒掉的原因里，不在启动时的 `problems` 里：它们让内核起不来。
