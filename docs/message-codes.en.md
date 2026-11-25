# Codes of configuration problems and warnings

[简体中文](message-codes.md) | **English**

Each configuration problem, warning, reason a configuration is refused for, and thing wrong with the Geo data that the kernel reports to the panel over the control channel carries, besides its English words, a fixed code and arguments; the panel says it its own way by the code, and shows the words for a code it does not know. Which fields carry them, and from which kernel on (the runtime capability `message_codes_v1`), is in the control protocol document of the panel repository, `docs/control-protocol-v1.en.md`; this page lists the codes alone.

The codes and arguments are written once each in the kernel source, `src/notice.rs`, where the English words come from as well. `kixdns::notice::CODES` in the library is every code with its argument names, in the order of the table below; the panel's check tool goes by it to make sure every code has Chinese words.

## What each one looks like

~~~json
{
  "place": "pipelines[0].rules[2].matchers[1]",
  "code": "matches_every_name",
  "args": { "matcher": "domain_suffix", "value": "." },
  "text": "pipelines[0].rules[2].matchers[1]: domain_suffix \".\" matches every name"
}
~~~

- `place`: where in the configuration it is about, as a path (`settings.bootstrap`, `pipeline_select[0]`, `pipelines[0].rules[2].matchers[1]`, the path of a key the kernel does not read). It goes by place, as rule names may repeat. What is wrong with the Geo data has no place, `null`.
- `text`: the English words, word for word the matching line of the list of strings beside it. With a place it is the place, a colon, a space and the English; without one the English alone. Where the list of strings is cut to 2048 characters, this is cut to the same length.
- `code`: a code from the table below; every one has one. A newer kernel may add codes, and one not known is shown by its `text`.
- `args`: the arguments, named as in the table. Arguments are not cut. A value is one of:
  - text: a value the configuration writes (`value`, `upstream`, `pipeline` and so on), a path (`path`), or an error written by a library or the system (`error`, see below);
  - a number: `value`, `most`, `bytes`, `times` and the like;
  - a list of text: `tags` (Geo tags), `capitals` (the parts of a regex in capitals that never match as written, as the regex writes them, without quotes);
  - one of a few fixed words: `matcher` is the kind of matcher (as `type` is written in a configuration, `domain_suffix` say), `transport` the transport (`udp`, `tcp`, `tcp+udp`, `doh`, `dot`, `doq`), `operator` `and_not` or `or_not`, `matchers` `matchers` or `response_matchers`, and `file` the kind of Geo data file: `geosite` (a GeoSite data file), `geoip` (a GeoIP data file) or `mmdb` (a GeoIP database);
  - a reason held within: `{code, args, text}`, with no `place`, its code also in the table. There are three: the `reason` of `upstream_unusable` and of `bootstrap_server_unusable`, and the `problem` of `default_upstream_over`. A reason's `text` is part of the words around it; with its code not known, show its `text`.

## What has no code

- Errors written by libraries and the system have no code and come as they are, as the argument `error`: the standard library's errors reading an IP address or a port, errors of url, rustls, ipnet and regex, errors of the file watch (notify), and errors reading Geo data files (a file that cannot be read, content that does not decode). Their words are written by the libraries depended on and change with their versions, with no fixed set of kinds to name; the panel shows them as they are.
- An error leaving a configuration unread (JSON written wrong, a wrong type, a file that cannot be read) is not among the reasons listed one by one: the list of reasons is then empty, with one error alone, written by serde and the system, with no code.
- System errors standing alone on the control channel: `watch_error` (why the configuration file cannot be watched) and `doh_error` (why the inbound DoH did not start) are one sentence each as before.

## Codes

| Code | Arguments | When it comes |
| --- | --- | --- |
| `no_upstream` | — | Problem: `settings.default_upstream`, or a forward in a rule, writes no upstream at all |
| `upstream_unknown_prefix` | `upstream`, `prefix` | Problem: the prefix of an upstream address (the `prefix` of `prefix://`) is not known |
| `upstream_unusable` | `upstream`, `reason` | Problem: an upstream address its transport cannot read, `reason` saying why (one of the reasons below) |
| `default_upstream_over` | `transport`, `problem` | Problem: a forward writing no upstream asks `settings.default_upstream` over `transport`, which cannot ask it; `problem` is an `upstream_unusable` |
| `bootstrap_server_unusable` | `server`, `reason` | Problem: a server in `settings.bootstrap` is no IP and port, `reason` saying why |
| `address_not_ip_port` | `error` | Reason: a UDP upstream is no IP address and port |
| `port_zero` | — | Reason: the port is 0 |
| `address_not_host_port` | — | Reason: a TCP upstream is no host and port |
| `port_invalid` | `error` | Reason: the port is no number, or above 65535 |
| `host_invalid` | `host` | Reason: the host name of a TCP upstream holds a character it may not |
| `doh_second_prefix` | `prefix` | Reason: a DoH upstream writes a second prefix after the first (`doh://http://…`) |
| `doh_url_invalid` | `error` | Reason: a DoH upstream does not read as a URL |
| `tls_server_name_invalid` | `error` | Reason: the TLS server name (SNI) of a DoT or DoQ upstream cannot be made |
| `second_prefix` | `prefix` | Reason: a DoT or DoQ upstream writes a second prefix after the first (`dot://tcp://…`) |
| `tls_url_invalid` | `transport`, `error` | Reason: a DoT or DoQ upstream does not read as a URL |
| `tls_host_missing` | `transport` | Reason: a DoT or DoQ upstream writes no host |
| `tls_path_given` | `transport` | Reason: a DoT or DoQ upstream writes a path |
| `zero_rtt_invalid` | `key`, `value` | Reason: the value of a DoQ upstream's `0rtt` or `enable_0rtt` parameter cannot be read |
| `tls_parameter_unknown` | `transport`, `key` | Reason: a DoT or DoQ upstream writes a parameter its transport does not read |
| `doq_ip_needs_sni` | — | Reason: a DoQ upstream written as an IP writes no `sni` |
| `doh_path_without_slash` | `path` | Problem: `settings.doh_path` does not start with `/` |
| `setting_over_limit` | `value`, `most` | Problem: a setting over its limit, startup using the limit; the place is the setting |
| `listen_address_invalid` | `value`, `error` | Problem: a listener address (`bind_udp`, `bind_tcp`, `bind_doh`) is no IP address and port |
| `doh_setting_missing` | `bind_doh` | Problem: `bind_doh` is set without the `doh_tls_cert` or `doh_tls_key` DoH needs; the place is the one not set |
| `cache_capacity_zero` | — | Problem: `settings.cache_capacity` is 0 |
| `cache_max_ttl_zero` | — | Problem: `settings.cache_max_ttl` is 0 |
| `refresh_threshold_too_high` | `value` | Problem: `settings.cache_refresh_threshold_percent` is 100 or more |
| `upstream_timeout_zero` | — | Problem: `settings.upstream_timeout_ms` is 0 |
| `dashmap_shards_invalid` | `value`, `most` | Problem: `settings.dashmap_shards` is neither 0 nor a power of two from 2 to `most` |
| `doq_idle_timeout_too_long` | `value` | Problem: `settings.doq_connection_idle_timeout_seconds` is more than QUIC can carry |
| `request_timeout_below_upstream` | `value`, `upstream` | Problem: `settings.request_timeout_ms` is less than `settings.upstream_timeout_ms` (`upstream`) |
| `select_pipeline_missing` | `pipeline` | Problem: a pipeline_select entry picks a pipeline that does not exist |
| `negation_on_first` | `operator`, `matchers` | Problem: the first of a chain of matchers (or the chain's own operator, with one matcher alone) is negated for nothing |
| `pipeline_id_repeated` | `times`, `id` | Problem: several pipelines are written with one id, only the first taking effect; raised once, at the first |
| `key_not_read` | — | Problem: the kernel does not read this key (most likely misspelt or written in the wrong place); the place is the key |
| `forward_ecs_differ` | — | Problem: the forwards of a rule asked together as one forward write different ecs |
| `ecs_ip_not_ip` | `ip` | Problem: the static ECS address of a forward is no IP |
| `rcode_unknown` | `rcode` | Problem: the rcode of a `static_response` is misspelt |
| `static_ip_invalid` | `ip` | Problem: the addresses of a `static_ip_response` are no comma-separated IPs |
| `cname_target_invalid` | `target` | Problem: the target of a `static_cname_response` is no domain name |
| `txt_no_string` | — | Problem: a TXT answer writes no string at all |
| `txt_segment_too_long` | `bytes`, `most` | Problem: a segment of a TXT answer is over 255 bytes |
| `txt_too_long` | `bytes`, `most` | Problem: a TXT answer does not fit in an answer |
| `log_level_unknown` | `level` | Problem: the level of a `log` action is misspelt |
| `jump_target_missing` | `pipeline` | Problem: a jump to a pipeline that does not exist |
| `matches_every_name` | `matcher`, `value` | Problem: a matcher's value written empty (or a lone dot), matching every name |
| `matches_only_root` | `matcher` | Problem: `domain_exact` or `request_domain_exact` written empty, matching only the root name |
| `txt_empty_matches_every_answer` | `mode` | Problem: `response_txt_content` with an empty value in prefix or regex mode, matching every answer with a TXT record |
| `response_rcode_unknown` | `rcode` | Problem: a `response_rcode` is misspelt |
| `never_matches` | `matcher`, `value` | Warning: a matcher's value written empty, never matching |
| `no_country_code` | `matcher` | Warning: a GeoIP country matcher writing no country code, never matching |
| `regex_capitals` | `matcher`, `pattern`, `capitals` | Warning: a name regex writes capitals outside `(?i)`, which never match as written |
| `listener_label_outside_select` | — | Problem: `listener_label` written in a rule, while it works in pipeline_select only |
| `network_invalid` | `value`, `error` | Problem: a network is mistyped |
| `regex_too_long` | `bytes`, `most` | Problem: a regex is written too long |
| `regex_invalid` | `error` | Problem: a name regex is written wrong or too large compiled; the words are the regex library's error |
| `txt_regex_invalid` | `error` | Problem: the regex of a `response_txt_content` is written wrong or too large compiled |
| `qclass_unknown` | `qclass` | Problem: a query class not known |
| `qtype_unknown` | `qtype` | Problem: a query type not known |
| `txt_mode_unknown` | `mode` | Problem: the mode of a `response_txt_content` is none of exact, prefix, regex |
| `background_refresh_rule_unused` | — | Warning: a `background_refresh_rule` written, which no longer does anything |
| `setting_retired` | — | Warning: a retired setting written; the place is the setting |
| `cache_capacity_large` | `value` | Warning: `settings.cache_capacity` is above one million |
| `request_timeout_short` | `value`, `upstream` | Warning: `settings.request_timeout_ms` is under 2.5 times the upstream timeout (`upstream`) |
| `jump_cycle` | `target`, `back_to` | Warning: jumping to `target` and on comes back round to `back_to` (the pipeline of this rule) |
| `geosite_tags_without_data` | `tags` | Warning: rules use GeoSite tags while `settings.geosite_data_paths` is empty |
| `geoip_tags_without_data` | `tags` | Warning: rules use GeoIP tags with neither `settings.geoip_dat_path` nor `settings.geoip_db_path` set |
| `geoip_tags_beyond_mmdb` | `tags` | Warning: rules use GeoIP tags that are no two-letter codes with only `settings.geoip_db_path` set, not `settings.geoip_dat_path` |
| `host_names_without_bootstrap` | `host` | Warning: `settings.bootstrap` unset while some upstream is written with a host name |
| `data_file_missing` | `file`, `path` | Geo data: a configured file is not there |
| `data_file_unreadable` | `file`, `path`, `error` | Geo data: a configured file cannot be read |
| `data_file_tags_gone` | `file`, `path`, `tags` | Geo data: a file reads yet has none of the tags rules use any more, `tags` keeping the data read from it before |
| `data_watch_failed` | `file`, `error` | Geo data: the watch thread of one kind of data (`file` being `geosite` or `geoip`) cannot start |
| `data_file_partly_watched` | `file`, `path`, `error` | Geo data: a file has places that cannot be watched, changes there noticed by the check every 10 s |
| `geosite_tags_unprovided` | `tags` | Geo data: GeoSite tags rules use are in no data file |
| `geoip_tags_unprovided` | `tags` | Geo data: GeoIP tags rules use are in no GeoIP data |

A "problem" comes among a configuration's `problems` and the reasons a reload or validation refuses it for, a "warning" among `warnings`, a "reason" only within the arguments of another saying, and "Geo data" among `data_warnings`. The problems found only as a configuration compiles (listener addresses, settings that make no sense, matchers that do not compile) come among the reasons for refusing it alone, never among startup's `problems`: they stop the kernel from starting.
