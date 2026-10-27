# Configuration reference

[简体中文](configuration.md) | **English**

This document describes the implementation currently on the main branch. Configuration fields that are accepted by deserialization but are not used by the running engine are called out explicitly.

## Configuration file

The configuration is JSON:

~~~json
{
  "version": "1.0",
  "settings": {},
  "pipeline_select": [],
  "pipelines": []
}
~~~

version is optional. settings, pipeline_select, and pipelines default to an empty/default value when omitted. If no pipeline selector matches, the first pipeline is used. If there is no pipeline, the request uses the global default upstream.

### Global settings

| Field | Default | Meaning |
|---|---:|---|
| min_ttl | 0 | Minimum upstream/cache TTL in seconds. |
| bind_udp | 0.0.0.0:5353 | UDP listen address. |
| bind_tcp | 0.0.0.0:5353 | TCP listen address. |
| bind_doh | null | Inbound DoH listen address; null disables it. |
| doh_tls_cert | null | PEM certificate path; required with bind_doh. |
| doh_tls_key | null | PEM private-key path; required with bind_doh. |
| doh_path | /dns-query | Inbound DoH request path. |
| default_upstream | 1.1.1.1:53 | Default upstream. A comma-separated list is accepted. |
| upstream_timeout_ms | 9000 | Timeout for one upstream operation; must be greater than zero. |
| request_timeout_ms | null | Overall request timeout. When null, it is upstream_timeout_ms * 2.5. It must be at least upstream_timeout_ms. |
| response_jump_limit | 10 | Maximum response-phase pipeline jumps. |
| udp_pool_size | 64 | Outbound UDP socket-pool size. |
| tcp_pool_size | 64 | TCP connections per upstream pool. |
| doh_pool_size | 8 | Maximum idle DoH connections per upstream. |
| dot_pool_size | 64 | DoT connections per upstream pool. |
| doq_pool_size | 16 | DoQ connections per upstream pool. |
| tcp_health_check_error_threshold | 3 | Reset a TCP/DoT connection after this many consecutive errors; 0 disables this check. |
| tcp_connection_max_age_seconds | 300 | Maximum TCP/DoT connection age; 0 disables aging. |
| tcp_connection_idle_timeout_seconds | 60 | TCP/DoT idle timeout; 0 disables it. |
| doq_connection_idle_timeout_seconds | 60 | DoQ idle timeout; 0 disables it. |
| doq_keepalive_interval_ms | 15000 | DoQ keepalive interval; 0 disables keepalive. |
| doq_enable_0rtt | true | Global DoQ 0-RTT setting. |
| enable_tcp_fallback | true | Retry UDP failure or truncation with TCP. |
| flow_control_enabled | false | Enable adaptive permit-based flow control. |
| flow_control_initial_permits | 500 | Initial permits when flow control is enabled. |
| flow_control_min_permits | 100 | Minimum permits when flow control is enabled. |
| flow_control_max_permits | 800 | Maximum permits when flow control is enabled. |
| flow_control_latency_threshold_ms | 100 | Latency threshold used by adaptive flow control. |
| flow_control_adjustment_interval_secs | 5 | Permit adjustment interval. |
| cache_capacity | 10000 | Maximum answers in the DNS response cache; must be greater than zero. |
| cache_max_ttl | 86400 | Maximum lifetime of a DNS cache entry in seconds; must be greater than zero. |
| dashmap_shards | 0 | Internal shard setting; 0 uses the DashMap default, otherwise the value must be a power of two. |
| cache_background_refresh | false | Refresh entries before their TTL expires. |
| cache_refresh_threshold_percent | 10 | Refresh threshold as a percentage of the entry TTL; must be below 100, since at 100 every cache hit refreshes upstream. |
| cache_refresh_min_ttl | 5 | Minimum refresh TTL considered for background refresh. |
| serve_stale | false | Keep and serve expired entries according to RFC 8767 behavior. |
| serve_stale_ttl | 30 | TTL written into a stale response. |
| serve_stale_expire_ttl | 86400 | Maximum stale age in seconds; 0 means no stale-age limit. |
| serve_stale_ttl_reset | true | Reset the stale-age window when stale data is served. |
| serve_stale_client_timeout_ms | 0 | 0 serves stale immediately; a positive value tries the upstream for up to this many milliseconds first, bounded by what is left of request_timeout_ms so the stale answer still goes out in time. |
| geoip_db_path | null | MaxMind MMDB path. |
| geoip_dat_path | null | V2Ray GeoIP data path: either a protobuf `.dat` file or the compatible JSON format described below. |
| geosite_data_paths | [] | V2Ray GeoSite .dat or JSON paths; multiple files are accepted. |

The following fields are deserialized by the current config type but are not read by the running engine: geoip_auto_convert and geoip_filter_countries. Use convert-geo-ip with --filter for conversion-time filtering. The top-level background_refresh_rule is also currently ignored by runtime configuration compilation.

### Pipeline selection

Each item in pipeline_select has a pipeline id, an optional matcher list, and an optional matcher_operator. Items are evaluated in array order. The first matching item whose pipeline id exists selects that pipeline.

### Pipelines and rules

Each pipeline has an id, an optional rules array, and an optional pipeline-level ecs object, which older configurations used for caching and which no longer affects it (changing it still starts that pipeline's cache afresh on reload). Rules are evaluated in configuration order. An empty matcher list matches. Within a rule, matchers form a left-to-right chain; each matcher can carry its own operator, or the rule-level matcher_operator can set the operator for a list whose item operators are all omitted.

The same structure is used for response_matchers, response_matcher_operator, response_actions_on_match, and response_actions_on_miss. Response actions run after a Forward response, or on the miss path after upstream attempts fail when miss actions are configured.

### Pipeline selector and request matchers

| Type | Fields |
|---|---|
| any | none |
| listener_label | value |
| client_ip | cidr |
| domain_suffix | value |
| domain_regex | value |
| qclass | value: IN, CH/CHAOS, or HS |
| edns_present | expect: boolean |
| geo_site | value: GeoSite tag |
| geo_site_not | value: GeoSite tag |
| geoip_country | country_codes: string array |
| geoip_private | expect: boolean |
| qtype | value: A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV, or OPT |

Pipeline selectors support all of the rows above. Request rules support all rows except listener_label.

#### GeoIP data sources and tags

- `geoip_db_path` loads a MaxMind MMDB database. It supplies two-letter country codes such as `CN` and `US`.
- `geoip_dat_path` loads either a V2Ray protobuf `.dat` file or a compatible JSON file. The JSON file is GeoIP data, not the main KixDNS configuration. Its shape is `{"entries":[{"country_code":"CLOUDFLARE","ips":["1.1.1.0/24"]}]}`.
- V2Ray data may contain country codes and named tags such as `CLOUDFLARE`, `NETFLIX`, or `TELEGRAM`. One IP may belong to several tags.
- When both sources are configured, MMDB decides two-letter country codes; named tags still come from `geoip_dat_path`.
- Only the country codes and tags rules use are read. The MMDB is read only when rules use a two-letter country code; `geoip_dat_path` is read only for the tags rules use that the MMDB does not decide, so with an MMDB configured and rules using two-letter country codes alone that file is not read. A tag rules use that the file lacks is logged as a warning, and rules using it never match.
- Tag matching is case-insensitive. `country_codes` should normally be a JSON string array, for example `["CN", "cloudflare"]`; a single or comma-separated string is also accepted for compatibility.

Domain suffix and GeoSite matching are also case-insensitive. `domain_suffix` and `request_domain_suffix` compare whole labels: `example.com` matches `example.com` itself and every subdomain such as `www.example.com`, while `.example.com` matches subdomains only; neither matches `notexample.com`. `domain_regex` and `request_domain_regex` use Rust regular-expression syntax.

#### GeoSite entries

- Entries are written as in V2Ray's domain lists (domain-list-community). `domain:example.com` and a bare `example.com` match the domain and every subdomain by whole labels (not `notexample.com`); unlike `domain_suffix`, a leading dot changes nothing here.
- `full:example.com` matches the domain only, `keyword:` and `regexp:` match a keyword or a regular expression, and a bare value with `*` is a wildcard.
- In `.dat` files a tag may carry an attribute key, `tag@attr` (`google@cn`), matched as a literal key as in V2Ray: `google@!cn` selects the domains marked `!cn`. The domains without an attribute are `geo_site: google` together with `geo_site_not: google@cn`.
- JSON entries with an unknown prefix, no value or an invalid regex are skipped with a warning.

### Response matchers

| Type | Fields |
|---|---|
| upstream_equals | value; compares the runtime upstream label literally |
| request_domain_suffix | value |
| request_domain_regex | value |
| response_upstream_ip | cidr; comma-separated CIDRs are accepted |
| response_answer_ip | cidr; comma-separated CIDRs are accepted |
| response_type | value; the first answer record type, or the query type if there is no answer |
| response_rcode | value: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED; an unknown value acts as the OTHER fallback |
| response_qclass | value |
| response_edns_present | expect: boolean |
| response_answer_ip_geoip_country | country_codes: string array |
| response_answer_ip_geoip_private | expect: boolean |
| response_request_domain_geo_site | value: GeoSite tag |
| response_request_domain_geo_site_not | value: GeoSite tag |
| response_txt_content | mode: exact, prefix, or regex; value is the text/pattern |

Response address matching uses these scopes:

- `response_answer_ip_geoip_country` checks Answers only. Every Answer that contains an address must match one of the requested GeoIP tags, and at least one Answer must contain an address.
- `response_answer_ip` and `response_answer_ip_geoip_private` check both Answers and Additionals and succeed when any address matches.
- A/AAAA addresses and HTTPS/SVCB `ipv4hint`/`ipv6hint` values are inspected. Hints in one HTTPS/SVCB record are alternative endpoints, so any matching hint satisfies that record.

These matchers only inspect existing records; they do not create or rewrite HTTPS/SVCB records.

The successful upstream label currently includes the transport prefix, for example udp:1.1.1.1:53 or tcp:1.1.1.1:53. Therefore upstream_equals values must include that prefix. response_upstream_ip currently parses a raw IP or host:port value; it does not strip the transport prefix.

### Logical operators

Operators are evaluated left to right. The first matcher seeds the result.

| Operator | Meaning |
|---|---|
| and | The next matcher must be true. This is the default. |
| or | The next matcher is used when the accumulated result is false. |
| and_not | The next matcher must be false when the accumulated result is true. |
| or_not | The next matcher must be false when the accumulated result is false. |
| not | Accepted as a deserialization alias for and_not. |

The aliases and-not, andnot, or-not, and ornot are also accepted.

### Actions

| Type | Fields | Behavior |
|---|---|---|
| log | level (optional) | Emits a tracing event for the matched rule. Supported levels are trace, debug, info, warn, and error. |
| static_response | rcode | Returns NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, or REFUSED. |
| static_ip_response | ip | Returns A or AAAA records matching the query type (both for ANY queries). Other query types, including HTTPS and SVCB, receive NODATA; this action does not synthesize IP hints. `ip` accepts one address or a comma-separated list of IPv4/IPv6 addresses (for example, `192.0.2.1,2001:db8::1`). Addresses are returned as-is; a very large list may exceed the UDP response size limit. |
| static_cname_response | target, ttl (optional) | Returns a CNAME record for every query type that maps the queried name to `target`; ttl defaults to 300. The target is not resolved server-side and its address records are not included, so the client or resolver must follow the alias. Clients that do not follow a bare CNAME may report no data. Invalid owner or target names return SERVFAIL. |
| static_txt_response | text, ttl (optional) | Returns a TXT response. text accepts a string or string array; ttl defaults to 300. |
| jump_to_pipeline | pipeline | Starts processing the referenced pipeline. |
| allow | none | Request phase: forward with the global default UDP upstream. Response phase: keep the current upstream response. |
| deny | none | Returns REFUSED. |
| forward | upstream (optional), transport (optional), ecs (optional) | Forwards to the selected upstream. A missing upstream uses default_upstream. |
| continue | none | Continues with the next request rule, or the next pipeline decision in the response flow. |
| replace_txt_response | text | Response-phase action that replaces TXT records in the current response. In the request phase it does not produce a response. |

### ECS

ECS is configured on a Forward action:

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

The supported modes are:

- clear: remove the request ECS option;
- from_client_ip: when the client sent ECS itself, forward its own subnet, cut to the prefix set here when it is longer, and a prefix of 0 as it is, adding no address (RFC 7871 section 7.1); a private or IPv4-mapped (`::ffff:a.b.c.d`) network the client sent counts as none and does not go upstream (section 11.3); an option nobody can read is removed, and no subnet of the client address is added either. Otherwise derive the subnet from the client address, defaulting to /24 for IPv4 and /56 for IPv6, injecting nothing for private, loopback, and ULA addresses;
- static: inject a configured IP and prefix.

A forward without ecs passes the client's own ECS option upstream as it is.

Cached answers follow RFC 7871 section 7.3. Each answer is kept for the requesters it applies to, judged by the ECS the forward actually sent and the SCOPE PREFIX-LENGTH in the upstream's reply:

- scope 0, or a reply without an ECS option to a query that carried one (which counts as scope 0), serves every request whose forward sends an ECS subnet; a request that sends none asks the upstream a different query and keeps an answer of its own;
- a scope no longer than the prefix sent serves requests whose subnet lies in that network; a longer scope serves only the same subnet at the same prefix;
- a query sent without ECS serves only requests that send none either, and one sent with prefix 0 only those sending prefix 0;
- an error reply without ECS (anything but NOERROR and NXDOMAIN), a reply echoing another subnet, and a failed forward hold only for the same subnet;
- an answer to an ECS option that does not follow RFC 7871 section 6 to the letter is not cached.

A lookup takes the longest prefix among the answers that apply. One question keeps answers for at most 64 networks; when that is full, answers for single subnets go before the ones every requester of a kind shares. In-flight deduplication joins only requests that send the same subnet. A client that sent no ECS gets replies without an ECS option, cached or not; a client that sent ECS gets its own subnet echoed back, with a scope at least as long as the one KixDNS keeps the answer for. The pipeline-level ecs object is still accepted but no longer affects caching.

## Network Protocols

### Inbound

UDP and TCP listeners are always created from settings.bind_udp and settings.bind_tcp.

Inbound listener behavior:

- Only standard single-question QUERY messages are processed. Malformed packets, non-QUERY opcodes, and DNS response packets are silently dropped.
- A listener processing error, an overall request timeout, or an exhausted flow-control permit returns SERVFAIL to the client for a valid query.
- UDP responses larger than the client's advertised size (the EDNS payload size, or 512 bytes without EDNS) are truncated at record boundaries with the TC bit set, so the client can retry over TCP.
- A dual-stack socket (inbound DoH listening on `[::]`, say) reports an IPv4 client as `::ffff:a.b.c.d`. Rules, GeoIP, ECS and the cache all judge it by the IPv4 address it carries, so client_ip takes IPv4 networks as usual; a network written as `::ffff:a.b.c.d/n` counts as the IPv4 network it names.

Inbound DoH is disabled unless settings.bind_doh is set. When it is set, settings.doh_tls_cert and settings.doh_tls_key are required and must point to PEM files. The path defaults to /dns-query and can be changed with settings.doh_path.

The inbound DoH handler:

- accepts POST requests at the configured path and reads a DNS wire message body;
- accepts GET requests at the configured path with a dns base64url-without-padding query parameter;
- rejects DNS bodies larger than 64 KiB;
- returns application/dns-message for a successful DNS response.

DoT and DoQ are implemented as outbound transports. There are no inbound DoT or DoQ listeners.

### Outbound

The Forward action has an optional transport field:

| Value | Transport |
|---|---|
| udp | DNS over UDP |
| tcp | DNS over TCP |
| tcp_udp | Sends TCP and UDP concurrently and uses the first accepted response |
| doh | DNS over HTTPS |
| dot | DNS over TLS |
| doq | DNS over QUIC |

The upstream field accepts a string, a comma-separated string, or a JSON string array. Multiple upstreams are queried concurrently and the first accepted response is returned. A response with SERVFAIL or REFUSED is not accepted when choosing among multiple upstreams.

The following prefixes override the transport field:

| Prefix | Transport | Alias |
|---|---|---|
| udp:// | UDP | |
| tcp:// | TCP | |
| tcp+udp://, udp+tcp:// | TCP+UDP | |
| doh:// | DoH | https:// |
| dot:// | DoT | tls:// |
| doq:// | DoQ | quic:// |

Without a prefix, an omitted transport means UDP. DoH URLs without a path use /dns-query. DoH supports a host query parameter as an HTTP Host override; that parameter is removed before the request is sent. A DoH answer is taken only with a success status, the application/dns-message media type and at most 65535 bytes; a redirect (3xx) is not followed and fails the upstream like any other error status.

DoT uses port 853 when no port is supplied. Its optional TLS name is supplied with sni or servername and it must not contain a DNS path.

DoQ uses port 853 when no port is supplied. Its optional query parameters are sni/servername and 0rtt/enable_0rtt. A DoQ upstream written with an IP literal requires an explicit SNI. 0-RTT is enabled globally by default, can be overridden per upstream, and is disabled for every connection to that upstream until the process restarts once a connection that used 0-RTT times out or is rejected, counting both an explicit rejection and the peer closing or resetting the connection, which is how a server refusing early data often answers. A timeout on a connection that did not use 0-RTT only means a slow answer and leaves 0-RTT alone.

When UDP forwarding fails, or when an upstream UDP response is truncated, TCP fallback is enabled by default and can be disabled with settings.enable_tcp_fallback. The fallback is applied by the forwarding path; it is not an additional listener.

## Configuration examples

### Basic routing and static response

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

### Response-based fallback

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

### Inbound DoH

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

## Cache and reload behavior

The DNS response cache uses the upstream response's minimum TTL, raised to min_ttl when configured, and is capped by cache_max_ttl and cache_capacity. Negative responses use the SOA negative-cache TTL when an SOA is present. Identical in-flight cache misses share one upstream operation.

When a pipeline's answer can depend on who is asking, the response cache, the in-flight deduplication, and the rule cache keep requesters apart by how its rules judge them, not by address: whether the client address is in each client_ip network, whether it is private (geoip_private), whether its GeoIP country or tag matches (geoip_country), and whether the query carries EDNS (edns_present, response_edns_present). The subnet a forward derives from the client keeps in-flight requests apart, while cached answers are told apart by their ECS scope (see ECS). Requesters judged alike share entries. The rules along the response-jump paths that a pipeline's answer checks start count too, because a request runs them before it answers. Such a path forwards the packet that the forward before the jump prepared, ECS included, so its in-flight entries are kept apart from those of requests that enter the pipeline directly; answers reached on it are not cached, as no lookup uses its keys. The rule cache holds the decisions of a pipeline's own rules and so judges by that pipeline's request matchers only; with cache_background_refresh on it also keys by client address, as before. A pipeline whose rules judge no requester facts shares entries between all clients as before. A background refresh replays the request from the same client address, with EDNS and the client's own ECS option when the request carried them (an ECS option that does not follow RFC 7871 section 6 is left out), so pipeline selection, request rules and the ECS sent upstream are the same as for that request. When the refreshed answer applies to other requesters than the entry it renews (the upstream narrowed its scope, say), that entry is removed and its requesters ask again.

When cache_background_refresh is enabled, entries near expiry can trigger an asynchronous refresh. A refresh runs the rules as a client query does, response rules and their actions included. When the upstream answers, an answer the rules accept replaces the entry, and when the rules end in an answer that is not cached under it (a static answer that is not cached, or an answer reached through a jump), the entry is removed so the next client query runs the rules itself. When the upstream fails (a jump target's upstream included, even when miss actions or later rules answer after the failure, unless the rules then pass over a fresh answer) or the rules find no answer, the entry stays unless what the rules produce is cached under it. A refresh that ends in SERVFAIL (the jump limit, a jump target that does not exist, a static SERVFAIL and so on) counts as failed too: it is logged as a failed refresh, and the SERVFAIL is not cached. So does a refresh that gets only a truncated answer. When serve_stale is enabled, an expired entry can be returned with serve_stale_ttl, subject to serve_stale_expire_ttl and serve_stale_client_timeout_ms. That client wait is additionally bounded by the remaining request_timeout_ms budget, so a wait configured longer than the request budget cannot push the stale answer past the deadline.

The main configuration watcher reloads a valid JSON file using per-pipeline cache namespaces. A changed pipeline immediately stops addressing response-cache, rule-cache, and in-flight entries created by its previous configuration; an unchanged pipeline keeps its warm caches. A change to global settings rotates every pipeline namespace. Old namespace entries are not synchronously deleted and remain bounded by the existing cache capacity and TTL policies. Each request, including background refresh and response-phase jumps, keeps the configuration snapshot that selected its namespace, so work started before a reload cannot write into the active generation. Invalid reloads leave the previous configuration active.

These global settings are read at startup only; a reload does not apply them, and a change takes a restart: `bind_udp`, `bind_tcp`, `bind_doh`, `doh_path`, `doh_tls_cert`, `doh_tls_key`, `cache_capacity`, `cache_max_ttl`, `dashmap_shards`, `udp_pool_size`, `tcp_pool_size`, `doh_pool_size`, `doh_health_check_error_threshold`, `dot_pool_size`, `doq_pool_size`, `tcp_health_check_error_threshold`, `tcp_connection_max_age_seconds`, `tcp_connection_idle_timeout_seconds`, `doq_connection_idle_timeout_seconds`, `doq_keepalive_interval_ms`, `doq_enable_0rtt` and every `flow_control_*`. Every other global setting applies on a reload. After a reload, the settings the configuration changes that are still waiting for a restart are listed in `restart_pending` in the control channel's `config` result; once changed back to their startup values, or after a restart, they are no longer listed. The UDP worker count comes from the command line and likewise applies at startup only. Renewed DoH TLS cert/key PEM files are hot-reloaded, though changing the configured file paths still requires a restart.

After a reload, upstreams the configuration no longer names have their TCP, DoT and DoQ connections closed, once the requests using them have finished.

GeoSite files in geosite_data_paths and the GeoIP file in geoip_dat_path are watched and read again when they change; the MMDB in geoip_db_path is not watched. A GeoSite `.dat` is read only for the tags rules use, and with none used it is neither read nor watched; GeoIP data is read only for the country codes and tags rules (geoip_country, response_answer_ip_geoip_country) use (see GeoIP data sources and tags above), and a file not read is not watched. When a hot reload changes the GeoSite or GeoIP tags rules use, or any of these file paths, the Geo data is read again for the new configuration and the watches move to the new files; the old data is replaced only once the new data has been read, so the new rules use the new data from their first query. A configured file that does not exist yet is read by the first hot reload after it appears.
