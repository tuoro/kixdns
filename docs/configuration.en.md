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
| min_ttl | 0 | Minimum TTL of upstream answers in seconds: every record of an answer has its TTL raised to at least this, and the cache keeps the answer at least this long. |
| bind_udp | 0.0.0.0:5533 | UDP listen address; with the port taken by another program, starting fails rather than sharing it. The default port used to be 5353, the mDNS port, often held by the system's mDNSResponder or avahi; to keep 5353, write the address out. With a wildcard address (`0.0.0.0`, `::`), on Linux, macOS, and FreeBSD and the other BSDs (OPNsense and pfSense among them) a reply leaves from the local address the query was sent to (RFC 2181 section 4.1), so a machine with several addresses (aliases, a CARP VIP that comes and goes) never answers from the wrong one; this adds about 0.1 microseconds of receive and send work to each query (measured on Linux), which writing the one address to serve avoids. On Windows the system picks the reply's source address. |
| bind_tcp | 0.0.0.0:5533 | TCP listen address. |
| bind_doh | null | Inbound DoH listen address; null disables it. |
| doh_tls_cert | null | PEM certificate path; required with bind_doh. |
| doh_tls_key | null | PEM private-key path; required with bind_doh. |
| doh_path | /dns-query | Inbound DoH request path, starting with `/`; one that does not matches no request and counts as a configuration problem (see below). |
| default_upstream | 1.1.1.1:53 | Default upstream. A comma-separated list is accepted. |
| bootstrap | empty | The plain DNS servers that resolve upstreams written with a host name (TCP, DoT, DoH, DoQ), comma-separated `IP:port`, asked over UDP; A and AAAA are asked at once, each of every server at once and the first to answer taken, and both are waited for until answered, one answered late used all the same, each for 2 seconds at most. One not given (unanswered by then, or answered with a failure reply alone such as SERVFAIL or REFUSED; an answer with no such record counts as given) never costs the other: it keeps the addresses last given for it (none when asked the first time) and is asked again 10 seconds later. Addresses once given are used at once: past their TTL too, while they are asked again in the background, the last ones staying in use for as long as none can be asked; only a name never given any waits, 2 seconds at most. Unset, the system resolver has them: should that be KixDNS itself, resolving an upstream's name comes back round to KixDNS and the upstream cannot be reached, so then a TCP, DoT, DoH or DoQ upstream written with a host name counts as a warning (see the writing worth knowing below). An upstream written as an IP needs no resolving. |
| upstream_timeout_ms | 9000 | Timeout for one upstream operation; must be greater than zero. A UDP forward with no reply after what the slowest one percent of this upstream's latest answers took sends the query again (waiting 50 ms at least and a third of the timeout at most, a third while this upstream has not answered yet), and for the whole of the timeout from then on whichever of the two is answered first is used. |
| request_timeout_ms | null | Overall request timeout. When null, it is upstream_timeout_ms * 2.5. It must be at least upstream_timeout_ms. |
| response_jump_limit | 10 | How many pipeline jumps a query may make, jumps in the request phase and the response phase both counting: the request phase's rules may jump this many times; from an answer action's first jump on, the jumps of answer actions and the rule-level jumps after them count anew, up to this many as well; one more answers SERVFAIL. At most 64. |
| udp_pool_size | 64 | Outbound UDP socket-pool size. Each query takes a socket and an ID at random; a socket that has sent 64 queries is replaced by a new one on another port the system picks, so no port lasts long, and the firewall's connection tracking gains just one entry per 64 misses. At most 1024. |
| tcp_pool_size | 64 | At most this many TCP connections per upstream. Normally only the first is used; further queries go to the later ones only while 32 or more are unanswered on it at once. At most 1024. |
| doh_pool_size | 8 | Maximum idle DoH connections per upstream when the upstream does not support HTTP/2 or `HTTPS_PROXY` / `ALL_PROXY` is set. An upstream supporting HTTP/2 is connected to directly, with at most one connection per worker thread and normally one in use, busy by the same rule as `tcp_pool_size`. At most 1024. |
| doh_health_check_error_threshold | 3 | After this many transport errors in a row on connections made (a timeout, a failure to read or to write; failing to connect does not count), a DoH upstream has all its connections dropped and made anew: the direct connections are closed and the pool used through a proxy or over HTTP/1.1 is rebuilt; requests broken together have it reconnect once. 0 turns the check off. |
| dot_pool_size | 64 | At most this many DoT connections per upstream, normally one in use, by the same rule as `tcp_pool_size`. At most 1024. |
| doq_pool_size | 16 | At most this many DoQ connections per upstream, normally one in use, by the same rule as `tcp_pool_size`. A connection is replaced only once it is gone, or a query timed out with no other answer on it meanwhile; a malformed answer or a reset stream fails just that query. At most 1024. |
| tcp_connection_max_age_seconds | 300 | Maximum TCP/DoT connection age; 0 disables aging. |
| tcp_connection_idle_timeout_seconds | 60 | How long a TCP/DoT connection may sit idle before it is closed: this long without a new query once the queries on it are past their deadlines, a connection far down the pool and normally left alone included (RFC 7766 section 6.2.3). A DoT connection sends close_notify as it closes. 0 disables it. |
| doq_connection_idle_timeout_seconds | 60 | DoQ idle timeout; 0 disables it. |
| doq_keepalive_interval_ms | 15000 | DoQ keepalive interval; 0 disables keepalive. |
| doq_enable_0rtt | true | Global DoQ 0-RTT setting. |
| enable_tcp_fallback | true | Retry UDP failure or truncation with TCP. |
| flow_control_enabled | false | Enable flow control, with no numbers to fill in as the kernel judges at run time. One device can take up four things, the handling capacity, the queries waiting on upstreams, an upstream and memory, each dealt with in its own way, and devices sending little go on throughout. **Handling capacity.** A receiving socket that has not run empty for 100 ms means the kernel is busy; busy with queries queueing over 20 ms inside the kernel, a device holding no fewer queries in flight than the average across devices gets SERVFAIL for new cache misses at once. When drops or refusals last over a second, UDP takes devices in turn: each has its own queue (shared with no other device, and at least 4 fit in each; for 10 seconds after the queued devices were full and a new one turned away, one fits in each, given up at its turn), what does not fit is dropped without a reply and devices sending little are unaffected, however rarely they ask. At most 4096 devices are queued at once and a new one past that is dropped: with a flood from enough sources to keep them all taken, devices sending little mostly do not get in. Drops or refusals again within a minute of catching up continue the same spell and take turns at once, so a flood in waves is held too. A query in turn is handed to the kernel, with at most 64 queries having work waiting for it (those handed over and not started on yet, and those whose upstream answer has arrived and has not been got to), any further staying in each device's own queue for the next turn: however many devices there are, however fast they send together and however many cores there are, nothing piles up inside the kernel, and the excess is dropped as above, from whoever sends most. While taking turns, the queries waiting on upstreams go by memory alone. This ends on catching up, that is once there would be no drops without it: a device sending more than its share at once does not keep it going, as long as each batch fits in the receive buffer and the average stays below capacity. **Stuck queries.** The kernel keeps, for each upstream, how long each of its latest few thousand exchanges took (from sending to an answer of use coming back; a SERVFAIL or REFUSED is not kept, what is kept is the exchange whose reply came: for an answer won by sending again only that resend, and for a first query's reply arriving after the resend the time since that first query went out; one read later than the upstream timeout is not kept). A cache miss waiting on an upstream and still without a result after twice what the slowest hundredth of that upstream's took (at least 100 ms), counted from when the forward began, counts as stuck; where a rule writes several upstreams, it goes by the slowest of them. Each upstream goes by its own: one at ten milliseconds and one at over two hundred do not affect each other. An upstream with no answer yet goes by all upstreams together for now; right after a start, with no answer from any upstream yet, it goes by a third of the upstream timeout (when a UDP forward sends again). A thousand stuck queries are kept waiting, shared among devices, each device keeping at least 4 (up to 4096 devices keeping any); one stuck after that does not wait out the upstream timeout and is treated as the upstream failing: what the rule says to do on an upstream failure is done (asking a fallback upstream, say), the answer got that way being for this query alone and not cached, and with nothing written it gets SERVFAIL (a stale answer as usual with `serve_stale` on), inbound over UDP, TCP and DoH alike. A query waiting on the same forward another query is making counts as stuck the same way (by the upstream of its own rule), only nothing of it goes into the outcomes of "an upstream that does not answer" below, and a device held back may wait like any other: it asked no upstream itself. Those kept are the ones each device had stuck first: with an upstream that is only slower, they get their answers, that time grows at once and the queries after no longer count as stuck; once answers come faster it takes over thirty thousand more answers to come back down. A new query is not refused over what is in flight: a slow upstream, load in waves and a fresh start refuse nothing. **An upstream that does not answer.** The latest outcomes are kept per device and upstream (the upstreams as a rule writes them). With 64 of a device's waits on an upstream unanswered, and more of them than answered (answered ones being kept count of once in 16), the upstream is not asked for it for now: its cache misses are treated as the upstream failing (as above, what the rule says to do on an upstream failure is done, the answer got that way being for this device alone and not cached: a static answer the rule gives outright and the answer of a fallback upstream alike, the cache being shared by all devices while the upstream does answer the others; with nothing written it gets SERVFAIL or a stale answer), one goes to try every second, and an answer of use to it lets them all through again. Other devices and this device's queries to other upstreams are left alone; another device asking the same name at that moment gets nothing of this failure and asks for itself. What counts as unanswered is the upstream sending nothing: past the time a query counts as stuck after above, or for the whole of the upstream timeout, a stuck query waiting no more included; not while the kernel itself is queueing, unless the device never got an answer from that upstream. A SERVFAIL or REFUSED from the upstream does not count, quick or slow: the upstream did reply, and a program asking one broken name over and over does not drag down the other names its device asks. An upstream being down, a flood of names with no answer, and an upstream no longer answering one device (dropping its queries when rate-limiting) are all held by this, with no sending on and on to an upstream that does not answer; an upstream rate-limiting with REFUSED is not held by it, the queries then having their result on the spot and holding no memory. In a flood of names the upstream takes long to fail, those past the share of stuck queries wait no more and count as unanswered, which holds it just the same. The price: a device most of whose names on one upstream get no answer has the answerable rest on that upstream held back too. A flood every name of which is answered, only slowly (each after two seconds, say), is neither stuck nor unanswered, and what is in flight is held only by memory, as below. **Memory.** Past 1000 queries handled at once memory is looked at: what is available to the system or a limit it runs under (a cgroup at any level on Linux, its job object on Windows), against a floor of a quarter of what the kernel itself holds plus a sixteenth of the total (the latter at most 256 MiB). Below twice the floor, the queries in flight are held to as many as when memory got tight (noted afresh once fewer than 1000 are in flight), fewer in proportion the nearer the floor and none at it, split among devices: a device holding no fewer queries in flight than its share gets SERVFAIL for new cache misses, and one holding no fewer open connections than the average, or its share of queries, has new TCP and DoH connections closed, while devices sending little go on. Shrinking in proportion, the device holding the memory gives it back bit by bit and memory settles between the two lines rather than sinking to the floor. Queries and connections are compared apart: one idle connection is no share of queries, and a device holding many connections does not make the shares of queries smaller. A device holding no query in flight goes on asking if it was in use 10 seconds before memory ran short, and a source turning up later is refused: in a flood with forged source addresses each source is new and holding one each still fills the memory, so this holds it while the devices in use all along go on. At most 512 such devices are kept, those in use the longest staying: forged sources each turn up once and only push each other out, and with the same sources flooding once and again a while later, what more gets in flight with no memory left is still at most 512 (about 5 MB). A device unseen for an hour counts as new when it comes back, and after a minute of enough memory the next shortage starts a new spell. Below the floor, devices holding queries in flight are refused and new TCP and DoH connections are closed. This ends when memory comes back, inbound over UDP, TCP and DoH alike. **What counts as one device.** An IPv4 address or a global IPv6 /64 counts as one device, what is counted per device (queries in flight, stuck ones, the outcomes of asking an upstream) kept in a slot by each of two hashes and mixed up with another device only when both are shared, which with two thousand sources is under one device in a thousand; and the IPv6 addresses of a LAN by the whole address: link-local, ULA, site-local, and global ones in a /64 the kernel itself is on (it looks at this machine's addresses every 30 seconds, the hosts of a home LAN sharing the /64 their provider handed out); an address in 64:ff9b::/96 goes by its IPv4 address; with a reverse proxy in front of DoH the kernel sees only the proxy's address, so every DoH user counts as one device. Memory is read on Linux, FreeBSD and Windows (on FreeBSD, what ZFS's ARC holds above its minimum counts as available); taking devices in turn works on every platform: Linux tells falling behind by the receiving socket's drops, and systems that cannot read them (FreeBSD, Windows) by the receiving socket going 100 ms without running empty. With it off, once 4096 queries waiting on upstreams are in flight in all, a device holding its share of them gets SERVFAIL for further ones, devices with few in flight going on as usual. |
| cache_capacity | 10000 | Maximum answers in the DNS response cache, one over 1 KB counting once per KB; must be greater than zero. |
| cache_max_ttl | 86400 | Maximum lifetime of a DNS cache entry in seconds; must be greater than zero. An entry leaves the cache once its own TTL (at most this) is over, or serve_stale_expire_ttl later with serve_stale on, a deny the rules gave by an upstream answer alike (an upstream's failure reply stays out of the cache, see "Cache and reload behavior"). No record of an upstream answer carries a longer TTL either, and it wins over min_ttl when the two cross. |
| dashmap_shards | 0 | Internal shard setting; 0 uses the DashMap default, otherwise the value must be a power of two from 2 to 65536. |
| cache_background_refresh | false | Refresh entries before their TTL expires. At most 128 are refreshed at once; with that many running, a hit waits for a later one to refresh. A refresh renews an entry only with a fresh answer from the route the entry came by: when the upstream fails the refresh ends there, the miss actions do not run, and the entry stays as it is, tried again a while later; once the entry really expires, client requests go through the rules as usual. |
| cache_refresh_threshold_percent | 10 | Refresh once the entry's TTL (the shortest in the answer, which is when it expires) is down to this percentage, at least a second before it expires; must be below 100, since at 100 every cache hit refreshes upstream. |
| cache_refresh_min_ttl | 5 | Entries whose TTL is below this many seconds are not refreshed in the background. |
| serve_stale | false | Keep and serve expired entries according to RFC 8767 behavior. Once the refresh of an expired answer fails, it is not refreshed again for 30 seconds, and requests hitting it get the stale data at once without waiting (the failure recheck of RFC 8767 section 5); the first hit after the 30 seconds tries again. |
| serve_stale_ttl | 30 | TTL written into a stale response. |
| serve_stale_expire_ttl | 86400 | Maximum stale age in seconds; 0 means no stale-age limit. |
| serve_stale_ttl_reset | false | Once the background refresh of a stale answer fails, how long it may still be served counts afresh from that failure: a name the upstream keeps giving nothing new for, and that keeps being asked, then goes out stale beyond serve_stale_expire_ttl (Unbound's serve-expired-ttl-reset, off there by default too). It used to be on by default and counted afresh on every stale answer served. |
| serve_stale_client_timeout_ms | 0 | 0 serves stale immediately; a positive value tries the upstream for up to this many milliseconds first, bounded by what is left of request_timeout_ms so the stale answer still goes out in time. When that refresh fails, the stale answer goes out at once instead of after the full wait. A stale answer the rules gave by an upstream answer waits the same way, its refresh running the rules again. |
| geoip_db_path | null | MaxMind MMDB path. |
| geoip_dat_path | null | V2Ray GeoIP data path: either a protobuf `.dat` file or the compatible JSON format described below. |
| geosite_data_paths | [] | V2Ray GeoSite .dat or JSON paths; multiple files are accepted. When several files declare one tag, the later file's is used. Either format is read only for the tags rules use, and with none used the files are neither read nor watched. |

geoip_auto_convert and geoip_filter_countries are retired: the engine never read them, and a configuration writing them loads as usual, with a warning at startup and on every reload; use convert-geo-ip with --filter for conversion-time filtering. The top-level background_refresh_rule is still read but has no effect: a background refresh replays the original request through its own rules. A configuration that has it loads as usual, with a warning at startup and on every reload; the entry can be removed.

### Pipeline selection

Each item in pipeline_select has a pipeline id, an optional matcher list, and an optional matcher_operator. Items are evaluated in array order. The first matching item whose pipeline id exists selects that pipeline.

### Pipelines and rules

Each pipeline has an id, an optional rules array, and an optional pipeline-level ecs object, which older configurations used for caching and which no longer affects it (changing it still starts that pipeline's cache afresh on reload). Rules are evaluated in configuration order; a rule's name is used only in logs and statistics and may repeat. An empty matcher list matches. Within a rule, matchers form a left-to-right chain; each matcher can carry its own operator, or the rule-level matcher_operator can set the operator for a list whose item operators are all omitted.

The same structure is used for response_matchers, response_matcher_operator, response_actions_on_match, and response_actions_on_miss. Response actions run after a Forward response, or on the miss path after upstream attempts fail when miss actions are configured. When several upstreams asked together all fail and at least one replied with a failure (SERVFAIL, REFUSED or an extended RCODE), the first such reply still goes to the answer check: when the check passes and response_actions_on_match has actions, the match actions run with that reply, as they do with a single upstream. When the check fails, or passes with no match actions, it is handled as an upstream failure as before: the miss actions run without a response when configured, otherwise a stale entry or SERVFAIL answers. An answer check that a SERVFAIL reply satisfies (such as switching to another group when the upstream answers SERVFAIL or REFUSED, or a negated IP condition) therefore applies however many upstreams are written. A background refresh does not do this: when every upstream replies with a failure, the refresh still counts as failed and the entry stays.

### Pipeline selector and request matchers

| Type | Fields |
|---|---|
| any | none |
| listener_label | value |
| client_ip | cidr |
| domain_suffix | value |
| domain_exact | value |
| domain_regex | value |
| qclass | value: IN, CH/CHAOS, or HS |
| edns_present | expect: boolean |
| geo_site | value: GeoSite tag |
| geo_site_not | value: GeoSite tag |
| geoip_country | country_codes: string array |
| geoip_private | expect: boolean |
| qtype | value: a record type name (A, AAAA, CNAME, HTTPS, SVCB, CAA, ANY and so on, in any case), or the RFC 3597 form such as `TYPE65` |

Pipeline selectors support all of the rows above. Request rules support all rows except listener_label.

#### GeoIP data sources and tags

- `geoip_db_path` loads a MaxMind MMDB database. It supplies two-letter country codes such as `CN` and `US`.
- `geoip_dat_path` loads either a V2Ray protobuf `.dat` file or a compatible JSON file. The JSON file is GeoIP data, not the main KixDNS configuration. Its shape is `{"entries":[{"country_code":"CLOUDFLARE","ips":["1.1.1.0/24"]}]}`. An address without a prefix length is that one address: `1.1.1.1` is `1.1.1.1/32` (/128 for IPv6).
- V2Ray data may contain country codes and named tags such as `CLOUDFLARE`, `NETFLIX`, or `TELEGRAM`. One IP may belong to several tags.
- When both sources are configured, MMDB decides two-letter country codes; named tags still come from `geoip_dat_path`.
- Only the country codes and tags rules use are read. The MMDB is read only when rules use a two-letter country code; `geoip_dat_path` is read only for the tags rules use that the MMDB does not decide, so with an MMDB configured and rules using two-letter country codes alone that file is not read. A tag rules use that the file lacks is logged as a warning, and rules using it never match.
- Tag matching is case-insensitive. `country_codes` should normally be a JSON string array, for example `["CN", "cloudflare"]`; a single or comma-separated string is also accepted for compatibility.

Domain suffix and GeoSite matching are also case-insensitive. `domain_suffix` and `request_domain_suffix` compare whole labels: `example.com` matches `example.com` itself and every subdomain such as `www.example.com`, while `.example.com` matches subdomains only; neither matches `notexample.com`. `domain_exact` and `request_domain_exact` match the name itself only: `api.example.com` does not match `www.api.example.com`. A trailing dot on any of these values changes nothing: `example.com.` is `example.com`; a lone dot is the root: domain_exact and request_domain_exact written `.` match the root name alone (to block ANY or NS amplification at the root, say), while domain_suffix and request_domain_suffix written `.` match every name as written empty do, a configuration problem (see below). `domain_regex` and `request_domain_regex` use Rust regular-expression syntax, at most 16384 bytes and 1 MB compiled each; a configuration with a longer or larger one is refused. Rules see the query name in lower case, without the trailing dot. A label byte that is not printable ASCII, and a dot or backslash inside a label, is written as `\DDD` (three decimal digits): the label `a.b` is `a\046b`, so it is never taken as two labels and does not match a suffix such as `b.example`. Write `domain_regex` patterns for such names in this form. So the names rules see are ASCII alone, and in `domain_regex` and `request_domain_regex` every class keeps just its ASCII part, with `\b` and the other word boundaries going by the ASCII `\w`, as in a GeoSite `regexp:`: `\w` is `[0-9A-Za-z_]`, `\d` is `[0-9]`, `\pL` is `[A-Za-z]`, and `.` and negated classes such as `[^.]` take ASCII characters alone too. Names match as they would under Unicode, at a fraction of the compiled size. A `response_txt_content` regex keeps the Unicode meaning.

#### GeoSite entries

- Entries are written as in V2Ray's domain lists (domain-list-community). `domain:example.com` and a bare `example.com` match the domain and every subdomain by whole labels (not `notexample.com`); unlike `domain_suffix`, a leading dot changes nothing here.
- `full:example.com` matches the domain only, `keyword:` and `regexp:` match a keyword or a regular expression, and a bare value with `*` is a wildcard.
- In `.dat` files a tag may carry an attribute key, `tag@attr` (`google@cn`), matched as a literal key as in V2Ray: `google@!cn` selects the domains marked `!cn`. Several attributes may be written, as in `google@cn@ads`, selecting the domains that carry every one of them. The domains without an attribute are `geo_site: google` together with `geo_site_not: google@cn`.
- JSON entries with an unknown prefix, no value or an invalid regex are skipped with a warning.
- A `regexp:` regex is at most 16384 bytes and 1 MB compiled, as a `domain_regex` is; one beyond either is skipped with a warning, in `.dat` and JSON alike. A tag's regexes are matched together, each still held to that limit.

### Response matchers

| Type | Fields |
|---|---|
| upstream_equals | value; holds when the answer came from this upstream, written as described below |
| request_domain_suffix | value |
| request_domain_exact | value |
| request_domain_regex | value |
| response_upstream_ip | cidr; comma-separated CIDRs are accepted |
| response_answer_ip | cidr; comma-separated CIDRs are accepted |
| response_type | value; the first answer record type, or the query type if there is no answer |
| response_rcode | value: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, or OTHER (any other RCODE), in any case; anything else written is a configuration problem (see below) |
| response_qclass | value |
| response_edns_present | expect: boolean |
| response_answer_ip_geoip_country | country_codes: string array |
| response_answer_ip_geoip_private | expect: boolean |
| response_request_domain_geo_site | value: GeoSite tag |
| response_request_domain_geo_site_not | value: GeoSite tag |
| response_txt_content | mode: exact, prefix, or regex; value is the text/pattern, a regex at most 1000 bytes. Each TXT record in the answer is compared on its own, and one matching is enough; a record's strings are joined without spaces before comparing (as RFC 7208 reads an SPF record), and an answer without a TXT record does not match |

Response address matching uses these scopes:

- `response_answer_ip_geoip_country` checks Answers only. Every Answer that contains an address must match one of the requested GeoIP tags, and at least one Answer must contain an address.
- `response_answer_ip` and `response_answer_ip_geoip_private` check both Answers and Additionals and succeed when any address matches.
- A/AAAA addresses and HTTPS/SVCB `ipv4hint`/`ipv6hint` values are inspected. Hints in one HTTPS/SVCB record are alternative endpoints, so any matching hint satisfies that record.
- An IPv4-mapped address (`::ffff:a.b.c.d` in an AAAA or an `ipv6hint`) is judged as the IPv4 address it names, and a network written as `::ffff:a.b.c.d/n` counts as the IPv4 network it names; response_upstream_ip reads them the same way.
- geoip_private and `response_answer_ip_geoip_private` count private networks (RFC 1918, ULA fc00::/7, the deprecated site-local fec0::/10), 100.64.0.0/10 of carrier-grade NAT and Tailscale, 192.0.0.0/24, loopback, link-local, 0.0.0.0/8, `::`, the discard-only 100::/64 and 255.255.255.255 as local network addresses; a NAT64 address (64:ff9b::/96, 64:ff9b:1::/48) counts by the IPv4 address its last 32 bits embed. 198.18.0.0/15 for benchmarking does not count: it is the default fake-ip range of Clash, mihomo and the like, and counted as local, every answer to a query forwarded to a fake-ip upstream would be stopped by anti-rebinding rules (ECS still injects no subnet for it, see ecs below).

These matchers only inspect existing records; they do not create or rewrite HTTPS/SVCB records.

upstream_equals and response_upstream_ip are about the upstream that answered this time: when a rule asks several upstreams at once, the one that gave this answer. An upstream_equals value is written in one of two ways. As the upstream's address, the way a forward's upstream writes it (`1.1.1.1:53`, `tcp://1.1.1.1:53`; with several separated by commas, any one of them answering holds), in which case only the address is compared, whichever transport carried the answer back in the end. Or as the runtime upstream label `transport:address` (`udp:1.1.1.1:53`, `tcp:1.1.1.1:53`, the transport one of udp, tcp, doh, dot, doq), in which case the transport has to be the same too; a UDP query that went over TCP after a truncated or failed answer is labelled `tcp:`. response_upstream_ip takes the IP in the answering upstream's address; it does not hold when the upstream's host is written as a name.

### Logical operators

Operators are evaluated left to right. The first matcher seeds the result: an and_not or or_not (not) written on it has nothing before it to join and does not negate it, and with a single matcher a rule-level negation is written for nothing just the same. Both are raised as configuration problems (an error logged at startup, loaded as before; refused on reload and on a save from the panel). To match queries for which a condition does not hold, put an `{"type": "any"}` first and write and_not on the condition.

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
| log | level (optional) | Emits a tracing event for the matched rule, for every query it matches (such a decision stays out of the rule cache; a query answered from the response cache runs no rules and emits none). Supported levels are trace, debug, info, warn, and error; without one it is info. The log keeps errors alone by default (see the logs section of the usage guide), so anything below error shows only once --debug or RUST_LOG lets it through (`RUST_LOG=error,kixdns::engine=info`, say), or with level written as error. |
| static_response | rcode | Returns NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, or REFUSED. |
| static_ip_response | ip | Returns A or AAAA records matching the query type (both for ANY queries). Other query types, including HTTPS and SVCB, receive NODATA; this action does not synthesize IP hints. `ip` accepts one address or a comma-separated list of IPv4/IPv6 addresses (for example, `192.0.2.1,2001:db8::1`). Addresses are returned as-is; a very large list may exceed the UDP response size limit. |
| static_cname_response | target, ttl (optional) | Returns a CNAME record for every query type that maps the queried name to `target`; ttl defaults to 300. The target is not resolved server-side and its address records are not included, so the client or resolver must follow the alias. Clients that do not follow a bare CNAME may report no data. Invalid owner or target names return SERVFAIL. |
| static_txt_response | text, ttl (optional) | Returns a TXT record for TXT and ANY queries; other query types receive NODATA. text accepts a string or string array; ttl defaults to 300. Each string is at most 255 bytes; the whole answer has to fit one DNS message (65535 bytes, keeping room for EDNS and an ECS echo, each string taking one length byte more), otherwise it is SERVFAIL, and text that fits no question at all is a configuration problem. |
| jump_to_pipeline | pipeline | Starts processing the referenced pipeline. |
| allow | none | Request phase: forward with the global default UDP upstream. Response phase: keep the current upstream response. |
| deny | none | Returns REFUSED. |
| forward | upstream (optional), transport (optional), ecs (optional) | Forwards to the selected upstream. A missing upstream (or null, or []) uses default_upstream; an empty string is not missing. |
| continue | none | Continues with the next request rule, or the next pipeline decision in the response flow. |
| replace_txt_response | text | Response-phase action that replaces the answer in hand with what static_txt_response gives (TTL 300): only TXT and ANY queries get the TXT record, other query types receive NODATA, with NOERROR whatever the upstream answered; run after an upstream failure it has no answer to replace and gives SERVFAIL. In the request phase it does not produce a response. text has the same size limits as static_txt_response. |

The records static_ip_response, static_cname_response, static_txt_response and replace_txt_response give are all of class IN, so they answer only questions of class IN or ANY; a question of another class (CH, for example) receives NODATA.

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
- from_client_ip: when the client sent ECS itself, forward its own subnet, cut to the prefix set here when it is longer, and a prefix of 0 as it is, adding no address (RFC 7871 section 7.1); a private or IPv4-mapped (`::ffff:a.b.c.d`) network the client sent counts as none and does not go upstream (section 11.3); an option nobody can read is removed, and no subnet of the client address is added either. Otherwise derive the subnet from the client address, defaulting to /24 for IPv4 and /56 for IPv6, injecting nothing for a client address geoip_private counts as local or one in benchmarking's 198.18.0.0/15 or the local-use translation prefix 64:ff9b:1::/48, that is the RFC 1918 private networks, 100.64.0.0/10, 192.0.0.0/24, 198.18.0.0/15, loopback, link-local, 0.0.0.0/8 and 255.255.255.255, and in IPv6 loopback, `::`, ULA fc00::/7, link-local fe80::/10, site-local fec0::/10, 100::/64, 64:ff9b:1::/48, and the NAT64 addresses of 64:ff9b::/96 whose last 32 bits embed one of those local IPv4 addresses (198.18.0.0/15 aside), and counting such a network the client sent as a private one;
- static: inject a configured IP and prefix.

A forward without ecs passes the client's own ECS option upstream as it is. A forward among the response actions may write an ecs too: with one, the query as the client sent it is rewritten by it, and which clients the answer applies to goes by it; without one, it sends the same packet as the rule's own forward.

The forwards of one rule merge into one forward that asks every upstream at once (with another deciding action written before them, a static answer or a jump say, the rule gives that action's outcome and the forwards do not run), so it sends one ECS: the forwards' ecs when they all write the same; when they differ (some written and some not, too) the rule acts as if no ecs were written, and this is a configuration problem (see "Cache and reload behavior"). A forward whose upstream is written empty (or commas only) is not part of the merge: it is skipped, its ecs does not count, and as long as another forward names an address it is no configuration problem.

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

- Only standard single-question QUERY messages are processed. A request whose opcode is not QUERY (NOTIFY, UPDATE and the like) gets NOTIMP, and a query without exactly one question or carrying answer or authority records gets FORMERR (RFC 9619), the header alone either way, with an OPT added when the request carries one that can be read (RFC 6891 section 7); DNS response packets and packets under 12 bytes are silently dropped (over TCP the connection closes). A message with a standard query header that cannot be read (two OPT records, say, or a UDP query over 4096 bytes) gets FORMERR, with the header and question alone (and an OPT when the query carries one that can be read), no longer than the query.
- A query whose EDNS version is not 0 is answered BADVERS (RFC 6891 section 6.1.3), with an OPT of version 0 in the reply.
- A query whose ECS option has an improper address (an unknown family, a prefix over the address length, an address whose byte count does not match the prefix, bits set beyond the prefix), or that carries more than one, is answered FORMERR (RFC 7871 sections 6 and 7.2.1), no upstream asked; one with a nonzero SCOPE counts as an option nobody can read under the ECS rules below.
- A listener processing error, an overall request timeout, or flow control refusing a query gets SERVFAIL, with the header and question and an OPT for a query with one; a timeout or a refusal parses nothing of the query, so one the quick parse cannot read is answered too.
- UDP responses larger than the client's advertised size (the EDNS payload size, at most 1232 bytes so as not to fragment at the IP layer, see DNS Flag Day 2020; or 512 bytes without EDNS) are truncated at record boundaries with the TC bit set, so the client can retry over TCP; with the answer and authority sections whole and only additional records left out, TC is not set (RFC 2181 section 9); the OPT of every reply advertises 1232.
- A message over TCP declaring more than 4096 bytes is not waited for: the connection closes there and then, the queries before it still answered. An answer over 65535 bytes, too long for one TCP message, gets SERVFAIL.
- Once 512 inbound TCP and DoH connections are open in all, a new one goes only to a device not yet holding its share, with flow control on or off: a device holding none always connects, and one opening any number gets no more than its share. A connection not taken is closed at once.
- Listening on `[::]`, IPv4 gets a `0.0.0.0` of its own and `[::]` takes IPv6 alone: whether an IPv6 socket takes IPv4 differs by system (FreeBSD and the other BSDs do not, OpenBSD never does), and this way both families are answered on every system, over UDP, TCP and inbound DoH alike. A client address in the IPv4-mapped form `::ffff:a.b.c.d` is judged by rules, GeoIP, ECS and the cache by the IPv4 address it carries, so client_ip takes IPv4 networks as usual; a network written as `::ffff:a.b.c.d/n` counts as the IPv4 network it names.

Inbound DoH is disabled unless settings.bind_doh is set. When it is set, settings.doh_tls_cert and settings.doh_tls_key are required and must point to PEM files. The path defaults to /dns-query and can be changed with settings.doh_path. The certificate and key are read at startup: when they cannot be read, or the DoH port cannot be bound, DNS answers as usual without inbound DoH, an error is logged, and the control channel's `config` result gives the reason as `doh_error` (null when DoH started or none is configured). Configuration validation and hot reloads only check that both paths are written and read no file, so a wrong path shows at the next start.

The inbound DoH handler:

- speaks HTTP/2 and HTTP/1.1: a client that picks h2 in the TLS handshake gets HTTP/2, with up to 100 requests handled at once on one connection; a client that only speaks HTTP/1.1, or sends no ALPN, keeps HTTP/1.1;
- closes a connection idle for 10 seconds (nothing being handled and nothing new coming), under either HTTP version; an HTTP/2 connection not closed 10 seconds after its GOAWAY is dropped;
- drops a connection whose answers make no progress being written for 10 seconds (a client sending without reading);
- accepts POST requests at the configured path and reads a DNS wire message body; one whose Content-Type is not application/dns-message gets 415 (RFC 8484 section 4.1);
- answers another method at the configured path with 405 and an Allow header of GET, POST, and another path with 404;
- accepts GET requests at the configured path with a dns base64url-without-padding query parameter;
- rejects queries over 4096 bytes (a POST body with 413, a GET dns parameter decoding longer with 400), the same bound as over UDP and TCP;
- answers standard queries only, as UDP and TCP do: a request with an opcode other than 0 gets NOTIMP, and a query with a question count other than 1 and the like FORMERR (both 200, the header alone); a response with QR=1 gets 400;
- returns application/dns-message for a successful DNS response;
- pads the answer to a query carrying EDNS padding (RFC 7830) to a multiple of 468 bytes (RFC 8467 section 4.1), and an answer to one without none. The UDP and TCP listeners are cleartext and pad nothing (RFC 7830 section 6).

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

The upstream field accepts a string, a comma-separated string, or a JSON string array. Multiple upstreams are queried concurrently and the first accepted response is returned. A response with SERVFAIL or REFUSED is not accepted when choosing among multiple upstreams; a truncated response (TC set, with TCP not fetching the whole one either) is held back and returned only when no other upstream gives a whole response, the client then turning to TCP itself on seeing TC; with neither, the first failure response received still goes to the answer check (see Pipelines and rules).

The following prefixes override the transport field:

| Prefix | Transport | Alias |
|---|---|---|
| udp:// | UDP | |
| tcp:// | TCP | |
| tcp+udp://, udp+tcp:// | TCP+UDP | |
| doh:// | DoH | https:// |
| dot:// | DoT | tls:// |
| doq:// | DoQ | quic:// |

Without a prefix, an omitted transport means UDP. DoH URLs without a path use /dns-query. DoH supports a host query parameter overriding the request's authority: the Host header under HTTP/1.1, the :authority under HTTP/2 (with no Host header), the connection and TLS still following the host in the URL; with `HTTPS_PROXY` / `ALL_PROXY` set, an upstream with it speaks HTTP/1.1 only. That parameter is removed before the request is sent. A DoH answer is taken only with a success status, the application/dns-message media type and at most 65535 bytes; a redirect (3xx) is not followed and fails the upstream like any other error status.

A DoH upstream that answers 429 Too Many Requests is not retried and does not count towards doh_health_check_error_threshold; it pauses from that moment for the seconds its Retry-After gives, brought into 1 to 60, or for 1 second when Retry-After is missing, a date or unreadable. While it is paused, a forward asking several upstreams together (several in one upstream, or several forward actions in one rule) leaves it out and the others answer; when every upstream of the set is paused all are asked as usual, and a forward to this upstream alone still asks it. The start of a pause logs one warning.

A DoH upstream that cannot be connected to (the connect or the TLS or HTTP/2 handshake failing, or a failed connect still being backed off from) is likewise not retried and does not count towards doh_health_check_error_threshold: rebuilding the pool is for dropping broken connections, and there is none to drop. Only an error or a timeout sending or receiving on a connection made is retried once and counted.

DoT uses port 853 when no port is supplied. Its optional TLS name is supplied with sni or servername and it must not contain a DNS path.

DoQ uses port 853 when no port is supplied. Its optional query parameters are sni/servername and 0rtt/enable_0rtt. A DoQ upstream written with an IP literal requires an explicit SNI. 0-RTT is enabled globally by default, can be overridden per upstream, and is disabled for every connection to that upstream until the process restarts once a connection that used 0-RTT times out or is rejected, counting both an explicit rejection and the peer closing or resetting the connection, which is how a server refusing early data often answers. A timeout on a connection that did not use 0-RTT only means a slow answer and leaves 0-RTT alone.

Connections to TCP, DoT and DoQ upstreams, and to DoH upstreams over HTTP/2, are made in the background, taking at most 5 seconds (resolving the name and the handshakes included): when the query that started one times out or is cancelled first (another upstream asked with it answering, say), the connection is made all the same and kept for the next query, which checks it is still open before using it and makes another when the upstream has closed it meanwhile. After a failed connect the upstream is left alone for 250 milliseconds before connecting again, the wait doubling with each failure in a row up to 5 seconds and counted from when the connect failed; queries forwarded to it meanwhile fail at once without connecting. An upstream resolving to several addresses is connected to staggered (RFC 8305): the families alternate, the first address's family first (IPv4 always first for DoQ), and an address not connected after 250 milliseconds, or failing, has the next one tried as well, the first to connect being used. When a TCP or DoT connection goes while a query waits on it, and it was there before that query or had answered other queries (an upstream answering some and closing), the unanswered query is sent once more on a fresh connection (RFC 7766 section 6.2.1.1); one the query made itself that went before answering anything is not sent on again.

An upstream answer is taken only when it answers this query's question (the name ignoring case, the same type and class). Over UDP, TCP and DoT an answer that does not match is dropped and the query keeps waiting for the real one; over DoH and DoQ a query gets a single answer, so a mismatch fails that upstream. An error answer with no question section and no records at all, which is how some upstreams send FORMERR or NOTIMP, is still taken.

Queries sent upstream always carry the AD bit (RFC 6840 section 5.7), so a validating upstream's answer always carries its verdict; for a client whose query had neither AD nor DO the answer loses AD (section 5.8), so the AD a client sees does not depend on who filled the cache. A TSIG-signed query is sent as it is. An answer handed on always loses its AA bit: KixDNS is not the authority for that data, less so for what comes from its cache.

Queries sent upstream over DoT, DoH and DoQ carry EDNS padding (RFC 7830) bringing them to a multiple of 128 bytes (RFC 8467 section 4.1); a query without EDNS gets an OPT for it (RFC 9250 section 5.4 has every DoQ query padded), and such a client still gets an answer without one. Nothing is padded over UDP or TCP (RFC 7830 section 6). Padding belongs to one hop: the padding in a client's query is not passed upstream, and the padding in an upstream's answer enters neither the cache nor a client's answer (inbound DoH pads by the client's query itself, see above). A signed query goes out as it is.

When UDP forwarding fails, or when an upstream UDP response is truncated, TCP fallback is enabled by default and can be disabled with settings.enable_tcp_fallback. When TCP gives no full answer for a truncated one (the upstream's TCP blocked, say), the truncated answer goes back, and the client turns to TCP itself on seeing the TC bit. The fallback is applied by the forwarding path; it is not an additional listener.

## Configuration examples

### Basic routing and static response

~~~json
{
  "version": "1.0",
  "settings": {
    "bind_udp": "0.0.0.0:5533",
    "bind_tcp": "0.0.0.0:5533",
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

Before an upstream answer is handed on or cached, the TTL of every record is brought into min_ttl to cache_max_ttl (cache_max_ttl winning when the two cross), so a client keeps an answer as long as the cache does. The DNS response cache uses the answer's minimum TTL, or the SOA negative-cache TTL for a negative response with an SOA, brought into the same range and bounded by cache_capacity; a negative response with a CNAME chain (NXDOMAIN, or NOERROR whose answers are only aliases) counts as negative too, and is cached for the shorter of the chain's minimum TTL and the negative-cache TTL; a negative response without an SOA is not cached (RFC 2308 section 4). Failures stay out of the cache: a SERVFAIL is never cached, wherever it comes from, and neither is a REFUSED or an extended RCODE from an upstream, records or not, so one passing failure does not stay until the entry expires; a static answer the rules give themselves (deny's REFUSED included) is cached when it depends on an upstream's answer, that is when an answer check's actions give it, or the rules after an answer check continued on an upstream's answer, or the pipeline it jumped to: cached, it spares asking the upstream next time. It is cached for the TTL it carries, the least of its records' (min_ttl raises the TTLs of upstream answers, not those a rule writes); one without records (deny, static_response, the NODATA of a type with no records) has no TTL of its own and is cached for the bound below. An answer cached after an answer check, be it a static answer of the rules or one fetched by a forward (forwarded by the answer check's actions, or by the rules after a continue, or the pipeline jumped to), stays no longer than the one staying shortest in the cache among the upstream answers the answer checks on the way went by: past that the upstream may answer otherwise, and the answer checks may take another way. With such an answer itself kept out of the cache (a TTL of 0, a negative response without an SOA), no answer after it is cached either. A static answer the rules give outright stays out of the response cache (one given outright in another pipeline after a request-phase jump into it too): the rules give it again outright, and the query log and rule counts still have it under its rule. A static answer given as a fallback after an upstream failure, no answer or a failure reply such as SERVFAIL or REFUSED seen by an answer check (by the miss actions or the answer check's actions, or the rules after their continue, or the pipeline they jump to), goes to this request and those waiting on it alone, and stays out of the cache too, so the upstream's answer is back as soon as the upstream is; a backup upstream's answer fetched then is cached as usual (unless flow control held the query back, see flow_control_enabled), under the same bound. Identical in-flight cache misses share one upstream operation.

When a pipeline's answer can depend on who is asking, the response cache, the in-flight deduplication, and the rule cache keep requesters apart by how its rules judge them, not by address: whether the client address is in each client_ip network, whether it is private (geoip_private), whether its GeoIP country or tag matches (geoip_country), and whether the query carries EDNS (edns_present, response_edns_present). The subnet a forward derives from the client keeps in-flight requests apart, while cached answers are told apart by their ECS scope (see ECS). Requesters judged alike share entries. The rules along the response-jump paths that a pipeline's answer checks start count too, because a request runs them before it answers. Such a path forwards the packet that the forward before the jump prepared, ECS included; the answers reached on it are cached under the key of the pipeline jumped from, which is also what requests waiting on that key get, and the forwards along the path merge no in-flight requests of their own. The rule cache holds the decisions of a pipeline's own rules and so judges by that pipeline's request matchers only, cache_background_refresh on or off (a background refresh does not read the rule cache); a decision whose evaluation ran a log action stays out of it. A pipeline whose rules judge no requester facts shares entries between all clients as before. A background refresh replays the request from the same client address, with EDNS and the client's own ECS option when the request carried them (an ECS option that does not follow RFC 7871 section 6 is left out), so pipeline selection, request rules and the ECS sent upstream are the same as for that request. When the refreshed answer applies to other requesters than the entry it renews (the upstream narrowed its scope, say), that entry is removed and its requesters ask again.

When cache_background_refresh is enabled, entries near expiry can trigger an asynchronous refresh. A refresh runs the rules as a client query does, response rules and their actions included, and what it comes to is settled at the end. When the upstream answers, the answer the rules reach is cached as usual and replaces the entry; when it is not cached under the entry (the upstream's answer kept out of the cache by its TTL: a TTL of 0, or a negative response without an SOA; a static answer that is not cached; one reached after a continue through a request-phase jump, which is cached under the target's key. An answer an answer check's jump reaches is cached under the entry and replaces it as usual), the entry is removed so the next client query runs the rules itself. When the upstream fails (a jump target's upstream included), the refresh ends there, neither miss actions nor later rules run, and the entry stays. A refresh that ends in an answer the cache never takes fails too and leaves the entry: SERVFAIL (the jump limit, a jump target that does not exist, a static SERVFAIL and so on), a truncated answer, a TSIG-signed answer; it is logged as a failed refresh. When serve_stale is enabled, an expired entry can be returned with serve_stale_ttl, subject to serve_stale_expire_ttl and serve_stale_client_timeout_ms. Returning an expired entry starts a refresh that decides the answer again; an answer the rules gave themselves (a static answer of an answer check, say) is decided again the same way once expired, so it is not served on after the upstream recovers. That client wait is additionally bounded by the remaining request_timeout_ms budget, so a wait configured longer than the request budget cannot push the stale answer past the deadline.

The main configuration watcher reloads a valid JSON file using per-pipeline cache namespaces. A changed pipeline immediately stops addressing response-cache, rule-cache, and in-flight entries created by its previous configuration; an unchanged pipeline keeps its warm caches. A change to a global setting that alters answers (min_ttl, default_upstream, response_jump_limit, enable_tcp_fallback) rotates every pipeline namespace; the settings that only decide how the cache is used (the timeouts, the serve_stale and background refresh families) leave them alone. A pipeline's namespace also covers the pipelines its answer checks' jumps reach: the answers got there are cached under its key, so a change to a jump target retires them too. Old namespace entries are not synchronously deleted and remain bounded by the existing cache capacity and TTL policies. Each request, including background refresh and response-phase jumps, keeps the configuration snapshot that selected its namespace, so work started before a reload cannot write into the active generation. Invalid reloads leave the previous configuration active and log an error, seen at the default log level too. At startup the configuration file is watched before it is read, so a change made while the kernel starts is still reloaded once it is up. When the file cannot be watched (no watches left, say), a change to it is not reloaded, nor is a save from the panel applied: an error is logged, and `watch_error` in the control channel's `config` result gives the reason (null while it is watched). So too when the configuration file, through a symlink, comes to lead somewhere that cannot be watched; once it is watched again it is back to null.

The following used to load and then silently do something else: an upstream address nothing can read (a bad port, a UDP upstream that is not an IP address, an unknown prefix such as `http://`, a DoQ IP literal without an SNI), a misspelt rcode (which answered NXDOMAIN), an invalid static IP or CNAME target, TXT content that does not fit a record (which answered SERVFAIL), a jump to a pipeline that does not exist (by a jump action or pipeline_select), a matcher written empty that so holds for every name (domain_suffix, `.` too, domain_regex, geo_site_not and their counterparts in answer checks, which matched every name; response_txt_content in prefix or regex mode written empty likewise, holding for every answer carrying a TXT record), domain_exact and request_domain_exact written empty (which match the root name alone; write `.` when the root is meant), forwards in one rule writing different ecs (which sent none of them), several pipelines written with one id (only one of them is found by the id, and the rules of the others do not run as written), a static-mode ecs address that is no IP (which logged a warning for every query and sent no ECS), a connection pool over 1024, a dashmap_shards over 65536 and a response_jump_limit over 64 (startup uses the limit), and keys the kernel does not read: a misspelt setting, or a key of a rule, pipeline or pipeline_select written under the wrong name or at the wrong level (`matcher` for `matchers`, say, which left the rule with no matcher, so it matched every query), and a key inside an action, matcher or ecs that is misspelt or not read by its kind (a forward's `upstream` written `upstrem`, say, which asked the default upstream), raised by paths like `settings.min_tll`, `pipelines[0].rules[2].matcher` and `pipelines[0].rules[2].actions[0].upstrem`, in the order written (a misspelt required field there still failing to parse); settings taken out earlier (the five former numbers of flow control, `prefetch`, `tcp_health_check_error_threshold`, never counted up to, `statistics_enabled` and `statistics_anonymize_client_ip`, which no longer do anything (rankings keep whole client addresses), and `geoip_auto_convert` and `geoip_filter_countries`, never read) are ignored as before, with only a warning (see the next paragraph). At startup they are logged as errors, seen at the default log level too, and the configuration loads all the same (a setting over its limit held to it), so one already in use still starts after an upgrade (the control channel's `config` result lists them in `problems` too, an item each of at most 2048 characters, cleared by a successful reload); a reload and the control channel's configuration validation refuse them, listing every problem at once (an item each, of at most 2048 characters, in `error.problems` of the validation's 422 answer and, once a reload is refused, in `last_reload.problems` of the control channel's `config` result; `error.message` and `last_reload.error` are them joined into one sentence, also cut to 2048 characters), so the next change has to fix them. Each problem starts with where it is, written as the paths of those keys are: `settings.doh_path`, `pipeline_select[0]`, `pipelines[1].rules[2]`, and for a matcher on down to `pipelines[1].rules[2].response_matchers[0]`, all counting from 0. Global settings that make no sense on their own (cache_capacity written 0, say, or a bind_udp that is no IP address and port) are taken by neither startup, reloads nor validation, and the error starts likewise with the setting and its value, as in `settings.bind_udp: "localhost:53" is not an IP address and port`.

Some other writing loads and runs as written yet is worth knowing: the retired settings above and background_refresh_rule, a matcher written empty that so never matches (geoip_country and response_answer_ip_geoip_country with no country code, geo_site, response_request_domain_geo_site, listener_label and upstream_equals written empty, response_upstream_ip and response_answer_ip naming no network), the parts of a domain_regex or request_domain_regex written in capitals outside `(?i)` that so never match (a literal holding a capital, a class taking capitals alone such as `[A-Z]`: the names rules see are lowercase), a cache_capacity over 1000000 (which may take a lot of memory), a request_timeout_ms under two and a half times upstream_timeout_ms (which may cut the resend and the TCP fallback short), a TCP, DoT, DoH or DoQ upstream written with a host name while bootstrap is unset (resolving comes back round should the system resolver be KixDNS itself), and Geo tags rules use with no data configured to read them from (GeoSite tags without geosite_data_paths, and without geoip_dat_path the GeoIP tags the MMDB cannot answer either, that is those other than two-letter country codes, or every one when geoip_db_path is not set either; such a geo_site or geoip_country never matches, and geo_site_not always does). These are no problems as above, and startup, reloads and validation refuse none of them: each is logged as a warning every time the configuration takes effect, the control channel's `config` result lists the current configuration's in `warnings`, and the configuration validation's answer carries `warnings` too, an item each of at most 2048 characters. Each warning starts, as a problem does, with the setting or matcher it is about, such as `settings.bootstrap` or `pipelines[0].rules[1].matchers[0]`.

These global settings are read at startup only; a reload does not apply them, and a change takes a restart: `bind_udp`, `bind_tcp`, `bind_doh`, `doh_path`, `doh_tls_cert`, `doh_tls_key`, `cache_capacity`, `cache_max_ttl`, `dashmap_shards`, `udp_pool_size`, `tcp_pool_size`, `doh_pool_size`, `doh_health_check_error_threshold`, `dot_pool_size`, `doq_pool_size`, `tcp_connection_max_age_seconds`, `tcp_connection_idle_timeout_seconds`, `doq_connection_idle_timeout_seconds`, `doq_keepalive_interval_ms`, `doq_enable_0rtt`, `bootstrap` and `flow_control_enabled`. Every other global setting applies on a reload. After a reload, the settings the configuration changes that are still waiting for a restart are listed in `restart_pending` in the control channel's `config` result, and an error naming them is logged (seen at the default log level too); once changed back to their startup values, or after a restart, they are no longer listed. Changing these settings on a reload does not drop the caches. The UDP worker count comes from the command line and likewise applies at startup only. Renewed DoH TLS cert/key PEM files are hot-reloaded, though changing the configured file paths still requires a restart. When the configuration file, the certificate and key, or a Geo data file is a symlink (a Kubernetes ConfigMap or Secret volume, say), a change to the file it points at, or any link along the way pointing elsewhere, counts as the file changing, and the watch follows the new target. These files are read once written: on Linux once the writer closes the file or it is renamed into place; elsewhere once writing has stopped for 0.3 seconds; a file written to without end is still read after 2 seconds. A metadata change alone (chmod, chown) is no change. A file that reads wrong (broken, cut short) leaves what is in use in place until it changes again.

After a reload, upstreams the configuration no longer names have their TCP, DoT and DoQ connections closed, once the requests using them have finished.

GeoSite files in geosite_data_paths and the GeoIP file in geoip_dat_path are watched and read again when they change; the MMDB in geoip_db_path is not watched; on a hot reload an unchanged MMDB file (same path, size and modification time) keeps the data already read and a changed one is read again, even with the configuration's GeoIP settings unchanged, and one that cannot be read (missing, being replaced, broken) leaves the data in use in place until the file looks otherwise (its path, size or modification time changed) and a hot reload after that reads it; hot reloads before that do not read it again, nor do they move the pipelines using GeoIP to a new cache namespace for it. A GeoSite `.dat` is read only for the tags rules use, and with none used it is neither read nor watched; GeoIP data is read only for the country codes and tags rules (geoip_country, response_answer_ip_geoip_country) use (see GeoIP data sources and tags above), and a file not read is not watched. When a hot reload changes the GeoSite or GeoIP tags rules use, or any of these file paths, the Geo data is read again for the new configuration and the watches move to the new files; the old data is replaced only once the new data has been read, so the new rules use the new data from their first query. A configured file that does not exist yet is watched too and read as soon as it appears, ranked among the files declaring one tag where the configuration puts it; when its directory does not exist either it cannot be watched, and the first hot reload after it appears reads it. A watched file that, read again, has none of the tags rules use while it provided some of them until now (an empty file left by a failed download, say) keeps the data in use for the tags it alone provided, until the file changes again; the tags another file provides too take that file's data, as reading every file again would have it. The same goes for such a file read again by a hot reload: the tags it provided that the rules still use and no other file provides keep the data in use. Data kept this way lives in the process alone and is gone after a restart, so such a file is logged as an error and listed in `data_warnings` below too, naming the tags keeping the data from before, until the file is put right and read in. A regex written wrong in a data file is skipped and matches no name. GeoSite tags rules use that no data file provides are logged as a warning, as GeoIP tags are. Geo data files and an MMDB that are configured yet missing or unreadable, and watches that cannot be installed, are each logged as an error, seen at the default log level too; `data_warnings` in the control channel's `config` result lists these problems with the Geo data as they stand, a sentence each, together with the tags rules use that no data provides (geo_site and geoip_country never match them, and geo_site_not always does), dropping each once its file is put right and read in, and is empty when nothing is wrong.

Once Geo data is swapped in (a changed file read again, or data read by a hot reload), the pipelines whose answers depend on a tag whose data changed move to a new cache namespace: those whose rules judge the request name by that GeoSite list (geo_site, response_request_domain_geo_site and the like) or the addresses in the answer by that GeoIP tag (response_answer_ip_geoip_country; with an MMDB, two-letter country codes go by the MMDB), counting what the pipelines their answer checks jump to use (the answers a request-phase jump gets are cached under the target pipeline's key and go with the target). Answers and rule decisions cached with the old data are no longer handed out, as when a hot reload changes the rules; pipelines that do not use that tag keep their caches. Whether the data changed goes by its content: a hot reload using one tag more, a file written over with the same content, or a file changing other tags alone leaves the pipelines reading the tag where they are. Rules judging only the client address's GeoIP country (geoip_country) need no new namespace: the cache already tells clients apart by the result of that judgement, which changes with the data.
