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
| bind_udp | 0.0.0.0:5533 | UDP 监听地址；端口被别的程序占着时启动失败，不和它共用。默认端口以前是 5353，那是 mDNS 的端口，常被系统的 mDNSResponder、avahi 占着；照旧要 5353 的写明这个地址。写通配地址（`0.0.0.0`、`::`）时，Linux、macOS 和 FreeBSD 等 BSD（OPNsense、pfSense 也是）上回答从查询发到的那个本机地址发出（RFC 2181 第 4.1 节），机器有几个地址（别名地址、随时会来去的 CARP VIP）也不会答错地址；为此每个查询的收发多约 0.1 微秒（Linux 上量的），只服务一个地址时写那个具体地址就没有这份开销。Windows 上回答的源地址由系统挑。 |
| bind_tcp | 0.0.0.0:5533 | TCP 监听地址。 |
| bind_doh | null | 入站 DoH 监听地址；null 表示禁用。 |
| doh_tls_cert | null | PEM 证书路径；设置 bind_doh 时必需。 |
| doh_tls_key | null | PEM 私钥路径；设置 bind_doh 时必需。 |
| doh_path | /dns-query | 入站 DoH 请求路径，以 `/` 开头；不以 `/` 开头的对不上任何请求，算一条配置问题（见下文）。 |
| default_upstream | 1.1.1.1:53 | 默认上游；支持逗号分隔列表。 |
| bootstrap | 空 | 解析写成主机名的上游（TCP、DoT、DoH、DoQ）用的明文 DNS 服务器，逗号分隔的 `IP:端口`，经 UDP 问；A 和 AAAA 同时问，每种同时问每个服务器、取先答上的那个，两种都等到答上，晚答上的照样用，各自最多等 2 秒。一种没问到（到时没答上，或者只答了 SERVFAIL、REFUSED 这样的失败应答；答了没有这种记录算问到）不连累另一种：这一种接着用上次问到的地址（头一回问时就先没有），10 秒后再问；问到过地址的名字后来一个地址也问不到（比如两种都答了 NXDOMAIN）时，也接着用上次的地址，10 秒后再问。问到的地址马上就用：TTL 过了也照用，同时在后台再问一次，问不到就一直用上次的；只有从没问到过的名字要等，最多 2 秒。不设时交给系统的解析器，也最多等 2 秒：系统的解析器要是 KixDNS 自己，解析上游的名字会绕回来问 KixDNS，上游就连不上，所以这时有写成主机名的 TCP、DoT、DoH、DoQ 上游会算一条警告（见下面值得知道的写法）。写成 IP 的上游不用解析。设了 `HTTPS_PROXY` / `ALL_PROXY` 时，DoH 经代理连上游，上游的名字由代理解析；代理自己的主机名也按这一项解析，系统的解析器是 KixDNS 自己、KixDNS 又要经这个代理才问得到它时也不会绕回来。这些服务器答了 DNS 里没有它的地址（A、AAAA 有一种答了 NXDOMAIN，或者两种都答了没有记录）时，它是本机或局域网自己的名字（hosts 文件里的、mDNS 的、局域网 DNS 的，或者靠搜索域补全的单个标签），交给系统的解析器；没问到时照样失败，不交给系统的解析器。NO_PROXY 里的 DoH 上游直连，照常按这一项解析。 |
| upstream_timeout_ms | 9000 | 单次上游操作超时；必须大于 0。UDP 转发等过这个上游最近最慢百分之一回答的用时还没有回答，会把查询再发一次（至少等 50 毫秒，最多等超时的三分之一；这个上游还没回答过时等三分之一），此后一整个超时里两次谁的回答先到用谁的。 |
| request_timeout_ms | null | 整体请求超时；为 null 时使用 upstream_timeout_ms * 2.5，且不能小于 upstream_timeout_ms。 |
| response_jump_limit | 10 | 一个查询最多跳转几次 Pipeline，请求阶段和响应阶段的跳转都算：请求阶段规则的跳转最多这么多次；回答动作头一次跳转起，回答动作里的跳转连同之后规则级的跳转另算，也最多这么多次；再跳就回 SERVFAIL。不能超过 64。 |
| udp_pool_size | 64 | 出站 UDP socket 池大小。每个查询随机挑一个 socket、随机取 ID；一个 socket 发满 64 个查询就换成系统另挑端口的新 socket，端口用不了多久，防火墙的连接跟踪也只多出未命中数的六十四分之一。不能超过 1024。 |
| tcp_pool_size | 64 | 每个上游最多几条 TCP 连接。平常只用第一条；它上面同时有 32 个以上查询没答完时，再来的查询才用后面的。不能超过 1024。 |
| doh_pool_size | 8 | 上游不支持 HTTP/2、或设了 `HTTPS_PROXY` / `ALL_PROXY` 时，每个上游最多保留的 DoH 空闲连接数。支持 HTTP/2 的上游直连，每个工作线程最多一条，平常只用一条，忙起来的规则和 `tcp_pool_size` 一样。不能超过 1024。 |
| doh_health_check_error_threshold | 3 | DoH 上游在建好的连接上连续出这么多次传输错误（超时、读写出错；连不上不算）以后，丢掉它的全部连接重新连：直连的连接断开，经代理或 HTTP/1.1 用的连接池重建；同一批一起断掉的请求只让它重连一次。0 表示不做这项检查。 |
| dot_pool_size | 64 | 每个上游最多几条 DoT 连接，平常只用一条，规则和 `tcp_pool_size` 一样。不能超过 1024。 |
| doq_pool_size | 16 | 每个上游最多几条 DoQ 连接，平常只用一条，规则和 `tcp_pool_size` 一样。连接没了、或者查询超时而这期间连接上没有别的回答时才换新的；回答不合协议、流被重置只算这一个查询失败。不能超过 1024。 |
| tcp_connection_max_age_seconds | 300 | TCP/DoT 连接最大存活时间；0 禁用。 |
| tcp_connection_idle_timeout_seconds | 60 | TCP/DoT 连接空闲多久就关掉：连接上的查询都过了期限以后，这么久没有新查询；排在池后面、平常轮不到的连接也一样（RFC 7766 第 6.2.3 节）。DoT 关的时候先发 close_notify。0 禁用。 |
| doq_connection_idle_timeout_seconds | 60 | DoQ 空闲超时；0 禁用。 |
| doq_keepalive_interval_ms | 15000 | DoQ keepalive 间隔；0 禁用。 |
| doq_enable_0rtt | true | 全局 DoQ 0-RTT 设置。 |
| enable_tcp_fallback | true | UDP 失败或截断时用 TCP 重试。 |
| flow_control_enabled | false | 启用流控，不用填数字，内核运行时自己判断。一台设备能占满的有四样：处理能力、等上游的查询、上游、内存，各有各的办法，发得少的设备都照常。**处理能力。** 接收 socket 连续 100 毫秒收不空算内核忙；忙而且查询在内核里排队超过 20 毫秒时，在途查询不比各设备平均少的设备，新的未命中查询直接回 SERVFAIL。丢包或拒绝持续一秒以上时，UDP 按设备轮流处理：每台设备各排各的队（不和别的设备共用，每台至少排得进 4 个；排队的设备满了、有新设备被挡在外面以后的 10 秒里每台只排得进一个，轮到一次就让出位置），排不下的不回应直接丢弃，发得少的设备不受影响，隔多久才问一次都一样。最多 4096 台设备同时排队，再来的新设备直接丢掉：洪泛的来源多到一直占满这些位置时，发得少的设备大多排不进去。跟上以后一分钟之内又丢包或拒绝，算同一阵的继续，马上轮流，一阵阵的洪泛也挡得住。轮到的查询交给内核处理，有活等着内核干的查询（交出去还没开始处理的，和上游的回答到了还没轮到处理的）最多 64 个，再多的留在各设备自己的队列里等下一轮：设备再多、合起来发得再快、有几个核，内核里都不积压，多出来的按上面的办法丢，谁发得多丢谁的。轮流期间要等上游的查询只看内存；跟上之后恢复，也就是不轮流也不会丢包：一台设备一次发得比自己那一份多，只要每批放得进接收缓冲、平均没超出处理能力，轮流也会结束。**卡住的查询。** 内核按上游记着最近几千次收发各用了多久（从发出到收到用得上的回答；SERVFAIL、REFUSED 不记，回答是哪一次发出的查询等到的就记那一次：重发才等到回答的只记重发的那一次，第一次的回答在重发以后才到的从第一次发出算起；比上游超时还晚才读到的也不记）。一个未命中查询等一个上游，等过了这个上游最慢百分之一用时的两倍（至少 100 毫秒）还没有结果，算卡住，从转发开始那一刻算起；规则里一次写了几个上游的，按最慢的那个算。每个上游各算各的：十毫秒的上游和两百多毫秒的上游互不影响。还没等到过回答的上游先按所有上游合起来的算；刚启动、哪个上游都还没等到过回答时，按上游超时的三分之一算（UDP 转发重发的时刻）。卡住的查询留一千个接着等，各设备平分，每台设备至少留得下 4 个（留着的设备到 4096 台为止）；再卡住的不等上游超时，当作上游失败：规则写了上游失败时的动作就照做（比如改问备用的上游），这样得到的回答只给这一个查询、不进缓存，没写就回 SERVFAIL（开着 `serve_stale` 时照常用过期缓存），UDP、TCP 和 DoH 入站都一样。等在别的查询正在做的同一个转发上的查询也这样算卡住（按它自己那条规则的上游算），只是不记进下面「不回答的上游」的结果，被拦着的设备也照样能等：它自己没有问上游。留着的是每台设备先卡住的那些：上游只是变慢时，它们等到回答，这个时间马上跟着变长，后面的查询不再算卡住；回答变快以后，要再来三万多个回答才降回去。新来的查询不因为在途多被拒：上游慢、负载一阵一阵、刚启动，都不拒。**不回答的上游。** 按「设备、规则里写的那一串上游」记最近的结果。一台设备等一个上游，没等到回答的到了 64 个、又比等到回答的多（等到回答的每 16 个记一次），就先不替它问这个上游：未命中查询当作上游失败（同上，照规则里上游失败时的动作办，这样得到的回答只给这台设备、不进缓存：规则直接给的静态应答、改问备用上游得到的回答都一样，缓存是所有设备共用的，别的设备问这个上游是有回答的；没写动作就回 SERVFAIL 或过期缓存），每秒放一个去试，试到了用得上的回答就放开。别的设备、这台设备走别的上游的查询都不受影响；同时在问同一个名字的别的设备不拿它这个失败，各自去问。算没等到回答的，是上游什么都没回的：等过了上面算卡住的时间，或者等满了上游超时，卡住以后不等了的也在内；内核自己正在排队时不算，除非这台设备在这个上游上一个回答都没等到过。上游回了 SERVFAIL、REFUSED 不算，回得快慢都一样：上游是回了的，一个程序反复问一个坏掉的名字，不连累这台设备问别的名字。一个上游不通、对着不回答的名字洪泛、上游不再回答某台设备（限速时直接丢弃），都是这一条拦住，不会一直往不回答的上游发；上游用 REFUSED 限速时这一条拦不住，那时查询当场就有结果，不占内存。对着上游要等很久才回失败的名字洪泛时，超出卡住那一份的不等了、算没回答，同样拦住。代价：一台设备问同一个上游的名字多半都没有回答时，它在这个上游上答得上的那小半也被拦住。上游每个都回答、只是都很慢的洪泛（比如每个都两秒才回），不算卡住也不算没回答，在途只受下面的内存限制。**内存。** 同时处理的查询超过 1000 个以后看内存，看的是系统或所在限制（Linux 的各级 cgroup、Windows 的作业对象）的可用内存，底线是内核自身占用的四分之一加总量的十六分之一（后者最多 256 MiB）。可用内存低于底线的两倍时，在途查询最多是变紧张那一刻的数（在途掉到 1000 以下以后重新记），离底线越近按比例越少，到底线时为 0，按设备平分：在途查询不比自己那一份少的设备，新的未命中查询回 SERVFAIL；开着的连接不比各设备平均少、或者占着查询那一份的设备，新的 TCP 和 DoH 连接直接关闭；发得少的设备照常。按比例收，占着内存的设备一点点让出来，内存停在两条线之间，不会一直掉到底线。查询和连接各比各的：只开着一条空闲连接不算占了查询的份，开着很多连接的设备也不让查询的那一份变小。手上一个在途查询都没有的设备，内存不够以前 10 秒就在用的照常问，之后才冒出来的来源不接：伪造来源地址的洪泛每个来源都是新的，每个只占一个也能把内存占满，这样挡得住，原来就在用的设备不受连累。这样照常的设备最多记 512 台，一直在用得久的留着：伪造的来源各只出现一次，只能互相挤掉，同一批来源先打一阵、隔一会儿再打，内存没了时多放进去的在途也最多 512 个（约 5 MB）。1 小时没见过的设备再来时按新来的算；内存连着 1 分钟都够，下次不够就重新算这一阵从哪里开始。低于底线时，手上有在途查询的设备都不接，新的 TCP 和 DoH 连接都关闭。内存回来后恢复，UDP、TCP 和 DoH 入站都一样。**怎么算一台设备。** IPv4 一个地址、公网 IPv6 一个 /64 算一台设备，按设备记的数（在途、卡住的、问上游的结果）每台按两个哈希各记一份，两份都和别的设备撞上才会算到一起，两千个来源时这样的不到千分之一；局域网里的 IPv6 地址按完整地址算：链路本地、ULA、站点本地，以及和内核在同一个 /64 里的公网地址（内核每 30 秒看一次本机网卡的地址，家里的局域网主机用的是运营商下发的同一个 /64）；64:ff9b::/96 的地址按里面的 IPv4 地址算；DoH 前面挂着反向代理时，内核只看得到代理的地址，所有 DoH 用户算一台。读内存支持 Linux、FreeBSD 和 Windows（FreeBSD 上 ZFS 的 ARC 高出下限的部分算可用）；按设备轮流各平台都有：Linux 按接收 socket 的丢包数判断跟不上，读不到丢包数的系统（FreeBSD、Windows）按接收 socket 连续 100 毫秒收不空判断。关着时，要等上游的查询一共在途到 4096 个以后，占满了自己那一份的设备再来的查询回 SERVFAIL，在途少的设备照常。 |
| cache_capacity | 10000 | DNS 响应缓存最多存放的应答数，超过 1 KB 的应答每 1 KB 算一份；必须大于 0。 |
| cache_max_ttl | 86400 | DNS 缓存条目的最大生存时间，单位秒；必须大于 0。条目在自己的 TTL（不超过它）到了以后就从缓存里去掉，开着 serve_stale 时再留 serve_stale_expire_ttl 这么久，规则据上游回答给出的 deny 也一样（上游的失败回答不进缓存，见「缓存和重载行为」）。上游回答里每条记录的 TTL 也不超过它，和 min_ttl 冲突时以它为准。 |
| dashmap_shards | 0 | 内部分片设置；0 使用 DashMap 默认值，否则必须是 2 到 65536 之间的 2 的幂。 |
| cache_background_refresh | false | 在 TTL 过期前刷新条目。同时最多刷新 128 条，满了这次先不刷新，等下一次命中。刷新只用条目原来那条路上的新应答续期：上游失败时刷新就到此为止，miss 动作不跑，条目原样留着，过一阵再试；条目真过期以后，客户端的请求照常走规则。 |
| cache_refresh_threshold_percent | 10 | 条目的 TTL（应答里最短的那个，也就是它过期的时间）剩到这个百分比以内时刷新，至少提前 1 秒；必须小于 100，取 100 时每次缓存命中都会刷新上游。 |
| cache_refresh_min_ttl | 5 | 条目的 TTL 低于这个秒数时不做后台刷新。 |
| serve_stale | false | 按 RFC 8767 行为保留并返回过期条目。一条过期应答刷新失败以后，30 秒内不再为它刷新，命中它的请求直接拿过期数据，不再等（RFC 8767 第 5 节的失败复查）；30 秒后的头一次命中再试一次。 |
| serve_stale_ttl | 30 | 过期响应中写入的 TTL。 |
| serve_stale_expire_ttl | 86400 | 允许返回过期条目的最大时间，单位秒；0 表示不限制过期时间。 |
| serve_stale_ttl_reset | false | 过期应答的后台刷新失败以后，从这次失败起重新算它还能续用多久：上游一直取不到新的、又一直有人问的名字，就一直交出过期应答，不受 serve_stale_expire_ttl 限制（对应 Unbound 的 serve-expired-ttl-reset，那边默认也关）。以前默认开，而且每交出一次过期应答就重新算一次。 |
| serve_stale_client_timeout_ms | 0 | 0 表示立即返回过期数据；大于 0 时先尝试上游最多指定毫秒数，并受 request_timeout_ms 剩余预算截断，保证过期应答来得及返回。这次刷新失败时不再等满，马上返回过期数据。规则据上游应答给出的过期应答也一样等，它的刷新会把规则重新走一遍。 |
| geoip_db_path | null | MaxMind MMDB 路径。 |
| geoip_dat_path | null | V2Ray GeoIP 数据文件路径：可以是 protobuf `.dat`，也可以是下文说明的兼容 JSON。 |
| geosite_data_paths | [] | V2Ray GeoSite .dat 或 JSON 路径列表；支持多个文件。几个文件声明同一个标签时，用排在后面的文件里的。两种格式都只读规则用到的标签，规则一个都没用到时文件不读也不监控。 |

geoip_auto_convert 和 geoip_filter_countries 已经退役：运行时从来不读它们，写了照样加载，只在启动和每次重载时记一条告警；转换时的国家过滤请使用 convert-geo-ip 的 --filter。顶层 background_refresh_rule 也照样能读，但不会生效：后台刷新按原请求走过的规则重放。配置里写了它，启动和每次重载时各记一条告警，配置照常加载，删掉这一项即可。

### Pipeline 选择

pipeline_select 的每项包含 Pipeline id、可选的匹配器列表和可选的 matcher_operator。数组按顺序评估；第一个匹配且 id 存在的项选择对应 Pipeline。

### Pipeline 和规则

每个 Pipeline 包含 id、可选的 rules 数组和可选的 Pipeline 级 ecs。Pipeline 级 ecs 是旧配置用来区分缓存的，现在不再影响缓存（改动它时，热加载后该 Pipeline 的缓存仍会重新开始）。规则按配置顺序处理；规则的 name 只用在日志和统计里，可以重复。空匹配器列表视为匹配。规则内的匹配器按从左到右形成链；每个匹配器可以携带自己的 operator，或者在所有匹配器都省略 operator 时由规则级 matcher_operator 设置。

响应阶段使用同样的 response_matchers、response_matcher_operator、response_actions_on_match 和 response_actions_on_miss。Forward 得到响应后执行响应动作；配置了 miss 动作时，上游尝试全部失败后也会进入 miss 路径。响应动作按写的顺序执行，到第一个作决定的为止（log、forward 不作决定）；其中的 forward 各问各的，问到的应答换掉手上的，写几个都照写的一个接一个执行。几个上游一起问、全都失败、其中有上游回了失败应答（SERVFAIL、REFUSED 或扩展 RCODE）时，最先收到的那个应答照样交给回答检查：检查通过、而且 response_actions_on_match 有动作时，按这个应答执行 match 动作，和只问一个上游时一样。检查不通过，或者通过了但没有 match 动作时，照旧按上游失败处理：有 miss 动作时在没有应答的情况下执行，否则给过期缓存或 SERVFAIL。因此，SERVFAIL 也能满足的回答检查（例如「上游回 SERVFAIL 或 REFUSED 时改问」，或取反的 IP 条件）不管写了几个上游都会生效。后台刷新不这样做：上游都回失败应答时，刷新照旧算失败，条目保留。

### Pipeline selector 和请求匹配器

| 类型 | 字段 |
|---|---|
| any | 无 |
| listener_label | value |
| client_ip | cidr |
| domain_suffix | value |
| domain_exact | value |
| domain_regex | value |
| qclass | value：IN、CH/CHAOS 或 HS |
| edns_present | expect：布尔值 |
| geo_site | value：GeoSite tag |
| geo_site_not | value：GeoSite tag |
| geoip_country | country_codes：字符串数组 |
| geoip_private | expect：布尔值 |
| qtype | value：记录类型名（A、AAAA、CNAME、HTTPS、SVCB、CAA、ANY 等，大小写不论），或 RFC 3597 的 `TYPE65` 这样的数字写法 |

Pipeline selector 支持上表全部类型；请求规则支持除 listener_label 之外的全部类型。

#### GeoIP 数据源与标签

- `geoip_db_path` 加载 MaxMind MMDB，用于 `CN`、`US` 等两位国家代码。
- `geoip_dat_path` 加载 V2Ray protobuf `.dat` 或兼容 JSON。这里的 JSON 是 GeoIP 数据文件，不是 KixDNS 主配置文件；格式示例：`{"entries":[{"country_code":"CLOUDFLARE","ips":["1.1.1.0/24"]}]}`。不带前缀长度的地址按单个地址算，`1.1.1.1` 就是 `1.1.1.1/32`（IPv6 是 /128）。
- V2Ray 数据既可以包含国家代码，也可以包含 `CLOUDFLARE`、`NETFLIX`、`TELEGRAM` 等命名标签；同一 IP 可以属于多个标签。
- 同时配置两种数据源时，两位国家代码以 MMDB 为准；命名标签仍从 `geoip_dat_path` 读取。
- 只读入规则用到的国家代码和标签。MMDB 只在规则用到两位国家代码时读入；`geoip_dat_path` 只读入规则用到、又不由 MMDB 判断的标签，所以配置了 MMDB、规则只用两位国家代码时，这个文件不读。规则用到的标签不在文件里时会记一条告警，这样的规则不会命中。
- 标签匹配不区分大小写。`country_codes` 建议使用 JSON 字符串数组，例如 `["CN", "cloudflare"]`；为兼容旧配置，也接受单个字符串或逗号分隔字符串。

域名后缀和 GeoSite 标签匹配也不区分大小写。domain_suffix 和 request_domain_suffix 按整段域名比较：`example.com` 命中它本身和 `www.example.com` 这样的子域名，`.example.com` 只命中子域名；两种写法都不命中 `notexample.com`。domain_exact 和 request_domain_exact 只命中这个名字本身：`api.example.com` 不命中 `www.api.example.com`。这几种的值结尾带不带点都一样，`example.com.` 就是 `example.com`；单独一个点是根：domain_exact 和 request_domain_exact 写成 `.` 只命中根名字（比如拦掉对根的 ANY、NS 放大查询），domain_suffix 和 request_domain_suffix 写成 `.` 和写成空的一样匹配每个名字，算一条配置问题（见下文）。domain_regex 和 request_domain_regex 使用 Rust 正则语法，一条最长 16384 字节，编译后最大 1 MB，超出的配置读不进来。 规则看到的名字是查询名转成小写、不带结尾的点。标签里不是可打印 ASCII 的字节，以及标签本身含有的点和反斜杠，写成 `\DDD`（三位十进制）：标签 `a.b` 写成 `a\046b`，不会被当成两段，也不会命中 `b.example` 这样的后缀。domain_regex 要匹配这类名字时，按这个写法写。规则看到的名字因此只有 ASCII，domain_regex 和 request_domain_regex 里的字符类都只取 ASCII 的部分，`\b` 等词边界按 ASCII 的 `\w` 分界，和 GeoSite 的 `regexp:` 一样：`\w` 是 `[0-9A-Za-z_]`，`\d` 是 `[0-9]`，`\pL` 是 `[A-Za-z]`，`.` 和 `[^.]` 这样取反的字符类也只认 ASCII 字符。匹配结果和按 Unicode 理解时相同，编译出来小得多。response_txt_content 的正则仍按 Unicode 理解。

#### GeoSite 条目

- 写法与 V2Ray 的域名列表（domain-list-community）相同。`domain:example.com` 和不带前缀的 `example.com` 按整段匹配域名本身及其所有子域名（不匹配 `notexample.com`）；和 domain_suffix 不同，这里开头加点不改变含义。
- `full:example.com` 只匹配域名本身，`keyword:`、`regexp:` 按关键词、正则匹配，不带前缀且含 `*` 的值按通配符匹配。
- `.dat` 文件里的标签可以带属性键，写作 `tag@attr`（如 `google@cn`），和 V2Ray 一样按字面键匹配：`google@!cn` 选的是标记为 `!cn` 的域名。可以写几个属性，如 `google@cn@ads`，选的是每个属性都带的域名。不带属性的域名用 `geo_site: google` 加上 `geo_site_not: google@cn` 选出。
- JSON 里前缀不认识、没有值或正则无效的条目会跳过并给出警告。
- `regexp:` 的正则和 domain_regex 一样最长 16384 字节、编译后最大 1 MB，超出的跳过并给出警告，`.dat` 和 JSON 都是；一个标签里的正则合在一起匹配，也照样按每条的这个上限。

### 响应匹配器

| 类型 | 字段 |
|---|---|
| upstream_equals | value；回答来自这个上游时成立，写法见下文 |
| request_domain_suffix | value |
| request_domain_exact | value |
| request_domain_regex | value |
| response_upstream_ip | cidr；支持逗号分隔 CIDR |
| response_answer_ip | cidr；支持逗号分隔 CIDR |
| response_type | value；优先检查第一个 Answer 记录，没有 Answer 时使用查询类型 |
| response_rcode | value：NOERROR、FORMERR、SERVFAIL、NXDOMAIN、NOTIMP、REFUSED，或 OTHER（其余的 RCODE），大小写不论；别的写法是配置问题（见下文） |
| response_qclass | value |
| response_edns_present | expect：布尔值 |
| response_answer_ip_geoip_country | country_codes：字符串数组 |
| response_answer_ip_geoip_private | expect：布尔值 |
| response_request_domain_geo_site | value：GeoSite tag |
| response_request_domain_geo_site_not | value：GeoSite tag |
| response_txt_content | mode：exact、prefix 或 regex；value 为文本/模式，regex 最长 1000 字节。应答里的每条 TXT 记录分开比较，有一条命中就算命中；一条记录里的几个字符串先不加空格连起来再比（和 RFC 7208 读 SPF 记录一样），没有 TXT 记录的应答不命中 |

响应地址匹配范围如下：

- `response_answer_ip_geoip_country` 只检查 Answer；每个包含地址的 Answer 都必须命中请求的某个 GeoIP 标签。
- `response_answer_ip` 和 `response_answer_ip_geoip_private` 同时检查 Answer 与 Additional，只要任一地址匹配即可。
- 匹配器会检查 A/AAAA 地址以及 HTTPS/SVCB 的 `ipv4hint`/`ipv6hint`。同一 HTTPS/SVCB 记录中的 hints 是候选端点，任一 hint 匹配即可。
- IPv4 映射形式的地址（AAAA 或 `ipv6hint` 里的 `::ffff:a.b.c.d`）按它所指的 IPv4 地址判断，写成 `::ffff:a.b.c.d/n` 的网段按它所指的 IPv4 网段处理，response_upstream_ip 也一样。
- geoip_private 和 `response_answer_ip_geoip_private` 把私有网段（RFC 1918、ULA fc00::/7、已废弃的站点本地 fec0::/10）、运营商级 NAT 和 Tailscale 用的 100.64.0.0/10、192.0.0.0/24、回环、链路本地、0.0.0.0/8、`::`、丢弃前缀 100::/64 和 255.255.255.255 算作内网地址；NAT64 地址（64:ff9b::/96、64:ff9b:1::/48）按末 32 位嵌着的 IPv4 地址判断。基准测试用的 198.18.0.0/15 不算：它是 Clash、mihomo 等 fake-ip 的默认网段，算作内网的话，转给 fake-ip 上游的查询，回答都会被防重绑定的规则拦下（ECS 照样不按它注入子网，见下面的 ecs）。

这些匹配器只读取已有记录，不会创建或改写 HTTPS/SVCB 记录。

upstream_equals 和 response_upstream_ip 看的是这次实际作答的上游：一条规则同时问几个上游时，是给出这个应答的那一个。upstream_equals 的 value 有两种写法。写上游的地址，和 forward 的 upstream 写法一样（`1.1.1.1:53`、`tcp://1.1.1.1:53`；逗号隔开几个时，其中任一个作答即成立），这时只比地址，不管应答最后是哪种传输带回来的。或者写运行时的上游标签 `传输:地址`（`udp:1.1.1.1:53`、`tcp:1.1.1.1:53`，传输是 udp、tcp、doh、dot、doq 之一），这时传输也要相同；UDP 查询因截断或失败改走 TCP 时，标签是 `tcp:`。response_upstream_ip 取作答上游地址里的 IP；上游的主机写的是域名时不成立。

### 逻辑运算符

运算符从左到右计算，第一个匹配器作为初始结果：它身上写的 and_not、or_not（not）前面没有东西可合，也不把它取反；只有一个匹配器时，规则级的取反也一样白写。这两种写法作为配置问题报出来（启动时记一条错误、照旧加载，重载和面板保存时拒绝）。要匹配某个条件不成立的查询，前面放一个 `{"type": "any"}`，再对它写 and_not。

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
| log | level（可选） | 输出匹配规则的 tracing 事件，每个命中的查询都输出（这样的决策不进规则缓存；从响应缓存答的查询不走规则，也就不输出）；支持 trace、debug、info、warn、error，不写时为 info。日志默认只记 error（见使用说明的日志一节），低于 error 的要用 --debug 或 RUST_LOG 放开才看得到（比如 `RUST_LOG=error,kixdns::engine::rules=info`，只放开 log 动作所在的模块；写成 `kixdns::engine=info` 会连带放开每个应答一条的 `dns_response`），或者把 level 写成 error。 |
| static_response | rcode | 返回 NOERROR、FORMERR、SERVFAIL、NXDOMAIN、NOTIMP 或 REFUSED。 |
| static_ip_response | ip | 按查询类型返回 A 或 AAAA 记录（ANY 查询返回两者）；HTTPS、SVCB 等其他查询类型返回 NODATA，且不会合成 IP hints。`ip` 支持单个地址或逗号分隔的 IPv4/IPv6 地址列表（例如 `192.0.2.1,2001:db8::1`）。地址列表原样返回；列表过大时响应可能超过 UDP 大小限制。 |
| static_cname_response | target、ttl（可选） | 对所有查询类型返回将查询域名映射到 `target` 的 CNAME 记录；ttl 默认 300。服务端不会继续解析目标域名，也不会附带目标地址记录，客户端或解析器必须自行追踪别名；不能追踪裸 CNAME 的客户端可能返回无数据。查询域名或目标域名无效时返回 SERVFAIL。 |
| static_txt_response | text、ttl（可选） | 对 TXT 和 ANY 查询返回 TXT 记录，其他查询类型返回 NODATA；text 支持字符串或字符串数组，ttl 默认 300。数组里至少要有一个字符串，写成 `[]` 的问什么都回 SERVFAIL，也算配置问题，空的 TXT 写成 `[""]`；每个字符串最长 255 字节；整个应答要装进一个 DNS 报文（65535 字节，并给 EDNS 和 ECS 回显留出地方，每个字符串另占一个长度字节），按最长的名字（255 字节）算，装不下的问什么名字都回 SERVFAIL，也算配置问题；装得下的问什么名字都装得下。 |
| jump_to_pipeline | pipeline | 开始处理指定 Pipeline。 |
| allow | 无 | 请求阶段：使用全局默认 UDP 上游；响应阶段：保留当前上游响应。 |
| deny | 无 | 返回 REFUSED。 |
| forward | upstream（可选）、transport（可选）、ecs（可选） | 转发到指定上游；缺少 upstream（或写成 null、[]）时使用 default_upstream，写成空字符串不算缺少。 |
| continue | 无 | 继续处理下一个请求规则，或继续响应流程中的下一个 Pipeline 决策。 |
| replace_txt_response | text | 响应阶段把当前的应答换成 static_txt_response 给出的那种（TTL 300）：只有 TXT 和 ANY 查询拿到 TXT 记录，其他查询类型返回 NODATA，响应码都是 NOERROR，不管上游回的是什么；上游失败以后执行时没有应答可换，回 SERVFAIL；请求阶段手上没有应答可换，什么也不做，同一条规则后面的动作照常执行。text 的写法和大小限制和 static_txt_response 一样。 |

static_ip_response、static_cname_response、static_txt_response 和 replace_txt_response 给出的记录都是 IN 类的，所以只回答类别为 IN 或 ANY 的问题；其他类别（例如 CH）的问题返回 NODATA。

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
- from_client_ip：客户端自己带了 ECS 时，转发它自己的子网，前缀比这里设置的长就截短到设置的长度，前缀为 0 的原样转发、不加地址（RFC 7871 第 7.1 节）；客户端带的是私有网段或 IPv4 映射形式（`::ffff:a.b.c.d`）的网段时当作没带，不发给上游（第 11.3 节）；带的选项读不懂时去掉，也不加来源地址的子网。没带时根据客户端地址生成子网，IPv4 默认 /24、IPv6 默认 /56；客户端地址是 geoip_private 算作内网的地址，或者在基准测试的 198.18.0.0/15、本地用的转换前缀 64:ff9b:1::/48 里时不注入，也就是 RFC 1918 私有网段、100.64.0.0/10、192.0.0.0/24、198.18.0.0/15、回环、链路本地、0.0.0.0/8、255.255.255.255，IPv6 的回环、`::`、ULA fc00::/7、链路本地 fe80::/10、站点本地 fec0::/10、100::/64、64:ff9b:1::/48，以及 64:ff9b::/96 里末 32 位嵌着上面这些 IPv4 内网地址（198.18.0.0/15 除外）的 NAT64 地址，客户端自己带的这些网段也当作私有网段；
- static：使用配置的 IP 和前缀注入。

不写 ecs 的转发把客户端自己带的 ECS 选项原样发往上游。响应动作里的 forward 也可以写 ecs：写了就从客户端发来的查询按它改写，应答适用于哪些客户端也按它算；不写时和规则自己的转发发同一个包。

一条规则里写了几个 forward 时，它们合成一次转发，同时问所有上游（forward 前面已经写了别的作决定的动作，如静态应答或跳转时，规则给的是那个动作的结果，后面的 forward 不执行），发出的 ECS 也只有一个：几个 forward 的 ecs 写得一样时照它发；写得不一样时（包括有的写、有的不写），这条规则和不写 ecs 一样，这是一条配置问题（见「缓存和重载行为」）。upstream 写成空的（或只有逗号）的 forward 不在合并里：合并时跳过它，它的 ecs 不算，只要别的 forward 写了地址也不算配置问题。

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

- 只处理标准单 question 的 QUERY 消息。opcode 不是 QUERY 的请求（NOTIFY、UPDATE 等）回 NOTIMP，问题数不是 1 或带着回答、授权记录的查询回 FORMERR（RFC 9619），都只有请求头，请求带着读得出的 OPT 时加一条 OPT（RFC 6891 第 7 节）；DNS 响应包和不足 12 字节的包会被静默丢弃（TCP 上断开连接）。请求头是标准查询、报文却读不了的（比如带两条 OPT，或 UDP 查询超过 4096 字节）回 FORMERR，只带请求头和问题（查询带着读得出的 OPT 时也带 OPT），不比查询长。
- EDNS 版本不是 0 的查询回 BADVERS（RFC 6891 第 6.1.3 节），回答里的 OPT 写版本 0。
- 查询带的 ECS 选项地址不合规（地址族未知、前缀超过地址长度、地址的字节数和前缀对不上、前缀之后的位不为零）或者不止一个时回 FORMERR（RFC 7871 第 6 节、第 7.2.1 节），不问上游；SCOPE 不为 0 的照下面 ECS 的规则当作读不懂的选项。
- 监听器处理错误、整体请求超时或流控拒绝时回 SERVFAIL，带着请求头和问题，查询带 OPT 时也带 OPT；超时和流控拒绝时不解析查询，快速解析读不了的查询也照样回。
- 大于客户端声明大小（EDNS 载荷大小，最多 1232 字节，免得在 IP 层分片，见 DNS Flag Day 2020；无 EDNS 时为 512 字节）的 UDP 响应会在记录边界截断并置 TC 位，客户端可据此改用 TCP 重试；回答段、授权段都放得下、只是附加段放不下时不置 TC（RFC 2181 第 9 节）；回答里的 OPT 都通告 1232。
- TCP 上声明的消息超过 4096 字节时不等它发完，连接当场关掉，之前的查询照样答。回答超过 65535 字节、放不进一个 TCP 消息时回 SERVFAIL。
- 入站的 TCP 和 DoH 连接一共开到 512 条以后，新连接只给还没占满自己那一份的设备，流控开不开都一样：没开过连接的设备总连得上，一台设备开再多也只占到它那一份。接不了的连接当场关掉。
- 监听 `[::]` 时 IPv4 另开一个 `0.0.0.0`，`[::]` 那个只收 IPv6：IPv6 套接字收不收 IPv4 各系统默认不同（FreeBSD 等 BSD 不收，OpenBSD 怎么都不收），这样在哪个系统上两个地址族都答，UDP、TCP 和入站 DoH 都这样。IPv4 映射形式的客户端地址 `::ffff:a.b.c.d`，规则、GeoIP、ECS 和缓存都按它背后的 IPv4 地址判断，client_ip 照常写 IPv4 网段；写成 `::ffff:a.b.c.d/n` 的网段按它所指的 IPv4 网段处理。

只有设置 settings.bind_doh 后才会启用入站 DoH。启用时必须同时设置 settings.doh_tls_cert 和 settings.doh_tls_key，且路径指向 PEM 文件。路径默认为 /dns-query，可通过 settings.doh_path 修改。证书和私钥在启动时才读：读不了、或者 DoH 的端口绑不上时，DNS 照常答，入站 DoH 不开，日志里记一条错误，控制通道 `config` 结果的 `doh_error` 写着原因（DoH 起来了或没配时为 null）。配置校验和热重载只查写没写这两个路径，不读文件，写错的路径要到下次启动才看得出来。

入站 DoH 处理器：

- 支持 HTTP/2 和 HTTP/1.1：TLS 握手时客户端选了 h2 就用 HTTP/2，一条连接上最多同时处理 100 个请求；只会 HTTP/1.1 或不发 ALPN 的客户端照旧用 HTTP/1.1；
- 连接空闲 10 秒（没有请求在处理，也没有新请求来）就关闭，两种 HTTP 版本一样；HTTP/2 发了 GOAWAY 以后 10 秒还没关上就直接断开；
- 写回答 10 秒没有进展（客户端只发不读）就断开连接；
- 接收配置路径上的 POST 请求，并读取 DNS wire message 请求体；Content-Type 不是 application/dns-message 的回 415（RFC 8484 第 4.1 节）；
- 配置路径上别的方法回 405，Allow 头写着 GET, POST；别的路径回 404；
- 接收配置路径上的 GET 请求，并读取 dns 查询参数中的无填充 base64url 数据；
- 拒绝超过 4096 字节的查询（POST 的请求体回 413，GET 的 dns 参数解码后超长回 400），和 UDP、TCP 的上限一样；
- 和 UDP、TCP 一样只回答标准查询：opcode 不是 0 的请求回 NOTIMP，问题数不是 1 等的查询回 FORMERR（都是 200，只有请求头）；QR=1 的应答回 400；
- 成功处理后返回 application/dns-message；
- 查询带了 EDNS 填充（RFC 7830）时，回答也填充，补到 468 字节的整数倍（RFC 8467 第 4.1 节）；没带的不填充。UDP、TCP 监听器是明文传输，一律不填充（RFC 7830 第 6 节）。

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

upstream 支持字符串、逗号分隔字符串或 JSON 字符串数组。多个上游会并发查询并返回第一个可接受的响应；在多个上游选择时，SERVFAIL 和 REFUSED 响应不会被接受；被截断的响应（带 TC 位，TCP 也没取到完整的）先放着，别的上游都给不出完整响应时才返回它，客户端看到 TC 位会自己改用 TCP；两样都没有时，最先收到的失败响应仍会交给回答检查（见「Pipeline 和规则」）。

以下协议前缀会覆盖 transport 字段：

| 前缀 | 传输 | 别名 |
|---|---|---|
| udp:// | UDP | |
| tcp:// | TCP | |
| tcp+udp://、udp+tcp:// | TCP+UDP | |
| doh:// | DoH | https:// |
| dot:// | DoT | tls:// |
| doq:// | DoQ | quic:// |

没有协议前缀时，省略 transport 默认为 UDP。没有路径的 DoH URL 使用 /dns-query。DoH 支持使用 host 查询参数覆盖请求的 authority：HTTP/1.1 上是 Host 头，HTTP/2 上是 :authority（不另带 Host 头），连接和 TLS 仍按 URL 里的主机；带它的上游设了 `HTTPS_PROXY` / `ALL_PROXY` 时只用 HTTP/1.1。该参数不会继续发送给上游。DoH 只接受状态为成功、媒体类型为 application/dns-message、不超过 65535 字节的回答；跳转（3xx）不跟随，和其他错误状态一样算这个上游失败。

DoH 上游回 429 Too Many Requests 时不重试，也不计入 doh_health_check_error_threshold，这个上游从这时起暂停一会儿：秒数按 Retry-After，收进 1 到 60 秒；没写、写的是日期或读不懂时暂停 1 秒。暂停期间，几个上游一起问（一个 upstream 里写了几个，或一条规则写了几个 forward）时不问它，由别的上游作答；一组里全都在暂停时照常全问，只写了这一个上游的转发也照问。暂停开始时记一条 warn。

DoH 上游连不上（建连或 TLS、HTTP/2 握手失败，或者还在建连失败以后的退避里）时同样不重试，也不计入 doh_health_check_error_threshold：重建连接池是为了丢掉坏了的连接，这时没有连接可丢。在建好的连接上收发出错或者超时，才重试一次、计入它。

DoT 未提供端口时使用 853。可通过 sni 或 servername 查询参数设置 TLS 名称，不收别的参数，且 DoT 上游不能包含 DNS path。

DoQ 未提供端口时使用 853。可通过 sni/servername 和 0rtt/enable_0rtt 查询参数配置，不收别的参数；0rtt 的值写 true、false、1、0、yes、no、on 或 off。使用 IP 字面量的 DoQ 上游必须显式设置 SNI。0-RTT 默认全局启用，也可以按上游覆盖，上游写的 0rtt 优先，全局关着时也照它。恢复会话时 0-RTT 只发往上一次完整握手连上的那个地址，它排在最前、不论哪一族，连接当场可用，别的地址不再连；上游要在 500 毫秒内回握手（那次完整握手往返时间的三倍更长时照它），到时没回、QUIC 的空闲超时先到了、等在上面的查询先超时了，或者上游没回握手就关掉了连接（比如拒绝新连接），都是这个地址的事，不影响 0-RTT：忘掉这个地址（连接还开着就关掉），上面的查询在各自剩下的时限里换一条新连接重发，它完整握手、几个地址照常错开着连；来不及重发的，错误里写着这个地址，上游关掉连接的还写着上游给的原因。上游回了握手却不收早期数据，是拒绝了 0-RTT，会在进程重启前对该上游的所有连接禁用 0-RTT；上游回了握手以后超时、关掉连接都不算拒绝，不影响 0-RTT。

TCP、DoT、DoQ 上游和走 HTTP/2 的 DoH 上游，连接都在后台建，最多用 5 秒（解析名字和握手都算在内）：发起建连的查询先超时或被取消了（比如一起问的别的上游先答了），连接照样建完，留给下一个查询用；那个查询用之前先看它还通不通，上游这期间已经关掉的就重建一条。建连失败以后这个上游歇 250 毫秒再连，接连失败每次翻倍，最多 5 秒，从失败的那一刻算起；这期间转给它的查询当场失败，不再去连，错误里写着上一次为什么失败、多久以前。上游解析出几个地址时错开着连（RFC 8305）：两族交替，第一个地址那一族在前（DoQ 总是 IPv4 在前，发 0-RTT 的那个地址除外），一个地址 250 毫秒还没连上、或者连不上，就接着连下一个；TCP 连上了的，从那一刻起再给 TLS 握手 250 毫秒，下一个才连（DoQ 的握手算在连上之内），先握手完的那个用；连上一个地址包括它的握手（DoT、DoH 的 TLS 握手，DoQ 的握手），所以接下 TCP 连接却不回握手的地址也一样跳过。到 5 秒还没连上时，错误里写着连过的每个地址：失败了的写原因，还没连上地址的写多久没回应，连上了地址、握手没回的写连上用了多久、握手多久没回应。TCP、DoT 的连接在查询等回答时断了，而它是这次查询之前就有的、或者答过别的查询（上游答了一些就关掉），没答的查询换一条新连接重发一次（RFC 7766 第 6.2.1.1 节）；这次查询自己新建、一个也没答就断了的不重发。

上游的回答必须是这次查询的问题（名称不分大小写，类型和类别相同）才收：UDP、TCP、DoT 上对不上的回答丢掉，继续等真正的回答；DoH、DoQ 上一个查询只有一个回答，对不上就算这个上游失败。没有问题段、也不带任何记录的错误回答（有些上游这样回 FORMERR、NOTIMP）照收。

发给上游的查询一律带 AD 位（RFC 6840 第 5.7 节），验证型上游的回答因此都带着它验证的结论；交给客户端时，查询既没带 AD 也没带 DO 的，回答去掉 AD（第 5.8 节），所以客户端看到的 AD 不取决于谁先把缓存填上。签过名（TSIG）的查询原样发出。转交的回答一律去掉 AA 位：KixDNS 不是这些数据的权威，从缓存里取出的更不是。

经 DoT、DoH、DoQ 发给上游的查询带 EDNS 填充（RFC 7830），补到 128 字节的整数倍（RFC 8467 第 4.1 节）；不带 EDNS 的查询为此补一条 OPT（RFC 9250 第 5.4 节要求 DoQ 的每个查询都填充），这样的客户端拿到的回答照旧不带 OPT。UDP、TCP 上不填充（RFC 7830 第 6 节）。填充只属于一跳：客户端查询里的填充不转给上游，上游回答里的填充不进缓存、也不交给客户端（入站 DoH 按客户端的查询自己填充，见上）。签过名的查询原样发出。

UDP 转发失败或 UDP 响应被截断时，TCP fallback 默认启用，可通过 settings.enable_tcp_fallback 禁用。截断的应答改用 TCP 也拿不到完整应答时（比如上游的 TCP 被挡住），交回截断的那份，客户端看到 TC 位会自己改用 TCP。该 fallback 属于转发路径，不是额外监听器。

## 配置示例

### 基本路由和静态响应

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

上游回答交出去、写进缓存之前，每条记录的 TTL 先收进 min_ttl 到 cache_max_ttl 之间（两者冲突时以 cache_max_ttl 为准），客户端留一份回答的时间就和缓存一样长。DNS 响应缓存使用回答的最小 TTL，否定响应在存在 SOA 时使用 SOA 负缓存 TTL，同样收进这个范围，并受 cache_capacity 限制；带 CNAME 链的否定响应（NXDOMAIN，或 NOERROR 但答案里只有别名）也算否定响应，整份按链上记录的最小 TTL 和负缓存 TTL 中短的那个缓存；没有 SOA 的否定响应不缓存（RFC 2308 第 4 节）。失败不进缓存：SERVFAIL 不管从哪里来都不缓存，上游回的 REFUSED 和扩展 RCODE 带着记录也不缓存，一次瞬时的故障不会在缓存里留到条目到期；规则自己给出的静态应答（deny 的 REFUSED 也算）取决于上游的回答时进缓存，也就是回答检查的动作给出的，或者回答检查在上游的回答上 continue 以后的规则、跳去的 Pipeline（回答检查跳去的，或 continue 以后的规则跳去的）给出的：缓存了下次不必再问上游。它按自己带的 TTL 缓存，即记录里最小的（min_ttl 只抬上游回答的 TTL，不抬规则写的）；不带记录的（deny、static_response、问的类型没有记录时的 NODATA）没有自己的 TTL，按下面的上限缓存。回答检查以后缓存的应答，不论是规则给的静态应答，还是转发拿到的（回答检查的动作转发的，continue 以后的规则、跳去的 Pipeline 转发的），都不比这一路上回答检查依据过的每份上游回答里 TTL 最短的那个留得久，交出去的每条记录的 TTL 也不比它长（记录里最短的那个比它短时也一样，比如短 A 记录旁边的长 CNAME）：过了那么久上游可能答得不一样，回答检查也就可能走另一条路。依据过的回答的 TTL 和记录的一样收进 min_ttl 到 cache_max_ttl 之间，没有 SOA 的否定响应（它本身不进缓存）也按 min_ttl 算；min_ttl 为 0 时，那样的回答或 TTL 为 0 的回答之后的应答都不缓存。回答检查据过上游的回答以后，不论回答检查跳转，还是 continue 以后的规则跳转，跳过去得出的应答都缓存在据那份回答的 Pipeline 的键下，受上面的上限：那份回答的上游故障时有过期应答可交，客户端拿到的 TTL 也不比它长。规则直接给出的静态应答不进响应缓存（还没据过上游的回答时请求阶段跳进别的 Pipeline，在那里直接给出的也一样）：规则下次照样直接给出，查询日志和规则计数照样记在这条规则名下。上游失败（没有回答，或者回答检查看到上游回了 SERVFAIL、REFUSED 这样的失败应答）以后兜底给出的静态应答（miss 动作或回答检查的动作直接给的，或者它们 continue 以后的规则、跳去的 Pipeline 给的）只给这一次请求和同时在等它的请求，也不进缓存，上游恢复以后马上换回上游的回答；这时改问备用上游拿到的回答照常缓存（流控拦下的除外，见 flow_control_enabled），同样受上面的上限。相同的进行中缓存未命中会共享一次上游操作。

Pipeline 的应答可能因请求方而不同时，响应缓存、并发未命中去重和规则缓存会按规则对请求方的判定把它们分开，而不是按地址：客户端地址是否在各个 client_ip 网段内，是否为私有地址（geoip_private），GeoIP 国家或标签是否匹配（geoip_country），查询是否带 EDNS（edns_present、response_edns_present）。转发取自客户端的子网用来分开并发未命中的请求，缓存的应答则按 ECS 作用范围区分（见 ECS）。判定相同的请求方共用条目。Pipeline 的回答检查开始的响应跳转路径上的规则也算在内，因为请求在应答之前会运行它们。这条路径转发的是跳转前那次转发准备的包，连同 ECS；路径上回答动作里自己写了 ecs 的 forward 例外，照它从客户端发来的查询改写（见 ECS）。路径上得到的应答缓存在跳转前那个 Pipeline 的键下，同时等在这个键上的请求拿到的也是它，路径上的转发不再另外合并并发未命中；上面那种 forward 发出的子网也算进这个键，分开并发未命中的请求。规则缓存保存的是 Pipeline 自身规则的决策，因此只按该 Pipeline 的请求匹配器判定，开着 cache_background_refresh 也一样（后台刷新不读规则缓存）；求值时执行了 log 动作的决策不进规则缓存。规则不判定任何请求方信息的 Pipeline 照旧在所有客户端之间共享。后台刷新从同一个客户端地址重放请求，原请求带 EDNS、带客户端自己的 ECS 选项时也一样带上（不符合 RFC 7871 第 6 节的 ECS 选项不带），因此 Pipeline 选择、请求规则和发往上游的 ECS 都与那次请求相同。刷新得到的应答适用的请求方与被刷新的条目不同时（例如上游的作用范围变窄了），那个条目会被删掉，它的请求方各自重新查询。

启用 cache_background_refresh 后，接近过期的条目可以触发异步刷新。刷新和客户端请求一样执行规则，包括响应规则及其动作，结果到最后一次定下。上游给出应答时，规则得出的应答照常缓存，替换这个条目；它不缓存在这个条目下时（上游的应答按它的 TTL 不进缓存：TTL 为 0，或没有 SOA 的否定响应；不缓存的静态应答。回答检查跳转得到的、continue 之后经请求阶段的跳转得到的应答都缓存在这个条目下，照常替换它），条目会被删除，由下一个客户端请求自己执行规则。上游失败时（包括跳转目标的上游失败），刷新到此结束，on_miss 动作和后面的规则都不执行，条目保留。刷新以缓存从来不收的应答结束时同样算失败、条目保留：SERVFAIL（跳转超过上限、跳转目标不存在、静态 SERVFAIL 等）、被截断的应答、TSIG 签过的应答；日志里记为刷新失败。启用 serve_stale 后，可以返回过期条目，并使用 serve_stale_ttl 作为响应 TTL，同时受 serve_stale_expire_ttl 和 serve_stale_client_timeout_ms 限制。返回过期条目的同时发起一次刷新，把这个应答重新决定一遍；规则自己给出的应答（比如回答检查给出的静态应答）过期后也一样，上游恢复以后不会一直用下去。该客户端等待还会被本次请求 request_timeout_ms 的剩余预算截断，配得比请求预算还长也不会把过期应答拖过截止时刻。

主配置 watcher 使用按 Pipeline 划分的缓存命名空间重载有效 JSON。发生变化的 Pipeline 会立即停止访问旧配置产生的响应缓存、规则缓存和进行中请求；未变化的 Pipeline 会保留热缓存。会改变应答的全局设置（min_ttl、default_upstream、response_jump_limit、enable_tcp_fallback）一改，所有 Pipeline 的缓存命名空间都轮换；只决定怎样用缓存的设置（各个超时、serve_stale 系列、后台刷新系列）改了不轮换。Pipeline 的命名空间还算上它的回答检查跳转、continue 以后的规则跳转能到达的 Pipeline：那里得到的应答缓存在它的键下，跳转目标一改，这些应答也不再用。旧命名空间中的条目不会被同步删除，而是继续受现有缓存容量和 TTL 策略限制。包括后台刷新和响应阶段跳转在内，每个请求都会保持选择其缓存命名空间时的配置快照，因此重载前启动的任务只会写进它那份配置的命名空间，整体请求时限（request_timeout_ms）和里面各段等待也照这份配置算。无效的重载会保留旧配置，并在日志里记一条错误，默认日志级别也看得到。启动时先监控配置文件、再读它，内核启动这段时间里改的配置，起来以后照样重载。配置文件监控不了、或者只监控得上一部分时（比如监控数用完了），改了不会重载，面板保存的配置也不生效：日志里记一条错误，控制通道 `config` 结果的 `watch_error` 写着原因（监控着时为 null）。配置文件经符号链接改了指向、新的地方监控不上时也一样，又监控上了以后变回 null。

下面这些写法以前能加载，却会悄悄做成别的事：读不懂的上游地址（端口不对、UDP 上游不是 IP 地址、不认识的前缀如 `http://`、前缀后面又写了一个前缀如 `doh://http://…`、`dot://tcp://…`（DoH、DoT、DoQ 都不收，DoH 一律走 https）、DoT 和 DoQ 不读的查询参数（比如把 `sni` 写成 `sin`，以前悄悄忽略）和读不懂的 0rtt 值（以前照全局设置）、IP 字面量的 DoQ 没写 SNI）、拼错的 rcode（以前回 NXDOMAIN）、无效的静态 IP 或 CNAME 目标、装不进一条记录的 TXT（以前回 SERVFAIL）和一个字符串也没写的 TXT（`text: []`，以前编出 RDATA 为空的记录，客户端整个应答都读不了；空的 TXT 写成 `[""]`）、跳到不存在的 Pipeline（跳转动作或 pipeline_select），值写成空、因而对每个名字都成立的匹配器（domain_suffix（写成 `.` 也一样）、domain_regex、geo_site_not 和回答检查里对应的几种，以前匹配所有域名；prefix、regex 模式下值写成空的 response_txt_content 也一样，对每份带 TXT 记录的回答都成立），写成空的 domain_exact 和 request_domain_exact（只命中根名字，要的就是根时写成 `.`），同一条规则里几个 forward 的 ecs 写得不一样（以前一个也不发），几个 Pipeline 写了同一个 id（按 id 只找得到其中一个，其余的规则不会照写的执行），ecs 的 static 模式里不是 IP 的地址（以前每个查询记一条警告、不发 ECS），超过 1024 的连接池、超过 65536 的 dashmap_shards 和超过 64 的 response_jump_limit（启动时按上限用），以及内核不读的键：拼错的设置名，写错名字或层级的规则、Pipeline、pipeline_select 的键（比如把 `matchers` 写成 `matcher`，以前这条规则没有匹配器，匹配所有查询），动作、匹配器和 ecs 里拼错的或这一种不读的键（比如把 forward 的 `upstream` 写成 `upstrem`，以前问的是默认上游），按 `settings.min_tll`、`pipelines[0].rules[2].matcher`、`pipelines[0].rules[2].actions[0].upstrem` 这样的路径、按写的顺序报出来（那里拼错的必填字段照旧报解析错误）；已经删掉的旧设置（智能流控以前的五个数字、`prefetch`、从来数不到的 `tcp_health_check_error_threshold`、不再起作用的 `statistics_enabled` 和 `statistics_anonymize_client_ip`（排行照原样记客户端地址）、从来没被读过的 `geoip_auto_convert` 和 `geoip_filter_countries`）照常忽略，只记一条警告（见下一段）。启动时遇到它们在日志里记错误（默认日志级别也看得到）、照样加载（超过上限的设置按上限用），已经在用的配置升级以后照样起得来（控制通道 `config` 结果的 `problems` 也把它们列出来，每项最长 2048 个字符，重载成功以后清空）；热重载和控制通道的配置校验会拒绝，并一次列出全部问题（校验的 422 回答的 `error.problems`、重载被拒以后控制通道 `config` 结果的 `last_reload.problems` 每条一项，每项最长 2048 个字符；`error.message` 和 `last_reload.error` 是它们连成的一句，也截到 2048 个字符），所以下一次改配置时要把它们改掉。每条问题前面写着它在哪，写法和这些键的路径一样：`settings.doh_path`、`pipeline_select[0]`、`pipelines[1].rules[2]`，匹配器的写到 `pipelines[1].rules[2].response_matchers[0]`，都从 0 数。全局设置本身说不通时（比如 cache_capacity 写成 0、bind_udp 不是 IP 地址和端口），以及匹配器编译不了时（比如正则写错），启动、重载和校验都不收，错误同样开头写着设置和它的值或匹配器的位置，比如 `settings.bind_udp: "localhost:53" is not an IP address and port`。这些和上面的问题一样一次列全：重载和校验时连同问题一起，每条一项列在 `error.problems`、`last_reload.problems` 里，问题在前，接着是设置的，匹配器的在最后；启动时有它们内核就起不来，它们照同样的顺序连同问题连成一句写在那条错误里，和重载列出的一样。

还有一些写法照样加载、照写的做，却值得知道：上面这些退役的设置和 background_refresh_rule，值写成空、因而永远不命中的匹配器（一个国家代码也没写的 geoip_country 和 response_answer_ip_geoip_country，写成空的 geo_site、response_request_domain_geo_site、listener_label 和 upstream_equals，一个网段也没写的 response_upstream_ip 和 response_answer_ip），domain_regex 和 request_domain_regex 里不在 `(?i)` 下写成大写、因而永远不命中的部分（带大写字母的字面量，只取大写字母的字符类如 `[A-Z]`：规则看到的名字是小写的），大于 1000000 的 cache_capacity（可能占掉很多内存），不到 upstream_timeout_ms 两倍半的 request_timeout_ms（可能来不及重发和改用 TCP），没设 bootstrap 却有写成主机名的 TCP、DoT、DoH、DoQ 上游（系统的解析器要是 KixDNS 自己，解析会绕回来），绕成圈的 jump_to_pipeline（从一条规则跳过去，一路跳下去能回到它所在的 Pipeline，规则的跳转和回答动作的跳转都算，执行不到的不算：请求动作里作决定的那个之后的（log、replace_txt_response 不作决定），请求阶段不是 forward 的规则的回答动作，回答动作里作决定的那个之后的（log、forward 不作决定）；绕上的查询把能跳的次数跳满才回 SERVFAIL（请求阶段 response_jump_limit 次，回答动作头一次跳转起另算这么多次），回答阶段每跳一次还要再问一次上游，每个圈在合上它的那条规则报一次），规则用到、却没配可读的数据的 Geo 标签（没写 geosite_data_paths 时的 GeoSite 标签，没写 geoip_dat_path 时 MMDB 也答不了的 GeoIP 标签，也就是两个字母的国家代码以外的、或者连 geoip_db_path 也没写时的全部标签；这样的 geo_site、geoip_country 永远不命中，geo_site_not 永远命中）。它们不算上面的问题，启动、重载和校验都不拒绝：配置每生效一次各记一条警告，控制通道 `config` 结果的 `warnings` 列出当前配置里的这些写法，配置校验的回答也带着 `warnings`，每项最长 2048 个字符。每条警告和问题一样，开头写着它说的是哪个设置、匹配器或规则，比如 `settings.bootstrap`、`pipelines[0].rules[1].matchers[0]`、`pipelines[1].rules[0]`。

下面这些全局设置只在启动时读取，重载不会让它们生效，修改后要重启服务：`bind_udp`、`bind_tcp`、`bind_doh`、`doh_path`、`doh_tls_cert`、`doh_tls_key`、`cache_capacity`、`cache_max_ttl`、`dashmap_shards`、`udp_pool_size`、`tcp_pool_size`、`doh_pool_size`、`doh_health_check_error_threshold`、`dot_pool_size`、`doq_pool_size`、`tcp_connection_max_age_seconds`、`tcp_connection_idle_timeout_seconds`、`doq_connection_idle_timeout_seconds`、`doq_keepalive_interval_ms`、`doq_enable_0rtt`、`bootstrap` 和 `flow_control_enabled`。其余全局设置重载即生效。重载后，配置里改过、还在等重启的设置会出现在控制通道 `config` 结果的 `restart_pending` 里，日志里也记一条错误列出它们（默认日志级别也看得到）；改回启动时的值，或者重启以后，它就不再出现。重载时改这些设置不会让缓存作废。UDP worker 数量由命令行指定，同样只在启动时生效。DoH TLS 证书/私钥 PEM 文件续期后会热更新生效，但修改配置中的证书路径仍需重启。配置文件、证书和私钥、Geo 数据文件是符号链接时（比如 Kubernetes 的 ConfigMap、Secret 卷），链接指向的文件变了、路上哪个链接换了指向，都算文件变了，监控跟着新的指向走。这些文件写完才读：Linux 上等写的一方关上文件或者改名到位；别的平台等写入停下 0.3 秒；一直有人在写时最多等 2 秒也读一次。只改属性（chmod、chown）不算改动。监视漏了事件时（比如 Linux 上 inotify 的队列满了），所有监视着的文件都当改过、各读一次，并记一条错误。读出来不对（写坏了、半截文件）时留着正在用的，等文件下次改动。

重载后，配置里不再出现的上游会关闭它们的 TCP、DoT、DoQ 连接；正在使用这些连接的请求处理完之后才会关闭。

geosite_data_paths 中的 GeoSite 文件和 geoip_dat_path 指定的 GeoIP 文件会被监控，文件变了就重新读入；geoip_db_path 指定的 MMDB 不监控；热加载时 MMDB 文件没变（路径、大小、修改时间都一样）就沿用已经读入的那份，变了就重读，配置里的 GeoIP 设置没改也一样，读不了（不存在、正在替换、写坏了）时保留正在用的那份，等文件换了样子（路径、大小、修改时间有一样变了）以后的热加载再读，在那之前的热加载不重读它，用到 GeoIP 的 Pipeline 也不因此换缓存命名空间。GeoSite 的 `.dat` 只读入规则用到的标签，一个都没用到时既不读也不监控；GeoIP 数据只读入规则（geoip_country、response_answer_ip_geoip_country）用到的国家代码和标签（见上文 GeoIP 数据源与标签），不读的文件也不监控。热加载改变了规则用到的 GeoSite 或 GeoIP 标签，或这几个文件路径时，会按新配置重新读入 Geo 数据，并改为监控新的文件；新数据读完才替换旧数据，新规则从第一个请求起就用新数据。配置里写了、当时还不存在的文件也监控，出现了就读入，几个文件声明同一个标签时它照旧按配置里的先后算；它所在的目录也不存在时监控不了，出现以后的下一次热加载读入。被监控的文件重新读出来以后，规则用到的标签一个都没有了、而它此前提供过（比如下载失败留下的空文件），只有它提供的标签留着正在用的数据，等文件下次改动；别的文件也提供的标签改用那个文件里的，和全部重新读一遍一样。热加载重新读入时遇到这样的文件也一样：它此前提供、规则现在还用、别的文件又不提供的标签留着正在用的数据。这样留着的数据只在进程里，重启以后就没有了，所以这样的文件记一条错误，也列在下面的 `data_warnings` 里，说哪些标签留着先前的数据，文件改好、读进来以后跟着去掉。数据文件里写错的正则跳过，不匹配任何名字。规则用到、却没有一个 GeoSite 数据文件提供的标签会记一条告警，和 GeoIP 一样。配置了却不存在或读不了的 Geo 数据文件和 MMDB、装不上的监控各记一条错误，默认日志级别也看得到；控制通道 `config` 结果的 `data_warnings` 一样一句地列出 Geo 数据眼下的这些问题，连同规则用到却没有数据提供的标签（这样的 geo_site、geoip_country 永远不命中，geo_site_not 永远命中），文件改好、读进来以后跟着去掉，没有问题时为空。数据文件经符号链接指向监控不上的地方时（比如链接指向的目录还不存在），不管是启动时就这样，还是运行中路上哪个链接改了指向，也一样记一条错误、列在 `data_warnings` 里：那里的改动监控看不到，由下一次热加载读入，和所在目录不存在的文件一样；又处处监控上了以后这句话去掉。

Geo 数据换进来以后（文件变了重新读入，或热加载读入），哪个标签的数据换了样子，应答取决于这个标签的 Pipeline 就换一个缓存命名空间：规则按这个 GeoSite 名单判断请求域名（geo_site、response_request_domain_geo_site 等），或按这个 GeoIP 标签判断回答里的地址（response_answer_ip_geoip_country；有 MMDB 时两个字母的国家代码看 MMDB），回答检查跳转过去的、回答检查 continue 以后规则跳转过去的 Pipeline 用到的也算（还没据过上游的回答时请求阶段跳转过去的，应答缓存在目标 Pipeline 的键下，跟着目标换）。按旧数据缓存的应答和规则决定从此不再拿出来用，和热加载改了规则一样；没用到这个标签的 Pipeline 留着各自的缓存。数据换没换样子按内容算：热加载多用了一个标签、文件重写了一遍内容没变、文件只改了别的标签，读这个标签的 Pipeline 都不换。只按客户端地址判断 GeoIP 国家（geoip_country）的规则不必换：缓存本来就按这次判断的结果区分客户端，数据一换，判断结果跟着变。一个请求从头到尾按它开始时的那份 Geo 数据判断，选 Pipeline、缓存的键、规则和回答检查都是；数据在它路上换了，从下一个请求起才用新的。
