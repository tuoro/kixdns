# 运行

**简体中文** | [English](usage.en.md)

## 构建和运行

仓库使用 Rust edition 2024。项目没有声明 MSRV，请使用支持 edition 2024 的工具链。

~~~bash
cargo build --release

# 不带子命令：使用 config/pipeline.json 和默认 listener label
./target/release/kixdns

# 显式使用 run 子命令
./target/release/kixdns run -c config/pipeline.json
~~~

UDP 和 TCP 默认监听 0.0.0.0:5533，默认上游是 1.1.1.1:53。所有路径都会按原样传给文件系统；相对路径相对于进程工作目录。

Release profile 设置 opt-level = 3、lto = fat、codegen-units = 1、panic = abort 和 strip = true。

主要依赖包括 tokio、hickory-proto、serde、dashmap、reqwest、tokio-rustls、quinn、maxminddb、notify、clap 和 tracing；具体版本以 Cargo.toml 和 Cargo.lock 为准。

## 命令行

~~~text
kixdns [COMMAND]

COMMANDS:
  run              运行 DNS 服务器
  convert-geo-ip   将 GeoIP .dat 转换为 MMDB
  help             显示帮助

OPTIONS:
  -h, --help       显示帮助
  -V, --version    显示版本
~~~

run 选项：

~~~text
-c, --config <FILE>             配置路径（默认：config/pipeline.json）
    --listener-label <LABEL>    Pipeline 选择使用的监听器标签（默认：default）
    --debug                     启用 debug 级别日志
    --udp-workers <NUM>         UDP worker 数量（0 表示使用可用 CPU 并行度）
    --admin-socket <PATH>       面板用的本机控制通道（Unix socket）；不设时不开，Windows 上没有这个选项
-h, --help                      显示帮助
~~~

GeoIP 转换选项：

~~~text
-i, --input <FILE>              输入 V2Ray GeoIP .dat 文件
-o, --output <FILE>             输出 MMDB 文件
-f, --filter <CODES>            逗号分隔的国家代码，例如 CN,US,JP
~~~

转换和运行时读数据文件是同一套解析：地址里的主机位清掉，超过位宽的前缀按单个地址算，同一个国家的网段合并。输入也可以是 V2Ray 的 JSON 数据文件（扩展名不是 `.dat` 就按 JSON 读）。MMDB 里一个地址只有一个国家，所以只转两个字母的国家代码；PRIVATE、CLOUDFLARE 这类标签和国家的网段重叠，不转，运行时由 geoip_dat_path 指向的数据文件直接匹配。--filter 里写了这类标签会报错。

Linux 和 FreeBSD 上每个 UDP worker 一个 socket，内核把报文分给它们（Linux 的 SO_REUSEPORT、FreeBSD 的 SO_REUSEPORT_LB）；别的系统（macOS、OpenBSD、NetBSD、Windows）的内核不这样分，各绑一个只有一个收得到报文，所以 worker 共用一个 socket。UDP 端口被别的程序占着时启动失败，不和它共用。这是实现细节，不代表固定吞吐承诺。

## 日志和响应统计

日志订阅器默认输出文本。不接 journald 时（终端，或 OpenWrt 上 procd 写的日志文件）每行是 UTC 的 RFC 3339 时间（以 Z 结尾）、级别和消息；接 journald 时时间和优先级由 journald 记，行里的时间按系统本地时区。默认过滤级别是 error；--debug 或 RUST_LOG 环境变量可以改变它。代码没有配置 JSON 日志输出。

DoH 上游回 429 Too Many Requests 时，只在它开始暂停那一刻记一条 warn，写着上游、暂停秒数和是不是照 Retry-After 定的（见配置文档）；暂停中再回的 429，以及这期间没问它的转发，只在 debug 级别记录。

上游失败、请求超时、跳转超过上限（请求阶段规则的跳转和回答动作的跳转都记）、上游的回答对不上查询、入站 DoH 的 TLS 握手失败这类每个查询、每个报文都可能碰上的 warn，同一处 10 秒内只记第一条，其余的只数不记；每条都带 `skipped` 字段，是上一条以来这一处没记下的条数，0 就是一条没漏。说的是哪个上游的（上游失败、上游的回答对不上查询），每个上游各算各的：一个上游一直坏着，别的上游的失败照样记得上；请求超时则是每个监听器（UDP、TCP、DoH）各算各的，告警里带着超时的查询名和客户端地址。日志级别不到 warn 时（比如默认的 error）这些 warn 既不记也不数。

响应统计可启用 `RUST_LOG=warn,kixdns::engine::phases=info`。
`event="dns_response"` 对引擎产出的每个应答记录一次，覆盖快速路径、
新鲜/过期缓存、静态应答及并发合并应答；它不证明客户端已收到报文。
监听器在并发许可耗尽时直接返回的过载 SERVFAIL 不经过引擎，不计入此事件。
内部后台刷新和中间转发尝试也不计入。`cache_hit` 仅在响应缓存提供应答时为真；
旧的 `cache` 字段已移除，因为它曾表示“结果可缓存”，改名后含义会静默翻转。
RCODE 取自实际应答，应答无法解析为 DNS 时省略。
取消了、没有应答的请求使用 `event="dns_request_finished"` 和 `status`，不猜测 RCODE（以错误结束的请求回 SERVFAIL，照样记 `dns_response`）。
并发合并的跟随请求标为 `upstream="inflight"`，因为共享结果不携带原请求的上游身份。

旧日志没有 `cache_hit`，其中 `cache=true` 可能表示上游应答可缓存，部分响应路径也未记录。
不能把新旧日志混合后宣称得到准确的历史命中率或完整请求量。

## systemd

创建 /etc/systemd/system/kixdns.service：

~~~ini
[Unit]
Description=KixDNS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kixdns run -c /etc/kixdns/pipeline.json
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
~~~

~~~bash
sudo install -m 0755 target/release/kixdns /usr/local/bin/kixdns
sudo mkdir -p /etc/kixdns
sudo cp config/pipeline.json /etc/kixdns/
sudo systemctl daemon-reload
sudo systemctl enable --now kixdns
~~~

## 测试

~~~bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
~~~
