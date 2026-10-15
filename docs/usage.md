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

UDP 和 TCP 默认监听 0.0.0.0:5353，默认上游是 1.1.1.1:53。所有路径都会按原样传给文件系统；相对路径相对于进程工作目录。

Release profile 设置 opt-level = 3、lto = fat、codegen-units = 1、panic = abort 和 strip = true。

主要依赖包括 tokio、hickory-proto、serde、moka、dashmap、reqwest、tokio-rustls、quinn、maxminddb、notify、clap 和 tracing；具体版本以 Cargo.toml 和 Cargo.lock 为准。

## 命令行

~~~text
kixdns [COMMAND]

COMMANDS:
  run              运行 DNS 服务器
  convert-geo-ip   将 GeoIP .dat 转换为 MMDB
  help             显示帮助
~~~

run 选项：

~~~text
-c, --config <FILE>             配置路径（默认：config/pipeline.json）
    --listener-label <LABEL>    Pipeline 选择使用的监听器标签（默认：default）
    --debug                     启用 debug 级别日志
    --udp-workers <NUM>         UDP worker 数量（0 表示使用可用 CPU 并行度）
-h, --help                      显示帮助
-V, --version                   显示版本
~~~

GeoIP 转换选项：

~~~text
-i, --input <FILE>              输入 V2Ray GeoIP .dat 文件
-o, --output <FILE>             输出 MMDB 文件
-f, --filter <CODES>            逗号分隔的国家代码，例如 CN,US,JP
~~~

Unix 构建会为 UDP worker 创建独立 socket，并使用平台提供的 reuse-port 能力；非 Unix 构建使用由多个 worker 共享的 UDP socket。这是实现细节，不代表固定吞吐承诺。

## 日志和响应统计

日志订阅器默认输出文本，时间戳使用 RFC 3339 格式并跟随系统本地时区。默认过滤级别是 error；--debug 或 RUST_LOG 环境变量可以改变它。代码没有配置 JSON 日志输出。

响应统计可启用 `RUST_LOG=warn,kixdns::engine::phases=info`。
`event="dns_response"` 对引擎产出的每个应答记录一次，覆盖快速路径、
新鲜/过期缓存、静态应答及并发合并应答；它不证明客户端已收到报文。
监听器在并发许可耗尽时直接返回的过载 SERVFAIL 不经过引擎，不计入此事件。
内部后台刷新和中间转发尝试也不计入。`cache_hit` 仅在响应缓存提供应答时为真；
旧的 `cache` 字段已移除，因为它曾表示“结果可缓存”，改名后含义会静默翻转。
RCODE 取自实际应答，应答无法解析为 DNS 时省略。
失败或取消且没有应答的请求使用 `event="dns_request_finished"` 和 `status`，不猜测 RCODE。
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
