# Running

[简体中文](usage.md) | **English**

## Build and run

The repository uses Rust edition 2024. The project does not declare an MSRV; use a toolchain that supports edition 2024.

~~~bash
cargo build --release

# No subcommand: uses config/pipeline.json and the default listener label
./target/release/kixdns

# Explicit run command
./target/release/kixdns run -c config/pipeline.json
~~~

The default listener addresses are UDP and TCP on 0.0.0.0:5353. The default upstream is 1.1.1.1:53. All paths are passed to the filesystem as written; relative paths are relative to the process working directory.

The release profile sets opt-level = 3, lto = fat, codegen-units = 1, panic = abort, and strip = true.

The main dependencies include tokio, hickory-proto, serde, moka, dashmap, reqwest, tokio-rustls, quinn, maxminddb, notify, clap, and tracing. The exact versions are defined by Cargo.toml and Cargo.lock.

## Command line

~~~text
kixdns [COMMAND]

COMMANDS:
  run              Run the DNS server
  convert-geo-ip   Convert a GeoIP .dat file to MMDB
  help             Print help
~~~

Run options:

~~~text
-c, --config <FILE>             Configuration path (default: config/pipeline.json)
    --listener-label <LABEL>    Listener label used by pipeline selectors (default: default)
    --debug                     Enable debug-level logging
    --udp-workers <NUM>         UDP worker count (0 selects available CPU parallelism)
-h, --help                      Show help
-V, --version                   Show version
~~~

GeoIP conversion options:

~~~text
-i, --input <FILE>              Input V2Ray GeoIP .dat file
-o, --output <FILE>             Output MMDB file
-f, --filter <CODES>            Comma-separated country codes, for example CN,US,JP
~~~

Unix builds create separate UDP sockets for workers with the platform's reuse-port support. Non-Unix builds use one UDP socket shared by the workers. This is an implementation detail, not a throughput guarantee.

## Logs and response statistics

The logging subscriber is text formatted by default, with RFC 3339 timestamps following the system's local timezone. The default filter is error unless --debug or the RUST_LOG environment variable changes it. The code does not configure JSON log output.

For response statistics, enable `RUST_LOG=warn,kixdns::engine::phases=info`.
`event="dns_response"` records one answer produced by the engine,
including fast-path, fresh/stale cache, static and singleflight answers. It is
not proof of network delivery. Overload SERVFAILs sent directly by the listener
when its concurrency permits run out bypass the engine and are not recorded.
Internal background refreshes and intermediate forwarding attempts are excluded.
`cache_hit` is true only when the response cache supplied the answer. The old
`cache` field is removed: it meant "cacheable", and reusing the name would have
silently flipped its meaning. RCODE is read from the answer and omitted when the
answer does not parse as DNS. A failed or cancelled
request without an answer uses `event="dns_request_finished"` and `status`, with
no inferred RCODE. Singleflight followers use `upstream="inflight"` because the
shared result does not carry the leader's upstream identity.

Older logs lack `cache_hit`: their `cache=true` can mean a cacheable forwarded
answer, and some response paths were not logged. Do not combine them with new
logs to claim an accurate historical hit rate or complete request count.

## systemd

Create /etc/systemd/system/kixdns.service:

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

## Tests

~~~bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
~~~
