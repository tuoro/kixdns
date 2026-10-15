# KixDNS 面板用的内核

这个仓库是 [olicesx/kixdns](https://github.com/olicesx/kixdns) 的 fork，给 [KixDNS 面板](https://github.com/tuoro/kixdns-panel) 构建和发布内核。

`main` 是上游加上两类提交：

- **修复**：按给上游提 PR 的标准做，提给上游时从上游的 main 另切分支，原样提交。
- **只给面板用的**：查询排行、控制接口和指标（`src/panel.rs`、`src/panel_trace.rs`）、这个目录和发布流程。这些不提给上游，提交标题以 `panel:` 或 `ci:` 开头。

每个改动都先开 PR 到 `main`，检查和构建通过后用合并提交合进去。上游有新提交时，开 PR 把上游合进 `main`。

## 版本和发布

版本是发布那天的日期（北京时间）：`2026.10.13`；同一天的第二个版本是 `2026.10.13.2`。只有 `main` 有新提交时才发新版本，不会为了续期重新构建：Release 的附件不会过期。

只发布 `main` 的最新提交，同一个提交只发一次。重跑旧的运行、从别的分支手动触发，都只检查和构建，不发布。不要手动创建 Release，需要补发就重跑发布流程。这个仓库已经去掉了上游构建流程在 Release 上的触发，免得它往手动创建的 Release 上挂没有检查过的二进制。

推到 `main` 以后，`.github/workflows/panel-release.yml`：

1. 检查：格式、clippy、全部测试、依赖审计（漏洞、不健全、已撤回会挡住发布；无人维护和通知只报告）、`panel/dns_smoke.py` 运行契约冒烟。
2. 构建：Ubuntu 22.04 容器里构建 x86_64 和 arm64，GLIBC 不超过 2.35（`panel/verify-glibc-baseline.sh`）。
3. 发布：每个架构一个 zip，加一份 `manifest.json`，发成标签为版本号的 Release。说明里列出这一版带进的提交和每个文件的 SHA-256。

往 `main` 的 PR 只做检查和构建，不发布。每天北京时间 11:41（UTC 03:41）还会单独查一次依赖有没有新的安全公告；有就让那次运行失败，GitHub 会发邮件通知，修好后推到 `main` 会发出新版本。

## Release 里的文件

`kixdns-<版本>-linux-<架构>.zip` 解开是：

| 文件 | 内容 |
| --- | --- |
| `kixdns` | 内核二进制 |
| `KIXDNS_CAPABILITIES.json` | 内核支持的配置能力，即 `panel/capabilities.json` |
| `KIXDNS_SOURCE.json` | 来源：仓库、版本、提交、基于的上游提交、架构、控制协议版本 |
| `SHA256SUMS` | 上面三个文件的 SHA-256 |

`manifest.json` 记录版本、提交、基于的上游提交、控制协议版本、配置能力，以及每个 zip 的文件名、大小和 SHA-256。面板先读它，再下载对应架构的 zip。

运行中的内核在控制接口的健康信息里报 `release_version` 和 `release_commit`；本地构建这两项是 `null`。`upstream_commit` 是基于的上游提交。

`2026.10.13` 是在合进 `main` 之前从 `panel` 分支发的，它的来源文件记的是 `base_commit`（当时 fork 的 main），之后的版本记 `upstream_commit`。

## English summary

`main` is upstream plus fixes (held to upstream-PR standards and sent upstream from branches cut from upstream's main) plus panel-only code: the query rankings, the control socket and metrics, this directory and the release workflow. Every push to `main` is checked, built for x86_64 and arm64 (Ubuntu 22.04, GLIBC ≤ 2.35) and released under a date version in Beijing time (`2026.10.13`, then `2026.10.13.2` the same day), with one zip per architecture and a `manifest.json`. Only the tip of `main` is released, each commit once; a released binary reports `release_version` and `release_commit` in health. A daily run audits the dependencies.
