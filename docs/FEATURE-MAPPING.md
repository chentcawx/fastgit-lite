# 功能对应表：FastGithub 2.1.5 (C#) → fastgithub-rs (Rust / Windows 10 x86)

本表是 `docs/ANALYSIS.md` 与 `docs/ANALYSIS-craft-anything.md` 之间的**可执行对照物**：
左列是原项目里承担该行为的类 / 方法 / 配置，右列是 Rust 项目里承担同一行为的模块 / 函数。
证据编号见文末「证据索引」，与 craft-anything 报告中的 `ev_…` 一一对应。

## 0-bis. r2 修订新增的 MITM 映射（2026-11-12）

默认模式改为 `Silent.Mode=mitm`。新增模块与对应原 C# 行为：

| 原 C# 类 / 方法 | Rust 模块 / 函数 | 等价度 |
| --- | --- | --- |
| `CertService` / `CertGenerator`（10 年 CA / 1 年叶证书 / `cacert/`） | `certs.rs::CertAuthority::load` / `generate_ca` / `issue` | ✅ 机制一致（rcgen 运行时生成，按 host 缓存） |
| `CaCertInstallerOfWindows`（`LocalMachine\Root`） | `scripts/install-ca.ps1` | 🔁 改为**显式一次性脚本**，默认 CurrentUser\Root 无需 UAC；进程运行时不写证书库 |
| `KestrelServerExtensions.UseTls()` / 自签叶证书 TLS 终止 | `tls.rs::server_stream` + `certs.rs::DynamicResolver`（按 SNI 选证书） | ✅ 等价 |
| `HttpClientHandler.TargetHost` / `RemoteCertificateValidationCallback` | `tls_sni.rs::upstream_sni` + `tls.rs::client_stream` / `NoCertificateVerification` | ✅ 等价（`TlsSni=false` → `ServerName::IpAddress` → 不发 SNI） |
| `HttpReverseProxyMiddleware`（`Destination` 路径前缀 / `Response` 短路） | `proxy.rs::mitm_serve` / `mitm_forward` / `forward_over` | ✅ r2 起 HTTPS 路径也完整支持 |
| `TunnelMiddleware` | `proxy.rs::handle_connect_mitm` | 🔁 CONNECT 后不再字节泵，而是终止 TLS 并解析 HTTP |
| `FlowAnalyzer` | `stats.rs::on_flow`（`forward_over` 双向计数） | ✅ |

> **关键更正**：r1 的「TLS 透传 + ClientHello SNI 改写」在密码学上不成立（transcript hash 覆盖 ClientHello），
> 见 `COMPATIBILITY.md` C-12。`proxy` 模式保留但只做字节级原样转发，不控制 SNI；`tls_sni.rs::rewrite_client_hello`
> 及相关测试保留为wire codec 工具，不再用于生产转发路径。

---

## 0-quater. r3 增量能力映射（2026-11-12）

本组是 Rust 版在 r2 之后按实测反馈新增的能力，**原 C# 项目无对应实现**，用 🆕 标记。

| 需求 / 现象 | Rust 实现位置 | 说明 |
| --- | --- | --- |
| LAN 共享：主代理绑定可配 | `config.rs::SilentOptions.proxy_bind`、`servers.rs::resolve_proxy_bind` | 默认 `127.0.0.1`；`0.0.0.0` / 具体 LAN IP 显式开启，非法值回退 loopback（2 项单测） |
| LAN 共享：PAC 不能把客户端指向自己 | `proxy.rs::pac_authority` / `format_proxy_authority` | 按 `local_addr()` 动态回显；通配地址收敛为 `127.0.0.1`（2 项单测） |
| LAN 客户端只导入公钥证书 | `scripts/install-ca.ps1 -CerPath` | 只分发 `.cer`，绝不分发 `.key` |
| CA 重新生成 / 轮换 | `main.rs`（`regen-ca` / `renew-ca`）、`platform.rs::parse_args`、`certs.rs::regenerate`、`scripts/regen-ca.ps1` | 旧 CA 备份到 `cacert\backup-<timestamp>\`；脚本完成停实例 → 轮换 → 卸载旧 CA → 导入新 CA → 重启 |
| GitHub Releases 侧栏骨架屏不消失 | `proxy.rs::mitm_forward` / `last_good_upstreams` | TCP 或 TLS 失败换下一个测速优选 IP（≤3）、优先复用上次成功 IP、单候选 IP 立即重试一次；`appsettings.github.json` 全系 `TlsSni: false` |
| 广告过滤 | `config.rs::AdBlockOptions` / `parse_ad_domains` / `Config::is_ad_domain`、`config/ad-domains.txt`、`proxy.rs::build_pac` + HTTP / MITM / CONNECT 三处短路 | 清单支持域名 / 通配 / `\|\|host^` / hosts 格式，2 秒热加载；命中域名同时写入 PAC |
| 完整请求体转发 | `proxy.rs::read_body` / `decode_chunked`、`build_http_request(..., complete_body)`、`mitm_serve` | MITM 单向泵必须先读满 body 再重建请求；支持 `Content-Length` / `chunked` → 精确 `Content-Length` / 本地应答 `Expect: 100-continue`；明文 `forward_http` 走双向 `relay` 不受影响（5 项单测） |
| 浏览器 UA 原样透传 + 标准 `Via` 防自环 | `proxy.rs::is_forward_loop` / `build_http_request`、`VIA_VALUE` | 原 C# 用 `User-Agent: FastGithub/1.0` 防自环；r5 改为 `Via: 1.1 fastgithub`（RFC 7230），UA 逐字节原样，仅无 UA 时补 tag；仍识别旧 UA 标记（3 项单测） |
| OAuth 授权链路可诊断 | `.workbuddy/tmp/oauth-chain-probe.py`、`pac-eval.js`、`docs/OAUTH-ASSESSMENT.md` | 本地 HTTPS stub 复现 GET → POST 表单 → 302 + Set-Cookie；确认代理侧无缺陷，回调后的服务端换 token 不在本机链路内 |

> 配置与清单文件在 `scripts/build-x86.cmd` 中一并装配进 `dist\config\`。详见 `README.md` 第 3.3–3.5 节与 `COMPATIBILITY.md` C-15~C-17。

---

## 0. 等价度定义

| 标记 | 含义 |
| --- | --- |
| ✅ 等价 | 输入、输出、默认值、边界行为一致（含已通过的单元测试） |
| 🟡 近似 | 主要行为一致，但实现机制不同或存在可枚举的边界差异 |
| 🔁 替代 | 有意用不同机制达成相同目标，差异登记在 `docs/COMPATIBILITY.md` |
| ❌ 不实现 | 与「x86 + 静默后台 + 无系统状态修改」硬约束冲突，明确移除 |

结论概览：**四大核心能力（纯净 IP 解析、IP 测速选优、TLS 连接自定义、CDN 替换）均有对应实现**；
被移除的是「系统级透明劫持」「HTTPS 解密」「UI / 外部进程 / 系统状态写入」这几类基础设施，而非业务能力本身。

---

## 1. 子系统总览

| # | 原项目子系统 | 主要源文件 | Rust 模块 | 等价度 |
| --- | --- | --- | --- | --- |
| 1 | 宿主 / 启动 / 单实例 | `FastGithub/Program.cs`、`ServiceExtensions.cs`、`Startup.cs` | `main.rs`、`platform.rs`、`service.rs`、`servers.rs` | 🟡 |
| 2 | 配置与域名策略 | `FastGithub.Configuration/*` | `config.rs` | ✅ |
| 3 | 纯净 DNS 解析 / IP 测速 | `FastGithub.DomainResolve/*` | `resolver.rs`、`dns.rs` | 🟡 |
| 4 | DNS 包拦截 | `FastGithub.PacketIntercept/Dns/*` | `servers.rs::spawn_dns_listener`、`dns.rs::build_loopback_response` | 🔁 |
| 5 | HTTP 正向代理 / CONNECT / PAC | `FastGithub.HttpServer/HttpMiddlewares/*` | `proxy.rs` | 🟡 |
| 6 | HTTP/HTTPS 反向代理与 Destination / Response | `HttpReverseProxyMiddleware.cs` | `proxy.rs::handle_http_connection`、`handle_https_passthrough` | 🟡 |
| 7 | TLS / SNI / 证书 | `Certs/*`、`FastGithub.Http/HttpClientHandler.cs` | `tls_sni.rs` | 🔁 |
| 8 | SSH / git 协议反向代理 | `TcpMiddlewares/*ReverseProxyHandler.cs` | `proxy.rs::handle_tcp_reverse` | ✅ |
| 9 | 流量统计 | `FastGithub.FlowAnalyze/*` | `stats.rs` | ✅ |
| 10 | 日志 | `Serilog` Console / File / UDP sinks | `logger.rs` | 🟡（无 Console sink，刻意） |
| 11 | Windows 服务 | `Microsoft.Extensions.Hosting.WindowsServices` | `service.rs`（原生 SCM） | 🟡 |
| 12 | WPF UI / 外部进程 / 系统状态 | `FastGithub.UI/*`、`HostsConflictSolver.cs`、`ProxyConflictSolver.cs`、`DnscryptProxy.cs` | — | ❌ |

---

## 2. 逐项功能对应

### 2.1 启动、生命周期与静默

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| 工作目录切到 exe 所在目录 | `Program.cs` (`Environment.CurrentDirectory`) | `main.rs::main` / `run_app` 中 `set_current_dir(platform::exe_dir())` | ✅ | 保证 `config/` 相对路径可用 |
| `ConsoleUtil.DisableQuickEdit()` | `ConsoleUtil.cs` | 不需要 | ❌ | GUI 子系统进程根本没有控制台，无需关闭 QuickEdit |
| `Global\FastGithub` 单实例互斥，重复启动退出 | `ServiceExtensions.cs` | `platform.rs::acquire_singleton` (`CreateMutexW` + `ERROR_ALREADY_EXISTS=183`) | ✅ | 名称与行为一致；重复启动静默退出并写日志 |
| `ParentProcessId` 父进程退出后停机 | `AppOptions.cs` / `AppHostedService.cs` | `platform.rs::parent_exited` + `main.rs::run_app` 500ms 轮询 | ✅ | `OpenProcess(SYNCHRONIZE)` + `WaitForSingleObject(...,0)` |
| `UdpLoggerPort` 参数 | `AppOptions.cs` / UI 启动参数 | `platform.rs::parse_args` → `logger::init` / `logger::configure` | ✅ | 兼容 `Key=Value` 命令行形式 |
| 任意 `Key=Value` 配置覆盖 | .NET `AddCommandLine` | `platform.rs::Cli::overrides` → `config.rs::apply_overrides` | 🟡 | 支持点分路径；不覆盖 .NET 环境变量/多配置源的全部语义 |
| `start` / `stop` 服务管理 | `ServiceExtensions.cs` | `service.rs::handle_command` | 🟡 | 原生 `CreateServiceW`/`StartServiceW`/`ControlService`/`DeleteService` |
| Windows 服务会话（Session 0） | `UseWindowsService()` | `service.rs::maybe_run_as_service` → `StartServiceCtrlDispatcherW` | 🟡 | 不会自动安装服务，必须显式 `start` |
| Linux systemd | `UseSystemd()` | — | ❌ | 交付目标仅为 Windows 10 x86 |
| `requireAdministrator` manifest | `FastGithub/app.manifest` | `resources/app.manifest` → `asInvoker` | 🔁 | 见 `COMPATIBILITY.md` C-01 |
| 控制台 / 弹窗 / 交互 | Console sink、WPF UI | 全代码无 `println!`/`eprintln!`/`MessageBox`/stdin | 🔁 | 见 `COMPATIBILITY.md` C-02 |

### 2.2 配置与域名策略

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| 读取 `appsettings.json` | `AddConfiguration()` | `config.rs::ConfigStore::load` | ✅ | UTF-8 BOM 兼容 |
| 读取 `appsettings/appsettings.*.json` 共 9 个文件 | 同上 | `ConfigStore::load` 合并 `DomainConfigs` | ✅ | 文件逐字复制自原项目 |
| 支持 `//` 与 `/* */` JSON 注释 | `JsonConfigurationProvider` (JsonCommentHandling.Skip) | `config.rs::strip_json_comments` | ✅ | 单测 `comment_stripping_keeps_strings` 保证 URL 内 `//` 不被误删 |
| PascalCase 键 `HttpProxyPort` / `FallbackDns` / `DomainConfigs` | `FastGithubOptions.cs` | `config.rs::FastGithubOptions` `#[serde(rename=…)]` | ✅ | 默认值 38457 与三组回退 DNS 一致 |
| `DomainConfig` 七字段 | `DomainConfig.cs` | `config.rs::DomainConfig` | ✅ | `TlsSni` 默认 `false` 与 C# record 默认一致 |
| `Response` 子对象 | `ResponseConfig.cs` | `config.rs::ResponseConfig::normalized` | ✅ | 状态码 0→200、空 ContentType→`text/plain;charset=utf-8` |
| `DomainPattern`：`*` 匹配除 `.` 外 0..N 字符、大小写不敏感 | `DomainPattern.cs` 正则 `^[^\.]*…$` | `config.rs::DomainPattern::is_match` + `wildcard_match` | ✅ | 单测覆盖通配、大小写、分段数、裸域不匹配 |
| `DomainPattern.CompareTo`：分段数升序、从右向左、`*` 视为 `char.MaxValue` | `DomainPattern.cs::Compare` | `impl Ord for DomainPattern` + `segment_key` (`U+FFFF`) | ✅ | 单测 `exact_pattern_wins_over_wildcard` |
| 未配置但被劫持域名使用 `TlsSni=true` 默认配置 | `HttpReverseProxyMiddleware.cs` | `config.rs::DomainConfig::default_for_unconfigured` | ✅ | 单测 `sni_policy_matches_original_defaults` |
| 配置文件热重载 | .NET `reloadOnChange` | `config.rs::ConfigStore::start_watcher` / `check_reload` | 🟡 | 2 秒轮询；与原版一样，新增/删除子配置文件需重启 |
| `Timeout` 解析 `"00:02:00"` | `DomainConfig.cs` (`TimeSpan`) | `config.rs::DomainConfig::timeout_duration` | ✅ | 非法值回退到 `ConnectTimeoutSecs` |
| `Destination` 绝对/相对 Uri 解析 | `HttpReverseProxyMiddleware.cs` | `config.rs::resolve_destination` | ✅ | 单测 `destination_resolution` 覆盖 `https://gapis.geekzu.org/ajax/` |
| `FastGithub.Silent` 段 | — | `config.rs::SilentOptions` | ➕ 新增 | Rust 独有；原 .NET 程序忽略此段 |

### 2.3 DNS 与 IP 选优

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| 回退 DNS `8.8.8.8:53` / `119.29.29.29:53` / `114.114.114.114:53` | `appsettings.json` | `config.rs::FastGithubOptions::default`；`resolver.rs::lookup` | ✅ | |
| 先探测 TCP:53 可用性再查询 | `DnsClient.cs` | `resolver.rs` (`DNS_PROBE_TIMEOUT=2s`) | ✅ | |
| 自建 DNS wire 查询 A / AAAA | `DNS` NuGet 7.0.0 | `dns.rs::build_query` / `parse_response` / `query` | ✅ | 纯 Rust 编解码，无第三方 DNS crate；单测 `query_roundtrip` |
| TCP:53 framed DNS + UDP DNS | `DnsClient.cs` | `dns.rs::query` (UDP) 与 `resolver.rs` TCP 路径 | 🟡 | UDP 优先，TCP 用于探测/回退 |
| 查询超时 4s | `DnsClient.cs` | `DNS_QUERY_TIMEOUT=4s` | ✅ | |
| 剔除回环解析结果 | `DnsClient.cs` | `dns.rs::parse_response` 中 `ip.is_loopback()` 过滤 | ✅ | 单测 `response_parser_extracts_a_record_and_rejects_loopback` |
| TTL 缓存下限 30s / 上限 10min | `DnsClient.cs` | `MIN_TTL=30s` / `MAX_TTL=600s` | ✅ | |
| 按 TCP 建连时延排序（5s 超时） | `IPAddressService.cs` | `resolver.rs::rank` + `CONNECT_TIMEOUT=5s` + `latency` 缓存 300s | ✅ | |
| 最快 IP 列表持久化 `dnsendpoints.json` | `PersistenceService.cs` | `resolver.rs::note` / `persist` / `read_endpoints` | ✅ | |
| 1s 周期测速循环 | `DomainResolveHostedService.cs` | `resolver.rs::start`（`SpeedTestIntervalSecs`） | ✅ | |
| `IPAddress` 固定上游 IP | `DomainConfig.cs` | `resolver.rs::resolve(pinned)` → 直接返回单元素列表 | ✅ | |
| `dnscrypt-proxy` 外部进程（5533 起） | `DnscryptProxy.cs` | — | ❌ | 见 `COMPATIBILITY.md` C-06 |
| 系统解析回退 | `Dns.GetHostAddresses` | `resolver.rs::Resolver::system_resolve` | ✅ | 未命中 DomainConfigs 的域名走系统解析器 |

### 2.4 DNS 拦截与端口接管

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| 过滤 `UDP.DstPort == 53` | `DnsInterceptor.cs` (WinDivert filter) | 直接绑定 `127.0.0.1:53` | 🔁 | 需一次性把系统 DNS 指向 `127.0.0.1`，见 C-03 |
| 命中域名伪造 A → `127.0.0.1`、AAAA → `::1` | `DnsInterceptor.cs` | `dns.rs::build_loopback_response` + `servers.rs::spawn_dns_listener` | ✅ | 压缩指针 `0xC00C`、TTL 300s；单测 `loopback_response_contains_127_0_0_1` |
| TTL 5 分钟 | `DnsInterceptor.ttl` | `servers.rs` 常量 `300` | ✅ | |
| 未命中查询转发上游 / SERVFAIL | WinDivert 直接放行 | `spawn_dns_listener` 转发给 `FallbackDns`，失败返回 `0x8182` | 🟡 | 行为结果一致，机制不同 |
| loopback TCP 端口改写 80/443/22/9418 → 动态端口 | `TcpInterceptor.cs` | 直接绑定这些端口（`servers.rs::bind_from`，冲突时向后扫 128 个端口） | 🔁 | 见 C-04 |
| `GlobalListener` 选择可用端口 | `GlobalListener.cs` | `servers.rs::bind_from` | ✅ | Windows 起 80/443/22/9418 |
| 非 Windows 端口 3880/38443 | `GlobalListener.cs` | — | ❌ | 仅 Windows 交付 |

### 2.5 HTTP / 代理 / TLS

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| HTTP 正向代理 38457 | `Startup.cs` `ListenHttpProxy` | `servers.rs::start_all` | ✅ | 端口占用时记 error 并跳过 |
| `CONNECT host:port` 隧道 | `TunnelMiddleware.cs` | `proxy.rs::handle_connect` | ✅ | 返回 `200 Connection Established` 后双向 relay |
| 绝对形式 HTTP 请求转发 | Yarp | `proxy.rs::forward_http` | ✅ | 重建请求行、注入 `Host`、过滤 hop-by-hop 头 |
| hop-by-hop 头过滤 | Yarp | `forward_http` 中的 `hop` 列表 | ✅ | connection / proxy-* / keep-alive / transfer-encoding / te / trailer / upgrade / host |
| `User-Agent: FastGithub/1.0` 防自环 | `FastGithub.Http/HttpClient.cs` | `proxy.rs::USER_AGENT_TAG` + 入口检测 + 出站追加 | ✅ | 命中标记返回 502 |
| 禁止 Proxy / Cookie / Redirect / 自动解压 | `HttpClientHandler.cs` | 无出站 HTTP 客户端库，天然不存在 | ✅ | |
| 出站连接 10s 超时 | `HttpClientHandler.cs` | `config.rs::Config::connect_timeout`（`ConnectTimeoutSecs=10`） | ✅ | |
| 逐个 IP 尝试连接 | `HttpClientHandler.cs` | `resolver.rs::connect_first` | ✅ | |
| `Destination` CDN 替换 | `HttpReverseProxyMiddleware.cs` | `proxy.rs::mitm_serve` / `mitm_forward` / `handle_http_connection` | ✅ | r2 MITM 下 HTTP 与 HTTPS 均支持完整路径前缀改写；见 0-bis |
| `Response` 直接响应（短路） | `HttpReverseProxyMiddleware.cs` | `proxy.rs::mitm_serve` / `handle_http_connection` 中 `domain_config.response` 分支 | ✅ | r2 起 HTTPS 路径同样支持；见 0-bis |
| `/proxy.pac` 自动生成 | `HttpServer` | `proxy.rs::build_pac` + `handle_http_connection` | ✅ | 按 DomainPattern 生成 `shExpMatch` 规则 |
| `/flowStatistics` JSON | `FlowAnalyze/*` | `stats.rs::json` + `handle_http_connection` | ✅ | 5 秒窗口，`totalRead/totalWrite/readRate/writeRate` |
| HTTP 反向代理（80） | `ListenHttpReverseProxy` | `servers.rs` + `handle_http_connection(reverse=true)` | ✅ | |
| HTTPS 监听（443） | `ListenHttpsReverseProxy` | `servers.rs` + `proxy.rs::handle_https_passthrough`（按 `Silent.Mode` 分派 MITM / 透传） | ✅ | 默认 MITM 终止 TLS；`proxy` 模式字节级透传，见 C-05 / C-12 |
| 自签 CA（10 年）+ 叶证书（1 年，SAN） | `CertService.cs` / `CertGenerator.cs` | `certs.rs::CertAuthority::load` / `generate_ca` / `issue` | ✅ | r2 恢复，按 SNI 动态签发并缓存；见 0-bis |
| 安装 CA 到 `LocalMachine\Root` | `CaCertInstallerOfWindows.cs` | `scripts/install-ca.ps1` | 🔁 | 显式一次性脚本，默认 `CurrentUser\Root` 无需 UAC；`-Machine` 可写全机；见 C-13 |
| `TargetHost` 控制 SNI、`@domain/@ipaddress/@random` | `HttpClientHandler.cs` / `TlsSniPattern.cs` | `tls_sni.rs::upstream_sni` + `tls.rs::client_stream` | ✅ | r2 由自身独立出站握手控制 SNI；`rewrite_client_hello` 仅保留为 wire codec 工具，不用于生产（C-12） |
| `TlsSni=false` 不发送 SNI | 同上 | `tls.rs::client_stream` 使用 `ServerName::IpAddress` | ✅ | 独立握手，不改动浏览器 ClientHello；实测 github 200（M7） |
| `TlsIgnoreNameMismatch` 放宽证书校验 | `RemoteCertificateValidationCallback` | `tls.rs::NoCertificateVerification` | ✅ | r2 MITM 出站恒定跳过校验；见 C-08 / C-14 |
| `github.com:22` SSH 反向代理 | `GithubSshReverseProxyHandler.cs` | `proxy.rs::handle_tcp_reverse(stream, state, "github.com", 22)` | ✅ | |
| `github.com:9418` git 协议反向代理 | `GithubGitReverseProxyHandler.cs` | `proxy.rs::handle_tcp_reverse(..., 9418)` | ✅ | |
| 双向字节泵与统计 | Yarp / `FlowAnalyzer` | `proxy.rs::relay` / `copy_loop` + `stats.rs::on_flow` | ✅ | 每连接双线程，16 KiB 缓冲；首包只在 `copy_loop` 计一次 |
| 本地直接响应的流量计量 | `FlowAnalyze` 中间件包住整条管线 | `proxy.rs::respond` / `send_response_is_ok` → `stats.rs::on_flow(true, n)` | ✅ | PAC、`Response`、502、CONNECT 200 均计入；冒烟实测非转发流量下 `/flowStatistics` 返回 `totalRead=4219` |

### 2.6 日志、系统状态与 UI

| 原项目行为 | 位置 | Rust 实现 | 等价度 | 说明 |
| --- | --- | --- | --- | --- |
| Console sink | `Serilog` | — | ❌ | 静默要求，见 C-02 |
| File sink（按天滚动） | `Serilog` | `logger.rs` → `logs/log-YYYY-MM-DD.txt` | ✅ | 级别 Debug/Information/Warning/Error |
| UDP sink（JSON） | `Serilog.Sinks.Udp` | `logger.rs` → `127.0.0.1:<UdpLoggerPort>` | 🟡 | 保留槽位，外部观察器可接入 |
| 注释 hosts 冲突行 | `HostsConflictSolver.cs` | — | ❌ | 见 C-07 |
| 写 HKCU `ProxyOverride` + `InternetSetOption` | `ProxyConflictSolver.cs` | — | ❌ | 见 C-07 |
| `git config --global http.sslverify false` | `GitConfigSslverify` | — | ❌ | 见 C-07 |
| `DnsFlushResolverCache()` | `PacketIntercept` | `platform.rs::flush_dns_cache`（保留 API，不自动调用） | 🟡 | 见 C-07 |
| 安装/卸载 dnscrypt-proxy Windows 服务 | `DnscryptProxy.cs` | — | ❌ | 见 C-06 |
| WPF UI + UDP 日志展示 | `FastGithub.UI/*` | — | ❌ | 见 C-02 |
| `CreateNoWindow=true` 启动主程序 | `FastGithub.UI/Program.cs` | 不需要：主程序本身即 GUI 子系统 | ✅ | |

---

## 3. 配置项对应表

| 原配置键 | 类型 / 默认 | Rust 字段 | 兼容 |
| --- | --- | --- | --- |
| `FastGithub.HttpProxyPort` | `int` / `38457` | `FastGithubOptions::http_proxy_port` | ✅ |
| `FastGithub.FallbackDns` | `IPEndPoint[]` | `FastGithubOptions::fallback_dns` | ✅ |
| `FastGithub.DomainConfigs` | `Dictionary<string, DomainConfig>` | `FastGithubOptions::domain_configs` | ✅ |
| `DomainConfig.TlsSni` | `bool` / `false` | `DomainConfig::tls_sni` | ✅ |
| `DomainConfig.TlsSniPattern` | `string?` | `DomainConfig::tls_sni_pattern` | ✅ |
| `DomainConfig.TlsIgnoreNameMismatch` | `bool` / `false` | `DomainConfig::tls_ignore_name_mismatch` | 🟡 r2 MITM 下恒定生效（出站跳过全部校验），字段不再起开关作用，见 C-08 |
| `DomainConfig.IPAddress` | `IPAddress?` | `DomainConfig::ip_address` | ✅ |
| `DomainConfig.Timeout` | `TimeSpan?` (`"00:02:00"`) | `DomainConfig::timeout` | ✅ |
| `DomainConfig.Destination` | `Uri?` | `DomainConfig::destination` | ✅ r2 MITM 下 HTTP/HTTPS 路径前缀改写均生效，见 C-05 |
| `DomainConfig.Response.*` | `StatusCode/ContentType/ContentValue` | `ResponseConfig` | ✅ r2 起 HTTP / HTTPS 均支持 |
| `AppOptions.ParentProcessId` | `int` | `AppOptionsJson::parent_process_id` | ✅ |
| `AppOptions.UdpLoggerPort` | `int` | `AppOptionsJson::udp_logger_port` | ✅ |
| `Serilog.MinimumLevel.Default` | `string` | `logger.rs::set_level` | 🟡 仅解析 `Default`，忽略 `Override` 子段 |
| `FastGithub.Silent.*` | — | `SilentOptions`（15 项） | ➕ Rust 独有 |
| 命令行 `ParentProcessId=` / `UdpLoggerPort=` / `Key=Value` | .NET CLI | `platform.rs::parse_args` | ✅ |

## 4. 端口对应表

| 端口 | 原项目 | Rust | 备注 |
| --- | --- | --- | --- |
| 38457 / TCP | HTTP 正向代理 + PAC + `/flowStatistics`（非 Windows 主入口） | 同 | 固定；占用则跳过 |
| 38457 / UDP | UI 日志接收端口 | 日志发送目标 | `UdpLog=true` 时启用 |
| 53 / UDP | WinDivert 拦截（不实际绑定） | 本地 DNS 监听 `127.0.0.1:53` | 占用则跳过并记日志 |
| 80 / TCP | loopback 拦截 → HTTP 反向代理 | 直接绑定，冲突向后扫 128 端口 | `HttpListener` |
| 443 / TCP | loopback 拦截 → HTTPS MITM | 直接绑定 → 默认 MITM 终止 TLS（`proxy` 模式字节级透传） | `HttpsListener` |
| 22 / TCP | loopback 拦截 → github.com:22 | 直接绑定 → TCP 反向代理 | `SshProxy` |
| 9418 / TCP | loopback 拦截 → github.com:9418 | 直接绑定 → TCP 反向代理 | `GitProxy` |
| 5533+ / UDP | dnscrypt-proxy | — | ❌ |
| 3880 / 38443 | 非 Windows 反向代理 | — | ❌ |

## 5. 常量对应表

| 常量 | 原值 | Rust 位置 |
| --- | --- | --- |
| DNS 应答 TTL | 300s | `servers.rs::spawn_dns_listener` |
| DNS 结果 TTL | 30s .. 600s | `resolver.rs::MIN_TTL` / `MAX_TTL` |
| DNS 查询超时 | 4s | `resolver.rs::DNS_QUERY_TIMEOUT` |
| DNS TCP 探测超时 | 2s | `resolver.rs::DNS_PROBE_TIMEOUT` |
| IP 测速连接超时 | 5s | `resolver.rs::CONNECT_TIMEOUT` |
| 时延/DNS 状态缓存 | 300s / 60s | `resolver.rs::LATENCY_TTL` / `DNS_STATE_TTL` |
| 出站连接超时 | 10s | `config.rs::Config::connect_timeout` |
| 测速周期 | 1s | `SilentOptions::speed_test_interval_secs` |
| 流量统计窗口 | 5s | `stats.rs::WINDOW_MS` |
| 端口扫描上限 | 动态可用端口 | `servers.rs::PORT_SCAN_LIMIT=128` |
| 最大 IP 数 | 3 (`MAX_IP_COUNT`) | `resolver.rs::rank` 截断 |
| 互斥体名 | `Global\FastGithub` | `platform.rs::acquire_singleton` |

---

## 6. 明确不实现 / 有意替代清单

| ID | 项 | 决策 | 依据 |
| --- | --- | --- | --- |
| C-01 | `requireAdministrator` / UAC | 改 `asInvoker` | 静默要求 |
| C-02 | 控制台、WPF UI、弹窗、交互 | 全部移除 | 静默要求 |
| C-03 | WinDivert DNS 包拦截 | 本地 DNS 监听 + 一次性系统 DNS 指向 | x86 驱动与弹窗冲突 |
| C-04 | WinDivert loopback TCP 端口改写 | 直接绑定 80/443/22/9418 | 同上 |
| ~~C-05~~ | ~~自签 CA + HTTPS MITM → 透传替代~~ | **r2 已恢复完整 MITM**，见 0-bis / C-13 | r1 方案被 C-12 证伪，本行仅保留修订痕迹 |
| C-06 | dnscrypt-proxy 外部进程 / 服务 | 纯 Rust DNS 客户端 | 仓库无 x86 二进制 |
| C-07 | hosts / 注册表 / git config / DNS 缓存刷新 | 不修改系统状态 | 静默 + 无管理员；CA 存储由显式一次性脚本处理（C-13） |
| ~~C-08~~ | ~~`TlsIgnoreNameMismatch` 不生效~~ | **r2 MITM 出站恒定跳过上游校验**，见 C-14 | r1 隧道模式结论已失效 |
| C-09 | Linux / macOS / systemd | 不实现 | 交付目标限定 |
| C-10 | Win7 支持 | 不实现 | 原版亦不支持 |
| C-11 | .NET 特有的多配置源 / Yarp 全部路由语义 | 近似实现 | 依赖树约束 |

> 每条差异的原因、影响、缓解措施详见 `docs/COMPATIBILITY.md`。
> r2 修订后 C-05 / C-08 不再属于「不实现」项，保留划删行以便追溯 r1 → r2 的决策变更。

---

## 7. 证据索引

craft-anything Deep 模式导入 9 条 evidence，10 条 findings、4 条 supported hypotheses、3 条 open questions。
下表给出短名与完整证据 id 的映射，完整报告见 `docs/ANALYSIS-craft-anything.md`。

| 短名 | 证据 id | 覆盖内容 |
| --- | --- | --- |
| `EV_ROOT` | `ev_3d748cd7db297c2c1b50abf3d645182957880290bec2f348b5658fab8c41bd9f` | 仓库整体（148 文件）/ 依赖 / 红线 |
| `EV_NET` | `ev_56111bbcbed02f50cebd89c3c9b3e24268f6c54a691046fdc6d5c9829c5b94df` | .NET 7 技术栈 |
| `EV_APP` | `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` | FastGithub 主程序（20 文件）/ 启动 / 服务 / 单实例 |
| `EV_CFG` | `ev_a285ac02a2ae4510f640ca6d27faab56eaaaa2a6803b4827cda75d3a228fd800` | 配置模型 / DomainPattern / GlobalListener |
| `EV_PKT` | `ev_b19cd1feaa60f602e2818fc1dbe9213f847f2263ed9906b0850288fdb6e8dae8` | WinDivert DNS/TCP 拦截 / 系统状态写入 |
| `EV_DNS` | `ev_ad587c8485257c5b34c59a387d3523d2cab1fe924002b419c5bc9d4403e49c3a` | DnsClient / IPAddressService / 持久化 |
| `EV_HTTP` | `ev_cf727f792c8cdafbeea50e14dce0e09e422a172ed8e5b0406f73fb0bf16e4b95` | Kestrel / 证书 / 反向代理 / 隧道 |
| `EV_OUT` | `ev_40767778d8fc6905cde73bb022c9507c885564947e55f7cf412bf91e20d11d0b` | HttpClientHandler / SNI / 防自环 |
| `EV_FLOW` | `ev_8439ce9b49d29aef362712bf9c30d5c3f22a3b3f0cd38069bf1130877f8ee3a7` | FlowAnalyzer / `/flowStatistics` |
