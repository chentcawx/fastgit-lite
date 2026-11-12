# Investigation report

**Question:** 分析 FastGithub-2.1.5 源码，梳理功能边界、核心模块、配置项、运行依赖与行为约束，作为用 Rust 在 Windows 10 x86 上重写为静默后台可执行应用的依据。

**Purpose:** 遗留 .NET 项目迁移/重写：保证主要功能与行为等价，且满足无控制台窗口、无弹窗、无交互提示的后台常驻要求

**Done when:** 形成带证据 id 的 findings：功能边界、核心模块清单、配置项全表、运行依赖、行为约束；并输出可供 Rust 实现直接对照的功能对应表与验收标准

## What we looked at

- FastGithub (source-tree)
- FastGithub-2.1.5 (source-tree)
- FastGithub.Configuration (source-tree)
- FastGithub.DomainResolve (source-tree)
- FastGithub.FlowAnalyze (source-tree)
- FastGithub.Http (source-tree)
- FastGithub.HttpServer (source-tree)
- FastGithub.PacketIntercept (source-tree)
- D:\WorkBuddy\fastgithub\FastGithub-2.1.5\

## What we found

### 功能边界：FastGithub 2.1.5 是本机 GitHub/相关域名加速代理，明确声明不具备翻墙、不加密隧道、不支持 Win7；四大能力为纯净 IP 解析、IP 测速选优、域名 TLS 连接自定义、境外 CDN 资源替换（Destination 改写）。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_3d748cd7db297c2c1b50abf3d645182957880290bec2f348b5658fab8c41bd9f` — FastGithub-2.1.5: 148 file(s), 0 script(s) analysed, 3 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5)
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)

### 工程结构：8 个 .csproj / net7.0；主程序 fastgithub.exe 为 ASP.NET Core Kestrel 宿主（Startup 注册 Configuration/DomainResolve/Http/ReverseProxy/FlowAnalyze/PacketIntercept），另有独立 WPF UI 进程通过 CreateNoWindow 启动主程序并通过 UDP 接收日志。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_56111bbcbed02f50cebd89c3c9b3e24268f6c54a691046fdc6d5c9829c5b94df` — FastGithub-2.1.5: looks built on .NET (C# and similar languages). (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5)
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)

### Windows 主链路是 WinDivert 包拦截：过滤 UDP.DstPort==53 的 DNS 查询，命中配置域名则伪造 A/AAAA 应答为 127.0.0.1/::1（TTL 5 分钟）；同时把 loopback 上 80/443/22/9418 的 TCP 包目标端口改写到本机动态可用端口，由 Kestrel 承接反向代理。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_b19cd1feaa60f602e2818fc1dbe9213f847f2263ed9906b0850288fdb6e8dae8` — FastGithub.PacketIntercept: 15 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.PacketIntercept)
  - `ev_a285ac02a2ae4510f640ca6d27faab56eaaaa2a6803b4827cda75d3a228fd800` — FastGithub.Configuration: 12 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.Configuration)

### 端口约定：HttpProxyPort 默认 38457（Linux/macOS 的 HTTP 正向代理与 PAC 端口，同时作为 UDP 日志端口）；Windows 下 GlobalListener 从 80/443/22/9418 起寻找首个未被占用的端口作为 HTTP/HTTPS/SSH/GIT 反向代理监听端口，非 Windows 使用 3880/38443。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_a285ac02a2ae4510f640ca6d27faab56eaaaa2a6803b4827cda75d3a228fd800` — FastGithub.Configuration: 12 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.Configuration)
  - `ev_cf727f792c8cdafbeea50e14dce0e09e422a172ed8e5b0406f73fb0bf16e4b95` — FastGithub.HttpServer: 26 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.HttpServer)
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)

### 配置模型：appsettings.json 定义 FastGithub.HttpProxyPort / FallbackDns(8.8.8.8:53、119.29.29.29:53、114.114.114.114:53) / DomainConfigs；9 个 appsettings.*.json 按域名分组，键支持 * 匹配除点外任意字符并按分段数/字典序排序优先；DomainConfig 字段为 TlsSni、TlsSniPattern(@domain/@ipaddress/@random)、TlsIgnoreNameMismatch、IPAddress、Timeout、Destination、Response(StatusCode/ContentType/ContentValue)。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_a285ac02a2ae4510f640ca6d27faab56eaaaa2a6803b4827cda75d3a228fd800` — FastGithub.Configuration: 12 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.Configuration)
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)

### 运行依赖：.NET 7 自包含单文件发布、ASP.NET Core/Kestrel、Yarp.ReverseProxy、Serilog(Console/File/UDP)、WindivertDotnet 1.1.2 + WinDivert 内核驱动、DNS 7.0.0 库、外部 dnscrypt-proxy 进程（仓库仅提供 win-x64/linux/macOS 的 x64 或 arm64 二进制）、管理员权限、根证书存储写入权限、git 可执行文件。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_56111bbcbed02f50cebd89c3c9b3e24268f6c54a691046fdc6d5c9829c5b94df` — FastGithub-2.1.5: looks built on .NET (C# and similar languages). (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5)
  - `ev_b19cd1feaa60f602e2818fc1dbe9213f847f2263ed9906b0850288fdb6e8dae8` — FastGithub.PacketIntercept: 15 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.PacketIntercept)
  - `ev_3d748cd7db297c2c1b50abf3d645182957880290bec2f348b5658fab8c41bd9f` — FastGithub-2.1.5: 148 file(s), 0 script(s) analysed, 3 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5)

### 域名解析子系统：DnsClient 优先用本机 dnscrypt-proxy（动态端口 5533 起），否则回退 DNS 且需 TCP:53 可用性探测；查询 A/AAAA、剔除回环 IP、结果按 TTL 缓存（下限 30s、上限 10min）、按 TCP 建连时延快速排序；IPAddressService 并行测速（5s 连接超时，5min/1min 缓存）；DomainResolver 保留最快 IP 列表并持久化到 dnsendpoints.json，测速循环周期 1s。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_ad587c8485257c5b34c59a387d3523d2cab1fe924002b419c5bc9d4403e49c3a` — FastGithub.DomainResolve: 11 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.DomainResolve)

### TLS/出站行为：CertService 生成 10 年 RSA-2048 自签 CA（cacert/fastgithub.cer + .key）并安装到 LocalMachine\Root，按域名签发 1 年叶证书（SAN 含机器名与回环 IP）；HttpClientHandler 自建连接，用 TargetHost 控制 SNI、TlsIgnoreNameMismatch 放宽证书名校验、按 IP 逐个尝试连接（10s 超时）、禁用代理/重定向/自动解压，并注入 User-Agent 标记防自环；默认把出站请求降级为 http 再在传输层做 TLS。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_cf727f792c8cdafbeea50e14dce0e09e422a172ed8e5b0406f73fb0bf16e4b95` — FastGithub.HttpServer: 26 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.HttpServer)
  - `ev_40767778d8fc6905cde73bb022c9507c885564947e55f7cf412bf91e20d11d0b` — FastGithub.Http: 12 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.Http)

### 辅助能力：proxy.pac 自动生成、HTTP 正向代理与 CONNECT 隧道（非 Windows）、github.com:22 SSH 与 :9418 git 协议反向代理、TLS  invading/restore 中间件兼容明文与 TLS 混合流量、5 秒窗口流量统计并通过 /flowStatistics 输出 JSON、Global\\FastGithub 单实例互斥、start/stop 安装卸载 Windows 服务、ParentProcessId 父进程退出后自动停机。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_cf727f792c8cdafbeea50e14dce0e09e422a172ed8e5b0406f73fb0bf16e4b95` — FastGithub.HttpServer: 26 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.HttpServer)
  - `ev_8439ce9b49d29aef362712bf9c30d5c3f22a3b3f0cd38069bf1130877f8ee3a7` — FastGithub.FlowAnalyze: 14 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.FlowAnalyze)
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)

### 行为约束与兼容性红线：app.manifest 要求 requireAdministrator（触发 UAC）、启动即写 hosts 冲突注释/注册表 ProxyOverride/根证书/git 全局 sslverify/服务；配置文件热重载仅对已加载文件生效，新增 appsettings.*.json 需重启；README 明确不支持 Win7；仓库只带 win-x64 的 dnscrypt-proxy.exe 与 WinDivert 所需管理员/驱动环境，没有 32 位 x86 二进制与驱动，因此 x86 重写必须自带等价能力而不能复用这些外部件。

- **Confidence:** Seen it (observed)
- **Evidence:**
  - `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub)
  - `ev_b19cd1feaa60f602e2818fc1dbe9213f847f2263ed9906b0850288fdb6e8dae8` — FastGithub.PacketIntercept: 15 file(s), 0 script(s) analysed, 0 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5/FastGithub.PacketIntercept)
  - `ev_3d748cd7db297c2c1b50abf3d645182957880290bec2f348b5658fab8c41bd9f` — FastGithub-2.1.5: 148 file(s), 0 script(s) analysed, 3 ignored. (path=D:/WorkBuddy/fastgithub/FastGithub-2.1.5)

## Open questions

> **后续实证更新（2026-11-12，r2 MITM 修订）**：以下 open questions 是静态分析阶段的原始记录，保留不改。
> 后续本机联网实测已确认：① 当前网络按 SNI 阻断 github（带 SNI → RST，不带 SNI → TLS1.3 握手成功）；
> ② 无 CA 的 TLS 透传改写 ClientHello 会破坏 transcript hash，`Finished` 校验必失败，见 `COMPATIBILITY.md` C-12；
> ③ r2 改为完整 MITM + 独立出站握手省略 SNI 后，`https://github.com/` 与 `https://api.github.com/` 均返回 200；
> ④ CA 由 `scripts/install-ca.ps1` 显式一次性写入 `CurrentUser\Root`，无需管理员 / UAC，U-3 已解决。
> 剩余 U-1 仅涉及多域名 CDN 替换质量与长时间并发资源占用，见 `ACCEPTANCE.md` G 节。

- 原程序真实运行时行为（DNS 命中率、SNI 改写效果、各 CDN 替换可用性）未在本次静态分析中实测，Rust 版功能等价性需联网回归验证。 _(severity Medium, Open)_
  - would settle it: 在隔离环境同时运行原版与 Rust 版，对比域名解析与代理响应
  - would settle it: 按验收标准中的用例逐项实测
- Win10 32 位 (x86) 上是否有可用且可静默加载的 WinDivert x86 内核驱动，以便 1:1 复刻 DNS/TCP 包拦截？ _(severity High, Open)_
  - would settle it: 核实 WinDivert 官方发布的 x86 驱动签名与 Win10 x86 支持情况
  - would settle it: 在目标机上以管理员权限试装并观察是否出现驱动签名/服务弹窗
- 目标部署机是否已预先授予管理员权限 / 已安装并信任自签 CA？这决定 Rust 版能否在不弹 UAC、不改系统状态的前提下提供 HTTPS 加速。 _(severity High, Open)_
  - would settle it: 确认部署方式（计划任务/服务/已提权父进程）
  - would settle it: 确认是否允许一次性预置 CA 与系统配置

## How this was done

- **Mode:** Deep (the original's code and files could be read)
- **Engines:** builtin
- **Limitations:**
  - A file being in the folder doesn't prove the app runs it: it may be unused, left over from an update, or there for another reason. Nothing was started, so these are inferences.
  - A source tree is someone's claim about what was built; js_source_bundle_compare checks it against the shipped code.
  - Only names, the ends of some files and the start of the main programs were read. The app's contents weren't unpacked or analysed; next_steps says what to run for that.
  - Some files were skipped by the size or count limits.

## Evidence ledger

- `ev_56111bbcbed02f50cebd89c3c9b3e24268f6c54a691046fdc6d5c9829c5b94df` **app_folder_explain** — FastGithub-2.1.5: looks built on .NET (C# and similar languages). (Best guess)
- `ev_3d748cd7db297c2c1b50abf3d645182957880290bec2f348b5658fab8c41bd9f` **app_source_import** — FastGithub-2.1.5: 148 file(s), 0 script(s) analysed, 3 ignored. (Seen it)
- `ev_1c297a9809e98a4004de76a17c917c1b3198676488a7f985efa232f2718d4407` **app_source_import** — FastGithub: 20 file(s), 0 script(s) analysed, 1 ignored. (Seen it)
- `ev_8439ce9b49d29aef362712bf9c30d5c3f22a3b3f0cd38069bf1130877f8ee3a7` **app_source_import** — FastGithub.FlowAnalyze: 14 file(s), 0 script(s) analysed, 0 ignored. (Seen it)
- `ev_40767778d8fc6905cde73bb022c9507c885564947e55f7cf412bf91e20d11d0b` **app_source_import** — FastGithub.Http: 12 file(s), 0 script(s) analysed, 0 ignored. (Seen it)
- `ev_b19cd1feaa60f602e2818fc1dbe9213f847f2263ed9906b0850288fdb6e8dae8` **app_source_import** — FastGithub.PacketIntercept: 15 file(s), 0 script(s) analysed, 0 ignored. (Seen it)
- `ev_cf727f792c8cdafbeea50e14dce0e09e422a172ed8e5b0406f73fb0bf16e4b95` **app_source_import** — FastGithub.HttpServer: 26 file(s), 0 script(s) analysed, 0 ignored. (Seen it)
- `ev_ad587c8485257c5b34c59a387d3523d2cab1fe924002b419c5bc9d4403e49c3a` **app_source_import** — FastGithub.DomainResolve: 11 file(s), 0 script(s) analysed, 0 ignored. (Seen it)
- `ev_a285ac02a2ae4510f640ca6d27faab56eaaaa2a6803b4827cda75d3a228fd800` **app_source_import** — FastGithub.Configuration: 12 file(s), 0 script(s) analysed, 0 ignored. (Seen it)

