# 兼容性约束与有意偏差

适用范围：`fastgithub-rs` v2.1.5，目标平台 **Windows 10 32 位 (x86)**，运行模式 **静默后台**。
本文逐条登记「为什么不能 1:1 复刻原项目」以及每个偏差带来的可观察影响和缓解方式。
功能对照见 `docs/FEATURE-MAPPING.md`，验收用例见 `docs/ACCEPTANCE.md`。

---

## 0. r2 修订：默认改为 HTTPS MITM（2026-11-12）

| # | 约束 / 偏差 | 说明 |
| --- | --- | --- |
| C-12 | **TLS 透传不能改写 ClientHello** | TLS transcript hash 覆盖 ClientHello 原文；中间人删改 SNI 会让客户端与服务器算出不同的 `Finished`，握手必失败。实测 `SEC_E_DECRYPT_FAILURE` / `decryption failed or bad record mac`；对照实验「客户端本来就不发 SNI（改写为字节级 no-op）」则握手成功。因此 `proxy` 模式只做字节级原样转发，**不具备 SNI 控制能力**；需要 SNI 控制必须走 MITM。 |
| C-13 | **MITM 需要一次性安装本地 CA** | `Silent.Mode=mitm` 为默认值。进程首次运行生成 `cacert/fastgithub.cer`（DER）、`.key`、`-ca.pem`，按 SNI 动态签发叶证书；CA 由用户显式运行 `scripts/install-ca.ps1` 安装一次（默认 CurrentUser\Root，**无需 UAC**）。进程本身绝不写证书库。未安装时浏览器会弹证书告警。 |
| C-14 | **上游证书校验被跳过** | `tls.rs::NoCertificateVerification` 等价原版 `RemoteCertificateValidationCallback => true` 与 `TlsIgnoreNameMismatch`；出站用 `ServerName::IpAddress` 达到不发 SNI，因此无法做域名校验。仅建议在可信本机环境使用。 |
| C-15 | **默认只监听 loopback，LAN 共享须显式开启** | `Silent.ProxyBind` 默认 `127.0.0.1`，仅 38457 按此绑定；80/443/22/9418 恒绑 loopback。设 `0.0.0.0` 或具体 LAN IP 后需自行放行防火墙入站（管理员一次操作），并给每台客户端导入**同一份** `fastgithub.cer` 公钥（`-CerPath`），绝不分发 `.key` 私钥。PAC 按客户端所连地址动态回显，避免指回客户端自己。38457 是**无认证开放代理**，配合 C-14 的跳过校验与 MITM 明文可见性，只允许在可信内网、按来源网段限制使用；禁止公网端口转发。另：`DnsBind` 必须保持 loopback，LAN 客户端把 DNS 指向服务端会拿到 `127.0.0.1` 而失效，应一律用 PAC / 手动代理。详见 `README.md` 第 3.3 节。 |
| C-16 | **github 系 CDN 也必须省略 SNI；侧栏空白是上游 IP 失败** | 对照实验：出站发 `SNI=github.githubassets.com` 立刻被 RST（`os error 10054`），不带 SNI 则返回 200。因此 `appsettings.github.json` 对 `*.githubassets.com` / `*.githubusercontent.com` 等显式设 `TlsSni: false`，省略该键亦为 `false`。GitHub 新版仓库页的 Releases 等侧栏是 React 骨架屏，依赖 `github.githubassets.com` 的 JS；日志显示部分 CDN 节点 TCP 超时 / TLS 被 RST，旧实现在第一个 IP 握手失败后直接 502 → JS 加载不全 → 骨架屏不消失。修复：`proxy.rs::mitm_forward` 在 TCP / TLS 失败时换下一个测速优选 IP（最多 3 个），优先复用上次成功 IP，单候选 IP 立即重试一次；多 IP 时单次连接上限 5s，单 IP 保留完整 10s（4s 会造成误判 502）。实测见 `ACCEPTANCE.md` M23–M28。 |
| C-17 | **广告过滤是代理层短路，不是浏览器扩展** | 命中 `config/ad-domains.txt` 的域名由程序返回空响应，不解析 DNS、不连上游；清单域名同时写入 PAC，确保请求进代理。仅覆盖 HTTP 明文与 MITM 终止后的 HTTPS 请求；`proxy` 透传模式下只能拒绝 CONNECT。不解析 URL 路径 / 页面元素，不做元素隐藏；Android 7+ 用户 CA 限制等系统行为不变。清单热加载仅对启动时已存在的文件生效（新增需重启）。 |
| C-18 | **SNI 阻断结论不能外推；Cloudflare 控制台必须走 DIRECT** | 实测 `dash` / `www` 的 DNS 正常、带 SNI 与不带 SNI 都能完成 TLS 1.3 并返回正确证书；故障来自 Cloudflare WAF `Cf-Mitigated: challenge` / 1015 限流 / 国际链路抖动（按出口公网 IP 判定，本地代理改不了出口 IP）。Cloudflare anycast 边缘 IP 与站点绑定，错段直接 403。MITM 会把 SPA 控制台降级为 HTTP/1.1、不支持 WebSocket、重建请求头，且账号会话在代理进程内明文可见。因此 `appsettings.bootcss.json` 只保留 `cdnjs.cloudflare.com` / `cdn.bootcss.com`，其余 cloudflare 域名由 PAC 判 DIRECT。详见 `docs/CLOUDFLARE-ASSESSMENT.md`、`ACCEPTANCE.md` M29。 |
| C-19 | **MITM 请求体必须自包含，否则表单提交会永久卡住** | 旧版 `mitm_serve` 的 `read_head` 只读到 `\r\n\r\n`，`leftover` 仅是同一次 `read()` 顺带读到的字节；而 `mitm_forward` 的 `forward_over` 是单向泵，写完请求后只读上游响应、不再读客户端。上游收到 `Content-Length: N` 却只拿到部分字节，会一直等待，浏览器表现为登录 / `Confirm access` / 表单提交无限转圈。修复：`proxy.rs::read_body` 在转发前按 `Content-Length` 读满、把 `chunked` 解码为裸 body、对 `Expect: 100-continue` 本地应答；`build_http_request(..., complete_body=true)` 重写精确 `Content-Length` 并剥离 `Expect` 与原 framing。明文 `forward_http` 走双向 `relay`，保留原请求头不受影响（该路径的 chunked 上传仍是已知限制）。本地 HTTPS echo 实测：修复前 64 KB 与 `Expect` 两组均 `HTTP=000` / 25s 超时 / 服务端 0 字节，修复后 256 B / 64 KB / chunked 8 KB / `Expect` 4 KB 全部 200 且 SHA 与直连一致。见 `ACCEPTANCE.md` M30–M31。 |
| C-20 | **浏览器 User-Agent 必须原样透传；防自环改用 `Via`** | 旧版在 `build_http_request` 里给每个请求的 `User-Agent` 追加 ` FastGithub/1.0` 作为防自环标记，实测经代理后变成 `curl/8.21.0 FastGithub/1.0`。GitHub 的设备验证 / sudo 二次确认 / OAuth 风控对 UA 敏感，被改写的 UA 可能被判为新设备。r5 起改用 RFC 7230 标准头 `Via: 1.1 fastgithub` 做跳数跟踪与防环：浏览器 UA 逐字节原样转发，仅当客户端完全没有 UA 时才补 `FastGithub/1.0`；`is_forward_loop()` 同时识别 `Via` 与旧 UA 标记以兼容混合版本，客户端自带的 `Via` 会被剥离后重写一次。实测 `Via` 标记与旧 UA 标记均返回 502，正常浏览器 UA 返回 200；见 `ACCEPTANCE.md` M33、`docs/OAUTH-ASSESSMENT.md` §6。 |
| C-21 | **OAuth 回调之后的链路不在本地代理管辖范围** | 浏览器 → `github.com/login/oauth/authorize`（经代理，实测 302 + `Set-Cookie` 完整）、GitHub 302 → `www.codebuddy.cn/...connect?code=`（PAC 判 DIRECT，实测 200）都在本机链路内；但 **CodeBuddy 服务端拿 `code` 换 `access_token`、校验一次性 `state`、写入绑定关系是服务器到 GitHub 的请求，完全不经过本机代理**。因此中文「授权失败」若出现在回调页，本地代理无法修复；需重新发起全新授权（新 `state`）或排查服务端链路。脱敏诊断结论见 `docs/OAUTH-ASSESSMENT.md`、`ACCEPTANCE.md` M32。 |

补充的运行时约束：
* 本机 UDP 53 被 `smartdns.exe` 占用，DNS 劫持链路自动跳过（记 WRN），必须显式配置代理 / PAC 指向 `127.0.0.1:38457`。
* Windows 原生 Schannel 客户端（`curl.exe` / PowerShell）对自建 CA 报 `CRYPT_E_NO_REVOCATION_CHECK`（无 CRL），加 `--ssl-no-revoke` 即可（实测 200）；Chrome/Edge 自带验证器不受影响。
* 直接依赖由 2 个增至 5 个：`serde`、`serde_json`、`rustls 0.23`、`rcgen 0.13`、`time 0.3`（全纯 Rust，i686 已验证）。

---

## 1. 平台与工具链约束

| 项 | 约束 | 实测 / 依据 |
| --- | --- | --- |
| 操作系统 | Windows 10 x86（32 位）；Windows 10/11 x64 通过 WOW64 亦可运行 | manifest `supportedOS {8e0f7a12-…}` 仅声明 Win10+；原版明确不支持 Win7 |
| CPU / ABI | `i686`（32 位 x86），PE32 | `Machine=0x014C`，`OptionalHeader.Magic=0x010B` |
| Rust | ≥ 1.97（`edition=2021`，`rust-version=1.97`） | 本机 `rustc 1.97.1` / `cargo 1.97.1` |
| 构建目标 | `i686-pc-windows-msvc` | `.cargo/config.toml` 已设为默认目标 |
| 链接器 | MSVC x86 linker + Windows SDK | `/MACHINE:X86`、`/MANIFEST:EMBED`、`/MANIFESTINPUT:resources/app.manifest` |
| 运行时依赖 | 无需 .NET、无需 VC++ 运行库分发、无需驱动、无需外部 exe | 5 个纯 Rust 直接依赖；`Cargo.lock` 共 67 个 package |
| 部署 | `fastgithub.exe` + `config/` 同目录即可 | 日志写入 `<exe_dir>/logs/`，测速状态写 `<exe_dir>/dnsendpoints.json` |

**关键结论**：原项目是 `net7.0` / `win-x64` / `PublishSingleFile` 自包含发布，且仓库内只提供 `dnscrypt-proxy` 的 x64/arm64 二进制与 WinDivert 驱动环境，
**没有任何可直接在 Win10 x86 上复用的外部件**（`EV_ROOT`、`EV_PKT`）。因此 Rust 版把全部能力内联为纯 Rust 实现。

---

## 2. 权限与静默红线

用户要求「启动后无控制台窗口、无弹窗、无交互提示且可持续在后台执行」。以下四条原版行为与之直接冲突，因此被列为**不可引入项**：

1. `FastGithub/app.manifest` 的 `requireAdministrator` → 每次启动触发 UAC 同意对话框；
2. WinDivert 内核驱动的安装/加载 → 需管理员 + 驱动签名，且可能触发系统提示；
3. 自签 CA 写入 `LocalMachine\Root` → 需管理员，且浏览器/系统可能弹出证书信任提示；
4. WPF UI、`git config --global`、hosts / 注册表改写 → 产生窗口或改变系统全局状态。

Rust 版的实现约束：

| 机制 | 位置 |
| --- | --- |
| GUI 子系统（PE `Subsystem=2`） | `src/main.rs` `#![cfg_attr(not(test), windows_subsystem = "windows")]` |
| `asInvoker` 清单（无 UAC） | `resources/app.manifest` + `build.rs` 嵌入 |
| `FreeConsole()` 兜底 + `SetConsoleCtrlHandler` | `src/platform.rs::init` |
| 无 `MessageBox` / `println!` / `eprintln!` / stdin 读取 | 全代码 |
| 无子进程、无 UI、无 WebView | 全代码 |
| 日志只写文件与 UDP | `src/logger.rs` |
| 单实例 + 父进程看护 + 停机信号 | `src/platform.rs` / `src/main.rs` |

> `start` / `stop` 服务命令是**唯一**可能需要管理员的操作。它们只在显式调用时执行，失败时只写日志、不弹 UAC、不退出非零码，符合静默要求。

---

## 3. 偏差登记表

### C-01 · 执行级别：requireAdministrator → asInvoker 🔁

- **原因**：UAC 弹窗违反静默要求；Rust 版不需要提权（只绑定 loopback 端口，Windows 上绑定低端口无需管理员）。
- **影响**：无法自动安装 Windows 服务、无法写 `LocalMachine\Root`、无法加载内核驱动。
- **缓解**：需要开机自启时使用 `scripts/install-silent-task.ps1`（已提权的安装会话注册计划任务，或未提权时写 Startup 快捷方式）；服务用 `fastgithub.exe start` 在已提权会话中一次性安装。
- **证据**：`EV_APP`、`EV_ROOT`。

### C-02 · 控制台 / UI / 交互全部移除 🔁

- **原因**：原版 `ConsoleUtil.DisableQuickEdit()`、Serilog Console sink、WPF UI 都与「无窗口」冲突。
- **影响**：没有交互式界面；状态只能通过 `logs/log-YYYY-MM-DD.txt`、UDP 日志、`/proxy.pac`、`/flowStatistics` 观察。
- **缓解**：`UdpLoggerPort` 参数保留，外部观察器可复用 `FastGithub.UI` 的 UDP 日志协议槽位。
- **证据**：`EV_APP`。

### C-03 · DNS 拦截：WinDivert 包捕获 → 本地 DNS 监听 🔁

- **原因**：WinDivert 是内核驱动；x86 驱动签名 + 管理员安装 + 潜在系统提示，三者都不可接受。
- **影响**：**不再全局透明劫持**。必须一次性把系统/网卡 DNS 指向 `127.0.0.1`，或直接使用 HTTP 正向代理 `127.0.0.1:38457`。
- **保持等价的部分**：命中 `DomainConfigs` 的 A/AAAA 查询返回 `127.0.0.1` / `::1`，TTL 300s，压缩指针 `0xC00C`；未命中查询转发 `FallbackDns`，全失败返回 SERVFAIL。
- **额外差异**：若 53 端口被系统 DNS Client 等占用，Rust 版**跳过该监听器并只记日志**，不影响其余监听器；原版靠驱动可无条件拦截。
- **缓解**：`Silent.DnsEnabled` / `Silent.DnsBind` 可配置；部署时检查 53 端口占用。
- **证据**：`EV_PKT`、`EV_CFG`。

### C-04 · TCP 端口改写：WinDivert → 直接绑定 🔁

- **原因**：同 C-03。
- **影响**：不再把 loopback 上任意目标端口改写为动态端口；改为程序自己占用 80/443/22/9418。若这些端口已被其他服务占用，`bind_from` 从起始端口向后最多扫描 128 个端口寻找可用端口，但**客户端必须连接实际监听端口**（透明模式下 DNS 已把域名指到 `127.0.0.1`，浏览器会访问标准端口 80/443，因此端口被占用时该链路失效）。
- **缓解**：部署前确认 80/443/22/9418 空闲；或关闭对应监听器改用 HTTP 正向代理模式。
- **证据**：`EV_PKT`、`EV_CFG`、`EV_HTTP`。

### C-05 · HTTPS：自签 CA + MITM → 完整 MITM（r2 恢复）✅

> **历史注记**：r1 曾采用「TLS 透传 + ClientHello SNI 改写」，该方案破坏 TLS transcript hash，已在 r2 废弃，见 C-12。

- **原因**：原版生成 10 年 CA 与 1 年叶证书、安装到 `LocalMachine\Root`、用 `SslStream` 终止浏览器 TLS 后再独立出站握手。r2 恢复同一机制，改用 `rustls 0.23` + `rcgen 0.13`，在 `i686-pc-windows-msvc` 上已完成依赖探针与 Release 构建验证。
- **Rust 版做法（默认 `Silent.Mode=mitm`）**：`certs.rs::CertAuthority` 生成 / 加载 CA 并按 SNI 动态签发 1 年叶证书；`tls.rs::server_stream` 终止浏览器侧 TLS；`proxy.rs::mitm_serve` 解析明文 HTTP/1.1 并应用 `Destination` / `Response` / 防自环；`tls.rs::client_stream` 用**独立出站握手**连接测速最优 IP，`TlsSni=false` 时以 `ServerName::IpAddress` 省略 SNI；`NoCertificateVerification` 跳过上游证书校验。
- **保持等价**：CA / 叶证书生命周期、按域名签发、`TlsSni=false` 不发 SNI、`@domain`/`@ipaddress`/`@random`、HTTPS 路径前缀 `Destination`、HTTPS `Response` 短路、IP 选优、防自环、超时、流量统计。
- **不等价 / 缺失**：
  - CA 由用户**显式运行一次** `scripts/install-ca.ps1` 安装，默认写 `CurrentUser\Root`（无需 UAC）；原版在进程运行时自动写 `LocalMachine\Root`。进程本身绝不写证书库。
  - 未安装 CA 时浏览器会出现证书告警；Windows 原生 Schannel 客户端还需 `--ssl-no-revoke`（见第 0 节注记）。
  - 绝对形式 HTTPS 请求（非 CONNECT）返回 502 `Use CONNECT for HTTPS`。
  - MITM 后按 HTTP/1.1 重建请求，未实现 HTTP/2 与 WebSocket 升级。
- **`proxy` 模式（`Silent.Mode=proxy`）**：保留字节级原样转发，不生成证书、**不控制 SNI**，仅适用于无需 `TlsSni=false` 绕行的网络。
- **证据**：`EV_HTTP`、`EV_OUT`、`EV_ROOT`；实测见 `ACCEPTANCE.md` M7–M11。

### C-06 · dnscrypt-proxy 外部进程 → 纯 Rust DNS 客户端 🔁

- **原因**：仓库只带 win-x64 / linux / macOS 的 x64 或 arm64 `dnscrypt-proxy.exe`，没有 x86 版本；且原版会安装/启动子进程或 Windows 服务，与静默冲突。
- **影响**：不使用 DNSCrypt/DoH 加密上游 DNS 查询；回退 DNS 为明文 UDP/TCP:53。
- **缓解**：`FallbackDns` 可自行指向支持加密的本地转发器（如本机 53 端口的 stub resolver），程序不关心其实现。
- **证据**：`EV_DNS`、`EV_ROOT`。

### C-07 · 不修改任何系统状态 🔁

| 原版行为 | Rust 版 | 影响 |
| --- | --- | --- |
| 注释 hosts 中的冲突行 | 不读写 hosts | 若 hosts 有手工绑定，优先级仍高于本地 DNS，需用户自行处理 |
| 写 HKCU `ProxyOverride` + `InternetSetOption` | 不写注册表 | 系统代理需用户/部署脚本自行设置或使用 PAC |
| 安装 CA 到 `LocalMachine\Root` | 进程不碰证书库；由 `install-ca.ps1` 显式一次性写入 `CurrentUser\Root`，无需 UAC | 见 C-13 |
| `git config --global http.sslverify false` | 不调用 git | 依赖证书校验的场景需客户端自行处理 |
| 启动/停止时 `DnsFlushResolverCache()` | API 保留但**不自动调用** | 切换 DNS 后可能需要手工 `ipconfig /flushdns` |
| 自动安装 Windows 服务 | 仅显式 `start` | 无自启除非用 `install-silent-task.ps1` |

- **原因**：全部需要管理员权限或产生全局副作用，与静默 + 无交互冲突。
- **证据**：`EV_PKT`、`EV_ROOT`。

### C-08 · `TlsIgnoreNameMismatch` 在 r2 中恒定生效 ✅

- **原因**：原版通过 `RemoteCertificateValidationCallback` 放宽**自己作为 TLS 客户端**时的证书名校验。r2 默认 MITM，出站 TLS 由 Rust 版自己终止，因此该语义由 `tls.rs::NoCertificateVerification` 无条件实现（跳过全部上游校验）。
- **影响**：配置键仍可解析、不会报错，但不再具有开关作用——上游证书始终不校验，见 C-14。
- **`proxy` 模式**：字节级透传时证书校验发生在浏览器与上游之间，该键不生效；如需放宽请切换 `Silent.Mode=mitm`。
- **证据**：`EV_OUT`。

### C-09 · 非 Windows 平台与 systemd ❌

- 交付目标限定 Windows 10 x86。`src/platform.rs` 与 `src/service.rs` 保留了 `#[cfg(not(windows))]` 兜底，可编译但功能不完整（端口 3880/38443、systemd 均不实现）。

### C-10 · Win7 ❌

- 原版 README 明确不支持 Win7；Rust 版 manifest 只声明 Win10/11 `supportedOS`，且使用 `GetTickCount64` 等 Vista+ API。

### C-11 · .NET 生态语义的近似实现 🟡

- 配置：只实现了 `appsettings.json` + `appsettings/*.json` + 命令行 `Key=Value`，未实现 .NET 的环境变量 / UserSecrets / 多 provider 优先级。`Serilog.MinimumLevel.Override` 子段会被忽略。
- 反向代理：自行实现 HTTP/1.1 请求重建与 hop-by-hop 头过滤，未复刻 Yarp 的完整路由、负载均衡、健康检查、HTTP/2/gRPC 语义。
- 出站：无 `HttpClient` 连接池、重试、自动解压、Cookie/Redirect（原版本身也禁用了这些）。
- 热加载：2 秒轮询已加载文件；与原版一致，**新增/删除 `appsettings.*.json` 需重启**。
- 连接模型：每连接双线程阻塞 I/O，不是 async；并发连接数受线程数限制，适合本机单用户加速场景。

---

## 4. 配置兼容矩阵

| 场景 | 结果 |
| --- | --- |
| 直接把原项目 `appsettings.json` + `appsettings/` 拷到 Rust 版 `config/` | ✅ 可启动，所有原键生效 |
| 原配置含 UTF-8 BOM / `//` / `/* */` 注释 | ✅ 可解析 |
| 原配置使用 PascalCase 键 | ✅ |
| 原配置含 `Response` 嵌套对象 | ✅ HTTP 路径生效 |
| 原配置含 `TlsIgnoreNameMismatch` | 🟡 解析成功但不生效（C-08） |
| 原配置含 HTTPS 路径前缀型 `Destination` | ✅ r2 MITM 下完整生效（C-05）；`proxy` 模式下仅主机替换 |
| 原配置含 `FastGithub.Silent` 段 | ➕ Rust 读取；原 .NET 程序忽略 |
| 新增子配置文件 | ❌ 热加载不感知，需重启（与原版一致） |
| 环境变量 `FastGithub__…` 覆盖 | ❌ 不支持 |

---

## 5. 协议与网络边界

- 只实现 **HTTP/1.1**（请求行、头部、body 透传）；无 HTTP/2、无 WebSocket 升级、无 gRPC。
- `proxy` 模式下 `CONNECT` 隧道对上层协议透明（TLS / SSH 原始字节均可），TLS 内部不可见；默认 `mitm` 模式下 443 的 TLS 被终止，HTTP/1.1 内部可见并支持 `Destination` / `Response`。
- DNS：UDP:53 主路径 + TCP:53 可用性探测；A / AAAA；支持压缩指针解析；不支持 DNSSEC / EDNS0 / 任意其他 RR 类型（返回 SERVFAIL 或转发）。
- 全部监听器绑定 `127.0.0.1`，**不对外网暴露**；`DnsBind` 默认 `127.0.0.1:53`。
- `User-Agent: FastGithub/1.0` 防自环标记必须保留，否则请求可能在本机形成环路。

---

## 6. 安全与合规边界

沿用原 README 声明：本项目**仅用于改善公开 GitHub 及相关 CDN 资源的访问质量**，
不提供加密隧道、不提供绕过网络监管的能力、不采集或外传用户数据。
Rust 版额外保证：不安装内核驱动、不修改 hosts / 注册表 / git 全局配置、不启动外部进程；**进程运行时不写证书库**，本地 CA 仅由用户显式执行一次 `install-ca.ps1` 写入 `CurrentUser\Root`（可用 `-Uninstall` 完整卸载，见 C-13）。

---

## 7. 未决事项（craft-anything open questions）

| # | 问题 | 严重度 | 状态 |
| --- | --- | --- | --- |
| U-1 | 原程序真实运行时行为（DNS 命中率、CDN 替换可用性、长时间并发）与原版等价性 | Medium | 🟡 部分收敛：r2 MITM 主链路已本机联网实证（github / api.github.com 均 200，见 `ACCEPTANCE.md` M7–M14）；剩余多域名 CDN 与并发资源占用按 G 组回归 |
| U-2 | Win10 x86 上是否存在可静默加载的 WinDivert x86 签名驱动 | High | 已按「不依赖驱动」设计规避，不再阻塞交付 |
| U-3 | 目标机是否已预置管理员权限 / 已信任自签 CA | High | r2 改为 MITM：CA 由 `install-ca.ps1` 显式安装到 CurrentUser\Root，无需管理员；不再阻塞交付 |

> 说明：U-2 通过「不依赖内核驱动」的 C-03/C-04 替代设计规避；U-3 在 r2 已显式解决——
> 不再需要管理员权限，CA 由用户一次性安装到 `CurrentUser\Root`。两者均不再是交付阻塞项。
