# FastGit Lite — Windows 10 x86 静默后台代理

> FastGithub 2.1.5 的 Rust 重写版 · 仓库：[chentcawx/fastgit-lite](https://github.com/chentcawx/fastgit-lite)

> **一句话**：单文件 32 位 Rust 程序，启动后无窗口 / 无弹窗 / 无 UAC / 无交互，常驻后台。
> 浏览器经 `127.0.0.1:38457` 代理访问 github，**出站不发 SNI** 绕过网络阻断。

| 关键事实 | 值 |
| --- | --- |
| 免编译软件包 | [Releases · 下载 `win-x86.zip`](https://github.com/chentcawx/fastgit-lite/releases/latest) |
| 发布包内容 | `fastgithub.exe` + `config\` + `scripts\` + `SHA256SUMS.txt`（**不含 CA 私钥**，首次运行自动生成） |
| 产物 | `dist\fastgithub.exe` · PE32 · `WINDOWS_GUI` · `asInvoker` |
| 默认代理 | `127.0.0.1:38457`（PAC： `http://127.0.0.1:38457/proxy.pac`） |
| 默认模式 | `mitm`（完整 HTTPS 终止，需一次性安装本地 CA） |
| 配置热加载 | 2 秒（已存在的文件；新增文件需重启） |
| 系统改动 | 进程运行时**零改动**；CA 与自启由用户显式脚本完成 |

---

## ⚡ 30 秒上手

**已有 Release 包**：解压 zip 后直接从下面第 2 步开始，无需 Rust 工具链。
**从源码构建**：先跑第 1 步。

```bat
:: 1 构建（下载 Release 包可跳过）
scripts\build-x86.cmd

:: 2 一次性安装本地 CA（当前用户，无 UAC）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-ca.ps1

:: 3 设置系统 PAC，然后重启浏览器
powershell -NoProfile -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -Value 'http://127.0.0.1:38457/proxy.pac'"

:: 4 启动（无任何窗口）
start "" dist\fastgithub.exe
```

**检查清单**

- [ ] `Get-Process fastgithub` 有进程
- [ ] `Get-NetTCPConnection -LocalPort 38457 -State Listen` 有监听
- [ ] `curl.exe --ssl-no-revoke -x http://127.0.0.1:38457 https://github.com/` 返回 `200`
- [ ] 浏览器**已重启**（PAC 变更不会即时生效）

---

## 1. 适用场景

| 适用 | 不适用 |
| --- | --- |
| 网络按 **SNI 阻断** github / api.github.com | 需要完整「翻墙」或访问任意被封站点 |
| Windows 10/11 本机后台常驻、无界面 | 需要 GUI、托盘、交互配置 |
| 需要纯净 IP 解析 + 连接测速选优 | 需要 HTTP/2、WebSocket、gRPC |
| 可信局域网内少量设备共享代理 | 公网开放代理 / 生产级高并发网关 |
| 需要按域名改写目标、短路响应、过滤广告 | 要求上游证书严格校验（本程序跳过校验） |
| Windows 10 **32 位 x86** 目标机 | Windows 7（原版也不支持） |

> **安全边界**：38457 是无认证开放代理；MITM 下 HTTPS 明文在服务端可见，出站跳过上游证书校验。只在可信本机 / 内网使用。

---

## 2. 功能清单

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| HTTP 正向代理 + CONNECT | ✅ | 38457，兼容原版 |
| **完整 HTTPS MITM** | ✅ | 本地 CA(10y) + 按 SNI 动态签发叶证书(1y) |
| **出站不发 SNI** | ✅ | `TlsSni=false` → `ServerName::IpAddress`；核心绕过手段 |
| 纯净 DNS + IP 测速选优 | ✅ | 自建 DNS wire codec、TTL 缓存、TCP 延迟排序 |
| `Destination` / `Response` 改写 | ✅ | HTTP 与 HTTPS 路径均支持 |
| **上游 IP 失败自动重试** | ✅ | TCP / TLS 握手失败时换下一个测速优选 IP（最多 3 个） |
| PAC 自动配置 | ✅ | 按客户端连入地址**动态回显**服务端 IP（LAN 可用） |
| `/flowStatistics` | ✅ | `totalRead`=上游响应字节，`totalWrite`=发往上游的请求字节 |
| **局域网共享** | ✅ | `Silent.ProxyBind` + 显式防火墙规则 + 客户端导入 CA |
| **广告过滤** | ✅ | `config/ad-domains.txt`，命中返回空响应，热加载 |
| **CA 轮换** | ✅ | `regen-ca` 命令 / `scripts\regen-ca.ps1`，自动备份旧 CA |
| 本地 DNS 监听 | 🟡 | 53 端口被占用时自动跳过，改用 PAC |
| 静默自启 | ✅ | `scripts\install-silent-task.ps1`（Startup 快捷方式，无 UAC） |
| Windows 服务 | ✅ | `start` / `stop` 显式命令，不自动安装 |
| HTTP/2 / WebSocket | ❌ | 仅 HTTP/1.1，每连接一个线程 |

---

## 3. 使用说明

### 3.1 启动 / 停止 / 自启

| 动作 | 命令 |
| --- | --- |
| 启动 | `start "" dist\fastgithub.exe` |
| 停止 | `Stop-Process -Name fastgithub -Force` |
| 登录自启 | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-silent-task.ps1` |
| 取消自启 | 同上加 `-Uninstall` |
| 查看日志 | `dist\logs\log-YYYY-MM-DD.txt`（不输出到控制台） |

> 用 Bash 会话级后台任务拉起的 exe 会随会话被回收，**必须直接启动 exe** 或配置自启。

### 3.2 浏览器 / 本机客户端

```powershell
# 系统 PAC（HKCU，无需管理员）；改完重启浏览器
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
  -Name AutoConfigURL -Value 'http://127.0.0.1:38457/proxy.pac'

# 验证
[System.Net.WebRequest]::GetSystemWebProxy().GetProxy('https://github.com/')
Invoke-WebRequest https://github.com/ -SkipCertificateCheck
```

- `AutoConfigURL` **必须是合法 URL**；裸路径 `e:\...\proxy.pac` 无效。
- PAC 模式下 `ProxyEnable=0` 是**正常的**（手动代理开关）。
- Windows 原生 Schannel 客户端（`curl.exe`）需 `--ssl-no-revoke`；Chrome / Edge 不受影响。

### 3.3 局域网共享（服务端 → 客户端）

**服务端**（当前交付已配置 `ProxyBind=0.0.0.0`）

| 步骤 | 内容 |
| --- | --- |
| 1 | 选客户端能 ping 通的网卡 IP：`<LAN-IP>` |
| 2 | `dist\config\appsettings.json` → `"ProxyBind": "0.0.0.0"`，重启程序 |
| 3 | **需管理员**：放行防火墙入站，见下方命令 |
| 4 | 分发 `dist\cacert\fastgithub.cer` + `dist\scripts\install-ca.ps1` |

```powershell
New-NetFirewallRule -DisplayName 'FastGithub LAN Proxy 38457' `
  -Direction Inbound -Protocol TCP -LocalPort 38457 `
  -Action Allow -Profile Private -RemoteAddress 192.168.1.0/24
```

> 把 `-RemoteAddress` 改成实际网段。**禁止** `-Profile Public` 与公网端口转发。
> 重新执行 `build-x86.cmd` 会把 `ProxyBind` 重置回 `127.0.0.1`，需再改一次。

**客户端**

| 平台 | 导入 CA | 设置代理 |
| --- | --- | --- |
| Windows | `powershell -ExecutionPolicy Bypass -File .\install-ca.ps1 -CerPath .\fastgithub.cer` | `AutoConfigURL = http://<LAN-IP>:38457/proxy.pac` |
| Android | `.cer` 改名 `.crt` → 设置 → 安全 → 从存储安装 | Wi-Fi 高级 → 代理手动：`<LAN-IP>` / `38457` |
| iOS | Safari 下载 → 安装描述文件 → 证书信任设置开启完全信任 | Wi-Fi → 自动代理 → PAC URL |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fastgithub.cer` | 网络 → 代理 → 自动代理配置 |
| Linux | 转 PEM 放入 `/usr/local/share/ca-certificates/` → `sudo update-ca-certificates` | 系统代理 PAC URL |

**三条硬规则**

1. **只分发 `.cer` 公钥，绝不分发 `fastgithub.key` 私钥。**
2. 客户端**不要**把 DNS 指向服务端 —— 本地 DNS 返回 `127.0.0.1`，对客户端是"自己"。
3. 服务端别删 `dist\cacert` 重新生成 CA；一旦轮换，**所有客户端要重新导入**。

### 3.4 重新生成 / 更新证书

```powershell
# 一键：停实例 → 备份旧 CA → 生成新 CA → 卸载旧 CA → 导入新 CA → 重启实例
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\regen-ca.ps1

# 只轮换文件、不动证书库 / 不重启
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\regen-ca.ps1 -SkipInstall -NoRestart
```

| 项 | 说明 |
| --- | --- |
| 程序命令 | `fastgithub.exe regen-ca`（别名 `renew-ca`），一次性执行后退出 |
| 旧 CA 备份 | `dist\cacert\backup-<时间戳>\` |
| 叶证书 | 进程重启时按 SNI 重新签发，无需单独操作 |
| **必做** | 把新的 `fastgithub.cer` 重新导入每台客户端 |

> 轮换 CA 后，仍装旧 CA 的客户端会立刻出现证书告警。原 CA 删除前先确认所有客户端已更新。

### 3.5 广告过滤

| 动作 | 操作 |
| --- | --- |
| 开关 | `appsettings.json` → `FastGithub.Silent.AdBlock.Enabled` |
| 改清单 | 编辑 `config\ad-domains.txt`，**保存后 2 秒热加载** |
| 响应码 | `Silent.AdBlock.StatusCode`（默认 `200` + 空内容） |
| 生效范围 | HTTP 明文请求、MITM 下的 HTTPS 请求；PAC 自动纳入清单域名 |
| 关闭 | `"Enabled": false`，或清空清单文件 |

清单格式（一行一条，`#` / `//` 注释）：

```
example.com
*.ads.example.com
||tracker.example.com^
0.0.0.0 blocked.example.com
```

> **不要填通用静态 CDN**（`alicdn.com` / `bdstatic.com` / `qq.com`），否则会破坏正常页面。
> 内置清单以国内广告联盟为主；「统计 / 追踪」组默认注释，按需取消。

---

## 4. 配置说明

### 4.1 文件地图

| 文件 | 作用 | 热加载 |
| --- | --- | --- |
| `config\appsettings.json` | 主配置（兼容原版 PascalCase + `//` 注释） | ✅ |
| `config\appsettings\appsettings.*.json` | 9 个域名策略子配置 | ✅ 已存在文件 |
| `config\ad-domains.txt` | 广告 / 追踪域名清单 | ✅ 已存在文件 |
| `dist\cacert\` | 本地 CA 与私钥（首次启动生成） | ❌ |
| `resources\app.manifest` | `asInvoker` + Windows 10 supportedOS | 构建期 |

### 4.2 `FastGithub.Silent` 主配置

| 键 | 默认 | 作用 |
| --- | --- | --- |
| `Mode` | `mitm` | `mitm` = 完整 TLS 终止；`proxy` = 字节透传（**不控制 SNI**） |
| `ProxyBind` | `127.0.0.1` | 38457 绑定地址；`0.0.0.0` = 开放 LAN，非法值回退 loopback |
| `LogLevel` / `LogToFile` / `UdpLog` | `Information` / `true` / `true` | 日志只写文件 + UDP |
| `SingleInstance` | `true` | `Global\FastGithub` 互斥 |
| `PacEnabled` / `FlowStatistics` | `true` / `true` | `/proxy.pac`、`/flowStatistics` |
| `DnsEnabled` / `DnsBind` | `true` / `127.0.0.1:53` | 本地 DNS；**LAN 场景必须保持 loopback** |
| `HttpListener` / `HttpsListener` / `SshProxy` / `GitProxy` | `true` | 80 / 443 / 22 / 9418 反向代理 |
| `ConnectTimeoutSecs` / `SpeedTestIntervalSecs` | `10` / `1` | 出站超时、测速周期 |
| `Mitm.Enabled` / `CaDir` | `true` / `cacert` | CA 目录；`InstallCa` / `ConfigureGit` 恒为 `false` |
| `AdBlock.Enabled` / `StatusCode` | `true` / `200` | 广告过滤开关与命中响应码 |

### 4.3 域名策略 `DomainConfigs`

| 键 | 默认 | 作用 |
| --- | --- | --- |
| `TlsSni` | **`false`** | 出站省略 SNI；本网络对 github 系任意 SNI 都会 RST |
| `TlsSniPattern` | `@domain` | 支持 `@domain` / `@ipaddress` / `@random` |
| `TlsIgnoreNameMismatch` | `false` | MITM 下恒定跳过上游校验，字段无开关作用 |
| `IPAddress` | `null` | 强制上游 IP |
| `Destination` | `null` | 目标改写（支持路径前缀） |
| `Response` | `null` | 直接短路响应 |
| `Timeout` | `null` | `"00:02:00"` 格式 |

**关键规则**

- **github 全系（含 `*.githubassets.com` / `*.githubusercontent.com`）都显式 `TlsSni: false`**；实测发 SNI 会被立即 RST。
- 省略 `TlsSni` = `false`（省略 SNI 是本网络的安全默认）；只有 `vscode-auth.github.com` 显式设 `true`。
- 完全未配置的域名回退为 `true`（正常发 SNI）。匹配规则：`*` 只匹配一段、大小写不敏感、精确 pattern 优先。
- **Cloudflare 控制台 / 官网走直连**：`dash.cloudflare.com`、`www.cloudflare.com`、裸域 `cloudflare.com` 不在 `DomainConfigs` 中，PAC 判 `DIRECT`；只有 `cdnjs.cloudflare.com` 和 `cdn.bootcss.com` 走代理。原因见 [`docs/CLOUDFLARE-ASSESSMENT.md`](docs/CLOUDFLARE-ASSESSMENT.md)。

### 4.4 命令行参数

```bat
fastgithub.exe FastGithub.HttpProxyPort=38458
fastgithub.exe FastGithub.Silent.Mode=proxy
fastgithub.exe FastGithub.Silent.ProxyBind=0.0.0.0
fastgithub.exe regen-ca
fastgithub.exe start / stop / --service
```

---

## 5. 实现逻辑

### 5.1 请求链路

```
浏览器 ──PAC──> 127.0.0.1:38457
   │
   ├─ HTTP 明文 ──> 广告过滤? ──> Response 短路 ──> Destination 改写 ──> 上游
   │
   └─ CONNECT host:443
        └─ 本地 CA 签发 host 叶证书 ──> 终止浏览器 TLS
             └─ 解析 HTTP/1.1 ──> 独立出站 TLS 握手
                  ├─ IP：纯净 DNS + 测速选优
                  └─ SNI：TlsSni=false → ServerName::IpAddress（不发 SNI）
```

### 5.2 为什么必须是 MITM

| 事实 | 结论 |
| --- | --- |
| TLS transcript hash 覆盖 ClientHello 原文 | 中间人改写 SNI 会让两端 `Finished` 不一致 → `SEC_E_DECRYPT_FAILURE` |
| 当前网络带 `SNI=github.com` 即 RST，不带 SNI 可握手 | 必须能控制**出站** ClientHello |
| 只有自己当 TLS 客户端才能控制 ClientHello | **完整 MITM 是唯一可行路由**，`proxy` 模式不具备 SNI 控制能力 |

### 5.3 静默后台如何保证

| 机制 | 实现 |
| --- | --- |
| 无控制台窗口 | `#![windows_subsystem = "windows"]` + `FreeConsole()` |
| 无 UAC | 内嵌 `asInvoker`，禁止 `requireAdministrator` |
| 无弹窗 / 无交互 | 无 MessageBox、无 stdin、无 `println!` |
| 日志 | 仅文件 + UDP |
| 常驻 | 监听器线程 + 500ms 主循环 + 单实例互斥 + 父进程看护 |

### 5.4 端口

| 端口 | 绑定 | 用途 |
| --- | --- | --- |
| `38457/tcp` | `ProxyBind` | 正向代理 / PAC / 统计（唯一可开放到 LAN 的端口） |
| `53/udp` | `127.0.0.1` | 本地 DNS（命中域名返回 loopback） |
| `80` / `443` | `127.0.0.1` | HTTP / HTTPS 反向代理 |
| `22` / `9418` | `127.0.0.1` | SSH / git 反向代理 |

---

## 6. 快速排障

| 现象 | 先查 | 修 |
| --- | --- | --- |
| 「已重置连接」 | 进程在不在 / 38457 有无监听 | 直接启动 exe 或配置自启 |
| 同上，进程在 | `AutoConfigURL` 是否合法 URL | 设为 `http://127.0.0.1:38457/proxy.pac`，**重启浏览器** |
| 侧栏 Releases / 骨架屏不消失 | 日志里 CDN 是否 `connection timed out` / `10054` | 程序自动换 IP 重试；仍失败给该域名配 `IPAddress` 固定可达 IP |
| LAN 设备连不上 | 防火墙入站规则 / `ProxyBind` | 管理员执行 `New-NetFirewallRule`，限定 LAN 网段 |
| 证书告警 | 客户端 CA 是否为**同一份** `.cer` | 重新导入；若服务端轮换过 CA，全部客户端都要更新 |
| `totalWrite=0` | 上游请求是否发出 | 检查上游 TLS 握手；`totalWrite` 只统计发往上游的请求字节 |
| 登录 / `Confirm access` / 表单提交一直转圈 | `dist\fastgithub.exe` 是否旧版 | 升级到 **1,086,464 B** 版本；新版转发前读满请求体（含 chunked / `Expect: 100-continue`） |
| 第三方 OAuth 提示「授权失败」 | 报错页面域名是 `github.com` 还是回调域名 | 回调之后的换 token / 校验 `state` 由对方服务端完成，**不经本机代理**；重新发起一次全新授权，别复用旧 URL。详见 `docs/OAUTH-ASSESSMENT.md` |
| `install-ca.ps1` 报「字符串缺少终止符: '」+ 中文乱码 / 「缺少右 }」 | Windows 10 自带 **PowerShell 5.1** 按 ANSI(GBK) 解码**无 BOM** 的 UTF-8 脚本 | 下载 **v2.1.6+** 发布包（所有 `.ps1` 内置 UTF-8 BOM）；若自行编辑过脚本，必须「另存为 UTF-8 **带 BOM**」，或改用 PowerShell 7 (`pwsh`) |

**Releases 侧栏为什么会空白**：GitHub 新版仓库页把 `Releases / Sponsors / Used by / Contributors / Languages` 渲染成骨架屏，靠 `github.githubassets.com` 的 JS 异步填充。实测部分 CDN 节点 TCP 超时或 TLS 握手被 RST（`10054`），而旧版在第一个 IP 握手失败后直接返回 502 → JS 加载不全 → 骨架屏一直不消失。现在 TCP 或 TLS 失败都会自动换下一个测速优选 IP（最多 3 次），并优先复用上次成功的 IP；只有一个候选 IP 时立即重试一次；多 IP 时单次连接上限 5 秒，单 IP 保留完整 10 秒（压到 4 秒曾造成误判 502）。另经对照实验确认：给 github 系 CDN **发 SNI 会被立刻 RST**，所以全系域名必须省略 SNI。

**表单提交为什么会卡住**：MITM 旧版只读完请求头就把请求发给上游，剩下的 body 留在客户端 socket 里没被转发；上游按 `Content-Length` 一直等，浏览器就无限转圈。现在转发前会读满请求体，把 `chunked` 转成精确 `Content-Length`，并本地应答 `Expect: 100-continue`。

三段式验证：

```bat
curl.exe --ssl-no-revoke -x http://127.0.0.1:38457 https://github.com/   :: 程序侧
:: 系统代理侧：Invoke-WebRequest https://github.com/ -SkipCertificateCheck
:: 不带 -x 直连被 RST 属预期（SNI 阻断）
```

---

## 7. 构建与验收

```bat
scripts\build-x86.cmd
```

| 检查 | 结果 |
| --- | --- |
| `cargo check` / `test` / `build --release --target i686-pc-windows-msvc` | 全部通过 |
| 单测 | **27/27** |
| PE 校验 | `PE_VERDICT=PASS`（9 项：`0x014C` / PE32 / `WINDOWS_GUI` / `asInvoker`） |
| 端到端 | github 200、仓库页 200、CDN JS 200、POST 0.83s 返回、OAuth 授权链路完整、PAC 200、广告拦截 200/0 B、CA 轮换成功、LAN 链路 200 |

深度内容：

- [`docs/ANALYSIS.md`](docs/ANALYSIS.md) — 原项目功能边界与模块分析
- [`docs/ANALYSIS-craft-anything.md`](docs/ANALYSIS-craft-anything.md) — 证据优先调查报告
- [`docs/FEATURE-MAPPING.md`](docs/FEATURE-MAPPING.md) — 逐项功能对应表
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — 兼容性约束 C-01..C-21
- [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) — 验收用例与实测结果
- [`docs/OAUTH-ASSESSMENT.md`](docs/OAUTH-ASSESSMENT.md) — GitHub OAuth 授权失败诊断与排查清单
- [`docs/CLOUDFLARE-ASSESSMENT.md`](docs/CLOUDFLARE-ASSESSMENT.md) — Cloudflare 控制台可访问性评估

---

## 已知限制

- 仅 HTTP/1.1；无 HTTP/2、WebSocket、gRPC。每连接一个线程，面向少量设备。
- **OAuth / 第三方授权**：浏览器到 GitHub 的授权页经代理正常，但回调之后由第三方服务端用 `code` 换 token、校验 `state` 的步骤不经本机代理；报「授权失败」时重新发起一次全新授权，别复用旧 URL。详见 `docs/OAUTH-ASSESSMENT.md`。
- 出站**跳过上游证书校验**；MITM 下 HTTPS 明文在服务端可见。
- 本地 DNS 命中域名返回 `127.0.0.1`，被 `smartdns.exe` 等占用 53 端口时自动跳过，**必须显式配置 PAC**。
- Android 7+ 用户安装的 CA 默认不被 Chrome 信任（系统限制）。
- 不改 hosts / 注册表 / git 全局配置，不装驱动，不启动外部进程。
