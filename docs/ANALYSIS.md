# FastGithub 2.1.5 源码分析报告

> 方法：craft-anything 0.6.0 证据优先调查（Deep 模式，`app_source_import` 按模块生成 7 份源码图证据 + `app_folder_explain` 目录勘察），辅以逐文件静态阅读。
> 证据 id 与 10 条 findings 见 [`ANALYSIS-craft-anything.md`](ANALYSIS-craft-anything.md)。
> 边界：本次为**静态分析**，未运行原程序、未联网探测、未修改系统 hosts/证书/防火墙。因此下文「运行时行为」均为源码推断，需按 `ACCEPTANCE.md` 实测确认。

---

## 1. 功能边界

**定位**：本机 GitHub 及相关域名访问加速代理。README 明确声明：不具备「翻墙」能力、不为游戏加速、不支持 Windows 7 等已停止支持的操作系统、不额外加密流量（仅网页原有 TLS）。

**四大能力**（README「软件功能」）：

1. 提供域名的纯净 IP 解析；
2. 提供 IP 测速并选择最快的 IP；
3. 提供域名的 TLS 连接自定义配置（SNI）；
4. google 等 CDN 资源替换，解决国外站点 JS/CSS 加载问题。

**场景**：github 打不开、头像加载失败、releases 上传下载、`git clone/pull/push`、SSH/git 协议、`ajax.googleapis.com` 等 CDN。

**不属于本项目**：VPN/加密隧道、内容审查绕过、游戏加速、服务端部署（虽然有 docker-compose demo）、WPF 图形界面（可选外壳，非核心）。

---

## 2. 核心模块

8 个 `.csproj`，`net7.0`，`Directory.Build.props` 固定 `RuntimeIdentifier=win-x64`，`publish.cmd` 用 `PublishSingleFile + PublishTrimmed + self-contained` 发布。

| 程序集 | 职责 | 关键类型 |
| --- | --- | --- |
| `FastGithub`（主程序 `fastgithub.exe`） | ASP.NET Core Kestrel 宿主；配置/日志/服务装配；单实例；Windows 服务与 systemd 生命周期；父进程看护 | `Program` `Startup` `ServiceExtensions` `AppHostedService` `ConsoleUtil` |
| `FastGithub.Configuration` | 配置模型、域名通配匹配、SNI 表达式、端口探测、日志扩展 | `FastGithubOptions` `DomainConfig` `DomainPattern` `TlsSniPattern` `GlobalListener` `FastGithubConfig` |
| `FastGithub.DomainResolve` | 纯净 DNS 查询、IP 测速排序、结果缓存与持久化、dnscrypt-proxy 子进程/服务 | `DnsClient` `DomainResolver` `IPAddressService` `PersistenceService` `DnscryptProxy` `ServiceInstallUtil` |
| `FastGithub.Http` | 自定义出站 HttpClient：直连指定 IP、SNI 控制、证书名校验放宽、防自环 User-Agent | `HttpClientHandler` `HttpClientFactory` `LifetimeHttpHandler` `RequestContext` |
| `FastGithub.HttpServer` | Kestrel 监听、TLS MITM、HTTP 反向代理、PAC、CONNECT 隧道、SSH/git 反向代理、自签 CA | `KestrelServerExtensions` `CertService` `CertGenerator` `HttpReverseProxyMiddleware` `HttpProxyMiddleware` `TunnelMiddleware` `TlsInvadeMiddleware` |
| `FastGithub.PacketIntercept`（仅 Windows） | WinDivert 内核级 DNS 伪造与 TCP 端口改写；hosts/代理冲突处理 | `DnsInterceptor` `TcpInterceptor` `HostsConflictSolver` `ProxyConflictSolver` |
| `FastGithub.FlowAnalyze` | 5 秒窗口读写流量统计 | `FlowAnalyzer` `FlowStatistics` |
| `FastGithub.UI`（WPF） | 托盘/流量图/日志展示；以 `CreateNoWindow` 启动主程序并监听 UDP 日志 | `Program` `UdpLogger` `MainWindow` |

### 2.1 Windows 主链路（推断自源码）

```
应用发出 DNS 查询 (UDP:53)
   └─ WinDivert 捕获 → 命中 DomainConfigs → 伪造 A/AAAA = 127.0.0.1 / ::1 (TTL 300s)
应用连接 127.0.0.1:80/443/22/9418
   └─ WinDivert 把 loopback 端口改写到 GlobalListener 动态端口
Kestrel 监听（本地 80/443/22/9418 之后的第一个空闲端口）
   ├─ HTTP  : 反向代理（Destination 改写 / Response 直接响应）
   ├─ HTTPS : 自签 CA 签发按域名叶证书 → MITM 解密 → 自定义出站 TLS
   ├─ SSH   : → github.com:22
   └─ GIT   : → github.com:9418
出站 HttpClient
   ├─ 从 dnscrypt-proxy / FallbackDns 解析 A+AAAA（剔除回环）
   ├─ 按 TCP 建连时延排序，逐个尝试
   └─ TargetHost = TlsSniPattern（可关闭 SNI / 忽略证书名不匹配）
```

### 2.2 非 Windows 链路

仅监听 `127.0.0.1:38457` 的 HTTP 正向代理（CONNECT 隧道 + 绝对形式请求），需用户手动设置系统代理为 `http://127.0.0.1:38457`；`AppHostedService` 会检测并提示（写日志）。

---

## 3. 配置项全表

配置由 `appsettings.json` + `appsettings/appsettings.*.json` 叠加而成（`ConfigureConfiguration` 逐个 `AddJsonFile(..., optional:true, reloadOnChange:true)`）。**新增子配置文件需重启**。

### 3.1 顶层

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `FastGithub.HttpProxyPort` | int | `38457` | 非 Windows 的正向代理端口；同时作为 UDP 日志端口默认值 |
| `FastGithub.FallbackDns` | `IPEndPoint[]` | `8.8.8.8:53`, `119.29.29.29:53`, `114.114.114.114:53` | 回退 DNS，注释明确「必须要支持 tcp」 |
| `FastGithub.DomainConfigs` | `Dictionary<string, DomainConfig>` | 见下 | 域名 → 策略 |
| `AppOptions.ParentProcessId` | int | 0（由 UI 以命令行传入） | >0 时父进程退出后主动停机 |
| `AppOptions.UdpLoggerPort` | int | 38457 | Serilog UDP sink 端口 |
| `Serilog.MinimumLevel` | object | Information + 覆盖项 | 日志级别 |

### 3.2 `DomainConfig`（`FastGithub.Configuration/DomainConfig.cs`）

| 键 | 类型 | C# 默认 | 语义 |
| --- | --- | --- | --- |
| `TlsSni` | bool | **false** | 出站 TLS 是否发送 SNI。未配置但被劫持的域名用 `defaultDomainConfig = { TlsSni = true }` |
| `TlsSniPattern` | string? | null | `@domain` / `@ipaddress` / `@random` 变量，其余字符保留；`TlsSni=true` 且 null 时等价于 `@domain` |
| `TlsIgnoreNameMismatch` | bool | false | 忽略上游证书域名不匹配（无 SNI 时服务器可能返回不匹配证书） |
| `IPAddress` | IPAddress? | null | 强制使用指定上游 IP |
| `Timeout` | TimeSpan? (`"00:02:00"`) | null | 请求超时 |
| `Destination` | Uri? | null | 绝对/相对 Uri，前缀改写（CDN 替换） |
| `Response` | ResponseConfig? | null | 直接响应，`StatusCode`=200、`ContentType`=`text/plain;charset=utf-8`、`ContentValue` 可选；**设置后其他配置全部失效** |

### 3.3 域名表达式 `DomainPattern`

`*` 匹配「除 `.` 之外 0 到多个任意字符」，大小写不敏感；`SortedDictionary` 排序规则：先按 `.` 分段数升序，再从最右段向左逐段比较，`*` 视为 `char.MaxValue`（即具体名称优先于通配）。`FastGithubConfig.TryGetDomainConfig` 取第一个匹配项并缓存在 `ConcurrentDictionary`。

### 3.4 域名子配置（9 个文件，共约 60 条）

| 文件 | 代表域名 | 关键策略 |
| --- | --- | --- |
| `github.json` | `github.com` `api.github.com` `githubstatus.com` | `TlsSni=false`；`*.githubusercontent.com` 等 `TlsIgnoreNameMismatch=true` |
| `google.json` | `ajax.googleapis.com` `fonts.googleapis.com` `fonts.gstatic.com` | `Destination` 改写为 `gapis.geekzu.org` / `fonts.geekzu.org` 镜像 |
| `microsoft.json` | `*.azure.com` `*.visualstudio.com` `az764295.vo.msecnd.net` | 大量 `TlsSni=true`；VS Code CDN 改写为 `vscode.cdn.azure.cn` |
| `bootcss.json` | `cdn.bootcss.com` | 改写为 `cdnjs.cloudflare.com/ajax/libs/` |
| `amazonaws` / `fastly` / `imgur` / `v2ex` / `packages` | S3 / fastly / imgur / v2ex / nuget / maven | `TlsIgnoreNameMismatch` 或 `TlsSni` 组合 |

### 3.5 关键时间/数量常量（源码硬编码）

| 常量 | 值 | 位置 |
| --- | --- | --- |
| DNS 伪造应答 TTL | 5 分钟 | `DnsInterceptor.ttl` |
| DNS 结果 TTL 夹取 | 30s ~ 10min | `DnsClient` |
| DNS 查询超时 / TCP 探测超时 | 4s / 2s | `DnsClient` |
| DNS 服务器可用状态缓存 | 5 分钟 | `DnsClient` |
| 域名-IP 缓存 / IP 时延缓存 | 10min / 5min（本机网络故障 1min） | `IPAddressService` |
| IP 连接超时 / 出站连接超时 | 5s / 10s | `IPAddressService` / `HttpClientHandler` |
| 测速循环周期 | 1s | `DomainResolveHostedService` |
| HTTP 客户端生命周期 | 首次 10s、后续 100s | `HttpClientFactory` |
| Kestrel 关闭超时 | 1s | `Startup.ConfigureWebHost` |
| 流量统计窗口 | 5s | `FlowAnalyzer` |
| 自签 CA / 叶证书有效期 | 10 年 / 1 年 | `CertService` |
| 展示用最快 IP 数量 | 3 | `DomainResolver.MAX_IP_COUNT` |

### 3.6 端口

| 端口 | Windows | 非 Windows |
| --- | --- | --- |
| HTTP 反向代理 | `GlobalListener.HttpPort` = 从 **80** 起第一个空闲端口 | 从 3880 起 |
| HTTPS 反向代理 | 从 **443** 起 | 从 38443 起 |
| SSH 反向代理 | 从 **22** 起 | 不监听 |
| git 反向代理 | 从 **9418** 起 | 不监听 |
| HTTP 正向代理 / PAC | 不监听（走透明劫持） | `38457` |
| dnscrypt-proxy | 从 **5533** 起第一个 TCP+UDP 均空闲端口 | 同 |
| UDP 日志 | `38457`（默认） | 同 |

---

## 4. 运行依赖

| 类别 | 依赖 | 备注 |
| --- | --- | --- |
| 运行时 | .NET 7（self-contained 单文件发布） | `Directory.Build.props` 固定 `win-x64` |
| Web | ASP.NET Core / Kestrel、`Yarp.ReverseProxy` | `AddHttpForwarder()` |
| 日志 | Serilog + Console/File/Network(UDP) sinks | `logs/log.txt` 按天滚动 |
| 包 | `DNS 7.0.0`、`WindivertDotnet 1.1.2`、`Microsoft.Extensions.Hosting.WindowsServices/Systemd 7.0.0-rc*`、`PInvoke.*` | `FastGithub.PacketIntercept.csproj` |
| 内核 | **WinDivert 驱动**（`WinDivert.dll` + `WinDivert.sys`） | 需管理员安装/加载，拦截层必需 |
| 外部进程 | `dnscrypt-proxy`（仓库内 `@dnscrypt-proxy/win-x64/dnscrypt-proxy.exe` 等） | 只有 x64 / arm64 二进制，**无 x86** |
| 权限 | `app.manifest` → `requireAdministrator` | 触发 UAC |
| 系统状态 | hosts 文件、HKCU `ProxyOverride`、`LocalMachine\Root` 证书存储、`git config --global`、Windows 服务 | 启动即写入 |
| 客户端 | 需信任 `cacert/fastgithub.cer`；Firefox 需手动导入；git 需 `http.sslverify false` | README 第 4/5 节 |

---

## 5. 行为约束（重写必须遵守 / 必须权衡）

1. **管理员 + UAC**：透明劫持依赖 WinDivert 内核驱动，`requireAdministrator` 会在每次启动弹 UAC；与「无弹窗、无交互提示」直接冲突。
2. **会修改系统状态**：hosts 冲突行被注释、写 `ProxyOverride` 并 `InternetSetOption`、安装根证书、关闭 git 全局 SSL 校验、安装/删除 Windows 服务（含 `FastGithub.dnscrypt-proxy` 服务）。
3. **自签 CA 每台机器独立**：`cacert/fastgithub.cer` + `fastgithub.key`，需客户端无条件信任；私钥泄露有风险。
4. **DNS 污染兜底**：`HttpReverseProxyMiddleware` 对「未配置但解析到本机的域名」使用 `TlsSni=true` 的默认策略并打警告，防止死循环。
5. **防自环**：出站 `User-Agent` 追加 `FastGithub/1.0`，检测到已带标记即中断转发；响应追加 `Server: FastGithub`。
6. **单实例**：`Global\FastGithub` 互斥；UI 另有 `Global\FastGithub.UI`。
7. **配置热加载**：`IOptionsMonitor.OnChange` 更新 `FastGithubConfig` 并 `DnsFlushResolverCache`；但新增子配置文件不生效，需重启。
8. **父进程看护**：UI 传 `ParentProcessId`，父进程退出则 `host.StopAsync`。
9. **启动失败策略**：`HttpProxyPort` 被占用时抛 `FastGithubException` 终止；DNS/TCP 拦截器异常（除 `ERROR_OPERATION_ABORTED` 995）会导致整个 host 停止。
10. **平台差异**：Windows 走透明劫持；Linux/macOS 走显式正向代理 + 手动 PAC；`Environment.UserInteractive == false` 时 dnscrypt-proxy 以服务方式安装。
11. **不支持 Win7**；`README` 明确声明。

---

## 6. 对 32 位 x86 + 静默后台的直接影响

| 约束 | 结论 |
| --- | --- |
| 仓库只有 `win-x64` 的 `dnscrypt-proxy.exe` | x86 版不能依赖外部 DNS 代理进程，需自带 DNS 客户端（Rust 版已实现） |
| 无 x86 WinDivert 驱动产物，且驱动安装需管理员 | 不能 1:1 复刻包拦截，必须换用等价机制（Rust 版：本地 DNS 监听 + 直接绑定低端口） |
| `requireAdministrator` | 必须改为 `asInvoker`，否则每次启动弹 UAC |
| 自签 CA 需写入 `LocalMachine\Root` | 需管理员；静默后台不应修改系统，故默认不启用 MITM |
| `git config --global` / `Process.Start` | 会产生子进程/潜在窗口，静默版不应执行 |
| WPF UI | 与「无弹窗」冲突，不移植 |

详见 [`COMPATIBILITY.md`](COMPATIBILITY.md) 与 [`FEATURE-MAPPING.md`](FEATURE-MAPPING.md)。
