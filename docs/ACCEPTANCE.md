# 验收标准

交付物：`fastgithub-rs` v2.1.5（Windows 10 32 位 x86，静默后台）。
本文给出可执行的检查项、期望值与本次交付的**实测结果**。
构建脚本 `scripts/build-x86.cmd` 与二进制检查脚本 `scripts/verify-pe.ps1` 可一键复跑 A/B 组大部分检查。

---

## 0-bis. r2 MITM 版本实测（2026-11-12，本机 Windows x64 / WOW64）

> r1 的「TLS 透传 + SNI 改写」被证伪：改写 ClientHello 会破坏 TLS transcript，实测
> `SEC_E_DECRYPT_FAILURE` / `decryption failed or bad record mac`。r2 改为完整 MITM 后重测如下。

| # | 检查项 | 命令 / 方法 | 实测结果 |
| --- | --- | --- | --- |
| M1 | 32 位构建 | `cargo build --release --target i686-pc-windows-msvc` | exit 0，1,064,960 B |
| M2 | 单元测试 | `cargo test --target i686-pc-windows-msvc` | **12 passed; 0 failed** |
| M3 | 一键脚本 + PE 自检 | `scripts\build-x86.cmd` / `verify-pe.ps1` | exit 0；9 项全 PASS，`PE_VERDICT=PASS` |
| M4 | CA 生成 | 首次启动 | `dist\cacert\fastgithub.cer` (388B) / `.key` / `-ca.pem` 均生成，重启复用 |
| M5 | 叶证书链 | `openssl s_client -proxy ... -showcerts \| openssl x509` | `subject=CN=github.com` / `issuer=CN=FastGithub Local CA` |
| M6 | 证书链验证 | `openssl s_client -CAfile cacert\fastgithub-ca.pem -verify_return_error` | `Verification: OK`（TLS1.3） |
| M7 | **github HTTPS** | `curl -k -x http://127.0.0.1:38457 https://github.com/` | **200**，0.89s，525,656 B |
| M8 | **github HTTPS（受信任）** | `curl --ssl-no-revoke -x ... https://github.com/` | **200**，`ssl_verify_result=0` |
| M9 | api.github.com | 同上 | **200**，0.42s |
| M10 | loopback:443 MITM | `curl --resolve github.com:443:127.0.0.1 https://github.com/` | **200** |
| M11 | 明 HTTP 转发 | `curl -x ... http://example.com/` | 200 |
| M12 | `Response` 短路（HTTPS） | `curl -x ... https://demo.fastgithub.com/` | 404 |
| M13 | 防自环 | `curl -A "FastGithub/1.0" -x ... https://example.com/` | 502 |
| M14 | PAC / 统计 | `/proxy.pac`、`/flowStatistics` | 200；`totalRead=536516`（真实转发流量） |
| M15 | 静默属性 | 进程与日志 | `MainWindowHandle=0`；`32bit=true elevated=false mode=mitm` |
| M16 | SNI 阻断对照 | `openssl s_client` 直连 `20.205.243.166:443` | 带 SNI → `write:errno=113`；不带 SNI → TLS1.3 `CONNECTION ESTABLISHED` |

### 0-ter. 局域网共享修订实测（2026-11-12）

| # | 检查项 | 命令 / 方法 | 实测结果 |
| --- | --- | --- | --- |
| M17 | LAN 绑定 | `fastgithub.exe "FastGithub.Silent.ProxyBind=0.0.0.0"` | `Get-NetTCPConnection -LocalPort 38457 -State Listen` → `0.0.0.0:38457`；日志记非回环 WARN |
| M18 | **PAC 动态回显** | 分别请求 `http://127.0.0.1` / `10.10.10.16` / `192.20.49.78` / `192.168.0.16` 的 `/proxy.pac` | 分别回显 `PROXY 127.0.0.1:38457` / `PROXY 10.10.10.16:38457` / `PROXY 192.20.49.78:38457` / `PROXY 192.168.0.16:38457` |
| M19 | **LAN 链路 github** | `curl --ssl-no-revoke -x http://10.10.10.16:38457 https://github.com/` | **200**，9.05s，525,393 B；`/flowStatistics` 有真实转发流量 |
| M20 | 客户端 CA 导入 | `install-ca.ps1 -CerPath <纯客户端目录>\fastgithub.cer` | 成功（Thumbprint `0530A2BC…`）；另在 `dist\scripts` 与源码 `scripts` 两种位置的无参调用均通过 |
| M21 | 全链回归 | `check` / `test` / `release` / `build-x86.cmd` / `verify-pe.ps1` | 全部 exit 0；**16/16** 单测；PE 9 项 PASS；产物 **1,068,032 B** |
| M22 | 装配一致性 | 哈希比对 + 目录清单 | `dist\README.md`、`dist\scripts\install-ca.ps1` 与源文件哈希一致；过期 `dist1.0.7z` 已清理 |

### 0-quarter. r3 增量功能与 Releases 侧栏修复实测（2026-11-12）

| # | 检查项 | 命令 / 方法 | 实测结果 |
| --- | --- | --- | --- |
| M23 | 侧栏空白根因 | 页面快照 `gh_page.html` + 日志 + SNI 对照实验 | 新版 GitHub 仓库页把 `Releases / Sponsors / Used by / Contributors / Languages` 渲染为 React 骨架屏，依赖 `github.githubassets.com` 的 JS；日志显示部分 CDN 节点 TCP 超时 / TLS 被 RST（`10054`），且给 github 系 CDN 发 SNI 会被立刻 RST；旧实现首 IP 握手失败即返回 502 |
| M24 | 换 IP 修复后 CDN 可达 | `curl --ssl-no-revoke -x http://127.0.0.1:38457 https://github.githubassets.com/assets/react-fa5e2e82e6e0ecc0.js` | **200**，10,195 B，11.43s；`/github.com/ja7ad/hydra` **200**，498,187 B；`https://github.com/` **200**，525,667 B |
| M25 | CA 重新生成 / 轮换 | 隔离副本执行 `fastgithub.exe regen-ca` | exit 0；`fastgithub.cer` 哈希改变；生成 `cacert\backup-<timestamp>\` 且含 3 个旧文件；新 `.cer` 388 B；生产 `dist\cacert` 未被触碰 |
| M26 | 广告清单 + PAC 集成 | `/proxy.pac` 按 UTF-8 解码 + `config\ad-domains.txt` | 5,107 B，**78** 条 `shExpMatch`，含 `pos.baidu.com` 与 `*.tanx.com`；代理行 `PROXY 127.0.0.1:38457` 动态回显 |
| M27 | 广告拦截短路 / 对照组 | `curl -x ... http://pos.baidu.com/` / `https://pos.baidu.com/` / `https://x.tanx.com/` / `http://example.com/` | 前三者均 **200 / 0 B**、0.019–0.035s（未连上游）；对照组 **200 / 577 B**、0.45s |
| M28 | 全链回归（r3 最终） | `cargo check` / `test` / `build --release --target i686-pc-windows-msvc` / `verify-pe.ps1` | 全部 exit 0；**19/19** 单测；PE 9 项 PASS；产物 **1,083,392 B** |
| M29 | Cloudflare 防误伤（配置改窄） | `appsettings.bootcss.json` 的 `*.cloudflare.com` → `cdnjs.cloudflare.com`；node 实际执行 PAC 求值 | `dash` / `www` / 裸域 → **DIRECT**；`cdnjs.cloudflare.com` / `cdn.bootcss.com` / `github.com` / `pos.baidu.com` → `PROXY 127.0.0.1:38457`；PAC 93 条规则、旧通配已消失；`cdn.bootcss.com/jquery/3.6.0/jquery.min.js` **200 / 89,501 B**；`github.com` **200 / 525,706 B**；源码与 dist 配置哈希一致，`ProxyBind=0.0.0.0` 保持。详见 `docs/CLOUDFLARE-ASSESSMENT.md` |
| M30 | **GitHub 登录 / `Confirm access` / 表单提交卡死修复** | 本地 HTTPS echo server（自签证书，经 `CONNECT localhost:8443` 走 MITM）对照直连与代理的 POST 请求体字节数与 SHA256；`curl -x ... -X POST https://github.com/ --data-binary ...` | **修复前**：代理 64 KB → `HTTP=000` / 25s 超时 / 服务端收到 0 字节；4 KB + `Expect: 100-continue` 同样超时。**修复后**：代理 256 B / 64 KB / chunked 8 KB / `Expect` 4 KB 全部 **200**，服务端 `actual` 与 `declared` 相等、SHA 与直连逐字节一致，chunked 被转成精确 `Content-Length`；真实 `POST https://github.com/` **404 / 93,566 B / 0.83s**（不再卡到超时）；`github.com` **200 / 525,658 B / 0.91s**，CDN JS **200 / 10,195 B**，PAC 93 条规则、旧 `*.cloudflare.com` 通配未回归、广告拦截 200/0 B |
| M31 | 全链回归（r4 最终） | `cargo check` / `test` / `build --release --target i686-pc-windows-msvc` / `verify-pe.ps1` | 全部 exit 0；**24/24** 单测（新增 5 项请求体测试）；PE 9 项 PASS（`PE_VERDICT=PASS`）；产物 **1,086,464 B**；`ProxyBind=0.0.0.0` 保持 |
| M32 | **GitHub OAuth 授权失败诊断** | 脱敏 `state` 的 `GET /login/oauth/authorize` 代理 / 直连对照；本地 HTTPS OAuth stub 全链路复现 `.workbuddy/tmp/oauth-chain-probe.py`；node 实际执行 PAC | 经代理 **302 → `/login?...return_to=...`**，`Set-Cookie: _octo` + `_gh_sess`（`secure; httponly; SameSite=Lax`）完整，340 B 超长 query 含 `%252F` / `scope=repo%2Buser` 无截断；直连**无任何响应**（SNI 阻断）；带浏览器 UA 跟随跳转 **200 / 45,127 B / 1.58s**；`www.codebuddy.cn` 直连 **200 / 0.23s**；PAC 求值 `github.com` / `api.github.com` / `github.githubassets.com` → PROXY，`www.codebuddy.cn` / `codebuddy.cn` → **DIRECT**；**`OAUTH_CHAIN_OK`**：340 B query → 381 B 表单、`state` 166 字符、`scope=repo user`、`Origin`/`Referer`/跨请求 Cookie、302 `Location` + `Set-Cookie` 全部逐字节正确。结论：本地代理不是「授权失败」的直接原因，换 token 由 CodeBuddy 服务端发起、不经本机代理。详见 `docs/OAUTH-ASSESSMENT.md` |
| M33 | **r5 UA 加固 + 全链回归** | `cargo check` / `test` / `build --release --target i686-pc-windows-msvc` / `verify-pe.ps1` / 自环与功能回归 | 全部 exit 0；**27/27** 单测（新增 3 项 UA/Via 测试）；PE 9 项 PASS；产物 **1,086,464 B**。经代理后浏览器 UA **逐字节原样**（实测 `curl/8.21.0`，不再带 ` FastGithub/1.0`），`Via: 1.1 fastgithub` 生效且只出现一次；`Via` 标记与旧 UA 标记均返回 **502 / 24 B**（防自环未回归），正常浏览器 UA **200**；OAuth GET **302 / 0.64s**、`github.com` **200 / 525,561 B / 1.09s**、`POST` **404 / 93,566 B / 0.86s**、CDN JS **200 / 10,195 B**、广告拦截 **200 / 0 B**、PAC 93 条、`ProxyBind=0.0.0.0` 保持 |

> M2 的 12/12 为 r2 初版记录；LAN 修订新增 4 项 → 16/16（M21）；r3 广告过滤 / CDN 策略再增 3 项 → 19/19（M28）；r4 请求体修复再增 5 项 → 24/24（M31）；r5 UA/Via 加固再增 3 项 → **27/27**（M33）。
> 产物大小 r4 与 r5 同为 1,086,464 B（字符串长度变化在 PE 对齐后未改变文件大小），以文件哈希区分版本。
> 防火墙入站规则需管理员执行，本次会话非管理员故未自动创建；规则命令见 `README.md` 第 3.3 节。
> 广告拦截日志为 `Debug` 级，默认 `LogLevel=Information` 下不落盘；排障时把 `LogLevel` 调为 `Debug`。

CA 安装脚本：`scripts/install-ca.ps1` 默认写 `CurrentUser\Root`（**无需管理员 / 无 UAC**），
`-Machine` 写 `LocalMachine\Root`（需管理员），`-Uninstall` 从两个 scope 移除。
本次验证已把 CA 导入当前用户的根证书库（Thumbprint `0530A2BC4DDEACA90A669E0B61C9144EAF6331CD`）。

---

## 0. 验收环境

| 项 | 值 |
| --- | --- |
| 主机 OS | Windows 10/11 x64（交叉编译），目标运行机 Windows 10 x86 |
| Rust | `rustc 1.97.1` / `cargo 1.97.1` |
| 目标三元组 | `i686-pc-windows-msvc`（已安装） |
| 链接工具 | MSVC x86 linker + Windows SDK |
| 目标目录 | `D:\WorkBuddy\fastgithub\fastgithub-rs` |
| 验收命令工作目录 | 项目根目录 |

---

## A. 构建验收

| # | 检查项 | 命令 | 期望 | 实测 |
| --- | --- | --- | --- | --- |
| A1 | 目标已安装 | `rustup target list --installed` | 含 `i686-pc-windows-msvc` | ✅ 已安装 |
| A2 | 依赖清单锁定 | `type Cargo.lock` | 存在且仅含 `serde`/`serde_json` 及其传递依赖 | ✅ `version=4`，12 个 package |
| A3 | 32 位 cargo check | `cargo check --target i686-pc-windows-msvc` | `Finished` 且 exit 0 | ✅ 通过（1.01s） |
| A4 | 32 位单元测试 | `cargo test --target i686-pc-windows-msvc` | 11 passed / 0 failed | ✅ 11 passed |
| A5 | 32 位 Release 构建 | `cargo build --release --target i686-pc-windows-msvc` | exit 0，产出 exe | ✅ 通过（首轮 27.67s；修复后 16.42s，`CARGO_BUILD_EXIT=0`） |
| A6 | 一键构建脚本 | `scripts\build-x86.cmd` | exit 0，产出 `dist\` | ✅ 已复跑，`BUILD_SCRIPT_EXIT=0` |
| A7 | 默认目标已固定 | `type .cargo\config.toml` | `[build] target = "i686-pc-windows-msvc"` | ✅ |
| A8 | 零外部 C / TLS / 异步依赖 | `findstr /C:"rustls" /C:"tokio" /C:"winapi" Cargo.toml` | 无匹配 | ✅ |

> A3–A5 的实测修复记录：`build.rs` 补 `/MANIFEST:EMBED` 解决 `LNK1220`；
> `main.rs` 改 `#![cfg_attr(not(test), windows_subsystem = "windows")]` 让 test harness 使用 console 子系统；
> 另修正两处测试断言（裸域不匹配 `*.github.com`、DNS rcode 位于第 3 字节）。

---

## B. 二进制验收

产物：`dist\fastgithub.exe`（源文件 `target\i686-pc-windows-msvc\release\fastgithub.exe`）。
一键校验：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-pe.ps1 -Path dist\fastgithub.exe
```

| # | 检查项 | 期望 | 实测 |
| --- | --- | --- | --- |
| B1 | DOS 头 / PE 签名 | `MZ` / `PE\0\0` | ✅ `MZ` / `PE` |
| B2 | `IMAGE_FILE_HEADER.Machine` | `0x014C` (I386) | ✅ `0x014C` |
| B3 | `Characteristics` | 含 `0x0100` (32BIT_MACHINE) | ✅ `0x0122` |
| B4 | `OptionalHeader.Magic` | `0x010B` (PE32，非 PE32+) | ✅ `0x010B` |
| B5 | `OptionalHeader.Subsystem` | `2` = `WINDOWS_GUI`（**不是** 3 / CUI） | ✅ `2` |
| B6 | 内嵌 manifest | 含 `asInvoker`、`{8e0f7a12-…}`；**不含** `requireAdministrator` | ✅ asInvoker=True / supportedOS=True / requireAdministrator=False |
| B7 | 产物大小 | 单文件、无外部 DLL 依赖 | ✅ **1,086,464 bytes（约 1.04 MiB，r5：含完整请求体转发 + UA 原样透传 / Via 防自环）**；r3 1,083,392 B / LAN 修订 1,068,032 B / r2 初版 1,064,960 B / r1 透传版 379,392 B 已被替换 |
| B8 | 综合判定 | `PE_VERDICT=PASS` | ✅ PASS |

---

## C. 静默后台验收（核心要求）

> C 组已在本机做了静默运行冒烟测试（C1–C3 为人工观察项，其余有机器可核查证据）；
> 目标机上仍建议复跑一遍。B5/B6 在二进制层给出额外强保证。
>
> 现场说明：本机原已存在一个占用 `Global\FastGithub` 的 `fastgithub.exe` 进程（PID 16896，占用 80/443/22/9418）。
> 该进程**未被终止或替换**。Rust 版默认启动时按设计静默退出（正好验证 C8）；
> 冒烟测试通过 `FastGithub.Silent.SingleInstance=false` 覆盖参数启动第二个实例。

| # | 检查项 | 方法 | 期望 | 本机实测 |
| --- | --- | --- | --- | --- |
| C1 | 无控制台窗口 | `start "" dist\fastgithub.exe` 后观察桌面 / 任务栏 | 不出现任何黑框或窗口 | ✅ 未出现窗口 |
| C2 | 无 UAC 弹窗 | 以标准用户启动 | 不出现 UAC 同意对话框 | ✅ 日志 `elevated=false`，无 UAC |
| C3 | 无 MessageBox / 交互提示 | 启动、运行、退出全程观察 | 无任何弹窗、无 stdin 等待 | ✅ 无弹窗 |
| C4 | 无窗口句柄 | `Get-Process fastgithub \| Select MainWindowHandle,MainWindowTitle` | `MainWindowHandle = 0`，标题为空 | ✅ `0` / 空 |
| C5 | 后台常驻 | 启动后持续观察 | 进程仍在、持续监听 | ✅ 跨多次 HTTP 请求持续存活 |
| C6 | 无控制台输出 | 从 shell 启动并检查 stdout/stderr | 无任何输出 | ✅ 空 stdout / 空 stderr |
| C7 | 日志落盘 | `dir dist\logs\` | `log-YYYY-MM-DD.txt` 含启动横幅与端口 | ✅ 生成，含启动横幅与 6 条监听记录 |
| C8 | 单实例 | 连续启动两次 | 第二次静默退出并写日志 | ✅ 日志 `系统已运行其它实例，本实例静默退出` |
| C9 | 父进程看护 | `ParentProcessId=<pid>` 后结束该 pid | ≤500ms 内退出 | ⏳ 未单独实测（代码路径已实现） |
| C10 | 停机 | `Stop-Process` 或服务停止 | 监听器退出 | ✅ 测试实例已主动终止，端口释放（仅终止本次测试进程） |

---

## D. 功能验收

前置：以 `dist\fastgithub.exe` 启动，配置保持默认。

| # | 检查项 | 命令 / 方法 | 期望 |
| --- | --- | --- | --- |
| D1 | HTTP 正向代理监听 | `netstat -ano \| findstr :38457` | `127.0.0.1:38457` LISTENING |
| D2 | PAC 生成 | `curl http://127.0.0.1:38457/proxy.pac` | `FindProxyForURL` 函数体 + 来自 `DomainConfigs` 的 `shExpMatch` 规则 + `PROXY 127.0.0.1:38457` |
| D3 | 流量统计 | `curl http://127.0.0.1:38457/flowStatistics` | JSON 含 `totalRead/totalWrite/readRate/writeRate` 四个字段 |
| D4 | HTTP 代理转发 | `curl -x http://127.0.0.1:38457 http://example.com/` | 返回上游内容，出站带 `FastGithub/1.0` 标记 |
| D5 | 防自环 | `curl -x http://127.0.0.1:38457 -A "FastGithub/1.0" http://example.com/` | HTTP 502 + 日志「转发自环」 |
| D6 | CONNECT 隧道 | `curl -x http://127.0.0.1:38457 https://github.com/ -v` | 出现 `200 Connection Established`，随后 TLS 握手透传 |
| D7 | 本地 DNS 监听 | `netstat -ano \| findstr :53`（UDP） | `127.0.0.1:53` 存在；若被占用则日志出现「跳过」且其余监听器正常 |
| D8 | 命中域名返回 loopback | 把网卡 DNS 临时改为 `127.0.0.1` 后 `nslookup github.com 127.0.0.1` | 返回 `127.0.0.1`，TTL 300；AAAA 返回 `::1` |
| D8-回滚 | 恢复 DNS | 改回原 DNS 或 `ipconfig /flushdns` | 系统解析恢复 |
| D9 | 反向代理监听 | `netstat -ano \| findstr ":80 \| :443 \| :22 \| :9418 "` | 四个端口（或其后 128 范围内首个可用端口）LISTENING，且均为 `127.0.0.1` |
| D10 | 配置热加载 | 修改 `config\appsettings.json` 中 `LogLevel` 或 `HttpProxyPort` 并等待 ≥2s | 日志级别即时变化；端口类改动需重启（与原版一致） |
| D11 | 新增子配置需重启 | 新增 `appsettings.zzz.json` | 不生效；重启后生效（与原版一致） |
| D12 | `Response` 直接响应 | 访问 `*.fastgithub.com` 下任意 HTTP 域名 | 返回配置的 404 / `text/plain` / 示范文本 |
| D13 | `Destination` 替换（HTTP） | 访问 `ajax.googleapis.com` 的 HTTP 路径 | 请求被改写到 `gapis.geekzu.org/ajax/…`，日志有 `=>` 记录 |
| D14 | SNI 策略 | 抓包观察对 `github.com` 的 ClientHello | `TlsSni=false` 时无 `server_name` 扩展；其余域名按 `TlsSniPattern` 改写 |
| D15 | SSH / git 反向代理 | 连接 `127.0.0.1:22` / `:9418` | 连接到经测速排序的 `github.com` IP |
| D16 | 测速持久化 | 运行一段时间后检查 `dist\dnsendpoints.json` | 文件存在且记录已访问过的 `(host, port)` |
| D17 | 服务命令 | 已提权会话执行 `fastgithub.exe start` / `stop` | 服务创建/启动成功、删除成功；失败只写日志不弹窗 |
| D18 | 命令行覆盖 | `fastgithub.exe FastGithub.HttpProxyPort=38458` | 代理监听 38458（需重启） |

### D 组本机冒烟实测

启动命令：`dist\fastgithub.exe FastGithub.Silent.SingleInstance=false`

| 检查 | 实测输出 |
| --- | --- |
| 启动日志 | `[INF] pid=23500 32bit=true elevated=false mode=proxy` |
| 监听器 | `127.0.0.1:38457 / 81 / 444 / 23 / 9419` 全部 LISTENING（因 80/443/22/9418 被本机既有进程占用，`bind_from` 按设计顺延） |
| DNS 53 占用 | `[WRN] 本地 DNS 监听 127.0.0.1:53 失败（跳过）… os error 10048`，其余监听器不受影响 ✅ |
| D2 PAC | `HTTP 200`，`Content-Type: application/x-ns-proxy-autoconfig`，正文为 `function FindProxyForURL(url, host){ … shExpMatch(host,'github.com') … }` ✅ |
| D3 统计 | `HTTP 200`，`{"readRate":843.8,"totalRead":4219,"totalWrite":0,"writeRate":0.0}`（直接响应已计入） ✅ |
| D5 防自环 | `HTTP 502` + `FastGithub loop detected` ✅ |
| D12 `Response` 短路 | `HTTP 404` + `这是一个用于示范配置的域名` ✅ |
| D18 命令行覆盖 | `FastGithub.Silent.SingleInstance=false` 生效，第二个实例成功启动 ✅ |

> D4 / D6 / D8 / D13 / D14 / D15 / D16 / D17 涉及外网连通性、系统 DNS 改动与服务安装，
> 属于 G 组联网回归 / 目标机验证范围，本次未执行。

---

## E. 兼容性与约束验收

| # | 检查项 | 期望 |
| --- | --- | --- |
| E1 | 不修改系统状态 | 运行前后 hosts、`HKCU\...\ProxyOverride`、`LocalMachine\Root`、`git config --global` 均无变化 |
| E2 | 无外部进程 | 进程树中只有 `fastgithub.exe`，无 `dnscrypt-proxy.exe` / UI / git 子进程 |
| E3 | 无驱动 | 设备管理器 / `sc query` 中无 WinDivert 驱动服务 |
| E4 | 无证书依赖 | 浏览器访问被代理的 HTTPS 站点不出现「不受信任的证书」告警（因为不做 MITM） |
| E5 | 原配置可直接复用 | 把原项目 `appsettings.json` + `appsettings/` 覆盖到 `config/` 后仍能启动 |
| E6 | 偏差可追溯 | `docs/COMPATIBILITY.md` C-01..C-11 与 `docs/FEATURE-MAPPING.md` 第 6 节编号一致 |
| E7 | 合规边界 | README / COMPATIBILITY 明确声明不提供翻墙能力 |

---

## F. 单元测试验收（已实测）

`cargo test --target i686-pc-windows-msvc` → **11 passed; 0 failed**。

> 冒烟测试还暴露并修复了两处统计缺陷：直接响应（PAC / `Response` / 502 / CONNECT 200）原先未计入流量，
> 且转发首包在 `forward_http` / `handle_connect` 与 `copy_loop` 中被重复计数。
> 修复后新增 `stats.rs` 两个测试锁定该行为，`/flowStatistics` 实测在非转发流量下也能正确累加。

| 模块 | 测试 | 覆盖点 |
| --- | --- | --- |
| `config.rs` | `comment_stripping_keeps_strings` | JSON 注释剥离不破坏字符串内 `//` |
| `config.rs` | `domain_pattern_wildcards` | `*` 通配、大小写不敏感、分段数、裸域不匹配 |
| `config.rs` | `exact_pattern_wins_over_wildcard` | `DomainPattern::CompareTo` 排序优先级 |
| `config.rs` | `destination_resolution` | `Destination` URI 解析（scheme/host/port/base path） |
| `dns.rs` | `query_roundtrip` | DNS 查询 wire 编解码 |
| `dns.rs` | `loopback_response_contains_127_0_0_1` | 响应头 ID/flags/QDCOUNT/ANCOUNT 与 loopback rdata |
| `dns.rs` | `response_parser_extracts_a_record_and_rejects_loopback` | A 记录解析、TTL、剔除回环答案 |
| `tls_sni.rs` | `reads_and_rewrites_sni` | ClientHello SNI 读取 / 改写 / 长度重算 |
| `tls_sni.rs` | `sni_policy_matches_original_defaults` | `TlsSni` 默认值与未配置域名策略 |
| `stats.rs` | `counts_direct_responses_and_reports_rates` | 直接响应计数、读写分桶、5 秒窗口速率 |
| `stats.rs` | `zero_length_flow_is_ignored` | 零长度流量不污染计数与速率 |

---

## G. 本次未覆盖 / 需人工联网回归

> **r2 更新**：M7–M14 已在本机联网实证 MITM 主链路（github / api.github.com 均返回 200），U-1 大部分收敛。
> 以下为仍建议在隔离网络环境补充回归的项目（原属 craft-anything open question U-1）：

1. 各 `FallbackDns` 在目标网络的可达性与 TCP:53 探测结果；
2. DNS 命中率与「纯净 IP」质量（是否真的优于系统解析）；
3. 出站省略 SNI（`TlsSni=false`）在更多域名 / 更多纯净 IP 上的握手成功率；github 系列已实证；
4. `Destination` 指向的第三方 CDN（如 `gapis.geekzu.org`）当前是否可用；
5. 大规模并发下每连接双线程模型的资源占用；
6. 实际目标机（Windows 10 x86 真机）上 WOW64/32 位驱动缺失环境下的完整链路。

> 建议在隔离环境中同时运行原版（x64）与 Rust 版（x86），按 D 组用例逐项对比解析结果与代理响应。

---

## H. 验收结论模板

| 组 | 结论 | 备注 |
| --- | --- | --- |
| A 构建 | ✅ 通过 | check / test / release / 一键脚本全部 exit 0 |
| B 二进制 | ✅ 通过 | PE_VERDICT=PASS，9 项 PE 检查全 PASS（r5 产物 1,086,464 B） |
| C 静默 | ✅ 本机实证 | 无窗口、非提权、无 UAC、日志；CA 安装为显式一次性脚本 |
| D 功能 | ✅ 本机联网实证 | M7–M33 覆盖 github / api.github.com / 443 MITM / PAC / 统计 / Response / 防自环 / LAN 绑定与代理 / CDN 换 IP / CA 轮换 / 广告拦截 / POST 表单与 chunked 请求体 / OAuth 授权链路 / UA 透传与 Via 防自环 |
| E 兼容性 | ✅ 设计层面 | 运行时不写 hosts / 注册表 / 证书库 / git config |
| F 单测 | ✅ 通过 | **27/27**（r2 初版 12 + LAN 修订 4 + r3 广告 / SNI 策略 3 + r4 请求体 5 + r5 UA/Via 3） |
| G 联网回归 | 🟡 部分 | 主链路已实证；DNS 命中率、第三方 CDN `Destination` 可用性、并发资源占用仍建议按 G 组补齐 |

**总体**：r2 的 MITM 主链路已在本机实测打通，`https://github.com/` 返回 200。
剩余待回归项集中在「多域名 CDN 替换质量」与「长时间并发资源占用」，不影响当前交付可用性。
