# GitHub OAuth 授权失败诊断（CodeBuddy Connector）

> 日期：2026-11-12 · 对象：`fastgithub-rs` r4 → r5 · 诊断方式：脱敏 URL 对照 + 本地 HTTPS OAuth stub 全链路复现
> **没有使用用户的真实 `state`、账号或凭据去请求任何外部服务。**

---

## 1. 结论速览

**本地代理不是「授权失败」的直接原因。** 经代理的 OAuth 三段链路已用本地 echo 完整复现并通过：长 query、POST 表单、Cookie 会话、`302 Location`、`Set-Cookie` 全部逐字节正确。

「授权失败」是中文文案，几乎可以确定来自 **`www.codebuddy.cn` 的回调页**（GitHub 自身页面为英文，报错形如 `Authorization failed` / `redirect_uri mismatch`）。而回调之后的关键一步——**CodeBuddy 服务端拿 `code` 去换 `access_token`——是服务器到 GitHub 的请求，完全不经过你本机的代理**。这一步失败时，本地代理帮不上忙。

代理侧仍有两个间接影响因素，已分别给出处理和加固：

| 因素 | 影响 | 处理 |
| --- | --- | --- |
| `github.com` 只有单个上游 IP 且间歇超时 | 授权页提交被拖慢 → 一次性 `state` 过期 | 重新发起一次全新授权；见 §5 |
| 浏览器 UA 被追加 ` FastGithub/1.0` | GitHub 设备验证 / 风控可能视作新设备 | **已加固**：改用标准 `Via` 防自环，UA 原样透传（§6） |

---

## 2. 实测证据

| # | 检查 | 命令 / 方法 | 结果 |
| --- | --- | --- | --- |
| E1 | 授权端点经代理 | `curl --ssl-no-revoke -x http://127.0.0.1:38457 'https://github.com/login/oauth/authorize?...'`（脱敏 state） | **302 → `/login?...return_to=...`**；`Set-Cookie: _octo=...` + `_gh_sess=...`（`secure; httponly; SameSite=Lax`）；340 B 超长 query 含 `%252F` 双重编码与 `scope=repo%2Buser` 完整保留 |
| E2 | 授权端点直连 | 同上，不带 `-x` | **无任何响应**（SNI 阻断），证明必须走代理 |
| E3 | 带浏览器 UA 跟随跳转 | `-L -A "Mozilla/5.0 ... Chrome/131"` | 落到 `https://github.com/login?...`，**200 / 45,127 B / 1.58s**，页面含 `Sign in`（curl 无用户 session，属预期） |
| E4 | 换 token 端点 | `POST https://github.com/login/oauth/access_token` 经代理 | 首次 **502 / 10.1s**（上游超时），随后两次 **404 / 5.7s**；间歇性，非稳定失败 |
| E5 | 回调域名直连 | `https://www.codebuddy.cn/` | **200 / 0.23s** |
| E6 | PAC 实际求值 | node 执行 `FindProxyForURL` | `github.com` / `api.github.com` / `github.githubassets.com` → `PROXY 127.0.0.1:38457`；`www.codebuddy.cn` / `codebuddy.cn` → **DIRECT** |
| E7 | **OAuth 全链路复现** | `.workbuddy/tmp/oauth-chain-probe.py`（本地 HTTPS stub 模拟 github.com） | **`OAUTH_CHAIN_OK`**，详见 §3 |
| E8 | 用户操作时段日志 | `14:12–14:16` | 2 条上游失败：`185.199.109.215:443 connection timed out`、`github.com TLS os error 10060 换下一个 IP` |
| E9 | 交付实例核对 | 文件 / 进程 / 注册表 | exe **1,086,464 B**（r4 修复版，13:48）、PID 4272（14:07 启动）、监听 `0.0.0.0:38457`、`AutoConfigURL=http://127.0.0.1:38457/proxy.pac`、`ProxyEnable=0`（PAC 模式正常） |

---

## 3. OAuth 全链路复现（`OAUTH_CHAIN_OK`）

本地 HTTPS server 充当 `github.com`，curl 经 `CONNECT localhost:8443` 走真实 MITM：

```
STEP 1  GET /login/oauth/authorize?... (340 B query)
        → 302 + Set-Cookie: _gh_sess=STUB_SESSION_123; SameSite=Lax
        服务端见到：query_len=340, path=/login/oauth/authorize, Host=localhost:8443

STEP 2  POST /login/oauth/authorize (381 B urlencoded form)
        Header: Origin / Referer / Content-Type / Cookie(_gh_sess=...)
        → 302 + Location: https://www.codebuddy.cn/...connect?code=...&state=...
          + Set-Cookie: user_session=STUB_LOGIN
        服务端见到：form_keys = [authenticity_token, authorize, client_id,
                    redirect_uri, scope, state]
                    form_state_len=166, form_scope="repo user", cookie 保持
```

判定条件全部满足：长 query 未截断、表单字段完整、`state` 长度一致、`Origin` 原样、跨请求 Cookie 连续、302 `Location` 与 `Set-Cookie` 原样回到客户端。

**代码层面对应**：`forward_over` 是纯字节流转发，不改写任何响应头；`build_http_request` 保留 `Cookie` / `Origin` / `Referer` / `Content-Type`，r4 的 `read_body` 保证表单 body 自包含。

---

## 4. 链路分段：谁经过本地代理

```
[浏览器] --PAC--> [本地代理 MITM] --出站省略 SNI--> [github.com]     ✅ 经过，E1/E7 证明正常
[github.com] --302--> [浏览器] --> [www.codebuddy.cn/...connect?code=]  ✅ 直连，E5/E6 证明正常
[CodeBuddy 服务端] ----> [github.com/login/oauth/access_token]          ❌ 不经过本机代理
[CodeBuddy 服务端] 校验 state / 写入绑定关系                              ❌ 不经过本机代理
```

因此「授权失败」若出现在回调页，排查重点在 **CodeBuddy 服务端与 GitHub 之间的链路**，以及 `state` 是否仍然有效。

---

## 5. 按概率排序的原因与处理

### A. `state` 一次性 / 已过期（最可能）

OAuth `state` 由 CodeBuddy 在发起时生成，通常绑定服务端 session 且只有数分钟有效期，且**只能用一次**。以下情况都会让回调校验失败：

- 授权页停留过久（E8 显示该时段上游有超时，`14:14:04 → 14:14:44` 出现 40s 空档）
- 反复刷新 / 重复点授权 / 复用同一个 URL
- 换了浏览器 profile、无痕窗口、或清了 `codebuddy.cn` 的 cookie
- 上一条消息的「Confirm access 卡住」期间已消耗过一次 `state`

**处理**：回到 CodeBuddy 控制台，**重新点一次连接 GitHub**，用全新的 URL / 新的 `state`，一气呵成完成授权，不要刷新授权页。

### B. CodeBuddy 服务端换 token 失败

`code` → `access_token` 由 CodeBuddy 服务器发起。若服务器出口到 `api.github.com` / `github.com` 受限（E2 已证明本机直连被 SNI 阻断，E4 也显示该端点间歇 502/404），就会在回调页报「授权失败」。**本地代理无法为服务器链路加速**。

**处理**：稍后重试；若稳定失败，属于 CodeBuddy 服务端侧问题，需要在其反馈渠道提供回调 URL 中的 `code` 与时间戳。

### C. GitHub 侧设备验证 / 二次确认未完成

与上一条消息的「Confirm access 卡住」同源。GitHub 对 `scope=repo` 这类高权限授权常要求 sudo 二次确认，未完成就回调会失败。

**处理**：确认 GitHub 账号已完成邮箱验证码 / 设备验证；必要时先在浏览器直接登录一次 `github.com` 并走完验证，再重新发起授权。

### D. 代理侧 UA 污染（已加固，非已证实根因）

实测经代理后 UA 变成 `curl/8.21.0 FastGithub/1.0`。虽然 E1/E7 链路本身正常，但 GitHub 风控可能据此判定设备异常。已在 r5 消除，见 §6。

---

## 6. 已实施的加固（r5）

`src/proxy.rs`：

| 改动 | 之前 | 之后 |
| --- | --- | --- |
| 防自环标记 | `User-Agent` 追加 ` FastGithub/1.0` | 标准 `Via: 1.1 fastgithub` |
| 浏览器 UA | `Chrome/... FastGithub/1.0` | **原样逐字节透传** |
| 无 UA 的请求 | `User-Agent: FastGithub/1.0` | 不变 |
| 旧版标记 | — | `is_forward_loop()` 仍识别，兼容混合版本 |
| 客户端带来的 `Via` | — | 剥离后只写一个，防重复 |

理由：RFC 7230 的 `Via` 本就是代理跳数跟踪 / 防环的标准头，上游见到它比见到被篡改的 UA 自然得多；OAuth 与设备验证页对 UA 敏感。

**这不是「授权失败」的已证实根因**，是消除代理侧唯一请求级污染的防御性改进。新增 3 项单测覆盖「UA 逐字节一致」「Via 与旧 UA 标记都能防环」「Via 只出现一次」。

复现脚本：`.workbuddy/tmp/oauth-chain-probe.py`（本地 HTTPS stub）、`.workbuddy/tmp/pac-eval.js`（PAC 求值）。

---

## 7. 需要用户确认的一件事

**「授权失败」这几个字出现在哪个页面？**

- **CodeBuddy 回调页 / 控制台**（域名 `www.codebuddy.cn`）→ 按 §5-A/B 处理：重新发起全新授权，并把浏览器地址栏里回调 URL 的 `code=` / `error=` 参数（可打码 `code` 值）发来。
- **GitHub 页面**（域名 `github.com`，英文界面却显示中文）→ 说明是 CodeBuddy 嵌入的提示层，同样取 F12 → Network 里那条失败请求的状态码与响应体。
- **浏览器错误页** → 另查网络层。

另请在 F12 → Network 里确认：授权后浏览器是否真的跳到了 `https://www.codebuddy.cn/console/as/p/connector/oauth/github/connect?code=...&state=...`，以及该请求的状态码。

---

## 8. 立即可做

1. **重启浏览器**（换 exe 后必须；PAC 也可能被缓存）。
2. 回到 CodeBuddy 控制台，**重新发起一次连接**，不要在授权页停留或刷新。
3. 若仍失败，按 §7 提供失败页面位置与回调 URL 参数。
4. 临时对照：换一个网络出口（手机热点）再发起一次，可快速区分「本机代理链路」与「CodeBuddy 服务端链路」。

> 安全提醒：不要分享 `code`、`access_token`、Cookie 或完整 `state` 原文；`code` 是一次性凭据。
