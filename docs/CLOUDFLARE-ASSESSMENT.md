# Cloudflare 域名可访问性评估

**日期**：2026-11-12 · **对象**：`https://dash.cloudflare.com/`、`https://www.cloudflare.com/`
**问题**：使用本项目（fastgithub-rs）配置后是否有益？

---

## 结论

**基本无益，且 `dash` 存在明确风险，不建议把这两个域名交给本项目代理。**
**已实施防误伤改动**：`dash` / `www` / 裸域 `cloudflare.com` 现在由 PAC 判 `DIRECT`，不再经过 MITM（见「已实施」章节）。

- 两者故障机制与 github 的 **SNI 阻断完全不同**，项目的核心绕过手段在这里用不上。
- 默认配置的 PAC 已命中 `*.cloudflare.com`，启用系统 PAC 后这两个域名会被**强制走 MITM**，可能把本来能直连的 200 变成 403 / challenge。
- 真正有效的解法是**更换出口公网 IP**，本地代理做不到这一点。

---

## 实测证据

| 检查项 | 结果 |
| --- | --- |
| DNS | 正常：`www` → `104.16.123.96/.124.96`，`dash` → `104.17.110.184/.111.184`，`cloudflare.com` → `104.16.132.229/.133.229`。**无 DNS 污染** |
| TLS 带 SNI | TLS 1.3 握手成功，返回正确证书 `CN=www.cloudflare.com` / `CN=dash.cloudflare.com` |
| TLS 不带 SNI | **同样握手成功、证书正确**，无 RST。→ 本项目「出站省略 SNI」的前提不成立 |
| 直连 `www` | 200 / 1,334,522 B，5.7–18.4s；一次 15s 超时只收到 708,617 B（链路抖动） |
| 代理 `www` | 200 / 1,334,522 B，8.8–18.1s；与直连互有胜负，**无稳定收益** |
| 直连 `dash` | 多次采样：0 B 超时 / 200 部分内容 / **403 + `Cf-Mitigated: challenge`** |
| 代理 `dash` | 多次采样：**403** / 000 超时 / **200 / 365,701 B**。波动同样大，代理未稳定胜出 |
| 代理 `api.cloudflare.com/client/v4/user` | 403 / 162 B |
| 边缘 IP 对照 | `104.16.123.96` / `.124.96` → 200；`104.16.132.229`、`104.17.110/111.184` → **403 / 17 B**。**IP 与站点绑定，错 IP 直接 403** |
| PAC 命中 | `shExpMatch(host, '*.cloudflare.com')` = **True**（来自 `config/appsettings/appsettings.bootcss.json`） |

> 采样期间直连与代理的结果都在 200 / 403 / 超时之间跳动，说明主导因素是 Cloudflare 侧的 WAF 质询（`Cf-Mitigated: challenge`）、限流（1015）与国际链路抖动，而非稳定的协议层阻断。

---

## 为什么机制不匹配

1. **项目针对 SNI RST**：当前网络对 github 系任意 SNI 都发 RST，因此 MITM + 出站 `ServerName::IpAddress` 省略 SNI 是核心绕过。Cloudflare 边缘这里带/不带 SNI 都能握手，该能力完全闲置。
2. **换 IP 空间极小且危险**：Cloudflare 是 anycast，DNS 只给 2 个绑定该站点的专用 IP；用别的段（如 `104.17.x` 请求 `www`）会直接 403。项目的「测速选优 / 换 IP 重试」在这里容易踩雷。
3. **challenge / 限流按出口 IP 判定**：`Cf-Mitigated: challenge` 与 1015 看的是客户端公网 IP 及行为评分。本地代理不改变出口 IP，绕不过。
4. **MITM 副作用对控制台更敏感**：
   - `dash` 是 SPA，依赖大量 `api.cloudflare.com` 请求、WebSocket 与 HTTP/2；项目只做 HTTP/1.1、不支持 WebSocket、会重建请求头。
   - 出站跳过上游证书校验（`COMPATIBILITY.md` C-14）。
   - **MITM 下 Cloudflare 账号会话 / 凭据在代理进程内是明文可见的**，对控制台类站点尤其不划算。

---

## 建议

### 有效手段（与本项目无关）

- 更换出口 IP：换网络 / 换运营商 / 使用出口 IP 干净可靠的商业代理，避免共享出口池。
- 若返回 1015：等待数分钟至数小时、降低并发，不要反复刷新。
- 浏览器侧：清 `cloudflare.com` cookie、换一个干净的浏览器 profile、暂时关闭可能触发 challenge 的扩展、确认系统时间准确；直接试 `https://dash.cloudflare.com/login`。

### 已实施：把 Cloudflare 从 PAC 排除（2026-11-12）

`config/appsettings/appsettings.bootcss.json` 的通配规则已改窄，只保留 CDN 需要的精确域名：

```jsonc
{
  "FastGithub": {
    "DomainConfigs": {
      // dash / www / 裸域 cloudflare.com 必须走 DIRECT
      "cdnjs.cloudflare.com": {
        "TlsSni": true
      },
      "cdn.bootcss.com": {
        "TlsSni": true,
        "Destination": "https://cdnjs.cloudflare.com/ajax/libs/"
      }
    }
  }
}
```

实施细节：

- **没跑 `build-x86.cmd`**：它会把 `dist\config\appsettings.json` 的 `ProxyBind` 覆盖回 `127.0.0.1`，破坏 LAN 部署。改为直接把改后的文件复制到 `dist\config\appsettings\`，两份哈希一致，`ProxyBind=0.0.0.0` 保持不变。
- 效果：`dash` / `www` / 裸域 `cloudflare.com` 走 **DIRECT**；`cdn.bootcss.com` 的 `Destination` 仍精确命中 `cdnjs.cloudflare.com` 且 `TlsSni: true`（Cloudflare CDN 需要 SNI）。
- **踩坑**：验证时发现残留实例（PID 14668）持有 `Global\FastGithub` 单实例互斥，新进程立即退出，PAC 请求打到了旧实例并返回旧规则（`*.cloudflare.com` 仍在）。必须先停掉所有 `fastgithub.exe` 再启动干净实例验证；不要依赖「热加载 2 秒」的时序。
- 改完已重启常驻实例，新 PAC 即时生效。浏览器若缓存旧 PAC，重启浏览器。

#### 实施后实测

| 检查 | 结果 |
| --- | --- |
| 配置同步 | 源码与 `dist` 的 `appsettings.bootcss.json` 哈希一致；`ProxyBind=0.0.0.0` 未被覆盖 |
| PAC 文本 | 93 条 `shExpMatch`；`*.cloudflare.com` 已消失，`cdnjs.cloudflare.com` / `cdn.bootcss.com` / `github.com` / `pos.baidu.com` 均在 |
| **PAC 实际求值**（node 执行 `FindProxyForURL`） | `dash.cloudflare.com` / `www.cloudflare.com` / `cloudflare.com` → **DIRECT**；`cdnjs.cloudflare.com` / `cdn.bootcss.com` / `github.com` / `pos.baidu.com` → `PROXY 127.0.0.1:38457` |
| CDN `Destination` 回归 | `https://cdn.bootcss.com/jquery/3.6.0/jquery.min.js` → **200 / 89,501 B** |
| github 回归 | `https://github.com/` → **200 / 525,706 B** |
| 配置解析 | 日志中 `JSON 解析失败` / `配置模型绑定失败` 计数 0（新增 `//` 注释被 JSONC 解析正确处理） |
| 常驻实例 | 重启后监听 `0.0.0.0:38457`，PAC 为新配置 |

---

## 复现命令

```bat
:: DNS / 直连
curl.exe -s -o NUL -w "%%{http_code} %%{size_download} %%{time_total}" --max-time 15 https://www.cloudflare.com/
curl.exe -s -D - -o NUL --max-time 15 https://dash.cloudflare.com/

:: TLS 带 / 不带 SNI 对照
openssl s_client -connect 104.17.110.184:443 -servername dash.cloudflare.com -brief
openssl s_client -connect 104.17.110.184:443 -noservername -brief

:: 经本项目代理
curl.exe --ssl-no-revoke -x http://127.0.0.1:38457 -s -o NUL -w "%%{http_code} %%{size_download}" https://dash.cloudflare.com/
```

---

## 相关约束

`docs/COMPATIBILITY.md` C-12（TLS 透传不能改写 ClientHello）、C-14（上游证书校验被跳过）、C-16（github 系 CDN 必须省略 SNI）。
`docs/ACCEPTANCE.md` M16（github 的 SNI 阻断对照实验）—— 本评估说明该结论**不能外推到 Cloudflare**。
