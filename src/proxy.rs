//! HTTP forward proxy, CONNECT tunnel with SNI rewriting, PAC, direct
//! `Response`, `Destination` rewriting and transparent TLS passthrough.
//!
//! All I/O is blocking on a thread per connection: no async runtime, no
//! console output, no dialogs. Every connection failure is logged and closed.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::config::{self, Config, DomainConfig};
use crate::logger;
use crate::resolver;
use crate::tls_sni;
use crate::AppState;

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 32 * 1024 * 1024;
// RFC 7230 `Via` is the standard hop-tracking header. Using it for loop
// detection keeps the browser's User-Agent byte-for-byte intact: GitHub's
// device-verification / OAuth risk checks treat an altered UA as a new device.
const VIA_VALUE: &str = "1.1 fastgithub";
const USER_AGENT_TAG: &str = "FastGithub/1.0"; // legacy marker, still recognised

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

fn read_head<R: Read>(stream: &mut R) -> io::Result<(HttpRequest, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let split = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") { break pos; }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP 头部过大"));
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "连接提前关闭"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((
        HttpRequest { method, target, version, headers },
        buf[split + 4..].to_vec(),
    ))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A request that already passed through this proxy must never be forwarded
/// again. `Via` is the current marker; the old UA tag is kept so that requests
/// emitted by an older instance are still detected.
fn is_forward_loop(req: &HttpRequest) -> bool {
    req.header("Via")
        .map(|v| v.to_ascii_lowercase().contains("fastgithub"))
        .unwrap_or(false)
        || req.header("User-Agent")
            .map(|v| v.contains(USER_AGENT_TAG))
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Request bodies (MITM path)
// ---------------------------------------------------------------------------

fn read_more<R: Read>(stream: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut tmp = [0u8; 16_384];
    let n = stream.read(&mut tmp)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "请求体读取中断"));
    }
    buf.extend_from_slice(&tmp[..n]);
    if buf.len() > MAX_BODY + MAX_HEAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "请求体过大"));
    }
    Ok(())
}

/// Decode a chunked request body into plain bytes. The rebuilt upstream request
/// uses an exact Content-Length instead, so no chunk framing survives.
fn decode_chunked<R: Read>(stream: &mut R, mut buf: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut plain = Vec::new();
    loop {
        let line_end = loop {
            if let Some(p) = find_subslice(&buf, b"\r\n") { break p; }
            read_more(stream, &mut buf)?;
        };
        let line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "无效的 chunk 长度"))?;
        buf.drain(..line_end + 2);
        if size == 0 {
            return Ok(plain);
        }
        if plain.len() + size > MAX_BODY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "请求体过大"));
        }
        while buf.len() < size + 2 {
            read_more(stream, &mut buf)?;
        }
        plain.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

/// `mitm_forward` is a one-way pump: after writing the rebuilt request it only
/// reads the upstream response and never the client again. Any body bytes still
/// sitting in the client socket would be dropped, leaving the upstream waiting
/// forever for the remaining Content-Length bytes. Read the complete body here
/// so the rebuilt request is self-contained.
fn read_body<R: Read + Write>(
    stream: &mut R,
    req: &HttpRequest,
    mut leftover: Vec<u8>,
) -> io::Result<Vec<u8>> {
    // The upstream never sees the client, so it cannot answer the challenge.
    if req.header("Expect")
        .map(|v| v.trim().eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false)
    {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        stream.flush()?;
    }

    let chunked = req.header("Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        return decode_chunked(stream, leftover);
    }

    let len = req.header("Content-Length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "请求体过大"));
    }
    if len == 0 {
        leftover.clear();
        return Ok(leftover);
    }
    while leftover.len() < len {
        read_more(stream, &mut leftover)?;
    }
    leftover.truncate(len);
    Ok(leftover)
}

/// Read one complete TLS handshake record. A single `read()` is not enough:
/// TCP can split a ClientHello, and a truncated record fails the parser, which
/// would silently forward the original SNI and get the connection reset.
fn read_tls_record(stream: &mut TcpStream, mut buf: Vec<u8>) -> Vec<u8> {
    let mut tmp = [0u8; 16_384];
    loop {
        if buf.len() >= 5 {
            if buf[0] != 0x16 { break; } // not a TLS handshake record
            let need = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= need { break; }
        }
        if buf.len() > MAX_HEAD { break; }
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    buf
}

#[derive(Debug, Clone)]
struct Target {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_target(req: &HttpRequest, reverse: bool) -> Option<Target> {
    let t = &req.target;
    if let Some(rest) = t.strip_prefix("http://") {
        return Some(split_authority("http", rest));
    }
    if let Some(rest) = t.strip_prefix("https://") {
        return Some(split_authority("https", rest));
    }
    if t.starts_with('/') {
        let authority = req.header("Host")?;
        if reverse {
            let mut target = split_authority("http", authority);
            target.path = t.clone();
            return Some(target);
        }
        return None; // origin-form request that hit the proxy itself
    }
    // CONNECT authority, or an unusual absolute authority without scheme
    Some(split_authority("https", t))
}

fn split_authority(scheme: &str, rest: &str) -> Target {
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.split('#').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(default_port(scheme)))
        }
        _ => (authority.to_string(), default_port(scheme)),
    };
    let host = host.trim_matches(['[', ']']).to_string();
    Target { scheme: scheme.to_string(), host, port, path: path.to_string() }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

/// Returns the number of client-bound bytes emitted (header + body).
fn send_response<W: Write>(stream: &mut W, code: u16, content_type: &str, body: &[u8], extra: &[(&str, String)]) -> usize {
    let mut head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {content_type}\r\n",
        status_text(code)
    );
    if code != 204 && code != 304 {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in extra { head.push_str(&format!("{k}: {v}\r\n")); }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    head.len() + body.len()
}

/// Direct responses (PAC / statistics / `Response` / errors) must be counted
/// too: `copy_loop` only sees bytes that pass through a relay. The direction
/// matches the upstream->client branch of `copy_loop` (`is_read = true`).
fn respond<W: Write>(state: &AppState, stream: &mut W, code: u16, content_type: &str, body: &[u8], extra: &[(&str, String)]) {
    let n = send_response(stream, code, content_type, body, extra);
    state.stats.on_flow(true, n);
}

fn build_pac(cfg: &Config, proxy_host: &str) -> String {
    let mut s = String::new();
    s.push_str("function FindProxyForURL(url, host){\n");
    s.push_str(&format!("    var fastgithub = 'PROXY {proxy_host}';\n"));
    for pattern in cfg.domain_patterns() {
        s.push_str(&format!("    if (shExpMatch(host, '{pattern}')) return fastgithub;\n"));
    }
    // Blocked hosts must travel through us, otherwise the browser would
    // reach them directly and no filtering could happen.
    for pattern in cfg.ad_patterns() {
        s.push_str(&format!(
            "    if (shExpMatch(host, '{}')) return fastgithub;\n",
            pattern.as_str()
        ));
    }
    s.push_str("    return 'DIRECT';\n}\n");
    s
}

/// A PAC file must point at an address the *client* can reach. `127.0.0.1`
/// would mean the LAN client itself, so echo back the local address of the
/// accepted socket (i.e. the address the client actually connected to).
fn pac_authority(client: &TcpStream, port: u16) -> String {
    let loopback = IpAddr::from([127, 0, 0, 1]);
    let ip = client.local_addr().map(|a| a.ip()).unwrap_or(loopback);
    format_proxy_authority(ip, port)
}

fn format_proxy_authority(ip: IpAddr, port: u16) -> String {
    if ip.is_unspecified() {
        return format!("127.0.0.1:{port}");
    }
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

// ---------------------------------------------------------------------------
// Connection handlers
// ---------------------------------------------------------------------------

/// HTTP proxy listener (default 38457) or plain HTTP reverse-proxy listener (80).
pub fn handle_http_connection(client: TcpStream, state: Arc<AppState>, reverse: bool) {
    let mut client = client;
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let (req, leftover) = match read_head(&mut client) {
        Ok(v) => v,
        Err(e) => {
            logger::debug(&format!("读取 HTTP 请求头失败: {e}"));
            return;
        }
    };

    if !reverse && req.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, state, &req, leftover);
        return;
    }

    let cfg = state.config.current();
    let proxy_host = pac_authority(&client, cfg.http_proxy_port);

    // Status / PAC endpoints on direct hits to the proxy itself.
    if req.target.starts_with('/') && !reverse {
        let path = req.target.split('?').next().unwrap_or("/");
        if path == "/flowStatistics" && cfg.silent.flow_statistics {
            let body = state.stats.json();
            respond(&state, &mut client, 200, "application/json;charset=utf-8", body.as_bytes(), &[]);
            return;
        }
        if cfg.silent.pac_enabled || path == "/proxy.pac" {
            let pac = build_pac(&cfg, &proxy_host);
            let extra = [("Content-Disposition", "attachment;filename=proxy.pac".to_string())];
            respond(
                &state,
                &mut client,
                200,
                "application/x-ns-proxy-autoconfig",
                pac.as_bytes(),
                &extra,
            );
            return;
        }
    }

    let Some(mut target) = parse_target(&req, reverse) else {
        respond(&state, &mut client, 400, "text/plain;charset=utf-8", b"Bad Request", &[]);
        return;
    };

    if cfg.is_ad_domain(&target.host) {
        logger::debug(&format!("广告拦截（HTTP）{}", target.host));
        respond(&state, &mut client, cfg.silent.ad_block.status_code, "text/plain;charset=utf-8", b"", &[]);
        return;
    }

    let mut domain_config = cfg.match_domain_or_default(&target.host);
    // Apply `Destination` (CDN replacement) before resolving the upstream.
    if let Some(dest) = domain_config.destination.as_deref() {
        if let Some((scheme, host, port, base)) =
            config::resolve_destination(&target.scheme, &target.host, Some(dest))
        {
            logger::info(&format!("{}://{}/ => {scheme}://{host}{base}", target.scheme, target.host));
            let path = target.path.clone();
            domain_config = cfg.match_domain_or_default(&host);
            target = Target { scheme, host, port, path: format!("{base}{path}") };
        }
    }

    // Short-circuit `Response` before any network access.
    if let Some(resp) = domain_config.response.as_ref() {
        let body = resp.content_value.clone().unwrap_or_default();
        respond(
            &state,
            &mut client,
            resp.status_code,
            &resp.content_type,
            body.as_bytes(),
            &[],
        );
        return;
    }

    if is_forward_loop(&req) {
        logger::warn("检测到转发自环（Via 或旧版 User-Agent 标记），中断本次转发");
        respond(&state, &mut client, 502, "text/plain;charset=utf-8", b"FastGithub loop detected", &[]);
        return;
    }

    if target.scheme == "https" {
        // Browsers always use CONNECT for HTTPS through a proxy; absolute-form
        // https would require a TLS client. MITM mode covers that path instead.
        logger::warn(&format!("绝对形式 HTTPS 请求在隧道模式下不支持: {}", req.target));
        respond(&state, &mut client, 502, "text/plain;charset=utf-8", b"Use CONNECT for HTTPS", &[]);
        return;
    }

    forward_http(client, state, cfg, target, req, leftover, domain_config);
}

fn forward_http(
    mut client: TcpStream,
    state: Arc<AppState>,
    cfg: Arc<Config>,
    target: Target,
    req: HttpRequest,
    leftover: Vec<u8>,
    domain_config: DomainConfig,
) {
    let pinned = domain_config.ip_address.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let matched = cfg.match_domain(&target.host).is_some();
    let mut addresses = if pinned.is_some() || matched {
        state.resolver.resolve(&target.host, target.port, pinned)
    } else {
        resolver::Resolver::system_resolve(&target.host, target.port)
    };
    if addresses.is_empty() {
        addresses = match (target.host.as_str(), target.port).to_socket_addrs() {
            Ok(it) => it.map(|s| s.ip()).collect(),
            Err(_) => Vec::new(),
        };
    }
    if addresses.is_empty() {
        logger::warn(&format!("无法解析 {}:{}", target.host, target.port));
        respond(&state, &mut client, 502, "text/plain;charset=utf-8", b"No upstream address", &[]);
        return;
    }
    let timeout = domain_config.timeout_duration(cfg.connect_timeout());
    let upstream = match resolver::connect_first(&addresses, target.port, timeout) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("连接 {}:{} 失败: {e}", target.host, target.port));
            respond(&state, &mut client, 502, "text/plain;charset=utf-8", e.to_string().as_bytes(), &[]);
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_read_timeout(Some(Duration::from_secs(120)));

    let payload = build_http_request(&req, &target, &leftover, false);
    // `relay` -> `copy_loop` already accounts for the initial payload.
    relay(client, upstream, payload, Vec::new(), state);
}

/// Rebuild a clean HTTP/1.1 request for the upstream: strip hop-by-hop
/// headers, set the correct Host, add a standard `Via` loop marker and force
/// `Connection: close` so the response can be streamed to EOF.
/// The browser's User-Agent is forwarded verbatim (never tagged).
///
/// `complete_body` is set only on the MITM path, where `read_body` already
/// collected the entire body: framing headers are replaced by an exact
/// Content-Length. On the plain-HTTP path the byte pump still forwards the
/// remaining body, so its original headers must be preserved.
fn build_http_request(req: &HttpRequest, target: &Target, leftover: &[u8], complete_body: bool) -> Vec<u8> {
    let host_value = if target.port == default_port(&target.scheme) {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let mut request = format!("{} {} {}\r\n", req.method, target.path, req.version);
    let hop = [
        "connection", "proxy-connection", "proxy-authenticate", "proxy-authorization",
        "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "host", "via",
    ];
    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if hop.contains(&lower.as_str()) { continue; }
        if complete_body && (lower == "content-length" || lower == "expect") { continue; }
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str(&format!("Host: {host_value}\r\n"));
    if complete_body && !leftover.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", leftover.len()));
    }
    request.push_str("Connection: close\r\n");
    request.push_str(&format!("Via: {VIA_VALUE}\r\n"));
    // Only synthesise a UA when the client sent none. Never append our tag to a
    // real browser UA: that changes device fingerprints on GitHub's sudo/OAuth
    // verification pages.
    if req.header("User-Agent").is_none() {
        request.push_str(&format!("User-Agent: {USER_AGENT_TAG}\r\n"));
    }
    request.push_str("\r\n");
    let mut payload = request.into_bytes();
    payload.extend_from_slice(leftover);
    payload
}

fn handle_connect(mut client: TcpStream, state: Arc<AppState>, req: &HttpRequest, leftover: Vec<u8>) {
    let cfg = state.config.current();
    let (host, port) = parse_connect_authority(&req.target);
    let mitm = cfg.silent.is_mitm() && state.certs.is_some();

    // In MITM mode the TLS is terminated and mitm_serve answers with an empty
    // body. Without a CA we can only refuse the tunnel outright.
    if !mitm && cfg.is_ad_domain(&host) {
        logger::debug(&format!("广告拦截（透传 CONNECT）{host}"));
        respond(&state, &mut client, 403, "text/plain;charset=utf-8", b"Blocked by FastGithub", &[]);
        return;
    }

    if mitm {
        handle_connect_mitm(client, state, &host, port);
    } else {
        handle_connect_passthrough(client, state, leftover, &host, port);
    }
}

/// Byte-for-byte TLS passthrough. The ClientHello must never be modified:
/// TLS transcript hashes cover those bytes, so any edit makes the client's
/// `Finished` verification fail with `bad record mac` / `SEC_E_DECRYPT_FAILURE`.
fn handle_connect_passthrough(
    mut client: TcpStream,
    state: Arc<AppState>,
    leftover: Vec<u8>,
    host: &str,
    port: u16,
) {
    let cfg = state.config.current();
    let domain_config = cfg.match_domain_or_default(host);
    let (mut upstream_host, mut upstream_port) = (host.to_string(), port);
    if let Some((scheme, dhost, dport, _)) =
        config::resolve_destination("https", host, domain_config.destination.as_deref())
    {
        if scheme == "https" {
            upstream_host = dhost;
            upstream_port = dport;
        }
    }
    let pinned = domain_config.ip_address.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let matched = cfg.match_domain(&upstream_host).is_some();
    let mut addresses = if pinned.is_some() || matched {
        state.resolver.resolve(&upstream_host, upstream_port, pinned)
    } else {
        resolver::Resolver::system_resolve(&upstream_host, upstream_port)
    };
    if addresses.is_empty() {
        addresses = match (upstream_host.as_str(), upstream_port).to_socket_addrs() {
            Ok(it) => it.map(|s| s.ip()).collect(),
            Err(_) => Vec::new(),
        };
    }
    if addresses.is_empty() {
        logger::warn(&format!("CONNECT {upstream_host}:{upstream_port} 无可用 IP"));
        respond(&state, &mut client, 502, "text/plain;charset=utf-8", b"No upstream address", &[]);
        return;
    }
    let timeout = domain_config.timeout_duration(cfg.connect_timeout());
    let upstream = match resolver::connect_first(&addresses, upstream_port, timeout) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("CONNECT {upstream_host}:{upstream_port} 失败: {e}"));
            respond(&state, &mut client, 502, "text/plain;charset=utf-8", e.to_string().as_bytes(), &[]);
            return;
        }
    };
    let upstream_ip = upstream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    if !send_response_is_ok(&mut client, &state) { return; }

    let _ = client.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(120)));
    let first = read_tls_record(&mut client, leftover);
    logger::info(&format!(
        "CONNECT 透传 {host}:{port} -> {upstream_host}:{upstream_port} @ {upstream_ip} hello={}B（原样转发，不改写 ClientHello）",
        first.len()
    ));
    relay(client, upstream, first, Vec::new(), state);
}

/// MITM: terminate the browser's TLS with a locally issued leaf certificate,
/// then open a completely independent TLS connection to the upstream. Because
/// the two handshakes are separate, we can control the upstream SNI freely
/// (`TlsSni = false` omits it) without touching the browser's transcript.
fn handle_connect_mitm(
    mut client: TcpStream,
    state: Arc<AppState>,
    host: &str,
    port: u16,
) {
    let Some(server_cfg) = state.certs.as_ref().and_then(|c| c.server_config()) else {
        return;
    };
    if !send_response_is_ok(&mut client, &state) { return; }
    let _ = client.set_read_timeout(Some(Duration::from_secs(120)));
    let mut tls = match crate::tls::server_stream(client, server_cfg) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("MITM 客户端握手失败 {host}:{port}: {e}"));
            return;
        }
    };
    logger::info(&format!("MITM 已终止 {host}:{port} 的 TLS（叶证书按 SNI 动态签发）"));

    mitm_serve(&mut tls, &state, host, port);
}

/// Shared plaintext-HTTP request loop for CONNECT tunnels and loopback:443 MITM.
fn mitm_serve<W: Read + Write>(client: &mut W, state: &AppState, host: &str, port: u16) {
    let _ = host;
    let cfg = state.config.current();
    loop {
        let (req, leftover) = match read_head(client) {
            Ok(v) => v,
            Err(e) => {
                logger::debug(&format!("MITM 请求读取结束: {e}"));
                break;
            }
        };
        if req.target.starts_with('/') && cfg.silent.flow_statistics {
            let path = req.target.split('?').next().unwrap_or("/");
            if path == "/flowStatistics" {
                let body = state.stats.json();
                respond(state, client, 200, "application/json;charset=utf-8", body.as_bytes(), &[]);
                continue;
            }
        }
        let Some(mut target) = parse_target(&req, true) else {
            respond(state, client, 400, "text/plain;charset=utf-8", b"Bad Request", &[]);
            break;
        };
        // Origin-form requests inside a CONNECT tunnel are HTTPS regardless of
        // what `parse_target` derives from the Host header (http:80 otherwise).
        // `Destination` may still override scheme/port below.
        target.scheme = "https".to_string();
        target.port = port;
        if cfg.is_ad_domain(&target.host) {
            logger::debug(&format!("广告拦截（MITM）{}", target.host));
            respond(state, client, cfg.silent.ad_block.status_code, "text/plain;charset=utf-8", b"", &[]);
            break;
        }
        let mut domain_config = cfg.match_domain_or_default(&target.host);
        if let Some(dest) = domain_config.destination.as_deref() {
            if let Some((scheme, dhost, dport, base)) =
                config::resolve_destination(&target.scheme, &target.host, Some(dest))
            {
                let path = target.path.clone();
                domain_config = cfg.match_domain_or_default(&dhost);
                target = Target { scheme, host: dhost, port: dport, path: format!("{base}{path}") };
            }
        }
        if let Some(resp) = domain_config.response.as_ref() {
            let body = resp.content_value.clone().unwrap_or_default();
            respond(state, client, resp.status_code, &resp.content_type, body.as_bytes(), &[]);
            break;
        }
        if is_forward_loop(&req) {
            logger::warn("检测到转发自环（Via 或旧版 User-Agent 标记），中断本次转发");
            respond(state, client, 502, "text/plain;charset=utf-8", b"FastGithub loop detected", &[]);
            break;
        }
        let body = match read_body(client, &req, leftover) {
            Ok(b) => b,
            Err(e) => {
                logger::warn(&format!("MITM 请求体读取失败 {}: {e}", target.host));
                respond(state, client, 400, "text/plain;charset=utf-8", b"Incomplete request body", &[]);
                break;
            }
        };
        if !mitm_forward(client, state, &cfg, &target, &req, &body, &domain_config) {
            break;
        }
    }
}

/// Remember the upstream IP that completed a request for each host. GitHub's
/// CDN resolves to several Fastly nodes, some of which time out or reset the
/// TLS handshake; trying a known-good node first keeps a page's dozens of
/// parallel asset requests fast and avoids re-probing dead nodes every time.
fn last_good_upstreams() -> &'static Mutex<HashMap<String, IpAddr>> {
    static CACHE: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(clippy::too_many_arguments)]
fn mitm_forward<W: Read + Write>(
    client: &mut W,
    state: &AppState,
    cfg: &Config,
    target: &Target,
    req: &HttpRequest,
    leftover: &[u8],
    domain_config: &DomainConfig,
) -> bool {
    let pinned = domain_config.ip_address.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let matched = cfg.match_domain(&target.host).is_some();
    let mut addresses = if pinned.is_some() || matched {
        state.resolver.resolve(&target.host, target.port, pinned)
    } else {
        resolver::Resolver::system_resolve(&target.host, target.port)
    };
    if addresses.is_empty() {
        addresses = match (target.host.as_str(), target.port).to_socket_addrs() {
            Ok(it) => it.map(|s| s.ip()).collect(),
            Err(_) => Vec::new(),
        };
    }
    if addresses.is_empty() {
        logger::warn(&format!("MITM {} 无可用 IP", target.host));
        respond(state, client, 502, "text/plain;charset=utf-8", b"No upstream address", &[]);
        return false;
    }
    if let Ok(cache) = last_good_upstreams().lock() {
        if let Some(good) = cache.get(&target.host) {
            if let Some(pos) = addresses.iter().position(|a| a == good) {
                if pos > 0 {
                    let ip = addresses.remove(pos);
                    addresses.insert(0, ip);
                }
            }
        }
    }
    // github.com often resolves to a single throttled IP. Duplicate it so a
    // transient TCP timeout gets an immediate second chance; the two 5s
    // attempts still fit the original 10s connect budget.
    if addresses.len() == 1 {
        let only = addresses[0];
        addresses.push(only);
    }
    let timeout = domain_config.timeout_duration(cfg.connect_timeout());
    // With several ranked candidates a dead node should fail fast. With only
    // one candidate (github.com) keep the full timeout — 4s caused spurious 502s.
    let connect_timeout = if addresses.len() > 1 {
        timeout.min(Duration::from_secs(5))
    } else {
        timeout
    };
    let payload = build_http_request(req, target, leftover, true);

    // TCP success is NOT enough. Some GitHub CDN nodes accept the socket and
    // then reset the TLS handshake (os error 10054). Retry the next ranked IP
    // instead of failing the whole asset, which otherwise leaves the React
    // repo sidebar stuck on its skeleton placeholders.
    let mut last_err = String::new();
    for ip in addresses.iter().take(3) {
        let sa = SocketAddr::new(*ip, target.port);
        let tcp = match TcpStream::connect_timeout(&sa, connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("{sa}: {e}");
                logger::warn(&format!("上游 TCP 连接 {sa} 失败: {e}"));
                continue;
            }
        };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(60)));
        logger::info(&format!("上游 TCP 已连接 {sa}"));

        if target.scheme == "https" {
            let sni = tls_sni::upstream_sni(domain_config, &target.host, ip);
            logger::info(&format!(
                "MITM {}:{} -> {} @ {} outSni={sni:?}（独立出站握手）",
                target.host, target.port, target.host, ip
            ));
            match crate::tls::client_stream(tcp, sni.as_deref()) {
                Ok(mut up) => {
                    if let Ok(mut cache) = last_good_upstreams().lock() {
                        cache.insert(target.host.clone(), *ip);
                    }
                    return forward_over(&mut up, client, state, &payload);
                }
                Err(e) => {
                    last_err = format!("{sa}: TLS {e}");
                    logger::warn(&format!("MITM 上游 TLS 握手失败 {}: {e}，换下一个 IP", target.host));
                    continue;
                }
            }
        } else {
            if let Ok(mut cache) = last_good_upstreams().lock() {
                cache.insert(target.host.clone(), *ip);
            }
            let mut up = tcp;
            return forward_over(&mut up, client, state, &payload);
        }
    }
    if last_err.is_empty() { last_err = "无可用上游 IP".to_string(); }
    logger::warn(&format!("MITM {} 候选 IP 全部失败: {last_err}", target.host));
    respond(state, client, 502, "text/plain;charset=utf-8", last_err.as_bytes(), &[]);
    false
}

fn forward_over<S: Read + Write, W: Read + Write>(
    upstream: &mut S,
    client: &mut W,
    state: &AppState,
    payload: &[u8],
) -> bool {
    if upstream.write_all(payload).and_then(|_| upstream.flush()).is_err() {
        return false;
    }
    state.stats.on_flow(false, payload.len());
    let mut buf = [0u8; 16_384];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() { break; }
                state.stats.on_flow(true, n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = client.flush();
    true
}

fn send_response_is_ok(client: &mut TcpStream, state: &AppState) -> bool {
    const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let ok = client
        .write_all(ESTABLISHED)
        .and_then(|_| client.flush())
        .is_ok();
    if ok { state.stats.on_flow(true, ESTABLISHED.len()); }
    ok
}

fn parse_connect_authority(target: &str) -> (String, u16) {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse().unwrap_or(443)),
        _ => (target.to_string(), 443),
    };
    (host.trim_matches(['[', ']']).to_string(), port)
}

/// 127.0.0.1:443 listener: TLS passthrough using ClientHello SNI, with the
/// same IP ranking and SNI policy, but no decryption and therefore no CA.
pub fn handle_https_passthrough(mut client: TcpStream, state: Arc<AppState>) {
    let cfg = state.config.current();
    if cfg.silent.is_mitm() {
        if let Some(server_cfg) = state.certs.as_ref().and_then(|c| c.server_config()) {
            let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
            match crate::tls::server_stream(client, server_cfg) {
                Ok(mut tls) => {
                    logger::info("MITM 已终止 loopback:443 入站 TLS（叶证书按 SNI 动态签发）");
                    mitm_serve(&mut tls, &state, "loopback", 443);
                }
                Err(e) => logger::warn(&format!("443 MITM 握手失败: {e}")),
            }
        }
        return;
    }

    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let first = read_tls_record(&mut client, Vec::new());
    if first.is_empty() { return; }
    let Some(host) = tls_sni::client_hello_sni(&first).filter(|s| !s.is_empty()) else {
        logger::warn("443 入站连接不是带 SNI 的 ClientHello，无法透传（已关闭）");
        return;
    };
    let domain_config = cfg.match_domain_or_default(&host);
    let (mut upstream_host, mut upstream_port) = (host.clone(), 443u16);
    if let Some((scheme, dhost, dport, _)) =
        config::resolve_destination("https", &host, domain_config.destination.as_deref())
    {
        if scheme == "https" {
            upstream_host = dhost;
            upstream_port = dport;
        }
    }
    let pinned = domain_config.ip_address.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let mut addresses = state.resolver.resolve(&upstream_host, upstream_port, pinned);
    if addresses.is_empty() {
        // Same fallback as the CONNECT path: pure-DNS lookup may fail while the
        // OS resolver still knows an address (hosts file, cached DNS, DoH client).
        addresses = resolver::Resolver::system_resolve(&upstream_host, upstream_port);
    }
    if addresses.is_empty() {
        logger::warn(&format!("TLS 透传 {upstream_host} 无可用 IP（已关闭连接）"));
        return;
    }
    let timeout = domain_config.timeout_duration(cfg.connect_timeout());
    let upstream = match resolver::connect_first(&addresses, upstream_port, timeout) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("TLS 透传 {upstream_host} 连接失败: {e}（已关闭连接）"));
            return;
        }
    };
    let upstream_ip = upstream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    logger::info(&format!(
        "TLS 透传 {host}:443 -> {upstream_host}:{upstream_port} @ {upstream_ip} hello={}B（原样转发，不改写 ClientHello）",
        first.len()
    ));
    let _ = client.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(120)));
    relay(client, upstream, first, Vec::new(), state);
}

/// Raw TCP reverse proxy for github.com:22 (ssh) and :9418 (git).
pub fn handle_tcp_reverse(client: TcpStream, state: Arc<AppState>, host: &str, port: u16) {
    let cfg = state.config.current();
    let addresses = state.resolver.resolve(host, port, None);
    if addresses.is_empty() {
        logger::warn(&format!("{host}:{port} 无可用 IP"));
        return;
    }
    let upstream = match resolver::connect_first(&addresses, port, cfg.connect_timeout()) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("{host}:{port} 连接失败: {e}"));
            return;
        }
    };
    let _ = client.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(120)));
    state.resolver.note(host, port);
    relay(client, upstream, Vec::new(), Vec::new(), state);
}

// ---------------------------------------------------------------------------
// Byte pump
// ---------------------------------------------------------------------------

fn shutdown_both(a: &TcpStream, b: &TcpStream) {
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}

fn copy_loop(mut from: TcpStream, mut to: TcpStream, initial: Vec<u8>, state: Arc<AppState>, is_read: bool) {
    if !initial.is_empty() {
        if to.write_all(&initial).is_err() {
            shutdown_both(&from, &to);
            return;
        }
        state.stats.on_flow(is_read, initial.len());
    }
    let mut buf = [0u8; 16_384];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() { break; }
                state.stats.on_flow(is_read, n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    shutdown_both(&from, &to);
}

pub fn relay(client: TcpStream, upstream: TcpStream, to_upstream: Vec<u8>, to_client: Vec<u8>, state: Arc<AppState>) {
    let Ok(c_in) = client.try_clone() else { return };
    let Ok(u_out) = upstream.try_clone() else { return };
    let st2 = state.clone();
    let handle = std::thread::Builder::new()
        .name("relay-up".into())
        .spawn(move || copy_loop(c_in, u_out, to_upstream, st2, false));
    copy_loop(upstream, client, to_client, state, true);
    if let Ok(h) = handle { let _ = h.join(); }
}

#[cfg(test)]
mod tests {
    use super::format_proxy_authority;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn pac_authority_echoes_reachable_address() {
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(format_proxy_authority(lan, 38457), "192.168.1.10:38457");
        assert_eq!(
            format_proxy_authority(IpAddr::from([127, 0, 0, 1]), 38457),
            "127.0.0.1:38457"
        );
        assert_eq!(
            format_proxy_authority(IpAddr::V6(Ipv6Addr::LOCALHOST), 38457),
            "[::1]:38457"
        );
    }

    #[test]
    fn pac_authority_never_returns_wildcard_address() {
        assert_eq!(
            format_proxy_authority(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 38457),
            "127.0.0.1:38457"
        );
        assert_eq!(
            format_proxy_authority(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 38457),
            "127.0.0.1:38457"
        );
    }

    use super::{build_http_request, is_forward_loop, read_body, HttpRequest, Target, VIA_VALUE};
    use std::io::{self, Read, Write};

    struct MemStream {
        incoming: std::io::Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }

    impl MemStream {
        fn new(data: &[u8]) -> Self {
            Self { incoming: std::io::Cursor::new(data.to_vec()), outgoing: Vec::new() }
        }
    }

    impl Read for MemStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.incoming.read(buf) }
    }

    impl Write for MemStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outgoing.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    fn req(headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target: "/session".into(),
            version: "HTTP/1.1".into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn target() -> Target {
        Target { scheme: "https".into(), host: "github.com".into(), port: 443, path: "/session".into() }
    }

    #[test]
    fn mitm_reads_full_content_length_body() {
        let r = req(&[("Content-Length", "10")]);
        let mut s = MemStream::new(b"defghij");
        let body = read_body(&mut s, &r, b"abc".to_vec()).unwrap();
        assert_eq!(body.as_slice(), b"abcdefghij");
        let wire = build_http_request(&r, &target(), &body, true);
        let head = String::from_utf8_lossy(&wire[..wire.len() - body.len()]).into_owned();
        assert!(head.contains("Content-Length: 10\r\n"));
        assert_eq!(&wire[wire.len() - 10..], b"abcdefghij");
    }

    #[test]
    fn mitm_decodes_chunked_body_into_content_length() {
        let r = req(&[("Transfer-Encoding", "chunked")]);
        let mut s = MemStream::new(b"5\r\nworld\r\n0\r\n\r\n");
        let body = read_body(&mut s, &r, b"5\r\nhello\r\n".to_vec()).unwrap();
        assert_eq!(body.as_slice(), b"helloworld");
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), &body, true)).into_owned();
        assert!(wire.contains("Content-Length: 10\r\n"));
        assert!(!wire.contains("Transfer-Encoding"));
    }

    #[test]
    fn mitm_answers_expect_locally_and_strips_it_upstream() {
        let r = req(&[("Expect", "100-continue"), ("Content-Length", "3")]);
        let mut s = MemStream::new(b"xyz");
        let body = read_body(&mut s, &r, Vec::new()).unwrap();
        assert_eq!(body.as_slice(), b"xyz");
        assert_eq!(s.outgoing.as_slice(), b"HTTP/1.1 100 Continue\r\n\r\n");
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), &body, true)).into_owned();
        assert!(!wire.contains("Expect:"));
    }

    #[test]
    fn plain_forward_proxy_keeps_original_framing() {
        let r = req(&[("Content-Length", "10")]);
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), b"abc", false)).into_owned();
        assert!(wire.contains("Content-Length: 10\r\n"), "byte pump still forwards the rest");
        assert!(!wire.contains("Content-Length: 3\r\n"));
    }

    #[test]
    fn browser_user_agent_is_forwarded_verbatim() {
        let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ".to_string()
            + "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        let r = req(&[("User-Agent", browser.as_str())]);
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), b"", true)).into_owned();
        assert!(wire.contains(&format!("User-Agent: {browser}\r\n")), "UA must be byte-identical");
        assert!(!wire.contains("FastGithub/1.0"), "no tag may be appended to a real UA");
        assert!(!is_forward_loop(&r), "a normal browser request is not a loop");
    }

    #[test]
    fn via_marks_loop_without_touching_ua() {
        let r = req(&[("Via", VIA_VALUE)]);
        assert!(is_forward_loop(&r));
        let legacy = req(&[("User-Agent", "curl/8.0 FastGithub/1.0")]);
        assert!(is_forward_loop(&legacy), "legacy marker still recognised");
        let foreign = req(&[("Via", "1.1 some-other-proxy")]);
        assert!(!is_forward_loop(&foreign));
    }

    #[test]
    fn via_header_is_emitted_exactly_once() {
        let r = req(&[("Via", "1.1 upstream-cdn")]);
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), b"", true)).into_owned();
        assert_eq!(wire.matches("Via: ").count(), 1);
        assert!(wire.contains(&format!("Via: {VIA_VALUE}\r\n")));
    }

    #[test]
    fn get_without_body_is_untouched() {
        let r = HttpRequest { method: "GET".into(), ..req(&[]) };
        let mut s = MemStream::new(b"");
        let body = read_body(&mut s, &r, Vec::new()).unwrap();
        assert!(body.is_empty());
        let wire = String::from_utf8_lossy(&build_http_request(&r, &target(), &body, true)).into_owned();
        assert!(!wire.contains("Content-Length"));
    }
}
