//! Listener orchestration.
//!
//! Ports mirror `FastGithub.Configuration.GlobalListener`:
//!  * 38457  HTTP forward proxy + PAC + /flowStatistics
//!  * 53/udp local DNS resolver (returns loopback for configured domains)
//!  * 80     plain HTTP reverse proxy
//!  * 443    TLS passthrough (SNI -> best IP -> SNI policy), or MITM
//!  * 22     github.com:22 SSH reverse proxy
//!  * 9418   github.com:9418 git:// reverse proxy
//!
//! Binding these ports needs no administrator rights on Windows. Unlike the
//! original WinDivert driver, this rewrite never installs a kernel driver.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::dns;
use crate::logger;
use crate::platform;
use crate::proxy;
use crate::AppState;

const PORT_SCAN_LIMIT: u16 = 128;

pub fn start_all(state: Arc<AppState>) {
    let cfg = state.config.current();

    // HTTP proxy port is fixed (the original aborts if it is occupied), but the
    // bind address is configurable so the service can be shared with the LAN.
    let proxy_addr = resolve_proxy_bind(&cfg.silent.proxy_bind, cfg.http_proxy_port);
    match TcpListener::bind(proxy_addr) {
        Ok(l) => {
            logger::info(&format!(
                "已监听 http://{}，HTTP 正向代理 / PAC / 状态接口启动完成",
                proxy_addr
            ));
            if !proxy_addr.ip().is_loopback() {
                logger::warn("正向代理绑定到非回环地址：请确认防火墙仅放行内网来源，且客户端已安装本地 CA（PAC 地址须用服务端 LAN IP）");
            }
            let s = state.clone();
            spawn_accept(l, "http-proxy", move |stream, st| {
                proxy::handle_http_connection(stream, st, false)
            }, s);
        }
        Err(e) => logger::error(&format!("端口 {} 被占用，正向代理未启动: {e}", cfg.http_proxy_port)),
    }

    if cfg.silent.dns_enabled {
        spawn_dns_listener(state.clone(), &cfg);
    }
    if cfg.silent.http_listener {
        if let Some((l, port)) = bind_from(80) {
            logger::info(&format!("已监听 http://127.0.0.1:{port}，HTTP 反向代理启动完成"));
            let s = state.clone();
            spawn_accept(l, "http-reverse", move |stream, st| {
                proxy::handle_http_connection(stream, st, true)
            }, s);
        }
    }
    if cfg.silent.https_listener {
        if let Some((l, port)) = bind_from(443) {
            logger::info(&format!("已监听 https://127.0.0.1:{port}，TLS 透传/MITM 启动完成"));
            let s = state.clone();
            spawn_accept(l, "https", move |stream, st| {
                proxy::handle_https_passthrough(stream, st)
            }, s);
        }
    }
    if cfg.silent.ssh_proxy {
        if let Some((l, port)) = bind_from(22) {
            logger::info(&format!("已监听 ssh://127.0.0.1:{port}，github.com:22 反向代理启动完成"));
            let s = state.clone();
            spawn_accept(l, "ssh", move |stream, st| {
                proxy::handle_tcp_reverse(stream, st, "github.com", 22)
            }, s);
        }
    }
    if cfg.silent.git_proxy {
        if let Some((l, port)) = bind_from(9418) {
            logger::info(&format!("已监听 git://127.0.0.1:{port}，github.com:9418 反向代理启动完成"));
            let s = state.clone();
            spawn_accept(l, "git", move |stream, st| {
                proxy::handle_tcp_reverse(stream, st, "github.com", 9418)
            }, s);
        }
    }
}

/// Accepts an IP literal (`0.0.0.0`, `::1`), a full socket address, or a
/// hostname. Invalid values fall back to loopback so a typo can never silently
/// expose the proxy on all interfaces.
fn resolve_proxy_bind(bind: &str, port: u16) -> SocketAddr {
    let fallback: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let text = bind.trim();
    if text.is_empty() {
        return fallback;
    }
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return addr;
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return SocketAddr::new(ip, port);
    }
    format!("{text}:{port}").parse().unwrap_or(fallback)
}

fn bind_from(start: u16) -> Option<(TcpListener, u16)> {
    for port in start..start.saturating_add(PORT_SCAN_LIMIT) {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => return Some((l, port)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse || e.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(_) => continue,
        }
    }
    logger::warn(&format!("端口 {start} 起连续 {PORT_SCAN_LIMIT} 个端口均不可用，已跳过该监听器"));
    None
}

fn spawn_accept<H>(listener: TcpListener, name: &'static str, handler: H, state: Arc<AppState>)
where
    H: Fn(TcpStream, Arc<AppState>) + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    std::thread::Builder::new()
        .name(format!("accept-{name}"))
        .spawn(move || {
            if listener.set_nonblocking(true).is_err() {
                logger::error(&format!("监听器 {name} 无法设置非阻塞"));
                return;
            }
            while !platform::is_shutting_down() {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nonblocking(false);
                        let h = handler.clone();
                        let s = state.clone();
                        let _ = std::thread::Builder::new()
                            .name(format!("conn-{name}"))
                            .spawn(move || h(stream, s));
                        logger::debug(&format!("{name} 接受连接 {peer}"));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(e) => {
                        logger::warn(&format!("{name} accept 异常: {e}"));
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
            logger::info(&format!("监听器 {name} 已停止"));
        })
        .ok();
}

/// Local DNS resolver. Matching domains are answered with 127.0.0.1 / ::1
/// (TTL 300s, exactly like `DnsInterceptor`). Other queries are forwarded to
/// the first reachable fallback DNS server.
fn spawn_dns_listener(state: Arc<AppState>, cfg: &Config) {
    let bind: SocketAddr = cfg.silent.dns_bind.parse().unwrap_or_else(|_| "127.0.0.1:53".parse().unwrap());
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            logger::warn(&format!("本地 DNS 监听 {} 失败（跳过）: {e}", bind));
            return;
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    logger::info(&format!("已监听 udp://{bind}，本地 DNS 解析服务启动完成"));
    std::thread::Builder::new()
        .name("dns-listener".into())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            while !platform::is_shutting_down() {
                let (n, peer) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => continue,
                    Err(e) => {
                        logger::warn(&format!("DNS 接收异常: {e}"));
                        continue;
                    }
                };
                let query = match dns::parse_query(&buf[..n]) {
                    Some(q) => q,
                    None => continue,
                };
                let Some(question) = query.questions.first() else { continue };
                let current = state.config.current();
                let matched = current.match_domain(&question.name).is_some();
                if matched && (question.qtype == dns::TYPE_A || question.qtype == dns::TYPE_AAAA) {
                    if let Some(resp) = dns::build_loopback_response(&query, question.qtype, 300) {
                        let _ = sock.send_to(&resp, peer);
                        logger::debug(&format!("{} -> loopback ({})", question.name, question.qtype));
                        continue;
                    }
                }
                // Forward unmatched queries upstream (best effort).
                let servers = current.fallback_dns.clone();
                let mut answered = false;
                for server in servers {
                    let relay = match UdpSocket::bind("0.0.0.0:0") {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = relay.set_read_timeout(Some(Duration::from_secs(2)));
                    if relay.send_to(&buf[..n], server).is_err() { continue; }
                    let mut rbuf = [0u8; 4096];
                    if let Ok((m, _)) = relay.recv_from(&mut rbuf) {
                        let _ = sock.send_to(&rbuf[..m], peer);
                        answered = true;
                        break;
                    }
                }
                if !answered {
                    // SERVFAIL, echoing the question section.
                    let mut fail = Vec::new();
                    fail.extend_from_slice(&query.id.to_be_bytes());
                    fail.extend_from_slice(&0x8182u16.to_be_bytes());
                    fail.extend_from_slice(&(query.questions.len() as u16).to_be_bytes());
                    fail.extend_from_slice(&0u16.to_be_bytes());
                    fail.extend_from_slice(&0u16.to_be_bytes());
                    fail.extend_from_slice(&0u16.to_be_bytes());
                    fail.extend_from_slice(&query.raw_questions);
                    let _ = sock.send_to(&fail, peer);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::resolve_proxy_bind;

    #[test]
    fn proxy_bind_accepts_lan_and_ipv6_literals() {
        assert_eq!(resolve_proxy_bind("127.0.0.1", 38457).to_string(), "127.0.0.1:38457");
        assert_eq!(resolve_proxy_bind("0.0.0.0", 38457).to_string(), "0.0.0.0:38457");
        assert_eq!(resolve_proxy_bind("192.168.1.10", 80).to_string(), "192.168.1.10:80");
        assert_eq!(resolve_proxy_bind("::1", 38457).to_string(), "[::1]:38457");
        assert_eq!(resolve_proxy_bind("0.0.0.0:9999", 38457).to_string(), "0.0.0.0:9999");
    }

    #[test]
    fn invalid_proxy_bind_never_exposes_all_interfaces() {
        assert_eq!(resolve_proxy_bind("", 38457).to_string(), "127.0.0.1:38457");
        assert_eq!(resolve_proxy_bind("not-an-ip!!", 38457).to_string(), "127.0.0.1:38457");
        assert_eq!(resolve_proxy_bind(" 127.0.0.1 ", 38457).to_string(), "127.0.0.1:38457");
    }
}
