//! Clean-IP resolution, connect-latency ranking and persistence.
//!
//! Ported behaviour from `DnsClient`, `IPAddressService`, `DomainResolver`,
//! `PersistenceService` and `DomainResolveHostedService`:
//!  * fallback DNS servers are probed over TCP:53, then queried for A/AAAA;
//!  * loopback answers are discarded;
//!  * answer TTL is clamped to 30s..10min;
//!  * candidate IPs are ranked by TCP connect latency (5s timeout);
//!  * known endpoints are persisted to `dnsendpoints.json`;
//!  * a background loop re-tests every `speed_test_interval_secs` (default 1s).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::ConfigStore;
use crate::dns;
use crate::logger;
use crate::platform;

const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(600);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const DNS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_STATE_TTL: Duration = Duration::from_secs(300);
const LATENCY_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    expires: Instant,
}

struct Inner {
    endpoints: Vec<(String, u16)>,
    resolved: HashMap<(String, u16), CacheEntry<Vec<IpAddr>>>,
    dns_lookup: HashMap<(String, SocketAddr), CacheEntry<Vec<IpAddr>>>,
    dns_state: HashMap<SocketAddr, CacheEntry<bool>>,
    latency: HashMap<(IpAddr, u16), CacheEntry<Duration>>,
    generation: u64,
}

pub struct Resolver {
    cfg: Arc<ConfigStore>,
    inner: Mutex<Inner>,
    data_file: PathBuf,
}

impl Resolver {
    pub fn new(cfg: Arc<ConfigStore>, root: &Path) -> Arc<Self> {
        let data_file = root.join("dnsendpoints.json");
        let endpoints = read_endpoints(&data_file);
        let me = Arc::new(Self {
            cfg,
            inner: Mutex::new(Inner {
                endpoints,
                resolved: HashMap::new(),
                dns_lookup: HashMap::new(),
                dns_state: HashMap::new(),
                latency: HashMap::new(),
                generation: 0,
            }),
            data_file,
        });
        me
    }

    pub fn clear_cache(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.resolved.clear();
            g.dns_lookup.clear();
            g.dns_state.clear();
            g.latency.clear();
        }
    }

    /// Record an endpoint so the background speed-test loop keeps it warm.
    pub fn note(&self, host: &str, port: u16) {
        let mut changed = false;
        if let Ok(mut g) = self.inner.lock() {
            if !host.is_empty() && !g.endpoints.iter().any(|(h, p)| h == host && *p == port) {
                g.endpoints.push((host.to_string(), port));
                changed = true;
            }
        }
        if changed { self.persist(); }
    }

    /// Ranked list of upstream IPs. `pinned` corresponds to `DomainConfig.IPAddress`.
    pub fn resolve(&self, host: &str, port: u16, pinned: Option<IpAddr>) -> Vec<IpAddr> {
        if let Some(ip) = pinned { return vec![ip]; }
        if let Ok(ip) = host.parse::<IpAddr>() { return vec![ip]; }
        if host.eq_ignore_ascii_case("localhost") {
            return vec![
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ];
        }
        let key = (host.to_ascii_lowercase(), port);

        let gen = self.cfg.generation.load(std::sync::atomic::Ordering::SeqCst);
        if let Ok(g) = self.inner.lock() {
            if g.generation != gen { /* handled below by clear_cache via watcher */ }
            if let Some(e) = g.resolved.get(&key) {
                if e.expires > Instant::now() && !e.value.is_empty() {
                    return e.value.clone();
                }
            }
        }

        let addresses = self.lookup(host);
        let ranked = self.rank(&addresses, port);
        logger::info(&format!(
            "解析 {host}:{port} 候选={} {:?} 可达={} {:?}",
            addresses.len(), addresses, ranked.len(), ranked
        ));
        if !ranked.is_empty() {
            if let Ok(mut g) = self.inner.lock() {
                g.resolved.insert(
                    key.clone(),
                    CacheEntry { value: ranked.clone(), expires: Instant::now() + MAX_TTL },
                );
            }
            self.note(&key.0, port);
        }
        ranked
    }

    /// System resolver fallback for domains that are not in DomainConfigs.
    pub fn system_resolve(host: &str, port: u16) -> Vec<IpAddr> {
        match (host, port).to_socket_addrs() {
            Ok(it) => it.map(|s| s.ip()).collect(),
            Err(e) => {
                logger::warn(&format!("系统解析 {host}:{port} 失败: {e}"));
                Vec::new()
            }
        }
    }

    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        let cfg = self.cfg.current();
        let servers = cfg.fallback_dns.clone();
        let mut out: Vec<IpAddr> = Vec::new();
        let mut seen = HashSet::new();
        for server in servers {
            if !self.dns_available(server) { continue; }
            for qtype in [dns::TYPE_A, dns::TYPE_AAAA] {
                let ck = (format!("{host}/{qtype}"), server);
                let cached = if let Ok(g) = self.inner.lock() {
                    g.dns_lookup.get(&ck).filter(|e| e.expires > Instant::now()).map(|e| e.value.clone())
                } else {
                    None
                };
                let answers = match cached {
                    Some(v) => v,
                    None => {
                        let (ips, ttl) = match dns::query(server, host, qtype, DNS_QUERY_TIMEOUT) {
                            Ok(a) => {
                                let ttl = a.iter().map(|x| x.ttl).min().unwrap_or(30).clamp(30, 600);
                                (a.iter().map(|x| x.ip).collect::<Vec<IpAddr>>(), ttl)
                            }
                            Err(e) => {
                                logger::debug(&format!("{host}@{server} A/AAAA 查询失败: {e}"));
                                (Vec::new(), 30u32)
                            }
                        };
                        logger::debug(&format!("DNS {server} {host}/{qtype} -> {ips:?}"));
                        if let Ok(mut g) = self.inner.lock() {
                            g.dns_lookup.insert(
                                ck.clone(),
                                CacheEntry {
                                    value: ips.clone(),
                                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                                },
                            );
                        }
                        ips
                    }
                };
                for ip in answers {
                    if !ip.is_loopback() && seen.insert(ip) {
                        out.push(ip);
                    }
                }
            }
        }
        out
    }

    fn dns_available(&self, server: SocketAddr) -> bool {
        if server.port() != 53 { return true; }
        if let Ok(g) = self.inner.lock() {
            if let Some(e) = g.dns_state.get(&server) {
                if e.expires > Instant::now() { return e.value; }
            }
        }
        let ok = TcpStream::connect_timeout(&server, DNS_PROBE_TIMEOUT).is_ok();
        if let Ok(mut g) = self.inner.lock() {
            g.dns_state.insert(
                server,
                CacheEntry { value: ok, expires: Instant::now() + DNS_STATE_TTL },
            );
        }
        ok
    }

    /// Order candidates by TCP connect latency; unreachable ones are dropped.
    fn rank(&self, candidates: &[IpAddr], port: u16) -> Vec<IpAddr> {
        let mut measured: Vec<(IpAddr, Duration)> = Vec::new();
        for ip in candidates {
            let key = (*ip, port);
            let cached = if let Ok(g) = self.inner.lock() {
                g.latency.get(&key).filter(|e| e.expires > Instant::now()).map(|e| e.value)
            } else {
                None
            };
            let elapsed = match cached {
                Some(d) => d,
                None => {
                    let sa = SocketAddr::new(*ip, port);
                    let start = Instant::now();
                    let ok = TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT).is_ok();
                    let d = if ok { start.elapsed() } else { Duration::MAX };
                    let ttl = if d == Duration::MAX { Duration::from_secs(60) } else { LATENCY_TTL };
                    if let Ok(mut g) = self.inner.lock() {
                        g.latency.insert(key, CacheEntry { value: d, expires: Instant::now() + ttl });
                    }
                    d
                }
            };
            if elapsed != Duration::MAX { measured.push((*ip, elapsed)); }
        }
        measured.sort_by(|a, b| a.1.cmp(&b.1));
        measured.into_iter().map(|(ip, _)| ip).collect()
    }

    /// Background speed-test loop. Intentionally low frequency of DNS traffic:
    /// DNS answers are cached, so this mostly re-ranks known IPs.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::Builder::new()
            .name("speed-test".into())
            .spawn(move || {
                let mut last_generation = me.cfg.generation.load(std::sync::atomic::Ordering::SeqCst);
                while !platform::is_shutting_down() {
                    let gen = me.cfg.generation.load(std::sync::atomic::Ordering::SeqCst);
                    if gen != last_generation {
                        me.clear_cache();
                        last_generation = gen;
                    }
                    let period = me.cfg.current().silent.speed_test_interval_secs.max(1);
                    let endpoints: Vec<(String, u16)> = me
                        .inner
                        .lock()
                        .map(|g| g.endpoints.clone())
                        .unwrap_or_default();
                    for (host, port) in endpoints {
                        if platform::is_shutting_down() { break; }
                        let addresses = me.lookup(&host);
                        let ranked = me.rank(&addresses, port);
                        if let Ok(mut g) = me.inner.lock() {
                            g.resolved.insert(
                                (host, port),
                                CacheEntry { value: ranked, expires: Instant::now() + MAX_TTL },
                            );
                        }
                    }
                    for _ in 0..period {
                        if platform::is_shutting_down() { break; }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .ok();
    }

    fn persist(&self) {
        let endpoints: Vec<(String, u16)> = self
            .inner
            .lock()
            .map(|g| g.endpoints.clone())
            .unwrap_or_default();
        let items: Vec<serde_json::Value> = endpoints
            .iter()
            .map(|(h, p)| serde_json::json!({ "host": h, "port": p }))
            .collect();
        match serde_json::to_vec_pretty(&items) {
            Ok(bytes) => {
                if let Err(e) = fs::write(&self.data_file, bytes) {
                    logger::warn(&format!("保存 dnsendpoints.json 失败: {e}"));
                }
            }
            Err(e) => logger::warn(&format!("序列化 dnsendpoints.json 失败: {e}")),
        }
    }
}

fn read_endpoints(path: &Path) -> Vec<(String, u16)> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(arr) = value.as_array() else { return Vec::new() };
    arr.iter()
        .filter_map(|v| {
            let host = v.get("host")?.as_str()?.to_string();
            let port = v.get("port")?.as_u64()? as u16;
            Some((host, port))
        })
        .collect()
}

/// Try each candidate IP in turn, returning the first connected stream.
pub fn connect_first(
    addresses: &[IpAddr],
    port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last: Option<io::Error> = None;
    for ip in addresses {
        let sa = SocketAddr::new(*ip, port);
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(s) => {
                logger::info(&format!("上游 TCP 已连接 {sa}"));
                return Ok(s);
            }
            Err(e) => {
                logger::warn(&format!("上游 TCP 连接 {sa} 失败: {e}"));
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "无可用上游 IP")))
}
