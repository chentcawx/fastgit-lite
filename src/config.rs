//! Configuration: reads the original `appsettings.json` + `appsettings/*.json`
//! verbatim (including `//` comments and UTF-8 BOM), merges them, supports hot
//! reload, and implements the original `DomainPattern` matching/priority rules.

use serde::Deserialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use crate::logger;
use crate::platform::{self, Cli};

// ---------------------------------------------------------------------------
// Wire format (PascalCase keys are kept compatible with the .NET original)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RootFile {
    #[serde(rename = "FastGithub")]
    pub fast_github: FastGithubOptions,
    #[serde(rename = "AppOptions")]
    pub app_options: AppOptionsJson,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AppOptionsJson {
    #[serde(rename = "ParentProcessId")]
    pub parent_process_id: u32,
    #[serde(rename = "UdpLoggerPort")]
    pub udp_logger_port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FastGithubOptions {
    #[serde(rename = "HttpProxyPort")]
    pub http_proxy_port: u16,
    #[serde(rename = "FallbackDns")]
    pub fallback_dns: Vec<String>,
    #[serde(rename = "DomainConfigs")]
    pub domain_configs: std::collections::HashMap<String, DomainConfig>,
    /// Rust-specific extension block. Ignored by the original .NET app.
    #[serde(rename = "Silent")]
    pub silent: SilentOptions,
}

impl Default for FastGithubOptions {
    fn default() -> Self {
        Self {
            http_proxy_port: 38457,
            fallback_dns: vec![
                "8.8.8.8:53".into(),
                "119.29.29.29:53".into(),
                "114.114.114.114:53".into(),
            ],
            domain_configs: Default::default(),
            silent: SilentOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct ResponseConfig {
    #[serde(rename = "StatusCode")]
    pub status_code: u16,
    #[serde(rename = "ContentType")]
    pub content_type: String,
    #[serde(rename = "ContentValue")]
    pub content_value: Option<String>,
}

impl ResponseConfig {
    fn normalized(&self) -> ResponseConfig {
        ResponseConfig {
            status_code: if self.status_code == 0 { 200 } else { self.status_code },
            content_type: if self.content_type.is_empty() {
                "text/plain;charset=utf-8".into()
            } else {
                self.content_type.clone()
            },
            content_value: self.content_value.clone(),
        }
    }
}

/// Mirrors `FastGithub.Configuration.DomainConfig`.
/// `TlsSni` defaults to `false`: on this network EVERY github-family SNI is
/// reset (measured: sending SNI=github.githubassets.com is RST'd immediately),
/// so configured hosts omit SNI by default. Hosts absent from `DomainConfigs`
/// fall back to `default_for_unconfigured()` with ordinary SNI.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct DomainConfig {
    #[serde(rename = "TlsSni")]
    pub tls_sni: bool,
    #[serde(rename = "TlsSniPattern")]
    pub tls_sni_pattern: Option<String>,
    #[serde(rename = "TlsIgnoreNameMismatch")]
    pub tls_ignore_name_mismatch: bool,
    #[serde(rename = "IPAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "Timeout")]
    pub timeout: Option<String>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Response")]
    pub response: Option<ResponseConfig>,
}

impl DomainConfig {
    pub fn default_for_unconfigured() -> Self {
        Self { tls_sni: true, ..Default::default() }
    }

    /// Parse `"00:02:00"` into a Duration; invalid values fall back to 10s.
    pub fn timeout_duration(&self, fallback: Duration) -> Duration {
        let Some(text) = self.timeout.as_deref() else { return fallback };
        let parts: Vec<u64> = text.split(':').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 3 {
            Duration::from_secs(parts[0] * 3600 + parts[1] * 60 + parts[2])
        } else {
            fallback
        }
    }
}

/// Rust-only options that control the silent/background operating mode.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct SilentOptions {
    /// "proxy" (tunnel + SNI rewrite, no CA needed) or "mitm" (full HTTPS decode).
    pub mode: String,
    pub log_level: String,
    pub log_to_file: bool,
    pub udp_log: bool,
    pub single_instance: bool,
    pub watch_config: bool,
    pub pac_enabled: bool,
    /// Address the HTTP forward proxy binds. `127.0.0.1` keeps it private to
    /// this machine; `0.0.0.0` exposes port 38457 to the LAN. The PAC endpoint
    /// echoes back the address the client actually connected to.
    pub proxy_bind: String,
    pub flow_statistics: bool,
    /// Ad / tracker blocking driven by `config/ad-domains.txt`.
    pub ad_block: AdBlockOptions,
    /// Local DNS listener that answers configured domains with loopback.
    pub dns_enabled: bool,
    pub dns_bind: String,
    /// Bind 127.0.0.1:443 and tunnel TLS using ClientHello SNI.
    pub https_listener: bool,
    /// Bind 127.0.0.1:80 and reverse-proxy plain HTTP by Host.
    pub http_listener: bool,
    /// github.com:22 / :9418 reverse proxies on 127.0.0.1.
    pub ssh_proxy: bool,
    pub git_proxy: bool,
    pub connect_timeout_secs: u64,
    pub speed_test_interval_secs: u64,
    pub mitm: MitmOptions,
}

impl Default for SilentOptions {
    fn default() -> Self {
        Self {
            mode: "proxy".into(),
            log_level: "Information".into(),
            log_to_file: true,
            udp_log: true,
            single_instance: true,
            watch_config: true,
            pac_enabled: true,
            proxy_bind: "127.0.0.1".into(),
            flow_statistics: true,
            ad_block: AdBlockOptions::default(),
            dns_enabled: true,
            dns_bind: "127.0.0.1:53".into(),
            https_listener: true,
            http_listener: true,
            ssh_proxy: true,
            git_proxy: true,
            connect_timeout_secs: 10,
            speed_test_interval_secs: 1,
            mitm: MitmOptions::default(),
        }
    }
}

/// Ad filtering is a plain host list, not a `DomainConfigs` entry: blocked
/// hosts never reach DNS resolution or the upstream TLS handshake.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct AdBlockOptions {
    pub enabled: bool,
    /// HTTP status returned for blocked requests. 200 with an empty body is
    /// the safest choice for mixed image/script/font requests.
    pub status_code: u16,
}

impl Default for AdBlockOptions {
    fn default() -> Self {
        Self { enabled: true, status_code: 200 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct MitmOptions {
    pub enabled: bool,
    pub ca_dir: String,
    /// Requires administrator rights and writes to LocalMachine\Root.
    /// Kept OFF by default: a silent background process must not modify the OS.
    pub install_ca: bool,
    /// Never spawn `git config` from a silent process. Kept OFF by default.
    pub configure_git: bool,
    pub server_name_in_san: bool,
}

impl SilentOptions {
    /// MITM is the only mode that can control the upstream SNI without
    /// breaking the TLS transcript with the browser.
    pub fn is_mitm(&self) -> bool {
        self.mode.eq_ignore_ascii_case("mitm") || self.mitm.enabled
    }
}

impl Default for MitmOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_dir: "cacert".into(),
            install_ca: false,
            configure_git: false,
            server_name_in_san: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain patterns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DomainPattern {
    raw: String,
    segments: Vec<String>,
}

/// Compare like `DomainPattern.CompareTo`: fewer segments first, then from the
/// rightmost segment leftwards, with `*` treated as greater than any character.
impl Ord for DomainPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.segments.len().cmp(&other.segments.len()).then_with(|| {
            for i in (0..self.segments.len()).rev() {
                let a = segment_key(&self.segments[i]);
                let b = segment_key(&other.segments[i]);
                match a.cmp(&b) {
                    Ordering::Equal => continue,
                    o => return o,
                }
            }
            self.raw.cmp(&other.raw)
        })
    }
}
impl PartialOrd for DomainPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

fn segment_key(s: &str) -> String {
    // `char::MAX` stands in for `*`; a plain String comparison is equivalent
    // here because '*' would otherwise sort before alphanumerics.
    s.replace('*', "\u{ffff}")
}

impl DomainPattern {
    pub fn new(raw: &str) -> Self {
        let raw = raw.trim().to_ascii_lowercase();
        let segments = raw.split('.').map(|s| s.to_string()).collect();
        Self { raw, segments }
    }

    pub fn as_str(&self) -> &str { &self.raw }

    /// `*` matches zero or more characters other than '.', case-insensitively.
    pub fn is_match(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() != self.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(parts.iter())
            .all(|(pat, part)| wildcard_match(pat, part))
    }
}

/// Classic iterative wildcard matcher ('*' only).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut i, mut j, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    while j < t.len() {
        if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            mark = j;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' { i += 1; }
    i == p.len()
}

/// Parse `config/ad-domains.txt`. Accepted forms per line:
/// `example.com`, `*.example.com`, `||example.com^`, `0.0.0.0 example.com`.
/// `#` / `//` comments and blank lines are ignored.
pub fn parse_ad_domains(text: &str) -> Vec<DomainPattern> {
    let mut out: Vec<DomainPattern> = Vec::new();
    for raw in text.lines() {
        let mut line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if let Some(pos) = line.find(" #") { line = line[..pos].trim(); }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut host = if parts.len() >= 2
            && matches!(parts[0], "0.0.0.0" | "127.0.0.1" | "::" | "::1")
        {
            parts[1]
        } else {
            parts[0]
        };
        host = host.trim_start_matches("||").trim_end_matches('^').trim();
        if host.is_empty() || host.contains('/') || host.contains(':') {
            continue;
        }
        let pattern = DomainPattern::new(host);
        if !out.contains(&pattern) { out.push(pattern); }
    }
    out
}

// ---------------------------------------------------------------------------
// Effective configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub http_proxy_port: u16,
    pub fallback_dns: Vec<SocketAddr>,
    pub patterns: Vec<(DomainPattern, DomainConfig)>,
    pub ad_domains: Vec<DomainPattern>,
    pub silent: SilentOptions,
    pub parent_process_id: u32,
    pub udp_logger_port: u16,
}

impl Config {
    pub fn match_domain(&self, host: &str) -> Option<DomainConfig> {
        self.patterns
            .iter()
            .find(|(p, _)| p.is_match(host))
            .map(|(_, c)| c.clone())
    }

    /// Match with the original "unconfigured but DNS-hijacked" fallback.
    pub fn match_domain_or_default(&self, host: &str) -> DomainConfig {
        self.match_domain(host).unwrap_or_else(DomainConfig::default_for_unconfigured)
    }

    pub fn is_ad_domain(&self, host: &str) -> bool {
        self.silent.ad_block.enabled && self.ad_domains.iter().any(|p| p.is_match(host))
    }

    pub fn ad_patterns(&self) -> &[DomainPattern] {
        &self.ad_domains
    }

    pub fn domain_patterns(&self) -> Vec<String> {
        self.patterns.iter().map(|(p, _)| p.as_str().to_string()).collect()
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.silent.connect_timeout_secs.max(1))
    }
}

pub struct ConfigStore {
    inner: RwLock<Arc<Config>>,
    files: Vec<PathBuf>,
    stamps: Mutex<Vec<u64>>,
    cli: Cli,
    pub generation: AtomicU64,
}

impl ConfigStore {
    pub fn load(root: &Path, cli: Cli) -> Result<Arc<Self>, String> {
        let config_dir = root.join("config");
        let base = config_dir.join("appsettings.json");
        if !base.exists() {
            return Err(format!("缺少主配置文件 {}", base.display()));
        }
        let mut files = vec![base];
        let sub = config_dir.join("appsettings");
        if let Ok(rd) = fs::read_dir(&sub) {
            let mut extra: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("appsettings.") && n.ends_with(".json"))
                        .unwrap_or(false)
                })
                .collect();
            extra.sort();
            files.extend(extra);
        }
        // Plain-text ad list participates in the same hot-reload timestamp set.
        let ad_list = config_dir.join("ad-domains.txt");
        if ad_list.exists() { files.push(ad_list); }

        let store = Arc::new(Self {
            inner: RwLock::new(Arc::new(Config {
                http_proxy_port: 38457,
                fallback_dns: Vec::new(),
                patterns: Vec::new(),
                ad_domains: Vec::new(),
                silent: SilentOptions::default(),
                parent_process_id: 0,
                udp_logger_port: 38457,
            })),
            files: files.clone(),
            stamps: Mutex::new(vec![0; files.len()]),
            cli,
            generation: AtomicU64::new(1),
        });
        let cfg = store.build_config()?;
        *store.inner.write().map_err(|e| e.to_string())? = Arc::new(cfg);
        *store.stamps.lock().map_err(|e| e.to_string())? = stamp_all(&files);
        Ok(store)
    }

    pub fn current(&self) -> Arc<Config> {
        self.inner.read().map(|g| g.clone()).unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Reload if any file changed. Returns true when the config was replaced.
    pub fn check_reload(&self) -> bool {
        let fresh = stamp_all(&self.files);
        let changed = {
            let mut guard = match self.stamps.lock() { Ok(g) => g, Err(e) => e.into_inner() };
            let changed = *guard != fresh;
            if changed { *guard = fresh; }
            changed
        };
        if !changed { return false; }
        match self.build_config() {
            Ok(cfg) => {
                if let Ok(mut guard) = self.inner.write() { *guard = Arc::new(cfg); }
                self.generation.fetch_add(1, AtomicOrdering::SeqCst);
                logger::info("配置文件已变更，已热加载并刷新 DNS 缓存");
                platform::flush_dns_cache();
                true
            }
            Err(e) => {
                logger::error(&format!("配置热加载失败，保留上一次有效配置: {e}"));
                false
            }
        }
    }

    pub fn start_watcher(self: &Arc<Self>, enabled: bool) {
        if !enabled { return; }
        let me = self.clone();
        std::thread::Builder::new()
            .name("config-watcher".into())
            .spawn(move || {
                while !platform::is_shutting_down() {
                    std::thread::sleep(Duration::from_secs(2));
                    me.check_reload();
                }
            })
            .ok();
    }

    fn build_config(&self) -> Result<Config, String> {
        let mut merged = Value::Object(serde_json::Map::new());
        let mut ad_domains: Vec<DomainPattern> = Vec::new();
        for file in &self.files {
            let raw = match fs::read(file) { Ok(r) => r, Err(_) => continue };
            let is_txt = file
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("txt"))
                .unwrap_or(false);
            if is_txt {
                ad_domains.extend(parse_ad_domains(&String::from_utf8_lossy(&raw)));
                continue;
            }
            let text = String::from_utf8_lossy(&raw);
            let cleaned = strip_json_comments(text.trim_start_matches('\u{feff}'));
            let value: Value = serde_json::from_str(&cleaned)
                .map_err(|e| format!("{} JSON 解析失败: {e}", file.display()))?;
            merge_json(&mut merged, value);
        }
        ad_domains.sort_by(|a, b| a.cmp(b));
        ad_domains.dedup();
        apply_overrides(&mut merged, &self.cli.overrides);
        let root: RootFile = serde_json::from_value(merged)
            .map_err(|e| format!("配置模型绑定失败: {e}"))?;

        let mut patterns: Vec<(DomainPattern, DomainConfig)> = root
            .fast_github
            .domain_configs
            .iter()
            .map(|(k, v)| {
                let mut v = v.clone();
                if let Some(r) = v.response.as_mut() { *r = r.normalized(); }
                (DomainPattern::new(k), v)
            })
            .collect();
        patterns.sort_by(|a, b| a.0.cmp(&b.0));

        let fallback_dns = root
            .fast_github
            .fallback_dns
            .iter()
            .filter_map(|s| resolve_endpoint(s))
            .collect();

        let udp_port = self
            .cli
            .udp_logger_port
            .or(root.app_options.udp_logger_port)
            .unwrap_or(root.fast_github.http_proxy_port);

        Ok(Config {
            http_proxy_port: root.fast_github.http_proxy_port,
            fallback_dns,
            patterns,
            ad_domains,
            silent: root.fast_github.silent,
            parent_process_id: if self.cli.parent_process_id > 0 {
                self.cli.parent_process_id
            } else {
                root.app_options.parent_process_id
            },
            udp_logger_port: udp_port,
        })
    }
}

fn resolve_endpoint(s: &str) -> Option<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() { return Some(addr); }
    // Allow "8.8.8.8" (defaults to :53) as well as "8.8.8.8:53".
    let with_port = format!("{s}:53");
    with_port.to_socket_addrs().ok()?.next()
}

fn stamp_all(files: &[PathBuf]) -> Vec<u64> {
    files
        .iter()
        .map(|p| {
            fs::metadata(p)
                .map(|m| {
                    let secs = m
                        .modified()
                        .unwrap_or(UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    secs ^ (m.len() << 16)
                })
                .unwrap_or(0)
        })
        .collect()
}

/// Remove `//` and `/* */` comments outside of JSON strings. The original
/// appsettings.json ships with inline comments, which serde_json rejects.
fn strip_json_comments(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0usize;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                i += 1;
                out.push(chars[i]);
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
        } else if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' { i += 1; }
        } else if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') { i += 1; }
            i = (i + 2).min(chars.len());
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn merge_json(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(&k) {
                    Some(slot) if slot.is_object() && v.is_object() => merge_json(slot, v),
                    _ => { a.insert(k, v); }
                }
            }
        }
        (slot, v) => *slot = v,
    }
}

/// `FastGithub.HttpProxyPort=38458` style dotted overrides.
fn apply_overrides(root: &mut Value, overrides: &[(String, String)]) {
    for (key, value) in overrides {
        let path: Vec<&str> = key.split('.').collect();
        let v: Value = match serde_json::from_str(value) {
            Ok(v) => v,
            Err(_) => Value::String(value.clone()),
        };
        let mut slot: &mut Value = &mut *root;
        for (idx, part) in path.iter().enumerate() {
            if idx + 1 == path.len() {
                if let Value::Object(map) = slot { map.insert((*part).to_string(), v.clone()); }
            } else if let Value::Object(map) = slot {
                slot = map.entry((*part).to_string()).or_insert_with(|| Value::Object(serde_json::Map::new()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_stripping_keeps_strings() {
        let input = "{\n // line\n \"url\": \"http://a/b\", /* block */ \"n\": 1\n}";
        let out = strip_json_comments(input);
        assert!(!out.contains("// line"));
        assert!(!out.contains("block"));
        assert!(out.contains("http://a/b"));
        assert!(serde_json::from_str::<Value>(&out).is_ok());
    }

    #[test]
    fn omitted_tls_sni_keeps_no_sni_default() {
        // github-family hosts are SNI-blocked; omitting SNI is intentional.
        let c: DomainConfig = serde_json::from_str(r#"{"TlsIgnoreNameMismatch":true}"#).unwrap();
        assert!(!c.tls_sni);
        assert!(c.tls_ignore_name_mismatch);

        let on: DomainConfig = serde_json::from_str(r#"{"TlsSni":true}"#).unwrap();
        assert!(on.tls_sni);
        assert!(DomainConfig::default_for_unconfigured().tls_sni);
    }

    #[test]
    fn ad_domain_list_parses_common_formats() {
        let text = "# comment\n// comment\n\nexample.com\n*.ads.cn # inline\n\
                    ||tracker.cn^\n0.0.0.0 blocked.cn\n127.0.0.1 bad.cn\n\
                    https://not-a-host/path\n";
        let list = parse_ad_domains(text);
        let names: Vec<&str> = list.iter().map(|p| p.as_str()).collect();
        for expected in ["example.com", "*.ads.cn", "tracker.cn", "blocked.cn", "bad.cn"] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        assert!(!names.iter().any(|n| n.contains("https")));
        assert!(list.iter().any(|p| p.is_match("x.ads.cn")));
    }

    #[test]
    fn ad_block_defaults_to_enabled_empty_200() {
        let a: AdBlockOptions = serde_json::from_str("{}").unwrap();
        assert!(a.enabled);
        assert_eq!(a.status_code, 200);
        let off: AdBlockOptions = serde_json::from_str(r#"{"Enabled":false,"StatusCode":204}"#).unwrap();
        assert!(!off.enabled);
        assert_eq!(off.status_code, 204);
    }

    #[test]
    fn domain_pattern_wildcards() {
        assert!(DomainPattern::new("*.github.com").is_match("raw.githubusercontent.com") == false);
        assert!(DomainPattern::new("*.github.com").is_match("api.github.com"));
        assert!(DomainPattern::new("*.github.com").is_match("API.GITHUB.COM")); // case-insensitive
        // The original regex is ^[^\.]*\.github\.com$ : '*' cannot span a dot,
        // so the apex domain needs its own "github.com" pattern.
        assert!(!DomainPattern::new("*.github.com").is_match("GITHUB.COM"));
        assert!(DomainPattern::new("github.com").is_match("GITHUB.COM"));
        assert!(!DomainPattern::new("*.*.fastly.net").is_match("a.fastly.net"));
        assert!(DomainPattern::new("*.*.fastly.net").is_match("a.b.fastly.net"));
        assert!(!DomainPattern::new("*.github.com").is_match("a.b.github.com"));
    }

    #[test]
    fn exact_pattern_wins_over_wildcard() {
        let mut patterns = vec![
            DomainPattern::new("*.github.com"),
            DomainPattern::new("github.com"),
        ];
        patterns.sort();
        assert_eq!(patterns[0].as_str(), "github.com");
    }

    #[test]
    fn destination_resolution() {
        let d = resolve_destination("https", "ajax.googleapis.com", Some("https://gapis.geekzu.org/ajax/")).unwrap();
        assert_eq!(d.0, "https");
        assert_eq!(d.1, "gapis.geekzu.org");
        assert_eq!(d.2, 443);
        assert_eq!(d.3, "/ajax");
    }
}

/// Absolute/relative `Destination` resolution (mirrors `new Uri(baseUri, destination)`).
pub fn resolve_destination(scheme: &str, host: &str, destination: Option<&str>) -> Option<(String, String, u16, String)> {
    let dest = destination?;
    let (d_scheme, rest) = match dest.split_once("://") {
        Some((s, r)) => (s.to_string(), r.to_string()),
        None => (scheme.to_string(), format!("{host}{dest}")),
    };
    let (authority, base_path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (d_host, d_port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse().unwrap_or(443)),
        _ => (authority, if d_scheme == "https" { 443 } else { 80 }),
    };
    let base_path = if base_path.ends_with('/') {
        base_path.trim_end_matches('/').to_string()
    } else {
        base_path
    };
    Some((d_scheme, d_host, d_port, base_path))
}
