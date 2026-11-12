//! TLS ClientHello inspection and SNI rewriting.
//!
//! The original controls the *upstream* SNI through
//! `SslClientAuthenticationOptions.TargetHost`. In tunnel mode we cannot
//! terminate TLS, but the ClientHello is still plaintext, so we can rewrite the
//! `server_name` extension in place (or drop it) before forwarding. This keeps
//! the `TlsSni` / `TlsSniPattern` behaviour without a CA, without a driver and
//! without administrator rights.

use std::net::IpAddr;

use crate::config::DomainConfig;
use crate::platform;

const EXT_SERVER_NAME: u16 = 0x0000;

fn u16be(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}

fn handshake_body(record: &[u8]) -> Option<&[u8]> {
    if record.len() < 9 { return None; }
    if record[0] != 0x16 || record[1] != 0x03 { return None; } // TLS handshake record
    let rec_len = u16be(record, 3)? as usize;
    if record.len() < 5 + rec_len { return None; }
    if record[5] != 0x01 { return None; } // ClientHello
    let hs_len = ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if 9 + hs_len > 5 + rec_len { return None; }
    // Only rewrite single-message records to avoid breaking coalesced handshakes.
    if 9 + hs_len != 5 + rec_len { return None; }
    record.get(9..9 + hs_len)
}

/// Offset of the 2-byte extensions-length field, plus the extensions blob.
fn extensions(body: &[u8]) -> Option<(usize, &[u8])> {
    let mut p = 2 + 32; // client_version + random
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16be(body, p)? as usize;
    p += 2 + cs_len;
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    let ext_len = u16be(body, p)? as usize;
    let ext = body.get(p + 2..p + 2 + ext_len)?;
    Some((p, ext))
}

fn first_server_name(ext: &[u8]) -> Option<String> {
    let mut p = 0usize;
    while p + 4 <= ext.len() {
        let kind = u16be(ext, p)?;
        let len = u16be(ext, p + 2)? as usize;
        let data = ext.get(p + 4..p + 4 + len)?;
        if kind == EXT_SERVER_NAME {
            let list_len = u16be(data, 0)? as usize;
            if list_len + 2 > data.len() { return Some(String::new()); }
            let mut q = 2usize;
            while q + 3 <= 2 + list_len {
                let name_type = *data.get(q)?;
                let n = u16be(data, q + 1)? as usize;
                let name = data.get(q + 3..q + 3 + n)?;
                if name_type == 0 { return Some(String::from_utf8_lossy(name).to_string()); }
                q += 3 + n;
            }
            return Some(String::new());
        }
        p += 4 + len;
    }
    None
}

/// SNI carried by a ClientHello, if any.
pub fn client_hello_sni(record: &[u8]) -> Option<String> {
    let body = handshake_body(record)?;
    let (_, ext) = extensions(body)?;
    first_server_name(ext)
}

pub fn looks_like_client_hello(record: &[u8]) -> bool {
    handshake_body(record).is_some()
}

fn encoded_server_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    let mut data = Vec::with_capacity(bytes.len() + 5);
    data.extend_from_slice(&((bytes.len() + 3) as u16).to_be_bytes()); // server_name_list length
    data.push(0); // host_name
    data.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(bytes);
    data
}

/// Rewrite the SNI extension. `None` removes the extension entirely (equivalent
/// to `TlsSni = false`); `Some(name)` replaces it. Returns the original bytes
/// unchanged when the record is not a rewritable ClientHello.
pub fn rewrite_client_hello(record: &[u8], new_sni: Option<&str>) -> Vec<u8> {
    let Some(body) = handshake_body(record) else { return record.to_vec() };
    let Some((ext_pos, ext)) = extensions(body) else { return record.to_vec() };

    let mut new_ext: Vec<u8> = Vec::with_capacity(ext.len() + 32);
    let mut p = 0usize;
    let mut seen_sni = false;
    while p + 4 <= ext.len() {
        let Some(kind) = u16be(ext, p) else { break };
        let Some(raw_len) = u16be(ext, p + 2) else { break };
        let len = raw_len as usize;
        let Some(data) = ext.get(p + 4..p + 4 + len) else { break };
        p += 4 + len;
        if kind == EXT_SERVER_NAME {
            if seen_sni { continue; }
            seen_sni = true;
            match new_sni {
                None => continue, // drop the extension: no SNI is sent
                Some(name) => {
                    let encoded = encoded_server_name(name);
                    new_ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
                    new_ext.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                    new_ext.extend_from_slice(&encoded);
                }
            }
        } else {
            new_ext.extend_from_slice(&kind.to_be_bytes());
            new_ext.extend_from_slice(&(len as u16).to_be_bytes());
            new_ext.extend_from_slice(data);
        }
    }
    if !seen_sni {
        if let Some(name) = new_sni {
            let encoded = encoded_server_name(name);
            new_ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            new_ext.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
            new_ext.extend_from_slice(&encoded);
        }
    }

    let hs_len = (ext_pos + 2 + new_ext.len()) as u32;
    let mut out = Vec::with_capacity(9 + hs_len as usize);
    out.extend_from_slice(&record[..3]); // content type + legacy version
    out.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
    out.push(0x01);
    out.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
    out.extend_from_slice(&body[..ext_pos]);
    out.extend_from_slice(&(new_ext.len() as u16).to_be_bytes());
    out.extend_from_slice(&new_ext);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DomainConfig;

    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut ext_data = Vec::new();
        ext_data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext_data.push(0);
        ext_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(name);
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&ext_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let hs_len = body.len() as u32;
        let mut rec = Vec::new();
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        rec.push(0x01);
        rec.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn reads_and_rewrites_sni() {
        let hello = client_hello("github.com");
        assert!(looks_like_client_hello(&hello));
        assert_eq!(client_hello_sni(&hello).as_deref(), Some("github.com"));

        let replaced = rewrite_client_hello(&hello, Some("api.github.com"));
        assert_eq!(client_hello_sni(&replaced).as_deref(), Some("api.github.com"));
        assert!(looks_like_client_hello(&replaced));

        let stripped = rewrite_client_hello(&hello, None);
        assert!(looks_like_client_hello(&stripped));
        assert_eq!(client_hello_sni(&stripped), None);
        assert!(stripped.len() < hello.len());
    }

    #[test]
    fn upstream_sni_omits_sni_when_disabled() {
        let ip: IpAddr = "140.82.112.3".parse().unwrap();
        // github.com and its CDN family explicitly omit SNI: no SNI at all.
        assert_eq!(upstream_sni(&DomainConfig::default(), "github.com", &ip), None);

        // Unconfigured domains default to tls_sni=true: normal SNI.
        let on = DomainConfig { tls_sni: true, ..Default::default() };
        assert_eq!(upstream_sni(&on, "github.com", &ip).as_deref(), Some("github.com"));

        // Explicit TlsSniPattern variables are expanded.
        let pattern = DomainConfig {
            tls_sni: true,
            tls_sni_pattern: Some("@domain.via.@ipaddress".into()),
            ..Default::default()
        };
        assert_eq!(
            upstream_sni(&pattern, "github.com", &ip).as_deref(),
            Some("github.com.via.140.82.112.3")
        );
    }

    #[test]
    fn rewritten_record_lengths_are_consistent() {
        let hello = client_hello("github.com");
        for target in [None, Some("github.com"), Some("example.org")] {
            let out = rewrite_client_hello(&hello, target);
            let rec_len = u16be(&out, 3).unwrap() as usize;
            assert_eq!(rec_len + 5, out.len(), "record length mismatch for {target:?}");
            let hs_len = ((out[6] as usize) << 16) | ((out[7] as usize) << 8) | out[8] as usize;
            assert_eq!(hs_len + 4, rec_len, "handshake length mismatch for {target:?}");
            assert!(looks_like_client_hello(&out), "not a ClientHello for {target:?}");
        }
    }
}

/// Outbound SNI policy, matching the original `HttpClientHandler.TargetHost`.
///
/// Only usable in MITM mode, where *we* are the TLS client and therefore own
/// the ClientHello. `None` means "omit the SNI extension entirely", which is
/// what `TlsSni = false` means in the original and what avoids SNI-based
/// blocking. It must never be applied by rewriting a browser's ClientHello:
/// TLS transcript hashes cover those bytes, so any edit breaks `Finished`.
pub fn upstream_sni(cfg: &DomainConfig, domain: &str, ip: &IpAddr) -> Option<String> {
    if !cfg.tls_sni {
        return None;
    }
    let pattern = cfg.tls_sni_pattern.as_deref().unwrap_or("@domain");
    let value = pattern
        .replace("@domain", domain)
        .replace("@ipaddress", &ip.to_string())
        .replace("@random", &platform::tick_ms().to_string());
    if value.is_empty() { None } else { Some(value) }
}
