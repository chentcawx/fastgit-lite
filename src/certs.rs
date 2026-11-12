//! Local CA and on-demand leaf certificates for MITM mode.
//!
//! Mirrors `FastGithub.HttpServer/Certs`: a 10-year self-signed CA persisted in
//! `cacert/`, one-year leaf certificates issued per SNI host and cached in
//! memory. A `ResolvesServerCert` hands rustls the right certificate based on
//! the ClientHello SNI, so the same `ServerConfig` serves every listener.
//!
//! The CA is never installed automatically. `scripts/install-ca.ps1` is an
//! explicit, one-off, administrator action; runtime stays silent and UAC-free.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::crypto::CryptoProvider;
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

use crate::logger;

fn rc_err<E: fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

struct CaSigner {
    cert: rcgen::Certificate,
    key: KeyPair,
}

pub struct CertAuthority {
    #[allow(dead_code)]
    dir: PathBuf,
    ca_der: CertificateDer<'static>,
    signer: Mutex<CaSigner>,
    provider: Arc<CryptoProvider>,
    certs: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    server: OnceLock<Arc<ServerConfig>>,
}

impl fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertAuthority")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// Explicitly rotate the local CA. Old files are copied into a timestamped
/// backup subfolder before replacement. The OS certificate store is never
/// touched — clients must import the new `fastgithub.cer` themselves.
/// Leaf certificates are re-issued on the next process start.
pub fn regenerate(root: &Path, dir_name: &str) -> io::Result<PathBuf> {
    let dir = root.join(if dir_name.is_empty() { "cacert" } else { dir_name });
    fs::create_dir_all(&dir)?;
    let names = ["fastgithub.cer", "fastgithub.key", "fastgithub-ca.pem"];
    if names.iter().any(|n| dir.join(n).exists()) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backup = dir.join(format!("backup-{stamp}"));
        fs::create_dir_all(&backup)?;
        for name in &names {
            let src = dir.join(name);
            if src.exists() {
                fs::copy(&src, backup.join(name))?;
                fs::remove_file(&src)?;
            }
        }
        logger::warn(&format!("旧 CA 已备份到 {}", backup.display()));
    }
    generate_ca(&dir.join(names[0]), &dir.join(names[1]), &dir.join(names[2]))?;
    logger::info("已重新生成本地 CA；所有客户端必须重新导入新的 fastgithub.cer");
    Ok(dir)
}

impl CertAuthority {
    pub fn load(root: &Path, dir_name: &str) -> io::Result<Arc<Self>> {
        let dir = root.join(if dir_name.is_empty() { "cacert" } else { dir_name });
        fs::create_dir_all(&dir)?;
        let cer = dir.join("fastgithub.cer");
        let key = dir.join("fastgithub.key");
        let pem = dir.join("fastgithub-ca.pem");

        if !cer.exists() || !key.exists() || !pem.exists() {
            generate_ca(&cer, &key, &pem)?;
            logger::info(&format!(
                "已生成本地 CA {}；需运行 scripts\\install-ca.ps1 安装一次",
                cer.display()
            ));
        } else {
            logger::info(&format!("已加载本地 CA {}", cer.display()));
        }

        let ca_der = CertificateDer::from(fs::read(&cer)?);
        let key_pem = fs::read_to_string(&key)?;
        let ca_key = KeyPair::from_pem(&key_pem).map_err(rc_err)?;
        // Rebuild a signer certificate from the stored DER. Only its subject
        // and key identifier are used when signing leaves; the chain sent to
        // clients always contains the original, imported CA certificate.
        let params = CertificateParams::from_ca_cert_der(&ca_der).map_err(rc_err)?;
        let signer_cert = params.self_signed(&ca_key).map_err(rc_err)?;

        let me = Arc::new(Self {
            dir,
            ca_der,
            signer: Mutex::new(CaSigner { cert: signer_cert, key: ca_key }),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            certs: Mutex::new(HashMap::new()),
            server: OnceLock::new(),
        });
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DynamicResolver { ca: me.clone() }));
        let _ = me.server.set(Arc::new(cfg));
        // Warm up the fallback certificate so a missing SNI never aborts a handshake.
        let _ = me.certified_key("fastgithub.local");
        Ok(me)
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.dir.join("fastgithub-ca.pem")
    }

    pub fn server_config(&self) -> Option<Arc<ServerConfig>> {
        self.server.get().cloned()
    }

    pub fn certified_key(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let name = match host.trim().to_ascii_lowercase() {
            s if s.is_empty() => "fastgithub.local".to_string(),
            s => s,
        };
        if let Ok(g) = self.certs.lock() {
            if let Some(v) = g.get(&name) {
                return Some(v.clone());
            }
        }
        let (chain, key) = self.issue(&name).ok()?;
        let ck = CertifiedKey::from_der(chain, key, self.provider.as_ref()).ok()?;
        let arc = Arc::new(ck);
        if let Ok(mut g) = self.certs.lock() {
            g.insert(name, arc.clone());
        }
        Some(arc)
    }

    fn issue(
        &self,
        host: &str,
    ) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut p = match host.parse::<IpAddr>() {
            Ok(ip) => {
                let mut q = CertificateParams::new(Vec::new()).map_err(rc_err)?;
                q.subject_alt_names.push(SanType::IpAddress(ip));
                q
            }
            Err(_) => CertificateParams::new(vec![host.to_string()]).map_err(rc_err)?,
        };
        p.distinguished_name.push(DnType::CommonName, host);
        p.use_authority_key_identifier_extension = true;
        p.key_usages.push(KeyUsagePurpose::DigitalSignature);
        p.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(365);

        let leaf_key = KeyPair::generate().map_err(rc_err)?;
        let leaf = {
            let signer = self.signer.lock().map_err(rc_err)?;
            p.signed_by(&leaf_key, &signer.cert, &signer.key)
                .map_err(rc_err)?
        };
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        Ok((chain, PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into())))
    }
}

#[derive(Debug)]
struct DynamicResolver {
    ca: Arc<CertAuthority>,
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.ca.certified_key(hello.server_name().unwrap_or("fastgithub.local"))
    }
}

fn generate_ca(cer: &Path, key: &Path, pem: &Path) -> io::Result<()> {
    let mut p = CertificateParams::new(Vec::new()).map_err(rc_err)?;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages.push(KeyUsagePurpose::DigitalSignature);
    p.key_usages.push(KeyUsagePurpose::KeyCertSign);
    p.key_usages.push(KeyUsagePurpose::CrlSign);
    p.distinguished_name
        .push(DnType::CommonName, "FastGithub Local CA");
    p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);

    let ca_key = KeyPair::generate().map_err(rc_err)?;
    let ca = p.self_signed(&ca_key).map_err(rc_err)?;
    fs::write(cer, ca.der().as_ref())?;
    fs::write(key, ca_key.serialize_pem())?;
    fs::write(pem, ca.pem())?;
    Ok(())
}
