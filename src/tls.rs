//! TLS stream wrappers for MITM mode, built on rustls `StreamOwned`.
//!
//! * Server side: terminates the browser's TLS using a locally issued leaf
//!   certificate chosen by SNI (`certs::CertAuthority`).
//! * Client side: connects to the upstream with an independently constructed
//!   ClientHello. Passing an IP as `ServerName` makes rustls omit SNI entirely
//!   (TLS forbids an IP literal in SNI), which is exactly what
//!   `TlsSni = false` means in the original. Certificate verification is
//!   skipped to reproduce `TlsIgnoreNameMismatch` / `RemoteCertificateValidationCallback`.
//!
//! Handshakes are completed explicitly before returning the stream, so the
//! caller only ever sees plaintext HTTP bytes.

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};

pub type ServerTlsStream = StreamOwned<ServerConnection, TcpStream>;
pub type ClientTlsStream = StreamOwned<ClientConnection, TcpStream>;

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Equivalent to the original `HttpClientHandler`'s
/// `RemoteCertificateValidationCallback => true`.
#[derive(Debug)]
pub struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth(),
        )
    })
    .clone()
}

pub fn server_stream(mut tcp: TcpStream, cfg: Arc<ServerConfig>) -> io::Result<ServerTlsStream> {
    let mut conn = ServerConnection::new(cfg).map_err(io_err)?;
    for _ in 0..64 {
        if !conn.is_handshaking() {
            break;
        }
        conn.complete_io(&mut tcp).map_err(io_err)?;
    }
    if conn.is_handshaking() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "TLS 服务端握手未完成"));
    }
    Ok(StreamOwned::new(conn, tcp))
}

/// `sni = None` omits the SNI extension (blocked networks inspect it);
/// `Some(name)` sends that name, honouring `TlsSniPattern`.
pub fn client_stream(mut tcp: TcpStream, sni: Option<&str>) -> io::Result<ClientTlsStream> {
    let peer_ip = tcp.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| {
        "127.0.0.1".parse().unwrap()
    });
    let name = match sni {
        Some(s) if !s.is_empty() => ServerName::try_from(s.to_string()).map_err(io_err)?,
        _ => ServerName::IpAddress(peer_ip.into()),
    };
    let mut conn = ClientConnection::new(client_config(), name).map_err(io_err)?;
    for _ in 0..64 {
        if !conn.is_handshaking() {
            break;
        }
        conn.complete_io(&mut tcp).map_err(io_err)?;
    }
    if conn.is_handshaking() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "TLS 上游握手未完成"));
    }
    Ok(StreamOwned::new(conn, tcp))
}
