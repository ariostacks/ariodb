//! TLS for both sides: agents connecting to ariodb, and ariodb connecting
//! to the database.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Anything we can read and write a connection over, plain or encrypted.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// How ariodb secures its connection to the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// No encryption. Only sensible for a database on the same host.
    Disable,
    /// Encrypt, but accept any certificate (like `accept_invalid_certificate`).
    Require,
    /// Encrypt and check the certificate against trusted roots and the host name.
    Verify,
}

/// Install the crypto provider once per process.
pub fn init() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn client_config(mode: TlsMode, ca_file: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    init();
    let config = match mode {
        TlsMode::Require => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth(),
        _ => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = ca_file {
                for cert in read_certs(path)? {
                    roots.add(cert).map_err(|e| format!("{path}: {e}"))?;
                }
            }
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

pub fn server_acceptor(
    cert_file: &str,
    key_file: &str,
) -> Result<tokio_rustls::TlsAcceptor, String> {
    init();
    let certs = read_certs(cert_file)?;
    let key = read_key(key_file)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS certificate: {e}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

pub async fn connect(
    stream: tokio::net::TcpStream,
    host: &str,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))?;
    tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|e| format!("TLS to {host}: {e}"))
}

/// A connector for tokio-postgres, used by the journal, setup and undo.
pub fn postgres_connector(
    mode: TlsMode,
    ca_file: Option<&str>,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, String> {
    let config = client_config(mode, ca_file)?;
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(
        (*config).clone(),
    ))
}

fn read_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e}"))
}

fn read_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| format!("{path}: {e}"))?
        .ok_or_else(|| format!("{path}: no private key found"))
}

/// Used only for `tls = "require"`: encrypt without checking who answers.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
