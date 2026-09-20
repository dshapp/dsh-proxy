//! TLS termination for the unified client edge.
//!
//! Every phone speaks HTTPS/WSS to the proxy now, so the proxy owns the
//! certificate. Noise still runs inside, from the proxy to the bridge: TLS is
//! what the client sees, Noise is what the Mac proves, and neither the bridge
//! nor the client has to know about the other framing.
//!
//! Only HTTP/1.1 is advertised. A WebSocket upgrade (wx.connectSocket) is an
//! HTTP/1.1 mechanism, and RFC 8441 extended CONNECT is not something a
//! mini-program can use.

use std::io;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// A certificate chain and its private key, ready for rustls.
pub struct TlsIdentity {
    /// Leaf first.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 private key.
    pub key: PrivateKeyDer<'static>,
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

/// Generate a self-signed identity for local development and tests.
///
/// A deployment uses a real certificate via `load_pem`; this exists so the
/// edge is exercisable without one.
pub fn self_signed(names: &[&str]) -> io::Result<TlsIdentity> {
    let ck = rcgen::generate_simple_self_signed(
        names.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
    )
    .map_err(other)?;
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    Ok(TlsIdentity { cert_chain: vec![cert], key })
}

/// Load a PEM certificate chain and private key from disk.
pub fn load_pem(cert_path: &str, key_path: &str) -> io::Result<TlsIdentity> {
    let cert_bytes = std::fs::read(cert_path)?;
    let key_bytes = std::fs::read(key_path)?;
    let cert_chain = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        return Err(other("certificate file holds no certificates"));
    }
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())?
        .ok_or_else(|| other("key file holds no private key"))?;
    Ok(TlsIdentity { cert_chain, key })
}

/// Build the server config the edge runs behind.
pub fn server_config(identity: TlsIdentity) -> io::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(other)?
        .with_no_client_auth()
        .with_single_cert(identity.cert_chain, identity.key)
        .map_err(other)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Build a client config that trusts exactly one certificate.
///
/// Used by tests and the benchmark harness against the self-signed identity; a
/// real client trusts the public CA that signed the proxy's certificate.
pub fn client_config_trusting(cert: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert).expect("a valid certificate");
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the ring provider speaks TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
