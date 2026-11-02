//! mTLS server configuration: TLS 1.3 only, and every client must present a
//! certificate signed by the configured client CA. There is no plaintext mode.
//! This file is the only code that touches the rustls API; compile-check it first
//! and pin the rustls version you test against.

use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::{fs::File, io::BufReader, sync::Arc};

fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(f)).collect::<Result<Vec<_>, _>>().map_err(|e| format!("{path}: {e}"))
}

pub fn server_config(cert: &str, key: &str, client_ca: &str) -> Result<Arc<ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    for c in certs(client_ca)? {
        roots.add(c).map_err(|e| format!("client_ca: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|e| format!("client verifier: {e}"))?;
    let key_file = File::open(key).map_err(|e| format!("{key}: {e}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("{key}: {e}"))?
        .ok_or_else(|| format!("{key}: no private key found"))?;
    let cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(cert)?, key)
        .map_err(|e| format!("tls: {e}"))?;
    Ok(Arc::new(cfg))
}
