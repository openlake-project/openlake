//! Cluster-wide TLS material — mirrors `rustfs/src/server/tls_material.rs`.
//!
//! `TlsMaterial` is a single value holding the three optional TLS handles
//! the server needs:
//!
//!   * `s3_acceptor`   — terminates client S3 connections.
//!   * `rpc_acceptor`  — terminates inter-node RPC connections.
//!   * `rpc_connector` — used by `RemoteBackend` when this node DIALS another
//!                       node, to verify the peer's cert against the cluster CA.
//!
//! The three handles are independent because the operator can choose to
//! enable TLS on the S3 plane, the RPC plane, both, or neither. Each is
//! `Option<...>` and the runtime checks `.is_some()` to decide whether to
//! wrap the listener / connector in a TLS layer.
//!
//! `TlsMaterial::load(&cfg)` is called once in `main` before any runtime
//! threads are spawned. The crypto provider install (`aws-lc-rs`) happens
//! exactly once via `Once`. The whole struct is `Clone`-cheap because
//! `TlsAcceptor` / `TlsConnector` are themselves `Arc<*Config>` wrappers
//! — cloning is one atomic refcount bump, not a config rebuild.
//!
//! Compare with `rustfs/src/server/tls_material.rs`: rustfs has the same
//! shape (a `TlsMaterialSnapshot` loaded once, cheap to share) but adds
//! features we don't have yet:
//!
//!   * `TlsAcceptorHolder` with `RwLock<Arc<TlsAcceptor>>` for hot reload
//!     on cert rotation.
//!   * `ServerSessionMemoryCache` for TLS session resumption.
//!   * Multi-cert SNI via `ResolvesServerCert`.
//!   * Optional mTLS via a `ClientCertVerifier`.
//!
//! Each is well-scoped to add later; this module's surface stays the same.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use compio::tls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::config::Config;

/// HTTP/1.1 only on the wire. Add `b"h2"` ahead of this once an h2
/// frontend lands.
const ALPN_H1: &[u8] = b"http/1.1";

/// One loaded snapshot of all TLS handles this node needs. Cheap to
/// `.clone()` — the underlying `Arc<*Config>` refcount is bumped once
/// per clone, no rustls work re-runs.
#[derive(Clone)]
pub struct TlsMaterial {
    s3_acceptor:   Option<TlsAcceptor>,
    rpc_acceptor:  Option<TlsAcceptor>,
    rpc_connector: Option<TlsConnector>,
}

impl TlsMaterial {
    /// Build all configured TLS handles from `cfg`. Any plane the
    /// operator left out (`s3_tls = None` / `rpc_tls = None`) yields
    /// `None` for that handle. Called once on startup.
    pub fn load(cfg: &Config) -> Result<Self> {
        install_default_crypto_provider();

        let s3_acceptor = cfg.s3_tls.as_ref()
            .map(|t| build_tls_acceptor(&t.cert_path, &t.key_path)
                .context("building S3 TLS acceptor"))
            .transpose()?;

        let rpc_acceptor = cfg.rpc_tls.as_ref()
            .map(|t| build_tls_acceptor(&t.cert_path, &t.key_path)
                .context("building RPC TLS acceptor"))
            .transpose()?;

        let rpc_connector = cfg.rpc_tls.as_ref()
            .and_then(|t| t.client_ca.as_ref())
            .map(|ca| build_tls_connector(ca)
                .context("building RPC TLS connector"))
            .transpose()?;

        Ok(Self { s3_acceptor, rpc_acceptor, rpc_connector })
    }

    /// Cheap clone of the S3 acceptor (or `None` if the operator left
    /// the S3 plane plaintext). One atomic refcount bump.
    pub fn s3_acceptor(&self) -> Option<TlsAcceptor> {
        self.s3_acceptor.clone()
    }

    /// Cheap clone of the inter-node RPC acceptor.
    pub fn rpc_acceptor(&self) -> Option<TlsAcceptor> {
        self.rpc_acceptor.clone()
    }

    /// Cheap clone of the inter-node RPC connector, used by
    /// `RemoteBackend` to dial peers and verify their certs against the
    /// cluster CA.
    pub fn rpc_connector(&self) -> Option<TlsConnector> {
        self.rpc_connector.clone()
    }
}

// ---------------------------------------------------------------------------
// Internal builders. Equivalent to rustfs's same-named helpers in
// `tls_material.rs`; the rustls API calls are identical.
// ---------------------------------------------------------------------------

/// Build a server-side TLS acceptor from a PEM cert chain + PEM private
/// key. `cert_path` should contain the full chain (leaf first, then
/// intermediates).
fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let chain = load_cert_chain(cert_path)
        .with_context(|| format!("loading cert chain from {}", cert_path.display()))?;
    let key = load_private_key(key_path)
        .with_context(|| format!("loading private key from {}", key_path.display()))?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("rustls ServerConfig::with_single_cert")?;
    cfg.alpn_protocols = vec![ALPN_H1.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Build a client-side TLS connector that trusts the supplied CA bundle.
/// Used by `RemoteBackend::dial` when this node calls another node and
/// needs to verify the peer's cert.
fn build_tls_connector(ca_path: &Path) -> Result<TlsConnector> {
    let bundle = load_cert_chain(ca_path)
        .with_context(|| format!("loading CA bundle from {}", ca_path.display()))?;
    if bundle.is_empty() {
        anyhow::bail!("CA bundle {} contained no certificates", ca_path.display());
    }
    let mut roots = RootCertStore::empty();
    for cert in bundle {
        roots.add(cert).context("adding CA cert to root store")?;
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// Read a PEM file containing one or more certificates and parse them
/// into rustls's DER-encoded form. Used for both the leaf-cert chain
/// (server side) and the CA bundle (client side).
///
/// rustfs's equivalent lives in `rustfs/crates/utils/src/certs.rs` —
/// same function body, different module location.
fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let chain = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parsing PEM certificates")?;
    if chain.is_empty() {
        anyhow::bail!("no PEM certificates found in {}", path.display());
    }
    Ok(chain)
}

/// Read a PEM file containing exactly one private key.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing PEM private key")?
        .ok_or_else(|| anyhow::anyhow!("no PEM private key in {}", path.display()))
}

/// rustls 0.23 demands exactly one default `CryptoProvider` per
/// process, and `install_default()` returns `Err` on the second call.
/// The `Once` wrapper makes this safe to call from any code path.
///
/// rustfs's equivalent uses an `is_none()` check before calling
/// `install_default()` (see `transition_api.rs:208-217`); functionally
/// the same.
fn install_default_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Idempotent on success; `Err` here just means another caller
        // beat us, which we treat as success.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
