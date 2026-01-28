//! TLS certificate and key types.
//!
//! These types wrap rustls types to provide a more ergonomic API
//! and decouple the public interface from rustls internals.

#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use std::sync::Arc;

/// A DER-encoded X.509 certificate.
#[derive(Clone, Debug)]
pub struct Certificate {
    #[cfg(feature = "tls")]
    inner: CertificateDer<'static>,
    #[cfg(not(feature = "tls"))]
    _data: Vec<u8>,
}

impl Certificate {
    /// Create a certificate from DER-encoded bytes.
    #[cfg(feature = "tls")]
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: CertificateDer::from(der.into()),
        }
    }

    /// Create a certificate from DER-encoded bytes (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self { _data: der.into() }
    }

    /// Get the inner rustls certificate.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> CertificateDer<'static> {
        self.inner
    }
}

/// A chain of X.509 certificates (leaf first, then intermediates).
#[derive(Clone, Debug, Default)]
pub struct CertificateChain {
    certs: Vec<Certificate>,
}

impl CertificateChain {
    /// Create an empty certificate chain.
    pub fn new() -> Self {
        Self { certs: Vec::new() }
    }

    /// Create a certificate chain from a single certificate.
    pub fn from_cert(cert: Certificate) -> Self {
        Self { certs: vec![cert] }
    }

    /// Add a certificate to the chain.
    pub fn push(&mut self, cert: Certificate) {
        self.certs.push(cert);
    }

    /// Get the number of certificates in the chain.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Convert to rustls certificate chain.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> Vec<CertificateDer<'static>> {
        self.certs.into_iter().map(|c| c.into_inner()).collect()
    }
}

impl From<Vec<Certificate>> for CertificateChain {
    fn from(certs: Vec<Certificate>) -> Self {
        Self { certs }
    }
}

impl IntoIterator for CertificateChain {
    type Item = Certificate;
    type IntoIter = std::vec::IntoIter<Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certs.into_iter()
    }
}

/// A private key for TLS authentication.
#[derive(Clone)]
pub struct PrivateKey {
    #[cfg(feature = "tls")]
    inner: Arc<PrivateKeyDer<'static>>,
    #[cfg(not(feature = "tls"))]
    _data: Vec<u8>,
}

impl PrivateKey {
    /// Create a private key from PKCS#8 DER-encoded bytes.
    #[cfg(feature = "tls")]
    pub fn from_pkcs8_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.into()))),
        }
    }

    /// Create a private key from PKCS#8 DER-encoded bytes (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn from_pkcs8_der(der: impl Into<Vec<u8>>) -> Self {
        Self { _data: der.into() }
    }

    /// Get the inner rustls private key.
    #[cfg(feature = "tls")]
    pub(crate) fn clone_inner(&self) -> PrivateKeyDer<'static> {
        (*self.inner).clone_key()
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("type", &"[redacted]")
            .finish()
    }
}

/// A store of trusted root certificates.
#[derive(Clone, Debug)]
pub struct RootCertStore {
    #[cfg(feature = "tls")]
    inner: rustls::RootCertStore,
    #[cfg(not(feature = "tls"))]
    certs: Vec<Certificate>,
}

impl Default for RootCertStore {
    fn default() -> Self {
        Self::empty()
    }
}

impl RootCertStore {
    /// Create an empty root certificate store.
    #[cfg(feature = "tls")]
    pub fn empty() -> Self {
        Self {
            inner: rustls::RootCertStore::empty(),
        }
    }

    /// Create an empty root certificate store (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn empty() -> Self {
        Self { certs: Vec::new() }
    }

    /// Add a certificate to the store.
    #[cfg(feature = "tls")]
    pub fn add(&mut self, cert: &Certificate) -> Result<(), crate::tls::TlsError> {
        self.inner
            .add(cert.clone().into_inner())
            .map_err(|e| crate::tls::TlsError::Certificate(e.to_string()))
    }

    /// Add a certificate to the store (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn add(&mut self, cert: &Certificate) -> Result<(), crate::tls::TlsError> {
        self.certs.push(cert.clone());
        Ok(())
    }

    /// Get the number of certificates in the store.
    #[cfg(feature = "tls")]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get the number of certificates in the store (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert to rustls root cert store.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> rustls::RootCertStore {
        self.inner
    }
}
