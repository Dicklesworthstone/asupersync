//! TLS certificate and key types.
//!
//! These types wrap rustls types to provide a more ergonomic API
//! and decouple the public interface from rustls internals.

#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use super::error::TlsError;

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

    /// Parse certificates from PEM-encoded data.
    ///
    /// Returns all certificates found in the PEM data.
    #[cfg(feature = "tls")]
    pub fn from_pem(pem: &[u8]) -> Result<Vec<Self>, TlsError> {
        let mut reader = BufReader::new(pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(e.to_string()))?;

        if certs.is_empty() {
            return Err(TlsError::Certificate("no certificates found in PEM".into()));
        }

        Ok(certs.into_iter().map(|c| Self { inner: c }).collect())
    }

    /// Parse certificates from PEM-encoded data (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn from_pem(_pem: &[u8]) -> Result<Vec<Self>, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Load certificates from a PEM file.
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Vec<Self>, TlsError> {
        let pem = std::fs::read(path.as_ref())
            .map_err(|e| TlsError::Certificate(format!("reading file: {e}")))?;
        Self::from_pem(&pem)
    }

    /// Get the raw DER bytes.
    #[cfg(feature = "tls")]
    pub fn as_der(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Get the raw DER bytes (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn as_der(&self) -> &[u8] {
        &self._data
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

    /// Load certificate chain from a PEM file.
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self, TlsError> {
        let certs = Certificate::from_pem_file(path)?;
        Ok(Self::from(certs))
    }

    /// Parse certificate chain from PEM-encoded data.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let certs = Certificate::from_pem(pem)?;
        Ok(Self::from(certs))
    }

    /// Convert to rustls certificate chain.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> Vec<CertificateDer<'static>> {
        self.certs
            .into_iter()
            .map(Certificate::into_inner)
            .collect()
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

    /// Parse a private key from PEM-encoded data.
    ///
    /// Supports PKCS#8, PKCS#1 (RSA), and SEC1 (EC) formats.
    #[cfg(feature = "tls")]
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let mut reader = BufReader::new(pem);

        // Try PKCS#8 first
        let pkcs8_keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(e.to_string()))?;

        if let Some(key) = pkcs8_keys.into_iter().next() {
            return Ok(Self {
                inner: Arc::new(PrivateKeyDer::Pkcs8(key)),
            });
        }

        // Try RSA (PKCS#1)
        let mut reader = BufReader::new(pem);
        let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(e.to_string()))?;

        if let Some(key) = rsa_keys.into_iter().next() {
            return Ok(Self {
                inner: Arc::new(PrivateKeyDer::Pkcs1(key)),
            });
        }

        // Try EC (SEC1)
        let mut reader = BufReader::new(pem);
        let ec_keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(e.to_string()))?;

        if let Some(key) = ec_keys.into_iter().next() {
            return Ok(Self {
                inner: Arc::new(PrivateKeyDer::Sec1(key)),
            });
        }

        Err(TlsError::Certificate("no private key found in PEM".into()))
    }

    /// Parse a private key from PEM-encoded data (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn from_pem(_pem: &[u8]) -> Result<Self, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Load a private key from a PEM file.
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self, TlsError> {
        let pem = std::fs::read(path.as_ref())
            .map_err(|e| TlsError::Certificate(format!("reading file: {e}")))?;
        Self::from_pem(&pem)
    }

    /// Create a private key from SEC1 (EC) DER-encoded bytes.
    #[cfg(feature = "tls")]
    pub fn from_sec1_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.into()))),
        }
    }

    /// Create a private key from SEC1 (EC) DER-encoded bytes (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn from_sec1_der(der: impl Into<Vec<u8>>) -> Self {
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

    /// Add certificates from a PEM file.
    ///
    /// Returns the number of certificates successfully added.
    pub fn add_pem_file(&mut self, path: impl AsRef<Path>) -> Result<usize, TlsError> {
        let certs = Certificate::from_pem_file(path)?;
        let mut count = 0;
        for cert in &certs {
            if self.add(cert).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Convert to rustls root cert store.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> rustls::RootCertStore {
        self.inner
    }
}
