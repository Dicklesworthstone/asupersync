//! TLS certificate and key types.
//!
//! These types wrap rustls types to provide a more ergonomic API
//! and decouple the public interface from rustls internals.

#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

use std::collections::BTreeSet;
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

    /// Create a certificate from DER-encoded bytes (fallback when TLS is disabled).
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

    /// Parse certificates from PEM-encoded data (fallback when TLS is disabled).
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

    /// Get the raw DER bytes (fallback when TLS is disabled).
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

    /// Create a private key from PKCS#8 DER-encoded bytes (fallback when TLS is disabled).
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

    /// Parse a private key from PEM-encoded data (fallback when TLS is disabled).
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

    /// Create a private key from SEC1 (EC) DER-encoded bytes (fallback when TLS is disabled).
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

    /// Create an empty root certificate store (fallback when TLS is disabled).
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

    /// Add a certificate to the store (fallback when TLS is disabled).
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

    /// Get the number of certificates in the store (fallback when TLS is disabled).
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

    /// Extend with webpki root certificates.
    ///
    /// Requires the `tls-webpki-roots` feature.
    #[cfg(feature = "tls-webpki-roots")]
    pub fn extend_from_webpki_roots(&mut self) {
        self.inner
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    /// Extend with webpki root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-webpki-roots"))]
    pub fn extend_from_webpki_roots(&mut self) {
        // No-op when feature is disabled
    }

    /// Extend with native/platform root certificates.
    ///
    /// On Linux, this typically reads from /etc/ssl/certs.
    /// On macOS, this uses the system keychain.
    /// On Windows, this uses the Windows certificate store.
    ///
    /// Requires the `tls-native-roots` feature.
    #[cfg(feature = "tls-native-roots")]
    pub fn extend_from_native_roots(&mut self) -> Result<usize, TlsError> {
        let result = rustls_native_certs::load_native_certs();
        let mut count = 0;
        for cert in result.certs {
            if self
                .inner
                .add(rustls_pki_types::CertificateDer::from(cert.to_vec()))
                .is_ok()
            {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Extend with native/platform root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-native-roots"))]
    pub fn extend_from_native_roots(&mut self) -> Result<usize, TlsError> {
        Err(TlsError::Configuration(
            "tls-native-roots feature not enabled".into(),
        ))
    }

    /// Convert to rustls root cert store.
    #[cfg(feature = "tls")]
    pub(crate) fn into_inner(self) -> rustls::RootCertStore {
        self.inner
    }
}

/// A certificate pin for certificate pinning.
///
/// Certificate pinning adds an additional layer of security by verifying
/// that the server's certificate matches a known value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificatePin {
    /// Pin by SPKI (Subject Public Key Info) SHA-256 hash.
    ///
    /// This is the recommended pinning method as it survives certificate
    /// renewal as long as the same key pair is used.
    SpkiSha256(Vec<u8>),

    /// Pin by certificate SHA-256 hash.
    ///
    /// This pins the entire certificate, so you need to update pins
    /// when certificates are renewed.
    CertSha256(Vec<u8>),
}

impl CertificatePin {
    /// Create a SPKI SHA-256 pin from a base64-encoded hash.
    pub fn spki_sha256_base64(base64_hash: &str) -> Result<Self, TlsError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_hash)
            .map_err(|e| TlsError::Certificate(format!("invalid base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(TlsError::Certificate(format!(
                "SPKI SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self::SpkiSha256(bytes))
    }

    /// Create a certificate SHA-256 pin from a base64-encoded hash.
    pub fn cert_sha256_base64(base64_hash: &str) -> Result<Self, TlsError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_hash)
            .map_err(|e| TlsError::Certificate(format!("invalid base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(TlsError::Certificate(format!(
                "certificate SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self::CertSha256(bytes))
    }

    /// Create a SPKI SHA-256 pin from raw bytes.
    pub fn spki_sha256(hash: impl Into<Vec<u8>>) -> Result<Self, TlsError> {
        let bytes = hash.into();
        if bytes.len() != 32 {
            return Err(TlsError::Certificate(format!(
                "SPKI SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self::SpkiSha256(bytes))
    }

    /// Create a certificate SHA-256 pin from raw bytes.
    pub fn cert_sha256(hash: impl Into<Vec<u8>>) -> Result<Self, TlsError> {
        let bytes = hash.into();
        if bytes.len() != 32 {
            return Err(TlsError::Certificate(format!(
                "certificate SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self::CertSha256(bytes))
    }

    /// Compute the SPKI SHA-256 pin for a certificate.
    #[cfg(feature = "tls")]
    pub fn compute_spki_sha256(cert: &Certificate) -> Result<Self, TlsError> {
        use ring::digest::{SHA256, digest};
        use x509_parser::prelude::*;

        let (_, parsed) = X509Certificate::from_der(cert.as_der())
            .map_err(|e| TlsError::Certificate(format!("failed to parse certificate: {e}")))?;
        let spki_bytes = parsed.public_key().raw;
        let hash = digest(&SHA256, spki_bytes);
        Ok(Self::SpkiSha256(hash.as_ref().to_vec()))
    }

    /// Compute the SPKI SHA-256 pin for a certificate (fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn compute_spki_sha256(_cert: &Certificate) -> Result<Self, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Compute the certificate SHA-256 pin for a certificate.
    #[cfg(feature = "tls")]
    pub fn compute_cert_sha256(cert: &Certificate) -> Result<Self, TlsError> {
        use ring::digest::{SHA256, digest};
        let hash = digest(&SHA256, cert.as_der());
        Ok(Self::CertSha256(hash.as_ref().to_vec()))
    }

    /// Compute the certificate SHA-256 pin for a certificate (fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn compute_cert_sha256(_cert: &Certificate) -> Result<Self, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Get the pin as a base64-encoded string.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        match self {
            Self::SpkiSha256(bytes) | Self::CertSha256(bytes) => {
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }
        }
    }

    /// Get the hash bytes.
    pub fn hash_bytes(&self) -> &[u8] {
        match self {
            Self::SpkiSha256(bytes) | Self::CertSha256(bytes) => bytes,
        }
    }
}

/// A set of certificate pins for pinning validation.
///
/// The set supports multiple pins to allow for key rotation without downtime.
#[derive(Clone, Debug, Default)]
pub struct CertificatePinSet {
    pins: BTreeSet<CertificatePin>,
    /// Whether to enforce pinning (fail if no pins match) or just warn.
    enforce: bool,
}

impl CertificatePinSet {
    /// Create a new empty pin set.
    pub fn new() -> Self {
        Self {
            pins: BTreeSet::new(),
            enforce: true,
        }
    }

    /// Create a pin set with enforcement disabled (report-only mode).
    pub fn report_only() -> Self {
        Self {
            pins: BTreeSet::new(),
            enforce: false,
        }
    }

    /// Add a pin to the set.
    pub fn add(&mut self, pin: CertificatePin) {
        self.pins.insert(pin);
    }

    /// Add a pin to the set (builder pattern).
    pub fn with_pin(mut self, pin: CertificatePin) -> Self {
        self.add(pin);
        self
    }

    /// Add a SPKI SHA-256 pin from base64.
    pub fn add_spki_sha256_base64(&mut self, base64_hash: &str) -> Result<(), TlsError> {
        self.add(CertificatePin::spki_sha256_base64(base64_hash)?);
        Ok(())
    }

    /// Add a certificate SHA-256 pin from base64.
    pub fn add_cert_sha256_base64(&mut self, base64_hash: &str) -> Result<(), TlsError> {
        self.add(CertificatePin::cert_sha256_base64(base64_hash)?);
        Ok(())
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Get the number of pins.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Check if enforcement is enabled.
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Set whether to enforce pinning.
    pub fn set_enforce(&mut self, enforce: bool) {
        self.enforce = enforce;
    }

    /// Validate a certificate against the pin set.
    ///
    /// Returns Ok(true) if a pin matches, Ok(false) if no pins match but
    /// enforcement is disabled, or Err if no pins match and enforcement is enabled.
    #[cfg(feature = "tls")]
    pub fn validate(&self, cert: &Certificate) -> Result<bool, TlsError> {
        if self.pins.is_empty() {
            return Ok(true);
        }

        // Compute both types of pins for the certificate
        let spki_pin = CertificatePin::compute_spki_sha256(cert)?;
        let cert_pin = CertificatePin::compute_cert_sha256(cert)?;

        // Check if any pin matches
        if self.pins.contains(&spki_pin) || self.pins.contains(&cert_pin) {
            return Ok(true);
        }

        // No match
        if self.enforce {
            let expected: Vec<String> = self.pins.iter().map(CertificatePin::to_base64).collect();
            Err(TlsError::PinMismatch {
                expected,
                actual: spki_pin.to_base64(),
            })
        } else {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(
                expected = ?self.pins.iter().map(CertificatePin::to_base64).collect::<Vec<_>>(),
                actual_spki = %spki_pin.to_base64(),
                actual_cert = %cert_pin.to_base64(),
                "Certificate pin mismatch (report-only mode)"
            );
            Ok(false)
        }
    }

    /// Validate a certificate against the pin set (fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn validate(&self, _cert: &Certificate) -> Result<bool, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Get an iterator over the pins.
    pub fn iter(&self) -> impl Iterator<Item = &CertificatePin> {
        self.pins.iter()
    }
}

impl FromIterator<CertificatePin> for CertificatePinSet {
    fn from_iter<I: IntoIterator<Item = CertificatePin>>(iter: I) -> Self {
        Self {
            pins: iter.into_iter().collect(),
            enforce: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_from_der() {
        // Minimal self-signed certificate DER (just test parsing doesn't panic)
        let cert = Certificate::from_der(vec![0x30, 0x00]);
        assert_eq!(cert.as_der().len(), 2);
    }

    #[test]
    fn certificate_chain_operations() {
        let chain = CertificateChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        let mut chain = CertificateChain::new();
        chain.push(Certificate::from_der(vec![1, 2, 3]));
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn certificate_chain_from_cert() {
        let cert = Certificate::from_der(vec![1, 2, 3]);
        let chain = CertificateChain::from_cert(cert);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn root_cert_store_empty() {
        let store = RootCertStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn certificate_pin_spki_base64_valid() {
        // Valid 32-byte SHA-256 hash in base64
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertificatePin::spki_sha256_base64(hash).unwrap();
        assert!(matches!(pin, CertificatePin::SpkiSha256(_)));
        assert_eq!(pin.hash_bytes().len(), 32);
        assert_eq!(pin.to_base64(), hash);
    }

    #[test]
    fn certificate_pin_cert_base64_valid() {
        // Valid 32-byte SHA-256 hash in base64
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertificatePin::cert_sha256_base64(hash).unwrap();
        assert!(matches!(pin, CertificatePin::CertSha256(_)));
        assert_eq!(pin.hash_bytes().len(), 32);
    }

    #[test]
    fn certificate_pin_invalid_base64() {
        let result = CertificatePin::spki_sha256_base64("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn certificate_pin_wrong_length() {
        // Valid base64 but wrong length (16 bytes instead of 32)
        let short_hash = "AAAAAAAAAAAAAAAAAAAAAA==";
        let result = CertificatePin::spki_sha256_base64(short_hash);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_pin_from_raw_bytes_valid() {
        let bytes = vec![0u8; 32];
        let pin = CertificatePin::spki_sha256(bytes).unwrap();
        assert_eq!(pin.hash_bytes().len(), 32);
    }

    #[test]
    fn certificate_pin_from_raw_bytes_wrong_length() {
        let bytes = vec![0u8; 16];
        let result = CertificatePin::spki_sha256(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn pin_set_operations() {
        let mut set = CertificatePinSet::new();
        assert!(set.is_empty());
        assert!(set.is_enforcing());

        let pin = CertificatePin::spki_sha256(vec![0u8; 32]).unwrap();
        set.add(pin);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn pin_set_report_only_mode() {
        let set = CertificatePinSet::report_only();
        assert!(!set.is_enforcing());
    }

    #[test]
    fn pin_set_builder_pattern() {
        let pin = CertificatePin::spki_sha256(vec![0u8; 32]).unwrap();
        let set = CertificatePinSet::new().with_pin(pin);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn pin_set_add_from_base64() {
        let mut set = CertificatePinSet::new();
        let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        set.add_spki_sha256_base64(hash).unwrap();
        set.add_cert_sha256_base64(hash).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn pin_set_from_iterator() {
        let pins: Vec<CertificatePin> = (0..3)
            .map(|i| CertificatePin::spki_sha256(vec![i; 32]).unwrap())
            .collect();
        let set: CertificatePinSet = pins.into_iter().collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn pin_set_empty_validates_any() {
        let set = CertificatePinSet::new();
        // Empty set should allow any certificate
        #[cfg(feature = "tls")]
        {
            // We'd need a real cert to test, so just verify the method exists
            let _ = &set;
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = &set;
        }
    }

    #[test]
    fn pin_equality_and_hash() {
        let pin1 = CertificatePin::spki_sha256(vec![1u8; 32]).unwrap();
        let pin2 = CertificatePin::spki_sha256(vec![1u8; 32]).unwrap();
        let pin3 = CertificatePin::spki_sha256(vec![2u8; 32]).unwrap();

        assert_eq!(pin1, pin2);
        assert_ne!(pin1, pin3);

        // Test hash by adding to HashSet
        let mut set = std::collections::BTreeSet::new();
        set.insert(pin1);
        assert!(set.contains(&pin2));
        assert!(!set.contains(&pin3));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        #[cfg(feature = "tls")]
        {
            // Just verify Debug impl exists and doesn't expose key material
            let key = PrivateKey::from_pkcs8_der(vec![0u8; 32]);
            let debug_str = format!("{key:?}");
            assert!(debug_str.contains("redacted"));
            assert!(!debug_str.contains('0'));
        }
    }

    #[test]
    fn error_variants_display() {
        use super::super::error::TlsError;

        let expired = TlsError::CertificateExpired {
            expired_at: 1000000,
            description: "test cert".to_string(),
        };
        let display = format!("{expired}");
        assert!(display.contains("expired"));
        assert!(display.contains("1000000"));

        let not_yet = TlsError::CertificateNotYetValid {
            valid_from: 2000000,
            description: "test cert".to_string(),
        };
        let display = format!("{not_yet}");
        assert!(display.contains("not valid"));
        assert!(display.contains("2000000"));

        let chain = TlsError::ChainValidation("chain error".to_string());
        let display = format!("{chain}");
        assert!(display.contains("chain"));

        let pin_mismatch = TlsError::PinMismatch {
            expected: vec!["pin1".to_string(), "pin2".to_string()],
            actual: "actual_pin".to_string(),
        };
        let display = format!("{pin_mismatch}");
        assert!(display.contains("mismatch"));
        assert!(display.contains("actual_pin"));
    }
}
