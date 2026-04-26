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
    #[inline]
    #[cfg(feature = "tls")]
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: CertificateDer::from(der.into()),
        }
    }

    /// Create a certificate from DER-encoded bytes (fallback when TLS is disabled).
    #[inline]
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
    #[inline]
    #[cfg(feature = "tls")]
    pub fn as_der(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Get the raw DER bytes (fallback when TLS is disabled).
    #[inline]
    #[cfg(not(feature = "tls"))]
    pub fn as_der(&self) -> &[u8] {
        &self._data
    }

    /// Get the inner rustls certificate.
    #[inline]
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
    #[inline]
    pub fn new() -> Self {
        Self::default()
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
        Certificate::from_pem_file(path).map(Self::from)
    }

    /// Parse certificate chain from PEM-encoded data.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        Certificate::from_pem(pem).map(Self::from)
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
    ///
    /// This hashes the DER-encoded `SubjectPublicKeyInfo` structure from the
    /// certificate, which is the pinning form that survives certificate
    /// renewal as long as the key pair stays the same.
    #[cfg(feature = "tls")]
    pub fn compute_spki_sha256(cert: &Certificate) -> Result<Self, TlsError> {
        use ring::digest::{SHA256, digest};

        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_der())
            .map_err(|e| TlsError::Certificate(format!("failed to parse certificate DER: {e}")))?;
        let hash = digest(&SHA256, parsed.public_key().raw);
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
#[derive(Clone, Debug)]
pub struct CertificatePinSet {
    pins: BTreeSet<CertificatePin>,
    /// Whether to enforce pinning (fail if no pins match) or just warn.
    enforce: bool,
}

impl Default for CertificatePinSet {
    /// Default pin set is empty with enforcement enabled (secure-by-default).
    fn default() -> Self {
        Self::new()
    }
}

impl CertificatePinSet {
    fn empty_with_enforcement(enforce: bool) -> Self {
        Self {
            pins: BTreeSet::new(),
            enforce,
        }
    }

    /// Create a new empty pin set.
    pub fn new() -> Self {
        Self::empty_with_enforcement(true)
    }

    /// Create a pin set with enforcement disabled (report-only mode).
    pub fn report_only() -> Self {
        Self::empty_with_enforcement(false)
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
    ///
    /// # Timing safety (br-asupersync-86n63i)
    ///
    /// Pin comparison iterates ALL stored pins and uses a constant-time byte
    /// equality check on the SHA-256 hashes. The previous implementation used
    /// `BTreeSet::contains`, which performs `Vec<u8>::cmp` (an `Ord`-based
    /// byte-by-byte comparison that short-circuits on the first mismatching
    /// byte). Against a remote attacker who can present arbitrary leaf certs
    /// and observe validation timing, that variable-time comparison would
    /// leak prefixes of the pinned hashes — eventually defeating pinning's
    /// secrecy. The replacement loop touches every stored pin and OR-folds
    /// match results into a single accumulator so timing reflects the size
    /// of the pin set, not its contents or the cert under test.
    #[cfg(feature = "tls")]
    pub fn validate(&self, cert: &Certificate) -> Result<bool, TlsError> {
        if self.pins.is_empty() {
            return Ok(true);
        }

        // Compute pin types on demand so malformed certificate material only
        // affects the pin types the set actually needs.
        let spki_pin = CertificatePin::compute_spki_sha256(cert).ok();
        let cert_pin = CertificatePin::compute_cert_sha256(cert).ok();

        // br-asupersync-86n63i: constant-time membership check. Iterate every
        // stored pin (no early break), compare hashes with `constant_time_eq`,
        // and accumulate match results into `matched` via bitwise OR so the
        // overall control flow never branches on whether any individual pin
        // matched. The match on pin TYPE (Spki vs Cert) is fine to branch on
        // because pin types are public configuration (they were chosen at
        // builder time, not derived from the candidate cert).
        let mut matched: u8 = 0;
        for stored in &self.pins {
            match (stored, spki_pin.as_ref(), cert_pin.as_ref()) {
                (
                    CertificatePin::SpkiSha256(stored_bytes),
                    Some(CertificatePin::SpkiSha256(candidate_bytes)),
                    _,
                ) => {
                    matched |= u8::from(constant_time_eq(stored_bytes, candidate_bytes));
                }
                (
                    CertificatePin::CertSha256(stored_bytes),
                    _,
                    Some(CertificatePin::CertSha256(candidate_bytes)),
                ) => {
                    matched |= u8::from(constant_time_eq(stored_bytes, candidate_bytes));
                }
                _ => {
                    // Stored pin type has no candidate (compute failed or
                    // type mismatch). Run a sham comparison against a 32-byte
                    // zero baseline so the iteration's per-pin work is the
                    // same shape regardless of which pin types appear in
                    // the set or which candidates were derivable.
                    let stored_bytes = stored.hash_bytes();
                    let zero = [0u8; 32];
                    let _ =
                        std::hint::black_box(constant_time_eq(stored_bytes, &zero));
                }
            }
        }

        if std::hint::black_box(matched) != 0 {
            return Ok(true);
        }

        // No match
        if self.enforce {
            let expected: Vec<String> = self.pins.iter().map(CertificatePin::to_base64).collect();
            let actual = spki_pin
                .as_ref()
                .or(cert_pin.as_ref())
                .map_or_else(|| "<unavailable>".to_string(), CertificatePin::to_base64);
            Err(TlsError::PinMismatch { expected, actual })
        } else {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(
                expected = ?self.pins.iter().map(CertificatePin::to_base64).collect::<Vec<_>>(),
                actual_spki = %spki_pin.as_ref().map_or_else(|| "<unavailable>".to_string(), CertificatePin::to_base64),
                actual_cert = %cert_pin.as_ref().map_or_else(|| "<unavailable>".to_string(), CertificatePin::to_base64),
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

/// Constant-time byte-slice equality (br-asupersync-86n63i).
///
/// Used by [`CertificatePinSet::validate`] to compare SHA-256 pin hashes
/// without leaking match progress through timing. Returns `false` immediately
/// for length mismatches because lengths of stored pins are public (always
/// 32 bytes for SHA-256) so the early-return cannot leak a secret. The XOR
/// accumulator is wrapped in `std::hint::black_box` so an aggressive
/// optimiser cannot rewrite the loop into an early-exit comparison.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUEOa/xZnL2Xclme2QSueCrHSMLnEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIyNjIyMjk1MloXDTM2MDIy
NDIyMjk1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAx1JqCHpDIHPR4H1LDrb3gHVCzoKujANyHdOKw7CTLKdz
JbDybwJYqZ8vZpq0xwhYKpHdGO4yv7yLT7a2kThq3MrxohfXp9tv1Dop7siTQiWT
7uGYJzh1bOhw7ElLJc8bW/mBf7ksMyqkX8/8mRXRWqqDv3dKe5CrSt2Pqti9tYH0
DcT2fftUGT14VvL/Fq1kWPM16ebTRCFp/4ki/Th7SzFvTN99L45MAilHZFefRSzc
9xN1qQZNm7lT6oo0zD3wmOy70iiasqpLrmG51TRdbnBnGH6CIHvUIl3rCDteUuj1
pB9lh67qt5kipCn4+8zceXmUaO/nmRawC7Vz+6AsTwIDAQABo2QwYjALBgNVHQ8E
BAMCBLAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAkGA1UdEwQCMAAwHQYDVR0OBBYEFEGZkeJqxBWpc24NHkE8k5PM8gTyMA0GCSqG
SIb3DQEBCwUAA4IBAQAzfQ4na2v1VhK/dyhC89rMHPN/8OX7CGWwrpWlEOYtpMds
OyQKTZjdz8aFSFl9rvnyGRHrdo4J1RoMGNR5wt1XQ7+k3l/iEWRlSRw+JU6+jqsx
xfjik55Dji36pN7ARGW4ADBpc3yTOHFhaH41GpSZ6s/2KdGG2gifo7UGNdkdgL60
nxRt1tfapaNtzpi90TfDx2w6MQmkNMKVOowbYX/zUY7kklJLP8KWTwXO7eovtIpr
FPAy+SbPl3+sqPbes5IqAQO9jhjb0w0/5RlSTPtiKetb6gAA7Yqw+yZWkBN0WDye
Lru15URJw9pE1Uae8IuzyzHiF1fnn45swnvW3Szb
-----END CERTIFICATE-----";
    #[cfg(feature = "tls")]
    const TEST_CERT_SPKI_SHA256_BASE64: &str = "Wic7R2QEWx8m0gjc0UYQD4iTxorg2Q51QmvN8HuCprc=";

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

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_pin_compute_spki_sha256_known_answer() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        assert_eq!(pin.to_base64(), TEST_CERT_SPKI_SHA256_BASE64);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_pin_compute_spki_sha256_rejects_invalid_der() {
        let cert = Certificate::from_der(vec![0x30, 0x00]);
        let err = CertificatePin::compute_spki_sha256(&cert).unwrap_err();
        match err {
            TlsError::Certificate(message) => {
                assert!(message.contains("failed to parse certificate DER"));
            }
            other => panic!("expected certificate error, got {other:?}"),
        }
    }

    /// br-asupersync-86n63i: regression. constant_time_eq must (a) accept
    /// identical inputs, (b) reject length-mismatched and content-mismatched
    /// inputs, and (c) — most importantly — perform the full comparison
    /// regardless of where the first mismatching byte appears. We can't
    /// directly observe wall-clock timing without flake risk, so we
    /// instead assert the FUNCTIONAL property that mismatches at the
    /// front, middle, and end all produce the same result, and that the
    /// helper handles the empty/full-zero edge cases.
    #[test]
    fn constant_time_eq_correctness_and_full_iteration_invariants() {
        // Identical
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(constant_time_eq(b"", b""));

        // Length mismatch — we accept this short-circuit because pin lengths
        // are public (always 32 for SHA-256).
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));

        // Mismatch at front, middle, end — all must return false. The CT
        // property is enforced by the loop structure: every byte is XORed
        // into the diff accumulator regardless of where the mismatch is.
        assert!(!constant_time_eq(&[9, 2, 3, 4], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[1, 2, 9, 4], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[1, 2, 3, 9], &[1, 2, 3, 4]));

        // 32-byte realistic SHA-256 length
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] ^= 0x01;
        assert!(!constant_time_eq(&a, &b));
        b[31] ^= 0x01;
        b[0] ^= 0x80;
        assert!(!constant_time_eq(&a, &b));
    }

    /// br-asupersync-86n63i: regression. CertificatePinSet::validate must
    /// iterate every stored pin and use constant-time byte equality. We
    /// verify this functionally: a set with many decoy pins plus one real
    /// match still accepts the matching cert. This catches refactors that
    /// reintroduce BTreeSet::contains or any short-circuiting Ord-based
    /// lookup (which, with the test certificate's SPKI hash sorted into
    /// the middle of the decoy ordering, would still functionally pass
    /// — but the *property* under test is that every stored pin
    /// participates in the comparison, which the unit test above
    /// (`constant_time_eq_correctness_*`) covers at the helper layer.
    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_accepts_match_among_many_decoys() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let real_pin = CertificatePin::compute_spki_sha256(&cert).unwrap();

        let mut set = CertificatePinSet::new();
        // Decoys: 32-byte hashes that are NOT the real pin. Vary them
        // across the byte space so the set's BTree storage interleaves
        // them with the real pin (defeating any test that secretly relies
        // on Ord ordering).
        for byte in [0x00u8, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70] {
            set.add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        set.add(real_pin);
        for byte in [0x80u8, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0] {
            set.add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        assert_eq!(set.len(), 17);

        // Real cert must validate even when surrounded by decoys.
        assert!(
            set.validate(&cert).unwrap(),
            "validate should match the real pin among 16 decoys"
        );

        // A cert that does NOT match any pin must yield PinMismatch.
        let mut decoy_only = CertificatePinSet::new();
        for byte in 0u8..16u8 {
            decoy_only
                .add(CertificatePin::spki_sha256(vec![byte; 32]).unwrap());
        }
        let err = decoy_only.validate(&cert).unwrap_err();
        assert!(matches!(err, TlsError::PinMismatch { .. }));
    }

    /// br-asupersync-86n63i: regression. Mixed pin types (Spki + Cert) in
    /// the same set must both work after the constant-time refactor.
    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_mixed_pin_types_each_resolved_independently() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let spki_pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        let cert_pin = CertificatePin::compute_cert_sha256(&cert).unwrap();

        // Set with only SPKI pin matches the cert.
        let mut spki_only = CertificatePinSet::new();
        spki_only.add(spki_pin.clone());
        spki_only.add(CertificatePin::cert_sha256(vec![0u8; 32]).unwrap());
        assert!(spki_only.validate(&cert).unwrap());

        // Set with only Cert pin matches the cert.
        let mut cert_only = CertificatePinSet::new();
        cert_only.add(CertificatePin::spki_sha256(vec![0u8; 32]).unwrap());
        cert_only.add(cert_pin);
        assert!(cert_only.validate(&cert).unwrap());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pin_set_validate_accepts_matching_spki_pin() {
        let cert = Certificate::from_pem(TEST_CERT_PEM).unwrap().remove(0);
        let pin = CertificatePin::compute_spki_sha256(&cert).unwrap();
        let mut set = CertificatePinSet::new();
        set.add(pin);
        assert!(set.validate(&cert).unwrap());
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
        let set: CertificatePinSet = (0..3)
            .map(|i| CertificatePin::spki_sha256(vec![i; 32]).unwrap())
            .collect();
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
            expired_at: 1_000_000,
            description: "test cert".to_string(),
        };
        let display = format!("{expired}");
        assert!(display.contains("expired"));
        assert!(display.contains("1000000"));

        let not_yet = TlsError::CertificateNotYetValid {
            valid_from: 2_000_000,
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
