//! TLS server acceptor.
//!
//! This module provides `TlsAcceptor` and `TlsAcceptorBuilder` for accepting
//! TLS connections on the server side.

use super::error::TlsError;
use super::types::{CertificateChain, PrivateKey, RootCertStore};

#[cfg(feature = "tls")]
use rustls::ServerConfig;

use std::path::Path;
use std::sync::Arc;

/// Server-side TLS acceptor.
///
/// This is typically configured once and reused to accept many connections.
/// Cloning is cheap (Arc-based).
///
/// # Example
///
/// ```ignore
/// let acceptor = TlsAcceptor::builder(cert_chain, private_key)
///     .alpn_http()
///     .build()?;
///
/// let tls_stream = acceptor.accept(tcp_stream).await?;
/// ```
#[derive(Clone)]
pub struct TlsAcceptor {
    #[cfg(feature = "tls")]
    config: Arc<ServerConfig>,
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<()>,
}

impl TlsAcceptor {
    /// Create an acceptor from a raw rustls `ServerConfig`.
    #[cfg(feature = "tls")]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Create a builder for constructing a `TlsAcceptor`.
    ///
    /// Requires the server's certificate chain and private key.
    pub fn builder(chain: CertificateChain, key: PrivateKey) -> TlsAcceptorBuilder {
        TlsAcceptorBuilder::new(chain, key)
    }

    /// Create a builder from PEM files.
    ///
    /// # Arguments
    /// * `cert_path` - Path to the certificate chain PEM file
    /// * `key_path` - Path to the private key PEM file
    pub fn builder_from_pem(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<TlsAcceptorBuilder, TlsError> {
        TlsAcceptorBuilder::from_pem_files(cert_path, key_path)
    }

    /// Get the inner configuration (for advanced use).
    #[cfg(feature = "tls")]
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.config
    }
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// Client authentication configuration.
#[derive(Debug, Clone, Default)]
pub enum ClientAuth {
    /// No client authentication required.
    #[default]
    None,
    /// Client certificate is optional.
    Optional(RootCertStore),
    /// Client certificate is required.
    Required(RootCertStore),
}

/// Builder for `TlsAcceptor`.
///
/// # Example
///
/// ```ignore
/// let acceptor = TlsAcceptorBuilder::new(cert_chain, private_key)
///     .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
///     .build()?;
/// ```
#[derive(Debug)]
pub struct TlsAcceptorBuilder {
    cert_chain: CertificateChain,
    key: PrivateKey,
    client_auth: ClientAuth,
    alpn_protocols: Vec<Vec<u8>>,
    session_memory_limit: usize,
    max_fragment_size: Option<usize>,
}

impl TlsAcceptorBuilder {
    /// Create a new builder with the server's certificate chain and private key.
    pub fn new(chain: CertificateChain, key: PrivateKey) -> Self {
        Self {
            cert_chain: chain,
            key,
            client_auth: ClientAuth::None,
            alpn_protocols: Vec::new(),
            session_memory_limit: 256 * 1024 * 1024, // 256 MB default
            max_fragment_size: None,
        }
    }

    /// Create a builder by loading certificate chain and key from PEM files.
    pub fn from_pem_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let chain = CertificateChain::from_pem_file(cert_path)?;
        let key = PrivateKey::from_pem_file(key_path)?;
        Ok(Self::new(chain, key))
    }

    /// Set client authentication mode.
    pub fn client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = auth;
        self
    }

    /// Require client certificates for mutual TLS.
    pub fn require_client_auth(self, root_certs: RootCertStore) -> Self {
        self.client_auth(ClientAuth::Required(root_certs))
    }

    /// Allow optional client certificates.
    pub fn optional_client_auth(self, root_certs: RootCertStore) -> Self {
        self.client_auth(ClientAuth::Optional(root_certs))
    }

    /// Set ALPN protocols (e.g., `["h2", "http/1.1"]`).
    ///
    /// Protocols are advertised to clients in the order provided.
    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Convenience method for HTTP/2 ALPN only.
    pub fn alpn_h2(self) -> Self {
        self.alpn_protocols(vec![b"h2".to_vec()])
    }

    /// Convenience method for HTTP/1.1 and HTTP/2 ALPN.
    ///
    /// HTTP/2 is preferred over HTTP/1.1.
    pub fn alpn_http(self) -> Self {
        self.alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    }

    /// Set session memory limit (for session resumption cache).
    ///
    /// Default is 256 MB.
    pub fn session_memory_limit(mut self, bytes: usize) -> Self {
        self.session_memory_limit = bytes;
        self
    }

    /// Set maximum TLS fragment size.
    ///
    /// This limits the size of TLS records. Smaller values may help with
    /// constrained networks but reduce throughput.
    pub fn max_fragment_size(mut self, size: usize) -> Self {
        self.max_fragment_size = Some(size);
        self
    }

    /// Build the `TlsAcceptor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g., invalid certificate/key pair).
    #[cfg(feature = "tls")]
    pub fn build(self) -> Result<TlsAcceptor, TlsError> {
        use rustls::crypto::ring::default_provider;
        use rustls::server::WebPkiClientVerifier;

        // Create the config builder with the crypto provider
        let builder = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Configuration(e.to_string()))?;

        // Configure client auth
        let builder = match self.client_auth {
            ClientAuth::None => builder.with_no_client_auth(),
            ClientAuth::Optional(roots) => {
                let verifier = WebPkiClientVerifier::builder(Arc::new(roots.into_inner()))
                    .allow_unauthenticated()
                    .build()
                    .map_err(|e| TlsError::Configuration(e.to_string()))?;
                builder.with_client_cert_verifier(verifier)
            }
            ClientAuth::Required(roots) => {
                let verifier = WebPkiClientVerifier::builder(Arc::new(roots.into_inner()))
                    .build()
                    .map_err(|e| TlsError::Configuration(e.to_string()))?;
                builder.with_client_cert_verifier(verifier)
            }
        };

        let mut config = builder
            .with_single_cert(self.cert_chain.into_inner(), self.key.clone_inner())
            .map_err(|e| TlsError::Configuration(e.to_string()))?;

        // Set ALPN if specified
        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols;
        }

        // Set max fragment size if specified
        if let Some(size) = self.max_fragment_size {
            config.max_fragment_size = Some(size);
        }

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            alpn = ?config.alpn_protocols,
            "TlsAcceptor built"
        );

        Ok(TlsAcceptor::new(config))
    }

    /// Build the `TlsAcceptor` (stub when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn build(self) -> Result<TlsAcceptor, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::Certificate;

    // Self-signed test certificate and key (for testing only)
    // Generated with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
    const TEST_CERT_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDQ0rXzDgNz5bfBjKk9m1EZ
wHr2F0yxCmJ5zCshCEcUJ2VzYYF0QyvnAXIZqmqz0A0WLkLhXRYhXMxnGqQA0pRD
AgMBAAGjUzBRMB0GA1UdDgQWBBQG3qXhXkKT8LoHlpX/B7cKCBcICTAfBgNVHSME
GDAWgBQG3qXhXkKT8LoHlpX/B7cKCBcICTAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAoLqsIgNPcy8PT0irKVrNd5IzLPbMqwCrNT0qHr1b8G8LJmpz
jB7V7NZxR9TqIJGlBF8M0C0aIuTzCmBE0BHnWg==
-----END CERTIFICATE-----"#;

    const TEST_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA0NK18w4Dc+W3wYyp
PZtRGcB69hdMsQpiecwrIQhHFCdlc2GBdEMr5wFyGapqs9ANFi5C4V0WIVzMZxqk
ANKUQwIDAQABAkA6tBOA3a8qM1V5VTnQqOFOeNNL3P2Ft06K+lPFLwBPFqPWFwIo
u4k4fL1MBv0BfFLNvx00dD9WLPH8MU7B1wfBAiEA7r0EhLz0POHqc0k7H8aXKF0E
W6nz9dG6x2TbPP+6JosCIQDgF8xfXPvJHXZJ8LvDkbV/2kF1mDRFJHj1e5qvRBLR
2QIhAKyIGFJGUlA9n3VUHU8Y8R5TDM7xNbL5Rp+d2Qm3oHUDAiBlbX3A7rJbY0XS
F9XrLJlPAJFqDXY/AQjg8DUQMf+YQQIhAMqXzXCRJ0l1Dn0h+L1qHv9hNPDhvQJV
VkqMWMD7RJGG
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_builder_new() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key);
        assert!(builder.alpn_protocols.is_empty());
    }

    #[test]
    fn test_builder_alpn_http() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_http();
        assert_eq!(
            builder.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn test_builder_alpn_h2() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_h2();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_client_auth_default() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key);
        assert!(matches!(builder.client_auth, ClientAuth::None));
    }

    #[test]
    fn test_certificate_from_pem() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_private_key_from_pem() {
        let _key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_acceptor() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_http()
            .build()
            .unwrap();

        assert_eq!(
            acceptor.config().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_acceptor_clone_is_cheap() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _clone = acceptor.clone();
        }
        let elapsed = start.elapsed();

        // Should be very fast (Arc clone)
        assert!(elapsed.as_millis() < 100);
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn test_build_without_tls_feature() {
        let chain = CertificateChain::new();
        let key = PrivateKey::from_pkcs8_der(vec![]);
        let result = TlsAcceptorBuilder::new(chain, key).build();
        assert!(result.is_err());
    }
}
