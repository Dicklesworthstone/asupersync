//! TLS server acceptor.
//!
//! This module provides `TlsAcceptor` and `TlsAcceptorBuilder` for accepting
//! TLS connections on the server side.

use super::error::TlsError;
use super::stream::TlsStream;
use super::types::{CertificateChain, PrivateKey, RootCertStore};
use crate::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rustls::ServerConfig;
#[cfg(feature = "tls")]
use rustls::ServerConnection;

#[cfg(feature = "tls")]
use std::future::poll_fn;
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
    handshake_timeout: Option<std::time::Duration>,
    alpn_required: bool,
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<()>,
}

impl TlsAcceptor {
    /// Create an acceptor from a raw rustls `ServerConfig`.
    #[cfg(feature = "tls")]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            handshake_timeout: None,
            alpn_required: false,
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

    /// Get the handshake timeout, if configured.
    #[must_use]
    pub fn handshake_timeout(&self) -> Option<std::time::Duration> {
        self.handshake_timeout
    }

    /// Accept an incoming TLS connection over the provided I/O stream.
    ///
    /// # Cancel-Safety
    /// Handshake is NOT cancel-safe. If cancelled mid-handshake, drop the stream.
    #[cfg(feature = "tls")]
    pub async fn accept<IO>(&self, io: IO) -> Result<TlsStream<IO>, TlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| TlsError::Configuration(e.to_string()))?;
        let mut stream = TlsStream::new_server(io, conn);
        if let Some(timeout) = self.handshake_timeout {
            match crate::time::timeout(
                super::wall_clock_now(),
                timeout,
                poll_fn(|cx| stream.poll_handshake(cx)),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => return Err(TlsError::Timeout(timeout)),
            }
        } else {
            poll_fn(|cx| stream.poll_handshake(cx)).await?;
        }
        if self.alpn_required {
            let expected = self.config.alpn_protocols.clone();
            let negotiated = stream.alpn_protocol().map(<[u8]>::to_vec);
            let ok = match negotiated.as_deref() {
                Some(p) => expected.iter().any(|e| e.as_slice() == p),
                None => false,
            };
            if !ok {
                return Err(TlsError::AlpnNegotiationFailed {
                    expected,
                    negotiated,
                });
            }
        }

        Ok(stream)
    }

    /// Accept a connection (disabled-mode fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub async fn accept<IO>(&self, _io: IO) -> Result<TlsStream<IO>, TlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Err(TlsError::Configuration("tls feature not enabled".into()))
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
    alpn_required: bool,
    max_fragment_size: Option<usize>,
    handshake_timeout: Option<std::time::Duration>,
}

impl TlsAcceptorBuilder {
    /// Create a new builder with the server's certificate chain and private key.
    pub fn new(chain: CertificateChain, key: PrivateKey) -> Self {
        Self {
            cert_chain: chain,
            key,
            client_auth: ClientAuth::None,
            alpn_protocols: Vec::new(),
            alpn_required: false,
            max_fragment_size: None,
            handshake_timeout: None,
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

    /// Require that the peer negotiates an ALPN protocol.
    ///
    /// If the peer does not negotiate any protocol (or negotiates something
    /// unexpected), `accept()` returns `TlsError::AlpnNegotiationFailed`.
    pub fn require_alpn(mut self) -> Self {
        self.alpn_required = true;
        self
    }

    /// Set ALPN protocols and require successful negotiation.
    pub fn alpn_protocols_required(self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols(protocols).require_alpn()
    }

    /// Convenience method for HTTP/2 ALPN only.
    pub fn alpn_h2(self) -> Self {
        self.alpn_protocols_required(vec![b"h2".to_vec()])
    }

    /// Convenience method for gRPC (HTTP/2-only) ALPN.
    pub fn alpn_grpc(self) -> Self {
        self.alpn_h2()
    }

    /// Convenience method for HTTP/1.1 and HTTP/2 ALPN.
    ///
    /// HTTP/2 is preferred over HTTP/1.1.
    pub fn alpn_http(self) -> Self {
        self.alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    }

    /// Set maximum TLS fragment size.
    ///
    /// This limits the size of TLS records. Smaller values may help with
    /// constrained networks but reduce throughput.
    pub fn max_fragment_size(mut self, size: usize) -> Self {
        self.max_fragment_size = Some(size);
        self
    }

    /// Set a timeout for the TLS handshake.
    pub fn handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = Some(timeout);
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

        if self.alpn_required && self.alpn_protocols.is_empty() {
            return Err(TlsError::Configuration(
                "require_alpn set but no ALPN protocols configured".into(),
            ));
        }

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

        Ok(TlsAcceptor {
            config: Arc::new(config),
            handshake_timeout: self.handshake_timeout,
            alpn_required: self.alpn_required,
        })
    }

    /// Build the `TlsAcceptor` (disabled-mode fallback when TLS is disabled).
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
MIIDCTCCAfGgAwIBAgIUILC2ZkjRHPrfcHhzefebjS2lOzcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEyODIyMzkwMVoXDTI3MDEy
ODIyMzkwMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA8X9QR91omFIGbziPFqHCIt5sL5BTpMBYTLL6IU1Aalr6
so9aB1JLpWphzYXQ/rUBCSviBv5yrSL0LD7x6hw3G83zqNeqCGZXTKIgv4pkk6cu
KKtdfYcAuV1uTid1w31fknoywq5uRWdxkEl1r93f6xiwjW6Zw3bj2LCKFxiJdKht
T8kgOJwr33B2XduCw5auo3rG2+bzc/jXOVvyaev4mHLM0mjRLqScpIZ2npF5+YQz
MksNjNivQWK6TIqeTk2JSqqWUlxW8JgOg+5J9a7cZLaUUnBYPkMyV9ILxkLQIION
OXfum2roBWuV7vHGYK4aVWEWxGoYTt7ICZWWVXesRQIDAQABo1MwUTAdBgNVHQ4E
FgQU0j96nz+0aCyjZu9FVEIAQlDYAcwwHwYDVR0jBBgwFoAU0j96nz+0aCyjZu9F
VEIAQlDYAcwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQvah
cGeykFFXCARLWF9TpXWaRdjRf3r9+eMli6SQcsvrl0OzkLZ2qwLALXed73onhnbT
XZ8FjFINtbcRjUIbi2qIf6iOn2+DLTCJjZfFxGEDtXVlBBx1TjaJz6j/oIAgPEWg
2DLGS7tTbvKyB1LAGHTIEyKfEN6PZlYCEXNHp+Moz+zzAy96GHRd/yOZunJ2fYuu
EiKoSldjL6VzfrQPcMBv0uHCUDGBeB3VcMhCkdxdz/w2vQNZD813iF1R1yhlITv9
wwAjs13JGIDbcjI4zLsz9cPltIHkicvVm35hdJy6ALlJCe3rcOjb36QFodU7K4tw
uWkd54q5y+R18MtvvQ==
-----END CERTIFICATE-----"#;

    const TEST_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxf1BH3WiYUgZv
OI8WocIi3mwvkFOkwFhMsvohTUBqWvqyj1oHUkulamHNhdD+tQEJK+IG/nKtIvQs
PvHqHDcbzfOo16oIZldMoiC/imSTpy4oq119hwC5XW5OJ3XDfV+SejLCrm5FZ3GQ
SXWv3d/rGLCNbpnDduPYsIoXGIl0qG1PySA4nCvfcHZd24LDlq6jesbb5vNz+Nc5
W/Jp6/iYcszSaNEupJykhnaekXn5hDMySw2M2K9BYrpMip5OTYlKqpZSXFbwmA6D
7kn1rtxktpRScFg+QzJX0gvGQtAgg405d+6baugFa5Xu8cZgrhpVYRbEahhO3sgJ
lZZVd6xFAgMBAAECggEAHqLiElvaOwic3Fs2e86FjFrfKqGKmunzybci2Dquo09r
Yl+hMjCUfCWkxqflPYrE2N8CS5TYA3Lduwc5NVPjAdn8wTyqy2oARS6ELQhnffvF
dU9YCuanhtx9c9i5rdUn3LM34U6zmoZm98D59xeUooR9UVPomc1pVkH/IrLwLSY5
sYTzPIWTWqezSl+JcOBauXdwY6ynQJYTlWtxDeFM3TiTMiKiMT7SIECW5gqlxLLV
uhWRgZd5CqgewvZJ+P5CsFsLih7vdDccja/nuEj7zuW4uC0NdyS3uqHlrM+YxqnR
f9KdzJ4KFK9JUHv57Q+KHMs6cPeR5ixdwyuwcLNz+QKBgQD51uuZCZjFxlbcG5nK
EwfQetX7SUemR/OkuQqBxAAbj038dHMJxjhdML95ZxAR+jzpobqO+rGpZsRi+ErS
/B0aEIbO3LlV26xIAJOKiQv6bgIhqBpWDM6K/ayIGaDI49xK4DdDCvHg1YV/tLQ+
YcLX34226EtOZt97ak2YOCct9wKBgQD3c7vxLxyHSLuRNDC69J0LTfU6FGgn/9MQ
RtRphoDPOaB1ojL7cvvg47aC1QxnlhOLbhmHZzLzUESCdyJj8g0Yf9wZkz5UTmwH
ZZiInBhRfnKwb6eOKj6uJXFvwuMCy4HflK0w2nBSyeAdAjjG1wec+hB8+4b10p6t
gZ17TOvYowKBgQDNE6iSFzmK5jJ4PEOxhot8isfIm68vg5Iv3SANwnggJzJpjqC7
HjU38YLKQVoEl7aWRAXhxVA98Dg10P+CTiYJNhWiCbYsDsRM2gRBzBrD9rbTL6xm
g96qYm3Tzc2X+MnjwEY8RuiimEIbwJXPOun3zu4BfI4MDg9Vu71zvGwUowKBgQDW
6pXZK+nDNdBylLmeJsYfA15xSzgLRY2zHVFvNXq6gHp0sKNG8N8Cu8PQbemQLjBb
cQyLJX6DBLv79CzSUXA+Tw6Cx/fikRoScpLAU5JrdT93LgKA3wABkFOtlb5Etyvd
W+vv+kiEHwGfMEbPrALYu/eGFY9qAbv/RgvZAz3zsQKBgBgiHqIb6EYoD8vcRyBz
qP4j9OjdFe5BIjpj4GcEhTO02cWe40bWQ5Ut7zj2C7IdaUdCVQjg8k9FzeDrikK7
XDJ6t6uzuOdQSZwBxiZ9npt3GBzqLI3qiWhTMaD1+4ca3/SBUwPcGBbqPovdpKEv
W7n9v0wIyo4e/O0DO2fczXZD
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
        assert!(builder.alpn_required);
    }

    #[test]
    fn test_builder_alpn_grpc() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let builder = TlsAcceptorBuilder::new(chain, key).alpn_grpc();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
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

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_accept_handshake() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_http()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:5001".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert!(client.is_ready());
            assert!(server.is_ready());
            assert!(client.protocol_version().is_some());
            assert!(server.protocol_version().is_some());
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_server_preference_ordering() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            // Server prefers http/1.1 over h2; client prefers h2 over http/1.1.
            // Per TLS ALPN, the server selects from the intersection.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_fallback_to_http11_when_server_h2_not_supported() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            // Server supports only http/1.1; client offers h2 + http/1.1.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5110".parse().unwrap(),
                "127.0.0.1:5111".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_none_when_server_has_no_alpn() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            // Server does not advertise ALPN; client offers h2 + http/1.1.
            // This should still succeed and return no negotiated ALPN.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5120".parse().unwrap(),
                "127.0.0.1:5121".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            assert!(client.alpn_protocol().is_none());
            assert!(server.alpn_protocol().is_none());
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_required_client_errors_on_no_overlap() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            // Client requires h2; server only offers http/1.1 -> no overlap.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2()
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5130".parse().unwrap(),
                "127.0.0.1:5131".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client_err = client_res.unwrap_err();
            assert!(matches!(client_err, TlsError::AlpnNegotiationFailed { .. }));

            // Server is not configured to require ALPN, so it accepts the connection but
            // no ALPN is negotiated.
            let server = server_res.unwrap();
            assert!(server.alpn_protocol().is_none());
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_required_server_errors_when_client_offers_none() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;
        use futures_lite::future::zip;

        run_test(|| async {
            // Server requires h2; client does not offer ALPN -> no negotiation.
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_h2()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5140".parse().unwrap(),
                "127.0.0.1:5141".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // Client doesn't require ALPN, so the handshake can succeed from its POV.
            let client = client_res.unwrap();
            assert!(client.alpn_protocol().is_none());

            // Server enforces ALPN and rejects post-handshake if nothing was negotiated.
            let server_err = server_res.unwrap_err();
            assert!(matches!(server_err, TlsError::AlpnNegotiationFailed { .. }));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_timeout() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;

        run_test(|| async {
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .handshake_timeout(std::time::Duration::from_millis(5))
                .build()
                .unwrap();

            let (client_io, _server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5002".parse().unwrap(),
                "127.0.0.1:5003".parse().unwrap(),
            );

            let err = connector.connect("localhost", client_io).await.unwrap_err();
            assert!(matches!(err, TlsError::Timeout(_)));
        });
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
