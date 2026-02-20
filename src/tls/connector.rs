//! TLS client connector.
//!
//! This module provides `TlsConnector` and `TlsConnectorBuilder` for establishing
//! TLS connections from the client side.

use super::error::TlsError;
use super::stream::TlsStream;
use super::types::{Certificate, CertificateChain, PrivateKey, RootCertStore};
use crate::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rustls::ClientConfig;
#[cfg(feature = "tls")]
use rustls::ClientConnection;
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;

#[cfg(feature = "tls")]
use std::future::poll_fn;
use std::sync::Arc;

/// Client-side TLS connector.
///
/// This is typically configured once and reused for many connections.
/// Cloning is cheap (Arc-based).
///
/// # Example
///
/// ```ignore
/// let connector = TlsConnector::builder()
///     .with_webpki_roots()
///     .alpn_http()
///     .build()?;
///
/// let tls_stream = connector.connect("example.com", tcp_stream).await?;
/// ```
#[derive(Clone)]
pub struct TlsConnector {
    #[cfg(feature = "tls")]
    config: Arc<ClientConfig>,
    handshake_timeout: Option<std::time::Duration>,
    alpn_required: bool,
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<()>,
}

impl TlsConnector {
    /// Create a connector from a raw rustls `ClientConfig`.
    #[cfg(feature = "tls")]
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
            handshake_timeout: None,
            alpn_required: false,
        }
    }

    /// Create a builder for constructing a `TlsConnector`.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder::new()
    }

    /// Get the handshake timeout, if configured.
    #[must_use]
    pub fn handshake_timeout(&self) -> Option<std::time::Duration> {
        self.handshake_timeout
    }

    /// Get the inner configuration (for advanced use).
    #[cfg(feature = "tls")]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }

    /// Establish a TLS connection over the provided I/O stream.
    ///
    /// # Cancel-Safety
    /// Handshake is NOT cancel-safe. If cancelled mid-handshake, drop the stream.
    #[cfg(feature = "tls")]
    pub async fn connect<IO>(&self, domain: &str, io: IO) -> Result<TlsStream<IO>, TlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(domain.to_string())
            .map_err(|_| TlsError::InvalidDnsName(domain.to_string()))?;
        let conn = ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|e| TlsError::Configuration(e.to_string()))?;
        let mut stream = TlsStream::new_client(io, conn);
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

    /// Establish a TLS connection (disabled-mode fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub async fn connect<IO>(&self, _domain: &str, _io: IO) -> Result<TlsStream<IO>, TlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }

    /// Validate a domain name for use with TLS.
    ///
    /// Returns an error if the domain is not a valid DNS name.
    #[cfg(feature = "tls")]
    pub fn validate_domain(domain: &str) -> Result<(), TlsError> {
        ServerName::try_from(domain.to_string())
            .map_err(|_| TlsError::InvalidDnsName(domain.to_string()))?;
        Ok(())
    }

    /// Validate a domain name for use with TLS (disabled-mode fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn validate_domain(domain: &str) -> Result<(), TlsError> {
        // Basic validation: not empty and no spaces
        if domain.is_empty() || domain.contains(' ') {
            return Err(TlsError::InvalidDnsName(domain.to_string()));
        }
        Ok(())
    }
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

/// Builder for `TlsConnector`.
///
/// # Example
///
/// ```ignore
/// let connector = TlsConnectorBuilder::new()
///     .with_native_roots()?
///     .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
///     .build()?;
/// ```
#[derive(Debug, Default)]
pub struct TlsConnectorBuilder {
    root_certs: RootCertStore,
    client_identity: Option<(CertificateChain, PrivateKey)>,
    alpn_protocols: Vec<Vec<u8>>,
    alpn_required: bool,
    enable_sni: bool,
    handshake_timeout: Option<std::time::Duration>,
    #[cfg(feature = "tls")]
    min_protocol: Option<rustls::ProtocolVersion>,
    #[cfg(feature = "tls")]
    max_protocol: Option<rustls::ProtocolVersion>,
    #[cfg(feature = "tls")]
    resumption: Option<rustls::client::Resumption>,
}

impl TlsConnectorBuilder {
    /// Create a new builder with default settings.
    ///
    /// By default:
    /// - No root certificates (you must add some)
    /// - No client certificate
    /// - No ALPN protocols
    /// - SNI enabled
    pub fn new() -> Self {
        Self {
            root_certs: RootCertStore::empty(),
            client_identity: None,
            alpn_protocols: Vec::new(),
            alpn_required: false,
            enable_sni: true,
            handshake_timeout: None,
            #[cfg(feature = "tls")]
            min_protocol: None,
            #[cfg(feature = "tls")]
            max_protocol: None,
            #[cfg(feature = "tls")]
            resumption: None,
        }
    }

    /// Add platform/native root certificates.
    ///
    /// On Linux, this typically reads from /etc/ssl/certs.
    /// On macOS, this uses the system keychain.
    /// On Windows, this uses the Windows certificate store.
    ///
    /// Requires the `tls-native-roots` feature.
    #[cfg(feature = "tls-native-roots")]
    pub fn with_native_roots(mut self) -> Result<Self, TlsError> {
        let result = rustls_native_certs::load_native_certs();

        // Log any errors but continue with successfully loaded certs
        #[cfg(feature = "tracing-integration")]
        for err in &result.errors {
            tracing::warn!(error = %err, "Error loading native certificate");
        }

        for cert in result.certs {
            // Ignore individual cert add errors
            let _ = self.root_certs.add(&Certificate::from_der(cert.to_vec()));
        }

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            count = self.root_certs.len(),
            "Loaded native root certificates"
        );
        Ok(self)
    }

    /// Add platform/native root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-native-roots"))]
    pub fn with_native_roots(self) -> Result<Self, TlsError> {
        Err(TlsError::Configuration(
            "tls-native-roots feature not enabled".into(),
        ))
    }

    /// Add the standard webpki root certificates.
    ///
    /// These are the Mozilla root certificates, embedded at compile time.
    ///
    /// Requires the `tls-webpki-roots` feature.
    #[cfg(feature = "tls-webpki-roots")]
    pub fn with_webpki_roots(mut self) -> Self {
        self.root_certs.extend_from_webpki_roots();
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            count = self.root_certs.len(),
            "Added webpki root certificates"
        );
        self
    }

    /// Add the standard webpki root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-webpki-roots"))]
    pub fn with_webpki_roots(self) -> Self {
        #[cfg(feature = "tracing-integration")]
        tracing::warn!("tls-webpki-roots feature not enabled, no roots added");
        self
    }

    /// Add a single root certificate.
    pub fn add_root_certificate(mut self, cert: &Certificate) -> Self {
        if let Err(e) = self.root_certs.add(cert) {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(error = %e, "Failed to add root certificate");
            let _ = e; // Suppress unused warning when tracing is disabled
        }
        self
    }

    /// Add multiple root certificates.
    pub fn add_root_certificates(mut self, certs: impl IntoIterator<Item = Certificate>) -> Self {
        for cert in certs {
            if let Err(e) = self.root_certs.add(&cert) {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(error = %e, "Failed to add root certificate");
                let _ = e;
            }
        }
        self
    }

    /// Set client certificate for mutual TLS (mTLS).
    pub fn identity(mut self, chain: CertificateChain, key: PrivateKey) -> Self {
        self.client_identity = Some((chain, key));
        self
    }

    /// Set ALPN protocols (e.g., `["h2", "http/1.1"]`).
    ///
    /// Protocols are tried in order of preference (first is most preferred).
    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Require that the peer negotiates an ALPN protocol.
    ///
    /// If the peer does not negotiate any protocol (or negotiates something
    /// unexpected), `connect()` returns `TlsError::AlpnNegotiationFailed`.
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

    /// Disable Server Name Indication (SNI).
    ///
    /// SNI is required by many servers. Only disable if you know what you're doing.
    pub fn disable_sni(mut self) -> Self {
        self.enable_sni = false;
        self
    }

    /// Set a timeout for the TLS handshake.
    pub fn handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = Some(timeout);
        self
    }

    /// Set minimum TLS protocol version.
    #[cfg(feature = "tls")]
    pub fn min_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.min_protocol = Some(version);
        self
    }

    /// Set maximum TLS protocol version.
    #[cfg(feature = "tls")]
    pub fn max_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.max_protocol = Some(version);
        self
    }

    /// Configure TLS session resumption.
    ///
    /// By default, rustls enables in-memory session storage (256 sessions).
    /// Use this to customize the resumption strategy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rustls::client::Resumption;
    ///
    /// let connector = TlsConnectorBuilder::new()
    ///     .session_resumption(Resumption::in_memory_sessions(512))
    ///     .build()?;
    /// ```
    #[cfg(feature = "tls")]
    pub fn session_resumption(mut self, resumption: rustls::client::Resumption) -> Self {
        self.resumption = Some(resumption);
        self
    }

    /// Disable TLS session resumption entirely.
    ///
    /// This forces a full handshake on every connection. Use for testing
    /// or when session tickets are a security concern.
    #[cfg(feature = "tls")]
    pub fn disable_session_resumption(mut self) -> Self {
        self.resumption = Some(rustls::client::Resumption::disabled());
        self
    }

    /// Build the `TlsConnector`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g., invalid client certificate).
    #[cfg(feature = "tls")]
    pub fn build(self) -> Result<TlsConnector, TlsError> {
        use rustls::crypto::ring::default_provider;

        if self.alpn_required && self.alpn_protocols.is_empty() {
            return Err(TlsError::Configuration(
                "require_alpn set but no ALPN protocols configured".into(),
            ));
        }

        if self.root_certs.is_empty() {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!("Building TlsConnector with no root certificates");
        }

        // Create the config builder with the crypto provider and protocol versions.
        let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()));
        let builder = if self.min_protocol.is_some() || self.max_protocol.is_some() {
            // Convert protocol versions to ordinals for comparison.
            // TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
            fn version_ordinal(v: rustls::ProtocolVersion) -> u16 {
                match v {
                    rustls::ProtocolVersion::TLSv1_2 => 0x0303,
                    rustls::ProtocolVersion::TLSv1_3 => 0x0304,
                    // For unknown versions, use a high value so they're excluded by default
                    _ => 0xFFFF,
                }
            }

            let min = self.min_protocol.map(version_ordinal);
            let max = self.max_protocol.map(version_ordinal);

            if let (Some(min_ord), Some(max_ord)) = (min, max) {
                if min_ord > max_ord {
                    return Err(TlsError::Configuration(
                        "min_protocol_version is greater than max_protocol_version".into(),
                    ));
                }
            }

            let versions: Vec<&'static rustls::SupportedProtocolVersion> = rustls::ALL_VERSIONS
                .iter()
                .filter(|v| {
                    let ordinal = version_ordinal(v.version);
                    let within_min = min.is_none_or(|m| ordinal >= m);
                    let within_max = max.is_none_or(|m| ordinal <= m);
                    within_min && within_max
                })
                .copied()
                .collect();

            if versions.is_empty() {
                return Err(TlsError::Configuration(
                    "no supported TLS protocol versions within requested range".into(),
                ));
            }

            builder
                .with_protocol_versions(&versions)
                .map_err(|e| TlsError::Configuration(e.to_string()))?
        } else {
            builder
                .with_safe_default_protocol_versions()
                .map_err(|e| TlsError::Configuration(e.to_string()))?
        };

        let builder = builder.with_root_certificates(self.root_certs.into_inner());

        // Set client identity if provided
        let mut config = if let Some((chain, key)) = self.client_identity {
            builder
                .with_client_auth_cert(chain.into_inner(), key.clone_inner())
                .map_err(|e| TlsError::Configuration(e.to_string()))?
        } else {
            builder.with_no_client_auth()
        };

        // Set ALPN if specified
        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols;
        }

        // SNI is enabled by default in rustls
        config.enable_sni = self.enable_sni;

        // Configure session resumption if explicitly set.
        // Default: rustls uses in-memory storage for 256 sessions.
        if let Some(resumption) = self.resumption {
            config.resumption = resumption;
        }

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            alpn = ?config.alpn_protocols,
            sni = config.enable_sni,
            "TlsConnector built"
        );

        Ok(TlsConnector {
            config: Arc::new(config),
            handshake_timeout: self.handshake_timeout,
            alpn_required: self.alpn_required,
        })
    }

    /// Build the `TlsConnector` (disabled-mode fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn build(self) -> Result<TlsConnector, TlsError> {
        Err(TlsError::Configuration("tls feature not enabled".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = TlsConnectorBuilder::new();
        assert!(builder.root_certs.is_empty());
        assert!(builder.alpn_protocols.is_empty());
        assert!(builder.enable_sni);
    }

    #[test]
    fn test_builder_alpn_http() {
        let builder = TlsConnectorBuilder::new().alpn_http();
        assert_eq!(
            builder.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn test_builder_alpn_h2() {
        let builder = TlsConnectorBuilder::new().alpn_h2();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[test]
    fn test_builder_alpn_grpc() {
        let builder = TlsConnectorBuilder::new().alpn_grpc();
        assert_eq!(builder.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(builder.alpn_required);
    }

    #[test]
    fn test_builder_disable_sni() {
        let builder = TlsConnectorBuilder::new().disable_sni();
        assert!(!builder.enable_sni);
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(TlsConnector::validate_domain("example.com").is_ok());
        assert!(TlsConnector::validate_domain("sub.example.com").is_ok());
        assert!(TlsConnector::validate_domain("localhost").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(TlsConnector::validate_domain("").is_err());
        assert!(TlsConnector::validate_domain("invalid domain with spaces").is_err());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_empty_roots() {
        // Should build but with a warning
        let connector = TlsConnectorBuilder::new().build().unwrap();
        assert!(connector.config().alpn_protocols.is_empty());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_alpn() {
        let connector = TlsConnectorBuilder::new().alpn_http().build().unwrap();

        assert_eq!(
            connector.config().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_handshake_timeout_builder() {
        let timeout = std::time::Duration::from_secs(1);
        let connector = TlsConnectorBuilder::new()
            .handshake_timeout(timeout)
            .build()
            .unwrap();
        assert_eq!(connector.handshake_timeout(), Some(timeout));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connector_clone_is_cheap() {
        let connector = TlsConnectorBuilder::new().build().unwrap();

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _clone = connector.clone();
        }
        let elapsed = start.elapsed();

        // Should be very fast (Arc clone)
        assert!(elapsed.as_millis() < 100);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_invalid_dns() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test;

        run_test(|| async {
            let connector = TlsConnectorBuilder::new().build().unwrap();
            let (client_io, _server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );
            let err = connector
                .connect("invalid domain with spaces", client_io)
                .await
                .unwrap_err();
            assert!(matches!(err, TlsError::InvalidDnsName(_)));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_session_resumption_custom() {
        let connector = TlsConnectorBuilder::new()
            .session_resumption(rustls::client::Resumption::in_memory_sessions(512))
            .build()
            .unwrap();
        // Connector builds successfully with custom resumption config.
        assert!(connector.handshake_timeout().is_none());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_session_resumption_disabled() {
        let connector = TlsConnectorBuilder::new()
            .disable_session_resumption()
            .build()
            .unwrap();
        assert!(connector.handshake_timeout().is_none());
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn test_build_without_tls_feature() {
        let result = TlsConnectorBuilder::new().build();
        assert!(result.is_err());
    }
}
