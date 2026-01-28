//! TLS client connector.
//!
//! This module provides `TlsConnector` and `TlsConnectorBuilder` for establishing
//! TLS connections from the client side.

use super::error::TlsError;
use super::types::{Certificate, CertificateChain, PrivateKey, RootCertStore};

#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use rustls::ClientConfig;

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
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<()>,
}

impl TlsConnector {
    /// Create a connector from a raw rustls `ClientConfig`.
    #[cfg(feature = "tls")]
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Create a builder for constructing a `TlsConnector`.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder::new()
    }

    /// Get the inner configuration (for advanced use).
    #[cfg(feature = "tls")]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
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

    /// Validate a domain name for use with TLS (stub when TLS is disabled).
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
    enable_sni: bool,
    #[cfg(feature = "tls")]
    min_protocol: Option<rustls::ProtocolVersion>,
    #[cfg(feature = "tls")]
    max_protocol: Option<rustls::ProtocolVersion>,
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
            enable_sni: true,
            #[cfg(feature = "tls")]
            min_protocol: None,
            #[cfg(feature = "tls")]
            max_protocol: None,
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
        for cert in rustls_native_certs::load_native_certs()? {
            // Ignore individual cert errors
            let _ = self.root_certs.add(&Certificate::from_der(cert.to_vec()));
        }
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            count = self.root_certs.len(),
            "Loaded native root certificates"
        );
        Ok(self)
    }

    /// Add platform/native root certificates (stub when feature is disabled).
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
        for cert in webpki_roots::TLS_SERVER_ROOTS.iter() {
            let _ = self.root_certs.add(&Certificate::from_der(
                cert.subject_public_key_info.to_vec(),
            ));
        }
        #[cfg(feature = "tracing-integration")]
        tracing::debug!("Added webpki root certificates");
        self
    }

    /// Add the standard webpki root certificates (stub when feature is disabled).
    #[cfg(not(feature = "tls-webpki-roots"))]
    pub fn with_webpki_roots(self) -> Self {
        #[cfg(feature = "tracing-integration")]
        tracing::warn!("tls-webpki-roots feature not enabled, no roots added");
        self
    }

    /// Add a single root certificate.
    pub fn add_root_certificate(mut self, cert: Certificate) -> Self {
        if let Err(e) = self.root_certs.add(&cert) {
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

    /// Disable Server Name Indication (SNI).
    ///
    /// SNI is required by many servers. Only disable if you know what you're doing.
    pub fn disable_sni(mut self) -> Self {
        self.enable_sni = false;
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

    /// Build the `TlsConnector`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g., invalid client certificate).
    #[cfg(feature = "tls")]
    pub fn build(self) -> Result<TlsConnector, TlsError> {
        use rustls::crypto::ring::default_provider;

        if self.root_certs.is_empty() {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!("Building TlsConnector with no root certificates");
        }

        // Create the config builder with the crypto provider
        let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Configuration(e.to_string()))?
            .with_root_certificates(self.root_certs.into_inner());

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

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            alpn = ?config.alpn_protocols,
            sni = config.enable_sni,
            "TlsConnector built"
        );

        Ok(TlsConnector::new(config))
    }

    /// Build the `TlsConnector` (stub when TLS is disabled).
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

    #[cfg(not(feature = "tls"))]
    #[test]
    fn test_build_without_tls_feature() {
        let result = TlsConnectorBuilder::new().build();
        assert!(result.is_err());
    }
}
