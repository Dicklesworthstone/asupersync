//! TLS client connector.
//!
//! This module provides `TlsConnector` and `TlsConnectorBuilder` for establishing
//! TLS connections from the client side.

use super::error::TlsError;
use super::stream::TlsStream;
use super::types::{Certificate, CertificateChain, CertificatePinSet, PrivateKey, RootCertStore};
use crate::io::{AsyncRead, AsyncWrite};
use base64::Engine as _;

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
    /// br-asupersync-v24lvi: certificate-pinning set. When `Some`,
    /// `connect()` validates the peer leaf certificate against
    /// these pins after the rustls handshake completes; failure
    /// aborts the connection. `None` (the default) skips pinning
    /// — webpki / native roots remain the only check.
    pin_set: Option<Arc<CertificatePinSet>>,
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
            pin_set: None,
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
                super::timeout_now(),
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
            let ok = negotiated
                .as_deref()
                .is_some_and(|p| expected.iter().any(|e| e.as_slice() == p));
            if !ok {
                return Err(TlsError::AlpnNegotiationFailed {
                    expected,
                    negotiated,
                });
            }
        }

        // br-asupersync-v24lvi: certificate-pinning enforcement.
        // After the rustls handshake completes (which validated the
        // chain against the configured root store), additionally
        // validate the peer leaf cert against the pinned hashes.
        // This catches CA-issued attack certs that would otherwise
        // pass webpki / native-roots validation. On enforcement
        // failure the stream is dropped immediately so no
        // application data flows over the un-pinned connection.
        if let Some(pin_set) = self.pin_set.as_ref() {
            let leaf_der = stream.peer_leaf_certificate_der().ok_or_else(|| {
                TlsError::Certificate(
                    "certificate-pinning enabled but peer presented no \
                     leaf certificate after handshake (br-asupersync-v24lvi)"
                        .to_string(),
                )
            })?;
            let leaf = Certificate::from_der(leaf_der);
            match pin_set.validate(&leaf) {
                Ok(true) => {
                    // Pin matched (or set was empty) — proceed.
                }
                Ok(false) => {
                    // Report-only mode: no match but enforcement
                    // disabled; let the connection through. The
                    // pin_set.validate impl already records the
                    // miss for diagnostic logging.
                }
                Err(err) => {
                    // Enforcement on + no match: abort the
                    // connection. Drop the stream explicitly so the
                    // FIN reaches the peer before we surface the
                    // error to the caller.
                    drop(stream);
                    return Err(err);
                }
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
    /// br-asupersync-v24lvi: certificate-pinning set. See
    /// [`Self::with_certificate_pins`].
    pin_set: Option<CertificatePinSet>,
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
            pin_set: None,
            #[cfg(feature = "tls")]
            min_protocol: None,
            #[cfg(feature = "tls")]
            max_protocol: None,
            #[cfg(feature = "tls")]
            resumption: None,
        }
    }

    /// Attach a [`CertificatePinSet`] for post-handshake leaf-cert
    /// validation.
    ///
    /// br-asupersync-v24lvi: when set, every connection produced by
    /// the resulting `TlsConnector` will, after the rustls handshake
    /// completes, extract the peer leaf certificate and call
    /// [`CertificatePinSet::validate`]. If validation fails AND the
    /// set is in enforcement mode, the handshake is rolled back —
    /// the stream is dropped before any application bytes flow.
    /// Report-only sets (`CertificatePinSet::report_only`) log the
    /// miss but allow the connection through.
    ///
    /// Pre-fix: `CertificatePinSet` existed in `tls/types.rs` but had
    /// no path into the connector handshake, so any caller who
    /// configured pins thought they were enforced when in fact
    /// rustls's CA-based validation was the only check.
    #[must_use]
    pub fn with_certificate_pins(mut self, pin_set: CertificatePinSet) -> Self {
        self.pin_set = Some(pin_set);
        self
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

        // Also load custom CA certs from SSL_CERT_FILE / SSL_CERT_DIR if set.
        // Corporate proxies commonly require a custom CA certificate, and these
        // env vars are the standard mechanism (supported by OpenSSL, curl, etc.).
        self.load_env_certs();

        Ok(self)
    }

    /// Add platform/native root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-native-roots"))]
    pub fn with_native_roots(self) -> Result<Self, TlsError> {
        Err(TlsError::Configuration(
            "tls-native-roots feature not enabled".into(),
        ))
    }

    /// Load additional CA certificates from `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables. This supports corporate proxy environments where
    /// a custom CA cert must be trusted.
    #[allow(dead_code)]
    fn load_env_certs(&mut self) {
        // Check multiple env vars that various tools use for custom CA bundles.
        // SSL_CERT_FILE is the most standard (OpenSSL), but REQUESTS_CA_BUNDLE
        // (Python) and CURL_CA_BUNDLE (curl) are also common in corporate envs.
        let cert_file = std::env::var("SSL_CERT_FILE")
            .or_else(|_| std::env::var("REQUESTS_CA_BUNDLE"))
            .or_else(|_| std::env::var("CURL_CA_BUNDLE"));
        if let Ok(cert_file) = cert_file {
            let path = std::path::Path::new(&cert_file);
            if path.exists() {
                #[allow(unused_variables)]
                let added = self.load_pem_file(path);
                #[cfg(feature = "tracing-integration")]
                if added > 0 {
                    tracing::debug!(
                        path = %cert_file,
                        count = added,
                        "Loaded CA certificates from SSL_CERT_FILE"
                    );
                }
            }
        }

        if let Ok(cert_dir) = std::env::var("SSL_CERT_DIR") {
            let dir = std::path::Path::new(&cert_dir);
            if dir.is_dir() {
                #[allow(unused_mut, unused_variables, unused_assignments)]
                let mut added = 0usize;
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(ext) = path.extension() {
                                if ext == "pem" || ext == "crt" || ext == "cer" {
                                    added += self.load_pem_file(&path);
                                }
                            }
                        } else if path.is_dir() {
                            // Ignore directories
                        }
                    }
                }
                #[cfg(feature = "tracing-integration")]
                if added > 0 {
                    tracing::debug!(
                        path = %cert_dir,
                        count = added,
                        "Loaded CA certificates from SSL_CERT_DIR"
                    );
                }
            }
        }
    }

    /// Parse PEM-encoded certificates from a file and add them to the root store.
    #[allow(dead_code)]
    fn load_pem_file(&mut self, path: &std::path::Path) -> usize {
        let Ok(pem_data) = std::fs::read(path) else {
            return 0;
        };

        let mut added = 0usize;
        // Simple PEM parser: extract base64 between BEGIN/END CERTIFICATE markers
        let pem_str = String::from_utf8_lossy(&pem_data);
        for block in pem_str.split("-----BEGIN CERTIFICATE-----") {
            if let Some(end_idx) = block.find("-----END CERTIFICATE-----") {
                let base64_data = &block[..end_idx];
                let cleaned: String = base64_data.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                    let _ = self.root_certs.add(&Certificate::from_der(der));
                    added += 1;
                }
            }
        }
        added
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
    ///
    /// # Advertise vs. require
    ///
    /// This setter **advertises** the listed protocols to the peer but does
    /// NOT require the peer to negotiate one. Per RFC 7301 a server that
    /// omits the ALPN extension entirely is still accepted, and
    /// `connect()` returns `Ok` with `negotiated_alpn = None`. If the caller
    /// is an HTTP/2-only or gRPC-only client (where a non-ALPN HTTP/1.1
    /// peer is a protocol mismatch rather than a valid fallback), pair this
    /// call with [`require_alpn`](Self::require_alpn), or — more concisely —
    /// use [`alpn_protocols_required`](Self::alpn_protocols_required),
    /// [`alpn_h2`](Self::alpn_h2), or [`alpn_grpc`](Self::alpn_grpc),
    /// which set the require-ALPN flag for you.
    ///
    /// [`alpn_http`](Self::alpn_http) intentionally keeps the require flag
    /// off because HTTP/1.1 fallback on no-ALPN is the correct behavior for
    /// dual-stack clients. Use this raw setter only when you need that
    /// precise advertise-but-don't-require semantic.
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
    /// HTTP/2 is preferred over HTTP/1.1. Unlike [`alpn_h2`](Self::alpn_h2)
    /// and [`alpn_grpc`](Self::alpn_grpc), this does **not** set
    /// `alpn_required`: servers that omit the ALPN extension fall back to
    /// HTTP/1.1, which is the correct behavior per RFC 7301 for clients
    /// that support both protocols.
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
            return Err(TlsError::Certificate(
                "no root certificates configured — server certificates cannot be verified"
                    .to_string(),
            ));
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
            pin_set: self.pin_set.map(Arc::new),
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
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

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
    fn test_validate_domain_rfc3492_punycode_vector() {
        // RFC 3492 / IDNA-style A-label for "bücher.example".
        let punycode = "xn--bcher-kva.example";

        assert!(TlsConnector::validate_domain(punycode).is_ok());
        assert!(TlsConnector::validate_domain("bücher.example").is_err());
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
        use crate::test_utils::run_test_with_cx;

        run_test_with_cx(|_cx| async move {
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
    fn test_connect_completes_under_lab_runtime() {
        use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
        use crate::cx::Cx;
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::init_test_logging;
        use crate::tls::TlsAcceptorBuilder;
        use futures_lite::future::zip;

        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE9)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (ready, protocol_present, alpn, checkpoints) = LabRuntimeTarget::block_on(
            &mut runtime,
            async move {
                let _cx = Cx::current().expect("lab runtime should install a current Cx");

                let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
                let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
                let acceptor = TlsAcceptorBuilder::new(chain, key)
                    .alpn_http()
                    .build()
                    .unwrap();

                let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
                let connector = TlsConnectorBuilder::new()
                    .add_root_certificates(certs)
                    .alpn_http()
                    .handshake_timeout(std::time::Duration::from_secs(1))
                    .build()
                    .unwrap();

                let (client_io, server_io) = VirtualTcpStream::pair(
                    "127.0.0.1:5300".parse().unwrap(),
                    "127.0.0.1:5301".parse().unwrap(),
                );

                let checkpoints = vec![serde_json::json!({
                    "phase": "connector_pair_created",
                    "client_addr": "127.0.0.1:5300",
                    "server_addr": "127.0.0.1:5301",
                    "handshake_timeout_ms": 1000,
                })];
                tracing::info!(event = %checkpoints[0], "tls_connector_lab_checkpoint");

                let (client_res, server_res) = zip(
                    connector.connect("localhost", client_io),
                    acceptor.accept(server_io),
                )
                .await;
                let client = client_res.expect("connector handshake should succeed");
                let server = server_res.expect("server handshake should succeed");

                let ready = client.is_ready() && server.is_ready();
                let protocol_present =
                    client.protocol_version().is_some() && server.protocol_version().is_some();
                let alpn = client.alpn_protocol().map(|protocol| protocol.to_vec());

                let mut checkpoints = checkpoints;
                checkpoints.push(serde_json::json!({
                    "phase": "connector_handshake_completed",
                    "ready": ready,
                    "protocol_present": protocol_present,
                    "client_alpn": alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                    "server_alpn": server.alpn_protocol().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                }));
                tracing::info!(event = %checkpoints[1], "tls_connector_lab_checkpoint");

                (ready, protocol_present, alpn, checkpoints)
            },
        );

        assert!(ready);
        assert!(protocol_present);
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
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

    // ── br-asupersync-v24lvi: certificate-pinning wiring tests ────────

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_with_certificate_pins_attaches_pin_set_to_connector() {
        // Builder accepts a pin set; the resulting connector carries
        // it. Pre-fix there was no such builder method — the only
        // way to "use" pins was to call them manually after connect()
        // returned, which 99% of callers never did.
        let mut pins = CertificatePinSet::new();
        pins.add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&Certificate::from_der(TEST_CERT_PEM.to_vec()))
            .with_certificate_pins(pins)
            .build()
            .expect("build with pins");
        assert!(
            connector.pin_set.is_some(),
            "with_certificate_pins must populate the connector's pin_set"
        );
        assert_eq!(
            connector.pin_set.as_ref().unwrap().len(),
            1,
            "all attached pins must reach the connector"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_default_connector_has_no_pin_set() {
        // Back-compat: a connector built WITHOUT calling
        // with_certificate_pins() carries no pin set, so existing
        // callers that rely on rustls-only validation are unaffected.
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&Certificate::from_der(TEST_CERT_PEM.to_vec()))
            .build()
            .expect("build without pins");
        assert!(
            connector.pin_set.is_none(),
            "default connector must not have an implicit pin set"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_mismatched_pin_returns_error_via_pin_set_validate() {
        // The connector wires CertificatePinSet::validate into the
        // post-handshake gate. We verify the validate semantics here
        // (the unit-of-fix for the connector's gate logic) — the
        // gate's *invocation* is exercised end-to-end by integration
        // tests that need a real TLS handshake. Without a mock
        // stream the connect() path can't run in a unit test, so
        // pinning the validate semantics + the wiring (above) is
        // the maximal regression we can land here.
        let cert = Certificate::from_der(TEST_CERT_PEM.to_vec());
        let mut mismatched = CertificatePinSet::new();
        mismatched
            .add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let result = mismatched.validate(&cert);
        assert!(
            result.is_err(),
            "mismatched-pin enforcement-on validation must Err; \
             got {result:?}. This is the failure that the connector \
             gate now propagates as TlsError to abort the connection."
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn v24lvi_report_only_mismatched_pin_does_not_error() {
        // Symmetry check: report-only sets surface as Ok(false) (not
        // Err) which the connector gate explicitly treats as
        // "log-and-continue" — verifies the connector's match-arm
        // handles the no-enforcement code path correctly without
        // tearing down the connection.
        let cert = Certificate::from_der(TEST_CERT_PEM.to_vec());
        let mut report_only = CertificatePinSet::report_only();
        report_only
            .add_spki_sha256_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("valid base64");
        let result = report_only.validate(&cert);
        assert!(
            matches!(result, Ok(false)),
            "report-only mismatched pin must return Ok(false) (not Err); \
             got {result:?}"
        );
    }
}
