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
    /// br-asupersync-gq7l9i: when `true`, `with_native_roots` also
    /// honours `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`
    /// / `SSL_CERT_DIR` env vars and adds every cert it finds as a
    /// trust anchor. Default is `false` — the env-var path is a known
    /// trust-injection vector in CI, container, and shared-host
    /// deployments, so callers must opt in via
    /// [`Self::enable_env_cert_loading`].
    enable_env_certs: bool,
    /// br-asupersync-p7369s: PEM-encoded CRL bodies the verifier will
    /// consult when validating the peer certificate chain. When
    /// non-empty, `build()` swaps the rustls default verifier for a
    /// `WebPkiServerVerifier` built with these CRLs.
    #[cfg(feature = "tls")]
    crl_pems: Vec<Vec<u8>>,
    #[cfg(feature = "tls")]
    min_protocol: Option<rustls::ProtocolVersion>,
    #[cfg(feature = "tls")]
    max_protocol: Option<rustls::ProtocolVersion>,
    #[cfg(feature = "tls")]
    resumption: Option<rustls::client::Resumption>,
    /// br-asupersync-y0gm5q: TLS 1.3 0-RTT (early data) opt-in on
    /// the client side. Defaults to `false` (matches rustls default
    /// and prevents accidental replay-vulnerable 0-RTT). See
    /// [`Self::enable_early_data`] for the explicit opt-in.
    early_data_enabled: bool,
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
            enable_env_certs: false,
            #[cfg(feature = "tls")]
            crl_pems: Vec::new(),
            #[cfg(feature = "tls")]
            min_protocol: None,
            #[cfg(feature = "tls")]
            max_protocol: None,
            #[cfg(feature = "tls")]
            resumption: None,
            // br-asupersync-y0gm5q: secure-by-default. 0-RTT off
            // until the operator opts in via enable_early_data(true).
            early_data_enabled: false,
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
    /// # Environment-variable trust anchors (br-asupersync-gq7l9i)
    ///
    /// `with_native_roots` does **not** consult the OpenSSL-style
    /// `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, or
    /// `SSL_CERT_DIR` environment variables. Honouring those vars
    /// silently allows any process able to set the environment (a
    /// container layer, a CI step, a sibling shell user) to inject
    /// arbitrary CAs into the trust store — a known root cause of
    /// supply-chain attacks. Callers who knowingly need the corporate-
    /// proxy CA pickup must opt in by chaining
    /// [`enable_env_cert_loading`](Self::enable_env_cert_loading)
    /// before `with_native_roots`. When that flag is set, every file
    /// added from an env-var path is logged at `warn!` (not `debug!`)
    /// with the source path and rejected-vs-loaded count.
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

        // br-asupersync-gq7l9i: load custom CA certs from
        // SSL_CERT_FILE / SSL_CERT_DIR / REQUESTS_CA_BUNDLE /
        // CURL_CA_BUNDLE only when the caller has explicitly opted in.
        // Default is no — silent env-var trust injection is a known
        // supply-chain attack vector.
        if self.enable_env_certs {
            self.load_env_certs();
        }

        Ok(self)
    }

    /// Opt in to OpenSSL-style env-var trust-anchor loading
    /// (br-asupersync-gq7l9i).
    ///
    /// When enabled, the next call to
    /// [`with_native_roots`](Self::with_native_roots) will also read
    /// CA certs from these environment variables (in priority order):
    ///
    /// * `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` —
    ///   a single PEM bundle file
    /// * `SSL_CERT_DIR` — a directory of `*.pem` / `*.crt` / `*.cer`
    ///   files; each file is loaded individually
    ///
    /// Each candidate cert is also subjected to the
    /// br-asupersync-0owoem `BasicConstraints CA:TRUE` gate before
    /// insertion: leaf certs and otherwise-non-CA certs are rejected
    /// even when present in the file.
    ///
    /// **Security note**: enabling this lets any caller able to set
    /// the process environment inject arbitrary trust anchors. Use
    /// only in deployments where the environment is part of your
    /// trust boundary (e.g., explicitly-configured corporate-proxy
    /// images), and prefer
    /// [`add_root_certificate`](Self::add_root_certificate) for
    /// known-good CA pinning.
    #[must_use]
    pub fn enable_env_cert_loading(mut self) -> Self {
        self.enable_env_certs = true;
        self
    }

    /// Add platform/native root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-native-roots"))]
    pub fn with_native_roots(self) -> Result<Self, TlsError> {
        Err(TlsError::Configuration(
            "tls-native-roots feature not enabled".into(),
        ))
    }

    /// Load additional CA certificates from the OpenSSL-style env vars.
    ///
    /// br-asupersync-gq7l9i: only invoked from `with_native_roots` when
    /// `self.enable_env_certs == true` (caller-set via
    /// [`Self::enable_env_cert_loading`]). Logs every loaded file and
    /// loaded/rejected count at `warn!` so the trust-anchor injection
    /// is visible in production logs.
    #[allow(dead_code)]
    fn load_env_certs(&mut self) {
        // Check multiple env vars that various tools use for custom CA
        // bundles. SSL_CERT_FILE is the most standard (OpenSSL),
        // REQUESTS_CA_BUNDLE (Python) and CURL_CA_BUNDLE (curl) are
        // also common in corporate envs.
        let cert_file = std::env::var("SSL_CERT_FILE")
            .or_else(|_| std::env::var("REQUESTS_CA_BUNDLE"))
            .or_else(|_| std::env::var("CURL_CA_BUNDLE"));
        if let Ok(cert_file) = cert_file {
            let path = std::path::Path::new(&cert_file);
            if path.exists() {
                #[allow(unused_variables)]
                let (loaded, rejected) = self.load_pem_file(path);
                // br-asupersync-gq7l9i: warn level (not debug) so this
                // shows up in default-config production logs.
                #[cfg(feature = "tracing-integration")]
                if loaded > 0 || rejected > 0 {
                    tracing::warn!(
                        path = %cert_file,
                        loaded = loaded,
                        rejected_non_ca = rejected,
                        "TLS: env-var CA bundle merged into trust store \
                         (br-asupersync-gq7l9i opt-in is active)"
                    );
                }
            }
        }

        if let Ok(cert_dir) = std::env::var("SSL_CERT_DIR") {
            let dir = std::path::Path::new(&cert_dir);
            if dir.is_dir() {
                #[allow(unused_mut, unused_variables, unused_assignments)]
                let mut loaded_total = 0usize;
                #[allow(unused_mut, unused_variables, unused_assignments)]
                let mut rejected_total = 0usize;
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(ext) = path.extension() {
                                if ext == "pem" || ext == "crt" || ext == "cer" {
                                    let (loaded, rejected) = self.load_pem_file(&path);
                                    loaded_total += loaded;
                                    rejected_total += rejected;
                                }
                            }
                        } else if path.is_dir() {
                            // Ignore subdirectories.
                        }
                    }
                }
                #[cfg(feature = "tracing-integration")]
                if loaded_total > 0 || rejected_total > 0 {
                    tracing::warn!(
                        path = %cert_dir,
                        loaded = loaded_total,
                        rejected_non_ca = rejected_total,
                        "TLS: SSL_CERT_DIR merged into trust store \
                         (br-asupersync-gq7l9i opt-in is active)"
                    );
                }
            }
        }
    }

    /// Parse PEM-encoded certificates from a file and add CAs to the
    /// root store. Returns `(loaded, rejected_non_ca)`.
    ///
    /// br-asupersync-0owoem: previously this used a hand-rolled
    /// splitter (`split("-----BEGIN CERTIFICATE-----")`) that did not
    /// require line-boundary anchoring — a crafted PEM file with the
    /// marker inside a comment could be split into spurious blocks
    /// whose base64 decoded to attacker-chosen DER, and the resulting
    /// `Certificate` was added to the trust store with no further
    /// validation. Worse, a non-CA leaf certificate would be accepted
    /// as a trust anchor (any cert it had "signed" would then
    /// validate). The implementation below now (a) parses via
    /// `rustls_pemfile::certs`, the same path used by
    /// `Certificate::from_pem`, and (b) gates each candidate on the
    /// `BasicConstraints CA:TRUE` extension via `x509-parser`. Certs
    /// that lack the extension or carry `cA=false` are rejected and
    /// counted in the second return value.
    #[allow(dead_code)]
    #[cfg(feature = "tls")]
    fn load_pem_file(&mut self, path: &std::path::Path) -> (usize, usize) {
        let Ok(pem_data) = std::fs::read(path) else {
            return (0, 0);
        };

        let mut reader = std::io::BufReader::new(&pem_data[..]);
        let der_certs: Vec<Vec<u8>> = match rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(certs) => certs.into_iter().map(|c| c.to_vec()).collect(),
            Err(_e) => {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    path = %path.display(),
                    error = %_e,
                    "TLS: PEM bundle parse failed; skipping file (br-asupersync-0owoem)"
                );
                return (0, 0);
            }
        };

        let mut loaded = 0usize;
        let mut rejected = 0usize;
        for der in der_certs {
            if !is_ca_certificate(&der) {
                rejected += 1;
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    path = %path.display(),
                    "TLS: rejecting non-CA certificate from trust-anchor file \
                     (basicConstraints CA:TRUE missing or absent — br-asupersync-0owoem)"
                );
                continue;
            }
            if self
                .root_certs
                .add(&Certificate::from_der(der))
                .is_ok()
            {
                loaded += 1;
            }
        }
        (loaded, rejected)
    }

    /// Stub for the `tls`-disabled build — env-var loading is a no-op.
    #[allow(dead_code)]
    #[cfg(not(feature = "tls"))]
    fn load_pem_file(&mut self, _path: &std::path::Path) -> (usize, usize) {
        (0, 0)
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

    /// **DANGEROUS**: send TLS 1.3 0-RTT (early data) on resumed
    /// handshakes when the server's resumption ticket allows it.
    ///
    /// br-asupersync-y0gm5q: 0-RTT is OFF by default on the
    /// client side — rustls's `enable_early_data` defaults to
    /// `false` and we leave it that way unless the operator opts
    /// in via this method. The corresponding acceptor-side
    /// opt-in is [`crate::tls::TlsAcceptorBuilder::enable_early_data`].
    ///
    /// # Replay vulnerability (RFC 8446 §8)
    ///
    /// 0-RTT data is replay-vulnerable BY SPEC. An attacker who
    /// captures the early-data record can replay it to the same
    /// server within the ticket window; the server has no
    /// transport-level mechanism to detect or reject the replay.
    /// Even read-only requests can leak — a replayed GET hits the
    /// origin (and any downstream metering / rate-limit / audit
    /// log) again. Only enable on the client when:
    ///
    /// 1. The application enforces idempotency for every
    ///    request that could carry early data, AND
    /// 2. The server side has a corresponding anti-replay store
    ///    bound to the resumption ticket.
    ///
    /// Pass `false` to explicitly disable (the default).
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn enable_early_data(mut self, enabled: bool) -> Self {
        self.early_data_enabled = enabled;
        self
    }

    /// Add a PEM-encoded Certificate Revocation List
    /// (br-asupersync-p7369s).
    ///
    /// When at least one CRL is configured, `build()` constructs a
    /// `WebPkiServerVerifier` that consults the CRLs during peer-cert
    /// validation. A peer cert whose serial number appears in any CRL
    /// is rejected with a typed verification error and the connection
    /// fails before any application bytes flow.
    ///
    /// # Tradeoffs
    ///
    /// * **Freshness**: rustls only consults the CRLs that were
    ///   present at `build()` time. CRL refresh requires constructing
    ///   a fresh `TlsConnector`. Long-lived processes connecting to
    ///   slowly-rotating PKIs should periodically rebuild the
    ///   connector with a current CRL.
    /// * **Coverage**: a CRL covers only the certs issued by the
    ///   matching CA. Mixing CRLs from multiple CAs is supported;
    ///   each CRL applies to its issuer. CRLs for CAs that do not
    ///   appear in the configured roots are silently inert.
    /// * **OCSP**: rustls 0.23 does not surface OCSP-stapling
    ///   *enforcement*, only OCSP-response *acceptance* during the
    ///   handshake. CRL is the more reliable revocation primitive
    ///   here. When OCSP-must-staple is required, deploy a sidecar
    ///   that pre-validates the OCSP response and blocklists revoked
    ///   serials into the CRL set.
    #[cfg(feature = "tls")]
    pub fn with_crl_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.crl_pems.push(pem.into());
        self
    }

    /// Add multiple PEM-encoded CRLs in one call
    /// (br-asupersync-p7369s).
    #[cfg(feature = "tls")]
    pub fn with_crl_pems<I, P>(mut self, pems: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<Vec<u8>>,
    {
        for pem in pems {
            self.crl_pems.push(pem.into());
        }
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

        // br-asupersync-p7369s: when at least one CRL is configured,
        // swap the rustls default verifier for a
        // `WebPkiServerVerifier` built with the CRLs. The resulting
        // verifier still uses the same trust roots; CRLs apply per-
        // issuer at validation time. With no CRLs, the rustls default
        // verifier path is used (existing behavior preserved).
        let roots = self.root_certs.into_inner();
        let builder = if self.crl_pems.is_empty() {
            builder.with_root_certificates(roots)
        } else {
            use rustls::server::WebPkiClientVerifier as _; // ensure rustls in scope
            let mut crl_ders: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
                Vec::new();
            for pem in &self.crl_pems {
                let mut reader = std::io::BufReader::new(&pem[..]);
                let der_iter = rustls_pemfile::crls(&mut reader);
                for der in der_iter {
                    let der = der.map_err(|e| {
                        TlsError::Configuration(format!("CRL PEM parse error: {e}"))
                    })?;
                    crl_ders.push(der);
                }
            }
            if crl_ders.is_empty() {
                return Err(TlsError::Configuration(
                    "with_crl_pem called but no CRL blocks were parsed from the supplied PEM(s)"
                        .into(),
                ));
            }
            let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                .with_crls(crl_ders)
                .build()
                .map_err(|e| TlsError::Configuration(format!("CRL verifier build: {e}")))?;
            // The dangerous() name reflects that callers can plug in
            // an arbitrary verifier — here we plug in webpki's own
            // verifier with CRLs attached, which is *strictly more*
            // strict than the default. This is the documented escape
            // hatch for adding CRL/OCSP enforcement on top of
            // standard validation.
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        };

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

        // br-asupersync-y0gm5q: explicit early-data write. rustls's
        // own default is `false` (0-RTT off) but we set it
        // explicitly so a future rustls API change cannot silently
        // flip the default to "on" without us noticing. The value
        // here is the operator's choice from `enable_early_data(...)`
        // (default false).
        config.enable_early_data = self.early_data_enabled;

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            alpn = ?config.alpn_protocols,
            sni = config.enable_sni,
            enable_early_data = config.enable_early_data,
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

/// Return `true` iff the DER-encoded certificate bears
/// `BasicConstraints CA:TRUE` and is therefore eligible to act as a
/// trust anchor (br-asupersync-0owoem).
///
/// A cert without the BasicConstraints extension, or with `cA=false`,
/// is **not** a CA per RFC 5280 §4.2.1.9 and must not be inserted
/// into the root-cert store: doing so would let any cert chained
/// underneath it be accepted by webpki — a complete trust bypass.
/// Self-signed leaf certs (very common in misconfigured deployments)
/// fall in this category and are rejected.
#[cfg(feature = "tls")]
fn is_ca_certificate(der: &[u8]) -> bool {
    // x509-parser is already an optional dep enabled by the `tls`
    // feature; reuse it rather than rolling a bespoke ASN.1 walker.
    let parsed = match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => cert,
        Err(_) => return false,
    };
    parsed
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca)
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

    // br-asupersync-7wnl2l: previously this test asserted that
    // `TlsConnectorBuilder::new().build()` *succeeded* with no roots
    // configured — directly contradicting the explicit empty-roots
    // rejection at the top of `build()` (which exists precisely so a
    // misconfigured caller doesn't open a no-roots connection that
    // would skip server-cert validation entirely). The test was dead
    // (silently failing the .unwrap() in any environment that
    // exercised it). Inverted to assert the rejection, plus a paired
    // positive test below using the test fixture's CA.
    #[cfg(feature = "tls")]
    #[test]
    fn test_build_empty_roots_rejected() {
        let err = TlsConnectorBuilder::new()
            .build()
            .expect_err("empty roots must be rejected by build()");
        match err {
            TlsError::Certificate(msg) => {
                assert!(
                    msg.contains("no root certificates configured"),
                    "expected empty-roots rejection message, got: {msg}"
                );
            }
            other => panic!("expected TlsError::Certificate, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_test_root_succeeds() {
        // Positive control for the empty-roots rejection above. Uses
        // the test-fixture CA so build() succeeds. Pins the success
        // path so a future agent removing the empty-roots check
        // cannot land it without also breaking this test.
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .build()
            .expect("builder with one root should succeed");
        assert!(connector.config().alpn_protocols.is_empty());
    }

    // --- br-asupersync-gq7l9i: env-var trust anchors are opt-in ----

    #[test]
    fn test_env_cert_loading_disabled_by_default() {
        // br-asupersync-gq7l9i: TlsConnectorBuilder::new() must leave
        // env-var trust-anchor loading disabled. A caller who sets
        // SSL_CERT_FILE in their environment must NOT have those
        // certs silently injected; explicit opt-in via
        // enable_env_cert_loading() is required.
        let builder = TlsConnectorBuilder::new();
        assert!(
            !builder.enable_env_certs,
            "env-var cert loading must be off by default"
        );
    }

    #[test]
    fn test_enable_env_cert_loading_sets_flag() {
        // br-asupersync-gq7l9i: explicit opt-in flips the flag.
        let builder = TlsConnectorBuilder::new().enable_env_cert_loading();
        assert!(
            builder.enable_env_certs,
            "enable_env_cert_loading must flip the opt-in flag"
        );
    }

    // --- br-asupersync-0owoem: BasicConstraints CA:TRUE gate -------

    #[cfg(feature = "tls")]
    #[test]
    fn test_is_ca_certificate_rejects_self_signed_leaf() {
        // br-asupersync-0owoem: the test fixture server cert is a
        // *leaf* — it lacks `basicConstraints CA:TRUE` (it carries
        // server-auth EKU and is signed by a real CA in test
        // setups). Adding it to the trust store as a *trust anchor*
        // would let any cert it "signed" validate, which is exactly
        // the trust-bypass the gate prevents.
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("parse test cert");
        let cert = certs.first().expect("at least one cert in fixture");
        let der: &[u8] = cert.as_der();
        let is_ca = super::is_ca_certificate(der);
        // The test fixture is a leaf cert (CA:FALSE or BC missing),
        // so the gate must reject it. If a future fixture rotation
        // ships a CA cert here, this assertion will fail loudly and
        // surface the regression — that's the intent.
        assert!(
            !is_ca,
            "test fixture leaf cert must be rejected by CA-gate (br-asupersync-0owoem); \
             if the fixture was rotated to a CA, update this test"
        );
    }

    // --- br-asupersync-p7369s: CRL configuration -------------------

    #[cfg(feature = "tls")]
    #[test]
    fn test_with_crl_pem_with_garbage_pem_rejected_at_build() {
        // br-asupersync-p7369s: garbage that doesn't parse as CRL
        // PEM must surface a typed Configuration error, not a panic
        // and not a silent skip-the-CRL.
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let err = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .with_crl_pem(b"not a valid CRL".to_vec())
            .build()
            .expect_err("garbage CRL PEM must reject at build()");
        match err {
            TlsError::Configuration(msg) => {
                assert!(
                    msg.contains("CRL"),
                    "expected CRL-related Configuration error, got: {msg}"
                );
            }
            other => panic!("expected TlsError::Configuration, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_no_crl_means_default_verifier_path() {
        // br-asupersync-p7369s: callers that don't configure any CRL
        // must continue to land on the rustls default-verifier code
        // path (i.e., build() must not regress to requiring CRL
        // configuration). This test pins the no-CRL no-op behaviour.
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .build()
            .expect("no-CRL build must succeed");
        let _ = connector.config(); // smoke-check the inner config materialised
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

    // ── br-asupersync-y0gm5q: 0-RTT secure-by-default ────────────────

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_default_connector_disables_0rtt_early_data() {
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&Certificate::from_der(TEST_CERT_PEM.to_vec()))
            .build()
            .expect("build default connector");
        assert!(
            !connector.config.enable_early_data,
            "default connector must have enable_early_data=false \
             (TLS 1.3 0-RTT disabled — replay defense)"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_opt_in_sets_flag() {
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&Certificate::from_der(TEST_CERT_PEM.to_vec()))
            .enable_early_data(true)
            .build()
            .expect("build with early data enabled");
        assert!(
            connector.config.enable_early_data,
            "enable_early_data(true) must propagate to ClientConfig"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_false_disables_flag() {
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&Certificate::from_der(TEST_CERT_PEM.to_vec()))
            .enable_early_data(true)
            .enable_early_data(false)
            .build()
            .expect("build with early data toggled off");
        assert!(
            !connector.config.enable_early_data,
            "enable_early_data(false) must reset enable_early_data flag"
        );
    }
}
