//! TLS client connector.
//!
//! This module provides `TlsConnector` and `TlsConnectorBuilder` for establishing
//! TLS connections from the client side.

use super::error::TlsError;
use super::stream::TlsStream;
#[cfg(feature = "tls")]
use super::types::pem_error_message;
use super::types::{Certificate, CertificateChain, CertificatePinSet, PrivateKey, RootCertStore};
use crate::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rustls::ClientConfig;
#[cfg(feature = "tls")]
use rustls::ClientConnection;
#[cfg(feature = "tls")]
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, pem::PemObject};

#[cfg(feature = "tls")]
use std::future::poll_fn;
use std::sync::Arc;

#[cfg(not(feature = "tls"))]
const TLS_FEATURE_HINT: &str = "rebuild with --features tls";

#[cfg(not(feature = "tls"))]
fn tls_feature_disabled(operation: &'static str) -> TlsError {
    TlsError::FeatureDisabled {
        operation,
        hint: TLS_FEATURE_HINT,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TlsCertificateLoadCounts {
    loaded: usize,
    rejected_non_ca: usize,
}

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

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    pub(crate) fn single_enforcing_spki(&self) -> Option<[u8; 32]> {
        self.pin_set.as_ref()?.single_enforcing_spki()
    }

    /// br-asupersync-m209nx — Attach a `CertificatePinSet` to a
    /// connector built from a raw `ClientConfig` (i.e., one that
    /// did not flow through `TlsConnectorBuilder::with_certificate_pins`).
    /// Useful for tests that need to combine a custom rustls
    /// `ClientConfig` (e.g., a permissive `ServerCertVerifier` for
    /// self-signed fixtures) with the v24lvi pinning gate; also
    /// useful for production callers that bring their own
    /// `ClientConfig` and want to layer pinning on top.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_pin_set(mut self, pin_set: CertificatePinSet) -> Self {
        self.pin_set = Some(Arc::new(pin_set));
        self
    }

    /// br-asupersync-m209nx — Attach a handshake timeout to a
    /// connector built from a raw `ClientConfig`. Mirrors the
    /// builder-side `TlsConnectorBuilder::handshake_timeout`.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = Some(timeout);
        self
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
        let _ = (self.alpn_required, self.pin_set.as_ref());
        Err(tls_feature_disabled("connect TLS stream"))
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
    /// br-asupersync-h41wya — operator acknowledgement that 0-RTT
    /// exposes the application to replay attacks on the early-data
    /// payload. When `false`, `build()` rejects
    /// `early_data_enabled = true` whatever the session-resumption
    /// setting (without resumption no 0-RTT is offered anyway), so a
    /// misconfiguration cannot ship by accident. The operator must call
    /// [`Self::acknowledge_zero_rtt_replay_risk`] to opt in,
    /// signalling that the application layer enforces idempotency
    /// for every request that could carry early data.
    acknowledge_zero_rtt_replay_risk: bool,
    /// br-asupersync-sx6j9y — when `true`, `add_root_certificate` and
    /// `add_root_certificates` apply the same `BasicConstraints
    /// CA:TRUE` gate that `enable_env_cert_loading` uses, instead of
    /// admitting any cert into the trust store. Set via
    /// [`Self::with_strict_ca_validation`]; automatically set as a
    /// side effect of [`Self::enable_env_cert_loading`].
    validate_ca_constraints: bool,
    /// The rustls crypto provider set with [`Self::crypto_provider`].
    /// `None` resolves as the `tls` module documentation describes.
    #[cfg(feature = "tls")]
    crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
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
            // br-asupersync-h41wya: 0-RTT replay risk is unacknowledged
            // by default; build() rejects early data until the
            // operator calls acknowledge_zero_rtt_replay_risk().
            acknowledge_zero_rtt_replay_risk: false,
            // br-asupersync-sx6j9y: BasicConstraints CA:TRUE gate is
            // off by default for backward compat (tests use self-
            // signed leaf certs as roots). Production callers should
            // chain with_strict_ca_validation(); enable_env_cert_loading
            // also sets it as a side effect because env-loaded certs
            // are unconditionally CA-gated by br-asupersync-0owoem.
            validate_ca_constraints: false,
            #[cfg(feature = "tls")]
            crypto_provider: None,
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
        // br-asupersync-sx6j9y — env-loaded certs are unconditionally
        // CA-gated (br-asupersync-0owoem). Mirror that gate to all
        // other root-cert insertion paths so the operator who opted
        // into env-cert loading also gets the same protection on
        // direct add_root_certificate / add_root_certificates calls.
        self.validate_ca_constraints = true;
        self
    }

    /// br-asupersync-sx6j9y — turn on the `BasicConstraints CA:TRUE`
    /// gate for all root-cert insertion paths. With this flag set,
    /// `add_root_certificate` and `add_root_certificates` skip any
    /// cert that does not assert `cA=TRUE`. Without it, the gate is
    /// applied only to env-loaded certs (the legacy behavior),
    /// leaving direct `add_root_certificate(<leaf>)` as a silent
    /// trust bypass — exactly the failure mode this method exists to
    /// close. Set as a side effect of
    /// [`Self::enable_env_cert_loading`]. Production callers SHOULD
    /// set this explicitly. Use
    /// the test-only `Self::insecure_add_root_certificate` for the rare cases
    /// where you intentionally want a non-CA cert in the trust
    /// store (e.g., pinning a self-signed test cert in a sandbox).
    #[must_use]
    pub fn with_strict_ca_validation(mut self) -> Self {
        self.validate_ca_constraints = true;
        self
    }

    /// br-asupersync-h41wya — explicitly acknowledge the 0-RTT
    /// (early data) replay-attack risk. TLS 1.3 0-RTT is by-spec
    /// replay-vulnerable (RFC 8446 §8): an attacker who captures the
    /// early-data wire bytes can replay them to the same server
    /// within the resumption ticket window, and rustls's in-memory
    /// session store provides no anti-replay window. The application
    /// layer MUST enforce idempotency for every request that could
    /// carry early data (idempotency keys, per-request nonces, or
    /// restriction of 0-RTT to safe HTTP methods).
    ///
    /// `build()` rejects `enable_early_data(true)` when this
    /// acknowledgement has not been made, whatever the session-resumption
    /// setting — preventing a misconfiguration from
    /// shipping silently. Call this only after wiring up the
    /// application-level idempotency layer.
    #[must_use]
    pub fn acknowledge_zero_rtt_replay_risk(mut self) -> Self {
        self.acknowledge_zero_rtt_replay_risk = true;
        self
    }

    /// Add platform/native root certificates (fallback when feature is disabled).
    #[cfg(not(feature = "tls-native-roots"))]
    pub fn with_native_roots(self) -> Result<Self, TlsError> {
        #[cfg(not(feature = "tls"))]
        {
            Err(tls_feature_disabled("load native root certificates"))
        }
        #[cfg(feature = "tls")]
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
                let load_result = self.load_pem_file(path);
                // br-asupersync-gq7l9i: warn level (not debug) so this
                // shows up in default-config production logs.
                #[cfg(feature = "tracing-integration")]
                match &load_result {
                    Ok(counts) if counts.loaded > 0 || counts.rejected_non_ca > 0 => {
                        tracing::warn!(
                            path = %cert_file,
                            loaded = counts.loaded,
                            rejected_non_ca = counts.rejected_non_ca,
                            "TLS: env-var CA bundle merged into trust store \
                             (br-asupersync-gq7l9i opt-in is active)"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %cert_file,
                            error = %error,
                            "TLS: env-var CA bundle requested but certificate loading failed"
                        );
                    }
                    _ => {}
                }
                let _ = load_result;
            }
        }

        if let Ok(cert_dir) = std::env::var("SSL_CERT_DIR") {
            let dir = std::path::Path::new(&cert_dir);
            if dir.is_dir() {
                // br-asupersync-s0nwli: only accumulate per-file
                // counters when the tracing-integration feature is on
                // — they are exclusively read by the tracing::warn!
                // block below. Without the feature, the totals were
                // dead-write which trips clippy's unused_assignments
                // lint at -D warnings.
                #[cfg(feature = "tracing-integration")]
                let mut loaded_total = 0usize;
                #[cfg(feature = "tracing-integration")]
                let mut rejected_total = 0usize;
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            if is_env_cert_bundle_path(&path) {
                                let load_result = self.load_pem_file(&path);
                                #[cfg(feature = "tracing-integration")]
                                match &load_result {
                                    Ok(counts) => {
                                        loaded_total = loaded_total.saturating_add(counts.loaded);
                                        rejected_total =
                                            rejected_total.saturating_add(counts.rejected_non_ca);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            path = %path.display(),
                                            error = %error,
                                            "TLS: SSL_CERT_DIR file requested but certificate loading failed"
                                        );
                                    }
                                }
                                let _ = load_result;
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
    /// root store. Returns explicit load counters.
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
    /// `CertificateDer::pem_reader_iter`, the same path used by
    /// `Certificate::from_pem`, and (b) gates each candidate on the
    /// `BasicConstraints CA:TRUE` extension via `x509-parser`. Certs
    /// that lack the extension or carry `cA=false` are rejected and
    /// counted in the second return value.
    #[allow(dead_code)]
    #[cfg(feature = "tls")]
    fn load_pem_file(
        &mut self,
        path: &std::path::Path,
    ) -> Result<TlsCertificateLoadCounts, TlsError> {
        let Ok(pem_data) = std::fs::read(path) else {
            return Ok(TlsCertificateLoadCounts::default());
        };

        let mut reader = std::io::BufReader::new(&pem_data[..]);
        let der_certs: Vec<Vec<u8>> =
            match CertificateDer::pem_reader_iter(&mut reader).collect::<Result<Vec<_>, _>>() {
                Ok(certs) => certs.into_iter().map(|c| c.to_vec()).collect(),
                Err(_e) => {
                    #[cfg(feature = "tracing-integration")]
                    tracing::warn!(
                        path = %path.display(),
                        error = %pem_error_message(_e),
                        "TLS: PEM bundle parse failed; skipping file (br-asupersync-0owoem)"
                    );
                    return Ok(TlsCertificateLoadCounts::default());
                }
            };

        let mut loaded = 0usize;
        let mut rejected = 0usize;
        for der in der_certs {
            if !is_ca_certificate(&der) {
                rejected = rejected.saturating_add(1);
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    path = %path.display(),
                    "TLS: rejecting non-CA certificate from trust-anchor file \
                     (basicConstraints CA:TRUE missing or absent — br-asupersync-0owoem)"
                );
                continue;
            }
            if self.root_certs.add(&Certificate::from_der(der)).is_ok() {
                loaded = loaded.saturating_add(1);
            }
        }
        Ok(TlsCertificateLoadCounts {
            loaded,
            rejected_non_ca: rejected,
        })
    }

    /// Disabled-mode PEM loading fails explicitly instead of reporting zero counts.
    #[allow(dead_code)]
    #[cfg(not(feature = "tls"))]
    fn load_pem_file(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<TlsCertificateLoadCounts, TlsError> {
        Err(tls_feature_disabled("load PEM trust anchors"))
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
    ///
    /// br-asupersync-sx6j9y — when [`Self::with_strict_ca_validation`]
    /// is set (or has been set as a side effect of
    /// [`Self::enable_env_cert_loading`]), the cert is gated by the
    /// `BasicConstraints CA:TRUE` predicate. A cert without that
    /// extension — most commonly a self-signed leaf — is rejected
    /// (logged at warn) and **not** inserted. This closes the
    /// silent-trust-bypass vector where a misconfigured operator
    /// adds their own server's leaf cert to the trust store.
    ///
    /// Use the test-only `Self::insecure_add_root_certificate` to bypass the
    /// gate when you intentionally want a non-CA cert in the trust
    /// store (rare; only legitimate for pinning a self-signed test
    /// cert in a sandbox).
    pub fn add_root_certificate(mut self, cert: &Certificate) -> Self {
        if !self.admit_root_certificate(cert) {
            return self;
        }
        if let Err(e) = self.root_certs.add(cert) {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(error = %e, "Failed to add root certificate");
            let _ = e; // Suppress unused warning when tracing is disabled
        }
        self
    }

    /// Add multiple root certificates.
    ///
    /// br-asupersync-sx6j9y — each cert is independently gated; see
    /// the doc on [`Self::add_root_certificate`] for the gate
    /// semantics.
    pub fn add_root_certificates(mut self, certs: impl IntoIterator<Item = Certificate>) -> Self {
        for cert in certs {
            if !self.admit_root_certificate(&cert) {
                continue;
            }
            if let Err(e) = self.root_certs.add(&cert) {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(error = %e, "Failed to add root certificate");
                let _ = e;
            }
        }
        self
    }

    /// br-asupersync-sx6j9y — bypass the `BasicConstraints CA:TRUE`
    /// gate and insert the cert into the trust store unconditionally.
    /// Reserved for the rare cases where a non-CA cert is
    /// intentionally trusted as a root (e.g., pinning a self-signed
    /// test cert in a sandbox).
    ///
    /// **SECURITY**: This method is restricted to test builds only to prevent
    /// production deployments from accidentally bypassing certificate validation
    /// and enabling MITM attacks. Use `add_root_certificate()` with
    /// `with_strict_ca_validation()` in production instead.
    #[cfg(test)]
    pub fn insecure_add_root_certificate(mut self, cert: &Certificate) -> Self {
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            "TLS: insecure_add_root_certificate called in test build — \
             BasicConstraints CA:TRUE gate bypassed (br-asupersync-sx6j9y)"
        );
        if let Err(e) = self.root_certs.add(cert) {
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(error = %e, "Failed to add root certificate");
            let _ = e;
        }
        self
    }

    /// br-asupersync-sx6j9y — apply the strict-CA gate when the
    /// builder has opted in. Returns `true` to admit the cert,
    /// `false` to reject it. Logs rejections at warn level when
    /// tracing integration is enabled.
    #[cfg(feature = "tls")]
    fn admit_root_certificate(&self, cert: &Certificate) -> bool {
        if !self.validate_ca_constraints {
            return true;
        }
        let der = cert.as_der();
        let is_ca = is_ca_certificate(der);
        #[cfg(feature = "tracing-integration")]
        if !is_ca {
            tracing::warn!(
                "TLS: rejecting non-CA cert from add_root_certificate / \
                 add_root_certificates — basicConstraints CA:TRUE missing or \
                 absent (br-asupersync-sx6j9y; with_strict_ca_validation is on)"
            );
        }
        is_ca
    }

    /// Fallback for the `tls`-disabled build — strict-CA gate is a no-op
    /// because there is no x509 parser available.
    #[cfg(not(feature = "tls"))]
    fn admit_root_certificate(&self, _cert: &Certificate) -> bool {
        true
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
    /// If the handshake completes but the peer negotiated no protocol (or
    /// something unexpected), `connect()` returns
    /// `TlsError::AlpnNegotiationFailed`. If the server offers ALPN with no
    /// protocol in common, it aborts the handshake itself with a
    /// `no_application_protocol` alert (RFC 7301), and `connect()` returns
    /// `TlsError::Handshake`.
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

    /// Use `provider` for this connector's cipher suites, key exchange and
    /// certificate signature verification.
    ///
    /// Without it, the connector uses the ring provider when `tls` links it,
    /// else rustls's process default; a `tls-core` build with neither fails
    /// in [`Self::build`]. The certificate verifier always uses the same
    /// provider as the connection.
    #[cfg(feature = "tls")]
    pub fn crypto_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
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

    /// **DANGEROUS**: offer TLS 1.3 0-RTT (early data) on resumed
    /// handshakes. No asupersync stream API writes early data yet.
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
    /// * **Coverage**: a CRL covers only the certs its CA issued, and a
    ///   cert whose issuer has no configured CRL is still accepted. CRLs
    ///   from several CAs can be mixed. CRLs for CAs that do not appear
    ///   in the configured roots are silently inert.
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

        // br-asupersync-h41wya — fail-closed on the silent
        // 0-RTT-replay misconfiguration. Combining session
        // resumption (client default: in-memory store of 256
        // sessions) with TLS 1.3 0-RTT exposes the application to
        // replay attacks on the early-data payload (RFC 8446 §8).
        // The operator must explicitly acknowledge the risk by
        // calling acknowledge_zero_rtt_replay_risk(); otherwise
        // build() rejects the combination so it cannot ship by
        // accident.
        if self.early_data_enabled && !self.acknowledge_zero_rtt_replay_risk {
            return Err(TlsError::Configuration(
                "enable_early_data(true) requires \
                 acknowledge_zero_rtt_replay_risk() — TLS 1.3 0-RTT is replay-vulnerable \
                 by spec (RFC 8446 §8) and rustls's in-memory session store provides \
                 no anti-replay window. Wire up application-level idempotency for every \
                 request that could carry early data, then call \
                 acknowledge_zero_rtt_replay_risk() to confirm"
                    .into(),
            ));
        }

        // Create the config builder with the crypto provider and protocol versions.
        let provider = super::resolve_crypto_provider(self.crypto_provider.as_ref())?;
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider));
        let builder = if self.min_protocol.is_some() || self.max_protocol.is_some() {
            // Compare protocol versions by their wire value (TLS 1.0 = 0x0301
            // ... TLS 1.3 = 0x0304), which orders every TLS version. A bound
            // below TLS 1.2 is then honoured: a TLS 1.1 ceiling leaves no
            // version (a build error) and a TLS 1.0 floor admits 1.2 and 1.3.
            // Mapping them to 0xFFFF made the ceiling a no-op and the floor an
            // error. DTLS values (0xFEFF and below) sort above every TLS one.
            fn version_ordinal(v: rustls::ProtocolVersion) -> u16 {
                u16::from(v)
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
            let mut crl_ders: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
                Vec::new();
            for pem in &self.crl_pems {
                let mut reader = std::io::BufReader::new(&pem[..]);
                let der_iter = CertificateRevocationListDer::pem_reader_iter(&mut reader);
                for der in der_iter {
                    let der = der.map_err(|e| {
                        TlsError::Configuration(format!(
                            "CRL PEM parse error: {}",
                            pem_error_message(e)
                        ))
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
            // rustls defaults to refusing any certificate whose issuer has
            // no configured CRL (UnknownRevocationStatus). A CRL covers only
            // its issuer, as documented on `with_crl_pem`, so a chain from a
            // CA without one is accepted and a listed serial is still refused.
            // `builder_with_provider` keeps the verifier on the connection's
            // provider; plain `builder` would use rustls's process default.
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .with_crls(crl_ders)
            .allow_unknown_revocation_status()
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
        let _ = (
            self.alpn_required,
            self.pin_set.as_ref(),
            self.early_data_enabled,
        );
        Err(tls_feature_disabled("build TLS connector"))
    }
}

fn is_env_cert_bundle_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("pem")
                || ext.eq_ignore_ascii_case("crt")
                || ext.eq_ignore_ascii_case("cer")
        })
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
#[path = "connector_inline_tests.rs"]
mod tests;
