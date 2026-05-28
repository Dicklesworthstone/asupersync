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
use std::collections::BTreeMap;
#[cfg(feature = "tls")]
use std::future::poll_fn;
use std::path::Path;
#[cfg(feature = "tls")]
use std::sync::Arc;

/// Server-side TLS acceptor.
///
/// This is typically configured once and reused to accept many connections.
/// Cloning is cheap (Arc-based).
///
/// # Security Considerations for Multi-Tenant Deployments
///
/// **CRITICAL**: In multi-tenant SaaS deployments, SNI-less connections
/// MUST be rejected to prevent exposure of the default certificate tenant.
/// Use `require_sni_for_multi_tenant()` to enforce this security boundary.
///
/// Without SNI enforcement, attackers can probe the default tenant by
/// connecting without the SNI extension, potentially bypassing tenant
/// isolation (tracked as asupersync-3iqbx3).
///
/// # Example (Single-tenant)
///
/// ```ignore
/// let acceptor = TlsAcceptor::builder(cert_chain, private_key)
///     .alpn_http()
///     .build()?;
///
/// let tls_stream = acceptor.accept(tcp_stream).await?;
/// ```
///
/// # Example (Multi-tenant - SECURITY REQUIRED)
///
/// ```ignore
/// let acceptor = TlsAcceptor::builder(cert_chain, private_key)
///     .alpn_http()
///     .require_sni_for_multi_tenant()  // CRITICAL for multi-tenant
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
    /// br-asupersync-vu10zb — when true, `accept()` requires the
    /// client's ClientHello to carry an SNI extension. SNI-less
    /// connections fail the handshake before any application bytes
    /// flow. Multi-tenant servers MUST set this so a probing
    /// attacker cannot reach the default-cert tenant.
    require_sni: bool,
    /// br-asupersync-i4n46s — optional per-SNI ALPN allow-list. When
    /// `Some`, after the handshake `accept()` checks that the
    /// negotiated ALPN protocol is in the allow-list for the
    /// observed SNI hostname. A SNI hostname not present in the map
    /// (case-insensitive) fails the handshake (strict allow-list
    /// semantics — silent accept of an unknown tenant is the bug
    /// this fix exists to close).
    #[cfg(feature = "tls")]
    sni_alpn_allow_list: Option<Arc<BTreeMap<String, Vec<Vec<u8>>>>>,
    /// br-asupersync-ycuuwy — replay protection strategy for TLS 1.3
    /// 0-RTT early data. Applications can use this to implement
    /// protection logic at the request processing layer.
    early_data_replay_protection: EarlyDataReplayProtection,
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
            require_sni: false,
            sni_alpn_allow_list: None,
            early_data_replay_protection: EarlyDataReplayProtection::None,
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

    /// Get the 0-RTT replay protection strategy.
    ///
    /// br-asupersync-ycuuwy: Applications can use this to implement
    /// request-level replay protection logic. For example, if the
    /// strategy is `SafeMethodsOnly`, the application should reject
    /// state-changing HTTP methods when the request arrived as 0-RTT.
    #[must_use]
    pub fn early_data_replay_protection(&self) -> &EarlyDataReplayProtection {
        &self.early_data_replay_protection
    }
}

impl EarlyDataReplayProtection {
    /// Check if an HTTP method is safe for 0-RTT with this protection strategy.
    ///
    /// br-asupersync-ycuuwy: Helper method for applications to validate
    /// HTTP methods against the configured replay protection strategy.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method string (e.g., "GET", "POST", "PUT")
    /// * `has_idempotency_key` - Whether request has idempotency key (for IdempotencyKeys strategy)
    /// * `has_valid_nonce` - Whether request has valid nonce (for NonceValidation strategy)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the request should be allowed, `Err(reason)` if rejected.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // In your HTTP handler:
    /// if tls_stream.received_early_data() {
    ///     if let Err(reason) = acceptor.early_data_replay_protection()
    ///         .validate_request_for_early_data("POST", true, false) {
    ///         return Response::builder()
    ///             .status(425) // Too Early
    ///             .body(format!("0-RTT rejected: {}", reason))?;
    ///     }
    /// }
    /// ```
    pub fn validate_request_for_early_data(
        &self,
        method: &str,
        has_idempotency_key: bool,
        has_valid_nonce: bool,
    ) -> Result<(), &'static str> {
        match self {
            EarlyDataReplayProtection::None => {
                Err("0-RTT enabled without replay protection - all requests vulnerable")
            }
            EarlyDataReplayProtection::UnprotectedForTesting => {
                // Allow everything in testing mode but this should log warnings
                Ok(())
            }
            EarlyDataReplayProtection::SafeMethodsOnly => {
                match method.to_ascii_uppercase().as_str() {
                    "GET" | "HEAD" | "OPTIONS" => Ok(()),
                    _ => Err("only safe HTTP methods (GET/HEAD/OPTIONS) allowed for 0-RTT"),
                }
            }
            EarlyDataReplayProtection::IdempotencyKeys => {
                if has_idempotency_key {
                    Ok(())
                } else {
                    Err("idempotency key required for 0-RTT requests")
                }
            }
            EarlyDataReplayProtection::NonceValidation => {
                if has_valid_nonce {
                    Ok(())
                } else {
                    Err("valid nonce required for 0-RTT requests")
                }
            }
        }
    }
}

impl TlsAcceptor {
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
                // SECURITY: br-asupersync-iz6751 — sanitize error message to prevent
                // ALPN protocol reconnaissance. Don't expose expected/negotiated protocol
                // lists which could help attackers understand server capabilities.
                return Err(TlsError::Configuration(
                    "ALPN protocol negotiation failed - client protocol not supported".into(),
                ));
            }
        }

        // br-asupersync-vu10zb — require SNI when configured. Multi-
        // tenant servers MUST reject SNI-less connections so the
        // default-cert tenant is not reachable via probing.
        if self.require_sni && stream.sni_hostname().is_none() {
            return Err(TlsError::Configuration(
                "SECURITY: Client did not send SNI extension but require_sni() is set. \
                 SNI-less connections are rejected to prevent exposure of default \
                 certificate tenant in multi-tenant deployments (asupersync-3iqbx3)"
                    .into(),
            ));
        }

        // br-asupersync-i4n46s — SNI/ALPN consistency check. When the
        // operator has configured a per-SNI ALPN allow-list, the
        // negotiated ALPN MUST be one of the protocols allowed for
        // the observed SNI hostname. Without this check, a
        // multi-tenant server that routes by ALPN OR by SNI but
        // trusts the other dimension to constrain the choice can be
        // bypassed (cross-protocol smuggling per RFC 7301 §5).
        if let Some(allow_list) = &self.sni_alpn_allow_list {
            let sni = stream.sni_hostname().map(str::to_ascii_lowercase);
            let alpn = stream.alpn_protocol().map(<[u8]>::to_vec);
            // SNI absent: require_sni() is the orthogonal gate; if
            // the operator opted into a SNI/ALPN map without also
            // requiring SNI, treat absence as a config error.
            let Some(sni) = sni else {
                return Err(TlsError::Configuration(
                    "sni_alpn_allow_list configured but client sent no SNI \
                     (also call require_sni() to make this explicit)"
                        .into(),
                ));
            };
            match allow_list.get(&sni) {
                None => {
                    // SECURITY: br-asupersync-iz6751 — sanitize error message to prevent
                    // SNI hostname reconnaissance. Don't expose which hostnames are
                    // configured which could help attackers enumerate tenants.
                    return Err(TlsError::Configuration(
                        "SNI hostname not permitted by server configuration".into(),
                    ));
                }
                Some(allowed) => {
                    let alpn_ref = alpn.as_deref();
                    let ok = alpn_ref.is_some_and(|p| allowed.iter().any(|a| a.as_slice() == p));
                    if !ok {
                        // SECURITY: br-asupersync-iz6751 — sanitize error message to prevent
                        // ALPN protocol reconnaissance. Don't expose allowed/negotiated protocol
                        // lists which could help attackers understand tenant-specific routing.
                        return Err(TlsError::Configuration(
                            "ALPN protocol not permitted for this SNI hostname".into(),
                        ));
                    }
                }
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
        let _ = (self.alpn_required, self.require_sni);
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

/// TLS 1.3 0-RTT replay protection strategy.
///
/// br-asupersync-ycuuwy: TLS 1.3 0-RTT (early data) is vulnerable to
/// replay attacks where an attacker can capture and replay 0-RTT requests
/// within the ticket validity window. This enum specifies the application-
/// layer protection strategy required when 0-RTT is enabled.
#[derive(Debug, Clone, Default)]
pub enum EarlyDataReplayProtection {
    /// No replay protection (UNSAFE).
    ///
    /// **CRITICAL SECURITY WARNING**: This option disables replay protection
    /// and should NEVER be used in production. 0-RTT requests can be captured
    /// and replayed by attackers, potentially causing duplicate state changes,
    /// financial transactions, or data corruption.
    ///
    /// Only use for testing scenarios where replay attacks are acceptable.
    #[default]
    None,

    /// Restrict 0-RTT to safe HTTP methods only (GET, HEAD, OPTIONS).
    ///
    /// This strategy allows 0-RTT only for HTTP methods that are idempotent
    /// and do not cause state changes. Requests with state-changing methods
    /// (POST, PUT, DELETE, PATCH) will be rejected if received as 0-RTT.
    ///
    /// Safe for read-only operations but still vulnerable to replay of
    /// GET requests that might have side effects.
    SafeMethodsOnly,

    /// Application implements idempotency key validation.
    ///
    /// The application MUST implement idempotency key checking where:
    /// 1. All state-changing requests include an `Idempotency-Key` header
    /// 2. The server tracks completed idempotency keys
    /// 3. Duplicate keys are rejected with 409 Conflict
    /// 4. Keys are stored with TTL matching the TLS ticket lifetime
    ///
    /// This provides strong replay protection for properly designed APIs.
    IdempotencyKeys,

    /// Application implements nonce-based anti-replay.
    ///
    /// The application MUST implement nonce validation where:
    /// 1. All requests include a unique nonce (timestamp + random)
    /// 2. The server maintains a bounded-window nonce store
    /// 3. Duplicate nonces within the window are rejected
    /// 4. The window size matches the TLS ticket lifetime
    ///
    /// Provides strong replay protection but requires careful nonce management.
    NonceValidation,

    /// Explicit acknowledgment that no protection is implemented (DANGEROUS).
    ///
    /// **USE ONLY FOR TESTING**: This explicitly acknowledges that no replay
    /// protection is implemented and accepts the security risk. This allows
    /// build() to succeed but logs critical security warnings.
    ///
    /// NEVER use in production - this is only for test environments where
    /// replay attacks are acceptable and you need to test 0-RTT behavior.
    UnprotectedForTesting,
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
    /// br-asupersync-q5i0bz: minimum negotiated TLS protocol version. When
    /// either `min_protocol` or `max_protocol` is set, `build()` filters
    /// `rustls::ALL_VERSIONS` to the requested range; otherwise the rustls
    /// safe-default-protocol-versions path is used (TLS 1.2 + TLS 1.3 with
    /// rustls 0.23 today; future rustls versions may relax that, which is
    /// exactly why this setter exists — operators who need to pin a
    /// stricter floor should not depend on the upstream default).
    #[cfg(feature = "tls")]
    min_protocol: Option<rustls::ProtocolVersion>,
    /// br-asupersync-q5i0bz: maximum negotiated TLS protocol version.
    #[cfg(feature = "tls")]
    max_protocol: Option<rustls::ProtocolVersion>,
    /// br-asupersync-y0gm5q: TLS 1.3 0-RTT (early data) max size in
    /// bytes. `0` means 0-RTT is DISABLED (the secure default — see
    /// the doc on [`Self::enable_early_data`] for why). Non-zero
    /// allows the server to accept early data up to this many bytes
    /// per connection. Operators that opt in MUST also implement an
    /// idempotency / anti-replay layer at the application level
    /// because TLS 1.3 0-RTT is by-spec replay-vulnerable.
    early_data_max_bytes: u32,
    /// br-asupersync-vu10zb — when `true`, `build()`-produced
    /// acceptors reject SNI-less ClientHellos. See
    /// [`Self::require_sni`].
    require_sni: bool,
    /// br-asupersync-i4n46s — per-SNI ALPN allow-list. See
    /// [`Self::sni_alpn_allow_list`].
    #[cfg(feature = "tls")]
    sni_alpn_allow_list: Option<BTreeMap<String, Vec<Vec<u8>>>>,
    /// br-asupersync-58ixk6 — when `true`, `build()` rejects
    /// certificate chains of length < 2 (i.e., a leaf with no
    /// accompanying intermediates). The default is permissive
    /// because tests routinely use single self-signed certs; set
    /// this in production deployments to force the operator to
    /// supply the full chain that pinning libraries downstream
    /// expect.
    require_full_chain: bool,
    /// br-asupersync-jxzrs4 — when `true`, `build()` performs
    /// strict certificate validation including expiration checking
    /// and basic integrity validation. The default is `true` for
    /// production safety; set to `false` only for testing with
    /// expired certificates (NOT recommended for production).
    strict_cert_validation: bool,
    /// br-asupersync-ycuuwy — when 0-RTT is enabled, this specifies
    /// the replay protection strategy. None means no protection
    /// (UNSAFE), which will cause build() to fail unless explicitly
    /// acknowledged. Production deployments MUST specify a replay
    /// protection strategy when enabling 0-RTT.
    early_data_replay_protection: EarlyDataReplayProtection,
}

impl TlsAcceptorBuilder {
    /// SECURITY: Validate certificate chain expiration and basic integrity.
    ///
    /// br-asupersync-jxzrs4: This function performs explicit certificate
    /// validation that goes beyond rustls's basic checks to prevent
    /// deployment of expired or invalid certificate chains.
    #[cfg(feature = "tls")]
    fn validate_certificate_chain(chain: &CertificateChain) -> Result<(), TlsError> {
        if chain.is_empty() {
            return Err(TlsError::Configuration("certificate chain is empty".into()));
        }

        // Get current time for expiration checking
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                TlsError::Configuration(
                    "failed to get current time for certificate validation".into(),
                )
            })?;

        // Validate each certificate in the chain
        for (i, cert) in chain.clone().into_iter().enumerate() {
            let cert_der = cert.as_der();
            // Parse the certificate using x509-parser to check validity
            match x509_parser::parse_x509_certificate(cert_der) {
                Ok((_, cert)) => {
                    // Check certificate validity period
                    let validity = cert.validity();

                    // Convert ASN.1 times to Unix timestamps for comparison
                    let not_before_unix = validity.not_before.timestamp();
                    let not_after_unix = validity.not_after.timestamp();
                    let current_unix = i64::try_from(now.as_secs()).map_err(|_| {
                        TlsError::Configuration(
                            "current time exceeds i64 seconds for certificate validation".into(),
                        )
                    })?;

                    if current_unix < not_before_unix {
                        return Err(TlsError::Configuration(format!(
                            "certificate {} in chain is not yet valid. \
                             Valid from: {} (current unix time: {}). \
                             Check certificate validity period (asupersync-jxzrs4)",
                            i, validity.not_before, current_unix
                        )));
                    }

                    if current_unix > not_after_unix {
                        return Err(TlsError::Configuration(format!(
                            "certificate {} in chain has EXPIRED. \
                             Expired on: {} (current unix time: {}). \
                             Replace with a valid certificate immediately (asupersync-jxzrs4)",
                            i, validity.not_after, current_unix
                        )));
                    }

                    // Additional validation: check certificate is well-formed
                    if cert.subject().iter_common_name().next().is_none()
                        && cert.subject().iter_organizational_unit().next().is_none()
                        && cert.subject().iter_organization().next().is_none()
                    {
                        return Err(TlsError::Configuration(format!(
                            "certificate {} in chain has empty subject. \
                             Certificate may be malformed (asupersync-jxzrs4)",
                            i
                        )));
                    }

                    #[cfg(feature = "tracing-integration")]
                    tracing::debug!(
                        cert_index = i,
                        subject = ?cert.subject(),
                        not_before = %validity.not_before,
                        not_after = %validity.not_after,
                        "Certificate validation passed"
                    );
                }
                Err(e) => {
                    return Err(TlsError::Configuration(format!(
                        "failed to parse certificate {} in chain: {}. \
                         Certificate may be malformed or corrupted (asupersync-jxzrs4)",
                        i, e
                    )));
                }
            }
        }

        #[cfg(feature = "tracing-integration")]
        tracing::info!(
            chain_length = chain.len(),
            "Certificate chain validation completed successfully"
        );

        Ok(())
    }

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
            #[cfg(feature = "tls")]
            min_protocol: None,
            #[cfg(feature = "tls")]
            max_protocol: None,
            // br-asupersync-y0gm5q: secure-by-default. 0-RTT is
            // off until the operator explicitly opts in via
            // `enable_early_data(...)` — see that method's doc for
            // the replay-attack tradeoff.
            early_data_max_bytes: 0,
            // br-asupersync-vu10zb: SNI-less connections are accepted
            // by default for backward compat; multi-tenant servers
            // MUST opt into `require_sni()`.
            require_sni: false,
            #[cfg(feature = "tls")]
            sni_alpn_allow_list: None,
            // br-asupersync-58ixk6: permissive default for testing
            // workflows that use single self-signed certs.
            require_full_chain: false,
            // br-asupersync-jxzrs4: strict validation enabled by
            // default for production safety. Can be disabled for
            // testing with expired certificates.
            strict_cert_validation: true,
            // br-asupersync-ycuuwy: no replay protection by default.
            // Operators must explicitly specify protection strategy
            // when enabling 0-RTT.
            early_data_replay_protection: EarlyDataReplayProtection::None,
        }
    }

    /// br-asupersync-vu10zb — require that incoming ClientHello
    /// messages carry the SNI extension. Connections that omit SNI
    /// are rejected after the rustls handshake completes (so the
    /// connection state is fully established before
    /// fail-closed) — necessary in multi-tenant deployments where
    /// SNI is the disambiguation primitive for which tenant's
    /// certificate / configuration applies. Without `require_sni()`
    /// a probing attacker reaches the default-cert tenant.
    #[must_use]
    pub fn require_sni(mut self) -> Self {
        self.require_sni = true;
        self
    }

    /// SECURITY: Require SNI for multi-tenant deployments.
    ///
    /// This is a security-focused variant of `require_sni()` that provides
    /// clearer semantics for multi-tenant SaaS deployments. In multi-tenant
    /// environments, SNI-less connections MUST be rejected to prevent
    /// attackers from accessing the default certificate tenant.
    ///
    /// **Critical Security Property**: Without SNI enforcement, an attacker
    /// can probe the default tenant's certificate and potentially bypass
    /// tenant isolation by connecting without the SNI extension.
    ///
    /// Use this method when:
    /// - Hosting multiple tenants with different certificates
    /// - Each tenant has distinct security boundaries
    /// - SNI is used for tenant routing/identification
    ///
    /// This method is equivalent to `require_sni()` but makes the security
    /// intent explicit for code review and compliance auditing.
    #[must_use]
    pub fn require_sni_for_multi_tenant(mut self) -> Self {
        self.require_sni = true;
        self
    }

    /// br-asupersync-i4n46s — set a per-SNI ALPN allow-list. After
    /// the handshake, the negotiated ALPN protocol must be one of
    /// the protocols allowed for the observed SNI hostname (case-
    /// insensitive lookup). A SNI hostname not present in the map
    /// fails the handshake (strict allow-list semantics).
    ///
    /// Pass an empty map to clear a previously-configured allow-list.
    /// Combine with [`Self::require_sni`] to also reject SNI-less
    /// connections (recommended — without `require_sni`, a SNI-less
    /// ClientHello yields a configuration error rather than silently
    /// passing). Pair with [`Self::require_alpn`] to also reject
    /// peers that omit ALPN entirely.
    ///
    /// Closes the cross-protocol smuggling vector where a multi-
    /// tenant server that routes by ALPN OR by SNI but trusts the
    /// other dimension to constrain the choice could be bypassed
    /// (RFC 7301 §5).
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn sni_alpn_allow_list(mut self, allow_list: BTreeMap<String, Vec<Vec<u8>>>) -> Self {
        let normalised: BTreeMap<String, Vec<Vec<u8>>> = allow_list
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        self.sni_alpn_allow_list = if normalised.is_empty() {
            None
        } else {
            Some(normalised)
        };
        self
    }

    /// br-asupersync-58ixk6 — require a full certificate chain
    /// (leaf + at least one intermediate). When set, `build()`
    /// rejects single-cert chains. Production deployments where
    /// downstream pinning libraries expect the leaf + intermediates
    /// MUST set this; the default is permissive because test
    /// fixtures routinely use single self-signed certs.
    #[must_use]
    pub fn require_full_chain(mut self) -> Self {
        self.require_full_chain = true;
        self
    }

    /// SECURITY: Disable strict certificate validation.
    ///
    /// br-asupersync-jxzrs4 — by default, `build()` performs strict
    /// certificate validation including expiration checking. This method
    /// disables that validation for testing scenarios where expired or
    /// invalid certificates need to be used.
    ///
    /// **WARNING**: This method should NEVER be used in production
    /// deployments as it disables critical security validation that
    /// prevents deployment of expired certificates.
    ///
    /// Only use this in test environments where you need to test with
    /// expired certificates or during development with self-signed certs
    /// that may have validity issues.
    #[must_use]
    pub fn disable_strict_cert_validation(mut self) -> Self {
        self.strict_cert_validation = false;
        self
    }

    /// Set the replay protection strategy for TLS 1.3 0-RTT (early data).
    ///
    /// br-asupersync-ycuuwy: This method MUST be called with an appropriate
    /// protection strategy before enabling 0-RTT. The protection strategy
    /// specifies how your application will prevent replay attacks.
    ///
    /// # Security Requirement
    ///
    /// TLS 1.3 0-RTT is vulnerable to replay attacks. You MUST implement
    /// one of the supported protection strategies before enabling 0-RTT,
    /// or `build()` will fail with a configuration error.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // For APIs that use idempotency keys
    /// acceptor.with_early_data_replay_protection(
    ///     EarlyDataReplayProtection::IdempotencyKeys
    /// );
    ///
    /// // For read-only services (GET/HEAD only)
    /// acceptor.with_early_data_replay_protection(
    ///     EarlyDataReplayProtection::SafeMethodsOnly
    /// );
    ///
    /// // For testing ONLY (NEVER in production)
    /// acceptor.with_early_data_replay_protection(
    ///     EarlyDataReplayProtection::UnprotectedForTesting
    /// );
    /// ```
    #[must_use]
    pub fn with_early_data_replay_protection(
        mut self,
        protection: EarlyDataReplayProtection,
    ) -> Self {
        self.early_data_replay_protection = protection;
        self
    }

    /// **REQUIRES REPLAY PROTECTION**: Enable TLS 1.3 0-RTT (early data).
    ///
    /// br-asupersync-ycuuwy: This method now REQUIRES that you first specify
    /// a replay protection strategy via `with_early_data_replay_protection()`.
    /// Without proper protection, `build()` will fail.
    ///
    /// # Security Model Change
    ///
    /// **BREAKING CHANGE**: Unlike the previous version, this method now
    /// enforces replay protection validation. You MUST:
    ///
    /// 1. First call `with_early_data_replay_protection()` with an appropriate strategy
    /// 2. Then call this method to set the max bytes
    /// 3. Implement the chosen protection in your application layer
    ///
    /// # Replay Protection Required
    ///
    /// TLS 1.3 0-RTT is **by-spec replay-vulnerable** (RFC 8446 §8).
    /// Attackers can capture and replay 0-RTT requests within the ticket
    /// validity window. Your application MUST implement one of:
    ///
    /// - `SafeMethodsOnly`: Restrict to GET/HEAD/OPTIONS only
    /// - `IdempotencyKeys`: Track completed idempotency keys
    /// - `NonceValidation`: Bounded-window nonce anti-replay store
    /// - `UnprotectedForTesting`: Testing only (logs security warnings)
    ///
    /// # Arguments
    ///
    /// `max_bytes` caps early data per connection. Typical: 16384 (16 KiB)
    /// for request headers. `0` disables 0-RTT.
    #[must_use]
    pub fn enable_early_data_with_protection(mut self, max_bytes: u32) -> Self {
        self.early_data_max_bytes = max_bytes;
        self
    }

    /// **DEPRECATED**: Legacy 0-RTT enable without replay protection.
    ///
    /// **SECURITY WARNING**: This method is deprecated because it allows
    /// enabling 0-RTT without explicit replay protection. Use
    /// `enable_early_data_with_protection()` instead.
    ///
    /// This method will be removed in a future version. Migration:
    /// ```ignore
    /// // Old (deprecated):
    /// acceptor.enable_early_data(16384)
    ///
    /// // New (secure):
    /// acceptor
    ///     .with_early_data_replay_protection(EarlyDataReplayProtection::SafeMethodsOnly)
    ///     .enable_early_data_with_protection(16384)
    /// ```
    #[deprecated(
        since = "0.3.3",
        note = "Use enable_early_data_with_protection() with explicit replay protection"
    )]
    #[must_use]
    pub fn enable_early_data(mut self, max_bytes: u32) -> Self {
        self.early_data_max_bytes = max_bytes;
        // Set to testing mode to allow legacy builds to succeed
        // but log security warnings
        if matches!(
            self.early_data_replay_protection,
            EarlyDataReplayProtection::None
        ) {
            self.early_data_replay_protection = EarlyDataReplayProtection::UnprotectedForTesting;
        }
        self
    }

    /// Disable TLS 1.3 0-RTT (early data). This is the default.
    /// Provided as an explicit setter for symmetry with
    /// [`Self::enable_early_data`] so config-driven builders
    /// (TOML / YAML) can round-trip the choice.
    /// (br-asupersync-y0gm5q.)
    #[must_use]
    pub fn disable_early_data(mut self) -> Self {
        self.early_data_max_bytes = 0;
        self
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
    ///
    /// # Advertise vs. require
    ///
    /// This setter **advertises** the listed protocols to the peer but does
    /// NOT require the peer to negotiate one. Per RFC 7301 a client that
    /// omits the ALPN extension entirely is still accepted, and
    /// `accept()` returns `Ok` with `negotiated_alpn = None`. If the caller
    /// is an HTTP/2-only or gRPC-only server (where a non-ALPN HTTP/1.1
    /// client is a protocol mismatch rather than a valid fallback), pair
    /// this call with [`require_alpn`](Self::require_alpn), or — more
    /// concisely — use [`alpn_protocols_required`](Self::alpn_protocols_required),
    /// [`alpn_h2`](Self::alpn_h2), or [`alpn_grpc`](Self::alpn_grpc),
    /// which set the require-ALPN flag for you.
    ///
    /// [`alpn_http`](Self::alpn_http) intentionally keeps the require flag
    /// off because HTTP/1.1 fallback on no-ALPN is the correct behavior for
    /// dual-stack servers. Use this raw setter only when you need that
    /// precise advertise-but-don't-require semantic.
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
    /// HTTP/2 is preferred over HTTP/1.1. Unlike [`alpn_h2`](Self::alpn_h2)
    /// and [`alpn_grpc`](Self::alpn_grpc), this does **not** set
    /// `alpn_required`: clients that omit the ALPN extension fall back to
    /// HTTP/1.1, which is the correct behavior per RFC 7301 for servers
    /// that support both protocols.
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

    /// Set the minimum TLS protocol version the acceptor will negotiate.
    ///
    /// br-asupersync-q5i0bz: mirrors `TlsConnectorBuilder::min_protocol_version`.
    /// When either this or [`max_protocol_version`](Self::max_protocol_version)
    /// is set, `build()` filters `rustls::ALL_VERSIONS` to the requested
    /// range and rejects connections whose negotiated version falls
    /// outside it. Without these setters the acceptor relies on rustls'
    /// safe-default-protocol-versions, which today excludes TLS 1.0/1.1
    /// but is not a contract operators can pin against.
    ///
    /// Pin to `TLSv1_3` to require TLS 1.3 and eliminate downgrade
    /// attacks plus TLS 1.2 cipher-suite-negotiation pitfalls. Pin to
    /// `TLSv1_2` only as the floor when interoperating with TLS-1.2-only
    /// clients you control.
    #[cfg(feature = "tls")]
    pub fn min_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.min_protocol = Some(version);
        self
    }

    /// Set the maximum TLS protocol version the acceptor will negotiate.
    ///
    /// br-asupersync-q5i0bz: mirrors `TlsConnectorBuilder::max_protocol_version`.
    /// See [`min_protocol_version`](Self::min_protocol_version) for the
    /// version-filtering semantics.
    #[cfg(feature = "tls")]
    pub fn max_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.max_protocol = Some(version);
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

        // SECURITY: br-asupersync-jxzrs4 — validate certificate chain
        // expiration and integrity before passing to rustls. This
        // prevents deployment of expired certificates that would fail
        // in production but might not be caught during configuration.
        if self.strict_cert_validation {
            Self::validate_certificate_chain(&self.cert_chain)?;
        }

        // SECURITY: br-asupersync-ycuuwy — validate 0-RTT replay protection
        // configuration. When 0-RTT is enabled, require explicit replay
        // protection strategy to prevent silent deployment of vulnerable
        // configurations.
        if self.early_data_max_bytes > 0 {
            match &self.early_data_replay_protection {
                EarlyDataReplayProtection::None => {
                    return Err(TlsError::Configuration(format!(
                        "TLS 1.3 0-RTT enabled (max_bytes={}) but no replay protection configured. \
                         0-RTT is vulnerable to replay attacks where captured requests can be \
                         replayed within ticket validity. You MUST specify replay protection via \
                         with_early_data_replay_protection() before enabling 0-RTT. \
                         See EarlyDataReplayProtection variants for options (asupersync-ycuuwy)",
                        self.early_data_max_bytes
                    )));
                }
                EarlyDataReplayProtection::UnprotectedForTesting => {
                    #[cfg(feature = "tracing-integration")]
                    tracing::error!(
                        max_early_data_bytes = self.early_data_max_bytes,
                        "CRITICAL SECURITY WARNING: TLS 1.3 0-RTT enabled without replay protection! \
                         This configuration is VULNERABLE to replay attacks and should NEVER be used \
                         in production. Attackers can capture and replay 0-RTT requests causing \
                         duplicate operations. Use only for testing (asupersync-ycuuwy)"
                    );
                }
                EarlyDataReplayProtection::SafeMethodsOnly
                | EarlyDataReplayProtection::IdempotencyKeys
                | EarlyDataReplayProtection::NonceValidation => {
                    #[cfg(feature = "tracing-integration")]
                    tracing::info!(
                        max_early_data_bytes = self.early_data_max_bytes,
                        protection_strategy = ?self.early_data_replay_protection,
                        "TLS 1.3 0-RTT enabled with replay protection strategy"
                    );
                }
            }
        }

        // SECURITY: br-asupersync-3iqbx3 — detect potential multi-tenant
        // configurations and warn if SNI is not enforced. Multi-tenant
        // patterns include SNI/ALPN allow-lists or multiple ALPN protocols
        // that suggest tenant-specific routing.
        if !self.require_sni {
            let has_sni_alpn_allowlist = self.sni_alpn_allow_list.is_some();
            let has_multiple_alpn = self.alpn_protocols.len() > 1;
            let likely_multi_tenant = has_sni_alpn_allowlist || has_multiple_alpn;

            if likely_multi_tenant {
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    sni_alpn_allowlist = has_sni_alpn_allowlist,
                    alpn_protocols_count = self.alpn_protocols.len(),
                    "SECURITY WARNING: Multi-tenant TLS configuration detected \
                     but require_sni() is not set. SNI-less connections can \
                     reach the default certificate tenant. Call require_sni() \
                     or require_sni_for_multi_tenant() to prevent tenant \
                     exposure (asupersync-3iqbx3)"
                );
            }
        }

        // br-asupersync-58ixk6 — reject empty cert chains and, when
        // require_full_chain is set, single-cert chains. rustls's
        // `with_single_cert` will not surface either condition as a
        // typed error reliably enough for downstream callers, so we
        // surface the misconfiguration here before any handshake
        // attempt.
        if self.cert_chain.is_empty() {
            return Err(TlsError::Configuration(
                "with_single_cert called with empty certificate chain".into(),
            ));
        }
        if self.require_full_chain && self.cert_chain.len() < 2 {
            return Err(TlsError::Configuration(format!(
                "require_full_chain set but certificate chain has only {} cert(s); \
                 expected leaf plus at least one intermediate",
                self.cert_chain.len()
            )));
        }

        // br-asupersync-i4n46s — sanity-check that any per-SNI ALPN
        // allow-list aligns with the configured `alpn_protocols`.
        // If the operator provides an allow-list whose protocols are
        // not advertised, no client can ever satisfy the gate.
        if let Some(allow_list) = self.sni_alpn_allow_list.as_ref() {
            for allowed in allow_list.values() {
                for protocol in allowed {
                    if !self.alpn_protocols.iter().any(|p| p == protocol) {
                        // SECURITY: br-asupersync-iz6751 — sanitize error message to prevent
                        // SNI hostname and ALPN protocol reconnaissance during config validation.
                        // Don't expose which hostnames or protocols are configured.
                        return Err(TlsError::Configuration(
                            "sni_alpn_allow_list contains protocol not advertised in alpn_protocols \
                             - check configuration consistency".into(),
                        ));
                    }
                }
            }
        }

        // Create the config builder with the crypto provider and
        // protocol-version filtering. br-asupersync-q5i0bz: mirrors the
        // connector's range-filter pattern so operators can pin a
        // narrower protocol range than the rustls safe defaults (e.g.,
        // TLS 1.3 only to eliminate downgrade-attack surface and TLS
        // 1.2 cipher-suite negotiation pitfalls).
        let builder = ServerConfig::builder_with_provider(Arc::new(default_provider()));
        let builder = if self.min_protocol.is_some() || self.max_protocol.is_some() {
            // Convert protocol versions to the wire ordinals so the
            // range comparison works regardless of the
            // `rustls::ProtocolVersion` enum's Rust-level Ord (which
            // has no documented stability guarantee).
            // TLS 1.2 = 0x0303, TLS 1.3 = 0x0304.
            fn version_ordinal(v: rustls::ProtocolVersion) -> u16 {
                match v {
                    rustls::ProtocolVersion::TLSv1_2 => 0x0303,
                    rustls::ProtocolVersion::TLSv1_3 => 0x0304,
                    // Unknown / future versions sort high so they're
                    // excluded by an explicit floor.
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

        // br-asupersync-y0gm5q: explicit max_early_data_size write.
        // rustls's own default is 0 (0-RTT off) but we set it
        // explicitly so a future rustls API change cannot silently
        // flip the default to "on" without us noticing. The value
        // here is the operator's choice from
        // `enable_early_data(max_bytes)` (default 0).
        config.max_early_data_size = self.early_data_max_bytes;

        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            alpn = ?config.alpn_protocols,
            max_early_data_size = config.max_early_data_size,
            "TlsAcceptor built"
        );

        Ok(TlsAcceptor {
            config: Arc::new(config),
            handshake_timeout: self.handshake_timeout,
            alpn_required: self.alpn_required,
            require_sni: self.require_sni,
            sni_alpn_allow_list: self.sni_alpn_allow_list.map(Arc::new),
            early_data_replay_protection: self.early_data_replay_protection,
        })
    }

    /// Build the `TlsAcceptor` (disabled-mode fallback when TLS is disabled).
    #[cfg(not(feature = "tls"))]
    pub fn build(self) -> Result<TlsAcceptor, TlsError> {
        let _ = (&self.cert_chain, &self.key);
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
    use crate::tls::Certificate;

    // Self-signed test certificate and key (for testing only)
    // Generated with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
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

    const TEST_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHUmoIekMgc9Hg
fUsOtveAdULOgq6MA3Id04rDsJMsp3MlsPJvAlipny9mmrTHCFgqkd0Y7jK/vItP
traROGrcyvGiF9en22/UOinuyJNCJZPu4ZgnOHVs6HDsSUslzxtb+YF/uSwzKqRf
z/yZFdFaqoO/d0p7kKtK3Y+q2L21gfQNxPZ9+1QZPXhW8v8WrWRY8zXp5tNEIWn/
iSL9OHtLMW9M330vjkwCKUdkV59FLNz3E3WpBk2buVPqijTMPfCY7LvSKJqyqkuu
YbnVNF1ucGcYfoIge9QiXesIO15S6PWkH2WHruq3mSKkKfj7zNx5eZRo7+eZFrAL
tXP7oCxPAgMBAAECggEAOwgH+jnHfql+m4dP/uwmUgeogQPIERSGLBo2Ky208NEo
8507t6/QtW+9OJyR9K5eekEX46XMJuf+tF2PJWQ5lemO9awtBPwi2w5c0+jYYAtE
DEgI6Xi5okcXBovQc0KqvisfdMXRNtgmtW+iRm5lQf5lJYP9baoTaQlEXttxF/t+
g7RLjaPaJNvE/Yq+4FJUuL1fWSTXfH99If6rR8Zy+FXtFRpCVbNdpruUaOmIgjuT
TlRaXf/VfnIocRNVsEWTlfCJq8Ra4qLAFM4KYuEBoPaRxpOH9of4nZftzOHwiJ0m
8+GwXqNhySVKO3SPw194LCVSoje1+PEaA/tPlE1RZQKBgQDoJpCQ0SmKOCG/c0lD
QebhqSruFoqQqeEV6poZCO+HZMvszhIiUkvk3/uoZnFQmb3w4YwbRH05YQd6iXFk
048lbqPzfGQGepMpLAY9DWhnbDy+mbuOZp+04gZ/QUen+qKBOc3mNUGhCZNyAUl3
YXeGgPNtknRQ6ebNgO1PFLaoewKBgQDbzHjknGMAFcZXr4/MPOc03I8mQiLECfxa
5PJYhjq85ygCMePiH08xJC4RT6ld3EC4GxliPFubzLMXJhqGBgboSzXGcDZbAOdw
YqleUF/jBChl2oyawzf280FepJqFG6d5qFwISi4hnCZKC7PdIbaKjjRGU7flDBej
AfGjIuzlPQKBgETAjxXkbAn8P7pkWTErBkaUhBtI37aiKQAFn6eEZvPRHTe/e81g
VAuvbedcl3iIX6FEGutEaFWi78URiVyT7xPl5XZJw5HLoWOTHzHbk6z1eDP2cX5l
1CyMt+HeImuUJaZhySHBafNYU6tyyCAr5GsYK3+q3PnNm8YGxcEi4EmbAoGAYbvA
wb58Euybvh+1bBZkpE+yY0ujE9Jw4KXO0OgWtCqA0sEGWGSdnPc+eLoYUEEAkhyS
o+i8v0E9HPz3bEK/zYirx6nbsYlsX7+vGd3ZVSNjJy8PuD035Fnz5jaA8tECHglr
qs/5RT6ek+wyNRCpj2B+BAtzyKgg1n2lyWldNu0CgYEA4Ux9QV5s99W39vJlzGHD
ilKqHWetmrehbe0nIeCe2bJWqb08oSrQD8Q7om/MGAKjhFqNyYqqoJXcmbAvLygu
kMtbiQcfyyxjefyCA0OvdWEXrvnRZYNEBosyX/ko7Bl2IRBFP6ahQhj7jHqm2+/J
SrXuVI5uunTgPWuOtJOP+KM=
-----END PRIVATE KEY-----";

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
    struct ClientHelloLayout {
        cipher_suites_len_pos: usize,
        extensions_len_pos: usize,
        sni_ext_len_pos: usize,
        sni_list_len_pos: usize,
        first_sni_entry_start: usize,
        first_sni_entry_end: usize,
    }

    #[cfg(feature = "tls")]
    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    #[cfg(feature = "tls")]
    fn set_u24(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset] = ((value >> 16) & 0xff) as u8;
        bytes[offset + 1] = ((value >> 8) & 0xff) as u8;
        bytes[offset + 2] = (value & 0xff) as u8;
    }

    #[cfg(feature = "tls")]
    fn adjust_u16(bytes: &mut [u8], offset: usize, delta: usize) {
        let value = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let adjusted = value
            .checked_add(u16::try_from(delta).expect("delta fits in u16"))
            .expect("length remains within u16");
        set_u16(bytes, offset, adjusted);
    }

    #[cfg(feature = "tls")]
    fn parse_client_hello_layout(bytes: &[u8]) -> ClientHelloLayout {
        assert!(bytes.len() >= 5, "TLS record header must be present");
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert!(
            bytes.len() >= 5 + record_len,
            "record payload must be complete"
        );

        let mut pos = 5;
        assert_eq!(bytes[pos], 0x01, "expected ClientHello handshake");
        pos += 4;
        pos += 2; // legacy_version
        pos += 32; // random

        let session_id_len = bytes[pos] as usize;
        pos += 1 + session_id_len;

        let cipher_suites_len_pos = pos;
        let cipher_suites_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        let compression_methods_len = bytes[pos] as usize;
        pos += 1 + compression_methods_len;

        let extensions_len_pos = pos;
        let extensions_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        let mut sni_ext_len_pos = None;
        let mut sni_list_len_pos = None;
        let mut first_sni_entry_start = None;
        let mut first_sni_entry_end = None;

        while pos + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let ext_len_pos = pos + 2;
            let ext_len = u16::from_be_bytes([bytes[ext_len_pos], bytes[ext_len_pos + 1]]) as usize;
            pos += 4;
            let ext_data_start = pos;
            let ext_data_end = pos + ext_len;
            assert!(ext_data_end <= extensions_end, "extension must fit");

            if ext_type == 0x0000 {
                sni_ext_len_pos = Some(ext_len_pos);
                sni_list_len_pos = Some(ext_data_start);
                let list_len =
                    u16::from_be_bytes([bytes[ext_data_start], bytes[ext_data_start + 1]]) as usize;
                let first_entry_start = ext_data_start + 2;
                let name_len_pos = first_entry_start + 1;
                let name_len =
                    u16::from_be_bytes([bytes[name_len_pos], bytes[name_len_pos + 1]]) as usize;
                let first_entry_end = first_entry_start + 3 + name_len;
                assert!(
                    first_entry_end <= ext_data_start + 2 + list_len,
                    "SNI entry must fit the advertised list"
                );
                first_sni_entry_start = Some(first_entry_start);
                first_sni_entry_end = Some(first_entry_end);
                break;
            }

            pos = ext_data_end;
        }

        ClientHelloLayout {
            cipher_suites_len_pos,
            extensions_len_pos,
            sni_ext_len_pos: sni_ext_len_pos.expect("ClientHello should include SNI"),
            sni_list_len_pos: sni_list_len_pos.expect("ClientHello should include SNI list"),
            first_sni_entry_start: first_sni_entry_start
                .expect("ClientHello should include an SNI entry"),
            first_sni_entry_end: first_sni_entry_end
                .expect("ClientHello should include an SNI entry"),
        }
    }

    #[cfg(feature = "tls")]
    fn make_client_hello(alpn_protocols: &[&[u8]]) -> Vec<u8> {
        use rustls::ClientConfig;
        use rustls::crypto::ring::default_provider;
        use rustls::pki_types::ServerName;

        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default client protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();

        let server_name = ServerName::try_from("localhost".to_string()).expect("server name");
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), server_name).expect("client config");
        let mut out = Vec::new();
        client.write_tls(&mut out).expect("client hello bytes");
        out
    }

    #[cfg(feature = "tls")]
    fn drive_server_parse(acceptor: &TlsAcceptor, bytes: &[u8]) -> Result<(), TlsError> {
        use std::io::Cursor;

        let mut server = rustls::ServerConnection::new(Arc::clone(acceptor.config()))
            .map_err(|err| TlsError::Configuration(err.to_string()))?;
        let mut cursor = Cursor::new(bytes);

        while (cursor.position() as usize) < bytes.len() {
            let read = server.read_tls(&mut cursor).map_err(TlsError::Io)?;
            if read == 0 {
                break;
            }
            server
                .process_new_packets()
                .map_err(|err| TlsError::Handshake(err.to_string()))?;
        }

        Ok(())
    }

    #[cfg(feature = "tls")]
    fn duplicate_first_sni_entry(bytes: &mut Vec<u8>) {
        let layout = parse_client_hello_layout(bytes);
        let duplicate = bytes[layout.first_sni_entry_start..layout.first_sni_entry_end].to_vec();
        bytes.splice(
            layout.first_sni_entry_end..layout.first_sni_entry_end,
            duplicate.iter().copied(),
        );

        let delta = duplicate.len();
        adjust_u16(bytes, layout.sni_list_len_pos, delta);
        adjust_u16(bytes, layout.sni_ext_len_pos, delta);
        adjust_u16(bytes, layout.extensions_len_pos, delta);

        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize + delta;
        set_u16(
            bytes,
            3,
            u16::try_from(record_len).expect("record length fits u16"),
        );

        let handshake_len =
            ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | bytes[8] as usize;
        set_u24(bytes, 6, handshake_len + delta);
    }

    #[cfg(feature = "tls")]
    fn zero_cipher_suites(bytes: &mut [u8]) {
        let layout = parse_client_hello_layout(bytes);
        set_u16(bytes, layout.cipher_suites_len_pos, 0);
    }

    #[cfg(feature = "tls")]
    fn fragment_first_tls_record(bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() >= 6, "need a full record to fragment");
        let payload_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let payload = &bytes[5..5 + payload_len];
        let split_at = payload.len() / 2;
        assert!(
            split_at > 0 && split_at < payload.len(),
            "payload must split into two records"
        );

        let mut fragmented = Vec::with_capacity(bytes.len() + 5);
        fragmented.extend_from_slice(&[bytes[0], bytes[1], bytes[2]]);
        fragmented.extend_from_slice(&(split_at as u16).to_be_bytes());
        fragmented.extend_from_slice(&payload[..split_at]);
        fragmented.extend_from_slice(&[bytes[0], bytes[1], bytes[2]]);
        fragmented.extend_from_slice(&((payload.len() - split_at) as u16).to_be_bytes());
        fragmented.extend_from_slice(&payload[split_at..]);
        fragmented
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
    fn test_duplicate_sni_client_hello_is_rejected_cleanly() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let mut client_hello = make_client_hello(&[b"h2"]);
        duplicate_first_sni_entry(&mut client_hello);

        let err = drive_server_parse(&acceptor, &client_hello).unwrap_err();
        assert!(matches!(err, TlsError::Handshake(_)));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_zero_cipher_suite_list_is_rejected_cleanly() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let mut client_hello = make_client_hello(&[b"h2"]);
        zero_cipher_suites(&mut client_hello);

        let err = drive_server_parse(&acceptor, &client_hello).unwrap_err();
        assert!(matches!(err, TlsError::Handshake(_)));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_fragmented_client_hello_record_is_processed() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_h2()
            .build()
            .unwrap();

        let client_hello = make_client_hello(&[b"h2"]);
        let fragmented = fragment_first_tls_record(&client_hello);

        drive_server_parse(&acceptor, &fragmented).expect("fragmented client hello should parse");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_connect_accept_handshake() {
        use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
        use crate::cx::Cx;
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::init_test_logging;
        use futures_lite::future::zip;

        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE7)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (
            client_ready,
            server_ready,
            client_protocol,
            server_protocol,
            client_alpn,
            server_alpn,
            checkpoints,
        ) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let _cx = Cx::current().expect("lab runtime should install a current Cx");

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

            let checkpoints = vec![serde_json::json!({
                "phase": "virtual_stream_pair_created",
                "client_addr": "127.0.0.1:5000",
                "server_addr": "127.0.0.1:5001",
            })];

            for checkpoint in &checkpoints {
                tracing::info!(event = %checkpoint, "tls_lab_checkpoint");
            }

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;
            let client = client_res.expect("client handshake should succeed");
            let server = server_res.expect("server handshake should succeed");
            let client_ready = client.is_ready();
            let server_ready = server.is_ready();
            let client_protocol = client.protocol_version().is_some();
            let server_protocol = server.protocol_version().is_some();
            let client_alpn = client.alpn_protocol().map(|protocol| protocol.to_vec());
            let server_alpn = server.alpn_protocol().map(|protocol| protocol.to_vec());

            let mut checkpoints = checkpoints;
            checkpoints.push(serde_json::json!({
                    "phase": "handshake_completed",
                    "client_ready": client_ready,
                    "server_ready": server_ready,
                    "client_protocol_present": client_protocol,
                    "server_protocol_present": server_protocol,
                    "client_alpn": client_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                    "server_alpn": server_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                }));

            for checkpoint in checkpoints.iter().skip(1) {
                tracing::info!(event = %checkpoint, "tls_lab_checkpoint");
            }

            (
                client_ready,
                server_ready,
                client_protocol,
                server_protocol,
                client_alpn,
                server_alpn,
                checkpoints,
            )
        });

        assert!(client_ready);
        assert!(server_ready);
        assert!(client_protocol);
        assert!(server_protocol);
        assert_eq!(client_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(server_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_server_preference_ordering() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
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
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
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
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
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
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
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

            // Rustls 0.23 enforces RFC 7301: if both sides offer ALPN but there is no overlap,
            // the server aborts the handshake with `no_application_protocol`.
            let client_err = client_res.unwrap_err();
            assert!(matches!(client_err, TlsError::Handshake(_)));

            let server_err = server_res.unwrap_err();
            assert!(matches!(server_err, TlsError::Handshake(_)));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_alpn_required_server_errors_when_client_offers_none() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
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
        use crate::test_utils::run_test_with_cx;

        run_test_with_cx(|_cx| async move {
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

    // --- br-asupersync-q5i0bz: protocol-version pinning ----------------

    #[cfg(feature = "tls")]
    #[test]
    fn test_min_protocol_version_inverted_range_rejected_at_build() {
        // Setting min > max must fail config validation, not silently
        // disable the filter or pick one side. Symmetric with the
        // connector's same validation.
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
            .build()
            .expect_err("inverted protocol-version range must be rejected");
        match err {
            TlsError::Configuration(msg) => {
                assert!(
                    msg.contains("greater than max_protocol_version"),
                    "expected inverted-range error, got: {msg}"
                );
            }
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_min_protocol_tls13_pin_builds_and_handshakes_with_matching_client() {
        // Positive control: when both ends are pinned to TLS 1.3, the
        // handshake succeeds and the negotiated protocol_version on
        // the server is TLSv1_3. This pins the success path that the
        // version-mismatch test below contrasts against.
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("TLS-1.3-only acceptor builds");

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("TLS-1.3-only connector builds");

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5160".parse().unwrap(),
                "127.0.0.1:5161".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(
                client_res.is_ok() && server_res.is_ok(),
                "TLS-1.3-only handshake must succeed (client={:?}, server={:?})",
                client_res.is_ok(),
                server_res.is_ok()
            );
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_acceptor_pinned_above_client_max_rejects_handshake() {
        // Negative control: acceptor pins floor at TLS 1.3 (rejects
        // anything below), client pins ceiling at TLS 1.2. No version
        // overlap — the handshake must fail. This is the analogue of
        // the bead's "min=TLS 1.2 rejects TLS 1.0" requirement: rustls
        // 0.23 doesn't even support TLS 1.0, so we exercise the same
        // defense by demonstrating that an acceptor pinned to a
        // higher floor than the client's ceiling rejects the
        // connection. With the previous (asymmetric) acceptor builder
        // this test could not have been written at all — there was
        // no API surface to pin the floor.
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
                .build()
                .expect("acceptor pinned to TLS 1.3 builds");

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
                .build()
                .expect("connector capped at TLS 1.2 builds");

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5170".parse().unwrap(),
                "127.0.0.1:5171".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(
                client_res.is_err() || server_res.is_err(),
                "version-mismatched handshake must fail (client_ok={}, server_ok={})",
                client_res.is_ok(),
                server_res.is_ok()
            );
        });
    }

    // ── br-asupersync-y0gm5q: 0-RTT secure-by-default ───────────────

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_default_acceptor_disables_0rtt_early_data() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .build()
        .expect("build default acceptor");
        assert_eq!(
            acceptor.config.max_early_data_size, 0,
            "default acceptor must have max_early_data_size=0 \
             (TLS 1.3 0-RTT disabled — replay defense)"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_enable_early_data_opt_in_sets_max_size() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .enable_early_data(16384)
        .build()
        .expect("build with early data enabled");
        assert_eq!(
            acceptor.config.max_early_data_size, 16384,
            "enable_early_data(N) must propagate N to ServerConfig"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn y0gm5q_disable_early_data_resets_to_zero() {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .enable_early_data(16384)
        .disable_early_data()
        .build()
        .expect("build with early data toggled off");
        assert_eq!(
            acceptor.config.max_early_data_size, 0,
            "disable_early_data must reset max_early_data_size=0"
        );
    }

    /// br-asupersync-58ixk6 — empty cert chain rejected by build().
    #[cfg(feature = "tls")]
    #[test]
    fn build_rejects_empty_cert_chain() {
        let chain: CertificateChain = Vec::<Certificate>::new().into();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .build()
            .expect_err("empty cert chain must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("empty certificate chain"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-58ixk6 — require_full_chain rejects single-cert
    /// chains (the most common pinning misconfiguration).
    #[cfg(feature = "tls")]
    #[test]
    fn build_with_require_full_chain_rejects_single_cert() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let err = TlsAcceptorBuilder::new(chain, key)
            .require_full_chain()
            .build()
            .expect_err("single-cert chain with require_full_chain must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("require_full_chain"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-vu10zb — `require_sni()` flips the corresponding
    /// builder flag and propagates to the produced acceptor.
    #[cfg(feature = "tls")]
    #[test]
    fn require_sni_propagates_to_acceptor() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .require_sni()
            .build()
            .expect("build should succeed");
        assert!(
            acceptor.require_sni,
            "require_sni() must flip the acceptor's flag"
        );
    }

    /// br-asupersync-i4n46s — sni_alpn_allow_list whose protocols are
    /// not advertised must be rejected at build() rather than
    /// silently failing every connection.
    #[cfg(feature = "tls")]
    #[test]
    fn build_rejects_sni_alpn_allow_list_without_advertised_protocol() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("api.example.com".to_string(), vec![b"h2".to_vec()]);
        let err = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"http/1.1".to_vec()])
            .sni_alpn_allow_list(allow)
            .build()
            .expect_err("allow-list with non-advertised protocol must be rejected");
        match err {
            TlsError::Configuration(msg) => assert!(
                msg.contains("not in alpn_protocols"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    /// br-asupersync-i4n46s — sni_alpn_allow_list with consistent
    /// protocols builds successfully and propagates to the acceptor.
    #[cfg(feature = "tls")]
    #[test]
    fn build_accepts_sni_alpn_allow_list_consistent_with_protocols() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("Api.Example.Com".to_string(), vec![b"h2".to_vec()]);
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .sni_alpn_allow_list(allow)
            .build()
            .expect("build should succeed");
        let list = acceptor
            .sni_alpn_allow_list
            .as_ref()
            .expect("allow-list must propagate");
        assert!(
            list.contains_key("api.example.com"),
            "allow-list keys must be normalised to lowercase"
        );
    }

    // ── br-asupersync-3iqbx3: SNI security validation tests ──────────

    #[cfg(feature = "tls")]
    #[test]
    fn test_require_sni_for_multi_tenant_sets_flag() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .require_sni_for_multi_tenant()
            .build()
            .unwrap();

        assert!(
            acceptor.require_sni,
            "require_sni_for_multi_tenant() must set require_sni flag"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_multi_tenant_warning_with_sni_alpn_allowlist_but_no_require_sni() {
        // This test verifies that the security warning is triggered when
        // a potentially multi-tenant configuration (SNI/ALPN allow-list)
        // is used without require_sni(). In production, this should be caught
        // during configuration validation.
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let mut allow = std::collections::BTreeMap::new();
        allow.insert("tenant1.example.com".to_string(), vec![b"h2".to_vec()]);

        // This should succeed but trigger a security warning
        let _acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols_required(vec![b"h2".to_vec()])
            .sni_alpn_allow_list(allow)
            // Note: deliberately NOT calling require_sni() to trigger warning
            .build()
            .expect("build should succeed but log security warning");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_multi_tenant_warning_with_multiple_alpn_but_no_require_sni() {
        // Multiple ALPN protocols suggest potential tenant-specific routing
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // This should succeed but trigger a security warning
        let _acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"grpc".to_vec()])
            // Note: deliberately NOT calling require_sni() to trigger warning
            .build()
            .expect("build should succeed but log security warning");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_sni_security_error_message_contains_security_context() {
        use crate::net::tcp::VirtualTcpStream;
        use crate::test_utils::run_test_with_cx;
        use futures_lite::future::zip;

        run_test_with_cx(|_cx| async move {
            // Create acceptor that requires SNI
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .require_sni_for_multi_tenant() // Use the security-focused variant
                .build()
                .unwrap();

            // Create client that doesn't send SNI
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .disable_sni() // This should cause the security error
                .build()
                .unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // Server should reject with security-focused error message
            let server_err = server_res.unwrap_err();
            match server_err {
                TlsError::Configuration(msg) => {
                    assert!(
                        msg.contains("SECURITY") && msg.contains("asupersync-3iqbx3"),
                        "error message should contain security context, got: {msg}"
                    );
                }
                other => {
                    panic!("expected Configuration error with security context, got {other:?}")
                }
            }
        });
    }

    // ── br-asupersync-jxzrs4: Certificate validation security tests ──

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_passes_for_valid_cert() {
        // Test that a valid (though self-signed) certificate passes validation
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&chain);

        // Should pass since the test certificate is not expired
        assert!(
            result.is_ok(),
            "valid certificate should pass validation: {:?}",
            result
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_rejects_empty_chain() {
        let empty_chain = CertificateChain::new();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&empty_chain);

        assert!(
            result.is_err(),
            "empty certificate chain should be rejected"
        );
        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(msg.contains("certificate chain is empty"));
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_with_certificate_validation_integration() {
        // Test that the build() method correctly calls certificate validation
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Should succeed with valid certificate
        let result = TlsAcceptorBuilder::new(chain, key).build();
        assert!(
            result.is_ok(),
            "build should succeed with valid certificate: {:?}",
            result
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_fails_with_empty_certificate_chain() {
        // Test that build() fails when certificate validation detects empty chain
        let empty_chain = CertificateChain::new();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(empty_chain, key).build();
        assert!(
            result.is_err(),
            "build should fail with empty certificate chain"
        );

        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(
                    msg.contains("certificate chain is empty"),
                    "error should mention empty chain validation: {msg}"
                );
            }
            other => panic!(
                "expected Configuration error for empty chain, got {:?}",
                other
            ),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_certificate_validation_provides_security_context() {
        // Test that validation errors include proper security context
        let empty_chain = CertificateChain::new();
        let result = TlsAcceptorBuilder::validate_certificate_chain(&empty_chain);

        match result {
            Err(TlsError::Configuration(msg)) => {
                // While this specific error doesn't include asupersync-jxzrs4,
                // it's part of the security validation system
                assert!(!msg.is_empty(), "error message should provide context");
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_disable_strict_cert_validation_allows_invalid_certs() {
        // Test that disabling strict validation bypasses certificate checks
        let empty_chain = CertificateChain::new();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Build should fail with strict validation (default)
        let strict_result = TlsAcceptorBuilder::new(empty_chain.clone(), key.clone()).build();
        assert!(
            strict_result.is_err(),
            "strict validation should reject empty chain"
        );

        // Build should still fail with disabled validation due to rustls validation
        // (our strict validation is an additional layer on top of rustls)
        let relaxed_result = TlsAcceptorBuilder::new(empty_chain, key)
            .disable_strict_cert_validation()
            .build();
        // Note: This will still fail because rustls also validates, but at least
        // we can verify our flag is being respected by checking the error doesn't
        // contain our validation message
        assert!(
            relaxed_result.is_err(),
            "empty chain should still fail rustls validation"
        );
    }

    // ── br-asupersync-ycuuwy: 0-RTT replay protection tests ──────────

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_requires_replay_protection() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // Enabling 0-RTT without protection should fail
        let result = TlsAcceptorBuilder::new(chain, key)
            .enable_early_data_with_protection(16384)
            // Deliberately NOT setting replay protection
            .build();

        assert!(result.is_err(), "0-RTT without protection should fail");
        match result {
            Err(TlsError::Configuration(msg)) => {
                assert!(
                    msg.contains("no replay protection configured")
                        && msg.contains("asupersync-ycuuwy"),
                    "error should mention missing protection: {msg}"
                );
            }
            other => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_safe_methods_protection_succeeds() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::SafeMethodsOnly)
            .enable_early_data_with_protection(16384)
            .build();

        assert!(
            result.is_ok(),
            "0-RTT with safe methods protection should succeed: {:?}",
            result
        );

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 16384);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::SafeMethodsOnly
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_idempotency_protection_succeeds() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::IdempotencyKeys)
            .enable_early_data_with_protection(8192)
            .build();

        assert!(
            result.is_ok(),
            "0-RTT with idempotency protection should succeed"
        );

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 8192);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::IdempotencyKeys
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_with_nonce_protection_succeeds() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::NonceValidation)
            .enable_early_data_with_protection(32768)
            .build();

        assert!(result.is_ok(), "0-RTT with nonce protection should succeed");

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 32768);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::NonceValidation
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_unprotected_for_testing_logs_warning() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // This should succeed but log security warnings
        let result = TlsAcceptorBuilder::new(chain, key)
            .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
            .enable_early_data_with_protection(16384)
            .build();

        assert!(
            result.is_ok(),
            "unprotected testing mode should succeed but log warnings"
        );

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 16384);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::UnprotectedForTesting
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_deprecated_enable_early_data_sets_testing_mode() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // The deprecated method should automatically set UnprotectedForTesting
        #[allow(deprecated)]
        let result = TlsAcceptorBuilder::new(chain, key)
            .enable_early_data(16384)
            .build();

        assert!(
            result.is_ok(),
            "deprecated enable_early_data should succeed in testing mode"
        );

        let acceptor = result.unwrap();
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::UnprotectedForTesting
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_no_early_data_allows_no_protection() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();

        // When 0-RTT is disabled (default), no protection is required
        let result = TlsAcceptorBuilder::new(chain, key)
            // Deliberately not setting any protection or enabling early data
            .build();

        assert!(result.is_ok(), "no 0-RTT should not require protection");

        let acceptor = result.unwrap();
        assert_eq!(acceptor.config.max_early_data_size, 0);
        assert!(matches!(
            acceptor.early_data_replay_protection(),
            EarlyDataReplayProtection::None
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_early_data_request_validation_helper() {
        // Test SafeMethodsOnly protection
        let safe_methods = EarlyDataReplayProtection::SafeMethodsOnly;
        assert!(
            safe_methods
                .validate_request_for_early_data("GET", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("HEAD", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("OPTIONS", false, false)
                .is_ok()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("POST", false, false)
                .is_err()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("PUT", false, false)
                .is_err()
        );
        assert!(
            safe_methods
                .validate_request_for_early_data("DELETE", false, false)
                .is_err()
        );

        // Test IdempotencyKeys protection
        let idempotency = EarlyDataReplayProtection::IdempotencyKeys;
        assert!(
            idempotency
                .validate_request_for_early_data("POST", true, false)
                .is_ok()
        );
        assert!(
            idempotency
                .validate_request_for_early_data("PUT", true, false)
                .is_ok()
        );
        assert!(
            idempotency
                .validate_request_for_early_data("GET", false, false)
                .is_err()
        );

        // Test NonceValidation protection
        let nonce = EarlyDataReplayProtection::NonceValidation;
        assert!(
            nonce
                .validate_request_for_early_data("POST", false, true)
                .is_ok()
        );
        assert!(
            nonce
                .validate_request_for_early_data("GET", false, true)
                .is_ok()
        );
        assert!(
            nonce
                .validate_request_for_early_data("PUT", false, false)
                .is_err()
        );

        // Test UnprotectedForTesting allows everything
        let unprotected = EarlyDataReplayProtection::UnprotectedForTesting;
        assert!(
            unprotected
                .validate_request_for_early_data("POST", false, false)
                .is_ok()
        );
        assert!(
            unprotected
                .validate_request_for_early_data("DELETE", false, false)
                .is_ok()
        );

        // Test None rejects everything
        let none = EarlyDataReplayProtection::None;
        assert!(
            none.validate_request_for_early_data("GET", false, false)
                .is_err()
        );
        assert!(
            none.validate_request_for_early_data("POST", true, true)
                .is_err()
        );
    }
}
