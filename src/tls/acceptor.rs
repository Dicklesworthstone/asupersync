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

/// The error `accept` returns when `require_sni` refuses a client that sent
/// no SNI.
#[cfg(feature = "tls")]
fn sni_required_error() -> TlsError {
    TlsError::Configuration(
        "SECURITY: Client did not send SNI extension but require_sni() is set. \
         SNI-less connections are rejected to prevent exposure of default \
         certificate tenant in multi-tenant deployments (asupersync-3iqbx3)"
            .into(),
    )
}

/// The certificate resolver of an acceptor built with `require_sni`: it
/// chooses no certificate for a ClientHello without SNI. rustls then aborts
/// the handshake with an `access_denied` alert before it sends any
/// certificate, so an SNI-less client never sees the chain
/// (br-asupersync-2dxusr item 5). Hellos with SNI go to the inner resolver.
#[cfg(feature = "tls")]
#[derive(Debug)]
struct RequireSniResolver(Arc<dyn rustls::server::ResolvesServerCert>);

#[cfg(feature = "tls")]
impl rustls::server::ResolvesServerCert for RequireSniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        client_hello.server_name()?;
        self.0.resolve(client_hello)
    }

    fn only_raw_public_keys(&self) -> bool {
        self.0.only_raw_public_keys()
    }
}

/// Server certificates that can change while an acceptor serves them.
///
/// An acceptor built with [`TlsAcceptorBuilder::from_certificates`] looks
/// its certificate up here at every handshake: the certificate stored for the
/// client's SNI name, then the one for a matching wildcard (`*.example.com`
/// covers `api.example.com`), then the default. Changes apply to the next
/// handshake without rebuilding the acceptor or restarting its listener:
/// renew a certificate by replacing it, add a tenant by inserting one.
/// Established connections keep the certificate they negotiated.
///
/// Clones share one table. Every certificate is checked when it is stored:
/// the chain must be non-empty and currently valid, and the key must belong
/// to the leaf certificate.
///
/// ```ignore
/// let certificates = TlsCertificates::with_default(chain, key)?;
/// certificates.insert("api.example.com", api_chain, api_key)?;
/// let acceptor = TlsAcceptorBuilder::from_certificates(certificates.clone()).build()?;
/// // Later, from a renewal task:
/// certificates.set_default(renewed_chain, renewed_key)?;
/// ```
#[cfg(feature = "tls")]
#[derive(Clone, Default)]
pub struct TlsCertificates {
    table: Arc<parking_lot::RwLock<CertificateTable>>,
}

#[cfg(feature = "tls")]
#[derive(Default)]
struct CertificateTable {
    default: Option<Arc<rustls::sign::CertifiedKey>>,
    by_name: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Loads the stored keys, which then sign the handshakes; `None` is the
    /// linked or process-default provider.
    provider: Option<Arc<rustls::crypto::CryptoProvider>>,
}

#[cfg(feature = "tls")]
impl TlsCertificates {
    /// An empty table: handshakes find no certificate until one is stored.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty table whose keys are loaded by `provider`, so its handshakes
    /// are signed by it: pass the provider given to
    /// [`TlsAcceptorBuilder::crypto_provider`] (an acceptor built from a table
    /// with another provider is refused). A table from [`Self::new`] uses the
    /// linked or process-default provider (br-asupersync-7u9x9b).
    #[must_use]
    pub fn with_crypto_provider(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        let certificates = Self::new();
        certificates.table.write().provider = Some(provider);
        certificates
    }

    /// The provider given to [`Self::with_crypto_provider`], if any.
    fn crypto_provider(&self) -> Option<Arc<rustls::crypto::CryptoProvider>> {
        self.table.read().provider.clone()
    }

    /// A table whose default certificate is `chain` with `key`.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Configuration`] when the certificate is rejected;
    /// see [`Self::set_default`].
    pub fn with_default(chain: CertificateChain, key: PrivateKey) -> Result<Self, TlsError> {
        let certificates = Self::new();
        certificates.set_default(chain, key)?;
        Ok(certificates)
    }

    /// Serves `chain` with `key` to clients whose SNI name has no
    /// certificate of its own, and to clients that send no SNI.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Configuration`] when the chain is empty, malformed
    /// or outside its validity period, or the key does not match the leaf
    /// certificate. The table is unchanged then.
    pub fn set_default(&self, chain: CertificateChain, key: PrivateKey) -> Result<(), TlsError> {
        let certified = certified_key(chain, key, self.crypto_provider().as_ref())?;
        self.table.write().default = Some(certified);
        Ok(())
    }

    /// Removes the default certificate: clients whose SNI name matches no
    /// stored certificate are then refused during the handshake.
    pub fn clear_default(&self) {
        self.table.write().default = None;
    }

    /// Whether a default certificate is stored.
    #[must_use]
    pub fn has_default(&self) -> bool {
        self.table.read().default.is_some()
    }

    /// Serves `chain` with `key` to clients that ask for `server_name`,
    /// replacing any certificate stored for it. `server_name` is a DNS name,
    /// or `*.` followed by one for a wildcard; it is matched without regard
    /// to case.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Configuration`] when the name is empty or the
    /// certificate is rejected (see [`Self::set_default`]). The table is
    /// unchanged then.
    pub fn insert(
        &self,
        server_name: &str,
        chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<(), TlsError> {
        let name = normalize_server_name(server_name)?;
        let certified = certified_key(chain, key, self.crypto_provider().as_ref())?;
        self.table.write().by_name.insert(name, certified);
        Ok(())
    }

    /// Removes the certificate stored for `server_name`; returns whether one
    /// was stored.
    pub fn remove(&self, server_name: &str) -> bool {
        normalize_server_name(server_name)
            .is_ok_and(|name| self.table.write().by_name.remove(&name).is_some())
    }

    /// The server names with a certificate of their own, sorted.
    #[must_use]
    pub fn server_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.table.read().by_name.keys().cloned().collect();
        names.sort();
        names
    }

    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let table = self.table.read();
        if let Some(name) = server_name {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(certified) = table.by_name.get(&name) {
                return Some(Arc::clone(certified));
            }
            if let Some((_, parent)) = name.split_once('.')
                && let Some(certified) = table.by_name.get(&format!("*.{parent}"))
            {
                return Some(Arc::clone(certified));
            }
        }
        table.default.clone()
    }
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for TlsCertificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCertificates")
            .field("has_default", &self.has_default())
            .field("server_names", &self.server_names())
            .finish()
    }
}

/// The table key for `server_name`, which must be a name a client can send
/// as SNI: an ASCII DNS name (an A-label, not a U-label, and not an IP
/// address), or `*.` followed by one (br-asupersync-7u9x9b).
#[cfg(feature = "tls")]
fn normalize_server_name(server_name: &str) -> Result<String, TlsError> {
    let name = server_name.trim_end_matches('.').to_ascii_lowercase();
    let host = name.strip_prefix("*.").unwrap_or(&name);
    if host.is_empty()
        || host.contains('*')
        || host.parse::<std::net::IpAddr>().is_ok()
        || rustls::pki_types::DnsName::try_from(host).is_err()
    {
        return Err(TlsError::Configuration(
            "a TLS server name must be a DNS name or *. followed by one".into(),
        ));
    }
    Ok(name)
}

/// Loads and checks one certificate for [`TlsCertificates`], with the
/// table's provider.
#[cfg(feature = "tls")]
fn certified_key(
    chain: CertificateChain,
    key: PrivateKey,
    provider: Option<&Arc<rustls::crypto::CryptoProvider>>,
) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError> {
    TlsAcceptorBuilder::validate_certificate_chain(&chain)?;
    let provider = super::resolve_crypto_provider(provider)?;
    let signing_key = provider
        .key_provider
        .load_private_key(key.clone_inner())
        .map_err(|e| TlsError::Configuration(format!("unusable private key: {e}")))?;
    let certified = rustls::sign::CertifiedKey::new(chain.into_inner(), signing_key);
    // As rustls's own `CertifiedKey::from_der`: a key that cannot report its
    // public key (some hardware-backed providers) is not a mismatch.
    match certified.keys_match() {
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(e) => {
            return Err(TlsError::Configuration(format!(
                "key does not match certificate: {e}"
            )));
        }
    }
    Ok(Arc::new(certified))
}

/// The resolver of an acceptor built from [`TlsCertificates`].
#[cfg(feature = "tls")]
#[derive(Debug)]
struct TableResolver(TlsCertificates);

#[cfg(feature = "tls")]
impl rustls::server::ResolvesServerCert for TableResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.resolve_name(client_hello.server_name())
    }
}

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
    /// 0-RTT early data. `accept` rejects early data whatever it is
    /// (br-asupersync-0n1dvh); it records the configured policy.
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
    /// br-asupersync-ycuuwy: the configured policy. No request arrives as
    /// 0-RTT through this acceptor today: `accept` rejects early data on
    /// every connection (br-asupersync-0n1dvh). Callers that apply the
    /// policy themselves, on another early-data path, can read it here.
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
    /// # Status (br-asupersync-snv902)
    ///
    /// This helper is **not yet wired into the server request pipeline**, and
    /// `TlsStream` exposes no early-data signal (there is no
    /// `received_early_data()` accessor). Because the per-request gate is
    /// therefore unreachable, [`TlsAcceptorBuilder::build`] **refuses** to
    /// enable 0-RTT for `SafeMethodsOnly` / `IdempotencyKeys` /
    /// `NonceValidation` (fail closed) until enforcement is wired, and `accept`
    /// rejects early data on every connection (0n1dvh). The helper remains available
    /// for callers that surface an early-data flag themselves and want to apply
    /// the policy manually.
    ///
    /// # Example (manual application)
    ///
    /// ```ignore
    /// // Once you can detect early-data requests, screen them with the
    /// // acceptor's configured strategy and map a rejection to 425 Too Early:
    /// if let Err(reason) = acceptor.early_data_replay_protection()
    ///     .validate_request_for_early_data("POST", true, false)
    /// {
    ///     return Response::builder()
    ///         .status(425) // Too Early
    ///         .body(format!("0-RTT rejected: {}", reason))?;
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
        let mut conn = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| TlsError::Configuration(e.to_string()))?;
        // br-asupersync-0n1dvh (owner decision 2026-10-13): reject 0-RTT here,
        // at the TLS layer, on every connection. TlsStream reads only 1-RTT
        // data, so accepted early data would be lost, and no replay strategy
        // is enforced per request (snv902), so delivering it would expose
        // replays. Rejected, the client is told in the handshake and resends
        // over 1-RTT: nothing is lost or replayed.
        conn.reject_early_data();
        let mut stream = TlsStream::new_server(io, conn);
        let handshake = if let Some(timeout) = self.handshake_timeout {
            match crate::time::timeout(
                super::timeout_now(),
                timeout,
                poll_fn(|cx| stream.poll_handshake(cx)),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => return Err(TlsError::Timeout(timeout)),
            }
        } else {
            poll_fn(|cx| stream.poll_handshake(cx)).await
        };
        if let Err(err) = handshake {
            // With require_sni, the certificate resolver refuses a hello
            // without SNI, so the handshake fails before any certificate is
            // sent (RequireSniResolver). Report that as the SNI refusal.
            if self.require_sni
                && matches!(err, TlsError::Handshake(_))
                && stream.sni_hostname().is_none()
            {
                return Err(sni_required_error());
            }
            return Err(err);
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
        // default-cert tenant is not reachable via probing. The resolver
        // already refused such a hello during the handshake; this check
        // stays as defence in depth.
        if self.require_sni && stream.sni_hostname().is_none() {
            return Err(sni_required_error());
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
/// br-asupersync-ycuuwy: TLS 1.3 0-RTT (early data) is replayable within
/// the ticket validity window. `build()` requires a strategy before it sets
/// a non-zero early-data cap, and `TlsAcceptor::accept` rejects early data
/// on every connection until one is enforced (br-asupersync-0n1dvh).
#[derive(Debug, Clone, Default)]
pub enum EarlyDataReplayProtection {
    /// No replay protection strategy (the default).
    ///
    /// `build()` refuses a non-zero early-data cap with this strategy
    /// (br-asupersync-ycuuwy), so 0-RTT stays off. Without a strategy,
    /// captured 0-RTT requests could be replayed, causing duplicate state
    /// changes, financial transactions, or data corruption.
    ///
    /// Choose a strategy before enabling 0-RTT.
    #[default]
    None,

    /// Restrict 0-RTT to safe HTTP methods only (GET, HEAD, OPTIONS).
    ///
    /// Intended to allow 0-RTT only for idempotent methods and to reject
    /// POST, PUT, DELETE and PATCH received as 0-RTT. Not enforced yet:
    /// `build()` refuses a non-zero early-data cap with this strategy
    /// (br-asupersync-snv902).
    ///
    /// Even when enforced, GET requests with side effects stay replayable.
    SafeMethodsOnly,

    /// Application implements idempotency key validation.
    ///
    /// The application MUST implement idempotency key checking where:
    /// 1. All state-changing requests include an `Idempotency-Key` header
    /// 2. The server tracks completed idempotency keys
    /// 3. Duplicate keys are rejected with 409 Conflict
    /// 4. Keys are stored with TTL matching the TLS ticket lifetime
    ///
    /// Not enforced yet: `build()` refuses a non-zero cap with it (snv902).
    IdempotencyKeys,

    /// Application implements nonce-based anti-replay.
    ///
    /// The application MUST implement nonce validation where:
    /// 1. All requests include a unique nonce (timestamp + random)
    /// 2. The server maintains a bounded-window nonce store
    /// 3. Duplicate nonces within the window are rejected
    /// 4. The window size matches the TLS ticket lifetime
    ///
    /// Not enforced yet: `build()` refuses a non-zero cap with it (snv902).
    NonceValidation,

    /// Explicit acknowledgment that no protection is implemented (DANGEROUS).
    ///
    /// **USE ONLY FOR TESTING**: This explicitly acknowledges that no replay
    /// protection is implemented. It lets `build()` set a non-zero cap, so
    /// tickets advertise 0-RTT, but `TlsAcceptor::accept` still rejects early
    /// data on every connection (br-asupersync-0n1dvh): clients resend it.
    ///
    /// No configuration delivers 0-RTT today; never rely on this in production.
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
    /// advertises 0-RTT in session tickets up to this many bytes,
    /// but `TlsAcceptor::accept` rejects early data on every
    /// connection (br-asupersync-0n1dvh), so the client resends it
    /// over 1-RTT and no request is replayed.
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
    /// The rustls crypto provider set with [`Self::crypto_provider`].
    /// `None` resolves as the `tls` module documentation describes.
    #[cfg(feature = "tls")]
    crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    /// Set by [`Self::from_certificates`]: certificates are looked up here at
    /// each handshake instead of `cert_chain` / `key`.
    #[cfg(feature = "tls")]
    certificates: Option<TlsCertificates>,
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

                    // RFC 5280 4.1.2.6: the subject may be empty when a SAN names it.
                    if cert.subject().iter_common_name().next().is_none()
                        && cert.subject().iter_organizational_unit().next().is_none()
                        && cert.subject().iter_organization().next().is_none()
                        && !matches!(cert.subject_alternative_name(), Ok(Some(_)))
                    {
                        return Err(TlsError::Configuration(format!(
                            "certificate {i} in chain has empty subject and no SAN. \
                             Certificate may be malformed (asupersync-jxzrs4)"
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
            #[cfg(feature = "tls")]
            crypto_provider: None,
            #[cfg(feature = "tls")]
            certificates: None,
        }
    }

    /// A builder whose acceptor takes its certificates from `certificates`
    /// at every handshake, by SNI name, so they can be renewed or added while
    /// it serves; see [`TlsCertificates`].
    ///
    /// The other settings apply as with [`Self::new`]. Certificates are
    /// checked when they are stored, so [`Self::require_full_chain`] and
    /// [`Self::disable_strict_cert_validation`] do not apply; `build` refuses
    /// `require_full_chain`. A table from
    /// [`TlsCertificates::with_crypto_provider`] gives the acceptor its
    /// provider unless [`Self::crypto_provider`] names the same one.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn from_certificates(certificates: TlsCertificates) -> Self {
        let mut builder = Self::new(
            CertificateChain::new(),
            PrivateKey::from_pkcs8_der(Vec::new()),
        );
        builder.certificates = Some(certificates);
        builder
    }

    /// br-asupersync-vu10zb — require that incoming ClientHello
    /// messages carry the SNI extension. A connection that omits SNI
    /// is refused during the handshake, before the server sends its
    /// certificate: the client gets an `access_denied` alert, and
    /// `accept` returns a `TlsError::Configuration` that says SNI was
    /// missing (br-asupersync-2dxusr item 5) — necessary in
    /// multi-tenant deployments where
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
    ///
    /// # Early data is rejected
    ///
    /// The cap reaches the tickets, so clients may offer 0-RTT, but
    /// `TlsAcceptor::accept` rejects early data at the TLS layer on every
    /// connection (br-asupersync-0n1dvh): the client resends over 1-RTT, so no
    /// request is lost or replayed. Delivering early data waits for
    /// per-request replay enforcement (br-asupersync-snv902).
    #[must_use]
    pub fn enable_early_data_with_protection(mut self, max_bytes: u32) -> Self {
        self.early_data_max_bytes = max_bytes;
        self
    }

    /// **DEPRECATED**: Legacy 0-RTT enable.
    ///
    /// br-asupersync-0n1dvh (owner decision 2026-10-13): this used to switch
    /// a builder without a replay strategy to
    /// [`EarlyDataReplayProtection::UnprotectedForTesting`], so `build()`
    /// succeeded with replayable 0-RTT on the wire. It no longer selects a
    /// strategy. With one already chosen, it sets the cap like
    /// [`Self::enable_early_data_with_protection`]; without one, it changes
    /// nothing and `build()` succeeds with 0-RTT off.
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
        if !matches!(
            self.early_data_replay_protection,
            EarlyDataReplayProtection::None
        ) {
            self.early_data_max_bytes = max_bytes;
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
    /// unexpected), `accept()` returns a sanitized `TlsError::Configuration`
    /// error ("ALPN protocol negotiation failed - client protocol not
    /// supported"); the message deliberately names neither the expected nor
    /// the negotiated protocol (br-asupersync-iz6751).
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
    /// This limits the size of TLS records to 32..=16389 bytes, checked by
    /// `build`. Smaller values help constrained networks but cost throughput.
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

    /// Use `provider` for this acceptor's cipher suites, key exchange,
    /// signing and client-certificate verification.
    ///
    /// Mirrors `TlsConnectorBuilder::crypto_provider`: without it, the
    /// acceptor uses the ring provider when `tls` links it, else rustls's
    /// process default; a `tls-core` build with neither fails in
    /// [`Self::build`]. With [`Self::from_certificates`], the table must come
    /// from [`TlsCertificates::with_crypto_provider`] with this same
    /// provider, or `build` refuses it.
    #[cfg(feature = "tls")]
    pub fn crypto_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Build the `TlsAcceptor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g., invalid certificate/key pair).
    #[cfg(feature = "tls")]
    pub fn build(self) -> Result<TlsAcceptor, TlsError> {
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
        if self.strict_cert_validation && self.certificates.is_none() {
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
                        "SECURITY WARNING: TLS 1.3 0-RTT advertised without replay protection. \
                         Tickets offer early data, but accept() rejects it on every connection \
                         (asupersync-0n1dvh), so clients resend over 1-RTT. Never rely on this \
                         configuration in production. Use only for testing (asupersync-ycuuwy)"
                    );
                }
                EarlyDataReplayProtection::SafeMethodsOnly
                | EarlyDataReplayProtection::IdempotencyKeys
                | EarlyDataReplayProtection::NonceValidation => {
                    // SECURITY: br-asupersync-snv902 — these strategies are
                    // only effective when EarlyDataReplayProtection::
                    // validate_request_for_early_data() runs PER REQUEST, but
                    // that gate is NOT wired into the server request pipeline
                    // (h1/h2/h3) and TlsStream exposes no early-data signal
                    // (received_early_data() does not exist). Since 0n1dvh,
                    // accept() rejects early data on every connection, so none
                    // is processed; building anyway would still name a policy
                    // that nothing enforces, a phantom control. The message
                    // below predates 0n1dvh and is pinned. Fail CLOSED: refuse to
                    // build a 0-RTT-enabled acceptor for a strategy whose
                    // per-request enforcement is unreachable, rather than ship
                    // un-enforced 0-RTT. (The build-time gate is the only place
                    // this can be caught fail-closed until enforcement is wired;
                    // tracked as the real-fix follow-up on the bead.)
                    return Err(TlsError::Configuration(format!(
                        "TLS 1.3 0-RTT enabled (max_bytes={}) with replay strategy \
                         {:?}, but per-request replay enforcement is NOT wired into \
                         the server request pipeline: validate_request_for_early_data() \
                         has no production caller and TlsStream exposes no early-data \
                         signal, so early data would be accepted on the wire and \
                         processed WITHOUT any replay screening — a false sense of \
                         protection. Until per-request enforcement is wired, either do \
                         not enable 0-RTT, or, for tests that explicitly accept NO replay \
                         protection, select EarlyDataReplayProtection::UnprotectedForTesting \
                         (asupersync-snv902).",
                        self.early_data_max_bytes, self.early_data_replay_protection
                    )));
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
        if self.certificates.is_some() && self.require_full_chain {
            return Err(TlsError::Configuration(
                "require_full_chain applies to the certificate given to new(); \
                 check chains before storing them in TlsCertificates"
                    .into(),
            ));
        }
        if self.cert_chain.is_empty() && self.certificates.is_none() {
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
        // A certificate table signs with the keys its own provider loaded, so
        // it must be the acceptor's provider: a table from `new()` next to an
        // explicit provider would sign every handshake with the default one
        // (br-asupersync-7u9x9b). A table with a provider lends it to an
        // acceptor that names none.
        let table_provider = self
            .certificates
            .as_ref()
            .and_then(TlsCertificates::crypto_provider);
        if let (Some(explicit), Some(_)) = (self.crypto_provider.as_ref(), &self.certificates)
            && !table_provider
                .as_ref()
                .is_some_and(|table| Arc::ptr_eq(table, explicit))
        {
            return Err(TlsError::Configuration(
                "crypto_provider differs from the TlsCertificates provider: build the table \
                 with TlsCertificates::with_crypto_provider and the same provider"
                    .into(),
            ));
        }
        let provider = super::resolve_crypto_provider(
            self.crypto_provider.as_ref().or(table_provider.as_ref()),
        )?;
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider));
        let builder = if self.min_protocol.is_some() || self.max_protocol.is_some() {
            // Convert protocol versions to the wire ordinals so the
            // range comparison works regardless of the
            // `rustls::ProtocolVersion` enum's Rust-level Ord (which
            // has no documented stability guarantee).
            // TLS 1.2 = 0x0303, TLS 1.3 = 0x0304.
            fn version_ordinal(v: rustls::ProtocolVersion) -> u16 {
                // The wire value orders every TLS version, so a bound below
                // TLS 1.2 is honoured: a TLS 1.1 ceiling leaves no version
                // (a build error) and a TLS 1.0 floor admits 1.2 and 1.3.
                // Mapping them to 0xFFFF made the ceiling a no-op and the
                // floor an error. Unknown values keep their own number, and
                // DTLS values (0xFEFF and below) sort above every TLS one.
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

        // Configure client auth. `builder_with_provider` keeps the verifier on
        // the connection's provider; plain `builder` would use rustls's
        // process default.
        let builder = match self.client_auth {
            ClientAuth::None => builder.with_no_client_auth(),
            ClientAuth::Optional(roots) => {
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots.into_inner()),
                    provider,
                )
                .allow_unauthenticated()
                .build()
                .map_err(|e| TlsError::Configuration(e.to_string()))?;
                builder.with_client_cert_verifier(verifier)
            }
            ClientAuth::Required(roots) => {
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots.into_inner()),
                    provider,
                )
                .build()
                .map_err(|e| TlsError::Configuration(e.to_string()))?;
                builder.with_client_cert_verifier(verifier)
            }
        };

        let mut config = match self.certificates {
            Some(certificates) => builder.with_cert_resolver(Arc::new(TableResolver(certificates))),
            None => builder
                .with_single_cert(self.cert_chain.into_inner(), self.key.clone_inner())
                .map_err(|e| TlsError::Configuration(e.to_string()))?,
        };

        // Refuse a hello without SNI before the certificate is sent, not
        // after the handshake completed (br-asupersync-2dxusr item 5).
        if self.require_sni {
            config.cert_resolver = Arc::new(RequireSniResolver(Arc::clone(&config.cert_resolver)));
        }

        // Set ALPN if specified
        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols;
        }

        // Set max fragment size if specified
        if let Some(size) = self.max_fragment_size {
            // rustls checks this bound only when each connection is created,
            // so an out-of-range value would fail every accept() instead.
            if !(32..=16_389).contains(&size) {
                return Err(TlsError::Configuration(format!(
                    "max_fragment_size {size} is outside 32..=16389"
                )));
            }
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
#[path = "acceptor_inline_tests.rs"]
mod tests;
