//! gRPC interceptor middleware.
//!
//! Provides a layer-based interceptor pattern for processing gRPC requests
//! and responses. Interceptors can be used for authentication, logging,
//! tracing, metrics, and other cross-cutting concerns.
//!
//! # Cross-interceptor state: `AuthContext`
//!
//! When an authentication interceptor (e.g. [`AuthInterceptor`] or a
//! custom one) parses a bearer token, it MUST share the resulting
//! identity with downstream interceptors (rate-limit per-tenant,
//! authorization, audit logging) and the eventual handler. Two patterns
//! are wrong here:
//!
//! 1. Stuffing the parsed user id into a custom metadata header
//!    (`x-asupersync-user`). This LEAKS the server-side identity onto
//!    the wire — visible to downstream microservices, log scrapers, and
//!    potentially echoed back in responses.
//! 2. Maintaining a thread-local "current user" register. This violates
//!    the asupersync I7 invariant (no ambient authority).
//!
//! The right pattern is [`AuthContext`] in `request.extensions_mut()`:
//!
//! ```ignore
//! use asupersync::grpc::interceptor::AuthContext;
//! use asupersync::grpc::server::Interceptor;
//!
//! struct MyAuthInterceptor;
//! impl Interceptor for MyAuthInterceptor {
//!     fn intercept_request(&self, req: &mut Request<Bytes>) -> Result<(), Status> {
//!         let token = req.metadata().get("authorization")
//!             .ok_or_else(|| Status::unauthenticated("missing token"))?;
//!         let (user_id, scopes) = parse_jwt(token)?;
//!         let auth = AuthContext::with_principal(user_id).with_scopes(scopes);
//!         req.extensions_mut().insert_typed(auth);
//!         Ok(())
//!     }
//!     fn intercept_response(&self, _r: &mut Response<Bytes>) -> Result<(), Status> {
//!         Ok(())
//!     }
//! }
//!
//! // A downstream interceptor or handler reads:
//! fn handler(req: &Request<Bytes>) -> Result<Response<Bytes>, Status> {
//!     let auth = req.extensions().get_typed::<AuthContext>()
//!         .ok_or_else(|| Status::unauthenticated("no auth context"))?;
//!     if !auth.has_scope("write:users") {
//!         return Err(Status::permission_denied("requires write:users"));
//!     }
//!     // ... use auth.principal ...
//!     Ok(Response::new(Bytes::new()))
//! }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use asupersync::grpc::interceptor::{InterceptorLayer, trace_interceptor, auth_bearer_interceptor};
//!
//! // Create a layered interceptor chain
//! let interceptor = InterceptorLayer::new()
//!     .layer(trace_interceptor())
//!     .layer(auth_bearer_interceptor("my-token"));
//!
//! // Apply to requests
//! let request = interceptor.intercept_request(request)?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::bytes::Bytes;

use super::server::{Interceptor, format_grpc_timeout, parse_grpc_timeout};
use super::status::Status;
use super::streaming::{MetadataValue, Request, Response};

// ─── AuthContext ───────────────────────────────────────────────────────────

/// Authenticated principal + scopes + claims, threaded through an
/// interceptor chain via [`Request::extensions_mut`].
///
/// The asupersync gRPC interceptor chain has no implicit auth flow —
/// each interceptor is independent. When an authentication interceptor
/// validates credentials, it inserts an `AuthContext` into the request's
/// typed extensions; downstream interceptors and handlers read it via
/// `request.extensions().get_typed::<AuthContext>()`.
///
/// This avoids two anti-patterns:
///   * leaking parsed identity into wire metadata (the metadata
///     round-trips to client; downstream services see it),
///   * maintaining a thread-local "current user" (violates the no-ambient-
///     authority invariant).
///
/// Resolves bead asupersync-z719f7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthContext {
    /// The authenticated principal id (user id, sub claim, service
    /// account name, etc.). Empty string means anonymous (typically
    /// not inserted at all in that case).
    pub principal: String,
    /// OAuth-style scopes / permissions granted to the principal.
    pub scopes: Vec<String>,
    /// Optional request id for correlation across services. Independent
    /// of the principal — useful for tracing even when unauthenticated.
    pub request_id: Option<String>,
    /// Additional claims (e.g. JWT custom claims, tenant id, role).
    /// Use sparingly — typed first-class fields above are preferred.
    pub claims: HashMap<String, String>,
}

impl AuthContext {
    /// Construct an empty AuthContext (anonymous, no scopes).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an AuthContext for the given principal id.
    #[must_use]
    pub fn with_principal(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            ..Self::default()
        }
    }

    /// Set the OAuth-style scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Set the request id for tracing/correlation.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Insert an additional claim.
    #[must_use]
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
    }

    /// Returns true if the principal holds the named scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Returns true if the principal holds ALL of the named scopes.
    #[must_use]
    pub fn has_all_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|needed| self.has_scope(needed))
    }

    /// Returns true if the AuthContext is anonymous (empty principal).
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.principal.is_empty()
    }
}

/// A composable layer of interceptors.
///
/// `InterceptorLayer` provides a builder pattern for composing multiple
/// interceptors into a single chain.
#[derive(Clone)]
pub struct InterceptorLayer {
    /// The chain of interceptors.
    interceptors: Vec<Arc<dyn Interceptor>>,
}

impl std::fmt::Debug for InterceptorLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptorLayer")
            .field(
                "interceptors",
                &format!("[{} interceptors]", self.interceptors.len()),
            )
            .finish()
    }
}

impl InterceptorLayer {
    /// Create a new empty interceptor layer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interceptors: Vec::with_capacity(4),
        }
    }

    /// Add an interceptor to the layer.
    ///
    /// Interceptors are applied in the order they are added for requests,
    /// and in reverse order for responses.
    #[must_use]
    pub fn layer<I>(mut self, interceptor: I) -> Self
    where
        I: Interceptor + 'static,
    {
        self.interceptors.push(Arc::new(interceptor));
        self
    }

    /// Add multiple interceptors.
    #[must_use]
    pub fn layers<I>(mut self, interceptors: impl IntoIterator<Item = I>) -> Self
    where
        I: Interceptor + 'static,
    {
        let interceptors = interceptors.into_iter();
        let (lower, upper) = interceptors.size_hint();
        self.interceptors.reserve(upper.unwrap_or(lower));

        for interceptor in interceptors {
            self.interceptors.push(Arc::new(interceptor));
        }
        self
    }

    /// Returns true if there are no interceptors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    /// Returns the number of interceptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interceptors.len()
    }
}

impl Default for InterceptorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl Interceptor for InterceptorLayer {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        // Mirror the Server::dispatch_unary cleanup contract: when an
        // inner interceptor at index `i` returns Err, walk back
        // through the interceptors[..=i] in REVERSE order calling
        // intercept_error_with_request so any side effects acquired by
        // the earlier inner interceptors get cleaned up. Without this,
        // a RateLimitInterceptor wrapped in an InterceptorLayer that
        // also contains an auth interceptor that rejects the request
        // would PERMANENTLY leak its slot — every auth failure burns
        // a slot, and after max_requests of them the rate limiter is
        // wedged rejecting legitimate traffic forever
        // (br-asupersync-9oxmqv).
        for (index, interceptor) in self.interceptors.iter().enumerate() {
            if let Err(mut status) = interceptor.intercept_request(request) {
                for cleanup in self.interceptors[..=index].iter().rev() {
                    if let Err(replacement) =
                        cleanup.intercept_error_with_request(request, &mut status)
                    {
                        status = replacement;
                    }
                }
                return Err(status);
            }
        }
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        // Apply in reverse order for responses
        for interceptor in self.interceptors.iter().rev() {
            interceptor.intercept_response(response)?;
        }
        Ok(())
    }

    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        for interceptor in self.interceptors.iter().rev() {
            interceptor.intercept_response_with_request(request, response)?;
        }
        Ok(())
    }

    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        status: &mut Status,
    ) -> Result<(), Status> {
        // br-asupersync-9oxmqv: when the OUTER dispatcher (Server::
        // dispatch_unary) error-walks past this aggregate, propagate
        // to every inner interceptor in reverse order so each one
        // has a chance to release its acquired resources (rate-limit
        // slots, auth-context drops, metric-decrement counters, …).
        // The trait default is a no-op that would otherwise sink the
        // cleanup signal here and leak the inner side effects.
        for inner in self.interceptors.iter().rev() {
            if let Err(replacement) = inner.intercept_error_with_request(request, status) {
                *status = replacement;
            }
        }
        Ok(())
    }
}

/// A function-based interceptor for requests.
#[derive(Clone)]
pub struct FnInterceptor<F> {
    f: F,
}

impl<F> FnInterceptor<F>
where
    F: Fn(&mut Request<Bytes>) -> Result<(), Status> + Send + Sync,
{
    /// Create a new function-based interceptor.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> std::fmt::Debug for FnInterceptor<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnInterceptor").finish_non_exhaustive()
    }
}

impl<F> Interceptor for FnInterceptor<F>
where
    F: Fn(&mut Request<Bytes>) -> Result<(), Status> + Send + Sync,
{
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        (self.f)(request)
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create an interceptor from a function.
pub fn fn_interceptor<F>(f: F) -> FnInterceptor<F>
where
    F: Fn(&mut Request<Bytes>) -> Result<(), Status> + Send + Sync,
{
    FnInterceptor::new(f)
}

const REQUEST_ID_METADATA_KEY: &str = "x-request-id";
const REQUEST_ID_SIGNATURE_METADATA_KEY: &str = "x-request-id-signature";

/// Verifies a client-supplied request ID and companion signature.
///
/// The verifier is intentionally tiny: deployments decide how signatures are
/// encoded and which key material is trusted. The interceptor only enforces
/// the fail-closed rule that unsigned or unverifiable request IDs are replaced
/// at an untrusted edge.
pub trait RequestIdSignatureVerifier: Send + Sync + 'static {
    /// Returns true when `signature` authenticates `request_id`.
    fn verify_request_id(&self, request_id: &str, signature: &str) -> bool;
}

impl<F> RequestIdSignatureVerifier for F
where
    F: for<'a, 'b> Fn(&'a str, &'b str) -> bool + Send + Sync + 'static,
{
    fn verify_request_id(&self, request_id: &str, signature: &str) -> bool {
        self(request_id, signature)
    }
}

#[derive(Clone)]
enum RequestIdTrustPolicy {
    UntrustedEdge,
    TrustedEdge,
    Signed {
        verifier: Arc<dyn RequestIdSignatureVerifier>,
    },
}

impl std::fmt::Debug for RequestIdTrustPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedEdge => f.write_str("UntrustedEdge"),
            Self::TrustedEdge => f.write_str("TrustedEdge"),
            Self::Signed { .. } => f.write_str("Signed { verifier: ... }"),
        }
    }
}

/// Tracing interceptor that adds request IDs to metadata.
#[derive(Debug, Clone)]
pub struct TracingInterceptor {
    /// Whether to generate request IDs.
    generate_request_id: bool,
    next_request_id: Arc<AtomicU64>,
    request_id_trust_policy: RequestIdTrustPolicy,
}

impl Default for TracingInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingInterceptor {
    /// Create a new tracing interceptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            generate_request_id: true,
            next_request_id: Arc::new(AtomicU64::new(1)),
            request_id_trust_policy: RequestIdTrustPolicy::UntrustedEdge,
        }
    }

    /// Configure whether to generate request IDs.
    #[must_use]
    pub fn with_request_id(mut self, enabled: bool) -> Self {
        self.generate_request_id = enabled;
        self
    }

    /// Preserve existing client request IDs from a trusted ingress boundary.
    ///
    /// Use this only when an upstream component already authenticated and
    /// normalized `x-request-id`. The default untrusted-edge policy replaces
    /// unsigned client IDs.
    #[must_use]
    pub fn with_trusted_client_request_ids(mut self) -> Self {
        self.request_id_trust_policy = RequestIdTrustPolicy::TrustedEdge;
        self
    }

    /// Preserve client request IDs only when the companion signature verifies.
    ///
    /// The verifier receives the ASCII `x-request-id` value and the ASCII
    /// `x-request-id-signature` value. Missing, binary, empty, or rejected
    /// signatures cause the request ID to be regenerated.
    #[must_use]
    pub fn with_request_id_signature_verifier<V>(mut self, verifier: V) -> Self
    where
        V: RequestIdSignatureVerifier,
    {
        self.request_id_trust_policy = RequestIdTrustPolicy::Signed {
            verifier: Arc::new(verifier),
        };
        self
    }

    fn should_preserve_request_id(&self, request: &Request<Bytes>) -> bool {
        let Some(MetadataValue::Ascii(request_id)) =
            request.metadata().get(REQUEST_ID_METADATA_KEY)
        else {
            return false;
        };
        if request_id.is_empty() {
            return false;
        }

        match &self.request_id_trust_policy {
            RequestIdTrustPolicy::UntrustedEdge => false,
            RequestIdTrustPolicy::TrustedEdge => true,
            RequestIdTrustPolicy::Signed { verifier } => {
                let Some(MetadataValue::Ascii(signature)) =
                    request.metadata().get(REQUEST_ID_SIGNATURE_METADATA_KEY)
                else {
                    return false;
                };
                !signature.is_empty() && verifier.verify_request_id(request_id, signature)
            }
        }
    }

    fn next_generated_request_id(&self) -> String {
        format!(
            "req-{:016x}",
            self.next_request_id.fetch_add(1, Ordering::Relaxed)
        )
    }
}

impl Interceptor for TracingInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        if self.generate_request_id && !self.should_preserve_request_id(request) {
            let id = self.next_generated_request_id();
            let metadata = request.metadata_mut();
            let _ = metadata.remove(REQUEST_ID_SIGNATURE_METADATA_KEY);
            let _ = metadata.insert_or_replace(REQUEST_ID_METADATA_KEY, id);
        }
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create a tracing interceptor.
#[must_use]
pub fn trace_interceptor() -> TracingInterceptor {
    TracingInterceptor::new()
}

/// Bearer token authentication interceptor.
#[derive(Debug, Clone)]
pub struct BearerAuthInterceptor {
    token: String,
}

impl BearerAuthInterceptor {
    /// Create a new bearer auth interceptor that adds the token to requests.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Interceptor for BearerAuthInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        let _ = request
            .metadata_mut()
            .insert("authorization", format!("Bearer {}", self.token));
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create a bearer token interceptor that adds the token to outgoing requests.
#[must_use]
pub fn auth_bearer_interceptor(token: impl Into<String>) -> BearerAuthInterceptor {
    BearerAuthInterceptor::new(token)
}

/// Helper to extract ASCII string from metadata value.
fn metadata_to_string(value: &MetadataValue) -> Option<&str> {
    match value {
        MetadataValue::Ascii(s) => Some(s.as_str()),
        MetadataValue::Binary(_) => None,
    }
}

fn bearer_token(auth: &str) -> Option<&str> {
    let (scheme, token) = auth.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim_start_matches(' ');
    if token.is_empty() {
        return None;
    }

    Some(token)
}

/// br-asupersync-icvybx — Fuzz-target entry point for the bearer-token
/// Authorization parser. `#[doc(hidden)]` because it exists only to let
/// `fuzz/fuzz_targets/grpc_bearer_token.rs` exercise the parser
/// directly without fabricating a full `Request<Bytes>` + metadata
/// stack. Production callers reach the same logic via
/// `BearerAuthValidator::intercept_request`.
#[doc(hidden)]
#[must_use]
pub fn fuzz_bearer_token(auth: &str) -> Option<&str> {
    bearer_token(auth)
}

/// Validates metadata key to prevent header injection attacks.
///
/// gRPC metadata keys must follow HTTP header naming rules:
/// - ASCII letters, digits, hyphens, underscores only
/// - Cannot start with hyphen (reserved)
/// - Cannot contain colons, CRLF, or other control characters
///
/// br-asupersync-uydhdw: Prevents header injection via malicious key names.
fn validate_metadata_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('-')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn copy_metadata_value(
    metadata: &mut super::streaming::Metadata,
    key: &str,
    value: &MetadataValue,
) {
    // br-asupersync-uydhdw: Validate metadata key to prevent header injection
    if !validate_metadata_key(key) {
        return;
    }

    match value {
        MetadataValue::Ascii(ascii) => {
            let _ = metadata.insert(key, ascii.clone());
        }
        MetadataValue::Binary(binary) => {
            let _ = metadata.insert_bin(key, binary.clone());
        }
    }
}

/// Constant-time byte-equality comparison.
///
/// Returns `true` iff the two slices have the same length AND the same
/// bytes. The comparison is data-independent: every byte is processed
/// regardless of where the first mismatch (if any) occurs, defeating the
/// timing-side-channel attack in which an attacker recovers a secret
/// byte-by-byte by measuring response latency.
///
/// **Length is not treated as secret**: returning early when `a.len() !=
/// b.len()` is acceptable because the attacker can already observe the
/// length they sent, and the legitimate token's length is fixed at
/// configuration time. What the attacker MUST NOT learn is which prefix
/// of their guess agrees with the secret — this function provides that
/// guarantee.
///
/// `std::hint::black_box` wraps the accumulator to prevent the optimiser
/// from short-circuiting once it can prove the result; without the
/// barrier, an aggressive optimiser could in principle convert the
/// constant-time loop into an early-exit comparison.
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

/// Interceptor that validates bearer tokens on incoming requests.
///
/// # Timing safety (br-asupersync-2dro05)
///
/// Two construction paths exist:
///
/// * [`BearerAuthValidator::with_token`] — **safe by default.** The
///   expected token is held inside the validator and compared against
///   the supplied token via [`constant_time_eq`], which never
///   short-circuits on the first byte difference. Use this whenever the
///   accept-set is a fixed set of tokens.
///
/// * [`BearerAuthValidator::new`] — **caller responsibility.** Takes a
///   user-supplied closure `Fn(&str) -> bool`. The closure body is
///   opaque to the library; if it uses Rust string equality (`==`) on
///   the bearer token, an attacker can recover the secret byte-by-byte
///   from response-latency timing (reduces token recovery from
///   O(256^N) to O(256·N) for an ASCII secret of length N). The
///   library cannot fix this from outside the closure. **Callers MUST
///   either** (a) use `with_token`, or (b) implement the closure with
///   [`constant_time_eq`] / `subtle::ConstantTimeEq`.
#[derive(Debug)]
pub struct BearerAuthValidator<F> {
    validator: F,
}

impl<F> BearerAuthValidator<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    /// Create a bearer auth validator from a user-supplied closure.
    ///
    /// **Warning**: the closure's comparison must be constant-time. See
    /// the type-level docs for context. Prefer
    /// [`BearerAuthValidator::with_token`] when the accept-set is a
    /// known secret string.
    pub fn new(validator: F) -> Self {
        Self { validator }
    }
}

impl BearerAuthValidator<Box<dyn Fn(&str) -> bool + Send + Sync>> {
    /// Create a bearer auth validator that accepts exactly the supplied
    /// `expected_token`, comparing in constant time.
    ///
    /// The token is moved into the closure and held for the lifetime of
    /// the validator. The comparison runs through [`constant_time_eq`],
    /// so an attacker cannot recover the token via response-latency
    /// timing.
    #[must_use]
    pub fn with_token(expected_token: impl Into<String>) -> Self {
        let expected = expected_token.into();
        let validator: Box<dyn Fn(&str) -> bool + Send + Sync> =
            Box::new(move |presented: &str| {
                constant_time_eq(presented.as_bytes(), expected.as_bytes())
            });
        Self { validator }
    }
}

impl<F> Interceptor for BearerAuthValidator<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        let auth_value = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;

        let auth_str = metadata_to_string(auth_value)
            .ok_or_else(|| Status::unauthenticated("authorization must be ASCII"))?;

        let token = bearer_token(auth_str)
            .ok_or_else(|| Status::unauthenticated("invalid authorization format"))?;

        if (self.validator)(token) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid token"))
        }
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create an interceptor that validates bearer tokens against a
/// user-supplied closure.
///
/// **Prefer [`auth_validator_with_token`]** for the common case of
/// matching a single fixed token; that variant uses constant-time
/// comparison internally and is timing-side-channel safe by default.
pub fn auth_validator<F>(validator: F) -> BearerAuthValidator<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    BearerAuthValidator::new(validator)
}

/// Create an interceptor that accepts exactly `expected_token`, with
/// constant-time comparison (br-asupersync-2dro05).
#[must_use]
pub fn auth_validator_with_token(
    expected_token: impl Into<String>,
) -> BearerAuthValidator<Box<dyn Fn(&str) -> bool + Send + Sync>> {
    BearerAuthValidator::with_token(expected_token)
}

/// Metadata propagation interceptor.
///
/// Copies specified metadata keys from request to response.
#[derive(Debug, Clone)]
pub struct MetadataPropagator {
    keys: Vec<String>,
}

impl MetadataPropagator {
    /// Create a new metadata propagator.
    ///
    /// br-asupersync-86jc5o: Only accept valid metadata keys to prevent header injection.
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let keys = keys.into_iter();
        let (lower, upper) = keys.size_hint();
        let mut collected_keys = Vec::with_capacity(upper.unwrap_or(lower));
        for key in keys {
            let key_string = key.into();
            // br-asupersync-86jc5o: Validate keys to prevent header injection
            if validate_metadata_key(&key_string) {
                collected_keys.push(key_string);
            }
        }

        Self {
            keys: collected_keys,
        }
    }
}

impl Interceptor for MetadataPropagator {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        // For propagation, we store the keys to propagate in a special metadata entry
        // This is a simplified approach that stores the key names
        let mut keys_to_propagate = Vec::with_capacity(self.keys.len());
        for key in &self.keys {
            if request.metadata().get(key).is_some() {
                keys_to_propagate.push(key.clone());
            }
        }

        if !keys_to_propagate.is_empty() {
            // br-asupersync-pcc2rq: Use space-separated format to prevent comma injection
            // Since keys are validated to contain only alphanumeric, hyphen, underscore,
            // spaces are safe delimiters that cannot appear in valid keys
            let _ = request
                .metadata_mut()
                .insert("x-propagate-keys", keys_to_propagate.join(" "));
        }
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        // Request-derived propagation requires the originating request. Callers
        // that need that behavior must use `intercept_response_with_request()`.
        let _ = response;
        Ok(())
    }

    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        let response_metadata = response.metadata_mut();
        response_metadata.reserve(self.keys.len());

        for key in &self.keys {
            if response_metadata.get(key).is_some() {
                continue;
            }
            if let Some(value) = request.metadata().get(key) {
                copy_metadata_value(response_metadata, key, value);
            }
        }

        Ok(())
    }
}

/// Create a metadata propagation interceptor.
#[must_use]
pub fn metadata_propagator(
    keys: impl IntoIterator<Item = impl Into<String>>,
) -> MetadataPropagator {
    MetadataPropagator::new(keys)
}

/// In-flight request limiting interceptor.
///
/// This limiter caps how many requests may be active at the same time. A slot
/// is acquired during request interception and released once the response path
/// or error path runs. If a request is cancelled before either terminal hook,
/// dropping the request releases the slot. Without those release steps, the
/// counter would monotonically increase and permanently exhaust after enough
/// failing, cancelled, or successful calls.
#[derive(Debug)]
pub struct RateLimitInterceptor {
    /// Maximum concurrent requests allowed.
    max_requests: u32,
    /// Current in-flight request count plus reset generation.
    state: std::sync::Arc<RateLimitState>,
}

#[derive(Debug)]
struct RateLimitState {
    packed: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
struct RateLimitLease {
    state: std::sync::Arc<RateLimitState>,
    generation: u32,
    released: std::sync::atomic::AtomicBool,
}

fn rate_limit_pack(generation: u32, count: u32) -> u64 {
    (u64::from(generation) << 32) | u64::from(count)
}

fn rate_limit_generation(packed: u64) -> u32 {
    let bytes = packed.to_be_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn rate_limit_count(packed: u64) -> u32 {
    let bytes = packed.to_be_bytes();
    u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
}

impl RateLimitLease {
    fn new(state: std::sync::Arc<RateLimitState>, generation: u32) -> Self {
        Self {
            state,
            generation,
            released: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn release(&self) {
        if self
            .released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }

        let mut packed = self.state.packed.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let generation = rate_limit_generation(packed);
            let count = rate_limit_count(packed);
            if generation != self.generation || count == 0 {
                return;
            }

            let next = rate_limit_pack(generation, count - 1);
            match self.state.packed.compare_exchange_weak(
                packed,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => packed = observed,
            }
        }
    }
}

impl Drop for RateLimitLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl RateLimitInterceptor {
    /// Create a new rate limit interceptor.
    #[must_use]
    pub fn new(max_requests: u32) -> Self {
        Self {
            max_requests,
            state: std::sync::Arc::new(RateLimitState {
                packed: std::sync::atomic::AtomicU64::new(rate_limit_pack(0, 0)),
            }),
        }
    }

    fn try_acquire_slot(&self) -> Option<u32> {
        let mut packed = self.state.packed.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let generation = rate_limit_generation(packed);
            let count = rate_limit_count(packed);
            if count >= self.max_requests {
                return None;
            }

            let next = rate_limit_pack(generation, count + 1);
            match self.state.packed.compare_exchange_weak(
                packed,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return Some(generation),
                Err(observed) => packed = observed,
            }
        }
    }

    fn release_slot_from_request(&self, request: &Request<Bytes>) {
        if let Some(lease) = request.extensions().get_typed::<RateLimitLease>() {
            lease.release();
        }
    }

    /// Reset the request counter.
    pub fn reset(&self) {
        let mut packed = self.state.packed.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let next_generation = rate_limit_generation(packed).wrapping_add(1);
            let next = rate_limit_pack(next_generation, 0);
            match self.state.packed.compare_exchange_weak(
                packed,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => packed = observed,
            }
        }
    }

    /// Get the current request count.
    #[must_use]
    pub fn current_count(&self) -> u32 {
        rate_limit_count(self.state.packed.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Interceptor for RateLimitInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        if let Some(generation) = self.try_acquire_slot() {
            request.extensions_mut().insert_typed(RateLimitLease::new(
                std::sync::Arc::clone(&self.state),
                generation,
            ));
            Ok(())
        } else {
            Err(Status::resource_exhausted("rate limit exceeded"))
        }
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }

    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        _response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        self.release_slot_from_request(request);
        Ok(())
    }

    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        _status: &mut Status,
    ) -> Result<(), Status> {
        self.release_slot_from_request(request);
        Ok(())
    }
}

/// Create a rate limiting interceptor.
#[must_use]
pub fn rate_limiter(max_requests: u32) -> RateLimitInterceptor {
    RateLimitInterceptor::new(max_requests)
}

/// Logging interceptor that marks requests for logging.
#[derive(Debug, Clone, Default)]
pub struct LoggingInterceptor {
    /// Log level for requests.
    log_requests: bool,
    /// Log level for responses.
    log_responses: bool,
}

impl LoggingInterceptor {
    /// Create a new logging interceptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            log_requests: true,
            log_responses: true,
        }
    }

    /// Configure request logging.
    #[must_use]
    pub fn log_requests(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }

    /// Configure response logging.
    #[must_use]
    pub fn log_responses(mut self, enabled: bool) -> Self {
        self.log_responses = enabled;
        self
    }
}

impl Interceptor for LoggingInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        if self.log_requests {
            // Mark the request as logged via metadata
            let _ = request.metadata_mut().insert("x-logged", "true");
        }
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        if self.log_responses {
            let _ = response.metadata_mut().insert("x-logged", "true");
        }
        Ok(())
    }
}

/// Create a logging interceptor.
#[must_use]
pub fn logging_interceptor() -> LoggingInterceptor {
    LoggingInterceptor::new()
}

/// Timeout interceptor that adds deadline metadata.
#[derive(Debug, Clone)]
pub struct TimeoutInterceptor {
    /// Timeout in milliseconds.
    timeout_ms: u64,
}

impl TimeoutInterceptor {
    /// Create a new timeout interceptor.
    #[must_use]
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }
}

impl Interceptor for TimeoutInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        // br-asupersync-wvn2dm: Sanitize timeout value to prevent header injection
        let timeout_value = match request.metadata().get("grpc-timeout") {
            Some(MetadataValue::Ascii(value)) => {
                match parse_grpc_timeout(value) {
                    Some(_parsed_duration) => {
                        // Sanitize the original value by removing CRLF characters
                        value
                            .chars()
                            .filter(|&c| c != '\r' && c != '\n')
                            .collect::<String>()
                    }
                    None => format_grpc_timeout(Duration::from_millis(self.timeout_ms)),
                }
            }
            _ => format_grpc_timeout(Duration::from_millis(self.timeout_ms)),
        };
        let _ = request
            .metadata_mut()
            .insert_or_replace("grpc-timeout", timeout_value);
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create a timeout interceptor.
#[must_use]
pub fn timeout_interceptor(timeout_ms: u64) -> TimeoutInterceptor {
    TimeoutInterceptor::new(timeout_ms)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use crate::grpc::Code;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Debug)]
    struct ResponseOrderInterceptor {
        name: &'static str,
        calls: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl Interceptor for ResponseOrderInterceptor {
        fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
            Ok(())
        }

        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            Ok(())
        }

        fn intercept_response_with_request(
            &self,
            _request: &Request<Bytes>,
            _response: &mut Response<Bytes>,
        ) -> Result<(), Status> {
            self.calls.lock().unwrap().push(self.name);
            Ok(())
        }
    }

    #[test]
    fn interceptor_layer_empty() {
        init_test("interceptor_layer_empty");
        let layer = InterceptorLayer::new();
        let empty = layer.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = layer.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("interceptor_layer_empty");
    }

    #[test]
    fn interceptor_layer_chain() {
        init_test("interceptor_layer_chain");
        let layer = InterceptorLayer::new()
            .layer(trace_interceptor())
            .layer(logging_interceptor());

        let empty = layer.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);
        let len = layer.len();
        crate::assert_with_log!(len == 2, "len", 2, len);
        crate::test_complete!("interceptor_layer_chain");
    }

    #[test]
    fn interceptor_layer_request() {
        init_test("interceptor_layer_request");
        let layer = InterceptorLayer::new().layer(trace_interceptor());

        let mut request = Request::new(Bytes::new());
        layer.intercept_request(&mut request).unwrap();

        let has_id = request.metadata().get("x-request-id").is_some();
        crate::assert_with_log!(has_id, "request id", true, has_id);
        crate::test_complete!("interceptor_layer_request");
    }

    #[test]
    fn bearer_auth_interceptor() {
        init_test("bearer_auth_interceptor");
        let interceptor = auth_bearer_interceptor("my-token");

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let auth = request.metadata().get("authorization").unwrap();
        let ok = matches!(auth, MetadataValue::Ascii(s) if s == "Bearer my-token");
        crate::assert_with_log!(ok, "auth header", true, ok);
        crate::test_complete!("bearer_auth_interceptor");
    }

    #[test]
    fn constant_time_eq_correctness() {
        // br-asupersync-2dro05: the timing-safe byte comparison must
        // return the same boolean as ordinary equality for *any* input
        // shape — equal-length differing-first-byte, equal-length
        // differing-last-byte, mismatched lengths, empty inputs, the
        // identical-pointer case. This test pins the *correctness*
        // surface; timing-side-channel resistance is a property of the
        // algorithm (no early-exit) and the `black_box` barrier rather
        // than something a unit test can measure directly.
        init_test("constant_time_eq_correctness");
        // Identical content.
        crate::assert_with_log!(
            super::constant_time_eq(b"hello", b"hello"),
            "identical",
            true,
            super::constant_time_eq(b"hello", b"hello")
        );
        // Differing first byte (would short-circuit fastest under naive ==).
        crate::assert_with_log!(
            !super::constant_time_eq(b"Xello", b"hello"),
            "first-byte differ",
            false,
            super::constant_time_eq(b"Xello", b"hello")
        );
        // Differing last byte (would short-circuit slowest under naive ==).
        crate::assert_with_log!(
            !super::constant_time_eq(b"hellX", b"hello"),
            "last-byte differ",
            false,
            super::constant_time_eq(b"hellX", b"hello")
        );
        // Mismatched lengths: length is not secret; early-return is OK.
        crate::assert_with_log!(
            !super::constant_time_eq(b"hello", b"hellos"),
            "length mismatch (longer)",
            false,
            super::constant_time_eq(b"hello", b"hellos")
        );
        crate::assert_with_log!(
            !super::constant_time_eq(b"hello", b"hell"),
            "length mismatch (shorter)",
            false,
            super::constant_time_eq(b"hello", b"hell")
        );
        // Both empty.
        crate::assert_with_log!(
            super::constant_time_eq(b"", b""),
            "both empty",
            true,
            super::constant_time_eq(b"", b"")
        );
        // One empty, one not.
        crate::assert_with_log!(
            !super::constant_time_eq(b"", b"x"),
            "empty vs non-empty",
            false,
            super::constant_time_eq(b"", b"x")
        );
        // Black-box wrapping: a hostile optimiser cannot fold the
        // comparison into a constant when both sides are computed at
        // runtime. We exercise that with `std::hint::black_box`-wrapped
        // inputs.
        let a = std::hint::black_box(b"super-secret-bearer-token-abcdefg".to_vec());
        let b = std::hint::black_box(b"super-secret-bearer-token-XXXXXXX".to_vec());
        crate::assert_with_log!(
            !super::constant_time_eq(&a, &b),
            "differing tail under black_box",
            false,
            super::constant_time_eq(&a, &b)
        );
        let c = std::hint::black_box(b"super-secret-bearer-token-abcdefg".to_vec());
        crate::assert_with_log!(
            super::constant_time_eq(&a, &c),
            "matching under black_box",
            true,
            super::constant_time_eq(&a, &c)
        );
        crate::test_complete!("constant_time_eq_correctness");
    }

    #[test]
    fn bearer_auth_validator_with_token_accepts_correct_token() {
        // br-asupersync-2dro05: the constant-time `with_token`
        // constructor accepts the exact configured token.
        init_test("bearer_auth_validator_with_token_accepts_correct_token");
        let interceptor = auth_validator_with_token("super-secret-token");
        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer super-secret-token");
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "with_token accepts correct", true, ok);
        crate::test_complete!("bearer_auth_validator_with_token_accepts_correct_token");
    }

    #[test]
    fn bearer_auth_validator_with_token_rejects_wrong_token_at_any_position() {
        // br-asupersync-2dro05: with_token must reject every
        // wrong-token shape — first-byte differ, last-byte differ,
        // shorter, longer — without ever returning `Ok`. The
        // *correctness* surface mirrors what an attacker would probe;
        // timing equivalence across these shapes is the security
        // property `constant_time_eq` provides.
        init_test("bearer_auth_validator_with_token_rejects_wrong_token_at_any_position");
        let interceptor = auth_validator_with_token("super-secret-token");
        for wrong in [
            "Xuper-secret-token",  // first-byte differ
            "super-secret-tokeX",  // last-byte differ
            "super-secret-toke",   // shorter
            "super-secret-tokens", // longer
            "totally-different",   // unrelated
            "",                    // empty
        ] {
            let mut request = Request::new(Bytes::new());
            let header = format!("Bearer {wrong}");
            request.metadata_mut().insert("authorization", &header);
            let err = interceptor.intercept_request(&mut request).is_err();
            crate::assert_with_log!(err, "with_token rejects wrong token", true, err);
        }
        crate::test_complete!(
            "bearer_auth_validator_with_token_rejects_wrong_token_at_any_position"
        );
    }

    #[test]
    fn bearer_auth_validator_success() {
        init_test("bearer_auth_validator_success");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer valid-token");

        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "intercept ok", true, ok);
        crate::test_complete!("bearer_auth_validator_success");
    }

    #[test]
    fn bearer_auth_validator_invalid() {
        init_test("bearer_auth_validator_invalid");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer invalid-token");

        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_invalid");
    }

    #[test]
    fn bearer_auth_validator_missing() {
        init_test("bearer_auth_validator_missing");
        let interceptor = auth_validator(|_| true);

        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_missing");
    }

    #[test]
    fn bearer_auth_validator_accepts_case_insensitive_scheme() {
        init_test("bearer_auth_validator_accepts_case_insensitive_scheme");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "bEaReR valid-token");

        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "intercept ok", true, ok);
        crate::test_complete!("bearer_auth_validator_accepts_case_insensitive_scheme");
    }

    #[test]
    fn bearer_auth_validator_rejects_empty_token() {
        init_test("bearer_auth_validator_rejects_empty_token");
        let interceptor = auth_validator(|_| true);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("authorization", "Bearer ");

        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_rejects_empty_token");
    }

    #[test]
    fn metadata_propagator_marks_keys() {
        init_test("metadata_propagator_marks_keys");
        let interceptor = metadata_propagator(["x-request-id", "x-trace-id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");
        request.metadata_mut().insert("x-trace-id", "trace-456");

        interceptor.intercept_request(&mut request).unwrap();

        match request.metadata().get("x-propagate-keys") {
            Some(MetadataValue::Ascii(keys)) => {
                crate::assert_with_log!(
                    keys == "x-request-id x-trace-id",
                    "space-delimited propagate keys",
                    "x-request-id x-trace-id",
                    keys
                );
                let has_comma_separator = keys.contains(",x-trace-id")
                    || keys.contains("x-request-id,")
                    || keys.contains(',');
                crate::assert_with_log!(
                    !has_comma_separator,
                    "comma separator removed",
                    false,
                    has_comma_separator
                );
            }
            other => panic!("expected x-propagate-keys metadata, got: {other:?}"),
        }
        crate::test_complete!("metadata_propagator_marks_keys");
    }

    #[test]
    fn metadata_propagator_rejects_comma_keys() {
        init_test("metadata_propagator_rejects_comma_keys");
        let interceptor = metadata_propagator(["x-request-id", "x,trace,id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");

        interceptor.intercept_request(&mut request).unwrap();

        match request.metadata().get("x-propagate-keys") {
            Some(MetadataValue::Ascii(keys)) => {
                crate::assert_with_log!(
                    keys == "x-request-id",
                    "invalid comma key dropped",
                    "x-request-id",
                    keys
                );
            }
            other => panic!("expected x-propagate-keys metadata, got: {other:?}"),
        }
        crate::test_complete!("metadata_propagator_rejects_comma_keys");
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        init_test("rate_limiter_allows_under_limit");
        let interceptor = rate_limiter(10);
        let mut admitted = Vec::new();

        for _ in 0..10 {
            let mut request = Request::new(Bytes::new());
            let ok = interceptor.intercept_request(&mut request).is_ok();
            crate::assert_with_log!(ok, "intercept ok", true, ok);
            admitted.push(request);
        }

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 10, "count", 10, count);
        drop(admitted);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after drop", 0, count);
        crate::test_complete!("rate_limiter_allows_under_limit");
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        init_test("rate_limiter_rejects_over_limit");
        let interceptor = rate_limiter(2);

        let mut first_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut first_request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut second_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut second_request).is_ok();
        crate::assert_with_log!(ok, "second ok", true, ok);

        let mut rejected_request = Request::new(Bytes::new());
        let err = interceptor
            .intercept_request(&mut rejected_request)
            .unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::ResourceExhausted,
            "code",
            Code::ResourceExhausted,
            code
        );
        crate::test_complete!("rate_limiter_rejects_over_limit");
    }

    #[test]
    fn rate_limiter_reset() {
        init_test("rate_limiter_reset");
        let interceptor = rate_limiter(1);

        let mut first_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut first_request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut rejected_request = Request::new(Bytes::new());
        let err = interceptor
            .intercept_request(&mut rejected_request)
            .is_err();
        crate::assert_with_log!(err, "second err", true, err);

        interceptor.reset();
        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count", 0, count);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "after reset ok", true, ok);
        crate::test_complete!("rate_limiter_reset");
    }

    #[test]
    fn rate_limiter_reset_ignores_stale_pre_reset_lease_drop() {
        init_test("rate_limiter_reset_ignores_stale_pre_reset_lease_drop");
        let interceptor = rate_limiter(2);

        let mut stale_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut stale_request).is_ok();
        crate::assert_with_log!(ok, "stale request ok", true, ok);

        interceptor.reset();

        let mut fresh_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut fresh_request).is_ok();
        crate::assert_with_log!(ok, "fresh request ok", true, ok);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 1, "fresh count", 1, count);

        drop(stale_request);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 1, "count after stale drop", 1, count);

        drop(fresh_request);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after fresh drop", 0, count);
        crate::test_complete!("rate_limiter_reset_ignores_stale_pre_reset_lease_drop");
    }

    #[test]
    fn rate_limiter_releases_slot_on_response() {
        init_test("rate_limiter_releases_slot_on_response");
        let interceptor = rate_limiter(1);

        let mut first_request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut first_request).unwrap();

        let mut blocked_request = Request::new(Bytes::new());
        let blocked = interceptor.intercept_request(&mut blocked_request).is_err();
        crate::assert_with_log!(
            blocked,
            "second blocked while first inflight",
            true,
            blocked
        );

        let mut response = Response::new(Bytes::new());
        interceptor
            .intercept_response_with_request(&first_request, &mut response)
            .unwrap();

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after release", 0, count);

        let mut retry_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut retry_request).is_ok();
        crate::assert_with_log!(ok, "request after response ok", true, ok);
        crate::test_complete!("rate_limiter_releases_slot_on_response");
    }

    #[test]
    fn rate_limiter_response_without_request_does_not_underflow() {
        init_test("rate_limiter_response_without_request_does_not_underflow");
        let interceptor = rate_limiter(1);

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count stays at zero", 0, count);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "request after stray response ok", true, ok);
        crate::test_complete!("rate_limiter_response_without_request_does_not_underflow");
    }

    #[test]
    fn timeout_interceptor_adds_header() {
        init_test("timeout_interceptor_adds_header");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "5S");
        crate::assert_with_log!(ok, "timeout header", true, ok);
        crate::test_complete!("timeout_interceptor_adds_header");
    }

    #[test]
    fn timeout_interceptor_uses_valid_eight_digit_timeout_header() {
        init_test("timeout_interceptor_uses_valid_eight_digit_timeout_header");
        let interceptor = timeout_interceptor(100_000_000);

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "100000S");
        crate::assert_with_log!(ok, "large timeout header stays valid", true, ok);
        crate::test_complete!("timeout_interceptor_uses_valid_eight_digit_timeout_header");
    }

    #[test]
    fn timeout_interceptor_preserves_existing() {
        init_test("timeout_interceptor_preserves_existing");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "1000m");

        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "1000m");
        crate::assert_with_log!(ok, "timeout header", true, ok);
        crate::test_complete!("timeout_interceptor_preserves_existing");
    }

    #[test]
    fn timeout_interceptor_repairs_malformed_existing_header() {
        init_test("timeout_interceptor_repairs_malformed_existing_header");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "bogus");

        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "5S");
        crate::assert_with_log!(ok, "malformed timeout repaired", true, ok);

        let timeout_count = request
            .metadata()
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        crate::assert_with_log!(
            timeout_count == 1,
            "repaired timeout replaces invalid duplicate",
            1,
            timeout_count
        );
        crate::test_complete!("timeout_interceptor_repairs_malformed_existing_header");
    }

    #[test]
    fn fn_interceptor_custom() {
        init_test("fn_interceptor_custom");
        let interceptor = fn_interceptor(|request: &mut Request<Bytes>| {
            request.metadata_mut().insert("x-custom", "value");
            Ok(())
        });

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let value = request.metadata().get("x-custom").unwrap();
        let ok = matches!(value, MetadataValue::Ascii(s) if s == "value");
        crate::assert_with_log!(ok, "custom header", true, ok);
        crate::test_complete!("fn_interceptor_custom");
    }

    #[test]
    fn logging_interceptor_marks_request() {
        init_test("logging_interceptor_marks_request");
        let interceptor = logging_interceptor();

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let logged = request.metadata().get("x-logged").is_some();
        crate::assert_with_log!(logged, "logged header", true, logged);
        crate::test_complete!("logging_interceptor_marks_request");
    }

    #[test]
    fn logging_interceptor_marks_response() {
        init_test("logging_interceptor_marks_response");
        let interceptor = logging_interceptor();

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let logged = response.metadata().get("x-logged").is_some();
        crate::assert_with_log!(logged, "logged header", true, logged);
        crate::test_complete!("logging_interceptor_marks_response");
    }

    #[test]
    fn metadata_propagator_copies_selected_request_metadata_to_response() {
        init_test("metadata_propagator_copies_selected_request_metadata_to_response");
        let interceptor = metadata_propagator(["x-request-id", "x-trace-id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");
        request.metadata_mut().insert("x-trace-id", "trace-456");
        request.metadata_mut().insert("x-unrelated", "skip-me");

        let mut response = Response::new(Bytes::new());
        interceptor
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let request_id = response.metadata().get("x-request-id");
        let trace_id = response.metadata().get("x-trace-id");
        let unrelated = response.metadata().get("x-unrelated");

        let request_id_ok =
            matches!(request_id, Some(MetadataValue::Ascii(value)) if value == "req-123");
        let trace_id_ok =
            matches!(trace_id, Some(MetadataValue::Ascii(value)) if value == "trace-456");
        crate::assert_with_log!(request_id_ok, "request id propagated", true, request_id_ok);
        crate::assert_with_log!(trace_id_ok, "trace id propagated", true, trace_id_ok);
        crate::assert_with_log!(
            unrelated.is_none(),
            "unrelated absent",
            true,
            unrelated.is_none()
        );
        crate::test_complete!("metadata_propagator_copies_selected_request_metadata_to_response");
    }

    #[test]
    fn metadata_propagator_response_only_hook_is_requestless_noop() {
        init_test("metadata_propagator_response_only_hook_is_requestless_noop");
        let interceptor = metadata_propagator(["x-request-id"]);

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let propagated = response.metadata().get("x-request-id");
        crate::assert_with_log!(
            propagated.is_none(),
            "response-only hook does not invent request metadata",
            true,
            propagated.is_none()
        );
        crate::test_complete!("metadata_propagator_response_only_hook_is_requestless_noop");
    }

    #[test]
    fn interceptor_layer_request_aware_response_hook_preserves_composition() {
        init_test("interceptor_layer_request_aware_response_hook_preserves_composition");
        let layer = InterceptorLayer::new()
            .layer(logging_interceptor())
            .layer(metadata_propagator(["x-request-id"]));

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");

        let mut response = Response::new(Bytes::new());
        layer
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let logged = response.metadata().get("x-logged");
        let request_id = response.metadata().get("x-request-id");
        let logged_ok = matches!(logged, Some(MetadataValue::Ascii(value)) if value == "true");
        let request_id_ok =
            matches!(request_id, Some(MetadataValue::Ascii(value)) if value == "req-123");
        crate::assert_with_log!(logged_ok, "logging interceptor still runs", true, logged_ok);
        crate::assert_with_log!(
            request_id_ok,
            "request-aware propagation copies metadata",
            true,
            request_id_ok
        );
        crate::test_complete!(
            "interceptor_layer_request_aware_response_hook_preserves_composition"
        );
    }

    #[test]
    fn interceptor_layer_request_aware_response_hook_runs_in_reverse_order() {
        init_test("interceptor_layer_request_aware_response_hook_runs_in_reverse_order");

        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = InterceptorLayer::new()
            .layer(ResponseOrderInterceptor {
                name: "outer",
                calls: std::sync::Arc::clone(&calls),
            })
            .layer(ResponseOrderInterceptor {
                name: "inner",
                calls: std::sync::Arc::clone(&calls),
            });

        let request = Request::new(Bytes::new());
        let mut response = Response::new(Bytes::new());
        layer
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let calls = calls.lock().unwrap().clone();
        crate::assert_with_log!(
            calls == vec!["inner", "outer"],
            "request-aware response order",
            vec!["inner", "outer"],
            calls
        );
        crate::test_complete!(
            "interceptor_layer_request_aware_response_hook_runs_in_reverse_order"
        );
    }

    #[test]
    fn tracing_interceptor_generates_request_id() {
        init_test("tracing_interceptor_generates_request_id");
        let interceptor = trace_interceptor();

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let id = request.metadata().get("x-request-id").unwrap();
        let ok = matches!(id, MetadataValue::Ascii(s) if s.starts_with("req-"));
        crate::assert_with_log!(ok, "request id", true, ok);
        crate::test_complete!("tracing_interceptor_generates_request_id");
    }

    #[test]
    fn tracing_interceptor_uses_deterministic_sequential_ids() {
        init_test("tracing_interceptor_uses_deterministic_sequential_ids");
        let interceptor = trace_interceptor();
        let cloned = interceptor.clone();

        let mut first = Request::new(Bytes::new());
        interceptor.intercept_request(&mut first).unwrap();
        let first_id = first.metadata().get("x-request-id").unwrap();

        let mut second = Request::new(Bytes::new());
        cloned.intercept_request(&mut second).unwrap();
        let second_id = second.metadata().get("x-request-id").unwrap();

        let ok = matches!(
            (first_id, second_id),
            (MetadataValue::Ascii(first), MetadataValue::Ascii(second))
                if first == "req-0000000000000001" && second == "req-0000000000000002"
        );
        crate::assert_with_log!(ok, "sequential request ids", true, ok);
        crate::test_complete!("tracing_interceptor_uses_deterministic_sequential_ids");
    }

    #[test]
    fn tracing_interceptor_replaces_unsigned_client_request_id_by_default() {
        init_test("tracing_interceptor_replaces_unsigned_client_request_id_by_default");
        let interceptor = trace_interceptor();

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        crate::assert_with_log!(ok, "unsigned client request id replaced", true, ok);
        crate::test_complete!("tracing_interceptor_replaces_unsigned_client_request_id_by_default");
    }

    #[test]
    fn tracing_interceptor_preserves_signed_request_id() {
        init_test("tracing_interceptor_preserves_signed_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|id: &str, sig: &str| {
                id == "req-client" && sig == "valid"
            });

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "valid");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-client"
        );
        crate::assert_with_log!(ok, "signed request id preserved", true, ok);
        crate::test_complete!("tracing_interceptor_preserves_signed_request_id");
    }

    #[test]
    fn tracing_interceptor_replaces_invalid_signature_request_id() {
        init_test("tracing_interceptor_replaces_invalid_signature_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|_: &str, _: &str| false);

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "invalid");
        interceptor.intercept_request(&mut request).unwrap();

        let replaced = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        let signature_scrubbed = request
            .metadata()
            .get(REQUEST_ID_SIGNATURE_METADATA_KEY)
            .is_none();
        crate::assert_with_log!(replaced, "invalid signature id replaced", true, replaced);
        crate::assert_with_log!(
            signature_scrubbed,
            "invalid signature scrubbed",
            true,
            signature_scrubbed
        );
        crate::test_complete!("tracing_interceptor_replaces_invalid_signature_request_id");
    }

    #[test]
    fn tracing_interceptor_replaces_empty_signed_request_id() {
        init_test("tracing_interceptor_replaces_empty_signed_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|_: &str, _: &str| true);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert(REQUEST_ID_METADATA_KEY, "");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "valid");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        crate::assert_with_log!(ok, "empty request id replaced", true, ok);
        crate::test_complete!("tracing_interceptor_replaces_empty_signed_request_id");
    }

    #[test]
    fn tracing_interceptor_trusted_edge_preserves_existing_request_id() {
        init_test("tracing_interceptor_trusted_edge_preserves_existing_request_id");
        let interceptor = trace_interceptor().with_trusted_client_request_ids();

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-custom");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-custom"
        );
        crate::assert_with_log!(ok, "trusted-edge request id preserved", true, ok);
        crate::test_complete!("tracing_interceptor_trusted_edge_preserves_existing_request_id");
    }
}
