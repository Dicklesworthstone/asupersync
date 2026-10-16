//! gRPC interceptor middleware.
//!
//! Provides a layer-based interceptor pattern for processing gRPC requests
//! and responses. Interceptors can be used for authentication, logging,
//! tracing, metrics, and other cross-cutting concerns.
//!
//! # Cross-interceptor state: `AuthContext`
//!
//! When an authentication interceptor (e.g. [`BearerAuthInterceptor`] or a
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
//! ```
//! use asupersync::bytes::Bytes;
//! use asupersync::grpc::interceptor::{InterceptorLayer, trace_interceptor, auth_bearer_interceptor};
//! use asupersync::grpc::{Interceptor, MetadataValue, Request, Status};
//!
//! // Create a layered interceptor chain
//! let interceptor = InterceptorLayer::new()
//!     .layer(trace_interceptor())
//!     .layer(auth_bearer_interceptor("my-token"));
//!
//! // Apply it to an outgoing request. `intercept_request` is the
//! // `Interceptor` trait method and edits the request in place.
//! let mut request = Request::new(Bytes::new());
//! interceptor.intercept_request(&mut request)?;
//! assert!(matches!(
//!     request.metadata().get("authorization"),
//!     Some(MetadataValue::Ascii(value)) if value == "Bearer my-token"
//! ));
//! # Ok::<(), Status>(())
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

/// W3C trace context metadata keys this interceptor reads and rewrites.
const W3C_TRACE_CONTEXT_KEYS: [&str; 3] = ["traceparent", "tracestate", "baggage"];

/// Interceptor that continues a request's W3C trace context or starts one.
///
/// On every request it reads `traceparent`, `tracestate` and `baggage` from
/// the metadata and replaces them with a child span of that context; a
/// missing or invalid `traceparent` starts a new trace (see
/// [`continue_or_start_trace`](crate::observability::w3c_trace_context::continue_or_start_trace)).
/// An interceptor gets no `Cx`, so new ids come from the operating system's
/// random source.
/// - On a client, each outgoing call gets its own span. To continue the
///   caller's trace, copy the caller's `traceparent` (and `tracestate`,
///   `baggage`) into the request metadata before the call.
/// - On a server, the handler finds its own span in the request metadata.
///
/// A client picks the trace id it sends; at an untrusted edge, either accept
/// that (the usual W3C deployment) or reset `traceparent` at a gateway first.
#[derive(Debug, Clone, Copy, Default)]
pub struct W3CTraceContextInterceptor;

impl W3CTraceContextInterceptor {
    /// Create a W3C trace context interceptor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Interceptor for W3CTraceContextInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        let incoming: std::collections::HashMap<String, String> = W3C_TRACE_CONTEXT_KEYS
            .into_iter()
            .filter_map(|key| {
                let value = metadata_to_string(request.metadata().get(key)?)?;
                Some((key.to_string(), value.to_string()))
            })
            .collect();
        let context = crate::observability::w3c_trace_context::continue_or_start_trace(&incoming);
        let mut outgoing = std::collections::HashMap::new();
        crate::observability::w3c_trace_context::inject_to_grpc(&context, &mut outgoing);
        let metadata = request.metadata_mut();
        // Keys are written in a fixed order. A key the new context does not
        // carry (for example the tracestate of an invalid traceparent) must
        // not survive from the incoming request.
        for key in W3C_TRACE_CONTEXT_KEYS {
            let _ = metadata.remove(key);
            if let Some(value) = outgoing.remove(key) {
                let _ = metadata.insert_or_replace(key, value);
            }
        }
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Create a W3C trace context interceptor.
#[must_use]
pub fn w3c_trace_context_interceptor() -> W3CTraceContextInterceptor {
    W3CTraceContextInterceptor::new()
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
///   the supplied token via `constant_time_eq`, which never
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
///   `constant_time_eq` / `subtle::ConstantTimeEq`.
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
    /// the validator. The comparison runs through `constant_time_eq`,
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

/// Every rate-limit lease a request holds, one per limiter in the chain.
/// Request extensions keep one value per type, so a lease stored on its own
/// was replaced by the next limiter's, and dropping it released the first
/// limiter's slot while the request was still in flight.
#[derive(Debug)]
struct RateLimitLeases(Vec<std::sync::Arc<RateLimitLease>>);

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
        if let Some(leases) = request.extensions().get_typed::<RateLimitLeases>() {
            for lease in leases
                .0
                .iter()
                .filter(|lease| std::sync::Arc::ptr_eq(&lease.state, &self.state))
            {
                lease.release();
            }
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
            let mut leases = request
                .extensions()
                .get_typed::<RateLimitLeases>()
                .map_or_else(Vec::new, |held| held.0.clone());
            leases.push(std::sync::Arc::new(RateLimitLease::new(
                std::sync::Arc::clone(&self.state),
                generation,
            )));
            request
                .extensions_mut()
                .insert_typed(RateLimitLeases(leases));
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
#[path = "interceptor_inline_tests.rs"]
mod tests;
