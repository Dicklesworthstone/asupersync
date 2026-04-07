//! Combinator middleware for HTTP handlers.
//!
//! This module bridges Asupersync's composable combinators (circuit breaker,
//! retry, timeout, rate limit, bulkhead) with the web framework's [`Handler`]
//! trait, enabling resilience patterns as middleware layers.
//!
//! # Architecture
//!
//! Each middleware wraps an inner [`Handler`] and applies a combinator before
//! or around the handler invocation. Middleware implements [`Handler`] itself,
//! so they compose naturally.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::middleware::*;
//! use asupersync::web::{Router, get};
//! use asupersync::combinator::*;
//! use std::time::Duration;
//!
//! let handler = FnHandler::new(|| "hello");
//!
//! // Single middleware
//! let protected = TimeoutMiddleware::new(handler, Duration::from_secs(5));
//!
//! // Composed middleware (outermost applied first)
//! let resilient = MiddlewareStack::new(handler)
//!     .with_timeout(Duration::from_secs(5))
//!     .with_rate_limit(RateLimitPolicy::default())
//!     .with_circuit_breaker(CircuitBreakerPolicy::default())
//!     .build();
//! ```
//!
//! # Execution Order
//!
//! When composing middleware via [`MiddlewareStack`], the order is outermost
//! first. For a stack built as `.with_timeout().with_rate_limit()`:
//!
//! ```text
//! Request → Timeout → RateLimit → Handler → Response
//! ```

use std::convert::Infallible;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::combinator::bulkhead::{Bulkhead, BulkheadPolicy};
use crate::combinator::circuit_breaker::{CircuitBreaker, CircuitBreakerPolicy};
use crate::combinator::rate_limit::{RateLimitPolicy, RateLimiter};
use crate::combinator::retry::RetryPolicy;
use crate::http::compress::{ContentEncoding, make_compressor, negotiate_encoding};
use crate::tracing_compat::{debug, warn};
use crate::types::Time;

use super::extract::Request;
use super::handler::Handler;
use super::response::{Response, StatusCode};

// ─── CorsMiddleware ─────────────────────────────────────────────────────────

/// Origin matching policy for CORS headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsAllowOrigin {
    /// Allow any origin (`*`).
    Any,
    /// Allow only the provided set of explicit origins.
    Exact(Vec<String>),
}

/// CORS policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsPolicy {
    /// Allowed origins.
    pub allow_origin: CorsAllowOrigin,
    /// Allowed methods for preflight responses.
    pub allow_methods: Vec<String>,
    /// Allowed headers for preflight responses.
    pub allow_headers: Vec<String>,
    /// Exposed headers for non-preflight responses.
    pub expose_headers: Vec<String>,
    /// Optional max-age for preflight cache.
    pub max_age: Option<Duration>,
    /// Whether credentials are allowed.
    pub allow_credentials: bool,
}

impl Default for CorsPolicy {
    fn default() -> Self {
        Self {
            allow_origin: CorsAllowOrigin::Any,
            allow_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_headers: vec!["*".to_string()],
            expose_headers: Vec::new(),
            max_age: Some(Duration::from_mins(10)),
            allow_credentials: false,
        }
    }
}

impl CorsPolicy {
    /// Allow only the provided origins.
    #[must_use]
    pub fn with_exact_origins(origins: impl IntoIterator<Item = String>) -> Self {
        Self {
            allow_origin: CorsAllowOrigin::Exact(origins.into_iter().collect()),
            ..Self::default()
        }
    }
}

/// Middleware that applies CORS policy and handles preflight requests.
pub struct CorsMiddleware<H> {
    inner: H,
    policy: CorsPolicy,
}

impl<H: Handler> CorsMiddleware<H> {
    /// Wrap a handler with CORS policy.
    #[must_use]
    pub fn new(inner: H, policy: CorsPolicy) -> Self {
        Self { inner, policy }
    }

    fn is_preflight(req: &Request) -> bool {
        req.method.eq_ignore_ascii_case("OPTIONS")
            && header_value(req, "origin").is_some()
            && header_value(req, "access-control-request-method").is_some()
    }

    fn allowed_origin_value(&self, origin: &str) -> Option<String> {
        match &self.policy.allow_origin {
            CorsAllowOrigin::Any => {
                if self.policy.allow_credentials {
                    Some(origin.to_string())
                } else {
                    Some("*".to_string())
                }
            }
            CorsAllowOrigin::Exact(origins) => origins
                .iter()
                .find(|candidate| candidate.eq_ignore_ascii_case(origin))
                .cloned(),
        }
    }

    fn apply_common_headers(&self, mut resp: Response, allow_origin: &str) -> Response {
        resp.headers.insert(
            "access-control-allow-origin".to_string(),
            allow_origin.to_string(),
        );
        // Cache key must vary by Origin when policy is origin-sensitive.
        // Use append (not insert) to preserve existing Vary tokens set by
        // the inner handler or other middleware (e.g., accept-encoding).
        append_vary_header(&mut resp, "origin");
        if self.policy.allow_credentials {
            resp.headers.insert(
                "access-control-allow-credentials".to_string(),
                "true".to_string(),
            );
        }
        if !self.policy.expose_headers.is_empty() {
            resp.headers.insert(
                "access-control-expose-headers".to_string(),
                self.policy.expose_headers.join(", "),
            );
        }
        resp
    }
}

impl<H: Handler> Handler for CorsMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let Some(origin) = header_value(&req, "origin") else {
            return self.inner.call(req);
        };

        let Some(allow_origin) = self.allowed_origin_value(&origin) else {
            // Origin not allowed: pass through without CORS headers.
            return self.inner.call(req);
        };

        if Self::is_preflight(&req) {
            let mut resp = Response::empty(StatusCode::NO_CONTENT);
            resp = self.apply_common_headers(resp, &allow_origin);
            resp.headers.insert(
                "access-control-allow-methods".to_string(),
                self.policy.allow_methods.join(", "),
            );
            resp.headers.insert(
                "access-control-allow-headers".to_string(),
                self.policy.allow_headers.join(", "),
            );
            if let Some(max_age) = self.policy.max_age {
                resp.headers.insert(
                    "access-control-max-age".to_string(),
                    max_age.as_secs().to_string(),
                );
            }
            append_vary_header(&mut resp, "origin");
            append_vary_header(&mut resp, "access-control-request-method");
            append_vary_header(&mut resp, "access-control-request-headers");
            return resp;
        }

        let resp = self.inner.call(req);
        self.apply_common_headers(resp, &allow_origin)
    }
}

fn header_value(req: &Request, header_name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(header_name))
        .map(|(_, value)| value.clone())
}

fn append_vary_header(resp: &mut Response, token: &str) {
    fn push_vary_token(tokens: &mut Vec<String>, token: &str) {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return;
        }
        if tokens
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&normalized))
        {
            return;
        }
        tokens.push(normalized);
    }

    let mut tokens = Vec::new();
    for (name, value) in &resp.headers {
        if !name.eq_ignore_ascii_case("vary") {
            continue;
        }
        for existing in value.split(',') {
            push_vary_token(&mut tokens, existing);
        }
    }
    push_vary_token(&mut tokens, token);

    if tokens.is_empty() {
        resp.remove_header("vary");
        return;
    }

    resp.remove_header("vary");
    resp.set_header("vary", tokens.join(", "));
}

fn normalize_header_name(name: impl Into<String>) -> String {
    name.into().to_ascii_lowercase()
}

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

// ─── TimeoutMiddleware ──────────────────────────────────────────────────────

/// Middleware that enforces a request deadline.
///
/// If the handler does not complete before the timeout, a 504 Gateway Timeout
/// response is returned. In Phase 0 (synchronous handlers), this checks
/// elapsed wall-clock time after the handler returns.
///
/// For true preemptive timeout, async runtime integration is required (Phase 1+).
pub struct TimeoutMiddleware<H> {
    inner: H,
    timeout: Duration,
    time_getter: fn() -> Time,
}

impl<H: Handler> TimeoutMiddleware<H> {
    /// Wrap a handler with a timeout.
    #[must_use]
    pub fn new(inner: H, timeout: Duration) -> Self {
        Self::with_time_getter(inner, timeout, wall_clock_now)
    }

    /// Wrap a handler with a timeout using a custom time source.
    #[must_use]
    pub fn with_time_getter(inner: H, timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            inner,
            timeout,
            time_getter,
        }
    }
}

impl<H: Handler> Handler for TimeoutMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let start = (self.time_getter)();
        let resp = self.inner.call(req);
        let elapsed = Duration::from_nanos((self.time_getter)().duration_since(start));

        if elapsed > self.timeout {
            Response::new(
                StatusCode::GATEWAY_TIMEOUT,
                format!("Request timed out after {elapsed:?}").into_bytes(),
            )
        } else {
            resp
        }
    }
}

// ─── CircuitBreakerMiddleware ───────────────────────────────────────────────

/// Middleware that wraps a handler with a circuit breaker.
///
/// When the circuit is open, requests are immediately rejected with 503
/// Service Unavailable. The circuit breaker tracks handler errors
/// (5xx responses) as failures.
pub struct CircuitBreakerMiddleware<H> {
    inner: H,
    breaker: Arc<CircuitBreaker>,
    time_getter: fn() -> Time,
}

#[derive(Debug)]
struct HandlerServerError(Response);

impl fmt::Display for HandlerServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server error: {}", self.0.status.as_u16())
    }
}

impl<H: Handler> CircuitBreakerMiddleware<H> {
    /// Wrap a handler with a circuit breaker.
    #[must_use]
    pub fn new(inner: H, policy: CircuitBreakerPolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Wrap a handler with a circuit breaker using a custom time source.
    #[must_use]
    pub fn with_time_getter(
        inner: H,
        policy: CircuitBreakerPolicy,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            inner,
            breaker: Arc::new(CircuitBreaker::new(policy)),
            time_getter,
        }
    }

    /// Wrap a handler with a shared circuit breaker.
    ///
    /// Use this to share a breaker across multiple routes or middleware.
    #[must_use]
    pub fn shared(inner: H, breaker: Arc<CircuitBreaker>) -> Self {
        Self::shared_with_time_getter(inner, breaker, wall_clock_now)
    }

    /// Wrap a handler with a shared circuit breaker and custom time source.
    #[must_use]
    pub fn shared_with_time_getter(
        inner: H,
        breaker: Arc<CircuitBreaker>,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            inner,
            breaker,
            time_getter,
        }
    }

    /// Returns a reference to the circuit breaker for metrics inspection.
    #[must_use]
    pub fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }
}

impl<H: Handler> Handler for CircuitBreakerMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let now = (self.time_getter)();

        // Use the circuit breaker to guard the handler call.
        // We treat the handler as a Result where 5xx = error.
        let result = self.breaker.call(now, || {
            let resp = self.inner.call(req);
            if resp.status.is_server_error() {
                Err(HandlerServerError(resp))
            } else {
                Ok(resp)
            }
        });

        match result {
            Ok(resp) => resp,
            Err(crate::combinator::circuit_breaker::CircuitBreakerError::Open { remaining }) => {
                let body =
                    format!("Service Unavailable: circuit breaker open, retry after {remaining:?}");
                Response::new(StatusCode::SERVICE_UNAVAILABLE, body.into_bytes())
                    .header("retry-after", format!("{}", remaining.as_secs().max(1)))
            }
            Err(crate::combinator::circuit_breaker::CircuitBreakerError::HalfOpenFull) => {
                Response::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"Service Unavailable: circuit breaker half-open, max probes active".to_vec(),
                )
            }
            Err(crate::combinator::circuit_breaker::CircuitBreakerError::Inner(err)) => {
                // Preserve the original server-error response while still counting
                // it as a breaker failure.
                err.0
            }
        }
    }
}

// ─── RateLimitMiddleware ────────────────────────────────────────────────────

/// Middleware that enforces a rate limit on requests.
///
/// Requests exceeding the rate limit receive a 429 Too Many Requests response
/// with a `retry-after` header indicating when to retry.
pub struct RateLimitMiddleware<H> {
    inner: H,
    limiter: Arc<RateLimiter>,
    time_getter: fn() -> Time,
}

impl<H: Handler> RateLimitMiddleware<H> {
    /// Wrap a handler with a rate limiter.
    #[must_use]
    pub fn new(inner: H, policy: RateLimitPolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Wrap a handler with a rate limiter using a custom time source.
    #[must_use]
    pub fn with_time_getter(inner: H, policy: RateLimitPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            inner,
            limiter: Arc::new(RateLimiter::new(policy)),
            time_getter,
        }
    }

    /// Wrap a handler with a shared rate limiter.
    ///
    /// Use this to share a limiter across multiple routes.
    #[must_use]
    pub fn shared(inner: H, limiter: Arc<RateLimiter>) -> Self {
        Self::shared_with_time_getter(inner, limiter, wall_clock_now)
    }

    /// Wrap a handler with a shared rate limiter and custom time source.
    #[must_use]
    pub fn shared_with_time_getter(
        inner: H,
        limiter: Arc<RateLimiter>,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            inner,
            limiter,
            time_getter,
        }
    }

    /// Returns a reference to the rate limiter for metrics inspection.
    #[must_use]
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }
}

impl<H: Handler> Handler for RateLimitMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let now = (self.time_getter)();

        match self
            .limiter
            .call(now, || Ok::<_, Infallible>(self.inner.call(req)))
        {
            Ok(resp) => resp,
            Err(
                crate::combinator::rate_limit::RateLimitError::RateLimitExceeded
                | crate::combinator::rate_limit::RateLimitError::Timeout { .. }
                | crate::combinator::rate_limit::RateLimitError::Cancelled,
            ) => {
                let retry_after = self.limiter.retry_after(1, now);
                let secs = retry_after.as_secs().max(1);
                Response::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Too Many Requests: rate limit exceeded, retry after {secs}s")
                        .into_bytes(),
                )
                .header("retry-after", format!("{secs}"))
            }
            Err(crate::combinator::rate_limit::RateLimitError::QueueIdExhausted) => Response::new(
                StatusCode::SERVICE_UNAVAILABLE,
                b"Service Unavailable: rate limiter queue exhausted".to_vec(),
            ),
            Err(crate::combinator::rate_limit::RateLimitError::Inner(never)) => match never {},
        }
    }
}

// ─── BulkheadMiddleware ─────────────────────────────────────────────────────

/// Middleware that isolates requests into a concurrency-limited compartment.
///
/// When all permits are in use, requests receive a 503 Service Unavailable
/// response. This prevents any single route or service from consuming all
/// server resources.
pub struct BulkheadMiddleware<H> {
    inner: H,
    bulkhead: Arc<Bulkhead>,
}

impl<H: Handler> BulkheadMiddleware<H> {
    /// Wrap a handler with a bulkhead.
    #[must_use]
    pub fn new(inner: H, policy: BulkheadPolicy) -> Self {
        Self {
            inner,
            bulkhead: Arc::new(Bulkhead::new(policy)),
        }
    }

    /// Wrap a handler with a shared bulkhead.
    ///
    /// Use this to share concurrency limits across routes.
    #[must_use]
    pub fn shared(inner: H, bulkhead: Arc<Bulkhead>) -> Self {
        Self { inner, bulkhead }
    }

    /// Returns a reference to the bulkhead for metrics inspection.
    #[must_use]
    pub fn bulkhead(&self) -> &Bulkhead {
        &self.bulkhead
    }
}

impl<H: Handler> Handler for BulkheadMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        self.bulkhead.try_acquire(1).map_or_else(
            || {
                Response::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"Service Unavailable: concurrency limit reached".to_vec(),
                )
            },
            |p| {
                let resp = self.inner.call(req);
                p.release();
                resp
            },
        )
    }
}

// ─── RetryMiddleware ────────────────────────────────────────────────────────

/// Middleware that retries failed handler invocations.
///
/// Only retries on 5xx server errors. The request body is cloned for each
/// retry attempt. Non-idempotent methods (POST, PATCH, DELETE) are retried
/// by default — callers should set `idempotent_only` to restrict retries to
/// safe methods.
///
/// Note: In Phase 0 (synchronous), retry sleeps block the thread. Production
/// use should rely on async retry with cooperative yielding (Phase 1+).
pub struct RetryMiddleware<H> {
    inner: H,
    policy: RetryPolicy,
    /// When true, only retry GET, HEAD, OPTIONS, PUT (idempotent methods).
    idempotent_only: bool,
}

impl<H: Handler> RetryMiddleware<H> {
    /// Wrap a handler with retry logic.
    #[must_use]
    pub fn new(inner: H, policy: RetryPolicy) -> Self {
        Self {
            inner,
            policy,
            idempotent_only: true,
        }
    }

    /// Allow retries for all methods, including non-idempotent ones.
    #[must_use]
    pub fn retry_all_methods(mut self) -> Self {
        self.idempotent_only = false;
        self
    }
}

/// Returns true if the method is considered idempotent.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE" | "TRACE"
    )
}

impl<H: Handler> Handler for RetryMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        // Check if retry is appropriate for this method.
        if self.idempotent_only && !is_idempotent(&req.method) {
            return self.inner.call(req);
        }

        let max = self.policy.max_attempts.max(1);
        let mut delay = self.policy.initial_delay;
        let mut last_resp = None;

        for attempt in 0..max {
            // Clone request for retry (first attempt uses original).
            if attempt != 0 {
                // Sleep before retry (Phase 0: blocking sleep).
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                // Compute next delay with exponential backoff.
                delay = Duration::from_secs_f64(
                    (delay.as_secs_f64() * self.policy.multiplier)
                        .min(self.policy.max_delay.as_secs_f64()),
                );
            }
            let try_req = req.clone();

            let resp = self.inner.call(try_req);
            if !resp.status.is_server_error() {
                return resp;
            }
            last_resp = Some(resp);
        }

        // All attempts failed; return the last response.
        last_resp.unwrap_or_else(|| {
            Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"Internal Server Error: all retry attempts exhausted".to_vec(),
            )
        })
    }
}

// ─── CompressionMiddleware ─────────────────────────────────────────────────

/// Supported compression encodings for the compression middleware.
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Encodings the server supports, in preference order.
    pub supported: Vec<ContentEncoding>,
    /// Minimum response body size (bytes) before compression is applied.
    /// Bodies smaller than this threshold are sent uncompressed.
    pub min_body_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            supported: vec![
                ContentEncoding::Brotli,
                ContentEncoding::Gzip,
                ContentEncoding::Deflate,
                ContentEncoding::Identity,
            ],
            min_body_size: 256,
        }
    }
}

/// Middleware that compresses response bodies based on Accept-Encoding
/// negotiation.
///
/// Uses [`negotiate_encoding`] to select the best encoding from the
/// client's Accept-Encoding header against the server's supported set.
/// Only compresses when the response body exceeds `min_body_size`.
pub struct CompressionMiddleware<H> {
    inner: H,
    config: CompressionConfig,
}

impl<H: Handler> CompressionMiddleware<H> {
    /// Wrap a handler with response compression.
    #[must_use]
    pub fn new(inner: H, config: CompressionConfig) -> Self {
        Self { inner, config }
    }
}

impl<H: Handler> Handler for CompressionMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let accept_encoding = header_value(&req, "accept-encoding");
        let mut resp = self.inner.call(req);

        if resp.status == StatusCode::NO_CONTENT || resp.status == StatusCode::NOT_MODIFIED {
            return resp;
        }

        if let Some(existing_encoding) = resp.remove_header("content-encoding") {
            resp.set_header("content-encoding", existing_encoding);
            return resp;
        }

        // Skip compression for small bodies.
        if resp.body.len() < self.config.min_body_size {
            return resp;
        }

        let available_encodings: Vec<_> = self
            .config
            .supported
            .iter()
            .copied()
            .filter(|encoding| compression_encoding_available(*encoding))
            .collect();

        let Some(encoding) = negotiate_encoding(accept_encoding.as_deref(), &available_encodings)
        else {
            if accept_encoding.is_some() {
                return Response::new(
                    StatusCode::from_u16(406),
                    b"No acceptable response encoding".to_vec(),
                );
            }
            return resp;
        };

        // Identity means no transformation needed.
        if encoding == ContentEncoding::Identity {
            append_vary_header(&mut resp, "accept-encoding");
            return resp;
        }

        let Some(mut compressor) = make_compressor(encoding) else {
            return resp;
        };

        let mut compressed = Vec::new();
        if compressor.compress(&resp.body, &mut compressed).is_err() {
            return resp;
        }
        if compressor.finish(&mut compressed).is_err() {
            return resp;
        }

        if compressed.len() >= resp.body.len() {
            append_vary_header(&mut resp, "accept-encoding");
            return resp;
        }

        resp.body = compressed.into();
        resp.set_header("content-encoding", encoding.as_token().to_string());
        append_vary_header(&mut resp, "accept-encoding");
        resp
    }
}

fn compression_encoding_available(encoding: ContentEncoding) -> bool {
    match encoding {
        ContentEncoding::Identity => true,
        #[cfg(feature = "compression")]
        ContentEncoding::Brotli | ContentEncoding::Gzip | ContentEncoding::Deflate => true,
        #[cfg(not(feature = "compression"))]
        ContentEncoding::Brotli | ContentEncoding::Gzip | ContentEncoding::Deflate => false,
    }
}

// ─── RequestBodyLimitMiddleware ───────────────────────────────────────────

/// Middleware that enforces a maximum request body size.
///
/// If the request body exceeds the limit, a 413 Payload Too Large response
/// is returned without invoking the inner handler. This provides a global
/// safety net independent of per-extractor limits.
pub struct RequestBodyLimitMiddleware<H> {
    inner: H,
    max_bytes: usize,
}

impl<H: Handler> RequestBodyLimitMiddleware<H> {
    /// Wrap a handler with a request body size limit.
    #[must_use]
    pub fn new(inner: H, max_bytes: usize) -> Self {
        Self { inner, max_bytes }
    }
}

impl<H: Handler> Handler for RequestBodyLimitMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        if req.body.len() > self.max_bytes {
            return Response::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "Payload Too Large: body is {} bytes, limit is {} bytes",
                    req.body.len(),
                    self.max_bytes
                )
                .into_bytes(),
            );
        }
        self.inner.call(req)
    }
}

// ─── RequestIdMiddleware ──────────────────────────────────────────────────

/// Middleware that generates or propagates a request ID.
///
/// If the request contains a header matching `header_name`, its value is
/// used. Otherwise, a monotonically increasing ID is generated. The ID
/// is stored in the request extensions under `"request_id"` and echoed
/// in the response header.
pub struct RequestIdMiddleware<H> {
    inner: H,
    header_name: String,
    counter: Arc<AtomicU64>,
}

impl<H: Handler> RequestIdMiddleware<H> {
    /// Wrap a handler with request ID generation.
    ///
    /// `header_name` specifies which request/response header carries the ID
    /// (e.g., `"x-request-id"`).
    #[must_use]
    pub fn new(inner: H, header_name: impl Into<String>) -> Self {
        Self {
            inner,
            header_name: normalize_header_name(header_name),
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Wrap a handler with request ID generation using a shared counter.
    ///
    /// Use this to ensure unique IDs across multiple middleware instances.
    #[must_use]
    pub fn shared(inner: H, header_name: impl Into<String>, counter: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            header_name: normalize_header_name(header_name),
            counter,
        }
    }
}

impl<H: Handler> Handler for RequestIdMiddleware<H> {
    fn call(&self, mut req: Request) -> Response {
        let request_id = header_value(&req, &self.header_name).unwrap_or_else(|| {
            let id = self.counter.fetch_add(1, Ordering::Relaxed);
            format!("req-{id}")
        });
        // Sanitize CRLF from client-supplied header to prevent response header injection.
        let request_id = request_id.replace(['\r', '\n'], "");

        req.extensions.insert("request_id", request_id.clone());
        req.extensions.insert("trace_id", request_id.clone());

        let mut resp = self.inner.call(req);
        resp.headers.insert(self.header_name.clone(), request_id);
        resp
    }
}

// ─── RequestTraceMiddleware ───────────────────────────────────────────────

/// Policy for request/response tracing middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTracePolicy {
    /// Response header for elapsed request time in milliseconds.
    ///
    /// Set to `None` to disable duration header injection.
    pub duration_header: Option<String>,
    /// Response header used for propagating the trace identifier.
    ///
    /// The middleware resolves trace ID from request extensions (`trace_id`,
    /// then `request_id`) or request header `x-request-id`.
    pub trace_header: Option<String>,
}

impl Default for RequestTracePolicy {
    fn default() -> Self {
        Self {
            duration_header: Some("x-response-time-ms".to_string()),
            trace_header: Some("x-trace-id".to_string()),
        }
    }
}

/// Middleware that emits request/response tracing events and optional metadata headers.
pub struct RequestTraceMiddleware<H> {
    inner: H,
    policy: RequestTracePolicy,
    time_getter: fn() -> Time,
}

impl<H: Handler> RequestTraceMiddleware<H> {
    /// Wrap a handler with request/response tracing.
    #[must_use]
    pub fn new(inner: H, policy: RequestTracePolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Wrap a handler with request/response tracing using a custom time source.
    #[must_use]
    pub fn with_time_getter(
        inner: H,
        policy: RequestTracePolicy,
        time_getter: fn() -> Time,
    ) -> Self {
        let policy = RequestTracePolicy {
            duration_header: policy.duration_header.map(normalize_header_name),
            trace_header: policy.trace_header.map(normalize_header_name),
        };
        Self {
            inner,
            policy,
            time_getter,
        }
    }

    fn resolve_trace_id(req: &Request) -> Option<String> {
        if let Some(id) = req.extensions.get("trace_id") {
            return Some(id.to_string());
        }
        if let Some(id) = req.extensions.get("request_id") {
            return Some(id.to_string());
        }
        header_value(req, "x-request-id")
    }
}

impl<H: Handler> Handler for RequestTraceMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let method = req.method.clone();
        let path = req.path.clone();
        let trace_id = Self::resolve_trace_id(&req);
        let start = (self.time_getter)();

        debug!(
            method = %method,
            path = %path,
            trace_id = ?trace_id,
            "http request start"
        );

        let mut resp = self.inner.call(req);
        let duration_ms =
            Duration::from_nanos((self.time_getter)().duration_since(start)).as_millis();
        let status_code = resp.status.as_u16();

        if let Some(header_name) = &self.policy.duration_header {
            resp.headers
                .insert(header_name.clone(), duration_ms.to_string());
        }

        if let (Some(header_name), Some(id)) = (&self.policy.trace_header, trace_id.as_ref()) {
            // Sanitize CRLF from trace ID to prevent response header injection.
            let sanitized = id.replace(['\r', '\n'], "");
            resp.headers
                .entry(header_name.clone())
                .or_insert_with(|| sanitized);
        }

        if status_code >= 500 {
            warn!(
                method = %method,
                path = %path,
                status = status_code,
                duration_ms = duration_ms,
                trace_id = ?trace_id,
                "http request completed with server error"
            );
        } else {
            debug!(
                method = %method,
                path = %path,
                status = status_code,
                duration_ms = duration_ms,
                trace_id = ?trace_id,
                "http request completed"
            );
        }

        #[cfg(not(feature = "tracing-integration"))]
        let _ = (&method, &path);

        resp
    }
}

// ─── AuthMiddleware ────────────────────────────────────────────────────────

/// Authorization policy for bearer-token middleware.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthPolicy {
    /// Any well-formed bearer token is accepted.
    #[default]
    AnyBearer,
    /// Only the listed bearer tokens are accepted.
    ExactBearer(Vec<String>),
}

impl AuthPolicy {
    /// Require exactly one bearer token.
    #[must_use]
    pub fn exact_bearer(token: impl Into<String>) -> Self {
        Self::ExactBearer(vec![token.into()])
    }

    fn allows(&self, req: &Request) -> bool {
        let Some(value) = header_value(req, "authorization") else {
            return false;
        };
        let Some(token) = parse_bearer_token(&value) else {
            return false;
        };
        match self {
            Self::AnyBearer => !token.is_empty(),
            Self::ExactBearer(tokens) => {
                // Constant-time scan: evaluate every token to prevent timing
                // side-channel leaks about which token matched or list length.
                tokens.iter().fold(false, |matched, expected| {
                    let mut diff = 0u8;
                    if expected.len() != token.len() {
                        diff |= 1;
                    }
                    let token_bytes = token.as_bytes();
                    for (i, b) in expected.bytes().enumerate() {
                        diff |= b ^ token_bytes.get(i).copied().unwrap_or(0);
                    }
                    // Intentional bitwise OR for constant-time comparison —
                    // `||` would short-circuit and leak timing information.
                    #[allow(clippy::needless_bitwise_bool)]
                    let result = matched | (diff == 0);
                    result
                })
            }
        }
    }
}

fn parse_bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(token.trim())
    } else {
        None
    }
}

/// Middleware that enforces bearer-token authorization.
pub struct AuthMiddleware<H> {
    inner: H,
    policy: AuthPolicy,
}

impl<H: Handler> AuthMiddleware<H> {
    /// Wrap a handler with authorization checks.
    #[must_use]
    pub fn new(inner: H, policy: AuthPolicy) -> Self {
        Self { inner, policy }
    }
}

impl<H: Handler> Handler for AuthMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        if !self.policy.allows(&req) {
            return Response::new(StatusCode::UNAUTHORIZED, b"Unauthorized".to_vec())
                .header("www-authenticate", "Bearer");
        }
        self.inner.call(req)
    }
}

// ─── LoadShedMiddleware ────────────────────────────────────────────────────

/// Policy for request-level load shedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadShedPolicy {
    /// Max in-flight requests before shedding starts.
    pub max_in_flight: usize,
}

impl Default for LoadShedPolicy {
    fn default() -> Self {
        Self {
            max_in_flight: 1024,
        }
    }
}

struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Middleware that sheds requests when in-flight count exceeds policy.
pub struct LoadShedMiddleware<H> {
    inner: H,
    policy: LoadShedPolicy,
    in_flight: Arc<AtomicUsize>,
}

impl<H: Handler> LoadShedMiddleware<H> {
    /// Wrap a handler with load-shedding checks.
    #[must_use]
    pub fn new(inner: H, policy: LoadShedPolicy) -> Self {
        Self {
            inner,
            policy,
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<H: Handler> Handler for LoadShedMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let previous = self.in_flight.fetch_add(1, Ordering::AcqRel);
        if previous >= self.policy.max_in_flight {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Response::new(
                StatusCode::SERVICE_UNAVAILABLE,
                b"Service Unavailable: overloaded".to_vec(),
            );
        }

        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        self.inner.call(req)
    }
}

// ─── CatchPanicMiddleware ─────────────────────────────────────────────────

/// Middleware that catches panics in the inner handler and returns a
/// 500 Internal Server Error response instead of unwinding.
///
/// This is a safety net for production servers: a panicking handler
/// should not take down the entire server. The panic message is logged
/// but not exposed to the client (to avoid information leakage).
pub struct CatchPanicMiddleware<H> {
    inner: H,
}

impl<H: Handler> CatchPanicMiddleware<H> {
    /// Wrap a handler with panic recovery.
    #[must_use]
    pub fn new(inner: H) -> Self {
        Self { inner }
    }
}

impl<H: Handler> Handler for CatchPanicMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        match panic::catch_unwind(AssertUnwindSafe(|| self.inner.call(req))) {
            Ok(resp) => resp,
            Err(_payload) => {
                // Do not expose panic details to the client.
                Response::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"Internal Server Error".to_vec(),
                )
            }
        }
    }
}

// ─── NormalizePathMiddleware ──────────────────────────────────────────────

/// Path normalization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrailingSlash {
    /// Remove trailing slashes: `/foo/` becomes `/foo`.
    Trim,
    /// Add trailing slashes: `/foo` becomes `/foo/`.
    Always,
    /// Redirect to the canonical form (301). The `Trim` or `Always`
    /// variant determines the canonical form.
    RedirectTrim,
    /// Redirect to the canonical form (301) with trailing slash.
    RedirectAlways,
}

/// Middleware that normalizes request paths.
///
/// Handles trailing slash normalization according to the configured
/// strategy. This prevents routing mismatches when clients send `/api/`
/// vs `/api`.
pub struct NormalizePathMiddleware<H> {
    inner: H,
    strategy: TrailingSlash,
}

impl<H: Handler> NormalizePathMiddleware<H> {
    /// Wrap a handler with path normalization.
    #[must_use]
    pub fn new(inner: H, strategy: TrailingSlash) -> Self {
        Self { inner, strategy }
    }
}

impl<H: Handler> Handler for NormalizePathMiddleware<H> {
    fn call(&self, mut req: Request) -> Response {
        let path = &req.path;

        match self.strategy {
            TrailingSlash::Trim => {
                if path.len() > 1 && path.ends_with('/') {
                    req.path = path.trim_end_matches('/').to_string();
                    if req.path.is_empty() {
                        req.path = "/".to_string();
                    }
                }
                self.inner.call(req)
            }
            TrailingSlash::Always => {
                if !path.ends_with('/') && !path.contains('.') {
                    req.path = format!("{path}/");
                }
                self.inner.call(req)
            }
            TrailingSlash::RedirectTrim => {
                if path.len() > 1 && path.ends_with('/') {
                    let mut trimmed = path.trim_end_matches('/').to_string();
                    if trimmed.is_empty() {
                        trimmed = "/".to_string();
                    }
                    // Sanitize CRLF to prevent HTTP response header injection.
                    let trimmed = trimmed.replace(['\r', '\n'], "");
                    return Response::empty(StatusCode::MOVED_PERMANENTLY)
                        .header("location", trimmed);
                }
                self.inner.call(req)
            }
            TrailingSlash::RedirectAlways => {
                if !path.ends_with('/') && !path.contains('.') {
                    let with_slash = format!("{path}/");
                    // Sanitize CRLF to prevent HTTP response header injection.
                    let with_slash = with_slash.replace(['\r', '\n'], "");
                    return Response::empty(StatusCode::MOVED_PERMANENTLY)
                        .header("location", with_slash);
                }
                self.inner.call(req)
            }
        }
    }
}

// ─── SetResponseHeaderMiddleware ─────────────────────────────────────────

/// Strategy for setting response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOverwrite {
    /// Always set the header, overwriting any existing value.
    Always,
    /// Only set the header if it is not already present.
    IfMissing,
}

/// Middleware that injects headers into every response.
///
/// Useful for security headers (e.g., `x-content-type-options: nosniff`,
/// `x-frame-options: DENY`) or custom metadata headers.
pub struct SetResponseHeaderMiddleware<H> {
    inner: H,
    name: String,
    value: String,
    mode: HeaderOverwrite,
}

impl<H: Handler> SetResponseHeaderMiddleware<H> {
    /// Wrap a handler to inject a response header.
    #[must_use]
    pub fn new(
        inner: H,
        name: impl Into<String>,
        value: impl Into<String>,
        mode: HeaderOverwrite,
    ) -> Self {
        Self {
            inner,
            name: normalize_header_name(name),
            value: value.into(),
            mode,
        }
    }

    /// Convenience: always-overwrite mode.
    #[must_use]
    pub fn always(inner: H, name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(inner, name, value, HeaderOverwrite::Always)
    }

    /// Convenience: set only if the header is not already present.
    #[must_use]
    pub fn if_missing(inner: H, name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(inner, name, value, HeaderOverwrite::IfMissing)
    }
}

impl<H: Handler> Handler for SetResponseHeaderMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let mut resp = self.inner.call(req);
        match self.mode {
            HeaderOverwrite::Always => {
                resp.headers.insert(self.name.clone(), self.value.clone());
            }
            HeaderOverwrite::IfMissing => {
                resp.headers
                    .entry(self.name.clone())
                    .or_insert_with(|| self.value.clone());
            }
        }
        resp
    }
}

// ─── MiddlewareStack ────────────────────────────────────────────────────────

/// Builder for composing multiple middleware layers around a handler.
///
/// Middleware is applied in the order specified (outermost first). The
/// resulting type implements [`Handler`].
///
/// # Example
///
/// ```ignore
/// let handler = MiddlewareStack::new(my_handler)
///     .with_timeout(Duration::from_secs(30))
///     .with_rate_limit(RateLimitPolicy::default())
///     .with_circuit_breaker(CircuitBreakerPolicy::default())
///     .build();
/// ```
///
/// Execution order: Timeout → RateLimit → CircuitBreaker → Handler
pub struct MiddlewareStack<H> {
    inner: H,
}

impl<H: Handler> MiddlewareStack<H> {
    /// Start building a middleware stack around the given handler.
    #[must_use]
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    /// Add a timeout middleware layer.
    #[must_use]
    pub fn with_timeout(self, timeout: Duration) -> MiddlewareStack<TimeoutMiddleware<H>> {
        MiddlewareStack {
            inner: TimeoutMiddleware::new(self.inner, timeout),
        }
    }

    /// Add a CORS middleware layer.
    #[must_use]
    pub fn with_cors(self, policy: CorsPolicy) -> MiddlewareStack<CorsMiddleware<H>> {
        MiddlewareStack {
            inner: CorsMiddleware::new(self.inner, policy),
        }
    }

    /// Add a circuit breaker middleware layer.
    #[must_use]
    pub fn with_circuit_breaker(
        self,
        policy: CircuitBreakerPolicy,
    ) -> MiddlewareStack<CircuitBreakerMiddleware<H>> {
        MiddlewareStack {
            inner: CircuitBreakerMiddleware::new(self.inner, policy),
        }
    }

    /// Add a circuit breaker middleware layer with a shared breaker.
    #[must_use]
    pub fn with_shared_circuit_breaker(
        self,
        breaker: Arc<CircuitBreaker>,
    ) -> MiddlewareStack<CircuitBreakerMiddleware<H>> {
        MiddlewareStack {
            inner: CircuitBreakerMiddleware::shared(self.inner, breaker),
        }
    }

    /// Add a rate limit middleware layer.
    #[must_use]
    pub fn with_rate_limit(
        self,
        policy: RateLimitPolicy,
    ) -> MiddlewareStack<RateLimitMiddleware<H>> {
        MiddlewareStack {
            inner: RateLimitMiddleware::new(self.inner, policy),
        }
    }

    /// Add a rate limit middleware layer with a shared limiter.
    #[must_use]
    pub fn with_shared_rate_limit(
        self,
        limiter: Arc<RateLimiter>,
    ) -> MiddlewareStack<RateLimitMiddleware<H>> {
        MiddlewareStack {
            inner: RateLimitMiddleware::shared(self.inner, limiter),
        }
    }

    /// Add a bulkhead middleware layer.
    #[must_use]
    pub fn with_bulkhead(self, policy: BulkheadPolicy) -> MiddlewareStack<BulkheadMiddleware<H>> {
        MiddlewareStack {
            inner: BulkheadMiddleware::new(self.inner, policy),
        }
    }

    /// Add a bulkhead middleware layer with a shared bulkhead.
    #[must_use]
    pub fn with_shared_bulkhead(
        self,
        bulkhead: Arc<Bulkhead>,
    ) -> MiddlewareStack<BulkheadMiddleware<H>> {
        MiddlewareStack {
            inner: BulkheadMiddleware::shared(self.inner, bulkhead),
        }
    }

    /// Add a retry middleware layer.
    #[must_use]
    pub fn with_retry(self, policy: RetryPolicy) -> MiddlewareStack<RetryMiddleware<H>> {
        MiddlewareStack {
            inner: RetryMiddleware::new(self.inner, policy),
        }
    }

    /// Add a response compression middleware layer.
    #[must_use]
    pub fn with_compression(
        self,
        config: CompressionConfig,
    ) -> MiddlewareStack<CompressionMiddleware<H>> {
        MiddlewareStack {
            inner: CompressionMiddleware::new(self.inner, config),
        }
    }

    /// Add a request body size limit middleware layer.
    #[must_use]
    pub fn with_body_limit(
        self,
        max_bytes: usize,
    ) -> MiddlewareStack<RequestBodyLimitMiddleware<H>> {
        MiddlewareStack {
            inner: RequestBodyLimitMiddleware::new(self.inner, max_bytes),
        }
    }

    /// Add a bearer auth middleware layer.
    #[must_use]
    pub fn with_auth(self, policy: AuthPolicy) -> MiddlewareStack<AuthMiddleware<H>> {
        MiddlewareStack {
            inner: AuthMiddleware::new(self.inner, policy),
        }
    }

    /// Add request-level load shedding middleware.
    #[must_use]
    pub fn with_load_shed(self, policy: LoadShedPolicy) -> MiddlewareStack<LoadShedMiddleware<H>> {
        MiddlewareStack {
            inner: LoadShedMiddleware::new(self.inner, policy),
        }
    }

    /// Add a request ID middleware layer.
    #[must_use]
    pub fn with_request_id(
        self,
        header_name: impl Into<String>,
    ) -> MiddlewareStack<RequestIdMiddleware<H>> {
        MiddlewareStack {
            inner: RequestIdMiddleware::new(self.inner, header_name),
        }
    }

    /// Add request/response tracing middleware.
    #[must_use]
    pub fn with_request_trace(
        self,
        policy: RequestTracePolicy,
    ) -> MiddlewareStack<RequestTraceMiddleware<H>> {
        MiddlewareStack {
            inner: RequestTraceMiddleware::new(self.inner, policy),
        }
    }

    /// Add a panic recovery middleware layer.
    #[must_use]
    pub fn with_catch_panic(self) -> MiddlewareStack<CatchPanicMiddleware<H>> {
        MiddlewareStack {
            inner: CatchPanicMiddleware::new(self.inner),
        }
    }

    /// Add a path normalization middleware layer.
    #[must_use]
    pub fn with_normalize_path(
        self,
        strategy: TrailingSlash,
    ) -> MiddlewareStack<NormalizePathMiddleware<H>> {
        MiddlewareStack {
            inner: NormalizePathMiddleware::new(self.inner, strategy),
        }
    }

    /// Add a response header injection middleware layer.
    #[must_use]
    pub fn with_response_header(
        self,
        name: impl Into<String>,
        value: impl Into<String>,
        mode: HeaderOverwrite,
    ) -> MiddlewareStack<SetResponseHeaderMiddleware<H>> {
        MiddlewareStack {
            inner: SetResponseHeaderMiddleware::new(self.inner, name, value, mode),
        }
    }

    /// Finish building and return the composed handler.
    #[must_use]
    pub fn build(self) -> H {
        self.inner
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handler::FnHandler;

    thread_local! {
        static TIMEOUT_TEST_TIME_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static CIRCUIT_TEST_TIME_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static REQUEST_TRACE_TEST_TIME_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static RATE_LIMIT_TEST_TIME_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_timeout_test_time(ms: u64) {
        TIMEOUT_TEST_TIME_MS.with(|t| t.set(ms));
    }

    fn timeout_test_time() -> Time {
        Time::from_millis(TIMEOUT_TEST_TIME_MS.with(std::cell::Cell::get))
    }

    fn set_circuit_test_time(ms: u64) {
        CIRCUIT_TEST_TIME_MS.with(|t| t.set(ms));
    }

    fn circuit_test_time() -> Time {
        Time::from_millis(CIRCUIT_TEST_TIME_MS.with(std::cell::Cell::get))
    }

    fn set_request_trace_test_time(ms: u64) {
        REQUEST_TRACE_TEST_TIME_MS.with(|t| t.set(ms));
    }

    fn request_trace_test_time() -> Time {
        Time::from_millis(REQUEST_TRACE_TEST_TIME_MS.with(std::cell::Cell::get))
    }

    fn set_rate_limit_test_time(ms: u64) {
        RATE_LIMIT_TEST_TIME_MS.with(|t| t.set(ms));
    }

    fn rate_limit_test_time() -> Time {
        Time::from_millis(RATE_LIMIT_TEST_TIME_MS.with(std::cell::Cell::get))
    }

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn error_handler() -> Response {
        Response::new(StatusCode::INTERNAL_SERVER_ERROR, b"fail".to_vec())
    }

    fn slow_handler() -> &'static str {
        std::thread::sleep(Duration::from_millis(50));
        "slow"
    }

    fn make_request() -> Request {
        Request::new("GET", "/test")
    }

    struct CountingHandler {
        calls: Arc<std::sync::atomic::AtomicU32>,
        delay: Duration,
        status: StatusCode,
    }

    impl Handler for CountingHandler {
        fn call(&self, _req: Request) -> Response {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            Response::new(self.status, b"counted".to_vec())
        }
    }

    struct InspectHandler;

    impl Handler for InspectHandler {
        fn call(&self, req: Request) -> Response {
            req.extensions.get("trace_id").map_or_else(
                || Response::new(StatusCode::BAD_REQUEST, b"missing trace_id".to_vec()),
                |value| Response::new(StatusCode::OK, value.as_bytes().to_vec()),
            )
        }
    }

    struct FailingIfCalled;

    impl Handler for FailingIfCalled {
        fn call(&self, _req: Request) -> Response {
            Response::new(StatusCode::INTERNAL_SERVER_ERROR, b"inner-called".to_vec())
        }
    }

    struct InspectPathHandler;

    impl Handler for InspectPathHandler {
        fn call(&self, req: Request) -> Response {
            Response::new(StatusCode::OK, req.path.into_bytes())
        }
    }

    struct PanicHandler;

    impl Handler for PanicHandler {
        fn call(&self, _req: Request) -> Response {
            panic!("boom");
        }
    }

    struct AdvanceTimeHandler {
        next_time_ms: u64,
        status: StatusCode,
    }

    impl Handler for AdvanceTimeHandler {
        fn call(&self, _req: Request) -> Response {
            set_timeout_test_time(self.next_time_ms);
            Response::new(self.status, b"advanced".to_vec())
        }
    }

    struct AdvanceRequestTraceTimeHandler {
        next_time_ms: u64,
        body: &'static [u8],
    }

    impl Handler for AdvanceRequestTraceTimeHandler {
        fn call(&self, _req: Request) -> Response {
            set_request_trace_test_time(self.next_time_ms);
            Response::new(StatusCode::OK, self.body.to_vec())
        }
    }

    // --- TimeoutMiddleware ---

    #[test]
    fn timeout_passes_when_fast() {
        let mw = TimeoutMiddleware::new(FnHandler::new(ok_handler), Duration::from_secs(5));
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn timeout_triggers_when_slow() {
        let mw = TimeoutMiddleware::new(FnHandler::new(slow_handler), Duration::from_millis(1));
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn timeout_time_getter_can_trigger_without_sleep() {
        set_timeout_test_time(0);
        let mw = TimeoutMiddleware::with_time_getter(
            AdvanceTimeHandler {
                next_time_ms: 25,
                status: StatusCode::OK,
            },
            Duration::from_millis(10),
            timeout_test_time,
        );

        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn timeout_time_getter_preserves_fast_response() {
        set_timeout_test_time(0);
        let mw = TimeoutMiddleware::with_time_getter(
            AdvanceTimeHandler {
                next_time_ms: 5,
                status: StatusCode::CREATED,
            },
            Duration::from_millis(10),
            timeout_test_time,
        );

        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::CREATED);
        assert_eq!(resp.body.as_ref(), b"advanced");
    }

    // --- CircuitBreakerMiddleware ---

    #[test]
    fn circuit_breaker_passes_success() {
        let policy = CircuitBreakerPolicy::default();
        let mw = CircuitBreakerMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn circuit_breaker_opens_after_failures() {
        let policy = CircuitBreakerPolicy {
            failure_threshold: 2,
            ..Default::default()
        };
        let mw = CircuitBreakerMiddleware::new(FnHandler::new(error_handler), policy);

        // Fail twice to reach threshold.
        let _ = mw.call(make_request());
        let _ = mw.call(make_request());

        // Next call should be rejected.
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn circuit_breaker_shared_state() {
        let policy = CircuitBreakerPolicy::default();
        let breaker = Arc::new(CircuitBreaker::new(policy));

        let mw1 =
            CircuitBreakerMiddleware::shared(FnHandler::new(ok_handler), Arc::clone(&breaker));
        let mw2 =
            CircuitBreakerMiddleware::shared(FnHandler::new(ok_handler), Arc::clone(&breaker));

        // Both share the same breaker.
        let _ = mw1.call(make_request());
        assert_eq!(
            mw1.breaker().metrics().total_success,
            mw2.breaker().metrics().total_success
        );
    }

    #[test]
    fn circuit_breaker_surfaces_handler_error() {
        let policy = CircuitBreakerPolicy {
            failure_threshold: 10,
            ..Default::default()
        };
        let mw = CircuitBreakerMiddleware::new(FnHandler::new(error_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.body.as_ref(), b"fail");
    }

    #[test]
    fn circuit_breaker_preserves_original_server_error_status_and_body() {
        fn bad_gateway_handler() -> Response {
            Response::new(StatusCode::BAD_GATEWAY, b"upstream gateway failed".to_vec())
        }

        let policy = CircuitBreakerPolicy {
            failure_threshold: 10,
            ..Default::default()
        };
        let mw = CircuitBreakerMiddleware::new(FnHandler::new(bad_gateway_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::BAD_GATEWAY);
        assert_eq!(resp.body.as_ref(), b"upstream gateway failed");
    }

    #[test]
    fn circuit_breaker_time_getter_controls_open_window() {
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let breaker = Arc::new(CircuitBreaker::new(policy));
        let fail_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            FnHandler::new(error_handler),
            Arc::clone(&breaker),
            circuit_test_time,
        );
        let ok_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            FnHandler::new(ok_handler),
            Arc::clone(&breaker),
            circuit_test_time,
        );

        set_circuit_test_time(1_000);
        let first = fail_mw.call(make_request());
        assert_eq!(first.status, StatusCode::INTERNAL_SERVER_ERROR);

        let open = ok_mw.call(make_request());
        assert_eq!(open.status, StatusCode::SERVICE_UNAVAILABLE);

        set_circuit_test_time(11_000);
        let recovered = ok_mw.call(make_request());
        assert_eq!(recovered.status, StatusCode::OK);
    }

    // --- RateLimitMiddleware ---

    #[test]
    fn rate_limit_allows_within_limit() {
        let policy = RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        };
        let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn rate_limit_rejects_over_limit() {
        let policy = RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(60),
            ..Default::default()
        };
        let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

        // First call consumes the burst.
        let resp1 = mw.call(make_request());
        assert_eq!(resp1.status, StatusCode::OK);

        // Second call should be rate-limited.
        let resp2 = mw.call(make_request());
        assert_eq!(resp2.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(resp2.headers.contains_key("retry-after"));
    }

    #[test]
    fn rate_limit_short_circuits_inner_handler() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(0),
            status: StatusCode::OK,
        };
        let policy = RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(60),
            ..Default::default()
        };
        let mw = RateLimitMiddleware::new(handler, policy);

        let _ = mw.call(make_request());
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn rate_limit_panic_restores_consumed_token() {
        let limiter = Arc::new(RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(60),
            ..Default::default()
        }));
        let panic_mw = RateLimitMiddleware::shared(PanicHandler, Arc::clone(&limiter));
        let ok_mw = RateLimitMiddleware::shared(FnHandler::new(ok_handler), Arc::clone(&limiter));

        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = panic_mw.call(make_request());
        }));
        assert!(panic.is_err(), "inner handler should panic");
        assert_eq!(
            limiter.available_tokens(),
            1,
            "panic path must refund the consumed token"
        );

        let resp = ok_mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(limiter.available_tokens(), 0);
    }

    #[test]
    fn rate_limit_time_getter_controls_retry_after_and_refill() {
        let policy = RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(60),
            ..Default::default()
        };
        let mw = RateLimitMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            policy,
            rate_limit_test_time,
        );

        set_rate_limit_test_time(10_000);
        let first = mw.call(make_request());
        assert_eq!(first.status, StatusCode::OK);

        let rejected = mw.call(make_request());
        assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rejected.headers.get("retry-after").map(String::as_str),
            Some("60")
        );

        set_rate_limit_test_time(40_000);
        let still_limited = mw.call(make_request());
        assert_eq!(still_limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            still_limited.headers.get("retry-after").map(String::as_str),
            Some("30")
        );

        set_rate_limit_test_time(70_000);
        let recovered = mw.call(make_request());
        assert_eq!(recovered.status, StatusCode::OK);
    }

    // --- BulkheadMiddleware ---

    #[test]
    fn bulkhead_allows_within_limit() {
        let policy = BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        };
        let mw = BulkheadMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn bulkhead_releases_permit_after_call() {
        let policy = BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        };
        let mw = BulkheadMiddleware::new(FnHandler::new(ok_handler), policy);

        // Sequential calls should all succeed since permit is released.
        for _ in 0..5 {
            let resp = mw.call(make_request());
            assert_eq!(resp.status, StatusCode::OK);
        }
    }

    // --- RetryMiddleware ---

    #[test]
    fn retry_succeeds_on_first_try() {
        let policy = RetryPolicy::immediate(3);
        let mw = RetryMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn retry_exhausts_attempts_on_server_error() {
        let policy = RetryPolicy::immediate(3);
        let mw = RetryMiddleware::new(FnHandler::new(error_handler), policy);
        let resp = mw.call(make_request());
        // Should get the error response after all retries exhausted.
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn retry_skips_non_idempotent_by_default() {
        let policy = RetryPolicy::immediate(3);
        let mw = RetryMiddleware::new(FnHandler::new(error_handler), policy);
        let resp = mw.call(Request::new("POST", "/create"));
        // POST is not idempotent, should not retry — single call.
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn retry_all_methods_retries_post() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static CALL_COUNT: AtomicU32 = AtomicU32::new(0);

        fn counting_handler() -> Response {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
            Response::new(StatusCode::INTERNAL_SERVER_ERROR, b"fail".to_vec())
        }

        CALL_COUNT.store(0, Ordering::SeqCst);

        let policy = RetryPolicy::immediate(3);
        let mw = RetryMiddleware::new(FnHandler::new(counting_handler), policy).retry_all_methods();
        let _resp = mw.call(Request::new("POST", "/create"));
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 3);
    }

    // --- is_idempotent ---

    #[test]
    fn idempotent_methods() {
        assert!(is_idempotent("GET"));
        assert!(is_idempotent("HEAD"));
        assert!(is_idempotent("OPTIONS"));
        assert!(is_idempotent("PUT"));
        assert!(is_idempotent("DELETE"));
        assert!(is_idempotent("TRACE"));
        assert!(!is_idempotent("POST"));
        assert!(!is_idempotent("PATCH"));
    }

    // --- CompressionMiddleware ---

    #[test]
    fn compression_identity_sets_vary_header() {
        let mw = CompressionMiddleware::new(
            FnHandler::new(ok_handler),
            CompressionConfig {
                supported: vec![ContentEncoding::Identity],
                min_body_size: 0,
            },
        );
        let req = Request::new("GET", "/compress").with_header("accept-encoding", "identity");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn compression_merges_mixed_case_vary_header() {
        fn handler() -> Response {
            let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
            resp.headers
                .insert("Vary".to_string(), "Accept-Language".to_string());
            resp
        }

        let mw = CompressionMiddleware::new(
            FnHandler::new(handler),
            CompressionConfig {
                supported: vec![ContentEncoding::Identity],
                min_body_size: 0,
            },
        );
        let req = Request::new("GET", "/compress").with_header("accept-encoding", "identity");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-language, accept-encoding".to_string())
        );
        assert!(!resp.headers.contains_key("Vary"));
    }

    #[test]
    fn compression_rejects_not_acceptable_encodings() {
        let mw = CompressionMiddleware::new(
            FnHandler::new(ok_handler),
            CompressionConfig {
                supported: vec![ContentEncoding::Identity],
                min_body_size: 0,
            },
        );
        let req = Request::new("GET", "/compress")
            .with_header("accept-encoding", "gzip;q=1, identity;q=0");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
    }

    // --- RequestBodyLimitMiddleware ---

    #[test]
    fn body_limit_short_circuits_large_payload() {
        let mw = RequestBodyLimitMiddleware::new(FailingIfCalled, 3);
        let req = Request::new("POST", "/upload").with_body(b"abcdef".to_vec());
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // --- RequestIdMiddleware ---

    #[test]
    fn request_id_generates_when_missing() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        let resp = mw.call(Request::new("GET", "/req-id"));
        let request_id = resp
            .headers
            .get("x-request-id")
            .expect("request id header should be present");
        assert!(request_id.starts_with("req-"));
    }

    #[test]
    fn request_id_preserves_incoming_header_value() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        let req = Request::new("GET", "/req-id").with_header("x-request-id", "abc-123");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("x-request-id"),
            Some(&"abc-123".to_string())
        );
    }

    #[test]
    fn request_id_normalizes_mixed_case_response_header_name() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "X-Request-Id");
        let req = Request::new("GET", "/req-id").with_header("x-request-id", "abc-123");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("x-request-id"),
            Some(&"abc-123".to_string())
        );
        assert!(!resp.headers.contains_key("X-Request-Id"));
    }

    // --- AuthMiddleware ---

    #[test]
    fn auth_rejects_missing_authorization_header() {
        let mw = AuthMiddleware::new(FnHandler::new(ok_handler), AuthPolicy::AnyBearer);
        let resp = mw.call(Request::new("GET", "/auth"));
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers.get("www-authenticate"),
            Some(&"Bearer".to_string())
        );
    }

    #[test]
    fn auth_accepts_matching_bearer_token() {
        let mw = AuthMiddleware::new(
            FnHandler::new(ok_handler),
            AuthPolicy::exact_bearer("token-123"),
        );
        let req = Request::new("GET", "/auth").with_header("authorization", "Bearer token-123");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn auth_rejects_non_matching_bearer_token() {
        let mw = AuthMiddleware::new(
            FnHandler::new(ok_handler),
            AuthPolicy::exact_bearer("token-123"),
        );
        let req = Request::new("GET", "/auth").with_header("authorization", "Bearer nope");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    // --- LoadShedMiddleware ---

    #[test]
    fn load_shed_rejects_when_capacity_zero() {
        let mw = LoadShedMiddleware::new(
            FnHandler::new(ok_handler),
            LoadShedPolicy { max_in_flight: 0 },
        );
        let resp = mw.call(Request::new("GET", "/shed"));
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // --- CatchPanicMiddleware ---

    #[test]
    fn catch_panic_returns_internal_server_error() {
        let mw = CatchPanicMiddleware::new(PanicHandler);
        let resp = mw.call(Request::new("GET", "/panic"));
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --- NormalizePathMiddleware ---

    #[test]
    fn normalize_path_trim_rewrites_trailing_slash() {
        let mw = NormalizePathMiddleware::new(InspectPathHandler, TrailingSlash::Trim);
        let resp = mw.call(Request::new("GET", "/users/"));
        assert_eq!(&resp.body[..], b"/users");
    }

    #[test]
    fn normalize_path_redirect_always_redirects_without_slash() {
        let mw = NormalizePathMiddleware::new(InspectPathHandler, TrailingSlash::RedirectAlways);
        let resp = mw.call(Request::new("GET", "/users"));
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.headers.get("location"), Some(&"/users/".to_string()));
    }

    // --- SetResponseHeaderMiddleware ---

    #[test]
    fn set_response_header_if_missing_preserves_existing() {
        let inner = FnHandler::new(|| {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-env", "existing")
        });
        let mw = SetResponseHeaderMiddleware::if_missing(inner, "x-env", "new");
        let resp = mw.call(Request::new("GET", "/"));
        assert_eq!(resp.headers.get("x-env"), Some(&"existing".to_string()));
    }

    // --- CorsMiddleware ---

    #[test]
    fn cors_adds_headers_for_simple_request() {
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), CorsPolicy::default());
        let req = Request::new("GET", "/cors").with_header("Origin", "https://example.com");

        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            Some(&"*".to_string())
        );
        assert_eq!(resp.headers.get("vary"), Some(&"origin".to_string()));
    }

    #[test]
    fn cors_merges_mixed_case_vary_header_without_duplicates() {
        fn handler() -> Response {
            let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
            resp.headers
                .insert("Vary".to_string(), "Accept-Language, Origin".to_string());
            resp
        }

        let mw = CorsMiddleware::new(FnHandler::new(handler), CorsPolicy::default());
        let req = Request::new("GET", "/cors").with_header("Origin", "https://example.com");

        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-language, origin".to_string())
        );
        assert!(!resp.headers.contains_key("Vary"));
    }

    #[test]
    fn cors_preflight_short_circuits_inner_handler() {
        let mw = CorsMiddleware::new(FailingIfCalled, CorsPolicy::default());
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST")
            .with_header("Access-Control-Request-Headers", "content-type");

        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            Some(&"*".to_string())
        );
        assert!(resp.headers.contains_key("access-control-allow-methods"));
        assert!(resp.headers.contains_key("access-control-allow-headers"));
    }

    #[test]
    fn cors_exact_origins_blocks_unknown_origin() {
        let policy = CorsPolicy::with_exact_origins(vec![
            "https://allowed.example".to_string(),
            "https://another.example".to_string(),
        ]);
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);

        let blocked =
            mw.call(Request::new("GET", "/cors").with_header("Origin", "https://blocked.example"));
        assert_eq!(blocked.status, StatusCode::OK);
        assert!(!blocked.headers.contains_key("access-control-allow-origin"));

        let allowed =
            mw.call(Request::new("GET", "/cors").with_header("Origin", "https://allowed.example"));
        assert_eq!(allowed.status, StatusCode::OK);
        assert_eq!(
            allowed.headers.get("access-control-allow-origin"),
            Some(&"https://allowed.example".to_string())
        );
    }

    #[test]
    fn cors_with_credentials_echoes_origin() {
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::default()
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp =
            mw.call(Request::new("GET", "/cors").with_header("Origin", "https://cred.example"));

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            Some(&"https://cred.example".to_string())
        );
        assert_eq!(
            resp.headers.get("access-control-allow-credentials"),
            Some(&"true".to_string())
        );
    }

    // --- MiddlewareStack ---

    #[test]
    fn middleware_stack_builds() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_timeout(Duration::from_secs(5))
            .build();

        let resp = handler.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn middleware_stack_composition() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_cors(CorsPolicy::default())
            .with_auth(AuthPolicy::AnyBearer)
            .with_load_shed(LoadShedPolicy { max_in_flight: 16 })
            .with_bulkhead(BulkheadPolicy {
                max_concurrent: 10,
                ..Default::default()
            })
            .with_rate_limit(RateLimitPolicy {
                rate: 100,
                burst: 50,
                ..Default::default()
            })
            .with_timeout(Duration::from_secs(30))
            .build();

        let resp = handler.call(make_request().with_header("authorization", "Bearer token"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn middleware_stack_with_retry() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_retry(RetryPolicy::immediate(3))
            .with_timeout(Duration::from_secs(5))
            .build();

        let resp = handler.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn middleware_stack_preserves_request_extensions() {
        let handler = MiddlewareStack::new(InspectHandler)
            .with_timeout(Duration::from_secs(1))
            .with_rate_limit(RateLimitPolicy {
                rate: 100,
                burst: 100,
                period: Duration::from_secs(1),
                ..Default::default()
            })
            .build();

        let mut req = Request::new("GET", "/ctx");
        req.extensions.insert("trace_id", "trace-123");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(&resp.body[..], b"trace-123");
    }

    #[test]
    fn middleware_stack_retry_wraps_timeout() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(10),
            status: StatusCode::OK,
        };
        let stacked = MiddlewareStack::new(handler)
            .with_timeout(Duration::from_millis(1))
            .with_retry(RetryPolicy::immediate(3))
            .build();

        let resp = stacked.call(make_request());
        assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    // --- Observability ---

    #[test]
    fn circuit_breaker_metrics_accessible() {
        let policy = CircuitBreakerPolicy::default();
        let mw = CircuitBreakerMiddleware::new(FnHandler::new(ok_handler), policy);

        let _ = mw.call(make_request());
        let metrics = mw.breaker().metrics();
        assert_eq!(metrics.total_success, 1);
    }

    #[test]
    fn rate_limit_metrics_accessible() {
        let policy = RateLimitPolicy::default();
        let burst = policy.burst;
        let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

        let _ = mw.call(make_request());
        let metrics = mw.limiter().metrics();
        assert!(metrics.total_allowed > 0);
        assert!(metrics.available_tokens <= burst);
    }
    #[test]
    fn bulkhead_metrics_accessible() {
        let policy = BulkheadPolicy {
            max_concurrent: 5,
            ..Default::default()
        };
        let mw = BulkheadMiddleware::new(FnHandler::new(ok_handler), policy);

        let _ = mw.call(make_request());
        let metrics = mw.bulkhead().metrics();
        // After call completes, permit should be released.
        assert_eq!(metrics.active_permits, 0);
    }

    // --- CompressionMiddleware ---

    #[test]
    fn compression_skips_small_bodies() {
        let config = CompressionConfig {
            min_body_size: 1000,
            ..Default::default()
        };
        let mw = CompressionMiddleware::new(FnHandler::new(ok_handler), config);
        let req = make_request().with_header("Accept-Encoding", "gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn compression_negotiates_encoding() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );

        #[cfg(feature = "compression")]
        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"gzip".to_string())
        );

        #[cfg(not(feature = "compression"))]
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn compression_absent_accept_encoding_remains_permissive() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
    }

    #[test]
    fn compression_empty_accept_encoding_is_not_treated_as_absent() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Gzip],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn compression_identity_passthrough() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "identity");
        let resp = mw.call(req);
        // Identity encoding means no content-encoding header.
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_brotli_roundtrip() {
        use crate::http::compress::{BrotliDecompressor, Decompressor};

        fn large_handler() -> Response {
            Response::new(StatusCode::OK, "brotli me".repeat(128).into_bytes())
        }

        let config = CompressionConfig {
            min_body_size: 0,
            supported: vec![ContentEncoding::Brotli, ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "br");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"br".to_string())
        );

        let mut dec = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&resp.body, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        assert_eq!(decompressed, "brotli me".repeat(128).into_bytes());
    }

    // --- RequestBodyLimitMiddleware ---

    #[test]
    fn body_limit_allows_within_limit() {
        let mw = RequestBodyLimitMiddleware::new(FnHandler::new(ok_handler), 1024);
        let mut req = make_request();
        req.body = vec![0u8; 512].into();
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn body_limit_rejects_over_limit() {
        let mw = RequestBodyLimitMiddleware::new(FnHandler::new(ok_handler), 100);
        let mut req = make_request();
        req.body = vec![0u8; 200].into();
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body_str = String::from_utf8_lossy(&resp.body);
        assert!(body_str.contains("200 bytes"));
        assert!(body_str.contains("100 bytes"));
    }

    #[test]
    fn body_limit_allows_exact_limit() {
        let mw = RequestBodyLimitMiddleware::new(FnHandler::new(ok_handler), 100);
        let mut req = make_request();
        req.body = vec![0u8; 100].into();
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn body_limit_short_circuits_handler() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&calls),
            delay: Duration::ZERO,
            status: StatusCode::OK,
        };
        let mw = RequestBodyLimitMiddleware::new(handler, 10);
        let mut req = make_request();
        req.body = vec![0u8; 20].into();
        let _ = mw.call(req);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // --- RequestIdMiddleware ---

    #[test]
    fn request_id_generates_id() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
        let id = resp.headers.get("x-request-id").unwrap();
        assert!(id.starts_with("req-"));
    }

    #[test]
    fn request_id_propagates_existing() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        let req = make_request().with_header("x-request-id", "custom-42");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("x-request-id"),
            Some(&"custom-42".to_string())
        );
    }

    #[test]
    fn request_id_monotonic_counter() {
        let counter = Arc::new(AtomicU64::new(100));
        let mw = RequestIdMiddleware::shared(
            FnHandler::new(ok_handler),
            "x-request-id",
            Arc::clone(&counter),
        );
        let resp1 = mw.call(make_request());
        let resp2 = mw.call(make_request());
        assert_eq!(
            resp1.headers.get("x-request-id"),
            Some(&"req-100".to_string())
        );
        assert_eq!(
            resp2.headers.get("x-request-id"),
            Some(&"req-101".to_string())
        );
    }

    #[test]
    fn request_id_stores_in_extensions() {
        struct RequestIdEchoHandler;
        impl Handler for RequestIdEchoHandler {
            fn call(&self, req: Request) -> Response {
                req.extensions.get("request_id").map_or_else(
                    || Response::new(StatusCode::BAD_REQUEST, b"no id".to_vec()),
                    |val| Response::new(StatusCode::OK, val.as_bytes().to_vec()),
                )
            }
        }

        let mw = RequestIdMiddleware::new(RequestIdEchoHandler, "x-request-id");
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.starts_with("req-"));
    }

    // --- RequestTraceMiddleware ---

    #[test]
    fn request_trace_injects_duration_and_trace_headers() {
        let mw =
            RequestTraceMiddleware::new(FnHandler::new(ok_handler), RequestTracePolicy::default());
        let req = make_request().with_header("x-request-id", "trace-42");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("x-trace-id"),
            Some(&"trace-42".to_string())
        );
        let duration = resp
            .headers
            .get("x-response-time-ms")
            .expect("duration header should be present");
        assert!(
            duration.parse::<u128>().is_ok(),
            "duration header should be numeric: {duration}"
        );
    }

    #[test]
    fn request_trace_time_getter_can_drive_duration_header_without_sleep() {
        set_request_trace_test_time(0);
        let mw = RequestTraceMiddleware::with_time_getter(
            AdvanceRequestTraceTimeHandler {
                next_time_ms: 25,
                body: b"traced",
            },
            RequestTracePolicy::default(),
            request_trace_test_time,
        );
        let resp = mw.call(make_request().with_header("x-request-id", "trace-99"));

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("x-response-time-ms"),
            Some(&"25".to_string())
        );
        assert_eq!(
            resp.headers.get("x-trace-id"),
            Some(&"trace-99".to_string())
        );
        assert_eq!(resp.body.as_ref(), b"traced");
    }

    #[test]
    fn request_trace_can_disable_duration_header() {
        let policy = RequestTracePolicy {
            duration_header: None,
            trace_header: Some("x-trace-id".to_string()),
        };
        let mw = RequestTraceMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request().with_header("x-request-id", "trace-7"));
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("x-response-time-ms"));
        assert_eq!(resp.headers.get("x-trace-id"), Some(&"trace-7".to_string()));
    }

    #[test]
    fn request_trace_preserves_existing_trace_header() {
        fn header_handler() -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-trace-id", "inner-trace")
        }

        let mw = RequestTraceMiddleware::new(
            FnHandler::new(header_handler),
            RequestTracePolicy::default(),
        );
        let resp = mw.call(make_request().with_header("x-request-id", "outer-trace"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("x-trace-id"),
            Some(&"inner-trace".to_string())
        );
    }

    #[test]
    fn request_trace_normalizes_mixed_case_policy_headers() {
        fn header_handler() -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-trace-id", "inner-trace")
        }

        let mw = RequestTraceMiddleware::new(
            FnHandler::new(header_handler),
            RequestTracePolicy {
                duration_header: Some("X-Response-Time-Ms".to_string()),
                trace_header: Some("X-Trace-Id".to_string()),
            },
        );
        let resp = mw.call(make_request().with_header("x-request-id", "outer-trace"));

        assert!(resp.headers.contains_key("x-response-time-ms"));
        assert!(!resp.headers.contains_key("X-Response-Time-Ms"));
        assert_eq!(
            resp.headers.get("x-trace-id"),
            Some(&"inner-trace".to_string())
        );
        assert!(!resp.headers.contains_key("X-Trace-Id"));
    }

    // --- CatchPanicMiddleware ---

    #[test]
    fn catch_panic_recovers() {
        let mw = CatchPanicMiddleware::new(PanicHandler);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8_lossy(&resp.body);
        assert_eq!(body, "Internal Server Error");
    }

    #[test]
    fn catch_panic_passes_normal_responses() {
        let mw = CatchPanicMiddleware::new(FnHandler::new(ok_handler));
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    // --- NormalizePathMiddleware ---

    #[test]
    fn normalize_path_trim_trailing_slash() {
        let mw = NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::Trim);
        let resp = mw.call(Request::new("GET", "/api/users/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn normalize_path_trim_preserves_root() {
        struct PathEchoHandler;
        impl Handler for PathEchoHandler {
            fn call(&self, req: Request) -> Response {
                Response::new(StatusCode::OK, req.path.into_bytes())
            }
        }

        let mw = NormalizePathMiddleware::new(PathEchoHandler, TrailingSlash::Trim);
        let resp = mw.call(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(&resp.body[..], b"/");
    }

    #[test]
    fn normalize_path_always_adds_slash() {
        struct PathEchoHandler;
        impl Handler for PathEchoHandler {
            fn call(&self, req: Request) -> Response {
                Response::new(StatusCode::OK, req.path.into_bytes())
            }
        }

        let mw = NormalizePathMiddleware::new(PathEchoHandler, TrailingSlash::Always);
        let resp = mw.call(Request::new("GET", "/api/users"));
        assert_eq!(String::from_utf8_lossy(&resp.body), "/api/users/");
    }

    #[test]
    fn normalize_path_always_skips_dotfiles() {
        struct PathEchoHandler;
        impl Handler for PathEchoHandler {
            fn call(&self, req: Request) -> Response {
                Response::new(StatusCode::OK, req.path.into_bytes())
            }
        }

        let mw = NormalizePathMiddleware::new(PathEchoHandler, TrailingSlash::Always);
        // Paths with dots (like /style.css) should NOT get trailing slash.
        let resp = mw.call(Request::new("GET", "/style.css"));
        assert_eq!(String::from_utf8_lossy(&resp.body), "/style.css");
    }

    #[test]
    fn normalize_path_redirect_trim() {
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectTrim);
        let resp = mw.call(Request::new("GET", "/api/users/"));
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers.get("location"),
            Some(&"/api/users".to_string())
        );
    }

    #[test]
    fn normalize_path_redirect_always() {
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectAlways);
        let resp = mw.call(Request::new("GET", "/api/users"));
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers.get("location"),
            Some(&"/api/users/".to_string())
        );
    }

    // --- SetResponseHeaderMiddleware ---

    #[test]
    fn set_header_always_overwrites() {
        fn header_handler() -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-custom", "original")
        }

        let mw = SetResponseHeaderMiddleware::always(
            FnHandler::new(header_handler),
            "x-custom",
            "overwritten",
        );
        let resp = mw.call(make_request());
        assert_eq!(
            resp.headers.get("x-custom"),
            Some(&"overwritten".to_string())
        );
    }

    #[test]
    fn set_header_if_missing_preserves_existing() {
        fn header_handler() -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-custom", "original")
        }

        let mw = SetResponseHeaderMiddleware::if_missing(
            FnHandler::new(header_handler),
            "x-custom",
            "default",
        );
        let resp = mw.call(make_request());
        assert_eq!(resp.headers.get("x-custom"), Some(&"original".to_string()));
    }

    #[test]
    fn set_header_if_missing_adds_when_absent() {
        let mw = SetResponseHeaderMiddleware::if_missing(
            FnHandler::new(ok_handler),
            "x-content-type-options",
            "nosniff",
        );
        let resp = mw.call(make_request());
        assert_eq!(
            resp.headers.get("x-content-type-options"),
            Some(&"nosniff".to_string())
        );
    }

    #[test]
    fn set_header_if_missing_normalizes_mixed_case_name() {
        fn header_handler() -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec()).header("x-custom", "original")
        }

        let mw = SetResponseHeaderMiddleware::if_missing(
            FnHandler::new(header_handler),
            "X-Custom",
            "new",
        );
        let resp = mw.call(make_request());

        assert_eq!(resp.headers.get("x-custom"), Some(&"original".to_string()));
        assert!(!resp.headers.contains_key("X-Custom"));
    }

    // --- Expanded MiddlewareStack tests ---

    #[test]
    fn middleware_stack_with_body_limit() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_body_limit(1024)
            .build();

        let resp = handler.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn middleware_stack_with_request_id() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_request_id("x-request-id")
            .build();

        let resp = handler.call(make_request());
        assert!(resp.headers.contains_key("x-request-id"));
    }

    #[test]
    fn middleware_stack_with_request_trace() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_request_trace(RequestTracePolicy::default())
            .build();

        let resp = handler.call(make_request().with_header("x-request-id", "trace-55"));
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.contains_key("x-response-time-ms"));
        assert_eq!(
            resp.headers.get("x-trace-id"),
            Some(&"trace-55".to_string())
        );
    }

    #[test]
    fn middleware_stack_with_catch_panic() {
        let handler = MiddlewareStack::new(PanicHandler)
            .with_catch_panic()
            .build();

        let resp = handler.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn middleware_stack_full_production_composition() {
        let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_catch_panic()
            .with_body_limit(10 * 1024 * 1024)
            .with_request_id("x-request-id")
            .with_request_trace(RequestTracePolicy::default())
            .with_normalize_path(TrailingSlash::Trim)
            .with_timeout(Duration::from_secs(30))
            .with_cors(CorsPolicy::default())
            .with_rate_limit(RateLimitPolicy {
                rate: 100,
                burst: 50,
                ..Default::default()
            })
            .with_response_header(
                "x-content-type-options",
                "nosniff",
                HeaderOverwrite::IfMissing,
            )
            .build();

        let req = Request::new("GET", "/api/test/").with_header("Origin", "https://example.com");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.contains_key("x-request-id"));
        assert!(resp.headers.contains_key("x-response-time-ms"));
        assert!(resp.headers.contains_key("access-control-allow-origin"));
        assert_eq!(
            resp.headers.get("x-content-type-options"),
            Some(&"nosniff".to_string())
        );
    }
}
