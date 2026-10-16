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
//! // Composed middleware (last-added layer runs first)
//! let resilient = MiddlewareStack::new(handler)
//!     .with_timeout(Duration::from_secs(5))
//!     .with_rate_limit(RateLimitPolicy::default())
//!     .with_circuit_breaker(CircuitBreakerPolicy::default())
//!     .build();
//! ```
//!
//! # Unified layering (one `Layer` trait)
//!
//! Every middleware has a companion `*Layer` adapter implementing
//! [`crate::service::Layer`] — the SAME trait the `service` stack composes
//! with. That makes three composition styles interchangeable
//! (br-asupersync-server-stack-hardening-eeexl1.3):
//!
//! ```ignore
//! // 1. Router-wide, onion-style (last-added layer outermost):
//! let app = Router::new()
//!     .route("/", get(handler))
//!     .layer(AuthLayer::new(policy))
//!     .layer(CatchPanicLayer::new());
//!
//! // 2. Fluent stack around one handler (sugar over the same layers):
//! let handler = MiddlewareStack::new(handler)
//!     .layer(AuthLayer::new(policy))
//!     .build();
//!
//! // 3. Raw service::Stack composition:
//! let handler = Stack::new(AuthLayer::new(policy), CatchPanicLayer::new())
//!     .layer(handler);
//! ```
//!
//! Stateful layers (`CircuitBreakerLayer`, `RateLimitLayer`, `BulkheadLayer`,
//! `LoadShedLayer`, `RequestIdLayer`) create their shared state once at layer
//! construction, so one layer value applied across a router's routes shares a
//! single breaker / limiter / counter.
//!
//! # Execution Order
//!
//! When composing middleware via [`MiddlewareStack`], each `with_*` call wraps
//! the stack built so far, so the **last-added layer becomes the outermost
//! layer**. For a stack built as `.with_timeout().with_rate_limit()`:
//!
//! ```text
//! Request → RateLimit → Timeout → Handler → Response
//! ```
//!
//! Security note: header-setting layers such as CSP / `x-frame-options` /
//! `x-content-type-options` should be added **after** short-circuiting layers
//! like rate-limit, timeout, circuit-breaker, and load-shed so their synthetic
//! 4xx/5xx responses still carry the security headers.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::combinator::bulkhead::{Bulkhead, BulkheadPolicy};
use crate::combinator::circuit_breaker::{CircuitBreaker, CircuitBreakerPolicy};
use crate::combinator::rate_limit::{RateLimitPolicy, RateLimiter};
use crate::combinator::retry::RetryPolicy;
use crate::cx::Cx;
use crate::http::compress::{
    ContentCoding, ContentEncoding, DEFAULT_MAX_COMPRESSED_SIZE, compress_body, negotiate_coding,
    negotiate_encoding,
};
/// The unified composition trait shared with the `service` stack.
///
/// Web middleware and `crate::service` layers compose through this single
/// trait; the `*Layer` adapters below implement it over [`Handler`] values
/// (br-asupersync-server-stack-hardening-eeexl1.3).
pub use crate::service::Layer;
use crate::tracing_compat::{debug, error, warn};
use crate::types::Time;

use super::compress::{
    RequestCompressionSensitivity, compression_oracle_sensitive, is_partial_content, weaken_etag,
};
use super::extract::Request;
use super::handler::Handler;
use super::response::{IntoResponse, Redirect, Response, StatusCode};

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

/// br-asupersync-0qb0bf: safe-by-default CORS preflight
/// `Access-Control-Allow-Headers` allowlist. Pre-fix the default
/// was `["*"]` which per Fetch §3.2.4 grants access to ALL request
/// headers — equivalent to no client-side header filtering. That
/// is especially dangerous in combination with
/// `allow_credentials = true` (where `*` is forbidden by Fetch
/// §3.2.5 for the origin axis but the headers axis still leaks
/// any custom header the caller chose to send). The conservative
/// default below is the union of:
///   - the CORS-safelisted request headers (Fetch §4.6) that
///     browsers permit without preflight already: `Accept`,
///     `Accept-Language`, `Content-Type`,
///   - `Authorization` (the canonical credentialed header — most
///     APIs require it),
///   - `X-Requested-With` (the de-facto AJAX marker that XHR-style
///     libraries rely on for CSRF defenses).
///
/// Callers needing a different allowlist should set
/// `allow_headers` explicitly. For the rare legacy use case that
/// truly needs wildcard, use [`CorsPolicy::with_any_headers`] —
/// the explicit constructor name makes the loosened security
/// posture visible at the call site.
const DEFAULT_ALLOW_HEADERS: &[&str] = &[
    "Accept",
    "Accept-Language",
    "Content-Type",
    "Authorization",
    "X-Requested-With",
];

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
            // br-asupersync-0qb0bf: narrow safe-by-default allowlist
            // instead of the previous wildcard. See
            // `DEFAULT_ALLOW_HEADERS` for the rationale of each entry.
            allow_headers: DEFAULT_ALLOW_HEADERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
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

    /// Construct a policy that echoes ALL request headers via the
    /// preflight `Access-Control-Allow-Headers: *` wildcard.
    ///
    /// br-asupersync-0qb0bf: this is the explicit opt-in for the
    /// loosened header policy that used to be the silent default.
    /// Callers that genuinely accept arbitrary client headers
    /// (e.g. proxies passing through unknown trace/correlation
    /// headers) should call this constructor so the security
    /// posture is visible at the call site. Note that combining
    /// `with_any_headers()` with `allow_credentials = true` is
    /// almost certainly a misconfiguration — Fetch §3.2.5 forbids
    /// the wildcard when credentials are allowed, and the
    /// browser will reject preflight responses that try this.
    #[must_use]
    pub fn with_any_headers() -> Self {
        Self {
            allow_headers: vec!["*".to_string()],
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
    ///
    /// # Panics (debug builds)
    ///
    /// Per the CORS specification (Fetch §3.2.5), the combination
    /// `Access-Control-Allow-Origin: *` with
    /// `Access-Control-Allow-Credentials: true` is forbidden — it
    /// would allow any origin to read credentialed responses, which is
    /// the canonical credential-reflection vulnerability. Until 2026-04
    /// this implementation silently downgraded `Any` to a per-request
    /// echo of the caller's `Origin` when `allow_credentials = true`,
    /// effectively reflecting credentials to any caller.
    ///
    /// In debug builds this constructor now panics on that
    /// configuration so the misuse is loud at development time. Release
    /// builds retain the prior reflective behaviour for backward
    /// compatibility but emit a structured warning via
    /// `tracing_compat::warn!` so SREs can spot the pattern in logs.
    /// (br-asupersync-cors-credentialed-any.)
    #[must_use]
    pub fn new(inner: H, policy: CorsPolicy) -> Self {
        if matches!(policy.allow_origin, CorsAllowOrigin::Any) && policy.allow_credentials {
            debug_assert!(
                false,
                "CorsPolicy violates Fetch §3.2.5: allow_origin = Any with \
                 allow_credentials = true is a credential-reflection vulnerability. \
                 Use CorsPolicy::with_exact_origins(...) when allow_credentials is true."
            );
            crate::tracing_compat::warn!(
                "CorsPolicy: allow_origin=Any with allow_credentials=true — \
                 forbidden by Fetch §3.2.5; per-request Origin will be echoed \
                 (credential reflection). Use exact-origin allow-list instead."
            );
        }
        Self { inner, policy }
    }

    fn is_preflight(req: &Request) -> bool {
        req.method.eq_ignore_ascii_case("OPTIONS")
            && header_value(req, "origin").is_some()
            && header_value(req, "access-control-request-method").is_some()
    }

    fn is_malformed_origin_value(origin: &str) -> bool {
        origin.contains(',')
    }

    fn allowed_origin_value(&self, origin: &str) -> Option<String> {
        match &self.policy.allow_origin {
            CorsAllowOrigin::Any => {
                if self.policy.allow_credentials {
                    // br-asupersync-d4f31s: credential-reflection vulnerability
                    // (Fetch §3.2.5). The forbidden combination
                    // `Allow-Origin: *` + `Allow-Credentials: true` was
                    // previously laundered through a per-request Origin
                    // echo — technically not the literal `*` byte, but the
                    // SAME exfiltration: every requesting origin received
                    // its own Origin echoed back, so any origin could read
                    // the credentialed response. The real fix is to fail
                    // closed: emit NO `Access-Control-Allow-Origin` header
                    // at all under this misconfiguration. The downstream
                    // caller path (line 216) then falls through to the
                    // inner handler without setting any CORS response
                    // header, so the browser's same-origin enforcement
                    // blocks the response from being read by the foreign
                    // origin. The `debug_assert` in `new()` still rejects
                    // this configuration in debug builds; this guard is
                    // the release-build fail-closed.
                    crate::tracing_compat::warn!(
                        origin = %origin,
                        "CorsMiddleware: dropping Access-Control-Allow-Origin \
                         header — Allow-Origin = Any with Allow-Credentials = \
                         true is forbidden by Fetch §3.2.5 (credential \
                         reflection). Configure CorsPolicy::with_exact_origins \
                         when credentials are enabled."
                    );
                    None
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
        // Use set_header() rather than direct headers.insert() to route
        // through sanitize_header_value(), preventing CRLF injection from
        // a reflected Origin value.
        resp.set_header("access-control-allow-origin", allow_origin);
        // Cache key must vary by Origin when policy is origin-sensitive.
        // Use append (not insert) to preserve existing Vary tokens set by
        // the inner handler or other middleware (e.g., accept-encoding).
        append_vary_header(&mut resp, "origin");
        if self.policy.allow_credentials {
            resp.set_header("access-control-allow-credentials", "true");
        }
        if !self.policy.expose_headers.is_empty() {
            resp.set_header(
                "access-control-expose-headers",
                self.policy.expose_headers.join(", "),
            );
        }
        resp
    }
}

impl<H: Handler> Handler for CorsMiddleware<H> {
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // A response without CORS headers still depends on the request's
            // Origin: a shared cache must not serve it to an allowed origin,
            // which would then be blocked. Mark it `Vary: Origin` as well.
            let without_cors = |mut resp: Response| {
                append_vary_header(&mut resp, "origin");
                resp
            };
            let Some(origin) = header_value(&req, "origin") else {
                return without_cors(self.inner.call(&cx, req).await);
            };

            if Self::is_malformed_origin_value(&origin) {
                crate::tracing_compat::warn!(
                    origin = %origin,
                    "CorsMiddleware: dropping malformed multi-origin request header"
                );
                return without_cors(self.inner.call(&cx, req).await);
            }

            let Some(allow_origin) = self.allowed_origin_value(&origin) else {
                // Origin not allowed: pass through without CORS headers.
                return without_cors(self.inner.call(&cx, req).await);
            };

            if Self::is_preflight(&req) {
                let mut resp = Response::empty(StatusCode::NO_CONTENT);
                resp = self.apply_common_headers(resp, &allow_origin);
                resp.set_header(
                    "access-control-allow-methods",
                    self.policy.allow_methods.join(", "),
                );
                resp.set_header(
                    "access-control-allow-headers",
                    self.policy.allow_headers.join(", "),
                );
                if let Some(max_age) = self.policy.max_age {
                    resp.set_header("access-control-max-age", max_age.as_secs().to_string());
                }
                append_vary_header(&mut resp, "origin");
                append_vary_header(&mut resp, "access-control-request-method");
                append_vary_header(&mut resp, "access-control-request-headers");
                return resp;
            }

            let resp = self.inner.call(&cx, req).await;
            self.apply_common_headers(resp, &allow_origin)
        })
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

pub(crate) fn wall_clock_now() -> Time {
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
    budget_aware: bool,
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
            budget_aware: false,
            time_getter,
        }
    }

    /// Wrap a handler with a budget-aware timeout (D1 deadline propagation).
    ///
    /// The effective timeout is the smaller of `cap` and the remaining
    /// request budget (`cx.budget().deadline`) observed at request start —
    /// min-plus composition: the tightest constraint wins. As with every
    /// timeout of this middleware, the check runs when the handler returns:
    /// a request that arrives with its budget already exhausted still runs
    /// its handler (whose effects stand) and then gets the 504.
    #[must_use]
    pub fn budget_aware(inner: H, cap: Duration) -> Self {
        Self::budget_aware_with_time_getter(inner, cap, wall_clock_now)
    }

    /// Budget-aware timeout with a custom time source.
    #[must_use]
    pub fn budget_aware_with_time_getter(
        inner: H,
        cap: Duration,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            inner,
            timeout: cap,
            budget_aware: true,
            time_getter,
        }
    }

    /// Effective timeout for this request: the configured value, optionally
    /// tightened by the remaining `Cx` budget (min-plus).
    fn effective_timeout(&self, cx: &crate::Cx, now: Time) -> Duration {
        if !self.budget_aware {
            return self.timeout;
        }
        match cx.budget().deadline {
            Some(deadline) => {
                let remaining = Duration::from_nanos(deadline.duration_since(now));
                self.timeout.min(remaining)
            }
            None => self.timeout,
        }
    }
}

impl<H: Handler> Handler for TimeoutMiddleware<H> {
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let start = (self.time_getter)();
            let effective = self.effective_timeout(&cx, start);
            let effective_nanos = u64::try_from(effective.as_nanos()).unwrap_or(u64::MAX);
            let deadline = start.saturating_add_nanos(effective_nanos);

            let timeout_fut = crate::time::TimeoutFuture::with_time_getter(
                self.inner.call(&cx, req),
                deadline,
                self.time_getter,
            );

            match timeout_fut.await {
                Ok(resp) => {
                    let elapsed = Duration::from_nanos((self.time_getter)().duration_since(start));
                    if elapsed > effective {
                        Response::new(
                            StatusCode::GATEWAY_TIMEOUT,
                            format!("Request timed out after {elapsed:?}").into_bytes(),
                        )
                    } else {
                        resp
                    }
                }
                Err(_) => {
                    let elapsed = Duration::from_nanos((self.time_getter)().duration_since(start));
                    Response::new(
                        StatusCode::GATEWAY_TIMEOUT,
                        format!("Request timed out after {elapsed:?}").into_bytes(),
                    )
                }
            }
        })
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
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // The guard frees a half-open probe slot if this future is dropped
            // (client gone, timeout) or the handler panics; a bare permit kept
            // the slot taken for good, so every later request got 503.
            let permit = match self.breaker.acquire_guarded((self.time_getter)()) {
                Ok(permit) => permit,
                Err(crate::combinator::circuit_breaker::CircuitBreakerError::Open {
                    remaining,
                }) => {
                    let body = format!(
                        "Service Unavailable: circuit breaker open, retry after {remaining:?}"
                    );
                    return Response::new(StatusCode::SERVICE_UNAVAILABLE, body.into_bytes())
                        .header("retry-after", format!("{}", remaining.as_secs().max(1)));
                }
                Err(crate::combinator::circuit_breaker::CircuitBreakerError::HalfOpenFull) => {
                    return Response::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        b"Service Unavailable: circuit breaker half-open, max probes active"
                            .to_vec(),
                    );
                }
                Err(crate::combinator::circuit_breaker::CircuitBreakerError::Inner(())) => {
                    unreachable!("should_allow cannot produce inner operation errors")
                }
            };

            // Call the handler
            let resp = self.inner.call(&cx, req).await;
            // The outcome is stamped when the call ends: with the start time, a
            // failure that took longer than open_duration opened the breaker
            // already that long ago, so the open phase was skipped.
            let now = (self.time_getter)();
            if resp.status.is_server_error() {
                permit.record_failure("server_error", now);
            } else {
                permit.record_success(now);
            }
            resp
        })
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
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let now = (self.time_getter)();

        Box::pin(async move {
            // Check rate limit first
            let cost = self.limiter.policy().default_cost;
            match self.limiter.acquire_permit(cost, now) {
                Ok(permit) => {
                    // Rate limit passed, call inner handler
                    let response = self.inner.call(&cx, req).await;
                    permit.commit();
                    response
                }
                Err(
                    crate::combinator::rate_limit::RateLimitError::RateLimitExceeded
                    | crate::combinator::rate_limit::RateLimitError::Timeout { .. }
                    | crate::combinator::rate_limit::RateLimitError::Cancelled,
                ) => {
                    let retry_after = self.limiter.retry_after(cost, now);
                    let secs = retry_after.as_secs().max(1);
                    Response::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Too Many Requests: rate limit exceeded, retry after {secs}s")
                            .into_bytes(),
                    )
                    .header("retry-after", format!("{secs}"))
                }
                Err(crate::combinator::rate_limit::RateLimitError::QueueIdExhausted) => {
                    Response::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        b"Service Unavailable: rate limiter queue exhausted".to_vec(),
                    )
                }
                Err(crate::combinator::rate_limit::RateLimitError::Inner(())) => {
                    unreachable!("permit acquisition has no inner operation")
                }
            }
        })
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
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // Deterministic clock reading so bulkhead can drain stale timed-out
            // queue entries before admitting (br-asupersync-bulkhead-tryacquire-starve-kodql2).
            let now = cx
                .timer_driver()
                .map_or_else(crate::time::wall_now, |timer| timer.now());
            match self.bulkhead.try_acquire(1, now) {
                Some(p) => {
                    let resp = self.inner.call(&cx, req).await;
                    p.release();
                    resp
                }
                None => Response::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"Service Unavailable: concurrency limit reached".to_vec(),
                ),
            }
        })
    }
}

// ─── RetryMiddleware ────────────────────────────────────────────────────────

/// Middleware that retries failed handler invocations.
///
/// Only retries on 5xx server errors. The request body is cloned for each
/// retry attempt. By default, retries are restricted to idempotent methods
/// (GET, HEAD, OPTIONS, PUT, DELETE, TRACE). Call
/// [`RetryMiddleware::retry_all_methods`] to opt into retrying
/// non-idempotent methods such as POST and PATCH.
///
/// Note: In Phase 0 (synchronous), retry sleeps block the thread. Production
/// use should rely on async retry with cooperative yielding (Phase 1+).
pub struct RetryMiddleware<H> {
    inner: H,
    policy: RetryPolicy,
    /// When true, only retry idempotent methods.
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
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // Check if retry is appropriate for this method.
            if self.idempotent_only && !is_idempotent(&req.method) {
                return self.inner.call(&cx, req).await;
            }

            let max = self.policy.max_attempts.max(1);
            let mut delay = self.policy.initial_delay;
            let mut last_resp = None;

            for attempt in 0..max {
                // Clone request for retry (first attempt uses original).
                if attempt != 0 {
                    // Sleep before retry (Phase 1: async sleep with cancellation support).
                    if !delay.is_zero() {
                        // Use asupersync::time::sleep for cooperative yielding and cancellation support
                        crate::time::sleep(wall_clock_now(), delay).await;
                    }
                    // Compute next delay with exponential backoff.
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * self.policy.multiplier)
                            .min(self.policy.max_delay.as_secs_f64()),
                    );
                }
                let try_req = req.clone();

                let resp = self.inner.call(&cx, try_req).await;
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
    /// Maximum compressed response body size (bytes).
    pub max_compressed_size: usize,
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
            max_compressed_size: DEFAULT_MAX_COMPRESSED_SIZE,
        }
    }
}

/// Middleware that compresses response bodies based on Accept-Encoding
/// negotiation.
///
/// Uses [`negotiate_encoding`] to select the best encoding from the
/// client's Accept-Encoding header against the server's supported set.
/// Only compresses when the response body exceeds `min_body_size`.
///
/// Like [`crate::web::compress`], it leaves uncompressed a response that a
/// BREACH-style length oracle could probe: one to a request carrying Cookie,
/// Authorization, X-CSRF-Token or X-XSRF-Token, or one that sets a cookie or
/// is marked `Cache-Control: private`/`no-store`/`no-cache`. It never
/// compresses a 206 (its Content-Range describes the uncompressed bytes).
pub struct CompressionMiddleware<H> {
    inner: H,
    config: CompressionConfig,
    compress_sensitive: bool,
    /// Offer zstd ahead of the configured encodings (see `with_zstd`).
    zstd: bool,
}

impl<H: Handler> CompressionMiddleware<H> {
    /// Wrap a handler with response compression.
    #[must_use]
    pub fn new(inner: H, config: CompressionConfig) -> Self {
        Self {
            inner,
            config,
            compress_sensitive: false,
            zstd: false,
        }
    }

    /// Also offer `zstd` (RFC 8878 §7.2), ahead of the configured encodings,
    /// so it wins a tie in client quality. Bodies go out as frames of at most
    /// 1 MiB, far below the 8 MiB window RFC 9659 lets decoders require,
    /// within `max_compressed_size`.
    #[cfg(feature = "zstd")]
    #[must_use]
    pub fn with_zstd(mut self) -> Self {
        self.zstd = true;
        self
    }

    /// Also compress the responses the BREACH guard leaves uncompressed.
    /// Enable this only when such responses never mix secrets with
    /// attacker-influenced content.
    #[must_use]
    pub fn compress_sensitive_responses(mut self, enabled: bool) -> Self {
        self.compress_sensitive = enabled;
        self
    }
}

impl<H: Handler> Handler for CompressionMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let accept_encoding = header_value(&req, "accept-encoding");
            let sensitivity = RequestCompressionSensitivity::from_request(&req);
            let mut resp = self.inner.call(&cx, req).await;

            if resp.status == StatusCode::NO_CONTENT {
                return resp;
            }
            if resp.status == StatusCode::NOT_MODIFIED {
                // A 304 carries the Vary of the response it validates.
                append_vary_header(&mut resp, "accept-encoding");
                return resp;
            }

            if let Some(existing_encoding) = resp.remove_header("content-encoding") {
                resp.set_header("content-encoding", existing_encoding);
                return resp;
            }

            if is_partial_content(&resp) {
                return resp;
            }

            // Nothing to encode: gzipping an empty body broke streamed routes
            // (their head may not carry bytes) and HEAD's Content-Length.
            if resp.body.is_empty() {
                return resp;
            }

            let available_encodings: Vec<_> = self
                .zstd
                .then_some(ContentCoding::Zstd)
                .into_iter()
                .chain(
                    self.config
                        .supported
                        .iter()
                        .map(|&encoding| ContentCoding::from(encoding)),
                )
                .filter(|coding| compression_coding_available(*coding))
                .collect();

            let identity_acceptable =
                negotiate_encoding(accept_encoding.as_deref(), &[ContentEncoding::Identity])
                    == Some(ContentEncoding::Identity);

            if !self.compress_sensitive && compression_oracle_sensitive(sensitivity, &resp) {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                append_vary_header(&mut resp, "accept-encoding");
                sensitivity.append_vary_tokens(&mut resp);
                return resp;
            }

            let body_below_minimum = resp.body.len() < self.config.min_body_size;
            if body_below_minimum && identity_acceptable {
                return resp;
            }

            let candidate_encodings = if body_below_minimum {
                available_encodings
                    .iter()
                    .copied()
                    .filter(|coding| *coding != ContentCoding::Identity)
                    .collect::<Vec<_>>()
            } else {
                available_encodings
            };

            let Some(encoding) = negotiate_coding(accept_encoding.as_deref(), &candidate_encodings)
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
            if encoding == ContentCoding::Identity {
                append_vary_header(&mut resp, "accept-encoding");
                return resp;
            }

            let Some(compressed) =
                compress_body(encoding, &resp.body, self.config.max_compressed_size)
            else {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                return resp;
            };
            let Ok(compressed) = compressed else {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                append_vary_header(&mut resp, "accept-encoding");
                return resp;
            };

            if compressed.len() >= resp.body.len() && identity_acceptable {
                append_vary_header(&mut resp, "accept-encoding");
                return resp;
            }

            resp.body = compressed.into();
            resp.remove_header("content-length");
            resp.set_header("content-encoding", encoding.as_token().to_string());
            weaken_etag(&mut resp);
            append_vary_header(&mut resp, "accept-encoding");
            resp
        })
    }
}

fn compression_coding_available(coding: ContentCoding) -> bool {
    match coding {
        ContentCoding::Identity => true,
        ContentCoding::Brotli | ContentCoding::Gzip | ContentCoding::Deflate => {
            cfg!(feature = "compression")
        }
        ContentCoding::Zstd => cfg!(feature = "zstd"),
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
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // SECURITY: Check Content-Length header BEFORE reading body to prevent DoS
            if let Some(cl_value) = super::extract::header_value_ci(&req, "content-length") {
                if let Ok(declared_length) = super::extract::parse_content_length(cl_value) {
                    if declared_length > self.max_bytes {
                        return Response::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!(
                                "Payload Too Large: Content-Length {} bytes exceeds limit {} bytes",
                                declared_length, self.max_bytes
                            )
                            .into_bytes(),
                        );
                    }
                }
            }

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
            // A streaming body (StreamingRawBody) is not in `req.body`, and a
            // chunked upload declares no Content-Length: neither check above
            // sees it. Cap the stream itself, as the router's body policy
            // does, so reading past the limit fails with BodyTooLarge.
            #[cfg(not(target_arch = "wasm32"))]
            super::extract::tighten_streaming_raw_body(&req, self.max_bytes);
            self.inner.call(&cx, req).await
        })
    }
}

// ─── RequestIdMiddleware ──────────────────────────────────────────────────

/// Default upper bound on a client-supplied request-ID character length.
///
/// 128 chars is generous for legitimate UUIDs (36 chars), ULIDs (26 chars),
/// CUIDs (25 chars), and the longest standard correlation IDs in the
/// ecosystem (W3C `traceparent` tracestate ~128 chars). Anything longer
/// is almost certainly an attacker probing log-amplification surfaces.
/// (br-asupersync-pol3ps.)
pub const DEFAULT_REQUEST_ID_MAX_LENGTH: usize = 128;

/// Default maximum length for trace IDs extracted from headers.
/// Same as request ID length to maintain consistency and prevent
/// amplification attacks. (br-asupersync-gwezkv)
pub const DEFAULT_TRACE_ID_MAX_LENGTH: usize = 128;

/// Middleware that generates or propagates a request ID.
///
/// If the request contains a header matching `header_name`, its value is
/// used. Otherwise, a monotonically increasing ID is generated. The ID
/// is stored in the request extensions under `"request_id"` and echoed
/// in the response header.
///
/// # Length bound (security)
///
/// Client-supplied request-ID values are TRUNCATED to `max_id_length`
/// characters (default [`DEFAULT_REQUEST_ID_MAX_LENGTH`] = 128) BEFORE
/// being stored in extensions or echoed in the response. Without this
/// bound, an attacker could send a multi-MiB `X-Request-ID` header that
/// is then cloned into request extensions twice (`request_id` +
/// `trace_id`), echoed in the response header, and logged by every
/// downstream middleware — a per-request log/memory amplification of
/// 4-8x the header size. Configure with [`Self::with_max_length`].
/// (br-asupersync-pol3ps.)
pub struct RequestIdMiddleware<H> {
    inner: H,
    header_name: String,
    counter: Arc<AtomicU64>,
    max_id_length: usize,
}

impl<H: Handler> RequestIdMiddleware<H> {
    /// Wrap a handler with request ID generation.
    ///
    /// `header_name` specifies which request/response header carries the ID
    /// (e.g., `"x-request-id"`).
    ///
    /// Client-supplied IDs are truncated at
    /// [`DEFAULT_REQUEST_ID_MAX_LENGTH`] characters; override with
    /// [`Self::with_max_length`].
    #[must_use]
    pub fn new(inner: H, header_name: impl Into<String>) -> Self {
        Self {
            inner,
            header_name: normalize_header_name(header_name),
            counter: Arc::new(AtomicU64::new(1)),
            max_id_length: DEFAULT_REQUEST_ID_MAX_LENGTH,
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
            max_id_length: DEFAULT_REQUEST_ID_MAX_LENGTH,
        }
    }

    /// Set the maximum allowed length, in characters, of a client-supplied
    /// request-ID header value. Values longer than this are TRUNCATED at a
    /// UTF-8 character boundary before being stored or echoed. A value of
    /// `0` is rejected and silently coerced to
    /// [`DEFAULT_REQUEST_ID_MAX_LENGTH`] to prevent accidental
    /// disable-the-cap configurations. (br-asupersync-pol3ps.)
    #[must_use]
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_id_length = if max == 0 {
            DEFAULT_REQUEST_ID_MAX_LENGTH
        } else {
            max
        };
        self
    }
}

/// Truncate `id` to at most `max` UTF-8 characters at a char boundary.
/// String::truncate panics on a non-char boundary; we instead find the
/// largest valid prefix.
fn truncate_request_id(id: &str, max: usize) -> String {
    if id.chars().count() <= max {
        return id.to_string();
    }
    let mut end = 0usize;
    for (i, _) in id.char_indices().take(max) {
        end = i;
    }
    // `end` now holds the byte index of the LAST kept char; advance past it
    // by walking one more char_indices step or using char_indices().nth.
    let mut iter = id.char_indices().skip(max);
    let cutoff = iter.next().map_or(id.len(), |(idx, _)| idx);
    let _ = end;
    id[..cutoff].to_string()
}

/// Sanitize and truncate a request/trace ID to prevent security issues.
///
/// This function performs two security-critical operations:
/// 1. Remove CRLF characters to prevent response header injection
/// 2. Truncate to max length to prevent log/memory amplification attacks
///
/// Order matters: sanitize CRLF first, then truncate, so we don't truncate
/// inside a control sequence.
fn sanitize_and_truncate_id(id: &str, max_length: usize) -> String {
    let sanitized = id.replace(['\r', '\n'], "");
    truncate_request_id(&sanitized, max_length)
}

impl<H: Handler> Handler for RequestIdMiddleware<H> {
    fn call(
        &self,
        cx: &crate::Cx,
        mut req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let request_id = header_value(&req, &self.header_name).unwrap_or_else(|| {
                let id = self.counter.fetch_add(1, Ordering::Relaxed);
                format!("req-{id}")
            });
            // Sanitize CRLF and truncate to prevent response header injection
            // and log amplification attacks (br-asupersync-pol3ps).
            let request_id = sanitize_and_truncate_id(&request_id, self.max_id_length);

            req.extensions.insert("request_id", request_id.clone());
            req.extensions.insert("trace_id", request_id.clone());

            let mut resp = self.inner.call(&cx, req).await;
            resp.set_header(&self.header_name, request_id);
            resp
        })
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

/// Structured record of one traced request/response exchange.
///
/// This is the canonical schema of the request log line emitted by
/// [`RequestTraceMiddleware`] and the router's default-on request trace.
/// Golden tests pin it through a [`RequestLogSink`], so changes here are
/// log-contract changes (br-asupersync-server-stack-hardening-eeexl1.3).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestLogRecord {
    /// Request method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Status as logged. Cancelled requests log `499` (client closed
    /// request) regardless of what the handler produced.
    pub status: u16,
    /// Outcome severity label: `ok`, `client_error`, `server_error`, or
    /// `cancelled`.
    pub severity: &'static str,
    /// Clock duration of the exchange in milliseconds.
    pub duration_ms: u128,
    /// Correlation id resolved from extensions / headers, if any.
    pub request_id: Option<String>,
    /// Whether cancellation was observed on the request `Cx`.
    pub cancelled: bool,
    /// The cancel reason, when cancelled.
    pub cancel_reason: Option<String>,
}

/// Observer invoked with the structured record of every traced exchange.
pub type RequestLogSink = Arc<dyn Fn(&RequestLogRecord) + Send + Sync>;

/// Shared trace instrumentation driving both [`RequestTraceMiddleware`] and
/// the router's default-on request trace.
///
/// Cancellation is an outcome, not an error: a request whose `Cx` observed
/// cancellation is logged as `499` with its cancel reason, so operators can
/// tell client-abandoned work from failures.
pub(crate) async fn trace_request<F, Fut>(
    policy: &RequestTracePolicy,
    time_getter: fn() -> Time,
    sink: Option<&RequestLogSink>,
    cx: &Cx,
    req: Request,
    call: F,
) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    let method = req.method.clone();
    let path = req.path.clone();
    let trace_id = resolve_trace_id(&req);
    let start = time_getter();

    debug!(
        method = %method,
        path = %path,
        trace_id = ?trace_id,
        "http request start"
    );

    let mut resp = call(req).await;
    let duration_ms = Duration::from_nanos(time_getter().duration_since(start)).as_millis();

    let cancelled = cx.is_cancel_requested();
    let cancel_reason = if cancelled {
        Some(
            cx.cancel_reason()
                .map_or_else(|| "unknown".to_string(), |reason| reason.to_string()),
        )
    } else {
        None
    };
    let status_code = if cancelled { 499 } else { resp.status.as_u16() };
    let severity = if cancelled {
        "cancelled"
    } else if status_code >= 500 {
        "server_error"
    } else if status_code >= 400 {
        "client_error"
    } else {
        "ok"
    };

    if let Some(header_name) = &policy.duration_header {
        resp.set_header(header_name, duration_ms.to_string());
    }

    if let (Some(header_name), Some(id)) = (&policy.trace_header, trace_id.as_ref()) {
        // Trace ID is already sanitized and truncated by resolve_trace_id
        if !resp.has_header(header_name) {
            resp.set_header(header_name, id.clone());
        }
    }

    if cancelled {
        warn!(
            method = %method,
            path = %path,
            status = status_code,
            severity = severity,
            duration_ms = duration_ms,
            trace_id = ?trace_id,
            cancel_reason = ?cancel_reason,
            "http request cancelled"
        );
    } else if status_code >= 500 {
        warn!(
            method = %method,
            path = %path,
            status = status_code,
            severity = severity,
            duration_ms = duration_ms,
            trace_id = ?trace_id,
            "http request completed with server error"
        );
    } else {
        debug!(
            method = %method,
            path = %path,
            status = status_code,
            severity = severity,
            duration_ms = duration_ms,
            trace_id = ?trace_id,
            "http request completed"
        );
    }

    if let Some(sink) = sink {
        sink(&RequestLogRecord {
            method,
            path,
            status: status_code,
            severity,
            duration_ms,
            request_id: trace_id,
            cancelled,
            cancel_reason,
        });
    }

    resp
}

/// Middleware that emits request/response tracing events and optional metadata headers.
pub struct RequestTraceMiddleware<H> {
    inner: H,
    policy: RequestTracePolicy,
    time_getter: fn() -> Time,
    sink: Option<RequestLogSink>,
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
            sink: None,
        }
    }

    /// Attach a structured record sink observing every traced exchange.
    ///
    /// Used by golden tests to pin the log schema; production deployments
    /// normally rely on the `tracing` events instead.
    #[must_use]
    pub fn with_record_sink(mut self, sink: RequestLogSink) -> Self {
        self.sink = Some(sink);
        self
    }
}

/// Free-function resolver shared by `RequestTraceMiddleware` and
/// `CatchPanicMiddleware` so panic logs carry the same correlation
/// id as the request-trace logs.
///
/// Resolution order: extensions `trace_id`, then extensions
/// `request_id`, then the raw `x-request-id` header (sanitized +
/// truncated to `DEFAULT_TRACE_ID_MAX_LENGTH` to prevent DoS via
/// giant headers being amplified into logs / response headers,
/// br-asupersync-gwezkv).
pub(crate) fn resolve_trace_id(req: &Request) -> Option<String> {
    if let Some(id) = req.extensions.get("trace_id") {
        return Some(id.to_string());
    }
    if let Some(id) = req.extensions.get("request_id") {
        return Some(id.to_string());
    }
    header_value(req, "x-request-id")
        .map(|id| sanitize_and_truncate_id(&id, DEFAULT_TRACE_ID_MAX_LENGTH))
}

impl<H: Handler> Handler for RequestTraceMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            trace_request(
                &self.policy,
                self.time_getter,
                self.sink.as_ref(),
                &cx,
                req,
                |req| self.inner.call(&cx, req),
            )
            .await
        })
    }
}

// ─── W3CTraceContextMiddleware ─────────────────────────────────────────────

/// Middleware that continues the request's W3C trace context or starts one.
///
/// It reads `traceparent`, `tracestate` and `baggage` and runs the handler as
/// a child span of that context; a missing or invalid `traceparent` starts a
/// new trace (see
/// [`continue_or_start_trace`](crate::observability::w3c_trace_context::continue_or_start_trace)).
/// New trace and span ids come from the request `Cx`'s entropy source, so a
/// lab run replays them. The handler finds its span in the request extensions:
/// - `traceparent`, and `tracestate` / `baggage` when present, ready to copy
///   onto outgoing requests so the trace continues downstream;
/// - `trace_id` (the 32-hex trace id), unless an outer layer set one, so the
///   logs of [`RequestTraceMiddleware`] and [`CatchPanicMiddleware`] layered
///   inside this one carry the W3C trace id. A [`RequestIdMiddleware`] layered
///   inside this one replaces it with the request id.
///
/// A client picks the trace id it sends. At an untrusted edge, either accept
/// that (the usual W3C deployment) or place this layer behind a gateway that
/// resets `traceparent`.
pub struct W3CTraceContextMiddleware<H> {
    inner: H,
}

impl<H: Handler> W3CTraceContextMiddleware<H> {
    /// Wrap a handler with W3C trace context propagation.
    #[must_use]
    pub fn new(inner: H) -> Self {
        Self { inner }
    }
}

impl<H: Handler> Handler for W3CTraceContextMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        mut req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let headers: std::collections::HashMap<String, String> =
            ["traceparent", "tracestate", "baggage"]
                .into_iter()
                .filter_map(|name| Some((name.to_string(), req.header(name)?.to_string())))
                .collect();
        // New ids come from the request's Cx, so a lab run replays them.
        let context = crate::observability::w3c_trace_context::continue_or_start_trace_with(
            &headers,
            |bytes: &mut [u8]| cx.random_bytes(bytes),
        );
        req.extensions
            .insert("traceparent", context.to_traceparent());
        if let Some(tracestate) = &context.tracestate {
            req.extensions.insert("tracestate", tracestate.clone());
        }
        if let Ok(baggage) = context.baggage.to_header() {
            if !baggage.is_empty() {
                req.extensions.insert("baggage", baggage);
            }
        }
        if req.extensions.get("trace_id").is_none() {
            req.extensions.insert("trace_id", context.trace_id.to_hex());
        }
        self.inner.call(cx, req)
    }
}

// ─── AuthMiddleware ────────────────────────────────────────────────────────

/// Authorization policy for bearer-token middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPolicy {
    /// Any well-formed bearer token is accepted.
    AnyBearer,
    /// Only the listed bearer tokens are accepted while unexpired. An empty
    /// allowlist fails closed, which is also the default policy.
    ExactBearer(Vec<BearerToken>),
}

/// A bearer token accepted by [`AuthPolicy::ExactBearer`] until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerToken {
    token: String,
    expires_at: Time,
}

impl BearerToken {
    /// Create a token record that expires at the provided runtime time.
    #[must_use]
    pub fn new(token: impl Into<String>, expires_at: Time) -> Self {
        Self {
            token: token.into(),
            expires_at,
        }
    }

    /// Create a token record with no practical expiration.
    #[must_use]
    pub fn non_expiring(token: impl Into<String>) -> Self {
        Self::new(token, Time::MAX)
    }

    /// Return the raw bearer token string.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Return the expiration instant.
    #[must_use]
    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }

    fn is_valid_at(&self, now: Time) -> bool {
        now < self.expires_at
    }
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self::ExactBearer(Vec::new())
    }
}

impl AuthPolicy {
    /// Require exactly one bearer token.
    #[must_use]
    pub fn exact_bearer(token: impl Into<String>) -> Self {
        Self::ExactBearer(vec![BearerToken::non_expiring(token)])
    }

    /// Require exactly one bearer token until `expires_at`.
    #[must_use]
    pub fn exact_bearer_until(token: impl Into<String>, expires_at: Time) -> Self {
        Self::ExactBearer(vec![BearerToken::new(token, expires_at)])
    }

    /// Require exactly one bearer token for `ttl` after `issued_at`.
    #[must_use]
    pub fn exact_bearer_for(token: impl Into<String>, issued_at: Time, ttl: Duration) -> Self {
        Self::exact_bearer_until(token, issued_at + ttl)
    }

    /// Add a replacement bearer token and remove tokens expired at `now`.
    ///
    /// This supports rotation windows where the old token remains accepted
    /// until its own expiration while the new token becomes valid immediately.
    pub fn rotate_exact_bearer(&mut self, token: impl Into<String>, expires_at: Time, now: Time) {
        if let Self::ExactBearer(tokens) = self {
            tokens.retain(|token| token.is_valid_at(now));
            tokens.push(BearerToken::new(token, expires_at));
        }
    }

    /// Remove expired exact-bearer tokens. `AnyBearer` is unchanged.
    pub fn prune_expired(&mut self, now: Time) {
        if let Self::ExactBearer(tokens) = self {
            tokens.retain(|token| token.is_valid_at(now));
        }
    }

    fn allows_at(&self, req: &Request, now: Time) -> bool {
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
                    let token_matches = constant_time_str_eq(expected.token(), token);
                    let token_active = expected.is_valid_at(now);
                    // Intentional bitwise OR for constant-time comparison —
                    // `||` would short-circuit and leak timing information.
                    #[allow(clippy::needless_bitwise_bool)]
                    let result = matched | (token_active & token_matches);
                    result
                })
            }
        }
    }
}

fn constant_time_str_eq(expected: &str, token: &str) -> bool {
    let mut diff = 0u8;
    if expected.len() != token.len() {
        diff |= 1;
    }
    let token_bytes = token.as_bytes();
    for (i, b) in expected.bytes().enumerate() {
        diff |= b ^ token_bytes.get(i).copied().unwrap_or(0);
    }
    diff == 0
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
    time_getter: fn() -> Time,
}

impl<H: Handler> AuthMiddleware<H> {
    /// Wrap a handler with authorization checks.
    #[must_use]
    pub fn new(inner: H, policy: AuthPolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Wrap a handler with authorization checks using an injected clock.
    #[must_use]
    pub fn with_time_getter(inner: H, policy: AuthPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            inner,
            policy,
            time_getter,
        }
    }
}

impl<H: Handler> Handler for AuthMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            if !self.policy.allows_at(&req, (self.time_getter)()) {
                return Response::new(StatusCode::UNAUTHORIZED, b"Unauthorized".to_vec())
                    .header("www-authenticate", "Bearer");
            }
            self.inner.call(&cx, req).await
        })
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
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
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
            self.inner.call(&cx, req).await
        })
    }
}

// ─── CatchPanicMiddleware ─────────────────────────────────────────────────

/// Middleware that catches panics in the inner handler and returns a
/// 500 Internal Server Error response instead of unwinding.
///
/// This is a safety net for production servers: a panicking handler
/// should not take down the entire server. On panic, a structured
/// `tracing::error!` event is emitted carrying the request method,
/// path, trace-id (resolved via the same lookup
/// `RequestTraceMiddleware` uses, so panic logs correlate with the
/// surrounding request-trace events), and the stringified panic
/// payload. The panic message is NOT exposed to the client (to avoid
/// information leakage).
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

/// Best-effort string extraction from a `catch_unwind` payload.
///
/// `panic!` payloads are commonly `&'static str` or `String`; we
/// downcast to both. Anything else surfaces as a sentinel string so the
/// log site never panics on the panic — the recovery path must be
/// totally infallible.
pub(super) fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

impl<H: Handler> Handler for CatchPanicMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let method = req.method.clone();
            let path = req.path.clone();
            let trace_id = resolve_trace_id(&req);

            // Two-stage safety net: a handler can panic either synchronously
            // while CONSTRUCTING its future (inside `call()` itself) or later
            // while the future is POLLED. Both must convert to a 500 — a
            // construction panic escaping here would tear down the connection
            // task this middleware exists to protect
            // (br-asupersync-server-stack-hardening-eeexl1.3).
            let outcome =
                match std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.call(&cx, req))) {
                    Ok(future) => crate::util::future::catch_unwind(AssertUnwindSafe(future)).await,
                    Err(payload) => Err(payload),
                };

            match outcome {
                Ok(response) => response,
                Err(payload) => {
                    let panic_message = panic_payload_message(payload.as_ref());
                    let _panic_log_fields = (&method, &path, &trace_id, &panic_message);
                    error!(
                        method = %method,
                        path = %path,
                        trace_id = trace_id.as_deref().unwrap_or(""),
                        panic_message = %panic_message,
                        "[ASUP-E502] web handler panic recovered"
                    );
                    // The panic message stays server-side; the client gets the
                    // stable remediation token only (no information leakage).
                    Response::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        b"[ASUP-E502] Internal Server Error".to_vec(),
                    )
                }
            }
        })
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

/// Build a permanent normalization redirect, rejecting any candidate that the
/// central redirect validator classifies as unsafe.
fn normalization_redirect_response(path: &str) -> Response {
    let candidate = path.replace(['\r', '\n'], "");
    match Redirect::permanent(candidate.clone()) {
        Ok(redirect) => redirect.into_response(),
        Err(err) => {
            let _ = &err;
            warn!(
                path = %candidate,
                error = %err,
                "NormalizePathMiddleware: refusing unsafe redirect candidate"
            );
            Response::new(
                StatusCode::BAD_REQUEST,
                b"Bad Request: invalid normalized redirect target".to_vec(),
            )
        }
    }
}

/// Keeps the request's query on a normalized redirect target, so
/// `GET /search/?q=x` redirects to `/search?q=x` rather than `/search`.
fn with_request_query(path: String, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path,
    }
}

fn invalid_normalized_redirect_response(path: &str, err: impl std::fmt::Display) -> Response {
    let _ = (&path, &err);
    warn!(
        path = %path,
        error = %err,
        "NormalizePathMiddleware: refusing unsafe request path for redirect strategy"
    );
    Response::new(
        StatusCode::BAD_REQUEST,
        b"Bad Request: invalid normalized redirect target".to_vec(),
    )
}

impl<H: Handler> Handler for NormalizePathMiddleware<H> {
    fn call(
        &self,
        cx: &Cx,
        mut req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let path = &req.path;
            if matches!(
                self.strategy,
                TrailingSlash::RedirectTrim | TrailingSlash::RedirectAlways
            ) && let Err(err) = Redirect::permanent(path.clone())
            {
                return invalid_normalized_redirect_response(path, err);
            }

            match self.strategy {
                TrailingSlash::Trim => {
                    if path.len() > 1 && path.ends_with('/') {
                        req.path = path.trim_end_matches('/').to_string();
                        if req.path.is_empty() {
                            req.path = "/".to_string();
                        }
                    }
                    self.inner.call(&cx, req).await
                }
                TrailingSlash::Always => {
                    if !path.ends_with('/') && !path.contains('.') {
                        req.path = format!("{path}/");
                    }
                    self.inner.call(&cx, req).await
                }
                TrailingSlash::RedirectTrim => {
                    if path.len() > 1 && path.ends_with('/') {
                        let mut trimmed = path.trim_end_matches('/').to_string();
                        if trimmed.is_empty() {
                            trimmed = "/".to_string();
                        }
                        let target = with_request_query(trimmed, req.query.as_deref());
                        return normalization_redirect_response(&target);
                    }
                    self.inner.call(&cx, req).await
                }
                TrailingSlash::RedirectAlways => {
                    if !path.ends_with('/') && !path.contains('.') {
                        let target = with_request_query(format!("{path}/"), req.query.as_deref());
                        return normalization_redirect_response(&target);
                    }
                    self.inner.call(&cx, req).await
                }
            }
        })
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
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let mut resp = self.inner.call(&cx, req).await;
            match self.mode {
                HeaderOverwrite::Always => {
                    resp.set_header(&self.name, self.value.clone());
                }
                HeaderOverwrite::IfMissing => {
                    resp.ensure_header(&self.name, self.value.clone());
                }
            }
            resp
        })
    }
}

// ─── MiddlewareStack ────────────────────────────────────────────────────────

/// Builder for composing multiple middleware layers around a handler.
///
/// Each `with_*` call wraps the stack built so far, so the last-added layer is
/// the outermost layer. The resulting type implements [`Handler`].
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
/// Execution order: CircuitBreaker → RateLimit → Timeout → Handler
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
        self.layer(TimeoutLayer::new(timeout))
    }

    /// Add a CORS middleware layer.
    #[must_use]
    pub fn with_cors(self, policy: CorsPolicy) -> MiddlewareStack<CorsMiddleware<H>> {
        self.layer(CorsLayer::new(policy))
    }

    /// Add a circuit breaker middleware layer.
    #[must_use]
    pub fn with_circuit_breaker(
        self,
        policy: CircuitBreakerPolicy,
    ) -> MiddlewareStack<CircuitBreakerMiddleware<H>> {
        self.layer(CircuitBreakerLayer::new(policy))
    }

    /// Add a circuit breaker middleware layer with a shared breaker.
    #[must_use]
    pub fn with_shared_circuit_breaker(
        self,
        breaker: Arc<CircuitBreaker>,
    ) -> MiddlewareStack<CircuitBreakerMiddleware<H>> {
        self.layer(CircuitBreakerLayer::shared(breaker))
    }

    /// Add a rate limit middleware layer.
    #[must_use]
    pub fn with_rate_limit(
        self,
        policy: RateLimitPolicy,
    ) -> MiddlewareStack<RateLimitMiddleware<H>> {
        self.layer(RateLimitLayer::new(policy))
    }

    /// Add a rate limit middleware layer with a shared limiter.
    #[must_use]
    pub fn with_shared_rate_limit(
        self,
        limiter: Arc<RateLimiter>,
    ) -> MiddlewareStack<RateLimitMiddleware<H>> {
        self.layer(RateLimitLayer::shared(limiter))
    }

    /// Add a bulkhead middleware layer.
    #[must_use]
    pub fn with_bulkhead(self, policy: BulkheadPolicy) -> MiddlewareStack<BulkheadMiddleware<H>> {
        self.layer(BulkheadLayer::new(policy))
    }

    /// Add a bulkhead middleware layer with a shared bulkhead.
    #[must_use]
    pub fn with_shared_bulkhead(
        self,
        bulkhead: Arc<Bulkhead>,
    ) -> MiddlewareStack<BulkheadMiddleware<H>> {
        self.layer(BulkheadLayer::shared(bulkhead))
    }

    /// Add a retry middleware layer.
    #[must_use]
    pub fn with_retry(self, policy: RetryPolicy) -> MiddlewareStack<RetryMiddleware<H>> {
        self.layer(RetryLayer::new(policy))
    }

    /// Add a response compression middleware layer.
    #[must_use]
    pub fn with_compression(
        self,
        config: CompressionConfig,
    ) -> MiddlewareStack<CompressionMiddleware<H>> {
        self.layer(CompressionLayer::new(config))
    }

    /// Add a request body size limit middleware layer.
    #[must_use]
    pub fn with_body_limit(
        self,
        max_bytes: usize,
    ) -> MiddlewareStack<RequestBodyLimitMiddleware<H>> {
        self.layer(RequestBodyLimitLayer::new(max_bytes))
    }

    /// Add a bearer auth middleware layer.
    #[must_use]
    pub fn with_auth(self, policy: AuthPolicy) -> MiddlewareStack<AuthMiddleware<H>> {
        self.layer(AuthLayer::new(policy))
    }

    /// Add request-level load shedding middleware.
    #[must_use]
    pub fn with_load_shed(self, policy: LoadShedPolicy) -> MiddlewareStack<LoadShedMiddleware<H>> {
        self.layer(LoadShedLayer::new(policy))
    }

    /// Add a request ID middleware layer.
    #[must_use]
    pub fn with_request_id(
        self,
        header_name: impl Into<String>,
    ) -> MiddlewareStack<RequestIdMiddleware<H>> {
        self.layer(RequestIdLayer::new(header_name))
    }

    /// Add request/response tracing middleware.
    #[must_use]
    pub fn with_request_trace(
        self,
        policy: RequestTracePolicy,
    ) -> MiddlewareStack<RequestTraceMiddleware<H>> {
        self.layer(RequestTraceLayer::new(policy))
    }

    /// Add W3C trace context propagation.
    #[must_use]
    pub fn with_w3c_trace_context(self) -> MiddlewareStack<W3CTraceContextMiddleware<H>> {
        self.layer(W3CTraceContextLayer::new())
    }

    /// Add a panic recovery middleware layer.
    #[must_use]
    pub fn with_catch_panic(self) -> MiddlewareStack<CatchPanicMiddleware<H>> {
        self.layer(CatchPanicLayer::new())
    }

    /// Add a path normalization middleware layer.
    #[must_use]
    pub fn with_normalize_path(
        self,
        strategy: TrailingSlash,
    ) -> MiddlewareStack<NormalizePathMiddleware<H>> {
        self.layer(NormalizePathLayer::new(strategy))
    }

    /// Add a response header injection middleware layer.
    #[must_use]
    pub fn with_response_header(
        self,
        name: impl Into<String>,
        value: impl Into<String>,
        mode: HeaderOverwrite,
    ) -> MiddlewareStack<SetResponseHeaderMiddleware<H>> {
        self.layer(SetResponseHeaderLayer::new(name, value, mode))
    }

    /// Apply any [`Layer`] whose output is itself a [`Handler`].
    ///
    /// This is the generic escape hatch that proves the stack is sugar over
    /// the unified [`Layer`] machinery: every `with_*` method is equivalent to
    /// `self.layer(SomeLayer::new(...))`.
    #[must_use]
    pub fn layer<L>(self, layer: L) -> MiddlewareStack<L::Service>
    where
        L: Layer<H>,
        L::Service: Handler,
    {
        MiddlewareStack {
            inner: layer.layer(self.inner),
        }
    }

    /// Finish building and return the composed handler.
    #[must_use]
    pub fn build(self) -> H {
        self.inner
    }
}

// ─── Layer adapters (unified service/web layering) ──────────────────────────
//
// br-asupersync-server-stack-hardening-eeexl1.3: the web middleware family and
// the `service` stack share ONE composition trait: [`crate::service::Layer`].
// Each middleware above has a companion `*Layer` adapter implementing
// `Layer<H: Handler>`, so handlers can be wrapped via `Router::layer`,
// [`MiddlewareStack`], or raw `service::Stack` composition interchangeably.
//
// Shared-state semantics: stateful layers (`CircuitBreakerLayer`,
// `RateLimitLayer`, `BulkheadLayer`, `LoadShedLayer`, `RequestIdLayer`) create
// their shared state ONCE at layer construction. Applying the same layer value
// to multiple handlers — as `Router::layer` does, one wrap per route — shares
// the breaker / limiter / bulkhead / in-flight counter / ID counter across all
// wrapped routes. Construct separate layer values when per-route isolation is
// wanted.

/// Layer that applies [`CorsMiddleware`] with a fixed policy.
#[derive(Debug, Clone)]
pub struct CorsLayer {
    policy: CorsPolicy,
}

impl CorsLayer {
    /// Create a CORS layer from the given policy.
    #[must_use]
    pub fn new(policy: CorsPolicy) -> Self {
        Self { policy }
    }
}

impl<H: Handler> Layer<H> for CorsLayer {
    type Service = CorsMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        CorsMiddleware::new(inner, self.policy.clone())
    }
}

/// Layer that applies [`TimeoutMiddleware`] with a fixed timeout.
///
/// ```
/// use asupersync::web::middleware::TimeoutLayer;
/// use asupersync::web::{FnHandler, Router, get};
/// use std::time::Duration;
///
/// let app = Router::new()
///     .route("/", get(FnHandler::new(|| "ok")))
///     // Effective timeout = min(2s, remaining request budget).
///     .layer(TimeoutLayer::budget_aware(Duration::from_secs(2)));
/// # let _ = app;
/// ```
#[derive(Debug, Clone)]
pub struct TimeoutLayer {
    timeout: Duration,
    budget_aware: bool,
    time_getter: fn() -> Time,
}

impl TimeoutLayer {
    /// Create a timeout layer using the wall clock.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self::with_time_getter(timeout, wall_clock_now)
    }

    /// Create a timeout layer with a custom time source.
    #[must_use]
    pub fn with_time_getter(timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            timeout,
            budget_aware: false,
            time_getter,
        }
    }

    /// Create a budget-aware timeout layer (D1 deadline propagation): the
    /// effective timeout per request is `min(cap, remaining Cx budget)`.
    #[must_use]
    pub fn budget_aware(cap: Duration) -> Self {
        Self::budget_aware_with_time_getter(cap, wall_clock_now)
    }

    /// Budget-aware timeout layer with a custom time source.
    #[must_use]
    pub fn budget_aware_with_time_getter(cap: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            timeout: cap,
            budget_aware: true,
            time_getter,
        }
    }
}

impl<H: Handler> Layer<H> for TimeoutLayer {
    type Service = TimeoutMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        if self.budget_aware {
            TimeoutMiddleware::budget_aware_with_time_getter(inner, self.timeout, self.time_getter)
        } else {
            TimeoutMiddleware::with_time_getter(inner, self.timeout, self.time_getter)
        }
    }
}

/// Layer that applies [`CircuitBreakerMiddleware`] sharing ONE breaker across
/// every handler it wraps.
#[derive(Clone)]
pub struct CircuitBreakerLayer {
    breaker: Arc<CircuitBreaker>,
    time_getter: fn() -> Time,
}

impl CircuitBreakerLayer {
    /// Create a layer with a new breaker built from the policy.
    ///
    /// The breaker is created once here; all handlers wrapped by this layer
    /// value share it.
    #[must_use]
    pub fn new(policy: CircuitBreakerPolicy) -> Self {
        Self::with_time_getter(policy, wall_clock_now)
    }

    /// Create a layer with a new breaker and a custom time source.
    #[must_use]
    pub fn with_time_getter(policy: CircuitBreakerPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            breaker: Arc::new(CircuitBreaker::new(policy)),
            time_getter,
        }
    }

    /// Create a layer around an existing shared breaker.
    #[must_use]
    pub fn shared(breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            breaker,
            time_getter: wall_clock_now,
        }
    }

    /// Create a layer around an existing shared breaker with a custom time source.
    #[must_use]
    pub fn shared_with_time_getter(
        breaker: Arc<CircuitBreaker>,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            breaker,
            time_getter,
        }
    }

    /// Returns the shared circuit breaker for metrics inspection.
    #[must_use]
    pub fn breaker(&self) -> &Arc<CircuitBreaker> {
        &self.breaker
    }
}

impl<H: Handler> Layer<H> for CircuitBreakerLayer {
    type Service = CircuitBreakerMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        CircuitBreakerMiddleware::shared_with_time_getter(
            inner,
            Arc::clone(&self.breaker),
            self.time_getter,
        )
    }
}

/// Layer that applies [`RateLimitMiddleware`] sharing ONE limiter across every
/// handler it wraps.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter>,
    time_getter: fn() -> Time,
}

impl RateLimitLayer {
    /// Create a layer with a new limiter built from the policy.
    ///
    /// The limiter is created once here; all handlers wrapped by this layer
    /// value share it.
    #[must_use]
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self::with_time_getter(policy, wall_clock_now)
    }

    /// Create a layer with a new limiter and a custom time source.
    #[must_use]
    pub fn with_time_getter(policy: RateLimitPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(policy)),
            time_getter,
        }
    }

    /// Create a layer around an existing shared limiter.
    #[must_use]
    pub fn shared(limiter: Arc<RateLimiter>) -> Self {
        Self {
            limiter,
            time_getter: wall_clock_now,
        }
    }

    /// Create a layer around an existing shared limiter with a custom time source.
    #[must_use]
    pub fn shared_with_time_getter(limiter: Arc<RateLimiter>, time_getter: fn() -> Time) -> Self {
        Self {
            limiter,
            time_getter,
        }
    }

    /// Returns the shared rate limiter for metrics inspection.
    #[must_use]
    pub fn limiter(&self) -> &Arc<RateLimiter> {
        &self.limiter
    }
}

impl<H: Handler> Layer<H> for RateLimitLayer {
    type Service = RateLimitMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        RateLimitMiddleware::shared_with_time_getter(
            inner,
            Arc::clone(&self.limiter),
            self.time_getter,
        )
    }
}

/// Layer that applies [`BulkheadMiddleware`] sharing ONE bulkhead across every
/// handler it wraps.
#[derive(Clone)]
pub struct BulkheadLayer {
    bulkhead: Arc<Bulkhead>,
}

impl BulkheadLayer {
    /// Create a layer with a new bulkhead built from the policy.
    ///
    /// The bulkhead is created once here; all handlers wrapped by this layer
    /// value share its concurrency limit.
    #[must_use]
    pub fn new(policy: BulkheadPolicy) -> Self {
        Self {
            bulkhead: Arc::new(Bulkhead::new(policy)),
        }
    }

    /// Create a layer around an existing shared bulkhead.
    #[must_use]
    pub fn shared(bulkhead: Arc<Bulkhead>) -> Self {
        Self { bulkhead }
    }

    /// Returns the shared bulkhead for metrics inspection.
    #[must_use]
    pub fn bulkhead(&self) -> &Arc<Bulkhead> {
        &self.bulkhead
    }
}

impl<H: Handler> Layer<H> for BulkheadLayer {
    type Service = BulkheadMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        BulkheadMiddleware::shared(inner, Arc::clone(&self.bulkhead))
    }
}

/// Layer that applies [`RetryMiddleware`] with a fixed policy.
#[derive(Debug, Clone)]
pub struct RetryLayer {
    policy: RetryPolicy,
}

impl RetryLayer {
    /// Create a retry layer from the given policy.
    #[must_use]
    pub fn new(policy: RetryPolicy) -> Self {
        Self { policy }
    }
}

impl<H: Handler> Layer<H> for RetryLayer {
    type Service = RetryMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        RetryMiddleware::new(inner, self.policy.clone())
    }
}

/// Layer that applies [`CompressionMiddleware`] with a fixed config.
///
/// ```
/// use asupersync::web::middleware::{CompressionConfig, CompressionLayer};
/// use asupersync::web::{FnHandler, Router, get};
///
/// let app = Router::new()
///     .route("/big", get(FnHandler::new(|| "payload".repeat(100))))
///     .layer(CompressionLayer::new(CompressionConfig::default()));
/// # let _ = app;
/// ```
#[derive(Debug, Clone)]
pub struct CompressionLayer {
    config: CompressionConfig,
    compress_sensitive: bool,
    zstd: bool,
}

impl CompressionLayer {
    /// Create a compression layer from the given config.
    #[must_use]
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            compress_sensitive: false,
            zstd: false,
        }
    }

    /// See [`CompressionMiddleware::compress_sensitive_responses`].
    #[must_use]
    pub fn compress_sensitive_responses(mut self, enabled: bool) -> Self {
        self.compress_sensitive = enabled;
        self
    }

    /// See [`CompressionMiddleware::with_zstd`].
    #[cfg(feature = "zstd")]
    #[must_use]
    pub fn with_zstd(mut self) -> Self {
        self.zstd = true;
        self
    }
}

impl Default for CompressionLayer {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

impl<H: Handler> Layer<H> for CompressionLayer {
    type Service = CompressionMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        let mut middleware = CompressionMiddleware::new(inner, self.config.clone())
            .compress_sensitive_responses(self.compress_sensitive);
        middleware.zstd = self.zstd;
        middleware
    }
}

/// Layer that applies [`RequestBodyLimitMiddleware`] with a fixed byte cap.
#[derive(Debug, Clone, Copy)]
pub struct RequestBodyLimitLayer {
    max_bytes: usize,
}

impl RequestBodyLimitLayer {
    /// Create a body-limit layer with the given maximum body size in bytes.
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

impl<H: Handler> Layer<H> for RequestBodyLimitLayer {
    type Service = RequestBodyLimitMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        RequestBodyLimitMiddleware::new(inner, self.max_bytes)
    }
}

/// Layer that applies [`RequestIdMiddleware`] sharing ONE counter across every
/// handler it wraps, so generated IDs stay unique router-wide.
#[derive(Debug, Clone)]
pub struct RequestIdLayer {
    header_name: String,
    counter: Arc<AtomicU64>,
    max_id_length: usize,
}

impl RequestIdLayer {
    /// Create a request-ID layer for the given header name.
    ///
    /// The ID counter is created once here; all handlers wrapped by this layer
    /// value share it.
    #[must_use]
    pub fn new(header_name: impl Into<String>) -> Self {
        Self::shared(header_name, Arc::new(AtomicU64::new(1)))
    }

    /// Create a request-ID layer around an existing shared counter.
    #[must_use]
    pub fn shared(header_name: impl Into<String>, counter: Arc<AtomicU64>) -> Self {
        Self {
            header_name: header_name.into(),
            counter,
            max_id_length: DEFAULT_REQUEST_ID_MAX_LENGTH,
        }
    }

    /// Set the maximum accepted client-supplied request-ID length.
    ///
    /// Zero is coerced to the default, matching
    /// [`RequestIdMiddleware::with_max_length`].
    #[must_use]
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_id_length = max;
        self
    }
}

impl<H: Handler> Layer<H> for RequestIdLayer {
    type Service = RequestIdMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        RequestIdMiddleware::shared(inner, self.header_name.clone(), Arc::clone(&self.counter))
            .with_max_length(self.max_id_length)
    }
}

/// Layer that applies [`RequestTraceMiddleware`] with a fixed policy.
///
/// The router already traces dispatches by default (log-only); an explicit
/// layer is how you add duration / trace-id header stamping or scope tracing
/// to a subset of routes.
///
/// ```
/// use asupersync::web::middleware::{RequestTraceLayer, RequestTracePolicy};
/// use asupersync::web::{FnHandler, Router, get};
///
/// let app = Router::new()
///     .route("/", get(FnHandler::new(|| "ok")))
///     .layer(RequestTraceLayer::new(RequestTracePolicy::default()));
/// # let _ = app;
/// ```
#[derive(Clone)]
pub struct RequestTraceLayer {
    policy: RequestTracePolicy,
    time_getter: fn() -> Time,
    sink: Option<RequestLogSink>,
}

impl RequestTraceLayer {
    /// Create a request-trace layer using the wall clock.
    #[must_use]
    pub fn new(policy: RequestTracePolicy) -> Self {
        Self::with_time_getter(policy, wall_clock_now)
    }

    /// Create a request-trace layer with a custom time source.
    #[must_use]
    pub fn with_time_getter(policy: RequestTracePolicy, time_getter: fn() -> Time) -> Self {
        Self {
            policy,
            time_getter,
            sink: None,
        }
    }

    /// Attach a structured record sink observing every traced exchange.
    #[must_use]
    pub fn with_record_sink(mut self, sink: RequestLogSink) -> Self {
        self.sink = Some(sink);
        self
    }
}

impl<H: Handler> Layer<H> for RequestTraceLayer {
    type Service = RequestTraceMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        let middleware =
            RequestTraceMiddleware::with_time_getter(inner, self.policy.clone(), self.time_getter);
        match &self.sink {
            Some(sink) => middleware.with_record_sink(Arc::clone(sink)),
            None => middleware,
        }
    }
}

/// Layer that applies [`AuthMiddleware`] with a fixed policy.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    policy: AuthPolicy,
    time_getter: fn() -> Time,
}

impl AuthLayer {
    /// Create an auth layer using the wall clock.
    #[must_use]
    pub fn new(policy: AuthPolicy) -> Self {
        Self::with_time_getter(policy, wall_clock_now)
    }

    /// Create an auth layer with a custom time source.
    #[must_use]
    pub fn with_time_getter(policy: AuthPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            policy,
            time_getter,
        }
    }
}

impl<H: Handler> Layer<H> for AuthLayer {
    type Service = AuthMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        AuthMiddleware::with_time_getter(inner, self.policy.clone(), self.time_getter)
    }
}

/// Layer that applies [`LoadShedMiddleware`] sharing ONE in-flight counter
/// across every handler it wraps, so shedding is router-wide rather than
/// per-route.
#[derive(Debug, Clone)]
pub struct LoadShedLayer {
    policy: LoadShedPolicy,
    in_flight: Arc<AtomicUsize>,
}

impl LoadShedLayer {
    /// Create a load-shed layer from the given policy.
    ///
    /// The in-flight counter is created once here; all handlers wrapped by
    /// this layer value share it.
    #[must_use]
    pub fn new(policy: LoadShedPolicy) -> Self {
        Self {
            policy,
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<H: Handler> Layer<H> for LoadShedLayer {
    type Service = LoadShedMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        LoadShedMiddleware {
            inner,
            policy: self.policy,
            in_flight: Arc::clone(&self.in_flight),
        }
    }
}

/// Layer that applies [`CatchPanicMiddleware`].
///
/// A panicking handler yields `500` with the stable `[ASUP-E502]` token in
/// the body (panic details stay server-side). Keep this layer outermost so
/// panics in other middleware are contained too.
///
/// ```
/// use asupersync::web::middleware::CatchPanicLayer;
/// use asupersync::web::{FnHandler, Router, get};
///
/// let app = Router::new()
///     .route("/", get(FnHandler::new(|| "ok")))
///     .layer(CatchPanicLayer::new());
/// # let _ = app;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CatchPanicLayer;

impl CatchPanicLayer {
    /// Create a panic-recovery layer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<H: Handler> Layer<H> for CatchPanicLayer {
    type Service = CatchPanicMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        CatchPanicMiddleware::new(inner)
    }
}

/// Layer that applies [`NormalizePathMiddleware`] with a fixed strategy.
#[derive(Debug, Clone, Copy)]
pub struct NormalizePathLayer {
    strategy: TrailingSlash,
}

impl NormalizePathLayer {
    /// Create a path-normalization layer with the given strategy.
    #[must_use]
    pub fn new(strategy: TrailingSlash) -> Self {
        Self { strategy }
    }
}

impl<H: Handler> Layer<H> for NormalizePathLayer {
    type Service = NormalizePathMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        NormalizePathMiddleware::new(inner, self.strategy)
    }
}

/// Layer that applies [`SetResponseHeaderMiddleware`] with a fixed header.
#[derive(Debug, Clone)]
pub struct SetResponseHeaderLayer {
    name: String,
    value: String,
    mode: HeaderOverwrite,
}

impl SetResponseHeaderLayer {
    /// Create a response-header layer.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>, mode: HeaderOverwrite) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            mode,
        }
    }
}

impl<H: Handler> Layer<H> for SetResponseHeaderLayer {
    type Service = SetResponseHeaderMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        SetResponseHeaderMiddleware::new(inner, self.name.clone(), self.value.clone(), self.mode)
    }
}

/// Layer that applies [`W3CTraceContextMiddleware`].
#[derive(Debug, Clone, Copy, Default)]
pub struct W3CTraceContextLayer;

impl W3CTraceContextLayer {
    /// Create a W3C trace context layer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<H: Handler> Layer<H> for W3CTraceContextLayer {
    type Service = W3CTraceContextMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        W3CTraceContextMiddleware::new(inner)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "middleware_inline_tests.rs"]
mod tests;
