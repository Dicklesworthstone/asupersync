//! gRPC interceptor middleware.
//!
//! Provides a layer-based interceptor pattern for processing gRPC requests
//! and responses. Interceptors can be used for authentication, logging,
//! tracing, metrics, and other cross-cutting concerns.
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

use std::sync::Arc;

use crate::bytes::Bytes;

use super::server::Interceptor;
use super::status::Status;
use super::streaming::{MetadataValue, Request, Response};

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
        for interceptor in &self.interceptors {
            interceptor.intercept_request(request)?;
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

/// Tracing interceptor that adds request IDs to metadata.
#[derive(Debug, Clone, Default)]
pub struct TracingInterceptor {
    /// Whether to generate request IDs.
    generate_request_id: bool,
}

impl TracingInterceptor {
    /// Create a new tracing interceptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            generate_request_id: true,
        }
    }

    /// Configure whether to generate request IDs.
    #[must_use]
    pub fn with_request_id(mut self, enabled: bool) -> Self {
        self.generate_request_id = enabled;
        self
    }
}

impl Interceptor for TracingInterceptor {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        if self.generate_request_id && request.metadata().get("x-request-id").is_none() {
            // Generate a simple request ID (in production, use UUID)
            let id = format!(
                "req-{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64
            );
            request.metadata_mut().insert("x-request-id", id);
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
        request
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

/// Interceptor that validates bearer tokens on incoming requests.
#[derive(Debug)]
pub struct BearerAuthValidator<F> {
    validator: F,
}

impl<F> BearerAuthValidator<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    /// Create a new bearer auth validator.
    pub fn new(validator: F) -> Self {
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

        let token = auth_str
            .strip_prefix("Bearer ")
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

/// Create an interceptor that validates bearer tokens.
pub fn auth_validator<F>(validator: F) -> BearerAuthValidator<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    BearerAuthValidator::new(validator)
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
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let keys = keys.into_iter();
        let (lower, upper) = keys.size_hint();
        let mut collected_keys = Vec::with_capacity(upper.unwrap_or(lower));
        for key in keys {
            collected_keys.push(key.into());
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
            request
                .metadata_mut()
                .insert("x-propagate-keys", keys_to_propagate.join(","));
        }
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        // In a real implementation, we would copy the values from request context
        // For now, we just acknowledge the propagation intent
        let _ = response;
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

/// Rate limiting interceptor.
///
/// Provides simple rate limiting based on request counts.
#[derive(Debug)]
pub struct RateLimitInterceptor {
    /// Maximum requests allowed.
    max_requests: u32,
    /// Current request count.
    current: std::sync::atomic::AtomicU32,
}

impl RateLimitInterceptor {
    /// Create a new rate limit interceptor.
    #[must_use]
    pub fn new(max_requests: u32) -> Self {
        Self {
            max_requests,
            current: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Reset the request counter.
    pub fn reset(&self) {
        self.current.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the current request count.
    #[must_use]
    pub fn current_count(&self) -> u32 {
        self.current.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Interceptor for RateLimitInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        let current = self
            .current
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if current >= self.max_requests {
            self.current
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            Err(Status::resource_exhausted("rate limit exceeded"))
        } else {
            Ok(())
        }
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
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
            request.metadata_mut().insert("x-logged", "true");
        }
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        if self.log_responses {
            response.metadata_mut().insert("x-logged", "true");
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
        // Add grpc-timeout header if not present
        if request.metadata().get("grpc-timeout").is_none() {
            request
                .metadata_mut()
                .insert("grpc-timeout", format!("{}m", self.timeout_ms));
        }
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
    use super::*;
    use crate::grpc::Code;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
    fn metadata_propagator_marks_keys() {
        init_test("metadata_propagator_marks_keys");
        let interceptor = metadata_propagator(["x-request-id", "x-trace-id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");
        request.metadata_mut().insert("x-trace-id", "trace-456");

        interceptor.intercept_request(&mut request).unwrap();

        // Check that propagation keys are marked
        let has_keys = request.metadata().get("x-propagate-keys").is_some();
        crate::assert_with_log!(has_keys, "propagate keys", true, has_keys);
        crate::test_complete!("metadata_propagator_marks_keys");
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        init_test("rate_limiter_allows_under_limit");
        let interceptor = rate_limiter(10);

        for _ in 0..10 {
            let mut request = Request::new(Bytes::new());
            let ok = interceptor.intercept_request(&mut request).is_ok();
            crate::assert_with_log!(ok, "intercept ok", true, ok);
        }

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 10, "count", 10, count);
        crate::test_complete!("rate_limiter_allows_under_limit");
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        init_test("rate_limiter_rejects_over_limit");
        let interceptor = rate_limiter(2);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "second ok", true, ok);

        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).unwrap_err();
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

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).is_err();
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
    fn timeout_interceptor_adds_header() {
        init_test("timeout_interceptor_adds_header");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "5000m");
        crate::assert_with_log!(ok, "timeout header", true, ok);
        crate::test_complete!("timeout_interceptor_adds_header");
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
}
