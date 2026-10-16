//! Builder for composing service layers.

use super::circuit_breaker::CircuitBreakerLayer;
use super::concurrency_limit::ConcurrencyLimitLayer;
use super::load_shed::LoadShedLayer;
use super::rate_limit::RateLimitLayer;
use super::retry::RetryLayer;
use super::timeout::TimeoutLayer;
use super::{Identity, Layer, Stack};
use crate::combinator::circuit_breaker::CircuitBreakerPolicy;
use std::sync::Arc;
use std::time::Duration;

/// Builder for stacking layers around a service.
///
/// # Layer order
///
/// The layer added **last** is the outermost: a request passes through it
/// first, and its `poll_ready` runs first. This is the reverse of
/// `tower::ServiceBuilder`, where the layer added first is the outermost.
/// Code ported from tower keeps compiling but changes meaning. For example,
/// to reject requests while a concurrency limit is saturated, load shedding
/// must wrap the limit, so it is added after it:
///
/// ```ignore
/// use asupersync::service::ServiceBuilder;
///
/// // Sheds: LoadShed(ConcurrencyLimit(svc)).
/// let svc = ServiceBuilder::new()
///     .concurrency_limit(10)
///     .load_shed()
///     .service(my_service);
/// ```
///
/// The tower spelling, `.load_shed().concurrency_limit(10)`, builds
/// `ConcurrencyLimit(LoadShed(svc))` here. A saturated limit then makes
/// requests wait for a permit instead of shedding them, because the load
/// shedder only sees the readiness of `svc`.
#[derive(Debug, Clone)]
pub struct ServiceBuilder<L> {
    layer: L,
}

impl ServiceBuilder<Identity> {
    /// Creates a new builder with the identity layer.
    #[must_use]
    pub fn new() -> Self {
        Self { layer: Identity }
    }
}

impl Default for ServiceBuilder<Identity> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L> ServiceBuilder<L> {
    /// Adds a new layer to the builder.
    #[must_use]
    pub fn layer<T>(self, layer: T) -> ServiceBuilder<Stack<L, T>> {
        ServiceBuilder {
            layer: Stack::new(self.layer, layer),
        }
    }

    /// Wraps the given service with the configured layers.
    #[must_use]
    pub fn service<S>(self, service: S) -> L::Service
    where
        L: Layer<S>,
    {
        self.layer.layer(service)
    }

    /// Returns a reference to the composed layer stack.
    #[must_use]
    pub fn layer_ref(&self) -> &L {
        &self.layer
    }

    // =========================================================================
    // Middleware convenience methods
    // =========================================================================

    /// Adds a timeout layer with the given duration.
    ///
    /// Requests that take longer than `timeout` will fail with a timeout error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::service::ServiceBuilder;
    /// use std::time::Duration;
    ///
    /// let svc = ServiceBuilder::new()
    ///     .timeout(Duration::from_secs(30))
    ///     .service(my_service);
    /// ```
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> ServiceBuilder<Stack<L, TimeoutLayer>> {
        self.layer(TimeoutLayer::new(timeout))
    }

    /// Adds a load shedding layer.
    ///
    /// When the inner service is not ready (backpressure), requests are
    /// immediately rejected instead of being queued.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::service::ServiceBuilder;
    ///
    /// let svc = ServiceBuilder::new()
    ///     .load_shed()
    ///     .service(my_service);
    /// ```
    #[must_use]
    pub fn load_shed(self) -> ServiceBuilder<Stack<L, LoadShedLayer>> {
        self.layer(LoadShedLayer::new())
    }

    /// Adds a concurrency limit layer.
    ///
    /// Limits the number of concurrent in-flight requests.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::service::ServiceBuilder;
    ///
    /// let svc = ServiceBuilder::new()
    ///     .concurrency_limit(10)  // Max 10 concurrent requests
    ///     .service(my_service);
    /// ```
    #[must_use]
    pub fn concurrency_limit(self, max: usize) -> ServiceBuilder<Stack<L, ConcurrencyLimitLayer>> {
        self.layer(ConcurrencyLimitLayer::new(max))
    }

    /// Adds a concurrency limit layer with a shared semaphore.
    ///
    /// This is useful when you want multiple services to share the same
    /// concurrency limit.
    #[must_use]
    pub fn concurrency_limit_with_semaphore(
        self,
        semaphore: Arc<crate::sync::Semaphore>,
    ) -> ServiceBuilder<Stack<L, ConcurrencyLimitLayer>> {
        self.layer(ConcurrencyLimitLayer::with_semaphore(semaphore))
    }

    /// Adds a circuit-breaker layer.
    ///
    /// Requests are admitted while the breaker is closed. A burst of failures
    /// opens the breaker, subsequent calls are rejected until the open duration
    /// elapses, and then half-open probes decide whether to close or reopen it.
    #[must_use]
    pub fn circuit_breaker(
        self,
        policy: CircuitBreakerPolicy,
    ) -> ServiceBuilder<Stack<L, CircuitBreakerLayer>> {
        self.layer(CircuitBreakerLayer::new(policy))
    }

    /// Adds a rate limiting layer.
    ///
    /// Limits requests to `rate` per `period` using a token bucket algorithm.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::service::ServiceBuilder;
    /// use std::time::Duration;
    ///
    /// let svc = ServiceBuilder::new()
    ///     .rate_limit(100, Duration::from_secs(1))  // 100 req/sec
    ///     .service(my_service);
    /// ```
    #[must_use]
    pub fn rate_limit(
        self,
        rate: u64,
        period: Duration,
    ) -> ServiceBuilder<Stack<L, RateLimitLayer>> {
        self.layer(RateLimitLayer::new(rate, period))
    }

    /// Adds a retry layer with the given policy.
    ///
    /// Failed requests will be retried according to the policy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::service::{ServiceBuilder, LimitedRetry};
    ///
    /// let svc = ServiceBuilder::new()
    ///     .retry(LimitedRetry::new(3))  // Retry up to 3 times
    ///     .service(my_service);
    /// ```
    #[must_use]
    pub fn retry<P>(self, policy: P) -> ServiceBuilder<Stack<L, RetryLayer<P>>>
    where
        P: Clone,
    {
        self.layer(RetryLayer::new(policy))
    }
}

#[cfg(test)]
#[path = "builder_inline_tests.rs"]
mod tests;
