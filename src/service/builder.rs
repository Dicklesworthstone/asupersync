//! Builder for composing service layers.

use super::concurrency_limit::ConcurrencyLimitLayer;
use super::load_shed::LoadShedLayer;
use super::rate_limit::RateLimitLayer;
use super::retry::RetryLayer;
use super::timeout::TimeoutLayer;
use super::{Identity, Layer, Stack};
use std::sync::Arc;
use std::time::Duration;

/// Builder for stacking layers around a service.
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
mod tests {
    use super::*;
    use crate::service::{Identity, Service, Stack};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Trivial service for testing layer composition.
    #[derive(Debug, Clone)]
    struct Echo;

    impl Service<String> for Echo {
        type Response = String;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: String) -> Self::Future {
            Box::pin(async move { Ok(req) })
        }
    }

    #[test]
    fn test_new_creates_identity_builder() {
        let builder = ServiceBuilder::new();
        // layer_ref should return Identity
        let _: &Identity = builder.layer_ref();
    }

    #[test]
    fn test_default_same_as_new() {
        let _builder: ServiceBuilder<Identity> = ServiceBuilder::default();
    }

    #[test]
    fn test_service_with_identity_returns_inner() {
        let mut svc = ServiceBuilder::new().service(Echo);
        let fut = svc.call("hello".to_string());
        // Just verify it compiles and produces the right type
        drop(fut);
    }

    #[test]
    fn test_layer_adds_stack() {
        let builder = ServiceBuilder::new().layer(Identity);
        let _: &Stack<Identity, Identity> = builder.layer_ref();
    }

    #[test]
    fn test_timeout_convenience() {
        let builder = ServiceBuilder::new().timeout(Duration::from_secs(5));
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_load_shed_convenience() {
        let builder = ServiceBuilder::new().load_shed();
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_concurrency_limit_convenience() {
        let builder = ServiceBuilder::new().concurrency_limit(10);
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_concurrency_limit_with_semaphore() {
        let sem = Arc::new(crate::sync::Semaphore::new(5));
        let builder = ServiceBuilder::new().concurrency_limit_with_semaphore(sem);
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_rate_limit_convenience() {
        let builder = ServiceBuilder::new().rate_limit(100, Duration::from_secs(1));
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_retry_convenience() {
        use crate::service::retry::LimitedRetry;
        let builder = ServiceBuilder::new().retry(LimitedRetry::<String>::new(3));
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_chaining_multiple_layers() {
        let builder = ServiceBuilder::new()
            .timeout(Duration::from_secs(30))
            .concurrency_limit(50)
            .load_shed()
            .rate_limit(1000, Duration::from_secs(1));
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_builder_is_clone() {
        let builder = ServiceBuilder::new().timeout(Duration::from_secs(1));
        let clone = builder.clone();
        let _ = builder.layer_ref();
        let _ = clone.layer_ref();
    }

    #[test]
    fn test_builder_is_debug() {
        let builder = ServiceBuilder::new();
        let debug = format!("{builder:?}");
        assert!(debug.contains("ServiceBuilder"));
    }

    #[test]
    fn test_concurrency_limit_zero() {
        // Zero concurrency limit should still compile
        let builder = ServiceBuilder::new().concurrency_limit(0);
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_rate_limit_zero_rate() {
        let builder = ServiceBuilder::new().rate_limit(0, Duration::from_secs(1));
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_timeout_zero_duration() {
        let builder = ServiceBuilder::new().timeout(Duration::ZERO);
        let _ = builder.layer_ref();
    }

    #[test]
    fn test_retry_with_no_retry_policy() {
        use crate::service::retry::NoRetry;
        let builder = ServiceBuilder::new().retry(NoRetry);
        let _ = builder.layer_ref();
    }
}
