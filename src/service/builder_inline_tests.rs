    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
    fn test_circuit_breaker_convenience() {
        let builder = ServiceBuilder::new().circuit_breaker(CircuitBreakerPolicy::default());
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
        fn assert_clone<T: Clone>(_value: &T) {}

        let builder = ServiceBuilder::new().timeout(Duration::from_secs(1));
        assert_clone(&builder);
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
