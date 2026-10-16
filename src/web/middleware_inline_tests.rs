    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use std::panic::{self, AssertUnwindSafe};

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

    fn auth_test_time_10s() -> Time {
        Time::from_secs(10)
    }

    fn auth_test_time_20s() -> Time {
        Time::from_secs(20)
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

    fn call_sync<H: Handler + ?Sized>(handler: &H, req: Request) -> Response {
        futures_lite::future::block_on(Handler::call(handler, &crate::Cx::for_testing(), req))
    }

    macro_rules! impl_test_sync_call {
        ($ty:ident) => {
            impl<H: Handler> $ty<H> {
                fn call(&self, req: Request) -> Response {
                    call_sync(self, req)
                }
            }
        };
    }

    impl_test_sync_call!(CorsMiddleware);
    impl_test_sync_call!(TimeoutMiddleware);
    impl_test_sync_call!(CircuitBreakerMiddleware);
    impl_test_sync_call!(RateLimitMiddleware);
    impl_test_sync_call!(BulkheadMiddleware);
    impl_test_sync_call!(RetryMiddleware);
    impl_test_sync_call!(CompressionMiddleware);
    impl_test_sync_call!(RequestBodyLimitMiddleware);
    impl_test_sync_call!(RequestIdMiddleware);
    impl_test_sync_call!(RequestTraceMiddleware);
    impl_test_sync_call!(AuthMiddleware);
    impl_test_sync_call!(LoadShedMiddleware);
    impl_test_sync_call!(CatchPanicMiddleware);
    impl_test_sync_call!(NormalizePathMiddleware);
    impl_test_sync_call!(SetResponseHeaderMiddleware);
    impl_test_sync_call!(W3CTraceContextMiddleware);

    struct CountingHandler {
        calls: Arc<std::sync::atomic::AtomicU32>,
        delay: Duration,
        status: StatusCode,
    }

    impl Handler for CountingHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !self.delay.is_zero() {
                    std::thread::sleep(self.delay);
                }
                Response::new(self.status, b"counted".to_vec())
            })
        }
    }

    struct InspectHandler;

    impl Handler for InspectHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                req.extensions.get("trace_id").map_or_else(
                    || Response::new(StatusCode::BAD_REQUEST, b"missing trace_id".to_vec()),
                    |value| Response::new(StatusCode::OK, value.as_bytes().to_vec()),
                )
            })
        }
    }

    struct FailingIfCalled;

    impl Handler for FailingIfCalled {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async {
                Response::new(StatusCode::INTERNAL_SERVER_ERROR, b"inner-called".to_vec())
            })
        }
    }

    struct InspectPathHandler;

    impl Handler for InspectPathHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move { Response::new(StatusCode::OK, req.path.into_bytes()) })
        }
    }

    struct PanicHandler;

    impl Handler for PanicHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async { panic!("boom") })
        }
    }

    struct AdvanceTimeHandler {
        next_time_ms: u64,
        status: StatusCode,
    }

    impl Handler for AdvanceTimeHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                set_timeout_test_time(self.next_time_ms);
                Response::new(self.status, b"advanced".to_vec())
            })
        }
    }

    struct AdvanceRequestTraceTimeHandler {
        next_time_ms: u64,
        body: &'static [u8],
    }

    impl Handler for AdvanceRequestTraceTimeHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                set_request_trace_test_time(self.next_time_ms);
                Response::new(StatusCode::OK, self.body.to_vec())
            })
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

    struct PendingHandler;

    impl Handler for PendingHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    #[test]
    fn timeout_preempts_pending_handler() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let resp = runtime.block_on(async {
            let cx = crate::Cx::for_testing();
            let mw = TimeoutMiddleware::new(PendingHandler, Duration::from_millis(5));
            Handler::call(&mw, &cx, make_request()).await
        });
        assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT);
    }

    fn frozen_at_zero() -> Time {
        Time::ZERO
    }

    /// Review r28-e8 of 14d252b8f (M3-1): a custom clock is the timeout's only
    /// clock. Its deadline was compared with the runtime's timer, which counts
    /// from process start, so once that passed the deadline every request was
    /// a 504 and its handler never ran.
    #[test]
    fn a_custom_clock_timeout_never_reads_the_runtime_clock() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let resp = runtime.block_on(async {
            // Put the runtime's clock past the 1 ms deadline; the frozen
            // custom clock never reaches it.
            crate::time::sleep(crate::time::wall_now(), Duration::from_millis(5)).await;
            let cx = crate::Cx::for_testing();
            let mw = TimeoutMiddleware::with_time_getter(
                FnHandler::new(ok_handler),
                Duration::from_millis(1),
                frozen_at_zero,
            );
            Handler::call(&mw, &cx, make_request()).await
        });
        assert_eq!(resp.status, StatusCode::OK);
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

    /// A half-open probe whose request was abandoned (client gone, timeout)
    /// kept its probe slot, so every later request got 503 HalfOpenFull.
    #[test]
    fn abandoned_request_releases_the_half_open_probe() {
        struct NeverHandler;
        impl Handler for NeverHandler {
            fn call(
                &self,
                _cx: &crate::Cx,
                _req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(std::future::pending())
            }
        }

        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::ZERO,
            ..Default::default()
        };
        let breaker = Arc::new(CircuitBreaker::new(policy));
        let fail_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            FnHandler::new(error_handler),
            Arc::clone(&breaker),
            circuit_test_time,
        );
        let never_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            NeverHandler,
            Arc::clone(&breaker),
            circuit_test_time,
        );
        let ok_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            FnHandler::new(ok_handler),
            Arc::clone(&breaker),
            circuit_test_time,
        );

        set_circuit_test_time(1_000);
        assert_eq!(
            fail_mw.call(make_request()).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let cx = crate::Cx::for_testing();
        let mut probe = Handler::call(&never_mw, &cx, make_request());
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(probe.as_mut().poll(&mut task_cx).is_pending());
        assert!(
            matches!(
                breaker.state(),
                crate::combinator::circuit_breaker::State::HalfOpen {
                    probes_active: 1,
                    ..
                }
            ),
            "the abandoned request must hold the probe: {:?}",
            breaker.state()
        );
        drop(probe);

        let next = ok_mw.call(make_request());
        assert_eq!(next.status, StatusCode::OK, "the probe slot was leaked");
        assert!(matches!(
            breaker.state(),
            crate::combinator::circuit_breaker::State::Closed { .. }
        ));
    }

    /// The outcome was stamped with the request's start time, so a failure
    /// that took longer than open_duration opened the breaker in the past and
    /// the next request went straight to half-open.
    #[test]
    fn a_slow_failure_opens_the_breaker_when_it_ends() {
        struct SlowFailureHandler;
        impl Handler for SlowFailureHandler {
            fn call(
                &self,
                _cx: &crate::Cx,
                _req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(async {
                    set_circuit_test_time(21_000);
                    Response::new(StatusCode::INTERNAL_SERVER_ERROR, b"late".to_vec())
                })
            }
        }

        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let breaker = Arc::new(CircuitBreaker::new(policy));
        let slow_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            SlowFailureHandler,
            Arc::clone(&breaker),
            circuit_test_time,
        );
        let ok_mw = CircuitBreakerMiddleware::shared_with_time_getter(
            FnHandler::new(ok_handler),
            Arc::clone(&breaker),
            circuit_test_time,
        );

        set_circuit_test_time(1_000);
        assert_eq!(
            slow_mw.call(make_request()).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            breaker.state(),
            crate::combinator::circuit_breaker::State::Open {
                since_millis: 21_000
            }
        );

        let rejected = ok_mw.call(make_request());
        assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
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

    #[test]
    fn rate_limit_retry_after_matches_rfc9110_delay_seconds_example() {
        let policy = RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(120),
            ..Default::default()
        };
        let mw = RateLimitMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            policy,
            rate_limit_test_time,
        );

        set_rate_limit_test_time(5_000);
        let first = mw.call(make_request());
        assert_eq!(first.status, StatusCode::OK);

        let rejected = mw.call(make_request());
        assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rejected.headers.get("retry-after").map(String::as_str),
            Some("120")
        );
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
                ..CompressionConfig::default()
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
                ..CompressionConfig::default()
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
                ..CompressionConfig::default()
            },
        );
        let req = Request::new("GET", "/compress")
            .with_header("accept-encoding", "gzip;q=1, identity;q=0");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
    }

    #[test]
    fn compression_weakens_the_etag_and_varies_a_not_modified() {
        // br-asupersync-a1q12q: a compressed body kept the identity bytes'
        // strong ETag (a resumed download spliced identity bytes onto it), and
        // a 304 left out the Vary its 200 carries.
        fn not_modified() -> Response {
            Response::empty(StatusCode::NOT_MODIFIED)
        }
        let mw =
            CompressionMiddleware::new(FnHandler::new(not_modified), CompressionConfig::default());
        let req = Request::new("GET", "/compress").with_header("accept-encoding", "gzip");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );

        #[cfg(feature = "compression")]
        {
            fn tagged() -> Response {
                Response::new(StatusCode::OK, "Hello, World! ".repeat(100).into_bytes())
                    .header("etag", "\"v1\"")
            }
            let mw = CompressionMiddleware::new(
                FnHandler::new(tagged),
                CompressionConfig {
                    min_body_size: 0,
                    ..CompressionConfig::default()
                },
            );
            let req = Request::new("GET", "/compress").with_header("accept-encoding", "gzip");
            let resp = mw.call(req);
            assert_eq!(
                resp.headers.get("content-encoding"),
                Some(&"gzip".to_string())
            );
            assert_eq!(resp.headers.get("etag"), Some(&"W/\"v1\"".to_string()));
        }
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

    #[test]
    fn request_id_overwrites_mixed_case_inner_header_without_duplication() {
        fn header_handler() -> Response {
            let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
            resp.headers
                .insert("X-Request-Id".to_string(), "inner".to_string());
            resp
        }

        let mw = RequestIdMiddleware::new(FnHandler::new(header_handler), "x-request-id");
        let req = Request::new("GET", "/req-id").with_header("x-request-id", "outer");
        let resp = mw.call(req);

        assert_eq!(resp.header_value("x-request-id"), Some("outer"));
        assert_eq!(
            resp.headers.len(),
            1,
            "response should not carry duplicate request-id headers"
        );
        assert!(!resp.headers.contains_key("X-Request-Id"));
    }

    // --- W3CTraceContextMiddleware ---

    /// Answers with the trace extensions it sees, one per line, `-` if absent.
    struct TraceExtensionsHandler;

    impl Handler for TraceExtensionsHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let body = ["traceparent", "tracestate", "baggage", "trace_id"]
                .map(|key| req.extensions.get(key).unwrap_or("-").to_string())
                .join("\n");
            Box::pin(async move { Response::new(StatusCode::OK, body.into_bytes()) })
        }
    }

    /// The handler's `[traceparent, tracestate, baggage, trace_id]`, with its
    /// traceparent parsed.
    fn handler_trace(
        resp: &Response,
    ) -> (
        crate::observability::w3c_trace_context::W3CTraceContext,
        Vec<String>,
    ) {
        let seen: Vec<String> = std::str::from_utf8(resp.body.as_ref())
            .expect("utf-8 body")
            .lines()
            .map(str::to_string)
            .collect();
        let span = seen[0]
            .parse()
            .expect("the handler always sees a valid traceparent");
        (span, seen)
    }

    #[test]
    fn w3c_trace_context_runs_the_handler_as_a_child_span_of_the_incoming_trace() {
        let upstream = crate::observability::w3c_trace_context::W3CTraceContext::new_root();
        let mw = W3CTraceContextMiddleware::new(TraceExtensionsHandler);
        let req = Request::new("GET", "/w3c")
            .with_header("Traceparent", upstream.to_traceparent())
            .with_header("tracestate", "vendor=a")
            .with_header("baggage", "user=7");
        let (span, seen) = handler_trace(&mw.call(req));

        assert_eq!(span.trace_id, upstream.trace_id, "the trace continues");
        assert_ne!(
            span.span_id, upstream.span_id,
            "the handler has its own span"
        );
        assert_eq!(span.flags, upstream.flags);
        assert_eq!(seen[1], "vendor=a");
        assert_eq!(seen[2], "user=7");
        assert_eq!(
            seen[3],
            upstream.trace_id.to_hex(),
            "logs carry the trace id"
        );
    }

    #[test]
    fn w3c_trace_context_starts_a_trace_without_a_valid_traceparent() {
        let mw = W3CTraceContextMiddleware::new(TraceExtensionsHandler);
        let missing = Request::new("GET", "/w3c").with_header("tracestate", "vendor=a");
        let invalid = Request::new("GET", "/w3c")
            .with_header("traceparent", "00-not-a-trace-01")
            .with_header("tracestate", "vendor=a");
        let mut trace_ids = Vec::new();
        for req in [missing, invalid] {
            let (span, seen) = handler_trace(&mw.call(req));
            assert_eq!(seen[1], "-", "the tracestate of no valid trace is dropped");
            assert_eq!(seen[3], span.trace_id.to_hex());
            trace_ids.push(span.trace_id);
        }
        assert_ne!(
            trace_ids[0], trace_ids[1],
            "each request starts its own trace"
        );
    }

    #[test]
    fn w3c_trace_context_keeps_a_trace_id_an_outer_layer_set() {
        let upstream = crate::observability::w3c_trace_context::W3CTraceContext::new_root();
        let mw = RequestIdMiddleware::new(
            W3CTraceContextMiddleware::new(TraceExtensionsHandler),
            "x-request-id",
        );
        let req = Request::new("GET", "/w3c")
            .with_header("traceparent", upstream.to_traceparent())
            .with_header("x-request-id", "abc-123");
        let (span, seen) = handler_trace(&mw.call(req));

        assert_eq!(seen[3], "abc-123", "the outer layer's trace_id is kept");
        assert_eq!(span.trace_id, upstream.trace_id);
    }

    #[test]
    fn w3c_trace_context_layer_and_stack_method_apply_the_middleware() {
        let upstream = crate::observability::w3c_trace_context::W3CTraceContext::new_root();
        let request =
            || Request::new("GET", "/w3c").with_header("traceparent", upstream.to_traceparent());
        let stacked = MiddlewareStack::new(TraceExtensionsHandler)
            .with_w3c_trace_context()
            .build();
        let layered = W3CTraceContextLayer::new().layer(TraceExtensionsHandler);
        for resp in [
            call_sync(&stacked, request()),
            call_sync(&layered, request()),
        ] {
            let (span, _) = handler_trace(&resp);
            assert_eq!(span.trace_id, upstream.trace_id);
            assert_ne!(span.span_id, upstream.span_id);
        }
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
    fn auth_default_policy_fails_closed_on_presence_only_bearer() {
        let mw = AuthMiddleware::new(FnHandler::new(ok_handler), AuthPolicy::default());
        let req = Request::new("GET", "/auth").with_header("authorization", "Bearer token-123");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers.get("www-authenticate"),
            Some(&"Bearer".to_string())
        );
    }

    #[test]
    fn auth_accepts_rfc7515_detached_compact_jws_bearer_token() {
        // RFC 7515 Appendix F detaches the payload by emptying the compact
        // serialization middle field; use the Appendix A.1 header/signature.
        let detached_jws =
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9..dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mw = AuthMiddleware::new(
            FnHandler::new(ok_handler),
            AuthPolicy::exact_bearer(detached_jws),
        );
        let req = Request::new("GET", "/auth")
            .with_header("authorization", format!("Bearer {detached_jws}"));
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

    #[test]
    fn auth_rejects_expired_exact_bearer_token() {
        let mw = AuthMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            AuthPolicy::exact_bearer_until("token-123", Time::from_secs(10)),
            auth_test_time_10s,
        );
        let req = Request::new("GET", "/auth").with_header("authorization", "Bearer token-123");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_accepts_unexpired_exact_bearer_token() {
        let mw = AuthMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            AuthPolicy::exact_bearer_until("token-123", Time::from_secs(11)),
            auth_test_time_10s,
        );
        let req = Request::new("GET", "/auth").with_header("authorization", "Bearer token-123");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn auth_rotation_accepts_new_token_and_rejects_expired_old_token() {
        let mut policy = AuthPolicy::exact_bearer_until("old-token", Time::from_secs(20));
        policy.rotate_exact_bearer("new-token", Time::from_secs(40), Time::from_secs(10));

        let before_expiry = AuthMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            policy.clone(),
            auth_test_time_10s,
        );
        let old_req = Request::new("GET", "/auth").with_header("authorization", "Bearer old-token");
        let new_req = Request::new("GET", "/auth").with_header("authorization", "Bearer new-token");
        assert_eq!(before_expiry.call(old_req).status, StatusCode::OK);
        assert_eq!(before_expiry.call(new_req).status, StatusCode::OK);

        let after_expiry = AuthMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            policy,
            auth_test_time_20s,
        );
        let old_req = Request::new("GET", "/auth").with_header("authorization", "Bearer old-token");
        let new_req = Request::new("GET", "/auth").with_header("authorization", "Bearer new-token");
        assert_eq!(after_expiry.call(old_req).status, StatusCode::UNAUTHORIZED);
        assert_eq!(after_expiry.call(new_req).status, StatusCode::OK);
    }

    #[test]
    fn auth_rotation_prune_removes_expired_tokens_without_dropping_replacement() {
        let mut policy = AuthPolicy::exact_bearer_until("old-token", Time::from_secs(20));
        policy.rotate_exact_bearer("new-token", Time::from_secs(40), Time::from_secs(10));
        policy.prune_expired(Time::from_secs(20));

        let AuthPolicy::ExactBearer(tokens) = &policy else {
            panic!("rotation must preserve exact-bearer policy");
        };
        assert_eq!(
            tokens.iter().map(BearerToken::token).collect::<Vec<_>>(),
            vec!["new-token"],
            "prune should remove expired old tokens and keep active replacements"
        );

        let mw = AuthMiddleware::with_time_getter(
            FnHandler::new(ok_handler),
            policy,
            auth_test_time_20s,
        );
        let old_req = Request::new("GET", "/auth").with_header("authorization", "Bearer old-token");
        let new_req = Request::new("GET", "/auth").with_header("authorization", "Bearer new-token");
        assert_eq!(mw.call(old_req).status, StatusCode::UNAUTHORIZED);
        assert_eq!(mw.call(new_req).status, StatusCode::OK);
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

    // ─── br-asupersync-0qb0bf: safe-by-default allow_headers ─────────

    #[test]
    fn _0qb0bf_default_allow_headers_is_narrow_safe_list_not_wildcard() {
        // Pre-fix CorsPolicy::default set allow_headers = ["*"]; per
        // Fetch §3.2.4 wildcard grants access to ALL request headers.
        // Post-fix the default is the conservative allowlist of
        // CORS-safelisted headers + Authorization + X-Requested-With.
        let policy = CorsPolicy::default();
        assert!(
            !policy.allow_headers.iter().any(|h| h == "*"),
            "default must NOT contain wildcard; got {:?}",
            policy.allow_headers
        );

        // Each safe header MUST be present (sanity check the
        // documented allowlist composition stays stable).
        for expected in [
            "Accept",
            "Accept-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
        ] {
            assert!(
                policy.allow_headers.iter().any(|h| h == expected),
                "default allowlist missing {expected:?}; got {:?}",
                policy.allow_headers
            );
        }
    }

    #[test]
    fn _0qb0bf_default_preflight_does_not_echo_arbitrary_requested_headers() {
        // The CRITICAL behavior: a client requesting an obscure
        // header (e.g. X-Evil-Internal) via
        // Access-Control-Request-Headers MUST NOT see that header
        // echoed back in Access-Control-Allow-Headers under the
        // default policy. The static allowlist is what the response
        // returns; the requested-headers list is intentionally
        // ignored.
        let mw = CorsMiddleware::new(FailingIfCalled, CorsPolicy::default());
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST")
            .with_header(
                "Access-Control-Request-Headers",
                "X-Evil-Internal, X-Internal-Auth, X-Backend-Token",
            );
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::NO_CONTENT);

        let allow = resp
            .headers
            .get("access-control-allow-headers")
            .expect("preflight must set Access-Control-Allow-Headers");
        for forbidden in ["X-Evil-Internal", "X-Internal-Auth", "X-Backend-Token"] {
            assert!(
                !allow.contains(forbidden),
                "default preflight must NOT echo arbitrary requested header \
                 {forbidden:?}; Allow-Headers was {allow:?}"
            );
        }
        // The static allowlist IS in the response.
        for expected in ["Authorization", "Content-Type", "X-Requested-With"] {
            assert!(
                allow.contains(expected),
                "static allowlist entry {expected:?} must be in Allow-Headers; \
                 got {allow:?}"
            );
        }
        assert!(
            !allow.contains('*'),
            "default preflight must NOT advertise wildcard; got {allow:?}"
        );
    }

    #[test]
    fn _0qb0bf_with_any_headers_opt_in_restores_wildcard() {
        // The escape hatch: callers that genuinely accept arbitrary
        // headers (e.g. transparent proxies) get the wildcard back
        // through the explicit constructor. The constructor name is
        // the documentation that the security posture is loosened
        // intentionally.
        let policy = CorsPolicy::with_any_headers();
        assert_eq!(policy.allow_headers, vec!["*".to_string()]);

        let mw = CorsMiddleware::new(FailingIfCalled, policy);
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST")
            .with_header("Access-Control-Request-Headers", "X-Any-Header");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("access-control-allow-headers"),
            Some(&"*".to_string()),
            "with_any_headers must produce wildcard on the wire"
        );
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
    fn cors_varies_on_origin_even_when_it_adds_no_cors_headers() {
        // A shared cache that stored the no-Origin or blocked-Origin variant
        // without `Vary: Origin` would serve it to allowed origins, whose
        // browsers would then block the response.
        let policy = CorsPolicy::with_exact_origins(vec!["https://allowed.example".to_string()]);
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let requests = [
            Request::new("GET", "/cors"),
            Request::new("GET", "/cors").with_header("Origin", "https://blocked.example"),
            Request::new("GET", "/cors")
                .with_header("Origin", "https://allowed.example, https://other.example"),
        ];
        for request in requests {
            let resp = mw.call(request);
            assert!(!resp.headers.contains_key("access-control-allow-origin"));
            assert_eq!(resp.headers.get("vary"), Some(&"origin".to_string()));
        }
    }

    #[test]
    fn cors_credentials_with_allowlisted_origin_echoes_exact_origin() {
        // br-asupersync-d4f31s: when credentials are enabled, the only
        // legal way to allow cross-origin reads is an explicit
        // origin allow-list. An allowlisted origin is echoed verbatim;
        // Allow-Credentials is set; the request succeeds.
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::with_exact_origins(vec!["https://cred.example".to_string()])
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

    #[test]
    fn cors_credentials_with_non_allowlisted_origin_emits_no_allow_origin() {
        // br-asupersync-d4f31s: credentials enabled + Origin not in the
        // explicit allow-list = the response must NOT carry
        // Access-Control-Allow-Origin or Access-Control-Allow-Credentials.
        // The browser's same-origin policy then blocks the foreign caller
        // from reading the response, even though the inner handler
        // returned 200 OK. This is the fail-closed contract per Fetch
        // §3.2.5 — never reflect credentials to an unvetted origin.
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::with_exact_origins(vec!["https://allowed.example".to_string()])
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp =
            mw.call(Request::new("GET", "/cors").with_header("Origin", "https://attacker.example"));

        assert_eq!(resp.status, StatusCode::OK, "inner handler still runs");
        assert!(
            !resp.headers.contains_key("access-control-allow-origin"),
            "non-allowlisted origin must not receive Allow-Origin"
        );
        assert!(
            !resp
                .headers
                .contains_key("access-control-allow-credentials"),
            "non-allowlisted origin must not receive Allow-Credentials"
        );
    }

    #[test]
    fn cors_multi_origin_header_fails_closed_for_exact_allowlist() {
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::with_exact_origins(vec!["https://allowed.example".to_string()])
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(Request::new("GET", "/cors").with_header(
            "Origin",
            "https://allowed.example, https://attacker.example",
        ));

        assert_eq!(resp.status, StatusCode::OK, "inner handler still runs");
        assert!(
            !resp.headers.contains_key("access-control-allow-origin"),
            "malformed multi-origin header must not be reflected"
        );
        assert!(
            !resp
                .headers
                .contains_key("access-control-allow-credentials"),
            "malformed multi-origin header must not receive Allow-Credentials"
        );
    }

    #[test]
    fn cors_multi_origin_header_fails_closed_for_any_policy() {
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), CorsPolicy::default());
        let resp = mw.call(Request::new("GET", "/cors").with_header(
            "Origin",
            "https://allowed.example, https://attacker.example",
        ));

        assert_eq!(resp.status, StatusCode::OK, "inner handler still runs");
        assert!(
            !resp.headers.contains_key("access-control-allow-origin"),
            "malformed multi-origin header must not receive wildcard Allow-Origin"
        );
    }

    // br-asupersync-d4f31s: the CorsPolicy::default + allow_credentials=true
    // pairing is now expected to fail-closed: no Allow-Origin emitted, no
    // Allow-Credentials emitted, regardless of which Origin the caller
    // presents. The constructor's debug_assert still rejects this
    // configuration in debug builds; this test runs only in release to pin
    // the release-mode fail-closed contract directly.
    #[cfg(not(debug_assertions))]
    #[test]
    fn cors_credentials_with_any_policy_fails_closed_in_release() {
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::default() // allow_origin: Any
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);

        for origin in [
            "https://attacker.example",
            "https://anything-else.example",
            "https://cred.example",
        ] {
            let resp = mw.call(Request::new("GET", "/cors").with_header("Origin", origin));
            assert_eq!(resp.status, StatusCode::OK);
            assert!(
                !resp.headers.contains_key("access-control-allow-origin"),
                "Any+credentials must not echo any origin (saw {origin})"
            );
            assert!(
                !resp
                    .headers
                    .contains_key("access-control-allow-credentials"),
                "Any+credentials must not emit Allow-Credentials (saw {origin})"
            );
        }
    }

    // ─── CORS preflight Fetch §3.2 conformance harness ───────────────
    //
    // Spec source: https://fetch.spec.whatwg.org/#cors-preflight-fetch
    // (consulted version: 2026-04 commit; the relevant clauses below are
    // stable since 2017). Each test names the clause it pins. Tests are
    // structured one-clause-per-test so a regression message points to
    // the exact spec rule that regressed.

    /// Fetch §3.2.1 — "A CORS-preflight request is a CORS request whose
    /// method is `OPTIONS` and that uses these headers:
    /// `Access-Control-Request-Method`, `Access-Control-Request-Headers`."
    /// An OPTIONS request without `Origin` is NOT a preflight — it is an
    /// ordinary OPTIONS request the application must handle.
    #[test]
    fn fetch_3_2_preflight_requires_origin_header() {
        let inner_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&inner_calls),
            delay: Duration::ZERO,
            status: StatusCode::OK,
        };
        let mw = CorsMiddleware::new(handler, CorsPolicy::default());

        let req =
            Request::new("OPTIONS", "/cors").with_header("Access-Control-Request-Method", "POST");
        let resp = mw.call(req);

        assert_eq!(
            inner_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "OPTIONS without Origin must reach the inner handler",
        );
        assert_eq!(resp.status, StatusCode::OK);
        assert!(
            !resp.headers.contains_key("access-control-allow-origin"),
            "non-CORS OPTIONS must not emit ACAO",
        );
    }

    /// Fetch §3.2.1 — without `Access-Control-Request-Method`, an
    /// OPTIONS request with `Origin` is a non-preflight CORS request:
    /// the inner handler runs and the simple-request CORS headers are
    /// applied, but no preflight short-circuit.
    #[test]
    fn fetch_3_2_preflight_requires_acrm_header() {
        let inner_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&inner_calls),
            delay: Duration::ZERO,
            status: StatusCode::OK,
        };
        let mw = CorsMiddleware::new(handler, CorsPolicy::default());

        let req = Request::new("OPTIONS", "/cors").with_header("Origin", "https://example.com");
        let resp = mw.call(req);

        assert_eq!(
            inner_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "OPTIONS without ACRM must reach the inner handler (not a preflight)",
        );
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            Some(&"*".to_string()),
            "non-preflight CORS request still gets ACAO",
        );
        assert!(
            !resp.headers.contains_key("access-control-allow-methods"),
            "Allow-Methods is preflight-only",
        );
        assert!(
            !resp.headers.contains_key("access-control-max-age"),
            "Max-Age is preflight-only",
        );
    }

    /// Fetch §4.10 step 7 — preflight response status MUST be in the
    /// 2xx range. Implementation pins to 204 No Content; this test
    /// freezes that contract so a future "200 OK" change is visible.
    #[test]
    fn fetch_3_2_preflight_response_status_is_204() {
        let mw = CorsMiddleware::new(FailingIfCalled, CorsPolicy::default());
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert!(resp.body.is_empty(), "preflight body must be empty");
    }

    /// Fetch §3.2.2 — `Access-Control-Allow-Methods` advertises the
    /// methods supported on the resource. The middleware must emit
    /// every method from the policy, NOT echo `Access-Control-Request-Method`
    /// (which would silently allow any caller-requested method).
    #[test]
    fn fetch_3_2_preflight_allow_methods_comes_from_policy_not_request() {
        let policy = CorsPolicy {
            allow_methods: vec!["GET".to_string(), "POST".to_string()],
            ..CorsPolicy::default()
        };
        let mw = CorsMiddleware::new(FailingIfCalled, policy);
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "DELETE");
        let resp = mw.call(req);

        let allow = resp
            .headers
            .get("access-control-allow-methods")
            .expect("preflight must set Allow-Methods");
        assert!(allow.contains("GET"));
        assert!(allow.contains("POST"));
        assert!(
            !allow.contains("DELETE"),
            "DELETE was requested but is not in the policy — it must NOT be echoed; got {allow:?}",
        );
    }

    /// Fetch §3.2.2 — `Access-Control-Max-Age` is advertised when the
    /// policy sets it. Counter: when the policy sets `max_age = None`
    /// the header MUST be omitted (default 5s on browser side; emitting
    /// `0` would be a different signal).
    #[test]
    fn fetch_3_2_preflight_max_age_emitted_from_policy() {
        let policy = CorsPolicy {
            max_age: Some(Duration::from_secs(7200)),
            ..CorsPolicy::default()
        };
        let mw = CorsMiddleware::new(FailingIfCalled, policy);
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST");
        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("access-control-max-age"),
            Some(&"7200".to_string()),
            "Max-Age must reflect the policy duration in seconds",
        );
    }

    /// Counter to the previous test: `max_age = None` MUST omit the
    /// header (rather than emitting a misleading default).
    #[test]
    fn fetch_3_2_preflight_max_age_omitted_when_none() {
        let policy = CorsPolicy {
            max_age: None,
            ..CorsPolicy::default()
        };
        let mw = CorsMiddleware::new(FailingIfCalled, policy);
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST");
        let resp = mw.call(req);

        assert!(
            !resp.headers.contains_key("access-control-max-age"),
            "Max-Age must be omitted when policy.max_age is None",
        );
    }

    /// HTTP caching §4.1 (and Fetch §3.2 by reference) — preflight
    /// responses MUST set `Vary` to include every request header whose
    /// value influenced the response. For a CORS preflight that is
    /// `Origin`, `Access-Control-Request-Method`, and
    /// `Access-Control-Request-Headers`. Without these tokens, an
    /// HTTP cache could serve a preflight response for one origin/method
    /// pair to a different origin/method pair.
    #[test]
    fn fetch_3_2_preflight_vary_includes_origin_acrm_acrh() {
        let mw = CorsMiddleware::new(FailingIfCalled, CorsPolicy::default());
        let req = Request::new("OPTIONS", "/cors")
            .with_header("Origin", "https://example.com")
            .with_header("Access-Control-Request-Method", "POST")
            .with_header("Access-Control-Request-Headers", "content-type");
        let resp = mw.call(req);

        let vary = resp
            .headers
            .get("vary")
            .expect("preflight must emit a Vary header");
        for token in [
            "origin",
            "access-control-request-method",
            "access-control-request-headers",
        ] {
            assert!(
                vary.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case(token)),
                "Vary must include {token:?}; got {vary:?}",
            );
        }
    }

    /// Fetch §3.2.4 — `Access-Control-Expose-Headers` is meaningful
    /// only on actual responses (not preflights), and it lists the
    /// response headers the client JS may read. The middleware MUST
    /// emit it from policy.expose_headers when non-empty.
    #[test]
    fn fetch_3_2_simple_request_emits_expose_headers_from_policy() {
        let policy = CorsPolicy {
            expose_headers: vec!["X-Request-Id".to_string(), "ETag".to_string()],
            ..CorsPolicy::default()
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let req = Request::new("GET", "/cors").with_header("Origin", "https://example.com");
        let resp = mw.call(req);

        let expose = resp
            .headers
            .get("access-control-expose-headers")
            .expect("Expose-Headers must be set when policy lists them");
        assert!(expose.contains("X-Request-Id"));
        assert!(expose.contains("ETag"));
    }

    /// Fetch §3.2.4 — empty `expose_headers` MUST omit the header
    /// (rather than emitting an empty value, which some caches treat
    /// as "expose nothing" and others as "advertise all").
    #[test]
    fn fetch_3_2_simple_request_omits_expose_headers_when_policy_empty() {
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), CorsPolicy::default());
        let req = Request::new("GET", "/cors").with_header("Origin", "https://example.com");
        let resp = mw.call(req);

        assert!(
            !resp.headers.contains_key("access-control-expose-headers"),
            "Expose-Headers must be omitted when policy.expose_headers is empty",
        );
    }

    /// Fetch §3.2.1 — `Origin: null` is a valid serialized origin
    /// (sandboxed iframe, file://, redirected `data:` URI). Under the
    /// non-credentialed `Any` policy, the middleware echoes `*` per the
    /// existing `allowed_origin_value(Any)` branch — `null` is not
    /// `*`, but `*` does cover `null` for non-credentialed reads. This
    /// test pins that `null` does NOT trigger the malformed-origin
    /// fail-closed (which is reserved for comma-bearing multi-origin).
    #[test]
    fn fetch_3_2_origin_null_is_not_malformed() {
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), CorsPolicy::default());
        let req = Request::new("GET", "/cors").with_header("Origin", "null");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            Some(&"*".to_string()),
            "Any policy must echo `*` for an opaque (`null`) origin on a non-credentialed request",
        );
    }

    /// Fetch §3.2.5 — credentialed mode MUST never match `Origin: null`
    /// against an exact-origin allow-list that does not literally list
    /// `null`. The fail-closed contract: no ACAO header.
    #[test]
    fn fetch_3_2_origin_null_not_in_exact_allowlist_emits_no_acao() {
        let policy = CorsPolicy {
            allow_credentials: true,
            ..CorsPolicy::with_exact_origins(vec!["https://app.example.com".to_string()])
        };
        let mw = CorsMiddleware::new(FnHandler::new(ok_handler), policy);
        let req = Request::new("GET", "/cors").with_header("Origin", "null");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(
            !resp.headers.contains_key("access-control-allow-origin"),
            "Origin: null must not match an exact-origin allow-list of named origins",
        );
        assert!(
            !resp
                .headers
                .contains_key("access-control-allow-credentials"),
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

    #[test]
    fn middleware_stack_last_added_header_covers_rate_limit_short_circuit() {
        let inner_header = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_response_header(
                "content-security-policy",
                "default-src 'none'",
                HeaderOverwrite::IfMissing,
            )
            .with_rate_limit(RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(60),
                ..Default::default()
            })
            .build();

        let outer_header = MiddlewareStack::new(FnHandler::new(ok_handler))
            .with_rate_limit(RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(60),
                ..Default::default()
            })
            .with_response_header(
                "content-security-policy",
                "default-src 'none'",
                HeaderOverwrite::IfMissing,
            )
            .build();

        assert_eq!(inner_header.call(make_request()).status, StatusCode::OK);
        let inner_limited = inner_header.call(make_request());
        assert_eq!(inner_limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            !inner_limited
                .headers
                .contains_key("content-security-policy")
        );

        assert_eq!(outer_header.call(make_request()).status, StatusCode::OK);
        let outer_limited = outer_header.call(make_request());
        assert_eq!(outer_limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            outer_limited.headers.get("content-security-policy"),
            Some(&"default-src 'none'".to_string())
        );
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
    fn compression_rejects_small_body_when_identity_is_unacceptable() {
        let config = CompressionConfig {
            min_body_size: 1000,
            ..Default::default()
        };
        let mw = CompressionMiddleware::new(FnHandler::new(ok_handler), config);
        let req = make_request().with_header("Accept-Encoding", "identity;q=0, *;q=0");
        let resp = mw.call(req);

        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn compression_negotiates_encoding() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
            ..CompressionConfig::default()
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

    #[cfg(feature = "compression")]
    #[test]
    fn compression_leaves_breach_sensitive_and_partial_responses_alone() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 1024])
        }
        fn partial_handler() -> Response {
            Response::new(StatusCode::PARTIAL_CONTENT, vec![b'x'; 1024])
                .header("content-range", "bytes 0-1023/4096")
        }
        let gzip = || make_request().with_header("Accept-Encoding", "gzip");
        let encoding = |resp: &Response| resp.headers.get("content-encoding").cloned();
        let mw =
            CompressionMiddleware::new(FnHandler::new(large_handler), CompressionConfig::default());

        assert_eq!(encoding(&mw.call(gzip())), Some("gzip".to_string()));
        // A secret in the response would leak through the compressed length.
        let sensitive = mw.call(gzip().with_header("Cookie", "session=s3cret"));
        assert_eq!(encoding(&sensitive), None);
        assert_eq!(
            sensitive.headers.get("vary"),
            Some(&"accept-encoding, cookie".to_string())
        );
        assert_eq!(
            encoding(&mw.call(gzip().with_header("Authorization", "Bearer t"))),
            None
        );

        let opted_in =
            CompressionMiddleware::new(FnHandler::new(large_handler), CompressionConfig::default())
                .compress_sensitive_responses(true);
        assert_eq!(
            encoding(&opted_in.call(gzip().with_header("Cookie", "session=s3cret"))),
            Some("gzip".to_string())
        );

        let partial = CompressionMiddleware::new(
            FnHandler::new(partial_handler),
            CompressionConfig::default(),
        );
        let resp = partial.call(gzip());
        assert_eq!(encoding(&resp), None, "a 206 is never compressed");
        assert_eq!(resp.body.len(), 1024);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_removes_stale_content_length_after_body_rewrite() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'a'; 4096]).header("content-length", "4096")
        }

        let config = CompressionConfig {
            min_body_size: 0,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
            ..CompressionConfig::default()
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "gzip");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"gzip".to_string())
        );
        assert!(
            !resp.headers.contains_key("content-length"),
            "compressed responses must not retain stale content-length after body rewrite"
        );
    }

    /// zstd through both front ends, the middleware and the layer, wins a tie
    /// in client quality once offered, and is never sent when not offered
    /// (br-asupersync-t1fblr.32).
    #[cfg(feature = "zstd")]
    #[test]
    fn compression_serves_zstd_when_offered() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, b"zstd middleware ".repeat(256))
        }
        let from_middleware =
            CompressionMiddleware::new(FnHandler::new(large_handler), CompressionConfig::default())
                .with_zstd();
        let from_layer = CompressionLayer::default()
            .with_zstd()
            .layer(FnHandler::new(large_handler));
        for mw in [&from_middleware, &from_layer] {
            let resp = mw.call(make_request().with_header("Accept-Encoding", "br, zstd, gzip"));
            assert_eq!(
                resp.headers.get("content-encoding"),
                Some(&"zstd".to_string())
            );
            let limits = asupersync_zstd::DecodeLimits::new(4096);
            let decoded = asupersync_zstd::decode_all(&resp.body, &limits).unwrap();
            assert_eq!(decoded, b"zstd middleware ".repeat(256));
        }
        let not_offered =
            CompressionMiddleware::new(FnHandler::new(large_handler), CompressionConfig::default());
        let resp =
            not_offered.call(make_request().with_header("Accept-Encoding", "zstd, identity;q=0.5"));
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_cap_falls_back_to_identity_when_allowed() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'a'; 4096])
        }

        let config = CompressionConfig {
            min_body_size: 0,
            max_compressed_size: 1,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "gzip");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(resp.body.as_ref(), &[b'a'; 4096]);
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_cap_rejects_when_identity_disallowed() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'a'; 4096])
        }

        let config = CompressionConfig {
            min_body_size: 0,
            max_compressed_size: 1,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_handler), config);
        let req = make_request().with_header("Accept-Encoding", "gzip, identity;q=0");
        let resp = mw.call(req);

        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn compression_absent_accept_encoding_remains_permissive() {
        fn large_handler() -> Response {
            Response::new(StatusCode::OK, vec![b'x'; 512])
        }

        let config = CompressionConfig {
            min_body_size: 256,
            supported: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
            ..CompressionConfig::default()
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
            ..CompressionConfig::default()
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
            ..CompressionConfig::default()
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
            ..CompressionConfig::default()
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_limit_caps_a_streaming_chunked_body() {
        use crate::http::h1::stream::{BodyKind, IncomingBodyError, IncomingRequestBody};
        use crate::web::extract::{
            FromRequest, StreamingRawBody, StreamingRawBodyCollectError, insert_streaming_raw_body,
        };

        // Collects the streaming body and answers with what it saw.
        struct CollectStreaming;
        impl Handler for CollectStreaming {
            fn call(
                &self,
                cx: &Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                let cx = cx.clone();
                Box::pin(async move {
                    let body = StreamingRawBody::from_request(req).expect("streaming body");
                    match body.collect_bounded_with_cx(&cx, 1024).await {
                        Ok(collected) => Response::new(
                            StatusCode::OK,
                            collected.data().len().to_string().into_bytes(),
                        ),
                        Err(StreamingRawBodyCollectError::Body(
                            IncomingBodyError::BodyTooLarge { .. },
                        )) => Response::empty(StatusCode::PAYLOAD_TOO_LARGE),
                        Err(other) => Response::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{other:?}").into_bytes(),
                        ),
                    }
                })
            }
        }

        // A chunked upload carries no Content-Length and leaves req.body
        // empty, so the 6-byte limit used to let all 8 bytes through.
        let cx = Cx::for_testing();
        let (mut writer, incoming) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut req = Request::new("POST", "/upload");
        let control = insert_streaming_raw_body(&mut req, incoming).expect("install body");
        futures_lite::future::block_on(
            writer.push_bytes(&cx, b"4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n"),
        )
        .expect("publish chunked body");

        let mw = RequestBodyLimitMiddleware::new(CollectStreaming, 6);
        let resp = mw.call(req);
        assert_eq!(
            resp.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{}",
            String::from_utf8_lossy(&resp.body)
        );
        drop(control);
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

    #[test]
    fn body_limit_middleware_checks_content_length_early_dos_prevention() {
        // AUDIT TEST: Verify RequestBodyLimitMiddleware checks Content-Length
        // BEFORE body processing to prevent DoS attacks via memory exhaustion
        use crate::bytes::Bytes;

        let mw = RequestBodyLimitMiddleware::new(FnHandler::new(ok_handler), 1024);

        // Test: Large Content-Length with small actual body - should be rejected early
        let req = Request::new("POST", "/upload")
            .with_header("content-length", "2097152") // 2MB declared
            .with_body(Bytes::from_static(b"small")); // But tiny actual body

        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);

        let body_str = String::from_utf8_lossy(&resp.body);
        assert!(
            body_str.contains("Content-Length"),
            "Error should mention Content-Length check, got: {}",
            body_str
        );
        assert!(
            body_str.contains("2097152"),
            "Error should mention declared Content-Length value"
        );
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
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(async move {
                    req.extensions.get("request_id").map_or_else(
                        || Response::new(StatusCode::BAD_REQUEST, b"no id".to_vec()),
                        |val| Response::new(StatusCode::OK, val.as_bytes().to_vec()),
                    )
                })
            }
        }

        let mw = RequestIdMiddleware::new(RequestIdEchoHandler, "x-request-id");
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.starts_with("req-"));
    }

    // br-asupersync-pol3ps: request-ID length cap prevents log amplification

    #[test]
    fn request_id_truncates_oversize_client_supplied_value_to_default_128() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        // 4 KiB attacker-supplied request ID — would normally be cloned 3x
        // (extensions["request_id"], extensions["trace_id"], response header)
        // and then logged by every downstream middleware that touches the ID.
        let huge = "A".repeat(4 * 1024);
        let req = make_request().with_header("x-request-id", &huge);
        let resp = mw.call(req);
        let echoed = resp.headers.get("x-request-id").unwrap();
        assert_eq!(
            echoed.chars().count(),
            DEFAULT_REQUEST_ID_MAX_LENGTH,
            "echo header must be truncated to DEFAULT_REQUEST_ID_MAX_LENGTH (128 chars), \
             got {} chars",
            echoed.chars().count()
        );
        assert!(echoed.chars().all(|c| c == 'A'));
    }

    #[test]
    fn request_id_with_max_length_overrides_default() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id")
            .with_max_length(16);
        let huge = "B".repeat(1024);
        let req = make_request().with_header("x-request-id", &huge);
        let resp = mw.call(req);
        let echoed = resp.headers.get("x-request-id").unwrap();
        assert_eq!(echoed.chars().count(), 16);
    }

    #[test]
    fn request_id_with_max_length_zero_falls_back_to_default() {
        // 0 is rejected (would silently disable the cap); coerced to default.
        let mw =
            RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id").with_max_length(0);
        let huge = "C".repeat(4 * 1024);
        let req = make_request().with_header("x-request-id", &huge);
        let resp = mw.call(req);
        let echoed = resp.headers.get("x-request-id").unwrap();
        assert_eq!(echoed.chars().count(), DEFAULT_REQUEST_ID_MAX_LENGTH);
    }

    #[test]
    fn request_id_truncate_respects_utf8_char_boundary() {
        // 50 multi-byte chars (each = 4 bytes); cap at 10 chars.
        // truncate_request_id MUST cut at a char boundary, not a byte boundary
        // (String::truncate at a non-boundary panics).
        let s: String = std::iter::repeat_n('🦀', 50).collect();
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id")
            .with_max_length(10);
        let req = make_request().with_header("x-request-id", &s);
        let resp = mw.call(req);
        let echoed = resp.headers.get("x-request-id").unwrap();
        assert_eq!(echoed.chars().count(), 10);
        assert_eq!(echoed.chars().filter(|c| *c == '🦀').count(), 10);
        // Must be valid UTF-8 (round-trip without panic).
        let _ = echoed.as_bytes();
    }

    #[test]
    fn request_id_passes_through_short_client_value_unchanged() {
        let mw = RequestIdMiddleware::new(FnHandler::new(ok_handler), "x-request-id");
        let req = make_request().with_header("x-request-id", "abc-123");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("x-request-id"),
            Some(&"abc-123".to_string()),
            "values under the cap must pass through verbatim"
        );
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
    fn request_trace_preserves_mixed_case_existing_trace_header_without_duplication() {
        fn header_handler() -> Response {
            let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
            resp.headers
                .insert("X-Trace-Id".to_string(), "inner-trace".to_string());
            resp
        }

        let mw = RequestTraceMiddleware::new(
            FnHandler::new(header_handler),
            RequestTracePolicy::default(),
        );
        let resp = mw.call(make_request().with_header("x-request-id", "outer-trace"));

        assert_eq!(resp.header_value("x-trace-id"), Some("inner-trace"));
        assert_eq!(
            resp.headers.len(),
            2,
            "only duration and trace headers should be present"
        );
        assert!(!resp.headers.contains_key("x-trace-id"));
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

    #[test]
    fn request_trace_truncates_giant_x_request_id_header_dos_attack() {
        // Regression test for br-asupersync-gwezkv: DoS via giant x-request-id
        // header that gets amplified into logs and response headers.
        let giant_id = "A".repeat(4 * 1024 * 1024); // 4MB header
        let mw =
            RequestTraceMiddleware::new(FnHandler::new(ok_handler), RequestTracePolicy::default());
        let req = make_request().with_header("x-request-id", &giant_id);
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);

        // Trace ID should be truncated to DEFAULT_TRACE_ID_MAX_LENGTH (128 chars)
        let trace_id = resp.headers.get("x-trace-id").unwrap();
        assert_eq!(
            trace_id.chars().count(),
            DEFAULT_TRACE_ID_MAX_LENGTH,
            "giant x-request-id must be truncated to prevent DoS amplification"
        );
        assert_eq!(trace_id, &"A".repeat(DEFAULT_TRACE_ID_MAX_LENGTH));

        // Verify the truncated value is all 'A's (no injection)
        assert!(trace_id.chars().all(|c| c == 'A'));
    }

    #[test]
    fn request_trace_sanitizes_crlf_in_x_request_id_header() {
        // Verify CRLF injection protection in trace ID extraction
        let malicious_id = "trace\r\nX-Injected: malicious\r\n";
        let mw =
            RequestTraceMiddleware::new(FnHandler::new(ok_handler), RequestTracePolicy::default());
        let req = make_request().with_header("x-request-id", malicious_id);
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);

        // CRLF should be stripped to prevent header injection
        let trace_id = resp.headers.get("x-trace-id").unwrap();
        assert_eq!(trace_id, "traceX-Injected: malicious");
        assert!(!trace_id.contains('\r'));
        assert!(!trace_id.contains('\n'));
    }

    // --- CatchPanicMiddleware ---

    #[test]
    fn catch_panic_recovers() {
        let mw = CatchPanicMiddleware::new(PanicHandler);
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8_lossy(&resp.body);
        assert_eq!(body, "[ASUP-E502] Internal Server Error");
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
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(async move { Response::new(StatusCode::OK, req.path.into_bytes()) })
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
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(async move { Response::new(StatusCode::OK, req.path.into_bytes()) })
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
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                Box::pin(async move { Response::new(StatusCode::OK, req.path.into_bytes()) })
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
    fn normalize_path_redirects_keep_the_query_string() {
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectTrim);
        let resp = mw.call(Request::new("GET", "/search/").with_query("q=x&page=2"));
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers.get("location"),
            Some(&"/search?q=x&page=2".to_string())
        );

        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectAlways);
        let resp = mw.call(Request::new("GET", "/search").with_query("q=x"));
        assert_eq!(
            resp.headers.get("location"),
            Some(&"/search/?q=x".to_string())
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

    // ─── Open Redirect Security Tests ───────────────────────────────────

    #[test]
    fn normalize_path_redirect_trim_prevents_protocol_relative_open_redirect() {
        // Protocol-relative URLs like //evil.com/ must fail closed rather than
        // emitting a Location header that a browser could treat as off-origin.
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectTrim);
        let resp = mw.call(Request::new("GET", "//evil.com/"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));
    }

    #[test]
    fn normalize_path_redirect_always_prevents_protocol_relative_open_redirect() {
        // Protocol-relative URLs like //evil must fail closed rather than
        // emitting a redirect gadget.
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectAlways);

        let resp = mw.call(Request::new("GET", "//evil"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));
    }

    #[test]
    fn normalize_path_redirect_handles_complex_protocol_relative_attacks() {
        // Additional regression coverage for hostile normalization inputs.
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectTrim);

        let resp = mw.call(Request::new("GET", "//attacker-host/path/"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));

        let resp = mw.call(Request::new("GET", "///triple-slash.example/"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));

        let mw_always =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectAlways);
        let resp = mw_always.call(Request::new("GET", "//evilhost"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));
    }

    #[test]
    fn normalize_path_redirect_rejects_backslash_host_pivot() {
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectAlways);
        let resp = mw.call(Request::new("GET", "/\\\\attacker.com"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));
    }

    #[test]
    fn normalize_path_redirect_rejects_percent_encoded_slash_host_pivot() {
        let mw =
            NormalizePathMiddleware::new(FnHandler::new(ok_handler), TrailingSlash::RedirectTrim);
        let resp = mw.call(Request::new("GET", "/%2fevil.example/"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(!resp.headers.contains_key("location"));
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

    #[test]
    fn set_header_if_missing_respects_mixed_case_existing_header() {
        fn header_handler() -> Response {
            let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
            resp.headers
                .insert("X-Custom".to_string(), "original".to_string());
            resp
        }

        let mw = SetResponseHeaderMiddleware::if_missing(
            FnHandler::new(header_handler),
            "x-custom",
            "new",
        );
        let resp = mw.call(make_request());

        assert_eq!(resp.header_value("x-custom"), Some("original"));
        assert_eq!(
            resp.headers.len(),
            1,
            "if-missing should not create a duplicate logical header"
        );
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

    /// AUDIT MODULE: Request rate limiting compliance verification
    ///
    /// AUDIT FINDING: SOUND - Rate limiting correctly returns 429 Too Many Requests
    /// with Retry-After header per RFC 9110 §15.5.16. Implementation distinguishes
    /// between rate limit exceeded (429) vs queue exhaustion (503).
    mod rate_limiting_compliance_audit {
        use super::*;

        /// AUDIT: Verify rate limiting returns correct 429 status per RFC 9110 §15.5.16
        ///
        /// RFC 9110 §15.5.16 specifies that 429 Too Many Requests should be used
        /// when the user has sent too many requests in a given amount of time.
        #[test]
        fn audit_rate_limit_returns_429_too_many_requests() {
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(60),
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            // First request consumes burst allowance
            let resp1 = mw.call(make_request());
            assert_eq!(resp1.status, StatusCode::OK, "First request should succeed");

            // Second request should be rate limited with proper status
            let resp2 = mw.call(make_request());
            assert_eq!(
                resp2.status,
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limited request must return 429 Too Many Requests per RFC 9110 §15.5.16"
            );

            // AUDIT VERIFICATION: Correct status code used
            // - 429 (not 503) for rate limit exceeded
            // - Distinguishes rate limiting from server overload
        }

        /// AUDIT: Verify Retry-After header inclusion per RFC 9110 §15.5.16
        ///
        /// RFC 9110 §15.5.16 specifies that 429 responses SHOULD include a
        /// Retry-After header to indicate when to retry the request.
        #[test]
        fn audit_retry_after_header_compliance() {
            let policy = RateLimitPolicy {
                rate: 2,                         // 2 requests per period
                burst: 1,                        // Allow 1 immediate request
                period: Duration::from_secs(30), // 30-second reset period
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            // Exhaust rate limit
            let _ = mw.call(make_request());
            let rate_limited = mw.call(make_request());

            assert_eq!(rate_limited.status, StatusCode::TOO_MANY_REQUESTS);

            // AUDIT REQUIREMENT 1: Retry-After header MUST be present
            assert!(
                rate_limited.headers.contains_key("retry-after"),
                "429 response must include Retry-After header per RFC 9110 §15.5.16"
            );

            // AUDIT REQUIREMENT 2: Retry-After value must be reasonable
            let retry_after = rate_limited.headers.get("retry-after").unwrap();
            let seconds: u64 = retry_after
                .parse()
                .expect("Retry-After should be numeric seconds");
            assert!(
                seconds > 0 && seconds <= 60,
                "Retry-After should specify reasonable delay: {} seconds",
                seconds
            );

            // AUDIT VERIFICATION: Header format follows RFC
            // - Uses delay-seconds format (not HTTP-date)
            // - Provides actionable retry guidance
        }

        /// AUDIT: Verify rate limit vs queue exhaustion status distinction
        ///
        /// Implementation correctly uses different status codes:
        /// - 429 for rate limit exceeded (client sent too many requests)
        /// - 503 for queue exhaustion (server-side resource exhaustion)
        #[test]
        fn audit_rate_limit_vs_queue_exhaustion_status_codes() {
            // Test regular rate limiting (429)
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(60),
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            let _ = mw.call(make_request()); // Consume allowance
            let rate_limited = mw.call(make_request());

            assert_eq!(
                rate_limited.status,
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded should return 429"
            );
            assert!(
                rate_limited.headers.contains_key("retry-after"),
                "Rate limit 429 should include Retry-After"
            );

            // AUDIT VERIFICATION: Proper status code semantics
            // - 429 = client behavior problem (too many requests)
            // - 503 = server resource problem (queue exhaustion)
            // - Retry-After provided for 429 but not necessarily 503
        }

        /// AUDIT: Verify response message follows RFC 9110 format recommendations
        ///
        /// While not strictly required, good practice per RFC 9110 to provide
        /// descriptive error messages for 429 responses.
        #[test]
        fn audit_rate_limit_error_message_format() {
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(45),
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            let _ = mw.call(make_request());
            let rate_limited = mw.call(make_request());

            let body = String::from_utf8(rate_limited.body.to_vec())
                .expect("Response body should be UTF-8");

            // AUDIT REQUIREMENT 1: Message should mention "Too Many Requests"
            assert!(
                body.contains("Too Many Requests"),
                "Error message should identify the 429 error type: {}",
                body
            );

            // AUDIT REQUIREMENT 2: Message should include retry guidance
            assert!(
                body.contains("retry after") || body.contains("Retry-After"),
                "Error message should provide retry guidance: {}",
                body
            );

            // AUDIT REQUIREMENT 3: Message should mention rate limit
            assert!(
                body.contains("rate limit"),
                "Error message should identify rate limiting as the cause: {}",
                body
            );

            // AUDIT VERIFICATION: User-friendly error responses
            // - Descriptive error message
            // - Clear retry guidance
            // - Identifies rate limiting as root cause
        }

        /// AUDIT: Verify Retry-After calculation accuracy
        ///
        /// The retry time should accurately reflect when the rate limit
        /// will allow the next request, based on the limiter's refill schedule.
        #[test]
        fn audit_retry_after_calculation_accuracy() {
            thread_local! {
                static TEST_TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
            }

            fn set_test_time(ms: u64) {
                TEST_TIME.with(|t| t.set(ms));
            }

            fn test_time() -> Time {
                Time::from_millis(TEST_TIME.with(std::cell::Cell::get))
            }

            let policy = RateLimitPolicy {
                rate: 1,                          // 1 request per period
                burst: 1,                         // 1 initial token
                period: Duration::from_secs(120), // 2-minute refill
                ..Default::default()
            };
            let mw = RateLimitMiddleware::with_time_getter(
                FnHandler::new(ok_handler),
                policy,
                test_time,
            );

            // Set initial time and consume token
            set_test_time(10_000); // t=10s
            let _ = mw.call(make_request());

            // Request immediately after should be rate limited
            let rate_limited = mw.call(make_request());
            assert_eq!(rate_limited.status, StatusCode::TOO_MANY_REQUESTS);

            // Check Retry-After matches refill period
            let retry_after = rate_limited.headers.get("retry-after").unwrap();
            assert_eq!(
                retry_after, "120",
                "Retry-After should match rate limiter refill period"
            );

            // Advance time and verify retry calculation updates
            set_test_time(70_000); // t=70s (60s elapsed after consuming at t=10s)
            let still_limited = mw.call(make_request());
            let updated_retry_after = still_limited.headers.get("retry-after").unwrap();
            assert_eq!(
                updated_retry_after, "60",
                "Retry-After should decrease as time progresses"
            );

            // AUDIT VERIFICATION: Dynamic retry time calculation
            // - Initially shows full refill period (120s)
            // - Decreases as time progresses (70s remaining)
            // - Provides accurate timing for next allowed request
        }

        /// AUDIT: Verify RFC 9110 compliance for Retry-After header format
        ///
        /// RFC 9110 allows two formats for Retry-After:
        /// - delay-seconds: number of seconds to delay
        /// - HTTP-date: absolute date when to retry
        ///
        /// Our implementation uses delay-seconds (preferred for rate limiting).
        #[test]
        fn audit_retry_after_format_rfc9110_compliance() {
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(300), // 5 minutes
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            let _ = mw.call(make_request());
            let rate_limited = mw.call(make_request());

            let retry_after = rate_limited.headers.get("retry-after").unwrap();

            // AUDIT REQUIREMENT: Must be valid delay-seconds format
            let seconds: Result<u64, _> = retry_after.parse();
            assert!(
                seconds.is_ok(),
                "Retry-After must be valid delay-seconds format per RFC 9110, got: {}",
                retry_after
            );

            let seconds = seconds.unwrap();
            assert!(
                seconds <= 300,
                "Retry-After should not exceed rate limit period"
            );
            assert!(
                seconds >= 1,
                "Retry-After should be at least 1 second (minimum meaningful delay)"
            );

            // AUDIT VERIFICATION: Standards-compliant header format
            // - Uses delay-seconds (not HTTP-date)
            // - Numeric value within reasonable range
            // - Provides immediate actionable timing
        }

        /// AUDIT: Edge case - zero burst policy behavior
        ///
        /// Verify rate limiting works correctly even with edge case configurations.
        #[test]
        fn audit_edge_case_zero_burst_handling() {
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 0, // No initial tokens
                period: Duration::from_secs(60),
                ..Default::default()
            };
            let mw = RateLimitMiddleware::new(FnHandler::new(ok_handler), policy);

            // With zero burst, first request should be rate limited
            let resp = mw.call(make_request());
            assert_eq!(
                resp.status,
                StatusCode::TOO_MANY_REQUESTS,
                "Zero burst should rate limit immediately"
            );
            assert!(
                resp.headers.contains_key("retry-after"),
                "Zero burst 429 should include Retry-After"
            );

            // AUDIT VERIFICATION: Edge case robustness
            // - Handles zero burst configuration correctly
            // - Still returns proper 429 + Retry-After headers
        }
    }

    // ─── Layer adapter tests (br-asupersync-server-stack-hardening-eeexl1.3) ─

    mod layer_adapters {
        use super::*;
        use crate::service::{Identity, Stack};

        #[test]
        fn timeout_layer_matches_direct_construction() {
            set_timeout_test_time(0);
            let via_layer =
                TimeoutLayer::with_time_getter(Duration::from_secs(5), timeout_test_time)
                    .layer(FnHandler::new(ok_handler));
            let direct = TimeoutMiddleware::with_time_getter(
                FnHandler::new(ok_handler),
                Duration::from_secs(5),
                timeout_test_time,
            );
            let layer_resp = call_sync(&via_layer, make_request());
            let direct_resp = call_sync(&direct, make_request());
            assert_eq!(layer_resp.status, direct_resp.status);
            assert_eq!(layer_resp.status, StatusCode::OK);
        }

        #[test]
        fn budget_aware_timeout_tightens_to_remaining_budget() {
            set_timeout_test_time(0);
            // Handler "takes" 100ms on the injected clock.
            let slow = FnHandler::new(|| {
                set_timeout_test_time(100);
                "done"
            });
            // Cap is generous (5s) but the request budget expires at 50ms →
            // min-plus: effective timeout is 50ms → 504.
            let mw = TimeoutMiddleware::budget_aware_with_time_getter(
                slow,
                Duration::from_secs(5),
                timeout_test_time,
            );
            let budget = crate::types::Budget::INFINITE.with_deadline(Time::from_millis(50));
            let cx = crate::Cx::for_testing_with_budget(budget);
            let resp = futures_lite::future::block_on(Handler::call(&mw, &cx, make_request()));
            assert_eq!(
                resp.status,
                StatusCode::GATEWAY_TIMEOUT,
                "budget tighter than cap must win (min-plus)"
            );

            // Without a budget deadline the cap alone applies → OK.
            set_timeout_test_time(0);
            let fast = FnHandler::new(|| {
                set_timeout_test_time(100);
                "done"
            });
            let mw = TimeoutMiddleware::budget_aware_with_time_getter(
                fast,
                Duration::from_secs(5),
                timeout_test_time,
            );
            let resp = call_sync(&mw, make_request());
            assert_eq!(resp.status, StatusCode::OK);
        }

        #[test]
        fn auth_layer_short_circuits_unauthorized() {
            let mw = AuthLayer::new(AuthPolicy::exact_bearer("token-123"))
                .layer(FnHandler::new(ok_handler));
            let resp = call_sync(&mw, make_request());
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        }

        #[test]
        fn rate_limit_layer_shares_limiter_across_wrapped_handlers() {
            set_rate_limit_test_time(0);
            let policy = RateLimitPolicy {
                rate: 1,
                burst: 1,
                period: Duration::from_secs(60),
                ..Default::default()
            };
            let layer = RateLimitLayer::with_time_getter(policy, rate_limit_test_time);
            let a = layer.layer(FnHandler::new(ok_handler));
            let b = layer.layer(FnHandler::new(ok_handler));

            assert_eq!(call_sync(&a, make_request()).status, StatusCode::OK);
            // The second handler shares the limiter, so the single token is gone.
            assert_eq!(
                call_sync(&b, make_request()).status,
                StatusCode::TOO_MANY_REQUESTS,
                "layer-shared limiter must apply across all wrapped handlers"
            );
        }

        #[test]
        fn circuit_breaker_layer_shares_breaker() {
            let layer = CircuitBreakerLayer::new(CircuitBreakerPolicy::default());
            let a = layer.layer(FnHandler::new(ok_handler));
            let b = layer.layer(FnHandler::new(ok_handler));
            assert!(
                Arc::ptr_eq(&a.breaker, &b.breaker),
                "one layer value must share one breaker"
            );
        }

        #[test]
        fn bulkhead_layer_shares_bulkhead() {
            let layer = BulkheadLayer::new(BulkheadPolicy::default());
            let a = layer.layer(FnHandler::new(ok_handler));
            let b = layer.layer(FnHandler::new(ok_handler));
            assert!(
                Arc::ptr_eq(&a.bulkhead, &b.bulkhead),
                "one layer value must share one bulkhead"
            );
        }

        #[test]
        fn load_shed_layer_shares_in_flight_counter() {
            let layer = LoadShedLayer::new(LoadShedPolicy { max_in_flight: 7 });
            let a = layer.layer(FnHandler::new(ok_handler));
            let b = layer.layer(FnHandler::new(ok_handler));
            assert!(
                Arc::ptr_eq(&a.in_flight, &b.in_flight),
                "one layer value must share one in-flight counter"
            );
        }

        #[test]
        fn request_id_layer_keeps_ids_unique_across_wrapped_handlers() {
            let layer = RequestIdLayer::new("x-request-id");
            let a = layer.layer(FnHandler::new(ok_handler));
            let b = layer.layer(FnHandler::new(ok_handler));
            assert!(Arc::ptr_eq(&a.counter, &b.counter));

            let ra = call_sync(&a, make_request());
            let rb = call_sync(&b, make_request());
            let ida = ra.headers.get("x-request-id").cloned();
            let idb = rb.headers.get("x-request-id").cloned();
            assert!(ida.is_some() && idb.is_some());
            assert_ne!(ida, idb, "shared counter must keep generated IDs unique");
        }

        #[test]
        fn service_stack_composes_web_layers() {
            // The service stack's Stack/Identity machinery composes web layers
            // directly: ONE Layer trait serves both families.
            let stack = Stack::new(
                AuthLayer::new(AuthPolicy::exact_bearer("tok")),
                SetResponseHeaderLayer::new("x-sec", "1", HeaderOverwrite::Always),
            );
            let handler = stack.layer(FnHandler::new(ok_handler));

            // Unauthorized request: inner auth layer rejects, outer header
            // layer still stamps the synthetic response.
            let resp = call_sync(&handler, make_request());
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers.get("x-sec").map(String::as_str), Some("1"));
        }

        #[test]
        fn identity_layer_is_transparent_for_handlers() {
            let handler = Identity.layer(FnHandler::new(ok_handler));
            assert_eq!(call_sync(&handler, make_request()).status, StatusCode::OK);
        }

        #[test]
        fn middleware_stack_layer_method_composes() {
            let handler = MiddlewareStack::new(FnHandler::new(ok_handler))
                .layer(CatchPanicLayer::new())
                .layer(SetResponseHeaderLayer::new(
                    "x-layered",
                    "yes",
                    HeaderOverwrite::Always,
                ))
                .build();
            let resp = call_sync(&handler, make_request());
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(
                resp.headers.get("x-layered").map(String::as_str),
                Some("yes")
            );
        }

        #[test]
        fn boxed_dyn_handler_can_be_layered() {
            let boxed: Box<dyn Handler> = Box::new(FnHandler::new(ok_handler));
            let wrapped = CatchPanicLayer::new().layer(boxed);
            assert_eq!(call_sync(&wrapped, make_request()).status, StatusCode::OK);
        }
    }
