    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::{
        AsupersyncService, AsupersyncServiceExt, OneshotError, OneshotState, Service, ServiceExt,
    };
    use crate::test_utils::run_test_with_cx;
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::pin::Pin;

    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Clone, Debug)]
    struct PanicOnCallService;

    impl Service<u32> for PanicOnCallService {
        type Response = ();
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            panic!("panic during oneshot call construction");
        }
    }

    #[derive(Clone, Debug)]
    struct EchoU32Service;

    impl Service<u32> for EchoU32Service {
        type Response = u32;
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u32) -> Self::Future {
            std::future::ready(Ok(req))
        }
    }

    #[derive(Debug)]
    struct PendingThenReadyFuture {
        value: u32,
        first_poll: bool,
    }

    impl Future for PendingThenReadyFuture {
        type Output = Result<u32, ()>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(self.value))
        }
    }

    #[derive(Debug)]
    struct PendingThenReadyService {
        ready_polls: Cell<u8>,
    }

    impl PendingThenReadyService {
        fn new() -> Self {
            Self {
                ready_polls: Cell::new(0),
            }
        }
    }

    impl Service<u32> for PendingThenReadyService {
        type Response = u32;
        type Error = ();
        type Future = PendingThenReadyFuture;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready_polls.get() == 0 {
                self.ready_polls.set(1);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u32) -> Self::Future {
            PendingThenReadyFuture {
                value: req,
                first_poll: true,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ErrorOnCallService;

    impl Service<u32> for ErrorOnCallService {
        type Response = u32;
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            std::future::ready(Err(()))
        }
    }

    #[test]
    fn function_service_call_works() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, ()>(req + 1) };
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);
        });
    }

    #[test]
    fn map_response_and_map_err() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, &str>(req) };
            let svc = svc.map_response(|v| v + 1).map_err(|e| format!("err:{e}"));
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);

            let fail = |_: &crate::cx::Cx, _: i32| async move { Err::<i32, &str>("nope") };
            let fail = fail.map_err(|e| format!("err:{e}"));
            let err = AsupersyncService::call(&fail, &cx, 0).await.unwrap_err();
            assert_eq!(err, "err:nope");
        });
    }

    #[test]
    fn oneshot_second_poll_fails_closed_after_success() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = EchoU32Service.oneshot(7);

        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Ok(7))
        ));
        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Err(OneshotError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn oneshot_pending_then_completion_then_repoll_fails_closed() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = PendingThenReadyService::new().oneshot(9);

        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));
        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));
        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Ok(9))
        ));
        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Err(OneshotError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn oneshot_repoll_after_inner_error_fails_closed() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = ErrorOnCallService.oneshot(7);

        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Err(OneshotError::Inner(())))
        ));
        assert!(matches!(
            Pin::new(&mut fut).poll(&mut cx),
            Poll::Ready(Err(OneshotError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn oneshot_call_panic_leaves_terminal_state() {
        let mut fut = PanicOnCallService.oneshot(7);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(first_panic.is_err(), "first poll should propagate panic");
        assert!(
            matches!(fut.state, OneshotState::Done),
            "panic path must leave Oneshot in Done state"
        );

        assert!(
            matches!(
                Pin::new(&mut fut).poll(&mut cx),
                Poll::Ready(Err(OneshotError::PolledAfterCompletion))
            ),
            "repoll should fail closed after panic left the future terminal"
        );
    }

    #[test]
    fn oneshot_error_display_and_source() {
        use std::error::Error;

        let inner = OneshotError::Inner(std::io::Error::other("boom"));
        assert_eq!(format!("{inner}"), "inner service error: boom");
        assert!(inner.source().is_some());

        let done: OneshotError<std::io::Error> = OneshotError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "oneshot future polled after completion");
        assert!(done.source().is_none());
    }

    // ========================================================================
    // Tower Adapter Configuration Tests
    // ========================================================================

    use super::{
        AdapterConfig, CancellationMode, DefaultErrorAdapter, ErrorAdapter, TowerAdapterError,
    };

    #[test]
    fn cancellation_mode_default_is_best_effort() {
        let mode = CancellationMode::default();
        assert_eq!(mode, CancellationMode::BestEffort);
    }

    #[test]
    fn adapter_config_builder_pattern() {
        let config = AdapterConfig::new()
            .cancellation_mode(CancellationMode::Strict)
            .fallback_timeout(std::time::Duration::from_secs(30))
            .min_budget_for_wait(100);

        assert_eq!(config.cancellation_mode, CancellationMode::Strict);
        assert_eq!(
            config.fallback_timeout,
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(config.min_budget_for_wait, 100);
    }

    #[test]
    fn adapter_config_default_values() {
        let config = AdapterConfig::default();

        assert_eq!(config.cancellation_mode, CancellationMode::BestEffort);
        assert!(config.fallback_timeout.is_none());
        assert_eq!(config.min_budget_for_wait, 10);
    }

    #[test]
    fn default_error_adapter_round_trip() {
        let adapter = DefaultErrorAdapter::<String>::new();

        let original = "test error".to_string();
        let converted = adapter.to_asupersync(original.clone());
        assert_eq!(converted, original);

        let back = adapter.to_tower(converted);
        assert_eq!(back, original);
    }

    #[test]
    fn tower_adapter_error_display() {
        let service_err: TowerAdapterError<&str> = TowerAdapterError::Service("inner error");
        assert_eq!(format!("{service_err}"), "service error: inner error");

        let cancelled: TowerAdapterError<&str> = TowerAdapterError::Cancelled;
        assert_eq!(format!("{cancelled}"), "operation cancelled");

        let timeout: TowerAdapterError<&str> = TowerAdapterError::Timeout;
        assert_eq!(format!("{timeout}"), "operation timed out");

        let overloaded: TowerAdapterError<&str> = TowerAdapterError::Overloaded;
        assert_eq!(
            format!("{overloaded}"),
            "service overloaded, insufficient budget"
        );

        let ignored: TowerAdapterError<&str> = TowerAdapterError::CancellationIgnored;
        assert_eq!(
            format!("{ignored}"),
            "service ignored cancellation request (strict mode)"
        );
    }

    #[test]
    fn tower_adapter_error_equality() {
        let err1: TowerAdapterError<i32> = TowerAdapterError::Service(42);
        let err2: TowerAdapterError<i32> = TowerAdapterError::Service(42);
        let err3: TowerAdapterError<i32> = TowerAdapterError::Service(43);

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);

        assert_eq!(
            TowerAdapterError::<i32>::Cancelled,
            TowerAdapterError::Cancelled
        );
        assert_ne!(
            TowerAdapterError::<i32>::Cancelled,
            TowerAdapterError::Timeout
        );
    }

    #[test]
    fn cancellation_mode_all_variants() {
        // Ensure all variants are distinct
        let best_effort = CancellationMode::BestEffort;
        let strict = CancellationMode::Strict;
        let timeout = CancellationMode::TimeoutFallback;

        assert_ne!(best_effort, strict);
        assert_ne!(best_effort, timeout);
        assert_ne!(strict, timeout);
    }

    // ========================================================================
    // Cx Provider Tests (cfg(feature = "tower"))
    // ========================================================================

    #[cfg(feature = "tower")]
    mod cx_provider_tests {
        use super::super::{CxProvider, FixedCxProvider, ThreadLocalCxProvider};
        use crate::Cx;

        #[test]
        fn thread_local_provider_returns_none_when_not_set() {
            let provider = ThreadLocalCxProvider;
            // Outside of runtime context, should return None
            assert!(provider.current_cx().is_none());
        }

        #[test]
        fn fixed_provider_returns_cx() {
            let cx: Cx = Cx::for_testing();
            let provider = FixedCxProvider::new(cx.clone());

            let retrieved = provider.current_cx();
            assert!(retrieved.is_some());
            // Same task ID indicates it's the same (or equivalent) Cx
            assert_eq!(retrieved.unwrap().task_id(), cx.task_id());
        }

        #[test]
        fn fixed_provider_for_testing_convenience() {
            let provider = FixedCxProvider::for_testing();
            assert!(provider.current_cx().is_some());
        }

        #[test]
        fn thread_local_provider_default() {
            let provider = ThreadLocalCxProvider;
            // Just verify it doesn't panic
            let _ = provider.current_cx();
        }

        #[test]
        fn fixed_provider_is_cloneable() {
            let provider = FixedCxProvider::for_testing();
            let cloned = provider.clone();
            assert!(provider.current_cx().is_some());
            assert!(cloned.current_cx().is_some());
        }
    }

    // ========================================================================
    // Tower Adapter with Provider Tests (cfg(feature = "tower"))
    // ========================================================================

    #[cfg(feature = "tower")]
    mod tower_provider_tests {
        use super::super::{
            AsupersyncService, CxProvider, FixedCxProvider, NoCxAvailable, ProviderAdapterError,
            TowerAdapterWithProvider,
        };
        use crate::Cx;

        // A simple test service
        struct AddOneService;

        impl AsupersyncService<i32> for AddOneService {
            type Response = i32;
            type Error = std::convert::Infallible;

            async fn call(&self, _cx: &Cx, req: i32) -> Result<Self::Response, Self::Error> {
                Ok(req + 1)
            }
        }

        #[test]
        fn adapter_with_fixed_provider_works() {
            let provider = FixedCxProvider::for_testing();
            let adapter = TowerAdapterWithProvider::with_provider(AddOneService, provider);

            // Verify provider is accessible
            assert!(adapter.provider().current_cx().is_some());
        }

        #[test]
        fn adapter_new_uses_thread_local_provider() {
            let adapter = TowerAdapterWithProvider::new(AddOneService);
            // Thread-local provider returns None when not in runtime
            assert!(adapter.provider().current_cx().is_none());
        }

        #[test]
        fn adapter_is_cloneable_with_clone_provider() {
            let provider = FixedCxProvider::for_testing();
            let adapter = TowerAdapterWithProvider::with_provider(AddOneService, provider);
            let _cloned = adapter;
        }

        #[test]
        fn no_cx_available_error_display() {
            let err = NoCxAvailable;
            let msg = format!("{err}");
            assert!(msg.contains("no Cx available"));
        }

        #[test]
        fn provider_adapter_error_display() {
            let no_cx: ProviderAdapterError<&str> = ProviderAdapterError::NoCx(NoCxAvailable);
            assert!(format!("{no_cx}").contains("no Cx available"));

            let service_err: ProviderAdapterError<&str> =
                ProviderAdapterError::Service("test error");
            assert_eq!(format!("{service_err}"), "service error: test error");
        }

        #[test]
        fn provider_adapter_error_equality() {
            let err1: ProviderAdapterError<i32> = ProviderAdapterError::Service(42);
            let err2: ProviderAdapterError<i32> = ProviderAdapterError::Service(42);
            let err3: ProviderAdapterError<i32> = ProviderAdapterError::Service(43);

            assert_eq!(err1, err2);
            assert_ne!(err1, err3);

            let no_cx1: ProviderAdapterError<i32> = ProviderAdapterError::NoCx(NoCxAvailable);
            let no_cx2: ProviderAdapterError<i32> = ProviderAdapterError::NoCx(NoCxAvailable);
            assert_eq!(no_cx1, no_cx2);
        }
    }

    #[cfg(feature = "tower")]
    mod tower_adapter_timeout_tests {
        use super::super::{
            AdapterConfig, AsupersyncAdapter, AsupersyncService, CancellationMode,
            TowerAdapterError,
        };
        use crate::Cx;
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId, Time};
        use std::future::{Future, pending};
        use std::pin::pin;
        use std::sync::Arc;
        use std::task::{Context, Poll, Waker};
        use std::time::Duration;

        fn noop_waker() -> Waker {
            std::task::Waker::noop().clone()
        }

        fn test_cx_with_timer() -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
            let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
            let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            (cx, clock, timer)
        }

        #[derive(Clone)]
        struct PendingService;

        #[derive(Clone)]
        struct PendingReadyService;

        #[derive(Debug)]
        struct TestError;

        impl std::fmt::Display for TestError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "test error")
            }
        }

        impl tower::Service<()> for PendingService {
            type Response = ();
            type Error = TestError;
            type Future = std::future::Pending<Result<(), TestError>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: ()) -> Self::Future {
                pending()
            }
        }

        impl tower::Service<()> for PendingReadyService {
            type Response = ();
            type Error = TestError;
            type Future = std::future::Ready<Result<(), TestError>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }

            fn call(&mut self, _req: ()) -> Self::Future {
                std::future::ready(Ok(()))
            }
        }

        #[test]
        fn timeout_fallback_triggers_timeout_error() {
            crate::test_utils::init_test_logging();
            crate::test_phase!("timeout_fallback_triggers_timeout_error");

            let (cx, clock, timer) = test_cx_with_timer();
            let _guard = Cx::set_current(Some(cx.clone()));

            let config = AdapterConfig::new()
                .cancellation_mode(CancellationMode::TimeoutFallback)
                .fallback_timeout(Duration::from_millis(5));
            let adapter = AsupersyncAdapter::with_config(PendingService, config);

            let mut fut = pin!(adapter.call(&cx, ()));
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            let first = fut.as_mut().poll(&mut context);
            assert!(first.is_pending());

            clock.advance(Time::from_millis(6).as_nanos());
            let _ = timer.process_timers();

            let result = fut.as_mut().poll(&mut context);
            let timed_out = matches!(result, Poll::Ready(Err(TowerAdapterError::Timeout)));
            crate::assert_with_log!(timed_out, "timeout error", true, timed_out);
            crate::test_complete!("timeout_fallback_triggers_timeout_error");
        }

        #[test]
        fn timeout_fallback_times_out_while_waiting_for_ready() {
            crate::test_utils::init_test_logging();
            crate::test_phase!("timeout_fallback_times_out_while_waiting_for_ready");

            let (cx, clock, timer) = test_cx_with_timer();
            let _guard = Cx::set_current(Some(cx.clone()));

            let config = AdapterConfig::new()
                .cancellation_mode(CancellationMode::TimeoutFallback)
                .fallback_timeout(Duration::from_millis(5));
            let adapter = AsupersyncAdapter::with_config(PendingReadyService, config);

            let mut fut = pin!(adapter.call(&cx, ()));
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            let first = fut.as_mut().poll(&mut context);
            assert!(first.is_pending());

            clock.advance(Time::from_millis(6).as_nanos());
            let _ = timer.process_timers();

            let result = fut.as_mut().poll(&mut context);
            let timed_out = matches!(result, Poll::Ready(Err(TowerAdapterError::Timeout)));
            crate::assert_with_log!(timed_out, "readiness timeout error", true, timed_out);
            crate::test_complete!("timeout_fallback_times_out_while_waiting_for_ready");
        }

        #[test]
        fn concurrent_ready_wait_yields_on_inner_service_lock() {
            crate::test_utils::init_test_logging();
            crate::test_phase!("concurrent_ready_wait_yields_on_inner_service_lock");

            let (cx, clock, timer) = test_cx_with_timer();
            let _guard = Cx::set_current(Some(cx.clone()));

            let config = AdapterConfig::new()
                .cancellation_mode(CancellationMode::TimeoutFallback)
                .fallback_timeout(Duration::from_millis(5));
            let adapter = AsupersyncAdapter::with_config(PendingReadyService, config);

            let mut first_call = pin!(adapter.call(&cx, ()));
            let mut second_call = pin!(adapter.call(&cx, ()));
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            let first = first_call.as_mut().poll(&mut context);
            assert!(first.is_pending());

            let second = second_call.as_mut().poll(&mut context);
            assert!(
                second.is_pending(),
                "second call should yield instead of blocking on the inner service lock"
            );

            clock.advance(Time::from_millis(6).as_nanos());
            let _ = timer.process_timers();

            let first_result = first_call.as_mut().poll(&mut context);
            let first_timed_out =
                matches!(first_result, Poll::Ready(Err(TowerAdapterError::Timeout)));
            crate::assert_with_log!(first_timed_out, "first call timeout", true, first_timed_out);

            let second_result = second_call.as_mut().poll(&mut context);
            let second_timed_out =
                matches!(second_result, Poll::Ready(Err(TowerAdapterError::Timeout)));
            crate::assert_with_log!(
                second_timed_out,
                "second call timeout",
                true,
                second_timed_out
            );

            crate::test_complete!("concurrent_ready_wait_yields_on_inner_service_lock");
        }
    }

    #[test]
    fn cancellation_mode_debug_clone_copy_default_eq() {
        let m = CancellationMode::default();
        assert_eq!(m, CancellationMode::BestEffort);

        let dbg = format!("{m:?}");
        assert!(dbg.contains("BestEffort"));

        let m2 = m;
        assert_eq!(m, m2);

        let m3 = m;
        assert_eq!(m, m3);

        assert_ne!(CancellationMode::BestEffort, CancellationMode::Strict);
    }

    #[test]
    fn tower_adapter_error_debug_clone_eq() {
        let e: TowerAdapterError<String> = TowerAdapterError::Cancelled;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Cancelled"));

        let e2 = e.clone();
        assert_eq!(e, e2);

        assert_ne!(
            TowerAdapterError::<String>::Cancelled,
            TowerAdapterError::Timeout
        );
    }
