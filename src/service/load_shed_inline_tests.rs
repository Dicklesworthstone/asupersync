    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::future::ready;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    // A service that is always ready
    struct ReadyService;

    impl Service<i32> for ReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req * 2))
        }
    }

    // A service that is never ready (backpressure)
    struct NeverReadyService;

    impl Service<i32> for NeverReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            std::future::pending()
        }
    }

    struct ToggleReadyService {
        ready: bool,
    }

    impl Service<i32> for ToggleReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req))
        }
    }

    struct SelfWakeReadyService {
        armed: bool,
    }

    impl Service<i32> for SelfWakeReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.armed {
                Poll::Ready(Ok(()))
            } else {
                self.armed = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req + 1))
        }
    }

    #[derive(Clone)]
    struct CountingReadyService {
        calls: Arc<AtomicUsize>,
    }

    impl CountingReadyService {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl Service<i32> for CountingReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(req))
        }
    }

    struct PanicOnPollFuture;

    impl std::future::Future for PanicOnPollFuture {
        type Output = Result<i32, std::convert::Infallible>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<<Self as std::future::Future>::Output> {
            panic!("panic in load shed future poll");
        }
    }

    struct PanicOnPollService;

    impl Service<i32> for PanicOnPollService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = PanicOnPollFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            PanicOnPollFuture
        }
    }

    #[test]
    fn load_shed_layer_creates_service() {
        init_test("load_shed_layer_creates_service");
        let layer = LoadShedLayer::new();
        let _svc: LoadShed<ReadyService> = layer.layer(ReadyService);
        crate::test_complete!("load_shed_layer_creates_service");
    }

    #[test]
    fn load_shed_passes_through_when_ready() {
        init_test("load_shed_passes_through_when_ready");
        let mut svc = LoadShed::new(ReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready should succeed
        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(!overloaded, "not overloaded", false, overloaded);

        // call should succeed
        let mut future = svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(ok, "call ok", true, ok);
        crate::test_complete!("load_shed_passes_through_when_ready");
    }

    #[test]
    fn load_shed_call_without_poll_ready_returns_not_ready() {
        init_test("load_shed_call_without_poll_ready_returns_not_ready");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "call without poll_ready fails closed",
            true,
            not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 0,
            "inner service not invoked on readiness misuse",
            0,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn load_shed_sheds_when_not_ready() {
        init_test("load_shed_sheds_when_not_ready");
        let mut svc = LoadShed::new(NeverReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready should return Ready (even though inner is pending)
        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overloaded", true, overloaded);

        // call should return overloaded error
        let mut future = svc.call(42);
        let result = Pin::new(&mut future).poll(&mut cx);
        let overloaded = matches!(result, Poll::Ready(Err(LoadShedError::Overloaded(_))));
        crate::assert_with_log!(overloaded, "overloaded error", true, overloaded);
        crate::test_complete!("load_shed_sheds_when_not_ready");
    }

    #[test]
    fn load_shed_recovers_after_shed() {
        init_test("load_shed_recovers_after_shed");
        let mut svc = LoadShed::new(NeverReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Trigger overload
        let _ = svc.poll_ready(&mut cx);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overloaded", true, overloaded);

        // Shed a request
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // Overloaded flag should remain set until poll_ready observes readiness.
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overload persists", true, overloaded);
        crate::test_complete!("load_shed_recovers_after_shed");
    }

    #[test]
    fn load_shed_keeps_shedding_until_ready_again() {
        init_test("load_shed_keeps_shedding_until_ready_again");
        let mut svc = LoadShed::new(ToggleReadyService { ready: false });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok while overloaded", true, ok);

        let mut first = svc.call(1);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_overloaded =
            matches!(first_result, Poll::Ready(Err(LoadShedError::Overloaded(_))));
        crate::assert_with_log!(
            first_overloaded,
            "first call overloaded",
            true,
            first_overloaded
        );

        let ready = svc.poll_ready(&mut cx);
        let second_ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            second_ready_ok,
            "repoll while still overloaded re-arms one shed",
            true,
            second_ready_ok
        );

        let mut second = svc.call(2);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_overloaded = matches!(
            second_result,
            Poll::Ready(Err(LoadShedError::Overloaded(_)))
        );
        crate::assert_with_log!(
            second_overloaded,
            "second call still overloaded",
            true,
            second_overloaded
        );

        svc.inner_mut().ready = true;
        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "ready once inner recovers", true, ready_ok);

        let mut success = svc.call(99);
        let success_result = Pin::new(&mut success).poll(&mut cx);
        let success_ok = matches!(success_result, Poll::Ready(Ok(99)));
        crate::assert_with_log!(success_ok, "call succeeds after recovery", true, success_ok);
        crate::test_complete!("load_shed_keeps_shedding_until_ready_again");
    }

    #[test]
    fn load_shed_preserves_same_turn_self_wake_readiness() {
        init_test("load_shed_preserves_same_turn_self_wake_readiness");
        let mut svc = LoadShed::new(SelfWakeReadyService { armed: false });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "ready after self-wake repoll", true, ready_ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(
            !overloaded,
            "self-wake readiness does not leave overload armed",
            false,
            overloaded
        );

        let mut future = svc.call(41);
        let result = Pin::new(&mut future).poll(&mut cx);
        let success = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(
            success,
            "immediate follow-up call succeeds after self-wake",
            true,
            success
        );
        crate::test_complete!("load_shed_preserves_same_turn_self_wake_readiness");
    }

    #[test]
    fn load_shed_ready_window_is_consumed_by_call() {
        init_test("load_shed_ready_window_is_consumed_by_call");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);

        let mut first = svc.call(7);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_ok = matches!(first_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call succeeds", true, first_ok);

        let mut second = svc.call(8);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_not_ready = matches!(second_result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            second_not_ready,
            "second call without repoll fails closed",
            true,
            second_not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 1,
            "only the authorized call reaches the inner service",
            1,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_ready_window_is_consumed_by_call");
    }

    #[test]
    fn load_shed_clone_does_not_inherit_ready_window() {
        init_test("load_shed_clone_does_not_inherit_ready_window");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "original service ready", true, ready_ok);

        let mut cloned = svc.clone();
        let mut future = cloned.call(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "clone requires its own readiness observation",
            true,
            not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 0,
            "clone misuse does not invoke inner service",
            0,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_clone_does_not_inherit_ready_window");
    }

    #[test]
    fn load_shed_reuses_its_probe_waker_while_shedding_over_a_full_buffer() {
        init_test("load_shed_reuses_its_probe_waker_while_shedding_over_a_full_buffer");
        struct CountWakes(Arc<AtomicUsize>);
        impl std::task::Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let buffer = crate::service::Buffer::new(ReadyService, 1);
        let mut holder = buffer.clone();
        let noop = noop_waker();
        let held = Service::<i32>::poll_ready(&mut holder, &mut Context::from_waker(&noop));
        assert!(
            matches!(held, Poll::Ready(Ok(()))),
            "the holder reserves the only slot"
        );

        let mut shed = LoadShed::new(buffer);
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWakes(Arc::clone(&wakes))));
        let mut cx = Context::from_waker(&waker);
        for _ in 0..100 {
            let ready = Service::<i32>::poll_ready(&mut shed, &mut cx);
            assert!(
                matches!(ready, Poll::Ready(Ok(()))),
                "the shedder stays ready"
            );
            assert!(shed.is_overloaded(), "a full buffer is shed");
        }

        // Releasing the slot wakes each distinct waker the buffer queued. The
        // shedder releases its wait whenever it sheds (an idle handle must not
        // keep a queue position, br-asupersync-wfch0u), and it never parks, so
        // at most one wake is owed: what this guards is one waker per shed
        // request, a hundred here.
        drop(holder);
        crate::assert_with_log!(
            wakes.load(Ordering::SeqCst) <= 1,
            "one task polling 100 times is queued, and woken, at most once",
            "<= 1",
            wakes.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_reuses_its_probe_waker_while_shedding_over_a_full_buffer");
    }

    #[test]
    fn overloaded_error_display() {
        init_test("overloaded_error_display");
        let err = Overloaded::new();
        let display = format!("{err}");
        let has_overloaded = display.contains("overloaded");
        crate::assert_with_log!(has_overloaded, "contains overloaded", true, has_overloaded);
        crate::test_complete!("overloaded_error_display");
    }

    #[test]
    fn load_shed_error_display() {
        init_test("load_shed_error_display");
        let err: LoadShedError<&str> = LoadShedError::NotReady;
        let display = format!("{err}");
        let has_not_ready = display.contains("poll_ready required");
        crate::assert_with_log!(has_not_ready, "not ready", true, has_not_ready);

        let err: LoadShedError<&str> = LoadShedError::PolledAfterCompletion;
        let display = format!("{err}");
        let has_polled_after_completion = display.contains("polled after completion");
        crate::assert_with_log!(
            has_polled_after_completion,
            "polled-after-completion",
            true,
            has_polled_after_completion
        );

        let err: LoadShedError<&str> = LoadShedError::Overloaded(Overloaded::new());
        let display = format!("{err}");
        let has_overloaded = display.contains("overloaded");
        crate::assert_with_log!(has_overloaded, "overloaded", true, has_overloaded);

        let err: LoadShedError<&str> = LoadShedError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("load_shed_error_display");
    }

    // =========================================================================
    // Wave 28: Data-type trait coverage
    // =========================================================================

    #[test]
    fn load_shed_layer_debug_clone_copy_default() {
        let layer = LoadShedLayer::new();
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("LoadShedLayer"));

        let cloned = layer;
        let _ = format!("{cloned:?}");

        let copied = layer; // Copy
        let _ = format!("{copied:?}");

        let default = LoadShedLayer;
        let _ = format!("{default:?}");
    }

    #[test]
    fn load_shed_debug() {
        let svc = LoadShed::new(42_i32);
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("LoadShed"));
        assert!(dbg.contains("overloaded"));
    }

    #[test]
    fn load_shed_into_inner() {
        let svc = LoadShed::new(42_i32);
        let inner = svc.into_inner();
        assert_eq!(inner, 42);
    }

    #[test]
    fn load_shed_inner_accessor() {
        let svc = LoadShed::new(99_i32);
        assert_eq!(*svc.inner(), 99);
    }

    #[test]
    fn overloaded_debug_clone_copy() {
        let err = Overloaded::new();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Overloaded"));

        let cloned = err;
        assert_eq!(err, cloned);

        let copied = err; // Copy
        assert_eq!(copied, Overloaded::new());
    }

    #[test]
    fn overloaded_default() {
        let err = Overloaded::default();
        assert_eq!(err, Overloaded::new());
    }

    #[test]
    fn overloaded_is_std_error() {
        let err: &dyn std::error::Error = &Overloaded::new();
        let _ = format!("{err}");
        let _ = format!("{err:?}");
        assert!(err.source().is_none());
    }

    #[test]
    fn load_shed_error_debug_all_variants() {
        let not_ready: LoadShedError<String> = LoadShedError::NotReady;
        let dbg = format!("{not_ready:?}");
        assert!(dbg.contains("NotReady"));

        let done: LoadShedError<String> = LoadShedError::PolledAfterCompletion;
        let dbg = format!("{done:?}");
        assert!(dbg.contains("PolledAfterCompletion"));

        let overloaded: LoadShedError<String> = LoadShedError::Overloaded(Overloaded::new());
        let dbg = format!("{overloaded:?}");
        assert!(dbg.contains("Overloaded"));

        let inner: LoadShedError<String> = LoadShedError::Inner("fail".to_string());
        let dbg = format!("{inner:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn load_shed_error_source() {
        use std::io;
        let not_ready: LoadShedError<io::Error> = LoadShedError::NotReady;
        let err: &dyn std::error::Error = &not_ready;
        assert!(err.source().is_none());

        let done: LoadShedError<io::Error> = LoadShedError::PolledAfterCompletion;
        let err: &dyn std::error::Error = &done;
        assert!(err.source().is_none());

        let overloaded: LoadShedError<io::Error> = LoadShedError::Overloaded(Overloaded::new());
        let err: &dyn std::error::Error = &overloaded;
        assert!(err.source().is_some()); // Overloaded implements Error

        let inner: LoadShedError<io::Error> = LoadShedError::Inner(io::Error::other("test"));
        let err: &dyn std::error::Error = &inner;
        assert!(err.source().is_some());
    }

    #[test]
    fn load_shed_future_debug() {
        let fut =
            LoadShedFuture::<std::future::Ready<Result<(), std::convert::Infallible>>>::overloaded(
            );
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("LoadShedFuture"));
    }

    #[test]
    fn load_shed_future_second_poll_fails_closed() {
        init_test("load_shed_future_second_poll_fails_closed");
        let mut fut =
            LoadShedFuture::<std::future::Ready<Result<(), std::convert::Infallible>>>::not_ready();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        let first_not_ready = matches!(first, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            first_not_ready,
            "first poll not ready",
            true,
            first_not_ready
        );

        let second = Pin::new(&mut fut).poll(&mut cx);
        let second_done = matches!(
            second,
            Poll::Ready(Err(LoadShedError::PolledAfterCompletion))
        );
        crate::assert_with_log!(second_done, "second poll fails closed", true, second_done);
        crate::test_complete!("load_shed_future_second_poll_fails_closed");
    }

    #[test]
    fn load_shed_future_inner_panic_fails_closed() {
        init_test("load_shed_future_inner_panic_fails_closed");
        let mut svc = LoadShed::new(PanicOnPollService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut fut = svc.call(3);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(LoadShedError::PolledAfterCompletion))
        ));
        crate::test_complete!("load_shed_future_inner_panic_fails_closed");
    }
