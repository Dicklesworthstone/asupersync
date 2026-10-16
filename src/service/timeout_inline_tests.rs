    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::Cx;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::future::{pending, ready};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    /// A no-op waker for testing.
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountingWaker(AtomicUsize);

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicUsize::new(0)))
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    use std::task::Wake;
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // A simple test service that returns the request
    struct EchoService;

    impl Service<i32> for EchoService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req))
        }
    }

    // A service that never completes
    struct NeverService;

    impl Service<()> for NeverService {
        type Response = ();
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<(), std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            pending()
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

    #[test]
    fn timeout_layer_creates_service() {
        let layer = TimeoutLayer::new(Duration::from_secs(5));
        let _svc: Timeout<EchoService> = layer.layer(EchoService);
    }

    #[test]
    fn timeout_accessors() {
        let timeout = Timeout::new(EchoService, Duration::from_secs(10));
        assert_eq!(timeout.timeout(), Duration::from_secs(10));
        let _ = timeout.inner();
    }

    std::thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn set_test_time(t: u64) {
        TEST_NOW.with(|now| now.set(t));
    }

    #[test]
    fn timeout_uses_time_getter_for_deadline() {
        set_test_time(1_000);
        let mut svc = Timeout::with_time_getter(EchoService, Duration::from_nanos(500), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let future = svc.call(1);
        assert_eq!(future.deadline(), Time::from_nanos(1_500));
    }

    #[test]
    fn timeout_future_poll_honors_custom_time_getter() {
        set_test_time(1_000);
        let mut svc = Timeout::with_time_getter(NeverService, Duration::from_nanos(500), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut future = svc.call(());

        let first: Poll<Result<(), TimeoutError<std::convert::Infallible>>> =
            Future::poll(Pin::new(&mut future), &mut cx);
        assert!(first.is_pending());

        set_test_time(2_000);
        let second: Poll<Result<(), TimeoutError<std::convert::Infallible>>> =
            Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(second, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_future_completes_before_deadline() {
        let mut future = TimeoutFuture::new(ready(Ok::<_, ()>(42)), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is well before deadline
        let result = future.poll_with_time(Time::from_secs(1), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(42))));
    }

    #[test]
    fn timeout_future_times_out() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is past deadline
        let result: Poll<Result<(), TimeoutError<()>>> =
            future.poll_with_time(Time::from_secs(10), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_future_pending_before_deadline() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline
        let result: Poll<Result<(), TimeoutError<()>>> =
            future.poll_with_time(Time::from_secs(5), &mut cx);
        assert!(result.is_pending());
    }

    #[test]
    fn timeout_future_poll_with_time_registers_timeout_waker() {
        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime_cx = Cx::new_with_drivers(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(runtime_cx));

        let waker = CountingWaker::new();
        let waker_handle = waker.clone();
        let task_waker: Waker = waker.into();
        let mut cx = Context::from_waker(&task_waker);

        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_millis(5));
        let first = future.poll_with_time(Time::ZERO, &mut cx);
        assert!(first.is_pending());
        assert_eq!(timer.pending_count(), 1);

        clock.advance(Time::from_millis(5).as_nanos());
        let fired = timer.process_timers();
        assert_eq!(fired, 1);
        assert!(waker_handle.count() > 0);

        let second = future.poll_with_time(Time::from_millis(5), &mut cx);
        assert!(matches!(second, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_finishes_when_custom_clock_expires_during_registration() {
        fn advancing_time() -> Time {
            TEST_NOW.with(|now| {
                let sampled = now.get();
                now.set(sampled.saturating_add(5_000_000));
                Time::from_nanos(sampled)
            })
        }

        let _guard = Cx::set_current(None);
        set_test_time(0);
        let deadline = Time::from_millis(5);
        let mut future =
            TimeoutFuture::with_time_getter(pending::<Result<(), ()>>(), deadline, advancing_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // The first clock sample is before the deadline; the Sleep registration
        // poll observes the deadline itself. That completion must not be lost.
        let result = Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(TimeoutError::Elapsed(elapsed))) if elapsed.deadline() == deadline
        ));
        assert!(matches!(
            Future::poll(Pin::new(&mut future), &mut cx),
            Poll::Ready(Err(TimeoutError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn timeout_finishes_when_driver_advances_past_explicit_time_sample() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime_cx = Cx::new_with_drivers(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(runtime_cx));
        let deadline = Time::from_millis(5);
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), deadline);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let sampled = timer.now();
        clock.advance(deadline.as_nanos());
        let result = future.poll_with_time(sampled, &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(TimeoutError::Elapsed(elapsed))) if elapsed.deadline() == deadline
        ));
        assert_eq!(timer.pending_count(), 0);
        assert!(matches!(
            future.poll_with_time(sampled, &mut cx),
            Poll::Ready(Err(TimeoutError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn timeout_owner_cancellation_preserves_cleanup_until_the_actual_deadline() {
        use crate::channel::oneshot;
        use std::sync::atomic::AtomicBool;

        struct CleanupDrop(Arc<AtomicBool>);
        impl Drop for CleanupDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // Cover default Future::poll, custom-clock Future::poll, and the
        // explicit-time registration path. Cancellation does not expire any
        // of them; cleanup can finish itself or reach the real timer bound.
        for mode in 0..3 {
            for finish_cleanup in [false, true] {
                let clock = Arc::new(VirtualClock::new());
                let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
                let runtime_cx = Cx::new_with_drivers(
                    RegionId::new_for_test(1, 0),
                    TaskId::new_for_test(1, 0),
                    Budget::INFINITE,
                    None,
                    None,
                    None,
                    Some(timer.clone()),
                    None,
                );
                let _guard = Cx::set_current(Some(runtime_cx.clone()));
                set_test_time(0);
                let deadline = Time::from_millis(5);
                let observed = Arc::new(AtomicBool::new(false));
                let dropped = Arc::new(AtomicBool::new(false));
                let (release, mut cleanup) = oneshot::channel::<()>();
                let inner_cx = runtime_cx.clone();
                let inner_observed = observed.clone();
                let inner_dropped = dropped.clone();
                let inner = Box::pin(async move {
                    let _retire = CleanupDrop(inner_dropped);
                    inner_cx.cancelled().await;
                    assert!(inner_cx.checkpoint().is_err(), "inner remains unmasked");
                    inner_observed.store(true, Ordering::SeqCst);
                    cleanup
                        .recv_uninterruptible()
                        .await
                        .expect("cleanup receipt");
                    Err::<(), _>("cancelled after cleanup")
                });
                let mut future = if mode == 1 {
                    TimeoutFuture::with_time_getter(inner, deadline, test_time)
                } else {
                    TimeoutFuture::new(inner, deadline)
                };
                let waker = CountingWaker::new();
                let task_waker = Waker::from(waker.clone());
                let mut task = Context::from_waker(&task_waker);
                let mut poll = |task: &mut Context<'_>| {
                    if mode == 2 {
                        future.poll_with_time(timer.now(), task)
                    } else {
                        Future::poll(Pin::new(&mut future), task)
                    }
                };

                assert!(poll(&mut task).is_pending());
                assert_eq!(timer.pending_count(), 1);
                let before_cancel = waker.count();
                runtime_cx.cancel_with(crate::types::CancelKind::User, Some("cancel timeout wait"));
                assert!(waker.count() > before_cancel);
                assert!(poll(&mut task).is_pending());
                assert!(observed.load(Ordering::SeqCst));
                assert!(!dropped.load(Ordering::SeqCst));
                assert_eq!(timer.now(), Time::ZERO);
                assert_eq!(timer.pending_count(), 1);

                if finish_cleanup {
                    let before_release = waker.count();
                    release.send_blocking(()).unwrap();
                    assert!(waker.count() > before_release);
                    assert!(matches!(
                        poll(&mut task),
                        Poll::Ready(Err(TimeoutError::Inner("cancelled after cleanup")))
                    ));
                } else {
                    let wakes_before = waker.count();
                    clock.advance(deadline.as_nanos());
                    set_test_time(deadline.as_nanos());
                    assert_eq!(timer.process_timers(), 1);
                    assert!(waker.count() > wakes_before);
                    assert!(matches!(
                        poll(&mut task),
                        Poll::Ready(Err(TimeoutError::Elapsed(elapsed))) if elapsed.deadline() == deadline
                    ));
                }
                assert!(dropped.load(Ordering::SeqCst));
                assert_eq!(timer.pending_count(), 0);
                assert!(matches!(
                    poll(&mut task),
                    Poll::Ready(Err(TimeoutError::PolledAfterCompletion))
                ));
            }
        }
    }

    #[test]
    fn timeout_future_boundary_prefers_ready_inner_result() {
        let mut future = TimeoutFuture::new(ready(Ok::<_, ()>(7)), Time::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = future.poll_with_time(Time::from_secs(5), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(7))));
    }

    #[test]
    fn timeout_future_poll_enforces_timeout_without_custom_time_source() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut future);

        let result: Poll<Result<(), TimeoutError<()>>> = Future::poll(pinned.as_mut(), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_service_poll_ready() {
        let mut svc = Timeout::new(EchoService, Duration::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
    }

    #[test]
    fn timeout_call_without_poll_ready_returns_not_ready() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = Timeout::new(
            CountingReadyService::new(Arc::clone(&calls)),
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = svc.call(7);
        let result = Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::NotReady))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn timeout_readiness_authorizes_only_one_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = Timeout::new(
            CountingReadyService::new(Arc::clone(&calls)),
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut first = svc.call(11);
        let first_result = Future::poll(Pin::new(&mut first), &mut cx);
        assert!(matches!(first_result, Poll::Ready(Ok(11))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut second = svc.call(12);
        let second_result = Future::poll(Pin::new(&mut second), &mut cx);
        assert!(matches!(
            second_result,
            Poll::Ready(Err(TimeoutError::NotReady))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timeout_error_display() {
        let err: TimeoutError<&str> = TimeoutError::NotReady;
        let display = format!("{err}");
        assert!(display.contains("poll_ready"));

        let err: TimeoutError<&str> = TimeoutError::PolledAfterCompletion;
        let display = format!("{err}");
        assert!(display.contains("polled after completion"));

        let err: TimeoutError<&str> = TimeoutError::Elapsed(Elapsed::new(Time::from_secs(5)));
        let display = format!("{err}");
        assert!(display.contains("timed out"));

        let err: TimeoutError<&str> = TimeoutError::Inner("inner error");
        let display = format!("{err}");
        assert!(display.contains("inner service error"));
    }

    // =========================================================================
    // Wave 49 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn timeout_layer_debug_clone_copy() {
        let layer = TimeoutLayer::new(Duration::from_secs(10));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("TimeoutLayer"), "{dbg}");
        let copied = layer;
        let cloned = layer;
        assert_eq!(copied.timeout(), cloned.timeout());
    }

    #[test]
    fn timeout_service_accessors() {
        let svc = Timeout::new(EchoService, Duration::from_secs(5));
        assert_eq!(svc.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn timeout_error_debug() {
        let err0: TimeoutError<&str> = TimeoutError::NotReady;
        let dbg0 = format!("{err0:?}");
        assert!(dbg0.contains("NotReady"), "{dbg0}");

        let err1: TimeoutError<&str> = TimeoutError::PolledAfterCompletion;
        let dbg1 = format!("{err1:?}");
        assert!(dbg1.contains("PolledAfterCompletion"), "{dbg1}");

        let err: TimeoutError<&str> = TimeoutError::Elapsed(Elapsed::new(Time::from_secs(5)));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Elapsed"), "{dbg}");
        let err2: TimeoutError<&str> = TimeoutError::Inner("fail");
        let dbg2 = format!("{err2:?}");
        assert!(dbg2.contains("Inner"), "{dbg2}");
    }

    // =========================================================================
    // Golden Conformance Tests for Budget Propagation (bead asupersync-w49ewm)
    // =========================================================================
    //
    // These tests validate timeout service conformance with asupersync's
    // structured concurrency and budget model.

    /// Test: Basic timeout service with custom time source
    ///
    /// This test verifies that timeout service works with a custom time source,
    /// which is the foundation for budget propagation.
    #[test]
    fn golden_timeout_with_custom_time_source() {
        set_test_time(1_000);
        let mut timeout_service =
            Timeout::with_time_getter(EchoService, Duration::from_nanos(500), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Service should be ready
        assert!(matches!(
            timeout_service.poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));

        // Call should succeed immediately since EchoService completes immediately
        let mut future = timeout_service.call(42);
        let result = Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(42))));
    }

    /// Test: Timeout with deadline from custom time source
    ///
    /// This test verifies that timeout service properly calculates deadline
    /// based on the custom time source, not wall clock.
    #[test]
    fn golden_timeout_deadline_from_custom_time() {
        set_test_time(2_000);
        let mut timeout_service =
            Timeout::with_time_getter(NeverService, Duration::from_nanos(1_000), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Service should be ready
        assert!(matches!(
            timeout_service.poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));

        // Call creates a future with deadline = start_time (2000) + duration (1000) = 3000
        let future = timeout_service.call(());
        assert_eq!(future.deadline(), Time::from_nanos(3_000));
    }

    /// Test: Timeout using TimeoutFuture::poll_with_time for explicit time control
    ///
    /// This test verifies that TimeoutFuture can be explicitly controlled with
    /// poll_with_time, which allows budget propagation to override wall clock.
    #[test]
    fn golden_timeout_poll_with_explicit_time() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_nanos(5_000));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Before deadline - should be pending
        let result = future.poll_with_time(Time::from_nanos(3_000), &mut cx);
        assert!(result.is_pending());

        // At deadline - should timeout
        let result = future.poll_with_time(Time::from_nanos(5_000), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    /// Test: Timeout after success is no-op
    ///
    /// This test verifies that if work completes before the timeout,
    /// the timeout becomes a no-op and doesn't interfere with the result.
    #[test]
    fn golden_timeout_after_success_is_noop() {
        let mut future = TimeoutFuture::new(ready(Ok::<_, ()>(42)), Time::from_nanos(10_000));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Future should complete immediately even if deadline is far in future
        let result = future.poll_with_time(Time::from_nanos(1_000), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(42))));
    }

    /// Test: Nested timeout inheritance
    ///
    /// This test verifies that when timeouts are nested, the inner timeout
    /// fires first if it has a shorter duration.
    #[test]
    fn golden_nested_timeout_inheritance() {
        // Create layered timeouts: outer (10s) > inner (3s) > never service.
        // The time arithmetic below operates at second scale (start + 2.5s / 3.5s
        // in nanos), so the durations must match that scale for the inner timeout
        // to fire between the two poll points.
        let inner_timeout =
            Timeout::with_time_getter(NeverService, Duration::from_secs(3), test_time);

        let mut outer_timeout =
            Timeout::with_time_getter(inner_timeout, Duration::from_secs(10), test_time);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Both services should be ready
        assert!(matches!(
            outer_timeout.poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));

        // Start the nested timeout at time 1000
        set_test_time(1_000_000_000); // 1000ms in nanos
        let mut future = outer_timeout.call(());
        let start_time = test_time();

        // Before inner timeout (at 2.5s) - should be pending
        set_test_time(start_time.as_nanos() + 2_500_000_000);
        let result = Future::poll(Pin::new(&mut future), &mut cx);
        assert!(result.is_pending());

        // After inner timeout (at 3.5s) - inner should have timed out
        set_test_time(start_time.as_nanos() + 3_500_000_000);
        let result = Future::poll(Pin::new(&mut future), &mut cx);

        // Should get a timeout error with the inner timeout's deadline. The
        // inner timeout fires first and surfaces as Elapsed; the outer timeout
        // observes that as an inner-service error, so the outer error type is
        // TimeoutError<TimeoutError<E>> with the inner Elapsed nested under Inner.
        match result {
            Poll::Ready(Err(TimeoutError::Inner(TimeoutError::Elapsed(elapsed)))) => {
                let expected_inner_deadline = start_time.saturating_add_nanos(3_000_000_000);
                assert_eq!(
                    elapsed.deadline(),
                    expected_inner_deadline,
                    "Should timeout at inner deadline (3s), not outer (10s)"
                );
            }
            other => panic!("Expected inner timeout, got: {:?}", other),
        }
    }

    /// br-asupersync-1sxucf LOW: the default Timeout passed the wall clock as
    /// a custom time getter. A `Sleep` with a custom getter cannot use the
    /// shared fallback timer, so off the runtime every request spawned a
    /// thread that polled the clock every millisecond.
    #[test]
    fn default_timeout_waits_on_the_runtime_clock_not_a_custom_getter() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for mut svc in [
            Timeout::new(NeverService, Duration::from_secs(30)),
            TimeoutLayer::new(Duration::from_secs(30)).layer(NeverService),
        ] {
            assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let future = svc.call(());
            let TimeoutFutureState::Running {
                sleep, time_getter, ..
            } = &future.state
            else {
                panic!("the call was authorized");
            };
            assert!(!sleep.has_custom_time_getter());
            assert!(time_getter.is_none());
        }

        let mut svc = Timeout::with_time_getter(NeverService, Duration::from_secs(30), test_time);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let future = svc.call(());
        let TimeoutFutureState::Running { sleep, .. } = &future.state else {
            panic!("the call was authorized");
        };
        assert!(sleep.has_custom_time_getter(), "a custom getter is kept");
    }

    /// The default Timeout still expires off the runtime: its `Sleep` now
    /// waits on the shared fallback timer.
    #[test]
    fn default_timeout_off_the_runtime_expires_through_the_shared_timer() {
        assert!(Cx::current().is_none(), "no ambient Cx");
        let mut svc = Timeout::new(NeverService, Duration::from_millis(20));
        let woken = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut future = svc.call(());
        let give_up = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = woken.count();
            match Future::poll(Pin::new(&mut future), &mut cx) {
                Poll::Ready(Err(TimeoutError::Elapsed(_))) => break,
                Poll::Ready(other) => panic!("expected Elapsed, got {other:?}"),
                Poll::Pending => {}
            }
            while woken.count() == seen {
                assert!(
                    std::time::Instant::now() < give_up,
                    "the timeout never woke its task"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Default timeouts polled off the runtime share the fallback timer's one
    /// thread instead of spawning a thread per request.
    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn default_timeouts_off_the_runtime_spawn_no_timer_thread_per_request() {
        assert!(Cx::current().is_none(), "no ambient Cx");
        let requests: u64 = 16;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut svc = Timeout::new(NeverService, Duration::from_secs(30));
        // Counters are process-global and tests run in parallel, so assert a
        // bound that one thread per request cannot meet.
        let before = crate::runtime::metrics::snapshot();
        for _ in 0..requests {
            assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let mut future = svc.call(());
            assert!(Future::poll(Pin::new(&mut future), &mut cx).is_pending());
        }
        let after = crate::runtime::metrics::snapshot();
        let spawned = after.timer_threads_spawned - before.timer_threads_spawned;
        assert!(
            spawned < requests,
            "{spawned} timer threads for {requests} requests"
        );
    }
