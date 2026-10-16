    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    // ================================================================
    // FilterLayer
    // ================================================================

    #[test]
    fn filter_layer_new() {
        init_test("filter_layer_new");
        let layer = FilterLayer::new(true);
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("FilterLayer"));
        crate::test_complete!("filter_layer_new");
    }

    #[test]
    fn filter_layer_clone() {
        let layer = FilterLayer::new(true);
        let cloned = layer.clone();
        assert!(cloned.predicate);
        assert!(layer.predicate);
    }

    // ================================================================
    // Filter
    // ================================================================

    #[derive(Debug, Clone)]
    struct MockSvc;

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
            std::future::ready(Ok(req))
        }
    }

    #[derive(Clone)]
    struct StrictReservingService {
        ready_polls: Arc<AtomicUsize>,
        available: Arc<AtomicUsize>,
        reserved: bool,
    }

    impl StrictReservingService {
        fn new(ready_polls: Arc<AtomicUsize>, available: Arc<AtomicUsize>) -> Self {
            Self {
                ready_polls,
                available,
                reserved: false,
            }
        }
    }

    impl Service<i32> for StrictReservingService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, Self::Error>>;

        fn release_readiness(&mut self) -> super::super::ReadinessRelease {
            if !std::mem::replace(&mut self.reserved, false) {
                return super::super::ReadinessRelease::default();
            }
            let available = Arc::clone(&self.available);
            super::super::ReadinessRelease::new(move || {
                available.fetch_add(1, Ordering::SeqCst);
            })
        }

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready_polls.fetch_add(1, Ordering::SeqCst);

            if self.reserved {
                return Poll::Pending;
            }

            let available = self.available.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }

            self.available.fetch_sub(1, Ordering::SeqCst);
            self.reserved = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            if !std::mem::replace(&mut self.reserved, false) {
                return std::future::ready(Err("not ready"));
            }

            self.available.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(req))
        }
    }

    #[derive(Clone)]
    struct PanicOnPollService;

    struct PanicOnPollFuture;

    impl std::future::Future for PanicOnPollFuture {
        type Output = Result<i32, std::convert::Infallible>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<<Self as std::future::Future>::Output> {
            panic!("panic in filter future poll");
        }
    }

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
    fn filter_new() {
        init_test("filter_new");
        let filter = Filter::new(MockSvc, |(): &()| true);
        let _ = filter.inner();
        let _ = filter.predicate();
        crate::test_complete!("filter_new");
    }

    #[test]
    fn filter_inner_mut() {
        let mut filter = Filter::new(42u32, |(): &()| true);
        *filter.inner_mut() = 99;
        assert_eq!(*filter.inner(), 99);
    }

    #[test]
    fn filter_debug() {
        let filter = Filter::new(MockSvc, |(): &()| true);
        let dbg = format!("{filter:?}");
        assert!(dbg.contains("Filter"));
    }

    #[test]
    fn filter_clone() {
        let filter = Filter::new(MockSvc, true);
        let cloned = filter.clone();
        assert!(cloned.predicate);
        assert!(filter.predicate);
    }

    #[test]
    fn filter_predicate_accepts() {
        init_test("filter_predicate_accepts");
        let pred = |x: &i32| *x > 0;
        assert!(pred(&5));
        assert!(!pred(&-1));
        crate::test_complete!("filter_predicate_accepts");
    }

    #[test]
    fn filter_layer_applies() {
        init_test("filter_layer_applies");
        let layer = FilterLayer::new(|(): &()| true);
        let filter = layer.layer(MockSvc);
        let _ = filter.inner();
        crate::test_complete!("filter_layer_applies");
    }

    #[test]
    fn filter_call_without_poll_ready_returns_not_ready() {
        init_test("filter_call_without_poll_ready_returns_not_ready");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = filter.call(7);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn filter_rejected_call_without_poll_ready_returns_rejected() {
        init_test("filter_rejected_call_without_poll_ready_returns_rejected");
        let ready_polls = Arc::new(AtomicUsize::new(0));
        let available = Arc::new(AtomicUsize::new(0));
        let inner = StrictReservingService::new(Arc::clone(&ready_polls), Arc::clone(&available));
        let mut filter = Filter::new(inner, |x: &i32| *x > 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut rejected = filter.call(-7);
        let rejected_result = Pin::new(&mut rejected).poll(&mut cx);
        let rejected_ok = matches!(rejected_result, Poll::Ready(Err(FilterError::Rejected)));
        crate::assert_with_log!(
            rejected_ok,
            "rejected request short-circuits without poll_ready",
            true,
            rejected_ok
        );
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 0,
            "rejected request never polls inner readiness",
            0,
            ready_polls.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 0,
            "inner backpressure state remains untouched",
            0,
            available.load(Ordering::SeqCst)
        );

        let mut accepted = filter.call(7);
        let accepted_result = Pin::new(&mut accepted).poll(&mut cx);
        let accepted_not_ready = matches!(accepted_result, Poll::Ready(Err(FilterError::NotReady)));
        crate::assert_with_log!(
            accepted_not_ready,
            "accepted requests still require an explicit readiness observation",
            true,
            accepted_not_ready
        );
        crate::test_complete!("filter_rejected_call_without_poll_ready_returns_rejected");
    }

    #[test]
    fn filter_ready_window_is_consumed_by_call() {
        init_test("filter_ready_window_is_consumed_by_call");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);

        let mut first = filter.call(7);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_ok = matches!(first_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call succeeds", true, first_ok);

        let mut second = filter.call(8);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_not_ready = matches!(second_result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_ready_window_is_consumed_by_call");
    }

    #[test]
    fn filter_clone_does_not_inherit_ready_window() {
        init_test("filter_clone_does_not_inherit_ready_window");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "original filter ready", true, ready_ok);

        let mut cloned = filter.clone();
        let mut future = cloned.call(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_clone_does_not_inherit_ready_window");
    }

    #[test]
    fn rejected_request_releases_capacity_and_requires_fresh_readiness() {
        init_test("rejected_request_releases_capacity_and_requires_fresh_readiness");
        let ready_polls = Arc::new(AtomicUsize::new(0));
        let available = Arc::new(AtomicUsize::new(1));
        let inner = StrictReservingService::new(Arc::clone(&ready_polls), Arc::clone(&available));
        let mut filter = Filter::new(inner, |x: &i32| *x > 10);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 1,
            "inner poll_ready called once to reserve capacity",
            1,
            ready_polls.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 0,
            "inner reservation consumes the only available slot",
            0,
            available.load(Ordering::SeqCst)
        );

        let mut rejected = filter.call(7);
        let rejected_result = Pin::new(&mut rejected).poll(&mut cx);
        let rejected_ok = matches!(rejected_result, Poll::Ready(Err(FilterError::Rejected)));
        crate::assert_with_log!(
            rejected_ok,
            "request rejected by predicate",
            true,
            rejected_ok
        );

        assert_eq!(
            available.load(Ordering::SeqCst),
            1,
            "a rejected request returns capacity while its handle remains alive"
        );
        let mut unready = filter.call(11);
        assert!(matches!(
            Pin::new(&mut unready).poll(&mut cx),
            Poll::Ready(Err(FilterError::NotReady))
        ));

        let ready_again = filter.poll_ready(&mut cx);
        let ready_again_ok = matches!(ready_again, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            ready_again_ok,
            "a fresh readiness window is acquired after rejection",
            true,
            ready_again_ok
        );
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 2,
            "re-poll must reserve the inner service again",
            2,
            ready_polls.load(Ordering::SeqCst)
        );

        let mut accepted = filter.call(11);
        let accepted_result = Pin::new(&mut accepted).poll(&mut cx);
        let accepted_ok = matches!(accepted_result, Poll::Ready(Ok(11)));
        crate::assert_with_log!(
            accepted_ok,
            "accepted follow-up request consumes the new readiness window",
            true,
            accepted_ok
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 1,
            "inner reservation is released once an accepted request reaches the service",
            1,
            available.load(Ordering::SeqCst)
        );

        let mut third = filter.call(12);
        let third_result = Pin::new(&mut third).poll(&mut cx);
        let third_not_ready = matches!(third_result, Poll::Ready(Err(FilterError::NotReady)));
        crate::assert_with_log!(
            third_not_ready,
            "accepted request consumes the new readiness ticket",
            true,
            third_not_ready
        );
        crate::test_complete!("rejected_request_releases_capacity_and_requires_fresh_readiness");
    }

    // ================================================================
    // FilterError
    // ================================================================

    #[test]
    fn filter_error_rejected_display() {
        let err: FilterError<std::io::Error> = FilterError::Rejected;
        assert!(format!("{err}").contains("request rejected by filter"));
    }

    #[test]
    fn filter_error_polled_after_completion_display() {
        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        assert!(format!("{err}").contains("polled after completion"));
    }

    #[test]
    fn filter_error_not_ready_display() {
        let err: FilterError<std::io::Error> = FilterError::NotReady;
        assert!(format!("{err}").contains("poll_ready required"));
    }

    #[test]
    fn filter_error_inner_display() {
        let err: FilterError<std::io::Error> = FilterError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn filter_error_source() {
        use std::error::Error;
        let err: FilterError<std::io::Error> = FilterError::NotReady;
        assert!(err.source().is_none());

        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        assert!(err.source().is_none());

        let err: FilterError<std::io::Error> = FilterError::Rejected;
        assert!(err.source().is_none());

        let err2: FilterError<std::io::Error> = FilterError::Inner(std::io::Error::other("fail"));
        assert!(err2.source().is_some());
    }

    #[test]
    fn filter_error_debug() {
        let err: FilterError<std::io::Error> = FilterError::Rejected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Rejected"));
    }

    #[test]
    fn filter_error_polled_after_completion_debug() {
        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    // ================================================================
    // FilterFuture
    // ================================================================

    #[test]
    fn filter_future_inner_debug() {
        let fut = FilterFuture::inner(std::future::ready(Ok::<i32, ()>(42)));
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn filter_future_not_ready_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::not_ready();
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("NotReady"));
    }

    #[test]
    fn filter_future_rejected_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::rejected();
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Rejected"));
    }

    #[test]
    fn filter_future_not_ready_repoll_fails_closed() {
        let mut fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::not_ready();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(FilterError::NotReady))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_rejected_repoll_fails_closed() {
        let mut fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::rejected();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(FilterError::Rejected))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_inner_repoll_fails_closed() {
        let mut fut = FilterFuture::inner(std::future::ready(Ok::<i32, ()>(42)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_inner_panic_fails_closed() {
        init_test("filter_future_inner_panic_fails_closed");
        let mut filter = Filter::new(PanicOnPollService, |_: &i32| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut fut = filter.call(7);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
        crate::test_complete!("filter_future_inner_panic_fails_closed");
    }
