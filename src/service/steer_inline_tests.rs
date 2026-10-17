    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future::block_on;
    use std::future::{Ready, ready};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn abandoned_readiness_cleanup_can_reenter_both_steer_locks() {
        use super::super::readiness_tests::{ReleaseCallback, ReleaseProbe};

        let callback: ReleaseCallback = Arc::new(Mutex::new(None));
        let mut steer = Steer::new(vec![ReleaseProbe(Arc::clone(&callback))], |_: &u8| 0);
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let released = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&released);
        *callback.lock() = Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }));

        let mut pending = steer.call(1);
        let waker = noop_waker();
        assert!(Pin::new(&mut pending)
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        drop(pending);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nested_filter_cleanup_runs_after_the_steer_service_unlocks() {
        use super::super::Filter;
        use super::super::readiness_tests::{ReadyReleaseProbe, ReleaseCallback};

        let callback: ReleaseCallback = Arc::new(Mutex::new(None));
        let filter = Filter::new(ReadyReleaseProbe(Arc::clone(&callback)), |_: &u8| false);
        let mut steer = Steer::new(vec![filter], |_: &u8| 0);
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let released = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&released);
        *callback.lock() = Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }));

        let mut response = steer.call(1);
        let waker = noop_waker();
        assert!(matches!(
            Pin::new(&mut response).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(SteerError::Inner(super::super::FilterError::Rejected)))
        ));
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panicking_inner_detacher_still_unregisters_the_steer_waiter_after_unlocking() {
        use super::super::ConcurrencyLimit;
        use super::super::readiness_tests::ReleaseCallback;
        use crate::sync::{OwnedSemaphorePermit, Semaphore};

        struct PanickingDetacher;

        impl Service<u8> for PanickingDetacher {
            type Response = u8;
            type Error = &'static str;
            type Future = Ready<Result<u8, Self::Error>>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: u8) -> Self::Future {
                ready(Ok(request))
            }

            fn release_readiness(&mut self) -> super::super::ReadinessRelease {
                panic!("inner detachment panic");
            }
        }

        struct DropWake(ReleaseCallback);

        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropWake {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropWake {
            fn drop(&mut self) {
                let callback = self.0.lock().take();
                if let Some(callback) = callback {
                    callback();
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
        let mut steer = Steer::new(
            vec![ConcurrencyLimit::new(PanickingDetacher, Arc::clone(&semaphore))],
            |_: &u8| 0,
        );
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&dropped);
        let callback: ReleaseCallback = Arc::new(Mutex::new(Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }))));
        let waker = Waker::from(Arc::new(DropWake(callback)));
        let mut pending = steer.call(1);
        assert!(Pin::new(&mut pending)
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        assert_eq!(steer.waiters[0].lock().wakers.len(), 1);
        drop(waker);
        let panic = catch_unwind(AssertUnwindSafe(|| drop(pending)))
            .expect_err("inner detachment panic must propagate");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"inner detachment panic"));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(steer.waiters[0].lock().wakers.is_empty());
        assert_eq!(steer.waiters[0].lock().owners, 0);
        drop(held);
        assert!(OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_ok());
    }

    // Deterministic test services.
    #[derive(Debug, Clone)]
    struct IdService {
        id: usize,
    }

    impl Service<usize> for IdService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            ready(Ok(self.id))
        }
    }

    #[derive(Debug)]
    struct ReservingService {
        id: usize,
        available: Arc<AtomicUsize>,
        reserved: bool,
    }

    impl ReservingService {
        fn new(id: usize, available: Arc<AtomicUsize>) -> Self {
            Self {
                id,
                available,
                reserved: false,
            }
        }

        fn available(&self) -> usize {
            self.available.load(Ordering::SeqCst)
        }
    }

    impl Service<usize> for ReservingService {
        type Response = usize;
        type Error = &'static str;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.reserved {
                return Poll::Ready(Ok(()));
            }

            let available = self.available.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }

            self.available.fetch_sub(1, Ordering::SeqCst);
            self.reserved = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            if !std::mem::replace(&mut self.reserved, false) {
                return ready(Err("not ready"));
            }

            self.available.fetch_add(1, Ordering::SeqCst);
            ready(Ok(self.id))
        }
    }

    #[derive(Debug, Clone)]
    struct FailService;

    impl Service<usize> for FailService {
        type Response = usize;
        type Error = &'static str;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            ready(Err("boom"))
        }
    }

    struct PanicOnPollFuture;

    impl Future for PanicOnPollFuture {
        type Output = Result<usize, std::convert::Infallible>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("panic in future poll");
        }
    }

    #[derive(Debug, Clone)]
    struct PanicOnPollService;

    impl Service<usize> for PanicOnPollService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = PanicOnPollFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            PanicOnPollFuture
        }
    }

    #[derive(Debug, Clone)]
    struct CountingCallService {
        calls: Arc<AtomicUsize>,
    }

    impl CountingCallService {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl Service<()> for CountingCallService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(0))
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn steer_new() {
        init_test("steer_new");
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.len(), 2);
        assert!(!steer.is_empty());
        crate::test_complete!("steer_new");
    }

    #[test]
    #[should_panic(expected = "steer requires at least one service")]
    fn steer_empty_panics() {
        let svcs: Vec<IdService> = vec![];
        let _ = Steer::new(svcs, |_req: &()| 0);
    }

    #[test]
    fn steer_services_ref() {
        let svcs = vec![IdService { id: 10 }, IdService { id: 20 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.services().len(), 2);
        assert_eq!(steer.services()[0].id, 10);
    }

    #[test]
    fn steer_services_mut() {
        let svcs = vec![IdService { id: 10 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        {
            let mut guards = steer.services_mut();
            guards[0].id = 99;
        }
        assert_eq!(steer.services()[0].id, 99);
    }

    #[test]
    fn steer_debug() {
        let svcs = vec![IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        let dbg = format!("{steer:?}");
        assert!(dbg.contains("Steer"));
    }

    #[test]
    fn steer_picker_routes() {
        init_test("steer_picker_routes");
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |req: &usize| req % 2);
        let picker = &steer.picker;
        assert_eq!(picker(&0), 0);
        assert_eq!(picker(&1), 1);
        assert_eq!(picker(&2), 0);
        assert_eq!(picker(&3), 1);
        crate::test_complete!("steer_picker_routes");
    }

    #[test]
    fn steer_invalid_route_display() {
        let err: SteerError<std::io::Error> = SteerError::InvalidRoute {
            index: 5,
            service_count: 2,
        };
        let msg = format!("{err}");
        assert!(msg.contains("invalid service index 5"));
        assert!(msg.contains("service count 2"));
    }

    #[test]
    fn steer_error_inner_display() {
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("steer service error"));
    }

    #[test]
    fn steer_error_no_services_display() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(format!("{err}").contains("no services available"));
    }

    #[test]
    fn steer_error_polled_after_completion_display() {
        let err: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        assert!(format!("{err}").contains("polled after completion"));
    }

    #[test]
    fn steer_error_source() {
        use std::error::Error;
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let invalid_route: SteerError<std::io::Error> = SteerError::InvalidRoute {
            index: 5,
            service_count: 2,
        };
        assert!(invalid_route.source().is_none());

        let err2: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(err2.source().is_none());

        let err3: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        assert!(err3.source().is_none());
    }

    #[test]
    fn steer_error_debug() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoServices"));
    }

    #[test]
    fn steer_error_debug_includes_polled_after_completion() {
        let err: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    #[test]
    fn steer_call_without_outer_poll_ready_still_routes_selected_backend() {
        init_test("steer_call_without_outer_poll_ready_still_routes_selected_backend");
        let mut steer = Steer::new(vec![IdService { id: 7 }], |_: &usize| 0);
        let result = block_on(steer.call(0)).expect("selected backend should succeed");
        assert_eq!(result, 7);
        crate::test_complete!("steer_call_without_outer_poll_ready_still_routes_selected_backend");
    }

    #[test]
    fn steer_call_only_reserves_selected_backend() {
        init_test("steer_call_only_reserves_selected_backend");
        let even_available = Arc::new(AtomicUsize::new(1));
        let odd_available = Arc::new(AtomicUsize::new(1));
        let mut steer = Steer::new(
            vec![
                ReservingService::new(0, Arc::clone(&even_available)),
                ReservingService::new(1, Arc::clone(&odd_available)),
            ],
            |req: &usize| req % 2,
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = steer.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(even_available.load(Ordering::SeqCst), 1);
        assert_eq!(odd_available.load(Ordering::SeqCst), 1);

        let result = block_on(steer.call(0)).expect("selected backend should succeed");
        assert_eq!(result, 0);

        let guards = steer.services_mut();
        assert_eq!(guards[0].available(), 1);
        assert_eq!(guards[1].available(), 1);
        crate::test_complete!("steer_call_only_reserves_selected_backend");
    }

    #[test]
    fn steer_invalid_picker_index_fails_closed_without_dispatching() {
        init_test("steer_invalid_picker_index_fails_closed_without_dispatching");
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let mut steer = Steer::new(
            vec![
                CountingCallService::new(Arc::clone(&first_calls)),
                CountingCallService::new(Arc::clone(&second_calls)),
            ],
            |(): &()| 5,
        );

        let result = block_on(steer.call(()));
        assert!(matches!(
            result,
            Err(SteerError::InvalidRoute {
                index: 5,
                service_count: 2
            })
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 0);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
        crate::test_complete!("steer_invalid_picker_index_fails_closed_without_dispatching");
    }

    #[test]
    fn steer_selected_route_is_not_blocked_by_other_backends() {
        init_test("steer_selected_route_is_not_blocked_by_other_backends");
        let blocked_available = Arc::new(AtomicUsize::new(0));
        let ready_available = Arc::new(AtomicUsize::new(1));
        let mut steer = Steer::new(
            vec![
                ReservingService::new(0, Arc::clone(&blocked_available)),
                ReservingService::new(1, Arc::clone(&ready_available)),
            ],
            |req: &usize| req % 2,
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = steer.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let result = block_on(steer.call(1)).expect("ready route should succeed");
        assert_eq!(result, 1);
        assert_eq!(blocked_available.load(Ordering::SeqCst), 0);
        assert_eq!(ready_available.load(Ordering::SeqCst), 1);
        crate::test_complete!("steer_selected_route_is_not_blocked_by_other_backends");
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_success() {
        let mut future = Steer::new(vec![IdService { id: 7 }], |_: &usize| 0).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(7))));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_inner_error() {
        let mut future = Steer::new(vec![FailService], |_: &usize| 0).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(SteerError::Inner("boom")))));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_invalid_route() {
        let mut future = Steer::new(vec![IdService { id: 7 }], |_: &usize| 3).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            first,
            Poll::Ready(Err(SteerError::InvalidRoute {
                index: 3,
                service_count: 1
            }))
        ));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_missing_request_fails_closed() {
        let mut future = SteerFuture::new(
            Arc::new(Mutex::new(IdService { id: 7 })),
            Arc::default(),
            0usize,
        );
        if let SteerState::PollReady { request, .. } = &mut future.state {
            *request = None;
        }
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            first,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_inner_panic_fails_closed() {
        init_test("steer_future_inner_panic_fails_closed");
        let mut future = SteerFuture::<PanicOnPollService, usize> {
            state: SteerState::<PanicOnPollService, usize>::Calling {
                future: PanicOnPollFuture,
            },
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut future).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
        crate::test_complete!("steer_future_inner_panic_fails_closed");
    }

    /// A backend that, like RateLimit or the ConcurrencyLimit semaphore,
    /// keeps only the latest waker passed to `poll_ready`.
    struct LatestWakerGate {
        open: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl Service<usize> for LatestWakerGate {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.open.load(Ordering::SeqCst) {
                return Poll::Ready(Ok(()));
            }
            *self.waker.lock() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn call(&mut self, req: usize) -> Self::Future {
            ready(Ok(req))
        }
    }

    struct CountingWaker(AtomicUsize);

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn assert_other_waiter_woken(drop_instead_of_dispatch: bool) {
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_waker = Arc::new(Mutex::new(None));
        let mut steer = Steer::new(
            vec![LatestWakerGate {
                open: Arc::clone(&open),
                waker: Arc::clone(&gate_waker),
            }],
            |_: &usize| 0,
        );
        let mut first = steer.call(1);
        let mut second = steer.call(2);
        let first_wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let second_wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        assert!(
            Pin::new(&mut first)
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        // The gate now holds only the second future's waker.
        assert!(
            Pin::new(&mut second)
                .poll(&mut Context::from_waker(&second_waker))
                .is_pending()
        );

        open.store(true, Ordering::SeqCst);
        gate_waker.lock().take().expect("gate waker").wake();
        assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
        if drop_instead_of_dispatch {
            drop(second);
        } else {
            let done = Pin::new(&mut second).poll(&mut Context::from_waker(&second_waker));
            assert!(matches!(done, Poll::Ready(Ok(2))));
        }
        assert_eq!(
            first_wakes.0.load(Ordering::SeqCst),
            1,
            "the first future must be woken to re-poll the backend"
        );
        let done = Pin::new(&mut first).poll(&mut Context::from_waker(&first_waker));
        assert!(matches!(done, Poll::Ready(Ok(1))));
    }

    #[test]
    fn a_waiter_is_woken_when_another_dispatches_to_its_backend() {
        init_test("a_waiter_is_woken_when_another_dispatches_to_its_backend");
        assert_other_waiter_woken(false);
        crate::test_complete!("a_waiter_is_woken_when_another_dispatches_to_its_backend");
    }

    #[test]
    fn a_waiter_is_woken_when_another_waiting_future_is_dropped() {
        init_test("a_waiter_is_woken_when_another_waiting_future_is_dropped");
        assert_other_waiter_woken(true);
        crate::test_complete!("a_waiter_is_woken_when_another_waiting_future_is_dropped");
    }
