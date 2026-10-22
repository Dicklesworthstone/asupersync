    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::future::ready;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Weak};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct ReentrantRateLimitWaker {
        state: Weak<Mutex<SharedRateLimitState>>,
        wakes: Arc<AtomicUsize>,
        unlocked_wakes: Arc<AtomicUsize>,
    }

    impl Wake for ReentrantRateLimitWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            if let Some(state) = self.state.upgrade()
                && state.try_lock().is_some()
            {
                self.unlocked_wakes.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn reentrant_rate_limit_waker(
        state: &Arc<Mutex<SharedRateLimitState>>,
    ) -> (Waker, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        let unlocked_wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(ReentrantRateLimitWaker {
            state: Arc::downgrade(state),
            wakes: Arc::clone(&wakes),
            unlocked_wakes: Arc::clone(&unlocked_wakes),
        }));
        (waker, wakes, unlocked_wakes)
    }

    struct RateLimitWakerDropProbe {
        state: Weak<Mutex<SharedRateLimitState>>,
        drops: Arc<AtomicUsize>,
        unlocked_drops: Arc<AtomicUsize>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl Wake for RateLimitWakerDropProbe {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for RateLimitWakerDropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if let Some(state) = self.state.upgrade()
                && state.try_lock().is_some()
            {
                self.unlocked_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn rate_limit_waker_drop_probe(
        state: &Arc<Mutex<SharedRateLimitState>>,
    ) -> (Waker, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        let unlocked_drops = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(RateLimitWakerDropProbe {
            state: Arc::downgrade(state),
            drops: Arc::clone(&drops),
            unlocked_drops: Arc::clone(&unlocked_drops),
        }));
        (waker, drops, unlocked_drops)
    }

    struct PanickingRateLimitWaker {
        wakes: Arc<AtomicUsize>,
    }

    impl Wake for PanickingRateLimitWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            panic!("hostile rate-limit wake");
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            panic!("hostile rate-limit wake-by-ref");
        }
    }

    struct PanickingDropRateLimitWaker {
        drops: Arc<AtomicUsize>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl Wake for PanickingDropRateLimitWaker {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for PanickingDropRateLimitWaker {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            panic!("hostile rate-limit Waker destructor");
        }
    }

    #[derive(Clone, Copy)]
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

    struct ToggleReadyService {
        ready: Arc<AtomicBool>,
        error: bool,
    }

    impl ToggleReadyService {
        fn new(ready: Arc<AtomicBool>, error: bool) -> Self {
            Self { ready, error }
        }
    }

    impl Service<()> for ToggleReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.error {
                Poll::Ready(Err("inner error"))
            } else if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct PanicOnCallService;

    impl Service<()> for PanicOnCallService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            panic!("panic while constructing rate-limited future");
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct PanicOnPollReadyService;

    impl Service<()> for PanicOnPollReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            panic!("panic while probing inner readiness");
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ReadyThenErrorService {
        returned_ready_once: bool,
    }

    impl Service<()> for ReadyThenErrorService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.returned_ready_once {
                Poll::Ready(Err("inner error"))
            } else {
                self.returned_ready_once = true;
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    std::thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn ready_sleep_time() -> Time {
        Time::from_nanos(u64::MAX)
    }

    fn set_test_time(t: u64) {
        TEST_NOW.with(|now| now.set(t));
    }

    fn set_bucket_state<S>(svc: &RateLimit<S>, tokens: u64, last_refill: Option<Time>) {
        let mut state = svc.state.lock();
        state.tokens = tokens;
        state.last_refill = last_refill;
    }

    fn install_test_waiter<S>(svc: &mut RateLimit<S>, waker: &Waker) -> RateLimitWaiterHandle {
        let registration = RegisteredRateLimitWaker::new(waker);
        let handle = {
            let mut state = svc.state.lock();
            state.waiters.reserve(1);
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let slot = state.waiters.insert(RateLimitWaiter {
                id,
                registration: Arc::clone(&registration),
            });
            RateLimitWaiterHandle { slot, id }
        };
        svc.reservations.waiter = Some(handle);
        handle
    }

    #[test]
    fn layer_creates_service() {
        init_test("layer_creates_service");
        let layer = RateLimitLayer::new(10, Duration::from_secs(1));
        let rate = layer.rate();
        crate::assert_with_log!(rate == 10, "rate", 10, rate);
        let period = layer.period();
        crate::assert_with_log!(
            period == Duration::from_secs(1),
            "period",
            Duration::from_secs(1),
            period
        );
        let _svc: RateLimit<EchoService> = layer.layer(EchoService);
        crate::test_complete!("layer_creates_service");
    }

    #[test]
    fn service_starts_with_full_bucket() {
        init_test("service_starts_with_full_bucket");
        let svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 5, "available", 5, available);
        crate::test_complete!("service_starts_with_full_bucket");
    }

    #[test]
    fn tokens_consumed_on_ready() {
        init_test("tokens_consumed_on_ready");
        let mut svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Each poll_ready → call cycle should consume a token from the shared bucket.
        for expected in (1..=5).rev() {
            let result = svc.poll_ready(&mut cx);
            let ok = matches!(result, Poll::Ready(Ok(())));
            crate::assert_with_log!(ok, "ready ok", true, ok);
            let available = svc.available_tokens();
            crate::assert_with_log!(
                available == expected - 1,
                "available",
                expected - 1,
                available
            );
            // Consume the reservation so the next poll_ready can acquire a fresh token.
            let mut future = svc.call(42);
            let _ = Pin::new(&mut future).poll(&mut cx);
        }
        crate::test_complete!("tokens_consumed_on_ready");
    }

    #[test]
    fn pending_when_no_tokens() {
        init_test("pending_when_no_tokens");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll_ready + call cycle consumes the sole token.
        let result = svc.poll_ready(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "first ready", true, ok);
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // Second poll_ready should be pending (no tokens left in shared bucket).
        let result = svc.poll_ready(&mut cx);
        let pending = result.is_pending();
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::test_complete!("pending_when_no_tokens");
    }

    #[test]
    fn exhausted_bucket_does_not_spin_in_a_cancelled_task() {
        init_test("exhausted_bucket_does_not_spin_in_a_cancelled_task");
        struct CountWakes(AtomicUsize);
        impl Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let current = crate::cx::Cx::for_testing();
        let _current = crate::cx::Cx::set_current(Some(current.clone()));
        current.cancel_with(crate::types::CancelKind::User, Some("caller gave up"));

        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(3600));
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // The refill is an hour away. The cancel-aware Sleep completed at once
        // in this cancelled task, so each poll woke the task again: a spin.
        for _ in 0..3 {
            assert!(svc.poll_ready(&mut cx).is_pending());
        }
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            0,
            "an exhausted bucket must not wake its task before the refill"
        );
        crate::test_complete!("exhausted_bucket_does_not_spin_in_a_cancelled_task");
    }

    #[test]
    fn inner_pending_does_not_consume_token() {
        init_test("inner_pending_does_not_consume_token");
        let ready = Arc::new(AtomicBool::new(false));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready.clone(), false),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_pending(), "pending", true, first.is_pending());
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available", 1, available);

        ready.store(true, Ordering::SeqCst);
        let second = svc.poll_ready(&mut cx);
        let ok = matches!(second, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 0, "available", 0, available);
        crate::test_complete!("inner_pending_does_not_consume_token");
    }

    #[test]
    fn inner_error_does_not_consume_token() {
        init_test("inner_error_does_not_consume_token");
        let ready = Arc::new(AtomicBool::new(true));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready, true),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        let err = matches!(result, Poll::Ready(Err(RateLimitError::Inner(_))));
        crate::assert_with_log!(err, "inner err", true, err);
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available", 1, available);
        crate::test_complete!("inner_error_does_not_consume_token");
    }

    #[test]
    fn synchronous_inner_call_panic_restores_reserved_token() {
        init_test("synchronous_inner_call_panic_restores_reserved_token");
        let mut svc = RateLimit::new(PanicOnCallService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 0, "available after reserve", 0, available);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _f = svc.call(());
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available after panic", 1, available);
        crate::test_complete!("synchronous_inner_call_panic_restores_reserved_token");
    }

    #[test]
    fn refill_adds_tokens() {
        init_test("refill_adds_tokens");
        let svc = RateLimit::new(EchoService, 10, Duration::from_secs(1));

        // Drain all tokens
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));

        // Refill after 1 second
        svc.refill(Time::from_secs(1));

        // Should have refilled to max
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 10, "available", 10, available);
        crate::test_complete!("refill_adds_tokens");
    }

    #[test]
    fn refill_caps_at_rate() {
        init_test("refill_caps_at_rate");
        let svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));

        // Start with some tokens
        set_bucket_state(&svc, 3, Some(Time::from_secs(0)));

        // Refill after 2 seconds
        svc.refill(Time::from_secs(2));

        // Should cap at rate (5), not 3 + 10
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 5, "available", 5, available);
        crate::test_complete!("refill_caps_at_rate");
    }

    #[test]
    fn poll_ready_uses_time_getter() {
        init_test("poll_ready_uses_time_getter");
        let mut svc =
            RateLimit::with_time_getter(EchoService, 5, Duration::from_secs(1), test_time);
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));
        set_test_time(1_000_000_000);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 4, "available", 4, available);
        crate::test_complete!("poll_ready_uses_time_getter");
    }

    #[test]
    fn poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready() {
        init_test("poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready");
        let ready = Arc::new(AtomicBool::new(false));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready.clone(), false),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        crate::assert_with_log!(first.is_pending(), "pending", true, first.is_pending());
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );

        ready.store(true, Ordering::SeqCst);
        let second = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let ok = matches!(second, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );
        crate::test_complete!(
            "poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready"
        );
    }

    #[test]
    fn poll_ready_with_time_propagates_inner_error() {
        init_test("poll_ready_with_time_propagates_inner_error");
        let ready = Arc::new(AtomicBool::new(true));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready, true),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let err = matches!(
            result,
            Poll::Ready(Err(RateLimitError::Inner("inner error")))
        );
        crate::assert_with_log!(err, "inner err", true, err);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("poll_ready_with_time_propagates_inner_error");
    }

    #[test]
    fn reserved_poll_ready_error_restores_token_and_clears_reservation() {
        init_test("reserved_poll_ready_error_restores_token_and_clears_reservation");
        let mut svc = RateLimit::with_time_getter(
            ReadyThenErrorService::default(),
            1,
            Duration::MAX,
            test_time,
        );
        let mut blocked = svc.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<()>(Time::ZERO, &mut cx);
        let first_ok = matches!(first, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ok, "first ready", true, first_ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available after reservation",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved after first ready",
            1,
            svc.reserved_tokens()
        );

        let (blocked_waker, wakes, unlocked_wakes) = reentrant_rate_limit_waker(&blocked.state);
        let mut blocked_cx = Context::from_waker(&blocked_waker);
        assert!(
            blocked
                .poll_ready_with_time::<()>(Time::ZERO, &mut blocked_cx)
                .is_pending()
        );

        let second = svc.poll_ready_with_time::<()>(Time::ZERO, &mut cx);
        let second_err = matches!(
            second,
            Poll::Ready(Err(RateLimitError::Inner("inner error")))
        );
        crate::assert_with_log!(second_err, "second ready error", true, second_err);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after reserved-path error",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved cleared after reserved-path error",
            0,
            svc.reserved_tokens()
        );
        crate::assert_with_log!(
            wakes.load(Ordering::SeqCst) == 1,
            "reserved-path error wakes exhausted clone",
            1,
            wakes.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            unlocked_wakes.load(Ordering::SeqCst) == 1,
            "reserved-path error wakes after unlock",
            1,
            unlocked_wakes.load(Ordering::SeqCst)
        );

        let mut future = svc.call(());
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "call requires a fresh successful poll_ready after error",
            true,
            not_ready
        );
        assert!(matches!(
            blocked.poll_ready_with_time::<()>(Time::ZERO, &mut blocked_cx),
            Poll::Ready(Ok(()))
        ));
        crate::test_complete!("reserved_poll_ready_error_restores_token_and_clears_reservation");
    }

    #[test]
    fn poll_ready_with_time_reserved_token_restores_on_call_panic() {
        init_test("poll_ready_with_time_reserved_token_restores_on_call_panic");
        let mut svc = RateLimit::with_time_getter(PanicOnCallService, 1, Duration::MAX, test_time);
        let mut blocked = svc.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available after reserve",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );

        let (blocked_waker, wakes, unlocked_wakes) = reentrant_rate_limit_waker(&blocked.state);
        let mut blocked_cx = Context::from_waker(&blocked_waker);
        assert!(
            blocked
                .poll_ready_with_time::<()>(Time::ZERO, &mut blocked_cx)
                .is_pending()
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _future = svc.call(());
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after panic",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            wakes.load(Ordering::SeqCst) == 1,
            "call panic refund wakes exhausted clone",
            1,
            wakes.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            unlocked_wakes.load(Ordering::SeqCst) == 1,
            "call panic refund wakes after unlock",
            1,
            unlocked_wakes.load(Ordering::SeqCst)
        );
        assert!(matches!(
            blocked.poll_ready_with_time::<()>(Time::ZERO, &mut blocked_cx),
            Poll::Ready(Ok(()))
        ));
        crate::test_complete!("poll_ready_with_time_reserved_token_restores_on_call_panic");
    }

    #[test]
    fn poll_ready_with_time_restores_token_on_inner_panic() {
        init_test("poll_ready_with_time_restores_token_on_inner_panic");
        let mut svc = RateLimit::new(PanicOnPollReadyService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner poll_ready panicked", true, panicked);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after panic",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("poll_ready_with_time_restores_token_on_inner_panic");
    }

    #[test]
    fn call_without_poll_ready_returns_not_ready() {
        init_test("call_without_poll_ready_returns_not_ready");
        let mut svc = RateLimit::new(PanicOnCallService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = svc.call(());
            Pin::new(&mut future).poll(&mut cx)
        }))
        .expect("call without poll_ready must not invoke inner service");

        let not_ready = matches!(result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(not_ready, "not ready", true, not_ready);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available tokens unchanged",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn zero_period_keeps_bucket_full() {
        init_test("zero_period_keeps_bucket_full");
        let mut svc = RateLimit::with_time_getter(EchoService, 2, Duration::ZERO, test_time);
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));

        set_test_time(1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("zero_period_keeps_bucket_full");
    }

    #[test]
    fn zero_period_zero_rate_still_ready() {
        init_test("zero_period_zero_rate_still_ready");
        let mut svc = RateLimit::with_time_getter(EchoService, 0, Duration::ZERO, test_time);
        set_test_time(1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("zero_period_zero_rate_still_ready");
    }

    // =========================================================================
    // Wave 31: Data-type trait coverage
    // =========================================================================

    #[test]
    fn rate_limit_layer_debug_clone() {
        let layer = RateLimitLayer::new(10, Duration::from_secs(1));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("RateLimitLayer"));
        let cloned = layer;
        assert_eq!(cloned.rate(), 10);
        assert_eq!(cloned.period(), Duration::from_secs(1));
    }

    #[test]
    fn rate_limit_layer_with_time_getter() {
        let layer = RateLimitLayer::with_time_getter(5, Duration::from_millis(500), test_time);
        assert_eq!(layer.rate(), 5);
        assert_eq!(layer.period(), Duration::from_millis(500));
    }

    #[test]
    fn rate_limit_service_debug() {
        let svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("RateLimit"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn rate_limit_service_clone() {
        let svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        let cloned = svc.clone();
        assert_eq!(*cloned.inner(), 42);
        assert_eq!(cloned.rate(), 10);
        assert_eq!(cloned.available_tokens(), 10);
        assert_eq!(svc.rate(), cloned.rate()); // use svc to avoid redundant_clone warning
    }

    #[test]
    fn rate_limit_clone_does_not_inherit_reserved_tokens() {
        init_test("rate_limit_clone_does_not_inherit_reserved_tokens");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );

        let mut cloned = svc.clone();
        crate::assert_with_log!(
            cloned.available_tokens() == 0,
            "clone sees shared token depletion",
            0,
            cloned.available_tokens()
        );
        crate::assert_with_log!(
            cloned.reserved_tokens() == 0,
            "clone reserved tokens reset",
            0,
            cloned.reserved_tokens()
        );

        let mut clone_future = cloned.call(7);
        let clone_result = Pin::new(&mut clone_future).poll(&mut cx);
        let clone_limited = matches!(clone_result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(
            clone_limited,
            "clone cannot spend original reservation",
            true,
            clone_limited
        );

        let mut original_future = svc.call(7);
        let original_result = Pin::new(&mut original_future).poll(&mut cx);
        let original_ok = matches!(original_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(
            original_ok,
            "original reservation still works",
            true,
            original_ok
        );
        crate::test_complete!("rate_limit_clone_does_not_inherit_reserved_tokens");
    }

    #[test]
    fn rate_limit_clone_shares_bucket_state() {
        init_test("rate_limit_clone_shares_bucket_state");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let mut cloned = svc.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
        let first_ready = matches!(first, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ready, "first ready", true, first_ready);
        crate::assert_with_log!(
            cloned.available_tokens() == 0,
            "clone sees depleted bucket",
            0,
            cloned.available_tokens()
        );

        let second = cloned.poll_ready_with_time::<i32>(Time::from_millis(500), &mut cx);
        crate::assert_with_log!(
            second.is_pending(),
            "second pending",
            true,
            second.is_pending()
        );

        let mut fut = svc.call(7);
        let result = Pin::new(&mut fut).poll(&mut cx);
        let first_ok = matches!(result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call result", true, first_ok);

        let third = cloned.poll_ready_with_time::<i32>(Time::from_secs(1), &mut cx);
        let third_ready = matches!(third, Poll::Ready(Ok(())));
        crate::assert_with_log!(third_ready, "third ready after refill", true, third_ready);
        crate::test_complete!("rate_limit_clone_shares_bucket_state");
    }

    #[test]
    fn expired_sleep_rewakes_instead_of_swallowing_readiness() {
        init_test("expired_sleep_rewakes_instead_of_swallowing_readiness");
        let mut svc = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        set_bucket_state(&svc, 0, Some(Time::ZERO));
        let (waker, wakes, unlocked_wakes) = reentrant_rate_limit_waker(&svc.state);
        let mut cx = Context::from_waker(&waker);

        // First install the shared waiter with a far-future fallback timer.
        assert!(
            svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                .is_pending()
        );
        assert_eq!(wakes.load(Ordering::SeqCst), 0);

        // Deterministically substitute the same-deadline Sleep in its ready
        // state. The poll must not swallow that readiness or retain a completed
        // future that would panic on repoll.
        drop(svc.sleep.take());
        svc.sleep = Some(crate::time::Sleep::with_time_getter(
            Time::from_nanos(u64::MAX),
            ready_sleep_time,
        ));
        assert!(
            svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                .is_pending()
        );
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(unlocked_wakes.load(Ordering::SeqCst), 1);
        assert!(svc.sleep.is_none());

        assert!(matches!(
            svc.poll_ready_with_time::<i32>(Time::from_nanos(u64::MAX), &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        crate::test_complete!("expired_sleep_rewakes_instead_of_swallowing_readiness");
    }

    #[test]
    fn dropping_clone_wakes_exhausted_peer_without_time_advance() {
        init_test("dropping_clone_wakes_exhausted_peer_without_time_advance");
        let mut holder = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        let mut blocked = holder.clone();

        let holder_waker = noop_waker();
        let mut holder_cx = Context::from_waker(&holder_waker);
        let ready = holder.poll_ready_with_time::<i32>(Time::ZERO, &mut holder_cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "holder reserves sole token", true, ready_ok);

        let (blocked_waker, wakes, unlocked_wakes) = reentrant_rate_limit_waker(&blocked.state);
        let mut blocked_cx = Context::from_waker(&blocked_waker);
        let pending = blocked.poll_ready_with_time::<i32>(Time::ZERO, &mut blocked_cx);
        crate::assert_with_log!(
            pending.is_pending(),
            "peer parks while bucket is empty",
            true,
            pending.is_pending()
        );
        crate::assert_with_log!(
            blocked.state.lock().waiters.len() == 1,
            "one shared waiter registered",
            1,
            blocked.state.lock().waiters.len()
        );

        drop(holder);

        crate::assert_with_log!(
            wakes.load(Ordering::SeqCst) == 1,
            "refund wakes parked peer exactly once",
            1,
            wakes.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            unlocked_wakes.load(Ordering::SeqCst) == 1,
            "wake callback runs after bucket unlock",
            1,
            unlocked_wakes.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            blocked.available_tokens() == 1,
            "drop restores shared token",
            1,
            blocked.available_tokens()
        );
        crate::assert_with_log!(
            blocked.state.lock().waiters.is_empty(),
            "refund atomically detaches waiters",
            true,
            blocked.state.lock().waiters.is_empty()
        );

        let ready = blocked.poll_ready_with_time::<i32>(Time::ZERO, &mut blocked_cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            ready_ok,
            "woken peer acquires without time advance",
            true,
            ready_ok
        );
        crate::test_complete!("dropping_clone_wakes_exhausted_peer_without_time_advance");
    }

    #[test]
    fn exhausted_waiter_registration_deduplicates_and_replaces_in_place() {
        init_test("exhausted_waiter_registration_deduplicates_and_replaces_in_place");
        let mut holder = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        let mut blocked = holder.clone();
        let holder_waker = noop_waker();
        let mut holder_cx = Context::from_waker(&holder_waker);
        assert!(matches!(
            holder.poll_ready_with_time::<i32>(Time::ZERO, &mut holder_cx),
            Poll::Ready(Ok(()))
        ));

        let state = Arc::clone(&blocked.state);
        let (first_waker, _, _) = reentrant_rate_limit_waker(&state);
        let first_handle;
        {
            let mut cx = Context::from_waker(&first_waker);
            assert!(
                blocked
                    .poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                    .is_pending()
            );
            first_handle = blocked
                .reservations
                .waiter
                .expect("pending poll must install a waiter");
            assert!(
                blocked
                    .poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                    .is_pending()
            );
            assert_eq!(blocked.reservations.waiter, Some(first_handle));
            let state = state.lock();
            assert_eq!(state.waiters.len(), 1);
            assert_eq!(state.next_waiter_id, 1);
        }

        let (replacement_waker, _, _) = reentrant_rate_limit_waker(&state);
        {
            let mut cx = Context::from_waker(&replacement_waker);
            assert!(
                blocked
                    .poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                    .is_pending()
            );
        }
        assert_eq!(blocked.reservations.waiter, Some(first_handle));
        {
            let state = state.lock();
            assert_eq!(state.waiters.len(), 1);
            assert_eq!(state.next_waiter_id, 1);
            assert!(
                waiter_by_handle(&state, first_handle)
                    .expect("replacement must preserve the waiter handle")
                    .registration
                    .will_wake(&replacement_waker)
            );
        }
        drop(blocked);
        assert!(state.lock().waiters.is_empty());
        drop(holder);
        crate::test_complete!("exhausted_waiter_registration_deduplicates_and_replaces_in_place");
    }

    #[test]
    fn waiter_replacement_retires_final_waker_after_unlock() {
        init_test("waiter_replacement_retires_final_waker_after_unlock");
        let mut blocked = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        set_bucket_state(&blocked, 0, Some(Time::ZERO));
        let state = Arc::clone(&blocked.state);
        let (first_waker, first_drops, first_unlocked_drops) = rate_limit_waker_drop_probe(&state);
        let handle = install_test_waiter(&mut blocked, &first_waker);
        drop(first_waker);
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);

        let replacement_waker = noop_waker();
        let mut cx = Context::from_waker(&replacement_waker);
        assert!(
            blocked
                .poll_ready_with_time::<i32>(Time::ZERO, &mut cx)
                .is_pending()
        );
        assert_eq!(blocked.reservations.waiter, Some(handle));
        assert_eq!(state.lock().waiters.len(), 1);
        assert_eq!(first_drops.load(Ordering::SeqCst), 1);
        assert_eq!(first_unlocked_drops.load(Ordering::SeqCst), 1);
        crate::test_complete!("waiter_replacement_retires_final_waker_after_unlock");
    }

    #[test]
    fn panicking_waiter_does_not_suppress_other_refund_wakes() {
        init_test("panicking_waiter_does_not_suppress_other_refund_wakes");
        let mut holder = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        let mut hostile = holder.clone();
        let mut healthy = holder.clone();
        let holder_waker = noop_waker();
        let mut holder_cx = Context::from_waker(&holder_waker);
        assert!(matches!(
            holder.poll_ready_with_time::<i32>(Time::ZERO, &mut holder_cx),
            Poll::Ready(Ok(()))
        ));

        let hostile_wakes = Arc::new(AtomicUsize::new(0));
        let hostile_waker = Waker::from(Arc::new(PanickingRateLimitWaker {
            wakes: Arc::clone(&hostile_wakes),
        }));
        let mut hostile_cx = Context::from_waker(&hostile_waker);
        assert!(
            hostile
                .poll_ready_with_time::<i32>(Time::ZERO, &mut hostile_cx)
                .is_pending()
        );

        let (healthy_waker, healthy_wakes, healthy_unlocked_wakes) =
            reentrant_rate_limit_waker(&healthy.state);
        let mut healthy_cx = Context::from_waker(&healthy_waker);
        assert!(
            healthy
                .poll_ready_with_time::<i32>(Time::ZERO, &mut healthy_cx)
                .is_pending()
        );
        assert_eq!(healthy.state.lock().waiters.len(), 2);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(holder)));
        assert!(result.is_ok());
        assert_eq!(hostile_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(healthy_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(healthy_unlocked_wakes.load(Ordering::SeqCst), 1);
        assert!(healthy.state.lock().waiters.is_empty());

        // One woken peer spends the refunded token. The other peer's stale
        // handle must re-register without removing the reused slab slot, then
        // receive the next zero-to-positive refund.
        assert!(matches!(
            healthy.poll_ready_with_time::<i32>(Time::ZERO, &mut healthy_cx),
            Poll::Ready(Ok(()))
        ));
        let (retry_waker, retry_wakes, retry_unlocked_wakes) =
            reentrant_rate_limit_waker(&hostile.state);
        let mut retry_cx = Context::from_waker(&retry_waker);
        assert!(
            hostile
                .poll_ready_with_time::<i32>(Time::ZERO, &mut retry_cx)
                .is_pending()
        );
        assert_eq!(hostile.state.lock().waiters.len(), 1);
        drop(healthy);
        assert_eq!(retry_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(retry_unlocked_wakes.load(Ordering::SeqCst), 1);
        assert!(hostile.state.lock().waiters.is_empty());
        crate::test_complete!("panicking_waiter_does_not_suppress_other_refund_wakes");
    }

    #[test]
    fn dropping_waiter_contains_panicking_registry_waker_destructor() {
        init_test("dropping_waiter_contains_panicking_registry_waker_destructor");
        let mut blocked = RateLimit::with_time_getter(EchoService, 1, Duration::MAX, test_time);
        set_bucket_state(&blocked, 0, Some(Time::ZERO));
        let state = Arc::clone(&blocked.state);
        let drops = Arc::new(AtomicUsize::new(0));
        let hostile_waker = Waker::from(Arc::new(PanickingDropRateLimitWaker {
            drops: Arc::clone(&drops),
        }));
        install_test_waiter(&mut blocked, &hostile_waker);
        drop(hostile_waker);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(blocked)));
        assert!(result.is_ok());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(state.lock().waiters.is_empty());
        crate::test_complete!("dropping_waiter_contains_panicking_registry_waker_destructor");
    }

    #[test]
    fn reserved_token_guard_caps_restored_bucket_at_rate() {
        init_test("reserved_token_guard_caps_restored_bucket_at_rate");
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: 1,
            last_refill: Some(Time::ZERO),
            waiters: Slab::new(),
            next_waiter_id: 0,
        }));

        {
            let _guard = ReservedTokenGuard::new(Arc::clone(&state), 1, false, true);
        }

        let tokens = state.lock().tokens;
        crate::assert_with_log!(tokens == 1, "restored tokens capped", 1, tokens);
        crate::test_complete!("reserved_token_guard_caps_restored_bucket_at_rate");
    }

    #[test]
    fn rate_limit_service_accessors() {
        let mut svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        assert_eq!(*svc.inner(), 42);
        assert_eq!(svc.rate(), 10);
        assert_eq!(svc.period(), Duration::from_secs(1));
        *svc.inner_mut() = 99;
        assert_eq!(svc.into_inner(), 99);
    }

    #[test]
    fn rate_limit_error_debug() {
        let err: RateLimitError<&str> = RateLimitError::NotReady;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotReady"));

        let err: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimitExceeded"));

        let err: RateLimitError<&str> = RateLimitError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));

        let err: RateLimitError<&str> = RateLimitError::Inner("fail");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn rate_limit_error_source() {
        use std::error::Error;
        let err: RateLimitError<std::io::Error> = RateLimitError::NotReady;
        assert!(err.source().is_none());

        let err: RateLimitError<std::io::Error> = RateLimitError::RateLimitExceeded;
        assert!(err.source().is_none());

        let err: RateLimitError<std::io::Error> = RateLimitError::PolledAfterCompletion;
        assert!(err.source().is_none());

        let inner = std::io::Error::other("test");
        let err = RateLimitError::Inner(inner);
        assert!(err.source().is_some());
    }

    #[test]
    fn rate_limit_future_debug() {
        let future: RateLimitFuture<_, &str> =
            RateLimitFuture::new(std::future::ready(Ok::<i32, &str>(42)));
        let dbg = format!("{future:?}");
        assert!(dbg.contains("RateLimitFuture"));
    }

    #[test]
    fn immediate_error_repolls_fail_closed_after_completion() {
        init_test("immediate_error_repolls_fail_closed_after_completion");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future: RateLimitFuture<
            std::future::Ready<Result<i32, &'static str>>,
            &'static str,
        > = RateLimitFuture::immediate_error(RateLimitError::NotReady);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RateLimitError::NotReady))),
            "first poll returns stored error",
            true,
            matches!(first, Poll::Ready(Err(RateLimitError::NotReady)))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("immediate_error_repolls_fail_closed_after_completion");
    }

    #[test]
    fn completed_inner_future_repolls_fail_closed() {
        init_test("completed_inner_future_repolls_fail_closed");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future: RateLimitFuture<_, &'static str> =
            RateLimitFuture::new(std::future::ready(Ok::<i32, &'static str>(42)));

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(42))),
            "first poll returns success",
            true,
            matches!(first, Poll::Ready(Ok(42)))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("completed_inner_future_repolls_fail_closed");
    }

    #[test]
    fn completed_inner_error_repolls_fail_closed() {
        init_test("completed_inner_error_repolls_fail_closed");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = RateLimitFuture::new(std::future::ready(Err::<i32, &'static str>("boom")));

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RateLimitError::Inner("boom")))),
            "first poll returns inner error",
            true,
            matches!(first, Poll::Ready(Err(RateLimitError::Inner("boom"))))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("completed_inner_error_repolls_fail_closed");
    }

    struct TrackWaker(Arc<AtomicBool>);
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn rate_limit_timer_context(timer: &TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 123),
            TaskId::new_for_test(0, 123),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        )
    }

    /// Exhausted buckets must register a real wake, then refill in the same
    /// clock domain as their configured source, including through layers/clones.
    #[test]
    fn exhausted_tokens_register_waker_not_hang() {
        init_test("exhausted_tokens_register_waker_not_hang");
        for (driver_start, custom_start) in [(100, 0), (0, 100), (100, 100)] {
            for construction in 0..4 {
                let clock = Arc::new(VirtualClock::new());
                clock.set(Time::from_secs(driver_start));
                let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
                let _current = Cx::set_current(Some(rate_limit_timer_context(&timer)));
                set_test_time(Time::from_secs(custom_start).as_nanos());
                let layer = RateLimitLayer::with_time_getter(1, Duration::from_secs(5), test_time);
                let mut svc = match construction {
                    0 => RateLimit::with_time_getter(
                        EchoService,
                        1,
                        Duration::from_secs(5),
                        test_time,
                    ),
                    1 => layer.layer(EchoService),
                    2 => RateLimit::with_time_getter(
                        EchoService,
                        1,
                        Duration::from_secs(5),
                        test_time,
                    )
                    .clone(),
                    _ => layer.clone().layer(EchoService).clone(),
                };
                let woken = Arc::new(AtomicBool::new(false));
                let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woken))));
                let mut cx = Context::from_waker(&waker);
                assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
                assert!(matches!(
                    Pin::new(&mut svc.call(42)).poll(&mut cx),
                    Poll::Ready(Ok(42))
                ));

                assert!(svc.poll_ready(&mut cx).is_pending());
                assert_eq!(svc.available_tokens(), 0);
                assert_eq!(svc.state.lock().waiters.len(), 1);
                assert_eq!(timer.pending_count(), 1);
                assert_eq!(
                    timer.next_deadline(),
                    Some(Time::from_secs(driver_start + 5))
                );
                assert!(!woken.load(Ordering::SeqCst));

                set_test_time(Time::from_secs(custom_start + 5).as_nanos());
                clock.set(Time::from_secs(driver_start + 5));
                assert_eq!(timer.process_timers(), 1);
                assert!(
                    woken.load(Ordering::SeqCst),
                    "refill timer wakes the waiter"
                );
                assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
                assert!(svc.sleep.is_none());
                assert!(svc.state.lock().waiters.is_empty());
                assert_eq!(timer.pending_count(), 0);
                assert!(matches!(
                    Pin::new(&mut svc.call(7)).poll(&mut cx),
                    Poll::Ready(Ok(7))
                ));
            }
        }
        crate::test_complete!("exhausted_tokens_register_waker_not_hang");
    }

    #[test]
    fn custom_clock_refill_wait_rearms_without_spinning_while_clock_is_frozen() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let _current = Cx::set_current(Some(rate_limit_timer_context(&timer)));
        set_test_time(Time::from_secs(100).as_nanos());
        let mut svc =
            RateLimit::with_time_getter(EchoService, 1, Duration::from_secs(5), test_time);
        let (waker, wakes, unlocked_wakes) = reentrant_rate_limit_waker(&svc.state);
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(
            Pin::new(&mut svc.call(42)).poll(&mut cx),
            Poll::Ready(Ok(42))
        ));
        assert!(svc.poll_ready(&mut cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(5)));

        clock.set(Time::from_secs(5));
        assert_eq!(timer.process_timers(), 1);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(unlocked_wakes.load(Ordering::SeqCst), 1);
        for _ in 0..3 {
            assert!(svc.poll_ready(&mut cx).is_pending());
            assert_eq!(wakes.load(Ordering::SeqCst), 1, "no immediate re-wake loop");
            assert_eq!(timer.pending_count(), 1);
            assert_eq!(timer.next_deadline(), Some(Time::from_secs(10)));
            assert_eq!(svc.state.lock().waiters.len(), 1);
        }

        set_test_time(Time::from_secs(105).as_nanos());
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(timer.pending_count(), 0);
        assert!(svc.state.lock().waiters.is_empty());
        assert!(svc.sleep.is_none());
        drop(svc.release_readiness());
        assert_eq!(svc.available_tokens(), 1);
    }

    #[test]
    fn default_clock_layers_and_clones_preserve_ordinary_refill_timers() {
        for construction in 0..3 {
            let clock = Arc::new(VirtualClock::new());
            clock.set(Time::from_secs(100));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let _current = Cx::set_current(Some(rate_limit_timer_context(&timer)));
            let layer = RateLimitLayer::new(1, Duration::from_secs(5));
            let mut svc = match construction {
                0 => RateLimit::new(EchoService, 1, Duration::from_secs(5)),
                1 => layer.layer(EchoService),
                _ => layer.clone().layer(EchoService).clone(),
            };
            let woken = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woken))));
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            assert!(matches!(
                Pin::new(&mut svc.call(42)).poll(&mut cx),
                Poll::Ready(Ok(42))
            ));
            assert!(svc.poll_ready(&mut cx).is_pending());
            assert!(
                !svc.sleep
                    .as_ref()
                    .expect("refill wait")
                    .has_custom_time_getter()
            );
            assert_eq!(timer.next_deadline(), Some(Time::from_secs(105)));

            clock.set(Time::from_secs(105));
            assert_eq!(timer.process_timers(), 1);
            assert!(woken.load(Ordering::SeqCst));
            assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            assert_eq!(timer.pending_count(), 0);
            assert!(svc.state.lock().waiters.is_empty());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_custom_clock_rate_limit_wakes_its_parked_refill_waiter() {
        fn offset_now() -> Time {
            Cx::current()
                .expect("native task context")
                .now()
                .saturating_add_nanos(Time::from_secs(100).as_nanos())
        }

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("native runtime");
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().expect("native task context");
            let timer = owner.timer_driver().expect("native timer driver");
            let mut svc =
                RateLimit::with_time_getter(EchoService, 1, Duration::from_millis(20), offset_now);
            std::future::poll_fn(|cx| svc.poll_ready(cx))
                .await
                .expect("initial capacity");
            assert!(matches!(svc.call(42).await, Ok(42)));
            let mut parked = false;
            let wait = std::future::poll_fn(|cx| {
                let result = svc.poll_ready(cx);
                if result.is_pending() && !parked {
                    parked = true;
                    assert_eq!(timer.pending_count(), 1, "refill wait is registered");
                }
                result
            });
            let result =
                crate::time::TimeoutFuture::after(owner.now(), Duration::from_secs(2), wait).await;
            assert!(matches!(result, Ok(Ok(()))));
            assert!(
                parked,
                "the exhausted service must actually park before refill"
            );
            assert!(svc.state.lock().waiters.is_empty());
            assert!(svc.sleep.is_none());
            assert_eq!(timer.pending_count(), 0);
            assert!(matches!(svc.call(7).await, Ok(7)));
        }));
    }

    #[test]
    fn error_display() {
        init_test("error_display");
        let err: RateLimitError<&str> = RateLimitError::NotReady;
        let display = format!("{err}");
        let has_not_ready = display.contains("poll_ready required before call");
        crate::assert_with_log!(has_not_ready, "not ready", true, has_not_ready);

        let err: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        let display = format!("{err}");
        let has_rate = display.contains("rate limit exceeded");
        crate::assert_with_log!(has_rate, "rate limit", true, has_rate);

        let err: RateLimitError<&str> = RateLimitError::PolledAfterCompletion;
        let display = format!("{err}");
        let has_polled_after_completion = display.contains("future polled after completion");
        crate::assert_with_log!(
            has_polled_after_completion,
            "polled after completion",
            true,
            has_polled_after_completion
        );

        let err: RateLimitError<&str> = RateLimitError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("error_display");
    }
