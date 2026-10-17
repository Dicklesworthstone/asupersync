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
    use crate::service::concurrency_limit::ConcurrencyLimitLayer;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    thread_local! {
        static TEST_CURRENT_CX_GUARD: std::cell::RefCell<Option<crate::cx::cx::CurrentCxGuard>> =
            const { std::cell::RefCell::new(None) };
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        // Concurrency-limit middleware (used by some retry tests) acquires a
        // semaphore permit synchronously in poll_ready. Permits are obligations
        // and ObligationToken::reserve rejects root-region tokens, so install a
        // non-root testing Cx as the thread-local current context.
        // (br-asupersync-88h4nd)
        TEST_CURRENT_CX_GUARD.with(|guard| {
            let mut guard = guard.borrow_mut();
            guard.take();
            *guard = Some(Cx::set_current(Some(Cx::for_testing())));
        });
        crate::test_phase!(name);
    }
    use std::task::Waker;

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    // A service that fails N times then succeeds
    struct FailingService {
        fail_count: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl Clone for FailingService {
        fn clone(&self) -> Self {
            Self {
                fail_count: self.fail_count.clone(),
                calls: self.calls.clone(),
            }
        }
    }

    impl FailingService {
        fn new(fail_count: usize) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    fail_count: Arc::new(AtomicUsize::new(fail_count)),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Service<i32> for FailingService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let remaining = self.fail_count.load(Ordering::SeqCst);
            if remaining > 0 {
                self.fail_count.fetch_sub(1, Ordering::SeqCst);
                std::future::ready(Err("service error"))
            } else {
                std::future::ready(Ok(req * 2))
            }
        }
    }

    struct OneShotRequest(i32);

    #[derive(Clone)]
    struct ReadyFailThenSucceedService {
        ready_failures_remaining: Arc<AtomicUsize>,
        ready_polls: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl ReadyFailThenSucceedService {
        fn new(ready_failures: usize) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let ready_polls = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    ready_failures_remaining: Arc::new(AtomicUsize::new(ready_failures)),
                    ready_polls: Arc::clone(&ready_polls),
                    calls: Arc::clone(&calls),
                },
                ready_polls,
                calls,
            )
        }
    }

    impl Service<OneShotRequest> for ReadyFailThenSucceedService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready_polls.fetch_add(1, Ordering::SeqCst);
            let remaining = self.ready_failures_remaining.load(Ordering::SeqCst);
            if remaining > 0 {
                self.ready_failures_remaining.fetch_sub(1, Ordering::SeqCst);
                Poll::Ready(Err("transient readiness failure"))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, req: OneShotRequest) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(req.0 * 3))
        }
    }

    #[derive(Clone, Copy)]
    struct RetryReadyOnceWithoutClone {
        attempted: bool,
    }

    impl RetryReadyOnceWithoutClone {
        const fn new() -> Self {
            Self { attempted: false }
        }
    }

    impl Policy<OneShotRequest, i32, &'static str> for RetryReadyOnceWithoutClone {
        type Future = std::future::Ready<Self>;

        fn retry(
            &self,
            _req: &OneShotRequest,
            result: Result<&i32, &&'static str>,
        ) -> Option<Self::Future> {
            if self.attempted || result.is_ok() {
                None
            } else {
                Some(std::future::ready(Self { attempted: true }))
            }
        }

        fn clone_request(&self, _req: &OneShotRequest) -> Option<OneShotRequest> {
            None
        }
    }

    #[test]
    fn layer_creates_service() {
        init_test("layer_creates_service");
        let policy = LimitedRetry::<i32>::new(3);
        let layer = RetryLayer::new(policy);
        let (svc, _) = FailingService::new(0);
        let _retry_svc: Retry<_, FailingService> = layer.layer(svc);
        crate::test_complete!("layer_creates_service");
    }

    #[test]
    fn limited_retry_policy_basics() {
        init_test("limited_retry_policy_basics");
        let policy = LimitedRetry::<i32>::new(3);
        let max = policy.max_retries();
        crate::assert_with_log!(max == 3, "max_retries", 3, max);
        let attempt = policy.current_attempt();
        crate::assert_with_log!(attempt == 0, "current_attempt", 0, attempt);
        crate::test_complete!("limited_retry_policy_basics");
    }

    #[test]
    fn limited_retry_clones_request() {
        init_test("limited_retry_clones_request");
        let policy = LimitedRetry::<i32>::new(3);
        // Specify generic types for Policy trait: Request=i32, Res=(), E=()
        let cloned = Policy::<i32, (), ()>::clone_request(&policy, &42);
        crate::assert_with_log!(cloned == Some(42), "cloned", Some(42), cloned);
        crate::test_complete!("limited_retry_clones_request");
    }

    #[test]
    fn limited_retry_returns_none_on_success() {
        init_test("limited_retry_returns_none_on_success");
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Ok::<&i32, &String>(&100));
        crate::assert_with_log!(result.is_none(), "none on success", true, result.is_none());
        crate::test_complete!("limited_retry_returns_none_on_success");
    }

    #[test]
    fn limited_retry_returns_some_on_error() {
        init_test("limited_retry_returns_some_on_error");
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "some on error", true, result.is_some());
        crate::test_complete!("limited_retry_returns_some_on_error");
    }

    #[test]
    fn limited_retry_exhausts_retries() {
        init_test("limited_retry_exhausts_retries");
        let mut policy = LimitedRetry::<i32>::new(2);

        // First retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "first retry", true, result.is_some());
        policy.current_attempt = 1;

        // Second retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "second retry", true, result.is_some());
        policy.current_attempt = 2;

        // Third attempt - should fail (max_retries reached)
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_none(), "third retry none", true, result.is_none());
        crate::test_complete!("limited_retry_exhausts_retries");
    }

    #[test]
    fn no_retry_policy() {
        init_test("no_retry_policy");
        let policy = NoRetry::new();
        let result: Option<std::future::Pending<NoRetry>> =
            Policy::<i32, (), &str>::retry(&policy, &42, Err(&"error"));
        crate::assert_with_log!(result.is_none(), "retry none", true, result.is_none());

        let cloned: Option<i32> = Policy::<i32, (), ()>::clone_request(&policy, &42);
        crate::assert_with_log!(cloned.is_none(), "clone none", true, cloned.is_none());
        crate::test_complete!("no_retry_policy");
    }

    #[test]
    fn retry_starts_no_attempt_once_the_task_is_cancelled() {
        init_test("retry_starts_no_attempt_once_the_task_is_cancelled");
        let current = Cx::for_testing();
        let _current = Cx::set_current(Some(current.clone()));
        current.cancel_with(crate::types::CancelKind::User, Some("caller gave up"));

        let (svc, calls) = FailingService::new(100);
        let mut retry_svc = Retry::new(svc, LimitedRetry::<i32>::new(3));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);
        let result = (0..100)
            .find_map(|_| match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
            .expect("the retry future completes");

        assert!(matches!(result, Err(RetryError::Inner("service error"))));
        let count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "no retry after cancel", 1, count);
        crate::test_complete!("retry_starts_no_attempt_once_the_task_is_cancelled");
    }

    #[test]
    fn retry_succeeds_after_failures() {
        init_test("retry_succeeds_after_failures");
        let policy = LimitedRetry::<i32>::new(3);
        let (svc, calls) = FailingService::new(2); // Fail twice, then succeed
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready
        let _ = retry_svc.poll_ready(&mut cx);

        // Start the retry future
        let mut future = retry_svc.call(21);

        // Poll until completion
        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(result) => {
                    let ok = matches!(result, Ok(42));
                    crate::assert_with_log!(ok, "result ok", true, ok);
                    break;
                }
                Poll::Pending => {}
            }
        }

        // Should have called the service 3 times (2 failures + 1 success)
        let count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "call count", 3, count);
        crate::test_complete!("retry_succeeds_after_failures");
    }

    #[test]
    fn retry_reuses_original_request_after_poll_ready_error() {
        init_test("retry_reuses_original_request_after_poll_ready_error");
        let policy = RetryReadyOnceWithoutClone::new();
        let (svc, ready_polls, calls) = ReadyFailThenSucceedService::new(1);
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = retry_svc.call(OneShotRequest(7));
        let result = Pin::new(&mut future).poll(&mut cx);

        crate::assert_with_log!(
            matches!(result, Poll::Ready(Ok(21))),
            "poll_ready failure retries with original one-shot request",
            "Poll::Ready(Ok(21))",
            result
        );

        let ready_poll_count = ready_polls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            ready_poll_count == 2,
            "service polled ready twice",
            2usize,
            ready_poll_count
        );

        let call_count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            call_count == 1,
            "request was not duplicated across readiness retry",
            1usize,
            call_count
        );

        crate::test_complete!("retry_reuses_original_request_after_poll_ready_error");
    }

    // =========================================================================
    // Wave 30: Data-type trait coverage
    // =========================================================================

    #[test]
    fn retry_layer_debug() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(3));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("RetryLayer"));
    }

    #[test]
    fn retry_layer_clone() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(3)).with_root_id(17);
        let cloned = layer.clone();
        assert_eq!(cloned.policy().max_retries(), 3);
        assert_ne!(layer.root_id, cloned.root_id);
        assert_eq!(layer.next_clone_ordinal.get(), 1);
        assert_eq!(cloned.next_clone_ordinal.get(), 0);
        assert_eq!(cloned.next_service_ordinal.get(), 0);
    }

    #[test]
    fn retry_layer_policy_accessor() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(5));
        assert_eq!(layer.policy().max_retries(), 5);
        assert_eq!(layer.policy().current_attempt(), 0);
    }

    #[test]
    fn retry_service_debug_clone() {
        let svc = Retry::new(42_i32, LimitedRetry::<i32>::new(3)).with_root_id(23);
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("Retry"));
        let cloned = svc.clone();
        assert_eq!(*cloned.inner(), 42);
        assert_ne!(svc.root_id, cloned.root_id);
        assert_eq!(svc.next_clone_ordinal.get(), 1);
        assert_eq!(svc.next_request_ordinal.get(), 0);
        assert_eq!(cloned.next_clone_ordinal.get(), 0);
        assert_eq!(cloned.next_request_ordinal.get(), 0);
    }

    #[test]
    fn layer_clone_interleaving_does_not_perturb_source_services() {
        fn roots(clone_first: bool) -> (u64, u64, u64) {
            let layer = RetryLayer::new(LimitedRetry::<i32>::new(3)).with_root_id(31);
            if clone_first {
                let cloned = layer.clone();
                let first = layer.layer(1_i32);
                let second = layer.layer(2_i32);
                let clone_service = cloned.layer(3_i32);
                (first.root_id, second.root_id, clone_service.root_id)
            } else {
                let first = layer.layer(1_i32);
                let cloned = layer.clone();
                let second = layer.layer(2_i32);
                let clone_service = cloned.layer(3_i32);
                (first.root_id, second.root_id, clone_service.root_id)
            }
        }

        let clone_before = roots(true);
        let clone_between = roots(false);
        assert_eq!(clone_before, clone_between);
        assert_ne!(clone_before.0, clone_before.1);
        assert_ne!(clone_before.0, clone_before.2);
        assert_ne!(clone_before.1, clone_before.2);
    }

    #[test]
    fn retry_service_accessors() {
        let mut svc = Retry::new(42_i32, LimitedRetry::<i32>::new(3));
        assert_eq!(*svc.inner(), 42);
        assert_eq!(svc.policy().max_retries(), 3);
        *svc.inner_mut() = 99;
        assert_eq!(*svc.inner(), 99);
        let inner = svc.into_inner();
        assert_eq!(inner, 99);
    }

    #[test]
    fn limited_retry_debug_clone_copy() {
        let policy = LimitedRetry::<i32>::new(5);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("LimitedRetry"));
        assert!(dbg.contains('5'));
        let cloned = policy;
        let copied = policy; // Copy
        assert_eq!(cloned.max_retries(), copied.max_retries());
    }

    #[test]
    fn no_retry_debug_clone_copy_default() {
        let policy = NoRetry::new();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("NoRetry"));
        let cloned = policy; // Copy
        assert_eq!(format!("{cloned:?}"), format!("{policy:?}"));
        let default = NoRetry;
        let _ = format!("{default:?}");
    }

    #[test]
    fn retry_future_debug() {
        let (svc, _) = FailingService::new(0);
        let policy = LimitedRetry::<i32>::new(1);
        let future = RetryFuture::new(svc, policy, 42);
        let dbg = format!("{future:?}");
        assert!(dbg.contains("RetryFuture"));
    }

    #[test]
    fn retry_error_display_and_source() {
        let inner = RetryError::Inner(std::io::Error::other("boom"));
        assert!(format!("{inner}").contains("boom"));
        assert!(std::error::Error::source(&inner).is_some());

        let done: RetryError<std::io::Error> = RetryError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "retry future polled after completion");
        assert!(std::error::Error::source(&done).is_none());
        assert!(format!("{done:?}").contains("PolledAfterCompletion"));
    }

    #[test]
    fn retry_future_second_poll_fails_closed() {
        init_test("retry_future_second_poll_fails_closed");
        let policy = NoRetry::new();
        let (svc, _) = FailingService::new(0);
        let mut retry_svc = Retry::new(svc, policy);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(42))),
            "first poll returns success",
            "Poll::Ready(Ok(42))",
            first
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RetryError::PolledAfterCompletion))),
            "second poll fails closed",
            "Poll::Ready(Err(RetryError::PolledAfterCompletion))",
            second
        );
        crate::test_complete!("retry_future_second_poll_fails_closed");
    }

    #[test]
    fn retry_exhausts_and_returns_error() {
        init_test("retry_exhausts_and_returns_error");
        let policy = LimitedRetry::<i32>::new(2);
        let (svc, calls) = FailingService::new(10); // Always fail
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(result) => {
                    let err = matches!(result, Err(RetryError::Inner("service error")));
                    crate::assert_with_log!(err, "result err", true, err);
                    break;
                }
                Poll::Pending => {}
            }
        }

        // Should have called 3 times (initial + 2 retries)
        let count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "call count", 3, count);
        crate::test_complete!("retry_exhausts_and_returns_error");
    }

    #[test]
    fn retry_yields_after_budget_on_immediate_retry_loop() {
        init_test("retry_yields_after_budget_on_immediate_retry_loop");
        let policy = LimitedRetry::<i32>::new(RETRY_COOPERATIVE_BUDGET);
        let (svc, calls) = FailingService::new(RETRY_COOPERATIVE_BUDGET + 1);
        let mut retry_svc = Retry::new(svc, policy);
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields after cooperative budget",
            "Poll::Pending",
            first
        );
        let first_calls = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            first_calls == RETRY_COOPERATIVE_BUDGET,
            "retry attempts capped at cooperative budget",
            RETRY_COOPERATIVE_BUDGET,
            first_calls
        );
        let was_woken = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(
            was_woken,
            "self-wake requested after budget exhaustion",
            true,
            was_woken
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RetryError::Inner("service error")))),
            "second poll resumes and returns the terminal error",
            "Poll::Ready(Err(RetryError::Inner(\"service error\")))",
            second
        );
        let total_calls = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            total_calls == RETRY_COOPERATIVE_BUDGET + 1,
            "remaining retry completes on second poll",
            RETRY_COOPERATIVE_BUDGET + 1,
            total_calls
        );
        crate::test_complete!("retry_yields_after_budget_on_immediate_retry_loop");
    }

    #[test]
    fn metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains() {
        init_test("metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains");

        fn first_poll_snapshot(failures_before_success: usize) -> (bool, usize, bool) {
            let policy = LimitedRetry::<i32>::new(failures_before_success);
            let (svc, calls) = FailingService::new(failures_before_success);
            let mut retry_svc = Retry::new(svc, policy);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
            let mut cx = Context::from_waker(&waker);

            let _ = retry_svc.poll_ready(&mut cx);
            let mut future = retry_svc.call(21);
            let first = Pin::new(&mut future).poll(&mut cx);

            (
                matches!(first, Poll::Pending),
                calls.load(Ordering::SeqCst),
                woke.load(Ordering::SeqCst),
            )
        }

        let budget_plus_one = first_poll_snapshot(RETRY_COOPERATIVE_BUDGET + 1);
        let much_longer = first_poll_snapshot(RETRY_COOPERATIVE_BUDGET * 2 + 17);

        crate::assert_with_log!(
            budget_plus_one.0 && much_longer.0,
            "both over-budget chains must yield on first poll",
            true,
            budget_plus_one.0 && much_longer.0
        );
        crate::assert_with_log!(
            budget_plus_one.1 == RETRY_COOPERATIVE_BUDGET
                && much_longer.1 == RETRY_COOPERATIVE_BUDGET,
            "first poll work stays capped at cooperative budget for longer chains",
            RETRY_COOPERATIVE_BUDGET,
            (budget_plus_one.1, much_longer.1)
        );
        crate::assert_with_log!(
            budget_plus_one.2 && much_longer.2,
            "both over-budget chains request a self-wake after budget exhaustion",
            true,
            budget_plus_one.2 && much_longer.2
        );

        crate::test_complete!(
            "metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains"
        );
    }

    #[test]
    fn poll_ready_does_not_strand_concurrency_limit_reservations() {
        init_test("poll_ready_does_not_strand_concurrency_limit_reservations");
        let inner = ConcurrencyLimitLayer::new(1).layer(FailingService::new(0).0);
        let mut retry_svc = Retry::new(inner, NoRetry::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = retry_svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "retry poll_ready ok", true, ready_ok);

        let available_after_ready = retry_svc.inner().available();
        crate::assert_with_log!(
            available_after_ready == 1,
            "available permits after outer poll_ready",
            1,
            available_after_ready
        );

        let mut future = retry_svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let call_ok = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(
            call_ok,
            "retry-wrapped concurrency-limited call completes",
            true,
            call_ok
        );

        let available_after_call = retry_svc.inner().available();
        crate::assert_with_log!(
            available_after_call == 1,
            "available permits after call completion",
            1,
            available_after_call
        );
        crate::test_complete!("poll_ready_does_not_strand_concurrency_limit_reservations");
    }

    // =========================================================================
    // Conformance: deterministic request-local jitter streams
    // =========================================================================

    fn jitter_sequence(mut policy: ExponentialBackoff<i32>, count: usize) -> Vec<u64> {
        let mut delays = Vec::with_capacity(count);
        for _ in 0..count {
            let (delay, next_policy) = policy.advance_for_retry();
            delays.push(delay);
            policy = next_policy;
        }
        delays
    }

    fn forked_jitter_sequence(
        policy: &ExponentialBackoff<i32>,
        stream_id: u64,
        count: usize,
    ) -> Vec<u64> {
        let policy = <ExponentialBackoff<i32> as Policy<i32, (), &'static str>>::fork_for_request(
            policy, stream_id,
        );
        jitter_sequence(policy, count)
    }

    #[test]
    fn inclusive_jitter_sampling_handles_u64_boundaries_without_bias() {
        init_test("inclusive_jitter_sampling_handles_u64_boundaries_without_bias");

        // This seed's first entropy word is u64::MAX. The literal full
        // domain accepts it directly, while [0, MAX - 1] maps MAX to zero;
        // its rejection threshold excludes word zero so zero is not
        // double-weighted.
        let max_word_seed = 0x6a2b_5165_0bc9_9dc4;
        let mut full_domain = DetRng::new(max_word_seed);
        assert_eq!(sample_inclusive(&mut full_domain, 0, u64::MAX), u64::MAX);

        let mut almost_full_domain = DetRng::new(max_word_seed);
        assert_eq!(
            sample_inclusive(&mut almost_full_domain, 0, u64::MAX - 1),
            0
        );

        // Degenerate intervals preserve the historical no-consumption
        // contract, so the following full-domain draw still sees MAX.
        let mut degenerate = DetRng::new(max_word_seed);
        assert_eq!(sample_inclusive(&mut degenerate, 17, 17), 17);
        assert_eq!(sample_inclusive(&mut degenerate, 0, u64::MAX), u64::MAX);

        // For [0, 2^63], seed 42's first word falls below the rejection
        // threshold and its second word is accepted.
        let upper = 1_u64 << 63;
        let span = upper + 1;
        let reject_below = span.wrapping_neg() % span;
        let mut oracle = DetRng::new(42);
        assert!(oracle.next_u64() < reject_below);
        assert!(oracle.next_u64() >= reject_below);

        let mut rejection = DetRng::new(42);
        assert_eq!(
            sample_inclusive(&mut rejection, 0, upper),
            2_308_845_766_745_129_662
        );

        crate::test_complete!("inclusive_jitter_sampling_handles_u64_boundaries_without_bias");
    }

    #[test]
    fn retry_jitter_respects_extreme_caps_and_equal_rounding() {
        init_test("retry_jitter_respects_extreme_caps_and_equal_rounding");

        let full = ExponentialBackoff::<i32>::new(1, u64::MAX, JitterStrategy::Full)
            .with_max_delay(u64::MAX)
            .with_jitter_seed(0x6a2b_5165_0bc9_9dc4);
        assert_eq!(jitter_sequence(full, 1), vec![u64::MAX]);

        for (base, cap, expected) in [(30_001, 30_000, 30_000), (1, 0, 0)] {
            let decorrelated =
                ExponentialBackoff::<i32>::new(3, base, JitterStrategy::Decorrelated)
                    .with_max_delay(cap)
                    .with_jitter_seed(0x71d3_0021_cafe_beef);
            assert_eq!(jitter_sequence(decorrelated, 3), vec![expected; 3]);
        }

        // Equal jitter intentionally rounds an odd capped delay down before
        // adding jitter from [0, half]; it never widens the range to the odd
        // upper endpoint.
        let equal = ExponentialBackoff::<i32>::new(5, 3, JitterStrategy::Equal)
            .with_max_delay(3)
            .with_jitter_seed(42);
        assert_eq!(jitter_sequence(equal, 5), vec![1, 2, 1, 1, 1]);

        crate::test_complete!("retry_jitter_respects_extreme_caps_and_equal_rounding");
    }

    #[test]
    fn seeded_jitter_stream_consumes_successive_entropy_words() {
        init_test("seeded_jitter_stream_consumes_successive_entropy_words");
        let seed = 0x71d3_0021_cafe_beef;

        for strategy in [
            JitterStrategy::Full,
            JitterStrategy::Equal,
            JitterStrategy::Decorrelated,
        ] {
            let mut oracle = DetRng::new(seed);
            let mut policy =
                ExponentialBackoff::<i32>::new(8, 100, strategy).with_jitter_seed(seed);

            for attempt in 0..5 {
                let expected = match strategy {
                    JitterStrategy::Full => {
                        let bound = policy
                            .base_delay_ms
                            .saturating_mul(1_u64 << attempt)
                            .min(policy.max_delay_ms);
                        oracle.next_u64() % (bound + 1)
                    }
                    JitterStrategy::Equal => {
                        let bound = policy
                            .base_delay_ms
                            .saturating_mul(1_u64 << attempt)
                            .min(policy.max_delay_ms);
                        let half = bound / 2;
                        half + (oracle.next_u64() % (half + 1))
                    }
                    JitterStrategy::Decorrelated => {
                        let upper = policy
                            .last_delay_ms
                            .saturating_mul(3)
                            .min(policy.max_delay_ms);
                        policy.base_delay_ms
                            + (oracle.next_u64() % (upper - policy.base_delay_ms + 1))
                    }
                    JitterStrategy::None => unreachable!(),
                };

                let (actual, next_policy) = policy.advance_for_retry();
                assert_eq!(actual, expected, "{strategy:?} attempt {attempt}");
                assert_eq!(next_policy.current_attempt, attempt + 1);
                assert_eq!(next_policy.last_delay_ms, actual.max(1));
                policy = next_policy;
            }
        }

        crate::test_complete!("seeded_jitter_stream_consumes_successive_entropy_words");
    }

    #[test]
    fn seeded_jitter_golden_vectors_detect_output_drift() {
        init_test("seeded_jitter_golden_vectors_detect_output_drift");
        let seed = 0x71d3_0021_cafe_beef;
        let cases = [
            (JitterStrategy::Full, [0, 7, 18, 7, 39]),
            (JitterStrategy::Equal, [5, 9, 26, 46, 82]),
            (JitterStrategy::Decorrelated, [24, 26, 67, 76, 79]),
        ];

        for (strategy, expected) in cases {
            let policy = ExponentialBackoff::<i32>::new(8, 8, strategy)
                .with_max_delay(100)
                .with_jitter_seed(seed);
            let actual = jitter_sequence(policy, expected.len());
            assert_eq!(actual.as_slice(), expected.as_slice());
        }

        crate::test_complete!("seeded_jitter_golden_vectors_detect_output_drift");
    }

    #[test]
    fn exponential_backoff_request_forks_are_distinct_and_replayable() {
        init_test("exponential_backoff_request_forks_are_distinct_and_replayable");
        let policy = ExponentialBackoff::<i32>::new(8, 100, JitterStrategy::Full)
            .with_jitter_seed(0x4f52_4947_494e_414c);

        let first: Vec<_> = (0..16)
            .map(|stream_id| forked_jitter_sequence(&policy, stream_id, 4))
            .collect();
        let replay: Vec<_> = (0..16)
            .map(|stream_id| forked_jitter_sequence(&policy, stream_id, 4))
            .collect();
        let forked_seeds: std::collections::HashSet<_> = (0..16)
            .map(|stream_id| {
                <ExponentialBackoff<i32> as Policy<i32, (), &'static str>>::fork_for_request(
                    &policy, stream_id,
                )
                .jitter_seed
            })
            .collect();
        let distinct_sequences: std::collections::HashSet<_> = first.iter().cloned().collect();
        let first_delays: std::collections::HashSet<_> =
            first.iter().map(|sequence| sequence[0]).collect();

        assert_eq!(first, replay);
        assert_eq!(forked_seeds.len(), 16);
        assert_eq!(distinct_sequences.len(), 16);
        assert!(first_delays.len() > 1);
        assert_eq!(policy.current_attempt(), 0);

        crate::test_complete!("exponential_backoff_request_forks_are_distinct_and_replayable");
    }

    #[test]
    #[should_panic(expected = "retry lineage ordinal overflow")]
    fn retry_lineage_allocation_fails_closed_on_exhaustion() {
        let next_ordinal = Cell::new(u64::MAX);
        let _ = allocate_retry_lineage(1, RETRY_REQUEST_DOMAIN, &next_ordinal);
    }

    fn call_jitter_seed(service: &mut Retry<ExponentialBackoff<i32>, FailingService>) -> u64 {
        let future = service.call(1);
        match future.state {
            RetryState::PollReady { policy, .. } => policy.jitter_seed,
            _ => unreachable!("new retry futures start in PollReady"),
        }
    }

    fn clone_call_world(reverse_interleaving: bool) -> ([u64; 2], [u64; 2]) {
        let (inner, _) = FailingService::new(0);
        let policy = ExponentialBackoff::new(4, 100, JitterStrategy::Full)
            .with_jitter_seed(0x434c_4f4e_4557_4f52);
        let source = Retry::new(inner, policy).with_root_id(41);
        let mut first = source.clone();
        let mut second = source.clone();

        if reverse_interleaving {
            let second_0 = call_jitter_seed(&mut second);
            let first_0 = call_jitter_seed(&mut first);
            let second_1 = call_jitter_seed(&mut second);
            let first_1 = call_jitter_seed(&mut first);
            ([first_0, first_1], [second_0, second_1])
        } else {
            let first_0 = call_jitter_seed(&mut first);
            let second_0 = call_jitter_seed(&mut second);
            let first_1 = call_jitter_seed(&mut first);
            let second_1 = call_jitter_seed(&mut second);
            ([first_0, first_1], [second_0, second_1])
        }
    }

    fn source_call_world(clone_between_calls: bool) -> [u64; 2] {
        let (inner, _) = FailingService::new(0);
        let policy = ExponentialBackoff::new(4, 100, JitterStrategy::Full)
            .with_jitter_seed(0x534f_5552_4345_434c);
        let mut source = Retry::new(inner, policy).with_root_id(42);
        let first = call_jitter_seed(&mut source);
        if clone_between_calls {
            let _sibling = source.clone();
        }
        let second = call_jitter_seed(&mut source);
        [first, second]
    }

    #[test]
    fn retry_clone_call_interleavings_preserve_lane_streams() {
        init_test("retry_clone_call_interleavings_preserve_lane_streams");
        let forward = clone_call_world(false);
        let reverse = clone_call_world(true);
        assert_eq!(forward, reverse);
        assert_ne!(forward.0, forward.1);
        assert_eq!(source_call_world(false), source_call_world(true));
        crate::test_complete!("retry_clone_call_interleavings_preserve_lane_streams");
    }

    #[test]
    fn unpolled_call_consumes_exactly_one_request_stream() {
        init_test("unpolled_call_consumes_exactly_one_request_stream");

        fn first_two(drop_first: bool) -> (u64, u64) {
            let (inner, _) = FailingService::new(0);
            let policy = ExponentialBackoff::new(4, 100, JitterStrategy::Full)
                .with_jitter_seed(0x4452_4f50_4341_4c4c);
            let mut service = Retry::new(inner, policy).with_root_id(43);
            let first = call_jitter_seed(&mut service);
            if !drop_first {
                return (first, first);
            }
            let second = call_jitter_seed(&mut service);
            (first, second)
        }

        let dropped = first_two(true);
        let replay = first_two(true);
        let undropped = first_two(false);
        assert_eq!(dropped, replay);
        assert_eq!(dropped.0, undropped.0);
        assert_ne!(dropped.0, dropped.1);

        crate::test_complete!("unpolled_call_consumes_exactly_one_request_stream");
    }

    #[test]
    fn explicit_root_replays_topology_and_separates_independent_trees() {
        init_test("explicit_root_replays_topology_and_separates_independent_trees");

        fn first_seed(root_id: u64) -> u64 {
            let (inner, _) = FailingService::new(0);
            let policy = ExponentialBackoff::new(4, 100, JitterStrategy::Full)
                .with_jitter_seed(0x524f_4f54_5245_504c);
            let mut service = Retry::new(inner, policy).with_root_id(root_id);
            call_jitter_seed(&mut service)
        }

        assert_eq!(first_seed(47), first_seed(47));
        assert_ne!(first_seed(47), first_seed(53));
        crate::test_complete!("explicit_root_replays_topology_and_separates_independent_trees");
    }

    #[test]
    fn dropped_retry_delay_preserves_source_rng_state() {
        init_test("dropped_retry_delay_preserves_source_rng_state");
        let source = ExponentialBackoff::<i32>::new(4, 100, JitterStrategy::Equal)
            .with_jitter_seed(0x4452_4f50_4445_4c59);
        let pristine = source.clone();
        let error: Result<&i32, &&str> = Err(&"error");
        let mut future = source.retry(&1, error).expect("retry should be scheduled");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        drop(future);

        assert_eq!(jitter_sequence(source, 4), jitter_sequence(pristine, 4));
        crate::test_complete!("dropped_retry_delay_preserves_source_rng_state");
    }

    #[test]
    fn retry_seeded_types_preserve_expected_auto_traits_and_redact_debug() {
        struct NonCloneRequest;

        fn assert_clone<T: Clone>() {}
        fn assert_debug<T: fmt::Debug>() {}
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}

        assert_clone::<ExponentialBackoff<NonCloneRequest>>();
        assert_clone::<SmartRetry<NonCloneRequest>>();
        assert_debug::<ExponentialBackoff<NonCloneRequest>>();
        assert_debug::<SmartRetry<NonCloneRequest>>();
        assert_send_sync::<ExponentialBackoff<i32>>();
        assert_send_sync::<SmartRetry<i32>>();
        assert_send::<RetryLayer<ExponentialBackoff<i32>>>();
        assert_send::<Retry<ExponentialBackoff<i32>, FailingService>>();
        assert_send::<RetryFuture<ExponentialBackoff<i32>, FailingService, i32>>();

        let policy = ExponentialBackoff::<i32>::new(4, 100, JitterStrategy::Full)
            .with_jitter_seed(0x0123_4567_89ab_cdef);
        let debug = format!("{policy:?}");
        assert!(debug.contains("jitter_seed: \"<redacted>\""));
        assert!(debug.contains("jitter_rng: \"<redacted>\""));
        assert!(!debug.contains("81985529216486895"));
        assert!(!debug.contains("0123456789abcdef"));
    }

    #[test]
    fn max_retries_enforcement() {
        init_test("max_retries_enforcement");

        let mut policy = ExponentialBackoff::<i32>::new(3, 100, JitterStrategy::None);
        let mut retry_results = Vec::new();

        // Simulate retry attempts
        for attempt in 0..6 {
            let request = 42;
            let error_result: Result<&i32, &&str> = Err(&"error");
            let retry_future = policy.retry(&request, error_result);

            let should_retry = retry_future.is_some();
            retry_results.push((attempt, should_retry));

            if should_retry {
                policy.current_attempt += 1;
            }
        }

        // Golden values: should retry for attempts 0, 1, 2 (max_retries=3), then stop
        let expected = vec![
            (0, true),  // First retry (attempt 0 → 1)
            (1, true),  // Second retry (attempt 1 → 2)
            (2, true),  // Third retry (attempt 2 → 3)
            (3, false), // Fourth attempt - should not retry (3 >= max_retries)
            (4, false), // Fifth attempt - should not retry
            (5, false), // Sixth attempt - should not retry
        ];

        for ((attempt, should_retry), (exp_attempt, exp_should_retry)) in
            retry_results.iter().zip(expected.iter())
        {
            crate::assert_with_log!(
                attempt == exp_attempt && should_retry == exp_should_retry,
                format!("max retries attempt {}", attempt),
                *exp_should_retry,
                *should_retry
            );
        }

        crate::test_complete!("max_retries_enforcement");
    }

    #[test]
    fn smart_retry_preserves_classification_and_delegates_request_fork() {
        init_test("smart_retry_preserves_classification_and_delegates_request_fork");

        let idempotent_policy = SmartRetry::<i32>::new(
            3,
            100,
            JitterStrategy::Full,
            RequestClassification::Idempotent,
        )
        .with_jitter_seed(0x534d_4152_5452_4554);
        let non_idempotent_policy = SmartRetry::<i32>::new(
            3,
            100,
            JitterStrategy::Full,
            RequestClassification::NonIdempotent,
        )
        .with_jitter_seed(0x534d_4152_5452_4554);

        // Test classification properties
        let mut results = Vec::new();

        // Non-idempotent retries fail closed unless the caller can prove the
        // error is transport-only.
        let error_result: Result<&i32, &&str> = Err(&"error");
        let success_result: Result<&i32, &&str> = Ok(&42);

        results.push((
            "idempotent_error",
            idempotent_policy.retry(&42, error_result).is_some(),
        ));
        results.push((
            "idempotent_success",
            idempotent_policy.retry(&42, success_result).is_some(),
        ));
        results.push((
            "non_idempotent_error",
            non_idempotent_policy.retry(&42, error_result).is_some(),
        ));
        results.push((
            "non_idempotent_success",
            non_idempotent_policy.retry(&42, success_result).is_some(),
        ));

        let expected = vec![
            ("idempotent_error", true),        // Should retry on error
            ("idempotent_success", false),     // Should not retry on success
            ("non_idempotent_error", false),   // Should fail closed on error
            ("non_idempotent_success", false), // Should not retry on success
        ];

        for ((name, result), (exp_name, exp_result)) in results.iter().zip(expected.iter()) {
            crate::assert_with_log!(
                name == exp_name && result == exp_result,
                format!("classification {}", name),
                *exp_result,
                *result
            );
        }

        let mut smart_sequences = Vec::new();
        let mut direct_sequences = Vec::new();
        for stream_id in [7, 11] {
            let smart = <SmartRetry<i32> as Policy<i32, (), &'static str>>::fork_for_request(
                &idempotent_policy,
                stream_id,
            );
            let direct =
                <ExponentialBackoff<i32> as Policy<i32, (), &'static str>>::fork_for_request(
                    idempotent_policy.backoff(),
                    stream_id,
                );
            smart_sequences.push(jitter_sequence(smart.backoff.clone(), 4));
            direct_sequences.push(jitter_sequence(direct, 4));
            assert_eq!(smart.classification(), RequestClassification::Idempotent);
        }
        assert_eq!(smart_sequences, direct_sequences);
        assert_ne!(smart_sequences[0], smart_sequences[1]);

        crate::test_complete!("smart_retry_preserves_classification_and_delegates_request_fork");
    }

    #[test]
    fn smart_retry_non_idempotent_errors_fail_closed() {
        init_test("smart_retry_non_idempotent_errors_fail_closed");

        let policy = SmartRetry::<i32>::new(
            3,
            10,
            JitterStrategy::None,
            RequestClassification::NonIdempotent,
        );

        let error_result: Result<&i32, &&str> = Err(&"transient");
        crate::assert_with_log!(
            policy.retry(&42, error_result).is_none(),
            "non-idempotent errors are not retried",
            true,
            false
        );

        crate::test_complete!("smart_retry_non_idempotent_errors_fail_closed");
    }

    #[test]
    fn exponential_backoff_future_waits_before_retrying() {
        init_test("exponential_backoff_future_waits_before_retrying");

        let policy = ExponentialBackoff::<i32>::new(3, 10, JitterStrategy::None);
        let error_result: Result<&i32, &&str> = Err(&"transient");
        let mut future = policy
            .retry(&7, error_result)
            .expect("retry should be scheduled");

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        crate::assert_with_log!(
            matches!(future.as_mut().poll(&mut cx), Poll::Pending),
            "backoff delay yields pending before timer fires",
            true,
            false
        );

        std::thread::sleep(Duration::from_millis(25));

        let next_policy = match future.as_mut().poll(&mut cx) {
            Poll::Ready(policy) => policy,
            Poll::Pending => panic!("retry backoff should complete after the delay"),
        };

        crate::assert_with_log!(
            next_policy.current_attempt() == 1,
            "retry advances after delay",
            1usize,
            next_policy.current_attempt()
        );

        crate::test_complete!("exponential_backoff_future_waits_before_retrying");
    }

    #[test]
    fn exponential_backoff_uses_ambient_timer_driver() {
        init_test("exponential_backoff_uses_ambient_timer_driver");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let policy = ExponentialBackoff::<i32>::new(3, 10, JitterStrategy::None);
        let error_result: Result<&i32, &&str> = Err(&"transient");
        let mut future = policy
            .retry(&7, error_result)
            .expect("retry should be scheduled");

        let waker = std::task::Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        crate::assert_with_log!(
            matches!(future.as_mut().poll(&mut poll_cx), Poll::Pending),
            "virtual timer starts pending",
            true,
            false
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "retry delay registered with ambient timer",
            1usize,
            timer.pending_count()
        );

        clock.advance(Duration::from_millis(10).as_nanos() as u64);

        let next_policy = match future.as_mut().poll(&mut poll_cx) {
            Poll::Ready(policy) => policy,
            Poll::Pending => panic!("retry delay should complete after virtual time advance"),
        };

        crate::assert_with_log!(
            next_policy.current_attempt() == 1,
            "retry completes after virtual advance",
            1usize,
            next_policy.current_attempt()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "retry delay clears timer registration",
            0usize,
            timer.pending_count()
        );

        crate::test_complete!("exponential_backoff_uses_ambient_timer_driver");
    }
