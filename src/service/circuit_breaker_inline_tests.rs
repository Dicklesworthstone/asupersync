    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]

    use super::*;
    use crate::combinator::circuit_breaker::FailurePredicate;
    use crate::service::retry::{Policy, Retry, RetryError};
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::future::{Future, Ready, ready};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;
    use std::time::Duration;

    std::thread_local! {
        static TEST_NOW_MS: Cell<u64> = const { Cell::new(0) };
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
        set_test_time_ms(0);
    }

    fn test_time() -> Time {
        Time::from_millis(TEST_NOW_MS.with(Cell::get))
    }

    fn set_test_time_ms(ms: u64) {
        TEST_NOW_MS.with(|now| now.set(ms));
    }

    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(future).poll(&mut cx)
    }

    fn test_policy() -> CircuitBreakerPolicy {
        CircuitBreakerPolicy {
            name: "test-endpoint".to_string(),
            failure_threshold: 2,
            success_threshold: 1,
            open_duration: Duration::from_millis(10),
            half_open_max_probes: 1,
            ..CircuitBreakerPolicy::default()
        }
    }

    #[derive(Clone, Debug)]
    enum Step {
        Ok(&'static str),
        Err(&'static str),
        Pending,
    }

    #[derive(Debug)]
    struct ScriptedService {
        steps: VecDeque<Step>,
        calls: usize,
    }

    impl ScriptedService {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                calls: 0,
            }
        }

        const fn calls(&self) -> usize {
            self.calls
        }
    }

    impl Service<()> for ScriptedService {
        type Response = &'static str;
        type Error = &'static str;
        type Future = ScriptedFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls = self.calls.saturating_add(1);
            match self.steps.pop_front().expect("scripted service exhausted") {
                Step::Ok(value) => ScriptedFuture::ready(Ok(value)),
                Step::Err(error) => ScriptedFuture::ready(Err(error)),
                Step::Pending => ScriptedFuture::pending(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SharedScriptedService {
        steps: std::sync::Arc<Mutex<VecDeque<Step>>>,
        calls: std::sync::Arc<AtomicUsize>,
    }

    impl SharedScriptedService {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: std::sync::Arc::new(Mutex::new(steps.into_iter().collect())),
                calls: std::sync::Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Service<()> for SharedScriptedService {
        type Response = &'static str;
        type Error = &'static str;
        type Future = ScriptedFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .steps
                .lock()
                .expect("scripted service mutex poisoned")
                .pop_front()
                .expect("scripted service exhausted");
            match step {
                Step::Ok(value) => ScriptedFuture::ready(Ok(value)),
                Step::Err(error) => ScriptedFuture::ready(Err(error)),
                Step::Pending => ScriptedFuture::pending(),
            }
        }
    }

    #[derive(Debug)]
    struct ScriptedFuture {
        result: Option<Result<&'static str, &'static str>>,
        pending: bool,
    }

    impl ScriptedFuture {
        const fn ready(result: Result<&'static str, &'static str>) -> Self {
            Self {
                result: Some(result),
                pending: false,
            }
        }

        const fn pending() -> Self {
            Self {
                result: None,
                pending: true,
            }
        }
    }

    impl Future for ScriptedFuture {
        type Output = Result<&'static str, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.pending {
                Poll::Pending
            } else {
                Poll::Ready(self.result.take().expect("future polled after completion"))
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct RetryInnerOnly {
        remaining: usize,
    }

    impl Policy<(), &'static str, CircuitBreakerError<&'static str>> for RetryInnerOnly {
        type Future = Ready<Self>;

        fn retry(
            &self,
            _req: &(),
            result: Result<&&'static str, &CircuitBreakerError<&'static str>>,
        ) -> Option<Self::Future> {
            match result {
                Err(error) if error.is_inner() && self.remaining > 0 => Some(ready(Self {
                    remaining: self.remaining - 1,
                })),
                Err(error) if error.is_rejected() => None,
                Err(_) | Ok(_) => None,
            }
        }

        fn clone_request(&self, _req: &()) -> Option<()> {
            Some(())
        }
    }

    // ---- AC4: configurable failure classification --------------------------

    /// Canonical HTTP-style classifier: 5xx counts as failure, 4xx is ignored
    /// (the upstream answered, just not what the caller wanted), `"cancelled"`
    /// errors are ignored, all other errors count as failures.
    fn http_like_classifier(result: &Result<&'static str, &'static str>) -> Disposition {
        match result {
            Ok(status) if status.starts_with('5') => Disposition::Failure,
            Ok(status) if status.starts_with('4') => Disposition::Ignore,
            Ok(_) => Disposition::Success,
            Err(error) if *error == "cancelled" => Disposition::Ignore,
            Err(_) => Disposition::Failure,
        }
    }

    fn classifier_policy() -> CircuitBreakerPolicy {
        // The classifier is the sole decider, so the inner predicate counts
        // everything handed to `record_failure`.
        CircuitBreakerPolicy {
            failure_predicate: FailurePredicate::AllErrors,
            ..test_policy()
        }
    }

    #[test]
    fn classifier_counts_5xx_response_as_failure() {
        init_test("classifier_counts_5xx_response_as_failure");
        let mut service = CircuitBreaker::with_classifier_and_time(
            ScriptedService::new([Step::Ok("500"), Step::Ok("503")]),
            classifier_policy(),
            test_time,
            FnClassifier(http_like_classifier),
        );

        // Two 5xx responses — each still delivered to the caller as `Ok(..)` —
        // are recorded as failures and trip the breaker (threshold 2).
        for _ in 0..2 {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let mut fut = service.call(());
            assert!(matches!(poll_once(&mut fut), Poll::Ready(Ok(_))));
        }
        assert!(matches!(service.state(), State::Open { .. }));

        // The breaker is now open: the next call is rejected before reaching
        // the (exhausted) inner service.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = service.poll_ready(&mut cx);
        let mut fut = service.call(());
        assert!(matches!(
            poll_once(&mut fut),
            Poll::Ready(Err(CircuitBreakerError::Open { .. }))
        ));
    }

    #[test]
    fn classifier_ignores_4xx_response() {
        init_test("classifier_ignores_4xx_response");
        let mut service = CircuitBreaker::with_classifier_and_time(
            ScriptedService::new([Step::Ok("404"), Step::Ok("400"), Step::Ok("403")]),
            classifier_policy(),
            test_time,
            FnClassifier(http_like_classifier),
        );

        for _ in 0..3 {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let mut fut = service.call(());
            assert!(matches!(poll_once(&mut fut), Poll::Ready(Ok(_))));
        }

        // 4xx never counts toward opening; the breaker stays closed with no
        // failures, and each is tallied as an ignored call.
        assert_eq!(service.state(), State::Closed { failures: 0 });
        assert_eq!(service.metrics().total_ignored_errors, 3);
    }

    #[test]
    fn classifier_ignores_cancelled_but_counts_other_errors() {
        init_test("classifier_ignores_cancelled_but_counts_other_errors");
        let mut service = CircuitBreaker::with_classifier_and_time(
            ScriptedService::new([
                Step::Err("cancelled"),
                Step::Err("cancelled"),
                Step::Err("boom"),
                Step::Err("boom"),
            ]),
            classifier_policy(),
            test_time,
            FnClassifier(http_like_classifier),
        );

        // Cancellations are ignored — the breaker stays closed.
        for _ in 0..2 {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let mut fut = service.call(());
            assert!(matches!(
                poll_once(&mut fut),
                Poll::Ready(Err(CircuitBreakerError::Inner("cancelled")))
            ));
        }
        assert_eq!(service.state(), State::Closed { failures: 0 });
        assert_eq!(service.metrics().total_ignored_errors, 2);

        // Real errors do count and open the breaker.
        for _ in 0..2 {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let _ = service.poll_ready(&mut cx);
            let mut fut = service.call(());
            let _ = poll_once(&mut fut);
        }
        assert!(matches!(service.state(), State::Open { .. }));
    }

    #[test]
    fn default_classifier_preserves_ok_success_err_failure() {
        init_test("default_classifier_preserves_ok_success_err_failure");
        // Without a custom classifier, behaviour is unchanged: Ok => success,
        // Err => failure (subject to the policy predicate).
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Ok("ok"), Step::Err("e1"), Step::Err("e2")]),
            classifier_policy(),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = service.poll_ready(&mut cx);
        let mut ok = service.call(());
        assert!(matches!(poll_once(&mut ok), Poll::Ready(Ok("ok"))));
        assert_eq!(service.state(), State::Closed { failures: 0 });

        for _ in 0..2 {
            let _ = service.poll_ready(&mut cx);
            let mut fut = service.call(());
            let _ = poll_once(&mut fut);
        }
        assert!(matches!(service.state(), State::Open { .. }));
    }

    #[test]
    fn failure_burst_opens_rejects_half_open_and_recovers() {
        init_test("failure_burst_opens_rejects_half_open_and_recovers");
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Err("e1"), Step::Err("e2"), Step::Ok("recovered")]),
            test_policy(),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_ready = service.poll_ready(&mut cx);
        let first_ready_ok = matches!(first_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ready_ok, "first ready", true, first_ready_ok);
        let mut first = service.call(());
        let first_result = poll_once(&mut first);
        let first_error = matches!(
            first_result,
            Poll::Ready(Err(CircuitBreakerError::Inner("e1")))
        );
        crate::assert_with_log!(first_error, "first error", true, first_error);
        crate::assert_with_log!(
            service.state() == (State::Closed { failures: 1 }),
            "one failure recorded",
            State::Closed { failures: 1 },
            service.state()
        );

        let second_ready = service.poll_ready(&mut cx);
        let second_ready_ok = matches!(second_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(second_ready_ok, "second ready", true, second_ready_ok);
        let mut second = service.call(());
        let second_result = poll_once(&mut second);
        let second_error = matches!(
            second_result,
            Poll::Ready(Err(CircuitBreakerError::Inner("e2")))
        );
        crate::assert_with_log!(second_error, "second error", true, second_error);
        let breaker_open = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(breaker_open, "breaker open", true, breaker_open);

        let calls_after_open = service.inner().calls();
        let open_ready = service.poll_ready(&mut cx);
        let open_ready_ok = matches!(open_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(open_ready_ok, "open ready delegates", true, open_ready_ok);
        let mut rejected = service.call(());
        let rejected_result = poll_once(&mut rejected);
        let rejected_open = matches!(
            rejected_result,
            Poll::Ready(Err(CircuitBreakerError::Open { .. }))
        );
        crate::assert_with_log!(rejected_open, "open rejection", true, rejected_open);
        let metrics_after_rejection = service.metrics();
        crate::assert_with_log!(
            metrics_after_rejection.total_rejected == 1,
            "open rejection counted",
            1,
            metrics_after_rejection.total_rejected
        );
        crate::assert_with_log!(
            service.inner().calls() == calls_after_open,
            "open rejection did not call inner",
            calls_after_open,
            service.inner().calls()
        );

        set_test_time_ms(11);
        let probe_ready = service.poll_ready(&mut cx);
        let probe_ready_ok = matches!(probe_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(probe_ready_ok, "probe ready", true, probe_ready_ok);
        let mut probe = service.call(());
        let probe_result = poll_once(&mut probe);
        let probe_recovered = matches!(probe_result, Poll::Ready(Ok("recovered")));
        crate::assert_with_log!(probe_recovered, "probe recovered", true, probe_recovered);
        crate::assert_with_log!(
            service.state() == (State::Closed { failures: 0 }),
            "breaker closed",
            State::Closed { failures: 0 },
            service.state()
        );
        let metrics = service.metrics();
        crate::assert_with_log!(
            metrics.times_opened == 1,
            "opened once",
            1,
            metrics.times_opened
        );
        crate::assert_with_log!(
            metrics.times_closed == 1,
            "closed once",
            1,
            metrics.times_closed
        );
        crate::test_complete!("failure_burst_opens_rejects_half_open_and_recovers");
    }

    #[test]
    fn call_without_poll_ready_fails_closed() {
        init_test("call_without_poll_ready_fails_closed");
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Ok("unused")]),
            test_policy(),
            test_time,
        );

        let mut future = service.call(());
        let result = poll_once(&mut future);
        let not_ready = matches!(result, Poll::Ready(Err(CircuitBreakerError::NotReady)));
        crate::assert_with_log!(not_ready, "not ready", true, not_ready);
        crate::assert_with_log!(
            service.inner().calls() == 0,
            "inner not called",
            0,
            service.inner().calls()
        );
        crate::test_complete!("call_without_poll_ready_fails_closed");
    }

    #[test]
    fn failure_predicate_ignores_non_counting_errors() {
        fn is_fatal(error: &str) -> bool {
            error == "fatal"
        }

        init_test("failure_predicate_ignores_non_counting_errors");
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            failure_predicate: FailurePredicate::ByType(is_fatal),
            ..test_policy()
        };
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Err("soft"), Step::Err("soft"), Step::Err("fatal")]),
            policy,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for attempt in 1..=2 {
            let ready = service.poll_ready(&mut cx);
            let ready_ok = matches!(ready, Poll::Ready(Ok(())));
            crate::assert_with_log!(ready_ok, "soft error ready", true, ready_ok);
            let mut future = service.call(());
            let result = poll_once(&mut future);
            let soft_error = matches!(result, Poll::Ready(Err(CircuitBreakerError::Inner("soft"))));
            crate::assert_with_log!(soft_error, "soft error returned", true, soft_error);
            crate::assert_with_log!(
                service.state() == (State::Closed { failures: 0 }),
                "ignored errors keep closed streak clear",
                State::Closed { failures: 0 },
                service.state()
            );
            crate::assert_with_log!(
                service.metrics().total_ignored_errors == attempt,
                "ignored error counted",
                attempt,
                service.metrics().total_ignored_errors
            );
        }

        let fatal_ready = service.poll_ready(&mut cx);
        let fatal_ready_ok = matches!(fatal_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(fatal_ready_ok, "fatal ready", true, fatal_ready_ok);
        let mut fatal = service.call(());
        let fatal_result = poll_once(&mut fatal);
        let fatal_error = matches!(
            fatal_result,
            Poll::Ready(Err(CircuitBreakerError::Inner("fatal")))
        );
        crate::assert_with_log!(fatal_error, "fatal error returned", true, fatal_error);
        let opened = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(opened, "fatal error opens", true, opened);
        let metrics = service.metrics();
        crate::assert_with_log!(
            metrics.total_ignored_errors == 2,
            "two ignored errors",
            2,
            metrics.total_ignored_errors
        );
        crate::assert_with_log!(
            metrics.total_failure == 1,
            "one counted failure",
            1,
            metrics.total_failure
        );
        crate::assert_with_log!(
            service.inner().calls() == 3,
            "all scripted attempts reached inner",
            3,
            service.inner().calls()
        );
        crate::test_complete!("failure_predicate_ignores_non_counting_errors");
    }

    #[test]
    fn retry_policy_can_stop_on_open_breaker_rejection() {
        init_test("retry_policy_can_stop_on_open_breaker_rejection");
        let shared = SharedScriptedService::new([Step::Err("fatal"), Step::Ok("unexpected")]);
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            ..test_policy()
        };
        let breaker = CircuitBreaker::with_time_getter(shared.clone(), policy, test_time);
        let mut service = Retry::new(breaker, RetryInnerOnly { remaining: 3 });

        let mut future = service.call(());
        let result = poll_once(&mut future);
        let stopped_on_open = matches!(
            result,
            Poll::Ready(Err(RetryError::Inner(ref error))) if error.is_open()
        );
        crate::assert_with_log!(
            stopped_on_open,
            "retry stops on open breaker",
            true,
            stopped_on_open
        );
        crate::assert_with_log!(
            shared.calls() == 1,
            "retry did not storm inner through open breaker",
            1,
            shared.calls()
        );
        crate::test_complete!("retry_policy_can_stop_on_open_breaker_rejection");
    }

    #[test]
    fn dropped_half_open_probe_reopens_without_stranding_probe() {
        init_test("dropped_half_open_probe_reopens_without_stranding_probe");
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_millis(10),
            half_open_max_probes: 1,
            ..test_policy()
        };
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Err("open"), Step::Pending, Step::Ok("later")]),
            policy,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = service.poll_ready(&mut cx);
        let mut opener = service.call(());
        let _ = poll_once(&mut opener);
        let opened = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(opened, "opened", true, opened);

        set_test_time_ms(11);
        let _ = service.poll_ready(&mut cx);
        let mut pending_probe = service.call(());
        let probe_poll = poll_once(&mut pending_probe);
        let probe_pending = probe_poll.is_pending();
        crate::assert_with_log!(probe_pending, "probe pending", true, probe_pending);
        let probe_active = matches!(
            service.state(),
            State::HalfOpen {
                probes_active: 1,
                ..
            }
        );
        crate::assert_with_log!(probe_active, "probe active", true, probe_active);

        drop(pending_probe);
        let reopened = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(reopened, "drop reopens", true, reopened);

        let _ = service.poll_ready(&mut cx);
        let mut rejected = service.call(());
        let rejected_result = poll_once(&mut rejected);
        let rejected_open = matches!(
            rejected_result,
            Poll::Ready(Err(CircuitBreakerError::Open { .. }))
        );
        crate::assert_with_log!(
            rejected_open,
            "rejected after dropped probe",
            true,
            rejected_open
        );
        crate::test_complete!("dropped_half_open_probe_reopens_without_stranding_probe");
    }
