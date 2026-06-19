//! Runnable proof for configurable circuit-breaker failure classification
//! (bead `asupersync-server-stack-hardening-eeexl1.7`, AC4).
//!
//! Drives the real `CircuitBreaker` service (with a custom `ResultClassifier`)
//! over a scripted inner service and asserts the runtime behaviour the
//! compile-only inline tests describe: a 5xx-shaped `Ok` response counts as a
//! breaker failure (and still reaches the caller), a 4xx is ignored, a
//! cancellation is ignored while other errors count, and the default classifier
//! preserves Ok=success / Err=failure.
//!
//! Run with: `cargo test --test circuit_breaker_classification_proof --features test-internals`.

use asupersync::combinator::circuit_breaker::{CircuitBreakerPolicy, FailurePredicate, State};
use asupersync::service::Service;
use asupersync::service::circuit_breaker::{
    CircuitBreaker, CircuitBreakerError, Disposition, FnClassifier, ResultClassifier,
};
use asupersync::types::Time;
use std::collections::VecDeque;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

fn t0() -> Time {
    Time::from_millis(0)
}

struct Scripted {
    steps: VecDeque<Result<&'static str, &'static str>>,
}

impl Scripted {
    fn new(steps: impl IntoIterator<Item = Result<&'static str, &'static str>>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }
}

impl Service<()> for Scripted {
    type Response = &'static str;
    type Error = &'static str;
    type Future = Ready<Result<&'static str, &'static str>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        ready(self.steps.pop_front().expect("scripted service exhausted"))
    }
}

fn http_classifier(result: &Result<&'static str, &'static str>) -> Disposition {
    match result {
        Ok(status) if status.starts_with('5') => Disposition::Failure,
        Ok(status) if status.starts_with('4') => Disposition::Ignore,
        Ok(_) => Disposition::Success,
        Err(error) if *error == "cancelled" => Disposition::Ignore,
        Err(_) => Disposition::Failure,
    }
}

fn policy() -> CircuitBreakerPolicy {
    CircuitBreakerPolicy {
        name: "test".to_string(),
        failure_threshold: 2,
        success_threshold: 1,
        open_duration: Duration::from_millis(10),
        half_open_max_probes: 1,
        failure_predicate: FailurePredicate::AllErrors,
        ..CircuitBreakerPolicy::default()
    }
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    Pin::new(future).poll(&mut cx)
}

fn run_call<C>(
    svc: &mut CircuitBreaker<Scripted, C>,
) -> Poll<Result<&'static str, CircuitBreakerError<&'static str>>>
where
    C: ResultClassifier<&'static str, &'static str> + Clone + Unpin,
{
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let _ = svc.poll_ready(&mut cx);
    let mut future = svc.call(());
    poll_once(&mut future)
}

#[test]
fn five_xx_response_counts_as_failure_and_opens_breaker() {
    let mut svc = CircuitBreaker::with_classifier_and_time(
        Scripted::new([Ok("500"), Ok("503")]),
        policy(),
        t0,
        FnClassifier(http_classifier),
    );
    // Each 5xx is still delivered to the caller as Ok(..) but counts as a
    // failure; two of them trip the breaker (threshold 2).
    for _ in 0..2 {
        assert!(matches!(run_call(&mut svc), Poll::Ready(Ok(_))));
    }
    assert!(matches!(svc.state(), State::Open { .. }));
}

#[test]
fn four_xx_is_ignored_and_breaker_stays_closed() {
    let mut svc = CircuitBreaker::with_classifier_and_time(
        Scripted::new([Ok("404"), Ok("400"), Ok("403")]),
        policy(),
        t0,
        FnClassifier(http_classifier),
    );
    for _ in 0..3 {
        assert!(matches!(run_call(&mut svc), Poll::Ready(Ok(_))));
    }
    assert_eq!(svc.state(), State::Closed { failures: 0 });
    assert_eq!(svc.metrics().total_ignored_errors, 3);
}

#[test]
fn cancellation_is_ignored_but_other_errors_count() {
    let mut svc = CircuitBreaker::with_classifier_and_time(
        Scripted::new([Err("cancelled"), Err("cancelled"), Err("boom"), Err("boom")]),
        policy(),
        t0,
        FnClassifier(http_classifier),
    );
    for _ in 0..2 {
        assert!(matches!(
            run_call(&mut svc),
            Poll::Ready(Err(CircuitBreakerError::Inner("cancelled")))
        ));
    }
    assert_eq!(svc.state(), State::Closed { failures: 0 });
    assert_eq!(svc.metrics().total_ignored_errors, 2);

    for _ in 0..2 {
        let _ = run_call(&mut svc);
    }
    assert!(matches!(svc.state(), State::Open { .. }));
}

#[test]
fn default_classifier_preserves_ok_success_err_failure() {
    let mut svc = CircuitBreaker::with_time_getter(
        Scripted::new([Ok("x"), Err("e1"), Err("e2")]),
        policy(),
        t0,
    );
    assert!(matches!(run_call(&mut svc), Poll::Ready(Ok("x"))));
    assert_eq!(svc.state(), State::Closed { failures: 0 });
    for _ in 0..2 {
        let _ = run_call(&mut svc);
    }
    assert!(matches!(svc.state(), State::Open { .. }));
}
