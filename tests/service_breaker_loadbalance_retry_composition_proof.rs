//! Runnable 3-layer composition proof for service resilience
//! (bead `asupersync-server-stack-hardening-eeexl1.7`, AC5).
//!
//! AC5's core invariant — "retry treats a breaker-open rejection as
//! non-retryable, so retries never storm an open breaker's backend" — is
//! covered inline (compile-validated) by
//! `service::circuit_breaker::tests::retry_policy_can_stop_on_open_breaker_rejection`.
//! This file makes the invariant RUNNABLE and proves it survives the full
//! `load_balance -> retry -> circuit_breaker -> backend` stack the bead calls
//! "the heart":
//!   1. `retry_does_not_storm_open_breaker`: Retry over CircuitBreaker —
//!      once the breaker opens, the retry loop stops on the Open rejection and
//!      the real backend is never called again (no storm).
//!   2. `load_balancer_over_retry_over_breaker_no_storm`: the same invariant
//!      survives being wrapped by the LoadBalancer (single backend).
//!   3. `load_balancer_routes_healthy_and_bounds_open_breaker`: with one
//!      failing and one healthy backend (each its own breaker), the failing
//!      backend's real service is hit only up to the failure threshold (bounded
//!      — no storm) while the healthy backend keeps serving.
//!
//! Driven synchronously with a no-op waker over `Ready` backend futures — no
//! runtime required — so it is deterministic and links the library in normal
//! (non-test) mode, sidestepping any in-crate `#[cfg(test)]` churn.
//!
//! Run with:
//! `cargo test --test service_breaker_loadbalance_retry_composition_proof`.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use asupersync::combinator::circuit_breaker::{CircuitBreakerPolicy, FailurePredicate};
use asupersync::service::Service;
use asupersync::service::circuit_breaker::{CircuitBreaker, CircuitBreakerError};
use asupersync::service::load_balance::{LoadBalanceError, LoadBalancer, RoundRobin};
use asupersync::service::retry::{Policy, Retry, RetryError};
use asupersync::types::Time;

fn t0() -> Time {
    Time::from_millis(0)
}

/// A backend whose clones share one call counter, so the call count survives
/// `Retry`/`LoadBalancer` cloning the service stack — letting us prove "the
/// real backend was hit exactly N times" through the composed layers.
#[derive(Clone)]
struct SharedBackend {
    inner: Arc<BackendInner>,
}

struct BackendInner {
    calls: AtomicUsize,
    always_err: bool,
}

impl SharedBackend {
    fn always_err() -> Self {
        Self {
            inner: Arc::new(BackendInner {
                calls: AtomicUsize::new(0),
                always_err: true,
            }),
        }
    }

    fn always_ok() -> Self {
        Self {
            inner: Arc::new(BackendInner {
                calls: AtomicUsize::new(0),
                always_err: false,
            }),
        }
    }

    fn calls(&self) -> usize {
        self.inner.calls.load(Ordering::SeqCst)
    }
}

impl Service<()> for SharedBackend {
    type Response = &'static str;
    type Error = &'static str;
    type Future = Ready<Result<&'static str, &'static str>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        if self.inner.always_err {
            ready(Err("boom"))
        } else {
            ready(Ok("ok"))
        }
    }
}

/// Retry policy: retry generic errors up to a budget, but treat a
/// circuit-breaker-open rejection as terminal (non-retryable). This is the
/// classifier the bead requires — it is what prevents the retry storm.
#[derive(Clone)]
struct StopOnOpen {
    remaining: usize,
}

impl Policy<(), &'static str, CircuitBreakerError<&'static str>> for StopOnOpen {
    type Future = Ready<Self>;

    fn retry(
        &self,
        _req: &(),
        result: Result<&&'static str, &CircuitBreakerError<&'static str>>,
    ) -> Option<Self::Future> {
        match result {
            Ok(_) => None,
            // Only the inner backend error is retryable. Every breaker-control
            // rejection (Open / HalfOpenFull / NotReady / PolledAfterCompletion)
            // is terminal: retrying it just burns the budget and would stampede
            // the backend once the breaker recovers. This is the no-storm
            // invariant the bead requires.
            Err(CircuitBreakerError::Inner(_)) => {
                if self.remaining == 0 {
                    None
                } else {
                    Some(ready(StopOnOpen {
                        remaining: self.remaining - 1,
                    }))
                }
            }
            Err(_) => None,
        }
    }

    fn clone_request(&self, _req: &()) -> Option<()> {
        Some(())
    }
}

fn breaker_policy(failure_threshold: u32) -> CircuitBreakerPolicy {
    CircuitBreakerPolicy {
        name: "eeexl1.7-ac5".to_string(),
        failure_threshold,
        success_threshold: 1,
        // Long open window so the breaker stays open for the whole test.
        open_duration: Duration::from_secs(3600),
        half_open_max_probes: 1,
        failure_predicate: FailurePredicate::AllErrors,
        ..CircuitBreakerPolicy::default()
    }
}

/// Drive a future to completion with a no-op waker (backends are `Ready`, so
/// this resolves in a bounded number of polls).
fn drive<F: Future + Unpin>(future: &mut F) -> F::Output {
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..10_000 {
        if let Poll::Ready(out) = Pin::new(&mut *future).poll(&mut cx) {
            return out;
        }
    }
    panic!("composed service future did not complete");
}

#[test]
fn retry_does_not_storm_open_breaker() {
    let backend = SharedBackend::always_err();
    let breaker = CircuitBreaker::with_time_getter(backend.clone(), breaker_policy(1), t0);
    let mut service = Retry::new(breaker, StopOnOpen { remaining: 8 });

    let mut future = Box::pin(service.call(()));
    let result = drive(&mut future);

    // The retry loop fires the backend once (which trips the threshold-1
    // breaker), then the next attempt hits the now-open breaker and the policy
    // refuses to retry it — so the backend is hit exactly once.
    assert_eq!(
        backend.calls(),
        1,
        "retry must not storm the backend through an open breaker"
    );
    match result {
        Err(RetryError::Inner(err)) => {
            assert!(
                err.is_open(),
                "expected breaker-open rejection, got {err:?}"
            );
        }
        other => panic!("expected RetryError::Inner(Open), got {other:?}"),
    }
}

#[test]
fn load_balancer_over_retry_over_breaker_no_storm() {
    let backend = SharedBackend::always_err();
    let breaker = CircuitBreaker::with_time_getter(backend.clone(), breaker_policy(1), t0);
    let retry = Retry::new(breaker, StopOnOpen { remaining: 8 });
    let lb = LoadBalancer::new(RoundRobin::new(), vec![retry]);

    // Several requests through the full 3-layer stack.
    for _ in 0..5 {
        let mut future = Box::pin(lb.call_balanced(()).expect("backend is ready"));
        let result = drive(&mut future);
        match result {
            Err(LoadBalanceError::Inner(RetryError::Inner(err))) => {
                assert!(
                    err.is_open(),
                    "expected breaker-open rejection, got {err:?}"
                );
            }
            other => panic!("expected LB->Retry->Open rejection, got {other:?}"),
        }
    }

    // Across all 5 composed requests the real backend was hit exactly once:
    // the first request tripped the breaker, every later attempt short-circuits
    // on the open breaker without reaching the backend.
    assert_eq!(
        backend.calls(),
        1,
        "load-balanced retry must not storm the backend through an open breaker"
    );
}

#[test]
fn load_balancer_routes_healthy_and_bounds_open_breaker() {
    let failing = SharedBackend::always_err();
    let healthy = SharedBackend::always_ok();

    let failing_stack = Retry::new(
        CircuitBreaker::with_time_getter(failing.clone(), breaker_policy(1), t0),
        StopOnOpen { remaining: 8 },
    );
    let healthy_stack = Retry::new(
        CircuitBreaker::with_time_getter(healthy.clone(), breaker_policy(1), t0),
        StopOnOpen { remaining: 8 },
    );

    let lb = LoadBalancer::new(RoundRobin::new(), vec![failing_stack, healthy_stack]);

    let mut healthy_ok = 0usize;
    for _ in 0..10 {
        let mut future = Box::pin(lb.call_balanced(()).expect("a backend is ready"));
        match drive(&mut future) {
            Ok("ok") => healthy_ok += 1,
            Ok(other) => panic!("unexpected ok response {other:?}"),
            Err(LoadBalanceError::Inner(RetryError::Inner(err))) => {
                assert!(
                    err.is_open() || matches!(err, CircuitBreakerError::Inner("boom")),
                    "failing backend should only ever surface its own error or an open breaker, got {err:?}"
                );
            }
            other => panic!("unexpected composed outcome {other:?}"),
        }
    }

    // The failing backend's real service is bounded to the failure threshold (1)
    // — round-robin keeps selecting it, but its open breaker absorbs every later
    // attempt instead of storming the backend.
    assert_eq!(
        failing.calls(),
        1,
        "failing backend must be hit only up to the breaker threshold (no storm)"
    );
    // The healthy backend kept serving its share of the round-robin traffic.
    assert!(
        healthy.calls() >= 1 && healthy_ok == healthy.calls(),
        "healthy backend should serve its requests successfully: ok={healthy_ok} calls={}",
        healthy.calls()
    );
}
