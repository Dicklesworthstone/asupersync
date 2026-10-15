//! Poll-level regressions for retry fairness and cancellation-safe admission.

use super::{
    AlwaysRetry, MAX_READY_ATTEMPTS_PER_POLL, NeverRetry, RetryBudget, RetryPolicy,
    RetryResult, RetryTokenBucket, retry,
};
use crate::types::{Outcome, Time};
use std::future::{Future, ready};
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn counting_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

#[test]
fn ready_failures_yield_before_starting_another_attempt() {
    let calls = AtomicU32::new(0);
    let mut operation = Box::pin(retry(
        RetryPolicy::immediate(MAX_READY_ATTEMPTS_PER_POLL * 3 + 1),
        AlwaysRetry,
        || {
            calls.fetch_add(1, Ordering::Relaxed);
            ready(Outcome::<(), &str>::Err("unavailable"))
        },
    ));
    let (wakes, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);

    assert!(operation.as_mut().poll(&mut task).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), MAX_READY_ATTEMPTS_PER_POLL);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);

    assert!(operation.as_mut().poll(&mut task).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), MAX_READY_ATTEMPTS_PER_POLL * 2);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
}

#[test]
fn success_after_multiple_yields_preserves_attempt_order() {
    let calls = AtomicU32::new(0);
    let target = MAX_READY_ATTEMPTS_PER_POLL * 2 + 3;
    let mut operation = Box::pin(retry(RetryPolicy::immediate(target), AlwaysRetry, || {
        let attempt = calls.fetch_add(1, Ordering::Relaxed) + 1;
        ready(if attempt == target {
            Outcome::Ok(attempt)
        } else {
            Outcome::Err(attempt)
        })
    }));
    let (wakes, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);

    for chunk in 1..=2 {
        assert!(operation.as_mut().poll(&mut task).is_pending());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            MAX_READY_ATTEMPTS_PER_POLL * chunk
        );
    }
    assert!(matches!(
        operation.as_mut().poll(&mut task),
        Poll::Ready(RetryResult::Ok(value)) if value == target
    ));
    assert_eq!(calls.load(Ordering::Relaxed), target);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
}

#[test]
fn final_failure_at_the_quantum_boundary_does_not_add_a_yield() {
    let mut operation = Box::pin(retry(
        RetryPolicy::immediate(MAX_READY_ATTEMPTS_PER_POLL),
        AlwaysRetry,
        || ready(Outcome::<(), &str>::Err("last error")),
    ));
    let (wakes, waker) = counting_waker();
    let result = operation.as_mut().poll(&mut Context::from_waker(&waker));
    let Poll::Ready(RetryResult::Failed(error)) = result else {
        panic!("exhaustion is terminal, not a scheduling yield");
    };
    assert_eq!(error.attempts, MAX_READY_ATTEMPTS_PER_POLL);
    assert_eq!(error.final_error, "last error");
    assert_eq!(error.total_delay, Duration::ZERO);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
}

#[test]
fn final_error_and_attempt_count_survive_cooperative_yields() {
    let calls = AtomicU32::new(0);
    let target = MAX_READY_ATTEMPTS_PER_POLL * 2 + 1;
    let operation = retry(RetryPolicy::immediate(target), AlwaysRetry, || {
        let attempt = calls.fetch_add(1, Ordering::Relaxed) + 1;
        ready(Outcome::<(), u32>::Err(attempt))
    });
    // This executor requires wake delivery after an artificial Pending; manual
    // repolling alone would not catch a missing self-wake.
    let RetryResult::Failed(error) = futures_lite::future::block_on(operation) else {
        panic!("all attempts fail");
    };
    assert_eq!(error.attempts, target);
    assert_eq!(error.final_error, target);
    assert_eq!(error.total_delay, Duration::ZERO);
    assert_eq!(calls.load(Ordering::Relaxed), target);
}

#[test]
fn non_retriable_error_returns_without_a_spurious_wake() {
    let calls = AtomicU32::new(0);
    let mut operation = Box::pin(retry(RetryPolicy::immediate(u32::MAX), NeverRetry, || {
        calls.fetch_add(1, Ordering::Relaxed);
        ready(Outcome::<(), &str>::Err("permanent"))
    }));
    let (wakes, waker) = counting_waker();
    assert!(matches!(
        operation.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(RetryResult::Failed(_))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
}

#[test]
fn shared_budget_is_not_charged_again_when_a_yield_resumes() {
    let tokens = MAX_READY_ATTEMPTS_PER_POLL + 2;
    let budget = RetryBudget::new(RetryTokenBucket::new(tokens, 0.0, Time::ZERO));
    let calls = AtomicU32::new(0);
    let mut operation = Box::pin(
        retry(
            RetryPolicy::immediate(MAX_READY_ATTEMPTS_PER_POLL * 3),
            AlwaysRetry,
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                ready(Outcome::<(), &str>::Err("unavailable"))
            },
        )
        .with_budget(budget.clone()),
    );
    let (_, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);

    assert!(operation.as_mut().poll(&mut task).is_pending());
    // Admission of the next retry already took a token before yielding, just
    // as admission takes one before entering a backoff sleep.
    assert_eq!(budget.available(), 2);
    let Poll::Ready(RetryResult::Failed(error)) = operation.as_mut().poll(&mut task) else {
        panic!("the shared retry budget must terminate this loop");
    };
    assert_eq!(error.attempts, tokens + 1);
    assert_eq!(calls.load(Ordering::Relaxed), tokens + 1);
    assert_eq!(budget.available(), 0);
}

struct PinnedAttempt {
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    _pin: PhantomPinned,
}

impl Future for PinnedAttempt {
    type Output = Outcome<u32, &'static str>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_ref().get_ref().polls.fetch_add(1, Ordering::Relaxed) {
            0 => Poll::Pending,
            1 => Poll::Ready(Outcome::Ok(42)),
            _ => panic!("a completed attempt must never be polled again"),
        }
    }
}

impl Drop for PinnedAttempt {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn pending_pinned_attempt_is_retained_and_not_busy_polled() {
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut operation = Box::pin(retry(RetryPolicy::immediate(u32::MAX), AlwaysRetry, || {
        PinnedAttempt {
            polls: Arc::clone(&polls),
            drops: Arc::clone(&drops),
            _pin: PhantomPinned,
        }
    }));
    let (wakes, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);

    assert!(operation.as_mut().poll(&mut task).is_pending());
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    assert!(matches!(
        operation.as_mut().poll(&mut task),
        Poll::Ready(RetryResult::Ok(42))
    ));
    assert_eq!(polls.load(Ordering::Relaxed), 2);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
