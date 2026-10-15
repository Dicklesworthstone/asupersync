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

// Keep these tests in the retry module so they use the same cfg(test) context
// constructor as the cancellation primitives, without a test-internals feature.
use super::RetryIf;
use crate::cx::Cx;
use crate::types::CancelKind;
use std::future::poll_fn;
use std::sync::atomic::AtomicBool;

#[test]
fn cancellation_published_by_an_attempt_skips_predicate_and_budget() {
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context.clone()));
    let budget = RetryBudget::new(RetryTokenBucket::new(3, 0.0, Time::ZERO));
    let predicates = AtomicU32::new(0);
    let calls = AtomicU32::new(0);
    let mut operation = Box::pin(
        retry(
            RetryPolicy::immediate(10),
            RetryIf(|_: &&str, _| {
                predicates.fetch_add(1, Ordering::Relaxed);
                true
            }),
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                let context = context.clone();
                poll_fn(move |_| {
                    context.cancel_fast(CancelKind::User);
                    Poll::Ready(Outcome::<(), &str>::Err("interrupted attempt"))
                })
            },
        )
        .with_budget(budget.clone()),
    );

    assert!(matches!(
        operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(RetryResult::Cancelled(reason)) if reason.kind == CancelKind::User
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(predicates.load(Ordering::Relaxed), 0);
    assert_eq!(budget.available(), 3);
}

#[test]
fn cancellation_from_a_predicate_does_not_spend_a_retry_token() {
    for decision in [false, true] {
        let context = Cx::for_testing();
        let _current = Cx::set_current(Some(context.clone()));
        let budget = RetryBudget::new(RetryTokenBucket::new(3, 0.0, Time::ZERO));
        let calls = AtomicU32::new(0);
        let predicates = AtomicU32::new(0);
        let mut operation = Box::pin(
            retry(
                RetryPolicy::immediate(10),
                RetryIf(|_: &&str, _| {
                    predicates.fetch_add(1, Ordering::Relaxed);
                    context.cancel_fast(CancelKind::User);
                    decision
                }),
                || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    ready(Outcome::<(), &str>::Err("transient"))
                },
            )
            .with_budget(budget.clone()),
        );

        assert!(matches!(
            operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(RetryResult::Cancelled(_))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(predicates.load(Ordering::Relaxed), 1);
        assert_eq!(budget.available(), 3);
    }
}

#[test]
fn cancellation_after_a_cooperative_yield_does_not_start_another_attempt() {
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context.clone()));
    let calls = AtomicU32::new(0);
    let mut operation = Box::pin(retry(
        RetryPolicy::immediate(MAX_READY_ATTEMPTS_PER_POLL * 3),
        AlwaysRetry,
        || {
            calls.fetch_add(1, Ordering::Relaxed);
            ready(Outcome::<(), &str>::Err("unavailable"))
        },
    ));
    let (_, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);
    assert!(operation.as_mut().poll(&mut task).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), MAX_READY_ATTEMPTS_PER_POLL);

    context.cancel_fast(CancelKind::User);
    assert!(matches!(
        operation.as_mut().poll(&mut task),
        Poll::Ready(RetryResult::Cancelled(_))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), MAX_READY_ATTEMPTS_PER_POLL);
}

struct DrainingAttempt {
    context: Cx,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    terminal: Arc<AtomicBool>,
    _pin: PhantomPinned,
}

impl Future for DrainingAttempt {
    type Output = Outcome<(), &'static str>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref().get_ref();
        match this.polls.fetch_add(1, Ordering::Relaxed) {
            0 | 1 => Poll::Pending,
            2 => {
                assert!(this.context.checkpoint().is_err());
                this.terminal.store(true, Ordering::Relaxed);
                Poll::Ready(Outcome::Cancelled(
                    this.context.cancel_reason().expect("cancellation was published"),
                ))
            }
            _ => panic!("drained future was polled after completion"),
        }
    }
}

impl Drop for DrainingAttempt {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn cancellation_keeps_polling_a_pending_child_until_it_drains() {
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context.clone()));
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let terminal = Arc::new(AtomicBool::new(false));
    let mut operation = Box::pin(retry(RetryPolicy::immediate(10), AlwaysRetry, || {
        DrainingAttempt {
            context: context.clone(),
            polls: Arc::clone(&polls),
            drops: Arc::clone(&drops),
            terminal: Arc::clone(&terminal),
            _pin: PhantomPinned,
        }
    }));
    let mut task = Context::from_waker(Waker::noop());

    assert!(operation.as_mut().poll(&mut task).is_pending());
    context.cancel_fast(CancelKind::User);
    assert!(operation.as_mut().poll(&mut task).is_pending());
    assert_eq!(polls.load(Ordering::Relaxed), 2);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(!terminal.load(Ordering::Relaxed));
    assert!(matches!(
        operation.as_mut().poll(&mut task),
        Poll::Ready(RetryResult::Cancelled(_))
    ));
    assert_eq!(polls.load(Ordering::Relaxed), 3);
    assert!(terminal.load(Ordering::Relaxed));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn a_successful_attempt_still_wins_its_race_with_cancellation() {
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context.clone()));
    let mut operation = Box::pin(retry(RetryPolicy::immediate(10), AlwaysRetry, || {
        let context = context.clone();
        poll_fn(move |_| {
            context.cancel_fast(CancelKind::User);
            Poll::Ready(Outcome::<u32, &str>::Ok(42))
        })
    }));

    assert!(matches!(
        operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(RetryResult::Ok(42))
    ));
}

#[test]
fn cancelling_one_caller_preserves_the_shared_budget_for_another() {
    let budget = RetryBudget::new(RetryTokenBucket::new(3, 0.0, Time::ZERO));
    {
        let context = Cx::for_testing();
        let _current = Cx::set_current(Some(context.clone()));
        let cancelled = retry(RetryPolicy::immediate(10), AlwaysRetry, || {
            let context = context.clone();
            poll_fn(move |_| {
                context.cancel_fast(CancelKind::User);
                Poll::Ready(Outcome::<(), &str>::Err("caller cancelled"))
            })
        })
        .with_budget(budget.clone());
        assert!(matches!(
            futures_lite::future::block_on(cancelled),
            RetryResult::Cancelled(_)
        ));
    }
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context));
    let calls = AtomicU32::new(0);
    let another = retry(RetryPolicy::immediate(10), AlwaysRetry, || {
        calls.fetch_add(1, Ordering::Relaxed);
        ready(Outcome::<(), &str>::Err("dependency unavailable"))
    })
    .with_budget(budget.clone());
    let RetryResult::Failed(error) = futures_lite::future::block_on(another) else {
        panic!("the independent caller has no cancellation request");
    };
    assert_eq!(calls.load(Ordering::Relaxed), 4);
    assert_eq!(error.attempts, 4);
    assert_eq!(budget.available(), 0);
}

#[test]
fn a_bounded_mask_defers_cancellation_at_retry_admission() {
    let context = Cx::for_testing();
    let _current = Cx::set_current(Some(context.clone()));
    let calls = AtomicU32::new(0);
    let budget = RetryBudget::new(RetryTokenBucket::new(1, 0.0, Time::ZERO));
    let mut operation = Box::pin(
        retry(RetryPolicy::immediate(2), AlwaysRetry, || {
            let attempt = calls.fetch_add(1, Ordering::Relaxed);
            ready(if attempt == 0 {
                Outcome::Err("retry while masked")
            } else {
                Outcome::Ok(42)
            })
        })
        .with_budget(budget.clone()),
    );
    context.cancel_fast(CancelKind::User);
    let result = context.masked(|| {
        operation.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    });
    assert!(matches!(result, Poll::Ready(RetryResult::Ok(42))));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(budget.available(), 0);
    assert!(context.checkpoint().is_err(), "the mask did not erase cancellation");
}
