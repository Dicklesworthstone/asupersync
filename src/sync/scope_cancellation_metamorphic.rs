//! Metamorphic tests for scope-spawn cancellation timing.

#![cfg(test)]

use crate::cx::{Cx, Scope};
use crate::runtime::RuntimeState;
use crate::runtime::task_handle::JoinError;
use crate::types::policy::FailFast;
use crate::types::{Budget, CancelReason, Outcome};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelTiming {
    BeforeFirstPoll,
    AfterFirstPoll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalTaskOutcome {
    Ok,
    Cancelled,
    Err,
    Panicked,
}

impl CanonicalTaskOutcome {
    const fn from_outcome(outcome: &Outcome<(), ()>) -> Self {
        match outcome {
            Outcome::Ok(()) => Self::Ok,
            Outcome::Err(()) => Self::Err,
            Outcome::Cancelled(_) => Self::Cancelled,
            Outcome::Panicked(_) => Self::Panicked,
        }
    }
}

struct YieldOnceThenCheckpoint {
    task_cx: Cx,
    yielded: bool,
}

impl Future for YieldOnceThenCheckpoint {
    type Output = Outcome<(), ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.yielded {
            self.yielded = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        if self.task_cx.checkpoint().is_err() {
            let reason = self
                .task_cx
                .cancel_reason()
                .unwrap_or_else(|| CancelReason::user("scope task cancelled"));
            Poll::Ready(Outcome::Cancelled(reason))
        } else {
            Poll::Ready(Outcome::Ok(()))
        }
    }
}

fn drive_spawned_task(timing: CancelTiming) -> Outcome<(), ()> {
    let mut state = RuntimeState::new();
    let cx = Cx::for_testing();
    let region = state.create_root_region(Budget::INFINITE);
    let scope: Scope<'static, FailFast> = Scope::new(region, Budget::INFINITE);

    let (mut handle, mut stored) = scope
        .spawn(&mut state, &cx, |task_cx| YieldOnceThenCheckpoint {
            task_cx,
            yielded: false,
        })
        .expect("scope spawn should succeed");

    let task_waker = std::task::Waker::noop();
    let mut task_cx = Context::from_waker(task_waker);

    match timing {
        CancelTiming::BeforeFirstPoll => {
            handle.abort();
        }
        CancelTiming::AfterFirstPoll => {
            assert!(
                matches!(stored.poll(&mut task_cx), Poll::Pending),
                "first poll should only register the task future"
            );
            handle.abort();
        }
    }

    let terminal = loop {
        match stored.poll(&mut task_cx) {
            Poll::Ready(outcome) => break outcome,
            Poll::Pending => {}
        }
    };
    assert!(
        matches!(terminal, Outcome::Ok(())),
        "Scope::spawn wrapper should complete after delivering the task result: {terminal:?}"
    );

    let join_waker = std::task::Waker::noop();
    let mut join_cx = Context::from_waker(join_waker);
    let mut join = std::pin::pin!(handle.join(&cx));
    match join.as_mut().poll(&mut join_cx) {
        Poll::Ready(Ok(outcome)) => outcome,
        Poll::Ready(Err(JoinError::Cancelled(reason))) => Outcome::Cancelled(reason),
        Poll::Ready(Err(err)) => panic!("unexpected join error: {err:?}"), // ubs:ignore - test oracle
        Poll::Pending => panic!("join should be ready after stored task completion"), // ubs:ignore - test oracle
    }
}

/// MR1: Scope cancellation timing equivalence.
///
/// Transformation: move `TaskHandle::abort()` from before the first poll to
/// after the first pending poll.
///
/// Relation: both executions have the same canonical task output,
/// `Outcome::Cancelled`.
#[test]
fn mr_scope_spawn_cancel_before_or_after_first_poll_is_cancelled() {
    let before = drive_spawned_task(CancelTiming::BeforeFirstPoll);
    let after = drive_spawned_task(CancelTiming::AfterFirstPoll);

    assert_eq!(
        CanonicalTaskOutcome::from_outcome(&before),
        CanonicalTaskOutcome::Cancelled,
        "pre-poll cancellation must complete as Outcome::Cancelled"
    );
    assert_eq!(
        CanonicalTaskOutcome::from_outcome(&after),
        CanonicalTaskOutcome::Cancelled,
        "post-first-poll cancellation must complete as Outcome::Cancelled"
    );
    assert_eq!(
        CanonicalTaskOutcome::from_outcome(&before),
        CanonicalTaskOutcome::from_outcome(&after),
        "moving cancellation across the first-poll boundary changed the canonical task outcome"
    );
}
