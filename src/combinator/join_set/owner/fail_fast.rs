//! Fail-fast collection with failure attribution retained through sibling drain.

use super::super::{CollectorWait, JoinSet, MemberWake, join_to_outcome};
use crate::cx::Cx;
use crate::types::{CancelReason, Outcome, Policy};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const CANDIDATES_PER_POLL: usize = 64;

enum Failure {
    Member(u64),
    Owner(CancelReason),
}

// Retain *all* results until every member retires. Discarding a successful
// value (or a secondary error) during drain could run a panicking user Drop
// before the remaining children have finished their asynchronous cleanup.
struct Collected<T, E> {
    outcomes: BTreeMap<u64, Outcome<T, E>>,
    failure: Option<Failure>,
    first_panic: Option<u64>,
}

impl<T, E> Collected<T, E> {
    fn new() -> Self {
        Self {
            outcomes: BTreeMap::new(),
            failure: None,
            first_panic: None,
        }
    }

    /// Return a cancellation reason only on the first non-success transition.
    fn record(&mut self, index: u64, outcome: Outcome<T, E>) -> Option<CancelReason> {
        let cancel = if self.failure.is_none() {
            match &outcome {
                Outcome::Ok(_) => None,
                Outcome::Err(_) | Outcome::Panicked(_) => Some(CancelReason::fail_fast()),
                Outcome::Cancelled(reason) => Some(reason.clone()),
            }
        } else {
            None
        };
        if cancel.is_some() {
            self.failure = Some(Failure::Member(index));
        }
        if matches!(&outcome, Outcome::Panicked(_)) && self.first_panic.is_none() {
            self.first_panic = Some(index);
        }
        let previous = self.outcomes.insert(index, outcome);
        debug_assert!(previous.is_none(), "member collected twice");
        cancel
    }

    fn finish(mut self) -> Outcome<Vec<T>, E> {
        let failure = self.first_panic.map(Failure::Member).or(self.failure);
        match failure {
            Some(Failure::Owner(reason)) => Outcome::Cancelled(reason),
            Some(Failure::Member(index)) => {
                match self
                    .outcomes
                    .remove(&index)
                    .expect("selected outcome retained")
                {
                    Outcome::Err(error) => Outcome::Err(error),
                    Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload),
                    Outcome::Ok(_) => unreachable!("selected failure cannot be a success"),
                }
            }
            None => Outcome::Ok(
                self.outcomes
                    .into_values()
                    .map(|outcome| match outcome {
                        Outcome::Ok(value) => value,
                        _ => unreachable!("non-success must select a failure"),
                    })
                    .collect(),
            ),
        }
    }
}

impl<T, E, P> JoinSet<'_, T, E, P>
where
    T: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    /// Join the remaining members, cancelling and draining siblings on failure.
    ///
    /// Unlike [`Self::join_all`], this observes completion candidates rather
    /// than waiting for the first input: a parked early member cannot hide a
    /// later member's error. Successful values are returned in spawn order,
    /// excluding members already collected before this call. Empty input is
    /// `Outcome::Ok(Vec::new())`, even for an already-cancelled caller.
    ///
    /// The first observed member error/cancellation selects the result and
    /// requests cancellation of every unfinished sibling before drain. Sibling
    /// cancellations caused by fail-fast cleanup do not replace that initiating
    /// error. A member panic observed at any point takes precedence; among
    /// several panics, the first observed panic is retained. Simultaneously
    /// examined candidates use their spawn indices as a deterministic tie-break.
    ///
    /// If the caller's cancellation is observed while a member is still running
    /// and before a member failure is selected, its reason selects
    /// `Outcome::Cancelled` instead. Already-published members are still joined
    /// to retirement, but do not make a completed group become cancelled merely
    /// because collection spans several polling quanta. Observation
    /// is mask-agnostic, while checkpoint acknowledgement respects masking.
    /// A later caller cancellation does not overwrite a selected failure.
    /// All members still retire before any result is returned. Successful
    /// values and secondary errors are retained until then, so their destructors
    /// cannot interrupt the asynchronous drain. No result needs to be `Clone`.
    ///
    /// Uses the set's existing ready index and persistent per-member wakers.
    /// At most 64 candidates are examined per poll, including pending ones;
    /// additional candidates schedule another poll instead of monopolizing a
    /// worker. The scan cursor survives yielded polls so repeatedly woken early
    /// members cannot starve a later failure. A fully parked set registers
    /// cancellation without self-spinning.
    ///
    /// Dropping this consuming future, including before its first poll,
    /// requests cancellation through the set's existing Drop implementation.
    /// Remaining members receive that request before already-collected values
    /// or errors are destroyed, including a panicking user destructor.
    /// The original regions remain the drain backstop. This does not create a
    /// region, detach tasks, forcibly preempt a non-cooperative member, or change
    /// the existing observation-only join APIs.
    pub async fn try_join_all<Caps>(self, cx: &Cx<Caps>) -> Outcome<Vec<T>, E> {
        let mut collected = Collected::new();
        // Reverse local drop order puts the set's cancellation request before
        // collected user destructors. Leaving the owner in the self argument
        // would destroy `collected` first when the future is dropped.
        let mut members = self;
        let mut cancelled = pin!(cx.cancelled());
        let mut owner_observed = false;
        let mut scan_from = 0;
        let mut collector = CollectorWait::new(Arc::clone(&members.ready));
        poll_fn(|task| {
            if members.members.is_empty() {
                return Poll::Ready(());
            }
            collector.refresh(task.waker());

            let mut from = Some(scan_from);
            for _ in 0..CANDIDATES_PER_POLL {
                let Some(index) = from.and_then(|start| members.ready.next_candidate(start)) else {
                    break;
                };
                from = index.checked_add(1);
                members.ready.candidates.lock().remove(&index);
                let ready = Arc::clone(&members.ready);
                let Some(member) = members.members.get_mut(&index) else {
                    // A late wake from an already-collected member is harmless.
                    continue;
                };
                let waker = member
                    .waker
                    .get_or_insert_with(|| Waker::from(Arc::new(MemberWake { index, ready })));
                if let Poll::Ready(joined) =
                    member.handle.poll_join(&mut Context::from_waker(waker))
                {
                    let outcome = join_to_outcome(joined);
                    members.take_member(index, &outcome);
                    if let Some(reason) = collected.record(index, outcome) {
                        members.cancel_unfinished_for_owner(&reason);
                    }
                }
            }

            if members.members.is_empty() {
                return Poll::Ready(());
            }
            let mut transition_wake = false;
            if !owner_observed
                && collected.failure.is_none()
                && cancelled.as_mut().poll(task).is_ready()
            {
                owner_observed = true;
                if members
                    .members
                    .values()
                    .any(|member| !member.handle.terminal_published())
                {
                    let reason = cx
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("fail-fast join owner cancelled"));
                    collected.failure = Some(Failure::Owner(reason.clone()));
                    let _ = cx.checkpoint();
                    members.cancel_unfinished_for_owner(&reason);
                    transition_wake = true;
                }
            }
            let more_forward =
                from.is_some_and(|start| members.ready.next_candidate(start).is_some());
            scan_from = if more_forward {
                from.expect("a forward candidate has a scan cursor")
            } else {
                0
            };
            // Backward arrivals are revisited only after the current sweep.
            // Their wakes may have happened during this poll; retain explicit
            // runnable work at the quantum boundary rather than losing it.
            let runnable = !members.ready.candidates.lock().is_empty();
            if transition_wake || runnable {
                task.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await;
        drop(collector);
        collected.finish()
    }
}

#[cfg(test)]
#[path = "fail_fast_inline_tests.rs"]
mod tests;
