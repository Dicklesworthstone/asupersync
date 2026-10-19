//! Policy trait for region outcome aggregation.
//!
//! A policy names a response to each child outcome
//! ([`Policy::on_child_outcome`]) and a way to aggregate several outcomes
//! ([`Policy::aggregate_outcomes`], used by the join combinators).
//!
//! [`PolicyRegion`](crate::cx::PolicyRegion) is the opt-in typed owner that
//! consults the policy when each admitted member completes. It freezes the
//! member's outcome before applying cancellation and retains every result
//! through quiescent close. `Escalate` explicitly cancels its admitted parent.
//!
//! The legacy `Scope::region` path still records no policy, so merely naming
//! `Scope<FailFast>` does not cancel siblings when a child fails
//! (br-asupersync-mfqmcs). `JoinSet::try_join_all` also provides fail-fast
//! collection with sibling drain, and a panicking fiber cancels its siblings.

use super::cancel::CancelReason;
use super::id::TaskId;
use super::outcome::{Outcome, PanicPayload};
use core::fmt;

/// Action to take when a child completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    /// Continue normally.
    Continue,
    /// Cancel all other children (fail-fast).
    CancelSiblings(CancelReason),
    /// Escalate to parent region.
    Escalate,
}

/// Decision for aggregating child outcomes.
#[derive(Debug, Clone)]
pub enum AggregateDecision<E> {
    /// All children succeeded; return combined success.
    AllOk,
    /// At least one child failed; return the error.
    FirstError(E),
    /// At least one child was cancelled.
    Cancelled(CancelReason),
    /// At least one child panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Index of the first child that panicked.
        first_panic_index: usize,
    },
}

/// Policy for region outcome handling.
///
/// This trait determines:
/// 1. What to do when a child completes (`on_child_outcome`)
/// 2. How to aggregate all child outcomes (`aggregate_outcomes`)
pub trait Policy: Clone + Send + Sync + 'static {
    /// The error type for this policy.
    type Error: Send + 'static;

    /// Called when a child task completes.
    ///
    /// Returns an action indicating how to respond.
    fn on_child_outcome<T>(&self, child: TaskId, outcome: &Outcome<T, Self::Error>)
    -> PolicyAction;

    /// Aggregates all child outcomes into a decision.
    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error>;
}

/// Fail-fast policy: an error or panic asks to cancel the siblings.
///
/// This is the default policy for most use cases. Its
/// [`on_child_outcome`](Policy::on_child_outcome) answers
/// [`PolicyAction::CancelSiblings`] for an error or panic. The typed
/// [`PolicyRegion`](crate::cx::PolicyRegion) owner applies that answer at
/// member completion; the legacy `Scope<FailFast>` marker does not.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailFast;

impl Policy for FailFast {
    type Error = crate::error::Error;

    #[inline]
    fn on_child_outcome<T>(
        &self,
        _child: TaskId,
        outcome: &Outcome<T, Self::Error>,
    ) -> PolicyAction {
        match outcome {
            Outcome::Ok(_) | Outcome::Cancelled(_) => PolicyAction::Continue,
            Outcome::Err(_) | Outcome::Panicked(_) => {
                PolicyAction::CancelSiblings(CancelReason::sibling_failed())
            }
        }
    }

    #[inline]
    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error> {
        // Severity lattice: Panicked > Cancelled > Err > Ok.
        // We must scan all outcomes to find the worst severity, not
        // short-circuit on Err (which would miss a later Panicked).
        let mut first_error: Option<Self::Error> = None;
        let mut strongest_cancel: Option<CancelReason> = None;
        for (i, outcome) in outcomes.iter().enumerate() {
            match outcome {
                Outcome::Panicked(p) => {
                    return AggregateDecision::Panicked {
                        payload: p.clone(),
                        first_panic_index: i,
                    };
                }
                Outcome::Cancelled(r) => match &mut strongest_cancel {
                    None => strongest_cancel = Some(r.clone()),
                    Some(existing) => {
                        existing.strengthen(r);
                    }
                },
                Outcome::Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e.clone());
                    }
                }
                Outcome::Ok(_) => {}
            }
        }
        if let Some(r) = strongest_cancel {
            return AggregateDecision::Cancelled(r);
        }
        if let Some(e) = first_error {
            return AggregateDecision::FirstError(e);
        }
        AggregateDecision::AllOk
    }
}

/// Collect-all policy: wait for all children regardless of errors.
///
/// Use this when you want to gather all results even if some fail.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectAll;

impl Policy for CollectAll {
    type Error = crate::error::Error;

    #[inline]
    fn on_child_outcome<T>(
        &self,
        _child: TaskId,
        _outcome: &Outcome<T, Self::Error>,
    ) -> PolicyAction {
        PolicyAction::Continue
    }

    #[inline]
    fn aggregate_outcomes<T>(
        &self,
        outcomes: &[Outcome<T, Self::Error>],
    ) -> AggregateDecision<Self::Error> {
        let mut first_error: Option<Self::Error> = None;
        let mut strongest_cancel: Option<CancelReason> = None;
        for (i, outcome) in outcomes.iter().enumerate() {
            match outcome {
                Outcome::Panicked(p) => {
                    return AggregateDecision::Panicked {
                        payload: p.clone(),
                        first_panic_index: i,
                    };
                }
                Outcome::Cancelled(r) => match &mut strongest_cancel {
                    None => strongest_cancel = Some(r.clone()),
                    Some(existing) => {
                        existing.strengthen(r);
                    }
                },
                Outcome::Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e.clone());
                    }
                }
                Outcome::Ok(_) => {}
            }
        }
        strongest_cancel.map_or_else(
            || first_error.map_or_else(|| AggregateDecision::AllOk, AggregateDecision::FirstError),
            AggregateDecision::Cancelled,
        )
    }
}

impl fmt::Display for PolicyAction {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::CancelSiblings(reason) => write!(f, "cancel siblings: {reason}"),
            Self::Escalate => write!(f, "escalate"),
        }
    }
}

#[cfg(test)]
#[path = "policy_inline_tests.rs"]
mod tests;
