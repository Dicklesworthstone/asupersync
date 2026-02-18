//! Policy trait for region outcome aggregation.
//!
//! Policies determine how a region responds to child outcomes and how
//! multiple child outcomes are aggregated when the region closes.

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

/// Fail-fast policy: cancel siblings on first error.
///
/// This is the default policy for most use cases.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailFast;

impl Policy for FailFast {
    type Error = crate::error::Error;

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

    fn on_child_outcome<T>(
        &self,
        _child: TaskId,
        _outcome: &Outcome<T, Self::Error>,
    ) -> PolicyAction {
        PolicyAction::Continue
    }

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::CancelSiblings(reason) => write!(f, "cancel siblings: {reason}"),
            Self::Escalate => write!(f, "escalate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_task_id() -> TaskId {
        TaskId::from_arena(crate::util::ArenaIndex::new(0, 0))
    }

    #[test]
    fn fail_fast_triggers_on_err_or_panic_only() {
        let policy = FailFast;

        let ok = Outcome::<(), crate::error::Error>::Ok(());
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &ok),
            PolicyAction::Continue
        );

        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &cancelled),
            PolicyAction::Continue
        );

        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &err),
            PolicyAction::CancelSiblings(CancelReason::sibling_failed())
        );

        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &panicked),
            PolicyAction::CancelSiblings(CancelReason::sibling_failed())
        );
    }

    #[test]
    fn aggregate_takes_panic_over_cancel_over_error() {
        let policy = CollectAll;
        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));

        assert!(matches!(
            policy.aggregate_outcomes(std::slice::from_ref(&err)),
            AggregateDecision::FirstError(_)
        ));
        match policy.aggregate_outcomes(&[err, cancelled.clone()]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::timeout()),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        match policy.aggregate_outcomes(&[cancelled, panicked]) {
            AggregateDecision::Panicked {
                payload: p,
                first_panic_index: idx,
            } => {
                assert_eq!(p.message(), "boom");
                assert_eq!(idx, 1);
            }
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_strengthens_cancel_reasons_deterministically() {
        let policy = CollectAll;
        let a = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::user("b"));
        let b = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::user("a"));
        let timeout = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());

        match policy.aggregate_outcomes(&[a.clone(), b.clone()]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::user("a")),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        match policy.aggregate_outcomes(&[b, timeout, a]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::timeout()),
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }
}
