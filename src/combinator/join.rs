//! Join combinator: run multiple operations in parallel.
//!
//! The join combinator runs multiple operations concurrently and waits
//! for **all** of them to complete. Even if one fails early, we wait for
//! the other to reach a terminal state.
//!
//! # Semantics
//!
//! `join(f1, f2)`:
//! 1. Spawn both futures as tasks
//! 2. Wait for both to complete (order doesn't matter)
//! 3. Return both outcomes (or aggregate them)
//!
//! **Key property**: Both futures always complete. Even if one fails or is
//! cancelled, we wait for the other to reach a terminal state.
//!
//! # Algebraic Laws
//!
//! - Associativity: `join(join(a, b), c) ≃ join(a, join(b, c))`
//! - Commutativity: `join(a, b) ≃ join(b, a)` (up to tuple order)
//! - Identity: `join(a, immediate_unit) ≃ a`
//!
//! # Outcome Aggregation
//!
//! When combining outcomes, the severity lattice applies:
//! `Ok < Err < Cancelled < Panicked`
//!
//! The worst outcome determines the aggregate result (policy may customize).

use core::fmt;
use std::marker::PhantomData;

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::policy::AggregateDecision;
use crate::types::{Outcome, Policy};

/// A join combinator for running operations in parallel.
///
/// This is a builder/marker type representing the join of two operations.
/// Actual execution happens via the runtime's spawn and await mechanisms.
///
/// # Type Parameters
/// * `A` - The first operation type
/// * `B` - The second operation type
#[derive(Debug)]
pub struct Join<A, B> {
    _a: PhantomData<A>,
    _b: PhantomData<B>,
}

impl<A, B> Join<A, B> {
    /// Creates a new join combinator (internal use).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _a: PhantomData,
            _b: PhantomData,
        }
    }
}

impl<A, B> Default for Join<A, B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for fail-fast join operations.
///
/// When using `join_fail_fast`, if either branch fails, this error type
/// indicates which branch failed and why.
#[derive(Debug, Clone)]
pub enum JoinError<E> {
    /// The first branch encountered an error.
    First(E),
    /// The second branch encountered an error.
    Second(E),
    /// One of the branches was cancelled.
    Cancelled(CancelReason),
    /// One of the branches panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for JoinError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(e) => write!(f, "first branch failed: {e}"),
            Self::Second(e) => write!(f, "second branch failed: {e}"),
            Self::Cancelled(r) => write!(f, "branch cancelled: {r}"),
            Self::Panicked(p) => write!(f, "branch panicked: {p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for JoinError<E> {}

/// Aggregates child outcomes under the provided policy.
///
/// This is the semantic core of `join`: compute the region outcome under the
/// `Ok < Err < Cancelled < Panicked` lattice (with policy-defined tie-breaking).
///
/// # Arguments
/// * `policy` - The policy determining how outcomes are aggregated
/// * `outcomes` - The slice of child outcomes to aggregate
///
/// # Returns
/// An `AggregateDecision` indicating the combined result.
pub fn aggregate_outcomes<P: Policy, T>(
    policy: &P,
    outcomes: &[Outcome<T, P::Error>],
) -> AggregateDecision<P::Error> {
    policy.aggregate_outcomes(outcomes)
}

/// Result type for [`join2_outcomes`].
///
/// The tuple contains: (aggregate outcome, preserved value from first branch, preserved value from second branch).
/// When both branches succeed, the values are in the aggregate outcome tuple and v1/v2 are None.
/// When one branch fails, the successful branch's value is preserved in the corresponding Option.
pub type Join2Result<T1, T2, E> = (Outcome<(T1, T2), E>, Option<T1>, Option<T2>);

/// Aggregates exactly two outcomes following the severity lattice.
///
/// This is a convenience function for the common binary join case.
/// Returns `Ok` only if both outcomes are `Ok`; otherwise returns the
/// worst outcome according to the severity lattice.
///
/// # Result Type
///
/// Returns a tuple `(aggregate_outcome, preserved_v1, preserved_v2)`:
/// - When both succeed: values are in the aggregate outcome tuple, v1/v2 are None
/// - When one fails: the successful branch's value is preserved in the corresponding Option
///
/// # Severity Lattice
/// `Ok < Err < Cancelled < Panicked`
///
/// # Example
/// ```
/// use asupersync::combinator::join::join2_outcomes;
/// use asupersync::types::Outcome;
///
/// let o1: Outcome<i32, &str> = Outcome::Ok(1);
/// let o2: Outcome<i32, &str> = Outcome::Ok(2);
/// let (result, v1, v2) = join2_outcomes(o1, o2);
/// assert!(result.is_ok());
/// // When both succeed, values are in the tuple; v1/v2 are None
/// assert!(v1.is_none());
/// assert!(v2.is_none());
/// ```
pub fn join2_outcomes<T1, T2, E: Clone>(
    o1: Outcome<T1, E>,
    o2: Outcome<T2, E>,
) -> Join2Result<T1, T2, E> {
    match (o1, o2) {
        (Outcome::Ok(v1), Outcome::Ok(v2)) => (Outcome::Ok((v1, v2)), None, None),
        // Panicked takes precedence
        (Outcome::Panicked(p), Outcome::Ok(v2)) => (Outcome::Panicked(p), None, Some(v2)),
        (Outcome::Ok(v1), Outcome::Panicked(p)) => (Outcome::Panicked(p), Some(v1), None),
        (Outcome::Panicked(p), _) | (_, Outcome::Panicked(p)) => (Outcome::Panicked(p), None, None),
        // Cancelled takes precedence over Err
        (Outcome::Cancelled(r), Outcome::Ok(v2)) => (Outcome::Cancelled(r), None, Some(v2)),
        (Outcome::Ok(v1), Outcome::Cancelled(r)) => (Outcome::Cancelled(r), Some(v1), None),
        (Outcome::Cancelled(r), _) | (_, Outcome::Cancelled(r)) => {
            (Outcome::Cancelled(r), None, None)
        }
        // Err cases
        (Outcome::Err(e), Outcome::Ok(v2)) => (Outcome::Err(e), None, Some(v2)),
        (Outcome::Ok(v1), Outcome::Err(e)) => (Outcome::Err(e), Some(v1), None),
        (Outcome::Err(e), _) => (Outcome::Err(e), None, None),
    }
}

/// Aggregates N outcomes following the severity lattice.
///
/// Returns the worst outcome according to the severity lattice,
/// along with any successful values that were obtained.
///
/// # Returns
/// A tuple of (aggregate decision, vector of successful values with their indices).
pub fn join_all_outcomes<T, E: Clone>(
    outcomes: Vec<Outcome<T, E>>,
) -> (AggregateDecision<E>, Vec<(usize, T)>) {
    let mut successes = Vec::new();
    let mut first_error: Option<E> = None;
    let mut strongest_cancel: Option<CancelReason> = None;

    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Panicked(p) => {
                return (AggregateDecision::Panicked(p), successes);
            }
            Outcome::Cancelled(r) => match &mut strongest_cancel {
                None => strongest_cancel = Some(r),
                Some(existing) => {
                    existing.strengthen(&r);
                }
            },
            Outcome::Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
            Outcome::Ok(v) => {
                successes.push((i, v));
            }
        }
    }

    let decision = strongest_cancel.map_or_else(
        || first_error.map_or(AggregateDecision::AllOk, AggregateDecision::FirstError),
        AggregateDecision::Cancelled,
    );

    (decision, successes)
}

/// Converts two outcomes to a Result for fail-fast join.
///
/// This is used by `join_fail_fast` to convert the outcome pair into
/// a single Result.
pub fn join2_to_result<T1, T2, E>(
    o1: Outcome<T1, E>,
    o2: Outcome<T2, E>,
) -> Result<(T1, T2), JoinError<E>> {
    match (o1, o2) {
        (Outcome::Ok(v1), Outcome::Ok(v2)) => Ok((v1, v2)),
        // Check for panics first (highest severity)
        (Outcome::Panicked(p), _) | (_, Outcome::Panicked(p)) => Err(JoinError::Panicked(p)),
        // Then cancellations
        (Outcome::Cancelled(r), _) | (_, Outcome::Cancelled(r)) => Err(JoinError::Cancelled(r)),
        // Then errors (first one encountered)
        (Outcome::Err(e), _) => Err(JoinError::First(e)),
        (_, Outcome::Err(e)) => Err(JoinError::Second(e)),
    }
}

/// Macro for joining multiple futures (placeholder).
///
/// In the full implementation, this expands to spawn + join operations.
/// Once the scheduler loop is implemented, this will spawn tasks and
/// wait for all of them to complete.
///
/// # Example (API shape)
/// ```ignore
/// let (r1, r2, r3) = join!(
///     async { compute_a().await },
///     async { compute_b().await },
///     async { compute_c().await },
/// );
/// ```
#[macro_export]
macro_rules! join {
    ($($future:expr),+ $(,)?) => {
        // Placeholder: in real implementation, this spawns and joins
        // For now, just a marker that shows the API shape
        {
            $(let _ = $future;)+
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::policy::{CollectAll, FailFast};

    #[test]
    fn join2_both_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_ok());
        assert!(v1.is_none()); // Values are in the result tuple
        assert!(v2.is_none());
        if let Outcome::Ok((a, b)) = result {
            assert_eq!(a, 1);
            assert_eq!(b, 2);
        }
    }

    #[test]
    fn join2_first_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error1");
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_err());
        assert!(v1.is_none());
        assert_eq!(v2, Some(2)); // Second value preserved
    }

    #[test]
    fn join2_second_err() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Err("error2");
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_err());
        assert_eq!(v1, Some(1)); // First value preserved
        assert!(v2.is_none());
    }

    #[test]
    fn join2_cancelled_over_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let (result, _, _) = join2_outcomes(o1, o2);

        assert!(result.is_cancelled());
    }

    #[test]
    fn join2_panic_over_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let o2: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("boom"));
        let (result, _, _) = join2_outcomes(o1, o2);

        assert!(result.is_panicked());
    }

    #[test]
    fn join_all_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let (decision, successes) = join_all_outcomes(outcomes);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(successes.len(), 3);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (1, 2));
        assert_eq!(successes[2], (2, 3));
    }

    #[test]
    fn join_all_one_err() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("error"), Outcome::Ok(3)];
        let (decision, successes) = join_all_outcomes(outcomes);

        assert!(matches!(decision, AggregateDecision::FirstError(_)));
        assert_eq!(successes.len(), 2);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (2, 3));
    }

    #[test]
    fn join_all_panic_short_circuits() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let (decision, successes) = join_all_outcomes(outcomes);

        assert!(matches!(decision, AggregateDecision::Panicked(_)));
        // Only first value collected before panic
        assert_eq!(successes.len(), 1);
    }

    #[test]
    fn join2_to_result_both_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let result = join2_to_result(o1, o2);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1, 2));
    }

    #[test]
    fn join2_to_result_first_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("error1");
        let o2: Outcome<i32, &str> = Outcome::Ok(2);
        let result = join2_to_result(o1, o2);

        assert!(matches!(result, Err(JoinError::First("error1"))));
    }

    #[test]
    fn join2_to_result_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Ok(1);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let result = join2_to_result(o1, o2);

        assert!(matches!(result, Err(JoinError::Cancelled(_))));
    }

    #[test]
    fn aggregate_with_fail_fast_policy() {
        let policy = FailFast;
        let outcomes: Vec<Outcome<(), crate::error::Error>> =
            vec![Outcome::Ok(()), Outcome::Ok(())];
        let decision = aggregate_outcomes(&policy, &outcomes);

        assert!(matches!(decision, AggregateDecision::AllOk));
    }

    #[test]
    fn aggregate_with_collect_all_policy() {
        let policy = CollectAll;
        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let outcomes = vec![Outcome::Ok(()), err];
        let decision = aggregate_outcomes(&policy, &outcomes);

        assert!(matches!(decision, AggregateDecision::FirstError(_)));
    }

    #[test]
    fn join_error_display() {
        let err: JoinError<&str> = JoinError::First("test error");
        assert!(err.to_string().contains("first branch failed"));

        let err: JoinError<&str> = JoinError::Second("test error");
        assert!(err.to_string().contains("second branch failed"));

        let err: JoinError<&str> = JoinError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: JoinError<&str> = JoinError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    // Algebraic property tests
    #[test]
    fn join_severity_is_monotone() {
        // Severity should only increase, never decrease
        // Ok(1) join Ok(2) = Ok
        // Ok(1) join Err = Err
        // Err join Cancelled = Cancelled
        // Cancelled join Panicked = Panicked

        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("e");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("p"));

        // Each step up the lattice should produce the higher severity
        let (r1, _, _) = join2_outcomes(ok.clone(), err.clone());
        assert!(r1.severity() >= ok.severity());

        let (r2, _, _) = join2_outcomes(err.clone(), cancelled.clone());
        assert!(r2.severity() >= err.severity());

        let (r3, _, _) = join2_outcomes(cancelled.clone(), panicked.clone());
        assert!(r3.severity() >= cancelled.severity());
    }

    #[test]
    fn join_is_commutative_in_severity() {
        // join(a, b) and join(b, a) should have same severity
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("e");

        let (r1, _, _) = join2_outcomes(ok.clone(), err.clone());
        let (r2, _, _) = join2_outcomes(err, ok);

        assert_eq!(r1.severity(), r2.severity());
    }
}
