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
//! # N-way Join (JoinAll)
//!
//! `join_all(f0, f1, ..., fn)`:
//! 1. Spawn all N futures as children in a subregion
//! 2. Wait for ALL to reach terminal state
//! 3. Aggregate outcomes under the severity lattice
//!
//! **Critical invariants**:
//! - No branch is abandoned (all must complete)
//! - Region close = quiescence (all children done)
//! - Deterministic in lab runtime
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

/// An N-way join combinator for running multiple operations in parallel.
///
/// This is a builder/marker type representing the join of N operations.
/// Actual execution happens via the runtime's spawn and await mechanisms.
///
/// # Type Parameters
/// * `T` - The element type for each operation
///
/// # Semantics
///
/// Given futures `f[0..n)`:
/// 1. Spawn each as a child in a subregion
/// 2. Await all join handles
/// 3. Aggregate outcomes according to the severity lattice
///
/// # Invariants
///
/// - **No abandonment**: Every spawned task completes
/// - **Region quiescence**: All children done before return
/// - **Deterministic**: Same seed → same execution order in lab runtime
///
/// # Example (API shape)
/// ```ignore
/// let results = scope.join_all(cx, vec![
///     async { compute_a(cx).await },
///     async { compute_b(cx).await },
///     async { compute_c(cx).await },
/// ]).await;
/// ```
#[derive(Debug)]
pub struct JoinAll<T> {
    _t: PhantomData<T>,
}

impl<T> JoinAll<T> {
    /// Creates a new N-way join combinator (internal use).
    #[must_use]
    pub const fn new() -> Self {
        Self { _t: PhantomData }
    }
}

impl<T> Default for JoinAll<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for JoinAll<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for JoinAll<T> {}

/// Result from joining N operations.
///
/// Contains the aggregate decision and all successful values with their indices.
/// This is analogous to [`super::race::RaceAllResult`] but waits for ALL branches.
pub struct JoinAllResult<T, E> {
    /// The aggregate decision following the severity lattice.
    pub decision: AggregateDecision<E>,
    /// Successful values with their original indices (0-based).
    /// Only contains values from branches that returned `Ok`.
    pub successes: Vec<(usize, T)>,
    /// The total number of branches that were joined.
    pub total_count: usize,
}

impl<T, E> JoinAllResult<T, E> {
    /// Creates a new join-all result.
    #[must_use]
    pub fn new(
        decision: AggregateDecision<E>,
        successes: Vec<(usize, T)>,
        total_count: usize,
    ) -> Self {
        Self {
            decision,
            successes,
            total_count,
        }
    }

    /// Returns true if all branches succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        matches!(self.decision, AggregateDecision::AllOk)
            && self.successes.len() == self.total_count
    }

    /// Returns the number of successful branches.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.successes.len()
    }

    /// Returns the number of failed branches.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.total_count - self.successes.len()
    }

    /// Extracts successful values in their original order.
    ///
    /// Returns `None` for indices where the branch did not succeed.
    #[must_use]
    pub fn into_ordered_values(self) -> Vec<Option<T>> {
        let mut result: Vec<Option<T>> = (0..self.total_count).map(|_| None).collect();
        for (i, v) in self.successes {
            if i < result.len() {
                result[i] = Some(v);
            }
        }
        result
    }
}

impl<T: fmt::Debug, E: fmt::Debug> fmt::Debug for JoinAllResult<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinAllResult")
            .field("decision", &self.decision)
            .field("successes", &self.successes)
            .field("total_count", &self.total_count)
            .finish()
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
        (Outcome::Cancelled(mut r1), Outcome::Cancelled(r2)) => {
            // Both cancelled: strengthen to keep the worst reason,
            // consistent with join_all_outcomes' severity lattice.
            r1.strengthen(&r2);
            (Outcome::Cancelled(r1), None, None)
        }
        (Outcome::Cancelled(r), _) | (_, Outcome::Cancelled(r)) => {
            (Outcome::Cancelled(r), None, None)
        }
        // Err cases
        (Outcome::Err(e), Outcome::Ok(v2)) => (Outcome::Err(e), None, Some(v2)),
        (Outcome::Ok(v1), Outcome::Err(e)) => (Outcome::Err(e), Some(v1), None),
        (Outcome::Err(e), _) => (Outcome::Err(e), None, None),
    }
}

/// Error type for N-way join operations.
///
/// When using `join_all_to_result`, if any branch fails, this error type
/// indicates which branch(es) failed and why.
#[derive(Debug, Clone)]
pub enum JoinAllError<E> {
    /// At least one branch encountered an error.
    /// Contains the first error and the index of the branch that produced it.
    Error {
        /// The error from the first failing branch.
        error: E,
        /// Index of the branch that produced this error.
        index: usize,
        /// Total number of branches that failed.
        total_failures: usize,
    },
    /// At least one branch was cancelled.
    Cancelled(CancelReason),
    /// At least one branch panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Index of the first branch that panicked.
        index: usize,
    },
}

impl<E: fmt::Display> fmt::Display for JoinAllError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error {
                error,
                index,
                total_failures,
            } => write!(
                f,
                "branch {index} failed: {error} ({total_failures} total failures)"
            ),
            Self::Cancelled(r) => write!(f, "branch cancelled: {r}"),
            Self::Panicked { payload, index } => write!(f, "branch {index} panicked: {payload}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for JoinAllError<E> {}

/// Aggregates N outcomes following the severity lattice.
///
/// Returns the worst outcome according to the severity lattice,
/// along with any successful values that were obtained.
///
/// # Returns
/// A tuple of (aggregate decision, vector of successful values with their indices).
#[must_use]
pub fn join_all_outcomes<T, E: Clone>(
    outcomes: Vec<Outcome<T, E>>,
) -> (AggregateDecision<E>, Vec<(usize, T)>) {
    let mut successes = Vec::new();
    let mut first_error: Option<E> = None;
    let mut strongest_cancel: Option<CancelReason> = None;
    let mut panic_payload: Option<PanicPayload> = None;
    let mut panic_index: Option<usize> = None;

    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Panicked(p) => {
                if panic_payload.is_none() {
                    panic_payload = Some(p);
                    panic_index = Some(i);
                }
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

    let decision = panic_payload.map_or_else(
        || {
            strongest_cancel.map_or_else(
                || first_error.map_or(AggregateDecision::AllOk, AggregateDecision::FirstError),
                AggregateDecision::Cancelled,
            )
        },
        |p| AggregateDecision::Panicked {
            payload: p,
            first_panic_index: panic_index.expect("panic index missing"),
        },
    );

    (decision, successes)
}

/// Constructs a [`JoinAllResult`] from a vector of outcomes.
///
/// This is the primary entry point for N-way join result construction.
/// All branches must have completed (no branch is abandoned).
///
/// # Arguments
/// * `outcomes` - The outcomes from all branches, in their original order
///
/// # Returns
/// A [`JoinAllResult`] containing the aggregate decision and successful values.
///
/// # Example
/// ```
/// use asupersync::combinator::join::{make_join_all_result, JoinAllResult};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
/// ];
/// let result = make_join_all_result(outcomes);
/// assert!(result.all_succeeded());
/// assert_eq!(result.success_count(), 3);
/// ```
#[must_use]
pub fn make_join_all_result<T, E: Clone>(outcomes: Vec<Outcome<T, E>>) -> JoinAllResult<T, E> {
    let total_count = outcomes.len();
    let (decision, successes) = join_all_outcomes(outcomes);
    JoinAllResult::new(decision, successes, total_count)
}

/// Converts a [`JoinAllResult`] to a Result for fail-fast handling.
///
/// If all branches succeeded, returns `Ok` with all values in order.
/// If any branch failed (error, cancelled, or panicked), returns `Err`.
///
/// # Example
/// ```
/// use asupersync::combinator::join::{make_join_all_result, join_all_to_result};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
/// ];
/// let result = make_join_all_result(outcomes);
/// let values = join_all_to_result(result);
/// assert_eq!(values.unwrap(), vec![1, 2, 3]);
/// ```
pub fn join_all_to_result<T, E: Clone>(
    result: JoinAllResult<T, E>,
) -> Result<Vec<T>, JoinAllError<E>> {
    match result.decision {
        AggregateDecision::AllOk => {
            // Fast path: for AllOk, successes are emitted in source index order.
            debug_assert_eq!(
                result.successes.len(),
                result.total_count,
                "AllOk must include every branch result"
            );
            debug_assert!(
                result
                    .successes
                    .iter()
                    .enumerate()
                    .all(|(expected, (idx, _))| *idx == expected),
                "AllOk successes must be contiguous and index-ordered"
            );
            Ok(result.successes.into_iter().map(|(_, v)| v).collect())
        }
        AggregateDecision::FirstError(e) => {
            // Find the first error index (the first index gap in successes).
            // Since successes is sorted by index (populated in iteration order),
            // we can just find the first missing sequence number.
            debug_assert!(
                result.successes.windows(2).all(|w| w[0].0 < w[1].0),
                "successes must be sorted by index for gap detection"
            );
            let mut first_error_index = 0;
            for (idx, _) in &result.successes {
                if *idx == first_error_index {
                    first_error_index += 1;
                } else {
                    // Gap found: first_error_index is missing
                    break;
                }
            }

            let total_failures = result.total_count - result.successes.len();
            Err(JoinAllError::Error {
                error: e,
                index: first_error_index,
                total_failures,
            })
        }
        AggregateDecision::Cancelled(r) => Err(JoinAllError::Cancelled(r)),
        AggregateDecision::Panicked {
            payload,
            first_panic_index,
        } => Err(JoinAllError::Panicked {
            payload,
            index: first_panic_index,
        }),
    }
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
        // Then cancellations — strengthen when both cancelled
        (Outcome::Cancelled(mut r1), Outcome::Cancelled(r2)) => {
            r1.strengthen(&r2);
            Err(JoinError::Cancelled(r1))
        }
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
    fn join_all_panic_collects_all_successes() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let (decision, successes) = join_all_outcomes(outcomes);

        match decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
        // All successful values collected (join waits for all branches)
        assert_eq!(successes.len(), 2);
        assert_eq!(successes[0], (0, 1));
        assert_eq!(successes[1], (2, 3));
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

    // ============================================================
    // JoinAll tests
    // ============================================================

    #[test]
    fn join_all_marker_is_copy() {
        let marker: JoinAll<i32> = JoinAll::new();
        let copy = marker;
        let _ = marker; // Still usable after copy
        let _ = copy;
    }

    #[test]
    fn join_all_marker_default() {
        let marker: JoinAll<i32> = JoinAll::default();
        let _ = marker;
    }

    #[test]
    fn join_all_result_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
        assert_eq!(result.total_count, 3);

        // Verify ordered values
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn join_all_result_partial_failure() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("fail"), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);

        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
        assert_eq!(result.total_count, 3);

        // Verify ordered values (None for failed index)
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(1), None, Some(3)]);
    }

    #[test]
    fn join_all_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded()); // Vacuously true
        assert_eq!(result.success_count(), 0);
        assert_eq!(result.failure_count(), 0);
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn join_all_result_single_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 1);
        let ordered = result.into_ordered_values();
        assert_eq!(ordered, vec![Some(42)]);
    }

    #[test]
    fn join_all_result_single_failure() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail")];
        let result = make_join_all_result(outcomes);

        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 0);
        assert_eq!(result.failure_count(), 1);
    }

    #[test]
    fn join_all_to_result_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);
        let values = join_all_to_result(result);

        assert!(values.is_ok());
        assert_eq!(values.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn join_all_to_result_with_error() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("middle-fail"), Outcome::Ok(3)];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        assert!(err.is_err());
        match err.unwrap_err() {
            JoinAllError::Error {
                error,
                index,
                total_failures,
            } => {
                assert_eq!(error, "middle-fail");
                assert_eq!(index, 1); // Middle branch failed
                assert_eq!(total_failures, 1);
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[test]
    fn join_all_to_result_with_cancellation() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        assert!(matches!(err, Err(JoinAllError::Cancelled(_))));
    }

    #[test]
    fn join_all_to_result_with_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        let err = join_all_to_result(result);

        match err {
            Err(JoinAllError::Panicked { payload, index }) => {
                assert_eq!(payload.message(), "boom");
                assert_eq!(index, 1);
            }
            _ => panic!("Expected Panicked error"),
        }
    }

    #[test]
    fn join_all_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_join_all_result(outcomes);
        let values = join_all_to_result(result);

        assert!(values.is_ok());
        assert_eq!(values.unwrap(), Vec::<i32>::new());
    }

    #[test]
    fn join_all_error_display() {
        let err: JoinAllError<&str> = JoinAllError::Error {
            error: "test error",
            index: 2,
            total_failures: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("branch 2 failed"));
        assert!(msg.contains("test error"));
        assert!(msg.contains("3 total failures"));

        let err: JoinAllError<&str> = JoinAllError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: JoinAllError<&str> = JoinAllError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 4,
        };
        assert!(err.to_string().contains("branch 4 panicked"));
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn join_all_respects_severity_lattice() {
        // Panic > Cancel > Error > Ok
        // Test that the worst outcome is selected

        // Error + Cancel = Cancel
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Err("error"),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let result = make_join_all_result(outcomes);
        assert!(matches!(result.decision, AggregateDecision::Cancelled(_)));

        // Cancel + Panic = Panic (panic short-circuits)
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];
        let result = make_join_all_result(outcomes);
        match result.decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
    }

    #[test]
    fn join_all_many_branches() {
        // Test with many branches to verify scaling
        let outcomes: Vec<Outcome<i32, &str>> = (0..100).map(Outcome::Ok).collect();
        let result = make_join_all_result(outcomes);

        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 100);

        let values = join_all_to_result(result).unwrap();
        assert_eq!(values.len(), 100);
        for (i, v) in values.iter().enumerate() {
            assert_eq!(*v, i32::try_from(i).unwrap());
        }
    }

    #[test]
    fn join_all_preserves_order_with_mixed_outcomes() {
        // Verify that successful values maintain their original indices
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(10),    // index 0
            Outcome::Err("e1"), // index 1
            Outcome::Ok(30),    // index 2
            Outcome::Err("e2"), // index 3
            Outcome::Ok(50),    // index 4
        ];
        let result = make_join_all_result(outcomes);

        assert_eq!(result.successes.len(), 3);
        assert_eq!(result.successes[0], (0, 10));
        assert_eq!(result.successes[1], (2, 30));
        assert_eq!(result.successes[2], (4, 50));
    }

    #[test]
    fn join2_both_cancelled_strengthens_to_worst_reason() {
        // Regression: join2_outcomes must use strengthen() when both branches
        // are cancelled, matching join_all_outcomes' severity lattice behavior.
        // User(severity 0) + Shutdown(severity 5) → Shutdown wins.
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let (result, v1, v2) = join2_outcomes(o1, o2);

        assert!(result.is_cancelled());
        assert!(v1.is_none());
        assert!(v2.is_none());
        if let Outcome::Cancelled(r) = &result {
            assert_eq!(
                r.kind(),
                crate::types::cancel::CancelKind::Shutdown,
                "join2_outcomes should strengthen to Shutdown (severity 5), not User (severity 0)"
            );
        }

        // Also test the reverse order: Shutdown + User → still Shutdown
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let (result, _, _) = join2_outcomes(o1, o2);

        if let Outcome::Cancelled(r) = &result {
            assert_eq!(
                r.kind(),
                crate::types::cancel::CancelKind::Shutdown,
                "join2_outcomes should be commutative in cancel severity"
            );
        }
    }

    #[test]
    fn join2_to_result_both_cancelled_strengthens() {
        // Same regression test for join2_to_result
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let result = join2_to_result(o1, o2);

        match result {
            Err(JoinError::Cancelled(r)) => {
                assert_eq!(
                    r.kind(),
                    crate::types::cancel::CancelKind::Shutdown,
                    "join2_to_result should strengthen to Shutdown"
                );
            }
            other => panic!("Expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn join_all_result_debug() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = make_join_all_result(outcomes);
        let debug = format!("{result:?}");
        assert!(debug.contains("JoinAllResult"));
        assert!(debug.contains("AllOk"));
    }
}
