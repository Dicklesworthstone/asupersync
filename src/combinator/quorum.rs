//! Quorum combinator: M-of-N completion semantics.
//!
//! The quorum combinator waits for M out of N concurrent operations to succeed.
//! This is essential for distributed consensus patterns, redundancy, and
//! fault-tolerant operations.
//!
//! # Mathematical Foundation
//!
//! Quorum generalizes between join and race in the near-semiring:
//! - `join(a, b)` = quorum(2, [a, b]) - all must succeed (N-of-N)
//! - `race(a, b)` = quorum(1, [a, b]) - first wins (1-of-N)
//! - `quorum(M, [a, b, ...])` - M-of-N generalization
//!
//! # Critical Invariant: Losers Are Drained
//!
//! Like race, quorum always drains losers:
//!
//! ```text
//! quorum(M, [f1, f2, ..., fn]):
//!   t1..tn ← spawn all futures
//!   winners ← []
//!   while len(winners) < M and possible:
//!     outcome ← await_any_complete(t1..tn)
//!     if outcome is Ok:
//!       winners.push(outcome)
//!     if remaining_failures > N - M:
//!       break  // Quorum impossible
//!   cancel(remaining tasks)
//!   await(remaining tasks)  // CRITICAL: drain all
//!   return aggregate(winners, losers)
//! ```
//!
//! # Outcome Aggregation
//!
//! - If ≥M tasks succeed: return Ok with successful values
//! - If quorum impossible: return worst outcome per severity lattice
//!   `Ok < Err < Cancelled < Panicked`
//!
//! # Edge Cases
//!
//! - `quorum(0, N)`: Return Ok([]) immediately, cancel all
//! - `quorum(N, N)`: Equivalent to join_all
//! - `quorum(1, N)`: Equivalent to race_all (first success wins)
//! - `quorum(M, N) where M > N`: Error (invalid quorum)

use core::fmt;
use std::marker::PhantomData;

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::Outcome;

/// A quorum combinator for M-of-N completion semantics.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct Quorum<T, E> {
    _t: PhantomData<T>,
    _e: PhantomData<E>,
}

impl<T, E> Quorum<T, E> {
    /// Creates a new quorum combinator (internal use).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _t: PhantomData,
            _e: PhantomData,
        }
    }
}

impl<T, E> Default for Quorum<T, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for quorum operations.
///
/// When a quorum cannot be achieved (too many failures), this error type
/// captures the failure information.
#[derive(Debug, Clone)]
pub enum QuorumError<E> {
    /// Not enough successes to meet the quorum.
    ///
    /// Contains the required quorum, total count, and all errors encountered.
    InsufficientSuccesses {
        /// Required number of successes.
        required: usize,
        /// Total number of operations.
        total: usize,
        /// Number of successes achieved.
        achieved: usize,
        /// Errors from failed operations.
        errors: Vec<E>,
    },
    /// One of the operations was cancelled.
    Cancelled(CancelReason),
    /// One of the operations panicked.
    Panicked(PanicPayload),
    /// Invalid quorum parameters (M > N).
    InvalidQuorum {
        /// Required successes.
        required: usize,
        /// Total operations.
        total: usize,
    },
}

impl<E: fmt::Display> fmt::Display for QuorumError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSuccesses {
                required,
                total,
                achieved,
                errors,
            } => {
                write!(
                    f,
                    "quorum not met: needed {required}/{total}, got {achieved} successes with {} errors",
                    errors.len()
                )
            }
            Self::Cancelled(r) => write!(f, "quorum cancelled: {r}"),
            Self::Panicked(p) => write!(f, "quorum panicked: {p}"),
            Self::InvalidQuorum { required, total } => {
                write!(
                    f,
                    "invalid quorum: required {required} exceeds total {total}"
                )
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for QuorumError<E> {}

/// Result of a quorum operation.
///
/// Contains information about which operations succeeded, which failed,
/// and whether the quorum was achieved.
#[derive(Debug)]
pub struct QuorumResult<T, E> {
    /// Whether the quorum was achieved (≥M successes).
    pub quorum_met: bool,
    /// Required number of successes.
    pub required: usize,
    /// Successful outcomes with their original indices.
    pub successes: Vec<(usize, T)>,
    /// Failed outcomes with their original indices.
    pub failures: Vec<(usize, QuorumFailure<E>)>,
    /// Whether any operation was cancelled.
    pub has_cancellation: bool,
    /// Whether any operation panicked.
    pub has_panic: bool,
}

/// A single failure in a quorum operation.
#[derive(Debug, Clone)]
pub enum QuorumFailure<E> {
    /// Application error.
    Error(E),
    /// Cancelled (typically as a loser when quorum was met).
    Cancelled(CancelReason),
    /// Panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for QuorumFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "error: {e}"),
            Self::Cancelled(r) => write!(f, "cancelled: {r}"),
            Self::Panicked(p) => write!(f, "panicked: {p}"),
        }
    }
}

impl<T, E> QuorumResult<T, E> {
    /// Creates a new quorum result.
    #[must_use]
    pub fn new(
        quorum_met: bool,
        required: usize,
        successes: Vec<(usize, T)>,
        failures: Vec<(usize, QuorumFailure<E>)>,
    ) -> Self {
        let has_cancellation = failures
            .iter()
            .any(|(_, f)| matches!(f, QuorumFailure::Cancelled(_)));
        let has_panic = failures
            .iter()
            .any(|(_, f)| matches!(f, QuorumFailure::Panicked(_)));

        Self {
            quorum_met,
            required,
            successes,
            failures,
            has_cancellation,
            has_panic,
        }
    }

    /// Returns true if the quorum was achieved.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.quorum_met
    }

    /// Returns the number of successful operations.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.successes.len()
    }

    /// Returns the number of failed operations.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Returns the total number of operations.
    #[must_use]
    pub fn total(&self) -> usize {
        self.successes.len() + self.failures.len()
    }
}

/// Aggregates outcomes with M-of-N quorum semantics.
///
/// This is the semantic core of the quorum combinator.
///
/// # Arguments
/// * `required` - Number of successes needed (M)
/// * `outcomes` - All outcomes from the N operations
///
/// # Returns
/// A `QuorumResult` containing success/failure information.
///
/// # Panics
/// Panics if `required > outcomes.len()`.
///
/// # Example
/// ```
/// use asupersync::combinator::quorum::quorum_outcomes;
/// use asupersync::types::Outcome;
///
/// // 2-of-3 quorum
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Err("failed"),
///     Outcome::Ok(2),
/// ];
/// let result = quorum_outcomes(2, outcomes);
/// assert!(result.quorum_met);
/// assert_eq!(result.success_count(), 2);
/// ```
#[must_use]
pub fn quorum_outcomes<T, E: Clone>(
    required: usize,
    outcomes: Vec<Outcome<T, E>>,
) -> QuorumResult<T, E> {
    let total = outcomes.len();

    // Handle invalid quorum
    if required > total {
        // Return a result with quorum not met
        return QuorumResult::new(false, required, Vec::new(), Vec::new());
    }

    // Handle trivial quorum(0, N)
    if required == 0 {
        let failures: Vec<_> = outcomes
            .into_iter()
            .enumerate()
            .map(|(i, o)| match o {
                Outcome::Ok(_) => (i, QuorumFailure::Cancelled(CancelReason::quorum_met())),
                Outcome::Err(e) => (i, QuorumFailure::Error(e)),
                Outcome::Cancelled(r) => (i, QuorumFailure::Cancelled(r)),
                Outcome::Panicked(p) => (i, QuorumFailure::Panicked(p)),
            })
            .collect();
        return QuorumResult::new(true, required, Vec::new(), failures);
    }

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    // Process outcomes
    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Ok(v) => {
                successes.push((i, v));
            }
            Outcome::Err(e) => {
                failures.push((i, QuorumFailure::Error(e)));
            }
            Outcome::Cancelled(r) => {
                failures.push((i, QuorumFailure::Cancelled(r)));
            }
            Outcome::Panicked(p) => {
                failures.push((i, QuorumFailure::Panicked(p)));
            }
        }
    }

    let quorum_met = successes.len() >= required;
    QuorumResult::new(quorum_met, required, successes, failures)
}

/// Checks if quorum is still achievable given current state.
///
/// This is useful for early termination: if enough failures have occurred
/// that the quorum can no longer be met, we can cancel remaining tasks.
///
/// # Arguments
/// * `required` - Number of successes needed (M)
/// * `total` - Total number of operations (N)
/// * `successes` - Current number of successes
/// * `failures` - Current number of failures
///
/// # Returns
/// `true` if quorum is still achievable, `false` if impossible.
#[must_use]
pub const fn quorum_still_possible(
    required: usize,
    total: usize,
    successes: usize,
    failures: usize,
) -> bool {
    // Remaining = total - successes - failures
    // Need: successes + remaining >= required
    // Therefore: successes + (total - successes - failures) >= required
    // Simplify: total - failures >= required
    let remaining = total.saturating_sub(successes).saturating_sub(failures);
    successes + remaining >= required
}

/// Checks if quorum has been achieved.
///
/// # Arguments
/// * `required` - Number of successes needed (M)
/// * `successes` - Current number of successes
///
/// # Returns
/// `true` if quorum has been achieved.
#[must_use]
pub const fn quorum_achieved(required: usize, successes: usize) -> bool {
    successes >= required
}

/// Converts a quorum result to a Result for fail-fast handling.
///
/// If the quorum was met, returns `Ok` with the successful values.
/// If the quorum was not met, returns `Err` with failure information.
///
/// # Example
/// ```
/// use asupersync::combinator::quorum::{quorum_outcomes, quorum_to_result};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Err("failed"),
/// ];
/// let result = quorum_outcomes(2, outcomes);
/// let values = quorum_to_result(result);
/// assert!(values.is_ok());
/// let v = values.unwrap();
/// assert_eq!(v.len(), 2);
/// ```
pub fn quorum_to_result<T, E: Clone>(result: QuorumResult<T, E>) -> Result<Vec<T>, QuorumError<E>> {
    if result.quorum_met {
        // Return successful values (without indices)
        Ok(result.successes.into_iter().map(|(_, v)| v).collect())
    } else {
        // Check for panics first (highest severity)
        for (_, failure) in &result.failures {
            if let QuorumFailure::Panicked(p) = failure {
                return Err(QuorumError::Panicked(p.clone()));
            }
        }

        // Check for cancellations (but not quorum-met cancellations, which are expected)
        for (_, failure) in &result.failures {
            if let QuorumFailure::Cancelled(r) = failure {
                // Only report if it's not a "quorum met" cancellation (i.e., a loser)
                if !matches!(r.kind(), crate::types::cancel::CancelKind::RaceLost) {
                    return Err(QuorumError::Cancelled(r.clone()));
                }
            }
        }

        // Compute counts before moving failures
        let success_count = result.success_count();
        let failure_count = result.failure_count();
        let total = success_count + failure_count;
        let required = result.required;

        // Collect errors
        let errors: Vec<E> = result
            .failures
            .into_iter()
            .filter_map(|(_, f)| match f {
                QuorumFailure::Error(e) => Some(e),
                _ => None,
            })
            .collect();

        Err(QuorumError::InsufficientSuccesses {
            required,
            total,
            achieved: success_count,
            errors,
        })
    }
}

/// Creates a cancel reason for operations cancelled because quorum was met.
impl CancelReason {
    /// Creates a cancel reason indicating the operation was cancelled because
    /// the quorum was already met (it became a "loser").
    #[must_use]
    pub fn quorum_met() -> Self {
        // Reuse race_loser since semantically it's the same: cancelled because
        // another operation "won"
        Self::race_loser()
    }
}

/// Waits for N of M futures to complete successfully.
///
/// Useful for consensus patterns where you need a majority to agree.
///
/// # Semantics
///
/// ```ignore
/// let (successes, failures) = quorum!(2 of 3;
///     replica_1(),
///     replica_2(),
///     replica_3(),
/// ).await;
/// ```
///
/// - Returns when `required` futures have completed successfully
/// - Remaining futures are cancelled after quorum is met
/// - If quorum cannot be met (too many failures), returns early with error
#[macro_export]
macro_rules! quorum {
    // Syntax: quorum!(N of M; fut1, fut2, ...)
    ($required:expr, $($future:expr),+ $(,)?) => {{
        // Placeholder: in real implementation, this waits for N successes
        let _ = $required;
        $(let _ = $future;)+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_all_succeed() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
    }

    #[test]
    fn quorum_exact_meet() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Ok(2)];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
    }

    #[test]
    fn quorum_not_met() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Err("e2")];
        let result = quorum_outcomes(2, outcomes);

        assert!(!result.quorum_met);
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.failure_count(), 2);
    }

    #[test]
    fn quorum_zero_required() {
        // quorum(0, N) is trivially met
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(0, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 0);
        // All outcomes become "failures" (cancelled because quorum trivially met)
        assert_eq!(result.failure_count(), 3);
    }

    #[test]
    fn quorum_n_of_n_is_join() {
        // quorum(N, N) is equivalent to join: all must succeed
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 3);
    }

    #[test]
    fn quorum_n_of_n_one_fails() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e"), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes);

        assert!(!result.quorum_met);
        assert_eq!(result.success_count(), 2);
    }

    #[test]
    fn quorum_1_of_n_is_race() {
        // quorum(1, N) is equivalent to race: first success wins
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(2), Outcome::Err("e2")];
        let result = quorum_outcomes(1, outcomes);

        assert!(result.quorum_met);
        assert_eq!(result.success_count(), 1);
    }

    #[test]
    fn quorum_invalid_m_greater_than_n() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = quorum_outcomes(5, outcomes);

        // Invalid quorum cannot be met
        assert!(!result.quorum_met);
    }

    #[test]
    fn quorum_with_cancellation() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(2),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert!(result.has_cancellation);
    }

    #[test]
    fn quorum_with_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(2),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        assert!(result.has_panic);
    }

    #[test]
    fn quorum_to_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Err("e")];
        let result = quorum_outcomes(2, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_ok());
        let v = values.unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&1));
        assert!(v.contains(&2));
    }

    #[test]
    fn quorum_to_result_insufficient() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e1"), Outcome::Err("e2")];
        let result = quorum_outcomes(2, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_err());
        match values.unwrap_err() {
            QuorumError::InsufficientSuccesses {
                required,
                achieved,
                errors,
                ..
            } => {
                assert_eq!(required, 2);
                assert_eq!(achieved, 1);
                assert_eq!(errors.len(), 2);
            }
            _ => panic!("Expected InsufficientSuccesses"),
        }
    }

    #[test]
    fn quorum_to_result_panic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Err("e"),
        ];
        let result = quorum_outcomes(3, outcomes);
        let values = quorum_to_result(result);

        assert!(values.is_err());
        assert!(matches!(values.unwrap_err(), QuorumError::Panicked(_)));
    }

    #[test]
    fn quorum_still_possible_test() {
        // 2-of-3, 0 successes, 0 failures -> possible
        assert!(quorum_still_possible(2, 3, 0, 0));

        // 2-of-3, 1 success, 0 failures -> possible
        assert!(quorum_still_possible(2, 3, 1, 0));

        // 2-of-3, 2 successes, 0 failures -> possible (already met)
        assert!(quorum_still_possible(2, 3, 2, 0));

        // 2-of-3, 0 successes, 2 failures -> not possible (only 1 remaining)
        assert!(!quorum_still_possible(2, 3, 0, 2));

        // 2-of-3, 1 success, 1 failure -> possible (1 remaining)
        assert!(quorum_still_possible(2, 3, 1, 1));
    }

    #[test]
    fn quorum_achieved_test() {
        assert!(!quorum_achieved(2, 0));
        assert!(!quorum_achieved(2, 1));
        assert!(quorum_achieved(2, 2));
        assert!(quorum_achieved(2, 3));
        assert!(quorum_achieved(0, 0)); // Trivial quorum
    }

    #[test]
    fn quorum_error_display() {
        let err: QuorumError<&str> = QuorumError::InsufficientSuccesses {
            required: 2,
            total: 3,
            achieved: 1,
            errors: vec!["e1", "e2"],
        };
        assert!(err.to_string().contains("needed 2/3"));
        assert!(err.to_string().contains("got 1 successes"));

        let err: QuorumError<&str> = QuorumError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: QuorumError<&str> = QuorumError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));

        let err: QuorumError<&str> = QuorumError::InvalidQuorum {
            required: 5,
            total: 3,
        };
        assert!(err.to_string().contains("invalid quorum"));
    }

    #[test]
    fn quorum_preserves_indices() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e0"),
            Outcome::Ok(10),
            Outcome::Err("e2"),
            Outcome::Ok(30),
        ];
        let result = quorum_outcomes(2, outcomes);

        assert!(result.quorum_met);
        // Check that indices are preserved
        assert!(result.successes.iter().any(|(i, v)| *i == 1 && *v == 10));
        assert!(result.successes.iter().any(|(i, v)| *i == 3 && *v == 30));
        assert!(result.failures.iter().any(|(i, _)| *i == 0));
        assert!(result.failures.iter().any(|(i, _)| *i == 2));
    }

    // Algebraic property tests
    #[test]
    fn quorum_1_equals_race_semantics() {
        // quorum(1, N) should succeed if ANY operation succeeds
        let outcomes_success: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(2), Outcome::Err("e3")];
        let result = quorum_outcomes(1, outcomes_success);
        assert!(result.quorum_met);

        let outcomes_fail: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = quorum_outcomes(1, outcomes_fail);
        assert!(!result.quorum_met);
    }

    #[test]
    fn quorum_n_equals_join_semantics() {
        // quorum(N, N) should succeed only if ALL operations succeed
        let outcomes_success: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes_success);
        assert!(result.quorum_met);

        let outcomes_fail: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e"), Outcome::Ok(3)];
        let result = quorum_outcomes(3, outcomes_fail);
        assert!(!result.quorum_met);
    }

    #[test]
    fn quorum_monotone_in_required() {
        // If quorum(M, outcomes) succeeds, then quorum(M-1, outcomes) also succeeds
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Err("e")];

        let result_2 = quorum_outcomes(2, outcomes.clone());
        let result_1 = quorum_outcomes(1, outcomes.clone());
        let result_3 = quorum_outcomes(3, outcomes);

        assert!(result_1.quorum_met);
        assert!(result_2.quorum_met);
        assert!(!result_3.quorum_met);
    }

    #[test]
    fn quorum_empty_outcomes() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];

        // quorum(0, []) is trivially met
        let result = quorum_outcomes(0, outcomes.clone());
        assert!(result.quorum_met);

        // quorum(1, []) cannot be met
        let result = quorum_outcomes(1, outcomes);
        assert!(!result.quorum_met);
    }
}

/// Waits for N of M futures to complete successfully.
///
/// Useful for consensus patterns where you need a majority to agree.
///
/// # Semantics
///
/// ```ignore
/// let (successes, failures) = quorum!(2 of 3;
///     replica_1(),
///     replica_2(),
///     replica_3(),
/// ).await;
/// ```
///
/// - Returns when `required` futures have completed successfully
/// - Remaining futures are cancelled after quorum is met
/// - If quorum cannot be met (too many failures), returns early with error
#[macro_export]
macro_rules! quorum {
    // Syntax: quorum!(N of M; fut1, fut2, ...)
    ($required:expr, $($future:expr),+ $(,)?) => {{
        // Placeholder: in real implementation, this waits for N successes
        let _ = $required;
        $(let _ = $future;)+
    }};
}
