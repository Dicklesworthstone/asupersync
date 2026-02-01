//! First-ok combinator: try operations until one succeeds.
//!
//! The first_ok combinator tries a sequence of operations, returning the first
//! `Ok` result. If all operations fail, returns an aggregated error containing
//! all failures. This is essential for fallback chains, service discovery,
//! and graceful degradation.
//!
//! # Distinction from Race
//!
//! - **race**: Run all concurrently, first to *complete* wins (regardless of outcome)
//! - **first_ok**: Try sequentially, first *success* wins (errors cause fallback)
//!
//! For Phase 0 (single-threaded), this implements sequential first_ok.
//! Concurrent variants will be added in Phase 1.
//!
//! # Semantics
//!
//! ```text
//! first_ok([f1, f2, ..., fn]):
//!   errors ← []
//!   for f in [f1, f2, ..., fn]:
//!     check_cancellation()
//!     result ← await(f)
//!     if result is Ok:
//!       return Ok(result)
//!     else:
//!       errors.push(result)
//!   return Err(errors)
//! ```
//!
//! # Use Cases
//!
//! - **Service fallback**: Primary → Secondary → Tertiary endpoint
//! - **Configuration sources**: File → Environment → Defaults
//! - **Parser fallback**: Try parsers in preference order
//! - **Cache hierarchy**: L1 → L2 → L3 → Origin
//!
//! # Cancellation Handling
//!
//! - Check cancellation status before each attempt
//! - If cancelled: return Cancelled with errors collected so far
//! - Do not start new attempts after cancellation

use core::fmt;
use std::marker::PhantomData;

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::Outcome;

/// A first_ok combinator for fallback chains.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct FirstOk<T, E> {
    _t: PhantomData<T>,
    _e: PhantomData<E>,
}

impl<T, E> FirstOk<T, E> {
    /// Creates a new first_ok combinator (internal use).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _t: PhantomData,
            _e: PhantomData,
        }
    }
}

impl<T, E> Default for FirstOk<T, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for first_ok operations.
///
/// When no operation succeeds, this error contains all the failures encountered.
#[derive(Debug, Clone)]
pub enum FirstOkError<E> {
    /// All operations failed with errors.
    ///
    /// Contains the errors from each operation in attempt order.
    AllFailed {
        /// Errors from each failed operation.
        errors: Vec<E>,
        /// Total number of operations attempted.
        attempted: usize,
    },
    /// The operation was cancelled before any succeeded.
    ///
    /// Contains errors collected before cancellation.
    Cancelled {
        /// The cancellation reason.
        reason: CancelReason,
        /// Errors collected before cancellation.
        errors_before_cancel: Vec<E>,
        /// Number of operations attempted before cancellation.
        attempted_before_cancel: usize,
    },
    /// One of the operations panicked.
    Panicked(PanicPayload),
    /// No operations were provided.
    Empty,
}

impl<E: fmt::Display> fmt::Display for FirstOkError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllFailed { errors, attempted } => {
                write!(
                    f,
                    "all {} operations failed: {} errors",
                    attempted,
                    errors.len()
                )
            }
            Self::Cancelled {
                reason,
                errors_before_cancel,
                attempted_before_cancel,
            } => {
                write!(
                    f,
                    "cancelled after {} attempts ({} errors): {}",
                    attempted_before_cancel,
                    errors_before_cancel.len(),
                    reason
                )
            }
            Self::Panicked(p) => write!(f, "operation panicked: {p}"),
            Self::Empty => write!(f, "no operations provided"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for FirstOkError<E> {}

/// A single failure in a first_ok chain.
#[derive(Debug, Clone)]
pub enum FirstOkFailure<E> {
    /// Application error.
    Error(E),
    /// Cancelled.
    Cancelled(CancelReason),
    /// Panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for FirstOkFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "error: {e}"),
            Self::Cancelled(r) => write!(f, "cancelled: {r}"),
            Self::Panicked(p) => write!(f, "panicked: {p}"),
        }
    }
}

/// Result of a first_ok operation.
///
/// Contains either the successful value or all failures encountered.
#[derive(Debug)]
pub struct FirstOkResult<T, E> {
    /// Whether any operation succeeded.
    pub success: Option<FirstOkSuccess<T>>,
    /// All failures encountered before success (or all failures if none succeeded).
    pub failures: Vec<(usize, FirstOkFailure<E>)>,
    /// Total number of operations.
    pub total: usize,
    /// Whether a cancellation was encountered.
    pub was_cancelled: bool,
    /// Whether a panic was encountered.
    pub had_panic: bool,
}

/// A successful result in a first_ok chain.
#[derive(Debug)]
pub struct FirstOkSuccess<T> {
    /// Index of the successful operation.
    pub index: usize,
    /// The successful value.
    pub value: T,
}

impl<T, E> FirstOkResult<T, E> {
    /// Creates a new first_ok result with a success.
    #[must_use]
    pub fn success(
        index: usize,
        value: T,
        failures: Vec<(usize, FirstOkFailure<E>)>,
        total: usize,
    ) -> Self {
        Self {
            success: Some(FirstOkSuccess { index, value }),
            failures,
            total,
            was_cancelled: false,
            had_panic: false,
        }
    }

    /// Creates a new first_ok result with no success.
    #[must_use]
    pub fn failure(failures: Vec<(usize, FirstOkFailure<E>)>, total: usize) -> Self {
        let was_cancelled = failures
            .iter()
            .any(|(_, f)| matches!(f, FirstOkFailure::Cancelled(_)));
        let had_panic = failures
            .iter()
            .any(|(_, f)| matches!(f, FirstOkFailure::Panicked(_)));

        Self {
            success: None,
            failures,
            total,
            was_cancelled,
            had_panic,
        }
    }

    /// Returns true if any operation succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.success.is_some()
    }

    /// Returns the number of operations attempted before success (or total if no success).
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.success
            .as_ref()
            .map_or(self.failures.len(), |s| s.index + 1)
    }
}

/// Aggregates outcomes with first-ok semantics.
///
/// This is the semantic core of the first_ok combinator. It processes
/// outcomes in order and returns on the first success.
///
/// # Arguments
/// * `outcomes` - All outcomes from the operations in attempt order
///
/// # Returns
/// A `FirstOkResult` containing either the first success or all failures.
///
/// # Example
/// ```
/// use asupersync::combinator::first_ok::first_ok_outcomes;
/// use asupersync::types::Outcome;
///
/// // Second operation succeeds
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Err("first failed"),
///     Outcome::Ok(42),
///     Outcome::Err("never reached"),
/// ];
/// let result = first_ok_outcomes(outcomes);
/// assert!(result.is_success());
/// assert_eq!(result.success.unwrap().index, 1);
/// ```
#[must_use]
pub fn first_ok_outcomes<T, E: Clone>(outcomes: Vec<Outcome<T, E>>) -> FirstOkResult<T, E> {
    let total = outcomes.len();

    // Handle empty case
    if total == 0 {
        return FirstOkResult::failure(Vec::new(), 0);
    }

    let mut failures = Vec::new();

    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Ok(v) => {
                // First success - return immediately
                return FirstOkResult::success(i, v, failures, total);
            }
            Outcome::Err(e) => {
                failures.push((i, FirstOkFailure::Error(e)));
            }
            Outcome::Cancelled(r) => {
                failures.push((i, FirstOkFailure::Cancelled(r)));
                // Cancellation stops the chain
                return FirstOkResult::failure(failures, total);
            }
            Outcome::Panicked(p) => {
                failures.push((i, FirstOkFailure::Panicked(p)));
                // Panic stops the chain
                return FirstOkResult::failure(failures, total);
            }
        }
    }

    // All failed
    FirstOkResult::failure(failures, total)
}

/// Converts a first_ok result to a Result for fail-fast handling.
///
/// If any operation succeeded, returns `Ok` with the value.
/// If all failed, returns `Err` with all errors.
///
/// # Example
/// ```
/// use asupersync::combinator::first_ok::{first_ok_outcomes, first_ok_to_result};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Err("first failed"),
///     Outcome::Ok(42),
/// ];
/// let result = first_ok_outcomes(outcomes);
/// let value = first_ok_to_result(result);
/// assert_eq!(value.unwrap(), 42);
/// ```
pub fn first_ok_to_result<T, E: Clone>(result: FirstOkResult<T, E>) -> Result<T, FirstOkError<E>> {
    // Check for success first
    if let Some(success) = result.success {
        return Ok(success.value);
    }

    // Handle empty case
    if result.total == 0 {
        return Err(FirstOkError::Empty);
    }

    // Check for panics first (highest severity)
    for (_, failure) in &result.failures {
        if let FirstOkFailure::Panicked(p) = failure {
            return Err(FirstOkError::Panicked(p.clone()));
        }
    }

    // Check for cancellations
    for (_, failure) in &result.failures {
        if let FirstOkFailure::Cancelled(r) = failure {
            // Collect errors before the cancellation
            let errors_before: Vec<E> = result
                .failures
                .iter()
                .filter_map(|(_, f)| match f {
                    FirstOkFailure::Error(e) => Some(e.clone()),
                    _ => None,
                })
                .collect();
            let attempted = result.failures.len();

            return Err(FirstOkError::Cancelled {
                reason: r.clone(),
                errors_before_cancel: errors_before,
                attempted_before_cancel: attempted,
            });
        }
    }

    // All errors - collect them
    let errors: Vec<E> = result
        .failures
        .into_iter()
        .filter_map(|(_, f)| match f {
            FirstOkFailure::Error(e) => Some(e),
            _ => None,
        })
        .collect();
    let attempted = errors.len();

    Err(FirstOkError::AllFailed { errors, attempted })
}

/// Checks if first_ok can still succeed given current state.
///
/// This is useful for early termination in concurrent implementations:
/// if cancellation or panic occurred, we should stop trying.
///
/// # Arguments
/// * `was_cancelled` - Whether a cancellation has been encountered
/// * `had_panic` - Whether a panic has been encountered
/// * `remaining` - Number of operations not yet tried
///
/// # Returns
/// `true` if first_ok can still succeed, `false` if impossible.
#[must_use]
pub const fn first_ok_still_possible(
    was_cancelled: bool,
    had_panic: bool,
    remaining: usize,
) -> bool {
    !was_cancelled && !had_panic && remaining > 0
}

/// Tries operations sequentially until one succeeds.
///
/// Returns the first success, or a collection of all errors if all fail.
///
/// # Semantics
///
/// ```ignore
/// let result = first_ok!(
///     try_cache(),
///     try_database(),
///     try_fallback(),
/// ).await;
/// ```
///
/// Operations are tried in order. Unlike `race!`, this is sequential:
/// the second operation only starts after the first fails.
#[macro_export]
macro_rules! first_ok {
    ($($operation:expr),+ $(,)?) => {{
        // Placeholder: in real implementation, this tries operations sequentially
        $(let _ = $operation;)+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_ok_first_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 0);
        assert_eq!(success.value, 1);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn first_ok_middle_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(42), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 1);
        assert_eq!(success.value, 42);
        assert_eq!(result.failures.len(), 1); // Only first failure collected
    }

    #[test]
    fn first_ok_last_succeeds() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Ok(99)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        let success = result.success.unwrap();
        assert_eq!(success.index, 2);
        assert_eq!(success.value, 99);
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_all_fail() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.success.is_none());
        assert_eq!(result.failures.len(), 3);
    }

    #[test]
    fn first_ok_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert_eq!(result.total, 0);
    }

    #[test]
    fn first_ok_single_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 42);
    }

    #[test]
    fn first_ok_single_failure() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail")];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert_eq!(result.failures.len(), 1);
    }

    #[test]
    fn first_ok_cancellation_stops() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(42), // Never reached
        ];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.was_cancelled);
        // The Ok at index 2 is not processed
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_panic_stops() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(42), // Never reached
        ];
        let result = first_ok_outcomes(outcomes);

        assert!(!result.is_success());
        assert!(result.had_panic);
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn first_ok_to_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Ok(42)];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_ok());
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn first_ok_to_result_all_failed() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Err("e2")];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        match value.unwrap_err() {
            FirstOkError::AllFailed { errors, attempted } => {
                assert_eq!(errors.len(), 2);
                assert_eq!(attempted, 2);
            }
            _ => panic!("Expected AllFailed"),
        }
    }

    #[test]
    fn first_ok_to_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Err("e1"),
            Outcome::Cancelled(CancelReason::timeout()),
        ];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        match value.unwrap_err() {
            FirstOkError::Cancelled {
                errors_before_cancel,
                attempted_before_cancel,
                ..
            } => {
                assert_eq!(errors_before_cancel.len(), 1);
                assert_eq!(attempted_before_cancel, 2);
            }
            _ => panic!("Expected Cancelled"),
        }
    }

    #[test]
    fn first_ok_to_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Panicked(PanicPayload::new("boom"))];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        assert!(matches!(value.unwrap_err(), FirstOkError::Panicked(_)));
    }

    #[test]
    fn first_ok_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = first_ok_outcomes(outcomes);
        let value = first_ok_to_result(result);

        assert!(value.is_err());
        assert!(matches!(value.unwrap_err(), FirstOkError::Empty));
    }

    #[test]
    fn first_ok_error_display() {
        let err: FirstOkError<&str> = FirstOkError::AllFailed {
            errors: vec!["e1", "e2"],
            attempted: 2,
        };
        assert!(err.to_string().contains("2 operations failed"));

        let err: FirstOkError<&str> = FirstOkError::Cancelled {
            reason: CancelReason::timeout(),
            errors_before_cancel: vec!["e1"],
            attempted_before_cancel: 2,
        };
        assert!(err.to_string().contains("cancelled"));

        let err: FirstOkError<&str> = FirstOkError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));

        let err: FirstOkError<&str> = FirstOkError::Empty;
        assert!(err.to_string().contains("no operations"));
    }

    #[test]
    fn first_ok_still_possible_test() {
        // Not cancelled, not panicked, has remaining
        assert!(first_ok_still_possible(false, false, 3));

        // Not cancelled, not panicked, no remaining
        assert!(!first_ok_still_possible(false, false, 0));

        // Cancelled
        assert!(!first_ok_still_possible(true, false, 3));

        // Panicked
        assert!(!first_ok_still_possible(false, true, 3));

        // Both
        assert!(!first_ok_still_possible(true, true, 3));
    }

    #[test]
    fn first_ok_attempts_count() {
        // Success at index 1 means 2 attempts
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e1"), Outcome::Ok(42), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);
        assert_eq!(result.attempts(), 2);

        // All fail means attempts == failures.len()
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("e1"), Outcome::Err("e2")];
        let result = first_ok_outcomes(outcomes);
        assert_eq!(result.attempts(), 2);
    }

    #[test]
    fn first_ok_preserves_failure_indices() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e0"), Outcome::Err("e1"), Outcome::Ok(2)];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        assert_eq!(result.failures.len(), 2);
        assert_eq!(result.failures[0].0, 0);
        assert_eq!(result.failures[1].0, 1);
    }

    // Semantic property tests
    #[test]
    fn first_ok_short_circuits() {
        // After first success, later outcomes don't affect result
        let outcomes1: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e"), Outcome::Ok(1), Outcome::Ok(2)];
        let outcomes2: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("e"), Outcome::Ok(1), Outcome::Err("ignored")];

        let r1 = first_ok_outcomes(outcomes1);
        let r2 = first_ok_outcomes(outcomes2);

        // Both should have same success
        assert_eq!(
            r1.success.as_ref().unwrap().value,
            r2.success.as_ref().unwrap().value
        );
        assert_eq!(
            r1.success.as_ref().unwrap().index,
            r2.success.as_ref().unwrap().index
        );
    }

    #[test]
    fn first_ok_err_after_success_not_collected() {
        // Errors after the first success are not collected
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("e2"), Outcome::Err("e3")];
        let result = first_ok_outcomes(outcomes);

        assert!(result.is_success());
        // No failures collected because first succeeded
        assert!(result.failures.is_empty());
    }

    #[test]
    fn first_ok_vs_race_semantic_difference() {
        // In first_ok, a failing operation before success doesn't win
        // This is different from race where first completion wins
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fast_error"), Outcome::Ok(42)];

        let result = first_ok_outcomes(outcomes);

        // first_ok: second operation wins because it's Ok
        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 42);

        // In race, the first to complete (Err) would win
        // This test documents the semantic difference
    }
}
