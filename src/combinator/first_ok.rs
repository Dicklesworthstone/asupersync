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
//! Two executable forms share the aggregation types in this module:
//!
//! - the inline [`first_ok!`](crate::first_ok) macro awaits each operation in
//!   place and yields a [`FirstOkResult`];
//! - [`Scope::first_ok`](crate::cx::Scope::first_ok) invokes lazy branch
//!   *factories* one at a time, runs each attempt as a region task, drains an
//!   in-flight attempt when the caller is cancelled, and folds the terminal
//!   outcomes through [`FirstOkResult`] / [`first_ok_to_result`].
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

use crate::types::Outcome;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;

/// A first_ok combinator for fallback chains.
///
/// This is a builder/marker type; execution happens through the
/// [`first_ok!`](crate::first_ok) macro (inline) or
/// [`Scope::first_ok`](crate::cx::Scope::first_ok) (runtime tasks).
#[derive(Debug)]
pub struct FirstOk<T, E> {
    _t: PhantomData<T>,
    _e: PhantomData<E>,
}

impl<T, E> FirstOk<T, E> {
    /// Creates a new first_ok combinator (internal use).
    #[inline]
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
pub fn first_ok_outcomes<T, E>(outcomes: Vec<Outcome<T, E>>) -> FirstOkResult<T, E> {
    let total = outcomes.len();

    // Handle empty case
    if total == 0 {
        return FirstOkResult::failure(Vec::new(), 0);
    }

    let mut failures = Vec::with_capacity(total);

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
pub fn first_ok_to_result<T, E>(result: FirstOkResult<T, E>) -> Result<T, FirstOkError<E>> {
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
    if let Some(cancel_idx) = result
        .failures
        .iter()
        .position(|(_, f)| matches!(f, FirstOkFailure::Cancelled(_)))
    {
        let _attempted = result.failures.len();
        let mut failures = result.failures;
        let cancel_failure = failures.remove(cancel_idx);
        let FirstOkFailure::Cancelled(reason) = cancel_failure.1 else {
            unreachable!()
        };

        // Collect errors before the cancellation
        let errors_before: Vec<E> = failures
            .into_iter()
            .take(cancel_idx)
            .filter_map(|(_, f)| match f {
                FirstOkFailure::Error(e) => Some(e),
                _ => None,
            })
            .collect();

        return Err(FirstOkError::Cancelled {
            reason,
            errors_before_cancel: errors_before,
            attempted_before_cancel: cancel_idx, // Number of attempts before the cancelled one
        });
    }

    // All errors - collect them
    let attempted = result.failures.len();
    let errors: Vec<E> = result
        .failures
        .into_iter()
        .filter_map(|(_, f)| match f {
            FirstOkFailure::Error(e) => Some(e),
            _ => None,
        })
        .collect();

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
    (@count $head:expr $(, $tail:expr)*) => {
        1usize $(+ $crate::first_ok!(@count $tail))*
    };
    ($($operation:expr),+ $(,)?) => {{
        async move {
            let __first_ok_total = $crate::first_ok!(@count $($operation),+);
            let mut __first_ok_failures = ::std::vec::Vec::with_capacity(__first_ok_total);
            let mut __first_ok_index = 0usize;

            $(
                // Never start an attempt once the ambient task is cancelled
                // (the module docs' "check cancellation before each attempt").
                if let ::std::option::Option::Some(__first_ok_reason) =
                    $crate::cx::Cx::current().and_then(|__first_ok_cx| {
                        __first_ok_cx.checkpoint().err().map(|_| {
                            __first_ok_cx.cancel_reason().unwrap_or_else(|| {
                                $crate::types::CancelReason::user("first_ok cancelled")
                            })
                        })
                    })
                {
                    __first_ok_failures.push((
                        __first_ok_index,
                        $crate::combinator::first_ok::FirstOkFailure::Cancelled(__first_ok_reason),
                    ));
                    return $crate::combinator::first_ok::FirstOkResult::failure(
                        __first_ok_failures,
                        __first_ok_total,
                    );
                }
                match ($operation).await {
                    $crate::types::Outcome::Ok(__first_ok_value) => {
                        return $crate::combinator::first_ok::FirstOkResult::success(
                            __first_ok_index,
                            __first_ok_value,
                            __first_ok_failures,
                            __first_ok_total,
                        );
                    }
                    $crate::types::Outcome::Err(__first_ok_error) => {
                        __first_ok_failures.push((
                            __first_ok_index,
                            $crate::combinator::first_ok::FirstOkFailure::Error(__first_ok_error),
                        ));
                    }
                    $crate::types::Outcome::Cancelled(__first_ok_reason) => {
                        __first_ok_failures.push((
                            __first_ok_index,
                            $crate::combinator::first_ok::FirstOkFailure::Cancelled(__first_ok_reason),
                        ));
                        return $crate::combinator::first_ok::FirstOkResult::failure(
                            __first_ok_failures,
                            __first_ok_total,
                        );
                    }
                    $crate::types::Outcome::Panicked(__first_ok_payload) => {
                        __first_ok_failures.push((
                            __first_ok_index,
                            $crate::combinator::first_ok::FirstOkFailure::Panicked(__first_ok_payload),
                        ));
                        return $crate::combinator::first_ok::FirstOkResult::failure(
                            __first_ok_failures,
                            __first_ok_total,
                        );
                    }
                }
                __first_ok_index += 1;
            )+

            $crate::combinator::first_ok::FirstOkResult::failure(
                __first_ok_failures,
                __first_ok_total,
            )
        }
    }};
}

#[cfg(test)]
#[path = "first_ok_inline_tests.rs"]
mod tests;
