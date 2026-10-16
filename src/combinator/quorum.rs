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
//! - For nonzero quorums, a panic in any drained branch is catastrophic and
//!   [`quorum_to_result`] returns [`QuorumError::Panicked`] even when enough
//!   sibling branches succeeded. `quorum(0, N)` remains the additive identity.
//!
//! # Edge Cases
//!
//! - `quorum(0, N)`: Return Ok([]) immediately, cancel all
//! - `quorum(N, N)`: Equivalent to join_all
//! - `quorum(1, N)`: Equivalent to race_all (first success wins)
//! - `quorum(M, N) where M > N`: Error (invalid quorum)
//!
//! # Executable entry point
//!
//! The items in this module are the *aggregation* half of the combinator:
//! [`quorum_outcomes`] / [`quorum_to_result`] fold an already-collected
//! outcome vector, and [`quorum_still_possible`] / [`quorum_achieved`] are the
//! early-termination predicates. The half that actually spawns branches,
//! waits for M successes, and cancels **and drains** the rest is
//! [`Scope::quorum`](crate::cx::Scope::quorum): it runs the pseudocode above
//! on the runtime and aggregates through these folders. Note that the
//! executable entry rejects `needed == 0` (as well as `needed > N`) with
//! [`QuorumError::InvalidQuorum`] before spawning anything, while the folder
//! keeps `quorum(0, N)` as the algebraic additive identity.

use core::fmt;
use std::marker::PhantomData;

use crate::types::Outcome;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;

/// A quorum combinator for M-of-N completion semantics.
///
/// This is a builder/marker type; execution happens through
/// [`Scope::quorum`](crate::cx::Scope::quorum), which aggregates through
/// [`quorum_outcomes`] and [`quorum_to_result`].
#[derive(Debug)]
pub struct Quorum<T, E> {
    _t: PhantomData<T>,
    _e: PhantomData<E>,
}

impl<T, E> Quorum<T, E> {
    /// Creates a new quorum combinator (internal use).
    #[inline]
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
            // Scope::quorum also refuses needed == 0, which does not exceed
            // anything.
            Self::InvalidQuorum { required: 0, total } => {
                write!(
                    f,
                    "invalid quorum: required 0 of {total}, at least 1 success must be required"
                )
            }
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
/// # Invalid Parameters
/// If `required > outcomes.len()`, the quorum is invalid and can never be met.
/// In this case, [`quorum_outcomes`] returns a `QuorumResult` with
/// `quorum_met = false`; [`quorum_to_result`] will return
/// [`QuorumError::InvalidQuorum`].
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
pub fn quorum_outcomes<T, E>(required: usize, outcomes: Vec<Outcome<T, E>>) -> QuorumResult<T, E> {
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

    let total = outcomes.len();
    let mut successes = Vec::with_capacity(total);
    let mut failures = Vec::with_capacity(total);

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
/// If the quorum was met and no branch panicked, returns `Ok` with the
/// successful values. For a nonzero quorum, a panic in any branch—including a
/// drained loser—takes precedence and returns [`QuorumError::Panicked`].
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
pub fn quorum_to_result<T, E>(result: QuorumResult<T, E>) -> Result<Vec<T>, QuorumError<E>> {
    let total = result.total();
    if result.required > total {
        return Err(QuorumError::InvalidQuorum {
            required: result.required,
            total,
        });
    }

    // `quorum(0, N)` is the additive identity: succeed immediately with no
    // winners, regardless of loser outcomes.
    if result.required == 0 {
        return Ok(Vec::new());
    }

    // Check for panics first (highest severity).
    // A panic in any branch (winner or loser) is a catastrophic failure and must propagate.
    for (_, failure) in &result.failures {
        if let QuorumFailure::Panicked(p) = failure {
            return Err(QuorumError::Panicked(p.clone()));
        }
    }

    if result.quorum_met {
        // Return successful values (without indices)
        Ok(result.successes.into_iter().map(|(_, v)| v).collect())
    } else {
        // Check for cancellations (but not quorum-met cancellations, which are
        // expected), reporting the strongest as join_all does: the first by
        // index could be weaker (a branch's own poll-quota stop) than the
        // shutdown that drained the rest (br-asupersync-1sngsf).
        let mut cancelled: Option<CancelReason> = None;
        for (_, failure) in &result.failures {
            if let QuorumFailure::Cancelled(r) = failure {
                // Only report if it's not a "quorum met" cancellation (i.e., a loser)
                if !matches!(r.kind(), crate::types::cancel::CancelKind::RaceLost) {
                    match &mut cancelled {
                        Some(strongest) => {
                            strongest.strengthen(r);
                        }
                        None => cancelled = Some(r.clone()),
                    }
                }
            }
        }
        if let Some(reason) = cancelled {
            return Err(QuorumError::Cancelled(reason));
        }

        // Compute counts before moving failures
        let success_count = result.success_count();
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

#[cfg(test)]
#[path = "quorum_inline_tests.rs"]
mod tests;
