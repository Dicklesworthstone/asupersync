//! Map-reduce combinator: parallel map followed by monoid-based reduction.
//!
//! The map_reduce combinator spawns N parallel tasks, waits for all to complete,
//! then reduces successful results using an associative combine function.
//!
//! # Semantics
//!
//! `map_reduce(inputs, map_fn, reduce_fn)`:
//! 1. Spawn a task for each input, applying `map_fn`
//! 2. Wait for ALL tasks to complete (join semantics)
//! 3. Collect successful values in input order
//! 4. Reduce values using `reduce_fn` (left fold in input order)
//!
//! # Algebraic Properties
//!
//! - **Deterministic reduction**: Values are reduced in input order (left fold)
//! - **Associative requirement**: For parallel execution, `reduce_fn` should be
//!   associative: `reduce(reduce(a, b), c) == reduce(a, reduce(b, c))`
//! - **Commutativity optional**: If `reduce_fn` is also commutative, reduction
//!   order doesn't affect the result
//!
//! # Outcome Semantics
//!
//! Follows the same severity lattice as join: `Ok < Err < Cancelled < Panicked`
//!
//! - If all tasks succeed: reduce all values and return `Ok(reduced)`
//! - If any task fails: return the aggregate failure (worst severity)
//! - Partial results from successful tasks are preserved for inspection
//!
//! # Critical Invariants
//!
//! - **No abandonment**: All spawned tasks complete (cancel/drain if needed)
//! - **Region quiescence**: All children done before return
//! - **Deterministic**: Same seed → same execution order in lab runtime
//! - **Ordered reduction**: Values always reduced in input order

use core::fmt;
use std::marker::PhantomData;

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::policy::AggregateDecision;
use crate::types::Outcome;

/// A map-reduce combinator for parallel computation with aggregation.
///
/// This is a builder/marker type representing a map-reduce operation.
/// Actual execution happens via the runtime's spawn and await mechanisms.
///
/// # Type Parameters
/// * `T` - The output type from the map phase (also the reduce input/output)
///
/// # Semantics
///
/// Given inputs `i[0..n)`, map function `f`, and reduce function `r`:
/// 1. Spawn `f(i[k])` for each input as children in a subregion
/// 2. Await all join handles (join semantics)
/// 3. Collect successful values `v[0..m)` in input order
/// 4. Compute `r(r(r(v[0], v[1]), v[2]), ...)` (left fold)
/// 5. Return reduced value or aggregate failure
///
/// # Invariants
///
/// - **No abandonment**: Every spawned task completes
/// - **Region quiescence**: All children done before return
/// - **Deterministic**: Same seed → same execution order in lab runtime
/// - **Ordered reduction**: Values reduced in input order (left fold)
///
/// # Example (API shape)
/// ```ignore
/// let sum = scope.map_reduce(
///     cx,
///     vec![1, 2, 3, 4, 5],
///     |n| async move { Outcome::Ok(n * 2) },
///     |acc, val| acc + val,
/// ).await;
/// // sum == Ok(30) if all succeed
/// ```
#[derive(Debug)]
pub struct MapReduce<T> {
    _t: PhantomData<T>,
}

impl<T> MapReduce<T> {
    /// Creates a new map-reduce combinator (internal use).
    #[must_use]
    pub const fn new() -> Self {
        Self { _t: PhantomData }
    }
}

impl<T> Default for MapReduce<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for MapReduce<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for MapReduce<T> {}

/// Result from a map-reduce operation.
///
/// Contains the aggregate decision, the reduced value (if all succeeded or
/// partial reduction is possible), and metadata about the operation.
pub struct MapReduceResult<T, E> {
    /// The aggregate decision following the severity lattice.
    pub decision: AggregateDecision<E>,
    /// The reduced value from successful tasks, if any succeeded.
    /// `None` if no tasks succeeded or reduction requires all to succeed.
    pub reduced: Option<T>,
    /// Successful values with their original indices (before reduction).
    /// Useful for debugging or partial result recovery.
    pub successes: Vec<(usize, T)>,
    /// The total number of tasks that were spawned.
    pub total_count: usize,
}

impl<T, E> MapReduceResult<T, E> {
    /// Creates a new map-reduce result.
    #[must_use]
    pub fn new(
        decision: AggregateDecision<E>,
        reduced: Option<T>,
        successes: Vec<(usize, T)>,
        total_count: usize,
    ) -> Self {
        Self {
            decision,
            reduced,
            successes,
            total_count,
        }
    }

    /// Returns true if all tasks succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        matches!(self.decision, AggregateDecision::AllOk)
            && self.successes.len() == self.total_count
    }

    /// Returns the number of successful tasks.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.successes.len()
    }

    /// Returns the number of failed tasks.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.total_count - self.successes.len()
    }

    /// Returns true if there's a reduced value available.
    #[must_use]
    pub fn has_reduced(&self) -> bool {
        self.reduced.is_some()
    }
}

impl<T: fmt::Debug, E: fmt::Debug> fmt::Debug for MapReduceResult<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapReduceResult")
            .field("decision", &self.decision)
            .field("reduced", &self.reduced)
            .field("successes", &self.successes)
            .field("total_count", &self.total_count)
            .finish()
    }
}

/// Error type for map-reduce operations.
///
/// When a map-reduce fails (not all tasks succeeded), this type
/// indicates the nature of the failure.
#[derive(Debug, Clone)]
pub enum MapReduceError<E> {
    /// At least one task encountered an error.
    Error {
        /// The error from the first failing task.
        error: E,
        /// Index of the task that produced this error.
        index: usize,
        /// Total number of tasks that failed.
        total_failures: usize,
        /// Number of tasks that succeeded.
        success_count: usize,
    },
    /// At least one task was cancelled.
    Cancelled(CancelReason),
    /// At least one task panicked.
    Panicked(PanicPayload),
    /// No tasks were provided (empty input).
    Empty,
}

impl<E> MapReduceError<E> {
    /// Returns the error index if this was an application error.
    #[must_use]
    pub const fn error_index(&self) -> Option<usize> {
        match self {
            Self::Error { index, .. } => Some(*index),
            _ => None,
        }
    }

    /// Returns true if this was an application error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns true if a task was cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if a task panicked.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Returns true if the input was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

impl<E: fmt::Display> fmt::Display for MapReduceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error {
                error,
                index,
                total_failures,
                success_count,
            } => write!(
                f,
                "map-reduce task {index} failed: {error} ({total_failures} failures, {success_count} successes)"
            ),
            Self::Cancelled(r) => write!(f, "map-reduce cancelled: {r}"),
            Self::Panicked(p) => write!(f, "map-reduce panicked: {p}"),
            Self::Empty => write!(f, "map-reduce requires at least one input"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for MapReduceError<E> {}

/// Aggregates N outcomes and reduces successful values in input order.
///
/// This is the semantic core of `map_reduce`:
/// 1. Aggregate outcomes under the severity lattice
/// 2. Collect successful values with their indices
/// 3. Apply the reduce function to successful values (in input order)
///
/// # Arguments
/// * `outcomes` - The outcomes from all tasks, in their original order
/// * `reduce` - Function to combine two values into one
///
/// # Returns
/// A tuple of (aggregate decision, optional reduced value, successful values with indices).
///
/// # Reduction Order
/// Values are reduced in input order using a left fold:
/// `reduce(reduce(reduce(v[0], v[1]), v[2]), v[3])`
///
/// This is deterministic and predictable, but requires the reduce function
/// to be associative for equivalent parallel execution.
pub fn map_reduce_outcomes<T, E: Clone, F>(
    outcomes: Vec<Outcome<T, E>>,
    reduce: F,
) -> (AggregateDecision<E>, Option<T>, Vec<(usize, T)>)
where
    F: Fn(T, T) -> T,
    T: Clone,
{
    let mut successes: Vec<(usize, T)> = Vec::new();
    let mut first_error: Option<E> = None;
    let mut strongest_cancel: Option<CancelReason> = None;

    let mut panic_payload: Option<PanicPayload> = None;

    // Collect outcomes
    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Panicked(p) => {
                // Panic is the strongest - stop collecting but continue to do partial reduction
                panic_payload = Some(p);
                break;
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

    // Determine aggregate decision (panic takes precedence)
    let decision = panic_payload.map_or_else(
        || {
            strongest_cancel.map_or_else(
                || first_error.map_or(AggregateDecision::AllOk, AggregateDecision::FirstError),
                AggregateDecision::Cancelled,
            )
        },
        AggregateDecision::Panicked,
    );

    // Sort successes by index to ensure input-order reduction
    successes.sort_by_key(|(i, _)| *i);

    // Reduce successful values (left fold in input order)
    let reduced = if successes.is_empty() {
        None
    } else {
        let mut iter = successes.iter();
        let (_, first) = iter.next().expect("already checked non-empty");
        let result = iter.fold(first.clone(), |acc, (_, v)| reduce(acc, v.clone()));
        Some(result)
    };

    (decision, reduced, successes)
}

/// Constructs a [`MapReduceResult`] from a vector of outcomes.
///
/// This is the primary entry point for map-reduce result construction.
/// All tasks must have completed (no task is abandoned).
///
/// # Arguments
/// * `outcomes` - The outcomes from all tasks, in their original order
/// * `reduce` - Function to combine two values into one
///
/// # Returns
/// A [`MapReduceResult`] containing the aggregate decision, reduced value, and metadata.
///
/// # Example
/// ```
/// use asupersync::combinator::map_reduce::make_map_reduce_result;
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
/// ];
/// let result = make_map_reduce_result(outcomes, |a, b| a + b);
/// assert!(result.all_succeeded());
/// assert_eq!(result.reduced, Some(6)); // 1 + 2 + 3
/// ```
#[must_use]
pub fn make_map_reduce_result<T, E: Clone, F>(
    outcomes: Vec<Outcome<T, E>>,
    reduce: F,
) -> MapReduceResult<T, E>
where
    F: Fn(T, T) -> T,
    T: Clone,
{
    let total_count = outcomes.len();
    let (decision, reduced, successes) = map_reduce_outcomes(outcomes, reduce);
    MapReduceResult::new(decision, reduced, successes, total_count)
}

/// Converts a [`MapReduceResult`] to a Result for fail-fast handling.
///
/// If all tasks succeeded, returns `Ok` with the reduced value.
/// If any task failed (error, cancelled, or panicked), returns `Err`.
///
/// # Special Cases
/// - Empty input returns `Err(MapReduceError::Empty)`
///
/// # Example
/// ```
/// use asupersync::combinator::map_reduce::{make_map_reduce_result, map_reduce_to_result};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
/// ];
/// let result = make_map_reduce_result(outcomes, |a, b| a + b);
/// let reduced = map_reduce_to_result(result);
/// assert_eq!(reduced.unwrap(), 6);
/// ```
pub fn map_reduce_to_result<T, E: Clone>(
    result: MapReduceResult<T, E>,
) -> Result<T, MapReduceError<E>> {
    // Handle empty input
    if result.total_count == 0 {
        return Err(MapReduceError::Empty);
    }

    match result.decision {
        AggregateDecision::AllOk => {
            // All succeeded - return reduced value
            // Safety: if AllOk and total_count > 0, reduced must be Some
            result.reduced.ok_or_else(|| MapReduceError::Empty)
        }
        AggregateDecision::FirstError(e) => {
            // Find the first error index (any index not in successes)
            let success_indices: std::collections::HashSet<usize> =
                result.successes.iter().map(|(i, _)| *i).collect();
            let first_error_index = (0..result.total_count)
                .find(|i| !success_indices.contains(i))
                .unwrap_or(0);
            let total_failures = result.total_count - result.successes.len();
            Err(MapReduceError::Error {
                error: e,
                index: first_error_index,
                total_failures,
                success_count: result.successes.len(),
            })
        }
        AggregateDecision::Cancelled(r) => Err(MapReduceError::Cancelled(r)),
        AggregateDecision::Panicked(p) => Err(MapReduceError::Panicked(p)),
    }
}

/// Reduces successful values from a map-reduce result without requiring all to succeed.
///
/// This is a lenient version that returns the reduced value from whatever
/// tasks succeeded, or `None` if no tasks succeeded.
///
/// # Use Cases
/// - Partial aggregation where some failures are acceptable
/// - Best-effort reduction with degraded results
///
/// # Example
/// ```
/// use asupersync::combinator::map_reduce::{make_map_reduce_result, reduce_successes};
/// use asupersync::types::Outcome;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Err("failed"),
///     Outcome::Ok(3),
/// ];
/// let result = make_map_reduce_result(outcomes, |a, b| a + b);
/// let partial = reduce_successes(&result);
/// assert_eq!(partial, Some(4)); // 1 + 3 (skipping the failure)
/// ```
#[must_use]
pub fn reduce_successes<T: Clone, E>(result: &MapReduceResult<T, E>) -> Option<T> {
    result.reduced.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== MapReduce marker type tests ==========

    #[test]
    fn map_reduce_marker_type() {
        let _mr: MapReduce<i32> = MapReduce::new();
        let _mr_default: MapReduce<String> = MapReduce::default();

        // Test Clone and Copy
        let m1: MapReduce<i32> = MapReduce::new();
        let m2 = m1;
        let m3 = m1;
        assert!(std::mem::size_of_val(&m1) == std::mem::size_of_val(&m2));
        assert!(std::mem::size_of_val(&m1) == std::mem::size_of_val(&m3));
    }

    // ========== MapReduceResult tests ==========

    #[test]
    fn map_reduce_result_all_succeeded() {
        let result: MapReduceResult<i32, &str> = MapReduceResult::new(
            AggregateDecision::AllOk,
            Some(6),
            vec![(0, 1), (1, 2), (2, 3)],
            3,
        );
        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
        assert!(result.has_reduced());
    }

    #[test]
    fn map_reduce_result_partial_failure() {
        let result: MapReduceResult<i32, &str> = MapReduceResult::new(
            AggregateDecision::FirstError("oops"),
            Some(4), // Partial reduction of successes
            vec![(0, 1), (2, 3)],
            3,
        );
        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
        assert!(result.has_reduced());
    }

    // ========== MapReduceError tests ==========

    #[test]
    fn map_reduce_error_predicates() {
        let err: MapReduceError<&str> = MapReduceError::Error {
            error: "test",
            index: 2,
            total_failures: 1,
            success_count: 2,
        };
        assert!(err.is_error());
        assert!(!err.is_cancelled());
        assert!(!err.is_panicked());
        assert!(!err.is_empty());
        assert_eq!(err.error_index(), Some(2));

        let err: MapReduceError<&str> = MapReduceError::Cancelled(CancelReason::timeout());
        assert!(!err.is_error());
        assert!(err.is_cancelled());
        assert_eq!(err.error_index(), None);

        let err: MapReduceError<&str> = MapReduceError::Panicked(PanicPayload::new("boom"));
        assert!(!err.is_error());
        assert!(err.is_panicked());

        let err: MapReduceError<&str> = MapReduceError::Empty;
        assert!(err.is_empty());
    }

    #[test]
    fn map_reduce_error_display() {
        let err: MapReduceError<&str> = MapReduceError::Error {
            error: "test error",
            index: 3,
            total_failures: 2,
            success_count: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("task 3"));
        assert!(msg.contains("test error"));
        assert!(msg.contains("2 failures"));
        assert!(msg.contains("5 successes"));

        let err: MapReduceError<&str> = MapReduceError::Empty;
        assert!(err.to_string().contains("at least one input"));
    }

    // ========== map_reduce_outcomes tests ==========

    #[test]
    fn map_reduce_outcomes_all_ok_sum() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(6)); // 1 + 2 + 3
        assert_eq!(successes.len(), 3);
    }

    #[test]
    fn map_reduce_outcomes_all_ok_product() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(2), Outcome::Ok(3), Outcome::Ok(4)];

        let (decision, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a * b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(24)); // 2 * 3 * 4
    }

    #[test]
    fn map_reduce_outcomes_partial_failure() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::FirstError("failed")));
        assert_eq!(reduced, Some(4)); // 1 + 3 (partial reduction)
        assert_eq!(successes.len(), 2);
    }

    #[test]
    fn map_reduce_outcomes_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(3),
        ];

        let (decision, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::Cancelled(_)));
        assert_eq!(reduced, Some(4)); // Partial reduction still works
    }

    #[test]
    fn map_reduce_outcomes_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];

        let (decision, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::Panicked(_)));
        // Only the first value collected before panic
        assert_eq!(reduced, Some(1));
    }

    #[test]
    fn map_reduce_outcomes_preserves_input_order() {
        // Values should be reduced in input order regardless of completion order
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(10), Outcome::Ok(100)];

        // Using subtraction to verify order matters
        let (_, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a - b);

        // Left fold: ((1 - 10) - 100) = -109
        assert_eq!(reduced, Some(-109));
    }

    #[test]
    fn map_reduce_outcomes_single_value() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(42)); // Single value returned as-is
        assert_eq!(successes.len(), 1);
    }

    #[test]
    fn map_reduce_outcomes_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, None); // No values to reduce
        assert!(successes.is_empty());
    }

    // ========== make_map_reduce_result tests ==========

    #[test]
    fn make_map_reduce_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];

        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        assert!(result.all_succeeded());
        assert_eq!(result.reduced, Some(6));
        assert_eq!(result.total_count, 3);
    }

    // ========== map_reduce_to_result tests ==========

    #[test]
    fn map_reduce_to_result_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert_eq!(value.unwrap(), 6);
    }

    #[test]
    fn map_reduce_to_result_error() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        match value {
            Err(MapReduceError::Error {
                error,
                index,
                total_failures,
                success_count,
            }) => {
                assert_eq!(error, "failed");
                assert_eq!(index, 1);
                assert_eq!(total_failures, 1);
                assert_eq!(success_count, 2);
            }
            _ => panic!("expected MapReduceError::Error"),
        }
    }

    #[test]
    fn map_reduce_to_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::timeout())];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert!(matches!(value, Err(MapReduceError::Cancelled(_))));
    }

    #[test]
    fn map_reduce_to_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Panicked(PanicPayload::new("crash"))];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert!(matches!(value, Err(MapReduceError::Panicked(_))));
    }

    #[test]
    fn map_reduce_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert!(matches!(value, Err(MapReduceError::Empty)));
    }

    // ========== reduce_successes tests ==========

    #[test]
    fn reduce_successes_partial() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let partial = reduce_successes(&result);
        assert_eq!(partial, Some(4)); // 1 + 3
    }

    #[test]
    fn reduce_successes_none_succeeded() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("failed1"), Outcome::Err("failed2")];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let partial = reduce_successes(&result);
        assert_eq!(partial, None);
    }

    // ========== String concatenation tests (non-numeric) ==========

    #[test]
    fn map_reduce_string_concat() {
        let outcomes: Vec<Outcome<String, &str>> = vec![
            Outcome::Ok("Hello".to_string()),
            Outcome::Ok(" ".to_string()),
            Outcome::Ok("World".to_string()),
        ];

        let result = make_map_reduce_result(outcomes, |a, b| a + &b);
        assert_eq!(result.reduced, Some("Hello World".to_string()));
    }

    // ========== Associativity documentation test ==========

    #[test]
    fn map_reduce_associative_vs_non_associative() {
        // Demonstrate that associative operations give consistent results
        let outcomes_a: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let outcomes_b = outcomes_a.clone();

        // Addition is associative
        let sum_result = make_map_reduce_result(outcomes_a, |a, b| a + b);
        assert_eq!(sum_result.reduced, Some(6)); // Always 6

        // Subtraction is NOT associative - order matters
        let difference_result = make_map_reduce_result(outcomes_b, |a, b| a - b);
        // Left fold: ((1 - 2) - 3) = -4
        assert_eq!(difference_result.reduced, Some(-4));
        // Note: If we did right fold it would be different: (1 - (2 - 3)) = 2
        // Our implementation always does left fold for determinism
    }
}
