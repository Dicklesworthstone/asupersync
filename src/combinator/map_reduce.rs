//! Bounded execution and outcome-fold helpers for map-reduce.
//!
//! [`execute_map_reduce`] and [`Scope::map_reduce`] lazily spawn real scoped
//! maps under independent concurrency and retained-work limits. Values enter a
//! fixed input-order left fold, so reducers need neither associativity nor
//! commutativity. Completed values waiting for an earlier input retain credit.
//! A failing execution stops admission, cancels and joins its owned children,
//! including asynchronous cleanup, before returning the severity join
//! `Ok < Err < Cancelled < Panicked`. Dropping the execution requests abort;
//! the region remains responsible for children that have not yet terminated.
//!
//! The unchanged [`MapReduce`] marker and helpers such as
//! [`map_reduce_outcomes`] and [`make_map_reduce_result`] operate on outcomes
//! already supplied by the caller. Those helpers retain partial successes;
//! they do not spawn tasks or provide the executing engine's work bounds.

use core::fmt;
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::task::Poll;

use crate::cx::{CancelWakerToken, Cx, Scope};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::Outcome;
use crate::types::Policy;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::policy::AggregateDecision;

/// A compatibility marker for map-reduce computation.
///
/// This marker does not execute work. Use [`execute_map_reduce`] or
/// [`Scope::map_reduce`] for bounded task execution, or the outcome-fold
/// helpers below to aggregate outcomes already obtained by the caller.
///
/// # Type Parameters
/// * `T` - The output type from the map phase (also the reduce input/output)
///
/// # Executing work
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::{Outcome, combinator::MapReduceLimits};
/// use std::num::NonZeroUsize;
/// let limits = MapReduceLimits::new(
///     NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(4).unwrap(),
/// );
/// let report = cx.scope().map_reduce(
///     cx, limits, [1, 2, 3, 4, 5],
///     |_child, n| async move { Outcome::<_, ()>::Ok(n * 2) },
///     |acc, val| acc + val,
/// ).await;
/// assert!(matches!(report.outcome, Outcome::Ok(Some(30))));
/// # }
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

    /// Returns true if all tasks succeeded and at least one task was present.
    ///
    /// Returns `false` for empty input (zero tasks) even though the
    /// aggregate decision is `AllOk` (vacuously true), because callers
    /// typically expect `reduced` to be `Some` when this returns `true`.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.total_count > 0
            && matches!(self.decision, AggregateDecision::AllOk)
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
        // Saturating: `total_count` is `>= successes.len()` by construction, but
        // this is a public accessor and a caller-supplied result built through a
        // public constructor could violate that — never panic/underflow here.
        self.total_count.saturating_sub(self.successes.len())
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
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Index of the first task that panicked.
        index: usize,
    },
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

    /// Returns the panic index if this was a panic.
    #[must_use]
    pub const fn panic_index(&self) -> Option<usize> {
        match self {
            Self::Panicked { index, .. } => Some(*index),
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
        matches!(self, Self::Panicked { .. })
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
            Self::Panicked { payload, index } => {
                write!(f, "map-reduce task {index} panicked: {payload}")
            }
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
pub fn map_reduce_outcomes<T, E, F>(
    outcomes: Vec<Outcome<T, E>>,
    reduce: F,
) -> (AggregateDecision<E>, Option<T>, Vec<(usize, T)>)
where
    F: Fn(T, T) -> T,
    T: Clone,
{
    let total = outcomes.len();
    let mut successes: Vec<(usize, T)> = Vec::with_capacity(total);
    let mut first_error: Option<E> = None;
    let mut strongest_cancel: Option<CancelReason> = None;

    let mut panic_payload: Option<PanicPayload> = None;
    let mut panic_index: Option<usize> = None;

    // Collect outcomes
    for (i, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Panicked(p) => {
                // Panic is the strongest - record it but keep collecting successes
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

    // Determine aggregate decision (panic takes precedence)
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

    // Note: successes are already in input order since we iterate outcomes
    // sequentially with enumerate(). No sort needed.

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
pub fn make_map_reduce_result<T, E, F>(
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
pub fn map_reduce_to_result<T, E>(result: MapReduceResult<T, E>) -> Result<T, MapReduceError<E>> {
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
            let total_failures = result.total_count.saturating_sub(result.successes.len());
            Err(MapReduceError::Error {
                error: e,
                index: first_error_index,
                total_failures,
                success_count: result.successes.len(),
            })
        }
        AggregateDecision::Cancelled(r) => Err(MapReduceError::Cancelled(r)),
        AggregateDecision::Panicked {
            payload,
            first_panic_index,
        } => Err(MapReduceError::Panicked {
            payload,
            index: first_panic_index,
        }),
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

/// Independent bounds for executing map-reduce work.
///
/// The retained bound counts every admitted input until its result is folded:
/// pending admission, running tasks, and completed results waiting for an
/// earlier input. It bounds work items, not their payload sizes or the reducer's
/// accumulator. Both limits are enforced, including when concurrency is larger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapReduceLimits {
    concurrency: NonZeroUsize,
    retained_work: NonZeroUsize,
}

impl MapReduceLimits {
    /// Constructs bounds that cannot admit a zero-capacity execution.
    #[must_use]
    pub const fn new(concurrency: NonZeroUsize, retained_work: NonZeroUsize) -> Self {
        Self {
            concurrency,
            retained_work,
        }
    }

    /// Maximum admitted children whose terminal results have not been collected.
    #[must_use]
    pub const fn concurrency(self) -> usize {
        self.concurrency.get()
    }

    /// Maximum admitted inputs not yet reduced in input order.
    #[must_use]
    pub const fn retained_work(self) -> usize {
        self.retained_work.get()
    }
}

/// Application or synchronous admission failure in executing map-reduce.
#[derive(Debug)]
#[non_exhaustive]
pub enum MapReduceExecutionError<E> {
    /// A map returned an application error.
    Map(E),
    /// The runtime refused synchronous child admission.
    Spawn(SpawnError),
    /// The input index cannot be represented by this platform.
    InputIndexExhausted,
}

impl<E: fmt::Display> fmt::Display for MapReduceExecutionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Map(error) => write!(f, "map failed: {error}"),
            Self::Spawn(error) => write!(f, "map admission failed: {error}"),
            Self::InputIndexExhausted => f.write_str("map input index exhausted"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for MapReduceExecutionError<E> {}

/// The first observed reason that stopped further input admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MapReduceStopCause {
    /// The input iterator panicked.
    InputPanicked,
    /// A map or admission returned an error.
    Error,
    /// A child was cancelled, or the caller requested cancellation.
    Cancelled,
    /// A map factory, future, or discarded result panicked.
    MapPanicked,
    /// The input-order reducer panicked.
    ReducerPanicked,
}

/// Terminal report for one executing map-reduce operation.
///
/// Every admitted child has been joined when this report is returned. Empty
/// input produces `Ok(None)`. Equal-severity failures select the lowest input
/// index. Cancellation requested while draining also participates in the
/// `Err < Cancelled < Panicked` join; `stopped_by` and `errors` retain the cause
/// when a later, more severe cleanup outcome wins. A selected error is owned by
/// `outcome`; the other indexed errors remain in `errors` (at most one stopped
/// admission window). Successful values are consumed by the reducer, never
/// cloned into an additional results collection.
#[derive(Debug)]
#[non_exhaustive]
pub struct MapReduceExecution<T, E> {
    /// Final severity-joined outcome, with an input-order fold on success.
    pub outcome: Outcome<Option<T>, MapReduceExecutionError<E>>,
    /// Input index of the selected non-success outcome, if any.
    pub failure_index: Option<usize>,
    /// First observed admission stop, before draining may strengthen severity.
    pub stopped_by: Option<(usize, MapReduceStopCause)>,
    /// Non-selected application/admission errors, sorted by input index.
    pub errors: Vec<(usize, MapReduceExecutionError<E>)>,
    /// Number of child handles accepted by the spawn gateway, including queued
    /// runtime admission. A later runtime refusal still terminates that handle.
    pub admitted: usize,
    /// Number of admitted child terminal results actually joined.
    pub completed: usize,
    /// Number of successful input values consumed by the ordered fold.
    pub reduced: usize,
    /// Observed maximum admitted children not yet joined.
    pub max_in_flight: usize,
    /// Observed maximum admitted inputs not yet reduced.
    pub max_retained: usize,
}

struct ExecutingMapSlot<T, E> {
    index: usize,
    handle: Option<TaskHandle<()>>,
    returned: Arc<parking_lot::Mutex<Option<Outcome<T, E>>>>,
    value: Option<T>,
}

struct ExecutingMapOwner<T, E> {
    cx: Cx,
    cancel_waker: Option<CancelWakerToken>,
    slots: VecDeque<ExecutingMapSlot<T, E>>,
    accumulator: Option<T>,
    next_scan: usize,
    scan_end: usize,
}

impl<T, E> ExecutingMapOwner<T, E> {
    fn abort(&self, reason: &CancelReason) {
        for slot in &self.slots {
            if let Some(handle) = &slot.handle
                && !handle.is_finished()
            {
                handle.abort_with_reason(reason.clone());
            }
        }
    }

    fn discard_completed_values(
        &mut self,
        failures: &mut ExecutingMapFailures<E>,
        reduced: usize,
    ) -> bool {
        let mut retired = 0;
        if let Some(value) = self.accumulator.take() {
            if let Some(payload) = executing_map_discard(value) {
                failures.panic(
                    reduced.saturating_sub(1),
                    MapReduceStopCause::MapPanicked,
                    payload,
                );
            }
            retired += 1;
        }
        for slot in &mut self.slots {
            if retired == 64 {
                break;
            }
            if let Some(value) = slot.value.take() {
                if let Some(payload) = executing_map_discard(value) {
                    failures.panic(slot.index, MapReduceStopCause::MapPanicked, payload);
                }
                retired += 1;
            }
        }
        self.slots.iter().any(|slot| slot.value.is_some())
    }
}

impl<T, E> Drop for ExecutingMapOwner<T, E> {
    fn drop(&mut self) {
        // Drop requests cancellation; it cannot claim to have awaited cleanup.
        // The existing region owns any child that still needs cooperative polls.
        for slot in &self.slots {
            if let Some(handle) = &slot.handle
                && !handle.is_finished()
                && let Err(payload) = catch_unwind(AssertUnwindSafe(|| handle.abort()))
            {
                // Do not let a secondary arbitrary panic payload destructor
                // prevent cancellation requests to the remaining children.
                std::mem::forget(payload);
            }
        }
        if let Some(token) = self.cancel_waker.take()
            && let Err(payload) =
                catch_unwind(AssertUnwindSafe(|| self.cx.clear_cancel_waker(token)))
        {
            std::mem::forget(payload);
        }
        // Values and result cells can own arbitrary user destructors. Retire
        // them one at a time after every cancellation request was issued.
        while let Some(slot) = self.slots.pop_front() {
            let ExecutingMapSlot {
                handle,
                returned,
                value,
                ..
            } = slot;
            executing_map_drop_during_teardown(handle);
            executing_map_drop_during_teardown(value);
            let logical = returned.lock().take();
            executing_map_drop_during_teardown(logical);
            // The child may have published after take(), making this Arc the
            // last owner of a newly filled cell. Catch that retirement too.
            executing_map_drop_during_teardown(returned);
        }
        executing_map_drop_during_teardown(self.accumulator.take());
    }
}

struct ExecutingMapFailures<E> {
    stopped_by: Option<(usize, MapReduceStopCause)>,
    errors: Vec<(usize, MapReduceExecutionError<E>)>,
    cancelled: Option<(usize, CancelReason)>,
    panicked: Option<(usize, PanicPayload)>,
}

impl<E> ExecutingMapFailures<E> {
    fn stop(&mut self, index: usize, cause: MapReduceStopCause) {
        self.stopped_by.get_or_insert((index, cause));
    }

    fn error(&mut self, index: usize, error: MapReduceExecutionError<E>) {
        self.stop(index, MapReduceStopCause::Error);
        self.errors.push((index, error));
    }

    fn cancel(&mut self, index: usize, reason: CancelReason) {
        self.stop(index, MapReduceStopCause::Cancelled);
        if self.cancelled.as_ref().is_none_or(|(old, _)| index < *old) {
            self.cancelled = Some((index, reason));
        } else if let Some((old, retained)) = &mut self.cancelled
            && *old == index
        {
            retained.strengthen(&reason);
        }
    }

    fn panic(&mut self, index: usize, cause: MapReduceStopCause, payload: PanicPayload) {
        self.stop(index, cause);
        if self.panicked.as_ref().is_none_or(|(old, _)| index < *old) {
            self.panicked = Some((index, payload));
        }
    }
}

impl<E> Drop for ExecutingMapFailures<E> {
    fn drop(&mut self) {
        for (_, error) in self.errors.drain(..) {
            executing_map_drop_during_teardown(error);
        }
    }
}

fn executing_map_drop_during_teardown<T>(value: T) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(value))) {
        // No result can be published when the execution itself is being
        // dropped; preserve any primary unwind and finish the other cleanup.
        std::mem::forget(payload);
    }
}

fn executing_map_discard<T>(value: T) -> Option<PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| drop(value)))
        .err()
        .map(executing_map_panic)
}

fn executing_map_panic(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
    let message = crate::cx::scope::payload_to_string(&payload);
    // Match the runtime's panic boundary: an arbitrary payload destructor must
    // not replace the original panic while owned children still need draining.
    std::mem::forget(payload);
    PanicPayload::new(message)
}

fn executing_map_caller_cancel<E>(
    cx: &Cx,
    observed: &mut Option<(usize, CancelReason)>,
    failures: &mut ExecutingMapFailures<E>,
    index: usize,
) -> bool {
    // A checkpoint publishes an acknowledgement consumed by the scheduler.
    // Re-acknowledging on every Pending cleanup poll would continuously
    // reschedule the coordinator even when only an external child wake can
    // make progress. Keep the owned cancellation registration, but acknowledge
    // once per reason. A stronger explicit request still needs one new
    // acknowledgement to reconcile the authoritative task state/budget.
    if let Some((first_index, acknowledged)) = observed {
        let changed = cx.cancel_reason().is_some_and(|current| {
            let mut merged = acknowledged.clone();
            merged.strengthen(&current)
        });
        if changed
            && cx.checkpoint().is_err()
            && let Some(current) = cx.cancel_reason()
        {
            acknowledged.strengthen(&current);
        }
        failures.cancel(*first_index, acknowledged.clone());
        true
    } else if cx.checkpoint().is_err() {
        let reason = cx
            .cancel_reason()
            .unwrap_or_else(|| CancelReason::user("map-reduce cancelled"));
        failures.cancel(index, reason.clone());
        *observed = Some((index, reason));
        true
    } else {
        false
    }
}

/// Lazily maps inputs as real scoped children and folds results in input order.
///
/// The mapper runs inside each cancellation-dominant child, including factory
/// construction. The reducer is a fixed left fold; it need not be associative
/// or commutative. Empty input returns `Ok(None)` and a singleton never calls
/// the reducer. No input or mapped value needs `Clone`.
///
/// Both limits apply before requesting the next input. A later completed map
/// continues to consume retained-work credit while an earlier map is pending.
/// Admission and ordered folding each yield after at most 64 inputs per poll,
/// independently of the configured limits, so a large window still permits
/// other tasks to run.
/// Input/reducer panics and all non-success child outcomes stop admission,
/// request cancellation of unfinished children and join every child, including
/// asynchronous cleanup, before reporting. A noncooperative child keeps this
/// future pending. Dropping the future requests cancellation; region ownership
/// remains the cleanup backstop, with no claim of synchronous drainage.
pub async fn execute_map_reduce<I, M, F, R, T, E, P>(
    cx: &Cx,
    scope: &Scope<'_, P>,
    limits: MapReduceLimits,
    inputs: I,
    map: M,
    mut reduce: R,
) -> MapReduceExecution<T, E>
where
    P: Policy,
    I: IntoIterator,
    I::Item: Send + 'static,
    M: Fn(Cx, I::Item) -> F + Send + Sync + 'static,
    F: Future<Output = Outcome<T, E>> + Send + 'static,
    R: FnMut(T, T) -> T,
    T: Send + 'static,
    E: Send + 'static,
{
    let mut owner = ExecutingMapOwner {
        cx: cx.clone(),
        cancel_waker: None,
        slots: VecDeque::new(),
        accumulator: None,
        next_scan: 0,
        scan_end: 0,
    };
    let mut failures = ExecutingMapFailures {
        stopped_by: None,
        errors: Vec::new(),
        cancelled: None,
        panicked: None,
    };
    let mut inputs = match catch_unwind(AssertUnwindSafe(|| inputs.into_iter())) {
        Ok(inputs) => Some(inputs),
        Err(payload) => {
            failures.panic(
                0,
                MapReduceStopCause::InputPanicked,
                executing_map_panic(payload),
            );
            None
        }
    };
    let map = Arc::new(map);
    let mut exhausted = false;
    let mut abort_requested = false;
    let mut caller_cancel_observed = None;
    let mut admitted = 0_usize;
    let mut completed = 0_usize;
    let mut reduced = 0_usize;
    let mut max_in_flight = 0_usize;
    let mut max_retained = 0_usize;

    std::future::poll_fn(|poll_cx| {
        owner.cancel_waker = Some(cx.refresh_cancel_waker(owner.cancel_waker, poll_cx.waker()));
        executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted);
        // Snapshot a finite input-index sweep. Absolute indices stay valid
        // when front folds remove slots; later admissions receive a subsequent
        // sweep. This bounds both terminal polling and canceled-value disposal.
        let first_index = owner.slots.front().map_or(admitted, |slot| slot.index);
        if owner.next_scan >= owner.scan_end {
            owner.next_scan = first_index;
            owner.scan_end = admitted;
        } else {
            owner.next_scan = owner.next_scan.max(first_index);
        }
        for _ in 0..64 {
            if owner.next_scan >= owner.scan_end {
                break;
            }
            let offset = owner.next_scan - first_index;
            owner.next_scan += 1;
            let slot = owner.slots.get_mut(offset).expect("retained input index");
            let Some(handle) = &mut slot.handle else {
                continue;
            };
            let Poll::Ready(joined) = handle.poll_join(poll_cx) else {
                continue;
            };
            slot.handle = None;
            completed += 1;
            // The logical four-way value becomes observable only AFTER actual
            // task termination. An encoded panic must still outrank runtime
            // cancellation, whose generic spawn policy sees only returned ().
            let returned = slot.returned.lock().take();
            match returned {
                Some(Outcome::Ok(value)) if joined.is_ok() => slot.value = Some(value),
                Some(Outcome::Ok(value)) => {
                    if let Some(payload) = executing_map_discard(value) {
                        failures.panic(slot.index, MapReduceStopCause::MapPanicked, payload);
                    }
                }
                Some(Outcome::Err(error)) => {
                    failures.error(slot.index, MapReduceExecutionError::Map(error))
                }
                Some(Outcome::Cancelled(reason)) => failures.cancel(slot.index, reason),
                Some(Outcome::Panicked(payload)) => {
                    failures.panic(slot.index, MapReduceStopCause::MapPanicked, payload)
                }
                None if joined.is_ok() => failures.panic(
                    slot.index,
                    MapReduceStopCause::MapPanicked,
                    PanicPayload::new("map child completed without its logical outcome"),
                ),
                None => {}
            }
            match joined {
                Ok(()) => {}
                Err(JoinError::Cancelled(reason)) => failures.cancel(slot.index, reason),
                Err(JoinError::Panicked(payload)) => {
                    failures.panic(slot.index, MapReduceStopCause::MapPanicked, payload)
                }
                Err(JoinError::PolledAfterCompletion) => failures.panic(
                    slot.index,
                    MapReduceStopCause::MapPanicked,
                    PanicPayload::new("map child join polled after completion"),
                ),
            }
        }
        let mut folded = 0;
        if failures.stopped_by.is_none() {
            while owner
                .slots
                .front()
                .is_some_and(|slot| slot.handle.is_none())
                && folded < 64
            {
                let mut slot = owner.slots.pop_front().expect("front was present");
                let value = slot
                    .value
                    .take()
                    .expect("successful completed map owns its value");
                if let Some(previous) = owner.accumulator.take() {
                    match catch_unwind(AssertUnwindSafe(|| reduce(previous, value))) {
                        Ok(value) => owner.accumulator = Some(value),
                        Err(payload) => {
                            failures.panic(
                                slot.index,
                                MapReduceStopCause::ReducerPanicked,
                                executing_map_panic(payload),
                            );
                            break;
                        }
                    }
                } else {
                    owner.accumulator = Some(value);
                }
                reduced += 1;
                folded += 1;
                // A reducer can publish cancellation even when no input is
                // left to admit. Observe it before any further fold or result.
                if executing_map_caller_cancel(
                    cx,
                    &mut caller_cancel_observed,
                    &mut failures,
                    slot.index,
                ) {
                    break;
                }
            }
        }
        let fold_pending = owner
            .slots
            .front()
            .is_some_and(|slot| slot.handle.is_none());
        let scan_pending = owner.next_scan < owner.scan_end || owner.scan_end < admitted;
        if failures.stopped_by.is_some() {
            if !abort_requested {
                let reason = cx.cancel_reason().unwrap_or_else(CancelReason::race_loser);
                owner.abort(&reason);
                abort_requested = true;
            }
            let values_pending = owner.discard_completed_values(&mut failures, reduced);
            if values_pending || scan_pending {
                poll_cx.waker().wake_by_ref();
            }
            return if completed == admitted && !values_pending {
                Poll::Ready(())
            } else {
                Poll::Pending
            };
        }
        let mut in_flight = admitted - completed;
        let mut spawned = 0;
        while !exhausted
            && in_flight < limits.concurrency()
            && owner.slots.len() < limits.retained_work()
            && spawned < 64
        {
            // A synchronous reducer/input callback can itself publish caller
            // cancellation. Recheck immediately before every admission.
            if executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted)
            {
                break;
            }
            let item = match catch_unwind(AssertUnwindSafe(|| {
                inputs.as_mut().expect("iterator exists before stop").next()
            })) {
                Ok(Some(item)) => item,
                Ok(None) => {
                    exhausted = true;
                    break;
                }
                Err(payload) => {
                    failures.panic(
                        admitted,
                        MapReduceStopCause::InputPanicked,
                        executing_map_panic(payload),
                    );
                    break;
                }
            };
            let Some(next_admitted) = admitted.checked_add(1) else {
                failures.error(admitted, MapReduceExecutionError::InputIndexExhausted);
                break;
            };
            if executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted)
            {
                break;
            }
            let mapper = Arc::clone(&map);
            let returned = Arc::new(parking_lot::Mutex::new(None));
            let child_returned = Arc::clone(&returned);
            match cx.spawn_in_cancellation_dominant(scope, move |child| async move {
                let outcome = mapper(child, item).await;
                *child_returned.lock() = Some(outcome);
            }) {
                Ok(handle) => {
                    owner.slots.push_back(ExecutingMapSlot {
                        index: admitted,
                        handle: Some(handle),
                        returned,
                        value: None,
                    });
                    admitted = next_admitted;
                    in_flight += 1;
                    max_in_flight = max_in_flight.max(in_flight);
                    max_retained = max_retained.max(owner.slots.len());
                    spawned += 1;
                }
                Err(error) => {
                    failures.error(admitted, MapReduceExecutionError::Spawn(error));
                    break;
                }
            }
        }
        // next() can request cancellation and return None. This checkpoint is
        // also the success-publication boundary when no admission was needed.
        executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted);
        if failures.stopped_by.is_some() {
            owner.abort(&cx.cancel_reason().unwrap_or_else(CancelReason::race_loser));
            abort_requested = true;
        }
        let values_pending =
            failures.stopped_by.is_some() && owner.discard_completed_values(&mut failures, reduced);
        if (failures.stopped_by.is_some() || (exhausted && owner.slots.is_empty()))
            && completed == admitted
            && !values_pending
        {
            Poll::Ready(())
        } else {
            // Newly admitted handles need a first poll_join registration even
            // when their completion races admission. Yield once per batch.
            if spawned != 0
                || fold_pending
                || values_pending
                || owner.next_scan < owner.scan_end
                || owner.scan_end < admitted
            {
                poll_cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    })
    .await;

    failures.errors.sort_by_key(|(index, _)| *index);
    let (failure_index, outcome) = if let Some((index, payload)) = failures.panicked.take() {
        (Some(index), Outcome::Panicked(payload))
    } else if let Some((index, reason)) = failures.cancelled.take() {
        (Some(index), Outcome::Cancelled(reason))
    } else if !failures.errors.is_empty() {
        let (index, error) = failures.errors.remove(0);
        (Some(index), Outcome::Err(error))
    } else {
        (None, Outcome::Ok(owner.accumulator.take()))
    };
    MapReduceExecution {
        outcome,
        failure_index,
        stopped_by: failures.stopped_by,
        errors: std::mem::take(&mut failures.errors),
        admitted,
        completed,
        reduced,
        max_in_flight,
        max_retained,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::types::Budget;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn executing_limits(concurrency: usize, retained: usize) -> MapReduceLimits {
        MapReduceLimits::new(
            NonZeroUsize::new(concurrency).unwrap(),
            NonZeroUsize::new(retained).unwrap(),
        )
    }

    fn assert_executing_lab_clean(lab: &mut LabRuntime, region: crate::types::RegionId) {
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.region(region).unwrap().pending_spawn_count(), 0);
        let effects =
            lab.state
                .cancel_request(region, &CancelReason::user("map test complete"), None);
        let (tasks, wakes) = effects.into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(region);
        assert!(lab.state.region(region).is_none());
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }

    fn run_executing_case<F, Fut, T>(factory: F) -> T
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0100).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("actual map coordinator");
                let value = factory(cx.clone()).await;
                *publication.lock() = Some((value, cx.cancel_reason()));
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        let (result, cancelled) = returned
            .lock()
            .take()
            .expect("bounded map execution returned");
        // RuntimeState::create_task deliberately uses cancellation-dominant
        // delivery. Its terminal receipt is distinct from the engine report.
        match cancelled {
            Some(reason) => assert_eq!(join.try_join(), Err(JoinError::Cancelled(reason))),
            None => assert_eq!(join.try_join(), Ok(Some(()))),
        }
        assert_executing_lab_clean(&mut lab, root);
        result
    }

    #[test]
    fn executing_map_zero_one_many_move_only_values_and_independent_limits() {
        struct MoveOnly(String);
        assert!(NonZeroUsize::new(0).is_none());
        for count in [0, 1, 9] {
            for (concurrency, retained) in [(1, 1), (4, 2), (2, 5)] {
                let report = run_executing_case(move |cx| async move {
                    cx.scope()
                        .map_reduce(
                            &cx,
                            executing_limits(concurrency, retained),
                            0..count,
                            |_child, index| async move {
                                Outcome::<_, ()>::Ok(MoveOnly(index.to_string()))
                            },
                            |left, right| MoveOnly(format!("{}>{}", left.0, right.0)),
                        )
                        .await
                });
                assert_eq!(report.admitted, count);
                assert_eq!(report.completed, count);
                assert_eq!(report.reduced, count);
                assert!(report.max_in_flight <= concurrency);
                assert!(report.max_retained <= retained);
                assert!(report.stopped_by.is_none());
                let Outcome::Ok(value) = report.outcome else {
                    panic!("all maps succeed")
                };
                assert_eq!(
                    value.map(|value| value.0),
                    (count > 0).then(|| (0..count)
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(">"))
                );
            }
        }
    }

    #[test]
    fn executing_map_held_first_input_keeps_completed_results_in_retained_window() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0101).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let input_pulled = Arc::clone(&pulled);
        let mapped_finished = Arc::clone(&finished);
        let child_gate = Arc::clone(&gate);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 3),
                        (0..20).inspect(move |_| {
                            input_pulled.fetch_add(1, Ordering::SeqCst);
                        }),
                        move |child, index| {
                            let gate = Arc::clone(&child_gate);
                            let finished = Arc::clone(&mapped_finished);
                            async move {
                                if index == 0 {
                                    drop(
                                        crate::sync::OwnedMutexGuard::lock(gate, &child)
                                            .await
                                            .unwrap(),
                                    );
                                }
                                finished.fetch_add(1, Ordering::SeqCst);
                                Outcome::<_, ()>::Ok(index.to_string())
                            }
                        },
                        |left, right| format!("{left}>{right}"),
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        assert_eq!(gate.waiters(), 1);
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            3,
            "later completions cannot release retained credit"
        );
        assert_eq!(
            finished.load(Ordering::SeqCst),
            2,
            "later maps really completed"
        );
        drop(held);
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(report.admitted, 20);
        assert_eq!(report.completed, 20);
        assert_eq!(report.reduced, 20);
        assert_eq!(report.max_in_flight, 2);
        assert_eq!(report.max_retained, 3);
        assert_eq!(
            report.outcome.unwrap(),
            Some((0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(">"))
        );
        assert_eq!(gate.waiters(), 0);
        assert_executing_lab_clean(&mut lab, root);
        eprintln!(
            "map retained case: pulled=20 completed=20 reduced=20 max_active=2 max_retained=3 first_blocked_later_completed=2"
        );
    }

    #[test]
    fn executing_map_large_window_yields_admission_to_an_actual_other_task() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0106).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let input_pulled = Arc::clone(&pulled);
        let child_gate = Arc::clone(&gate);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(4096, 4096),
                        (0..4096).inspect(move |_| {
                            input_pulled.fetch_add(1, Ordering::SeqCst);
                        }),
                        move |child, index| {
                            let gate = Arc::clone(&child_gate);
                            async move {
                                if index == 0 {
                                    match crate::sync::OwnedMutexGuard::lock(gate, &child).await {
                                        Ok(guard) => drop(guard),
                                        Err(_) => {
                                            return Outcome::Cancelled(
                                                child.cancel_reason().unwrap(),
                                            );
                                        }
                                    }
                                }
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        |left, right| left + right,
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.step_for_test();
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            64,
            "one real coordinator poll has a fixed admission burst"
        );
        assert!(join.try_join().unwrap().is_none());
        let observer_pulled = Arc::clone(&pulled);
        let (observer, mut observation) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let seen = observer_pulled.load(Ordering::SeqCst);
                parent_cx.cancel_with(
                    crate::types::CancelKind::User,
                    Some("observer made progress"),
                );
                seen
            })
            .unwrap();
        lab.scheduler.lock().schedule(observer, 255);
        lab.run_until_idle();
        let seen = observation.try_join().unwrap().unwrap();
        assert!(
            (64..4096).contains(&seen),
            "other task must execute before a large window is exhausted: {seen}"
        );
        assert_eq!(
            join.try_join(),
            Err(JoinError::Cancelled(
                lab.state
                    .trace_handle()
                    .snapshot()
                    .iter()
                    .find_map(|event| {
                        match &event.data {
                            crate::trace::TraceData::Cancel { task, reason, .. }
                                if *task == parent =>
                            {
                                Some(reason.clone())
                            }
                            _ => None,
                        }
                    })
                    .expect("actual parent cancellation trace")
            ))
        );
        let report = returned.lock().take().expect("actual map engine report");
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.admitted, pulled.load(Ordering::SeqCst));
        assert_eq!(report.completed, report.admitted);
        assert_eq!(gate.waiters(), 0);
        drop(held);
        assert_executing_lab_clean(&mut lab, root);
        eprintln!(
            "map admission fairness: first_poll=64 observer_at={seen} admitted={} joined={}",
            report.admitted, report.completed
        );
    }

    #[test]
    fn executing_map_single_error_remains_an_error_without_cancelled_siblings() {
        let report = run_executing_case(|cx| async move {
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(1, 1),
                    [5],
                    |_child, _| async { Outcome::<usize, _>::Err("map refused") },
                    |left, right| left + right,
                )
                .await
        });
        assert!(matches!(
            report.outcome,
            Outcome::Err(MapReduceExecutionError::Map("map refused"))
        ));
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(report.stopped_by, Some((0, MapReduceStopCause::Error)));
        assert!(report.errors.is_empty());
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (1, 1, 0)
        );
    }

    #[test]
    fn executing_map_missing_gateway_is_an_admission_error_without_running_mapper() {
        let cx = Cx::new(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 1),
            Budget::INFINITE,
        );
        let scope = cx.scope();
        let mapped = Arc::new(AtomicUsize::new(0));
        let child_mapped = Arc::clone(&mapped);
        let mut execution = Box::pin(scope.map_reduce(
            &cx,
            executing_limits(2, 3),
            [1, 2, 3],
            move |_child, value| {
                child_mapped.fetch_add(1, Ordering::SeqCst);
                async move { Outcome::<_, ()>::Ok(value) }
            },
            |left, right| left + right,
        ));
        let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(report) = execution.as_mut().poll(&mut poll_cx) else {
            panic!("synchronous admission refusal cannot leave a fictitious child pending")
        };
        assert!(matches!(
            report.outcome,
            Outcome::Err(MapReduceExecutionError::Spawn(
                SpawnError::RuntimeUnavailable
            ))
        ));
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (0, 0, 0)
        );
        assert_eq!(mapped.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn executing_map_cancellation_before_or_during_input_does_not_spawn() {
        for cancel_before_input in [false, true] {
            let pulled = Arc::new(AtomicUsize::new(0));
            let mapped = Arc::new(AtomicUsize::new(0));
            let input_pulled = Arc::clone(&pulled);
            let child_mapped = Arc::clone(&mapped);
            let report = run_executing_case(move |cx| async move {
                if cancel_before_input {
                    cx.cancel_with(crate::types::CancelKind::User, Some("before first input"));
                }
                let input_cx = cx.clone();
                let inputs = [1, 2, 3].into_iter().inspect(move |_| {
                    input_pulled.fetch_add(1, Ordering::SeqCst);
                    input_cx.cancel_with(crate::types::CancelKind::User, Some("inside next input"));
                });
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 3),
                        inputs,
                        move |_child, value| {
                            child_mapped.fetch_add(1, Ordering::SeqCst);
                            async move { Outcome::<_, ()>::Ok(value) }
                        },
                        |left, right| left + right,
                    )
                    .await
            });
            assert!(report.outcome.is_cancelled());
            assert_eq!(report.failure_index, Some(0));
            assert_eq!(
                (report.admitted, report.completed, report.reduced),
                (0, 0, 0)
            );
            assert_eq!(
                pulled.load(Ordering::SeqCst),
                usize::from(!cancel_before_input)
            );
            assert_eq!(mapped.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn executing_map_terminal_reducer_and_none_input_cancellation_cannot_return_success() {
        let report = run_executing_case(|cx| async move {
            let reducer_cx = cx.clone();
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(4, 4),
                    [2, 3],
                    |_child, value| async move { Outcome::<_, ()>::Ok(value) },
                    move |left, right| {
                        reducer_cx
                            .cancel_with(crate::types::CancelKind::User, Some("final reducer"));
                        left + right
                    },
                )
                .await
        });
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.failure_index, Some(1));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (2, 2, 2)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let input_calls = Arc::clone(&calls);
        let report = run_executing_case(move |cx| async move {
            let input_cx = cx.clone();
            let input = std::iter::from_fn(move || {
                input_calls.fetch_add(1, Ordering::SeqCst);
                input_cx.cancel_with(crate::types::CancelKind::User, Some("terminal None"));
                None::<usize>
            });
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(4, 4),
                    input,
                    |_child, value| async move { Outcome::<_, ()>::Ok(value) },
                    |left, right| left + right,
                )
                .await
        });
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (0, 0, 0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn executing_map_stronger_caller_cancel_reconciles_once_at_original_reducer_index() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0110).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (started, first_wait) = crate::channel::oneshot::channel::<()>();
        let started = Arc::new(parking_lot::Mutex::new(Some(started)));
        let first_wait = Arc::new(parking_lot::Mutex::new(Some(first_wait)));
        let (release, held) = crate::channel::oneshot::channel::<()>();
        let held = Arc::new(parking_lot::Mutex::new(Some(held)));
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let third_id = Arc::new(parking_lot::Mutex::new(None));
        let actual_third = Arc::clone(&third_id);
        let (parent, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let reducer_cx = cx.clone();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(3, 3),
                        [0, 1, 2],
                        move |child, index| {
                            let started = Arc::clone(&started);
                            let first_wait = Arc::clone(&first_wait);
                            let held = Arc::clone(&held);
                            let actual_third = Arc::clone(&actual_third);
                            async move {
                                if index == 0 {
                                    let mut receiver = first_wait.lock().take().unwrap();
                                    receiver.recv_uninterruptible().await.unwrap();
                                } else if index == 2 {
                                    *actual_third.lock() = Some(child.task_id());
                                    started.lock().take().unwrap().send_blocking(()).unwrap();
                                    let mut receiver = held.lock().take().unwrap();
                                    receiver.recv_uninterruptible().await.unwrap();
                                }
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        move |left, right| {
                            reducer_cx.cancel_with(
                                crate::types::CancelKind::User,
                                Some("reducer owns first cancellation"),
                            );
                            left + right
                        },
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(lab.steps() < 8192);
        assert!(lab.scheduler.lock().is_empty());
        assert_eq!(lab.run_until_idle(), 0);
        assert_eq!(joined.try_join(), Ok(None));
        assert!(returned.lock().is_none());
        let third = third_id.lock().unwrap();
        assert!(
            lab.state.task(third).is_some(),
            "the higher input really remains owned"
        );
        assert_eq!(lab.state.live_task_count(), 2);
        assert_eq!(
            lab.state
                .task(parent)
                .unwrap()
                .cancel_reason()
                .unwrap()
                .kind,
            crate::types::CancelKind::User
        );

        parent_cx.cancel_with(
            crate::types::CancelKind::Timeout,
            Some("stronger request during held cleanup"),
        );
        let stronger = parent_cx.cancel_reason().unwrap();
        assert_eq!(stronger.kind, crate::types::CancelKind::Timeout);
        let progress = lab.run_until_idle();
        assert!(
            progress > 0,
            "the owned cancellation waker must publish real progress"
        );
        assert!(lab.steps() < 8192);
        assert!(
            lab.scheduler.lock().is_empty(),
            "unchanged strengthened cancellation must park again"
        );
        assert_eq!(lab.run_until_idle(), 0);
        let holder = lab.state.task(parent).unwrap();
        assert_eq!(holder.cancel_reason(), Some(&stronger));
        assert_eq!(holder.cleanup_budget(), Some(stronger.cleanup_budget()));
        assert_eq!(joined.try_join(), Ok(None));
        assert!(returned.lock().is_none());
        assert!(lab.state.task(third).is_some());

        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(
            joined.try_join(),
            Err(JoinError::Cancelled(stronger.clone()))
        );
        let report = returned
            .lock()
            .take()
            .expect("engine waits for the actual third terminal");
        assert_eq!(
            report.failure_index,
            Some(1),
            "caller attribution stays at the actual reducer"
        );
        assert_eq!(report.stopped_by, Some((1, MapReduceStopCause::Cancelled)));
        assert!(matches!(report.outcome, Outcome::Cancelled(reason) if reason == stronger));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (3, 3, 2)
        );
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_completed_prefix_folds_in_bounded_cooperative_bursts() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0107).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let finished = Arc::new(AtomicUsize::new(0));
        let reductions = Arc::new(AtomicUsize::new(0));
        let child_gate = Arc::clone(&gate);
        let child_finished = Arc::clone(&finished);
        let reducer_calls = Arc::clone(&reductions);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(192, 193),
                        0..192,
                        move |child, value| {
                            let gate = Arc::clone(&child_gate);
                            let finished = Arc::clone(&child_finished);
                            async move {
                                if value == 0 {
                                    drop(
                                        crate::sync::OwnedMutexGuard::lock(gate, &child)
                                            .await
                                            .unwrap(),
                                    );
                                }
                                finished.fetch_add(1, Ordering::SeqCst);
                                Outcome::<_, ()>::Ok(value)
                            }
                        },
                        move |left, right| {
                            reducer_calls.fetch_add(1, Ordering::SeqCst);
                            left - right
                        },
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(finished.load(Ordering::SeqCst), 191);
        assert_eq!(reductions.load(Ordering::SeqCst), 0);
        assert_eq!(gate.waiters(), 1);
        drop(held);
        for _ in 0..1024 {
            lab.step_for_test();
            if reductions.load(Ordering::SeqCst) != 0 {
                break;
            }
        }
        assert_eq!(
            reductions.load(Ordering::SeqCst),
            63,
            "first fold consumes 64 values and yields with 128 still retained"
        );
        assert!(
            join.try_join().unwrap().is_none(),
            "all children being complete cannot publish an unfinished fold"
        );
        let observer_reductions = Arc::clone(&reductions);
        let (observer, mut observed) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                observer_reductions.load(Ordering::SeqCst)
            })
            .unwrap();
        lab.scheduler.lock().schedule(observer, 255);
        lab.run_until_idle();
        let seen = observed.try_join().unwrap().unwrap();
        assert!(
            (63..191).contains(&seen),
            "another task progresses before the entire buffered fold: {seen}"
        );
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(report.outcome.unwrap(), Some(-(1..192).sum::<i32>()));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (192, 192, 192)
        );
        assert_eq!(report.max_retained, 192);
        assert_eq!(reductions.load(Ordering::SeqCst), 191);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_failure_waits_for_real_pending_cleanup_and_preserves_cause() {
        for mode in ["error", "cancel", "panic", "encoded_panic"] {
            let mut lab = LabRuntime::new(LabConfig::new(0x32_0102).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trigger = Arc::new(crate::sync::Mutex::new(()));
            let held_trigger = trigger.try_lock_owned().unwrap();
            let (keep_sender, receiver) = crate::channel::mpsc::channel::<()>(1);
            let receiver = Arc::new(parking_lot::Mutex::new(Some(receiver)));
            let (finish_cleanup, cleanup) = crate::channel::oneshot::channel::<()>();
            let cleanup = Arc::new(parking_lot::Mutex::new(Some(cleanup)));
            let cleanup_started = Arc::new(AtomicUsize::new(0));
            let cleanup_finished = Arc::new(AtomicUsize::new(0));
            let started = Arc::clone(&cleanup_started);
            let finished = Arc::clone(&cleanup_finished);
            let child_trigger = Arc::clone(&trigger);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .map_reduce(
                            &cx,
                            executing_limits(2, 2),
                            0..100,
                            move |child, index| {
                                let trigger = Arc::clone(&child_trigger);
                                let receiver = Arc::clone(&receiver);
                                let cleanup = Arc::clone(&cleanup);
                                let started = Arc::clone(&started);
                                let finished = Arc::clone(&finished);
                                async move {
                                    if index == 0 {
                                        drop(
                                            crate::sync::OwnedMutexGuard::lock(trigger, &child)
                                                .await
                                                .unwrap(),
                                        );
                                        match mode {
                                            "error" => Outcome::Err("triggering map failure"),
                                            "cancel" => Outcome::Cancelled(CancelReason::timeout()),
                                            "panic" => panic!("actual mapper panic"),
                                            "encoded_panic" => Outcome::Panicked(
                                                PanicPayload::new("encoded mapper panic"),
                                            ),
                                            _ => unreachable!(),
                                        }
                                    } else {
                                        assert_eq!(
                                            index, 1,
                                            "admission stops at the bounded failure window"
                                        );
                                        let mut receiver = receiver.lock().take().unwrap();
                                        assert_eq!(
                                            receiver.recv(&child).await,
                                            Err(crate::channel::mpsc::RecvError::Cancelled)
                                        );
                                        started.fetch_add(1, Ordering::SeqCst);
                                        let mut cleanup = cleanup.lock().take().unwrap();
                                        cleanup.recv_uninterruptible().await.unwrap();
                                        finished.fetch_add(1, Ordering::SeqCst);
                                        Outcome::Ok(index)
                                    }
                                }
                            },
                            |left, right| left + right,
                        )
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(trigger.waiters(), 1);
            assert_eq!(keep_sender.telemetry_snapshot(3202).recv_waiter_count, 1);
            drop(held_trigger);
            lab.run_until_idle();
            assert!(
                join.try_join().unwrap().is_none(),
                "cleanup Pending is not a terminal child"
            );
            assert_eq!(cleanup_started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 0);
            assert_eq!(keep_sender.telemetry_snapshot(3202).recv_waiter_count, 0);
            finish_cleanup.send_blocking(()).unwrap();
            lab.run_until_idle();
            let report = join.try_join().unwrap().unwrap();
            assert_eq!(report.admitted, 2);
            assert_eq!(report.completed, 2);
            assert_eq!(report.reduced, 0);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 1);
            assert_eq!(report.stopped_by.as_ref().unwrap().0, 0);
            if mode == "error" {
                assert!(
                    report.outcome.is_cancelled(),
                    "induced drain cancellation joins severity"
                );
                assert!(matches!(
                    report.errors.as_slice(),
                    [(0, MapReduceExecutionError::Map("triggering map failure"))]
                ));
            } else if mode == "cancel" {
                assert!(report.outcome.is_cancelled());
                assert_eq!(report.failure_index, Some(0));
            } else {
                assert!(report.outcome.is_panicked());
                assert_eq!(report.failure_index, Some(0));
            }
            assert_executing_lab_clean(&mut lab, root);
            eprintln!(
                "map failure mode={mode} admitted=2 joined=2 cleanup_started=1 cleanup_finished=1"
            );
        }
    }

    #[test]
    fn executing_map_iteration_factory_and_reducer_panics_stop_admission() {
        for mode in ["iterator", "factory", "reducer"] {
            let report = run_executing_case(move |cx| async move {
                let mut next = 0;
                let input = std::iter::from_fn(move || {
                    if mode == "iterator" && next == 2 {
                        panic!("actual input iterator panic");
                    }
                    if next == 8 {
                        return None;
                    }
                    let index = next;
                    next += 1;
                    Some(index)
                });
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(1, 1),
                        input,
                        move |_child, index| {
                            if mode == "factory" {
                                panic!("actual factory construction panic");
                            }
                            async move { Outcome::<_, ()>::Ok(index) }
                        },
                        move |left, right| {
                            if mode == "reducer" {
                                panic!("actual reducer panic");
                            }
                            left - right
                        },
                    )
                    .await
            });
            assert!(report.outcome.is_panicked());
            assert_eq!(report.completed, report.admitted);
            assert_eq!(report.admitted, if mode == "factory" { 1 } else { 2 });
            assert_eq!(
                report.stopped_by.unwrap().1,
                match mode {
                    "iterator" => MapReduceStopCause::InputPanicked,
                    "factory" => MapReduceStopCause::MapPanicked,
                    "reducer" => MapReduceStopCause::ReducerPanicked,
                    _ => unreachable!(),
                }
            );
        }
    }

    #[test]
    fn executing_map_caller_cancel_wakes_coordinator_and_keeps_noncooperative_child_owned() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0103).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let started = Arc::new(AtomicUsize::new(0));
        let child_started = Arc::clone(&started);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(1, 1),
                        0..10,
                        move |_child, index| {
                            let gate = Arc::clone(&gate);
                            let started = Arc::clone(&child_started);
                            async move {
                                started.fetch_add(1, Ordering::SeqCst);
                                let mut gate = gate.lock().take().unwrap();
                                gate.recv_uninterruptible().await.unwrap();
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        |left, right| left + right,
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        let child = lab
            .state
            .region(root)
            .unwrap()
            .task_ids()
            .into_iter()
            .find(|id| *id != parent)
            .unwrap();
        let child_cx = lab.state.task(child).unwrap().cx.clone().unwrap();
        parent_cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel map coordinator"),
        );
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        assert!(
            child_cx.is_cancel_requested(),
            "owned cancellation waker repolls coordinator to abort its child"
        );
        assert!(lab.state.task(child).is_some());
        assert_eq!(lab.state.live_task_count(), 2);
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(
            lab.steps() < 4096,
            "parked cleanup must not exhaust the step bound"
        );
        assert!(
            lab.scheduler.lock().is_empty(),
            "cancellation is acknowledged once, then the coordinator parks"
        );
        assert_eq!(
            lab.run_until_idle(),
            0,
            "no input or child wake means no draining polls"
        );
        assert!(
            returned.lock().is_none(),
            "no report before the actual child terminal"
        );
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(
            join.try_join(),
            Err(JoinError::Cancelled(parent_cx.cancel_reason().unwrap()))
        );
        let report = returned
            .lock()
            .take()
            .expect("actual map engine report after child join");
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.admitted, 1);
        assert_eq!(report.completed, 1);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_drop_requests_abort_without_claiming_child_completion() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0104).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let started = Arc::new(AtomicUsize::new(0));
        let child_started = Arc::clone(&started);
        let (notify_started, mut receive_started) = crate::channel::oneshot::channel::<()>();
        let notify_started = Arc::new(parking_lot::Mutex::new(Some(notify_started)));
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let mut execution = Box::pin(scope.map_reduce(
                    &cx,
                    executing_limits(1, 1),
                    [7],
                    move |_child, value| {
                        let gate = Arc::clone(&gate);
                        let started = Arc::clone(&child_started);
                        let notify_started = Arc::clone(&notify_started);
                        async move {
                            started.fetch_add(1, Ordering::SeqCst);
                            notify_started
                                .lock()
                                .take()
                                .unwrap()
                                .send_blocking(())
                                .unwrap();
                            let mut gate = gate.lock().take().unwrap();
                            gate.recv_uninterruptible().await.unwrap();
                            Outcome::<_, ()>::Ok(value)
                        }
                    },
                    |left, right| left + right,
                ));
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                receive_started.recv_uninterruptible().await.unwrap();
                drop(execution);
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(join.try_join().unwrap(), Some(()));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(
            lab.state.live_task_count(),
            1,
            "dropped owner did not fabricate a drain"
        );
        let child = lab.state.region(root).unwrap().task_ids()[0];
        assert!(
            lab.state
                .task(child)
                .unwrap()
                .cx
                .as_ref()
                .unwrap()
                .is_cancel_requested()
        );
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_late_lower_index_encoded_panic_outranks_drain_cancellation() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0105).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 2),
                        0..10,
                        move |_child, index| {
                            let gate = Arc::clone(&gate);
                            async move {
                                if index == 0 {
                                    let mut gate = gate.lock().take().unwrap();
                                    gate.recv_uninterruptible().await.unwrap();
                                }
                                Outcome::<usize, ()>::Panicked(PanicPayload::new(format!(
                                    "panic at {index}"
                                )))
                            }
                        },
                        |left, right| left + right,
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(
            report.stopped_by,
            Some((1, MapReduceStopCause::MapPanicked))
        );
        assert_eq!(report.failure_index, Some(0));
        let Outcome::Panicked(payload) = report.outcome else {
            panic!("encoded panic must survive cancellation-dominant generic spawn")
        };
        assert_eq!(payload.message(), "panic at 0");
        assert_eq!(report.admitted, 2);
        assert_eq!(report.completed, 2);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_result_destructor_panics_preserve_pending_cleanup_and_drop_abort() {
        #[derive(Debug)]
        struct ResultDrop {
            panics: bool,
            dropped: Arc<AtomicUsize>,
        }

        impl Drop for ResultDrop {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                assert!(!self.panics, "actual discarded map result panic");
            }
        }

        for (buffered, drop_execution) in [(false, false), (true, false), (true, true)] {
            let mut lab = LabRuntime::new(LabConfig::new(0x32_0108).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let count = if buffered { 3 } else { 2 };
            let mut senders = Vec::new();
            let mut receivers = Vec::new();
            for _ in 0..count {
                let (sender, receiver) = crate::channel::mpsc::channel::<()>(1);
                senders.push(sender);
                receivers.push(parking_lot::Mutex::new(Some(receiver)));
            }
            let receivers = Arc::new(receivers);
            let (finish_cleanup, cleanup) = crate::channel::oneshot::channel::<()>();
            let cleanup = Arc::new(parking_lot::Mutex::new(Some(cleanup)));
            let (request_drop, mut drop_requested) = crate::channel::oneshot::channel::<()>();
            let ready_values = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let cleanup_started = Arc::new(AtomicUsize::new(0));
            let cleanup_finished = Arc::new(AtomicUsize::new(0));
            let child_ready = Arc::clone(&ready_values);
            let child_dropped = Arc::clone(&dropped);
            let child_started = Arc::clone(&cleanup_started);
            let child_finished = Arc::clone(&cleanup_finished);
            let returned = Arc::new(parking_lot::Mutex::new(None));
            let publication = Arc::clone(&returned);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let mut execution = Box::pin(scope.map_reduce(
                        &cx,
                        executing_limits(count, count),
                        0..count,
                        move |child, index| {
                            let receivers = Arc::clone(&receivers);
                            let cleanup = Arc::clone(&cleanup);
                            let ready = Arc::clone(&child_ready);
                            let dropped = Arc::clone(&child_dropped);
                            let started = Arc::clone(&child_started);
                            let finished = Arc::clone(&child_finished);
                            async move {
                                if buffered && index != 0 {
                                    ready.fetch_add(1, Ordering::SeqCst);
                                    return Outcome::<_, ()>::Ok(ResultDrop {
                                        panics: true,
                                        dropped,
                                    });
                                }
                                let mut receiver = receivers[index].lock().take().unwrap();
                                assert_eq!(
                                    receiver.recv(&child).await,
                                    Err(crate::channel::mpsc::RecvError::Cancelled)
                                );
                                if buffered || index == 1 {
                                    started.fetch_add(1, Ordering::SeqCst);
                                    let mut cleanup = cleanup.lock().take().unwrap();
                                    cleanup.recv_uninterruptible().await.unwrap();
                                    finished.fetch_add(1, Ordering::SeqCst);
                                }
                                Outcome::Ok(ResultDrop {
                                    panics: !buffered && index == 0,
                                    dropped,
                                })
                            }
                        },
                        |_left, _right| -> ResultDrop {
                            panic!("a held first input prevents any reduction")
                        },
                    ));
                    let report = if drop_execution {
                        let mut requested = std::pin::pin!(drop_requested.recv_uninterruptible());
                        std::future::poll_fn(|poll_cx| {
                            if let Poll::Ready(result) = requested.as_mut().poll(poll_cx) {
                                result.unwrap();
                                return Poll::Ready(());
                            }
                            assert!(execution.as_mut().poll(poll_cx).is_pending());
                            Poll::Pending
                        })
                        .await;
                        drop(execution);
                        None
                    } else {
                        Some(execution.await)
                    };
                    *publication.lock() = Some(report);
                })
                .unwrap();
            let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(
                ready_values.load(Ordering::SeqCst),
                if buffered { 2 } else { 0 }
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            assert_eq!(senders[0].telemetry_snapshot(3208).recv_waiter_count, 1);
            if !buffered {
                assert_eq!(senders[1].telemetry_snapshot(3208).recv_waiter_count, 1);
            }
            if drop_execution {
                request_drop.send_blocking(()).unwrap();
            } else {
                parent_cx.cancel_with(crate::types::CancelKind::User, Some("retire map results"));
            }
            lab.run_until_idle();
            assert_eq!(dropped.load(Ordering::SeqCst), if buffered { 2 } else { 1 });
            assert_eq!(cleanup_started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 0);
            assert!(
                lab.steps() < 8192,
                "cleanup Pending must park before the step bound"
            );
            assert!(
                lab.scheduler.lock().is_empty(),
                "all held cleanup tasks really parked"
            );
            assert_eq!(lab.run_until_idle(), 0);
            if drop_execution {
                assert_eq!(join.try_join(), Ok(Some(())));
                assert!(matches!(returned.lock().take(), Some(None)));
                assert_eq!(
                    lab.state.live_task_count(),
                    1,
                    "result destructor panics cannot skip the remaining child's abort"
                );
            } else {
                assert!(
                    join.try_join().unwrap().is_none(),
                    "Panicked is not permission to abandon asynchronous cleanup"
                );
                assert!(returned.lock().is_none());
            }
            finish_cleanup.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), count);
            if !drop_execution {
                assert_eq!(
                    join.try_join(),
                    Err(JoinError::Cancelled(parent_cx.cancel_reason().unwrap()))
                );
                let report = returned
                    .lock()
                    .take()
                    .expect("actual engine return")
                    .unwrap();
                let Outcome::Panicked(payload) = report.outcome else {
                    panic!("actual result destructor panic must dominate cancellation")
                };
                assert_eq!(payload.message(), "actual discarded map result panic");
                assert_eq!(
                    (report.admitted, report.completed, report.reduced),
                    (count, count, 0)
                );
            }
            assert_executing_lab_clean(&mut lab, root);
            eprintln!(
                "map destructor buffered={buffered} drop_execution={drop_execution} values_dropped={count} cleanup_completed=1"
            );
        }
    }

    #[test]
    fn executing_map_simultaneous_cancelled_results_retire_in_bounded_join_sweeps() {
        struct CountDrop(Arc<AtomicUsize>);
        impl Drop for CountDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = 192;
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0109).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..count {
            let (sender, receiver) = crate::channel::mpsc::channel::<()>(1);
            senders.push(sender);
            receivers.push(parking_lot::Mutex::new(Some(receiver)));
        }
        let receivers = Arc::new(receivers);
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (all_started, mut receive_started) = crate::channel::oneshot::channel::<()>();
        let all_started = Arc::new(parking_lot::Mutex::new(Some(all_started)));
        let (resume, mut receive_resume) = crate::channel::oneshot::channel::<()>();
        let child_started = Arc::clone(&started);
        let child_dropped = Arc::clone(&dropped);
        let probe_dropped = Arc::clone(&dropped);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let mut execution = Box::pin(scope.map_reduce(
                    &cx,
                    executing_limits(count, count),
                    0..count,
                    move |child, index| {
                        let receivers = Arc::clone(&receivers);
                        let started = Arc::clone(&child_started);
                        let all_started = Arc::clone(&all_started);
                        let dropped = Arc::clone(&child_dropped);
                        async move {
                            if started.fetch_add(1, Ordering::SeqCst) + 1 == count {
                                all_started
                                    .lock()
                                    .take()
                                    .unwrap()
                                    .send_blocking(())
                                    .unwrap();
                            }
                            let mut receiver = receivers[index].lock().take().unwrap();
                            assert_eq!(
                                receiver.recv(&child).await,
                                Err(crate::channel::mpsc::RecvError::Cancelled)
                            );
                            Outcome::<_, ()>::Ok(CountDrop(dropped))
                        }
                    },
                    |_left, _right| -> CountDrop { panic!("cancelled values cannot be reduced") },
                ));
                let mut ready = std::pin::pin!(receive_started.recv_uninterruptible());
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    ready.as_mut().poll(poll_cx)
                })
                .await
                .unwrap();
                // Keep every real result cell owned but stop polling the engine
                // until the host has observed all actual children terminate.
                receive_resume.recv_uninterruptible().await.unwrap();
                assert_eq!(probe_dropped.load(Ordering::SeqCst), 0);
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(
                    probe_dropped.load(Ordering::SeqCst),
                    64,
                    "one engine poll retires only one bounded terminal sweep"
                );
                execution.await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(started.load(Ordering::SeqCst), count);
        assert!(
            senders
                .iter()
                .all(|sender| sender.telemetry_snapshot(3209).recv_waiter_count == 1)
        );
        let children: Vec<_> = lab
            .state
            .region(root)
            .unwrap()
            .task_ids()
            .into_iter()
            .filter(|id| *id != parent)
            .map(|id| lab.state.task(id).unwrap().cx.clone().unwrap())
            .collect();
        assert_eq!(children.len(), count);
        for child in &children {
            child.cancel_with(
                crate::types::CancelKind::User,
                Some("simultaneous result retirement"),
            );
        }
        lab.run_until_idle();
        assert_eq!(
            lab.state.live_task_count(),
            1,
            "every actual child has terminated before the bounded poll"
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "all terminal values are still owned by the parked engine"
        );
        assert!(join.try_join().unwrap().is_none());
        resume.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert!(report.outcome.is_cancelled());
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (count, count, 0)
        );
        assert_eq!(dropped.load(Ordering::SeqCst), count);
        assert!(
            senders
                .iter()
                .all(|sender| sender.telemetry_snapshot(3209).recv_waiter_count == 0)
        );
        assert_executing_lab_clean(&mut lab, root);
    }

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

        let err: MapReduceError<&str> = MapReduceError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 3,
        };
        assert!(!err.is_error());
        assert!(err.is_panicked());
        assert_eq!(err.panic_index(), Some(3));

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

        let err: MapReduceError<&str> = MapReduceError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 1,
        };
        assert!(err.to_string().contains("task 1 panicked"));
        assert!(err.to_string().contains("boom"));

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

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        match decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
        // All successful values collected and reduced (join semantics: all branches complete)
        assert_eq!(successes.len(), 2);
        assert_eq!(reduced, Some(4)); // 1 + 3 = 4
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

    #[test]
    fn map_reduce_result_empty_not_all_succeeded() {
        // Empty input should NOT report all_succeeded() = true,
        // even though the decision is vacuously AllOk.
        // This prevents callers from doing result.reduced.unwrap() after
        // checking all_succeeded(), which would panic on empty input.
        let result: MapReduceResult<i32, &str> =
            MapReduceResult::new(AggregateDecision::AllOk, None, vec![], 0);
        assert!(!result.all_succeeded());
        assert!(!result.has_reduced());
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
        match value {
            Err(MapReduceError::Panicked { payload: _, index }) => assert_eq!(index, 0),
            _ => panic!("Expected Panicked error"),
        }
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

    #[test]
    fn metamorphic_commutative_reducer_is_permutation_invariant() {
        let outcomes_a: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(3),
            Outcome::Ok(1),
            Outcome::Ok(4),
            Outcome::Ok(2),
        ];
        let outcomes_b: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(2),
            Outcome::Ok(4),
            Outcome::Ok(1),
            Outcome::Ok(3),
        ];

        let (decision_a, reduced_a, successes_a) = map_reduce_outcomes(outcomes_a, |a, b| a + b);
        let (decision_b, reduced_b, successes_b) = map_reduce_outcomes(outcomes_b, |a, b| a + b);

        assert!(matches!(decision_a, AggregateDecision::AllOk));
        assert!(matches!(decision_b, AggregateDecision::AllOk));
        assert_eq!(
            reduced_a, reduced_b,
            "commutative reduction should be invariant under permutation of successful inputs"
        );
        assert_eq!(reduced_a, Some(10));
        assert_eq!(successes_a.len(), successes_b.len());
        assert_eq!(successes_a.len(), 4);
        assert_ne!(
            successes_a, successes_b,
            "permuted inputs should still preserve their own input-order success traces"
        );
    }

    // --- wave 79 trait coverage ---

    #[test]
    fn map_reduce_error_debug_clone() {
        let e: MapReduceError<&str> = MapReduceError::Error {
            error: "bad",
            index: 2,
            total_failures: 1,
            success_count: 3,
        };
        let e2 = e.clone();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Error"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("Error"));

        let empty: MapReduceError<&str> = MapReduceError::Empty;
        let empty2 = empty.clone();
        let dbg3 = format!("{empty:?}");
        assert!(dbg3.contains("Empty"));
        let dbg4 = format!("{empty2:?}");
        assert!(dbg4.contains("Empty"));
    }
}
