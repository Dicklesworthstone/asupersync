//! Bounded execution and outcome-fold helpers for map-reduce.
//!
//! [`execute_map_reduce`] and [`Scope::map_reduce`] lazily spawn real scoped
//! maps under independent concurrency and retained-work limits. Values enter a
//! fixed input-order left fold, so reducers need neither associativity nor
//! commutativity. Completed values waiting for an earlier input retain credit.
//! A failing execution stops admission, cancels and joins its owned children,
//! including asynchronous cleanup, before returning the severity join
//! `Ok < Err < Cancelled < Panicked`. Cancellation issued solely to drain a
//! sibling does not replace the initiating failure. Dropping the execution
//! requests abort; the region remains responsible for children that have not
//! yet terminated.
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
/// input produces `Ok(None)`. Equal-severity independent failures select the
/// lowest input index. Independent child cancellation outcomes and caller requests during
/// drain also participate in the `Err < Cancelled < Panicked` join. Cancellation
/// issued by this execution solely to drain a sibling is cleanup, not another
/// failure; `stopped_by` and `errors` retain the cause when a later, more severe
/// cleanup outcome wins. An application error returned under the execution's
/// exact drain cancellation is retained in `errors`, not selected as the primary
/// error. Panics still participate in the severity join. A selected error is
/// owned by `outcome`; the other indexed errors remain in `errors` (at most one stopped
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
    drain_reason: Option<CancelReason>,
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
    fn abort(&mut self) {
        let caller_reason = self.cx.cancel_reason();
        let induced = caller_reason.is_none();
        let reason = caller_reason.unwrap_or_else(|| {
            CancelReason::race_loser()
                .with_region(self.cx.region_id())
                .with_task(self.cx.task_id())
                .with_timestamp(self.cx.now_for_observability())
                .with_message("map-reduce sibling drain")
        });
        for slot in &mut self.slots {
            if let Some(handle) = &slot.handle
                && !handle.is_finished()
            {
                // Keep exact per-child provenance. Comparing only RaceLost
                // would erase an independently returned cancellation of the
                // same kind, and comparing only the input index would erase
                // a stronger cancellation arriving during asynchronous drain.
                if induced {
                    slot.drain_reason = Some(reason.clone());
                }
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
        // A child that published its result has finished, even before its
        // record retires: do not stamp a cancellation onto it.
        for slot in &self.slots {
            if let Some(handle) = &slot.handle
                && !handle.terminal_published()
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
    primary_error_index: Option<usize>,
    cancelled: Option<(usize, CancelReason)>,
    panicked: Option<(usize, PanicPayload)>,
}

impl<E> ExecutingMapFailures<E> {
    fn stop(&mut self, index: usize, cause: MapReduceStopCause) {
        self.stopped_by.get_or_insert((index, cause));
    }

    fn error(&mut self, index: usize, error: MapReduceExecutionError<E>) {
        self.stop(index, MapReduceStopCause::Error);
        self.primary_error_index = Some(self.primary_error_index.map_or(index, |old| old.min(index)));
        self.errors.push((index, error));
    }

    fn map_error(
        &mut self,
        index: usize,
        error: E,
        joined: &Result<(), JoinError>,
        drain_reason: Option<&CancelReason>,
    ) {
        let error = MapReduceExecutionError::Map(error);
        if matches!(joined, Err(JoinError::Cancelled(reason)) if Some(reason) == drain_reason) {
            // A cancellable operation commonly maps its cancellation to Err
            // (including through `?`). Keep that error for diagnostics, but
            // the exact runtime terminal identifies it as our own cleanup.
            // Merely having requested cancellation is not sufficient: a task
            // that completed before the request still supplies a real error.
            self.errors.push((index, error));
        } else {
            self.error(index, error);
        }
    }

    fn take_primary_error(&mut self) -> Option<(usize, MapReduceExecutionError<E>)> {
        let index = self.primary_error_index.take()?;
        let position = self
            .errors
            .iter()
            .position(|(candidate, _)| *candidate == index)
            .expect("the selected independent error remains owned");
        Some(self.errors.remove(position))
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
        primary_error_index: None,
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
    // Child terminations, counted by the guard each child future carries;
    // ahead of `completed` whenever a join sweep has passed a finished child.
    let terminated = Arc::new(std::sync::atomic::AtomicUsize::new(0));

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
                    failures.map_error(slot.index, error, &joined, slot.drain_reason.as_ref());
                }
                Some(Outcome::Cancelled(reason)) => {
                    if slot.drain_reason.as_ref() != Some(&reason) {
                        failures.cancel(slot.index, reason);
                    }
                }
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
                Err(JoinError::Cancelled(reason)) => {
                    if slot.drain_reason.as_ref() != Some(&reason) {
                        failures.cancel(slot.index, reason);
                    }
                }
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
                owner.abort();
                abort_requested = true;
            }
            let values_pending = owner.discard_completed_values(&mut failures, reduced);
            // A termination the sweep already passed restarts the sweep.
            let unobserved_terminations =
                terminated.load(std::sync::atomic::Ordering::Acquire) > completed;
            if values_pending || scan_pending || unobserved_terminations {
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
            // Moved into the future at spawn so it fires on every terminal
            // path, including cancellation before the first poll.
            match super::TerminationTally::track_spawn(&terminated, |tally| {
                cx.spawn_in_cancellation_dominant(scope, move |child| async move {
                    let _tally = tally;
                    let outcome = mapper(child, item).await;
                    *child_returned.lock() = Some(outcome);
                })
            }) {
                Ok(handle) => {
                    owner.slots.push_back(ExecutingMapSlot {
                        index: admitted,
                        handle: Some(handle),
                        returned,
                        value: None,
                        drain_reason: None,
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
            owner.abort();
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
                || terminated.load(std::sync::atomic::Ordering::Acquire) > completed
            {
                poll_cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    })
    .await;

    // These captures may run arbitrary destructors, including a new caller
    // cancellation request. Retire them before choosing the report, even when
    // iterator construction failed. Admitted children have all joined, so the
    // mapper Arc is no longer shared with any child execution.
    for (cause, panic) in [
        (
            MapReduceStopCause::InputPanicked,
            executing_map_discard(inputs.take()),
        ),
        (MapReduceStopCause::MapPanicked, executing_map_discard(map)),
        (
            MapReduceStopCause::ReducerPanicked,
            executing_map_discard(reduce),
        ),
    ] {
        if let Some(payload) = panic {
            failures.panic(admitted, cause, payload);
        }
    }
    executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted);
    if failures.stopped_by.is_some() {
        // A late cleanup failure must retire the formerly successful fold;
        // an actual successful return keeps its accumulator alive for callers.
        while owner.discard_completed_values(&mut failures, reduced) {
            crate::runtime::yield_now().await;
        }
        executing_map_caller_cancel(cx, &mut caller_cancel_observed, &mut failures, admitted);
    }

    failures.errors.sort_by_key(|(index, _)| *index);
    let (failure_index, outcome) = if let Some((index, payload)) = failures.panicked.take() {
        (Some(index), Outcome::Panicked(payload))
    } else if let Some((index, reason)) = failures.cancelled.take() {
        (Some(index), Outcome::Cancelled(reason))
    } else if let Some((index, error)) = failures.take_primary_error() {
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
#[path = "map_reduce_inline_tests.rs"]
mod tests;
