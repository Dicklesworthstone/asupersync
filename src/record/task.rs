//! Task record for the runtime.
//!
//! A task is a unit of concurrent execution owned by a region.
//! This module defines the internal record structure for tracking task state.

use crate::cx::Cx;
use crate::tracing_compat::trace;
#[cfg(feature = "tracing-integration")]
use crate::types::task_context::PendingTaskCancelTrace;
use crate::types::task_context::{
    CancelTaskTraceKind, CancelWakeEffects, CancelWaker, CancellationEffects, RunnablePublication,
};
use crate::types::{
    Budget, CancelPhase, CancelReason, CancelWitness, CxInner, Outcome, RegionId, TaskId, Time,
};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::task::Waker;
// br-asupersync-1w9aot: removed `use std::time::Instant`. The
// `created_instant` field (production; tracing-integration only) is now
// `crate::types::Time` sampled via `crate::time::wall_now()` so replay
// determinism is preserved when a virtual clock is installed via the
// runtime's existing `wall_now` indirection. Mirrors the
// br-asupersync-qdkyqs precedent on `scheduler/worker.rs::poll_start`.

/// The concrete outcome type stored in task records (Phase 0).
pub type TaskOutcome = Outcome<(), crate::error::Error>;

/// Receipt for a checkpoint acknowledgement consumed by the runtime owner.
///
/// A task-handle cancellation becomes visible in `CxInner` before its
/// callback-free gateway command reaches the scheduler.  When a checkpoint
/// observes that cancellation in the gap, the runtime must materialize the
/// request in the authoritative [`TaskRecord`] before it completes or parks
/// the task.  The receipt preserves the logical request/acknowledgement order
/// for the protocol validator and deterministic lab oracle. Callback-capable
/// Wakers travel separately in the opaque [`CancellationEffects`] envelope.
#[derive(Debug)]
pub(crate) struct CheckpointCancelAck {
    pub(crate) effective_reason: CancelReason,
    pub(crate) cleanup_priority: u8,
    pub(crate) request_transition: Option<(TaskState, TaskState)>,
    pub(crate) acknowledge_transition: Option<(TaskState, TaskState)>,
    pub(crate) region_id: RegionId,
    pub(crate) spawned_at: Time,
}

impl CheckpointCancelAck {
    #[inline]
    #[must_use]
    pub(crate) const fn newly_materialized(&self) -> bool {
        self.request_transition.is_some()
    }
}

/// Scheduler routing chosen while applying a runtime-owned handle command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandleCancelRoute {
    pub(crate) priority: u8,
    /// `true` when no lane existed at mutation time and the command consumer
    /// owns the task's first physical cancel-lane publication.
    pub(crate) delegated_initial: bool,
}

/// Callback-free result of reconciling one handle command into TaskRecord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandleCancelUpdate {
    pub(crate) newly_cancelled: bool,
    pub(crate) route: Option<HandleCancelRoute>,
}

// Incremental Lyapunov counters (br-asupersync-xxcss5)
/// The state of a task in its lifecycle.
#[derive(Debug, Clone)]
pub enum TaskState {
    /// Initial state after spawn.
    Created,
    /// Actively being polled.
    Running,
    /// Cancel has been requested but not yet acknowledged.
    CancelRequested {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Task has acknowledged cancel and is running cleanup code.
    Cancelling {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Cleanup done; task is running finalizers.
    Finalizing {
        /// The reason for cancellation.
        reason: CancelReason,
        /// Budget for bounded cleanup.
        cleanup_budget: Budget,
    },
    /// Terminal state.
    Completed(TaskOutcome),
}

/// Coarse-grained task phase for cross-thread reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskPhase {
    /// Task created but not yet running.
    Created = 0,
    /// Task currently running.
    Running = 1,
    /// Cancellation requested but not yet acknowledged.
    CancelRequested = 2,
    /// Task running cancellation cleanup.
    Cancelling = 3,
    /// Task running finalizers after cleanup.
    Finalizing = 4,
    /// Task completed (terminal).
    Completed = 5,
}

impl TaskPhase {
    /// Returns `true` for terminal phases (currently only [`TaskPhase::Completed`]).
    /// Added by br-asupersync-xxcss5 follow-up to unblock the Lyapunov
    /// governor's live-task scan that filters out terminal records.
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Returns whether transitioning from `self` to `next` is a legal
    /// state machine transition.
    ///
    /// The formal transition table for task phases:
    ///
    /// ```text
    /// ┌─────────────────┬────────────────────────────────────────────────┐
    /// │ From             │ Valid targets                                  │
    /// ├─────────────────┼────────────────────────────────────────────────┤
    /// │ Created          │ Running, CancelRequested, Completed            │
    /// │ Running          │ CancelRequested, Completed                     │
    /// │ CancelRequested  │ CancelRequested (strengthen), Cancelling,      │
    /// │                  │ Completed                                      │
    /// │ Cancelling       │ Cancelling (strengthen), Finalizing, Completed │
    /// │ Finalizing       │ Finalizing (strengthen), Completed             │
    /// │ Completed        │ (terminal — no transitions)                    │
    /// └─────────────────┴────────────────────────────────────────────────┘
    /// ```
    ///
    /// Notes:
    /// - `CancelRequested → CancelRequested` is valid (reason strengthening).
    /// - `Cancelling → Cancelling` and `Finalizing → Finalizing` are valid
    ///   (reason/budget strengthening during cleanup/finalizers).
    /// - `Created → Completed` allows error/panic during spawn before running.
    /// - `CancelRequested → Completed` allows error/panic before cancel ack.
    /// - `Cancelling → Completed` and `Finalizing → Completed` allow for
    ///   err/panic during cleanup/finalization.
    /// - `Running → Completed` allows normal completion (Ok/Err/Panic).
    /// - `Completed` is terminal; no further transitions are valid.
    #[inline]
    #[must_use]
    pub const fn is_valid_transition(self, next: Self) -> bool {
        matches!(
            (self as u8, next as u8),
            // Created → Running | CancelRequested | Completed (err/panic at spawn)
            (0, 1 | 2 | 5)
            // Running → CancelRequested | Completed
            | (1, 2 | 5)
            // CancelRequested → CancelRequested (strengthen) | Cancelling | Completed (err/panic before ack)
            | (2, 2 | 3 | 5)
            // Cancelling → Cancelling (strengthen) | Finalizing | Completed (err/panic during cleanup)
            | (3, 3..=5)
            // Finalizing → Finalizing (strengthen) | Completed
            | (4, 4..=5)
        )
    }

    /// Returns the numeric encoding for this state.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decodes a numeric state value.
    #[inline]
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Created),
            1 => Some(Self::Running),
            2 => Some(Self::CancelRequested),
            3 => Some(Self::Cancelling),
            4 => Some(Self::Finalizing),
            5 => Some(Self::Completed),
            _ => None,
        }
    }
}

/// Shared atomic counters for live task tracking and phase tracking across direct
/// mutations.
#[derive(Debug, Default)]
pub(crate) struct TaskPhaseTracker {
    pub(crate) live_count: AtomicUsize,
    pub(crate) phase_counts: [AtomicUsize; 5],
}

/// Atomic task phase cell for cross-thread state checks.
#[derive(Debug)]
pub struct TaskPhaseCell {
    inner: AtomicU8,
    /// Shared tracker of the task table that holds this record. Every
    /// phase change goes through [`Self::store`], which keeps the counts exact
    /// even when a record is mutated directly (br-asupersync-bzict6).
    tracker: Option<Arc<TaskPhaseTracker>>,
}

impl TaskPhaseCell {
    /// Creates a new cell initialized to the given phase.
    #[inline]
    #[must_use]
    pub fn new(phase: TaskPhase) -> Self {
        Self {
            inner: AtomicU8::new(phase.as_u8()),
            tracker: None,
        }
    }

    /// Counts this cell in `tracker` while its phase is not terminal.
    pub(crate) fn attach_phase_tracker(&mut self, tracker: Arc<TaskPhaseTracker>) {
        self.detach_phase_tracker();
        let phase = self.load();
        if !phase.is_terminal() {
            tracker.live_count.fetch_add(1, Ordering::AcqRel);
            let idx = phase as usize;
            if idx < 5 {
                tracker.phase_counts[idx].fetch_add(1, Ordering::AcqRel);
            }
        }
        self.tracker = Some(tracker);
    }

    /// Stops counting this cell.
    pub(crate) fn detach_phase_tracker(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            let phase = self.load();
            if !phase.is_terminal() {
                tracker.live_count.fetch_sub(1, Ordering::AcqRel);
                let idx = phase as usize;
                if idx < 5 {
                    tracker.phase_counts[idx].fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn attach_live_count(&mut self, live_count: Arc<AtomicUsize>) {
        let tracker = Arc::new(TaskPhaseTracker {
            live_count: AtomicUsize::new(live_count.load(Ordering::Acquire)),
            phase_counts: [const { AtomicUsize::new(0) }; 5],
        });
        self.attach_phase_tracker(tracker);
    }

    #[allow(dead_code)]
    pub(crate) fn detach_live_count(&mut self) {
        self.detach_phase_tracker();
    }

    /// Loads the current phase.
    #[inline]
    #[must_use]
    pub fn load(&self) -> TaskPhase {
        let v = self.inner.load(Ordering::Acquire);
        TaskPhase::from_u8(v).unwrap_or_else(|| {
            debug_assert!(false, "invalid TaskPhase value: {v}");
            TaskPhase::Completed
        })
    }

    /// Stores the new phase, validating the transition in debug builds.
    ///
    /// In debug mode, this asserts that the transition from the current phase
    /// to the new phase is valid according to the cancellation state machine.
    pub fn store(&self, phase: TaskPhase) {
        #[cfg(debug_assertions)]
        {
            let current = self.load();
            debug_assert!(
                current.is_valid_transition(phase),
                "invalid TaskPhase transition: {current:?} -> {phase:?}"
            );
        }
        let Some(tracker) = &self.tracker else {
            self.inner.store(phase as u8, Ordering::Release);
            return;
        };
        let prev_raw = self.inner.swap(phase as u8, Ordering::AcqRel);
        if let Some(prev) = TaskPhase::from_u8(prev_raw) {
            let was_live = !prev.is_terminal();
            let is_live = !phase.is_terminal();
            match (was_live, is_live) {
                (true, false) => {
                    tracker.live_count.fetch_sub(1, Ordering::AcqRel);
                }
                (false, true) => {
                    tracker.live_count.fetch_add(1, Ordering::AcqRel);
                }
                _ => {}
            }
            let prev_idx = prev as usize;
            if prev_idx < 5 {
                tracker.phase_counts[prev_idx].fetch_sub(1, Ordering::AcqRel);
            }
            let new_idx = phase as usize;
            if new_idx < 5 {
                tracker.phase_counts[new_idx].fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

impl Drop for TaskPhaseCell {
    fn drop(&mut self) {
        self.detach_phase_tracker();
    }
}

/// Cross-thread wake dedup state for a task.
#[derive(Debug, Default)]
pub struct TaskWakeState {
    state: AtomicU8,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WakeState {
    Idle = 0,
    Polling = 1,
    Notified = 2,
}

impl TaskWakeState {
    /// Creates a new wake state with no pending notification.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a pending wake and returns true if scheduling should occur.
    #[inline]
    pub fn notify(&self) -> bool {
        // Release is sufficient: we only need to publish the Notified state to
        // readers who subsequently Acquire. The Acquire half of AcqRel is
        // unnecessary because no caller reads memory through the returned prev
        // value beyond comparing it to Idle.
        let prev = self
            .state
            .swap(WakeState::Notified as u8, Ordering::Release);
        prev == WakeState::Idle as u8
    }

    /// Marks the task as being polled.
    ///
    /// Always called under a task table or runtime state lock, so the lock's
    /// release semantics provide the needed ordering. Relaxed suffices here.
    #[inline]
    pub fn begin_poll(&self) {
        self.state
            .store(WakeState::Polling as u8, Ordering::Relaxed);
    }

    /// Finishes polling and returns true if a wake occurred during poll.
    #[inline]
    pub fn finish_poll(&self) -> bool {
        // Release on success: publishes poll side-effects before Idle is visible.
        // Acquire on success is redundant: the old value (Polling) was written by
        // this thread's begin_poll(), so there is nothing new to acquire.
        // Acquire on failure: pairs with notify()'s Release to read Notified.
        match self.state.compare_exchange(
            WakeState::Polling as u8,
            WakeState::Idle as u8,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => false,
            Err(current) => current == WakeState::Notified as u8,
        }
    }

    /// Clears any pending wake and marks the task idle.
    #[inline]
    pub fn clear(&self) {
        self.state.store(WakeState::Idle as u8, Ordering::Release);
    }

    /// Returns true if a wake is pending.
    #[inline]
    #[must_use]
    pub fn is_notified(&self) -> bool {
        self.state.load(Ordering::Acquire) == WakeState::Notified as u8
    }
}

impl TaskState {
    /// Returns true if the task is in a terminal state.
    #[inline]
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns true if cancellation has been requested or is in progress.
    #[inline]
    #[must_use]
    pub fn is_cancelling(&self) -> bool {
        matches!(
            self,
            Self::CancelRequested { .. } | Self::Cancelling { .. } | Self::Finalizing { .. }
        )
    }

    /// Returns true if the task can be polled.
    #[inline]
    #[must_use]
    pub fn can_be_polled(&self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::CancelRequested { .. }
                | Self::Cancelling { .. }
                | Self::Finalizing { .. }
        )
    }
}

/// Internal record for a task in the runtime.
#[derive(Debug)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct TaskRecord {
    /// Unique identifier for this task.
    pub id: TaskId,
    /// The region that owns this task.
    pub owner: RegionId,
    /// Current state of the task.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub state: TaskState,
    /// Cross-thread lifecycle phase (atomic snapshot).
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub phase: TaskPhaseCell,
    /// Cross-thread wake dedup state for this task.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub wake_state: Arc<TaskWakeState>,
    /// Shared capability context state.
    ///
    /// This is shared with the `Cx` held by the user code.
    /// It is `None` only during initial construction or testing if not provided.
    /// This remains public for 0.4.3 source compatibility.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub cx_inner: Option<Arc<RwLock<CxInner>>>,
    /// Full capability context for this task.
    ///
    /// This allows the runtime to set a current task context while polling.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub cx: Option<Cx>,
    /// Logical time when the task was created.
    pub created_at: Time,
    /// The task's current deadline (cached from cx_inner).
    pub deadline: Option<Time>,

    /// Number of polls remaining (for budget tracking).
    pub polls_remaining: u32,
    /// Total number of polls executed (for completion metrics).
    pub total_polls: u64,
    /// Replayable creation timestamp used by the `tracing-integration`
    /// duration metric.
    ///
    /// br-asupersync-1w9aot: previously a `std::time::Instant` sampled
    /// via `Instant::now()`, which baked wall-clock time into the
    /// metric and broke lab-replay determinism (the same lab seed
    /// produced different `duration_us` values across runs). The field
    /// is now `crate::types::Time` sampled through
    /// `crate::time::wall_now()` — which the lab runtime overrides
    /// with its `TimerDriverHandle`-backed virtual clock when present
    /// — so replays are byte-identical. The `serde(skip)` marker is
    /// preserved so the test-internals JSON snapshots that already
    /// scrub `created_instant` to `[INSTANT]` continue to round-trip.
    /// Mirrors the br-asupersync-qdkyqs fix on
    /// `scheduler/worker.rs::poll_start`.
    #[cfg(feature = "tracing-integration")]
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub created_instant: Time,
    /// Lab-only: last step this task was polled (for futurelock detection).
    pub last_polled_step: u64,
    /// Tasks waiting for this task to complete.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub waiters: SmallVec<[TaskId; 4]>,
    /// Cached waker for this task (avoids per-poll Arc allocation).
    /// The tuple stores (waker, priority) so we can detect priority changes.
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub cached_waker: Option<(Waker, u8)>,
    /// Cached cancel waker for this task (avoids per-poll Arc allocation).
    #[cfg_attr(feature = "test-internals", serde(skip))]
    pub cached_cancel_waker: Option<(Waker, u8)>,
    /// Cancellation epoch (increments on first cancel request).
    pub cancel_epoch: u64,
    /// Whether this task is a local (`!Send`) task pinned to its owner worker.
    ///
    /// Local tasks must never be stolen by another worker thread.
    pub is_local: bool,
    /// Owning worker for local tasks (when known).
    pub pinned_worker: Option<usize>,
    // ── Intrusive queue fields (cache-local queues) ──────────────────────
    /// Next task in the intrusive queue (None if tail or not in queue).
    pub next_in_queue: Option<TaskId>,
    /// Previous task in the intrusive queue (None if head or not in queue).
    pub prev_in_queue: Option<TaskId>,
    /// Queue membership tag: 0 = not in any queue, 1+ = queue identifier.
    /// Used to prevent double-enqueue and enable O(1) membership check.
    pub queue_tag: u8,
    // ── Intrusive heap fields (cache-aware priority scheduling) ────────
    /// Position in the intrusive priority heap (`None` if not in any heap).
    /// Enables O(1) lookup and O(log n) removal by task ID.
    pub heap_index: Option<u32>,
    /// Cached scheduling priority: the linked context's budget priority, set
    /// with the context (the three-lane scheduler gives it to every waker it
    /// builds for the task), and rewritten by an `IntrusivePriorityHeap` that
    /// holds the task.
    pub sched_priority: u8,
    /// FIFO generation counter for tie-breaking within equal priorities.
    /// Lower generation = earlier insertion = higher scheduling priority.
    pub sched_generation: u64,
}

impl TaskRecord {
    /// Creates a new task record.
    #[must_use]
    pub fn new(id: TaskId, owner: RegionId, budget: Budget) -> Self {
        Self::new_with_time(id, owner, budget, Time::from_nanos(1_000_000_000))
    }

    /// Creates a new task record with an explicit creation time.
    #[must_use]
    pub fn new_with_time(id: TaskId, owner: RegionId, budget: Budget, created_at: Time) -> Self {
        Self {
            id,
            owner,
            state: TaskState::Created,
            phase: TaskPhaseCell::new(TaskPhase::Created),
            wake_state: Arc::new(TaskWakeState::new()),
            cx_inner: None, // Must be set via set_cx_inner or similar
            cx: None,
            created_at,
            deadline: budget.deadline,
            polls_remaining: budget.poll_quota,
            total_polls: 0,
            // br-asupersync-1w9aot: route through wall_now() so the
            // lab runtime's virtual clock can intercept; production
            // unchanged.
            #[cfg(feature = "tracing-integration")]
            created_instant: crate::time::wall_now(),
            last_polled_step: 0,
            waiters: SmallVec::new(),
            cached_waker: None,
            cached_cancel_waker: None,
            cancel_epoch: 0,
            is_local: false,
            pinned_worker: None,
            next_in_queue: None,
            prev_in_queue: None,
            queue_tag: 0,
            heap_index: None,
            sched_priority: 0,
            sched_generation: 0,
        }
    }

    /// Returns the logical time when the task was created.
    #[inline]
    #[must_use]
    pub const fn created_at(&self) -> Time {
        self.created_at
    }

    /// Returns the current scheduling priority of this task's linked context.
    #[inline]
    #[must_use]
    pub fn priority(&self) -> u8 {
        self.cx_inner
            .as_ref()
            .map_or(0, |inner| inner.read().budget.priority)
    }

    /// Returns whether this task's linked context has a published cancellation request.
    ///
    /// A record without a linked context has no cancellation state to observe.
    #[inline]
    #[must_use]
    pub fn is_cancel_requested(&self) -> Option<bool> {
        self.cx_inner
            .as_ref()
            .map(|inner| inner.read().is_cancel_requested())
    }

    /// Installs the primary cancellation Waker without exposing the linked context.
    ///
    /// Returns `false` when no context is linked or its Waker registry is closed.
    /// The retired Waker is dropped only after releasing the context lock.
    pub fn install_cancel_waker(&mut self, waker: Waker) -> bool {
        let Some(inner) = &self.cx_inner else {
            return false;
        };
        let incoming = Arc::new(CancelWaker::new(waker));
        let retired = {
            let mut inner = inner.write();
            if inner.cancel_waker_registry_closed {
                return false;
            }
            inner.cancel_waker.replace(incoming)
        };
        drop(retired);
        true
    }

    /// Sets the shared CxInner.
    #[inline]
    pub fn set_cx_inner(&mut self, inner: Arc<RwLock<CxInner>>) {
        let budget = inner.read().budget;
        self.deadline = budget.deadline;
        // Nothing else fills this field on the production path, so every
        // re-wake used to carry priority 0 (br-asupersync-5khftq).
        self.sched_priority = budget.priority;
        self.cx_inner = Some(inner);
    }

    /// Sets the full Cx for this task.
    pub fn set_cx(&mut self, cx: Cx) {
        self.cx = Some(cx);
    }

    /// Returns a snapshot of the budget carried by the linked task context.
    ///
    /// A newly constructed record is not linked until runtime admission, so
    /// callers must handle `None`. The snapshot deliberately exposes no
    /// authority-bearing context handle and cannot be used to rebind the task.
    #[inline]
    #[must_use]
    pub fn context_budget(&self) -> Option<Budget> {
        self.cx_inner.as_ref().map(|inner| inner.read().budget)
    }

    /// Returns whether cancellation is published in the linked task context.
    ///
    /// Returns `None` before runtime admission links the record to a context.
    /// This read-only snapshot preserves the sealed `CxInner` boundary while
    /// supporting diagnostics and behavioral contract tests.
    #[inline]
    #[must_use]
    pub fn context_cancel_requested(&self) -> Option<bool> {
        self.cx_inner
            .as_ref()
            .map(|inner| inner.read().is_cancel_requested())
    }

    /// Records that the task was polled on the given lab step.
    pub fn mark_polled(&mut self, step: u64) {
        self.last_polled_step = step;
    }

    /// Increments the total poll counter for this task.
    ///
    /// Call this each time the task is polled to maintain accurate metrics.
    pub fn increment_polls(&mut self) {
        self.total_polls += 1;
    }

    /// Returns true if the task can be polled.
    #[inline]
    #[must_use]
    pub fn is_runnable(&self) -> bool {
        matches!(&self.state, TaskState::Created | TaskState::Running) || self.state.can_be_polled()
    }

    /// Returns a string name for the current state (for tracing).
    #[inline]
    #[must_use]
    pub fn state_name(&self) -> &'static str {
        match &self.state {
            TaskState::Created => "Created",
            TaskState::Running => "Running",
            TaskState::CancelRequested { .. } => "CancelRequested",
            TaskState::Cancelling { .. } => "Cancelling",
            TaskState::Finalizing { .. } => "Finalizing",
            TaskState::Completed(_) => "Completed",
        }
    }

    /// Returns the atomic lifecycle phase for this task.
    #[inline]
    #[must_use]
    pub fn phase(&self) -> TaskPhase {
        self.phase.load()
    }

    /// Requests cancellation of this task.
    ///
    /// Returns whether the request was new together with the opaque Waker
    /// effects that must be dispatched after releasing every caller-owned
    /// task-table and runtime-state lock.
    pub fn request_cancel(&mut self, reason: CancelReason) -> CancellationEffects<bool> {
        // Need to get current budget from somewhere.
        // If we removed `budget` field, we should get it from `CxInner` or use default?
        // `request_cancel_with_budget` takes explicit budget.
        // `request_cancel` assumes a default cleanup budget?
        // Usually `reason.cleanup_budget()`.
        let budget = reason.cleanup_budget();
        self.request_cancel_with_budget(reason, budget)
    }

    /// Requests cancellation with an explicit cleanup budget.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::used_underscore_binding)]
    pub fn request_cancel_with_budget(
        &mut self,
        reason: CancelReason,
        cleanup_budget: Budget,
    ) -> CancellationEffects<bool> {
        let effects = self.request_cancel_with_budget_and_publication(reason, cleanup_budget);
        let ((newly_cancelled, _changed, _publication), wakes) = effects.into_parts();
        CancellationEffects::new(newly_cancelled, wakes)
    }

    /// Runtime-internal cancellation variant that snapshots the initial
    /// runnable-publication gate in the same Cx critical section as the
    /// cancellation mutation. This avoids a TOCTOU double-publication race
    /// between admission and runtime cancellation schedulers.
    pub(crate) fn request_cancel_with_budget_and_publication(
        &mut self,
        mut reason: CancelReason,
        mut cleanup_budget: Budget,
    ) -> CancellationEffects<(bool, bool, RunnablePublication)> {
        if self.state.is_terminal() {
            return CancellationEffects::ready((false, false, RunnablePublication::Published));
        }

        let previous_state = self.state_name();
        // Keep the Cx cancellation mutation and first-publication decision in
        // one critical section. Admission uses the same lock while publishing
        // the initial runnable lane, so cancellation cannot expose a
        // reasonless or half-published task.
        let cx_inner = self.cx_inner.clone();
        let mut inner_guard = cx_inner.as_ref().map(|inner| inner.write());
        if let Some(guard) = inner_guard.as_mut() {
            let newly_requested = !guard.cancel_requested;
            if let Some(cx_reason) = guard.cancel_reason.as_ref() {
                if reason.strengthen(cx_reason) {
                    cleanup_budget = cleanup_budget.combine_untraced(cx_reason.cleanup_budget());
                }
            }
            guard.set_cancel_requested(true);
            if newly_requested {
                guard.cancel_wakers_pending = true;
            }
            // Budget update is deferred to acknowledge_cancel to prevent
            // pre-empting the cancellation check with a budget exhaustion error.
        }
        let requested_cancel_kind = reason.kind;
        let requested_cleanup_poll_quota = cleanup_budget.poll_quota;
        let mut updated_reason_for_inner = None;

        let result = match &mut self.state {
            TaskState::CancelRequested {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            } => {
                self.phase.store(TaskPhase::CancelRequested);
                let reason_changed = existing_reason.strengthen(&reason);
                let combined_budget = existing_budget.combine_untraced(cleanup_budget);
                let budget_changed = combined_budget != *existing_budget;
                *existing_budget = combined_budget;
                updated_reason_for_inner = Some(existing_reason.clone());
                (
                    false,
                    reason_changed || budget_changed,
                    CancelTaskTraceKind::StrengthenedRequested,
                )
            }
            TaskState::Cancelling {
                reason: existing_reason,
                cleanup_budget: b,
            } => {
                self.phase.store(TaskPhase::Cancelling);
                let reason_changed = existing_reason.strengthen(&reason);
                let new_budget = b.combine_untraced(cleanup_budget);
                let budget_changed = new_budget != *b;
                *b = new_budget;
                updated_reason_for_inner = Some(existing_reason.clone());

                // Update shared state so user code sees tighter budget immediately
                if let Some(guard) = inner_guard.as_mut() {
                    guard.budget = new_budget;
                    guard.budget_baseline = new_budget;
                    guard.cleanup_phase = true;
                }
                // Also update polls_remaining to respect tighter quota
                self.polls_remaining = self.polls_remaining.min(new_budget.poll_quota);

                (
                    false,
                    reason_changed || budget_changed,
                    CancelTaskTraceKind::StrengthenedCleanup,
                )
            }
            TaskState::Finalizing {
                reason: existing_reason,
                cleanup_budget: b,
            } => {
                self.phase.store(TaskPhase::Finalizing);
                let reason_changed = existing_reason.strengthen(&reason);
                let new_budget = b.combine_untraced(cleanup_budget);
                let budget_changed = new_budget != *b;
                *b = new_budget;
                updated_reason_for_inner = Some(existing_reason.clone());

                // Update shared state so user code sees tighter budget immediately
                if let Some(guard) = inner_guard.as_mut() {
                    guard.budget = new_budget;
                    guard.budget_baseline = new_budget;
                    guard.cleanup_phase = true;
                }
                // Also update polls_remaining to respect tighter quota
                self.polls_remaining = self.polls_remaining.min(new_budget.poll_quota);

                (
                    false,
                    reason_changed || budget_changed,
                    CancelTaskTraceKind::StrengthenedCleanup,
                )
            }
            TaskState::Created | TaskState::Running => {
                let requested_reason = reason.clone();
                if self.cancel_epoch == 0 {
                    self.cancel_epoch = 1;
                } else {
                    self.cancel_epoch = self.cancel_epoch.saturating_add(1);
                }
                self.state = TaskState::CancelRequested {
                    reason,
                    cleanup_budget,
                };
                self.phase.store(TaskPhase::CancelRequested);
                updated_reason_for_inner = Some(requested_reason);
                (true, true, CancelTaskTraceKind::Requested)
            }
            TaskState::Completed(_) => (false, false, CancelTaskTraceKind::StrengthenedCleanup),
        };
        // Trace the authoritative post-strengthening reason and budget. Using
        // the incoming request here can falsely publish a weaker cancellation
        // even though the task record correctly preserved its stronger reason.
        let (cancel_kind, trace_cleanup_poll_quota) = match &self.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            }
            | TaskState::Cancelling {
                reason,
                cleanup_budget,
            }
            | TaskState::Finalizing {
                reason,
                cleanup_budget,
            } => (reason.kind, cleanup_budget.poll_quota),
            TaskState::Created | TaskState::Running | TaskState::Completed(_) => {
                (requested_cancel_kind, requested_cleanup_poll_quota)
            }
        };
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (&previous_state, &cancel_kind, trace_cleanup_poll_quota);
        if let Some(reason) = updated_reason_for_inner {
            if let Some(guard) = inner_guard.as_mut() {
                let reason_changed = if let Some(existing) = guard.cancel_reason.as_mut() {
                    existing.strengthen(&reason)
                } else {
                    guard.cancel_reason = Some(reason);
                    true
                };
                if reason_changed {
                    guard.cancel_wakers_pending = true;
                }
            }
        }
        let runnable_publication = inner_guard
            .as_ref()
            .map_or(RunnablePublication::Published, |guard| {
                guard.runnable_publication
            });
        let cancel_wakers = inner_guard.as_mut().map_or_else(SmallVec::new, |guard| {
            if guard.cancel_requested
                && guard.cancel_wakers_pending
                && runnable_publication.is_published()
            {
                let wakers = guard.cancel_waker_snapshot();
                guard.cancel_wakers_pending = false;
                wakers
            } else {
                SmallVec::new()
            }
        });
        let wakes = CancelWakeEffects::new(cancel_wakers);
        #[cfg(feature = "tracing-integration")]
        let wakes = {
            let mut wakes = wakes;
            let trace = PendingTaskCancelTrace::new(
                result.2,
                self.id,
                self.owner,
                previous_state,
                cancel_kind,
                trace_cleanup_poll_quota,
            );
            if runnable_publication.is_published() {
                trace.append_to(&mut wakes);
            } else {
                let pending = &mut inner_guard
                    .as_mut()
                    .expect("prepublication tasks retain their Cx admission gate")
                    .pending_task_cancel_trace;
                if pending.is_none() {
                    *pending = Some(trace);
                }
            }
            wakes
        };
        #[cfg(not(feature = "tracing-integration"))]
        let _ = result.2;
        drop(inner_guard);
        CancellationEffects::new((result.0, result.1, runnable_publication), wakes)
    }

    /// Atomically publishes a managed handle abort's delegated first cancel lane.
    ///
    /// The authoritative task-table/RuntimeState owner must keep its record lock
    /// across this call. `publish_lane` runs while the Cx publication gate is
    /// write-locked and must only mutate scheduler queues: it must not wake a
    /// worker, emit observability, or re-enter the task table. That ordering
    /// prevents an already-awake worker from removing or polling the task before
    /// the lane, strongest Cx reason, Wakers, and pending trace receipt agree.
    /// If the closure rejects the route, Cx remains delegated and the returned
    /// effects own only duplicate Waker snapshots; the caller must retire those
    /// snapshots without dispatch after releasing the outer record lock.
    pub(crate) fn publish_delegated_cancel_lane<T>(
        &mut self,
        publish_lane: impl FnOnce(u8, bool, Option<usize>) -> Option<T>,
    ) -> CancellationEffects<Option<T>> {
        if self.state.is_terminal() {
            return CancellationEffects::ready(None);
        }
        let Some(cx_inner) = self.cx_inner.clone() else {
            return CancellationEffects::ready(None);
        };
        let mut guard = cx_inner.write();
        if !guard.runnable_publication.is_delegated_cancel() || !guard.cancel_requested {
            return CancellationEffects::ready(None);
        }

        // A direct TaskHandle producer can strengthen Cx and enqueue a second
        // command after the first command reconciles TaskRecord. Materialize
        // that full reason and cleanup budget before exposing the first lane;
        // merely promoting the queue priority would let an immediately-ready
        // task retire with stale cancellation attribution.
        let Some(priority) = self.materialize_delegated_cx_cancel(&mut guard) else {
            return CancellationEffects::ready(None);
        };
        // Snapshot every fallible/allocating receipt before queue visibility.
        // Keep ownership pending in Cx until insertion succeeds so a rejected
        // route can retry without losing either Wakers or the trace receipt.
        let cancel_wakers = if guard.cancel_wakers_pending {
            guard.cancel_waker_snapshot()
        } else {
            SmallVec::new()
        };
        #[cfg(feature = "tracing-integration")]
        let pending_trace = guard.pending_task_cancel_trace;
        self.wake_state.notify();
        let publication = publish_lane(priority, self.is_local, self.pinned_worker);
        let Some(publication) = publication else {
            drop(guard);
            return CancellationEffects::new(None, CancelWakeEffects::new(cancel_wakers));
        };
        // The write gate was checked above and cannot change while held.
        // Avoid any assertion/panic edge after physical queue visibility.
        guard.runnable_publication.mark_published();

        if guard.cancel_wakers_pending {
            guard.cancel_wakers_pending = false;
        }
        #[cfg(feature = "tracing-integration")]
        {
            guard.pending_task_cancel_trace = None;
        }
        drop(guard);
        let wakes = CancelWakeEffects::new(cancel_wakers);
        #[cfg(feature = "tracing-integration")]
        let wakes = {
            let mut wakes = wakes;
            if let Some(trace) = pending_trace {
                trace.append_to(&mut wakes);
            }
            wakes
        };
        CancellationEffects::new(Some(publication), wakes)
    }

    /// Reconciles a Cx-only cancellation strengthening into the authoritative
    /// record while the caller owns both the record and Cx publication gates.
    /// This helper deliberately performs no tracing or other observer calls.
    fn materialize_delegated_cx_cancel(&mut self, guard: &mut CxInner) -> Option<u8> {
        let cx_reason = guard.cancel_reason.as_ref()?;
        let cx_budget = cx_reason.cleanup_budget();
        let mut active_cleanup_budget = None;

        match &mut self.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            } => {
                reason.strengthen(cx_reason);
                *cleanup_budget = cleanup_budget.combine_untraced(cx_budget);
            }
            TaskState::Cancelling {
                reason,
                cleanup_budget,
            }
            | TaskState::Finalizing {
                reason,
                cleanup_budget,
            } => {
                reason.strengthen(cx_reason);
                *cleanup_budget = cleanup_budget.combine_untraced(cx_budget);
                active_cleanup_budget = Some(*cleanup_budget);
            }
            TaskState::Created | TaskState::Running | TaskState::Completed(_) => return None,
        }

        if let Some(cleanup_budget) = active_cleanup_budget {
            guard.budget = cleanup_budget;
            guard.budget_baseline = cleanup_budget;
            guard.cleanup_phase = true;
            self.polls_remaining = self.polls_remaining.min(cleanup_budget.poll_quota);
        }
        self.cleanup_budget().map(|budget| budget.priority)
    }

    /// Reconciles a producer-side handle cancellation into authoritative task
    /// state and selects the lane publication owned by its scheduler consumer.
    pub(crate) fn request_cancel_for_handle(
        &mut self,
        reason: &CancelReason,
    ) -> CancellationEffects<HandleCancelUpdate> {
        let budget = reason.cleanup_budget();
        let effects = self.request_cancel_with_budget_and_publication(reason.clone(), budget);
        let cleanup_priority = self.cleanup_budget().map(|budget| budget.priority);
        let ((newly_cancelled, changed, publication), wakes) = effects.into_parts();
        let route = cleanup_priority.and_then(|priority| {
            if publication.is_delegated_cancel() {
                Some(HandleCancelRoute {
                    priority,
                    delegated_initial: true,
                })
            } else if changed && publication.is_published() {
                Some(HandleCancelRoute {
                    priority,
                    delegated_initial: false,
                })
            } else {
                None
            }
        });
        CancellationEffects::new(
            HandleCancelUpdate {
                newly_cancelled,
                route,
            },
            wakes,
        )
    }

    /// Returns a cancellation witness for the current task state, if cancelled.
    #[must_use]
    pub fn cancel_witness(&self) -> Option<CancelWitness> {
        if self.cancel_epoch == 0 {
            return None;
        }
        let (phase, reason) = match &self.state {
            TaskState::CancelRequested { reason, .. } => (CancelPhase::Requested, reason.clone()),
            TaskState::Cancelling { reason, .. } => (CancelPhase::Cancelling, reason.clone()),
            TaskState::Finalizing { reason, .. } => (CancelPhase::Finalizing, reason.clone()),
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                (CancelPhase::Completed, reason.clone())
            }
            _ => return None,
        };
        Some(CancelWitness::new(
            self.id,
            self.owner,
            self.cancel_epoch,
            phase,
            reason,
        ))
    }

    /// Marks the task as running (Created → Running).
    ///
    /// Returns true if the state changed.
    pub fn start_running(&mut self) -> bool {
        match self.state {
            TaskState::Created => {
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = "Created",
                    new_state = "Running",
                    "task state transition"
                );
                self.state = TaskState::Running;
                self.phase.store(TaskPhase::Running);
                true
            }
            _ => false,
        }
    }

    /// Reconciles a cancellation already observed by the running task's Cx.
    ///
    /// A TaskHandle request makes the Cx flag visible before its callback-free
    /// command can acquire the runtime/task-table owner. If the task reaches a
    /// checkpoint in that interval, completion must first materialize the
    /// acknowledged reason in the authoritative TaskRecord. This path is
    /// intentionally Waker-free: the task is already executing the poll that
    /// observed cancellation.
    pub(crate) fn reconcile_checkpoint_cancel(&mut self, mut reason: CancelReason) -> bool {
        if self.state.is_terminal() {
            return false;
        }
        let cx_inner = self.cx_inner.clone();
        let mut cleanup_budget = reason.cleanup_budget();
        let changed = match &mut self.state {
            TaskState::Created | TaskState::Running => {
                if self.cancel_epoch == 0 {
                    self.cancel_epoch = 1;
                } else {
                    self.cancel_epoch = self.cancel_epoch.saturating_add(1);
                }
                self.state = TaskState::CancelRequested {
                    reason,
                    cleanup_budget,
                };
                self.phase.store(TaskPhase::CancelRequested);
                true
            }
            TaskState::CancelRequested {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            }
            | TaskState::Cancelling {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            }
            | TaskState::Finalizing {
                reason: existing_reason,
                cleanup_budget: existing_budget,
            } => {
                if reason.strengthen(existing_reason) {
                    cleanup_budget =
                        cleanup_budget.combine_untraced(existing_reason.cleanup_budget());
                }
                let reason_changed = existing_reason.strengthen(&reason);
                let combined_budget = existing_budget.combine_untraced(cleanup_budget);
                let budget_changed = combined_budget != *existing_budget;
                *existing_budget = combined_budget;
                reason_changed || budget_changed
            }
            TaskState::Completed(_) => false,
        };
        if matches!(
            self.state,
            TaskState::Cancelling { .. } | TaskState::Finalizing { .. }
        ) && let Some(cleanup_budget) = self.cleanup_budget()
        {
            if let Some(inner) = cx_inner {
                let mut guard = inner.write();
                guard.budget = cleanup_budget;
                guard.budget_baseline = cleanup_budget;
                guard.cleanup_phase = true;
            }
            self.polls_remaining = self.polls_remaining.min(cleanup_budget.poll_quota);
        }
        changed
    }

    /// Consumes a cancellation acknowledgement already published by this
    /// task's `Cx` and reconciles it into the authoritative task state.
    ///
    /// Callers that observe a receipt after `Poll::Pending` must publish a
    /// cancel-lane entry before dispatching the returned Wakers or parking the
    /// task. Callers completing the same poll dispatch only after terminal
    /// state and dependent queue publication.
    pub(crate) fn consume_checkpoint_cancel_ack(
        &mut self,
    ) -> CancellationEffects<Option<CheckpointCancelAck>> {
        // Every pending poll lands here. Refresh the cached quota in the same
        // read already needed for acknowledgement: a GenServer phase can
        // tighten or restore its budget during the poll (asupersync-0fvvq9).
        // The next native dispatch then charges the live phase exactly once,
        // without adding a lock to the unlimited pre-poll fast path.
        // Almost no poll acknowledges cancellation; avoid cloning the Arc in
        // that case (br-asupersync-issue65-criticisms-kpmoy5.1.3). The flag is
        // re-checked under the write lock below.
        let acknowledged = self.cx_inner.as_ref().is_some_and(|inner| {
            let guard = inner.read();
            self.polls_remaining = guard.budget.poll_quota;
            guard.cancel_acknowledged
        });
        if !acknowledged {
            return CancellationEffects::ready(None);
        }
        let Some(inner) = self.cx_inner.clone() else {
            return CancellationEffects::ready(None);
        };
        let mut guard = inner.write();
        if !guard.cancel_acknowledged {
            return CancellationEffects::ready(None);
        }
        guard.cancel_acknowledged = false;
        let observed_reason = guard.cancel_reason.clone().unwrap_or_else(|| {
            CancelReason::with_origin(crate::types::CancelKind::User, self.owner, self.created_at)
                .with_task(self.id)
                .with_message("checkpoint acknowledged cancellation without a reason")
        });
        drop(guard);

        let request_from = self.state.clone();
        let was_unmaterialized = matches!(request_from, TaskState::Created | TaskState::Running);
        let _ = self.reconcile_checkpoint_cancel(observed_reason.clone());
        let request_transition = was_unmaterialized.then(|| (request_from, self.state.clone()));

        let acknowledge_from = self.state.clone();
        let acknowledge_transition = self
            .acknowledge_cancel()
            .map(|_| (acknowledge_from, self.state.clone()));
        let mut effective_reason = self.cancel_reason().cloned().unwrap_or(observed_reason);
        // A stronger handle abort can land after the first Cx snapshot but
        // before this poll commits its checkpoint receipt. Re-read until the
        // authoritative TaskRecord dominates the Cx reason, then use the final
        // Cx critical section as the completion/cancellation linearization
        // point. A still-later abort loses to this completing poll and leaves
        // its Waker debt untouched for terminal retirement.
        let cancel_wakers = loop {
            let mut guard = inner.write();
            if let Some(latest_reason) = guard.cancel_reason.clone() {
                let mut merged_reason = effective_reason.clone();
                if merged_reason.strengthen(&latest_reason) {
                    drop(guard);
                    let _ = self.reconcile_checkpoint_cancel(latest_reason);
                    effective_reason = self.cancel_reason().cloned().unwrap_or(merged_reason);
                    continue;
                }
            }
            if guard.cancel_requested
                && guard.cancel_wakers_pending
                && guard.runnable_publication.is_published()
            {
                let wakers = guard.cancel_waker_snapshot();
                guard.cancel_wakers_pending = false;
                break wakers;
            } else {
                break SmallVec::new();
            }
        };
        let cleanup_priority = self.cleanup_budget().map_or_else(
            || effective_reason.cleanup_budget().priority,
            |budget| budget.priority,
        );

        CancellationEffects::new(
            Some(CheckpointCancelAck {
                effective_reason,
                cleanup_priority,
                request_transition,
                acknowledge_transition,
                region_id: self.owner,
                spawned_at: self.created_at,
            }),
            CancelWakeEffects::new(cancel_wakers),
        )
    }

    /// Completes the task with the given outcome.
    ///
    /// Returns true if the state changed.
    #[allow(clippy::used_underscore_binding, clippy::no_effect_underscore_binding)]
    pub fn complete(&mut self, outcome: TaskOutcome) -> bool {
        if self.state.is_terminal() {
            return false;
        }
        if let Some(cx) = &self.cx {
            cx.revoke_obligation_admission();
        }
        let outcome = match (&self.state, outcome) {
            (
                TaskState::CancelRequested { reason, .. }
                | TaskState::Cancelling { reason, .. }
                | TaskState::Finalizing { reason, .. },
                Outcome::Ok(()) | Outcome::Err(_),
            ) => Outcome::Cancelled(reason.clone()),
            (
                TaskState::CancelRequested { reason, .. }
                | TaskState::Cancelling { reason, .. }
                | TaskState::Finalizing { reason, .. },
                Outcome::Cancelled(outcome_reason),
            ) => {
                let mut final_reason = reason.clone();
                final_reason.strengthen(&outcome_reason);
                Outcome::Cancelled(final_reason)
            }
            (_, outcome) => outcome,
        };
        if matches!(outcome, Outcome::Cancelled(_)) && self.cancel_epoch == 0 {
            self.cancel_epoch = 1;
        }
        #[cfg(feature = "tracing-integration")]
        {
            let prev_state = self.state_name();
            let outcome_label = match &outcome {
                Outcome::Ok(()) => "Ok",
                Outcome::Err(_) => "Err",
                Outcome::Cancelled(_) => "Cancelled",
                Outcome::Panicked(_) => "Panicked",
            };
            // br-asupersync-1w9aot: sample "now" through wall_now()
            // (replayable when the lab runtime installs a virtual
            // clock) and compute the elapsed nanos via Time
            // arithmetic. `Time::duration_since` is saturating, so a
            // backward clock step (NTP slew, Time::ZERO default) can
            // never produce a negative or wrap-around duration.
            let now: Time = crate::time::wall_now();
            let duration_us = now.duration_since(self.created_instant) / 1000;
            let total_polls = self.total_polls;
            crate::tracing_compat::debug!(
                task_id = ?self.id,
                region_id = ?self.owner,
                old_state = prev_state,
                new_state = "Completed",
                outcome_kind = outcome_label,
                duration_us = duration_us,
                poll_count = total_polls,
                "task completed"
            );
        }
        self.state = TaskState::Completed(outcome);
        self.phase.store(TaskPhase::Completed);
        true
    }

    /// Adds a waiter for this task's completion.
    pub fn add_waiter(&mut self, waiter: TaskId) {
        if !self.waiters.contains(&waiter) {
            self.waiters.push(waiter);
        }
    }

    /// Acknowledges cancellation, transitioning from `CancelRequested` to `Cancelling`.
    ///
    /// This is called when `checkpoint()` observes cancellation with mask_depth == 0.
    /// Returns the `CancelReason` if the transition occurred, `None` otherwise.
    /// The transition is callback-free because scheduler callers commonly hold
    /// an authoritative TaskTable or RuntimeState lock here.
    ///
    /// # State Transition
    /// ```text
    /// CancelRequested { reason, cleanup_budget } → Cancelling { reason, cleanup_budget }
    /// ```
    pub fn acknowledge_cancel(&mut self) -> Option<CancelReason> {
        match &self.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            } => {
                let reason = reason.clone();
                let budget = *cleanup_budget;

                // Apply cleanup budget now that we are entering cleanup phase
                if let Some(inner) = &self.cx_inner {
                    let mut guard = inner.write();
                    guard.budget = budget;
                    guard.budget_baseline = budget;
                    guard.cleanup_phase = true;
                }
                self.polls_remaining = budget.poll_quota;

                self.state = TaskState::Cancelling {
                    reason: reason.clone(),
                    cleanup_budget: budget,
                };
                self.phase.store(TaskPhase::Cancelling);
                Some(reason)
            }
            _ => None,
        }
    }

    /// Transitions from `Cancelling` to `Finalizing` after cleanup code completes.
    ///
    /// Returns `true` if the transition occurred.
    ///
    /// # State Transition
    /// ```text
    /// Cancelling { reason, cleanup_budget } → Finalizing { reason, cleanup_budget }
    /// ```
    pub fn cleanup_done(&mut self) -> bool {
        match &self.state {
            TaskState::Cancelling {
                reason,
                cleanup_budget,
            } => {
                let reason = reason.clone();
                let budget = *cleanup_budget;
                trace!(
                    task_id = ?self.id,
                    region_id = ?self.owner,
                    old_state = "Cancelling",
                    new_state = "Finalizing",
                    cancel_kind = ?reason.kind,
                    finalizer_budget_poll_quota = budget.poll_quota,
                    finalizer_budget_priority = budget.priority,
                    "task cleanup done, entering finalization"
                );
                self.state = TaskState::Finalizing {
                    reason,
                    cleanup_budget: budget,
                };
                self.phase.store(TaskPhase::Finalizing);
                true
            }
            _ => false,
        }
    }

    /// Transitions from `Finalizing` to `Completed(Cancelled)` after finalizers complete.
    ///
    /// Returns `true` if the transition occurred.
    ///
    /// # State Transition
    /// ```text
    /// Finalizing { .. } → Completed(Cancelled(reason))
    /// ```
    #[allow(clippy::no_effect_underscore_binding)]
    pub fn finalize_done(&mut self) -> bool {
        self.finalize_done_with_witness().is_some()
    }

    /// Transitions from `Finalizing` to `Completed(Cancelled)` and returns a witness.
    #[allow(clippy::no_effect_underscore_binding)]
    pub fn finalize_done_with_witness(&mut self) -> Option<CancelWitness> {
        let TaskState::Finalizing {
            reason,
            cleanup_budget,
        } = &self.state
        else {
            return None;
        };
        let reason = reason.clone();
        let budget = *cleanup_budget;
        if let Some(cx) = &self.cx {
            cx.revoke_obligation_admission();
        }
        #[cfg(feature = "tracing-integration")]
        {
            // br-asupersync-1w9aot: same wall_now-routed Time
            // arithmetic as the success-path trace site above.
            let now: Time = crate::time::wall_now();
            let duration_us = now.duration_since(self.created_instant) / 1000;
            let total_polls = self.total_polls;
            crate::tracing_compat::debug!(
                task_id = ?self.id,
                region_id = ?self.owner,
                old_state = "Finalizing",
                new_state = "Completed",
                outcome_kind = "Cancelled",
                cancel_kind = ?reason.kind,
                finalizer_budget_poll_quota = budget.poll_quota,
                finalizer_budget_priority = budget.priority,
                duration_us = duration_us,
                poll_count = total_polls,
                "task finalization done"
            );
        }
        let _ = budget;
        self.state = TaskState::Completed(Outcome::Cancelled(reason.clone()));
        self.phase.store(TaskPhase::Completed);
        Some(CancelWitness::new(
            self.id,
            self.owner,
            self.cancel_epoch,
            CancelPhase::Completed,
            reason,
        ))
    }

    /// Returns the cancel reason if the task is being cancelled.
    ///
    /// This returns `Some` for `CancelRequested`, `Cancelling`, and `Finalizing` states.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<&CancelReason> {
        match &self.state {
            TaskState::CancelRequested { reason, .. }
            | TaskState::Cancelling { reason, .. }
            | TaskState::Finalizing { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// Returns the cleanup budget if the task is being cancelled.
    #[must_use]
    pub fn cleanup_budget(&self) -> Option<Budget> {
        match &self.state {
            TaskState::CancelRequested { cleanup_budget, .. }
            | TaskState::Cancelling { cleanup_budget, .. }
            | TaskState::Finalizing { cleanup_budget, .. } => Some(*cleanup_budget),
            _ => None,
        }
    }

    /// Marks this task as a local (`!Send`) task pinned to its owner worker.
    ///
    /// Once set, the scheduler must never steal this task across threads.
    pub fn mark_local(&mut self) {
        self.is_local = true;
    }

    /// Marks this task as local and pins it to a specific worker.
    ///
    /// This should be used when spawning local tasks on a worker thread.
    pub fn pin_to_worker(&mut self, worker_id: usize) {
        self.is_local = true;
        self.pinned_worker = Some(worker_id);
    }

    /// Returns `true` if this is a local (`!Send`) task.
    #[must_use]
    #[inline]
    pub const fn is_local(&self) -> bool {
        self.is_local
    }

    /// Returns the owning worker for local tasks, if known.
    #[must_use]
    #[inline]
    pub const fn pinned_worker(&self) -> Option<usize> {
        self.pinned_worker
    }

    // ── Intrusive queue helpers ──────────────────────────────────────────

    /// Returns true if this task is currently in any intrusive queue.
    #[must_use]
    #[inline]
    pub const fn is_in_queue(&self) -> bool {
        self.queue_tag != 0
    }

    /// Returns true if this task is in the specified queue.
    #[must_use]
    #[inline]
    pub const fn is_in_queue_tag(&self, tag: u8) -> bool {
        self.queue_tag == tag
    }

    /// Sets the queue links and tag when inserting into a queue.
    #[inline]
    pub fn set_queue_links(&mut self, prev: Option<TaskId>, next: Option<TaskId>, tag: u8) {
        self.prev_in_queue = prev;
        self.next_in_queue = next;
        self.queue_tag = tag;
    }

    /// Clears the queue links and tag when removing from a queue.
    #[inline]
    pub fn clear_queue_links(&mut self) {
        self.prev_in_queue = None;
        self.next_in_queue = None;
        self.queue_tag = 0;
    }

    /// Decrements the mask depth, returning the new value.
    ///
    /// Returns `None` if already at zero.
    ///
    /// This now accesses the shared `CxInner`.
    pub fn decrement_mask(&mut self) -> Option<u32> {
        if let Some(inner) = &self.cx_inner {
            let mut guard = inner.write();
            if guard.mask_depth > 0 {
                guard.mask_depth -= 1;
                return Some(guard.mask_depth);
            }
        }
        None
    }

    /// Increments the mask depth, returning the new value.
    pub fn increment_mask(&mut self) -> u32 {
        if let Some(inner) = &self.cx_inner {
            let mut guard = inner.write();
            // Enforce mask depth cap to prevent overflow and infinite recursion
            // This maintains INV-MASK-BOUNDED invariant in both debug and release builds
            assert!(
                guard.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
                "mask depth exceeded MAX_MASK_DEPTH ({}): violates INV-MASK-BOUNDED",
                crate::types::task_context::MAX_MASK_DEPTH,
            );
            guard.mask_depth += 1;
            return guard.mask_depth;
        }
        0 // Fallback if no inner (shouldn't happen in running task)
    }
}

impl crate::util::Recyclable for TaskRecord {
    /// Resets the TaskRecord to a clean state for reuse in the object pool.
    ///
    /// This method clears all runtime state while preserving the core structure
    /// to enable efficient recycling. The reset record can be reused for a new
    /// task by calling the appropriate initialization methods.
    fn reset(&mut self) {
        // Reset core task state
        self.id = TaskId::from_arena(crate::util::ArenaIndex::new(0, 0));
        self.owner = RegionId::from_arena(crate::util::ArenaIndex::new(0, 0));
        self.state = TaskState::Created;
        self.phase = TaskPhaseCell::new(TaskPhase::Created);

        // Reset context and waker state
        self.cx_inner = None;
        self.cx = None;

        // Reset timing and metrics
        self.created_at = Time::from_nanos(1_000_000_000);
        self.deadline = None;
        self.polls_remaining = 0;
        self.total_polls = 0;
        // br-asupersync-1w9aot: reset path also routes through
        // wall_now() so the lab runtime can intercept on replay.
        #[cfg(feature = "tracing-integration")]
        {
            self.created_instant = crate::time::wall_now();
        }
        self.last_polled_step = 0;

        // Clear collections
        self.waiters.clear();

        // Reset cached wakers
        self.cached_waker = None;
        self.cached_cancel_waker = None;

        // Reset cancellation state
        self.cancel_epoch = 0;

        // Reset locality state
        self.is_local = false;
        self.pinned_worker = None;

        // Reset intrusive queue state
        self.next_in_queue = None;
        self.prev_in_queue = None;
        self.queue_tag = 0;

        // Reset intrusive heap state
        self.heap_index = None;
        self.sched_priority = 0;
        self.sched_generation = 0;

        // Create new wake_state (or reuse existing allocation if uniquely owned)
        if let Some(state) = std::sync::Arc::get_mut(&mut self.wake_state) {
            *state = TaskWakeState::new();
        } else {
            self.wake_state = std::sync::Arc::new(TaskWakeState::new());
        }
    }
}

#[cfg(test)]
#[path = "task_inline_tests.rs"]
mod tests;
