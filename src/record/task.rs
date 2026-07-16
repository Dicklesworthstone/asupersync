//! Task record for the runtime.
//!
//! A task is a unit of concurrent execution owned by a region.
//! This module defines the internal record structure for tracking task state.

use crate::cx::Cx;
use crate::tracing_compat::trace;
#[cfg(feature = "tracing-integration")]
use crate::types::task_context::PendingTaskCancelTrace;
use crate::types::task_context::{
    CancelTaskTraceKind, CancelWakeEffects, CancellationEffects, RunnablePublication,
};
use crate::types::{
    Budget, CancelPhase, CancelReason, CancelWitness, CxInner, Outcome, RegionId, TaskId, Time,
};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
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

/// Atomic task phase cell for cross-thread state checks.
#[derive(Debug)]
pub struct TaskPhaseCell {
    inner: AtomicU8,
}

impl TaskPhaseCell {
    /// Creates a new cell initialized to the given phase.
    #[inline]
    #[must_use]
    pub fn new(phase: TaskPhase) -> Self {
        Self {
            inner: AtomicU8::new(phase.as_u8()),
        }
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
        self.inner.store(phase as u8, Ordering::Release);
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
    /// Cached scheduling priority for intrusive heap comparison.
    /// Set when the task is inserted into an `IntrusivePriorityHeap`.
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

    /// Sets the shared CxInner.
    #[inline]
    pub fn set_cx_inner(&mut self, inner: Arc<RwLock<CxInner>>) {
        self.deadline = inner.read().budget.deadline;
        self.cx_inner = Some(inner);
    }

    /// Sets the full Cx for this task.
    pub fn set_cx(&mut self, cx: Cx) {
        self.cx = Some(cx);
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
            guard.cancel_requested = true;
            if newly_requested {
                guard.cancel_wakers_pending = true;
            }
            guard
                .fast_cancel
                .store(true, std::sync::atomic::Ordering::Release);
            // Budget update is deferred to acknowledge_cancel to prevent
            // pre-empting the cancellation check with a budget exhaustion error.
        }
        let cancel_kind = reason.kind;
        #[cfg(not(feature = "tracing-integration"))]
        let _ = (&previous_state, &cancel_kind);

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
                cleanup_budget.poll_quota,
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
    use crate::error::{Error, ErrorKind};
    use crate::types::task_context::CancelWaker;
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 0))
    }

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn request_cancel(record: &mut TaskRecord, reason: CancelReason) -> bool {
        let (newly_cancelled, wakes) = record.request_cancel(reason).into_parts();
        wakes.dispatch();
        newly_cancelled
    }

    fn request_cancel_with_budget(
        record: &mut TaskRecord,
        reason: CancelReason,
        budget: Budget,
    ) -> bool {
        let (newly_cancelled, wakes) = record
            .request_cancel_with_budget(reason, budget)
            .into_parts();
        wakes.dispatch();
        newly_cancelled
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn cancellation_trace_reenters_only_after_outer_lock_and_contains_panic() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
            reentries: Arc<AtomicUsize>,
            outer_lock: Arc<parking_lot::Mutex<()>>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if self.outer_lock.try_lock().is_some() {
                    self.reentries.fetch_add(1, Ordering::SeqCst);
                }
                panic!("adversarial cancellation tracing subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let reentries = Arc::new(AtomicUsize::new(0));
        let outer_lock = Arc::new(parking_lot::Mutex::new(()));
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
            reentries: Arc::clone(&reentries),
            outer_lock: Arc::clone(&outer_lock),
        });

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || {
                let effects = {
                    let _outer_guard = outer_lock.lock();
                    let effects = record
                        .request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE);
                    assert_eq!(
                        attempts.load(Ordering::SeqCst),
                        0,
                        "request_cancel must not enter the subscriber under the outer lock"
                    );
                    effects
                };

                let (newly_cancelled, observers_and_wakes) = effects.into_parts();
                assert!(newly_cancelled);
                observers_and_wakes.dispatch();
                assert_eq!(attempts.load(Ordering::SeqCst), 1);
                assert_eq!(reentries.load(Ordering::SeqCst), 1);
            });
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn unpublished_cancel_trace_waits_for_admission_publication_callback() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
            early_attempts: Arc<AtomicUsize>,
            lane_published: Arc<std::sync::atomic::AtomicBool>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if !self.lane_published.load(Ordering::SeqCst) {
                    self.early_attempts.fetch_add(1, Ordering::SeqCst);
                }
                panic!("adversarial pre-publication tracing subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let early_attempts = Arc::new(AtomicUsize::new(0));
        let lane_published = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        inner.write().runnable_publication = RunnablePublication::Unpublished;
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
            early_attempts: Arc::clone(&early_attempts),
            lane_published: Arc::clone(&lane_published),
        });

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || {
                let effects = record.request_cancel_with_budget(
                    CancelReason::user("prepublication"),
                    Budget::INFINITE,
                );
                let (newly_cancelled, immediate_effects) = effects.into_parts();
                assert!(newly_cancelled);
                immediate_effects.dispatch();
                assert_eq!(attempts.load(Ordering::SeqCst), 0);

                let repeated =
                    record.request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE);
                let (newly_cancelled, repeated_effects) = repeated.into_parts();
                assert!(!newly_cancelled);
                repeated_effects.dispatch();
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    0,
                    "prepublication strengthening traces remain coalesced"
                );
                assert!(
                    record
                        .cancel_reason()
                        .is_some_and(|reason| reason.is_kind(crate::types::CancelKind::Shutdown)),
                    "strongest prepublication reason remains authoritative"
                );

                let deferred = crate::runtime::task_handle::publish_admitted_cancel_state(
                    &inner,
                    None,
                    |priority| {
                        assert!(
                            priority.is_some(),
                            "cancelled admission selects cancel lane"
                        );
                        lane_published.store(true, Ordering::SeqCst);
                    },
                );
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                assert!(inner.read().runnable_publication.is_published());
                deferred.dispatch();
            });
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(early_attempts.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn terminal_retirement_suppresses_unpublished_cancel_trace() {
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        inner.write().runnable_publication = RunnablePublication::Unpublished;
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));

        let (newly_cancelled, immediate_effects) = record
            .request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE)
            .into_parts();
        assert!(newly_cancelled);
        immediate_effects.dispatch();
        assert!(
            inner.read().pending_task_cancel_trace.is_some(),
            "unpublished cancellation retains one bounded trace receipt"
        );

        let retired_wakers = {
            let mut guard = inner.write();
            let retired_wakers = guard.take_cancel_wakers();
            assert!(
                guard.pending_task_cancel_trace.is_none(),
                "terminal retirement suppresses a receipt with no physical lane"
            );
            retired_wakers
        };
        drop(retired_wakers);
    }

    fn scrub_task_record_ids(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(task_id) = scrubbed.pointer_mut("/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        if let Some(region_id) = scrubbed.pointer_mut("/region_id") {
            *region_id = json!("[REGION_ID]");
        }

        if let Some(origin_region) = scrubbed.pointer_mut("/reason/origin_region") {
            *origin_region = json!("[REGION_ID]");
        }

        if let Some(origin_task) = scrubbed.pointer_mut("/reason/origin_task") {
            *origin_task = json!("[TASK_ID]");
        }

        scrubbed
    }

    #[test]
    fn task_phase_transitions_are_atomic() {
        init_test("task_phase_transitions_are_atomic");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        crate::assert_with_log!(
            t.phase() == TaskPhase::Created,
            "phase created",
            TaskPhase::Created,
            t.phase()
        );

        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Running,
            "phase running",
            TaskPhase::Running,
            t.phase()
        );

        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        crate::assert_with_log!(
            t.phase() == TaskPhase::CancelRequested,
            "phase cancel requested",
            TaskPhase::CancelRequested,
            t.phase()
        );

        let ack = t.acknowledge_cancel();
        crate::assert_with_log!(ack.is_some(), "acknowledge_cancel", true, ack.is_some());
        crate::assert_with_log!(
            t.phase() == TaskPhase::Cancelling,
            "phase cancelling",
            TaskPhase::Cancelling,
            t.phase()
        );

        let cleaned = t.cleanup_done();
        crate::assert_with_log!(cleaned, "cleanup_done", true, cleaned);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Finalizing,
            "phase finalizing",
            TaskPhase::Finalizing,
            t.phase()
        );

        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Completed,
            "phase completed",
            TaskPhase::Completed,
            t.phase()
        );

        crate::test_complete!("task_phase_transitions_are_atomic");
    }

    #[test]
    fn wake_state_dedups_across_threads() {
        init_test("wake_state_dedups_across_threads");
        let state = Arc::new(TaskWakeState::new());
        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let state = Arc::clone(&state);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if state.notify() {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }

        let count = successes.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "single notify wins", 1usize, count);
        let notified = state.is_notified();
        crate::assert_with_log!(notified, "notified true", true, notified);
        state.clear();
        let cleared = state.is_notified();
        crate::assert_with_log!(!cleared, "notified cleared", false, cleared);
        crate::test_complete!("wake_state_dedups_across_threads");
    }

    #[test]
    fn wake_state_tracks_wake_during_poll() {
        init_test("wake_state_tracks_wake_during_poll");
        let state = TaskWakeState::new();

        state.begin_poll();
        let woken = state.finish_poll();
        crate::assert_with_log!(!woken, "no wake during poll", false, woken);

        state.begin_poll();
        let scheduled = state.notify();
        crate::assert_with_log!(
            !scheduled,
            "wake during poll does not schedule",
            false,
            scheduled
        );
        let woken = state.finish_poll();
        crate::assert_with_log!(woken, "wake observed after poll", true, woken);
        let pending = state.is_notified();
        crate::assert_with_log!(pending, "pending wake recorded", true, pending);
        state.clear();
        let cleared = state.is_notified();
        crate::assert_with_log!(!cleared, "wake cleared", false, cleared);
        crate::test_complete!("wake_state_tracks_wake_during_poll");
    }

    #[test]
    fn cancel_before_first_poll_enters_cancel_requested() {
        init_test("cancel_before_first_poll_enters_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        match &t.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget: _,
            } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_before_first_poll_enters_cancel_requested");
    }

    #[test]
    fn cancel_strengthens_idempotently_when_already_cancel_requested() {
        init_test("cancel_strengthens_idempotently_when_already_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let first = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(first, "first cancel", true, first);
        let second = request_cancel(&mut t, CancelReason::shutdown());
        crate::assert_with_log!(!second, "second cancel false", false, second);
        match &t.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Shutdown,
                    "reason kind",
                    crate::types::CancelKind::Shutdown,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_strengthens_idempotently_when_already_cancel_requested");
    }

    #[test]
    fn completed_is_absorbing() {
        init_test("completed_is_absorbing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(!requested, "request_cancel false", false, requested);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(outcome) => {
                let ok = matches!(outcome, Outcome::Ok(()));
                crate::assert_with_log!(ok, "outcome ok", true, ok);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        crate::test_complete!("completed_is_absorbing");
    }

    #[test]
    fn can_be_polled_matches_state() {
        init_test("can_be_polled_matches_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(!can_poll, "not pollable", false, can_poll);
        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable", true, can_poll);

        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel_with_budget(&mut t, CancelReason::timeout(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable after cancel", true, can_poll);
        crate::test_complete!("can_be_polled_matches_state");
    }

    #[test]
    fn complete_with_error_outcome() {
        init_test("complete_with_error_outcome");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let err = Error::new(ErrorKind::User);
        let completed = t.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        crate::test_complete!("complete_with_error_outcome");
    }

    #[test]
    fn complete_cancelled_without_prior_request_still_emits_witness() {
        init_test("complete_cancelled_without_prior_request_still_emits_witness");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.start_running();

        let completed = t.complete(Outcome::Cancelled(CancelReason::timeout()));
        crate::assert_with_log!(completed, "complete cancelled", true, completed);

        let witness = t.cancel_witness().expect("completed cancel witness");
        crate::assert_with_log!(witness.epoch == 1, "epoch initialized", 1, witness.epoch);
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        CancelWitness::validate_transition(None, &witness)
            .expect("terminal cancelled witness is self-consistent");

        crate::test_complete!("complete_cancelled_without_prior_request_still_emits_witness");
    }

    #[test]
    fn complete_ok_after_cancel_request_becomes_cancelled() {
        init_test("complete_ok_after_cancel_request_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason preserved",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t
            .cancel_witness()
            .expect("cancel witness after coerced completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_after_cancel_request_becomes_cancelled");
    }

    #[test]
    fn complete_err_after_cancel_request_becomes_cancelled() {
        init_test("complete_err_after_cancel_request_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        let err = Error::new(ErrorKind::User);
        let completed = t.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason preserved",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t
            .cancel_witness()
            .expect("cancel witness after coerced completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_err_after_cancel_request_becomes_cancelled");
    }

    #[test]
    fn complete_ok_during_cancellation_cleanup_becomes_cancelled() {
        init_test("complete_ok_during_cancellation_cleanup_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "completed cancelled", true, cancelled);

        let witness = t
            .cancel_witness()
            .expect("cancel witness during cleanup completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_during_cancellation_cleanup_becomes_cancelled");
    }

    #[test]
    fn complete_cancelled_during_protocol_does_not_weaken_reason() {
        init_test("complete_cancelled_during_protocol_does_not_weaken_reason");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());

        let completed = t.complete(Outcome::Cancelled(CancelReason::user("soft")));
        crate::assert_with_log!(completed, "complete cancelled", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason stayed strongest",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t.cancel_witness().expect("cancel witness after completion");
        crate::assert_with_log!(
            witness.reason.kind == crate::types::CancelKind::Timeout,
            "witness reason stayed strongest",
            crate::types::CancelKind::Timeout,
            witness.reason.kind
        );

        crate::test_complete!("complete_cancelled_during_protocol_does_not_weaken_reason");
    }

    #[test]
    fn complete_ok_during_finalization_becomes_cancelled() {
        init_test("complete_ok_during_finalization_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "completed cancelled", true, cancelled);

        let witness = t
            .cancel_witness()
            .expect("cancel witness during finalization completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_during_finalization_becomes_cancelled");
    }

    #[test]
    fn acknowledge_cancel_transitions_to_cancelling() {
        init_test("acknowledge_cancel_transitions_to_cancelling");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());

        let reason = t.acknowledge_cancel();
        let has_reason = reason.is_some();
        crate::assert_with_log!(has_reason, "reason present", true, has_reason);
        let kind = reason.unwrap().kind;
        crate::assert_with_log!(
            kind == crate::types::CancelKind::Timeout,
            "reason kind",
            crate::types::CancelKind::Timeout,
            kind
        );
        let cancelling = matches!(
            t.state,
            TaskState::Cancelling {
                reason: CancelReason {
                    kind: crate::types::CancelKind::Timeout,
                    ..
                },
                ..
            }
        );
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        crate::test_complete!("acknowledge_cancel_transitions_to_cancelling");
    }

    #[test]
    fn acknowledge_cancel_fails_for_wrong_state() {
        init_test("acknowledge_cancel_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in created", true, none);

        // Move to Running
        t.start_running();
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in running", true, none);
        crate::test_complete!("acknowledge_cancel_fails_for_wrong_state");
    }

    #[test]
    fn cleanup_done_transitions_to_finalizing() {
        init_test("cleanup_done_transitions_to_finalizing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        crate::test_complete!("cleanup_done_transitions_to_finalizing");
    }

    #[test]
    fn cleanup_done_fails_for_wrong_state() {
        init_test("cleanup_done_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);

        let _ = request_cancel(&mut t, CancelReason::timeout());
        // Still in CancelRequested, not Cancelling
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);
        crate::test_complete!("cleanup_done_fails_for_wrong_state");
    }

    #[test]
    fn finalize_done_transitions_to_completed_cancelled() {
        init_test("finalize_done_transitions_to_completed_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }
        crate::test_complete!("finalize_done_transitions_to_completed_cancelled");
    }

    #[test]
    fn full_cancellation_protocol_flow() {
        init_test("full_cancellation_protocol_flow");
        // Complete flow: Created → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);

        // Step 1: Request cancellation
        let requested = request_cancel(&mut t, CancelReason::user("stop"));
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        let cancelling = t.state.is_cancelling();
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 2: Acknowledge cancellation (checkpoint with mask=0)
        let reason = t.acknowledge_cancel().expect("should acknowledge");
        crate::assert_with_log!(
            reason.kind == crate::types::CancelKind::User,
            "reason kind",
            crate::types::CancelKind::User,
            reason.kind
        );
        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 3: Cleanup completes
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);

        // Step 4: Finalizers complete
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);
        crate::test_complete!("full_cancellation_protocol_flow");
    }

    #[test]
    fn cancellation_witness_sequence_is_monotone() {
        init_test("cancellation_witness_sequence_is_monotone");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();

        let _ = request_cancel(&mut t, CancelReason::timeout());
        let w1 = t.cancel_witness().expect("requested witness");

        let _ = t.acknowledge_cancel();
        let w2 = t.cancel_witness().expect("cancelling witness");
        CancelWitness::validate_transition(Some(&w1), &w2).expect("requested -> cancelling");

        let _ = t.cleanup_done();
        let w3 = t.cancel_witness().expect("finalizing witness");
        CancelWitness::validate_transition(Some(&w2), &w3).expect("cancelling -> finalizing");

        let w4 = t.finalize_done_with_witness().expect("completed witness");
        CancelWitness::validate_transition(Some(&w3), &w4).expect("finalizing -> completed");

        crate::test_complete!("cancellation_witness_sequence_is_monotone");
    }

    #[test]
    fn cancellation_witness_idempotent_requests() {
        init_test("cancellation_witness_idempotent_requests");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();

        let _ = request_cancel(&mut t, CancelReason::timeout());
        let w1 = t.cancel_witness().expect("first witness");

        let _ = request_cancel(&mut t, CancelReason::shutdown());
        let w2 = t.cancel_witness().expect("second witness");

        crate::assert_with_log!(w1.epoch == w2.epoch, "epoch stable", w1.epoch, w2.epoch);
        CancelWitness::validate_transition(Some(&w1), &w2).expect("idempotent request transition");

        crate::test_complete!("cancellation_witness_idempotent_requests");
    }

    #[test]
    fn cancellation_witness_rejects_out_of_order() {
        init_test("cancellation_witness_rejects_out_of_order");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let requested = t.cancel_witness().expect("requested witness");
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();
        let completed = t.finalize_done_with_witness().expect("completed witness");

        let err = CancelWitness::validate_transition(Some(&completed), &requested).err();
        crate::assert_with_log!(err.is_some(), "out of order rejected", true, err.is_some());

        crate::test_complete!("cancellation_witness_rejects_out_of_order");
    }

    #[test]
    fn masking_operations() {
        init_test("masking_operations");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        // Need to set inner for mask operations to work
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner);

        let mask1 = t.increment_mask();
        crate::assert_with_log!(mask1 == 1, "mask 1", 1, mask1);
        let mask2 = t.increment_mask();
        crate::assert_with_log!(mask2 == 2, "mask 2", 2, mask2);

        let dec1 = t.decrement_mask();
        crate::assert_with_log!(dec1 == Some(1), "dec 1", Some(1), dec1);
        let dec0 = t.decrement_mask();
        crate::assert_with_log!(dec0 == Some(0), "dec 0", Some(0), dec0);

        // Can't go below zero
        let dec_none = t.decrement_mask();
        crate::assert_with_log!(dec_none.is_none(), "dec none", true, dec_none.is_none());
        crate::test_complete!("masking_operations");
    }

    #[test]
    fn cleanup_budget_accessor() {
        init_test("cleanup_budget_accessor");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.cleanup_budget().is_none();
        crate::assert_with_log!(none, "no budget", true, none);

        let _ = request_cancel_with_budget(
            &mut t,
            CancelReason::timeout(),
            Budget::new().with_poll_quota(500),
        );
        let budget = t.cleanup_budget().expect("should have cleanup budget");
        crate::assert_with_log!(
            budget.poll_quota == 500,
            "poll_quota",
            500,
            budget.poll_quota
        );
        crate::test_complete!("cleanup_budget_accessor");
    }

    #[test]
    fn request_cancel_updates_shared_cx() {
        init_test("request_cancel_updates_shared_cx");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner.clone());

        let cancel_requested = inner.read().cancel_requested;
        crate::assert_with_log!(
            !cancel_requested,
            "cancel_requested false",
            false,
            cancel_requested
        );
        let cancel_reason_none = inner.read().cancel_reason.is_none();
        crate::assert_with_log!(
            cancel_reason_none,
            "cancel_reason none",
            true,
            cancel_reason_none
        );

        let _ = request_cancel(&mut t, CancelReason::timeout());

        let cancel_requested = inner.read().cancel_requested;
        crate::assert_with_log!(
            cancel_requested,
            "cancel_requested true",
            true,
            cancel_requested
        );
        let cancel_reason = inner.read().cancel_reason.clone();
        crate::assert_with_log!(
            cancel_reason == Some(CancelReason::timeout()),
            "cancel_reason",
            Some(CancelReason::timeout()),
            cancel_reason
        );
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        crate::test_complete!("request_cancel_updates_shared_cx");
    }

    #[test]
    fn direct_cx_wake_is_not_republished_by_checkpoint_materialization() {
        init_test("direct_cx_wake_is_not_republished_by_checkpoint_materialization");

        struct CountWake(Arc<AtomicUsize>);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        let cx: crate::cx::Cx<crate::cx::cap::All> =
            crate::cx::Cx::from_inner(Arc::clone(&inner));
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        record.start_running();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        inner.write().cancel_waker = Some(Arc::new(CancelWaker::new(waker)));

        cx.cancel_fast(crate::types::CancelKind::RaceLost);
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(!inner.read().cancel_wakers_pending);

        assert!(cx.checkpoint().is_err());
        let (receipt, wakes) = record.consume_checkpoint_cancel_ack().into_parts();
        assert!(
            receipt.is_some(),
            "checkpoint must materialize TaskRecord cancellation"
        );
        assert!(
            wakes.is_empty(),
            "direct Cx producer already paid the wake debt"
        );
        wakes.dispatch();

        assert!(matches!(record.state, TaskState::Cancelling { .. }));
        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "checkpoint reconciliation must not dispatch the same Waker twice"
        );
        crate::test_complete!("direct_cx_wake_is_not_republished_by_checkpoint_materialization");
    }

    #[test]
    fn delegated_publication_promotes_stronger_cx_reason_before_wakers() {
        init_test("delegated_publication_promotes_stronger_cx_reason_before_wakers");

        struct CountWake(Arc<AtomicUsize>);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        {
            let mut guard = inner.write();
            guard.runnable_publication = RunnablePublication::Unpublished;
            guard.runnable_publication.delegate_cancel();
        }
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));

        let lower = CancelReason::user("delegated lower priority");
        let lower_priority = lower.cleanup_budget().priority;
        let (update, lower_wakes) = record.request_cancel_for_handle(&lower).into_parts();
        assert_eq!(
            update.route,
            Some(HandleCancelRoute {
                priority: lower_priority,
                delegated_initial: true,
            })
        );
        assert!(lower_wakes.is_empty());
        lower_wakes.dispatch();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        let stronger = CancelReason::shutdown();
        let stronger_priority = stronger.cleanup_budget().priority;
        {
            let mut guard = inner.write();
            guard
                .cancel_reason
                .as_mut()
                .expect("lower reason installed")
                .strengthen(&stronger);
            guard.cancel_wakers_pending = true;
            guard.cancel_waker = Some(Arc::new(CancelWaker::new(waker)));
        }

        let lane_published = AtomicBool::new(false);
        let (published, wakes) = record
            .publish_delegated_cancel_lane(|priority, is_local, pinned_worker| {
                assert_eq!(priority, stronger_priority);
                assert!(!is_local);
                assert_eq!(pinned_worker, None);
                lane_published.store(true, Ordering::SeqCst);
                Some(priority)
            })
            .into_parts();
        assert_eq!(published, Some(stronger_priority));
        assert!(lane_published.load(Ordering::SeqCst));
        assert!(!wakes.is_empty());
        assert!(inner.read().runnable_publication.is_published());
        assert!(!inner.read().cancel_wakers_pending);
        assert!(matches!(
            &record.state,
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            } if reason.is_kind(crate::types::cancel::CancelKind::Shutdown)
                && cleanup_budget.priority == stronger_priority
        ));
        wakes.dispatch();
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let (repeat, repeat_wakes) = record
            .publish_delegated_cancel_lane(|_, _, _| -> Option<u8> {
                panic!("an already-published command must not insert another lane")
            })
            .into_parts();
        assert_eq!(repeat, None);
        assert!(repeat_wakes.is_empty());
        repeat_wakes.dispatch();
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        crate::test_complete!("delegated_publication_promotes_stronger_cx_reason_before_wakers");
    }

    #[test]
    fn failed_delegated_publication_retires_snapshot_after_outer_lock() {
        struct DropProbe {
            outer_lock: Arc<parking_lot::Mutex<()>>,
            drops: Arc<AtomicUsize>,
            drops_under_outer_lock: Arc<AtomicUsize>,
        }

        impl std::task::Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                if self.outer_lock.try_lock().is_none() {
                    self.drops_under_outer_lock.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let outer_lock = Arc::new(parking_lot::Mutex::new(()));
        let drops = Arc::new(AtomicUsize::new(0));
        let drops_under_outer_lock = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        {
            let mut guard = inner.write();
            guard.runnable_publication = RunnablePublication::Unpublished;
            guard.runnable_publication.delegate_cancel();
            guard.cancel_waker = Some(Arc::new(CancelWaker::new(std::task::Waker::from(
                Arc::new(DropProbe {
                    outer_lock: Arc::clone(&outer_lock),
                    drops: Arc::clone(&drops),
                    drops_under_outer_lock: Arc::clone(&drops_under_outer_lock),
                }),
            ))));
        }
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        let (_, request_wakes) = record
            .request_cancel_for_handle(&CancelReason::shutdown())
            .into_parts();
        request_wakes.dispatch();

        let outer_guard = outer_lock.lock();
        let (publication, retirement) = record
            .publish_delegated_cancel_lane(|_, _, _| None::<u8>)
            .into_parts();
        assert_eq!(publication, None);
        assert_eq!(retirement.len(), 1);
        let registry_owner = inner.write().cancel_waker.take();
        drop(registry_owner);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the failed attempt must not retire its snapshot under the outer lock"
        );

        drop(outer_guard);
        retirement.retire_without_dispatch();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            drops_under_outer_lock.load(Ordering::SeqCst),
            0,
            "the final RawWaker destructor runs only after the outer lock is gone"
        );
    }

    #[test]
    fn task_record_cancel_witness_snapshot_scrubs_ids() {
        init_test("task_record_cancel_witness_snapshot_scrubs_ids");
        let mut record = TaskRecord::new(
            TaskId::new_for_test(4, 2),
            RegionId::new_for_test(8, 1),
            Budget::new().with_poll_quota(5),
        );
        let requested = request_cancel(
            &mut record,
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(77, 6))
                .with_task(TaskId::new_for_test(11, 5))
                .with_timestamp(Time::from_nanos(44))
                .with_message("peer closed"),
        );
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        insta::assert_json_snapshot!(
            "task_record_cancel_witness_scrubbed_ids",
            scrub_task_record_ids(
                serde_json::to_value(record.cancel_witness().expect("cancel witness"))
                    .expect("serialize witness")
            )
        );
        crate::test_complete!("task_record_cancel_witness_snapshot_scrubs_ids");
    }

    /// Enhanced scrubbing function for TaskRecord snapshots that handles timing fields
    fn scrub_task_record_state(value: Value) -> Value {
        let mut scrubbed = scrub_task_record_ids(value);

        // Scrub timing fields that vary between test runs
        if let Some(created_at) = scrubbed.pointer_mut("/created_at") {
            *created_at = json!(0);
        }

        if let Some(created_instant) = scrubbed.pointer_mut("/created_instant") {
            *created_instant = json!("[INSTANT]");
        }

        if let Some(timestamp) = scrubbed.pointer_mut("/reason/timestamp") {
            *timestamp = json!("[TIMESTAMP]");
        }

        scrubbed
    }

    #[test]
    fn task_record_lifecycle_states_snapshot() {
        init_test("task_record_lifecycle_states_snapshot");

        // Test each major lifecycle phase with golden snapshots
        let task_id = TaskId::new_for_test(1, 0);
        let region_id = RegionId::new_for_test(2, 0);
        let budget = Budget::new().with_poll_quota(100_000);

        // Phase 1: Created state
        let record_created = TaskRecord::new(task_id, region_id, budget);
        insta::assert_json_snapshot!(
            "task_record_state_created",
            scrub_task_record_state(
                serde_json::to_value(&record_created)
                    .expect("should serialize created task record")
            )
        );

        // Phase 2: Running state
        let mut record_running = TaskRecord::new(task_id, region_id, budget);
        let started = record_running.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        insta::assert_json_snapshot!(
            "task_record_state_running",
            scrub_task_record_state(
                serde_json::to_value(&record_running)
                    .expect("should serialize running task record")
            )
        );

        // Phase 3: CancelRequested state with timeout reason
        let mut record_cancel_requested = TaskRecord::new(task_id, region_id, budget);
        let requested = request_cancel(
            &mut record_cancel_requested,
            CancelReason::timeout()
                .with_timestamp(Time::from_nanos(123456789))
                .with_message("operation timeout"),
        );
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        insta::assert_json_snapshot!(
            "task_record_state_cancel_requested",
            scrub_task_record_state(
                serde_json::to_value(&record_cancel_requested)
                    .expect("should serialize cancel_requested task record")
            )
        );

        // Phase 4: Cancelling state
        let mut record_cancelling = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(&mut record_cancelling, CancelReason::user("abort"));
        let ack = record_cancelling.acknowledge_cancel();
        crate::assert_with_log!(ack.is_some(), "acknowledge_cancel", true, ack.is_some());
        insta::assert_json_snapshot!(
            "task_record_state_cancelling",
            scrub_task_record_state(
                serde_json::to_value(&record_cancelling)
                    .expect("should serialize cancelling task record")
            )
        );

        // Phase 5: Finalizing state
        let mut record_finalizing = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(&mut record_finalizing, CancelReason::shutdown());
        let _ = record_finalizing.acknowledge_cancel();
        let cleaned = record_finalizing.cleanup_done();
        crate::assert_with_log!(cleaned, "cleanup_done", true, cleaned);
        insta::assert_json_snapshot!(
            "task_record_state_finalizing",
            scrub_task_record_state(
                serde_json::to_value(&record_finalizing).expect("serialize finalizing")
            )
        );

        // Phase 6: Completed(Ok) state
        let mut record_completed_ok = TaskRecord::new(task_id, region_id, budget);
        let completed = record_completed_ok.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        insta::assert_json_snapshot!(
            "task_record_state_completed_ok",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_ok).expect("serialize completed_ok")
            )
        );

        // Phase 7: Completed(Err) state
        let mut record_completed_err = TaskRecord::new(task_id, region_id, budget);
        let err = Error::new(ErrorKind::User);
        let completed = record_completed_err.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);
        insta::assert_json_snapshot!(
            "task_record_state_completed_err",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_err).expect("serialize completed_err")
            )
        );

        // Phase 8: Completed(Cancelled) state through full protocol
        let mut record_completed_cancelled = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(
            &mut record_completed_cancelled,
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(5, 1))
                .with_task(TaskId::new_for_test(7, 2)),
        );
        let _ = record_completed_cancelled.acknowledge_cancel();
        let _ = record_completed_cancelled.cleanup_done();
        let finalized = record_completed_cancelled.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        insta::assert_json_snapshot!(
            "task_record_state_completed_cancelled",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_cancelled)
                    .expect("serialize completed_cancelled")
            )
        );

        crate::test_complete!("task_record_lifecycle_states_snapshot");
    }

    #[test]
    fn task_record_cancel_reasons_snapshot() {
        init_test("task_record_cancel_reasons_snapshot");

        let task_id = TaskId::new_for_test(3, 1);
        let region_id = RegionId::new_for_test(4, 1);
        let budget = Budget::new().with_poll_quota(5);

        // Test different cancel reason types
        let cancel_reasons = vec![
            CancelReason::timeout()
                .with_timestamp(Time::from_nanos(100))
                .with_message("request timeout"),
            CancelReason::user("manual abort").with_timestamp(Time::from_nanos(200)),
            CancelReason::shutdown().with_message("graceful shutdown"),
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(10, 2))
                .with_task(TaskId::new_for_test(20, 3))
                .with_message("dependency failed"),
        ];

        for (i, reason) in cancel_reasons.into_iter().enumerate() {
            let mut record = TaskRecord::new(task_id, region_id, budget);
            let _ = request_cancel(&mut record, reason);

            let snapshot_name = format!("task_record_cancel_reason_{}", i);
            insta::assert_json_snapshot!(
                snapshot_name,
                scrub_task_record_state(
                    serde_json::to_value(&record).expect("serialize cancel reason")
                )
            );
        }

        crate::test_complete!("task_record_cancel_reasons_snapshot");
    }

    #[test]
    fn task_record_budget_variants_snapshot() {
        init_test("task_record_budget_variants_snapshot");

        let task_id = TaskId::new_for_test(6, 1);
        let region_id = RegionId::new_for_test(7, 1);

        // Test different budget configurations
        let budgets = vec![
            Budget::INFINITE,
            Budget::new().with_poll_quota(1),
            Budget::new().with_poll_quota(100),
            Budget::new().with_poll_quota(u32::MAX),
        ];

        for (i, budget) in budgets.into_iter().enumerate() {
            let record = TaskRecord::new(task_id, region_id, budget);

            let snapshot_name = format!("task_record_budget_{}", i);
            insta::assert_json_snapshot!(
                snapshot_name,
                scrub_task_record_state(serde_json::to_value(&record).expect("serialize budget"))
            );
        }

        crate::test_complete!("task_record_budget_variants_snapshot");
    }

    #[test]
    fn task_record_transition_sequence_snapshot() {
        init_test("task_record_transition_sequence_snapshot");

        // Test complete transition sequence with snapshots at each step
        let task_id = TaskId::new_for_test(9, 1);
        let region_id = RegionId::new_for_test(11, 1);
        let budget = Budget::new().with_poll_quota(100_000);

        let mut record = TaskRecord::new(task_id, region_id, budget);

        // Capture sequence: Created → Running → CancelRequested → Cancelling → Finalizing → Completed
        let mut sequence = Vec::new();

        // Step 1: Created
        sequence.push(("created", serde_json::to_value(&record).expect("serialize")));

        // Step 2: Running
        let _ = record.start_running();
        sequence.push(("running", serde_json::to_value(&record).expect("serialize")));

        // Step 3: CancelRequested
        let _ = request_cancel(
            &mut record,
            CancelReason::shutdown().with_message("shutdown initiated"),
        );
        sequence.push((
            "cancel_requested",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 4: Cancelling
        let _ = record.acknowledge_cancel();
        sequence.push((
            "cancelling",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 5: Finalizing
        let _ = record.cleanup_done();
        sequence.push((
            "finalizing",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 6: Completed
        let _ = record.finalize_done();
        sequence.push((
            "completed",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Create snapshot for complete sequence
        let scrubbed_sequence: Vec<_> = sequence
            .into_iter()
            .map(|(phase, value)| (phase, scrub_task_record_state(value)))
            .collect();

        insta::assert_json_snapshot!("task_record_transition_sequence", scrubbed_sequence);

        crate::test_complete!("task_record_transition_sequence_snapshot");
    }

    // =================================================================
    // TaskPhase transition table validation (bd-2qqyi)
    // =================================================================

    use TaskPhase::*;

    #[test]
    fn valid_transitions_accepted() {
        init_test("valid_transitions_accepted");
        let valid = [
            (Created, Running),
            (Created, CancelRequested),
            (Created, Completed), // err/panic at spawn
            (Running, CancelRequested),
            (Running, Completed),
            (CancelRequested, CancelRequested), // strengthen
            (CancelRequested, Cancelling),
            (CancelRequested, Completed), // err/panic before ack
            (Cancelling, Cancelling),     // strengthen
            (Cancelling, Finalizing),
            (Cancelling, Completed),  // err/panic during cleanup
            (Finalizing, Finalizing), // strengthen
            (Finalizing, Completed),
        ];

        for (from, to) in valid {
            crate::assert_with_log!(
                from.is_valid_transition(to),
                "transition should be valid",
                true,
                (from, to)
            );
        }
        crate::test_complete!("valid_transitions_accepted");
    }

    #[test]
    fn invalid_transitions_rejected() {
        init_test("invalid_transitions_rejected");
        let invalid = [
            // Backwards transitions
            (Running, Created),
            (CancelRequested, Running),
            (CancelRequested, Created),
            (Cancelling, CancelRequested),
            (Cancelling, Running),
            (Cancelling, Created),
            (Finalizing, Cancelling),
            (Finalizing, CancelRequested),
            (Finalizing, Running),
            (Finalizing, Created),
            // Skipped states
            (Created, Cancelling),
            (Created, Finalizing),
            (Running, Cancelling),
            (Running, Finalizing),
            (CancelRequested, Finalizing),
            // Terminal: no transitions out
            (Completed, Created),
            (Completed, Running),
            (Completed, CancelRequested),
            (Completed, Cancelling),
            (Completed, Finalizing),
            (Completed, Completed),
        ];

        for (from, to) in invalid {
            crate::assert_with_log!(
                !from.is_valid_transition(to),
                "transition should be invalid",
                false,
                (from, to)
            );
        }
        crate::test_complete!("invalid_transitions_rejected");
    }

    #[test]
    fn transition_table_is_exhaustive() {
        init_test("transition_table_is_exhaustive");
        let phases = [
            Created,
            Running,
            CancelRequested,
            Cancelling,
            Finalizing,
            Completed,
        ];

        // Every (from, to) pair should be either valid or invalid — never panic
        let mut valid_count = 0;
        let mut invalid_count = 0;
        for from in phases {
            for to in phases {
                if from.is_valid_transition(to) {
                    valid_count += 1;
                } else {
                    invalid_count += 1;
                }
            }
        }
        // 6x6 = 36 total pairs; 13 valid (see valid_transitions_accepted)
        crate::assert_with_log!(
            valid_count == 13,
            "valid transitions count",
            13,
            valid_count
        );
        crate::assert_with_log!(
            invalid_count == 23,
            "invalid transitions count",
            23,
            invalid_count
        );
        crate::test_complete!("transition_table_is_exhaustive");
    }

    // Proptest support for TaskPhase
    #[cfg(feature = "test-internals")]
    mod proptest_support {
        use super::TaskPhase;
        use proptest::prelude::*;

        impl Arbitrary for TaskPhase {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                prop_oneof![
                    Just(TaskPhase::Created),
                    Just(TaskPhase::Running),
                    Just(TaskPhase::CancelRequested),
                    Just(TaskPhase::Cancelling),
                    Just(TaskPhase::Finalizing),
                    Just(TaskPhase::Completed),
                ]
                .boxed()
            }
        }
    }
}
