//! Task inspection and debugging for runtime diagnostics.
//!
//! This module provides task-state inspection for runtime diagnostics,
//! including checkpoint-based idle-time heuristics, wake-pending state,
//! obligation ownership, and deterministic wire snapshots.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::observability::{TaskInspector, TaskInspectorConfig};
//! use std::time::Duration;
//!
//! let inspector = TaskInspector::new(state.clone(), console);
//! let summary = inspector.summary();
//! println!("Total tasks: {}, Running: {}", summary.total_tasks, summary.running);
//!
//! // Find stuck tasks (not polled recently)
//! let stuck = inspector.find_stuck_tasks(Duration::from_secs(30));
//! for task in &stuck {
//!     println!("Stuck: {:?}", task.id);
//! }
//! ```

use crate::console::Console;
use crate::cx::Cx;
use crate::record::task::{TaskPhase, TaskRecord, TaskState};
use crate::record::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState, RegionRecord,
};
use crate::runtime::obligation_table::ObligationTable;
use crate::runtime::state::{LoserDrainHistoryEvent, RuntimeState};
use crate::runtime::task_table::TaskTable;
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{debug, info, trace, warn};
use crate::types::{Budget, ObligationId, Outcome, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

/// Where an inspector or diagnostics engine reads runtime state from.
///
/// `Owned` is the historical detached form: [`TaskInspector::new`] and
/// [`Diagnostics::new`](crate::observability::Diagnostics::new) hand over an
/// `Arc<RuntimeState>` that nothing else mutates concurrently.
///
/// `Shared` binds to a live [`Runtime`](crate::runtime::Runtime). Every
/// query locks the unified runtime state for its own duration and, when the
/// runtime keeps task records in the scheduler's external dispatch table
/// and/or obligation records in a shard-C table, those tables too, in the
/// canonical B -> A -> C lock order (the same order `spawn`,
/// `cancel_request`, and `Runtime::is_quiescent` use from user threads).
/// Queries copy plain data out and never run user code or await while
/// holding those locks, so they are safe to issue from any thread, including
/// from inside a task running on the same runtime.
#[derive(Debug)]
pub(crate) enum RuntimeStateSource {
    /// Caller-owned, detached state.
    Owned(Arc<RuntimeState>),
    /// A live runtime's shared state, locked per query.
    Shared {
        /// Unified runtime state (lock class B).
        state: Arc<ContendedMutex<RuntimeState>>,
        /// The scheduler's external dispatch task table (lock class A) when
        /// the runtime keeps live task records outside the unified arena
        /// (E1.2 dispatch-table runtimes and the sharded state shape, whose
        /// shard A is this same table). `None` when task records live in the
        /// unified state.
        tasks: Option<Arc<ContendedMutex<TaskTable>>>,
        /// Shard-C obligation table when the runtime was built with the
        /// sharded state shape. `None` on the default unified shape.
        obligations: Option<Arc<ContendedMutex<ObligationTable>>>,
    },
}

/// Borrowed read view over runtime state that resolves each record kind to
/// the table owning it (embedded arena, or external shard when present).
pub(crate) struct RuntimeStateView<'a> {
    state: &'a RuntimeState,
    shard_tasks: Option<&'a TaskTable>,
    shard_obligations: Option<&'a ObligationTable>,
}

impl<'a> RuntimeStateView<'a> {
    /// Task record by id: external shard-A table first, then the embedded arena.
    pub(crate) fn task(&self, task_id: TaskId) -> Option<&'a TaskRecord> {
        let state: &'a RuntimeState = self.state;
        self.shard_tasks
            .and_then(|table| table.task(task_id))
            .or_else(|| state.task(task_id))
    }

    /// Every task record: the external shard-A table (when present), then
    /// the embedded arena.
    pub(crate) fn tasks(&self) -> impl Iterator<Item = &'a TaskRecord> + 'a {
        let state: &'a RuntimeState = self.state;
        let external = self.shard_tasks.map(|table| table.tasks_arena().iter());
        external
            .into_iter()
            .flatten()
            .chain(state.tasks_arena().iter())
            .map(|(_, record)| record)
    }

    /// Region record by id (regions stay embedded in the unified state on
    /// every shape).
    pub(crate) fn region(&self, region_id: RegionId) -> Option<&'a RegionRecord> {
        let state: &'a RuntimeState = self.state;
        state.region(region_id)
    }

    /// Every region record (regions stay embedded in the unified state on
    /// every shape).
    pub(crate) fn regions(&self) -> impl Iterator<Item = &'a RegionRecord> + 'a {
        let state: &'a RuntimeState = self.state;
        state.regions.iter().map(|(_, record)| record)
    }

    /// Every obligation record: the external shard-C table (when present),
    /// then the embedded table.
    pub(crate) fn obligations(&self) -> impl Iterator<Item = &'a ObligationRecord> + 'a {
        let state: &'a RuntimeState = self.state;
        let external = self.shard_obligations.map(ObligationTable::iter);
        external
            .into_iter()
            .flatten()
            .chain(state.obligations.iter())
            .map(|(_, record)| record)
    }

    /// Sorted ids of pending obligations held by `task_id` across the
    /// owning table(s).
    pub(crate) fn pending_obligations_for_holder(&self, task_id: TaskId) -> Vec<ObligationId> {
        let mut ids: Vec<ObligationId> = self
            .state
            .obligations
            .sorted_pending_ids_for_holder(task_id)
            .into_iter()
            .collect();
        if let Some(table) = self.shard_obligations {
            ids.extend(table.sorted_pending_ids_for_holder(task_id));
            ids.sort_unstable();
            ids.dedup();
        }
        ids
    }

    /// Loser-drain race history. A native runtime keeps every in-flight race
    /// and only its most recently completed ones.
    pub(crate) fn loser_drain_history(&self) -> Vec<LoserDrainHistoryEvent> {
        self.state.loser_drain_history()
    }

    /// Current runtime time for observability.
    ///
    /// Live runtimes advance time through the timer driver, while timerless
    /// runtimes and many direct tests only move `RuntimeState::now`. Prefer
    /// the timer driver when present and fall back to the logical state
    /// clock so ages remain meaningful in both modes.
    pub(crate) fn now(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(self.state.now, TimerDriverHandle::now)
    }
}

impl RuntimeStateSource {
    /// Runs `f` against a consistent read view of the state.
    ///
    /// For `Shared` sources this holds the unified state lock (and the shard
    /// A/C table locks on the sharded shape) for exactly the duration of `f`;
    /// `f` must therefore stay a pure read that copies data out — never a
    /// callback into user code, a tracing emit, or an await.
    pub(crate) fn with_view<R>(&self, f: impl FnOnce(&RuntimeStateView<'_>) -> R) -> R {
        match self {
            Self::Owned(state) => f(&RuntimeStateView {
                state: state.as_ref(),
                shard_tasks: None,
                shard_obligations: None,
            }),
            Self::Shared {
                state,
                tasks,
                obligations,
            } => {
                // Lock order B (unified state) -> A (dispatch/shard tasks) ->
                // C (shard obligations); locals drop in reverse declaration
                // order, so C and A release before B.
                let state = state.lock().unwrap_or_else(PoisonError::into_inner);
                let tasks = tasks
                    .as_ref()
                    .map(|table| table.lock().unwrap_or_else(PoisonError::into_inner));
                let obligations = obligations
                    .as_ref()
                    .map(|table| table.lock().unwrap_or_else(PoisonError::into_inner));
                f(&RuntimeStateView {
                    state: &state,
                    shard_tasks: tasks.as_deref(),
                    shard_obligations: obligations.as_deref(),
                })
            }
        }
    }
}

/// Configuration for the task inspector.
#[derive(Debug, Clone)]
pub struct TaskInspectorConfig {
    /// Age threshold for stuck task warnings (default: 30s).
    pub stuck_task_threshold: Duration,
    /// Whether to include obligations in task details.
    pub show_obligations: bool,
    /// Whether to highlight stuck tasks in output.
    pub highlight_stuck_tasks: bool,
}

impl Default for TaskInspectorConfig {
    fn default() -> Self {
        Self {
            stuck_task_threshold: Duration::from_secs(30),
            show_obligations: true,
            highlight_stuck_tasks: true,
        }
    }
}

impl TaskInspectorConfig {
    /// Create a new configuration with the specified stuck threshold.
    #[must_use]
    pub fn with_stuck_threshold(mut self, threshold: Duration) -> Self {
        self.stuck_task_threshold = threshold;
        self
    }

    /// Enable or disable obligation display.
    #[must_use]
    pub fn with_show_obligations(mut self, show: bool) -> Self {
        self.show_obligations = show;
        self
    }

    /// Enable or disable stuck task highlighting.
    #[must_use]
    pub fn with_highlight_stuck_tasks(mut self, highlight: bool) -> Self {
        self.highlight_stuck_tasks = highlight;
        self
    }
}

/// Detailed information about a task's current state.
#[derive(Debug, Clone)]
pub struct TaskDetails {
    /// Task identifier.
    pub id: TaskId,
    /// Owning region.
    pub region_id: RegionId,
    /// Current lifecycle state.
    pub state: TaskStateInfo,
    /// Atomic phase (cross-thread safe snapshot).
    pub phase: TaskPhase,
    /// Total number of polls executed.
    pub poll_count: u64,
    /// Polls remaining in budget.
    pub polls_remaining: u32,
    /// Logical time when created.
    pub created_at: Time,
    /// Time since creation.
    pub age: Duration,
    /// Time since the last explicit progress checkpoint / idle-time sample.
    pub time_since_last_poll: Option<Duration>,
    /// Whether a wake is pending.
    pub wake_pending: bool,
    /// Pending obligations still held by this task.
    pub obligations: Vec<ObligationId>,
    /// Tasks waiting for this one to complete.
    pub waiters: Vec<TaskId>,
}

impl TaskDetails {
    /// Returns true if the task is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, TaskStateInfo::Completed { .. })
    }

    /// Returns true if the task is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(self.state, TaskStateInfo::Running)
    }

    /// Returns true if the task is being cancelled.
    #[must_use]
    pub fn is_cancelling(&self) -> bool {
        matches!(
            self.state,
            TaskStateInfo::CancelRequested { .. }
                | TaskStateInfo::Cancelling { .. }
                | TaskStateInfo::Finalizing { .. }
        )
    }

    /// Returns true if the task matches the inspector's stuck-task heuristic.
    ///
    /// Prefer explicit idle-time metadata when it is available. Today the
    /// inspector derives this from task progress checkpoints. When no explicit
    /// idle-time sample exists yet, only classify old tasks that have never
    /// been polled as potentially stuck so long-lived waiting tasks are not
    /// misreported just because they are old.
    ///
    /// A pending wake does NOT short-circuit the staleness check. Treating
    /// `wake_pending` as an automatic "not stuck" blinded the detector exactly
    /// when the scheduler is the wedged component: a task can sit with a wake
    /// queued indefinitely if the executor never re-polls it, and that is
    /// precisely the situation this heuristic exists to surface. A wake that was
    /// delivered but not serviced within `age_threshold` is therefore still
    /// flagged.
    #[must_use]
    pub fn is_potentially_stuck(&self, age_threshold: Duration) -> bool {
        if self.is_terminal() {
            return false;
        }

        self.time_since_last_poll.map_or_else(
            || self.age > age_threshold && self.poll_count == 0,
            |idle_for| idle_for > age_threshold,
        )
    }
}

/// Simplified task state for inspection (matches TaskState but serializable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStateInfo {
    /// Initial state after spawn.
    Created,
    /// Actively being polled.
    Running,
    /// Cancel requested but not acknowledged.
    CancelRequested {
        /// Reason for cancellation.
        reason: String,
    },
    /// Task running cleanup code.
    Cancelling {
        /// Reason for cancellation.
        reason: String,
    },
    /// Task running finalizers.
    Finalizing {
        /// Reason for cancellation.
        reason: String,
    },
    /// Terminal state.
    Completed {
        /// Outcome kind.
        outcome: String,
    },
}

/// Stable schema identifier for task-inspector wire snapshots.
pub const TASK_CONSOLE_WIRE_SCHEMA_V1: &str = "asupersync.task_console_wire.v1";

/// Stable schema identifier for the combined runtime-inspector snapshot.
pub const INSPECTOR_SNAPSHOT_SCHEMA_V1: &str = "asupersync.inspector_snapshot.v1";

/// Controls whether a runtime snapshot includes free-form diagnostic text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InspectorProfile {
    /// Include obligation descriptions, acquisition locations, and checkpoint messages.
    Full,
    /// Remove those fields while preserving identities, topology, and counters.
    Shareable,
}

/// The sources and limits of a snapshot, rather than inferred runtime telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorCoverage {
    /// The runtime's record-table locks were held together during collection.
    /// False for a caller-borrowed or detached `RuntimeState`.
    pub record_tables_locked: bool,
    /// Phase/wake atomics, context data, and region metadata are sampled separately.
    /// Even when the record tables are locked, these are not one atomic observation.
    pub dynamic_metadata_sampled_separately: bool,
    /// An external dispatch/shard-A task table was included.
    pub external_task_table: bool,
    /// An external shard-C obligation table was included.
    pub external_obligation_table: bool,
    /// Obligations cover retained records, not reaped history or undrained mailbox posts.
    pub retained_obligations_only: bool,
    /// Wait edges cover task join waiters, not all resource/spectral wait edges.
    pub join_wait_edges_only: bool,
    /// Whether scheduler lane depths and fairness telemetry are included.
    pub scheduler_statistics: bool,
    /// Whether adaptive controller cards are included.
    pub controller_cards: bool,
}

/// Counts derived from the records actually present in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorCounters {
    /// Retained task records, including completed tasks not yet reaped.
    pub tasks: usize,
    /// Tasks whose recorded state is not completed.
    pub active_tasks: usize,
    /// Retained region records.
    pub regions: usize,
    /// All retained obligation records.
    pub retained_obligations: usize,
    /// Unresolved obligation records.
    pub reserved_obligations: usize,
    /// Successfully committed obligation records.
    pub committed_obligations: usize,
    /// Cleanly aborted obligation records.
    pub aborted_obligations: usize,
    /// Confirmed leaked obligation records.
    pub leaked_obligations: usize,
    /// Distinct task join wait edges.
    pub join_wait_edges: usize,
}

/// Serializable copy of every dimension of a runtime budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorBudget {
    /// Absolute deadline in the budget's clock domain.
    pub deadline: Option<Time>,
    /// Stored poll quota; task-record remaining polls are reported separately.
    pub poll_quota: u32,
    /// Optional cost quota.
    pub cost_quota: Option<u64>,
    /// Scheduling priority.
    pub priority: u8,
}

impl From<Budget> for InspectorBudget {
    fn from(budget: Budget) -> Self {
        Self {
            deadline: budget.deadline,
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

/// A retained progress checkpoint, in its task's runtime-clock domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorCheckpoint {
    /// Runtime timestamp recorded by the task.
    pub at: Time,
    /// Omitted under the shareable profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A task record with its context budget and bounded progress trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorTask {
    /// Existing task wire fields, including join waiters and pending obligation ids.
    #[serde(flatten)]
    pub details: TaskDetailsWire,
    /// Context budget when the task still has context state; never synthesized.
    pub budget: Option<InspectorBudget>,
    /// Total progress checkpoints, including pending fast-path accounting.
    pub checkpoint_count: Option<u64>,
    /// Last checkpoint in the task's runtime-clock domain. Absent when the task
    /// has no runtime timer driver, so wall-clock timestamps are not exported.
    pub last_checkpoint: Option<Time>,
    /// Retained message checkpoints, oldest first. Empty without a runtime clock.
    pub checkpoint_trail: Vec<InspectorCheckpoint>,
}

/// A region's topology, lifecycle state, budget, and close-blocking counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorRegion {
    /// Region identity.
    pub id: RegionId,
    /// Parent region, absent for roots.
    pub parent: Option<RegionId>,
    /// Direct children sorted by region id.
    pub children: Vec<RegionId>,
    /// Registered tasks sorted by task id.
    pub tasks: Vec<TaskId>,
    /// Region lifecycle state.
    pub state: String,
    /// Logical creation time.
    pub created_at: Time,
    /// Current region budget.
    pub budget: InspectorBudget,
    /// Spawn reservations not yet applied to the region.
    pub pending_spawns: u32,
    /// Outstanding obligation mailbox credits, sampled independently.
    pub pending_obligation_posts: u32,
    /// Applied pending obligation count.
    pub pending_obligations: usize,
    /// Checked admission credits awaiting their arena projection.
    pub unapplied_obligations: usize,
    /// Registered finalizers remaining.
    pub finalizers: usize,
}

/// An obligation still retained by the runtime, including terminal records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorObligation {
    /// Obligation identity.
    pub id: ObligationId,
    /// Resource kind.
    pub kind: ObligationKind,
    /// Holder task identity.
    pub holder: TaskId,
    /// Owning region identity.
    pub region: RegionId,
    /// Recorded lifecycle state.
    pub state: ObligationState,
    /// Reservation timestamp.
    pub reserved_at: Time,
    /// Resolution timestamp when terminal.
    pub resolved_at: Option<Time>,
    /// Time since reservation, including time retained after resolution.
    pub age_nanos: u64,
    /// Resolution reason for an aborted obligation.
    pub abort_reason: Option<ObligationAbortReason>,
    /// Diagnostic description; omitted under the shareable profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Acquisition path, line, and column; omitted under the shareable profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired_at: Option<String>,
    /// Whether a backtrace was captured. Backtrace text is never exported.
    pub has_acquire_backtrace: bool,
}

/// A registered task join dependency. Either endpoint may since have been reaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorWaitEdge {
    /// Task waiting for completion.
    pub waiter: TaskId,
    /// Task whose completion is awaited.
    pub awaited_task: TaskId,
}

/// Versioned, deterministic runtime record snapshot for tools and tests.
///
/// Task, region, obligation, and edge ordering uses numeric runtime identities.
/// Collection does not poll tasks, drain mailboxes, or run callbacks. Payloads,
/// panic text, and backtrace text are never included. The shareable profile also
/// removes free-form descriptions, source locations, and checkpoint messages.
/// See [`InspectorCoverage`] for fields unavailable from these record tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorSnapshot {
    /// Schema version identifier.
    pub schema_version: String,
    /// Applied diagnostic-text policy.
    pub profile: InspectorProfile,
    /// Runtime timestamp captured once before collecting the records.
    pub generated_at: Time,
    /// Source coverage and consistency limits.
    pub coverage: InspectorCoverage,
    /// Counts of the records below, rather than lifetime or scheduler counters.
    pub counters: InspectorCounters,
    /// Task records sorted by id.
    pub tasks: Vec<InspectorTask>,
    /// Region records sorted by id.
    pub regions: Vec<InspectorRegion>,
    /// Retained obligation records sorted by id.
    pub obligations: Vec<InspectorObligation>,
    /// Join wait edges sorted by waiter then awaited task.
    pub wait_edges: Vec<InspectorWaitEdge>,
}

impl InspectorSnapshot {
    /// Remove diagnostic text before exporting an already captured snapshot.
    ///
    /// This applies the same policy as capturing with
    /// [`InspectorProfile::Shareable`], including when the snapshot was
    /// deserialized or supplied by an application callback. Record identities,
    /// timing, topology, counters, and coverage are preserved.
    #[must_use]
    pub fn into_shareable(mut self) -> Self {
        self.profile = InspectorProfile::Shareable;
        for task in &mut self.tasks {
            for checkpoint in &mut task.checkpoint_trail {
                checkpoint.message = None;
            }
        }
        for obligation in &mut self.obligations {
            obligation.description = None;
            obligation.acquired_at = None;
        }
        self
    }

    /// Capture caller-borrowed state, including `LabRuntime::state`.
    ///
    /// Use [`TaskInspector::runtime_snapshot`] for a live native runtime: its
    /// binding also acquires the external task and obligation tables when present.
    #[must_use]
    pub fn from_state(state: &RuntimeState, profile: InspectorProfile) -> Self {
        Self::from_view(
            &RuntimeStateView {
                state,
                shard_tasks: None,
                shard_obligations: None,
            },
            profile,
            false,
        )
    }

    fn from_view(
        view: &RuntimeStateView<'_>,
        profile: InspectorProfile,
        record_tables_locked: bool,
    ) -> Self {
        let generated_at = view.now();
        let full = profile == InspectorProfile::Full;
        // Stable sorting preserves external-table precedence if a record is
        // temporarily represented in both tables, matching `view.task`.
        let mut obligation_records: Vec<_> = view.obligations().collect();
        obligation_records.sort_by_key(|record| record.id.as_u64());
        obligation_records.dedup_by_key(|record| record.id);
        let mut by_holder: BTreeMap<TaskId, Vec<ObligationId>> = BTreeMap::new();
        let obligations: Vec<_> = obligation_records
            .into_iter()
            .map(|record| {
                if record.state == ObligationState::Reserved {
                    by_holder.entry(record.holder).or_default().push(record.id);
                }
                InspectorObligation {
                    id: record.id,
                    kind: record.kind,
                    holder: record.holder,
                    region: record.region,
                    state: record.state,
                    reserved_at: record.reserved_at,
                    resolved_at: record.resolved_at,
                    age_nanos: generated_at.duration_since(record.reserved_at),
                    abort_reason: record.abort_reason,
                    description: full.then(|| record.description.clone()).flatten(),
                    acquired_at: full.then(|| record.acquired_at.to_string()),
                    has_acquire_backtrace: record.acquire_backtrace.is_some(),
                }
            })
            .collect();

        let mut task_records: Vec<_> = view.tasks().collect();
        task_records.sort_by_key(|record| record.id.as_u64());
        task_records.dedup_by_key(|record| record.id);
        let tasks: Vec<_> = task_records
            .into_iter()
            .map(|task| {
                let checkpoint_now = TaskInspector::current_checkpoint_time_for_task(task);
                let (budget, checkpoint_count, last_checkpoint, checkpoint_trail) = task
                    .cx_inner
                    .as_ref()
                    .map_or((None, None, None, Vec::new()), |inner| {
                        let inner = inner.read();
                        let checkpoints = inner.materialised_checkpoint_state();
                        let trail = if checkpoint_now.is_some() {
                            checkpoints
                                .history()
                                .into_iter()
                                .map(|entry| InspectorCheckpoint {
                                    at: entry.at,
                                    message: full.then_some(entry.message),
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                        (
                            Some(InspectorBudget::from(inner.budget)),
                            Some(checkpoints.checkpoint_count),
                            checkpoint_now.and(checkpoints.last_checkpoint),
                            trail,
                        )
                    });
                let mut waiters = task.waiters.to_vec();
                waiters.sort_unstable_by_key(TaskId::as_u64);
                waiters.dedup();
                InspectorTask {
                    details: TaskDetailsWire {
                        id: task.id,
                        region_id: task.owner,
                        state: TaskStateInfo::from(&task.state),
                        phase: phase_name(task.phase()).to_string(),
                        poll_count: task.total_polls,
                        polls_remaining: task.polls_remaining,
                        created_at: task.created_at,
                        age_nanos: generated_at.duration_since(task.created_at),
                        time_since_last_poll_nanos: checkpoint_now
                            .zip(last_checkpoint)
                            .map(|(now, last)| now.duration_since(last)),
                        wake_pending: task.wake_state.is_notified(),
                        obligations: by_holder.remove(&task.id).unwrap_or_default(),
                        waiters,
                    },
                    budget,
                    checkpoint_count,
                    last_checkpoint,
                    checkpoint_trail,
                }
            })
            .collect();

        let mut regions: Vec<_> = view
            .regions()
            .map(|region| {
                let mut children = region.child_ids();
                children.sort_unstable_by_key(RegionId::as_u64);
                let mut tasks = region.task_ids();
                tasks.sort_unstable_by_key(TaskId::as_u64);
                InspectorRegion {
                    id: region.id,
                    parent: region.parent,
                    children,
                    tasks,
                    state: format!("{:?}", region.state()),
                    created_at: region.created_at,
                    budget: InspectorBudget::from(region.budget()),
                    pending_spawns: region.pending_spawn_count(),
                    pending_obligation_posts: region.pending_obligation_post_count(),
                    pending_obligations: region.pending_obligations(),
                    unapplied_obligations: region.unapplied_obligation_count(),
                    finalizers: region.finalizer_count(),
                }
            })
            .collect();
        regions.sort_unstable_by_key(|region| region.id.as_u64());

        let mut wait_edges: Vec<_> = tasks
            .iter()
            .flat_map(|task| {
                task.details
                    .waiters
                    .iter()
                    .map(move |&waiter| InspectorWaitEdge {
                        waiter,
                        awaited_task: task.details.id,
                    })
            })
            .collect();
        wait_edges.sort_unstable_by_key(|edge| (edge.waiter.as_u64(), edge.awaited_task.as_u64()));
        let count_obligations = |state| obligations.iter().filter(|ob| ob.state == state).count();
        let counters = InspectorCounters {
            tasks: tasks.len(),
            active_tasks: tasks
                .iter()
                .filter(|task| !matches!(task.details.state, TaskStateInfo::Completed { .. }))
                .count(),
            regions: regions.len(),
            retained_obligations: obligations.len(),
            reserved_obligations: count_obligations(ObligationState::Reserved),
            committed_obligations: count_obligations(ObligationState::Committed),
            aborted_obligations: count_obligations(ObligationState::Aborted),
            leaked_obligations: count_obligations(ObligationState::Leaked),
            join_wait_edges: wait_edges.len(),
        };
        Self {
            schema_version: INSPECTOR_SNAPSHOT_SCHEMA_V1.to_string(),
            profile,
            generated_at,
            coverage: InspectorCoverage {
                record_tables_locked,
                dynamic_metadata_sampled_separately: true,
                external_task_table: view.shard_tasks.is_some(),
                external_obligation_table: view.shard_obligations.is_some(),
                retained_obligations_only: true,
                join_wait_edges_only: true,
                scheduler_statistics: false,
                controller_cards: false,
            },
            counters,
            tasks,
            regions,
            obligations,
            wait_edges,
        }
    }
}

/// Deterministic wire payload for task-inspector snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskConsoleWireSnapshot {
    /// Schema version identifier.
    pub schema_version: String,
    /// Logical timestamp of snapshot capture.
    pub generated_at: Time,
    /// Aggregate task-state counters.
    pub summary: TaskSummaryWire,
    /// Task-level records sorted by `TaskId`.
    pub tasks: Vec<TaskDetailsWire>,
}

impl TaskConsoleWireSnapshot {
    /// Build a wire snapshot with deterministic task ordering.
    #[must_use]
    pub fn new(
        generated_at: Time,
        summary: TaskSummaryWire,
        mut tasks: Vec<TaskDetailsWire>,
    ) -> Self {
        tasks.sort_unstable_by_key(|record| record.id);
        Self {
            schema_version: TASK_CONSOLE_WIRE_SCHEMA_V1.to_string(),
            generated_at,
            summary,
            tasks,
        }
    }

    /// Returns true when the payload schema matches the expected version.
    #[must_use]
    pub fn has_expected_schema(&self) -> bool {
        self.schema_version == TASK_CONSOLE_WIRE_SCHEMA_V1
    }

    /// Encode snapshot as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` when serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Encode snapshot as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` when serialization fails.
    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Decode snapshot from JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` when parsing fails.
    pub fn from_json(payload: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(payload)
    }
}

/// Region-level task count in wire payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRegionCountWire {
    /// Region identifier.
    pub region_id: RegionId,
    /// Number of tasks currently owned by this region.
    pub task_count: usize,
}

/// Summary section for task-inspector wire snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSummaryWire {
    /// Total number of tasks.
    pub total_tasks: usize,
    /// Tasks in `Created`.
    pub created: usize,
    /// Tasks in `Running`.
    pub running: usize,
    /// Tasks in any cancellation phase.
    pub cancelling: usize,
    /// Completed tasks.
    pub completed: usize,
    /// Number of tasks classified as potentially stuck.
    pub stuck_count: usize,
    /// Region distribution, sorted by `RegionId`.
    pub by_region: Vec<TaskRegionCountWire>,
}

impl From<TaskSummary> for TaskSummaryWire {
    fn from(summary: TaskSummary) -> Self {
        let by_region = summary
            .by_region
            .into_iter()
            .map(|(region_id, task_count)| TaskRegionCountWire {
                region_id,
                task_count,
            })
            .collect();
        Self {
            total_tasks: summary.total_tasks,
            created: summary.created,
            running: summary.running,
            cancelling: summary.cancelling,
            completed: summary.completed,
            stuck_count: summary.stuck_count,
            by_region,
        }
    }
}

/// Task-level section for task-inspector wire snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDetailsWire {
    /// Task identifier.
    pub id: TaskId,
    /// Owning region.
    pub region_id: RegionId,
    /// High-level task state.
    pub state: TaskStateInfo,
    /// Coarse-grained atomic phase.
    pub phase: String,
    /// Poll count since task creation.
    pub poll_count: u64,
    /// Remaining poll budget.
    pub polls_remaining: u32,
    /// Task creation logical timestamp.
    pub created_at: Time,
    /// Task age in nanoseconds.
    pub age_nanos: u64,
    /// Time since last poll in nanoseconds when available.
    pub time_since_last_poll_nanos: Option<u64>,
    /// Whether a wake is pending.
    pub wake_pending: bool,
    /// Held obligations sorted by `ObligationId`.
    pub obligations: Vec<ObligationId>,
    /// Waiting tasks sorted by `TaskId`.
    pub waiters: Vec<TaskId>,
}

impl From<TaskDetails> for TaskDetailsWire {
    fn from(task: TaskDetails) -> Self {
        let mut obligations = task.obligations;
        obligations.sort_unstable();
        let mut waiters = task.waiters;
        waiters.sort_unstable();
        Self {
            id: task.id,
            region_id: task.region_id,
            state: task.state,
            phase: phase_name(task.phase).to_string(),
            poll_count: task.poll_count,
            polls_remaining: task.polls_remaining,
            created_at: task.created_at,
            age_nanos: duration_to_nanos(task.age),
            time_since_last_poll_nanos: task.time_since_last_poll.map(duration_to_nanos),
            wake_pending: task.wake_pending,
            obligations,
            waiters,
        }
    }
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn phase_name(phase: TaskPhase) -> &'static str {
    match phase {
        TaskPhase::Created => "Created",
        TaskPhase::Running => "Running",
        TaskPhase::CancelRequested => "CancelRequested",
        TaskPhase::Cancelling => "Cancelling",
        TaskPhase::Finalizing => "Finalizing",
        TaskPhase::Completed => "Completed",
    }
}

impl TaskStateInfo {
    /// Returns a short name for the state.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Running => "Running",
            Self::CancelRequested { .. } => "CancelRequested",
            Self::Cancelling { .. } => "Cancelling",
            Self::Finalizing { .. } => "Finalizing",
            Self::Completed { .. } => "Completed",
        }
    }
}

impl From<&TaskState> for TaskStateInfo {
    fn from(state: &TaskState) -> Self {
        match state {
            TaskState::Created => Self::Created,
            TaskState::Running => Self::Running,
            TaskState::CancelRequested { reason, .. } => Self::CancelRequested {
                reason: format!("{:?}", reason.kind),
            },
            TaskState::Cancelling { reason, .. } => Self::Cancelling {
                reason: format!("{:?}", reason.kind),
            },
            TaskState::Finalizing { reason, .. } => Self::Finalizing {
                reason: format!("{:?}", reason.kind),
            },
            TaskState::Completed(outcome) => Self::Completed {
                outcome: match outcome {
                    Outcome::Ok(()) => "Ok".to_string(),
                    Outcome::Err(e) => format!("Err({:?})", e.kind()),
                    Outcome::Cancelled(r) => format!("Cancelled({:?})", r.kind),
                    Outcome::Panicked(_) => "Panicked".to_string(),
                },
            },
        }
    }
}

/// Summary of all tasks in the runtime.
#[derive(Debug, Clone, Default)]
pub struct TaskSummary {
    /// Total number of tasks.
    pub total_tasks: usize,
    /// Tasks in Created state.
    pub created: usize,
    /// Tasks in Running state.
    pub running: usize,
    /// Tasks being cancelled (any cancellation state).
    pub cancelling: usize,
    /// Completed tasks.
    pub completed: usize,
    /// Tasks grouped by region.
    pub by_region: BTreeMap<RegionId, usize>,
    /// Number of potentially stuck tasks.
    pub stuck_count: usize,
}

/// Real-time task inspector for runtime diagnostics.
#[derive(Debug)]
pub struct TaskInspector {
    state: RuntimeStateSource,
    config: TaskInspectorConfig,
    console: Option<Console>,
}

impl TaskInspector {
    /// Create a new task inspector.
    #[must_use]
    pub fn new(state: Arc<RuntimeState>, console: Option<Console>) -> Self {
        Self::with_config(state, console, TaskInspectorConfig::default())
    }

    /// Create a new task inspector with custom configuration.
    #[must_use]
    pub fn with_config(
        state: Arc<RuntimeState>,
        console: Option<Console>,
        config: TaskInspectorConfig,
    ) -> Self {
        Self::from_source(RuntimeStateSource::Owned(state), console, config)
    }

    /// Create an inspector over any state source: detached state or a live
    /// runtime's shared state (see
    /// [`Runtime::task_inspector`](crate::runtime::Runtime::task_inspector)).
    pub(crate) fn from_source(
        state: RuntimeStateSource,
        console: Option<Console>,
        config: TaskInspectorConfig,
    ) -> Self {
        debug!(
            stuck_threshold_secs = config.stuck_task_threshold.as_secs(),
            show_obligations = config.show_obligations,
            "task inspector created"
        );
        Self {
            state,
            config,
            console,
        }
    }

    /// Get the current checkpoint time when it shares the task's checkpoint clock.
    ///
    /// `Cx::checkpoint()` records time using the task-local timer driver handle
    /// captured in the `Cx`. If a task was created before the runtime attached a
    /// timer driver, later switching `RuntimeState` to timer-driver time does
    /// not retroactively update that `Cx`; the task will keep recording wall
    /// clock checkpoints. The inspector therefore has to consult the task's own
    /// `Cx` handle instead of the runtime-global timer driver to avoid mixing
    /// clock domains after late driver attachment.
    fn current_checkpoint_time_for_task(task: &TaskRecord) -> Option<Time> {
        task.cx
            .as_ref()
            .and_then(Cx::timer_driver)
            .map(|driver| driver.now())
    }

    /// Get detailed information about a specific task.
    #[must_use]
    pub fn inspect_task(&self, task_id: TaskId) -> Option<TaskDetails> {
        trace!(task_id = ?task_id, "inspecting task");
        self.state
            .with_view(|view| self.inspect_task_in(view, task_id))
    }

    /// Pure read of one task against an already-resolved state view.
    fn inspect_task_in(&self, view: &RuntimeStateView<'_>, task_id: TaskId) -> Option<TaskDetails> {
        let task = view.task(task_id)?;
        let current_time = view.now();
        let age_nanos = current_time.duration_since(task.created_at);
        let age = Duration::from_nanos(age_nanos);

        // Collect obligations held by this task
        let obligations: Vec<ObligationId> = if self.config.show_obligations {
            view.pending_obligations_for_holder(task_id)
        } else {
            Vec::new()
        };

        let time_since_last_poll = Self::current_checkpoint_time_for_task(task).and_then(|now| {
            task.cx_inner.as_ref().and_then(|inner| {
                inner
                    .read()
                    .materialised_checkpoint_state()
                    .last_checkpoint
                    .map(|last_checkpoint| {
                        Duration::from_nanos(now.duration_since(last_checkpoint))
                    })
            })
        });

        Some(TaskDetails {
            id: task.id,
            region_id: task.owner,
            state: TaskStateInfo::from(&task.state),
            phase: task.phase(),
            poll_count: task.total_polls,
            polls_remaining: task.polls_remaining,
            created_at: task.created_at,
            age,
            time_since_last_poll,
            wake_pending: task.wake_state.is_notified(),
            obligations,
            waiters: task.waiters.to_vec(),
        })
    }

    /// List all tasks with their details.
    #[must_use]
    pub fn list_tasks(&self) -> Vec<TaskDetails> {
        trace!("listing all tasks");
        self.state.with_view(|view| self.list_tasks_in(view))
    }

    /// Pure read of every task against an already-resolved state view.
    fn list_tasks_in(&self, view: &RuntimeStateView<'_>) -> Vec<TaskDetails> {
        view.tasks()
            .filter_map(|task| self.inspect_task_in(view, task.id))
            .collect()
    }

    /// List non-terminal tasks only.
    #[must_use]
    pub fn list_active_tasks(&self) -> Vec<TaskDetails> {
        self.list_tasks()
            .into_iter()
            .filter(|t| !t.is_terminal())
            .collect()
    }

    /// Get tasks in a specific region.
    #[must_use]
    pub fn by_region(&self, region_id: RegionId) -> Vec<TaskDetails> {
        trace!(region_id = ?region_id, "filtering tasks by region");
        self.list_tasks()
            .into_iter()
            .filter(|t| t.region_id == region_id)
            .collect()
    }

    /// Get tasks in a specific state.
    #[must_use]
    pub fn by_state(&self, state_name: &str) -> Vec<TaskDetails> {
        trace!(state_name = %state_name, "filtering tasks by state");
        self.list_tasks()
            .into_iter()
            .filter(|t| t.state.name() == state_name)
            .collect()
    }

    /// Find tasks that haven't reported progress recently (potentially stuck).
    ///
    /// Note: This is heuristic-based because explicit idle-time metadata is not
    /// always available. When no checkpoint-derived idle time exists yet, the
    /// inspector only flags aged tasks that have never been polled, avoiding
    /// false positives for long-lived waiting tasks.
    #[must_use]
    pub fn find_stuck_tasks(&self, age_threshold: Duration) -> Vec<TaskDetails> {
        debug!(
            threshold_secs = age_threshold.as_secs(),
            "checking for stuck tasks"
        );

        let stuck: Vec<_> = self
            .list_active_tasks()
            .into_iter()
            .filter(|task| task.is_potentially_stuck(age_threshold))
            .collect();

        if !stuck.is_empty() {
            warn!(
                count = stuck.len(),
                threshold_secs = age_threshold.as_secs(),
                "potential stuck tasks detected"
            );
            for task in &stuck {
                // When tracing is compiled out, ensure `task` is still considered "used".
                let _ = task;
                info!(
                    task_id = ?task.id,
                    region_id = ?task.region_id,
                    age_secs = task.age.as_secs(),
                    poll_count = task.poll_count,
                    state = task.state.name(),
                    "potential stuck task"
                );
            }
        }

        stuck
    }

    /// Find stuck tasks using the configured threshold.
    #[must_use]
    pub fn find_stuck_tasks_default(&self) -> Vec<TaskDetails> {
        self.find_stuck_tasks(self.config.stuck_task_threshold)
    }

    fn summarize_tasks(tasks: &[TaskDetails], stuck_threshold: Duration) -> TaskSummary {
        let mut by_region: BTreeMap<RegionId, usize> = BTreeMap::new();
        let mut created = 0;
        let mut running = 0;
        let mut cancelling = 0;
        let mut completed = 0;
        let mut stuck_count = 0;

        for task in tasks {
            *by_region.entry(task.region_id).or_insert(0) += 1;

            match &task.state {
                TaskStateInfo::Created => created += 1,
                TaskStateInfo::Running => running += 1,
                TaskStateInfo::CancelRequested { .. }
                | TaskStateInfo::Cancelling { .. }
                | TaskStateInfo::Finalizing { .. } => cancelling += 1,
                TaskStateInfo::Completed { .. } => completed += 1,
            }

            if task.is_potentially_stuck(stuck_threshold) {
                stuck_count += 1;
            }
        }

        TaskSummary {
            total_tasks: tasks.len(),
            created,
            running,
            cancelling,
            completed,
            by_region,
            stuck_count,
        }
    }

    /// Get a summary of all tasks.
    #[must_use]
    pub fn summary(&self) -> TaskSummary {
        let tasks = self.list_tasks();
        let summary = Self::summarize_tasks(&tasks, self.config.stuck_task_threshold);

        debug!(
            total = summary.total_tasks,
            created = summary.created,
            running = summary.running,
            cancelling = summary.cancelling,
            completed = summary.completed,
            stuck = summary.stuck_count,
            "task summary computed"
        );

        summary
    }

    /// Build a deterministic wire snapshot suitable for console or dashboard consumers.
    #[must_use]
    pub fn wire_snapshot(&self) -> TaskConsoleWireSnapshot {
        // One view so the task list and the snapshot timestamp come from the
        // same lock scope.
        let (captured_at, tasks) = self
            .state
            .with_view(|view| (view.now(), self.list_tasks_in(view)));
        let summary = Self::summarize_tasks(&tasks, self.config.stuck_task_threshold);
        let wire_tasks = tasks.into_iter().map(TaskDetailsWire::from).collect();
        TaskConsoleWireSnapshot::new(captured_at, TaskSummaryWire::from(summary), wire_tasks)
    }

    /// Capture tasks, regions, retained obligations, and task join dependencies.
    ///
    /// One state view holds the record-table locks in B -> A -> C order on a
    /// live runtime, including external dispatch and obligation tables. Atomic
    /// phase/wake fields and interior context/region metadata may still change;
    /// the snapshot explicitly reports that consistency boundary. Inspector
    /// display settings do not suppress obligation records in this API.
    #[must_use]
    pub fn runtime_snapshot(&self, profile: InspectorProfile) -> InspectorSnapshot {
        let record_tables_locked = matches!(&self.state, RuntimeStateSource::Shared { .. });
        self.state
            .with_view(|view| InspectorSnapshot::from_view(view, profile, record_tables_locked))
    }

    /// Serialize a wire snapshot as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` when serialization fails.
    pub fn wire_snapshot_json(&self) -> Result<String, serde_json::Error> {
        self.wire_snapshot().to_json()
    }

    /// Serialize a wire snapshot as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` when serialization fails.
    pub fn wire_snapshot_pretty_json(&self) -> Result<String, serde_json::Error> {
        self.wire_snapshot().to_pretty_json()
    }

    fn format_summary_output(
        summary: &TaskSummary,
        stuck: &[TaskDetails],
        highlight_stuck_tasks: bool,
    ) -> String {
        let mut output = String::new();
        writeln!(&mut output, "Task Inspector").expect("expected");
        writeln!(
            &mut output,
            "Total: {}  |  Running: {}  |  Cancelling: {}  |  Completed: {}  |  Stuck: {}",
            summary.total_tasks,
            summary.running,
            summary.cancelling,
            summary.completed,
            summary.stuck_count
        )
        .expect("expected");
        output.push_str(&"-".repeat(70));
        output.push('\n');

        output.push_str("By Region:\n");
        for (region_id, count) in &summary.by_region {
            writeln!(&mut output, "  {region_id:?}: {count} tasks").expect("expected");
        }

        if highlight_stuck_tasks && !stuck.is_empty() {
            output.push_str(&"-".repeat(70));
            output.push('\n');
            output.push_str("POTENTIAL STUCK TASKS:\n");
            for stuck_task in stuck {
                let id = stuck_task.id;
                let region_id = stuck_task.region_id;
                let state = stuck_task.state.name();
                let age_secs = stuck_task.age.as_secs_f64();
                let poll_count = stuck_task.poll_count;
                writeln!(
                    &mut output,
                    "  {id:?} in {region_id:?} - {state} for {age_secs:.1}s, {poll_count} polls"
                )
                .expect("expected");
            }
        }

        output
    }

    /// Render task summary to console (if available).
    pub fn render_summary(&self) -> std::io::Result<()> {
        let Some(console) = &self.console else {
            return Ok(());
        };

        let summary = self.summary();
        let stuck = self.find_stuck_tasks_default();
        let output =
            Self::format_summary_output(&summary, &stuck, self.config.highlight_stuck_tasks);

        console.print(&RawText(&output))
    }

    /// Render detailed task information to console.
    pub fn render_task_details(&self, task_id: TaskId) -> std::io::Result<()> {
        let Some(console) = &self.console else {
            return Ok(());
        };

        let Some(task) = self.inspect_task(task_id) else {
            let mut output = String::new();
            writeln!(&mut output, "Task {task_id:?} not found").expect("expected");
            return console.print(&RawText(&output));
        };

        let mut output = String::new();
        writeln!(&mut output, "Task Inspector: {task_id:?}").expect("expected");
        output.push_str(&"-".repeat(50));
        output.push('\n');
        writeln!(&mut output, "State:         {}", task.state.name()).expect("expected");
        writeln!(&mut output, "Phase:         {:?}", task.phase).expect("expected");
        writeln!(&mut output, "Region:        {:?}", task.region_id).expect("expected");
        writeln!(&mut output, "Age:           {:.3}s", task.age.as_secs_f64()).expect("expected");
        writeln!(&mut output, "Poll count:    {}", task.poll_count).expect("expected");
        writeln!(&mut output, "Polls left:    {}", task.polls_remaining)
            .expect("write should not fail on String");
        writeln!(&mut output, "Wake pending:  {}", task.wake_pending).expect("expected");

        if !task.obligations.is_empty() {
            output.push_str(&"-".repeat(50));
            output.push('\n');
            output.push_str("Obligations:\n");
            for ob_id in &task.obligations {
                writeln!(&mut output, "  {ob_id:?}").expect("write should not fail on String");
            }
        }

        if !task.waiters.is_empty() {
            output.push_str(&"-".repeat(50));
            output.push('\n');
            output.push_str("Waiters:\n");
            for waiter_id in &task.waiters {
                writeln!(&mut output, "  {waiter_id:?}").expect("write should not fail on String");
            }
        }

        console.print(&RawText(&output))
    }
}

/// Simple wrapper for rendering raw text.
struct RawText<'a>(&'a str);

impl crate::console::Render for RawText<'_> {
    fn render(
        &self,
        out: &mut String,
        _caps: &crate::console::Capabilities,
        _mode: crate::console::ColorMode,
    ) {
        out.push_str(self.0);
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
#[path = "task_inspector_inline_tests.rs"]
mod tests;
