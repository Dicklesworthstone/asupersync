//! Deterministic swarm replay scenarios for multi-agent pressure tests.
//!
//! This module is a small source-owned scenario surface for swarm-scale lab
//! workloads. It keeps the first slice deliberately narrow: build deterministic
//! task pressure, route it through [`LabRuntime`], request cancellation through
//! the runtime state machine, and return a byte-stable summary that higher-level
//! replay packs can serialize or shrink.

use super::config::LabConfig;
use super::runtime::{LabRunReport, LabRuntime};
use crate::cx::Cx;
use crate::runtime::scheduler::SchedulerFeedbackMetrics;
use crate::types::{
    Budget, CancelReason, CapabilityBudget, CapabilityBudgetDimension,
    CapabilityBudgetRequirements, RegionId, TaskId,
};
use crate::util::DetRng;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Stable schema version for swarm replay summaries.
pub const SWARM_REPLAY_SCHEMA_VERSION: &str = "asupersync.swarm-replay-lab.v1";

/// Stable schema version for swarm pressure summaries.
pub const SWARM_PRESSURE_SCHEMA_VERSION: &str = "asupersync.swarm-pressure-lab.v1";

/// Stable schema version for operator-readable swarm pressure trace summaries.
pub const SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION: &str =
    "asupersync.swarm-pressure-trace-summary.v1";

/// Stable schema version for swarm contention heatmap ledgers.
pub const SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION: &str =
    "asupersync.swarm-contention-heatmap-ledger.v1";

/// Stable schema version for deterministic agent-run summaries.
pub const SWARM_AGENT_RUN_SCHEMA_VERSION: &str = "asupersync.swarm-agent-run-lab.v1";

/// Stable schema version for swarm what-if admission plans.
pub const SWARM_WHAT_IF_PLAN_SCHEMA_VERSION: &str = "asupersync.swarm-what-if-plan.v1";

/// Stable schema version for compaction-safe swarm handoff verification.
pub const SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION: &str =
    "asupersync.swarm-handoff-verification.v1";

/// Stable schema version for remote-only swarm proof-lane plans.
pub const SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION: &str = "asupersync.swarm-proof-lane-plan.v1";

/// Stable schema version for deterministic swarm proof-lane atlas reports.
pub const SWARM_PROOF_LANE_ATLAS_REPORT_SCHEMA_VERSION: &str =
    "asupersync.swarm-proof-lane-atlas-report.v1";

/// Stable schema version for deterministic swarm failure minimizer reports.
pub const SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION: &str = "asupersync.swarm-failure-minimizer.v1";

/// Stable schema version for operator cockpit swarm reports.
pub const SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION: &str =
    "asupersync.swarm-operator-cockpit-report.v1";

const MAX_FIRST_SLICE_TASKS: usize = 10_000;

/// Deterministic workload knobs for a swarm replay lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SwarmReplayScenario {
    /// Stable scenario identifier used in logs and artifacts.
    pub scenario_id: String,
    /// Lab runtime seed. Same seed and same knobs must produce the same summary.
    pub seed: u64,
    /// Virtual workers modeled by [`LabConfig`].
    pub worker_count: usize,
    /// Logical worker cohorts used by later placement and NUMA policy beads.
    pub cohort_count: usize,
    /// Number of modeled child regions under the scenario root.
    pub region_count: usize,
    /// Number of tasks spawned in each region.
    pub tasks_per_region: usize,
    /// Base number of cooperative yield points per task.
    pub yields_per_task: usize,
    /// Seeded extra yield points in the range `0..=yield_jitter`.
    pub yield_jitter: usize,
    /// Modeled bounded channel capacity for backlog accounting.
    pub channel_capacity: usize,
    /// Modeled messages reserved by each task before it starts yielding.
    pub messages_per_task: usize,
    /// Modeled semaphore permits touched by each task.
    pub semaphore_permits_per_task: usize,
    /// Modeled pool slots checked out by each task.
    pub pool_slots_per_task: usize,
    /// Modeled linear obligations resolved by each task.
    pub obligations_per_task: usize,
    /// Modeled virtual timer wakeups associated with each task.
    pub timer_ticks_per_task: usize,
    /// Depth of the modeled cancellation tree from root to leaf tasks.
    pub cancellation_tree_depth: usize,
    /// Modeled proof/trace artifact bytes emitted by a completed task.
    pub artifact_bytes_per_task: usize,
    /// Optional per-region runnable-task admission limit.
    ///
    /// `None` admits every modeled task in the region. `Some(0)` models an
    /// empty runnable-task budget and must fail closed without scheduling work.
    pub region_task_admission_limit: Option<usize>,
    /// Decision used when requested region work exceeds the admission limit.
    pub region_over_limit_decision: SwarmReplayAdmissionDecision,
    /// Modeled memory envelope consumed by each admitted task.
    pub region_memory_bytes_per_task: u64,
    /// Modeled queue-depth envelope consumed by each admitted task.
    pub region_queue_depth_units_per_task: u64,
    /// Modeled blocking-pool submission envelope consumed by each admitted task.
    pub region_blocking_pool_units_per_task: u64,
    /// Modeled cleanup/drain poll quota consumed by each admitted task.
    pub region_cleanup_poll_quota_per_task: u64,
    /// Scheduler steps to run before issuing a cancellation cascade.
    ///
    /// `None` means the scenario runs to normal quiescence without an explicit
    /// cancellation request.
    pub cancel_after_steps: Option<u64>,
    /// Maximum lab steps before the runtime stops.
    pub max_steps: u64,
}

impl Default for SwarmReplayScenario {
    fn default() -> Self {
        Self {
            scenario_id: "swarm-replay-default".to_string(),
            seed: 0xA5A5_5EED,
            worker_count: 2,
            cohort_count: 1,
            region_count: 2,
            tasks_per_region: 4,
            yields_per_task: 4,
            yield_jitter: 2,
            channel_capacity: 8,
            messages_per_task: 2,
            semaphore_permits_per_task: 1,
            pool_slots_per_task: 1,
            obligations_per_task: 2,
            timer_ticks_per_task: 1,
            cancellation_tree_depth: 2,
            artifact_bytes_per_task: 256,
            region_task_admission_limit: None,
            region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
            region_memory_bytes_per_task: 1024,
            region_queue_depth_units_per_task: 1,
            region_blocking_pool_units_per_task: 1,
            region_cleanup_poll_quota_per_task: 1,
            cancel_after_steps: Some(3),
            max_steps: 10_000,
        }
    }
}

impl SwarmReplayScenario {
    /// Total number of modeled tasks.
    #[must_use]
    pub const fn task_count(&self) -> usize {
        self.region_count.saturating_mul(self.tasks_per_region)
    }

    /// Validate that the scenario is bounded and replayable.
    pub fn validate(&self) -> Result<(), SwarmReplayError> {
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmReplayError::EmptyScenarioId);
        }
        if self.worker_count == 0 {
            return Err(SwarmReplayError::ZeroWorkerCount);
        }
        if self.cohort_count == 0 {
            return Err(SwarmReplayError::ZeroCohortCount);
        }
        if self.cohort_count > self.worker_count {
            return Err(SwarmReplayError::CohortCountExceedsWorkers {
                cohort_count: self.cohort_count,
                worker_count: self.worker_count,
            });
        }
        if self.region_count == 0 {
            return Err(SwarmReplayError::ZeroRegionCount);
        }
        if self.tasks_per_region == 0 {
            return Err(SwarmReplayError::ZeroTasksPerRegion);
        }
        if self.channel_capacity == 0 {
            return Err(SwarmReplayError::ZeroChannelCapacity);
        }
        if self.semaphore_permits_per_task == 0 {
            return Err(SwarmReplayError::ZeroSemaphorePermits);
        }
        if self.pool_slots_per_task == 0 {
            return Err(SwarmReplayError::ZeroPoolSlots);
        }
        if self.obligations_per_task == 0 {
            return Err(SwarmReplayError::ZeroObligationsPerTask);
        }
        if self.timer_ticks_per_task == 0 {
            return Err(SwarmReplayError::ZeroTimerTicks);
        }
        if self.cancellation_tree_depth == 0 {
            return Err(SwarmReplayError::ZeroCancellationTreeDepth);
        }
        if self.max_steps == 0 {
            return Err(SwarmReplayError::ZeroMaxSteps);
        }
        if self.yield_jitter == usize::MAX {
            return Err(SwarmReplayError::YieldJitterOverflow);
        }

        let task_count = self.task_count();
        if task_count > MAX_FIRST_SLICE_TASKS {
            return Err(SwarmReplayError::TooManyTasks {
                task_count,
                max: MAX_FIRST_SLICE_TASKS,
            });
        }

        if let Some(cancel_after_steps) = self.cancel_after_steps {
            if cancel_after_steps >= self.max_steps {
                return Err(SwarmReplayError::CancelStepBeyondMax {
                    cancel_after_steps,
                    max_steps: self.max_steps,
                });
            }
        }
        if let Some(limit) = self.region_task_admission_limit {
            if limit < self.tasks_per_region
                && self.region_over_limit_decision == SwarmReplayAdmissionDecision::Accept
            {
                return Err(SwarmReplayError::InvalidOverLimitAcceptDecision);
            }
        }

        self.artifact_bytes_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::ArtifactByteCountOverflow)?;
        self.messages_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::ChannelOperationCountOverflow)?;
        self.semaphore_permits_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::SemaphoreOperationCountOverflow)?;
        self.pool_slots_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::PoolOperationCountOverflow)?;
        self.obligations_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::ObligationCountOverflow)?;
        self.timer_ticks_per_task
            .checked_mul(task_count)
            .ok_or(SwarmReplayError::TimerTickCountOverflow)?;
        self.region_memory_bytes_per_task
            .checked_mul(task_count as u64)
            .ok_or(SwarmReplayError::RegionBudgetUnitOverflow)?;
        self.region_queue_depth_units_per_task
            .checked_mul(task_count as u64)
            .ok_or(SwarmReplayError::RegionBudgetUnitOverflow)?;
        self.region_blocking_pool_units_per_task
            .checked_mul(task_count as u64)
            .ok_or(SwarmReplayError::RegionBudgetUnitOverflow)?;
        let cleanup_quota = self
            .region_cleanup_poll_quota_per_task
            .checked_mul(task_count as u64)
            .ok_or(SwarmReplayError::RegionBudgetUnitOverflow)?;
        if cleanup_quota > u64::from(u32::MAX) {
            return Err(SwarmReplayError::RegionCleanupPollQuotaOverflow);
        }

        Ok(())
    }
}

/// Error returned when a swarm replay scenario is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmReplayError {
    /// The scenario id is empty.
    EmptyScenarioId,
    /// No regions were requested.
    ZeroRegionCount,
    /// No tasks were requested per region.
    ZeroTasksPerRegion,
    /// Channel capacity was zero, which would make backlog accounting invalid.
    ZeroChannelCapacity,
    /// The lab step limit was zero.
    ZeroMaxSteps,
    /// No logical workers were requested.
    ZeroWorkerCount,
    /// No logical worker cohorts were requested.
    ZeroCohortCount,
    /// More cohorts were requested than logical workers.
    CohortCountExceedsWorkers {
        /// Requested cohort count.
        cohort_count: usize,
        /// Requested worker count.
        worker_count: usize,
    },
    /// No modeled semaphore permits were requested per task.
    ZeroSemaphorePermits,
    /// No modeled pool slots were requested per task.
    ZeroPoolSlots,
    /// No modeled obligations were requested per task.
    ZeroObligationsPerTask,
    /// No modeled timer ticks were requested per task.
    ZeroTimerTicks,
    /// No modeled cancellation tree depth was requested.
    ZeroCancellationTreeDepth,
    /// No interactive work was requested.
    ZeroInteractiveTasks,
    /// No synthetic agents were requested.
    ZeroAgentCount,
    /// A what-if workload was missing a stable id.
    EmptyWorkloadId {
        /// Workload index in the scenario input.
        workload_index: usize,
    },
    /// The interactive latency bound was zero.
    ZeroInteractiveLatencyBound,
    /// A configured synthetic agent index is outside the scenario.
    AgentIndexOutOfRange {
        /// Field that carried the out-of-range index.
        field: &'static str,
        /// Requested agent index.
        agent_index: usize,
        /// Number of agents configured for the scenario.
        agent_count: usize,
    },
    /// An RCH worker event used a zero delta.
    ZeroRchWorkerDelta {
        /// Step containing the invalid event.
        at_step: u64,
    },
    /// The yield jitter range cannot be represented as an inclusive bound.
    YieldJitterOverflow,
    /// The requested task count exceeds the first-slice safety cap.
    TooManyTasks {
        /// Requested task count.
        task_count: usize,
        /// Maximum accepted task count.
        max: usize,
    },
    /// The configured cancellation step can never execute before the step limit.
    CancelStepBeyondMax {
        /// Requested cancellation step.
        cancel_after_steps: u64,
        /// Maximum lab steps.
        max_steps: u64,
    },
    /// Artifact byte accounting overflowed `usize`.
    ArtifactByteCountOverflow,
    /// Modeled channel operation accounting overflowed `usize`.
    ChannelOperationCountOverflow,
    /// Modeled semaphore operation accounting overflowed `usize`.
    SemaphoreOperationCountOverflow,
    /// Modeled pool operation accounting overflowed `usize`.
    PoolOperationCountOverflow,
    /// Modeled obligation accounting overflowed `usize`.
    ObligationCountOverflow,
    /// Modeled timer accounting overflowed `usize`.
    TimerTickCountOverflow,
    /// Modeled region capability-budget unit accounting overflowed `u64`.
    RegionBudgetUnitOverflow,
    /// Modeled cleanup poll quota cannot fit the runtime budget type.
    RegionCleanupPollQuotaOverflow,
    /// Over-limit admission cannot use the accept decision.
    InvalidOverLimitAcceptDecision,
    /// Region creation was rejected by the runtime state.
    RegionCreateRejected {
        /// Scenario region ordinal.
        region_index: usize,
        /// Stable debug reason from the runtime state.
        reason: String,
    },
    /// Task creation was rejected by the runtime state.
    TaskSpawnRejected {
        /// Scenario region ordinal.
        region_index: usize,
        /// Task ordinal within the region.
        task_index: usize,
        /// Stable debug reason from the runtime state.
        reason: String,
    },
}

impl fmt::Display for SwarmReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenarioId => f.write_str("scenario_id must be nonempty"),
            Self::ZeroRegionCount => f.write_str("region_count must be greater than zero"),
            Self::ZeroTasksPerRegion => f.write_str("tasks_per_region must be greater than zero"),
            Self::ZeroChannelCapacity => f.write_str("channel_capacity must be greater than zero"),
            Self::ZeroMaxSteps => f.write_str("max_steps must be greater than zero"),
            Self::ZeroWorkerCount => f.write_str("worker_count must be greater than zero"),
            Self::ZeroCohortCount => f.write_str("cohort_count must be greater than zero"),
            Self::CohortCountExceedsWorkers {
                cohort_count,
                worker_count,
            } => write!(
                f,
                "cohort_count {cohort_count} must not exceed worker_count {worker_count}"
            ),
            Self::ZeroSemaphorePermits => {
                f.write_str("semaphore_permits_per_task must be greater than zero")
            }
            Self::ZeroPoolSlots => f.write_str("pool_slots_per_task must be greater than zero"),
            Self::ZeroObligationsPerTask => {
                f.write_str("obligations_per_task must be greater than zero")
            }
            Self::ZeroTimerTicks => f.write_str("timer_ticks_per_task must be greater than zero"),
            Self::ZeroCancellationTreeDepth => {
                f.write_str("cancellation_tree_depth must be greater than zero")
            }
            Self::ZeroInteractiveTasks => {
                f.write_str("interactive_tasks must be greater than zero")
            }
            Self::ZeroAgentCount => f.write_str("agent_count must be greater than zero"),
            Self::EmptyWorkloadId { workload_index } => {
                write!(
                    f,
                    "what-if workload {workload_index} must have a nonempty id"
                )
            }
            Self::ZeroInteractiveLatencyBound => {
                f.write_str("interactive_latency_bound_steps must be greater than zero")
            }
            Self::AgentIndexOutOfRange {
                field,
                agent_index,
                agent_count,
            } => write!(
                f,
                "{field} index {agent_index} must be less than agent_count {agent_count}"
            ),
            Self::ZeroRchWorkerDelta { at_step } => write!(
                f,
                "rch worker event at step {at_step} used zero worker_delta"
            ),
            Self::YieldJitterOverflow => f.write_str("yield_jitter must be less than usize::MAX"),
            Self::TooManyTasks { task_count, max } => write!(
                f,
                "task_count {task_count} exceeds first-slice safety cap {max}"
            ),
            Self::CancelStepBeyondMax {
                cancel_after_steps,
                max_steps,
            } => write!(
                f,
                "cancel_after_steps {cancel_after_steps} must be less than max_steps {max_steps}"
            ),
            Self::ArtifactByteCountOverflow => f.write_str("artifact byte count overflowed usize"),
            Self::ChannelOperationCountOverflow => {
                f.write_str("channel operation count overflowed usize")
            }
            Self::SemaphoreOperationCountOverflow => {
                f.write_str("semaphore operation count overflowed usize")
            }
            Self::PoolOperationCountOverflow => {
                f.write_str("pool operation count overflowed usize")
            }
            Self::ObligationCountOverflow => f.write_str("obligation count overflowed usize"),
            Self::TimerTickCountOverflow => f.write_str("timer tick count overflowed usize"),
            Self::RegionBudgetUnitOverflow => {
                f.write_str("region capability-budget unit count overflowed u64")
            }
            Self::RegionCleanupPollQuotaOverflow => {
                f.write_str("region cleanup poll quota exceeds u32::MAX")
            }
            Self::InvalidOverLimitAcceptDecision => {
                f.write_str("over-limit admission decision cannot be accept")
            }
            Self::RegionCreateRejected {
                region_index,
                reason,
            } => write!(f, "region {region_index} creation rejected: {reason}"),
            Self::TaskSpawnRejected {
                region_index,
                task_index,
                reason,
            } => write!(
                f,
                "task {task_index} in region {region_index} creation rejected: {reason}"
            ),
        }
    }
}

impl std::error::Error for SwarmReplayError {}

/// Stable event kind emitted by a swarm replay scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmReplayEventKind {
    /// A region admission was accepted.
    AdmissionAccepted,
    /// A region admission deferred excess work.
    AdmissionDeferred,
    /// A region admission shed excess work.
    AdmissionShed,
    /// A region admission cancelled admitted work to drain safely.
    AdmissionCancelled,
    /// A task was inserted into the lab scheduler.
    TaskScheduled,
    /// A task modeled bounded channel reservation pressure.
    MessageReserved,
    /// A task modeled committing reserved channel sends.
    MessageCommitted,
    /// A task modeled aborting reserved channel sends after cancellation.
    MessageAborted,
    /// A task modeled taking semaphore permits.
    SemaphoreAcquired,
    /// A task modeled checking out object-pool slots.
    PoolSlotCheckedOut,
    /// A task modeled virtual timer wakeups.
    TimerAdvanced,
    /// A task modeled committing linear obligations.
    ObligationCommitted,
    /// A task modeled aborting linear obligations after cancellation.
    ObligationAborted,
    /// A region cancellation request was issued through runtime state.
    CancellationRequested,
    /// A task observed cancellation at a `Cx` checkpoint.
    CancelObserved,
    /// A task reached normal completion.
    Completed,
    /// A task modeled proof/trace artifact emission.
    ArtifactEmitted,
}

/// One deterministic event in the swarm replay summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayEvent {
    /// Stable event kind.
    pub kind: SwarmReplayEventKind,
    /// Region ordinal from the scenario.
    pub region_index: usize,
    /// Runtime region id when the event has an admitted region.
    pub region_id: Option<u64>,
    /// Task ordinal within the region when the event is task-local.
    pub task_index: Option<usize>,
    /// Global task ordinal when the event is task-local.
    pub global_task_index: Option<usize>,
    /// Budget class associated with admission events.
    pub budget_class: Option<SwarmReplayBudgetClass>,
    /// Modeled queue depth after this event.
    pub queue_depth: usize,
    /// Modeled artifact bytes associated with this event.
    pub artifact_bytes: usize,
}

/// Budget class surfaced by deterministic region-admission evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmReplayBudgetClass {
    /// Runnable task slots in a region.
    RunnableTaskSlots,
    /// Region-local queue-depth envelope.
    QueueDepth,
    /// Region memory-estimate envelope.
    MemoryEnvelope,
    /// Blocking-pool submission envelope.
    BlockingPoolSubmissions,
    /// Cleanup/drain work budget.
    CleanupDrainWork,
    /// Artifact/proof byte envelope.
    ArtifactBytes,
}

/// Region admission decision surfaced in swarm replay evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SwarmReplayAdmissionDecision {
    /// Admit all requested work.
    Accept,
    /// Defer over-limit work for a later wave.
    Defer,
    /// Shed over-limit work.
    #[default]
    Shed,
    /// Cancel admitted prefix work so the region drains safely.
    Cancel,
}

/// Drain result associated with an admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmReplayAdmissionDrainResult {
    /// No cancellation/drain step was required.
    NotRequired,
    /// Admission failed before a child region was allocated.
    RefusedBeforeRegion,
    /// Cancellation was requested and the runtime still needs to report.
    CancellationRequested,
    /// Cancellation was requested and the lab run reached quiescence.
    Quiescent,
}

/// Byte-stable admission evidence for one region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayAdmissionRecord {
    /// Region ordinal from the scenario.
    pub region_index: usize,
    /// Runtime region id, absent when admission failed before region creation.
    pub region_id: Option<u64>,
    /// Budget class that made the admission decision.
    pub budget_class: SwarmReplayBudgetClass,
    /// Final admission decision.
    pub decision: SwarmReplayAdmissionDecision,
    /// Requested tasks for this region.
    pub requested_tasks: usize,
    /// Tasks admitted and scheduled for this region.
    pub admitted_tasks: usize,
    /// Tasks rejected/deferred/shed/cancelled by admission.
    pub rejected_tasks: usize,
    /// Remaining runnable-task slots before admission.
    pub before_remaining_units: usize,
    /// Remaining runnable-task slots after admission.
    pub after_remaining_units: usize,
    /// Refusal reason from capability-budget planning, if any.
    pub refusal: Option<String>,
    /// Whether admission requested runtime cancellation.
    pub cancellation_requested: bool,
    /// Cancellation/drain result for this admission record.
    pub drain_result: SwarmReplayAdmissionDrainResult,
    /// Runtime quiescence verdict after the lab run.
    pub quiescence_verdict: bool,
}

/// Terminal task status recorded by the scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmReplayTaskStatus {
    /// The task completed normally.
    Completed,
    /// The task observed cancellation and returned.
    Cancelled,
}

/// Stable terminal outcome for one modeled task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayTaskOutcome {
    /// Global task ordinal.
    pub global_task_index: usize,
    /// Region ordinal from the scenario.
    pub region_index: usize,
    /// Task ordinal within the region.
    pub task_index: usize,
    /// Terminal task status.
    pub status: SwarmReplayTaskStatus,
    /// Cooperative poll/yield points attempted by the task.
    pub yield_points: usize,
}

/// Work lane modeled by the swarm pressure simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPressureLane {
    /// Latency-sensitive interactive agent edits and source-only checks.
    Interactive,
    /// Artifact-producing proof or Cargo validation work.
    Proof,
    /// Explicit cleanup requests that must remain report-only until authorized.
    Cleanup,
}

/// Coarse disk-pressure state for admission simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmDiskPressureLevel {
    /// Normal disk pressure.
    Green,
    /// Red/critical disk pressure where artifact-heavy work is unsafe.
    Red,
}

/// A deterministic disk-pressure transition at a lab step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDiskPressureTransition {
    /// Lab step where this pressure state becomes active.
    pub at_step: u64,
    /// Disk-pressure state after this transition.
    pub level: SwarmDiskPressureLevel,
}

/// RCH worker availability event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmRchWorkerEventKind {
    /// Remote workers became unavailable.
    Loss,
    /// Remote workers recovered.
    Recovery,
}

/// A deterministic RCH worker availability transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRchWorkerEvent {
    /// Lab step where this worker event becomes active.
    pub at_step: u64,
    /// Event kind.
    pub kind: SwarmRchWorkerEventKind,
    /// Number of logical remote workers lost or recovered.
    pub worker_delta: usize,
}

/// Deterministic knobs for the high-concurrency pressure simulator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureScenario {
    /// Stable scenario identifier used in JSON evidence.
    pub scenario_id: String,
    /// Lab runtime seed.
    pub seed: u64,
    /// Logical worker count modeled by [`LabConfig`].
    pub worker_count: usize,
    /// Sustained latency-sensitive interactive tasks.
    pub interactive_tasks: usize,
    /// Bursty artifact-producing proof tasks.
    pub proof_tasks: usize,
    /// Report-only cleanup requests.
    pub cleanup_requests: usize,
    /// Remote RCH workers available before worker events are applied.
    pub rch_workers_initial: usize,
    /// Disk-pressure transitions applied by lab step.
    pub disk_pressure_transitions: Vec<SwarmDiskPressureTransition>,
    /// Remote worker loss/recovery events applied by lab step.
    pub rch_worker_events: Vec<SwarmRchWorkerEvent>,
    /// Maximum allowed modeled interactive admission latency.
    pub interactive_latency_bound_steps: u64,
    /// Maximum lab steps before the runtime stops.
    pub max_steps: u64,
}

impl Default for SwarmPressureScenario {
    fn default() -> Self {
        Self {
            scenario_id: "swarm-pressure-default".to_string(),
            seed: 0x64C0_A11D,
            worker_count: 64,
            interactive_tasks: 64,
            proof_tasks: 32,
            cleanup_requests: 2,
            rch_workers_initial: 8,
            disk_pressure_transitions: vec![
                SwarmDiskPressureTransition {
                    at_step: 0,
                    level: SwarmDiskPressureLevel::Green,
                },
                SwarmDiskPressureTransition {
                    at_step: 4,
                    level: SwarmDiskPressureLevel::Red,
                },
                SwarmDiskPressureTransition {
                    at_step: 16,
                    level: SwarmDiskPressureLevel::Green,
                },
            ],
            rch_worker_events: vec![
                SwarmRchWorkerEvent {
                    at_step: 6,
                    kind: SwarmRchWorkerEventKind::Loss,
                    worker_delta: 8,
                },
                SwarmRchWorkerEvent {
                    at_step: 20,
                    kind: SwarmRchWorkerEventKind::Recovery,
                    worker_delta: 8,
                },
            ],
            interactive_latency_bound_steps: 4,
            max_steps: 50_000,
        }
    }
}

impl SwarmPressureScenario {
    /// Validate that the pressure scenario is bounded and replayable.
    pub fn validate(&self) -> Result<(), SwarmReplayError> {
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmReplayError::EmptyScenarioId);
        }
        if self.worker_count == 0 {
            return Err(SwarmReplayError::ZeroWorkerCount);
        }
        if self.interactive_tasks == 0 {
            return Err(SwarmReplayError::ZeroInteractiveTasks);
        }
        if self.interactive_latency_bound_steps == 0 {
            return Err(SwarmReplayError::ZeroInteractiveLatencyBound);
        }
        if self.max_steps == 0 {
            return Err(SwarmReplayError::ZeroMaxSteps);
        }

        let task_count = self
            .interactive_tasks
            .saturating_add(self.proof_tasks)
            .saturating_add(self.cleanup_requests);
        if task_count > MAX_FIRST_SLICE_TASKS {
            return Err(SwarmReplayError::TooManyTasks {
                task_count,
                max: MAX_FIRST_SLICE_TASKS,
            });
        }
        if let Some(event) = self
            .rch_worker_events
            .iter()
            .find(|event| event.worker_delta == 0)
        {
            return Err(SwarmReplayError::ZeroRchWorkerDelta {
                at_step: event.at_step,
            });
        }

        Ok(())
    }
}

/// Stable event kind emitted by the pressure simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPressureEventKind {
    /// Disk pressure changed.
    DiskPressureChanged,
    /// Remote RCH workers were lost.
    RchWorkersLost,
    /// Remote RCH workers recovered.
    RchWorkersRecovered,
    /// Interactive work was admitted.
    InteractiveAdmitted,
    /// Proof work was admitted.
    ProofAdmitted,
    /// Proof work was throttled because artifact-heavy work was unsafe.
    ProofThrottled,
    /// Cleanup work was requested in report-only mode.
    CleanupRequested,
}

/// One deterministic pressure-simulator event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureEvent {
    /// Stable event kind.
    pub kind: SwarmPressureEventKind,
    /// Lab step associated with this event.
    pub step: u64,
    /// Lane associated with this event, when applicable.
    pub lane: Option<SwarmPressureLane>,
    /// Queue depth after the event.
    pub queue_depth: usize,
    /// Remote RCH workers available after applying the event.
    pub rch_workers_available: usize,
    /// Disk pressure visible at the event step.
    pub disk_pressure: SwarmDiskPressureLevel,
    /// Modeled admission latency in lab steps.
    pub admission_latency_steps: u64,
    /// Whether cleanup was explicitly authorized.
    pub cleanup_authorized: bool,
    /// Auto-delete command count emitted by the simulator.
    pub auto_delete_command_count: usize,
}

/// Byte-stable summary emitted by the high-concurrency pressure simulator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureSummary {
    /// Stable schema version.
    pub schema_version: String,
    /// Scenario id copied from input.
    pub scenario_id: String,
    /// Lab runtime seed.
    pub seed: u64,
    /// Logical worker count modeled by the run.
    pub worker_count: usize,
    /// Number of interactive tasks submitted.
    pub interactive_tasks: usize,
    /// Number of proof tasks submitted.
    pub proof_tasks: usize,
    /// Number of cleanup requests submitted.
    pub cleanup_requests: usize,
    /// Maximum modeled interactive admission latency.
    pub max_interactive_admission_latency_steps: u64,
    /// Bound used for interactive admission latency.
    pub interactive_latency_bound_steps: u64,
    /// Number of proof submissions throttled by disk/RCH pressure.
    pub proof_throttled_count: usize,
    /// Number of cleanup requests left pending human authorization.
    pub cleanup_authorization_required_count: usize,
    /// Auto-delete command count emitted by the simulator.
    pub auto_delete_command_count: usize,
    /// Number of disk-pressure transitions observed.
    pub disk_pressure_transition_count: usize,
    /// Number of RCH worker-loss events observed.
    pub rch_worker_loss_events: usize,
    /// Number of RCH worker-recovery events observed.
    pub rch_worker_recovery_events: usize,
    /// Number of tasks scheduled into [`LabRuntime`].
    pub scheduled_task_count: usize,
    /// Number of tracked tasks that reached a terminal state.
    pub terminal_task_count: usize,
    /// Number of tracked tasks still non-terminal after the run.
    pub non_terminal_task_count: usize,
    /// Task leak count derived from non-terminal tracked tasks.
    pub task_leaks: usize,
    /// Whether the lab runtime reached quiescence.
    pub quiescent: bool,
    /// Canonical trace fingerprint from the lab run report.
    pub trace_fingerprint: u64,
    /// Trace event count from the lab run report.
    pub trace_event_count: usize,
    /// Runtime invariant violations from the lab run report.
    pub invariant_violations: Vec<String>,
    /// Deterministic event log for dashboard/future artifact consumers.
    pub event_log: Vec<SwarmPressureEvent>,
}

/// Source artifact kind consumed by the pressure trace summarizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPressureTraceSourceKind {
    /// A [`SwarmReplaySummary`] artifact with region/obligation details.
    ReplayLab,
    /// A [`SwarmPressureSummary`] artifact with pressure/admission details.
    PressureLab,
    /// A [`SwarmAgentRunSummary`] artifact with e2e agent-run details.
    AgentRun,
    /// The artifact schema was missing or not recognized.
    Unknown,
}

/// Fail-closed verdict emitted by the pressure trace summarizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPressureTraceVerdict {
    /// Required fields were present and no invariant, task, or obligation leak was observed.
    Pass,
    /// Required fields were present but the artifact reports a concrete failure.
    Fail,
    /// The artifact can be summarized, but required proof fields are absent.
    Incomplete,
}

/// Region lifecycle counters extracted from a pressure trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceRegionLifecycle {
    /// Regions declared by the source artifact.
    pub regions_declared: usize,
    /// Regions with a runtime id in the artifact.
    pub regions_with_runtime_id: usize,
    /// Region admission records that reached a quiescent verdict.
    pub quiescent_regions: usize,
    /// Region admission records that did not prove quiescence.
    pub non_quiescent_regions: usize,
}

/// Task lifecycle counters extracted from a pressure trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceTaskLifecycle {
    /// Submitted task count when known.
    pub submitted_tasks: usize,
    /// Tasks scheduled into the lab runtime.
    pub scheduled_tasks: usize,
    /// Tasks that reached a terminal state.
    pub terminal_tasks: usize,
    /// Tasks still non-terminal at the end of the source run.
    pub non_terminal_tasks: usize,
    /// Task leaks derived from non-terminal tasks.
    pub task_leaks: usize,
}

/// Cancellation and drain counters extracted from a pressure trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceCancellation {
    /// Cancellation requests modeled by the source artifact.
    pub cancellation_requests: usize,
    /// Tasks that explicitly observed cancellation.
    pub cancelled_tasks: usize,
    /// Scheduler steps spent after explicit cancellation was requested.
    pub cancellation_drain_steps: u64,
    /// Whether cancellation losers drained to a terminal state.
    pub losers_drained: bool,
}

/// Obligation counters extracted from a pressure trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceObligations {
    /// Whether obligation fields were present in the source artifact.
    pub fields_present: bool,
    /// Modeled obligations resolved by commit or abort.
    pub resolved_obligations: usize,
    /// Modeled obligations committed by completed tasks.
    pub committed_obligations: usize,
    /// Modeled obligations aborted by cancelled tasks.
    pub aborted_obligations: usize,
    /// Obligations suspected to be unresolved.
    pub unresolved_obligations: usize,
}

/// Queue pressure counters extracted from a pressure trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceQueuePressure {
    /// Maximum modeled queue depth in the event log.
    pub peak_queue_depth: usize,
    /// Number of events that carried non-zero queue pressure.
    pub pressure_event_count: usize,
    /// Stable scope for the peak queue event.
    pub peak_scope: Option<String>,
}

/// Admission and combiner-style decision counters extracted from a trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceAdmission {
    /// Region or lane admissions accepted.
    pub accepted: usize,
    /// Region admissions deferred.
    pub deferred: usize,
    /// Region admissions shed.
    pub shed: usize,
    /// Region admissions that cancelled admitted work.
    pub cancelled: usize,
    /// Proof-lane admissions accepted.
    pub proof_admitted: usize,
    /// Proof-lane admissions throttled.
    pub proof_throttled: usize,
    /// Interactive-lane admissions accepted.
    pub interactive_admitted: usize,
    /// Cleanup requests observed.
    pub cleanup_requested: usize,
    /// Total admission/combiner decisions represented in the artifact.
    pub combiner_or_admission_decisions: usize,
    /// First refusal or blocker that should route a follow-up bead.
    pub first_rejection: Option<String>,
}

/// Cleanup latency and authorization counters extracted from a trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceCleanup {
    /// Cleanup requests observed.
    pub cleanup_requests: usize,
    /// Cleanup requests left pending authorization.
    pub authorization_required: usize,
    /// Cleanup requests explicitly authorized.
    pub authorized: usize,
    /// Maximum modeled cleanup latency in lab steps.
    pub max_cleanup_latency_steps: u64,
    /// Whether the artifact attempted an auto-delete operation.
    pub auto_delete_command_count: usize,
}

/// Region hotspot emitted by the pressure trace summarizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceHotRegion {
    /// Region ordinal from the source artifact.
    pub region_index: usize,
    /// Runtime region id, when available.
    pub region_id: Option<u64>,
    /// Event count attributed to this region.
    pub event_count: usize,
    /// Task count attributed to this region.
    pub task_count: usize,
    /// Cancelled task count attributed to this region.
    pub cancelled_task_count: usize,
    /// Peak modeled queue depth attributed to this region.
    pub queue_peak: usize,
    /// Admission decisions attributed to this region.
    pub admission_decision_count: usize,
    /// Stable follow-up routing hint.
    pub route_hint: String,
}

/// Drain hotspot emitted by the pressure trace summarizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceDrainHotSpot {
    /// Scope for the drain hotspot.
    pub scope: String,
    /// Modeled drain latency in lab steps.
    pub drain_steps: u64,
    /// Whether the scope proved quiescent.
    pub quiescent: bool,
    /// Stable reason for surfacing the hotspot.
    pub reason: String,
}

/// Queue hotspot emitted by the pressure trace summarizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceQueueHotSpot {
    /// Scope for the queue hotspot.
    pub scope: String,
    /// Modeled queue depth at the hotspot.
    pub queue_depth: usize,
    /// Stable event kind or lane that produced the hotspot.
    pub event_kind: String,
    /// Stable follow-up routing hint.
    pub route_hint: String,
}

/// Obligation leak suspect emitted by the pressure trace summarizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceObligationLeakSuspect {
    /// Scope for the suspect.
    pub scope: String,
    /// Suspected unresolved obligation count.
    pub unresolved_obligations: usize,
    /// Stable evidence string suitable for closeout logs.
    pub evidence: String,
    /// Stable follow-up routing hint.
    pub route_hint: String,
}

/// Operator-readable summary extracted from a pressure-lab or e2e trace artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPressureTraceSummary {
    /// Stable schema version.
    pub schema_version: String,
    /// Source schema version copied from the artifact.
    pub source_schema_version: String,
    /// Source artifact kind.
    pub source_kind: SwarmPressureTraceSourceKind,
    /// Scenario id copied from the source artifact when present.
    pub scenario_id: String,
    /// Seed copied from the source artifact when present.
    pub seed: u64,
    /// Fail-closed summary verdict.
    pub verdict: SwarmPressureTraceVerdict,
    /// Whether all fields required for a pass verdict were present.
    pub required_fields_present: bool,
    /// Required fields missing from the source artifact.
    pub missing_required_fields: Vec<String>,
    /// First invariant violation reported by the runtime.
    pub first_invariant_violation: Option<String>,
    /// Region lifecycle counters.
    pub region_lifecycle: SwarmPressureTraceRegionLifecycle,
    /// Task lifecycle counters.
    pub task_lifecycle: SwarmPressureTraceTaskLifecycle,
    /// Cancellation and drain counters.
    pub cancellation: SwarmPressureTraceCancellation,
    /// Obligation counters.
    pub obligations: SwarmPressureTraceObligations,
    /// Queue pressure counters.
    pub queue_pressure: SwarmPressureTraceQueuePressure,
    /// Admission and combiner-style decisions.
    pub admission: SwarmPressureTraceAdmission,
    /// Cleanup counters.
    pub cleanup: SwarmPressureTraceCleanup,
    /// Hottest regions by event count and queue pressure.
    pub top_hot_regions: Vec<SwarmPressureTraceHotRegion>,
    /// Longest drain scopes.
    pub longest_drains: Vec<SwarmPressureTraceDrainHotSpot>,
    /// Largest queue scopes.
    pub largest_queues: Vec<SwarmPressureTraceQueueHotSpot>,
    /// Obligation leak suspects.
    pub obligation_leak_suspects: Vec<SwarmPressureTraceObligationLeakSuspect>,
    /// Stable follow-up routing hints for agents.
    pub routing_hints: Vec<String>,
}

/// Verdict emitted by the swarm contention heatmap ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmContentionHeatmapVerdict {
    /// Required trace, lock, and scheduler fields were present with nominal hotspots.
    Pass,
    /// Required fields were present, but at least one hotspot needs operator attention.
    Degraded,
    /// Required trace, lock, or scheduler evidence was missing.
    Incomplete,
    /// Required fields were present, but the baseline is too old to compare safely.
    StaleEvidence,
}

/// Contention severity class used by heatmap rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmContentionSeverity {
    /// No meaningful contention signal.
    Nominal,
    /// Low contention worth observing.
    Watch,
    /// Elevated contention that should be routed to an owner.
    Warning,
    /// Critical contention or stale/missing proof inputs.
    Critical,
}

/// Hotspot source kind in the heatmap ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmContentionHotspotKind {
    /// ContendedMutex wait/hold metric row.
    Lock,
    /// Scheduler lane metric row.
    SchedulerLane,
    /// Region hotspot derived from a swarm pressure trace summary.
    Region,
    /// Queue hotspot derived from a swarm pressure trace summary.
    Queue,
}

/// Serializable lock metric row consumed by the heatmap planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmContentionLockMetric {
    /// Human-readable lock name.
    pub name: String,
    /// Successful lock acquisitions.
    pub acquisitions: u64,
    /// Contended acquisitions.
    pub contentions: u64,
    /// Cumulative wait duration.
    pub wait_ns: u64,
    /// Cumulative hold duration.
    pub hold_ns: u64,
    /// Maximum observed wait duration.
    pub max_wait_ns: u64,
    /// Maximum observed hold duration.
    pub max_hold_ns: u64,
    /// Median or average wait duration when known.
    pub p50_wait_ns: u64,
    /// p95 wait duration.
    pub p95_wait_ns: u64,
    /// p99 wait duration, or the nearest stricter percentile available.
    pub p99_wait_ns: u64,
    /// p95 hold duration.
    pub p95_hold_ns: u64,
    /// p99 hold duration, or the nearest stricter percentile available.
    pub p99_hold_ns: u64,
    /// Instrumentation mode from the lock metric source.
    pub instrumentation_mode: String,
}

impl SwarmContentionLockMetric {
    /// Convert a live [`crate::sync::LockMetricsSnapshot`] into a ledger row.
    #[must_use]
    pub fn from_lock_metrics_snapshot(snapshot: &crate::sync::LockMetricsSnapshot) -> Self {
        let p50_wait_ns = if snapshot.acquisitions == 0 {
            0
        } else {
            snapshot.wait_ns / snapshot.acquisitions
        };

        Self {
            name: snapshot.name.to_string(),
            acquisitions: snapshot.acquisitions,
            contentions: snapshot.contentions,
            wait_ns: snapshot.wait_ns,
            hold_ns: snapshot.hold_ns,
            max_wait_ns: snapshot.max_wait_ns,
            max_hold_ns: snapshot.max_hold_ns,
            p50_wait_ns,
            p95_wait_ns: snapshot.p95_wait_ns,
            p99_wait_ns: snapshot.p999_wait_ns,
            p95_hold_ns: snapshot.p95_hold_ns,
            p99_hold_ns: snapshot.p999_hold_ns,
            instrumentation_mode: snapshot.instrumentation_mode.to_string(),
        }
    }
}

/// Scheduler lane metric row consumed by the heatmap planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmContentionSchedulerLaneMetric {
    /// Stable lane identifier.
    pub lane_id: String,
    /// Number of tasks dispatched by this lane.
    pub dispatched_tasks: u64,
    /// p50 lane wait duration.
    pub p50_wait_ns: u64,
    /// p95 lane wait duration.
    pub p95_wait_ns: u64,
    /// p99 lane wait duration.
    pub p99_wait_ns: u64,
    /// p50 queue depth.
    pub queue_depth_p50: u64,
    /// p95 queue depth.
    pub queue_depth_p95: u64,
    /// p99 queue depth.
    pub queue_depth_p99: u64,
    /// Number of steal attempts attributed to this lane.
    pub steal_attempts: u64,
    /// Number of fairness/starvation yields attributed to this lane.
    pub fairness_yields: u64,
}

/// Ranked heatmap row across locks, lanes, regions, and queues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmContentionHotSpot {
    /// Stable row key.
    pub key: String,
    /// Source kind for this row.
    pub kind: SwarmContentionHotspotKind,
    /// Severity class.
    pub severity: SwarmContentionSeverity,
    /// Deterministic impact score used for sorting.
    pub impact_score: u64,
    /// p50 wait duration when available.
    pub p50_wait_ns: Option<u64>,
    /// p95 wait duration when available.
    pub p95_wait_ns: Option<u64>,
    /// p99 wait duration when available.
    pub p99_wait_ns: Option<u64>,
    /// p95 queue depth when available.
    pub queue_depth_p95: Option<u64>,
    /// p99 queue depth when available.
    pub queue_depth_p99: Option<u64>,
    /// Contention count when available.
    pub contentions: Option<u64>,
    /// Region id or trace scope when available.
    pub region_or_scope: Option<String>,
    /// Stable evidence string for logs and Agent Mail.
    pub evidence: String,
    /// Suggested owner surface.
    pub owner_surface: String,
    /// Suggested owner bead or follow-up thread.
    pub owner_bead_hint: String,
}

/// Input for building an operator-readable contention heatmap ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmContentionHeatmapInput {
    /// Stable ledger id.
    pub ledger_id: String,
    /// Optional baseline id used for stale-evidence detection.
    pub baseline_id: Option<String>,
    /// Age of the baseline in seconds.
    pub baseline_age_secs: u64,
    /// Maximum acceptable baseline age in seconds.
    pub max_baseline_age_secs: u64,
    /// Trace summary consumed by this ledger.
    pub trace_summary: Option<SwarmPressureTraceSummary>,
    /// Lock metrics consumed by this ledger.
    pub lock_metrics: Vec<SwarmContentionLockMetric>,
    /// Scheduler lane metrics consumed by this ledger.
    pub scheduler_lanes: Vec<SwarmContentionSchedulerLaneMetric>,
    /// Stable trace ids or artifact ids consumed by this ledger.
    pub source_trace_ids: Vec<String>,
    /// Proof command that validates this ledger surface.
    pub proof_command: Option<String>,
}

/// Operator-readable contention heatmap report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmContentionHeatmapLedger {
    /// Stable schema version.
    pub schema_version: String,
    /// Ledger id copied from the input.
    pub ledger_id: String,
    /// Source scenario id copied from the trace summary when present.
    pub scenario_id: Option<String>,
    /// Baseline id copied from the input.
    pub baseline_id: Option<String>,
    /// Whether the baseline is older than the accepted bound.
    pub stale_baseline: bool,
    /// Heatmap verdict.
    pub verdict: SwarmContentionHeatmapVerdict,
    /// Highest severity observed in ranked hotspots.
    pub max_severity: SwarmContentionSeverity,
    /// Whether every required evidence family was present.
    pub required_fields_present: bool,
    /// Missing required fields.
    pub missing_required_fields: Vec<String>,
    /// Stable trace ids or artifact ids consumed by this ledger.
    pub source_trace_ids: Vec<String>,
    /// Proof command copied from the input.
    pub proof_command: Option<String>,
    /// Ranked lock hotspots.
    pub lock_hotspots: Vec<SwarmContentionHotSpot>,
    /// Ranked scheduler lane hotspots.
    pub scheduler_lane_hotspots: Vec<SwarmContentionHotSpot>,
    /// Ranked region hotspots.
    pub region_hotspots: Vec<SwarmContentionHotSpot>,
    /// Ranked queue hotspots.
    pub queue_hotspots: Vec<SwarmContentionHotSpot>,
    /// Top cross-family hotspots.
    pub top_hotspots: Vec<SwarmContentionHotSpot>,
    /// Stable routing hints for agents.
    pub routing_hints: Vec<String>,
}

/// Final fail-closed outcome for an operator cockpit report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOperatorCockpitOutcome {
    /// Required evidence is present and all reported verdicts are nominal.
    Pass,
    /// Required evidence is present, but one or more lanes need operator attention.
    Degraded,
    /// The modeled run exhausted the deterministic brownout policy.
    NoWin,
    /// Required live proof evidence is not available yet.
    Blocked,
    /// Evidence was captured against stale source state or stale baselines.
    StaleEvidence,
    /// Required report fields are missing or redaction is not preserved.
    Malformed,
    /// The requested report shape is outside the supported cockpit policy.
    Unsupported,
}

/// Memory and brownout state copied into an operator cockpit report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOperatorCockpitMemoryDecision {
    /// No brownout was required.
    Nominal,
    /// Optional work was shed while the core invariant evidence remained valid.
    BrownoutOptional,
    /// The modeled run has no winning admission policy under current pressure.
    NoWin,
    /// The source evidence cannot support a cockpit memory decision.
    Unsupported,
}

/// Obligation verdict projected into the cockpit report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOperatorCockpitObligationVerdict {
    /// Obligation fields were present and every obligation resolved.
    Clean,
    /// Obligation fields were present, but unresolved obligations remain.
    LeakSuspect,
    /// Obligation fields were absent from the source trace.
    Missing,
    /// The trace itself was incomplete, so the obligation verdict is not reliable.
    Incomplete,
}

/// Compact proof-lane row embedded in an operator cockpit report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorCockpitProofLaneSummary {
    /// Stable proof-lane id.
    pub lane_id: String,
    /// Planner decision copied from the proof lane.
    pub decision: SwarmProofLaneDecision,
    /// Whether remote RCH execution was mandatory for the lane.
    pub remote_required: bool,
    /// Whether remote RCH worker provenance was observed.
    pub remote_observed: bool,
    /// Whether expected and observed HEAD evidence disagreed.
    pub stale_head: bool,
    /// Exact command copied from the proof lane.
    pub command: String,
    /// Cargo target directory copied from the proof lane.
    pub target_dir: String,
}

/// Input consumed by the deterministic operator cockpit report builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorCockpitInput {
    /// Stable report id.
    pub report_id: String,
    /// Scenario that produced the reported swarm run.
    pub scenario: Option<SwarmReplayScenario>,
    /// Trace summary carrying quiescence, cancellation, and obligation evidence.
    pub trace_summary: Option<SwarmPressureTraceSummary>,
    /// Remote-only proof lanes that validate the report.
    pub proof_lanes: Vec<SwarmProofLanePlan>,
    /// Contention ledger for lock, scheduler, region, and queue hotspots.
    pub contention_ledger: Option<SwarmContentionHeatmapLedger>,
    /// Optional minimized failure report for first-failure routing.
    pub minimizer_report: Option<SwarmFailureMinimizerReport>,
    /// Memory and brownout decision observed for the run.
    pub memory_decision: SwarmOperatorCockpitMemoryDecision,
    /// Operator-readable reason for the memory decision.
    pub memory_decision_reason: Option<String>,
    /// p50 latency in nanoseconds when known.
    pub latency_p50_ns: Option<u64>,
    /// p95 latency in nanoseconds when known.
    pub latency_p95_ns: Option<u64>,
    /// p99 latency in nanoseconds when known.
    pub latency_p99_ns: Option<u64>,
    /// Coefficient of variation in basis points when known.
    pub latency_cv_bps: Option<u16>,
    /// Source artifacts consumed by this report.
    pub source_artifacts: Vec<String>,
    /// Redaction policy applied before report publication.
    pub redaction_policy_id: Option<String>,
    /// Count of secret-like values that remain unredacted.
    pub secret_like_value_count: usize,
    /// Agent, harness, or release lane that generated the report.
    pub generated_by: String,
}

/// Stable operator cockpit report suitable for Agent Mail and release evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorCockpitReport {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable report id.
    pub report_id: String,
    /// Scenario id copied from the scenario when present.
    pub scenario_id: Option<String>,
    /// Replay seed copied from the scenario when present.
    pub seed: Option<u64>,
    /// Worker count copied from the scenario when present.
    pub worker_count: Option<usize>,
    /// Region count copied from the scenario when present.
    pub region_count: Option<usize>,
    /// Modeled task count copied from the scenario when present.
    pub task_count: Option<usize>,
    /// Final cockpit outcome.
    pub outcome: SwarmOperatorCockpitOutcome,
    /// Whether every required evidence family was present.
    pub required_fields_present: bool,
    /// Required evidence fields that were absent or rejected.
    pub missing_required_fields: Vec<String>,
    /// Whether region close reached quiescence when known.
    pub quiescent: Option<bool>,
    /// Obligation verdict copied from the trace summary.
    pub obligation_verdict: SwarmOperatorCockpitObligationVerdict,
    /// Number of unresolved obligations when known.
    pub unresolved_obligations: Option<usize>,
    /// Trace verdict copied from the trace summary.
    pub trace_verdict: Option<SwarmPressureTraceVerdict>,
    /// Compact proof-lane rows.
    pub proof_lanes: Vec<SwarmOperatorCockpitProofLaneSummary>,
    /// Count of proof lanes attached to the report.
    pub proof_lane_count: usize,
    /// Count of proof lanes that are ready and fresh.
    pub ready_proof_lane_count: usize,
    /// Proof-lane ids with stale HEAD evidence.
    pub stale_proof_lane_ids: Vec<String>,
    /// Proof-lane ids that block publication.
    pub blocked_proof_lane_ids: Vec<String>,
    /// Whether every remote-required proof lane observed remote provenance.
    pub rch_remote_provenance_observed: bool,
    /// p50 latency in nanoseconds when known.
    pub latency_p50_ns: Option<u64>,
    /// p95 latency in nanoseconds when known.
    pub latency_p95_ns: Option<u64>,
    /// p99 latency in nanoseconds when known.
    pub latency_p99_ns: Option<u64>,
    /// Coefficient of variation in basis points when known.
    pub latency_cv_bps: Option<u16>,
    /// Memory and brownout decision observed for the run.
    pub memory_decision: SwarmOperatorCockpitMemoryDecision,
    /// Operator-readable reason for the memory decision.
    pub memory_decision_reason: Option<String>,
    /// Contention verdict copied from the heatmap ledger when present.
    pub contention_verdict: Option<SwarmContentionHeatmapVerdict>,
    /// Maximum contention severity copied from the heatmap ledger when present.
    pub contention_max_severity: Option<SwarmContentionSeverity>,
    /// Highest-ranked contention hotspots.
    pub contention_hotspots: Vec<SwarmContentionHotSpot>,
    /// Minimizer verdict copied from the failure minimizer when present.
    pub minimizer_verdict: Option<SwarmFailureMinimizerVerdict>,
    /// Minimizer stop reason copied from the failure minimizer when present.
    pub minimizer_stop_reason: Option<SwarmFailureMinimizerStopReason>,
    /// Minimized scenario id when a minimizer report is present.
    pub minimized_scenario_id: Option<String>,
    /// First invariant violation or first failure.
    pub first_invariant_violation: Option<String>,
    /// Suggested next owner bead.
    pub next_owner_bead: String,
    /// Stable routing hints for operators and agents.
    pub routing_hints: Vec<String>,
    /// Source artifacts consumed by this report.
    pub source_artifacts: Vec<String>,
    /// Redaction policy applied before report publication.
    pub redaction_policy_id: Option<String>,
    /// Whether redaction requirements were preserved.
    pub redaction_preserved: bool,
    /// Agent, harness, or release lane that generated the report.
    pub generated_by: String,
    /// Cockpit reports never request destructive cleanup.
    pub destructive_cleanup_required: bool,
    /// Cockpit reports never request branch or worktree creation.
    pub branch_or_worktree_required: bool,
}

/// Failure family the deterministic minimizer preserves while shrinking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFailureInvariantClass {
    /// Cancellation request, loser drain, or cancellation storm failure.
    CancellationStorm,
    /// Scheduler deadlock or lost-wakeup suspect.
    DeadlockOrLostWakeup,
    /// Obligation commit/abort accounting leak suspect.
    ObligationLeak,
    /// Admission or shedding decision failure.
    AdmissionFailure,
    /// Queue pressure or region hotspot failure.
    QueuePressure,
    /// Generic runtime invariant violation.
    InvariantViolation,
}

/// Final fail-closed verdict from the swarm failure minimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFailureMinimizerVerdict {
    /// Evidence proves the invariant still reproduces after shrinking.
    Minimized,
    /// Evidence reproduces, but every modeled knob is already at its lower bound.
    AlreadyMinimal,
    /// The reported failure did not reproduce in the supplied trace verdict.
    NonReproducible,
    /// Required evidence, provenance, or redaction state is missing.
    Incomplete,
}

/// Explicit reason the minimizer stopped shrinking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFailureMinimizerStopReason {
    /// The minimized scenario kept the supplied invariant reproduction proof.
    InvariantPreserved,
    /// The input scenario already matched the minimizer lower bounds.
    AlreadyMinimal,
    /// The supplied trace verdict did not reproduce the failure.
    NonReproducible,
    /// Required evidence or proof-lane provenance was missing.
    MissingEvidence,
    /// The bundle still contains secret-like payloads that must be redacted first.
    RedactionRequired,
    /// The original scenario was not replayable.
    InvalidScenario,
    /// The configured reduction pass limit prevented a complete minimization pass.
    StepLimitReached,
}

/// Failure bundle consumed by the deterministic minimizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFailureBundle {
    /// Stable bundle id.
    pub bundle_id: String,
    /// Repository or artifact-store pointer to the original failing bundle.
    pub original_artifact: String,
    /// Failure family the minimizer must preserve.
    pub invariant_class: SwarmFailureInvariantClass,
    /// Whether the invariant was reproduced by the source replay evidence.
    pub invariant_reproduced: bool,
    /// First failure or invariant text from the source bundle.
    pub first_failure: String,
    /// Trace summary extracted from the source replay or pressure artifact.
    pub trace_summary: Option<SwarmPressureTraceSummary>,
    /// Proof-lane provenance for the command that captured the failure evidence.
    pub proof_lane_plan: Option<SwarmProofLanePlan>,
    /// Redaction policy that must be preserved in the minimized report.
    pub redaction_policy_id: Option<String>,
    /// Count of secret-like values still present in the bundle.
    pub secret_like_value_count: usize,
}

/// Input for deterministic swarm failure minimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFailureMinimizerInput {
    /// Stable minimizer run id.
    pub minimizer_id: String,
    /// Original replay scenario that produced the source failure bundle.
    pub original_scenario: SwarmReplayScenario,
    /// Failure bundle and provenance to preserve.
    pub failure_bundle: SwarmFailureBundle,
    /// Lowest region count the minimizer may emit.
    pub minimum_regions: usize,
    /// Lowest per-region task count the minimizer may emit.
    pub minimum_tasks_per_region: usize,
    /// Lowest replay step budget the minimizer may emit.
    pub minimum_replay_steps: u64,
    /// Maximum deterministic reduction steps allowed for this run.
    pub max_reduction_passes: usize,
    /// Stable trace or bundle ids consumed by this minimizer run.
    pub source_trace_ids: Vec<String>,
    /// Exact replay command to publish with the minimized scenario.
    pub replay_command: Option<String>,
}

/// One deterministic reduction applied by the minimizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFailureReductionStep {
    /// Stable knob name.
    pub knob: String,
    /// Original knob value.
    pub before: String,
    /// Minimized knob value.
    pub after: String,
    /// Evidence-based reason for the reduction.
    pub reason: String,
    /// Whether the source invariant reproduction proof is still attached.
    pub preserved_invariant: bool,
}

/// Deterministic minimizer report suitable for Agent Mail and artifact storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFailureMinimizerReport {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable minimizer run id.
    pub minimizer_id: String,
    /// Original failure bundle id.
    pub bundle_id: String,
    /// Pointer to the original, unminimized artifact.
    pub original_artifact: String,
    /// Original scenario id.
    pub original_scenario_id: String,
    /// Minimized replay scenario.
    pub minimized_scenario: SwarmReplayScenario,
    /// Replay command for the minimized scenario.
    pub replay_command: Option<String>,
    /// Final minimizer verdict.
    pub verdict: SwarmFailureMinimizerVerdict,
    /// Failure family preserved by the report.
    pub invariant_class: SwarmFailureInvariantClass,
    /// First failure or invariant text from the source bundle.
    pub first_failure: String,
    /// Explicit stop reason.
    pub stop_reason: SwarmFailureMinimizerStopReason,
    /// Whether the report is allowed to claim invariant preservation.
    pub preserved_invariant: bool,
    /// Whether every required input field was present.
    pub required_fields_present: bool,
    /// Missing required input fields.
    pub missing_required_fields: Vec<String>,
    /// Proof-lane decision copied from provenance when present.
    pub proof_lane_decision: Option<SwarmProofLaneDecision>,
    /// Stable trace or bundle ids consumed by this minimizer run.
    pub source_trace_ids: Vec<String>,
    /// Redaction policy copied from the source bundle.
    pub redaction_policy_id: Option<String>,
    /// Whether the minimized report preserved redaction requirements.
    pub redaction_preserved: bool,
    /// Deterministic reduction steps.
    pub reduction_steps: Vec<SwarmFailureReductionStep>,
    /// Original modeled task count.
    pub original_task_count: usize,
    /// Minimized modeled task count.
    pub minimized_task_count: usize,
    /// Task-count reduction in basis points.
    pub reduction_ratio_bps: u16,
    /// Suggested owner module or surface.
    pub owner_surface: String,
    /// Suggested owner bead or follow-up thread.
    pub owner_bead_hint: String,
    /// Stable routing hints for operators and agents.
    pub routing_hints: Vec<String>,
    /// Minimization reports never request destructive cleanup.
    pub destructive_cleanup_required: bool,
    /// Minimization reports never request branch or worktree creation.
    pub branch_or_worktree_required: bool,
}

/// Work class used by the deterministic swarm what-if planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWhatIfWorkClass {
    /// Source edits, source-only checks, and lightweight agent work.
    Code,
    /// Documentation or tracker-only work that should not consume proof lanes.
    Docs,
    /// Cargo/RCH proof work.
    Proof,
    /// Artifact-heavy ATP or replay work.
    Artifact,
    /// Operator doctor/cockpit work.
    Doctor,
    /// Cleanup requests that remain report-only unless explicitly authorized.
    Cleanup,
}

/// Priority class used by the deterministic swarm what-if planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWhatIfPriority {
    /// Background work that may be deferred first.
    Background,
    /// Normal foreground agent work.
    Foreground,
    /// Release-frontier or unblocker work.
    Critical,
}

/// One workload class in a swarm admission what-if scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmWhatIfWorkload {
    /// Stable workload id included in deferred-work reports.
    pub workload_id: String,
    /// Work class for capacity weighting.
    pub work_class: SwarmWhatIfWorkClass,
    /// Number of agents in this workload class.
    pub agent_count: usize,
    /// Whether this workload requires an admissible remote RCH worker.
    pub remote_required: bool,
    /// Priority for deterministic deferral ordering.
    pub priority: SwarmWhatIfPriority,
    /// Estimated artifact footprint in GiB for this workload class.
    pub artifact_gib: u64,
}

impl SwarmWhatIfWorkload {
    /// Creates a workload row for the what-if planner.
    #[must_use]
    pub fn new(
        workload_id: impl Into<String>,
        work_class: SwarmWhatIfWorkClass,
        agent_count: usize,
        remote_required: bool,
        priority: SwarmWhatIfPriority,
        artifact_gib: u64,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            work_class,
            agent_count,
            remote_required,
            priority,
            artifact_gib,
        }
    }
}

/// Deterministic input for pre-admission swarm planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmWhatIfScenario {
    /// Stable scenario id copied into the plan.
    pub scenario_id: String,
    /// Age of the oldest input snapshot in seconds.
    pub input_age_secs: u64,
    /// Local agent slots available before RCH workers are considered.
    pub local_agent_slots: usize,
    /// Remote RCH workers currently admissible.
    pub rch_workers_admissible: usize,
    /// RCH workers with cache warmth for the requested proof lanes.
    pub cache_warm_workers: usize,
    /// Host memory pressure on a 0..=10_000 basis-point scale.
    pub memory_pressure_bps: u16,
    /// Disk/artifact pressure on a 0..=10_000 basis-point scale.
    pub disk_pressure_bps: u16,
    /// Count of active reservation conflicts visible to the operator.
    pub reservation_conflicts: usize,
    /// Workload classes to simulate.
    pub workloads: Vec<SwarmWhatIfWorkload>,
}

impl SwarmWhatIfScenario {
    /// Returns total agent count across workload classes.
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.workloads
            .iter()
            .map(|workload| workload.agent_count)
            .sum()
    }

    /// Validate that the scenario is bounded and replayable.
    pub fn validate(&self) -> Result<(), SwarmReplayError> {
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmReplayError::EmptyScenarioId);
        }
        let agent_count = self.agent_count();
        if agent_count > MAX_FIRST_SLICE_TASKS {
            return Err(SwarmReplayError::TooManyTasks {
                task_count: agent_count,
                max: MAX_FIRST_SLICE_TASKS,
            });
        }
        for (workload_index, workload) in self.workloads.iter().enumerate() {
            if workload.workload_id.trim().is_empty() {
                return Err(SwarmReplayError::EmptyWorkloadId { workload_index });
            }
            if workload.agent_count == 0 {
                return Err(SwarmReplayError::ZeroAgentCount);
            }
        }
        Ok(())
    }
}

/// Input freshness class attached to a what-if plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWhatIfInputFreshness {
    /// Inputs are fresh enough for direct operator action.
    Fresh,
    /// Inputs are usable but should be refreshed soon.
    Partial,
    /// Inputs are stale; the recommendation is conservative.
    Stale,
}

/// Planner recommendation for the next swarm wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWhatIfRecommendation {
    /// Admit all requested work.
    AdmitNow,
    /// Admit a bounded prefix under the returned cap.
    AdmitWithCap,
    /// Defer lower-priority workloads first.
    DeferLowPriority,
    /// Split the wave into smaller deterministic batches.
    SplitWave,
    /// Request more remote RCH workers before admitting remote-required work.
    RequestRemoteWorkers,
    /// Refuse until the first blocker clears.
    RefuseUntilBlockerClears,
}

/// Starvation-risk class for the simulated wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWhatIfStarvationRisk {
    /// No modeled starvation pressure.
    Low,
    /// Some queueing or coordination pressure is expected.
    Medium,
    /// Work is likely to wait behind capacity pressure.
    High,
    /// Critical starvation risk or fail-closed pressure.
    Critical,
}

/// Byte-stable plan emitted by the deterministic what-if planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmWhatIfPlan {
    /// Stable schema version.
    pub schema_version: String,
    /// Scenario id copied from input.
    pub scenario_id: String,
    /// Total requested agents.
    pub agent_count: usize,
    /// Weighted capacity demand used for queue estimates.
    pub weighted_demand_units: usize,
    /// Weighted capacity available for this scenario.
    pub weighted_capacity_units: usize,
    /// Bounded queue estimate after admission.
    pub bounded_queue_estimate: usize,
    /// Final recommendation.
    pub recommendation: SwarmWhatIfRecommendation,
    /// Starvation risk for the simulated wave.
    pub starvation_risk: SwarmWhatIfStarvationRisk,
    /// Input freshness classification.
    pub input_freshness: SwarmWhatIfInputFreshness,
    /// Confidence score on a 0..=100 basis-point-like scale.
    pub confidence_bps: u16,
    /// Optional agent cap for `admit_with_cap` or `split_wave`.
    pub admit_agent_cap: Option<usize>,
    /// Workload ids the planner would defer first.
    pub deferred_workload_ids: Vec<String>,
    /// First cap an operator should adjust.
    pub first_cap_to_adjust: Option<String>,
    /// First blocker that must clear before full admission.
    pub first_blocker: Option<String>,
    /// Visible caveats about stale or partial inputs.
    pub caveats: Vec<String>,
    /// Deterministic operator log lines.
    pub detailed_log: Vec<String>,
    /// Planner never asks for file deletion.
    pub destructive_cleanup_required: bool,
    /// Planner never asks for branch/worktree creation.
    pub branch_or_worktree_required: bool,
}

/// Fallback policy for a proof lane when remote execution cannot be proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneFallbackPolicy {
    /// Remote RCH execution is mandatory; local fallback invalidates the lane.
    RemoteOnly,
    /// Local execution was explicitly authorized by the operator.
    LocalAuthorized,
    /// The lane is only a report and does not establish proof evidence.
    ReportOnly,
}

/// Atlas-aware admission outcome for a proof lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneAdmissionDecision {
    /// Inputs are fresh and the lane may run immediately.
    Admit,
    /// Inputs are valid, but resource pressure says to wait.
    Defer,
    /// Inputs are valid, but proof evidence must be discarded or refused.
    Reject,
    /// Compatible lane should be grouped with a batch on a large host.
    Batch,
    /// Coordination state blocks the lane until handoff.
    Blocked,
    /// Evidence is stale or incomplete and needs a narrow refresh.
    StaleEvidence,
    /// Required structured inputs are malformed.
    Malformed,
    /// Spectral evidence is advisory and needs a witness before deadlock claims.
    AdvisorySpectralWarning,
    /// A validated trapped-cycle witness permits the proven label.
    TrappedCycleProven,
}

/// Target-directory isolation evidence surfaced by atlas-aware planning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneTargetDirIsolationStatus {
    /// The lane declares and publishes an isolated target directory.
    #[default]
    Isolated,
    /// The lane omitted a target directory.
    Missing,
    /// The published command does not expose the declared target directory.
    NotInCommand,
    /// Remote provenance observed a different target directory.
    ProvenanceMismatch,
}

/// Peer reservation overlap evidence surfaced by atlas-aware planning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLanePeerReservationOverlapStatus {
    /// No overlapping peer reservation blocks this lane.
    #[default]
    Clear,
    /// A peer owns a related reservation and handoff is needed.
    PeerOverlap,
    /// An active exclusive peer reservation blocks this lane.
    ActiveExclusiveConflict,
    /// Reservation evidence is stale or malformed.
    StaleOrMalformed,
}

/// Trapped-cycle witness evidence surfaced by atlas-aware planning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneTrappedCycleWitnessStatus {
    /// This lane does not need trapped-cycle evidence.
    #[default]
    NotRequired,
    /// Spectral evidence says a witness is required but none is validated.
    RequiredMissing,
    /// A witness exists but still needs replay validation.
    ReplayPending,
    /// Witness evidence is malformed.
    Malformed,
    /// A witness row is validated but does not prove a deadlock label.
    Validated,
    /// A validated witness row proves the trapped-cycle/deadlock label.
    Proven,
}

/// Read-only atlas context consumed by the proof-lane planner.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SwarmProofLaneAtlasAdmissionContext {
    /// Source atlas rows used for this decision receipt.
    pub source_rows: Vec<String>,
    /// Atlas reason codes copied into the final receipt.
    pub reason_codes: Vec<String>,
    /// Large-host worker saturation label, if supplied by the atlas.
    pub worker_saturation: Option<String>,
    /// Large-host batching recommendation, if supplied by the atlas.
    pub batching_decision: Option<String>,
    /// Reservation overlap state from Agent Mail inputs.
    pub peer_reservation_overlap_status: SwarmProofLanePeerReservationOverlapStatus,
    /// Target-dir isolation state from atlas inputs, if fresher than command parsing.
    pub target_dir_isolation_status: Option<SwarmProofLaneTargetDirIsolationStatus>,
    /// Trapped-cycle witness state from atlas inputs.
    pub trapped_cycle_witness_status: SwarmProofLaneTrappedCycleWitnessStatus,
    /// Whether any source row is stale or missing.
    pub stale_evidence: bool,
    /// Whether any source row is malformed.
    pub malformed: bool,
    /// Whether spectral evidence is advisory and not deadlock-proof.
    pub spectral_warning_advisory: bool,
}

/// Planner decision for a proof lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneDecision {
    /// The lane has enough evidence to be used as proof.
    Ready,
    /// The lane needs a fresh commit, target directory, or cache observation.
    RefreshStaleInputs,
    /// The lane is unsafe until remote-only proof evidence is captured.
    RefuseUntilRemoteProof,
}

/// Severity attached to a proof-lane planner finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmProofLaneFindingSeverity {
    /// Informational finding that does not block the proof lane.
    Info,
    /// Finding that requires a narrow refresh before widening proof scope.
    RefreshRequired,
    /// Finding that invalidates the proof lane until corrected.
    Unsafe,
}

/// Remote-worker provenance captured for one proof lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofLaneRchProvenance {
    /// Stable worker identifier reported by RCH.
    pub worker_id: String,
    /// Whether the proof observed remote RCH execution.
    pub remote_observed: bool,
    /// Commit or source snapshot observed by the proof lane.
    pub observed_head: String,
    /// Cargo target directory observed by the proof lane.
    pub target_dir: String,
    /// Process exit status observed for the proof command.
    pub exit_status: Option<i32>,
}

/// Deterministic input for planning and validating one proof lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofLaneRequest {
    /// Stable proof-lane id.
    pub lane_id: String,
    /// Scenario fixture or source surface this lane proves.
    pub scenario_id: String,
    /// Repository-relative source artifacts consumed by the lane.
    pub source_artifacts: Vec<String>,
    /// Touched source or test surfaces the lane is intended to cover.
    pub touched_surfaces: Vec<String>,
    /// Exact command that should be run or was run.
    pub command: String,
    /// Cargo target directory required for isolated proof artifacts.
    pub target_dir: String,
    /// Explicit Cargo feature scope used by the command.
    pub features: Vec<String>,
    /// Artifacts expected from the proof lane.
    pub expected_artifacts: Vec<String>,
    /// Timeout budget in seconds.
    pub timeout_secs: u64,
    /// Whether the command must prove remote RCH execution.
    pub remote_required: bool,
    /// Whether the operator explicitly authorized local fallback.
    pub local_fallback_authorized: bool,
    /// Commit or source snapshot the proof was planned against.
    pub expected_head: Option<String>,
    /// Commit or source snapshot observed when proof evidence was captured.
    pub observed_head: Option<String>,
    /// Remote-worker provenance, if the proof lane has run.
    pub rch_provenance: Option<SwarmProofLaneRchProvenance>,
    /// Transcript markers captured from proof output.
    pub transcript_markers: Vec<String>,
    /// Claims this lane is allowed to prove.
    pub covers: Vec<String>,
    /// Claims this lane explicitly does not prove.
    pub does_not_cover: Vec<String>,
    /// Optional read-only atlas context for admission-aware planning.
    #[serde(default)]
    pub atlas_context: Option<SwarmProofLaneAtlasAdmissionContext>,
}

/// One proof-lane planner finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofLaneFinding {
    /// Stable machine-readable finding code.
    pub code: String,
    /// Operator-readable finding detail.
    pub detail: String,
    /// Concrete next action.
    pub action: String,
    /// Finding severity.
    pub severity: SwarmProofLaneFindingSeverity,
}

/// Byte-stable proof-lane plan and validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofLanePlan {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable proof-lane id.
    pub lane_id: String,
    /// Scenario fixture or source surface copied from the request.
    pub scenario_id: String,
    /// Exact command copied from the request.
    pub command: String,
    /// Cargo target directory copied from the request.
    pub target_dir: String,
    /// Explicit Cargo feature scope, sorted and deduplicated.
    pub features: Vec<String>,
    /// Expected artifacts, sorted and deduplicated.
    pub expected_artifacts: Vec<String>,
    /// Timeout budget in seconds.
    pub timeout_secs: u64,
    /// Whether remote RCH execution is mandatory.
    pub remote_required: bool,
    /// Fallback policy inferred from the request.
    pub fallback_policy: SwarmProofLaneFallbackPolicy,
    /// Planner decision after fail-closed validation.
    pub decision: SwarmProofLaneDecision,
    /// Atlas-aware admission outcome.
    pub admission_decision: SwarmProofLaneAdmissionDecision,
    /// Stable key for batching compatible proof lanes.
    pub batch_key: String,
    /// Stable cache key carrying command, target, feature, artifact, and head inputs.
    pub cache_key_fingerprint: String,
    /// Whether expected and observed HEAD evidence disagree.
    pub stale_head: bool,
    /// Whether the request omitted an isolated target directory.
    pub missing_target_dir: bool,
    /// Whether proof output shows local fallback without authorization.
    pub local_fallback_marker_detected: bool,
    /// Whether remote provenance is required by this plan.
    pub remote_provenance_required: bool,
    /// Whether remote provenance was observed.
    pub remote_provenance_observed: bool,
    /// Source rows consumed by the admission receipt.
    pub source_rows: Vec<String>,
    /// Machine-readable reasons that explain the admission decision.
    pub reason_codes: Vec<String>,
    /// Target-dir isolation status included in the receipt.
    pub target_dir_isolation_status: SwarmProofLaneTargetDirIsolationStatus,
    /// Peer reservation overlap status included in the receipt.
    pub peer_reservation_overlap_status: SwarmProofLanePeerReservationOverlapStatus,
    /// Trapped-cycle witness status included in the receipt.
    pub trapped_cycle_witness_status: SwarmProofLaneTrappedCycleWitnessStatus,
    /// Claims this lane is allowed to prove.
    pub covers: Vec<String>,
    /// Claims this lane explicitly does not prove.
    pub does_not_cover: Vec<String>,
    /// Fail-closed planner findings.
    pub findings: Vec<SwarmProofLaneFinding>,
    /// Concise deterministic text for Agent Mail handoffs.
    pub agent_mail_summary: String,
    /// Planner never mutates live services.
    pub mutates_external_state: bool,
    /// Planner never asks for file deletion.
    pub destructive_cleanup_required: bool,
    /// Planner never asks for branch/worktree creation.
    pub branch_or_worktree_required: bool,
}

/// Compact deterministic atlas report for operator and agent closeouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofLaneAtlasReport {
    /// Stable report schema version.
    pub schema_version: String,
    /// Operator closeout taxonomy label.
    pub closeout_label: String,
    /// Stable proof-lane id.
    pub lane_id: String,
    /// Scenario fixture or source surface copied from the plan.
    pub scenario_id: String,
    /// Planner decision after fail-closed validation.
    pub planner_decision: SwarmProofLaneDecision,
    /// Atlas-aware admission outcome.
    pub admission_decision: SwarmProofLaneAdmissionDecision,
    /// Freshness class derived from head, atlas, target-dir, and witness evidence.
    pub freshness: String,
    /// Exact proof command.
    pub proof_command: String,
    /// Whether remote RCH execution is mandatory.
    pub remote_required: bool,
    /// Whether remote RCH execution was observed.
    pub remote_provenance_observed: bool,
    /// Fallback policy inferred from the proof lane.
    pub fallback_policy: SwarmProofLaneFallbackPolicy,
    /// Cargo target directory copied from the plan.
    pub target_dir: String,
    /// Target-dir isolation status included in the receipt.
    pub target_dir_isolation_status: SwarmProofLaneTargetDirIsolationStatus,
    /// Peer reservation overlap status included in the receipt.
    pub peer_reservation_overlap_status: SwarmProofLanePeerReservationOverlapStatus,
    /// Trapped-cycle witness status included in the receipt.
    pub trapped_cycle_witness_status: SwarmProofLaneTrappedCycleWitnessStatus,
    /// Source rows consumed by the admission receipt.
    pub source_rows: Vec<String>,
    /// Machine-readable reasons that explain the admission decision.
    pub reason_codes: Vec<String>,
    /// Claims this lane is allowed to prove.
    pub covers: Vec<String>,
    /// Claims this lane explicitly does not prove.
    pub does_not_cover: Vec<String>,
    /// Fail-closed finding codes.
    pub finding_codes: Vec<String>,
    /// Number of fail-closed findings.
    pub finding_count: usize,
    /// Renderer never mutates live services.
    pub mutates_external_state: bool,
    /// Renderer never asks for file deletion.
    pub destructive_cleanup_required: bool,
    /// Renderer never asks for branch/worktree creation.
    pub branch_or_worktree_required: bool,
}

/// Self-contained capsule emitted before compaction or session handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffCapsule {
    /// Stable capsule id for replay and operator logs.
    pub capsule_id: String,
    /// Current agent identity from the handoff summary.
    pub current_agent: String,
    /// Generated timestamp as epoch seconds.
    pub generated_at_epoch_secs: u64,
    /// Documentation hash or read-receipt hash expected by the resumed agent.
    pub expected_docs_hash: Option<String>,
    /// Documentation hash observed by the resumed agent.
    pub observed_docs_hash: Option<String>,
    /// Main commit hash expected by the handoff.
    pub expected_main_hash: Option<String>,
    /// Main commit hash observed by the resumed agent.
    pub observed_main_hash: Option<String>,
    /// Beads the handoff claims are actively owned by this agent.
    pub claimed_bead_ids: Vec<String>,
    /// Active file reservations captured in the handoff.
    pub active_reservations: Vec<SwarmHandoffReservation>,
    /// Dirty paths classified by ownership at handoff time.
    pub dirty_paths: Vec<SwarmHandoffDirtyPath>,
    /// Exact proof commands and observed proof status.
    pub proof_commands: Vec<SwarmHandoffProofCommand>,
    /// Inbox ack state needed before continuing.
    pub inbox_acks: Vec<SwarmHandoffInboxAck>,
    /// Commits pushed by the previous agent session.
    pub pushed_commits: Vec<SwarmHandoffCommit>,
    /// First blocker carried by the compacted handoff, if any.
    pub first_blocker: Option<String>,
}

/// Reservation evidence captured in a handoff capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffReservation {
    /// Reserved path or glob.
    pub path_pattern: String,
    /// Agent that holds the reservation.
    pub holder_agent: String,
    /// Time the reservation was observed, as epoch seconds.
    pub observed_at_epoch_secs: u64,
    /// Reservation expiry, as epoch seconds.
    pub expires_at_epoch_secs: u64,
}

/// Ownership class for a dirty handoff path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffDirtyOwner {
    /// Dirty path belongs to the current handoff agent.
    CurrentAgent,
    /// Dirty path belongs to another known agent.
    PeerAgent,
    /// Dirty path ownership is not known.
    Unknown,
}

/// Dirty path evidence captured in a handoff capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffDirtyPath {
    /// Repository-relative path.
    pub path: String,
    /// Ownership classification for the dirty path.
    pub owner: SwarmHandoffDirtyOwner,
    /// Optional owner name after redaction policy has been applied.
    pub owner_agent: Option<String>,
}

/// Proof command evidence captured in a handoff capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffProofCommand {
    /// Exact command that was or must be replayed.
    pub command: String,
    /// Whether this proof lane requires remote RCH execution.
    pub remote_required: bool,
    /// Whether remote RCH execution was observed.
    pub remote_observed: bool,
    /// Process exit status, if the proof ran.
    pub exit_status: Option<i32>,
    /// First blocker from the proof lane, if it did not pass.
    pub first_blocker: Option<String>,
}

/// Inbox ack evidence captured in a handoff capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffInboxAck {
    /// Agent Mail message id.
    pub message_id: u64,
    /// Whether the message required acknowledgement.
    pub ack_required: bool,
    /// Whether the acknowledgement was observed.
    pub acknowledged: bool,
}

/// Commit evidence captured in a handoff capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffCommit {
    /// Pushed commit id.
    pub commit_id: String,
    /// Whether the commit reached `main`.
    pub pushed_to_main: bool,
    /// Whether `main` was mirrored to `master`.
    pub synced_to_master: bool,
    /// Whether Beads or handoff notes recorded the commit.
    pub recorded_in_beads_comment: bool,
}

/// Verifier decision for a compaction-safe handoff capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHandoffDecision {
    /// Evidence is fresh enough to continue.
    Continue,
    /// Refresh a narrow live snapshot before continuing.
    NarrowRefreshRequired,
    /// Coordinate with another agent or mailbox before continuing.
    CoordinateFirst,
    /// Fail closed; the capsule is not safe to continue from.
    UnsafeToContinue,
}

/// One verifier reason explaining a handoff decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffVerifierReason {
    /// Stable machine-readable reason code.
    pub code: String,
    /// Operator-facing reason.
    pub detail: String,
    /// Concrete next action.
    pub action: String,
}

/// Deterministic, non-mutating handoff verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmHandoffVerification {
    /// Stable schema version.
    pub schema_version: String,
    /// Capsule id copied from input.
    pub capsule_id: String,
    /// Final verifier decision.
    pub decision: SwarmHandoffDecision,
    /// All reasons that contributed to the decision.
    pub reasons: Vec<SwarmHandoffVerifierReason>,
    /// Number of narrow-refresh findings.
    pub stale_evidence_count: usize,
    /// Number of coordination findings.
    pub coordination_required_count: usize,
    /// Number of fail-closed findings.
    pub unsafe_issue_count: usize,
    /// Short operator-facing next action.
    pub next_action: String,
    /// Whether a future agent can replay the capsule without this conversation.
    pub self_contained: bool,
    /// Whether verification mutated Git, Beads, Agent Mail, or RCH.
    pub mutates_external_state: bool,
}

/// Plans a deterministic swarm admission wave without launching live work.
pub fn plan_swarm_admission_wave(
    scenario: &SwarmWhatIfScenario,
) -> Result<SwarmWhatIfPlan, SwarmReplayError> {
    scenario.validate()?;

    let agent_count = scenario.agent_count();
    let weighted_demand_units = weighted_demand_units(&scenario.workloads);
    let weighted_capacity_units = weighted_capacity_units(scenario);
    let bounded_queue_estimate = weighted_demand_units.saturating_sub(weighted_capacity_units);
    let input_freshness = input_freshness(scenario.input_age_secs);
    let mut caveats = input_caveats(input_freshness);
    let mut deferred_workload_ids = Vec::new();
    let mut first_cap_to_adjust = None;
    let mut first_blocker = None;
    let recommendation;

    if agent_count == 0 {
        recommendation = SwarmWhatIfRecommendation::AdmitNow;
    } else if disk_blocks_artifact_work(scenario) {
        recommendation = SwarmWhatIfRecommendation::RefuseUntilBlockerClears;
        deferred_workload_ids = matching_workload_ids(&scenario.workloads, |workload| {
            matches!(
                workload.work_class,
                SwarmWhatIfWorkClass::Artifact | SwarmWhatIfWorkClass::Proof
            )
        });
        first_cap_to_adjust = Some("artifact_disk_pressure".to_string());
        first_blocker = Some("disk/artifact pressure blocks proof-heavy admission".to_string());
    } else if remote_workers_block_required_work(scenario) {
        recommendation = SwarmWhatIfRecommendation::RequestRemoteWorkers;
        deferred_workload_ids =
            matching_workload_ids(&scenario.workloads, |workload| workload.remote_required);
        first_cap_to_adjust = Some("rch_worker_pool".to_string());
        first_blocker = Some("remote-required work has no admissible RCH worker".to_string());
    } else if scenario.reservation_conflicts > 0 {
        recommendation = SwarmWhatIfRecommendation::DeferLowPriority;
        deferred_workload_ids = low_priority_workload_ids(&scenario.workloads);
        first_cap_to_adjust = Some("file_reservation_conflicts".to_string());
        first_blocker = Some("active reservation conflict requires coordination first".to_string());
    } else if scenario.memory_pressure_bps >= 9_000 {
        recommendation = SwarmWhatIfRecommendation::SplitWave;
        deferred_workload_ids = noncritical_workload_ids(&scenario.workloads);
        first_cap_to_adjust = Some("memory_tier_cap".to_string());
        first_blocker = Some("memory-tier pressure is above admission threshold".to_string());
    } else if weighted_demand_units > weighted_capacity_units.saturating_mul(2).max(1)
        || (agent_count >= 200 && bounded_queue_estimate > 0)
    {
        recommendation = SwarmWhatIfRecommendation::SplitWave;
        deferred_workload_ids = noncritical_workload_ids(&scenario.workloads);
        first_cap_to_adjust = Some("agent_wave_cap".to_string());
        first_blocker = Some("wave demand exceeds deterministic admission envelope".to_string());
    } else if weighted_demand_units > weighted_capacity_units {
        recommendation = SwarmWhatIfRecommendation::AdmitWithCap;
        deferred_workload_ids = low_priority_workload_ids(&scenario.workloads);
        first_cap_to_adjust = Some("proof_lane_cap".to_string());
    } else {
        recommendation = SwarmWhatIfRecommendation::AdmitNow;
    }

    if input_freshness != SwarmWhatIfInputFreshness::Fresh {
        caveats.push(
            "refresh stale capacity, RCH, and reservation inputs before widening the wave"
                .to_string(),
        );
    }
    if remote_workers_block_required_work(scenario) {
        caveats.push(
            "local Cargo fallback is not a planner recommendation for remote-required lanes"
                .to_string(),
        );
    }

    deferred_workload_ids.sort();
    deferred_workload_ids.dedup();

    let starvation_risk = starvation_risk(
        bounded_queue_estimate,
        weighted_capacity_units,
        scenario.memory_pressure_bps,
        scenario.disk_pressure_bps,
        scenario.reservation_conflicts,
    );
    let admit_agent_cap = admission_agent_cap(recommendation, scenario, weighted_capacity_units);
    let confidence_bps = confidence_bps(input_freshness, starvation_risk, first_blocker.is_some());
    let detailed_log = what_if_log(
        scenario,
        weighted_demand_units,
        weighted_capacity_units,
        bounded_queue_estimate,
        recommendation,
        starvation_risk,
        first_blocker.as_deref(),
    );

    Ok(SwarmWhatIfPlan {
        schema_version: SWARM_WHAT_IF_PLAN_SCHEMA_VERSION.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        agent_count,
        weighted_demand_units,
        weighted_capacity_units,
        bounded_queue_estimate,
        recommendation,
        starvation_risk,
        input_freshness,
        confidence_bps,
        admit_agent_cap,
        deferred_workload_ids,
        first_cap_to_adjust,
        first_blocker,
        caveats,
        detailed_log,
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    })
}

/// Plans and validates a remote-only proof lane without running live work.
#[must_use]
pub fn plan_swarm_proof_lane(request: &SwarmProofLaneRequest) -> SwarmProofLanePlan {
    let mut decision = SwarmProofLaneDecision::Ready;
    let mut findings = Vec::new();
    let features = sorted_unique_strings(&request.features);
    let expected_artifacts = sorted_unique_strings(&request.expected_artifacts);
    let covers = sorted_unique_strings(&request.covers);
    let does_not_cover = sorted_unique_strings(&request.does_not_cover);
    let fallback_policy = if request.remote_required {
        if request.local_fallback_authorized {
            SwarmProofLaneFallbackPolicy::LocalAuthorized
        } else {
            SwarmProofLaneFallbackPolicy::RemoteOnly
        }
    } else {
        SwarmProofLaneFallbackPolicy::ReportOnly
    };
    let remote_provenance_observed = request
        .rch_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.remote_observed);
    let local_fallback_marker_detected = proof_lane_local_fallback_marker_detected(request);
    let stale_head = proof_lane_stale_head(request);
    let missing_target_dir = request.target_dir.trim().is_empty();
    let remote_provenance_required = request.remote_required;

    if request.lane_id.trim().is_empty() {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_lane_id",
            "proof lane is missing a stable id",
            "assign a stable lane id before publishing proof evidence",
        );
    }
    if request.scenario_id.trim().is_empty() {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_scenario_id",
            "proof lane is missing a scenario or source fixture id",
            "attach the proof lane to a concrete scenario fixture or source surface",
        );
    }
    if request.command.trim().is_empty() {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_command",
            "proof lane is missing an exact replayable command",
            "capture the exact rch exec command before accepting the lane",
        );
    }
    if missing_target_dir {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefreshStaleInputs,
            SwarmProofLaneFindingSeverity::RefreshRequired,
            "missing_target_dir",
            "proof lane does not declare an isolated Cargo target directory",
            "set CARGO_TARGET_DIR to a lane-specific remote target directory",
        );
    } else if !request.command.contains(&request.target_dir)
        && !request.command.contains("CARGO_TARGET_DIR")
    {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefreshStaleInputs,
            SwarmProofLaneFindingSeverity::RefreshRequired,
            "target_dir_not_in_command",
            "proof command does not expose the declared target directory",
            "publish the command with an explicit CARGO_TARGET_DIR assignment",
        );
    }
    if request.timeout_secs == 0 {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefreshStaleInputs,
            SwarmProofLaneFindingSeverity::RefreshRequired,
            "missing_timeout",
            "proof lane has no timeout budget",
            "set a deterministic timeout budget for operator handoffs",
        );
    }
    if expected_artifacts.is_empty() {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_expected_artifact",
            "proof lane declares no expected artifacts",
            "list at least one source, test, or evidence artifact the lane proves",
        );
    }
    if covers.is_empty() || does_not_cover.is_empty() {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_claim_scope",
            "proof lane must include both covers and does_not_cover claims",
            "separate the exact proof claim from surfaces this lane does not validate",
        );
    }
    if proof_lane_needs_feature_scope(&request.command) && !proof_lane_has_feature_scope(request) {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "missing_feature_scope",
            "Cargo proof command does not carry an explicit feature scope",
            "add --features, --all-features, or --no-default-features and mirror it in features",
        );
    }
    if request.remote_required {
        if !proof_lane_command_requires_remote(&request.command) {
            add_proof_lane_finding(
                &mut findings,
                &mut decision,
                SwarmProofLaneDecision::RefuseUntilRemoteProof,
                SwarmProofLaneFindingSeverity::Unsafe,
                "missing_remote_requirement",
                "remote-required proof command lacks RCH_REQUIRE_REMOTE=1 rch exec",
                "rerun through RCH with RCH_REQUIRE_REMOTE=1 and capture the exact command",
            );
        }
        if !remote_provenance_observed {
            add_proof_lane_finding(
                &mut findings,
                &mut decision,
                SwarmProofLaneDecision::RefuseUntilRemoteProof,
                SwarmProofLaneFindingSeverity::Unsafe,
                "missing_rch_provenance",
                "remote-required proof lane has no observed remote worker provenance",
                "capture remote worker id, observed head, target directory, and status",
            );
        }
    }
    if local_fallback_marker_detected && !request.local_fallback_authorized {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefuseUntilRemoteProof,
            SwarmProofLaneFindingSeverity::Unsafe,
            "local_fallback_marker",
            "proof transcript or command shows local fallback without authorization",
            "discard the result and rerun with remote-required RCH semantics",
        );
    }
    if stale_head {
        add_proof_lane_finding(
            &mut findings,
            &mut decision,
            SwarmProofLaneDecision::RefreshStaleInputs,
            SwarmProofLaneFindingSeverity::RefreshRequired,
            "stale_head",
            "expected and observed proof HEAD evidence do not match",
            "refresh git state and rerun the proof lane against current main",
        );
    }
    if let Some(provenance) = &request.rch_provenance {
        if provenance.exit_status != Some(0) {
            add_proof_lane_finding(
                &mut findings,
                &mut decision,
                SwarmProofLaneDecision::RefuseUntilRemoteProof,
                SwarmProofLaneFindingSeverity::Unsafe,
                "proof_not_green",
                "proof command did not report a successful exit status",
                "surface the first blocker instead of treating the lane as green",
            );
        }
        if !request.target_dir.trim().is_empty()
            && !provenance.target_dir.trim().is_empty()
            && provenance.target_dir != request.target_dir
        {
            add_proof_lane_finding(
                &mut findings,
                &mut decision,
                SwarmProofLaneDecision::RefreshStaleInputs,
                SwarmProofLaneFindingSeverity::RefreshRequired,
                "stale_target_dir",
                "remote provenance target directory differs from the requested target directory",
                "rerun with the published target directory before reusing cache evidence",
            );
        }
    }

    let target_dir_isolation_status = proof_lane_target_dir_isolation_status(request);
    let peer_reservation_overlap_status = request.atlas_context.as_ref().map_or(
        SwarmProofLanePeerReservationOverlapStatus::Clear,
        |context| context.peer_reservation_overlap_status,
    );
    let trapped_cycle_witness_status = request.atlas_context.as_ref().map_or(
        SwarmProofLaneTrappedCycleWitnessStatus::NotRequired,
        |context| context.trapped_cycle_witness_status,
    );
    let source_rows = proof_lane_source_rows(request);
    let reason_codes = proof_lane_reason_codes(
        request,
        fallback_policy,
        target_dir_isolation_status,
        peer_reservation_overlap_status,
        trapped_cycle_witness_status,
        &findings,
    );
    let admission_decision = proof_lane_admission_decision(
        request,
        stale_head,
        target_dir_isolation_status,
        peer_reservation_overlap_status,
        trapped_cycle_witness_status,
        &findings,
    );

    let mut plan = SwarmProofLanePlan {
        schema_version: SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION.to_string(),
        lane_id: request.lane_id.clone(),
        scenario_id: request.scenario_id.clone(),
        command: request.command.clone(),
        target_dir: request.target_dir.clone(),
        features,
        expected_artifacts,
        timeout_secs: request.timeout_secs,
        remote_required: request.remote_required,
        fallback_policy,
        decision,
        admission_decision,
        batch_key: proof_lane_batch_key(request),
        cache_key_fingerprint: proof_lane_cache_key(request),
        stale_head,
        missing_target_dir,
        local_fallback_marker_detected,
        remote_provenance_required,
        remote_provenance_observed,
        source_rows,
        reason_codes,
        target_dir_isolation_status,
        peer_reservation_overlap_status,
        trapped_cycle_witness_status,
        covers,
        does_not_cover,
        findings,
        agent_mail_summary: String::new(),
        mutates_external_state: false,
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    };
    plan.agent_mail_summary = render_swarm_proof_lane_agent_mail_summary(&plan);
    plan
}

/// Render a stable Agent Mail proof-lane handoff summary.
#[must_use]
pub fn render_swarm_proof_lane_agent_mail_summary(plan: &SwarmProofLanePlan) -> String {
    let finding_codes = if plan.findings.is_empty() {
        "none".to_string()
    } else {
        plan.findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    vec![
        format!("proof_lane: {}", plan.lane_id),
        format!("schema_version: {}", plan.schema_version),
        format!("scenario: {}", plan.scenario_id),
        format!("decision: {:?}", plan.decision),
        format!("admission_decision: {:?}", plan.admission_decision),
        format!(
            "remote_required={} remote_observed={} fallback={:?}",
            plan.remote_required, plan.remote_provenance_observed, plan.fallback_policy
        ),
        format!("target_dir: {}", plan.target_dir),
        format!(
            "target_dir_isolation: {:?}",
            plan.target_dir_isolation_status
        ),
        format!(
            "peer_reservation_overlap: {:?}",
            plan.peer_reservation_overlap_status
        ),
        format!(
            "trapped_cycle_witness: {:?}",
            plan.trapped_cycle_witness_status
        ),
        format!("features: {}", plan.features.join(",")),
        format!("source_rows: {}", plan.source_rows.join(",")),
        format!("reason_codes: {}", plan.reason_codes.join(",")),
        format!("covers: {}", plan.covers.join(",")),
        format!("does_not_cover: {}", plan.does_not_cover.join(",")),
        format!("findings: {finding_codes}"),
        format!("command: {}", plan.command),
    ]
    .join("\n")
}

/// Builds a compact deterministic atlas report from a proof-lane plan.
#[must_use]
pub fn build_swarm_proof_lane_atlas_report(plan: &SwarmProofLanePlan) -> SwarmProofLaneAtlasReport {
    let finding_codes = sorted_unique_owned(
        plan.findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect(),
    );
    SwarmProofLaneAtlasReport {
        schema_version: SWARM_PROOF_LANE_ATLAS_REPORT_SCHEMA_VERSION.to_string(),
        closeout_label: proof_lane_closeout_label(plan.admission_decision).to_string(),
        lane_id: plan.lane_id.clone(),
        scenario_id: plan.scenario_id.clone(),
        planner_decision: plan.decision,
        admission_decision: plan.admission_decision,
        freshness: proof_lane_report_freshness(plan).to_string(),
        proof_command: plan.command.clone(),
        remote_required: plan.remote_required,
        remote_provenance_observed: plan.remote_provenance_observed,
        fallback_policy: plan.fallback_policy,
        target_dir: plan.target_dir.clone(),
        target_dir_isolation_status: plan.target_dir_isolation_status,
        peer_reservation_overlap_status: plan.peer_reservation_overlap_status,
        trapped_cycle_witness_status: plan.trapped_cycle_witness_status,
        source_rows: plan.source_rows.clone(),
        reason_codes: plan.reason_codes.clone(),
        covers: plan.covers.clone(),
        does_not_cover: plan.does_not_cover.clone(),
        finding_count: finding_codes.len(),
        finding_codes,
        mutates_external_state: false,
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    }
}

/// Renders a byte-stable JSON atlas report for operator tooling.
#[must_use]
pub fn render_swarm_proof_lane_atlas_report_json(plan: &SwarmProofLanePlan) -> String {
    let mut rendered = serde_json::to_string_pretty(&build_swarm_proof_lane_atlas_report(plan))
        .expect("swarm proof-lane atlas report serializes");
    rendered.push('\n');
    rendered
}

/// Renders a byte-stable Markdown atlas report for Beads and Agent Mail closeouts.
#[must_use]
pub fn render_swarm_proof_lane_atlas_report_markdown(plan: &SwarmProofLanePlan) -> String {
    let report = build_swarm_proof_lane_atlas_report(plan);
    let mut lines = vec![
        "# Swarm Proof-Lane Atlas Report".to_string(),
        String::new(),
        format!("- schema_version: `{}`", report.schema_version),
        format!("- closeout_label: `{}`", report.closeout_label),
        format!("- lane_id: `{}`", report.lane_id),
        format!("- scenario_id: `{}`", report.scenario_id),
        format!(
            "- planner_decision: `{}`",
            proof_lane_decision_code(report.planner_decision)
        ),
        format!(
            "- admission_decision: `{}`",
            proof_lane_admission_decision_code(report.admission_decision)
        ),
        format!("- freshness: `{}`", report.freshness),
        format!("- remote_required: `{}`", report.remote_required),
        format!(
            "- remote_provenance_observed: `{}`",
            report.remote_provenance_observed
        ),
        format!(
            "- fallback_policy: `{}`",
            proof_lane_fallback_policy_code(report.fallback_policy)
        ),
        format!("- target_dir: `{}`", report.target_dir),
        format!(
            "- target_dir_isolation_status: `{}`",
            proof_lane_target_dir_status_code(report.target_dir_isolation_status)
        ),
        format!(
            "- peer_reservation_overlap_status: `{}`",
            proof_lane_peer_reservation_status_code(report.peer_reservation_overlap_status)
        ),
        format!(
            "- trapped_cycle_witness_status: `{}`",
            proof_lane_trapped_cycle_witness_status_code(report.trapped_cycle_witness_status)
        ),
        format!("- finding_count: `{}`", report.finding_count),
        format!(
            "- mutates_external_state: `{}`",
            report.mutates_external_state
        ),
        format!(
            "- destructive_cleanup_required: `{}`",
            report.destructive_cleanup_required
        ),
        format!(
            "- branch_or_worktree_required: `{}`",
            report.branch_or_worktree_required
        ),
        String::new(),
        "## Proof Command".to_string(),
        String::new(),
        "```text".to_string(),
        report.proof_command,
        "```".to_string(),
        String::new(),
    ];
    append_swarm_proof_lane_report_list(&mut lines, "Reasons", &report.reason_codes);
    append_swarm_proof_lane_report_list(&mut lines, "Source Rows", &report.source_rows);
    append_swarm_proof_lane_report_list(&mut lines, "Covers", &report.covers);
    append_swarm_proof_lane_report_list(&mut lines, "Does Not Cover", &report.does_not_cover);
    append_swarm_proof_lane_report_list(&mut lines, "Findings", &report.finding_codes);
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines.join("\n") + "\n"
}

/// Verifies a compaction-safe handoff capsule without touching live services.
#[must_use]
pub fn verify_swarm_handoff_capsule(capsule: &SwarmHandoffCapsule) -> SwarmHandoffVerification {
    let mut decision = SwarmHandoffDecision::Continue;
    let mut reasons = Vec::new();
    let mut stale_evidence_count = 0usize;
    let mut coordination_required_count = 0usize;
    let mut unsafe_issue_count = 0usize;

    if capsule.capsule_id.trim().is_empty() {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::UnsafeToContinue,
            "missing_capsule_id",
            "handoff capsule is missing a stable id",
            "recreate the handoff capsule before continuing",
        );
        unsafe_issue_count = unsafe_issue_count.saturating_add(1);
    }
    if capsule.current_agent.trim().is_empty() {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::UnsafeToContinue,
            "missing_agent",
            "handoff capsule is missing the current agent identity",
            "refresh Agent Mail identity before continuing",
        );
        unsafe_issue_count = unsafe_issue_count.saturating_add(1);
    }
    if capsule.claimed_bead_ids.is_empty() {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::NarrowRefreshRequired,
            "missing_claimed_bead",
            "handoff capsule does not identify an active bead",
            "refresh Beads state and claim a concrete bead before continuing",
        );
        stale_evidence_count = stale_evidence_count.saturating_add(1);
    }

    if capsule.expected_docs_hash != capsule.observed_docs_hash {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::NarrowRefreshRequired,
            "stale_docs_hash",
            "documentation or AGENTS read-receipt hash changed after compaction",
            "reread required docs and regenerate the capsule",
        );
        stale_evidence_count = stale_evidence_count.saturating_add(1);
    }
    if capsule.expected_main_hash != capsule.observed_main_hash {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::NarrowRefreshRequired,
            "stale_main_hash",
            "observed main commit does not match the handoff capsule",
            "refresh git status and proof commands against current main",
        );
        stale_evidence_count = stale_evidence_count.saturating_add(1);
    }

    if capsule.proof_commands.is_empty()
        || capsule
            .proof_commands
            .iter()
            .any(|proof| proof.command.trim().is_empty())
    {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::UnsafeToContinue,
            "missing_proof_command",
            "handoff capsule lacks an exact replayable proof command",
            "capture the exact rch proof command before continuing",
        );
        unsafe_issue_count = unsafe_issue_count.saturating_add(1);
    }

    for proof in &capsule.proof_commands {
        if proof.remote_required && !proof.remote_observed {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::UnsafeToContinue,
                "missing_remote_proof",
                "remote-required proof did not observe remote RCH execution",
                "rerun the proof with rch and do not treat local fallback as green",
            );
            unsafe_issue_count = unsafe_issue_count.saturating_add(1);
        }
        if proof.exit_status != Some(0) || proof.first_blocker.is_some() {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::UnsafeToContinue,
                "proof_not_green",
                "proof evidence is failing, missing, or carries a first blocker",
                "surface the first blocker before continuing implementation",
            );
            unsafe_issue_count = unsafe_issue_count.saturating_add(1);
        }
    }

    for reservation in &capsule.active_reservations {
        if reservation.expires_at_epoch_secs <= reservation.observed_at_epoch_secs {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::NarrowRefreshRequired,
                "stale_reservation",
                format!(
                    "reservation {} expired before or at the observed handoff time",
                    reservation.path_pattern
                ),
                "refresh file reservations before editing",
            );
            stale_evidence_count = stale_evidence_count.saturating_add(1);
        } else if reservation.holder_agent != capsule.current_agent {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::CoordinateFirst,
                "peer_reservation",
                format!(
                    "reservation {} is held by {}",
                    reservation.path_pattern, reservation.holder_agent
                ),
                "coordinate with the reservation holder before touching the path",
            );
            coordination_required_count = coordination_required_count.saturating_add(1);
        }
    }

    for dirty_path in &capsule.dirty_paths {
        match dirty_path.owner {
            SwarmHandoffDirtyOwner::CurrentAgent => {
                add_handoff_reason(
                    &mut reasons,
                    &mut decision,
                    SwarmHandoffDecision::NarrowRefreshRequired,
                    "dirty_owned_path",
                    format!("current agent has dirty path {}", dirty_path.path),
                    "inspect and preserve owned dirty work before continuing",
                );
                stale_evidence_count = stale_evidence_count.saturating_add(1);
            }
            SwarmHandoffDirtyOwner::PeerAgent => {
                add_handoff_reason(
                    &mut reasons,
                    &mut decision,
                    SwarmHandoffDecision::CoordinateFirst,
                    "dirty_peer_path",
                    format!(
                        "peer-owned dirty path {} blocks safe continuation",
                        dirty_path.path
                    ),
                    "avoid the path or coordinate with the peer owner",
                );
                coordination_required_count = coordination_required_count.saturating_add(1);
            }
            SwarmHandoffDirtyOwner::Unknown => {
                add_handoff_reason(
                    &mut reasons,
                    &mut decision,
                    SwarmHandoffDecision::CoordinateFirst,
                    "dirty_unknown_owner_path",
                    format!("dirty path {} has unknown ownership", dirty_path.path),
                    "classify dirty ownership before continuing",
                );
                coordination_required_count = coordination_required_count.saturating_add(1);
            }
        }
    }

    for ack in &capsule.inbox_acks {
        if ack.ack_required && !ack.acknowledged {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::CoordinateFirst,
                "unresolved_inbox_ack",
                format!("message {} still requires acknowledgement", ack.message_id),
                "acknowledge or answer required inbox messages before continuing",
            );
            coordination_required_count = coordination_required_count.saturating_add(1);
        }
    }

    for commit in &capsule.pushed_commits {
        if commit.pushed_to_main && !commit.recorded_in_beads_comment {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::CoordinateFirst,
                "pushed_commit_missing_comment",
                format!(
                    "commit {} reached main without a Beads or handoff comment",
                    commit.commit_id
                ),
                "record the pushed commit in Beads or the handoff before continuing",
            );
            coordination_required_count = coordination_required_count.saturating_add(1);
        }
        if commit.pushed_to_main && !commit.synced_to_master {
            add_handoff_reason(
                &mut reasons,
                &mut decision,
                SwarmHandoffDecision::NarrowRefreshRequired,
                "missing_master_sync",
                format!(
                    "commit {} reached main without main-to-master sync",
                    commit.commit_id
                ),
                "sync master from main before release handoff",
            );
            stale_evidence_count = stale_evidence_count.saturating_add(1);
        }
    }

    if let Some(first_blocker) = &capsule.first_blocker {
        add_handoff_reason(
            &mut reasons,
            &mut decision,
            SwarmHandoffDecision::UnsafeToContinue,
            "unresolved_first_blocker",
            format!("handoff still carries first blocker: {first_blocker}"),
            "resolve or explicitly surface the blocker before continuing",
        );
        unsafe_issue_count = unsafe_issue_count.saturating_add(1);
    }

    SwarmHandoffVerification {
        schema_version: SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION.to_string(),
        capsule_id: capsule.capsule_id.clone(),
        decision,
        stale_evidence_count,
        coordination_required_count,
        unsafe_issue_count,
        next_action: handoff_next_action(decision).to_string(),
        self_contained: !capsule.capsule_id.trim().is_empty()
            && !capsule.current_agent.trim().is_empty()
            && !capsule.claimed_bead_ids.is_empty()
            && !capsule.proof_commands.is_empty()
            && capsule
                .proof_commands
                .iter()
                .all(|proof| !proof.command.trim().is_empty()),
        mutates_external_state: false,
        reasons,
    }
}

/// Deterministic knobs for the synthetic agent-run lab harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAgentRunScenario {
    /// Stable scenario identifier used in JSON evidence.
    pub scenario_id: String,
    /// Lab runtime seed.
    pub seed: u64,
    /// Number of synthetic agents to schedule.
    pub agent_count: usize,
    /// Logical remote RCH workers available to the scenario.
    pub rch_workers: usize,
    /// Agent that should observe remote-required RCH refusal.
    pub rch_refusal_agent: Option<usize>,
    /// Agent that should hit an unrelated validation frontier blocker.
    pub validation_blocker_agent: Option<usize>,
    /// Agent that should crash before completing proof handoff.
    pub crash_agent: Option<usize>,
    /// Maximum lab steps before the runtime stops.
    pub max_steps: u64,
}

impl Default for SwarmAgentRunScenario {
    fn default() -> Self {
        Self {
            scenario_id: "swarm-agent-run-default".to_string(),
            seed: 0xA6E1_7A5C,
            agent_count: 6,
            rch_workers: 2,
            rch_refusal_agent: Some(1),
            validation_blocker_agent: Some(3),
            crash_agent: Some(5),
            max_steps: 20_000,
        }
    }
}

impl SwarmAgentRunScenario {
    /// Validate that the synthetic agent run is bounded and replayable.
    pub fn validate(&self) -> Result<(), SwarmReplayError> {
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmReplayError::EmptyScenarioId);
        }
        if self.agent_count == 0 {
            return Err(SwarmReplayError::ZeroAgentCount);
        }
        if self.max_steps == 0 {
            return Err(SwarmReplayError::ZeroMaxSteps);
        }
        if self.agent_count > MAX_FIRST_SLICE_TASKS {
            return Err(SwarmReplayError::TooManyTasks {
                task_count: self.agent_count,
                max: MAX_FIRST_SLICE_TASKS,
            });
        }

        for (field, maybe_index) in [
            ("rch_refusal_agent", self.rch_refusal_agent),
            ("validation_blocker_agent", self.validation_blocker_agent),
            ("crash_agent", self.crash_agent),
        ] {
            if let Some(agent_index) = maybe_index {
                if agent_index >= self.agent_count {
                    return Err(SwarmReplayError::AgentIndexOutOfRange {
                        field,
                        agent_index,
                        agent_count: self.agent_count,
                    });
                }
            }
        }

        Ok(())
    }
}

/// Stable event kind emitted by the synthetic agent-run lab harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAgentRunEventKind {
    /// The agent claimed a bead in the modeled tracker.
    BeadClaimed,
    /// The agent acquired modeled file reservations.
    FileReserved,
    /// The agent sent modeled coordination mail.
    MailSent,
    /// The agent started an RCH-backed proof lane.
    RchProofStarted,
    /// Remote-required RCH refused local fallback.
    RchProofRemoteRefused,
    /// The proof lane passed.
    RchProofPassed,
    /// An unrelated validation frontier blocked completion.
    ValidationBlocked,
    /// A main-branch commit was recorded after proof success.
    CommitRecorded,
    /// The agent crashed before the run completed.
    AgentCrashed,
    /// A replayable handoff was emitted for a failed or interrupted run.
    RecoveryHandoffEmitted,
    /// The agent released modeled file reservations.
    FileReservationReleased,
}

/// One deterministic synthetic agent-run event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAgentRunEvent {
    /// Stable sequence number used for byte-stable ordering.
    pub stable_sequence: u64,
    /// Synthetic agent ordinal.
    pub agent_index: usize,
    /// Pseudonymized synthetic agent name.
    pub agent_name: String,
    /// Synthetic bead claimed by the agent.
    pub bead_id: String,
    /// Stable event kind.
    pub kind: SwarmAgentRunEventKind,
    /// Modeled source frontier touched by this agent.
    pub file_frontier: Vec<String>,
    /// Modeled proof command, when the event belongs to a proof lane.
    pub proof_command: Option<String>,
    /// Modeled blocker or failure reason.
    pub blocker: Option<String>,
    /// Modeled proof, handoff, or trace artifact references.
    pub artifact_refs: Vec<String>,
    /// Simulated main-branch commit id after a green proof.
    pub commit_id: Option<String>,
    /// Stable replay pointer for this event.
    pub replay_pointer: String,
    /// Whether this event mutates real external services or the repo.
    pub mutates_real_services: bool,
}

/// Forbidden real-world side effects for the synthetic lab harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAgentRunForbiddenActions {
    /// Whether the harness runs real Cargo.
    pub runs_cargo: bool,
    /// Whether the harness mutates Git state.
    pub runs_git_mutation: bool,
    /// Whether the harness mutates Beads state.
    pub runs_beads_mutation: bool,
    /// Whether the harness mutates Agent Mail state.
    pub runs_agent_mail_mutation: bool,
    /// Whether the harness runs destructive cleanup.
    pub runs_destructive_command: bool,
}

impl SwarmAgentRunForbiddenActions {
    const fn none() -> Self {
        Self {
            runs_cargo: false,
            runs_git_mutation: false,
            runs_beads_mutation: false,
            runs_agent_mail_mutation: false,
            runs_destructive_command: false,
        }
    }
}

/// Byte-stable summary emitted by the synthetic agent-run lab harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAgentRunSummary {
    /// Stable schema version.
    pub schema_version: String,
    /// Scenario id copied from input.
    pub scenario_id: String,
    /// Lab runtime seed.
    pub seed: u64,
    /// Number of synthetic agents submitted.
    pub agent_count: usize,
    /// Number of tasks scheduled into [`LabRuntime`].
    pub scheduled_task_count: usize,
    /// Number of tracked tasks that reached a terminal state.
    pub terminal_task_count: usize,
    /// Number of tracked tasks still non-terminal after the run.
    pub non_terminal_task_count: usize,
    /// Task leak count derived from non-terminal tracked tasks.
    pub task_leaks: usize,
    /// Number of modeled bead claims.
    pub bead_claim_count: usize,
    /// Number of modeled file reservations acquired.
    pub file_reservations_acquired: usize,
    /// Number of modeled file reservations released.
    pub file_reservations_released: usize,
    /// Number of modeled Agent Mail messages.
    pub mail_message_count: usize,
    /// Number of modeled RCH proof attempts.
    pub rch_proof_attempt_count: usize,
    /// Number of modeled remote-required RCH refusals.
    pub rch_remote_refusal_count: usize,
    /// Number of modeled unrelated validation blockers.
    pub validation_blocker_count: usize,
    /// Number of modeled proof passes.
    pub proof_pass_count: usize,
    /// Number of modeled commits after green proof.
    pub commit_count: usize,
    /// Number of modeled crashed agents.
    pub crashed_agent_count: usize,
    /// Number of replayable handoff records emitted.
    pub recovery_handoff_count: usize,
    /// Whether active bead ownership stayed unique.
    pub no_duplicate_ownership: bool,
    /// Whether every modeled file reservation was released.
    pub no_leaked_reservations: bool,
    /// Whether commits only appear after a green proof.
    pub no_false_green_proof: bool,
    /// Whether the harness is report-only and non-mutating.
    pub non_mutating: bool,
    /// Forbidden real-world side effects observed by the harness.
    pub forbidden_actions: SwarmAgentRunForbiddenActions,
    /// First blocker, if any, for operator handoff.
    pub first_blocker: Option<String>,
    /// Replay command for the deterministic lab scenario.
    pub replay_command: String,
    /// Whether the lab runtime reached quiescence.
    pub quiescent: bool,
    /// Canonical trace fingerprint from the lab run report.
    pub trace_fingerprint: u64,
    /// Trace event count from the lab run report.
    pub trace_event_count: usize,
    /// Runtime invariant violations from the lab run report.
    pub invariant_violations: Vec<String>,
    /// Deterministic event log for replay bundles and golden tests.
    pub event_log: Vec<SwarmAgentRunEvent>,
}

/// Deterministic shrink hint for failing swarm replay scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayShrinkHint {
    /// First task outcome that observed cancellation.
    pub first_cancelled_task: Option<usize>,
    /// Prefix length that preserves the first cancellation observation.
    pub event_prefix_len: usize,
    /// Region count to try first when shrinking this scenario.
    pub suggested_region_count: usize,
    /// Tasks per region to try first when shrinking this scenario.
    pub suggested_tasks_per_region: usize,
}

/// Byte-stable summary emitted after a swarm replay scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplaySummary {
    /// Stable schema version.
    pub schema_version: String,
    /// Scenario id copied from input.
    pub scenario_id: String,
    /// Lab runtime seed.
    pub seed: u64,
    /// Logical worker count modeled by the scenario.
    pub worker_count: usize,
    /// Logical worker cohort count modeled by the scenario.
    pub cohort_count: usize,
    /// Number of regions created.
    pub region_count: usize,
    /// Number of tasks modeled.
    pub task_count: usize,
    /// Number of tasks scheduled into the lab runtime.
    pub scheduled_task_count: usize,
    /// Number of tasks admitted by region admission control.
    pub admitted_task_count: usize,
    /// Number of tasks rejected by region admission control.
    pub rejected_task_count: usize,
    /// Number of tasks deferred by region admission control.
    pub deferred_task_count: usize,
    /// Number of tasks shed by region admission control.
    pub shed_task_count: usize,
    /// Number of tasks rejected by an admission-cancel decision.
    pub admission_cancelled_task_count: usize,
    /// Number of cancellation requests scheduled into cancel lanes.
    pub cancellation_requests: usize,
    /// Number of tasks that reached a terminal state by the end of the run.
    pub terminal_task_count: usize,
    /// Number of tracked tasks still non-terminal at the end of the run.
    pub non_terminal_task_count: usize,
    /// Number of modeled channel reservations.
    pub channel_reservations: usize,
    /// Number of modeled channel sends committed by completed tasks.
    pub channel_commits: usize,
    /// Number of modeled channel reservations aborted by cancelled tasks.
    pub channel_aborts: usize,
    /// Maximum modeled channel backlog.
    pub channel_backlog_peak: usize,
    /// Number of modeled semaphore acquisitions.
    pub semaphore_acquires: usize,
    /// Number of modeled semaphore releases.
    pub semaphore_releases: usize,
    /// Number of modeled pool slot checkouts.
    pub pool_checkouts: usize,
    /// Number of modeled pool slot checkins.
    pub pool_checkins: usize,
    /// Number of modeled obligations committed by completed tasks.
    pub obligation_commits: usize,
    /// Number of modeled obligations aborted by cancelled tasks.
    pub obligation_aborts: usize,
    /// Number of modeled virtual timer registrations.
    pub timer_registrations: usize,
    /// Number of modeled virtual timer wakeups.
    pub timer_wakeups: usize,
    /// Depth of the modeled cancellation tree.
    pub cancellation_tree_depth: usize,
    /// Scheduler steps spent after explicit cancellation was requested.
    pub cancellation_drain_steps: u64,
    /// Total modeled artifact bytes emitted by normally completed tasks.
    pub artifact_bytes_emitted: usize,
    /// Scheduler steps run by `LabRuntime`.
    pub steps_delta: u64,
    /// Whether the runtime reached quiescence.
    pub quiescent: bool,
    /// Canonical trace fingerprint from the lab run report.
    pub trace_fingerprint: u64,
    /// Hex digest of the canonical trace fingerprint for JSON/NDJSON artifacts.
    pub trace_digest: String,
    /// Trace event count from the lab run report.
    pub trace_event_count: usize,
    /// Runtime invariant violations from the lab run report.
    pub invariant_violations: Vec<String>,
    /// Actual terminal task order observed by the lab run.
    pub completion_order: Vec<usize>,
    /// Sorted deterministic event log.
    pub event_log: Vec<SwarmReplayEvent>,
    /// Per-task terminal outcomes sorted by global task index.
    pub task_outcomes: Vec<SwarmReplayTaskOutcome>,
    /// Deterministic shrink hint for replay minimization.
    pub shrink_hint: SwarmReplayShrinkHint,
    /// Region-level admission evidence.
    pub admission_records: Vec<SwarmReplayAdmissionRecord>,
}

fn region_admission_requirements() -> CapabilityBudgetRequirements {
    CapabilityBudgetRequirements::new()
        .require_cpu_units()
        .require_memory_bytes()
        .require_io_bytes()
        .require_cleanup()
        .require_artifact_bytes()
}

fn region_capability_budget(
    scenario: &SwarmReplayScenario,
    admitted_tasks: usize,
) -> CapabilityBudget {
    let admitted = admitted_tasks as u64;
    let memory_bytes = scenario
        .region_memory_bytes_per_task
        .saturating_mul(admitted);
    let io_bytes = scenario
        .region_queue_depth_units_per_task
        .saturating_mul(admitted)
        .saturating_add(
            scenario
                .region_blocking_pool_units_per_task
                .saturating_mul(admitted),
        );
    let cleanup_quota = scenario
        .region_cleanup_poll_quota_per_task
        .saturating_mul(admitted)
        .min(u64::from(u32::MAX)) as u32;
    let artifact_bytes = (scenario.artifact_bytes_per_task as u64).saturating_mul(admitted);

    CapabilityBudget::new()
        .with_cpu_units(admitted)
        .with_memory_bytes(memory_bytes)
        .with_io_bytes(io_bytes)
        .with_cleanup_budget(Budget::new().with_poll_quota(cleanup_quota))
        .with_artifact_bytes(artifact_bytes)
}

fn admission_event_kind(decision: SwarmReplayAdmissionDecision) -> SwarmReplayEventKind {
    match decision {
        SwarmReplayAdmissionDecision::Accept => SwarmReplayEventKind::AdmissionAccepted,
        SwarmReplayAdmissionDecision::Defer => SwarmReplayEventKind::AdmissionDeferred,
        SwarmReplayAdmissionDecision::Shed => SwarmReplayEventKind::AdmissionShed,
        SwarmReplayAdmissionDecision::Cancel => SwarmReplayEventKind::AdmissionCancelled,
    }
}

fn primary_budget_class_for_refusal(reason: &str) -> SwarmReplayBudgetClass {
    if reason.contains(CapabilityBudgetDimension::MemoryBytes.as_str()) {
        SwarmReplayBudgetClass::MemoryEnvelope
    } else if reason.contains(CapabilityBudgetDimension::IoBytes.as_str()) {
        SwarmReplayBudgetClass::QueueDepth
    } else if reason.contains(CapabilityBudgetDimension::Cleanup.as_str()) {
        SwarmReplayBudgetClass::CleanupDrainWork
    } else if reason.contains(CapabilityBudgetDimension::ArtifactBytes.as_str()) {
        SwarmReplayBudgetClass::ArtifactBytes
    } else {
        SwarmReplayBudgetClass::RunnableTaskSlots
    }
}

/// Run a deterministic swarm replay scenario through [`LabRuntime`].
pub fn run_swarm_replay_scenario(
    scenario: &SwarmReplayScenario,
) -> Result<SwarmReplaySummary, SwarmReplayError> {
    scenario.validate()?;

    let config = LabConfig::new(scenario.seed)
        .worker_count(scenario.worker_count)
        .max_steps(scenario.max_steps)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let events = Arc::new(Mutex::new(Vec::new()));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let completion_order = Arc::new(Mutex::new(Vec::new()));
    let mut rng = DetRng::new(scenario.seed);
    let mut region_ids = Vec::with_capacity(scenario.region_count);
    let mut scheduled_tasks = Vec::with_capacity(scenario.task_count());
    let mut tracked_tasks = Vec::with_capacity(scenario.task_count());
    let mut admission_records = Vec::with_capacity(scenario.region_count);
    let mut admission_cancel_regions = Vec::new();

    let scenario_root = runtime.state.create_root_region(Budget::INFINITE);

    for region_index in 0..scenario.region_count {
        let requested_tasks = scenario.tasks_per_region;
        let admission_limit = scenario
            .region_task_admission_limit
            .unwrap_or(requested_tasks);
        let admitted_tasks = requested_tasks.min(admission_limit);
        let rejected_tasks = requested_tasks.saturating_sub(admitted_tasks);
        let admission_decision = if rejected_tasks == 0 {
            SwarmReplayAdmissionDecision::Accept
        } else {
            scenario.region_over_limit_decision
        };
        let capability_budget = region_capability_budget(scenario, admitted_tasks);
        let region = runtime.state.create_child_region_with_capability_budget(
            scenario_root,
            Budget::INFINITE,
            capability_budget,
            region_admission_requirements(),
        );
        let region = match region {
            Ok(region) => region,
            Err(err) => {
                let reason = err.to_string();
                events.lock().push(SwarmReplayEvent {
                    kind: admission_event_kind(admission_decision),
                    region_index,
                    region_id: None,
                    task_index: None,
                    global_task_index: None,
                    budget_class: Some(primary_budget_class_for_refusal(&reason)),
                    queue_depth: rejected_tasks,
                    artifact_bytes: 0,
                });
                admission_records.push(SwarmReplayAdmissionRecord {
                    region_index,
                    region_id: None,
                    budget_class: primary_budget_class_for_refusal(&reason),
                    decision: admission_decision,
                    requested_tasks,
                    admitted_tasks: 0,
                    rejected_tasks: requested_tasks,
                    before_remaining_units: admission_limit,
                    after_remaining_units: 0,
                    refusal: Some(reason),
                    cancellation_requested: false,
                    drain_result: SwarmReplayAdmissionDrainResult::RefusedBeforeRegion,
                    quiescence_verdict: false,
                });
                continue;
            }
        };
        let region_id = region.as_u64();
        region_ids.push((region_index, region));
        if admission_decision == SwarmReplayAdmissionDecision::Cancel && admitted_tasks > 0 {
            admission_cancel_regions.push((region_index, region));
        }
        events.lock().push(SwarmReplayEvent {
            kind: admission_event_kind(admission_decision),
            region_index,
            region_id: Some(region_id),
            task_index: None,
            global_task_index: None,
            budget_class: Some(SwarmReplayBudgetClass::RunnableTaskSlots),
            queue_depth: rejected_tasks,
            artifact_bytes: 0,
        });
        admission_records.push(SwarmReplayAdmissionRecord {
            region_index,
            region_id: Some(region_id),
            budget_class: SwarmReplayBudgetClass::RunnableTaskSlots,
            decision: admission_decision,
            requested_tasks,
            admitted_tasks,
            rejected_tasks,
            before_remaining_units: admission_limit,
            after_remaining_units: admission_limit.saturating_sub(admitted_tasks),
            refusal: None,
            cancellation_requested: admission_decision == SwarmReplayAdmissionDecision::Cancel
                && admitted_tasks > 0,
            drain_result: if admission_decision == SwarmReplayAdmissionDecision::Cancel
                && admitted_tasks > 0
            {
                SwarmReplayAdmissionDrainResult::CancellationRequested
            } else {
                SwarmReplayAdmissionDrainResult::NotRequired
            },
            quiescence_verdict: false,
        });

        for task_index in 0..admitted_tasks {
            let global_task_index = region_index
                .saturating_mul(scenario.tasks_per_region)
                .saturating_add(task_index);
            let jitter = if scenario.yield_jitter == 0 {
                0
            } else {
                rng.next_usize(scenario.yield_jitter + 1)
            };
            let yield_points = scenario.yields_per_task.saturating_add(jitter);
            let queue_depth = scenario
                .messages_per_task
                .saturating_add(jitter)
                .min(scenario.channel_capacity);
            let messages_per_task = scenario.messages_per_task;
            let semaphore_permits = scenario.semaphore_permits_per_task;
            let pool_slots = scenario.pool_slots_per_task;
            let obligations_per_task = scenario.obligations_per_task;
            let timer_ticks = scenario.timer_ticks_per_task;
            let events_for_task = Arc::clone(&events);
            let outcomes_for_task = Arc::clone(&outcomes);
            let order_for_task = Arc::clone(&completion_order);
            let artifact_bytes = scenario.artifact_bytes_per_task;

            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::SemaphoreAcquired,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::BlockingPoolSubmissions),
                        queue_depth: semaphore_permits,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::PoolSlotCheckedOut,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::BlockingPoolSubmissions),
                        queue_depth: pool_slots,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::MessageReserved,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::QueueDepth),
                        queue_depth,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::TimerAdvanced,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
                        queue_depth: timer_ticks,
                        artifact_bytes: 0,
                    });

                    for _ in 0..yield_points {
                        let Some(cx) = Cx::current() else {
                            return;
                        };
                        if cx.checkpoint().is_err() {
                            events_for_task.lock().push(SwarmReplayEvent {
                                kind: SwarmReplayEventKind::MessageAborted,
                                region_index,
                                region_id: Some(region_id),
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
                                budget_class: Some(SwarmReplayBudgetClass::QueueDepth),
                                queue_depth: messages_per_task,
                                artifact_bytes: 0,
                            });
                            events_for_task.lock().push(SwarmReplayEvent {
                                kind: SwarmReplayEventKind::ObligationAborted,
                                region_index,
                                region_id: Some(region_id),
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
                                budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
                                queue_depth: obligations_per_task,
                                artifact_bytes: 0,
                            });
                            events_for_task.lock().push(SwarmReplayEvent {
                                kind: SwarmReplayEventKind::CancelObserved,
                                region_index,
                                region_id: Some(region_id),
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
                                budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
                                queue_depth,
                                artifact_bytes: 0,
                            });
                            outcomes_for_task.lock().push(SwarmReplayTaskOutcome {
                                global_task_index,
                                region_index,
                                task_index,
                                status: SwarmReplayTaskStatus::Cancelled,
                                yield_points,
                            });
                            order_for_task.lock().push(global_task_index);
                            return;
                        }
                        yield_once().await;
                    }

                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::MessageCommitted,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::QueueDepth),
                        queue_depth: messages_per_task,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::ObligationCommitted,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
                        queue_depth: obligations_per_task,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::ArtifactEmitted,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: Some(SwarmReplayBudgetClass::ArtifactBytes),
                        queue_depth,
                        artifact_bytes,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::Completed,
                        region_index,
                        region_id: Some(region_id),
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        budget_class: None,
                        queue_depth,
                        artifact_bytes: 0,
                    });
                    outcomes_for_task.lock().push(SwarmReplayTaskOutcome {
                        global_task_index,
                        region_index,
                        task_index,
                        status: SwarmReplayTaskStatus::Completed,
                        yield_points,
                    });
                    order_for_task.lock().push(global_task_index);
                })
                .map_err(|err| SwarmReplayError::TaskSpawnRejected {
                    region_index,
                    task_index,
                    reason: format!("{err:?}"), // ubs:ignore - error path only
                })?;

            tracked_tasks.push(task_id);
            scheduled_tasks.push((
                task_id,
                SwarmReplayEvent {
                    kind: SwarmReplayEventKind::TaskScheduled,
                    region_index,
                    region_id: Some(region_id),
                    task_index: Some(task_index),
                    global_task_index: Some(global_task_index),
                    budget_class: Some(SwarmReplayBudgetClass::RunnableTaskSlots),
                    queue_depth: 0,
                    artifact_bytes: 0,
                },
            ));
        }
    }

    shuffle_tasks(&mut scheduled_tasks, scenario.seed);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task_id, event) in &scheduled_tasks {
            scheduler.schedule(*task_id, 0);
            events.lock().push(event.clone()); // ubs:ignore - simulation setup iteration
        }
    }

    let mut cancellation_requests = 0usize;
    for (region_index, region) in &admission_cancel_regions {
        let tasks = runtime.state.cancel_request(
            *region,
            &CancelReason::user("swarm replay admission budget exhausted"),
            None,
        );
        cancellation_requests = cancellation_requests.saturating_add(tasks.len());
        events.lock().push(SwarmReplayEvent {
            kind: SwarmReplayEventKind::CancellationRequested,
            region_index: *region_index,
            region_id: Some(region.as_u64()),
            task_index: None,
            global_task_index: None,
            budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
            queue_depth: 0,
            artifact_bytes: 0,
        });

        let mut scheduler = runtime.scheduler.lock();
        for (task_id, priority) in tasks {
            scheduler.schedule_cancel(task_id, priority);
        }
    }
    if let Some(cancel_after_steps) = scenario.cancel_after_steps {
        for _ in 0..cancel_after_steps {
            runtime.step_for_test();
        }

        for (region_index, region) in &region_ids {
            let tasks = runtime.state.cancel_request(
                *region,
                &CancelReason::user("swarm replay cascade"),
                None,
            );
            cancellation_requests = cancellation_requests.saturating_add(tasks.len());
            events.lock().push(SwarmReplayEvent {
                kind: SwarmReplayEventKind::CancellationRequested,
                region_index: *region_index,
                region_id: Some(region.as_u64()),
                task_index: None,
                global_task_index: None,
                budget_class: Some(SwarmReplayBudgetClass::CleanupDrainWork),
                queue_depth: 0,
                artifact_bytes: 0,
            });

            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks {
                scheduler.schedule_cancel(task_id, priority);
            }
        }
    }

    let report = runtime.run_until_quiescent_with_report();
    for record in &mut admission_records {
        record.quiescence_verdict = report.quiescent;
        if record.drain_result == SwarmReplayAdmissionDrainResult::CancellationRequested
            && report.quiescent
        {
            record.drain_result = SwarmReplayAdmissionDrainResult::Quiescent;
        }
    }
    let terminal_counts = terminal_counts(&runtime, &tracked_tasks);
    let mut event_log = events.lock().clone();
    let mut task_outcomes = outcomes.lock().clone();
    let completion_order = completion_order.lock().clone();

    event_log.sort_by_key(|event| {
        (
            event.region_index,
            event.region_id,
            event.global_task_index.unwrap_or(usize::MAX),
            event.kind,
            event.budget_class,
            event.queue_depth,
            event.artifact_bytes,
        )
    });
    task_outcomes.sort_by_key(|outcome| outcome.global_task_index);

    Ok(build_summary(
        scenario,
        report,
        scheduled_tasks.len(),
        cancellation_requests,
        terminal_counts,
        event_log,
        task_outcomes,
        completion_order,
        admission_records,
    ))
}

/// Run a high-concurrency swarm pressure scenario through [`LabRuntime`].
pub fn run_swarm_pressure_scenario(
    scenario: &SwarmPressureScenario,
) -> Result<SwarmPressureSummary, SwarmReplayError> {
    scenario.validate()?;

    let config = LabConfig::new(scenario.seed)
        .worker_count(scenario.worker_count)
        .max_steps(scenario.max_steps)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let disk_transitions = sorted_disk_transitions(scenario);
    let rch_events = sorted_rch_events(scenario);
    let mut event_log = Vec::new();
    let mut tracked_tasks = Vec::with_capacity(
        scenario
            .interactive_tasks
            .saturating_add(scenario.proof_tasks)
            .saturating_add(scenario.cleanup_requests),
    );

    for transition in &disk_transitions {
        event_log.push(SwarmPressureEvent {
            kind: SwarmPressureEventKind::DiskPressureChanged,
            step: transition.at_step,
            lane: None,
            queue_depth: 0,
            rch_workers_available: rch_workers_at_step(
                &rch_events,
                scenario.rch_workers_initial,
                scenario.worker_count,
                transition.at_step,
            ),
            disk_pressure: transition.level,
            admission_latency_steps: 0,
            cleanup_authorized: false,
            auto_delete_command_count: 0,
        });
    }

    for event in &rch_events {
        event_log.push(SwarmPressureEvent {
            kind: match event.kind {
                SwarmRchWorkerEventKind::Loss => SwarmPressureEventKind::RchWorkersLost,
                SwarmRchWorkerEventKind::Recovery => SwarmPressureEventKind::RchWorkersRecovered,
            },
            step: event.at_step,
            lane: None,
            queue_depth: 0,
            rch_workers_available: rch_workers_at_step(
                &rch_events,
                scenario.rch_workers_initial,
                scenario.worker_count,
                event.at_step,
            ),
            disk_pressure: disk_pressure_at_step(&disk_transitions, event.at_step),
            admission_latency_steps: 0,
            cleanup_authorized: false,
            auto_delete_command_count: 0,
        });
    }

    let mut scheduled_task_count = 0usize;
    let mut max_interactive_admission_latency_steps = 0u64;
    for index in 0..scenario.interactive_tasks {
        let admission_latency_steps = (index / scenario.worker_count) as u64;
        max_interactive_admission_latency_steps =
            max_interactive_admission_latency_steps.max(admission_latency_steps);
        let step = (index as u64).saturating_add(admission_latency_steps);
        let queue_depth = scenario.interactive_tasks.saturating_sub(index + 1);
        event_log.push(SwarmPressureEvent {
            kind: SwarmPressureEventKind::InteractiveAdmitted,
            step,
            lane: Some(SwarmPressureLane::Interactive),
            queue_depth,
            rch_workers_available: rch_workers_at_step(
                &rch_events,
                scenario.rch_workers_initial,
                scenario.worker_count,
                step,
            ),
            disk_pressure: disk_pressure_at_step(&disk_transitions, step),
            admission_latency_steps,
            cleanup_authorized: false,
            auto_delete_command_count: 0,
        });
        let task_id = spawn_pressure_task(
            &mut runtime,
            root,
            index,
            SwarmPressureLane::Interactive,
            1 + index % 3,
        )?;
        runtime.scheduler.lock().schedule(task_id, 9);
        tracked_tasks.push(task_id);
        scheduled_task_count = scheduled_task_count.saturating_add(1);
    }

    let mut proof_throttled_count = 0usize;
    for index in 0..scenario.proof_tasks {
        let step = index as u64 % scenario.max_steps; // ubs:ignore - test oracle truncation
        let disk_pressure = disk_pressure_at_step(&disk_transitions, step);
        let rch_workers_available = rch_workers_at_step(
            &rch_events,
            scenario.rch_workers_initial,
            scenario.worker_count,
            step,
        );
        let queue_depth = scenario.proof_tasks.saturating_sub(index + 1);
        let throttled = disk_pressure == SwarmDiskPressureLevel::Red || rch_workers_available == 0;
        event_log.push(SwarmPressureEvent {
            kind: if throttled {
                SwarmPressureEventKind::ProofThrottled
            } else {
                SwarmPressureEventKind::ProofAdmitted
            },
            step,
            lane: Some(SwarmPressureLane::Proof),
            queue_depth,
            rch_workers_available,
            disk_pressure,
            admission_latency_steps: u64::from(throttled),
            cleanup_authorized: false,
            auto_delete_command_count: 0,
        });
        if throttled {
            proof_throttled_count = proof_throttled_count.saturating_add(1);
            continue;
        }
        let task_id = spawn_pressure_task(
            &mut runtime,
            root,
            scenario.interactive_tasks.saturating_add(index),
            SwarmPressureLane::Proof,
            2 + index % 4,
        )?;
        runtime.scheduler.lock().schedule(task_id, 3);
        tracked_tasks.push(task_id);
        scheduled_task_count = scheduled_task_count.saturating_add(1);
    }

    let mut cleanup_authorization_required_count = 0usize;
    for index in 0..scenario.cleanup_requests {
        let step = index as u64;
        cleanup_authorization_required_count =
            cleanup_authorization_required_count.saturating_add(1);
        event_log.push(SwarmPressureEvent {
            kind: SwarmPressureEventKind::CleanupRequested,
            step,
            lane: Some(SwarmPressureLane::Cleanup),
            queue_depth: scenario.cleanup_requests.saturating_sub(index + 1),
            rch_workers_available: rch_workers_at_step(
                &rch_events,
                scenario.rch_workers_initial,
                scenario.worker_count,
                step,
            ),
            disk_pressure: disk_pressure_at_step(&disk_transitions, step),
            admission_latency_steps: 0,
            cleanup_authorized: false,
            auto_delete_command_count: 0,
        });
        let task_id = spawn_pressure_task(
            &mut runtime,
            root,
            scenario
                .interactive_tasks
                .saturating_add(scenario.proof_tasks)
                .saturating_add(index),
            SwarmPressureLane::Cleanup,
            1,
        )?;
        runtime.scheduler.lock().schedule(task_id, 1);
        tracked_tasks.push(task_id);
        scheduled_task_count = scheduled_task_count.saturating_add(1);
    }

    event_log.sort_by_key(|event| {
        (
            event.step,
            event.kind,
            event.lane,
            event.queue_depth,
            event.rch_workers_available,
        )
    });

    let report = runtime.run_until_quiescent_with_report();
    let terminal_counts = terminal_counts(&runtime, &tracked_tasks);
    let auto_delete_command_count = event_log
        .iter()
        .map(|event| event.auto_delete_command_count)
        .sum::<usize>();

    Ok(SwarmPressureSummary {
        schema_version: SWARM_PRESSURE_SCHEMA_VERSION.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        worker_count: scenario.worker_count,
        interactive_tasks: scenario.interactive_tasks,
        proof_tasks: scenario.proof_tasks,
        cleanup_requests: scenario.cleanup_requests,
        max_interactive_admission_latency_steps,
        interactive_latency_bound_steps: scenario.interactive_latency_bound_steps,
        proof_throttled_count,
        cleanup_authorization_required_count,
        auto_delete_command_count,
        disk_pressure_transition_count: disk_transitions.len(),
        rch_worker_loss_events: rch_events
            .iter()
            .filter(|event| event.kind == SwarmRchWorkerEventKind::Loss) // ubs:ignore - enum comparison, not a secret
            .count(),
        rch_worker_recovery_events: rch_events
            .iter()
            .filter(|event| event.kind == SwarmRchWorkerEventKind::Recovery)
            .count(),
        scheduled_task_count,
        terminal_task_count: terminal_counts.0,
        non_terminal_task_count: terminal_counts.1,
        task_leaks: terminal_counts.1,
        quiescent: report.quiescent,
        trace_fingerprint: report.trace_fingerprint,
        trace_event_count: report.trace_len,
        invariant_violations: report.invariant_violations,
        event_log,
    })
}

/// Summarize a JSON swarm trace artifact with fail-closed required-field checks.
///
/// This entrypoint is intended for scripts and e2e harnesses that read artifacts
/// before choosing the concrete typed summary. Missing quiescence or obligation
/// fields force an [`SwarmPressureTraceVerdict::Incomplete`] verdict so an
/// operator never gets a false green summary from a partial trace.
#[must_use]
pub fn summarize_swarm_trace_artifact_json(value: &serde_json::Value) -> SwarmPressureTraceSummary {
    let source_schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    match source_schema_version {
        SWARM_REPLAY_SCHEMA_VERSION => summarize_replay_artifact_json(value),
        SWARM_PRESSURE_SCHEMA_VERSION => summarize_pressure_artifact_json(value),
        SWARM_AGENT_RUN_SCHEMA_VERSION => summarize_agent_run_artifact_json(value),
        _ => {
            let missing_required_fields = if source_schema_version == "unknown" {
                vec!["schema_version".to_string()]
            } else {
                Vec::new()
            };
            incomplete_trace_summary(
                SwarmPressureTraceSourceKind::Unknown,
                source_schema_version,
                value,
                missing_required_fields,
                Some(format!(
                    "unsupported swarm trace schema version `{source_schema_version}`"
                )),
            )
        }
    }
}

/// Summarize a typed replay-lab artifact into stable JSON-ready counters.
#[must_use]
pub fn summarize_swarm_replay_trace(summary: &SwarmReplaySummary) -> SwarmPressureTraceSummary {
    let cancelled_tasks = summary
        .task_outcomes
        .iter()
        .filter(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled)
        .count();
    let accepted = summary
        .admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Accept)
        .count();
    let deferred = summary
        .admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Defer)
        .count();
    let shed = summary
        .admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Shed)
        .count();
    let cancelled_admissions = summary
        .admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Cancel)
        .count();
    let cancellation_requests = summary.cancellation_requests;
    let losers_drained =
        cancellation_requests == 0 || (summary.quiescent && summary.non_terminal_task_count == 0);
    let resolved_obligations = summary
        .obligation_commits
        .saturating_add(summary.obligation_aborts);
    let unresolved_obligations = if summary.quiescent && summary.non_terminal_task_count == 0 {
        0
    } else {
        summary
            .non_terminal_task_count
            .max(bool_as_usize(obligation_violation_present(
                &summary.invariant_violations,
            )))
    };
    let obligation_leak_suspects = replay_obligation_leak_suspects(summary, unresolved_obligations);
    let first_invariant_violation = summary.invariant_violations.first().cloned();
    let required_fields_present = true;
    let verdict = trace_verdict(
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        unresolved_obligations,
        &summary.invariant_violations,
    );
    let top_hot_regions = replay_hot_regions(summary);
    let largest_queues = replay_largest_queues(summary);
    let longest_drains = replay_longest_drains(summary);
    let queue_pressure = replay_queue_pressure(summary, &largest_queues);
    let first_rejection = summary
        .admission_records
        .iter()
        .find_map(|record| record.refusal.clone())
        .or_else(|| {
            summary
                .admission_records
                .iter()
                .find(|record| record.rejected_tasks > 0)
                .map(|record| {
                    format!(
                        "region {} {:?} rejected {} task(s)",
                        record.region_index, record.decision, record.rejected_tasks
                    )
                })
        });
    let routing_hints = trace_routing_hints(
        SwarmPressureTraceSourceKind::ReplayLab,
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        unresolved_obligations,
        first_invariant_violation.as_deref(),
        first_rejection.as_deref(),
    );

    SwarmPressureTraceSummary {
        schema_version: SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION.to_string(),
        source_schema_version: summary.schema_version.clone(),
        source_kind: SwarmPressureTraceSourceKind::ReplayLab,
        scenario_id: summary.scenario_id.clone(),
        seed: summary.seed,
        verdict,
        required_fields_present,
        missing_required_fields: Vec::new(),
        first_invariant_violation,
        region_lifecycle: SwarmPressureTraceRegionLifecycle {
            regions_declared: summary.region_count,
            regions_with_runtime_id: summary
                .admission_records
                .iter()
                .filter(|record| record.region_id.is_some())
                .count(),
            quiescent_regions: summary
                .admission_records
                .iter()
                .filter(|record| record.quiescence_verdict)
                .count(),
            non_quiescent_regions: summary
                .admission_records
                .iter()
                .filter(|record| !record.quiescence_verdict)
                .count(),
        },
        task_lifecycle: SwarmPressureTraceTaskLifecycle {
            submitted_tasks: summary.task_count,
            scheduled_tasks: summary.scheduled_task_count,
            terminal_tasks: summary.terminal_task_count,
            non_terminal_tasks: summary.non_terminal_task_count,
            task_leaks: summary.non_terminal_task_count,
        },
        cancellation: SwarmPressureTraceCancellation {
            cancellation_requests,
            cancelled_tasks,
            cancellation_drain_steps: summary.cancellation_drain_steps,
            losers_drained,
        },
        obligations: SwarmPressureTraceObligations {
            fields_present: true,
            resolved_obligations,
            committed_obligations: summary.obligation_commits,
            aborted_obligations: summary.obligation_aborts,
            unresolved_obligations,
        },
        queue_pressure,
        admission: SwarmPressureTraceAdmission {
            accepted,
            deferred,
            shed,
            cancelled: cancelled_admissions,
            proof_admitted: 0,
            proof_throttled: 0,
            interactive_admitted: 0,
            cleanup_requested: 0,
            combiner_or_admission_decisions: summary.admission_records.len(),
            first_rejection,
        },
        cleanup: SwarmPressureTraceCleanup {
            cleanup_requests: cancellation_requests,
            authorization_required: 0,
            authorized: cancellation_requests,
            max_cleanup_latency_steps: summary.cancellation_drain_steps,
            auto_delete_command_count: 0,
        },
        top_hot_regions,
        longest_drains,
        largest_queues,
        obligation_leak_suspects,
        routing_hints,
    }
}

/// Derive scheduler feedback metrics from a real replay-lab swarm run.
///
/// The conversion intentionally uses only fields emitted by
/// [`run_swarm_replay_scenario`]. It gives feedback dry-runs an evidence source
/// rooted in deterministic LabRuntime pressure instead of benchmark-local
/// synthetic cost functions.
#[must_use]
pub fn scheduler_feedback_metrics_from_swarm_replay(
    scenario: &SwarmReplayScenario,
    summary: &SwarmReplaySummary,
) -> SchedulerFeedbackMetrics {
    let worker_region_slots = scenario
        .worker_count
        .max(1)
        .saturating_mul(scenario.region_count.max(1));
    let ready_slots = scenario
        .worker_count
        .max(1)
        .saturating_mul(scenario.tasks_per_region.max(1));
    let reservation_capacity = scenario
        .region_count
        .max(1)
        .saturating_mul(scenario.channel_capacity.max(1));
    let blocking_capacity = summary
        .scheduled_task_count
        .max(1)
        .saturating_mul(scenario.pool_slots_per_task.max(1))
        .saturating_mul(2);
    let requested_memory = (summary.admitted_task_count as u64)
        .saturating_mul(scenario.region_memory_bytes_per_task.max(1));
    let modeled_memory_budget = (summary.task_count.max(1) as u64)
        .saturating_mul(scenario.region_memory_bytes_per_task.max(1))
        .saturating_mul(2);
    let scheduled_tasks = summary.scheduled_task_count.max(1);
    let dispatch_latency_base = summary
        .steps_delta
        .saturating_mul(1_000)
        .saturating_div(scheduled_tasks as u64);
    let queue_latency = (summary.channel_backlog_peak as u64).saturating_mul(100);

    SchedulerFeedbackMetrics {
        runnable_queue_pressure: Some(pressure_ratio_usize(
            summary.scheduled_task_count,
            worker_region_slots,
        )),
        ready_queue_pressure: Some(pressure_ratio_usize(
            summary
                .terminal_task_count
                .saturating_add(summary.non_terminal_task_count),
            ready_slots,
        )),
        blocking_pool_pressure: Some(pressure_ratio_usize(
            summary.pool_checkouts,
            blocking_capacity,
        )),
        channel_backlog_pressure: Some(pressure_ratio_usize(
            summary
                .channel_backlog_peak
                .max(summary.channel_reservations / scenario.region_count.max(1)),
            reservation_capacity,
        )),
        cancellation_pressure: Some(pressure_ratio_usize(
            summary
                .cancellation_requests
                .saturating_add(summary.admission_cancelled_task_count),
            scheduled_tasks,
        )),
        cleanup_debt_pressure: Some(pressure_ratio_u64(
            summary.cancellation_drain_steps,
            summary.steps_delta.max(1),
        )),
        memory_budget_pressure: Some(pressure_ratio_u64(requested_memory, modeled_memory_budget)),
        p95_dispatch_latency_us: Some(dispatch_latency_base.saturating_add(queue_latency)),
        p99_dispatch_latency_us: Some(
            dispatch_latency_base
                .saturating_add(queue_latency.saturating_mul(2))
                .saturating_add(summary.cancellation_drain_steps.saturating_mul(100)),
        ),
    }
}

fn pressure_ratio_usize(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn pressure_ratio_u64(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Summarize a typed pressure-lab artifact into stable JSON-ready counters.
#[must_use]
pub fn summarize_swarm_pressure_trace(summary: &SwarmPressureSummary) -> SwarmPressureTraceSummary {
    let proof_admitted = summary
        .event_log
        .iter()
        .filter(|event| event.kind == SwarmPressureEventKind::ProofAdmitted)
        .count();
    let proof_throttled = summary
        .event_log
        .iter()
        .filter(|event| event.kind == SwarmPressureEventKind::ProofThrottled)
        .count();
    let interactive_admitted = summary
        .event_log
        .iter()
        .filter(|event| event.kind == SwarmPressureEventKind::InteractiveAdmitted)
        .count();
    let cleanup_requested = summary
        .event_log
        .iter()
        .filter(|event| event.kind == SwarmPressureEventKind::CleanupRequested)
        .count();
    let required_fields_present = false;
    let missing_required_fields = pressure_missing_required_fields();
    let largest_queues = pressure_largest_queues(summary);
    let queue_pressure = pressure_queue_pressure(summary, &largest_queues);
    let first_invariant_violation = summary.invariant_violations.first().cloned();
    let verdict = trace_verdict(
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        0,
        &summary.invariant_violations,
    );
    let routing_hints = trace_routing_hints(
        SwarmPressureTraceSourceKind::PressureLab,
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        0,
        first_invariant_violation.as_deref(),
        None,
    );

    SwarmPressureTraceSummary {
        schema_version: SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION.to_string(),
        source_schema_version: summary.schema_version.clone(),
        source_kind: SwarmPressureTraceSourceKind::PressureLab,
        scenario_id: summary.scenario_id.clone(),
        seed: summary.seed,
        verdict,
        required_fields_present,
        missing_required_fields,
        first_invariant_violation,
        region_lifecycle: SwarmPressureTraceRegionLifecycle {
            regions_declared: 0,
            regions_with_runtime_id: 0,
            quiescent_regions: bool_as_usize(summary.quiescent),
            non_quiescent_regions: bool_as_usize(!summary.quiescent),
        },
        task_lifecycle: SwarmPressureTraceTaskLifecycle {
            submitted_tasks: summary
                .interactive_tasks
                .saturating_add(summary.proof_tasks)
                .saturating_add(summary.cleanup_requests),
            scheduled_tasks: summary.scheduled_task_count,
            terminal_tasks: summary.terminal_task_count,
            non_terminal_tasks: summary.non_terminal_task_count,
            task_leaks: summary.task_leaks,
        },
        cancellation: SwarmPressureTraceCancellation {
            cancellation_requests: 0,
            cancelled_tasks: 0,
            cancellation_drain_steps: 0,
            losers_drained: summary.quiescent && summary.non_terminal_task_count == 0,
        },
        obligations: SwarmPressureTraceObligations {
            fields_present: false,
            resolved_obligations: 0,
            committed_obligations: 0,
            aborted_obligations: 0,
            unresolved_obligations: 0,
        },
        queue_pressure,
        admission: SwarmPressureTraceAdmission {
            accepted: proof_admitted.saturating_add(interactive_admitted),
            deferred: 0,
            shed: 0,
            cancelled: 0,
            proof_admitted,
            proof_throttled,
            interactive_admitted,
            cleanup_requested,
            combiner_or_admission_decisions: summary.event_log.len(),
            first_rejection: (proof_throttled > 0)
                .then(|| format!("{proof_throttled} proof task(s) throttled by disk/RCH pressure")),
        },
        cleanup: SwarmPressureTraceCleanup {
            cleanup_requests: summary.cleanup_requests,
            authorization_required: summary.cleanup_authorization_required_count,
            authorized: summary
                .cleanup_requests
                .saturating_sub(summary.cleanup_authorization_required_count),
            max_cleanup_latency_steps: summary
                .event_log
                .iter()
                .filter(|event| event.kind == SwarmPressureEventKind::CleanupRequested)
                .map(|event| event.admission_latency_steps)
                .max()
                .unwrap_or(0),
            auto_delete_command_count: summary.auto_delete_command_count,
        },
        top_hot_regions: Vec::new(),
        longest_drains: pressure_longest_drains(summary),
        largest_queues,
        obligation_leak_suspects: pressure_obligation_leak_suspects(summary),
        routing_hints,
    }
}

/// Summarize a typed e2e agent-run artifact into stable JSON-ready counters.
#[must_use]
pub fn summarize_swarm_agent_run_trace(
    summary: &SwarmAgentRunSummary,
) -> SwarmPressureTraceSummary {
    let required_fields_present = false;
    let missing_required_fields = agent_run_missing_required_fields();
    let first_invariant_violation = summary.invariant_violations.first().cloned();
    let unresolved_obligations = bool_as_usize(!summary.no_leaked_reservations)
        .saturating_add(bool_as_usize(!summary.no_false_green_proof));
    let verdict = trace_verdict(
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        unresolved_obligations,
        &summary.invariant_violations,
    );
    let first_rejection = summary.first_blocker.clone();
    let routing_hints = trace_routing_hints(
        SwarmPressureTraceSourceKind::AgentRun,
        required_fields_present,
        summary.quiescent,
        summary.non_terminal_task_count,
        unresolved_obligations,
        first_invariant_violation.as_deref(),
        first_rejection.as_deref(),
    );

    SwarmPressureTraceSummary {
        schema_version: SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION.to_string(),
        source_schema_version: summary.schema_version.clone(),
        source_kind: SwarmPressureTraceSourceKind::AgentRun,
        scenario_id: summary.scenario_id.clone(),
        seed: summary.seed,
        verdict,
        required_fields_present,
        missing_required_fields,
        first_invariant_violation,
        region_lifecycle: SwarmPressureTraceRegionLifecycle {
            regions_declared: 0,
            regions_with_runtime_id: 0,
            quiescent_regions: bool_as_usize(summary.quiescent),
            non_quiescent_regions: bool_as_usize(!summary.quiescent),
        },
        task_lifecycle: SwarmPressureTraceTaskLifecycle {
            submitted_tasks: summary.agent_count,
            scheduled_tasks: summary.scheduled_task_count,
            terminal_tasks: summary.terminal_task_count,
            non_terminal_tasks: summary.non_terminal_task_count,
            task_leaks: summary.task_leaks,
        },
        cancellation: SwarmPressureTraceCancellation {
            cancellation_requests: summary.recovery_handoff_count,
            cancelled_tasks: summary.crashed_agent_count,
            cancellation_drain_steps: 0,
            losers_drained: summary.quiescent && summary.non_terminal_task_count == 0,
        },
        obligations: SwarmPressureTraceObligations {
            fields_present: false,
            resolved_obligations: summary.file_reservations_released,
            committed_obligations: summary.commit_count,
            aborted_obligations: summary.recovery_handoff_count,
            unresolved_obligations,
        },
        queue_pressure: SwarmPressureTraceQueuePressure {
            peak_queue_depth: summary.rch_proof_attempt_count,
            pressure_event_count: summary.rch_remote_refusal_count,
            peak_scope: Some("agent_run:rch_proof_attempts".to_string()),
        },
        admission: SwarmPressureTraceAdmission {
            accepted: summary.bead_claim_count,
            deferred: summary.validation_blocker_count,
            shed: summary.rch_remote_refusal_count,
            cancelled: summary.crashed_agent_count,
            proof_admitted: summary.proof_pass_count,
            proof_throttled: summary
                .rch_remote_refusal_count
                .saturating_add(summary.validation_blocker_count),
            interactive_admitted: summary.bead_claim_count,
            cleanup_requested: summary.recovery_handoff_count,
            combiner_or_admission_decisions: summary.event_log.len(),
            first_rejection,
        },
        cleanup: SwarmPressureTraceCleanup {
            cleanup_requests: summary.recovery_handoff_count,
            authorization_required: 0,
            authorized: summary.recovery_handoff_count,
            max_cleanup_latency_steps: 0,
            auto_delete_command_count: bool_as_usize(
                summary.forbidden_actions.runs_destructive_command,
            ),
        },
        top_hot_regions: Vec::new(),
        longest_drains: agent_run_longest_drains(summary),
        largest_queues: agent_run_largest_queues(summary),
        obligation_leak_suspects: agent_run_obligation_leak_suspects(summary),
        routing_hints,
    }
}

/// Render a stable text summary for operator logs and closeout evidence.
#[must_use]
pub fn render_swarm_pressure_trace_text(summary: &SwarmPressureTraceSummary) -> String {
    let mut lines = vec![
        "Swarm Pressure Trace Summary".to_string(),
        format!("schema_version: {}", summary.schema_version),
        format!(
            "source: {:?} schema={} scenario={} seed={}",
            summary.source_kind, summary.source_schema_version, summary.scenario_id, summary.seed
        ),
        format!(
            "verdict: {:?} required_fields_present={} missing={}",
            summary.verdict,
            summary.required_fields_present,
            if summary.missing_required_fields.is_empty() {
                "none".to_string()
            } else {
                summary.missing_required_fields.join(",")
            }
        ),
        format!(
            "regions: declared={} runtime_ids={} quiescent={} non_quiescent={}",
            summary.region_lifecycle.regions_declared,
            summary.region_lifecycle.regions_with_runtime_id,
            summary.region_lifecycle.quiescent_regions,
            summary.region_lifecycle.non_quiescent_regions
        ),
        format!(
            "tasks: submitted={} scheduled={} terminal={} non_terminal={} leaks={}",
            summary.task_lifecycle.submitted_tasks,
            summary.task_lifecycle.scheduled_tasks,
            summary.task_lifecycle.terminal_tasks,
            summary.task_lifecycle.non_terminal_tasks,
            summary.task_lifecycle.task_leaks
        ),
        format!(
            "cancellation: requests={} cancelled_tasks={} drain_steps={} losers_drained={}",
            summary.cancellation.cancellation_requests,
            summary.cancellation.cancelled_tasks,
            summary.cancellation.cancellation_drain_steps,
            summary.cancellation.losers_drained
        ),
        format!(
            "obligations: fields_present={} resolved={} committed={} aborted={} unresolved={}",
            summary.obligations.fields_present,
            summary.obligations.resolved_obligations,
            summary.obligations.committed_obligations,
            summary.obligations.aborted_obligations,
            summary.obligations.unresolved_obligations
        ),
        format!(
            "queue: peak={} pressure_events={} peak_scope={}",
            summary.queue_pressure.peak_queue_depth,
            summary.queue_pressure.pressure_event_count,
            summary
                .queue_pressure
                .peak_scope
                .as_deref()
                .unwrap_or("none")
        ),
        format!(
            "admission: accepted={} deferred={} shed={} cancelled={} proof_admitted={} proof_throttled={} interactive_admitted={} cleanup_requested={} decisions={}",
            summary.admission.accepted,
            summary.admission.deferred,
            summary.admission.shed,
            summary.admission.cancelled,
            summary.admission.proof_admitted,
            summary.admission.proof_throttled,
            summary.admission.interactive_admitted,
            summary.admission.cleanup_requested,
            summary.admission.combiner_or_admission_decisions
        ),
        format!(
            "cleanup: requests={} authorization_required={} authorized={} max_latency_steps={} auto_delete_commands={}",
            summary.cleanup.cleanup_requests,
            summary.cleanup.authorization_required,
            summary.cleanup.authorized,
            summary.cleanup.max_cleanup_latency_steps,
            summary.cleanup.auto_delete_command_count
        ),
        format!(
            "first_invariant_violation: {}",
            summary
                .first_invariant_violation
                .as_deref()
                .unwrap_or("none")
        ),
    ];

    lines.push("top_hot_regions:".to_string());
    if summary.top_hot_regions.is_empty() {
        lines.push("- none".to_string());
    } else {
        for region in &summary.top_hot_regions {
            lines.push(format!(
                "- region={} runtime_id={} events={} tasks={} cancelled={} queue_peak={} admissions={} route={}",
                region.region_index,
                region
                    .region_id
                    .map_or_else(|| "none".to_string(), |id| id.to_string()),
                region.event_count,
                region.task_count,
                region.cancelled_task_count,
                region.queue_peak,
                region.admission_decision_count,
                region.route_hint
            ));
        }
    }

    lines.push("longest_drains:".to_string());
    if summary.longest_drains.is_empty() {
        lines.push("- none".to_string());
    } else {
        for drain in &summary.longest_drains {
            lines.push(format!(
                "- scope={} drain_steps={} quiescent={} reason={}",
                drain.scope, drain.drain_steps, drain.quiescent, drain.reason
            ));
        }
    }

    lines.push("largest_queues:".to_string());
    if summary.largest_queues.is_empty() {
        lines.push("- none".to_string());
    } else {
        for queue in &summary.largest_queues {
            lines.push(format!(
                "- scope={} depth={} event={} route={}",
                queue.scope, queue.queue_depth, queue.event_kind, queue.route_hint
            ));
        }
    }

    lines.push("obligation_leak_suspects:".to_string());
    if summary.obligation_leak_suspects.is_empty() {
        lines.push("- none".to_string());
    } else {
        for suspect in &summary.obligation_leak_suspects {
            lines.push(format!(
                "- scope={} unresolved={} evidence={} route={}",
                suspect.scope, suspect.unresolved_obligations, suspect.evidence, suspect.route_hint
            ));
        }
    }

    lines.push("routing_hints:".to_string());
    if summary.routing_hints.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hint in &summary.routing_hints {
            lines.push(format!("- {hint}"));
        }
    }

    lines.join("\n")
}

/// Build a deterministic, fail-closed contention heatmap ledger.
#[must_use]
pub fn build_swarm_contention_heatmap(
    input: &SwarmContentionHeatmapInput,
) -> SwarmContentionHeatmapLedger {
    let mut missing_required_fields = Vec::new();
    if input.ledger_id.trim().is_empty() {
        missing_required_fields.push("ledger_id".to_string());
    }
    if input.trace_summary.is_none() {
        missing_required_fields.push("trace_summary".to_string());
    }
    if input.lock_metrics.is_empty() {
        missing_required_fields.push("lock_metrics".to_string());
    }
    if input.scheduler_lanes.is_empty() {
        missing_required_fields.push("scheduler_lanes".to_string());
    }

    let scenario_id = input
        .trace_summary
        .as_ref()
        .map(|summary| summary.scenario_id.clone());
    if let Some(summary) = &input.trace_summary {
        if !summary.required_fields_present {
            missing_required_fields.extend(
                summary
                    .missing_required_fields
                    .iter()
                    .map(|field| format!("trace_summary.{field}")),
            );
        }
        if summary.verdict == SwarmPressureTraceVerdict::Incomplete {
            missing_required_fields.push("trace_summary.verdict".to_string());
        }
    }
    missing_required_fields = sorted_unique_owned(missing_required_fields);

    let stale_baseline = input.baseline_age_secs > input.max_baseline_age_secs;
    let lock_hotspots = ranked_lock_hotspots(&input.lock_metrics);
    let scheduler_lane_hotspots = ranked_scheduler_lane_hotspots(&input.scheduler_lanes);
    let (region_hotspots, queue_hotspots) = input
        .trace_summary
        .as_ref()
        .map_or_else(|| (Vec::new(), Vec::new()), trace_contention_hotspots);

    let mut top_hotspots = Vec::new();
    top_hotspots.extend(lock_hotspots.clone());
    top_hotspots.extend(scheduler_lane_hotspots.clone());
    top_hotspots.extend(region_hotspots.clone());
    top_hotspots.extend(queue_hotspots.clone());
    sort_heatmap_hotspots(&mut top_hotspots);
    top_hotspots.truncate(8);

    let max_severity = top_hotspots
        .iter()
        .map(|hotspot| hotspot.severity)
        .max()
        .unwrap_or(SwarmContentionSeverity::Nominal);
    let required_fields_present = missing_required_fields.is_empty();
    let verdict = if !required_fields_present {
        SwarmContentionHeatmapVerdict::Incomplete
    } else if stale_baseline {
        SwarmContentionHeatmapVerdict::StaleEvidence
    } else if max_severity >= SwarmContentionSeverity::Warning {
        SwarmContentionHeatmapVerdict::Degraded
    } else {
        SwarmContentionHeatmapVerdict::Pass
    };

    let mut routing_hints = Vec::new();
    if !required_fields_present {
        routing_hints.push(format!(
            "missing contention evidence: {}",
            missing_required_fields.join(",")
        ));
    }
    if stale_baseline {
        routing_hints.push(format!(
            "refresh baseline {}: age={}s max={}s",
            input.baseline_id.as_deref().unwrap_or("unknown"),
            input.baseline_age_secs,
            input.max_baseline_age_secs
        ));
    }
    if let Some(summary) = &input.trace_summary {
        routing_hints.extend(summary.routing_hints.clone());
    }
    routing_hints.extend(
        top_hotspots
            .iter()
            .filter(|hotspot| hotspot.severity >= SwarmContentionSeverity::Warning)
            .map(|hotspot| {
                format!(
                    "{} {:?} hotspot routes to {} ({})",
                    hotspot.key, hotspot.kind, hotspot.owner_surface, hotspot.owner_bead_hint
                )
            }),
    );
    routing_hints = sorted_unique_owned(routing_hints);

    SwarmContentionHeatmapLedger {
        schema_version: SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION.to_string(),
        ledger_id: input.ledger_id.clone(),
        scenario_id,
        baseline_id: input.baseline_id.clone(),
        stale_baseline,
        verdict,
        max_severity,
        required_fields_present,
        missing_required_fields,
        source_trace_ids: sorted_unique_owned(input.source_trace_ids.clone()),
        proof_command: input.proof_command.clone(),
        lock_hotspots,
        scheduler_lane_hotspots,
        region_hotspots,
        queue_hotspots,
        top_hotspots,
        routing_hints,
    }
}

/// Render a compact deterministic text summary for Agent Mail handoff.
#[must_use]
pub fn render_swarm_contention_heatmap_text(ledger: &SwarmContentionHeatmapLedger) -> String {
    let mut lines = vec![
        "Swarm Contention Heatmap Ledger".to_string(),
        format!("schema_version: {}", ledger.schema_version),
        format!(
            "ledger_id: {} scenario={} baseline={} stale_baseline={}",
            ledger.ledger_id,
            ledger.scenario_id.as_deref().unwrap_or("none"),
            ledger.baseline_id.as_deref().unwrap_or("none"),
            ledger.stale_baseline
        ),
        format!(
            "verdict: {:?} max_severity={:?} required_fields_present={} missing={}",
            ledger.verdict,
            ledger.max_severity,
            ledger.required_fields_present,
            if ledger.missing_required_fields.is_empty() {
                "none".to_string()
            } else {
                ledger.missing_required_fields.join(",")
            }
        ),
    ];

    lines.push("top_hotspots:".to_string());
    if ledger.top_hotspots.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hotspot in &ledger.top_hotspots {
            lines.push(format!(
                "- key={} kind={:?} severity={:?} score={} p50={} p95={} p99={} q95={} q99={} route={} bead={}",
                hotspot.key,
                hotspot.kind,
                hotspot.severity,
                hotspot.impact_score,
                optional_u64_text(hotspot.p50_wait_ns),
                optional_u64_text(hotspot.p95_wait_ns),
                optional_u64_text(hotspot.p99_wait_ns),
                optional_u64_text(hotspot.queue_depth_p95),
                optional_u64_text(hotspot.queue_depth_p99),
                hotspot.owner_surface,
                hotspot.owner_bead_hint
            ));
        }
    }

    lines.push("routing_hints:".to_string());
    if ledger.routing_hints.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hint in &ledger.routing_hints {
            lines.push(format!("- {hint}"));
        }
    }

    lines.join("\n")
}

/// Minimize a failing swarm replay scenario without mutating live services.
#[must_use]
pub fn minimize_swarm_failure(input: &SwarmFailureMinimizerInput) -> SwarmFailureMinimizerReport {
    let proof_lane_decision = input
        .failure_bundle
        .proof_lane_plan
        .as_ref()
        .map(|plan| plan.decision);
    let replay_command = minimizer_replay_command(input);
    let mut missing_required_fields =
        minimizer_missing_required_fields(input, replay_command.as_deref());
    let original_valid = input.original_scenario.validate().is_ok();
    if !original_valid {
        missing_required_fields.push("original_scenario.valid".to_string());
    }
    missing_required_fields = sorted_unique_owned(missing_required_fields);

    let redaction_preserved = input
        .failure_bundle
        .redaction_policy_id
        .as_deref()
        .is_some_and(|policy| !policy.trim().is_empty())
        && input.failure_bundle.secret_like_value_count == 0;
    let required_fields_present = missing_required_fields.is_empty();
    let (owner_surface, owner_bead_hint) =
        minimizer_owner_hint(input.failure_bundle.invariant_class);
    let mut routing_hints = minimizer_routing_hints(input, &owner_surface, &owner_bead_hint);
    let source_trace_ids = sorted_unique_owned(input.source_trace_ids.clone());
    let original_task_count = input.original_scenario.task_count();
    let mut minimized_scenario = input.original_scenario.clone();
    let mut reduction_steps = Vec::new();
    let mut preserved_invariant = minimizer_invariant_reproduced(input);
    let (verdict, stop_reason) = if !original_valid {
        preserved_invariant = false;
        (
            SwarmFailureMinimizerVerdict::Incomplete,
            SwarmFailureMinimizerStopReason::InvalidScenario,
        )
    } else if !required_fields_present {
        preserved_invariant = false;
        (
            SwarmFailureMinimizerVerdict::Incomplete,
            SwarmFailureMinimizerStopReason::MissingEvidence,
        )
    } else if !redaction_preserved {
        preserved_invariant = false;
        (
            SwarmFailureMinimizerVerdict::Incomplete,
            SwarmFailureMinimizerStopReason::RedactionRequired,
        )
    } else if !preserved_invariant {
        (
            SwarmFailureMinimizerVerdict::NonReproducible,
            SwarmFailureMinimizerStopReason::NonReproducible,
        )
    } else {
        let stop_reason =
            reduce_swarm_failure_scenario(input, &mut minimized_scenario, &mut reduction_steps);
        let verdict = match stop_reason {
            SwarmFailureMinimizerStopReason::InvariantPreserved => {
                SwarmFailureMinimizerVerdict::Minimized
            }
            SwarmFailureMinimizerStopReason::AlreadyMinimal => {
                SwarmFailureMinimizerVerdict::AlreadyMinimal
            }
            SwarmFailureMinimizerStopReason::StepLimitReached => {
                preserved_invariant = false;
                SwarmFailureMinimizerVerdict::Incomplete
            }
            SwarmFailureMinimizerStopReason::InvalidScenario
            | SwarmFailureMinimizerStopReason::MissingEvidence
            | SwarmFailureMinimizerStopReason::RedactionRequired => {
                preserved_invariant = false;
                SwarmFailureMinimizerVerdict::Incomplete
            }
            SwarmFailureMinimizerStopReason::NonReproducible => {
                preserved_invariant = false;
                SwarmFailureMinimizerVerdict::NonReproducible
            }
        };
        (verdict, stop_reason)
    };

    if !required_fields_present {
        routing_hints.push(format!(
            "missing minimizer evidence: {}",
            missing_required_fields.join(",")
        ));
    }
    if !redaction_preserved {
        routing_hints.push(format!(
            "redaction policy {} still has {} secret-like value(s)",
            input
                .failure_bundle
                .redaction_policy_id
                .as_deref()
                .unwrap_or("missing"),
            input.failure_bundle.secret_like_value_count
        ));
    }
    if !preserved_invariant {
        routing_hints.push("do not mark minimized until the invariant reproduces".to_string());
    }
    routing_hints = sorted_unique_owned(routing_hints);

    let minimized_task_count = minimized_scenario.task_count();
    let reduction_ratio_bps = reduction_ratio_bps(original_task_count, minimized_task_count);

    SwarmFailureMinimizerReport {
        schema_version: SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION.to_string(),
        minimizer_id: input.minimizer_id.clone(),
        bundle_id: input.failure_bundle.bundle_id.clone(),
        original_artifact: input.failure_bundle.original_artifact.clone(),
        original_scenario_id: input.original_scenario.scenario_id.clone(),
        minimized_scenario,
        replay_command,
        verdict,
        invariant_class: input.failure_bundle.invariant_class,
        first_failure: input.failure_bundle.first_failure.clone(),
        stop_reason,
        preserved_invariant,
        required_fields_present,
        missing_required_fields,
        proof_lane_decision,
        source_trace_ids,
        redaction_policy_id: input.failure_bundle.redaction_policy_id.clone(),
        redaction_preserved,
        reduction_steps,
        original_task_count,
        minimized_task_count,
        reduction_ratio_bps,
        owner_surface,
        owner_bead_hint,
        routing_hints,
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    }
}

/// Render a compact deterministic minimizer report for Agent Mail handoff.
#[must_use]
pub fn render_swarm_failure_minimizer_text(report: &SwarmFailureMinimizerReport) -> String {
    let mut lines = vec![
        "Swarm Failure Minimizer".to_string(),
        format!("schema_version: {}", report.schema_version),
        format!(
            "minimizer_id: {} bundle={} original_artifact={}",
            report.minimizer_id, report.bundle_id, report.original_artifact
        ),
        format!(
            "verdict: {:?} stop_reason={:?} invariant_class={:?} preserved_invariant={}",
            report.verdict, report.stop_reason, report.invariant_class, report.preserved_invariant
        ),
        format!(
            "scenario: original={} minimized={} tasks={}=>{} reduction_bps={}",
            report.original_scenario_id,
            report.minimized_scenario.scenario_id,
            report.original_task_count,
            report.minimized_task_count,
            report.reduction_ratio_bps
        ),
        format!("first_failure: {}", report.first_failure),
        format!(
            "owner: {} ({})",
            report.owner_surface, report.owner_bead_hint
        ),
        format!(
            "required_fields_present={} missing={}",
            report.required_fields_present,
            if report.missing_required_fields.is_empty() {
                "none".to_string()
            } else {
                report.missing_required_fields.join(",")
            }
        ),
        format!(
            "redaction_policy={} redaction_preserved={}",
            report.redaction_policy_id.as_deref().unwrap_or("none"),
            report.redaction_preserved
        ),
    ];

    lines.push("reduction_steps:".to_string());
    if report.reduction_steps.is_empty() {
        lines.push("- none".to_string());
    } else {
        for step in &report.reduction_steps {
            lines.push(format!(
                "- knob={} before={} after={} preserved={} reason={}",
                step.knob, step.before, step.after, step.preserved_invariant, step.reason
            ));
        }
    }

    lines.push("routing_hints:".to_string());
    if report.routing_hints.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hint in &report.routing_hints {
            lines.push(format!("- {hint}"));
        }
    }

    if let Some(command) = &report.replay_command {
        lines.push(format!("replay_command: {command}"));
    }

    lines.join("\n")
}

/// Build a deterministic operator cockpit report from source-owned swarm evidence.
#[must_use]
pub fn build_swarm_operator_cockpit_report(
    input: &SwarmOperatorCockpitInput,
) -> SwarmOperatorCockpitReport {
    let scenario = input.scenario.as_ref();
    let trace = input.trace_summary.as_ref();
    let contention = input.contention_ledger.as_ref();
    let minimizer = input.minimizer_report.as_ref();
    let mut missing_required_fields = cockpit_missing_required_fields(input);
    let proof_lanes = cockpit_proof_lane_summaries(&input.proof_lanes);
    let stale_proof_lane_ids = cockpit_stale_proof_lane_ids(&input.proof_lanes);
    let blocked_proof_lane_ids = cockpit_blocked_proof_lane_ids(&input.proof_lanes);
    let rch_remote_provenance_observed = !input.proof_lanes.is_empty()
        && input
            .proof_lanes
            .iter()
            .all(|lane| !lane.remote_required || lane.remote_provenance_observed);
    let ready_proof_lane_count = input
        .proof_lanes
        .iter()
        .filter(|lane| cockpit_proof_lane_is_ready(lane))
        .count();
    let quiescent = trace.map(cockpit_trace_quiescent);
    let obligation_verdict = cockpit_obligation_verdict(trace);
    let unresolved_obligations = trace.map(|summary| summary.obligations.unresolved_obligations);
    let redaction_preserved = cockpit_redaction_preserved(input);
    let contention_hotspots = contention.map_or_else(Vec::new, |ledger| {
        ledger.top_hotspots.iter().take(5).cloned().collect()
    });
    let first_invariant_violation = trace
        .and_then(|summary| summary.first_invariant_violation.clone())
        .or_else(|| minimizer.map(|report| report.first_failure.clone()));
    let next_owner_bead = cockpit_next_owner_bead(trace, contention, minimizer);
    let source_artifacts = sorted_unique_owned(input.source_artifacts.clone());

    if !redaction_preserved
        && !missing_required_fields
            .iter()
            .any(|field| field.starts_with("redaction"))
    {
        missing_required_fields.push("redaction.policy".to_string());
        missing_required_fields = sorted_unique_owned(missing_required_fields);
    }

    let required_fields_present = missing_required_fields.is_empty();
    let outcome = cockpit_outcome(
        required_fields_present,
        &missing_required_fields,
        !stale_proof_lane_ids.is_empty()
            || contention.is_some_and(|ledger| {
                ledger.verdict == SwarmContentionHeatmapVerdict::StaleEvidence
            }),
        !blocked_proof_lane_ids.is_empty(),
        trace.map(|summary| summary.verdict),
        obligation_verdict,
        contention.map(|ledger| ledger.verdict),
        minimizer.map(|report| report.verdict),
        input.memory_decision,
    );
    let routing_hints = cockpit_routing_hints(
        input,
        &missing_required_fields,
        &stale_proof_lane_ids,
        &blocked_proof_lane_ids,
        &next_owner_bead,
    );

    SwarmOperatorCockpitReport {
        schema_version: SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION.to_string(),
        report_id: input.report_id.clone(),
        scenario_id: scenario.map(|scenario| scenario.scenario_id.clone()),
        seed: scenario.map(|scenario| scenario.seed),
        worker_count: scenario.map(|scenario| scenario.worker_count),
        region_count: scenario.map(|scenario| scenario.region_count),
        task_count: scenario.map(SwarmReplayScenario::task_count),
        outcome,
        required_fields_present,
        missing_required_fields,
        quiescent,
        obligation_verdict,
        unresolved_obligations,
        trace_verdict: trace.map(|summary| summary.verdict),
        proof_lanes,
        proof_lane_count: input.proof_lanes.len(),
        ready_proof_lane_count,
        stale_proof_lane_ids,
        blocked_proof_lane_ids,
        rch_remote_provenance_observed,
        latency_p50_ns: input.latency_p50_ns,
        latency_p95_ns: input.latency_p95_ns,
        latency_p99_ns: input.latency_p99_ns,
        latency_cv_bps: input.latency_cv_bps,
        memory_decision: input.memory_decision,
        memory_decision_reason: input.memory_decision_reason.clone(),
        contention_verdict: contention.map(|ledger| ledger.verdict),
        contention_max_severity: contention.map(|ledger| ledger.max_severity),
        contention_hotspots,
        minimizer_verdict: minimizer.map(|report| report.verdict),
        minimizer_stop_reason: minimizer.map(|report| report.stop_reason),
        minimized_scenario_id: minimizer
            .map(|report| report.minimized_scenario.scenario_id.clone()),
        first_invariant_violation,
        next_owner_bead,
        routing_hints,
        source_artifacts,
        redaction_policy_id: input.redaction_policy_id.clone(),
        redaction_preserved,
        generated_by: input.generated_by.clone(),
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    }
}

/// Render a compact deterministic cockpit report for Agent Mail and release notes.
#[must_use]
pub fn render_swarm_operator_cockpit_text(report: &SwarmOperatorCockpitReport) -> String {
    let mut lines = vec![
        "Swarm Operator Cockpit Report".to_string(),
        format!("schema_version: {}", report.schema_version),
        format!(
            "report_id: {} outcome={:?} generated_by={}",
            report.report_id, report.outcome, report.generated_by
        ),
        format!(
            "scenario: {} seed={} workers={} regions={} tasks={}",
            report.scenario_id.as_deref().unwrap_or("missing"),
            optional_u64_text(report.seed),
            optional_usize_text(report.worker_count),
            optional_usize_text(report.region_count),
            optional_usize_text(report.task_count)
        ),
        format!(
            "verdicts: quiescent={} obligation={:?} trace={} required_fields_present={} missing={}",
            optional_bool_text(report.quiescent),
            report.obligation_verdict,
            optional_trace_verdict_text(report.trace_verdict),
            report.required_fields_present,
            if report.missing_required_fields.is_empty() {
                "none".to_string()
            } else {
                report.missing_required_fields.join(",")
            }
        ),
        format!(
            "proof_lanes: ready={}/{} remote_observed={} stale={} blocked={}",
            report.ready_proof_lane_count,
            report.proof_lane_count,
            report.rch_remote_provenance_observed,
            cockpit_join_or_none(&report.stale_proof_lane_ids),
            cockpit_join_or_none(&report.blocked_proof_lane_ids)
        ),
        format!(
            "latency_ns: p50={} p95={} p99={} cv_bps={}",
            optional_u64_text(report.latency_p50_ns),
            optional_u64_text(report.latency_p95_ns),
            optional_u64_text(report.latency_p99_ns),
            report
                .latency_cv_bps
                .map_or_else(|| "n/a".to_string(), |value| value.to_string())
        ),
        format!(
            "memory: {:?} reason={}",
            report.memory_decision,
            report.memory_decision_reason.as_deref().unwrap_or("none")
        ),
        format!(
            "contention: verdict={} max_severity={} hotspots={}",
            optional_contention_verdict_text(report.contention_verdict),
            optional_contention_severity_text(report.contention_max_severity),
            report.contention_hotspots.len()
        ),
        format!(
            "minimizer: verdict={} stop={} minimized_scenario={}",
            optional_minimizer_verdict_text(report.minimizer_verdict),
            optional_minimizer_stop_text(report.minimizer_stop_reason),
            report.minimized_scenario_id.as_deref().unwrap_or("none")
        ),
        format!(
            "redaction: policy={} preserved={}",
            report.redaction_policy_id.as_deref().unwrap_or("missing"),
            report.redaction_preserved
        ),
        format!(
            "provenance: artifacts={} destructive_cleanup_required={} branch_or_worktree_required={}",
            cockpit_join_or_none(&report.source_artifacts),
            report.destructive_cleanup_required,
            report.branch_or_worktree_required
        ),
        format!(
            "first_invariant_violation: {}",
            report
                .first_invariant_violation
                .as_deref()
                .unwrap_or("none")
        ),
        format!("next_owner_bead: {}", report.next_owner_bead),
    ];

    lines.push("top_hotspots:".to_string());
    if report.contention_hotspots.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hotspot in report.contention_hotspots.iter().take(3) {
            lines.push(format!(
                "- key={} kind={:?} severity={:?} score={} route={} bead={}",
                hotspot.key,
                hotspot.kind,
                hotspot.severity,
                hotspot.impact_score,
                hotspot.owner_surface,
                hotspot.owner_bead_hint
            ));
        }
    }

    lines.push("proof_lane_rows:".to_string());
    if report.proof_lanes.is_empty() {
        lines.push("- none".to_string());
    } else {
        for lane in report.proof_lanes.iter().take(4) {
            lines.push(format!(
                "- id={} decision={:?} remote_required={} remote_observed={} stale_head={} target_dir={}",
                lane.lane_id,
                lane.decision,
                lane.remote_required,
                lane.remote_observed,
                lane.stale_head,
                lane.target_dir
            ));
        }
    }

    lines.push("routing_hints:".to_string());
    if report.routing_hints.is_empty() {
        lines.push("- none".to_string());
    } else {
        for hint in report.routing_hints.iter().take(6) {
            lines.push(format!("- {hint}"));
        }
    }

    lines.join("\n")
}

fn cockpit_missing_required_fields(input: &SwarmOperatorCockpitInput) -> Vec<String> {
    let mut missing = Vec::new();
    let expected_scenario_id = input.scenario.as_ref().and_then(|scenario| {
        let scenario_id = scenario.scenario_id.trim();
        (!scenario_id.is_empty()).then_some(scenario_id)
    });

    if input.report_id.trim().is_empty() {
        missing.push("report_id".to_string());
    }
    match &input.scenario {
        Some(scenario) => {
            if scenario.scenario_id.trim().is_empty() {
                missing.push("scenario.scenario_id".to_string());
            }
            if scenario.validate().is_err() {
                missing.push("scenario.valid".to_string());
            }
        }
        None => missing.push("scenario".to_string()),
    }

    match &input.trace_summary {
        Some(summary) => {
            if let Some(expected_scenario_id) = expected_scenario_id {
                if summary.scenario_id.trim() != expected_scenario_id {
                    missing.push("trace_summary.scenario_id".to_string());
                }
            }
            if !summary.required_fields_present {
                missing.extend(
                    summary
                        .missing_required_fields
                        .iter()
                        .map(|field| format!("trace_summary.{field}")),
                );
            }
            if summary.verdict == SwarmPressureTraceVerdict::Incomplete {
                missing.push("trace_summary.verdict".to_string());
            }
            if !summary.obligations.fields_present {
                missing.push("trace_summary.obligation_verdict".to_string());
            }
            if summary
                .missing_required_fields
                .iter()
                .any(|field| field == "quiescence_verdict")
            {
                missing.push("trace_summary.quiescence_verdict".to_string());
            }
        }
        None => missing.push("trace_summary".to_string()),
    }

    if input.proof_lanes.is_empty() {
        missing.push("proof_lanes".to_string());
    }
    if input
        .proof_lanes
        .iter()
        .any(|lane| lane.remote_required && !lane.remote_provenance_observed)
    {
        missing.push("proof_lanes.remote_provenance".to_string());
    }
    if let Some(expected_scenario_id) = expected_scenario_id {
        if input
            .proof_lanes
            .iter()
            .any(|lane| lane.scenario_id.trim() != expected_scenario_id)
        {
            missing.push("proof_lanes.scenario_id".to_string());
        }
    }

    match &input.contention_ledger {
        Some(ledger) => {
            if let Some(expected_scenario_id) = expected_scenario_id {
                match ledger.scenario_id.as_deref().map(str::trim) {
                    Some(ledger_scenario_id) if ledger_scenario_id == expected_scenario_id => {}
                    _ => missing.push("contention_ledger.scenario_id".to_string()),
                }
            }
            if !ledger.required_fields_present {
                missing.extend(
                    ledger
                        .missing_required_fields
                        .iter()
                        .map(|field| format!("contention_ledger.{field}")),
                );
            }
            if ledger.verdict == SwarmContentionHeatmapVerdict::Incomplete {
                missing.push("contention_ledger.verdict".to_string());
            }
        }
        None => missing.push("contention_ledger".to_string()),
    }

    if input.source_artifacts.is_empty() {
        missing.push("source_artifacts".to_string());
    }
    if input
        .redaction_policy_id
        .as_deref()
        .is_none_or(|policy| policy.trim().is_empty())
    {
        missing.push("redaction_policy_id".to_string());
    }
    if input.secret_like_value_count > 0 {
        missing.push("redaction.secret_like_values".to_string());
    }
    if input.generated_by.trim().is_empty() {
        missing.push("generated_by".to_string());
    }
    if input
        .minimizer_report
        .as_ref()
        .is_some_and(|report| !report.redaction_preserved)
    {
        missing.push("minimizer_report.redaction".to_string());
    }
    if let (Some(expected_scenario_id), Some(report)) =
        (expected_scenario_id, input.minimizer_report.as_ref())
    {
        if report.original_scenario_id.trim() != expected_scenario_id {
            missing.push("minimizer_report.original_scenario_id".to_string());
        }
    }

    sorted_unique_owned(missing)
}

fn cockpit_redaction_preserved(input: &SwarmOperatorCockpitInput) -> bool {
    input
        .redaction_policy_id
        .as_deref()
        .is_some_and(|policy| !policy.trim().is_empty())
        && input.secret_like_value_count == 0
        && input
            .minimizer_report
            .as_ref()
            .is_none_or(|report| report.redaction_preserved)
}

fn cockpit_proof_lane_summaries(
    proof_lanes: &[SwarmProofLanePlan],
) -> Vec<SwarmOperatorCockpitProofLaneSummary> {
    let mut summaries = proof_lanes
        .iter()
        .map(|lane| SwarmOperatorCockpitProofLaneSummary {
            lane_id: lane.lane_id.clone(),
            decision: lane.decision,
            remote_required: lane.remote_required,
            remote_observed: lane.remote_provenance_observed,
            stale_head: lane.stale_head,
            command: lane.command.clone(),
            target_dir: lane.target_dir.clone(),
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    summaries
}

fn cockpit_stale_proof_lane_ids(proof_lanes: &[SwarmProofLanePlan]) -> Vec<String> {
    sorted_unique_owned(
        proof_lanes
            .iter()
            .filter(|lane| lane.stale_head)
            .map(|lane| lane.lane_id.clone())
            .collect(),
    )
}

fn cockpit_blocked_proof_lane_ids(proof_lanes: &[SwarmProofLanePlan]) -> Vec<String> {
    sorted_unique_owned(
        proof_lanes
            .iter()
            .filter(|lane| !cockpit_proof_lane_is_ready(lane) && !lane.stale_head)
            .map(|lane| lane.lane_id.clone())
            .collect(),
    )
}

fn cockpit_proof_lane_is_ready(lane: &SwarmProofLanePlan) -> bool {
    lane.decision == SwarmProofLaneDecision::Ready
        && !lane.stale_head
        && (!lane.remote_required || lane.remote_provenance_observed)
}

fn cockpit_trace_quiescent(summary: &SwarmPressureTraceSummary) -> bool {
    summary.region_lifecycle.non_quiescent_regions == 0
        && summary.task_lifecycle.non_terminal_tasks == 0
        && summary.task_lifecycle.task_leaks == 0
}

fn cockpit_obligation_verdict(
    trace: Option<&SwarmPressureTraceSummary>,
) -> SwarmOperatorCockpitObligationVerdict {
    match trace {
        None => SwarmOperatorCockpitObligationVerdict::Missing,
        Some(summary) if !summary.obligations.fields_present => {
            SwarmOperatorCockpitObligationVerdict::Missing
        }
        Some(summary) if !summary.required_fields_present => {
            SwarmOperatorCockpitObligationVerdict::Incomplete
        }
        Some(summary)
            if summary.obligations.unresolved_obligations > 0
                || !summary.obligation_leak_suspects.is_empty() =>
        {
            SwarmOperatorCockpitObligationVerdict::LeakSuspect
        }
        Some(_) => SwarmOperatorCockpitObligationVerdict::Clean,
    }
}

fn cockpit_outcome(
    required_fields_present: bool,
    missing_required_fields: &[String],
    stale_evidence: bool,
    blocked_proofs: bool,
    trace_verdict: Option<SwarmPressureTraceVerdict>,
    obligation_verdict: SwarmOperatorCockpitObligationVerdict,
    contention_verdict: Option<SwarmContentionHeatmapVerdict>,
    minimizer_verdict: Option<SwarmFailureMinimizerVerdict>,
    memory_decision: SwarmOperatorCockpitMemoryDecision,
) -> SwarmOperatorCockpitOutcome {
    if !required_fields_present {
        return if cockpit_missing_fields_are_only_proof_blockers(missing_required_fields) {
            SwarmOperatorCockpitOutcome::Blocked
        } else {
            SwarmOperatorCockpitOutcome::Malformed
        };
    }
    if stale_evidence {
        return SwarmOperatorCockpitOutcome::StaleEvidence;
    }
    if blocked_proofs {
        return SwarmOperatorCockpitOutcome::Blocked;
    }
    match memory_decision {
        SwarmOperatorCockpitMemoryDecision::Unsupported => {
            return SwarmOperatorCockpitOutcome::Unsupported;
        }
        SwarmOperatorCockpitMemoryDecision::NoWin => return SwarmOperatorCockpitOutcome::NoWin,
        SwarmOperatorCockpitMemoryDecision::Nominal
        | SwarmOperatorCockpitMemoryDecision::BrownoutOptional => {}
    }

    let degraded = memory_decision == SwarmOperatorCockpitMemoryDecision::BrownoutOptional
        || trace_verdict == Some(SwarmPressureTraceVerdict::Fail)
        || obligation_verdict == SwarmOperatorCockpitObligationVerdict::LeakSuspect
        || contention_verdict == Some(SwarmContentionHeatmapVerdict::Degraded)
        || minimizer_verdict.is_some();

    if degraded {
        SwarmOperatorCockpitOutcome::Degraded
    } else {
        SwarmOperatorCockpitOutcome::Pass
    }
}

fn cockpit_missing_fields_are_only_proof_blockers(fields: &[String]) -> bool {
    !fields.is_empty()
        && fields.iter().all(|field| {
            matches!(
                field.as_str(),
                "proof_lanes" | "proof_lanes.remote_provenance"
            )
        })
}

fn cockpit_next_owner_bead(
    trace: Option<&SwarmPressureTraceSummary>,
    contention: Option<&SwarmContentionHeatmapLedger>,
    minimizer: Option<&SwarmFailureMinimizerReport>,
) -> String {
    if let Some(report) = minimizer {
        return report.owner_bead_hint.clone();
    }
    if let Some(hotspot) = contention.and_then(|ledger| {
        ledger
            .top_hotspots
            .iter()
            .find(|hotspot| hotspot.severity >= SwarmContentionSeverity::Warning)
    }) {
        return hotspot.owner_bead_hint.clone();
    }
    if let Some(summary) = trace {
        if let Some(hint) = summary.routing_hints.first() {
            return hint.clone();
        }
    }
    "asupersync-vssefs.9.6".to_string()
}

fn cockpit_routing_hints(
    input: &SwarmOperatorCockpitInput,
    missing_required_fields: &[String],
    stale_proof_lane_ids: &[String],
    blocked_proof_lane_ids: &[String],
    next_owner_bead: &str,
) -> Vec<String> {
    let mut hints = Vec::new();
    if !missing_required_fields.is_empty() {
        hints.push(format!(
            "missing cockpit evidence: {}",
            missing_required_fields.join(",")
        ));
    }
    if !stale_proof_lane_ids.is_empty() {
        hints.push(format!(
            "refresh stale proof lanes: {}",
            stale_proof_lane_ids.join(",")
        ));
    }
    if !blocked_proof_lane_ids.is_empty() {
        hints.push(format!(
            "rerun blocked proof lanes through remote RCH: {}",
            blocked_proof_lane_ids.join(",")
        ));
    }
    if input.secret_like_value_count > 0 {
        hints.push(format!(
            "redact {} secret-like value(s) before Agent Mail handoff",
            input.secret_like_value_count
        ));
    }
    if let Some(summary) = &input.trace_summary {
        hints.extend(summary.routing_hints.clone());
        if let Some(invariant) = &summary.first_invariant_violation {
            hints.push(format!("first invariant violation: {invariant}"));
        }
    }
    if let Some(ledger) = &input.contention_ledger {
        hints.extend(ledger.routing_hints.clone());
    }
    if let Some(report) = &input.minimizer_report {
        hints.extend(report.routing_hints.clone());
        hints.push(format!(
            "minimizer {:?} routes to {}",
            report.verdict, report.owner_bead_hint
        ));
    }
    hints.push(format!("next owner bead: {next_owner_bead}"));
    sorted_unique_owned(hints)
}

fn cockpit_join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn optional_usize_text(value: Option<usize>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| value.to_string())
}

fn optional_bool_text(value: Option<bool>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| value.to_string())
}

fn optional_trace_verdict_text(value: Option<SwarmPressureTraceVerdict>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:?}"))
}

fn optional_contention_verdict_text(value: Option<SwarmContentionHeatmapVerdict>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:?}"))
}

fn optional_contention_severity_text(value: Option<SwarmContentionSeverity>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:?}"))
}

fn optional_minimizer_verdict_text(value: Option<SwarmFailureMinimizerVerdict>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:?}"))
}

fn optional_minimizer_stop_text(value: Option<SwarmFailureMinimizerStopReason>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:?}"))
}

fn ranked_lock_hotspots(metrics: &[SwarmContentionLockMetric]) -> Vec<SwarmContentionHotSpot> {
    let mut hotspots = metrics
        .iter()
        .filter(|metric| {
            metric.acquisitions > 0
                || metric.contentions > 0
                || metric.p95_wait_ns > 0
                || metric.p99_wait_ns > 0
        })
        .map(|metric| {
            let severity = wait_severity(metric.p95_wait_ns, metric.p99_wait_ns);
            let impact_score = metric
                .p99_wait_ns
                .saturating_add(metric.p95_wait_ns)
                .saturating_add(metric.max_wait_ns)
                .saturating_add(metric.contentions.saturating_mul(10_000))
                .saturating_add(metric.p99_hold_ns / 2);
            SwarmContentionHotSpot {
                key: metric.name.clone(),
                kind: SwarmContentionHotspotKind::Lock,
                severity,
                impact_score,
                p50_wait_ns: Some(metric.p50_wait_ns),
                p95_wait_ns: Some(metric.p95_wait_ns),
                p99_wait_ns: Some(metric.p99_wait_ns),
                queue_depth_p95: None,
                queue_depth_p99: None,
                contentions: Some(metric.contentions),
                region_or_scope: None,
                evidence: format!(
                    "acquisitions={} contentions={} wait_p95={}ns wait_p99={}ns hold_p95={}ns hold_p99={}ns mode={}",
                    metric.acquisitions,
                    metric.contentions,
                    metric.p95_wait_ns,
                    metric.p99_wait_ns,
                    metric.p95_hold_ns,
                    metric.p99_hold_ns,
                    metric.instrumentation_mode
                ),
                owner_surface: "src/sync/contended_mutex.rs".to_string(),
                owner_bead_hint: "asupersync-vssefs.9.4".to_string(),
            }
        })
        .collect::<Vec<_>>();
    sort_heatmap_hotspots(&mut hotspots);
    hotspots
}

fn ranked_scheduler_lane_hotspots(
    metrics: &[SwarmContentionSchedulerLaneMetric],
) -> Vec<SwarmContentionHotSpot> {
    let mut hotspots = metrics
        .iter()
        .filter(|metric| {
            metric.dispatched_tasks > 0
                || metric.p95_wait_ns > 0
                || metric.p99_wait_ns > 0
                || metric.queue_depth_p95 > 0
                || metric.queue_depth_p99 > 0
        })
        .map(|metric| {
            let wait = wait_severity(metric.p95_wait_ns, metric.p99_wait_ns);
            let queue = queue_severity(metric.queue_depth_p95, metric.queue_depth_p99);
            let severity = wait.max(queue);
            let impact_score = metric
                .p99_wait_ns
                .saturating_add(metric.p95_wait_ns)
                .saturating_add(metric.queue_depth_p99.saturating_mul(20_000))
                .saturating_add(metric.queue_depth_p95.saturating_mul(5_000))
                .saturating_add(metric.fairness_yields.saturating_mul(50_000))
                .saturating_add(metric.steal_attempts.saturating_mul(1_000));
            SwarmContentionHotSpot {
                key: metric.lane_id.clone(),
                kind: SwarmContentionHotspotKind::SchedulerLane,
                severity,
                impact_score,
                p50_wait_ns: Some(metric.p50_wait_ns),
                p95_wait_ns: Some(metric.p95_wait_ns),
                p99_wait_ns: Some(metric.p99_wait_ns),
                queue_depth_p95: Some(metric.queue_depth_p95),
                queue_depth_p99: Some(metric.queue_depth_p99),
                contentions: Some(metric.steal_attempts.saturating_add(metric.fairness_yields)),
                region_or_scope: Some(metric.lane_id.clone()),
                evidence: format!(
                    "dispatched={} wait_p95={}ns wait_p99={}ns queue_p95={} queue_p99={} steals={} fairness_yields={}",
                    metric.dispatched_tasks,
                    metric.p95_wait_ns,
                    metric.p99_wait_ns,
                    metric.queue_depth_p95,
                    metric.queue_depth_p99,
                    metric.steal_attempts,
                    metric.fairness_yields
                ),
                owner_surface: "src/runtime/scheduler/three_lane.rs".to_string(),
                owner_bead_hint: "asupersync-vssefs.9.4".to_string(),
            }
        })
        .collect::<Vec<_>>();
    sort_heatmap_hotspots(&mut hotspots);
    hotspots
}

fn trace_contention_hotspots(
    summary: &SwarmPressureTraceSummary,
) -> (Vec<SwarmContentionHotSpot>, Vec<SwarmContentionHotSpot>) {
    let mut regions = summary
        .top_hot_regions
        .iter()
        .map(|region| {
            let severity = queue_severity(region.queue_peak as u64, region.queue_peak as u64).max(
                if region.cancelled_task_count > 0 {
                    SwarmContentionSeverity::Warning
                } else {
                    SwarmContentionSeverity::Nominal
                },
            );
            let impact_score = (region.event_count as u64)
                .saturating_mul(1_000)
                .saturating_add((region.queue_peak as u64).saturating_mul(20_000))
                .saturating_add((region.cancelled_task_count as u64).saturating_mul(50_000))
                .saturating_add((region.admission_decision_count as u64).saturating_mul(5_000));
            SwarmContentionHotSpot {
                key: format!("region:{}", region.region_index),
                kind: SwarmContentionHotspotKind::Region,
                severity,
                impact_score,
                p50_wait_ns: None,
                p95_wait_ns: None,
                p99_wait_ns: None,
                queue_depth_p95: Some(region.queue_peak as u64),
                queue_depth_p99: Some(region.queue_peak as u64),
                contentions: Some(region.admission_decision_count as u64),
                region_or_scope: region.region_id.map_or_else(
                    || Some(format!("region:{}", region.region_index)),
                    |id| Some(format!("region_id:{id}")),
                ),
                evidence: format!(
                    "events={} tasks={} cancelled={} queue_peak={} admissions={}",
                    region.event_count,
                    region.task_count,
                    region.cancelled_task_count,
                    region.queue_peak,
                    region.admission_decision_count
                ),
                owner_surface: region.route_hint.clone(),
                owner_bead_hint: "asupersync-vssefs.9.4".to_string(),
            }
        })
        .collect::<Vec<_>>();

    let mut queues = summary
        .largest_queues
        .iter()
        .map(|queue| {
            let severity = queue_severity(queue.queue_depth as u64, queue.queue_depth as u64);
            SwarmContentionHotSpot {
                key: queue.scope.clone(),
                kind: SwarmContentionHotspotKind::Queue,
                severity,
                impact_score: (queue.queue_depth as u64).saturating_mul(20_000),
                p50_wait_ns: None,
                p95_wait_ns: None,
                p99_wait_ns: None,
                queue_depth_p95: Some(queue.queue_depth as u64),
                queue_depth_p99: Some(queue.queue_depth as u64),
                contentions: Some(queue.queue_depth as u64),
                region_or_scope: Some(queue.scope.clone()),
                evidence: format!(
                    "queue_depth={} event_kind={}",
                    queue.queue_depth, queue.event_kind
                ),
                owner_surface: queue.route_hint.clone(),
                owner_bead_hint: "asupersync-vssefs.9.4".to_string(),
            }
        })
        .collect::<Vec<_>>();

    sort_heatmap_hotspots(&mut regions);
    sort_heatmap_hotspots(&mut queues);
    (regions, queues)
}

const fn wait_severity(p95_wait_ns: u64, p99_wait_ns: u64) -> SwarmContentionSeverity {
    if p99_wait_ns >= 1_000_000 || p95_wait_ns >= 500_000 {
        SwarmContentionSeverity::Critical
    } else if p99_wait_ns >= 250_000 || p95_wait_ns >= 100_000 {
        SwarmContentionSeverity::Warning
    } else if p99_wait_ns >= 50_000 || p95_wait_ns >= 25_000 {
        SwarmContentionSeverity::Watch
    } else {
        SwarmContentionSeverity::Nominal
    }
}

const fn queue_severity(queue_depth_p95: u64, queue_depth_p99: u64) -> SwarmContentionSeverity {
    if queue_depth_p99 >= 256 || queue_depth_p95 >= 128 {
        SwarmContentionSeverity::Critical
    } else if queue_depth_p99 >= 64 || queue_depth_p95 >= 32 {
        SwarmContentionSeverity::Warning
    } else if queue_depth_p99 >= 8 || queue_depth_p95 >= 4 {
        SwarmContentionSeverity::Watch
    } else {
        SwarmContentionSeverity::Nominal
    }
}

fn sort_heatmap_hotspots(hotspots: &mut [SwarmContentionHotSpot]) {
    hotspots.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.impact_score.cmp(&left.impact_score))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.key.cmp(&right.key))
    });
}

fn sorted_unique_owned(mut values: Vec<String>) -> Vec<String> {
    for value in &mut values {
        *value = value.trim().to_string();
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values
}

fn minimizer_replay_command(input: &SwarmFailureMinimizerInput) -> Option<String> {
    input
        .replay_command
        .as_deref()
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .map(str::to_string)
        .or_else(|| {
            input
                .failure_bundle
                .proof_lane_plan
                .as_ref()
                .map(|plan| plan.command.trim())
                .filter(|command| !command.is_empty())
                .map(str::to_string)
        })
}

fn minimizer_missing_required_fields(
    input: &SwarmFailureMinimizerInput,
    replay_command: Option<&str>,
) -> Vec<String> {
    let mut missing = Vec::new();
    if input.minimizer_id.trim().is_empty() {
        missing.push("minimizer_id".to_string());
    }
    if input.failure_bundle.bundle_id.trim().is_empty() {
        missing.push("failure_bundle.bundle_id".to_string());
    }
    if input.failure_bundle.original_artifact.trim().is_empty() {
        missing.push("failure_bundle.original_artifact".to_string());
    }
    if input.failure_bundle.first_failure.trim().is_empty() {
        missing.push("failure_bundle.first_failure".to_string());
    }
    if input
        .failure_bundle
        .redaction_policy_id
        .as_deref()
        .is_none_or(|policy| policy.trim().is_empty())
    {
        missing.push("failure_bundle.redaction_policy_id".to_string());
    }
    if input.minimum_regions == 0 {
        missing.push("minimum_regions".to_string());
    }
    if input.minimum_tasks_per_region == 0 {
        missing.push("minimum_tasks_per_region".to_string());
    }
    if input.minimum_replay_steps == 0 {
        missing.push("minimum_replay_steps".to_string());
    }
    if input.max_reduction_passes == 0 {
        missing.push("max_reduction_passes".to_string());
    }
    if input.source_trace_ids.is_empty() {
        missing.push("source_trace_ids".to_string());
    }
    if replay_command.is_none() {
        missing.push("replay_command".to_string());
    }

    match &input.failure_bundle.trace_summary {
        Some(summary) => {
            if !summary.required_fields_present {
                missing.push("trace_summary.required_fields_present".to_string());
                missing.extend(
                    summary
                        .missing_required_fields
                        .iter()
                        .map(|field| format!("trace_summary.{field}")),
                );
            }
            if summary.verdict == SwarmPressureTraceVerdict::Incomplete {
                missing.push("trace_summary.verdict".to_string());
            }
            if summary.scenario_id.trim().is_empty() {
                missing.push("trace_summary.scenario_id".to_string());
            }
        }
        None => missing.push("trace_summary".to_string()),
    }

    match &input.failure_bundle.proof_lane_plan {
        Some(plan) => {
            if plan.decision != SwarmProofLaneDecision::Ready {
                missing.push("proof_lane_plan.ready".to_string());
            }
            if plan.remote_required && !plan.remote_provenance_observed {
                missing.push("proof_lane_plan.remote_provenance".to_string());
            }
            if plan.command.trim().is_empty() {
                missing.push("proof_lane_plan.command".to_string());
            }
        }
        None => missing.push("proof_lane_plan".to_string()),
    }

    missing
}

fn minimizer_invariant_reproduced(input: &SwarmFailureMinimizerInput) -> bool {
    input.failure_bundle.invariant_reproduced
        && input
            .failure_bundle
            .trace_summary
            .as_ref()
            .is_some_and(|summary| summary.verdict == SwarmPressureTraceVerdict::Fail)
}

fn reduce_swarm_failure_scenario(
    input: &SwarmFailureMinimizerInput,
    scenario: &mut SwarmReplayScenario,
    reduction_steps: &mut Vec<SwarmFailureReductionStep>,
) -> SwarmFailureMinimizerStopReason {
    let (target_regions, target_tasks_per_region, target_max_steps) = minimizer_target_knobs(input);
    let reduction_count_before = reduction_steps.len();

    if target_regions < scenario.region_count {
        if !push_minimizer_reduction(
            reduction_steps,
            input.max_reduction_passes,
            "region_count",
            scenario.region_count,
            target_regions,
            "smallest region set carrying the failure class",
        ) {
            return SwarmFailureMinimizerStopReason::StepLimitReached;
        }
        scenario.region_count = target_regions;
    }

    if target_tasks_per_region < scenario.tasks_per_region {
        if !push_minimizer_reduction(
            reduction_steps,
            input.max_reduction_passes,
            "tasks_per_region",
            scenario.tasks_per_region,
            target_tasks_per_region,
            "smallest per-region task budget carrying the failure class",
        ) {
            return SwarmFailureMinimizerStopReason::StepLimitReached;
        }
        scenario.tasks_per_region = target_tasks_per_region;
    }

    if target_max_steps < scenario.max_steps {
        if !push_minimizer_reduction(
            reduction_steps,
            input.max_reduction_passes,
            "max_steps",
            scenario.max_steps,
            target_max_steps,
            "lowest replay budget that still covers the first failure window",
        ) {
            return SwarmFailureMinimizerStopReason::StepLimitReached;
        }
        scenario.max_steps = target_max_steps;
    }

    if reduction_steps.len() > reduction_count_before {
        scenario.scenario_id = format!("{}-minimized", input.original_scenario.scenario_id);
        SwarmFailureMinimizerStopReason::InvariantPreserved
    } else {
        SwarmFailureMinimizerStopReason::AlreadyMinimal
    }
}

fn minimizer_target_knobs(input: &SwarmFailureMinimizerInput) -> (usize, usize, u64) {
    let scenario = &input.original_scenario;
    let summary = input
        .failure_bundle
        .trace_summary
        .as_ref()
        .expect("checked before minimizer targets are computed");
    let min_regions = input.minimum_regions.max(1).min(scenario.region_count);
    let min_tasks_per_region = input
        .minimum_tasks_per_region
        .max(1)
        .min(scenario.tasks_per_region);
    let mut target_regions = min_regions;
    let mut target_tasks_per_region = min_tasks_per_region;

    match input.failure_bundle.invariant_class {
        SwarmFailureInvariantClass::CancellationStorm => {
            let evidence_regions = summary
                .region_lifecycle
                .non_quiescent_regions
                .max(summary.longest_drains.len())
                .max(1);
            target_regions = target_regions.max(evidence_regions);
            target_tasks_per_region = target_tasks_per_region.max(ceil_div_usize(
                summary.cancellation.cancelled_tasks.max(1),
                target_regions,
            ));
        }
        SwarmFailureInvariantClass::DeadlockOrLostWakeup => {
            let evidence_regions = summary
                .region_lifecycle
                .non_quiescent_regions
                .max(summary.longest_drains.len())
                .max(1);
            target_regions = target_regions.max(evidence_regions);
            target_tasks_per_region = target_tasks_per_region.max(
                ceil_div_usize(
                    summary.task_lifecycle.non_terminal_tasks.max(2),
                    target_regions,
                )
                .max(2),
            );
        }
        SwarmFailureInvariantClass::ObligationLeak => {
            let evidence_regions = summary.obligation_leak_suspects.len().max(1);
            target_regions = target_regions.max(evidence_regions);
            target_tasks_per_region = target_tasks_per_region.max(ceil_div_usize(
                summary.obligations.unresolved_obligations.max(1),
                target_regions,
            ));
        }
        SwarmFailureInvariantClass::AdmissionFailure => {
            let evidence_regions = summary
                .admission
                .combiner_or_admission_decisions
                .max(summary.region_lifecycle.non_quiescent_regions)
                .max(1);
            target_regions = target_regions.max(evidence_regions);
            if let Some(limit) = scenario.region_task_admission_limit {
                target_tasks_per_region = target_tasks_per_region.max(limit.saturating_add(1));
            }
        }
        SwarmFailureInvariantClass::QueuePressure => {
            let evidence_regions = summary
                .top_hot_regions
                .len()
                .max(summary.largest_queues.len())
                .max(1);
            target_regions = target_regions.max(evidence_regions);
            let peak_queue = summary.queue_pressure.peak_queue_depth.max(1);
            target_tasks_per_region =
                target_tasks_per_region.max(ceil_div_usize(peak_queue, target_regions));
        }
        SwarmFailureInvariantClass::InvariantViolation => {
            let evidence_regions = summary
                .region_lifecycle
                .non_quiescent_regions
                .max(summary.top_hot_regions.len())
                .max(1);
            target_regions = target_regions.max(evidence_regions);
            target_tasks_per_region = target_tasks_per_region.max(ceil_div_usize(
                summary.task_lifecycle.non_terminal_tasks.max(1),
                target_regions,
            ));
        }
    }

    target_regions = target_regions.min(scenario.region_count);
    target_tasks_per_region = target_tasks_per_region.min(scenario.tasks_per_region);
    let target_max_steps = minimizer_target_max_steps(input, summary);

    (target_regions, target_tasks_per_region, target_max_steps)
}

fn minimizer_target_max_steps(
    input: &SwarmFailureMinimizerInput,
    summary: &SwarmPressureTraceSummary,
) -> u64 {
    let scenario = &input.original_scenario;
    let cancel_window = scenario
        .cancel_after_steps
        .map_or(0, |step| step.saturating_add(1));
    let failure_window = match input.failure_bundle.invariant_class {
        SwarmFailureInvariantClass::CancellationStorm => cancel_window
            .saturating_add(summary.cancellation.cancellation_drain_steps)
            .saturating_add(16),
        SwarmFailureInvariantClass::DeadlockOrLostWakeup => cancel_window
            .saturating_add(summary.cancellation.cancellation_drain_steps)
            .saturating_add(summary.task_lifecycle.non_terminal_tasks as u64)
            .saturating_add(16),
        SwarmFailureInvariantClass::ObligationLeak => cancel_window
            .saturating_add(summary.obligations.unresolved_obligations as u64)
            .saturating_add(16),
        SwarmFailureInvariantClass::AdmissionFailure => cancel_window
            .saturating_add(summary.admission.combiner_or_admission_decisions.max(1) as u64 + 8),
        SwarmFailureInvariantClass::QueuePressure => cancel_window
            .saturating_add(summary.queue_pressure.pressure_event_count as u64)
            .saturating_add(16),
        SwarmFailureInvariantClass::InvariantViolation => cancel_window.saturating_add(32),
    };
    let lower_bound = input
        .minimum_replay_steps
        .max(cancel_window)
        .min(scenario.max_steps);
    failure_window.max(lower_bound).min(scenario.max_steps)
}

fn push_minimizer_reduction<T: fmt::Display>(
    reduction_steps: &mut Vec<SwarmFailureReductionStep>,
    max_reduction_passes: usize,
    knob: &str,
    before: T,
    after: T,
    reason: &str,
) -> bool {
    if reduction_steps.len() >= max_reduction_passes {
        return false;
    }
    reduction_steps.push(SwarmFailureReductionStep {
        knob: knob.to_string(),
        before: before.to_string(),
        after: after.to_string(),
        reason: reason.to_string(),
        preserved_invariant: true,
    });
    true
}

fn minimizer_owner_hint(invariant_class: SwarmFailureInvariantClass) -> (String, String) {
    match invariant_class {
        SwarmFailureInvariantClass::CancellationStorm => (
            "src/cancel/mod.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:cancellation-drain".to_string(),
        ),
        SwarmFailureInvariantClass::DeadlockOrLostWakeup => (
            "src/runtime/scheduler/three_lane.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:scheduler-wakeup".to_string(),
        ),
        SwarmFailureInvariantClass::ObligationLeak => (
            "src/obligation/mod.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:obligation-leak".to_string(),
        ),
        SwarmFailureInvariantClass::AdmissionFailure => (
            "src/lab/swarm_replay.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:admission".to_string(),
        ),
        SwarmFailureInvariantClass::QueuePressure => (
            "src/runtime/scheduler/three_lane.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:queue-pressure".to_string(),
        ),
        SwarmFailureInvariantClass::InvariantViolation => (
            "src/runtime/mod.rs".to_string(),
            "asupersync-vssefs.9.5-follow-up:runtime-invariant".to_string(),
        ),
    }
}

fn minimizer_routing_hints(
    input: &SwarmFailureMinimizerInput,
    owner_surface: &str,
    owner_bead_hint: &str,
) -> Vec<String> {
    let mut hints = vec![
        format!(
            "minimized {:?} routes to {owner_surface} ({owner_bead_hint})",
            input.failure_bundle.invariant_class
        ),
        format!(
            "keep original artifact pointer {}",
            input.failure_bundle.original_artifact
        ),
        format!("first failure: {}", input.failure_bundle.first_failure),
    ];
    if let Some(summary) = &input.failure_bundle.trace_summary {
        hints.extend(summary.routing_hints.clone());
        if let Some(invariant) = &summary.first_invariant_violation {
            hints.push(format!("first invariant violation: {invariant}"));
        }
    }
    if let Some(plan) = &input.failure_bundle.proof_lane_plan {
        hints.push(format!(
            "proof lane {} decision {:?}",
            plan.lane_id, plan.decision
        ));
    }
    hints
}

const fn ceil_div_usize(numerator: usize, denominator: usize) -> usize {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_add(denominator - 1) / denominator
    }
}

fn reduction_ratio_bps(original: usize, minimized: usize) -> u16 {
    if original == 0 || minimized >= original {
        return 0;
    }
    let reduced = original - minimized;
    let ratio = reduced.saturating_mul(10_000) / original;
    ratio.min(10_000) as u16
}

fn optional_u64_text(value: Option<u64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| value.to_string())
}

const REPLAY_TRACE_REQUIRED_FIELDS: &[&str] = &[
    "schema_version",
    "scenario_id",
    "seed",
    "region_count",
    "task_count",
    "scheduled_task_count",
    "terminal_task_count",
    "non_terminal_task_count",
    "obligation_commits",
    "obligation_aborts",
    "cancellation_drain_steps",
    "quiescent",
    "trace_event_count",
    "invariant_violations",
    "event_log",
    "admission_records",
];

const PRESSURE_TRACE_REQUIRED_FOR_PASS: &[&str] = &[
    "region_count",
    "obligation_commits",
    "obligation_aborts",
    "cancellation_drain_steps",
    "admission_records",
];

const AGENT_RUN_TRACE_REQUIRED_FOR_PASS: &[&str] = &[
    "region_count",
    "obligation_commits",
    "obligation_aborts",
    "queue_pressure",
    "admission_records",
];

#[derive(Debug, Clone)]
struct RegionTraceAccum {
    region_index: usize,
    region_id: Option<u64>,
    event_count: usize,
    task_count: usize,
    cancelled_task_count: usize,
    queue_peak: usize,
    admission_decision_count: usize,
}

fn summarize_replay_artifact_json(value: &serde_json::Value) -> SwarmPressureTraceSummary {
    let missing = missing_top_level_fields(value, REPLAY_TRACE_REQUIRED_FIELDS);
    if !missing.is_empty() {
        return incomplete_trace_summary(
            SwarmPressureTraceSourceKind::ReplayLab,
            SWARM_REPLAY_SCHEMA_VERSION,
            value,
            missing,
            Some("replay artifact missing fields required for a pass verdict".to_string()),
        );
    }
    match serde_json::from_value::<SwarmReplaySummary>(value.clone()) {
        Ok(summary) => summarize_swarm_replay_trace(&summary),
        Err(error) => incomplete_trace_summary(
            SwarmPressureTraceSourceKind::ReplayLab,
            SWARM_REPLAY_SCHEMA_VERSION,
            value,
            Vec::new(),
            Some(format!("replay artifact failed to deserialize: {error}")),
        ),
    }
}

fn summarize_pressure_artifact_json(value: &serde_json::Value) -> SwarmPressureTraceSummary {
    match serde_json::from_value::<SwarmPressureSummary>(value.clone()) {
        Ok(summary) => summarize_swarm_pressure_trace(&summary),
        Err(error) => incomplete_trace_summary(
            SwarmPressureTraceSourceKind::PressureLab,
            SWARM_PRESSURE_SCHEMA_VERSION,
            value,
            pressure_missing_required_fields(),
            Some(format!("pressure artifact failed to deserialize: {error}")),
        ),
    }
}

fn summarize_agent_run_artifact_json(value: &serde_json::Value) -> SwarmPressureTraceSummary {
    match serde_json::from_value::<SwarmAgentRunSummary>(value.clone()) {
        Ok(summary) => summarize_swarm_agent_run_trace(&summary),
        Err(error) => incomplete_trace_summary(
            SwarmPressureTraceSourceKind::AgentRun,
            SWARM_AGENT_RUN_SCHEMA_VERSION,
            value,
            agent_run_missing_required_fields(),
            Some(format!("agent-run artifact failed to deserialize: {error}")),
        ),
    }
}

fn incomplete_trace_summary(
    source_kind: SwarmPressureTraceSourceKind,
    source_schema_version: &str,
    value: &serde_json::Value,
    missing_required_fields: Vec<String>,
    first_invariant_violation: Option<String>,
) -> SwarmPressureTraceSummary {
    let scenario_id = value
        .get("scenario_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let seed = value
        .get("seed")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let mut routing_hints =
        vec!["source artifact cannot prove success until required fields are present".to_string()];
    if !missing_required_fields.is_empty() {
        routing_hints.push(format!(
            "missing required fields: {}",
            missing_required_fields.join(",")
        ));
    }
    if let Some(violation) = &first_invariant_violation {
        routing_hints.push(format!("first parse/schema issue: {violation}"));
    }

    SwarmPressureTraceSummary {
        schema_version: SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION.to_string(),
        source_schema_version: source_schema_version.to_string(),
        source_kind,
        scenario_id,
        seed,
        verdict: SwarmPressureTraceVerdict::Incomplete,
        required_fields_present: false,
        missing_required_fields,
        first_invariant_violation,
        region_lifecycle: SwarmPressureTraceRegionLifecycle {
            regions_declared: 0,
            regions_with_runtime_id: 0,
            quiescent_regions: 0,
            non_quiescent_regions: 0,
        },
        task_lifecycle: SwarmPressureTraceTaskLifecycle {
            submitted_tasks: 0,
            scheduled_tasks: 0,
            terminal_tasks: 0,
            non_terminal_tasks: 0,
            task_leaks: 0,
        },
        cancellation: SwarmPressureTraceCancellation {
            cancellation_requests: 0,
            cancelled_tasks: 0,
            cancellation_drain_steps: 0,
            losers_drained: false,
        },
        obligations: SwarmPressureTraceObligations {
            fields_present: false,
            resolved_obligations: 0,
            committed_obligations: 0,
            aborted_obligations: 0,
            unresolved_obligations: 0,
        },
        queue_pressure: SwarmPressureTraceQueuePressure {
            peak_queue_depth: 0,
            pressure_event_count: 0,
            peak_scope: None,
        },
        admission: SwarmPressureTraceAdmission {
            accepted: 0,
            deferred: 0,
            shed: 0,
            cancelled: 0,
            proof_admitted: 0,
            proof_throttled: 0,
            interactive_admitted: 0,
            cleanup_requested: 0,
            combiner_or_admission_decisions: 0,
            first_rejection: None,
        },
        cleanup: SwarmPressureTraceCleanup {
            cleanup_requests: 0,
            authorization_required: 0,
            authorized: 0,
            max_cleanup_latency_steps: 0,
            auto_delete_command_count: 0,
        },
        top_hot_regions: Vec::new(),
        longest_drains: Vec::new(),
        largest_queues: Vec::new(),
        obligation_leak_suspects: Vec::new(),
        routing_hints,
    }
}

fn trace_verdict(
    required_fields_present: bool,
    quiescent: bool,
    non_terminal_task_count: usize,
    unresolved_obligations: usize,
    invariant_violations: &[String],
) -> SwarmPressureTraceVerdict {
    if !required_fields_present {
        return SwarmPressureTraceVerdict::Incomplete;
    }
    if quiescent
        && non_terminal_task_count == 0
        && unresolved_obligations == 0
        && invariant_violations.is_empty()
    {
        SwarmPressureTraceVerdict::Pass
    } else {
        SwarmPressureTraceVerdict::Fail
    }
}

const fn bool_as_usize(value: bool) -> usize {
    if value { 1 } else { 0 }
}

fn missing_top_level_fields(value: &serde_json::Value, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter(|field| value.get(**field).is_none())
        .map(|field| (*field).to_string())
        .collect()
}

fn pressure_missing_required_fields() -> Vec<String> {
    PRESSURE_TRACE_REQUIRED_FOR_PASS
        .iter()
        .map(|field| (*field).to_string())
        .collect()
}

fn agent_run_missing_required_fields() -> Vec<String> {
    AGENT_RUN_TRACE_REQUIRED_FOR_PASS
        .iter()
        .map(|field| (*field).to_string())
        .collect()
}

fn obligation_violation_present(violations: &[String]) -> bool {
    violations.iter().any(|violation| {
        let lower = violation.to_ascii_lowercase();
        lower.contains("obligation") || lower.contains("leak")
    })
}

fn trace_routing_hints(
    source_kind: SwarmPressureTraceSourceKind,
    required_fields_present: bool,
    quiescent: bool,
    non_terminal_task_count: usize,
    unresolved_obligations: usize,
    first_invariant_violation: Option<&str>,
    first_rejection: Option<&str>,
) -> Vec<String> {
    let mut hints = Vec::new();
    if !required_fields_present {
        hints.push(format!(
            "{source_kind:?} artifact is useful for triage but cannot be used as pass evidence"
        ));
    }
    if !quiescent {
        hints.push("route follow-up to lab/runtime quiescence owner".to_string());
    }
    if non_terminal_task_count > 0 {
        hints.push(format!(
            "route {} non-terminal task(s) to scheduler/region lifecycle owner",
            non_terminal_task_count
        ));
    }
    if unresolved_obligations > 0 {
        hints.push(format!(
            "route {} unresolved obligation(s) to obligation/cancel owner",
            unresolved_obligations
        ));
    }
    if let Some(violation) = first_invariant_violation {
        hints.push(format!("first invariant violation: {violation}"));
    }
    if let Some(rejection) = first_rejection {
        hints.push(format!("first admission blocker: {rejection}"));
    }
    hints
}

fn replay_hot_regions(summary: &SwarmReplaySummary) -> Vec<SwarmPressureTraceHotRegion> {
    let mut regions: BTreeMap<usize, RegionTraceAccum> = BTreeMap::new();
    for record in &summary.admission_records {
        let entry = regions
            .entry(record.region_index)
            .or_insert_with(|| RegionTraceAccum {
                region_index: record.region_index,
                region_id: record.region_id,
                event_count: 0,
                task_count: 0,
                cancelled_task_count: 0,
                queue_peak: 0,
                admission_decision_count: 0,
            });
        entry.region_id = entry.region_id.or(record.region_id);
        entry.task_count = entry.task_count.saturating_add(record.admitted_tasks);
        entry.admission_decision_count = entry.admission_decision_count.saturating_add(1);
    }
    for outcome in &summary.task_outcomes {
        let entry = regions
            .entry(outcome.region_index)
            .or_insert_with(|| RegionTraceAccum {
                region_index: outcome.region_index,
                region_id: None,
                event_count: 0,
                task_count: 0,
                cancelled_task_count: 0,
                queue_peak: 0,
                admission_decision_count: 0,
            });
        if outcome.status == SwarmReplayTaskStatus::Cancelled {
            entry.cancelled_task_count = entry.cancelled_task_count.saturating_add(1);
        }
    }
    for event in &summary.event_log {
        let entry = regions
            .entry(event.region_index)
            .or_insert_with(|| RegionTraceAccum {
                region_index: event.region_index,
                region_id: event.region_id,
                event_count: 0,
                task_count: 0,
                cancelled_task_count: 0,
                queue_peak: 0,
                admission_decision_count: 0,
            });
        entry.region_id = entry.region_id.or(event.region_id);
        entry.event_count = entry.event_count.saturating_add(1);
        entry.queue_peak = entry.queue_peak.max(event.queue_depth);
    }

    let mut hot_regions: Vec<_> = regions
        .into_values()
        .map(|region| SwarmPressureTraceHotRegion {
            region_index: region.region_index,
            region_id: region.region_id,
            event_count: region.event_count,
            task_count: region.task_count,
            cancelled_task_count: region.cancelled_task_count,
            queue_peak: region.queue_peak,
            admission_decision_count: region.admission_decision_count,
            route_hint: format!("src/lab/swarm_replay.rs region {}", region.region_index),
        })
        .collect();
    hot_regions.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| right.queue_peak.cmp(&left.queue_peak))
            .then_with(|| left.region_index.cmp(&right.region_index))
    });
    hot_regions.truncate(5);
    hot_regions
}

fn replay_largest_queues(summary: &SwarmReplaySummary) -> Vec<SwarmPressureTraceQueueHotSpot> {
    let mut queues_by_key: BTreeMap<(String, String), SwarmPressureTraceQueueHotSpot> =
        BTreeMap::new();
    for event in summary
        .event_log
        .iter()
        .filter(|event| event.queue_depth > 0)
    {
        let scope = format!("region:{}", event.region_index);
        let event_kind = format!("{:?}", event.kind);
        let key = (scope.clone(), event_kind.clone());
        let candidate = SwarmPressureTraceQueueHotSpot {
            scope,
            queue_depth: event.queue_depth,
            event_kind,
            route_hint: format!("region {} event {:?}", event.region_index, event.kind),
        };
        queues_by_key
            .entry(key)
            .and_modify(|existing| {
                if candidate.queue_depth > existing.queue_depth {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    let mut queues: Vec<_> = queues_by_key.into_values().collect();
    queues.sort_by(|left, right| {
        right
            .queue_depth
            .cmp(&left.queue_depth)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.event_kind.cmp(&right.event_kind))
    });
    queues.truncate(5);
    queues
}

fn replay_queue_pressure(
    summary: &SwarmReplaySummary,
    largest_queues: &[SwarmPressureTraceQueueHotSpot],
) -> SwarmPressureTraceQueuePressure {
    SwarmPressureTraceQueuePressure {
        peak_queue_depth: largest_queues.first().map_or(0, |queue| queue.queue_depth),
        pressure_event_count: summary
            .event_log
            .iter()
            .filter(|event| event.queue_depth > 0)
            .count(),
        peak_scope: largest_queues.first().map(|queue| queue.scope.clone()),
    }
}

fn replay_longest_drains(summary: &SwarmReplaySummary) -> Vec<SwarmPressureTraceDrainHotSpot> {
    let mut drains = Vec::new();
    if summary.cancellation_drain_steps > 0 || summary.cancellation_requests > 0 {
        drains.push(SwarmPressureTraceDrainHotSpot {
            scope: "global:cancellation".to_string(),
            drain_steps: summary.cancellation_drain_steps,
            quiescent: summary.quiescent,
            reason: format!(
                "{} cancellation request(s), {} cancelled task(s)",
                summary.cancellation_requests,
                summary
                    .task_outcomes
                    .iter()
                    .filter(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled)
                    .count()
            ),
        });
    }
    for record in &summary.admission_records {
        if record.cancellation_requested || !record.quiescence_verdict {
            drains.push(SwarmPressureTraceDrainHotSpot {
                scope: format!("region:{}", record.region_index),
                drain_steps: summary.cancellation_drain_steps,
                quiescent: record.quiescence_verdict,
                reason: format!(
                    "{:?} admission drain {:?}",
                    record.decision, record.drain_result
                ),
            });
        }
    }
    drains.sort_by(|left, right| {
        right
            .drain_steps
            .cmp(&left.drain_steps)
            .then_with(|| left.scope.cmp(&right.scope))
    });
    drains.truncate(5);
    drains
}

fn replay_obligation_leak_suspects(
    summary: &SwarmReplaySummary,
    unresolved_obligations: usize,
) -> Vec<SwarmPressureTraceObligationLeakSuspect> {
    let mut suspects = Vec::new();
    if unresolved_obligations > 0 {
        suspects.push(SwarmPressureTraceObligationLeakSuspect {
            scope: "global:obligations".to_string(),
            unresolved_obligations,
            evidence: format!(
                "quiescent={} non_terminal_tasks={} invariant_violations={}",
                summary.quiescent,
                summary.non_terminal_task_count,
                summary.invariant_violations.len()
            ),
            route_hint: "src/obligation and src/cancel".to_string(),
        });
    }
    for violation in summary.invariant_violations.iter().filter(|violation| {
        let lower = violation.to_ascii_lowercase();
        lower.contains("obligation") || lower.contains("leak")
    }) {
        suspects.push(SwarmPressureTraceObligationLeakSuspect {
            scope: "runtime:invariant".to_string(),
            unresolved_obligations: unresolved_obligations.max(1),
            evidence: violation.clone(),
            route_hint: "runtime invariant violation points at obligation cleanup".to_string(),
        });
    }
    suspects
}

fn pressure_largest_queues(summary: &SwarmPressureSummary) -> Vec<SwarmPressureTraceQueueHotSpot> {
    let mut queues_by_key: BTreeMap<(String, String), SwarmPressureTraceQueueHotSpot> =
        BTreeMap::new();
    for event in summary
        .event_log
        .iter()
        .filter(|event| event.queue_depth > 0)
    {
        let scope = event.lane.map_or_else(
            || "pressure:global".to_string(),
            |lane| format!("pressure:{lane:?}"),
        );
        let event_kind = format!("{:?}", event.kind);
        let key = (scope.clone(), event_kind.clone());
        let candidate = SwarmPressureTraceQueueHotSpot {
            scope,
            queue_depth: event.queue_depth,
            event_kind,
            route_hint: format!(
                "pressure event {:?} at step {} disk={:?} rch_workers={}",
                event.kind, event.step, event.disk_pressure, event.rch_workers_available
            ),
        };
        queues_by_key
            .entry(key)
            .and_modify(|existing| {
                if candidate.queue_depth > existing.queue_depth {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    let mut queues: Vec<_> = queues_by_key.into_values().collect();
    queues.sort_by(|left, right| {
        right
            .queue_depth
            .cmp(&left.queue_depth)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.event_kind.cmp(&right.event_kind))
    });
    queues.truncate(5);
    queues
}

fn pressure_queue_pressure(
    summary: &SwarmPressureSummary,
    largest_queues: &[SwarmPressureTraceQueueHotSpot],
) -> SwarmPressureTraceQueuePressure {
    SwarmPressureTraceQueuePressure {
        peak_queue_depth: largest_queues.first().map_or(0, |queue| queue.queue_depth),
        pressure_event_count: summary
            .event_log
            .iter()
            .filter(|event| event.queue_depth > 0)
            .count(),
        peak_scope: largest_queues.first().map(|queue| queue.scope.clone()),
    }
}

fn pressure_longest_drains(summary: &SwarmPressureSummary) -> Vec<SwarmPressureTraceDrainHotSpot> {
    let mut drains = Vec::new();
    if summary.cleanup_requests > 0 {
        drains.push(SwarmPressureTraceDrainHotSpot {
            scope: "pressure:cleanup".to_string(),
            drain_steps: summary
                .event_log
                .iter()
                .filter(|event| event.kind == SwarmPressureEventKind::CleanupRequested)
                .map(|event| event.admission_latency_steps)
                .max()
                .unwrap_or(0),
            quiescent: summary.quiescent,
            reason: format!(
                "{} cleanup request(s), {} requiring authorization",
                summary.cleanup_requests, summary.cleanup_authorization_required_count
            ),
        });
    }
    if summary.non_terminal_task_count > 0 {
        drains.push(SwarmPressureTraceDrainHotSpot {
            scope: "pressure:task-leak".to_string(),
            drain_steps: 0,
            quiescent: false,
            reason: format!(
                "{} non-terminal pressure task(s)",
                summary.non_terminal_task_count
            ),
        });
    }
    drains
}

fn pressure_obligation_leak_suspects(
    summary: &SwarmPressureSummary,
) -> Vec<SwarmPressureTraceObligationLeakSuspect> {
    let mut suspects = Vec::new();
    if !summary.quiescent || summary.non_terminal_task_count > 0 {
        suspects.push(SwarmPressureTraceObligationLeakSuspect {
            scope: "pressure:missing-obligation-fields".to_string(),
            unresolved_obligations: summary.non_terminal_task_count,
            evidence: "pressure summaries do not carry obligation commit/abort counters"
                .to_string(),
            route_hint: "rerun with replay-lab artifact when obligation proof is required"
                .to_string(),
        });
    }
    suspects
}

fn agent_run_longest_drains(summary: &SwarmAgentRunSummary) -> Vec<SwarmPressureTraceDrainHotSpot> {
    let mut drains = Vec::new();
    if summary.recovery_handoff_count > 0 || summary.crashed_agent_count > 0 {
        drains.push(SwarmPressureTraceDrainHotSpot {
            scope: "agent-run:recovery".to_string(),
            drain_steps: 0,
            quiescent: summary.quiescent,
            reason: format!(
                "{} handoff(s), {} crashed agent(s)",
                summary.recovery_handoff_count, summary.crashed_agent_count
            ),
        });
    }
    drains
}

fn agent_run_largest_queues(summary: &SwarmAgentRunSummary) -> Vec<SwarmPressureTraceQueueHotSpot> {
    let mut queues = Vec::new();
    if summary.rch_proof_attempt_count > 0 {
        queues.push(SwarmPressureTraceQueueHotSpot {
            scope: "agent-run:proof".to_string(),
            queue_depth: summary.rch_proof_attempt_count,
            event_kind: "rch_proof_attempts".to_string(),
            route_hint: "proof lane pressure from synthetic agent run".to_string(),
        });
    }
    if summary.mail_message_count > 0 {
        queues.push(SwarmPressureTraceQueueHotSpot {
            scope: "agent-run:mail".to_string(),
            queue_depth: summary.mail_message_count,
            event_kind: "mail_messages".to_string(),
            route_hint: "coordination queue pressure from synthetic agent run".to_string(),
        });
    }
    queues.sort_by(|left, right| {
        right
            .queue_depth
            .cmp(&left.queue_depth)
            .then_with(|| left.scope.cmp(&right.scope))
    });
    queues
}

fn agent_run_obligation_leak_suspects(
    summary: &SwarmAgentRunSummary,
) -> Vec<SwarmPressureTraceObligationLeakSuspect> {
    let mut suspects = Vec::new();
    if !summary.no_leaked_reservations {
        suspects.push(SwarmPressureTraceObligationLeakSuspect {
            scope: "agent-run:file-reservations".to_string(),
            unresolved_obligations: summary
                .file_reservations_acquired
                .saturating_sub(summary.file_reservations_released),
            evidence: "modeled file reservations were not all released".to_string(),
            route_hint: "Agent Mail reservation closeout".to_string(),
        });
    }
    if !summary.no_false_green_proof {
        suspects.push(SwarmPressureTraceObligationLeakSuspect {
            scope: "agent-run:proof".to_string(),
            unresolved_obligations: 1,
            evidence: "modeled commit appeared without a green proof".to_string(),
            route_hint: "proof gate and closeout verifier".to_string(),
        });
    }
    suspects
}

/// Run a deterministic synthetic agent coordination scenario through [`LabRuntime`].
pub fn run_swarm_agent_run_scenario(
    scenario: &SwarmAgentRunScenario,
) -> Result<SwarmAgentRunSummary, SwarmReplayError> {
    scenario.validate()?;

    let config = LabConfig::new(scenario.seed)
        .worker_count(scenario.agent_count.min(scenario.rch_workers.max(1)))
        .max_steps(scenario.max_steps)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut tracked_tasks = Vec::with_capacity(scenario.agent_count);

    for agent_index in 0..scenario.agent_count {
        let task_id = spawn_agent_run_task(&mut runtime, root, scenario, agent_index, &events)?;
        runtime.scheduler.lock().schedule(task_id, 5);
        tracked_tasks.push(task_id);
    }

    let report = runtime.run_until_quiescent_with_report();
    let terminal_counts = terminal_counts(&runtime, &tracked_tasks);
    let mut event_log = events.lock().clone();
    event_log.sort_by_key(|event| {
        (
            event.stable_sequence,
            event.agent_index,
            event.kind,
            event.bead_id.clone(),
        )
    });

    Ok(build_agent_run_summary(
        scenario,
        report,
        terminal_counts,
        event_log,
    ))
}

fn build_summary(
    scenario: &SwarmReplayScenario,
    report: LabRunReport,
    scheduled_task_count: usize,
    cancellation_requests: usize,
    terminal_counts: (usize, usize),
    event_log: Vec<SwarmReplayEvent>,
    task_outcomes: Vec<SwarmReplayTaskOutcome>,
    completion_order: Vec<usize>,
    admission_records: Vec<SwarmReplayAdmissionRecord>,
) -> SwarmReplaySummary {
    let channel_backlog_peak = event_log
        .iter()
        .filter(|event| event.kind == SwarmReplayEventKind::MessageReserved)
        .map(|event| event.queue_depth)
        .max()
        .unwrap_or(0);
    let artifact_bytes_emitted = event_log
        .iter()
        .map(|event| event.artifact_bytes)
        .sum::<usize>();
    let first_cancelled_task = task_outcomes
        .iter()
        .find(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled)
        .map(|outcome| outcome.global_task_index);
    let event_prefix_len = first_cancelled_task.map_or(event_log.len(), |task| {
        event_log
            .iter()
            .position(|event| {
                event.global_task_index == Some(task)
                    && event.kind == SwarmReplayEventKind::CancelObserved // ubs:ignore - enum equality, not a secret
            })
            .map_or(event_log.len(), |index| index + 1)
    });
    let completed_tasks = task_outcomes
        .iter()
        .filter(|outcome| outcome.status == SwarmReplayTaskStatus::Completed)
        .count();
    let task_count = scenario.task_count();
    let admitted_task_count = scheduled_task_count;
    let rejected_task_count = task_count.saturating_sub(admitted_task_count);
    let deferred_task_count = admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Defer)
        .map(|record| record.rejected_tasks)
        .sum::<usize>();
    let shed_task_count = admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Shed)
        .map(|record| record.rejected_tasks)
        .sum::<usize>();
    let admission_cancelled_task_count = admission_records
        .iter()
        .filter(|record| record.decision == SwarmReplayAdmissionDecision::Cancel)
        .map(|record| record.rejected_tasks)
        .sum::<usize>();
    let channel_reservations = admitted_task_count.saturating_mul(scenario.messages_per_task);
    let channel_commits = completed_tasks.saturating_mul(scenario.messages_per_task);
    let channel_aborts = channel_reservations.saturating_sub(channel_commits);
    let semaphore_acquires =
        admitted_task_count.saturating_mul(scenario.semaphore_permits_per_task);
    let semaphore_releases = semaphore_acquires;
    let pool_checkouts = admitted_task_count.saturating_mul(scenario.pool_slots_per_task);
    let pool_checkins = pool_checkouts;
    let total_obligations = admitted_task_count.saturating_mul(scenario.obligations_per_task);
    let obligation_commits = completed_tasks.saturating_mul(scenario.obligations_per_task);
    let obligation_aborts = total_obligations.saturating_sub(obligation_commits);
    let timer_registrations = admitted_task_count;
    let timer_wakeups = admitted_task_count.saturating_mul(scenario.timer_ticks_per_task);
    let cancellation_drain_steps = scenario.cancel_after_steps.map_or(0, |cancel_step| {
        report.steps_delta.saturating_sub(cancel_step)
    });

    SwarmReplaySummary {
        schema_version: SWARM_REPLAY_SCHEMA_VERSION.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        worker_count: scenario.worker_count,
        cohort_count: scenario.cohort_count,
        region_count: scenario.region_count,
        task_count,
        scheduled_task_count,
        admitted_task_count,
        rejected_task_count,
        deferred_task_count,
        shed_task_count,
        admission_cancelled_task_count,
        cancellation_requests,
        terminal_task_count: terminal_counts.0,
        non_terminal_task_count: terminal_counts.1,
        channel_reservations,
        channel_commits,
        channel_aborts,
        channel_backlog_peak,
        semaphore_acquires,
        semaphore_releases,
        pool_checkouts,
        pool_checkins,
        obligation_commits,
        obligation_aborts,
        timer_registrations,
        timer_wakeups,
        cancellation_tree_depth: scenario.cancellation_tree_depth,
        cancellation_drain_steps,
        artifact_bytes_emitted,
        steps_delta: report.steps_delta,
        quiescent: report.quiescent,
        trace_fingerprint: report.trace_fingerprint,
        trace_digest: format!("{:016x}", report.trace_fingerprint),
        trace_event_count: report.trace_len,
        invariant_violations: report.invariant_violations,
        completion_order,
        event_log,
        task_outcomes,
        shrink_hint: SwarmReplayShrinkHint {
            first_cancelled_task,
            event_prefix_len,
            suggested_region_count: scenario.region_count.min(1),
            suggested_tasks_per_region: scenario.tasks_per_region.min(2),
        },
        admission_records,
    }
}

fn build_agent_run_summary(
    scenario: &SwarmAgentRunScenario,
    report: LabRunReport,
    terminal_counts: (usize, usize),
    event_log: Vec<SwarmAgentRunEvent>,
) -> SwarmAgentRunSummary {
    let bead_claim_count = count_agent_events(&event_log, SwarmAgentRunEventKind::BeadClaimed);
    let file_reservations_acquired =
        count_agent_events(&event_log, SwarmAgentRunEventKind::FileReserved);
    let file_reservations_released =
        count_agent_events(&event_log, SwarmAgentRunEventKind::FileReservationReleased);
    let mail_message_count = count_agent_events(&event_log, SwarmAgentRunEventKind::MailSent);
    let rch_proof_attempt_count =
        count_agent_events(&event_log, SwarmAgentRunEventKind::RchProofStarted);
    let rch_remote_refusal_count =
        count_agent_events(&event_log, SwarmAgentRunEventKind::RchProofRemoteRefused);
    let validation_blocker_count =
        count_agent_events(&event_log, SwarmAgentRunEventKind::ValidationBlocked);
    let proof_pass_count = count_agent_events(&event_log, SwarmAgentRunEventKind::RchProofPassed);
    let commit_count = count_agent_events(&event_log, SwarmAgentRunEventKind::CommitRecorded);
    let crashed_agent_count = count_agent_events(&event_log, SwarmAgentRunEventKind::AgentCrashed);
    let recovery_handoff_count =
        count_agent_events(&event_log, SwarmAgentRunEventKind::RecoveryHandoffEmitted);
    let no_duplicate_ownership = no_duplicate_bead_claims(&event_log);
    let no_false_green_proof = no_false_green_agent_commits(&event_log);
    let first_blocker = event_log
        .iter()
        .find_map(|event| event.blocker.as_ref().map(ToString::to_string));

    SwarmAgentRunSummary {
        schema_version: SWARM_AGENT_RUN_SCHEMA_VERSION.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        agent_count: scenario.agent_count,
        scheduled_task_count: scenario.agent_count,
        terminal_task_count: terminal_counts.0,
        non_terminal_task_count: terminal_counts.1,
        task_leaks: terminal_counts.1,
        bead_claim_count,
        file_reservations_acquired,
        file_reservations_released,
        mail_message_count,
        rch_proof_attempt_count,
        rch_remote_refusal_count,
        validation_blocker_count,
        proof_pass_count,
        commit_count,
        crashed_agent_count,
        recovery_handoff_count,
        no_duplicate_ownership,
        no_leaked_reservations: file_reservations_acquired == file_reservations_released,
        no_false_green_proof,
        non_mutating: event_log.iter().all(|event| !event.mutates_real_services),
        forbidden_actions: SwarmAgentRunForbiddenActions::none(),
        first_blocker,
        replay_command: swarm_agent_replay_command(scenario),
        quiescent: report.quiescent,
        trace_fingerprint: report.trace_fingerprint,
        trace_event_count: report.trace_len,
        invariant_violations: report.invariant_violations,
        event_log,
    }
}

fn count_agent_events(events: &[SwarmAgentRunEvent], kind: SwarmAgentRunEventKind) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

fn add_handoff_reason(
    reasons: &mut Vec<SwarmHandoffVerifierReason>,
    decision: &mut SwarmHandoffDecision,
    candidate: SwarmHandoffDecision,
    code: impl Into<String>,
    detail: impl Into<String>,
    action: impl Into<String>,
) {
    escalate_handoff_decision(decision, candidate);
    reasons.push(SwarmHandoffVerifierReason {
        code: code.into(),
        detail: detail.into(),
        action: action.into(),
    });
}

fn escalate_handoff_decision(decision: &mut SwarmHandoffDecision, candidate: SwarmHandoffDecision) {
    if handoff_decision_rank(candidate) > handoff_decision_rank(*decision) {
        *decision = candidate;
    }
}

const fn handoff_decision_rank(decision: SwarmHandoffDecision) -> u8 {
    match decision {
        SwarmHandoffDecision::Continue => 0,
        SwarmHandoffDecision::NarrowRefreshRequired => 1,
        SwarmHandoffDecision::CoordinateFirst => 2,
        SwarmHandoffDecision::UnsafeToContinue => 3,
    }
}

const fn handoff_next_action(decision: SwarmHandoffDecision) -> &'static str {
    match decision {
        SwarmHandoffDecision::Continue => "continue from capsule",
        SwarmHandoffDecision::NarrowRefreshRequired => "refresh narrow live evidence",
        SwarmHandoffDecision::CoordinateFirst => "coordinate before continuing",
        SwarmHandoffDecision::UnsafeToContinue => "fail closed and surface blocker",
    }
}

fn weighted_demand_units(workloads: &[SwarmWhatIfWorkload]) -> usize {
    workloads
        .iter()
        .map(|workload| {
            let class_weight = match workload.work_class {
                SwarmWhatIfWorkClass::Code
                | SwarmWhatIfWorkClass::Docs
                | SwarmWhatIfWorkClass::Doctor
                | SwarmWhatIfWorkClass::Cleanup => 1usize,
                SwarmWhatIfWorkClass::Proof => 2,
                SwarmWhatIfWorkClass::Artifact => 3,
            };
            let artifact_weight = usize::try_from(workload.artifact_gib / 16).unwrap_or(usize::MAX);
            workload
                .agent_count
                .saturating_mul(class_weight)
                .saturating_add(artifact_weight)
        })
        .sum()
}

fn weighted_capacity_units(scenario: &SwarmWhatIfScenario) -> usize {
    scenario
        .local_agent_slots
        .saturating_mul(2)
        .saturating_add(scenario.rch_workers_admissible.saturating_mul(4))
        .saturating_add(scenario.cache_warm_workers.saturating_mul(2))
}

fn input_freshness(input_age_secs: u64) -> SwarmWhatIfInputFreshness {
    match input_age_secs {
        0..=300 => SwarmWhatIfInputFreshness::Fresh,
        301..=900 => SwarmWhatIfInputFreshness::Partial,
        _ => SwarmWhatIfInputFreshness::Stale,
    }
}

fn input_caveats(input_freshness: SwarmWhatIfInputFreshness) -> Vec<String> {
    match input_freshness {
        SwarmWhatIfInputFreshness::Fresh => Vec::new(),
        SwarmWhatIfInputFreshness::Partial => {
            vec!["some inputs are aging; keep the wave bounded".to_string()]
        }
        SwarmWhatIfInputFreshness::Stale => {
            vec!["inputs are stale; treat this as a conservative forecast".to_string()]
        }
    }
}

fn disk_blocks_artifact_work(scenario: &SwarmWhatIfScenario) -> bool {
    scenario.disk_pressure_bps >= 9_000
        && scenario.workloads.iter().any(|workload| {
            matches!(
                workload.work_class,
                SwarmWhatIfWorkClass::Artifact | SwarmWhatIfWorkClass::Proof
            ) || workload.artifact_gib > 0
        })
}

fn remote_workers_block_required_work(scenario: &SwarmWhatIfScenario) -> bool {
    scenario.rch_workers_admissible == 0
        && scenario
            .workloads
            .iter()
            .any(|workload| workload.remote_required)
}

fn matching_workload_ids(
    workloads: &[SwarmWhatIfWorkload],
    predicate: impl Fn(&SwarmWhatIfWorkload) -> bool,
) -> Vec<String> {
    workloads
        .iter()
        .filter(|workload| predicate(workload))
        .map(|workload| workload.workload_id.clone())
        .collect()
}

fn low_priority_workload_ids(workloads: &[SwarmWhatIfWorkload]) -> Vec<String> {
    let mut ids = matching_workload_ids(workloads, |workload| {
        workload.priority == SwarmWhatIfPriority::Background
    });
    if ids.is_empty() {
        ids = noncritical_workload_ids(workloads);
    }
    ids
}

fn noncritical_workload_ids(workloads: &[SwarmWhatIfWorkload]) -> Vec<String> {
    matching_workload_ids(workloads, |workload| {
        workload.priority != SwarmWhatIfPriority::Critical
    })
}

fn admission_agent_cap(
    recommendation: SwarmWhatIfRecommendation,
    scenario: &SwarmWhatIfScenario,
    weighted_capacity_units: usize,
) -> Option<usize> {
    if !matches!(
        recommendation,
        SwarmWhatIfRecommendation::AdmitWithCap | SwarmWhatIfRecommendation::SplitWave
    ) {
        return None;
    }
    let average_weight = average_workload_weight(&scenario.workloads);
    let cap = weighted_capacity_units
        .checked_div(average_weight.max(1))
        .unwrap_or(0)
        .max(1)
        .min(scenario.agent_count());
    Some(cap)
}

fn average_workload_weight(workloads: &[SwarmWhatIfWorkload]) -> usize {
    let agent_count = workloads
        .iter()
        .map(|workload| workload.agent_count)
        .sum::<usize>();
    if agent_count == 0 {
        return 1;
    }
    weighted_demand_units(workloads)
        .checked_div(agent_count)
        .unwrap_or(1)
        .max(1)
}

fn starvation_risk(
    bounded_queue_estimate: usize,
    weighted_capacity_units: usize,
    memory_pressure_bps: u16,
    disk_pressure_bps: u16,
    reservation_conflicts: usize,
) -> SwarmWhatIfStarvationRisk {
    if memory_pressure_bps >= 9_500
        || disk_pressure_bps >= 9_500
        || (weighted_capacity_units == 0 && bounded_queue_estimate > 0)
    {
        return SwarmWhatIfStarvationRisk::Critical;
    }
    if bounded_queue_estimate > weighted_capacity_units.max(1) {
        return SwarmWhatIfStarvationRisk::High;
    }
    if bounded_queue_estimate > 0
        || reservation_conflicts > 0
        || memory_pressure_bps >= 8_000
        || disk_pressure_bps >= 8_000
    {
        return SwarmWhatIfStarvationRisk::Medium;
    }
    SwarmWhatIfStarvationRisk::Low
}

fn confidence_bps(
    input_freshness: SwarmWhatIfInputFreshness,
    starvation_risk: SwarmWhatIfStarvationRisk,
    has_blocker: bool,
) -> u16 {
    let freshness_score = match input_freshness {
        SwarmWhatIfInputFreshness::Fresh => 95u16,
        SwarmWhatIfInputFreshness::Partial => 75,
        SwarmWhatIfInputFreshness::Stale => 45,
    };
    let risk_penalty = match starvation_risk {
        SwarmWhatIfStarvationRisk::Low => 0u16,
        SwarmWhatIfStarvationRisk::Medium => 8,
        SwarmWhatIfStarvationRisk::High => 16,
        SwarmWhatIfStarvationRisk::Critical => 24,
    };
    let blocker_penalty = if has_blocker { 8 } else { 0 };
    freshness_score.saturating_sub(risk_penalty + blocker_penalty)
}

fn what_if_log(
    scenario: &SwarmWhatIfScenario,
    weighted_demand_units: usize,
    weighted_capacity_units: usize,
    bounded_queue_estimate: usize,
    recommendation: SwarmWhatIfRecommendation,
    starvation_risk: SwarmWhatIfStarvationRisk,
    first_blocker: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "scenario={} agents={} workloads={}",
            scenario.scenario_id,
            scenario.agent_count(),
            scenario.workloads.len()
        ),
        format!(
            "capacity_units={} demand_units={} queue_estimate={}",
            weighted_capacity_units, weighted_demand_units, bounded_queue_estimate
        ),
        format!(
            "pressures memory_bps={} disk_bps={} reservations={}",
            scenario.memory_pressure_bps,
            scenario.disk_pressure_bps,
            scenario.reservation_conflicts
        ),
        format!("recommendation={recommendation:?} starvation_risk={starvation_risk:?}"),
    ];
    if let Some(blocker) = first_blocker {
        lines.push(format!("first_blocker={blocker}"));
    }
    lines
}

fn no_duplicate_bead_claims(events: &[SwarmAgentRunEvent]) -> bool {
    let mut active_claims = BTreeSet::new();
    for event in events {
        if event.kind == SwarmAgentRunEventKind::BeadClaimed
            && !active_claims.insert(event.bead_id.as_str())
        {
            return false;
        }
    }
    true
}

fn no_false_green_agent_commits(events: &[SwarmAgentRunEvent]) -> bool {
    let mut proof_pass_agents = BTreeSet::new();
    let mut blocked_agents = BTreeSet::new();
    let mut commit_agents = BTreeSet::new();

    for event in events {
        match event.kind {
            SwarmAgentRunEventKind::RchProofPassed => {
                proof_pass_agents.insert(event.agent_index);
            }
            SwarmAgentRunEventKind::RchProofRemoteRefused
            | SwarmAgentRunEventKind::ValidationBlocked
            | SwarmAgentRunEventKind::AgentCrashed => {
                blocked_agents.insert(event.agent_index);
            }
            SwarmAgentRunEventKind::CommitRecorded => {
                commit_agents.insert(event.agent_index);
            }
            SwarmAgentRunEventKind::BeadClaimed
            | SwarmAgentRunEventKind::FileReserved
            | SwarmAgentRunEventKind::MailSent
            | SwarmAgentRunEventKind::RchProofStarted
            | SwarmAgentRunEventKind::RecoveryHandoffEmitted
            | SwarmAgentRunEventKind::FileReservationReleased => {}
        }
    }

    commit_agents.is_subset(&proof_pass_agents) && commit_agents.is_disjoint(&blocked_agents)
}

fn terminal_counts(runtime: &LabRuntime, tracked_tasks: &[TaskId]) -> (usize, usize) {
    let mut terminal = 0usize;
    let mut non_terminal = 0usize;

    for (_, record) in runtime.state.tasks_iter() {
        if !tracked_tasks.contains(&record.id) {
            continue;
        }
        if record.state.is_terminal() {
            terminal = terminal.saturating_add(1);
        } else {
            non_terminal = non_terminal.saturating_add(1);
        }
    }

    terminal = terminal.saturating_add(tracked_tasks.len().saturating_sub(terminal + non_terminal));
    (terminal, non_terminal)
}

fn spawn_pressure_task(
    runtime: &mut LabRuntime,
    region: RegionId,
    task_index: usize,
    lane: SwarmPressureLane,
    yield_points: usize,
) -> Result<TaskId, SwarmReplayError> {
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let mut digest = pressure_lane_digest(lane) ^ task_index as u64;
            for step in 0..yield_points {
                digest = digest
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(step as u64);
                yield_once().await;
            }
            digest
        })
        .map_err(|err| SwarmReplayError::TaskSpawnRejected {
            region_index: 0,
            task_index,
            reason: format!("{err:?}"),
        })?;
    Ok(task_id)
}

fn spawn_agent_run_task(
    runtime: &mut LabRuntime,
    region: RegionId,
    scenario: &SwarmAgentRunScenario,
    agent_index: usize,
    events: &Arc<Mutex<Vec<SwarmAgentRunEvent>>>,
) -> Result<TaskId, SwarmReplayError> {
    let scenario_id = scenario.scenario_id.clone();
    let seed = scenario.seed;
    let proof_command = swarm_agent_replay_command(scenario);
    let remote_refusal = scenario.rch_refusal_agent == Some(agent_index);
    let validation_blocker = scenario.validation_blocker_agent == Some(agent_index);
    let crash = scenario.crash_agent == Some(agent_index);
    let events_for_task = Arc::clone(events);

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                0,
                SwarmAgentRunEventKind::BeadClaimed,
                None,
                None,
                None,
            );
            yield_once().await;
            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                1,
                SwarmAgentRunEventKind::FileReserved,
                None,
                None,
                None,
            );
            yield_once().await;
            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                2,
                SwarmAgentRunEventKind::MailSent,
                None,
                None,
                None,
            );
            yield_once().await;

            if crash {
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    3,
                    SwarmAgentRunEventKind::AgentCrashed,
                    None,
                    Some("agent crashed before proof handoff"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    4,
                    SwarmAgentRunEventKind::RecoveryHandoffEmitted,
                    None,
                    Some("crash handoff emitted with replay seed and reserved files"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    5,
                    SwarmAgentRunEventKind::FileReservationReleased,
                    None,
                    None,
                    None,
                );
                return;
            }

            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                3,
                SwarmAgentRunEventKind::RchProofStarted,
                Some(proof_command.clone()),
                None,
                None,
            );
            yield_once().await;

            if remote_refusal {
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    4,
                    SwarmAgentRunEventKind::RchProofRemoteRefused,
                    Some(proof_command.clone()),
                    Some("rch remote required refused local fallback: no admissible worker"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    5,
                    SwarmAgentRunEventKind::RecoveryHandoffEmitted,
                    None,
                    Some("remote refusal handoff emitted with first blocker"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    6,
                    SwarmAgentRunEventKind::FileReservationReleased,
                    None,
                    None,
                    None,
                );
                return;
            }

            if validation_blocker {
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    4,
                    SwarmAgentRunEventKind::ValidationBlocked,
                    Some(proof_command.clone()),
                    Some("unrelated validation frontier blocked proof before closeout"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    5,
                    SwarmAgentRunEventKind::RecoveryHandoffEmitted,
                    None,
                    Some("validation blocker handoff emitted with proof command"),
                    None,
                );
                push_agent_event(
                    &events_for_task,
                    &scenario_id,
                    seed,
                    agent_index,
                    6,
                    SwarmAgentRunEventKind::FileReservationReleased,
                    None,
                    None,
                    None,
                );
                return;
            }

            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                4,
                SwarmAgentRunEventKind::RchProofPassed,
                Some(proof_command),
                None,
                None,
            );
            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                5,
                SwarmAgentRunEventKind::CommitRecorded,
                None,
                None,
                Some(agent_commit_id(seed, agent_index)),
            );
            push_agent_event(
                &events_for_task,
                &scenario_id,
                seed,
                agent_index,
                6,
                SwarmAgentRunEventKind::FileReservationReleased,
                None,
                None,
                None,
            );
        })
        .map_err(|err| SwarmReplayError::TaskSpawnRejected {
            region_index: 0,
            task_index: agent_index,
            reason: format!("{err:?}"),
        })?;
    Ok(task_id)
}

fn push_agent_event(
    events: &Arc<Mutex<Vec<SwarmAgentRunEvent>>>,
    scenario_id: &str,
    seed: u64,
    agent_index: usize,
    event_ordinal: u64,
    kind: SwarmAgentRunEventKind,
    proof_command: Option<String>,
    blocker: Option<&'static str>,
    commit_id: Option<String>,
) {
    let stable_sequence = (agent_index as u64)
        .saturating_mul(16)
        .saturating_add(event_ordinal);
    let artifact_refs = agent_event_artifacts(seed, agent_index, kind);
    events.lock().push(SwarmAgentRunEvent {
        stable_sequence,
        agent_index,
        agent_name: agent_label(agent_index),
        bead_id: agent_bead_id(agent_index),
        kind,
        file_frontier: agent_file_frontier(agent_index),
        proof_command,
        blocker: blocker.map(ToString::to_string),
        artifact_refs,
        commit_id,
        replay_pointer: format!(
            "swarm-agent-run://{scenario_id}/agent/{agent_index:03}/event/{stable_sequence:04}"
        ),
        mutates_real_services: false,
    });
}

const fn pressure_lane_digest(lane: SwarmPressureLane) -> u64 {
    match lane {
        SwarmPressureLane::Interactive => 0x1A7E_5A11,
        SwarmPressureLane::Proof => 0x9E57_000F,
        SwarmPressureLane::Cleanup => 0xC1EA_2026,
    }
}

fn agent_label(agent_index: usize) -> String {
    format!("agent-{agent_index:03}")
}

fn agent_bead_id(agent_index: usize) -> String {
    format!("asw-lab-{agent_index:03}")
}

fn agent_file_frontier(agent_index: usize) -> Vec<String> {
    vec![format!("src/lab/swarm_replay.rs#agent-{agent_index:03}")]
}

fn agent_commit_id(seed: u64, agent_index: usize) -> String {
    format!("simulated-main-{seed:016x}-{agent_index:03}")
}

fn swarm_agent_replay_command(scenario: &SwarmAgentRunScenario) -> String {
    format!(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_p6 cargo test -p asupersync --test swarm_replay_lab_contract deterministic_agent_run_lab_models_claim_reserve_proof_commit_blocker_and_recovery -- --exact --nocapture # scenario={} seed={:016x}",
        scenario.scenario_id, scenario.seed
    )
}

fn agent_event_artifacts(
    seed: u64,
    agent_index: usize,
    kind: SwarmAgentRunEventKind,
) -> Vec<String> {
    match kind {
        SwarmAgentRunEventKind::RchProofStarted
        | SwarmAgentRunEventKind::RchProofRemoteRefused
        | SwarmAgentRunEventKind::RchProofPassed
        | SwarmAgentRunEventKind::ValidationBlocked => {
            vec![format!(
                "target/lab-replay/swarm-agent-run/seed-{seed:016x}/agent-{agent_index:03}/proof.json"
            )]
        }
        SwarmAgentRunEventKind::RecoveryHandoffEmitted => {
            vec![format!(
                "target/lab-replay/swarm-agent-run/seed-{seed:016x}/agent-{agent_index:03}/handoff.json"
            )]
        }
        SwarmAgentRunEventKind::CommitRecorded => {
            vec![format!(
                "target/lab-replay/swarm-agent-run/seed-{seed:016x}/agent-{agent_index:03}/commit.json"
            )]
        }
        SwarmAgentRunEventKind::BeadClaimed
        | SwarmAgentRunEventKind::FileReserved
        | SwarmAgentRunEventKind::MailSent
        | SwarmAgentRunEventKind::AgentCrashed
        | SwarmAgentRunEventKind::FileReservationReleased => Vec::new(),
    }
}

fn sorted_disk_transitions(scenario: &SwarmPressureScenario) -> Vec<SwarmDiskPressureTransition> {
    let mut transitions = scenario.disk_pressure_transitions.clone();
    transitions.sort_by_key(|transition| (transition.at_step, transition.level));
    transitions
}

fn sorted_rch_events(scenario: &SwarmPressureScenario) -> Vec<SwarmRchWorkerEvent> {
    let mut events = scenario.rch_worker_events.clone();
    events.sort_by_key(|event| (event.at_step, event.kind, event.worker_delta));
    events
}

fn sorted_unique_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    sorted.sort();
    sorted.dedup();
    sorted
}

fn proof_lane_batch_key(request: &SwarmProofLaneRequest) -> String {
    format!(
        "target={};features={};surfaces={}",
        if request.target_dir.trim().is_empty() {
            "missing-target"
        } else {
            request.target_dir.trim()
        },
        sorted_unique_strings(&request.features).join("+"),
        sorted_unique_strings(&request.touched_surfaces).join("+")
    )
}

fn proof_lane_cache_key(request: &SwarmProofLaneRequest) -> String {
    format!(
        "head={};target={};features={};artifacts={};command={}",
        request
            .expected_head
            .as_deref()
            .or(request.observed_head.as_deref())
            .unwrap_or("missing-head"),
        if request.target_dir.trim().is_empty() {
            "missing-target"
        } else {
            request.target_dir.trim()
        },
        sorted_unique_strings(&request.features).join("+"),
        sorted_unique_strings(&request.expected_artifacts).join("+"),
        request.command.trim()
    )
}

fn proof_lane_local_fallback_marker_detected(request: &SwarmProofLaneRequest) -> bool {
    std::iter::once(request.command.as_str())
        .chain(
            request
                .transcript_markers
                .iter()
                .map(std::string::String::as_str),
        )
        .any(|text| {
            let lower = text.to_ascii_lowercase();
            lower.contains("[rch] local")
                || lower.contains("local fallback")
                || lower.contains("fallback to local")
                || lower.contains("executing locally")
                || lower.contains("rch_require_remote=0")
        })
}

fn append_swarm_proof_lane_report_list(lines: &mut Vec<String>, heading: &str, values: &[String]) {
    lines.push(format!("## {heading}"));
    lines.push(String::new());
    if values.is_empty() {
        lines.push("- none".to_string());
    } else {
        lines.extend(values.iter().map(|value| format!("- `{value}`")));
    }
    lines.push(String::new());
}

const fn proof_lane_closeout_label(decision: SwarmProofLaneAdmissionDecision) -> &'static str {
    match decision {
        SwarmProofLaneAdmissionDecision::Admit => "replay-backed",
        SwarmProofLaneAdmissionDecision::Defer
        | SwarmProofLaneAdmissionDecision::Batch
        | SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning => "advisory",
        SwarmProofLaneAdmissionDecision::TrappedCycleProven => "trapped-cycle-proven",
        SwarmProofLaneAdmissionDecision::Reject
        | SwarmProofLaneAdmissionDecision::Blocked
        | SwarmProofLaneAdmissionDecision::Malformed => "validation-blocked",
        SwarmProofLaneAdmissionDecision::StaleEvidence => "stale",
    }
}

fn proof_lane_report_freshness(plan: &SwarmProofLanePlan) -> &'static str {
    if matches!(
        plan.admission_decision,
        SwarmProofLaneAdmissionDecision::Malformed
    ) {
        return "malformed";
    }
    if plan.stale_head
        || plan.missing_target_dir
        || matches!(
            plan.admission_decision,
            SwarmProofLaneAdmissionDecision::StaleEvidence
        )
        || matches!(
            plan.target_dir_isolation_status,
            SwarmProofLaneTargetDirIsolationStatus::Missing
                | SwarmProofLaneTargetDirIsolationStatus::NotInCommand
                | SwarmProofLaneTargetDirIsolationStatus::ProvenanceMismatch
        )
        || matches!(
            plan.peer_reservation_overlap_status,
            SwarmProofLanePeerReservationOverlapStatus::StaleOrMalformed
        )
        || matches!(
            plan.trapped_cycle_witness_status,
            SwarmProofLaneTrappedCycleWitnessStatus::ReplayPending
        )
    {
        return "stale";
    }
    "fresh"
}

const fn proof_lane_decision_code(decision: SwarmProofLaneDecision) -> &'static str {
    match decision {
        SwarmProofLaneDecision::Ready => "ready",
        SwarmProofLaneDecision::RefreshStaleInputs => "refresh_stale_inputs",
        SwarmProofLaneDecision::RefuseUntilRemoteProof => "refuse_until_remote_proof",
    }
}

const fn proof_lane_admission_decision_code(
    decision: SwarmProofLaneAdmissionDecision,
) -> &'static str {
    match decision {
        SwarmProofLaneAdmissionDecision::Admit => "admit",
        SwarmProofLaneAdmissionDecision::Defer => "defer",
        SwarmProofLaneAdmissionDecision::Reject => "reject",
        SwarmProofLaneAdmissionDecision::Batch => "batch",
        SwarmProofLaneAdmissionDecision::Blocked => "blocked",
        SwarmProofLaneAdmissionDecision::StaleEvidence => "stale_evidence",
        SwarmProofLaneAdmissionDecision::Malformed => "malformed",
        SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning => "advisory_spectral_warning",
        SwarmProofLaneAdmissionDecision::TrappedCycleProven => "trapped_cycle_proven",
    }
}

fn proof_lane_stale_head(request: &SwarmProofLaneRequest) -> bool {
    let request_stale = request
        .expected_head
        .as_deref()
        .zip(request.observed_head.as_deref())
        .is_some_and(|(expected, observed)| {
            !expected.trim().is_empty() && !observed.trim().is_empty() && expected != observed
        });
    let provenance_stale = request
        .expected_head
        .as_deref()
        .zip(
            request
                .rch_provenance
                .as_ref()
                .map(|provenance| provenance.observed_head.as_str()),
        )
        .is_some_and(|(expected, observed)| {
            !expected.trim().is_empty() && !observed.trim().is_empty() && expected != observed
        });
    request_stale || provenance_stale
}

fn proof_lane_needs_feature_scope(command: &str) -> bool {
    let command = command.to_ascii_lowercase();
    command.contains("cargo test")
        || command.contains("cargo check")
        || command.contains("cargo clippy")
}

fn proof_lane_has_feature_scope(request: &SwarmProofLaneRequest) -> bool {
    !sorted_unique_strings(&request.features).is_empty()
        && (request.command.contains("--features")
            || request.command.contains("--all-features")
            || request.command.contains("--no-default-features"))
}

fn proof_lane_command_requires_remote(command: &str) -> bool {
    command.contains("RCH_REQUIRE_REMOTE=1") && command.contains("rch exec")
}

fn proof_lane_target_dir_isolation_status(
    request: &SwarmProofLaneRequest,
) -> SwarmProofLaneTargetDirIsolationStatus {
    if let Some(status) = request
        .atlas_context
        .as_ref()
        .and_then(|context| context.target_dir_isolation_status)
    {
        return status;
    }

    if request.target_dir.trim().is_empty() {
        return SwarmProofLaneTargetDirIsolationStatus::Missing;
    }
    if request.rch_provenance.as_ref().is_some_and(|provenance| {
        !provenance.target_dir.trim().is_empty() && provenance.target_dir != request.target_dir
    }) {
        return SwarmProofLaneTargetDirIsolationStatus::ProvenanceMismatch;
    }
    if request.command.contains(&request.target_dir) || request.command.contains("CARGO_TARGET_DIR")
    {
        SwarmProofLaneTargetDirIsolationStatus::Isolated
    } else {
        SwarmProofLaneTargetDirIsolationStatus::NotInCommand
    }
}

fn proof_lane_source_rows(request: &SwarmProofLaneRequest) -> Vec<String> {
    let mut rows = request.source_artifacts.clone();
    if let Some(context) = &request.atlas_context {
        rows.extend(context.source_rows.clone());
    }
    sorted_unique_owned(rows)
}

fn proof_lane_reason_codes(
    request: &SwarmProofLaneRequest,
    fallback_policy: SwarmProofLaneFallbackPolicy,
    target_dir_status: SwarmProofLaneTargetDirIsolationStatus,
    peer_reservation_status: SwarmProofLanePeerReservationOverlapStatus,
    trapped_cycle_witness_status: SwarmProofLaneTrappedCycleWitnessStatus,
    findings: &[SwarmProofLaneFinding],
) -> Vec<String> {
    let mut codes = Vec::new();
    if let Some(context) = &request.atlas_context {
        codes.extend(context.reason_codes.clone());
        if context.stale_evidence {
            codes.push("atlas_stale_evidence".to_string());
        }
        if context.malformed {
            codes.push("atlas_malformed_input".to_string());
        }
        if context.spectral_warning_advisory {
            codes.push("advisory_spectral_warning".to_string());
        }
        if let Some(saturation) = &context.worker_saturation {
            codes.push(format!("worker_saturation_{saturation}"));
        }
        if let Some(decision) = &context.batching_decision {
            codes.push(format!("batching_decision_{decision}"));
        }
    }

    codes.extend(findings.iter().map(|finding| finding.code.clone()));
    if request.remote_required {
        codes.push("remote_required_policy".to_string());
    }
    codes.push(format!(
        "fallback_policy_{}",
        proof_lane_fallback_policy_code(fallback_policy)
    ));
    codes.push(format!(
        "target_dir_{}",
        proof_lane_target_dir_status_code(target_dir_status)
    ));
    codes.push(format!(
        "peer_reservation_{}",
        proof_lane_peer_reservation_status_code(peer_reservation_status)
    ));
    codes.push(format!(
        "trapped_cycle_witness_{}",
        proof_lane_trapped_cycle_witness_status_code(trapped_cycle_witness_status)
    ));
    sorted_unique_owned(codes)
}

fn proof_lane_admission_decision(
    request: &SwarmProofLaneRequest,
    stale_head: bool,
    target_dir_status: SwarmProofLaneTargetDirIsolationStatus,
    peer_reservation_status: SwarmProofLanePeerReservationOverlapStatus,
    trapped_cycle_witness_status: SwarmProofLaneTrappedCycleWitnessStatus,
    findings: &[SwarmProofLaneFinding],
) -> SwarmProofLaneAdmissionDecision {
    let context = request.atlas_context.as_ref();
    if context.is_some_and(|context| context.malformed)
        || matches!(
            trapped_cycle_witness_status,
            SwarmProofLaneTrappedCycleWitnessStatus::Malformed
        )
        || proof_lane_has_any_finding(
            findings,
            &[
                "missing_lane_id",
                "missing_scenario_id",
                "missing_command",
                "missing_expected_artifact",
                "missing_claim_scope",
            ],
        )
    {
        return SwarmProofLaneAdmissionDecision::Malformed;
    }

    if matches!(
        peer_reservation_status,
        SwarmProofLanePeerReservationOverlapStatus::PeerOverlap
            | SwarmProofLanePeerReservationOverlapStatus::ActiveExclusiveConflict
    ) {
        return SwarmProofLaneAdmissionDecision::Blocked;
    }

    if stale_head
        || context.is_some_and(|context| context.stale_evidence)
        || matches!(
            target_dir_status,
            SwarmProofLaneTargetDirIsolationStatus::Missing
                | SwarmProofLaneTargetDirIsolationStatus::NotInCommand
                | SwarmProofLaneTargetDirIsolationStatus::ProvenanceMismatch
        )
        || matches!(
            peer_reservation_status,
            SwarmProofLanePeerReservationOverlapStatus::StaleOrMalformed
        )
        || matches!(
            trapped_cycle_witness_status,
            SwarmProofLaneTrappedCycleWitnessStatus::ReplayPending
        )
    {
        return SwarmProofLaneAdmissionDecision::StaleEvidence;
    }

    if proof_lane_has_any_finding(
        findings,
        &[
            "missing_remote_requirement",
            "missing_rch_provenance",
            "local_fallback_marker",
            "proof_not_green",
            "missing_feature_scope",
        ],
    ) {
        return SwarmProofLaneAdmissionDecision::Reject;
    }

    if matches!(
        trapped_cycle_witness_status,
        SwarmProofLaneTrappedCycleWitnessStatus::Proven
    ) {
        return SwarmProofLaneAdmissionDecision::TrappedCycleProven;
    }

    if context.is_some_and(|context| context.spectral_warning_advisory)
        || matches!(
            trapped_cycle_witness_status,
            SwarmProofLaneTrappedCycleWitnessStatus::RequiredMissing
        )
    {
        return SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning;
    }

    if context.is_some_and(proof_lane_context_prefers_batch) {
        return SwarmProofLaneAdmissionDecision::Batch;
    }
    if context.is_some_and(proof_lane_context_defers) {
        return SwarmProofLaneAdmissionDecision::Defer;
    }

    SwarmProofLaneAdmissionDecision::Admit
}

fn proof_lane_context_prefers_batch(context: &SwarmProofLaneAtlasAdmissionContext) -> bool {
    context
        .batching_decision
        .as_ref()
        .is_some_and(|decision| matches!(decision.as_str(), "prefer_warm_worker" | "admit_batch"))
}

fn proof_lane_context_defers(context: &SwarmProofLaneAtlasAdmissionContext) -> bool {
    context.batching_decision.as_ref().is_some_and(|decision| {
        matches!(
            decision.as_str(),
            "queue_low_memory"
                | "defer_worker_saturated"
                | "queue_disk_headroom"
                | "defer_non_large_host"
        )
    }) || context
        .worker_saturation
        .as_ref()
        .is_some_and(|saturation| {
            matches!(
                saturation.as_str(),
                "low_memory" | "worker_saturated" | "disk_constrained" | "non_large_host"
            )
        })
}

fn proof_lane_has_any_finding(findings: &[SwarmProofLaneFinding], codes: &[&str]) -> bool {
    findings
        .iter()
        .any(|finding| codes.contains(&finding.code.as_str()))
}

const fn proof_lane_fallback_policy_code(policy: SwarmProofLaneFallbackPolicy) -> &'static str {
    match policy {
        SwarmProofLaneFallbackPolicy::RemoteOnly => "remote_only",
        SwarmProofLaneFallbackPolicy::LocalAuthorized => "local_authorized",
        SwarmProofLaneFallbackPolicy::ReportOnly => "report_only",
    }
}

const fn proof_lane_target_dir_status_code(
    status: SwarmProofLaneTargetDirIsolationStatus,
) -> &'static str {
    match status {
        SwarmProofLaneTargetDirIsolationStatus::Isolated => "isolated",
        SwarmProofLaneTargetDirIsolationStatus::Missing => "missing",
        SwarmProofLaneTargetDirIsolationStatus::NotInCommand => "not_in_command",
        SwarmProofLaneTargetDirIsolationStatus::ProvenanceMismatch => "provenance_mismatch",
    }
}

const fn proof_lane_peer_reservation_status_code(
    status: SwarmProofLanePeerReservationOverlapStatus,
) -> &'static str {
    match status {
        SwarmProofLanePeerReservationOverlapStatus::Clear => "clear",
        SwarmProofLanePeerReservationOverlapStatus::PeerOverlap => "peer_overlap",
        SwarmProofLanePeerReservationOverlapStatus::ActiveExclusiveConflict => {
            "active_exclusive_conflict"
        }
        SwarmProofLanePeerReservationOverlapStatus::StaleOrMalformed => "stale_or_malformed",
    }
}

const fn proof_lane_trapped_cycle_witness_status_code(
    status: SwarmProofLaneTrappedCycleWitnessStatus,
) -> &'static str {
    match status {
        SwarmProofLaneTrappedCycleWitnessStatus::NotRequired => "not_required",
        SwarmProofLaneTrappedCycleWitnessStatus::RequiredMissing => "required_missing",
        SwarmProofLaneTrappedCycleWitnessStatus::ReplayPending => "replay_pending",
        SwarmProofLaneTrappedCycleWitnessStatus::Malformed => "malformed",
        SwarmProofLaneTrappedCycleWitnessStatus::Validated => "validated",
        SwarmProofLaneTrappedCycleWitnessStatus::Proven => "proven",
    }
}

fn add_proof_lane_finding(
    findings: &mut Vec<SwarmProofLaneFinding>,
    decision: &mut SwarmProofLaneDecision,
    candidate: SwarmProofLaneDecision,
    severity: SwarmProofLaneFindingSeverity,
    code: impl Into<String>,
    detail: impl Into<String>,
    action: impl Into<String>,
) {
    escalate_proof_lane_decision(decision, candidate);
    findings.push(SwarmProofLaneFinding {
        code: code.into(),
        detail: detail.into(),
        action: action.into(),
        severity,
    });
}

fn escalate_proof_lane_decision(
    decision: &mut SwarmProofLaneDecision,
    candidate: SwarmProofLaneDecision,
) {
    if proof_lane_decision_rank(candidate) > proof_lane_decision_rank(*decision) {
        *decision = candidate;
    }
}

const fn proof_lane_decision_rank(decision: SwarmProofLaneDecision) -> u8 {
    match decision {
        SwarmProofLaneDecision::Ready => 0,
        SwarmProofLaneDecision::RefreshStaleInputs => 1,
        SwarmProofLaneDecision::RefuseUntilRemoteProof => 2,
    }
}

fn disk_pressure_at_step(
    transitions: &[SwarmDiskPressureTransition],
    step: u64,
) -> SwarmDiskPressureLevel {
    let mut current = SwarmDiskPressureLevel::Green;
    for transition in transitions {
        if transition.at_step > step {
            break;
        }
        current = transition.level;
    }
    current
}

fn rch_workers_at_step(
    events: &[SwarmRchWorkerEvent],
    initial: usize,
    worker_count: usize,
    step: u64,
) -> usize {
    let mut current = initial.min(worker_count);
    for event in events {
        if event.at_step > step {
            break;
        }
        match event.kind {
            SwarmRchWorkerEventKind::Loss => {
                current = current.saturating_sub(event.worker_delta);
            }
            SwarmRchWorkerEventKind::Recovery => {
                current = current.saturating_add(event.worker_delta).min(worker_count);
            }
        }
    }
    current
}

fn shuffle_tasks(tasks: &mut [(TaskId, SwarmReplayEvent)], seed: u64) {
    let mut rng = DetRng::new(seed ^ 0x5A5A_F00D);
    for index in (1..tasks.len()).rev() {
        let swap_with = rng.next_usize(index + 1);
        tasks.swap(index, swap_with);
    }
}

struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_once() {
    YieldOnce { yielded: false }.await;
}
