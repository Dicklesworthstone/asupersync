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
use crate::types::{Budget, CancelReason, RegionId, TaskId};
use crate::util::DetRng;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Stable schema version for swarm replay summaries.
pub const SWARM_REPLAY_SCHEMA_VERSION: &str = "asupersync.swarm-replay-lab.v1";

/// Stable schema version for swarm pressure summaries.
pub const SWARM_PRESSURE_SCHEMA_VERSION: &str = "asupersync.swarm-pressure-lab.v1";

/// Stable schema version for deterministic agent-run summaries.
pub const SWARM_AGENT_RUN_SCHEMA_VERSION: &str = "asupersync.swarm-agent-run-lab.v1";

/// Stable schema version for swarm what-if admission plans.
pub const SWARM_WHAT_IF_PLAN_SCHEMA_VERSION: &str = "asupersync.swarm-what-if-plan.v1";

/// Stable schema version for compaction-safe swarm handoff verification.
pub const SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION: &str =
    "asupersync.swarm-handoff-verification.v1";

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
    /// Task ordinal within the region when the event is task-local.
    pub task_index: Option<usize>,
    /// Global task ordinal when the event is task-local.
    pub global_task_index: Option<usize>,
    /// Modeled queue depth after this event.
    pub queue_depth: usize,
    /// Modeled artifact bytes associated with this event.
    pub artifact_bytes: usize,
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

    let scenario_root = runtime.state.create_root_region(Budget::INFINITE);

    for region_index in 0..scenario.region_count {
        let region = runtime
            .state
            .create_child_region(scenario_root, Budget::INFINITE)
            .map_err(|err| SwarmReplayError::RegionCreateRejected {
                region_index,
                reason: format!("{err:?}"), // ubs:ignore - error path only
            })?;
        region_ids.push(region);

        for task_index in 0..scenario.tasks_per_region {
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
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth: semaphore_permits,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::PoolSlotCheckedOut,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth: pool_slots,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::MessageReserved,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::TimerAdvanced,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
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
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
                                queue_depth: messages_per_task,
                                artifact_bytes: 0,
                            });
                            events_for_task.lock().push(SwarmReplayEvent {
                                kind: SwarmReplayEventKind::ObligationAborted,
                                region_index,
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
                                queue_depth: obligations_per_task,
                                artifact_bytes: 0,
                            });
                            events_for_task.lock().push(SwarmReplayEvent {
                                kind: SwarmReplayEventKind::CancelObserved,
                                region_index,
                                task_index: Some(task_index),
                                global_task_index: Some(global_task_index),
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
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth: messages_per_task,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::ObligationCommitted,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth: obligations_per_task,
                        artifact_bytes: 0,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::ArtifactEmitted,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth,
                        artifact_bytes,
                    });
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::Completed,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
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
                    task_index: Some(task_index),
                    global_task_index: Some(global_task_index),
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
    if let Some(cancel_after_steps) = scenario.cancel_after_steps {
        for _ in 0..cancel_after_steps {
            runtime.step_for_test();
        }

        for (region_index, region) in region_ids.into_iter().enumerate() {
            let tasks = runtime.state.cancel_request(
                region,
                &CancelReason::user("swarm replay cascade"),
                None,
            );
            cancellation_requests = cancellation_requests.saturating_add(tasks.len());
            events.lock().push(SwarmReplayEvent {
                kind: SwarmReplayEventKind::CancellationRequested,
                region_index,
                task_index: None,
                global_task_index: None,
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
    let terminal_counts = terminal_counts(&runtime, &tracked_tasks);
    let mut event_log = events.lock().clone();
    let mut task_outcomes = outcomes.lock().clone();
    let completion_order = completion_order.lock().clone();

    event_log.sort_by_key(|event| {
        (
            event.region_index,
            event.global_task_index.unwrap_or(usize::MAX),
            event.kind,
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
    let channel_reservations = task_count.saturating_mul(scenario.messages_per_task);
    let channel_commits = completed_tasks.saturating_mul(scenario.messages_per_task);
    let channel_aborts = channel_reservations.saturating_sub(channel_commits);
    let semaphore_acquires = task_count.saturating_mul(scenario.semaphore_permits_per_task);
    let semaphore_releases = semaphore_acquires;
    let pool_checkouts = task_count.saturating_mul(scenario.pool_slots_per_task);
    let pool_checkins = pool_checkouts;
    let total_obligations = task_count.saturating_mul(scenario.obligations_per_task);
    let obligation_commits = completed_tasks.saturating_mul(scenario.obligations_per_task);
    let obligation_aborts = total_obligations.saturating_sub(obligation_commits);
    let timer_registrations = task_count;
    let timer_wakeups = task_count.saturating_mul(scenario.timer_ticks_per_task);
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
