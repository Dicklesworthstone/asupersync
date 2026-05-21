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
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Stable schema version for swarm replay summaries.
pub const SWARM_REPLAY_SCHEMA_VERSION: &str = "asupersync.swarm-replay-lab.v1";

/// Stable schema version for swarm pressure summaries.
pub const SWARM_PRESSURE_SCHEMA_VERSION: &str = "asupersync.swarm-pressure-lab.v1";

const MAX_FIRST_SLICE_TASKS: usize = 10_000;

/// Deterministic workload knobs for a swarm replay lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayScenario {
    /// Stable scenario identifier used in logs and artifacts.
    pub scenario_id: String,
    /// Lab runtime seed. Same seed and same knobs must produce the same summary.
    pub seed: u64,
    /// Virtual workers modeled by [`LabConfig`].
    pub worker_count: usize,
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
            region_count: 2,
            tasks_per_region: 4,
            yields_per_task: 4,
            yield_jitter: 2,
            channel_capacity: 8,
            messages_per_task: 2,
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
        if self.region_count == 0 {
            return Err(SwarmReplayError::ZeroRegionCount);
        }
        if self.tasks_per_region == 0 {
            return Err(SwarmReplayError::ZeroTasksPerRegion);
        }
        if self.channel_capacity == 0 {
            return Err(SwarmReplayError::ZeroChannelCapacity);
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
    /// No interactive work was requested.
    ZeroInteractiveTasks,
    /// The interactive latency bound was zero.
    ZeroInteractiveLatencyBound,
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
            Self::ZeroInteractiveTasks => {
                f.write_str("interactive_tasks must be greater than zero")
            }
            Self::ZeroInteractiveLatencyBound => {
                f.write_str("interactive_latency_bound_steps must be greater than zero")
            }
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
    /// Maximum modeled channel backlog.
    pub channel_backlog_peak: usize,
    /// Total modeled artifact bytes emitted by normally completed tasks.
    pub artifact_bytes_emitted: usize,
    /// Scheduler steps run by `LabRuntime`.
    pub steps_delta: u64,
    /// Whether the runtime reached quiescence.
    pub quiescent: bool,
    /// Canonical trace fingerprint from the lab run report.
    pub trace_fingerprint: u64,
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
            let events_for_task = Arc::clone(&events);
            let outcomes_for_task = Arc::clone(&outcomes);
            let order_for_task = Arc::clone(&completion_order);
            let artifact_bytes = scenario.artifact_bytes_per_task;

            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    events_for_task.lock().push(SwarmReplayEvent {
                        kind: SwarmReplayEventKind::MessageReserved,
                        region_index,
                        task_index: Some(task_index),
                        global_task_index: Some(global_task_index),
                        queue_depth,
                        artifact_bytes: 0,
                    });

                    for _ in 0..yield_points {
                        let Some(cx) = Cx::current() else {
                            return;
                        };
                        if cx.checkpoint().is_err() {
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

    SwarmReplaySummary {
        schema_version: SWARM_REPLAY_SCHEMA_VERSION.to_string(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        region_count: scenario.region_count,
        task_count: scenario.task_count(),
        scheduled_task_count,
        cancellation_requests,
        terminal_task_count: terminal_counts.0,
        non_terminal_task_count: terminal_counts.1,
        channel_backlog_peak,
        artifact_bytes_emitted,
        steps_delta: report.steps_delta,
        quiescent: report.quiescent,
        trace_fingerprint: report.trace_fingerprint,
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

const fn pressure_lane_digest(lane: SwarmPressureLane) -> u64 {
    match lane {
        SwarmPressureLane::Interactive => 0x1A7E_5A11,
        SwarmPressureLane::Proof => 0x9E57_000F,
        SwarmPressureLane::Cleanup => 0xC1EA_2026,
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
