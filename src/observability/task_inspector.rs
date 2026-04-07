//! Task inspection and debugging for runtime diagnostics.
//!
//! This module provides detailed task state inspection, including await points,
//! waker information, and execution metrics for debugging and observability.
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
use crate::runtime::state::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{debug, info, trace, warn};
use crate::types::{ObligationId, Outcome, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the task inspector.
#[derive(Debug, Clone)]
pub struct TaskInspectorConfig {
    /// Age threshold for stuck task warnings (default: 30s).
    pub stuck_task_threshold: Duration,
    /// Whether to include obligations in task details.
    pub show_obligations: bool,
    /// Maximum number of recent events to include per task.
    pub max_event_history: usize,
    /// Whether to highlight stuck tasks in output.
    pub highlight_stuck_tasks: bool,
}

impl Default for TaskInspectorConfig {
    fn default() -> Self {
        Self {
            stuck_task_threshold: Duration::from_secs(30),
            show_obligations: true,
            max_event_history: 10,
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

    /// Set maximum event history per task.
    #[must_use]
    pub fn with_max_event_history(mut self, max: usize) -> Self {
        self.max_event_history = max;
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
    #[must_use]
    pub fn is_potentially_stuck(&self, age_threshold: Duration) -> bool {
        if self.is_terminal() || self.wake_pending {
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
    state: Arc<RuntimeState>,
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

    /// Get the current runtime time for observability.
    ///
    /// Live runtimes advance time through the timer driver, while timerless
    /// runtimes and many direct tests only move `RuntimeState::now`.
    /// Prefer the timer driver when present and fall back to the logical state
    /// clock otherwise so task ages remain meaningful in both modes.
    fn current_time(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(self.state.now, TimerDriverHandle::now)
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

        let task = self.state.task(task_id)?;
        let current_time = self.current_time();
        let age_nanos = current_time.duration_since(task.created_at);
        let age = Duration::from_nanos(age_nanos);

        // Collect obligations held by this task
        let obligations: Vec<ObligationId> = if self.config.show_obligations {
            self.state
                .obligations
                .sorted_pending_ids_for_holder(task_id)
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };

        let time_since_last_poll = Self::current_checkpoint_time_for_task(task).and_then(|now| {
            task.cx_inner.as_ref().and_then(|inner| {
                inner
                    .read()
                    .checkpoint_state
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
        self.state
            .tasks_iter()
            .filter_map(|(_, task)| self.inspect_task(task.id))
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
        let tasks = self.list_tasks();
        let summary = Self::summarize_tasks(&tasks, self.config.stuck_task_threshold);
        let wire_tasks = tasks.into_iter().map(TaskDetailsWire::from).collect();
        TaskConsoleWireSnapshot::new(
            self.current_time(),
            TaskSummaryWire::from(summary),
            wire_tasks,
        )
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
mod tests {
    use super::*;
    use crate::Budget;
    use crate::time::{TimerDriverHandle, VirtualClock};

    #[test]
    fn test_task_state_info_name() {
        assert_eq!(TaskStateInfo::Created.name(), "Created");
        assert_eq!(TaskStateInfo::Running.name(), "Running");
        assert_eq!(
            TaskStateInfo::CancelRequested {
                reason: "test".to_string()
            }
            .name(),
            "CancelRequested"
        );
        assert_eq!(
            TaskStateInfo::Cancelling {
                reason: "test".to_string()
            }
            .name(),
            "Cancelling"
        );
        assert_eq!(
            TaskStateInfo::Finalizing {
                reason: "test".to_string()
            }
            .name(),
            "Finalizing"
        );
        assert_eq!(
            TaskStateInfo::Completed {
                outcome: "Ok".to_string()
            }
            .name(),
            "Completed"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = TaskInspectorConfig::default();
        assert_eq!(config.stuck_task_threshold, Duration::from_secs(30));
        assert!(config.show_obligations);
        assert_eq!(config.max_event_history, 10);
        assert!(config.highlight_stuck_tasks);
    }

    #[test]
    fn test_config_builder() {
        let config = TaskInspectorConfig::default()
            .with_stuck_threshold(Duration::from_secs(60))
            .with_show_obligations(false)
            .with_max_event_history(20)
            .with_highlight_stuck_tasks(false);

        assert_eq!(config.stuck_task_threshold, Duration::from_secs(60));
        assert!(!config.show_obligations);
        assert_eq!(config.max_event_history, 20);
        assert!(!config.highlight_stuck_tasks);
    }

    #[test]
    fn test_summary_default() {
        let summary = TaskSummary::default();
        assert_eq!(summary.total_tasks, 0);
        assert_eq!(summary.created, 0);
        assert_eq!(summary.running, 0);
        assert_eq!(summary.cancelling, 0);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.stuck_count, 0);
        assert!(summary.by_region.is_empty());
    }

    #[test]
    fn test_task_details_is_terminal() {
        let created_details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Created,
            phase: TaskPhase::Created,
            poll_count: 0,
            polls_remaining: 100,
            created_at: Time::ZERO,
            age: Duration::ZERO,
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(!created_details.is_terminal());

        let completed_details = TaskDetails {
            state: TaskStateInfo::Completed {
                outcome: "Ok".to_string(),
            },
            ..created_details
        };
        assert!(completed_details.is_terminal());
    }

    #[test]
    fn test_task_details_is_running() {
        let running_details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 5,
            polls_remaining: 95,
            created_at: Time::ZERO,
            age: Duration::from_secs(1),
            time_since_last_poll: None,
            wake_pending: true,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(running_details.is_running());
        assert!(!running_details.is_terminal());
        assert!(!running_details.is_cancelling());
    }

    #[test]
    fn test_task_details_is_cancelling() {
        let cancel_requested = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::CancelRequested {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::CancelRequested,
            poll_count: 10,
            polls_remaining: 50,
            created_at: Time::ZERO,
            age: Duration::from_secs(5),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        assert!(cancel_requested.is_cancelling());

        let cancelling = TaskDetails {
            state: TaskStateInfo::Cancelling {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::Cancelling,
            ..cancel_requested.clone()
        };
        assert!(cancelling.is_cancelling());

        let finalizing = TaskDetails {
            state: TaskStateInfo::Finalizing {
                reason: "Timeout".to_string(),
            },
            phase: TaskPhase::Finalizing,
            ..cancel_requested
        };
        assert!(finalizing.is_cancelling());
    }

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn config_debug_clone() {
        let cfg = TaskInspectorConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("TaskInspectorConfig"));
    }

    #[test]
    fn task_state_info_debug_clone() {
        let s = TaskStateInfo::Running;
        let s2 = s;
        assert!(format!("{s2:?}").contains("Running"));
    }

    #[test]
    fn task_state_info_all_variants_debug() {
        let variants: Vec<TaskStateInfo> = vec![
            TaskStateInfo::Created,
            TaskStateInfo::Running,
            TaskStateInfo::CancelRequested {
                reason: "timeout".into(),
            },
            TaskStateInfo::Cancelling {
                reason: "timeout".into(),
            },
            TaskStateInfo::Finalizing {
                reason: "timeout".into(),
            },
            TaskStateInfo::Completed {
                outcome: "Ok".into(),
            },
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
            assert!(!v.name().is_empty());
        }
    }

    #[test]
    fn task_details_debug_clone() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Created,
            phase: TaskPhase::Created,
            poll_count: 0,
            polls_remaining: 100,
            created_at: Time::ZERO,
            age: Duration::ZERO,
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        let details2 = details;
        assert!(format!("{details2:?}").contains("TaskDetails"));
    }

    #[test]
    fn task_summary_debug_clone_default() {
        let summary = TaskSummary::default();
        let summary2 = summary;
        assert_eq!(summary2.total_tasks, 0);
        assert!(format!("{summary2:?}").contains("TaskSummary"));
    }

    #[test]
    fn task_summary_with_data() {
        let mut summary = TaskSummary {
            total_tasks: 10,
            running: 5,
            completed: 3,
            cancelling: 2,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::testing_default(), 10);
        assert_eq!(summary.by_region.len(), 1);
    }

    #[test]
    fn task_details_with_obligations_and_waiters() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 42,
            polls_remaining: 58,
            created_at: Time::ZERO,
            age: Duration::from_secs(10),
            time_since_last_poll: Some(Duration::from_millis(100)),
            wake_pending: true,
            obligations: vec![ObligationId::new_for_test(1, 0)],
            waiters: vec![TaskId::new_for_test(2, 0)],
        };
        assert!(details.is_running());
        assert!(!details.is_terminal());
        assert!(!details.obligations.is_empty());
        assert!(!details.waiters.is_empty());
    }

    #[test]
    fn task_details_stuck_heuristic_ignores_old_polled_task_without_idle_metadata() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 3,
            polls_remaining: 97,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
    }

    #[test]
    fn task_details_stuck_heuristic_uses_idle_metadata_when_available() {
        let details = TaskDetails {
            id: TaskId::testing_default(),
            region_id: RegionId::testing_default(),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 3,
            polls_remaining: 97,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: Some(Duration::from_secs(45)),
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        assert!(details.is_potentially_stuck(Duration::from_secs(30)));
    }

    #[test]
    fn wire_snapshot_round_trip_and_schema() {
        let summary = TaskSummaryWire {
            total_tasks: 2,
            created: 0,
            running: 1,
            cancelling: 1,
            completed: 0,
            stuck_count: 0,
            by_region: vec![TaskRegionCountWire {
                region_id: RegionId::new_for_test(1, 0),
                task_count: 2,
            }],
        };
        let first = TaskDetailsWire {
            id: TaskId::new_for_test(1, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 4,
            polls_remaining: 10,
            created_at: Time::from_nanos(100),
            age_nanos: 200,
            time_since_last_poll_nanos: Some(30),
            wake_pending: true,
            obligations: vec![ObligationId::new_for_test(2, 0)],
            waiters: vec![TaskId::new_for_test(3, 0)],
        };
        let second = TaskDetailsWire {
            id: TaskId::new_for_test(5, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::CancelRequested {
                reason: "Timeout".to_string(),
            },
            phase: "CancelRequested".to_string(),
            poll_count: 2,
            polls_remaining: 3,
            created_at: Time::from_nanos(80),
            age_nanos: 220,
            time_since_last_poll_nanos: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };

        let snapshot =
            TaskConsoleWireSnapshot::new(Time::from_nanos(999), summary, vec![second, first]);
        assert!(snapshot.has_expected_schema());
        assert_eq!(snapshot.schema_version, TASK_CONSOLE_WIRE_SCHEMA_V1);
        assert_eq!(snapshot.tasks[0].id, TaskId::new_for_test(1, 0));
        assert_eq!(snapshot.tasks[1].id, TaskId::new_for_test(5, 0));

        let encoded = snapshot.to_json().expect("wire snapshot must encode");
        let decoded =
            TaskConsoleWireSnapshot::from_json(&encoded).expect("wire snapshot must decode");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn details_wire_normalizes_collections_and_phase_name() {
        let details = TaskDetails {
            id: TaskId::new_for_test(10, 0),
            region_id: RegionId::new_for_test(1, 0),
            state: TaskStateInfo::Finalizing {
                reason: "Shutdown".to_string(),
            },
            phase: TaskPhase::Finalizing,
            poll_count: 7,
            polls_remaining: 9,
            created_at: Time::from_nanos(10),
            age: Duration::from_nanos(99),
            time_since_last_poll: Some(Duration::from_nanos(7)),
            wake_pending: false,
            obligations: vec![
                ObligationId::new_for_test(3, 0),
                ObligationId::new_for_test(1, 0),
            ],
            waiters: vec![TaskId::new_for_test(8, 0), TaskId::new_for_test(2, 0)],
        };

        let wire = TaskDetailsWire::from(details);
        assert_eq!(wire.phase, "Finalizing");
        assert_eq!(wire.age_nanos, 99);
        assert_eq!(wire.time_since_last_poll_nanos, Some(7));
        assert_eq!(wire.obligations[0], ObligationId::new_for_test(1, 0));
        assert_eq!(wire.obligations[1], ObligationId::new_for_test(3, 0));
        assert_eq!(wire.waiters[0], TaskId::new_for_test(2, 0));
        assert_eq!(wire.waiters[1], TaskId::new_for_test(8, 0));
    }

    #[test]
    fn format_summary_output_hides_stuck_section_when_highlight_disabled() {
        let mut summary = TaskSummary {
            total_tasks: 1,
            running: 1,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::new_for_test(7, 0), 1);
        let stuck = vec![TaskDetails {
            id: TaskId::new_for_test(11, 0),
            region_id: RegionId::new_for_test(7, 0),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 0,
            polls_remaining: 10,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        }];
        let task_label = format!("{:?}", stuck[0].id);

        let output = TaskInspector::format_summary_output(&summary, &stuck, false);
        assert!(output.contains("Stuck: 1"));
        assert!(!output.contains("POTENTIAL STUCK TASKS:"));
        assert!(!output.contains(&task_label));
    }

    #[test]
    fn format_summary_output_shows_stuck_section_when_highlight_enabled() {
        let mut summary = TaskSummary {
            total_tasks: 1,
            running: 1,
            stuck_count: 1,
            ..TaskSummary::default()
        };
        summary.by_region.insert(RegionId::new_for_test(7, 0), 1);
        let stuck = vec![TaskDetails {
            id: TaskId::new_for_test(11, 0),
            region_id: RegionId::new_for_test(7, 0),
            state: TaskStateInfo::Running,
            phase: TaskPhase::Running,
            poll_count: 0,
            polls_remaining: 10,
            created_at: Time::ZERO,
            age: Duration::from_secs(90),
            time_since_last_poll: None,
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        }];
        let task_label = format!("{:?}", stuck[0].id);

        let output = TaskInspector::format_summary_output(&summary, &stuck, true);
        assert!(output.contains("POTENTIAL STUCK TASKS:"));
        assert!(output.contains(&task_label));
    }

    #[test]
    fn inspector_uses_runtime_logical_time_without_timer_driver() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        state.now = Time::from_secs(65);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(65));

        let summary = inspector.summary();
        assert_eq!(summary.stuck_count, 1);

        let wire = inspector.wire_snapshot();
        assert_eq!(wire.generated_at, Time::from_secs(65));
    }

    #[test]
    fn inspector_does_not_flag_old_polled_tasks_without_last_poll_duration() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let task = state.task_mut(task_id).expect("task record");
        task.state = TaskState::Running;
        task.increment_polls();
        state.now = Time::from_secs(65);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.poll_count, 1);
        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
        assert!(inspector.find_stuck_tasks_default().is_empty());
        assert_eq!(inspector.summary().stuck_count, 0);
    }

    #[test]
    fn inspector_prefers_timer_driver_when_available() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        state.now = Time::from_secs(5);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(8)),
        )));

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(8));

        let wire = inspector.wire_snapshot();
        assert_eq!(wire.generated_at, Time::from_secs(8));
    }

    #[test]
    fn inspector_reports_checkpoint_idle_time_from_timer_driver() {
        let mut state = RuntimeState::new();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(3)));
        state.now = Time::from_secs(3);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let cx = {
            let task = state.task_mut(task_id).expect("task record");
            task.state = TaskState::Running;
            task.increment_polls();
            task.cx.as_ref().expect("task cx").clone()
        };
        cx.checkpoint().expect("checkpoint");
        clock.advance_to(Time::from_secs(8));

        let inspector = TaskInspector::with_config(
            Arc::new(state),
            None,
            TaskInspectorConfig::default().with_stuck_threshold(Duration::from_secs(4)),
        );
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.time_since_last_poll, Some(Duration::from_secs(5)));
        assert!(details.is_potentially_stuck(Duration::from_secs(4)));
        assert_eq!(inspector.summary().stuck_count, 1);
        assert_eq!(
            inspector.wire_snapshot().tasks[0].time_since_last_poll_nanos,
            Some(duration_to_nanos(Duration::from_secs(5)))
        );
    }

    #[test]
    fn inspector_does_not_mix_wall_clock_checkpoint_idle_without_timer_driver() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let task = state.task_mut(task_id).expect("task record");
        task.state = TaskState::Running;
        task.increment_polls();
        if let Some(inner) = &task.cx_inner {
            inner.write().checkpoint_state.record_at(Time::from_secs(3));
        }
        state.now = Time::from_secs(5);

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.age, Duration::from_secs(5));
        assert_eq!(details.time_since_last_poll, None);
        assert!(!details.is_potentially_stuck(Duration::from_secs(30)));
        assert_eq!(inspector.summary().stuck_count, 0);
        assert_eq!(
            inspector.wire_snapshot().tasks[0].time_since_last_poll_nanos,
            None
        );
    }

    #[test]
    fn inspector_does_not_mix_checkpoint_time_after_late_timer_driver_attachment() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let cx = {
            let task = state.task_mut(task_id).expect("task record");
            task.state = TaskState::Running;
            task.increment_polls();
            task.cx.as_ref().expect("task cx").clone()
        };
        cx.checkpoint().expect("checkpoint");
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(60)),
        )));

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.time_since_last_poll, None);
        assert_eq!(inspector.summary().stuck_count, 0);
    }

    #[test]
    fn inspector_only_reports_only_pending_obligations() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let pending = state
            .create_obligation(crate::record::ObligationKind::IoOp, task_id, root, None)
            .expect("create pending obligation");
        let committed = state
            .create_obligation(crate::record::ObligationKind::Ack, task_id, root, None)
            .expect("create committed obligation");
        state
            .commit_obligation(committed)
            .expect("commit obligation");
        let aborted = state
            .create_obligation(crate::record::ObligationKind::Lease, task_id, root, None)
            .expect("create aborted obligation");
        state
            .abort_obligation(aborted, crate::record::ObligationAbortReason::Cancel)
            .expect("abort obligation");

        let inspector = TaskInspector::new(Arc::new(state), None);
        let details = inspector.inspect_task(task_id).expect("task exists");
        assert_eq!(details.obligations, vec![pending]);
    }
}
