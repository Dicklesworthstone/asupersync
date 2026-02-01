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
use crate::record::task::{TaskPhase, TaskState};
use crate::runtime::state::RuntimeState;
use crate::tracing_compat::{debug, info, trace, warn};
use crate::types::{ObligationId, Outcome, RegionId, TaskId, Time};
use std::collections::HashMap;
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
    /// Time since last poll (if applicable).
    pub time_since_last_poll: Option<Duration>,
    /// Whether a wake is pending.
    pub wake_pending: bool,
    /// Obligations held by this task.
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
}

/// Simplified task state for inspection (matches TaskState but serializable).
#[derive(Debug, Clone)]
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
    pub by_region: HashMap<RegionId, usize>,
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

    /// Get the current time from the timer driver, or ZERO if unavailable.
    fn current_time(&self) -> Time {
        self.state
            .timer_driver()
            .map(|d| d.now())
            .unwrap_or(Time::ZERO)
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
                .iter()
                .filter_map(|(_, record)| {
                    if record.holder == task_id {
                        Some(record.id)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        Some(TaskDetails {
            id: task.id,
            region_id: task.owner,
            state: TaskStateInfo::from(&task.state),
            phase: task.phase(),
            poll_count: task.total_polls,
            polls_remaining: task.polls_remaining,
            created_at: task.created_at,
            age,
            time_since_last_poll: None, // Would need wall-clock tracking
            wake_pending: task.wake_state.is_notified(),
            obligations,
            waiters: task.waiters.clone(),
        })
    }

    /// List all tasks with their details.
    #[must_use]
    pub fn list_tasks(&self) -> Vec<TaskDetails> {
        trace!("listing all tasks");
        self.state
            .tasks
            .iter()
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

    /// Find tasks that haven't been polled recently (potentially stuck).
    ///
    /// Note: This is heuristic-based since we don't track wall-clock poll times.
    /// It uses task age and poll count to estimate activity.
    #[must_use]
    pub fn find_stuck_tasks(&self, age_threshold: Duration) -> Vec<TaskDetails> {
        debug!(
            threshold_secs = age_threshold.as_secs(),
            "checking for stuck tasks"
        );

        let stuck: Vec<_> = self
            .list_active_tasks()
            .into_iter()
            .filter(|t| {
                // Heuristic: old tasks with no polls might be stuck
                t.age > age_threshold && !t.wake_pending
            })
            .collect();

        if !stuck.is_empty() {
            warn!(
                count = stuck.len(),
                threshold_secs = age_threshold.as_secs(),
                "potential stuck tasks detected"
            );
            for task in &stuck {
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

    /// Get a summary of all tasks.
    #[must_use]
    pub fn summary(&self) -> TaskSummary {
        let tasks = self.list_tasks();
        let mut by_region: HashMap<RegionId, usize> = HashMap::new();
        let mut created = 0;
        let mut running = 0;
        let mut cancelling = 0;
        let mut completed = 0;
        let mut stuck_count = 0;

        for task in &tasks {
            *by_region.entry(task.region_id).or_insert(0) += 1;

            match &task.state {
                TaskStateInfo::Created => created += 1,
                TaskStateInfo::Running => running += 1,
                TaskStateInfo::CancelRequested { .. }
                | TaskStateInfo::Cancelling { .. }
                | TaskStateInfo::Finalizing { .. } => cancelling += 1,
                TaskStateInfo::Completed { .. } => completed += 1,
            }

            // Count stuck tasks
            if task.age > self.config.stuck_task_threshold
                && !task.is_terminal()
                && !task.wake_pending
            {
                stuck_count += 1;
            }
        }

        let total_tasks = tasks.len();

        debug!(
            total = total_tasks,
            created = created,
            running = running,
            cancelling = cancelling,
            completed = completed,
            stuck = stuck_count,
            "task summary computed"
        );

        TaskSummary {
            total_tasks,
            created,
            running,
            cancelling,
            completed,
            by_region,
            stuck_count,
        }
    }

    /// Render task summary to console (if available).
    pub fn render_summary(&self) -> std::io::Result<()> {
        let console = match &self.console {
            Some(c) => c,
            None => return Ok(()),
        };

        let summary = self.summary();
        let stuck = self.find_stuck_tasks_default();

        let mut output = String::new();
        output.push_str("Task Inspector\n");
        output.push_str(&format!(
            "Total: {}  |  Running: {}  |  Cancelling: {}  |  Completed: {}  |  Stuck: {}\n",
            summary.total_tasks,
            summary.running,
            summary.cancelling,
            summary.completed,
            summary.stuck_count
        ));
        output.push_str(&"-".repeat(70));
        output.push('\n');

        // Region breakdown
        output.push_str("By Region:\n");
        for (region_id, count) in &summary.by_region {
            output.push_str(&format!("  {:?}: {} tasks\n", region_id, count));
        }

        // Stuck tasks section
        if !stuck.is_empty() {
            output.push_str(&"-".repeat(70));
            output.push('\n');
            output.push_str("POTENTIAL STUCK TASKS:\n");
            for stuck_task in &stuck {
                output.push_str(&format!(
                    "  {:?} in {:?} - {} for {:.1}s, {} polls\n",
                    stuck_task.id,
                    stuck_task.region_id,
                    stuck_task.state.name(),
                    stuck_task.age.as_secs_f64(),
                    stuck_task.poll_count
                ));
            }
        }

        console.print(&RawText(&output))
    }

    /// Render detailed task information to console.
    pub fn render_task_details(&self, task_id: TaskId) -> std::io::Result<()> {
        let console = match &self.console {
            Some(c) => c,
            None => return Ok(()),
        };

        let task = match self.inspect_task(task_id) {
            Some(t) => t,
            None => {
                let mut output = String::new();
                output.push_str(&format!("Task {:?} not found\n", task_id));
                return console.print(&RawText(&output));
            }
        };

        let mut output = String::new();
        output.push_str(&format!("Task Inspector: {:?}\n", task_id));
        output.push_str(&"-".repeat(50));
        output.push('\n');
        output.push_str(&format!("State:         {}\n", task.state.name()));
        output.push_str(&format!("Phase:         {:?}\n", task.phase));
        output.push_str(&format!("Region:        {:?}\n", task.region_id));
        output.push_str(&format!("Age:           {:.3}s\n", task.age.as_secs_f64()));
        output.push_str(&format!("Poll count:    {}\n", task.poll_count));
        output.push_str(&format!("Polls left:    {}\n", task.polls_remaining));
        output.push_str(&format!("Wake pending:  {}\n", task.wake_pending));

        if !task.obligations.is_empty() {
            output.push_str(&"-".repeat(50));
            output.push('\n');
            output.push_str("Obligations:\n");
            for ob_id in &task.obligations {
                output.push_str(&format!("  {:?}\n", ob_id));
            }
        }

        if !task.waiters.is_empty() {
            output.push_str(&"-".repeat(50));
            output.push('\n');
            output.push_str("Waiters:\n");
            for waiter_id in &task.waiters {
                output.push_str(&format!("  {:?}\n", waiter_id));
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
mod tests {
    use super::*;

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
}
