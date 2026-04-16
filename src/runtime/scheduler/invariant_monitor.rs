//! Three-Lane Scheduler Invariant Verification Matrix
//!
//! Comprehensive runtime verification framework that ensures the three-lane scheduler
//! maintains all its invariants across state transitions, work-stealing operations,
//! and cancellation scenarios.
//!
//! The scheduler maintains complex invariants around:
//! - Priority ordering (cancel > timed > ready)
//! - Fairness (work distribution across workers)
//! - Task ownership and lifecycle consistency
//! - Work-stealing correctness
//! - Queue consistency and integrity

use crate::types::{TaskId, Time};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Configuration for scheduler invariant monitoring.
#[derive(Debug, Clone)]
pub struct InvariantConfig {
    /// Enable real-time invariant verification (production-safe).
    pub enable_verification: bool,
    /// Enable detailed violation diagnostics (higher overhead).
    pub enable_diagnostics: bool,
    /// Maximum number of violations to track before dropping oldest.
    pub max_tracked_violations: usize,
    /// Threshold for detecting priority inversion (milliseconds).
    pub priority_inversion_threshold_ms: u64,
    /// Threshold for detecting task starvation (milliseconds).
    pub starvation_threshold_ms: u64,
    /// Threshold for detecting load imbalance (ratio).
    pub load_imbalance_threshold: f64,
    /// Enable stack trace capture for violations (expensive).
    pub enable_stack_traces: bool,
}

impl Default for InvariantConfig {
    fn default() -> Self {
        Self {
            enable_verification: true,
            enable_diagnostics: false,
            max_tracked_violations: 1000,
            priority_inversion_threshold_ms: 10,
            starvation_threshold_ms: 100,
            load_imbalance_threshold: 2.0,
            enable_stack_traces: false,
        }
    }
}

/// Categories of scheduler invariants that must be maintained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvariantCategory {
    /// Priority ordering: cancel > timed > ready
    PriorityOrdering,
    /// Fairness: equitable resource distribution
    Fairness,
    /// Task lifecycle: proper state transitions
    TaskLifecycle,
    /// Queue consistency: internal data structure integrity
    QueueConsistency,
    /// Work-stealing: correctness of steal operations
    WorkStealing,
    /// Cancellation: proper cleanup of cancelled tasks
    Cancellation,
    /// Load balancing: work distribution across workers
    LoadBalancing,
}

/// Specific scheduler invariant that can be violated.
#[derive(Debug, Clone, PartialEq)]
pub enum SchedulerInvariant {
    /// A task appears in multiple queues simultaneously
    TaskInMultipleQueues {
        /// ID of the task found in multiple queues.
        task_id: TaskId,
        /// Number of queues the task was found in.
        queue_count: usize,
    },
    /// Higher priority task scheduled after lower priority
    PriorityOrderViolation {
        /// ID of the higher priority task that was scheduled late.
        high_priority_task: TaskId,
        /// Priority level of the high priority task.
        high_priority: u8,
        /// ID of the lower priority task that was scheduled first.
        low_priority_task: TaskId,
        /// Priority level of the low priority task.
        low_priority: u8,
    },
    /// Task starved for excessive time
    TaskStarvation {
        /// ID of the starved task.
        task_id: TaskId,
        /// How long the task has been waiting (in milliseconds).
        wait_time_ms: u64,
        /// Position of the task in the queue.
        queue_position: usize,
    },
    /// Worker load severely imbalanced
    LoadImbalance {
        /// ID of the overloaded worker.
        overloaded_worker: usize,
        /// ID of the underloaded worker.
        underloaded_worker: usize,
        /// Ratio of load imbalance between workers.
        load_ratio: f64,
    },
    /// Work-stealing caused double execution
    WorkStealingDoubleExecution {
        /// ID of the task that was executed twice.
        task_id: TaskId,
        /// Worker that originally owned the task.
        original_worker: usize,
        /// Worker that stole and re-executed the task.
        stealing_worker: usize,
    },
    /// Cancelled task not properly drained
    CancelledTaskLeak {
        /// ID of the leaked cancelled task.
        task_id: TaskId,
        /// Name of the queue where the task remains.
        queue_name: String,
        /// Time since cancellation in milliseconds.
        time_since_cancel_ms: u64,
    },
    /// Queue depth metric doesn't match actual content
    QueueDepthMismatch {
        /// Name of the queue with the mismatch.
        queue_name: String,
        /// Depth reported by metrics.
        reported_depth: usize,
        /// Actual depth measured by counting.
        actual_depth: usize,
    },
    /// Task state transition is invalid
    InvalidStateTransition {
        /// ID of the task with invalid transition.
        task_id: TaskId,
        /// State the task was transitioning from.
        from_state: String,
        /// State the task was transitioning to.
        to_state: String,
    },
}

impl SchedulerInvariant {
    /// Returns the category this invariant belongs to.
    pub fn category(&self) -> InvariantCategory {
        match self {
            Self::PriorityOrderViolation { .. } => InvariantCategory::PriorityOrdering,
            Self::TaskStarvation { .. } | Self::LoadImbalance { .. } => InvariantCategory::Fairness,
            Self::InvalidStateTransition { .. } => InvariantCategory::TaskLifecycle,
            Self::TaskInMultipleQueues { .. } | Self::QueueDepthMismatch { .. } => {
                InvariantCategory::QueueConsistency
            }
            Self::WorkStealingDoubleExecution { .. } => InvariantCategory::WorkStealing,
            Self::CancelledTaskLeak { .. } => InvariantCategory::Cancellation,
        }
    }

    /// Returns the severity level (0=low, 1=medium, 2=high, 3=critical).
    pub fn severity(&self) -> u8 {
        match self {
            Self::QueueDepthMismatch { .. } => 1, // Medium: metrics issue
            Self::TaskStarvation { .. } => 2,     // High: performance issue
            Self::LoadImbalance { .. } => 2,      // High: performance issue
            Self::PriorityOrderViolation { .. } => 2, // High: correctness issue
            Self::CancelledTaskLeak { .. } => 2,  // High: resource leak
            Self::TaskInMultipleQueues { .. } => 3, // Critical: corruption
            Self::WorkStealingDoubleExecution { .. } => 3, // Critical: data race
            Self::InvalidStateTransition { .. } => 3, // Critical: state corruption
        }
    }

    /// Returns a human-readable description of the violation.
    pub fn description(&self) -> String {
        match self {
            Self::TaskInMultipleQueues {
                task_id,
                queue_count,
            } => {
                format!(
                    "Task {:?} found in {} queues simultaneously",
                    task_id, queue_count
                )
            }
            Self::PriorityOrderViolation {
                high_priority_task,
                high_priority,
                low_priority_task,
                low_priority,
            } => {
                format!(
                    "Priority violation: task {:?} (priority {}) scheduled after task {:?} (priority {})",
                    low_priority_task, low_priority, high_priority_task, high_priority
                )
            }
            Self::TaskStarvation {
                task_id,
                wait_time_ms,
                queue_position,
            } => {
                format!(
                    "Task {:?} starved for {}ms at queue position {}",
                    task_id, wait_time_ms, queue_position
                )
            }
            Self::LoadImbalance {
                overloaded_worker,
                underloaded_worker,
                load_ratio,
            } => {
                format!(
                    "Load imbalance: worker {} has {:.2}x load of worker {}",
                    overloaded_worker, load_ratio, underloaded_worker
                )
            }
            Self::WorkStealingDoubleExecution {
                task_id,
                original_worker,
                stealing_worker,
            } => {
                format!(
                    "Task {:?} executed on both worker {} and worker {} (double execution)",
                    task_id, original_worker, stealing_worker
                )
            }
            Self::CancelledTaskLeak {
                task_id,
                queue_name,
                time_since_cancel_ms,
            } => {
                format!(
                    "Cancelled task {:?} still in {} after {}ms",
                    task_id, queue_name, time_since_cancel_ms
                )
            }
            Self::QueueDepthMismatch {
                queue_name,
                reported_depth,
                actual_depth,
            } => {
                format!(
                    "Queue {} reports depth {} but contains {} items",
                    queue_name, reported_depth, actual_depth
                )
            }
            Self::InvalidStateTransition {
                task_id,
                from_state,
                to_state,
            } => {
                format!(
                    "Task {:?} invalid transition from {} to {}",
                    task_id, from_state, to_state
                )
            }
        }
    }
}

/// Detailed information about an invariant violation.
#[derive(Debug, Clone)]
pub struct InvariantViolation {
    /// The specific invariant that was violated.
    pub invariant: SchedulerInvariant,
    /// Timestamp when the violation was detected.
    pub timestamp: Time,
    /// Worker ID where the violation was detected (if applicable).
    pub worker_id: Option<usize>,
    /// Call stack when violation was detected (if enabled).
    pub stack_trace: Option<String>,
    /// Additional context about the violation.
    pub context: HashMap<String, String>,
}

/// Statistics about invariant violations by category.
#[derive(Debug, Clone, Default)]
pub struct InvariantStats {
    /// Total violations detected by category.
    pub violations_by_category: HashMap<InvariantCategory, u64>,
    /// Total violations detected by severity.
    pub violations_by_severity: [u64; 4], // [low, medium, high, critical]
    /// Most recent violation timestamp.
    pub last_violation_time: Option<Time>,
    /// Number of workers currently being monitored.
    pub monitored_workers: usize,
    /// Total scheduler operations monitored.
    pub operations_monitored: u64,
    /// Average overhead of monitoring (nanoseconds per operation).
    pub avg_monitoring_overhead_ns: u64,
}

/// Task tracking state for invariant verification.
#[derive(Debug, Clone)]
struct TaskInvariantState {
    /// Current queue(s) the task is in.
    queues: HashSet<String>,
    /// Task priority.
    priority: u8,
    /// Time when task was first enqueued.
    enqueue_time: Time,
    /// Last time task was updated.
    last_update: Time,
    /// Current lifecycle state.
    lifecycle_state: String,
    /// Worker that owns this task (for local tasks).
    owner_worker: Option<usize>,
    /// Whether task has been cancelled.
    is_cancelled: bool,
}

/// Queue state snapshot for consistency verification.
#[derive(Debug, Clone)]
pub struct QueueSnapshot {
    /// Queue identifier.
    pub name: String,
    /// Reported depth from queue metrics.
    pub reported_depth: usize,
    /// Actual tasks found in queue.
    pub actual_tasks: Vec<TaskId>,
    /// Priority range in queue (min, max).
    pub priority_range: Option<(u8, u8)>,
    /// Time range of enqueued tasks (oldest, newest).
    pub time_range: Option<(Time, Time)>,
}

/// Snapshot of a tracked task in the invariant monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedTaskSnapshot {
    /// Task identifier.
    pub task_id: TaskId,
    /// Queues currently containing the task.
    pub queues: Vec<String>,
    /// Task priority captured at enqueue time.
    pub priority: u8,
    /// Time when the task was first enqueued.
    pub enqueue_time: Time,
    /// Last time the task state changed.
    pub last_update: Time,
    /// Current lifecycle state string.
    pub lifecycle_state: String,
    /// Worker that owns the task, when known.
    pub owner_worker: Option<usize>,
    /// Whether the task has been cancelled.
    pub is_cancelled: bool,
}

/// Worker load state for load balancing verification.
#[derive(Debug, Clone)]
pub struct WorkerLoadSnapshot {
    /// Worker ID.
    pub worker_id: usize,
    /// Number of tasks in local queues.
    pub local_queue_depth: usize,
    /// Number of tasks currently executing.
    pub executing_count: usize,
    /// Total tasks processed recently.
    pub recent_task_count: u64,
    /// Average task execution time.
    pub avg_execution_time_ms: f64,
}

/// Comprehensive scheduler invariant monitoring framework.
#[derive(Debug)]
pub struct SchedulerInvariantMonitor {
    /// Configuration for monitoring behavior.
    config: InvariantConfig,
    /// Tracked violations with timestamps.
    violations: VecDeque<InvariantViolation>,
    /// Current state of tracked tasks.
    task_states: HashMap<TaskId, TaskInvariantState>,
    /// Statistics by violation category and severity.
    stats: InvariantStats,
    /// Total operations monitored for overhead calculation.
    operations_count: AtomicU64,
    /// Total monitoring overhead in nanoseconds.
    total_overhead_ns: AtomicU64,
    /// Timestamp of last cleanup operation.
    last_cleanup: Option<Time>,
}

impl SchedulerInvariantMonitor {
    /// Creates a new invariant monitor with the given configuration.
    pub fn new(config: InvariantConfig) -> Self {
        Self {
            config,
            violations: VecDeque::new(),
            task_states: HashMap::new(),
            stats: InvariantStats::default(),
            operations_count: AtomicU64::new(0),
            total_overhead_ns: AtomicU64::new(0),
            last_cleanup: None,
        }
    }

    /// Creates a new invariant monitor with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(InvariantConfig::default())
    }

    /// Records a task being enqueued in a specific queue.
    pub fn record_task_enqueue(
        &mut self,
        task_id: TaskId,
        queue_name: &str,
        priority: u8,
        timestamp: Time,
    ) {
        if !self.config.enable_verification {
            return;
        }

        let start = std::time::Instant::now();

        let should_record_violation = {
            let task_state =
                self.task_states
                    .entry(task_id)
                    .or_insert_with(|| TaskInvariantState {
                        queues: HashSet::new(),
                        priority,
                        enqueue_time: timestamp,
                        last_update: timestamp,
                        lifecycle_state: "enqueued".to_string(),
                        owner_worker: None,
                        is_cancelled: false,
                    });

            let already_queued = !task_state.queues.is_empty();
            task_state.queues.insert(queue_name.to_string());
            task_state.last_update = timestamp;

            if already_queued {
                Some(task_state.queues.len())
            } else {
                None
            }
        };

        if let Some(queue_count) = should_record_violation {
            self.record_violation(
                SchedulerInvariant::TaskInMultipleQueues {
                    task_id,
                    queue_count,
                },
                timestamp,
                None,
            );
        }

        self.update_monitoring_overhead(start.elapsed());
    }

    /// Records a task being dequeued from a specific queue.
    pub fn record_task_dequeue(&mut self, task_id: TaskId, queue_name: &str, timestamp: Time) {
        if !self.config.enable_verification {
            return;
        }

        let start = std::time::Instant::now();

        if let Some(task_state) = self.task_states.get_mut(&task_id) {
            task_state.queues.remove(queue_name);
            task_state.last_update = timestamp;

            if task_state.queues.is_empty() {
                task_state.lifecycle_state = "executing".to_string();
            }
        }

        self.update_monitoring_overhead(start.elapsed());
    }

    /// Records a task being cancelled.
    pub fn record_task_cancel(&mut self, task_id: TaskId, timestamp: Time) {
        if !self.config.enable_verification {
            return;
        }

        if let Some(task_state) = self.task_states.get_mut(&task_id) {
            task_state.is_cancelled = true;
            task_state.lifecycle_state = "cancelled".to_string();
            task_state.last_update = timestamp;
        }
    }

    /// Records a task execution completing.
    pub fn record_task_complete(&mut self, task_id: TaskId, worker_id: usize, timestamp: Time) {
        if !self.config.enable_verification {
            return;
        }

        let leaked_queues = {
            if let Some(task_state) = self.task_states.get_mut(&task_id) {
                let leaked = if !task_state.queues.is_empty() && !task_state.is_cancelled {
                    let time_since_cancel = timestamp
                        .as_nanos()
                        .saturating_sub(task_state.last_update.as_nanos())
                        / 1_000_000;
                    Some((task_state.queues.clone(), time_since_cancel))
                } else {
                    None
                };

                task_state.lifecycle_state = "completed".to_string();
                task_state.last_update = timestamp;
                leaked
            } else {
                None
            }
        };

        if let Some((queues, time_since_cancel_ms)) = leaked_queues {
            for queue_name in queues {
                self.record_violation(
                    SchedulerInvariant::CancelledTaskLeak {
                        task_id,
                        queue_name,
                        time_since_cancel_ms,
                    },
                    timestamp,
                    Some(worker_id),
                );
            }
        }
    }

    /// Verifies priority ordering between two tasks.
    pub fn verify_priority_ordering(
        &mut self,
        first_task: TaskId,
        first_priority: u8,
        second_task: TaskId,
        second_priority: u8,
        timestamp: Time,
    ) {
        if !self.config.enable_verification {
            return;
        }

        // Higher priority (lower number) should be scheduled first
        if first_priority > second_priority {
            self.record_violation(
                SchedulerInvariant::PriorityOrderViolation {
                    high_priority_task: second_task,
                    high_priority: second_priority,
                    low_priority_task: first_task,
                    low_priority: first_priority,
                },
                timestamp,
                None,
            );
        }
    }

    /// Verifies queue consistency against a queue snapshot.
    pub fn verify_queue_consistency(&mut self, snapshot: &QueueSnapshot, timestamp: Time) {
        if !self.config.enable_verification {
            return;
        }

        let start = std::time::Instant::now();

        // Check reported vs actual depth
        if snapshot.reported_depth != snapshot.actual_tasks.len() {
            self.record_violation(
                SchedulerInvariant::QueueDepthMismatch {
                    queue_name: snapshot.name.clone(),
                    reported_depth: snapshot.reported_depth,
                    actual_depth: snapshot.actual_tasks.len(),
                },
                timestamp,
                None,
            );
        }

        // Check for starvation based on time range
        if let Some((oldest_time, _)) = snapshot.time_range {
            let wait_time_ms =
                timestamp.as_nanos().saturating_sub(oldest_time.as_nanos()) / 1_000_000;
            if wait_time_ms > self.config.starvation_threshold_ms {
                // Find the oldest task for detailed reporting
                if let Some(&oldest_task) = snapshot.actual_tasks.first() {
                    self.record_violation(
                        SchedulerInvariant::TaskStarvation {
                            task_id: oldest_task,
                            wait_time_ms,
                            queue_position: 0,
                        },
                        timestamp,
                        None,
                    );
                }
            }
        }

        self.update_monitoring_overhead(start.elapsed());
    }

    /// Verifies load balancing across workers.
    pub fn verify_load_balance(&mut self, worker_loads: &[WorkerLoadSnapshot], timestamp: Time) {
        if !self.config.enable_verification || worker_loads.len() < 2 {
            return;
        }

        let start = std::time::Instant::now();

        // Find min and max loaded workers
        let min_worker = worker_loads
            .iter()
            .min_by_key(|w| w.local_queue_depth)
            .unwrap();
        let max_worker = worker_loads
            .iter()
            .max_by_key(|w| w.local_queue_depth)
            .unwrap();

        if min_worker.local_queue_depth > 0 {
            let load_ratio =
                max_worker.local_queue_depth as f64 / min_worker.local_queue_depth as f64;

            if load_ratio > self.config.load_imbalance_threshold {
                self.record_violation(
                    SchedulerInvariant::LoadImbalance {
                        overloaded_worker: max_worker.worker_id,
                        underloaded_worker: min_worker.worker_id,
                        load_ratio,
                    },
                    timestamp,
                    Some(max_worker.worker_id),
                );
            }
        }

        self.update_monitoring_overhead(start.elapsed());
    }

    /// Records an invariant violation.
    fn record_violation(
        &mut self,
        invariant: SchedulerInvariant,
        timestamp: Time,
        worker_id: Option<usize>,
    ) {
        let severity = invariant.severity();
        let category = invariant.category();

        // Update statistics
        *self
            .stats
            .violations_by_category
            .entry(category)
            .or_insert(0) += 1;
        self.stats.violations_by_severity[severity as usize] += 1;
        self.stats.last_violation_time = Some(timestamp);

        // Create violation record
        let violation = InvariantViolation {
            invariant: invariant.clone(),
            timestamp,
            worker_id,
            stack_trace: if self.config.enable_stack_traces {
                Some(format!("{:?}", std::backtrace::Backtrace::capture()))
            } else {
                None
            },
            context: HashMap::new(),
        };

        // Log the violation
        if self.config.enable_diagnostics {
            eprintln!(
                "[SCHEDULER-INVARIANT] VIOLATION: {}",
                invariant.description()
            );
            if let Some(worker) = worker_id {
                eprintln!("  Worker: {}", worker);
            }
            eprintln!("  Timestamp: {:?}", timestamp);
            eprintln!(
                "  Severity: {}",
                match severity {
                    0 => "Low",
                    1 => "Medium",
                    2 => "High",
                    3 => "Critical",
                    _ => "Unknown",
                }
            );
        }

        // Store violation (with bounds checking)
        self.violations.push_back(violation);
        while self.violations.len() > self.config.max_tracked_violations {
            self.violations.pop_front();
        }
    }

    /// Updates monitoring overhead statistics.
    fn update_monitoring_overhead(&self, elapsed: Duration) {
        self.operations_count.fetch_add(1, Ordering::Relaxed);
        self.total_overhead_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Returns current statistics about invariant violations.
    pub fn stats(&self) -> InvariantStats {
        let operations = self.operations_count.load(Ordering::Relaxed);
        let total_overhead = self.total_overhead_ns.load(Ordering::Relaxed);

        InvariantStats {
            violations_by_category: self.stats.violations_by_category.clone(),
            violations_by_severity: self.stats.violations_by_severity,
            last_violation_time: self.stats.last_violation_time,
            monitored_workers: self.stats.monitored_workers,
            operations_monitored: operations,
            avg_monitoring_overhead_ns: if operations > 0 {
                total_overhead / operations
            } else {
                0
            },
        }
    }

    /// Returns all recorded violations.
    pub fn violations(&self) -> &VecDeque<InvariantViolation> {
        &self.violations
    }

    /// Returns violations by category.
    pub fn violations_by_category(&self, category: InvariantCategory) -> Vec<&InvariantViolation> {
        self.violations
            .iter()
            .filter(|v| v.invariant.category() == category)
            .collect()
    }

    /// Returns violations by severity level.
    pub fn violations_by_severity(&self, severity: u8) -> Vec<&InvariantViolation> {
        self.violations
            .iter()
            .filter(|v| v.invariant.severity() == severity)
            .collect()
    }

    /// Returns snapshots of all currently tracked tasks.
    pub fn tracked_tasks(&self) -> Vec<TrackedTaskSnapshot> {
        let mut tasks = self
            .task_states
            .iter()
            .map(|(task_id, state)| {
                let mut queues = state.queues.iter().cloned().collect::<Vec<_>>();
                queues.sort();
                TrackedTaskSnapshot {
                    task_id: *task_id,
                    queues,
                    priority: state.priority,
                    enqueue_time: state.enqueue_time,
                    last_update: state.last_update,
                    lifecycle_state: state.lifecycle_state.clone(),
                    owner_worker: state.owner_worker,
                    is_cancelled: state.is_cancelled,
                }
            })
            .collect::<Vec<_>>();
        tasks.sort_by_key(|task| task.task_id);
        tasks
    }

    /// Cleans up old task states and violations to prevent memory growth.
    pub fn cleanup_old_data(&mut self, current_time: Time, max_age: Duration) {
        let cutoff_time = Time::from_nanos(
            current_time
                .as_nanos()
                .saturating_sub(max_age.as_nanos() as u64),
        );

        // Clean up old task states
        self.task_states
            .retain(|_, state| state.last_update.as_nanos() >= cutoff_time.as_nanos());

        // Clean up old violations
        self.violations
            .retain(|violation| violation.timestamp.as_nanos() >= cutoff_time.as_nanos());

        self.last_cleanup = Some(current_time);
    }

    /// Returns true if monitoring is enabled and functioning.
    pub fn is_enabled(&self) -> bool {
        self.config.enable_verification
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &InvariantConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_monitor_basic_operations() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::from(42);

        // Test basic enqueue/dequeue
        monitor.record_task_enqueue(task_id, "ready_queue", 1, now);
        assert_eq!(monitor.task_states.len(), 1);
        assert!(monitor.violations.is_empty());

        monitor.record_task_dequeue(task_id, "ready_queue", now);
        assert!(monitor.violations.is_empty());

        monitor.record_task_complete(task_id, 0, now);
        assert!(monitor.violations.is_empty());
    }

    #[test]
    fn test_invariant_violations_detected() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::from(42);

        // Test double enqueue violation
        monitor.record_task_enqueue(task_id, "ready_queue", 1, now);
        monitor.record_task_enqueue(task_id, "timed_queue", 1, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::TaskInMultipleQueues {
                task_id: tid,
                queue_count,
            } => {
                assert_eq!(*tid, task_id);
                assert_eq!(*queue_count, 2);
            }
            _ => panic!("Expected TaskInMultipleQueues violation"),
        }
    }

    #[test]
    fn test_priority_ordering_violations() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        // Test priority violation (higher number = lower priority)
        monitor.verify_priority_ordering(TaskId::from(1), 5, TaskId::from(2), 3, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::PriorityOrderViolation {
                high_priority_task,
                high_priority,
                low_priority_task,
                low_priority,
            } => {
                assert_eq!(*high_priority_task, TaskId::from(2));
                assert_eq!(*high_priority, 3);
                assert_eq!(*low_priority_task, TaskId::from(1));
                assert_eq!(*low_priority, 5);
            }
            _ => panic!("Expected PriorityOrderViolation"),
        }
    }

    #[test]
    fn test_queue_consistency_verification() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        let snapshot = QueueSnapshot {
            name: "test_queue".to_string(),
            reported_depth: 5,
            actual_tasks: vec![TaskId::from(1), TaskId::from(2), TaskId::from(3)],
            priority_range: Some((1, 3)),
            time_range: Some((Time::from_nanos(500), now)),
        };

        monitor.verify_queue_consistency(&snapshot, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::QueueDepthMismatch {
                queue_name,
                reported_depth,
                actual_depth,
            } => {
                assert_eq!(queue_name, "test_queue");
                assert_eq!(*reported_depth, 5);
                assert_eq!(*actual_depth, 3);
            }
            _ => panic!("Expected QueueDepthMismatch violation"),
        }
    }

    #[test]
    fn test_load_balance_verification() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        let worker_loads = vec![
            WorkerLoadSnapshot {
                worker_id: 0,
                local_queue_depth: 10,
                executing_count: 2,
                recent_task_count: 100,
                avg_execution_time_ms: 5.0,
            },
            WorkerLoadSnapshot {
                worker_id: 1,
                local_queue_depth: 2,
                executing_count: 1,
                recent_task_count: 20,
                avg_execution_time_ms: 4.0,
            },
        ];

        monitor.verify_load_balance(&worker_loads, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::LoadImbalance {
                overloaded_worker,
                underloaded_worker,
                load_ratio,
            } => {
                assert_eq!(*overloaded_worker, 0);
                assert_eq!(*underloaded_worker, 1);
                assert!((*load_ratio - 5.0).abs() < 0.1);
            }
            _ => panic!("Expected LoadImbalance violation"),
        }
    }

    #[test]
    fn test_statistics_tracking() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        // Generate some violations
        monitor.verify_priority_ordering(TaskId::from(1), 5, TaskId::from(2), 3, now);
        monitor.verify_priority_ordering(TaskId::from(3), 7, TaskId::from(4), 2, now);

        let stats = monitor.stats();
        assert_eq!(
            stats.violations_by_category[&InvariantCategory::PriorityOrdering],
            2
        );
        assert_eq!(stats.violations_by_severity[2], 2); // High severity
        assert_eq!(stats.last_violation_time, Some(now));
    }

    #[test]
    fn test_cleanup_old_data() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let old_time = Time::from_nanos(1000);
        let new_time = Time::from_nanos(5000);

        // Add old task state
        monitor.record_task_enqueue(TaskId::from(1), "queue", 1, old_time);

        // Add old violation
        monitor.verify_priority_ordering(TaskId::from(2), 5, TaskId::from(3), 3, old_time);

        assert_eq!(monitor.task_states.len(), 1);
        assert_eq!(monitor.violations.len(), 1);

        // Clean up data older than 2000ns
        monitor.cleanup_old_data(new_time, Duration::from_nanos(2000));

        assert_eq!(monitor.task_states.len(), 0);
        assert_eq!(monitor.violations.len(), 0);
    }

    #[test]
    fn test_tracked_task_snapshots_expose_internal_state() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let enqueue_time = Time::from_nanos(1000);
        let task_id = TaskId::from(7);

        monitor.record_task_enqueue(task_id, "ready_queue", 3, enqueue_time);
        if let Some(state) = monitor.task_states.get_mut(&task_id) {
            state.owner_worker = Some(2);
        }
        monitor.record_task_cancel(task_id, Time::from_nanos(1500));

        let snapshots = monitor.tracked_tasks();
        assert_eq!(snapshots.len(), 1);

        let snapshot = &snapshots[0];
        assert_eq!(snapshot.task_id, task_id);
        assert_eq!(snapshot.queues, vec!["ready_queue".to_string()]);
        assert_eq!(snapshot.priority, 3);
        assert_eq!(snapshot.enqueue_time, enqueue_time);
        assert_eq!(snapshot.last_update, Time::from_nanos(1500));
        assert_eq!(snapshot.lifecycle_state, "cancelled");
        assert_eq!(snapshot.owner_worker, Some(2));
        assert!(snapshot.is_cancelled);
    }
}
