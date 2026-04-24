//! Scheduler Priority Inversion Oracle
//!
//! Detects priority inversions where high-priority tasks are blocked by
//! low-priority tasks, either directly through resource contention or
//! indirectly through dependency chains.
//!
//! Priority inversions violate scheduling guarantees and can cause
//! unpredictable latency spikes in real-time systems.

use crate::types::TaskId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Detects and reports priority inversion violations in the scheduler.
#[derive(Debug)]
pub struct PriorityInversionOracle {
    /// Configuration for the oracle.
    config: PriorityInversionConfig,
    /// Current state of the oracle.
    state: Arc<Mutex<PriorityInversionState>>,
}

/// Configuration for priority inversion detection.
#[derive(Debug, Clone)]
pub struct PriorityInversionConfig {
    /// Minimum duration to consider a priority inversion significant.
    pub min_inversion_duration: Duration,
    /// Maximum number of inversions to track simultaneously.
    pub max_tracked_inversions: usize,
    /// Whether to enable priority inheritance tracking.
    pub track_priority_inheritance: bool,
    /// Whether to enable transitive blocking detection.
    pub detect_transitive_blocking: bool,
    /// Threshold for reporting statistics.
    pub stats_reporting_interval: Duration,
}

impl Default for PriorityInversionConfig {
    fn default() -> Self {
        Self {
            min_inversion_duration: Duration::from_millis(1),
            max_tracked_inversions: 1000,
            track_priority_inheritance: true,
            detect_transitive_blocking: true,
            stats_reporting_interval: Duration::from_secs(10),
        }
    }
}

/// Internal state of the priority inversion oracle.
#[derive(Debug)]
struct PriorityInversionState {
    /// Active task information.
    active_tasks: HashMap<TaskId, TaskInfo>,
    /// Resource locks currently held.
    resource_locks: HashMap<ResourceId, ResourceLockInfo>,
    /// Active priority inversions being tracked.
    active_inversions: HashMap<InversionId, PriorityInversion>,
    /// Statistics since last reset.
    statistics: PriorityInversionStatistics,
    /// Last time statistics were reported.
    last_stats_report: Instant,
    /// Next available inversion ID.
    next_inversion_id: u64,
}

/// Information about an active task.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TaskInfo {
    /// Task identifier.
    pub task_id: TaskId,
    /// Current priority level.
    pub priority: Priority,
    /// Original priority (before inheritance).
    pub original_priority: Priority,
    /// Current state of the task.
    pub state: TaskState,
    /// Time when task was spawned.
    pub spawn_time: Instant,
    /// Time when task started running (if applicable).
    pub start_time: Option<Instant>,
    /// Resources currently held by this task.
    pub held_resources: HashSet<ResourceId>,
    /// Resources this task is waiting for.
    pub waiting_for: HashSet<ResourceId>,
}

/// Task priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Cooperative priority (lowest).
    Cooperative = 0,
    /// Normal priority.
    Normal = 1,
    /// High priority (highest).
    High = 2,
}

/// Current state of a task in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is spawned but not yet scheduled.
    Spawned,
    /// Task is waiting for resources.
    Blocked,
    /// Task is currently running.
    Running,
    /// Task has completed.
    Completed,
    /// Task has been cancelled.
    Cancelled,
}

/// Identifier for a resource (mutex, channel, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceId(pub u64);

/// Information about a resource lock.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ResourceLockInfo {
    /// Resource identifier.
    pub resource_id: ResourceId,
    /// Task currently holding the lock.
    pub holder: TaskId,
    /// Time when the lock was acquired.
    pub acquire_time: Instant,
    /// Queue of tasks waiting for this resource.
    pub wait_queue: VecDeque<TaskId>,
}

/// Unique identifier for a priority inversion instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InversionId(pub u64);

/// A detected priority inversion.
#[derive(Debug, Clone)]
pub struct PriorityInversion {
    /// Unique identifier for this inversion.
    pub inversion_id: InversionId,
    /// High-priority task being blocked.
    pub blocked_task: TaskId,
    /// Priority of the blocked task.
    pub blocked_priority: Priority,
    /// Low-priority task causing the blocking.
    pub blocking_task: TaskId,
    /// Priority of the blocking task.
    pub blocking_priority: Priority,
    /// Resource involved in the inversion.
    pub resource_id: ResourceId,
    /// Time when the inversion started.
    pub start_time: Instant,
    /// Duration of the inversion (if resolved).
    pub duration: Option<Duration>,
    /// Type of priority inversion detected.
    pub inversion_type: InversionType,
    /// Chain of blocking if transitive.
    pub blocking_chain: Vec<TaskId>,
}

/// Types of priority inversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InversionType {
    /// Direct inversion: high-priority task blocked by low-priority task.
    Direct,
    /// Transitive inversion: blocking chain through multiple tasks.
    Transitive,
    /// Priority inheritance failure.
    InheritanceFailure,
}

/// Statistics about priority inversions.
#[derive(Debug, Clone, Default)]
pub struct PriorityInversionStatistics {
    /// Total number of inversions detected.
    pub total_inversions: u64,
    /// Number of direct inversions.
    pub direct_inversions: u64,
    /// Number of transitive inversions.
    pub transitive_inversions: u64,
    /// Number of inheritance failures.
    pub inheritance_failures: u64,
    /// Total time spent in inversions.
    pub total_inversion_duration: Duration,
    /// Maximum inversion duration observed.
    pub max_inversion_duration: Duration,
    /// Average inversion duration.
    pub avg_inversion_duration: Duration,
    /// Number of currently active inversions.
    pub active_inversion_count: u64,
}

impl PriorityInversionOracle {
    /// Create a new priority inversion oracle.
    #[must_use]
    pub fn new(config: PriorityInversionConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(PriorityInversionState {
                active_tasks: HashMap::new(),
                resource_locks: HashMap::new(),
                active_inversions: HashMap::new(),
                statistics: PriorityInversionStatistics::default(),
                last_stats_report: Instant::now(),
                next_inversion_id: 1,
            })),
        }
    }

    /// Create oracle with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PriorityInversionConfig::default())
    }

    /// Record a task spawn event.
    pub fn on_task_spawn(&self, task_id: TaskId, priority: Priority) {
        let mut state = self.state.lock().unwrap();

        let task_info = TaskInfo {
            task_id,
            priority,
            original_priority: priority,
            state: TaskState::Spawned,
            spawn_time: Instant::now(),
            start_time: None,
            held_resources: HashSet::new(),
            waiting_for: HashSet::new(),
        };

        state.active_tasks.insert(task_id, task_info);
    }

    /// Record a task starting execution.
    pub fn on_task_start(&self, task_id: TaskId) {
        let mut state = self.state.lock().unwrap();

        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.state = TaskState::Running;
            task_info.start_time = Some(Instant::now());
        }
    }

    /// Record a task completing.
    pub fn on_task_complete(&self, task_id: TaskId) {
        let mut state = self.state.lock().unwrap();

        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.state = TaskState::Completed;

            // Release all resources held by this task
            let held_resources: Vec<_> = task_info.held_resources.iter().copied().collect();
            for resource_id in held_resources {
                self.release_resource_internal(&mut state, task_id, resource_id);
            }
        }

        // Check for resolved inversions
        self.check_resolved_inversions(&mut state);
    }

    /// Record a resource acquisition.
    pub fn on_resource_acquire(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut state = self.state.lock().unwrap();

        // Update task info
        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.held_resources.insert(resource_id);
            task_info.waiting_for.remove(&resource_id);

            if task_info.state == TaskState::Blocked {
                task_info.state = TaskState::Running;
            }
        }

        // Update resource lock info
        let lock_info = ResourceLockInfo {
            resource_id,
            holder: task_id,
            acquire_time: Instant::now(),
            wait_queue: VecDeque::new(),
        };
        state.resource_locks.insert(resource_id, lock_info);

        // Check for resolved inversions
        self.check_resolved_inversions(&mut state);
    }

    /// Record a task waiting for a resource.
    pub fn on_resource_wait(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut state = self.state.lock().unwrap();

        // Update task info
        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.waiting_for.insert(resource_id);
            task_info.state = TaskState::Blocked;
        }

        // Add to wait queue
        if let Some(lock_info) = state.resource_locks.get_mut(&resource_id) {
            lock_info.wait_queue.push_back(task_id);
        }

        // Check for new priority inversions
        self.detect_priority_inversions(&mut state, task_id, resource_id);
    }

    /// Record a resource release.
    pub fn on_resource_release(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut state = self.state.lock().unwrap();
        self.release_resource_internal(&mut state, task_id, resource_id);
        self.check_resolved_inversions(&mut state);
    }

    /// Internal resource release implementation.
    fn release_resource_internal(
        &self,
        state: &mut PriorityInversionState,
        task_id: TaskId,
        resource_id: ResourceId,
    ) {
        // Update task info
        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.held_resources.remove(&resource_id);
        }

        // Remove resource lock
        state.resource_locks.remove(&resource_id);
    }

    /// Detect new priority inversions.
    fn detect_priority_inversions(
        &self,
        state: &mut PriorityInversionState,
        waiting_task: TaskId,
        resource_id: ResourceId,
    ) {
        let waiting_task_info = match state.active_tasks.get(&waiting_task) {
            Some(info) => info.clone(),
            None => return,
        };

        let lock_info = match state.resource_locks.get(&resource_id) {
            Some(info) => info.clone(),
            None => return,
        };

        let holder_task_info = match state.active_tasks.get(&lock_info.holder) {
            Some(info) => info.clone(),
            None => return,
        };

        // Check for direct priority inversion
        if waiting_task_info.priority > holder_task_info.priority {
            let inversion_id = InversionId(state.next_inversion_id);
            state.next_inversion_id += 1;

            let inversion = PriorityInversion {
                inversion_id,
                blocked_task: waiting_task,
                blocked_priority: waiting_task_info.priority,
                blocking_task: lock_info.holder,
                blocking_priority: holder_task_info.priority,
                resource_id,
                start_time: Instant::now(),
                duration: None,
                inversion_type: InversionType::Direct,
                blocking_chain: vec![lock_info.holder],
            };

            state.active_inversions.insert(inversion_id, inversion);
            state.statistics.total_inversions += 1;
            state.statistics.direct_inversions += 1;
            state.statistics.active_inversion_count += 1;

            // Apply priority inheritance if enabled
            if self.config.track_priority_inheritance {
                self.apply_priority_inheritance(
                    state,
                    lock_info.holder,
                    waiting_task_info.priority,
                );
            }
        }

        // Check for transitive inversions if enabled
        if self.config.detect_transitive_blocking {
            self.detect_transitive_inversions(state, waiting_task, resource_id);
        }
    }

    /// Detect transitive priority inversions.
    fn detect_transitive_inversions(
        &self,
        state: &mut PriorityInversionState,
        waiting_task: TaskId,
        _resource_id: ResourceId,
    ) {
        // Build blocking chain
        let mut blocking_chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current_task = waiting_task;

        while let Some(task_info) = state.active_tasks.get(&current_task) {
            if visited.contains(&current_task) {
                break; // Cycle detection
            }
            visited.insert(current_task);

            // Find what this task is blocked on
            if let Some(&blocking_resource) = task_info.waiting_for.iter().next() {
                if let Some(lock_info) = state.resource_locks.get(&blocking_resource) {
                    blocking_chain.push(lock_info.holder);
                    current_task = lock_info.holder;
                } else {
                    break;
                }
            } else {
                break;
            }

            if blocking_chain.len() > 10 {
                break; // Prevent excessive chain length
            }
        }

        // Check if we have a transitive inversion
        if blocking_chain.len() > 1 {
            let waiting_task_info = state.active_tasks.get(&waiting_task).unwrap();
            let final_blocker_info = state
                .active_tasks
                .get(blocking_chain.last().unwrap())
                .unwrap();

            if waiting_task_info.priority > final_blocker_info.priority {
                let inversion_id = InversionId(state.next_inversion_id);
                state.next_inversion_id += 1;

                let inversion = PriorityInversion {
                    inversion_id,
                    blocked_task: waiting_task,
                    blocked_priority: waiting_task_info.priority,
                    blocking_task: *blocking_chain.last().unwrap(),
                    blocking_priority: final_blocker_info.priority,
                    resource_id: ResourceId(0), // Multiple resources involved
                    start_time: Instant::now(),
                    duration: None,
                    inversion_type: InversionType::Transitive,
                    blocking_chain,
                };

                state.active_inversions.insert(inversion_id, inversion);
                state.statistics.total_inversions += 1;
                state.statistics.transitive_inversions += 1;
                state.statistics.active_inversion_count += 1;
            }
        }
    }

    /// Apply priority inheritance to prevent inversion.
    fn apply_priority_inheritance(
        &self,
        state: &mut PriorityInversionState,
        holder_task: TaskId,
        inherited_priority: Priority,
    ) {
        if let Some(task_info) = state.active_tasks.get_mut(&holder_task) {
            if inherited_priority > task_info.priority {
                task_info.priority = inherited_priority;
            }
        }
    }

    /// Check for resolved priority inversions.
    fn check_resolved_inversions(&self, state: &mut PriorityInversionState) {
        let mut resolved_inversions = Vec::new();

        for (inversion_id, inversion) in &state.active_inversions {
            // Check if the blocked task is no longer blocked
            let blocked_task_info = state.active_tasks.get(&inversion.blocked_task);
            let blocking_task_info = state.active_tasks.get(&inversion.blocking_task);

            let is_resolved = match (blocked_task_info, blocking_task_info) {
                (Some(blocked), Some(blocking)) => {
                    blocked.state == TaskState::Running
                        || blocked.state == TaskState::Completed
                        || blocking.state == TaskState::Completed
                        || !blocked.waiting_for.contains(&inversion.resource_id)
                }
                _ => true, // One of the tasks is gone
            };

            if is_resolved {
                resolved_inversions.push(*inversion_id);
            }
        }

        // Update statistics and remove resolved inversions
        for inversion_id in resolved_inversions {
            if let Some(mut inversion) = state.active_inversions.remove(&inversion_id) {
                let duration = inversion.start_time.elapsed();
                inversion.duration = Some(duration);

                // Update statistics
                state.statistics.active_inversion_count -= 1;
                state.statistics.total_inversion_duration += duration;

                if duration > state.statistics.max_inversion_duration {
                    state.statistics.max_inversion_duration = duration;
                }

                // Update average duration
                let total_resolved =
                    state.statistics.total_inversions - state.statistics.active_inversion_count;
                if total_resolved > 0 {
                    state.statistics.avg_inversion_duration =
                        state.statistics.total_inversion_duration / total_resolved as u32;
                }

                // Restore original priority if inheritance was applied
                if self.config.track_priority_inheritance {
                    self.restore_original_priority(state, inversion.blocking_task);
                }
            }
        }
    }

    /// Restore original priority after inversion resolution.
    fn restore_original_priority(&self, state: &mut PriorityInversionState, task_id: TaskId) {
        if let Some(task_info) = state.active_tasks.get_mut(&task_id) {
            task_info.priority = task_info.original_priority;
        }
    }

    /// Get current priority inversion statistics.
    #[must_use]
    pub fn statistics(&self) -> PriorityInversionStatistics {
        let state = self.state.lock().unwrap();
        state.statistics.clone()
    }

    /// Get list of currently active priority inversions.
    #[must_use]
    pub fn active_inversions(&self) -> Vec<PriorityInversion> {
        let state = self.state.lock().unwrap();
        state.active_inversions.values().cloned().collect()
    }

    /// Check for any active priority inversions.
    #[must_use]
    pub fn has_active_inversions(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.active_inversions.is_empty()
    }

    /// Reset all tracking state and statistics.
    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.active_tasks.clear();
        state.resource_locks.clear();
        state.active_inversions.clear();
        state.statistics = PriorityInversionStatistics::default();
        state.last_stats_report = Instant::now();
        state.next_inversion_id = 1;
    }

    /// Generate a detailed report of priority inversion status.
    #[must_use]
    pub fn generate_report(&self) -> String {
        let state = self.state.lock().unwrap();
        let stats = &state.statistics;

        let mut report = String::new();
        report.push_str("=== Priority Inversion Oracle Report ===\n");
        report.push_str(&format!("Total Inversions: {}\n", stats.total_inversions));
        report.push_str(&format!("Direct Inversions: {}\n", stats.direct_inversions));
        report.push_str(&format!(
            "Transitive Inversions: {}\n",
            stats.transitive_inversions
        ));
        report.push_str(&format!(
            "Inheritance Failures: {}\n",
            stats.inheritance_failures
        ));
        report.push_str(&format!(
            "Active Inversions: {}\n",
            stats.active_inversion_count
        ));
        report.push_str(&format!(
            "Total Inversion Duration: {:?}\n",
            stats.total_inversion_duration
        ));
        report.push_str(&format!(
            "Max Inversion Duration: {:?}\n",
            stats.max_inversion_duration
        ));
        report.push_str(&format!(
            "Avg Inversion Duration: {:?}\n",
            stats.avg_inversion_duration
        ));

        if !state.active_inversions.is_empty() {
            report.push_str("\n=== Active Inversions ===\n");
            for inversion in state.active_inversions.values() {
                report.push_str(&format!(
                    "Inversion {}: Task {:?}(P{:?}) blocked by Task {:?}(P{:?}) on Resource {:?} for {:?}\n",
                    inversion.inversion_id.0,
                    inversion.blocked_task,
                    inversion.blocked_priority,
                    inversion.blocking_task,
                    inversion.blocking_priority,
                    inversion.resource_id,
                    inversion.start_time.elapsed()
                ));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn test_oracle_creation() {
        let oracle = PriorityInversionOracle::with_defaults();
        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversion_count, 0);
    }

    #[test]
    fn test_task_lifecycle() {
        let oracle = PriorityInversionOracle::with_defaults();
        let task_id = TaskId::testing_default();

        oracle.on_task_spawn(task_id, Priority::High);
        oracle.on_task_start(task_id);
        oracle.on_task_complete(task_id);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
    }

    #[test]
    fn test_direct_priority_inversion_detection() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Spawn tasks
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);

        // Low priority task acquires resource
        oracle.on_resource_acquire(low_task, resource);

        // High priority task waits for same resource - should detect inversion
        oracle.on_resource_wait(high_task, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 1);
        assert_eq!(stats.direct_inversions, 1);
        assert_eq!(stats.active_inversion_count, 1);
        assert!(oracle.has_active_inversions());
    }

    #[test]
    fn test_inversion_resolution() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Create inversion
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);
        oracle.on_resource_acquire(low_task, resource);
        oracle.on_resource_wait(high_task, resource);

        assert_eq!(oracle.statistics().active_inversion_count, 1);

        // Resolve inversion by releasing resource
        oracle.on_resource_release(low_task, resource);
        oracle.on_resource_acquire(high_task, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.active_inversion_count, 0);
        assert_eq!(stats.total_inversions, 1);
        assert!(!oracle.has_active_inversions());
    }

    #[test]
    fn test_no_inversion_when_priorities_equal() {
        let oracle = PriorityInversionOracle::with_defaults();
        let task1 = TaskId::testing_default();
        let task2 = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        oracle.on_task_spawn(task1, Priority::Normal);
        oracle.on_task_spawn(task2, Priority::Normal);
        oracle.on_resource_acquire(task1, resource);
        oracle.on_resource_wait(task2, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert!(!oracle.has_active_inversions());
    }

    #[test]
    fn test_report_generation() {
        let oracle = PriorityInversionOracle::with_defaults();
        let report = oracle.generate_report();
        assert!(report.contains("Priority Inversion Oracle Report"));
        assert!(report.contains("Total Inversions: 0"));
    }

    #[test]
    fn test_oracle_reset() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Create some activity
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);
        oracle.on_resource_acquire(low_task, resource);
        oracle.on_resource_wait(high_task, resource);

        assert_eq!(oracle.statistics().total_inversions, 1);

        oracle.reset();

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversion_count, 0);
        assert!(!oracle.has_active_inversions());
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cooperative => write!(f, "Cooperative"),
            Self::Normal => write!(f, "Normal"),
            Self::High => write!(f, "High"),
        }
    }
}

impl std::fmt::Display for InversionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::Transitive => write!(f, "Transitive"),
            Self::InheritanceFailure => write!(f, "InheritanceFailure"),
        }
    }
}
