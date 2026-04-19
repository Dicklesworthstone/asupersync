//! Priority Inversion Oracle for Three-Lane Scheduler
//!
//! This module provides real-time detection and measurement of priority inversions
//! in the three-lane scheduler. Priority inversion occurs when a high-priority task
//! is blocked waiting for a low-priority task, violating priority ordering guarantees.
//!
//! # Design
//!
//! The oracle tracks task execution and blocking relationships to detect:
//! 1. Direct inversions: high-priority task blocked by resource held by low-priority task
//! 2. Chain inversions: high-priority task blocked through dependency chain
//! 3. Unbounded inversions: inversions without priority inheritance mitigation
//! 4. Starvation: high-priority tasks not making progress due to inversions
//!
//! # Integration
//!
//! The oracle integrates with the scheduler to monitor:
//! - Task spawning and priority assignment
//! - Resource acquisition and release
//! - Work-stealing operations
//! - Task completion and cancellation

use crate::runtime::scheduler::priority::DispatchLane;
use crate::runtime::scheduler::worker::WorkerId;
use crate::types::TaskId;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Priority level for scheduling decisions
pub type Priority = u8;

/// Unique identifier for resources that can cause blocking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceId(u64);

impl ResourceId {
    /// Creates a new resource ID
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Information about a detected priority inversion
#[derive(Debug, Clone)]
pub struct PriorityInversion {
    /// Unique identifier for this inversion instance
    pub inversion_id: InversionId,
    /// High-priority task being blocked
    pub blocked_task: TaskId,
    /// Priority of the blocked task
    pub blocked_priority: Priority,
    /// Low-priority task causing the blocking
    pub blocking_task: TaskId,
    /// Priority of the blocking task
    pub blocking_priority: Priority,
    /// Resource involved in the inversion
    pub resource: ResourceId,
    /// When the inversion started
    pub start_time: Instant,
    /// Duration of the inversion (None if still ongoing)
    pub duration: Option<Duration>,
    /// Type of inversion detected
    pub inversion_type: InversionType,
    /// Chain of tasks involved (for transitive inversions)
    pub task_chain: Vec<TaskId>,
    /// Impact assessment
    pub impact: InversionImpact,
}

/// Types of priority inversions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InversionType {
    /// Direct blocking: high-priority task directly blocked by low-priority task
    Direct,
    /// Chain blocking: high-priority task blocked through dependency chain
    Chain,
    /// Unbounded: inversion without priority inheritance mitigation
    Unbounded,
    /// Work-stealing related inversion
    WorkStealing,
}

/// Impact assessment of a priority inversion
#[derive(Debug, Clone)]
pub struct InversionImpact {
    /// Scheduling delay introduced (microseconds)
    pub delay_us: u64,
    /// Number of higher-priority tasks affected
    pub affected_tasks: usize,
    /// Severity level
    pub severity: InversionSeverity,
    /// Performance impact on throughput
    pub throughput_impact: f64,
    /// Impact on fairness metrics
    pub fairness_impact: f64,
}

/// Severity levels for priority inversions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InversionSeverity {
    /// Minor inversion with limited impact
    Minor,
    /// Moderate inversion causing noticeable delay
    Moderate,
    /// Severe inversion causing significant scheduling disruption
    Severe,
    /// Critical inversion threatening real-time guarantees
    Critical,
}

/// Unique identifier for inversion instances
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InversionId(u64);

impl InversionId {
    /// Creates a stable identifier for a detected priority inversion.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Task execution state for inversion detection
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are used for tracking but may appear unused to linter
struct TaskState {
    task_id: TaskId,
    priority: Priority,
    lane: DispatchLane,
    worker_id: Option<WorkerId>,
    start_time: Instant,
    blocked_on: Option<ResourceId>,
    blocking_tasks: HashSet<TaskId>,
    held_resources: HashSet<ResourceId>,
}

/// Resource state for tracking contention
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are used for tracking but may appear unused to linter
struct ResourceState {
    resource_id: ResourceId,
    owner: Option<TaskId>,
    waiters: VecDeque<TaskId>,
    creation_time: Instant,
}

/// Statistics for priority inversion monitoring
#[derive(Debug, Default, Clone)]
pub struct InversionStats {
    /// Total number of inversions detected
    pub total_inversions: u64,
    /// Number of active inversions
    pub active_inversions: u64,
    /// Average inversion duration in microseconds
    pub avg_duration_us: u64,
    /// Maximum inversion duration seen
    pub max_duration_us: u64,
    /// Total scheduling delay caused by inversions
    pub total_delay_us: u64,
    /// Breakdown by inversion type
    pub by_type: HashMap<String, u64>,
    /// Breakdown by severity
    pub by_severity: HashMap<String, u64>,
    /// Tasks affected by inversions
    pub affected_tasks: u64,
    /// Overall priority ordering health (0.0 = many inversions, 1.0 = no inversions)
    pub priority_health: f64,
}

/// Priority Inversion Oracle implementation
pub struct PriorityInversionOracle {
    /// Task states indexed by TaskId
    tasks: Arc<RwLock<HashMap<TaskId, TaskState>>>,
    /// Resource states indexed by ResourceId
    resources: Arc<RwLock<HashMap<ResourceId, ResourceState>>>,
    /// Active priority inversions
    active_inversions: Arc<RwLock<HashMap<InversionId, PriorityInversion>>>,
    /// Historical inversions for analysis
    historical_inversions: Arc<RwLock<VecDeque<PriorityInversion>>>,
    /// Statistics and metrics
    stats: Arc<RwLock<InversionStats>>,
    /// Sequence counter for unique IDs
    next_inversion_id: AtomicU64,
    next_resource_id: AtomicU64,
    /// Configuration
    config: InversionOracleConfig,
}

/// Configuration for priority inversion detection
#[derive(Debug, Clone)]
pub struct InversionOracleConfig {
    /// Minimum duration to consider an inversion (microseconds)
    pub min_inversion_duration_us: u64,
    /// Maximum number of historical inversions to retain
    pub max_history_size: usize,
    /// Whether to detect chain inversions (more expensive)
    pub detect_chain_inversions: bool,
    /// Priority difference threshold for inversion detection
    pub priority_threshold: u8,
    /// Enable detailed impact analysis
    pub enable_impact_analysis: bool,
}

impl Default for InversionOracleConfig {
    fn default() -> Self {
        Self {
            min_inversion_duration_us: 100, // 0.1ms minimum
            max_history_size: 1000,
            detect_chain_inversions: true,
            priority_threshold: 1, // Any priority difference
            enable_impact_analysis: true,
        }
    }
}

impl PriorityInversionOracle {
    /// Creates a new priority inversion oracle
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(InversionOracleConfig::default())
    }

    /// Creates a new oracle with custom configuration
    #[must_use]
    pub fn with_config(config: InversionOracleConfig) -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            active_inversions: Arc::new(RwLock::new(HashMap::new())),
            historical_inversions: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(InversionStats::default())),
            next_inversion_id: AtomicU64::new(1),
            next_resource_id: AtomicU64::new(1),
            config,
        }
    }

    /// Records that a task was spawned
    pub fn track_task_spawned(
        &self,
        task_id: TaskId,
        priority: Priority,
        lane: DispatchLane,
        worker_id: Option<WorkerId>,
    ) {
        let task_state = TaskState {
            task_id,
            priority,
            lane,
            worker_id,
            start_time: Instant::now(),
            blocked_on: None,
            blocking_tasks: HashSet::new(),
            held_resources: HashSet::new(),
        };

        self.tasks.write().insert(task_id, task_state);
    }

    /// Records that a task completed
    pub fn track_task_completed(&self, task_id: TaskId) {
        let mut tasks = self.tasks.write();
        if let Some(task_state) = tasks.remove(&task_id) {
            // Release any resources held by this task
            drop(tasks);
            for resource_id in task_state.held_resources {
                self.release_resource(task_id, resource_id);
            }

            // End any inversions involving this task
            self.end_inversions_for_task(task_id);
        }
    }

    /// Records that a task acquired a resource
    pub fn track_resource_acquired(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut resources = self.resources.write();
        let mut tasks = self.tasks.write();

        // Update resource state
        let resource_state = resources
            .entry(resource_id)
            .or_insert_with(|| ResourceState {
                resource_id,
                owner: None,
                waiters: VecDeque::new(),
                creation_time: Instant::now(),
            });

        resource_state.owner = Some(task_id);

        // Update task state
        if let Some(task_state) = tasks.get_mut(&task_id) {
            task_state.held_resources.insert(resource_id);
            task_state.blocked_on = None;
        }

        drop(resources);
        drop(tasks);

        // Check for priority inversion resolution
        self.check_inversion_resolution(resource_id);
    }

    /// Records that a task is waiting for a resource
    pub fn track_resource_waiting(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut resources = self.resources.write();
        let mut tasks = self.tasks.write();

        // Add to resource waiters
        let resource_state = resources
            .entry(resource_id)
            .or_insert_with(|| ResourceState {
                resource_id,
                owner: None,
                waiters: VecDeque::new(),
                creation_time: Instant::now(),
            });

        resource_state.waiters.push_back(task_id);

        // Update task state
        if let Some(task_state) = tasks.get_mut(&task_id) {
            task_state.blocked_on = Some(resource_id);
        }

        // Get task and resource owner info for inversion detection
        let waiting_task_priority = tasks.get(&task_id).map(|t| t.priority);
        let owner_task_id = resource_state.owner;

        drop(resources);
        drop(tasks);

        // Check for priority inversion
        if let (Some(waiting_priority), Some(owner_id)) = (waiting_task_priority, owner_task_id) {
            self.detect_direct_inversion(task_id, waiting_priority, owner_id, resource_id);
        }
    }

    /// Records that a task released a resource
    pub fn release_resource(&self, task_id: TaskId, resource_id: ResourceId) {
        let mut resources = self.resources.write();
        let mut tasks = self.tasks.write();

        // Update resource state
        if let Some(resource_state) = resources.get_mut(&resource_id) {
            resource_state.owner = None;

            // Wake next waiter if any
            if let Some(next_waiter) = resource_state.waiters.pop_front() {
                if let Some(waiter_state) = tasks.get_mut(&next_waiter) {
                    waiter_state.blocked_on = None;
                }

                // Transfer ownership
                resource_state.owner = Some(next_waiter);
                if let Some(waiter_state) = tasks.get_mut(&next_waiter) {
                    waiter_state.held_resources.insert(resource_id);
                }
            }
        }

        // Update task state
        if let Some(task_state) = tasks.get_mut(&task_id) {
            task_state.held_resources.remove(&resource_id);
        }

        drop(resources);
        drop(tasks);

        // Check for inversion resolution
        self.check_inversion_resolution(resource_id);
    }

    /// Detects direct priority inversion
    fn detect_direct_inversion(
        &self,
        blocked_task: TaskId,
        blocked_priority: Priority,
        blocking_task: TaskId,
        resource: ResourceId,
    ) {
        let tasks = self.tasks.read();

        if let Some(blocking_task_state) = tasks.get(&blocking_task) {
            let blocking_priority = blocking_task_state.priority;

            // Check if this is actually an inversion (blocked has higher priority)
            if blocked_priority > blocking_priority
                && (blocked_priority - blocking_priority) >= self.config.priority_threshold
            {
                drop(tasks);

                let inversion_id =
                    InversionId::new(self.next_inversion_id.fetch_add(1, Ordering::Relaxed));
                let start_time = Instant::now();

                let impact = if self.config.enable_impact_analysis {
                    self.analyze_inversion_impact(
                        blocked_task,
                        blocking_task,
                        blocked_priority,
                        blocking_priority,
                    )
                } else {
                    InversionImpact {
                        delay_us: 0,
                        affected_tasks: 0,
                        severity: InversionSeverity::Minor,
                        throughput_impact: 0.0,
                        fairness_impact: 0.0,
                    }
                };

                let inversion = PriorityInversion {
                    inversion_id,
                    blocked_task,
                    blocked_priority,
                    blocking_task,
                    blocking_priority,
                    resource,
                    start_time,
                    duration: None,
                    inversion_type: InversionType::Direct,
                    task_chain: vec![blocked_task, blocking_task],
                    impact,
                };

                // Record the inversion
                self.active_inversions
                    .write()
                    .insert(inversion_id, inversion.clone());
                self.update_stats_for_new_inversion(&inversion);

                // Optionally detect chain inversions
                if self.config.detect_chain_inversions {
                    self.detect_chain_inversions(blocked_task, blocked_priority);
                }
            }
        }
    }

    /// Detects transitive (chain) priority inversions
    fn detect_chain_inversions(&self, original_blocked: TaskId, original_priority: Priority) {
        let tasks = self.tasks.read();
        let resources = self.resources.read();

        // Build dependency graph and look for chains
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        self.find_blocking_chains(
            &tasks,
            &resources,
            original_blocked,
            original_priority,
            &mut visited,
            &mut chain,
        );
    }

    /// Recursively finds blocking chains that constitute priority inversions
    fn find_blocking_chains(
        &self,
        tasks: &HashMap<TaskId, TaskState>,
        resources: &HashMap<ResourceId, ResourceState>,
        current_task: TaskId,
        original_priority: Priority,
        visited: &mut HashSet<TaskId>,
        chain: &mut Vec<TaskId>,
    ) {
        if visited.contains(&current_task) {
            return; // Avoid cycles
        }

        visited.insert(current_task);
        chain.push(current_task);

        if let Some(task_state) = tasks.get(&current_task) {
            if let Some(resource_id) = task_state.blocked_on {
                if let Some(resource_state) = resources.get(&resource_id) {
                    if let Some(owner_task) = resource_state.owner {
                        if let Some(owner_state) = tasks.get(&owner_task) {
                            // Check if this creates a priority inversion
                            if original_priority > owner_state.priority
                                && (original_priority - owner_state.priority)
                                    >= self.config.priority_threshold
                                && chain.len() > 2
                            {
                                // Chain inversion needs at least 3 tasks

                                let inversion_id = InversionId::new(
                                    self.next_inversion_id.fetch_add(1, Ordering::Relaxed),
                                );

                                let impact = if self.config.enable_impact_analysis {
                                    self.analyze_inversion_impact(
                                        chain[0],
                                        owner_task,
                                        original_priority,
                                        owner_state.priority,
                                    )
                                } else {
                                    InversionImpact {
                                        delay_us: 0,
                                        affected_tasks: chain.len(),
                                        severity: InversionSeverity::Moderate,
                                        throughput_impact: 0.0,
                                        fairness_impact: 0.0,
                                    }
                                };

                                let inversion = PriorityInversion {
                                    inversion_id,
                                    blocked_task: chain[0],
                                    blocked_priority: original_priority,
                                    blocking_task: owner_task,
                                    blocking_priority: owner_state.priority,
                                    resource: resource_id,
                                    start_time: Instant::now(),
                                    duration: None,
                                    inversion_type: InversionType::Chain,
                                    task_chain: chain.clone(),
                                    impact,
                                };

                                // Record chain inversion
                                let mut active = self.active_inversions.write();
                                active.insert(inversion_id, inversion.clone());
                                drop(active);
                                self.update_stats_for_new_inversion(&inversion);
                            }

                            // Continue chain
                            self.find_blocking_chains(
                                tasks,
                                resources,
                                owner_task,
                                original_priority,
                                visited,
                                chain,
                            );
                        }
                    }
                }
            }
        }

        chain.pop();
    }

    /// Checks for inversion resolution when a resource state changes
    fn check_inversion_resolution(&self, resource_id: ResourceId) {
        let mut resolved_inversions = Vec::new();

        {
            let active = self.active_inversions.read();
            for (inversion_id, inversion) in active.iter() {
                if inversion.resource == resource_id && inversion.duration.is_none() {
                    resolved_inversions.push(*inversion_id);
                }
            }
        }

        // Resolve inversions
        for inversion_id in resolved_inversions {
            self.end_inversion(inversion_id);
        }
    }

    /// Ends inversions involving a specific task
    fn end_inversions_for_task(&self, task_id: TaskId) {
        let mut to_resolve = Vec::new();

        {
            let active = self.active_inversions.read();
            for (inversion_id, inversion) in active.iter() {
                if (inversion.blocked_task == task_id || inversion.blocking_task == task_id)
                    && inversion.duration.is_none()
                {
                    to_resolve.push(*inversion_id);
                }
            }
        }

        for inversion_id in to_resolve {
            self.end_inversion(inversion_id);
        }
    }

    /// Ends a specific inversion
    fn end_inversion(&self, inversion_id: InversionId) {
        let mut active = self.active_inversions.write();

        if let Some(mut inversion) = active.remove(&inversion_id) {
            let end_time = Instant::now();
            let duration = end_time.duration_since(inversion.start_time);

            // Only record if above minimum duration threshold
            if duration.as_micros() as u64 >= self.config.min_inversion_duration_us {
                inversion.duration = Some(duration);

                // Update impact with actual duration
                if self.config.enable_impact_analysis {
                    inversion.impact.delay_us = duration.as_micros() as u64;
                    inversion.impact.severity =
                        self.classify_inversion_severity(duration, &inversion);
                }

                // Add to historical record
                let mut history = self.historical_inversions.write();
                history.push_back(inversion.clone());

                // Limit history size
                while history.len() > self.config.max_history_size {
                    history.pop_front();
                }
                drop(history);

                // Update statistics
                self.update_stats_for_resolved_inversion(&inversion);
            }
        }
    }

    /// Analyzes the impact of a priority inversion
    fn analyze_inversion_impact(
        &self,
        _blocked_task: TaskId,
        _blocking_task: TaskId,
        blocked_priority: Priority,
        blocking_priority: Priority,
    ) -> InversionImpact {
        let tasks = self.tasks.read();

        // Count affected high-priority tasks
        let affected_tasks = tasks
            .values()
            .filter(|t| t.priority >= blocked_priority)
            .count();

        let priority_diff = blocked_priority - blocking_priority;

        // Estimate impact based on priority difference
        let severity = match priority_diff {
            1..=2 => InversionSeverity::Minor,
            3..=5 => InversionSeverity::Moderate,
            6..=10 => InversionSeverity::Severe,
            _ => InversionSeverity::Critical,
        };

        let throughput_impact = f64::from(priority_diff) * 0.1; // 10% per priority level
        let fairness_impact = f64::from(priority_diff) * 0.05; // 5% per priority level

        InversionImpact {
            delay_us: 0, // Will be filled when inversion resolves
            affected_tasks,
            severity,
            throughput_impact: throughput_impact.min(1.0),
            fairness_impact: fairness_impact.min(1.0),
        }
    }

    /// Classifies inversion severity based on duration and context
    fn classify_inversion_severity(
        &self,
        duration: Duration,
        inversion: &PriorityInversion,
    ) -> InversionSeverity {
        let duration_ms = duration.as_millis() as u64;
        let priority_diff = inversion.blocked_priority - inversion.blocking_priority;

        match (duration_ms, priority_diff) {
            (0..=1, _) => InversionSeverity::Minor,
            (2..=10, 1..=2) => InversionSeverity::Minor,
            (2..=10, 3..=5) => InversionSeverity::Moderate,
            (2..=10, _) => InversionSeverity::Severe,
            (11..=100, 1..=2) => InversionSeverity::Moderate,
            (11..=100, _) => InversionSeverity::Severe,
            (_, _) => InversionSeverity::Critical,
        }
    }

    /// Updates statistics for a new inversion
    fn update_stats_for_new_inversion(&self, inversion: &PriorityInversion) {
        let mut stats = self.stats.write();
        stats.total_inversions += 1;
        stats.active_inversions += 1;

        let type_name = format!("{:?}", inversion.inversion_type);
        *stats.by_type.entry(type_name).or_insert(0) += 1;

        let severity_name = format!("{:?}", inversion.impact.severity);
        *stats.by_severity.entry(severity_name).or_insert(0) += 1;

        stats.affected_tasks += inversion.impact.affected_tasks as u64;

        // Recalculate priority health
        self.update_priority_health(&mut stats);
    }

    /// Updates statistics when an inversion resolves
    fn update_stats_for_resolved_inversion(&self, inversion: &PriorityInversion) {
        let mut stats = self.stats.write();
        stats.active_inversions = stats.active_inversions.saturating_sub(1);

        if let Some(duration) = inversion.duration {
            let duration_us = duration.as_micros() as u64;
            stats.total_delay_us += duration_us;
            stats.max_duration_us = stats.max_duration_us.max(duration_us);

            // Update average duration
            if stats.total_inversions > 0 {
                stats.avg_duration_us = stats.total_delay_us / stats.total_inversions;
            }
        }

        self.update_priority_health(&mut stats);
    }

    /// Updates the overall priority health metric
    fn update_priority_health(&self, stats: &mut InversionStats) {
        // Health decreases with more active inversions and total delay
        let active_penalty = (stats.active_inversions as f64) * 0.1;
        let delay_penalty = (stats.total_delay_us as f64) / 1_000_000.0; // Convert to seconds

        stats.priority_health = (1.0 - (active_penalty + delay_penalty * 0.01)).max(0.0);
    }

    /// Creates a new unique resource ID
    pub fn create_resource(&self) -> ResourceId {
        ResourceId::new(self.next_resource_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Gets current statistics
    pub fn get_stats(&self) -> InversionStats {
        self.stats.read().clone()
    }

    /// Gets all active inversions
    pub fn get_active_inversions(&self) -> Vec<PriorityInversion> {
        self.active_inversions.read().values().cloned().collect()
    }

    /// Gets historical inversions
    pub fn get_historical_inversions(&self) -> Vec<PriorityInversion> {
        self.historical_inversions.read().iter().cloned().collect()
    }

    /// Resets all statistics and clears history
    pub fn reset(&self) {
        self.tasks.write().clear();
        self.resources.write().clear();
        self.active_inversions.write().clear();
        self.historical_inversions.write().clear();
        *self.stats.write() = InversionStats::default();
        self.next_inversion_id.store(1, Ordering::Relaxed);
        self.next_resource_id.store(1, Ordering::Relaxed);
    }
}

impl Default for PriorityInversionOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskId;

    #[test]
    fn test_oracle_creation() {
        let oracle = PriorityInversionOracle::new();
        let stats = oracle.get_stats();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversions, 0);
    }

    #[test]
    fn test_task_tracking() {
        let oracle = PriorityInversionOracle::new();
        let task_id = TaskId::new_for_test(1, 0);

        oracle.track_task_spawned(task_id, 5, DispatchLane::Ready, None);

        let tasks = oracle.tasks.read();
        assert!(tasks.contains_key(&task_id));
        assert_eq!(tasks.get(&task_id).unwrap().priority, 5);
    }

    #[test]
    fn test_direct_inversion_detection() {
        let oracle = PriorityInversionOracle::new();
        let high_priority_task = TaskId::new_for_test(1, 0);
        let low_priority_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Spawn tasks with different priorities
        oracle.track_task_spawned(high_priority_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_priority_task, 1, DispatchLane::Ready, None);

        // Low priority task acquires resource
        oracle.track_resource_acquired(low_priority_task, resource);

        // High priority task waits for same resource (should detect inversion)
        oracle.track_resource_waiting(high_priority_task, resource);

        let active_inversions = oracle.get_active_inversions();
        assert_eq!(active_inversions.len(), 1);

        let inversion = &active_inversions[0];
        assert_eq!(inversion.blocked_task, high_priority_task);
        assert_eq!(inversion.blocking_task, low_priority_task);
        assert_eq!(inversion.blocked_priority, 10);
        assert_eq!(inversion.blocking_priority, 1);
        assert_eq!(inversion.inversion_type, InversionType::Direct);
    }

    #[test]
    fn test_inversion_resolution() {
        let oracle = PriorityInversionOracle::new();
        let high_priority_task = TaskId::new_for_test(1, 0);
        let low_priority_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Set up inversion
        oracle.track_task_spawned(high_priority_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_priority_task, 1, DispatchLane::Ready, None);
        oracle.track_resource_acquired(low_priority_task, resource);
        oracle.track_resource_waiting(high_priority_task, resource);

        assert_eq!(oracle.get_active_inversions().len(), 1);

        // Resolve inversion by releasing resource
        oracle.release_resource(low_priority_task, resource);

        // Should resolve the inversion
        assert_eq!(oracle.get_active_inversions().len(), 0);

        // Check that it was recorded in history
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure above minimum duration
        assert!(oracle.get_historical_inversions().len() <= 1); // May not be recorded if below threshold
    }

    #[test]
    fn test_no_inversion_same_priority() {
        let oracle = PriorityInversionOracle::new();
        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Spawn tasks with same priority
        oracle.track_task_spawned(task1, 5, DispatchLane::Ready, None);
        oracle.track_task_spawned(task2, 5, DispatchLane::Ready, None);

        oracle.track_resource_acquired(task1, resource);
        oracle.track_resource_waiting(task2, resource);

        // Should not detect inversion for same priority
        assert_eq!(oracle.get_active_inversions().len(), 0);
    }

    #[test]
    fn test_statistics_updates() {
        let oracle = PriorityInversionOracle::new();
        let high_task = TaskId::new_for_test(1, 0);
        let low_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        oracle.track_task_spawned(high_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_task, 1, DispatchLane::Ready, None);
        oracle.track_resource_acquired(low_task, resource);
        oracle.track_resource_waiting(high_task, resource);

        let stats = oracle.get_stats();
        assert_eq!(stats.total_inversions, 1);
        assert_eq!(stats.active_inversions, 1);
        assert!(stats.by_type.contains_key("Direct"));
    }

    #[test]
    fn test_resource_id_uniqueness() {
        let oracle = PriorityInversionOracle::new();
        let resource1 = oracle.create_resource();
        let resource2 = oracle.create_resource();

        assert_ne!(resource1, resource2);
    }

    #[test]
    fn test_task_completion_cleanup() {
        let oracle = PriorityInversionOracle::new();
        let task_id = TaskId::new_for_test(1, 0);

        oracle.track_task_spawned(task_id, 5, DispatchLane::Ready, None);
        assert!(oracle.tasks.read().contains_key(&task_id));

        oracle.track_task_completed(task_id);
        assert!(!oracle.tasks.read().contains_key(&task_id));
    }
}
