//! Region Leak Detection Oracle
//!
//! This oracle provides real-time monitoring of region lifecycle to detect
//! structured concurrency violations and task orphaning. It ensures that
//! regions properly close to quiescence as required by asupersync's
//! structured concurrency guarantees.
//!
//! # Core Invariants Monitored
//!
//! ## Structured Concurrency
//! - All regions must close to quiescence (no live children + finalizers done)
//! - Parent regions cannot close while children are still active
//! - Tasks must complete before their owning region closes
//!
//! ## Resource Management
//! - No region should remain active indefinitely
//! - All spawned tasks must eventually reach a terminal state
//! - Finalizers must complete within reasonable time bounds
//!
//! ## Timeout Detection
//! - Regions stuck in various states beyond configured thresholds
//! - Long-running tasks that may indicate infinite loops or deadlocks
//! - Finalizers that never complete
//!
//! # Usage
//!
//! The oracle integrates with the lab runtime and can be used in both
//! development and testing environments:
//!
//! ```ignore
//! use asupersync::lab::oracle::region_leak::RegionLeakOracle;
//!
//! let mut oracle = RegionLeakOracle::new(config);
//!
//! // Hook into region events
//! oracle.on_region_created(region_id, parent_id, context);
//! oracle.on_task_spawned(task_id, region_id, context);
//! oracle.on_task_completed(task_id, outcome, context);
//! oracle.on_region_closing(region_id, context);
//! oracle.on_region_closed(region_id, context);
//!
//! // Check for violations
//! if let Some(violations) = oracle.check()? {
//!     for violation in violations {
//!         eprintln!("Region leak detected: {:?}", violation);
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};
use serde::{Serialize, Deserialize};

use crate::types::{RegionId, TaskId, Budget, Outcome};

/// Configuration for region leak detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionLeakConfig {
    /// Maximum time a region can remain in Created state before violation
    pub max_creation_delay: Duration,

    /// Maximum time a region can remain in Closing state before violation
    pub max_closing_time: Duration,

    /// Maximum time a region can remain in Finalizing state before violation
    pub max_finalizing_time: Duration,

    /// Maximum time a task can remain active before violation
    pub max_task_lifetime: Duration,

    /// Maximum time a region can remain active without progress
    pub max_idle_time: Duration,

    /// Whether to check for violations on every oracle call
    pub continuous_checking: bool,

    /// Whether to abort immediately on first violation detected
    pub fail_fast_mode: bool,

    /// Maximum number of violations to track before purging old ones
    pub max_violations_tracked: usize,

    /// Whether to include full stack traces in violation reports
    pub include_stack_traces: bool,
}

impl Default for RegionLeakConfig {
    fn default() -> Self {
        Self {
            max_creation_delay: Duration::from_millis(100),
            max_closing_time: Duration::from_secs(5),
            max_finalizing_time: Duration::from_secs(10),
            max_task_lifetime: Duration::from_secs(30),
            max_idle_time: Duration::from_secs(60),
            continuous_checking: true,
            fail_fast_mode: false,
            max_violations_tracked: 100,
            include_stack_traces: true,
        }
    }
}

/// State of a region being tracked by the oracle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionState {
    pub region_id: RegionId,
    pub parent_id: Option<RegionId>,
    pub state: RegionLifecycleState,
    pub creation_time: Instant,
    pub last_activity: Instant,
    pub active_tasks: HashSet<TaskId>,
    pub child_regions: HashSet<RegionId>,
    pub expected_finalizers: u32,
    pub completed_finalizers: u32,
    pub creation_context: Option<String>,
    pub budget: Budget,
}

/// Lifecycle states that a region can be in
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionLifecycleState {
    /// Region has been created but not yet activated
    Created,
    /// Region is actively running with tasks
    Active,
    /// Region is closing - waiting for children and finalizers
    Closing,
    /// Region is running finalizers
    Finalizing,
    /// Region has completed and been cleaned up
    Closed,
}

/// A detected region leak or structured concurrency violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionViolation {
    pub violation_type: ViolationType,
    pub region_id: RegionId,
    pub detected_at: SystemTime,
    pub duration: Duration,
    pub description: String,
    pub context: ViolationContext,
    pub suggested_fix: String,
}

/// Types of region violations that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    /// Region stuck in Created state too long
    StuckCreation,
    /// Region stuck in Closing state too long
    StuckClosing,
    /// Region stuck in Finalizing state too long
    StuckFinalizing,
    /// Region has been idle (no task activity) too long
    IdleRegion,
    /// Task running too long within region
    LongRunningTask,
    /// Parent region closed while child regions still active
    OrphanedChildren,
    /// Region closed while tasks still active
    OrphanedTasks,
    /// Finalizers never completed
    FinalizersIncomplete,
    /// Resource leak detected (budget not released)
    ResourceLeak,
    /// Circular dependency between regions
    CircularDependency,
}

/// Detailed context about a violation for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationContext {
    pub active_tasks: Vec<TaskId>,
    pub child_regions: Vec<RegionId>,
    pub parent_region: Option<RegionId>,
    pub last_activity_description: String,
    pub outstanding_finalizers: u32,
    pub budget_info: BudgetInfo,
    pub stack_trace: Option<String>,
    pub related_violations: Vec<RegionId>,
}

/// Budget information for violation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetInfo {
    pub budget_type: String,
    pub initial_amount: String,
    pub remaining_amount: String,
    pub exhaustion_state: String,
}

/// Task information tracked by the oracle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskState {
    pub task_id: TaskId,
    pub region_id: RegionId,
    pub spawn_time: Instant,
    pub last_poll_time: Option<Instant>,
    pub state: TaskLifecycleState,
    pub spawn_context: Option<String>,
}

/// Lifecycle states for tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskLifecycleState {
    Spawned,
    Running,
    Completed,
    Cancelled,
    Panicked,
}

/// The main region leak detection oracle
#[derive(Debug, Default)]
pub struct RegionLeakOracle {
    config: RegionLeakConfig,
    regions: HashMap<RegionId, RegionState>,
    tasks: HashMap<TaskId, TaskState>,
    violations: VecDeque<RegionViolation>,
    start_time: Instant,
    last_check_time: Instant,
    total_regions_created: u64,
    total_regions_closed: u64,
    total_tasks_spawned: u64,
    total_tasks_completed: u64,
}

impl RegionLeakOracle {
    /// Create a new region leak detection oracle with the given configuration
    pub fn new(config: RegionLeakConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            regions: HashMap::new(),
            tasks: HashMap::new(),
            violations: VecDeque::new(),
            start_time: now,
            last_check_time: now,
            total_regions_created: 0,
            total_regions_closed: 0,
            total_tasks_spawned: 0,
            total_tasks_completed: 0,
        }
    }

    /// Create oracle with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RegionLeakConfig::default())
    }

    /// Create oracle with stricter timeouts for testing
    pub fn with_strict_timeouts() -> Self {
        Self::new(RegionLeakConfig {
            max_creation_delay: Duration::from_millis(10),
            max_closing_time: Duration::from_millis(100),
            max_finalizing_time: Duration::from_millis(500),
            max_task_lifetime: Duration::from_secs(1),
            max_idle_time: Duration::from_secs(2),
            fail_fast_mode: true,
            ..RegionLeakConfig::default()
        })
    }

    /// Called when a new region is created
    pub fn on_region_created(
        &mut self,
        region_id: RegionId,
        parent_id: Option<RegionId>,
        context: Option<String>,
        budget: Budget,
    ) {
        let now = Instant::now();

        // If this region already exists, that's a violation
        if self.regions.contains_key(&region_id) {
            self.record_violation(RegionViolation {
                violation_type: ViolationType::CircularDependency,
                region_id,
                detected_at: SystemTime::now(),
                duration: Duration::from_secs(0),
                description: format!("Region {} created twice", region_id),
                context: ViolationContext::empty(),
                suggested_fix: "Check for duplicate region creation logic".to_string(),
            });
            return;
        }

        // Update parent's child list
        if let Some(parent) = parent_id {
            if let Some(parent_state) = self.regions.get_mut(&parent) {
                parent_state.child_regions.insert(region_id);
                parent_state.last_activity = now;
            }
        }

        let region_state = RegionState {
            region_id,
            parent_id,
            state: RegionLifecycleState::Created,
            creation_time: now,
            last_activity: now,
            active_tasks: HashSet::new(),
            child_regions: HashSet::new(),
            expected_finalizers: 0,
            completed_finalizers: 0,
            creation_context: context,
            budget,
        };

        self.regions.insert(region_id, region_state);
        self.total_regions_created += 1;

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a region becomes active (starts running)
    pub fn on_region_activated(&mut self, region_id: RegionId) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.state = RegionLifecycleState::Active;
            region.last_activity = Instant::now();
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a task is spawned within a region
    pub fn on_task_spawned(
        &mut self,
        task_id: TaskId,
        region_id: RegionId,
        context: Option<String>,
    ) {
        let now = Instant::now();

        // Update region's active task list
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.active_tasks.insert(task_id);
            region.last_activity = now;

            // Activate region if it was just created
            if region.state == RegionLifecycleState::Created {
                region.state = RegionLifecycleState::Active;
            }
        }

        let task_state = TaskState {
            task_id,
            region_id,
            spawn_time: now,
            last_poll_time: None,
            state: TaskLifecycleState::Spawned,
            spawn_context: context,
        };

        self.tasks.insert(task_id, task_state);
        self.total_tasks_spawned += 1;

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a task is polled (shows activity)
    pub fn on_task_polled(&mut self, task_id: TaskId) {
        let now = Instant::now();

        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.last_poll_time = Some(now);
            task.state = TaskLifecycleState::Running;

            // Update region last activity
            if let Some(region) = self.regions.get_mut(&task.region_id) {
                region.last_activity = now;
            }
        }
    }

    /// Called when a task completes (success, error, or cancellation)
    pub fn on_task_completed(&mut self, task_id: TaskId, outcome: Outcome<(), String>) {
        let now = Instant::now();

        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.state = match outcome {
                Outcome::Ok(()) => TaskLifecycleState::Completed,
                Outcome::Err(_) => TaskLifecycleState::Completed,
                Outcome::Cancelled(_) => TaskLifecycleState::Cancelled,
                Outcome::Panicked(_) => TaskLifecycleState::Panicked,
            };

            // Remove from region's active task list
            if let Some(region) = self.regions.get_mut(&task.region_id) {
                region.active_tasks.remove(&task_id);
                region.last_activity = now;
            }
        }

        self.total_tasks_completed += 1;

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a region starts closing (waiting for children/finalizers)
    pub fn on_region_closing(&mut self, region_id: RegionId, expected_finalizers: u32) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.state = RegionLifecycleState::Closing;
            region.expected_finalizers = expected_finalizers;
            region.last_activity = Instant::now();
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a finalizer completes within a region
    pub fn on_finalizer_completed(&mut self, region_id: RegionId) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.completed_finalizers += 1;
            region.last_activity = Instant::now();

            // Transition to finalizing if all children done but finalizers remain
            if region.child_regions.is_empty() &&
               region.active_tasks.is_empty() &&
               region.completed_finalizers < region.expected_finalizers {
                region.state = RegionLifecycleState::Finalizing;
            }
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a region has fully closed
    pub fn on_region_closed(&mut self, region_id: RegionId) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.state = RegionLifecycleState::Closed;
            region.last_activity = Instant::now();
        }

        self.total_regions_closed += 1;

        // Remove from parent's child list
        let parent_id = self.regions.get(&region_id).and_then(|r| r.parent_id);
        if let Some(parent) = parent_id {
            if let Some(parent_region) = self.regions.get_mut(&parent) {
                parent_region.child_regions.remove(&region_id);
                parent_region.last_activity = Instant::now();
            }
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Check for region leak violations and return any detected issues
    pub fn check_for_violations(&mut self) -> Result<Vec<RegionViolation>, String> {
        let now = Instant::now();
        self.last_check_time = now;

        let mut new_violations = Vec::new();

        // Check each region for violations
        for region in self.regions.values() {
            if let Some(violation) = self.check_region_violations(region, now) {
                new_violations.push(violation);
            }
        }

        // Check each task for violations
        for task in self.tasks.values() {
            if let Some(violation) = self.check_task_violations(task, now) {
                new_violations.push(violation);
            }
        }

        // Check for structural violations (orphans, circular deps)
        new_violations.extend(self.check_structural_violations(now));

        // Record new violations
        for violation in &new_violations {
            self.record_violation(violation.clone());
        }

        // Return violations if any found
        if new_violations.is_empty() {
            Ok(vec![])
        } else {
            if self.config.fail_fast_mode {
                return Err(format!("Region leak detected: {:?}", new_violations[0]));
            }
            Ok(new_violations)
        }
    }

    /// Get all violations detected so far
    pub fn violations(&self) -> &VecDeque<RegionViolation> {
        &self.violations
    }

    /// Get summary statistics about the oracle's monitoring
    pub fn statistics(&self) -> RegionLeakStatistics {
        RegionLeakStatistics {
            total_regions_created: self.total_regions_created,
            total_regions_closed: self.total_regions_closed,
            total_tasks_spawned: self.total_tasks_spawned,
            total_tasks_completed: self.total_tasks_completed,
            active_regions: self.regions.len() as u64,
            active_tasks: self.tasks.len() as u64,
            total_violations: self.violations.len() as u64,
            monitoring_duration: self.last_check_time.duration_since(self.start_time),
        }
    }

    /// Clear all violation history
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Reset the oracle state (useful for tests)
    pub fn reset(&mut self) {
        self.regions.clear();
        self.tasks.clear();
        self.violations.clear();
        let now = Instant::now();
        self.start_time = now;
        self.last_check_time = now;
        self.total_regions_created = 0;
        self.total_regions_closed = 0;
        self.total_tasks_spawned = 0;
        self.total_tasks_completed = 0;
    }

    // Private helper methods

    fn record_violation(&mut self, violation: RegionViolation) {
        self.violations.push_back(violation);

        // Limit violation history size
        while self.violations.len() > self.config.max_violations_tracked {
            self.violations.pop_front();
        }
    }

    fn check_region_violations(&self, region: &RegionState, now: Instant) -> Option<RegionViolation> {
        let duration = now.duration_since(region.creation_time);

        match region.state {
            RegionLifecycleState::Created => {
                if duration > self.config.max_creation_delay {
                    return Some(RegionViolation {
                        violation_type: ViolationType::StuckCreation,
                        region_id: region.region_id,
                        detected_at: SystemTime::now(),
                        duration,
                        description: format!(
                            "Region {} stuck in Created state for {:?}",
                            region.region_id, duration
                        ),
                        context: self.build_violation_context(region),
                        suggested_fix: "Check region activation logic".to_string(),
                    });
                }
            }
            RegionLifecycleState::Closing => {
                if duration > self.config.max_closing_time {
                    return Some(RegionViolation {
                        violation_type: ViolationType::StuckClosing,
                        region_id: region.region_id,
                        detected_at: SystemTime::now(),
                        duration,
                        description: format!(
                            "Region {} stuck in Closing state for {:?}",
                            region.region_id, duration
                        ),
                        context: self.build_violation_context(region),
                        suggested_fix: "Check for hanging child tasks or finalizers".to_string(),
                    });
                }
            }
            RegionLifecycleState::Finalizing => {
                if duration > self.config.max_finalizing_time {
                    return Some(RegionViolation {
                        violation_type: ViolationType::StuckFinalizing,
                        region_id: region.region_id,
                        detected_at: SystemTime::now(),
                        duration,
                        description: format!(
                            "Region {} stuck in Finalizing state for {:?}",
                            region.region_id, duration
                        ),
                        context: self.build_violation_context(region),
                        suggested_fix: "Check for hanging finalizer logic".to_string(),
                    });
                }
            }
            RegionLifecycleState::Active => {
                let idle_duration = now.duration_since(region.last_activity);
                if idle_duration > self.config.max_idle_time {
                    return Some(RegionViolation {
                        violation_type: ViolationType::IdleRegion,
                        region_id: region.region_id,
                        detected_at: SystemTime::now(),
                        duration: idle_duration,
                        description: format!(
                            "Region {} idle for {:?}",
                            region.region_id, idle_duration
                        ),
                        context: self.build_violation_context(region),
                        suggested_fix: "Check for deadlocked or infinite-loop tasks".to_string(),
                    });
                }
            }
            RegionLifecycleState::Closed => {
                // Closed regions don't need violation checks
            }
        }

        None
    }

    fn check_task_violations(&self, task: &TaskState, now: Instant) -> Option<RegionViolation> {
        if task.state == TaskLifecycleState::Completed ||
           task.state == TaskLifecycleState::Cancelled ||
           task.state == TaskLifecycleState::Panicked {
            return None;
        }

        let duration = now.duration_since(task.spawn_time);
        if duration > self.config.max_task_lifetime {
            return Some(RegionViolation {
                violation_type: ViolationType::LongRunningTask,
                region_id: task.region_id,
                detected_at: SystemTime::now(),
                duration,
                description: format!(
                    "Task {} running for {:?} in region {}",
                    task.task_id, duration, task.region_id
                ),
                context: ViolationContext {
                    active_tasks: vec![task.task_id],
                    child_regions: vec![],
                    parent_region: None,
                    last_activity_description: format!(
                        "Task spawned at {:?}, last poll: {:?}",
                        task.spawn_time,
                        task.last_poll_time.unwrap_or(task.spawn_time)
                    ),
                    outstanding_finalizers: 0,
                    budget_info: BudgetInfo {
                        budget_type: "Unknown".to_string(),
                        initial_amount: "Unknown".to_string(),
                        remaining_amount: "Unknown".to_string(),
                        exhaustion_state: "Unknown".to_string(),
                    },
                    stack_trace: None,
                    related_violations: vec![],
                },
                suggested_fix: "Check for infinite loops or blocking operations".to_string(),
            });
        }

        None
    }

    fn check_structural_violations(&self, _now: Instant) -> Vec<RegionViolation> {
        let mut violations = Vec::new();

        // Check for orphaned children (parent closed while children active)
        for region in self.regions.values() {
            if let Some(parent_id) = region.parent_id {
                if let Some(parent) = self.regions.get(&parent_id) {
                    if parent.state == RegionLifecycleState::Closed &&
                       region.state != RegionLifecycleState::Closed {
                        violations.push(RegionViolation {
                            violation_type: ViolationType::OrphanedChildren,
                            region_id: region.region_id,
                            detected_at: SystemTime::now(),
                            duration: Duration::from_secs(0),
                            description: format!(
                                "Region {} orphaned by closed parent {}",
                                region.region_id, parent_id
                            ),
                            context: self.build_violation_context(region),
                            suggested_fix: "Ensure parent waits for all children to close".to_string(),
                        });
                    }
                }
            }

            // Check for orphaned tasks (region closed while tasks active)
            if region.state == RegionLifecycleState::Closed && !region.active_tasks.is_empty() {
                violations.push(RegionViolation {
                    violation_type: ViolationType::OrphanedTasks,
                    region_id: region.region_id,
                    detected_at: SystemTime::now(),
                    duration: Duration::from_secs(0),
                    description: format!(
                        "Region {} closed with {} active tasks",
                        region.region_id, region.active_tasks.len()
                    ),
                    context: self.build_violation_context(region),
                    suggested_fix: "Ensure all tasks complete before region closes".to_string(),
                });
            }

            // Check for incomplete finalizers
            if region.state == RegionLifecycleState::Closed &&
               region.completed_finalizers < region.expected_finalizers {
                violations.push(RegionViolation {
                    violation_type: ViolationType::FinalizersIncomplete,
                    region_id: region.region_id,
                    detected_at: SystemTime::now(),
                    duration: Duration::from_secs(0),
                    description: format!(
                        "Region {} closed with {}/{} finalizers completed",
                        region.region_id, region.completed_finalizers, region.expected_finalizers
                    ),
                    context: self.build_violation_context(region),
                    suggested_fix: "Ensure all finalizers run to completion".to_string(),
                });
            }
        }

        violations
    }

    fn build_violation_context(&self, region: &RegionState) -> ViolationContext {
        ViolationContext {
            active_tasks: region.active_tasks.iter().copied().collect(),
            child_regions: region.child_regions.iter().copied().collect(),
            parent_region: region.parent_id,
            last_activity_description: format!("Last activity: {:?}", region.last_activity),
            outstanding_finalizers: region.expected_finalizers - region.completed_finalizers,
            budget_info: BudgetInfo {
                budget_type: format!("{:?}", region.budget),
                initial_amount: "Unknown".to_string(),
                remaining_amount: "Unknown".to_string(),
                exhaustion_state: "Unknown".to_string(),
            },
            stack_trace: if self.config.include_stack_traces {
                Some("Stack trace capture not implemented".to_string())
            } else {
                None
            },
            related_violations: vec![],
        }
    }
}

impl ViolationContext {
    fn empty() -> Self {
        Self {
            active_tasks: vec![],
            child_regions: vec![],
            parent_region: None,
            last_activity_description: String::new(),
            outstanding_finalizers: 0,
            budget_info: BudgetInfo {
                budget_type: String::new(),
                initial_amount: String::new(),
                remaining_amount: String::new(),
                exhaustion_state: String::new(),
            },
            stack_trace: None,
            related_violations: vec![],
        }
    }
}

/// Statistics about region leak monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionLeakStatistics {
    pub total_regions_created: u64,
    pub total_regions_closed: u64,
    pub total_tasks_spawned: u64,
    pub total_tasks_completed: u64,
    pub active_regions: u64,
    pub active_tasks: u64,
    pub total_violations: u64,
    pub monitoring_duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_creation() {
        let oracle = RegionLeakOracle::with_defaults();
        assert_eq!(oracle.violations().len(), 0);
    }

    #[test]
    fn test_region_lifecycle_tracking() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();

        // Create a region
        oracle.on_region_created(1, None, None, Budget::INFINITE);

        // Activate and close it properly
        oracle.on_region_activated(1);
        oracle.on_region_closing(1, 0);
        oracle.on_region_closed(1);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn test_stuck_region_detection() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();

        // Create a region but never activate it
        oracle.on_region_created(1, None, None, Budget::INFINITE);

        // Wait longer than timeout would allow
        std::thread::sleep(Duration::from_millis(50));

        // Should detect stuck creation
        let violations = oracle.check_for_violations().unwrap();
        assert!(!violations.is_empty());
        assert!(matches!(violations[0].violation_type, ViolationType::StuckCreation));
    }

    #[test]
    fn test_task_tracking() {
        let mut oracle = RegionLeakOracle::with_defaults();

        // Create region and spawn task
        oracle.on_region_created(1, None, None, Budget::INFINITE);
        oracle.on_task_spawned(100, 1, None);

        // Complete task
        oracle.on_task_completed(100, Outcome::Ok(()));

        // Close region
        oracle.on_region_closing(1, 0);
        oracle.on_region_closed(1);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_tasks_spawned, 1);
        assert_eq!(stats.total_tasks_completed, 1);
    }

    #[test]
    fn test_orphaned_task_detection() {
        let mut oracle = RegionLeakOracle::with_defaults();

        // Create region and spawn task
        oracle.on_region_created(1, None, None, Budget::INFINITE);
        oracle.on_task_spawned(100, 1, None);

        // Close region without completing task (violation!)
        oracle.on_region_closing(1, 0);
        oracle.on_region_closed(1);

        // Should detect orphaned tasks
        let violations = oracle.check_for_violations().unwrap();
        assert!(!violations.is_empty());
        assert!(matches!(violations[0].violation_type, ViolationType::OrphanedTasks));
    }
}

impl std::fmt::Display for RegionViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.violation_type, self.description)
    }
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationType::StuckCreation => write!(f, "Stuck Creation"),
            ViolationType::StuckClosing => write!(f, "Stuck Closing"),
            ViolationType::StuckFinalizing => write!(f, "Stuck Finalizing"),
            ViolationType::IdleRegion => write!(f, "Idle Region"),
            ViolationType::LongRunningTask => write!(f, "Long Running Task"),
            ViolationType::OrphanedChildren => write!(f, "Orphaned Children"),
            ViolationType::OrphanedTasks => write!(f, "Orphaned Tasks"),
            ViolationType::FinalizersIncomplete => write!(f, "Finalizers Incomplete"),
            ViolationType::ResourceLeak => write!(f, "Resource Leak"),
            ViolationType::CircularDependency => write!(f, "Circular Dependency"),
        }
    }
}