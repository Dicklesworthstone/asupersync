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

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
#[cfg(any(test, feature = "deterministic-mode"))]
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant, SystemTime};

use crate::types::{Budget, Outcome, RegionId, TaskId};
use crate::util::stack_trace;

/// Pluggable wall-clock source for [`RegionLeakOracle`].
///
/// br-asupersync-6yx9iw + br-asupersync-qdcchl.
///
/// The oracle's threshold checks compare elapsed wall-clock duration
/// against `RegionLeakConfig::max_*` ceilings. When run inside a lab
/// harness with virtual time, those checks must come from the harness's
/// deterministic clock — not `std::time::Instant::now()` — or two
/// replays of the same scenario produce different violation reports.
/// `TimeSource` is `Arc<dyn Fn() -> Instant + Send + Sync>` so the lab
/// harness can install a virtual-clock-backed closure while production
/// callers keep the default `Instant::now`.
pub type TimeSource = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Default wall-clock time source — direct `Instant::now()`. Used when
/// no explicit override is provided. Production deployments retain
/// wall-clock semantics; lab replay must override via
/// [`RegionLeakOracle::with_time_source`].
fn default_time_source() -> TimeSource {
    Arc::new(Instant::now)
}

/// br-asupersync-hq5gou — Wall-clock proxy for the violation
/// `detected_at` field. In production the oracle stamps real
/// `SystemTime::now()`, but under `cfg(any(test, feature =
/// "deterministic-mode"))` returns `UNIX_EPOCH` so test runs and lab
/// replays produce byte-stable violation records (the original concern
/// in the bead: identical scenarios producing different violation
/// stamps across runs broke crashpack-hash equivalence and snapshot
/// regression tests).
///
/// Note: this helper addresses the *violation-record* non-determinism
/// (the part that flows out to crashpacks and trace certificates). The
/// internal `Instant::now()` sites used for threshold detection
/// remain — they affect *when* a violation fires, which is a separate
/// concern requiring the oracle's whole timing model to switch to
/// `crate::types::Time`. Tracked as follow-up.
#[inline]
fn violation_now() -> SystemTime {
    #[cfg(any(test, feature = "deterministic-mode"))]
    {
        UNIX_EPOCH
    }
    #[cfg(not(any(test, feature = "deterministic-mode")))]
    {
        SystemTime::now()
    }
}

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
#[derive(Debug, Clone)]
pub struct RegionState {
    /// Unique identifier for this region.
    pub region_id: RegionId,
    /// Optional ID of the parent region.
    pub parent_id: Option<RegionId>,
    /// Current lifecycle state of the region.
    pub state: RegionLifecycleState,
    /// Timestamp when the region was created.
    pub creation_time: Instant,
    /// Timestamp of the last activity in this region.
    pub last_activity: Instant,
    /// Set of active task IDs in this region.
    pub active_tasks: BTreeSet<TaskId>,
    /// Set of child region IDs.
    pub child_regions: BTreeSet<RegionId>,
    /// Number of finalizers expected to run.
    pub expected_finalizers: u32,
    /// Number of finalizers that have completed.
    pub completed_finalizers: u32,
    /// Optional context string for region creation debugging.
    pub creation_context: Option<String>,
    /// Budget allocated for this region's cleanup.
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
    /// Type of violation detected.
    pub violation_type: ViolationType,
    /// ID of the region where violation occurred.
    pub region_id: RegionId,
    /// Timestamp when the violation was detected.
    pub detected_at: SystemTime,
    /// Duration the violation has been present.
    pub duration: Duration,
    /// Human-readable description of the violation.
    pub description: String,
    /// Additional context information about the violation.
    pub context: ViolationContext,
    /// Suggested fix or remediation for the violation.
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
    /// List of active task IDs in the region.
    pub active_tasks: Vec<TaskId>,
    /// List of child region IDs.
    pub child_regions: Vec<RegionId>,
    /// Optional parent region ID.
    pub parent_region: Option<RegionId>,
    /// Description of the last activity in the region.
    pub last_activity_description: String,
    /// Number of outstanding finalizers.
    pub outstanding_finalizers: u32,
    /// Budget information for the region.
    pub budget_info: BudgetInfo,
    /// Optional stack trace at violation detection time.
    pub stack_trace: Option<String>,
    /// List of related region IDs that may have violations.
    pub related_violations: Vec<RegionId>,
}

/// Budget information for violation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetInfo {
    /// Type of budget (time, memory, etc.).
    pub budget_type: String,
    /// Initial budget amount allocated.
    pub initial_amount: String,
    /// Remaining budget amount available.
    pub remaining_amount: String,
    /// Current exhaustion state of the budget.
    pub exhaustion_state: String,
}

/// Task information tracked by the oracle
#[derive(Debug, Clone)]
pub struct TaskState {
    /// Unique identifier for the task.
    pub task_id: TaskId,
    /// ID of the region containing this task.
    pub region_id: RegionId,
    /// Timestamp when the task was spawned.
    pub spawn_time: Instant,
    /// Optional timestamp of the last poll operation.
    pub last_poll_time: Option<Instant>,
    /// Current lifecycle state of the task.
    pub state: TaskLifecycleState,
    /// Optional context string for task spawn debugging.
    pub spawn_context: Option<String>,
}

/// Lifecycle states for tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskLifecycleState {
    /// Task has been spawned but not yet polled.
    Spawned,
    /// Task is actively running (being polled).
    Running,
    /// Task has completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task panicked during execution.
    Panicked,
}

impl TaskLifecycleState {
    #[inline]
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Panicked)
    }
}

/// The main region leak detection oracle.
///
/// br-asupersync-qdcchl: `regions` and `tasks` are `BTreeMap`, and
/// per-region task/child membership uses `BTreeSet`. Iteration over
/// these structures is sorted by `RegionId` / `TaskId`, so the oracle's
/// observable output stops depending on `RandomState`'s per-process hash
/// seed.
pub struct RegionLeakOracle {
    config: RegionLeakConfig,
    regions: BTreeMap<RegionId, RegionState>,
    tasks: BTreeMap<TaskId, TaskState>,
    violations: VecDeque<RegionViolation>,
    start_time: Instant,
    last_check_time: Instant,
    total_regions_created: u64,
    total_regions_closed: u64,
    total_tasks_spawned: u64,
    total_tasks_completed: u64,
    /// br-asupersync-6yx9iw: pluggable time source. Default is
    /// [`Instant::now`]; lab harnesses install a virtual-clock-backed
    /// closure via [`Self::with_time_source`].
    time_source: TimeSource,
}

impl RegionLeakOracle {
    /// Create a new region leak detection oracle with the given configuration
    #[must_use]
    pub fn new(config: RegionLeakConfig) -> Self {
        let time_source = default_time_source();
        let now = (time_source)();
        Self {
            config,
            regions: BTreeMap::new(),
            tasks: BTreeMap::new(),
            violations: VecDeque::new(),
            start_time: now,
            last_check_time: now,
            total_regions_created: 0,
            total_regions_closed: 0,
            total_tasks_spawned: 0,
            total_tasks_completed: 0,
            time_source,
        }
    }

    /// br-asupersync-6yx9iw: replace the oracle's time source with
    /// `source`. Lab harnesses use this to route every internal
    /// `now()` call through a virtual clock so two replays of the
    /// same scenario produce identical violation timing. Production
    /// callers do not need to call this — the default
    /// [`Instant::now`] source is the right shape outside of replay.
    ///
    /// The oracle's `start_time` and `last_check_time` are reset to
    /// the new source's current value so subsequent duration
    /// computations are consistent with the new clock.
    pub fn with_time_source(mut self, source: TimeSource) -> Self {
        let now = (source)();
        self.start_time = now;
        self.last_check_time = now;
        self.time_source = source;
        self
    }

    /// Returns the oracle's current view of "now" via the installed
    /// time source. All internal threshold checks read this value;
    /// exposing it lets lab tests assert that the virtual clock is wired.
    #[must_use]
    pub fn now(&self) -> Instant {
        (self.time_source)()
    }

    /// Create oracle with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RegionLeakConfig::default())
    }

    /// Create oracle with stricter timeouts for testing
    #[must_use]
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
        let now = (self.time_source)();

        // If this region already exists, that's a violation
        if self.regions.contains_key(&region_id) {
            self.record_violation(RegionViolation {
                violation_type: ViolationType::CircularDependency,
                region_id,
                detected_at: violation_now(),
                duration: Duration::from_secs(0),
                description: format!("Region {region_id} created twice"),
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
            active_tasks: BTreeSet::new(),
            child_regions: BTreeSet::new(),
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
            region.last_activity = (self.time_source)();
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
        let now = (self.time_source)();

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
        let now = (self.time_source)();

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
        let now = (self.time_source)();

        let mut completed_new_terminal_state = false;
        if let Some(task) = self.tasks.get_mut(&task_id)
            && !task.state.is_terminal()
        {
            task.state = match outcome {
                Outcome::Ok(()) => TaskLifecycleState::Completed,
                Outcome::Err(_) => TaskLifecycleState::Completed,
                Outcome::Cancelled(_) => TaskLifecycleState::Cancelled,
                Outcome::Panicked(_) => TaskLifecycleState::Panicked,
            };
            completed_new_terminal_state = true;

            // Remove from region's active task list
            if let Some(region) = self.regions.get_mut(&task.region_id) {
                region.active_tasks.remove(&task_id);
                region.last_activity = now;
            }
        }

        if completed_new_terminal_state {
            self.total_tasks_completed += 1;
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a region starts closing (waiting for children/finalizers)
    pub fn on_region_closing(&mut self, region_id: RegionId, expected_finalizers: u32) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.state = RegionLifecycleState::Closing;
            region.expected_finalizers = expected_finalizers;
            region.last_activity = (self.time_source)();
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a finalizer completes within a region
    pub fn on_finalizer_completed(&mut self, region_id: RegionId) {
        if let Some(region) = self.regions.get_mut(&region_id) {
            region.completed_finalizers = region.completed_finalizers.saturating_add(1);
            region.last_activity = (self.time_source)();

            // Transition to finalizing if all children done but finalizers remain
            if region.child_regions.is_empty()
                && region.active_tasks.is_empty()
                && region.completed_finalizers < region.expected_finalizers
            {
                region.state = RegionLifecycleState::Finalizing;
            }
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Called when a region has fully closed
    pub fn on_region_closed(&mut self, region_id: RegionId) {
        let closed_new_region = match self.regions.get_mut(&region_id) {
            Some(region) if region.state != RegionLifecycleState::Closed => {
                region.state = RegionLifecycleState::Closed;
                region.last_activity = (self.time_source)();
                true
            }
            _ => false,
        };

        if closed_new_region {
            self.total_regions_closed += 1;
        }

        // Remove from parent's child list
        if closed_new_region {
            let parent_id = self.regions.get(&region_id).and_then(|r| r.parent_id);
            if let Some(parent) = parent_id {
                if let Some(parent_region) = self.regions.get_mut(&parent) {
                    parent_region.child_regions.remove(&region_id);
                    parent_region.last_activity = (self.time_source)();
                }
            }
        }

        if self.config.continuous_checking {
            let _ = self.check_for_violations();
        }
    }

    /// Check for region leak violations and return any detected issues
    pub fn check_for_violations(&mut self) -> Result<Vec<RegionViolation>, String> {
        let now = (self.time_source)();
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
    #[must_use]
    pub fn violations(&self) -> &VecDeque<RegionViolation> {
        &self.violations
    }

    /// Get summary statistics about the oracle's monitoring
    #[must_use]
    pub fn statistics(&self) -> RegionLeakStatistics {
        let active_regions = self
            .regions
            .values()
            .filter(|region| region.state != RegionLifecycleState::Closed)
            .count() as u64;
        let active_tasks = self
            .tasks
            .values()
            .filter(|task| !task.state.is_terminal())
            .count() as u64;
        RegionLeakStatistics {
            total_regions_created: self.total_regions_created,
            total_regions_closed: self.total_regions_closed,
            total_tasks_spawned: self.total_tasks_spawned,
            total_tasks_completed: self.total_tasks_completed,
            active_regions,
            active_tasks,
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
        let now = (self.time_source)();
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

    fn check_region_violations(
        &self,
        region: &RegionState,
        now: Instant,
    ) -> Option<RegionViolation> {
        let duration = now.duration_since(region.creation_time);

        match region.state {
            RegionLifecycleState::Created => {
                if duration > self.config.max_creation_delay {
                    return Some(RegionViolation {
                        violation_type: ViolationType::StuckCreation,
                        region_id: region.region_id,
                        detected_at: violation_now(),
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
                        detected_at: violation_now(),
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
                        detected_at: violation_now(),
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
                        detected_at: violation_now(),
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
        if task.state.is_terminal() {
            return None;
        }

        let duration = now.duration_since(task.spawn_time);
        if duration > self.config.max_task_lifetime {
            return Some(RegionViolation {
                violation_type: ViolationType::LongRunningTask,
                region_id: task.region_id,
                detected_at: violation_now(),
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
                    if parent.state == RegionLifecycleState::Closed
                        && region.state != RegionLifecycleState::Closed
                    {
                        violations.push(RegionViolation {
                            violation_type: ViolationType::OrphanedChildren,
                            region_id: region.region_id,
                            detected_at: violation_now(),
                            duration: Duration::from_secs(0),
                            description: format!(
                                "Region {} orphaned by closed parent {}",
                                region.region_id, parent_id
                            ),
                            context: self.build_violation_context(region),
                            suggested_fix: "Ensure parent waits for all children to close"
                                .to_string(),
                        });
                    }
                }
            }

            // Check for orphaned tasks (region closed while tasks active)
            if region.state == RegionLifecycleState::Closed && !region.active_tasks.is_empty() {
                violations.push(RegionViolation {
                    violation_type: ViolationType::OrphanedTasks,
                    region_id: region.region_id,
                    detected_at: violation_now(),
                    duration: Duration::from_secs(0),
                    description: format!(
                        "Region {} closed with {} active tasks",
                        region.region_id,
                        region.active_tasks.len()
                    ),
                    context: self.build_violation_context(region),
                    suggested_fix: "Ensure all tasks complete before region closes".to_string(),
                });
            }

            // Check for incomplete finalizers
            if region.state == RegionLifecycleState::Closed
                && region.completed_finalizers < region.expected_finalizers
            {
                violations.push(RegionViolation {
                    violation_type: ViolationType::FinalizersIncomplete,
                    region_id: region.region_id,
                    detected_at: violation_now(),
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
            outstanding_finalizers: region
                .expected_finalizers
                .saturating_sub(region.completed_finalizers),
            budget_info: BudgetInfo {
                budget_type: format!("{:?}", region.budget),
                initial_amount: "Unknown".to_string(),
                remaining_amount: "Unknown".to_string(),
                exhaustion_state: "Unknown".to_string(),
            },
            stack_trace: if self.config.include_stack_traces {
                Some(stack_trace::capture_stack_trace())
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
    /// Total number of regions created since monitoring began.
    pub total_regions_created: u64,
    /// Total number of regions properly closed.
    pub total_regions_closed: u64,
    /// Total number of tasks spawned.
    pub total_tasks_spawned: u64,
    /// Total number of tasks that completed successfully.
    pub total_tasks_completed: u64,
    /// Current number of active regions.
    pub active_regions: u64,
    /// Current number of active tasks.
    pub active_tasks: u64,
    /// Total number of violations detected.
    pub total_violations: u64,
    /// Total duration the monitor has been active.
    pub monitoring_duration: Duration,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_oracle_creation() {
        let oracle = RegionLeakOracle::with_defaults();
        assert_eq!(oracle.violations().len(), 0);
    }

    #[test]
    fn test_region_lifecycle_tracking() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();
        let region_id = RegionId::new_for_test(1, 0);

        // Create a region
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);

        // Activate and close it properly
        oracle.on_region_activated(region_id);
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn test_stuck_region_detection() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();
        let region_id = RegionId::new_for_test(1, 0);

        // Create a region but never activate it
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);

        // Wait longer than timeout would allow
        std::thread::sleep(Duration::from_millis(50));

        // `with_strict_timeouts` enables `fail_fast_mode`, which causes
        // `check_for_violations` to return `Err` as soon as any violation is
        // recorded. Drain the recorded violation list directly instead of
        // unwrapping the result, which would panic in fail-fast mode.
        let _ = oracle.check_for_violations();
        let recorded: Vec<_> = oracle.violations().iter().cloned().collect();
        assert!(!recorded.is_empty());
        assert!(matches!(
            recorded[0].violation_type,
            ViolationType::StuckCreation
        ));
    }

    #[test]
    fn test_task_tracking() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        // Create region and spawn task
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        // Complete task
        oracle.on_task_completed(task_id, Outcome::Ok(()));

        // Close region
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_tasks_spawned, 1);
        assert_eq!(stats.total_tasks_completed, 1);
    }

    #[test]
    fn statistics_report_current_active_entities() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        let active_stats = oracle.statistics();
        assert_eq!(active_stats.active_regions, 1);
        assert_eq!(active_stats.active_tasks, 1);

        oracle.on_task_completed(task_id, Outcome::Ok(()));
        oracle.on_task_completed(task_id, Outcome::Err("duplicate completion".to_string()));
        oracle.on_task_completed(TaskId::new_for_test(999, 0), Outcome::Ok(()));
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);
        oracle.on_region_closed(region_id);
        oracle.on_region_closed(RegionId::new_for_test(999, 0));

        let closed_stats = oracle.statistics();
        assert_eq!(closed_stats.active_regions, 0);
        assert_eq!(closed_stats.active_tasks, 0);
        assert_eq!(closed_stats.total_regions_created, 1);
        assert_eq!(closed_stats.total_regions_closed, 1);
        assert_eq!(closed_stats.total_tasks_spawned, 1);
        assert_eq!(closed_stats.total_tasks_completed, 1);
    }

    #[test]
    fn violation_context_ids_are_deterministically_ordered() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let parent = RegionId::new_for_test(10, 0);
        let child_a = RegionId::new_for_test(30, 0);
        let child_b = RegionId::new_for_test(20, 0);
        let task_a = TaskId::new_for_test(300, 0);
        let task_b = TaskId::new_for_test(100, 0);
        let task_c = TaskId::new_for_test(200, 0);

        oracle.on_region_created(parent, None, None, Budget::INFINITE);
        oracle.on_region_created(child_a, Some(parent), None, Budget::INFINITE);
        oracle.on_region_created(child_b, Some(parent), None, Budget::INFINITE);
        oracle.on_task_spawned(task_a, parent, None);
        oracle.on_task_spawned(task_b, parent, None);
        oracle.on_task_spawned(task_c, parent, None);

        let parent_region = oracle.regions.get(&parent).unwrap();
        let context = oracle.build_violation_context(parent_region);
        assert_eq!(context.active_tasks, vec![task_b, task_c, task_a]);
        assert_eq!(context.child_regions, vec![child_b, child_a]);
    }

    #[test]
    fn extra_finalizer_events_do_not_underflow_context() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);

        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_region_closing(region_id, 1);
        oracle.on_finalizer_completed(region_id);
        oracle.on_finalizer_completed(region_id);

        let region = oracle.regions.get(&region_id).unwrap();
        let context = oracle.build_violation_context(region);
        assert_eq!(context.outstanding_finalizers, 0);
    }

    #[test]
    fn test_orphaned_task_detection() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        // Create region and spawn task
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        // Close region without completing task (violation!)
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should detect orphaned tasks
        let violations = oracle.check_for_violations().unwrap();
        assert!(!violations.is_empty());
        assert!(matches!(
            violations[0].violation_type,
            ViolationType::OrphanedTasks
        ));
    }

    /// br-asupersync-rw5m1a: `RegionViolation` must implement
    /// `std::error::Error` so it composes with the `?` operator and
    /// other `dyn Error`-keyed plumbing.
    #[test]
    fn region_violation_implements_std_error() {
        // Compile-time bound: a function that requires `dyn Error +
        // Send + Sync + 'static` accepts our type. If `RegionViolation`
        // does not impl `Error`, this fails to compile.
        fn assert_impls_error<E: std::error::Error + Send + Sync + 'static>(_: &E) {}

        let violation = RegionViolation {
            violation_type: ViolationType::IdleRegion,
            region_id: RegionId::new_for_test(1, 0),
            detected_at: SystemTime::now(),
            duration: Duration::from_secs(0),
            description: "test".to_string(),
            context: ViolationContext::empty(),
            suggested_fix: String::new(),
        };
        assert_impls_error(&violation);

        // The default `source()` returns None for our aggregate type.
        let as_error: &dyn std::error::Error = &violation;
        assert!(as_error.source().is_none());
    }

    /// br-asupersync-rw5m1a: `?` operator works on a function that
    /// returns `Result<_, RegionViolation>` and converts via
    /// `Box<dyn Error>`. This locks in the practical use-case the
    /// Error impl exists to enable.
    #[test]
    fn region_violation_works_with_question_mark_operator() {
        fn make_failing() -> Result<(), RegionViolation> {
            Err(RegionViolation {
                violation_type: ViolationType::ResourceLeak,
                region_id: RegionId::new_for_test(2, 0),
                detected_at: SystemTime::now(),
                duration: Duration::from_secs(0),
                description: "synthetic".to_string(),
                context: ViolationContext::empty(),
                suggested_fix: String::new(),
            })
        }

        // The body uses `?` to convert RegionViolation into
        // `Box<dyn Error>` via the `From<E: Error> for Box<dyn Error>`
        // blanket impl. If `RegionViolation` did not impl `Error`,
        // this function would fail to compile.
        fn boxed_error_caller() -> Result<(), Box<dyn std::error::Error>> {
            make_failing()?;
            Ok(())
        }

        let result = boxed_error_caller();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The Display impl renders "<violation_type>: <description>".
        let rendered = format!("{err}");
        assert!(rendered.contains("Resource Leak"));
        assert!(rendered.contains("synthetic"));
    }
}

impl Default for RegionLeakOracle {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl std::fmt::Debug for RegionLeakOracle {
    /// br-asupersync-6yx9iw: manual `Debug` because `TimeSource`
    /// (an `Arc<dyn Fn() -> Instant + Send + Sync>`) does not
    /// implement Debug. We elide the closure and surface the
    /// observable state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegionLeakOracle")
            .field("config", &self.config)
            .field("regions_len", &self.regions.len())
            .field("tasks_len", &self.tasks.len())
            .field("violations_len", &self.violations.len())
            .field("total_regions_created", &self.total_regions_created)
            .field("total_regions_closed", &self.total_regions_closed)
            .field("total_tasks_spawned", &self.total_tasks_spawned)
            .field("total_tasks_completed", &self.total_tasks_completed)
            .field("time_source", &"<Arc<dyn Fn() -> Instant>>")
            .finish()
    }
}

impl std::fmt::Display for RegionViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.violation_type, self.description)
    }
}

/// br-asupersync-rw5m1a: implement `std::error::Error` so
/// `RegionViolation` composes with the `?` operator and any other
/// `dyn Error`-keyed plumbing (anyhow, miette, downstream
/// match-on-source). Every other Violation type in the oracle
/// system already implements `Error`; this brings `RegionViolation`
/// in line.
///
/// The default `source()` implementation returns `None` because
/// `RegionViolation` aggregates structural diagnostic fields rather
/// than wrapping an underlying error — there is no upstream cause to
/// chain to.
impl std::error::Error for RegionViolation {}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StuckCreation => write!(f, "Stuck Creation"),
            Self::StuckClosing => write!(f, "Stuck Closing"),
            Self::StuckFinalizing => write!(f, "Stuck Finalizing"),
            Self::IdleRegion => write!(f, "Idle Region"),
            Self::LongRunningTask => write!(f, "Long Running Task"),
            Self::OrphanedChildren => write!(f, "Orphaned Children"),
            Self::OrphanedTasks => write!(f, "Orphaned Tasks"),
            Self::FinalizersIncomplete => write!(f, "Finalizers Incomplete"),
            Self::ResourceLeak => write!(f, "Resource Leak"),
            Self::CircularDependency => write!(f, "Circular Dependency"),
        }
    }
}
