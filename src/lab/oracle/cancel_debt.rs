//! Cancellation Debt Accumulation Monitor
//!
//! This oracle tracks when cancellation work accumulates faster than it can be processed,
//! potentially leading to resource exhaustion or delayed cleanup.
//!
//! # Concept of Cancellation Debt
//!
//! Cancellation debt occurs when cleanup work (finalization, resource deallocation,
//! obligation discharge) accumulates faster than the runtime can process it. This can happen
//! during high cancellation rates or when cleanup operations are slow.
//!
//! # Key Detection Capabilities
//!
//! - **Queue depth monitoring**: Track cancellation/cleanup work queue sizes
//! - **Processing rate analysis**: Monitor cleanup work completion rates
//! - **Debt accumulation**: Detect when work arrival > completion rates
//! - **Threshold violations**: Alert when debt exceeds configured limits
//! - **Resource pressure**: Monitor memory/resource usage from pending cleanup
//!
//! # Integration Points
//!
//! - Monitors cleanup queues across the runtime
//! - Tracks finalizer execution rates and completion times
//! - Provides early warning for potential resource exhaustion

use crate::types::{RegionId, TaskId, Time};
use parking_lot::RwLock;
use std::backtrace::Backtrace;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Configuration for the cancellation debt accumulation monitor.
#[derive(Debug, Clone)]
pub struct CancelDebtConfig {
    /// Maximum allowed debt before triggering violations.
    /// Debt is measured as pending cleanup work items.
    pub max_debt_items: usize,

    /// Time window for measuring processing rates.
    pub measurement_window_ns: u64,

    /// Threshold for debt accumulation rate (items per second).
    /// If debt accumulates faster than this, it's considered a violation.
    pub max_debt_rate_per_sec: f64,

    /// Maximum number of violations to track before dropping old ones.
    pub max_violations: usize,

    /// Whether to panic immediately on violations (vs just recording them).
    pub panic_on_violation: bool,

    /// Whether to capture stack traces for violations (expensive).
    pub capture_stack_traces: bool,

    /// Maximum depth of stack traces to capture.
    pub max_stack_trace_depth: usize,
}

impl Default for CancelDebtConfig {
    fn default() -> Self {
        Self {
            max_debt_items: 1000,
            measurement_window_ns: 10_000_000_000, // 10 seconds
            max_debt_rate_per_sec: 100.0,          // 100 items/second
            max_violations: 1000,
            panic_on_violation: false,
            capture_stack_traces: true,
            max_stack_trace_depth: 32,
        }
    }
}

/// A cancellation debt violation detected by the oracle.
#[derive(Debug, Clone)]
pub enum CancelDebtViolation {
    /// Debt exceeded the maximum allowed threshold.
    DebtThresholdExceeded {
        /// Current amount of accumulated debt.
        current_debt: usize,
        /// Maximum allowed debt threshold.
        max_debt: usize,
        /// Type of queue where debt threshold was exceeded.
        queue_type: String,
        /// Timestamp when threshold violation was detected.
        detected_at: Time,
        /// Optional stack trace captured at violation time.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Debt accumulation rate exceeded the maximum allowed rate.
    DebtAccumulationTooFast {
        /// Current rate at which debt is accumulating (items per second).
        current_rate: f64,
        /// Maximum allowed accumulation rate.
        max_rate: f64,
        /// Size of the measurement window in nanoseconds.
        window_size_ns: u64,
        /// Type of queue where debt accumulation rate was exceeded.
        queue_type: String,
        /// Timestamp when rate violation was detected.
        detected_at: Time,
        /// Optional stack trace captured at violation time.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Cleanup processing has stalled (no progress in expected timeframe).
    CleanupStall {
        /// Type of queue where cleanup has stalled.
        queue_type: String,
        /// Duration of the stall in nanoseconds.
        stall_duration_ns: u64,
        /// Number of items pending cleanup.
        pending_items: usize,
        /// Timestamp when stall was detected.
        detected_at: Time,
        /// Optional stack trace captured at stall detection time.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Resource pressure from accumulated cleanup work.
    ResourcePressure {
        /// Type of queue causing resource pressure.
        queue_type: String,
        /// Estimated memory usage from pending cleanup work.
        estimated_memory_bytes: usize,
        /// Current amount of accumulated cleanup debt.
        current_debt: usize,
        /// Timestamp when resource pressure was detected.
        detected_at: Time,
        /// Optional stack trace captured at pressure detection time.
        stack_trace: Option<Arc<Backtrace>>,
    },
}

impl fmt::Display for CancelDebtViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebtThresholdExceeded {
                current_debt,
                max_debt,
                queue_type,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Debt threshold exceeded: {} has {} items (max: {}) at {}",
                    queue_type,
                    current_debt,
                    max_debt,
                    detected_at.as_nanos()
                )
            }
            Self::DebtAccumulationTooFast {
                current_rate,
                max_rate,
                window_size_ns,
                queue_type,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Debt accumulating too fast: {} at {:.1} items/sec (max: {:.1}) over {}ns window at {}",
                    queue_type,
                    current_rate,
                    max_rate,
                    window_size_ns,
                    detected_at.as_nanos()
                )
            }
            Self::CleanupStall {
                queue_type,
                stall_duration_ns,
                pending_items,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Cleanup stall: {} stalled for {}ns with {} pending items at {}",
                    queue_type,
                    stall_duration_ns,
                    pending_items,
                    detected_at.as_nanos()
                )
            }
            Self::ResourcePressure {
                queue_type,
                estimated_memory_bytes,
                current_debt,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Resource pressure: {} using ~{} bytes for {} items at {}",
                    queue_type,
                    estimated_memory_bytes,
                    current_debt,
                    detected_at.as_nanos()
                )
            }
        }
    }
}

/// Information about a cleanup work item.
#[derive(Debug, Clone)]
struct CleanupWorkItem {
    task_id: Option<TaskId>,
    region_id: Option<RegionId>,
    work_type: CleanupWorkType,
    created_at: Time,
    estimated_size_bytes: usize,
}

/// Type of cleanup work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupWorkType {
    /// Finalizing cancelled tasks.
    TaskFinalization,
    /// Cleaning up closed regions.
    RegionCleanup,
    /// Discharging obligations and permits.
    ObligationDischarge,
    /// Deallocating resources and memory.
    ResourceDeallocation,
    /// Executing finalizer functions.
    FinalizerExecution,
}

/// Snapshot of a tracked cleanup work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupWorkItemSnapshot {
    /// Task associated with the cleanup item, if any.
    pub task_id: Option<TaskId>,
    /// Region associated with the cleanup item, if any.
    pub region_id: Option<RegionId>,
    /// Cleanup work type.
    pub work_type: CleanupWorkType,
    /// Stable work-type label.
    pub work_type_name: &'static str,
    /// Time when the cleanup work item was created.
    pub created_at: Time,
    /// Estimated memory footprint of the item.
    pub estimated_size_bytes: usize,
}

/// Snapshot of a tracked cleanup queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueDebtSnapshot {
    /// Queue identifier.
    pub queue_type: String,
    /// Number of pending work items.
    pub pending_items: usize,
    /// Estimated memory usage across pending work.
    pub estimated_memory_usage: usize,
    /// Work items currently pending in FIFO order.
    pub work_items: Vec<CleanupWorkItemSnapshot>,
}

impl CleanupWorkType {
    fn name(self) -> &'static str {
        match self {
            Self::TaskFinalization => "task_finalization",
            Self::RegionCleanup => "region_cleanup",
            Self::ObligationDischarge => "obligation_discharge",
            Self::ResourceDeallocation => "resource_deallocation",
            Self::FinalizerExecution => "finalizer_execution",
        }
    }

    fn estimated_size_bytes(self) -> usize {
        match self {
            Self::TaskFinalization => 200,     // Task record + metadata
            Self::RegionCleanup => 300,        // Region state + cleanup
            Self::ObligationDischarge => 150,  // Obligation tracking
            Self::ResourceDeallocation => 100, // Basic resource cleanup
            Self::FinalizerExecution => 250,   // Finalizer context + execution
        }
    }
}

/// Queue state tracking for a particular type of cleanup work.
#[derive(Debug)]
struct QueueState {
    queue_type: String,
    pending_items: VecDeque<CleanupWorkItem>,
    completion_times: VecDeque<(Time, usize)>, // (completion_time, items_completed)
    last_completion: Option<Time>,
    total_completed: u64,
}

impl QueueState {
    fn new(queue_type: String) -> Self {
        Self {
            queue_type,
            pending_items: VecDeque::new(),
            completion_times: VecDeque::new(),
            last_completion: None,
            total_completed: 0,
        }
    }

    fn add_work_item(&mut self, item: CleanupWorkItem) {
        self.pending_items.push_back(item);
    }

    fn complete_items(&mut self, count: usize, completion_time: Time) {
        let actual_completed = std::cmp::min(count, self.pending_items.len());
        for _ in 0..actual_completed {
            self.pending_items.pop_front();
        }

        self.completion_times
            .push_back((completion_time, actual_completed));
        self.last_completion = Some(completion_time);
        self.total_completed += actual_completed as u64;

        // Keep completion times bounded (last 1000 entries)
        while self.completion_times.len() > 1000 {
            self.completion_times.pop_front();
        }
    }

    fn current_debt(&self) -> usize {
        self.pending_items.len()
    }

    fn estimated_memory_usage(&self) -> usize {
        self.pending_items
            .iter()
            .map(|item| item.estimated_size_bytes)
            .sum()
    }

    fn completion_rate_over_window(&self, window_ns: u64, now: Time) -> f64 {
        if self.completion_times.is_empty() {
            return 0.0;
        }

        let cutoff_time = Time::from_nanos(now.as_nanos().saturating_sub(window_ns));
        let completions_in_window: usize = self
            .completion_times
            .iter()
            .filter(|(time, _)| *time >= cutoff_time)
            .map(|(_, count)| *count)
            .sum();

        let window_seconds = window_ns as f64 / 1_000_000_000.0;
        completions_in_window as f64 / window_seconds
    }

    fn debt_accumulation_rate(&self, window_ns: u64, now: Time) -> f64 {
        if self.pending_items.len() < 2 {
            return 0.0;
        }

        let cutoff_time = Time::from_nanos(now.as_nanos().saturating_sub(window_ns));
        let items_added_in_window = self
            .pending_items
            .iter()
            .filter(|item| item.created_at >= cutoff_time)
            .count();

        let completion_rate = self.completion_rate_over_window(window_ns, now);
        let window_seconds = window_ns as f64 / 1_000_000_000.0;
        let addition_rate = items_added_in_window as f64 / window_seconds;

        addition_rate - completion_rate
    }

    fn stall_duration(&self, now: Time) -> u64 {
        self.last_completion.map_or(0, |last| now.as_nanos().saturating_sub(last.as_nanos()))
    }
}

/// The cancellation debt accumulation monitor.
#[derive(Debug)]
pub struct CancelDebtOracle {
    config: CancelDebtConfig,

    /// Tracked queue states by queue type.
    queue_states: RwLock<HashMap<String, QueueState>>,

    /// Detected violations.
    violations: RwLock<VecDeque<CancelDebtViolation>>,

    /// Statistics counters.
    work_items_tracked: AtomicU64,
    completions_tracked: AtomicU64,
    violations_detected: AtomicU64,
    debt_checks_performed: AtomicU64,
}

impl Default for CancelDebtOracle {
    fn default() -> Self {
        Self::with_default_config()
    }
}

impl CancelDebtOracle {
    /// Creates a new cancellation debt oracle with the given configuration.
    #[must_use]
    pub fn new(config: CancelDebtConfig) -> Self {
        Self {
            config,
            queue_states: RwLock::new(HashMap::new()),
            violations: RwLock::new(VecDeque::new()),
            work_items_tracked: AtomicU64::new(0),
            completions_tracked: AtomicU64::new(0),
            violations_detected: AtomicU64::new(0),
            debt_checks_performed: AtomicU64::new(0),
        }
    }

    /// Creates a new oracle with default configuration.
    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(CancelDebtConfig::default())
    }

    /// Record a new cleanup work item being added to a queue.
    pub fn on_work_item_added(
        &self,
        queue_type: &str,
        task_id: Option<TaskId>,
        region_id: Option<RegionId>,
        work_type: CleanupWorkType,
        created_at: Time,
    ) {
        self.work_items_tracked.fetch_add(1, Ordering::Relaxed);

        let item = CleanupWorkItem {
            task_id,
            region_id,
            work_type: work_type.clone(),
            created_at,
            estimated_size_bytes: work_type.estimated_size_bytes(),
        };

        let mut states = self.queue_states.write();
        let state = states
            .entry(queue_type.to_string())
            .or_insert_with(|| QueueState::new(queue_type.to_string()));

        state.add_work_item(item);
    }

    /// Record completion of cleanup work items from a queue.
    pub fn on_work_items_completed(&self, queue_type: &str, count: usize, completion_time: Time) {
        self.completions_tracked
            .fetch_add(count as u64, Ordering::Relaxed);

        let mut states = self.queue_states.write();
        if let Some(state) = states.get_mut(queue_type) {
            state.complete_items(count, completion_time);
        }
    }

    /// Check for debt accumulation violations across all tracked queues.
    pub fn check_debt_accumulation(&self, now: Time) {
        self.debt_checks_performed.fetch_add(1, Ordering::Relaxed);

        let states = self.queue_states.read();
        for state in states.values() {
            self.check_queue_violations(state, now);
        }
    }

    /// Check for violations following the oracle pattern.
    pub fn check(&self, now: Time) -> Result<(), CancelDebtViolation> {
        // First check for new debt accumulation violations
        self.check_debt_accumulation(now);

        // Return the first violation if any exist
        let violations = self.violations.read();
        if let Some(violation) = violations.front() {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Reset the oracle to its initial state.
    pub fn reset(&self) {
        self.queue_states.write().clear();
        self.violations.write().clear();
        self.work_items_tracked.store(0, Ordering::Relaxed);
        self.completions_tracked.store(0, Ordering::Relaxed);
        self.violations_detected.store(0, Ordering::Relaxed);
        self.debt_checks_performed.store(0, Ordering::Relaxed);
    }

    /// Get statistics about oracle operation.
    pub fn get_statistics(&self) -> CancelDebtStatistics {
        let states = self.queue_states.read();
        let violations = self.violations.read();

        let total_debt: usize = states.values().map(|s| s.current_debt()).sum();
        let total_memory_usage: usize = states.values().map(|s| s.estimated_memory_usage()).sum();

        CancelDebtStatistics {
            work_items_tracked: self.work_items_tracked.load(Ordering::Relaxed),
            completions_tracked: self.completions_tracked.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            debt_checks_performed: self.debt_checks_performed.load(Ordering::Relaxed),
            tracked_queues: states.len(),
            total_current_debt: total_debt,
            total_estimated_memory_usage: total_memory_usage,
            total_violations: violations.len(),
        }
    }

    /// Get recent violations for debugging.
    pub fn get_recent_violations(&self, limit: usize) -> Vec<CancelDebtViolation> {
        let violations = self.violations.read();
        violations.iter().rev().take(limit).cloned().collect()
    }

    /// Get detailed queue states for debugging.
    pub fn get_queue_states(&self) -> Vec<(String, usize, usize)> {
        let states = self.queue_states.read();
        states
            .values()
            .map(|s| {
                (
                    s.queue_type.clone(),
                    s.current_debt(),
                    s.estimated_memory_usage(),
                )
            })
            .collect()
    }

    /// Get detailed queue state snapshots including pending work metadata.
    pub fn get_queue_state_snapshots(&self) -> Vec<QueueDebtSnapshot> {
        let states = self.queue_states.read();
        let mut snapshots = states
            .values()
            .map(|state| QueueDebtSnapshot {
                queue_type: state.queue_type.clone(),
                pending_items: state.current_debt(),
                estimated_memory_usage: state.estimated_memory_usage(),
                work_items: state
                    .pending_items
                    .iter()
                    .map(|item| CleanupWorkItemSnapshot {
                        task_id: item.task_id,
                        region_id: item.region_id,
                        work_type: item.work_type,
                        work_type_name: item.work_type.name(),
                        created_at: item.created_at,
                        estimated_size_bytes: item.estimated_size_bytes,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        snapshots.sort_by(|a, b| a.queue_type.cmp(&b.queue_type));
        snapshots
    }

    fn check_queue_violations(&self, state: &QueueState, now: Time) {
        // Check debt threshold violation
        let current_debt = state.current_debt();
        if current_debt > self.config.max_debt_items {
            let violation = CancelDebtViolation::DebtThresholdExceeded {
                current_debt,
                max_debt: self.config.max_debt_items,
                queue_type: state.queue_type.clone(),
                detected_at: now,
                stack_trace: self.capture_stack_trace(),
            };
            self.record_violation(violation);
        }

        // Check debt accumulation rate
        let debt_rate = state.debt_accumulation_rate(self.config.measurement_window_ns, now);
        if debt_rate > self.config.max_debt_rate_per_sec {
            let violation = CancelDebtViolation::DebtAccumulationTooFast {
                current_rate: debt_rate,
                max_rate: self.config.max_debt_rate_per_sec,
                window_size_ns: self.config.measurement_window_ns,
                queue_type: state.queue_type.clone(),
                detected_at: now,
                stack_trace: self.capture_stack_trace(),
            };
            self.record_violation(violation);
        }

        // Check for cleanup stalls (only if we have pending work)
        if current_debt > 0 {
            let stall_duration = state.stall_duration(now);
            // Consider it a stall if no progress for more than 2x the measurement window
            if stall_duration > self.config.measurement_window_ns * 2 {
                let violation = CancelDebtViolation::CleanupStall {
                    queue_type: state.queue_type.clone(),
                    stall_duration_ns: stall_duration,
                    pending_items: current_debt,
                    detected_at: now,
                    stack_trace: self.capture_stack_trace(),
                };
                self.record_violation(violation);
            }
        }

        // Check resource pressure (warn if using > 1MB)
        let memory_usage = state.estimated_memory_usage();
        if memory_usage > 1_048_576 {
            // 1MB threshold
            let violation = CancelDebtViolation::ResourcePressure {
                queue_type: state.queue_type.clone(),
                estimated_memory_bytes: memory_usage,
                current_debt,
                detected_at: now,
                stack_trace: self.capture_stack_trace(),
            };
            self.record_violation(violation);
        }
    }

    fn record_violation(&self, violation: CancelDebtViolation) {
        self.violations_detected.fetch_add(1, Ordering::Relaxed);

        if self.config.panic_on_violation {
            panic!("Cancellation debt violation detected: {}", violation);
        }

        // Record violation for later inspection
        let mut violations = self.violations.write();
        violations.push_back(violation);

        // Keep violations bounded
        while violations.len() > self.config.max_violations {
            violations.pop_front();
        }
    }

    fn capture_stack_trace(&self) -> Option<Arc<Backtrace>> {
        if self.config.capture_stack_traces {
            Some(Arc::new(Backtrace::capture()))
        } else {
            None
        }
    }
}

/// Statistics about cancel debt oracle operation.
#[derive(Debug, Clone)]
pub struct CancelDebtStatistics {
    /// Number of work items tracked.
    pub work_items_tracked: u64,
    /// Number of completions tracked.
    pub completions_tracked: u64,
    /// Number of violations detected.
    pub violations_detected: u64,
    /// Number of debt checks performed.
    pub debt_checks_performed: u64,
    /// Number of queues currently tracked.
    pub tracked_queues: usize,
    /// Total current debt across all queues.
    pub total_current_debt: usize,
    /// Estimated total memory usage of pending work.
    pub total_estimated_memory_usage: usize,
    /// Total number of violations recorded.
    pub total_violations: usize,
}

impl fmt::Display for CancelDebtStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CancelDebtStats {{ work_items: {}, completions: {}, violations: {}, checks: {}, queues: {}, debt: {}, memory: {}KB, total_violations: {} }}",
            self.work_items_tracked,
            self.completions_tracked,
            self.violations_detected,
            self.debt_checks_performed,
            self.tracked_queues,
            self.total_current_debt,
            self.total_estimated_memory_usage / 1024,
            self.total_violations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    #[test]
    fn test_normal_operation_no_violations() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();
        let now = Time::ZERO;

        // Add some work items
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            now,
        );

        // Complete them quickly
        oracle.on_work_items_completed("finalizers", 1, Time::from_nanos(1000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.work_items_tracked, 1);
        assert_eq!(stats.completions_tracked, 1);
    }

    #[test]
    fn test_debt_threshold_violation() {
        init_test_logging();

        let config = CancelDebtConfig {
            max_debt_items: 5, // Low threshold for testing
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);
        let now = Time::ZERO;

        // Add more items than the threshold
        for i in 0..10 {
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 1000),
            );
        }

        // Check for violations
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(!violations.is_empty());
        assert!(matches!(
            violations[0],
            CancelDebtViolation::DebtThresholdExceeded { .. }
        ));
    }

    #[test]
    fn test_debt_accumulation_rate_violation() {
        init_test_logging();

        let config = CancelDebtConfig {
            max_debt_rate_per_sec: 1.0,           // Very low rate for testing
            measurement_window_ns: 1_000_000_000, // 1 second
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);

        // Add items rapidly without completing them
        for i in 0..10 {
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 100_000_000), // 100ms intervals
            );
        }

        let now = Time::from_nanos(2_000_000_000); // 2 seconds later
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(!violations.is_empty());
        // Should have both threshold and rate violations
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::DebtAccumulationTooFast { .. }))
        );
    }

    #[test]
    fn test_cleanup_stall_detection() {
        init_test_logging();

        let config = CancelDebtConfig {
            measurement_window_ns: 1_000_000_000, // 1 second
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);

        // Add some work
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::ZERO,
        );

        // Complete one item initially
        oracle.on_work_items_completed("finalizers", 1, Time::from_nanos(100_000_000));

        // Add more work but don't complete it
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::new_for_test(2, 0)),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::from_nanos(500_000_000),
        );

        // Check after a long stall (3 seconds later)
        let now = Time::from_nanos(3_500_000_000);
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::CleanupStall { .. }))
        );
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation by exceeding threshold
        for i in 0..1500 {
            // Above default threshold of 1000
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 1000),
            );
        }

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Add some state and violations
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::ZERO,
        );

        let stats_before = oracle.get_statistics();
        assert!(stats_before.work_items_tracked > 0);

        // Reset should clear everything
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.work_items_tracked, 0);
        assert_eq!(stats_after.completions_tracked, 0);
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.tracked_queues, 0);
        assert_eq!(stats_after.total_current_debt, 0);
    }

    #[test]
    fn test_resource_pressure_detection() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Add many large work items to trigger memory pressure
        for i in 0..5000 {
            oracle.on_work_item_added(
                "large_finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution, // ~250 bytes each
                Time::from_nanos(i * 1000),
            );
        }

        oracle.check_debt_accumulation(Time::ZERO);

        let violations = oracle.get_recent_violations(10);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::ResourcePressure { .. }))
        );
    }

    #[test]
    fn test_queue_state_snapshots_expose_pending_work_metadata() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();
        let task_id = TaskId::new_for_test(11, 0);
        let region_id = RegionId::testing_default();
        let created_at = Time::from_nanos(42);

        oracle.on_work_item_added(
            "finalizers",
            Some(task_id),
            Some(region_id),
            CleanupWorkType::FinalizerExecution,
            created_at,
        );

        let snapshots = oracle.get_queue_state_snapshots();
        assert_eq!(snapshots.len(), 1);

        let queue = &snapshots[0];
        assert_eq!(queue.queue_type, "finalizers");
        assert_eq!(queue.pending_items, 1);
        assert_eq!(queue.work_items.len(), 1);

        let item = &queue.work_items[0];
        assert_eq!(item.task_id, Some(task_id));
        assert_eq!(item.region_id, Some(region_id));
        assert_eq!(item.work_type, CleanupWorkType::FinalizerExecution);
        assert_eq!(item.work_type_name, "finalizer_execution");
        assert_eq!(item.created_at, created_at);
        assert_eq!(
            item.estimated_size_bytes,
            CleanupWorkType::FinalizerExecution.estimated_size_bytes()
        );
        assert_eq!(queue.estimated_memory_usage, item.estimated_size_bytes);
    }
}
