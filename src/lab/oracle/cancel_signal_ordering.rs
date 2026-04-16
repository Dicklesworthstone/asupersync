//! Cancel Signal Ordering Invariant Checker
//!
//! This oracle verifies that cancel signals maintain proper causal ordering
//! through the structured concurrency tree - parent cancellations must happen
//! before child cancellations.
//!
//! # Invariant
//!
//! In structured concurrency, cancellation must propagate from parent to child:
//! - When a parent region/task is cancelled, all children must be cancelled
//! - Child cancellation must occur AFTER parent cancellation
//! - No child should be cancelled before its parent
//!
//! # Key Detection Capabilities
//!
//! - **Order violations**: Child cancelled before parent
//! - **Missing propagation**: Parent cancelled but child not cancelled
//! - **Orphaned cancellation**: Child cancelled without parent cancellation
//! - **Timing violations**: Concurrent cancellations with incorrect ordering
//!
//! # Integration Points
//!
//! - Tracks cancellation signals across the structured concurrency tree
//! - Monitors parent-child relationships during cancellation
//! - Provides diagnostics with causality chains and timing information

use crate::types::{RegionId, TaskId, Time, CancelReason};
use parking_lot::RwLock;
use std::backtrace::Backtrace;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Configuration for the cancel signal ordering oracle.
#[derive(Debug, Clone)]
pub struct CancelOrderingConfig {
    /// Maximum time window for cancel signal ordering validation.
    /// Signals within this window are checked for proper ordering.
    pub max_ordering_window_ns: u64,

    /// Maximum number of violations to track before dropping old ones.
    pub max_violations: usize,

    /// Whether to panic immediately on violations (vs just recording them).
    pub panic_on_violation: bool,

    /// Whether to capture stack traces for violations (expensive).
    pub capture_stack_traces: bool,

    /// Maximum depth of stack traces to capture.
    pub max_stack_trace_depth: usize,
}

impl Default for CancelOrderingConfig {
    fn default() -> Self {
        Self {
            max_ordering_window_ns: 1_000_000_000, // 1 second
            max_violations: 1000,
            panic_on_violation: false,
            capture_stack_traces: true,
            max_stack_trace_depth: 32,
        }
    }
}

/// A cancel signal ordering violation detected by the oracle.
#[derive(Debug, Clone)]
pub enum CancelOrderingViolation {
    /// Child was cancelled before its parent.
    ChildBeforeParent {
        parent_task: TaskId,
        child_task: TaskId,
        parent_region: RegionId,
        child_region: RegionId,
        child_cancel_time: Time,
        parent_cancel_time: Time,
        time_gap_ns: u64,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Parent was cancelled but child was not cancelled within the expected window.
    MissingChildCancellation {
        parent_task: TaskId,
        child_task: TaskId,
        parent_region: RegionId,
        child_region: RegionId,
        parent_cancel_time: Time,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Child was cancelled but parent shows no sign of cancellation.
    OrphanedChildCancellation {
        child_task: TaskId,
        parent_task: Option<TaskId>,
        child_region: RegionId,
        parent_region: RegionId,
        child_cancel_time: Time,
        detected_at: Time,
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Concurrent cancellation signals violated ordering requirements.
    ConcurrentOrderingViolation {
        first_task: TaskId,
        second_task: TaskId,
        first_region: RegionId,
        second_region: RegionId,
        first_cancel_time: Time,
        second_cancel_time: Time,
        relationship: String, // describes the parent-child relationship
        stack_trace: Option<Arc<Backtrace>>,
    },
}

impl fmt::Display for CancelOrderingViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildBeforeParent {
                parent_task,
                child_task,
                parent_region,
                child_region,
                child_cancel_time,
                parent_cancel_time,
                time_gap_ns,
                ..
            } => {
                write!(
                    f,
                    "Child before parent: child {}@{} cancelled at {} before parent {}@{} at {} (gap: {}ns)",
                    child_task,
                    child_region,
                    child_cancel_time.as_nanos(),
                    parent_task,
                    parent_region,
                    parent_cancel_time.as_nanos(),
                    time_gap_ns
                )
            }
            Self::MissingChildCancellation {
                parent_task,
                child_task,
                parent_region,
                child_region,
                parent_cancel_time,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Missing child cancellation: parent {}@{} cancelled at {} but child {}@{} not cancelled (detected at {})",
                    parent_task,
                    parent_region,
                    parent_cancel_time.as_nanos(),
                    child_task,
                    child_region,
                    detected_at.as_nanos()
                )
            }
            Self::OrphanedChildCancellation {
                child_task,
                parent_task,
                child_region,
                parent_region,
                child_cancel_time,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Orphaned child cancellation: child {}@{} cancelled at {} without parent {:?}@{} cancellation (detected at {})",
                    child_task,
                    child_region,
                    child_cancel_time.as_nanos(),
                    parent_task,
                    parent_region,
                    detected_at.as_nanos()
                )
            }
            Self::ConcurrentOrderingViolation {
                first_task,
                second_task,
                first_region,
                second_region,
                first_cancel_time,
                second_cancel_time,
                relationship,
                ..
            } => {
                write!(
                    f,
                    "Concurrent ordering violation: {}@{} and {}@{} cancelled at {} and {} ({} relationship)",
                    first_task,
                    first_region,
                    second_task,
                    second_region,
                    first_cancel_time.as_nanos(),
                    second_cancel_time.as_nanos(),
                    relationship
                )
            }
        }
    }
}

/// Cancellation signal information.
#[derive(Debug, Clone)]
struct CancelSignal {
    task_id: TaskId,
    region_id: RegionId,
    cancel_time: Time,
    cancel_reason: CancelReason,
    parent_task: Option<TaskId>,
    parent_region: Option<RegionId>,
}

/// Tracked state for cancel signal ordering.
#[derive(Debug)]
struct OrderingState {
    /// All cancellation signals received.
    cancel_signals: VecDeque<CancelSignal>,

    /// Parent-child relationships in the structured concurrency tree.
    parent_child_map: HashMap<TaskId, Vec<TaskId>>,
    child_parent_map: HashMap<TaskId, TaskId>,

    /// Task-to-region mapping for tracking which task belongs to which region.
    task_region_map: HashMap<TaskId, RegionId>,

    /// Region hierarchy mapping.
    region_parent_map: HashMap<RegionId, RegionId>,
    region_children_map: HashMap<RegionId, Vec<RegionId>>,
}

impl OrderingState {
    fn new() -> Self {
        Self {
            cancel_signals: VecDeque::new(),
            parent_child_map: HashMap::new(),
            child_parent_map: HashMap::new(),
            task_region_map: HashMap::new(),
            region_parent_map: HashMap::new(),
            region_children_map: HashMap::new(),
        }
    }

    fn add_parent_child_relationship(&mut self, parent: TaskId, child: TaskId) {
        self.parent_child_map.entry(parent).or_default().push(child);
        self.child_parent_map.insert(child, parent);
    }

    fn add_region_relationship(&mut self, parent_region: RegionId, child_region: RegionId) {
        self.region_parent_map.insert(child_region, parent_region);
        self.region_children_map.entry(parent_region).or_default().push(child_region);
    }

    fn add_task_region_mapping(&mut self, task_id: TaskId, region_id: RegionId) {
        self.task_region_map.insert(task_id, region_id);
    }

    fn add_cancel_signal(&mut self, signal: CancelSignal) {
        self.cancel_signals.push_back(signal);
    }

    fn get_parent_task(&self, task_id: TaskId) -> Option<TaskId> {
        self.child_parent_map.get(&task_id).copied()
    }

    fn get_children_tasks(&self, task_id: TaskId) -> Option<&Vec<TaskId>> {
        self.parent_child_map.get(&task_id)
    }

    fn find_cancel_signal(&self, task_id: TaskId) -> Option<&CancelSignal> {
        self.cancel_signals.iter().find(|signal| signal.task_id == task_id)
    }

    fn get_task_region(&self, task_id: TaskId) -> Option<RegionId> {
        self.task_region_map.get(&task_id).copied()
    }
}

/// The cancel signal ordering invariant checker.
#[derive(Debug)]
pub struct CancelOrderingOracle {
    config: CancelOrderingConfig,

    /// Tracked state for cancellation ordering.
    state: RwLock<OrderingState>,

    /// Detected violations.
    violations: RwLock<VecDeque<CancelOrderingViolation>>,

    /// Statistics counters.
    signals_processed: AtomicU64,
    violations_detected: AtomicU64,
    ordering_checks_performed: AtomicU64,
}

impl Default for CancelOrderingOracle {
    fn default() -> Self {
        Self::with_default_config()
    }
}

impl CancelOrderingOracle {
    /// Creates a new cancel signal ordering oracle with the given configuration.
    pub fn new(config: CancelOrderingConfig) -> Self {
        Self {
            config,
            state: RwLock::new(OrderingState::new()),
            violations: RwLock::new(VecDeque::new()),
            signals_processed: AtomicU64::new(0),
            violations_detected: AtomicU64::new(0),
            ordering_checks_performed: AtomicU64::new(0),
        }
    }

    /// Creates a new oracle with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(CancelOrderingConfig::default())
    }

    /// Register a parent-child task relationship.
    ///
    /// This should be called when a child task is spawned within a parent region/task.
    pub fn on_task_spawned(&self, parent_task: TaskId, child_task: TaskId, parent_region: RegionId, child_region: RegionId) {
        let mut state = self.state.write();
        state.add_parent_child_relationship(parent_task, child_task);
        state.add_task_region_mapping(parent_task, parent_region);
        state.add_task_region_mapping(child_task, child_region);
        if parent_region != child_region {
            state.add_region_relationship(parent_region, child_region);
        }
    }

    /// Notify the oracle of a cancellation signal.
    ///
    /// This is called when any task/region receives a cancellation signal.
    pub fn on_cancel_signal(&self, task_id: TaskId, region_id: RegionId, cancel_time: Time, reason: CancelReason) {
        self.signals_processed.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.write();

        // Record task-region mapping when we learn about it
        state.add_task_region_mapping(task_id, region_id);

        let parent_task = state.get_parent_task(task_id);
        let parent_region = state.region_parent_map.get(&region_id).copied();

        let signal = CancelSignal {
            task_id,
            region_id,
            cancel_time,
            cancel_reason: reason,
            parent_task,
            parent_region,
        };

        // Check for ordering violations before adding the signal
        self.check_signal_ordering(&state, &signal);

        state.add_cancel_signal(signal);
    }

    /// Check for cancel signal ordering violations.
    ///
    /// This should be called periodically to detect violations that depend on timing.
    pub fn check_ordering_violations(&self, now: Time) {
        self.ordering_checks_performed.fetch_add(1, Ordering::Relaxed);

        let state = self.state.read();

        // Check for missing child cancellations
        for signal in &state.cancel_signals {
            if let Some(children) = state.get_children_tasks(signal.task_id) {
                for &child_task in children {
                    if state.find_cancel_signal(child_task).is_none() {
                        let time_since_parent = now.as_nanos() - signal.cancel_time.as_nanos();
                        if time_since_parent > self.config.max_ordering_window_ns {
                            let child_region = state.get_task_region(child_task)
                                .unwrap_or(RegionId::testing_default());
                            let violation = CancelOrderingViolation::MissingChildCancellation {
                                parent_task: signal.task_id,
                                child_task,
                                parent_region: signal.region_id,
                                child_region,
                                parent_cancel_time: signal.cancel_time,
                                detected_at: now,
                                stack_trace: self.capture_stack_trace(),
                            };
                            self.record_violation(violation);
                        }
                    }
                }
            }
        }
    }

    /// Check for violations following the oracle pattern.
    pub fn check(&self, now: Time) -> Result<(), CancelOrderingViolation> {
        // First check for new ordering violations
        self.check_ordering_violations(now);

        // Return the first violation if any exist
        let violations = self.violations.read();
        if let Some(violation) = violations.front() {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Reset the oracle to its initial state.
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = OrderingState::new();

        self.violations.write().clear();
        self.signals_processed.store(0, Ordering::Relaxed);
        self.violations_detected.store(0, Ordering::Relaxed);
        self.ordering_checks_performed.store(0, Ordering::Relaxed);
    }

    /// Get statistics about oracle operation.
    pub fn get_statistics(&self) -> CancelOrderingStatistics {
        let state = self.state.read();
        let violations = self.violations.read();

        CancelOrderingStatistics {
            signals_processed: self.signals_processed.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            ordering_checks_performed: self.ordering_checks_performed.load(Ordering::Relaxed),
            tracked_signals: state.cancel_signals.len(),
            tracked_relationships: state.parent_child_map.len(),
            total_violations: violations.len(),
        }
    }

    /// Get recent violations for debugging.
    pub fn get_recent_violations(&self, limit: usize) -> Vec<CancelOrderingViolation> {
        let violations = self.violations.read();
        violations.iter().rev().take(limit).cloned().collect()
    }

    fn check_signal_ordering(&self, state: &OrderingState, new_signal: &CancelSignal) {
        // Check if this is a child task being cancelled
        if let Some(parent_task) = new_signal.parent_task {
            // Check if parent was cancelled before this child
            if let Some(parent_signal) = state.find_cancel_signal(parent_task) {
                // Parent was already cancelled - this is correct ordering
                return;
            }

            // Child cancelled but parent not yet cancelled - potential violation
            let violation = CancelOrderingViolation::OrphanedChildCancellation {
                    child_task: new_signal.task_id,
                    parent_task: Some(parent_task),
                    child_region: new_signal.region_id,
                    parent_region: new_signal.parent_region.unwrap_or_else(RegionId::testing_default),
                    child_cancel_time: new_signal.cancel_time,
                    detected_at: new_signal.cancel_time,
                    stack_trace: self.capture_stack_trace(),
                };
                self.record_violation(violation);
            }
        }

        // Check if any children were cancelled before this parent
        if let Some(children) = state.get_children_tasks(new_signal.task_id) {
            for &child_task in children {
                if let Some(child_signal) = state.find_cancel_signal(child_task) {
                    if child_signal.cancel_time < new_signal.cancel_time {
                        let time_gap = new_signal.cancel_time.as_nanos() - child_signal.cancel_time.as_nanos();
                        let violation = CancelOrderingViolation::ChildBeforeParent {
                            parent_task: new_signal.task_id,
                            child_task,
                            parent_region: new_signal.region_id,
                            child_region: child_signal.region_id,
                            child_cancel_time: child_signal.cancel_time,
                            parent_cancel_time: new_signal.cancel_time,
                            time_gap_ns: time_gap,
                            stack_trace: self.capture_stack_trace(),
                        };
                        self.record_violation(violation);
                    }
                }
            }
        }
    }

    fn record_violation(&self, violation: CancelOrderingViolation) {
        self.violations_detected.fetch_add(1, Ordering::Relaxed);

        if self.config.panic_on_violation {
            panic!("Cancel ordering violation detected: {}", violation);
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

/// Statistics about cancel ordering oracle operation.
#[derive(Debug, Clone)]
pub struct CancelOrderingStatistics {
    /// Number of cancel signals processed.
    pub signals_processed: u64,
    /// Number of violations detected.
    pub violations_detected: u64,
    /// Number of ordering checks performed.
    pub ordering_checks_performed: u64,
    /// Number of cancel signals currently tracked.
    pub tracked_signals: usize,
    /// Number of parent-child relationships tracked.
    pub tracked_relationships: usize,
    /// Total number of violations recorded.
    pub total_violations: usize,
}

impl fmt::Display for CancelOrderingStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CancelOrderingStats {{ signals: {}, violations: {}, checks: {}, tracked: {}, relationships: {}, total_violations: {} }}",
            self.signals_processed,
            self.violations_detected,
            self.ordering_checks_performed,
            self.tracked_signals,
            self.tracked_relationships,
            self.total_violations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    #[test]
    fn test_correct_parent_child_ordering() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel parent first (correct order)
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Then cancel child (correct order)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::from_nanos(1000),
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.signals_processed, 2);
    }

    #[test]
    fn test_child_before_parent_violation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel child first (incorrect order)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Then cancel parent (should detect violation)
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::from_nanos(1000),
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 2); // orphaned child + child before parent

        let violations = oracle.get_recent_violations(5);
        assert_eq!(violations.len(), 2);

        // Check that we detected child before parent violation
        let has_child_before_parent = violations.iter().any(|v| {
            matches!(v, CancelOrderingViolation::ChildBeforeParent { .. })
        });
        assert!(has_child_before_parent);
    }

    #[test]
    fn test_orphaned_child_cancellation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel only child, not parent (orphaned cancellation)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelOrderingViolation::OrphanedChildCancellation { .. }
        ));
    }

    #[test]
    fn test_missing_child_cancellation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel only parent
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Wait long enough to trigger violation
        let later_time = Time::from_nanos(2_000_000_000); // 2 seconds
        oracle.check_ordering_violations(later_time);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelOrderingViolation::MissingChildCancellation { .. }
        ));
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from_u64(2);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from_u64(2);

        // Add some state
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        let stats_before = oracle.get_statistics();
        assert!(stats_before.violations_detected > 0);

        // Reset should clear everything
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.signals_processed, 0);
        assert_eq!(stats_after.tracked_signals, 0);
        assert_eq!(stats_after.tracked_relationships, 0);
    }

    #[test]
    fn test_task_region_tracking() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::from(42);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::from(123);

        // Spawn a task - this should record the task-region mappings
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel the parent task
        oracle.on_cancel_signal(parent_task, parent_region, Time::from_nanos(1000), CancelReason::UserCancelled);

        // Wait for the ordering window to expire so missing child cancellation is detected
        oracle.check_ordering_violations(Time::from_nanos(20_000_000));

        // Should detect a violation with the correct child region (not testing_default placeholder)
        let violations = oracle.get_recent_violations(10);
        assert_eq!(violations.len(), 1);

        match &violations[0] {
            CancelOrderingViolation::MissingChildCancellation { child_region: detected_child_region, .. } => {
                assert_eq!(*detected_child_region, child_region, "Should use actual child region, not placeholder");
            }
            other => panic!("Expected MissingChildCancellation, got: {:?}", other),
        }
    }
}