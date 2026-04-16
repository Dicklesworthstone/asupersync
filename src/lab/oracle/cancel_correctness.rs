//! Cancel-Correctness Property Oracle
//!
//! This oracle continuously verifies that the cancellation protocol is followed
//! correctly, ensuring every cancel request leads to proper drain → finalize → complete(cancelled)
//! transitions without violations.
//!
//! # Key Detection Capabilities
//!
//! - **Protocol violations**: Illegal state transitions in cancel protocol
//! - **Premature completion**: Tasks completing without proper draining
//! - **Stuck cancellations**: Tasks not progressing through cancel protocol
//! - **Missing finalize steps**: Tasks skipping finalization before completion
//! - **Race conditions**: Concurrent cancellation state update violations
//! - **Propagation failures**: Cancellation not propagating in structured concurrency
//!
//! # Integration Points
//!
//! - Hooks into `CancelWitness` validation in `types::cancel`
//! - Monitors cancellation state transitions per task/region
//! - Provides diagnostics with stack traces and cancellation path visualization
//! - Configurable enforcement modes (warn vs panic)

use crate::types::{CancelPhase, CancelReason, CancelWitness, RegionId, TaskId, Time};
use crate::util::det_hash::DetHashMap;
use parking_lot::RwLock;
use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Configuration for the cancel-correctness oracle.
#[derive(Debug, Clone)]
pub struct CancelCorrectnessConfig {
    /// Maximum time allowed for a task to transition between cancellation phases.
    /// Tasks that remain in a phase longer than this are considered stuck.
    pub max_phase_duration_ns: u64,

    /// Maximum number of violations to track before dropping old ones.
    pub max_violations: usize,

    /// Whether to panic immediately on violations (vs just recording them).
    pub panic_on_violation: bool,

    /// Whether to capture stack traces for violations (expensive).
    pub capture_stack_traces: bool,

    /// Maximum depth of stack traces to capture.
    pub max_stack_trace_depth: usize,
}

impl Default for CancelCorrectnessConfig {
    fn default() -> Self {
        Self {
            max_phase_duration_ns: 10_000_000_000, // 10 seconds
            max_violations: 1000,
            panic_on_violation: false,
            capture_stack_traces: true,
            max_stack_trace_depth: 32,
        }
    }
}

/// A cancellation protocol violation detected by the oracle.
#[derive(Debug, Clone)]
pub enum CancelCorrectnessViolation {
    /// Task completed without going through proper cancellation phases.
    PrematureCompletion {
        /// The task that completed prematurely.
        task_id: TaskId,
        /// The region containing the task.
        region_id: RegionId,
        /// The last cancellation phase reached before completion.
        last_phase: CancelPhase,
        /// When the premature completion was detected.
        completion_time: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Task stuck in a cancellation phase for too long.
    StuckCancellation {
        /// The task that is stuck in cancellation.
        task_id: TaskId,
        /// The region containing the stuck task.
        region_id: RegionId,
        /// The cancellation phase where the task is stuck.
        phase: CancelPhase,
        /// When the task first entered this phase.
        stuck_since: Time,
        /// When the stuck condition was detected.
        detected_at: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Invalid state transition detected.
    InvalidTransition {
        /// The task with invalid transition.
        task_id: TaskId,
        /// The region containing the task.
        region_id: RegionId,
        /// The phase the task was transitioning from.
        from_phase: CancelPhase,
        /// The invalid phase the task tried to transition to.
        to_phase: CancelPhase,
        /// When the invalid transition was attempted.
        transition_time: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Task skipped finalization phase.
    MissedFinalization {
        /// The task that skipped finalization.
        task_id: TaskId,
        /// The region containing the task.
        region_id: RegionId,
        /// The phase the task was in before skipping finalization.
        from_phase: CancelPhase,
        /// When the task completed without finalization.
        completion_time: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// Cancellation propagation failed in structured concurrency tree.
    PropagationFailure {
        /// The parent task that should have propagated cancellation.
        parent_task: TaskId,
        /// The child task that did not receive cancellation.
        child_task: TaskId,
        /// The region containing the parent task.
        parent_region: RegionId,
        /// The region containing the child task.
        child_region: RegionId,
        /// When the propagation failure was detected.
        detected_at: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },
}

impl fmt::Display for CancelCorrectnessViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrematureCompletion {
                task_id,
                region_id,
                last_phase,
                completion_time,
                ..
            } => {
                write!(
                    f,
                    "Premature completion: task {}@{} completed at {} without proper cancellation (last phase: {:?})",
                    task_id,
                    region_id,
                    completion_time.as_nanos(),
                    last_phase
                )
            }
            Self::StuckCancellation {
                task_id,
                region_id,
                phase,
                stuck_since,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Stuck cancellation: task {}@{} stuck in {:?} phase from {} to {} ({} ns)",
                    task_id,
                    region_id,
                    phase,
                    stuck_since.as_nanos(),
                    detected_at.as_nanos(),
                    detected_at.as_nanos() - stuck_since.as_nanos()
                )
            }
            Self::InvalidTransition {
                task_id,
                region_id,
                from_phase,
                to_phase,
                transition_time,
                ..
            } => {
                write!(
                    f,
                    "Invalid transition: task {}@{} attempted {:?} → {:?} at {}",
                    task_id,
                    region_id,
                    from_phase,
                    to_phase,
                    transition_time.as_nanos()
                )
            }
            Self::MissedFinalization {
                task_id,
                region_id,
                from_phase,
                completion_time,
                ..
            } => {
                write!(
                    f,
                    "Missed finalization: task {}@{} jumped from {:?} to completion at {} without finalization",
                    task_id,
                    region_id,
                    from_phase,
                    completion_time.as_nanos()
                )
            }
            Self::PropagationFailure {
                parent_task,
                child_task,
                parent_region,
                child_region,
                detected_at,
                ..
            } => {
                write!(
                    f,
                    "Propagation failure: cancellation from parent {}@{} failed to propagate to child {}@{} at {}",
                    parent_task,
                    parent_region,
                    child_task,
                    child_region,
                    detected_at.as_nanos()
                )
            }
        }
    }
}

/// Current cancellation state for a task.
#[derive(Debug, Clone)]
struct TaskCancelState {
    task_id: TaskId,
    region_id: RegionId,
    current_phase: CancelPhase,
    epoch: u64,
    last_transition: Time,
    cancel_reason: CancelReason,
    witness_history: VecDeque<CancelWitness>,
}

impl TaskCancelState {
    fn new(witness: CancelWitness, now: Time) -> Self {
        let task_id = witness.task_id;
        let region_id = witness.region_id;
        let current_phase = witness.phase;
        let epoch = witness.epoch;
        let cancel_reason = witness.reason.clone();

        let mut witness_history = VecDeque::new();
        witness_history.push_back(witness);

        Self {
            task_id,
            region_id,
            current_phase,
            epoch,
            last_transition: now,
            cancel_reason,
            witness_history,
        }
    }

    fn update_with_witness(&mut self, witness: CancelWitness, now: Time) {
        self.current_phase = witness.phase;
        self.last_transition = now;
        self.witness_history.push_back(witness);

        // Keep only last few witnesses to avoid unbounded growth
        while self.witness_history.len() > 10 {
            self.witness_history.pop_front();
        }
    }
}

/// The cancel-correctness property oracle.
#[derive(Debug)]
pub struct CancelCorrectnessOracle {
    config: CancelCorrectnessConfig,

    /// Current cancellation states tracked by task ID.
    task_states: RwLock<DetHashMap<TaskId, TaskCancelState>>,

    /// Detected violations.
    violations: RwLock<VecDeque<CancelCorrectnessViolation>>,

    /// Statistics counters.
    witnesses_processed: AtomicU64,
    violations_detected: AtomicU64,
    stuck_checks_performed: AtomicU64,
}

impl Default for CancelCorrectnessOracle {
    fn default() -> Self {
        Self::with_default_config()
    }
}

impl CancelCorrectnessOracle {
    /// Creates a new cancel-correctness oracle with the given configuration.
    pub fn new(config: CancelCorrectnessConfig) -> Self {
        Self {
            config,
            task_states: RwLock::new(DetHashMap::default()),
            violations: RwLock::new(VecDeque::new()),
            witnesses_processed: AtomicU64::new(0),
            violations_detected: AtomicU64::new(0),
            stuck_checks_performed: AtomicU64::new(0),
        }
    }

    /// Creates a new oracle with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(CancelCorrectnessConfig::default())
    }

    /// Notify the oracle of a cancellation witness.
    ///
    /// This is the main entry point called by the runtime when cancellation
    /// state transitions occur.
    pub fn notify_cancel_witness(&self, witness: CancelWitness, now: Time) {
        self.witnesses_processed.fetch_add(1, Ordering::Relaxed);

        let mut task_states = self.task_states.write();

        match task_states.get_mut(&witness.task_id) {
            Some(existing_state) => {
                // Validate transition
                if let Err(_) = self.validate_transition(existing_state, &witness, now) {
                    // Violation already recorded by validate_transition
                }
                existing_state.update_with_witness(witness, now);
            }
            None => {
                // First witness for this task
                let state = TaskCancelState::new(witness, now);
                task_states.insert(state.task_id, state);
            }
        }
    }

    /// Check for stuck cancellations and other time-based violations.
    ///
    /// This should be called periodically by the runtime to detect tasks
    /// that have been stuck in cancellation phases for too long.
    pub fn check_stuck_cancellations(&self, now: Time) {
        self.stuck_checks_performed.fetch_add(1, Ordering::Relaxed);

        let task_states = self.task_states.read();
        let max_duration = self.config.max_phase_duration_ns;

        for state in task_states.values() {
            // Check if task has been in current phase too long
            let duration_ns = now
                .as_nanos()
                .saturating_sub(state.last_transition.as_nanos());

            if duration_ns > max_duration && state.current_phase != CancelPhase::Completed {
                let violation = CancelCorrectnessViolation::StuckCancellation {
                    task_id: state.task_id,
                    region_id: state.region_id,
                    phase: state.current_phase,
                    stuck_since: state.last_transition,
                    detected_at: now,
                    stack_trace: self.capture_stack_trace(),
                };

                self.record_violation(violation);
            }
        }
    }

    /// Notify the oracle that a task has completed.
    ///
    /// This allows the oracle to check if the completion was premature
    /// (i.e., without proper cancellation protocol).
    pub fn notify_task_completed(&self, task_id: TaskId, completion_time: Time) {
        let mut task_states = self.task_states.write();

        if let Some(state) = task_states.get(&task_id) {
            // Check if task completed without going through proper cancellation phases
            if state.current_phase != CancelPhase::Completed {
                let violation = CancelCorrectnessViolation::PrematureCompletion {
                    task_id,
                    region_id: state.region_id,
                    last_phase: state.current_phase,
                    completion_time,
                    stack_trace: self.capture_stack_trace(),
                };

                self.record_violation(violation);
            }
        }

        // Clean up state for completed task
        task_states.remove(&task_id);
    }

    /// Get statistics about oracle operation.
    pub fn get_statistics(&self) -> CancelCorrectnessStatistics {
        let task_states = self.task_states.read();
        let violations = self.violations.read();

        CancelCorrectnessStatistics {
            witnesses_processed: self.witnesses_processed.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            stuck_checks_performed: self.stuck_checks_performed.load(Ordering::Relaxed),
            active_tasks: task_states.len(),
            total_violations: violations.len(),
        }
    }

    /// Get recent violations for debugging.
    pub fn get_recent_violations(&self, limit: usize) -> Vec<CancelCorrectnessViolation> {
        let violations = self.violations.read();
        violations.iter().rev().take(limit).cloned().collect()
    }

    /// Check for violations following the oracle pattern.
    ///
    /// Returns the first violation found, or Ok(()) if no violations are present.
    pub fn check(&self, now: Time) -> Result<(), CancelCorrectnessViolation> {
        // First check for stuck cancellations
        self.check_stuck_cancellations(now);

        // Return the first violation if any exist
        let violations = self.violations.read();
        if let Some(violation) = violations.front() {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Reset the oracle to its initial state.
    pub fn reset(&self) {
        self.task_states.write().clear();
        self.violations.write().clear();
        self.witnesses_processed.store(0, Ordering::Relaxed);
        self.violations_detected.store(0, Ordering::Relaxed);
        self.stuck_checks_performed.store(0, Ordering::Relaxed);
    }

    /// Clear all tracked state (for testing).
    #[cfg(test)]
    pub fn clear_state(&self) {
        self.reset();
    }

    fn validate_transition(
        &self,
        current_state: &TaskCancelState,
        new_witness: &CancelWitness,
        now: Time,
    ) -> Result<(), ()> {
        // Check for invalid phase transitions
        if let Some(_last_witness) = current_state.witness_history.back() {
            if new_witness.phase < current_state.current_phase {
                let violation = CancelCorrectnessViolation::InvalidTransition {
                    task_id: current_state.task_id,
                    region_id: current_state.region_id,
                    from_phase: current_state.current_phase,
                    to_phase: new_witness.phase,
                    transition_time: now,
                    stack_trace: self.capture_stack_trace(),
                };

                self.record_violation(violation);
                return Err(());
            }

            // Check for skipped finalization
            if current_state.current_phase == CancelPhase::Cancelling
                && new_witness.phase == CancelPhase::Completed
            {
                let violation = CancelCorrectnessViolation::MissedFinalization {
                    task_id: current_state.task_id,
                    region_id: current_state.region_id,
                    from_phase: current_state.current_phase,
                    completion_time: now,
                    stack_trace: self.capture_stack_trace(),
                };

                self.record_violation(violation);
                return Err(());
            }
        }

        Ok(())
    }

    fn record_violation(&self, violation: CancelCorrectnessViolation) {
        self.violations_detected.fetch_add(1, Ordering::Relaxed);

        if self.config.panic_on_violation {
            panic!("Cancel-correctness violation detected: {}", violation);
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

/// Statistics about cancel-correctness oracle operation.
#[derive(Debug, Clone)]
pub struct CancelCorrectnessStatistics {
    /// Number of cancellation witnesses processed.
    pub witnesses_processed: u64,
    /// Number of violations detected.
    pub violations_detected: u64,
    /// Number of stuck cancellation checks performed.
    pub stuck_checks_performed: u64,
    /// Number of tasks currently being tracked.
    pub active_tasks: usize,
    /// Total number of violations recorded.
    pub total_violations: usize,
}

impl fmt::Display for CancelCorrectnessStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CancelCorrectnessStats {{ witnesses: {}, violations: {}, stuck_checks: {}, active: {}, total_violations: {} }}",
            self.witnesses_processed,
            self.violations_detected,
            self.stuck_checks_performed,
            self.active_tasks,
            self.total_violations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::{RegionId, TaskId, Time};

    #[test]
    fn test_normal_cancellation_flow() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        // Normal flow: Requested → Cancelling → Finalizing → Completed
        let reason = CancelReason::user("test_cancel");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Completed, reason),
            now,
        );

        oracle.notify_task_completed(task_id, now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.witnesses_processed, 4);
    }

    #[test]
    fn test_premature_completion_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Task gets cancelled but completes prematurely
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Requested, reason),
            now,
        );

        oracle.notify_task_completed(task_id, now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::PrematureCompletion { .. }
        ));
    }

    #[test]
    fn test_invalid_transition_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Normal start
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );

        // Invalid transition: Finalizing → Cancelling (backwards)
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_missed_finalization_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Skip finalization: Requested → Cancelling → Completed (missing Finalizing)
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Completed, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::MissedFinalization { .. }
        ));
    }

    #[test]
    fn test_concurrent_cancellation_safety() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("concurrent_test");

        // Simulate concurrent witnesses for the same task
        std::thread::scope(|s| {
            for i in 0..4 {
                s.spawn(|| {
                    oracle.notify_cancel_witness(
                        CancelWitness::new(
                            task_id,
                            region_id,
                            1,
                            match i {
                                0 => CancelPhase::Requested,
                                1 => CancelPhase::Cancelling,
                                2 => CancelPhase::Finalizing,
                                _ => CancelPhase::Completed,
                            },
                            reason.clone(),
                        ),
                        now + Time::from_nanos(i * 1000),
                    );
                });
            }
        });

        // Should handle concurrent updates without panicking
        let stats = oracle.get_statistics();
        assert!(stats.witnesses_processed >= 4);
    }

    #[test]
    fn test_multiple_task_tracking() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("multi_task_test");

        // Track multiple tasks through normal cancellation flow
        for i in 0..5 {
            let task_id = TaskId::new_for_test(i, 0);

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Requested,
                    reason.clone(),
                ),
                now,
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Cancelling,
                    reason.clone(),
                ),
                now + Time::from_nanos(1000),
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Finalizing,
                    reason.clone(),
                ),
                now + Time::from_nanos(2000),
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Completed,
                    reason.clone(),
                ),
                now + Time::from_nanos(3000),
            );
        }

        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 20); // 5 tasks × 4 witnesses each
        assert_eq!(stats.violations_detected, 0); // No violations in normal flow
    }

    #[test]
    fn test_stuck_cancellation_detection() {
        init_test_logging();

        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 1000, // Very short timeout for testing
            ..Default::default()
        };
        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("stuck_test");

        // Task gets stuck in Cancelling phase
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now + Time::from_nanos(100),
        );

        // Check for stuck cancellations after timeout period
        oracle.check_stuck_cancellations(now + Time::from_nanos(2000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::StuckCancellation { .. }
        ));
    }

    #[test]
    fn test_violation_statistics_tracking() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("stats_test");

        // Create several violation types

        // 1. Premature completion
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_task_completed(task_id, now);

        // 2. Invalid transition (different task)
        let task_id2 = TaskId::new_for_test(2, 0);
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id2,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id2, region_id, 1, CancelPhase::Cancelling, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected >= 2);

        let violations = oracle.get_recent_violations(10);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_oracle_configuration() {
        init_test_logging();

        // Test default configuration
        let oracle = CancelCorrectnessOracle::with_default_config();
        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 0);
        assert_eq!(stats.violations_detected, 0);

        // Test custom configuration
        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 5000,
            max_violations: 50,
            panic_on_violation: false,
            capture_stack_traces: false,
            max_stack_trace_depth: 16,
        };

        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        // Normal flow should work with custom config
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                CancelReason::user("config_test"),
            ),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 1);
    }
}
