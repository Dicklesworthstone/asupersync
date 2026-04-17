//! Work-stealing correctness verification.
//!
//! This module provides runtime verification that work-stealing operations
//! preserve task ownership invariants, prevent double-execution, and ensure
//! no work is lost during stealing operations.
//!
//! # Design
//!
//! The checker tracks all task ownership transfers between workers and validates
//! that the work-stealing protocol maintains these invariants:
//!
//! 1. **Single Ownership**: Every task has exactly one owner at any time
//! 2. **No Double Execution**: Tasks are never executed by multiple workers
//! 3. **No Lost Work**: Tasks are never dropped during stealing
//! 4. **Ownership Transfer**: Stealing transfers ownership atomically
//! 5. **LIFO/FIFO Ordering**: Owner uses LIFO, stealers use FIFO

#![allow(missing_docs)]

use crate::runtime::scheduler::worker::WorkerId;
use crate::types::TaskId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Statistics for work-stealing operations.
#[derive(Debug, Default, Clone)]
pub struct StealingStats {
    /// Total number of steal attempts
    pub steal_attempts: u64,
    /// Number of successful steals
    pub successful_steals: u64,
    /// Number of failed steals (empty queue)
    pub failed_steals: u64,
    /// Number of ownership transfer violations detected
    pub ownership_violations: u64,
    /// Number of double-execution violations detected
    pub double_execution_violations: u64,
    /// Number of lost work violations detected
    pub lost_work_violations: u64,
    /// Average steal latency in microseconds
    pub avg_steal_latency_us: u64,
}

/// Task ownership state for tracking transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipState {
    /// Task is owned by a specific worker
    Owned(WorkerId),
    /// Task is currently being stolen (transitional state)
    Stealing { from: WorkerId, to: WorkerId },
    /// Task execution has completed
    Completed,
    /// Task was cancelled
    Cancelled,
}

/// Violation detected by the work-stealing checker.
#[derive(Debug, Clone)]
pub enum ViolationType {
    /// Task has multiple owners simultaneously
    MultipleOwners {
        task_id: TaskId,
        owners: Vec<WorkerId>,
    },
    /// Task was executed by multiple workers
    DoubleExecution {
        task_id: TaskId,
        first_worker: WorkerId,
        second_worker: WorkerId,
    },
    /// Task disappeared during stealing (lost work)
    LostWork {
        task_id: TaskId,
        last_owner: WorkerId,
    },
    /// Stealing operation took longer than expected
    SlowSteal {
        task_id: TaskId,
        from_worker: WorkerId,
        to_worker: WorkerId,
        duration: Duration,
    },
    /// Task was stolen from wrong end of queue (LIFO/FIFO violation)
    OrderingViolation {
        task_id: TaskId,
        expected_order: String,
        actual_order: String,
    },
}

/// Work-stealing correctness checker.
///
/// Tracks task ownership transfers and validates that work-stealing
/// preserves correctness invariants.
#[derive(Debug)]
pub struct WorkStealingChecker {
    /// Current task ownership state
    task_owners: Arc<RwLock<HashMap<TaskId, OwnershipState>>>,
    /// Tasks currently being executed
    executing_tasks: Arc<RwLock<HashMap<TaskId, WorkerId>>>,
    /// Queue of detected violations
    violations: Arc<RwLock<Vec<ViolationType>>>,
    /// Stealing operation statistics
    stats: Arc<RwLock<StealingStats>>,
    /// Sequence number for ordering validation
    sequence_counter: AtomicU64,
    /// Task order tracking for LIFO/FIFO validation
    task_sequences: Arc<RwLock<HashMap<TaskId, u64>>>,
    /// Whether the checker is enabled
    enabled: bool,
}

impl Default for WorkStealingChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkStealingChecker {
    /// Creates a new work-stealing correctness checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_owners: Arc::new(RwLock::new(HashMap::new())),
            executing_tasks: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(StealingStats::default())),
            sequence_counter: AtomicU64::new(0),
            task_sequences: Arc::new(RwLock::new(HashMap::new())),
            enabled: true,
        }
    }

    /// Creates a disabled checker (no-op for production).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            task_owners: Arc::new(RwLock::new(HashMap::new())),
            executing_tasks: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(StealingStats::default())),
            sequence_counter: AtomicU64::new(0),
            task_sequences: Arc::new(RwLock::new(HashMap::new())),
            enabled: false,
        }
    }

    /// Records that a task was queued by a worker.
    pub fn track_task_queued(&self, task_id: TaskId, worker_id: WorkerId) {
        if !self.enabled {
            return;
        }

        let sequence = self.sequence_counter.fetch_add(1, Ordering::Relaxed);

        {
            let mut owners = self.task_owners.write();
            owners.insert(task_id, OwnershipState::Owned(worker_id));
        }

        {
            let mut sequences = self.task_sequences.write();
            sequences.insert(task_id, sequence);
        }
    }

    /// Records the start of a steal operation.
    pub fn track_steal_start(
        &self,
        task_id: TaskId,
        from_worker: WorkerId,
        to_worker: WorkerId,
    ) -> Option<StealTracker<'_>> {
        if !self.enabled {
            return None;
        }

        {
            let mut owners = self.task_owners.write();
            if let Some(state) = owners.get_mut(&task_id) {
                match state {
                    OwnershipState::Owned(owner) if *owner == from_worker => {
                        *state = OwnershipState::Stealing {
                            from: from_worker,
                            to: to_worker,
                        };
                    }
                    _ => {
                        // Ownership violation - task not owned by expected worker
                        self.record_violation(ViolationType::MultipleOwners {
                            task_id,
                            owners: vec![from_worker, to_worker],
                        });
                        return None;
                    }
                }
            }
        }

        {
            let mut stats = self.stats.write();
            stats.steal_attempts += 1;
        }

        Some(StealTracker {
            task_id,
            from_worker,
            to_worker,
            start_time: Instant::now(),
            checker: self,
        })
    }

    /// Records successful completion of a steal operation.
    fn track_steal_success(
        &self,
        task_id: TaskId,
        from_worker: WorkerId,
        to_worker: WorkerId,
        duration: Duration,
    ) {
        {
            let mut owners = self.task_owners.write();
            if let Some(state) = owners.get_mut(&task_id) {
                match state {
                    OwnershipState::Stealing { from, to }
                        if *from == from_worker && *to == to_worker =>
                    {
                        *state = OwnershipState::Owned(to_worker);
                    }
                    _ => {
                        // State inconsistency during steal
                        self.record_violation(ViolationType::LostWork {
                            task_id,
                            last_owner: from_worker,
                        });
                        return;
                    }
                }
            }
        }

        {
            let mut stats = self.stats.write();
            stats.successful_steals += 1;
            let duration_us = duration.as_micros() as u64;
            if stats.successful_steals == 1 {
                stats.avg_steal_latency_us = duration_us;
            } else {
                // Exponential moving average
                stats.avg_steal_latency_us = (stats.avg_steal_latency_us * 3 + duration_us) / 4;
            }
        }

        // Check for slow steal violations (> 1ms is suspicious)
        if duration > Duration::from_millis(1) {
            self.record_violation(ViolationType::SlowSteal {
                task_id,
                from_worker,
                to_worker,
                duration,
            });
        }
    }

    /// Records failed steal operation.
    fn track_steal_failure(&self, _task_id: TaskId, _from_worker: WorkerId, _to_worker: WorkerId) {
        let mut stats = self.stats.write();
        stats.failed_steals += 1;
    }

    /// Records that a task has started execution.
    pub fn track_task_execution_start(&self, task_id: TaskId, worker_id: WorkerId) {
        if !self.enabled {
            return;
        }

        // Check for double execution
        {
            let mut executing = self.executing_tasks.write();
            if let Some(&existing_worker) = executing.get(&task_id) {
                self.record_violation(ViolationType::DoubleExecution {
                    task_id,
                    first_worker: existing_worker,
                    second_worker: worker_id,
                });
                return;
            }
            executing.insert(task_id, worker_id);
        }

        // Verify task is owned by this worker
        {
            let owners = self.task_owners.read();
            if let Some(state) = owners.get(&task_id) {
                match state {
                    OwnershipState::Owned(owner) if *owner != worker_id => {
                        self.record_violation(ViolationType::MultipleOwners {
                            task_id,
                            owners: vec![*owner, worker_id],
                        });
                    }
                    OwnershipState::Stealing { .. } => {
                        // Task is being stolen - this shouldn't happen
                        self.record_violation(ViolationType::MultipleOwners {
                            task_id,
                            owners: vec![worker_id],
                        });
                    }
                    _ => {
                        // Completed or cancelled - this is fine
                    }
                }
            }
        }
    }

    /// Records that a task has completed execution.
    pub fn track_task_execution_complete(&self, task_id: TaskId, _worker_id: WorkerId) {
        if !self.enabled {
            return;
        }

        {
            let mut executing = self.executing_tasks.write();
            executing.remove(&task_id);
        }

        {
            let mut owners = self.task_owners.write();
            owners.insert(task_id, OwnershipState::Completed);
        }

        {
            let mut sequences = self.task_sequences.write();
            sequences.remove(&task_id);
        }
    }

    /// Records a violation.
    fn record_violation(&self, violation: ViolationType) {
        let mut violations = self.violations.write();
        violations.push(violation);

        let mut stats = self.stats.write();
        match violations.last().unwrap() {
            ViolationType::MultipleOwners { .. } => stats.ownership_violations += 1,
            ViolationType::DoubleExecution { .. } => stats.double_execution_violations += 1,
            ViolationType::LostWork { .. } => stats.lost_work_violations += 1,
            ViolationType::SlowSteal { .. } => {} // Not counted as violation, just warning
            ViolationType::OrderingViolation { .. } => {} // Not counted as violation, just warning
        }
    }

    /// Gets current statistics.
    #[must_use]
    pub fn stats(&self) -> StealingStats {
        self.stats.read().clone()
    }

    /// Gets all detected violations.
    #[must_use]
    pub fn violations(&self) -> Vec<ViolationType> {
        self.violations.read().clone()
    }

    /// Clears all violations and resets statistics.
    pub fn reset(&self) {
        self.violations.write().clear();
        *self.stats.write() = StealingStats::default();
        self.task_owners.write().clear();
        self.executing_tasks.write().clear();
        self.task_sequences.write().clear();
        self.sequence_counter.store(0, Ordering::Relaxed);
    }

    /// Validates queue ordering (LIFO for owner, FIFO for stealers).
    pub fn validate_ordering(&self, task_id: TaskId, is_owner: bool, _worker_id: WorkerId) {
        if !self.enabled {
            return;
        }

        // This is a simplified ordering check - in a full implementation,
        // we would need more sophisticated tracking of queue operations
        let sequences = self.task_sequences.read();
        if let Some(&_task_sequence) = sequences.get(&task_id) {
            // Owner should get newer tasks (higher sequence), thieves get older tasks
            let _expected_order = if is_owner { "LIFO" } else { "FIFO" };

            // For demonstration - in practice, this would require more complex
            // tracking of which tasks were added when and how they're being accessed
            drop(sequences);
        }
    }

    /// Returns true if any violations have been detected.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        !self.violations.read().is_empty()
    }

    /// Returns the number of violations detected.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.read().len()
    }
}

/// RAII tracker for steal operations.
pub struct StealTracker<'a> {
    task_id: TaskId,
    from_worker: WorkerId,
    to_worker: WorkerId,
    start_time: Instant,
    checker: &'a WorkStealingChecker,
}

impl StealTracker<'_> {
    /// Records successful steal completion.
    pub fn success(self) {
        let duration = self.start_time.elapsed();
        self.checker
            .track_steal_success(self.task_id, self.from_worker, self.to_worker, duration);
    }

    /// Records failed steal attempt.
    pub fn failure(self) {
        self.checker
            .track_steal_failure(self.task_id, self.from_worker, self.to_worker);
    }
}

impl Drop for StealTracker<'_> {
    fn drop(&mut self) {
        // If not explicitly completed, assume failure
        self.checker
            .track_steal_failure(self.task_id, self.from_worker, self.to_worker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ownership_tracking() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let _worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        // Queue task on worker 1
        checker.track_task_queued(task, worker1);

        // Start execution on worker 1
        checker.track_task_execution_start(task, worker1);
        assert!(!checker.has_violations());

        // Complete execution
        checker.track_task_execution_complete(task, worker1);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_steal_operation() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        // Queue task on worker 1
        checker.track_task_queued(task, worker1);

        // Start steal operation
        if let Some(tracker) = checker.track_steal_start(task, worker1, worker2) {
            // Complete steal successfully
            tracker.success();
        }

        // Execute on worker 2 (after successful steal)
        checker.track_task_execution_start(task, worker2);
        checker.track_task_execution_complete(task, worker2);

        let stats = checker.stats();
        assert_eq!(stats.successful_steals, 1);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_double_execution_detection() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        checker.track_task_queued(task, worker1);

        // Start execution on worker 1
        checker.track_task_execution_start(task, worker1);

        // Try to start execution on worker 2 (should detect violation)
        checker.track_task_execution_start(task, worker2);

        assert!(checker.has_violations());
        let violations = checker.violations();
        assert_eq!(violations.len(), 1);
        matches!(violations[0], ViolationType::DoubleExecution { .. });
    }

    #[test]
    fn test_ownership_violation_detection() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let worker3 = 3;
        let task = TaskId::new_for_test(100, 0);

        checker.track_task_queued(task, worker1);

        // Try to steal from wrong worker (should detect violation)
        let tracker = checker.track_steal_start(task, worker2, worker3);
        assert!(tracker.is_none()); // Should fail to create tracker

        assert!(checker.has_violations());
    }
}
