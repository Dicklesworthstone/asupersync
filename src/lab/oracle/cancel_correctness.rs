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
//! - **Post-completion witnesses**: Late stale witnesses reopening completed tasks
//!
//! # Integration Points
//!
//! - Hooks into `CancelWitness` validation in `types::cancel`
//! - Monitors cancellation state transitions per task/region
//! - Provides diagnostics with stack traces and cancellation path visualization
//! - Configurable enforcement modes (warn vs panic)

use crate::types::{
    CancelPhase, CancelReason, CancelWitness, CancelWitnessError, RegionId, TaskId, Time,
};
use crate::util::det_hash::{DetBuildHasher, DetHashMap, DetHashSet};
use parking_lot::RwLock;
use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::time::Duration;

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
    /// The first witness for a task was malformed.
    InvalidInitialWitness {
        /// The task whose first witness was malformed.
        task_id: TaskId,
        /// The region containing the task.
        region_id: RegionId,
        /// The initial phase that was observed.
        phase: CancelPhase,
        /// The initial epoch that was observed.
        epoch: u64,
        /// The specific reason the initial witness was rejected.
        kind: InvalidInitialWitnessKind,
        /// When the invalid initial witness was observed.
        observed_at: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

    /// A stale witness arrived after the task had already completed.
    WitnessAfterCompletion {
        /// The task whose cancellation stream reopened after completion.
        task_id: TaskId,
        /// The region carried by the late witness.
        region_id: RegionId,
        /// The late witness phase that arrived after completion.
        phase: CancelPhase,
        /// The late witness epoch.
        epoch: u64,
        /// When the late witness was observed.
        observed_at: Time,
        /// Optional stack trace for debugging.
        stack_trace: Option<Arc<Backtrace>>,
    },

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

    /// Cancel witness stream violated canonical witness validation rules.
    WitnessValidationFailed {
        /// The task whose witness stream became inconsistent.
        task_id: TaskId,
        /// The region currently associated with the tracked task state.
        region_id: RegionId,
        /// The validation error returned by `CancelWitness::validate_transition`.
        error: CancelWitnessError,
        /// When the invalid witness was observed.
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
}

/// The reason an initial cancellation witness was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidInitialWitnessKind {
    /// The first observed cancellation epoch must be non-zero.
    ZeroEpoch,
}

impl fmt::Display for CancelCorrectnessViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInitialWitness {
                task_id,
                region_id,
                phase,
                epoch,
                kind,
                observed_at,
                ..
            } => {
                let detail = match kind {
                    InvalidInitialWitnessKind::ZeroEpoch => {
                        "first witness used cancellation epoch 0"
                    }
                };
                write!(
                    f,
                    "Invalid initial witness: task {}@{} observed {:?} epoch {} at {} ({detail})",
                    task_id,
                    region_id,
                    phase,
                    epoch,
                    observed_at.as_nanos()
                )
            }
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
            Self::WitnessAfterCompletion {
                task_id,
                region_id,
                phase,
                epoch,
                observed_at,
                ..
            } => {
                write!(
                    f,
                    "Witness after completion: task {}@{} observed stale {:?} epoch {} at {} after completion",
                    task_id,
                    region_id,
                    phase,
                    epoch,
                    observed_at.as_nanos()
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
            Self::WitnessValidationFailed {
                task_id,
                region_id,
                error,
                transition_time,
                ..
            } => {
                write!(
                    f,
                    "Witness validation failed: task {}@{} observed inconsistent cancellation witness ({error:?}) at {}",
                    task_id,
                    region_id,
                    transition_time.as_nanos()
                )
            }
        }
    }
}

#[derive(Debug)]
struct CompletedTaskCache {
    task_ids: DetHashSet<TaskId>,
    order: VecDeque<TaskId>,
}

impl Default for CompletedTaskCache {
    fn default() -> Self {
        // GH#55: fixed-seed hashing for feature-independent lab determinism.
        Self {
            task_ids: DetHashSet::with_hasher(DetBuildHasher::for_lab()),
            order: VecDeque::new(),
        }
    }
}

impl CompletedTaskCache {
    fn contains(&self, task_id: TaskId) -> bool {
        self.task_ids.contains(&task_id)
    }

    fn remember(&mut self, task_id: TaskId, limit: usize) {
        if self.task_ids.insert(task_id) {
            self.order.push_back(task_id);
        }

        while self.order.len() > limit {
            if let Some(evicted) = self.order.pop_front() {
                self.task_ids.remove(&evicted);
            }
        }
    }

    fn clear(&mut self) {
        self.task_ids.clear();
        self.order.clear();
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
    stuck_violation_reported: bool,
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
            stuck_violation_reported: false,
        }
    }

    fn update_with_witness(&mut self, witness: CancelWitness, now: Time) {
        let phase_changed = witness.phase != self.current_phase;
        self.current_phase = witness.phase;
        self.epoch = witness.epoch;
        self.cancel_reason = witness.reason.clone();

        if phase_changed {
            self.last_transition = now;
            self.stuck_violation_reported = false;
        }

        self.witness_history.push_back(witness);

        // Keep only last few witnesses to avoid unbounded growth
        while self.witness_history.len() > 10 {
            self.witness_history.pop_front();
        }
    }
}

/// Snapshot of a tracked task's cancellation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedCancelTaskSnapshot {
    /// Task identifier.
    pub task_id: TaskId,
    /// Region containing the task.
    pub region_id: RegionId,
    /// Current cancellation phase.
    pub current_phase: CancelPhase,
    /// Latest cancellation epoch carried by the witness stream.
    pub epoch: u64,
    /// Latest cancellation reason observed for the task.
    pub cancel_reason: CancelReason,
    /// Time of the last phase transition.
    pub last_transition: Time,
    /// Number of witnesses retained in the local history window.
    pub witness_history_len: usize,
}

/// The cancel-correctness property oracle.
#[derive(Debug)]
pub struct CancelCorrectnessOracle {
    config: CancelCorrectnessConfig,

    /// Current cancellation states tracked by task ID.
    task_states: RwLock<DetHashMap<TaskId, TaskCancelState>>,

    /// Recently completed tasks retained long enough to reject stale late witnesses.
    completed_tasks: RwLock<CompletedTaskCache>,

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
    #[must_use]
    pub fn new(config: CancelCorrectnessConfig) -> Self {
        Self {
            config,
            // GH#55: fixed-seed hashing keeps the lab oracle deterministic
            // even without the `test-internals` feature. Keys are internal
            // TaskIds, so the documented HashDoS concern does not apply.
            task_states: RwLock::new(DetHashMap::with_hasher(DetBuildHasher::for_lab())),
            completed_tasks: RwLock::new(CompletedTaskCache::default()),
            violations: RwLock::new(VecDeque::new()),
            witnesses_processed: AtomicU64::new(0),
            violations_detected: AtomicU64::new(0),
            stuck_checks_performed: AtomicU64::new(0),
        }
    }

    /// Creates a new oracle with default configuration.
    #[must_use]
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

        if let Some(existing_state) = task_states.get_mut(&witness.task_id) {
            // Validate transition
            if self
                .validate_transition(existing_state, &witness, now)
                .is_ok()
            {
                existing_state.update_with_witness(witness, now);
            }
        } else {
            if self.completed_tasks.read().contains(witness.task_id) {
                drop(task_states);
                self.record_violation(CancelCorrectnessViolation::WitnessAfterCompletion {
                    task_id: witness.task_id,
                    region_id: witness.region_id,
                    phase: witness.phase,
                    epoch: witness.epoch,
                    observed_at: now,
                    stack_trace: self.capture_stack_trace(),
                });
                return;
            }

            // First witness for this task. The oracle may attach after
            // cancellation has already progressed, so accept any initial phase
            // with a non-zero epoch and validate monotone transitions from
            // that point onward.
            if self.validate_initial_witness(&witness, now).is_ok() {
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

        let mut pending_violations = Vec::new();
        let mut task_states = self.task_states.write();
        let max_duration = self.config.max_phase_duration_ns;

        for state in task_states.values_mut() {
            // Check if task has been in current phase too long
            let duration_ns = now
                .as_nanos()
                .saturating_sub(state.last_transition.as_nanos());

            if duration_ns > max_duration
                && state.current_phase != CancelPhase::Completed
                && !state.stuck_violation_reported
            {
                state.stuck_violation_reported = true;
                pending_violations.push(CancelCorrectnessViolation::StuckCancellation {
                    task_id: state.task_id,
                    region_id: state.region_id,
                    phase: state.current_phase,
                    stuck_since: state.last_transition,
                    detected_at: now,
                    stack_trace: self.capture_stack_trace(),
                });
            }
        }
        drop(task_states);

        for violation in pending_violations {
            self.record_violation(violation);
        }
    }

    /// Notify the oracle that a task has completed.
    ///
    /// This allows the oracle to check if the completion was premature
    /// (i.e., without proper cancellation protocol).
    pub fn notify_task_completed(&self, task_id: TaskId, completion_time: Time) {
        let mut task_states = self.task_states.write();
        let premature_violation = task_states
            .get(&task_id)
            .filter(|state| state.current_phase != CancelPhase::Completed)
            .map(|state| CancelCorrectnessViolation::PrematureCompletion {
                task_id,
                region_id: state.region_id,
                last_phase: state.current_phase,
                completion_time,
                stack_trace: self.capture_stack_trace(),
            });

        // Clean up state for completed task
        task_states.remove(&task_id);
        let mut completed_tasks = self.completed_tasks.write();
        completed_tasks.remember(task_id, self.completed_task_cache_limit());
        drop(completed_tasks);
        drop(task_states);

        if let Some(violation) = premature_violation {
            self.record_violation(violation);
        }
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

    /// Returns snapshots of the currently tracked task cancellation states.
    pub fn tracked_tasks(&self) -> Vec<TrackedCancelTaskSnapshot> {
        let mut snapshots = self
            .task_states
            .read()
            .values()
            .map(|state| TrackedCancelTaskSnapshot {
                task_id: state.task_id,
                region_id: state.region_id,
                current_phase: state.current_phase,
                epoch: state.epoch,
                cancel_reason: state.cancel_reason.clone(),
                last_transition: state.last_transition,
                witness_history_len: state.witness_history.len(),
            })
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| snapshot.task_id);
        snapshots
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
            let violation = violation.clone();
            drop(violations);
            return Err(violation);
        }
        drop(violations);

        Ok(())
    }

    /// Reset the oracle to its initial state.
    pub fn reset(&self) {
        self.task_states.write().clear();
        self.completed_tasks.write().clear();
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
        if let Some(last_witness) = current_state.witness_history.back() {
            match CancelWitness::validate_transition(Some(last_witness), new_witness) {
                Ok(()) => {}
                Err(CancelWitnessError::PhaseRegression { from, to }) => {
                    let violation = CancelCorrectnessViolation::InvalidTransition {
                        task_id: current_state.task_id,
                        region_id: current_state.region_id,
                        from_phase: from,
                        to_phase: to,
                        transition_time: now,
                        stack_trace: self.capture_stack_trace(),
                    };

                    self.record_violation(violation);
                    return Err(());
                }
                Err(error) => {
                    let violation = CancelCorrectnessViolation::WitnessValidationFailed {
                        task_id: current_state.task_id,
                        region_id: current_state.region_id,
                        error,
                        transition_time: now,
                        stack_trace: self.capture_stack_trace(),
                    };

                    self.record_violation(violation);
                    return Err(());
                }
            }

            if new_witness.phase != CancelPhase::Completed
                && phase_step(new_witness.phase) > phase_step(current_state.current_phase) + 1
            {
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
            if new_witness.phase == CancelPhase::Completed
                && current_state.current_phase != CancelPhase::Finalizing
                && current_state.current_phase != CancelPhase::Completed
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

    fn completed_task_cache_limit(&self) -> usize {
        self.config.max_violations.max(64)
    }

    /// br-asupersync-9fjaqe / -f1zjwu — Routes initial-witness
    /// validation through the canonical
    /// [`CancelWitness::validate_initial`] entry point. Previously
    /// this oracle inlined the `epoch == 0` rejection while the
    /// sibling [`crate::lab::oracle::cancellation_protocol`] oracle
    /// did not enforce it at all, so two oracles wired to the same
    /// witness stream could produce disagreeing verdicts. Both
    /// oracles now route through `CancelWitness::validate_initial`,
    /// guaranteeing identical epoch verdicts on identical inputs.
    fn validate_initial_witness(&self, witness: &CancelWitness, now: Time) -> Result<(), ()> {
        if witness.validate_initial() == Err(CancelWitnessError::InitialEpochZero) {
            self.record_violation(CancelCorrectnessViolation::InvalidInitialWitness {
                task_id: witness.task_id,
                region_id: witness.region_id,
                phase: witness.phase,
                epoch: witness.epoch,
                kind: InvalidInitialWitnessKind::ZeroEpoch,
                observed_at: now,
                stack_trace: self.capture_stack_trace(),
            });
            return Err(());
        }

        Ok(())
    }

    /// br-asupersync-ywx3sz — Push the violation BEFORE optionally
    /// panicking. The previous order (counter++, panic, push) left the
    /// violation in a half-recorded state if the panic was caught
    /// upstream (lab campaigns deliberately catch panics): the counter
    /// reported +1 but the queue still missed the entry, so callers
    /// inspecting state after a caught panic saw a phantom violation.
    /// Now: counter++, push to queue, prepare panic message, drop the
    /// queue lock, then panic. State after the panic (caught or not)
    /// has counter == queue length.
    fn record_violation(&self, violation: CancelCorrectnessViolation) {
        self.violations_detected.fetch_add(1, Ordering::Relaxed);

        let panic_msg = if self.config.panic_on_violation {
            Some(format!(
                "Cancel-correctness violation detected: {violation}"
            ))
        } else {
            None
        };

        {
            let mut violations = self.violations.write();
            violations.push_back(violation);
            // Keep violations bounded.
            while violations.len() > self.config.max_violations {
                violations.pop_front();
            }
        }

        if let Some(msg) = panic_msg {
            panic!("{msg}");
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

fn phase_step(phase: CancelPhase) -> u8 {
    match phase {
        CancelPhase::Requested => 0,
        CancelPhase::Cancelling => 1,
        CancelPhase::Finalizing => 2,
        CancelPhase::Completed => 3,
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
#[path = "cancel_correctness_inline_tests.rs"]
mod tests;
