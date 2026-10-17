//! Runtime State Machine Transition Verifier
//!
//! Checks a task, region or obligation state transition that a caller passes
//! in against the legal transitions of its state type, and counts the checks
//! and the violations.
//!
//! The runtime does not pass its own transitions through it. The verifier that
//! [`RuntimeState::state_verifier`](crate::runtime::RuntimeState::state_verifier)
//! returns counts only what callers validate through it, so with no caller its
//! statistics stay at zero (asupersync-7yq1pv item 3). The runtime's own
//! transitions are checked where they happen instead:
//! - a task phase change is a `debug_assert!` in the task record;
//! - a region's lifecycle steps (`begin_close`, `begin_drain`,
//!   `begin_finalize`, `complete_close`) each check the state they start
//!   from (`set_state` stores without a check; the lab and snapshot restore
//!   use it);
//! - an obligation panics if it is resolved twice.

use crate::record::{ObligationState, region::RegionState, task::TaskPhase};
use crate::types::{ObligationId, RegionId, TaskId};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Configuration for state transition monitoring.
#[derive(Debug, Clone)]
pub struct StateVerifierConfig {
    /// Enable transition validation in production (recommended).
    pub enable_validation: bool,
    /// Enable detailed violation logging (higher overhead).
    pub enable_diagnostics: bool,
    /// Enable stack trace capture for violations (expensive).
    pub enable_stack_traces: bool,
    /// Maximum number of violations to track before dropping oldest.
    pub max_tracked_violations: usize,
    /// Whether to panic on invalid transitions (recommended for testing).
    pub panic_on_violation: bool,
}

impl Default for StateVerifierConfig {
    fn default() -> Self {
        Self {
            enable_validation: true,
            enable_diagnostics: cfg!(debug_assertions),
            enable_stack_traces: false,
            max_tracked_violations: 1000,
            panic_on_violation: cfg!(debug_assertions),
        }
    }
}

/// Type of entity undergoing state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateEntityType {
    /// Task state transition.
    Task,
    /// Region state transition.
    Region,
    /// Obligation state transition.
    Obligation,
}

/// Details of a state transition violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateViolation {
    /// Type of entity with invalid transition.
    pub entity_type: StateEntityType,
    /// ID of the entity (formatted as string for uniform handling).
    pub entity_id: String,
    /// Previous state (formatted as string).
    pub from_state: String,
    /// Attempted new state (formatted as string).
    pub to_state: String,
    /// Timestamp when violation occurred.
    pub timestamp: SystemTime,
    /// Stack trace if enabled.
    pub stack_trace: Option<String>,
    /// Additional context.
    pub context: String,
}

/// Statistics about state transition validation.
#[derive(Debug, Default)]
pub struct StateVerifierStats {
    /// Total transitions validated.
    pub total_transitions: AtomicU64,
    /// Violations detected.
    pub violations_detected: AtomicU64,
    /// Transitions by entity type.
    pub transitions_by_type: [AtomicU64; 3], // Task, Region, Obligation
    /// Violations by entity type.
    pub violations_by_type: [AtomicU64; 3], // Task, Region, Obligation
}

impl StateVerifierStats {
    /// Records a transition validation.
    fn record_transition(&self, entity_type: StateEntityType, valid: bool) {
        self.total_transitions.fetch_add(1, Ordering::Relaxed);
        let type_index = match entity_type {
            StateEntityType::Task => 0,
            StateEntityType::Region => 1,
            StateEntityType::Obligation => 2,
        };
        self.transitions_by_type[type_index].fetch_add(1, Ordering::Relaxed);

        if !valid {
            self.violations_detected.fetch_add(1, Ordering::Relaxed);
            self.violations_by_type[type_index].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Gets a snapshot of current statistics.
    #[inline]
    pub fn snapshot(&self) -> StateVerifierStatsSnapshot {
        StateVerifierStatsSnapshot {
            total_transitions: self.total_transitions.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            task_transitions: self.transitions_by_type[0].load(Ordering::Relaxed),
            region_transitions: self.transitions_by_type[1].load(Ordering::Relaxed),
            obligation_transitions: self.transitions_by_type[2].load(Ordering::Relaxed),
            task_violations: self.violations_by_type[0].load(Ordering::Relaxed),
            region_violations: self.violations_by_type[1].load(Ordering::Relaxed),
            obligation_violations: self.violations_by_type[2].load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of state verifier statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerifierStatsSnapshot {
    /// Total number of state transitions verified.
    pub total_transitions: u64,
    /// Total number of violations detected.
    pub violations_detected: u64,
    /// Number of task state transitions.
    pub task_transitions: u64,
    /// Number of region state transitions.
    pub region_transitions: u64,
    /// Number of obligation state transitions.
    pub obligation_transitions: u64,
    /// Number of task-related violations.
    pub task_violations: u64,
    /// Number of region-related violations.
    pub region_violations: u64,
    /// Number of obligation-related violations.
    pub obligation_violations: u64,
}

/// Centralized state machine transition verifier.
#[derive(Debug)]
pub struct StateTransitionVerifier {
    config: StateVerifierConfig,
    stats: StateVerifierStats,
    violations: Arc<Mutex<Vec<StateViolation>>>,
}

impl StateTransitionVerifier {
    /// Creates a new state transition verifier with the given configuration.
    #[must_use]
    pub fn new(config: StateVerifierConfig) -> Self {
        Self {
            config,
            stats: StateVerifierStats::default(),
            violations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Validates a task phase transition.
    pub fn validate_task_transition(
        &self,
        task_id: TaskId,
        from: TaskPhase,
        to: TaskPhase,
        context: &str,
    ) -> Result<(), StateViolation> {
        if !self.config.enable_validation {
            return Ok(());
        }
        let valid = from.is_valid_transition(to);
        self.stats.record_transition(StateEntityType::Task, valid);

        if !valid {
            let violation = StateViolation {
                entity_type: StateEntityType::Task,
                entity_id: format!("{task_id:?}"),
                from_state: format!("{from:?}"),
                to_state: format!("{to:?}"),
                timestamp: SystemTime::now(),
                stack_trace: if self.config.enable_stack_traces {
                    Some(std::backtrace::Backtrace::force_capture().to_string())
                } else {
                    None
                },
                context: context.to_string(),
            };

            self.record_violation(violation.clone());
            return Err(violation);
        }

        Ok(())
    }

    /// Validates a region state transition.
    pub fn validate_region_transition(
        &self,
        region_id: RegionId,
        from: RegionState,
        to: RegionState,
        context: &str,
    ) -> Result<(), StateViolation> {
        if !self.config.enable_validation {
            return Ok(());
        }
        let valid = from.is_valid_transition(to);
        self.stats.record_transition(StateEntityType::Region, valid);

        if !valid {
            let violation = StateViolation {
                entity_type: StateEntityType::Region,
                entity_id: format!("{region_id:?}"),
                from_state: format!("{from:?}"),
                to_state: format!("{to:?}"),
                timestamp: SystemTime::now(),
                stack_trace: if self.config.enable_stack_traces {
                    Some(std::backtrace::Backtrace::force_capture().to_string())
                } else {
                    None
                },
                context: context.to_string(),
            };

            self.record_violation(violation.clone());
            return Err(violation);
        }

        Ok(())
    }

    /// Validates an obligation state transition.
    pub fn validate_obligation_transition(
        &self,
        obligation_id: ObligationId,
        from: ObligationState,
        to: ObligationState,
        context: &str,
    ) -> Result<(), StateViolation> {
        if !self.config.enable_validation {
            return Ok(());
        }
        let valid = from.is_valid_transition(to);
        self.stats
            .record_transition(StateEntityType::Obligation, valid);

        if !valid {
            let violation = StateViolation {
                entity_type: StateEntityType::Obligation,
                entity_id: format!("{obligation_id:?}"),
                from_state: format!("{from:?}"),
                to_state: format!("{to:?}"),
                timestamp: SystemTime::now(),
                stack_trace: if self.config.enable_stack_traces {
                    Some(std::backtrace::Backtrace::force_capture().to_string())
                } else {
                    None
                },
                context: context.to_string(),
            };

            self.record_violation(violation.clone());
            return Err(violation);
        }

        Ok(())
    }

    /// Records a state transition violation.
    fn record_violation(&self, violation: StateViolation) {
        if self.config.enable_diagnostics {
            crate::tracing_compat::error!(
                entity_type = ?violation.entity_type,
                entity_id = %violation.entity_id,
                from_state = %violation.from_state,
                to_state = %violation.to_state,
                context = %violation.context,
                "Invalid state transition detected"
            );
        }

        if let Ok(mut violations) = self.violations.lock() {
            violations.push(violation.clone());

            // Keep violations within configured limit
            if violations.len() > self.config.max_tracked_violations {
                let excess = violations.len() - self.config.max_tracked_violations;
                violations.drain(0..excess);
            }
        }

        assert!(
            !self.config.panic_on_violation,
            "Invalid state transition: {} {} -> {} (context: {})",
            violation.entity_type as u8,
            violation.from_state,
            violation.to_state,
            violation.context
        );
    }

    /// Gets current statistics.
    #[inline]
    pub fn stats(&self) -> StateVerifierStatsSnapshot {
        self.stats.snapshot()
    }

    /// Gets all recorded violations.
    pub fn violations(&self) -> Vec<StateViolation> {
        self.violations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clears all recorded violations.
    pub fn clear_violations(&self) {
        if let Ok(mut violations) = self.violations.lock() {
            violations.clear();
        }
    }
}

/// Extension trait for RegionState to add transition validation.
pub trait RegionStateTransitions {
    /// Returns whether transitioning from `self` to `next` is valid.
    fn is_valid_transition(self, next: Self) -> bool;
}

impl RegionStateTransitions for RegionState {
    /// Returns whether transitioning from `self` to `next` is a legal
    /// state machine transition.
    ///
    /// The formal transition table for region states:
    ///
    /// ```text
    /// ┌─────────────┬────────────────────────────────────────────────┐
    /// │ From        │ Valid targets                                  │
    /// ├─────────────┼────────────────────────────────────────────────┤
    /// │ Open        │ Closing                                        │
    /// │ Closing     │ Draining, Finalizing                           │
    /// │ Draining    │ Finalizing                                     │
    /// │ Finalizing  │ Closed                                         │
    /// │ Closed      │ (terminal — no transitions)                    │
    /// └─────────────┴────────────────────────────────────────────────┘
    /// ```
    ///
    /// Notes:
    /// - `Open → Closing` begins the close sequence.
    /// - `Closing → Draining` when there are children to wait for.
    /// - `Closing → Finalizing` when there are no children (direct skip).
    /// - `Draining → Finalizing` when all children complete.
    /// - `Finalizing → Closed` when all finalizers complete.
    /// - `Closed` is terminal; no further transitions are valid.
    fn is_valid_transition(self, next: Self) -> bool {
        use RegionState::{Closed, Closing, Draining, Finalizing, Open};
        matches!(
            (self, next),
            // Open → Closing (begin close sequence)
            (Open, Closing)
            // Closing → Draining (has children to wait for) | Finalizing (no children)
            | (Closing, Draining | Finalizing)
            // Draining → Finalizing (children completed)
            | (Draining, Finalizing)
            // Finalizing → Closed (finalizers completed)
            | (Finalizing, Closed)
        )
    }
}

/// Extension trait for ObligationState to add transition validation.
pub trait ObligationStateTransitions {
    /// Returns whether transitioning from `self` to `next` is valid.
    fn is_valid_transition(self, next: Self) -> bool;
}

impl ObligationStateTransitions for ObligationState {
    /// Returns whether transitioning from `self` to `next` is a legal
    /// state machine transition.
    ///
    /// The formal transition table for obligation states:
    ///
    /// ```text
    /// ┌─────────────┬────────────────────────────────────────────────┐
    /// │ From        │ Valid targets                                  │
    /// ├─────────────┼────────────────────────────────────────────────┤
    /// │ Reserved    │ Committed, Aborted, Leaked                     │
    /// │ Committed   │ (terminal — no transitions)                    │
    /// │ Aborted     │ (terminal — no transitions)                    │
    /// │ Leaked      │ (terminal — no transitions)                    │
    /// └─────────────┴────────────────────────────────────────────────┘
    /// ```
    ///
    /// Notes:
    /// - `Reserved → Committed` for successful resolution.
    /// - `Reserved → Aborted` for clean cancellation.
    /// - `Reserved → Leaked` for error case (holder completed without resolving).
    /// - All terminal states are absorbing.
    fn is_valid_transition(self, next: Self) -> bool {
        use ObligationState::{Aborted, Committed, Leaked, Reserved};
        matches!(
            (self, next),
            // Reserved → Committed | Aborted | Leaked
            (Reserved, Committed | Aborted | Leaked) // All terminal states are absorbing (no outbound transitions)
        )
    }
}

#[cfg(test)]
#[path = "state_verifier_inline_tests.rs"]
mod tests;
