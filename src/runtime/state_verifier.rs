//! Runtime State Machine Transition Verifier
//!
//! Validates that all runtime state transitions (task states, region states, obligation states)
//! follow legal paths and don't skip required intermediate states. Provides centralized
//! monitoring and error handling for invalid state transitions across all runtime components.
//!
//! The verifier enforces the state machine contracts defined in each state type and provides
//! debugging capabilities to detect illegal state transitions early during development.

use crate::record::{ObligationState, task::TaskPhase, region::RegionState};
use crate::types::{TaskId, RegionId, ObligationId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

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
    pub total_transitions: u64,
    pub violations_detected: u64,
    pub task_transitions: u64,
    pub region_transitions: u64,
    pub obligation_transitions: u64,
    pub task_violations: u64,
    pub region_violations: u64,
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
        let valid = from.is_valid_transition(to);
        self.stats.record_transition(StateEntityType::Obligation, valid);

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

        if self.config.panic_on_violation {
            panic!(
                "Invalid state transition: {} {} -> {} (context: {})",
                violation.entity_type as u8, violation.from_state, violation.to_state, violation.context
            );
        }
    }

    /// Gets current statistics.
    pub fn stats(&self) -> StateVerifierStatsSnapshot {
        self.stats.snapshot()
    }

    /// Gets all recorded violations.
    pub fn violations(&self) -> Vec<StateViolation> {
        self.violations.lock().unwrap_or_else(|e| e.into_inner()).clone()
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
        use RegionState::*;
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
        use ObligationState::*;
        matches!(
            (self, next),
            // Reserved → Committed | Aborted | Leaked
            (Reserved, Committed | Aborted | Leaked)
            // All terminal states are absorbing (no outbound transitions)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_state_valid_transitions() {
        use RegionState::*;

        // Valid transitions
        assert!(Open.is_valid_transition(Closing));
        assert!(Closing.is_valid_transition(Draining));
        assert!(Closing.is_valid_transition(Finalizing));
        assert!(Draining.is_valid_transition(Finalizing));
        assert!(Finalizing.is_valid_transition(Closed));

        // Invalid transitions
        assert!(!Open.is_valid_transition(Draining));
        assert!(!Open.is_valid_transition(Finalizing));
        assert!(!Open.is_valid_transition(Closed));
        assert!(!Closing.is_valid_transition(Open));
        assert!(!Closing.is_valid_transition(Closed));
        assert!(!Draining.is_valid_transition(Open));
        assert!(!Draining.is_valid_transition(Closing));
        assert!(!Draining.is_valid_transition(Closed));
        assert!(!Finalizing.is_valid_transition(Open));
        assert!(!Finalizing.is_valid_transition(Closing));
        assert!(!Finalizing.is_valid_transition(Draining));
        assert!(!Closed.is_valid_transition(Open));
        assert!(!Closed.is_valid_transition(Closing));
        assert!(!Closed.is_valid_transition(Draining));
        assert!(!Closed.is_valid_transition(Finalizing));
    }

    #[test]
    fn test_obligation_state_valid_transitions() {
        use ObligationState::*;

        // Valid transitions
        assert!(Reserved.is_valid_transition(Committed));
        assert!(Reserved.is_valid_transition(Aborted));
        assert!(Reserved.is_valid_transition(Leaked));

        // Invalid transitions (terminal states)
        assert!(!Committed.is_valid_transition(Reserved));
        assert!(!Committed.is_valid_transition(Aborted));
        assert!(!Committed.is_valid_transition(Leaked));
        assert!(!Aborted.is_valid_transition(Reserved));
        assert!(!Aborted.is_valid_transition(Committed));
        assert!(!Aborted.is_valid_transition(Leaked));
        assert!(!Leaked.is_valid_transition(Reserved));
        assert!(!Leaked.is_valid_transition(Committed));
        assert!(!Leaked.is_valid_transition(Aborted));
    }

    #[test]
    fn test_state_verifier_task_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use crate::record::task::TaskPhase::*;
        let task_id = TaskId::new(1);

        // Valid transition
        assert!(verifier.validate_task_transition(task_id, Created, Running, "test").is_ok());

        // Invalid transition
        assert!(verifier.validate_task_transition(task_id, Created, Finalizing, "test").is_err());

        let stats = verifier.stats();
        assert_eq!(stats.task_transitions, 2);
        assert_eq!(stats.task_violations, 1);
    }

    #[test]
    fn test_state_verifier_region_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use RegionState::*;
        let region_id = RegionId::new(1);

        // Valid transition
        assert!(verifier.validate_region_transition(region_id, Open, Closing, "test").is_ok());

        // Invalid transition
        assert!(verifier.validate_region_transition(region_id, Open, Closed, "test").is_err());

        let stats = verifier.stats();
        assert_eq!(stats.region_transitions, 2);
        assert_eq!(stats.region_violations, 1);
    }

    #[test]
    fn test_state_verifier_obligation_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new(1);

        // Valid transition
        assert!(verifier.validate_obligation_transition(obligation_id, Reserved, Committed, "test").is_ok());

        // Invalid transition
        assert!(verifier.validate_obligation_transition(obligation_id, Committed, Reserved, "test").is_err());

        let stats = verifier.stats();
        assert_eq!(stats.obligation_transitions, 2);
        assert_eq!(stats.obligation_violations, 1);
    }

    #[test]
    fn test_violation_tracking() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            max_tracked_violations: 2,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new(1);

        // Generate violations
        let _ = verifier.validate_obligation_transition(obligation_id, Committed, Reserved, "test1");
        let _ = verifier.validate_obligation_transition(obligation_id, Aborted, Reserved, "test2");
        let _ = verifier.validate_obligation_transition(obligation_id, Leaked, Reserved, "test3");

        let violations = verifier.violations();
        assert_eq!(violations.len(), 2); // Limited to max_tracked_violations
        assert_eq!(violations[0].context, "test2"); // Oldest dropped
        assert_eq!(violations[1].context, "test3");

        verifier.clear_violations();
        assert_eq!(verifier.violations().len(), 0);
    }

    #[test]
    #[should_panic(expected = "Invalid state transition")]
    fn test_panic_on_violation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: true,
            enable_diagnostics: false,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new(1);

        // This should panic
        let _ = verifier.validate_obligation_transition(obligation_id, Committed, Reserved, "test");
    }
}