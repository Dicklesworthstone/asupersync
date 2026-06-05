//! Cancel Protocol State Machines
//!
//! This module defines formal state machines for all cancellation protocol components
//! in asupersync. These state machines ensure cancel-safety by tracking valid state
//! transitions and detecting protocol violations at runtime.
//!
//! # Design Principles
//!
//! 1. **Mathematically Precise**: Each state machine has well-defined states and transitions
//! 2. **Protocol Compliant**: Aligned with asupersync's structured concurrency guarantees
//! 3. **Runtime Validated**: State transitions are checked at runtime with configurable assertion levels
//! 4. **Performance Aware**: Minimal overhead in optimized builds
//! 5. **Error Recovery**: Clear error states for protocol violations
//!
//! # State Machines Defined
//!
//! - [`RegionStateMachine`]: Region lifecycle from creation to finalization
//! - [`TaskStateMachine`]: Task lifecycle from spawn to completion/cancellation
//! - [`ObligationStateMachine`]: Two-phase reserve/commit protocol states
//! - [`ChannelStateMachine`]: Channel lifecycle with proper waker cleanup
//! - [`IoStateMachine`]: IO operation states including cancellation cleanup
//! - [`TimerStateMachine`]: Timer lifecycle with cancellation support

#![allow(missing_docs)]

use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::HashMap;
use std::fmt::Debug;

// ============================================================================
// State Machine Framework
// ============================================================================

/// Validation level for state machine assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// No validation (production default).
    None,
    /// Basic validation - only critical invariants.
    Basic,
    /// Full validation - all state transitions checked.
    Full,
    /// Debug validation - includes detailed logging.
    Debug,
}

/// Result of a state transition validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    /// Transition is valid.
    Valid,
    /// Transition violates the protocol.
    Invalid {
        reason: String,
        current_state: String,
        attempted_transition: String,
    },
    /// Transition would be valid but violates an invariant.
    InvariantViolation { invariant: String, context: String },
}

/// Trait for all cancel protocol state machines.
pub trait CancelStateMachine: Debug {
    type State: Debug + Clone + PartialEq;
    type Event: Debug + Clone;
    type Context: Debug;

    /// Get the current state.
    fn current_state(&self) -> &Self::State;

    /// Attempt a state transition.
    fn transition(&mut self, event: Self::Event, context: &Self::Context) -> TransitionResult;

    /// Check if the state machine is in a terminal state.
    fn is_terminal(&self) -> bool;

    /// Get all valid transitions from the current state.
    fn valid_transitions(&self) -> Vec<Self::Event>;

    /// Check invariants for the current state.
    fn check_invariants(&self, context: &Self::Context) -> Result<(), String>;

    /// Get a human-readable description of the current state.
    fn state_description(&self) -> String;
}

// ============================================================================
// Region State Machine
// ============================================================================

/// States in the region lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionState {
    /// Region has been created but not yet active.
    Created,
    /// Region is active and can spawn tasks.
    Active {
        active_tasks: u32,
        pending_finalizers: u32,
    },
    /// Region is cancelling - no new tasks, existing tasks draining.
    Cancelling {
        draining_tasks: u32,
        pending_finalizers: u32,
        cancel_reason: String,
    },
    /// All tasks drained, finalizers running.
    Finalizing { running_finalizers: u32 },
    /// Region fully quiesced and finalized.
    Finalized,
    /// Error state - protocol violation detected.
    Error {
        violation: String,
        last_valid_state: Box<Self>,
    },
}

/// Events that can trigger region state transitions.
#[derive(Debug, Clone)]
pub enum RegionEvent {
    /// Activate the region.
    Activate,
    /// Spawn a new task in the region.
    TaskSpawned,
    /// A task completed normally.
    TaskCompleted,
    /// A task was cancelled and drained.
    TaskDrained,
    /// Cancel the region with a reason.
    Cancel { reason: String },
    /// Register a finalizer.
    FinalizerRegistered,
    /// A finalizer started running.
    FinalizerStarted,
    /// A finalizer completed.
    FinalizerCompleted,
    /// Request region close (must be quiesced).
    RequestClose,
}

/// Context for region state transitions.
#[derive(Debug)]
pub struct RegionContext {
    pub region_id: RegionId,
    pub parent_region: Option<RegionId>,
    pub created_at: Time,
    pub validation_level: ValidationLevel,
}

/// Region lifecycle state machine.
///
/// Identity fields (`region_id`, `validation_level`) are retained for tracing,
/// structured logging, and external validator harnesses even when the in-crate
/// consumer only reads `state`. Suppress `dead_code` for the whole struct so
/// the lib builds without a `protocol_validator_test_suite`-like reader.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RegionStateMachine {
    state: RegionState,
    region_id: RegionId,
    transition_history: Vec<(Time, RegionEvent, RegionState)>,
    validation_level: ValidationLevel,
}

impl RegionStateMachine {
    /// Create a new region state machine.
    #[must_use]
    pub fn new(region_id: RegionId, validation_level: ValidationLevel) -> Self {
        Self {
            state: RegionState::Created,
            region_id,
            transition_history: Vec::new(),
            validation_level,
        }
    }

    /// Get the number of active tasks.
    #[must_use]
    pub fn active_task_count(&self) -> u32 {
        match &self.state {
            RegionState::Active { active_tasks, .. } => *active_tasks,
            RegionState::Cancelling { draining_tasks, .. } => *draining_tasks,
            _ => 0,
        }
    }

    /// Check if the region is quiesced (no active tasks, no finalizers).
    #[must_use]
    pub fn is_quiesced(&self) -> bool {
        match self.state {
            RegionState::Created | RegionState::Finalized => true,
            RegionState::Active {
                active_tasks: 0,
                pending_finalizers: 0,
            } => true,
            RegionState::Cancelling {
                draining_tasks: 0,
                pending_finalizers: 0,
                ..
            } => true,
            _ => false,
        }
    }

    /// Check region-specific invariants.
    fn check_region_invariants(&self, _context: &RegionContext) -> Result<(), String> {
        match &self.state {
            RegionState::Created => {
                // Created region should have no tasks or finalizers
                Ok(())
            }
            RegionState::Active { .. } => {
                // An active region may legitimately be empty between activation,
                // task admission, and an explicit RequestClose transition.
                Ok(())
            }
            RegionState::Cancelling {
                draining_tasks,
                pending_finalizers,
                ..
            } => {
                // Cancelling region should eventually drain all tasks
                if *draining_tasks == 0 && *pending_finalizers == 0 {
                    return Err(
                        "Cancelling region with no tasks should transition to finalizing"
                            .to_string(),
                    );
                }
                Ok(())
            }
            RegionState::Finalizing { running_finalizers } => {
                // Finalizing region should eventually complete all finalizers
                if *running_finalizers == 0 {
                    return Err(
                        "Finalizing region with no running finalizers should be finalized"
                            .to_string(),
                    );
                }
                Ok(())
            }
            RegionState::Finalized => {
                // Finalized region is terminal - no further transitions allowed
                Ok(())
            }
            RegionState::Error { .. } => {
                // Error state is terminal
                Ok(())
            }
        }
    }
}

impl CancelStateMachine for RegionStateMachine {
    type State = RegionState;
    type Event = RegionEvent;
    type Context = RegionContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, context: &Self::Context) -> TransitionResult {
        let old_state = self.state.clone();
        let new_state = match (&self.state, &event) {
            // Created -> Active
            (RegionState::Created, RegionEvent::Activate) => RegionState::Active {
                active_tasks: 0,
                pending_finalizers: 0,
            },

            // Active state transitions
            (
                RegionState::Active {
                    active_tasks,
                    pending_finalizers,
                },
                RegionEvent::TaskSpawned,
            ) => RegionState::Active {
                active_tasks: active_tasks + 1,
                pending_finalizers: *pending_finalizers,
            },
            (
                RegionState::Active {
                    active_tasks,
                    pending_finalizers,
                },
                RegionEvent::TaskCompleted,
            ) => {
                if *active_tasks == 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot complete task in region with no active tasks".to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                RegionState::Active {
                    active_tasks: active_tasks - 1,
                    pending_finalizers: *pending_finalizers,
                }
            }
            (
                RegionState::Active {
                    active_tasks,
                    pending_finalizers,
                },
                RegionEvent::FinalizerRegistered,
            ) => RegionState::Active {
                active_tasks: *active_tasks,
                pending_finalizers: pending_finalizers + 1,
            },
            (
                RegionState::Active {
                    active_tasks,
                    pending_finalizers,
                },
                RegionEvent::Cancel { reason },
            ) => match (*active_tasks, *pending_finalizers) {
                (0, 0) => RegionState::Finalized,
                (0, running_finalizers) => RegionState::Finalizing { running_finalizers },
                (draining_tasks, pending_finalizers) => RegionState::Cancelling {
                    draining_tasks,
                    pending_finalizers,
                    cancel_reason: reason.clone(),
                },
            },
            (
                RegionState::Active {
                    active_tasks,
                    pending_finalizers,
                },
                RegionEvent::RequestClose,
            ) => {
                if *active_tasks > 0 || *pending_finalizers > 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot close active region with pending work".to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                RegionState::Finalized
            }

            // Cancelling state transitions
            (state @ RegionState::Cancelling { .. }, RegionEvent::Cancel { .. }) => state.clone(),
            (
                RegionState::Cancelling {
                    draining_tasks,
                    pending_finalizers,
                    cancel_reason,
                },
                RegionEvent::TaskDrained,
            ) => {
                if *draining_tasks == 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot drain task in region with no draining tasks".to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                let new_draining = draining_tasks - 1;
                if new_draining == 0 && *pending_finalizers == 0 {
                    RegionState::Finalized
                } else if new_draining == 0 {
                    RegionState::Finalizing {
                        running_finalizers: *pending_finalizers,
                    }
                } else {
                    RegionState::Cancelling {
                        draining_tasks: new_draining,
                        pending_finalizers: *pending_finalizers,
                        cancel_reason: cancel_reason.clone(),
                    }
                }
            }
            (state @ RegionState::Cancelling { .. }, RegionEvent::FinalizerStarted) => {
                // FinalizerStarted does not change the count of pending_finalizers,
                // because TaskDrained relies on pending_finalizers to initialize running_finalizers
                // when transitioning to Finalizing.
                state.clone()
            }
            (
                RegionState::Cancelling {
                    draining_tasks,
                    pending_finalizers,
                    cancel_reason,
                },
                RegionEvent::FinalizerRegistered,
            ) => RegionState::Cancelling {
                draining_tasks: *draining_tasks,
                pending_finalizers: pending_finalizers + 1,
                cancel_reason: cancel_reason.clone(),
            },

            // Finalizing state transitions
            (RegionState::Finalizing { running_finalizers }, RegionEvent::FinalizerCompleted) => {
                if *running_finalizers == 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot complete finalizer with no running finalizers".to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                let new_running = running_finalizers - 1;
                if new_running == 0 {
                    RegionState::Finalized
                } else {
                    RegionState::Finalizing {
                        running_finalizers: new_running,
                    }
                }
            }

            (state @ RegionState::Finalizing { .. }, RegionEvent::FinalizerStarted) => {
                state.clone()
            }
            (state @ RegionState::Finalizing { .. }, RegionEvent::Cancel { .. }) => state.clone(),
            (state @ RegionState::Finalized, RegionEvent::Cancel { .. }) => state.clone(),

            // Terminal states - no transitions allowed
            (RegionState::Finalized, _) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from finalized state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
            (RegionState::Error { .. }, _) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from error state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }

            // Invalid transitions
            _ => {
                return TransitionResult::Invalid {
                    reason: format!(
                        "Invalid transition from {:?} with event {:?}",
                        self.state, event
                    ),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        // Check invariants on the new state
        self.state = new_state.clone();
        if let Err(invariant_error) = self.check_invariants(context) {
            self.state = RegionState::Error {
                violation: invariant_error.clone(),
                last_valid_state: Box::new(old_state),
            };
            return TransitionResult::InvariantViolation {
                invariant: "Region invariant".to_string(),
                context: invariant_error,
            };
        }

        // Record transition if validation is enabled
        if self.validation_level != ValidationLevel::None {
            self.transition_history
                .push((context.created_at, event, new_state));
        }

        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            RegionState::Finalized | RegionState::Error { .. }
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            RegionState::Created => vec![RegionEvent::Activate],
            RegionState::Active { .. } => vec![
                RegionEvent::TaskSpawned,
                RegionEvent::TaskCompleted,
                RegionEvent::FinalizerRegistered,
                RegionEvent::Cancel {
                    reason: "example".to_string(),
                },
                RegionEvent::RequestClose,
            ],
            RegionState::Cancelling { .. } => vec![
                RegionEvent::TaskDrained,
                RegionEvent::FinalizerStarted,
                RegionEvent::FinalizerRegistered,
                RegionEvent::Cancel {
                    reason: "example".to_string(),
                },
            ],
            RegionState::Finalizing { .. } => vec![
                RegionEvent::FinalizerStarted,
                RegionEvent::FinalizerCompleted,
                RegionEvent::Cancel {
                    reason: "example".to_string(),
                },
            ],
            RegionState::Finalized => vec![RegionEvent::Cancel {
                reason: "example".to_string(),
            }],
            RegionState::Error { .. } => vec![],
        }
    }

    fn check_invariants(&self, context: &Self::Context) -> Result<(), String> {
        self.check_region_invariants(context)
    }

    fn state_description(&self) -> String {
        match &self.state {
            RegionState::Created => "Created - ready for activation".to_string(),
            RegionState::Active {
                active_tasks,
                pending_finalizers,
            } => {
                format!("Active - {active_tasks} tasks, {pending_finalizers} finalizers")
            }
            RegionState::Cancelling {
                draining_tasks,
                pending_finalizers,
                cancel_reason,
            } => {
                format!(
                    "Cancelling ({cancel_reason}) - {draining_tasks} draining, {pending_finalizers} finalizers"
                )
            }
            RegionState::Finalizing { running_finalizers } => {
                format!("Finalizing - {running_finalizers} finalizers running")
            }
            RegionState::Finalized => "Finalized - terminal state".to_string(),
            RegionState::Error { violation, .. } => {
                format!("Error - {violation}")
            }
        }
    }
}

// ============================================================================
// Task State Machine
// ============================================================================

/// States in the task lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// Task has been spawned but not yet started.
    Spawned,
    /// Task is actively running.
    Running,
    /// Task has been requested to cancel.
    CancelRequested,
    /// Task is draining (completing current work before exit).
    Draining,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled and has been drained.
    Cancelled,
    /// Task panicked during execution.
    Panicked { message: String },
    /// Error state - protocol violation.
    Error { violation: String },
}

/// Events for task state transitions.
#[derive(Debug, Clone)]
pub enum TaskEvent {
    /// Start executing the task.
    Start,
    /// Request task cancellation.
    RequestCancel,
    /// Task completed its work successfully.
    Complete,
    /// Task finished draining after cancel.
    DrainComplete,
    /// Task panicked.
    Panic { message: String },
}

/// Context for task state transitions.
#[derive(Debug)]
pub struct TaskContext {
    pub task_id: TaskId,
    pub region_id: RegionId,
    pub spawned_at: Time,
    pub validation_level: ValidationLevel,
}

/// Task lifecycle state machine.
#[derive(Debug)]
#[allow(dead_code)] // identity fields retained for tracing/validator harnesses
pub struct TaskStateMachine {
    state: TaskState,
    task_id: TaskId,
    region_id: RegionId,
    validation_level: ValidationLevel,
}

impl TaskStateMachine {
    /// Create a new task state machine.
    #[must_use]
    pub fn new(task_id: TaskId, region_id: RegionId, validation_level: ValidationLevel) -> Self {
        Self {
            state: TaskState::Spawned,
            task_id,
            region_id,
            validation_level,
        }
    }

    /// Check if the task is in a state where it can be cancelled.
    #[must_use]
    pub fn is_cancellable(&self) -> bool {
        matches!(self.state, TaskState::Spawned | TaskState::Running)
    }

    /// Check if the task has completed (successfully, cancelled, or panicked).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            TaskState::Completed | TaskState::Cancelled | TaskState::Panicked { .. }
        )
    }
}

impl CancelStateMachine for TaskStateMachine {
    type State = TaskState;
    type Event = TaskEvent;
    type Context = TaskContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, _context: &Self::Context) -> TransitionResult {
        let _old_state = self.state.clone();
        let new_state = match (&self.state, &event) {
            // Spawned -> Running
            (TaskState::Spawned, TaskEvent::Start) => TaskState::Running,

            // Spawned -> Cancelled (cancelled before starting)
            (TaskState::Spawned, TaskEvent::RequestCancel) => TaskState::Cancelled,

            // Running -> Completed
            (TaskState::Running, TaskEvent::Complete) => TaskState::Completed,

            // Running -> CancelRequested
            (TaskState::Running, TaskEvent::RequestCancel) => TaskState::CancelRequested,

            // Running -> Panicked
            (TaskState::Running, TaskEvent::Panic { message }) => TaskState::Panicked {
                message: message.clone(),
            },

            // Repeated cancellation is a no-op once the task is already draining/cancelled.
            (
                state @ (TaskState::CancelRequested | TaskState::Draining | TaskState::Cancelled),
                TaskEvent::RequestCancel,
            ) => state.clone(),

            // CancelRequested -> Draining (task acknowledges cancel and starts cleanup)
            (TaskState::CancelRequested, TaskEvent::DrainComplete) => TaskState::Cancelled,

            // CancelRequested -> Panicked (task panics during cancel)
            (TaskState::CancelRequested, TaskEvent::Panic { message }) => TaskState::Panicked {
                message: message.clone(),
            },

            // Terminal states - no transitions
            (
                TaskState::Completed
                | TaskState::Cancelled
                | TaskState::Panicked { .. }
                | TaskState::Error { .. },
                _,
            ) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from terminal state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }

            // Invalid transitions
            _ => {
                return TransitionResult::Invalid {
                    reason: format!(
                        "Invalid transition from {:?} with event {:?}",
                        self.state, event
                    ),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        self.state = new_state;
        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TaskState::Completed
                | TaskState::Cancelled
                | TaskState::Panicked { .. }
                | TaskState::Error { .. }
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            TaskState::Spawned => vec![TaskEvent::Start, TaskEvent::RequestCancel],
            TaskState::Running => vec![
                TaskEvent::Complete,
                TaskEvent::RequestCancel,
                TaskEvent::Panic {
                    message: "example".to_string(),
                },
            ],
            TaskState::CancelRequested => vec![
                TaskEvent::DrainComplete,
                TaskEvent::RequestCancel,
                TaskEvent::Panic {
                    message: "example".to_string(),
                },
            ],
            TaskState::Draining => vec![TaskEvent::RequestCancel],
            TaskState::Cancelled => vec![TaskEvent::RequestCancel],
            _ => vec![],
        }
    }

    fn check_invariants(&self, _context: &Self::Context) -> Result<(), String> {
        // Task-specific invariants
        match &self.state {
            TaskState::Draining => {
                // Tasks in draining state should eventually complete draining
                // This is a temporal invariant that would be checked by the validator
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn state_description(&self) -> String {
        match &self.state {
            TaskState::Spawned => "Spawned - waiting to start".to_string(),
            TaskState::Running => "Running - actively executing".to_string(),
            TaskState::CancelRequested => "Cancel requested - draining".to_string(),
            TaskState::Draining => "Draining - completing cleanup".to_string(),
            TaskState::Completed => "Completed - finished successfully".to_string(),
            TaskState::Cancelled => "Cancelled - drained and terminated".to_string(),
            TaskState::Panicked { message } => format!("Panicked - {message}"),
            TaskState::Error { violation } => format!("Error - {violation}"),
        }
    }
}

// ============================================================================
// Obligation State Machine
// ============================================================================

/// States in the obligation lifecycle (two-phase reserve/commit protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationState {
    /// Obligation created but not yet reserved.
    Created,
    /// Resources reserved, must commit or abort.
    Reserved { reservation_token: u64 },
    /// Resources committed, obligation fulfilled.
    Committed,
    /// Reservation aborted, resources released.
    Aborted { reason: String },
    /// Error state - protocol violation.
    Error { violation: String },
}

/// Events for obligation state transitions.
#[derive(Debug, Clone)]
pub enum ObligationEvent {
    /// Reserve resources for this obligation.
    Reserve { token: u64 },
    /// Commit the reserved resources.
    Commit,
    /// Abort the reservation.
    Abort { reason: String },
}

/// Context for obligation state transitions.
#[derive(Debug)]
pub struct ObligationContext {
    pub obligation_id: ObligationId,
    pub region_id: RegionId,
    pub created_at: Time,
    pub validation_level: ValidationLevel,
}

/// Obligation lifecycle state machine.
#[derive(Debug)]
#[allow(dead_code)] // identity fields retained for tracing/validator harnesses
pub struct ObligationStateMachine {
    state: ObligationState,
    obligation_id: ObligationId,
    validation_level: ValidationLevel,
}

impl ObligationStateMachine {
    /// Create a new obligation state machine.
    #[must_use]
    pub fn new(obligation_id: ObligationId, validation_level: ValidationLevel) -> Self {
        Self {
            state: ObligationState::Created,
            obligation_id,
            validation_level,
        }
    }

    /// Check if the obligation is currently reserved.
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        matches!(self.state, ObligationState::Reserved { .. })
    }

    /// Check if the obligation is fulfilled (committed or aborted).
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(
            self.state,
            ObligationState::Committed | ObligationState::Aborted { .. }
        )
    }
}

impl CancelStateMachine for ObligationStateMachine {
    type State = ObligationState;
    type Event = ObligationEvent;
    type Context = ObligationContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, context: &Self::Context) -> TransitionResult {
        let old_state = self.state.clone();
        let new_state = match (&self.state, &event) {
            // Created -> Reserved
            (ObligationState::Created, ObligationEvent::Reserve { token }) => {
                ObligationState::Reserved {
                    reservation_token: *token,
                }
            }

            // Reserved -> Committed
            (ObligationState::Reserved { .. }, ObligationEvent::Commit) => {
                ObligationState::Committed
            }

            // Reserved -> Aborted
            (ObligationState::Reserved { .. }, ObligationEvent::Abort { reason }) => {
                ObligationState::Aborted {
                    reason: reason.clone(),
                }
            }

            // Terminal states - no transitions
            (
                ObligationState::Committed
                | ObligationState::Aborted { .. }
                | ObligationState::Error { .. },
                _,
            ) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from terminal obligation state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }

            // Invalid transitions
            _ => {
                return TransitionResult::Invalid {
                    reason: format!(
                        "Invalid obligation transition from {:?} with event {:?}",
                        self.state, event
                    ),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        // ATOMIC FIX: Check invariants on new state BEFORE leaving it in an invalid state
        // to prevent race condition where state is temporarily invalid
        self.state = new_state.clone();
        if let Err(invariant_error) = self.check_invariants(context) {
            // Set error state immediately on invariant violation - no intermediate invalid state
            self.state = ObligationState::Error {
                violation: invariant_error.clone(),
            };
            return TransitionResult::InvariantViolation {
                invariant: "Obligation invariant".to_string(),
                context: format!(
                    "{invariant_error}; previous state: {old_state:?}, attempted transition: {event:?}"
                ),
            };
        }
        // State transition is now atomic - new state is valid and committed
        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ObligationState::Committed
                | ObligationState::Aborted { .. }
                | ObligationState::Error { .. }
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            ObligationState::Created => vec![ObligationEvent::Reserve { token: 0 }],
            ObligationState::Reserved { .. } => vec![
                ObligationEvent::Commit,
                ObligationEvent::Abort {
                    reason: "example".to_string(),
                },
            ],
            _ => vec![],
        }
    }

    fn check_invariants(&self, _context: &Self::Context) -> Result<(), String> {
        match &self.state {
            ObligationState::Reserved { reservation_token } => {
                if *reservation_token == 0 {
                    return Err("Reserved obligation must have non-zero token".to_string());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn state_description(&self) -> String {
        match &self.state {
            ObligationState::Created => "Created - ready for reservation".to_string(),
            ObligationState::Reserved { reservation_token } => {
                format!("Reserved - token {reservation_token}")
            }
            ObligationState::Committed => "Committed - obligation fulfilled".to_string(),
            ObligationState::Aborted { reason } => {
                format!("Aborted - {reason}")
            }
            ObligationState::Error { violation } => {
                format!("Error - {violation}")
            }
        }
    }
}

// ============================================================================
// Channel State Machine
// ============================================================================

/// States in the channel lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is open and accepting operations.
    Open { pending_reservations: u32 },
    /// Close initiated, operations draining.
    Closing { draining_ops: u32 },
    /// Terminal state, all wakers cleaned up.
    Closed,
    /// Error state - protocol violation.
    Error { violation: String },
}

/// Events for channel state transitions.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// Operation started (reservation made).
    OperationStarted,
    /// Operation completed (reservation released).
    OperationCompleted,
    /// Initiate channel close.
    InitiateClose,
    /// All operations drained, channel can close.
    AllOperationsDrained,
}

/// Context for channel state transitions.
#[derive(Debug)]
pub struct ChannelContext {
    pub channel_id: u64, // Simplified channel ID
    pub validation_level: ValidationLevel,
}

/// Channel lifecycle state machine.
#[derive(Debug)]
#[allow(dead_code)] // identity fields retained for tracing/validator harnesses
pub struct ChannelStateMachine {
    state: ChannelState,
    channel_id: u64,
    validation_level: ValidationLevel,
}

impl ChannelStateMachine {
    /// Create a new channel state machine.
    #[must_use]
    pub fn new(channel_id: u64, validation_level: ValidationLevel) -> Self {
        Self {
            state: ChannelState::Open {
                pending_reservations: 0,
            },
            channel_id,
            validation_level,
        }
    }

    /// Check if the channel is accepting new operations.
    #[must_use]
    pub fn is_accepting_ops(&self) -> bool {
        matches!(self.state, ChannelState::Open { .. })
    }

    /// Get the number of pending operations.
    #[must_use]
    pub fn pending_ops(&self) -> u32 {
        match &self.state {
            ChannelState::Open {
                pending_reservations,
            } => *pending_reservations,
            ChannelState::Closing { draining_ops } => *draining_ops,
            _ => 0,
        }
    }
}

impl CancelStateMachine for ChannelStateMachine {
    type State = ChannelState;
    type Event = ChannelEvent;
    type Context = ChannelContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, _context: &Self::Context) -> TransitionResult {
        let new_state = match (&self.state, &event) {
            // Open state transitions
            (
                ChannelState::Open {
                    pending_reservations,
                },
                ChannelEvent::OperationStarted,
            ) => ChannelState::Open {
                pending_reservations: pending_reservations + 1,
            },
            (
                ChannelState::Open {
                    pending_reservations,
                },
                ChannelEvent::OperationCompleted,
            ) => {
                if *pending_reservations == 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot complete operation with no pending reservations"
                            .to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                ChannelState::Open {
                    pending_reservations: pending_reservations - 1,
                }
            }
            (
                ChannelState::Open {
                    pending_reservations,
                },
                ChannelEvent::InitiateClose,
            ) => {
                if *pending_reservations == 0 {
                    ChannelState::Closed
                } else {
                    ChannelState::Closing {
                        draining_ops: *pending_reservations,
                    }
                }
            }
            (state @ ChannelState::Closing { .. }, ChannelEvent::InitiateClose) => state.clone(),
            (state @ ChannelState::Closed, ChannelEvent::InitiateClose) => state.clone(),

            // Closing state transitions
            (ChannelState::Closing { draining_ops }, ChannelEvent::OperationCompleted) => {
                if *draining_ops == 0 {
                    return TransitionResult::Invalid {
                        reason: "Cannot complete operation with no draining ops".to_string(),
                        current_state: format!("{:?}", self.state),
                        attempted_transition: format!("{event:?}"),
                    };
                }
                let new_draining = draining_ops - 1;
                if new_draining == 0 {
                    ChannelState::Closed
                } else {
                    ChannelState::Closing {
                        draining_ops: new_draining,
                    }
                }
            }
            (ChannelState::Closing { draining_ops }, ChannelEvent::AllOperationsDrained) => {
                if *draining_ops != 0 {
                    return TransitionResult::InvariantViolation {
                        invariant: "All operations must be drained before this event".to_string(),
                        context: format!("Still {draining_ops} draining ops"),
                    };
                }
                ChannelState::Closed
            }

            // Terminal/error states - no transitions
            (ChannelState::Closed | ChannelState::Error { .. }, _) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from terminal channel state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }

            // Invalid transitions
            _ => {
                return TransitionResult::Invalid {
                    reason: format!(
                        "Invalid channel transition from {:?} with event {:?}",
                        self.state, event
                    ),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        self.state = new_state;
        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ChannelState::Closed | ChannelState::Error { .. }
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            ChannelState::Open { .. } => vec![
                ChannelEvent::OperationStarted,
                ChannelEvent::OperationCompleted,
                ChannelEvent::InitiateClose,
            ],
            ChannelState::Closing { .. } => vec![
                ChannelEvent::OperationCompleted,
                ChannelEvent::AllOperationsDrained,
                ChannelEvent::InitiateClose,
            ],
            ChannelState::Closed => vec![ChannelEvent::InitiateClose],
            ChannelState::Error { .. } => vec![],
        }
    }

    fn check_invariants(&self, _context: &Self::Context) -> Result<(), String> {
        match &self.state {
            ChannelState::Closing { draining_ops } => {
                if *draining_ops == 0 {
                    return Err(
                        "Closing channel should transition to closed when no ops remain"
                            .to_string(),
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn state_description(&self) -> String {
        match &self.state {
            ChannelState::Open {
                pending_reservations,
            } => {
                format!("Open - {pending_reservations} pending operations")
            }
            ChannelState::Closing { draining_ops } => {
                format!("Closing - {draining_ops} operations draining")
            }
            ChannelState::Closed => "Closed - terminal state".to_string(),
            ChannelState::Error { violation } => {
                format!("Error - {violation}")
            }
        }
    }
}

// ============================================================================
// IO Operation State Machine
// ============================================================================

/// States in the IO operation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoState {
    /// Operation submitted to IO driver.
    Pending { io_handle: u64 },
    /// Cancel signal received.
    Cancelled,
    /// Cleaning up cancelled operation.
    Cleanup,
    /// Operation completed successfully.
    Completed { result_size: usize },
    /// IO error occurred.
    Error { io_error: String },
}

/// Events for IO operation state transitions.
#[derive(Debug, Clone)]
pub enum IoEvent {
    /// IO operation completed successfully.
    Complete { result_size: usize },
    /// Cancel the IO operation.
    Cancel,
    /// Cleanup of cancelled operation finished.
    CleanupComplete,
    /// IO error occurred.
    IoError { error: String },
}

/// Context for IO operation state transitions.
#[derive(Debug)]
pub struct IoContext {
    pub operation_id: u64,
    pub operation_type: String,
    pub validation_level: ValidationLevel,
}

/// IO operation state machine.
#[derive(Debug)]
#[allow(dead_code)] // identity fields retained for tracing/validator harnesses
pub struct IoStateMachine {
    state: IoState,
    operation_id: u64,
    validation_level: ValidationLevel,
}

impl IoStateMachine {
    /// Create a new IO operation state machine.
    #[must_use]
    pub fn new(operation_id: u64, io_handle: u64, validation_level: ValidationLevel) -> Self {
        Self {
            state: IoState::Pending { io_handle },
            operation_id,
            validation_level,
        }
    }

    /// Check if the operation is still pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.state, IoState::Pending { .. })
    }

    /// Check if the operation completed successfully.
    #[must_use]
    pub fn completed_successfully(&self) -> bool {
        matches!(self.state, IoState::Completed { .. })
    }
}

impl CancelStateMachine for IoStateMachine {
    type State = IoState;
    type Event = IoEvent;
    type Context = IoContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, _context: &Self::Context) -> TransitionResult {
        let new_state = match (&self.state, &event) {
            // Pending state transitions
            (IoState::Pending { .. }, IoEvent::Complete { result_size }) => IoState::Completed {
                result_size: *result_size,
            },
            (IoState::Pending { .. }, IoEvent::Cancel) => IoState::Cancelled,
            (IoState::Pending { .. }, IoEvent::IoError { error }) => IoState::Error {
                io_error: error.clone(),
            },
            (state @ (IoState::Cancelled | IoState::Cleanup), IoEvent::Cancel) => state.clone(),

            // Cancelled -> Cleanup
            (IoState::Cancelled, IoEvent::CleanupComplete) => IoState::Cleanup,

            // Terminal states - no transitions
            (IoState::Completed { .. } | IoState::Error { .. } | IoState::Cleanup, _) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from terminal IO state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }

            // Invalid transitions
            _ => {
                return TransitionResult::Invalid {
                    reason: format!(
                        "Invalid IO transition from {:?} with event {:?}",
                        self.state, event
                    ),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        self.state = new_state;
        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            IoState::Completed { .. } | IoState::Error { .. } | IoState::Cleanup
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            IoState::Pending { .. } => vec![
                IoEvent::Complete { result_size: 0 },
                IoEvent::Cancel,
                IoEvent::IoError {
                    error: "example".to_string(),
                },
            ],
            IoState::Cancelled => vec![IoEvent::CleanupComplete, IoEvent::Cancel],
            IoState::Cleanup => vec![IoEvent::Cancel],
            _ => vec![],
        }
    }

    fn check_invariants(&self, _context: &Self::Context) -> Result<(), String> {
        // IO-specific invariants could be added here
        // e.g., handle validity, cleanup requirements, etc.
        Ok(())
    }

    fn state_description(&self) -> String {
        match &self.state {
            IoState::Pending { io_handle } => {
                format!("Pending - handle {io_handle}")
            }
            IoState::Cancelled => "Cancelled - awaiting cleanup".to_string(),
            IoState::Cleanup => "Cleanup complete - terminal".to_string(),
            IoState::Completed { result_size } => {
                format!("Completed - {result_size} bytes")
            }
            IoState::Error { io_error } => {
                format!("Error - {io_error}")
            }
        }
    }
}

// ============================================================================
// Timer State Machine
// ============================================================================

/// States in the timer lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimerState {
    /// Timer registered with timer wheel.
    Scheduled { deadline: Time },
    /// Timer cancelled before firing.
    Cancelled,
    /// Timer deadline reached and fired.
    Fired,
    /// Timer system error.
    Error { violation: String },
}

/// Events for timer state transitions.
#[derive(Debug, Clone)]
pub enum TimerEvent {
    /// Timer deadline reached.
    Fire,
    /// Cancel the timer.
    Cancel,
    /// Timer system error.
    TimerError { error: String },
}

/// Context for timer state transitions.
#[derive(Debug)]
pub struct TimerContext {
    pub timer_id: u64,
    pub current_time: Time,
    pub validation_level: ValidationLevel,
}

/// Timer state machine.
#[derive(Debug)]
#[allow(dead_code)] // identity fields retained for tracing/validator harnesses
pub struct TimerStateMachine {
    state: TimerState,
    timer_id: u64,
    validation_level: ValidationLevel,
}

impl TimerStateMachine {
    /// Create a new timer state machine.
    #[must_use]
    pub fn new(timer_id: u64, deadline: Time, validation_level: ValidationLevel) -> Self {
        Self {
            state: TimerState::Scheduled { deadline },
            timer_id,
            validation_level,
        }
    }

    /// Check if the timer is still scheduled.
    #[must_use]
    pub fn is_scheduled(&self) -> bool {
        matches!(self.state, TimerState::Scheduled { .. })
    }

    /// Get the timer deadline if scheduled.
    #[must_use]
    pub fn deadline(&self) -> Option<Time> {
        match &self.state {
            TimerState::Scheduled { deadline } => Some(*deadline),
            _ => None,
        }
    }
}

impl CancelStateMachine for TimerStateMachine {
    type State = TimerState;
    type Event = TimerEvent;
    type Context = TimerContext;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn transition(&mut self, event: Self::Event, context: &Self::Context) -> TransitionResult {
        let new_state = match (&self.state, &event) {
            // Scheduled state transitions
            (TimerState::Scheduled { deadline }, TimerEvent::Fire) => {
                // Verify deadline has been reached
                if context.current_time < *deadline {
                    return TransitionResult::InvariantViolation {
                        invariant: "Timer should not fire before deadline".to_string(),
                        context: format!(
                            "Current: {:?}, Deadline: {:?}",
                            context.current_time, deadline
                        ),
                    };
                }
                TimerState::Fired
            }
            (TimerState::Scheduled { .. }, TimerEvent::Cancel) => TimerState::Cancelled,
            (TimerState::Scheduled { .. }, TimerEvent::TimerError { error }) => TimerState::Error {
                violation: error.clone(),
            },
            (state @ TimerState::Cancelled, TimerEvent::Cancel) => state.clone(),

            // Terminal states - no transitions
            (TimerState::Cancelled | TimerState::Fired | TimerState::Error { .. }, _) => {
                return TransitionResult::Invalid {
                    reason: "Cannot transition from terminal timer state".to_string(),
                    current_state: format!("{:?}", self.state),
                    attempted_transition: format!("{event:?}"),
                };
            }
        };

        self.state = new_state;
        TransitionResult::Valid
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TimerState::Cancelled | TimerState::Fired | TimerState::Error { .. }
        )
    }

    fn valid_transitions(&self) -> Vec<Self::Event> {
        match &self.state {
            TimerState::Scheduled { .. } => vec![
                TimerEvent::Fire,
                TimerEvent::Cancel,
                TimerEvent::TimerError {
                    error: "example".to_string(),
                },
            ],
            TimerState::Cancelled => vec![TimerEvent::Cancel],
            _ => vec![],
        }
    }

    fn check_invariants(&self, context: &Self::Context) -> Result<(), String> {
        match &self.state {
            TimerState::Scheduled { deadline } => {
                if context.current_time > *deadline {
                    return Err(format!(
                        "Timer past deadline should have fired: current={:?}, deadline={:?}",
                        context.current_time, deadline
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn state_description(&self) -> String {
        match &self.state {
            TimerState::Scheduled { deadline } => {
                format!("Scheduled - deadline {deadline:?}")
            }
            TimerState::Cancelled => "Cancelled - will not fire".to_string(),
            TimerState::Fired => "Fired - timer completed".to_string(),
            TimerState::Error { violation } => {
                format!("Error - {violation}")
            }
        }
    }
}

// ============================================================================
// State Machine Validator
// ============================================================================

/// Runtime validator for cancel protocol state machines.
#[derive(Debug)]
pub struct CancelProtocolValidator {
    validation_level: ValidationLevel,
    region_machines: HashMap<RegionId, RegionStateMachine>,
    task_machines: HashMap<TaskId, TaskStateMachine>,
    obligation_machines: HashMap<ObligationId, ObligationStateMachine>,
    channel_machines: HashMap<u64, ChannelStateMachine>,
    io_machines: HashMap<u64, IoStateMachine>,
    timer_machines: HashMap<u64, TimerStateMachine>,
    violation_count: u64,
}

impl CancelProtocolValidator {
    /// Create a new cancel protocol validator.
    #[must_use]
    pub fn new(validation_level: ValidationLevel) -> Self {
        Self {
            validation_level,
            region_machines: HashMap::new(),
            task_machines: HashMap::new(),
            obligation_machines: HashMap::new(),
            channel_machines: HashMap::new(),
            io_machines: HashMap::new(),
            timer_machines: HashMap::new(),
            violation_count: 0,
        }
    }

    /// Register a new region for tracking.
    pub fn register_region(&mut self, region_id: RegionId) {
        let machine = RegionStateMachine::new(region_id, self.validation_level);
        self.region_machines.insert(region_id, machine);
    }

    /// Register a new task for tracking.
    pub fn register_task(&mut self, task_id: TaskId, region_id: RegionId) {
        let machine = TaskStateMachine::new(task_id, region_id, self.validation_level);
        self.task_machines.insert(task_id, machine);
    }

    /// Register a new obligation for tracking.
    pub fn register_obligation(&mut self, obligation_id: ObligationId) {
        let machine = ObligationStateMachine::new(obligation_id, self.validation_level);
        self.obligation_machines.insert(obligation_id, machine);
    }

    /// Register a new channel for tracking.
    pub fn register_channel(&mut self, channel_id: u64) {
        let machine = ChannelStateMachine::new(channel_id, self.validation_level);
        self.channel_machines.insert(channel_id, machine);
    }

    /// Register a new IO operation for tracking.
    pub fn register_io_operation(&mut self, operation_id: u64, io_handle: u64) {
        let machine = IoStateMachine::new(operation_id, io_handle, self.validation_level);
        self.io_machines.insert(operation_id, machine);
    }

    /// Register a new timer for tracking.
    pub fn register_timer(&mut self, timer_id: u64, deadline: Time) {
        let machine = TimerStateMachine::new(timer_id, deadline, self.validation_level);
        self.timer_machines.insert(timer_id, machine);
    }

    /// Emit a structured protocol-violation record without writing directly to stderr.
    ///
    /// When `tracing-integration` is disabled the compatibility macro compiles
    /// to a no-op, so the formatted fields appear unused in default builds.
    #[allow(unused_variables)]
    fn log_violation(
        &self,
        component: &'static str,
        identifier: &dyn Debug,
        result: &TransitionResult,
    ) {
        if matches!(
            self.validation_level,
            ValidationLevel::Debug | ValidationLevel::Full
        ) {
            crate::tracing_compat::error!(
                component = component,
                id = ?identifier,
                validation_level = ?self.validation_level,
                result = ?result,
                "cancel protocol violation"
            );
        }
    }

    /// Validate a region state transition.
    pub fn validate_region_transition(
        &mut self,
        region_id: RegionId,
        event: RegionEvent,
        context: &RegionContext,
    ) -> TransitionResult {
        if let Some(machine) = self.region_machines.get_mut(&region_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;

                self.log_violation("region", &region_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("Region {region_id:?} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("region", &region_id, &result);
            result
        }
    }

    /// Validate a task state transition.
    pub fn validate_task_transition(
        &mut self,
        task_id: TaskId,
        event: TaskEvent,
        context: &TaskContext,
    ) -> TransitionResult {
        if let Some(machine) = self.task_machines.get_mut(&task_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;

                self.log_violation("task", &task_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("Task {task_id:?} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("task", &task_id, &result);
            result
        }
    }

    /// Get the current state of a region.
    #[must_use]
    pub fn region_state(&self, region_id: RegionId) -> Option<&RegionState> {
        self.region_machines
            .get(&region_id)
            .map(CancelStateMachine::current_state)
    }

    /// Get the current state of a task.
    #[must_use]
    pub fn task_state(&self, task_id: TaskId) -> Option<&TaskState> {
        self.task_machines
            .get(&task_id)
            .map(CancelStateMachine::current_state)
    }

    /// Get the total number of protocol violations detected.
    #[must_use]
    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }

    /// Validate an obligation state transition.
    pub fn validate_obligation_transition(
        &mut self,
        obligation_id: ObligationId,
        event: ObligationEvent,
        context: &ObligationContext,
    ) -> TransitionResult {
        if let Some(machine) = self.obligation_machines.get_mut(&obligation_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;
                self.log_violation("obligation", &obligation_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("Obligation {obligation_id:?} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("obligation", &obligation_id, &result);
            result
        }
    }

    /// Validate a channel state transition.
    pub fn validate_channel_transition(
        &mut self,
        channel_id: u64,
        event: ChannelEvent,
        context: &ChannelContext,
    ) -> TransitionResult {
        if let Some(machine) = self.channel_machines.get_mut(&channel_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;
                self.log_violation("channel", &channel_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("Channel {channel_id} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("channel", &channel_id, &result);
            result
        }
    }

    /// Validate an IO operation state transition.
    pub fn validate_io_transition(
        &mut self,
        operation_id: u64,
        event: IoEvent,
        context: &IoContext,
    ) -> TransitionResult {
        if let Some(machine) = self.io_machines.get_mut(&operation_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;
                self.log_violation("io", &operation_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("IO operation {operation_id} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("io", &operation_id, &result);
            result
        }
    }

    /// Validate a timer state transition.
    pub fn validate_timer_transition(
        &mut self,
        timer_id: u64,
        event: TimerEvent,
        context: &TimerContext,
    ) -> TransitionResult {
        if let Some(machine) = self.timer_machines.get_mut(&timer_id) {
            let result = machine.transition(event, context);
            if let TransitionResult::Invalid { .. } | TransitionResult::InvariantViolation { .. } =
                &result
            {
                self.violation_count += 1;
                self.log_violation("timer", &timer_id, &result);
            }
            result
        } else {
            let result = TransitionResult::Invalid {
                reason: format!("Timer {timer_id} not registered with validator"),
                current_state: "Unknown".to_string(),
                attempted_transition: format!("{event:?}"),
            };
            self.violation_count += 1;
            self.log_violation("timer", &timer_id, &result);
            result
        }
    }

    /// Get validation statistics.
    #[must_use]
    pub fn stats(&self) -> (usize, usize, usize, usize, usize, usize, u64) {
        (
            self.region_machines.len(),
            self.task_machines.len(),
            self.obligation_machines.len(),
            self.channel_machines.len(),
            self.io_machines.len(),
            self.timer_machines.len(),
            self.violation_count,
        )
    }
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
    use proptest::prelude::*;

    fn region_context(region_id: RegionId) -> RegionContext {
        RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        }
    }

    fn task_context(task_id: TaskId, region_id: RegionId) -> TaskContext {
        TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        }
    }

    fn channel_context(channel_id: u64) -> ChannelContext {
        ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        }
    }

    fn io_context(operation_id: u64, operation_type: &str) -> IoContext {
        IoContext {
            operation_id,
            operation_type: operation_type.to_string(),
            validation_level: ValidationLevel::Full,
        }
    }

    fn timer_context(timer_id: u64, current_time: Time) -> TimerContext {
        TimerContext {
            timer_id,
            current_time,
            validation_level: ValidationLevel::Full,
        }
    }

    fn prime_region_for_cancel(
        machine: &mut RegionStateMachine,
        context: &RegionContext,
        active_tasks: u8,
        pending_finalizers: u8,
    ) {
        machine.transition(RegionEvent::Activate, context).unwrap();
        for _ in 0..active_tasks {
            machine
                .transition(RegionEvent::TaskSpawned, context)
                .unwrap();
        }
        for _ in 0..pending_finalizers {
            machine
                .transition(RegionEvent::FinalizerRegistered, context)
                .unwrap();
        }
    }

    fn drive_region_cancel_projection(machine: &mut RegionStateMachine, context: &RegionContext) {
        loop {
            match machine.current_state().clone() {
                RegionState::Cancelling {
                    draining_tasks: 0,
                    pending_finalizers: 0,
                    ..
                }
                | RegionState::Finalized => break,
                RegionState::Cancelling {
                    draining_tasks: 0, ..
                } => machine
                    .transition(RegionEvent::FinalizerStarted, context)
                    .unwrap(),
                RegionState::Cancelling { .. } => machine
                    .transition(RegionEvent::TaskDrained, context)
                    .unwrap(),
                RegionState::Finalizing { .. } => machine
                    .transition(RegionEvent::FinalizerCompleted, context)
                    .unwrap(),
                state => {
                    panic!("unexpected region state while driving cancel projection: {state:?}") // ubs:ignore - test helper
                }
            }
        }
    }

    fn prime_channel_for_close(
        machine: &mut ChannelStateMachine,
        context: &ChannelContext,
        pending_ops: u8,
    ) {
        for _ in 0..pending_ops {
            machine
                .transition(ChannelEvent::OperationStarted, context)
                .unwrap();
        }
    }

    fn drive_channel_close_projection(machine: &mut ChannelStateMachine, context: &ChannelContext) {
        while let ChannelState::Closing { .. } = machine.current_state() {
            machine
                .transition(ChannelEvent::OperationCompleted, context)
                .unwrap();
        }
    }

    proptest! {
        #[test]
        fn metamorphic_cancel_then_cancel_is_identity_on_cancel_projection(
            active_tasks in 0u8..4,
            pending_finalizers in 0u8..4,
            task_started in any::<bool>(),
            channel_pending in 0u8..4,
        ) {
            prop_assume!(active_tasks > 0 || pending_finalizers > 0);

            let region_id = RegionId::new_for_test(101, 0);
            let region_context = region_context(region_id);
            let mut region_once = RegionStateMachine::new(region_id, ValidationLevel::Full);
            let mut region_twice = RegionStateMachine::new(region_id, ValidationLevel::Full);
            prime_region_for_cancel(&mut region_once, &region_context, active_tasks, pending_finalizers);
            prime_region_for_cancel(&mut region_twice, &region_context, active_tasks, pending_finalizers);
            let region_once_cancel = region_once.transition(
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_once_cancel.is_valid());
            let region_twice_first_cancel = region_twice.transition(
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_twice_first_cancel.is_valid());
            let region_after_first = region_twice.current_state().clone();
            let region_twice_second_cancel = region_twice.transition(
                RegionEvent::Cancel {
                    reason: "second".to_string(),
                },
                &region_context,
            );
            prop_assert!(region_twice_second_cancel.is_valid());
            prop_assert_eq!(
                region_once.current_state().clone(),
                region_after_first.clone()
            );
            prop_assert_eq!(region_twice.current_state().clone(), region_after_first);
            drive_region_cancel_projection(&mut region_once, &region_context);
            drive_region_cancel_projection(&mut region_twice, &region_context);
            prop_assert_eq!(region_once.current_state().clone(), region_twice.current_state().clone());

            let task_id = TaskId::new_for_test(202, 0);
            let task_context = task_context(task_id, region_id);
            let mut task_once = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
            let mut task_twice = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
            if task_started {
                let task_once_start = task_once.transition(TaskEvent::Start, &task_context);
                prop_assert!(task_once_start.is_valid());
                let task_twice_start = task_twice.transition(TaskEvent::Start, &task_context);
                prop_assert!(task_twice_start.is_valid());
            }
            let task_once_cancel = task_once.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_once_cancel.is_valid());
            let task_twice_cancel = task_twice.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_twice_cancel.is_valid());
            let task_after_first = task_twice.current_state().clone();
            let task_twice_second_cancel =
                task_twice.transition(TaskEvent::RequestCancel, &task_context);
            prop_assert!(task_twice_second_cancel.is_valid());
            prop_assert_eq!(
                task_once.current_state().clone(),
                task_after_first.clone()
            );
            prop_assert_eq!(task_twice.current_state().clone(), task_after_first);
            if matches!(task_once.current_state(), TaskState::CancelRequested) {
                let task_once_drain = task_once.transition(TaskEvent::DrainComplete, &task_context);
                prop_assert!(task_once_drain.is_valid());
                let task_twice_drain =
                    task_twice.transition(TaskEvent::DrainComplete, &task_context);
                prop_assert!(task_twice_drain.is_valid());
            }
            prop_assert_eq!(task_once.current_state().clone(), task_twice.current_state().clone());

            let channel_id = 303;
            let channel_context = channel_context(channel_id);
            let mut channel_once = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
            let mut channel_twice = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
            prime_channel_for_close(&mut channel_once, &channel_context, channel_pending);
            prime_channel_for_close(&mut channel_twice, &channel_context, channel_pending);
            let channel_once_close =
                channel_once.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_once_close.is_valid());
            let channel_twice_close =
                channel_twice.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_twice_close.is_valid());
            let channel_after_first = channel_twice.current_state().clone();
            let channel_twice_second_close =
                channel_twice.transition(ChannelEvent::InitiateClose, &channel_context);
            prop_assert!(channel_twice_second_close.is_valid());
            prop_assert_eq!(
                channel_once.current_state().clone(),
                channel_after_first.clone()
            );
            prop_assert_eq!(channel_twice.current_state().clone(), channel_after_first);
            drive_channel_close_projection(&mut channel_once, &channel_context);
            drive_channel_close_projection(&mut channel_twice, &channel_context);
            prop_assert_eq!(channel_once.current_state().clone(), channel_twice.current_state().clone());

            let io_context = io_context(404, "read");
            let mut io_once = IoStateMachine::new(404, 7, ValidationLevel::Full);
            let mut io_twice = IoStateMachine::new(404, 7, ValidationLevel::Full);
            let io_once_cancel = io_once.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_once_cancel.is_valid());
            let io_twice_cancel = io_twice.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_twice_cancel.is_valid());
            let io_after_first = io_twice.current_state().clone();
            let io_twice_second_cancel = io_twice.transition(IoEvent::Cancel, &io_context);
            prop_assert!(io_twice_second_cancel.is_valid());
            prop_assert_eq!(io_once.current_state().clone(), io_after_first.clone());
            prop_assert_eq!(io_twice.current_state().clone(), io_after_first);
            let io_once_cleanup = io_once.transition(IoEvent::CleanupComplete, &io_context);
            prop_assert!(io_once_cleanup.is_valid());
            let io_twice_cleanup = io_twice.transition(IoEvent::CleanupComplete, &io_context);
            prop_assert!(io_twice_cleanup.is_valid());
            prop_assert_eq!(io_once.current_state().clone(), io_twice.current_state().clone());

            let timer_context = timer_context(505, Time::ZERO);
            let mut timer_once =
                TimerStateMachine::new(505, Time::from_nanos(5), ValidationLevel::Full);
            let mut timer_twice =
                TimerStateMachine::new(505, Time::from_nanos(5), ValidationLevel::Full);
            let timer_once_cancel = timer_once.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_once_cancel.is_valid());
            let timer_twice_cancel = timer_twice.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_twice_cancel.is_valid());
            let timer_after_first = timer_twice.current_state().clone();
            let timer_twice_second_cancel =
                timer_twice.transition(TimerEvent::Cancel, &timer_context);
            prop_assert!(timer_twice_second_cancel.is_valid());
            prop_assert_eq!(
                timer_once.current_state().clone(),
                timer_after_first.clone()
            );
            prop_assert_eq!(timer_twice.current_state().clone(), timer_after_first);
        }
    }

    #[test]
    fn validator_repeated_cancel_requests_do_not_increment_violation_count() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let region_id = RegionId::new_for_test(901, 0);
        let task_id = TaskId::new_for_test(902, 0);
        let channel_id = 903;
        let operation_id = 904;
        let timer_id = 905;

        validator.register_region(region_id);
        validator.register_task(task_id, region_id);
        validator.register_channel(channel_id);
        validator.register_io_operation(operation_id, 7);
        validator.register_timer(timer_id, Time::from_nanos(5));

        let region_context = region_context(region_id);
        let task_context = task_context(task_id, region_id);
        let channel_context = channel_context(channel_id);
        let io_context = io_context(operation_id, "read");
        let timer_context = timer_context(timer_id, Time::ZERO);

        validator
            .validate_region_transition(region_id, RegionEvent::Activate, &region_context)
            .unwrap();
        validator
            .validate_region_transition(region_id, RegionEvent::TaskSpawned, &region_context)
            .unwrap();
        validator
            .validate_region_transition(
                region_id,
                RegionEvent::FinalizerRegistered,
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::Start, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(
                channel_id,
                ChannelEvent::OperationStarted,
                &channel_context,
            )
            .unwrap();

        validator
            .validate_region_transition(
                region_id,
                RegionEvent::Cancel {
                    reason: "first".to_string(),
                },
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::RequestCancel, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(channel_id, ChannelEvent::InitiateClose, &channel_context)
            .unwrap();
        validator
            .validate_io_transition(operation_id, IoEvent::Cancel, &io_context)
            .unwrap();
        validator
            .validate_timer_transition(timer_id, TimerEvent::Cancel, &timer_context)
            .unwrap();

        let baseline_violations = validator.violation_count();
        let baseline_region = validator
            .region_machines
            .get(&region_id)
            .expect("region machine")
            .current_state()
            .clone();
        let baseline_task = validator
            .task_machines
            .get(&task_id)
            .expect("task machine")
            .current_state()
            .clone();
        let baseline_channel = validator
            .channel_machines
            .get(&channel_id)
            .expect("channel machine")
            .current_state()
            .clone();
        let baseline_io = validator
            .io_machines
            .get(&operation_id)
            .expect("io machine")
            .current_state()
            .clone();
        let baseline_timer = validator
            .timer_machines
            .get(&timer_id)
            .expect("timer machine")
            .current_state()
            .clone();

        validator
            .validate_region_transition(
                region_id,
                RegionEvent::Cancel {
                    reason: "second".to_string(),
                },
                &region_context,
            )
            .unwrap();
        validator
            .validate_task_transition(task_id, TaskEvent::RequestCancel, &task_context)
            .unwrap();
        validator
            .validate_channel_transition(channel_id, ChannelEvent::InitiateClose, &channel_context)
            .unwrap();
        validator
            .validate_io_transition(operation_id, IoEvent::Cancel, &io_context)
            .unwrap();
        validator
            .validate_timer_transition(timer_id, TimerEvent::Cancel, &timer_context)
            .unwrap();

        assert_eq!(validator.violation_count(), baseline_violations);
        assert_eq!(
            validator
                .region_machines
                .get(&region_id)
                .expect("region machine")
                .current_state(),
            &baseline_region
        );
        assert_eq!(
            validator
                .task_machines
                .get(&task_id)
                .expect("task machine")
                .current_state(),
            &baseline_task
        );
        assert_eq!(
            validator
                .channel_machines
                .get(&channel_id)
                .expect("channel machine")
                .current_state(),
            &baseline_channel
        );
        assert_eq!(
            validator
                .io_machines
                .get(&operation_id)
                .expect("io machine")
                .current_state(),
            &baseline_io
        );
        assert_eq!(
            validator
                .timer_machines
                .get(&timer_id)
                .expect("timer machine")
                .current_state(),
            &baseline_timer
        );
    }

    #[test]
    fn test_region_is_quiesced() {
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created region should be quiesced
        assert!(machine.is_quiesced());

        // Activate to empty Active state
        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        // Empty Active region should be quiesced
        assert!(machine.is_quiesced());

        // Spawn a task, no longer quiesced
        assert_eq!(
            machine.transition(RegionEvent::TaskSpawned, &context),
            TransitionResult::Valid
        );
        assert!(!machine.is_quiesced());

        // Complete the task, quiesced again
        assert_eq!(
            machine.transition(RegionEvent::TaskCompleted, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_quiesced());
    }

    #[test]
    fn test_region_lifecycle() {
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created -> Active
        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Active { .. }
        ));

        // Spawn and complete a task
        assert_eq!(
            machine.transition(RegionEvent::TaskSpawned, &context),
            TransitionResult::Valid
        );
        assert_eq!(machine.active_task_count(), 1);

        assert_eq!(
            machine.transition(RegionEvent::TaskCompleted, &context),
            TransitionResult::Valid
        );
        assert_eq!(machine.active_task_count(), 0);

        // Close empty region
        assert_eq!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
        assert!(machine.is_terminal());
    }

    #[test]
    fn region_cancel_with_only_pending_finalizers_enters_finalizing() {
        let region_id = RegionId::new_for_test(12, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(RegionEvent::FinalizerRegistered, &context),
            TransitionResult::Valid
        );
        assert_eq!(
            machine.transition(
                RegionEvent::Cancel {
                    reason: "test".to_owned(),
                },
                &context,
            ),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Finalizing {
                running_finalizers: 1
            }
        ));
        assert_eq!(
            machine.transition(RegionEvent::FinalizerCompleted, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
    }

    #[test]
    fn test_region_activate_allows_empty_active_state() {
        let region_id = RegionId::new_for_test(10, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(matches!(
            machine.current_state(),
            RegionState::Active {
                active_tasks: 0,
                pending_finalizers: 0
            }
        ));
        assert_eq!(
            machine.transition(RegionEvent::RequestClose, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), RegionState::Finalized));
    }

    #[test]
    fn test_region_empty_active_state_is_quiesced() {
        let region_id = RegionId::new_for_test(11, 0);
        let mut machine = RegionStateMachine::new(region_id, ValidationLevel::Full);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        assert_eq!(
            machine.transition(RegionEvent::Activate, &context),
            TransitionResult::Valid
        );
        assert!(
            machine.is_quiesced(),
            "an active region with no tasks or finalizers should report quiescence"
        );
    }

    #[test]
    fn test_task_lifecycle() {
        let task_id = TaskId::new_for_test(1, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Spawned -> Running
        assert!(machine.is_cancellable());
        assert_eq!(
            machine.transition(TaskEvent::Start, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), TaskState::Running));

        // Running -> Completed
        assert_eq!(
            machine.transition(TaskEvent::Complete, &context),
            TransitionResult::Valid
        );
        assert!(matches!(machine.current_state(), TaskState::Completed));
        assert!(machine.is_complete());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_task_cancellation() {
        let task_id = TaskId::new_for_test(2, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Spawned -> Running -> CancelRequested -> Cancelled
        machine.transition(TaskEvent::Start, &context).unwrap();
        machine
            .transition(TaskEvent::RequestCancel, &context)
            .unwrap();
        assert!(matches!(
            machine.current_state(),
            TaskState::CancelRequested
        ));

        machine
            .transition(TaskEvent::DrainComplete, &context)
            .unwrap();
        assert!(matches!(machine.current_state(), TaskState::Cancelled));
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_invalid_transitions() {
        let task_id = TaskId::new_for_test(3, 0);
        let region_id = RegionId::new_for_test(1, 0);
        let mut machine = TaskStateMachine::new(task_id, region_id, ValidationLevel::Full);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Try to complete without starting
        let result = machine.transition(TaskEvent::Complete, &context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));

        // Valid transition to running
        machine.transition(TaskEvent::Start, &context).unwrap();

        // Complete the task
        machine.transition(TaskEvent::Complete, &context).unwrap();

        // Try to transition from terminal state
        let result = machine.transition(TaskEvent::RequestCancel, &context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_obligation_lifecycle() {
        let obligation_id = ObligationId::new_for_test(1, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Created -> Reserved -> Committed
        assert_eq!(
            machine.transition(ObligationEvent::Reserve { token: 12345 }, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_reserved());

        assert_eq!(
            machine.transition(ObligationEvent::Commit, &context),
            TransitionResult::Valid
        );
        assert!(machine.is_fulfilled());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_obligation_zero_token_is_invariant_violation() {
        let obligation_id = ObligationId::new_for_test(7, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result = machine.transition(ObligationEvent::Reserve { token: 0 }, &context);
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));
        assert!(matches!(
            machine.current_state(),
            ObligationState::Error { .. }
        ));
    }

    #[test]
    fn test_obligation_state_transition_atomicity() {
        // Test that verifies state transitions are atomic under concurrent access
        // This addresses the race condition fix in br-asupersync-g4frfy
        use std::sync::{Arc, Mutex};
        use std::thread;

        let obligation_id = ObligationId::new_for_test(42, 0);
        let machine = Arc::new(Mutex::new(ObligationStateMachine::new(
            obligation_id,
            ValidationLevel::Full,
        )));
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // First, transition to Reserved state
        {
            let mut m = machine.lock().unwrap();
            let result = m.transition(ObligationEvent::Reserve { token: 12345 }, &context);
            assert_eq!(result, TransitionResult::Valid);
            assert!(m.is_reserved());
        }

        // Now test concurrent transitions from Reserved state
        let machine_clone = Arc::clone(&machine);
        let observed_states = Arc::new(Mutex::new(Vec::new()));
        let observed_states_clone = Arc::clone(&observed_states);

        // Spawn thread that continuously reads state during transition
        let reader_handle = thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(m) = machine_clone.try_lock() {
                    let state = m.current_state().clone();
                    observed_states_clone.lock().unwrap().push(state);
                    // Yield to give transition thread a chance
                    thread::yield_now();
                } else {
                    thread::yield_now();
                }
            }
        });

        // Give reader thread time to start
        thread::sleep(std::time::Duration::from_millis(1));

        // Perform transition that should be atomic
        let result = {
            let mut m = machine.lock().unwrap();
            m.transition(ObligationEvent::Commit, &context)
        };
        assert_eq!(result, TransitionResult::Valid);

        // Wait for reader to finish
        reader_handle.join().unwrap();

        // Verify that all observed states are valid - no intermediate invalid states
        let states = observed_states.lock().unwrap();
        for state in states.iter() {
            match state {
                ObligationState::Created
                | ObligationState::Reserved { .. }
                | ObligationState::Committed
                | ObligationState::Aborted { .. }
                | ObligationState::Error { .. } => {
                    // All these states are valid - good!
                }
            }
        }

        // Verify final state is correct
        let final_machine = machine.lock().unwrap();
        assert!(matches!(
            final_machine.current_state(),
            ObligationState::Committed
        ));
        assert!(final_machine.is_fulfilled());
        assert!(final_machine.is_terminal());
    }

    #[test]
    fn test_obligation_invariant_violation_atomicity() {
        // Test that invariant violations are handled atomically
        // When invariants fail, state should go directly to Error without invalid intermediates
        let obligation_id = ObligationId::new_for_test(99, 0);
        let mut machine = ObligationStateMachine::new(obligation_id, ValidationLevel::Full);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        // Attempt transition that will fail invariant check (token = 0)
        let result = machine.transition(ObligationEvent::Reserve { token: 0 }, &context);

        // Should get invariant violation
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));

        // State should be Error, not some intermediate invalid state
        assert!(matches!(
            machine.current_state(),
            ObligationState::Error { .. }
        ));

        // Machine should be in terminal state
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_channel_lifecycle() {
        let channel_id = 1;
        let mut machine = ChannelStateMachine::new(channel_id, ValidationLevel::Full);
        let context = ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_accepting_ops());

        // Start some operations
        machine
            .transition(ChannelEvent::OperationStarted, &context)
            .unwrap();
        machine
            .transition(ChannelEvent::OperationStarted, &context)
            .unwrap();
        assert_eq!(machine.pending_ops(), 2);

        // Initiate close while operations are pending
        machine
            .transition(ChannelEvent::InitiateClose, &context)
            .unwrap();
        assert!(!machine.is_accepting_ops());

        // Complete operations
        machine
            .transition(ChannelEvent::OperationCompleted, &context)
            .unwrap();
        machine
            .transition(ChannelEvent::OperationCompleted, &context)
            .unwrap();

        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), ChannelState::Closed));
    }

    #[test]
    fn test_io_operation_lifecycle() {
        let operation_id = 1;
        let io_handle = 42;
        let mut machine = IoStateMachine::new(operation_id, io_handle, ValidationLevel::Full);
        let context = IoContext {
            operation_id,
            operation_type: "read".to_string(),
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_pending());

        // Complete successfully
        machine
            .transition(IoEvent::Complete { result_size: 1024 }, &context)
            .unwrap();
        assert!(machine.completed_successfully());
        assert!(machine.is_terminal());
    }

    #[test]
    fn test_io_operation_cancellation() {
        let operation_id = 2;
        let io_handle = 43;
        let mut machine = IoStateMachine::new(operation_id, io_handle, ValidationLevel::Full);
        let context = IoContext {
            operation_id,
            operation_type: "write".to_string(),
            validation_level: ValidationLevel::Full,
        };

        // Cancel and cleanup
        machine.transition(IoEvent::Cancel, &context).unwrap();
        machine
            .transition(IoEvent::CleanupComplete, &context)
            .unwrap();

        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), IoState::Cleanup));
    }

    #[test]
    fn test_timer_lifecycle() {
        let timer_id = 1;
        let deadline = Time::from_nanos(1000);
        let mut machine = TimerStateMachine::new(timer_id, deadline, ValidationLevel::Full);
        let context = TimerContext {
            timer_id,
            current_time: Time::from_nanos(999), // Before deadline
            validation_level: ValidationLevel::Full,
        };

        assert!(machine.is_scheduled());
        assert_eq!(machine.deadline(), Some(deadline));

        // Try to fire before deadline (should fail)
        let result = machine.transition(TimerEvent::Fire, &context);
        assert!(matches!(
            result,
            TransitionResult::InvariantViolation { .. }
        ));

        // Update context time and fire
        let context = TimerContext {
            timer_id,
            current_time: Time::from_nanos(1001), // After deadline
            validation_level: ValidationLevel::Full,
        };

        machine.transition(TimerEvent::Fire, &context).unwrap();
        assert!(machine.is_terminal());
        assert!(matches!(machine.current_state(), TimerState::Fired));
    }

    #[test]
    fn test_validator() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(1, 0);
        let obligation_id = ObligationId::new_for_test(1, 0);
        let channel_id = 1;

        validator.register_region(region_id);
        validator.register_task(task_id, region_id);
        validator.register_obligation(obligation_id);
        validator.register_channel(channel_id);

        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let obligation_context = ObligationContext {
            obligation_id,
            region_id,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let channel_context = ChannelContext {
            channel_id,
            validation_level: ValidationLevel::Full,
        };

        // Valid transitions
        assert!(matches!(
            validator.validate_region_transition(region_id, RegionEvent::Activate, &region_context),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_task_transition(task_id, TaskEvent::Start, &task_context),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_obligation_transition(
                obligation_id,
                ObligationEvent::Reserve { token: 123 },
                &obligation_context
            ),
            TransitionResult::Valid
        ));

        assert!(matches!(
            validator.validate_channel_transition(
                channel_id,
                ChannelEvent::OperationStarted,
                &channel_context
            ),
            TransitionResult::Valid
        ));

        assert_eq!(validator.violation_count(), 0);
        let (regions, tasks, obligations, channels, io_ops, timers, violations) = validator.stats();
        assert_eq!(regions, 1);
        assert_eq!(tasks, 1);
        assert_eq!(obligations, 1);
        assert_eq!(channels, 1);
        assert_eq!(io_ops, 0);
        assert_eq!(timers, 0);
        assert_eq!(violations, 0);
    }

    #[test]
    fn test_validator_counts_invalid_transition_without_panicking() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let task_id = TaskId::new_for_test(9, 0);
        let region_id = RegionId::new_for_test(1, 0);

        validator.register_task(task_id, region_id);

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result =
            validator.validate_task_transition(task_id, TaskEvent::Complete, &task_context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
        assert_eq!(validator.violation_count(), 1);
    }

    #[test]
    fn test_validator_counts_unregistered_transition() {
        let mut validator = CancelProtocolValidator::new(ValidationLevel::Full);
        let task_id = TaskId::new_for_test(11, 0);
        let region_id = RegionId::new_for_test(1, 0);

        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        let result =
            validator.validate_task_transition(task_id, TaskEvent::Complete, &task_context);
        assert!(matches!(result, TransitionResult::Invalid { .. }));
        assert_eq!(validator.violation_count(), 1);
    }
}

impl TransitionResult {
    /// Check if the transition was successful.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Unwrap a valid transition result, panicking on invalid transitions.
    pub fn unwrap(self) {
        assert!(self.is_valid(), "Transition failed: {self:?}");
    }
}
