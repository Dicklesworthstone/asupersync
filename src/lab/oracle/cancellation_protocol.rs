//! Cancellation protocol oracle for verifying the cancellation invariant.
//!
//! This oracle verifies invariant #3: Cancellation is a protocol.
//! Tasks must transition through request → drain → finalize in a bounded way.
//!
//! Additionally, this oracle verifies **INV-CANCEL-PROPAGATES**:
//! When a region is cancelled, all its descendant regions also have cancel set.
//!
//! # The Protocol
//!
//! Valid cancellation transitions for a task:
//! ```text
//! Created/Running → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
//! ```
//!
//! Key properties:
//! - Cancellation is idempotent (repeated requests strengthen but don't break protocol)
//! - Mask deferral is bounded (eventually checkpoint must acknowledge)
//! - Cleanup budgets are respected
//! - Cancel propagates downward through the region tree
//!
//! # Runtime Integration
//!
//! `LabRuntime` feeds this oracle's hooks during a run. Used standalone, the
//! caller drives the same hooks for real-time cancellation protocol
//! verification:
//!
//! ```rust,no_run
//! use asupersync::lab::oracle::cancellation_protocol::{
//!     CancelCorrectnessConfig, CancellationProtocolOracle, EnforcementMode,
//! };
//! use asupersync::record::task::TaskState;
//! use asupersync::types::{Budget, CancelReason, RegionId, TaskId, Time};
//!
//! // Configure for runtime use
//! let config = CancelCorrectnessConfig {
//!     enforcement: EnforcementMode::Warn, // or Panic / Collect
//!     capture_stacks: true,
//!     max_violations_tracked: 100,
//!     structured_logging: true,
//! };
//! let mut oracle = CancellationProtocolOracle::with_config(config);
//!
//! // Under `LabRuntime`, the runtime feeds the cancel-request, transition and
//! // poll hooks itself; standalone use drives the hooks by hand:
//! let region = RegionId::testing_default();
//! let task = TaskId::testing_default();
//! let reason = CancelReason::user("shutdown");
//! oracle.on_region_create(region, None);
//! oracle.on_task_create(task, region);
//! oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(10));
//! oracle.on_transition(
//!     task,
//!     &TaskState::Running,
//!     &TaskState::CancelRequested {
//!         reason: reason.clone(),
//!         cleanup_budget: Budget::INFINITE,
//!     },
//!     Time::from_nanos(11),
//! );
//! oracle.on_region_cancel(region, reason, Time::from_nanos(12));
//!
//! // Check for violations
//! if let Err(violation) = oracle.check() {
//!     match oracle.config().enforcement {
//!         EnforcementMode::Warn | EnforcementMode::Collect => {
//!             eprintln!("Cancel protocol violation: {}", violation);
//!         }
//!         EnforcementMode::Panic => panic!("Cancel protocol violation: {}", violation),
//!     }
//! }
//! ```
//!
//! # Feature Gating
//!
//! The oracle's hooks and checks are compiled and run whether or not the
//! `cancel-correctness-oracle` feature is enabled. The feature gates only the
//! structured error log a violation emits
//! ([`emit_structured_log`](ViolationRecord::emit_structured_log)).

use crate::record::task::TaskState;
use crate::runtime::RuntimeState;
use crate::types::{
    CancelKind, CancelPhase, CancelReason, CancelWitness, CancelWitnessError, RegionId, TaskId,
    Time,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Configuration for cancel-correctness oracle runtime behavior.
#[derive(Debug, Clone)]
pub struct CancelCorrectnessConfig {
    /// Enforcement mode for violations.
    pub enforcement: EnforcementMode,
    /// Whether to capture stack traces for violations.
    pub capture_stacks: bool,
    /// Maximum number of violations to track (prevents unbounded memory growth).
    pub max_violations_tracked: usize,
    /// Whether to emit structured logs for all violations.
    pub structured_logging: bool,
}

impl Default for CancelCorrectnessConfig {
    fn default() -> Self {
        Self {
            enforcement: EnforcementMode::Warn,
            capture_stacks: cfg!(debug_assertions),
            max_violations_tracked: 100,
            structured_logging: true,
        }
    }
}

/// Enforcement mode for protocol violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Log violations but continue execution.
    Warn,
    /// Panic immediately on first violation.
    Panic,
    /// Collect violations but take no action (metrics only).
    Collect,
}

/// A violation record with enhanced diagnostics and tracing.
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    /// The violation itself.
    pub violation: CancellationProtocolViolation,
    /// Unique trace ID for correlation with logs.
    pub trace_id: u64,
    /// Stack trace at violation point (if capture_stacks enabled).
    pub stack_trace: Option<String>,
    /// Timestamp when violation was detected.
    pub detected_at: Time,
    /// Replay command for reproducing the violation.
    pub replay_command: Option<String>,
}

/// br-asupersync-2ybwmx — Deterministic wall-clock proxy for the
/// violation `detected_at` field. Mirrors the established pattern
/// in lab/oracle/region_leak.rs::violation_now (br-asupersync-hq5gou):
/// in production stamps real `SystemTime::now()` rendered as
/// nanos-since-epoch; under `cfg(any(test, feature =
/// "deterministic-mode"))` returns `Time::ZERO` so test runs and
/// lab replays produce byte-stable violation records.
///
/// cancellation_protocol was the one oracle in src/lab/oracle/
/// that had not been migrated to this pattern after the 2026-04-26
/// determinism audit batch (region_leak / waker_dedup /
/// channel_atomicity all use the wrapper). This addresses the
/// consistency gap: identical scenarios that fire a cancellation-
/// protocol violation now produce byte-equal ViolationRecord
/// stamps across replays, satisfying the lab golden-artifact
/// run-twice-and-compare gate that
/// tests/lab_runtime_seed_golden.rs::build_scenario depends on.
///
/// Note: this helper covers the violation-record `detected_at`
/// field that flows out to crashpacks and trace certificates. The
/// internal threshold-detection clock is a separate concern (matches
/// region_leak's documented limitation).
#[inline]
fn violation_now() -> Time {
    #[cfg(any(test, feature = "deterministic-mode"))]
    {
        Time::ZERO
    }
    #[cfg(not(any(test, feature = "deterministic-mode")))]
    {
        Time::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        )
    }
}

impl ViolationRecord {
    /// Creates a new violation record with enhanced diagnostics.
    fn new(violation: CancellationProtocolViolation, config: &CancelCorrectnessConfig) -> Self {
        static TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        let trace_id = TRACE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

        let stack_trace = if config.capture_stacks {
            Some(capture_stack_trace())
        } else {
            None
        };

        let replay_command = Some(format!(
            "asupersync test --oracle cancel-correctness --trace-id {trace_id}"
        ));

        Self {
            violation,
            trace_id,
            stack_trace,
            // br-asupersync-2ybwmx: route through the cfg-gated
            // violation_now() helper so test/deterministic-mode
            // builds produce byte-stable detected_at stamps.
            detected_at: violation_now(),
            replay_command,
        }
    }

    /// Emits structured log for this violation.
    #[allow(unused_variables)]
    pub fn emit_structured_log(&self) {
        if cfg!(feature = "cancel-correctness-oracle") {
            crate::tracing_compat::error!(
                violation_type = "cancel_protocol_violation",
                trace_id = self.trace_id,
                violation_kind = ?std::mem::discriminant(&self.violation),
                timestamp_nanos = self.detected_at.as_nanos(),
                replay_command = ?self.replay_command,
                stack_trace = ?self.stack_trace,
                violation = %self.violation,
                "cancel protocol violation"
            );
        }
    }
}

/// Captures a stack trace for the violation diagnostic.
///
/// br-asupersync-z00sw8 — Delegates to
/// [`crate::lab::util::stack_trace::capture_stack_trace_default`], which
/// uses the `backtrace` crate (gated on the `lab-stack-traces` feature)
/// to produce a real multi-frame trace. The previous implementation
/// returned `format!("Stack trace capture at {Location::caller()}")` in
/// debug and a constant string in release — neither carried any forensic
/// value when an oracle violation fired.
fn capture_stack_trace() -> String {
    crate::lab::util::stack_trace::capture_stack_trace_default()
}

/// Statistics about violations detected by the oracle.
#[derive(Debug, Clone)]
pub struct ViolationStats {
    /// Total number of violations detected.
    pub total_violations: usize,
    /// Count of violations by type.
    pub by_type: std::collections::HashMap<String, usize>,
    /// Current enforcement mode.
    pub enforcement_mode: EnforcementMode,
}

/// Maximum number of observed polls a task may remain in `CancelRequested`
/// before the oracle reports a missing acknowledgement.
///
/// `CHECKPOINT-MASKED` can consume at most one unit of mask depth per cancel
/// checkpoint, after which the next checkpoint must acknowledge cancellation.
/// If the oracle observes more polls than this bound while the task remains in
/// `CancelRequested`, cancellation is no longer making bounded progress.
const CANCEL_ACK_POLL_BOUND: u32 = crate::types::MAX_MASK_DEPTH + 1;

/// A violation of the cancellation protocol invariant.
#[derive(Debug, Clone)]
pub enum CancellationProtocolViolation {
    /// Task skipped a required state in the cancellation sequence.
    SkippedState {
        /// The task that skipped a state.
        task: TaskId,
        /// The state the task was in.
        from: TaskStateKind,
        /// The state the task transitioned to (illegally).
        to: TaskStateKind,
        /// When this occurred.
        time: Time,
    },

    /// Task was cancelled but not acknowledged within expected bounds.
    CancelNotAcknowledged {
        /// The task that was not acknowledged.
        task: TaskId,
        /// When the cancel was requested.
        requested_at: Time,
        /// Number of polls that have occurred since request.
        polls_since_request: u32,
    },

    /// Task was cancelled but never completed.
    CancelNotCompleted {
        /// The task that didn't complete.
        task: TaskId,
        /// The state the task is stuck in.
        stuck_state: TaskStateKind,
        /// When the cancel was requested.
        requested_at: Time,
    },

    /// Cancel propagation violated: parent cancelled but child was not.
    CancelNotPropagated {
        /// The parent region that was cancelled.
        parent: RegionId,
        /// The child region that was NOT cancelled.
        uncancelled_child: RegionId,
    },

    /// Non-monotonic cancel reason (reason got weaker instead of stronger).
    NonMonotonicCancel {
        /// The task with non-monotonic cancel.
        task: TaskId,
        /// The cancel kind before.
        before: CancelKind,
        /// The cancel kind after (should be >= before).
        after: CancelKind,
    },

    /// Cancel was acknowledged while the task was in a masked section.
    ///
    /// The cancellation protocol requires that cancel acknowledgement is
    /// deferred while `mask_depth > 0`. A task transitioning to `Cancelling`
    /// while masked violates **INV-MASK-DEFER**.
    CancelAckWhileMasked {
        /// The task that acknowledged cancel while masked.
        task: TaskId,
        /// The mask depth at the time of acknowledgement.
        mask_depth: u32,
        /// When this occurred.
        time: Time,
    },

    /// Mask depth exceeded the compile-time bound (`MAX_MASK_DEPTH`).
    ///
    /// Violates **INV-MASK-BOUNDED**: a task's mask depth must be finite
    /// and bounded to guarantee that cancellation cannot be deferred
    /// indefinitely.
    MaskDepthExceeded {
        /// The task that exceeded the mask depth bound.
        task: TaskId,
        /// The actual mask depth reached.
        depth: u32,
        /// The maximum allowed depth.
        max: u32,
        /// When this occurred.
        time: Time,
    },

    /// `on_mask_exit` was observed while the task's mask depth was already
    /// zero — i.e., more exits than enters. Violates the mask-section
    /// well-formedness invariant: mask sections must nest, so the count of
    /// observed exits cannot exceed the count of observed enters at any
    /// point in time. Previously this was silently absorbed by a
    /// `saturating_sub`, hiding a real protocol bug (br-asupersync-kzhbt8).
    UnmatchedMaskExit {
        /// The task whose `on_mask_exit` arrived without a matching enter.
        task: TaskId,
        /// When the unmatched exit was observed.
        time: Time,
    },

    /// br-asupersync-9fjaqe / -f1zjwu — Initial witness for a task
    /// failed [`CancelWitness::validate_initial`] (e.g., used the
    /// reserved epoch 0 sentinel). Surfaced when the protocol oracle
    /// is wired to a witness stream via `on_cancel_witness`; the
    /// matching variant in the cancel-correctness oracle is
    /// `InvalidInitialWitness`. Both oracles route through the same
    /// shared validator so they cannot disagree.
    InvalidInitialWitnessEpoch {
        /// The task whose initial witness was rejected.
        task: TaskId,
        /// The (invalid) epoch carried by the initial witness.
        epoch: u64,
        /// The witness phase observed.
        phase: CancelPhase,
        /// When the witness was observed.
        time: Time,
    },

    /// br-asupersync-9fjaqe / -f1zjwu — A subsequent witness in a
    /// per-task stream failed [`CancelWitness::validate_transition`]
    /// (epoch mismatch, phase regression, reason weakened, or
    /// task/region mismatch). Routed through the same shared
    /// validator the cancel-correctness oracle uses, so the two
    /// oracles agree on transition validity.
    InvalidWitnessTransition {
        /// The task whose witness transition was rejected.
        task: TaskId,
        /// The specific transition error reported by the validator.
        error: CancelWitnessError,
        /// When the offending witness was observed.
        time: Time,
    },
}

impl fmt::Display for CancellationProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SkippedState {
                task,
                from,
                to,
                time,
            } => {
                write!(
                    f,
                    "Task {task} skipped state: {from:?} -> {to:?} at {time} \
                     (expected intermediate states)"
                )
            }
            Self::CancelNotAcknowledged {
                task,
                requested_at,
                polls_since_request,
            } => {
                write!(
                    f,
                    "Task {task} cancel requested at {requested_at} but not acknowledged \
                     after {polls_since_request} polls"
                )
            }
            Self::CancelNotCompleted {
                task,
                stuck_state,
                requested_at,
            } => {
                write!(
                    f,
                    "Task {task} cancel requested at {requested_at} but stuck in {stuck_state:?}"
                )
            }
            Self::CancelNotPropagated {
                parent,
                uncancelled_child,
            } => {
                write!(
                    f,
                    "Cancel not propagated: parent {parent} cancelled but child \
                     {uncancelled_child} not cancelled"
                )
            }
            Self::NonMonotonicCancel {
                task,
                before,
                after,
            } => {
                write!(
                    f,
                    "Task {task} cancel reason got weaker: {before:?} -> {after:?}"
                )
            }
            Self::CancelAckWhileMasked {
                task,
                mask_depth,
                time,
            } => {
                write!(
                    f,
                    "Task {task} acknowledged cancel while masked (depth={mask_depth}) at {time}"
                )
            }
            Self::MaskDepthExceeded {
                task,
                depth,
                max,
                time,
            } => {
                write!(
                    f,
                    "Task {task} mask depth {depth} exceeded maximum {max} at {time}"
                )
            }
            Self::UnmatchedMaskExit { task, time } => {
                write!(
                    f,
                    "Task {task} observed mask_exit while mask_depth=0 at {time} \
                     (more mask_exit calls than mask_enter — protocol violation)"
                )
            }
            Self::InvalidInitialWitnessEpoch {
                task,
                epoch,
                phase,
                time,
            } => {
                write!(
                    f,
                    "Task {task} initial witness invalid: epoch {epoch} phase {phase:?} \
                     at {time} (epoch 0 is the no-cancel sentinel and may not appear in a witness)"
                )
            }
            Self::InvalidWitnessTransition { task, error, time } => {
                write!(
                    f,
                    "Task {task} witness transition rejected at {time}: {error:?}"
                )
            }
        }
    }
}

impl std::error::Error for CancellationProtocolViolation {}

/// Simplified task state kind for tracking transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskStateKind {
    /// Initial state.
    Created,
    /// Task is running normally.
    Running,
    /// Cancel has been requested but not acknowledged.
    CancelRequested,
    /// Task has acknowledged cancel and is running cleanup.
    Cancelling,
    /// Cleanup done, running finalizers.
    Finalizing,
    /// Task completed with Ok result.
    CompletedOk,
    /// Task completed with error.
    CompletedErr,
    /// Task completed due to cancellation.
    CompletedCancelled,
    /// Task completed due to panic.
    CompletedPanicked,
}

impl TaskStateKind {
    /// Converts from the full TaskState enum.
    #[must_use]
    pub fn from_task_state(state: &TaskState) -> Self {
        match state {
            TaskState::Created => Self::Created,
            TaskState::Running => Self::Running,
            TaskState::CancelRequested { .. } => Self::CancelRequested,
            TaskState::Cancelling { .. } => Self::Cancelling,
            TaskState::Finalizing { .. } => Self::Finalizing,
            TaskState::Completed(outcome) => match outcome {
                crate::types::Outcome::Ok(()) => Self::CompletedOk,
                crate::types::Outcome::Err(_) => Self::CompletedErr,
                crate::types::Outcome::Cancelled(_) => Self::CompletedCancelled,
                crate::types::Outcome::Panicked(_) => Self::CompletedPanicked,
            },
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CompletedOk
                | Self::CompletedErr
                | Self::CompletedCancelled
                | Self::CompletedPanicked
        )
    }

    /// Returns true if this state is part of the cancellation sequence.
    #[must_use]
    pub const fn is_cancel_sequence(self) -> bool {
        matches!(
            self,
            Self::CancelRequested | Self::Cancelling | Self::Finalizing | Self::CompletedCancelled
        )
    }
}

/// Record of a cancel request event.
#[derive(Debug, Clone)]
struct CancelRequestRecord {
    /// When the cancel was requested.
    requested_at: Time,
    /// The cancel reason.
    reason: CancelReason,
    /// Number of polls since the request.
    polls_since: u32,
    /// Whether the cancel has been acknowledged.
    acknowledged: bool,
}

/// Record of a task's state for protocol verification.
#[derive(Debug, Clone)]
struct TaskProtocolRecord {
    /// Current state of the task.
    current_state: TaskStateKind,
    /// Cancel request if any.
    cancel_request: Option<CancelRequestRecord>,
    /// History of state transitions for debugging.
    transitions: Vec<(TaskStateKind, TaskStateKind, Time)>,
    /// Current mask depth (0 = unmasked).
    mask_depth: u32,
    /// br-asupersync-9fjaqe / -f1zjwu — Last cancellation witness
    /// observed via `on_cancel_witness`. Used to validate per-task
    /// witness transitions through the same `CancelWitness` validator
    /// the cancel-correctness oracle uses, so the two oracles agree
    /// on epoch / phase / reason invariants when wired to the same
    /// witness stream.
    last_witness: Option<CancelWitness>,
}

impl TaskProtocolRecord {
    fn new() -> Self {
        Self {
            current_state: TaskStateKind::Created,
            cancel_request: None,
            transitions: Vec::new(),
            mask_depth: 0,
            last_witness: None,
        }
    }
}

/// Oracle for verifying the cancellation protocol invariant.
///
/// This oracle tracks:
/// - Task state transitions
/// - Cancel requests and acknowledgements
/// - Region tree structure for propagation checking
/// - Region cancel status
///
/// Enhanced for runtime use with configurable enforcement, structured logging,
/// stack trace capture, and thread-safe violation tracking.
#[derive(Debug, Default)]
pub struct CancellationProtocolOracle {
    /// Per-task protocol records.
    tasks: BTreeMap<TaskId, TaskProtocolRecord>,
    /// Map from region to its parent.
    region_parents: BTreeMap<RegionId, Option<RegionId>>,
    /// Map from region to its children.
    region_children: BTreeMap<RegionId, Vec<RegionId>>,
    /// Regions that have been cancelled.
    cancelled_regions: BTreeMap<RegionId, CancelReason>,
    /// Map from task to owning region.
    task_regions: BTreeMap<TaskId, RegionId>,
    /// Regions the topology above holds because a runtime snapshot reported
    /// them (rather than a caller feeding `on_region_create`), so a later
    /// snapshot can retire the ones that have since closed.
    state_regions: BTreeSet<RegionId>,
    /// Detected violations (legacy format).
    violations: Vec<CancellationProtocolViolation>,
    /// Enhanced violation records with diagnostics and tracing.
    violation_records: Vec<ViolationRecord>,
    /// Configuration for runtime behavior.
    config: CancelCorrectnessConfig,
}

impl CancellationProtocolOracle {
    /// Creates a new cancellation protocol oracle with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new oracle with specific configuration for runtime use.
    #[must_use]
    pub fn with_config(config: CancelCorrectnessConfig) -> Self {
        Self {
            tasks: BTreeMap::new(),
            region_parents: BTreeMap::new(),
            region_children: BTreeMap::new(),
            cancelled_regions: BTreeMap::new(),
            task_regions: BTreeMap::new(),
            state_regions: BTreeSet::new(),
            violations: Vec::new(),
            violation_records: Vec::new(),
            config,
        }
    }

    /// Creates a new oracle for production runtime use with optimized settings.
    #[must_use]
    pub fn for_runtime() -> Self {
        Self::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Warn,
            capture_stacks: false,      // Disabled for performance
            max_violations_tracked: 50, // Reduced for memory usage
            structured_logging: true,
        })
    }

    /// Records a violation and applies the configured enforcement mode.
    fn record_violation(&mut self, violation: CancellationProtocolViolation) {
        // Legacy format for backward compatibility
        self.violations.push(violation.clone());

        // Enhanced format with diagnostics
        let record = ViolationRecord::new(violation.clone(), &self.config);

        // Emit structured log if enabled
        if self.config.structured_logging {
            record.emit_structured_log();
        }

        // Store the record (with memory bounds)
        if self.violation_records.len() < self.config.max_violations_tracked {
            self.violation_records.push(record);
        }

        // Apply enforcement mode
        match self.config.enforcement {
            EnforcementMode::Panic => {
                panic!("Cancel protocol violation detected: {violation}");
            }
            EnforcementMode::Warn => {
                crate::tracing_compat::warn!(
                    violation = %violation,
                    "cancel protocol violation"
                );
                #[cfg(feature = "tracing-integration")]
                {
                    if let Some(stack) = self
                        .violation_records
                        .last()
                        .and_then(|r| r.stack_trace.as_ref())
                    {
                        crate::tracing_compat::warn!(
                            stack_trace = %stack,
                            "cancel protocol violation stack trace"
                        );
                    }
                }
            }
            EnforcementMode::Collect => {
                // Just collect, no immediate action
            }
        }
    }

    /// Records a region creation event.
    pub fn on_region_create(&mut self, region: RegionId, parent: Option<RegionId>) {
        self.region_parents.insert(region, parent);
        self.region_children.entry(region).or_default();

        if let Some(p) = parent {
            self.region_children.entry(p).or_default().push(region);
        }
    }

    /// Records a task creation event.
    pub fn on_task_create(&mut self, task: TaskId, region: RegionId) {
        self.tasks.insert(task, TaskProtocolRecord::new());
        self.task_regions.insert(task, region);
    }

    /// Records a cancel request on a task.
    pub fn on_cancel_request(&mut self, task: TaskId, reason: CancelReason, time: Time) {
        // First, check if we need to report a violation
        let violation = if let Some(existing_record) = self.tasks.get(&task) {
            if let Some(ref existing) = existing_record.cancel_request {
                if reason.kind.severity() < existing.reason.kind.severity() {
                    Some(CancellationProtocolViolation::NonMonotonicCancel {
                        task,
                        before: existing.reason.kind,
                        after: reason.kind,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Record the violation if needed
        if let Some(v) = violation {
            self.record_violation(v);
        }

        // Now update the record
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);

        if let Some(ref mut existing) = record.cancel_request {
            // Strengthen the reason
            existing.reason.strengthen(&reason);
        } else {
            record.cancel_request = Some(CancelRequestRecord {
                requested_at: time,
                reason,
                polls_since: 0,
                acknowledged: false,
            });
        }
    }

    /// Records a cancel acknowledgement (checkpoint with mask=0).
    pub fn on_cancel_ack(&mut self, task: TaskId, _time: Time) {
        if let Some(record) = self.tasks.get_mut(&task) {
            if let Some(ref mut cancel) = record.cancel_request {
                cancel.acknowledged = true;
            }
        }
    }

    /// Records a poll event for a task (for tracking acknowledgement timing).
    pub fn on_task_poll(&mut self, task: TaskId) {
        if let Some(record) = self.tasks.get_mut(&task) {
            if let Some(ref mut cancel) = record.cancel_request {
                if !cancel.acknowledged {
                    cancel.polls_since += 1;
                }
            }
        }
    }

    /// Records a mask section entry for a task.
    ///
    /// Tracks the current mask depth so the oracle can verify that cancel
    /// acknowledgement is deferred while masked (**INV-MASK-DEFER**) and
    /// that mask depth never exceeds the compile-time bound (**INV-MASK-BOUNDED**).
    ///
    /// Enforces `rule.cancel.checkpoint_masked` (#10) and
    /// `inv.cancel.mask_bounded` (#11, `inv.cancel.mask_monotone` #12).
    pub fn on_mask_enter(&mut self, task: TaskId, time: Time) {
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        record.mask_depth += 1;

        let new_depth = record.mask_depth;
        if new_depth > crate::types::MAX_MASK_DEPTH {
            // Need to record violation after releasing the borrow
            self.record_violation(CancellationProtocolViolation::MaskDepthExceeded {
                task,
                depth: new_depth,
                max: crate::types::MAX_MASK_DEPTH,
                time,
            });
        }
    }

    /// Records a mask section exit for a task.
    ///
    /// br-asupersync-kzhbt8: an exit observed while `mask_depth == 0` is a
    /// protocol violation (more exits than enters), not a no-op. The
    /// previous implementation used `saturating_sub`, silently swallowing
    /// the asymmetry and producing a false-negative oracle verdict.
    pub fn on_mask_exit(&mut self, task: TaskId, time: Time) {
        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        if record.mask_depth == 0 {
            self.record_violation(CancellationProtocolViolation::UnmatchedMaskExit { task, time });
            return;
        }
        record.mask_depth -= 1;
    }

    /// Records a task state transition.
    ///
    /// This validates that the transition follows the cancellation protocol.
    pub fn on_transition(&mut self, task: TaskId, from: &TaskState, to: &TaskState, time: Time) {
        let from_kind = TaskStateKind::from_task_state(from);
        let to_kind = TaskStateKind::from_task_state(to);

        // Validate the transition first (before borrowing self.tasks mutably)
        let violation = Self::validate_transition_static(task, from_kind, to_kind, time);
        if let Some(v) = violation {
            self.record_violation(v);
        }

        let record = self
            .tasks
            .entry(task)
            .or_insert_with(TaskProtocolRecord::new);
        record.transitions.push((from_kind, to_kind, time));
        record.current_state = to_kind;

        // If transitioning to Cancelling, mark as acknowledged and check mask state
        if to_kind == TaskStateKind::Cancelling {
            let current_mask_depth = record.mask_depth;
            if current_mask_depth > 0 {
                // Need to record violation after releasing the borrow
                self.record_violation(CancellationProtocolViolation::CancelAckWhileMasked {
                    task,
                    mask_depth: current_mask_depth,
                    time,
                });
                // Re-borrow to mark as acknowledged
                if let Some(record) = self.tasks.get_mut(&task) {
                    if let Some(ref mut cancel) = record.cancel_request {
                        cancel.acknowledged = true;
                    }
                }
            } else if let Some(ref mut cancel) = record.cancel_request {
                cancel.acknowledged = true;
            }
        }
    }

    /// Records a region cancel event.
    ///
    /// This also checks that all descendants are cancelled (INV-CANCEL-PROPAGATES).
    pub fn on_region_cancel(&mut self, region: RegionId, reason: CancelReason, _time: Time) {
        self.cancelled_regions.insert(region, reason);
    }

    /// Records a region close event.
    ///
    /// The cancellation protocol oracle does not currently enforce close
    /// semantics directly; this hook exists for symmetry with other oracles
    /// and for conformance tests that model region close events.
    pub fn on_region_close(&mut self, _region: RegionId, _time: Time) {}

    /// br-asupersync-9fjaqe / -f1zjwu — Cross-oracle witness hook.
    ///
    /// Routes through the canonical [`CancelWitness::validate_initial`]
    /// and [`CancelWitness::validate_transition`] entry points, which
    /// the witness-based [`crate::lab::oracle::cancel_correctness`]
    /// oracle also uses. With both oracles wired to the same witness
    /// stream, they cannot disagree on epoch / phase / reason
    /// invariants — the disagreement that motivated this bead.
    ///
    /// Invariants enforced (delegated to `CancelWitness`):
    /// - Initial witness must use a non-zero epoch (epoch 0 is the
    ///   "no-cancel" sentinel).
    /// - Successive witnesses for the same task must agree on
    ///   task_id / region_id / epoch, advance phase monotonically,
    ///   and never weaken the cancellation reason.
    ///
    /// On violation, a `InvalidInitialWitnessEpoch` or
    /// `InvalidWitnessTransition` is recorded; the offending witness
    /// is *not* stored as the new "last witness" so subsequent
    /// transitions are validated against the last well-formed witness.
    pub fn on_cancel_witness(&mut self, witness: CancelWitness, time: Time) {
        let task_id = witness.task_id;
        let phase = witness.phase;
        let epoch = witness.epoch;

        let record = self
            .tasks
            .entry(task_id)
            .or_insert_with(TaskProtocolRecord::new);

        if let Some(prev) = record.last_witness.as_ref() {
            match CancelWitness::validate_transition(Some(prev), &witness) {
                Ok(()) => {
                    record.last_witness = Some(witness);
                }
                Err(error) => {
                    self.record_violation(
                        CancellationProtocolViolation::InvalidWitnessTransition {
                            task: task_id,
                            error,
                            time,
                        },
                    );
                }
            }
        } else {
            match witness.validate_initial() {
                Ok(()) => {
                    record.last_witness = Some(witness);
                }
                Err(_) => {
                    self.record_violation(
                        CancellationProtocolViolation::InvalidInitialWitnessEpoch {
                            task: task_id,
                            epoch,
                            phase,
                            time,
                        },
                    );
                }
            }
        }
    }

    /// Rebuilds oracle state from a runtime snapshot.
    ///
    /// This snapshot path is intentionally conservative: it captures the
    /// current cancellation topology and task cancellation states without
    /// replaying full transition histories.
    pub fn snapshot_from_state(&mut self, state: &RuntimeState, now: Time) {
        self.reset();

        let mut regions = Vec::new();
        for (_, region) in state.regions_iter() {
            regions.push((region.id, region.parent, region.cancel_reason()));
        }
        regions.sort_by_key(|(id, _, _)| *id);

        for (region, parent, _) in &regions {
            self.region_parents.insert(*region, *parent);
            self.region_children.entry(*region).or_default();
            self.state_regions.insert(*region);
        }
        for (region, parent, _) in &regions {
            if let Some(parent_id) = parent {
                self.region_children
                    .entry(*parent_id)
                    .or_default()
                    .push(*region);
            }
        }
        for children in self.region_children.values_mut() {
            children.sort();
        }
        for (region, _, reason) in regions {
            if let Some(cancel_reason) = reason {
                self.cancelled_regions.insert(region, cancel_reason);
            }
        }

        let mut tasks = Vec::new();
        for (_, task) in state.tasks_iter() {
            let state_kind = TaskStateKind::from_task_state(&task.state);
            let cancel_reason = match &task.state {
                TaskState::CancelRequested { reason, .. }
                | TaskState::Cancelling { reason, .. }
                | TaskState::Finalizing { reason, .. } => Some(reason.clone()),
                TaskState::Completed(crate::types::Outcome::Cancelled(reason)) => {
                    Some(reason.clone())
                }
                _ => None,
            };
            let mask_depth = task
                .cx_inner
                .as_ref()
                .map_or(0, |inner| inner.read().mask_depth);
            tasks.push((task.id, task.owner, state_kind, cancel_reason, mask_depth));
        }
        tasks.sort_by_key(|(task, _, _, _, _)| *task);

        for (task, region, state_kind, cancel_reason, mask_depth) in tasks {
            self.tasks.insert(
                task,
                TaskProtocolRecord {
                    current_state: state_kind,
                    cancel_request: cancel_reason.map(|reason| CancelRequestRecord {
                        requested_at: now,
                        reason,
                        polls_since: 0,
                        acknowledged: !matches!(state_kind, TaskStateKind::CancelRequested),
                    }),
                    transitions: Vec::new(),
                    mask_depth,
                    last_witness: None,
                },
            );
            self.task_regions.insert(task, region);
        }
    }

    /// Refreshes the region topology, the region cancellations and the
    /// task-to-region map from a runtime snapshot, keeping every live task
    /// record and anything a caller fed by hand.
    ///
    /// The lab runtime feeds this oracle task transitions, polls, cancel
    /// requests and acknowledgements as they happen, but region creation and
    /// region cancellation happen inside the runtime state. Only
    /// [`Self::snapshot_from_state`] captured them, and the lab ran it only
    /// while the oracle had seen no live event. Once any task had been polled,
    /// the propagation check therefore ran on an empty region tree, and a
    /// cancelled region with an uncancelled live child passed
    /// (br-asupersync-vcu2oz). Closed regions leave the runtime's table, so
    /// regions an earlier snapshot reported and that are gone now are retired
    /// here instead of being compared against a later cancellation.
    pub fn refresh_region_topology_from_state(&mut self, state: &RuntimeState) {
        let retired: Vec<RegionId> = std::mem::take(&mut self.state_regions)
            .into_iter()
            .collect();
        for region in &retired {
            self.region_parents.remove(region);
            self.region_children.remove(region);
            self.cancelled_regions.remove(region);
        }
        for children in self.region_children.values_mut() {
            children.retain(|child| !retired.contains(child));
        }

        let mut regions = Vec::new();
        for (_, region) in state.regions_iter() {
            regions.push((region.id, region.parent, region.cancel_reason()));
        }
        regions.sort_by_key(|(id, _, _)| *id);
        for (region, parent, _) in &regions {
            self.region_parents.insert(*region, *parent);
            self.region_children.entry(*region).or_default();
            self.state_regions.insert(*region);
        }
        for (region, parent, _) in &regions {
            if let Some(parent_id) = parent {
                let children = self.region_children.entry(*parent_id).or_default();
                if !children.contains(region) {
                    children.push(*region);
                }
            }
        }
        for children in self.region_children.values_mut() {
            children.sort();
        }
        for (region, _, reason) in regions {
            if let Some(cancel_reason) = reason {
                self.cancelled_regions.insert(region, cancel_reason);
            }
        }
        for (_, task) in state.tasks_iter() {
            self.task_regions.entry(task.id).or_insert(task.owner);
        }
    }

    /// Validates a single state transition (static version for borrow checker).
    fn validate_transition_static(
        task: TaskId,
        from: TaskStateKind,
        to: TaskStateKind,
        time: Time,
    ) -> Option<CancellationProtocolViolation> {
        // Define valid transitions (nested patterns for clippy)
        let is_valid = matches!(
            (from, to),
            // From Created: can go to Running or CancelRequested
            (TaskStateKind::Created, TaskStateKind::Running | TaskStateKind::CancelRequested)
                // From Running: can complete normally or start cancellation
                | (
                    TaskStateKind::Running,
                    TaskStateKind::CompletedOk
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                        | TaskStateKind::CancelRequested
                )
                // From CancelRequested: can strengthen, move to Cancelling, or
                // complete before acknowledging. The runtime canonicalizes
                // successful completion under cancel to CompletedCancelled.
                | (
                    TaskStateKind::CancelRequested,
                    TaskStateKind::CancelRequested
                        | TaskStateKind::Cancelling
                        | TaskStateKind::CompletedCancelled
                        | TaskStateKind::CompletedOk
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                )
                // From Cancelling: can finalize or error/panic during cleanup
                | (
                    TaskStateKind::Cancelling,
                    TaskStateKind::Finalizing
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                )
                // From Finalizing: can complete cancelled or error/panic
                | (
                    TaskStateKind::Finalizing,
                    TaskStateKind::CompletedCancelled
                        | TaskStateKind::CompletedErr
                        | TaskStateKind::CompletedPanicked
                )
        ) || from == to; // Same state (no-op)

        if is_valid {
            None
        } else {
            Some(CancellationProtocolViolation::SkippedState {
                task,
                from,
                to,
                time,
            })
        }
    }

    /// Verifies cancel propagation for all cancelled regions.
    fn check_cancel_propagation(&self) -> Result<(), CancellationProtocolViolation> {
        let mut regions: Vec<RegionId> = self.cancelled_regions.keys().copied().collect();
        regions.sort();
        for region in regions {
            self.verify_descendants_cancelled(region)?;
        }
        Ok(())
    }

    /// Recursively verifies that all descendants of a cancelled region are also cancelled.
    fn verify_descendants_cancelled(
        &self,
        region: RegionId,
    ) -> Result<(), CancellationProtocolViolation> {
        if let Some(children) = self.region_children.get(&region) {
            let mut ordered = children.clone();
            ordered.sort();
            for child in ordered {
                if !self.cancelled_regions.contains_key(&child) {
                    return Err(CancellationProtocolViolation::CancelNotPropagated {
                        parent: region,
                        uncancelled_child: child,
                    });
                }
                self.verify_descendants_cancelled(child)?;
            }
        }
        Ok(())
    }

    /// Checks for cancelled tasks that haven't completed.
    fn check_cancelled_tasks_completed(&self) -> Vec<CancellationProtocolViolation> {
        let mut violations = Vec::new();

        let mut tasks: Vec<TaskId> = self.tasks.keys().copied().collect();
        tasks.sort();
        for task in tasks {
            let Some(record) = self.tasks.get(&task) else {
                continue;
            };
            if let Some(ref cancel) = record.cancel_request {
                if !record.current_state.is_terminal() {
                    violations.push(CancellationProtocolViolation::CancelNotCompleted {
                        task,
                        stuck_state: record.current_state,
                        requested_at: cancel.requested_at,
                    });
                }
            }
        }

        violations
    }

    /// Checks for tasks that stay in `CancelRequested` beyond the bounded
    /// acknowledgement window.
    fn check_cancel_acknowledged(&self) -> Vec<CancellationProtocolViolation> {
        let mut violations = Vec::new();

        let mut tasks: Vec<TaskId> = self.tasks.keys().copied().collect();
        tasks.sort();
        for task in tasks {
            let Some(record) = self.tasks.get(&task) else {
                continue;
            };
            let Some(cancel) = record.cancel_request.as_ref() else {
                continue;
            };

            if !cancel.acknowledged
                && record.current_state == TaskStateKind::CancelRequested
                && cancel.polls_since > CANCEL_ACK_POLL_BOUND
            {
                violations.push(CancellationProtocolViolation::CancelNotAcknowledged {
                    task,
                    requested_at: cancel.requested_at,
                    polls_since_request: cancel.polls_since,
                });
            }
        }

        violations
    }

    /// Checks all invariants and returns the first violation, if any.
    ///
    /// # Errors
    ///
    /// Returns `Err(CancellationProtocolViolation)` if the cancellation protocol
    /// was violated.
    pub fn check(&self) -> Result<(), CancellationProtocolViolation> {
        // Return any accumulated violations first
        if let Some(v) = self.violations.first() {
            return Err(v.clone());
        }

        // Check cancel propagation
        self.check_cancel_propagation()?;

        // Check that cancel requests are acknowledged within bounded polls.
        let ack_violations = self.check_cancel_acknowledged();
        if let Some(v) = ack_violations.first() {
            return Err(v.clone());
        }

        // Check that cancelled tasks completed
        let task_violations = self.check_cancelled_tasks_completed();
        if let Some(v) = task_violations.first() {
            return Err(v.clone());
        }

        Ok(())
    }

    /// Returns all violations detected so far.
    #[must_use]
    pub fn all_violations(&self) -> Vec<CancellationProtocolViolation> {
        let mut all = self.violations.clone();

        // Add propagation violations
        let mut regions: Vec<RegionId> = self.cancelled_regions.keys().copied().collect();
        regions.sort();
        for region in regions {
            if let Err(v) = self.verify_descendants_cancelled(region) {
                all.push(v);
            }
        }

        // Add acknowledgement-bound violations.
        all.extend(self.check_cancel_acknowledged());

        // Add completion violations
        all.extend(self.check_cancelled_tasks_completed());

        all
    }

    /// Returns the set of regions that have been cancelled.
    #[must_use]
    pub fn cancelled_regions(&self) -> &BTreeMap<RegionId, CancelReason> {
        &self.cancelled_regions
    }

    /// Returns the current state of a task, if tracked.
    #[must_use]
    pub fn task_state(&self, task: TaskId) -> Option<TaskStateKind> {
        self.tasks.get(&task).map(|r| r.current_state)
    }

    /// Returns true if a task has an active cancel request.
    #[must_use]
    pub fn has_cancel_request(&self, task: TaskId) -> bool {
        self.tasks
            .get(&task)
            .is_some_and(|r| r.cancel_request.is_some())
    }

    /// Returns the number of tracked regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.region_parents.len()
    }

    /// Returns the number of cancelled regions.
    #[must_use]
    pub fn cancel_count(&self) -> usize {
        self.cancelled_regions.len()
    }

    /// Returns whether the oracle has already observed live protocol events.
    ///
    /// This lets higher-level hydration paths avoid overwriting richer
    /// request/drain/finalize evidence with a synthetic state-only snapshot.
    #[must_use]
    pub fn has_observed_events(&self) -> bool {
        !self.tasks.is_empty()
            || !self.region_parents.is_empty()
            || !self.region_children.is_empty()
            || !self.cancelled_regions.is_empty()
            || !self.task_regions.is_empty()
            || !self.violations.is_empty()
            || !self.violation_records.is_empty()
    }

    /// Returns the current mask depth of a task, if tracked.
    #[must_use]
    pub fn task_mask_depth(&self, task: TaskId) -> Option<u32> {
        self.tasks.get(&task).map(|r| r.mask_depth)
    }

    /// Returns all enhanced violation records with full diagnostics.
    #[must_use]
    pub fn violation_records(&self) -> &[ViolationRecord] {
        &self.violation_records
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &CancelCorrectnessConfig {
        &self.config
    }

    /// Updates the enforcement configuration for runtime use.
    pub fn set_enforcement_mode(&mut self, mode: EnforcementMode) {
        self.config.enforcement = mode;
    }

    /// Returns statistics about violations detected.
    #[must_use]
    pub fn violation_stats(&self) -> ViolationStats {
        ViolationStats {
            total_violations: self.violation_records.len(),
            by_type: {
                let mut counts = std::collections::HashMap::new();
                for record in &self.violation_records {
                    let violation_type = std::mem::discriminant(&record.violation);
                    *counts.entry(format!("{violation_type:?}")).or_insert(0) += 1;
                }
                counts
            },
            enforcement_mode: self.config.enforcement,
        }
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.tasks.clear();
        self.region_parents.clear();
        self.region_children.clear();
        self.cancelled_regions.clear();
        self.task_regions.clear();
        self.state_regions.clear();
        self.violations.clear();
        self.violation_records.clear();
    }
}

#[cfg(test)]
#[path = "cancellation_protocol_inline_tests.rs"]
mod tests;
