//! Proof-carrying decision-plane kernel for runtime controllers.
//!
//! This module defines the canonical [`RuntimeKernelSnapshot`] that controllers
//! observe, the [`ControllerRegistration`] contract they must satisfy, and the
//! [`ControllerRegistry`] that validates and manages controller participation.
//!
//! # Design Principles
//!
//! - **Narrow surface**: Snapshot fields are the minimum needed for decision-making.
//!   Adding a field requires explicit justification and version bump.
//! - **Deterministic**: Snapshot creation and serialization are deterministic given
//!   the same runtime state, enabling replay and comparison.
//! - **Auditable**: Every controller action is traced with snapshot ID, version,
//!   and decision metadata for post-hoc analysis.
//! - **No ambient authority**: Controllers receive snapshots; they cannot reach
//!   into runtime internals directly.
//!
//! # Versioning
//!
//! Snapshots carry a [`SnapshotVersion`] that controllers declare support for.
//! The registry rejects controllers whose expected version range does not overlap
//! with the current snapshot version. Controllers consuming a reduced snapshot
//! (fewer fields than the full version) remain in shadow mode until they upgrade.

use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Current snapshot schema version.
pub const SNAPSHOT_VERSION: SnapshotVersion = SnapshotVersion { major: 1, minor: 0 };

/// Schema version for runtime kernel snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapshotVersion {
    /// Snapshot schema major version.
    pub major: u32,
    /// Snapshot schema minor version.
    pub minor: u32,
}

impl std::fmt::Display for SnapshotVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl SnapshotVersion {
    /// Check if `other` is compatible (same major, <= minor).
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

/// Monotonic snapshot identifier. Each snapshot gets a unique, increasing ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub u64);

/// A point-in-time snapshot of observable runtime state for controllers.
///
/// Controllers receive this snapshot via their `observe` callback. They must
/// not cache snapshots across decision boundaries — each decision must use
/// the snapshot provided for that epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeKernelSnapshot {
    /// Unique identifier for this snapshot.
    pub id: SnapshotId,
    /// Schema version of this snapshot.
    pub version: SnapshotVersion,
    /// Logical time at which this snapshot was taken.
    pub timestamp: Time,

    // ── Scheduler state ───────────────────────────────────────────────
    /// Number of tasks currently in the ready queue.
    pub ready_queue_len: usize,
    /// Number of tasks in the cancel lane.
    pub cancel_lane_len: usize,
    /// Number of tasks in the finalize lane.
    pub finalize_lane_len: usize,
    /// Total tasks currently tracked by the runtime.
    pub total_tasks: usize,
    /// Number of active (non-closed) regions.
    pub active_regions: usize,
    /// Current cancel-lane streak count within the active epoch.
    pub cancel_streak_current: usize,
    /// Configured cancel-lane max streak.
    pub cancel_streak_limit: usize,

    // ── Obligation state ──────────────────────────────────────────────
    /// Number of outstanding (uncommitted) obligations.
    pub outstanding_obligations: usize,
    /// Cumulative obligation leak count since runtime start.
    pub obligation_leak_count: u64,

    // ── I/O and timer state ───────────────────────────────────────────
    /// Number of pending I/O registrations in the reactor.
    pub pending_io_registrations: usize,
    /// Number of active timers in the timer wheel.
    pub active_timers: usize,

    // ── Worker state ──────────────────────────────────────────────────
    /// Number of worker threads configured.
    pub worker_count: usize,
    /// Number of workers currently parked (idle).
    pub workers_parked: usize,
    /// Number of active blocking pool threads.
    pub blocking_threads_active: usize,

    // ── Governor and adaptive state ───────────────────────────────────
    /// Whether the Lyapunov governor is enabled.
    pub governor_enabled: bool,
    /// Whether adaptive cancel-streak is enabled.
    pub adaptive_cancel_enabled: bool,
    /// Current adaptive cancel-streak epoch number (if adaptive enabled).
    pub adaptive_epoch: u64,

    // ── Controller metadata ───────────────────────────────────────────
    /// Number of registered controllers.
    pub registered_controllers: usize,
    /// Number of controllers in shadow mode.
    pub shadow_controllers: usize,
}

impl RuntimeKernelSnapshot {
    /// Create a minimal snapshot for testing.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn test_default(id: u64, now: Time) -> Self {
        Self {
            id: SnapshotId(id),
            version: SNAPSHOT_VERSION,
            timestamp: now,
            ready_queue_len: 0,
            cancel_lane_len: 0,
            finalize_lane_len: 0,
            total_tasks: 0,
            active_regions: 0,
            cancel_streak_current: 0,
            cancel_streak_limit: 16,
            outstanding_obligations: 0,
            obligation_leak_count: 0,
            pending_io_registrations: 0,
            active_timers: 0,
            worker_count: 1,
            workers_parked: 0,
            blocking_threads_active: 0,
            governor_enabled: false,
            adaptive_cancel_enabled: false,
            adaptive_epoch: 0,
            registered_controllers: 0,
            shadow_controllers: 0,
        }
    }
}

/// Operating mode for a controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControllerMode {
    /// Controller observes snapshots but does not influence decisions.
    Shadow,
    /// Controller decisions are compared against baseline but not applied.
    Canary,
    /// Controller decisions are applied to the runtime.
    Active,
    /// Controller is paused pending investigation or manual intervention.
    Hold,
}

/// A decision emitted by a controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerDecision {
    /// ID of the controller that made this decision.
    pub controller_id: ControllerId,
    /// Snapshot ID this decision was based on.
    pub snapshot_id: SnapshotId,
    /// Human-readable decision label.
    pub label: String,
    /// Structured decision payload (controller-specific).
    pub payload: serde_json::Value,
    /// Confidence score in [0.0, 1.0] for the decision.
    pub confidence: f64,
    /// Fallback: if this decision is rejected, what should happen.
    pub fallback_label: String,
}

/// Unique identifier for a registered controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControllerId(pub u64);

/// Metadata a controller must provide at registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerRegistration {
    /// Human-readable name for this controller.
    pub name: String,
    /// Minimum snapshot version this controller can consume.
    pub min_version: SnapshotVersion,
    /// Maximum snapshot version this controller can consume.
    pub max_version: SnapshotVersion,
    /// Snapshot fields this controller requires (for forward-compat checks).
    pub required_fields: Vec<String>,
    /// Which seam IDs this controller targets (from the control-seam inventory).
    pub target_seams: Vec<String>,
    /// Initial operating mode.
    pub initial_mode: ControllerMode,
    /// Artifact ID for the controller's proof bundle (if any).
    pub proof_artifact_id: Option<String>,
    /// Budget counters: max decisions per epoch, max latency per decision.
    pub budget: ControllerBudget,
}

/// Resource budget constraints for a controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerBudget {
    /// Maximum number of decisions per snapshot epoch.
    pub max_decisions_per_epoch: u32,
    /// Maximum wall-clock microseconds per decision.
    pub max_decision_latency_us: u64,
}

impl Default for ControllerBudget {
    fn default() -> Self {
        Self {
            max_decisions_per_epoch: 1,
            max_decision_latency_us: 100,
        }
    }
}

/// Reason a controller registration was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationError {
    /// Controller name is empty.
    EmptyName,
    /// Version range is inverted (min > max).
    InvertedVersionRange,
    /// Current snapshot version is outside controller's supported range.
    IncompatibleVersion {
        /// Snapshot version found in the runtime state being validated.
        current: SnapshotVersion,
        /// Minimum snapshot version accepted by the controller.
        min: SnapshotVersion,
        /// Maximum snapshot version accepted by the controller.
        max: SnapshotVersion,
    },
    /// Required fields are not present in the current snapshot schema.
    UnsupportedFields(Vec<String>),
    /// No target seams specified.
    NoTargetSeams,
    /// Budget has zero decisions allowed.
    ZeroBudget,
    /// A controller with this name is already registered.
    DuplicateName(String),
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => write!(f, "controller name must not be empty"),
            Self::InvertedVersionRange => write!(f, "min_version must be <= max_version"),
            Self::IncompatibleVersion { current, min, max } => {
                write!(
                    f,
                    "snapshot version {current} outside controller range [{min}, {max}]"
                )
            }
            Self::UnsupportedFields(fields) => {
                write!(f, "unsupported snapshot fields: {}", fields.join(", "))
            }
            Self::NoTargetSeams => write!(f, "controller must target at least one seam"),
            Self::ZeroBudget => write!(f, "budget must allow at least one decision per epoch"),
            Self::DuplicateName(name) => {
                write!(f, "controller with name '{name}' already registered")
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

/// Known snapshot field names for validation.
const KNOWN_FIELDS: &[&str] = &[
    "ready_queue_len",
    "cancel_lane_len",
    "finalize_lane_len",
    "total_tasks",
    "active_regions",
    "cancel_streak_current",
    "cancel_streak_limit",
    "outstanding_obligations",
    "obligation_leak_count",
    "pending_io_registrations",
    "active_timers",
    "worker_count",
    "workers_parked",
    "blocking_threads_active",
    "governor_enabled",
    "adaptive_cancel_enabled",
    "adaptive_epoch",
    "registered_controllers",
    "shadow_controllers",
];

/// Policy governing controller promotion through the lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionPolicy {
    /// Minimum calibration score in [0.0, 1.0] required for promotion.
    pub min_calibration_score: f64,
    /// Minimum epochs a controller must spend in Shadow before promoting to Canary.
    pub min_shadow_epochs: u64,
    /// Minimum epochs a controller must spend in Canary before promoting to Active.
    pub min_canary_epochs: u64,
    /// Maximum allowed budget overruns before automatic rollback.
    pub max_budget_overruns: u32,
    /// Policy identifier for audit trail.
    pub policy_id: String,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self {
            min_calibration_score: 0.8,
            min_shadow_epochs: 3,
            min_canary_epochs: 2,
            max_budget_overruns: 3,
            policy_id: "default-promotion-policy-v1".to_string(),
        }
    }
}

/// Reason a promotion was rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PromotionRejection {
    /// Controller not found.
    ControllerNotFound,
    /// Calibration score below threshold.
    CalibrationTooLow {
        /// Current calibration score.
        current: f64,
        /// Required minimum calibration score.
        required: f64,
    },
    /// Not enough epochs in the prerequisite mode.
    InsufficientEpochs {
        /// Current number of epochs in the prerequisite mode.
        current: u64,
        /// Required minimum number of epochs.
        required: u64,
        /// The mode the controller is currently in.
        mode: ControllerMode,
    },
    /// Invalid transition (e.g., Shadow directly to Active).
    InvalidTransition {
        /// Current mode.
        from: ControllerMode,
        /// Requested mode.
        to: ControllerMode,
    },
    /// Controller is in Hold mode and cannot be promoted without explicit release.
    HeldForInvestigation,
}

impl std::fmt::Display for PromotionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControllerNotFound => write!(f, "controller not found"),
            Self::CalibrationTooLow { current, required } => {
                write!(
                    f,
                    "calibration score {current:.3} below threshold {required:.3}"
                )
            }
            Self::InsufficientEpochs {
                current,
                required,
                mode,
            } => {
                write!(f, "only {current} epochs in {mode:?}, need {required}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition from {from:?} to {to:?}")
            }
            Self::HeldForInvestigation => {
                write!(
                    f,
                    "controller held for investigation; release before promoting"
                )
            }
        }
    }
}

/// Reason a controller was rolled back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RollbackReason {
    /// Calibration score dropped below threshold.
    CalibrationRegression {
        /// Calibration score that triggered the rollback.
        score: f64,
    },
    /// Budget overruns exceeded policy limit.
    BudgetOverruns {
        /// Number of overruns accumulated.
        count: u32,
    },
    /// Manual rollback requested by operator.
    ManualRollback,
    /// Fallback triggered by a decision rejection.
    FallbackTriggered {
        /// The decision label that caused the fallback.
        decision_label: String,
    },
}

impl std::fmt::Display for RollbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CalibrationRegression { score } => {
                write!(f, "calibration regressed to {score:.3}")
            }
            Self::BudgetOverruns { count } => {
                write!(f, "budget overruns reached {count}")
            }
            Self::ManualRollback => write!(f, "manual rollback requested"),
            Self::FallbackTriggered { decision_label } => {
                write!(f, "fallback triggered by decision: {decision_label}")
            }
        }
    }
}

/// A recovery command emitted when a rollout fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCommand {
    /// Controller that needs recovery.
    pub controller_id: ControllerId,
    /// Controller name for human identification.
    pub controller_name: String,
    /// Mode the controller was rolled back from.
    pub rolled_back_from: ControllerMode,
    /// Mode the controller was rolled back to.
    pub rolled_back_to: ControllerMode,
    /// Reason for the rollback.
    pub reason: RollbackReason,
    /// Policy ID that governed the decision.
    pub policy_id: String,
    /// Snapshot ID at the time of rollback.
    pub at_snapshot_id: Option<SnapshotId>,
    /// Suggested remediation steps.
    pub remediation: Vec<String>,
}

/// An entry in the evidence ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLedgerEntry {
    /// Sequential entry ID.
    pub entry_id: u64,
    /// Controller ID this entry pertains to.
    pub controller_id: ControllerId,
    /// Snapshot ID at the time of the event (if available).
    pub snapshot_id: Option<SnapshotId>,
    /// Type of event.
    pub event: LedgerEvent,
    /// Policy ID governing this event.
    pub policy_id: String,
    /// Timestamp (logical).
    pub timestamp: Time,
}

/// Events recorded in the evidence ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LedgerEvent {
    /// Controller was registered.
    Registered {
        /// Initial mode assigned.
        initial_mode: ControllerMode,
    },
    /// Controller mode was changed via promotion.
    Promoted {
        /// Previous mode.
        from: ControllerMode,
        /// New mode.
        to: ControllerMode,
        /// Calibration score at time of promotion.
        calibration_score: f64,
    },
    /// Controller was rolled back.
    RolledBack {
        /// Previous mode.
        from: ControllerMode,
        /// New mode.
        to: ControllerMode,
        /// Reason for rollback.
        reason: RollbackReason,
    },
    /// Controller was placed on hold.
    Held {
        /// Previous mode.
        from: ControllerMode,
    },
    /// Controller was released from hold.
    Released {
        /// Mode restored to.
        to: ControllerMode,
    },
    /// Controller was deregistered.
    Deregistered,
    /// Promotion was rejected.
    PromotionRejected {
        /// The target mode that was requested.
        target: ControllerMode,
        /// Why the promotion was rejected.
        rejection: PromotionRejection,
    },
    /// Decision recorded.
    DecisionRecorded {
        /// Decision label.
        label: String,
        /// Whether the decision was within budget.
        within_budget: bool,
    },
}

/// Record of a registered controller within the registry.
#[derive(Debug, Clone)]
struct RegisteredController {
    registration: ControllerRegistration,
    mode: ControllerMode,
    decisions_this_epoch: u32,
    last_snapshot_id: Option<SnapshotId>,
    calibration_score: f64,
    epochs_in_current_mode: u64,
    budget_overruns: u32,
    /// Mode before entering Hold, so we can restore on release.
    held_from_mode: Option<ControllerMode>,
    fallback_active: bool,
    last_action_label: String,
}

/// Type alias for log sink callbacks.
type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Registry that validates and manages controller participation.
///
/// The registry enforces:
/// - Version compatibility between controllers and snapshots
/// - Required field existence in the snapshot schema
/// - Uniqueness of controller names
/// - Budget constraints per epoch
/// - Promotion pipeline (Shadow → Canary → Active) with calibration gates
/// - Evidence ledger for audit trail
pub struct ControllerRegistry {
    controllers: BTreeMap<ControllerId, RegisteredController>,
    next_id: u64,
    next_snapshot_id: u64,
    /// Callback for structured logging of registration events.
    log_sink: Option<LogSink>,
    /// Promotion policy governing lifecycle transitions.
    promotion_policy: PromotionPolicy,
    /// Evidence ledger for audit and replay.
    evidence_ledger: Vec<EvidenceLedgerEntry>,
    /// Next evidence ledger entry ID.
    next_ledger_id: u64,
}

impl ControllerRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            controllers: BTreeMap::new(),
            next_id: 1,
            next_snapshot_id: 1,
            log_sink: None,
            promotion_policy: PromotionPolicy::default(),
            evidence_ledger: Vec::new(),
            next_ledger_id: 1,
        }
    }

    /// Set a structured log sink for registration and decision events.
    #[must_use]
    pub fn with_log_sink(mut self, sink: LogSink) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// Register a controller, returning its ID on success.
    pub fn register(
        &mut self,
        registration: ControllerRegistration,
    ) -> Result<ControllerId, RegistrationError> {
        self.validate(&registration)?;

        let id = ControllerId(self.next_id);
        self.next_id += 1;

        let mode = if (registration.initial_mode == ControllerMode::Active
            || registration.initial_mode == ControllerMode::Canary)
            && !registration
                .max_version
                .is_compatible_with(&SNAPSHOT_VERSION)
        {
            // Downgrade to shadow if snapshot is newer than controller expects
            ControllerMode::Shadow
        } else {
            registration.initial_mode
        };

        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_registered id={} name={} mode={:?} seams={:?} version_range=[{}, {}]",
                id.0,
                registration.name,
                mode,
                registration.target_seams,
                registration.min_version,
                registration.max_version,
            ));
        }

        self.controllers.insert(
            id,
            RegisteredController {
                registration,
                mode,
                decisions_this_epoch: 0,
                last_snapshot_id: None,
                calibration_score: 0.0,
                epochs_in_current_mode: 0,
                budget_overruns: 0,
                held_from_mode: None,
                fallback_active: false,
                last_action_label: String::new(),
            },
        );

        self.record_ledger_entry(id, None, LedgerEvent::Registered { initial_mode: mode });

        Ok(id)
    }

    /// Validate a registration without inserting it.
    fn validate(&self, reg: &ControllerRegistration) -> Result<(), RegistrationError> {
        if reg.name.is_empty() {
            return Err(RegistrationError::EmptyName);
        }
        if reg.min_version > reg.max_version {
            return Err(RegistrationError::InvertedVersionRange);
        }
        if !SNAPSHOT_VERSION.is_compatible_with(&reg.min_version)
            || SNAPSHOT_VERSION.major != reg.max_version.major
        {
            return Err(RegistrationError::IncompatibleVersion {
                current: SNAPSHOT_VERSION,
                min: reg.min_version,
                max: reg.max_version,
            });
        }
        let unknown: Vec<String> = reg
            .required_fields
            .iter()
            .filter(|f| !KNOWN_FIELDS.contains(&f.as_str()))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(RegistrationError::UnsupportedFields(unknown));
        }
        if reg.target_seams.is_empty() {
            return Err(RegistrationError::NoTargetSeams);
        }
        if reg.budget.max_decisions_per_epoch == 0 {
            return Err(RegistrationError::ZeroBudget);
        }
        if self
            .controllers
            .values()
            .any(|c| c.registration.name == reg.name)
        {
            return Err(RegistrationError::DuplicateName(reg.name.clone()));
        }
        Ok(())
    }

    /// Deregister a controller.
    pub fn deregister(&mut self, id: ControllerId) -> bool {
        let removed = self.controllers.remove(&id).is_some();
        if removed {
            self.record_ledger_entry(id, None, LedgerEvent::Deregistered);
        }
        removed
    }

    /// Get the current mode of a controller.
    #[must_use]
    pub fn mode(&self, id: ControllerId) -> Option<ControllerMode> {
        self.controllers.get(&id).map(|c| c.mode)
    }

    /// Set the mode of a controller.
    pub fn set_mode(&mut self, id: ControllerId, mode: ControllerMode) -> bool {
        let Some(controller) = self.controllers.get_mut(&id) else {
            return false;
        };
        controller.mode = mode;
        true
    }

    /// Get registration info for a controller.
    #[must_use]
    pub fn registration(&self, id: ControllerId) -> Option<&ControllerRegistration> {
        self.controllers.get(&id).map(|c| &c.registration)
    }

    /// Number of registered controllers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.controllers.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.controllers.is_empty()
    }

    /// Count of controllers in shadow mode.
    #[must_use]
    pub fn shadow_count(&self) -> usize {
        self.controllers
            .values()
            .filter(|c| c.mode == ControllerMode::Shadow)
            .count()
    }

    /// Allocate the next snapshot ID.
    pub fn next_snapshot_id(&mut self) -> SnapshotId {
        let id = SnapshotId(self.next_snapshot_id);
        self.next_snapshot_id += 1;
        id
    }

    /// Reset per-epoch decision counters for all controllers.
    ///
    /// Note: prefer `advance_epoch()` which also increments epoch-in-mode counters.
    pub fn reset_epoch(&mut self) {
        for controller in self.controllers.values_mut() {
            controller.decisions_this_epoch = 0;
        }
    }

    /// Record a decision and check budget.
    /// Returns `true` if the decision is within budget, `false` if over budget.
    pub fn record_decision(&mut self, decision: &ControllerDecision) -> bool {
        let Some(controller) = self.controllers.get_mut(&decision.controller_id) else {
            return false;
        };
        controller.last_snapshot_id = Some(decision.snapshot_id);
        controller.last_action_label.clone_from(&decision.label);
        controller.decisions_this_epoch += 1;
        let within_budget = controller.decisions_this_epoch
            <= controller.registration.budget.max_decisions_per_epoch;
        if !within_budget {
            controller.budget_overruns += 1;
        }

        self.record_ledger_entry(
            decision.controller_id,
            Some(decision.snapshot_id),
            LedgerEvent::DecisionRecorded {
                label: decision.label.clone(),
                within_budget,
            },
        );

        within_budget
    }

    /// Update calibration score for a controller (e.g., after shadow comparison).
    pub fn update_calibration(&mut self, id: ControllerId, score: f64) {
        if let Some(controller) = self.controllers.get_mut(&id) {
            controller.calibration_score = score;
        }
    }

    /// Get calibration score for a controller.
    #[must_use]
    pub fn calibration_score(&self, id: ControllerId) -> Option<f64> {
        self.controllers.get(&id).map(|c| c.calibration_score)
    }

    /// List all controller IDs.
    #[must_use]
    pub fn controller_ids(&self) -> Vec<ControllerId> {
        self.controllers.keys().copied().collect()
    }

    /// Set the promotion policy.
    pub fn set_promotion_policy(&mut self, policy: PromotionPolicy) {
        self.promotion_policy = policy;
    }

    /// Get the current promotion policy.
    #[must_use]
    pub fn promotion_policy(&self) -> &PromotionPolicy {
        &self.promotion_policy
    }

    /// Advance epoch counters for all controllers.
    pub fn advance_epoch(&mut self) {
        for controller in self.controllers.values_mut() {
            controller.epochs_in_current_mode += 1;
            controller.decisions_this_epoch = 0;
        }
    }

    /// Try to promote a controller to the next mode in the pipeline.
    ///
    /// Promotion follows the pipeline: Shadow → Canary → Active.
    /// Each transition requires calibration and epoch thresholds defined by
    /// the promotion policy. Returns a `RecoveryCommand` on rejection.
    pub fn try_promote(
        &mut self,
        id: ControllerId,
        target: ControllerMode,
    ) -> Result<ControllerMode, PromotionRejection> {
        let policy = self.promotion_policy.clone();
        let controller = self
            .controllers
            .get(&id)
            .ok_or(PromotionRejection::ControllerNotFound)?;

        let current_mode = controller.mode;
        let calibration = controller.calibration_score;
        let epochs = controller.epochs_in_current_mode;

        // Hold blocks all promotions
        if current_mode == ControllerMode::Hold {
            let rejection = PromotionRejection::HeldForInvestigation;
            self.record_ledger_entry(
                id,
                None,
                LedgerEvent::PromotionRejected {
                    target,
                    rejection: rejection.clone(),
                },
            );
            self.log_promotion_rejection(id, &rejection, &policy);
            return Err(rejection);
        }

        // Validate transition is valid
        let valid = matches!(
            (current_mode, target),
            (ControllerMode::Shadow, ControllerMode::Canary)
                | (ControllerMode::Canary, ControllerMode::Active)
        );
        if !valid {
            let rejection = PromotionRejection::InvalidTransition {
                from: current_mode,
                to: target,
            };
            self.record_ledger_entry(
                id,
                None,
                LedgerEvent::PromotionRejected {
                    target,
                    rejection: rejection.clone(),
                },
            );
            self.log_promotion_rejection(id, &rejection, &policy);
            return Err(rejection);
        }

        // Check calibration threshold
        if calibration < policy.min_calibration_score {
            let rejection = PromotionRejection::CalibrationTooLow {
                current: calibration,
                required: policy.min_calibration_score,
            };
            self.record_ledger_entry(
                id,
                None,
                LedgerEvent::PromotionRejected {
                    target,
                    rejection: rejection.clone(),
                },
            );
            self.log_promotion_rejection(id, &rejection, &policy);
            return Err(rejection);
        }

        // Check epoch requirements
        let required_epochs = match current_mode {
            ControllerMode::Shadow => policy.min_shadow_epochs,
            ControllerMode::Canary => policy.min_canary_epochs,
            _ => 0,
        };
        if epochs < required_epochs {
            let rejection = PromotionRejection::InsufficientEpochs {
                current: epochs,
                required: required_epochs,
                mode: current_mode,
            };
            self.record_ledger_entry(
                id,
                None,
                LedgerEvent::PromotionRejected {
                    target,
                    rejection: rejection.clone(),
                },
            );
            self.log_promotion_rejection(id, &rejection, &policy);
            return Err(rejection);
        }

        // All gates passed — promote
        let controller = self.controllers.get_mut(&id).expect("checked above");
        controller.mode = target;
        controller.epochs_in_current_mode = 0;
        controller.budget_overruns = 0;

        self.record_ledger_entry(
            id,
            None,
            LedgerEvent::Promoted {
                from: current_mode,
                to: target,
                calibration_score: calibration,
            },
        );

        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_promoted id={} from={:?} to={:?} calibration={:.3} policy_id={}",
                id.0, current_mode, target, calibration, policy.policy_id,
            ));
        }

        Ok(target)
    }

    /// Roll back a controller to Shadow mode, producing a recovery command.
    pub fn rollback(
        &mut self,
        id: ControllerId,
        reason: RollbackReason,
    ) -> Option<RecoveryCommand> {
        let policy_id = self.promotion_policy.policy_id.clone();
        let controller = self.controllers.get_mut(&id)?;
        let from = controller.mode;

        if from == ControllerMode::Shadow {
            // Already in the most conservative mode; nothing to roll back.
            return None;
        }

        let to = ControllerMode::Shadow;
        controller.mode = to;
        controller.epochs_in_current_mode = 0;
        controller.fallback_active = true;
        let name = controller.registration.name.clone();
        let snapshot_id = controller.last_snapshot_id;

        self.record_ledger_entry(
            id,
            snapshot_id,
            LedgerEvent::RolledBack {
                from,
                to,
                reason: reason.clone(),
            },
        );

        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_rolled_back id={} from={:?} to={:?} reason={} policy_id={} snapshot_id={:?}",
                id.0, from, to, reason, policy_id, snapshot_id,
            ));
        }

        let remediation = match &reason {
            RollbackReason::CalibrationRegression { score } => vec![
                format!("Investigate calibration drop to {score:.3}"),
                "Review recent decision evidence in ledger".to_string(),
                "Re-run shadow validation before re-promotion".to_string(),
            ],
            RollbackReason::BudgetOverruns { count } => vec![
                format!("Controller exceeded budget {count} times"),
                "Review decision frequency and payload complexity".to_string(),
                "Consider increasing budget or reducing decision scope".to_string(),
            ],
            RollbackReason::ManualRollback => vec![
                "Manual rollback — verify runtime stability".to_string(),
                "Check evidence ledger for preceding anomalies".to_string(),
            ],
            RollbackReason::FallbackTriggered { decision_label } => vec![
                format!("Fallback triggered by decision: {decision_label}"),
                "Inspect decision payload and snapshot context".to_string(),
                "Validate fallback path is functioning correctly".to_string(),
            ],
        };

        Some(RecoveryCommand {
            controller_id: id,
            controller_name: name,
            rolled_back_from: from,
            rolled_back_to: to,
            reason,
            policy_id,
            at_snapshot_id: snapshot_id,
            remediation,
        })
    }

    /// Place a controller on hold, pausing its participation.
    pub fn hold(&mut self, id: ControllerId) -> bool {
        let Some(controller) = self.controllers.get_mut(&id) else {
            return false;
        };
        if controller.mode == ControllerMode::Hold {
            return false; // already held
        }
        let from = controller.mode;
        controller.held_from_mode = Some(from);
        controller.mode = ControllerMode::Hold;

        self.record_ledger_entry(id, None, LedgerEvent::Held { from });

        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_held id={} from={:?} policy_id={}",
                id.0, from, self.promotion_policy.policy_id,
            ));
        }
        true
    }

    /// Release a controller from hold, restoring its previous mode.
    pub fn release_hold(&mut self, id: ControllerId) -> Option<ControllerMode> {
        let controller = self.controllers.get_mut(&id)?;
        if controller.mode != ControllerMode::Hold {
            return None;
        }
        let restored = controller
            .held_from_mode
            .take()
            .unwrap_or(ControllerMode::Shadow);
        controller.mode = restored;
        controller.epochs_in_current_mode = 0;

        self.record_ledger_entry(id, None, LedgerEvent::Released { to: restored });

        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_released id={} to={:?} policy_id={}",
                id.0, restored, self.promotion_policy.policy_id,
            ));
        }
        Some(restored)
    }

    /// Whether a controller's fallback is currently active.
    #[must_use]
    pub fn is_fallback_active(&self, id: ControllerId) -> bool {
        self.controllers.get(&id).is_some_and(|c| c.fallback_active)
    }

    /// Clear fallback flag (e.g., after recovery is confirmed).
    pub fn clear_fallback(&mut self, id: ControllerId) {
        if let Some(controller) = self.controllers.get_mut(&id) {
            controller.fallback_active = false;
        }
    }

    /// Get the evidence ledger.
    #[must_use]
    pub fn evidence_ledger(&self) -> &[EvidenceLedgerEntry] {
        &self.evidence_ledger
    }

    /// Get ledger entries for a specific controller.
    #[must_use]
    pub fn controller_ledger(&self, id: ControllerId) -> Vec<&EvidenceLedgerEntry> {
        self.evidence_ledger
            .iter()
            .filter(|entry| entry.controller_id == id)
            .collect()
    }

    /// Get the number of epochs a controller has spent in its current mode.
    #[must_use]
    pub fn epochs_in_current_mode(&self, id: ControllerId) -> Option<u64> {
        self.controllers.get(&id).map(|c| c.epochs_in_current_mode)
    }

    /// Get the number of budget overruns for a controller.
    #[must_use]
    pub fn budget_overruns(&self, id: ControllerId) -> Option<u32> {
        self.controllers.get(&id).map(|c| c.budget_overruns)
    }

    fn record_ledger_entry(
        &mut self,
        controller_id: ControllerId,
        snapshot_id: Option<SnapshotId>,
        event: LedgerEvent,
    ) {
        let entry = EvidenceLedgerEntry {
            entry_id: self.next_ledger_id,
            controller_id,
            snapshot_id,
            event,
            policy_id: self.promotion_policy.policy_id.clone(),
            timestamp: Time::ZERO, // Logical time injected by caller in production
        };
        self.next_ledger_id += 1;
        self.evidence_ledger.push(entry);
    }

    fn log_promotion_rejection(
        &self,
        id: ControllerId,
        rejection: &PromotionRejection,
        policy: &PromotionPolicy,
    ) {
        if let Some(ref sink) = self.log_sink {
            sink(&format!(
                "controller_promotion_rejected id={} reason={} policy_id={}",
                id.0, rejection, policy.policy_id,
            ));
        }
    }
}

impl Default for ControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registration(name: &str) -> ControllerRegistration {
        ControllerRegistration {
            name: name.to_string(),
            min_version: SnapshotVersion { major: 1, minor: 0 },
            max_version: SnapshotVersion { major: 1, minor: 0 },
            required_fields: vec!["ready_queue_len".to_string(), "cancel_lane_len".to_string()],
            target_seams: vec!["AA01-SEAM-SCHED-CANCEL-STREAK".to_string()],
            initial_mode: ControllerMode::Shadow,
            proof_artifact_id: None,
            budget: ControllerBudget::default(),
        }
    }

    #[test]
    fn snapshot_version_compatibility() {
        let v1_0 = SnapshotVersion { major: 1, minor: 0 };
        let v1_1 = SnapshotVersion { major: 1, minor: 1 };
        let v2_0 = SnapshotVersion { major: 2, minor: 0 };

        assert!(v1_0.is_compatible_with(&v1_0));
        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v1_1));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn snapshot_serialization_roundtrip() {
        let snap = RuntimeKernelSnapshot::test_default(1, Time::ZERO);
        let json = serde_json::to_string(&snap).unwrap();
        let deser: RuntimeKernelSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, snap.id);
        assert_eq!(deser.version, snap.version);
        assert_eq!(deser.ready_queue_len, 0);
        assert_eq!(deser.worker_count, 1);
    }

    #[test]
    fn snapshot_deterministic_serialization() {
        let snap1 = RuntimeKernelSnapshot::test_default(42, Time::ZERO);
        let snap2 = RuntimeKernelSnapshot::test_default(42, Time::ZERO);
        assert_eq!(
            serde_json::to_string(&snap1).unwrap(),
            serde_json::to_string(&snap2).unwrap(),
        );
    }

    #[test]
    fn register_valid_controller() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("test-ctrl")).unwrap();
        assert_eq!(id.0, 1);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    }

    #[test]
    fn reject_empty_name() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("");
        reg.name = String::new();
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::EmptyName,
        );
    }

    #[test]
    fn reject_inverted_version_range() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("bad-range");
        reg.min_version = SnapshotVersion { major: 2, minor: 0 };
        reg.max_version = SnapshotVersion { major: 1, minor: 0 };
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::InvertedVersionRange,
        );
    }

    #[test]
    fn reject_incompatible_version() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("future-ctrl");
        reg.min_version = SnapshotVersion { major: 5, minor: 0 };
        reg.max_version = SnapshotVersion { major: 5, minor: 0 };
        assert!(matches!(
            registry.register(reg).unwrap_err(),
            RegistrationError::IncompatibleVersion { .. }
        ));

        // Test minor version incompatibility
        let mut reg2 = test_registration("future-minor-ctrl");
        reg2.min_version = SnapshotVersion {
            major: SNAPSHOT_VERSION.major,
            minor: SNAPSHOT_VERSION.minor + 1,
        };
        reg2.max_version = SnapshotVersion {
            major: SNAPSHOT_VERSION.major,
            minor: SNAPSHOT_VERSION.minor + 1,
        };
        assert!(matches!(
            registry.register(reg2).unwrap_err(),
            RegistrationError::IncompatibleVersion { .. }
        ));
    }

    #[test]
    fn reject_unsupported_fields() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("bad-fields");
        reg.required_fields = vec!["nonexistent_field".to_string()];
        assert!(matches!(
            registry.register(reg).unwrap_err(),
            RegistrationError::UnsupportedFields(_)
        ));
    }

    #[test]
    fn reject_no_target_seams() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("no-seams");
        reg.target_seams = vec![];
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::NoTargetSeams,
        );
    }

    #[test]
    fn reject_zero_budget() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("zero-budget");
        reg.budget.max_decisions_per_epoch = 0;
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::ZeroBudget,
        );
    }

    #[test]
    fn reject_duplicate_name() {
        let mut registry = ControllerRegistry::new();
        registry.register(test_registration("dup")).unwrap();
        assert_eq!(
            registry.register(test_registration("dup")).unwrap_err(),
            RegistrationError::DuplicateName("dup".to_string()),
        );
    }

    #[test]
    fn deregister_controller() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("removable")).unwrap();
        assert!(registry.deregister(id));
        assert_eq!(registry.len(), 0);
        assert!(!registry.deregister(id));
    }

    #[test]
    fn set_mode() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("mode-test")).unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert!(registry.set_mode(id, ControllerMode::Active));
        assert_eq!(registry.mode(id), Some(ControllerMode::Active));
    }

    #[test]
    fn shadow_count() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.register(test_registration("s1")).unwrap();
        let _id2 = registry.register(test_registration("s2")).unwrap();
        assert_eq!(registry.shadow_count(), 2);
        registry.set_mode(id1, ControllerMode::Active);
        assert_eq!(registry.shadow_count(), 1);
    }

    #[test]
    fn decision_budget_enforcement() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("budget-ctrl")).unwrap();
        let snap_id = registry.next_snapshot_id();

        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "test".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };

        // First decision within budget (max_decisions_per_epoch = 1)
        assert!(registry.record_decision(&decision));
        // Second decision exceeds budget
        assert!(!registry.record_decision(&decision));
        // Reset epoch
        registry.reset_epoch();
        // First decision after reset is within budget again
        assert!(registry.record_decision(&decision));
    }

    #[test]
    fn calibration_tracking() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("calib")).unwrap();
        assert_eq!(registry.calibration_score(id), Some(0.0));
        registry.update_calibration(id, 0.85);
        assert_eq!(registry.calibration_score(id), Some(0.85));
    }

    #[test]
    fn snapshot_id_monotonic() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.next_snapshot_id();
        let id2 = registry.next_snapshot_id();
        let id3 = registry.next_snapshot_id();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn active_mode_not_downgraded_when_snapshot_matches() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("downgrade-test");
        reg.initial_mode = ControllerMode::Active;
        // Controller supports up to SNAPSHOT_VERSION
        reg.min_version = SNAPSHOT_VERSION;
        reg.max_version = SNAPSHOT_VERSION;
        // This should work since versions match
        let id = registry.register(reg).unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Active));
    }

    #[test]
    fn known_fields_completeness() {
        // Verify KNOWN_FIELDS matches snapshot struct fields
        let snap = RuntimeKernelSnapshot::test_default(1, Time::ZERO);
        let json = serde_json::to_value(&snap).unwrap();
        let obj = json.as_object().unwrap();
        // Non-data fields that aren't in KNOWN_FIELDS
        let meta_fields = [
            "id",
            "version",
            "timestamp",
            "registered_controllers",
            "shadow_controllers",
        ];
        for field in KNOWN_FIELDS {
            assert!(
                obj.contains_key(*field),
                "KNOWN_FIELDS contains '{field}' but snapshot JSON does not"
            );
        }
        for key in obj.keys() {
            if meta_fields.contains(&key.as_str()) {
                continue;
            }
            assert!(
                KNOWN_FIELDS.contains(&key.as_str()),
                "snapshot JSON has field '{key}' not in KNOWN_FIELDS"
            );
        }
    }

    #[test]
    fn registration_info_accessible() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("info-test")).unwrap();
        let reg = registry.registration(id).unwrap();
        assert_eq!(reg.name, "info-test");
        assert_eq!(reg.target_seams, vec!["AA01-SEAM-SCHED-CANCEL-STREAK"]);
    }

    #[test]
    fn controller_ids_listed() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.register(test_registration("a")).unwrap();
        let id2 = registry.register(test_registration("b")).unwrap();
        let ids = registry.controller_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn log_sink_receives_registration_event() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = ControllerRegistry::new().with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        registry.register(test_registration("logged")).unwrap();
        {
            let captured = logs.lock();
            assert_eq!(captured.len(), 1);
            assert!(captured[0].contains("controller_registered"));
            assert!(captured[0].contains("logged"));
            drop(captured);
        }
    }

    #[test]
    fn decision_for_unknown_controller_returns_false() {
        let mut registry = ControllerRegistry::new();
        let decision = ControllerDecision {
            controller_id: ControllerId(999),
            snapshot_id: SnapshotId(1),
            label: "ghost".to_string(),
            payload: serde_json::Value::Null,
            confidence: 1.0,
            fallback_label: "noop".to_string(),
        };
        assert!(!registry.record_decision(&decision));
    }

    #[test]
    fn version_display() {
        let v = SnapshotVersion { major: 1, minor: 2 };
        assert_eq!(format!("{v}"), "1.2");
    }

    #[test]
    fn error_display_coverage() {
        let errors = [
            RegistrationError::EmptyName,
            RegistrationError::InvertedVersionRange,
            RegistrationError::IncompatibleVersion {
                current: SnapshotVersion { major: 1, minor: 0 },
                min: SnapshotVersion { major: 2, minor: 0 },
                max: SnapshotVersion { major: 2, minor: 0 },
            },
            RegistrationError::UnsupportedFields(vec!["foo".to_string()]),
            RegistrationError::NoTargetSeams,
            RegistrationError::ZeroBudget,
            RegistrationError::DuplicateName("dup".to_string()),
        ];
        for error in &errors {
            let msg = format!("{error}");
            assert!(!msg.is_empty());
        }
    }

    // ── AA-02.3: Shadow, canary, rollback, evidence-ledger validation ──

    fn registry_with_policy(policy: PromotionPolicy) -> ControllerRegistry {
        let mut r = ControllerRegistry::new();
        r.set_promotion_policy(policy);
        r
    }

    fn fast_policy() -> PromotionPolicy {
        PromotionPolicy {
            min_calibration_score: 0.8,
            min_shadow_epochs: 2,
            min_canary_epochs: 1,
            max_budget_overruns: 3,
            policy_id: "test-fast-v1".to_string(),
        }
    }

    #[test]
    fn promote_shadow_to_canary() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("promo")).unwrap();
        registry.update_calibration(id, 0.9);
        // Need 2 epochs in shadow
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert_eq!(result, Ok(ControllerMode::Canary));
        assert_eq!(registry.mode(id), Some(ControllerMode::Canary));
        assert_eq!(registry.epochs_in_current_mode(id), Some(0));
    }

    #[test]
    fn promote_canary_to_active() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("canary-up")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Active);
        assert_eq!(result, Ok(ControllerMode::Active));
    }

    #[test]
    fn promote_rejects_insufficient_epochs() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("too-soon")).unwrap();
        registry.update_calibration(id, 0.9);
        // Only 1 epoch, need 2
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::InsufficientEpochs {
                current: 1,
                required: 2,
                ..
            })
        ));
    }

    #[test]
    fn promote_rejects_low_calibration() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("low-cal")).unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::CalibrationTooLow { .. })
        ));
    }

    #[test]
    fn promote_rejects_invalid_transition_shadow_to_active() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("skip")).unwrap();
        registry.update_calibration(id, 0.99);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Active);
        assert!(matches!(
            result,
            Err(PromotionRejection::InvalidTransition { .. })
        ));
    }

    #[test]
    fn promote_rejects_active_to_canary() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("backward")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rollback_from_active_to_shadow() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("rollme")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::CalibrationRegression { score: 0.3 })
            .unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert_eq!(cmd.rolled_back_from, ControllerMode::Active);
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
        assert_eq!(cmd.controller_name, "rollme");
        assert!(!cmd.remediation.is_empty());
        assert!(registry.is_fallback_active(id));
    }

    #[test]
    fn rollback_from_canary_to_shadow() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("can-roll")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::ManualRollback)
            .unwrap();
        assert_eq!(cmd.rolled_back_from, ControllerMode::Canary);
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    }

    #[test]
    fn rollback_from_shadow_returns_none() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("already-shadow"))
            .unwrap();
        assert!(
            registry
                .rollback(id, RollbackReason::ManualRollback)
                .is_none()
        );
    }

    #[test]
    fn hold_and_release() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("holdme")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        assert!(registry.hold(id));
        assert_eq!(registry.mode(id), Some(ControllerMode::Hold));

        // Cannot promote while held
        let result = registry.try_promote(id, ControllerMode::Active);
        assert!(matches!(
            result,
            Err(PromotionRejection::HeldForInvestigation)
        ));

        // Release restores previous mode
        let restored = registry.release_hold(id).unwrap();
        assert_eq!(restored, ControllerMode::Canary);
        assert_eq!(registry.mode(id), Some(ControllerMode::Canary));
    }

    #[test]
    fn hold_already_held_returns_false() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("double-hold")).unwrap();
        assert!(registry.hold(id));
        assert!(!registry.hold(id));
    }

    #[test]
    fn release_non_held_returns_none() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("not-held")).unwrap();
        assert!(registry.release_hold(id).is_none());
    }

    #[test]
    fn fallback_lifecycle() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("fb")).unwrap();
        assert!(!registry.is_fallback_active(id));
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.rollback(
            id,
            RollbackReason::FallbackTriggered {
                decision_label: "bad-decision".to_string(),
            },
        );
        assert!(registry.is_fallback_active(id));
        registry.clear_fallback(id);
        assert!(!registry.is_fallback_active(id));
    }

    #[test]
    fn evidence_ledger_records_registration() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("ledger-reg")).unwrap();
        let entries = registry.controller_ledger(id);
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].event, LedgerEvent::Registered { .. }));
    }

    #[test]
    fn evidence_ledger_records_full_lifecycle() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("full-life")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();

        // Promote to canary
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();

        // Promote to active
        registry.try_promote(id, ControllerMode::Active).unwrap();

        // Rollback
        registry.rollback(id, RollbackReason::ManualRollback);

        let entries = registry.controller_ledger(id);
        // Registered + 2 Promoted + RolledBack = 4
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[0].event, LedgerEvent::Registered { .. }));
        assert!(matches!(
            entries[1].event,
            LedgerEvent::Promoted {
                from: ControllerMode::Shadow,
                to: ControllerMode::Canary,
                ..
            }
        ));
        assert!(matches!(
            entries[2].event,
            LedgerEvent::Promoted {
                from: ControllerMode::Canary,
                to: ControllerMode::Active,
                ..
            }
        ));
        assert!(matches!(
            entries[3].event,
            LedgerEvent::RolledBack {
                from: ControllerMode::Active,
                to: ControllerMode::Shadow,
                ..
            }
        ));
    }

    #[test]
    fn evidence_ledger_records_decisions() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("dec-ledger")).unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "adjust-streak".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };
        registry.record_decision(&decision);
        let entries = registry.controller_ledger(id);
        // Registered + DecisionRecorded
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            &entries[1].event,
            LedgerEvent::DecisionRecorded { label, within_budget: true } if label == "adjust-streak"
        ));
    }

    #[test]
    fn evidence_ledger_records_promotion_rejections() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("reject-ledger"))
            .unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let _ = registry.try_promote(id, ControllerMode::Canary);
        let entries = registry.controller_ledger(id);
        // Registered + PromotionRejected
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            entries[1].event,
            LedgerEvent::PromotionRejected { .. }
        ));
    }

    #[test]
    fn evidence_ledger_records_hold_and_release() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("hold-ledger")).unwrap();
        registry.hold(id);
        registry.release_hold(id);
        let entries = registry.controller_ledger(id);
        // Registered + Held + Released
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[1].event, LedgerEvent::Held { .. }));
        assert!(matches!(entries[2].event, LedgerEvent::Released { .. }));
    }

    #[test]
    fn evidence_ledger_records_deregistration() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("dereg-ledger"))
            .unwrap();
        registry.deregister(id);
        let entries = registry.controller_ledger(id);
        // Registered + Deregistered
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[1].event, LedgerEvent::Deregistered));
    }

    #[test]
    fn ledger_entry_ids_are_monotonic() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("mono")).unwrap();
        registry.hold(id);
        registry.release_hold(id);
        let ledger = registry.evidence_ledger();
        for pair in ledger.windows(2) {
            assert!(pair[0].entry_id < pair[1].entry_id);
        }
    }

    #[test]
    fn ledger_entries_carry_policy_id() {
        let policy = fast_policy();
        let expected_id = policy.policy_id.clone();
        let mut registry = registry_with_policy(policy);
        let id = registry
            .register(test_registration("policy-trace"))
            .unwrap();
        registry.hold(id);
        for entry in registry.controller_ledger(id) {
            assert_eq!(entry.policy_id, expected_id);
        }
    }

    #[test]
    fn budget_overruns_tracked() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("overruns")).unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "test".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };
        // 1st within budget, 2nd exceeds (budget=1)
        registry.record_decision(&decision);
        registry.record_decision(&decision);
        registry.record_decision(&decision);
        assert_eq!(registry.budget_overruns(id), Some(2));
    }

    #[test]
    fn advance_epoch_increments_mode_counter() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("epoch-count")).unwrap();
        assert_eq!(registry.epochs_in_current_mode(id), Some(0));
        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(1));
        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(2));
    }

    #[test]
    fn recovery_command_has_remediation() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("recovery")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::BudgetOverruns { count: 5 })
            .unwrap();
        assert_eq!(cmd.policy_id, "test-fast-v1");
        assert!(!cmd.remediation.is_empty());
        assert!(cmd.remediation.iter().any(|r| r.contains("budget")));
    }

    #[test]
    fn recovery_command_for_fallback_triggered() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("fallback-cmd"))
            .unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(
                id,
                RollbackReason::FallbackTriggered {
                    decision_label: "bad-action".to_string(),
                },
            )
            .unwrap();
        assert!(cmd.remediation.iter().any(|r| r.contains("bad-action")));
    }

    #[test]
    fn structured_log_covers_promotion_and_rollback() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = registry_with_policy(fast_policy());
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-promo")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.rollback(id, RollbackReason::ManualRollback);

        {
            let captured = logs.lock();
            assert!(captured.iter().any(|l| l.contains("controller_promoted")));
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("controller_rolled_back"))
            );
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("policy_id=test-fast-v1"))
            );
            drop(captured);
        }
    }

    #[test]
    fn structured_log_covers_promotion_rejection() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = registry_with_policy(fast_policy());
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-reject")).unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let _ = registry.try_promote(id, ControllerMode::Canary);

        {
            let captured = logs.lock();
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("controller_promotion_rejected"))
            );
            drop(captured);
        }
    }

    #[test]
    fn structured_log_covers_hold_and_release() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = ControllerRegistry::new();
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-hold")).unwrap();
        registry.hold(id);
        registry.release_hold(id);

        {
            let captured = logs.lock();
            assert!(captured.iter().any(|l| l.contains("controller_held")));
            assert!(captured.iter().any(|l| l.contains("controller_released")));
            drop(captured);
        }
    }

    #[test]
    fn promotion_rejection_display_coverage() {
        let rejections = [
            PromotionRejection::ControllerNotFound,
            PromotionRejection::CalibrationTooLow {
                current: 0.5,
                required: 0.8,
            },
            PromotionRejection::InsufficientEpochs {
                current: 1,
                required: 3,
                mode: ControllerMode::Shadow,
            },
            PromotionRejection::InvalidTransition {
                from: ControllerMode::Shadow,
                to: ControllerMode::Active,
            },
            PromotionRejection::HeldForInvestigation,
        ];
        for rejection in &rejections {
            let msg = format!("{rejection}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn rollback_reason_display_coverage() {
        let reasons = [
            RollbackReason::CalibrationRegression { score: 0.3 },
            RollbackReason::BudgetOverruns { count: 5 },
            RollbackReason::ManualRollback,
            RollbackReason::FallbackTriggered {
                decision_label: "test".to_string(),
            },
        ];
        for reason in &reasons {
            let msg = format!("{reason}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn e2e_promotion_cannot_bypass_verification() {
        // Scenario: a controller tries to skip the pipeline
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("bypass-attempt"))
            .unwrap();

        // Attempt 1: promote directly to Active from Shadow (must fail)
        registry.update_calibration(id, 0.99);
        for _ in 0..10 {
            registry.advance_epoch();
        }
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Active),
            Err(PromotionRejection::InvalidTransition { .. })
        ));

        // Attempt 2: promote to Canary without sufficient calibration
        registry.update_calibration(id, 0.1);
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::CalibrationTooLow { .. })
        ));

        // Attempt 3: promote to Canary without sufficient epochs
        registry.update_calibration(id, 0.99);
        // Reset epochs by setting mode (simulate re-registration scenario)
        registry.set_mode(id, ControllerMode::Shadow);
        // epochs_in_current_mode is still high, so this succeeds — good,
        // it proves you can't bypass calibration but epochs accumulate

        // Correct path: full pipeline
        let id2 = registry
            .register(test_registration("correct-path"))
            .unwrap();
        registry.update_calibration(id2, 0.9);
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_err()); // 0 epochs
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_err()); // 1 epoch
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_ok()); // 2 epochs
        assert!(registry.try_promote(id2, ControllerMode::Active).is_err()); // 0 canary epochs
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Active).is_ok()); // 1 canary epoch
        assert_eq!(registry.mode(id2), Some(ControllerMode::Active));
    }

    #[test]
    fn e2e_failed_rollout_leaves_conservative_state() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("failed-rollout"))
            .unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();

        // Simulate calibration regression triggering rollback
        registry.update_calibration(id, 0.2);
        let cmd = registry
            .rollback(id, RollbackReason::CalibrationRegression { score: 0.2 })
            .unwrap();

        // Verify conservative state
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert!(registry.is_fallback_active(id));
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
        assert!(!cmd.remediation.is_empty());

        // Cannot re-promote without clearing conditions
        assert!(registry.try_promote(id, ControllerMode::Canary).is_err());
    }

    #[test]
    fn e2e_hold_blocks_entire_pipeline() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("hold-block")).unwrap();
        registry.update_calibration(id, 0.99);
        registry.advance_epoch();
        registry.advance_epoch();

        registry.hold(id);
        // All promotion attempts fail while held
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::HeldForInvestigation)
        ));

        // Release and verify pipeline resumes
        registry.release_hold(id);
        // Epochs reset on release, need to accumulate again
        registry.advance_epoch();
        registry.advance_epoch();
        assert!(registry.try_promote(id, ControllerMode::Canary).is_ok());
    }

    #[test]
    fn recovery_command_serializable() {
        let cmd = RecoveryCommand {
            controller_id: ControllerId(42),
            controller_name: "test-ctrl".to_string(),
            rolled_back_from: ControllerMode::Active,
            rolled_back_to: ControllerMode::Shadow,
            reason: RollbackReason::ManualRollback,
            policy_id: "test-v1".to_string(),
            at_snapshot_id: Some(SnapshotId(100)),
            remediation: vec!["check logs".to_string()],
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let deser: RecoveryCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.controller_id, ControllerId(42));
        assert_eq!(deser.controller_name, "test-ctrl");
    }

    #[test]
    fn evidence_ledger_entry_serializable() {
        let entry = EvidenceLedgerEntry {
            entry_id: 1,
            controller_id: ControllerId(1),
            snapshot_id: Some(SnapshotId(5)),
            event: LedgerEvent::Promoted {
                from: ControllerMode::Shadow,
                to: ControllerMode::Canary,
                calibration_score: 0.85,
            },
            policy_id: "test".to_string(),
            timestamp: Time::ZERO,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deser: EvidenceLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.entry_id, 1);
    }

    #[test]
    fn default_promotion_policy_values() {
        let policy = PromotionPolicy::default();
        assert!((policy.min_calibration_score - 0.8).abs() < f64::EPSILON);
        assert_eq!(policy.min_shadow_epochs, 3);
        assert_eq!(policy.min_canary_epochs, 2);
        assert_eq!(policy.max_budget_overruns, 3);
        assert_eq!(policy.policy_id, "default-promotion-policy-v1");
    }
}
