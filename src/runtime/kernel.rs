//! Proof-carrying decision-plane kernel for runtime controllers.
//!
//! This module defines the canonical [`crate::runtime::kernel::RuntimeKernelSnapshot`]
//! that controllers observe, the [`crate::runtime::kernel::ControllerRegistration`]
//! contract they must satisfy, and the [`crate::runtime::kernel::ControllerRegistry`]
//! that validates and manages controller participation.
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
//! Snapshots carry a [`crate::runtime::kernel::SnapshotVersion`] that controllers
//! declare support for.
//! The registry rejects controllers whose expected version range does not overlap
//! with the current snapshot version. Controllers consuming a reduced snapshot
//! (fewer fields than the full version) remain in shadow mode until they upgrade.

use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Current snapshot schema version.
pub const SNAPSHOT_VERSION: SnapshotVersion = SnapshotVersion { major: 1, minor: 0 };

/// Schema version for exported controller snapshot ledgers.
pub const CONTROLLER_SNAPSHOT_LEDGER_SCHEMA_VERSION: &str = "controller-snapshot-ledger-v1";

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
    #[inline]
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
    /// Confidence score in `[0.0, 1.0]` for the decision.
    pub confidence: f64,
    /// Fallback: if this decision is rejected, what should happen.
    pub fallback_label: String,
}

/// Unique identifier for a registered controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControllerId(pub u64);

/// Planner-facing snapshot of one controller's observable runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerSnapshotState {
    /// Unique identifier for the controller.
    pub controller_id: ControllerId,
    /// Human-readable controller name.
    pub controller_name: String,
    /// Current operating mode.
    pub mode: ControllerMode,
    /// Decisions recorded in the current epoch.
    pub decisions_this_epoch: u32,
    /// Whether the controller is running on a conservative fallback path.
    pub fallback_active: bool,
    /// Latest calibration score tracked for this controller.
    pub calibration_score: f64,
    /// Latest decision confidence observed for this controller, if any.
    pub last_decision_confidence: Option<f64>,
    /// Last high-level action recorded for this controller, if any.
    pub last_action_label: Option<String>,
    /// Monotonic evidence tick (ledger entry ID) of the last recorded action.
    pub last_evidence_tick: Option<u64>,
    /// Latest runtime snapshot ID consumed by the controller, if any.
    pub last_snapshot_id: Option<SnapshotId>,
    /// Epochs spent in the current operating mode.
    pub epochs_in_current_mode: u64,
    /// Budget overruns accumulated since the last successful promotion.
    pub budget_overruns: u32,
    /// Proof artifact associated with the controller registration, if any.
    pub proof_artifact_id: Option<String>,
}

/// Deterministic controller-state ledger exported for operator bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerSnapshotLedger {
    /// Version tag for the controller snapshot ledger schema.
    pub schema_version: String,
    /// Number of registered controllers included in this ledger.
    pub registered_controllers: usize,
    /// Number of controllers currently operating in shadow mode.
    pub shadow_controllers: usize,
    /// Stable controller state rows sorted by controller ID.
    pub controllers: Vec<ControllerSnapshotState>,
}

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
    /// Minimum calibration score in `[0.0, 1.0]` required for promotion.
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
        /// Confidence score recorded with the decision.
        confidence: f64,
        /// Fallback label recorded with the decision.
        fallback_label: String,
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
    last_decision_confidence: Option<f64>,
    epochs_in_current_mode: u64,
    budget_overruns: u32,
    /// Mode before entering Hold, so we can restore on release.
    held_from_mode: Option<ControllerMode>,
    fallback_active: bool,
    last_evidence_tick: Option<u64>,
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
    fn snapshot_version_supported(
        current: SnapshotVersion,
        min: SnapshotVersion,
        max: SnapshotVersion,
    ) -> bool {
        current.major == min.major && current.major == max.major && min <= current && current <= max
    }

    fn set_controller_mode_state(controller: &mut RegisteredController, mode: ControllerMode) {
        if controller.mode == ControllerMode::Hold && mode != ControllerMode::Hold {
            controller.held_from_mode = None;
        }
        controller.mode = mode;
        // Epoch residency is scoped to the controller's current mode. Any
        // explicit mode set starts a fresh residency window, even when the
        // caller is re-asserting the same mode to reset stale state.
        controller.epochs_in_current_mode = 0;
    }

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
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("runtime kernel controller id counter exhausted");

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
                last_decision_confidence: None,
                epochs_in_current_mode: 0,
                budget_overruns: 0,
                held_from_mode: None,
                fallback_active: false,
                last_evidence_tick: None,
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
        if !Self::snapshot_version_supported(SNAPSHOT_VERSION, reg.min_version, reg.max_version) {
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
    #[inline]
    pub fn mode(&self, id: ControllerId) -> Option<ControllerMode> {
        self.controllers.get(&id).map(|c| c.mode)
    }

    /// Set the mode of a controller.
    #[inline]
    pub fn set_mode(&mut self, id: ControllerId, mode: ControllerMode) -> bool {
        let Some(controller) = self.controllers.get_mut(&id) else {
            return false;
        };
        if mode == ControllerMode::Hold && controller.mode != ControllerMode::Hold {
            controller.held_from_mode = Some(controller.mode);
        }
        Self::set_controller_mode_state(controller, mode);
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
        self.next_snapshot_id = self
            .next_snapshot_id
            .checked_add(1)
            .expect("runtime kernel snapshot id counter exhausted");
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
        controller.last_snapshot_id = Some(
            controller
                .last_snapshot_id
                .map_or(decision.snapshot_id, |current| {
                    current.max(decision.snapshot_id)
                }),
        );
        controller.last_decision_confidence = Some(decision.confidence);
        let within_budget = controller.decisions_this_epoch
            < controller.registration.budget.max_decisions_per_epoch;
        controller.decisions_this_epoch = controller.decisions_this_epoch.saturating_add(1);
        if !within_budget {
            controller.budget_overruns = controller.budget_overruns.saturating_add(1);
        }

        self.record_ledger_entry(
            decision.controller_id,
            Some(decision.snapshot_id),
            LedgerEvent::DecisionRecorded {
                label: decision.label.clone(),
                confidence: decision.confidence,
                fallback_label: decision.fallback_label.clone(),
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
        Self::set_controller_mode_state(controller, target);
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
        Self::set_controller_mode_state(controller, to);
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
        Self::set_controller_mode_state(controller, ControllerMode::Hold);

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
        Self::set_controller_mode_state(controller, restored);

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
            controller.last_action_label = "fallback_cleared".to_string();
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

    /// Export deterministic planner-facing controller state.
    #[must_use]
    pub fn controller_snapshot_ledger(&self) -> ControllerSnapshotLedger {
        let controllers = self
            .controllers
            .iter()
            .map(|(&controller_id, controller)| ControllerSnapshotState {
                controller_id,
                controller_name: controller.registration.name.clone(),
                mode: controller.mode,
                decisions_this_epoch: controller.decisions_this_epoch,
                fallback_active: controller.fallback_active,
                calibration_score: controller.calibration_score,
                last_decision_confidence: controller.last_decision_confidence,
                last_action_label: (!controller.last_action_label.is_empty())
                    .then(|| controller.last_action_label.clone()),
                last_evidence_tick: controller.last_evidence_tick,
                last_snapshot_id: controller.last_snapshot_id,
                epochs_in_current_mode: controller.epochs_in_current_mode,
                budget_overruns: controller.budget_overruns,
                proof_artifact_id: controller.registration.proof_artifact_id.clone(),
            })
            .collect();
        ControllerSnapshotLedger {
            schema_version: CONTROLLER_SNAPSHOT_LEDGER_SCHEMA_VERSION.to_string(),
            registered_controllers: self.len(),
            shadow_controllers: self.shadow_count(),
            controllers,
        }
    }

    fn record_ledger_entry(
        &mut self,
        controller_id: ControllerId,
        snapshot_id: Option<SnapshotId>,
        event: LedgerEvent,
    ) {
        let entry_id = self.next_ledger_id;
        let action_label = Self::ledger_event_action_label(&event);
        let entry = EvidenceLedgerEntry {
            entry_id,
            controller_id,
            snapshot_id,
            event,
            policy_id: self.promotion_policy.policy_id.clone(),
            timestamp: Time::ZERO, // Logical time injected by caller in production
        };
        if let Some(controller) = self.controllers.get_mut(&controller_id) {
            controller.last_evidence_tick = Some(entry_id);
            controller.last_action_label = action_label;
        }
        self.next_ledger_id = self
            .next_ledger_id
            .checked_add(1)
            .expect("ledger ID overflow");
        self.evidence_ledger.push(entry);
    }

    fn ledger_event_action_label(event: &LedgerEvent) -> String {
        match event {
            LedgerEvent::Registered { .. } => "registered".to_string(),
            LedgerEvent::Promoted { to, .. } => format!("promoted:{to:?}"),
            LedgerEvent::RolledBack { reason, .. } => {
                format!("rolled_back:{}", Self::rollback_reason_code(reason))
            }
            LedgerEvent::Held { .. } => "held".to_string(),
            LedgerEvent::Released { to } => format!("released:{to:?}"),
            LedgerEvent::Deregistered => "deregistered".to_string(),
            LedgerEvent::PromotionRejected { target, rejection } => format!(
                "promotion_rejected:{target:?}:{}",
                Self::promotion_rejection_code(rejection)
            ),
            LedgerEvent::DecisionRecorded { label, .. } => format!("decision:{label}"),
        }
    }

    fn promotion_rejection_code(rejection: &PromotionRejection) -> &'static str {
        match rejection {
            PromotionRejection::ControllerNotFound => "controller_not_found",
            PromotionRejection::CalibrationTooLow { .. } => "calibration_too_low",
            PromotionRejection::InsufficientEpochs { .. } => "insufficient_epochs",
            PromotionRejection::InvalidTransition { .. } => "invalid_transition",
            PromotionRejection::HeldForInvestigation => "held_for_investigation",
        }
    }

    fn rollback_reason_code(reason: &RollbackReason) -> &'static str {
        match reason {
            RollbackReason::CalibrationRegression { .. } => "calibration_regression",
            RollbackReason::BudgetOverruns { .. } => "budget_overruns",
            RollbackReason::ManualRollback => "manual_rollback",
            RollbackReason::FallbackTriggered { .. } => "fallback_triggered",
        }
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
#[path = "kernel_inline_tests.rs"]
mod tests;
