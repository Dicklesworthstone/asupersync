//! Versioned WASM ABI contract for JS/TS boundary integration.
//!
//! This module defines a stable ABI schema for browser adapters and bindgen
//! layers. It is intentionally explicit about:
//!
//! - Version compatibility decisions
//! - Boundary symbol set and payload shapes
//! - Outcome/error/cancellation encoding across the JS <-> WASM boundary
//! - Ownership state transitions for boundary handles
//! - Deterministic fingerprinting for ABI drift detection

use crate::types::{CancelPhase, CancelReason, Outcome};
use crate::util::det_hash::{BTreeMap, DetHasher};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Current ABI major version.
pub const WASM_ABI_MAJOR_VERSION: u16 = 1;
/// Current ABI minor version.
pub const WASM_ABI_MINOR_VERSION: u16 = 0;

/// Expected fingerprint of [`WASM_ABI_SIGNATURES_V1`].
///
/// Any change to the signature table requires:
/// 1) an explicit compatibility decision, and
/// 2) an update of this constant with migration notes.
pub const WASM_ABI_SIGNATURE_FINGERPRINT_V1: u64 = 4_558_451_663_113_424_898;

/// Semantic ABI version used by the JS package and wasm artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmAbiVersion {
    /// Semver major. Breaking ABI changes must bump this.
    pub major: u16,
    /// Semver minor. Backward-compatible additive changes bump this.
    pub minor: u16,
}

impl WasmAbiVersion {
    /// Current ABI version.
    pub const CURRENT: Self = Self {
        major: WASM_ABI_MAJOR_VERSION,
        minor: WASM_ABI_MINOR_VERSION,
    };
}

impl fmt::Display for WasmAbiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Result of ABI compatibility negotiation between producer and consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WasmAbiCompatibilityDecision {
    /// Exact major/minor match.
    Exact,
    /// Consumer is newer but backward compatible with producer.
    BackwardCompatible {
        /// Producer minor version.
        producer_minor: u16,
        /// Consumer minor version.
        consumer_minor: u16,
    },
    /// Major version mismatch (always incompatible).
    MajorMismatch {
        /// Producer major version.
        producer_major: u16,
        /// Consumer major version.
        consumer_major: u16,
    },
    /// Same major, but consumer is too old for producer minor.
    ConsumerTooOld {
        /// Producer minor version.
        producer_minor: u16,
        /// Consumer minor version.
        consumer_minor: u16,
    },
}

impl WasmAbiCompatibilityDecision {
    /// Returns `true` when the decision is compatible.
    #[must_use]
    pub const fn is_compatible(self) -> bool {
        matches!(self, Self::Exact | Self::BackwardCompatible { .. })
    }

    /// Stable, machine-readable decision name for structured logs.
    #[must_use]
    pub const fn decision_name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::BackwardCompatible { .. } => "backward_compatible",
            Self::MajorMismatch { .. } => "major_mismatch",
            Self::ConsumerTooOld { .. } => "consumer_too_old",
        }
    }
}

/// Classify compatibility between a producer ABI and consumer ABI.
///
/// Rules:
/// - Major mismatch => incompatible
/// - Same major + consumer minor < producer minor => incompatible
/// - Same major + equal minor => exact
/// - Same major + consumer minor > producer minor => backward compatible
#[must_use]
pub const fn classify_wasm_abi_compatibility(
    producer: WasmAbiVersion,
    consumer: WasmAbiVersion,
) -> WasmAbiCompatibilityDecision {
    if producer.major != consumer.major {
        return WasmAbiCompatibilityDecision::MajorMismatch {
            producer_major: producer.major,
            consumer_major: consumer.major,
        };
    }
    if consumer.minor < producer.minor {
        return WasmAbiCompatibilityDecision::ConsumerTooOld {
            producer_minor: producer.minor,
            consumer_minor: consumer.minor,
        };
    }
    if consumer.minor == producer.minor {
        WasmAbiCompatibilityDecision::Exact
    } else {
        WasmAbiCompatibilityDecision::BackwardCompatible {
            producer_minor: producer.minor,
            consumer_minor: consumer.minor,
        }
    }
}

/// ABI change class used to decide required version bump policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiChangeClass {
    /// Additive field in existing payload shape.
    AdditiveField,
    /// Additive symbol/function with no behavior change to existing symbols.
    AdditiveSymbol,
    /// Tightening validation or preconditions with same wire format.
    BehavioralTightening,
    /// Relaxing behavior with same wire format.
    BehavioralRelaxation,
    /// Removing/renaming existing symbol.
    SymbolRemoval,
    /// Changing wire layout/encoding of existing payload.
    ValueEncodingChange,
    /// Reinterpreting outcome/error semantics.
    OutcomeSemanticChange,
    /// Reinterpreting cancellation semantics.
    CancellationSemanticChange,
}

/// Required semantic version bump for a change class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiVersionBump {
    /// No version bump required.
    None,
    /// Minor bump required.
    Minor,
    /// Major bump required.
    Major,
}

/// Computes the required semantic version bump for a given ABI change class.
#[must_use]
pub const fn required_wasm_abi_bump(change: WasmAbiChangeClass) -> WasmAbiVersionBump {
    match change {
        WasmAbiChangeClass::AdditiveField
        | WasmAbiChangeClass::AdditiveSymbol
        | WasmAbiChangeClass::BehavioralRelaxation => WasmAbiVersionBump::Minor,
        WasmAbiChangeClass::BehavioralTightening
        | WasmAbiChangeClass::SymbolRemoval
        | WasmAbiChangeClass::ValueEncodingChange
        | WasmAbiChangeClass::OutcomeSemanticChange
        | WasmAbiChangeClass::CancellationSemanticChange => WasmAbiVersionBump::Major,
    }
}

/// Stable boundary symbols exported by the WASM adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiSymbol {
    RuntimeCreate,
    RuntimeClose,
    ScopeEnter,
    ScopeClose,
    TaskSpawn,
    TaskJoin,
    TaskCancel,
    FetchRequest,
}

impl WasmAbiSymbol {
    /// Stable symbol name used in diagnostics and JS package tables.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeCreate => "runtime_create",
            Self::RuntimeClose => "runtime_close",
            Self::ScopeEnter => "scope_enter",
            Self::ScopeClose => "scope_close",
            Self::TaskSpawn => "task_spawn",
            Self::TaskJoin => "task_join",
            Self::TaskCancel => "task_cancel",
            Self::FetchRequest => "fetch_request",
        }
    }
}

/// Boundary payload shape classes (wire-format contracts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiPayloadShape {
    Empty,
    HandleRefV1,
    ScopeEnterRequestV1,
    SpawnRequestV1,
    CancelRequestV1,
    FetchRequestV1,
    OutcomeEnvelopeV1,
}

/// Contract signature tuple for one ABI symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmAbiSignature {
    /// Stable symbol.
    pub symbol: WasmAbiSymbol,
    /// Request payload shape.
    pub request: WasmAbiPayloadShape,
    /// Response payload shape.
    pub response: WasmAbiPayloadShape,
}

/// Canonical symbol set for ABI v1.
pub const WASM_ABI_SIGNATURES_V1: [WasmAbiSignature; 8] = [
    WasmAbiSignature {
        symbol: WasmAbiSymbol::RuntimeCreate,
        request: WasmAbiPayloadShape::Empty,
        response: WasmAbiPayloadShape::HandleRefV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::RuntimeClose,
        request: WasmAbiPayloadShape::HandleRefV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::ScopeEnter,
        request: WasmAbiPayloadShape::ScopeEnterRequestV1,
        response: WasmAbiPayloadShape::HandleRefV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::ScopeClose,
        request: WasmAbiPayloadShape::HandleRefV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::TaskSpawn,
        request: WasmAbiPayloadShape::SpawnRequestV1,
        response: WasmAbiPayloadShape::HandleRefV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::TaskJoin,
        request: WasmAbiPayloadShape::HandleRefV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::TaskCancel,
        request: WasmAbiPayloadShape::CancelRequestV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::FetchRequest,
        request: WasmAbiPayloadShape::FetchRequestV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
];

/// Computes a deterministic fingerprint for a signature set.
///
/// The fingerprint is used by CI checks to detect contract drift.
#[must_use]
pub fn wasm_abi_signature_fingerprint(signatures: &[WasmAbiSignature]) -> u64 {
    let mut hasher = DetHasher::default();
    for signature in signatures {
        signature.hash(&mut hasher);
    }
    hasher.finish()
}

/// Encoded handle reference crossing JS <-> WASM boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmHandleRef {
    /// Logical handle class.
    pub kind: WasmHandleKind,
    /// Stable slot/index.
    pub slot: u32,
    /// Generation counter for stale-handle rejection.
    pub generation: u32,
}

/// Handle classes surfaced by the wasm boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmHandleKind {
    Runtime,
    Region,
    Task,
    CancelToken,
    FetchRequest,
}

/// JS/WASM wire value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WasmAbiValue {
    Unit,
    Bool(bool),
    I64(i64),
    U64(u64),
    String(String),
    Bytes(Vec<u8>),
    Handle(WasmHandleRef),
}

/// Error code classes for boundary failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiErrorCode {
    CapabilityDenied,
    InvalidHandle,
    DecodeFailure,
    CompatibilityRejected,
    InternalFailure,
}

/// Recoverability class for boundary failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbiRecoverability {
    Transient,
    Permanent,
    Unknown,
}

/// Encoded boundary failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmAbiFailure {
    /// Stable code for programmatic handling.
    pub code: WasmAbiErrorCode,
    /// Retry classification.
    pub recoverability: WasmAbiRecoverability,
    /// Human-readable context.
    pub message: String,
}

/// Encoded cancellation payload for boundary transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmAbiCancellation {
    /// Cancellation kind.
    pub kind: String,
    /// Cancellation phase at boundary observation point.
    pub phase: String,
    /// Origin region identifier (display-safe string form).
    pub origin_region: String,
    /// Optional origin task identifier.
    pub origin_task: Option<String>,
    /// Timestamp captured in abstract runtime nanoseconds.
    pub timestamp_nanos: u64,
    /// Optional operator message.
    pub message: Option<String>,
    /// Whether attribution chain was truncated.
    pub truncated: bool,
}

impl WasmAbiCancellation {
    /// Builds a boundary cancellation payload from core cancellation state.
    pub fn from_reason(reason: &CancelReason, phase: CancelPhase) -> Self {
        Self {
            kind: format!("{:?}", reason.kind()).to_lowercase(),
            phase: format!("{phase:?}").to_lowercase(),
            origin_region: reason.origin_region().to_string(),
            origin_task: reason.origin_task().map(|task| task.to_string()),
            timestamp_nanos: reason.timestamp().as_nanos(),
            message: reason.message().map(std::string::ToString::to_string),
            truncated: reason.any_truncated(),
        }
    }
}

/// Cancellation propagation policy between runtime cancel tokens and browser
/// `AbortSignal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmAbortPropagationMode {
    /// Runtime cancellation updates JS `AbortSignal`; JS abort does not
    /// request runtime cancellation.
    RuntimeToAbortSignal,
    /// JS `AbortSignal` requests runtime cancellation; runtime cancellation
    /// does not update JS abort state.
    AbortSignalToRuntime,
    /// Propagate cancellation in both directions.
    Bidirectional,
}

impl WasmAbortPropagationMode {
    /// Returns true when runtime cancellation should propagate to JS
    /// `AbortSignal`.
    #[must_use]
    pub const fn propagates_runtime_to_abort_signal(self) -> bool {
        matches!(self, Self::RuntimeToAbortSignal | Self::Bidirectional)
    }

    /// Returns true when JS `AbortSignal` abort should request runtime
    /// cancellation.
    #[must_use]
    pub const fn propagates_abort_signal_to_runtime(self) -> bool {
        matches!(self, Self::AbortSignalToRuntime | Self::Bidirectional)
    }
}

/// Snapshot of boundary state used when applying cancel/abort interop rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmAbortInteropSnapshot {
    /// Interop propagation mode.
    pub mode: WasmAbortPropagationMode,
    /// Current boundary lifecycle state.
    pub boundary_state: WasmBoundaryState,
    /// Whether the browser abort signal is already in aborted state.
    pub abort_signal_aborted: bool,
}

/// Deterministic interop update result for one cancel/abort step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmAbortInteropUpdate {
    /// Next boundary state after applying the interop rule.
    pub next_boundary_state: WasmBoundaryState,
    /// Updated browser abort state.
    pub abort_signal_aborted: bool,
    /// Whether a JS abort event was propagated to runtime cancellation.
    pub propagated_to_runtime: bool,
    /// Whether a runtime cancellation phase was propagated to JS abort state.
    pub propagated_to_abort_signal: bool,
}

/// Maps runtime cancellation phase to boundary-state intent.
#[must_use]
pub const fn wasm_boundary_state_for_cancel_phase(phase: CancelPhase) -> WasmBoundaryState {
    match phase {
        CancelPhase::Requested | CancelPhase::Cancelling => WasmBoundaryState::Cancelling,
        CancelPhase::Finalizing => WasmBoundaryState::Draining,
        CancelPhase::Completed => WasmBoundaryState::Closed,
    }
}

/// Applies a JS `AbortSignal` abort event to boundary state.
///
/// This helper is deterministic and idempotent:
/// - If abort is already observed, no additional runtime propagation occurs.
/// - When propagation is enabled, active work transitions to cancelling.
/// - Bound-but-not-active handles close immediately on JS abort.
#[must_use]
pub fn apply_abort_signal_event(snapshot: WasmAbortInteropSnapshot) -> WasmAbortInteropUpdate {
    let propagated_to_runtime = snapshot.mode.propagates_abort_signal_to_runtime()
        && !snapshot.abort_signal_aborted
        && matches!(
            snapshot.boundary_state,
            WasmBoundaryState::Bound | WasmBoundaryState::Active
        );

    let next_boundary_state = if propagated_to_runtime {
        match snapshot.boundary_state {
            WasmBoundaryState::Bound => WasmBoundaryState::Closed,
            WasmBoundaryState::Active => WasmBoundaryState::Cancelling,
            state => state,
        }
    } else {
        snapshot.boundary_state
    };

    WasmAbortInteropUpdate {
        next_boundary_state,
        abort_signal_aborted: true,
        propagated_to_runtime,
        propagated_to_abort_signal: false,
    }
}

/// Applies a runtime cancellation phase event to boundary + abort state.
///
/// Runtime cancel protocol (`requested -> cancelling -> finalizing -> completed`)
/// is mapped to boundary state transitions with monotonic progression when legal.
#[must_use]
pub fn apply_runtime_cancel_phase_event(
    snapshot: WasmAbortInteropSnapshot,
    phase: CancelPhase,
) -> WasmAbortInteropUpdate {
    let target_state = wasm_boundary_state_for_cancel_phase(phase);
    let next_boundary_state = if snapshot.boundary_state == target_state
        || is_valid_wasm_boundary_transition(snapshot.boundary_state, target_state)
    {
        target_state
    } else {
        snapshot.boundary_state
    };

    let should_abort = snapshot.mode.propagates_runtime_to_abort_signal()
        && !snapshot.abort_signal_aborted
        && matches!(
            phase,
            CancelPhase::Requested
                | CancelPhase::Cancelling
                | CancelPhase::Finalizing
                | CancelPhase::Completed
        );

    let abort_signal_aborted = snapshot.abort_signal_aborted
        || (snapshot.mode.propagates_runtime_to_abort_signal()
            && matches!(
                phase,
                CancelPhase::Requested
                    | CancelPhase::Cancelling
                    | CancelPhase::Finalizing
                    | CancelPhase::Completed
            ));

    WasmAbortInteropUpdate {
        next_boundary_state,
        abort_signal_aborted,
        propagated_to_runtime: false,
        propagated_to_abort_signal: should_abort,
    }
}

/// Encoded outcome envelope for boundary transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WasmAbiOutcomeEnvelope {
    /// Successful result.
    Ok { value: WasmAbiValue },
    /// Domain/runtime failure.
    Err { failure: WasmAbiFailure },
    /// Cancellation protocol result.
    Cancelled { cancellation: WasmAbiCancellation },
    /// Panic surfaced from boundary task.
    Panicked { message: String },
}

impl WasmAbiOutcomeEnvelope {
    /// Converts a typed runtime outcome to the boundary envelope.
    #[must_use]
    pub fn from_outcome(outcome: Outcome<WasmAbiValue, WasmAbiFailure>) -> Self {
        match outcome {
            Outcome::Ok(value) => Self::Ok { value },
            Outcome::Err(failure) => Self::Err { failure },
            Outcome::Cancelled(reason) => Self::Cancelled {
                cancellation: WasmAbiCancellation::from_reason(&reason, CancelPhase::Completed),
            },
            Outcome::Panicked(payload) => Self::Panicked {
                message: payload.message().to_string(),
            },
        }
    }
}

/// Ownership/boundary state for JS-visible handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(rename_all = "snake_case")]
pub enum WasmBoundaryState {
    Unbound,
    Bound,
    Active,
    Cancelling,
    Draining,
    Closed,
}

/// Error emitted when a boundary state transition violates contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WasmBoundaryTransitionError {
    /// Transition was not legal under contract.
    #[error("invalid wasm boundary transition: {from:?} -> {to:?}")]
    Invalid {
        /// Current state.
        from: WasmBoundaryState,
        /// Requested next state.
        to: WasmBoundaryState,
    },
}

/// Returns true when a state transition is legal.
#[must_use]
pub fn is_valid_wasm_boundary_transition(from: WasmBoundaryState, to: WasmBoundaryState) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (WasmBoundaryState::Unbound, WasmBoundaryState::Bound)
            | (
                WasmBoundaryState::Bound,
                WasmBoundaryState::Active | WasmBoundaryState::Closed
            )
            | (
                WasmBoundaryState::Active,
                WasmBoundaryState::Cancelling
                    | WasmBoundaryState::Draining
                    | WasmBoundaryState::Closed
            )
            | (
                WasmBoundaryState::Cancelling,
                WasmBoundaryState::Draining | WasmBoundaryState::Closed
            )
            | (WasmBoundaryState::Draining, WasmBoundaryState::Closed)
    )
}

/// Validates a state transition against contract rules.
pub fn validate_wasm_boundary_transition(
    from: WasmBoundaryState,
    to: WasmBoundaryState,
) -> Result<(), WasmBoundaryTransitionError> {
    if is_valid_wasm_boundary_transition(from, to) {
        Ok(())
    } else {
        Err(WasmBoundaryTransitionError::Invalid { from, to })
    }
}

/// Structured boundary-event payload for deterministic observability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmAbiBoundaryEvent {
    /// ABI version used by producer.
    pub abi_version: WasmAbiVersion,
    /// Called boundary symbol.
    pub symbol: WasmAbiSymbol,
    /// Payload schema used by this event.
    pub payload_shape: WasmAbiPayloadShape,
    /// Boundary state before call.
    pub state_from: WasmBoundaryState,
    /// Boundary state after call.
    pub state_to: WasmBoundaryState,
    /// Compatibility result for this call path.
    pub compatibility: WasmAbiCompatibilityDecision,
}

impl WasmAbiBoundaryEvent {
    /// Converts this event to stable key/value log fields.
    #[must_use]
    pub fn as_log_fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("abi_version", self.abi_version.to_string());
        fields.insert("symbol", self.symbol.as_str().to_string());
        fields.insert(
            "payload_shape",
            format!("{:?}", self.payload_shape).to_lowercase(),
        );
        fields.insert(
            "state_from",
            format!("{:?}", self.state_from).to_lowercase(),
        );
        fields.insert("state_to", format!("{:?}", self.state_to).to_lowercase());
        fields.insert(
            "compatibility",
            self.compatibility.decision_name().to_string(),
        );
        fields.insert(
            "compatibility_decision",
            self.compatibility.decision_name().to_string(),
        );
        fields.insert(
            "compatibility_compatible",
            self.compatibility.is_compatible().to_string(),
        );
        match self.compatibility {
            WasmAbiCompatibilityDecision::Exact => {
                fields.insert(
                    "compatibility_producer_major",
                    self.abi_version.major.to_string(),
                );
                fields.insert(
                    "compatibility_consumer_major",
                    self.abi_version.major.to_string(),
                );
                fields.insert(
                    "compatibility_producer_minor",
                    self.abi_version.minor.to_string(),
                );
                fields.insert(
                    "compatibility_consumer_minor",
                    self.abi_version.minor.to_string(),
                );
            }
            WasmAbiCompatibilityDecision::BackwardCompatible {
                producer_minor,
                consumer_minor,
            }
            | WasmAbiCompatibilityDecision::ConsumerTooOld {
                producer_minor,
                consumer_minor,
            } => {
                fields.insert(
                    "compatibility_producer_major",
                    self.abi_version.major.to_string(),
                );
                fields.insert(
                    "compatibility_consumer_major",
                    self.abi_version.major.to_string(),
                );
                fields.insert("compatibility_producer_minor", producer_minor.to_string());
                fields.insert("compatibility_consumer_minor", consumer_minor.to_string());
            }
            WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major,
                consumer_major,
            } => {
                fields.insert("compatibility_producer_major", producer_major.to_string());
                fields.insert("compatibility_consumer_major", consumer_major.to_string());
            }
        }
        fields
    }
}

// ---------------------------------------------------------------------------
// Memory Ownership Protocol
// ---------------------------------------------------------------------------
//
// The WASM boundary uses a strict ownership model:
//
// 1. **No shared memory**: All values crossing JS<->WASM are serialized.
//    There are no raw pointers, `Arc`s, or shared buffers.
//
// 2. **Handle ownership**: WASM owns all entities. JS receives opaque
//    `WasmHandleRef` tokens (slot + generation) that reference WASM-side
//    state. JS cannot inspect or mutate the underlying entity.
//
// 3. **Pinning**: While a handle is in `Active` or `Cancelling` state,
//    the WASM-side entity is pinned and must not be deallocated.
//
// 4. **Release protocol**: JS must explicitly close/release handles.
//    Leaked handles are detected by the `WasmHandleTable` diagnostics.
//
// 5. **Generation counters**: Prevent use-after-free by invalidating stale
//    handles after slot reuse.
//
// Ownership invariants:
//   - `WasmOwned` + `Active` = WASM entity is live, JS holds reference
//   - `WasmOwned` + `Closed` = WASM may reclaim slot after JS releases
//   - `TransferredToJs` = ownership moved to JS (e.g., detached buffer)
//   - `Released` = handle is dead; any access returns `InvalidHandle`

/// Ownership side for a boundary handle.
///
/// Tracks which side of the JS<->WASM boundary currently owns the
/// entity's lifetime. Most handles remain `WasmOwned` throughout their
/// lifecycle; `TransferredToJs` is reserved for detached buffer patterns
/// where JS takes full ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmHandleOwnership {
    /// WASM runtime owns the entity; JS holds an opaque reference.
    WasmOwned,
    /// Ownership transferred to JS (e.g., detached `ArrayBuffer`).
    /// WASM must not access the underlying data after transfer.
    TransferredToJs,
    /// Handle has been released; any access is use-after-free.
    Released,
}

/// Entry in the handle table tracking one boundary-visible entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHandleEntry {
    /// Handle reference visible to JS.
    pub handle: WasmHandleRef,
    /// Parent handle that owns this handle's lifetime, if any.
    pub parent: Option<WasmHandleRef>,
    /// Current boundary lifecycle state.
    pub state: WasmBoundaryState,
    /// Ownership side.
    pub ownership: WasmHandleOwnership,
    /// Whether the entity is pinned against deallocation.
    ///
    /// Pinned entities cannot be reclaimed by WASM even if the boundary
    /// state reaches `Closed`. The pin must be explicitly dropped before
    /// the slot can be recycled.
    pub pinned: bool,
}

/// Error when a handle operation violates ownership protocol.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WasmHandleError {
    /// Handle slot does not exist in the table.
    #[error("handle slot {slot} out of range (table size {table_size})")]
    SlotOutOfRange {
        /// Requested slot.
        slot: u32,
        /// Current table capacity.
        table_size: u32,
    },
    /// Handle generation does not match (stale handle / use-after-free).
    #[error("stale handle: slot {slot} generation {expected} != {actual}")]
    StaleGeneration {
        /// Slot index.
        slot: u32,
        /// Expected generation at the slot.
        expected: u32,
        /// Generation in the provided handle.
        actual: u32,
    },
    /// Handle has already been released.
    #[error("handle slot {slot} already released")]
    AlreadyReleased {
        /// Slot index.
        slot: u32,
    },
    /// Cannot transfer ownership of a handle that is not `WasmOwned`.
    #[error("cannot transfer handle slot {slot}: current ownership is {current:?}")]
    InvalidTransfer {
        /// Slot index.
        slot: u32,
        /// Current ownership state.
        current: WasmHandleOwnership,
    },
    /// Cannot unpin a handle that is not pinned.
    #[error("handle slot {slot} is not pinned")]
    NotPinned {
        /// Slot index.
        slot: u32,
    },
    /// Cannot release a pinned handle without unpinning first.
    #[error("handle slot {slot} is pinned; unpin before releasing")]
    ReleasePinned {
        /// Slot index.
        slot: u32,
    },
    /// Cannot release a handle before its boundary lifecycle is closed.
    #[error("handle slot {slot} is still {state:?}; close before releasing")]
    ReleaseBeforeClosed {
        /// Slot index.
        slot: u32,
        /// Current boundary state.
        state: WasmBoundaryState,
    },
    /// Cannot release a handle while it still owns live descendants.
    #[error(
        "handle slot {slot} still has {live_descendants} live descendant(s); release children first"
    )]
    ReleaseWithLiveDescendants {
        /// Slot index.
        slot: u32,
        /// Number of non-released descendants still attached to this handle.
        live_descendants: usize,
    },
    /// Boundary state transition was not legal under contract.
    #[error("invalid state transition for slot {slot}: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Slot index.
        slot: u32,
        /// Current boundary state.
        from: WasmBoundaryState,
        /// Requested boundary state.
        to: WasmBoundaryState,
    },
}

/// Handle table managing all boundary-visible entity handles.
///
/// Implements slot-based allocation with generation counters for
/// use-after-free prevention. All operations are deterministic
/// (no randomness, no time-dependence).
///
/// # Capacity
///
/// Grows dynamically. Free slots are recycled LIFO for cache locality.
///
/// # Thread Safety
///
/// This type is `!Sync` — boundary calls are serialized through the
/// WASM event loop (single-threaded by spec). If multi-threaded WASM
/// is added later, wrap in the runtime's `ContendedMutex`.
#[derive(Debug)]
pub struct WasmHandleTable {
    /// Slot storage. `None` means the slot is free.
    slots: Vec<Option<WasmHandleEntry>>,
    /// Generation counter per slot. Incremented on each release.
    generations: Vec<u32>,
    /// Free slot indices (LIFO stack).
    free_list: Vec<u32>,
    /// Count of live (non-released) handles.
    live_count: usize,
}

impl Default for WasmHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmHandleTable {
    /// Creates an empty handle table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            generations: Vec::new(),
            free_list: Vec::new(),
            live_count: 0,
        }
    }

    /// Creates a table with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            generations: Vec::with_capacity(capacity),
            free_list: Vec::new(),
            live_count: 0,
        }
    }

    /// Allocates a new handle for an entity.
    ///
    /// Returns a `WasmHandleRef` that JS can use as an opaque token.
    /// The handle starts in `Unbound` state with `WasmOwned` ownership.
    pub fn allocate(&mut self, kind: WasmHandleKind) -> WasmHandleRef {
        self.allocate_with_parent(kind, None)
    }

    /// Allocates a new handle with an explicit parent owner.
    pub fn allocate_with_parent(
        &mut self,
        kind: WasmHandleKind,
        parent: Option<WasmHandleRef>,
    ) -> WasmHandleRef {
        let slot = if let Some(recycled) = self.free_list.pop() {
            recycled
        } else {
            let slot = u32::try_from(self.slots.len()).expect("handle table overflow");
            self.slots.push(None);
            self.generations.push(0);
            slot
        };

        let generation = self.generations[slot as usize];
        let handle = WasmHandleRef {
            kind,
            slot,
            generation,
        };

        self.slots[slot as usize] = Some(WasmHandleEntry {
            handle,
            parent,
            state: WasmBoundaryState::Unbound,
            ownership: WasmHandleOwnership::WasmOwned,
            pinned: false,
        });
        self.live_count += 1;

        handle
    }

    /// Returns owned descendants in deterministic post-order.
    #[must_use]
    pub fn descendants_postorder(&self, root: &WasmHandleRef) -> Vec<WasmHandleRef> {
        fn visit(
            table: &WasmHandleTable,
            parent: WasmHandleRef,
            descendants: &mut Vec<WasmHandleRef>,
        ) {
            for entry in table.slots.iter().flatten() {
                if entry.parent == Some(parent) && entry.ownership != WasmHandleOwnership::Released
                {
                    visit(table, entry.handle, descendants);
                    descendants.push(entry.handle);
                }
            }
        }

        let mut descendants = Vec::new();
        visit(self, *root, &mut descendants);
        descendants
    }

    /// Looks up an entry by handle, validating generation.
    pub fn get(&self, handle: &WasmHandleRef) -> Result<&WasmHandleEntry, WasmHandleError> {
        let slot = handle.slot as usize;
        if slot >= self.slots.len() {
            return Err(WasmHandleError::SlotOutOfRange {
                slot: handle.slot,
                table_size: u32::try_from(self.slots.len()).unwrap_or(u32::MAX),
            });
        }
        let current_gen = self.generations[slot];
        if handle.generation != current_gen {
            return Err(WasmHandleError::StaleGeneration {
                slot: handle.slot,
                expected: current_gen,
                actual: handle.generation,
            });
        }
        self.slots[slot].as_ref().map_or(
            Err(WasmHandleError::AlreadyReleased { slot: handle.slot }),
            |entry| {
                if entry.ownership == WasmHandleOwnership::Released {
                    Err(WasmHandleError::AlreadyReleased { slot: handle.slot })
                } else {
                    Ok(entry)
                }
            },
        )
    }

    /// Looks up a mutable entry by handle, validating generation.
    pub fn get_mut(
        &mut self,
        handle: &WasmHandleRef,
    ) -> Result<&mut WasmHandleEntry, WasmHandleError> {
        let slot = handle.slot as usize;
        if slot >= self.slots.len() {
            return Err(WasmHandleError::SlotOutOfRange {
                slot: handle.slot,
                table_size: u32::try_from(self.slots.len()).unwrap_or(u32::MAX),
            });
        }
        let current_gen = self.generations[slot];
        if handle.generation != current_gen {
            return Err(WasmHandleError::StaleGeneration {
                slot: handle.slot,
                expected: current_gen,
                actual: handle.generation,
            });
        }
        self.slots[slot].as_mut().map_or(
            Err(WasmHandleError::AlreadyReleased { slot: handle.slot }),
            |entry| {
                if entry.ownership == WasmHandleOwnership::Released {
                    Err(WasmHandleError::AlreadyReleased { slot: handle.slot })
                } else {
                    Ok(entry)
                }
            },
        )
    }

    /// Advances the boundary state of a handle.
    ///
    /// Validates that the transition is legal per the boundary state machine.
    pub fn transition(
        &mut self,
        handle: &WasmHandleRef,
        to: WasmBoundaryState,
    ) -> Result<(), WasmHandleError> {
        let entry = self.get_mut(handle)?;
        let from = entry.state;
        validate_wasm_boundary_transition(from, to).map_err(|_| {
            WasmHandleError::InvalidStateTransition {
                slot: handle.slot,
                from,
                to,
            }
        })?;
        // Re-borrow after validation
        let entry = self.slots[handle.slot as usize]
            .as_mut()
            .expect("slot must be populated to be mutated");
        entry.state = to;
        Ok(())
    }

    /// Pins a handle, preventing WASM-side deallocation.
    ///
    /// Pinning is idempotent: pinning an already-pinned handle is a no-op.
    pub fn pin(&mut self, handle: &WasmHandleRef) -> Result<(), WasmHandleError> {
        let entry = self.get_mut(handle)?;
        entry.pinned = true;
        Ok(())
    }

    /// Unpins a handle, allowing future deallocation.
    pub fn unpin(&mut self, handle: &WasmHandleRef) -> Result<(), WasmHandleError> {
        let entry = self.get_mut(handle)?;
        if !entry.pinned {
            return Err(WasmHandleError::NotPinned { slot: handle.slot });
        }
        entry.pinned = false;
        Ok(())
    }

    /// Transfers ownership of a handle's underlying data to JS.
    ///
    /// After transfer, WASM must not access the data. The handle remains
    /// in the table for bookkeeping but cannot be used for WASM-side ops.
    pub fn transfer_to_js(&mut self, handle: &WasmHandleRef) -> Result<(), WasmHandleError> {
        let entry = self.get_mut(handle)?;
        if entry.ownership != WasmHandleOwnership::WasmOwned {
            return Err(WasmHandleError::InvalidTransfer {
                slot: handle.slot,
                current: entry.ownership,
            });
        }
        entry.ownership = WasmHandleOwnership::TransferredToJs;
        Ok(())
    }

    /// Releases a handle, recycling the slot for future allocation.
    ///
    /// # Errors
    ///
    /// Returns `ReleasePinned` if the handle is still pinned.
    /// Returns `ReleaseBeforeClosed` if the boundary state is not `Closed`.
    /// Returns `ReleaseWithLiveDescendants` if any descendants are still live.
    /// Returns `AlreadyReleased` if the handle was previously released.
    pub fn release(&mut self, handle: &WasmHandleRef) -> Result<(), WasmHandleError> {
        let entry = self.get(handle)?;
        if entry.pinned {
            return Err(WasmHandleError::ReleasePinned { slot: handle.slot });
        }
        if entry.state != WasmBoundaryState::Closed {
            return Err(WasmHandleError::ReleaseBeforeClosed {
                slot: handle.slot,
                state: entry.state,
            });
        }
        let live_descendants = self.descendants_postorder(handle).len();
        if live_descendants != 0 {
            return Err(WasmHandleError::ReleaseWithLiveDescendants {
                slot: handle.slot,
                live_descendants,
            });
        }
        let entry = self.get_mut(handle)?;
        entry.ownership = WasmHandleOwnership::Released;
        self.slots[handle.slot as usize] = None;
        self.generations[handle.slot as usize] =
            self.generations[handle.slot as usize].wrapping_add(1);
        self.free_list.push(handle.slot);
        self.live_count -= 1;
        Ok(())
    }

    /// Number of live (non-released) handles.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live_count
    }

    /// Total allocated capacity (including free slots).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Generates a memory report for diagnostics and leak detection.
    #[must_use]
    pub fn memory_report(&self) -> WasmMemoryReport {
        let mut by_kind = BTreeMap::new();
        let mut by_state = BTreeMap::new();
        let mut pinned_count: usize = 0;

        for entry in self.slots.iter().flatten() {
            if entry.ownership != WasmHandleOwnership::Released {
                *by_kind
                    .entry(format!("{:?}", entry.handle.kind).to_lowercase())
                    .or_insert(0usize) += 1;
                *by_state
                    .entry(format!("{:?}", entry.state).to_lowercase())
                    .or_insert(0usize) += 1;
                if entry.pinned {
                    pinned_count += 1;
                }
            }
        }

        WasmMemoryReport {
            live_handles: self.live_count,
            capacity: self.slots.len(),
            free_slots: self.free_list.len(),
            pinned_count,
            by_kind,
            by_state,
        }
    }

    /// Returns handles that appear leaked: `Closed` state but not released.
    #[must_use]
    pub fn detect_leaks(&self) -> Vec<WasmHandleRef> {
        self.slots
            .iter()
            .flatten()
            .filter(|entry| {
                entry.state == WasmBoundaryState::Closed
                    && entry.ownership != WasmHandleOwnership::Released
            })
            .map(|entry| entry.handle)
            .collect()
    }
}

/// Diagnostic report for boundary memory state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMemoryReport {
    /// Number of live (non-released) handles.
    pub live_handles: usize,
    /// Total slot capacity.
    pub capacity: usize,
    /// Number of free slots available for recycling.
    pub free_slots: usize,
    /// Number of pinned handles.
    pub pinned_count: usize,
    /// Live handle counts by kind.
    pub by_kind: BTreeMap<String, usize>,
    /// Live handle counts by boundary state.
    pub by_state: BTreeMap<String, usize>,
}

/// Buffer transfer descriptor for large data crossing the boundary.
///
/// When passing `Bytes` payloads, this descriptor tracks the ownership
/// transfer semantics. For small payloads, copy semantics are used
/// (serialized in the value envelope). For large payloads, a zero-copy
/// transfer via `ArrayBuffer.transfer()` may be used if the runtime
/// supports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmBufferTransfer {
    /// Handle to the buffer's parent entity (e.g., the task that produced it).
    pub source_handle: WasmHandleRef,
    /// Byte length of the buffer.
    pub byte_length: u64,
    /// Transfer mode.
    pub mode: WasmBufferTransferMode,
}

/// How a buffer crosses the JS<->WASM boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmBufferTransferMode {
    /// Buffer is copied (serialized in the value envelope).
    /// Safe default; no ownership transfer.
    Copy,
    /// Buffer is transferred via `ArrayBuffer.transfer()`.
    /// Source loses access; receiver gets exclusive ownership.
    /// Only valid when source ownership is `WasmOwned`.
    Transfer,
}

impl WasmBufferTransferMode {
    /// Returns true if the buffer is copied (no ownership change).
    #[must_use]
    pub const fn is_copy(self) -> bool {
        matches!(self, Self::Copy)
    }
}

/// Structured event emitted during handle lifecycle for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHandleLifecycleEvent {
    /// The handle involved.
    pub handle: WasmHandleRef,
    /// Event kind.
    pub event: WasmHandleEventKind,
    /// Ownership before the event.
    pub ownership_before: WasmHandleOwnership,
    /// Ownership after the event.
    pub ownership_after: WasmHandleOwnership,
    /// Boundary state before the event.
    pub state_before: WasmBoundaryState,
    /// Boundary state after the event.
    pub state_after: WasmBoundaryState,
}

/// Handle lifecycle event kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmHandleEventKind {
    /// Handle was allocated.
    Allocated,
    /// Handle boundary state was advanced.
    StateTransition,
    /// Handle was pinned.
    Pinned,
    /// Handle was unpinned.
    Unpinned,
    /// Ownership was transferred to JS.
    TransferredToJs,
    /// Handle was released (slot recycled).
    Released,
}

// ---------------------------------------------------------------------------
// Export Dispatch Layer
// ---------------------------------------------------------------------------
//
// Implements the concrete wasm-bindgen export boundary. Each of the 8
// `WasmAbiSymbol` operations maps to a dispatcher method that:
//
// 1. Validates ABI compatibility.
// 2. Validates/decodes the request payload.
// 3. Manages handle table state transitions.
// 4. Emits structured boundary events for observability.
// 5. Returns a typed `WasmAbiOutcomeEnvelope` (or `WasmHandleRef`).
//
// The dispatcher is single-threaded (WASM event loop) and owns all
// boundary state. No runtime coupling — the dispatcher delegates
// actual work via callback traits injected by the runtime adapter.

/// Request payload for `ScopeEnter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmScopeEnterRequest {
    /// Parent runtime or region handle.
    pub parent: WasmHandleRef,
    /// Optional human-readable label for diagnostics.
    pub label: Option<String>,
}

/// Request payload for `TaskSpawn`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmTaskSpawnRequest {
    /// Scope/region handle in which to spawn the task.
    pub scope: WasmHandleRef,
    /// Optional task label for diagnostics.
    pub label: Option<String>,
    /// Optional cancel kind to associate with the task.
    pub cancel_kind: Option<String>,
}

/// Request payload for `TaskCancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmTaskCancelRequest {
    /// Task handle to cancel.
    pub task: WasmHandleRef,
    /// Cancellation kind (maps to `CancelKind` variants).
    pub kind: String,
    /// Optional human-readable reason message.
    pub message: Option<String>,
}

/// Request payload for `FetchRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFetchRequest {
    /// Scope handle providing capability context.
    pub scope: WasmHandleRef,
    /// URL to fetch.
    pub url: String,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
}

/// Dispatch result for operations that return a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmExportResult {
    /// Operation produced a new handle (RuntimeCreate, ScopeEnter, TaskSpawn).
    Handle(WasmHandleRef),
    /// Operation produced an outcome envelope (Close, Join, Cancel, Fetch).
    Outcome(WasmAbiOutcomeEnvelope),
}

/// Error returned when a dispatch call fails at the boundary level
/// (before reaching the runtime).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WasmDispatchError {
    /// ABI version is not compatible.
    #[error("ABI incompatible: {decision:?}")]
    Incompatible {
        /// The compatibility decision that rejected the call.
        decision: WasmAbiCompatibilityDecision,
    },
    /// Handle validation failed.
    #[error("handle error: {0}")]
    Handle(#[from] WasmHandleError),
    /// Boundary state does not allow this operation.
    #[error("invalid boundary state {state:?} for symbol {symbol:?}")]
    InvalidState {
        /// Current boundary state.
        state: WasmBoundaryState,
        /// Attempted operation.
        symbol: WasmAbiSymbol,
    },
    /// Request payload failed validation.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// Explanation of the validation failure.
        reason: String,
    },
}

impl WasmDispatchError {
    /// Converts this dispatch error to a boundary failure envelope.
    #[must_use]
    pub fn to_failure(&self) -> WasmAbiFailure {
        match self {
            Self::Incompatible { .. } => WasmAbiFailure {
                code: WasmAbiErrorCode::CompatibilityRejected,
                recoverability: WasmAbiRecoverability::Permanent,
                message: self.to_string(),
            },
            Self::Handle(_) | Self::InvalidState { .. } => WasmAbiFailure {
                code: WasmAbiErrorCode::InvalidHandle,
                recoverability: WasmAbiRecoverability::Permanent,
                message: self.to_string(),
            },
            Self::InvalidRequest { .. } => WasmAbiFailure {
                code: WasmAbiErrorCode::DecodeFailure,
                recoverability: WasmAbiRecoverability::Permanent,
                message: self.to_string(),
            },
        }
    }

    /// Wraps this error as an `Err` outcome envelope.
    #[must_use]
    pub fn to_outcome(&self) -> WasmAbiOutcomeEnvelope {
        WasmAbiOutcomeEnvelope::Err {
            failure: self.to_failure(),
        }
    }
}

/// Boundary event collector for structured observability.
///
/// Collects `WasmAbiBoundaryEvent`s emitted during dispatch for
/// post-hoc analysis, deterministic replay, and diagnostics.
#[derive(Debug, Default)]
pub struct WasmBoundaryEventLog {
    events: Vec<WasmAbiBoundaryEvent>,
}

impl WasmBoundaryEventLog {
    /// Creates an empty event log.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Records a boundary event.
    pub fn record(&mut self, event: WasmAbiBoundaryEvent) {
        self.events.push(event);
    }

    /// Returns all recorded events.
    #[must_use]
    pub fn events(&self) -> &[WasmAbiBoundaryEvent] {
        &self.events
    }

    /// Drains all events, returning them.
    pub fn drain(&mut self) -> Vec<WasmAbiBoundaryEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Export dispatcher implementing the 8-symbol wasm boundary contract.
///
/// Owns the handle table, event log, and ABI version state. Each public
/// method corresponds to one `WasmAbiSymbol` and performs:
///
/// 1. ABI compatibility check (if consumer version provided).
/// 2. Handle validation and state transition.
/// 3. Boundary event emission.
/// 4. Result encoding.
///
/// # Single-threaded
///
/// WASM is single-threaded by spec. This dispatcher is `!Sync` and
/// must be called from the WASM event loop thread.
#[derive(Debug)]
pub struct WasmExportDispatcher {
    /// Handle table for all boundary-visible entities.
    handles: WasmHandleTable,
    /// Boundary event log for observability.
    event_log: WasmBoundaryEventLog,
    /// Producer ABI version (this WASM module).
    producer_version: WasmAbiVersion,
    /// Abort interop mode for cancel/abort bridging.
    abort_mode: WasmAbortPropagationMode,
    /// Total dispatch call counter (monotonic).
    dispatch_count: u64,
}

impl Default for WasmExportDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmExportDispatcher {
    /// Creates a new dispatcher with current ABI version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handles: WasmHandleTable::new(),
            event_log: WasmBoundaryEventLog::new(),
            producer_version: WasmAbiVersion::CURRENT,
            abort_mode: WasmAbortPropagationMode::Bidirectional,
            dispatch_count: 0,
        }
    }

    /// Creates a dispatcher with a specific abort propagation mode.
    #[must_use]
    pub fn with_abort_mode(mut self, mode: WasmAbortPropagationMode) -> Self {
        self.abort_mode = mode;
        self
    }

    /// Returns a reference to the handle table.
    #[must_use]
    pub fn handles(&self) -> &WasmHandleTable {
        &self.handles
    }

    /// Returns a mutable reference to the handle table.
    pub fn handles_mut(&mut self) -> &mut WasmHandleTable {
        &mut self.handles
    }

    /// Returns the boundary event log.
    #[must_use]
    pub fn event_log(&self) -> &WasmBoundaryEventLog {
        &self.event_log
    }

    /// Returns a mutable reference to the event log.
    pub fn event_log_mut(&mut self) -> &mut WasmBoundaryEventLog {
        &mut self.event_log
    }

    /// Total number of dispatch calls processed.
    #[must_use]
    pub fn dispatch_count(&self) -> u64 {
        self.dispatch_count
    }

    /// Validates ABI compatibility for an incoming call.
    fn check_compat(
        &self,
        consumer: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiCompatibilityDecision, WasmDispatchError> {
        let consumer = consumer.unwrap_or(self.producer_version);
        let decision = classify_wasm_abi_compatibility(self.producer_version, consumer);
        if decision.is_compatible() {
            Ok(decision)
        } else {
            Err(WasmDispatchError::Incompatible { decision })
        }
    }

    /// Emits a boundary event for a symbol invocation.
    fn emit_event(
        &mut self,
        symbol: WasmAbiSymbol,
        state_from: WasmBoundaryState,
        state_to: WasmBoundaryState,
        compatibility: WasmAbiCompatibilityDecision,
    ) {
        let sig = WASM_ABI_SIGNATURES_V1
            .iter()
            .find(|s| s.symbol == symbol)
            .expect("symbol not in signature table");

        self.event_log.record(WasmAbiBoundaryEvent {
            abi_version: self.producer_version,
            symbol,
            payload_shape: sig.request,
            state_from,
            state_to,
            compatibility,
        });
    }

    fn drain_and_release_handle(
        &mut self,
        handle: &WasmHandleRef,
    ) -> Result<WasmBoundaryState, WasmDispatchError> {
        let state_from = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?
            .state;

        for target in [
            WasmBoundaryState::Cancelling,
            WasmBoundaryState::Draining,
            WasmBoundaryState::Closed,
        ] {
            let current = self
                .handles
                .get(handle)
                .map_err(WasmDispatchError::Handle)?
                .state;
            if is_valid_wasm_boundary_transition(current, target) {
                self.handles
                    .transition(handle, target)
                    .map_err(WasmDispatchError::Handle)?;
            }
        }

        if self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?
            .pinned
        {
            self.handles
                .unpin(handle)
                .map_err(WasmDispatchError::Handle)?;
        }
        self.handles
            .release(handle)
            .map_err(WasmDispatchError::Handle)?;
        Ok(state_from)
    }

    fn close_handle_tree(
        &mut self,
        root: &WasmHandleRef,
    ) -> Result<WasmBoundaryState, WasmDispatchError> {
        let descendants = self.handles.descendants_postorder(root);
        for descendant in descendants {
            self.drain_and_release_handle(&descendant)?;
        }
        self.drain_and_release_handle(root)
    }

    // ----- Symbol implementations -----

    /// `RuntimeCreate`: allocates a new runtime handle.
    ///
    /// Creates a runtime handle, transitions it to `Bound`, and returns it.
    /// This is the entry point for JS code initializing the WASM runtime.
    pub fn runtime_create(
        &mut self,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;
        let handle = self.handles.allocate(WasmHandleKind::Runtime);
        self.handles
            .transition(&handle, WasmBoundaryState::Bound)
            .map_err(WasmDispatchError::Handle)?;
        self.handles
            .transition(&handle, WasmBoundaryState::Active)
            .map_err(WasmDispatchError::Handle)?;
        self.emit_event(
            WasmAbiSymbol::RuntimeCreate,
            WasmBoundaryState::Unbound,
            WasmBoundaryState::Active,
            compat,
        );
        Ok(handle)
    }

    /// `RuntimeClose`: closes a runtime handle and drains all children.
    ///
    /// Transitions the runtime handle through cancelling → draining → closed
    /// and releases it. Returns an outcome envelope.
    pub fn runtime_close(
        &mut self,
        handle: &WasmHandleRef,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;
        let entry = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?;

        if entry.handle.kind != WasmHandleKind::Runtime {
            return Err(WasmDispatchError::InvalidState {
                state: entry.state,
                symbol: WasmAbiSymbol::RuntimeClose,
            });
        }
        let state_from = self.close_handle_tree(handle)?;

        self.emit_event(
            WasmAbiSymbol::RuntimeClose,
            state_from,
            WasmBoundaryState::Closed,
            compat,
        );

        Ok(WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        })
    }

    /// `ScopeEnter`: creates a new scope/region under a parent handle.
    pub fn scope_enter(
        &mut self,
        request: &WasmScopeEnterRequest,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;

        // Validate parent handle exists and is active
        let parent_entry = self
            .handles
            .get(&request.parent)
            .map_err(WasmDispatchError::Handle)?;
        if parent_entry.state != WasmBoundaryState::Active {
            return Err(WasmDispatchError::InvalidState {
                state: parent_entry.state,
                symbol: WasmAbiSymbol::ScopeEnter,
            });
        }

        let handle = self
            .handles
            .allocate_with_parent(WasmHandleKind::Region, Some(request.parent));
        self.handles
            .transition(&handle, WasmBoundaryState::Bound)
            .map_err(WasmDispatchError::Handle)?;
        self.handles
            .transition(&handle, WasmBoundaryState::Active)
            .map_err(WasmDispatchError::Handle)?;
        self.emit_event(
            WasmAbiSymbol::ScopeEnter,
            WasmBoundaryState::Unbound,
            WasmBoundaryState::Active,
            compat,
        );
        Ok(handle)
    }

    /// `ScopeClose`: closes a scope/region handle.
    pub fn scope_close(
        &mut self,
        handle: &WasmHandleRef,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;
        let entry = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?;

        if entry.handle.kind != WasmHandleKind::Region {
            return Err(WasmDispatchError::InvalidState {
                state: entry.state,
                symbol: WasmAbiSymbol::ScopeClose,
            });
        }
        let state_from = self.close_handle_tree(handle)?;

        self.emit_event(
            WasmAbiSymbol::ScopeClose,
            state_from,
            WasmBoundaryState::Closed,
            compat,
        );
        Ok(WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        })
    }

    /// `TaskSpawn`: spawns a task within a scope.
    pub fn task_spawn(
        &mut self,
        request: &WasmTaskSpawnRequest,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;

        // Validate scope handle
        let scope_entry = self
            .handles
            .get(&request.scope)
            .map_err(WasmDispatchError::Handle)?;
        if scope_entry.state != WasmBoundaryState::Active {
            return Err(WasmDispatchError::InvalidState {
                state: scope_entry.state,
                symbol: WasmAbiSymbol::TaskSpawn,
            });
        }
        if scope_entry.handle.kind != WasmHandleKind::Region
            && scope_entry.handle.kind != WasmHandleKind::Runtime
        {
            return Err(WasmDispatchError::InvalidRequest {
                reason: format!(
                    "task_spawn requires Region or Runtime scope, got {:?}",
                    scope_entry.handle.kind
                ),
            });
        }

        let handle = self
            .handles
            .allocate_with_parent(WasmHandleKind::Task, Some(request.scope));
        self.handles
            .transition(&handle, WasmBoundaryState::Bound)
            .map_err(WasmDispatchError::Handle)?;
        self.handles
            .transition(&handle, WasmBoundaryState::Active)
            .map_err(WasmDispatchError::Handle)?;
        // Pin task handles during execution to prevent premature deallocation
        self.handles
            .pin(&handle)
            .map_err(WasmDispatchError::Handle)?;
        self.emit_event(
            WasmAbiSymbol::TaskSpawn,
            WasmBoundaryState::Unbound,
            WasmBoundaryState::Active,
            compat,
        );
        Ok(handle)
    }

    /// `TaskJoin`: waits for a task to complete and returns its outcome.
    pub fn task_join(
        &mut self,
        handle: &WasmHandleRef,
        outcome: WasmAbiOutcomeEnvelope,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;
        let entry = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?;

        if entry.handle.kind != WasmHandleKind::Task {
            return Err(WasmDispatchError::InvalidState {
                state: entry.state,
                symbol: WasmAbiSymbol::TaskJoin,
            });
        }
        let state_from = entry.state;

        // Drive to Closed
        for target in [WasmBoundaryState::Draining, WasmBoundaryState::Closed] {
            if is_valid_wasm_boundary_transition(
                self.handles
                    .get(handle)
                    .map_err(WasmDispatchError::Handle)?
                    .state,
                target,
            ) {
                self.handles
                    .transition(handle, target)
                    .map_err(WasmDispatchError::Handle)?;
            }
        }

        // Unpin and release
        if self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?
            .pinned
        {
            self.handles
                .unpin(handle)
                .map_err(WasmDispatchError::Handle)?;
        }
        self.handles
            .release(handle)
            .map_err(WasmDispatchError::Handle)?;

        self.emit_event(
            WasmAbiSymbol::TaskJoin,
            state_from,
            WasmBoundaryState::Closed,
            compat,
        );
        Ok(outcome)
    }

    /// `TaskCancel`: requests cancellation of a task.
    pub fn task_cancel(
        &mut self,
        request: &WasmTaskCancelRequest,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;
        let entry = self
            .handles
            .get(&request.task)
            .map_err(WasmDispatchError::Handle)?;

        if entry.handle.kind != WasmHandleKind::Task {
            return Err(WasmDispatchError::InvalidState {
                state: entry.state,
                symbol: WasmAbiSymbol::TaskCancel,
            });
        }
        let state_from = entry.state;

        // Only active tasks can be cancelled
        if state_from != WasmBoundaryState::Active {
            return Err(WasmDispatchError::InvalidState {
                state: state_from,
                symbol: WasmAbiSymbol::TaskCancel,
            });
        }

        self.handles
            .transition(&request.task, WasmBoundaryState::Cancelling)
            .map_err(WasmDispatchError::Handle)?;

        self.emit_event(
            WasmAbiSymbol::TaskCancel,
            state_from,
            WasmBoundaryState::Cancelling,
            compat,
        );

        Ok(WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit,
        })
    }

    /// `FetchRequest`: initiates a fetch operation within a scope.
    pub fn fetch_request(
        &mut self,
        request: &WasmFetchRequest,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        self.dispatch_count += 1;
        let compat = self.check_compat(consumer_version)?;

        // Validate scope handle
        let scope_entry = self
            .handles
            .get(&request.scope)
            .map_err(WasmDispatchError::Handle)?;
        if scope_entry.state != WasmBoundaryState::Active {
            return Err(WasmDispatchError::InvalidState {
                state: scope_entry.state,
                symbol: WasmAbiSymbol::FetchRequest,
            });
        }

        // Validate URL is non-empty
        if request.url.is_empty() {
            return Err(WasmDispatchError::InvalidRequest {
                reason: "fetch URL must not be empty".to_string(),
            });
        }

        let handle = self
            .handles
            .allocate_with_parent(WasmHandleKind::FetchRequest, Some(request.scope));
        self.handles
            .transition(&handle, WasmBoundaryState::Bound)
            .map_err(WasmDispatchError::Handle)?;
        self.handles
            .transition(&handle, WasmBoundaryState::Active)
            .map_err(WasmDispatchError::Handle)?;
        self.handles
            .pin(&handle)
            .map_err(WasmDispatchError::Handle)?;
        self.emit_event(
            WasmAbiSymbol::FetchRequest,
            WasmBoundaryState::Unbound,
            WasmBoundaryState::Active,
            compat,
        );
        Ok(handle)
    }

    /// Completes a fetch handle with an outcome, releasing it.
    ///
    /// This is called when the browser fetch resolves/rejects, delivering
    /// the result back through the boundary.
    pub fn fetch_complete(
        &mut self,
        handle: &WasmHandleRef,
        outcome: WasmAbiOutcomeEnvelope,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.dispatch_count += 1;
        let entry = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?;
        if entry.handle.kind != WasmHandleKind::FetchRequest {
            return Err(WasmDispatchError::InvalidState {
                state: entry.state,
                symbol: WasmAbiSymbol::FetchRequest,
            });
        }

        // Drive to closed
        for target in [WasmBoundaryState::Draining, WasmBoundaryState::Closed] {
            if is_valid_wasm_boundary_transition(
                self.handles
                    .get(handle)
                    .map_err(WasmDispatchError::Handle)?
                    .state,
                target,
            ) {
                self.handles
                    .transition(handle, target)
                    .map_err(WasmDispatchError::Handle)?;
            }
        }

        if self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?
            .pinned
        {
            self.handles
                .unpin(handle)
                .map_err(WasmDispatchError::Handle)?;
        }
        self.handles
            .release(handle)
            .map_err(WasmDispatchError::Handle)?;

        Ok(outcome)
    }

    /// Applies an abort signal event to a handle, propagating cancellation
    /// according to the configured abort interop mode.
    pub fn apply_abort(
        &mut self,
        handle: &WasmHandleRef,
    ) -> Result<WasmAbortInteropUpdate, WasmDispatchError> {
        let entry = self
            .handles
            .get(handle)
            .map_err(WasmDispatchError::Handle)?;
        let snapshot = WasmAbortInteropSnapshot {
            mode: self.abort_mode,
            boundary_state: entry.state,
            abort_signal_aborted: false,
        };
        let update = apply_abort_signal_event(snapshot);

        // Apply boundary state change if needed
        if update.next_boundary_state != entry.state {
            self.handles
                .transition(handle, update.next_boundary_state)
                .map_err(WasmDispatchError::Handle)?;
        }

        Ok(update)
    }
}

// ---------------------------------------------------------------------------
// High-Level Ergonomic API Facade
// ---------------------------------------------------------------------------
//
// These types reduce ceremony for common WASM boundary patterns while
// keeping lifecycle, cancellation, and ownership semantics fully explicit.
//
// Design principle: **thin wrappers, not hidden behavior**. Every facade
// method documents which lifecycle transitions it performs. The caller
// always sees state changes through return values.

/// Builder for `WasmScopeEnterRequest` — reduces boilerplate for scope creation.
///
/// ```ignore
/// let req = WasmScopeEnterBuilder::new(runtime_handle)
///     .label("data-fetch")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct WasmScopeEnterBuilder {
    parent: WasmHandleRef,
    label: Option<String>,
}

impl WasmScopeEnterBuilder {
    /// Start building a scope enter request.
    #[must_use]
    pub fn new(parent: WasmHandleRef) -> Self {
        Self {
            parent,
            label: None,
        }
    }

    /// Set a diagnostic label for the scope.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> WasmScopeEnterRequest {
        WasmScopeEnterRequest {
            parent: self.parent,
            label: self.label,
        }
    }
}

/// Builder for `WasmTaskSpawnRequest` — reduces boilerplate for task spawning.
///
/// ```ignore
/// let req = WasmTaskSpawnBuilder::new(scope_handle)
///     .label("background-sync")
///     .cancel_kind("timeout")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct WasmTaskSpawnBuilder {
    scope: WasmHandleRef,
    label: Option<String>,
    cancel_kind: Option<String>,
}

impl WasmTaskSpawnBuilder {
    /// Start building a task spawn request.
    #[must_use]
    pub fn new(scope: WasmHandleRef) -> Self {
        Self {
            scope,
            label: None,
            cancel_kind: None,
        }
    }

    /// Set a diagnostic label for the task.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the cancel kind to associate with the task.
    #[must_use]
    pub fn cancel_kind(mut self, kind: impl Into<String>) -> Self {
        self.cancel_kind = Some(kind.into());
        self
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> WasmTaskSpawnRequest {
        WasmTaskSpawnRequest {
            scope: self.scope,
            label: self.label,
            cancel_kind: self.cancel_kind,
        }
    }
}

/// Builder for `WasmFetchRequest` — reduces boilerplate for fetch operations.
///
/// ```ignore
/// let req = WasmFetchBuilder::new(scope, "https://api.example.com/data")
///     .method("POST")
///     .body(payload_bytes)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct WasmFetchBuilder {
    scope: WasmHandleRef,
    url: String,
    method: String,
    body: Option<Vec<u8>>,
}

impl WasmFetchBuilder {
    /// Start building a fetch request (defaults to GET).
    #[must_use]
    pub fn new(scope: WasmHandleRef, url: impl Into<String>) -> Self {
        Self {
            scope,
            url: url.into(),
            method: "GET".to_string(),
            body: None,
        }
    }

    /// Set the HTTP method.
    #[must_use]
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Set the request body.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> WasmFetchRequest {
        WasmFetchRequest {
            scope: self.scope,
            url: self.url,
            method: self.method,
            body: self.body,
        }
    }
}

/// Extension trait for inspecting `WasmAbiOutcomeEnvelope` values.
///
/// Provides pattern-match helpers so callers don't need to destructure
/// the tagged enum for common checks.
pub trait WasmOutcomeExt {
    /// Returns `true` if the outcome is `Ok`.
    fn is_ok(&self) -> bool;
    /// Returns `true` if the outcome is an error.
    fn is_err(&self) -> bool;
    /// Returns `true` if the outcome is a cancellation.
    fn is_cancelled(&self) -> bool;
    /// Returns `true` if the outcome is a panic.
    fn is_panicked(&self) -> bool;

    /// Extracts the `Ok` value, if present.
    fn ok_value(&self) -> Option<&WasmAbiValue>;
    /// Extracts the error failure, if present.
    fn err_failure(&self) -> Option<&WasmAbiFailure>;
    /// Extracts the cancellation payload, if present.
    fn cancellation(&self) -> Option<&WasmAbiCancellation>;

    /// Returns the stable outcome kind name for structured logging.
    fn outcome_kind(&self) -> &'static str;
}

impl WasmOutcomeExt for WasmAbiOutcomeEnvelope {
    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }

    fn is_err(&self) -> bool {
        matches!(self, Self::Err { .. })
    }

    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked { .. })
    }

    fn ok_value(&self) -> Option<&WasmAbiValue> {
        match self {
            Self::Ok { value } => Some(value),
            _ => None,
        }
    }

    fn err_failure(&self) -> Option<&WasmAbiFailure> {
        match self {
            Self::Err { failure } => Some(failure),
            _ => None,
        }
    }

    fn cancellation(&self) -> Option<&WasmAbiCancellation> {
        match self {
            Self::Cancelled { cancellation } => Some(cancellation),
            _ => None,
        }
    }

    fn outcome_kind(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::Err { .. } => "err",
            Self::Cancelled { .. } => "cancelled",
            Self::Panicked { .. } => "panicked",
        }
    }
}

/// Convenience methods on `WasmExportDispatcher` for common patterns.
///
/// These methods compose multiple dispatch calls into single operations.
/// Each method documents the lifecycle transitions it performs so the
/// caller retains full visibility into state changes.
impl WasmExportDispatcher {
    /// Creates a runtime and scope in one call.
    ///
    /// Lifecycle: allocates runtime (→ Active), allocates scope (→ Active).
    /// Returns both handles. Caller is responsible for closing scope then runtime.
    pub fn create_scoped_runtime(
        &mut self,
        scope_label: Option<&str>,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<(WasmHandleRef, WasmHandleRef), WasmDispatchError> {
        let runtime = self.runtime_create(consumer_version)?;
        let scope = self.scope_enter(
            &WasmScopeEnterBuilder::new(runtime)
                .label(scope_label.unwrap_or("root"))
                .build(),
            consumer_version,
        )?;
        Ok((runtime, scope))
    }

    /// Spawns a task using the builder pattern.
    ///
    /// Lifecycle: allocates task (→ Active, pinned).
    pub fn spawn(
        &mut self,
        request: WasmTaskSpawnBuilder,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        self.task_spawn(&request.build(), consumer_version)
    }

    /// Spawns a task and immediately provides its outcome (for sync-like patterns).
    ///
    /// Lifecycle: allocates task (→ Active, pinned), then joins (→ Closed, released).
    /// Returns the outcome envelope.
    pub fn spawn_and_join(
        &mut self,
        scope: WasmHandleRef,
        label: Option<&str>,
        outcome: WasmAbiOutcomeEnvelope,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        let mut builder = WasmTaskSpawnBuilder::new(scope);
        if let Some(l) = label {
            builder = builder.label(l);
        }
        let task = self.task_spawn(&builder.build(), consumer_version)?;
        self.task_join(&task, outcome, consumer_version)
    }

    /// Closes a scope and runtime in order (structured teardown).
    ///
    /// Lifecycle: scope (→ Closed, released), runtime (→ Closed, released).
    /// Returns the runtime close outcome.
    pub fn close_scoped_runtime(
        &mut self,
        scope: &WasmHandleRef,
        runtime: &WasmHandleRef,
        consumer_version: Option<WasmAbiVersion>,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.scope_close(scope, consumer_version)?;
        self.runtime_close(runtime, consumer_version)
    }

    /// Returns a diagnostic snapshot of the current dispatcher state.
    #[must_use]
    pub fn diagnostic_snapshot(&self) -> WasmDispatcherDiagnostics {
        WasmDispatcherDiagnostics {
            dispatch_count: self.dispatch_count,
            memory_report: self.handles.memory_report(),
            event_count: self.event_log.len(),
            leaks: self.handles.detect_leaks(),
            producer_version: self.producer_version,
        }
    }
}

/// Diagnostic snapshot of dispatcher state for observability and leak detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmDispatcherDiagnostics {
    /// Total dispatch calls processed.
    pub dispatch_count: u64,
    /// Handle table memory report.
    pub memory_report: WasmMemoryReport,
    /// Number of boundary events recorded.
    pub event_count: usize,
    /// Handles that appear leaked (Closed but not released).
    pub leaks: Vec<WasmHandleRef>,
    /// Producer ABI version.
    pub producer_version: WasmAbiVersion,
}

impl WasmDispatcherDiagnostics {
    /// Returns `true` if there are no leaks and no live handles.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.leaks.is_empty() && self.memory_report.live_handles == 0
    }

    /// Converts diagnostics to stable key/value fields for structured logging.
    #[must_use]
    pub fn as_log_fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("dispatch_count", self.dispatch_count.to_string());
        fields.insert("live_handles", self.memory_report.live_handles.to_string());
        fields.insert("pinned_count", self.memory_report.pinned_count.to_string());
        fields.insert("event_count", self.event_count.to_string());
        fields.insert("leak_count", self.leaks.len().to_string());
        fields.insert("abi_version", self.producer_version.to_string());
        fields.insert("clean", self.is_clean().to_string());
        fields
    }
}

// ---------------------------------------------------------------------------
// React Runtime Provider Lifecycle Contract
// ---------------------------------------------------------------------------
//
// These types model how a React component tree interacts with the WASM
// runtime through a provider pattern. The key invariants:
//
// 1. **Single runtime per provider**: A `<RuntimeProvider>` component owns
//    exactly one WASM runtime instance. Nested providers are separate.
//
// 2. **Mount/unmount = init/close**: React mount triggers runtime_create +
//    scope_enter. Unmount triggers scope_close + runtime_close.
//
// 3. **StrictMode remount**: React StrictMode double-invokes effects.
//    The provider must handle mount → unmount → mount without leaking
//    handles, scopes, or obligations from the first mount.
//
// 4. **Cancellation preservation**: When a component unmounts, all tasks
//    spawned within its scope are cancelled (not silently dropped).
//    The cancel protocol is fully visible to the WASM runtime.
//
// 5. **Scope ownership follows component tree**: Child components that
//    call `useScope()` get a child scope of the nearest provider's scope.
//    Component unmount closes the child scope first.

/// React provider lifecycle phases.
///
/// Models the provider component's journey from initial render through
/// cleanup. These phases map directly to React effect lifecycle hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactProviderPhase {
    /// Component rendered but effect not yet fired.
    /// No WASM handles allocated.
    Pending,
    /// Effect fired; runtime and root scope are being initialized.
    /// Handles are being allocated but not yet Active.
    Initializing,
    /// Runtime and root scope are Active. Child components can spawn
    /// tasks and create sub-scopes.
    Ready,
    /// Cleanup effect fired (unmount or StrictMode remount).
    /// Active tasks are being cancelled, scopes are draining.
    Disposing,
    /// All handles released, runtime closed. Terminal state.
    Disposed,
    /// Initialization or disposal failed. Contains error context.
    /// Provider should render an error boundary fallback.
    Failed,
}

/// Error returned when a provider lifecycle transition is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid provider transition: {from:?} -> {to:?}")]
pub struct ReactProviderTransitionError {
    /// Current phase.
    pub from: ReactProviderPhase,
    /// Requested next phase.
    pub to: ReactProviderPhase,
}

/// Returns true when a provider phase transition is valid.
#[must_use]
pub fn is_valid_provider_transition(from: ReactProviderPhase, to: ReactProviderPhase) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            ReactProviderPhase::Pending | ReactProviderPhase::Disposed,
            ReactProviderPhase::Initializing
        ) | (
            ReactProviderPhase::Initializing,
            ReactProviderPhase::Ready | ReactProviderPhase::Failed
        ) | (ReactProviderPhase::Ready, ReactProviderPhase::Disposing)
            | (
                ReactProviderPhase::Disposing,
                ReactProviderPhase::Disposed | ReactProviderPhase::Failed
            )
    )
}

/// Validates a provider phase transition.
pub fn validate_provider_transition(
    from: ReactProviderPhase,
    to: ReactProviderPhase,
) -> Result<(), ReactProviderTransitionError> {
    if is_valid_provider_transition(from, to) {
        Ok(())
    } else {
        Err(ReactProviderTransitionError { from, to })
    }
}

/// Configuration for a React runtime provider.
///
/// Passed to the `<RuntimeProvider>` component as props. Controls
/// initialization behavior, cancellation policy, and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactProviderConfig {
    /// Human-readable label for the provider (diagnostics only).
    pub label: String,
    /// ABI version to negotiate with the WASM module.
    pub consumer_version: Option<WasmAbiVersion>,
    /// Abort propagation mode for cancel/abort bridging.
    pub abort_mode: WasmAbortPropagationMode,
    /// Whether to enable StrictMode remount resilience.
    ///
    /// When true, the provider tolerates mount → unmount → mount sequences
    /// by cleanly disposing the first instance before reinitializing.
    pub strict_mode_resilient: bool,
    /// Whether to collect diagnostic events for the React DevTools.
    pub devtools_diagnostics: bool,
}

impl Default for ReactProviderConfig {
    fn default() -> Self {
        Self {
            label: "asupersync".to_string(),
            consumer_version: None,
            abort_mode: WasmAbortPropagationMode::Bidirectional,
            strict_mode_resilient: true,
            devtools_diagnostics: false,
        }
    }
}

/// Snapshot of provider state for diagnostics and DevTools integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactProviderSnapshot {
    /// Current lifecycle phase.
    pub phase: ReactProviderPhase,
    /// Provider configuration.
    pub config: ReactProviderConfig,
    /// Runtime handle (if allocated).
    pub runtime_handle: Option<WasmHandleRef>,
    /// Root scope handle (if allocated).
    pub root_scope_handle: Option<WasmHandleRef>,
    /// Number of child scopes currently active.
    pub child_scope_count: usize,
    /// Number of active tasks across all scopes.
    pub active_task_count: usize,
    /// Phase transition history (for StrictMode debugging).
    pub transition_history: Vec<ReactProviderPhase>,
    /// Dispatcher diagnostics snapshot.
    pub dispatcher_diagnostics: Option<WasmDispatcherDiagnostics>,
}

/// React provider state machine managing runtime lifecycle.
///
/// Wraps a `WasmExportDispatcher` and manages the provider lifecycle:
/// Pending → Initializing → Ready → Disposing → Disposed.
///
/// Supports StrictMode remount: Disposed → Initializing → Ready.
#[derive(Debug)]
pub struct ReactProviderState {
    /// Current lifecycle phase.
    phase: ReactProviderPhase,
    /// Provider configuration.
    config: ReactProviderConfig,
    /// Underlying WASM dispatcher.
    dispatcher: WasmExportDispatcher,
    /// Runtime handle (if allocated).
    runtime_handle: Option<WasmHandleRef>,
    /// Root scope handle (if allocated).
    root_scope_handle: Option<WasmHandleRef>,
    /// Active child scope handles.
    child_scopes: Vec<WasmHandleRef>,
    /// Active task handles.
    active_tasks: Vec<WasmHandleRef>,
    /// Phase transition history.
    transition_history: Vec<ReactProviderPhase>,
}

impl ReactProviderState {
    /// Creates a new provider state in `Pending` phase.
    #[must_use]
    pub fn new(config: ReactProviderConfig) -> Self {
        let dispatcher = WasmExportDispatcher::new().with_abort_mode(config.abort_mode);
        Self {
            phase: ReactProviderPhase::Pending,
            config,
            dispatcher,
            runtime_handle: None,
            root_scope_handle: None,
            child_scopes: Vec::new(),
            active_tasks: Vec::new(),
            transition_history: vec![ReactProviderPhase::Pending],
        }
    }

    /// Returns the current lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> ReactProviderPhase {
        self.phase
    }

    /// Returns the runtime handle, if allocated.
    #[must_use]
    pub fn runtime_handle(&self) -> Option<WasmHandleRef> {
        self.runtime_handle
    }

    /// Returns the root scope handle, if allocated.
    #[must_use]
    pub fn root_scope_handle(&self) -> Option<WasmHandleRef> {
        self.root_scope_handle
    }

    /// Returns a reference to the underlying dispatcher.
    #[must_use]
    pub fn dispatcher(&self) -> &WasmExportDispatcher {
        &self.dispatcher
    }

    /// Advances to a new phase, validating the transition.
    fn advance(&mut self, to: ReactProviderPhase) -> Result<(), ReactProviderTransitionError> {
        // Cap transition history to prevent unbounded growth.
        const MAX_HISTORY: usize = 256;

        validate_provider_transition(self.phase, to)?;
        self.phase = to;
        if self.transition_history.len() >= MAX_HISTORY {
            self.transition_history.drain(..MAX_HISTORY / 2);
        }
        self.transition_history.push(to);
        Ok(())
    }

    /// Initializes the runtime and root scope (effect mount).
    ///
    /// Lifecycle: Pending/Disposed → Initializing → Ready.
    /// Allocates runtime handle (→ Active) and root scope (→ Active).
    pub fn mount(&mut self) -> Result<(), WasmDispatchError> {
        self.advance(ReactProviderPhase::Initializing)
            .map_err(|e| WasmDispatchError::InvalidRequest {
                reason: e.to_string(),
            })?;

        match self.do_mount() {
            Ok(()) => {
                self.advance(ReactProviderPhase::Ready).map_err(|e| {
                    WasmDispatchError::InvalidRequest {
                        reason: e.to_string(),
                    }
                })?;
                Ok(())
            }
            Err(e) => {
                // Transition to Failed on error
                let _ = self.advance(ReactProviderPhase::Failed);
                Err(e)
            }
        }
    }

    fn do_mount(&mut self) -> Result<(), WasmDispatchError> {
        let (rt, scope) = self
            .dispatcher
            .create_scoped_runtime(Some(&self.config.label), self.config.consumer_version)?;
        self.runtime_handle = Some(rt);
        self.root_scope_handle = Some(scope);
        Ok(())
    }

    /// Disposes the runtime and all scopes (effect cleanup / unmount).
    ///
    /// Lifecycle: Ready → Disposing → Disposed.
    /// Cancels all active tasks, closes child scopes (inner-first),
    /// then closes root scope and runtime.
    pub fn unmount(&mut self) -> Result<(), WasmDispatchError> {
        self.advance(ReactProviderPhase::Disposing).map_err(|e| {
            WasmDispatchError::InvalidRequest {
                reason: e.to_string(),
            }
        })?;

        match self.do_unmount() {
            Ok(()) => {
                self.advance(ReactProviderPhase::Disposed).map_err(|e| {
                    WasmDispatchError::InvalidRequest {
                        reason: e.to_string(),
                    }
                })?;
                Ok(())
            }
            Err(e) => {
                let _ = self.advance(ReactProviderPhase::Failed);
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn do_unmount(&mut self) -> Result<(), WasmDispatchError> {
        let cv = self.config.consumer_version;

        // 1. Cancel all active tasks
        for task in std::mem::take(&mut self.active_tasks) {
            // Best-effort cancel — task may already be closed
            if self.dispatcher.handles().get(&task).is_ok() {
                let state = self
                    .dispatcher
                    .handles()
                    .get(&task)
                    .map_or(WasmBoundaryState::Closed, |e| e.state);
                if state == WasmBoundaryState::Active {
                    let _ = self.dispatcher.task_cancel(
                        &WasmTaskCancelRequest {
                            task,
                            kind: "unmount".to_string(),
                            message: Some("React component unmounted".to_string()),
                        },
                        cv,
                    );
                }
                // Join with cancelled outcome to release
                if self.dispatcher.handles().get(&task).is_ok() {
                    let _ = self.dispatcher.task_join(
                        &task,
                        WasmAbiOutcomeEnvelope::Cancelled {
                            cancellation: WasmAbiCancellation {
                                kind: "unmount".to_string(),
                                phase: "completed".to_string(),
                                origin_region: "react-provider".to_string(),
                                origin_task: None,
                                timestamp_nanos: 0,
                                message: Some("component unmounted".to_string()),
                                truncated: false,
                            },
                        },
                        cv,
                    );
                }
            }
        }

        // 2. Close child scopes (inner-first / LIFO for structured concurrency)
        let child_scopes: Vec<_> = self.child_scopes.drain(..).rev().collect();
        for scope in child_scopes {
            if self.dispatcher.handles().get(&scope).is_ok() {
                let _ = self.dispatcher.scope_close(&scope, cv);
            }
        }

        // 3. Close root scope
        if let Some(scope) = self.root_scope_handle.take() {
            if self.dispatcher.handles().get(&scope).is_ok() {
                self.dispatcher.scope_close(&scope, cv)?;
            }
        }

        // 4. Close runtime
        if let Some(rt) = self.runtime_handle.take() {
            if self.dispatcher.handles().get(&rt).is_ok() {
                self.dispatcher.runtime_close(&rt, cv)?;
            }
        }

        Ok(())
    }

    /// Creates a child scope within the provider's root scope.
    ///
    /// Used by `useScope()` hooks in child components. The child scope
    /// is tracked and will be cancelled on provider unmount.
    pub fn create_child_scope(
        &mut self,
        label: Option<&str>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        if self.phase != ReactProviderPhase::Ready {
            return Err(WasmDispatchError::InvalidState {
                state: WasmBoundaryState::Closed,
                symbol: WasmAbiSymbol::ScopeEnter,
            });
        }
        let parent = self
            .root_scope_handle
            .ok_or_else(|| WasmDispatchError::InvalidRequest {
                reason: "no root scope".to_string(),
            })?;
        let scope = self.dispatcher.scope_enter(
            &WasmScopeEnterBuilder::new(parent)
                .label(label.unwrap_or("child"))
                .build(),
            self.config.consumer_version,
        )?;
        self.child_scopes.push(scope);
        Ok(scope)
    }

    /// Spawns a task within the provider's root scope (or a child scope).
    ///
    /// The task handle is tracked for cancellation on unmount.
    pub fn spawn_task(
        &mut self,
        scope: WasmHandleRef,
        label: Option<&str>,
    ) -> Result<WasmHandleRef, WasmDispatchError> {
        if self.phase != ReactProviderPhase::Ready {
            return Err(WasmDispatchError::InvalidState {
                state: WasmBoundaryState::Closed,
                symbol: WasmAbiSymbol::TaskSpawn,
            });
        }
        let task = self.dispatcher.spawn(
            {
                let mut b = WasmTaskSpawnBuilder::new(scope);
                if let Some(l) = label {
                    b = b.label(l);
                }
                b
            },
            self.config.consumer_version,
        )?;
        self.active_tasks.push(task);
        Ok(task)
    }

    /// Completes a task with its outcome, removing it from tracking.
    pub fn complete_task(
        &mut self,
        task: &WasmHandleRef,
        outcome: WasmAbiOutcomeEnvelope,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.active_tasks.retain(|t| t != task);
        self.dispatcher
            .task_join(task, outcome, self.config.consumer_version)
    }

    /// Returns a diagnostic snapshot of the provider state.
    #[must_use]
    pub fn snapshot(&self) -> ReactProviderSnapshot {
        ReactProviderSnapshot {
            phase: self.phase,
            config: self.config.clone(),
            runtime_handle: self.runtime_handle,
            root_scope_handle: self.root_scope_handle,
            child_scope_count: self.child_scopes.len(),
            active_task_count: self.active_tasks.len(),
            transition_history: self.transition_history.clone(),
            dispatcher_diagnostics: Some(self.dispatcher.diagnostic_snapshot()),
        }
    }
}

// ---------------------------------------------------------------------------
// React Hook Contracts
// ---------------------------------------------------------------------------
//
// These types define the semantic contracts for React hooks that bridge
// component lifecycle with structured concurrency primitives. Each hook
// manages owned resources (scopes, tasks, handles) and guarantees cleanup
// on unmount or dependency change.
//
// The hooks are:
//
// - `useScope`: Creates a child scope owned by the component. Scope closes
//   (cancelling all child work) when the component unmounts.
//
// - `useTask`: Spawns a task tied to dependencies. When deps change, the
//   previous task is cancelled before spawning a new one. No leak possible.
//
// - `useRace`: Races N tasks; first to resolve wins, losers are cancelled
//   and drained before the result is delivered.
//
// - `useCancellation`: Observes the cancellation state of the enclosing
//   scope, and provides a trigger to request cancellation.

/// Lifecycle phase of a React hook instance.
///
/// Hooks progress through these phases during component rendering and
/// effect execution. StrictMode may cause Idle → Active → Cleanup → Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactHookPhase {
    /// Hook registered but effect not yet fired.
    Idle,
    /// Effect fired; resources are allocated and active.
    Active,
    /// Cleanup running; resources are being released.
    Cleanup,
    /// Hook unmounted; all resources released. Terminal.
    Unmounted,
    /// Hook entered an error state during setup or cleanup.
    Error,
}

/// Returns true when a hook phase transition is valid.
#[must_use]
pub fn is_valid_hook_transition(from: ReactHookPhase, to: ReactHookPhase) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            ReactHookPhase::Idle,
            ReactHookPhase::Active | ReactHookPhase::Error
        ) | (ReactHookPhase::Active, ReactHookPhase::Cleanup)
            | (
                ReactHookPhase::Cleanup,
                ReactHookPhase::Unmounted | ReactHookPhase::Active | ReactHookPhase::Error
            )
            | (ReactHookPhase::Unmounted, ReactHookPhase::Active)
    )
}

/// Error for invalid hook phase transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid hook transition: {from:?} -> {to:?}")]
pub struct ReactHookTransitionError {
    /// Current phase.
    pub from: ReactHookPhase,
    /// Requested next phase.
    pub to: ReactHookPhase,
}

/// Validates a hook phase transition, returning an error if invalid.
pub fn validate_hook_transition(
    from: ReactHookPhase,
    to: ReactHookPhase,
) -> Result<(), ReactHookTransitionError> {
    if is_valid_hook_transition(from, to) {
        Ok(())
    } else {
        Err(ReactHookTransitionError { from, to })
    }
}

/// Identifies which hook type produced a diagnostic event or error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactHookKind {
    /// `useScope` — child scope ownership.
    Scope,
    /// `useTask` — dependency-keyed task spawning.
    Task,
    /// `useRace` — N-way task race with loser drain.
    Race,
    /// `useCancellation` — cancellation observation/trigger.
    Cancellation,
}

// -- useScope contract --

/// Configuration for the `useScope` hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseScopeConfig {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// Whether to propagate cancellation from this scope to the parent.
    /// Default: true (structured concurrency).
    pub propagate_cancel: bool,
}

impl Default for UseScopeConfig {
    fn default() -> Self {
        Self {
            label: "scope".to_string(),
            propagate_cancel: true,
        }
    }
}

/// Snapshot of `useScope` hook state for DevTools/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseScopeSnapshot {
    /// Current lifecycle phase.
    pub phase: ReactHookPhase,
    /// Hook configuration.
    pub config: UseScopeConfig,
    /// Handle to the owned scope (if active).
    pub scope_handle: Option<WasmHandleRef>,
    /// Number of tasks spawned within this scope.
    pub task_count: usize,
    /// Number of child scopes nested under this one.
    pub child_scope_count: usize,
}

// -- useTask contract --

/// Cancellation behavior when task dependencies change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskDepChangePolicy {
    /// Cancel the running task immediately, then spawn new one.
    CancelAndRestart,
    /// Let the running task finish, discard its result, then spawn new one.
    DiscardAndRestart,
    /// Keep the running task; ignore the dependency change.
    KeepRunning,
}

/// Configuration for the `useTask` hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseTaskConfig {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// Policy when dependencies change while a task is running.
    pub dep_change_policy: TaskDepChangePolicy,
    /// Whether the task result should be memoized across re-renders
    /// when dependencies haven't changed.
    pub memoize_result: bool,
}

impl Default for UseTaskConfig {
    fn default() -> Self {
        Self {
            label: "task".to_string(),
            dep_change_policy: TaskDepChangePolicy::CancelAndRestart,
            memoize_result: true,
        }
    }
}

/// Current execution state of a `useTask` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseTaskStatus {
    /// No task spawned yet (initial render, deps not ready).
    Idle,
    /// Task is executing.
    Running,
    /// Task completed successfully.
    Success,
    /// Task completed with an error.
    Error,
    /// Task was cancelled (dep change, unmount, or explicit).
    Cancelled,
}

/// Snapshot of `useTask` hook state for DevTools/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseTaskSnapshot {
    /// Hook lifecycle phase.
    pub phase: ReactHookPhase,
    /// Task execution status.
    pub status: UseTaskStatus,
    /// Hook configuration.
    pub config: UseTaskConfig,
    /// Handle to the current task (if running).
    pub task_handle: Option<WasmHandleRef>,
    /// Scope the task runs within.
    pub scope_handle: Option<WasmHandleRef>,
    /// Number of times the task has been (re)spawned.
    pub spawn_count: u32,
    /// Number of times the task was cancelled due to dep changes.
    pub dep_cancel_count: u32,
}

// -- useRace contract --

/// Configuration for the `useRace` hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseRaceConfig {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// Maximum number of concurrent racers.
    pub max_racers: usize,
    /// Whether loser drain must complete before the winner result is
    /// delivered. Default: true (no leaked work).
    pub drain_losers_before_resolve: bool,
}

impl Default for UseRaceConfig {
    fn default() -> Self {
        Self {
            label: "race".to_string(),
            max_racers: 8,
            drain_losers_before_resolve: true,
        }
    }
}

/// Current state of an individual racer within a `useRace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RacerState {
    /// Racer is executing.
    Running,
    /// Racer finished — won the race.
    Won,
    /// Racer is being cancelled (loser drain).
    Draining,
    /// Racer fully drained.
    Drained,
}

/// Snapshot of a single racer for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RacerSnapshot {
    /// Index of this racer in the race.
    pub index: usize,
    /// Racer's current state.
    pub state: RacerState,
    /// Handle to the racer's task.
    pub task_handle: WasmHandleRef,
    /// Optional label.
    pub label: Option<String>,
}

/// Snapshot of `useRace` hook state for DevTools/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseRaceSnapshot {
    /// Hook lifecycle phase.
    pub phase: ReactHookPhase,
    /// Hook configuration.
    pub config: UseRaceConfig,
    /// Scope the race runs within.
    pub scope_handle: Option<WasmHandleRef>,
    /// Per-racer snapshots.
    pub racers: Vec<RacerSnapshot>,
    /// Number of races completed.
    pub race_count: u32,
    /// Whether a winner has been determined for the current race.
    pub has_winner: bool,
    /// Whether all losers have been drained for the current race.
    pub losers_drained: bool,
}

// -- useCancellation contract --

/// Configuration for the `useCancellation` hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseCancellationConfig {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// Whether this hook can trigger cancellation (vs. observe only).
    pub can_trigger: bool,
}

impl Default for UseCancellationConfig {
    fn default() -> Self {
        Self {
            label: "cancellation".to_string(),
            can_trigger: false,
        }
    }
}

/// Snapshot of `useCancellation` hook state for DevTools/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseCancellationSnapshot {
    /// Hook lifecycle phase.
    pub phase: ReactHookPhase,
    /// Hook configuration.
    pub config: UseCancellationConfig,
    /// Scope being observed.
    pub scope_handle: Option<WasmHandleRef>,
    /// Whether cancellation has been requested in the observed scope.
    pub is_cancelled: bool,
    /// Cancellation details (if cancelled).
    pub cancellation: Option<WasmAbiCancellation>,
}

/// Unified diagnostic event emitted by any React hook.
///
/// These events feed into the `WasmBoundaryEventLog` for DevTools and
/// structured logging. Each event identifies the hook instance, the
/// transition, and any associated handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactHookDiagnosticEvent {
    /// Which hook emitted the event.
    pub hook_kind: ReactHookKind,
    /// Hook instance label (from config).
    pub label: String,
    /// Phase before the transition.
    pub from_phase: ReactHookPhase,
    /// Phase after the transition.
    pub to_phase: ReactHookPhase,
    /// Handles involved (scope, task, etc.).
    pub handles: Vec<WasmHandleRef>,
    /// Optional detail message.
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Next.js App Router Integration Architecture
// ---------------------------------------------------------------------------
//
// These types define the boundary map for Next.js App Router integration.
// The key architectural constraints:
//
// 1. **Client Components only**: The WASM runtime runs exclusively in client
//    components (`'use client'`). Server Components, Server Actions, and
//    Route Handlers CANNOT import or use the runtime directly.
//
// 2. **No SSR execution**: The runtime initializes after hydration. During
//    SSR, the provider renders a placeholder (loading/skeleton). There is
//    no server-side WASM execution.
//
// 3. **Edge/Node split**: Edge Runtime has no WASM support in this model.
//    Node.js middleware/API routes interact only through serialized messages,
//    never through direct runtime calls.
//
// 4. **Hydration safety**: The provider must produce identical server and
//    client markup during hydration (empty/loading state). Runtime
//    initialization happens in useEffect, never during render.
//
// 5. **Route transitions**: React Router transitions (soft navigation) do
//    NOT destroy the runtime. Only full page navigations (hard nav) or
//    explicit unmount trigger runtime cleanup.

/// Next.js rendering environment where a component executes.
///
/// Determines what capabilities are available. The WASM runtime is only
/// usable in `ClientComponent` after hydration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsRenderEnvironment {
    /// Server Component — no WASM, no browser APIs, no state/effects.
    ServerComponent,
    /// Client Component during SSR pass — no WASM, limited browser APIs.
    ClientSsr,
    /// Client Component after hydration — full WASM and browser APIs.
    ClientHydrated,
    /// Edge Runtime — no WASM, limited Node APIs.
    EdgeRuntime,
    /// Node.js API route / Server Action — no WASM, full Node APIs.
    NodeServer,
}

/// Coarse Next.js boundary mode for mixed deployment planning.
///
/// This normalizes detailed render environments into the three operator-facing
/// lanes used in docs and adapter policy checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsBoundaryMode {
    /// Browser client lane (`client` boundary).
    Client,
    /// Server component / node lane (`server` boundary).
    Server,
    /// Edge runtime lane (`edge` boundary).
    Edge,
}

/// Fallback behavior when runtime capability is unavailable in a boundary.
///
/// This is the explicit policy surface for "what should happen instead of
/// direct WASM runtime execution" in mixed Next.js deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsRuntimeFallback {
    /// No fallback needed; runtime is directly available.
    NoneRequired,
    /// Client-side runtime call attempted before hydration; defer until hydrated.
    DeferUntilHydrated,
    /// Runtime is unavailable in server/node boundary; use serialized node bridge.
    UseServerBridge,
    /// Runtime is unavailable in edge boundary; use serialized edge bridge.
    UseEdgeBridge,
}

impl NextjsRenderEnvironment {
    /// Returns true if this environment supports WASM runtime initialization.
    #[must_use]
    pub fn supports_wasm_runtime(self) -> bool {
        self == Self::ClientHydrated
    }

    /// Returns true if browser APIs (DOM, fetch with credentials, etc.) are available.
    #[must_use]
    pub fn has_browser_apis(self) -> bool {
        matches!(self, Self::ClientSsr | Self::ClientHydrated)
    }

    /// Returns true if this is a server-side environment.
    #[must_use]
    pub fn is_server_side(self) -> bool {
        matches!(
            self,
            Self::ServerComponent | Self::EdgeRuntime | Self::NodeServer
        )
    }

    /// Returns the normalized boundary mode for this environment.
    #[must_use]
    pub fn boundary_mode(self) -> NextjsBoundaryMode {
        match self {
            Self::ClientSsr | Self::ClientHydrated => NextjsBoundaryMode::Client,
            Self::ServerComponent | Self::NodeServer => NextjsBoundaryMode::Server,
            Self::EdgeRuntime => NextjsBoundaryMode::Edge,
        }
    }

    /// Returns deterministic fallback behavior when runtime capability is unavailable.
    #[must_use]
    pub fn runtime_fallback(self) -> NextjsRuntimeFallback {
        match self {
            Self::ClientHydrated => NextjsRuntimeFallback::NoneRequired,
            Self::ClientSsr => NextjsRuntimeFallback::DeferUntilHydrated,
            Self::ServerComponent | Self::NodeServer => NextjsRuntimeFallback::UseServerBridge,
            Self::EdgeRuntime => NextjsRuntimeFallback::UseEdgeBridge,
        }
    }

    /// Human-readable fallback guidance for diagnostics and docs.
    #[must_use]
    pub fn runtime_fallback_reason(self) -> &'static str {
        match self.runtime_fallback() {
            NextjsRuntimeFallback::NoneRequired => {
                "runtime capability available: execute directly in hydrated client boundary"
            }
            NextjsRuntimeFallback::DeferUntilHydrated => {
                "runtime unavailable during SSR client pass: defer initialization until hydration completes"
            }
            NextjsRuntimeFallback::UseServerBridge => {
                "runtime unavailable in server boundary: route through serialized node/server bridge"
            }
            NextjsRuntimeFallback::UseEdgeBridge => {
                "runtime unavailable in edge boundary: route through serialized edge bridge"
            }
        }
    }
}

/// Capability that may or may not be available in a given render environment.
///
/// Used to build a capability matrix for documentation and runtime validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsCapability {
    /// Initialize and run the WASM runtime.
    WasmRuntime,
    /// Use React hooks (useState, useEffect, etc.).
    ReactHooks,
    /// Access browser DOM APIs.
    DomAccess,
    /// Use Web Workers / shared workers.
    WebWorkers,
    /// Access IndexedDB / localStorage.
    BrowserStorage,
    /// Use the Fetch API with credentials/cookies.
    AuthenticatedFetch,
    /// Read/write cookies via next/headers.
    ServerCookies,
    /// Access the request object (headers, IP, etc.).
    RequestContext,
    /// Use Node.js-specific APIs (fs, crypto, etc.).
    NodeApis,
    /// Perform streaming SSR.
    StreamingSsr,
}

/// Returns true if a capability is available in the given environment.
#[must_use]
pub fn is_capability_available(env: NextjsRenderEnvironment, cap: NextjsCapability) -> bool {
    use NextjsCapability as C;
    use NextjsRenderEnvironment as E;
    matches!(
        (env, cap),
        (
            E::ClientHydrated,
            C::WasmRuntime | C::DomAccess | C::WebWorkers | C::BrowserStorage
        ) | (
            E::ClientSsr | E::ClientHydrated,
            C::ReactHooks | C::AuthenticatedFetch
        ) | (
            E::ServerComponent | E::EdgeRuntime | E::NodeServer,
            C::ServerCookies | C::RequestContext
        ) | (E::NodeServer, C::NodeApis)
            | (E::ServerComponent | E::EdgeRuntime, C::StreamingSsr)
    )
}

/// Known anti-patterns for Next.js + WASM runtime integration.
///
/// Each anti-pattern describes something that developers might try but
/// that violates architectural constraints. Used in documentation,
/// linting rules, and diagnostic error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsAntiPattern {
    /// Importing WASM runtime in a Server Component.
    WasmImportInServerComponent,
    /// Calling runtime methods during SSR render pass.
    RuntimeCallDuringSsr,
    /// Initializing runtime in render (not in useEffect).
    RuntimeInitInRender,
    /// Sharing runtime handles across route segments.
    HandlesSharingAcrossRoutes,
    /// Using runtime in Edge middleware.
    RuntimeInEdgeMiddleware,
    /// Blocking hydration on runtime initialization.
    BlockingHydration,
    /// Passing WASM handles through Server Actions.
    HandlesInServerActions,
}

impl NextjsAntiPattern {
    /// Returns a human-readable explanation of why this pattern is wrong.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::WasmImportInServerComponent => {
                "Server Components cannot import WASM modules. Use 'use client' directive."
            }
            Self::RuntimeCallDuringSsr => {
                "WASM runtime is not available during SSR. Initialize in useEffect after hydration."
            }
            Self::RuntimeInitInRender => {
                "Runtime initialization has side effects. Use useEffect, not the render function."
            }
            Self::HandlesSharingAcrossRoutes => {
                "WASM handles are scoped to a provider instance. Each route segment needs its own provider."
            }
            Self::RuntimeInEdgeMiddleware => {
                "Edge Runtime does not support WASM execution in this integration model."
            }
            Self::BlockingHydration => {
                "Never block hydration on WASM init. Render a placeholder, then initialize async."
            }
            Self::HandlesInServerActions => {
                "WasmHandleRef values are opaque client-side references. They cannot be serialized for server actions."
            }
        }
    }
}

/// Navigation type that affects runtime lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsNavigationType {
    /// Soft navigation (React Router transition). Runtime survives.
    SoftNavigation,
    /// Hard navigation (full page load). Runtime is destroyed.
    HardNavigation,
    /// Back/forward navigation. Runtime may or may not survive
    /// depending on bfcache behavior.
    PopState,
}

impl NextjsNavigationType {
    /// Returns true if the runtime is expected to survive this navigation.
    #[must_use]
    pub fn runtime_survives(self) -> bool {
        matches!(self, Self::SoftNavigation)
    }
}

/// Phase of the Next.js client bootstrap sequence.
///
/// The provider must wait for `Hydrated` before initializing the WASM runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsBootstrapPhase {
    /// Server-rendered HTML received, JS not yet loaded.
    ServerRendered,
    /// JS bundles loaded, React hydration in progress.
    Hydrating,
    /// Hydration complete. useEffect callbacks firing.
    Hydrated,
    /// WASM module loaded and runtime initialized.
    RuntimeReady,
    /// Runtime initialization failed.
    RuntimeFailed,
}

/// Returns true when a bootstrap phase transition is valid.
#[must_use]
pub fn is_valid_bootstrap_transition(from: NextjsBootstrapPhase, to: NextjsBootstrapPhase) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            NextjsBootstrapPhase::ServerRendered,
            NextjsBootstrapPhase::Hydrating
        ) | (
            NextjsBootstrapPhase::Hydrating,
            NextjsBootstrapPhase::Hydrated | NextjsBootstrapPhase::RuntimeFailed
        ) | (
            NextjsBootstrapPhase::Hydrated,
            NextjsBootstrapPhase::RuntimeReady
                | NextjsBootstrapPhase::RuntimeFailed
                | NextjsBootstrapPhase::ServerRendered
        ) | (
            NextjsBootstrapPhase::RuntimeReady | NextjsBootstrapPhase::RuntimeFailed,
            NextjsBootstrapPhase::Hydrating | NextjsBootstrapPhase::ServerRendered
        )
    )
}

/// Error for invalid bootstrap phase transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid bootstrap transition: {from:?} -> {to:?}")]
pub struct NextjsBootstrapTransitionError {
    /// Current phase.
    pub from: NextjsBootstrapPhase,
    /// Requested next phase.
    pub to: NextjsBootstrapPhase,
}

/// Validates a bootstrap phase transition.
pub fn validate_bootstrap_transition(
    from: NextjsBootstrapPhase,
    to: NextjsBootstrapPhase,
) -> Result<(), NextjsBootstrapTransitionError> {
    if is_valid_bootstrap_transition(from, to) {
        Ok(())
    } else {
        Err(NextjsBootstrapTransitionError { from, to })
    }
}

/// Placement of a component within the Next.js rendering tree.
///
/// Determines the rules that apply to the component's use of the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsComponentPlacement {
    /// Rendering environment for this component.
    pub environment: NextjsRenderEnvironment,
    /// Route segment path (e.g., "/dashboard/settings").
    pub route_segment: String,
    /// Whether this component is inside a `<Suspense>` boundary.
    pub inside_suspense: bool,
    /// Whether this component is inside an error boundary.
    pub inside_error_boundary: bool,
    /// Layout nesting depth (root = 0).
    pub layout_depth: u32,
}

/// Snapshot of the Next.js integration state for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsIntegrationSnapshot {
    /// Current bootstrap phase.
    pub bootstrap_phase: NextjsBootstrapPhase,
    /// Active render environment.
    pub environment: NextjsRenderEnvironment,
    /// Current route segment.
    pub route_segment: String,
    /// Number of active providers in the component tree.
    pub active_provider_count: usize,
    /// Whether the WASM module has been loaded.
    pub wasm_module_loaded: bool,
    /// Navigation events observed since last snapshot.
    pub navigation_count: u32,
}

/// Trigger that caused a bootstrap transition.
///
/// This keeps bootstrap logs deterministic and machine-readable so hydration
/// and runtime-init behavior can be replayed and audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextjsBootstrapTrigger {
    /// Initial server-rendered state.
    InitialState,
    /// Hydration has started.
    HydrationStarted,
    /// Hydration completed successfully.
    HydrationCompleted,
    /// Runtime initialization completed successfully.
    RuntimeInitSucceeded,
    /// Runtime initialization failed.
    RuntimeInitFailed,
    /// Runtime initialization was cancelled.
    RuntimeInitCancelled,
    /// Retry after a runtime initialization failure.
    RetryAfterFailure,
    /// Navigation event (soft, hard, or popstate).
    Navigation,
    /// Hot reload / Fast Refresh event.
    HotReload,
}

/// One deterministic bootstrap transition record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsBootstrapTransitionRecord {
    /// Phase before transition processing.
    pub from: NextjsBootstrapPhase,
    /// Phase after transition processing.
    pub to: NextjsBootstrapPhase,
    /// Trigger that caused this transition.
    pub trigger: NextjsBootstrapTrigger,
    /// Optional deterministic detail payload.
    pub detail: Option<String>,
}

/// Next.js client bootstrap state machine.
///
/// This tracks hydration-safe runtime initialization with explicit phase
/// transitions, deterministic history, and idempotent re-entry behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsBootstrapState {
    phase: NextjsBootstrapPhase,
    hydration_cycle_count: u32,
    runtime_generation: u32,
    navigation_count: u32,
    hot_reload_count: u32,
    last_failure: Option<String>,
    transition_log: Vec<NextjsBootstrapTransitionRecord>,
}

impl NextjsBootstrapState {
    /// Creates a new bootstrap state at `ServerRendered`.
    #[must_use]
    pub fn new() -> Self {
        let initial_phase = NextjsBootstrapPhase::ServerRendered;
        Self {
            phase: initial_phase,
            hydration_cycle_count: 0,
            runtime_generation: 0,
            navigation_count: 0,
            hot_reload_count: 0,
            last_failure: None,
            transition_log: vec![NextjsBootstrapTransitionRecord {
                from: initial_phase,
                to: initial_phase,
                trigger: NextjsBootstrapTrigger::InitialState,
                detail: None,
            }],
        }
    }

    /// Returns current bootstrap phase.
    #[must_use]
    pub fn phase(&self) -> NextjsBootstrapPhase {
        self.phase
    }

    /// Returns number of hydration cycles observed.
    #[must_use]
    pub fn hydration_cycle_count(&self) -> u32 {
        self.hydration_cycle_count
    }

    /// Returns runtime generation counter.
    ///
    /// This increments every time bootstrap reaches `RuntimeReady`.
    #[must_use]
    pub fn runtime_generation(&self) -> u32 {
        self.runtime_generation
    }

    /// Returns number of navigation events processed.
    #[must_use]
    pub fn navigation_count(&self) -> u32 {
        self.navigation_count
    }

    /// Returns number of hot-reload events processed.
    #[must_use]
    pub fn hot_reload_count(&self) -> u32 {
        self.hot_reload_count
    }

    /// Returns last runtime initialization failure reason, if any.
    #[must_use]
    pub fn last_failure(&self) -> Option<&str> {
        self.last_failure.as_deref()
    }

    /// Returns deterministic transition history.
    #[must_use]
    pub fn transition_log(&self) -> &[NextjsBootstrapTransitionRecord] {
        &self.transition_log
    }

    /// Starts hydration.
    ///
    /// This is idempotent when already in `Hydrating`.
    pub fn start_hydration(&mut self) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::Hydrating,
            NextjsBootstrapTrigger::HydrationStarted,
            None,
        )
    }

    /// Completes hydration.
    ///
    /// This is idempotent when already in `Hydrated`.
    pub fn complete_hydration(&mut self) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::Hydrated,
            NextjsBootstrapTrigger::HydrationCompleted,
            None,
        )
    }

    /// Marks runtime initialization success.
    ///
    /// This is idempotent when already in `RuntimeReady`.
    pub fn mark_runtime_ready(&mut self) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::RuntimeReady,
            NextjsBootstrapTrigger::RuntimeInitSucceeded,
            None,
        )
    }

    /// Marks runtime initialization failure with a deterministic reason.
    pub fn mark_runtime_failed(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::RuntimeFailed,
            NextjsBootstrapTrigger::RuntimeInitFailed,
            Some(reason.into()),
        )
    }

    /// Marks runtime initialization cancellation with a deterministic reason.
    pub fn mark_runtime_cancelled(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::RuntimeFailed,
            NextjsBootstrapTrigger::RuntimeInitCancelled,
            Some(reason.into()),
        )
    }

    /// Retries bootstrap after a previous runtime failure.
    pub fn retry_after_failure(&mut self) -> Result<bool, NextjsBootstrapTransitionError> {
        self.transition(
            NextjsBootstrapPhase::Hydrating,
            NextjsBootstrapTrigger::RetryAfterFailure,
            None,
        )
    }

    /// Applies a navigation event to bootstrap state.
    ///
    /// Soft navigations preserve runtime state. Hard and popstate navigations
    /// reset to `ServerRendered`.
    pub fn on_navigation(
        &mut self,
        navigation: NextjsNavigationType,
    ) -> Result<bool, NextjsBootstrapTransitionError> {
        self.navigation_count = self.navigation_count.saturating_add(1);
        if navigation.runtime_survives() {
            self.push_transition(
                self.phase,
                self.phase,
                NextjsBootstrapTrigger::Navigation,
                Some("soft_navigation".to_string()),
            );
            return Ok(false);
        }

        let detail = match navigation {
            NextjsNavigationType::SoftNavigation => "soft_navigation",
            NextjsNavigationType::HardNavigation => "hard_navigation",
            NextjsNavigationType::PopState => "pop_state_navigation",
        };

        self.transition(
            NextjsBootstrapPhase::ServerRendered,
            NextjsBootstrapTrigger::Navigation,
            Some(detail.to_string()),
        )
    }

    /// Applies a hot-reload event (e.g., Fast Refresh).
    ///
    /// This forces re-hydration from active or failed runtime phases while
    /// preserving deterministic bookkeeping.
    pub fn on_hot_reload(&mut self) -> Result<bool, NextjsBootstrapTransitionError> {
        self.hot_reload_count = self.hot_reload_count.saturating_add(1);
        self.transition(
            NextjsBootstrapPhase::Hydrating,
            NextjsBootstrapTrigger::HotReload,
            Some("fast_refresh".to_string()),
        )
    }

    fn transition(
        &mut self,
        to: NextjsBootstrapPhase,
        trigger: NextjsBootstrapTrigger,
        detail: Option<String>,
    ) -> Result<bool, NextjsBootstrapTransitionError> {
        let from = self.phase;

        if from != to {
            validate_bootstrap_transition(from, to)?;
            self.phase = to;
        }

        if to == NextjsBootstrapPhase::Hydrating && from != NextjsBootstrapPhase::Hydrating {
            self.hydration_cycle_count = self.hydration_cycle_count.saturating_add(1);
        }
        if to == NextjsBootstrapPhase::RuntimeReady && from != NextjsBootstrapPhase::RuntimeReady {
            self.runtime_generation = self.runtime_generation.saturating_add(1);
            self.last_failure = None;
        } else if to == NextjsBootstrapPhase::RuntimeFailed {
            self.last_failure.clone_from(&detail);
        }

        self.push_transition(from, to, trigger, detail);
        Ok(from != to)
    }

    fn push_transition(
        &mut self,
        from: NextjsBootstrapPhase,
        to: NextjsBootstrapPhase,
        trigger: NextjsBootstrapTrigger,
        detail: Option<String>,
    ) {
        // Cap transition log to prevent unbounded growth in long-running SPAs.
        const MAX_TRANSITION_LOG: usize = 256;
        if self.transition_log.len() >= MAX_TRANSITION_LOG {
            self.transition_log.drain(..MAX_TRANSITION_LOG / 2);
        }
        self.transition_log.push(NextjsBootstrapTransitionRecord {
            from,
            to,
            trigger,
            detail,
        });
    }
}

impl Default for NextjsBootstrapState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Suspense, Transitions, and Async Boundary Integration
// ---------------------------------------------------------------------------
//
// These types define how WASM runtime outcomes map to React's async
// rendering primitives:
//
// 1. **Suspense integration**: A running task maps to the "pending" state
//    of a Suspense boundary. Task completion resolves the boundary; task
//    failure triggers the nearest error boundary.
//
// 2. **Error boundary mapping**: Runtime outcomes (Err, Panic, Cancelled)
//    each have distinct error boundary behavior. Panics are always fatal;
//    errors may be retryable; cancellation is not an error (silent unmount).
//
// 3. **Transitions (startTransition)**: Tasks spawned within a transition
//    keep the old UI visible until completion. Cancellation of a transition
//    task reverts cleanly without UI flash.
//
// 4. **Progressive data loading**: Multiple tasks can feed a single Suspense
//    boundary, with partial results rendered as they arrive. The boundary
//    resolves when all required tasks complete.

/// How a WASM runtime outcome maps to a React Suspense boundary state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspenseBoundaryState {
    /// Task is running; Suspense shows fallback UI.
    Pending,
    /// Task completed successfully; Suspense reveals content.
    Resolved,
    /// Task failed with a recoverable error; nearest error boundary triggered.
    ErrorRecoverable,
    /// Task panicked; nearest error boundary triggered with fatal flag.
    ErrorFatal,
    /// Task was cancelled (unmount, dep change, race loser).
    /// Not an error — Suspense boundary simply unmounts or reverts.
    Cancelled,
}

/// Maps a `WasmAbiOutcomeEnvelope` to the appropriate Suspense boundary state.
#[must_use]
pub fn outcome_to_suspense_state(outcome: &WasmAbiOutcomeEnvelope) -> SuspenseBoundaryState {
    match outcome {
        WasmAbiOutcomeEnvelope::Ok { .. } => SuspenseBoundaryState::Resolved,
        WasmAbiOutcomeEnvelope::Err { failure } => match failure.recoverability {
            WasmAbiRecoverability::Permanent => SuspenseBoundaryState::ErrorFatal,
            WasmAbiRecoverability::Transient | WasmAbiRecoverability::Unknown => {
                SuspenseBoundaryState::ErrorRecoverable
            }
        },
        WasmAbiOutcomeEnvelope::Cancelled { .. } => SuspenseBoundaryState::Cancelled,
        WasmAbiOutcomeEnvelope::Panicked { .. } => SuspenseBoundaryState::ErrorFatal,
    }
}

/// Error boundary behavior for different outcome types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorBoundaryAction {
    /// No error boundary involvement (success or cancellation).
    None,
    /// Show error UI with retry option.
    ShowWithRetry,
    /// Show error UI without retry (permanent failure).
    ShowFatal,
    /// Reset the error boundary (e.g., after successful retry).
    Reset,
}

/// Maps a `WasmAbiOutcomeEnvelope` to the appropriate error boundary action.
#[must_use]
pub fn outcome_to_error_boundary_action(outcome: &WasmAbiOutcomeEnvelope) -> ErrorBoundaryAction {
    match outcome {
        WasmAbiOutcomeEnvelope::Ok { .. } | WasmAbiOutcomeEnvelope::Cancelled { .. } => {
            ErrorBoundaryAction::None
        }
        WasmAbiOutcomeEnvelope::Err { failure } => match failure.recoverability {
            WasmAbiRecoverability::Permanent => ErrorBoundaryAction::ShowFatal,
            WasmAbiRecoverability::Transient | WasmAbiRecoverability::Unknown => {
                ErrorBoundaryAction::ShowWithRetry
            }
        },
        WasmAbiOutcomeEnvelope::Panicked { .. } => ErrorBoundaryAction::ShowFatal,
    }
}

/// Context for a React transition (`startTransition`) that wraps runtime work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTaskState {
    /// Transition started; old UI remains visible.
    Pending,
    /// Task completed; transition commits new UI.
    Committed,
    /// Task failed; transition reverts to old UI.
    Reverted,
    /// Task cancelled; transition reverts cleanly.
    Cancelled,
}

/// Maps a `WasmAbiOutcomeEnvelope` to a transition task state.
#[must_use]
pub fn outcome_to_transition_state(outcome: &WasmAbiOutcomeEnvelope) -> TransitionTaskState {
    match outcome {
        WasmAbiOutcomeEnvelope::Ok { .. } => TransitionTaskState::Committed,
        WasmAbiOutcomeEnvelope::Err { .. } | WasmAbiOutcomeEnvelope::Panicked { .. } => {
            TransitionTaskState::Reverted
        }
        WasmAbiOutcomeEnvelope::Cancelled { .. } => TransitionTaskState::Cancelled,
    }
}

/// Configuration for Suspense-integrated task execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspenseTaskConfig {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// Whether this task participates in a `startTransition`.
    pub is_transition: bool,
    /// Whether the Suspense boundary should show fallback on retry.
    pub show_fallback_on_retry: bool,
    /// Maximum number of automatic retries for transient errors.
    pub max_retries: u32,
}

impl Default for SuspenseTaskConfig {
    fn default() -> Self {
        Self {
            label: "suspense-task".to_string(),
            is_transition: false,
            show_fallback_on_retry: true,
            max_retries: 0,
        }
    }
}

/// Tracks the state of a task integrated with a Suspense boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspenseTaskSnapshot {
    /// Task configuration.
    pub config: SuspenseTaskConfig,
    /// Current Suspense boundary state.
    pub boundary_state: SuspenseBoundaryState,
    /// Error boundary action (if any).
    pub error_action: ErrorBoundaryAction,
    /// Transition state (if this is a transition task).
    pub transition_state: Option<TransitionTaskState>,
    /// Handle to the underlying WASM task.
    pub task_handle: Option<WasmHandleRef>,
    /// Number of retries attempted.
    pub retry_count: u32,
    /// Whether the task is currently retrying (re-thrown promise).
    pub is_retrying: bool,
}

/// Progressive loading slot within a Suspense boundary.
///
/// Models one data source in a multi-source Suspense boundary where
/// partial results render as they arrive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressiveLoadSlot {
    /// Slot label for diagnostics.
    pub label: String,
    /// Whether this slot is required for boundary resolution.
    pub required: bool,
    /// Current Suspense state for this slot.
    pub state: SuspenseBoundaryState,
    /// Handle to the underlying task.
    pub task_handle: Option<WasmHandleRef>,
}

/// Snapshot of a multi-source progressive loading Suspense boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressiveLoadSnapshot {
    /// All loading slots.
    pub slots: Vec<ProgressiveLoadSlot>,
    /// Overall boundary state (Pending if any required slot is Pending).
    pub overall_state: SuspenseBoundaryState,
}

impl ProgressiveLoadSnapshot {
    /// Computes the overall boundary state from individual slots.
    #[must_use]
    pub fn compute_overall_state(slots: &[ProgressiveLoadSlot]) -> SuspenseBoundaryState {
        let mut has_pending_required = false;
        let mut has_fatal = false;
        let mut has_recoverable_error = false;

        for slot in slots {
            if !slot.required {
                continue;
            }
            match slot.state {
                SuspenseBoundaryState::Pending => has_pending_required = true,
                SuspenseBoundaryState::ErrorFatal => has_fatal = true,
                SuspenseBoundaryState::ErrorRecoverable => has_recoverable_error = true,
                SuspenseBoundaryState::Resolved | SuspenseBoundaryState::Cancelled => {}
            }
        }

        if has_fatal {
            SuspenseBoundaryState::ErrorFatal
        } else if has_recoverable_error {
            SuspenseBoundaryState::ErrorRecoverable
        } else if has_pending_required {
            SuspenseBoundaryState::Pending
        } else {
            SuspenseBoundaryState::Resolved
        }
    }
}

/// Diagnostic event for Suspense/transition integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspenseDiagnosticEvent {
    /// Task label.
    pub label: String,
    /// Previous boundary state.
    pub from_state: SuspenseBoundaryState,
    /// New boundary state.
    pub to_state: SuspenseBoundaryState,
    /// Whether this was a transition task.
    pub is_transition: bool,
    /// Error boundary action taken.
    pub error_action: ErrorBoundaryAction,
    /// Handle involved.
    pub task_handle: Option<WasmHandleRef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CancelKind, CancelReason, PanicPayload, RegionId, Time};

    fn close_handle_for_release(table: &mut WasmHandleTable, handle: &WasmHandleRef) {
        match table.get(handle).unwrap().state {
            WasmBoundaryState::Unbound => {
                table.transition(handle, WasmBoundaryState::Bound).unwrap();
                table.transition(handle, WasmBoundaryState::Closed).unwrap();
            }
            WasmBoundaryState::Bound
            | WasmBoundaryState::Active
            | WasmBoundaryState::Cancelling
            | WasmBoundaryState::Draining => {
                table.transition(handle, WasmBoundaryState::Closed).unwrap();
            }
            WasmBoundaryState::Closed => {}
        }
    }

    #[test]
    fn abi_compatibility_rules_enforced() {
        let exact = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 2 },
            WasmAbiVersion { major: 1, minor: 2 },
        );
        assert_eq!(exact, WasmAbiCompatibilityDecision::Exact);
        assert!(exact.is_compatible());

        let backward = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 2 },
            WasmAbiVersion { major: 1, minor: 5 },
        );
        assert!(matches!(
            backward,
            WasmAbiCompatibilityDecision::BackwardCompatible {
                producer_minor: 2,
                consumer_minor: 5
            }
        ));
        assert!(backward.is_compatible());

        let old_consumer = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 3 },
            WasmAbiVersion { major: 1, minor: 2 },
        );
        assert!(matches!(
            old_consumer,
            WasmAbiCompatibilityDecision::ConsumerTooOld {
                producer_minor: 3,
                consumer_minor: 2
            }
        ));
        assert!(!old_consumer.is_compatible());

        let major_mismatch = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 0 },
            WasmAbiVersion { major: 2, minor: 0 },
        );
        assert!(matches!(
            major_mismatch,
            WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2
            }
        ));
        assert!(!major_mismatch.is_compatible());
    }

    #[test]
    fn change_class_maps_to_required_version_bump() {
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::AdditiveField),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::AdditiveSymbol),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::BehavioralRelaxation),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::BehavioralTightening),
            WasmAbiVersionBump::Major
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::SymbolRemoval),
            WasmAbiVersionBump::Major
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::ValueEncodingChange),
            WasmAbiVersionBump::Major
        );
    }

    #[test]
    fn signature_fingerprint_matches_expected_v1() {
        let fingerprint = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
        assert_eq!(
            fingerprint, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
            "ABI signature drift detected; update version policy and migration notes first"
        );
    }

    #[test]
    fn cancellation_payload_maps_core_reason_fields() {
        let reason = CancelReason::with_origin(
            CancelKind::Timeout,
            RegionId::new_for_test(3, 7),
            Time::from_nanos(42),
        )
        .with_task(crate::types::TaskId::new_for_test(4, 1))
        .with_message("deadline exceeded");

        let encoded = WasmAbiCancellation::from_reason(&reason, CancelPhase::Cancelling);

        assert_eq!(encoded.kind, "timeout");
        assert_eq!(encoded.phase, "cancelling");
        assert_eq!(encoded.timestamp_nanos, 42);
        assert_eq!(encoded.message.as_deref(), Some("deadline exceeded"));
        assert_eq!(encoded.origin_region, "R3");
        assert_eq!(encoded.origin_task.as_deref(), Some("T4"));
    }

    #[test]
    fn abort_signal_event_propagates_to_runtime_when_configured() {
        let snapshot = WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::AbortSignalToRuntime,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        };

        let update = apply_abort_signal_event(snapshot);
        assert_eq!(update.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(update.abort_signal_aborted);
        assert!(update.propagated_to_runtime);
        assert!(!update.propagated_to_abort_signal);

        let repeated = apply_abort_signal_event(WasmAbortInteropSnapshot {
            mode: snapshot.mode,
            boundary_state: update.next_boundary_state,
            abort_signal_aborted: update.abort_signal_aborted,
        });
        assert_eq!(repeated.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(repeated.abort_signal_aborted);
        assert!(!repeated.propagated_to_runtime);
        assert!(!repeated.propagated_to_abort_signal);
    }

    #[test]
    fn runtime_cancel_phase_event_maps_to_abort_signal_and_state() {
        let requested = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: WasmBoundaryState::Active,
                abort_signal_aborted: false,
            },
            CancelPhase::Requested,
        );
        assert_eq!(requested.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(requested.abort_signal_aborted);
        assert!(requested.propagated_to_abort_signal);
        assert!(!requested.propagated_to_runtime);

        let finalizing = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: requested.next_boundary_state,
                abort_signal_aborted: requested.abort_signal_aborted,
            },
            CancelPhase::Finalizing,
        );
        assert_eq!(finalizing.next_boundary_state, WasmBoundaryState::Draining);
        assert!(finalizing.abort_signal_aborted);
        assert!(!finalizing.propagated_to_abort_signal);

        let completed = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: finalizing.next_boundary_state,
                abort_signal_aborted: finalizing.abort_signal_aborted,
            },
            CancelPhase::Completed,
        );
        assert_eq!(completed.next_boundary_state, WasmBoundaryState::Closed);
        assert!(completed.abort_signal_aborted);
    }

    #[test]
    fn bidirectional_mode_keeps_already_aborted_signal_idempotent() {
        let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::Bidirectional,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: true,
        });
        assert_eq!(update.next_boundary_state, WasmBoundaryState::Active);
        assert!(update.abort_signal_aborted);
        assert!(!update.propagated_to_runtime);
    }

    #[test]
    fn outcome_envelope_serialization_round_trip() {
        let handle = WasmHandleRef {
            kind: WasmHandleKind::Task,
            slot: 11,
            generation: 2,
        };
        let ok = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        };
        let ok_json = serde_json::to_string(&ok).expect("serialize ok");
        let ok_back: WasmAbiOutcomeEnvelope =
            serde_json::from_str(&ok_json).expect("deserialize ok");
        assert_eq!(ok, ok_back);

        let err = WasmAbiOutcomeEnvelope::Err {
            failure: WasmAbiFailure {
                code: WasmAbiErrorCode::CapabilityDenied,
                recoverability: WasmAbiRecoverability::Permanent,
                message: "missing fetch capability".to_string(),
            },
        };
        let err_json = serde_json::to_string(&err).expect("serialize err");
        let err_back: WasmAbiOutcomeEnvelope =
            serde_json::from_str(&err_json).expect("deserialize err");
        assert_eq!(err, err_back);
    }

    #[test]
    fn from_outcome_maps_cancel_and_panic_variants() {
        let cancel_reason = CancelReason::with_origin(
            CancelKind::ParentCancelled,
            RegionId::new_for_test(9, 1),
            Time::from_nanos(9_000),
        );
        let cancelled = WasmAbiOutcomeEnvelope::from_outcome(Outcome::cancelled(cancel_reason));
        assert!(matches!(
            cancelled,
            WasmAbiOutcomeEnvelope::Cancelled {
                cancellation: WasmAbiCancellation {
                    kind,
                    phase,
                    ..
                }
            } if kind == "parentcancelled" && phase == "completed"
        ));

        let panicked = WasmAbiOutcomeEnvelope::from_outcome(Outcome::Panicked(PanicPayload::new(
            "boundary panic",
        )));
        assert_eq!(
            panicked,
            WasmAbiOutcomeEnvelope::Panicked {
                message: "boundary panic".to_string(),
            }
        );
    }

    #[test]
    fn boundary_transition_validator_accepts_and_rejects_expected_paths() {
        assert!(
            validate_wasm_boundary_transition(WasmBoundaryState::Unbound, WasmBoundaryState::Bound)
                .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(WasmBoundaryState::Bound, WasmBoundaryState::Active)
                .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Active,
                WasmBoundaryState::Cancelling
            )
            .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Cancelling,
                WasmBoundaryState::Draining
            )
            .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Draining,
                WasmBoundaryState::Closed
            )
            .is_ok()
        );

        let invalid =
            validate_wasm_boundary_transition(WasmBoundaryState::Closed, WasmBoundaryState::Active);
        assert!(matches!(
            invalid,
            Err(WasmBoundaryTransitionError::Invalid {
                from: WasmBoundaryState::Closed,
                to: WasmBoundaryState::Active
            })
        ));
    }

    #[test]
    fn boundary_event_log_fields_include_contract_keys() {
        let event = WasmAbiBoundaryEvent {
            abi_version: WasmAbiVersion::CURRENT,
            symbol: WasmAbiSymbol::FetchRequest,
            payload_shape: WasmAbiPayloadShape::FetchRequestV1,
            state_from: WasmBoundaryState::Active,
            state_to: WasmBoundaryState::Cancelling,
            compatibility: WasmAbiCompatibilityDecision::Exact,
        };

        let fields = event.as_log_fields();
        assert_eq!(fields.get("abi_version"), Some(&"1.0".to_string()));
        assert_eq!(fields.get("symbol"), Some(&"fetch_request".to_string()));
        assert!(fields.contains_key("payload_shape"));
        assert!(fields.contains_key("state_from"));
        assert!(fields.contains_key("state_to"));
        assert!(fields.contains_key("compatibility"));
        assert_eq!(fields.get("compatibility"), Some(&"exact".to_string()));
        assert_eq!(
            fields.get("compatibility_decision"),
            Some(&"exact".to_string())
        );
        assert_eq!(
            fields.get("compatibility_compatible"),
            Some(&"true".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_minor"),
            Some(&"0".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_minor"),
            Some(&"0".to_string())
        );
    }

    #[test]
    fn major_mismatch_log_fields_include_major_only_details() {
        let event = WasmAbiBoundaryEvent {
            abi_version: WasmAbiVersion::CURRENT,
            symbol: WasmAbiSymbol::RuntimeCreate,
            payload_shape: WasmAbiPayloadShape::Empty,
            state_from: WasmBoundaryState::Unbound,
            state_to: WasmBoundaryState::Bound,
            compatibility: WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2,
            },
        };

        let fields = event.as_log_fields();
        assert_eq!(
            fields.get("compatibility_decision"),
            Some(&"major_mismatch".to_string())
        );
        assert_eq!(
            fields.get("compatibility_compatible"),
            Some(&"false".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_major"),
            Some(&"2".to_string())
        );
        assert!(!fields.contains_key("compatibility_producer_minor"));
        assert!(!fields.contains_key("compatibility_consumer_minor"));
    }

    // -----------------------------------------------------------------------
    // Memory Ownership Protocol Tests
    // -----------------------------------------------------------------------

    #[test]
    fn handle_table_allocate_and_get() {
        let mut table = WasmHandleTable::new();
        assert_eq!(table.live_count(), 0);

        let h1 = table.allocate(WasmHandleKind::Runtime);
        assert_eq!(h1.slot, 0);
        assert_eq!(h1.generation, 0);
        assert_eq!(h1.kind, WasmHandleKind::Runtime);
        assert_eq!(table.live_count(), 1);

        let entry = table.get(&h1).unwrap();
        assert_eq!(entry.state, WasmBoundaryState::Unbound);
        assert_eq!(entry.ownership, WasmHandleOwnership::WasmOwned);
        assert!(!entry.pinned);

        let h2 = table.allocate(WasmHandleKind::Task);
        assert_eq!(h2.slot, 1);
        assert_eq!(table.live_count(), 2);
    }

    #[test]
    fn handle_table_full_lifecycle() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Region);

        // Unbound -> Bound -> Active -> Cancelling -> Draining -> Closed
        table.transition(&h, WasmBoundaryState::Bound).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Bound);

        table.transition(&h, WasmBoundaryState::Active).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Active);

        table.transition(&h, WasmBoundaryState::Cancelling).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Cancelling);

        table.transition(&h, WasmBoundaryState::Draining).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Draining);

        table.transition(&h, WasmBoundaryState::Closed).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Closed);

        // Release the closed handle
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn handle_table_slot_recycling_with_generation_bump() {
        let mut table = WasmHandleTable::new();
        let h1 = table.allocate(WasmHandleKind::Task);
        assert_eq!(h1.slot, 0);
        assert_eq!(h1.generation, 0);

        // Release h1
        close_handle_for_release(&mut table, &h1);
        table.release(&h1).unwrap();

        // Allocate again — should reuse slot 0 with bumped generation
        let h2 = table.allocate(WasmHandleKind::Region);
        assert_eq!(h2.slot, 0);
        assert_eq!(h2.generation, 1);

        // h1 is now stale
        let err = table.get(&h1).unwrap_err();
        assert!(matches!(
            err,
            WasmHandleError::StaleGeneration {
                slot: 0,
                expected: 1,
                actual: 0,
            }
        ));

        // h2 is valid
        assert!(table.get(&h2).is_ok());
    }

    #[test]
    fn handle_table_stale_handle_rejected() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::CancelToken);
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();

        // Try to use released handle
        let err = table.get(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
    }

    #[test]
    fn handle_table_out_of_range() {
        let table = WasmHandleTable::new();
        let fake = WasmHandleRef {
            kind: WasmHandleKind::Runtime,
            slot: 999,
            generation: 0,
        };
        let err = table.get(&fake).unwrap_err();
        assert!(matches!(
            err,
            WasmHandleError::SlotOutOfRange {
                slot: 999,
                table_size: 0,
            }
        ));
    }

    #[test]
    fn handle_table_pin_unpin() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);

        // Pin
        table.pin(&h).unwrap();
        assert!(table.get(&h).unwrap().pinned);

        // Pinning again is idempotent
        table.pin(&h).unwrap();
        assert!(table.get(&h).unwrap().pinned);

        // Cannot release while pinned
        let err = table.release(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::ReleasePinned { slot: 0 }));

        // Unpin
        table.unpin(&h).unwrap();
        assert!(!table.get(&h).unwrap().pinned);

        // Can release after unpin
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn handle_table_unpin_not_pinned_is_error() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Runtime);

        let err = table.unpin(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::NotPinned { slot: 0 }));
    }

    #[test]
    fn handle_table_transfer_to_js() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::FetchRequest);

        table.transfer_to_js(&h).unwrap();
        assert_eq!(
            table.get(&h).unwrap().ownership,
            WasmHandleOwnership::TransferredToJs
        );

        // Cannot transfer again
        let err = table.transfer_to_js(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::InvalidTransfer { .. }));
    }

    #[test]
    fn handle_table_detect_leaks() {
        let mut table = WasmHandleTable::new();
        let h1 = table.allocate(WasmHandleKind::Task);
        let h2 = table.allocate(WasmHandleKind::Region);
        let h3 = table.allocate(WasmHandleKind::Runtime);

        // h1: close but don't release (leaked)
        table.transition(&h1, WasmBoundaryState::Bound).unwrap();
        table.transition(&h1, WasmBoundaryState::Closed).unwrap();

        // h2: still active (not leaked yet)
        table.transition(&h2, WasmBoundaryState::Bound).unwrap();
        table.transition(&h2, WasmBoundaryState::Active).unwrap();

        // h3: properly released
        close_handle_for_release(&mut table, &h3);
        table.release(&h3).unwrap();

        let leaks = table.detect_leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0], h1);
    }

    #[test]
    fn handle_table_memory_report() {
        let mut table = WasmHandleTable::with_capacity(8);
        let h1 = table.allocate(WasmHandleKind::Runtime);
        let h2 = table.allocate(WasmHandleKind::Task);
        let _h3 = table.allocate(WasmHandleKind::Task);

        table.transition(&h1, WasmBoundaryState::Bound).unwrap();
        table.transition(&h1, WasmBoundaryState::Active).unwrap();
        table.pin(&h2).unwrap();

        let report = table.memory_report();
        assert_eq!(report.live_handles, 3);
        assert_eq!(report.pinned_count, 1);
        assert_eq!(report.by_kind.get("task"), Some(&2));
        assert_eq!(report.by_kind.get("runtime"), Some(&1));

        // _h3 is still unbound
        assert_eq!(report.by_state.get("unbound"), Some(&2));
        assert_eq!(report.by_state.get("active"), Some(&1));
    }

    #[test]
    fn handle_table_release_already_released() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();

        // Stale generation
        let err = table.release(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
    }

    #[test]
    fn handle_table_release_requires_closed_and_quiescent_state() {
        let mut table = WasmHandleTable::new();
        let root = table.allocate(WasmHandleKind::Runtime);
        let child = table.allocate_with_parent(WasmHandleKind::Task, Some(root));

        let err = table.release(&root).unwrap_err();
        assert_eq!(
            err,
            WasmHandleError::ReleaseBeforeClosed {
                slot: root.slot,
                state: WasmBoundaryState::Unbound,
            }
        );
        assert_eq!(table.live_count(), 2);

        close_handle_for_release(&mut table, &root);
        let err = table.release(&root).unwrap_err();
        assert_eq!(
            err,
            WasmHandleError::ReleaseWithLiveDescendants {
                slot: root.slot,
                live_descendants: 1,
            }
        );
        assert_eq!(table.live_count(), 2);

        close_handle_for_release(&mut table, &child);
        table.release(&child).unwrap();
        table.release(&root).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn buffer_transfer_mode_copy_is_default() {
        assert!(WasmBufferTransferMode::Copy.is_copy());
        assert!(!WasmBufferTransferMode::Transfer.is_copy());
    }

    #[test]
    fn buffer_transfer_serialization_round_trip() {
        let transfer = WasmBufferTransfer {
            source_handle: WasmHandleRef {
                kind: WasmHandleKind::FetchRequest,
                slot: 5,
                generation: 2,
            },
            byte_length: 1024,
            mode: WasmBufferTransferMode::Transfer,
        };
        let json = serde_json::to_string(&transfer).unwrap();
        let back: WasmBufferTransfer = serde_json::from_str(&json).unwrap();
        assert_eq!(transfer, back);
    }

    #[test]
    fn handle_ownership_serialization_round_trip() {
        for ownership in [
            WasmHandleOwnership::WasmOwned,
            WasmHandleOwnership::TransferredToJs,
            WasmHandleOwnership::Released,
        ] {
            let json = serde_json::to_string(&ownership).unwrap();
            let back: WasmHandleOwnership = serde_json::from_str(&json).unwrap();
            assert_eq!(ownership, back);
        }
    }

    #[test]
    fn handle_lifecycle_event_captures_transitions() {
        let event = WasmHandleLifecycleEvent {
            handle: WasmHandleRef {
                kind: WasmHandleKind::Task,
                slot: 3,
                generation: 0,
            },
            event: WasmHandleEventKind::StateTransition,
            ownership_before: WasmHandleOwnership::WasmOwned,
            ownership_after: WasmHandleOwnership::WasmOwned,
            state_before: WasmBoundaryState::Active,
            state_after: WasmBoundaryState::Cancelling,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: WasmHandleLifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn handle_table_cancellation_and_release_flow() {
        // Simulates a typical task lifecycle: create → activate → cancel → drain → close → release
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);

        table.transition(&h, WasmBoundaryState::Bound).unwrap();
        table.transition(&h, WasmBoundaryState::Active).unwrap();

        // Pin during active work
        table.pin(&h).unwrap();

        // Cancel arrives
        table.transition(&h, WasmBoundaryState::Cancelling).unwrap();
        table.transition(&h, WasmBoundaryState::Draining).unwrap();
        table.transition(&h, WasmBoundaryState::Closed).unwrap();

        // Still pinned — cannot release
        assert!(table.release(&h).is_err());

        // Unpin and release
        table.unpin(&h).unwrap();
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
        assert!(table.detect_leaks().is_empty());
    }

    #[test]
    fn handle_table_with_capacity_preallocates() {
        let table = WasmHandleTable::with_capacity(16);
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.capacity(), 0); // No actual slots until allocated
    }

    // -----------------------------------------------------------------------
    // Export Dispatcher Conformance Tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatcher_runtime_create_and_close_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        assert_eq!(d.dispatch_count(), 0);

        let rt = d.runtime_create(None).unwrap();
        assert_eq!(rt.kind, WasmHandleKind::Runtime);
        assert_eq!(d.dispatch_count(), 1);
        assert_eq!(d.handles().live_count(), 1);

        let outcome = d.runtime_close(&rt, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.dispatch_count(), 2);
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_scope_enter_and_close() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("test-scope".to_string()),
                },
                None,
            )
            .unwrap();
        assert_eq!(scope.kind, WasmHandleKind::Region);
        assert_eq!(d.handles().live_count(), 2);

        let outcome = d.scope_close(&scope, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.handles().live_count(), 1); // runtime still alive

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_runtime_close_releases_descendants() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("runtime-close".to_string()),
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("worker".to_string()),
                    cancel_kind: Some("user".to_string()),
                },
                None,
            )
            .unwrap();
        let fetch = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://example.com/data".to_string(),
                    method: "GET".to_string(),
                    body: None,
                },
                None,
            )
            .unwrap();

        let outcome = d.runtime_close(&rt, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.handles().live_count(), 0);
        assert!(d.handles().get(&scope).is_err());
        assert!(d.handles().get(&task).is_err());
        assert!(d.handles().get(&fetch).is_err());
        assert!(d.handles().detect_leaks().is_empty());
    }

    #[test]
    fn dispatcher_scope_close_releases_nested_descendants() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let outer = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("outer".to_string()),
                },
                None,
            )
            .unwrap();
        let inner = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: outer,
                    label: Some("inner".to_string()),
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: inner,
                    label: Some("nested".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let outcome = d.scope_close(&outer, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert!(d.handles().get(&inner).is_err());
        assert!(d.handles().get(&task).is_err());
        assert_eq!(d.handles().live_count(), 1);

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_task_spawn_join_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("worker".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(task.kind, WasmHandleKind::Task);
        assert!(d.handles().get(&task).unwrap().pinned); // tasks are auto-pinned

        let result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
                None,
            )
            .unwrap();
        assert!(matches!(
            result,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::I64(42)
            }
        ));

        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_task_cancel_flow() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Cancel the active task
        let cancel_result = d
            .task_cancel(
                &WasmTaskCancelRequest {
                    task,
                    kind: "user".to_string(),
                    message: Some("user requested".to_string()),
                },
                None,
            )
            .unwrap();
        assert!(matches!(cancel_result, WasmAbiOutcomeEnvelope::Ok { .. }));

        // Task is now Cancelling
        assert_eq!(
            d.handles().get(&task).unwrap().state,
            WasmBoundaryState::Cancelling
        );

        // Join with cancelled outcome
        let join_result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Cancelled {
                    cancellation: WasmAbiCancellation {
                        kind: "user".to_string(),
                        phase: "completed".to_string(),
                        origin_region: "R0".to_string(),
                        origin_task: None,
                        timestamp_nanos: 0,
                        message: Some("user requested".to_string()),
                        truncated: false,
                    },
                },
                None,
            )
            .unwrap();
        assert!(matches!(
            join_result,
            WasmAbiOutcomeEnvelope::Cancelled { .. }
        ));
        assert_eq!(d.handles().live_count(), 1); // only runtime left

        d.runtime_close(&rt, None).unwrap();
    }

    #[test]
    fn dispatcher_abi_incompatible_rejected() {
        let mut d = WasmExportDispatcher::new();
        let bad_version = WasmAbiVersion {
            major: 99,
            minor: 0,
        };

        let err = d.runtime_create(Some(bad_version)).unwrap_err();
        assert!(matches!(err, WasmDispatchError::Incompatible { .. }));

        // Error converts to proper failure envelope
        let failure = err.to_failure();
        assert_eq!(failure.code, WasmAbiErrorCode::CompatibilityRejected);
        assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
    }

    #[test]
    fn dispatcher_stale_handle_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        // Try to close again — handle is stale
        let err = d.runtime_close(&rt, None).unwrap_err();
        assert!(matches!(err, WasmDispatchError::Handle(_)));
    }

    #[test]
    fn dispatcher_scope_enter_requires_active_parent() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        // Try to enter scope on closed runtime — stale handle
        let err = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::Handle(_)));
    }

    #[test]
    fn dispatcher_task_spawn_wrong_handle_kind_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        // Spawn a task
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Try to spawn under a Task handle (not Region/Runtime)
        let err = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: task,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_cancel_non_active_task_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Cancel once (should succeed)
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "user".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();

        // Cancel again — task is now Cancelling, not Active
        let err = d
            .task_cancel(
                &WasmTaskCancelRequest {
                    task,
                    kind: "user".to_string(),
                    message: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidState { .. }));
    }

    #[test]
    fn dispatcher_fetch_request_and_complete() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();

        let fetch = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://example.com/api".to_string(),
                    method: "GET".to_string(),
                    body: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(fetch.kind, WasmHandleKind::FetchRequest);
        assert!(d.handles().get(&fetch).unwrap().pinned);

        let result = d
            .fetch_complete(
                &fetch,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::String("response body".to_string()),
                },
            )
            .unwrap();
        assert!(matches!(result, WasmAbiOutcomeEnvelope::Ok { .. }));
        // Fetch handle released after completion
        assert!(d.handles().get(&fetch).is_err());
    }

    #[test]
    fn dispatcher_fetch_empty_url_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let err = d
            .fetch_request(
                &WasmFetchRequest {
                    scope: rt,
                    url: String::new(),
                    method: "GET".to_string(),
                    body: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_event_log_records_all_symbol_calls() {
        let mut d = WasmExportDispatcher::new();

        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "timeout".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        let events = d.event_log().events();
        assert_eq!(events.len(), 7);
        assert_eq!(events[0].symbol, WasmAbiSymbol::RuntimeCreate);
        assert_eq!(events[1].symbol, WasmAbiSymbol::ScopeEnter);
        assert_eq!(events[2].symbol, WasmAbiSymbol::TaskSpawn);
        assert_eq!(events[3].symbol, WasmAbiSymbol::TaskCancel);
        assert_eq!(events[4].symbol, WasmAbiSymbol::TaskJoin);
        assert_eq!(events[5].symbol, WasmAbiSymbol::ScopeClose);
        assert_eq!(events[6].symbol, WasmAbiSymbol::RuntimeClose);
    }

    #[test]
    fn dispatcher_event_log_drain_clears() {
        let mut d = WasmExportDispatcher::new();
        d.runtime_create(None).unwrap();

        assert_eq!(d.event_log().len(), 1);
        let drained = d.event_log_mut().drain();
        assert_eq!(drained.len(), 1);
        assert!(d.event_log().is_empty());
    }

    #[test]
    fn dispatcher_dispatch_count_increments_on_errors() {
        let mut d = WasmExportDispatcher::new();

        // Failing call still increments dispatch count
        let _ = d.runtime_create(Some(WasmAbiVersion {
            major: 99,
            minor: 0,
        }));
        assert_eq!(d.dispatch_count(), 1);
    }

    #[test]
    fn dispatcher_abort_signal_propagation() {
        let mut d =
            WasmExportDispatcher::new().with_abort_mode(WasmAbortPropagationMode::Bidirectional);
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Apply abort signal
        let update = d.apply_abort(&task).unwrap();
        assert!(update.propagated_to_runtime);
        assert_eq!(
            d.handles().get(&task).unwrap().state,
            WasmBoundaryState::Cancelling
        );
    }

    #[test]
    fn dispatcher_full_multi_task_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("multi-task".to_string()),
                },
                None,
            )
            .unwrap();

        // Spawn multiple tasks
        let t1 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t1".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        let t2 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t2".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        let t3 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t3".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        assert_eq!(d.handles().live_count(), 5); // rt + scope + 3 tasks

        // Complete t1, cancel t2, join t3
        d.task_join(
            &t1,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::I64(1),
            },
            None,
        )
        .unwrap();
        d.task_cancel(
            &WasmTaskCancelRequest {
                task: t2,
                kind: "race_lost".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &t2,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &t3,
            WasmAbiOutcomeEnvelope::Err {
                failure: WasmAbiFailure {
                    code: WasmAbiErrorCode::InternalFailure,
                    recoverability: WasmAbiRecoverability::Transient,
                    message: "transient failure".to_string(),
                },
            },
            None,
        )
        .unwrap();

        assert_eq!(d.handles().live_count(), 2); // rt + scope

        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
        assert!(d.handles().detect_leaks().is_empty());
    }

    #[test]
    fn dispatcher_high_frequency_invocation_stress() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        // Rapid-fire 100 task spawn/join cycles
        for i in 0u64..100 {
            let task = d
                .task_spawn(
                    &WasmTaskSpawnRequest {
                        scope: rt,
                        label: Some(format!("task-{i}")),
                        cancel_kind: None,
                    },
                    None,
                )
                .unwrap();
            d.task_join(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::U64(i),
                },
                None,
            )
            .unwrap();
        }

        assert_eq!(d.dispatch_count(), 201); // 1 create + 100 spawns + 100 joins
        assert_eq!(d.handles().live_count(), 1); // only runtime
        assert!(d.handles().detect_leaks().is_empty());

        // Verify slot recycling worked — capacity should be much less than 100
        let report = d.handles().memory_report();
        assert!(report.capacity <= 100);

        d.runtime_close(&rt, None).unwrap();
    }

    #[test]
    fn dispatcher_error_to_outcome_envelope_conversion() {
        let errors = [
            WasmDispatchError::Incompatible {
                decision: WasmAbiCompatibilityDecision::MajorMismatch {
                    producer_major: 1,
                    consumer_major: 2,
                },
            },
            WasmDispatchError::Handle(WasmHandleError::SlotOutOfRange {
                slot: 5,
                table_size: 3,
            }),
            WasmDispatchError::InvalidState {
                state: WasmBoundaryState::Closed,
                symbol: WasmAbiSymbol::TaskSpawn,
            },
            WasmDispatchError::InvalidRequest {
                reason: "bad payload".to_string(),
            },
        ];

        let expected_codes = [
            WasmAbiErrorCode::CompatibilityRejected,
            WasmAbiErrorCode::InvalidHandle,
            WasmAbiErrorCode::InvalidHandle,
            WasmAbiErrorCode::DecodeFailure,
        ];

        for (err, expected_code) in errors.iter().zip(expected_codes.iter()) {
            let outcome = err.to_outcome();
            match outcome {
                WasmAbiOutcomeEnvelope::Err { failure } => {
                    assert_eq!(failure.code, *expected_code);
                    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
                    assert!(!failure.message.is_empty());
                }
                _ => panic!("expected Err outcome"),
            }
        }
    }

    #[test]
    fn dispatcher_backward_compatible_version_accepted() {
        let mut d = WasmExportDispatcher::new();
        // Consumer with higher minor version (backward compatible)
        let compat_version = WasmAbiVersion {
            major: WASM_ABI_MAJOR_VERSION,
            minor: WASM_ABI_MINOR_VERSION + 5,
        };

        let rt = d.runtime_create(Some(compat_version)).unwrap();
        assert_eq!(rt.kind, WasmHandleKind::Runtime);

        // Check that the event recorded the compatibility decision
        let event = &d.event_log().events()[0];
        assert!(matches!(
            event.compatibility,
            WasmAbiCompatibilityDecision::BackwardCompatible { .. }
        ));
    }

    #[test]
    fn dispatcher_request_payload_serialization_round_trip() {
        let scope_req = WasmScopeEnterRequest {
            parent: WasmHandleRef {
                kind: WasmHandleKind::Runtime,
                slot: 0,
                generation: 0,
            },
            label: Some("test".to_string()),
        };
        let json = serde_json::to_string(&scope_req).unwrap();
        let back: WasmScopeEnterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(scope_req, back);

        let spawn_req = WasmTaskSpawnRequest {
            scope: WasmHandleRef {
                kind: WasmHandleKind::Region,
                slot: 1,
                generation: 0,
            },
            label: Some("worker".to_string()),
            cancel_kind: Some("timeout".to_string()),
        };
        let json = serde_json::to_string(&spawn_req).unwrap();
        let back: WasmTaskSpawnRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(spawn_req, back);

        let cancel_req = WasmTaskCancelRequest {
            task: WasmHandleRef {
                kind: WasmHandleKind::Task,
                slot: 2,
                generation: 0,
            },
            kind: "user".to_string(),
            message: Some("cancelled by operator".to_string()),
        };
        let json = serde_json::to_string(&cancel_req).unwrap();
        let back: WasmTaskCancelRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(cancel_req, back);

        let fetch_req = WasmFetchRequest {
            scope: WasmHandleRef {
                kind: WasmHandleKind::Region,
                slot: 1,
                generation: 0,
            },
            url: "https://example.com".to_string(),
            method: "POST".to_string(),
            body: Some(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&fetch_req).unwrap();
        let back: WasmFetchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(fetch_req, back);
    }

    #[test]
    fn dispatcher_nested_scopes_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let s1 = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("outer".to_string()),
                },
                None,
            )
            .unwrap();
        let s2 = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: s1,
                    label: Some("inner".to_string()),
                },
                None,
            )
            .unwrap();

        assert_eq!(d.handles().live_count(), 3); // rt + s1 + s2

        // Close inner first, then outer (structured concurrency order)
        d.scope_close(&s2, None).unwrap();
        assert_eq!(d.handles().live_count(), 2);

        d.scope_close(&s1, None).unwrap();
        assert_eq!(d.handles().live_count(), 1);

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_panicked_outcome_passes_through() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Panicked {
                    message: "boundary panic in task".to_string(),
                },
                None,
            )
            .unwrap();
        assert_eq!(
            result,
            WasmAbiOutcomeEnvelope::Panicked {
                message: "boundary panic in task".to_string(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Ergonomic API Facade Tests
    // -----------------------------------------------------------------------

    #[test]
    fn scope_enter_builder_produces_correct_request() {
        let parent = WasmHandleRef {
            kind: WasmHandleKind::Runtime,
            slot: 0,
            generation: 0,
        };

        // With label
        let req = WasmScopeEnterBuilder::new(parent).label("test").build();
        assert_eq!(req.parent, parent);
        assert_eq!(req.label, Some("test".to_string()));

        // Without label
        let req = WasmScopeEnterBuilder::new(parent).build();
        assert_eq!(req.label, None);
    }

    #[test]
    fn task_spawn_builder_produces_correct_request() {
        let scope = WasmHandleRef {
            kind: WasmHandleKind::Region,
            slot: 1,
            generation: 0,
        };

        let req = WasmTaskSpawnBuilder::new(scope)
            .label("worker")
            .cancel_kind("timeout")
            .build();
        assert_eq!(req.scope, scope);
        assert_eq!(req.label, Some("worker".to_string()));
        assert_eq!(req.cancel_kind, Some("timeout".to_string()));
    }

    #[test]
    fn fetch_builder_defaults_to_get() {
        let scope = WasmHandleRef {
            kind: WasmHandleKind::Region,
            slot: 1,
            generation: 0,
        };

        let req = WasmFetchBuilder::new(scope, "https://example.com").build();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://example.com");
        assert!(req.body.is_none());

        let req = WasmFetchBuilder::new(scope, "https://example.com")
            .method("POST")
            .body(vec![1, 2, 3])
            .build();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, Some(vec![1, 2, 3]));
    }

    #[test]
    fn outcome_ext_trait_inspectors() {
        let ok = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::I64(42),
        };
        assert!(ok.is_ok());
        assert!(!ok.is_err());
        assert!(!ok.is_cancelled());
        assert!(!ok.is_panicked());
        assert_eq!(ok.ok_value(), Some(&WasmAbiValue::I64(42)));
        assert!(ok.err_failure().is_none());
        assert_eq!(ok.outcome_kind(), "ok");

        let err = WasmAbiOutcomeEnvelope::Err {
            failure: WasmAbiFailure {
                code: WasmAbiErrorCode::InternalFailure,
                recoverability: WasmAbiRecoverability::Transient,
                message: "boom".to_string(),
            },
        };
        assert!(err.is_err());
        assert!(!err.is_ok());
        assert_eq!(
            err.err_failure().unwrap().code,
            WasmAbiErrorCode::InternalFailure
        );
        assert_eq!(err.outcome_kind(), "err");

        let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
            cancellation: WasmAbiCancellation {
                kind: "user".to_string(),
                phase: "completed".to_string(),
                origin_region: "R0".to_string(),
                origin_task: None,
                timestamp_nanos: 0,
                message: None,
                truncated: false,
            },
        };
        assert!(cancelled.is_cancelled());
        assert!(cancelled.cancellation().is_some());
        assert_eq!(cancelled.outcome_kind(), "cancelled");

        let panicked = WasmAbiOutcomeEnvelope::Panicked {
            message: "oom".to_string(),
        };
        assert!(panicked.is_panicked());
        assert_eq!(panicked.outcome_kind(), "panicked");
    }

    #[test]
    fn create_scoped_runtime_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("test"), None).unwrap();

        assert_eq!(rt.kind, WasmHandleKind::Runtime);
        assert_eq!(scope.kind, WasmHandleKind::Region);
        assert_eq!(d.handles().live_count(), 2);

        d.close_scoped_runtime(&scope, &rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn spawn_with_builder_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(None, None).unwrap();

        let task = d
            .spawn(WasmTaskSpawnBuilder::new(scope).label("worker"), None)
            .unwrap();
        assert_eq!(task.kind, WasmHandleKind::Task);

        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.close_scoped_runtime(&scope, &rt, None).unwrap();
    }

    #[test]
    fn spawn_and_join_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(None, None).unwrap();

        let result = d
            .spawn_and_join(
                scope,
                Some("inline-task"),
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::String("done".to_string()),
                },
                None,
            )
            .unwrap();
        assert!(result.is_ok());
        assert_eq!(
            result.ok_value(),
            Some(&WasmAbiValue::String("done".to_string()))
        );

        d.close_scoped_runtime(&scope, &rt, None).unwrap();
    }

    #[test]
    fn diagnostic_snapshot_clean_after_full_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("diag-test"), None).unwrap();

        let task = d
            .spawn(WasmTaskSpawnBuilder::new(scope).label("t1"), None)
            .unwrap();
        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.close_scoped_runtime(&scope, &rt, None).unwrap();

        let diag = d.diagnostic_snapshot();
        assert!(diag.is_clean());
        assert!(diag.leaks.is_empty());
        assert_eq!(diag.memory_report.live_handles, 0);
        assert!(diag.dispatch_count > 0);
    }

    #[test]
    fn diagnostic_snapshot_detects_leaks() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let task = d
            .task_spawn(&WasmTaskSpawnBuilder::new(rt).label("leaked").build(), None)
            .unwrap();

        // Cancel and close but don't join (handle transitions to Closed via
        // dispatcher internals when we force-close)
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "user".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();

        // Task is still live (Cancelling, pinned) — not leaked yet
        let diag = d.diagnostic_snapshot();
        assert!(!diag.is_clean());
        assert_eq!(diag.memory_report.live_handles, 2); // rt + task
    }

    #[test]
    fn diagnostic_log_fields_include_expected_keys() {
        let mut d = WasmExportDispatcher::new();
        d.runtime_create(None).unwrap();

        let diag = d.diagnostic_snapshot();
        let fields = diag.as_log_fields();

        assert!(fields.contains_key("dispatch_count"));
        assert!(fields.contains_key("live_handles"));
        assert!(fields.contains_key("pinned_count"));
        assert!(fields.contains_key("event_count"));
        assert!(fields.contains_key("leak_count"));
        assert!(fields.contains_key("abi_version"));
        assert!(fields.contains_key("clean"));
        assert_eq!(fields.get("abi_version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn ergonomic_api_full_lifecycle_with_mixed_outcomes() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("mixed"), None).unwrap();

        // Spawn-and-join with Ok
        let r1 = d
            .spawn_and_join(
                scope,
                Some("ok-task"),
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(1),
                },
                None,
            )
            .unwrap();
        assert!(r1.is_ok());

        // Spawn-and-join with Err
        let r2 = d
            .spawn_and_join(
                scope,
                Some("err-task"),
                WasmAbiOutcomeEnvelope::Err {
                    failure: WasmAbiFailure {
                        code: WasmAbiErrorCode::InternalFailure,
                        recoverability: WasmAbiRecoverability::Transient,
                        message: "retriable".to_string(),
                    },
                },
                None,
            )
            .unwrap();
        assert!(r2.is_err());
        assert_eq!(
            r2.err_failure().unwrap().recoverability,
            WasmAbiRecoverability::Transient
        );

        // Spawn-and-join with Cancelled
        let r3 = d
            .spawn_and_join(
                scope,
                Some("cancelled-task"),
                WasmAbiOutcomeEnvelope::Cancelled {
                    cancellation: WasmAbiCancellation {
                        kind: "timeout".to_string(),
                        phase: "completed".to_string(),
                        origin_region: "R0".to_string(),
                        origin_task: None,
                        timestamp_nanos: 100,
                        message: Some("deadline".to_string()),
                        truncated: false,
                    },
                },
                None,
            )
            .unwrap();
        assert!(r3.is_cancelled());
        assert_eq!(r3.cancellation().unwrap().kind, "timeout");

        d.close_scoped_runtime(&scope, &rt, None).unwrap();

        let diag = d.diagnostic_snapshot();
        assert!(diag.is_clean());
    }

    // -----------------------------------------------------------------------
    // React Provider Lifecycle Tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_phase_transitions_valid() {
        use ReactProviderPhase::*;
        // Valid forward transitions
        assert!(is_valid_provider_transition(Pending, Initializing));
        assert!(is_valid_provider_transition(Initializing, Ready));
        assert!(is_valid_provider_transition(Initializing, Failed));
        assert!(is_valid_provider_transition(Ready, Disposing));
        assert!(is_valid_provider_transition(Disposing, Disposed));
        assert!(is_valid_provider_transition(Disposing, Failed));
        // StrictMode remount
        assert!(is_valid_provider_transition(Disposed, Initializing));
        // Identity
        assert!(is_valid_provider_transition(Ready, Ready));
    }

    #[test]
    fn provider_phase_transitions_invalid() {
        use ReactProviderPhase::*;
        assert!(!is_valid_provider_transition(Pending, Ready));
        assert!(!is_valid_provider_transition(Pending, Disposing));
        assert!(!is_valid_provider_transition(Ready, Initializing));
        assert!(!is_valid_provider_transition(Disposed, Ready));
        assert!(!is_valid_provider_transition(Failed, Ready));
        assert!(validate_provider_transition(Pending, Ready).is_err());
    }

    #[test]
    fn provider_mount_unmount_lifecycle() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        assert_eq!(provider.phase(), ReactProviderPhase::Pending);

        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        assert!(provider.runtime_handle().is_some());
        assert!(provider.root_scope_handle().is_some());

        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);

        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 0);
        assert_eq!(snap.active_task_count, 0);
        assert_eq!(
            snap.transition_history,
            vec![
                ReactProviderPhase::Pending,
                ReactProviderPhase::Initializing,
                ReactProviderPhase::Ready,
                ReactProviderPhase::Disposing,
                ReactProviderPhase::Disposed,
            ]
        );
    }

    #[test]
    fn provider_strict_mode_remount() {
        let mut provider = ReactProviderState::new(ReactProviderConfig {
            strict_mode_resilient: true,
            ..Default::default()
        });

        // First mount
        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        let first_rt = provider.runtime_handle().unwrap();

        // StrictMode unmount
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);

        // StrictMode remount — new handles, clean state
        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        let second_rt = provider.runtime_handle().unwrap();
        assert_ne!(first_rt, second_rt);

        // Final cleanup
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);
    }

    #[test]
    fn provider_child_scopes_tracked() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();

        let s1 = provider.create_child_scope(Some("panel-a")).unwrap();
        let s2 = provider.create_child_scope(Some("panel-b")).unwrap();
        assert_ne!(s1, s2);

        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 2);

        // Unmount cleans up child scopes
        provider.unmount().unwrap();
        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 0);
    }

    #[test]
    fn provider_task_spawn_and_complete() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();

        let task = provider.spawn_task(root_scope, Some("fetch-user")).unwrap();
        assert_eq!(provider.snapshot().active_task_count, 1);

        let outcome = provider
            .complete_task(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
            )
            .unwrap();
        assert!(outcome.is_ok());
        assert_eq!(provider.snapshot().active_task_count, 0);

        provider.unmount().unwrap();
    }

    #[test]
    fn provider_unmount_cancels_active_tasks() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();

        // Spawn tasks but don't complete them
        let _t1 = provider.spawn_task(root_scope, Some("task-a")).unwrap();
        let _t2 = provider.spawn_task(root_scope, Some("task-b")).unwrap();
        assert_eq!(provider.snapshot().active_task_count, 2);

        // Unmount should cancel tasks, not leak them
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);
    }

    #[test]
    fn provider_operations_rejected_when_not_ready() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        // Not mounted — should reject operations
        assert!(provider.create_child_scope(Some("x")).is_err());
        assert!(
            provider
                .spawn_task(
                    WasmHandleRef {
                        kind: WasmHandleKind::Runtime,
                        slot: 0,
                        generation: 0,
                    },
                    Some("y"),
                )
                .is_err()
        );
    }

    #[test]
    fn provider_snapshot_diagnostics() {
        let mut provider = ReactProviderState::new(ReactProviderConfig {
            label: "test-provider".to_string(),
            devtools_diagnostics: true,
            ..Default::default()
        });
        provider.mount().unwrap();

        let snap = provider.snapshot();
        assert_eq!(snap.phase, ReactProviderPhase::Ready);
        assert_eq!(snap.config.label, "test-provider");
        assert!(snap.config.devtools_diagnostics);
        assert!(snap.dispatcher_diagnostics.is_some());
        assert!(snap.runtime_handle.is_some());
        assert!(snap.root_scope_handle.is_some());

        provider.unmount().unwrap();
    }

    #[test]
    fn provider_config_default_values() {
        let cfg = ReactProviderConfig::default();
        assert_eq!(cfg.label, "asupersync");
        assert_eq!(cfg.abort_mode, WasmAbortPropagationMode::Bidirectional);
        assert!(cfg.strict_mode_resilient);
        assert!(!cfg.devtools_diagnostics);
        assert!(cfg.consumer_version.is_none());
    }

    // -----------------------------------------------------------------------
    // React Hook Contract Tests
    // -----------------------------------------------------------------------

    #[test]
    fn hook_phase_transitions_valid() {
        use ReactHookPhase::*;
        assert!(is_valid_hook_transition(Idle, Active));
        assert!(is_valid_hook_transition(Idle, Error));
        assert!(is_valid_hook_transition(Active, Cleanup));
        assert!(is_valid_hook_transition(Cleanup, Unmounted));
        assert!(is_valid_hook_transition(Cleanup, Active)); // StrictMode remount
        assert!(is_valid_hook_transition(Cleanup, Error));
        assert!(is_valid_hook_transition(Unmounted, Active)); // StrictMode
        // Identity
        assert!(is_valid_hook_transition(Active, Active));
    }

    #[test]
    fn hook_phase_transitions_invalid() {
        use ReactHookPhase::*;
        assert!(!is_valid_hook_transition(Idle, Cleanup));
        assert!(!is_valid_hook_transition(Idle, Unmounted));
        assert!(!is_valid_hook_transition(Active, Idle));
        assert!(!is_valid_hook_transition(Active, Unmounted));
        assert!(!is_valid_hook_transition(Error, Active));
        assert!(validate_hook_transition(Idle, Cleanup).is_err());
    }

    #[test]
    fn use_scope_config_defaults() {
        let cfg = UseScopeConfig::default();
        assert_eq!(cfg.label, "scope");
        assert!(cfg.propagate_cancel);
    }

    #[test]
    fn use_scope_snapshot_round_trip() {
        let snap = UseScopeSnapshot {
            phase: ReactHookPhase::Active,
            config: UseScopeConfig::default(),
            scope_handle: None,
            task_count: 3,
            child_scope_count: 1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseScopeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_task_config_defaults() {
        let cfg = UseTaskConfig::default();
        assert_eq!(cfg.label, "task");
        assert_eq!(cfg.dep_change_policy, TaskDepChangePolicy::CancelAndRestart);
        assert!(cfg.memoize_result);
    }

    #[test]
    fn use_task_snapshot_round_trip() {
        let snap = UseTaskSnapshot {
            phase: ReactHookPhase::Active,
            status: UseTaskStatus::Running,
            config: UseTaskConfig::default(),
            task_handle: None,
            scope_handle: None,
            spawn_count: 2,
            dep_cancel_count: 1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseTaskSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_race_config_defaults() {
        let cfg = UseRaceConfig::default();
        assert_eq!(cfg.label, "race");
        assert_eq!(cfg.max_racers, 8);
        assert!(cfg.drain_losers_before_resolve);
    }

    #[test]
    fn racer_snapshot_round_trip() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);
        let racer = RacerSnapshot {
            index: 0,
            state: RacerState::Won,
            task_handle: h,
            label: Some("fast-path".to_string()),
        };
        let json = serde_json::to_string(&racer).unwrap();
        let decoded: RacerSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(racer, decoded);
    }

    #[test]
    fn use_race_snapshot_round_trip() {
        let snap = UseRaceSnapshot {
            phase: ReactHookPhase::Active,
            config: UseRaceConfig::default(),
            scope_handle: None,
            racers: vec![],
            race_count: 1,
            has_winner: true,
            losers_drained: true,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseRaceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_cancellation_config_defaults() {
        let cfg = UseCancellationConfig::default();
        assert_eq!(cfg.label, "cancellation");
        assert!(!cfg.can_trigger);
    }

    #[test]
    fn use_cancellation_snapshot_round_trip() {
        let snap = UseCancellationSnapshot {
            phase: ReactHookPhase::Active,
            config: UseCancellationConfig {
                label: "cancel-observer".to_string(),
                can_trigger: true,
            },
            scope_handle: None,
            is_cancelled: true,
            cancellation: Some(WasmAbiCancellation {
                kind: "timeout".to_string(),
                phase: "completed".to_string(),
                origin_region: "R0".to_string(),
                origin_task: None,
                timestamp_nanos: 0,
                message: None,
                truncated: false,
            }),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseCancellationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn hook_diagnostic_event_round_trip() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Region);
        let evt = ReactHookDiagnosticEvent {
            hook_kind: ReactHookKind::Scope,
            label: "panel".to_string(),
            from_phase: ReactHookPhase::Idle,
            to_phase: ReactHookPhase::Active,
            handles: vec![h],
            detail: Some("mounted".to_string()),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let decoded: ReactHookDiagnosticEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, decoded);
    }

    #[test]
    fn task_dep_change_policy_serde() {
        for policy in [
            TaskDepChangePolicy::CancelAndRestart,
            TaskDepChangePolicy::DiscardAndRestart,
            TaskDepChangePolicy::KeepRunning,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let decoded: TaskDepChangePolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, decoded);
        }
    }

    #[test]
    fn hook_kind_serde() {
        for kind in [
            ReactHookKind::Scope,
            ReactHookKind::Task,
            ReactHookKind::Race,
            ReactHookKind::Cancellation,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: ReactHookKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // Next.js App Router Integration Tests
    // -----------------------------------------------------------------------

    #[test]
    fn render_environment_supports_wasm() {
        assert!(NextjsRenderEnvironment::ClientHydrated.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::ClientSsr.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::ServerComponent.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::EdgeRuntime.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::NodeServer.supports_wasm_runtime());
    }

    #[test]
    fn render_environment_has_browser_apis() {
        assert!(NextjsRenderEnvironment::ClientHydrated.has_browser_apis());
        assert!(NextjsRenderEnvironment::ClientSsr.has_browser_apis());
        assert!(!NextjsRenderEnvironment::ServerComponent.has_browser_apis());
        assert!(!NextjsRenderEnvironment::EdgeRuntime.has_browser_apis());
        assert!(!NextjsRenderEnvironment::NodeServer.has_browser_apis());
    }

    #[test]
    fn render_environment_is_server_side() {
        assert!(NextjsRenderEnvironment::ServerComponent.is_server_side());
        assert!(NextjsRenderEnvironment::EdgeRuntime.is_server_side());
        assert!(NextjsRenderEnvironment::NodeServer.is_server_side());
        assert!(!NextjsRenderEnvironment::ClientSsr.is_server_side());
        assert!(!NextjsRenderEnvironment::ClientHydrated.is_server_side());
    }

    #[test]
    fn render_environment_boundary_mode_mapping() {
        assert_eq!(
            NextjsRenderEnvironment::ClientSsr.boundary_mode(),
            NextjsBoundaryMode::Client
        );
        assert_eq!(
            NextjsRenderEnvironment::ClientHydrated.boundary_mode(),
            NextjsBoundaryMode::Client
        );
        assert_eq!(
            NextjsRenderEnvironment::ServerComponent.boundary_mode(),
            NextjsBoundaryMode::Server
        );
        assert_eq!(
            NextjsRenderEnvironment::NodeServer.boundary_mode(),
            NextjsBoundaryMode::Server
        );
        assert_eq!(
            NextjsRenderEnvironment::EdgeRuntime.boundary_mode(),
            NextjsBoundaryMode::Edge
        );
    }

    #[test]
    fn render_environment_runtime_fallback_mapping() {
        assert_eq!(
            NextjsRenderEnvironment::ClientHydrated.runtime_fallback(),
            NextjsRuntimeFallback::NoneRequired
        );
        assert_eq!(
            NextjsRenderEnvironment::ClientSsr.runtime_fallback(),
            NextjsRuntimeFallback::DeferUntilHydrated
        );
        assert_eq!(
            NextjsRenderEnvironment::ServerComponent.runtime_fallback(),
            NextjsRuntimeFallback::UseServerBridge
        );
        assert_eq!(
            NextjsRenderEnvironment::NodeServer.runtime_fallback(),
            NextjsRuntimeFallback::UseServerBridge
        );
        assert_eq!(
            NextjsRenderEnvironment::EdgeRuntime.runtime_fallback(),
            NextjsRuntimeFallback::UseEdgeBridge
        );

        for env in [
            NextjsRenderEnvironment::ClientSsr,
            NextjsRenderEnvironment::ClientHydrated,
            NextjsRenderEnvironment::ServerComponent,
            NextjsRenderEnvironment::EdgeRuntime,
            NextjsRenderEnvironment::NodeServer,
        ] {
            assert!(
                !env.runtime_fallback_reason().is_empty(),
                "fallback reason should be present for {env:?}"
            );
        }
    }

    #[test]
    fn capability_matrix_wasm_runtime() {
        use NextjsCapability::WasmRuntime;
        assert!(is_capability_available(
            NextjsRenderEnvironment::ClientHydrated,
            WasmRuntime
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::ClientSsr,
            WasmRuntime
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::ServerComponent,
            WasmRuntime
        ));
    }

    #[test]
    fn capability_matrix_server_only() {
        use NextjsCapability::{NodeApis, RequestContext, ServerCookies};
        for cap in [ServerCookies, RequestContext] {
            assert!(is_capability_available(
                NextjsRenderEnvironment::ServerComponent,
                cap
            ));
            assert!(is_capability_available(
                NextjsRenderEnvironment::EdgeRuntime,
                cap
            ));
            assert!(is_capability_available(
                NextjsRenderEnvironment::NodeServer,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ClientHydrated,
                cap
            ));
        }
        assert!(is_capability_available(
            NextjsRenderEnvironment::NodeServer,
            NodeApis
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::EdgeRuntime,
            NodeApis
        ));
    }

    #[test]
    fn capability_matrix_client_only() {
        use NextjsCapability::{BrowserStorage, DomAccess, WebWorkers};
        for cap in [DomAccess, WebWorkers, BrowserStorage] {
            assert!(is_capability_available(
                NextjsRenderEnvironment::ClientHydrated,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ClientSsr,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ServerComponent,
                cap
            ));
        }
    }

    #[test]
    fn anti_pattern_explanations_non_empty() {
        let patterns = [
            NextjsAntiPattern::WasmImportInServerComponent,
            NextjsAntiPattern::RuntimeCallDuringSsr,
            NextjsAntiPattern::RuntimeInitInRender,
            NextjsAntiPattern::HandlesSharingAcrossRoutes,
            NextjsAntiPattern::RuntimeInEdgeMiddleware,
            NextjsAntiPattern::BlockingHydration,
            NextjsAntiPattern::HandlesInServerActions,
        ];
        for ap in patterns {
            assert!(
                !ap.explanation().is_empty(),
                "anti-pattern {ap:?} has empty explanation"
            );
        }
    }

    #[test]
    fn navigation_type_runtime_survives() {
        assert!(NextjsNavigationType::SoftNavigation.runtime_survives());
        assert!(!NextjsNavigationType::HardNavigation.runtime_survives());
        assert!(!NextjsNavigationType::PopState.runtime_survives());
    }

    #[test]
    fn bootstrap_transitions_valid() {
        use NextjsBootstrapPhase::*;
        assert!(is_valid_bootstrap_transition(ServerRendered, Hydrating));
        assert!(is_valid_bootstrap_transition(Hydrating, Hydrated));
        assert!(is_valid_bootstrap_transition(Hydrating, RuntimeFailed));
        assert!(is_valid_bootstrap_transition(Hydrated, RuntimeReady));
        assert!(is_valid_bootstrap_transition(Hydrated, RuntimeFailed));
        assert!(is_valid_bootstrap_transition(RuntimeReady, Hydrating));
        assert!(is_valid_bootstrap_transition(RuntimeReady, ServerRendered));
        assert!(is_valid_bootstrap_transition(RuntimeFailed, Hydrating));
        assert!(is_valid_bootstrap_transition(RuntimeFailed, ServerRendered));
        // Identity
        assert!(is_valid_bootstrap_transition(Hydrated, Hydrated));
    }

    #[test]
    fn bootstrap_transitions_invalid() {
        use NextjsBootstrapPhase::*;
        assert!(!is_valid_bootstrap_transition(ServerRendered, Hydrated));
        assert!(!is_valid_bootstrap_transition(ServerRendered, RuntimeReady));
        assert!(!is_valid_bootstrap_transition(Hydrating, RuntimeReady)); // must pass through Hydrated
        assert!(!is_valid_bootstrap_transition(RuntimeFailed, RuntimeReady)); // must retry hydration first
        assert!(validate_bootstrap_transition(ServerRendered, RuntimeReady).is_err());
    }

    #[test]
    fn bootstrap_state_idempotent_hydration_reentry() {
        let mut state = NextjsBootstrapState::new();
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);

        let changed = state.start_hydration().expect("start hydration");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 1);

        let changed = state.start_hydration().expect("idempotent hydration start");
        assert!(!changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 1);
    }

    #[test]
    fn bootstrap_state_cancelled_then_retry_flow() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");

        state
            .mark_runtime_cancelled("navigation interrupted")
            .expect("mark cancelled");
        assert_eq!(state.phase(), NextjsBootstrapPhase::RuntimeFailed);
        assert_eq!(state.last_failure(), Some("navigation interrupted"));

        let changed = state.retry_after_failure().expect("retry after failure");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 2);
    }

    #[test]
    fn bootstrap_state_soft_navigation_is_non_destructive() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state
            .on_navigation(NextjsNavigationType::SoftNavigation)
            .expect("soft navigation");
        assert!(!changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(state.runtime_generation(), 1);
        assert_eq!(state.navigation_count(), 1);
    }

    #[test]
    fn bootstrap_state_hard_navigation_resets_phase() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state
            .on_navigation(NextjsNavigationType::HardNavigation)
            .expect("hard navigation");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);
        assert_eq!(state.navigation_count(), 1);
    }

    #[test]
    fn bootstrap_state_hot_reload_forces_rehydration() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state.on_hot_reload().expect("hot reload");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hot_reload_count(), 1);
        assert_eq!(state.hydration_cycle_count(), 2);
    }

    #[test]
    fn component_placement_round_trip() {
        let placement = NextjsComponentPlacement {
            environment: NextjsRenderEnvironment::ClientHydrated,
            route_segment: "/dashboard/settings".to_string(),
            inside_suspense: true,
            inside_error_boundary: false,
            layout_depth: 2,
        };
        let json = serde_json::to_string(&placement).unwrap();
        let decoded: NextjsComponentPlacement = serde_json::from_str(&json).unwrap();
        assert_eq!(placement, decoded);
    }

    #[test]
    fn integration_snapshot_round_trip() {
        let snap = NextjsIntegrationSnapshot {
            bootstrap_phase: NextjsBootstrapPhase::RuntimeReady,
            environment: NextjsRenderEnvironment::ClientHydrated,
            route_segment: "/app".to_string(),
            active_provider_count: 1,
            wasm_module_loaded: true,
            navigation_count: 3,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: NextjsIntegrationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn anti_pattern_serde() {
        for ap in [
            NextjsAntiPattern::WasmImportInServerComponent,
            NextjsAntiPattern::RuntimeCallDuringSsr,
            NextjsAntiPattern::RuntimeInitInRender,
            NextjsAntiPattern::HandlesSharingAcrossRoutes,
            NextjsAntiPattern::RuntimeInEdgeMiddleware,
            NextjsAntiPattern::BlockingHydration,
            NextjsAntiPattern::HandlesInServerActions,
        ] {
            let json = serde_json::to_string(&ap).unwrap();
            let decoded: NextjsAntiPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(ap, decoded);
        }
    }
}
