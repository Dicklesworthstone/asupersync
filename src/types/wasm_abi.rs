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
            state: WasmBoundaryState::Unbound,
            ownership: WasmHandleOwnership::WasmOwned,
            pinned: false,
        });
        self.live_count += 1;

        handle
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
        validate_wasm_boundary_transition(entry.state, to).map_err(|_| {
            // Re-read state for the error (entry borrow ended)
            WasmHandleError::InvalidTransfer {
                slot: handle.slot,
                current: WasmHandleOwnership::WasmOwned,
            }
        })?;
        // Re-borrow after validation
        let entry = self.slots[handle.slot as usize].as_mut().unwrap();
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
    /// Returns `AlreadyReleased` if the handle was previously released.
    pub fn release(&mut self, handle: &WasmHandleRef) -> Result<(), WasmHandleError> {
        let entry = self.get_mut(handle)?;
        if entry.pinned {
            return Err(WasmHandleError::ReleasePinned { slot: handle.slot });
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CancelKind, CancelReason, PanicPayload, RegionId, Time};

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
        let h3 = table.allocate(WasmHandleKind::Task);

        table.transition(&h1, WasmBoundaryState::Bound).unwrap();
        table.transition(&h1, WasmBoundaryState::Active).unwrap();
        table.pin(&h2).unwrap();

        let report = table.memory_report();
        assert_eq!(report.live_handles, 3);
        assert_eq!(report.pinned_count, 1);
        assert_eq!(report.by_kind.get("task"), Some(&2));
        assert_eq!(report.by_kind.get("runtime"), Some(&1));

        // h3 is still unbound
        assert_eq!(report.by_state.get("unbound"), Some(&2));
        assert_eq!(report.by_state.get("active"), Some(&1));
    }

    #[test]
    fn handle_table_release_already_released() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);
        table.release(&h).unwrap();

        // Stale generation
        let err = table.release(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
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
}
