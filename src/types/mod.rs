//! Core types for the Asupersync runtime.
//!
//! This module contains the fundamental types used throughout the runtime:
//!
//! - [`id`]: Identifier types (`RegionId`, `TaskId`, `ObligationId`, `Time`)
//! - [`outcome`]: Four-valued outcome type with severity lattice
//! - [`cancel`]: Cancellation reason and kind types
//! - [`budget`]: Budget type with product semiring semantics + min-plus curves
//! - [`policy`]: Policy trait for outcome aggregation
//! - [`symbol`]: Symbol types for RaptorQ-based distributed layer
//! - [`resource`]: Resource limits and symbol buffer pools
//! - [`rref`]: Region-owned reference for Send tasks

pub mod budget;
pub mod builder;
pub mod cancel;
pub mod id;
pub mod outcome;
pub mod policy;
pub mod pressure;
pub mod resource;
pub mod rref;
pub mod symbol;
pub mod symbol_set;
pub mod task_context;
pub mod typed_symbol;
pub mod wasm_abi;

pub use budget::{Budget, CurveBudget, CurveError, MinPlusCurve, backlog_bound, delay_bound};
pub use builder::{BuildError, BuildResult};
pub use cancel::{
    CancelAttributionConfig, CancelKind, CancelPhase, CancelReason, CancelWitness,
    CancelWitnessError,
};
pub use id::{ObligationId, RegionId, TaskId, Time};

// Canonical FrankenSuite identifiers.
//
// `TraceId` here is the 128-bit timestamped identifier defined in
// `franken_kernel` (timestamp_ms in the high 48 bits + 80 bits of randomness,
// hex-serialized). It is the canonical "TraceId" for EvidenceLedger linkage
// and any new code that needs to correlate runtime decisions with persistent
// audit records.
//
// Two narrower internal trace identifiers exist with the *same name* in
// different modules and serve distinct purposes — they are NOT
// interchangeable with this one (br-asupersync-dwtjto):
//
//   * `crate::observability::cancellation_tracer::TraceId` — `u64`
//     auto-counter used purely for in-process cancellation propagation
//     traces. No timestamp, no cross-process meaning.
//
//   * `crate::trace::distributed::id::TraceId` — `{high: u64, low: u64}`
//     W3C-formatted (32 hex chars) distributed trace context. Locked by
//     a golden snapshot (`canonical_trace_id_serialization`) so the
//     wire format cannot drift.
//
// New code that wants a "TraceId" should reach for this one. Migration
// of the two purpose-specific types is tracked under follow-up beads
// rather than a single sweeping rename, because their field shapes and
// serialization semantics differ in ways that golden tests pin in place.
pub use franken_kernel::{DecisionId, PolicyId, SchemaVersion, TraceId};
pub use outcome::{Outcome, OutcomeError, PanicPayload, Severity, join_outcomes};
pub use policy::Policy;
pub use pressure::SystemPressure;
pub use rref::{RRef, RRefAccess, RRefAccessWitness, RRefError};
pub use symbol::{DEFAULT_SYMBOL_SIZE, ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
pub use symbol_set::{
    BlockProgress, ConcurrentSymbolSet, InsertResult, SymbolSet, ThresholdConfig,
};
pub use task_context::{CheckpointState, CxInner, MAX_MASK_DEPTH};
pub use typed_symbol::{
    DeserializationError, Deserializer, SerdeCodec, SerializationError, SerializationFormat,
    Serializer, TYPED_SYMBOL_HEADER_LEN, TYPED_SYMBOL_MAGIC, TypeDescriptor, TypeMismatchError,
    TypeRegistry, TypedDecoder, TypedEncoder, TypedSymbol,
};
pub use wasm_abi::{
    NextjsAntiPattern, NextjsBootstrapPhase, NextjsBootstrapState, NextjsBootstrapTransitionError,
    NextjsBootstrapTransitionRecord, NextjsBootstrapTrigger, NextjsBoundaryMode, NextjsCapability,
    NextjsComponentPlacement, NextjsIntegrationSnapshot, NextjsNavigationType,
    NextjsRenderEnvironment, NextjsRuntimeFallback, ProgressiveLoadSlot, ProgressiveLoadSnapshot,
    RacerSnapshot, RacerState, ReactHookDiagnosticEvent, ReactHookKind, ReactHookPhase,
    ReactHookTransitionError, ReactProviderConfig, ReactProviderPhase, ReactProviderSnapshot,
    ReactProviderState, ReactProviderTransitionError, SuspenseBoundaryState,
    SuspenseDiagnosticEvent, SuspenseTaskConfig, SuspenseTaskSnapshot, TaskDepChangePolicy,
    TransitionTaskState, UseCancellationConfig, UseCancellationSnapshot, UseRaceConfig,
    UseRaceSnapshot, UseScopeConfig, UseScopeSnapshot, UseTaskConfig, UseTaskSnapshot,
    UseTaskStatus, WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION,
    WASM_ABI_SIGNATURE_FINGERPRINT_V1, WASM_ABI_SIGNATURES_V1, WasmAbiBoundaryEvent,
    WasmAbiCancellation, WasmAbiChangeClass, WasmAbiCompatibilityDecision, WasmAbiErrorCode,
    WasmAbiFailure, WasmAbiOutcomeEnvelope, WasmAbiPayloadShape, WasmAbiRecoverability,
    WasmAbiSignature, WasmAbiSymbol, WasmAbiValue, WasmAbiVersion, WasmAbiVersionBump,
    WasmAbortInteropSnapshot, WasmAbortInteropUpdate, WasmAbortPropagationMode,
    WasmBoundaryEventLog, WasmBoundaryState, WasmBoundaryTransitionError, WasmDispatchError,
    WasmDispatcherDiagnostics, WasmExportDispatcher, WasmExportResult, WasmFetchBuilder,
    WasmFetchRequest, WasmHandleKind, WasmHandleRef, WasmOutcomeExt, WasmScopeEnterBuilder,
    WasmScopeEnterRequest, WasmTaskCancelRequest, WasmTaskSpawnBuilder, WasmTaskSpawnRequest,
    apply_abort_signal_event, apply_runtime_cancel_phase_event, classify_wasm_abi_compatibility,
    is_capability_available, is_valid_bootstrap_transition, is_valid_hook_transition,
    is_valid_provider_transition, is_valid_wasm_boundary_transition,
    outcome_to_error_boundary_action, outcome_to_suspense_state, outcome_to_transition_state,
    required_wasm_abi_bump, validate_bootstrap_transition, validate_hook_transition,
    validate_provider_transition, validate_wasm_boundary_transition,
    wasm_abi_signature_fingerprint, wasm_boundary_state_for_cancel_phase,
};
