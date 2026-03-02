#![allow(missing_docs)]

use asupersync::types::wasm_abi::ErrorBoundaryAction;
use asupersync::types::{
    CancelPhase, NextjsBootstrapPhase, NextjsIntegrationSnapshot, NextjsNavigationType,
    NextjsRenderEnvironment, is_valid_bootstrap_transition,
};
use asupersync::{
    ProgressiveLoadSlot, ProgressiveLoadSnapshot, SuspenseBoundaryState, TransitionTaskState,
    WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
    WASM_ABI_SIGNATURES_V1, WasmAbiBoundaryEvent, WasmAbiCancellation,
    WasmAbiCompatibilityDecision, WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope,
    WasmAbiPayloadShape, WasmAbiRecoverability, WasmAbiSymbol, WasmAbiValue, WasmAbiVersion,
    WasmAbortInteropSnapshot, WasmAbortPropagationMode, WasmBoundaryState,
    apply_abort_signal_event, apply_runtime_cancel_phase_event, classify_wasm_abi_compatibility,
    outcome_to_error_boundary_action, outcome_to_suspense_state, outcome_to_transition_state,
    wasm_abi_signature_fingerprint,
};
use std::collections::{BTreeMap, BTreeSet};

fn bootstrap_hydration_context(phase: NextjsBootstrapPhase) -> &'static str {
    match phase {
        NextjsBootstrapPhase::ServerRendered => "server_rendered",
        NextjsBootstrapPhase::Hydrating => "hydrating",
        NextjsBootstrapPhase::Hydrated => "hydrated",
        NextjsBootstrapPhase::RuntimeReady => "runtime_ready",
        NextjsBootstrapPhase::RuntimeFailed => "runtime_failed",
    }
}

fn bootstrap_boundary_mode(environment: NextjsRenderEnvironment) -> &'static str {
    match environment {
        NextjsRenderEnvironment::ClientSsr | NextjsRenderEnvironment::ClientHydrated => "client",
        NextjsRenderEnvironment::ServerComponent | NextjsRenderEnvironment::NodeServer => "server",
        NextjsRenderEnvironment::EdgeRuntime => "edge",
    }
}

fn nextjs_bootstrap_log_fields(
    snapshot: &NextjsIntegrationSnapshot,
    navigation: NextjsNavigationType,
    recovery_action: &'static str,
) -> BTreeMap<&'static str, String> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "active_provider_count",
        snapshot.active_provider_count.to_string(),
    );
    fields.insert(
        "bootstrap_phase",
        bootstrap_hydration_context(snapshot.bootstrap_phase).to_string(),
    );
    fields.insert(
        "boundary_mode",
        bootstrap_boundary_mode(snapshot.environment).to_string(),
    );
    fields.insert(
        "hydration_context",
        bootstrap_hydration_context(snapshot.bootstrap_phase).to_string(),
    );
    fields.insert("navigation_count", snapshot.navigation_count.to_string());
    fields.insert(
        "navigation_type",
        match navigation {
            NextjsNavigationType::SoftNavigation => "soft_navigation".to_string(),
            NextjsNavigationType::HardNavigation => "hard_navigation".to_string(),
            NextjsNavigationType::PopState => "pop_state".to_string(),
        },
    );
    fields.insert("recovery_action", recovery_action.to_string());
    fields.insert("route_segment", snapshot.route_segment.clone());
    fields.insert(
        "wasm_module_loaded",
        snapshot.wasm_module_loaded.to_string(),
    );
    fields
}

fn transient_failure(message: &str) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::InternalFailure,
            recoverability: WasmAbiRecoverability::Transient,
            message: message.to_string(),
        },
    }
}

fn permanent_failure(message: &str) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::CompatibilityRejected,
            recoverability: WasmAbiRecoverability::Permanent,
            message: message.to_string(),
        },
    }
}

#[test]
fn wasm_abi_signature_matrix_matches_v1_contract() {
    let signatures: Vec<(&str, WasmAbiPayloadShape, WasmAbiPayloadShape)> = WASM_ABI_SIGNATURES_V1
        .iter()
        .map(|signature| {
            (
                signature.symbol.as_str(),
                signature.request,
                signature.response,
            )
        })
        .collect();

    assert_eq!(
        signatures,
        vec![
            (
                "runtime_create",
                WasmAbiPayloadShape::Empty,
                WasmAbiPayloadShape::HandleRefV1,
            ),
            (
                "runtime_close",
                WasmAbiPayloadShape::HandleRefV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ),
            (
                "scope_enter",
                WasmAbiPayloadShape::ScopeEnterRequestV1,
                WasmAbiPayloadShape::HandleRefV1,
            ),
            (
                "scope_close",
                WasmAbiPayloadShape::HandleRefV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ),
            (
                "task_spawn",
                WasmAbiPayloadShape::SpawnRequestV1,
                WasmAbiPayloadShape::HandleRefV1,
            ),
            (
                "task_join",
                WasmAbiPayloadShape::HandleRefV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ),
            (
                "task_cancel",
                WasmAbiPayloadShape::CancelRequestV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ),
            (
                "fetch_request",
                WasmAbiPayloadShape::FetchRequestV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ),
        ],
        "ABI signature matrix drifted from v1 contract"
    );

    let unique_symbols: BTreeSet<&str> = signatures.iter().map(|(symbol, _, _)| *symbol).collect();
    assert_eq!(
        unique_symbols.len(),
        signatures.len(),
        "ABI signature matrix must not contain duplicate symbols"
    );
}

#[test]
fn wasm_abi_version_and_fingerprint_constants_match_signature_table() {
    assert_eq!(WASM_ABI_MAJOR_VERSION, 1);
    assert_eq!(WASM_ABI_MINOR_VERSION, 0);
    assert_eq!(
        wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1),
        WASM_ABI_SIGNATURE_FINGERPRINT_V1
    );
}

#[test]
fn wasm_abi_compatibility_rules_cover_exact_backward_and_rejecting_paths() {
    let exact = classify_wasm_abi_compatibility(
        WasmAbiVersion { major: 1, minor: 0 },
        WasmAbiVersion { major: 1, minor: 0 },
    );
    assert_eq!(exact, WasmAbiCompatibilityDecision::Exact);

    let backward = classify_wasm_abi_compatibility(
        WasmAbiVersion { major: 1, minor: 0 },
        WasmAbiVersion { major: 1, minor: 3 },
    );
    assert!(matches!(
        backward,
        WasmAbiCompatibilityDecision::BackwardCompatible {
            producer_minor: 0,
            consumer_minor: 3
        }
    ));

    let consumer_too_old = classify_wasm_abi_compatibility(
        WasmAbiVersion { major: 1, minor: 3 },
        WasmAbiVersion { major: 1, minor: 2 },
    );
    assert!(matches!(
        consumer_too_old,
        WasmAbiCompatibilityDecision::ConsumerTooOld {
            producer_minor: 3,
            consumer_minor: 2
        }
    ));

    let major_mismatch = classify_wasm_abi_compatibility(
        WasmAbiVersion { major: 1, minor: 3 },
        WasmAbiVersion { major: 2, minor: 0 },
    );
    assert!(matches!(
        major_mismatch,
        WasmAbiCompatibilityDecision::MajorMismatch {
            producer_major: 1,
            consumer_major: 2
        }
    ));
}

#[test]
fn wasm_boundary_event_log_fields_are_deterministic() {
    let event = WasmAbiBoundaryEvent {
        abi_version: WasmAbiVersion::CURRENT,
        symbol: WasmAbiSymbol::TaskCancel,
        payload_shape: WasmAbiPayloadShape::CancelRequestV1,
        state_from: WasmBoundaryState::Active,
        state_to: WasmBoundaryState::Cancelling,
        compatibility: WasmAbiCompatibilityDecision::Exact,
    };

    let fields = event.as_log_fields();
    let key_order: Vec<&str> = fields.keys().copied().collect();
    assert_eq!(
        key_order,
        vec![
            "abi_version",
            "compatibility",
            "compatibility_compatible",
            "compatibility_consumer_major",
            "compatibility_consumer_minor",
            "compatibility_decision",
            "compatibility_producer_major",
            "compatibility_producer_minor",
            "payload_shape",
            "state_from",
            "state_to",
            "symbol"
        ]
    );
    assert_eq!(fields["abi_version"], "1.0");
    assert_eq!(fields["symbol"], "task_cancel");
    assert_eq!(fields["compatibility"], "exact");
    assert_eq!(fields["compatibility_decision"], "exact");
    assert_eq!(fields["compatibility_compatible"], "true");
    assert_eq!(fields["compatibility_producer_major"], "1");
    assert_eq!(fields["compatibility_consumer_major"], "1");
    assert_eq!(fields["compatibility_producer_minor"], "0");
    assert_eq!(fields["compatibility_consumer_minor"], "0");
}

#[test]
fn wasm_abortsignal_interop_contract_is_deterministic() {
    let js_abort = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::AbortSignalToRuntime,
        boundary_state: WasmBoundaryState::Active,
        abort_signal_aborted: false,
    });
    assert_eq!(js_abort.next_boundary_state, WasmBoundaryState::Cancelling);
    assert!(js_abort.abort_signal_aborted);
    assert!(js_abort.propagated_to_runtime);
    assert!(!js_abort.propagated_to_abort_signal);

    let runtime_requested = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        },
        CancelPhase::Requested,
    );
    assert_eq!(
        runtime_requested.next_boundary_state,
        WasmBoundaryState::Cancelling
    );
    assert!(runtime_requested.abort_signal_aborted);
    assert!(!runtime_requested.propagated_to_runtime);
    assert!(runtime_requested.propagated_to_abort_signal);

    let runtime_completed = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
            boundary_state: runtime_requested.next_boundary_state,
            abort_signal_aborted: runtime_requested.abort_signal_aborted,
        },
        CancelPhase::Completed,
    );
    assert_eq!(
        runtime_completed.next_boundary_state,
        WasmBoundaryState::Closed
    );
    assert!(runtime_completed.abort_signal_aborted);
}

#[test]
fn nextjs_bootstrap_state_machine_paths_are_explicit() {
    use NextjsBootstrapPhase::*;

    assert!(is_valid_bootstrap_transition(ServerRendered, Hydrating));
    assert!(is_valid_bootstrap_transition(Hydrating, Hydrated));
    assert!(is_valid_bootstrap_transition(Hydrated, RuntimeReady));
    assert!(is_valid_bootstrap_transition(Hydrated, RuntimeFailed));

    // Idempotent re-entry is explicitly legal for all phases.
    assert!(is_valid_bootstrap_transition(
        ServerRendered,
        ServerRendered
    ));
    assert!(is_valid_bootstrap_transition(Hydrating, Hydrating));
    assert!(is_valid_bootstrap_transition(Hydrated, Hydrated));
    assert!(is_valid_bootstrap_transition(RuntimeReady, RuntimeReady));
    assert!(is_valid_bootstrap_transition(RuntimeFailed, RuntimeFailed));

    assert!(!is_valid_bootstrap_transition(ServerRendered, RuntimeReady));
    assert!(!is_valid_bootstrap_transition(Hydrating, RuntimeReady));
    assert!(is_valid_bootstrap_transition(RuntimeReady, Hydrating)); // Valid for Fast Refresh
    assert!(is_valid_bootstrap_transition(RuntimeFailed, Hydrating)); // Valid for Retry / Fast Refresh
    assert!(!is_valid_bootstrap_transition(RuntimeFailed, Hydrated));
}

#[test]
fn nextjs_bootstrap_recovery_paths_are_navigation_and_retry_safe() {
    use NextjsBootstrapPhase::*;

    // Local retry after failure keeps the same phase until a boundary-level
    // recovery action (remount/hard navigation) starts a new lifecycle.
    assert!(is_valid_bootstrap_transition(RuntimeFailed, RuntimeFailed));

    // Hard navigation destroys runtime and restarts bootstrap deterministically.
    assert!(!NextjsNavigationType::HardNavigation.runtime_survives());
    assert!(is_valid_bootstrap_transition(ServerRendered, Hydrating));
    assert!(is_valid_bootstrap_transition(Hydrating, Hydrated));
    assert!(is_valid_bootstrap_transition(Hydrated, RuntimeReady));

    // Soft navigation keeps the runtime alive.
    assert!(NextjsNavigationType::SoftNavigation.runtime_survives());
    assert!(is_valid_bootstrap_transition(RuntimeReady, RuntimeReady));
}

#[test]
fn nextjs_bootstrap_log_fields_are_deterministic_and_replayable() {
    let snapshot = NextjsIntegrationSnapshot {
        bootstrap_phase: NextjsBootstrapPhase::Hydrating,
        environment: NextjsRenderEnvironment::ClientHydrated,
        route_segment: "/dashboard".to_string(),
        active_provider_count: 1,
        wasm_module_loaded: false,
        navigation_count: 2,
    };

    // Cancellation request during bootstrap should map to cancelling boundary
    // state with deterministic recovery logging.
    let cancel_requested = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        },
        CancelPhase::Requested,
    );
    assert_eq!(
        cancel_requested.next_boundary_state,
        WasmBoundaryState::Cancelling
    );

    let fields = nextjs_bootstrap_log_fields(
        &snapshot,
        NextjsNavigationType::SoftNavigation,
        "retry_after_cancel",
    );
    let key_order: Vec<&str> = fields.keys().copied().collect();
    assert_eq!(
        key_order,
        vec![
            "active_provider_count",
            "bootstrap_phase",
            "boundary_mode",
            "hydration_context",
            "navigation_count",
            "navigation_type",
            "recovery_action",
            "route_segment",
            "wasm_module_loaded",
        ]
    );
    assert_eq!(fields["bootstrap_phase"], "hydrating");
    assert_eq!(fields["hydration_context"], "hydrating");
    assert_eq!(fields["boundary_mode"], "client");
    assert_eq!(fields["navigation_type"], "soft_navigation");
    assert_eq!(fields["recovery_action"], "retry_after_cancel");
    assert_eq!(fields["route_segment"], "/dashboard");
    assert_eq!(fields["wasm_module_loaded"], "false");
}

#[test]
fn wasm_suspense_and_transition_outcome_mappings_are_deterministic() {
    let ok = WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Unit,
    };
    assert_eq!(
        outcome_to_suspense_state(&ok),
        SuspenseBoundaryState::Resolved
    );
    assert_eq!(
        outcome_to_error_boundary_action(&ok),
        ErrorBoundaryAction::None
    );
    assert_eq!(
        outcome_to_transition_state(&ok),
        TransitionTaskState::Committed
    );

    let recoverable_err = transient_failure("temporary backend timeout");
    assert_eq!(
        outcome_to_suspense_state(&recoverable_err),
        SuspenseBoundaryState::ErrorRecoverable
    );
    assert_eq!(
        outcome_to_error_boundary_action(&recoverable_err),
        ErrorBoundaryAction::ShowWithRetry
    );
    assert_eq!(
        outcome_to_transition_state(&recoverable_err),
        TransitionTaskState::Reverted
    );

    let fatal_err = permanent_failure("invalid contract shape");
    assert_eq!(
        outcome_to_suspense_state(&fatal_err),
        SuspenseBoundaryState::ErrorFatal
    );
    assert_eq!(
        outcome_to_error_boundary_action(&fatal_err),
        ErrorBoundaryAction::ShowFatal
    );
    assert_eq!(
        outcome_to_transition_state(&fatal_err),
        TransitionTaskState::Reverted
    );

    let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: WasmAbiCancellation {
            kind: "user".to_string(),
            phase: "completed".to_string(),
            origin_region: "r:1".to_string(),
            origin_task: Some("t:2".to_string()),
            timestamp_nanos: 42,
            message: Some("route_change".to_string()),
            truncated: false,
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&cancelled),
        SuspenseBoundaryState::Cancelled
    );
    assert_eq!(
        outcome_to_error_boundary_action(&cancelled),
        ErrorBoundaryAction::None
    );
    assert_eq!(
        outcome_to_transition_state(&cancelled),
        TransitionTaskState::Cancelled
    );

    let panicked = WasmAbiOutcomeEnvelope::Panicked {
        message: "panic in hook".to_string(),
    };
    assert_eq!(
        outcome_to_suspense_state(&panicked),
        SuspenseBoundaryState::ErrorFatal
    );
    assert_eq!(
        outcome_to_error_boundary_action(&panicked),
        ErrorBoundaryAction::ShowFatal
    );
    assert_eq!(
        outcome_to_transition_state(&panicked),
        TransitionTaskState::Reverted
    );
}

#[test]
fn progressive_loading_state_aggregation_respects_required_slot_precedence() {
    let slots = vec![
        ProgressiveLoadSlot {
            label: "required-users".to_string(),
            required: true,
            state: SuspenseBoundaryState::Pending,
            task_handle: None,
        },
        ProgressiveLoadSlot {
            label: "optional-metrics".to_string(),
            required: false,
            state: SuspenseBoundaryState::ErrorFatal,
            task_handle: None,
        },
    ];
    assert_eq!(
        ProgressiveLoadSnapshot::compute_overall_state(&slots),
        SuspenseBoundaryState::Pending
    );

    let slots = vec![
        ProgressiveLoadSlot {
            label: "required-users".to_string(),
            required: true,
            state: SuspenseBoundaryState::Resolved,
            task_handle: None,
        },
        ProgressiveLoadSlot {
            label: "required-permissions".to_string(),
            required: true,
            state: SuspenseBoundaryState::ErrorRecoverable,
            task_handle: None,
        },
    ];
    assert_eq!(
        ProgressiveLoadSnapshot::compute_overall_state(&slots),
        SuspenseBoundaryState::ErrorRecoverable
    );

    let slots = vec![
        ProgressiveLoadSlot {
            label: "required-users".to_string(),
            required: true,
            state: SuspenseBoundaryState::Resolved,
            task_handle: None,
        },
        ProgressiveLoadSlot {
            label: "required-permissions".to_string(),
            required: true,
            state: SuspenseBoundaryState::ErrorFatal,
            task_handle: None,
        },
    ];
    assert_eq!(
        ProgressiveLoadSnapshot::compute_overall_state(&slots),
        SuspenseBoundaryState::ErrorFatal
    );

    let slots = vec![
        ProgressiveLoadSlot {
            label: "required-users".to_string(),
            required: true,
            state: SuspenseBoundaryState::Resolved,
            task_handle: None,
        },
        ProgressiveLoadSlot {
            label: "required-permissions".to_string(),
            required: true,
            state: SuspenseBoundaryState::Cancelled,
            task_handle: None,
        },
    ];
    assert_eq!(
        ProgressiveLoadSnapshot::compute_overall_state(&slots),
        SuspenseBoundaryState::Resolved
    );
}
