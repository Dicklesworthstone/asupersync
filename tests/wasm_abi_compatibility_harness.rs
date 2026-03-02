//! WASM ABI Compatibility Harness (WASM-8.5)
//!
//! Validates ABI compatibility invariants: fingerprint stability,
//! version negotiation exhaustive coverage, boundary state machine
//! completeness, handle lifecycle correctness, cancellation/abort
//! interop determinism, and outcome-to-UI mapping stability.
//!
//! Bead: asupersync-umelq.8.5

#![allow(missing_docs)]

use asupersync::types::wasm_abi::{
    ErrorBoundaryAction, WasmHandleError, WasmHandleOwnership, WasmHandleTable,
};
use asupersync::types::{CancelPhase, NextjsBootstrapPhase, is_valid_bootstrap_transition};
use asupersync::{
    SuspenseBoundaryState, TransitionTaskState, WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION,
    WASM_ABI_SIGNATURE_FINGERPRINT_V1, WASM_ABI_SIGNATURES_V1, WasmAbiChangeClass,
    WasmAbiCompatibilityDecision, WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope,
    WasmAbiPayloadShape, WasmAbiRecoverability, WasmAbiValue, WasmAbiVersion, WasmAbiVersionBump,
    WasmAbortInteropSnapshot, WasmAbortPropagationMode, WasmBoundaryState, WasmHandleKind,
    WasmHandleRef, apply_abort_signal_event, apply_runtime_cancel_phase_event,
    classify_wasm_abi_compatibility, is_valid_wasm_boundary_transition,
    outcome_to_error_boundary_action, outcome_to_suspense_state, outcome_to_transition_state,
    required_wasm_abi_bump, validate_wasm_boundary_transition, wasm_abi_signature_fingerprint,
    wasm_boundary_state_for_cancel_phase,
};
use std::path::Path;

// ─── Policy document existence ──────────────────────────────────────

#[test]
fn policy_document_exists() {
    assert!(
        Path::new("docs/wasm_abi_compatibility_policy.md").exists(),
        "Compatibility policy document must exist"
    );
}

#[test]
fn policy_document_references_bead() {
    let doc = std::fs::read_to_string("docs/wasm_abi_compatibility_policy.md")
        .expect("failed to load policy document");
    assert!(
        doc.contains("asupersync-umelq.8.5"),
        "Policy document must reference its own bead ID"
    );
}

// ─── Fingerprint stability ──────────────────────────────────────────

#[test]
fn fingerprint_matches_guard_constant() {
    let computed = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
    assert_eq!(
        computed, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
        "Signature fingerprint drift detected. If intentional, update \
         WASM_ABI_SIGNATURE_FINGERPRINT_V1 and add migration note."
    );
}

#[test]
fn signature_table_has_expected_symbol_count() {
    assert_eq!(
        WASM_ABI_SIGNATURES_V1.len(),
        8,
        "v1 signature table must have exactly 8 symbols"
    );
}

#[test]
fn signature_table_symbol_ordering_is_canonical() {
    let symbols: Vec<&str> = WASM_ABI_SIGNATURES_V1
        .iter()
        .map(|s| s.symbol.as_str())
        .collect();
    assert_eq!(
        symbols,
        vec![
            "runtime_create",
            "runtime_close",
            "scope_enter",
            "scope_close",
            "task_spawn",
            "task_join",
            "task_cancel",
            "fetch_request",
        ],
        "Symbol ordering must match canonical v1 contract"
    );
}

#[test]
fn signature_table_symbols_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for sig in &WASM_ABI_SIGNATURES_V1 {
        assert!(
            seen.insert(sig.symbol.as_str()),
            "Duplicate symbol in signature table: {}",
            sig.symbol.as_str()
        );
    }
}

#[test]
fn signature_table_payload_shapes_match_v1_contract() {
    let expected: Vec<(&str, WasmAbiPayloadShape, WasmAbiPayloadShape)> = vec![
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
    ];

    for (i, sig) in WASM_ABI_SIGNATURES_V1.iter().enumerate() {
        let (exp_sym, exp_req, exp_resp) = &expected[i];
        assert_eq!(
            sig.symbol.as_str(),
            *exp_sym,
            "Symbol mismatch at index {i}"
        );
        assert_eq!(
            sig.request, *exp_req,
            "Request shape mismatch for {exp_sym}"
        );
        assert_eq!(
            sig.response, *exp_resp,
            "Response shape mismatch for {exp_sym}"
        );
    }
}

// ─── Version constants ──────────────────────────────────────────────

#[test]
fn version_constants_are_v1_0() {
    assert_eq!(WASM_ABI_MAJOR_VERSION, 1);
    assert_eq!(WASM_ABI_MINOR_VERSION, 0);
    assert_eq!(
        WasmAbiVersion::CURRENT,
        WasmAbiVersion { major: 1, minor: 0 }
    );
}

// ─── Version compatibility exhaustive coverage ──────────────────────

#[test]
fn compatibility_exact_match() {
    for major in [0, 1, 2, 255] {
        for minor in [0, 1, 5, 100] {
            let v = WasmAbiVersion { major, minor };
            let result = classify_wasm_abi_compatibility(v, v);
            assert_eq!(
                result,
                WasmAbiCompatibilityDecision::Exact,
                "Same version must be Exact: {major}.{minor}"
            );
            assert!(result.is_compatible());
        }
    }
}

#[test]
fn compatibility_backward_compatible() {
    let producer = WasmAbiVersion { major: 1, minor: 0 };
    for consumer_minor in [1, 2, 5, 100] {
        let consumer = WasmAbiVersion {
            major: 1,
            minor: consumer_minor,
        };
        let result = classify_wasm_abi_compatibility(producer, consumer);
        assert!(
            matches!(
                result,
                WasmAbiCompatibilityDecision::BackwardCompatible { .. }
            ),
            "Consumer newer minor must be BackwardCompatible: consumer minor={consumer_minor}"
        );
        assert!(result.is_compatible());
    }
}

#[test]
fn compatibility_consumer_too_old() {
    let producer = WasmAbiVersion {
        major: 1,
        minor: 10,
    };
    for consumer_minor in [0, 1, 5, 9] {
        let consumer = WasmAbiVersion {
            major: 1,
            minor: consumer_minor,
        };
        let result = classify_wasm_abi_compatibility(producer, consumer);
        assert!(
            matches!(result, WasmAbiCompatibilityDecision::ConsumerTooOld { .. }),
            "Consumer older minor must be ConsumerTooOld: consumer minor={consumer_minor}"
        );
        assert!(!result.is_compatible());
    }
}

#[test]
fn compatibility_major_mismatch() {
    let pairs = [(1, 2), (2, 1), (0, 1), (1, 0), (3, 5)];
    for (pmaj, cmaj) in pairs {
        let result = classify_wasm_abi_compatibility(
            WasmAbiVersion {
                major: pmaj,
                minor: 0,
            },
            WasmAbiVersion {
                major: cmaj,
                minor: 0,
            },
        );
        assert!(
            matches!(result, WasmAbiCompatibilityDecision::MajorMismatch { .. }),
            "Different major must be MajorMismatch: {pmaj} vs {cmaj}"
        );
        assert!(!result.is_compatible());
    }
}

#[test]
fn compatibility_decision_names_are_stable() {
    assert_eq!(WasmAbiCompatibilityDecision::Exact.decision_name(), "exact");
    assert_eq!(
        WasmAbiCompatibilityDecision::BackwardCompatible {
            producer_minor: 0,
            consumer_minor: 1
        }
        .decision_name(),
        "backward_compatible"
    );
    assert_eq!(
        WasmAbiCompatibilityDecision::MajorMismatch {
            producer_major: 1,
            consumer_major: 2
        }
        .decision_name(),
        "major_mismatch"
    );
    assert_eq!(
        WasmAbiCompatibilityDecision::ConsumerTooOld {
            producer_minor: 2,
            consumer_minor: 1
        }
        .decision_name(),
        "consumer_too_old"
    );
}

// ─── Change class → version bump policy ─────────────────────────────

#[test]
fn change_class_minor_bumps() {
    let minor_classes = [
        WasmAbiChangeClass::AdditiveField,
        WasmAbiChangeClass::AdditiveSymbol,
        WasmAbiChangeClass::BehavioralRelaxation,
    ];
    for class in minor_classes {
        assert_eq!(
            required_wasm_abi_bump(class),
            WasmAbiVersionBump::Minor,
            "{class:?} must require Minor bump"
        );
    }
}

#[test]
fn change_class_major_bumps() {
    let major_classes = [
        WasmAbiChangeClass::BehavioralTightening,
        WasmAbiChangeClass::SymbolRemoval,
        WasmAbiChangeClass::ValueEncodingChange,
        WasmAbiChangeClass::OutcomeSemanticChange,
        WasmAbiChangeClass::CancellationSemanticChange,
    ];
    for class in major_classes {
        assert_eq!(
            required_wasm_abi_bump(class),
            WasmAbiVersionBump::Major,
            "{class:?} must require Major bump"
        );
    }
}

// ─── Boundary state machine exhaustive ──────────────────────────────

const ALL_STATES: [WasmBoundaryState; 6] = [
    WasmBoundaryState::Unbound,
    WasmBoundaryState::Bound,
    WasmBoundaryState::Active,
    WasmBoundaryState::Cancelling,
    WasmBoundaryState::Draining,
    WasmBoundaryState::Closed,
];

#[test]
fn boundary_identity_transitions_always_legal() {
    for state in ALL_STATES {
        assert!(
            is_valid_wasm_boundary_transition(state, state),
            "Identity transition must be legal for {state:?}"
        );
        assert!(validate_wasm_boundary_transition(state, state).is_ok());
    }
}

#[test]
fn boundary_forward_transitions_are_legal() {
    let legal = [
        (WasmBoundaryState::Unbound, WasmBoundaryState::Bound),
        (WasmBoundaryState::Bound, WasmBoundaryState::Active),
        (WasmBoundaryState::Bound, WasmBoundaryState::Closed),
        (WasmBoundaryState::Active, WasmBoundaryState::Cancelling),
        (WasmBoundaryState::Active, WasmBoundaryState::Draining),
        (WasmBoundaryState::Active, WasmBoundaryState::Closed),
        (WasmBoundaryState::Cancelling, WasmBoundaryState::Draining),
        (WasmBoundaryState::Cancelling, WasmBoundaryState::Closed),
        (WasmBoundaryState::Draining, WasmBoundaryState::Closed),
    ];
    for (from, to) in legal {
        assert!(
            is_valid_wasm_boundary_transition(from, to),
            "Transition {from:?} -> {to:?} must be legal"
        );
        assert!(validate_wasm_boundary_transition(from, to).is_ok());
    }
}

#[test]
fn boundary_backward_transitions_are_illegal() {
    let illegal = [
        (WasmBoundaryState::Bound, WasmBoundaryState::Unbound),
        (WasmBoundaryState::Active, WasmBoundaryState::Unbound),
        (WasmBoundaryState::Active, WasmBoundaryState::Bound),
        (WasmBoundaryState::Cancelling, WasmBoundaryState::Active),
        (WasmBoundaryState::Cancelling, WasmBoundaryState::Bound),
        (WasmBoundaryState::Cancelling, WasmBoundaryState::Unbound),
        (WasmBoundaryState::Draining, WasmBoundaryState::Active),
        (WasmBoundaryState::Draining, WasmBoundaryState::Cancelling),
        (WasmBoundaryState::Draining, WasmBoundaryState::Bound),
        (WasmBoundaryState::Draining, WasmBoundaryState::Unbound),
        (WasmBoundaryState::Closed, WasmBoundaryState::Unbound),
        (WasmBoundaryState::Closed, WasmBoundaryState::Bound),
        (WasmBoundaryState::Closed, WasmBoundaryState::Active),
        (WasmBoundaryState::Closed, WasmBoundaryState::Cancelling),
        (WasmBoundaryState::Closed, WasmBoundaryState::Draining),
    ];
    for (from, to) in illegal {
        assert!(
            !is_valid_wasm_boundary_transition(from, to),
            "Transition {from:?} -> {to:?} must be illegal"
        );
        assert!(validate_wasm_boundary_transition(from, to).is_err());
    }
}

#[test]
fn boundary_skip_transitions_are_illegal() {
    // Unbound cannot skip to Active, Cancelling, Draining directly
    let skips = [
        (WasmBoundaryState::Unbound, WasmBoundaryState::Active),
        (WasmBoundaryState::Unbound, WasmBoundaryState::Cancelling),
        (WasmBoundaryState::Unbound, WasmBoundaryState::Draining),
        (WasmBoundaryState::Unbound, WasmBoundaryState::Closed),
        (WasmBoundaryState::Bound, WasmBoundaryState::Cancelling),
        (WasmBoundaryState::Bound, WasmBoundaryState::Draining),
    ];
    for (from, to) in skips {
        assert!(
            !is_valid_wasm_boundary_transition(from, to),
            "Skip transition {from:?} -> {to:?} must be illegal"
        );
    }
}

// ─── Handle table lifecycle ─────────────────────────────────────────

#[test]
fn handle_allocate_get_release_cycle() {
    let mut table = WasmHandleTable::new();

    let h = table.allocate(WasmHandleKind::Runtime);
    assert_eq!(h.slot, 0);
    assert_eq!(h.generation, 0);

    let entry = table.get(&h).unwrap();
    assert_eq!(entry.handle.kind, WasmHandleKind::Runtime);
    assert!(matches!(entry.ownership, WasmHandleOwnership::WasmOwned));

    table.release(&h).unwrap();

    // Accessing released handle returns stale generation error (generation bumped)
    let err = table.get(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
}

#[test]
fn handle_generation_bumps_on_reuse() {
    let mut table = WasmHandleTable::new();

    let h1 = table.allocate(WasmHandleKind::Region);
    assert_eq!(h1.generation, 0);
    table.release(&h1).unwrap();

    let h2 = table.allocate(WasmHandleKind::Task);
    assert_eq!(h2.slot, h1.slot, "Freed slot should be reused");
    assert_eq!(h2.generation, 1, "Generation must bump after reuse");

    // Old handle with generation 0 must fail
    let err = table.get(&h1).unwrap_err();
    assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));

    // New handle works
    assert!(table.get(&h2).is_ok());
}

#[test]
fn handle_out_of_bounds_is_rejected() {
    let table = WasmHandleTable::new();
    let fake = WasmHandleRef {
        kind: WasmHandleKind::Runtime,
        slot: 999,
        generation: 0,
    };
    let err = table.get(&fake).unwrap_err();
    assert!(matches!(err, WasmHandleError::SlotOutOfRange { .. }));
}

#[test]
fn handle_pin_unpin_lifecycle() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);

    table.pin(&h).unwrap();
    let entry = table.get(&h).unwrap();
    assert!(entry.pinned, "Handle must be pinned after pin()");

    table.unpin(&h).unwrap();
    let entry = table.get(&h).unwrap();
    assert!(!entry.pinned, "Handle must be unpinned after unpin()");

    table.release(&h).unwrap();
}

#[test]
fn handle_transfer_to_js() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Runtime);

    assert!(matches!(
        table.get(&h).unwrap().ownership,
        WasmHandleOwnership::WasmOwned
    ));

    table.transfer_to_js(&h).unwrap();
    assert!(matches!(
        table.get(&h).unwrap().ownership,
        WasmHandleOwnership::TransferredToJs
    ));

    // Can still release after transfer
    table.release(&h).unwrap();
}

#[test]
fn handle_leak_detection() {
    let mut table = WasmHandleTable::new();
    let h1 = table.allocate(WasmHandleKind::Runtime);
    let h2 = table.allocate(WasmHandleKind::Region);
    let h3 = table.allocate(WasmHandleKind::Task);

    // Transition h2 to Closed state (simulating completed lifecycle)
    // but do NOT release it — this is a "leak" (Closed but not released)
    table.transition(&h2, WasmBoundaryState::Bound).unwrap();
    table.transition(&h2, WasmBoundaryState::Active).unwrap();
    table.transition(&h2, WasmBoundaryState::Closed).unwrap();

    // Release h1 and h3 properly
    table.release(&h1).unwrap();
    table.release(&h3).unwrap();

    let leaks = table.detect_leaks();
    assert_eq!(leaks.len(), 1, "Should detect exactly one leaked handle");
    assert_eq!(leaks[0].slot, 1);
}

#[test]
fn handle_memory_report_is_consistent() {
    let mut table = WasmHandleTable::new();
    let h1 = table.allocate(WasmHandleKind::Runtime);
    let _h2 = table.allocate(WasmHandleKind::Region);

    let report = table.memory_report();
    assert_eq!(report.capacity, 2);
    assert_eq!(report.live_handles, 2);
    assert_eq!(report.free_slots, 0);

    table.release(&h1).unwrap();
    let report = table.memory_report();
    assert_eq!(report.live_handles, 1);
    assert_eq!(report.free_slots, 1);
}

// ─── Cancel phase → boundary state mapping ──────────────────────────

#[test]
fn cancel_phase_to_boundary_state_mapping() {
    assert_eq!(
        wasm_boundary_state_for_cancel_phase(CancelPhase::Requested),
        WasmBoundaryState::Cancelling
    );
    assert_eq!(
        wasm_boundary_state_for_cancel_phase(CancelPhase::Cancelling),
        WasmBoundaryState::Cancelling
    );
    assert_eq!(
        wasm_boundary_state_for_cancel_phase(CancelPhase::Finalizing),
        WasmBoundaryState::Draining
    );
    assert_eq!(
        wasm_boundary_state_for_cancel_phase(CancelPhase::Completed),
        WasmBoundaryState::Closed
    );
}

// ─── Abort signal interop: all three propagation modes ──────────────

#[test]
fn abort_runtime_to_js_propagation() {
    // Runtime cancel phase propagates to JS abort signal
    let update = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        },
        CancelPhase::Requested,
    );
    assert_eq!(update.next_boundary_state, WasmBoundaryState::Cancelling);
    assert!(update.abort_signal_aborted);
    assert!(update.propagated_to_abort_signal);
    assert!(!update.propagated_to_runtime);
}

#[test]
fn abort_js_to_runtime_propagation() {
    // JS abort event propagates to runtime cancel
    let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::AbortSignalToRuntime,
        boundary_state: WasmBoundaryState::Active,
        abort_signal_aborted: false,
    });
    assert_eq!(update.next_boundary_state, WasmBoundaryState::Cancelling);
    assert!(update.abort_signal_aborted);
    assert!(update.propagated_to_runtime);
    assert!(!update.propagated_to_abort_signal);
}

#[test]
fn abort_bidirectional_propagation() {
    // Runtime cancel in bidirectional mode propagates to JS
    let update = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::Bidirectional,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        },
        CancelPhase::Requested,
    );
    assert!(update.propagated_to_abort_signal);
    assert!(update.abort_signal_aborted);

    // JS abort in bidirectional mode propagates to runtime
    let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::Bidirectional,
        boundary_state: WasmBoundaryState::Active,
        abort_signal_aborted: false,
    });
    assert!(update.propagated_to_runtime);
    assert!(update.abort_signal_aborted);
}

#[test]
fn abort_idempotence_no_duplicate_propagation() {
    // Already-aborted signal: repeated abort event is idempotent
    let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::AbortSignalToRuntime,
        boundary_state: WasmBoundaryState::Cancelling,
        abort_signal_aborted: true,
    });
    assert!(update.abort_signal_aborted);
    assert!(
        !update.propagated_to_runtime,
        "Already-aborted must not re-propagate"
    );
}

#[test]
fn abort_monotonicity_never_unaborts() {
    // Once aborted, remains aborted through all subsequent phases
    let phases = [
        CancelPhase::Requested,
        CancelPhase::Cancelling,
        CancelPhase::Finalizing,
        CancelPhase::Completed,
    ];
    let mut aborted = false;
    let mut state = WasmBoundaryState::Active;

    for phase in phases {
        let update = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: state,
                abort_signal_aborted: aborted,
            },
            phase,
        );
        if update.abort_signal_aborted {
            aborted = true;
        }
        state = update.next_boundary_state;
        assert!(
            aborted,
            "Once aborted, must stay aborted through phase {phase:?}"
        );
    }
}

#[test]
fn abort_from_bound_state_closes_directly() {
    // JS abort when still in Bound state should close directly (no active tasks)
    let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::AbortSignalToRuntime,
        boundary_state: WasmBoundaryState::Bound,
        abort_signal_aborted: false,
    });
    assert_eq!(update.next_boundary_state, WasmBoundaryState::Closed);
    assert!(update.abort_signal_aborted);
}

// ─── Outcome → UI state mappings ────────────────────────────────────

#[test]
fn outcome_ok_mappings() {
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
}

#[test]
fn outcome_transient_error_mappings() {
    let err = WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::InternalFailure,
            recoverability: WasmAbiRecoverability::Transient,
            message: "timeout".to_string(),
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&err),
        SuspenseBoundaryState::ErrorRecoverable
    );
    assert_eq!(
        outcome_to_error_boundary_action(&err),
        ErrorBoundaryAction::ShowWithRetry
    );
    assert_eq!(
        outcome_to_transition_state(&err),
        TransitionTaskState::Reverted
    );
}

#[test]
fn outcome_permanent_error_mappings() {
    let err = WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::CompatibilityRejected,
            recoverability: WasmAbiRecoverability::Permanent,
            message: "invalid".to_string(),
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&err),
        SuspenseBoundaryState::ErrorFatal
    );
    assert_eq!(
        outcome_to_error_boundary_action(&err),
        ErrorBoundaryAction::ShowFatal
    );
    assert_eq!(
        outcome_to_transition_state(&err),
        TransitionTaskState::Reverted
    );
}

#[test]
fn outcome_cancelled_mappings() {
    let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: asupersync::WasmAbiCancellation {
            kind: "user".to_string(),
            phase: "completed".to_string(),
            origin_region: "r:1".to_string(),
            origin_task: None,
            timestamp_nanos: 0,
            message: None,
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
}

#[test]
fn outcome_panicked_mappings() {
    let panicked = WasmAbiOutcomeEnvelope::Panicked {
        message: "unexpected".to_string(),
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

// ─── Next.js bootstrap state machine compatibility ──────────────────

const ALL_BOOTSTRAP_PHASES: [NextjsBootstrapPhase; 5] = [
    NextjsBootstrapPhase::ServerRendered,
    NextjsBootstrapPhase::Hydrating,
    NextjsBootstrapPhase::Hydrated,
    NextjsBootstrapPhase::RuntimeReady,
    NextjsBootstrapPhase::RuntimeFailed,
];

#[test]
fn bootstrap_identity_transitions_always_legal() {
    for phase in ALL_BOOTSTRAP_PHASES {
        assert!(
            is_valid_bootstrap_transition(phase, phase),
            "Identity transition must be legal for {phase:?}"
        );
    }
}

#[test]
fn bootstrap_happy_path_is_legal() {
    use NextjsBootstrapPhase::*;
    let path = [ServerRendered, Hydrating, Hydrated, RuntimeReady];
    for window in path.windows(2) {
        assert!(
            is_valid_bootstrap_transition(window[0], window[1]),
            "Happy path transition {:?} -> {:?} must be legal",
            window[0],
            window[1]
        );
    }
}

#[test]
fn bootstrap_failure_path_is_legal() {
    use NextjsBootstrapPhase::*;
    assert!(is_valid_bootstrap_transition(Hydrated, RuntimeFailed));
}

#[test]
fn bootstrap_recovery_paths_are_legal() {
    use NextjsBootstrapPhase::*;
    // Fast Refresh from RuntimeReady
    assert!(is_valid_bootstrap_transition(RuntimeReady, Hydrating));
    // Retry from RuntimeFailed
    assert!(is_valid_bootstrap_transition(RuntimeFailed, Hydrating));
}

#[test]
fn bootstrap_skip_phases_are_illegal() {
    use NextjsBootstrapPhase::*;
    assert!(!is_valid_bootstrap_transition(ServerRendered, RuntimeReady));
    assert!(!is_valid_bootstrap_transition(Hydrating, RuntimeReady));
    assert!(!is_valid_bootstrap_transition(RuntimeFailed, Hydrated));
    assert!(!is_valid_bootstrap_transition(ServerRendered, Hydrated));
    assert!(!is_valid_bootstrap_transition(
        ServerRendered,
        RuntimeFailed
    ));
}
