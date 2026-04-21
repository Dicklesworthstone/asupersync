#![allow(warnings)]
#![allow(clippy::all)]
//! WASM ABI Compatibility Harness (WASM-8.5)
//!
//! Validates ABI compatibility invariants: fingerprint stability,
//! version negotiation exhaustive coverage, boundary state machine
//! completeness, handle lifecycle correctness, cancellation/abort
//! interop determinism, and outcome-to-UI mapping stability.
//!
//! Bead: asupersync-umelq.8.5

#![allow(missing_docs)]

use asupersync::types::WasmDispatchError;
use asupersync::types::wasm_abi::{
    ErrorBoundaryAction, WasmHandleError, WasmHandleOwnership, WasmHandleTable,
    WasmScopeEnterRequest, WasmTaskSpawnRequest,
};
use asupersync::types::{CancelPhase, NextjsBootstrapPhase, is_valid_bootstrap_transition};
use asupersync::{
    SuspenseBoundaryState, TransitionTaskState, WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION,
    WASM_ABI_SIGNATURE_FINGERPRINT_V1, WASM_ABI_SIGNATURES_V1, WasmAbiChangeClass,
    WasmAbiCompatibilityDecision, WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope,
    WasmAbiPayloadShape, WasmAbiRecoverability, WasmAbiValue, WasmAbiVersion, WasmAbiVersionBump,
    WasmAbortInteropSnapshot, WasmAbortPropagationMode, WasmBoundaryState, WasmExportDispatcher,
    WasmHandleKind, WasmHandleRef, apply_abort_signal_event, apply_runtime_cancel_phase_event,
    classify_wasm_abi_compatibility, is_valid_wasm_boundary_transition,
    outcome_to_error_boundary_action, outcome_to_suspense_state, outcome_to_transition_state,
    required_wasm_abi_bump, validate_wasm_boundary_transition, wasm_abi_signature_fingerprint,
    wasm_boundary_state_for_cancel_phase,
};
use std::path::Path;

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

    close_handle_for_release(&mut table, &h);
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
    close_handle_for_release(&mut table, &h1);
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

    close_handle_for_release(&mut table, &h);
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
    close_handle_for_release(&mut table, &h);
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
    close_handle_for_release(&mut table, &h1);
    close_handle_for_release(&mut table, &h3);
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

    close_handle_for_release(&mut table, &h1);
    table.release(&h1).unwrap();
    let report = table.memory_report();
    assert_eq!(report.live_handles, 1);
    assert_eq!(report.free_slots, 1);
}

#[test]
fn handle_descendants_postorder_is_deterministic_and_skips_released_children() {
    let mut table = WasmHandleTable::new();

    let root = table.allocate(WasmHandleKind::Runtime);
    let child_a = table.allocate_with_parent(WasmHandleKind::Region, Some(root));
    let grandchild_a = table.allocate_with_parent(WasmHandleKind::Task, Some(child_a));
    let child_b = table.allocate_with_parent(WasmHandleKind::FetchRequest, Some(root));
    let grandchild_b = table.allocate_with_parent(WasmHandleKind::Task, Some(child_b));

    close_handle_for_release(&mut table, &grandchild_a);
    table.release(&grandchild_a).unwrap();

    let descendants = table.descendants_postorder(&root).unwrap();
    assert_eq!(
        descendants,
        vec![child_a, grandchild_b, child_b],
        "descendants must be stable post-order and skip released children"
    );
}

#[test]
fn release_pinned_handle_is_rejected_without_mutating_counts() {
    let mut table = WasmHandleTable::new();
    let handle = table.allocate(WasmHandleKind::Task);
    table.pin(&handle).unwrap();

    let err = table.release(&handle).unwrap_err();
    assert_eq!(err, WasmHandleError::ReleasePinned { slot: handle.slot });
    assert_eq!(
        table.live_count(),
        1,
        "failed release must not drop live count"
    );
    assert_eq!(
        table.memory_report().free_slots,
        0,
        "failed release must not recycle slot"
    );

    let entry = table.get(&handle).unwrap();
    assert!(entry.pinned, "failed release must leave pin state intact");
    assert_eq!(entry.ownership, WasmHandleOwnership::WasmOwned);
}

#[test]
fn transfer_to_js_cannot_repeat_or_cross_release_boundary() {
    let mut table = WasmHandleTable::new();
    let handle = table.allocate(WasmHandleKind::FetchRequest);

    table.transfer_to_js(&handle).unwrap();
    let err = table.transfer_to_js(&handle).unwrap_err();
    assert_eq!(
        err,
        WasmHandleError::InvalidTransfer {
            slot: handle.slot,
            current: WasmHandleOwnership::TransferredToJs,
        }
    );

    close_handle_for_release(&mut table, &handle);
    table.release(&handle).unwrap();
    let err = table.transfer_to_js(&handle).unwrap_err();
    assert!(
        matches!(err, WasmHandleError::StaleGeneration { .. }),
        "released handles must fail closed on post-release transfer"
    );
}

#[test]
fn explicit_scope_close_releases_descendants_without_leaks() {
    let mut dispatcher = WasmExportDispatcher::new();
    let runtime = dispatcher.runtime_create(None).unwrap();
    let scope = dispatcher
        .scope_enter(
            &WasmScopeEnterRequest {
                parent: runtime,
                label: Some("scope-close".to_string()),
            },
            None,
        )
        .unwrap();
    let task = dispatcher
        .task_spawn(
            &WasmTaskSpawnRequest {
                scope,
                label: Some("close-me".to_string()),
                cancel_kind: Some("user".to_string()),
            },
            None,
        )
        .unwrap();

    let outcome = dispatcher.scope_close(&scope, None).unwrap();
    assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
    assert!(dispatcher.handles().get(&scope).is_err());
    assert!(dispatcher.handles().get(&task).is_err());
    assert!(
        dispatcher.handles().get(&runtime).is_ok(),
        "scope_close must not release the parent runtime handle"
    );
    assert_eq!(dispatcher.handles().live_count(), 1);
    assert!(
        dispatcher.handles().detect_leaks().is_empty(),
        "explicit close must drain descendants without leaks"
    );
}

#[test]
fn explicit_scope_close_rejects_stale_second_close_without_touching_runtime() {
    let mut dispatcher = WasmExportDispatcher::new();
    let runtime = dispatcher.runtime_create(None).unwrap();
    let scope = dispatcher
        .scope_enter(
            &WasmScopeEnterRequest {
                parent: runtime,
                label: Some("double-close".to_string()),
            },
            None,
        )
        .unwrap();

    dispatcher.scope_close(&scope, None).unwrap();
    let err = dispatcher.scope_close(&scope, None).unwrap_err();
    assert!(
        matches!(
            err,
            WasmDispatchError::Handle(WasmHandleError::StaleGeneration { slot, .. })
                if slot == scope.slot
        ),
        "second scope_close must fail on a stale handle instead of double-freeing"
    );
    assert!(
        dispatcher.handles().get(&runtime).is_ok(),
        "failed second scope_close must not disturb the parent runtime"
    );
    assert_eq!(dispatcher.handles().live_count(), 1);
}

#[test]
fn explicit_runtime_close_rejects_stale_second_close_without_leaks() {
    let mut dispatcher = WasmExportDispatcher::new();
    let runtime = dispatcher.runtime_create(None).unwrap();

    let outcome = dispatcher.runtime_close(&runtime, None).unwrap();
    assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));

    let err = dispatcher.runtime_close(&runtime, None).unwrap_err();
    assert!(
        matches!(
            err,
            WasmDispatchError::Handle(WasmHandleError::StaleGeneration { slot, .. })
                if slot == runtime.slot
        ),
        "second runtime_close must fail on a stale handle instead of double-freeing"
    );
    assert_eq!(dispatcher.handles().live_count(), 0);
    assert!(dispatcher.handles().detect_leaks().is_empty());
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
fn abort_signal_does_not_propagate_to_runtime_in_runtime_to_js_mode() {
    let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
        mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
        boundary_state: WasmBoundaryState::Active,
        abort_signal_aborted: false,
    });
    assert_eq!(update.next_boundary_state, WasmBoundaryState::Active);
    assert!(update.abort_signal_aborted);
    assert!(!update.propagated_to_runtime);
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
fn runtime_cancel_does_not_abort_signal_in_abort_to_runtime_only_mode() {
    let update = apply_runtime_cancel_phase_event(
        WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::AbortSignalToRuntime,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        },
        CancelPhase::Requested,
    );
    assert_eq!(update.next_boundary_state, WasmBoundaryState::Cancelling);
    assert!(!update.abort_signal_aborted);
    assert!(!update.propagated_to_runtime);
    assert!(!update.propagated_to_abort_signal);
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

#[test]
fn dispatch_error_to_failure_preserves_error_class() {
    let incompatible = WasmDispatchError::Incompatible {
        decision: WasmAbiCompatibilityDecision::MajorMismatch {
            producer_major: 1,
            consumer_major: 2,
        },
    };
    let failure = incompatible.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::CompatibilityRejected);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);

    let handle = WasmDispatchError::Handle(WasmHandleError::AlreadyReleased { slot: 3 });
    let failure = handle.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::InvalidHandle);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);

    let invalid_request = WasmDispatchError::InvalidRequest {
        reason: "missing payload".to_string(),
    };
    let failure = invalid_request.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::DecodeFailure);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
}

#[test]
fn dispatch_error_to_outcome_wraps_failure_without_losing_message() {
    let err = WasmDispatchError::InvalidState {
        state: WasmBoundaryState::Draining,
        symbol: asupersync::WasmAbiSymbol::TaskJoin,
    };
    let expected_failure = err.to_failure();
    let outcome = err.to_outcome();
    assert_eq!(
        outcome,
        WasmAbiOutcomeEnvelope::Err {
            failure: expected_failure,
        }
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
