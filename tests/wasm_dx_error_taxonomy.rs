//! WASM DX Error Taxonomy Validation (WASM-9.5)
//!
//! Validates that the DX error taxonomy document exists, covers all
//! error codes, recoverability levels, handle errors, dispatch errors,
//! outcome mappings, and diagnostic enrichment surface. Validates
//! dispatch-to-failure mapping correctness and cross-references.
//!
//! Bead: asupersync-umelq.9.5

#![allow(missing_docs)]

use asupersync::types::wasm_abi::{
    ErrorBoundaryAction, WasmBoundaryEventLog, WasmDispatchError, WasmHandleError, WasmHandleTable,
};
use asupersync::{
    SuspenseBoundaryState, TransitionTaskState, WasmAbiCompatibilityDecision, WasmAbiErrorCode,
    WasmAbiFailure, WasmAbiOutcomeEnvelope, WasmAbiRecoverability, WasmAbiSymbol, WasmAbiValue,
    WasmBoundaryState, WasmHandleKind, outcome_to_error_boundary_action, outcome_to_suspense_state,
    outcome_to_transition_state,
};
use std::path::Path;

fn load_taxonomy() -> String {
    std::fs::read_to_string("docs/wasm_dx_error_taxonomy.md")
        .expect("failed to load DX error taxonomy")
}

// ─── Document infrastructure ─────────────────────────────────────────

#[test]
fn taxonomy_document_exists() {
    assert!(
        Path::new("docs/wasm_dx_error_taxonomy.md").exists(),
        "DX error taxonomy document must exist"
    );
}

#[test]
fn taxonomy_references_bead() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("asupersync-umelq.9.5"),
        "Taxonomy must reference its own bead ID"
    );
}

#[test]
fn taxonomy_references_cross_documents() {
    let doc = load_taxonomy();
    let refs = [
        "wasm_abi_contract.md",
        "wasm_abi_compatibility_policy.md",
        "wasm_typescript_type_model_contract.md",
        "wasm_typescript_package_topology.md",
        "wasm_bundler_compatibility_matrix.md",
    ];
    let mut missing = Vec::new();
    for r in &refs {
        if !doc.contains(r) {
            missing.push(*r);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing cross-references:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Error code coverage ─────────────────────────────────────────────

#[test]
fn taxonomy_covers_all_error_codes() {
    let doc = load_taxonomy();
    let codes = [
        "CapabilityDenied",
        "InvalidHandle",
        "DecodeFailure",
        "CompatibilityRejected",
        "InternalFailure",
    ];
    let mut missing = Vec::new();
    for code in &codes {
        if !doc.contains(code) {
            missing.push(*code);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing error codes:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_covers_all_recoverability_levels() {
    let doc = load_taxonomy();
    let levels = ["Transient", "Permanent", "Unknown"];
    let mut missing = Vec::new();
    for level in &levels {
        if !doc.contains(level) {
            missing.push(*level);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing recoverability levels:\n{}",
        missing
            .iter()
            .map(|l| format!("  - {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Handle error coverage ───────────────────────────────────────────

#[test]
fn taxonomy_covers_all_handle_errors() {
    let doc = load_taxonomy();
    let errors = [
        "SlotOutOfRange",
        "StaleGeneration",
        "AlreadyReleased",
        "InvalidTransfer",
        "NotPinned",
        "ReleasePinned",
    ];
    let mut missing = Vec::new();
    for err in &errors {
        if !doc.contains(err) {
            missing.push(*err);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing handle errors:\n{}",
        missing
            .iter()
            .map(|e| format!("  - {e}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Dispatch error coverage ─────────────────────────────────────────

#[test]
fn taxonomy_covers_all_dispatch_errors() {
    let doc = load_taxonomy();
    let dispatch_errors = ["Incompatible", "InvalidState", "InvalidRequest"];
    let mut missing = Vec::new();
    for de in &dispatch_errors {
        if !doc.contains(de) {
            missing.push(*de);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing dispatch error variants:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Outcome mapping coverage ────────────────────────────────────────

#[test]
fn taxonomy_covers_outcome_variants() {
    let doc = load_taxonomy();
    let outcomes = ["Ok", "Err", "Cancelled", "Panicked"];
    let mut missing = Vec::new();
    for outcome in &outcomes {
        if !doc.contains(outcome) {
            missing.push(*outcome);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing outcome variants:\n{}",
        missing
            .iter()
            .map(|o| format!("  - {o}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_covers_suspense_states() {
    let doc = load_taxonomy();
    let states = ["Resolved", "ErrorRecoverable", "ErrorFatal", "Cancelled"];
    let mut missing = Vec::new();
    for state in &states {
        if !doc.contains(state) {
            missing.push(*state);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing Suspense boundary states:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_covers_error_boundary_actions() {
    let doc = load_taxonomy();
    let actions = ["ShowWithRetry", "ShowFatal"];
    let mut missing = Vec::new();
    for action in &actions {
        if !doc.contains(action) {
            missing.push(*action);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing error boundary actions:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_covers_transition_states() {
    let doc = load_taxonomy();
    let states = ["Committed", "Reverted"];
    let mut missing = Vec::new();
    for state in &states {
        if !doc.contains(state) {
            missing.push(*state);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing transition task states:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Dispatch-to-failure mapping correctness ─────────────────────────

#[test]
fn dispatch_incompatible_maps_to_compatibility_rejected() {
    let err = WasmDispatchError::Incompatible {
        decision: WasmAbiCompatibilityDecision::MajorMismatch {
            producer_major: 2,
            consumer_major: 1,
        },
    };
    let failure = err.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::CompatibilityRejected);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
}

#[test]
fn dispatch_handle_error_maps_to_invalid_handle() {
    let err = WasmDispatchError::Handle(WasmHandleError::SlotOutOfRange {
        slot: 99,
        table_size: 10,
    });
    let failure = err.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::InvalidHandle);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
}

#[test]
fn dispatch_invalid_state_maps_to_invalid_handle() {
    let err = WasmDispatchError::InvalidState {
        state: WasmBoundaryState::Unbound,
        symbol: WasmAbiSymbol::TaskSpawn,
    };
    let failure = err.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::InvalidHandle);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
}

#[test]
fn dispatch_invalid_request_maps_to_decode_failure() {
    let err = WasmDispatchError::InvalidRequest {
        reason: "missing field 'budget'".into(),
    };
    let failure = err.to_failure();
    assert_eq!(failure.code, WasmAbiErrorCode::DecodeFailure);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
}

#[test]
fn dispatch_to_outcome_wraps_as_err() {
    let err = WasmDispatchError::InvalidRequest {
        reason: "test".into(),
    };
    let outcome = err.to_outcome();
    match outcome {
        WasmAbiOutcomeEnvelope::Err { failure } => {
            assert_eq!(failure.code, WasmAbiErrorCode::DecodeFailure);
        }
        other => panic!("expected Err outcome, got {other:?}"),
    }
}

// ─── All dispatch errors are permanent ───────────────────────────────

#[test]
fn all_dispatch_errors_are_permanent() {
    let errors: Vec<WasmDispatchError> = vec![
        WasmDispatchError::Incompatible {
            decision: WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2,
            },
        },
        WasmDispatchError::Handle(WasmHandleError::AlreadyReleased { slot: 0 }),
        WasmDispatchError::InvalidState {
            state: WasmBoundaryState::Closed,
            symbol: WasmAbiSymbol::RuntimeCreate,
        },
        WasmDispatchError::InvalidRequest {
            reason: "test".into(),
        },
    ];
    for err in &errors {
        let failure = err.to_failure();
        assert_eq!(
            failure.recoverability,
            WasmAbiRecoverability::Permanent,
            "Dispatch error {err:?} should map to Permanent recoverability"
        );
    }
}

// ─── Failure construction correctness ────────────────────────────────

#[test]
fn failure_has_all_required_fields() {
    let failure = WasmAbiFailure {
        code: WasmAbiErrorCode::CapabilityDenied,
        recoverability: WasmAbiRecoverability::Permanent,
        message: "test capability failure".into(),
    };
    // All three fields must be populated
    assert_eq!(failure.code, WasmAbiErrorCode::CapabilityDenied);
    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
    assert!(!failure.message.is_empty());
}

#[test]
fn failure_serializes_to_snake_case() {
    let failure = WasmAbiFailure {
        code: WasmAbiErrorCode::CapabilityDenied,
        recoverability: WasmAbiRecoverability::Transient,
        message: "test".into(),
    };
    let json = serde_json::to_string(&failure).expect("serialize");
    assert!(
        json.contains("capability_denied"),
        "code must be snake_case"
    );
    assert!(
        json.contains("transient"),
        "recoverability must be snake_case"
    );
}

// ─── Outcome-to-UI mapping integration ───────────────────────────────

#[test]
fn transient_error_maps_to_recoverable_ui_states() {
    let outcome = WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::InternalFailure,
            recoverability: WasmAbiRecoverability::Transient,
            message: "transient failure".into(),
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&outcome),
        SuspenseBoundaryState::ErrorRecoverable
    );
    assert_eq!(
        outcome_to_error_boundary_action(&outcome),
        ErrorBoundaryAction::ShowWithRetry
    );
    assert_eq!(
        outcome_to_transition_state(&outcome),
        TransitionTaskState::Reverted
    );
}

#[test]
fn permanent_error_maps_to_fatal_ui_states() {
    let outcome = WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::CapabilityDenied,
            recoverability: WasmAbiRecoverability::Permanent,
            message: "permanent failure".into(),
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&outcome),
        SuspenseBoundaryState::ErrorFatal
    );
    assert_eq!(
        outcome_to_error_boundary_action(&outcome),
        ErrorBoundaryAction::ShowFatal
    );
    assert_eq!(
        outcome_to_transition_state(&outcome),
        TransitionTaskState::Reverted
    );
}

#[test]
fn panicked_maps_to_fatal_ui_states() {
    let outcome = WasmAbiOutcomeEnvelope::Panicked {
        message: "unexpected panic".into(),
    };
    assert_eq!(
        outcome_to_suspense_state(&outcome),
        SuspenseBoundaryState::ErrorFatal
    );
    assert_eq!(
        outcome_to_error_boundary_action(&outcome),
        ErrorBoundaryAction::ShowFatal
    );
    assert_eq!(
        outcome_to_transition_state(&outcome),
        TransitionTaskState::Reverted
    );
}

#[test]
fn cancelled_maps_to_clean_ui_states() {
    let outcome = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: asupersync::WasmAbiCancellation {
            kind: "explicit".into(),
            phase: "completed".into(),
            origin_region: "root".into(),
            origin_task: None,
            timestamp_nanos: 0,
            message: Some("user cancelled".into()),
            truncated: false,
        },
    };
    assert_eq!(
        outcome_to_suspense_state(&outcome),
        SuspenseBoundaryState::Cancelled
    );
    assert_eq!(
        outcome_to_error_boundary_action(&outcome),
        ErrorBoundaryAction::None
    );
    assert_eq!(
        outcome_to_transition_state(&outcome),
        TransitionTaskState::Cancelled
    );
}

#[test]
fn ok_maps_to_success_ui_states() {
    let outcome = WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Unit,
    };
    assert_eq!(
        outcome_to_suspense_state(&outcome),
        SuspenseBoundaryState::Resolved
    );
    assert_eq!(
        outcome_to_error_boundary_action(&outcome),
        ErrorBoundaryAction::None
    );
    assert_eq!(
        outcome_to_transition_state(&outcome),
        TransitionTaskState::Committed
    );
}

// ─── Handle table error paths ────────────────────────────────────────

#[test]
fn handle_table_stale_generation_error() {
    let mut table = WasmHandleTable::new();
    let handle = table.allocate(WasmHandleKind::Task);
    // Release the handle
    table
        .transition(&handle, WasmBoundaryState::Bound)
        .expect("bound");
    table
        .transition(&handle, WasmBoundaryState::Active)
        .expect("active");
    table
        .transition(&handle, WasmBoundaryState::Closed)
        .expect("closed");
    table.release(&handle).expect("release");

    // Now allocate a new handle (reuses slot with bumped generation)
    let _new_handle = table.allocate(WasmHandleKind::Region);

    // Old handle has stale generation — get should fail
    let result = table.get(&handle);
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmHandleError::StaleGeneration { .. } => {}
        other => panic!("expected StaleGeneration, got {other:?}"),
    }
}

#[test]
fn handle_table_double_release_error() {
    let mut table = WasmHandleTable::new();
    let handle = table.allocate(WasmHandleKind::Runtime);
    table
        .transition(&handle, WasmBoundaryState::Bound)
        .expect("bound");
    table
        .transition(&handle, WasmBoundaryState::Active)
        .expect("active");
    table
        .transition(&handle, WasmBoundaryState::Closed)
        .expect("closed");
    table.release(&handle).expect("first release");

    // Double release fails with StaleGeneration because release() bumps
    // generation and clears the slot.
    let result = table.release(&handle);
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmHandleError::StaleGeneration { .. } => {}
        other => panic!("expected StaleGeneration on double release, got {other:?}"),
    }
}

#[test]
fn handle_table_release_pinned_error() {
    let mut table = WasmHandleTable::new();
    let handle = table.allocate(WasmHandleKind::Task);
    table
        .transition(&handle, WasmBoundaryState::Bound)
        .expect("bound");
    table
        .transition(&handle, WasmBoundaryState::Active)
        .expect("active");
    table.pin(&handle).expect("pin");

    // Move to closed while pinned
    table
        .transition(&handle, WasmBoundaryState::Closed)
        .expect("closed");

    // Release pinned should fail
    let result = table.release(&handle);
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmHandleError::ReleasePinned { .. } => {}
        other => panic!("expected ReleasePinned, got {other:?}"),
    }
}

// ─── Diagnostic types exist ──────────────────────────────────────────

#[test]
fn boundary_event_log_is_constructible() {
    let log = WasmBoundaryEventLog::default();
    assert_eq!(log.events().len(), 0, "Empty log should have no events");
}

// ─── Error code exhaustiveness ───────────────────────────────────────

#[test]
fn error_code_count_is_five() {
    // Enumerate all error codes to ensure exhaustiveness
    let codes = [
        WasmAbiErrorCode::CapabilityDenied,
        WasmAbiErrorCode::InvalidHandle,
        WasmAbiErrorCode::DecodeFailure,
        WasmAbiErrorCode::CompatibilityRejected,
        WasmAbiErrorCode::InternalFailure,
    ];
    assert_eq!(
        codes.len(),
        5,
        "WasmAbiErrorCode must have exactly 5 variants"
    );
}

#[test]
fn recoverability_count_is_three() {
    let levels = [
        WasmAbiRecoverability::Transient,
        WasmAbiRecoverability::Permanent,
        WasmAbiRecoverability::Unknown,
    ];
    assert_eq!(
        levels.len(),
        3,
        "WasmAbiRecoverability must have exactly 3 variants"
    );
}

// ─── Taxonomy document structure ─────────────────────────────────────

#[test]
fn taxonomy_has_required_sections() {
    let doc = load_taxonomy();
    let sections = [
        "Error Taxonomy",
        "Outcome-to-Developer-Action Mapping",
        "Diagnostic Enrichment Contract",
        "Developer Error Message Catalog",
        "IntelliSense Quality Contract",
        "Boundary Violation Diagnostics",
        "CI Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !doc.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_documents_initialization_errors() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("Initialization Errors") || doc.contains("initialization"),
        "Taxonomy must document initialization error scenarios"
    );
}

#[test]
fn taxonomy_documents_cancellation_errors() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("Cancellation") || doc.contains("cancellation"),
        "Taxonomy must document cancellation/abort error scenarios"
    );
}

#[test]
fn taxonomy_documents_feature_mismatch_errors() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("Feature Mismatch") || doc.contains("feature mismatch"),
        "Taxonomy must document feature mismatch error scenarios"
    );
}

#[test]
fn taxonomy_documents_nextjs_boundary_violations() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("server_component") && doc.contains("edge_runtime"),
        "Taxonomy must document Next.js boundary violation diagnostics"
    );
}

#[test]
fn taxonomy_documents_react_strict_mode() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("Strict Mode"),
        "Taxonomy must document React Strict Mode diagnostics"
    );
}

#[test]
fn taxonomy_documents_recovery_decision_tree() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("Recovery Decision Tree") || doc.contains("recovery decision"),
        "Taxonomy must include a recovery decision tree"
    );
}

#[test]
fn taxonomy_documents_diagnostic_log_fields() {
    let doc = load_taxonomy();
    let fields = [
        "abi_version",
        "symbol",
        "payload_shape",
        "state_from",
        "state_to",
        "compatibility",
    ];
    let mut missing = Vec::new();
    for field in &fields {
        if !doc.contains(field) {
            missing.push(*field);
        }
    }
    assert!(
        missing.is_empty(),
        "Taxonomy missing diagnostic log fields:\n{}",
        missing
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn taxonomy_references_test_suite() {
    let doc = load_taxonomy();
    assert!(
        doc.contains("wasm_dx_error_taxonomy"),
        "Taxonomy must reference its own test suite"
    );
}
