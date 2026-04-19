//! Contract tests for exported-handle ownership, outcome, and cancellation
//! invariants (asupersync-3qv04.8.2.2).
//!
//! Validates the Rust-side semantic contract of the WASM ABI boundary:
//! handle lifecycle/ownership, boundary state machine, outcome envelope
//! mapping, cancellation propagation, and leak detection.

use asupersync::types::wasm_abi::*;

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

// ── Handle Allocation ────────────────────────────────────────────────

#[test]
fn allocate_returns_unique_handles() {
    let mut table = WasmHandleTable::new();
    let h1 = table.allocate(WasmHandleKind::Runtime);
    let h2 = table.allocate(WasmHandleKind::Region);
    let h3 = table.allocate(WasmHandleKind::Task);

    assert_ne!(h1.slot, h2.slot);
    assert_ne!(h2.slot, h3.slot);
    assert_eq!(table.live_count(), 3);
}

#[test]
fn allocated_handle_starts_unbound_wasm_owned() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Runtime);
    let entry = table.get(&h).unwrap();

    assert_eq!(entry.state, WasmBoundaryState::Unbound);
    assert_eq!(entry.ownership, WasmHandleOwnership::WasmOwned);
    assert!(!entry.pinned);
    assert!(entry.parent.is_none());
}

#[test]
fn allocate_with_parent_sets_parent_ref() {
    let mut table = WasmHandleTable::new();
    let parent = table.allocate(WasmHandleKind::Runtime);
    let child = table.allocate_with_parent(WasmHandleKind::Region, Some(parent));

    let entry = table.get(&child).unwrap();
    assert_eq!(entry.parent, Some(parent));
}

#[test]
fn with_capacity_preallocates() {
    let table = WasmHandleTable::with_capacity(16);
    assert_eq!(table.live_count(), 0);
    assert_eq!(table.capacity(), 0); // no actual slots until allocated
}

// ── Handle Lookup ────────────────────────────────────────────────────

#[test]
fn get_with_valid_handle_succeeds() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);
    assert!(table.get(&h).is_ok());
}

#[test]
fn get_with_out_of_range_slot_fails() {
    let table = WasmHandleTable::new();
    let bogus = WasmHandleRef {
        kind: WasmHandleKind::Task,
        slot: 999,
        generation: 0,
    };
    let err = table.get(&bogus).unwrap_err();
    assert!(matches!(err, WasmHandleError::SlotOutOfRange { .. }));
}

#[test]
fn get_with_stale_generation_fails() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);
    close_handle_for_release(&mut table, &h);
    table.release(&h).unwrap();

    // h now has stale generation
    let err = table.get(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
}

// ── Boundary State Transitions ───────────────────────────────────────

#[test]
fn valid_forward_state_transitions() {
    use WasmBoundaryState::*;
    let valid = [
        (Unbound, Bound),
        (Bound, Active),
        (Bound, Closed),
        (Active, Cancelling),
        (Active, Draining),
        (Active, Closed),
        (Cancelling, Draining),
        (Cancelling, Closed),
        (Draining, Closed),
    ];

    for (from, to) in &valid {
        assert!(
            is_valid_wasm_boundary_transition(*from, *to),
            "transition {from:?} -> {to:?} should be valid"
        );
    }
}

#[test]
fn self_transitions_are_valid() {
    use WasmBoundaryState::*;
    for state in [Unbound, Bound, Active, Cancelling, Draining, Closed] {
        assert!(
            is_valid_wasm_boundary_transition(state, state),
            "self-transition {state:?} -> {state:?} should be valid"
        );
    }
}

#[test]
fn backward_transitions_are_invalid() {
    use WasmBoundaryState::*;
    let invalid = [
        (Bound, Unbound),
        (Active, Bound),
        (Active, Unbound),
        (Closed, Active),
        (Closed, Unbound),
        (Draining, Active),
        (Cancelling, Active),
        (Cancelling, Bound),
    ];

    for (from, to) in &invalid {
        assert!(
            !is_valid_wasm_boundary_transition(*from, *to),
            "transition {from:?} -> {to:?} should be invalid"
        );
    }
}

#[test]
fn validate_transition_returns_error_for_invalid() {
    let result =
        validate_wasm_boundary_transition(WasmBoundaryState::Closed, WasmBoundaryState::Active);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        WasmBoundaryTransitionError::Invalid {
            from: WasmBoundaryState::Closed,
            to: WasmBoundaryState::Active,
        }
    ));
}

#[test]
fn handle_transition_through_full_lifecycle() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);

    table.transition(&h, WasmBoundaryState::Bound).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Bound);

    table.transition(&h, WasmBoundaryState::Active).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Active);

    table.transition(&h, WasmBoundaryState::Draining).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Draining);

    table.transition(&h, WasmBoundaryState::Closed).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Closed);
}

#[test]
fn handle_transition_through_cancellation_path() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);

    table.transition(&h, WasmBoundaryState::Bound).unwrap();
    table.transition(&h, WasmBoundaryState::Active).unwrap();
    table.transition(&h, WasmBoundaryState::Cancelling).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Cancelling);

    table.transition(&h, WasmBoundaryState::Closed).unwrap();
    assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Closed);
}

// ── Ownership Transfer ───────────────────────────────────────────────

#[test]
fn transfer_to_js_changes_ownership() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::FetchRequest);
    table.transfer_to_js(&h).unwrap();
    assert_eq!(
        table.get(&h).unwrap().ownership,
        WasmHandleOwnership::TransferredToJs
    );
}

#[test]
fn double_transfer_to_js_fails() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::FetchRequest);
    table.transfer_to_js(&h).unwrap();

    let err = table.transfer_to_js(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::InvalidTransfer { .. }));
}

// ── Release and Slot Recycling ───────────────────────────────────────

#[test]
fn release_decrements_live_count() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Runtime);
    assert_eq!(table.live_count(), 1);

    close_handle_for_release(&mut table, &h);
    table.release(&h).unwrap();
    assert_eq!(table.live_count(), 0);
}

#[test]
fn double_release_fails() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Runtime);
    close_handle_for_release(&mut table, &h);
    table.release(&h).unwrap();

    let err = table.release(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
}

#[test]
fn released_slot_is_recycled_with_new_generation() {
    let mut table = WasmHandleTable::new();
    let h1 = table.allocate(WasmHandleKind::Task);
    let slot = h1.slot;
    let orig_gen = h1.generation;

    close_handle_for_release(&mut table, &h1);
    table.release(&h1).unwrap();
    let h2 = table.allocate(WasmHandleKind::Region);

    // Same slot, bumped generation
    assert_eq!(h2.slot, slot);
    assert_eq!(h2.generation, orig_gen + 1);
}

#[test]
fn stale_handle_after_recycling_cannot_access_new_entry() {
    let mut table = WasmHandleTable::new();
    let old = table.allocate(WasmHandleKind::Task);
    close_handle_for_release(&mut table, &old);
    table.release(&old).unwrap();
    let _new = table.allocate(WasmHandleKind::Region);

    // old handle has stale generation
    let err = table.get(&old).unwrap_err();
    assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
}

// ── Pin/Unpin ────────────────────────────────────────────────────────

#[test]
fn pin_prevents_release() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::CancelToken);
    table.pin(&h).unwrap();

    let err = table.release(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::ReleasePinned { .. }));
}

#[test]
fn unpin_then_release_succeeds() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::CancelToken);
    table.pin(&h).unwrap();
    table.unpin(&h).unwrap();
    close_handle_for_release(&mut table, &h);
    table.release(&h).unwrap();
    assert_eq!(table.live_count(), 0);
}

#[test]
fn release_before_closed_fails_without_recycling_slot() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);

    let err = table.release(&h).unwrap_err();
    assert_eq!(
        err,
        WasmHandleError::ReleaseBeforeClosed {
            slot: h.slot,
            state: WasmBoundaryState::Unbound,
        }
    );
    assert_eq!(table.live_count(), 1);
    assert_eq!(table.memory_report().free_slots, 0);
}

#[test]
fn release_with_live_descendants_fails_until_children_are_released() {
    let mut table = WasmHandleTable::new();
    let root = table.allocate(WasmHandleKind::Runtime);
    let child = table.allocate_with_parent(WasmHandleKind::Region, Some(root));

    close_handle_for_release(&mut table, &root);
    let err = table.release(&root).unwrap_err();
    assert_eq!(
        err,
        WasmHandleError::ReleaseWithLiveDescendants {
            slot: root.slot,
            live_descendants: 1,
        }
    );

    close_handle_for_release(&mut table, &child);
    table.release(&child).unwrap();
    table.release(&root).unwrap();
    assert_eq!(table.live_count(), 0);
}

#[test]
fn unpin_without_pin_fails() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);

    let err = table.unpin(&h).unwrap_err();
    assert!(matches!(err, WasmHandleError::NotPinned { .. }));
}

#[test]
fn pin_is_idempotent() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Runtime);
    table.pin(&h).unwrap();
    table.pin(&h).unwrap(); // second pin is no-op
    assert!(table.get(&h).unwrap().pinned);
}

// ── Parent-Child Descendants ─────────────────────────────────────────

#[test]
fn descendants_postorder_returns_children_then_grandchildren() {
    let mut table = WasmHandleTable::new();
    let root = table.allocate(WasmHandleKind::Runtime);
    let child1 = table.allocate_with_parent(WasmHandleKind::Region, Some(root));
    let child2 = table.allocate_with_parent(WasmHandleKind::Region, Some(root));
    let grandchild = table.allocate_with_parent(WasmHandleKind::Task, Some(child1));

    let descendants = table
        .descendants_postorder(&root)
        .expect("acyclic ownership tree should enumerate descendants");
    // Post-order: grandchild first, then child1 (its parent), then child2
    assert!(descendants.contains(&grandchild));
    assert!(descendants.contains(&child1));
    assert!(descendants.contains(&child2));
    assert_eq!(descendants.len(), 3);

    // Grandchild must come before child1 (post-order)
    let gc_pos = descendants.iter().position(|h| *h == grandchild).unwrap();
    let c1_pos = descendants.iter().position(|h| *h == child1).unwrap();
    assert!(gc_pos < c1_pos, "post-order: grandchild before parent");
}

#[test]
fn released_children_excluded_from_descendants() {
    let mut table = WasmHandleTable::new();
    let root = table.allocate(WasmHandleKind::Runtime);
    let child = table.allocate_with_parent(WasmHandleKind::Region, Some(root));
    close_handle_for_release(&mut table, &child);
    table.release(&child).unwrap();

    let descendants = table
        .descendants_postorder(&root)
        .expect("released descendants should still produce a successful traversal");
    assert!(descendants.is_empty());
}

// ── Leak Detection ───────────────────────────────────────────────────

#[test]
fn no_leaks_when_all_handles_released() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);
    close_handle_for_release(&mut table, &h);
    table.release(&h).unwrap();
    assert!(table.detect_leaks().is_empty());
}

#[test]
fn closed_but_unreleased_handle_is_leak() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);
    table.transition(&h, WasmBoundaryState::Bound).unwrap();
    table.transition(&h, WasmBoundaryState::Active).unwrap();
    table.transition(&h, WasmBoundaryState::Closed).unwrap();
    // Not released — this is a leak
    let leaks = table.detect_leaks();
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0], h);
}

#[test]
fn active_handle_is_not_a_leak() {
    let mut table = WasmHandleTable::new();
    let h = table.allocate(WasmHandleKind::Task);
    table.transition(&h, WasmBoundaryState::Bound).unwrap();
    table.transition(&h, WasmBoundaryState::Active).unwrap();
    assert!(table.detect_leaks().is_empty());
}

// ── Memory Report ────────────────────────────────────────────────────

#[test]
fn memory_report_reflects_live_state() {
    let mut table = WasmHandleTable::new();
    let h1 = table.allocate(WasmHandleKind::Runtime);
    let _h2 = table.allocate(WasmHandleKind::Task);
    let h3 = table.allocate(WasmHandleKind::Task);
    table.pin(&h1).unwrap();
    close_handle_for_release(&mut table, &h3);
    table.release(&h3).unwrap();

    let report = table.memory_report();
    assert_eq!(report.live_handles, 2);
    assert_eq!(report.pinned_count, 1);
    assert_eq!(report.free_slots, 1);
    assert!(report.by_kind.contains_key("runtime"));
    assert!(report.by_kind.contains_key("task"));
}

// ── Outcome Envelope ─────────────────────────────────────────────────

#[test]
fn outcome_ok_maps_to_ok_envelope() {
    use asupersync::types::Outcome;

    let outcome: Outcome<WasmAbiValue, WasmAbiFailure> =
        Outcome::Ok(WasmAbiValue::String("hello".to_string()));
    let envelope = WasmAbiOutcomeEnvelope::from_outcome(outcome);

    assert!(matches!(
        envelope,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::String(_)
        }
    ));
}

#[test]
fn outcome_err_maps_to_err_envelope() {
    use asupersync::types::Outcome;

    let failure = WasmAbiFailure {
        code: WasmAbiErrorCode::InvalidHandle,
        recoverability: WasmAbiRecoverability::Permanent,
        message: "handle not found".to_string(),
    };
    let outcome: Outcome<WasmAbiValue, WasmAbiFailure> = Outcome::Err(failure);
    let envelope = WasmAbiOutcomeEnvelope::from_outcome(outcome);

    match envelope {
        WasmAbiOutcomeEnvelope::Err { failure } => {
            assert_eq!(failure.code, WasmAbiErrorCode::InvalidHandle);
            assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
        }
        other => panic!("expected Err envelope, got {other:?}"),
    }
}

#[test]
fn outcome_unit_value() {
    use asupersync::types::Outcome;

    let outcome: Outcome<WasmAbiValue, WasmAbiFailure> = Outcome::Ok(WasmAbiValue::Unit);
    let envelope = WasmAbiOutcomeEnvelope::from_outcome(outcome);
    assert!(matches!(
        envelope,
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Unit
        }
    ));
}

#[test]
fn outcome_handle_value_round_trips() {
    use asupersync::types::Outcome;

    let handle = WasmHandleRef {
        kind: WasmHandleKind::Task,
        slot: 42,
        generation: 7,
    };
    let outcome: Outcome<WasmAbiValue, WasmAbiFailure> = Outcome::Ok(WasmAbiValue::Handle(handle));
    let envelope = WasmAbiOutcomeEnvelope::from_outcome(outcome);

    match envelope {
        WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(h),
        } => {
            assert_eq!(h.slot, 42);
            assert_eq!(h.generation, 7);
            assert_eq!(h.kind, WasmHandleKind::Task);
        }
        other => panic!("expected Ok(Handle), got {other:?}"),
    }
}

// ── ABI Version Compatibility ────────────────────────────────────────

#[test]
fn exact_version_match_is_compatible() {
    let decision = WasmAbiCompatibilityDecision::Exact;
    assert!(decision.is_compatible());
    assert_eq!(decision.decision_name(), "exact");
}

#[test]
fn backward_compatible_is_compatible() {
    let decision = WasmAbiCompatibilityDecision::BackwardCompatible {
        producer_minor: 0,
        consumer_minor: 1,
    };
    assert!(decision.is_compatible());
    assert_eq!(decision.decision_name(), "backward_compatible");
}

#[test]
fn major_mismatch_is_incompatible() {
    let decision = WasmAbiCompatibilityDecision::MajorMismatch {
        producer_major: 1,
        consumer_major: 2,
    };
    assert!(!decision.is_compatible());
    assert_eq!(decision.decision_name(), "major_mismatch");
}

#[test]
fn consumer_too_old_is_incompatible() {
    let decision = WasmAbiCompatibilityDecision::ConsumerTooOld {
        producer_minor: 2,
        consumer_minor: 0,
    };
    assert!(!decision.is_compatible());
    assert_eq!(decision.decision_name(), "consumer_too_old");
}

// ── Abort Propagation Modes ──────────────────────────────────────────

#[test]
fn runtime_to_abort_signal_propagates_to_js_only() {
    let mode = WasmAbortPropagationMode::RuntimeToAbortSignal;
    assert!(mode.propagates_runtime_to_abort_signal());
    assert!(!mode.propagates_abort_signal_to_runtime());
}

#[test]
fn abort_signal_to_runtime_propagates_to_runtime_only() {
    let mode = WasmAbortPropagationMode::AbortSignalToRuntime;
    assert!(!mode.propagates_runtime_to_abort_signal());
    assert!(mode.propagates_abort_signal_to_runtime());
}

#[test]
fn bidirectional_propagates_both_ways() {
    let mode = WasmAbortPropagationMode::Bidirectional;
    assert!(mode.propagates_runtime_to_abort_signal());
    assert!(mode.propagates_abort_signal_to_runtime());
}

// ── Fingerprint Stability ────────────────────────────────────────────

#[test]
fn abi_signature_fingerprint_is_deterministic() {
    let fp1 = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
    let fp2 = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
}

#[test]
fn abi_signature_fingerprint_matches_constant() {
    let fp = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
    assert_eq!(
        fp, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
        "fingerprint has drifted from constant — update constant or review ABI changes"
    );
}

// ── Error Code Coverage ──────────────────────────────────────────────

#[test]
fn all_error_codes_have_distinct_serialized_names() {
    let codes = [
        WasmAbiErrorCode::CapabilityDenied,
        WasmAbiErrorCode::InvalidHandle,
        WasmAbiErrorCode::DecodeFailure,
        WasmAbiErrorCode::CompatibilityRejected,
        WasmAbiErrorCode::InternalFailure,
    ];
    let serialized: Vec<String> = codes
        .iter()
        .map(|c| serde_json::to_string(c).unwrap())
        .collect();
    let unique: std::collections::HashSet<&str> = serialized.iter().map(String::as_str).collect();
    assert_eq!(
        serialized.len(),
        unique.len(),
        "all error codes must have distinct serialized names"
    );
}

#[test]
fn recoverability_variants_serialize_to_snake_case() {
    let variants = [
        WasmAbiRecoverability::Transient,
        WasmAbiRecoverability::Permanent,
        WasmAbiRecoverability::Unknown,
    ];
    for v in &variants {
        let s = serde_json::to_string(v).unwrap();
        let inner = s.trim_matches('"');
        assert!(
            inner.chars().all(|c| c.is_lowercase() || c == '_'),
            "recoverability variant must be snake_case, got {inner}"
        );
    }
}
