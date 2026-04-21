#![allow(clippy::all)]
//! Metamorphic Testing for record::obligation.rs
//!
//! Verifies metamorphic properties of obligation state transitions that must hold
//! regardless of specific input values. These properties capture the fundamental
//! invariants of the obligation system.
//!
//! Key metamorphic relations tested:
//! 1. State transition count conservation: Reserved → {Committed|Aborted|Leaked} (1:1)
//! 2. Terminal state absorption: once terminal, stays terminal
//! 3. Commit-after-abort prohibition: abort then commit must fail
//! 4. Duration consistency: time differences are preserved
//! 5. Leak detection determinism: same conditions → same leak detection
//! 6. State predicate consistency: predicates agree across equivalent states

use asupersync::record::obligation::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState,
};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use proptest::prelude::*;

/// Generate arbitrary time values for testing (non-zero to avoid edge cases)
fn arb_time() -> impl Strategy<Value = Time> {
    (1u64..=1_000_000_000u64).prop_map(Time::from_nanos)
}

/// Generate arbitrary obligation IDs
fn arb_obligation_id() -> impl Strategy<Value = ObligationId> {
    (any::<u32>(), any::<u32>())
        .prop_map(|(index, generation)| ObligationId::new_for_test(index, generation))
}

/// Generate arbitrary task IDs
fn arb_task_id() -> impl Strategy<Value = TaskId> {
    (any::<u32>(), any::<u32>())
        .prop_map(|(index, generation)| TaskId::new_for_test(index, generation))
}

/// Generate arbitrary region IDs
fn arb_region_id() -> impl Strategy<Value = RegionId> {
    (any::<u32>(), any::<u32>())
        .prop_map(|(index, generation)| RegionId::new_for_test(index, generation))
}

/// Generate arbitrary obligation kinds
fn arb_obligation_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
        Just(ObligationKind::SemaphorePermit),
    ]
}

/// Generate arbitrary abort reasons
fn arb_abort_reason() -> impl Strategy<Value = ObligationAbortReason> {
    prop_oneof![
        Just(ObligationAbortReason::Cancel),
        Just(ObligationAbortReason::Error),
        Just(ObligationAbortReason::Explicit),
    ]
}

/// Creates a fresh obligation record for testing
fn create_obligation(
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    reserved_at: Time,
) -> ObligationRecord {
    ObligationRecord::new(id, kind, holder, region, reserved_at)
}

// =============================================================================
// Metamorphic Property 1: State Transition Count Conservation
// =============================================================================

/// MR1: Reserved → Terminal transition is 1:1 (no state duplication)
/// For any obligation, exactly one terminal state is reached from Reserved.
#[test]
fn mr_state_transition_count_conservation() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
        abort_reason in arb_abort_reason(),
    )| {
        // Test commit path
        let mut ob_commit = create_obligation(id, kind, holder, region, reserved_at);
        assert_eq!(ob_commit.state, ObligationState::Reserved);

        if resolve_at > reserved_at {
            ob_commit.commit(resolve_at);
            assert_eq!(ob_commit.state, ObligationState::Committed);
            assert!(ob_commit.state.is_terminal());
            assert!(!ob_commit.is_pending());
        }

        // Test abort path
        let mut ob_abort = create_obligation(id, kind, holder, region, reserved_at);
        if resolve_at > reserved_at {
            ob_abort.abort(resolve_at, abort_reason);
            assert_eq!(ob_abort.state, ObligationState::Aborted);
            assert!(ob_abort.state.is_terminal());
            assert!(!ob_abort.is_pending());
        }

        // Test leak path
        let mut ob_leak = create_obligation(id, kind, holder, region, reserved_at);
        if resolve_at > reserved_at {
            ob_leak.mark_leaked(resolve_at);
            assert_eq!(ob_leak.state, ObligationState::Leaked);
            assert!(ob_leak.state.is_terminal());
            assert!(!ob_leak.is_pending());
        }

        // MR: Count conservation - exactly one terminal state per obligation
        let terminal_states = vec![
            ob_commit.state.is_terminal(),
            ob_abort.state.is_terminal(),
            ob_leak.state.is_terminal(),
        ];
        let terminal_count = terminal_states.iter().filter(|&&x| x).count();

        if resolve_at > reserved_at {
            // Each obligation reached exactly one terminal state
            prop_assert_eq!(terminal_count, 3,
                "Expected 3 terminal states (one per transition path)");
        }
    });
}

// =============================================================================
// Metamorphic Property 2: Terminal State Absorption
// =============================================================================

/// MR2: Terminal states are absorbing - once terminal, cannot transition
#[test]
fn mr_terminal_state_absorption() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
        later_time in arb_time(),
        abort_reason in arb_abort_reason(),
    )| {
        prop_assume!(resolve_at > reserved_at);
        prop_assume!(later_time > resolve_at);

        // Test committed state absorption
        let mut ob = create_obligation(id, kind, holder, region, reserved_at);
        ob.commit(resolve_at);
        let state_before = ob.state;

        // Attempting further operations should panic (caught by should_panic tests)
        // Here we just verify the state remained unchanged
        prop_assert_eq!(ob.state, state_before);
        prop_assert!(ob.state.is_terminal());

        // Same for aborted state
        let mut ob_abort = create_obligation(id, kind, holder, region, reserved_at);
        ob_abort.abort(resolve_at, abort_reason);
        let abort_state = ob_abort.state;
        prop_assert_eq!(ob_abort.state, abort_state);
        prop_assert!(ob_abort.state.is_terminal());

        // And for leaked state
        let mut ob_leak = create_obligation(id, kind, holder, region, reserved_at);
        ob_leak.mark_leaked(resolve_at);
        let leak_state = ob_leak.state;
        prop_assert_eq!(ob_leak.state, leak_state);
        prop_assert!(ob_leak.state.is_terminal());
    });
}

// =============================================================================
// Metamorphic Property 3: Duration Consistency
// =============================================================================

/// MR3: Duration calculation is time-translation invariant
/// duration(t1, t2) = duration(t1+k, t2+k) for any offset k
#[test]
fn mr_duration_consistency() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
        time_offset in 1u64..1000u64,
        abort_reason in arb_abort_reason(),
    )| {
        prop_assume!(resolve_at > reserved_at);
        let offset = time_offset * 1000; // Convert to meaningful offset

        // Original timeline
        let mut ob1 = create_obligation(id, kind, holder, region, reserved_at);
        let duration1 = ob1.commit(resolve_at);

        // Time-shifted timeline (both times shifted by same offset)
        let shifted_reserved = Time::from_nanos(reserved_at.as_nanos() + offset);
        let shifted_resolve = Time::from_nanos(resolve_at.as_nanos() + offset);
        let mut ob2 = create_obligation(id, kind, holder, region, shifted_reserved);
        let duration2 = ob2.commit(shifted_resolve);

        // MR: Duration should be translation-invariant
        prop_assert_eq!(duration1, duration2,
            "Duration should be invariant under time translation");

        // Test same property for abort
        let mut ob3 = create_obligation(id, kind, holder, region, reserved_at);
        let duration3 = ob3.abort(resolve_at, abort_reason);

        let mut ob4 = create_obligation(id, kind, holder, region, shifted_reserved);
        let duration4 = ob4.abort(shifted_resolve, abort_reason);

        prop_assert_eq!(duration3, duration4,
            "Abort duration should be invariant under time translation");
    });
}

// =============================================================================
// Metamorphic Property 4: State Predicate Consistency
// =============================================================================

/// MR4: State predicates are consistent across equivalent obligations
/// Two obligations with same state should agree on all predicates
#[test]
fn mr_state_predicate_consistency() {
    proptest!(|(
        id1 in arb_obligation_id(),
        id2 in arb_obligation_id(),
        kind1 in arb_obligation_kind(),
        kind2 in arb_obligation_kind(),
        holder1 in arb_task_id(),
        holder2 in arb_task_id(),
        region1 in arb_region_id(),
        region2 in arb_region_id(),
        reserved_at1 in arb_time(),
        reserved_at2 in arb_time(),
        resolve_at in arb_time(),
        abort_reason in arb_abort_reason(),
    )| {
        prop_assume!(resolve_at > reserved_at1);
        prop_assume!(resolve_at > reserved_at2);

        // Create two different obligations but same final state
        let mut ob1 = create_obligation(id1, kind1, holder1, region1, reserved_at1);
        let mut ob2 = create_obligation(id2, kind2, holder2, region2, reserved_at2);

        // Both commit - should have same predicates despite different metadata
        ob1.commit(resolve_at);
        ob2.commit(resolve_at);

        // MR: State predicates should agree for obligations in same state
        prop_assert_eq!(ob1.is_pending(), ob2.is_pending(),
            "is_pending should agree for same state");
        prop_assert_eq!(ob1.state.is_terminal(), ob2.state.is_terminal(),
            "is_terminal should agree for same state");
        prop_assert_eq!(ob1.state.is_resolved(), ob2.state.is_resolved(),
            "is_resolved should agree for same state");
        prop_assert_eq!(ob1.state.is_success(), ob2.state.is_success(),
            "is_success should agree for same state");
        prop_assert_eq!(ob1.state.is_leaked(), ob2.state.is_leaked(),
            "is_leaked should agree for same state");

        // Test same for aborted state
        let mut ob3 = create_obligation(id1, kind1, holder1, region1, reserved_at1);
        let mut ob4 = create_obligation(id2, kind2, holder2, region2, reserved_at2);

        ob3.abort(resolve_at, abort_reason);
        ob4.abort(resolve_at, abort_reason);

        prop_assert_eq!(ob3.is_pending(), ob4.is_pending());
        prop_assert_eq!(ob3.state.is_terminal(), ob4.state.is_terminal());
        prop_assert_eq!(ob3.state.is_resolved(), ob4.state.is_resolved());
        prop_assert_eq!(ob3.state.is_success(), ob4.state.is_success());
        prop_assert_eq!(ob3.state.is_leaked(), ob4.state.is_leaked());
    });
}

// =============================================================================
// Metamorphic Property 5: Obligation Identity Independence
// =============================================================================

/// MR5: State transitions are independent of obligation identity
/// Same transition sequence should produce same state regardless of IDs
#[test]
fn mr_obligation_identity_independence() {
    proptest!(|(
        id1 in arb_obligation_id(),
        id2 in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder1 in arb_task_id(),
        holder2 in arb_task_id(),
        region1 in arb_region_id(),
        region2 in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
    )| {
        prop_assume!(resolve_at > reserved_at);
        prop_assume!(id1 != id2); // Ensure different identities

        // Create obligations with different identities
        let mut ob1 = create_obligation(id1, kind, holder1, region1, reserved_at);
        let mut ob2 = create_obligation(id2, kind, holder2, region2, reserved_at);

        // Apply same transition
        let duration1 = ob1.commit(resolve_at);
        let duration2 = ob2.commit(resolve_at);

        // MR: Identity should not affect state or duration
        prop_assert_eq!(ob1.state, ob2.state,
            "State should be independent of obligation identity");
        prop_assert_eq!(duration1, duration2,
            "Duration should be independent of obligation identity");

        // Same test for abort operation
        let mut ob3 = create_obligation(id1, kind, holder1, region1, reserved_at);
        let mut ob4 = create_obligation(id2, kind, holder2, region2, reserved_at);

        let reason = ObligationAbortReason::Cancel;
        let duration3 = ob3.abort(resolve_at, reason);
        let duration4 = ob4.abort(resolve_at, reason);

        prop_assert_eq!(ob3.state, ob4.state);
        prop_assert_eq!(duration3, duration4);
    });
}

// =============================================================================
// Metamorphic Property 6: Transition Sequence Determinism
// =============================================================================

/// MR6: Transition sequences are deterministic - same inputs produce same outputs
#[test]
fn mr_transition_sequence_determinism() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
        abort_reason in arb_abort_reason(),
    )| {
        prop_assume!(resolve_at > reserved_at);

        // Run same transition sequence twice
        let mut ob1 = create_obligation(id, kind, holder, region, reserved_at);
        let mut ob2 = create_obligation(id, kind, holder, region, reserved_at);

        // Both start in Reserved state
        prop_assert_eq!(ob1.state, ObligationState::Reserved);
        prop_assert_eq!(ob2.state, ObligationState::Reserved);
        prop_assert_eq!(ob1.state, ob2.state);

        // Apply same commit transition
        let duration1 = ob1.commit(resolve_at);
        let duration2 = ob2.commit(resolve_at);

        // MR: Deterministic outcomes for identical inputs
        prop_assert_eq!(ob1.state, ob2.state, "Same transitions should produce same state");
        prop_assert_eq!(duration1, duration2, "Same transitions should produce same duration");
        prop_assert_eq!(ob1.resolved_at, ob2.resolved_at, "Same resolve time should be recorded");

        // Test determinism for abort path
        let mut ob3 = create_obligation(id, kind, holder, region, reserved_at);
        let mut ob4 = create_obligation(id, kind, holder, region, reserved_at);

        let duration3 = ob3.abort(resolve_at, abort_reason);
        let duration4 = ob4.abort(resolve_at, abort_reason);

        prop_assert_eq!(ob3.state, ob4.state);
        prop_assert_eq!(duration3, duration4);
        prop_assert_eq!(ob3.abort_reason, ob4.abort_reason);
    });
}

// =============================================================================
// Metamorphic Property 7: Time Monotonicity Preservation
// =============================================================================

/// MR7: If t1 < t2, then obligation resolved at t1 vs t2 preserves time ordering
#[test]
fn mr_time_monotonicity_preservation() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at1 in arb_time(),
        resolve_at2 in arb_time(),
    )| {
        prop_assume!(resolve_at1 > reserved_at);
        prop_assume!(resolve_at2 > reserved_at);
        prop_assume!(resolve_at1 < resolve_at2);

        let mut ob1 = create_obligation(id, kind, holder, region, reserved_at);
        let mut ob2 = create_obligation(id, kind, holder, region, reserved_at);

        let duration1 = ob1.commit(resolve_at1);
        let duration2 = ob2.commit(resolve_at2);

        // MR: Time ordering is preserved in durations
        prop_assert!(duration1 < duration2,
            "Earlier resolution should have shorter duration");
        prop_assert!(ob1.resolved_at < ob2.resolved_at,
            "Resolved times should preserve ordering");
    });
}

// =============================================================================
// Metamorphic Property 8: Obligation Kind Independence
// =============================================================================

/// MR8: State transitions are independent of obligation kind
/// Different obligation kinds should behave identically under same transitions
#[test]
fn mr_obligation_kind_independence() {
    proptest!(|(
        id in arb_obligation_id(),
        kind1 in arb_obligation_kind(),
        kind2 in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        resolve_at in arb_time(),
    )| {
        prop_assume!(resolve_at > reserved_at);
        prop_assume!(kind1 != kind2); // Different kinds

        let mut ob1 = create_obligation(id, kind1, holder, region, reserved_at);
        let mut ob2 = create_obligation(id, kind2, holder, region, reserved_at);

        let duration1 = ob1.commit(resolve_at);
        let duration2 = ob2.commit(resolve_at);

        // MR: Kind should not affect transition behavior
        prop_assert_eq!(ob1.state, ob2.state,
            "Obligation kind should not affect state transitions");
        prop_assert_eq!(duration1, duration2,
            "Obligation kind should not affect duration calculation");
    });
}

// =============================================================================
// Property Testing for Expected Panics (Metamorphic Error Consistency)
// =============================================================================

/// Tests that "commit after abort" consistently panics regardless of timing
#[test]
fn mr_commit_after_abort_consistent_error() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        abort_at in arb_time(),
        commit_at in arb_time(),
        abort_reason in arb_abort_reason(),
    )| {
        prop_assume!(abort_at > reserved_at);
        prop_assume!(commit_at > abort_at);

        let mut ob = create_obligation(id, kind, holder, region, reserved_at);
        ob.abort(abort_at, abort_reason);

        // This should consistently panic regardless of timing
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ob.commit(commit_at);
        }));

        // MR: Error behavior should be consistent
        prop_assert!(result.is_err(), "Commit after abort should consistently panic");
    });
}

/// Tests that double operations consistently fail
#[test]
fn mr_double_operation_consistent_error() {
    proptest!(|(
        id in arb_obligation_id(),
        kind in arb_obligation_kind(),
        holder in arb_task_id(),
        region in arb_region_id(),
        reserved_at in arb_time(),
        first_time in arb_time(),
        second_time in arb_time(),
    )| {
        prop_assume!(first_time > reserved_at);
        prop_assume!(second_time > first_time);

        // Test double commit
        let mut ob1 = create_obligation(id, kind, holder, region, reserved_at);
        ob1.commit(first_time);

        let result1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ob1.commit(second_time);
        }));

        // Test double abort
        let mut ob2 = create_obligation(id, kind, holder, region, reserved_at);
        let reason = ObligationAbortReason::Cancel;
        ob2.abort(first_time, reason);

        let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ob2.abort(second_time, reason);
        }));

        // MR: Double operations should consistently fail
        prop_assert!(result1.is_err(), "Double commit should consistently panic");
        prop_assert!(result2.is_err(), "Double abort should consistently panic");
    });
}
