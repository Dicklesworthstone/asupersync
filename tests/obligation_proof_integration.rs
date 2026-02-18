//! Integration and property-based tests for Separation Logic proof infrastructure.
//!
//! This test suite validates the three proof modules from the bd-1xwvk series
//! (separation logic specs, no-aliasing proof, no-leak proof) both individually
//! at scale and in cross-module integration scenarios.
//!
//! # Coverage
//!
//! 1. **Cross-module consistency**: same event trace verified by all three provers
//! 2. **Dynamic no-aliasing registry**: concurrent permit lifecycles
//! 3. **Dynamic no-leak check**: region quiescence with random obligations
//! 4. **Cancellation path coverage**: all exit paths exercise Drop correctly
//! 5. **Mutation testing**: known-bad traces rejected by all three provers
//! 6. **Cross-obligation interaction**: multiple kinds interacting
//! 7. **Property-based tests**: random lifecycle sequences preserve invariants

#[macro_use]
mod common;
use common::*;

use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind};
use asupersync::obligation::no_aliasing_proof::{
    NoAliasingProver, ViolationKind as AliasingViolation,
};
use asupersync::obligation::no_leak_proof::{LivenessProperty, NoLeakProver};
use asupersync::obligation::separation_logic::SeparationLogicVerifier;
use asupersync::record::ObligationKind;
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use proptest::prelude::*;

// ============================================================================
// Helper constructors
// ============================================================================

fn o(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}
fn t(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}
fn r(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn reserve(
    time_ns: u64,
    obl: ObligationId,
    kind: ObligationKind,
    task: TaskId,
    region: RegionId,
) -> MarkingEvent {
    MarkingEvent::new(
        Time::from_nanos(time_ns),
        MarkingEventKind::Reserve {
            obligation: obl,
            kind,
            task,
            region,
        },
    )
}

fn commit(time_ns: u64, obl: ObligationId, region: RegionId, kind: ObligationKind) -> MarkingEvent {
    MarkingEvent::new(
        Time::from_nanos(time_ns),
        MarkingEventKind::Commit {
            obligation: obl,
            region,
            kind,
        },
    )
}

fn abort(time_ns: u64, obl: ObligationId, region: RegionId, kind: ObligationKind) -> MarkingEvent {
    MarkingEvent::new(
        Time::from_nanos(time_ns),
        MarkingEventKind::Abort {
            obligation: obl,
            region,
            kind,
        },
    )
}

fn leak(time_ns: u64, obl: ObligationId, region: RegionId, kind: ObligationKind) -> MarkingEvent {
    MarkingEvent::new(
        Time::from_nanos(time_ns),
        MarkingEventKind::Leak {
            obligation: obl,
            region,
            kind,
        },
    )
}

fn close(time_ns: u64, region: RegionId) -> MarkingEvent {
    MarkingEvent::new(
        Time::from_nanos(time_ns),
        MarkingEventKind::RegionClose { region },
    )
}

const ALL_KINDS: [ObligationKind; 4] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

// ============================================================================
// 1. Cross-Module Consistency
// ============================================================================

/// A clean trace must pass all three provers.
#[test]
fn cross_module_clean_trace_all_provers_agree() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::Ack, t(1), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        abort(11, o(1), r(0), ObligationKind::Ack),
        close(20, r(0)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(sl_result.is_sound(), "SL verifier: {sl_result}");

    let mut aliasing = NoAliasingProver::all_kinds();
    let aliasing_result = aliasing.check(&events);
    assert!(
        aliasing_result.is_verified(),
        "no-aliasing: {aliasing_result}"
    );

    let mut leak = NoLeakProver::new();
    let leak_result = leak.check(&events);
    assert!(leak_result.is_verified(), "no-leak: {leak_result}");
    assert_eq!(leak_result.ghost_counter_final, 0);
}

/// A trace with an unresolved obligation must be detected by both
/// the SL verifier and the no-leak prover.
#[test]
fn cross_module_unresolved_detected_by_sl_and_leak() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        // No commit/abort — obligation leaks at trace end.
    ];

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound(), "SL should detect unresolved");

    let mut leak = NoLeakProver::new();
    let leak_result = leak.check(&events);
    assert!(
        !leak_result.is_verified(),
        "leak prover should detect unresolved"
    );
    assert!(
        leak_result
            .counterexamples
            .iter()
            .any(|c| c.property == LivenessProperty::EventualResolution),
        "should have EventualResolution counterexample"
    );
}

/// A trace with kind mismatch (reserve SendPermit, commit as Lease) must be
/// detected by both SL verifier and no-aliasing prover.
#[test]
fn cross_module_kind_mismatch_detected_by_sl_and_aliasing() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(10, o(0), r(0), ObligationKind::Lease), // Wrong kind!
        close(20, r(0)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound(), "SL should detect kind mismatch");

    let mut aliasing = NoAliasingProver::new(); // sendpermit_only mode
    let aliasing_result = aliasing.check(&events);
    assert!(
        !aliasing_result.is_verified(),
        "no-aliasing should detect kind confusion"
    );
    assert!(
        aliasing_result
            .counterexamples
            .iter()
            .any(|c| c.violation == AliasingViolation::KindDisagreement),
        "should have KindDisagreement counterexample"
    );
}

/// Region close with pending obligation detected by SL and no-leak.
#[test]
fn cross_module_premature_region_close() {
    let events = vec![
        reserve(0, o(0), ObligationKind::IoOp, t(0), r(0)),
        close(10, r(0)), // Close while obligation still pending!
    ];

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound(), "SL should detect premature close");

    let mut leak = NoLeakProver::new();
    let leak_result = leak.check(&events);
    // The prover should flag region quiescence violation.
    assert!(
        leak_result
            .counterexamples
            .iter()
            .any(|c| c.property == LivenessProperty::RegionQuiescence),
        "should have RegionQuiescence counterexample"
    );
}

// ============================================================================
// 2. Dynamic No-Aliasing Registry (scale test)
// ============================================================================

/// 100 concurrent permit lifecycles — no aliasing at any point.
#[test]
fn dynamic_no_aliasing_100_concurrent_permits() {
    let n = 100;
    let mut events = Vec::with_capacity(n * 2 + 1);

    // Reserve 100 permits across 10 tasks and 5 regions.
    for i in 0..n {
        events.push(reserve(
            i as u64,
            o(i as u32),
            ALL_KINDS[i % 4],
            t((i % 10) as u32),
            r((i % 5) as u32),
        ));
    }

    // Commit all permits (interleaved with different tasks).
    for i in 0..n {
        events.push(commit(
            (n + i) as u64,
            o(i as u32),
            r((i % 5) as u32),
            ALL_KINDS[i % 4],
        ));
    }

    // Close all regions.
    for reg in 0..5 {
        events.push(close((2 * n + reg) as u64, r(reg as u32)));
    }

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(result.is_verified(), "100 concurrent permits: {result}");
    assert_eq!(result.peak_active_permits, n);
}

/// Verify that duplicate allocation (same ID reserved twice) is caught.
#[test]
fn dynamic_no_aliasing_rejects_duplicate_allocation() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(0), ObligationKind::SendPermit, t(1), r(0)), // Duplicate!
    ];

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(!result.is_verified());
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.violation == AliasingViolation::DuplicateAllocation),
    );
}

// ============================================================================
// 3. Dynamic No-Leak Check (scale test)
// ============================================================================

/// 50 regions × 10 tasks × random obligations = all resolved at quiescence.
#[test]
fn dynamic_no_leak_50_regions_10_tasks() {
    let regions: u32 = 50;
    let tasks_per_region: u32 = 10;
    let mut events = Vec::new();
    let mut time: u64 = 0;
    let mut obl_id: u32 = 0;

    for reg in 0..regions {
        for task_idx in 0..tasks_per_region {
            let task = reg * tasks_per_region + task_idx;
            let kind = ALL_KINDS[(obl_id as usize) % 4];

            events.push(reserve(time, o(obl_id), kind, t(task), r(reg)));
            time += 1;
            obl_id += 1;
        }

        // Resolve all obligations in this region.
        let start_obl = obl_id - tasks_per_region;
        for i in 0..tasks_per_region {
            let oid = start_obl + i;
            let kind = ALL_KINDS[(oid as usize) % 4];
            // Vary the resolution path.
            let event = match i % 3 {
                0 => commit(time, o(oid), r(reg), kind),
                1 => abort(time, o(oid), r(reg), kind),
                _ => leak(time, o(oid), r(reg), kind),
            };
            events.push(event);
            time += 1;
        }

        events.push(close(time, r(reg)));
        time += 1;
    }

    let mut prover = NoLeakProver::new();
    let result = prover.check(&events);
    assert!(result.is_verified(), "50 regions × 10 tasks: {result}");
    assert_eq!(result.ghost_counter_final, 0);
    assert_eq!(result.total_reserved, u64::from(regions * tasks_per_region));
    assert_eq!(result.paths_exercised.paths_covered(), 3);
}

/// Task with unresolved obligation at trace end is caught by eventual resolution.
#[test]
fn dynamic_no_leak_task_with_unresolved_obligation() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        // o(1) still pending at trace end.
    ];

    let mut prover = NoLeakProver::new();
    let result = prover.check(&events);
    assert!(!result.is_verified(), "should detect unresolved obligation");
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == LivenessProperty::EventualResolution),
        "should have EventualResolution counterexample"
    );
    assert_eq!(result.ghost_counter_final, 1);
}

// ============================================================================
// 4. Cancellation Path Coverage
// ============================================================================

/// All three exit paths (commit, abort, leak/Drop) resolve obligations.
#[test]
fn cancellation_all_paths_resolve_obligations() {
    let events = vec![
        // Normal commit path.
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(1, o(0), r(0), ObligationKind::SendPermit),
        // Abort path (error/cancel).
        reserve(2, o(1), ObligationKind::Ack, t(1), r(0)),
        abort(3, o(1), r(0), ObligationKind::Ack),
        // Leak path (panic/Drop).
        reserve(4, o(2), ObligationKind::Lease, t(2), r(0)),
        leak(5, o(2), r(0), ObligationKind::Lease),
        close(10, r(0)),
    ];

    // All three provers should agree this is clean.
    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(sl_result.is_sound(), "SL with all paths: {sl_result}");

    let mut aliasing = NoAliasingProver::all_kinds();
    let aliasing_result = aliasing.check(&events);
    assert!(
        aliasing_result.is_verified(),
        "aliasing with all paths: {aliasing_result}"
    );

    let mut leak_prover = NoLeakProver::new();
    let leak_result = leak_prover.check(&events);
    assert!(
        leak_result.is_verified(),
        "leak with all paths: {leak_result}"
    );
    assert_eq!(leak_result.paths_exercised.commit_count, 1);
    assert_eq!(leak_result.paths_exercised.abort_count, 1);
    assert_eq!(leak_result.paths_exercised.leak_count, 1);
    assert_eq!(leak_result.paths_exercised.paths_covered(), 3);
}

/// Verify Drop-safety (Lemma 5) paths are correctly tracked.
#[test]
fn cancellation_drop_safety_across_severities() {
    // Model four obligations dropped at different severity levels:
    // Ok (commit), Err (abort), Cancelled (abort), Panicked (leak/Drop).
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
        reserve(2, o(2), ObligationKind::SendPermit, t(2), r(0)),
        reserve(3, o(3), ObligationKind::SendPermit, t(3), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit), // Ok
        abort(11, o(1), r(0), ObligationKind::SendPermit),  // Err
        abort(12, o(2), r(0), ObligationKind::SendPermit),  // Cancelled
        leak(13, o(3), r(0), ObligationKind::SendPermit),   // Panicked (Drop)
        close(20, r(0)),
    ];

    let mut aliasing = NoAliasingProver::new();
    let result = aliasing.check(&events);
    assert!(result.is_verified(), "drop safety across severities");

    let mut leak_prover = NoLeakProver::new();
    let leak_result = leak_prover.check(&events);
    assert!(
        leak_result.is_verified(),
        "all dropped obligations resolved"
    );
    assert_eq!(leak_result.ghost_counter_final, 0);
}

// ============================================================================
// 5. Mutation Testing
// ============================================================================

/// Mutation: clone a permit (double reserve same ID) → caught by aliasing prover.
#[test]
fn mutation_clone_permit_rejected() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(0), ObligationKind::SendPermit, t(1), r(0)), // Clone!
    ];

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(!result.is_verified(), "clone must be rejected");

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound(), "SL should also reject clone");
}

/// Mutation: skip release on one path → caught by leak prover.
#[test]
fn mutation_skip_release_rejected() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::Ack, t(1), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        // o(1) never resolved — simulates missing release.
        close(20, r(0)),
    ];

    let mut leak_prover = NoLeakProver::new();
    let result = leak_prover.check(&events);
    assert!(!result.is_verified(), "missing release must be caught");
    assert!(result.ghost_counter_final > 0);

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(
        !sl_result.is_sound(),
        "SL should also catch missing release"
    );
}

/// Mutation: resolve-without-reserve → caught by all provers.
#[test]
fn mutation_resolve_without_reserve_rejected() {
    let events = vec![
        commit(10, o(99), r(0), ObligationKind::SendPermit), // No prior reserve!
    ];

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(!result.is_verified());

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound());
}

/// Mutation: double resolve → caught by aliasing prover.
#[test]
fn mutation_double_resolve_rejected() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        commit(20, o(0), r(0), ObligationKind::SendPermit), // Double resolve!
    ];

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(!result.is_verified(), "double resolve rejected by aliasing");
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.violation == AliasingViolation::UseAfterRelease),
    );

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(
        !sl_result.is_sound(),
        "SL should also reject double resolve"
    );
}

/// Mutation: region mismatch between reserve and resolve.
#[test]
fn mutation_region_mismatch_rejected() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(10, o(0), r(1), ObligationKind::SendPermit), // Wrong region!
        close(20, r(0)),
        close(21, r(1)),
    ];

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(!result.is_verified());

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(!sl_result.is_sound());
}

/// Mutation: reserve in closed region → detected by SL verifier.
#[test]
fn mutation_reserve_in_closed_region_rejected() {
    let events = vec![
        close(0, r(0)),
        reserve(10, o(0), ObligationKind::SendPermit, t(0), r(0)), // After close!
    ];

    let mut sl = SeparationLogicVerifier::new();
    let result = sl.verify(&events);
    assert!(
        !result.is_sound(),
        "reserve in closed region rejected by SL"
    );
}

// ============================================================================
// 6. Cross-Obligation Interaction
// ============================================================================

/// Multiple obligation kinds interacting within the same region.
#[test]
fn cross_obligation_all_four_kinds_same_region() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
        reserve(2, o(2), ObligationKind::Lease, t(1), r(0)),
        reserve(3, o(3), ObligationKind::IoOp, t(1), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        commit(11, o(1), r(0), ObligationKind::Ack),
        abort(12, o(2), r(0), ObligationKind::Lease),
        leak(13, o(3), r(0), ObligationKind::IoOp),
        close(20, r(0)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&events).is_sound());

    let mut aliasing = NoAliasingProver::all_kinds();
    assert!(aliasing.check(&events).is_verified());

    let mut leak_prover = NoLeakProver::new();
    let result = leak_prover.check(&events);
    assert!(result.is_verified());
    assert_eq!(result.paths_exercised.paths_covered(), 3);
}

/// SendPermit held while Lease is active — no cross-contamination.
#[test]
fn cross_obligation_sendpermit_during_lease() {
    let events = vec![
        reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
        reserve(1, o(1), ObligationKind::SendPermit, t(0), r(0)),
        commit(5, o(1), r(0), ObligationKind::SendPermit), // Commit send while lease active.
        commit(10, o(0), r(0), ObligationKind::Lease),
        close(20, r(0)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&events).is_sound());

    let mut aliasing = NoAliasingProver::all_kinds();
    assert!(aliasing.check(&events).is_verified());

    let mut leak_prover = NoLeakProver::new();
    assert!(leak_prover.check(&events).is_verified());
}

/// Obligations across multiple regions — no cross-region contamination.
#[test]
fn cross_obligation_multi_region_isolation() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        close(11, r(0)),
        // r(1) obligations still pending — r(0) close is fine.
        commit(20, o(1), r(1), ObligationKind::SendPermit),
        close(21, r(1)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&events).is_sound());

    let mut aliasing = NoAliasingProver::all_kinds();
    let result = aliasing.check(&events);
    assert!(result.is_verified());
    // Frame checks should confirm cross-region isolation.
    assert!(result.frame_checks > 0);
}

// ============================================================================
// 7. Transfer + Lifecycle Integration
// ============================================================================

/// Multiple permits reserved by different tasks — no cross-contamination.
/// Tests that separate permits in same region have frame independence.
#[test]
fn transfer_separate_permits_frame_independent() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
        // Commit one while the other is still active.
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        commit(20, o(1), r(0), ObligationKind::SendPermit),
        close(30, r(0)),
    ];

    let mut aliasing = NoAliasingProver::new();
    let result = aliasing.check(&events);
    assert!(result.is_verified(), "frame independence: {result}");
    assert!(
        result.frame_checks > 0,
        "should have performed frame checks"
    );
}

/// Verify that use-after-release is caught (commit same obligation twice).
#[test]
fn transfer_use_after_release_rejected() {
    let events = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        // Re-use after release:
        commit(20, o(0), r(0), ObligationKind::SendPermit),
    ];

    let mut aliasing = NoAliasingProver::new();
    let result = aliasing.check(&events);
    assert!(!result.is_verified(), "use-after-release rejected");
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.violation == AliasingViolation::UseAfterRelease),
    );
}

// ============================================================================
// 8. Stress: Many Obligations, Regions, Tasks
// ============================================================================

/// 500 obligations across 25 regions and 50 tasks — full lifecycle.
#[test]
fn stress_500_obligations_full_lifecycle() {
    let n_obligations: u32 = 500;
    let n_regions: u32 = 25;
    let n_tasks: u32 = 50;
    let mut events = Vec::new();
    let mut time: u64 = 0;

    // Reserve phase.
    for i in 0..n_obligations {
        events.push(reserve(
            time,
            o(i),
            ALL_KINDS[(i as usize) % 4],
            t(i % n_tasks),
            r(i % n_regions),
        ));
        time += 1;
    }

    // Resolve phase (varied paths).
    for i in 0..n_obligations {
        let kind = ALL_KINDS[(i as usize) % 4];
        let region = r(i % n_regions);
        let event = match i % 5 {
            0..=2 => commit(time, o(i), region, kind),
            3 => abort(time, o(i), region, kind),
            _ => leak(time, o(i), region, kind),
        };
        events.push(event);
        time += 1;
    }

    // Close all regions.
    for reg in 0..n_regions {
        events.push(close(time, r(reg)));
        time += 1;
    }

    let mut sl = SeparationLogicVerifier::new();
    let sl_result = sl.verify(&events);
    assert!(sl_result.is_sound(), "SL 500-stress: {sl_result}");

    let mut aliasing = NoAliasingProver::all_kinds();
    let aliasing_result = aliasing.check(&events);
    assert!(
        aliasing_result.is_verified(),
        "aliasing 500-stress: {aliasing_result}"
    );
    assert_eq!(aliasing_result.peak_active_permits, n_obligations as usize);

    let mut leak_prover = NoLeakProver::new();
    let leak_result = leak_prover.check(&events);
    assert!(leak_result.is_verified(), "leak 500-stress: {leak_result}");
    assert_eq!(leak_result.ghost_counter_final, 0);
    assert_eq!(leak_result.total_reserved, u64::from(n_obligations));
    assert_eq!(leak_result.paths_exercised.paths_covered(), 3);
}

// ============================================================================
// 9. Property-Based Tests
// ============================================================================

/// Arbitrary obligation kind.
fn arb_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
    ]
}

/// Resolution type.
#[derive(Debug, Clone, Copy)]
enum ResolutionType {
    Commit,
    Abort,
    Leak,
}

fn arb_resolution_type() -> impl Strategy<Value = ResolutionType> {
    prop_oneof![
        Just(ResolutionType::Commit),
        Just(ResolutionType::Abort),
        Just(ResolutionType::Leak),
    ]
}

/// Generate a valid obligation lifecycle (reserve then resolve).
fn arb_lifecycle(
    max_tasks: u32,
    max_regions: u32,
) -> impl Strategy<Value = (ObligationKind, u32, u32, ResolutionType)> {
    (
        arb_kind(),
        0..max_tasks,
        0..max_regions,
        arb_resolution_type(),
    )
}

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Random valid lifecycle sequences preserve all three invariants.
    #[test]
    fn prop_valid_lifecycle_all_invariants_hold(
        lifecycles in proptest::collection::vec(arb_lifecycle(10, 5), 1..50),
    ) {
        let mut events = Vec::new();
        let mut time: u64 = 0;

        // Reserve all.
        for (i, (kind, task_idx, region_idx, _)) in lifecycles.iter().enumerate() {
            events.push(reserve(time, o(i as u32), *kind, t(*task_idx), r(*region_idx)));
            time += 1;
        }

        // Resolve all.
        for (i, (kind, _, region_idx, res_type)) in lifecycles.iter().enumerate() {
            let event = match res_type {
                ResolutionType::Commit => commit(time, o(i as u32), r(*region_idx), *kind),
                ResolutionType::Abort => abort(time, o(i as u32), r(*region_idx), *kind),
                ResolutionType::Leak => leak(time, o(i as u32), r(*region_idx), *kind),
            };
            events.push(event);
            time += 1;
        }

        // Close all used regions.
        let mut regions_used: Vec<u32> = lifecycles.iter().map(|(_, _, r, _)| *r).collect();
        regions_used.sort_unstable();
        regions_used.dedup();
        for reg in &regions_used {
            events.push(close(time, r(*reg)));
            time += 1;
        }

        // All three provers must agree.
        let mut sl = SeparationLogicVerifier::new();
        prop_assert!(sl.verify(&events).is_sound(), "SL failed on random valid lifecycle");

        let mut aliasing = NoAliasingProver::all_kinds();
        prop_assert!(aliasing.check(&events).is_verified(), "aliasing failed on random valid lifecycle");

        let mut leak_prover = NoLeakProver::new();
        let result = leak_prover.check(&events);
        prop_assert!(result.is_verified(), "leak failed on random valid lifecycle");
        prop_assert_eq!(result.ghost_counter_final, 0);
    }

    /// Random cancellation injection: some obligations are cancelled (aborted/leaked)
    /// instead of committed. All invariants should still hold.
    #[test]
    fn prop_random_cancellation_all_resolved(
        n in 5..30usize,
        cancel_mask in proptest::collection::vec(0..3u8, 5..30),
    ) {
        let n = n.min(cancel_mask.len());
        let mut events = Vec::new();
        let mut time: u64 = 0;

        for i in 0..n {
            events.push(reserve(
                time,
                o(i as u32),
                ALL_KINDS[i % 4],
                t((i % 5) as u32),
                r(0),
            ));
            time += 1;
        }

        for i in 0..n {
            let kind = ALL_KINDS[i % 4];
            let event = match cancel_mask[i] % 3 {
                0 => commit(time, o(i as u32), r(0), kind),
                1 => abort(time, o(i as u32), r(0), kind),
                _ => leak(time, o(i as u32), r(0), kind),
            };
            events.push(event);
            time += 1;
        }
        events.push(close(time, r(0)));

        let mut leak_prover = NoLeakProver::new();
        let result = leak_prover.check(&events);
        prop_assert!(result.is_verified());
        prop_assert_eq!(result.ghost_counter_final, 0);
    }

    /// Interleaved reserve/resolve order: obligations can be resolved out of order.
    #[test]
    fn prop_interleaved_order_invariants_hold(
        n in 2..20usize,
        resolve_order in proptest::collection::vec(0..20u32, 2..20),
    ) {
        let n = n.min(resolve_order.len());
        let mut events = Vec::new();
        let mut time: u64 = 0;

        // Reserve all.
        for i in 0..n {
            events.push(reserve(
                time,
                o(i as u32),
                ObligationKind::SendPermit,
                t((i % 5) as u32),
                r(0),
            ));
            time += 1;
        }

        // Resolve in shuffled order.
        let mut order: Vec<usize> = (0..n).collect();
        // Use resolve_order to create a permutation.
        for i in (1..n).rev() {
            let j = resolve_order[i % resolve_order.len()] as usize % (i + 1);
            order.swap(i, j);
        }

        for &idx in &order {
            events.push(commit(
                time,
                o(idx as u32),
                r(0),
                ObligationKind::SendPermit,
            ));
            time += 1;
        }
        events.push(close(time, r(0)));

        let mut aliasing = NoAliasingProver::new();
        prop_assert!(aliasing.check(&events).is_verified());

        let mut leak_prover = NoLeakProver::new();
        let result = leak_prover.check(&events);
        prop_assert!(result.is_verified());
        prop_assert_eq!(result.ghost_counter_final, 0);
    }
}

// ============================================================================
// 10. Prover Reuse
// ============================================================================

/// Provers can be reused across multiple traces without state leaking.
#[test]
fn prover_reuse_isolation() {
    let trace1 = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        commit(10, o(0), r(0), ObligationKind::SendPermit),
        close(20, r(0)),
    ];

    // Bad trace for SL and leak prover: unresolved obligation.
    let bad_trace_leak = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        // Missing resolve.
    ];

    // Bad trace for aliasing prover: duplicate allocation.
    let bad_trace_aliasing = vec![
        reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
        reserve(1, o(0), ObligationKind::SendPermit, t(1), r(0)), // Duplicate!
    ];

    let trace2 = vec![
        reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
        abort(10, o(0), r(0), ObligationKind::Ack),
        close(20, r(0)),
    ];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&trace1).is_sound());
    assert!(!sl.verify(&bad_trace_leak).is_sound());
    assert!(
        sl.verify(&trace2).is_sound(),
        "SL reuse after bad trace should work"
    );

    let mut aliasing = NoAliasingProver::all_kinds();
    assert!(aliasing.check(&trace1).is_verified());
    assert!(!aliasing.check(&bad_trace_aliasing).is_verified());
    assert!(
        aliasing.check(&trace2).is_verified(),
        "aliasing reuse after bad trace should work"
    );

    let mut leak_prover = NoLeakProver::new();
    assert!(leak_prover.check(&trace1).is_verified());
    assert!(!leak_prover.check(&bad_trace_leak).is_verified());
    assert!(
        leak_prover.check(&trace2).is_verified(),
        "leak reuse after bad trace should work"
    );
}

// ============================================================================
// 11. Edge Cases
// ============================================================================

/// Empty trace is valid for all provers.
#[test]
fn edge_empty_trace_all_provers() {
    let events: Vec<MarkingEvent> = vec![];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&events).is_sound());

    let mut aliasing = NoAliasingProver::all_kinds();
    assert!(aliasing.check(&events).is_verified());

    let mut leak_prover = NoLeakProver::new();
    let result = leak_prover.check(&events);
    assert!(result.is_verified());
    assert_eq!(result.ghost_counter_final, 0);
}

/// Single obligation through full lifecycle.
#[test]
fn edge_single_obligation_full_lifecycle() {
    for kind in &ALL_KINDS {
        let events = vec![
            reserve(0, o(0), *kind, t(0), r(0)),
            commit(10, o(0), r(0), *kind),
            close(20, r(0)),
        ];

        let mut sl = SeparationLogicVerifier::new();
        assert!(sl.verify(&events).is_sound(), "SL failed for {kind:?}");

        let mut aliasing = NoAliasingProver::all_kinds();
        assert!(
            aliasing.check(&events).is_verified(),
            "aliasing failed for {kind:?}"
        );

        let mut leak_prover = NoLeakProver::new();
        assert!(
            leak_prover.check(&events).is_verified(),
            "leak failed for {kind:?}"
        );
    }
}

/// Region close without any obligations is valid.
#[test]
fn edge_empty_region_close() {
    let events = vec![close(0, r(0))];

    let mut sl = SeparationLogicVerifier::new();
    assert!(sl.verify(&events).is_sound());

    let mut leak_prover = NoLeakProver::new();
    assert!(leak_prover.check(&events).is_verified());
}
