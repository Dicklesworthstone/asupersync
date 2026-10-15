//! Lease semantics and liveness tests (bd-yj06g).
//!
//! Validates lease renewal/expiry semantics using the obligation marking
//! analyzer and oracle system. Tests exercise:
//!   - Normal lease lifecycle: reserve → commit
//!   - Lease renewal window behavior
//!   - Lease expiry → cancellation escalation
//!   - Lease liveness: budget-constrained renewal
//!   - Interaction with region close (blocking semantics)
//!
//! Cross-references:
//!   - Obligation state machine: src/record/obligation.rs:125-130
//!   - VASS marking: src/obligation/marking.rs
//!   - Remote protocol spec: asupersync_plan_v4.md:594-725
//!   - Lean Step constructors: formal/lean/Asupersync.lean (reserve/commit/abort/leak)

#[macro_use]
mod common;

use asupersync::lab::oracle::{ObligationLeakOracle, TaskLeakOracle};
use asupersync::obligation::marking::{MarkingAnalyzer, MarkingEvent, MarkingEventKind};
use asupersync::record::obligation::ObligationKind;
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Normal Lease Lifecycle
// Validates: lease reserve → commit follows obligation state machine
// ============================================================================

/// Normal lease: reserve → commit → region close. No violations.
/// Validates: Lean commit_resolves_obligation applied to Lease kind.
#[test]
fn lease_normal_lifecycle_commit() {
    init_test("lease_normal_lifecycle_commit");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    let events = vec![
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        MarkingEvent::new(
            t(100),
            MarkingEventKind::Commit {
                obligation: o0,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "lease commit is safe", true, safe);

    test_complete!("lease_normal_lifecycle_commit");
}

/// Lease abort: reserve → abort → region close. Clean cancellation.
/// Validates: Lean abort_resolves_obligation applied to Lease kind.
#[test]
fn lease_normal_lifecycle_abort() {
    init_test("lease_normal_lifecycle_abort");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    let events = vec![
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        MarkingEvent::new(
            t(100),
            MarkingEventKind::Abort {
                obligation: o0,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "lease abort is safe", true, safe);

    test_complete!("lease_normal_lifecycle_abort");
}

// ============================================================================
// Lease Expiry and Escalation
// Validates: unrenewal within window → leak → region escalation
// ============================================================================

/// Lease leak: holder task completes without resolving the lease.
/// This models lease expiry where the task times out.
/// Validates: Lean Step.leak applied to Lease kind.
///
/// The MarkingAnalyzer treats Leak as a resolution (decrements marking),
/// so the region closes safely from the marking perspective. However,
/// the ObligationLeakOracle detects the unresolved obligation.
#[test]
fn lease_expiry_causes_leak() {
    init_test("lease_expiry_causes_leak");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    let events = vec![
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        // Lease leaks (task completes without resolving)
        MarkingEvent::new(
            t(100),
            MarkingEventKind::Leak {
                obligation: o0,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    // Marking perspective: Leak decrements the marking, so region closes safely.
    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "marking safe after leak+close", true, safe);

    // Oracle perspective: obligation was never properly resolved → violation.
    let mut oracle = ObligationLeakOracle::new();
    oracle.on_create(o0, ObligationKind::Lease, t0, r0);
    // Do NOT call on_resolve — the lease leaked.
    oracle.on_region_close(r0, t(200));
    let oracle_result = oracle.check(t(200));
    let is_err = oracle_result.is_err();
    assert_with_log!(is_err, "oracle detects leaked lease", true, is_err);

    test_complete!("lease_expiry_causes_leak");
}

/// Unresolved lease blocks region close (marking violation).
/// Models: lease not renewed AND not aborted → region cannot close safely.
#[test]
fn lease_unresolved_blocks_region_close() {
    init_test("lease_unresolved_blocks_region_close");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    let events = vec![
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        // Region closes WITHOUT resolving the lease
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let not_safe = !result.is_safe();
    assert_with_log!(not_safe, "unresolved lease blocks close", true, not_safe);

    test_complete!("lease_unresolved_blocks_region_close");
}

// ============================================================================
// Lease Liveness: Budget-Constrained Renewal
// Validates: if budget allows, lease can be renewed; otherwise escalates
// ============================================================================

/// Multiple lease cycles: reserve → commit → reserve → commit.
/// Models: successful lease renewal under budget.
/// Validates liveness: renewable leases don't block progress.
#[test]
fn lease_renewal_under_budget() {
    init_test("lease_renewal_under_budget");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);
    let o1 = obligation(1);

    let events = vec![
        // First lease period
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        MarkingEvent::new(
            t(50),
            MarkingEventKind::Commit {
                obligation: o0,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        // Second lease period (renewal)
        MarkingEvent::new(
            t(51),
            MarkingEventKind::Reserve {
                obligation: o1,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        MarkingEvent::new(
            t(100),
            MarkingEventKind::Commit {
                obligation: o1,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        // Region closes after all leases resolved
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "lease renewal under budget", true, safe);

    // Verify marking was zero at close
    let leaks = result.leak_count();
    assert_with_log!(leaks == 0, "no leaks during renewal", 0, leaks);

    test_complete!("lease_renewal_under_budget");
}

/// Lease with mixed obligation kinds: lease + send permit in same region.
/// Validates: lease resolution is independent of other obligation kinds.
#[test]
fn lease_with_mixed_obligations() {
    init_test("lease_with_mixed_obligations");

    let r0 = region(0);
    let t0 = task(0);
    let t1 = task(1);
    let o_lease = obligation(0);
    let o_send = obligation(1);

    let events = vec![
        // Reserve lease
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o_lease,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        // Reserve send permit
        MarkingEvent::new(
            t(20),
            MarkingEventKind::Reserve {
                obligation: o_send,
                kind: ObligationKind::SendPermit,
                task: t1,
                region: r0,
            },
        ),
        // Commit send permit first
        MarkingEvent::new(
            t(50),
            MarkingEventKind::Commit {
                obligation: o_send,
                region: r0,
                kind: ObligationKind::SendPermit,
            },
        ),
        // Then commit lease
        MarkingEvent::new(
            t(100),
            MarkingEventKind::Commit {
                obligation: o_lease,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: r0 }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "mixed obligations safe", true, safe);

    test_complete!("lease_with_mixed_obligations");
}

// ============================================================================
// Lease + Cancellation Propagation
// Validates: cancellation causes lease abort, enabling region close
// ============================================================================

/// Lease aborted during cancellation: cancel causes lease abort.
/// Models: region cancel → task cancel → lease abort → clean close.
#[test]
fn lease_aborted_during_cancellation() {
    init_test("lease_aborted_during_cancellation");

    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);
    let mut task_leak = TaskLeakOracle::new();

    task_leak.on_spawn(t0, r0, t(5));

    let events = vec![
        // Lease reserved
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: r0,
            },
        ),
        // Cancellation causes lease abort
        MarkingEvent::new(
            t(50),
            MarkingEventKind::Abort {
                obligation: o0,
                region: r0,
                kind: ObligationKind::Lease,
            },
        ),
        // Region closes after cancellation completes
        MarkingEvent::new(t(100), MarkingEventKind::RegionClose { region: r0 }),
    ];

    // Task completes (via cancellation)
    task_leak.on_complete(t0, t(80));
    task_leak.on_region_close(r0, t(100));

    let mut analyzer = MarkingAnalyzer::new();
    let marking_result = analyzer.analyze(&events);
    let tl_result = task_leak.check(t(100));

    let ok = marking_result.is_safe() && tl_result.is_ok();
    assert_with_log!(ok, "lease aborted during cancel", true, ok);

    test_complete!("lease_aborted_during_cancellation");
}

// ============================================================================
// Nested Region Lease Semantics
// Validates: lease in child region must resolve before parent close
// ============================================================================

/// Lease in child region: must resolve before child and parent close.
#[test]
fn lease_in_nested_region() {
    init_test("lease_in_nested_region");

    let parent = region(0);
    let child = region(1);
    let t0 = task(0);
    let o0 = obligation(0);

    let events = vec![
        // Lease in child region
        MarkingEvent::new(
            t(10),
            MarkingEventKind::Reserve {
                obligation: o0,
                kind: ObligationKind::Lease,
                task: t0,
                region: child,
            },
        ),
        // Commit lease
        MarkingEvent::new(
            t(50),
            MarkingEventKind::Commit {
                obligation: o0,
                region: child,
                kind: ObligationKind::Lease,
            },
        ),
        // Child closes, then parent
        MarkingEvent::new(t(100), MarkingEventKind::RegionClose { region: child }),
        MarkingEvent::new(t(200), MarkingEventKind::RegionClose { region: parent }),
    ];

    let mut analyzer = MarkingAnalyzer::new();
    let result = analyzer.analyze(&events);
    let safe = result.is_safe();
    assert_with_log!(safe, "nested lease safe", true, safe);

    test_complete!("lease_in_nested_region");
}

/// Oracle-level verification: lease blocks region close via obligation leak oracle.
#[test]
fn lease_obligation_oracle_verification() {
    init_test("lease_obligation_oracle_verification");

    let mut oracle = ObligationLeakOracle::new();
    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    // Reserve a lease obligation
    oracle.on_create(o0, ObligationKind::Lease, t0, r0);

    // Resolve it
    oracle.on_resolve(
        o0,
        asupersync::record::obligation::ObligationState::Committed,
    );

    // Close region
    oracle.on_region_close(r0, t(100));

    let result = oracle.check(t(100));
    let ok = result.is_ok();
    assert_with_log!(ok, "oracle: lease resolved before close", true, ok);

    test_complete!("lease_obligation_oracle_verification");
}

/// Negative: lease not resolved → oracle detects violation.
#[test]
fn lease_obligation_oracle_detects_leak() {
    init_test("lease_obligation_oracle_detects_leak");

    let mut oracle = ObligationLeakOracle::new();
    let r0 = region(0);
    let t0 = task(0);
    let o0 = obligation(0);

    // Reserve a lease but DON'T resolve it
    oracle.on_create(o0, ObligationKind::Lease, t0, r0);

    // Close region
    oracle.on_region_close(r0, t(100));

    let result = oracle.check(t(100));
    let is_err = result.is_err();
    assert_with_log!(is_err, "oracle: unresolved lease detected", true, is_err);

    test_complete!("lease_obligation_oracle_detects_leak");
}
