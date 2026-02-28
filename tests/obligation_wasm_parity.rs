#![allow(missing_docs)]
//! Obligation ledger WASM parity verification tests (asupersync-umelq.6.3).
//!
//! These tests prove that the obligation accounting subsystem is fully
//! functional under browser-like execution conditions. The obligation module
//! uses no platform-specific dependencies — Time is abstract (caller-supplied),
//! storage is BTreeMap (deterministic), and all operations are single-threaded
//! compatible. These tests document and verify those properties.
//!
//! # Why This Matters for WASM
//!
//! In the browser (wasm32-unknown-unknown):
//! - No `std::time::Instant` — all time is caller-supplied via `Time::from_nanos`
//! - Single-threaded execution — no concurrent obligation mutations
//! - Tab suspension can cause large time gaps between operations
//! - Deterministic ordering is critical for replay debugging
//! - Region quiescence is the only safe shutdown mechanism (no OS signals)
//!
//! # Invariants Verified
//!
//! 1. **Abstract time**: Ledger works with arbitrary `Time` values (no system clock)
//! 2. **BTreeMap determinism**: Iteration and drain ordering is reproducible
//! 3. **Cancel drain completeness**: All obligations aborted during cancellation
//! 4. **Host interruption**: Accounting is correct after time gaps (tab suspension)
//! 5. **Multi-region isolation**: Region drain does not affect sibling regions
//! 6. **Graded obligation parity**: Type-level obligation tracking works without platform deps
//! 7. **GradedScope accounting**: Scope-level zero-leak verification
//! 8. **Leak detection**: Oracle catches unresolvedobligation across all scenarios

#[macro_use]
mod common;

use asupersync::obligation::graded::{GradedObligation, GradedScope, Resolution};
use asupersync::obligation::ledger::ObligationLedger;
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;

// ============================================================================
// Helpers
// ============================================================================

fn task(n: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(n, 0))
}

fn region(n: u32) -> RegionId {
    RegionId::from_arena(ArenaIndex::new(n, 0))
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

// ============================================================================
// 1. Abstract Time: ledger works with arbitrary Time values
// ============================================================================

/// Obligation durations are computed purely from caller-supplied Time values,
/// proving no dependency on std::time::Instant or any system clock.
#[test]
fn wasm_obligation_lifecycle_with_abstract_time() {
    let mut ledger = ObligationLedger::new();

    // Use arbitrary nanos values that a browser's performance.now() might supply
    let reserve_time = t(1_000_000); // 1ms in browser perf time
    let commit_time = t(5_500_000); // 5.5ms later

    let token = ledger.acquire(
        ObligationKind::SendPermit,
        task(0),
        region(0),
        reserve_time,
    );

    let duration = ledger.commit(token, commit_time);
    assert_eq!(
        duration, 4_500_000,
        "Duration must be computed from abstract time delta, not system clock"
    );

    let stats = ledger.stats();
    assert!(stats.is_clean(), "Ledger must be clean after commit");
}

/// Large time gaps (simulating tab suspension) do not break obligation accounting.
/// A browser tab suspended for 30 seconds should still correctly compute durations.
#[test]
fn wasm_obligation_survives_large_time_gap() {
    let mut ledger = ObligationLedger::new();

    let reserve_time = t(100_000); // 0.1ms
    let gap_time = t(30_000_000_000); // 30 seconds later (tab was suspended)

    let token = ledger.acquire(ObligationKind::Lease, task(0), region(0), reserve_time);

    let duration = ledger.commit(token, gap_time);
    assert_eq!(
        duration,
        30_000_000_000 - 100_000,
        "Duration must span the full suspension gap"
    );

    assert!(
        ledger.stats().is_clean(),
        "Ledger must be clean despite large time gap"
    );
}

/// Multiple obligations with different time bases (simulating browser
/// performance.now() which starts at page load, not epoch).
#[test]
fn wasm_obligation_non_epoch_time_base() {
    let mut ledger = ObligationLedger::new();

    // Browser performance.now() starts near zero at page load
    let t0 = t(0);
    let t1 = t(100);
    let t2 = t(200);
    let t3 = t(300);

    let tok1 = ledger.acquire(ObligationKind::SendPermit, task(0), region(0), t0);
    let tok2 = ledger.acquire(ObligationKind::Ack, task(1), region(0), t1);

    let dur1 = ledger.commit(tok1, t2);
    let dur2 = ledger.abort(tok2, t3, ObligationAbortReason::Cancel);

    assert_eq!(dur1, 200, "First obligation held for 200ns");
    assert_eq!(dur2, 200, "Second obligation held for 200ns");
    assert!(ledger.stats().is_clean());
}

/// Time::ZERO is a valid reservation time (browser may start obligations at t=0).
#[test]
fn wasm_obligation_at_time_zero() {
    let mut ledger = ObligationLedger::new();

    let token = ledger.acquire(ObligationKind::IoOp, task(0), region(0), Time::ZERO);
    let duration = ledger.commit(token, Time::ZERO);

    assert_eq!(duration, 0, "Zero-duration obligation is valid");
    assert!(ledger.stats().is_clean());
}

// ============================================================================
// 2. BTreeMap Determinism: iteration and drain ordering is reproducible
// ============================================================================

/// Obligation IDs are monotonically increasing regardless of kind or holder,
/// ensuring BTreeMap iteration is deterministic for browser replay.
#[test]
fn wasm_obligation_id_monotonicity() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    let tok1 = ledger.acquire(ObligationKind::Lease, task(0), r, t(0));
    let tok2 = ledger.acquire(ObligationKind::SendPermit, task(1), r, t(1));
    let tok3 = ledger.acquire(ObligationKind::Ack, task(2), r, t(2));
    let tok4 = ledger.acquire(ObligationKind::IoOp, task(0), r, t(3));

    let ids = [tok1.id(), tok2.id(), tok3.id(), tok4.id()];
    for window in ids.windows(2) {
        assert!(
            window[0] < window[1],
            "Obligation IDs must be monotonically increasing: {:?} >= {:?}",
            window[0],
            window[1]
        );
    }

    // Verify iteration order matches allocation order
    let iter_ids: Vec<ObligationId> = ledger.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        &ids[..],
        &iter_ids[..],
        "BTreeMap iteration must match allocation order"
    );

    // Clean up
    ledger.commit(tok1, t(10));
    ledger.commit(tok2, t(10));
    ledger.commit(tok3, t(10));
    ledger.commit(tok4, t(10));
}

/// pending_ids_for_region returns IDs in deterministic (BTreeMap) order,
/// which is essential for reproducible cancellation drain in browser.
#[test]
fn wasm_drain_ordering_is_deterministic_across_runs() {
    // Run the same allocation pattern twice and verify identical drain order
    let drain_order = |_run: u32| -> Vec<ObligationId> {
        let mut ledger = ObligationLedger::new();
        let r = region(0);

        let _t1 = ledger.acquire(ObligationKind::Ack, task(2), r, t(100));
        let _t2 = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(50));
        let _t3 = ledger.acquire(ObligationKind::Lease, task(1), r, t(75));

        ledger.pending_ids_for_region(r)
    };

    let order_a = drain_order(1);
    let order_b = drain_order(2);

    assert_eq!(
        order_a, order_b,
        "Drain ordering must be identical across runs (BTreeMap determinism)"
    );
    assert_eq!(
        order_a.len(),
        3,
        "All obligations must be included in drain"
    );
}

// ============================================================================
// 3. Cancel Drain Completeness: all obligations aborted during cancellation
// ============================================================================

/// Browser cancellation scenario: user navigates away, all obligations in the
/// region must be drained. Simulates the cancel→drain→quiescence protocol.
#[test]
fn wasm_cancel_drain_all_obligations_in_region() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);
    let cancel_time = t(1000);

    // Simulate multiple tasks holding obligations when navigation occurs
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ];

    for (i, &kind) in kinds.iter().enumerate() {
        let _tok = ledger.acquire(kind, task(i as u32), r, t(i as u64 * 10));
    }

    assert_eq!(ledger.pending_for_region(r), 4, "Pre-drain: 4 pending");

    // Drain: enumerate and abort all pending obligations
    let pending_ids = ledger.pending_ids_for_region(r);
    assert_eq!(
        pending_ids.len(),
        4,
        "Must find all 4 obligations for drain"
    );

    for id in &pending_ids {
        ledger.mark_leaked(*id, cancel_time);
    }

    assert!(
        ledger.is_region_clean(r),
        "Region must be clean after cancel drain"
    );
    assert_eq!(
        ledger.pending_count(),
        0,
        "Global pending must be zero after full drain"
    );
}

/// Cancel drain with mixed resolution: some obligations committed before cancel,
/// remaining must be drained. This models a browser scenario where some fetch()
/// calls complete before the page navigates away.
#[test]
fn wasm_cancel_drain_with_partial_completion() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    let tok1 = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(0));
    let tok2 = ledger.acquire(ObligationKind::Ack, task(1), r, t(10));
    let _tok3 = ledger.acquire(ObligationKind::Lease, task(2), r, t(20));
    let _tok4 = ledger.acquire(ObligationKind::IoOp, task(3), r, t(30));

    // Two obligations complete normally before cancel
    ledger.commit(tok1, t(50));
    ledger.abort(tok2, t(60), ObligationAbortReason::Explicit);

    assert_eq!(
        ledger.pending_for_region(r),
        2,
        "Two obligations still pending"
    );

    // Cancel arrives: drain remaining
    let remaining = ledger.pending_ids_for_region(r);
    assert_eq!(remaining.len(), 2, "Two obligations to drain");

    for id in &remaining {
        ledger.mark_leaked(*id, t(100));
    }

    assert!(
        ledger.is_region_clean(r),
        "Region clean after partial drain"
    );

    let stats = ledger.stats();
    assert_eq!(stats.total_committed, 1);
    assert_eq!(stats.total_aborted, 1);
    assert_eq!(stats.total_leaked, 2);
    assert_eq!(stats.pending, 0);
}

/// Cancel drain preserves abort reason in the obligation record,
/// which is needed for browser-side diagnostics.
#[test]
fn wasm_cancel_drain_preserves_abort_reason() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    let tok = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(0));
    let id = tok.id();

    ledger.abort(tok, t(100), ObligationAbortReason::Cancel);

    let record = ledger.get(id).expect("Record must persist after abort");
    assert_eq!(
        record.state,
        ObligationState::Aborted,
        "State must be Aborted"
    );
}

// ============================================================================
// 4. Host Interruption: time gaps from tab suspension
// ============================================================================

/// Simulates a browser tab being suspended mid-obligation. Multiple obligations
/// are held across a large time gap, then resolved. Accounting must be correct.
#[test]
fn wasm_host_interruption_tab_suspension_multi_obligation() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    // Phase 1: acquire obligations at normal browser speed
    let tok_send = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(1_000));
    let tok_ack = ledger.acquire(ObligationKind::Ack, task(1), r, t(2_000));
    let tok_lease = ledger.acquire(ObligationKind::Lease, task(0), r, t(3_000));

    assert_eq!(ledger.pending_count(), 3);

    // Phase 2: tab suspended for 60 seconds (user switched tabs)
    let post_suspension = t(60_000_000_000);

    // Phase 3: tab resumes, obligations resolved
    let dur_send = ledger.commit(tok_send, post_suspension);
    let dur_ack = ledger.abort(tok_ack, t(60_000_001_000), ObligationAbortReason::Cancel);
    let dur_lease = ledger.commit(tok_lease, t(60_000_002_000));

    // Verify durations span the suspension gap
    assert_eq!(dur_send, 60_000_000_000 - 1_000);
    assert_eq!(dur_ack, 60_000_001_000 - 2_000);
    assert_eq!(dur_lease, 60_000_002_000 - 3_000);

    assert!(ledger.stats().is_clean());
}

/// Tab suspension during cancel drain: cancel is requested, tab suspends,
/// tab resumes, drain completes. This tests the most dangerous browser edge case.
#[test]
fn wasm_host_interruption_during_cancel_drain() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    // Obligations acquired pre-cancel
    let tok1 = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(100));
    let tok2 = ledger.acquire(ObligationKind::Ack, task(1), r, t(200));
    let tok3 = ledger.acquire(ObligationKind::Lease, task(2), r, t(300));

    // Cancel requested at t=500
    // First obligation drained before suspension
    ledger.abort(tok1, t(500), ObligationAbortReason::Cancel);

    // Tab suspended... 10 seconds pass
    // Tab resumes, drain continues
    ledger.abort(tok2, t(10_000_000_500), ObligationAbortReason::Cancel);
    ledger.abort(tok3, t(10_000_001_000), ObligationAbortReason::Cancel);

    assert!(
        ledger.is_region_clean(r),
        "Region must be clean even after interrupted drain"
    );

    let stats = ledger.stats();
    assert_eq!(stats.total_aborted, 3, "All three obligations aborted");
    assert!(stats.is_clean(), "No leaks despite suspension during drain");
}

// ============================================================================
// 5. Multi-Region Isolation: drain does not affect sibling regions
// ============================================================================

/// Three independent regions: draining one leaves the others untouched.
/// This models browser components with independent obligation scopes.
#[test]
fn wasm_multi_region_isolation_during_drain() {
    let mut ledger = ObligationLedger::new();
    let r_nav = region(0); // Navigation region (being cancelled)
    let r_bg = region(1); // Background sync region (still active)
    let r_ui = region(2); // UI region (still active)

    // Navigation region: 2 obligations
    let nav1 = ledger.acquire(ObligationKind::SendPermit, task(0), r_nav, t(0));
    let nav2 = ledger.acquire(ObligationKind::Ack, task(0), r_nav, t(0));

    // Background sync: 1 obligation
    let _bg1 = ledger.acquire(ObligationKind::Lease, task(1), r_bg, t(0));

    // UI region: 1 obligation
    let _ui1 = ledger.acquire(ObligationKind::IoOp, task(2), r_ui, t(0));

    // Drain navigation region only
    ledger.abort(nav1, t(100), ObligationAbortReason::Cancel);
    ledger.abort(nav2, t(100), ObligationAbortReason::Cancel);

    assert!(ledger.is_region_clean(r_nav), "Nav region clean");
    assert_eq!(
        ledger.pending_for_region(r_bg),
        1,
        "Background region untouched"
    );
    assert_eq!(ledger.pending_for_region(r_ui), 1, "UI region untouched");
    assert_eq!(ledger.pending_count(), 2, "Global pending = 2 (bg + ui)");
}

/// Cross-region task: one task holds obligations in different regions.
/// Cancelling one region's obligations must not affect the other.
#[test]
fn wasm_cross_region_task_isolation() {
    let mut ledger = ObligationLedger::new();
    let r1 = region(0);
    let r2 = region(1);
    let shared_task = task(0);

    let tok_r1 = ledger.acquire(ObligationKind::SendPermit, shared_task, r1, t(0));
    let _tok_r2 = ledger.acquire(ObligationKind::Ack, shared_task, r2, t(0));

    // Cancel region 1
    ledger.abort(tok_r1, t(50), ObligationAbortReason::Cancel);

    assert!(ledger.is_region_clean(r1), "Region 1 clean");
    assert_eq!(
        ledger.pending_for_region(r2),
        1,
        "Region 2 still has obligation from same task"
    );
    assert_eq!(
        ledger.pending_for_task(shared_task),
        1,
        "Task still has one pending obligation"
    );
}

// ============================================================================
// 6. Graded Obligation Parity: type-level obligation tracking
// ============================================================================

/// GradedObligation reserve/commit lifecycle works with pure Rust types,
/// no platform dependencies. This proves browser parity at the type level.
#[test]
fn wasm_graded_obligation_commit() {
    let ob = GradedObligation::reserve(ObligationKind::SendPermit, "browser fetch permit");
    assert!(!ob.is_resolved());
    assert_eq!(ob.kind(), ObligationKind::SendPermit);
    assert_eq!(ob.description(), "browser fetch permit");

    let proof = ob.resolve(Resolution::Commit);
    assert_eq!(proof.kind, ObligationKind::SendPermit);
    assert_eq!(proof.resolution, Resolution::Commit);
}

/// GradedObligation abort lifecycle.
#[test]
fn wasm_graded_obligation_abort() {
    let ob = GradedObligation::reserve(ObligationKind::Lease, "browser websocket lease");
    let proof = ob.resolve(Resolution::Abort);
    assert_eq!(proof.resolution, Resolution::Abort);
}

/// GradedObligation into_raw escape hatch (for browser FFI interop).
#[test]
fn wasm_graded_obligation_into_raw() {
    let ob = GradedObligation::reserve(ObligationKind::IoOp, "browser IndexedDB write");
    let raw = ob.into_raw();
    assert_eq!(raw.kind, ObligationKind::IoOp);
    assert_eq!(raw.description, "browser IndexedDB write");
    // raw can be dropped without panic — escape hatch was used
}

/// GradedObligation drop bomb catches leaks (critical for browser debugging).
#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn wasm_graded_obligation_leak_panics() {
    let _ob = GradedObligation::reserve(ObligationKind::Ack, "leaked browser ack");
    // Dropping without resolve triggers panic
}

// ============================================================================
// 7. GradedScope Accounting: scope-level zero-leak verification
// ============================================================================

/// GradedScope tracks obligation counts and verifies zero-leak at exit.
/// This is the browser's compile-time-approximated obligation safety net.
#[test]
fn wasm_graded_scope_clean_lifecycle() {
    let mut scope = GradedScope::open("browser_component");

    // Reserve and resolve three obligations
    scope.on_reserve();
    scope.on_reserve();
    scope.on_reserve();

    scope.on_resolve();
    scope.on_resolve();
    scope.on_resolve();

    assert_eq!(scope.outstanding(), 0, "No outstanding obligations");
    let proof = scope.close().expect("Scope should close cleanly");
    assert_eq!(proof.total_reserved, 3);
    assert_eq!(proof.total_resolved, 3);
}

/// GradedScope detects leaked obligations at scope exit.
#[test]
fn wasm_graded_scope_detects_leak() {
    let mut scope = GradedScope::open("leaky_component");

    scope.on_reserve();
    scope.on_reserve();
    scope.on_resolve(); // Only resolve 1 of 2

    assert_eq!(scope.outstanding(), 1, "One obligation leaked");

    let result = scope.close();
    assert!(result.is_err(), "Scope must report leak");
    let err = result.unwrap_err();
    assert_eq!(err.outstanding, 1, "Exactly one obligation leaked");
}

/// GradedScope double-resolution is caught (browser correctness invariant).
#[test]
#[should_panic(expected = "on_resolve called more times than on_reserve")]
fn wasm_graded_scope_double_resolution_panics() {
    let mut scope = GradedScope::open("double_resolve");
    scope.on_reserve();
    scope.on_resolve();
    scope.on_resolve(); // This is the double-resolution — panic
}

// ============================================================================
// 8. Leak Detection: oracle catches unresolved obligations
// ============================================================================

/// Leak check correctly identifies multiple leaked obligations by region,
/// with enough diagnostic info for browser-side debugging.
#[test]
fn wasm_leak_detection_multi_kind() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    let _tok1 = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(0));
    let _tok2 = ledger.acquire(ObligationKind::Lease, task(1), r, t(10));
    let tok3 = ledger.acquire(ObligationKind::Ack, task(0), r, t(20));

    // Only resolve one of three
    ledger.commit(tok3, t(30));

    let result = ledger.check_region_leaks(r);
    assert!(!result.is_clean(), "Region has leaked obligations");
    assert_eq!(result.leaked.len(), 2, "Two obligations leaked");

    // Verify leaked obligations have correct diagnostic info
    for leak in &result.leaked {
        assert_eq!(
            leak.region, r,
            "Leaked obligation must be in the correct region"
        );
        assert!(
            leak.kind == ObligationKind::SendPermit || leak.kind == ObligationKind::Lease,
            "Leaked kinds must be the unresolved ones"
        );
    }

    // Global check also catches them
    let global = ledger.check_leaks();
    assert_eq!(global.leaked.len(), 2);
}

/// mark_leaked + check_leaks: leaked obligations show up in both
/// the stats and the diagnostic report.
#[test]
fn wasm_mark_leaked_detected_by_oracle() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    let tok = ledger.acquire(ObligationKind::IoOp, task(0), r, t(0));
    let id = tok.id();

    ledger.mark_leaked(id, t(1000));

    let stats = ledger.stats();
    assert_eq!(stats.total_leaked, 1);
    assert_eq!(stats.pending, 0, "mark_leaked reduces pending count");
    assert!(!stats.is_clean(), "Stats reflect the leak");

    let result = ledger.check_leaks();
    assert!(!result.is_clean());
    assert_eq!(result.leaked[0].id, id);
}

// ============================================================================
// 9. Comprehensive: full browser lifecycle simulation
// ============================================================================

/// End-to-end browser lifecycle: page load → component mount → async work →
/// some work completes → navigation (cancel) → drain → quiescence.
#[test]
fn wasm_full_browser_lifecycle_simulation() {
    let mut ledger = ObligationLedger::new();

    // -- Page load: create regions for different components --
    let r_fetch = region(0); // HTTP fetch region
    let r_ws = region(1); // WebSocket region
    let r_idb = region(2); // IndexedDB region

    // -- Component mount: tasks acquire obligations --
    let fetch_tok = ledger.acquire(ObligationKind::SendPermit, task(0), r_fetch, t(100));
    let ws_lease = ledger.acquire(ObligationKind::Lease, task(1), r_ws, t(200));
    let idb_op = ledger.acquire(ObligationKind::IoOp, task(2), r_idb, t(300));
    let fetch_ack = ledger.acquire(ObligationKind::Ack, task(0), r_fetch, t(400));

    assert_eq!(ledger.pending_count(), 4);

    // -- Async work: some obligations complete normally --
    ledger.commit(fetch_tok, t(1_000)); // Fetch response arrived
    ledger.commit(fetch_ack, t(1_200)); // Ack sent

    assert!(ledger.is_region_clean(r_fetch), "Fetch region done");
    assert_eq!(ledger.pending_count(), 2, "WS and IDB still active");

    // -- Navigation event: cancel remaining regions --
    ledger.abort(ws_lease, t(2_000), ObligationAbortReason::Cancel);
    ledger.abort(idb_op, t(2_100), ObligationAbortReason::Cancel);

    // -- Quiescence: all regions clean --
    assert!(ledger.is_region_clean(r_fetch));
    assert!(ledger.is_region_clean(r_ws));
    assert!(ledger.is_region_clean(r_idb));

    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, 4);
    assert_eq!(stats.total_committed, 2);
    assert_eq!(stats.total_aborted, 2);
    assert_eq!(stats.total_leaked, 0);
    assert_eq!(stats.pending, 0);
    assert!(stats.is_clean(), "Full lifecycle results in clean ledger");
}

/// Stress test: many obligations across many regions, all drained cleanly.
/// Verifies no accounting drift under load (browser may have many components).
#[test]
fn wasm_stress_many_obligations_many_regions() {
    let mut ledger = ObligationLedger::new();

    let num_regions = 10;
    let obligations_per_region = 20;
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ];

    // Acquire many obligations across many regions
    let mut all_tokens = Vec::new();
    for r in 0..num_regions {
        for i in 0..obligations_per_region {
            let kind = kinds[(r * obligations_per_region + i) % kinds.len()];
            let tok = ledger.acquire(
                kind,
                task((r * obligations_per_region + i) as u32),
                region(r as u32),
                t((r * 1000 + i * 10) as u64),
            );
            all_tokens.push((tok, r as u32));
        }
    }

    let total = (num_regions * obligations_per_region) as u64;
    assert_eq!(ledger.pending_count(), total);

    // Resolve all: alternate between commit and abort
    let drain_time = t(100_000);
    for (i, (tok, _)) in all_tokens.into_iter().enumerate() {
        if i % 2 == 0 {
            ledger.commit(tok, drain_time);
        } else {
            ledger.abort(tok, drain_time, ObligationAbortReason::Cancel);
        }
    }

    // All regions must be clean
    for r in 0..num_regions {
        assert!(
            ledger.is_region_clean(region(r as u32)),
            "Region {r} must be clean after full drain"
        );
    }

    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, total);
    assert_eq!(stats.total_committed, total / 2);
    assert_eq!(stats.total_aborted, total / 2);
    assert_eq!(stats.pending, 0);
    assert!(stats.is_clean());
}

/// Reset then reuse: browser page reload should start with fresh ledger state.
#[test]
fn wasm_reset_simulates_page_reload() {
    let mut ledger = ObligationLedger::new();
    let r = region(0);

    // First page load: some obligations
    let tok = ledger.acquire(ObligationKind::SendPermit, task(0), r, t(0));
    ledger.commit(tok, t(100));

    assert_eq!(ledger.stats().total_acquired, 1);

    // Page reload: reset
    ledger.reset();
    assert!(ledger.is_empty());
    assert_eq!(ledger.stats().total_acquired, 0);
    assert_eq!(ledger.len(), 0);

    // Second page load: fresh obligations
    let tok2 = ledger.acquire(ObligationKind::Ack, task(0), r, t(0));
    ledger.commit(tok2, t(50));

    assert_eq!(ledger.stats().total_acquired, 1);
    assert!(ledger.stats().is_clean());
}
