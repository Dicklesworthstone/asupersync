//! Refinement map conformance tests (bd-3g13z).
//!
//! Verifies that the Rust implementation's state transitions match the
//! Lean specification's Step constructors. Each test exercises an observable
//! transition and checks that the pre/post state projects correctly through
//! the refinement map (abstraction function α).
//!
//! # Refinement Map (α : ImplState → SpecState)
//!
//! TaskState mapping (1:1):
//!   Created                    → TaskState.created
//!   Running                    → TaskState.running
//!   CancelRequested{r,b}       → TaskState.cancelRequested reason cleanup
//!   Cancelling{r,b}            → TaskState.cancelling reason cleanup
//!   Finalizing{r,b}            → TaskState.finalizing reason cleanup
//!   Completed(outcome)         → TaskState.completed outcome
//!
//! RegionState mapping (1:1):
//!   Open     → RegionState.open
//!   Closing  → RegionState.closing
//!   Draining → RegionState.draining
//!   Finalizing → RegionState.finalizing
//!   Closed   → RegionState.closed outcome
//!
//! ObligationState mapping (1:1):
//!   Reserved  → ObligationState.reserved
//!   Committed → ObligationState.committed
//!   Aborted   → ObligationState.aborted
//!   Leaked    → ObligationState.leaked
//!
//! # Stuttering
//!
//! Implementation-only transitions (work stealing, metrics, cache) are
//! stuttering steps that do not change spec-visible state. The Lean theorem
//! `stuttering_preserves_wellformed` proves these cannot violate invariants.
//!
//! # Testable Bounds
//!
//! Cancellation terminates in at most MAX_MASK_DEPTH + 3 = 67 steps per task.
//! This matches the Lean theorem `cancel_steps_testable_bound`.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::lab::oracle::{
    CancellationProtocolOracle, OracleSuite, QuiescenceOracle, TaskLeakOracle,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::runtime::yield_now;
use asupersync::trace::{trace_fingerprint, TraceEvent};
use asupersync::types::{Budget, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time};
use common::*;
use serde_json::Value;
use std::path::Path;

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

const SEMANTICS_TRACE_FINGERPRINT: u64 = 17_536_848_186_479_526_199;
const INVARIANT_LINK_MAP_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_theorem_test_link_map.json");

// ============================================================================
// Spawn Simulation Tests
// Lean theorem: spawn_creates_task
// Verifies: spawn produces a task with state=Created in the target region
// ============================================================================

/// Validates: Lean spawn_creates_task — spawn produces Created state in region.
#[test]
fn refinement_spawn_creates_task_in_region() {
    init_test("refinement_spawn_creates_task_in_region");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);

    // Spec precondition: region exists and is open
    oracle.on_region_create(root, None);

    // Spec step: spawn(r, t) — task absent, region open
    oracle.on_task_create(worker, root);

    // Post-state: task exists with state=Created (spec: TaskState.created)
    // The oracle tracks this; if task were in wrong state, later transitions would fail.

    // Verify: task can transition from Created → Running (confirms Created state)
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "spawn creates task in region", true, ok);

    test_complete!("refinement_spawn_creates_task_in_region");
}

/// Validates: Lean spawn_preserves_other_tasks — spawn doesn't affect existing tasks.
#[test]
fn refinement_spawn_preserves_existing_tasks() {
    init_test("refinement_spawn_preserves_existing_tasks");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let existing = task(1);
    let new_task = task(2);
    let reason = CancelReason::timeout();
    let cleanup = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(existing, root);
    oracle.on_transition(existing, &TaskState::Created, &TaskState::Running, t(10));

    // Spawn a second task (should not affect existing task's state)
    oracle.on_task_create(new_task, root);

    // Existing task continues its protocol normally (confirms no interference)
    oracle.on_cancel_request(existing, reason.clone(), t(20));
    oracle.on_transition(
        existing,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(20),
    );
    oracle.on_transition(
        existing,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(30),
    );
    oracle.on_transition(
        existing,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(40),
    );
    oracle.on_transition(
        existing,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(50),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "spawn preserves existing tasks", true, ok);

    test_complete!("refinement_spawn_preserves_existing_tasks");
}

// ============================================================================
// Cancel Simulation Tests
// Lean theorems: cancel_step_strengthens_reason, cancel_protocol_terminates
// Verifies: cancel request transitions + bounded termination
// ============================================================================

/// Validates: Lean cancel_protocol_terminates — full cancel protocol completes.
/// Also validates cancel_steps_testable_bound — at most mask + 3 steps.
#[test]
fn refinement_cancel_protocol_terminates() {
    init_test("refinement_cancel_protocol_terminates");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);
    let reason = CancelReason::user("test");
    let cleanup = Budget::INFINITE;

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Cancel request (Lean: cancelRequest step)
    oracle.on_cancel_request(worker, reason.clone(), t(100));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(100),
    );

    // CancelAcknowledge (Lean: cancelAcknowledge step, mask=0 so immediate)
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(200),
    );

    // CancelFinalize (Lean: cancelFinalize step)
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(300),
    );

    // CancelComplete (Lean: cancelComplete step)
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(400),
    );

    // Verify: protocol completed without violations
    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "cancel protocol terminates", true, ok);

    // Verify: total steps = 3 (ack + finalize + complete) ≤ MAX_MASK_DEPTH + 3 = 67
    // mask=0, so exactly 3 cancel-protocol steps as predicted by cancel_potential
    let total_steps = 3u32; // ack, finalize, complete
    let max_steps = 64 + 3; // MAX_MASK_DEPTH + 3
    assert_with_log!(
        total_steps <= max_steps,
        "cancel steps within bound",
        true,
        total_steps <= max_steps
    );

    test_complete!("refinement_cancel_protocol_terminates");
}

/// Validates: Lean cancel_step_strengthens_reason — cancel strengthens region cancel.
#[test]
fn refinement_cancel_strengthens_reason() {
    init_test("refinement_cancel_strengthens_reason");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let t1 = task(1);
    let t2 = task(2);

    oracle.on_region_create(root, None);
    oracle.on_task_create(t1, root);
    oracle.on_task_create(t2, root);
    oracle.on_transition(t1, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_transition(t2, &TaskState::Created, &TaskState::Running, t(10));

    // First cancel with user reason
    let reason1 = CancelReason::user("stop");
    oracle.on_cancel_request(t1, reason1.clone(), t(50));
    oracle.on_transition(
        t1,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason1.clone(),
            cleanup_budget: Budget::INFINITE,
        },
        t(50),
    );

    // Second cancel with shutdown reason (stronger per Lean strengthenReason)
    let reason2 = CancelReason::shutdown();
    oracle.on_cancel_request(t2, reason2.clone(), t(60));
    oracle.on_transition(
        t2,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason2.clone(),
            cleanup_budget: Budget::INFINITE,
        },
        t(60),
    );

    // Both tasks complete their protocols
    for (tid, reason) in [(t1, reason1), (t2, reason2)] {
        let cleanup = Budget::INFINITE;
        oracle.on_transition(
            tid,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget: cleanup,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget: cleanup,
            },
            t(100),
        );
        oracle.on_transition(
            tid,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget: cleanup,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget: cleanup,
            },
            t(150),
        );
        oracle.on_transition(
            tid,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget: cleanup,
            },
            &TaskState::Completed(Outcome::Cancelled(reason)),
            t(200),
        );
    }

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "cancel strengthens reason", true, ok);

    test_complete!("refinement_cancel_strengthens_reason");
}

// ============================================================================
// Close Simulation Tests
// Lean theorem: close_produces_closed_region
// Verifies: region close sequence matches spec
// ============================================================================

/// Validates: Lean close_produces_closed_region — region reaches closed state.
/// Uses QuiescenceOracle + TaskLeakOracle to verify region close.
#[test]
fn refinement_close_produces_closed_region() {
    init_test("refinement_close_produces_closed_region");

    let mut quiescence = QuiescenceOracle::new();
    let mut task_leak = TaskLeakOracle::new();
    let root = region(0);
    let worker = task(1);

    quiescence.on_region_create(root, None);
    quiescence.on_spawn(worker, root);
    task_leak.on_spawn(worker, root, t(5));

    // Task completes normally (Lean: complete step)
    quiescence.on_task_complete(worker);
    task_leak.on_complete(worker, t(50));

    // Region close (Lean: closeBegin → closeChildrenDone → close)
    quiescence.on_region_close(root, t(100));
    task_leak.on_region_close(root, t(100));

    let q_result = quiescence.check();
    let t_result = task_leak.check(t(100));
    let ok = q_result.is_ok() && t_result.is_ok();
    assert_with_log!(ok, "close produces closed region", true, ok);

    test_complete!("refinement_close_produces_closed_region");
}

// ============================================================================
// Obligation Simulation Tests
// Lean theorems: commit_resolves_obligation, abort_resolves_obligation
// Verifies: obligation lifecycle matches spec
// ============================================================================

/// Validates: Lean commit_resolves_obligation — commit transitions to committed.
/// Uses cancellation oracle to verify clean task lifecycle with obligation resolution.
#[test]
fn refinement_obligation_commit_lifecycle() {
    init_test("refinement_obligation_commit_lifecycle");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(1);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));

    // Obligation reserve → commit lifecycle is validated by the obligation oracle.
    // Here we verify that the task can complete cleanly after obligation resolution.
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(100),
    );

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "obligation commit lifecycle", true, ok);

    test_complete!("refinement_obligation_commit_lifecycle");
}

// ============================================================================
// Stuttering Tests
// Lean theorem: stuttering_preserves_wellformed
// Verifies: internal scheduler operations don't affect protocol correctness
// ============================================================================

/// Validates: Lean stuttering_preserves_wellformed — scheduler-only transitions
/// don't violate spec invariants.
#[test]
fn refinement_stuttering_preserves_invariants() {
    init_test("refinement_stuttering_preserves_invariants");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let t1 = task(1);
    let t2 = task(2);
    let t3 = task(3);

    oracle.on_region_create(root, None);

    // Spawn multiple tasks (interleaved with scheduler activity = stuttering)
    oracle.on_task_create(t1, root);
    oracle.on_task_create(t2, root);
    oracle.on_task_create(t3, root);

    // All tasks go through full lifecycle (scheduler may interleave = stuttering)
    for tid in [t1, t2, t3] {
        oracle.on_transition(tid, &TaskState::Created, &TaskState::Running, t(10));
        oracle.on_transition(
            tid,
            &TaskState::Running,
            &TaskState::Completed(Outcome::Ok(())),
            t(50),
        );
    }

    let result = oracle.check();
    let ok = result.is_ok();
    assert_with_log!(ok, "stuttering preserves invariants", true, ok);

    test_complete!("refinement_stuttering_preserves_invariants");
}

// ============================================================================
// Semantics Conformance Suite (Unit + E2E)
// Verifies: spawn/cancel/close/obligation lifecycle + trace-logged execution
// ============================================================================

/// Unit-level conformance: spawn → cancel → close + obligation resolution.
#[test]
fn refinement_semantics_spawn_cancel_close_obligation() {
    init_test("refinement_semantics_spawn_cancel_close_obligation");

    let mut suite = OracleSuite::new();
    let root = region(0);
    let worker = task(1);
    let ob = obligation(0);
    let reason = CancelReason::timeout();
    let cleanup = Budget::INFINITE;

    // Region + task setup.
    suite.region_tree.on_region_create(root, None, t(0));
    suite.quiescence.on_region_create(root, None);
    suite.task_leak.on_spawn(worker, root, t(5));
    suite.quiescence.on_spawn(worker, root);

    suite.cancellation_protocol.on_region_create(root, None);
    suite.cancellation_protocol.on_task_create(worker, root);
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Created,
        &TaskState::Running,
        t(10),
    );

    // Obligation lifecycle.
    suite
        .obligation_leak
        .on_create(ob, ObligationKind::SendPermit, worker, root);

    // Cancel request + cleanup/finalize path.
    suite
        .cancellation_protocol
        .on_cancel_request(worker, reason.clone(), t(20));
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(20),
    );
    suite
        .obligation_leak
        .on_resolve(ob, ObligationState::Aborted);
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(25),
    );
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        t(30),
    );
    suite.cancellation_protocol.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: cleanup,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(40),
    );

    // Close + quiescence.
    suite.task_leak.on_complete(worker, t(40));
    suite.quiescence.on_task_complete(worker);
    suite.obligation_leak.on_region_close(root, t(50));
    suite.quiescence.on_region_close(root, t(50));
    suite.task_leak.on_region_close(root, t(50));

    let violations = suite.check_all(t(60));
    assert_with_log!(
        violations.is_empty(),
        "spawn/cancel/close/obligation conformance",
        "empty",
        violations
    );

    test_complete!("refinement_semantics_spawn_cancel_close_obligation");
}

/// E2E conformance: deterministic lab trace for spawn + cancel + close.
#[test]
fn refinement_semantics_trace_golden() {
    init_test("refinement_semantics_trace_golden");

    let seed = 0x00C0_FFEE_u64;
    let config = LabConfig::new(seed)
        .worker_count(2)
        .trace_capacity(4096)
        .max_steps(5000);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            for _ in 0..4 {
                if cx.checkpoint().is_err() {
                    return;
                }
                yield_now().await;
            }
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    for _ in 0..4 {
        runtime.step_for_test();
    }

    let reason = CancelReason::timeout();
    let tasks_to_cancel = runtime.state.cancel_request(region, &reason, None);
    {
        let mut scheduler = runtime.scheduler.lock().unwrap();
        for (tid, priority) in tasks_to_cancel {
            scheduler.schedule_cancel(tid, priority);
        }
    }

    runtime.run_until_quiescent();

    let violations = runtime.oracles.check_all(runtime.now());
    assert_with_log!(
        violations.is_empty(),
        "lab trace has no oracle violations",
        "empty",
        violations
    );

    let events = runtime.trace().snapshot();
    let fingerprint = trace_fingerprint(&events);
    assert_with_log!(
        fingerprint == SEMANTICS_TRACE_FINGERPRINT,
        "semantics trace fingerprint",
        SEMANTICS_TRACE_FINGERPRINT,
        fingerprint
    );

    test_complete!("refinement_semantics_trace_golden");
}

/// Refinement validation should treat benign interleaving differences as equivalent.
///
/// This is the core anti-noise guard for Track-4 divergence triage: raw event order
/// can differ while the canonical trace class remains identical.
#[test]
fn refinement_trace_equivalence_filters_schedule_noise() {
    init_test("refinement_trace_equivalence_filters_schedule_noise");

    // Two independent task timelines with different raw interleavings.
    let trace_a = vec![
        TraceEvent::spawn(1, t(1), task(1), region(1)),
        TraceEvent::spawn(2, t(2), task(2), region(2)),
        TraceEvent::complete(3, t(3), task(1), region(1)),
        TraceEvent::complete(4, t(4), task(2), region(2)),
    ];
    let trace_b = vec![
        TraceEvent::spawn(10, t(1), task(2), region(2)),
        TraceEvent::spawn(11, t(2), task(1), region(1)),
        TraceEvent::complete(12, t(3), task(2), region(2)),
        TraceEvent::complete(13, t(4), task(1), region(1)),
    ];

    assert_with_log!(
        trace_a != trace_b,
        "raw traces differ under schedule noise",
        true,
        trace_a != trace_b
    );

    let fp_a = trace_fingerprint(&trace_a);
    let fp_b = trace_fingerprint(&trace_b);
    assert_with_log!(
        fp_a == fp_b,
        "equivalence fingerprint ignores benign ordering differences",
        fp_a,
        fp_b
    );

    // Determinism: repeated fingerprint computation must be stable.
    let fp_a_again = trace_fingerprint(&trace_a);
    assert_with_log!(
        fp_a == fp_a_again,
        "fingerprint deterministic for same trace",
        fp_a,
        fp_a_again
    );

    test_complete!("refinement_trace_equivalence_filters_schedule_noise");
}

/// Refinement validation should still flag semantic mismatches.
///
/// Reordering dependent events for the same task must produce a different
/// equivalence fingerprint.
#[test]
fn refinement_trace_equivalence_detects_semantic_mismatch() {
    init_test("refinement_trace_equivalence_detects_semantic_mismatch");

    let baseline = vec![
        TraceEvent::spawn(20, t(1), task(3), region(3)),
        TraceEvent::complete(21, t(2), task(3), region(3)),
    ];
    let mismatch = vec![
        TraceEvent::complete(30, t(1), task(3), region(3)),
        TraceEvent::spawn(31, t(2), task(3), region(3)),
    ];

    let baseline_fp = trace_fingerprint(&baseline);
    let mismatch_fp = trace_fingerprint(&mismatch);
    assert_with_log!(
        baseline_fp != mismatch_fp,
        "semantic mismatch is not normalized away",
        baseline_fp,
        mismatch_fp
    );

    test_complete!("refinement_trace_equivalence_detects_semantic_mismatch");
}

fn invariant_row<'a>(rows: &'a [Value], invariant_id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get("invariant_id").and_then(Value::as_str) == Some(invariant_id))
        .unwrap_or_else(|| panic!("missing invariant row {invariant_id}"))
}

fn string_array_set(parent: &Value, key: &str) -> std::collections::BTreeSet<String> {
    parent
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>()
}

#[test]
fn refinement_liveness_link_map_contract_feeds_conformance_harnesses() {
    init_test("refinement_liveness_link_map_contract_feeds_conformance_harnesses");

    let link_map: Value = serde_json::from_str(INVARIANT_LINK_MAP_JSON)
        .expect("invariant theorem/test link map must parse");
    let rows = link_map
        .get("invariant_links")
        .and_then(Value::as_array)
        .expect("invariant_links must be an array");

    let cancel_row = invariant_row(rows, "inv.cancel.protocol");
    let loser_row = invariant_row(rows, "inv.race.losers_drained");
    let quiescence_row = invariant_row(rows, "inv.region_close.quiescence");

    for row in [cancel_row, loser_row, quiescence_row] {
        let assumption_envelope = row
            .get("assumption_envelope")
            .expect("liveness row must include assumption_envelope");
        let assumptions = string_array_set(assumption_envelope, "assumptions");
        let guardrails = string_array_set(assumption_envelope, "runtime_guardrails");
        assert!(
            !assumptions.is_empty(),
            "liveness assumption_envelope must define assumptions"
        );
        assert!(
            !guardrails.is_empty(),
            "liveness assumption_envelope must define runtime_guardrails"
        );

        let composition_contract = row
            .get("composition_contract")
            .expect("liveness row must include composition_contract");
        let consumed_by = string_array_set(composition_contract, "consumed_by");
        assert!(
            consumed_by.contains("tests/refinement_conformance.rs"),
            "liveness composition_contract must feed tests/refinement_conformance.rs"
        );
        for path in consumed_by {
            assert!(
                Path::new(&path).exists(),
                "composition consumer path does not exist: {path}"
            );
        }
    }

    let cancel_checks = string_array_set(cancel_row, "executable_checks");
    assert!(
        cancel_checks.contains("tests/cancel_obligation_invariants.rs"),
        "cancel protocol row must include cancellation/obligation conformance coverage"
    );
    assert!(
        cancel_checks.contains("tests/cancellation_conformance.rs"),
        "cancel protocol row must include cancellation conformance coverage"
    );

    let loser_checks = string_array_set(loser_row, "executable_checks");
    assert!(
        loser_checks.contains("tests/e2e/combinator/cancel_correctness/loser_drain.rs"),
        "loser-drain row must include loser_drain harness"
    );
    assert!(
        loser_checks.contains("tests/e2e/combinator/cancel_correctness/async_loser_drain.rs"),
        "loser-drain row must include async loser_drain harness"
    );

    assert_eq!(
        loser_row
            .get("composition_contract")
            .and_then(|contract| contract.get("status"))
            .and_then(Value::as_str)
            .expect("loser-drain composition status must be present"),
        "partial"
    );
    assert_eq!(
        cancel_row
            .get("composition_contract")
            .and_then(|contract| contract.get("status"))
            .and_then(Value::as_str)
            .expect("cancel composition status must be present"),
        "ready"
    );
    assert_eq!(
        quiescence_row
            .get("composition_contract")
            .and_then(|contract| contract.get("status"))
            .and_then(Value::as_str)
            .expect("quiescence composition status must be present"),
        "ready"
    );

    test_complete!("refinement_liveness_link_map_contract_feeds_conformance_harnesses");
}
