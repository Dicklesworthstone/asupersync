//! Reference integration test for the `TestEvidenceSink` harness
//! (br-asupersync-364340).
//!
//! Demonstrates the required instrumentation shape so future tests can be
//! retrofitted by mechanical pattern copy: `setup` → build `Cx` / runtime,
//! `execute` → each significant runtime action, `assert` → invariants,
//! `teardown` → resource release. The resulting JSONL at
//! `tests/_evidence/evidence_harness_demo.jsonl` is the golden artifact for
//! the CI flake-pattern analyzer described in the testing-perfect-e2e skill.

#![cfg(feature = "test-internals")]

mod common;

use asupersync::cx::Cx;
use common::{TestEvidenceSink, TestOutcome, TestPhase, read_evidence};

#[test]
fn evidence_harness_demo_emits_lifecycle_jsonl() {
    let sink = TestEvidenceSink::new("evidence_harness_demo");

    // ── setup ───────────────────────────────────────────────────────────────
    sink.setup("construct_cx", TestOutcome::Ok);
    let cx = Cx::for_testing();

    // ── execute ─────────────────────────────────────────────────────────────
    sink.execute(&cx, "region_discovered", TestOutcome::Ok);
    sink.execute(&cx, "task_simulated", TestOutcome::Ok);
    // Record a negative example so downstream analyzers see at least one
    // `err` outcome in the golden artifact.
    sink.execute(
        &cx,
        "intentional_negative_for_schema",
        TestOutcome::Err("expected demo error — not a real failure".into()),
    );
    sink.emit(
        TestPhase::Custom("sampling".into()),
        &cx,
        "custom_phase_event",
        TestOutcome::Note,
    );

    // ── assert ──────────────────────────────────────────────────────────────
    sink.assert_event(&cx, "region_task_ids_present", TestOutcome::Ok);

    // ── teardown ────────────────────────────────────────────────────────────
    sink.teardown("drop_cx", TestOutcome::Ok);

    let path = sink.path().to_path_buf();
    drop(sink);

    // Round-trip the JSONL to catch schema drift at commit time.
    let records = read_evidence(&path);
    assert_eq!(records.len(), 7, "expected 7 lifecycle records at {path:?}");

    // Phase ordering — setup precedes execute precedes assert precedes teardown.
    let phases: Vec<_> = records.iter().map(|r| r.phase.as_str()).collect();
    assert_eq!(
        phases,
        [
            "setup", "execute", "execute", "execute", "sampling", "assert", "teardown",
        ]
    );

    // Required fields populated on every line.
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.test_name, "evidence_harness_demo");
        assert_eq!(r.seq, i as u64);
        assert!(!r.event.is_empty(), "event empty at seq={i}");
        assert!(!r.cx_id.is_empty(), "cx_id empty at seq={i}");
        assert!(!r.outcome.is_empty(), "outcome empty at seq={i}");
        assert!(r.ts_unix_nanos > 0);
    }

    // The err outcome carries its message.
    let err = records
        .iter()
        .find(|r| r.outcome == "err")
        .expect("err record present");
    assert_eq!(
        err.error.as_deref(),
        Some("expected demo error — not a real failure")
    );
}
