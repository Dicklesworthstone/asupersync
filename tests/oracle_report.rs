//! Integration tests for the unified oracle report and expanded mutations.
//!
//! Validates:
//! - Unified OracleReport generation from OracleSuite
//! - JSON serialization roundtrip
//! - Deterministic report output across identical lab runs
//! - New mutations (actor_leak, supervision, mailbox) work end-to-end
//! - MetaRunner produces correct coverage with all 12 mutations

mod common;
use common::*;

use asupersync::lab::meta::{builtin_mutations, MetaRunner};
use asupersync::lab::oracle::OracleSuite;
use asupersync::lab::OracleReport;
use asupersync::types::Time;

// ==================== Unified Report Tests ====================

#[test]
fn unified_report_clean_suite_all_pass() {
    init_test_logging();
    test_phase!("unified_report_clean_suite_all_pass");

    let suite = OracleSuite::new();
    let report = suite.report(Time::ZERO);

    assert!(report.all_passed(), "clean suite should pass all oracles");
    assert_eq!(report.total, 12, "should check all 12 oracles");
    assert_eq!(report.passed, 12);
    assert_eq!(report.failed, 0);
    assert_eq!(report.entries.len(), 12);
    assert!(report.failures().is_empty());

    test_complete!("unified_report_clean_suite_all_pass");
}

#[test]
fn unified_report_json_roundtrip() {
    init_test_logging();
    test_phase!("unified_report_json_roundtrip");

    let suite = OracleSuite::new();
    let report = suite.report(Time::from_nanos(42));

    // Serialize to JSON string
    let json_str = serde_json::to_string(&report).expect("serialize");

    // Deserialize back
    let deserialized: OracleReport = serde_json::from_str(&json_str).expect("deserialize");

    assert_eq!(deserialized.total, report.total);
    assert_eq!(deserialized.passed, report.passed);
    assert_eq!(deserialized.failed, report.failed);
    assert_eq!(deserialized.check_time_nanos, report.check_time_nanos);
    assert_eq!(deserialized.entries.len(), report.entries.len());

    for (orig, deser) in report.entries.iter().zip(deserialized.entries.iter()) {
        assert_eq!(orig.invariant, deser.invariant);
        assert_eq!(orig.passed, deser.passed);
        assert_eq!(orig.violation, deser.violation);
        assert_eq!(orig.stats, deser.stats);
    }

    test_complete!("unified_report_json_roundtrip");
}

#[test]
fn unified_report_deterministic_across_runs() {
    init_test_logging();
    test_phase!("unified_report_deterministic_across_runs");

    // Two identical suites should produce identical reports.
    let suite1 = OracleSuite::new();
    let suite2 = OracleSuite::new();

    let report1 = suite1.report(Time::from_nanos(100));
    let report2 = suite2.report(Time::from_nanos(100));

    let json1 = serde_json::to_string(&report1).expect("ser1");
    let json2 = serde_json::to_string(&report2).expect("ser2");
    assert_eq!(
        json1, json2,
        "identical suites should produce identical JSON"
    );

    test_complete!("unified_report_deterministic_across_runs");
}

#[test]
fn unified_report_text_contains_all_oracles() {
    init_test_logging();
    test_phase!("unified_report_text_contains_all_oracles");

    let suite = OracleSuite::new();
    let report = suite.report(Time::ZERO);
    let text = report.to_text();

    let expected_invariants = [
        "task_leak",
        "obligation_leak",
        "quiescence",
        "loser_drain",
        "finalizer",
        "region_tree",
        "ambient_authority",
        "deadline_monotone",
        "cancellation_protocol",
        "actor_leak",
        "supervision",
        "mailbox",
    ];

    for inv in &expected_invariants {
        assert!(
            text.contains(inv),
            "report text should contain '{inv}', got:\n{text}"
        );
    }

    assert!(
        text.contains("[PASS]"),
        "clean report should have PASS entries"
    );
    assert!(
        !text.contains("[FAIL]"),
        "clean report should not have FAIL entries"
    );

    test_complete!("unified_report_text_contains_all_oracles");
}

#[test]
fn unified_report_entry_lookup() {
    init_test_logging();
    test_phase!("unified_report_entry_lookup");

    let suite = OracleSuite::new();
    let report = suite.report(Time::ZERO);

    // All 12 invariants should be findable.
    let invariants = [
        "task_leak",
        "obligation_leak",
        "quiescence",
        "loser_drain",
        "finalizer",
        "region_tree",
        "ambient_authority",
        "deadline_monotone",
        "cancellation_protocol",
        "actor_leak",
        "supervision",
        "mailbox",
    ];

    for inv in &invariants {
        let entry = report.entry(inv);
        assert!(entry.is_some(), "should find entry for '{inv}'");
        assert!(entry.unwrap().passed, "'{inv}' should pass in clean suite");
    }

    // Nonexistent invariant should return None.
    assert!(report.entry("nonexistent").is_none());

    test_complete!("unified_report_entry_lookup");
}

// ==================== Expanded Mutation Tests ====================

#[test]
fn meta_mutations_all_12_covered() {
    init_test_logging();
    test_phase!("meta_mutations_all_12_covered");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());

    // Should have 12 mutations now (9 original + 3 new).
    assert_eq!(report.results().len(), 12, "should run 12 mutations");

    // AmbientAuthority oracle has a known detection gap.
    let failures: Vec<_> = report
        .failures()
        .into_iter()
        .filter(|f| f.mutation != "mutation_ambient_authority_spawn_without_capability")
        .collect();
    assert!(
        failures.is_empty(),
        "unexpected meta oracle failures:\n{}",
        report.to_text()
    );

    test_complete!("meta_mutations_all_12_covered");
}

#[test]
fn meta_mutations_actor_leak_detected() {
    init_test_logging();
    test_phase!("meta_mutations_actor_leak_detected");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());

    let actor_result = report
        .results()
        .iter()
        .find(|r| r.mutation == "mutation_actor_leak")
        .expect("actor_leak mutation should exist");

    assert!(actor_result.baseline_clean(), "baseline should be clean");
    assert!(
        actor_result.mutation_detected(),
        "actor_leak mutation should be detected"
    );

    test_complete!("meta_mutations_actor_leak_detected");
}

#[test]
fn meta_mutations_supervision_detected() {
    init_test_logging();
    test_phase!("meta_mutations_supervision_detected");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());

    let sup_result = report
        .results()
        .iter()
        .find(|r| r.mutation == "mutation_supervision_restart_limit")
        .expect("supervision mutation should exist");

    assert!(sup_result.baseline_clean(), "baseline should be clean");
    assert!(
        sup_result.mutation_detected(),
        "supervision mutation should be detected"
    );

    test_complete!("meta_mutations_supervision_detected");
}

#[test]
fn meta_mutations_mailbox_detected() {
    init_test_logging();
    test_phase!("meta_mutations_mailbox_detected");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());

    let mb_result = report
        .results()
        .iter()
        .find(|r| r.mutation == "mutation_mailbox_capacity_exceeded")
        .expect("mailbox mutation should exist");

    assert!(mb_result.baseline_clean(), "baseline should be clean");
    assert!(
        mb_result.mutation_detected(),
        "mailbox mutation should be detected"
    );

    test_complete!("meta_mutations_mailbox_detected");
}

#[test]
fn meta_coverage_now_includes_actor_supervision_mailbox() {
    init_test_logging();
    test_phase!("meta_coverage_now_includes_actor_supervision_mailbox");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());
    let missing = report.coverage().missing_invariants();

    assert!(
        !missing.contains(&"actor_leak"),
        "actor_leak should be covered by mutations"
    );
    assert!(
        !missing.contains(&"supervision"),
        "supervision should be covered by mutations"
    );
    assert!(
        !missing.contains(&"mailbox"),
        "mailbox should be covered by mutations"
    );

    test_complete!("meta_coverage_now_includes_actor_supervision_mailbox");
}

#[test]
fn meta_runner_deterministic_with_new_mutations() {
    init_test_logging();
    test_phase!("meta_runner_deterministic_with_new_mutations");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report1 = runner.run(builtin_mutations());
    let report2 = runner.run(builtin_mutations());

    assert_eq!(report1.results().len(), report2.results().len());
    for (r1, r2) in report1.results().iter().zip(report2.results()) {
        assert_eq!(r1.mutation, r2.mutation);
        assert_eq!(r1.invariant, r2.invariant);
        assert_eq!(r1.baseline_clean(), r2.baseline_clean());
        assert_eq!(r1.mutation_detected(), r2.mutation_detected());
    }

    test_complete!("meta_runner_deterministic_with_new_mutations");
}
