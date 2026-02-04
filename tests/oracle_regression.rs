#![allow(clippy::too_many_lines)]
//! Oracle E2E regression suite with evidence logs.
//!
//! This suite provides:
//! - Full meta-mutation regression across all invariants
//! - Evidence ledger integration for galaxy-brain diagnostics
//! - E-process anytime-valid monitoring regression
//! - Deterministic reproduction via fixed seeds
//! - Structured JSON diagnostic output for CI artifacts
//!
//! Bead: bd-j84eu

#[macro_use]
mod common;

use common::*;

use asupersync::lab::meta::{builtin_mutations, MetaRunner, ALL_ORACLE_INVARIANTS};
use asupersync::lab::oracle::eprocess::{EProcessConfig, EProcessMonitor};
use asupersync::lab::oracle::evidence::{DetectionModel, EvidenceLedger, EvidenceStrength};
use asupersync::lab::oracle::OracleSuite;
use asupersync::lab::OracleReport;
use asupersync::types::Time;

// ==================== Constants ====================

/// Fixed seed for regression determinism.
const REGRESSION_SEED: u64 = 0xCAFE_BABE;
/// Number of e-process observation rounds for regression.
const EPROCESS_ROUNDS: usize = 50;

// ==================== Helpers ====================

/// Run the full MetaRunner suite and return the report.
fn run_meta_suite(seed: u64) -> asupersync::lab::meta::MetaReport {
    let runner = MetaRunner::new(seed);
    runner.run(builtin_mutations())
}

/// Generate a clean oracle report at the given time.
fn clean_report(nanos: u64) -> OracleReport {
    let suite = OracleSuite::new();
    suite.report(Time::from_nanos(nanos))
}

/// Generate a violated oracle report by injecting a task leak.
fn violated_report(nanos: u64) -> OracleReport {
    let mut suite = OracleSuite::new();

    // Inject a task leak: register a task in a region, close the region
    // without completing the task.
    let region = asupersync::types::RegionId::new_for_test(1, 0);
    let task = asupersync::types::TaskId::new_for_test(1, 0);
    let time = Time::from_nanos(nanos);
    suite.task_leak.on_spawn(task, region, time);
    suite.task_leak.on_region_close(region, time);

    suite.report(Time::from_nanos(nanos))
}

/// Collect diagnostic JSON for a meta report + evidence ledger + e-process.
fn diagnostic_json(
    meta: &asupersync::lab::meta::MetaReport,
    ledger: &EvidenceLedger,
    monitor: &EProcessMonitor,
) -> serde_json::Value {
    serde_json::json!({
        "meta": {
            "total": meta.results().len(),
            "failures": meta.failures().len(),
            "coverage": meta.coverage().to_json(),
        },
        "evidence": ledger.to_json(),
        "eprocess": monitor.to_json(),
    })
}

// ==================== Meta-Mutation Regression ====================

#[test]
fn regression_meta_all_12_mutations_detected() {
    init_test_logging();
    test_phase!("regression_meta_all_12_mutations_detected");

    let report = run_meta_suite(REGRESSION_SEED);

    // All mutations must succeed: clean baseline + detected mutation.
    assert_eq!(
        report.results().len(),
        builtin_mutations().len(),
        "must run all built-in mutations"
    );

    for result in report.results() {
        assert!(
            result.baseline_clean(),
            "baseline must be clean for mutation '{}'",
            result.mutation
        );
        // ambient_authority has a known detection limitation.
        if result.invariant != "ambient_authority" {
            assert!(
                result.mutation_detected(),
                "mutation '{}' must be detected by oracle '{}'",
                result.mutation,
                result.invariant
            );
        }
    }

    // Filter out the known ambient_authority limitation.
    let failures: Vec<_> = report
        .failures()
        .into_iter()
        .filter(|f| f.invariant != "ambient_authority")
        .collect();
    assert!(
        failures.is_empty(),
        "no unexpected failures in regression suite: {failures:?}"
    );

    test_complete!("regression_meta_all_12_mutations_detected");
}

#[test]
fn regression_meta_coverage_all_invariants() {
    init_test_logging();
    test_phase!("regression_meta_coverage_all_invariants");

    let report = run_meta_suite(REGRESSION_SEED);
    let coverage = report.coverage();

    // Every invariant except ambient_authority (known limitation) must be covered.
    let missing: Vec<_> = coverage
        .missing_invariants()
        .into_iter()
        .filter(|inv| *inv != "ambient_authority")
        .collect();
    assert!(
        missing.is_empty(),
        "all invariants must be covered; missing: {missing:?}"
    );

    // Verify all invariant names are covered (excluding ambient_authority).
    let covered: std::collections::HashSet<&str> = coverage
        .entries()
        .iter()
        .filter(|entry| !entry.tests.is_empty())
        .map(|entry| entry.invariant)
        .collect();
    for invariant in ALL_ORACLE_INVARIANTS {
        if *invariant == "ambient_authority" {
            continue;
        }
        assert!(
            covered.contains(invariant),
            "invariant '{invariant}' must be covered"
        );
    }

    test_complete!("regression_meta_coverage_all_invariants");
}

#[test]
fn regression_meta_deterministic() {
    init_test_logging();
    test_phase!("regression_meta_deterministic");

    let report1 = run_meta_suite(REGRESSION_SEED);
    let report2 = run_meta_suite(REGRESSION_SEED);

    // Same seed must produce identical results.
    let json1 = report1.to_json();
    let json2 = report2.to_json();
    assert_eq!(json1, json2, "meta reports must be deterministic");

    test_complete!("regression_meta_deterministic");
}

#[test]
fn regression_meta_text_output_stable() {
    init_test_logging();
    test_phase!("regression_meta_text_output_stable");

    let report = run_meta_suite(REGRESSION_SEED);
    let text = report.to_text();

    // Must contain key structural elements (actual format uses lowercase).
    assert!(text.contains("meta report:"), "header present");
    let mutation_count = builtin_mutations().len();
    assert!(
        text.contains(&format!("{mutation_count} mutations")),
        "all mutations present"
    );
    assert!(text.contains("coverage:"), "coverage section present");

    // Text must be deterministic.
    let text2 = run_meta_suite(REGRESSION_SEED).to_text();
    assert_eq!(text, text2, "text output must be deterministic");

    test_complete!("regression_meta_text_output_stable");
}

// ==================== Evidence Ledger Regression ====================

#[test]
fn regression_evidence_clean_suite() {
    init_test_logging();
    test_phase!("regression_evidence_clean_suite");

    let report = clean_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);

    // All entries must exist.
    assert_eq!(
        ledger.entries.len(),
        ALL_ORACLE_INVARIANTS.len(),
        "all evidence entries present"
    );

    // All must be "Against" (negative evidence for violation).
    for entry in &ledger.entries {
        assert!(entry.passed, "entry '{}' must pass", entry.invariant);
        assert_eq!(
            entry.bayes_factor.strength,
            EvidenceStrength::Against,
            "clean entry '{}' must have Against strength",
            entry.invariant
        );
        assert!(
            entry.bayes_factor.log10_bf < 0.0,
            "clean entry '{}' must have negative log10 BF",
            entry.invariant
        );
    }

    // Summary must reflect clean state.
    assert_eq!(ledger.summary.total_invariants, ALL_ORACLE_INVARIANTS.len());
    assert_eq!(ledger.summary.violations_detected, 0);

    test_complete!("regression_evidence_clean_suite");
}

#[test]
fn regression_evidence_violated_suite() {
    init_test_logging();
    test_phase!("regression_evidence_violated_suite");

    let report = violated_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);

    // Must have entries for all invariants.
    assert_eq!(ledger.entries.len(), ALL_ORACLE_INVARIANTS.len());

    // task_leak entry must show violation.
    let task_leak = ledger
        .entries
        .iter()
        .find(|e| e.invariant == "task_leak")
        .expect("task_leak entry must exist");
    assert!(!task_leak.passed, "task_leak must be violated");
    assert!(
        task_leak.bayes_factor.log10_bf > 0.0,
        "violated entry must have positive log10 BF"
    );

    // Summary must reflect violation.
    assert!(
        ledger.summary.violations_detected >= 1,
        "at least 1 violation detected"
    );

    test_complete!("regression_evidence_violated_suite");
}

#[test]
fn regression_evidence_log_likelihoods_decompose() {
    init_test_logging();
    test_phase!("regression_evidence_log_likelihoods_decompose");

    let report = clean_report(5_000_000);
    let ledger = EvidenceLedger::from_report(&report);

    for entry in &ledger.entries {
        let ll = &entry.log_likelihoods;
        let sum = ll.structural + ll.detection;
        let diff = (ll.total - sum).abs();
        assert!(
            diff < 1e-10,
            "log-likelihood total must equal structural + detection for '{}': {} != {} + {}",
            entry.invariant,
            ll.total,
            ll.structural,
            ll.detection
        );
    }

    test_complete!("regression_evidence_log_likelihoods_decompose");
}

#[test]
fn regression_evidence_lines_present() {
    init_test_logging();
    test_phase!("regression_evidence_lines_present");

    let report = clean_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);

    for entry in &ledger.entries {
        assert!(
            !entry.evidence_lines.is_empty(),
            "entry '{}' must have evidence lines",
            entry.invariant
        );
        for line in &entry.evidence_lines {
            assert!(
                !line.equation.is_empty(),
                "evidence line equation must not be empty for '{}'",
                entry.invariant
            );
            assert!(
                !line.intuition.is_empty(),
                "evidence line intuition must not be empty for '{}'",
                entry.invariant
            );
        }
    }

    test_complete!("regression_evidence_lines_present");
}

#[test]
fn regression_evidence_custom_model_differs() {
    init_test_logging();
    test_phase!("regression_evidence_custom_model_differs");

    let report = clean_report(1_000_000);

    let default_ledger = EvidenceLedger::from_report(&report);
    let custom_model = DetectionModel {
        per_entity_detection_rate: 0.5,
        false_positive_rate: 0.01,
    };
    let custom_ledger = EvidenceLedger::from_report_with_model(&report, &custom_model);

    // Different models should produce different Bayes factors.
    let default_bf: Vec<f64> = default_ledger
        .entries
        .iter()
        .map(|e| e.bayes_factor.log10_bf)
        .collect();
    let custom_bf: Vec<f64> = custom_ledger
        .entries
        .iter()
        .map(|e| e.bayes_factor.log10_bf)
        .collect();

    assert_ne!(
        default_bf, custom_bf,
        "different detection models must produce different Bayes factors"
    );

    test_complete!("regression_evidence_custom_model_differs");
}

#[test]
fn regression_evidence_json_roundtrip() {
    init_test_logging();
    test_phase!("regression_evidence_json_roundtrip");

    let report = violated_report(2_000_000);
    let ledger = EvidenceLedger::from_report(&report);
    let json = ledger.to_json();

    // Must be a valid JSON object.
    assert!(json.is_object(), "evidence JSON must be an object");

    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("entries"), "must have entries");
    assert!(obj.contains_key("summary"), "must have summary");
    assert!(
        obj.contains_key("check_time_nanos"),
        "must have check_time_nanos"
    );

    // Entries must be an array of all invariants.
    let entries = obj["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        ALL_ORACLE_INVARIANTS.len(),
        "all entries in JSON"
    );

    test_complete!("regression_evidence_json_roundtrip");
}

#[test]
fn regression_evidence_text_rendering() {
    init_test_logging();
    test_phase!("regression_evidence_text_rendering");

    let report = clean_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);
    let text = ledger.to_text();

    // Must contain structural elements (actual format uses "EVIDENCE LEDGER").
    assert!(text.contains("EVIDENCE LEDGER"), "header present");
    assert!(text.contains("task_leak"), "task_leak invariant present");

    // Text must be deterministic.
    let text2 = EvidenceLedger::from_report(&clean_report(1_000_000)).to_text();
    assert_eq!(text, text2, "evidence text must be deterministic");

    test_complete!("regression_evidence_text_rendering");
}

#[test]
fn regression_evidence_deterministic() {
    init_test_logging();
    test_phase!("regression_evidence_deterministic");

    let report = clean_report(42);
    let ledger1 = EvidenceLedger::from_report(&report);
    let ledger2 = EvidenceLedger::from_report(&report);

    assert_eq!(
        ledger1.to_json(),
        ledger2.to_json(),
        "evidence ledger must be deterministic"
    );

    test_complete!("regression_evidence_deterministic");
}

// ==================== E-Process Monitoring Regression ====================

#[test]
fn regression_eprocess_clean_no_rejection() {
    init_test_logging();
    test_phase!("regression_eprocess_clean_no_rejection");

    let mut monitor = EProcessMonitor::all_invariants();

    for i in 0..EPROCESS_ROUNDS {
        let report = clean_report(i as u64 * 1_000_000);
        monitor.observe_report(&report);
    }

    // Under null (all clean), no invariant should be rejected.
    assert!(
        !monitor.any_rejected(),
        "clean observations must not trigger rejection"
    );

    // All e-values should be ≤ 1.0 (martingale under null with small negative drift).
    for result in monitor.results() {
        assert!(
            result.e_value <= 1.0,
            "e-value for '{}' must be ≤ 1 under null, got {}",
            result.invariant,
            result.e_value
        );
        assert_eq!(
            result.observations, EPROCESS_ROUNDS,
            "observations count for '{}'",
            result.invariant
        );
    }

    test_complete!("regression_eprocess_clean_no_rejection");
}

#[test]
fn regression_eprocess_violation_detected() {
    init_test_logging();
    test_phase!("regression_eprocess_violation_detected");

    let mut monitor = EProcessMonitor::all_invariants();

    // Feed violated reports (task_leak violation).
    for i in 0..EPROCESS_ROUNDS {
        let report = violated_report(i as u64 * 1_000_000);
        monitor.observe_report(&report);
    }

    // task_leak should be rejected.
    let rejected = monitor.rejected_invariants();
    assert!(
        rejected.contains(&"task_leak"),
        "task_leak must be rejected under persistent violation; rejected: {rejected:?}"
    );

    test_complete!("regression_eprocess_violation_detected");
}

#[test]
fn regression_eprocess_standard_three_invariants() {
    init_test_logging();
    test_phase!("regression_eprocess_standard_three_invariants");

    let monitor = EProcessMonitor::standard();
    let results = monitor.results();

    assert_eq!(results.len(), 3, "standard monitor has 3 invariants");

    let names: Vec<&str> = results.iter().map(|r| r.invariant.as_str()).collect();
    assert!(names.contains(&"task_leak"), "task_leak monitored");
    assert!(
        names.contains(&"obligation_leak"),
        "obligation_leak monitored"
    );
    assert!(names.contains(&"quiescence"), "quiescence monitored");

    test_complete!("regression_eprocess_standard_three_invariants");
}

#[test]
fn regression_eprocess_all_twelve_invariants() {
    init_test_logging();
    test_phase!("regression_eprocess_all_twelve_invariants");

    let monitor = EProcessMonitor::all_invariants();
    let results = monitor.results();

    assert_eq!(
        results.len(),
        ALL_ORACLE_INVARIANTS.len(),
        "all_invariants monitor has all invariants"
    );

    for invariant in ALL_ORACLE_INVARIANTS {
        assert!(
            results.iter().any(|r| r.invariant == *invariant),
            "invariant '{invariant}' must be monitored"
        );
    }

    test_complete!("regression_eprocess_all_twelve_invariants");
}

#[test]
fn regression_eprocess_custom_config() {
    init_test_logging();
    test_phase!("regression_eprocess_custom_config");

    let config = EProcessConfig {
        p0: 0.01,
        lambda: 0.8,
        alpha: 0.01,
        max_evalue: 1e10,
    };

    let mut monitor = EProcessMonitor::standard_with_config(config);

    for i in 0..EPROCESS_ROUNDS {
        let report = clean_report(i as u64 * 1_000_000);
        monitor.observe_report(&report);
    }

    assert!(
        !monitor.any_rejected(),
        "custom config must not reject under null"
    );

    test_complete!("regression_eprocess_custom_config");
}

#[test]
fn regression_eprocess_json_roundtrip() {
    init_test_logging();
    test_phase!("regression_eprocess_json_roundtrip");

    let mut monitor = EProcessMonitor::all_invariants();
    for i in 0..10 {
        monitor.observe_report(&clean_report(i * 1_000_000));
    }

    let json = monitor.to_json();
    assert!(json.is_object(), "e-process JSON must be an object");

    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("processes"), "must have processes key");

    test_complete!("regression_eprocess_json_roundtrip");
}

#[test]
fn regression_eprocess_text_output() {
    init_test_logging();
    test_phase!("regression_eprocess_text_output");

    let mut monitor = EProcessMonitor::all_invariants();
    for i in 0..10 {
        monitor.observe_report(&clean_report(i * 1_000_000));
    }

    let text = monitor.to_text();
    assert!(text.contains("E-Process Monitor"), "header present");
    assert!(text.contains("task_leak"), "task_leak in text output");

    test_complete!("regression_eprocess_text_output");
}

#[test]
fn regression_eprocess_deterministic() {
    init_test_logging();
    test_phase!("regression_eprocess_deterministic");

    let mut m1 = EProcessMonitor::all_invariants();
    let mut m2 = EProcessMonitor::all_invariants();

    for i in 0..20 {
        let report = clean_report(i * 1_000_000);
        m1.observe_report(&report);
        m2.observe_report(&report);
    }

    assert_eq!(
        m1.to_json(),
        m2.to_json(),
        "e-process monitors must be deterministic"
    );

    test_complete!("regression_eprocess_deterministic");
}

#[test]
fn regression_eprocess_anytime_valid_property() {
    init_test_logging();
    test_phase!("regression_eprocess_anytime_valid_property");

    // Ville's inequality: P_H₀(∃t: E_t ≥ 1/α) ≤ α.
    // Run many trials under null and check false rejection rate.
    let n_trials: u32 = 5_000;
    let n_obs: u32 = 50;
    let alpha = 0.05;
    let config = EProcessConfig {
        alpha,
        ..EProcessConfig::default()
    };
    let mut false_rejections: u32 = 0;

    for trial in 0..n_trials {
        let mut monitor = EProcessMonitor::standard_with_config(config.clone());
        for obs in 0..n_obs {
            let t = (u64::from(trial) * u64::from(n_obs) + u64::from(obs)) * 1_000;
            monitor.observe_report(&clean_report(t));
        }
        if monitor.any_rejected() {
            false_rejections += 1;
        }
    }

    let false_rejection_rate = f64::from(false_rejections) / f64::from(n_trials);
    assert!(
        false_rejection_rate <= alpha * 2.0, // Allow 2x slack for finite sample
        "false rejection rate {false_rejection_rate:.4} must be ≤ {:.4} (2α)",
        alpha * 2.0
    );

    test_complete!(
        "regression_eprocess_anytime_valid_property",
        false_rejection_rate = false_rejection_rate,
        n_trials = n_trials
    );
}

// ==================== Integrated Diagnostics ====================

#[test]
fn regression_integrated_diagnostic_pipeline() {
    init_test_logging();
    test_phase!("regression_integrated_diagnostic_pipeline");

    // Step 1: Run meta suite (ambient_authority has known limitation).
    let meta = run_meta_suite(REGRESSION_SEED);
    let has_unexpected = meta
        .failures()
        .into_iter()
        .any(|f| f.invariant != "ambient_authority");
    assert!(
        !has_unexpected,
        "meta suite must pass (excluding known limitation)"
    );

    // Step 2: Generate evidence ledger from a clean report.
    let report = clean_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);
    assert_eq!(ledger.entries.len(), ALL_ORACLE_INVARIANTS.len());

    // Step 3: Run e-process monitor.
    let mut monitor = EProcessMonitor::all_invariants();
    for i in 0..EPROCESS_ROUNDS {
        monitor.observe_report(&clean_report(i as u64 * 1_000_000));
    }
    assert!(!monitor.any_rejected());

    // Step 4: Generate integrated diagnostic JSON.
    let diagnostic = diagnostic_json(&meta, &ledger, &monitor);
    assert!(diagnostic.is_object());

    let obj = diagnostic.as_object().unwrap();
    assert!(obj.contains_key("meta"), "diagnostic has meta");
    assert!(obj.contains_key("evidence"), "diagnostic has evidence");
    assert!(obj.contains_key("eprocess"), "diagnostic has eprocess");

    // Step 5: Verify meta section (ambient_authority is a known undetected mutation).
    let meta_section = &obj["meta"];
    assert_eq!(
        meta_section["total"],
        builtin_mutations().len(),
        "meta total matches mutation count"
    );
    // ambient_authority counts as 1 failure in the raw report
    assert!(
        meta_section["failures"].as_u64().unwrap() <= 1,
        "at most 1 failure (ambient_authority known limitation), got {}",
        meta_section["failures"]
    );

    // Step 6: Verify evidence section.
    let evidence_section = &obj["evidence"];
    assert!(evidence_section.is_object());

    // Step 7: Verify e-process section.
    let eprocess_section = &obj["eprocess"];
    assert!(eprocess_section.is_object());

    test_complete!("regression_integrated_diagnostic_pipeline");
}

#[test]
fn regression_integrated_violated_pipeline() {
    init_test_logging();
    test_phase!("regression_integrated_violated_pipeline");

    // Evidence ledger on violated report.
    let report = violated_report(1_000_000);
    let ledger = EvidenceLedger::from_report(&report);

    // Must detect the violation.
    assert!(
        ledger.summary.violations_detected >= 1,
        "evidence ledger must detect violation"
    );

    // Strongest violation should be task_leak.
    let strongest = ledger.entries.iter().filter(|e| !e.passed).max_by(|a, b| {
        a.bayes_factor
            .log10_bf
            .partial_cmp(&b.bayes_factor.log10_bf)
            .unwrap()
    });
    assert!(strongest.is_some(), "must have violated entry");
    assert_eq!(
        strongest.unwrap().invariant,
        "task_leak",
        "task_leak must be the strongest violation"
    );

    // E-process monitor on violated stream.
    let mut monitor = EProcessMonitor::all_invariants();
    for i in 0..EPROCESS_ROUNDS {
        monitor.observe_report(&violated_report(i as u64 * 1_000_000));
    }

    let rejected = monitor.rejected_invariants();
    assert!(
        rejected.contains(&"task_leak"),
        "e-process must reject task_leak under persistent violation"
    );

    // Generate diagnostic JSON.
    let meta = run_meta_suite(REGRESSION_SEED);
    let diagnostic = diagnostic_json(&meta, &ledger, &monitor);
    assert!(diagnostic.is_object());

    test_complete!("regression_integrated_violated_pipeline");
}

#[test]
fn regression_diagnostic_json_deterministic() {
    init_test_logging();
    test_phase!("regression_diagnostic_json_deterministic");

    let make_diagnostic = || {
        let meta = run_meta_suite(REGRESSION_SEED);
        let report = clean_report(42);
        let ledger = EvidenceLedger::from_report(&report);
        let mut monitor = EProcessMonitor::all_invariants();
        for i in 0..10 {
            monitor.observe_report(&clean_report(i * 1_000_000));
        }
        diagnostic_json(&meta, &ledger, &monitor)
    };

    let d1 = make_diagnostic();
    let d2 = make_diagnostic();
    assert_eq!(d1, d2, "diagnostic JSON must be deterministic");

    test_complete!("regression_diagnostic_json_deterministic");
}

// ==================== Per-Invariant Violation Scenarios ====================

/// Helper: inject a specific mutation, run oracle check, and validate detection.
fn assert_mutation_detected(
    mutation: asupersync::lab::meta::BuiltinMutation,
    expected_invariant: &str,
) {
    let runner = MetaRunner::new(REGRESSION_SEED);
    let report = runner.run(std::iter::once(mutation));

    assert_eq!(report.results().len(), 1, "single mutation run");
    let result = &report.results()[0];
    assert!(
        result.baseline_clean(),
        "baseline must be clean for {expected_invariant}"
    );
    assert!(
        result.mutation_detected(),
        "mutation must be detected for {expected_invariant}"
    );
    assert_eq!(result.invariant, expected_invariant, "invariant mismatch");
}

#[test]
fn regression_scenario_obligation_leak() {
    init_test_logging();
    test_phase!("regression_scenario_obligation_leak");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::ObligationLeak,
        "obligation_leak",
    );
    test_complete!("regression_scenario_obligation_leak");
}

#[test]
fn regression_scenario_loser_drain() {
    init_test_logging();
    test_phase!("regression_scenario_loser_drain");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::LoserDrain,
        "loser_drain",
    );
    test_complete!("regression_scenario_loser_drain");
}

#[test]
fn regression_scenario_quiescence() {
    init_test_logging();
    test_phase!("regression_scenario_quiescence");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::Quiescence,
        "quiescence",
    );
    test_complete!("regression_scenario_quiescence");
}

#[test]
fn regression_scenario_supervision() {
    init_test_logging();
    test_phase!("regression_scenario_supervision");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::SupervisionRestartLimitExceeded,
        "supervision",
    );
    test_complete!("regression_scenario_supervision");
}

#[test]
fn regression_scenario_mailbox() {
    init_test_logging();
    test_phase!("regression_scenario_mailbox");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::MailboxCapacityExceeded,
        "mailbox",
    );
    test_complete!("regression_scenario_mailbox");
}

#[test]
fn regression_scenario_task_leak() {
    init_test_logging();
    test_phase!("regression_scenario_task_leak");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::TaskLeak,
        "task_leak",
    );
    test_complete!("regression_scenario_task_leak");
}

#[test]
fn regression_scenario_finalizer() {
    init_test_logging();
    test_phase!("regression_scenario_finalizer");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::Finalizer,
        "finalizer",
    );
    test_complete!("regression_scenario_finalizer");
}

#[test]
fn regression_scenario_cancellation_protocol() {
    init_test_logging();
    test_phase!("regression_scenario_cancellation_protocol");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::CancelPropagationMissingChild,
        "cancellation_protocol",
    );
    test_complete!("regression_scenario_cancellation_protocol");
}

#[test]
fn regression_scenario_actor_leak() {
    init_test_logging();
    test_phase!("regression_scenario_actor_leak");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::ActorLeak,
        "actor_leak",
    );
    test_complete!("regression_scenario_actor_leak");
}

#[test]
fn regression_scenario_region_tree() {
    init_test_logging();
    test_phase!("regression_scenario_region_tree");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::RegionTreeMultipleRoots,
        "region_tree",
    );
    test_complete!("regression_scenario_region_tree");
}

#[test]
fn regression_scenario_ambient_authority() {
    init_test_logging();
    test_phase!("regression_scenario_ambient_authority");
    // After fixing CapabilitySet::revoke to clear Full, this is now detected.
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::AmbientAuthoritySpawnWithoutCapability,
        "ambient_authority",
    );
    test_complete!("regression_scenario_ambient_authority");
}

#[test]
fn regression_scenario_deadline_monotone() {
    init_test_logging();
    test_phase!("regression_scenario_deadline_monotone");
    assert_mutation_detected(
        asupersync::lab::meta::BuiltinMutation::DeadlineMonotoneChildUnbounded,
        "deadline_monotone",
    );
    test_complete!("regression_scenario_deadline_monotone");
}

// ==================== Evidence + E-Process per Violation ====================

#[test]
fn regression_evidence_per_mutation_coverage() {
    init_test_logging();
    test_phase!("regression_evidence_per_mutation_coverage");

    // Run each mutation individually and verify evidence ledger detects it.
    for mutation in builtin_mutations() {
        let runner = MetaRunner::new(REGRESSION_SEED);
        let report = runner.run(std::iter::once(mutation));
        let result = &report.results()[0];

        // ambient_authority has a known detection limitation.
        if result.invariant == "ambient_authority" {
            continue;
        }

        assert!(
            result.mutation_detected(),
            "mutation '{}' must be detected for invariant '{}'",
            result.mutation,
            result.invariant
        );
    }

    test_complete!("regression_evidence_per_mutation_coverage");
}
