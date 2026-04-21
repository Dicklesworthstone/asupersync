#![allow(warnings)]
#![allow(clippy::all)]
//! Unified Semantic Verification Runner Validation (SEM-12.9)
//!
//! Validates that the unified runner script exists, supports all required
//! profiles and suites, and references all verification components.
//!
//! Bead: asupersync-3cddg.12.9

use std::path::Path;

fn load_runner() -> String {
    std::fs::read_to_string("scripts/run_semantic_verification.sh")
        .expect("failed to load unified runner script")
}

// ─── Script infrastructure ───────────────────────────────────────

#[test]
fn unified_runner_exists() {
    assert!(
        Path::new("scripts/run_semantic_verification.sh").exists(),
        "Unified semantic verification runner must exist"
    );
}

#[test]
fn unified_runner_is_bash() {
    let script = load_runner();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Runner must use /usr/bin/env bash shebang"
    );
}

// ─── Profile support ─────────────────────────────────────────────

#[test]
fn unified_runner_supports_profiles() {
    let script = load_runner();

    let profiles = ["smoke", "full", "forensics"];
    for profile in &profiles {
        assert!(
            script.contains(profile),
            "Runner must support profile: {profile}"
        );
    }
}

#[test]
fn unified_runner_supports_ci_mode() {
    let script = load_runner();

    assert!(script.contains("--ci"), "Runner must support --ci flag");
    assert!(
        script.contains("CI_MODE"),
        "Runner must implement CI mode logic"
    );
}

#[test]
fn unified_runner_supports_json() {
    let script = load_runner();

    assert!(script.contains("--json"), "Runner must support --json flag");
    assert!(
        script.contains("verification_report.json"),
        "Runner must write JSON verification report"
    );
}

// ─── Suite orchestration ─────────────────────────────────────────

#[test]
fn unified_runner_includes_all_suites() {
    let script = load_runner();

    // Must reference all verification test suites
    let suites = [
        "semantic_docs_lint",
        "semantic_docs_rule_mapping_lint",
        "semantic_golden_fixture_validation",
        "semantic_lean_regression",
        "semantic_tla_scenarios",
        "semantic_log_schema_validation",
        "semantic_witness_replay_e2e",
        "run_lean_regression.sh",
        "run_tla_scenarios.sh",
    ];

    let mut missing = Vec::new();
    for suite in &suites {
        if !script.contains(suite) {
            missing.push(*suite);
        }
    }

    assert!(
        missing.is_empty(),
        "Runner missing suite references:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn unified_runner_supports_suite_filter() {
    let script = load_runner();

    assert!(
        script.contains("--suite"),
        "Runner must support --suite filter flag"
    );

    let filter_options = ["docs", "runtime", "golden", "lean", "tla", "logging"];
    for option in &filter_options {
        assert!(
            script.contains(option),
            "Runner must support suite filter: {option}"
        );
    }
}

// ─── Report schema ──────────────────────────────────────────────

#[test]
fn unified_runner_report_schema() {
    let script = load_runner();

    let required_fields = [
        "semantic-verification-report-v1",
        "profile",
        "ci_mode",
        "suites_total",
        "suites_passed",
        "suites_failed",
        "suites_skipped",
        "overall_status",
        "results",
        "quality_gates",
        "semantic_coverage_logging_gate",
        "profile_contract",
        "runtime_budget_s",
        "budget_status",
        "suite_inclusion",
        "suite_skipped",
        "required_artifacts",
        "required_log_outputs",
        "global_thresholds",
        "domain_thresholds",
        "failures",
    ];

    let mut missing = Vec::new();
    for field in &required_fields {
        if !script.contains(field) {
            missing.push(*field);
        }
    }

    assert!(
        missing.is_empty(),
        "Runner report schema missing fields:\n{}",
        missing
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn unified_runner_declares_profile_budgets_and_skip_logging() {
    let script = load_runner();

    assert!(
        script.contains("PROFILE_RUNTIME_BUDGET_S"),
        "Runner must declare runtime budget per profile"
    );
    assert!(
        script.contains("Profile selected:"),
        "Runner logs must declare selected profile"
    );
    assert!(
        script.contains("Skipped components:"),
        "Runner logs must declare skipped components"
    );
    assert!(
        script.contains("coverage_gate"),
        "Profile component matrix must include coverage_gate component"
    );
}

// ─── Exit code semantics ─────────────────────────────────────────

#[test]
fn unified_runner_distinguishes_required_optional() {
    let script = load_runner();

    // Runner must distinguish required vs optional suites
    assert!(
        script.contains("required"),
        "Runner must track required vs optional suites"
    );
    assert!(
        script.contains("REQUIRED_FAILURES") || script.contains("required_failures"),
        "Runner must count required failures separately in CI mode"
    );
}

#[test]
fn unified_runner_sem_12_14_gate_present() {
    let script = load_runner();

    assert!(
        script.contains("SEM-12.14"),
        "Runner must reference SEM-12.14 gate ownership"
    );
    assert!(
        script.contains("coverage_gate"),
        "Runner must emit a coverage_gate result row"
    );
    assert!(
        script.contains("semantic_verification_matrix.md"),
        "Runner must consume semantic matrix coverage inputs"
    );
    assert!(
        script.contains("semantic_verification_log_schema.md"),
        "Runner must consume logging schema coverage inputs"
    );
}

#[test]
fn unified_runner_exit_codes() {
    let script = load_runner();

    // Must document exit codes
    assert!(
        script.contains("exit 0") && script.contains("exit 1") && script.contains("exit 2"),
        "Runner must use exit codes 0 (success), 1 (failure), 2 (config error)"
    );
}

// ─── Artifact management ─────────────────────────────────────────

#[test]
fn unified_runner_saves_suite_output() {
    let script = load_runner();

    assert!(
        script.contains("_output.txt"),
        "Runner must save individual suite output to files"
    );
    assert!(
        script.contains("target/semantic-verification"),
        "Runner must write artifacts to target/semantic-verification/"
    );
}
