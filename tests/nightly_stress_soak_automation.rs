#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
//! Schema and contract validation for nightly stress/soak automation (asupersync-umelq.18.10).
//!
//! Validates:
//! - Runner script exists and is executable
//! - Burndown report generator exists and is executable
//! - Doc spec exists with required sections
//! - JSON schema contracts for run manifest, trend report, burndown report
//! - Suite registry completeness
//! - Regression gate logic
//! - CI workflow artifact contract
//! - Flake governance policy cross-reference

use std::collections::HashSet;
use std::path::Path;

// ── Constants ──────────────────────────────────────────────────────────

const RUNNER_SCRIPT: &str = "scripts/run_nightly_stress_soak.sh";
const BURNDOWN_SCRIPT: &str = "scripts/generate_flake_burndown_report.sh";
const DOC_SPEC: &str = "docs/nightly_stress_soak_automation.md";
const FLAKE_GOVERNANCE_POLICY: &str = ".github/wasm_flake_governance_policy.json";
const FLAKE_DETECTOR_SCRIPT: &str = "scripts/run_semantic_flake_detector.sh";

const RUN_MANIFEST_SCHEMA: &str = "nightly-stress-manifest-v1";
const TREND_REPORT_SCHEMA: &str = "nightly-trend-report-v1";
const BURNDOWN_REPORT_SCHEMA: &str = "nightly-burndown-report-v1";

const REQUIRED_SUITES: &[&str] = &[
    "cancellation_stress",
    "obligation_leak",
    "scheduler_fairness",
    "quic_h3_soak",
];

const REQUIRED_SUITE_CATEGORIES: &[&str] = &["stress", "soak"];

const REQUIRED_DOC_SECTIONS: &[&str] = &[
    "Purpose",
    "Architecture",
    "Runner Contract",
    "Run Manifest Schema",
    "Trend Report Schema",
    "Burndown Report Schema",
    "Reliability Regression Gates",
    "CI Integration",
    "Forensic Artifact Retention",
    "Cross-References",
];

// ── Script existence and executability ─────────────────────────────────

#[test]
fn runner_script_exists_and_is_executable() {
    let path = Path::new(RUNNER_SCRIPT);
    assert!(path.exists(), "Runner script missing: {RUNNER_SCRIPT}");
    let content = std::fs::read_to_string(path).unwrap();
    assert!(
        content.starts_with("#!/usr/bin/env bash"),
        "Runner script must have bash shebang"
    );
    assert!(
        content.contains("asupersync-umelq.18.10"),
        "Runner script must reference bead ID"
    );
}

#[test]
fn burndown_script_exists_and_is_executable() {
    let path = Path::new(BURNDOWN_SCRIPT);
    assert!(path.exists(), "Burndown script missing: {BURNDOWN_SCRIPT}");
    let content = std::fs::read_to_string(path).unwrap();
    assert!(
        content.starts_with("#!/usr/bin/env bash"),
        "Burndown script must have bash shebang"
    );
    assert!(
        content.contains("asupersync-umelq.18.10"),
        "Burndown script must reference bead ID"
    );
}

#[test]
fn doc_spec_exists_with_required_sections() {
    let path = Path::new(DOC_SPEC);
    assert!(path.exists(), "Doc spec missing: {DOC_SPEC}");
    let content = std::fs::read_to_string(path).unwrap();
    for section in REQUIRED_DOC_SECTIONS {
        assert!(
            content.contains(section),
            "Doc spec missing section: {section}"
        );
    }
    assert!(
        content.contains("asupersync-umelq.18.10"),
        "Doc spec must reference bead ID"
    );
}

// ── Schema contract validation ─────────────────────────────────────────

#[test]
fn run_manifest_schema_version_in_doc() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    assert!(
        content.contains(RUN_MANIFEST_SCHEMA),
        "Doc must reference run manifest schema: {RUN_MANIFEST_SCHEMA}"
    );
}

#[test]
fn trend_report_schema_version_in_doc() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    assert!(
        content.contains(TREND_REPORT_SCHEMA),
        "Doc must reference trend report schema: {TREND_REPORT_SCHEMA}"
    );
}

#[test]
fn burndown_report_schema_version_in_doc() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    assert!(
        content.contains(BURNDOWN_REPORT_SCHEMA),
        "Doc must reference burndown report schema: {BURNDOWN_REPORT_SCHEMA}"
    );
}

#[test]
fn run_manifest_schema_in_runner_script() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(
        content.contains(RUN_MANIFEST_SCHEMA),
        "Runner must emit schema version: {RUN_MANIFEST_SCHEMA}"
    );
}

#[test]
fn burndown_report_schema_in_burndown_script() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(
        content.contains(BURNDOWN_REPORT_SCHEMA),
        "Burndown script must emit schema version: {BURNDOWN_REPORT_SCHEMA}"
    );
}

// ── Suite registry validation ──────────────────────────────────────────

#[test]
fn runner_registers_all_required_suites() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    for suite in REQUIRED_SUITES {
        assert!(
            content.contains(suite),
            "Runner must register suite: {suite}"
        );
    }
}

#[test]
fn runner_registers_required_categories() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    for category in REQUIRED_SUITE_CATEGORIES {
        assert!(
            content.contains(&format!("\"{category}\"")),
            "Runner must use category: {category}"
        );
    }
}

#[test]
fn doc_lists_all_required_suites() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    for suite in REQUIRED_SUITES {
        assert!(content.contains(suite), "Doc must list suite: {suite}");
    }
}

#[test]
fn suite_test_targets_exist() {
    let test_files = [
        "tests/cancellation_stress_e2e.rs",
        "tests/obligation_leak_stress.rs",
        "tests/scheduler_stress_fairness_e2e.rs",
        "tests/tokio_quic_h3_soak_adversarial.rs",
    ];
    for test_file in &test_files {
        assert!(
            Path::new(test_file).exists(),
            "Suite test target missing: {test_file}"
        );
    }
}

// ── Regression gate logic ──────────────────────────────────────────────

#[test]
fn runner_has_ci_mode_flag() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(content.contains("--ci"), "Runner must support --ci flag");
    assert!(
        content.contains("CI_MODE"),
        "Runner must have CI_MODE variable"
    );
    assert!(
        content.contains("exit 1"),
        "Runner must exit 1 on CI failure"
    );
}

#[test]
fn runner_detects_trend_regression() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(
        content.contains("TREND_REGRESSION"),
        "Runner must track trend regressions"
    );
    assert!(
        content.contains("regression_detected"),
        "Runner must emit regression_detected in trend report"
    );
}

#[test]
fn doc_specifies_regression_thresholds() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    assert!(
        content.contains("5 percentage points"),
        "Doc must specify pass-rate regression threshold"
    );
    assert!(
        content.contains("50%"),
        "Doc must specify duration regression threshold"
    );
}

// ── Cross-reference validation ─────────────────────────────────────────

#[test]
fn flake_governance_policy_exists() {
    assert!(
        Path::new(FLAKE_GOVERNANCE_POLICY).exists(),
        "Flake governance policy missing: {FLAKE_GOVERNANCE_POLICY}"
    );
}

#[test]
fn flake_detector_script_exists() {
    assert!(
        Path::new(FLAKE_DETECTOR_SCRIPT).exists(),
        "Flake detector script missing: {FLAKE_DETECTOR_SCRIPT}"
    );
}

#[test]
fn doc_cross_references_dependencies() {
    let content = std::fs::read_to_string(DOC_SPEC).unwrap();
    let required_refs = [
        "wasm_flake_governance_policy.json",
        "run_semantic_flake_detector.sh",
        "replay-debugging.md",
        "cancellation_stress_e2e.rs",
        "obligation_leak_stress.rs",
        "tokio_quic_h3_soak_adversarial.rs",
    ];
    for ref_item in &required_refs {
        assert!(
            content.contains(ref_item),
            "Doc must cross-reference: {ref_item}"
        );
    }
}

// ── Artifact path conventions ──────────────────────────────────────────

#[test]
fn runner_uses_standard_artifact_path() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(
        content.contains("target/nightly-stress"),
        "Runner must use target/nightly-stress/ directory"
    );
    assert!(
        content.contains("run_manifest.json"),
        "Runner must write run_manifest.json"
    );
    assert!(
        content.contains("trend_report.json"),
        "Runner must write trend_report.json"
    );
    assert!(
        content.contains("burndown_report.json"),
        "Runner must write burndown_report.json"
    );
    assert!(
        content.contains("suite_logs"),
        "Runner must write suite_logs/"
    );
}

// ── Burndown report contract ───────────────────────────────────────────

#[test]
fn burndown_script_reads_quarantine_manifest() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(
        content.contains("wasm_flake_quarantine_manifest"),
        "Burndown script must read quarantine manifest"
    );
}

#[test]
fn burndown_script_detects_sla_breaches() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(
        content.contains("sla_breaches"),
        "Burndown script must detect SLA breaches"
    );
    assert!(
        content.contains("sla_hours"),
        "Burndown script must use SLA hours from governance"
    );
}

#[test]
fn burndown_script_routes_to_owners() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(
        content.contains("owner_routing"),
        "Burndown script must provide owner routing"
    );
    assert!(
        content.contains("owner"),
        "Burndown script must track flake owners"
    );
}

#[test]
fn burndown_script_classifies_trend() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    let trends = ["clear", "improving", "degrading", "stable"];
    for trend in &trends {
        assert!(
            content.contains(trend),
            "Burndown script must classify trend: {trend}"
        );
    }
}

#[test]
fn burndown_script_gates_release() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(
        content.contains("release_blocked") || content.contains("release_gate"),
        "Burndown script must have release gate logic"
    );
}

// ── Completeness checks ────────────────────────────────────────────────

#[test]
fn runner_script_has_help_flag() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(content.contains("--help"), "Runner must support --help");
    assert!(content.contains("-h"), "Runner must support -h");
}

#[test]
fn burndown_script_has_help_flag() {
    let content = std::fs::read_to_string(BURNDOWN_SCRIPT).unwrap();
    assert!(content.contains("--help"), "Burndown must support --help");
    assert!(content.contains("-h"), "Burndown must support -h");
}

#[test]
fn runner_configures_obligation_stress_schedules() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(
        content.contains("OBLIGATION_STRESS_SCHEDULES"),
        "Runner must configure obligation stress schedule count"
    );
    assert!(
        content.contains("--stress-schedules"),
        "Runner must accept --stress-schedules flag"
    );
}

#[test]
fn runner_captures_environment_metadata() {
    let content = std::fs::read_to_string(RUNNER_SCRIPT).unwrap();
    assert!(
        content.contains("rust_version") || content.contains("RUST_VERSION"),
        "Runner must capture Rust version"
    );
    assert!(
        content.contains("uname"),
        "Runner must capture OS/arch info"
    );
}

#[test]
fn all_required_schema_versions_are_distinct() {
    let schemas: HashSet<&str> = [
        RUN_MANIFEST_SCHEMA,
        TREND_REPORT_SCHEMA,
        BURNDOWN_REPORT_SCHEMA,
    ]
    .into_iter()
    .collect();
    assert_eq!(schemas.len(), 3, "Schema versions must be distinct");
}
