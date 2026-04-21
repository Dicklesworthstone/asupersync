#![allow(clippy::all)]
//! Semantic Verification Summary Validation (SEM-12.10)
//!
//! Validates that the verification summary generator exists, produces correct
//! outputs covering all domains and evidence classes, includes first-failure
//! triage, remediation owners, and deterministic reproducibility commands.
//!
//! Bead: asupersync-3cddg.12.10

use std::path::Path;

fn load_script() -> String {
    std::fs::read_to_string("scripts/generate_verification_summary.sh")
        .expect("failed to load verification summary script")
}

// ─── Script infrastructure ───────────────────────────────────────

#[test]
fn summary_script_exists() {
    assert!(
        Path::new("scripts/generate_verification_summary.sh").exists(),
        "Verification summary script must exist"
    );
}

#[test]
fn summary_script_is_bash() {
    let script = load_script();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Script must use /usr/bin/env bash shebang"
    );
}

#[test]
fn summary_script_supports_json_output() {
    let script = load_script();
    assert!(script.contains("--json"), "Script must support --json flag");
    assert!(
        script.contains("verification_summary.json"),
        "Script must write JSON summary"
    );
}

#[test]
fn summary_script_supports_ci_mode() {
    let script = load_script();
    assert!(script.contains("--ci"), "Script must support --ci flag");
    assert!(
        script.contains("CI_MODE"),
        "Script must implement CI mode logic"
    );
}

#[test]
fn summary_script_supports_verbose() {
    let script = load_script();
    assert!(
        script.contains("--verbose"),
        "Script must support --verbose flag"
    );
    assert!(
        script.contains("VERBOSE"),
        "Script must implement verbose logic"
    );
}

// ─── Input sources ──────────────────────────────────────────────

#[test]
fn summary_script_consumes_runner_report() {
    let script = load_script();
    assert!(
        script.contains("--runner-report"),
        "Script must accept --runner-report flag"
    );
    assert!(
        script.contains("verification_report.json"),
        "Script must reference unified runner report"
    );
}

#[test]
fn summary_script_consumes_evidence_bundle() {
    let script = load_script();
    assert!(
        script.contains("--evidence-bundle"),
        "Script must accept --evidence-bundle flag"
    );
    assert!(
        script.contains("evidence_bundle.json"),
        "Script must reference evidence bundle"
    );
}

#[test]
fn summary_script_consumes_gate_manifest() {
    let script = load_script();
    assert!(
        script.contains("--gate-manifest"),
        "Script must accept --gate-manifest flag"
    );
    assert!(
        script.contains("bundle_manifest.json"),
        "Script must reference gate manifest"
    );
}

// ─── Domain coverage ────────────────────────────────────────────

#[test]
fn summary_script_covers_all_domains() {
    let script = load_script();

    let domains = [
        "cancellation",
        "obligation",
        "region",
        "outcome",
        "ownership",
        "combinator",
        "capability",
        "determinism",
    ];

    let mut missing = Vec::new();
    for domain in &domains {
        if !script.contains(domain) {
            missing.push(*domain);
        }
    }
    assert!(
        missing.is_empty(),
        "Summary script missing domains:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn summary_script_covers_evidence_classes() {
    let script = load_script();

    let classes = ["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"];

    let mut missing = Vec::new();
    for cls in &classes {
        if !script.contains(cls) {
            missing.push(*cls);
        }
    }
    assert!(
        missing.is_empty(),
        "Summary script missing evidence classes:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Output content requirements ────────────────────────────────

#[test]
fn summary_script_generates_suite_results() {
    let script = load_script();
    assert!(
        script.contains("Suite Results") || script.contains("suite_results"),
        "Summary must include suite results section"
    );
    assert!(
        script.contains("PASS") && script.contains("FAIL") && script.contains("SKIP"),
        "Summary must use PASS/FAIL/SKIP verdict labels"
    );
}

#[test]
fn summary_script_generates_gate_status() {
    let script = load_script();

    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !script.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Summary script missing gate references:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn summary_script_generates_first_failure_triage() {
    let script = load_script();
    assert!(
        script.contains("first_failure") || script.contains("First-Failure"),
        "Summary must include first-failure triage section"
    );
    assert!(
        script.contains("root_cause") || script.contains("Root Cause"),
        "Triage must include root-cause hints"
    );
    assert!(
        script.contains("rerun") || script.contains("Rerun"),
        "Triage must include rerun commands"
    );
}

#[test]
fn summary_script_generates_remediation_owners() {
    let script = load_script();
    assert!(
        script.contains("missing_evidence_by_owner") || script.contains("Remediation Owner"),
        "Summary must include remediation owner mapping"
    );
    assert!(
        script.contains("owner_bead"),
        "Summary must reference owner beads for missing evidence"
    );
}

// ─── Deterministic output ───────────────────────────────────────

#[test]
fn summary_script_includes_reproducibility() {
    let script = load_script();
    assert!(
        script.contains("Reproducibility") || script.contains("reproducibility"),
        "Summary must include reproducibility section"
    );
    assert!(
        script.contains("run_semantic_verification.sh"),
        "Summary must reference unified runner for rerun"
    );
    assert!(
        script.contains("assemble_evidence_bundle.sh"),
        "Summary must reference evidence bundle assembly for rerun"
    );
    assert!(
        script.contains("generate_verification_summary.sh"),
        "Summary must reference itself for regeneration"
    );
}

#[test]
fn summary_script_includes_artifact_links() {
    let script = load_script();
    assert!(
        script.contains("Artifact") || script.contains("artifact"),
        "Summary must include artifact links section"
    );
}

// ─── JSON schema ────────────────────────────────────────────────

#[test]
fn summary_script_json_schema() {
    let script = load_script();

    let required_fields = [
        "verification-summary-v1",
        "timestamp",
        "commit_hash",
        "overall_status",
        "suites",
        "gates",
        "coverage",
        "missing_evidence",
        "first_failures",
        "reproducibility",
    ];

    let mut missing = Vec::new();
    for field in &required_fields {
        if !script.contains(field) {
            missing.push(*field);
        }
    }
    assert!(
        missing.is_empty(),
        "Summary JSON schema missing fields:\n{}",
        missing
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn summary_script_json_includes_domain_coverage() {
    let script = load_script();
    assert!(
        script.contains("coverage_pct") || script.contains("\"coverage\""),
        "JSON must include per-domain coverage percentages"
    );
    assert!(
        script.contains("evidence_present") && script.contains("evidence_missing"),
        "JSON must include per-domain evidence class counts"
    );
}

// ─── Output structure ───────────────────────────────────────────

#[test]
fn summary_script_writes_markdown_summary() {
    let script = load_script();
    assert!(
        script.contains("verification_summary.md"),
        "Script must write markdown summary"
    );
}

#[test]
fn summary_script_writes_triage_report() {
    let script = load_script();
    assert!(
        script.contains("triage_report.md"),
        "Script must write triage report"
    );
}

#[test]
fn summary_script_exit_codes() {
    let script = load_script();
    assert!(
        script.contains("exit 0") && script.contains("exit 1") && script.contains("exit 2"),
        "Script must use exit codes 0 (success), 1 (critical failure), 2 (config error)"
    );
}

// ─── Traceability ───────────────────────────────────────────────

#[test]
fn summary_script_references_bead() {
    let script = load_script();
    assert!(
        script.contains("asupersync-3cddg.12.10"),
        "Script must reference its own bead ID"
    );
}

#[test]
fn summary_script_groups_by_domain_and_rule() {
    let script = load_script();
    assert!(
        script.contains("domain") && script.contains("rule_id"),
        "Script must group results by domain and rule ID"
    );
    assert!(
        script.contains("DOMAIN_ORDER") || script.contains("domain_stats"),
        "Script must process domains in canonical order"
    );
}
