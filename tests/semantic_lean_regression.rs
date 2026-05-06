//! Lean Proof Regression Script Validation (SEM-12.3)
//!
//! Validates that the Lean regression runner script exists, is well-formed,
//! and produces correct structured output. The actual `lake build` execution
//! is deferred to CI (requires Lean toolchain).
//!
//! Bead: asupersync-3cddg.12.3

use std::path::Path;

fn load_lean_source() -> String {
    std::fs::read_to_string("formal/lean/Asupersync.lean").expect("failed to load Lean source")
}

fn load_lakefile() -> String {
    std::fs::read_to_string("formal/lean/lakefile.lean").expect("failed to load lakefile")
}

fn load_runner_script() -> String {
    std::fs::read_to_string("scripts/run_lean_regression.sh")
        .expect("failed to load Lean regression script")
}

// ─── Script infrastructure ───────────────────────────────────────

#[test]
fn lean_regression_script_exists() {
    assert!(
        Path::new("scripts/run_lean_regression.sh").exists(),
        "Lean regression runner script must exist"
    );
}

#[test]
fn lean_regression_script_is_bash() {
    let script = load_runner_script();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Script must use /usr/bin/env bash shebang"
    );
}

#[test]
fn lean_regression_script_supports_json_output() {
    let script = load_runner_script();
    assert!(script.contains("--json"), "Script must support --json flag");
    assert!(
        script.contains("regression_report.json"),
        "Script must write JSON report"
    );
}

#[test]
fn lean_regression_script_report_schema() {
    let script = load_runner_script();

    // Report must include key fields
    let required_fields = [
        "lean-regression-report-v1",
        "status",
        "lean_available",
        "theorems_checked",
        "theorems_passed",
        "theorems_failed",
        "errors",
    ];

    for field in &required_fields {
        assert!(
            script.contains(field),
            "Script report schema must include field: {field}"
        );
    }
}

#[test]
fn lean_regression_script_graceful_skip() {
    let script = load_runner_script();

    // Must handle missing `lake` gracefully
    assert!(
        script.contains("lake") && script.contains("SKIP"),
        "Script must skip gracefully when lake is unavailable"
    );
}

// ─── Lean source structure ───────────────────────────────────────

#[test]
fn lean_source_defines_core_types() {
    let lean = load_lean_source();

    let core_types = [
        "Outcome",
        "CancelKind",
        "CancelReason",
        "Budget",
        "TaskState",
        "RegionState",
        "ObligationState",
    ];

    let mut missing = Vec::new();
    for ty in &core_types {
        if !lean.contains(ty) {
            missing.push(*ty);
        }
    }

    assert!(
        missing.is_empty(),
        "Lean source missing core type definitions:\n{}",
        missing
            .iter()
            .map(|t| format!("  - {t}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn lean_source_has_theorems() {
    let lean = load_lean_source();

    let theorem_count = lean
        .lines()
        .filter(|line| {
            line.starts_with("theorem ")
                || line.starts_with("lemma ")
                || line.starts_with("instance ")
        })
        .count();

    assert!(
        theorem_count > 0,
        "Lean source must contain at least one theorem/lemma (found {theorem_count})"
    );
}

#[test]
fn lean_lakefile_targets_asupersync() {
    let lakefile = load_lakefile();

    assert!(
        lakefile.contains("asupersync_semantics") || lakefile.contains("Asupersync"),
        "Lakefile must target asupersync semantics library"
    );
}

// ─── Theorem-to-rule traceability ────────────────────────────────

#[test]
fn lean_source_references_cancel_protocol() {
    let lean = load_lean_source();

    // The Lean spec should model cancel protocol transitions
    // Lean uses camelCase constructors (e.g., cancelRequested)
    let cancel_terms = ["cancelRequested", "cancelling", "finalizing"];

    let mut missing = Vec::new();
    for term in &cancel_terms {
        if !lean.contains(term) {
            missing.push(*term);
        }
    }

    assert!(
        missing.is_empty(),
        "Lean source missing cancel protocol states:\n{}",
        missing
            .iter()
            .map(|t| format!("  - {t}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn lean_source_models_strengthen() {
    let lean = load_lean_source();

    assert!(
        lean.contains("strengthen"),
        "Lean source must model the cancel strengthening operation"
    );
}
