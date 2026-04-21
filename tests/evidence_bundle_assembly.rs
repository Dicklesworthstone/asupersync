#![allow(warnings)]
#![allow(clippy::all)]
//! Evidence Bundle Assembly Validation (SEM-09.2)
//!
//! Validates that the evidence bundle assembly script exists, supports all
//! required gates and phases, produces structured JSON output, and references
//! all evidence artifacts from projection tracks.
//!
//! Bead: asupersync-3cddg.9.2

use std::path::Path;

fn load_bundle_script() -> String {
    std::fs::read_to_string("scripts/assemble_evidence_bundle.sh")
        .expect("failed to load evidence bundle assembly script")
}

// ─── Script infrastructure ───────────────────────────────────────

#[test]
fn bundle_script_exists() {
    assert!(
        Path::new("scripts/assemble_evidence_bundle.sh").exists(),
        "Evidence bundle assembly script must exist"
    );
}

#[test]
fn bundle_script_is_bash() {
    let script = load_bundle_script();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Script must use /usr/bin/env bash shebang"
    );
}

#[test]
fn bundle_script_supports_json_output() {
    let script = load_bundle_script();
    assert!(script.contains("--json"), "Script must support --json flag");
    assert!(
        script.contains("bundle_manifest.json"),
        "Script must write JSON bundle manifest"
    );
}

#[test]
fn bundle_script_supports_ci_mode() {
    let script = load_bundle_script();
    assert!(script.contains("--ci"), "Script must support --ci flag");
    assert!(
        script.contains("CI_MODE"),
        "Script must implement CI mode logic"
    );
}

// ─── Gate evaluation ─────────────────────────────────────────────

#[test]
fn bundle_script_evaluates_all_gates() {
    let script = load_bundle_script();

    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !script.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing gate evaluation:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_gate_domains() {
    let script = load_bundle_script();

    let gate_labels = [
        "Documentation Alignment",
        "LEAN Proof Coverage",
        "TLA+ Model Checking",
        "Runtime Conformance",
        "Property and Law Tests",
        "Cross-Artifact E2E",
        "Logging and Diagnostics",
    ];

    let mut missing = Vec::new();
    for label in &gate_labels {
        if !script.contains(label) {
            missing.push(*label);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing gate domain labels:\n{}",
        missing
            .iter()
            .map(|l| format!("  - {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_gate_verdicts() {
    let script = load_bundle_script();

    assert!(
        script.contains("PASS") && script.contains("FAIL"),
        "Script must use PASS/FAIL verdicts"
    );
    assert!(
        script.contains("GATE_VERDICT"),
        "Script must track gate verdicts"
    );
    assert!(
        script.contains("GATE_CHECKS_PASSED") && script.contains("GATE_CHECKS_TOTAL"),
        "Script must track per-gate check counts"
    );
}

// ─── Evidence artifact collection ────────────────────────────────

#[test]
fn bundle_script_collects_lean_evidence() {
    let script = load_bundle_script();

    let lean_artifacts = [
        "lean_coverage_matrix",
        "theorem_surface_inventory",
        "baseline_report",
        "Asupersync.lean",
    ];

    let mut missing = Vec::new();
    for artifact in &lean_artifacts {
        if !script.contains(artifact) {
            missing.push(*artifact);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing Lean evidence artifacts:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_collects_tla_evidence() {
    let script = load_bundle_script();

    let tla_artifacts = [
        "result.json",
        "Asupersync.tla",
        "Asupersync_MC.cfg",
        "model_check",
    ];

    let mut missing = Vec::new();
    for artifact in &tla_artifacts {
        if !script.contains(artifact) {
            missing.push(*artifact);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing TLA+ evidence artifacts:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_collects_docs_evidence() {
    let script = load_bundle_script();

    let docs = [
        "semantic_contract_schema.md",
        "semantic_contract_glossary.md",
        "semantic_contract_transitions.md",
        "semantic_contract_invariants.md",
        "semantic_docs_rule_mapping.md",
        "semantic_verification_matrix.md",
        "semantic_verification_log_schema.md",
    ];

    let mut missing = Vec::new();
    for doc in &docs {
        if !script.contains(doc) {
            missing.push(*doc);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing documentation evidence:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_references_unified_runner() {
    let script = load_bundle_script();

    assert!(
        script.contains("run_semantic_verification.sh"),
        "Script must invoke the unified semantic verification runner"
    );
    assert!(
        script.contains("verification_report.json"),
        "Script must collect verification report from unified runner"
    );
}

// ─── Cross-artifact conformance ──────────────────────────────────

#[test]
fn bundle_script_builds_conformance_matrix() {
    let script = load_bundle_script();

    assert!(
        script.contains("conformance_matrix"),
        "Script must build cross-artifact conformance matrix"
    );
    assert!(
        script.contains("conformance-matrix-v1"),
        "Conformance matrix must use versioned schema"
    );
}

#[test]
fn bundle_script_conformance_checks_all_layers() {
    let script = load_bundle_script();

    // Must check Lean, TLA+, and docs coverage per rule
    assert!(
        script.contains("lean_coverage")
            && script.contains("tla_coverage")
            && script.contains("docs_coverage"),
        "Conformance matrix must check Lean, TLA+, and docs coverage"
    );
}

// ─── Phase completion ────────────────────────────────────────────

#[test]
fn bundle_script_supports_phases() {
    let script = load_bundle_script();

    assert!(
        script.contains("--phase"),
        "Script must support --phase flag"
    );

    // Phase 1: G1 + G4 required
    assert!(
        script.contains("Phase 1") || script.contains("phase 1") || script.contains("PHASE=1"),
        "Script must support Phase 1"
    );

    // Phase 2: All gates required
    assert!(
        script.contains("Phase 2")
            || script.contains("phase 2")
            || (script.contains("2)") && script.contains("PHASE")),
        "Script must support Phase 2"
    );
}

#[test]
fn bundle_script_phase_gate_requirements() {
    let script = load_bundle_script();

    // Phase 1 requires G1 and G4
    assert!(
        script.contains("REQUIRED_GATES") || script.contains("required_gates"),
        "Script must define required gates per phase"
    );
    assert!(
        script.contains("OPTIONAL_GATES") || script.contains("optional_gates"),
        "Script must define optional gates per phase"
    );
}

// ─── Bundle manifest schema ──────────────────────────────────────

#[test]
fn bundle_manifest_schema() {
    let script = load_bundle_script();

    let required_fields = [
        "evidence-bundle-v1",
        "bead",
        "phase",
        "timestamp",
        "phase_verdict",
        "overall_verdict",
        "gates",
        "runner_status",
        "exceptions",
        "artifacts",
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
        "Bundle manifest missing required fields:\n{}",
        missing
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_manifest_includes_reproducibility() {
    let script = load_bundle_script();

    assert!(
        script.contains("rerun_command"),
        "Manifest must include rerun command for reproducibility"
    );
    assert!(
        script.contains("run_semantic_verification.sh")
            && script.contains("run_lean_regression.sh")
            && script.contains("run_tla_scenarios.sh"),
        "Manifest must reference all verification runner scripts"
    );
}

// ─── Output structure ────────────────────────────────────────────

#[test]
fn bundle_script_creates_directory_structure() {
    let script = load_bundle_script();

    let dirs = [
        "metadata",
        "lean",
        "tla",
        "runtime",
        "docs",
        "cross_artifact",
    ];
    let mut missing = Vec::new();
    for dir in &dirs {
        if !script.contains(dir) {
            missing.push(*dir);
        }
    }
    assert!(
        missing.is_empty(),
        "Bundle script missing output directories:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn bundle_script_exit_codes() {
    let script = load_bundle_script();

    assert!(
        script.contains("exit 0") && script.contains("exit 1") && script.contains("exit 2"),
        "Script must use exit codes 0 (success), 1 (gate failure), 2 (config error)"
    );
}

// ─── Skip runner support ─────────────────────────────────────────

#[test]
fn bundle_script_supports_skip_runner() {
    let script = load_bundle_script();

    assert!(
        script.contains("--skip-runner"),
        "Script must support --skip-runner flag for using cached results"
    );
    assert!(
        script.contains("SKIP_RUNNER"),
        "Script must implement skip-runner logic"
    );
}

// ─── Gap matrix integration ─────────────────────────────────────

#[test]
fn bundle_script_checks_gap_matrix() {
    let script = load_bundle_script();

    assert!(
        script.contains("semantic_runtime_gap_matrix"),
        "Script must check runtime gap matrix for G4"
    );
    assert!(
        script.contains("CODE-GAP") || script.contains("code_gaps"),
        "Script must check for CODE-GAPs"
    );
}
