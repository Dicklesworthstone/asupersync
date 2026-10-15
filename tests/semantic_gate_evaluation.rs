//! Semantic Gate Evaluation Report Validation (SEM-09.3)
//!
//! Validates that the gate evaluation report exists, covers all gates,
//! includes rerun instructions, and references the evidence bundle.
//!
//! Bead: asupersync-3cddg.9.3

use std::path::Path;

fn load_report() -> String {
    std::fs::read_to_string("docs/semantic_gate_evaluation_report.md")
        .expect("failed to load gate evaluation report")
}

fn load_bundle_script() -> String {
    std::fs::read_to_string("scripts/assemble_evidence_bundle.sh")
        .expect("failed to load evidence bundle assembly script")
}

// ─── Report infrastructure ───────────────────────────────────────

#[test]
fn gate_report_exists() {
    assert!(
        Path::new("docs/semantic_gate_evaluation_report.md").exists(),
        "Gate evaluation report must exist"
    );
}

#[test]
fn gate_report_references_bead() {
    let report = load_report();
    assert!(
        report.contains("asupersync-3cddg.9.3"),
        "Report must reference its own bead ID"
    );
}

// ─── Gate coverage ───────────────────────────────────────────────

#[test]
fn gate_report_covers_all_gates() {
    let report = load_report();

    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !report.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Gate evaluation report missing gates:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn gate_report_gate_domain_labels() {
    let report = load_report();

    let domains = [
        "Documentation Alignment",
        "LEAN Proof Coverage",
        "TLA+ Model Checking",
        "Runtime Conformance",
        "Property and Law Tests",
        "Cross-Artifact E2E",
        "Logging and Diagnostics",
    ];

    let mut missing = Vec::new();
    for domain in &domains {
        if !report.contains(domain) {
            missing.push(*domain);
        }
    }
    assert!(
        missing.is_empty(),
        "Gate report missing domain labels:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn gate_report_has_verdicts() {
    let report = load_report();

    // Must contain PASS and either FAIL or DEFER
    assert!(report.contains("PASS"), "Report must contain PASS verdicts");
    assert!(
        report.contains("FAIL") || report.contains("DEFER"),
        "Report must contain FAIL or DEFER verdicts for incomplete gates"
    );
}

// ─── Evidence references ─────────────────────────────────────────

#[test]
fn gate_report_references_evidence_artifacts() {
    let report = load_report();

    let artifacts = [
        "formal/tla/Asupersync.tla",
        "formal/lean/Asupersync.lean",
        "formal/tla/output/result.json",
        "semantic_contract_",
        "semantic_runtime_gap_matrix",
    ];

    let mut missing = Vec::new();
    for artifact in &artifacts {
        if !report.contains(artifact) {
            missing.push(*artifact);
        }
    }
    assert!(
        missing.is_empty(),
        "Gate report missing evidence artifact references:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn gate_report_references_bundle() {
    let report = load_report();

    assert!(
        report.contains("assemble_evidence_bundle.sh"),
        "Report must reference the evidence bundle assembly script"
    );
    assert!(
        report.contains("evidence-bundle"),
        "Report must reference the evidence bundle directory"
    );
}

// ─── Reproducibility ─────────────────────────────────────────────

#[test]
fn gate_report_includes_rerun_commands() {
    let report = load_report();

    // Must include rerun commands for reproducibility
    assert!(
        report.contains("Rerun") || report.contains("rerun"),
        "Report must include rerun instructions"
    );

    let rerun_commands = [
        "assemble_evidence_bundle.sh",
        "run_model_check.sh",
        "cargo test",
    ];

    let mut missing = Vec::new();
    for cmd in &rerun_commands {
        if !report.contains(cmd) {
            missing.push(*cmd);
        }
    }
    assert!(
        missing.is_empty(),
        "Gate report missing rerun commands:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Phase completion ────────────────────────────────────────────

#[test]
fn gate_report_includes_phase_decision() {
    let report = load_report();

    assert!(
        report.contains("Phase 1") || report.contains("phase 1"),
        "Report must reference Phase 1"
    );
    assert!(
        report.contains("Phase Completion")
            || report.contains("phase completion")
            || report.contains("Decision"),
        "Report must include phase completion decision"
    );
}

// ─── Conformance matrix ─────────────────────────────────────────

#[test]
fn gate_report_includes_conformance_summary() {
    let report = load_report();

    assert!(
        report.contains("Conformance Matrix") || report.contains("conformance matrix"),
        "Report must include conformance matrix summary"
    );
    assert!(
        report.contains("TLA+") && report.contains("Lean") && report.contains("Docs"),
        "Conformance summary must reference all three layers"
    );
}

// ─── Residual blockers ──────────────────────────────────────────

#[test]
fn gate_report_identifies_blockers() {
    let report = load_report();

    assert!(
        report.contains("Blocker") || report.contains("blocker") || report.contains("Residual"),
        "Report must identify residual blockers"
    );
    assert!(
        report.contains("Remediation") || report.contains("remediation"),
        "Report must include remediation guidance for blockers"
    );
}

// ─── Bundle script still valid ───────────────────────────────────

#[test]
fn bundle_script_still_valid() {
    let script = load_bundle_script();
    assert!(
        script.contains("evidence-bundle-v1"),
        "Evidence bundle script must use versioned schema"
    );
    assert!(
        script.contains("G1") && script.contains("G7"),
        "Evidence bundle script must evaluate gates G1-G7"
    );
}

// ─── TLC evidence referenced ─────────────────────────────────────

#[test]
fn gate_report_references_tlc_evidence() {
    let report = load_report();

    assert!(
        report.contains("23998") || report.contains("23,998"),
        "Report must reference TLC distinct state count"
    );
    assert!(
        report.contains("0 violations")
            || report.contains("violations: 0")
            || (report.contains("violations") && report.contains('0')),
        "Report must confirm zero TLC violations"
    );
}
