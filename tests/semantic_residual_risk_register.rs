#![allow(clippy::all)]
//! Semantic Residual Risk Register Contract (SEM-09.4)
//!
//! Validates the SEM-09.4 artifact includes explicit gate criteria, evidence
//! class links, bounded exceptions, and objective go/no-go rules.

use std::path::Path;

fn load_register() -> String {
    std::fs::read_to_string("docs/semantic_residual_risk_register.md")
        .expect("failed to load semantic residual risk register")
}

#[test]
fn register_exists() {
    assert!(
        Path::new("docs/semantic_residual_risk_register.md").exists(),
        "SEM-09.4 residual risk register must exist"
    );
}

#[test]
fn register_references_bead() {
    let doc = load_register();
    assert!(
        doc.contains("asupersync-3cddg.9.4"),
        "register must reference SEM-09.4 bead id"
    );
}

#[test]
fn register_includes_all_evidence_classes() {
    let doc = load_register();
    let classes = ["docs", "Lean", "TLA", "runtime", "e2e", "logging"];
    let mut missing = Vec::new();
    for class in &classes {
        if !doc.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "register missing evidence classes:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn register_has_owner_expiry_follow_up_fields() {
    let doc = load_register();
    assert!(
        doc.contains("Owner bead"),
        "register must include owner column"
    );
    assert!(
        doc.contains("Expiry"),
        "register must include expiry column"
    );
    assert!(
        doc.contains("Follow-up bead"),
        "register must include follow-up bead column"
    );
}

#[test]
fn register_has_multiple_risk_entries() {
    let doc = load_register();
    let risk_count = doc.matches("SEM-RISK-09-").count();
    assert!(
        risk_count >= 4,
        "register must include at least 4 explicit residual risks, found {risk_count}"
    );
}

#[test]
fn register_includes_reproducible_commands() {
    let doc = load_register();
    let commands = [
        "assemble_evidence_bundle.sh",
        "run_lean_regression.sh",
        "run_model_check.sh",
        "semantic_witness_replay_e2e",
        "semantic_log_schema_validation",
    ];
    let mut missing = Vec::new();
    for cmd in &commands {
        if !doc.contains(cmd) {
            missing.push(*cmd);
        }
    }
    assert!(
        missing.is_empty(),
        "register missing reproducible command references:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn register_includes_objective_go_no_go_logic() {
    let doc = load_register();
    assert!(
        doc.contains("Go/No-Go") || doc.contains("GO/NO-GO"),
        "register must include go/no-go section"
    );
    assert!(
        doc.contains("Current decision"),
        "register must include explicit current decision"
    );
    assert!(
        doc.contains("NO-GO"),
        "register must include explicit no-go condition"
    );
}
