//! First Recurring Audit Retrospective Validation (SEM-11.5)
//!
//! Validates that the first audit retrospective exists, documents gate
//! status, coverage snapshot, drift deltas, risk register review,
//! retrospective findings, and action items.
//!
//! Bead: asupersync-3cddg.11.5

use std::path::Path;

fn load_retrospective() -> String {
    std::fs::read_to_string("docs/semantic_first_audit_retrospective.md")
        .expect("failed to load first audit retrospective")
}

// ─── Document infrastructure ──────────────────────────────────────

#[test]
fn retrospective_exists() {
    assert!(
        Path::new("docs/semantic_first_audit_retrospective.md").exists(),
        "First audit retrospective must exist"
    );
}

#[test]
fn retrospective_references_bead() {
    let retro = load_retrospective();
    assert!(
        retro.contains("asupersync-3cddg.11.5"),
        "Retrospective must reference its own bead ID"
    );
}

// ─── Audit scope ──────────────────────────────────────────────────

#[test]
fn retrospective_documents_verification_commands() {
    let retro = load_retrospective();
    assert!(
        retro.contains("run_semantic_verification.sh"),
        "Must document verification runner execution"
    );
    assert!(
        retro.contains("assemble_evidence_bundle.sh"),
        "Must document evidence bundle assembly"
    );
    assert!(
        retro.contains("generate_verification_summary.sh"),
        "Must document summary generation"
    );
}

#[test]
fn retrospective_documents_inputs() {
    let retro = load_retrospective();
    assert!(
        retro.contains("verification_report.json"),
        "Must list runner output as input"
    );
    assert!(
        retro.contains("bundle_manifest.json"),
        "Must list gate evaluation as input"
    );
    assert!(
        retro.contains("semantic_harmonization_report.md"),
        "Must reference harmonization report as baseline"
    );
}

// ─── Gate status ──────────────────────────────────────────────────

#[test]
fn retrospective_reviews_all_gates() {
    let retro = load_retrospective();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !retro.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Retrospective missing gate reviews:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn retrospective_identifies_passing_gates() {
    let retro = load_retrospective();
    assert!(
        retro.contains("PASS") && retro.contains("DEFER"),
        "Must identify both passing and deferred gates"
    );
}

// ─── Coverage snapshot ────────────────────────────────────────────

#[test]
fn retrospective_includes_coverage_snapshot() {
    let retro = load_retrospective();
    let classes = ["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"];
    let mut missing = Vec::new();
    for class in &classes {
        if !retro.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "Coverage snapshot missing evidence classes:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Drift deltas ─────────────────────────────────────────────────

#[test]
fn retrospective_includes_drift_deltas() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Drift Delta") || retro.contains("drift delta") || retro.contains("Delta"),
        "Must include drift delta comparison"
    );
    assert!(
        retro.contains("Baseline") || retro.contains("baseline"),
        "Must compare against baseline"
    );
}

// ─── Risk register ────────────────────────────────────────────────

#[test]
fn retrospective_reviews_risk_register() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Risk Register") || retro.contains("risk register"),
        "Must review risk register"
    );
    assert!(
        retro.contains("SEM-RISK"),
        "Must reference specific risk IDs"
    );
}

// ─── Verification infrastructure ──────────────────────────────────

#[test]
fn retrospective_validates_infrastructure() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Operational") || retro.contains("operational"),
        "Must validate verification infrastructure status"
    );
}

#[test]
fn retrospective_includes_test_counts() {
    let retro = load_retrospective();
    assert!(
        retro.contains("221") || retro.contains("Test Suite"),
        "Must include total semantic test count"
    );
}

// ─── Retrospective findings ───────────────────────────────────────

#[test]
fn retrospective_has_what_went_well() {
    let retro = load_retrospective();
    assert!(
        retro.contains("What Went Well") || retro.contains("what went well"),
        "Must include what-went-well section"
    );
}

#[test]
fn retrospective_has_what_could_be_improved() {
    let retro = load_retrospective();
    assert!(
        retro.contains("What Could Be Improved")
            || retro.contains("could be improved")
            || retro.contains("Improved"),
        "Must include improvement opportunities"
    );
}

#[test]
fn retrospective_has_action_items() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Action Items") || retro.contains("action items"),
        "Must include action items"
    );
}

#[test]
fn retrospective_action_items_have_owners() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Owner") || retro.contains("owner"),
        "Action items must have owners"
    );
}

// ─── Drift health rating ─────────────────────────────────────────

#[test]
fn retrospective_includes_drift_rating() {
    let retro = load_retrospective();
    assert!(
        retro.contains("GREEN") || retro.contains("YELLOW") || retro.contains("RED"),
        "Must include drift health rating"
    );
}

#[test]
fn retrospective_references_cadence_indicators() {
    let retro = load_retrospective();
    assert!(
        retro.contains("semantic_audit_cadence.md"),
        "Must reference audit cadence document for indicator definitions"
    );
}

// ─── Next audit schedule ──────────────────────────────────────────

#[test]
fn retrospective_includes_next_schedule() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Next Audit") || retro.contains("next audit") || retro.contains("Next Due"),
        "Must include next audit schedule"
    );
}

// ─── Process effectiveness ────────────────────────────────────────

#[test]
fn retrospective_assesses_process_effectiveness() {
    let retro = load_retrospective();
    assert!(
        retro.contains("Process Effectiveness")
            || retro.contains("process effectiveness")
            || retro.contains("Verdict"),
        "Must assess process effectiveness"
    );
}
