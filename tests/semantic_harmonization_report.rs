#![allow(warnings)]
#![allow(clippy::all)]
//! SEM-11.1 harmonization report contract checks.
//!
//! Ensures the harmonization report preserves drift deltas, ADR references,
//! owner mapping for unresolved concerns, and deterministic rerun guidance.

use std::path::Path;

fn load_report() -> String {
    std::fs::read_to_string("docs/semantic_harmonization_report.md")
        .expect("failed to load SEM-11.1 harmonization report")
}

#[test]
fn report_exists() {
    assert!(
        Path::new("docs/semantic_harmonization_report.md").exists(),
        "SEM-11.1 report must exist"
    );
}

#[test]
fn report_references_bead_and_parent() {
    let report = load_report();
    assert!(
        report.contains("asupersync-3cddg.11.1"),
        "report must reference SEM-11.1 bead id"
    );
    assert!(
        report.contains("SEM-11 Rollout, Enablement, and Recurring Semantic Audits"),
        "report must reference SEM-11 parent"
    );
}

#[test]
fn report_links_primary_sem_artifacts() {
    let report = load_report();
    let required_inputs = [
        "docs/semantic_drift_matrix.md",
        "docs/semantic_adr_decisions.md",
        "docs/semantic_runtime_gap_matrix.md",
        "docs/semantic_gate_evaluation_report.md",
        "docs/semantic_residual_risk_register.md",
        "docs/semantic_closure_recommendation_packet.md",
        "docs/semantic_verification_matrix.md",
    ];
    for input in required_inputs {
        assert!(
            report.contains(input),
            "report must reference primary artifact {input}"
        );
    }
}

#[test]
fn report_covers_adr_index() {
    let report = load_report();
    let adrs = [
        "ADR-001", "ADR-002", "ADR-003", "ADR-004", "ADR-005", "ADR-006", "ADR-007", "ADR-008",
    ];
    for adr in adrs {
        assert!(
            report.contains(adr),
            "report must include decision reference {adr}"
        );
    }
}

#[test]
fn report_contains_before_after_delta_table() {
    let report = load_report();
    assert!(
        report.contains("Measurable Before/After Drift Deltas"),
        "report must include explicit before/after delta section"
    );
    assert!(
        report.contains("| Metric | Before | After | Delta | Evidence |"),
        "report must include metric table with before/after/delta columns"
    );
    assert!(
        report.contains("| Runtime DOC-GAP backlog | 7 | 0 | -7 |"),
        "report must include runtime doc-gap delta"
    );
    assert!(
        report.contains("| Runtime TEST-GAP backlog | 6 | 0 | -6 |"),
        "report must include runtime test-gap delta"
    );
}

#[test]
fn report_mentions_all_gate_ids_and_current_posture() {
    let report = load_report();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    for gate in gates {
        assert!(report.contains(gate), "report must include gate {gate}");
    }
    assert!(
        report.contains("PASS") && report.contains("DEFER"),
        "report must include current pass/defer gate posture"
    );
}

#[test]
fn report_includes_owned_unresolved_concerns() {
    let report = load_report();
    let risk_ids = [
        "SEM-RISK-09-01",
        "SEM-RISK-09-02",
        "SEM-RISK-09-03",
        "SEM-RISK-09-04",
        "SEM-RISK-09-05",
    ];
    for risk_id in risk_ids {
        assert!(
            report.contains(risk_id),
            "report must include unresolved concern {risk_id}"
        );
    }

    let owner_beads = [
        "asupersync-3cddg.12.3",
        "asupersync-3cddg.12.4",
        "asupersync-3cddg.12.6",
        "asupersync-3cddg.12.7",
        "asupersync-3cddg.12.14",
        "asupersync-3cddg.6.4",
        "asupersync-3cddg.7.4",
    ];
    for bead in owner_beads {
        assert!(
            report.contains(bead),
            "report must include owner/follow-up bead {bead}"
        );
    }
}

#[test]
fn report_has_reproducibility_commands_and_rch_for_cargo() {
    let report = load_report();
    let commands = [
        "scripts/run_semantic_verification.sh --profile full --json",
        "scripts/build_semantic_evidence_bundle.sh",
        "scripts/generate_verification_summary.sh --json --ci",
        "rch exec -- cargo test --test semantic_verification_summary",
    ];
    for command in commands {
        assert!(
            report.contains(command),
            "report must include reproducibility command: {command}"
        );
    }
}
