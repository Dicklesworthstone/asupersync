#![allow(warnings)]
#![allow(clippy::all)]
//! SEM-09.5 closure recommendation packet contract checks.
//!
//! Ensures the closure packet stays objective, reproducible, and tied to
//! bounded residual-risk ownership.

use std::path::Path;

fn load_packet() -> String {
    std::fs::read_to_string("docs/semantic_closure_recommendation_packet.md")
        .expect("failed to load SEM-09.5 closure recommendation packet")
}

#[test]
fn packet_exists() {
    assert!(
        Path::new("docs/semantic_closure_recommendation_packet.md").exists(),
        "SEM-09.5 closure recommendation packet must exist"
    );
}

#[test]
fn packet_references_bead_and_parent() {
    let packet = load_packet();
    assert!(
        packet.contains("asupersync-3cddg.9.5"),
        "packet must reference bead id"
    );
    assert!(
        packet.contains("SEM-09 Verification Bundle and Readiness Gates"),
        "packet must reference SEM-09 parent"
    );
}

#[test]
fn packet_covers_all_gate_ids() {
    let packet = load_packet();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    for gate in gates {
        assert!(
            packet.contains(gate),
            "packet must include gate identifier {gate}"
        );
    }
}

#[test]
fn packet_contains_evidence_classes() {
    let packet = load_packet();
    let evidence_classes = ["docs", "Lean", "TLA", "runtime", "e2e", "logging"];
    for class in evidence_classes {
        assert!(
            packet.contains(class),
            "packet must include evidence class {class}"
        );
    }
}

#[test]
fn packet_imports_sem09_4_risks_with_expiry_and_follow_up() {
    let packet = load_packet();
    let risk_ids = [
        "SEM-RISK-09-01",
        "SEM-RISK-09-02",
        "SEM-RISK-09-03",
        "SEM-RISK-09-04",
        "SEM-RISK-09-05",
    ];
    for risk_id in risk_ids {
        assert!(
            packet.contains(risk_id),
            "packet must include imported residual risk {risk_id}"
        );
    }

    assert!(
        packet.contains("Expiry") || packet.contains("expiry"),
        "packet must include expiry tracking for residual risks"
    );
    assert!(
        packet.contains("Follow-up bead") || packet.contains("follow-up bead"),
        "packet must include follow-up bead tracking"
    );
}

#[test]
fn packet_has_objective_go_no_go_rules() {
    let packet = load_packet();
    assert!(
        packet.contains("Objective GO/NO-GO Rule Evaluation"),
        "packet must define objective go/no-go rules"
    );
    assert!(
        packet.contains("Final sign-off recommendation"),
        "packet must provide final sign-off recommendation"
    );
    assert!(
        packet.contains("NO-GO"),
        "packet must currently reflect non-closure when blockers remain"
    );
}

#[test]
fn packet_includes_reproducible_commands_with_rch_for_cargo() {
    let packet = load_packet();
    assert!(
        packet.contains("Deterministic Rerun Commands"),
        "packet must include deterministic rerun section"
    );
    assert!(
        packet.contains("scripts/run_model_check.sh --ci"),
        "packet must include model-check rerun command"
    );
    assert!(
        packet.contains("scripts/run_lean_regression.sh --json"),
        "packet must include lean rerun command"
    );
    assert!(
        packet.contains("rch exec -- cargo test"),
        "packet must route cargo-heavy checks through rch"
    );
}
