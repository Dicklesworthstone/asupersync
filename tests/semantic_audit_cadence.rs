//! Semantic Audit Cadence Validation (SEM-11.4)
//!
//! Validates that the audit cadence document exists, defines all required
//! audit tiers, ownership rotation, drift indicators, and integration
//! with CI and verification infrastructure.
//!
//! Bead: asupersync-3cddg.11.4

use std::path::Path;

fn load_cadence() -> String {
    std::fs::read_to_string("docs/semantic_audit_cadence.md")
        .expect("failed to load audit cadence document")
}

// ─── Document infrastructure ──────────────────────────────────────

#[test]
fn cadence_exists() {
    assert!(
        Path::new("docs/semantic_audit_cadence.md").exists(),
        "Audit cadence document must exist"
    );
}

#[test]
fn cadence_references_bead() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("asupersync-3cddg.11.4"),
        "Cadence document must reference its own bead ID"
    );
}

// ─── Audit tiers ──────────────────────────────────────────────────

#[test]
fn cadence_defines_four_tiers() {
    let cadence = load_cadence();
    assert!(cadence.contains("Tier 1"), "Must define Tier 1 (Per-PR)");
    assert!(cadence.contains("Tier 2"), "Must define Tier 2 (Weekly)");
    assert!(cadence.contains("Tier 3"), "Must define Tier 3 (Monthly)");
    assert!(cadence.contains("Tier 4"), "Must define Tier 4 (Quarterly)");
}

#[test]
fn cadence_tier1_covers_quality_gates() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("cargo check")
            && cadence.contains("cargo clippy")
            && cadence.contains("cargo fmt"),
        "Tier 1 must include quality gate commands"
    );
}

#[test]
fn cadence_tier2_covers_weekly_sweep() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Weekly") || cadence.contains("weekly"),
        "Must define weekly sweep cadence"
    );
    assert!(
        cadence.contains("run_semantic_verification.sh"),
        "Weekly sweep must use unified verification runner"
    );
    assert!(
        cadence.contains("generate_verification_summary.sh"),
        "Weekly sweep must generate summary"
    );
}

#[test]
fn cadence_tier3_covers_monthly_evidence() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Monthly") || cadence.contains("monthly"),
        "Must define monthly evidence audit"
    );
    assert!(
        cadence.contains("assemble_evidence_bundle.sh"),
        "Monthly audit must assemble evidence bundle"
    );
}

#[test]
fn cadence_tier4_covers_quarterly_review() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Quarterly") || cadence.contains("quarterly"),
        "Must define quarterly deep review"
    );
}

#[test]
fn cadence_tiers_have_checklists() {
    let cadence = load_cadence();
    // Each tier should have checkbox items
    let checkbox_count = cadence.matches("- [ ]").count();
    assert!(
        checkbox_count >= 10,
        "Must have at least 10 audit checklist items, found {checkbox_count}",
    );
}

// ─── Drift health indicators ─────────────────────────────────────

#[test]
fn cadence_defines_drift_indicators() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Green") || cadence.contains("Healthy"),
        "Must define healthy drift state"
    );
    assert!(
        cadence.contains("Yellow") || cadence.contains("Attention"),
        "Must define attention-needed drift state"
    );
    assert!(
        cadence.contains("Red") || cadence.contains("Immediate"),
        "Must define critical drift state"
    );
}

#[test]
fn cadence_drift_indicators_have_responses() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Response:") || cadence.contains("response"),
        "Drift indicators must include response actions"
    );
}

// ─── Ownership ────────────────────────────────────────────────────

#[test]
fn cadence_defines_audit_lead_role() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Audit Lead") || cadence.contains("audit lead"),
        "Must define audit lead role"
    );
}

#[test]
fn cadence_defines_rotation_schedule() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Rotation") || cadence.contains("rotation"),
        "Must define ownership rotation schedule"
    );
}

#[test]
fn cadence_defines_handoff_protocol() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Handoff") || cadence.contains("handoff"),
        "Must define audit lead handoff protocol"
    );
}

// ─── Audit artifacts ──────────────────────────────────────────────

#[test]
fn cadence_lists_audit_artifacts() {
    let cadence = load_cadence();
    let artifacts = [
        "verification_summary",
        "triage_report",
        "bundle_manifest",
        "gate_evaluation_report",
        "residual_risk_register",
    ];
    let mut missing = Vec::new();
    for artifact in &artifacts {
        if !cadence.contains(artifact) {
            missing.push(*artifact);
        }
    }
    assert!(
        missing.is_empty(),
        "Cadence missing artifact references:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Escalation ───────────────────────────────────────────────────

#[test]
fn cadence_defines_escalation_thresholds() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Escalation") || cadence.contains("escalation"),
        "Must define escalation thresholds"
    );
}

#[test]
fn cadence_escalation_covers_gate_regression() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Gate regression") || cadence.contains("gate regression"),
        "Escalation must cover gate regression scenario"
    );
}

// ─── Success metrics ──────────────────────────────────────────────

#[test]
fn cadence_defines_success_metrics() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Success Metrics") || cadence.contains("success metrics"),
        "Must define audit success metrics"
    );
}

// ─── CI integration ───────────────────────────────────────────────

#[test]
fn cadence_documents_ci_integration() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("CI") || cadence.contains("ci"),
        "Must document CI integration"
    );
}

#[test]
fn cadence_references_anti_drift_checks() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("check_semantic_consistency")
            || cadence.contains("check_rule_traceability"),
        "Must reference SEM-10 anti-drift CI checks"
    );
}

#[test]
fn cadence_references_gate_status() {
    let cadence = load_cadence();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !cadence.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Cadence missing gate references:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Self-review ──────────────────────────────────────────────────

#[test]
fn cadence_includes_self_review_clause() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("Review of This Document") || cadence.contains("review of this document"),
        "Must include self-review clause for the cadence document itself"
    );
}

#[test]
fn cadence_references_playbook() {
    let cadence = load_cadence();
    assert!(
        cadence.contains("semantic_maintainer_playbook.md"),
        "Must reference maintainer playbook for cross-linking"
    );
}
