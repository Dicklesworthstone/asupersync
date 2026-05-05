#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.8] Replacement claim RFC and sign-off record enforcement.
//!
//! Validates that the replacement claim RFC contains complete capability
//! matrices, evidence chains, limitation registers, incident playbook
//! links, diagnostic guidance, readiness assessment, invariant
//! preservation, sign-off record, and rollback triggers.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Capability matrix completeness
//!   3. Evidence chain validation
//!   4. Limitation register
//!   5. Incident playbook links
//!   6. Diagnostic guidance
//!   7. Readiness assessment
//!   8. Invariant preservation
//!   9. Sign-off record
//!  10. Rollback triggers
//!  11. Quality gates
//!  12. Evidence links
//!  13. Cross-reference validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn rfc_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_replacement_claim_rfc.md")
}

fn load_rfc() -> String {
    std::fs::read_to_string(rfc_path()).expect("replacement claim RFC must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t98_01_rfc_exists_and_is_substantial() {
    init_test("t98_01_rfc_exists_and_is_substantial");

    assert!(rfc_path().exists(), "RFC must exist");
    let doc = load_rfc();
    assert!(doc.len() > 8000, "RFC must be substantial (>8KB)");

    test_complete!("t98_01_rfc_exists_and_is_substantial");
}

#[test]
fn t98_02_rfc_references_bead_and_program() {
    init_test("t98_02_rfc_references_bead_and_program");

    let doc = load_rfc();
    assert!(doc.contains("asupersync-2oh2u.11.8"), "must reference bead");
    assert!(doc.contains("[T9.8]"), "must reference T9.8");

    test_complete!("t98_02_rfc_references_bead_and_program");
}

#[test]
fn t98_03_rfc_has_required_sections() {
    init_test("t98_03_rfc_has_required_sections");

    let doc = load_rfc();

    for section in [
        "Executive Summary",
        "Scope",
        "Capability",
        "Evidence Chain",
        "Known Limitations",
        "Incident Playbook",
        "Diagnostic Guidance",
        "Readiness Assessment",
        "Invariant Preservation",
        "Sign-Off Record",
        "Rollback Trigger",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t98_03_rfc_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Capability matrix completeness
// ============================================================================

#[test]
fn t98_04_capability_matrix_has_all_13_domains() {
    init_test("t98_04_capability_matrix_has_all_13_domains");

    let doc = load_rfc();

    for domain in [
        "Core Runtime",
        "Channels",
        "Time",
        "I/O",
        "Networking",
        "QUIC",
        "HTTP/1.1",
        "Web Framework",
        "Database",
        "Service Layer",
        "Filesystem",
        "Streams",
        "Tokio Interop",
    ] {
        test_section!(domain);
        assert!(doc.contains(domain), "missing domain: {domain}");
    }

    test_complete!("t98_04_capability_matrix_has_all_13_domains");
}

#[test]
fn t98_05_capability_counts_present() {
    init_test("t98_05_capability_counts_present");

    let doc = load_rfc();

    assert!(doc.contains("65"), "must cite 65 Full parity");
    assert!(doc.contains("84"), "must cite 84 total capabilities");
    assert!(doc.contains("77.4%"), "must cite 77.4% full parity ratio");

    test_complete!("t98_05_capability_counts_present");
}

#[test]
fn t98_06_governance_binding_referenced() {
    init_test("t98_06_governance_binding_referenced");

    let doc = load_rfc();

    assert!(
        doc.contains("asupersync-2oh2u.11.6"),
        "must bind to governance policy"
    );
    assert!(doc.contains("Stable"), "must reference Stable tier");
    assert!(
        doc.contains("Provisional"),
        "must reference Provisional tier"
    );

    test_complete!("t98_06_governance_binding_referenced");
}

// ============================================================================
// Tests: Section 3 - Evidence chain validation
// ============================================================================

#[test]
fn t98_07_unit_test_evidence_per_track() {
    init_test("t98_07_unit_test_evidence_per_track");

    let doc = load_rfc();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(
            doc.contains(track),
            "unit test evidence must cover: {track}"
        );
    }

    test_complete!("t98_07_unit_test_evidence_per_track");
}

#[test]
fn t98_08_e2e_validation_campaigns_referenced() {
    init_test("t98_08_e2e_validation_campaigns_referenced");

    let doc = load_rfc();

    for vc in ["VC-01", "VC-02", "VC-03", "VC-04", "VC-05", "VC-06"] {
        test_section!(vc);
        assert!(doc.contains(vc), "missing validation campaign: {vc}");
    }

    test_complete!("t98_08_e2e_validation_campaigns_referenced");
}

#[test]
fn t98_09_structured_log_evidence_referenced() {
    init_test("t98_09_structured_log_evidence_referenced");

    let doc = load_rfc();

    assert!(
        doc.contains("schema_version"),
        "must cite log schema fields"
    );
    assert!(doc.contains("correlation_id"), "must cite correlation IDs");
    assert!(doc.contains("replay_pointer"), "must cite replay pointers");

    test_complete!("t98_09_structured_log_evidence_referenced");
}

#[test]
fn t98_10_benchmark_evidence_referenced() {
    init_test("t98_10_benchmark_evidence_referenced");

    let doc = load_rfc();

    assert!(doc.contains("BM-01"), "must reference benchmark BM-01");
    assert!(doc.contains("BM-12"), "must reference benchmark BM-12");
    assert!(doc.contains("EQUIVALENT"), "must cite comparison verdicts");

    test_complete!("t98_10_benchmark_evidence_referenced");
}

// ============================================================================
// Tests: Section 4 - Limitation register
// ============================================================================

#[test]
fn t98_11_all_10_limitations_listed() {
    init_test("t98_11_all_10_limitations_listed");

    let doc = load_rfc();

    for lid in [
        "L-01", "L-02", "L-03", "L-04", "L-05", "L-06", "L-07", "L-08", "L-09", "L-10",
    ] {
        test_section!(lid);
        assert!(doc.contains(lid), "missing limitation: {lid}");
    }

    test_complete!("t98_11_all_10_limitations_listed");
}

#[test]
fn t98_12_limitation_severities_classified() {
    init_test("t98_12_limitation_severities_classified");

    let doc = load_rfc();

    assert!(doc.contains("High"), "must classify High severity");
    assert!(doc.contains("Medium"), "must classify Medium severity");
    assert!(doc.contains("Low"), "must classify Low severity");

    test_complete!("t98_12_limitation_severities_classified");
}

#[test]
fn t98_13_unresolved_risk_register_present() {
    init_test("t98_13_unresolved_risk_register_present");

    let doc = load_rfc();

    assert!(
        doc.contains("Unresolved Risk"),
        "must have unresolved risk register"
    );
    assert!(
        doc.contains("Probability"),
        "risk register must have probability"
    );
    assert!(doc.contains("Impact"), "risk register must have impact");

    test_complete!("t98_13_unresolved_risk_register_present");
}

// ============================================================================
// Tests: Section 5 - Incident playbook links
// ============================================================================

#[test]
fn t98_14_incident_classes_referenced() {
    init_test("t98_14_incident_classes_referenced");

    let doc = load_rfc();

    assert!(doc.contains("IC-01"), "must reference IC-01");
    assert!(doc.contains("IC-16"), "must reference IC-16");
    assert!(
        doc.contains("16 incident classes"),
        "must cite 16 incident classes"
    );

    test_complete!("t98_14_incident_classes_referenced");
}

#[test]
fn t98_15_detection_rules_referenced() {
    init_test("t98_15_detection_rules_referenced");

    let doc = load_rfc();

    assert!(doc.contains("DR-01"), "must reference detection rule DR-01");
    assert!(doc.contains("DR-06"), "must reference detection rule DR-06");

    test_complete!("t98_15_detection_rules_referenced");
}

#[test]
fn t98_16_sla_targets_defined() {
    init_test("t98_16_sla_targets_defined");

    let doc = load_rfc();

    assert!(doc.contains("SEV-1"), "must define SEV-1 SLA");
    assert!(doc.contains("30min"), "SEV-1 must have <30min target");

    test_complete!("t98_16_sla_targets_defined");
}

// ============================================================================
// Tests: Section 6 - Diagnostic guidance
// ============================================================================

#[test]
fn t98_17_migration_failure_classes_referenced() {
    init_test("t98_17_migration_failure_classes_referenced");

    let doc = load_rfc();

    assert!(doc.contains("MF-01"), "must reference MF-01");
    assert!(doc.contains("MF-10"), "must reference MF-10");
    assert!(doc.contains("10 failure"), "must cite 10 failure classes");

    test_complete!("t98_17_migration_failure_classes_referenced");
}

#[test]
fn t98_18_mttr_improvement_targets_defined() {
    init_test("t98_18_mttr_improvement_targets_defined");

    let doc = load_rfc();

    assert!(doc.contains("MTTR"), "must define MTTR improvement targets");
    assert!(
        doc.contains("50%"),
        "must cite 50% improvement for type errors"
    );
    assert!(
        doc.contains("67%"),
        "must cite 67% improvement for runtime errors"
    );

    test_complete!("t98_18_mttr_improvement_targets_defined");
}

// ============================================================================
// Tests: Section 7 - Readiness assessment
// ============================================================================

#[test]
fn t98_19_readiness_dimensions_defined() {
    init_test("t98_19_readiness_dimensions_defined");

    let doc = load_rfc();

    for dim in [
        "RG-DIM-01",
        "RG-DIM-02",
        "RG-DIM-03",
        "RG-DIM-04",
        "RG-DIM-05",
        "RG-DIM-06",
        "RG-DIM-07",
        "RG-DIM-08",
    ] {
        test_section!(dim);
        assert!(doc.contains(dim), "missing readiness dimension: {dim}");
    }

    test_complete!("t98_19_readiness_dimensions_defined");
}

#[test]
fn t98_20_promotion_thresholds_defined() {
    init_test("t98_20_promotion_thresholds_defined");

    let doc = load_rfc();

    assert!(doc.contains("0.85"), "must define GO threshold (0.85)");
    assert!(
        doc.contains("0.70"),
        "must define CONDITIONAL threshold (0.70)"
    );
    assert!(
        doc.contains("HARD_FAIL"),
        "must reference HARD_FAIL gate status"
    );

    test_complete!("t98_20_promotion_thresholds_defined");
}

// ============================================================================
// Tests: Section 8 - Invariant preservation
// ============================================================================

#[test]
fn t98_21_all_5_invariants_preserved() {
    init_test("t98_21_all_5_invariants_preserved");

    let doc = load_rfc();

    for inv in ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5"] {
        test_section!(inv);
        assert!(doc.contains(inv), "missing invariant: {inv}");
    }

    let preserved_count = doc
        .lines()
        .filter(|l| l.contains("INV-") && l.contains("Preserved"))
        .count();
    assert_eq!(preserved_count, 5, "all 5 invariants must be Preserved");

    test_complete!("t98_21_all_5_invariants_preserved");
}

#[test]
fn t98_22_lean_proofs_referenced() {
    init_test("t98_22_lean_proofs_referenced");

    let doc = load_rfc();

    assert!(doc.contains("Lean"), "must reference Lean formal proofs");
    assert!(
        doc.contains("FULLY_PROVEN"),
        "must cite FULLY_PROVEN status"
    );

    test_complete!("t98_22_lean_proofs_referenced");
}

// ============================================================================
// Tests: Section 9 - Sign-off record
// ============================================================================

#[test]
fn t98_23_signoff_matrix_present() {
    init_test("t98_23_signoff_matrix_present");

    let doc = load_rfc();

    assert!(doc.contains("Program Lead"), "must list Program Lead");
    assert!(doc.contains("QA Lead"), "must list QA Lead");
    assert!(doc.contains("Security Lead"), "must list Security Lead");

    test_complete!("t98_23_signoff_matrix_present");
}

#[test]
fn t98_24_signoff_criteria_defined() {
    init_test("t98_24_signoff_criteria_defined");

    let doc = load_rfc();

    assert!(
        doc.contains("Sign-Off Criteria"),
        "must define sign-off criteria"
    );
    assert!(
        doc.contains("evidence they have reviewed"),
        "approvers must review evidence"
    );

    test_complete!("t98_24_signoff_criteria_defined");
}

// ============================================================================
// Tests: Section 10 - Rollback triggers
// ============================================================================

#[test]
fn t98_25_rollback_triggers_defined() {
    init_test("t98_25_rollback_triggers_defined");

    let doc = load_rfc();

    for rt in ["RT-01", "RT-02", "RT-03", "RT-04", "RT-05"] {
        test_section!(rt);
        assert!(doc.contains(rt), "missing rollback trigger: {rt}");
    }

    test_complete!("t98_25_rollback_triggers_defined");
}

#[test]
fn t98_26_rollback_authority_defined() {
    init_test("t98_26_rollback_authority_defined");

    let doc = load_rfc();

    assert!(
        doc.contains("Track lead"),
        "must define Alpha rollback authority"
    );
    assert!(
        doc.contains("Engineering VP"),
        "must define GA rollback authority"
    );

    test_complete!("t98_26_rollback_authority_defined");
}

// ============================================================================
// Tests: Section 11 - Quality gates
// ============================================================================

#[test]
fn t98_27_quality_gates_defined() {
    init_test("t98_27_quality_gates_defined");

    let doc = load_rfc();

    for gate in [
        "RFC-01", "RFC-02", "RFC-03", "RFC-04", "RFC-05", "RFC-06", "RFC-07", "RFC-08", "RFC-09",
        "RFC-10",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t98_27_quality_gates_defined");
}

// ============================================================================
// Tests: Section 12 - Evidence links
// ============================================================================

#[test]
fn t98_28_all_prerequisite_beads_referenced() {
    init_test("t98_28_all_prerequisite_beads_referenced");

    let doc = load_rfc();

    for bead in [
        "asupersync-2oh2u.11.11",
        "asupersync-2oh2u.10.9",
        "asupersync-2oh2u.11.12",
        "asupersync-2oh2u.11.7",
        "asupersync-2oh2u.11.6",
        "asupersync-2oh2u.10.10",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t98_28_all_prerequisite_beads_referenced");
}

#[test]
fn t98_29_downstream_referenced() {
    init_test("t98_29_downstream_referenced");

    let doc = load_rfc();
    assert!(
        doc.contains("asupersync-2oh2u.11.9"),
        "must reference T9.9 downstream"
    );

    test_complete!("t98_29_downstream_referenced");
}

#[test]
fn t98_30_evidence_docs_exist() {
    init_test("t98_30_evidence_docs_exist");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_compatibility_limitation_matrix.md",
        "docs/tokio_compatibility_governance_deprecation_policy.md",
        "docs/tokio_release_channels_stabilization_policy.md",
        "docs/tokio_replacement_readiness_gate_aggregator.md",
        "docs/tokio_incident_response_rollback_playbooks.md",
        "docs/tokio_operator_enablement_pack.md",
        "docs/tokio_migration_cookbooks.md",
        "docs/tokio_replacement_roadmap.md",
    ] {
        test_section!(evidence_doc);
        assert!(
            base.join(evidence_doc).exists(),
            "evidence doc must exist: {evidence_doc}"
        );
    }

    test_complete!("t98_30_evidence_docs_exist");
}

// ============================================================================
// Tests: Section 13 - Cross-reference validation
// ============================================================================

#[test]
fn t98_31_ci_commands_present() {
    init_test("t98_31_ci_commands_present");

    let doc = load_rfc();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t98_31_ci_commands_present");
}

#[test]
fn t98_32_rfc_has_tables() {
    init_test("t98_32_rfc_has_tables");

    let doc = load_rfc();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 12,
        "must have at least 12 tables, found {table_count}"
    );

    test_complete!("t98_32_rfc_has_tables");
}

#[test]
fn t98_33_no_deferred_markers() {
    init_test("t98_33_no_deferred_markers");

    let doc = load_rfc();

    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "RFC has {marker} marker");
    }

    test_complete!("t98_33_no_deferred_markers");
}

#[test]
fn t98_34_revision_history_present() {
    init_test("t98_34_revision_history_present");

    let doc = load_rfc();
    assert!(
        doc.contains("Revision History"),
        "must have revision history"
    );

    test_complete!("t98_34_revision_history_present");
}

#[test]
fn t98_35_executive_summary_quantitative() {
    init_test("t98_35_executive_summary_quantitative");

    let doc = load_rfc();

    // Executive summary should have key quantitative claims
    assert!(doc.contains("77.4%"), "must cite parity percentage");
    assert!(
        doc.contains("84 capability"),
        "must cite total capabilities"
    );
    assert!(
        doc.contains("0 Critical"),
        "must cite zero critical limitations"
    );

    test_complete!("t98_35_executive_summary_quantitative");
}
