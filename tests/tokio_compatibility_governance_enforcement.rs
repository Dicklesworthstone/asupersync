#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.6] Compatibility governance and deprecation policy enforcement.
//!
//! Validates compatibility tiers, deprecation process, breaking change
//! management, governance board structure, version policy, ecosystem
//! compatibility rules, exception handling, escalation paths,
//! invariant preservation, and staleness policy.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Compatibility tier definitions
//!   3. Deprecation process validation
//!   4. Breaking change management
//!   5. Governance board structure
//!   6. Version policy
//!   7. Ecosystem compatibility
//!   8. Quality gate definitions
//!   9. Evidence link validation
//!  10. Exception and waiver handling
//!  11. Escalation paths
//!  12. Invariant preservation
//!  13. Staleness and freshness
//!  14. Deprecation register schema
//!  15. Audit cadence

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn policy_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_compatibility_governance_deprecation_policy.md")
}

fn load_policy() -> String {
    std::fs::read_to_string(policy_path()).expect("governance policy must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t96_01_policy_exists_and_is_substantial() {
    init_test("t96_01_policy_exists_and_is_substantial");

    assert!(policy_path().exists(), "governance policy must exist");
    let doc = load_policy();
    assert!(doc.len() > 3000, "policy must be substantial");

    test_complete!("t96_01_policy_exists_and_is_substantial");
}

#[test]
fn t96_02_policy_references_bead_and_program() {
    init_test("t96_02_policy_references_bead_and_program");

    let doc = load_policy();
    assert!(doc.contains("asupersync-2oh2u.11.6"), "must reference bead");
    assert!(doc.contains("[T9.6]"), "must reference T9.6");

    test_complete!("t96_02_policy_references_bead_and_program");
}

#[test]
fn t96_03_policy_has_required_sections() {
    init_test("t96_03_policy_has_required_sections");

    let doc = load_policy();

    for section in [
        "Compatibility Tier",
        "Deprecation",
        "Breaking Change",
        "Governance Board",
        "Version Policy",
        "Ecosystem",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t96_03_policy_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Compatibility tier definitions
// ============================================================================

#[test]
fn t96_04_stability_tiers_defined() {
    init_test("t96_04_stability_tiers_defined");

    let doc = load_policy();

    for tier in ["Stable", "Provisional", "Experimental", "Internal"] {
        test_section!(tier);
        assert!(doc.contains(tier), "missing stability tier: {tier}");
    }

    test_complete!("t96_04_stability_tiers_defined");
}

#[test]
fn t96_05_compatibility_dimensions_defined() {
    init_test("t96_05_compatibility_dimensions_defined");

    let doc = load_policy();

    for dim in ["CD-01", "CD-02", "CD-03", "CD-04", "CD-05", "CD-06"] {
        test_section!(dim);
        assert!(doc.contains(dim), "missing dimension: {dim}");
    }

    test_complete!("t96_05_compatibility_dimensions_defined");
}

#[test]
fn t96_06_dimensions_cover_key_areas() {
    init_test("t96_06_dimensions_cover_key_areas");

    let doc = load_policy();

    for area in [
        "Source compatibility",
        "Binary compatibility",
        "Behavioral compatibility",
        "Performance compatibility",
        "Wire compatibility",
    ] {
        test_section!(area);
        assert!(doc.contains(area), "missing compatibility area: {area}");
    }

    test_complete!("t96_06_dimensions_cover_key_areas");
}

// ============================================================================
// Tests: Section 3 - Deprecation process validation
// ============================================================================

#[test]
fn t96_07_deprecation_lifecycle_defined() {
    init_test("t96_07_deprecation_lifecycle_defined");

    let doc = load_policy();

    for phase in ["PROPOSAL", "REVIEW", "APPROVED", "DEPRECATED", "REMOVED"] {
        test_section!(phase);
        assert!(doc.contains(phase), "missing lifecycle phase: {phase}");
    }

    test_complete!("t96_07_deprecation_lifecycle_defined");
}

#[test]
fn t96_08_deprecation_notice_requirements_defined() {
    init_test("t96_08_deprecation_notice_requirements_defined");

    let doc = load_policy();

    for req in ["DN-01", "DN-02", "DN-03", "DN-04", "DN-05"] {
        test_section!(req);
        assert!(doc.contains(req), "missing notice requirement: {req}");
    }

    test_complete!("t96_08_deprecation_notice_requirements_defined");
}

#[test]
fn t96_09_deprecation_impact_assessment_defined() {
    init_test("t96_09_deprecation_impact_assessment_defined");

    let doc = load_policy();

    for step in ["DIA-01", "DIA-02", "DIA-03", "DIA-04", "DIA-05"] {
        test_section!(step);
        assert!(doc.contains(step), "missing impact assessment: {step}");
    }

    test_complete!("t96_09_deprecation_impact_assessment_defined");
}

// ============================================================================
// Tests: Section 4 - Breaking change management
// ============================================================================

#[test]
fn t96_10_breaking_change_classes_defined() {
    init_test("t96_10_breaking_change_classes_defined");

    let doc = load_policy();

    for bc in ["BC-01", "BC-02", "BC-03", "BC-04", "BC-05", "BC-06"] {
        test_section!(bc);
        assert!(doc.contains(bc), "missing breaking change class: {bc}");
    }

    test_complete!("t96_10_breaking_change_classes_defined");
}

#[test]
fn t96_11_rfc_process_defined() {
    init_test("t96_11_rfc_process_defined");

    let doc = load_policy();

    assert!(doc.contains("RFC"), "must define RFC process");
    assert!(
        doc.contains("14 days"),
        "must define review period for Stable APIs"
    );
    assert!(
        doc.contains("7 days"),
        "must define review period for Provisional APIs"
    );

    test_complete!("t96_11_rfc_process_defined");
}

// ============================================================================
// Tests: Section 5 - Governance board structure
// ============================================================================

#[test]
fn t96_12_governance_board_composition_defined() {
    init_test("t96_12_governance_board_composition_defined");

    let doc = load_policy();

    assert!(
        doc.contains("Program Lead"),
        "board must include Program Lead"
    );
    assert!(doc.contains("Track Lead"), "board must include Track Leads");
    assert!(doc.contains("QA Lead"), "board must include QA Lead");

    test_complete!("t96_12_governance_board_composition_defined");
}

#[test]
fn t96_13_decision_thresholds_defined() {
    init_test("t96_13_decision_thresholds_defined");

    let doc = load_policy();

    assert!(
        doc.contains("2/3 majority"),
        "must define deprecation threshold"
    );
    assert!(
        doc.contains("3/4 majority"),
        "must define breaking change threshold"
    );
    assert!(doc.contains("Quorum"), "must define quorum requirements");

    test_complete!("t96_13_decision_thresholds_defined");
}

// ============================================================================
// Tests: Section 6 - Version policy
// ============================================================================

#[test]
fn t96_14_semver_rules_defined() {
    init_test("t96_14_semver_rules_defined");

    let doc = load_policy();

    assert!(doc.contains("Major"), "must define major version rules");
    assert!(doc.contains("Minor"), "must define minor version rules");
    assert!(doc.contains("Patch"), "must define patch version rules");

    test_complete!("t96_14_semver_rules_defined");
}

#[test]
fn t96_15_prerelease_identifiers_defined() {
    init_test("t96_15_prerelease_identifiers_defined");

    let doc = load_policy();

    for id in ["-alpha", "-beta", "-rc"] {
        test_section!(id);
        assert!(doc.contains(id), "missing pre-release identifier: {id}");
    }

    test_complete!("t96_15_prerelease_identifiers_defined");
}

#[test]
fn t96_16_support_policy_defined() {
    init_test("t96_16_support_policy_defined");

    let doc = load_policy();

    assert!(
        doc.contains("Support Duration") || doc.contains("Support Policy"),
        "must define support duration"
    );
    assert!(doc.contains("LTS"), "must define LTS policy");
    assert!(doc.contains("18 months"), "LTS must have defined duration");

    test_complete!("t96_16_support_policy_defined");
}

// ============================================================================
// Tests: Section 7 - Ecosystem compatibility
// ============================================================================

#[test]
fn t96_17_msrv_policy_defined() {
    init_test("t96_17_msrv_policy_defined");

    let doc = load_policy();

    assert!(doc.contains("MSRV"), "must define MSRV policy");
    assert!(doc.contains("Latest stable"), "must reference stable Rust");

    test_complete!("t96_17_msrv_policy_defined");
}

#[test]
fn t96_18_third_party_compatibility_tiered() {
    init_test("t96_18_third_party_compatibility_tiered");

    let doc = load_policy();

    for tier in ["Critical", "High", "Medium", "Low"] {
        test_section!(tier);
        assert!(
            doc.contains(tier),
            "ecosystem compatibility must include tier: {tier}"
        );
    }

    // Key crates mentioned
    assert!(doc.contains("reqwest"), "must mention reqwest");
    assert!(doc.contains("axum"), "must mention axum");
    assert!(doc.contains("tonic"), "must mention tonic");

    test_complete!("t96_18_third_party_compatibility_tiered");
}

// ============================================================================
// Tests: Section 8 - Quality gate definitions
// ============================================================================

#[test]
fn t96_19_quality_gates_defined() {
    init_test("t96_19_quality_gates_defined");

    let doc = load_policy();

    for gate in [
        "CG-01", "CG-02", "CG-03", "CG-04", "CG-05", "CG-06", "CG-07", "CG-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t96_19_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Evidence link validation
// ============================================================================

#[test]
fn t96_20_prerequisites_referenced() {
    init_test("t96_20_prerequisites_referenced");

    let doc = load_policy();

    for bead in [
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.11.5",
        "asupersync-2oh2u.11.3",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t96_20_prerequisites_referenced");
}

#[test]
fn t96_21_downstream_referenced() {
    init_test("t96_21_downstream_referenced");

    let doc = load_policy();
    assert!(
        doc.contains("asupersync-2oh2u.11.8"),
        "must reference T9.8 downstream"
    );

    test_complete!("t96_21_downstream_referenced");
}

#[test]
fn t96_22_evidence_docs_exist() {
    init_test("t96_22_evidence_docs_exist");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = load_policy();

    for evidence_doc in [
        "docs/tokio_release_channels_stabilization_policy.md",
        "docs/tokio_migration_cookbooks.md",
        "docs/tokio_replacement_roadmap.md",
    ] {
        test_section!(evidence_doc);
        let stem = evidence_doc
            .strip_prefix("docs/")
            .unwrap()
            .strip_suffix(".md")
            .unwrap();
        assert!(doc.contains(stem), "must reference {evidence_doc}");
        assert!(
            base.join(evidence_doc).exists(),
            "evidence doc must exist: {evidence_doc}"
        );
    }

    test_complete!("t96_22_evidence_docs_exist");
}

#[test]
fn t96_23_ci_commands_present() {
    init_test("t96_23_ci_commands_present");

    let doc = load_policy();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t96_23_ci_commands_present");
}

#[test]
fn t96_24_policy_has_tables() {
    init_test("t96_24_policy_has_tables");

    let doc = load_policy();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 8,
        "must have at least 8 tables, found {table_count}"
    );

    test_complete!("t96_24_policy_has_tables");
}

#[test]
fn t96_25_policy_has_code_blocks() {
    init_test("t96_25_policy_has_code_blocks");

    let doc = load_policy();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 4,
        "must have at least 2 code blocks, found {code_fences} fences"
    );

    test_complete!("t96_25_policy_has_code_blocks");
}

// ============================================================================
// Tests: Section 10 - Exception and waiver handling
// ============================================================================

#[test]
fn t96_26_waiver_types_defined() {
    init_test("t96_26_waiver_types_defined");

    let doc = load_policy();

    for wv in ["WV-01", "WV-02", "WV-03", "WV-04"] {
        test_section!(wv);
        assert!(doc.contains(wv), "missing waiver type: {wv}");
    }

    test_complete!("t96_26_waiver_types_defined");
}

#[test]
fn t96_27_waiver_constraints_documented() {
    init_test("t96_27_waiver_constraints_documented");

    let doc = load_policy();

    for constraint in [
        "justification",
        "risk assessment",
        "follow-up bead",
        "enhanced monitoring",
        "Expire automatically",
    ] {
        test_section!(constraint);
        assert!(
            doc.contains(constraint),
            "missing waiver constraint: {constraint}"
        );
    }

    test_complete!("t96_27_waiver_constraints_documented");
}

#[test]
fn t96_28_waiver_register_schema_defined() {
    init_test("t96_28_waiver_register_schema_defined");

    let doc = load_policy();

    assert!(
        doc.contains("compat-waiver-v1"),
        "must define waiver schema version"
    );
    assert!(
        doc.contains("waiver_id"),
        "waiver schema must have waiver_id"
    );
    assert!(
        doc.contains("blast_radius"),
        "waiver schema must have blast_radius"
    );
    assert!(
        doc.contains("monitoring_plan"),
        "waiver schema must have monitoring_plan"
    );

    test_complete!("t96_28_waiver_register_schema_defined");
}

// ============================================================================
// Tests: Section 11 - Escalation paths
// ============================================================================

#[test]
fn t96_29_escalation_triggers_defined() {
    init_test("t96_29_escalation_triggers_defined");

    let doc = load_policy();

    for esc in ["ESC-01", "ESC-02", "ESC-03", "ESC-04", "ESC-05"] {
        test_section!(esc);
        assert!(doc.contains(esc), "missing escalation trigger: {esc}");
    }

    test_complete!("t96_29_escalation_triggers_defined");
}

#[test]
fn t96_30_escalation_has_timelines() {
    init_test("t96_30_escalation_has_timelines");

    let doc = load_policy();

    for timeline in ["4h", "24h", "48h", "1 week", "Same-day"] {
        test_section!(timeline);
        assert!(
            doc.contains(timeline),
            "escalation must include timeline: {timeline}"
        );
    }

    test_complete!("t96_30_escalation_has_timelines");
}

#[test]
fn t96_31_emergency_process_defined() {
    init_test("t96_31_emergency_process_defined");

    let doc = load_policy();

    for step in ["EM-01", "EM-02", "EM-03", "EM-04", "EM-05", "EM-06"] {
        test_section!(step);
        assert!(doc.contains(step), "missing emergency step: {step}");
    }

    assert!(doc.contains("CVSS"), "must reference CVSS scoring");

    test_complete!("t96_31_emergency_process_defined");
}

// ============================================================================
// Tests: Section 12 - Invariant preservation
// ============================================================================

#[test]
fn t96_32_invariant_preservation_defined() {
    init_test("t96_32_invariant_preservation_defined");

    let doc = load_policy();

    for inv in ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5"] {
        test_section!(inv);
        assert!(doc.contains(inv), "missing invariant: {inv}");
    }

    test_complete!("t96_32_invariant_preservation_defined");
}

#[test]
fn t96_33_invariant_governance_constraints() {
    init_test("t96_33_invariant_governance_constraints");

    let doc = load_policy();

    assert!(
        doc.contains("No ambient authority") || doc.contains("no ambient authority"),
        "must constrain INV-1"
    );
    assert!(
        doc.contains("Structured concurrency") || doc.contains("structured concurrency"),
        "must constrain INV-2"
    );
    assert!(
        doc.contains("Cancellation is a protocol") || doc.contains("cancellation is a protocol"),
        "must constrain INV-3"
    );

    test_complete!("t96_33_invariant_governance_constraints");
}

// ============================================================================
// Tests: Section 13 - Staleness and freshness
// ============================================================================

#[test]
fn t96_34_staleness_thresholds_defined() {
    init_test("t96_34_staleness_thresholds_defined");

    let doc = load_policy();

    assert!(
        doc.contains("30 days"),
        "must define 30-day warning threshold"
    );
    assert!(
        doc.contains("60 days"),
        "must define 60-day hard-fail threshold"
    );

    test_complete!("t96_34_staleness_thresholds_defined");
}

#[test]
fn t96_35_freshness_metrics_covered() {
    init_test("t96_35_freshness_metrics_covered");

    let doc = load_policy();

    for metric in [
        "Compatibility matrix age",
        "Deprecation log review",
        "Waiver register audit",
        "Policy document age",
    ] {
        test_section!(metric);
        assert!(doc.contains(metric), "missing freshness metric: {metric}");
    }

    test_complete!("t96_35_freshness_metrics_covered");
}

// ============================================================================
// Tests: Section 14 - Deprecation register schema
// ============================================================================

#[test]
fn t96_36_deprecation_register_schema_defined() {
    init_test("t96_36_deprecation_register_schema_defined");

    let doc = load_policy();

    assert!(
        doc.contains("deprecation-register-v1"),
        "must define deprecation register schema version"
    );

    for field in [
        "dep_id",
        "surface",
        "stage",
        "replacement",
        "removal_target",
        "owner_track",
    ] {
        test_section!(field);
        assert!(
            doc.contains(field),
            "deprecation register missing field: {field}"
        );
    }

    test_complete!("t96_36_deprecation_register_schema_defined");
}

#[test]
fn t96_37_deprecation_summary_fields() {
    init_test("t96_37_deprecation_summary_fields");

    let doc = load_policy();

    for field in [
        "total_deprecations",
        "active_warnings",
        "soft_removed",
        "hard_removed",
    ] {
        test_section!(field);
        assert!(
            doc.contains(field),
            "deprecation summary missing field: {field}"
        );
    }

    test_complete!("t96_37_deprecation_summary_fields");
}

// ============================================================================
// Tests: Section 15 - Audit cadence
// ============================================================================

#[test]
fn t96_38_audit_cadence_defined() {
    init_test("t96_38_audit_cadence_defined");

    let doc = load_policy();

    for freq in ["Monthly", "Bi-weekly", "Quarterly", "Semi-annual"] {
        test_section!(freq);
        assert!(doc.contains(freq), "missing audit frequency: {freq}");
    }

    test_complete!("t96_38_audit_cadence_defined");
}

#[test]
fn t96_39_extended_quality_gates() {
    init_test("t96_39_extended_quality_gates");

    let doc = load_policy();

    for gate in ["CG-09", "CG-10", "CG-11", "CG-12"] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing extended quality gate: {gate}");
    }

    test_complete!("t96_39_extended_quality_gates");
}

#[test]
fn t96_40_no_deferred_markers() {
    init_test("t96_40_no_deferred_markers");

    let doc = load_policy();

    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "policy has {marker} marker");
    }

    test_complete!("t96_40_no_deferred_markers");
}
