#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T8.10] Incident-response and rollback playbook enforcement.
//!
//! Validates the incident-response playbooks, rollback procedures, detection
//! rules, triage decision trees, drill framework, and quality gates for
//! Tokio-replacement track surfaces.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Incident classification coverage
//!   3. Detection rule validation
//!   4. Triage decision tree completeness
//!   5. Containment procedure validation
//!   6. Rollback playbook completeness
//!   7. Post-incident review schema
//!   8. Drill framework validation
//!   9. Quality gate definitions
//!  10. Cross-reference and evidence validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn playbook_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_incident_response_rollback_playbooks.md")
}

fn load_playbook() -> String {
    std::fs::read_to_string(playbook_path()).expect("incident playbook must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t810_01_playbook_exists_and_is_substantial() {
    init_test("t810_01_playbook_exists_and_is_substantial");

    assert!(playbook_path().exists(), "incident playbook must exist");
    let doc = load_playbook();
    assert!(
        doc.len() > 3000,
        "playbook must be substantial (>3000 chars)"
    );

    test_complete!("t810_01_playbook_exists_and_is_substantial");
}

#[test]
fn t810_02_playbook_references_bead_and_program() {
    init_test("t810_02_playbook_references_bead_and_program");

    let doc = load_playbook();
    assert!(
        doc.contains("asupersync-2oh2u.10.10"),
        "must reference bead"
    );
    assert!(doc.contains("[T8.10]"), "must reference T8.10");
    assert!(doc.contains("asupersync-2oh2u"), "must reference program");

    test_complete!("t810_02_playbook_references_bead_and_program");
}

#[test]
fn t810_03_playbook_has_required_sections() {
    init_test("t810_03_playbook_has_required_sections");

    let doc = load_playbook();

    for section in [
        "Incident Classification",
        "Detection",
        "Triage",
        "Containment",
        "Rollback",
        "Post-Incident",
        "Drill",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t810_03_playbook_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Incident classification coverage
// ============================================================================

#[test]
fn t810_04_severity_levels_defined() {
    init_test("t810_04_severity_levels_defined");

    let doc = load_playbook();

    for sev in ["SEV-1", "SEV-2", "SEV-3", "SEV-4"] {
        test_section!(sev);
        assert!(doc.contains(sev), "missing severity level: {sev}");
    }

    test_complete!("t810_04_severity_levels_defined");
}

#[test]
fn t810_05_all_incident_classes_defined() {
    init_test("t810_05_all_incident_classes_defined");

    let doc = load_playbook();

    for ic in [
        "IC-01", "IC-02", "IC-03", "IC-04", "IC-05", "IC-06", "IC-07", "IC-08", "IC-09", "IC-10",
        "IC-11", "IC-12", "IC-13", "IC-14", "IC-15", "IC-16",
    ] {
        test_section!(ic);
        assert!(doc.contains(ic), "missing incident class: {ic}");
    }

    test_complete!("t810_05_all_incident_classes_defined");
}

#[test]
fn t810_06_incident_classes_cover_all_tracks() {
    init_test("t810_06_incident_classes_cover_all_tracks");

    let doc = load_playbook();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(
            doc.contains(track),
            "incident classes must cover track: {track}"
        );
    }

    test_complete!("t810_06_incident_classes_cover_all_tracks");
}

#[test]
fn t810_07_severity_slas_quantitative() {
    init_test("t810_07_severity_slas_quantitative");

    let doc = load_playbook();

    // Verify SLAs have quantitative values
    assert!(doc.contains("< 1 min"), "SEV-1 detection SLA");
    assert!(doc.contains("< 5 min"), "SEV-1 response SLA");
    assert!(doc.contains("< 30 min"), "SEV-1 resolution SLA");

    test_complete!("t810_07_severity_slas_quantitative");
}

// ============================================================================
// Tests: Section 3 - Detection rule validation
// ============================================================================

#[test]
fn t810_08_detection_rules_defined() {
    init_test("t810_08_detection_rules_defined");

    let doc = load_playbook();

    for dr in ["DR-01", "DR-02", "DR-03", "DR-04", "DR-05", "DR-06"] {
        test_section!(dr);
        assert!(doc.contains(dr), "missing detection rule: {dr}");
    }

    test_complete!("t810_08_detection_rules_defined");
}

#[test]
fn t810_09_detection_emits_structured_logs() {
    init_test("t810_09_detection_emits_structured_logs");

    let doc = load_playbook();

    assert!(
        doc.contains("incident-detection-v1"),
        "must define detection log schema version"
    );
    assert!(
        doc.contains("correlation_id"),
        "detection logs must include correlation IDs"
    );
    assert!(
        doc.contains("replay_pointer"),
        "detection logs must include replay pointers"
    );

    test_complete!("t810_09_detection_emits_structured_logs");
}

// ============================================================================
// Tests: Section 4 - Triage decision tree completeness
// ============================================================================

#[test]
fn t810_10_triage_flow_defined() {
    init_test("t810_10_triage_flow_defined");

    let doc = load_playbook();

    assert!(
        doc.contains("INCIDENT DETECTED"),
        "triage must start with detection"
    );
    assert!(
        doc.contains("CONTAINMENT") || doc.contains("IMMEDIATE CONTAINMENT"),
        "triage must include containment step"
    );
    assert!(
        doc.contains("ROLLBACK"),
        "triage must include rollback decision"
    );

    test_complete!("t810_10_triage_flow_defined");
}

#[test]
fn t810_11_track_specific_triage_present() {
    init_test("t810_11_track_specific_triage_present");

    let doc = load_playbook();

    // Track-specific triage sections
    for label in ["I/O", "gRPC", "Database"] {
        test_section!(label);
        assert!(doc.contains(label), "triage must cover track area: {label}");
    }

    test_complete!("t810_11_track_specific_triage_present");
}

// ============================================================================
// Tests: Section 5 - Containment procedure validation
// ============================================================================

#[test]
fn t810_12_containment_procedures_defined() {
    init_test("t810_12_containment_procedures_defined");

    let doc = load_playbook();

    assert!(
        doc.contains("Emergency Containment"),
        "must have emergency containment"
    );
    assert!(
        doc.contains("Targeted Mitigation"),
        "must have targeted mitigation"
    );
    assert!(
        doc.contains("Isolate"),
        "containment must include isolation step"
    );

    test_complete!("t810_12_containment_procedures_defined");
}

// ============================================================================
// Tests: Section 6 - Rollback playbook completeness
// ============================================================================

#[test]
fn t810_13_emergency_rollback_defined() {
    init_test("t810_13_emergency_rollback_defined");

    let doc = load_playbook();

    assert!(
        doc.contains("Emergency Rollback"),
        "must define emergency rollback"
    );
    assert!(
        doc.contains("last-known-good") || doc.contains("Revert"),
        "emergency rollback must describe reversion"
    );

    test_complete!("t810_13_emergency_rollback_defined");
}

#[test]
fn t810_14_gradual_rollback_defined() {
    init_test("t810_14_gradual_rollback_defined");

    let doc = load_playbook();

    assert!(
        doc.contains("Gradual Rollback") || doc.contains("Feature-Flag"),
        "must define gradual rollback"
    );

    for step in ["RB-01", "RB-02", "RB-03", "RB-04"] {
        test_section!(step);
        assert!(doc.contains(step), "missing rollback step: {step}");
    }

    test_complete!("t810_14_gradual_rollback_defined");
}

#[test]
fn t810_15_track_specific_rollback_conditions() {
    init_test("t810_15_track_specific_rollback_conditions");

    let doc = load_playbook();

    // Each track should have rollback conditions
    assert!(
        doc.contains("cargo test"),
        "rollback must include verification commands"
    );
    assert!(
        doc.contains("Rollback Trigger"),
        "must define rollback triggers"
    );
    assert!(
        doc.contains("Rollback Target"),
        "must define rollback targets"
    );

    test_complete!("t810_15_track_specific_rollback_conditions");
}

// ============================================================================
// Tests: Section 7 - Post-incident review schema
// ============================================================================

#[test]
fn t810_16_incident_report_schema_defined() {
    init_test("t810_16_incident_report_schema_defined");

    let doc = load_playbook();

    assert!(
        doc.contains("incident-report-v1"),
        "must define incident report schema version"
    );

    for field in [
        "incident_id",
        "incident_class",
        "root_cause",
        "remediation",
        "rollback_used",
        "follow_up_bead",
    ] {
        test_section!(field);
        assert!(
            doc.contains(field),
            "incident report missing field: {field}"
        );
    }

    test_complete!("t810_16_incident_report_schema_defined");
}

#[test]
fn t810_17_post_incident_checklist_present() {
    init_test("t810_17_post_incident_checklist_present");

    let doc = load_playbook();

    for step in ["PIR-01", "PIR-02", "PIR-03", "PIR-04", "PIR-05", "PIR-06"] {
        test_section!(step);
        assert!(doc.contains(step), "missing post-incident step: {step}");
    }

    test_complete!("t810_17_post_incident_checklist_present");
}

// ============================================================================
// Tests: Section 8 - Drill framework validation
// ============================================================================

#[test]
fn t810_18_drill_types_defined() {
    init_test("t810_18_drill_types_defined");

    let doc = load_playbook();

    for drill in [
        "DRILL-01", "DRILL-02", "DRILL-03", "DRILL-04", "DRILL-05", "DRILL-06",
    ] {
        test_section!(drill);
        assert!(doc.contains(drill), "missing drill type: {drill}");
    }

    test_complete!("t810_18_drill_types_defined");
}

#[test]
fn t810_19_drill_protocol_defined() {
    init_test("t810_19_drill_protocol_defined");

    let doc = load_playbook();

    for phase in [
        "Announce", "Inject", "Detect", "Respond", "Verify", "Review",
    ] {
        test_section!(phase);
        assert!(doc.contains(phase), "drill protocol missing phase: {phase}");
    }

    test_complete!("t810_19_drill_protocol_defined");
}

// ============================================================================
// Tests: Section 9 - Quality gate definitions
// ============================================================================

#[test]
fn t810_20_quality_gates_defined() {
    init_test("t810_20_quality_gates_defined");

    let doc = load_playbook();

    for gate in [
        "IR-01", "IR-02", "IR-03", "IR-04", "IR-05", "IR-06", "IR-07", "IR-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t810_20_quality_gates_defined");
}

// ============================================================================
// Tests: Section 10 - Cross-reference and evidence validation
// ============================================================================

#[test]
fn t810_21_prerequisites_referenced() {
    init_test("t810_21_prerequisites_referenced");

    let doc = load_playbook();

    assert!(
        doc.contains("asupersync-2oh2u.11.11"),
        "must reference T9.11 diagnostics UX"
    );
    assert!(
        doc.contains("asupersync-2oh2u.10.13"),
        "must reference T8.13 golden corpus"
    );
    assert!(
        doc.contains("asupersync-2oh2u.10.12"),
        "must reference T8.12 logging gates"
    );

    test_complete!("t810_21_prerequisites_referenced");
}

#[test]
fn t810_22_downstream_dependencies_referenced() {
    init_test("t810_22_downstream_dependencies_referenced");

    let doc = load_playbook();

    assert!(
        doc.contains("asupersync-2oh2u.10.9"),
        "must reference T8.9 readiness gate"
    );
    assert!(
        doc.contains("asupersync-2oh2u.11.12"),
        "must reference T9.12 operator enablement"
    );

    test_complete!("t810_22_downstream_dependencies_referenced");
}

#[test]
fn t810_23_evidence_links_reference_existing_docs() {
    init_test("t810_23_evidence_links_reference_existing_docs");

    let doc = load_playbook();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_diagnostics_ux_hardening_contract.md",
        "docs/tokio_cross_track_e2e_logging_gate_contract.md",
        "docs/tokio_web_grpc_migration_runbook.md",
        "docs/tokio_migration_cookbooks.md",
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
            "referenced doc must exist: {evidence_doc}"
        );
    }

    test_complete!("t810_23_evidence_links_reference_existing_docs");
}

#[test]
fn t810_24_ci_commands_present() {
    init_test("t810_24_ci_commands_present");

    let doc = load_playbook();

    assert!(
        doc.contains("cargo test"),
        "must include cargo test commands"
    );
    assert!(
        doc.contains("rch exec"),
        "must include rch exec for remote execution"
    );

    test_complete!("t810_24_ci_commands_present");
}

#[test]
fn t810_25_playbook_has_tables_and_code_blocks() {
    init_test("t810_25_playbook_has_tables_and_code_blocks");

    let doc = load_playbook();

    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 6,
        "must have at least 6 markdown tables, found {table_count}"
    );

    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 6,
        "must have at least 3 code blocks (6 fences), found {code_fences}"
    );

    test_complete!("t810_25_playbook_has_tables_and_code_blocks");
}
