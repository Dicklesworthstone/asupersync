#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.12] Operator enablement pack enforcement.
//!
//! Validates symptom-based runbooks, escalation decision trees, support
//! handoff templates, postmortem checklists, drill execution guides, and
//! quality gates for the operator enablement pack.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Symptom catalog coverage
//!   3. Runbook entry validation
//!   4. Escalation decision trees
//!   5. Support handoff templates
//!   6. Drill execution guide
//!   7. Quality gate definitions
//!   8. Evidence link validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn pack_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_operator_enablement_pack.md")
}

fn load_pack() -> String {
    std::fs::read_to_string(pack_path()).expect("operator enablement pack must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t912_01_pack_exists_and_is_substantial() {
    init_test("t912_01_pack_exists_and_is_substantial");

    assert!(pack_path().exists(), "operator enablement pack must exist");
    let doc = load_pack();
    assert!(doc.len() > 3000, "pack must be substantial");

    test_complete!("t912_01_pack_exists_and_is_substantial");
}

#[test]
fn t912_02_pack_references_bead_and_program() {
    init_test("t912_02_pack_references_bead_and_program");

    let doc = load_pack();
    assert!(
        doc.contains("asupersync-2oh2u.11.12"),
        "must reference bead"
    );
    assert!(doc.contains("[T9.12]"), "must reference T9.12");

    test_complete!("t912_02_pack_references_bead_and_program");
}

#[test]
fn t912_03_pack_has_required_sections() {
    init_test("t912_03_pack_has_required_sections");

    let doc = load_pack();

    for section in [
        "Symptom",
        "Runbook",
        "Escalation",
        "Handoff",
        "Postmortem",
        "Drill",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t912_03_pack_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Symptom catalog coverage
// ============================================================================

#[test]
fn t912_04_all_symptoms_defined() {
    init_test("t912_04_all_symptoms_defined");

    let doc = load_pack();

    for sy in [
        "SY-01", "SY-02", "SY-03", "SY-04", "SY-05", "SY-06", "SY-07", "SY-08",
    ] {
        test_section!(sy);
        assert!(doc.contains(sy), "missing symptom: {sy}");
    }

    test_complete!("t912_04_all_symptoms_defined");
}

#[test]
fn t912_05_symptoms_have_replay_pointers() {
    init_test("t912_05_symptoms_have_replay_pointers");

    let doc = load_pack();

    // Each runbook entry should have a replay pointer
    let replay_count = doc.matches("Replay").count();
    assert!(
        replay_count >= 8,
        "each symptom runbook must have replay pointer, found {replay_count}"
    );

    test_complete!("t912_05_symptoms_have_replay_pointers");
}

#[test]
fn t912_06_symptoms_reference_correlation_ids() {
    init_test("t912_06_symptoms_reference_correlation_ids");

    let doc = load_pack();

    assert!(
        doc.contains("correlation_id") || doc.contains("correlation"),
        "runbooks must reference correlation IDs"
    );

    test_complete!("t912_06_symptoms_reference_correlation_ids");
}

// ============================================================================
// Tests: Section 3 - Runbook entry validation
// ============================================================================

#[test]
fn t912_07_runbook_entries_have_steps() {
    init_test("t912_07_runbook_entries_have_steps");

    let doc = load_pack();

    // Each runbook should have numbered steps
    assert!(
        doc.contains("1.") && doc.contains("2.") && doc.contains("3."),
        "runbook entries must have numbered steps"
    );

    test_complete!("t912_07_runbook_entries_have_steps");
}

#[test]
fn t912_08_runbook_covers_key_scenarios() {
    init_test("t912_08_runbook_covers_key_scenarios");

    let doc = load_pack();

    for scenario in [
        "Pool Exhaustion",
        "Timeout",
        "File Handle Leak",
        "Ordering",
        "Adapter Panic",
    ] {
        test_section!(scenario);
        assert!(
            doc.contains(scenario),
            "runbook must cover scenario: {scenario}"
        );
    }

    test_complete!("t912_08_runbook_covers_key_scenarios");
}

// ============================================================================
// Tests: Section 4 - Escalation decision trees
// ============================================================================

#[test]
fn t912_09_escalation_matrix_defined() {
    init_test("t912_09_escalation_matrix_defined");

    let doc = load_pack();

    assert!(doc.contains("Escalation"), "must define escalation matrix");
    assert!(
        doc.contains("SEV-1") && doc.contains("SEV-2"),
        "escalation must cover severity levels"
    );
    assert!(doc.contains("On-call"), "must reference on-call engineer");

    test_complete!("t912_09_escalation_matrix_defined");
}

#[test]
fn t912_10_communication_templates_defined() {
    init_test("t912_10_communication_templates_defined");

    let doc = load_pack();

    for ct in ["CT-01", "CT-02", "CT-03", "CT-04"] {
        test_section!(ct);
        assert!(doc.contains(ct), "missing communication template: {ct}");
    }

    test_complete!("t912_10_communication_templates_defined");
}

// ============================================================================
// Tests: Section 5 - Support handoff templates
// ============================================================================

#[test]
fn t912_11_handoff_schema_defined() {
    init_test("t912_11_handoff_schema_defined");

    let doc = load_pack();

    assert!(
        doc.contains("support-handoff-v1"),
        "must define handoff schema version"
    );

    for field in [
        "handoff_id",
        "incident_id",
        "actions_taken",
        "pending_actions",
        "replay_pointers",
    ] {
        test_section!(field);
        assert!(doc.contains(field), "handoff schema missing: {field}");
    }

    test_complete!("t912_11_handoff_schema_defined");
}

#[test]
fn t912_12_postmortem_checklist_complete() {
    init_test("t912_12_postmortem_checklist_complete");

    let doc = load_pack();

    for pm in [
        "PM-01", "PM-02", "PM-03", "PM-04", "PM-05", "PM-06", "PM-07", "PM-08", "PM-09", "PM-10",
    ] {
        test_section!(pm);
        assert!(doc.contains(pm), "missing postmortem item: {pm}");
    }

    test_complete!("t912_12_postmortem_checklist_complete");
}

// ============================================================================
// Tests: Section 6 - Drill execution guide
// ============================================================================

#[test]
fn t912_13_pre_drill_checklist_defined() {
    init_test("t912_13_pre_drill_checklist_defined");

    let doc = load_pack();

    for pd in ["PD-01", "PD-02", "PD-03", "PD-04", "PD-05"] {
        test_section!(pd);
        assert!(doc.contains(pd), "missing pre-drill item: {pd}");
    }

    test_complete!("t912_13_pre_drill_checklist_defined");
}

#[test]
fn t912_14_drill_scripts_present() {
    init_test("t912_14_drill_scripts_present");

    let doc = load_pack();

    assert!(
        doc.contains("cargo test"),
        "drill scripts must include cargo test"
    );
    assert!(
        doc.contains("rch exec"),
        "drill scripts must include rch exec"
    );

    test_complete!("t912_14_drill_scripts_present");
}

#[test]
fn t912_15_drill_report_schema_defined() {
    init_test("t912_15_drill_report_schema_defined");

    let doc = load_pack();

    assert!(
        doc.contains("drill-report-v1"),
        "must define drill report schema version"
    );

    for field in [
        "drill_id",
        "detection_time",
        "response_time",
        "resolution_time",
        "sla_met",
    ] {
        test_section!(field);
        assert!(doc.contains(field), "drill report schema missing: {field}");
    }

    test_complete!("t912_15_drill_report_schema_defined");
}

// ============================================================================
// Tests: Section 7 - Quality gate definitions
// ============================================================================

#[test]
fn t912_16_quality_gates_defined() {
    init_test("t912_16_quality_gates_defined");

    let doc = load_pack();

    for gate in [
        "OE-01", "OE-02", "OE-03", "OE-04", "OE-05", "OE-06", "OE-07", "OE-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t912_16_quality_gates_defined");
}

// ============================================================================
// Tests: Section 8 - Evidence link validation
// ============================================================================

#[test]
fn t912_17_prerequisites_referenced() {
    init_test("t912_17_prerequisites_referenced");

    let doc = load_pack();

    for bead in [
        "asupersync-2oh2u.11.11",
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.11.7",
        "asupersync-2oh2u.10.10",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t912_17_prerequisites_referenced");
}

#[test]
fn t912_18_downstream_referenced() {
    init_test("t912_18_downstream_referenced");

    let doc = load_pack();
    assert!(
        doc.contains("asupersync-2oh2u.11.8"),
        "must reference T9.8 downstream"
    );

    test_complete!("t912_18_downstream_referenced");
}

#[test]
fn t912_19_evidence_docs_exist() {
    init_test("t912_19_evidence_docs_exist");

    let doc = load_pack();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_diagnostics_ux_hardening_contract.md",
        "docs/tokio_incident_response_rollback_playbooks.md",
        "docs/tokio_external_validation_benchmark_packs.md",
        "docs/tokio_golden_log_corpus_contract.md",
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

    test_complete!("t912_19_evidence_docs_exist");
}

#[test]
fn t912_20_pack_has_tables() {
    init_test("t912_20_pack_has_tables");

    let doc = load_pack();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 6,
        "must have at least 6 tables, found {table_count}"
    );

    test_complete!("t912_20_pack_has_tables");
}

#[test]
fn t912_21_pack_has_code_blocks() {
    init_test("t912_21_pack_has_code_blocks");

    let doc = load_pack();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 6,
        "must have at least 3 code blocks, found {code_fences} fences"
    );

    test_complete!("t912_21_pack_has_code_blocks");
}

#[test]
fn t912_22_handoff_simulation() {
    init_test("t912_22_handoff_simulation");

    let handoff = serde_json::json!({
        "schema_version": "support-handoff-v1",
        "handoff_id": "HO-20260304-001",
        "incident_id": "INC-20260304-001",
        "from_role": "On-call engineer",
        "to_role": "Track lead",
        "correlation_ids": ["inc-20260304-abc123"],
        "actions_taken": ["Contained pool exhaustion"],
        "pending_actions": ["Fix connection drop guard"]
    });

    assert_eq!(
        handoff["schema_version"].as_str().unwrap(),
        "support-handoff-v1"
    );
    assert!(
        !handoff["correlation_ids"].as_array().unwrap().is_empty(),
        "must have correlation IDs"
    );
    assert!(
        !handoff["pending_actions"].as_array().unwrap().is_empty(),
        "must have pending actions"
    );

    test_complete!("t912_22_handoff_simulation");
}

#[test]
fn t912_23_drill_report_simulation() {
    init_test("t912_23_drill_report_simulation");

    let report = serde_json::json!({
        "schema_version": "drill-report-v1",
        "drill_id": "DR-20260304-001",
        "drill_type": "DRILL-01",
        "detection_time_seconds": 3,
        "response_time_seconds": 45,
        "resolution_time_seconds": 180,
        "sla_met": true,
        "gaps_identified": []
    });

    assert!(report["sla_met"].as_bool().unwrap(), "SLA must be met");
    assert_eq!(
        report["detection_time_seconds"].as_i64().unwrap(),
        3,
        "detection time"
    );
    assert!(
        report["gaps_identified"].as_array().unwrap().is_empty(),
        "no gaps expected in passing drill"
    );

    test_complete!("t912_23_drill_report_simulation");
}

#[test]
fn t912_24_ci_commands_present() {
    init_test("t912_24_ci_commands_present");

    let doc = load_pack();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t912_24_ci_commands_present");
}

#[test]
fn t912_25_incident_classes_referenced() {
    init_test("t912_25_incident_classes_referenced");

    let doc = load_pack();

    // Symptoms should reference incident classes from T8.10
    for ic in ["IC-03", "IC-08", "IC-11", "IC-14", "IC-15"] {
        test_section!(ic);
        assert!(
            doc.contains(ic),
            "symptoms must reference incident class: {ic}"
        );
    }

    test_complete!("t912_25_incident_classes_referenced");
}
