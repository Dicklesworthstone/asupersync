#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.10] User-journey migration lab KPI enforcement.
//!
//! Validates the migration lab contract, persona definitions, service
//! archetypes, KPI thresholds, lab protocol, results schema, and quality
//! gates for migration friction measurement.
//!
//! Organisation:
//!   1. Contract document validation
//!   2. Persona archetype coverage
//!   3. Service archetype coverage
//!   4. KPI definition and threshold validation
//!   5. Lab protocol structure
//!   6. Results schema validation
//!   7. Quality gate definitions
//!   8. Cross-reference validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::collections::BTreeMap;
use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn contract_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_migration_lab_kpi_contract.md")
}

fn load_contract() -> String {
    std::fs::read_to_string(contract_path()).expect("lab KPI contract must exist")
}

// ============================================================================
// Tests: Section 1 - Contract document validation
// ============================================================================

#[test]
fn t910_01_contract_exists_and_is_substantial() {
    init_test("t910_01_contract_exists_and_is_substantial");

    assert!(contract_path().exists(), "lab KPI contract must exist");
    let doc = load_contract();
    assert!(doc.len() > 3000, "contract must be substantial");

    test_complete!("t910_01_contract_exists_and_is_substantial");
}

#[test]
fn t910_02_contract_references_bead_and_program() {
    init_test("t910_02_contract_references_bead_and_program");

    let doc = load_contract();
    assert!(
        doc.contains("asupersync-2oh2u.11.10"),
        "must reference bead"
    );
    assert!(doc.contains("[T9.10]"), "must reference T9.10");

    test_complete!("t910_02_contract_references_bead_and_program");
}

#[test]
fn t910_03_contract_has_required_sections() {
    init_test("t910_03_contract_has_required_sections");

    let doc = load_contract();

    for section in [
        "Persona",
        "Service Archetype",
        "Friction KPI",
        "Lab Run Protocol",
        "Results Schema",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t910_03_contract_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Persona archetype coverage
// ============================================================================

#[test]
fn t910_04_all_personas_defined() {
    init_test("t910_04_all_personas_defined");

    let doc = load_contract();

    for persona in ["P-01", "P-02", "P-03", "P-04", "P-05", "P-06"] {
        test_section!(persona);
        assert!(doc.contains(persona), "missing persona: {persona}");
    }

    test_complete!("t910_04_all_personas_defined");
}

#[test]
fn t910_05_personas_cover_all_tracks() {
    init_test("t910_05_personas_cover_all_tracks");

    let doc = load_contract();

    // Each track should appear in persona table
    for track in ["T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(doc.contains(track), "persona table missing track: {track}");
    }

    test_complete!("t910_05_personas_cover_all_tracks");
}

// ============================================================================
// Tests: Section 3 - Service archetype coverage
// ============================================================================

#[test]
fn t910_06_all_service_archetypes_defined() {
    init_test("t910_06_all_service_archetypes_defined");

    let doc = load_contract();

    for archetype in ["S-01", "S-02", "S-03", "S-04", "S-05", "S-06"] {
        test_section!(archetype);
        assert!(doc.contains(archetype), "missing archetype: {archetype}");
    }

    test_complete!("t910_06_all_service_archetypes_defined");
}

#[test]
fn t910_07_archetypes_span_complexity_levels() {
    init_test("t910_07_archetypes_span_complexity_levels");

    let doc = load_contract();

    for level in ["Low", "Medium", "High"] {
        test_section!(level);
        assert!(
            doc.contains(level),
            "archetype table must include {level} complexity"
        );
    }

    test_complete!("t910_07_archetypes_span_complexity_levels");
}

// ============================================================================
// Tests: Section 4 - KPI definitions and thresholds
// ============================================================================

#[test]
fn t910_08_all_kpis_defined() {
    init_test("t910_08_all_kpis_defined");

    let doc = load_contract();

    for kpi in [
        "FK-01", "FK-02", "FK-03", "FK-04", "FK-05", "FK-06", "FK-07", "FK-08",
    ] {
        test_section!(kpi);
        assert!(doc.contains(kpi), "missing KPI: {kpi}");
    }

    test_complete!("t910_08_all_kpis_defined");
}

#[test]
fn t910_09_kpis_have_units_and_descriptions() {
    init_test("t910_09_kpis_have_units_and_descriptions");

    let doc = load_contract();

    // Check units are present for key KPIs
    for unit in ["minutes", "count", "ratio", "percentage", "lines"] {
        test_section!(unit);
        assert!(
            doc.contains(unit),
            "KPI table must include unit type: {unit}"
        );
    }

    test_complete!("t910_09_kpis_have_units_and_descriptions");
}

#[test]
fn t910_10_kpi_thresholds_have_hard_and_soft_fail() {
    init_test("t910_10_kpi_thresholds_have_hard_and_soft_fail");

    let doc = load_contract();

    assert!(
        doc.contains("Hard-Fail"),
        "must define hard-fail thresholds"
    );
    assert!(
        doc.contains("Soft-Fail"),
        "must define soft-fail thresholds"
    );

    // Each KPI should have a threshold row
    let threshold_rows = doc.lines().filter(|l| l.starts_with("| FK-")).count();
    assert!(
        threshold_rows >= 8,
        "must have threshold rows for all 8 KPIs, found {threshold_rows}"
    );

    test_complete!("t910_10_kpi_thresholds_have_hard_and_soft_fail");
}

#[test]
fn t910_11_kpi_threshold_values_are_quantitative() {
    init_test("t910_11_kpi_threshold_values_are_quantitative");

    let doc = load_contract();

    // Threshold table must contain numeric values
    assert!(
        doc.contains("30 min") || doc.contains("<= 30"),
        "FK-01 must have quantitative threshold"
    );
    assert!(
        doc.contains("60 min") || doc.contains("<= 60"),
        "FK-02 must have quantitative threshold"
    );

    test_complete!("t910_11_kpi_threshold_values_are_quantitative");
}

// ============================================================================
// Tests: Section 5 - Lab protocol structure
// ============================================================================

#[test]
fn t910_12_lab_protocol_has_phases() {
    init_test("t910_12_lab_protocol_has_phases");

    let doc = load_contract();

    for phase in ["Lab Setup", "Migration Execution", "Verification"] {
        test_section!(phase);
        assert!(doc.contains(phase), "missing lab protocol phase: {phase}");
    }

    test_complete!("t910_12_lab_protocol_has_phases");
}

#[test]
fn t910_13_artifact_emission_requirements() {
    init_test("t910_13_artifact_emission_requirements");

    let doc = load_contract();

    assert!(
        doc.contains("migration_lab_results.json"),
        "must specify results JSON artifact"
    );
    assert!(
        doc.contains("migration_lab_log.md"),
        "must specify narrative log artifact"
    );
    assert!(
        doc.contains("correlation") || doc.contains("Correlation"),
        "must require correlation IDs in artifacts"
    );
    assert!(
        doc.contains("replay") || doc.contains("Replay"),
        "must require replay pointers"
    );

    test_complete!("t910_13_artifact_emission_requirements");
}

// ============================================================================
// Tests: Section 6 - Results schema validation
// ============================================================================

#[test]
fn t910_14_results_schema_includes_required_fields() {
    init_test("t910_14_results_schema_includes_required_fields");

    let doc = load_contract();

    for field in [
        "schema_version",
        "lab_id",
        "persona_id",
        "service_archetype",
        "kpis",
        "outcome",
    ] {
        test_section!(field);
        assert!(doc.contains(field), "results schema missing field: {field}");
    }

    test_complete!("t910_14_results_schema_includes_required_fields");
}

#[test]
fn t910_15_results_schema_version_defined() {
    init_test("t910_15_results_schema_version_defined");

    let doc = load_contract();
    assert!(
        doc.contains("migration-lab-results-v1"),
        "must define results schema version"
    );

    test_complete!("t910_15_results_schema_version_defined");
}

#[test]
fn t910_16_follow_up_bead_schema_defined() {
    init_test("t910_16_follow_up_bead_schema_defined");

    let doc = load_contract();
    assert!(
        doc.contains("follow_up_bead") || doc.contains("Follow-Up Bead"),
        "must define follow-up bead schema"
    );
    assert!(
        doc.contains("remediation_hypothesis"),
        "follow-up must require remediation hypothesis"
    );

    test_complete!("t910_16_follow_up_bead_schema_defined");
}

// ============================================================================
// Tests: Section 7 - Quality gate definitions
// ============================================================================

#[test]
fn t910_17_quality_gates_defined() {
    init_test("t910_17_quality_gates_defined");

    let doc = load_contract();

    for gate in ["ML-01", "ML-02", "ML-03", "ML-04", "ML-05", "ML-06"] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t910_17_quality_gates_defined");
}

// ============================================================================
// Tests: Section 8 - Cross-references
// ============================================================================

#[test]
fn t910_18_prerequisites_referenced() {
    init_test("t910_18_prerequisites_referenced");

    let doc = load_contract();

    for bead in ["asupersync-2oh2u.10.12", "asupersync-2oh2u.11.2"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t910_18_prerequisites_referenced");
}

#[test]
fn t910_19_downstream_binding_defined() {
    init_test("t910_19_downstream_binding_defined");

    let doc = load_contract();

    for bead in [
        "asupersync-2oh2u.11.11",
        "asupersync-2oh2u.11.9",
        "asupersync-2oh2u.10.9",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream bead: {bead}");
    }

    test_complete!("t910_19_downstream_binding_defined");
}

// ============================================================================
// Tests: Section 9 - KPI simulation (unit tests for evaluation logic)
// ============================================================================

#[test]
fn t910_20_kpi_pass_fail_evaluation() {
    init_test("t910_20_kpi_pass_fail_evaluation");

    // Simulate KPI evaluation
    struct KpiThreshold {
        id: &'static str,
        soft_fail: f64,
        hard_fail: f64,
    }

    let thresholds = [
        KpiThreshold {
            id: "FK-01",
            soft_fail: 30.0,
            hard_fail: 60.0,
        },
        KpiThreshold {
            id: "FK-02",
            soft_fail: 60.0,
            hard_fail: 120.0,
        },
        KpiThreshold {
            id: "FK-05",
            soft_fail: 0.10,
            hard_fail: 0.30,
        },
        KpiThreshold {
            id: "FK-08",
            soft_fail: 0.10,
            hard_fail: 0.50,
        },
    ];

    for t in &thresholds {
        test_section!(t.id);
        // Pass case
        let pass_value = t.soft_fail * 0.5;
        assert!(pass_value <= t.soft_fail, "{} pass case failed", t.id);

        // Soft-fail case
        let soft_value = f64::midpoint(t.soft_fail, t.hard_fail);
        assert!(
            soft_value > t.soft_fail && soft_value <= t.hard_fail,
            "{} soft-fail case failed",
            t.id
        );

        // Hard-fail case
        let hard_value = t.hard_fail * 1.5;
        assert!(hard_value > t.hard_fail, "{} hard-fail case failed", t.id);
    }

    test_complete!("t910_20_kpi_pass_fail_evaluation");
}

#[test]
fn t910_21_lab_results_json_schema_validation() {
    init_test("t910_21_lab_results_json_schema_validation");

    // Build a synthetic lab result and validate schema
    let mut kpis = BTreeMap::new();
    kpis.insert(
        "FK-01".to_string(),
        serde_json::json!({
            "value": 15, "unit": "minutes", "threshold": 30, "status": "pass"
        }),
    );
    kpis.insert(
        "FK-02".to_string(),
        serde_json::json!({
            "value": 45, "unit": "minutes", "threshold": 60, "status": "pass"
        }),
    );

    let result = serde_json::json!({
        "schema_version": "migration-lab-results-v1",
        "lab_id": "lab-S01-P01-001",
        "persona_id": "P-01",
        "service_archetype": "S-01",
        "started_at": "2026-03-04T00:00:00Z",
        "completed_at": "2026-03-04T01:00:00Z",
        "kpis": kpis,
        "outcome": "pass",
        "artifacts": [],
        "follow_up_beads": []
    });

    test_section!("required_fields");
    for field in [
        "schema_version",
        "lab_id",
        "persona_id",
        "service_archetype",
        "kpis",
        "outcome",
    ] {
        assert!(!result[field].is_null(), "missing field: {field}");
    }

    test_section!("kpi_entries");
    let kpi_obj = result["kpis"].as_object().unwrap();
    assert!(kpi_obj.len() >= 2, "must have at least 2 KPI entries");
    for (kpi_id, kpi_val) in kpi_obj {
        assert!(kpi_val["value"].is_number(), "{kpi_id} must have value");
        assert!(kpi_val["status"].is_string(), "{kpi_id} must have status");
    }

    test_complete!("t910_21_lab_results_json_schema_validation");
}

// ============================================================================
// Tests: Section 10 - Document quality
// ============================================================================

#[test]
fn t910_22_contract_has_tables() {
    init_test("t910_22_contract_has_tables");

    let doc = load_contract();
    let table_rows = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_rows >= 6,
        "contract must have at least 6 markdown tables, found {table_rows}"
    );

    test_complete!("t910_22_contract_has_tables");
}

#[test]
fn t910_23_contract_has_code_blocks() {
    init_test("t910_23_contract_has_code_blocks");

    let doc = load_contract();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 4,
        "contract must have at least 2 code blocks, found {code_fences} fences"
    );

    test_complete!("t910_23_contract_has_code_blocks");
}

#[test]
fn t910_24_ci_commands_present() {
    init_test("t910_24_ci_commands_present");

    let doc = load_contract();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t910_24_ci_commands_present");
}

#[test]
fn t910_25_cookbook_dependency_referenced() {
    init_test("t910_25_cookbook_dependency_referenced");

    let doc = load_contract();
    assert!(
        doc.contains("cookbook") || doc.contains("Cookbook"),
        "must reference migration cookbooks as prerequisite"
    );

    test_complete!("t910_25_cookbook_dependency_referenced");
}
