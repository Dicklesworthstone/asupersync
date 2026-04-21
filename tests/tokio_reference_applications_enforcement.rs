#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.4] Reference applications and templates enforcement.
//!
//! Validates the reference application catalog, template library, test suite
//! requirements, structured logging conformance, operational requirements,
//! migration lab integration, and documentation standards.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Application catalog coverage
//!   3. Test suite requirements
//!   4. Structured logging requirements
//!   5. Operational requirements
//!   6. Template library
//!   7. Migration lab integration
//!   8. Quality gate definitions
//!   9. Evidence link validation
//!  10. Cross-reference validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn contract_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_reference_applications_templates.md")
}

fn load_contract() -> String {
    std::fs::read_to_string(contract_path()).expect("reference apps contract must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t94_01_contract_exists_and_is_substantial() {
    init_test("t94_01_contract_exists_and_is_substantial");

    assert!(
        contract_path().exists(),
        "reference apps contract must exist"
    );
    let doc = load_contract();
    assert!(doc.len() > 3000, "contract must be substantial");

    test_complete!("t94_01_contract_exists_and_is_substantial");
}

#[test]
fn t94_02_contract_references_bead_and_program() {
    init_test("t94_02_contract_references_bead_and_program");

    let doc = load_contract();
    assert!(doc.contains("asupersync-2oh2u.11.4"), "must reference bead");
    assert!(doc.contains("[T9.4]"), "must reference T9.4");

    test_complete!("t94_02_contract_references_bead_and_program");
}

#[test]
fn t94_03_contract_has_required_sections() {
    init_test("t94_03_contract_has_required_sections");

    let doc = load_contract();

    for section in [
        "Application Catalog",
        "Template",
        "Test Suite",
        "Structured Logging",
        "Operational",
        "Migration Lab",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t94_03_contract_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Application catalog coverage
// ============================================================================

#[test]
fn t94_04_all_reference_apps_defined() {
    init_test("t94_04_all_reference_apps_defined");

    let doc = load_contract();

    for app in [
        "RA-01", "RA-02", "RA-03", "RA-04", "RA-05", "RA-06", "RA-07", "RA-08",
    ] {
        test_section!(app);
        assert!(doc.contains(app), "missing reference app: {app}");
    }

    test_complete!("t94_04_all_reference_apps_defined");
}

#[test]
fn t94_05_apps_cover_all_tracks() {
    init_test("t94_05_apps_cover_all_tracks");

    let doc = load_contract();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(
            doc.contains(track),
            "reference apps must cover track: {track}"
        );
    }

    test_complete!("t94_05_apps_cover_all_tracks");
}

#[test]
fn t94_06_app_complexity_levels_present() {
    init_test("t94_06_app_complexity_levels_present");

    let doc = load_contract();

    for level in ["Low", "Medium", "High"] {
        test_section!(level);
        assert!(doc.contains(level), "missing complexity level: {level}");
    }

    test_complete!("t94_06_app_complexity_levels_present");
}

#[test]
fn t94_07_standard_structure_defined() {
    init_test("t94_07_standard_structure_defined");

    let doc = load_contract();

    for component in ["main.rs", "config.rs", "Cargo.toml", "README.md"] {
        test_section!(component);
        assert!(
            doc.contains(component),
            "standard structure must include: {component}"
        );
    }

    test_complete!("t94_07_standard_structure_defined");
}

// ============================================================================
// Tests: Section 3 - Test suite requirements
// ============================================================================

#[test]
fn t94_08_test_requirements_defined() {
    init_test("t94_08_test_requirements_defined");

    let doc = load_contract();

    for req in ["TR-01", "TR-02", "TR-03", "TR-04", "TR-05"] {
        test_section!(req);
        assert!(doc.contains(req), "missing test requirement: {req}");
    }

    test_complete!("t94_08_test_requirements_defined");
}

#[test]
fn t94_09_test_categories_covered() {
    init_test("t94_09_test_categories_covered");

    let doc = load_contract();

    for category in ["Unit", "Integration", "Cancellation", "Determinism"] {
        test_section!(category);
        assert!(
            doc.contains(category),
            "test categories must include: {category}"
        );
    }

    test_complete!("t94_09_test_categories_covered");
}

// ============================================================================
// Tests: Section 4 - Structured logging requirements
// ============================================================================

#[test]
fn t94_10_logging_requirements_defined() {
    init_test("t94_10_logging_requirements_defined");

    let doc = load_contract();

    for req in ["SL-01", "SL-02", "SL-03", "SL-04", "SL-05"] {
        test_section!(req);
        assert!(doc.contains(req), "missing logging requirement: {req}");
    }

    test_complete!("t94_10_logging_requirements_defined");
}

#[test]
fn t94_11_logging_covers_key_concerns() {
    init_test("t94_11_logging_covers_key_concerns");

    let doc = load_contract();

    assert!(
        doc.contains("correlation"),
        "logging must require correlation IDs"
    );
    assert!(
        doc.contains("Redact") || doc.contains("redact"),
        "logging must require redaction"
    );
    assert!(
        doc.contains("replay"),
        "logging must require replay pointers"
    );

    test_complete!("t94_11_logging_covers_key_concerns");
}

// ============================================================================
// Tests: Section 5 - Operational requirements
// ============================================================================

#[test]
fn t94_12_operational_requirements_defined() {
    init_test("t94_12_operational_requirements_defined");

    let doc = load_contract();

    for req in ["OP-01", "OP-02", "OP-03", "OP-04", "OP-05"] {
        test_section!(req);
        assert!(doc.contains(req), "missing operational requirement: {req}");
    }

    test_complete!("t94_12_operational_requirements_defined");
}

#[test]
fn t94_13_operational_covers_production_concerns() {
    init_test("t94_13_operational_covers_production_concerns");

    let doc = load_contract();

    assert!(doc.contains("Health"), "must require health checks");
    assert!(
        doc.contains("Metrics") || doc.contains("metrics"),
        "must require metrics"
    );
    assert!(
        doc.contains("SIGTERM") || doc.contains("graceful"),
        "must require graceful shutdown"
    );

    test_complete!("t94_13_operational_covers_production_concerns");
}

// ============================================================================
// Tests: Section 6 - Template library
// ============================================================================

#[test]
fn t94_14_all_templates_defined() {
    init_test("t94_14_all_templates_defined");

    let doc = load_contract();

    for template in ["TM-01", "TM-02", "TM-03", "TM-04", "TM-05", "TM-06"] {
        test_section!(template);
        assert!(doc.contains(template), "missing template: {template}");
    }

    test_complete!("t94_14_all_templates_defined");
}

// ============================================================================
// Tests: Section 7 - Migration lab integration
// ============================================================================

#[test]
fn t94_15_migration_lab_scripts_specified() {
    init_test("t94_15_migration_lab_scripts_specified");

    let doc = load_contract();

    assert!(
        doc.contains("migration_lab"),
        "must specify migration lab scripts"
    );
    assert!(
        doc.contains("incident_drill"),
        "must specify incident drill scripts"
    );
    assert!(
        doc.contains("migration-lab-results-v1"),
        "lab results must use v1 schema"
    );

    test_complete!("t94_15_migration_lab_scripts_specified");
}

// ============================================================================
// Tests: Section 8 - Quality gate definitions
// ============================================================================

#[test]
fn t94_16_quality_gates_defined() {
    init_test("t94_16_quality_gates_defined");

    let doc = load_contract();

    for gate in [
        "RA-G01", "RA-G02", "RA-G03", "RA-G04", "RA-G05", "RA-G06", "RA-G07", "RA-G08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t94_16_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Evidence link validation
// ============================================================================

#[test]
fn t94_17_prerequisites_referenced() {
    init_test("t94_17_prerequisites_referenced");

    let doc = load_contract();

    for bead in [
        "asupersync-2oh2u.10.13",
        "asupersync-2oh2u.10.12",
        "asupersync-2oh2u.11.2",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t94_17_prerequisites_referenced");
}

#[test]
fn t94_18_downstream_referenced() {
    init_test("t94_18_downstream_referenced");

    let doc = load_contract();
    assert!(
        doc.contains("asupersync-2oh2u.11.7"),
        "must reference T9.7 downstream"
    );

    test_complete!("t94_18_downstream_referenced");
}

#[test]
fn t94_19_evidence_docs_exist() {
    init_test("t94_19_evidence_docs_exist");

    let doc = load_contract();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_golden_log_corpus_contract.md",
        "docs/tokio_migration_cookbooks.md",
        "docs/tokio_incident_response_rollback_playbooks.md",
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

    test_complete!("t94_19_evidence_docs_exist");
}

// ============================================================================
// Tests: Section 10 - Cross-reference and document quality
// ============================================================================

#[test]
fn t94_20_documentation_requirements_defined() {
    init_test("t94_20_documentation_requirements_defined");

    let doc = load_contract();

    for doc_req in ["DOC-01", "DOC-02", "DOC-03", "DOC-04", "DOC-05", "DOC-06"] {
        test_section!(doc_req);
        assert!(doc.contains(doc_req), "missing doc requirement: {doc_req}");
    }

    test_complete!("t94_20_documentation_requirements_defined");
}

#[test]
fn t94_21_contract_has_tables() {
    init_test("t94_21_contract_has_tables");

    let doc = load_contract();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 6,
        "must have at least 6 tables, found {table_count}"
    );

    test_complete!("t94_21_contract_has_tables");
}

#[test]
fn t94_22_contract_has_code_blocks() {
    init_test("t94_22_contract_has_code_blocks");

    let doc = load_contract();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 4,
        "must have at least 2 code blocks, found {code_fences} fences"
    );

    test_complete!("t94_22_contract_has_code_blocks");
}

#[test]
fn t94_23_ci_commands_present() {
    init_test("t94_23_ci_commands_present");

    let doc = load_contract();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t94_23_ci_commands_present");
}

#[test]
fn t94_24_multi_track_app_defined() {
    init_test("t94_24_multi_track_app_defined");

    let doc = load_contract();
    assert!(
        doc.contains("Multi-track") || doc.contains("full-stack"),
        "must define a multi-track reference app"
    );

    test_complete!("t94_24_multi_track_app_defined");
}

#[test]
fn t94_25_interop_bridge_app_defined() {
    init_test("t94_25_interop_bridge_app_defined");

    let doc = load_contract();
    assert!(
        doc.contains("interop-bridge") || doc.contains("tokio-compat"),
        "must define interop bridge reference app"
    );

    test_complete!("t94_25_interop_bridge_app_defined");
}
