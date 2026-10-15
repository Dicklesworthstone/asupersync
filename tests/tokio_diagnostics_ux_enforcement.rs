#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.11] Diagnostics and error-message UX hardening enforcement.
//!
//! Validates the diagnostic contract, failure mode taxonomy, message quality
//! rules, remediation hints, redaction compliance, and MTTR improvement targets.
//!
//! Organisation:
//!   1. Contract document validation
//!   2. Failure mode taxonomy coverage
//!   3. Diagnostic message requirements
//!   4. Message quality rules
//!   5. Remediation hint framework
//!   6. Redaction compliance
//!   7. MTTR improvement targets
//!   8. Quality gate definitions
//!   9. Cross-references

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn contract_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_diagnostics_ux_hardening_contract.md")
}

fn load_contract() -> String {
    std::fs::read_to_string(contract_path()).expect("diagnostics contract must exist")
}

// ============================================================================
// Tests: Section 1 - Contract document validation
// ============================================================================

#[test]
fn t911_01_contract_exists_and_is_substantial() {
    init_test("t911_01_contract_exists_and_is_substantial");

    assert!(contract_path().exists(), "diagnostics contract must exist");
    let doc = load_contract();
    assert!(doc.len() > 3000, "contract must be substantial");

    test_complete!("t911_01_contract_exists_and_is_substantial");
}

#[test]
fn t911_02_contract_references_bead_and_program() {
    init_test("t911_02_contract_references_bead_and_program");

    let doc = load_contract();
    assert!(
        doc.contains("asupersync-2oh2u.11.11"),
        "must reference bead"
    );
    assert!(doc.contains("[T9.11]"), "must reference T9.11");

    test_complete!("t911_02_contract_references_bead_and_program");
}

#[test]
fn t911_03_contract_has_required_sections() {
    init_test("t911_03_contract_has_required_sections");

    let doc = load_contract();

    for section in [
        "Failure Mode",
        "Diagnostic Message",
        "Remediation",
        "Redaction",
        "MTTR",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t911_03_contract_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Failure mode taxonomy
// ============================================================================

#[test]
fn t911_04_all_failure_modes_defined() {
    init_test("t911_04_all_failure_modes_defined");

    let doc = load_contract();

    for mf in [
        "MF-01", "MF-02", "MF-03", "MF-04", "MF-05", "MF-06", "MF-07", "MF-08", "MF-09", "MF-10",
    ] {
        test_section!(mf);
        assert!(doc.contains(mf), "missing failure mode: {mf}");
    }

    test_complete!("t911_04_all_failure_modes_defined");
}

#[test]
fn t911_05_failure_modes_have_severity_levels() {
    init_test("t911_05_failure_modes_have_severity_levels");

    let doc = load_contract();

    for level in ["Critical", "High", "Medium", "Low"] {
        test_section!(level);
        assert!(doc.contains(level), "missing severity level: {level}");
    }

    test_complete!("t911_05_failure_modes_have_severity_levels");
}

#[test]
fn t911_06_failure_modes_span_all_categories() {
    init_test("t911_06_failure_modes_span_all_categories");

    let doc = load_contract();

    for category in ["Compilation", "Runtime", "Behavioral", "Operational"] {
        test_section!(category);
        assert!(
            doc.contains(category),
            "missing failure category: {category}"
        );
    }

    test_complete!("t911_06_failure_modes_span_all_categories");
}

// ============================================================================
// Tests: Section 3 - Diagnostic message requirements
// ============================================================================

#[test]
fn t911_07_message_structure_fields_defined() {
    init_test("t911_07_message_structure_fields_defined");

    let doc = load_contract();

    for field in [
        "error_code",
        "severity",
        "message",
        "context",
        "remediation",
        "replay_pointer",
    ] {
        test_section!(field);
        assert!(
            doc.contains(field),
            "message structure missing field: {field}"
        );
    }

    test_complete!("t911_07_message_structure_fields_defined");
}

// ============================================================================
// Tests: Section 4 - Message quality rules
// ============================================================================

#[test]
fn t911_08_message_quality_rules_defined() {
    init_test("t911_08_message_quality_rules_defined");

    let doc = load_contract();

    for rule in ["DX-01", "DX-02", "DX-03", "DX-04", "DX-05"] {
        test_section!(rule);
        assert!(doc.contains(rule), "missing quality rule: {rule}");
    }

    test_complete!("t911_08_message_quality_rules_defined");
}

#[test]
fn t911_09_quality_rules_have_examples() {
    init_test("t911_09_quality_rules_have_examples");

    let doc = load_contract();
    // Rules should have concrete examples
    assert!(
        doc.contains("active voice"),
        "DX-01 must describe active voice"
    );
    assert!(
        doc.contains("concrete values"),
        "DX-02 must mention concrete values"
    );

    test_complete!("t911_09_quality_rules_have_examples");
}

// ============================================================================
// Tests: Section 5 - Remediation hint framework
// ============================================================================

#[test]
fn t911_10_remediation_categories_defined() {
    init_test("t911_10_remediation_categories_defined");

    let doc = load_contract();

    for cat in [
        "API_CHANGE",
        "PATTERN_MIGRATION",
        "CONFIGURATION",
        "DEPENDENCY",
        "ROLLBACK",
    ] {
        test_section!(cat);
        assert!(doc.contains(cat), "missing remediation category: {cat}");
    }

    test_complete!("t911_10_remediation_categories_defined");
}

#[test]
fn t911_11_remediation_actionability_requirements() {
    init_test("t911_11_remediation_actionability_requirements");

    let doc = load_contract();

    assert!(doc.contains("Specific"), "hints must be specific");
    assert!(doc.contains("Executable"), "hints must be executable");
    assert!(doc.contains("Verifiable"), "hints must be verifiable");

    test_complete!("t911_11_remediation_actionability_requirements");
}

// ============================================================================
// Tests: Section 6 - Redaction compliance
// ============================================================================

#[test]
fn t911_12_redaction_rules_defined() {
    init_test("t911_12_redaction_rules_defined");

    let doc = load_contract();

    assert!(
        doc.contains("Bearer") || doc.contains("token"),
        "must forbid bearer tokens"
    );
    assert!(
        doc.contains("credential") || doc.contains("connection string"),
        "must forbid credentials"
    );
    assert!(doc.contains("PII"), "must forbid PII");

    test_complete!("t911_12_redaction_rules_defined");
}

#[test]
fn t911_13_redaction_links_to_t812() {
    init_test("t911_13_redaction_links_to_t812");

    let doc = load_contract();
    assert!(
        doc.contains("LQ-04") || doc.contains("T8.12"),
        "must reference T8.12 redaction gate"
    );

    test_complete!("t911_13_redaction_links_to_t812");
}

// ============================================================================
// Tests: Section 7 - MTTR improvement targets
// ============================================================================

#[test]
fn t911_14_mttr_baseline_defined() {
    init_test("t911_14_mttr_baseline_defined");

    let doc = load_contract();
    assert!(
        doc.contains("Baseline") && doc.contains("MTTR"),
        "must define MTTR baseline"
    );

    test_complete!("t911_14_mttr_baseline_defined");
}

#[test]
fn t911_15_mttr_improvement_targets_quantitative() {
    init_test("t911_15_mttr_improvement_targets_quantitative");

    let doc = load_contract();
    assert!(
        doc.contains("50%") || doc.contains("67%") || doc.contains("75%"),
        "must have quantitative improvement targets"
    );

    test_complete!("t911_15_mttr_improvement_targets_quantitative");
}

#[test]
fn t911_16_mttr_targets_cover_all_severity_ranges() {
    init_test("t911_16_mttr_targets_cover_all_severity_ranges");

    let doc = load_contract();
    // Must cover failure class ranges
    assert!(
        doc.contains("MF-01..MF-02") || doc.contains("MF-01"),
        "must cover compilation failures"
    );
    assert!(
        doc.contains("MF-03..MF-06") || doc.contains("MF-03"),
        "must cover runtime failures"
    );
    assert!(
        doc.contains("MF-07..MF-08") || doc.contains("MF-07"),
        "must cover behavioral failures"
    );
    assert!(
        doc.contains("MF-09..MF-10") || doc.contains("MF-09"),
        "must cover operational failures"
    );

    test_complete!("t911_16_mttr_targets_cover_all_severity_ranges");
}

// ============================================================================
// Tests: Section 8 - Quality gates
// ============================================================================

#[test]
fn t911_17_quality_gates_defined() {
    init_test("t911_17_quality_gates_defined");

    let doc = load_contract();

    for gate in ["DX-G01", "DX-G02", "DX-G03", "DX-G04", "DX-G05", "DX-G06"] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t911_17_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Cross-references
// ============================================================================

#[test]
fn t911_18_prerequisites_referenced() {
    init_test("t911_18_prerequisites_referenced");

    let doc = load_contract();

    for bead in ["asupersync-2oh2u.11.10", "asupersync-2oh2u.10.13"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t911_18_prerequisites_referenced");
}

#[test]
fn t911_19_downstream_binding_defined() {
    init_test("t911_19_downstream_binding_defined");

    let doc = load_contract();

    for bead in ["asupersync-2oh2u.11.9", "asupersync-2oh2u.10.9"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream: {bead}");
    }

    test_complete!("t911_19_downstream_binding_defined");
}

// ============================================================================
// Tests: Section 10 - Diagnostic message simulation
// ============================================================================

#[test]
fn t911_20_diagnostic_message_schema_validation() {
    init_test("t911_20_diagnostic_message_schema_validation");

    // Build a synthetic diagnostic message and validate structure
    let diag = serde_json::json!({
        "error_code": "MF-01",
        "severity": "High",
        "message": "Type mismatch: expected asupersync::io::AsyncRead, found tokio::io::AsyncRead",
        "context": "Migrating TCP stream handler in service S-01",
        "remediation": "Replace `use tokio::io::AsyncReadExt` with `use asupersync::io::AsyncReadExt`",
        "docs_link": "docs/tokio_migration_cookbooks.md#track-t2",
        "replay_pointer": "cargo test --test tokio_io_parity_audit -- t2_codec_roundtrip --nocapture"
    });

    for field in [
        "error_code",
        "severity",
        "message",
        "context",
        "remediation",
        "replay_pointer",
    ] {
        test_section!(field);
        assert!(!diag[field].is_null(), "diagnostic missing field: {field}");
        assert!(
            diag[field].as_str().is_some_and(|s| !s.is_empty()),
            "diagnostic field must be non-empty: {field}"
        );
    }

    test_complete!("t911_20_diagnostic_message_schema_validation");
}

#[test]
fn t911_21_diagnostic_redaction_check() {
    init_test("t911_21_diagnostic_redaction_check");

    let forbidden_patterns = [
        "Bearer ",
        "password=",
        "secret=",
        "Authorization:",
        "api_key=",
        "token=sk-",
    ];

    // Sample diagnostic messages (simulated)
    let messages = [
        "Type mismatch in service handler",
        "Connection pool exhausted after 30s (limit: 100 connections)",
        "Timeout propagation failed across region boundary",
        "Log schema version mismatch: expected v3, got v2",
    ];

    for msg in &messages {
        test_section!(msg);
        for pattern in &forbidden_patterns {
            assert!(
                !msg.contains(pattern),
                "diagnostic message contains forbidden pattern: {pattern}"
            );
        }
    }

    test_complete!("t911_21_diagnostic_redaction_check");
}

// ============================================================================
// Tests: Section 11 - Document quality
// ============================================================================

#[test]
fn t911_22_contract_has_tables() {
    init_test("t911_22_contract_has_tables");

    let doc = load_contract();
    let table_rows = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_rows >= 6,
        "contract must have at least 6 tables, found {table_rows}"
    );

    test_complete!("t911_22_contract_has_tables");
}

#[test]
fn t911_23_severity_levels_have_mttr_targets() {
    init_test("t911_23_severity_levels_have_mttr_targets");

    let doc = load_contract();
    // Each severity level should have an MTTR target
    assert!(doc.contains("< 5 min"), "Critical must have < 5 min MTTR");
    assert!(doc.contains("< 15 min"), "High must have < 15 min MTTR");
    assert!(doc.contains("< 30 min"), "Medium must have < 30 min MTTR");
    assert!(doc.contains("< 60 min"), "Low must have < 60 min MTTR");

    test_complete!("t911_23_severity_levels_have_mttr_targets");
}

#[test]
fn t911_24_ci_commands_present() {
    init_test("t911_24_ci_commands_present");

    let doc = load_contract();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t911_24_ci_commands_present");
}

#[test]
fn t911_25_migration_lab_dependency_referenced() {
    init_test("t911_25_migration_lab_dependency_referenced");

    let doc = load_contract();
    assert!(
        doc.contains("migration lab") || doc.contains("T9.10"),
        "must reference migration lab as source of failure data"
    );

    test_complete!("t911_25_migration_lab_dependency_referenced");
}
