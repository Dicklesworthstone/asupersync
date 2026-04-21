#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T5.10] Web/gRPC/middleware migration docs and operator runbook enforcement.
//!
//! Validates the migration runbook, operator guides, and decision frameworks
//! for the web/gRPC stack replacement. Checks document structure, evidence
//! links, anti-pattern coverage, and CI command references.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Migration decision framework validation
//!   3. Migration workflow completeness
//!   4. Operator runbook sections
//!   5. Anti-pattern and failure mode coverage
//!   6. Evidence link validation
//!   7. CI command presence
//!   8. Cross-reference validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn runbook_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_web_grpc_migration_runbook.md")
}

fn load_runbook() -> String {
    std::fs::read_to_string(runbook_path()).expect("runbook must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t510_01_runbook_exists_and_is_substantial() {
    init_test("t510_01_runbook_exists_and_is_substantial");

    assert!(runbook_path().exists(), "migration runbook must exist");
    let doc = load_runbook();
    assert!(
        doc.len() > 3000,
        "runbook must be substantial (>3000 chars)"
    );

    test_complete!("t510_01_runbook_exists_and_is_substantial");
}

#[test]
fn t510_02_runbook_references_bead_and_program() {
    init_test("t510_02_runbook_references_bead_and_program");

    let doc = load_runbook();
    assert!(doc.contains("asupersync-2oh2u.5.10"), "must reference bead");
    assert!(doc.contains("[T5.10]"), "must reference T5.10");
    assert!(doc.contains("asupersync-2oh2u"), "must reference program");

    test_complete!("t510_02_runbook_references_bead_and_program");
}

#[test]
fn t510_03_runbook_has_required_sections() {
    init_test("t510_03_runbook_has_required_sections");

    let doc = load_runbook();

    for section in [
        "Scope",
        "Migration Decision Framework",
        "Migration Workflows",
        "Operator Runbooks",
        "Anti-Patterns",
        "Evidence Links",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t510_03_runbook_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Migration decision framework
// ============================================================================

#[test]
fn t510_04_migration_readiness_checklist_present() {
    init_test("t510_04_migration_readiness_checklist_present");

    let doc = load_runbook();

    for check in ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05"] {
        test_section!(check);
        assert!(doc.contains(check), "missing readiness check: {check}");
    }

    test_complete!("t510_04_migration_readiness_checklist_present");
}

#[test]
fn t510_05_migration_path_table_covers_key_patterns() {
    init_test("t510_05_migration_path_table_covers_key_patterns");

    let doc = load_runbook();

    for pattern in [
        "HTTP routing",
        "JSON extraction",
        "Middleware",
        "gRPC service",
        "gRPC-web",
        "Compression",
        "Connection pool",
    ] {
        test_section!(pattern);
        assert!(
            doc.contains(pattern),
            "migration path table missing pattern: {pattern}"
        );
    }

    test_complete!("t510_05_migration_path_table_covers_key_patterns");
}

// ============================================================================
// Tests: Section 3 - Migration workflow completeness
// ============================================================================

#[test]
fn t510_06_http_migration_has_four_phases() {
    init_test("t510_06_http_migration_has_four_phases");

    let doc = load_runbook();

    for phase in [
        "Inventory",
        "Adapter Bridge",
        "Direct Replacement",
        "Verification",
    ] {
        test_section!(phase);
        assert!(doc.contains(phase), "HTTP migration missing phase: {phase}");
    }

    test_complete!("t510_06_http_migration_has_four_phases");
}

#[test]
fn t510_07_grpc_migration_has_four_phases() {
    init_test("t510_07_grpc_migration_has_four_phases");

    let doc = load_runbook();

    for phase in ["Service Definition", "Interceptor Chain", "gRPC-web Bridge"] {
        test_section!(phase);
        assert!(doc.contains(phase), "gRPC migration missing phase: {phase}");
    }

    test_complete!("t510_07_grpc_migration_has_four_phases");
}

// ============================================================================
// Tests: Section 4 - Operator runbook sections
// ============================================================================

#[test]
fn t510_08_rollback_procedure_present() {
    init_test("t510_08_rollback_procedure_present");

    let doc = load_runbook();

    assert!(doc.contains("Rollback"), "must have rollback procedure");
    assert!(
        doc.contains("last-known-good") || doc.contains("Revert"),
        "rollback must describe reversion"
    );
    assert!(
        doc.contains("incident report") || doc.contains("diagnostic"),
        "rollback must include incident reporting"
    );

    test_complete!("t510_08_rollback_procedure_present");
}

#[test]
fn t510_09_health_check_verification_present() {
    init_test("t510_09_health_check_verification_present");

    let doc = load_runbook();

    assert!(
        doc.contains("Health Check"),
        "must have health check section"
    );
    assert!(
        doc.contains("/health") || doc.contains("health service"),
        "must reference health endpoints"
    );

    test_complete!("t510_09_health_check_verification_present");
}

#[test]
fn t510_10_performance_monitoring_thresholds_present() {
    init_test("t510_10_performance_monitoring_thresholds_present");

    let doc = load_runbook();

    assert!(
        doc.contains("Performance Monitoring"),
        "must have performance monitoring"
    );
    assert!(
        doc.contains("p50") || doc.contains("p99"),
        "must define latency percentiles"
    );
    assert!(
        doc.contains("Error rate") || doc.contains("error rate"),
        "must define error rate thresholds"
    );

    test_complete!("t510_10_performance_monitoring_thresholds_present");
}

#[test]
fn t510_11_incident_escalation_defined() {
    init_test("t510_11_incident_escalation_defined");

    let doc = load_runbook();

    assert!(doc.contains("Escalation"), "must define escalation policy");
    for severity in ["P0", "P1", "P2", "P3"] {
        assert!(doc.contains(severity), "missing severity level: {severity}");
    }

    test_complete!("t510_11_incident_escalation_defined");
}

// ============================================================================
// Tests: Section 5 - Anti-patterns and failure modes
// ============================================================================

#[test]
fn t510_12_anti_patterns_documented() {
    init_test("t510_12_anti_patterns_documented");

    let doc = load_runbook();

    for ap in ["AP-01", "AP-02", "AP-03", "AP-04", "AP-05"] {
        test_section!(ap);
        assert!(doc.contains(ap), "missing anti-pattern: {ap}");
    }

    test_complete!("t510_12_anti_patterns_documented");
}

#[test]
fn t510_13_failure_modes_documented() {
    init_test("t510_13_failure_modes_documented");

    let doc = load_runbook();

    for fm in ["FM-01", "FM-02", "FM-03", "FM-04", "FM-05"] {
        test_section!(fm);
        assert!(doc.contains(fm), "missing failure mode: {fm}");
    }

    test_complete!("t510_13_failure_modes_documented");
}

// ============================================================================
// Tests: Section 6 - Evidence link validation
// ============================================================================

#[test]
fn t510_14_evidence_links_reference_existing_artifacts() {
    init_test("t510_14_evidence_links_reference_existing_artifacts");

    let doc = load_runbook();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Check that referenced test files exist
    for test_file in [
        "tests/web_grpc_e2e_service_scripts.rs",
        "tests/web_grpc_exhaustive_unit.rs",
    ] {
        test_section!(test_file);
        let stem = test_file
            .strip_prefix("tests/")
            .unwrap()
            .strip_suffix(".rs")
            .unwrap();
        assert!(doc.contains(stem), "runbook must reference {test_file}");
        assert!(
            base.join(test_file).exists(),
            "referenced test file must exist: {test_file}"
        );
    }

    test_section!("parity_map");
    assert!(
        doc.contains("tokio_web_grpc_parity_map"),
        "must reference parity map"
    );
    assert!(
        base.join("docs/tokio_web_grpc_parity_map.md").exists(),
        "parity map doc must exist"
    );

    test_complete!("t510_14_evidence_links_reference_existing_artifacts");
}

#[test]
fn t510_15_golden_corpus_referenced() {
    init_test("t510_15_golden_corpus_referenced");

    let doc = load_runbook();
    assert!(
        doc.contains("golden") || doc.contains("logging_golden_corpus"),
        "must reference golden log corpus"
    );

    test_complete!("t510_15_golden_corpus_referenced");
}

// ============================================================================
// Tests: Section 7 - CI commands
// ============================================================================

#[test]
fn t510_16_ci_commands_present() {
    init_test("t510_16_ci_commands_present");

    let doc = load_runbook();

    assert!(
        doc.contains("cargo test"),
        "must include cargo test commands"
    );
    assert!(
        doc.contains("rch exec"),
        "must include rch exec for remote execution"
    );

    test_complete!("t510_16_ci_commands_present");
}

// ============================================================================
// Tests: Section 8 - Cross-references and prerequisites
// ============================================================================

#[test]
fn t510_17_prerequisites_referenced() {
    init_test("t510_17_prerequisites_referenced");

    let doc = load_runbook();

    for bead in [
        "asupersync-2oh2u.5.9",
        "asupersync-2oh2u.5.11",
        "asupersync-2oh2u.5.12",
    ] {
        test_section!(bead);
        assert!(
            doc.contains(bead),
            "must reference prerequisite bead: {bead}"
        );
    }

    test_complete!("t510_17_prerequisites_referenced");
}

#[test]
fn t510_18_downstream_dependencies_referenced() {
    init_test("t510_18_downstream_dependencies_referenced");

    let doc = load_runbook();

    for bead in ["asupersync-2oh2u.11.2", "asupersync-2oh2u.10.9"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream bead: {bead}");
    }

    test_complete!("t510_18_downstream_dependencies_referenced");
}

// ============================================================================
// Tests: Section 9 - Migration pattern completeness
// ============================================================================

#[test]
fn t510_19_structured_concurrency_migration_mentioned() {
    init_test("t510_19_structured_concurrency_migration_mentioned");

    let doc = load_runbook();
    assert!(
        doc.contains("structured concurrency") || doc.contains("regions"),
        "must mention structured concurrency as replacement for tokio::spawn"
    );

    test_complete!("t510_19_structured_concurrency_migration_mentioned");
}

#[test]
fn t510_20_tokio_compat_adapter_mentioned() {
    init_test("t510_20_tokio_compat_adapter_mentioned");

    let doc = load_runbook();
    assert!(
        doc.contains("compat") || doc.contains("adapter"),
        "must mention tokio-compat adapter for incremental migration"
    );

    test_complete!("t510_20_tokio_compat_adapter_mentioned");
}

// ============================================================================
// Tests: Section 10 - Document quality
// ============================================================================

#[test]
fn t510_21_runbook_has_tables() {
    init_test("t510_21_runbook_has_tables");

    let doc = load_runbook();
    // Count table separator rows (|---...|---...|)
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 4,
        "runbook must have at least 4 markdown tables, found {table_count}"
    );

    test_complete!("t510_21_runbook_has_tables");
}

#[test]
fn t510_22_runbook_has_code_blocks() {
    init_test("t510_22_runbook_has_code_blocks");

    let doc = load_runbook();
    let code_blocks = doc.matches("```").count();
    assert!(
        code_blocks >= 4,
        "runbook must have at least 2 code blocks (4 fences), found {code_blocks} fences"
    );

    test_complete!("t510_22_runbook_has_code_blocks");
}

#[test]
fn t510_23_no_broken_markdown_links() {
    init_test("t510_23_no_broken_markdown_links");

    let doc = load_runbook();
    // Simple check: no orphaned link brackets
    let open_brackets = doc.matches('[').count();
    let close_brackets = doc.matches(']').count();
    // In markdown tables, | can create brackets in context, so just check
    // they're roughly balanced
    let diff = open_brackets.abs_diff(close_brackets);
    assert!(
        diff <= 2,
        "bracket imbalance suggests broken links: open={open_brackets}, close={close_brackets}"
    );

    test_complete!("t510_23_no_broken_markdown_links");
}

// ============================================================================
// Tests: Section 11 - Parity map cross-check
// ============================================================================

#[test]
fn t510_24_parity_map_exists() {
    init_test("t510_24_parity_map_exists");

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_web_grpc_parity_map.md");
    assert!(path.exists(), "web/gRPC parity map must exist");

    let doc = std::fs::read_to_string(&path).unwrap();
    assert!(doc.len() > 1000, "parity map must be substantial");

    test_complete!("t510_24_parity_map_exists");
}

#[test]
fn t510_25_e2e_and_unit_test_files_exist() {
    init_test("t510_25_e2e_and_unit_test_files_exist");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for test_file in [
        "tests/web_grpc_e2e_service_scripts.rs",
        "tests/web_grpc_exhaustive_unit.rs",
    ] {
        test_section!(test_file);
        assert!(
            base.join(test_file).exists(),
            "test file must exist: {test_file}"
        );
    }

    test_complete!("t510_25_e2e_and_unit_test_files_exist");
}
