#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.2] Domain-specific migration cookbook enforcement.
//!
//! Validates the migration cookbooks document covers all 6 capability tracks,
//! includes before/after examples, anti-patterns, log expectations, and
//! evidence links to existing test/doc artifacts.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Track coverage (T2..T7)
//!   3. Recipe presence per track
//!   4. Anti-pattern and failure mode documentation
//!   5. Evidence link validation
//!   6. Cross-cutting concerns
//!   7. User-friction assumptions
//!   8. Prerequisite and downstream references

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn cookbook_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_migration_cookbooks.md")
}

fn load_cookbook() -> String {
    std::fs::read_to_string(cookbook_path()).expect("cookbook doc must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t92_01_cookbook_exists_and_is_substantial() {
    init_test("t92_01_cookbook_exists_and_is_substantial");

    assert!(cookbook_path().exists(), "cookbook doc must exist");
    let doc = load_cookbook();
    assert!(
        doc.len() > 5000,
        "cookbook must be substantial (>5000 chars)"
    );

    test_complete!("t92_01_cookbook_exists_and_is_substantial");
}

#[test]
fn t92_02_cookbook_references_bead_and_program() {
    init_test("t92_02_cookbook_references_bead_and_program");

    let doc = load_cookbook();
    assert!(doc.contains("asupersync-2oh2u.11.2"), "must reference bead");
    assert!(doc.contains("[T9.2]"), "must reference T9.2");

    test_complete!("t92_02_cookbook_references_bead_and_program");
}

#[test]
fn t92_03_cookbook_has_uniform_structure() {
    init_test("t92_03_cookbook_has_uniform_structure");

    let doc = load_cookbook();
    assert!(
        doc.contains("Cookbook Structure"),
        "must describe structure"
    );
    assert!(doc.contains("Migration Recipes"), "must mention recipes");
    assert!(
        doc.contains("Before/After") || doc.contains("Before"),
        "must have examples"
    );
    assert!(doc.contains("Anti-Pattern"), "must cover anti-patterns");
    assert!(doc.contains("Evidence"), "must have evidence links");

    test_complete!("t92_03_cookbook_has_uniform_structure");
}

// ============================================================================
// Tests: Section 2 - Track coverage
// ============================================================================

#[test]
fn t92_04_all_six_tracks_covered() {
    init_test("t92_04_all_six_tracks_covered");

    let doc = load_cookbook();

    for (track, domain) in [
        ("T2", "I/O"),
        ("T3", "fs"),
        ("T4", "QUIC"),
        ("T5", "Web"),
        ("T6", "Database"),
        ("T7", "Interop"),
    ] {
        test_section!(track);
        assert!(
            doc.contains(&format!("Track {track}")) || doc.contains(track),
            "missing track: {track} ({domain})"
        );
    }

    test_complete!("t92_04_all_six_tracks_covered");
}

#[test]
fn t92_05_each_track_has_domain_overview() {
    init_test("t92_05_each_track_has_domain_overview");

    let doc = load_cookbook();
    let overview_count = doc.matches("Domain Overview").count();
    assert!(
        overview_count >= 6,
        "each track must have a Domain Overview section, found {overview_count}"
    );

    test_complete!("t92_05_each_track_has_domain_overview");
}

// ============================================================================
// Tests: Section 3 - Recipe presence per track
// ============================================================================

#[test]
fn t92_06_track_recipes_use_consistent_naming() {
    init_test("t92_06_track_recipes_use_consistent_naming");

    let doc = load_cookbook();

    for prefix in ["R2-", "R3-", "R4-", "R5-", "R6-", "R7-"] {
        test_section!(prefix);
        let count = doc.matches(prefix).count();
        assert!(
            count >= 5,
            "track {prefix} must have at least 5 recipes, found {count}"
        );
    }

    test_complete!("t92_06_track_recipes_use_consistent_naming");
}

#[test]
fn t92_07_recipes_include_from_and_to_columns() {
    init_test("t92_07_recipes_include_from_and_to_columns");

    let doc = load_cookbook();
    // Each recipe table should have From and To headers
    let from_count = doc.matches("| From").count();
    let to_count = doc.matches("| To").count();
    assert!(from_count >= 6, "each track recipe table needs From column");
    assert!(to_count >= 6, "each track recipe table needs To column");

    test_complete!("t92_07_recipes_include_from_and_to_columns");
}

// ============================================================================
// Tests: Section 4 - Anti-patterns
// ============================================================================

#[test]
fn t92_08_each_track_has_anti_patterns() {
    init_test("t92_08_each_track_has_anti_patterns");

    let doc = load_cookbook();

    for prefix in ["AP-T2-", "AP-T3-", "AP-T4-", "AP-T5-", "AP-T6-", "AP-T7-"] {
        test_section!(prefix);
        let count = doc.matches(prefix).count();
        assert!(
            count >= 2,
            "track {prefix} must have at least 2 anti-patterns, found {count}"
        );
    }

    test_complete!("t92_08_each_track_has_anti_patterns");
}

// ============================================================================
// Tests: Section 5 - Evidence links
// ============================================================================

#[test]
fn t92_09_evidence_links_reference_test_files() {
    init_test("t92_09_evidence_links_reference_test_files");

    let doc = load_cookbook();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for test_file in [
        "tests/web_grpc_e2e_service_scripts.rs",
        "tests/web_grpc_exhaustive_unit.rs",
        "tests/tokio_interop_e2e_scenarios.rs",
        "tests/e2e_t6_data_path.rs",
        "tests/t6_database_messaging_unit_matrix.rs",
    ] {
        test_section!(test_file);
        let stem = test_file
            .strip_prefix("tests/")
            .unwrap()
            .strip_suffix(".rs")
            .unwrap();
        assert!(doc.contains(stem), "must reference {test_file}");
        assert!(
            base.join(test_file).exists(),
            "file must exist: {test_file}"
        );
    }

    test_complete!("t92_09_evidence_links_reference_test_files");
}

#[test]
fn t92_10_evidence_links_reference_docs() {
    init_test("t92_10_evidence_links_reference_docs");

    let doc = load_cookbook();

    for doc_ref in [
        "tokio_web_grpc_migration_runbook",
        "tokio_web_grpc_parity_map",
        "tokio_interop_support_matrix",
        "tokio_adapter_boundary_architecture",
    ] {
        test_section!(doc_ref);
        assert!(doc.contains(doc_ref), "must reference {doc_ref}");
    }

    test_complete!("t92_10_evidence_links_reference_docs");
}

#[test]
fn t92_11_golden_corpus_referenced() {
    init_test("t92_11_golden_corpus_referenced");

    let doc = load_cookbook();
    assert!(
        doc.contains("golden") || doc.contains("logging_golden_corpus"),
        "must reference golden log corpus"
    );

    test_complete!("t92_11_golden_corpus_referenced");
}

// ============================================================================
// Tests: Section 6 - Cross-cutting concerns
// ============================================================================

#[test]
fn t92_12_structured_logging_requirements_documented() {
    init_test("t92_12_structured_logging_requirements_documented");

    let doc = load_cookbook();
    assert!(
        doc.contains("Structured Logging") || doc.contains("structured log"),
        "must document structured logging requirements"
    );
    assert!(
        doc.contains("schema") || doc.contains("schema_version"),
        "must reference log schema"
    );

    test_complete!("t92_12_structured_logging_requirements_documented");
}

#[test]
fn t92_13_correlation_id_propagation_documented() {
    init_test("t92_13_correlation_id_propagation_documented");

    let doc = load_cookbook();
    assert!(
        doc.contains("Correlation ID") || doc.contains("correlation"),
        "must document correlation ID propagation"
    );

    test_complete!("t92_13_correlation_id_propagation_documented");
}

#[test]
fn t92_14_rollback_decision_points_documented() {
    init_test("t92_14_rollback_decision_points_documented");

    let doc = load_cookbook();
    assert!(
        doc.contains("Rollback") || doc.contains("rollback"),
        "must document rollback decision points"
    );

    test_complete!("t92_14_rollback_decision_points_documented");
}

// ============================================================================
// Tests: Section 7 - User-friction assumptions
// ============================================================================

#[test]
fn t92_15_user_friction_assumptions_present() {
    init_test("t92_15_user_friction_assumptions_present");

    let doc = load_cookbook();
    assert!(
        doc.contains("User-Friction") || doc.contains("friction"),
        "must document user-friction assumptions"
    );
    assert!(
        doc.contains("Threshold") || doc.contains("threshold"),
        "must define measurable thresholds"
    );

    test_complete!("t92_15_user_friction_assumptions_present");
}

#[test]
fn t92_16_friction_assumptions_are_measurable() {
    init_test("t92_16_friction_assumptions_are_measurable");

    let doc = load_cookbook();
    // Must include quantitative thresholds
    assert!(
        doc.contains("min") || doc.contains('<') || doc.contains('>') || doc.contains('%'),
        "friction assumptions must include quantitative thresholds"
    );

    test_complete!("t92_16_friction_assumptions_are_measurable");
}

// ============================================================================
// Tests: Section 8 - Prerequisites and downstream
// ============================================================================

#[test]
fn t92_17_prerequisites_referenced() {
    init_test("t92_17_prerequisites_referenced");

    let doc = load_cookbook();

    for bead in [
        "asupersync-2oh2u.10.13",
        "asupersync-2oh2u.2.10",
        "asupersync-2oh2u.11.1",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t92_17_prerequisites_referenced");
}

#[test]
fn t92_18_downstream_references_present() {
    init_test("t92_18_downstream_references_present");

    let doc = load_cookbook();
    assert!(
        doc.contains("asupersync-2oh2u.11.10") || doc.contains("T9.10"),
        "must reference downstream T9.10"
    );

    test_complete!("t92_18_downstream_references_present");
}

// ============================================================================
// Tests: Section 9 - Code examples
// ============================================================================

#[test]
fn t92_19_has_code_examples() {
    init_test("t92_19_has_code_examples");

    let doc = load_cookbook();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 4,
        "must have at least 2 code blocks (4 fences), found {code_fences}"
    );

    test_complete!("t92_19_has_code_examples");
}

#[test]
fn t92_20_code_examples_show_before_after() {
    init_test("t92_20_code_examples_show_before_after");

    let doc = load_cookbook();
    assert!(
        doc.contains("// Before") && doc.contains("// After"),
        "must have before/after code comments"
    );

    test_complete!("t92_20_code_examples_show_before_after");
}

// ============================================================================
// Tests: Section 10 - CI and quality
// ============================================================================

#[test]
fn t92_21_ci_commands_present() {
    init_test("t92_21_ci_commands_present");

    let doc = load_cookbook();
    assert!(
        doc.contains("cargo test"),
        "must include cargo test commands"
    );
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t92_21_ci_commands_present");
}

#[test]
fn t92_22_recipe_tables_have_minimum_rows() {
    init_test("t92_22_recipe_tables_have_minimum_rows");

    let doc = load_cookbook();
    let table_rows = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_rows >= 8,
        "must have at least 8 markdown tables, found {table_rows}"
    );

    test_complete!("t92_22_recipe_tables_have_minimum_rows");
}

// ============================================================================
// Tests: Section 11 - Compat adapter documentation
// ============================================================================

#[test]
fn t92_23_compat_adapter_migration_path() {
    init_test("t92_23_compat_adapter_migration_path");

    let doc = load_cookbook();
    assert!(
        doc.contains("compat") || doc.contains("adapter"),
        "must document tokio-compat adapter for incremental migration"
    );
    assert!(
        doc.contains("asupersync-tokio-compat"),
        "must reference the compat crate"
    );

    test_complete!("t92_23_compat_adapter_migration_path");
}

#[test]
fn t92_24_structured_concurrency_migration() {
    init_test("t92_24_structured_concurrency_migration");

    let doc = load_cookbook();
    assert!(
        doc.contains("structured concurrency") || doc.contains("regions"),
        "must mention structured concurrency as tokio::spawn replacement"
    );

    test_complete!("t92_24_structured_concurrency_migration");
}

#[test]
fn t92_25_cookbook_scope_table_has_all_tracks() {
    init_test("t92_25_cookbook_scope_table_has_all_tracks");

    let doc = load_cookbook();
    // Verify the scope table lists all 6 tracks with their domains
    for domain in [
        "Async I/O",
        "fs/process/signal",
        "QUIC",
        "Web/gRPC",
        "Database",
        "Interop",
    ] {
        test_section!(domain);
        assert!(doc.contains(domain), "scope table missing domain: {domain}");
    }

    test_complete!("t92_25_cookbook_scope_table_has_all_tracks");
}

// ============================================================================
// Tests: Section 12 - Failure modes (AC-1 edge-case handling)
// ============================================================================

#[test]
fn t92_26_each_track_has_failure_modes() {
    init_test("t92_26_each_track_has_failure_modes");

    let doc = load_cookbook();

    for prefix in ["FM-T2-", "FM-T3-", "FM-T4-", "FM-T5-", "FM-T6-", "FM-T7-"] {
        test_section!(prefix);
        let count = doc.matches(prefix).count();
        assert!(
            count >= 2,
            "track {prefix} must have at least 2 failure modes, found {count}"
        );
    }

    test_complete!("t92_26_each_track_has_failure_modes");
}

#[test]
fn t92_27_failure_modes_have_mitigation() {
    init_test("t92_27_failure_modes_have_mitigation");

    let doc = load_cookbook();
    let mit_count = doc.matches("Mitigation").count();
    assert!(
        mit_count >= 6,
        "each track failure mode table needs Mitigation column, found {mit_count}"
    );

    test_complete!("t92_27_failure_modes_have_mitigation");
}

// ============================================================================
// Tests: Section 13 - Edge cases (AC-1)
// ============================================================================

#[test]
fn t92_28_each_track_has_edge_cases() {
    init_test("t92_28_each_track_has_edge_cases");

    let doc = load_cookbook();
    let count = doc.matches("Edge Cases").count();
    assert!(
        count >= 6,
        "each track must have Edge Cases section, found {count}"
    );

    test_complete!("t92_28_each_track_has_edge_cases");
}

// ============================================================================
// Tests: Section 14 - Rollback decision points (AC-1)
// ============================================================================

#[test]
fn t92_29_each_track_has_rollback_decision_points() {
    init_test("t92_29_each_track_has_rollback_decision_points");

    let doc = load_cookbook();
    let count = doc.matches("Rollback Decision Points").count();
    assert!(
        count >= 6,
        "each track must have Rollback Decision Points, found {count}"
    );

    test_complete!("t92_29_each_track_has_rollback_decision_points");
}

#[test]
fn t92_30_rollback_tables_have_criterion_and_action() {
    init_test("t92_30_rollback_tables_have_criterion_and_action");

    let doc = load_cookbook();
    let crit_count = doc.matches("Rollback Criterion").count();
    assert!(
        crit_count >= 6,
        "each rollback table needs Rollback Criterion header, found {crit_count}"
    );

    test_complete!("t92_30_rollback_tables_have_criterion_and_action");
}

// ============================================================================
// Tests: Section 15 - Evidence file existence (AC-2)
// ============================================================================

#[test]
fn t92_31_evidence_test_files_exist_on_disk() {
    init_test("t92_31_evidence_test_files_exist_on_disk");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    let test_files = [
        "tests/tokio_io_codec_cancellation_correctness.rs",
        "tests/tokio_fs_process_signal_e2e.rs",
        "tests/tokio_fs_process_signal_unit_test_matrix.rs",
        "tests/tokio_quic_h3_e2e_scenario_manifest.rs",
        "tests/web_grpc_e2e_service_scripts.rs",
        "tests/web_grpc_exhaustive_unit.rs",
        "tests/e2e_t6_data_path.rs",
        "tests/t6_database_messaging_unit_matrix.rs",
        "tests/tokio_interop_e2e_scenarios.rs",
    ];

    for f in &test_files {
        test_section!(f);
        assert!(base.join(f).exists(), "evidence test file missing: {f}");
    }

    test_complete!("t92_31_evidence_test_files_exist_on_disk");
}

#[test]
fn t92_32_evidence_doc_files_exist_on_disk() {
    init_test("t92_32_evidence_doc_files_exist_on_disk");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    let doc_files = [
        "docs/tokio_io_parity_audit.md",
        "docs/tokio_fs_process_signal_migration_playbook.md",
        "docs/tokio_web_grpc_migration_runbook.md",
        "docs/tokio_web_grpc_parity_map.md",
        "docs/tokio_db_messaging_migration_packs_contract.md",
        "docs/tokio_t6_migration_packs.md",
        "docs/tokio_interop_support_matrix.md",
        "docs/tokio_adapter_boundary_architecture.md",
    ];

    for f in &doc_files {
        test_section!(f);
        assert!(base.join(f).exists(), "evidence doc file missing: {f}");
    }

    test_complete!("t92_32_evidence_doc_files_exist_on_disk");
}

#[test]
fn t92_33_golden_corpus_fixtures_exist() {
    init_test("t92_33_golden_corpus_fixtures_exist");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus_dir = base.join("tests/fixtures/logging_golden_corpus");

    assert!(
        corpus_dir.join("manifest.json").exists(),
        "manifest.json missing"
    );

    test_complete!("t92_33_golden_corpus_fixtures_exist");
}

// ============================================================================
// Tests: Section 16 - Structured log expectations (AC-3)
// ============================================================================

#[test]
fn t92_34_log_schema_fields_documented() {
    init_test("t92_34_log_schema_fields_documented");

    let doc = load_cookbook();
    for field in [
        "schema_version",
        "scenario_id",
        "correlation_id",
        "outcome",
        "replay_pointer",
    ] {
        test_section!(field);
        assert!(doc.contains(field), "log schema field missing: {field}");
    }

    test_complete!("t92_34_log_schema_fields_documented");
}

// ============================================================================
// Tests: Section 17 - User-friction KPIs (AC-4)
// ============================================================================

#[test]
fn t92_35_friction_thresholds_quantified() {
    init_test("t92_35_friction_thresholds_quantified");

    let doc = load_cookbook();
    assert!(doc.contains("30 min"), "migration time threshold missing");
    assert!(doc.contains("2 hours"), "learning curve threshold missing");
    assert!(
        doc.contains("Zero downtime") || doc.contains("zero downtime"),
        "zero downtime requirement missing"
    );

    test_complete!("t92_35_friction_thresholds_quantified");
}

#[test]
fn t92_36_friction_validation_links_to_migration_labs() {
    init_test("t92_36_friction_validation_links_to_migration_labs");

    let doc = load_cookbook();
    assert!(
        doc.contains("T9.10") || doc.contains("asupersync-2oh2u.11.10"),
        "friction assumptions must reference T9.10 migration labs"
    );

    test_complete!("t92_36_friction_validation_links_to_migration_labs");
}

// ============================================================================
// Tests: Section 18 - Before/After code coverage
// ============================================================================

#[test]
fn t92_37_each_track_has_before_after_code() {
    init_test("t92_37_each_track_has_before_after_code");

    let doc = load_cookbook();
    let ba_count = doc.matches("Before/After").count();
    assert!(
        ba_count >= 6,
        "each track must have Before/After section, found {ba_count}"
    );

    test_complete!("t92_37_each_track_has_before_after_code");
}

// ============================================================================
// Tests: Section 19 - No deferred markers
// ============================================================================

#[test]
fn t92_38_no_deferred_markers() {
    init_test("t92_38_no_deferred_markers");

    let doc = load_cookbook();
    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "doc has {marker} marker");
    }

    test_complete!("t92_38_no_deferred_markers");
}

// ============================================================================
// Tests: Section 20 - Downstream binding completeness
// ============================================================================

#[test]
fn t92_39_downstream_binding_to_t9_4() {
    init_test("t92_39_downstream_binding_to_t9_4");

    let doc = load_cookbook();
    assert!(
        doc.contains("asupersync-2oh2u.11.4") || doc.contains("T9.4"),
        "must bind to T9.4 reference applications"
    );

    test_complete!("t92_39_downstream_binding_to_t9_4");
}

#[test]
fn t92_40_revision_history_present() {
    init_test("t92_40_revision_history_present");

    let doc = load_cookbook();
    assert!(
        doc.contains("Revision History"),
        "must have Revision History section"
    );

    test_complete!("t92_40_revision_history_present");
}
