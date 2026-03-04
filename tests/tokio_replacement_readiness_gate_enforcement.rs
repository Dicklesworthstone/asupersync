#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T8.9] Replacement-readiness gate aggregator enforcement.
//!
//! Validates the readiness gate taxonomy, evidence dimensions, evaluation rules,
//! output schema, hard-fail diagnostics, waiver process, and quality gates for
//! the final Tokio-replacement readiness checkpoint.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Evidence dimension coverage
//!   3. Evaluation rule validation
//!   4. Per-track readiness profiles
//!   5. Output schema validation
//!   6. Hard-fail diagnostic completeness
//!   7. Waiver process
//!   8. Quality gate definitions
//!   9. Evidence link validation
//!  10. Readiness score simulation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn contract_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_replacement_readiness_gate_aggregator.md")
}

fn load_contract() -> String {
    std::fs::read_to_string(contract_path()).expect("readiness gate contract must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t89_01_contract_exists_and_is_substantial() {
    init_test("t89_01_contract_exists_and_is_substantial");

    assert!(
        contract_path().exists(),
        "readiness gate contract must exist"
    );
    let doc = load_contract();
    assert!(doc.len() > 3000, "contract must be substantial");

    test_complete!("t89_01_contract_exists_and_is_substantial");
}

#[test]
fn t89_02_contract_references_bead_and_program() {
    init_test("t89_02_contract_references_bead_and_program");

    let doc = load_contract();
    assert!(doc.contains("asupersync-2oh2u.10.9"), "must reference bead");
    assert!(doc.contains("[T8.9]"), "must reference T8.9");
    assert!(doc.contains("asupersync-2oh2u"), "must reference program");

    test_complete!("t89_02_contract_references_bead_and_program");
}

#[test]
fn t89_03_contract_has_required_sections() {
    init_test("t89_03_contract_has_required_sections");

    let doc = load_contract();

    for section in [
        "Gate Taxonomy",
        "Per-Track",
        "Gate Output",
        "Hard-Fail",
        "Waiver",
        "Quality Gate",
        "Evidence Link",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t89_03_contract_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Evidence dimension coverage
// ============================================================================

#[test]
fn t89_04_all_evidence_dimensions_defined() {
    init_test("t89_04_all_evidence_dimensions_defined");

    let doc = load_contract();

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
        assert!(doc.contains(dim), "missing evidence dimension: {dim}");
    }

    test_complete!("t89_04_all_evidence_dimensions_defined");
}

#[test]
fn t89_05_dimensions_have_weights() {
    init_test("t89_05_dimensions_have_weights");

    let doc = load_contract();

    // Weights should sum to 100%
    for weight in ["25%", "15%", "10%", "5%"] {
        test_section!(weight);
        assert!(doc.contains(weight), "missing weight value: {weight}");
    }

    test_complete!("t89_05_dimensions_have_weights");
}

#[test]
fn t89_06_dimensions_map_to_prerequisites() {
    init_test("t89_06_dimensions_map_to_prerequisites");

    let doc = load_contract();

    for source in [
        "Feature Parity",
        "Unit Test Quality",
        "Logging Quality",
        "Performance Budget",
        "Security Audit",
        "Migration Lab",
        "Golden Corpus",
        "Operations Readiness",
    ] {
        test_section!(source);
        assert!(
            doc.contains(source),
            "dimension must map to source: {source}"
        );
    }

    test_complete!("t89_06_dimensions_map_to_prerequisites");
}

// ============================================================================
// Tests: Section 3 - Evaluation rule validation
// ============================================================================

#[test]
fn t89_07_evaluation_statuses_defined() {
    init_test("t89_07_evaluation_statuses_defined");

    let doc = load_contract();

    for eval_status in ["PASS", "SOFT_FAIL", "HARD_FAIL", "NOT_APPLICABLE"] {
        test_section!(eval_status);
        assert!(doc.contains(eval_status), "missing status: {eval_status}");
    }

    test_complete!("t89_07_evaluation_statuses_defined");
}

#[test]
fn t89_08_aggregation_formula_defined() {
    init_test("t89_08_aggregation_formula_defined");

    let doc = load_contract();

    assert!(
        doc.contains("readiness_score"),
        "must define readiness score formula"
    );
    assert!(doc.contains("0.85"), "must define GO threshold (0.85)");
    assert!(
        doc.contains("0.70"),
        "must define CONDITIONAL threshold (0.70)"
    );

    test_complete!("t89_08_aggregation_formula_defined");
}

#[test]
fn t89_09_verdict_levels_defined() {
    init_test("t89_09_verdict_levels_defined");

    let doc = load_contract();

    for verdict in ["GO", "CONDITIONAL", "NO_GO"] {
        test_section!(verdict);
        assert!(doc.contains(verdict), "missing verdict level: {verdict}");
    }

    test_complete!("t89_09_verdict_levels_defined");
}

// ============================================================================
// Tests: Section 4 - Per-track readiness profiles
// ============================================================================

#[test]
fn t89_10_all_tracks_have_profiles() {
    init_test("t89_10_all_tracks_have_profiles");

    let doc = load_contract();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(doc.contains(track), "missing track profile: {track}");
    }

    test_complete!("t89_10_all_tracks_have_profiles");
}

#[test]
fn t89_11_evidence_freshness_rules_defined() {
    init_test("t89_11_evidence_freshness_rules_defined");

    let doc = load_contract();

    assert!(
        doc.contains("Maximum Age") || doc.contains("Freshness"),
        "must define evidence freshness rules"
    );
    assert!(doc.contains("7 days"), "must define 7-day freshness rule");
    assert!(doc.contains("14 days"), "must define 14-day freshness rule");
    assert!(doc.contains("30 days"), "must define 30-day freshness rule");

    test_complete!("t89_11_evidence_freshness_rules_defined");
}

// ============================================================================
// Tests: Section 5 - Output schema validation
// ============================================================================

#[test]
fn t89_12_output_schema_version_defined() {
    init_test("t89_12_output_schema_version_defined");

    let doc = load_contract();
    assert!(
        doc.contains("readiness-gate-v1"),
        "must define output schema version"
    );

    test_complete!("t89_12_output_schema_version_defined");
}

#[test]
fn t89_13_output_schema_has_required_fields() {
    init_test("t89_13_output_schema_has_required_fields");

    let doc = load_contract();

    for field in [
        "evaluation_id",
        "verdict",
        "readiness_score",
        "dimensions",
        "hard_fails",
        "correlation_id",
    ] {
        test_section!(field);
        assert!(doc.contains(field), "output schema missing field: {field}");
    }

    test_complete!("t89_13_output_schema_has_required_fields");
}

#[test]
fn t89_14_human_readable_summary_required() {
    init_test("t89_14_human_readable_summary_required");

    let doc = load_contract();

    assert!(
        doc.contains("Human-Readable"),
        "must require human-readable summary"
    );
    assert!(
        doc.contains("decision rationale"),
        "summary must include decision rationale"
    );
    assert!(
        doc.contains("risk register"),
        "summary must link risk register"
    );

    test_complete!("t89_14_human_readable_summary_required");
}

// ============================================================================
// Tests: Section 6 - Hard-fail diagnostic completeness
// ============================================================================

#[test]
fn t89_15_missing_evidence_diagnostic() {
    init_test("t89_15_missing_evidence_diagnostic");

    let doc = load_contract();

    assert!(
        doc.contains("Missing") && doc.contains("evidence"),
        "must define missing evidence diagnostic"
    );
    assert!(doc.contains("owner"), "diagnostic must include owner");
    assert!(
        doc.contains("remediation"),
        "diagnostic must include remediation"
    );

    test_complete!("t89_15_missing_evidence_diagnostic");
}

#[test]
fn t89_16_stale_evidence_diagnostic() {
    init_test("t89_16_stale_evidence_diagnostic");

    let doc = load_contract();

    assert!(
        doc.contains("Stale") && doc.contains("evidence"),
        "must define stale evidence diagnostic"
    );
    assert!(
        doc.contains("evidence_age_days"),
        "stale diagnostic must include age"
    );
    assert!(
        doc.contains("max_age_days"),
        "stale diagnostic must include max age"
    );

    test_complete!("t89_16_stale_evidence_diagnostic");
}

#[test]
fn t89_17_invalid_evidence_diagnostic() {
    init_test("t89_17_invalid_evidence_diagnostic");

    let doc = load_contract();

    assert!(
        doc.contains("Invalid") && doc.contains("evidence"),
        "must define invalid evidence diagnostic"
    );
    assert!(
        doc.contains("validation_error"),
        "invalid diagnostic must include error detail"
    );

    test_complete!("t89_17_invalid_evidence_diagnostic");
}

// ============================================================================
// Tests: Section 7 - Waiver process
// ============================================================================

#[test]
fn t89_18_waiver_conditions_defined() {
    init_test("t89_18_waiver_conditions_defined");

    let doc = load_contract();

    assert!(doc.contains("Waiver"), "must define waiver process");
    assert!(
        doc.contains("workaround") || doc.contains("Workaround"),
        "must describe known-limitation waivers"
    );
    assert!(
        doc.contains("expires_at") || doc.contains("Max Duration"),
        "waivers must have expiry"
    );

    test_complete!("t89_18_waiver_conditions_defined");
}

// ============================================================================
// Tests: Section 8 - Quality gate definitions
// ============================================================================

#[test]
fn t89_19_quality_gates_defined() {
    init_test("t89_19_quality_gates_defined");

    let doc = load_contract();

    for gate in [
        "RG-01", "RG-02", "RG-03", "RG-04", "RG-05", "RG-06", "RG-07", "RG-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t89_19_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Evidence link validation
// ============================================================================

#[test]
fn t89_20_prerequisites_referenced() {
    init_test("t89_20_prerequisites_referenced");

    let doc = load_contract();

    for bead in [
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.10.13",
        "asupersync-2oh2u.10.12",
        "asupersync-2oh2u.10.11",
        "asupersync-2oh2u.2.8",
        "asupersync-2oh2u.10.8",
        "asupersync-2oh2u.10.7",
        "asupersync-2oh2u.10.10",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t89_20_prerequisites_referenced");
}

#[test]
fn t89_21_downstream_dependencies_referenced() {
    init_test("t89_21_downstream_dependencies_referenced");

    let doc = load_contract();

    for bead in [
        "asupersync-2oh2u.11.5",
        "asupersync-2oh2u.11.8",
        "asupersync-2oh2u.11.9",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream: {bead}");
    }

    test_complete!("t89_21_downstream_dependencies_referenced");
}

#[test]
fn t89_22_evidence_docs_exist() {
    init_test("t89_22_evidence_docs_exist");

    let doc = load_contract();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_functional_parity_contracts.md",
        "docs/tokio_cross_track_e2e_logging_gate_contract.md",
        "docs/tokio_golden_log_corpus_contract.md",
        "docs/tokio_incident_response_rollback_playbooks.md",
        "docs/tokio_capability_risk_register.md",
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

    test_complete!("t89_22_evidence_docs_exist");
}

// ============================================================================
// Tests: Section 10 - Readiness score simulation
// ============================================================================

#[test]
fn t89_23_readiness_score_go_verdict() {
    init_test("t89_23_readiness_score_go_verdict");

    // Simulate a GO evaluation
    let weights = [0.25, 0.15, 0.10, 0.15, 0.10, 0.10, 0.05, 0.10];
    let statuses = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0]; // RG-DIM-07 soft-fail

    let total_weight: f64 = weights.iter().sum();
    let score: f64 = weights
        .iter()
        .zip(statuses.iter())
        .map(|(w, s)| w * s)
        .sum::<f64>()
        / total_weight;

    assert!(score >= 0.85, "all-pass (minus one) should be GO: {score}");
    assert!(score <= 1.0, "score must not exceed 1.0");

    test_complete!("t89_23_readiness_score_go_verdict");
}

#[test]
fn t89_24_readiness_score_no_go_verdict() {
    init_test("t89_24_readiness_score_no_go_verdict");

    // Simulate a NO_GO evaluation (multiple failures)
    let weights = [0.25, 0.15, 0.10, 0.15, 0.10, 0.10, 0.05, 0.10];
    let statuses = [1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0]; // 3 fails

    let total_weight: f64 = weights.iter().sum();
    let score: f64 = weights
        .iter()
        .zip(statuses.iter())
        .map(|(w, s)| w * s)
        .sum::<f64>()
        / total_weight;

    assert!(score < 0.70, "multiple failures should be NO_GO: {score}");

    test_complete!("t89_24_readiness_score_no_go_verdict");
}

#[test]
fn t89_25_ci_commands_present() {
    init_test("t89_25_ci_commands_present");

    let doc = load_contract();

    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t89_25_ci_commands_present");
}
