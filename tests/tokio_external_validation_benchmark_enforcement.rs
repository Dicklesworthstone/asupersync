#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.7] External validation and benchmark evidence pack enforcement.
//!
//! Validates campaign design, benchmark suite, evidence pack structure,
//! comparison methodology, publication requirements, and quality gates.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Campaign design validation
//!   3. Benchmark suite coverage
//!   4. Evidence pack structure
//!   5. Comparison methodology
//!   6. Publication requirements
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

fn contract_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_external_validation_benchmark_packs.md")
}

fn load_contract() -> String {
    std::fs::read_to_string(contract_path()).expect("validation contract must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t97_01_contract_exists_and_is_substantial() {
    init_test("t97_01_contract_exists_and_is_substantial");

    assert!(contract_path().exists(), "validation contract must exist");
    let doc = load_contract();
    assert!(doc.len() > 3000, "contract must be substantial");

    test_complete!("t97_01_contract_exists_and_is_substantial");
}

#[test]
fn t97_02_contract_references_bead_and_program() {
    init_test("t97_02_contract_references_bead_and_program");

    let doc = load_contract();
    assert!(doc.contains("asupersync-2oh2u.11.7"), "must reference bead");
    assert!(doc.contains("[T9.7]"), "must reference T9.7");

    test_complete!("t97_02_contract_references_bead_and_program");
}

#[test]
fn t97_03_contract_has_required_sections() {
    init_test("t97_03_contract_has_required_sections");

    let doc = load_contract();

    for section in [
        "Validation Campaign",
        "Benchmark Suite",
        "Evidence Pack",
        "Comparison",
        "Publication",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t97_03_contract_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Campaign design validation
// ============================================================================

#[test]
fn t97_04_all_campaigns_defined() {
    init_test("t97_04_all_campaigns_defined");

    let doc = load_contract();

    for vc in ["VC-01", "VC-02", "VC-03", "VC-04", "VC-05", "VC-06"] {
        test_section!(vc);
        assert!(doc.contains(vc), "missing campaign: {vc}");
    }

    test_complete!("t97_04_all_campaigns_defined");
}

#[test]
fn t97_05_comparison_methodology_defined() {
    init_test("t97_05_comparison_methodology_defined");

    let doc = load_contract();

    for metric in ["Latency", "Throughput", "Memory", "Error rate"] {
        test_section!(metric);
        assert!(doc.contains(metric), "missing comparison metric: {metric}");
    }

    test_complete!("t97_05_comparison_methodology_defined");
}

// ============================================================================
// Tests: Section 3 - Benchmark suite coverage
// ============================================================================

#[test]
fn t97_06_all_benchmarks_defined() {
    init_test("t97_06_all_benchmarks_defined");

    let doc = load_contract();

    for bm in [
        "BM-01", "BM-02", "BM-03", "BM-04", "BM-05", "BM-06", "BM-07", "BM-08", "BM-09", "BM-10",
        "BM-11", "BM-12",
    ] {
        test_section!(bm);
        assert!(doc.contains(bm), "missing benchmark: {bm}");
    }

    test_complete!("t97_06_all_benchmarks_defined");
}

#[test]
fn t97_07_benchmarks_cover_all_tracks() {
    init_test("t97_07_benchmarks_cover_all_tracks");

    let doc = load_contract();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(doc.contains(track), "benchmarks must cover track: {track}");
    }

    test_complete!("t97_07_benchmarks_cover_all_tracks");
}

#[test]
fn t97_08_benchmark_protocol_defined() {
    init_test("t97_08_benchmark_protocol_defined");

    let doc = load_contract();

    assert!(doc.contains("Warmup"), "must define warmup period");
    assert!(
        doc.contains("Measurement") || doc.contains("steady-state"),
        "must define measurement window"
    );
    assert!(
        doc.contains("Repetitions") || doc.contains("3 runs"),
        "must define repetition count"
    );
    assert!(
        doc.contains("correlation"),
        "must tag runs with correlation IDs"
    );

    test_complete!("t97_08_benchmark_protocol_defined");
}

// ============================================================================
// Tests: Section 4 - Evidence pack structure
// ============================================================================

#[test]
fn t97_09_evidence_pack_schema_defined() {
    init_test("t97_09_evidence_pack_schema_defined");

    let doc = load_contract();

    assert!(
        doc.contains("evidence-pack-v1"),
        "must define evidence pack schema version"
    );
    assert!(doc.contains("pack_id"), "manifest must include pack_id");
    assert!(
        doc.contains("reproducibility"),
        "manifest must include reproducibility info"
    );

    test_complete!("t97_09_evidence_pack_schema_defined");
}

#[test]
fn t97_10_pack_layout_defined() {
    init_test("t97_10_pack_layout_defined");

    let doc = load_contract();

    assert!(doc.contains("manifest.json"), "must define manifest file");
    assert!(
        doc.contains("campaigns/"),
        "must define campaigns directory"
    );
    assert!(
        doc.contains("benchmarks/"),
        "must define benchmarks directory"
    );
    assert!(doc.contains("summary/"), "must define summary directory");

    test_complete!("t97_10_pack_layout_defined");
}

// ============================================================================
// Tests: Section 5 - Comparison methodology
// ============================================================================

#[test]
fn t97_11_comparison_verdicts_defined() {
    init_test("t97_11_comparison_verdicts_defined");

    let doc = load_contract();

    for verdict in [
        "BETTER",
        "EQUIVALENT",
        "ACCEPTABLE",
        "REGRESSION",
        "INCOMPATIBLE",
    ] {
        test_section!(verdict);
        assert!(doc.contains(verdict), "missing verdict: {verdict}");
    }

    test_complete!("t97_11_comparison_verdicts_defined");
}

#[test]
fn t97_12_compatibility_delta_schema_defined() {
    init_test("t97_12_compatibility_delta_schema_defined");

    let doc = load_contract();

    assert!(
        doc.contains("compatibility-delta-v1"),
        "must define delta schema version"
    );
    assert!(doc.contains("delta_id"), "delta must include id");
    assert!(
        doc.contains("follow_up_bead"),
        "delta must include follow-up bead"
    );

    test_complete!("t97_12_compatibility_delta_schema_defined");
}

// ============================================================================
// Tests: Section 6 - Publication requirements
// ============================================================================

#[test]
fn t97_13_reproducibility_requirements_defined() {
    init_test("t97_13_reproducibility_requirements_defined");

    let doc = load_contract();

    for req in ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05"] {
        test_section!(req);
        assert!(
            doc.contains(req),
            "missing reproducibility requirement: {req}"
        );
    }

    test_complete!("t97_13_reproducibility_requirements_defined");
}

#[test]
fn t97_14_independent_review_requirements_defined() {
    init_test("t97_14_independent_review_requirements_defined");

    let doc = load_contract();

    for req in ["IR-01", "IR-02", "IR-03", "IR-04", "IR-05"] {
        test_section!(req);
        assert!(doc.contains(req), "missing review requirement: {req}");
    }

    test_complete!("t97_14_independent_review_requirements_defined");
}

// ============================================================================
// Tests: Section 7 - Quality gate definitions
// ============================================================================

#[test]
fn t97_15_quality_gates_defined() {
    init_test("t97_15_quality_gates_defined");

    let doc = load_contract();

    for gate in [
        "EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-06", "EV-07", "EV-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t97_15_quality_gates_defined");
}

// ============================================================================
// Tests: Section 8 - Evidence link validation
// ============================================================================

#[test]
fn t97_16_prerequisites_referenced() {
    init_test("t97_16_prerequisites_referenced");

    let doc = load_contract();

    for bead in [
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.10.13",
        "asupersync-2oh2u.10.12",
        "asupersync-2oh2u.11.5",
        "asupersync-2oh2u.11.4",
        "asupersync-2oh2u.10.10",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t97_16_prerequisites_referenced");
}

#[test]
fn t97_17_downstream_referenced() {
    init_test("t97_17_downstream_referenced");

    let doc = load_contract();

    for bead in ["asupersync-2oh2u.11.8", "asupersync-2oh2u.11.12"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream: {bead}");
    }

    test_complete!("t97_17_downstream_referenced");
}

#[test]
fn t97_18_evidence_docs_exist() {
    init_test("t97_18_evidence_docs_exist");

    let doc = load_contract();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_golden_log_corpus_contract.md",
        "docs/tokio_release_channels_stabilization_policy.md",
        "docs/tokio_reference_applications_templates.md",
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

    test_complete!("t97_18_evidence_docs_exist");
}

#[test]
fn t97_19_ci_commands_present() {
    init_test("t97_19_ci_commands_present");

    let doc = load_contract();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t97_19_ci_commands_present");
}

#[test]
fn t97_20_contract_has_tables() {
    init_test("t97_20_contract_has_tables");

    let doc = load_contract();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 6,
        "must have at least 6 tables, found {table_count}"
    );

    test_complete!("t97_20_contract_has_tables");
}

#[test]
fn t97_21_contract_has_code_blocks() {
    init_test("t97_21_contract_has_code_blocks");

    let doc = load_contract();
    let code_fences = doc.matches("```").count();
    assert!(
        code_fences >= 6,
        "must have at least 3 code blocks, found {code_fences} fences"
    );

    test_complete!("t97_21_contract_has_code_blocks");
}

// ============================================================================
// Tests: Section 9 - Benchmark result simulation
// ============================================================================

#[test]
fn t97_22_verdict_classification_simulation() {
    init_test("t97_22_verdict_classification_simulation");

    fn classify(asupersync_ms: f64, tokio_ms: f64) -> &'static str {
        let ratio = asupersync_ms / tokio_ms;
        if ratio < 0.95 {
            "BETTER"
        } else if ratio <= 1.05 {
            "EQUIVALENT"
        } else if ratio <= 1.20 {
            "ACCEPTABLE"
        } else {
            "REGRESSION"
        }
    }

    assert_eq!(classify(8.0, 10.0), "BETTER");
    assert_eq!(classify(10.0, 10.0), "EQUIVALENT");
    assert_eq!(classify(11.5, 10.0), "ACCEPTABLE");
    assert_eq!(classify(13.0, 10.0), "REGRESSION");

    test_complete!("t97_22_verdict_classification_simulation");
}

#[test]
fn t97_23_evidence_pack_manifest_simulation() {
    init_test("t97_23_evidence_pack_manifest_simulation");

    let manifest = serde_json::json!({
        "schema_version": "evidence-pack-v1",
        "pack_id": "EP-20260304-001",
        "campaigns": ["VC-01", "VC-02"],
        "benchmarks": ["BM-01", "BM-02"],
        "tracks_covered": ["T2", "T3"],
        "verdict": "GO",
        "correlation_id": "ep-test-001"
    });

    assert_eq!(
        manifest["schema_version"].as_str().unwrap(),
        "evidence-pack-v1"
    );
    assert_eq!(manifest["campaigns"].as_array().unwrap().len(), 2);
    assert_eq!(manifest["verdict"].as_str().unwrap(), "GO");

    test_complete!("t97_23_evidence_pack_manifest_simulation");
}

#[test]
fn t97_24_multi_track_benchmark_present() {
    init_test("t97_24_multi_track_benchmark_present");

    let doc = load_contract();
    assert!(
        doc.contains("Multi-track") || doc.contains("full-stack"),
        "must include a multi-track benchmark"
    );

    test_complete!("t97_24_multi_track_benchmark_present");
}

#[test]
fn t97_25_interop_benchmark_present() {
    init_test("t97_25_interop_benchmark_present");

    let doc = load_contract();
    assert!(
        doc.contains("tokio-compat") || doc.contains("Interop"),
        "must include interop/compat benchmark"
    );

    test_complete!("t97_25_interop_benchmark_present");
}
