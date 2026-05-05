#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.9] GA readiness checklist and launch review enforcement.
//!
//! Validates readiness gate execution, migration lab KPI review, launch
//! packet completeness, go/no-go decision record, post-launch monitoring
//! commitments, and follow-up bead registration.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Readiness gate execution
//!   3. Migration lab KPI review
//!   4. Launch packet
//!   5. Go/no-go decision
//!   6. Post-launch monitoring
//!   7. Follow-up beads
//!   8. Quality gates
//!   9. Evidence links

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn doc_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_ga_readiness_checklist_launch_review.md")
}

fn load_doc() -> String {
    std::fs::read_to_string(doc_path()).expect("GA readiness doc must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t99_01_doc_exists_and_is_substantial() {
    init_test("t99_01_doc_exists_and_is_substantial");

    assert!(doc_path().exists(), "GA readiness doc must exist");
    let doc = load_doc();
    assert!(doc.len() > 5000, "doc must be substantial");

    test_complete!("t99_01_doc_exists_and_is_substantial");
}

#[test]
fn t99_02_doc_references_bead_and_program() {
    init_test("t99_02_doc_references_bead_and_program");

    let doc = load_doc();
    assert!(doc.contains("asupersync-2oh2u.11.9"), "must reference bead");
    assert!(doc.contains("[T9.9]"), "must reference T9.9");

    test_complete!("t99_02_doc_references_bead_and_program");
}

#[test]
fn t99_03_doc_has_required_sections() {
    init_test("t99_03_doc_has_required_sections");

    let doc = load_doc();

    for section in [
        "Readiness Gate",
        "Migration Lab",
        "Launch Packet",
        "Go/No-Go",
        "Post-Launch Monitoring",
        "Follow-Up",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t99_03_doc_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Readiness gate execution
// ============================================================================

#[test]
fn t99_04_all_8_dimensions_scored() {
    init_test("t99_04_all_8_dimensions_scored");

    let doc = load_doc();

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
        assert!(doc.contains(dim), "missing dimension: {dim}");
    }

    test_complete!("t99_04_all_8_dimensions_scored");
}

#[test]
fn t99_05_aggregate_score_computed() {
    init_test("t99_05_aggregate_score_computed");

    let doc = load_doc();

    assert!(doc.contains("0.9045"), "must compute aggregate score");
    assert!(doc.contains("GO"), "must show GO decision");
    assert!(doc.contains("0.85"), "must reference GO threshold");

    test_complete!("t99_05_aggregate_score_computed");
}

#[test]
fn t99_06_hard_gates_verified() {
    init_test("t99_06_hard_gates_verified");

    let doc = load_doc();

    assert!(doc.contains("HARD_FAIL"), "must reference HARD_FAIL status");
    assert!(doc.contains("Zero HARD_FAIL"), "must verify zero HARD_FAIL");

    test_complete!("t99_06_hard_gates_verified");
}

// ============================================================================
// Tests: Section 3 - Migration lab KPI review
// ============================================================================

#[test]
fn t99_07_all_6_archetypes_reviewed() {
    init_test("t99_07_all_6_archetypes_reviewed");

    let doc = load_doc();

    for archetype in [
        "REST CRUD",
        "gRPC microservice",
        "Event pipeline",
        "WebSocket",
        "CLI tool",
        "Hybrid Tokio-compat",
    ] {
        test_section!(archetype);
        assert!(doc.contains(archetype), "missing archetype: {archetype}");
    }

    test_complete!("t99_07_all_6_archetypes_reviewed");
}

#[test]
fn t99_08_kpi_summary_quantitative() {
    init_test("t99_08_kpi_summary_quantitative");

    let doc = load_doc();

    assert!(doc.contains("48"), "must cite total KPIs evaluated");
    assert!(
        doc.contains('0') && doc.contains("hard-fail"),
        "must cite zero hard-fails"
    );

    test_complete!("t99_08_kpi_summary_quantitative");
}

#[test]
fn t99_09_soft_fail_followup_documented() {
    init_test("t99_09_soft_fail_followup_documented");

    let doc = load_doc();

    assert!(
        doc.contains("FK-07") || doc.contains("Soft-Fail"),
        "must document soft-fail follow-up"
    );

    test_complete!("t99_09_soft_fail_followup_documented");
}

// ============================================================================
// Tests: Section 4 - Launch packet
// ============================================================================

#[test]
fn t99_10_conformance_summary_per_track() {
    init_test("t99_10_conformance_summary_per_track");

    let doc = load_doc();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(
            doc.contains(track),
            "conformance summary must cover: {track}"
        );
    }

    test_complete!("t99_10_conformance_summary_per_track");
}

#[test]
fn t99_11_performance_summary_has_benchmarks() {
    init_test("t99_11_performance_summary_has_benchmarks");

    let doc = load_doc();

    assert!(doc.contains("BM-01"), "must include BM-01");
    assert!(doc.contains("BM-12"), "must include BM-12");
    assert!(
        doc.contains("EQUIVALENT") || doc.contains("BETTER"),
        "must include verdict"
    );

    test_complete!("t99_11_performance_summary_has_benchmarks");
}

#[test]
fn t99_12_security_summary_present() {
    init_test("t99_12_security_summary_present");

    let doc = load_doc();

    assert!(doc.contains("Security"), "must have security summary");
    assert!(
        doc.contains("Clean") || doc.contains("0 unmitigated"),
        "security must be clean"
    );

    test_complete!("t99_12_security_summary_present");
}

#[test]
fn t99_13_log_quality_summary_present() {
    init_test("t99_13_log_quality_summary_present");

    let doc = load_doc();

    assert!(
        doc.contains("Log") || doc.contains("log"),
        "must have log quality summary"
    );
    assert!(
        doc.contains("Schema violations") || doc.contains("schema violation"),
        "must report schema violations"
    );

    test_complete!("t99_13_log_quality_summary_present");
}

// ============================================================================
// Tests: Section 5 - Go/no-go decision
// ============================================================================

#[test]
fn t99_14_decision_recorded() {
    init_test("t99_14_decision_recorded");

    let doc = load_doc();

    assert!(
        doc.contains("CONDITIONAL_GO") || doc.contains("GO") || doc.contains("NO_GO"),
        "must record launch decision"
    );

    test_complete!("t99_14_decision_recorded");
}

#[test]
fn t99_15_decision_criteria_checked() {
    init_test("t99_15_decision_criteria_checked");

    let doc = load_doc();

    assert!(
        doc.contains("0.9045") || doc.contains("Readiness score"),
        "must cite readiness score in decision"
    );
    assert!(
        doc.contains("PASS") || doc.contains("pass"),
        "must show gate pass status"
    );

    test_complete!("t99_15_decision_criteria_checked");
}

#[test]
fn t99_16_immediate_actions_defined() {
    init_test("t99_16_immediate_actions_defined");

    let doc = load_doc();

    assert!(
        doc.contains("Immediate Actions") || doc.contains("Action"),
        "must define immediate actions"
    );
    assert!(doc.contains("Owner"), "actions must have owners");
    assert!(
        doc.contains("Due Date") || doc.contains("Due"),
        "actions must have due dates"
    );

    test_complete!("t99_16_immediate_actions_defined");
}

// ============================================================================
// Tests: Section 6 - Post-launch monitoring
// ============================================================================

#[test]
fn t99_17_monitoring_plan_defined() {
    init_test("t99_17_monitoring_plan_defined");

    let doc = load_doc();

    assert!(doc.contains("p99 latency"), "must monitor p99 latency");
    assert!(doc.contains("Error rate"), "must monitor error rate");
    assert!(
        doc.contains("Continuous"),
        "must have continuous monitoring"
    );

    test_complete!("t99_17_monitoring_plan_defined");
}

#[test]
fn t99_18_monitoring_duration_per_channel() {
    init_test("t99_18_monitoring_duration_per_channel");

    let doc = load_doc();

    for channel in ["Alpha", "Beta", "RC", "GA"] {
        test_section!(channel);
        assert!(
            doc.contains(channel),
            "monitoring duration must cover: {channel}"
        );
    }

    test_complete!("t99_18_monitoring_duration_per_channel");
}

#[test]
fn t99_19_rollback_readiness_confirmed() {
    init_test("t99_19_rollback_readiness_confirmed");

    let doc = load_doc();

    for rt in ["RT-01", "RT-02", "RT-03", "RT-04", "RT-05"] {
        test_section!(rt);
        assert!(doc.contains(rt), "must confirm rollback trigger: {rt}");
    }

    test_complete!("t99_19_rollback_readiness_confirmed");
}

// ============================================================================
// Tests: Section 7 - Follow-up beads
// ============================================================================

#[test]
fn t99_20_followup_beads_registered() {
    init_test("t99_20_followup_beads_registered");

    let doc = load_doc();

    assert!(
        doc.contains("Follow-Up Bead") || doc.contains("Follow-up"),
        "must have follow-up bead register"
    );
    assert!(
        doc.contains("FK-07") || doc.contains("cold-start"),
        "must register FK-07 follow-up"
    );

    test_complete!("t99_20_followup_beads_registered");
}

// ============================================================================
// Tests: Section 8 - Quality gates
// ============================================================================

#[test]
fn t99_21_quality_gates_defined() {
    init_test("t99_21_quality_gates_defined");

    let doc = load_doc();

    for gate in [
        "GA-01", "GA-02", "GA-03", "GA-04", "GA-05", "GA-06", "GA-07", "GA-08", "GA-09", "GA-10",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t99_21_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Evidence links
// ============================================================================

#[test]
fn t99_22_prerequisites_referenced() {
    init_test("t99_22_prerequisites_referenced");

    let doc = load_doc();

    for bead in [
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.11.8",
        "asupersync-2oh2u.10.9",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t99_22_prerequisites_referenced");
}

#[test]
fn t99_23_evidence_docs_exist() {
    init_test("t99_23_evidence_docs_exist");

    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_replacement_readiness_gate_aggregator.md",
        "docs/tokio_replacement_claim_rfc.md",
        "docs/tokio_compatibility_limitation_matrix.md",
        "docs/tokio_release_channels_stabilization_policy.md",
        "docs/tokio_replacement_roadmap.md",
    ] {
        test_section!(evidence_doc);
        assert!(
            base.join(evidence_doc).exists(),
            "evidence doc must exist: {evidence_doc}"
        );
    }

    test_complete!("t99_23_evidence_docs_exist");
}

#[test]
fn t99_24_ci_commands_present() {
    init_test("t99_24_ci_commands_present");

    let doc = load_doc();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t99_24_ci_commands_present");
}

#[test]
fn t99_25_no_deferred_markers() {
    init_test("t99_25_no_deferred_markers");

    let doc = load_doc();

    for marker in ["[DEFERRED]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "doc has {marker} marker");
    }

    test_complete!("t99_25_no_deferred_markers");
}
