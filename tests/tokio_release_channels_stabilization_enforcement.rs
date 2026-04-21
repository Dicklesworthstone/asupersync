#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T9.5] Release channels and stabilization policy enforcement.
//!
//! Validates release channel definitions, promotion criteria, rollback triggers,
//! stabilization timeline, exception handling, and quality gates for
//! Tokio-replacement surface lifecycle management.
//!
//! Organisation:
//!   1. Document existence and structure
//!   2. Release channel definitions
//!   3. Promotion criteria validation
//!   4. Rollback trigger completeness
//!   5. Stabilization timeline
//!   6. Exception handling
//!   7. Owner responsibilities
//!   8. Quality gate definitions
//!   9. Evidence link validation
//!  10. Promotion simulation

#[macro_use]
mod common;

use common::init_test_logging;

use std::path::Path;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn policy_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_release_channels_stabilization_policy.md")
}

fn load_policy() -> String {
    std::fs::read_to_string(policy_path()).expect("stabilization policy must exist")
}

// ============================================================================
// Tests: Section 1 - Document existence and structure
// ============================================================================

#[test]
fn t95_01_policy_exists_and_is_substantial() {
    init_test("t95_01_policy_exists_and_is_substantial");

    assert!(policy_path().exists(), "stabilization policy must exist");
    let doc = load_policy();
    assert!(doc.len() > 3000, "policy must be substantial");

    test_complete!("t95_01_policy_exists_and_is_substantial");
}

#[test]
fn t95_02_policy_references_bead_and_program() {
    init_test("t95_02_policy_references_bead_and_program");

    let doc = load_policy();
    assert!(doc.contains("asupersync-2oh2u.11.5"), "must reference bead");
    assert!(doc.contains("[T9.5]"), "must reference T9.5");

    test_complete!("t95_02_policy_references_bead_and_program");
}

#[test]
fn t95_03_policy_has_required_sections() {
    init_test("t95_03_policy_has_required_sections");

    let doc = load_policy();

    for section in [
        "Release Channel",
        "Promotion Criteria",
        "Rollback",
        "Stabilization",
        "Exception",
        "Quality Gate",
    ] {
        test_section!(section);
        assert!(doc.contains(section), "missing section: {section}");
    }

    test_complete!("t95_03_policy_has_required_sections");
}

// ============================================================================
// Tests: Section 2 - Release channel definitions
// ============================================================================

#[test]
fn t95_04_all_channels_defined() {
    init_test("t95_04_all_channels_defined");

    let doc = load_policy();

    for channel in ["Alpha", "Beta", "RC", "GA"] {
        test_section!(channel);
        assert!(doc.contains(channel), "missing channel: {channel}");
    }

    test_complete!("t95_04_all_channels_defined");
}

#[test]
fn t95_05_channels_have_api_guarantees() {
    init_test("t95_05_channels_have_api_guarantees");

    let doc = load_policy();

    assert!(
        doc.contains("breaking changes"),
        "Alpha must describe breaking change policy"
    );
    assert!(doc.contains("semver"), "must define semver guarantees");
    assert!(doc.contains("LTS"), "GA must describe LTS commitment");

    test_complete!("t95_05_channels_have_api_guarantees");
}

#[test]
fn t95_06_feature_flags_defined() {
    init_test("t95_06_feature_flags_defined");

    let doc = load_policy();

    assert!(
        doc.contains("tokio-replace-"),
        "must define tokio-replace feature flags"
    );
    assert!(doc.contains("alpha"), "must define alpha feature flags");
    assert!(doc.contains("beta"), "must define beta feature flags");

    test_complete!("t95_06_feature_flags_defined");
}

// ============================================================================
// Tests: Section 3 - Promotion criteria validation
// ============================================================================

#[test]
fn t95_07_alpha_entry_criteria_defined() {
    init_test("t95_07_alpha_entry_criteria_defined");

    let doc = load_policy();

    for gate in ["PC-A01", "PC-A02", "PC-A03", "PC-A04", "PC-A05"] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing alpha gate: {gate}");
    }

    test_complete!("t95_07_alpha_entry_criteria_defined");
}

#[test]
fn t95_08_beta_promotion_criteria_defined() {
    init_test("t95_08_beta_promotion_criteria_defined");

    let doc = load_policy();

    for gate in [
        "PC-B01", "PC-B02", "PC-B03", "PC-B04", "PC-B05", "PC-B06", "PC-B07",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing beta gate: {gate}");
    }

    test_complete!("t95_08_beta_promotion_criteria_defined");
}

#[test]
fn t95_09_rc_promotion_criteria_defined() {
    init_test("t95_09_rc_promotion_criteria_defined");

    let doc = load_policy();

    for gate in [
        "PC-R01", "PC-R02", "PC-R03", "PC-R04", "PC-R05", "PC-R06", "PC-R07", "PC-R08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing RC gate: {gate}");
    }

    test_complete!("t95_09_rc_promotion_criteria_defined");
}

#[test]
fn t95_10_ga_promotion_criteria_defined() {
    init_test("t95_10_ga_promotion_criteria_defined");

    let doc = load_policy();

    for gate in ["PC-G01", "PC-G02", "PC-G03", "PC-G04", "PC-G05", "PC-G06"] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing GA gate: {gate}");
    }

    test_complete!("t95_10_ga_promotion_criteria_defined");
}

#[test]
fn t95_11_promotion_criteria_have_thresholds() {
    init_test("t95_11_promotion_criteria_have_thresholds");

    let doc = load_policy();

    // Key quantitative thresholds
    assert!(
        doc.contains("60%"),
        "alpha must have 60% coverage threshold"
    );
    assert!(doc.contains("80%"), "beta must have 80% coverage threshold");
    assert!(
        doc.contains("0.70"),
        "beta must reference 0.70 readiness score"
    );
    assert!(
        doc.contains("0.85"),
        "RC must reference 0.85 readiness score"
    );
    assert!(doc.contains("14-day"), "GA must require 14-day soak");

    test_complete!("t95_11_promotion_criteria_have_thresholds");
}

// ============================================================================
// Tests: Section 4 - Rollback trigger completeness
// ============================================================================

#[test]
fn t95_12_rollback_triggers_defined() {
    init_test("t95_12_rollback_triggers_defined");

    let doc = load_policy();

    for trigger in ["RT-01", "RT-02", "RT-03", "RT-04", "RT-05"] {
        test_section!(trigger);
        assert!(doc.contains(trigger), "missing rollback trigger: {trigger}");
    }

    test_complete!("t95_12_rollback_triggers_defined");
}

#[test]
fn t95_13_rollback_authority_defined() {
    init_test("t95_13_rollback_authority_defined");

    let doc = load_policy();

    assert!(
        doc.contains("Rollback Authority"),
        "must define rollback authority"
    );
    assert!(
        doc.contains("Track lead"),
        "must include track lead authority"
    );
    assert!(
        doc.contains("Program lead"),
        "must include program lead authority"
    );

    test_complete!("t95_13_rollback_authority_defined");
}

// ============================================================================
// Tests: Section 5 - Stabilization timeline
// ============================================================================

#[test]
fn t95_14_timeline_estimates_present() {
    init_test("t95_14_timeline_estimates_present");

    let doc = load_policy();

    assert!(
        doc.contains("Minimum Duration"),
        "must define minimum duration"
    );
    assert!(
        doc.contains("Typical Duration"),
        "must define typical duration"
    );
    assert!(doc.contains("weeks"), "timeline must use weeks as unit");

    test_complete!("t95_14_timeline_estimates_present");
}

#[test]
fn t95_15_per_track_timeline_present() {
    init_test("t95_15_per_track_timeline_present");

    let doc = load_policy();

    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(track);
        assert!(doc.contains(track), "timeline must include track: {track}");
    }

    test_complete!("t95_15_per_track_timeline_present");
}

// ============================================================================
// Tests: Section 6 - Exception handling
// ============================================================================

#[test]
fn t95_16_waiver_process_defined() {
    init_test("t95_16_waiver_process_defined");

    let doc = load_policy();

    assert!(
        doc.contains("Waiver") || doc.contains("waiver"),
        "must define waiver process"
    );
    assert!(
        doc.contains("promotion-waiver-v1"),
        "must define waiver schema version"
    );

    test_complete!("t95_16_waiver_process_defined");
}

// ============================================================================
// Tests: Section 7 - Owner responsibilities
// ============================================================================

#[test]
fn t95_17_role_matrix_defined() {
    init_test("t95_17_role_matrix_defined");

    let doc = load_policy();

    assert!(
        doc.contains("Role Matrix") || doc.contains("Owner Responsibilities"),
        "must define role matrix"
    );
    assert!(doc.contains("Track Lead"), "must include Track Lead");
    assert!(doc.contains("QA Lead"), "must include QA Lead");
    assert!(doc.contains("Ops Lead"), "must include Ops Lead");

    test_complete!("t95_17_role_matrix_defined");
}

// ============================================================================
// Tests: Section 8 - Quality gate definitions
// ============================================================================

#[test]
fn t95_18_quality_gates_defined() {
    init_test("t95_18_quality_gates_defined");

    let doc = load_policy();

    for gate in [
        "SP-01", "SP-02", "SP-03", "SP-04", "SP-05", "SP-06", "SP-07", "SP-08",
    ] {
        test_section!(gate);
        assert!(doc.contains(gate), "missing quality gate: {gate}");
    }

    test_complete!("t95_18_quality_gates_defined");
}

// ============================================================================
// Tests: Section 9 - Evidence link validation
// ============================================================================

#[test]
fn t95_19_prerequisites_referenced() {
    init_test("t95_19_prerequisites_referenced");

    let doc = load_policy();

    for bead in [
        "asupersync-2oh2u.11.10",
        "asupersync-2oh2u.10.9",
        "asupersync-2oh2u.11.3",
        "asupersync-2oh2u.10.10",
    ] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference prerequisite: {bead}");
    }

    test_complete!("t95_19_prerequisites_referenced");
}

#[test]
fn t95_20_downstream_referenced() {
    init_test("t95_20_downstream_referenced");

    let doc = load_policy();

    for bead in ["asupersync-2oh2u.11.7", "asupersync-2oh2u.11.6"] {
        test_section!(bead);
        assert!(doc.contains(bead), "must reference downstream: {bead}");
    }

    test_complete!("t95_20_downstream_referenced");
}

#[test]
fn t95_21_evidence_docs_exist() {
    init_test("t95_21_evidence_docs_exist");

    let doc = load_policy();
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    for evidence_doc in [
        "docs/tokio_replacement_readiness_gate_aggregator.md",
        "docs/tokio_incident_response_rollback_playbooks.md",
        "docs/tokio_replacement_roadmap.md",
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

    test_complete!("t95_21_evidence_docs_exist");
}

// ============================================================================
// Tests: Section 10 - Promotion simulation
// ============================================================================

#[test]
fn t95_22_promotion_gate_check_simulation() {
    init_test("t95_22_promotion_gate_check_simulation");

    // Simulate alpha entry check
    struct GateResult {
        gate_id: &'static str,
        passed: bool,
    }

    let alpha_gates = [
        GateResult {
            gate_id: "PC-A01",
            passed: true,
        },
        GateResult {
            gate_id: "PC-A02",
            passed: true,
        },
        GateResult {
            gate_id: "PC-A03",
            passed: true,
        },
        GateResult {
            gate_id: "PC-A04",
            passed: true,
        },
        GateResult {
            gate_id: "PC-A05",
            passed: true,
        },
    ];

    let all_pass = alpha_gates.iter().all(|g| g.passed);
    assert!(all_pass, "all alpha gates should pass for promotion");

    // Simulate beta promotion with one failure
    let beta_gates = [
        GateResult {
            gate_id: "PC-B01",
            passed: true,
        },
        GateResult {
            gate_id: "PC-B02",
            passed: false,
        }, // coverage below 80%
        GateResult {
            gate_id: "PC-B03",
            passed: true,
        },
    ];

    let beta_pass = beta_gates.iter().all(|g| g.passed);
    assert!(!beta_pass, "beta promotion should fail with gate failure");

    let failed: Vec<_> = beta_gates.iter().filter(|g| !g.passed).collect();
    assert_eq!(failed.len(), 1, "exactly one gate should fail");
    assert_eq!(failed[0].gate_id, "PC-B02", "PC-B02 should be the failure");

    test_complete!("t95_22_promotion_gate_check_simulation");
}

#[test]
fn t95_23_rollback_trigger_evaluation() {
    init_test("t95_23_rollback_trigger_evaluation");

    // Simulate rollback trigger evaluation
    let sev1_count_24h = 1_u32;
    let sev2_count_7d = 4_u32;
    let readiness_score = 0.68_f64;

    // RT-01: SEV-1 within 24h
    assert!(sev1_count_24h > 0, "RT-01 should trigger on SEV-1");

    // RT-02: Readiness below minimum
    assert!(readiness_score < 0.70, "RT-02 should trigger below 0.70");

    // RT-04: 3+ SEV-2 in 7 days
    assert!(sev2_count_7d >= 3, "RT-04 should trigger on 3+ SEV-2");

    test_complete!("t95_23_rollback_trigger_evaluation");
}

#[test]
fn t95_24_ci_commands_present() {
    init_test("t95_24_ci_commands_present");

    let doc = load_policy();
    assert!(doc.contains("cargo test"), "must include cargo test");
    assert!(doc.contains("rch exec"), "must include rch exec");

    test_complete!("t95_24_ci_commands_present");
}

#[test]
fn t95_25_policy_has_tables() {
    init_test("t95_25_policy_has_tables");

    let doc = load_policy();
    let table_count = doc.lines().filter(|l| l.contains("|--")).count();
    assert!(
        table_count >= 8,
        "policy must have at least 8 tables, found {table_count}"
    );

    test_complete!("t95_25_policy_has_tables");
}
