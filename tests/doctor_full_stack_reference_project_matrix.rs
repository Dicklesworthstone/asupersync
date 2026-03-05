//! Full-Stack Reference Project Matrix Validation (Track 6.5)
//!
//! Validates deterministic profile-matrix definitions used by the
//! doctor full-stack reference-project regression suite.
//!
//! Bead: asupersync-2b4jj.6.5

#![allow(missing_docs)]
#![cfg(feature = "cli")]

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/doctor_full_stack_reference_projects_contract.md";
const SCRIPT_PATH: &str = "scripts/test_doctor_full_stack_reference_projects_e2e.sh";

#[derive(Debug, Clone)]
struct ProfileSpec {
    id: &'static str,
    complexity_band: &'static str,
    scripts: &'static [&'static str],
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load doctor full-stack reference-project contract doc")
}

fn load_script() -> String {
    std::fs::read_to_string(repo_root().join(SCRIPT_PATH))
        .expect("failed to load doctor full-stack reference-project e2e script")
}

fn reference_profile_matrix() -> Vec<ProfileSpec> {
    vec![
        ProfileSpec {
            id: "small",
            complexity_band: "small",
            scripts: &[
                "scripts/test_doctor_workspace_scan_e2e.sh",
                "scripts/test_doctor_invariant_analyzer_e2e.sh",
            ],
        },
        ProfileSpec {
            id: "medium",
            complexity_band: "medium",
            scripts: &[
                "scripts/test_doctor_orchestration_state_machine_e2e.sh",
                "scripts/test_doctor_scenario_coverage_packs_e2e.sh",
            ],
        },
        ProfileSpec {
            id: "large",
            complexity_band: "large",
            scripts: &[
                "scripts/test_doctor_remediation_verification_e2e.sh",
                "scripts/test_doctor_remediation_failure_injection_e2e.sh",
                "scripts/test_doctor_report_export_e2e.sh",
            ],
        },
    ]
}

fn derive_profile_seed(base_seed: &str, profile_id: &str) -> String {
    format!("{base_seed}:{profile_id}")
}

fn select_profiles(mode: &str) -> Result<Vec<&'static str>, String> {
    match mode {
        "all" => Ok(vec!["small", "medium", "large"]),
        "small" => Ok(vec!["small"]),
        "medium" => Ok(vec!["medium"]),
        "large" => Ok(vec!["large"]),
        other => Err(format!(
            "PROFILE_MODE must be all|small|medium|large; got {other}"
        )),
    }
}

fn classify_failure(stage_id: &str, exit_code: i32) -> &'static str {
    if exit_code == 124 {
        return "timeout";
    }
    match stage_id {
        s if s.contains("workspace_scan") => "workspace_scan_failure",
        s if s.contains("invariant_analyzer") => "invariant_analyzer_failure",
        s if s.contains("orchestration_state_machine") || s.contains("scenario_coverage_packs") => {
            "orchestration_failure"
        }
        s if s.contains("remediation") || s.contains("report_export") => {
            "remediation_or_reporting_failure"
        }
        _ => "unknown_failure",
    }
}

fn diagnosis_time_delta_pct(run1_seconds: f64, run2_seconds: f64) -> f64 {
    if run1_seconds <= 0.0 {
        0.0
    } else {
        ((run2_seconds - run1_seconds) / run1_seconds) * 100.0
    }
}

fn false_transition_rates(run1_statuses: &[&str], run2_statuses: &[&str]) -> (f64, f64) {
    let total = run1_statuses.len().max(run2_statuses.len());
    if total == 0 {
        return (0.0, 0.0);
    }

    let mut false_positive_pairs = 0usize;
    let mut false_negative_pairs = 0usize;

    for idx in 0..total {
        let left = run1_statuses.get(idx).copied().unwrap_or("missing");
        let right = run2_statuses.get(idx).copied().unwrap_or("missing");
        if left != "passed" && right == "passed" {
            false_positive_pairs += 1;
        }
        if left == "passed" && right != "passed" {
            false_negative_pairs += 1;
        }
    }

    (
        (false_positive_pairs as f64 / total as f64) * 100.0,
        (false_negative_pairs as f64 / total as f64) * 100.0,
    )
}

fn remediation_success_rate_pct(passed: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (passed as f64 / total as f64) * 100.0
    }
}

fn operator_confidence_score(
    diagnosis_delta_pct: f64,
    false_positive_rate_pct: f64,
    false_negative_rate_pct: f64,
    remediation_success_rate_pct: f64,
    deterministic_pair_rate_pct: f64,
) -> f64 {
    let raw = 100.0
        - (diagnosis_delta_pct.abs() * 1.5)
        - (false_positive_rate_pct * 3.0)
        - (false_negative_rate_pct * 3.0)
        - ((100.0 - remediation_success_rate_pct) * 0.5)
        - ((100.0 - deterministic_pair_rate_pct) * 0.5);
    raw.clamp(0.0, 100.0)
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "full-stack reference-project contract doc must exist"
    );
}

#[test]
fn script_exists() {
    assert!(
        Path::new(SCRIPT_PATH).exists(),
        "full-stack reference-project e2e script must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2b4jj.6.5"),
        "doc must reference bead id"
    );
    assert!(
        doc.contains("asupersync-2b4jj.6.4"),
        "doc must include rollout adoption metrics addendum bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Reference Project Matrix",
        "Orchestration Controls",
        "Deterministic Seed Handling",
        "Scenario Selection",
        "Failure Classification",
        "Structured Logging and Transcript Requirements",
        "Final Report Contract",
        "Dogfood Rollout Addendum (`asupersync-2b4jj.6.4`)",
        "Required Adoption Metrics",
        "Metric Definitions (Deterministic Form)",
        "Rollout Decision Gate",
        "CI Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing required sections:\n{}",
        missing
            .iter()
            .map(|section| format!("  - {section}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_script_and_test_file() {
    let doc = load_doc();
    assert!(
        doc.contains("test_doctor_full_stack_reference_projects_e2e.sh"),
        "doc must reference e2e script"
    );
    assert!(
        doc.contains("doctor_full_stack_reference_project_matrix.rs"),
        "doc must reference test file"
    );
}

#[test]
fn script_declares_adoption_metric_env_contract() {
    let script = load_script();
    let required_tokens = [
        "MAX_DIAGNOSIS_TIME_DELTA_PCT",
        "MAX_FALSE_POSITIVE_RATE_PCT",
        "MAX_FALSE_NEGATIVE_RATE_PCT",
        "MIN_REMEDIATION_SUCCESS_RATE_PCT",
        "MIN_OPERATOR_CONFIDENCE_SCORE",
        "QUALITY_GATE_2B4JJ_6_6_STATUS",
        "QUALITY_GATE_2B4JJ_6_7_STATUS",
        "QUALITY_GATE_2B4JJ_6_8_STATUS",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "script must declare adoption metric env token {token}"
        );
    }
}

#[test]
fn script_enforces_quality_gate_dependency_blocking() {
    let script = load_script();
    let required_tokens = [
        "quality_gate_dependencies",
        "quality_gate_failures",
        "select(.status != \"green\")",
        "QUALITY_GATES_FILE",
        "quality_gate_dependency_failure",
        "Resolve prerequisite quality gate statuses (2b4jj.6.6/6.7/6.8) to green before rollout decision can advance",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "script quality-gate enforcement missing token {token}"
        );
    }
}

#[test]
fn script_summary_includes_rollout_and_adoption_fields() {
    let script = load_script();
    let required_tokens = [
        "rollout_gate_status",
        "rollout_decision",
        "adoption_metrics",
        "adoption_metric_thresholds",
        "operator_confidence_signals",
        "quality_gate_dependencies",
        "quality_gate_failures",
        "followup_actions",
        "artifact_links",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "script summary contract missing token {token}"
        );
    }
}

#[test]
fn matrix_has_three_complexity_profiles() {
    let matrix = reference_profile_matrix();
    assert_eq!(matrix.len(), 3, "matrix must have exactly three profiles");

    let ids: BTreeSet<&str> = matrix.iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids,
        BTreeSet::from(["large", "medium", "small"]),
        "matrix profile ids must be small/medium/large"
    );
}

#[test]
fn matrix_scripts_exist_and_are_unique() {
    let matrix = reference_profile_matrix();
    let mut seen = HashSet::new();

    for profile in matrix {
        assert!(
            matches!(profile.complexity_band, "small" | "medium" | "large"),
            "invalid complexity band: {}",
            profile.complexity_band
        );
        assert!(
            !profile.scripts.is_empty(),
            "profile {} must define at least one stage script",
            profile.id
        );
        for script in profile.scripts {
            assert!(Path::new(script).exists(), "missing stage script: {script}");
            assert!(
                seen.insert(script),
                "stage script {script} is duplicated across profiles"
            );
        }
    }
}

#[test]
fn seed_derivation_is_deterministic_and_profile_scoped() {
    let small1 = derive_profile_seed("4242", "small");
    let small2 = derive_profile_seed("4242", "small");
    let medium = derive_profile_seed("4242", "medium");

    assert_eq!(small1, "4242:small");
    assert_eq!(small1, small2, "seed derivation must be deterministic");
    assert_ne!(small1, medium, "profile seeds must be profile-scoped");
}

#[test]
fn scenario_selection_mode_filters_profiles() {
    assert_eq!(
        select_profiles("all").expect("all"),
        vec!["small", "medium", "large"]
    );
    assert_eq!(select_profiles("small").expect("small"), vec!["small"]);
    assert_eq!(select_profiles("medium").expect("medium"), vec!["medium"]);
    assert_eq!(select_profiles("large").expect("large"), vec!["large"]);
}

#[test]
fn scenario_selection_rejects_unknown_mode() {
    let err = select_profiles("xlarge").expect_err("must fail");
    assert!(
        err.contains("PROFILE_MODE"),
        "error must describe PROFILE_MODE contract"
    );
}

#[test]
fn failure_classification_maps_stage_and_timeout() {
    assert_eq!(
        classify_failure("test_doctor_workspace_scan_e2e", 1),
        "workspace_scan_failure"
    );
    assert_eq!(
        classify_failure("test_doctor_invariant_analyzer_e2e", 1),
        "invariant_analyzer_failure"
    );
    assert_eq!(
        classify_failure("test_doctor_orchestration_state_machine_e2e", 1),
        "orchestration_failure"
    );
    assert_eq!(
        classify_failure("test_doctor_remediation_verification_e2e", 1),
        "remediation_or_reporting_failure"
    );
    assert_eq!(classify_failure("unknown-stage", 2), "unknown_failure");
    assert_eq!(classify_failure("any-stage", 124), "timeout");
}

#[test]
fn diagnosis_time_delta_handles_zero_baseline() {
    assert_eq!(diagnosis_time_delta_pct(0.0, 12.0), 0.0);
    assert_eq!(diagnosis_time_delta_pct(10.0, 12.5), 25.0);
}

#[test]
fn false_transition_rates_capture_fp_and_fn_pairs() {
    let run1 = ["failed", "passed", "passed", "failed"];
    let run2 = ["passed", "failed", "passed", "failed"];
    let (fp, fn_rate) = false_transition_rates(&run1, &run2);

    assert!(
        (fp - 25.0).abs() < f64::EPSILON,
        "expected one false-positive pair out of four"
    );
    assert!(
        (fn_rate - 25.0).abs() < f64::EPSILON,
        "expected one false-negative pair out of four"
    );
}

#[test]
fn remediation_success_rate_is_bounded() {
    assert_eq!(remediation_success_rate_pct(0, 0), 0.0);
    assert_eq!(remediation_success_rate_pct(3, 4), 75.0);
}

#[test]
fn operator_confidence_score_clamps_to_range() {
    let high = operator_confidence_score(0.0, 0.0, 0.0, 100.0, 100.0);
    assert!((high - 100.0).abs() < f64::EPSILON);

    let low = operator_confidence_score(90.0, 20.0, 20.0, 10.0, 10.0);
    assert!((0.0..=100.0).contains(&low));
    assert_eq!(low, 0.0);
}
