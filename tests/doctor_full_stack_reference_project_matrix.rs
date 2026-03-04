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
