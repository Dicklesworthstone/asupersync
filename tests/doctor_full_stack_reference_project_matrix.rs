#![allow(clippy::all)]
//! Full-Stack Reference Project Matrix Validation (Track 6.5)
//!
//! Validates deterministic profile-matrix definitions used by the
//! doctor full-stack reference-project regression suite.
//!
//! Bead: asupersync-2b4jj.6.5

#![allow(missing_docs)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::float_cmp)]
#![cfg(feature = "cli")]

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const DOC_PATH: &str = "docs/doctor_full_stack_reference_projects_contract.md";
const SCRIPT_PATH: &str = "scripts/test_doctor_full_stack_reference_projects_e2e.sh";
const ORCHESTRATION_SCRIPT_PATH: &str = "scripts/test_doctor_orchestration_state_machine_e2e.sh";
const WORKSPACE_SCAN_SCRIPT_PATH: &str = "scripts/test_doctor_workspace_scan_e2e.sh";
const REPORT_EXPORT_SCRIPT_PATH: &str = "scripts/test_doctor_report_export_e2e.sh";

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

fn load_orchestration_script() -> String {
    std::fs::read_to_string(repo_root().join(ORCHESTRATION_SCRIPT_PATH))
        .expect("failed to load doctor orchestration state-machine e2e script")
}

fn load_workspace_scan_script() -> String {
    std::fs::read_to_string(repo_root().join(WORKSPACE_SCAN_SCRIPT_PATH))
        .expect("failed to load doctor workspace scan e2e script")
}

fn load_report_export_script() -> String {
    std::fs::read_to_string(repo_root().join(REPORT_EXPORT_SCRIPT_PATH))
        .expect("failed to load doctor report export e2e script")
}

fn unique_test_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("failed to create unique temp dir");
    dir
}

fn single_artifact_dir(staging_root: &Path) -> PathBuf {
    let artifact_dirs: Vec<PathBuf> = fs::read_dir(staging_root)
        .expect("failed to read staging root")
        .map(|entry| entry.expect("failed to read dir entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(
        artifact_dirs.len(),
        1,
        "expected exactly one artifact dir in {}",
        staging_root.display()
    );
    artifact_dirs
        .into_iter()
        .next()
        .expect("artifact dir missing after len check")
}

fn unique_test_seed(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    format!("{prefix}:{nanos}")
}

fn write_executable_script(path: &Path, contents: &str) {
    fs::write(path, contents).expect("failed to write executable script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(path, perms).expect("failed to chmod executable script");
    }
}

fn find_artifact_dir_by_suite_and_seed(output_root: &Path, suite_id: &str, seed: &str) -> PathBuf {
    let artifact_dirs: Vec<PathBuf> = fs::read_dir(output_root)
        .expect("failed to read artifact output root")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if !path.is_dir() {
                return None;
            }
            let summary_path = path.join("summary.json");
            let summary = fs::read_to_string(summary_path).ok()?;
            let summary: Value = serde_json::from_str(&summary).ok()?;
            (summary.get("suite_id").and_then(Value::as_str) == Some(suite_id)
                && summary.get("seed").and_then(Value::as_str) == Some(seed))
            .then_some(path)
        })
        .collect();

    assert_eq!(
        artifact_dirs.len(),
        1,
        "expected exactly one artifact dir for suite {suite_id} seed {seed} in {}",
        output_root.display()
    );
    artifact_dirs
        .into_iter()
        .next()
        .expect("artifact dir missing after len check")
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

fn resolved_stage_failure_class(
    stage_id: &str,
    exit_code: i32,
    summary_failure_class: Option<&str>,
) -> String {
    if exit_code == 124 {
        return "timeout".to_string();
    }

    match summary_failure_class.map(str::trim) {
        Some(value)
            if !value.is_empty() && value != "none" && value != "missing" && value != "null" =>
        {
            value.to_string()
        }
        _ => classify_failure(stage_id, exit_code).to_string(),
    }
}

fn resolved_stage_repro_command(
    stage_repro_command: &str,
    summary_repro_command: Option<&str>,
) -> String {
    match summary_repro_command.map(str::trim) {
        Some(value) if !value.is_empty() && value != "null" => value.to_string(),
        _ => stage_repro_command.to_string(),
    }
}

fn stage_attempt_passes(exit_code: i32, summary_status: &str, summary_failure_class: &str) -> bool {
    exit_code == 0 && summary_status == "passed" && summary_failure_class == "none"
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
fn script_preserves_stage_summary_failure_details() {
    let script = load_script();
    let required_tokens = [
        "resolved_stage_failure_class()",
        "resolved_stage_repro_command()",
        "summary_failure_class",
        "summary_repro_command",
        "summary reported status=${summary_status} failure_class=${summary_failure_class}; rejecting attempt",
        "resolved_stage_failure_class \"${stage_id}\" \"${exit_code}\" \"${summary_failure_class}\"",
        "resolved_stage_repro_command \"${stage_repro_command}\" \"${summary_repro_command}\"",
        "failed_stages:",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "script must preserve stage summary failure metadata token {token}"
        );
    }
}

#[test]
fn orchestration_stage_script_uses_staging_before_publish() {
    let script = load_orchestration_script();
    let required_tokens = [
        "STAGING_ROOT=",
        "PUBLISHED_ARTIFACT_DIR=",
        "ensure_artifact_dirs()",
        "publish_artifacts()",
        "rch_attempt_went_local()",
        "write_summary()",
        "mark_publish_failure()",
        "summary.publish.tmp",
        "falling back to local",
        "artifact_publish_failure",
        "rch_local_fallback",
        "cp \"${SUMMARY_FILE}\" \"${PUBLISHED_ARTIFACT_DIR}/summary.json\"",
        "\"${PUBLISHED_ARTIFACT_DIR}/summary.json\"",
        "\"${PUBLISHED_ARTIFACT_DIR}/run1.log\"",
        "\"${PUBLISHED_ARTIFACT_DIR}\"",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "orchestration stage script missing staging/publish token {token}"
        );
    }
}

#[test]
fn workspace_scan_stage_script_contains_fail_closed_rch_tokens() {
    let script = load_workspace_scan_script();
    let required_tokens = [
        "rch_attempt_went_local()",
        "update_run_failure_class()",
        "fell back to local cargo; rejecting attempt",
        "rm -f \"${run_json}\"",
        "DOCTOR_FULLSTACK_SINGLE_RUN",
        "FAILURE_CLASS=\"rch_local_fallback\"",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "workspace scan stage script missing fail-closed token {token}"
        );
    }
}

#[test]
fn report_export_stage_script_contains_fail_closed_rch_tokens() {
    let script = load_report_export_script();
    let required_tokens = [
        "rch_attempt_went_local()",
        "update_run_failure_class()",
        "fell back to local cargo; rejecting attempt",
        "rm -f \"${run_json}\"",
        "DOCTOR_FULLSTACK_SINGLE_RUN",
        "FAILURE_CLASS=\"rch_local_fallback\"",
    ];
    for token in required_tokens {
        assert!(
            script.contains(token),
            "report export stage script missing fail-closed token {token}"
        );
    }
}

#[test]
fn orchestration_stage_script_rejects_rch_local_fallback() {
    let temp_root = unique_test_temp_dir("asupersync-orch-rch-local-fallback");
    let shim_dir = temp_root.join("shim");
    let script_tmp = temp_root.join("tmp");
    fs::create_dir_all(&shim_dir).expect("failed to create shim dir");
    fs::create_dir_all(&script_tmp).expect("failed to create tmp dir");

    let fake_rch = shim_dir.join("fake-rch");
    write_executable_script(
        &fake_rch,
        r#"#!/usr/bin/env bash
set -euo pipefail
cat <<'ENDLOG'
[RCH] local (all worker circuits open)
running 5 tests
test orchestration_state_machine_alpha ... ok
test orchestration_state_machine_beta ... ok
test orchestration_state_machine_gamma ... ok
test orchestration_state_machine_delta ... ok
test orchestration_state_machine_epsilon ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
ENDLOG
"#,
    );

    let output = Command::new("bash")
        .arg(repo_root().join(ORCHESTRATION_SCRIPT_PATH))
        .env("TMPDIR", &script_tmp)
        .env("RCH_BIN", &fake_rch)
        .env("TEST_SEED", "4242:rch-local-fallback")
        .env("DOCTOR_FULLSTACK_SINGLE_RUN", "1")
        .output()
        .expect("failed to execute orchestration script");

    assert!(
        !output.status.success(),
        "script should fail when rch falls back local"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("Status:         failed"),
        "stdout should report failed status, got:\n{stdout}"
    );

    let artifact_dir = single_artifact_dir(
        &script_tmp.join("asupersync-e2e-staging/doctor_orchestration_state_machine"),
    );
    let summary: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("summary.json"))
            .expect("failed to read orchestration summary"),
    )
    .expect("summary should parse as json");

    assert_eq!(summary["status"], "failed");
    assert_eq!(summary["failure_class"], "rch_local_fallback");
    assert_eq!(summary["exit_code"], 1);
    assert_eq!(summary["tests_passed"], 0);
    assert_eq!(summary["tests_failed"], 1);
}

#[test]
fn workspace_scan_stage_script_rejects_rch_local_fallback() {
    let temp_root = unique_test_temp_dir("asupersync-workspace-scan-rch-local-fallback");
    let shim_dir = temp_root.join("shim");
    fs::create_dir_all(&shim_dir).expect("failed to create shim dir");

    let fake_rch = shim_dir.join("fake-rch");
    write_executable_script(
        &fake_rch,
        r#"#!/usr/bin/env bash
set -euo pipefail
cat <<'ENDLOG'
[RCH] local (all worker circuits open)
{"scanner_version":"doctor-workspace-scan-v1","taxonomy_version":"capability-surfaces-v1"}
ENDLOG
"#,
    );

    let seed = unique_test_seed("4242:workspace-scan-rch-local-fallback");
    let output = Command::new("bash")
        .arg(repo_root().join(WORKSPACE_SCAN_SCRIPT_PATH))
        .env("RCH_BIN", &fake_rch)
        .env("TEST_SEED", &seed)
        .env("DOCTOR_FULLSTACK_SINGLE_RUN", "1")
        .env("RCH_RETRY_ATTEMPTS", "1")
        .output()
        .expect("failed to execute workspace scan script");

    assert!(
        !output.status.success(),
        "workspace scan script should fail when rch falls back local"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("Status:         failed"),
        "stdout should report failed status, got:\n{stdout}"
    );

    let artifact_dir = find_artifact_dir_by_suite_and_seed(
        &repo_root().join("target/e2e-results/doctor_workspace_scan"),
        "doctor_workspace_scan_e2e",
        &seed,
    );
    let summary: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("summary.json"))
            .expect("failed to read workspace scan summary"),
    )
    .expect("summary should parse as json");

    assert_eq!(summary["status"], "failed");
    assert_eq!(summary["failure_class"], "rch_local_fallback");
    assert_eq!(summary["exit_code"], 1);
    assert_eq!(summary["tests_passed"], 0);
    assert_eq!(summary["tests_failed"], 1);
    assert!(
        !artifact_dir.join("scan_run1.json").exists(),
        "workspace scan should not keep captured JSON from a local fallback attempt"
    );
}

#[test]
fn report_export_stage_script_rejects_rch_local_fallback() {
    let temp_root = unique_test_temp_dir("asupersync-report-export-rch-local-fallback");
    let shim_dir = temp_root.join("shim");
    fs::create_dir_all(&shim_dir).expect("failed to create shim dir");

    let fake_rch = shim_dir.join("fake-rch");
    write_executable_script(
        &fake_rch,
        r#"#!/usr/bin/env bash
set -euo pipefail
cat <<'ENDLOG'
[RCH] local (all worker circuits open)
{"schema_version":"doctor-report-export-v1","core_schema_version":"doctor-core-report-v1","extension_schema_version":"doctor-advanced-report-v1"}
ENDLOG
"#,
    );

    let seed = unique_test_seed("4242:report-export-rch-local-fallback");
    let output = Command::new("bash")
        .arg(repo_root().join(REPORT_EXPORT_SCRIPT_PATH))
        .env("RCH_BIN", &fake_rch)
        .env("TEST_SEED", &seed)
        .env("DOCTOR_FULLSTACK_SINGLE_RUN", "1")
        .env("RCH_RETRY_ATTEMPTS", "1")
        .output()
        .expect("failed to execute report export script");

    assert!(
        !output.status.success(),
        "report export script should fail when rch falls back local"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("Status:         failed"),
        "stdout should report failed status, got:\n{stdout}"
    );

    let artifact_dir = find_artifact_dir_by_suite_and_seed(
        &repo_root().join("target/e2e-results/doctor_report_export"),
        "doctor_report_export_e2e",
        &seed,
    );
    let summary: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("summary.json"))
            .expect("failed to read report export summary"),
    )
    .expect("summary should parse as json");

    assert_eq!(summary["status"], "failed");
    assert_eq!(summary["failure_class"], "rch_local_fallback");
    assert_eq!(summary["exit_code"], 1);
    assert_eq!(summary["tests_passed"], 0);
    assert_eq!(summary["tests_failed"], 1);
    assert!(
        !artifact_dir.join("report_export_run1.json").exists(),
        "report export should not keep captured JSON from a local fallback attempt"
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

#[test]
fn resolved_stage_failure_class_prefers_child_summary_reason() {
    assert_eq!(
        resolved_stage_failure_class(
            "test_doctor_orchestration_state_machine_e2e",
            1,
            Some("rch_local_fallback"),
        ),
        "rch_local_fallback"
    );
    assert_eq!(
        resolved_stage_failure_class(
            "test_doctor_orchestration_state_machine_e2e",
            1,
            Some("none")
        ),
        "orchestration_failure"
    );
    assert_eq!(
        resolved_stage_failure_class(
            "test_doctor_orchestration_state_machine_e2e",
            124,
            Some("missing")
        ),
        "timeout"
    );
    assert_eq!(
        resolved_stage_failure_class(
            "test_doctor_orchestration_state_machine_e2e",
            124,
            Some("rch_local_fallback")
        ),
        "timeout"
    );
}

#[test]
fn resolved_stage_repro_command_prefers_child_summary_repro() {
    let stage_repro = "DOCTOR_FULLSTACK_SINGLE_RUN=1 TEST_SEED=4242:medium RCH_BIN=/tmp/fake-rch bash /repo/scripts/test_doctor_orchestration_state_machine_e2e.sh";
    let summary_repro = "TEST_LOG_LEVEL=info RUST_LOG=asupersync=info TEST_SEED=4242:medium RCH_BIN=/tmp/fake-rch bash /repo/scripts/test_doctor_orchestration_state_machine_e2e.sh";

    assert_eq!(
        resolved_stage_repro_command(stage_repro, Some(summary_repro)),
        summary_repro
    );
    assert_eq!(
        resolved_stage_repro_command(stage_repro, Some("")),
        stage_repro
    );
}

#[test]
fn stage_attempt_requires_passed_summary_and_none_failure_class() {
    assert!(stage_attempt_passes(0, "passed", "none"));
    assert!(!stage_attempt_passes(0, "failed", "rch_local_fallback"));
    assert!(!stage_attempt_passes(0, "passed", "rch_local_fallback"));
    assert!(!stage_attempt_passes(1, "passed", "none"));
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
