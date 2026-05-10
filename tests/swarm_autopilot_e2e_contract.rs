//! Contract tests for the synthetic swarm autopilot E2E proof.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_autopilot_e2e.py";
const FIXTURE_ROOT: &str = "tests/fixtures/swarm_autopilot_e2e";
const GENERATED_AT: &str = "2026-05-10T09:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_e2e(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run swarm autopilot e2e proof")
}

fn e2e_json(fixture: &str) -> Value {
    let output = run_e2e(fixture);
    assert!(
        output.status.success(),
        "e2e helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("e2e output must be JSON")
}

fn stage<'a>(receipt: &'a Value, stage_id: &str) -> &'a Value {
    receipt["stage_logs"]
        .as_array()
        .expect("stage logs")
        .iter()
        .find(|row| row["stage_id"].as_str() == Some(stage_id))
        .expect("stage should exist")
}

fn stage_ids(receipt: &Value) -> BTreeSet<String> {
    receipt["stage_logs"]
        .as_array()
        .expect("stage logs")
        .iter()
        .map(|row| row["stage_id"].as_str().expect("stage id").to_owned())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "e2e helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn happy_path_composes_autopilot_helpers() {
    let receipt = e2e_json("happy_path.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("swarm-autopilot-e2e-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["scenario_id"].as_str(), Some("happy_path"));
    assert_eq!(
        receipt["scenario_outcome"].as_str(),
        Some("ready-to-closeout")
    );
    assert_eq!(receipt["overall_status"].as_str(), Some("pass"));
    assert_eq!(receipt["summary"]["stage_count"].as_u64(), Some(4));
    assert_eq!(
        stage_ids(&receipt),
        BTreeSet::from([
            "closeout_verifier".to_owned(),
            "proof_receipt".to_owned(),
            "scanner_templates".to_owned(),
            "work_finder".to_owned(),
        ])
    );

    let proof = stage(&receipt, "proof_receipt");
    assert_eq!(proof["status"].as_str(), Some("pass"));
    assert_eq!(
        proof["observed"]["classification"].as_str(),
        Some("remote_success")
    );
    assert_eq!(
        proof["observed"]["target_dir_audit_status"].as_str(),
        Some("pass")
    );
    assert!(
        proof["command"]
            .as_str()
            .expect("command")
            .contains("scripts/rch_retrieval_receipt.py")
    );

    let finder = stage(&receipt, "work_finder");
    assert_eq!(
        finder["observed"]["recommendation_candidate_id"].as_str(),
        Some("testing-fuzzing:postgres_row_description")
    );
    let scanner = stage(&receipt, "scanner_templates");
    assert_eq!(scanner["observed"]["template_count"].as_u64(), Some(4));
    let closeout = stage(&receipt, "closeout_verifier");
    assert_eq!(
        closeout["observed"]["overall_status"].as_str(),
        Some("pass")
    );
}

#[test]
fn blocked_path_is_successful_when_blockers_are_observed() {
    let receipt = e2e_json("blocked_path.json");

    assert_eq!(receipt["scenario_id"].as_str(), Some("blocked_path"));
    assert_eq!(
        receipt["scenario_outcome"].as_str(),
        Some("blocked-as-expected")
    );
    assert_eq!(receipt["overall_status"].as_str(), Some("pass"));

    let proof = stage(&receipt, "proof_receipt");
    assert_eq!(
        proof["observed"]["classification"].as_str(),
        Some("local_fallback")
    );
    assert_eq!(proof["observed"]["decision"].as_str(), Some("invalid"));
    assert_eq!(
        proof["observed"]["target_dir_audit_status"].as_str(),
        Some("blocker")
    );

    let finder = stage(&receipt, "work_finder");
    assert_eq!(
        finder["observed"]["recommendation_category"].as_str(),
        Some("blocked-no-safe-work")
    );
    let scanner = stage(&receipt, "scanner_templates");
    assert_eq!(scanner["observed"]["template_count"].as_u64(), Some(0));
    let closeout = stage(&receipt, "closeout_verifier");
    assert_eq!(
        closeout["observed"]["overall_status"].as_str(),
        Some("fail")
    );
}

#[test]
fn helper_aggregates_non_mutation_safety() {
    let receipt = e2e_json("happy_path.json");

    assert_eq!(receipt["safety"]["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        receipt["safety"]["stage_safety_findings"]
            .as_array()
            .expect("stage safety findings")
            .len(),
        0
    );
    for key in [
        "runs_live_agent_mail_mutation",
        "runs_beads_mutation",
        "runs_git_mutation",
        "runs_cargo",
        "runs_destructive_command",
        "creates_branch_or_worktree",
    ] {
        assert_eq!(
            receipt["safety"]["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
