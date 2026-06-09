//! Contract tests for durable RCH proof submission lifecycle planning.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/durable_rch_proof_submission.py";
const GENERATED_AT: &str = "2026-06-09T08:45:00Z";
const HEAD: &str = "01a40c0e9a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const SOURCE_TREE: &str = "git-tree:01a40c0e9";
const LANE_ID: &str = "proof-lane-manifest-contract";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_submission(extra_args: &[&str]) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--lane-id")
        .arg(LANE_ID)
        .arg("--agent")
        .arg("MistyMill")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--branch")
        .arg("main")
        .arg("--head-commit")
        .arg(HEAD)
        .arg("--expected-head")
        .arg(HEAD)
        .arg("--source-tree-fingerprint")
        .arg(SOURCE_TREE)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    command.args(extra_args);
    command.output().expect("run durable submission helper")
}

fn submission_json(extra_args: &[&str]) -> Value {
    let output = run_submission(extra_args);
    assert!(
        output.status.success(),
        "submission helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("submission output must be JSON")
}

fn write_json_fixture(value: &Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create JSON fixture");
    serde_json::to_writer_pretty(&mut file, value).expect("write JSON fixture");
    writeln!(file).expect("terminate JSON fixture");
    file
}

fn manifest_with_lane_command(command: &str) -> tempfile::NamedTempFile {
    let manifest_path = repo_root().join("artifacts/proof_lane_manifest_v1.json");
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("read proof lane manifest"))
            .expect("parse proof lane manifest");
    let lanes = manifest["lanes"].as_array_mut().expect("manifest lanes");
    let lane = lanes
        .iter_mut()
        .find(|lane| lane["lane_id"].as_str() == Some(LANE_ID))
        .expect("target lane exists");
    lane["command"] = Value::String(command.to_string());
    write_json_fixture(&manifest)
}

fn reason_codes(record: &Value) -> Vec<String> {
    record["reason_codes"]
        .as_array()
        .expect("reason_codes")
        .iter()
        .map(|value| value.as_str().expect("reason string").to_string())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "submission helper must exist at {SCRIPT_PATH}"
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
fn accepted_submission_freezes_manifest_command_source_and_resume_token() {
    let record = submission_json(&[]);

    assert_eq!(
        record["schema_version"].as_str(),
        Some("durable-rch-proof-submission-v1")
    );
    assert_eq!(record["decision"].as_str(), Some("accepted"));
    assert!(
        record["reason_codes"]
            .as_array()
            .expect("reasons")
            .is_empty()
    );
    assert_eq!(
        record["submission"]["lifecycle_state"].as_str(),
        Some("queued")
    );
    assert_eq!(
        record["submission"]["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    assert_eq!(
        record["submission"]["command"]["remote_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        record["submission"]["command"]["local_fallback_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        record["submission"]["command"]["target_dir"].as_str(),
        Some("${TMPDIR:-/tmp}/rch_target_proof_lane_manifest")
    );
    assert_eq!(
        record["submission"]["source"]["branch"].as_str(),
        Some("main")
    );
    assert_eq!(
        record["submission"]["source"]["expected_head"].as_str(),
        Some(HEAD)
    );
    assert_eq!(
        record["submission"]["receipt_expectations"]["receipt_schema_version"].as_str(),
        Some("durable-rch-proof-receipt-v1")
    );
    assert_eq!(
        record["submission"]["resume"]["observable_without_submitter"].as_bool(),
        Some(true)
    );
    assert_eq!(
        record["submission"]["execution"]["live_rch_invoked"].as_bool(),
        Some(false)
    );
    assert_eq!(
        record["submission"]["execution"]["tracker_mutation_allowed"].as_bool(),
        Some(false)
    );
    assert!(
        record["submission"]["command"]["command_fingerprint"]
            .as_str()
            .expect("command fingerprint")
            .starts_with("sha256:")
    );
}

#[test]
fn submission_id_is_stable_for_same_lane_head_and_command() {
    let left = submission_json(&[]);
    let right = submission_json(&[]);

    assert_eq!(
        left["submission"]["submission_id"],
        right["submission"]["submission_id"]
    );
    assert_eq!(
        left["submission"]["lease"]["match_key"],
        right["submission"]["lease"]["match_key"]
    );
    assert_eq!(
        left["submission"]["resume"]["resume_token"],
        right["submission"]["resume"]["resume_token"]
    );
}

#[test]
fn duplicate_running_submission_coalesces_to_existing_record() {
    let first = submission_json(&[]);
    let existing = json!({
        "submissions": [{
            "submission_id": "drps-existing-running",
            "manifest_lane_id": LANE_ID,
            "lifecycle_state": "running",
            "command": {
                "command_fingerprint": first["submission"]["command"]["command_fingerprint"]
            },
            "source": {
                "expected_head": HEAD
            },
            "lease": {
                "match_key": first["submission"]["lease"]["match_key"]
            }
        }]
    });
    let fixture = write_json_fixture(&existing);
    let record = submission_json(&[
        "--existing-submissions",
        fixture.path().to_str().expect("fixture path"),
    ]);

    assert_eq!(record["decision"].as_str(), Some("coalesced"));
    assert_eq!(
        record["submission"]["lease"]["duplicate_action"].as_str(),
        Some("coalesced-existing-submission")
    );
    assert_eq!(
        record["submission"]["lease"]["existing_submission_id"].as_str(),
        Some("drps-existing-running")
    );
    assert_eq!(
        record["submission"]["lifecycle_state"].as_str(),
        Some("running")
    );
}

#[test]
fn duplicate_lane_head_with_different_command_is_rejected() {
    let existing = json!({
        "submissions": [{
            "submission_id": "drps-conflict",
            "manifest_lane_id": LANE_ID,
            "lifecycle_state": "queued",
            "command": {
                "command_fingerprint": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            },
            "source": {
                "expected_head": HEAD
            },
            "lease": {
                "match_key": "sha256:conflict"
            }
        }]
    });
    let fixture = write_json_fixture(&existing);
    let record = submission_json(&[
        "--existing-submissions",
        fixture.path().to_str().expect("fixture path"),
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&record).contains(&"duplicate-submission-conflict".to_string()));
    assert_eq!(
        record["submission"]["lease"]["duplicate_action"].as_str(),
        Some("rejected-conflicting-lane-head-command")
    );
}

#[test]
fn missing_remote_required_command_fails_closed_as_local_fallback_refusal() {
    let manifest =
        manifest_with_lane_command("cargo test -p asupersync --test proof_lane_manifest_contract");
    let record = submission_json(&[
        "--manifest",
        manifest.path().to_str().expect("manifest path"),
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&record).contains(&"command-mismatch".to_string()));
    assert_eq!(
        record["submission"]["lifecycle_state"].as_str(),
        Some("terminal_fail")
    );
    assert_eq!(
        record["submission"]["terminal_classification"].as_str(),
        Some("local_fallback_refused")
    );
    assert_eq!(
        record["submission"]["execution"]["live_rch_invoked"].as_bool(),
        Some(false)
    );
}

#[test]
fn non_main_branch_and_stale_head_are_rejected_before_execution() {
    let record = submission_json(&[
        "--branch",
        "feature",
        "--head-commit",
        "2222222222222222222222222222222222222222",
        "--expected-head",
        HEAD,
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    let reasons = reason_codes(&record);
    assert!(reasons.contains(&"branch-mismatch".to_string()));
    assert!(reasons.contains(&"stale-head".to_string()));
    assert_eq!(
        record["submission"]["proof_evidence_status"].as_str(),
        Some("refused")
    );
}

#[test]
fn dirty_overlap_with_lane_source_paths_is_rejected() {
    let record = submission_json(&[
        "--dirty-frontier-status",
        "dirty",
        "--dirty-path",
        "tests/proof_lane_manifest_contract.rs",
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&record).contains(&"dirty-frontier-overlap".to_string()));
}

#[test]
fn record_output_writes_to_explicit_tmp_path_and_rejects_tracker_paths() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output_path = tempdir.path().join("submission.json");
    let output_text = output_path.to_str().expect("output path");
    let record = submission_json(&["--record-output", output_text]);

    assert_eq!(record["decision"].as_str(), Some("accepted"));
    assert!(output_path.exists(), "record output should be written");
    let written: Value = serde_json::from_str(
        &fs::read_to_string(&output_path).expect("read written submission record"),
    )
    .expect("written record JSON");
    assert_eq!(
        written["submission"]["submission_id"],
        record["submission"]["submission_id"]
    );

    let refused = submission_json(&["--record-output", ".beads/durable-submission.json"]);
    assert_eq!(refused["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&refused).contains(&"output-path-not-allowed".to_string()));
    assert_eq!(
        refused["submission"]["terminal_classification"].as_str(),
        Some("cargo_failure")
    );
}
