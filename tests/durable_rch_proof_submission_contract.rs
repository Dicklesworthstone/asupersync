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

fn run_cli(args: &[&str]) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run durable proof CLI")
}

fn cli_json(args: &[&str]) -> Value {
    let output = run_cli(args);
    assert!(
        output.status.success(),
        "durable proof CLI failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI output must be JSON")
}

fn accepted_submission() -> Value {
    submission_json(&[])["submission"].clone()
}

fn value_str(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
        .to_string()
}

fn job_store(submissions: Vec<Value>, receipts: Vec<Value>) -> tempfile::NamedTempFile {
    write_json_fixture(&json!({
        "submissions": submissions,
        "receipts": receipts,
    }))
}

fn receipt_for(
    submission: &Value,
    lifecycle_state: &str,
    terminal_classification: &str,
    proof_evidence_status: &str,
    citable: bool,
    refusal_reasons: &[&str],
) -> Value {
    json!({
        "schema_version": "durable-rch-proof-receipt-v1",
        "receipt_id": format!("drpr-{terminal_classification}"),
        "submission_id": submission["submission_id"],
        "generated_at": GENERATED_AT,
        "manifest_lane_id": submission["manifest_lane_id"],
        "manifest_guarantee_ids": submission["manifest_guarantee_ids"],
        "claim_scope": submission["claim_scope"],
        "proof_evidence_status": proof_evidence_status,
        "lifecycle_state": lifecycle_state,
        "terminal_classification": terminal_classification,
        "command": submission["command"],
        "source": submission["source"],
        "rch_provenance": {
            "worker_id": "vmi1227854",
            "remote_route_segments": ["rch-daemon", "vmi1227854"],
            "submitted_at": "2026-06-09T08:40:00Z",
            "started_at": "2026-06-09T08:40:10Z",
            "finished_at": "2026-06-09T08:41:00Z",
            "detector_progress_stale": terminal_classification == "stale_progress_canceled",
            "detector_heartbeat_stale": false
        },
        "outcome": {
            "status": if terminal_classification == "pass" { "pass" } else { "fail" },
            "exit_code": if terminal_classification == "pass" { 0 } else { 101 },
            "output_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "first_blocker_lines": ["error: contract failed"],
            "cancellation_reason": if terminal_classification == "operator_canceled" {
                "operator-requested"
            } else {
                ""
            },
            "staleness_reason": if terminal_classification == "stale_progress_canceled" {
                "progress-stale"
            } else {
                ""
            }
        },
        "claim_boundaries": {
            "citable": citable,
            "covers": "focused durable RCH lane only",
            "explicit_not_covered": [
                "release-readiness",
                "workspace-health",
                "live-rch-fleet-availability"
            ],
            "refusal_reason_codes": refusal_reasons
        }
    })
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

#[test]
fn status_running_submission_surfaces_lane_head_and_progress_metadata() {
    let mut submission = accepted_submission();
    submission["lifecycle_state"] = Value::String("running".to_string());
    submission["rch_provenance"] = json!({
        "worker_id": "vmi1227854",
        "remote_route_segments": ["rch-daemon", "vmi1227854"],
        "submitted_at": "2026-06-09T08:40:00Z",
        "started_at": "2026-06-09T08:40:10Z",
        "finished_at": "",
        "detector_progress_stale": false,
        "detector_heartbeat_stale": false
    });
    let submission_id = value_str(&submission, "submission_id");
    let store = job_store(vec![submission], vec![]);
    let record = cli_json(&[
        "status",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(
        record["schema_version"].as_str(),
        Some("durable-rch-proof-cli-v1")
    );
    assert_eq!(record["operation"].as_str(), Some("status"));
    assert_eq!(record["decision"].as_str(), Some("accepted"));
    assert_eq!(record["lifecycle_state"].as_str(), Some("running"));
    assert_eq!(record["manifest_lane_id"].as_str(), Some(LANE_ID));
    assert_eq!(record["source"]["head_commit"].as_str(), Some(HEAD));
    assert_eq!(
        record["command"]["command_fingerprint"]
            .as_str()
            .map(|text| text.starts_with("sha256:")),
        Some(true)
    );
    assert_eq!(
        record["rch_provenance"]["worker_id"].as_str(),
        Some("vmi1227854")
    );
    assert_eq!(
        record["rch_provenance"]["detector_progress_stale"].as_bool(),
        Some(false)
    );
    assert_eq!(record["terminal"].as_bool(), Some(false));
}

#[test]
fn status_terminal_pass_receipt_marks_receipt_citable() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let receipt = receipt_for(
        &submission,
        "terminal_pass",
        "pass",
        "fresh-rch-pass",
        true,
        &[],
    );
    let store = job_store(vec![submission], vec![receipt]);
    let record = cli_json(&[
        "status",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(record["decision"].as_str(), Some("accepted"));
    assert_eq!(record["receipt_available"].as_bool(), Some(true));
    assert_eq!(record["receipt_id"].as_str(), Some("drpr-pass"));
    assert_eq!(record["lifecycle_state"].as_str(), Some("terminal_pass"));
    assert_eq!(
        record["proof_evidence_status"].as_str(),
        Some("fresh-rch-pass")
    );
    assert_eq!(record["claim_boundaries"]["citable"].as_bool(), Some(true));
    assert_eq!(record["terminal"].as_bool(), Some(true));
}

#[test]
fn query_terminal_fail_includes_refusal_reasons_and_receipt() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let receipt = receipt_for(
        &submission,
        "terminal_fail",
        "cargo_failure",
        "blocked",
        false,
        &["failed-proof-status"],
    );
    let store = job_store(vec![submission], vec![receipt]);
    let record = cli_json(&[
        "query",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--claim",
        "proof-lane-manifest-contract",
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(record["operation"].as_str(), Some("query"));
    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&record).contains(&"failed-proof-status".to_string()));
    assert_eq!(
        record["receipt"]["terminal_classification"].as_str(),
        Some("cargo_failure")
    );
    assert_eq!(record["claim_boundaries"]["citable"].as_bool(), Some(false));
}

#[test]
fn status_terminal_stale_receipt_is_not_citable_green_proof() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let receipt = receipt_for(
        &submission,
        "terminal_stale",
        "stale_progress_canceled",
        "blocked",
        false,
        &["failed-proof-status"],
    );
    let store = job_store(vec![submission], vec![receipt]);
    let record = cli_json(&[
        "status",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(record["lifecycle_state"].as_str(), Some("terminal_stale"));
    assert_eq!(
        record["terminal_classification"].as_str(),
        Some("stale_progress_canceled")
    );
    assert_eq!(
        record["rch_provenance"]["detector_progress_stale"].as_bool(),
        Some(true)
    );
    assert_eq!(record["claim_boundaries"]["citable"].as_bool(), Some(false));
}

#[test]
fn unknown_submission_is_machine_readable_refusal() {
    let store = job_store(vec![accepted_submission()], vec![]);
    let record = cli_json(&[
        "status",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        "drps-missing",
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert_eq!(record["lifecycle_state"].as_str(), Some("unknown"));
    assert!(reason_codes(&record).contains(&"unknown-submission-id".to_string()));
}

#[test]
fn query_refuses_unsupported_broad_claim_even_with_pass_receipt() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let receipt = receipt_for(
        &submission,
        "terminal_pass",
        "pass",
        "fresh-rch-pass",
        true,
        &[],
    );
    let store = job_store(vec![submission], vec![receipt]);
    let record = cli_json(&[
        "query",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--claim",
        "workspace-health",
        "--generated-at",
        GENERATED_AT,
    ]);

    assert_eq!(record["decision"].as_str(), Some("refused"));
    assert!(reason_codes(&record).contains(&"broad-claim-unsupported".to_string()));
    assert_eq!(record["receipt_available"].as_bool(), Some(true));
    assert_eq!(record["claim_boundaries"]["citable"].as_bool(), Some(false));
    assert_eq!(
        record["receipt"]["claim_boundaries"]["citable"].as_bool(),
        Some(true)
    );
}

#[test]
fn cancel_records_operator_cancellation_separately_from_cargo_failure() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let store = job_store(vec![submission.clone()], vec![]);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cancel_path = tempdir.path().join("cancel.json");
    let record = cli_json(&[
        "cancel",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--agent",
        "MistyMill",
        "--reason-code",
        "operator-requested",
        "--generated-at",
        GENERATED_AT,
        "--record-output",
        cancel_path.to_str().expect("cancel path"),
    ]);

    assert_eq!(record["decision"].as_str(), Some("accepted"));
    assert_eq!(
        record["lifecycle_state"].as_str(),
        Some("terminal_canceled")
    );
    assert_eq!(
        record["terminal_classification"].as_str(),
        Some("operator_canceled")
    );
    assert_eq!(record["proof_evidence_status"].as_str(), Some("blocked"));
    assert_eq!(
        record["cancellation"]["not_cargo_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        record["cancellation"]["rch_cancel_invoked"].as_bool(),
        Some(false)
    );
    assert!(cancel_path.exists(), "cancel evidence should be written");

    let canceled_store = write_json_fixture(&json!({
        "submissions": [submission],
        "cancellations": [record["cancellation"].clone()]
    }));
    let status = cli_json(&[
        "status",
        "--job-store",
        canceled_store.path().to_str().expect("canceled store path"),
        "--submission-id",
        &submission_id,
        "--generated-at",
        GENERATED_AT,
    ]);
    assert_eq!(
        status["lifecycle_state"].as_str(),
        Some("terminal_canceled")
    );
    assert_eq!(
        status["terminal_classification"].as_str(),
        Some("operator_canceled")
    );
    assert_eq!(
        status["cancellation"]["not_cargo_failure"].as_bool(),
        Some(true)
    );
}

#[test]
fn human_status_output_is_single_line_and_concise() {
    let submission = accepted_submission();
    let submission_id = value_str(&submission, "submission_id");
    let store = job_store(vec![submission], vec![]);
    let output = run_cli(&[
        "status",
        "--job-store",
        store.path().to_str().expect("store path"),
        "--submission-id",
        &submission_id,
        "--generated-at",
        GENERATED_AT,
        "--output",
        "human",
    ]);

    assert!(
        output.status.success(),
        "human status failed: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("human output UTF-8");
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("status accepted"));
    assert!(text.contains("state=queued"));
    assert!(text.contains(&submission_id));
}
