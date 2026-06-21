//! Contract tests for the agent-swarm safe proof runner.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_runner.py";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const STATUS_SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const SCHEMA_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";
const RCH_OUTCOME_CONTRACT_PATH: &str = "artifacts/proof_runner_rch_outcome_contract_v1.json";
const FIXTURE_ROOT: &str = "tests/fixtures/proof_runner";

fn load_json(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn run_proof_runner(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new("python3").arg(SCRIPT_PATH).args(args).output()
}

fn run_python_snippet(source: &str) -> Output {
    Command::new("python3")
        .arg("-c")
        .arg(source)
        .output()
        .expect("python snippet should execute")
}

fn proof_runner_json(args: &[&str]) -> Value {
    let output = run_proof_runner(args).expect("proof runner should execute");
    assert!(
        output.status.success(),
        "proof runner failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

fn write_reservation_snapshot(raw: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create reservation snapshot fixture");
    file.write_all(raw.as_bytes())
        .expect("write reservation snapshot fixture");
    file
}

fn write_build_slot_snapshot(raw: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create build-slot snapshot fixture");
    file.write_all(raw.as_bytes())
        .expect("write build-slot snapshot fixture");
    file
}

fn write_text_fixture(raw: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create text fixture");
    file.write_all(raw.as_bytes()).expect("write text fixture");
    file
}

fn write_json_fixture(value: &Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create JSON fixture");
    serde_json::to_writer_pretty(&mut file, value).expect("write JSON fixture");
    writeln!(file).expect("terminate JSON fixture");
    file
}

fn output_json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

fn proof_status_dashboard_with_snapshot(snapshot: &Value, generated_at: &str) -> Value {
    let fixture = write_json_fixture(snapshot);
    let snapshot_path = fixture.path().to_str().expect("snapshot fixture path utf8");
    proof_runner_json(&[
        "--proof-status-dashboard",
        "--proof-status-snapshot",
        snapshot_path,
        "--proof-console-generated-at",
        generated_at,
        "--output",
        "json",
    ])
}

fn dashboard_claim_row<'a>(dashboard: &'a Value, claim_id: &str) -> &'a Value {
    dashboard["claim_status_rows"]
        .as_array()
        .expect("claim status rows")
        .iter()
        .find(|row| row["claim_id"].as_str() == Some(claim_id))
        .unwrap_or_else(|| panic!("claim row {claim_id} should be present"))
}

fn release_pack_golden_projection(result: &Value) -> Value {
    let pack = &result["proof_pack"];
    let source_artifacts = pack["source_artifacts"]
        .as_array()
        .expect("source artifact rows")
        .iter()
        .map(|row| {
            json!({
                "path": row["path"],
                "copy_path": row["copy_path"],
                "status": row["status"],
            })
        })
        .collect::<Vec<_>>();
    let proof_commands = pack["proof_commands"]
        .as_array()
        .expect("proof command rows")
        .iter()
        .map(|row| {
            json!({
                "lane_id": row["lane_id"],
                "expected_signal": row["expected_signal"],
                "guarantee_ids": row["guarantee_ids"],
                "command": row["command"],
            })
        })
        .collect::<Vec<_>>();
    let rch_log_rows = pack["rch_log_rows"]
        .as_array()
        .expect("rch log rows")
        .iter()
        .map(|row| {
            json!({
                "path": row["path"],
                "command": row["command"],
                "outcome_class": row["outcome_class"],
                "decision": row["decision"],
                "sha256": "sha256:[scrubbed]",
                "bytes": "[bytes]"
            })
        })
        .collect::<Vec<_>>();
    let tracker = &pack["summaries"]["tracker"];
    let status_count_keys = tracker["status_counts"]
        .as_object()
        .expect("tracker status counts")
        .keys()
        .map(|key| Value::String(key.clone()))
        .collect::<Vec<_>>();

    json!({
        "schema_version": pack["schema_version"],
        "generated_at": pack["generated_at"],
        "generator": pack["generator"],
        "source_artifacts": source_artifacts,
        "embedded_report_rows": [
            {
                "path": pack["embedded_report_rows"][0]["path"],
                "schema_version": pack["embedded_report_rows"][0]["schema_version"],
                "sha256": "sha256:[scrubbed]",
                "bytes": "[bytes]"
            }
        ],
        "embedded_reports": {
            "proof_console_report_v1": {
                "schema_version": pack["embedded_reports"]["proof_console_report_v1"]["schema_version"],
                "generated_at": pack["embedded_reports"]["proof_console_report_v1"]["generated_at"],
                "generator": pack["embedded_reports"]["proof_console_report_v1"]["generator"],
                "summary": pack["embedded_reports"]["proof_console_report_v1"]["summary"],
                "verdict": pack["embedded_reports"]["proof_console_report_v1"]["verdict"]
            }
        },
        "rch_log_rows": rch_log_rows,
        "proof_commands": proof_commands,
        "summaries": {
            "proof_console": pack["summaries"]["proof_console"],
            "conformance_registry": pack["summaries"]["conformance_registry"],
            "adapter_certification_matrix": pack["summaries"]["adapter_certification_matrix"],
            "tracker": {
                "path": tracker["path"],
                "status": tracker["status"],
                "sha256": "sha256:[scrubbed]",
                "valid_issue_count": "[count]",
                "status_count_keys": status_count_keys,
                "raw_issue_rows_embedded": tracker["raw_issue_rows_embedded"]
            }
        },
        "summary": pack["summary"],
        "failure_reasons": pack["failure_reasons"],
        "verdict": pack["verdict"]
    })
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURE_ROOT}/{fixture}"))
        .unwrap_or_else(|error| panic!("read proof runner fixture {fixture}: {error}"))
}

fn classify_fixture(fixture: &str, command: &str, touched_files: &[&str]) -> Value {
    classify_fixture_with_extra_args(fixture, command, touched_files, &[])
}

fn classify_fixture_with_extra_args(
    fixture: &str,
    command: &str,
    touched_files: &[&str],
    extra_args: &[&str],
) -> Value {
    let fixture_path = format!("{FIXTURE_ROOT}/{fixture}");
    let mut args = vec![
        "--classify-rch-log",
        fixture_path.as_str(),
        "--command",
        command,
        "--touched-files",
    ];
    args.extend_from_slice(touched_files);
    args.extend_from_slice(extra_args);
    args.extend_from_slice(&["--output", "json"]);
    proof_runner_json(&args)
}

fn proof_runner_disk_preflight_result(root_free_bytes: u64, dev_shm_free_bytes: u64) -> Value {
    let snapshot = write_json_fixture(&json!({
        "root": {
            "path": "/",
            "available": true,
            "free_bytes": root_free_bytes,
            "total_bytes": 4_194_304_u64,
            "used_bytes": 2_097_152_u64
        },
        "dev_shm": {
            "path": "/dev/shm",
            "available": true,
            "free_bytes": dev_shm_free_bytes,
            "total_bytes": 4_194_304_u64,
            "used_bytes": 2_097_152_u64
        }
    }));
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--skip-dirty-check",
        "--disk-preflight-snapshot",
        snapshot_path,
        "--disk-min-free-bytes",
        "1048576",
        "--disk-dev-shm-min-free-bytes",
        "1048576",
        "--output",
        "json",
    ])
}

fn assert_low_disk_guidance(disk: &Value, classification: &str) {
    assert_eq!(disk["classification"].as_str(), Some(classification));
    assert_eq!(
        disk["recommendation"].as_str(),
        Some("use_disk_safe_proof_path")
    );
    assert_eq!(
        disk["guidance"]["preferred_next_action"].as_str(),
        Some(
            "defer Cargo-heavy validation or capture an artifact-free proof receipt; do not delete files automatically"
        )
    );
    assert_eq!(
        disk["guidance"]["cargo_target_dir_guidance"].as_str(),
        Some("keep lane-specific CARGO_TARGET_DIR on any later Cargo rerun")
    );
    assert_eq!(
        disk["guidance"]["proof_receipt_guidance"].as_str(),
        Some("prefer artifact-free proof receipt")
    );
    assert_eq!(
        disk["guidance"]["cleanup_permission_record"].as_str(),
        Some("cleanup requires explicit user permission")
    );
    assert_eq!(
        disk["guidance"]["cleanup_requires_explicit_user_permission"].as_bool(),
        Some(true)
    );
    assert_eq!(
        disk["guidance"]["automatic_cleanup_performed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        disk["guidance"]["deletion_command_recommended"].as_bool(),
        Some(false)
    );
    assert_eq!(
        disk["custom_target_dir_validation_permitted"].as_bool(),
        Some(false)
    );
}

#[test]
fn proof_runner_script_exists_and_is_executable() {
    assert!(
        std::path::Path::new(SCRIPT_PATH).exists(),
        "proof runner script must exist at {SCRIPT_PATH}"
    );
    let output = run_proof_runner(&["--help"]).expect("proof runner must be executable");
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "proof runner --help should succeed"
    );
}

#[test]
fn proof_runner_can_list_available_lanes() {
    let result = proof_runner_json(&["--list-lanes", "--output", "json"]);
    let lanes = result["available_lanes"]
        .as_array()
        .expect("list-lanes should return available_lanes array");

    // Should have the key lanes from the manifest
    let lane_set: BTreeSet<String> = lanes
        .iter()
        .map(|v| v.as_str().expect("lane should be string").to_string())
        .collect();

    for required_lane in [
        "rustfmt-check",
        "all-targets-check",
        "clippy-all-targets",
        "lib-tests",
    ] {
        assert!(
            lane_set.contains(required_lane),
            "list-lanes should include {required_lane}"
        );
    }
}

#[test]
fn proof_runner_list_lanes_matches_exact_reviewed_golden() {
    let expected_fixture = "list_lanes_expected.json";
    let output = run_proof_runner(&["--list-lanes", "--output", "json"])
        .expect("proof runner should execute");
    assert!(
        output.status.success(),
        "proof runner failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("proof runner stdout must be UTF-8");
    let expected = fixture_text(expected_fixture);

    let actual_json: Value = serde_json::from_str(&actual).unwrap_or_else(|error| {
        panic!("actual proof-runner list-lanes JSON for {expected_fixture}: {error}")
    });
    let expected_json: Value = serde_json::from_str(&expected).unwrap_or_else(|error| {
        panic!("golden proof-runner list-lanes JSON {expected_fixture}: {error}")
    });
    assert_eq!(
        actual_json, expected_json,
        "parsed proof-runner lane list JSON drifted from {expected_fixture}"
    );
    assert_eq!(
        actual, expected,
        "proof runner list-lanes output changed; update the golden only after reviewing lane ordering and operator-facing JSON shape"
    );
}

#[test]
fn proof_runner_suggests_appropriate_lanes_for_rust_files() {
    let result = proof_runner_json(&[
        "--suggest-lanes",
        "--touched-files",
        "src/runtime/state.rs",
        "src/obligation/ledger.rs",
        "--output",
        "json",
    ]);

    let suggested = result["suggested_lanes"]
        .as_array()
        .expect("suggest-lanes should return suggested_lanes array");

    let suggestions: BTreeSet<String> = suggested
        .iter()
        .map(|v| v.as_str().expect("suggestion should be string").to_string())
        .collect();

    // Should suggest format check for any file
    assert!(suggestions.contains("rustfmt-check"));

    // Should suggest compilation and linting for Rust files
    assert!(suggestions.contains("all-targets-check"));
    assert!(suggestions.contains("clippy-all-targets"));

    // Should suggest lib tests for src/ files
    assert!(suggestions.contains("lib-tests"));
}

#[test]
fn proof_runner_suggests_dependency_checks_for_cargo_toml() {
    let result = proof_runner_json(&[
        "--suggest-lanes",
        "--touched-files",
        "Cargo.toml",
        "--output",
        "json",
    ]);

    let suggested = result["suggested_lanes"]
        .as_array()
        .expect("suggest-lanes should return suggested_lanes array");

    let suggestions: BTreeSet<String> = suggested
        .iter()
        .map(|v| v.as_str().expect("suggestion should be string").to_string())
        .collect();

    // Should suggest dependency validation for Cargo.toml changes
    assert!(suggestions.contains("default-production-tokio-tree"));
    assert!(suggestions.contains("rustfmt-check"));
}

#[test]
fn proof_runner_blocks_unknown_lanes() {
    let output = run_proof_runner(&[
        "--lane",
        "nonexistent-lane-12345",
        "--touched-files",
        "src/test.rs",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    // Should fail with exit code 1 (blocked)
    assert_eq!(output.status.code(), Some(1));

    let result: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("should return JSON on error");

    assert!(!result["preflight_passed"].as_bool().unwrap_or(true));
    let record = &result["validation_frontier_record"];
    assert_eq!(record["decision"].as_str(), Some("blocked-external"));
    assert_eq!(record["error_class"].as_str(), Some("unknown_proof_lane"));
}

#[test]
fn proof_runner_reports_unavailable_reservation_snapshot() {
    let snapshot = write_reservation_snapshot("{not-json");
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--reservation-snapshot",
        snapshot_path,
        "--skip-dirty-check",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    let record = &result["validation_frontier_record"];
    assert_eq!(record["decision"].as_str(), Some("blocked-external"));
    assert_eq!(
        record["error_class"].as_str(),
        Some("file_reservation_conflict")
    );
    assert!(
        record["summary"]
            .as_str()
            .expect("summary string")
            .contains("unavailable"),
        "malformed reservation snapshot should be reported as unavailable"
    );
    assert_eq!(
        result["reservation_check"]["classifications"][0]["classification"].as_str(),
        Some("unavailable")
    );
}

#[test]
fn proof_runner_blocks_peer_active_reservation_from_snapshot() {
    let snapshot = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "scripts/proof_runner.py",
              "agent_name": "TopazGoose",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    let record = &result["validation_frontier_record"];
    assert_eq!(
        record["error_class"].as_str(),
        Some("file_reservation_conflict")
    );
    assert_eq!(
        result["reservation_check"]["classifications"][0]["classification"].as_str(),
        Some("peer-active")
    );
    assert_eq!(
        record["first_failure"]["file"].as_str(),
        Some("scripts/proof_runner.py")
    );
}

#[test]
fn proof_runner_blocks_peer_directory_reservation_from_snapshot() {
    let snapshot = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "tests/fixtures/proof_runner",
              "agent_name": "TopazGoose",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "tests/fixtures/proof_runner/new.log",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    let record = &result["validation_frontier_record"];
    assert_eq!(
        record["error_class"].as_str(),
        Some("file_reservation_conflict")
    );
    assert_eq!(
        result["reservation_check"]["classifications"][0]["classification"].as_str(),
        Some("peer-active")
    );
    assert_eq!(
        result["reservation_check"]["classifications"][0]["path"].as_str(),
        Some("tests/fixtures/proof_runner/new.log")
    );
    assert_eq!(
        result["reservation_check"]["classifications"][0]["path_pattern"].as_str(),
        Some("tests/fixtures/proof_runner")
    );
}

#[test]
fn proof_runner_allows_owned_and_expired_reservations() {
    let snapshot = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "scripts/proof_runner.py",
              "agent_name": "BlackDove",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            },
            {
              "path_pattern": "tests/proof_runner_contract.rs",
              "agent_name": "TopazGoose",
              "expires_ts": "2000-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "tests/proof_runner_contract.rs",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    let classifications: BTreeSet<String> = result["reservation_check"]["classifications"]
        .as_array()
        .expect("classifications array")
        .iter()
        .map(|item| {
            item["classification"]
                .as_str()
                .expect("classification string")
                .to_string()
        })
        .collect();
    assert!(classifications.contains("owned-active"));
    assert!(classifications.contains("expired"));
}

#[test]
fn proof_runner_classifies_tracker_only_reservations() {
    let snapshot = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": ".beads/issues.jsonl",
              "agent_name": "CopperSpring",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");

    let unrelated = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);
    assert_eq!(unrelated["preflight_passed"].as_bool(), Some(true));
    assert_eq!(
        unrelated["reservation_check"]["classifications"]
            .as_array()
            .expect("classifications array")
            .len(),
        0,
        "tracker reservations should not affect unrelated touched files"
    );

    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        ".beads/issues.jsonl",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    assert_eq!(
        result["reservation_check"]["classifications"][0]["classification"].as_str(),
        Some("tracker-only")
    );
}

#[test]
fn proof_runner_blocks_unknown_owner_reservation() {
    let snapshot = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "src/lib.rs",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    assert_eq!(
        result["reservation_check"]["classifications"][0]["classification"].as_str(),
        Some("unknown-owner")
    );
}

#[test]
fn proof_runner_reports_reservation_check_unavailable_when_unconfigured() {
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    assert_eq!(
        result["reservation_check"]["source"].as_str(),
        Some("not_configured")
    );
    assert_eq!(
        result["reservation_check"]["classifications"]
            .as_array()
            .expect("classifications array")
            .len(),
        0
    );
}

#[test]
fn proof_runner_execute_allows_owned_build_slot_and_records_release_path() {
    let snapshot = write_build_slot_snapshot(
        r#"{
          "acquired": {
            "slot": "proof-runner-rch",
            "agent_name": "BlackDove",
            "expires_ts": "2999-01-01T00:00:00Z"
          }
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--build-slot-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--execute",
        "--output",
        "json",
    ]);

    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    assert_eq!(
        result["build_slot_check"]["classifications"][0]["classification"].as_str(),
        Some("acquired")
    );
    assert_eq!(
        result["build_slot_check"]["release_after_command"].as_str(),
        Some(
            "release_build_slot(project_key='/data/projects/asupersync', agent_name='BlackDove', slot='proof-runner-rch')"
        )
    );
}

#[test]
fn proof_runner_execute_blocks_peer_build_slot_conflict() {
    let snapshot = write_build_slot_snapshot(
        r#"{
          "conflicts": [
            {
              "slot": "proof-runner-rch",
              "holders": [
                {
                  "agent": "TopazGoose",
                  "expires_ts": "2999-01-01T00:00:00Z"
                }
              ]
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--build-slot-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--execute",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    assert_eq!(
        result["validation_frontier_record"]["error_class"].as_str(),
        Some("build_slot_conflict")
    );
    assert_eq!(
        result["build_slot_check"]["classifications"][0]["classification"].as_str(),
        Some("peer-active")
    );
    assert_eq!(
        result["build_slot_check"]["classifications"][0]["holder"].as_str(),
        Some("TopazGoose")
    );
}

#[test]
fn proof_runner_execute_blocks_when_only_expired_build_slot_is_present() {
    let snapshot = write_build_slot_snapshot(
        r#"{
          "build_slots": [
            {
              "slot": "proof-runner-rch",
              "agent_name": "BlackDove",
              "expires_ts": "2000-01-01T00:00:00Z"
            }
          ]
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let output = run_proof_runner(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--build-slot-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--execute",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    assert_eq!(output.status.code(), Some(1));
    let result = output_json(&output);
    assert_eq!(
        result["validation_frontier_record"]["error_class"].as_str(),
        Some("build_slot_unavailable")
    );
    assert_eq!(
        result["build_slot_check"]["classifications"][0]["classification"].as_str(),
        Some("expired")
    );
}

#[test]
fn proof_runner_records_renewed_and_released_build_slot_states() {
    let snapshot = write_build_slot_snapshot(
        r#"{
          "renewed": {
            "slot": "proof-runner-rch",
            "agent_name": "BlackDove",
            "expires_ts": "2999-01-01T00:00:00Z"
          },
          "released": {
            "slot": "proof-runner-rch",
            "agent_name": "BlackDove",
            "released_ts": "2026-05-08T04:00:00Z"
          }
        }"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--build-slot-snapshot",
        snapshot_path,
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--execute",
        "--output",
        "json",
    ]);

    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    let states: BTreeSet<String> = result["build_slot_check"]["classifications"]
        .as_array()
        .expect("build slot classifications array")
        .iter()
        .map(|item| {
            item["classification"]
                .as_str()
                .expect("classification string")
                .to_string()
        })
        .collect();
    assert!(states.contains("renewed"));
    assert!(states.contains("released"));
}

#[test]
fn proof_runner_dry_run_and_suggestions_do_not_require_build_slot_snapshot() {
    let dry_run = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "scripts/proof_runner.py",
        "--agent-name",
        "BlackDove",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);
    assert_eq!(dry_run["preflight_passed"].as_bool(), Some(true));
    assert_eq!(
        dry_run["build_slot_check"]["source"].as_str(),
        Some("not_required")
    );

    let suggestions = proof_runner_json(&[
        "--suggest-lanes",
        "--touched-files",
        "scripts/proof_runner.py",
        "--agent-name",
        "BlackDove",
        "--output",
        "json",
    ]);
    assert!(
        suggestions["suggested_lanes"]
            .as_array()
            .expect("suggestions array")
            .contains(&Value::String("rustfmt-check".to_string()))
    );
}

#[test]
fn proof_runner_disk_preflight_classifies_healthy_root_and_dev_shm() {
    let result = proof_runner_disk_preflight_result(2_097_152, 2_097_152);
    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    assert_eq!(result["recommendation"].as_str(), Some("proceed"));

    let disk = &result["disk_pressure_preflight"];
    assert_eq!(
        disk["schema_version"].as_str(),
        Some("proof-runner-disk-pressure-v1")
    );
    assert_eq!(disk["source"].as_str(), Some("fixture"));
    assert_eq!(disk["classification"].as_str(), Some("healthy"));
    assert_eq!(
        disk["guidance"]["preferred_next_action"].as_str(),
        Some("run requested proof lane as planned")
    );
    assert_eq!(
        disk["guidance"]["cleanup_requires_explicit_user_permission"].as_bool(),
        Some(true)
    );
    assert_eq!(
        disk["guidance"]["automatic_cleanup_performed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        disk["guidance"]["deletion_command_recommended"].as_bool(),
        Some(false)
    );
    assert_eq!(
        disk["custom_target_dir_validation_permitted"].as_bool(),
        Some(true)
    );
}

#[test]
fn proof_runner_disk_preflight_classifies_low_root_space() {
    let result = proof_runner_disk_preflight_result(1, 2_097_152);
    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    assert_eq!(result["recommendation"].as_str(), Some("use_supplemental"));
    assert_low_disk_guidance(&result["disk_pressure_preflight"], "low-root-space");
}

#[test]
fn proof_runner_disk_preflight_classifies_low_dev_shm_space() {
    let result = proof_runner_disk_preflight_result(2_097_152, 1);
    assert_eq!(result["preflight_passed"].as_bool(), Some(true));
    assert_eq!(result["recommendation"].as_str(), Some("use_supplemental"));
    assert_low_disk_guidance(&result["disk_pressure_preflight"], "low-dev-shm-space");
}

#[test]
fn proof_runner_rank_fallback_beads_prefers_disk_safe_under_pressure() {
    let fallback = write_json_fixture(&json!({"beads": [
        {"id": "cargo-heavy", "title": "run clippy frontier", "priority": 1,
         "validation_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_clippy cargo clippy -p asupersync --all-targets -- -D warnings"},
        {"id": "docs-safe", "title": "docs-only policy note", "priority": 2,
         "disk_safe": true, "validation_command": "python3 scripts/proof_runner.py --suggest-lanes --touched-files docs/proof_runner_usage.md --output json"},
        {"id": "receipt-safe", "title": "artifact-free receipt fixture", "priority": 1,
         "disk_safety": "disk-safe", "validation_command": "python3 scripts/rch_retrieval_receipt.py --artifact-free-proof-receipt --rch-log fixture.log --output json"}
    ]}));
    let healthy = write_json_fixture(&json!({
        "root": {"path": "/", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64},
        "dev_shm": {"path": "/dev/shm", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64}
    }));
    let low_root = write_json_fixture(&json!({
        "root": {"path": "/", "available": true, "free_bytes": 1_u64, "total_bytes": 4_194_304_u64},
        "dev_shm": {"path": "/dev/shm", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64}
    }));
    let low_shm = write_json_fixture(&json!({
        "root": {"path": "/", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64},
        "dev_shm": {"path": "/dev/shm", "available": true, "free_bytes": 1_u64, "total_bytes": 4_194_304_u64}
    }));
    let fallback_path = fallback.path().to_str().expect("fallback path utf8");
    let run = |disk_path: &str| {
        proof_runner_json(&[
            "--rank-fallback-beads",
            "--fallback-bead-snapshot",
            fallback_path,
            "--disk-preflight-snapshot",
            disk_path,
            "--disk-min-free-bytes",
            "1048576",
            "--disk-dev-shm-min-free-bytes",
            "1048576",
            "--output",
            "json",
        ])
    };

    let healthy_result = run(healthy.path().to_str().expect("healthy path utf8"));
    let healthy_ids: Vec<&str> = healthy_result["ranked_fallback_beads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(healthy_ids, ["cargo-heavy", "docs-safe", "receipt-safe"]);
    assert_eq!(
        healthy_result["summary"]["disk_pressure_active"].as_bool(),
        Some(false)
    );
    assert_eq!(
        healthy_result["summary"]["cargo_heavy_warning_count"].as_i64(),
        Some(0)
    );

    let low_root_result = run(low_root.path().to_str().expect("low root path utf8"));
    let low_ids: Vec<&str> = low_root_result["ranked_fallback_beads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(low_ids, ["docs-safe", "receipt-safe", "cargo-heavy"]);
    assert_eq!(
        low_root_result["disk_pressure_preflight"]["classification"].as_str(),
        Some("low-root-space")
    );
    assert_eq!(
        low_root_result["summary"]["cargo_heavy_warning_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        low_root_result["ranked_fallback_beads"][2]["disk_pressure_warning"].as_str(),
        Some(
            "local disk pressure detected; prefer disk-safe fallback work or an artifact-free proof receipt before Cargo-heavy validation"
        )
    );
    assert_eq!(
        low_root_result["ranked_fallback_beads"][2]["eligible"].as_bool(),
        Some(true)
    );

    let low_shm_result = run(low_shm.path().to_str().expect("low shm path utf8"));
    assert_eq!(
        low_shm_result["disk_pressure_preflight"]["classification"].as_str(),
        Some("low-dev-shm-space")
    );
    assert_eq!(
        low_shm_result["ranked_fallback_beads"][0]["disk_safety"].as_str(),
        Some("disk-safe")
    );
    assert_eq!(
        low_shm_result["ranked_fallback_beads"][2]["disk_safety"].as_str(),
        Some("cargo-heavy")
    );
}

#[test]
fn proof_runner_rank_fallback_beads_demotes_peer_reserved_candidates() {
    let fallback = write_json_fixture(&json!({"beads": [
        {"id": "reserved-safe", "title": "reserved fixture work", "priority": 1,
         "disk_safety": "disk-safe", "touched_files": ["scripts/proof_runner.py"]},
        {"id": "open-safe", "title": "open fixture work", "priority": 1,
         "disk_safety": "disk-safe", "touched_files": ["tests/proof_runner_contract.rs"]},
        {"id": "tracker-hard", "title": "tracker bookkeeping", "priority": 1,
         "disk_safety": "disk-safe", "touched_files": [".beads/issues.jsonl"]}
    ]}));
    let reservations = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "scripts/proof_runner.py",
              "agent_name": "TopazGoose",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            },
            {
              "path_pattern": ".beads/issues.jsonl",
              "agent_name": "TopazGoose",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let fallback_path = fallback.path().to_str().expect("fallback path utf8");
    let reservation_path = reservations.path().to_str().expect("reservation path utf8");
    let result = proof_runner_json(&[
        "--rank-fallback-beads",
        "--fallback-bead-snapshot",
        fallback_path,
        "--reservation-snapshot",
        reservation_path,
        "--agent-name",
        "FrostyAspen",
        "--output",
        "json",
    ]);

    let ids: Vec<&str> = result["ranked_fallback_beads"]
        .as_array()
        .expect("ranked fallback beads")
        .iter()
        .map(|row| row["id"].as_str().expect("bead id"))
        .collect();
    assert_eq!(ids, ["open-safe", "reserved-safe", "tracker-hard"]);
    assert_eq!(
        result["summary"]["reservation_demotion_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        result["summary"]["reservation_hard_block_count"].as_i64(),
        Some(1)
    );

    let reserved = &result["ranked_fallback_beads"][1];
    assert_eq!(reserved["id"].as_str(), Some("reserved-safe"));
    assert_eq!(reserved["eligible"].as_bool(), Some(true));
    assert_eq!(reserved["reservation_demoted"].as_bool(), Some(true));
    assert_eq!(
        reserved["reservation_overlaps"][0]["classification"].as_str(),
        Some("peer-active")
    );
    assert_eq!(
        reserved["reservation_overlaps"][0]["holder"].as_str(),
        Some("TopazGoose")
    );
    assert_eq!(
        reserved["reservation_overlaps"][0]["path"].as_str(),
        Some("scripts/proof_runner.py")
    );

    let tracker = &result["ranked_fallback_beads"][2];
    assert_eq!(tracker["id"].as_str(), Some("tracker-hard"));
    assert_eq!(tracker["eligible"].as_bool(), Some(false));
    assert_eq!(tracker["reservation_hard_blocked"].as_bool(), Some(true));
    assert_eq!(
        tracker["reservation_blocker"]["classification"].as_str(),
        Some("tracker-only")
    );
}

#[test]
fn proof_runner_rank_fallback_beads_reports_fileless_reservation_snapshot() {
    let fallback = write_json_fixture(&json!({"beads": [
        {"id": "fileless-safe", "title": "fileless fixture work", "priority": 1,
         "disk_safety": "disk-safe"}
    ]}));
    let reservations = write_reservation_snapshot(
        r#"{
          "reservations": [
            {
              "path_pattern": "scripts/proof_runner.py",
              "agent_name": "TopazGoose",
              "expires_ts": "2999-01-01T00:00:00Z",
              "exclusive": true
            }
          ]
        }"#,
    );
    let fallback_path = fallback.path().to_str().expect("fallback path utf8");
    let reservation_path = reservations.path().to_str().expect("reservation path utf8");
    let result = proof_runner_json(&[
        "--rank-fallback-beads",
        "--fallback-bead-snapshot",
        fallback_path,
        "--reservation-snapshot",
        reservation_path,
        "--agent-name",
        "FrostyAspen",
        "--output",
        "json",
    ]);

    assert_eq!(
        result["reservation_snapshot"]["enabled"].as_bool(),
        Some(true)
    );
    assert_eq!(
        result["reservation_snapshot"]["source"].as_str(),
        Some("snapshot")
    );
    assert_eq!(
        result["summary"]["reservation_demotion_count"].as_i64(),
        Some(0)
    );
    assert_eq!(
        result["summary"]["reservation_hard_block_count"].as_i64(),
        Some(0)
    );

    let ranked = &result["ranked_fallback_beads"][0];
    assert_eq!(ranked["id"].as_str(), Some("fileless-safe"));
    assert_eq!(ranked["eligible"].as_bool(), Some(true));
    assert_eq!(ranked["touched_files"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        ranked["reservation_overlaps"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn proof_runner_rank_fallback_beads_blocks_bare_cargo_validation() {
    let fallback = write_json_fixture(&json!({"beads": [
        {"id": "bare-cargo", "title": "bare cargo validation", "priority": 1,
         "validation_command": "cargo test -p asupersync --test proof_runner_contract"},
        {"id": "bare-rch-cargo", "title": "bare rch cargo validation", "priority": 1,
         "validation_command": "rch exec -- cargo test -p asupersync --test proof_runner_contract"},
        {"id": "missing-remote-required", "title": "rch cargo validation without remote-required guard", "priority": 1,
         "validation_command": "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner cargo test -p asupersync --test proof_runner_contract"},
        {"id": "shell-control-rch-cargo", "title": "rch cargo validation with shell control", "priority": 1,
         "validation_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner cargo test -p asupersync --test proof_runner_contract; touch /tmp/asupersync-proof-runner-pwn"},
        {"id": "forbidden-delete", "title": "destructive validation command", "priority": 1,
         "validation_command": "rm -rf /tmp/asupersync-proof-runner-pwn"},
        {"id": "rch-cargo", "title": "rch cargo validation", "priority": 1,
         "validation_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner cargo test -p asupersync --test proof_runner_contract"}
    ]}));
    let fallback_path = fallback.path().to_str().expect("fallback path utf8");

    let result = proof_runner_json(&[
        "--rank-fallback-beads",
        "--fallback-bead-snapshot",
        fallback_path,
        "--output",
        "json",
    ]);

    let ids: Vec<&str> = result["ranked_fallback_beads"]
        .as_array()
        .expect("ranked fallback beads")
        .iter()
        .map(|row| row["id"].as_str().expect("bead id"))
        .collect();
    assert_eq!(
        ids,
        [
            "rch-cargo",
            "bare-cargo",
            "bare-rch-cargo",
            "missing-remote-required",
            "shell-control-rch-cargo",
            "forbidden-delete"
        ]
    );
    assert_eq!(
        result["summary"]["unsafe_validation_block_count"].as_i64(),
        Some(5)
    );

    let safe = &result["ranked_fallback_beads"][0];
    assert_eq!(safe["id"].as_str(), Some("rch-cargo"));
    assert_eq!(safe["eligible"].as_bool(), Some(true));
    assert_eq!(safe["unsafe_validation_blocked"].as_bool(), Some(false));

    let blocked = &result["ranked_fallback_beads"][1];
    assert_eq!(blocked["id"].as_str(), Some("bare-cargo"));
    assert_eq!(blocked["eligible"].as_bool(), Some(false));
    assert_eq!(blocked["unsafe_validation_blocked"].as_bool(), Some(true));
    assert_eq!(
        blocked["unsafe_validation_commands"][0].as_str(),
        Some("cargo test -p asupersync --test proof_runner_contract")
    );
    assert_eq!(
        blocked["validation_command_policy"].as_str(),
        Some(
            "cargo validation must route through RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo; validation commands must not contain shell control or irreversible git/filesystem operations"
        )
    );

    let blocked = &result["ranked_fallback_beads"][2];
    assert_eq!(blocked["id"].as_str(), Some("bare-rch-cargo"));
    assert_eq!(blocked["eligible"].as_bool(), Some(false));
    assert_eq!(blocked["unsafe_validation_blocked"].as_bool(), Some(true));
    assert_eq!(
        blocked["unsafe_validation_commands"][0].as_str(),
        Some("rch exec -- cargo test -p asupersync --test proof_runner_contract")
    );

    let blocked = &result["ranked_fallback_beads"][3];
    assert_eq!(blocked["id"].as_str(), Some("missing-remote-required"));
    assert_eq!(blocked["eligible"].as_bool(), Some(false));
    assert_eq!(blocked["unsafe_validation_blocked"].as_bool(), Some(true));
    assert_eq!(
        blocked["unsafe_validation_commands"][0].as_str(),
        Some(
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner cargo test -p asupersync --test proof_runner_contract"
        )
    );

    let blocked = &result["ranked_fallback_beads"][4];
    assert_eq!(blocked["id"].as_str(), Some("shell-control-rch-cargo"));
    assert_eq!(blocked["eligible"].as_bool(), Some(false));
    assert_eq!(blocked["unsafe_validation_blocked"].as_bool(), Some(true));
    assert_eq!(
        blocked["unsafe_validation_commands"][0].as_str(),
        Some(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner cargo test -p asupersync --test proof_runner_contract; touch /tmp/asupersync-proof-runner-pwn"
        )
    );
    assert!(
        blocked["unsafe_validation_reasons"][0]["reasons"]
            .as_array()
            .expect("shell-control reasons array")
            .contains(&Value::String("shell-control-metacharacters".to_string()))
    );

    let blocked = &result["ranked_fallback_beads"][5];
    assert_eq!(blocked["id"].as_str(), Some("forbidden-delete"));
    assert_eq!(blocked["eligible"].as_bool(), Some(false));
    assert_eq!(blocked["unsafe_validation_blocked"].as_bool(), Some(true));
    assert_eq!(
        blocked["unsafe_validation_commands"][0].as_str(),
        Some("rm -rf /tmp/asupersync-proof-runner-pwn")
    );
    assert!(
        blocked["unsafe_validation_reasons"][0]["reasons"]
            .as_array()
            .expect("destructive reasons array")
            .contains(&Value::String("forbidden-file-deletion".to_string()))
    );

    let plan = proof_runner_json(&[
        "--autopilot-proof-plan",
        "--fallback-bead-snapshot",
        fallback_path,
        "--touched-files",
        "scripts/proof_runner.py",
        "--output",
        "json",
    ]);
    assert_eq!(
        plan["selected_fallback_bead"]["id"].as_str(),
        Some("rch-cargo")
    );
    assert_eq!(
        plan["selected_fallback_bead"]["eligible"].as_bool(),
        Some(true)
    );
}

#[test]
fn proof_runner_autopilot_plan_combines_lanes_disk_and_fallbacks() {
    let fallback = write_json_fixture(&json!({"beads": [
        {"id": "cargo-heavy", "title": "run clippy frontier", "priority": 1,
         "validation_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_clippy cargo clippy -p asupersync --all-targets -- -D warnings"},
        {"id": "docs-safe", "title": "docs-only policy note", "priority": 2,
         "disk_safe": true, "validation_command": "python3 scripts/proof_runner.py --suggest-lanes --touched-files docs/proof_runner_usage.md --output json"},
        {"id": "receipt-safe", "title": "artifact-free receipt fixture", "priority": 1,
         "disk_safety": "disk-safe", "validation_command": "python3 scripts/rch_retrieval_receipt.py --artifact-free-proof-receipt --rch-log fixture.log --output json"}
    ]}));
    let healthy = write_json_fixture(&json!({
        "root": {"path": "/", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64},
        "dev_shm": {"path": "/dev/shm", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64}
    }));
    let low_shm = write_json_fixture(&json!({
        "root": {"path": "/", "available": true, "free_bytes": 2_097_152_u64, "total_bytes": 4_194_304_u64},
        "dev_shm": {"path": "/dev/shm", "available": true, "free_bytes": 1_u64, "total_bytes": 4_194_304_u64}
    }));
    let fallback_path = fallback.path().to_str().expect("fallback path utf8");
    let run = |disk_path: &str| {
        proof_runner_json(&[
            "--autopilot-proof-plan",
            "--fallback-bead-snapshot",
            fallback_path,
            "--disk-preflight-snapshot",
            disk_path,
            "--disk-min-free-bytes",
            "1048576",
            "--disk-dev-shm-min-free-bytes",
            "1048576",
            "--touched-files",
            "src/lib.rs",
            "docs/proof_runner_usage.md",
            "--output",
            "json",
        ])
    };

    let healthy_result = run(healthy.path().to_str().expect("healthy path utf8"));
    assert_eq!(
        healthy_result["schema_version"].as_str(),
        Some("proof-runner-autopilot-plan-v1")
    );
    assert_eq!(healthy_result["mode"].as_str(), Some("dry-run"));
    assert_eq!(
        healthy_result["selected_fallback_bead"]["id"].as_str(),
        Some("cargo-heavy")
    );
    assert_eq!(
        healthy_result["disk_pressure_preflight"]["classification"].as_str(),
        Some("healthy")
    );
    assert_eq!(
        healthy_result["no_mutation"]["executes_proof_commands"].as_bool(),
        Some(false)
    );
    assert_eq!(
        healthy_result["no_mutation"]["mutates_beads"].as_bool(),
        Some(false)
    );
    assert_eq!(
        healthy_result["no_mutation"]["mutates_agent_mail"].as_bool(),
        Some(false)
    );
    assert_eq!(
        healthy_result["no_mutation"]["deletes_files"].as_bool(),
        Some(false)
    );
    let suggested_lanes: BTreeSet<String> = healthy_result["suggested_lanes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|lane| lane.as_str().unwrap().to_string())
        .collect();
    assert!(suggested_lanes.contains("rustfmt-check"));
    assert!(suggested_lanes.contains("all-targets-check"));
    assert!(suggested_lanes.contains("clippy-all-targets"));
    assert!(suggested_lanes.contains("lib-tests"));
    assert!(suggested_lanes.contains("rustdoc-api"));

    let low_shm_result = run(low_shm.path().to_str().expect("low shm path utf8"));
    assert_eq!(
        low_shm_result["disk_pressure_preflight"]["classification"].as_str(),
        Some("low-dev-shm-space")
    );
    assert_eq!(
        low_shm_result["selected_fallback_bead"]["id"].as_str(),
        Some("docs-safe")
    );
    assert_eq!(
        low_shm_result["fallback_ranking"]["summary"]["cargo_heavy_warning_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        low_shm_result["fallback_ranking"]["ranked_fallback_beads"][2]["disk_pressure_warning"]
            .as_str(),
        Some(
            "local disk pressure detected; prefer disk-safe fallback work or an artifact-free proof receipt before Cargo-heavy validation"
        )
    );
    assert_eq!(
        low_shm_result["no_mutation"]["requires_explicit_cleanup_permission"].as_bool(),
        Some(true)
    );
}

#[test]
fn proof_runner_preserves_git_status_columns_for_unstaged_dirty_paths() {
    let snippet = r#"
import importlib.util
import json

spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Completed:
    stdout = " M scripts/proof_runner.py\nA  tests/proof_runner_contract.rs\n?? tests/fixtures/proof_runner/new.log\n M tests/fixtures/proof_runner/trailing-space.log \nR  src/runtime/old_state.rs -> src/runtime/state.rs\nC  docs/old.md -> docs/new.md\n"

module.subprocess.run = lambda *args, **kwargs: Completed()
status = module.GitStatus(".")
print(json.dumps({
    "status_lines": status._get_status(),
    "uncommitted": status.get_uncommitted_files(),
    "staged": status.get_staged_files(),
}, sort_keys=True))
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "status parser snippet should execute\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("status parser output should be JSON");

    assert_eq!(
        parsed["status_lines"][0].as_str(),
        Some(" M scripts/proof_runner.py"),
        "leading porcelain status column must be preserved for unstaged paths"
    );
    assert_eq!(
        parsed["uncommitted"][0].as_str(),
        Some("scripts/proof_runner.py")
    );
    assert_eq!(
        parsed["staged"][0].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert_eq!(
        parsed["uncommitted"][2].as_str(),
        Some("tests/fixtures/proof_runner/new.log")
    );
    assert_eq!(
        parsed["status_lines"][3].as_str(),
        Some(" M tests/fixtures/proof_runner/trailing-space.log "),
        "trailing path whitespace must not be stripped from status lines"
    );
    assert_eq!(
        parsed["uncommitted"][3].as_str(),
        Some("tests/fixtures/proof_runner/trailing-space.log ")
    );
    assert_eq!(
        parsed["uncommitted"][4].as_str(),
        Some("src/runtime/old_state.rs")
    );
    assert_eq!(
        parsed["uncommitted"][5].as_str(),
        Some("src/runtime/state.rs")
    );
    assert_eq!(
        parsed["staged"][1].as_str(),
        Some("src/runtime/old_state.rs")
    );
    assert_eq!(parsed["staged"][2].as_str(), Some("src/runtime/state.rs"));
    assert_eq!(parsed["staged"][3].as_str(), Some("docs/old.md"));
    assert_eq!(parsed["staged"][4].as_str(), Some("docs/new.md"));
}

#[test]
fn proof_runner_dirty_check_normalizes_touched_file_paths() {
    let snippet = r#"
import importlib.util
import json

spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

runner = module.ProofRunner(skip_build_slot_check=True)
runner.git._status_lines = [
    " M scripts/proof_runner.py",
    "A  tests/proof_runner_contract.rs",
]
can_proceed, record = runner.analyze_preflight(
    "rustfmt-check",
    ["./scripts/proof_runner.py", "tests/proof_runner_contract.rs/"],
)
print(json.dumps({
    "can_proceed": can_proceed,
    "decision": record["decision"],
    "dirty_tree_summary": record["dirty_tree_summary"],
    "summary": record["summary"],
    "uncommitted": runner.git.get_uncommitted_files(),
    "staged": runner.git.get_staged_files(),
}, sort_keys=True))
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "dirty path normalization snippet should execute\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("normalization output should be JSON");

    assert_eq!(parsed["can_proceed"].as_bool(), Some(true));
    assert_eq!(parsed["decision"].as_str(), Some("pass"));
    assert_eq!(
        parsed["uncommitted"][0].as_str(),
        Some("scripts/proof_runner.py")
    );
    assert_eq!(
        parsed["staged"][0].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert_eq!(
        parsed["dirty_tree_summary"]["overlaps_touched_files"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["dirty_tree_summary"]["touched_dirty_files"][0].as_str(),
        Some("scripts/proof_runner.py")
    );
}

#[test]
fn proof_runner_emits_validation_frontier_compatible_records() {
    // Test with a known lane to get a proper record structure
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    let record = &result["validation_frontier_record"];

    // Verify required fields from the schema exist
    assert!(record["command"].is_string(), "record must have command");
    assert!(
        record["proof_lane_id"].is_string(),
        "record must have proof_lane_id"
    );
    assert!(record["commit"].is_string(), "record must have commit");
    assert!(
        record["timestamp"].is_string(),
        "record must have timestamp"
    );
    assert!(
        record["touched_files"].is_array(),
        "record must have touched_files array"
    );
    assert!(
        record["dirty_tree_summary"].is_object(),
        "record must have dirty_tree_summary object"
    );
    assert!(
        record["rch_result"].is_object(),
        "record must have rch_result object"
    );
    assert!(
        record["exit_status"].is_number(),
        "record must have exit_status"
    );
    assert!(record["decision"].is_string(), "record must have decision");
    assert!(
        record["error_class"].is_string(),
        "record must have error_class"
    );
    assert!(
        record["first_blocker"].is_object() || record["first_blocker"].is_null(),
        "record must have nullable first_blocker"
    );

    let first_failure = &record["first_failure"];
    assert!(first_failure["crate_or_surface"].is_string());
    assert!(first_failure["target"].is_string());
    assert!(first_failure["file"].is_string());
    assert!(first_failure["line"].is_number());

    assert!(
        record["error_buckets"].is_array(),
        "record must have error_buckets"
    );
    assert!(
        record["affected_files"].is_array(),
        "record must have affected_files"
    );
    assert!(
        record["likely_owner"].is_string(),
        "record must have likely_owner"
    );
    assert!(
        record["blocker_origin"].is_object(),
        "record must have blocker_origin"
    );
    assert!(
        record["external_to_narrow_fuzz_target_work"].is_boolean(),
        "record must have external_to_narrow_fuzz_target_work"
    );
    assert!(
        record["green_proof_claimed"].is_boolean(),
        "record must have green_proof_claimed"
    );
    assert!(record["supplemental_proof_command"].is_string());
    assert!(record["summary"].is_string(), "record must have summary");

    // Decision should be valid
    let decision = record["decision"]
        .as_str()
        .expect("decision should be string");
    assert!(
        matches!(decision, "pass" | "blocked-external" | "failed-local"),
        "decision should be a valid frontier decision: {decision}"
    );
}

#[test]
fn proof_runner_generates_appropriate_supplemental_proofs() {
    // Test supplemental proof for formatting
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/runtime/state.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    let supplemental = result["validation_frontier_record"]["supplemental_proof_command"]
        .as_str()
        .expect("should have supplemental proof command");

    // Should generate a narrow rustfmt command
    assert!(
        supplemental.contains("rustfmt") && supplemental.contains("src/runtime/state.rs"),
        "supplemental proof should focus on touched file: {supplemental}"
    );

    // Test supplemental proof for compilation
    let result = proof_runner_json(&[
        "--lane",
        "all-targets-check",
        "--touched-files",
        "src/sync/mutex.rs",
        "src/sync/pool.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    let supplemental = result["validation_frontier_record"]["supplemental_proof_command"]
        .as_str()
        .expect("should have supplemental proof command");

    // Should suggest a narrower compilation check
    assert!(
        supplemental.contains("cargo check") || supplemental.contains("rustfmt"),
        "supplemental proof should be narrower than all-targets: {supplemental}"
    );
    assert!(
        !supplemental.contains("rch exec -- cargo"),
        "supplemental Cargo proof must not use bare rch cargo routing: {supplemental}"
    );
    if supplemental.contains("cargo ") {
        assert!(
            supplemental.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env ")
                && supplemental.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/"),
            "supplemental Cargo proof must require remote rch and preserve a target dir: {supplemental}"
        );
        assert!(
            !supplemental.contains("rch exec -- cargo"),
            "supplemental Cargo proof must not use bare rch cargo routing: {supplemental}"
        );
    }

    let result = proof_runner_json(&[
        "--lane",
        "lib-tests",
        "--touched-files",
        "tests/proof_runner_contract.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);
    let supplemental = result["validation_frontier_record"]["supplemental_proof_command"]
        .as_str()
        .expect("should have supplemental proof command");
    assert!(
        supplemental.contains("cargo test")
            && supplemental.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env ")
            && supplemental.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/"),
        "test supplemental proof must require remote rch and preserve a target dir: {supplemental}"
    );
    assert!(
        !supplemental.contains("rch exec -- cargo"),
        "test supplemental proof must not use bare rch cargo routing: {supplemental}"
    );
}

#[test]
fn proof_runner_uses_manifest_commands_correctly() {
    let manifest = load_json(MANIFEST_PATH);
    let lanes = manifest["lanes"]
        .as_array()
        .expect("manifest should have lanes");

    // Pick a few representative lanes to test
    for lane in lanes.iter().take(3) {
        let lane_id = lane["lane_id"].as_str().expect("lane should have id");
        let expected_command = lane["command"].as_str().expect("lane should have command");

        let result = proof_runner_json(&[
            "--lane",
            lane_id,
            "--touched-files",
            "src/lib.rs",
            "--skip-dirty-check",
            "--output",
            "json",
        ]);

        let actual_command = result["command_would_run"]
            .as_str()
            .expect("result should include command_would_run");

        assert_eq!(
            actual_command, expected_command,
            "proof runner should use manifest command for lane {lane_id}"
        );
    }
}

#[test]
fn proof_runner_execute_path_does_not_use_shell_true() {
    let script = std::fs::read_to_string(SCRIPT_PATH).expect("read proof runner script");
    assert!(
        !script.contains("shell=True"),
        "execute mode must not route manifest commands through a shell"
    );
    assert!(
        script.contains("safe_command_argv"),
        "execute mode must validate manifest commands before running them"
    );
}

#[test]
fn proof_runner_rejects_shell_control_metacharacters() {
    let snippet = r#"
import importlib.util
spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.safe_command_argv("rch exec -- cargo test; touch /tmp/asupersync-proof-runner-pwn")
except ValueError as error:
    print(str(error))
else:
    raise SystemExit("accepted shell metacharacter")
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "malicious command should be rejected cleanly\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("shell control metacharacters"),
        "rejection reason should identify shell metacharacters: {stdout}"
    );
}

#[test]
fn proof_runner_parses_manifest_env_command_without_shell_expansion() {
    let snippet = r#"
import importlib.util
import json
spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
argv = module.safe_command_argv("rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test CARGO_INCREMENTAL=0 RUSTFLAGS='-C debuginfo=0' cargo check -p asupersync")
print(json.dumps(argv))
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "valid manifest env command should parse\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let argv: Vec<String> =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("parse argv JSON: {error}"));
    assert_eq!(&argv[..3], &["rch", "exec", "--"]);
    assert_eq!(argv[3], "env");
    assert!(
        argv.iter()
            .any(|token| token == "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test"),
        "TMPDIR fallback should be preserved for rch worker-side handling: {argv:?}"
    );
    assert!(
        argv.iter()
            .all(|token| !token.starts_with("CARGO_TARGET_DIR=/tmp/")),
        "TMPDIR fallback should not be expanded on the local client: {argv:?}"
    );
    assert!(
        argv.iter().any(|token| token == "cargo"),
        "remote cargo program should be preserved: {argv:?}"
    );
}

#[test]
fn proof_runner_parses_remote_required_prefix_without_shell_expansion() {
    let snippet = r#"
import importlib.util
import json
spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
argv = module.safe_command_argv("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test cargo check -p asupersync")
print(json.dumps(argv))
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "remote-required command should parse\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let argv: Vec<String> =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("parse argv JSON: {error}"));
    assert_eq!(argv[0], "env");
    assert_eq!(argv[1], "RCH_REQUIRE_REMOTE=1");
    let rch_index = argv
        .iter()
        .position(|token| token == "rch")
        .expect("rch program should be preserved");
    assert_eq!(&argv[rch_index..rch_index + 3], &["rch", "exec", "--"]);
    assert!(
        argv.iter()
            .any(|token| token == "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test"),
        "TMPDIR fallback should be preserved for rch worker-side handling: {argv:?}"
    );
}

#[test]
fn proof_runner_rch_outcome_contract_names_required_fixtures() {
    let contract = load_json(RCH_OUTCOME_CONTRACT_PATH);
    assert_eq!(
        contract["generated_artifact_schema"].as_str(),
        Some("proof-runner-rch-outcome-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-xeh8m0.2"));

    let fixtures = contract["fixtures"].as_array().expect("fixtures array");
    let fixture_names: BTreeSet<&str> = fixtures
        .iter()
        .map(|fixture| fixture["path"].as_str().expect("fixture path"))
        .collect();
    for required in [
        "tests/fixtures/proof_runner/rch_pass.log",
        "tests/fixtures/proof_runner/normal_artifact_retrieval.log",
        "tests/fixtures/proof_runner/cargo_error.log",
        "tests/fixtures/proof_runner/wrapper_hang_after_remote_exit.log",
        "tests/fixtures/proof_runner/external_blocker.log",
        "tests/fixtures/proof_runner/rch_control_plane_inconsistent_enable_not_found.log",
        "tests/fixtures/proof_runner/rustc_json_error.log",
        "tests/fixtures/proof_runner/rustfmt_diff.log",
        "tests/fixtures/proof_runner/clippy_lint.log",
        "tests/fixtures/proof_runner/truncated_rustc_output.log",
        "tests/fixtures/proof_runner/rch_remote_required_refusal.log",
    ] {
        assert!(
            fixture_names.contains(required),
            "missing fixture {required}"
        );
    }

    let required_output_fields: BTreeSet<&str> = contract["required_output_fields"]
        .as_array()
        .expect("required output fields")
        .iter()
        .map(|field| field.as_str().expect("field string"))
        .collect();
    for required in [
        "schema_version",
        "rch_outcome",
        "validation_frontier_record",
        "closeout_summary",
    ] {
        assert!(
            required_output_fields.contains(required),
            "missing required output field {required}"
        );
    }

    let required_outcome_fields: BTreeSet<&str> = contract["required_rch_outcome_fields"]
        .as_array()
        .expect("required outcome fields")
        .iter()
        .map(|field| field.as_str().expect("field string"))
        .collect();
    for required in [
        "command",
        "command_scope",
        "remote_exit_status",
        "outcome_class",
        "diagnostic_class",
        "decision",
        "first_blocker",
        "control_plane",
    ] {
        assert!(
            required_outcome_fields.contains(required),
            "missing required outcome field {required}"
        );
    }

    assert_eq!(
        contract["closeout_summary_schema"].as_str(),
        Some("proof-runner-closeout-summary-v1")
    );
    let required_closeout_fields: BTreeSet<&str> = contract["required_closeout_summary_fields"]
        .as_array()
        .expect("required closeout summary fields")
        .iter()
        .map(|field| field.as_str().expect("field string"))
        .collect();
    for required in [
        "schema_version",
        "bead_id",
        "likely_owner",
        "proof_claim",
        "green_proof_claimed",
        "blocker_origin",
        "first_blocker",
        "beads_comment",
        "agent_mail_body",
    ] {
        assert!(
            required_closeout_fields.contains(required),
            "missing required closeout field {required}"
        );
    }

    let proof_command = contract["proof_command"]
        .as_str()
        .expect("proof command string");
    assert!(
        proof_command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must force remote rch execution: {proof_command}"
    );
    assert!(
        proof_command.contains("CARGO_TARGET_DIR="),
        "proof command must use an explicit remote target directory: {proof_command}"
    );
    assert!(
        proof_command.contains(" cargo test -p asupersync --test proof_runner_contract "),
        "proof command must prove this contract test binary: {proof_command}"
    );
    assert!(
        !proof_command.contains("rch exec -- cargo"),
        "proof command must route Cargo through rch env setup: {proof_command}"
    );
}

#[test]
fn proof_runner_classifies_rch_pass_log_with_command_scope() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_console CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_console_report_contract -- --nocapture";
    let result = classify_fixture(
        "rch_pass.log",
        command,
        &["tests/proof_console_report_contract.rs"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("pass"));
    assert_eq!(outcome["decision"].as_str(), Some("pass"));
    assert_eq!(outcome["remote_exit_status"].as_i64(), Some(0));
    assert_eq!(
        outcome["command_scope"]["package"].as_str(),
        Some("asupersync")
    );
    assert_eq!(
        outcome["command_scope"]["target_kind"].as_str(),
        Some("test")
    );
    assert_eq!(
        outcome["command_scope"]["target"].as_str(),
        Some("proof_console_report_contract")
    );
    assert_eq!(
        result["validation_frontier_record"]["decision"].as_str(),
        Some("pass")
    );
    let frontier = &result["validation_frontier_record"];
    assert_eq!(frontier["proof_lane_id"].as_str(), Some("lib-tests"));
    assert_eq!(
        frontier["rch_result"]["admission"].as_str(),
        Some("remote-executed")
    );
    assert_eq!(frontier["exit_status"].as_i64(), Some(0));
    assert!(frontier["first_blocker"].is_null());
    assert_eq!(frontier["error_class"].as_str(), Some("none"));
    assert_eq!(frontier["green_proof_claimed"].as_bool(), Some(true));
}

#[test]
fn proof_runner_treats_normal_artifact_retrieval_as_pass() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let result = classify_fixture(
        "normal_artifact_retrieval.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("pass"));
    assert_eq!(outcome["decision"].as_str(), Some("pass"));
    assert_eq!(outcome["remote_exit_status"].as_i64(), Some(0));
    assert!(
        outcome["summary"]
            .as_str()
            .expect("summary")
            .contains("passed")
    );
    assert_eq!(
        outcome["source_log_path"].as_str(),
        Some("tests/fixtures/proof_runner/normal_artifact_retrieval.log")
    );
    assert!(
        outcome["source_log_sha256"]
            .as_str()
            .expect("source log hash")
            .starts_with("sha256:")
    );
    assert!(
        outcome["source_log_bytes"]
            .as_u64()
            .expect("source log bytes")
            > 0
    );
}

#[test]
fn proof_runner_classifies_local_cargo_error_blocker() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let result = classify_fixture(
        "cargo_error.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("failed_local"));
    assert_eq!(outcome["decision"].as_str(), Some("failed-local"));
    assert_eq!(outcome["remote_exit_status"].as_i64(), Some(101));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(918));
    assert_eq!(
        result["validation_frontier_record"]["decision"].as_str(),
        Some("failed-local")
    );
    let frontier = &result["validation_frontier_record"];
    assert_eq!(frontier["exit_status"].as_i64(), Some(101));
    assert_eq!(
        frontier["rch_result"]["admission"].as_str(),
        Some("remote-executed")
    );
    assert_eq!(
        frontier["first_blocker"]["file"].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert_eq!(
        frontier["error_buckets"][0]["error_code"].as_str(),
        Some("E0425")
    );
    assert_eq!(
        frontier["affected_files"][0].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert_eq!(frontier["green_proof_claimed"].as_bool(), Some(false));
}

#[test]
fn proof_runner_classify_rch_log_emits_bead_owner_closeout_summary() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let result = classify_fixture_with_extra_args(
        "cargo_error.log",
        command,
        &["tests/proof_runner_contract.rs"],
        &[
            "--bead-id",
            "asupersync-oxqrae.1",
            "--likely-owner",
            "DustyGorge",
        ],
    );
    let frontier = &result["validation_frontier_record"];
    let closeout = &result["closeout_summary"];

    assert_eq!(
        frontier["likely_bead"].as_str(),
        Some("asupersync-oxqrae.1")
    );
    assert_eq!(frontier["likely_owner"].as_str(), Some("DustyGorge"));
    assert_eq!(
        frontier["error_buckets"][0]["likely_bead"].as_str(),
        Some("asupersync-oxqrae.1")
    );
    assert_eq!(
        frontier["error_buckets"][0]["likely_owner"].as_str(),
        Some("DustyGorge")
    );
    assert_eq!(
        closeout["schema_version"].as_str(),
        Some("proof-runner-closeout-summary-v1")
    );
    assert_eq!(closeout["bead_id"].as_str(), Some("asupersync-oxqrae.1"));
    assert_eq!(closeout["likely_owner"].as_str(), Some("DustyGorge"));
    assert_eq!(closeout["proof_claim"].as_str(), Some("no-green-proof"));
    assert_eq!(closeout["green_proof_claimed"].as_bool(), Some(false));
    assert_eq!(
        closeout["first_blocker"]["file"].as_str(),
        Some("tests/proof_runner_contract.rs")
    );
    assert!(
        closeout["beads_comment"]
            .as_str()
            .expect("beads closeout comment")
            .contains("NO_GREEN_PROOF bead=asupersync-oxqrae.1")
    );
    assert!(
        closeout["agent_mail_body"]
            .as_str()
            .expect("agent mail body")
            .contains("green_proof_claimed=false")
    );
}

#[test]
fn proof_runner_infers_blocker_origin_from_recent_git_commit_metadata() {
    let snippet = r#"
import importlib.util
import json

spec = importlib.util.spec_from_file_location("proof_runner", "scripts/proof_runner.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture"
git_line = "0123456789abcdef0123456789abcdef01234567\x1fNavyWillow\x1fnavy@example.invalid\x1fFix blocker br-asupersync-nod48i"
scanned_origin = module.blocker_origin_from_git_log_lines("tests/proof_runner_contract.rs", [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1fLatestAuthor\x1flatest@example.invalid\x1fRecent cleanup without tracker id",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x1fOlderAuthor\x1folder@example.invalid\x1fWire proof br-asupersync-older7",
])

runner = module.ProofRunner(skip_build_slot_check=True)
runner.git._status_lines = []
runner.git.head_commit = lambda: "abc123def456"
runner.git.recent_commit_hint_for_path = lambda path: module.blocker_origin_from_git_log_line(path, git_line)
result = runner.classify_rch_log(
    command,
    "tests/fixtures/proof_runner/cargo_error.log",
    ["tests/proof_runner_contract.rs"],
)
print(json.dumps({
    "bead_from_text": module.bead_id_from_text("close br-asupersync-oxqrae.1 after proof"),
    "frontier_bead": result["validation_frontier_record"]["likely_bead"],
    "frontier_origin": result["validation_frontier_record"]["blocker_origin"],
    "bucket_origin": result["validation_frontier_record"]["error_buckets"][0]["blocker_origin"],
    "closeout_origin": result["closeout_summary"]["blocker_origin"],
    "beads_comment": result["closeout_summary"]["beads_comment"],
    "scanned_origin": scanned_origin,
}, sort_keys=True))
"#;
    let output = run_python_snippet(snippet);
    assert!(
        output.status.success(),
        "blocker origin snippet should execute\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("blocker origin output should be JSON");

    assert_eq!(
        parsed["bead_from_text"].as_str(),
        Some("asupersync-oxqrae.1")
    );
    assert_eq!(parsed["frontier_bead"].as_str(), Some("asupersync-nod48i"));
    assert_eq!(
        parsed["frontier_origin"]["commit"].as_str(),
        Some("0123456789ab")
    );
    assert_eq!(
        parsed["frontier_origin"]["bead_id"].as_str(),
        Some("asupersync-nod48i")
    );
    assert_eq!(
        parsed["frontier_origin"]["bead_commit"].as_str(),
        Some("0123456789ab")
    );
    assert_eq!(
        parsed["frontier_origin"]["author"].as_str(),
        Some("NavyWillow")
    );
    assert_eq!(
        parsed["bucket_origin"]["subject"].as_str(),
        Some("Fix blocker br-asupersync-nod48i")
    );
    assert_eq!(
        parsed["closeout_origin"]["author_email"].as_str(),
        Some("navy@example.invalid")
    );
    assert!(
        parsed["beads_comment"]
            .as_str()
            .expect("beads comment")
            .contains("origin_commit=0123456789ab")
    );
    assert_eq!(
        parsed["scanned_origin"]["commit"].as_str(),
        Some("aaaaaaaaaaaa")
    );
    assert_eq!(
        parsed["scanned_origin"]["bead_id"].as_str(),
        Some("asupersync-older7")
    );
    assert_eq!(
        parsed["scanned_origin"]["bead_commit"].as_str(),
        Some("bbbbbbbbbbbb")
    );
}

#[test]
fn proof_runner_classifies_rustc_json_error_fixture() {
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_validation_frontier cargo test -p asupersync --test validation_frontier_ledger_contract --message-format=json";
    let result = classify_fixture(
        "rustc_json_error.log",
        command,
        &["tests/validation_frontier_ledger_contract.rs"],
    );
    let outcome = &result["rch_outcome"];
    let frontier = &result["validation_frontier_record"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("failed_local"));
    assert_eq!(
        outcome["diagnostic_class"].as_str(),
        Some("rustc_compile_error")
    );
    assert_eq!(outcome["decision"].as_str(), Some("failed-local"));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("tests/validation_frontier_ledger_contract.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(18));
    assert_eq!(outcome["first_blocker"]["code"].as_str(), Some("E0063"));
    assert_eq!(
        frontier["error_class"].as_str(),
        Some("rustc_compile_error")
    );
    assert_eq!(
        frontier["error_buckets"][0]["error_code"].as_str(),
        Some("E0063")
    );
    assert_eq!(
        frontier["affected_files"][0].as_str(),
        Some("tests/validation_frontier_ledger_contract.rs")
    );
}

#[test]
fn proof_runner_classifies_rustfmt_diff_fixture() {
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_fmt cargo fmt --check";
    let result = classify_fixture(
        "rustfmt_diff.log",
        command,
        &["tests/validation_frontier_ledger_contract.rs"],
    );
    let outcome = &result["rch_outcome"];
    let frontier = &result["validation_frontier_record"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("failed_local"));
    assert_eq!(outcome["diagnostic_class"].as_str(), Some("rustfmt_diff"));
    assert_eq!(outcome["decision"].as_str(), Some("failed-local"));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("tests/validation_frontier_ledger_contract.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(18));
    assert_eq!(frontier["error_class"].as_str(), Some("rustfmt_diff"));
    assert_eq!(
        frontier["first_failure"]["crate_or_surface"].as_str(),
        Some("rustfmt")
    );
    assert_eq!(
        frontier["first_failure"]["target"].as_str(),
        Some("format-check")
    );
    assert_eq!(
        frontier["error_buckets"][0]["error_code"].as_str(),
        Some("rustfmt_diff")
    );
}

#[test]
fn proof_runner_classifies_clippy_lint_fixture() {
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_clippy cargo clippy -p asupersync --lib -- -D warnings";
    let result = classify_fixture("clippy_lint.log", command, &["src/observability/otel.rs"]);
    let outcome = &result["rch_outcome"];
    let frontier = &result["validation_frontier_record"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("failed_local"));
    assert_eq!(
        outcome["diagnostic_class"].as_str(),
        Some("clippy_lint_wall")
    );
    assert_eq!(outcome["decision"].as_str(), Some("failed-local"));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("src/observability/otel.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(114));
    assert_eq!(frontier["error_class"].as_str(), Some("clippy_lint_wall"));
    assert_eq!(
        frontier["error_buckets"][0]["error_code"].as_str(),
        Some("clippy::too_many_arguments")
    );
}

#[test]
fn proof_runner_classifies_truncated_rustc_output_fixture() {
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_lib cargo test -p asupersync --lib -- --nocapture";
    let result = classify_fixture(
        "truncated_rustc_output.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    let outcome = &result["rch_outcome"];
    let frontier = &result["validation_frontier_record"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("blocked_external"));
    assert_eq!(
        outcome["diagnostic_class"].as_str(),
        Some("truncated_rustc_output")
    );
    assert_eq!(outcome["decision"].as_str(), Some("blocked-external"));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("src/runtime/region_heap.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(44));
    assert_eq!(
        frontier["error_class"].as_str(),
        Some("truncated_rustc_output")
    );
    assert_eq!(
        frontier["first_blocker"]["file"].as_str(),
        Some("src/runtime/region_heap.rs")
    );
    assert_eq!(
        frontier["external_to_narrow_fuzz_target_work"].as_bool(),
        Some(true)
    );
}

#[test]
fn proof_runner_compile_frontier_plans_file_shards() {
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_lib cargo test --message-format=short -p asupersync --lib cancel_cx_runtime_channel_metamorphic_tests -- --nocapture";
    let result = proof_runner_json(&[
        "--plan-compile-frontier-shards",
        "tests/fixtures/proof_runner/compile_frontier_multi.log",
        "--command",
        command,
        "--touched-files",
        "src/cx_obligation_trace_metamorphic_tests.rs",
        "--output",
        "json",
    ]);

    assert_eq!(
        result["schema_version"].as_str(),
        Some("proof-runner-compile-frontier-shards-v1")
    );
    assert_eq!(result["total_diagnostics"].as_i64(), Some(4));
    assert_eq!(result["file_group_count"].as_i64(), Some(3));
    assert_eq!(
        result["first_blocker"]["file"].as_str(),
        Some("src/messaging_primitives_conformance_tests.rs")
    );
    assert_eq!(
        result["first_touched_blocker"]["file"].as_str(),
        Some("src/cx_obligation_trace_metamorphic_tests.rs")
    );
    assert_eq!(
        result["first_external_blocker"]["file"].as_str(),
        Some("src/messaging_primitives_conformance_tests.rs")
    );
    assert_eq!(
        result["file_groups"][0]["diagnostic_count"].as_i64(),
        Some(2)
    );
    assert_eq!(
        result["suggested_shards"][0]["reservation_paths"][0].as_str(),
        Some("src/cx_obligation_trace_metamorphic_tests.rs")
    );
    assert_eq!(
        result["suggested_shards"][0]["validation_hint"].as_str(),
        Some(command)
    );
    assert_eq!(
        result["summary"]["green_proof_claimed"].as_bool(),
        Some(false)
    );
    assert_eq!(result["summary"]["mutates_beads"].as_bool(), Some(false));
    assert_eq!(
        result["summary"]["mutates_agent_mail"].as_bool(),
        Some(false)
    );
}

#[test]
fn proof_runner_compile_frontier_planner_avoids_reserved_shards() {
    let snapshot = write_reservation_snapshot(
        r#"{"reservations":[
{"path_pattern":"src/messaging_primitives_conformance_tests.rs","holder":"SilverPike","expires_ts":"2999-01-01T00:00:00Z"},
{"path_pattern":"src/cx_obligation_trace_metamorphic_tests.rs","holder":"RainyFalcon","expires_ts":"2999-01-01T00:00:00Z"}
]}"#,
    );
    let snapshot_path = snapshot.path().to_str().expect("snapshot path utf8");
    let command = "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_lib cargo test --message-format=short -p asupersync --lib cancel_cx_runtime_channel_metamorphic_tests -- --nocapture";
    let result = proof_runner_json(&[
        "--plan-compile-frontier-shards",
        "tests/fixtures/proof_runner/compile_frontier_multi.log",
        "--command",
        command,
        "--touched-files",
        "src/cx_obligation_trace_metamorphic_tests.rs",
        "--reservation-snapshot",
        snapshot_path,
        "--agent-name",
        "RainyFalcon",
        "--output",
        "json",
    ]);

    assert_eq!(
        result["blocked_shards"][0]["reservation_paths"][0].as_str(),
        Some("src/messaging_primitives_conformance_tests.rs")
    );
    assert_eq!(
        result["blocked_shards"][0]["reservation_state"].as_str(),
        Some("peer-active")
    );
    let suggested = result["suggested_shards"]
        .as_array()
        .expect("suggested shards");
    assert!(
        suggested
            .iter()
            .all(|row| row["reservation_paths"][0].as_str()
                != Some("src/messaging_primitives_conformance_tests.rs"))
    );
    assert_eq!(
        result["file_groups"][1]["reservation_state"].as_str(),
        Some("owned-active")
    );
}

#[test]
fn proof_runner_classifies_remote_required_refusal_as_external_admission_blocker() {
    let command = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_refusal cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let result = classify_fixture(
        "rch_remote_required_refusal.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    let outcome = &result["rch_outcome"];
    let frontier = &result["validation_frontier_record"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("blocked_external"));
    assert_eq!(
        outcome["diagnostic_class"].as_str(),
        Some("rch_admission_refusal")
    );
    assert_eq!(outcome["decision"].as_str(), Some("blocked-external"));
    assert_eq!(outcome["first_blocker"]["file"].as_str(), Some("rch"));
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(0));
    assert_eq!(
        frontier["error_class"].as_str(),
        Some("rch_admission_refusal")
    );
    assert_eq!(
        frontier["first_failure"]["crate_or_surface"].as_str(),
        Some("rch")
    );
    assert_eq!(
        frontier["first_failure"]["target"].as_str(),
        Some("remote-admission")
    );
    assert_eq!(
        frontier["rch_result"]["admission"].as_str(),
        Some("local-fallback-refused")
    );
    assert_eq!(
        frontier["rch_result"]["local_fallback_refused"].as_bool(),
        Some(true)
    );
    assert_eq!(frontier["green_proof_claimed"].as_bool(), Some(false));
}

#[test]
fn proof_runner_classifies_full_local_fallback_marker_set_as_failed_local() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";

    for marker in [
        "[RCH] local (daemon unavailable)",
        "falling back to local execution",
        "local fallback selected",
        "fallback to local execution",
        "executing locally after remote failure",
    ] {
        let log = write_text_fixture(&format!(
            "Compiling asupersync v0.3.1\n{marker}\nRemote command finished: exit=0\n"
        ));
        let path = log.path().to_str().expect("text fixture path utf8");
        let output = run_proof_runner(&[
            "--classify-rch-log",
            path,
            "--command",
            command,
            "--touched-files",
            "tests/proof_runner_contract.rs",
            "--output",
            "json",
        ])
        .expect("classify local fallback marker");
        assert!(
            output.status.success(),
            "proof runner failed for marker {marker}: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let result = output_json(&output);
        let outcome = &result["rch_outcome"];

        assert_eq!(
            outcome["outcome_class"].as_str(),
            Some("failed_local"),
            "marker should fail closed: {marker}"
        );
        assert_eq!(
            outcome["decision"].as_str(),
            Some("failed-local"),
            "marker should fail closed: {marker}"
        );
        assert_eq!(
            outcome["first_blocker"]["file"].as_str(),
            Some("rch-local-fallback"),
            "marker should surface local fallback blocker: {marker}"
        );
        assert_eq!(
            result["validation_frontier_record"]["rch_result"]["admission"].as_str(),
            Some("local-fallback-refused"),
            "marker should preserve local fallback admission: {marker}"
        );
        assert_eq!(
            result["validation_frontier_record"]["rch_result"]["local_fallback_refused"].as_bool(),
            Some(true),
            "marker should refuse local fallback: {marker}"
        );
    }
}

#[test]
fn proof_runner_classifies_wrapper_hang_after_remote_exit_separately() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_web_csrf_audit_frontier CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test web_csrf_validation_audit -- --nocapture";
    let result = classify_fixture(
        "wrapper_hang_after_remote_exit.log",
        command,
        &["tests/web_csrf_validation_audit.rs"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(
        outcome["outcome_class"].as_str(),
        Some("wrapper_hang_after_remote_exit")
    );
    assert_eq!(outcome["remote_exit_status"].as_i64(), Some(0));
    assert_eq!(outcome["decision"].as_str(), Some("pass"));
    assert!(
        outcome["summary"]
            .as_str()
            .expect("summary")
            .contains("retrieval")
    );
}

#[test]
fn proof_runner_extracts_external_blocker_file_and_line() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_crashpack_repro_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test crashpack_repro_contract -- --nocapture";
    let result = classify_fixture(
        "external_blocker.log",
        command,
        &["tests/crashpack_repro_contract.rs"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(outcome["outcome_class"].as_str(), Some("blocked_external"));
    assert_eq!(outcome["decision"].as_str(), Some("blocked-external"));
    assert_eq!(
        outcome["first_blocker"]["file"].as_str(),
        Some("src/runtime/scheduler/three_lane.rs")
    );
    assert_eq!(outcome["first_blocker"]["line"].as_i64(), Some(15747));
    assert_eq!(
        result["validation_frontier_record"]["first_failure"]["file"].as_str(),
        Some("src/runtime/scheduler/three_lane.rs")
    );
    assert_eq!(
        result["validation_frontier_record"]["first_failure"]["line"].as_i64(),
        Some(15747)
    );
    assert_eq!(
        result["validation_frontier_record"]["first_blocker"]["file"].as_str(),
        Some("src/runtime/scheduler/three_lane.rs")
    );
    assert_eq!(
        result["validation_frontier_record"]["error_buckets"][0]["error_code"].as_str(),
        Some("E0609")
    );
    assert_eq!(
        result["validation_frontier_record"]["affected_files"][0].as_str(),
        Some("src/runtime/scheduler/three_lane.rs")
    );
    assert_eq!(
        result["validation_frontier_record"]["external_to_narrow_fuzz_target_work"].as_bool(),
        Some(true)
    );
}

#[test]
fn proof_runner_classifies_rch_control_plane_inconsistency() {
    let result = classify_fixture(
        "rch_control_plane_inconsistent_enable_not_found.log",
        "rch workers enable vmi1153651",
        &["scripts/proof_runner.py"],
    );
    let outcome = &result["rch_outcome"];

    assert_eq!(
        outcome["outcome_class"].as_str(),
        Some("rch-control-plane-inconsistent")
    );
    assert_eq!(outcome["decision"].as_str(), Some("blocked-external"));
    assert_eq!(outcome["remote_exit_status"].as_i64(), None);
    assert_eq!(
        outcome["control_plane"]["classification"].as_str(),
        Some("rch-control-plane-inconsistent")
    );
    assert_eq!(
        outcome["control_plane"]["worker"].as_str(),
        Some("vmi1153651")
    );
    assert_eq!(outcome["control_plane"]["action"].as_str(), Some("enable"));
    assert_eq!(
        outcome["control_plane"]["listed_healthy"].as_bool(),
        Some(true)
    );
    assert_eq!(
        outcome["control_plane"]["probed_healthy"].as_bool(),
        Some(true)
    );
    assert_eq!(
        outcome["control_plane"]["recommendation"].as_str(),
        Some("continue repo work if validation does not depend on this worker")
    );
    assert_eq!(
        result["validation_frontier_record"]["decision"].as_str(),
        Some("blocked-external")
    );
    assert_eq!(
        result["validation_frontier_record"]["error_class"].as_str(),
        Some("rch-control-plane-inconsistent")
    );
    assert_eq!(
        result["validation_frontier_record"]["first_failure"]["file"].as_str(),
        Some("rch-control-plane")
    );
    assert_eq!(
        result["validation_frontier_record"]["rch_result"]["admission"].as_str(),
        Some("remote-refused")
    );
    assert_eq!(
        result["validation_frontier_record"]["first_blocker"]["file"].as_str(),
        Some("rch-control-plane")
    );
}

#[test]
fn proof_runner_record_schema_matches_validation_frontier_contract() {
    let schema = load_json(SCHEMA_PATH);
    let required_fields: BTreeSet<String> = schema["record_fields"]
        .as_array()
        .expect("schema should have record_fields")
        .iter()
        .map(|field| {
            field["name"]
                .as_str()
                .expect("field should have name")
                .to_string()
        })
        .collect();

    // Get a sample record from the proof runner
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "README.md",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    let record = &result["validation_frontier_record"];

    // Verify all required fields are present
    for field in &required_fields {
        if field.contains('.') {
            // Nested field like "first_failure.file"
            let parts: Vec<&str> = field.split('.').collect();
            if parts.len() == 2 {
                assert!(
                    record[parts[0]][parts[1]].is_string()
                        || record[parts[0]][parts[1]].is_number()
                        || record[parts[0]][parts[1]].is_boolean()
                        || record[parts[0]][parts[1]].is_null(),
                    "record should have nested field {field}"
                );
            }
        } else {
            // Top-level field
            assert!(
                record[field].is_string()
                    || record[field].is_array()
                    || record[field].is_object()
                    || record[field].is_boolean()
                    || record[field].is_number()
                    || record[field].is_null(),
                "record should have field {field}"
            );
        }
    }
}

#[test]
fn proof_runner_produces_deterministic_output_for_same_inputs() {
    let args = &[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/types/outcome.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ];

    let result1 = proof_runner_json(args);
    let result2 = proof_runner_json(args);

    // Remove timestamp which is expected to differ
    let mut record1 = result1["validation_frontier_record"].clone();
    let mut record2 = result2["validation_frontier_record"].clone();

    if let Value::Object(ref mut map1) = record1 {
        map1.remove("timestamp");
    }
    if let Value::Object(ref mut map2) = record2 {
        map2.remove("timestamp");
    }

    assert_eq!(
        record1, record2,
        "proof runner should produce deterministic output for same inputs"
    );
}

#[test]
fn proof_runner_output_format_is_machine_readable() {
    let result = proof_runner_json(&[
        "--lane",
        "lib-tests",
        "--touched-files",
        "src/channel/mpsc.rs",
        "--skip-dirty-check",
        "--output",
        "json",
    ]);

    // Should have required top-level fields
    assert!(result["preflight_passed"].is_boolean());
    assert!(result["lane_id"].is_string());
    assert!(result["command_would_run"].is_string());
    assert!(result["validation_frontier_record"].is_object());
    assert!(result["recommendation"].is_string());

    let recommendation = result["recommendation"]
        .as_str()
        .expect("recommendation should be string");
    assert!(
        matches!(recommendation, "proceed" | "use_supplemental"),
        "recommendation should be valid: {recommendation}"
    );
}

#[test]
fn proof_runner_emits_deterministic_proof_console_report() {
    let args = &[
        "--proof-console-report",
        "--proof-console-generated-at",
        "2026-05-08T00:00:00Z",
        "--output",
        "json",
    ];
    let report1 = proof_runner_json(args);
    let report2 = proof_runner_json(args);

    assert_eq!(report1, report2, "proof console output must be stable");
    assert_eq!(
        report1["schema_version"].as_str(),
        Some("proof-console-report-v1")
    );
    assert_eq!(
        report1["generated_at"].as_str(),
        Some("2026-05-08T00:00:00Z")
    );
    assert_eq!(report1["generator"]["name"].as_str(), Some(SCRIPT_PATH));
    assert!(
        report1["source_artifact_hashes"]["artifacts/proof_lane_manifest_v1.json"]
            .as_str()
            .expect("manifest hash")
            .starts_with("sha256:")
    );
    assert!(
        !report1["claim_rows"]
            .as_array()
            .expect("claim rows")
            .is_empty()
    );
    assert!(
        !report1["lane_rows"]
            .as_array()
            .expect("lane rows")
            .is_empty()
    );
    assert_eq!(report1["verdict"].as_str(), Some("pass"));
}

#[test]
fn proof_console_report_keeps_mapped_claims_distinct_from_fresh_rch_outcomes() {
    let report = proof_runner_json(&["--proof-console-report", "--output", "json"]);
    let default_claim = report["claim_rows"]
        .as_array()
        .expect("claim rows")
        .iter()
        .find(|row| row["claim_id"].as_str() == Some("no-tokio-production-graph"))
        .expect("no-tokio claim should be present");
    assert_eq!(default_claim["status"].as_str(), Some("green"));
    assert_eq!(default_claim["broad_claim"].as_bool(), Some(false));

    let lane_id = default_claim["manifest_lane_ids"][0]
        .as_str()
        .expect("claim lane id");
    let lane = report["lane_rows"]
        .as_array()
        .expect("lane rows")
        .iter()
        .find(|row| row["lane_id"].as_str() == Some(lane_id))
        .expect("referenced lane should be present");
    assert_eq!(
        lane["status"].as_str(),
        Some("not_run"),
        "snapshot mapping is not a fresh remote execution result"
    );
    assert!(
        lane["explicit_not_covered"]
            .as_str()
            .expect("explicit_not_covered")
            .contains("Workspace"),
        "operator report should preserve lane scope limits"
    );
    assert!(
        report["rch_outcomes"]
            .as_array()
            .expect("rch outcomes")
            .is_empty(),
        "report must not fabricate rch outcomes"
    );
}

#[test]
fn proof_console_report_maps_explicit_rch_outcome_to_lane_status() {
    let outcome = write_reservation_snapshot(
        r#"{
          "rch_outcome": {
            "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_default_tokio_tree cargo tree -e normal -p asupersync -i tokio",
            "outcome_class": "pass",
            "decision": "pass",
            "remote_exit_status": 0,
            "first_blocker": null
          }
        }"#,
    );
    let outcome_path = outcome.path().to_str().expect("outcome path utf8");
    let report = proof_runner_json(&[
        "--proof-console-report",
        "--proof-console-rch-outcome",
        outcome_path,
        "--output",
        "json",
    ]);
    let lane = report["lane_rows"]
        .as_array()
        .expect("lane rows")
        .iter()
        .find(|row| row["lane_id"].as_str() == Some("default-production-tokio-tree"))
        .expect("default production tokio lane should be present");

    assert_eq!(
        lane["status"].as_str(),
        Some("pass"),
        "explicit classified rch outcome should update the matching lane"
    );
    assert_eq!(
        report["summary"]["unclassified_rch_outcome_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["rch_outcomes"]
            .as_array()
            .expect("rch outcomes")
            .len(),
        1
    );
}

#[test]
fn proof_console_human_output_is_stable_markdown_without_raw_coordination_data() {
    let output1 = run_proof_runner(&["--proof-console-report", "--output", "human"])
        .expect("proof console markdown should execute");
    let output2 = run_proof_runner(&["--proof-console-report", "--output", "human"])
        .expect("proof console markdown should execute");

    assert!(output1.status.success());
    assert!(output2.status.success());
    assert_eq!(
        output1.stdout, output2.stdout,
        "default markdown report should be deterministic"
    );

    let markdown = String::from_utf8(output1.stdout).expect("markdown utf8");
    assert!(
        markdown.starts_with("# Proof Console Report\n"),
        "markdown should start with a stable title: {markdown}"
    );
    assert!(
        markdown.contains("| Claim | Status | Lanes | Broad Claim |"),
        "markdown should include the claim table"
    );
    assert!(
        markdown.contains("| Lane | Kind | Status | Guarantees |"),
        "markdown should include the lane table"
    );
    assert!(
        markdown.contains("`no-tokio-production-graph`"),
        "markdown should include snapshot claim rows"
    );
    for forbidden in [
        "/home/ubuntu/",
        "body_md",
        "ack_required",
        "Authorization: Bearer ",
    ] {
        assert!(
            !markdown.contains(forbidden),
            "markdown must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn proof_runner_emits_manifest_backed_proof_status_dashboard() {
    let args = &[
        "--proof-status-dashboard",
        "--proof-console-generated-at",
        "2026-05-08T00:00:00Z",
        "--output",
        "json",
    ];
    let dashboard1 = proof_runner_json(args);
    let dashboard2 = proof_runner_json(args);

    assert_eq!(
        dashboard1, dashboard2,
        "proof status dashboard must be stable"
    );
    assert_eq!(
        dashboard1["schema_version"].as_str(),
        Some("proof-status-dashboard-v1")
    );
    assert_eq!(
        dashboard1["source_report_schema_version"].as_str(),
        Some("proof-console-report-v1")
    );
    assert_eq!(dashboard1["verdict"].as_str(), Some("pass"));
    assert_eq!(
        dashboard1["summary"]["unsupported_broad_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        dashboard1["summary"]["stale_blocker_count"].as_u64(),
        Some(0)
    );

    let no_tokio = dashboard_claim_row(&dashboard1, "no-tokio-production-graph");
    assert_eq!(no_tokio["status"].as_str(), Some("green"));
    assert_eq!(no_tokio["broad_claim"].as_bool(), Some(false));
    assert!(
        no_tokio["proof_commands"]
            .as_array()
            .expect("proof commands")
            .iter()
            .all(|command| command
                .as_str()
                .expect("proof command")
                .starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ")),
        "dashboard must surface exact remote manifest proof commands"
    );
    assert!(
        dashboard1["lane_status_rows"]
            .as_array()
            .expect("lane rows")
            .iter()
            .all(|row| row["command"]
                .as_str()
                .expect("lane command")
                .starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ")),
        "dashboard lane rows must preserve fail-closed remote proof commands"
    );
}

#[test]
fn proof_status_dashboard_fails_closed_on_missing_manifest_lane() {
    let mut snapshot = load_json(STATUS_SNAPSHOT_PATH);
    let claims = snapshot["claim_categories"]
        .as_array_mut()
        .expect("claim categories");
    let claim = claims.first_mut().expect("first claim");
    let claim_id = claim["claim_id"].as_str().expect("claim id").to_string();
    claim["manifest_lane_ids"] = json!(["missing-proof-lane"]);

    let dashboard = proof_status_dashboard_with_snapshot(&snapshot, "2026-05-24T00:00:00Z");

    assert_eq!(dashboard["verdict"].as_str(), Some("fail_closed"));
    assert_eq!(
        dashboard["summary"]["unsupported_broad_claim_count"].as_u64(),
        Some(1)
    );
    assert!(
        dashboard["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(
                |reason| reason["reason_id"].as_str() == Some("unsupported-broad-claim")
                    && reason["claim_id"].as_str() == Some(claim_id.as_str()),
            ),
        "missing manifest lane should be reported as an unsupported claim"
    );

    let row = dashboard_claim_row(&dashboard, &claim_id);
    assert_eq!(row["broad_claim"].as_bool(), Some(true));
    assert!(
        row["operator_action"]
            .as_str()
            .expect("operator action")
            .contains("proof_lane_manifest_v1.json"),
        "operator action should point at the manifest/snapshot repair"
    );
}

#[test]
fn proof_status_dashboard_fails_closed_on_unsupported_guarantee() {
    let mut snapshot = load_json(STATUS_SNAPSHOT_PATH);
    let claims = snapshot["claim_categories"]
        .as_array_mut()
        .expect("claim categories");
    let claim = claims.first_mut().expect("first claim");
    let claim_id = claim["claim_id"].as_str().expect("claim id").to_string();
    claim["manifest_guarantee_ids"] = json!(["unsupported-proof-guarantee"]);

    let dashboard = proof_status_dashboard_with_snapshot(&snapshot, "2026-05-24T00:00:00Z");

    assert_eq!(dashboard["verdict"].as_str(), Some("fail_closed"));
    let row = dashboard_claim_row(&dashboard, &claim_id);
    assert_eq!(row["broad_claim"].as_bool(), Some(true));
    assert!(
        row["failure_reason_ids"]
            .as_array()
            .expect("failure reason ids")
            .iter()
            .any(|reason| reason.as_str() == Some("unsupported-broad-claim")),
        "unsupported guarantee must be tied to the claim row"
    );
}

#[test]
fn proof_status_dashboard_fails_closed_on_stale_blocker_row() {
    let mut snapshot = load_json(STATUS_SNAPSHOT_PATH);
    let claims = snapshot["claim_categories"]
        .as_array_mut()
        .expect("claim categories");
    let claim = claims.first_mut().expect("first claim");
    let claim_id = claim["claim_id"].as_str().expect("claim id").to_string();
    let lane_id = claim["manifest_lane_ids"][0]
        .as_str()
        .expect("lane id")
        .to_string();
    let command = claim["proof_commands"][0]
        .as_str()
        .expect("proof command")
        .to_string();
    claim["status"] = json!("red_blocked_external");
    claim["blocked_frontier"] = json!({
        "generated_at": "2026-05-01T00:00:00Z",
        "command": command,
        "proof_lane_id": lane_id,
        "first_failure": {
            "file": "",
            "line": 0,
            "column": 0,
            "code": "",
            "message": "remote proof lane blocked before an exact source location was recorded"
        }
    });

    let dashboard = proof_status_dashboard_with_snapshot(&snapshot, "2026-05-24T00:00:00Z");

    assert_eq!(dashboard["verdict"].as_str(), Some("fail_closed"));
    assert_eq!(
        dashboard["summary"]["stale_blocker_count"].as_u64(),
        Some(1)
    );
    assert!(
        dashboard["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason["reason_id"].as_str() == Some("stale-blocker-row")),
        "stale red rows should fail closed"
    );

    let row = dashboard_claim_row(&dashboard, &claim_id);
    assert_eq!(row["blocker_status"].as_str(), Some("stale"));
    assert_eq!(row["current_blocker"]["line"].as_u64(), Some(0));
    assert!(
        row["operator_action"]
            .as_str()
            .expect("operator action")
            .contains("refresh blocked_frontier"),
        "operator action should require a fresh exact blocker record"
    );
}

#[test]
fn proof_runner_emits_deterministic_release_proof_pack() {
    let args = &[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--output",
        "json",
    ];
    let result1 = proof_runner_json(args);
    let result2 = proof_runner_json(args);
    assert_eq!(result1, result2, "release proof pack must be stable");

    let pack = &result1["proof_pack"];
    assert_eq!(
        pack["schema_version"].as_str(),
        Some("release-proof-pack-v1")
    );
    assert_eq!(pack["generated_at"].as_str(), Some("2026-05-08T00:00:00Z"));
    assert_eq!(pack["generator"]["name"].as_str(), Some(SCRIPT_PATH));
    assert_eq!(
        pack["generator"]["mode"].as_str(),
        Some("release-proof-pack")
    );
    assert_eq!(pack["verdict"].as_str(), Some("pass"));
    assert_eq!(
        pack["embedded_reports"]["proof_console_report_v1"]["schema_version"].as_str(),
        Some("proof-console-report-v1")
    );
    assert_eq!(
        pack["summaries"]["tracker"]["raw_issue_rows_embedded"].as_bool(),
        Some(false),
        "proof pack must not embed raw tracker rows"
    );
    let tracker_status_keys: BTreeSet<String> = pack["summaries"]["tracker"]["status_counts"]
        .as_object()
        .expect("tracker status counts")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        tracker_status_keys,
        BTreeSet::from([
            "blocked".to_string(),
            "closed".to_string(),
            "in_progress".to_string(),
            "open".to_string(),
            "tombstone".to_string(),
            "unknown".to_string(),
        ]),
        "tracker status buckets must be stable under live tracker churn"
    );

    let artifact_paths: BTreeSet<String> = pack["source_artifacts"]
        .as_array()
        .expect("source artifact rows")
        .iter()
        .map(|row| row["path"].as_str().expect("artifact path").to_string())
        .collect();
    for required in [
        "artifacts/proof_lane_manifest_v1.json",
        "artifacts/proof_status_snapshot_v1.json",
        "artifacts/validation_frontier_ledger_schema_v1.json",
        "artifacts/conformance_registry_contract_v1.json",
        "artifacts/adapter_certification_matrix_v1.json",
        "artifacts/release_proof_pack_contract_v1.json",
    ] {
        assert!(
            artifact_paths.contains(required),
            "release proof pack must include {required}"
        );
    }

    for row in pack["source_artifacts"]
        .as_array()
        .expect("source artifact rows")
    {
        assert_eq!(row["status"].as_str(), Some("included"));
        assert!(
            row["sha256"]
                .as_str()
                .expect("artifact hash")
                .starts_with("sha256:")
        );
        assert!(
            row["bytes"].as_u64().expect("artifact bytes") > 0,
            "included artifact should have nonzero size"
        );
    }

    let commands = pack["proof_commands"]
        .as_array()
        .expect("proof command rows");
    assert!(!commands.is_empty(), "proof pack must list proof commands");
    assert!(
        commands.iter().any(|row| row["command"]
            .as_str()
            .expect("proof command")
            .starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ")),
        "proof pack must carry remote-required rch-routed commands"
    );
}

#[test]
fn release_proof_pack_index_matches_scrubbed_golden() {
    let result = proof_runner_json(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--output",
        "json",
    ]);
    let projection = release_pack_golden_projection(&result);
    let expected =
        load_json("tests/fixtures/proof_runner/release_proof_pack_index_scrubbed_expected.json");
    assert_eq!(
        projection, expected,
        "scrubbed release proof-pack index changed; update the golden only after reviewing release evidence shape, proof commands, and redaction boundaries"
    );
}

#[test]
fn proof_runner_writes_reproducible_release_proof_pack_directory() {
    let tempdir = tempfile::tempdir().expect("create release proof pack tempdir");
    let output_dir = tempdir.path().join("pack");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack tempdir path utf8");
    let output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");

    assert!(
        output.status.success(),
        "release proof pack failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result = output_json(&output);
    let index_path = output_dir.join("index.json");
    let report_path = output_dir.join("reports/proof_console_report_v1.json");
    let manifest_copy = output_dir.join("source_artifacts/artifacts/proof_lane_manifest_v1.json");
    assert!(index_path.exists(), "release pack should write index.json");
    assert!(
        report_path.exists(),
        "release pack should write embedded proof console report"
    );
    assert!(
        manifest_copy.exists(),
        "release pack should copy source artifacts"
    );

    let written_index: Value = serde_json::from_str(
        &std::fs::read_to_string(index_path).expect("read written release index"),
    )
    .expect("parse written release index");
    assert_eq!(
        written_index, result["proof_pack"],
        "written index must match reported proof pack"
    );
    let written_files: BTreeSet<String> = result["write_result"]["written_files"]
        .as_array()
        .expect("written files")
        .iter()
        .map(|value| value.as_str().expect("written file").to_string())
        .collect();
    for required in [
        "index.json",
        "reports/proof_console_report_v1.json",
        "source_artifacts/artifacts/proof_lane_manifest_v1.json",
    ] {
        assert!(
            written_files.contains(required),
            "written_files must include {required}"
        );
    }
}

#[test]
fn proof_runner_verifies_written_release_proof_pack_directory() {
    let tempdir = tempfile::tempdir().expect("create release proof pack tempdir");
    let output_dir = tempdir.path().join("pack");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack tempdir path utf8");
    let write_output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(
        write_output.status.success(),
        "release proof pack write failed: {}\nstdout: {}\nstderr: {}",
        write_output.status,
        String::from_utf8_lossy(&write_output.stdout),
        String::from_utf8_lossy(&write_output.stderr)
    );

    let verify_output = run_proof_runner(&[
        "--verify-release-proof-pack-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack verifier should execute");
    assert!(
        verify_output.status.success(),
        "release proof pack verifier failed: {}\nstdout: {}\nstderr: {}",
        verify_output.status,
        String::from_utf8_lossy(&verify_output.stdout),
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verification = output_json(&verify_output);
    assert_eq!(
        verification["schema_version"].as_str(),
        Some("release-proof-pack-verification-v1")
    );
    assert_eq!(verification["verdict"].as_str(), Some("pass"));
    assert_eq!(
        verification["summary"]["source_artifact_count"].as_u64(),
        Some(6)
    );
    assert_eq!(
        verification["summary"]["embedded_report_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        verification["summary"]["stale_file_count"].as_u64(),
        Some(0)
    );
}

#[test]
fn release_proof_pack_verifier_fail_closes_on_stale_copied_artifact() {
    let tempdir = tempfile::tempdir().expect("create release proof pack tempdir");
    let output_dir = tempdir.path().join("pack");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack tempdir path utf8");
    let write_output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(
        write_output.status.success(),
        "release proof pack write failed: {}\nstdout: {}\nstderr: {}",
        write_output.status,
        String::from_utf8_lossy(&write_output.stdout),
        String::from_utf8_lossy(&write_output.stderr)
    );

    let manifest_copy = output_dir.join("source_artifacts/artifacts/proof_lane_manifest_v1.json");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&manifest_copy)
        .expect("open copied manifest artifact");
    writeln!(file, "stale verifier mutation").expect("mutate copied manifest artifact");

    let verify_output = run_proof_runner(&[
        "--verify-release-proof-pack-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack verifier should execute");
    assert!(
        !verify_output.status.success(),
        "stale copied artifact must make verifier fail closed"
    );
    let verification = output_json(&verify_output);
    assert_eq!(verification["verdict"].as_str(), Some("fail_closed"));
    assert_eq!(
        verification["summary"]["stale_file_count"].as_u64(),
        Some(1)
    );
    assert!(
        verification["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason["reason_id"].as_str() == Some("stale-source-artifact-copy")),
        "verifier should identify stale copied source artifact"
    );
}

#[test]
fn release_proof_pack_rch_log_bundles_and_verifies_source_logs() {
    let command = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_release_pack cargo tree -e normal -p asupersync -i tokio";
    let classified = classify_fixture(
        "rch_pass.log",
        command,
        &["artifacts/proof_lane_manifest_v1.json"],
    );
    let outcome = write_json_fixture(&classified);
    let outcome_path = outcome.path().to_str().expect("outcome path utf8");
    let tempdir = tempfile::tempdir().expect("create release proof pack tempdir");
    let output_dir = tempdir.path().join("pack");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack tempdir path utf8");

    let write_output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-rch-outcome",
        outcome_path,
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(
        write_output.status.success(),
        "release proof pack with rch log failed: {}\nstdout: {}\nstderr: {}",
        write_output.status,
        String::from_utf8_lossy(&write_output.stdout),
        String::from_utf8_lossy(&write_output.stderr)
    );
    let result = output_json(&write_output);
    let pack = &result["proof_pack"];
    let rch_log_rows = pack["rch_log_rows"].as_array().expect("rch log rows");
    assert_eq!(rch_log_rows.len(), 1);
    assert_eq!(
        pack["summary"]["rch_log_count"].as_u64(),
        Some(1),
        "pack summary should count bundled rch logs"
    );
    let copied_log = output_dir.join(rch_log_rows[0]["path"].as_str().expect("rch log path"));
    assert!(
        copied_log.exists(),
        "release pack should copy rch source log"
    );

    let verify_output = run_proof_runner(&[
        "--verify-release-proof-pack-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack verifier should execute");
    assert!(
        verify_output.status.success(),
        "release proof pack verifier failed after rch log copy: {}\nstdout: {}\nstderr: {}",
        verify_output.status,
        String::from_utf8_lossy(&verify_output.stdout),
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verification = output_json(&verify_output);
    assert_eq!(verification["verdict"].as_str(), Some("pass"));
    assert_eq!(verification["summary"]["rch_log_count"].as_u64(), Some(1));
}

#[test]
fn release_proof_pack_rch_log_verifier_fail_closes_on_stale_copy() {
    let command = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_release_pack cargo tree -e normal -p asupersync -i tokio";
    let classified = classify_fixture(
        "rch_pass.log",
        command,
        &["artifacts/proof_lane_manifest_v1.json"],
    );
    let outcome = write_json_fixture(&classified);
    let outcome_path = outcome.path().to_str().expect("outcome path utf8");
    let tempdir = tempfile::tempdir().expect("create release proof pack tempdir");
    let output_dir = tempdir.path().join("pack");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack tempdir path utf8");

    let write_output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-rch-outcome",
        outcome_path,
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(write_output.status.success());
    let result = output_json(&write_output);
    let log_path = result["proof_pack"]["rch_log_rows"][0]["path"]
        .as_str()
        .expect("rch log path");
    let copied_log = output_dir.join(log_path);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&copied_log)
        .expect("open copied rch log");
    writeln!(file, "stale rch log mutation").expect("mutate copied rch log");

    let verify_output = run_proof_runner(&[
        "--verify-release-proof-pack-dir",
        output_dir_text,
        "--output",
        "json",
    ])
    .expect("release proof pack verifier should execute");
    assert!(
        !verify_output.status.success(),
        "stale copied rch log must make verifier fail closed"
    );
    let verification = output_json(&verify_output);
    assert_eq!(verification["verdict"].as_str(), Some("fail_closed"));
    assert!(
        verification["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason["reason_id"].as_str() == Some("stale-rch-log-copy")),
        "verifier should identify stale copied rch log"
    );
}

#[test]
fn release_proof_pack_rch_log_e2e_smoke_fixture_writes_and_verifies_pack() {
    let command = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_release_pack cargo tree -e normal -p asupersync -i tokio";
    let tempdir = tempfile::tempdir().expect("create release proof pack smoke tempdir");
    let output_dir = tempdir.path().join("smoke");
    let output_dir_text = output_dir
        .to_str()
        .expect("release proof pack smoke tempdir path utf8");
    let output = run_proof_runner(&[
        "--release-proof-pack-e2e-smoke",
        "--command",
        command,
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-output-dir",
        output_dir_text,
        "--release-proof-pack-smoke-log-fixture",
        "tests/fixtures/proof_runner/rch_pass.log",
        "--touched-files",
        "artifacts/proof_lane_manifest_v1.json",
        "--output",
        "json",
    ])
    .expect("release proof pack smoke should execute");
    assert!(
        output.status.success(),
        "release proof pack smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let smoke = output_json(&output);
    assert_eq!(
        smoke["schema_version"].as_str(),
        Some("release-proof-pack-e2e-smoke-v1")
    );
    assert_eq!(smoke["execution_mode"].as_str(), Some("fixture"));
    assert_eq!(smoke["verdict"].as_str(), Some("pass"));
    assert_eq!(
        smoke["smoke_commands"][0]["decision"].as_str(),
        Some("pass")
    );
    assert_eq!(
        smoke["proof_pack"]["summary"]["rch_log_count"].as_u64(),
        Some(1)
    );
    assert_eq!(smoke["verification"]["verdict"].as_str(), Some("pass"));
    assert!(
        output_dir.join("pack/index.json").exists(),
        "smoke should write a release proof pack directory"
    );
}

#[test]
fn release_proof_pack_fail_closes_on_missing_rch_log() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let mut classified = classify_fixture(
        "normal_artifact_retrieval.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    classified["rch_outcome"]["source_log_path"] =
        Value::String("tests/fixtures/proof_runner/missing-rch-proof.log".to_string());
    let outcome = write_json_fixture(&classified);
    let outcome_path = outcome.path().to_str().expect("outcome path utf8");
    let output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-rch-outcome",
        outcome_path,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(
        !output.status.success(),
        "missing source rch log must make release pack fail closed"
    );
    let result = output_json(&output);
    let pack = &result["proof_pack"];
    assert_eq!(pack["verdict"].as_str(), Some("fail_closed"));
    assert!(
        pack["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason["reason_id"].as_str() == Some("missing-rch-log")),
        "release pack should name the missing rch source log"
    );
}

#[test]
fn release_proof_pack_fail_closes_on_stale_rch_log_digest() {
    let command = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture";
    let mut classified = classify_fixture(
        "normal_artifact_retrieval.log",
        command,
        &["tests/proof_runner_contract.rs"],
    );
    classified["rch_outcome"]["source_log_sha256"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    let outcome = write_json_fixture(&classified);
    let outcome_path = outcome.path().to_str().expect("outcome path utf8");
    let output = run_proof_runner(&[
        "--release-proof-pack",
        "--release-proof-pack-generated-at",
        "2026-05-08T00:00:00Z",
        "--release-proof-pack-rch-outcome",
        outcome_path,
        "--output",
        "json",
    ])
    .expect("release proof pack should execute");
    assert!(
        !output.status.success(),
        "stale source rch log digest must make release pack fail closed"
    );
    let result = output_json(&output);
    let pack = &result["proof_pack"];
    assert_eq!(pack["verdict"].as_str(), Some("fail_closed"));
    assert!(
        pack["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason["reason_id"].as_str() == Some("stale-rch-log")),
        "release pack should name the stale rch source log"
    );
}

#[test]
fn release_proof_pack_contract_names_required_artifacts_and_proofs() {
    let contract = load_json("artifacts/release_proof_pack_contract_v1.json");
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("release-proof-pack-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-rgzqen"));
    assert_eq!(
        contract["generator"]["script"].as_str(),
        Some("scripts/proof_runner.py")
    );
    assert_eq!(
        contract["generator"]["mode"].as_str(),
        Some("--release-proof-pack")
    );

    let required_artifacts: BTreeSet<String> = contract["required_source_artifacts"]
        .as_array()
        .expect("required source artifacts")
        .iter()
        .map(|value| value.as_str().expect("artifact path").to_string())
        .collect();
    for required in [
        "artifacts/proof_lane_manifest_v1.json",
        "artifacts/conformance_registry_contract_v1.json",
        "artifacts/adapter_certification_matrix_v1.json",
        "artifacts/release_proof_pack_contract_v1.json",
    ] {
        assert!(
            required_artifacts.contains(required),
            "contract must require {required}"
        );
    }

    let commands = contract["validation_commands"]
        .as_array()
        .expect("validation commands")
        .iter()
        .map(|value| value.as_str().expect("validation command"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(commands.contains("--release-proof-pack"));
    assert!(commands.contains("--release-proof-pack-e2e-smoke"));
    assert!(commands.contains("rch exec -- "));
}
