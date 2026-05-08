//! Contract tests for the agent-swarm safe proof runner.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_runner.py";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
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
    if !output.status.success() {
        panic!(
            "proof runner failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
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

fn output_json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURE_ROOT}/{fixture}"))
        .unwrap_or_else(|error| panic!("read proof runner fixture {fixture}: {error}"))
}

fn classify_fixture(fixture: &str, command: &str, touched_files: &[&str]) -> Value {
    let fixture_path = format!("{FIXTURE_ROOT}/{fixture}");
    let mut args = vec![
        "--classify-rch-log",
        fixture_path.as_str(),
        "--command",
        command,
        "--touched-files",
    ];
    args.extend_from_slice(touched_files);
    args.extend_from_slice(&["--output", "json"]);
    proof_runner_json(&args)
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
fn proof_runner_emits_validation_frontier_compatible_records() {
    // Test with a known lane to get a proper record structure
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--output",
        "json",
    ]);

    let record = &result["validation_frontier_record"];

    // Verify required fields from the schema exist
    assert!(record["command"].is_string(), "record must have command");
    assert!(
        record["timestamp"].is_string(),
        "record must have timestamp"
    );
    assert!(
        record["touched_files"].is_array(),
        "record must have touched_files array"
    );
    assert!(record["decision"].is_string(), "record must have decision");
    assert!(
        record["error_class"].is_string(),
        "record must have error_class"
    );

    let first_failure = &record["first_failure"];
    assert!(first_failure["crate_or_surface"].is_string());
    assert!(first_failure["target"].is_string());
    assert!(first_failure["file"].is_string());
    assert!(first_failure["line"].is_number());

    assert!(
        record["likely_owner"].is_string(),
        "record must have likely_owner"
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
    ] {
        assert!(
            fixture_names.contains(required),
            "missing fixture {required}"
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
        "decision",
        "first_blocker",
    ] {
        assert!(
            required_outcome_fields.contains(required),
            "missing required outcome field {required}"
        );
    }
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
                        || record[parts[0]][parts[1]].is_null(),
                    "record should have nested field {field}"
                );
            }
        } else {
            // Top-level field
            assert!(
                record[field].is_string() || record[field].is_array() || record[field].is_null(),
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
