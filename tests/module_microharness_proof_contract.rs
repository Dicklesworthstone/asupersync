//! Contract tests for module-scoped proof microharness receipts.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/module_microharness_proof.py";
const FIXTURE_ROOT: &str = "tests/fixtures/module_microharness_proof";
const GENERATED_AT: &str = "2026-05-29T00:00:00Z";
const TARGET_DIR: &str = "/tmp/rch_target_l5m170_1_raptorq_table_invariant_contract";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_microharness(args: &[&str]) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run module microharness proof helper")
}

fn receipt_json(args: &[&str]) -> Value {
    let output = run_microharness(args);
    assert!(
        output.status.success(),
        "microharness proof helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("microharness receipt must be JSON")
}

fn classify_fixture(fixture: &str) -> Value {
    let fixture_path = repo_root().join(FIXTURE_ROOT).join(fixture);
    receipt_json(&[
        "--from-log",
        fixture_path.to_str().expect("fixture path utf8"),
        "--generated-at",
        GENERATED_AT,
        "--target-dir",
        TARGET_DIR,
    ])
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "microharness proof helper must exist at {SCRIPT_PATH}"
    );
    let output = run_microharness(&["--help"]);
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn dry_run_declares_mapping_command_and_exclusions() {
    let receipt = receipt_json(&[
        "--dry-run",
        "--generated-at",
        GENERATED_AT,
        "--target-dir",
        TARGET_DIR,
    ]);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("module-microharness-proof-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(
        receipt["lane"]["implementation_bead_id"].as_str(),
        Some("asupersync-l5m170.1")
    );
    assert_eq!(
        receipt["lane"]["blocked_bead_id"].as_str(),
        Some("asupersync-to7e65.12")
    );
    assert_eq!(
        receipt["lane"]["cargo_test_target"].as_str(),
        Some("raptorq_proof_table_invariant_microharness")
    );
    assert!(
        receipt["lane"]["command"]
            .as_str()
            .expect("command")
            .contains("--test raptorq_proof_table_invariant_microharness")
    );
    assert_eq!(receipt["summary"]["status"].as_str(), Some("planned"));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
}

#[test]
fn passing_rch_log_produces_closeable_receipt() {
    let receipt = classify_fixture("raptorq_table_invariant_pass.log");

    assert_eq!(receipt["summary"]["status"].as_str(), Some("passed"));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(
        receipt["summary"]["ready_to_close_blocked_bead"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["execution"]["selected_worker"].as_str(),
        Some("vmi1227854")
    );
    assert_eq!(receipt["execution"]["remote_exit_code"].as_i64(), Some(0));
    assert_eq!(
        receipt["execution"]["remote_elapsed_ms"].as_i64(),
        Some(12345)
    );
    assert_eq!(
        receipt["execution"]["wrapper_timed_out"].as_bool(),
        Some(false)
    );
    assert_eq!(receipt["execution"]["test_count"].as_u64(), Some(3));
    assert_eq!(
        receipt["execution"]["test_result"]["passed"].as_u64(),
        Some(3)
    );
    assert_eq!(
        receipt["execution"]["microharness_events"][0]["proof_target"].as_str(),
        Some("raptorq-proof-table-invariant")
    );
}

#[test]
fn stalled_rch_log_is_not_misreported_as_pass() {
    let receipt = classify_fixture("raptorq_table_invariant_stall.log");

    assert_eq!(
        receipt["summary"]["status"].as_str(),
        Some("unknown-stalled")
    );
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        receipt["summary"]["retry_recommendation"].as_str(),
        Some("retry-on-fresh-worker-or-use-stall-receipt")
    );
    assert_eq!(
        receipt["execution"]["selected_worker"].as_str(),
        Some("vmi1149989")
    );
    assert_eq!(receipt["execution"]["remote_exit_code"].as_i64(), None);
    assert_eq!(receipt["execution"]["test_count"].as_u64(), None);
    assert_eq!(
        receipt["execution"]["last_compile_frontier"]["text"].as_str(),
        Some("Compiling asupersync-conformance v0.3.1 (/data/projects/asupersync/conformance)")
    );
}

#[test]
fn failing_rch_log_exits_nonzero_and_keeps_failure_counts() {
    let fixture_path = repo_root()
        .join(FIXTURE_ROOT)
        .join("raptorq_table_invariant_failure.log");
    let output = run_microharness(&[
        "--from-log",
        fixture_path.to_str().expect("fixture path utf8"),
        "--generated-at",
        GENERATED_AT,
        "--target-dir",
        TARGET_DIR,
    ]);

    assert!(
        !output.status.success(),
        "failing fixture should produce a nonzero helper exit"
    );
    let receipt: Value =
        serde_json::from_slice(&output.stdout).expect("failure receipt must be JSON");
    assert_eq!(receipt["summary"]["status"].as_str(), Some("failed"));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(receipt["execution"]["remote_exit_code"].as_i64(), Some(101));
    assert_eq!(
        receipt["execution"]["test_result"]["failed"].as_u64(),
        Some(1)
    );
}
