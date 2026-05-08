//! Contract tests for the rch worker quarantine receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/rch_worker_quarantine_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/rch_worker_quarantine_receipt";
const GENERATED_AT: &str = "2026-05-08T05:35:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--observations")
        .arg(Path::new(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run rch worker quarantine receipt helper")
}

fn fixture_text(fixture: &str) -> String {
    let path = repo_root().join(FIXTURE_ROOT).join(fixture);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read golden fixture {}: {err}", path.display()))
}

fn receipt_json(fixture: &str) -> Value {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn worker<'a>(receipt: &'a Value, name: &str) -> &'a Value {
    receipt["workers"]
        .as_array()
        .expect("workers array")
        .iter()
        .find(|worker| worker["worker"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing worker {name}"))
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "receipt helper must exist at {SCRIPT_PATH}"
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
fn healthy_fixture_does_not_quarantine_worker() {
    let receipt = receipt_json("healthy.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("rch-worker-quarantine-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["decision"].as_str(), Some("no-quarantine"));
    assert_eq!(receipt["source_counts"]["observations"].as_u64(), Some(2));
    assert_eq!(
        receipt["source_counts"]["quarantine_recommended"].as_u64(),
        Some(0)
    );

    let fast = worker(&receipt, "vmi-fast");
    assert_eq!(fast["classification"].as_str(), Some("healthy"));
    assert_eq!(fast["quarantine_recommended"].as_bool(), Some(false));
    assert_eq!(fast["healthy_samples"].as_u64(), Some(2));
}

#[test]
fn mixed_degraded_output_matches_full_reviewed_golden() {
    let output = run_receipt("mixed_degraded.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be utf-8");
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt output JSON");
    let expected = fixture_text("mixed_degraded_expected.json");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected receipt output JSON");

    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(actual, expected);
}

#[test]
fn repeated_slow_retrievals_trigger_quarantine() {
    let receipt = receipt_json("mixed_degraded.json");
    let slow = worker(&receipt, "vmi-slow");

    assert_eq!(receipt["decision"].as_str(), Some("quarantine-suggested"));
    assert_eq!(slow["classification"].as_str(), Some("quarantine"));
    assert_eq!(slow["quarantine_recommended"].as_bool(), Some(true));
    assert_eq!(slow["slow_retrieval_count"].as_u64(), Some(2));
    assert!(
        slow["operator_guidance"]
            .as_str()
            .expect("operator guidance")
            .contains("Avoid selecting this worker")
    );
}

#[test]
fn repeated_remote_failures_trigger_quarantine() {
    let receipt = receipt_json("mixed_degraded.json");
    let failing = worker(&receipt, "vmi-fail");

    assert_eq!(failing["classification"].as_str(), Some("quarantine"));
    assert_eq!(failing["remote_failure_count"].as_u64(), Some(2));
    assert_eq!(failing["quarantine_recommended"].as_bool(), Some(true));
}

#[test]
fn single_failure_and_no_capacity_are_distinct_non_quarantine_states() {
    let receipt = receipt_json("mixed_degraded.json");
    let one_fail = worker(&receipt, "vmi-onefail");
    let zero = worker(&receipt, "vmi-zero");

    assert_eq!(one_fail["classification"].as_str(), Some("remote-failing"));
    assert_eq!(one_fail["quarantine_recommended"].as_bool(), Some(false));
    assert_eq!(zero["classification"].as_str(), Some("no-capacity"));
    assert_eq!(zero["no_capacity_count"].as_u64(), Some(1));
}

#[test]
fn observation_flags_preserve_worker_level_evidence() {
    let receipt = receipt_json("mixed_degraded.json");
    let flags = receipt["observation_flags"]
        .as_array()
        .expect("observation flags array");

    assert!(flags.iter().any(|sample| {
        sample["worker"].as_str() == Some("vmi-slow")
            && sample["flags"]
                .as_array()
                .expect("flags")
                .iter()
                .any(|flag| flag.as_str() == Some("slow_artifact_retrieval"))
    }));
    assert!(flags.iter().any(|sample| {
        sample["worker"].as_str() == Some("vmi-zero")
            && sample["flags"]
                .as_array()
                .expect("flags")
                .iter()
                .any(|flag| flag.as_str() == Some("no_capacity"))
    }));
}

#[test]
fn helper_declares_it_does_not_mutate_project_or_rch_state() {
    let receipt = receipt_json("mixed_degraded.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_rch_mutation",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}

#[test]
fn fixtures_are_json_objects() {
    for fixture in ["healthy.json", "mixed_degraded.json"] {
        let path = repo_root().join(FIXTURE_ROOT).join(fixture);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        assert!(
            parsed.as_object().is_some(),
            "{} must be a JSON object",
            Path::new(fixture).display()
        );
    }
}
