//! Contract tests for the runtime p999 divergence receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/runtime_p999_divergence_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/runtime_p999_divergence_receipt";
const GENERATED_AT: &str = "2026-05-08T05:50:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--measurements")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run runtime p999 divergence receipt helper")
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

fn scenario<'a>(receipt: &'a Value, name: &str) -> &'a Value {
    receipt["scenarios"]
        .as_array()
        .expect("scenarios array")
        .iter()
        .find(|scenario| scenario["scenario"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing scenario {name}"))
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
fn aligned_fixture_passes_with_ratio_under_threshold() {
    let receipt = receipt_json("aligned.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("runtime-p999-divergence-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["decision"].as_str(), Some("passed"));
    assert_eq!(receipt["source_counts"]["aligned"].as_u64(), Some(1));
    assert_eq!(receipt["source_counts"]["divergent"].as_u64(), Some(0));

    let scheduler = scenario(&receipt, "scheduler_burst_64");
    assert_eq!(scheduler["classification"].as_str(), Some("aligned"));
    assert_eq!(scheduler["sample_count_ok"].as_bool(), Some(true));
    assert!(
        scheduler["p999_ratio"].as_f64().expect("ratio") < 1.25,
        "aligned fixture should stay under ratio threshold"
    );
}

#[test]
fn divergent_fixture_flags_p999_gap_and_missing_pair() {
    let receipt = receipt_json("diverged_and_missing.json");

    assert_eq!(receipt["decision"].as_str(), Some("needs-review"));
    assert_eq!(receipt["source_counts"]["divergent"].as_u64(), Some(2));
    assert_eq!(receipt["source_counts"]["missing_pairs"].as_u64(), Some(1));
    assert_eq!(
        receipt["source_counts"]["blocked_measurements"].as_u64(),
        Some(1)
    );

    let scheduler = scenario(&receipt, "scheduler_burst_64");
    assert_eq!(scheduler["classification"].as_str(), Some("p999-diverged"));
    assert_eq!(scheduler["p999_ratio"].as_f64(), Some(2.0));

    let cancel = scenario(&receipt, "cancel_storm_512");
    assert_eq!(cancel["classification"].as_str(), Some("missing-lab"));
    assert!(cancel["lab"].is_null());
}

#[test]
fn low_sample_counts_are_divergence_until_rerun() {
    let receipt = receipt_json("diverged_and_missing.json");
    let timer = scenario(&receipt, "timer_wheel_steady");

    assert_eq!(timer["classification"].as_str(), Some("p999-diverged"));
    assert_eq!(timer["sample_count_ok"].as_bool(), Some(false));
    assert!(
        timer["operator_guidance"]
            .as_str()
            .expect("operator guidance")
            .contains("Do not cite native-vs-lab parity")
    );
}

#[test]
fn blocked_measurements_are_not_treated_as_parity() {
    let receipt = receipt_json("diverged_and_missing.json");
    let reactor = scenario(&receipt, "io_reactor_wakeup");

    assert_eq!(
        reactor["classification"].as_str(),
        Some("blocked-measurement")
    );
    assert_eq!(reactor["sample_count_ok"].as_bool(), Some(false));
    assert!(
        reactor["operator_guidance"]
            .as_str()
            .expect("operator guidance")
            .contains("blocked evidence")
    );
}

#[test]
fn helper_declares_it_does_not_run_benchmarks_or_mutate_state() {
    let receipt = receipt_json("aligned.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_benchmarks",
        "runs_cargo",
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
fn fixtures_are_valid_json_objects() {
    for fixture in ["aligned.json", "diverged_and_missing.json"] {
        let path = repo_root().join(FIXTURE_ROOT).join(fixture);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        assert!(parsed.as_object().is_some(), "{fixture} must be an object");
    }
}
