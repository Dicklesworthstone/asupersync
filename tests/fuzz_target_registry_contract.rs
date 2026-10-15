//! Contract tests for the fuzz target registry proof-lane helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/fuzz_target_registry_contract.py";
const FIXTURE_ROOT: &str = "tests/fixtures/fuzz_target_registry_contract";
const GENERATED_AT: &str = "2026-05-10T08:35:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_registry(fixture: &str) -> Output {
    let root = repo_root().join(FIXTURE_ROOT).join(fixture);
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--manifest")
        .arg(root.join("fuzz/Cargo.toml"))
        .arg("--target-root")
        .arg(root.join("fuzz/fuzz_targets"))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run fuzz target registry helper")
}

fn registry_json(fixture: &str) -> Value {
    let output = run_registry(fixture);
    assert!(
        output.status.success(),
        "registry helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("registry output must be JSON")
}

fn issue_codes(receipt: &Value) -> Vec<&str> {
    receipt["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .filter_map(|row| row["code"].as_str())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "registry helper must exist at {SCRIPT_PATH}"
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
fn clean_manifest_derives_bin_scoped_rch_proof_lanes() {
    let receipt = registry_json("clean");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("fuzz-target-registry-contract-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(receipt["summary"]["registered_targets"].as_u64(), Some(1));
    assert_eq!(receipt["summary"]["target_files"].as_u64(), Some(2));
    assert_eq!(
        receipt["registered_targets"][0]["name"].as_str(),
        Some("h2_settings_window")
    );
    assert_eq!(
        receipt["included_target_files"][0].as_str(),
        Some(
            "tests/fixtures/fuzz_target_registry_contract/clean/fuzz/fuzz_targets/h2_settings_window_body.rs"
        )
    );
    assert_eq!(receipt["orphan_target_files"].as_array().unwrap().len(), 0);
    assert_eq!(
        receipt["registered_targets"][0]["proof_lane"]["check"].as_str(),
        Some(
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_<agent>_h2_settings_window cargo check --manifest-path fuzz/Cargo.toml --bin h2_settings_window"
        )
    );
    assert_eq!(
        receipt["registered_targets"][0]["proof_lane"]["clippy"].as_str(),
        Some(
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_<agent>_h2_settings_window cargo clippy --manifest-path fuzz/Cargo.toml --bin h2_settings_window --no-deps -- -D warnings"
        )
    );
}

#[test]
fn orphan_target_file_fails_registration_contract() {
    let receipt = registry_json("orphan");
    let codes = issue_codes(&receipt);

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert!(codes.contains(&"missing-registration"));
    assert_eq!(
        receipt["orphan_target_files"][0].as_str(),
        Some(
            "tests/fixtures/fuzz_target_registry_contract/orphan/fuzz/fuzz_targets/orphan_target.rs"
        )
    );
}

#[test]
fn duplicate_bin_names_and_paths_are_blockers() {
    let receipt = registry_json("duplicate");
    let codes = issue_codes(&receipt);

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert!(codes.contains(&"duplicate-bin-name"));
    assert!(codes.contains(&"duplicate-target-path"));
    assert_eq!(
        receipt["requirements"]["bin_names_are_unique"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["requirements"]["every_target_file_has_one_bin"].as_bool(),
        Some(false)
    );
}

#[test]
fn mismatched_bin_name_is_reported_with_allowed_names() {
    let receipt = registry_json("mismatched_name");
    let codes = issue_codes(&receipt);
    let mismatch = receipt["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .find(|row| row["code"].as_str() == Some("bin-name-path-mismatch"))
        .expect("mismatch issue");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert!(codes.contains(&"bin-name-path-mismatch"));
    assert_eq!(mismatch["name"].as_str(), Some("redis_resp_parser"));
    assert!(
        mismatch["allowed_names"]
            .as_array()
            .expect("allowed names")
            .iter()
            .any(|value| value.as_str() == Some("postgres_row_description"))
    );
}

#[test]
fn helper_declares_it_never_mutates_or_runs_cargo() {
    let receipt = registry_json("clean");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "edits_fuzz_manifest",
        "creates_fuzz_targets",
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
