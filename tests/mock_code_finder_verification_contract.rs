#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let path = repo_path("artifacts/mock_code_finder_verification_contract_v1.json");
    let json = std::fs::read_to_string(&path).expect("read mock-code-finder contract artifact");
    serde_json::from_str(&json).expect("parse mock-code-finder contract artifact")
}

fn string_array<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

#[test]
fn mock_code_finder_contract_declares_required_evidence_shape() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("mock-code-finder-verification-contract-v1")
    );
    assert_eq!(
        contract.get("schema_version").and_then(Value::as_str),
        Some("mock-code-finder-evidence-jsonl-schema-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-qlvtin")
    );
    assert_eq!(
        contract.get("artifact_root").and_then(Value::as_str),
        Some("artifacts/mock-code-finder")
    );

    let required = contract
        .pointer("/record_layout/required_fields")
        .and_then(Value::as_array)
        .expect("required_fields array");
    let required: BTreeSet<_> = required
        .iter()
        .map(|item| item.as_str().expect("required field names are strings"))
        .collect();

    for field in [
        "schema_version",
        "bead_id",
        "scenario_id",
        "subsystem",
        "support_class",
        "source_files_inspected",
        "command",
        "rch_command_if_used",
        "cargo_features",
        "test_filter",
        "env_keys_required",
        "deterministic_seed_or_fixture_id",
        "input_artifact",
        "output_artifact",
        "expected_behavior",
        "actual_behavior",
        "verdict",
        "first_failure_line",
        "duration_ms",
        "git_sha_or_tree_state",
        "blocker_bead_id",
        "evidence_quality",
    ] {
        assert!(
            required.contains(field),
            "required_fields should include {field}"
        );
    }

    assert_eq!(
        required.len(),
        22,
        "required_fields should not carry duplicate or surprise fields"
    );
}

#[test]
fn mock_code_finder_contract_samples_cover_non_live_outcomes() {
    let contract = contract();
    let verdicts = string_array(&contract["allowed_values"], "verdict");
    let verdicts: BTreeSet<_> = verdicts.into_iter().collect();
    assert_eq!(
        verdicts,
        BTreeSet::from([
            "blocked",
            "expected_fail",
            "fail",
            "fixture_only",
            "pass",
            "unsupported"
        ])
    );

    let samples = contract
        .get("sample_records")
        .and_then(Value::as_array)
        .expect("sample_records array");
    let sample_verdicts: BTreeSet<_> = samples
        .iter()
        .map(|sample| {
            sample
                .get("verdict")
                .and_then(Value::as_str)
                .expect("sample verdict")
        })
        .collect();
    assert_eq!(sample_verdicts, verdicts);

    let required = contract
        .pointer("/record_layout/required_fields")
        .and_then(Value::as_array)
        .expect("required_fields array");
    for sample in samples {
        for field in required {
            let field = field.as_str().expect("required field name");
            assert!(sample.get(field).is_some(), "sample record missing {field}");
        }
    }
}

#[test]
fn mock_code_finder_validator_self_test_passes() {
    let output = Command::new("python3")
        .arg("scripts/validate_mock_code_finder_evidence.py")
        .arg("--self-test")
        .current_dir(repo_path(""))
        .output()
        .expect("run mock-code-finder validator self-test");

    assert!(
        output.status.success(),
        "validator self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
