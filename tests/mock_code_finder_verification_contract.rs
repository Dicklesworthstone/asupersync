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

#[test]
fn rfc6330_evidence_runner_lists_and_self_tests() {
    let list_output = Command::new("bash")
        .arg("scripts/run_rfc6330_conformance_evidence.sh")
        .arg("--list")
        .current_dir(repo_path(""))
        .output()
        .expect("list RFC6330 evidence runner scenarios");

    assert!(
        list_output.status.success(),
        "runner --list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list_output.stdout),
        String::from_utf8_lossy(&list_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("RFC6330-PROOF-RUN-ALL-LIVE"));
    assert!(stdout.contains("RFC6330-PROOF-SECTION-5-3-LIVE"));
    assert!(stdout.contains("aggregate_runner_bead=asupersync-oelvq2"));

    let artifact_root = repo_path("target/mock-code-finder/asupersync-kokw3m-contract-test")
        .join(std::process::id().to_string());
    let self_test_output = Command::new("bash")
        .arg("scripts/run_rfc6330_conformance_evidence.sh")
        .arg("--self-test")
        .arg("--artifact-root")
        .arg(&artifact_root)
        .current_dir(repo_path(""))
        .output()
        .expect("run RFC6330 evidence runner self-test");

    assert!(
        self_test_output.status.success(),
        "runner --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test_output.stdout),
        String::from_utf8_lossy(&self_test_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&self_test_output.stdout);
    assert!(stdout.contains("RFC6330 evidence runner self-test: pass"));
    assert!(stdout.contains("rfc6330-self-test.jsonl"));
    assert!(stdout.contains("rfc6330-self-test.summary.json"));
}

#[test]
fn runtime_sync_evidence_runner_lists_and_self_tests() {
    let script =
        std::fs::read_to_string(repo_path("scripts/run_runtime_sync_invariant_evidence.sh"))
            .expect("read runtime/sync evidence runner");
    let forbidden = ["bash", " -lc"].concat();
    assert!(
        !script.contains(&forbidden),
        "runtime/sync evidence runner should not execute scenario commands through a local shell"
    );
    assert!(
        script.contains(r#"bash "$0" --internal-oneshot-scan"#),
        "oneshot source scan should execute directly through the runner"
    );
    assert!(
        script.contains("run_local_command_capture()"),
        "local execution path should use fixed argv commands"
    );

    let list_output = Command::new("bash")
        .arg("scripts/run_runtime_sync_invariant_evidence.sh")
        .arg("--list")
        .current_dir(repo_path(""))
        .output()
        .expect("list runtime/sync evidence runner scenarios");

    assert!(
        list_output.status.success(),
        "runner --list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list_output.stdout),
        String::from_utf8_lossy(&list_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("RUNTIME-SCHEDULER-SHUTDOWN-BOUNDARY-LIVE"));
    assert!(stdout.contains("SYNC-RWLOCK-UPGRADE-CANCEL-LIVE"));
    assert!(stdout.contains("CHANNEL-ONESHOT-TRIPWIRE-SCAN-LIVE"));
    assert!(stdout.contains("aggregate_runner_bead=asupersync-oelvq2"));

    let artifact_root = repo_path("target/mock-code-finder/asupersync-a5d34a-contract-test")
        .join(std::process::id().to_string());
    let self_test_output = Command::new("bash")
        .arg("scripts/run_runtime_sync_invariant_evidence.sh")
        .arg("--self-test")
        .arg("--artifact-root")
        .arg(&artifact_root)
        .current_dir(repo_path(""))
        .output()
        .expect("run runtime/sync evidence runner self-test");

    assert!(
        self_test_output.status.success(),
        "runner --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test_output.stdout),
        String::from_utf8_lossy(&self_test_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&self_test_output.stdout);
    assert!(stdout.contains("runtime/sync evidence runner self-test: pass"));
    assert!(stdout.contains("runtime-sync-self-test.jsonl"));
    assert!(stdout.contains("runtime-sync-self-test.summary.json"));
}

#[test]
fn observability_evidence_runner_lists_and_self_tests() {
    let script = std::fs::read_to_string(repo_path("scripts/run_observability_evidence.sh"))
        .expect("read observability evidence runner");
    let forbidden = ["bash", " -lc"].concat();
    assert!(
        !script.contains(&forbidden),
        "observability evidence runner should not execute scenario commands through a local shell"
    );
    assert!(
        script.contains(r#"timeout "$RCH_WRAPPER_TIMEOUT" "$RCH_BIN" exec -- env"#),
        "rch execution path should use direct argv env commands"
    );
    assert!(
        script.contains("run_local_command_capture()"),
        "local execution path should use fixed argv commands"
    );

    let list_output = Command::new("bash")
        .arg("scripts/run_observability_evidence.sh")
        .arg("--list")
        .current_dir(repo_path(""))
        .output()
        .expect("list observability evidence runner scenarios");

    assert!(
        list_output.status.success(),
        "runner --list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list_output.stdout),
        String::from_utf8_lossy(&list_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("OTEL-HISTOGRAM-AGGREGATOR-LIVE"));
    assert!(stdout.contains("OTEL-TRACE-CONTEXT-PROPAGATION-LIVE"));
    assert!(stdout.contains("OTEL-EVIDENCE-REDACTION-SELF-TEST-LIVE"));
    assert!(stdout.contains("aggregate_runner_bead=asupersync-oelvq2"));

    let artifact_root = repo_path("target/mock-code-finder/asupersync-uw9zg9-contract-test")
        .join(std::process::id().to_string());
    let self_test_output = Command::new("bash")
        .arg("scripts/run_observability_evidence.sh")
        .arg("--self-test")
        .arg("--artifact-root")
        .arg(&artifact_root)
        .current_dir(repo_path(""))
        .output()
        .expect("run observability evidence runner self-test");

    assert!(
        self_test_output.status.success(),
        "runner --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test_output.stdout),
        String::from_utf8_lossy(&self_test_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&self_test_output.stdout);
    assert!(stdout.contains("observability evidence runner self-test: pass"));
    assert!(stdout.contains("observability-self-test.jsonl"));
    assert!(stdout.contains("observability-self-test.summary.json"));
}

#[test]
fn h2_conformance_evidence_runner_lists_and_self_tests() {
    let list_output = Command::new("bash")
        .arg("scripts/run_h2_conformance_evidence.sh")
        .arg("--list")
        .current_dir(repo_path(""))
        .output()
        .expect("list HTTP/2 conformance evidence runner scenarios");

    assert!(
        list_output.status.success(),
        "runner --list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list_output.stdout),
        String::from_utf8_lossy(&list_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    for scenario in [
        "H2-LIVE-ADAPTER-INTEGRATION-LIVE",
        "H2-GOAWAY-STATE-MACHINE-LIVE",
        "H2-PING-ACK-LIVE",
        "H2-DATA-END-STREAM-LIVE",
        "H2-PRIORITY-STATE-LIVE",
        "H2-ENABLE-PUSH-LIVE",
        "H2-SIMULATE-HELPER-SCAN-LIVE",
    ] {
        assert!(
            stdout.contains(scenario),
            "runner --list should include {scenario}"
        );
    }
    assert!(stdout.contains("aggregate_runner_bead=asupersync-oelvq2"));
    assert!(stdout.contains("aggregate_child_bead=asupersync-hxi1ga"));

    let artifact_root = repo_path("target/mock-code-finder/asupersync-hxi1ga-contract-test")
        .join(std::process::id().to_string());
    let self_test_output = Command::new("bash")
        .arg("scripts/run_h2_conformance_evidence.sh")
        .arg("--self-test")
        .arg("--artifact-root")
        .arg(&artifact_root)
        .current_dir(repo_path(""))
        .output()
        .expect("run HTTP/2 conformance evidence runner self-test");

    assert!(
        self_test_output.status.success(),
        "runner --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test_output.stdout),
        String::from_utf8_lossy(&self_test_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&self_test_output.stdout);
    assert!(stdout.contains("HTTP/2 conformance evidence runner self-test: pass"));
    assert!(stdout.contains("h2-conformance-self-test.jsonl"));
    assert!(stdout.contains("h2-conformance-self-test.summary.json"));
}
