#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn json_file(path: &str) -> Value {
    let text = fs::read_to_string(repo_path(path)).expect("read json artifact");
    serde_json::from_str(&text).expect("parse json artifact")
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {key}"))
}

fn run_ok(mut command: Command, label: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("run {label}: {error}");
    });
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_fail(mut command: Command, label: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("run {label}: {error}");
    });
    assert!(
        !output.status.success(),
        "{label} unexpectedly passed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn fixture_record(verdict: &str, quality: &str, support: &str) -> Value {
    serde_json::json!({
        "schema_version": "mock-code-finder-evidence-jsonl-schema-v1",
        "bead_id": "asupersync-fixture",
        "scenario_id": format!("fixture-{verdict}"),
        "subsystem": "fixture",
        "support_class": support,
        "source_files_inspected": ["fixture.sh"],
        "command": "fixture child",
        "rch_command_if_used": "",
        "cargo_features": [],
        "test_filter": format!("fixture-{verdict}"),
        "env_keys_required": ["ARTIFACT_ROOT"],
        "deterministic_seed_or_fixture_id": "fixture-seed",
        "input_artifact": "fixture.sh",
        "output_artifact": "fixture.log",
        "expected_behavior": format!("fixture emits {verdict}"),
        "actual_behavior": format!("fixture emitted {verdict} with deterministic log context"),
        "verdict": verdict,
        "first_failure_line": if matches!(verdict, "fail" | "blocked") { "fixture:1" } else { "" },
        "duration_ms": 0,
        "git_sha_or_tree_state": "fixture",
        "blocker_bead_id": if verdict == "blocked" { "asupersync-fixture-blocker" } else { "" },
        "evidence_quality": quality,
    })
}

fn write_child_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(format!("{name}.sh"));
    let mut file = fs::File::create(&path).expect("create fixture script");
    writeln!(file, "#!/usr/bin/env bash").unwrap();
    writeln!(file, "set -euo pipefail").unwrap();
    write!(file, "{body}").unwrap();
    drop(file);
    let mut permissions = fs::metadata(&path).expect("script metadata").permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&path, permissions).expect("set script executable");
    path
}

fn write_record_child(dir: &Path, name: &str, record: &Value, exit_code: i32) -> PathBuf {
    let record = serde_json::to_string(record).expect("serialize fixture record");
    write_child_script(
        dir,
        name,
        &format!(
            "mkdir -p \"$ARTIFACT_ROOT\"\n\
             echo '{name} log' > \"$ARTIFACT_ROOT/{name}.log\"\n\
             printf '%s\\n' '{record}' > \"$ARTIFACT_ROOT/{name}.jsonl\"\n\
             exit {exit_code}\n"
        ),
    )
}

fn write_config(path: &Path, children: Vec<(&str, &str, PathBuf)>) {
    let rows: Vec<Value> = children
        .into_iter()
        .map(|(bead, subsystem, command)| {
            serde_json::json!({
                "child_bead_id": bead,
                "subsystem": subsystem,
                "command": ["bash", command],
            })
        })
        .collect();
    fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::json!({ "children": rows })).unwrap(),
    )
    .expect("write fixture config");
}

#[test]
fn aggregate_contract_declares_children_and_failure_rules() {
    let contract = json_file("artifacts/mock_code_finder_aggregate_contract_v1.json");
    assert_eq!(
        str_field(&contract, "contract_version"),
        "mock-code-finder-aggregate-contract-v1"
    );
    assert_eq!(str_field(&contract, "bead_id"), "asupersync-oelvq2");
    assert_eq!(
        str_field(&contract, "shared_record_schema"),
        "mock-code-finder-evidence-jsonl-schema-v1"
    );

    let child_ids: BTreeSet<_> = array(&contract, "default_child_runners")
        .iter()
        .map(|child| str_field(child, "child_bead_id"))
        .collect();
    assert_eq!(
        child_ids,
        BTreeSet::from([
            "asupersync-a45",
            "asupersync-a5d34a",
            "asupersync-hxi1ga",
            "asupersync-kokw3m",
            "asupersync-uw9zg9",
            "asupersync-zftrj9",
        ])
    );
    for field in [
        "run_id",
        "git_sha_or_tree_state",
        "started_at",
        "finished_at",
        "child_bead_id",
        "scenario_count",
        "final_verdict",
    ] {
        assert!(
            array(&contract, "required_aggregate_fields")
                .iter()
                .any(|value| value.as_str() == Some(field)),
            "aggregate contract should require {field}"
        );
    }
}

#[test]
fn aggregate_runner_lists_and_dry_runs_default_children() {
    let output = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--list")
                .arg("--mode")
                .arg("rch")
                .arg("--run-id")
                .arg("list-contract")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner --list",
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("parse list payload");
    assert_eq!(
        str_field(&payload, "schema_version"),
        "mock-code-finder-aggregate-plan-v1"
    );
    assert_eq!(str_field(&payload, "mode"), "rch");
    assert_eq!(array(&payload, "children").len(), 6);
    let commands: Vec<String> = array(&payload, "children")
        .iter()
        .map(|child| child["command"].to_string())
        .collect();
    assert!(
        commands
            .iter()
            .any(|text| text.contains("run_no_mock_policy_evidence.sh")),
        "list output should include the no-mock policy runner"
    );

    let dry_run = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--dry-run")
                .arg("--ci")
                .arg("--run-id")
                .arg("ci-contract")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner --dry-run",
    );
    let payload: Value = serde_json::from_slice(&dry_run.stdout).expect("parse dry-run payload");
    assert_eq!(str_field(&payload, "mode"), "ci");
}

#[test]
fn aggregate_runner_self_test_passes() {
    let output = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--self-test")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner self-test",
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("mock-code-finder aggregate self-test: pass")
    );
}

#[test]
fn aggregate_runner_aggregates_fixture_children_and_preserves_logs() {
    let root = repo_path("target/mock-code-finder/asupersync-oelvq2-contract-test")
        .join(std::process::id().to_string())
        .join("fixture-pass");
    let scripts = root.join("scripts");
    fs::create_dir_all(&scripts).expect("create fixture script dir");

    let pass = write_record_child(
        &scripts,
        "pass",
        &fixture_record("pass", "live", "production_live"),
        0,
    );
    let blocked = write_record_child(
        &scripts,
        "blocked",
        &fixture_record("blocked", "blocked", "blocked_external"),
        0,
    );
    let unsupported = write_record_child(
        &scripts,
        "unsupported",
        &fixture_record("unsupported", "unsupported", "explicitly_unsupported"),
        0,
    );
    let expected = write_record_child(
        &scripts,
        "expected",
        &fixture_record("expected_fail", "expected_fail", "production_live"),
        0,
    );
    let fixture = write_record_child(
        &scripts,
        "fixture",
        &fixture_record("fixture_only", "fixture_only", "fixture_reference"),
        0,
    );
    let config = root.join("config.json");
    write_config(
        &config,
        vec![
            ("asupersync-fixture-pass", "fixture-pass", pass),
            ("asupersync-fixture-blocked", "fixture-blocked", blocked),
            (
                "asupersync-fixture-unsupported",
                "fixture-unsupported",
                unsupported,
            ),
            ("asupersync-fixture-expected", "fixture-expected", expected),
            ("asupersync-fixture-only", "fixture-only", fixture),
        ],
    );

    let artifact_root = root.join("artifacts");
    let output = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--config-json")
                .arg(&config)
                .arg("--artifact-root")
                .arg(&artifact_root)
                .arg("--run-id")
                .arg("fixture-pass")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner fixture pass",
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("aggregate run: pass"));

    let aggregate_path = artifact_root
        .join("fixture-pass")
        .join("mock-code-finder-aggregate.json");
    let aggregate: Value =
        serde_json::from_str(&fs::read_to_string(&aggregate_path).expect("read aggregate json"))
            .expect("parse aggregate json");
    assert_eq!(str_field(&aggregate, "final_verdict"), "pass");
    assert_eq!(aggregate["scenario_count"], Value::from(5));
    assert_eq!(aggregate["verdict_counts"]["pass"], Value::from(1));
    assert_eq!(aggregate["verdict_counts"]["blocked"], Value::from(1));
    assert_eq!(aggregate["verdict_counts"]["unsupported"], Value::from(1));
    assert_eq!(aggregate["verdict_counts"]["expected_fail"], Value::from(1));
    assert_eq!(aggregate["verdict_counts"]["fixture_only"], Value::from(1));

    for child in array(&aggregate, "children") {
        let stdout = str_field(child, "stdout_log");
        let stderr = str_field(child, "stderr_log");
        assert!(
            Path::new(stdout).exists(),
            "child stdout log should exist: {stdout}"
        );
        assert!(
            Path::new(stderr).exists(),
            "child stderr log should exist: {stderr}"
        );
        assert!(
            !array(child, "jsonl_artifacts").is_empty(),
            "child JSONL artifacts should be preserved: {child:?}"
        );
    }
}

#[test]
fn aggregate_runner_rejects_malformed_zero_missing_quality_and_missing_context() {
    let root = repo_path("target/mock-code-finder/asupersync-oelvq2-contract-test")
        .join(std::process::id().to_string())
        .join("fixture-fail");
    let scripts = root.join("scripts");
    fs::create_dir_all(&scripts).expect("create fixture script dir");

    let malformed = write_child_script(
        &scripts,
        "malformed",
        "mkdir -p \"$ARTIFACT_ROOT\"\nprintf '%s\\n' '{not-json' > \"$ARTIFACT_ROOT/malformed.jsonl\"\n",
    );
    let zero = write_child_script(
        &scripts,
        "zero",
        "mkdir -p \"$ARTIFACT_ROOT\"\n: > \"$ARTIFACT_ROOT/zero.jsonl\"\n",
    );
    let mut missing_quality_record = fixture_record("pass", "live", "production_live");
    missing_quality_record
        .as_object_mut()
        .expect("fixture record object")
        .remove("evidence_quality");
    let missing_quality =
        write_record_child(&scripts, "missing-quality", &missing_quality_record, 0);
    let mut missing_context_record = fixture_record("blocked", "blocked", "blocked_external");
    {
        let object = missing_context_record
            .as_object_mut()
            .expect("fixture record object");
        object.insert("blocker_bead_id".to_string(), Value::from(""));
        object.insert("first_failure_line".to_string(), Value::from(""));
        object.insert("actual_behavior".to_string(), Value::from(""));
    }
    let missing_context =
        write_record_child(&scripts, "missing-context", &missing_context_record, 0);

    for (name, script, expected) in [
        ("malformed", malformed, "malformed JSONL"),
        ("zero", zero, "zero scenario records"),
        (
            "missing-quality",
            missing_quality,
            "missing evidence_quality",
        ),
        ("missing-context", missing_context, "lacks blocker/context"),
    ] {
        let config = root.join(format!("{name}.json"));
        write_config(&config, vec![("asupersync-fixture-bad", name, script)]);
        let output = run_fail(
            {
                let mut command = Command::new("python3");
                command
                    .arg("scripts/run_mock_code_finder_evidence.py")
                    .arg("--config-json")
                    .arg(&config)
                    .arg("--artifact-root")
                    .arg(root.join(format!("artifacts-{name}")))
                    .arg("--run-id")
                    .arg(name)
                    .current_dir(repo_path(""));
                command
            },
            name,
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains(expected),
            "{name} output should mention {expected}\n{combined}"
        );
    }
}
