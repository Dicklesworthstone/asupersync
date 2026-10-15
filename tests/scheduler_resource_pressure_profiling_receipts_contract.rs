#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ARTIFACT_PATH: &str = "artifacts/scheduler_resource_pressure_profiling_receipts_v1.json";
const DOC_PATH: &str = "docs/scheduler_resource_pressure_profiling_receipts.md";
const E2E_SCRIPT_PATH: &str = "scripts/run_scheduler_resource_pressure_profiling_receipts_e2e.sh";
const FIXTURE_ROOT: &str = "tests/fixtures/scheduler_resource_pressure_profiling_receipts";
const GENERATED_AT: &str = "2026-06-06T02:45:00Z";
const SCRIPT_PATH: &str = "scripts/scheduler_resource_pressure_profiling_receipts.py";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&read_text(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn artifact() -> Value {
    read_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_member(value: &serde_json::Map<String, Value>, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn run_helper_with_fixture(fixture: &Path, output: &str) -> Output {
    Command::new("python3")
        .current_dir(repo_root())
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(fixture)
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output)
        .output()
        .expect("run profiling receipt helper")
}

fn run_helper_json(relative_fixture: &str) -> Value {
    let output = run_helper_with_fixture(&repo_path(relative_fixture), "json");
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("helper stdout must be JSON")
}

fn assert_hash(value: &str, field: &str) {
    assert!(
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64,
        "{field} must be sha256:<64 lowercase hex>, got {value}"
    );
    assert!(
        value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "{field} must use lowercase hex"
    );
}

#[test]
fn artifact_declares_schema_sources_and_scenario_catalog() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("scheduler-resource-pressure-profiling-receipts-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some("asupersync-94pz70")
    );

    for path in object(&artifact, "source_of_truth").values() {
        let path = path.as_str().expect("source path string");
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let expected = [
        "scheduler-spawn-storm",
        "obligation-cleanup-drain",
        "proof-lane-report-generation",
        "dirty-tree-correlation",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    let actual = array(&artifact, "scenario_catalog")
        .iter()
        .map(|row| string(row, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(string_set(&artifact, "required_scenario_ids"), expected);
}

#[test]
fn scenario_receipts_have_rch_commands_hot_paths_and_memory_observations() {
    let artifact = artifact();
    for row in array(&artifact, "scenario_catalog") {
        let scenario_id = string(row, "scenario_id");
        for field in array(&artifact, "required_receipt_fields") {
            let field = field.as_str().expect("required field string");
            assert!(
                row.get(field).is_some(),
                "{scenario_id}: missing required field {field}"
            );
        }

        for field in ["command", "rch_refresh_command"] {
            let command = string(row, field);
            assert!(
                command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
                "{scenario_id}: {field} must be remote-required RCH"
            );
            assert!(
                command.contains("CARGO_TARGET_DIR="),
                "{scenario_id}: {field} must isolate CARGO_TARGET_DIR"
            );
        }

        assert_hash(string(row, "data_hash"), "data_hash");
        let environment = object(row, "environment");
        assert_eq!(
            environment.get("remote_required").and_then(Value::as_bool),
            Some(true),
            "{scenario_id}: remote_required"
        );
        assert_eq!(
            environment
                .get("local_fallback_allowed")
                .and_then(Value::as_bool),
            Some(false),
            "{scenario_id}: local_fallback_allowed"
        );

        let top_hot_paths = array(row, "top_hot_paths");
        assert!(
            !top_hot_paths.is_empty(),
            "{scenario_id}: hot path list must be nonempty"
        );
        for (index, hot_path) in top_hot_paths.iter().enumerate() {
            assert_eq!(
                hot_path.get("rank").and_then(Value::as_u64),
                Some((index + 1) as u64),
                "{scenario_id}: hot path ranks must be ordered"
            );
            let path = string(hot_path, "path");
            assert!(repo_path(path).exists(), "{scenario_id}: {path} missing");
            string(hot_path, "symbol");
            string(hot_path, "expected_pressure");
        }

        let observations = array(row, "memory_observations");
        assert!(
            observations.iter().any(|item| {
                item.get("metric").and_then(Value::as_str) == Some("refresh_memory_ceiling_mb")
                    && item.get("value").and_then(Value::as_u64).unwrap_or(0) > 0
            }),
            "{scenario_id}: memory observations need refresh_memory_ceiling_mb"
        );

        let proof_boundary = object(row, "proof_boundary");
        assert_eq!(
            proof_boundary
                .get("fresh_benchmark")
                .and_then(Value::as_bool),
            Some(false),
            "{scenario_id}: contract must not claim fresh benchmark"
        );
        assert_eq!(
            proof_boundary
                .get("real_host_throughput_proof")
                .and_then(Value::as_bool),
            Some(false),
            "{scenario_id}: contract must not claim throughput proof"
        );

        for source_ref in array(row, "source_refs") {
            let source_ref = source_ref.as_str().expect("source ref string");
            assert!(
                repo_path(source_ref).exists(),
                "{scenario_id}: source ref missing: {source_ref}"
            );
        }
    }
}

#[test]
fn proof_boundary_and_docs_preserve_non_claims() {
    let artifact = artifact();
    let boundary = object(&artifact, "proof_boundary");
    assert!(!bool_member(
        boundary,
        "contract_receipts_are_fresh_benchmarks"
    ));
    assert!(!bool_member(boundary, "proves_real_host_throughput"));
    assert!(!bool_member(boundary, "proves_scheduler_regression_closed"));
    assert!(!bool_member(boundary, "local_cargo_fallback_allowed"));
    assert!(bool_member(boundary, "requires_rch_for_refresh_commands"));

    let docs = read_text(DOC_PATH);
    for marker in [
        "scheduler-resource-pressure-profiling-receipts-v1",
        "not a benchmark report",
        "Local Cargo fallback is not admissible",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=",
        "scheduler-spawn-storm",
        "obligation-cleanup-drain",
        "proof-lane-report-generation",
        "dirty-tree-correlation",
    ] {
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }
}

#[test]
fn helper_emits_stable_json_and_markdown_from_artifact() {
    let report = run_helper_json(ARTIFACT_PATH);
    assert_eq!(
        report.get("schema_version").and_then(Value::as_str),
        Some("scheduler-resource-pressure-profiling-receipts-report-v1")
    );
    assert_eq!(
        report.get("generated_at").and_then(Value::as_str),
        Some(GENERATED_AT)
    );
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["operator_summary"]["scenario_count"].as_u64(),
        Some(4)
    );
    assert_eq!(array(&report, "blockers").len(), 0);
    assert_hash(
        report
            .get("source_digest")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "source_digest",
    );

    let output = run_helper_with_fixture(&repo_path(ARTIFACT_PATH), "markdown");
    assert!(output.status.success(), "markdown helper should succeed");
    let markdown = String::from_utf8(output.stdout).expect("markdown utf8");
    assert!(markdown.contains("| scheduler-spawn-storm | scheduler_spawn_storm | pass |"));
    assert!(markdown.contains("## Refresh Commands"));
}

#[test]
fn helper_reports_missing_required_fields_without_mutating() {
    let report = run_helper_json(&format!("{FIXTURE_ROOT}/missing_required_field.json"));
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report["operator_summary"]["blocked_count"].as_u64(),
        Some(1)
    );
    let blocker_kinds = array(&report, "blockers")
        .iter()
        .map(|row| string(row, "kind").to_string())
        .collect::<BTreeSet<_>>();
    assert!(blocker_kinds.contains("missing-required-field"));
    assert!(blocker_kinds.contains("missing-hot-path"));

    for key in [
        "runs_cargo",
        "runs_rch",
        "runs_git_mutation",
        "runs_beads_mutation",
        "sends_agent_mail",
        "writes_cache",
        "deletes_files",
    ] {
        assert_eq!(
            report["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must remain false"
        );
    }
}

#[test]
fn e2e_script_writes_json_markdown_and_detailed_logs() {
    let tempdir = tempfile::tempdir().expect("temp output dir");
    let output = Command::new("bash")
        .current_dir(repo_root())
        .arg(repo_path(E2E_SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(ARTIFACT_PATH))
        .arg("--output-root")
        .arg(tempdir.path())
        .arg("--run-id")
        .arg("contract-test")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .output()
        .expect("run profiling e2e script");
    assert!(
        output.status.success(),
        "e2e failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_dir = tempdir.path().join("run_contract-test");
    let json_report = report_dir.join("run_report.json");
    let markdown_report = report_dir.join("run_report.md");
    let run_log = report_dir.join("run.log");
    assert!(json_report.is_file(), "JSON report missing");
    assert!(markdown_report.is_file(), "Markdown report missing");
    assert!(run_log.is_file(), "run log missing");

    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&json_report).expect("read JSON report"))
            .expect("parse JSON report");
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(true)
    );
    let markdown = std::fs::read_to_string(markdown_report).expect("read Markdown report");
    assert!(markdown.contains("These rows are deterministic contract receipts"));

    let log = std::fs::read_to_string(run_log).expect("read run log");
    assert!(log.contains("scenario_id=scheduler-spawn-storm"));
    assert!(log.contains("scenario_family=scheduler_spawn_storm"));
    assert!(log.contains("status=pass"));
    assert!(log.contains("first_failure="));
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout utf8")
            .contains("scenario_id=summary")
    );
}
