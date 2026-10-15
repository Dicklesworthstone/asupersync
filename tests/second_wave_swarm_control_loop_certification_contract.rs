#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/second_wave_swarm_control_loop_certification_v1.json";
const DOC_PATH: &str = "docs/second_wave_swarm_control_loop_certification.md";
const E2E_SCRIPT_PATH: &str = "scripts/run_second_wave_swarm_control_loop_certification_e2e.sh";
const GENERATED_AT: &str = "2026-06-06T11:15:00Z";
const README_PATH: &str = "README.md";
const REQUIRED_RCH_PREFIX: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- ";
const SCRIPT_PATH: &str = "scripts/second_wave_swarm_control_loop_certification.py";
const TEST_PATH: &str = "tests/second_wave_swarm_control_loop_certification_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn run_helper(output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--repo-root")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output_format)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run second-wave certification helper")
}

fn report_json() -> Value {
    let output = run_helper("json");
    assert_success("helper json", &output);
    serde_json::from_slice(&output.stdout).expect("helper JSON output")
}

fn markdown_report() -> String {
    let output = run_helper("markdown");
    assert_success("helper markdown", &output);
    String::from_utf8(output.stdout).expect("markdown is utf-8")
}

fn assert_success(name: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{name} failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
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

fn rows_by_child(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "child_bead_id").to_string(), row.clone()))
        .collect()
}

fn rejected_by_id(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rejected_rows")
        .iter()
        .map(|row| (string(row, "evidence_id").to_string(), row.clone()))
        .collect()
}

fn fixture(contract: &Value) -> &Value {
    object(contract, "fixture")
}

#[test]
fn helper_and_e2e_sources_remain_bounded_and_read_only() {
    assert!(repo_path(SCRIPT_PATH).exists(), "{SCRIPT_PATH} must exist");
    assert!(
        repo_path(E2E_SCRIPT_PATH).exists(),
        "{E2E_SCRIPT_PATH} must exist"
    );

    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--help")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run helper --help");
    assert_success("helper help", &output);

    let helper = read_repo_file(SCRIPT_PATH);
    for forbidden in [
        "subprocess",
        "os.system",
        "git add",
        "git commit",
        "git push",
        "cargo test",
        "cargo check",
        "br update",
        "br close",
        "bv ",
        "send_message",
        "file_reservation_paths",
        "write_text",
        "Path.write",
        "open(\"w\"",
    ] {
        assert!(
            !helper.contains(forbidden),
            "read-only helper must not contain forbidden token {forbidden}"
        );
    }

    let e2e = read_repo_file(E2E_SCRIPT_PATH);
    for forbidden in [
        "git add",
        "git commit",
        "git push",
        "git branch",
        "git worktree",
        "cargo test",
        "cargo check",
        "br update",
        "br close",
    ] {
        assert!(
            !e2e.contains(forbidden),
            "bounded E2E runner must not contain forbidden token {forbidden}"
        );
    }
}

#[test]
fn contract_fixture_emits_expected_certification_summary() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(fixture(&contract), "expected_summary");
    let report = report_json();
    let summary = object(&report, "summary");

    assert_eq!(
        string(&report, "schema_version"),
        "second-wave-swarm-control-loop-certification-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "second-wave-swarm-control-loop-certification-contract-fixture"
    );
    assert_eq!(
        string(&report, "bundle_id"),
        "asupersync-ol11aa.8-second-wave-certification"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);

    for key in [
        "required_children",
        "accepted_rows",
        "rejected_rows",
        "missing_required_children",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    for key in [
        "operator_workflow_certified",
        "parent_epic_close_allowed",
        "release_ready",
        "broad_workspace_health",
        "performance_benchmark",
    ] {
        assert_eq!(bool_field(summary, key), bool_field(expected, key), "{key}");
    }
    assert_eq!(
        string(summary, "certification_verdict"),
        string(expected, "certification_verdict")
    );
    assert_eq!(
        array(&report, "missing_required_children").len(),
        0,
        "all required children should be represented by accepted rows"
    );
}

#[test]
fn every_required_child_has_current_remote_nonzero_evidence() {
    let contract = json_file(CONTRACT_PATH);
    let required = string_set(fixture(&contract), "required_child_beads");
    let report = report_json();
    let rows = rows_by_child(&report);

    assert_eq!(
        rows.keys().cloned().collect::<BTreeSet<_>>(),
        required,
        "certification rows must exactly cover required child beads"
    );

    for (child, row) in &rows {
        assert!(bool_field(row, "accepted"), "{child} should be accepted");
        assert_eq!(string(row, "classification"), "green", "{child}");
        assert!(
            array(row, "reason_codes").is_empty(),
            "{child} must have no rejection reasons"
        );
        assert!(
            string(row, "rerun_command").starts_with(REQUIRED_RCH_PREFIX),
            "{child} command must require remote RCH"
        );
        assert!(
            string(row, "rerun_command").contains("CARGO_TARGET_DIR="),
            "{child} command must isolate CARGO_TARGET_DIR"
        );
        assert!(
            !bool_field(row, "local_fallback_observed"),
            "{child} must reject local fallback"
        );
        assert!(!bool_field(row, "advisory_only"), "{child}");
        assert!(
            u64_field(row, "executed_tests") > 0,
            "{child} must report nonzero test evidence"
        );
        assert_eq!(
            string(row, "artifact_head"),
            string(row, "source_head"),
            "{child} must use a current receipt head"
        );
        assert!(
            array(row, "missing_paths").is_empty(),
            "{child} must reference existing source paths"
        );
        let envelope = object(row, "command_envelope");
        assert!(bool_field(envelope, "remote_required"), "{child}");
        assert!(!bool_field(envelope, "local_fallback_allowed"), "{child}");
        assert!(bool_field(envelope, "target_dir_isolated"), "{child}");
        assert!(u64_field(envelope, "timeout_seconds") > 0, "{child}");
        assert!(u64_field(envelope, "memory_mb") > 0, "{child}");
    }
}

#[test]
fn rejection_fixtures_fail_closed_for_required_cases() {
    let report = report_json();
    let rejected = rejected_by_id(&report);
    let expected = [
        ("reject-stale-head", "stale-head"),
        ("reject-local-fallback", "local-fallback"),
        ("reject-zero-test", "zero-test"),
        ("reject-advisory-only", "advisory-only"),
        ("reject-missing-rch-envelope", "missing-rch-envelope"),
        ("reject-missing-artifact", "missing-artifact"),
    ];

    assert_eq!(
        rejected.len(),
        expected.len(),
        "all fail-closed fixtures should be emitted"
    );
    for (fixture_id, reason) in expected {
        let row = rejected
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing rejection fixture {fixture_id}"));
        assert!(!bool_field(row, "accepted"), "{fixture_id}");
        assert_eq!(string(row, "classification"), "red", "{fixture_id}");
        assert!(
            string_set(row, "reason_codes").contains(reason),
            "{fixture_id} should reject for {reason}: {:?}",
            array(row, "reason_codes")
        );
    }
}

#[test]
fn markdown_report_has_green_yellow_red_and_exact_commands() {
    let markdown = markdown_report();
    for marker in [
        "# Second-Wave Swarm Control-Loop Certification",
        "## Green",
        "## Yellow",
        "## Red",
        "## Exact Rerun Commands",
        "operator_workflow_certified: `true`",
        "parent_epic_close_allowed: `false`",
        "not a release publish proof",
        "not a substitute for broad check/clippy/test gates",
        REQUIRED_RCH_PREFIX,
        "asupersync-ol11aa.7",
    ] {
        assert!(markdown.contains(marker), "markdown missing {marker}");
    }
}

#[test]
fn bounded_e2e_runner_emits_reports_and_line_log() {
    let output = Command::new("bash")
        .arg(repo_path(E2E_SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--output-root")
        .arg(repo_path(
            "target/second-wave-swarm-control-loop-certification",
        ))
        .arg("--run-id")
        .arg("contract")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run second-wave certification e2e");
    assert_success("second-wave certification e2e", &output);

    let summary_path = String::from_utf8(output.stdout)
        .expect("summary path utf8")
        .trim()
        .to_string();
    let summary_text = std::fs::read_to_string(&summary_path).expect("read E2E summary JSON path");
    let summary: Value = serde_json::from_str(&summary_text).expect("parse E2E summary");
    assert_eq!(
        string(&summary, "schema_version"),
        "second-wave-swarm-control-loop-certification-e2e-summary-v1"
    );
    assert!(bool_field(&summary, "dry_run_only"));
    assert!(bool_field(&summary, "non_mutating"));
    assert!(!bool_field(&summary, "runs_proof_commands"));
    assert!(bool_field(&summary, "operator_workflow_certified"));
    assert!(!bool_field(&summary, "parent_epic_close_allowed"));
    assert_eq!(u64_field(&summary, "accepted_rows"), 7);
    assert_eq!(u64_field(&summary, "rejected_rows"), 6);

    for key in ["json_report", "markdown_report", "log_path"] {
        let path = string(&summary, key);
        assert!(Path::new(path).exists(), "{key} should exist at {path}");
    }
    let log = std::fs::read_to_string(string(&summary, "log_path")).expect("read E2E log");
    assert!(log.contains("verdict=pass"));
    assert!(log.contains("green=7"));
    assert!(log.contains("red=6"));
    assert!(log.contains("child=asupersync-ol11aa.1 classification=green"));
    assert!(log.contains("fixture=reject-missing-rch-envelope classification=red"));
}

#[test]
fn docs_readme_and_contract_markers_stay_aligned() {
    let docs = read_repo_file(DOC_PATH);
    let readme = read_repo_file(README_PATH);
    let contract = read_repo_file(CONTRACT_PATH);
    let self_test = read_repo_file(TEST_PATH);

    for marker in [
        "artifacts/second_wave_swarm_control_loop_certification_v1.json",
        "scripts/second_wave_swarm_control_loop_certification.py",
        "scripts/run_second_wave_swarm_control_loop_certification_e2e.sh",
        "tests/second_wave_swarm_control_loop_certification_contract.rs",
        "not a performance benchmark",
        "not a release publish proof",
        "not a substitute for broad check/clippy/test gates",
        REQUIRED_RCH_PREFIX,
    ] {
        assert!(docs.contains(marker), "docs missing {marker}");
        assert!(readme.contains(marker), "README missing {marker}");
        assert!(contract.contains(marker), "contract missing {marker}");
        assert!(self_test.contains(marker), "test missing {marker}");
    }
}
