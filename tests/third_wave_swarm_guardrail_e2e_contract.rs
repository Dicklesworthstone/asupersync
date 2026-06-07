#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json";
const DOC_PATH: &str = "docs/third_wave_swarm_guardrail_e2e.md";
const E2E_SCRIPT_PATH: &str = "scripts/run_third_wave_swarm_guardrail_e2e.sh";
const GENERATED_AT: &str = "2026-06-06T17:20:00Z";
const README_PATH: &str = "README.md";
const SCRIPT_PATH: &str = "scripts/third_wave_swarm_guardrail_e2e.py";
const TEST_PATH: &str = "tests/third_wave_swarm_guardrail_e2e_contract.rs";

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
        .expect("run third-wave guardrail e2e helper")
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

fn fixture(contract: &Value) -> &Value {
    object(contract, "fixture")
}

fn components_by_id(report: &Value) -> BTreeMap<String, Value> {
    array(report, "components")
        .iter()
        .map(|component| (string(component, "id").to_string(), component.clone()))
        .collect()
}

#[test]
fn helper_and_e2e_sources_remain_bounded_and_non_mutating() {
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
    assert!(
        helper.contains("subprocess.run"),
        "aggregate e2e helper should invoke child helpers through subprocess.run"
    );
    for forbidden in [
        "os.system",
        "git add",
        "git commit",
        "git push",
        "git branch",
        "git worktree",
        "cargo test",
        "cargo check",
        "cargo clippy",
        "br update",
        "br close",
        "send_message",
        "file_reservation_paths",
        "requests.",
        "socket.",
        "write_text",
        "Path.write",
        "open(\"w\"",
        "open('w'",
    ] {
        assert!(
            !helper.contains(forbidden),
            "aggregate helper must not contain forbidden token {forbidden}"
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
fn contract_fixture_emits_expected_guardrail_summary() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(&contract, "expected_summary");
    let report = report_json();
    let summary = object(&report, "summary");

    assert_eq!(
        string(&report, "schema_version"),
        "third-wave-swarm-guardrail-e2e-report-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "third-wave-swarm-guardrail-e2e-contract-fixture"
    );
    assert_eq!(
        string(&report, "bundle_id"),
        "asupersync-ol11aa.9.6-third-wave-guardrail-e2e"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);

    for key in [
        "component_count",
        "passed_components",
        "failed_components",
        "child_scenario_count",
        "required_classification_count",
        "required_marker_count",
        "mutation_command_count",
        "proof_command_count",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    for key in [
        "dry_run_only",
        "non_mutating",
        "invokes_child_helpers",
        "uses_live_external_services",
        "runs_proof_commands",
    ] {
        assert_eq!(bool_field(summary, key), bool_field(expected, key), "{key}");
    }
    assert_eq!(
        string(summary, "guardrail_verdict"),
        string(expected, "guardrail_verdict")
    );
}

#[test]
fn every_component_passes_with_required_classifications_and_markers() {
    let contract = json_file(CONTRACT_PATH);
    let report = report_json();
    let actual = components_by_id(&report);
    let expected_ids = array(fixture(&contract), "components")
        .iter()
        .map(|component| string(component, "id").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual.keys().cloned().collect::<BTreeSet<_>>(),
        expected_ids,
        "component coverage should match fixture"
    );

    for (id, component) in actual {
        assert_eq!(string(&component, "status"), "passed", "{id}");
        assert!(
            array(&component, "errors").is_empty(),
            "{id} should have no errors"
        );
        assert_eq!(
            string(&component, "child_schema_version"),
            string(&component, "expected_schema_version"),
            "{id} schema should match"
        );
        assert!(u64_field(&component, "child_row_count") > 0, "{id}");

        for result in array(&component, "summary_results") {
            assert!(
                bool_field(result, "matched"),
                "{id} summary field {} should match",
                string(result, "field")
            );
        }
        for result in array(&component, "classification_results") {
            assert!(
                bool_field(result, "matched"),
                "{id} classification {} should match",
                string(result, "classification")
            );
            assert_eq!(u64_field(result, "expected_count"), 1, "{id}");
            assert_eq!(u64_field(result, "observed_count"), 1, "{id}");
            assert!(bool_field(result, "catalog_present"), "{id}");
        }
        for result in array(&component, "marker_results") {
            assert!(
                bool_field(result, "matched"),
                "{id} marker {} should match",
                string(result, "row_id")
            );
            assert!(
                array(result, "errors").is_empty(),
                "{id} marker should have no errors"
            );
        }
    }
}

#[test]
fn markdown_report_names_components_and_scope_limits() {
    let markdown = markdown_report();
    for marker in [
        "# Third-Wave Swarm Guardrail E2E",
        "## Components",
        "## Guardrails",
        "## Non-Claims",
        "guardrail_verdict: `pass`",
        "stale-in-progress-reaper",
        "tracker-graph-drift",
        "reservation-lease-watchdog",
        "swarm-lane-closeout",
        "rch-quiet-phase",
        "not a broad workspace health proof",
        "not a release publish proof",
        "not a substitute for broad check/clippy/test gates",
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
        .arg(repo_path("target/third-wave-swarm-guardrail-e2e"))
        .arg("--run-id")
        .arg("contract")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run third-wave guardrail e2e");
    assert_success("third-wave guardrail e2e", &output);

    let summary_path = String::from_utf8(output.stdout)
        .expect("summary path utf8")
        .trim()
        .to_string();
    let summary_text = std::fs::read_to_string(&summary_path).expect("read E2E summary JSON path");
    let summary: Value = serde_json::from_str(&summary_text).expect("parse E2E summary");
    assert_eq!(
        string(&summary, "schema_version"),
        "third-wave-swarm-guardrail-e2e-summary-v1"
    );
    assert!(bool_field(&summary, "dry_run_only"));
    assert!(bool_field(&summary, "non_mutating"));
    assert!(bool_field(&summary, "invokes_child_helpers"));
    assert!(!bool_field(&summary, "uses_live_external_services"));
    assert!(!bool_field(&summary, "runs_proof_commands"));
    assert_eq!(string(&summary, "guardrail_verdict"), "pass");
    assert_eq!(u64_field(&summary, "component_count"), 5);
    assert_eq!(u64_field(&summary, "passed_components"), 5);
    assert_eq!(u64_field(&summary, "failed_components"), 0);
    assert_eq!(u64_field(&summary, "child_scenario_count"), 35);
    assert_eq!(u64_field(&summary, "required_classification_count"), 35);
    assert_eq!(u64_field(&summary, "required_marker_count"), 15);

    for key in ["json_report", "markdown_report", "log_path"] {
        let path = string(&summary, key);
        assert!(Path::new(path).exists(), "{key} should exist at {path}");
    }
    let log = std::fs::read_to_string(string(&summary, "log_path")).expect("read E2E log");
    assert!(log.contains("verdict=pass"));
    assert!(log.contains("components=5"));
    assert!(log.contains("passed=5"));
    assert!(log.contains("component=stale-in-progress-reaper status=passed"));
    assert!(log.contains("component=rch-quiet-phase status=passed"));
}

#[test]
fn docs_readme_and_contract_markers_stay_aligned() {
    let docs = read_repo_file(DOC_PATH);
    let readme = read_repo_file(README_PATH);
    let contract = read_repo_file(CONTRACT_PATH);
    let self_test = read_repo_file(TEST_PATH);

    for marker in [
        "artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json",
        "scripts/third_wave_swarm_guardrail_e2e.py",
        "scripts/run_third_wave_swarm_guardrail_e2e.sh",
        "tests/third_wave_swarm_guardrail_e2e_contract.rs",
        "docs/third_wave_swarm_guardrail_e2e.md",
        "invokes child helpers",
        "not a broad workspace health proof",
        "not a release publish proof",
        "not a substitute for broad check/clippy/test gates",
    ] {
        assert!(docs.contains(marker), "docs missing {marker}");
        assert!(readme.contains(marker), "README missing {marker}");
        assert!(contract.contains(marker), "contract missing {marker}");
        assert!(self_test.contains(marker), "test missing {marker}");
    }
}

#[test]
fn combined_classification_counts_cover_all_child_guardrails() {
    let report = report_json();
    let combined = object(&report, "combined_classification_counts");
    for classification in [
        "stale-reopen-candidate",
        "br-ready-bv-empty-divergence",
        "sufficient-ttl",
        "admissible-closeout",
        "remote-success-with-quiet-progress",
    ] {
        assert_eq!(
            combined.get(classification).and_then(Value::as_u64),
            Some(1),
            "{classification} should appear exactly once"
        );
    }
}
