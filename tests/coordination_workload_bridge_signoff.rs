#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const ARTIFACT_PATH: &str = "artifacts/coordination_workload_bridge_signoff_v1.json";
const DOC_PATH: &str = "docs/coordination_workload_bridge_signoff.md";
const SCRIPT_PATH: &str = "scripts/run_coordination_workload_bridge_signoff.sh";
const GENERATED_AT: &str = "2026-05-05T05:00:00Z";
static EXECUTE_REPORT: OnceLock<Value> = OnceLock::new();

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn unique_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "asupersync-coordination-signoff-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn load_json(relative: &str) -> Value {
    let raw = fs::read_to_string(repo_path(relative)).expect("read json artifact");
    serde_json::from_str(&raw).expect("parse json artifact")
}

fn load_path_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path).expect("read json file");
    serde_json::from_str(&raw).expect("parse json file")
}

fn run_signoff(args: &[String]) -> Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run coordination bridge signoff script")
}

fn run_signoff_static(args: &[&str]) -> Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run coordination bridge signoff script")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report_path(root: &Path, run_id: &str) -> PathBuf {
    root.join(run_id)
        .join("coordination-workload-bridge-signoff-report.json")
}

fn execute_fixture(root: &Path, run_id: &str) -> Value {
    let output = run_signoff(&[
        "--execute".to_string(),
        "--fixture".to_string(),
        "--output-root".to_string(),
        root.to_string_lossy().into_owned(),
        "--run-id".to_string(),
        run_id.to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
    ]);
    assert_success(&output, "execute fixture");
    load_path_json(&report_path(root, run_id))
}

fn shared_execute_report() -> &'static Value {
    EXECUTE_REPORT.get_or_init(|| execute_fixture(&unique_root("shared-execute"), "shared-execute"))
}

fn rows_by_id(report: &Value) -> BTreeMap<String, Value> {
    report["rows"]
        .as_array()
        .expect("rows must be array")
        .iter()
        .map(|row| {
            (
                row["row_id"].as_str().expect("row id").to_string(),
                row.clone(),
            )
        })
        .collect()
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string entry").to_string())
        .collect()
}

#[test]
fn doc_and_artifact_reference_final_signoff_surfaces() {
    let doc = fs::read_to_string(repo_path(DOC_PATH)).expect("read signoff doc");
    for expected in [
        "asupersync-qn8i0p.8",
        SCRIPT_PATH,
        ARTIFACT_PATH,
        "tests/coordination_workload_bridge_signoff.rs",
        "scripts/run_coordination_workload_bridge_smoke.sh",
        "field-derivation-map.json",
        "fingerprint-comparison.json",
        "fail-closed-diagnostics.json",
        "dependency-boundary.json",
        "br show asupersync-qn8i0p --json",
        "bv --robot-alerts",
        "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_coordination_workload_bridge_signoff cargo test -p asupersync --test coordination_workload_bridge_signoff --features test-internals -- --nocapture",
    ] {
        assert!(
            doc.contains(expected),
            "signoff doc must mention {expected}"
        );
    }

    let artifact = load_json(ARTIFACT_PATH);
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("coordination-workload-bridge-signoff-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-qn8i0p.8"));
    assert_eq!(artifact["runner_script"].as_str(), Some(SCRIPT_PATH));
    assert_eq!(artifact["runbook_doc"].as_str(), Some(DOC_PATH));
    assert_eq!(
        artifact["test"].as_str(),
        Some("tests/coordination_workload_bridge_signoff.rs")
    );
}

#[test]
fn artifact_keeps_child_graph_fields_fail_closed_and_validation_contracts() {
    let artifact = load_json(ARTIFACT_PATH);

    let children: BTreeSet<String> = artifact["child_evidence"]
        .as_array()
        .expect("child evidence")
        .iter()
        .map(|child| child["bead_id"].as_str().expect("bead id").to_string())
        .collect();
    assert_eq!(
        children,
        BTreeSet::from([
            "asupersync-qn8i0p.1".to_string(),
            "asupersync-qn8i0p.2".to_string(),
            "asupersync-qn8i0p.3".to_string(),
            "asupersync-qn8i0p.4".to_string(),
            "asupersync-qn8i0p.5".to_string(),
            "asupersync-qn8i0p.6".to_string(),
            "asupersync-qn8i0p.7".to_string(),
        ])
    );

    let fields = string_set(&artifact["field_derivation_contract"]["required_workload_fields"]);
    for expected in [
        "workload_id",
        "family",
        "scenario_family",
        "scenario_id",
        "runtime_profile",
        "semantic_pressure",
        "provenance_only_context",
        "source_event_kinds",
        "source_event_count",
        "source_hashes",
        "source_bundle_hash",
        "replay_command",
        "entry_command",
        "expected_artifact_globs",
        "scheduler_evidence_input_id",
    ] {
        assert!(
            fields.contains(expected),
            "missing field mapping for {expected}"
        );
    }

    let refusal_reasons =
        string_set(&artifact["fail_closed_diagnostics"]["required_refusal_reasons"]);
    for expected in [
        "missing_scenario_dimensions",
        "unknown_schema_version",
        "unredacted_secret",
        "unsupported_dirty_paths",
        "stale_source",
    ] {
        assert!(
            refusal_reasons.contains(expected),
            "missing refusal reason {expected}"
        );
    }

    let graph = string_set(&artifact["validation"]["graph_state"]);
    for expected in [
        "br show asupersync-qn8i0p --json",
        "br show asupersync-qn8i0p.8 --json",
        "br ready --json",
        "bv --robot-alerts",
    ] {
        assert!(graph.contains(expected), "missing graph command {expected}");
    }

    let forbidden =
        string_set(&artifact["core_runtime_dependency_boundary"]["forbidden_dependency_keys"]);
    for expected in [
        "mcp_agent_mail",
        "agent-mail",
        "beads",
        "beads_rust",
        "br",
        "bv",
        "rch",
    ] {
        assert!(
            forbidden.contains(expected),
            "missing forbidden key {expected}"
        );
    }
}

#[test]
fn list_and_dry_run_modes_emit_signoff_plan_without_child_execution() {
    let list = run_signoff_static(&["--list"]);
    assert_success(&list, "list");
    let stdout = String::from_utf8_lossy(&list.stdout);
    for expected in [
        "modes list dry-run execute fixture output-root run-id generated-at",
        "row child_evidence_matrix_complete",
        "row repeated_fixture_fingerprints_identical",
        "row field_derivation_map_covers_generated_workloads",
        "row core_runtime_dependency_boundary_enforced",
        "graph bv --robot-alerts",
    ] {
        assert!(stdout.contains(expected), "list output missing {expected}");
    }

    let root = unique_root("dry-run");
    let dry = run_signoff(&[
        "--dry-run".to_string(),
        "--fixture".to_string(),
        "--output-root".to_string(),
        root.to_string_lossy().into_owned(),
        "--run-id".to_string(),
        "dry-run".to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
    ]);
    assert_success(&dry, "dry-run");
    let report = load_path_json(&report_path(&root, "dry-run"));
    assert_eq!(report["status"].as_str(), Some("dry_run"));
    assert_eq!(report["dry_run_row_count"].as_u64(), Some(8));
    for row in report["rows"].as_array().expect("rows") {
        assert_eq!(row["status"].as_str(), Some("dry_run"));
        assert_eq!(row["expected_status"].as_str(), Some("dry_run"));
        assert_eq!(row["detail"]["planned"].as_bool(), Some(true));
    }
}

#[test]
fn execute_fixture_emits_operator_grade_signoff_report() {
    let report = shared_execute_report();
    assert_eq!(report["status"].as_str(), Some("passed"));
    assert_eq!(report["live_inputs_used"].as_bool(), Some(false));
    assert_eq!(report["live_rch_used"].as_bool(), Some(false));
    assert_eq!(report["passed_row_count"].as_u64(), Some(8));
    assert_eq!(report["fail_closed_row_count"].as_u64(), Some(0));
    assert_eq!(report["unexpected_failure_count"].as_u64(), Some(0));

    for artifact_key in [
        "manifest",
        "rows_jsonl",
        "report",
        "summary",
        "child_evidence_matrix",
        "fingerprint_comparison",
        "field_derivation_map",
        "fail_closed_diagnostics",
        "dependency_boundary",
    ] {
        let path = report["artifact_paths"][artifact_key]
            .as_str()
            .expect("artifact path");
        assert!(Path::new(path).exists(), "missing artifact {artifact_key}");
    }

    let rows = rows_by_id(&report);
    for row_id in [
        "missing_prerequisite_guard",
        "child_evidence_matrix_complete",
        "repeated_fixture_fingerprints_identical",
        "field_derivation_map_covers_generated_workloads",
        "fail_closed_diagnostics_cover_malformed_stale_secret_unsupported",
        "core_runtime_dependency_boundary_enforced",
        "planner_capacity_profile_handoff_confirmed",
        "graph_state_and_rch_validation_commands_documented",
    ] {
        assert_eq!(
            rows[row_id]["status"].as_str(),
            Some("passed"),
            "{row_id} should pass"
        );
    }
}

#[test]
fn repeated_smoke_runs_are_canonically_identical_and_include_fail_closed_rows() {
    let report = shared_execute_report();
    let comparison_path = report["artifact_paths"]["fingerprint_comparison"]
        .as_str()
        .expect("fingerprint comparison path");
    let comparison = load_path_json(Path::new(comparison_path));
    assert_eq!(comparison["all_equal"].as_bool(), Some(true));
    assert_eq!(comparison["row_count"].as_u64(), Some(10));
    assert_eq!(comparison["first_passed_row_count"].as_u64(), Some(5));
    assert_eq!(comparison["second_passed_row_count"].as_u64(), Some(5));
    assert_eq!(comparison["first_fail_closed_row_count"].as_u64(), Some(5));
    assert_eq!(comparison["second_fail_closed_row_count"].as_u64(), Some(5));

    for row in comparison["rows"].as_array().expect("comparison rows") {
        assert_eq!(row["fingerprint_equal"].as_bool(), Some(true));
        assert_eq!(row["status_equal"].as_bool(), Some(true));
        assert!(
            row["first_fingerprint"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
    }
}

#[test]
fn field_derivation_map_covers_every_generated_workload_field() {
    let report = shared_execute_report();
    let field_path = report["artifact_paths"]["field_derivation_map"]
        .as_str()
        .expect("field derivation path");
    let field_map = load_path_json(Path::new(field_path));
    assert_eq!(field_map["workload_count"].as_u64(), Some(7));
    assert_eq!(field_map["required_field_count"].as_u64(), Some(15));
    assert_eq!(field_map["row_count"].as_u64(), Some(105));
    assert!(
        field_map["missing_or_mismatched"]
            .as_array()
            .expect("missing")
            .is_empty()
    );

    let mut workload_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in field_map["rows"].as_array().expect("field rows") {
        assert_eq!(row["status"].as_str(), Some("mapped"));
        assert!(
            row["source_evidence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert!(
            row["derivation_logic"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert!(
            row["observed_value_hash"]
                .as_str()
                .is_some_and(|text| text.starts_with("sha256:"))
        );
        workload_fields
            .entry(
                row["workload_id"]
                    .as_str()
                    .expect("workload id")
                    .to_string(),
            )
            .or_default()
            .insert(row["field"].as_str().expect("field").to_string());
    }
    assert_eq!(workload_fields.len(), 7);
    for (workload_id, fields) in workload_fields {
        assert!(
            workload_id.starts_with("ASWARM-WL-"),
            "{workload_id} must be a generated coordination workload"
        );
        assert_eq!(fields.len(), 15, "{workload_id} field count drifted");
    }
}

#[test]
fn fail_closed_and_dependency_boundary_evidence_are_explicit() {
    let report = shared_execute_report();

    let fail_path = report["artifact_paths"]["fail_closed_diagnostics"]
        .as_str()
        .expect("fail closed path");
    let fail = load_path_json(Path::new(fail_path));
    assert!(
        fail["missing_refusal_reasons"]
            .as_array()
            .expect("missing refusal reasons")
            .is_empty()
    );
    let observed = string_set(&fail["observed_refusal_reasons"]);
    for expected in [
        "missing_scenario_dimensions",
        "unknown_schema_version",
        "unredacted_secret",
        "unsupported_dirty_paths",
        "stale_source",
    ] {
        assert!(observed.contains(expected), "missing observed {expected}");
    }
    for diagnostic in fail["diagnostics"].as_array().expect("diagnostics") {
        assert!(
            diagnostic["first_failure_line"]
                .as_str()
                .is_some_and(|line| !line.is_empty())
        );
    }

    let boundary_path = report["artifact_paths"]["dependency_boundary"]
        .as_str()
        .expect("dependency boundary path");
    let boundary = load_path_json(Path::new(boundary_path));
    assert!(
        boundary["violations"]
            .as_array()
            .expect("violations")
            .is_empty(),
        "core runtime must not depend on Agent Mail, Beads, br, bv, or rch"
    );
    assert_eq!(
        boundary["comments_and_operator_commands_ignored"].as_bool(),
        Some(true)
    );
    assert_eq!(
        boundary["policy"]["allowed_core_runtime_surface"].as_str(),
        Some("consume generated JSON fixtures or replay stimuli only")
    );
}

#[test]
fn missing_extra_prerequisite_writes_fail_closed_report_and_exits_nonzero() {
    let root = unique_root("missing-prereq");
    let output = run_signoff(&[
        "--execute".to_string(),
        "--fixture".to_string(),
        "--output-root".to_string(),
        root.to_string_lossy().into_owned(),
        "--run-id".to_string(),
        "missing-prereq".to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
        "--extra-required-path".to_string(),
        "target/coordination-workload-bridge-signoff-missing-prereq".to_string(),
    ]);
    assert!(
        !output.status.success(),
        "missing prerequisite probe should exit nonzero"
    );
    let report = load_path_json(&report_path(&root, "missing-prereq"));
    assert_eq!(report["status"].as_str(), Some("failed"));
    assert_eq!(report["unexpected_failure_count"].as_u64(), Some(1));
    let rows = rows_by_id(&report);
    let guard = &rows["missing_prerequisite_guard"];
    assert_eq!(guard["status"].as_str(), Some("fail_closed"));
    assert!(
        guard["first_failure_line"]
            .as_str()
            .is_some_and(|line| line.contains("missing prerequisites"))
    );
}

#[test]
fn script_and_contract_pass_direct_syntax_and_schema_checks() {
    let syntax = Command::new("bash")
        .arg("-n")
        .arg(repo_path(SCRIPT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run bash syntax check");
    assert_success(&syntax, "bash -n");

    let schema = Command::new("jq")
        .arg("empty")
        .arg(repo_path(ARTIFACT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run jq schema check");
    assert_success(&schema, "jq empty");
}
