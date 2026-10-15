#![allow(missing_docs)]

use asupersync::lab::replay::{
    CoordinationWorkloadExpansionPack, minimize_coordination_pressure_replay,
    synthesize_coordination_pressure_replay,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const DOC_PATH: &str = "docs/coordination_workload_bridge_smoke_runbook.md";
const ARTIFACT_PATH: &str = "artifacts/coordination_workload_bridge_smoke_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/run_coordination_workload_bridge_smoke.sh";
const GENERATED_AT: &str = "2026-05-05T05:00:00Z";

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
        "asupersync-coordination-bridge-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn load_doc() -> String {
    fs::read_to_string(repo_path(DOC_PATH)).expect("read bridge runbook")
}

fn load_json(relative: &str) -> Value {
    let raw = fs::read_to_string(repo_path(relative)).expect("read json artifact");
    serde_json::from_str(&raw).expect("parse json artifact")
}

fn load_path_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path).expect("read json file");
    serde_json::from_str(&raw).expect("parse json file")
}

fn run_bridge(args: &[String]) -> Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run coordination bridge smoke script")
}

fn run_bridge_static(args: &[&str]) -> Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run coordination bridge smoke script")
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
        .join("coordination-workload-bridge-smoke-report.json")
}

fn execute_fixture(root: &Path, run_id: &str) -> Value {
    let output = run_bridge(&[
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

fn assert_remote_required_rch_cargo_commands(value: &Value, context: &str) {
    let commands = value.as_array().expect("rch_cargo commands");
    assert!(
        !commands.is_empty(),
        "{context} must publish at least one rch cargo command"
    );
    for command in commands {
        let command = command.as_str().expect("rch_cargo command string");
        assert!(
            command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
            "{context} cargo command must require a remote rch worker: {command}"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR="),
            "{context} cargo command must keep an explicit target dir: {command}"
        );
        assert!(
            !command.contains("rch exec -- cargo"),
            "{context} cargo command must not use bare rch cargo: {command}"
        );
    }
}

#[test]
fn doc_and_artifact_reference_bridge_surfaces() {
    let doc = load_doc();
    for expected in [
        "asupersync-qn8i0p.7",
        SCRIPT_PATH,
        ARTIFACT_PATH,
        "tests/coordination_workload_bridge_smoke_contract.rs",
        "scripts/run_agent_swarm_coordination_collector.sh",
        "scripts/run_runtime_workload_corpus.sh",
        "scripts/run_capacity_envelope_planner_smoke.sh",
        "scripts/run_host_profile_planner_smoke.sh",
        "scripts/run_signed_profile_bundle_smoke.sh",
        "synthesize_coordination_pressure_replay",
        "minimize_coordination_pressure_replay",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_coordination_workload_bridge_smoke cargo test -p asupersync --test coordination_workload_bridge_smoke_contract --features test-internals -- --nocapture",
    ] {
        assert!(doc.contains(expected), "runbook must mention {expected}");
    }

    let artifact = load_json(ARTIFACT_PATH);
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("coordination-workload-bridge-smoke-contract-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-qn8i0p.7"));
    assert_eq!(artifact["runner_script"].as_str(), Some(SCRIPT_PATH));
    assert_eq!(artifact["runbook_doc"].as_str(), Some(DOC_PATH));
    assert_remote_required_rch_cargo_commands(&artifact["validation"]["rch_cargo"], "artifact");
}

#[test]
fn artifact_lists_modes_outputs_fail_closed_conditions_and_rows() {
    let artifact = load_json(ARTIFACT_PATH);

    let modes: BTreeSet<String> = artifact["modes"]
        .as_array()
        .expect("modes")
        .iter()
        .map(|mode| mode["mode"].as_str().expect("mode").to_string())
        .collect();
    assert_eq!(
        modes,
        BTreeSet::from([
            "dry-run".to_string(),
            "execute".to_string(),
            "fixture".to_string(),
            "list".to_string(),
            "output-root".to_string(),
        ])
    );

    let outputs = string_set(&artifact["artifact_outputs"]);
    for expected in [
        "coordination-workload-bridge-smoke-manifest.json",
        "coordination-workload-bridge-smoke.jsonl",
        "coordination-workload-bridge-smoke-report.json",
        "coordination-workload-bridge-smoke.summary.txt",
        "logs/*.log",
    ] {
        assert!(outputs.contains(expected), "missing output {expected}");
    }

    let fail_closed = string_set(&artifact["fail_closed_conditions"]);
    for expected in [
        "malformed explicit source JSON",
        "unredacted secret or token-like content in an input source",
        "dirty frontier containing unsupported absolute or home-directory paths",
        "coordination bundle schema mismatch",
        "coordination workload pack missing required scenario families",
    ] {
        assert!(
            fail_closed.contains(expected),
            "missing fail-closed condition {expected}"
        );
    }

    let rows: BTreeSet<String> = artifact["smoke_rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["row_id"].as_str().expect("row id").to_string())
        .collect();
    assert_eq!(
        rows,
        BTreeSet::from([
            "capacity_profile_planner_handoff_records_used_refused_absent".to_string(),
            "collector_fixture_accepts_redacted_inputs".to_string(),
            "collector_refuses_malformed_source_schema".to_string(),
            "collector_refuses_unredacted_secret".to_string(),
            "dirty_frontier_unsupported_paths_fail_closed".to_string(),
            "missing_prerequisite_guard".to_string(),
            "replay_hook_handoff_validates_minimization_inputs".to_string(),
            "schema_mismatch_guard_fails_closed".to_string(),
            "workload_expansion_accepts_collector_bundle".to_string(),
            "workload_expansion_refuses_missing_dimensions".to_string(),
        ])
    );
}

#[test]
fn list_and_dry_run_modes_emit_operator_surfaces_without_child_execution() {
    let list = run_bridge_static(&["--list"]);
    assert_success(&list, "list");
    let stdout = String::from_utf8_lossy(&list.stdout);
    for expected in [
        "modes list dry-run execute fixture output-root run-id generated-at",
        "row collector_fixture_accepts_redacted_inputs",
        "row workload_expansion_refuses_missing_dimensions",
        "row capacity_profile_planner_handoff_records_used_refused_absent",
    ] {
        assert!(stdout.contains(expected), "list output missing {expected}");
    }

    let root = unique_root("dry-run");
    let run_id = "dry-run";
    let dry = run_bridge(&[
        "--dry-run".to_string(),
        "--fixture".to_string(),
        "--output-root".to_string(),
        root.to_string_lossy().into_owned(),
        "--run-id".to_string(),
        run_id.to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
    ]);
    assert_success(&dry, "dry-run");
    let report = load_path_json(&report_path(&root, run_id));
    assert_eq!(report["status"].as_str(), Some("dry_run"));
    assert_eq!(report["dry_run_row_count"].as_u64(), Some(10));
    for row in report["rows"].as_array().expect("rows") {
        assert_eq!(row["status"].as_str(), Some("dry_run"));
        assert_eq!(row["expected_status"].as_str(), Some("dry_run"));
    }
}

#[test]
fn execute_fixture_emits_all_expected_pass_and_fail_closed_rows() {
    let root = unique_root("execute");
    let report = execute_fixture(&root, "execute");
    assert_eq!(report["status"].as_str(), Some("passed"));
    assert_eq!(report["live_inputs_used"].as_bool(), Some(false));
    assert_eq!(report["live_rch_used"].as_bool(), Some(false));
    assert_eq!(report["passed_row_count"].as_u64(), Some(5));
    assert_eq!(report["fail_closed_row_count"].as_u64(), Some(5));
    assert_eq!(report["unexpected_failure_count"].as_u64(), Some(0));
    assert_remote_required_rch_cargo_commands(
        &report["validation_commands"]["rch_cargo"],
        "report",
    );

    for artifact_key in ["manifest", "rows_jsonl", "report", "summary"] {
        let path = report["artifact_paths"][artifact_key]
            .as_str()
            .expect("artifact path");
        assert!(Path::new(path).exists(), "missing artifact {artifact_key}");
    }

    let rows = rows_by_id(&report);
    for row_id in [
        "missing_prerequisite_guard",
        "collector_fixture_accepts_redacted_inputs",
        "workload_expansion_accepts_collector_bundle",
        "replay_hook_handoff_validates_minimization_inputs",
        "capacity_profile_planner_handoff_records_used_refused_absent",
    ] {
        assert_eq!(
            rows[row_id]["status"].as_str(),
            Some("passed"),
            "{row_id} should pass"
        );
    }
    for row_id in [
        "workload_expansion_refuses_missing_dimensions",
        "collector_refuses_malformed_source_schema",
        "collector_refuses_unredacted_secret",
        "dirty_frontier_unsupported_paths_fail_closed",
        "schema_mismatch_guard_fails_closed",
    ] {
        assert_eq!(
            rows[row_id]["status"].as_str(),
            Some("fail_closed"),
            "{row_id} should fail closed"
        );
        assert!(
            rows[row_id]["first_failure_line"]
                .as_str()
                .is_some_and(|line| !line.is_empty()),
            "{row_id} must keep a first failure line"
        );
    }

    let consumers: BTreeSet<String> = report["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["consumer"].as_str().expect("consumer").to_string())
        .collect();
    for expected in [
        "capacity-profile",
        "collector",
        "operator",
        "redaction",
        "replay",
        "synthesis",
    ] {
        assert!(consumers.contains(expected), "missing consumer {expected}");
    }

    let planner_row = &rows["capacity_profile_planner_handoff_records_used_refused_absent"];
    assert_eq!(
        planner_row["detail"]["planner_child_modes"]["capacity"].as_str(),
        Some("dry-run")
    );
    assert!(
        planner_row["detail"]["scenario_ids"]
            .as_array()
            .expect("scenario ids")
            .iter()
            .any(|id| id.as_str() == Some("AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-USED"))
    );
}

#[test]
fn execute_fixture_fingerprints_are_stable_across_output_roots() {
    let first = execute_fixture(&unique_root("stable-a"), "stable-a");
    let second = execute_fixture(&unique_root("stable-b"), "stable-b");
    let first_rows = rows_by_id(&first);
    let second_rows = rows_by_id(&second);

    assert_eq!(first_rows.len(), second_rows.len());
    for (row_id, first_row) in first_rows {
        let second_row = second_rows.get(&row_id).expect("matching row id");
        let first_fingerprint = first_row["stable_fingerprint"]
            .as_str()
            .expect("first fingerprint");
        let second_fingerprint = second_row["stable_fingerprint"]
            .as_str()
            .expect("second fingerprint");
        assert!(
            first_fingerprint.starts_with("sha256:"),
            "{row_id} fingerprint must be sha256"
        );
        assert_eq!(
            first_fingerprint, second_fingerprint,
            "{row_id} fingerprint drifted across roots"
        );
    }
}

#[test]
fn missing_extra_prerequisite_writes_fail_closed_report_and_exits_nonzero() {
    let root = unique_root("missing-prereq");
    let run_id = "missing-prereq";
    let output = run_bridge(&[
        "--execute".to_string(),
        "--fixture".to_string(),
        "--output-root".to_string(),
        root.to_string_lossy().into_owned(),
        "--run-id".to_string(),
        run_id.to_string(),
        "--generated-at".to_string(),
        GENERATED_AT.to_string(),
        "--extra-required-path".to_string(),
        "target/coordination-workload-bridge-definitely-missing-prereq".to_string(),
    ]);
    assert!(
        !output.status.success(),
        "missing prerequisite probe should exit nonzero"
    );
    let report = load_path_json(&report_path(&root, run_id));
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
fn emitted_pack_replays_through_real_lab_hooks_with_detailed_log_totals() {
    let root = unique_root("replay");
    let report = execute_fixture(&root, "replay");
    let rows = rows_by_id(&report);
    let replay_row = &rows["replay_hook_handoff_validates_minimization_inputs"];
    let pack_path = replay_row["artifact_paths"]["expansion_pack"]
        .as_str()
        .expect("expansion pack path");
    let raw = fs::read_to_string(pack_path).expect("read emitted coordination pack");
    let pack: CoordinationWorkloadExpansionPack =
        serde_json::from_str(&raw).expect("parse emitted coordination pack");

    let plan = synthesize_coordination_pressure_replay(0xC007_D157, &pack)
        .expect("emitted pack should synthesize through replay hook");
    assert_eq!(plan.stimuli.len(), 7);
    assert!(plan.log.event_count >= 7);
    assert_eq!(plan.log.synthesized_task_count, 18);
    assert_eq!(plan.log.queue_dimension, 16);
    assert_eq!(plan.log.timer_dimension, 12);
    assert_eq!(plan.log.cancel_dimension, 2);
    assert_eq!(plan.log.artifact_delay_dimension, 11);

    let minimized = minimize_coordination_pressure_replay(&plan);
    assert_eq!(minimized.stimuli.len(), 1);
    assert_eq!(
        minimized.log.first_failure_or_refusal.as_deref(),
        Some("dirty_frontier_fail_closed")
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
