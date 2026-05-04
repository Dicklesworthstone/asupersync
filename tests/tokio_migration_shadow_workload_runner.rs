#![allow(missing_docs)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTRACT_PATH: &str = "artifacts/tokio_migration_shadow_workload_contract_v1.json";
const RUNNER_PATH: &str = "scripts/run_tokio_migration_shadow_workload_smoke.sh";
const DEFAULT_SCENARIO: &str = "TM-SHADOW-001-MPSC-BACKPRESSURE";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn runner_path() -> PathBuf {
    repo_root().join(RUNNER_PATH)
}

fn contract() -> Value {
    let text = std::fs::read_to_string(repo_root().join(CONTRACT_PATH))
        .expect("shadow workload contract should exist");
    serde_json::from_str(&text).expect("shadow workload contract should parse")
}

fn temp_output_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "asupersync_tokio_shadow_{name}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn run_runner(args: &[&str]) -> std::process::Output {
    Command::new(runner_path())
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("runner should launch with args {args:?}: {err}"))
}

fn parse_jsonl(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    text.lines()
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

#[test]
fn runner_lists_every_contract_scenario() {
    let output = run_runner(&["--list"]);
    assert!(
        output.status.success(),
        "--list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("runner output should be utf8");
    let listed: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.split('\t').next())
        .collect();
    let contract = contract();
    let expected: Vec<_> = contract["scenarios"]
        .as_array()
        .expect("contract scenarios")
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("scenario id should be string")
        })
        .collect();

    assert_eq!(listed, expected, "runner --list must follow contract order");
}

#[test]
fn dry_run_logs_required_fields_for_both_runtime_sides() {
    let output_root = temp_output_root("dry_run");
    let output_root_text = output_root.to_string_lossy().to_string();
    let output = run_runner(&[
        "--dry-run",
        "--scenario",
        DEFAULT_SCENARIO,
        "--output-root",
        &output_root_text,
    ]);
    assert!(
        output.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("runner output should be utf8");
    for needle in [
        "scenario_id=TM-SHADOW-001-MPSC-BACKPRESSURE",
        "contract_version=tokio-migration-shadow-workload-v1",
        "runtime_side=tokio-reference",
        "runtime_side=asupersync",
        "worker_count=",
        "task_count=256",
        "channel_capacity=16",
        "cancellation_injection_point=before_reserve_poll",
        "clock_mode=canonical-tokio-boundary-contract",
        "clock_mode=deterministic-virtual-contract",
        "artifact_path=",
        "final_verdict=dry_run_contract_row",
        "projection_hash=",
    ] {
        assert!(
            stdout.contains(needle),
            "missing {needle} in stdout:\n{stdout}"
        );
    }
}

#[test]
fn execute_writes_jsonl_rows_and_summary_artifact() {
    let output_root = temp_output_root("execute");
    let output_root_text = output_root.to_string_lossy().to_string();
    let output = run_runner(&[
        "--execute",
        "--scenario",
        DEFAULT_SCENARIO,
        "--output-root",
        &output_root_text,
        "--scale",
        "small",
    ]);
    assert!(
        output.status.success(),
        "execute failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run_root = std::fs::read_dir(&output_root)
        .expect("output root should exist")
        .next()
        .expect("runner should create a run dir")
        .expect("run dir should be readable")
        .path()
        .join(DEFAULT_SCENARIO);
    let report_path = run_root.join("shadow_workload_report.jsonl");
    let summary_path = run_root.join("shadow_workload_summary.json");

    assert!(report_path.exists(), "report jsonl should exist");
    assert!(summary_path.exists(), "summary json should exist");

    let rows = parse_jsonl(&report_path);
    assert_eq!(rows.len(), 2, "both runtime sides should be reported");
    assert_eq!(rows[0]["runtime_side"], "tokio-reference");
    assert_eq!(rows[1]["runtime_side"], "asupersync");
    for row in &rows {
        assert_eq!(row["scenario_id"], DEFAULT_SCENARIO);
        assert_eq!(row["task_count"], 256);
        assert_eq!(row["channel_capacity"], 16);
        assert!(
            row["projection_hash"]
                .as_str()
                .is_some_and(|hash| !hash.is_empty()),
            "projection_hash must be populated: {row:?}"
        );
        assert!(
            row["artifact_paths"]["report_jsonl"]
                .as_str()
                .is_some_and(|path| path.ends_with("shadow_workload_report.jsonl")),
            "row should name report artifact path: {row:?}"
        );
    }

    let summary: Value = serde_json::from_str(
        &std::fs::read_to_string(summary_path).expect("summary should be readable"),
    )
    .expect("summary should parse");
    assert_eq!(summary["row_count"], 2);
    assert_eq!(summary["runtime_sides"][0], "asupersync");
    assert_eq!(summary["runtime_sides"][1], "tokio-reference");
}

#[test]
fn real_host_template_scale_is_explicit_not_implicit_average() {
    let output_root = temp_output_root("real_host");
    let output_root_text = output_root.to_string_lossy().to_string();
    let output = run_runner(&[
        "--dry-run",
        "--scenario",
        DEFAULT_SCENARIO,
        "--output-root",
        &output_root_text,
        "--scale",
        "real-host-template",
        "--runtime-side",
        "asupersync",
    ]);
    assert!(
        output.status.success(),
        "real-host dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("runner output should be utf8");
    assert!(stdout.contains("runtime_side=asupersync"));
    assert!(stdout.contains("worker_count=256"));
    assert!(stdout.contains("task_count=65536"));
    assert!(stdout.contains("channel_capacity=1024"));
    assert!(
        !stdout.contains("runtime_side=tokio-reference"),
        "runtime-side filter should be respected"
    );
}

#[test]
fn runner_keeps_tokio_out_of_default_asupersync_normal_graph() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(repo_root())
        .args(["tree", "-e", "normal", "-p", "asupersync", "-i", "tokio"])
        .output();

    let output = match output {
        Ok(output) => output,
        Err(err) => {
            println!("skipping cargo-tree proof because cargo failed to launch: {err}");
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        combined.contains("nothing to print")
            || combined.contains("nothing depends on")
            || combined.contains("no matches found")
            || combined.contains("not found in the graph"),
        "tokio entered the default asupersync normal graph or cargo tree failed unexpectedly:\n{combined}"
    );
}
