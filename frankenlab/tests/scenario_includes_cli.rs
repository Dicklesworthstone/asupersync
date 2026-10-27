//! Exercises explicit include composition through the compiled FrankenLab CLI.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::ScenarioRunner;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn directory(label: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "scenario_includes_{label}_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("create scenario directory");
    path
}

fn write(root: &Path, name: &str, source: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, source).expect("write scenario");
    path
}

fn run(command: &str, path: &Path, resolve: bool, arguments: &[&str]) -> Output {
    let mut cli = Command::new(env!("CARGO_BIN_EXE_frankenlab"));
    cli.arg(command).arg(path).arg("--json");
    if resolve {
        cli.arg("--resolve-includes");
    }
    cli.args(arguments).output().expect("run FrankenLab")
}

fn successful_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON command report")
}

fn workload(root: &Path) {
    write(
        root,
        "workload.yaml",
        "lab: {seed: 17, worker_count: 2}\nparticipants:\n  - name: swarm\n    role: swarm\n    properties: {tasks: 2}\ncancellation: {strategy: all_points}\n",
    );
}

#[test]
fn inherited_workload_runs_replays_explores_and_tests_cancellation() {
    let dir = directory("workflow");
    workload(&dir);
    let path = write(
        &dir,
        "root.yaml",
        "id: include-workflow\ninclude: [{path: workload.yaml}]\nlab: {seed: 23}\n",
    );

    let validated = successful_json(&run("validate", &path, true, &[]));
    assert_eq!(validated["valid"], true);
    assert_eq!(validated["scenario_id"], "include-workflow");

    let executed = successful_json(&run("run", &path, true, &[]));
    assert_eq!(executed["passed"], true);
    assert_eq!(executed["workload_ran"], true);
    assert_eq!(executed["seed"], 23);
    assert!(executed["steps"].as_u64().unwrap() > 0);

    let replayed = successful_json(&run("replay", &path, true, &[]));
    assert_eq!(replayed["deterministic"], true);
    assert_eq!(
        replayed["event_hash"],
        executed["certificate"]["event_hash"]
    );
    assert_eq!(
        replayed["schedule_hash"],
        executed["certificate"]["schedule_hash"]
    );

    let explored = successful_json(&run(
        "explore",
        &path,
        true,
        &["--seeds", "2", "--start-seed", "23"],
    ));
    assert_eq!(explored["seeds_explored"], 2);
    assert_eq!(explored["failed"], 0);

    let cancelled = successful_json(&run("cancel", &path, true, &[]));
    assert_eq!(cancelled["passed"], true);
    assert!(cancelled["attempted_trials"].as_u64().unwrap() > 1);
    assert_eq!(cancelled["remaining_trials"], 0);
    assert_eq!(cancelled["baseline"]["scenario_id"], "include-workflow");
}

#[test]
fn default_commands_keep_single_document_behavior_and_expansion_is_explicit() {
    let dir = directory("opt_in");
    let path = write(
        &dir,
        "root.yaml",
        "id: single-file\ninclude: [{path: missing.yaml}]\n",
    );
    assert_eq!(
        successful_json(&run("validate", &path, false, &[]))["valid"],
        true
    );
    assert_eq!(
        successful_json(&run("run", &path, false, &[]))["workload_ran"],
        false
    );
    let expanded = run("validate", &path, true, &[]);
    assert!(!expanded.status.success());
    assert!(String::from_utf8_lossy(&expanded.stderr).contains("missing.yaml"));

    write(
        &dir,
        "root.yaml",
        "id: strings\nmetadata: {revision: 123}\n",
    );
    assert_eq!(
        successful_json(&run("validate", &path, false, &[]))["valid"],
        true
    );
    let expanded = run("validate", &path, true, &[]);
    assert!(!expanded.status.success());
    let error = String::from_utf8_lossy(&expanded.stderr);
    assert!(error.contains("root.yaml"), "{error}");
    assert!(error.contains("quote"), "{error}");
}

#[test]
fn minimizing_a_composed_failure_emits_a_standalone_reproducer() {
    let dir = directory("minimize");
    workload(&dir);
    let path = write(
        &dir,
        "root.yaml",
        "id: include-minimize\ninclude: [{path: workload.yaml}]\nlab: {max_steps: 1}\n",
    );
    let report = successful_json(&run("minimize", &path, true, &["--max-replays", "8"]));
    assert_eq!(report["outcome"]["verified_still_failing"], true);
    assert_eq!(
        report["minimized_scenario"]["include"],
        serde_json::json!([])
    );
    assert_eq!(
        report["minimized_scenario"]["participants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report["minimized_scenario"]["lab"]["seed"], 17);

    write(
        &dir,
        "workload.yaml",
        "invalid: [changed after minimization\n",
    );
    let scenario: Scenario = serde_json::from_value(report["minimized_scenario"].clone())
        .expect("standalone typed scenario");
    let replay = ScenarioRunner::run(&scenario).expect("execute standalone minimum");
    assert!(
        !replay.passed(),
        "minimum must still reproduce the bounded-step failure"
    );
}

#[test]
fn resolved_cli_enforces_byte_limits_without_changing_legacy_input_policy() {
    let dir = directory("bytes");
    let mut source = String::from("id: large-comment\n#");
    source.push_str(&"x".repeat(1024 * 1024));
    source.push('\n');
    let path = write(&dir, "root.yaml", &source);
    assert_eq!(
        successful_json(&run("validate", &path, false, &[]))["valid"],
        true
    );
    let output = run("validate", &path, true, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("max_file_bytes"));
}
