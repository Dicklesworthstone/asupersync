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

fn exact_workload(root: &Path) -> PathBuf {
    write(
        root,
        "exact.yaml",
        "id: exact-cli\nlab: {seed: 17, worker_count: 1}\nchaos: {preset: off}\nparticipants:\n  - name: first\n    role: sender\n    properties: {messages: 1}\n  - name: second\n    role: sender\n    properties: {messages: 1}\n  - name: sink\n    role: receiver\n    properties: {capacity: 1}\n",
    )
}

#[test]
fn exact_search_exhaustion_requires_real_work_and_preserves_seeded_mode() {
    let dir = directory("exact_complete");
    let path = write(
        &dir,
        "complete.yaml",
        "id: exact-complete\nlab: {seed: 17, worker_count: 1}\nchaos: {preset: off}\nparticipants:\n  - name: sink\n    role: receiver\n",
    );
    let exact = successful_json(&run("explore", &path, false, &["--exact"]));
    assert_eq!(exact["schema"], "scenario-schedule-exploration-v1");
    assert_eq!(exact["passed"], true);
    assert_eq!(exact["termination"], "search_exhausted");
    assert_eq!(exact["pending_prefixes"], 0);
    assert!(exact["progress"]["runs"].as_u64().unwrap() > 0);
    assert!(exact["runs"][0]["steps"].as_u64().unwrap() > 0);
    assert_eq!(exact["runs"][0]["complete_receipt"], true);

    let seeded = successful_json(&run("explore", &path, false, &["--seeds", "2"]));
    assert_eq!(seeded["seeds_explored"], 2);
    assert_eq!(seeded["failed"], 0);
    let conflicting = run("explore", &path, false, &["--exact", "--seeds", "2"]);
    assert!(!conflicting.status.success(), "explicit search modes conflict");
    let missing_mode = run("explore", &path, false, &["--max-runs", "2"]);
    assert!(!missing_mode.status.success(), "exact limits require --exact");
}

#[test]
fn exact_cli_checkpoint_resumes_remaining_work_without_claiming_verified_history() {
    let dir = directory("exact_resume");
    let path = exact_workload(&dir);
    let first_checkpoint = dir.join("first.bin");
    let first = run(
        "explore", &path, false,
        &["--exact", "--max-runs", "1", "--checkpoint-out", first_checkpoint.to_str().unwrap()],
    );
    assert!(!first.status.success(), "a limited search must not pass");
    let first_report: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_report["progress"]["runs"], 1);
    assert_eq!(first_report["termination"], "run_limit");
    assert!(first_report["pending_prefixes"].as_u64().unwrap() > 0);
    assert_eq!(first_report["scenario_failed"], 0);
    let original_checkpoint = fs::read(&first_checkpoint).unwrap();

    let second_checkpoint = dir.join("second.bin");
    let second = run(
        "explore", &path, false,
        &["--exact", "--max-runs", "1", "--resume", first_checkpoint.to_str().unwrap(),
          "--checkpoint-out", second_checkpoint.to_str().unwrap()],
    );
    assert!(!second.status.success(), "loaded historical observations remain unverified");
    let second_report: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_report["progress"]["runs"], 2);
    assert_eq!(second_report["runs"].as_array().unwrap().len(), 1);
    assert_eq!(second_report["historical_progress_verified"], false);
    assert_eq!(second_report["passed"], false);
    assert_ne!(fs::read(&second_checkpoint).unwrap(), original_checkpoint);

    let overwrite = run(
        "explore", &path, false,
        &["--exact", "--checkpoint-out", first_checkpoint.to_str().unwrap()],
    );
    assert!(!overwrite.status.success());
    assert!(String::from_utf8_lossy(&overwrite.stderr).contains("already exists"));
    assert_eq!(fs::read(&first_checkpoint).unwrap(), original_checkpoint);

    let too_large = run(
        "explore", &path, false,
        &["--exact", "--resume", first_checkpoint.to_str().unwrap(), "--checkpoint-max-bytes", "32"],
    );
    assert!(!too_large.status.success());
    assert!(String::from_utf8_lossy(&too_large.stderr).contains("byte limit"));

    let changed = fs::read_to_string(&path).unwrap().replace("messages: 1", "messages: 2");
    let changed_path = write(&dir, "changed.yaml", &changed);
    let mismatch = run(
        "explore", &changed_path, false,
        &["--exact", "--resume", first_checkpoint.to_str().unwrap()],
    );
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("WorkloadMismatch"));
}

#[test]
fn exact_cli_refuses_unsupported_models_and_preserves_real_workload_failures() {
    let dir = directory("exact_failure");
    let unsupported = write(
        &dir,
        "multi.yaml",
        "id: multi\nlab: {worker_count: 2}\nparticipants:\n  - name: sink\n    role: receiver\n",
    );
    let result = run("explore", &unsupported, false, &["--exact"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("MultipleWorkers"));

    let failed = write(
        &dir,
        "failed.yaml",
        "id: failed-worker\nlab: {worker_count: 1}\nchaos: {preset: off}\nparticipants:\n  - name: owner\n    role: supervisor\n    properties: {max_restarts: 0}\n  - name: child\n    role: worker\n    properties: {fail_times: 1}\n",
    );
    let result = run("explore", &failed, false, &["--exact"]);
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["passed"], false);
    assert_eq!(report["scenario_failed"], 1);
    assert_eq!(report["termination"], "stopped");
    assert!(!report["runs"][0]["invariant_violations"].as_array().unwrap().is_empty());
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
