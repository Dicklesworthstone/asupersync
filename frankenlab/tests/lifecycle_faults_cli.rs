//! The shipped lifecycle scenario drives real managed work through the CLI.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::ScenarioRunner;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(command: &str, path: &Path, arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenlab"))
        .arg(command)
        .arg(path)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("run FrankenLab");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON command report")
}

#[test]
fn shipped_host_crash_workload_runs_replays_and_explores_through_cli() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/scenarios/host_crash_restart.yaml");
    let source = std::fs::read_to_string(&path).unwrap();
    let scenario: Scenario = serde_yaml::from_str(&source).unwrap();
    let expected = ScenarioRunner::run(&scenario).unwrap();
    assert!(
        expected.passed(),
        "{:?}",
        expected.lab_report.invariant_violations
    );
    // If faults become records again, all worker work ends before 400 ms.
    // The replacement must start after restart and do a fresh 500 ms of work.
    assert_eq!(expected.lab_report.now_nanos, 900_000_000);

    let executed = run("run", &path, &[]);
    assert_eq!(executed["passed"], true);
    assert_eq!(executed["workload_ran"], true);
    assert_eq!(executed["faults_injected"], 2);
    assert_eq!(executed["certificate"], expected.to_json()["certificate"]);
    assert!(executed["steps"].as_u64().unwrap() > 0);

    let replayed = run("replay", &path, &[]);
    assert_eq!(replayed["deterministic"], true);
    assert_eq!(
        replayed["event_hash"],
        executed["certificate"]["event_hash"]
    );
    let explored = run("explore", &path, &["--seeds", "3"]);
    assert_eq!(explored["seeds_explored"], 3);
    assert_eq!(explored["failed"], 0);
}
