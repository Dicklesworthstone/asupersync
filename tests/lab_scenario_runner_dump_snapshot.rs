//! Golden snapshot for scenario-runner report dumps.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::{
    ScenarioExplorationResult, ScenarioRunResult, ScenarioRunner,
};
use std::fmt::Write as _;

fn snapshot_scenario() -> Scenario {
    serde_json::from_str(
        r#"{
            "id": "snapshot-scenario-report",
            "description": "Scenario report dump snapshot",
            "faults": [
                {
                    "at_ms": 10,
                    "action": "partition",
                    "args": {"from": "api", "to": "db"}
                },
                {
                    "at_ms": 25,
                    "action": "heal",
                    "args": {"from": "api", "to": "db"}
                }
            ],
            "oracles": ["task_leak", "obligation_leak"],
            "metadata": {
                "surface_contract_version": "snapshot-scenario.v1"
            }
        }"#,
    )
    .expect("snapshot scenario should parse")
}

fn snapshot_report_dump(
    run: &ScenarioRunResult,
    exploration: &ScenarioExplorationResult,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "scenario: {}", run.scenario_id);
    let _ = writeln!(out, "seed: {}", run.seed);
    let _ = writeln!(out, "passed: {}", run.passed());
    let _ = writeln!(out, "faults_injected: {}", run.faults_injected);
    let _ = writeln!(out, "steps: {}", run.lab_report.steps_total);
    let _ = writeln!(out, "quiescent: {}", run.lab_report.quiescent);
    let _ = writeln!(out, "adapter: {}", run.adapter);
    let _ = writeln!(
        out,
        "surface_contract_version: {}",
        run.replay_metadata.family.surface_contract_version
    );
    let _ = writeln!(
        out,
        "execution_instance: {}",
        run.replay_metadata.instance.key()
    );
    let _ = writeln!(
        out,
        "certificate: event_hash={} schedule_hash={} fingerprint={} steps={}",
        run.certificate.event_hash,
        run.certificate.schedule_hash,
        run.certificate.trace_fingerprint,
        run.certificate.steps
    );
    let _ = writeln!(
        out,
        "oracles: checked={} passed={} failed={} all_passed={}",
        run.oracle_report.checked.len(),
        run.oracle_report.passed_count,
        run.oracle_report.failed_count,
        run.oracle_report.all_passed
    );
    for entry in &run.oracle_report.entries {
        let _ = writeln!(out, "  - {}: {}", entry.invariant, entry.passed);
    }
    let _ = writeln!(out, "exploration:");
    let _ = writeln!(out, "  scenario_id: {}", exploration.scenario_id);
    let _ = writeln!(out, "  seeds_explored: {}", exploration.seeds_explored);
    let _ = writeln!(out, "  passed: {}", exploration.passed);
    let _ = writeln!(out, "  failed: {}", exploration.failed);
    let _ = writeln!(
        out,
        "  unique_fingerprints: {}",
        exploration.unique_fingerprints
    );
    let _ = writeln!(
        out,
        "  first_failure_seed: {}",
        exploration
            .first_failure_seed
            .map_or_else(|| "none".to_string(), |seed| seed.to_string())
    );
    let _ = writeln!(out, "  runs:");
    for run in &exploration.runs {
        let _ = writeln!(
            out,
            "    - seed={} passed={} steps={} fingerprint={} failures={}",
            run.seed,
            run.passed,
            run.steps,
            run.fingerprint,
            run.failures.join("|")
        );
    }
    out
}

#[test]
fn scenario_report_dump_snapshot_scrubbed() {
    let scenario = snapshot_scenario();
    let run = ScenarioRunner::run_with_seed(&scenario, Some(7)).unwrap();
    let exploration = ScenarioRunner::explore_seeds(&scenario, 7, 3).unwrap();

    insta::assert_snapshot!(
        "scenario_report_dump_scrubbed",
        snapshot_report_dump(&run, &exploration)
    );
}
