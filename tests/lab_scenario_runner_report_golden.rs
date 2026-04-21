//! Golden snapshot for scenario-runner report dumps.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::{ScenarioRunResult, ScenarioRunner};
use insta::assert_json_snapshot;
use serde_json::{Value, json};

fn scenario_runner_happy_path() -> Scenario {
    serde_json::from_str(
        r#"{
            "id": "scenario-runner-report-happy",
            "description": "happy path report dump snapshot"
        }"#,
    )
    .expect("happy-path scenario should parse")
}

fn scenario_runner_faulted_path() -> Scenario {
    serde_json::from_str(
        r#"{
            "id": "scenario-runner-report-faulted",
            "description": "fault-injected report dump snapshot",
            "faults": [
                {
                    "at_ms": 5,
                    "action": "partition",
                    "args": {"from": "scheduler", "to": "executor"}
                },
                {
                    "at_ms": 12,
                    "action": "heal",
                    "args": {"from": "scheduler", "to": "executor"}
                }
            ]
        }"#,
    )
    .expect("faulted scenario should parse")
}

fn scrub_transient_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if matches!(key.as_str(), "now_nanos" | "recorded_at") {
                    *nested = Value::String("[scrubbed]".into());
                } else {
                    scrub_transient_fields(nested);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                scrub_transient_fields(nested);
            }
        }
        _ => {}
    }
}

fn scrubbed_report_dump(result: &ScenarioRunResult) -> Value {
    let mut value = result.to_json();
    scrub_transient_fields(&mut value);
    value
}

#[test]
fn scenario_report_dump() {
    let happy = ScenarioRunner::run(&scenario_runner_happy_path())
        .expect("happy-path scenario runner execution should succeed");
    let faulted = ScenarioRunner::run(&scenario_runner_faulted_path())
        .expect("faulted scenario runner execution should succeed");

    let golden = json!({
        "happy_path": scrubbed_report_dump(&happy),
        "faulted_path": scrubbed_report_dump(&faulted),
    });

    assert_json_snapshot!("scenario_report_dump", golden);
}
