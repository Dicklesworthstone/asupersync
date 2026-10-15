//! Golden snapshot for scenario-runner trace output.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::{ScenarioRunResult, ScenarioRunner};
use asupersync::trace::replay::ReplayTrace;
use insta::assert_json_snapshot;
use serde_json::{Value, json};

fn scenario_runner_happy_path() -> Scenario {
    serde_json::from_str(
        r#"{
            "id": "scenario-runner-happy",
            "description": "happy path trace snapshot"
        }"#,
    )
    .expect("happy-path scenario should parse")
}

fn scenario_runner_injected_failure() -> Scenario {
    serde_json::from_str(
        r#"{
            "id": "scenario-runner-injected-failure",
            "description": "fault-injected trace snapshot",
            "faults": [
                {
                    "at_ms": 10,
                    "action": "partition",
                    "args": {"from": "alice", "to": "bob"}
                },
                {
                    "at_ms": 40,
                    "action": "heal",
                    "args": {"from": "alice", "to": "bob"}
                }
            ]
        }"#,
    )
    .expect("fault-injected scenario should parse")
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

fn scrub_replay_trace(trace: Option<&ReplayTrace>) -> Value {
    let mut value = trace.map_or(Value::Null, |trace| {
        serde_json::to_value(trace).expect("replay trace should serialize")
    });
    scrub_transient_fields(&mut value);
    value
}

fn scrubbed_scenario_runner_output(result: &ScenarioRunResult) -> Value {
    let mut replay_metadata = json!({
        "family": {
            "id": result.replay_metadata.family.id,
            "surface_id": result.replay_metadata.family.surface_id,
            "surface_contract_version": result.replay_metadata.family.surface_contract_version,
        },
        "instance": {
            "family_id": result.replay_metadata.instance.family_id,
            "effective_seed": result.replay_metadata.instance.effective_seed,
            "run_index": result.replay_metadata.instance.run_index,
            "runtime_kind": result.replay_metadata.instance.runtime_kind,
        },
        "effective_seed": result.replay_metadata.effective_seed,
        "effective_entropy_seed": result.replay_metadata.effective_entropy_seed,
        "event_count": result.replay_metadata.event_count,
        "event_hash": result.replay_metadata.event_hash,
        "schedule_hash": result.replay_metadata.schedule_hash,
        "trace_fingerprint": result.replay_metadata.trace_fingerprint,
        "steps_total": result.replay_metadata.steps_total,
        "repro_command": result.replay_metadata.repro_command,
    });
    scrub_transient_fields(&mut replay_metadata);

    let mut trace_summary = json!({
        "seed": result.lab_report.seed,
        "steps_total": result.lab_report.steps_total,
        "quiescent": result.lab_report.quiescent,
        "now_nanos": result.lab_report.now_nanos,
        "trace_len": result.lab_report.trace_len,
        "trace_fingerprint": result.lab_report.trace_fingerprint,
        "trace_certificate": {
            "event_count": result.lab_report.trace_certificate.event_count,
            "event_hash": result.lab_report.trace_certificate.event_hash,
            "schedule_hash": result.lab_report.trace_certificate.schedule_hash,
        },
    });
    scrub_transient_fields(&mut trace_summary);

    json!({
        "summary": {
            "scenario_id": result.scenario_id,
            "seed": result.seed,
            "passed": result.passed(),
            "faults_injected": result.faults_injected,
        },
        "trace_summary": trace_summary,
        "certificate": {
            "event_hash": result.certificate.event_hash,
            "schedule_hash": result.certificate.schedule_hash,
            "trace_fingerprint": result.certificate.trace_fingerprint,
        },
        "oracle_report": {
            "checked": result.oracle_report.checked,
            "passed_count": result.oracle_report.passed_count,
            "failed_count": result.oracle_report.failed_count,
            "all_passed": result.oracle_report.all_passed,
        },
        "replay_metadata": replay_metadata,
        "seed_lineage": {
            "seed_lineage_id": result.seed_lineage.seed_lineage_id,
            "canonical_seed": result.seed_lineage.canonical_seed,
            "lab_effective_seed": result.seed_lineage.lab_effective_seed,
            "live_effective_seed": result.seed_lineage.live_effective_seed,
            "lab_entropy_seed": result.seed_lineage.lab_entropy_seed,
            "live_entropy_seed": result.seed_lineage.live_entropy_seed,
            "seeds_match": result.seed_lineage.seeds_match,
        },
        "replay_trace": scrub_replay_trace(result.replay_trace.as_ref()),
    })
}

#[test]
fn scenario_runner_trace_output_scrubbed() {
    let happy = ScenarioRunner::run(&scenario_runner_happy_path())
        .expect("happy-path scenario runner execution should succeed");
    let injected_failure = ScenarioRunner::run(&scenario_runner_injected_failure())
        .expect("fault-injected scenario runner execution should succeed");

    assert_json_snapshot!(
        "scenario_runner_trace_output_scrubbed",
        json!({
            "happy_path": scrubbed_scenario_runner_output(&happy),
            "injected_failure": scrubbed_scenario_runner_output(&injected_failure),
        })
    );
}
