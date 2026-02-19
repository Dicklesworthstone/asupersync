//! E2E log quality + schema validation gates (asupersync-3narc.3.5).
//!
//! These tests ensure deterministic E2E logging contracts stay enforced in CI.
//! They validate:
//! - `e2e-suite-summary-v3` schema completeness
//! - replay metadata presence
//! - timestamp ordering/seed/artifact-path quality constraints
//! - script-level contract wiring across E2E runners/orchestrator

use serde_json::Value;
use std::fs;

fn validate_suite_summary_v3(summary: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    let required_strings = [
        "schema_version",
        "suite_id",
        "scenario_id",
        "started_ts",
        "ended_ts",
        "status",
        "repro_command",
        "artifact_path",
    ];

    for field in required_strings {
        match summary.get(field) {
            Some(Value::String(value)) if !value.trim().is_empty() => {}
            Some(_) => errors.push(format!("field '{field}' must be a non-empty string")),
            None => errors.push(format!("missing required field '{field}'")),
        }
    }

    match summary.get("seed") {
        Some(Value::String(seed)) if !seed.trim().is_empty() => {}
        Some(Value::Number(_)) => {}
        Some(_) => errors.push("field 'seed' must be string or number".to_string()),
        None => errors.push("missing required field 'seed'".to_string()),
    }

    if let Some(Value::String(schema)) = summary.get("schema_version") {
        if schema != "e2e-suite-summary-v3" {
            errors.push(format!(
                "'schema_version' must be 'e2e-suite-summary-v3' (got '{schema}')"
            ));
        }
    }

    if let Some(Value::String(status)) = summary.get("status") {
        if status != "passed" && status != "failed" {
            errors.push(format!(
                "'status' must be 'passed' or 'failed' (got '{status}')"
            ));
        }
    }

    if let (Some(Value::String(started_ts)), Some(Value::String(ended_ts))) =
        (summary.get("started_ts"), summary.get("ended_ts"))
    {
        if started_ts > ended_ts {
            errors.push(format!(
                "timestamp order invalid: started_ts ({started_ts}) > ended_ts ({ended_ts})"
            ));
        }
    }

    if let Some(Value::String(repro)) = summary.get("repro_command") {
        let has_expected_tool = repro.contains("bash ")
            || repro.contains("cargo ")
            || repro.contains("rch exec --")
            || repro.contains("run_all_e2e.sh");
        if !has_expected_tool {
            errors.push("repro_command does not look executable/replayable".to_string());
        }
    }

    if let Some(Value::String(artifact_path)) = summary.get("artifact_path") {
        if !std::path::Path::new(artifact_path.as_str())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            errors.push(format!(
                "artifact_path must end with .json (got '{artifact_path}')"
            ));
        }
        if !artifact_path.contains("summary.json") {
            errors.push(format!(
                "artifact_path should point at summary.json (got '{artifact_path}')"
            ));
        }
    }

    // If status is failed, we require non-empty failure context.
    if let Some(Value::String(status)) = summary.get("status") {
        if status == "failed" {
            match summary.get("failure_class") {
                Some(Value::String(value))
                    if !value.trim().is_empty() && value.trim() != "none" => {}
                Some(_) => errors.push(
                    "failed status requires non-empty failure_class different from 'none'"
                        .to_string(),
                ),
                None => errors.push("failed status requires failure_class".to_string()),
            }
        }
    }

    errors
}

#[test]
fn suite_summary_v3_accepts_valid_payload() {
    let payload: Value = serde_json::from_str(
        r#"{
            "schema_version": "e2e-suite-summary-v3",
            "suite_id": "scheduler_e2e",
            "scenario_id": "E2E-SUITE-SCHEDULER-WAKEUP",
            "seed": "0xDEADBEEF",
            "started_ts": "2026-02-19T03:00:00Z",
            "ended_ts": "2026-02-19T03:00:30Z",
            "status": "passed",
            "failure_class": "none",
            "repro_command": "RCH_BIN=rch bash scripts/test_scheduler_wakeup_e2e.sh",
            "artifact_path": "target/e2e-results/scheduler/artifacts_20260219_030000/summary.json"
        }"#,
    )
    .expect("valid summary JSON");

    let errors = validate_suite_summary_v3(&payload);
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
}

#[test]
fn suite_summary_v3_rejects_missing_replay_metadata() {
    let payload: Value = serde_json::from_str(
        r#"{
            "schema_version": "e2e-suite-summary-v3",
            "suite_id": "scheduler_e2e",
            "scenario_id": "E2E-SUITE-SCHEDULER-WAKEUP",
            "seed": "0xDEADBEEF",
            "started_ts": "2026-02-19T03:00:00Z",
            "ended_ts": "2026-02-19T03:00:30Z",
            "status": "passed",
            "artifact_path": "target/e2e-results/scheduler/artifacts_20260219_030000/summary.json"
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_suite_summary_v3(&payload);
    assert!(
        errors.iter().any(|msg| msg.contains("repro_command")),
        "expected missing replay metadata error, got: {errors:?}"
    );
}

#[test]
fn suite_summary_v3_rejects_bad_timestamp_order() {
    let payload: Value = serde_json::from_str(
        r#"{
            "schema_version": "e2e-suite-summary-v3",
            "suite_id": "combinators_e2e",
            "scenario_id": "E2E-SUITE-COMBINATORS",
            "seed": "0xDEADBEEF",
            "started_ts": "2026-02-19T03:01:00Z",
            "ended_ts": "2026-02-19T03:00:59Z",
            "status": "failed",
            "failure_class": "test_or_invariant_failure",
            "repro_command": "bash scripts/test_combinators.sh",
            "artifact_path": "target/e2e-results/combinators/artifacts_20260219_030000/summary.json"
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_suite_summary_v3(&payload);
    assert!(
        errors
            .iter()
            .any(|msg| msg.contains("timestamp order invalid")),
        "expected timestamp-order failure, got: {errors:?}"
    );
}

#[test]
fn suite_summary_v3_failed_status_requires_failure_context() {
    let payload: Value = serde_json::from_str(
        r#"{
            "schema_version": "e2e-suite-summary-v3",
            "suite_id": "phase6_e2e",
            "scenario_id": "E2E-SUITE-PHASE6",
            "seed": "0xDEADBEEF",
            "started_ts": "2026-02-19T03:00:00Z",
            "ended_ts": "2026-02-19T03:00:30Z",
            "status": "failed",
            "failure_class": "none",
            "repro_command": "bash scripts/run_phase6_e2e.sh",
            "artifact_path": "target/phase6-e2e/artifacts_20260219_030000/summary.json"
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_suite_summary_v3(&payload);
    assert!(
        errors
            .iter()
            .any(|msg| msg.contains("requires non-empty failure_class")),
        "expected failure-context validation error, got: {errors:?}"
    );
}

#[test]
fn e2e_runner_scripts_emit_required_summary_contract_fields() {
    let scripts = [
        "scripts/test_websocket_e2e.sh",
        "scripts/test_http_e2e.sh",
        "scripts/test_messaging_e2e.sh",
        "scripts/test_transport_e2e.sh",
        "scripts/test_database_e2e.sh",
        "scripts/test_distributed_e2e.sh",
        "scripts/test_h2_security_e2e.sh",
        "scripts/test_net_hardening_e2e.sh",
        "scripts/test_redis_e2e.sh",
        "scripts/test_combinators.sh",
        "scripts/test_cancel_attribution.sh",
        "scripts/test_scheduler_wakeup_e2e.sh",
        "scripts/run_phase6_e2e.sh",
    ];

    let required_fragments = [
        "\"schema_version\": \"e2e-suite-summary-v3\"",
        "\"suite_id\":",
        "\"scenario_id\":",
        "\"seed\":",
        "\"started_ts\":",
        "\"ended_ts\":",
        "\"status\":",
        "\"repro_command\":",
        "\"artifact_path\":",
    ];

    for script in scripts {
        let content = fs::read_to_string(script).expect("read e2e runner script");
        for fragment in required_fragments {
            assert!(
                content.contains(fragment),
                "script '{script}' missing required summary fragment: {fragment}"
            );
        }
    }
}

#[test]
fn run_all_orchestrator_keeps_log_quality_enforcement_hooks() {
    let content = fs::read_to_string("scripts/run_all_e2e.sh")
        .expect("read run_all_e2e.sh for quality gate checks");

    assert!(
        content.contains("validate_suite_summary_contract"),
        "run_all_e2e.sh must enforce suite summary contract validation"
    );
    assert!(
        content.contains("\"summary_schema_reason\""),
        "run_all_e2e.sh must emit schema validation reasons"
    );
    assert!(
        content.contains("failure_contract_violations"),
        "run_all_e2e.sh must track failure contract violations"
    );
    assert!(
        content.contains("scenario_coverage_map"),
        "run_all_e2e.sh must emit scenario coverage map artifact"
    );
    assert!(
        content.contains("cross_suite_manifest"),
        "run_all_e2e.sh must emit cross-suite manifest artifact"
    );
}
