//! Contract tests for operator SLO policy bundles.

use asupersync::types::{
    SLO_POLICY_BUNDLE_SCHEMA_VERSION, SloLatencyObjective, SloLatencyUnit, SloNoWinFallback,
    SloOptionalWorkClass, SloPolicyBundle, SloPolicyProvenance, SloPolicyRedaction,
    SloPolicyValidationIssueKind, SloPolicyValidationReport, SloResourcePressureThresholds,
    SloWorkloadClass, validate_slo_policy_bundle_json,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/slo_policy_bundle_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_slo_policy_bundle.sh";

fn json_file(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn contract() -> Value {
    json_file(CONTRACT_PATH)
}

fn scenario<'a>(artifact: &'a Value, id: &str) -> &'a Value {
    artifact["scenarios"]
        .as_array()
        .expect("scenarios are present")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("scenario {id} is present"))
}

fn profile_hash(hex_digit: char) -> String {
    format!("sha256:{}", hex_digit.to_string().repeat(64))
}

fn valid_bundle() -> SloPolicyBundle {
    SloPolicyBundle {
        schema_version: SLO_POLICY_BUNDLE_SCHEMA_VERSION,
        policy_id: "agent-swarm-standard".to_string(),
        workload_class: SloWorkloadClass::AgentSwarm,
        latency_objectives: vec![
            SloLatencyObjective {
                objective_id: "queue_wait".to_string(),
                unit: SloLatencyUnit::Milliseconds,
                p50: 5,
                p95: 25,
                p99: 60,
                p999: 120,
            },
            SloLatencyObjective {
                objective_id: "cleanup".to_string(),
                unit: SloLatencyUnit::Milliseconds,
                p50: 10,
                p95: 50,
                p99: 150,
                p999: 250,
            },
        ],
        cleanup_deadline_ms: 300,
        max_queue_wait_ms: 80,
        resource_pressure: SloResourcePressureThresholds {
            memory_basis_points: 8_500,
            fd_basis_points: 8_000,
            timer_queue_depth: 50_000,
        },
        optional_work_classes: vec![
            SloOptionalWorkClass {
                class_id: "index_refresh".to_string(),
                brownout_priority: 1,
                degradation_step: "delay non-critical index refresh jobs".to_string(),
            },
            SloOptionalWorkClass {
                class_id: "analytics_rollup".to_string(),
                brownout_priority: 2,
                degradation_step: "batch analytics rollups until pressure clears".to_string(),
            },
        ],
        no_win_fallback: Some(SloNoWinFallback {
            fallback_profile: "agent-swarm-safe-mode".to_string(),
            fallback_reason: "objectives-conflict-with-pressure".to_string(),
            proof_command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture".to_string(),
        }),
        provenance: SloPolicyProvenance {
            profile_id: "agent-swarm-prod".to_string(),
            profile_hash: profile_hash('a'),
            observed_profile_hash: Some(profile_hash('a')),
            target_commit: "b8f24024890da34b9151aaea62fff2d06d90f282".to_string(),
            feature_flags: vec!["test-internals".to_string()],
            artifact_path: Some(CONTRACT_PATH.to_string()),
            related_bead_id: Some("asupersync-bgtplc.1".to_string()),
        },
        redaction: SloPolicyRedaction {
            policy_id: "slo-redaction-v1".to_string(),
            passed: true,
        },
        metadata: BTreeMap::from([(
            "compiler_target".to_string(),
            Value::String("budget-admission-v1".to_string()),
        )]),
    }
}

fn issue_tags(report: &SloPolicyValidationReport) -> BTreeSet<String> {
    report
        .issues
        .iter()
        .map(|issue| issue.kind.as_str().to_string())
        .collect()
}

fn assert_issue(report: &SloPolicyValidationReport, kind: SloPolicyValidationIssueKind) {
    assert!(
        report.contains_issue(kind),
        "expected issue {}, got {:?}",
        kind.as_str(),
        issue_tags(report)
    );
}

fn workload_class_tags() -> BTreeSet<String> {
    [
        SloWorkloadClass::ControlPlane,
        SloWorkloadClass::DataPlane,
        SloWorkloadClass::Background,
        SloWorkloadClass::AgentSwarm,
    ]
    .into_iter()
    .map(|class| class.as_str().to_string())
    .collect()
}

fn latency_unit_tags() -> BTreeSet<String> {
    [SloLatencyUnit::Milliseconds, SloLatencyUnit::Microseconds]
        .into_iter()
        .map(|unit| unit.as_str().to_string())
        .collect()
}

fn validation_issue_tags() -> BTreeSet<String> {
    [
        SloPolicyValidationIssueKind::MalformedJson,
        SloPolicyValidationIssueKind::UnsupportedSchemaVersion,
        SloPolicyValidationIssueKind::MissingRequiredField,
        SloPolicyValidationIssueKind::NonMonotonicPercentile,
        SloPolicyValidationIssueKind::InvalidUnit,
        SloPolicyValidationIssueKind::MissingNoWinFallback,
        SloPolicyValidationIssueKind::SecretLikeMaterial,
        SloPolicyValidationIssueKind::ExternalPath,
        SloPolicyValidationIssueKind::StaleProfileHash,
        SloPolicyValidationIssueKind::UnsupportedWorkloadClass,
        SloPolicyValidationIssueKind::DuplicateObjective,
        SloPolicyValidationIssueKind::ImpossibleDeadline,
        SloPolicyValidationIssueKind::OversizedField,
        SloPolicyValidationIssueKind::RedactionFailure,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn expected_issue_tags(scenario_value: &Value) -> BTreeSet<String> {
    scenario_value["expected"]["issue_kinds"]
        .as_array()
        .expect("expected issue kinds")
        .iter()
        .map(|value| value.as_str().expect("issue kind is string").to_string())
        .collect()
}

#[test]
fn artifact_catalog_matches_rust_tags_and_required_fields() {
    let artifact = contract();
    let artifact_workloads = artifact["workload_classes"]
        .as_array()
        .expect("workload classes")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("workload class is string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_units = artifact["latency_units"]
        .as_array()
        .expect("latency units")
        .iter()
        .map(|value| value.as_str().expect("unit is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_issues = artifact["validation_issue_kinds"]
        .as_array()
        .expect("validation issue kinds")
        .iter()
        .map(|value| value.as_str().expect("issue is string").to_string())
        .collect::<BTreeSet<_>>();
    let required_fields = artifact["required_bundle_fields"]
        .as_array()
        .expect("required bundle fields")
        .iter()
        .map(|value| value.as_str().expect("field is string").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(artifact_workloads, workload_class_tags());
    assert_eq!(artifact_units, latency_unit_tags());
    assert_eq!(artifact_issues, validation_issue_tags());
    assert_eq!(
        artifact["policy_bundle_schema_version"].as_u64(),
        Some(u64::from(SLO_POLICY_BUNDLE_SCHEMA_VERSION))
    );
    for field in [
        "schema_version",
        "policy_id",
        "workload_class",
        "latency_objectives",
        "cleanup_deadline_ms",
        "max_queue_wait_ms",
        "resource_pressure",
        "no_win_fallback",
        "provenance",
        "redaction",
    ] {
        assert!(required_fields.contains(field), "required field {field}");
    }
}

#[test]
fn accepted_bundle_validates_and_fingerprint_is_stable() {
    let bundle = valid_bundle();
    let report = bundle.validate();
    assert!(report.accepted, "accepted report: {report:?}");
    assert!(report.issues.is_empty());

    let json = bundle.to_json().expect("bundle serializes");
    assert!(json.contains("\"workload_class\": \"agent_swarm\""));
    let reparsed = SloPolicyBundle::from_json(&json).expect("bundle reparses");
    assert_eq!(bundle.fingerprint(), reparsed.fingerprint());

    let report_from_json = validate_slo_policy_bundle_json(&json);
    assert!(
        report_from_json.accepted,
        "json report: {report_from_json:?}"
    );
    assert_eq!(report.fingerprint, report_from_json.fingerprint);
}

#[test]
fn validation_rejects_required_failure_modes() {
    let mut non_monotonic = valid_bundle();
    non_monotonic.latency_objectives[0].p95 = 4;
    assert_issue(
        &non_monotonic.validate(),
        SloPolicyValidationIssueKind::NonMonotonicPercentile,
    );

    let mut missing_fallback = valid_bundle();
    missing_fallback.no_win_fallback = None;
    assert_issue(
        &missing_fallback.validate(),
        SloPolicyValidationIssueKind::MissingNoWinFallback,
    );

    let mut unsupported_version = valid_bundle();
    unsupported_version.schema_version = 99;
    assert_issue(
        &unsupported_version.validate(),
        SloPolicyValidationIssueKind::UnsupportedSchemaVersion,
    );

    let mut stale_profile = valid_bundle();
    stale_profile.provenance.observed_profile_hash = Some(profile_hash('b'));
    assert_issue(
        &stale_profile.validate(),
        SloPolicyValidationIssueKind::StaleProfileHash,
    );

    let mut uppercase_hash = valid_bundle();
    uppercase_hash.provenance.profile_hash = profile_hash('A');
    uppercase_hash.provenance.observed_profile_hash = Some(profile_hash('A'));
    assert_issue(
        &uppercase_hash.validate(),
        SloPolicyValidationIssueKind::StaleProfileHash,
    );

    let mut redaction_failure = valid_bundle();
    redaction_failure.redaction.passed = false;
    redaction_failure.metadata.insert(
        "api_token".to_string(),
        Value::String("sk-redacted".to_string()),
    );
    let redaction_report = redaction_failure.validate();
    assert_issue(
        &redaction_report,
        SloPolicyValidationIssueKind::RedactionFailure,
    );
    assert_issue(
        &redaction_report,
        SloPolicyValidationIssueKind::SecretLikeMaterial,
    );

    let mut external_path = valid_bundle();
    external_path.provenance.artifact_path = Some("/home/ubuntu/private/profile.json".to_string());
    assert_issue(
        &external_path.validate(),
        SloPolicyValidationIssueKind::ExternalPath,
    );

    let mut duplicate_objective = valid_bundle();
    duplicate_objective
        .latency_objectives
        .push(duplicate_objective.latency_objectives[0].clone());
    assert_issue(
        &duplicate_objective.validate(),
        SloPolicyValidationIssueKind::DuplicateObjective,
    );

    let mut unsupported_vocab = serde_json::to_value(valid_bundle()).expect("bundle to value");
    unsupported_vocab["workload_class"] = json!("space_station");
    unsupported_vocab["latency_objectives"][0]["unit"] = json!("fortnights");
    let unsupported_bundle: SloPolicyBundle =
        serde_json::from_value(unsupported_vocab).expect("unsupported tags are preserved");
    let unsupported_report = unsupported_bundle.validate();
    assert_issue(
        &unsupported_report,
        SloPolicyValidationIssueKind::UnsupportedWorkloadClass,
    );
    assert_issue(
        &unsupported_report,
        SloPolicyValidationIssueKind::InvalidUnit,
    );
}

#[test]
fn json_validation_rejects_malformed_document() {
    let report = validate_slo_policy_bundle_json("{\"schema_version\":1,");
    assert!(!report.accepted);
    assert_issue(&report, SloPolicyValidationIssueKind::MalformedJson);
}

#[test]
fn contract_scenarios_match_rust_validator() {
    let artifact = contract();
    for scenario_value in artifact["scenarios"].as_array().expect("scenarios") {
        let report = if scenario_value["scenario_id"].as_str() == Some("malformed-json") {
            let document = scenario_value["fixture_document"]
                .as_str()
                .expect("malformed fixture document");
            validate_slo_policy_bundle_json(document)
        } else {
            let bundle: SloPolicyBundle = serde_json::from_value(scenario_value["bundle"].clone())
                .unwrap_or_else(|error| panic!("scenario bundle parses: {error}"));
            bundle.validate()
        };
        let expected_accepted = scenario_value["expected"]["accepted"]
            .as_bool()
            .expect("expected accepted flag");
        assert_eq!(
            report.accepted, expected_accepted,
            "scenario {}",
            scenario_value["scenario_id"]
        );
        assert_eq!(
            issue_tags(&report),
            expected_issue_tags(scenario_value),
            "scenario {}",
            scenario_value["scenario_id"]
        );
    }
    assert_eq!(
        scenario(&artifact, "accepted-agent-swarm")["expected"]["accepted"].as_bool(),
        Some(true)
    );
}

#[test]
fn script_emits_accepted_rejected_and_malformed_rows() {
    let output_root = "target/slo-policy-bundle-contract-test";
    let run_id = "script-emits";
    let status = Command::new("bash")
        .args([
            SCRIPT_PATH,
            "--output-root",
            output_root,
            "--run-id",
            run_id,
        ])
        .status()
        .expect("run SLO policy validator script");
    assert!(status.success(), "script status: {status:?}");

    let log_path = format!("{output_root}/{run_id}/slo-policy-bundle-events.ndjson");
    let rows = std::fs::read_to_string(&log_path).expect("script event log");
    let events = rows
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event row parses"))
        .collect::<Vec<_>>();

    assert!(events.iter().any(|event| event["accepted"] == true));
    assert!(events.iter().any(|event| event["accepted"] == false));
    assert!(events.iter().any(|event| {
        event["issue_kinds"]
            .as_array()
            .expect("issue kinds")
            .iter()
            .any(|kind| kind.as_str() == Some("malformed_json"))
    }));

    let input_status = Command::new("bash")
        .args([SCRIPT_PATH, "--input-jsonl", &log_path])
        .status()
        .expect("validate generated JSONL");
    assert!(
        input_status.success(),
        "input jsonl status: {input_status:?}"
    );
}

#[test]
fn script_rejects_malformed_jsonl_input() {
    let output_root = "target/slo-policy-bundle-contract-test";
    std::fs::create_dir_all(output_root).expect("create output root");
    let path = format!("{output_root}/malformed.ndjson");
    std::fs::write(&path, "{not-json\n").expect("write malformed JSONL fixture");

    let status = Command::new("bash")
        .args([SCRIPT_PATH, "--input-jsonl", &path])
        .status()
        .expect("run malformed JSONL validation");
    assert!(!status.success(), "malformed input must fail closed");
}
