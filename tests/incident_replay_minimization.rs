//! Contract tests for incident replay-package minimization.

use asupersync::trace::{
    INCIDENT_MINIMIZED_REPRO_SCHEMA_VERSION, IncidentBundle, IncidentMinimizedReplayRepro,
    IncidentOracleKind, IncidentReplayMinimizationConfig, IncidentReplayMinimizationIssueKind,
    IncidentReplayMinimizationVerdict, IncidentReplayOracle, IncidentReplayPackage,
    IncidentReplayShrinkStepKind, minimize_incident_replay_package,
};
use serde_json::Value;
use std::collections::BTreeSet;

const CONTRACT_PATH: &str = "artifacts/incident_replay_minimization_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_incident_replay_minimization.sh";

fn contract() -> Value {
    let raw =
        std::fs::read_to_string(CONTRACT_PATH).expect("incident minimization contract exists");
    serde_json::from_str(&raw).expect("incident minimization contract parses")
}

fn scenario<'a>(artifact: &'a Value, id: &str) -> &'a Value {
    artifact["scenarios"]
        .as_array()
        .expect("scenarios are present")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("scenario {id} is present"))
}

fn scenario_package(artifact: &Value, scenario_value: &Value) -> IncidentReplayPackage {
    let bundle_source = if let Some(reference) = scenario_value["bundle_ref"].as_str() {
        &scenario(artifact, reference)["bundle"]
    } else {
        &scenario_value["bundle"]
    };
    let bundle: IncidentBundle =
        serde_json::from_value(bundle_source.clone()).expect("scenario bundle parses");
    let mut package = bundle
        .import_replay_package()
        .package
        .expect("scenario package imports");

    if let Some(filter) = scenario_value["source_filter"].as_array() {
        let keep = filter
            .iter()
            .map(|value| value.as_str().expect("source id filter is string"))
            .collect::<BTreeSet<_>>();
        package
            .sources
            .retain(|source| keep.contains(source.source_id.as_str()));
    }
    package
}

fn scenario_oracle(artifact: &Value, scenario_value: &Value) -> IncidentReplayOracle {
    let oracle_source = if let Some(reference) = scenario_value["oracle_ref"].as_str() {
        &scenario(artifact, reference)["oracle"]
    } else {
        &scenario_value["oracle"]
    };
    serde_json::from_value(oracle_source.clone()).expect("scenario oracle parses")
}

fn scenario_config(scenario_value: &Value) -> IncidentReplayMinimizationConfig {
    serde_json::from_value(scenario_value["config"].clone()).expect("scenario config parses")
}

fn issue_tags(report: &asupersync::trace::IncidentReplayMinimizationReport) -> BTreeSet<String> {
    report
        .issues
        .iter()
        .map(|issue| issue.kind.as_str().to_string())
        .collect()
}

#[test]
fn artifact_catalog_matches_rust_minimizer_tags() {
    let artifact = contract();
    let oracle_tags: BTreeSet<String> = artifact["oracle_kinds"]
        .as_array()
        .expect("oracle kinds are listed")
        .iter()
        .map(|value| value.as_str().expect("oracle kind is string").to_string())
        .collect();
    let issue_tags: BTreeSet<String> = artifact["issue_kinds"]
        .as_array()
        .expect("issue kinds are listed")
        .iter()
        .map(|value| value.as_str().expect("issue kind is string").to_string())
        .collect();
    let step_tags: BTreeSet<String> = artifact["shrink_step_kinds"]
        .as_array()
        .expect("step kinds are listed")
        .iter()
        .map(|value| value.as_str().expect("step kind is string").to_string())
        .collect();

    let rust_oracles = [
        IncidentOracleKind::Panic,
        IncidentOracleKind::CancellationLeak,
        IncidentOracleKind::ObligationLeak,
        IncidentOracleKind::QuiescenceViolation,
        IncidentOracleKind::ProtocolError,
        IncidentOracleKind::ClaimDrift,
        IncidentOracleKind::ProofCommandFailure,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect::<BTreeSet<_>>();
    let rust_issues = [
        IncidentReplayMinimizationIssueKind::EmptyTrace,
        IncidentReplayMinimizationIssueKind::FlakyOracle,
        IncidentReplayMinimizationIssueKind::BudgetExhausted,
        IncidentReplayMinimizationIssueKind::MissingOracleSourceRole,
        IncidentReplayMinimizationIssueKind::MissingOracleTraceFingerprint,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect::<BTreeSet<_>>();
    let rust_steps = [
        IncidentReplayShrinkStepKind::RemoveSource,
        IncidentReplayShrinkStepKind::RemoveFeatureFlag,
        IncidentReplayShrinkStepKind::KeepRequired,
        IncidentReplayShrinkStepKind::BudgetExhausted,
    ]
    .into_iter()
    .map(|kind| {
        serde_json::to_value(kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
    .collect::<BTreeSet<_>>();

    assert_eq!(oracle_tags, rust_oracles);
    assert_eq!(issue_tags, rust_issues);
    assert_eq!(step_tags, rust_steps);
    assert_eq!(
        artifact["minimized_repro_schema_version"].as_u64(),
        Some(u64::from(INCIDENT_MINIMIZED_REPRO_SCHEMA_VERSION))
    );
}

#[test]
fn contract_scenarios_produce_expected_verdicts() {
    let artifact = contract();
    for scenario_value in artifact["scenarios"].as_array().expect("scenarios") {
        let sid = scenario_value["scenario_id"].as_str().expect("scenario id");
        let package = scenario_package(&artifact, scenario_value);
        let oracle = scenario_oracle(&artifact, scenario_value);
        let config = scenario_config(scenario_value);
        let report = minimize_incident_replay_package(&package, oracle, config);
        let expected = scenario_value["expected_verdict"]
            .as_str()
            .expect("expected verdict is string");
        let actual = serde_json::to_value(report.verdict)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(actual, expected, "{sid}: {report:#?}");
        if let Some(expected_issues) = scenario_value["expected_issue_kinds"].as_array() {
            let expected_issues = expected_issues
                .iter()
                .map(|value| value.as_str().expect("issue is string").to_string())
                .collect::<BTreeSet<_>>();
            assert!(
                expected_issues.is_subset(&issue_tags(&report)),
                "{sid}: expected issues {expected_issues:?}, got {:?}",
                issue_tags(&report)
            );
        }
    }
}

#[test]
fn minimized_fixture_shrinks_and_preserves_oracle() {
    let artifact = contract();
    let scenario_value = scenario(&artifact, "minimize-crashpack-trace");
    let package = scenario_package(&artifact, scenario_value);
    let report = minimize_incident_replay_package(
        &package,
        scenario_oracle(&artifact, scenario_value),
        scenario_config(scenario_value),
    );
    let repro = report.repro.expect("minimized repro emitted");

    assert_eq!(report.verdict, IncidentReplayMinimizationVerdict::Minimized);
    assert!(repro.summary.minimized_units < repro.summary.original_units);
    assert_eq!(repro.retained_sources.len(), 1);
    assert_eq!(repro.removed_source_ids, ["trace-log-main"]);
    assert!(
        repro.steps.iter().any(|step| {
            step.kind == IncidentReplayShrinkStepKind::RemoveSource && step.accepted
        })
    );
}

#[test]
fn no_reduction_fixture_emits_already_minimal_repro() {
    let artifact = contract();
    let scenario_value = scenario(&artifact, "already-minimal-single-source");
    let package = scenario_package(&artifact, scenario_value);
    let report = minimize_incident_replay_package(
        &package,
        scenario_oracle(&artifact, scenario_value),
        scenario_config(scenario_value),
    );
    let repro = report.repro.expect("already minimal repro emitted");

    assert_eq!(
        report.verdict,
        IncidentReplayMinimizationVerdict::AlreadyMinimal
    );
    assert_eq!(repro.summary.minimized_units, repro.summary.original_units);
    assert!(repro.removed_source_ids.is_empty());
}

#[test]
fn repro_json_round_trip_is_stable() {
    let artifact = contract();
    let scenario_value = scenario(&artifact, "minimize-crashpack-trace");
    let package = scenario_package(&artifact, scenario_value);
    let repro = minimize_incident_replay_package(
        &package,
        scenario_oracle(&artifact, scenario_value),
        scenario_config(scenario_value),
    )
    .repro
    .expect("repro emitted");
    let json = repro.to_json().expect("repro serializes");
    let parsed = IncidentMinimizedReplayRepro::from_json(&json).expect("repro parses");

    assert_eq!(repro.repro_id, parsed.repro_id);
    assert_eq!(repro, parsed);
}

#[test]
fn artifact_lists_script_logs_and_rch_proof_commands() {
    let artifact = contract();
    assert_eq!(artifact["e2e_script"].as_str(), Some(SCRIPT_PATH));
    assert!(
        std::path::Path::new(SCRIPT_PATH).exists(),
        "fixture runner must exist"
    );

    let log_fields = artifact["required_log_fields"]
        .as_array()
        .expect("required log fields")
        .iter()
        .map(|value| value.as_str().expect("log field is string").to_string())
        .collect::<BTreeSet<_>>();
    for field in [
        "scenario_id",
        "bead_id",
        "bundle_id",
        "verdict",
        "repro_id",
        "issue_kinds",
        "step_count",
        "artifact_path",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
    }

    let commands = artifact["proof_commands"]
        .as_array()
        .expect("proof commands are present");
    assert!(commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|text| text.contains("rch exec"))
    }));
    assert!(commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|text| text.contains("incident_replay_minimization"))
    }));
}
