//! Contract tests for operator-facing incident proof reports.

use asupersync::trace::{
    INCIDENT_PROOF_REPORT_SCHEMA_VERSION, IncidentBundle, IncidentProofEvidenceQuality,
    IncidentProofReport, IncidentProofReportGateConfig, IncidentProofReportStatus,
    IncidentProofReportValidationIssueKind, IncidentProofSupportClass,
    IncidentRegressionPromotionPolicy, IncidentRegressionPromotionReport,
    IncidentRegressionPromotionVerdict, IncidentRegressionProofTarget, IncidentReplayImportReport,
    IncidentReplayMinimizationConfig, IncidentReplayMinimizationReport, IncidentReplayOracle,
    build_incident_proof_report, promote_minimized_incident_repro,
    render_incident_proof_report_summary, validate_incident_proof_report,
    validate_incident_proof_report_json,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const PROOF_REPORT_CONTRACT_PATH: &str = "artifacts/incident_proof_report_contract_v1.json";
const PROMOTION_CONTRACT_PATH: &str = "artifacts/incident_replay_promotion_contract_v1.json";
const MINIMIZATION_CONTRACT_PATH: &str = "artifacts/incident_replay_minimization_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_incident_proof_report.sh";

fn json_file(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn proof_report_contract() -> Value {
    json_file(PROOF_REPORT_CONTRACT_PATH)
}

fn promotion_contract() -> Value {
    json_file(PROMOTION_CONTRACT_PATH)
}

fn minimization_contract() -> Value {
    json_file(MINIMIZATION_CONTRACT_PATH)
}

fn scenario<'a>(artifact: &'a Value, id: &str) -> &'a Value {
    artifact["scenarios"]
        .as_array()
        .expect("scenarios are present")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("scenario {id} is present"))
}

fn bundle_for_scenario(artifact: &Value, scenario_value: &Value) -> IncidentBundle {
    let bundle_source = if let Some(reference) = scenario_value["bundle_ref"].as_str() {
        &scenario(artifact, reference)["bundle"]
    } else {
        &scenario_value["bundle"]
    };
    serde_json::from_value(bundle_source.clone()).expect("scenario bundle parses")
}

fn oracle_for_scenario(artifact: &Value, scenario_value: &Value) -> IncidentReplayOracle {
    let oracle_source = if let Some(reference) = scenario_value["oracle_ref"].as_str() {
        &scenario(artifact, reference)["oracle"]
    } else {
        &scenario_value["oracle"]
    };
    serde_json::from_value(oracle_source.clone()).expect("scenario oracle parses")
}

fn config_for_scenario(scenario_value: &Value) -> IncidentReplayMinimizationConfig {
    serde_json::from_value(scenario_value["config"].clone()).expect("scenario config parses")
}

fn minimization_report_for_scenario(
    id: &str,
) -> (IncidentReplayImportReport, IncidentReplayMinimizationReport) {
    let artifact = minimization_contract();
    let scenario_value = scenario(&artifact, id);
    let bundle = bundle_for_scenario(&artifact, scenario_value);
    let mut import_report = bundle.import_replay_package();
    if let Some(filter) = scenario_value["source_filter"].as_array() {
        let keep = filter
            .iter()
            .map(|value| value.as_str().expect("source id filter is string"))
            .collect::<BTreeSet<_>>();
        import_report
            .package
            .as_mut()
            .expect("scenario package imports")
            .sources
            .retain(|source| keep.contains(source.source_id.as_str()));
    }
    let package = import_report
        .package
        .clone()
        .expect("scenario package imports");
    let minimization_report = package.minimize_repro(
        oracle_for_scenario(&artifact, scenario_value),
        config_for_scenario(scenario_value),
    );
    (import_report, minimization_report)
}

fn policy_for_promotion_scenario(
    promotion_artifact: &Value,
    scenario_value: &Value,
) -> IncidentRegressionPromotionPolicy {
    let mut policy: IncidentRegressionPromotionPolicy =
        serde_json::from_value(scenario_value["policy"].clone()).expect("promotion policy parses");
    if let Some(reference) = scenario_value["duplicate_seed_from_scenario"].as_str() {
        let base = scenario(promotion_artifact, reference);
        let (_, base_minimization) = minimization_report_for_scenario(
            base["minimization_scenario"]
                .as_str()
                .expect("base minimization scenario"),
        );
        let base_repro = base_minimization.repro.expect("base scenario emits repro");
        let base_policy: IncidentRegressionPromotionPolicy =
            serde_json::from_value(base["policy"].clone()).expect("base policy parses");
        let seed_id = promote_minimized_incident_repro(&base_repro, base_policy)
            .proof
            .expect("base scenario promotes")
            .seed_id;
        policy.existing_seed_ids.push(seed_id);
    }
    policy
}

fn proof_report_for_promotion_scenario(id: &str) -> IncidentProofReport {
    let artifact = promotion_contract();
    let scenario_value = scenario(&artifact, id);
    let minimization_scenario = scenario_value["minimization_scenario"]
        .as_str()
        .expect("minimization scenario");
    let (import_report, minimization_report) =
        minimization_report_for_scenario(minimization_scenario);
    let repro = minimization_report
        .repro
        .as_ref()
        .unwrap_or_else(|| panic!("{id} emits a repro"));
    let policy = policy_for_promotion_scenario(&artifact, scenario_value);
    let expected_hashes = policy.expected_fixture_hashes.clone();
    let promotion_report = promote_minimized_incident_repro(repro, policy);
    build_incident_proof_report(
        id,
        "incident-redaction-v1",
        &import_report,
        &minimization_report,
        &promotion_report,
        expected_hashes,
    )
}

fn proof_report_for_minimizer_scenario(
    id: &str,
    promotion_report: IncidentRegressionPromotionReport,
) -> IncidentProofReport {
    let (import_report, minimization_report) = minimization_report_for_scenario(id);
    build_incident_proof_report(
        id,
        "incident-redaction-v1",
        &import_report,
        &minimization_report,
        &promotion_report,
        BTreeMap::new(),
    )
}

fn placeholder_blocked_promotion(repro_id: &str) -> IncidentRegressionPromotionReport {
    IncidentRegressionPromotionReport {
        verdict: IncidentRegressionPromotionVerdict::Blocked,
        target: IncidentRegressionProofTarget::UnitTest,
        repro_id: repro_id.to_string(),
        proof: None,
        blocks: Vec::new(),
    }
}

fn status_tags() -> BTreeSet<String> {
    [
        IncidentProofReportStatus::Pass,
        IncidentProofReportStatus::Fail,
        IncidentProofReportStatus::Blocked,
        IncidentProofReportStatus::FixtureOnly,
        IncidentProofReportStatus::Flaky,
        IncidentProofReportStatus::Unsupported,
        IncidentProofReportStatus::NoWin,
    ]
    .into_iter()
    .map(|status| status.as_str().to_string())
    .collect()
}

fn support_class_tags() -> BTreeSet<String> {
    [
        IncidentProofSupportClass::ExecutableRegression,
        IncidentProofSupportClass::FixtureOnly,
        IncidentProofSupportClass::FollowUpRequired,
        IncidentProofSupportClass::Unsupported,
        IncidentProofSupportClass::NoWin,
    ]
    .into_iter()
    .map(|class| class.as_str().to_string())
    .collect()
}

fn evidence_quality_tags() -> BTreeSet<String> {
    [
        IncidentProofEvidenceQuality::Trusted,
        IncidentProofEvidenceQuality::Partial,
        IncidentProofEvidenceQuality::Blocked,
        IncidentProofEvidenceQuality::Rejected,
    ]
    .into_iter()
    .map(|quality| quality.as_str().to_string())
    .collect()
}

fn validation_issue_tags() -> BTreeSet<String> {
    [
        IncidentProofReportValidationIssueKind::MalformedJson,
        IncidentProofReportValidationIssueKind::UnsupportedSchemaVersion,
        IncidentProofReportValidationIssueKind::MissingRequiredField,
        IncidentProofReportValidationIssueKind::MissingProofCommand,
        IncidentProofReportValidationIssueKind::ProofCommandNotRch,
        IncidentProofReportValidationIssueKind::StaleFixtureHash,
        IncidentProofReportValidationIssueKind::RedactionFailure,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

#[test]
fn artifact_catalog_matches_rust_report_tags() {
    let artifact = proof_report_contract();
    let artifact_statuses = artifact["report_statuses"]
        .as_array()
        .expect("report statuses")
        .iter()
        .map(|value| value.as_str().expect("status is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_support = artifact["support_classes"]
        .as_array()
        .expect("support classes")
        .iter()
        .map(|value| value.as_str().expect("support class is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_quality = artifact["evidence_qualities"]
        .as_array()
        .expect("evidence qualities")
        .iter()
        .map(|value| value.as_str().expect("quality is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_issues = artifact["validation_issue_kinds"]
        .as_array()
        .expect("validation issue kinds")
        .iter()
        .map(|value| value.as_str().expect("issue is string").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(artifact_statuses, status_tags());
    assert_eq!(artifact_support, support_class_tags());
    assert_eq!(artifact_quality, evidence_quality_tags());
    assert_eq!(artifact_issues, validation_issue_tags());
    assert_eq!(
        artifact["proof_report_schema_version"].as_u64(),
        Some(u64::from(INCIDENT_PROOF_REPORT_SCHEMA_VERSION))
    );
}

#[test]
fn promoted_report_serializes_and_validates_with_rch_command() {
    let report = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    assert_eq!(report.status, IncidentProofReportStatus::Pass);
    assert_eq!(
        report.support_class,
        IncidentProofSupportClass::ExecutableRegression
    );
    assert_eq!(
        report.evidence_quality,
        IncidentProofEvidenceQuality::Trusted
    );
    assert!(report.report_id.starts_with("incident-proof-report-v1:"));
    assert!(
        report
            .proof_commands
            .iter()
            .any(|command| command.command_line.contains("rch exec"))
    );

    let validation =
        validate_incident_proof_report(&report, IncidentProofReportGateConfig::default());
    assert!(validation.accepted, "{validation:#?}");

    let json = serde_json::to_string_pretty(&report).expect("report serializes");
    let json_validation =
        validate_incident_proof_report_json(&json, IncidentProofReportGateConfig::default());
    assert!(json_validation.accepted, "{json_validation:#?}");
}

#[test]
fn aggregation_distinguishes_fixture_blocked_flaky_unsupported_no_win_and_fail() {
    let fixture = proof_report_for_promotion_scenario("fixture-only-redacted-repro");
    assert_eq!(fixture.status, IncidentProofReportStatus::FixtureOnly);
    assert_eq!(
        fixture.support_class,
        IncidentProofSupportClass::FixtureOnly
    );
    assert_eq!(
        fixture.evidence_quality,
        IncidentProofEvidenceQuality::Partial
    );

    let blocked = proof_report_for_promotion_scenario("block-stale-fixture-hash");
    assert_eq!(blocked.status, IncidentProofReportStatus::Blocked);
    assert_eq!(
        blocked.support_class,
        IncidentProofSupportClass::FollowUpRequired
    );
    assert!(
        blocked
            .block_kinds
            .contains(&"stale_fixture_hash".to_string())
    );
    let blocked_validation =
        validate_incident_proof_report(&blocked, IncidentProofReportGateConfig::default());
    assert!(
        blocked_validation.contains_issue(IncidentProofReportValidationIssueKind::StaleFixtureHash)
    );

    let flaky =
        proof_report_for_minimizer_scenario("flaky-oracle", placeholder_blocked_promotion("flaky"));
    assert_eq!(flaky.status, IncidentProofReportStatus::Flaky);
    assert_eq!(
        flaky.support_class,
        IncidentProofSupportClass::FollowUpRequired
    );
    assert!(flaky.block_kinds.contains(&"flaky_oracle".to_string()));

    let no_win = proof_report_for_minimizer_scenario(
        "budget-exhausted",
        placeholder_blocked_promotion("budget"),
    );
    assert_eq!(no_win.status, IncidentProofReportStatus::NoWin);
    assert_eq!(no_win.support_class, IncidentProofSupportClass::NoWin);
    assert!(no_win.block_kinds.contains(&"budget_exhausted".to_string()));

    let unsupported = proof_report_for_promotion_scenario("unsupported-conformance-target");
    assert_eq!(unsupported.status, IncidentProofReportStatus::Unsupported);
    assert_eq!(
        unsupported.support_class,
        IncidentProofSupportClass::Unsupported
    );
    assert!(
        unsupported
            .block_kinds
            .contains(&"unsupported_promotion_target".to_string())
    );

    let mut failing = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    failing.status = IncidentProofReportStatus::Fail;
    failing.support_class = IncidentProofSupportClass::ExecutableRegression;
    failing.evidence_quality = IncidentProofEvidenceQuality::Rejected;
    failing.human_summary = render_incident_proof_report_summary(&failing);
    let failing_validation =
        validate_incident_proof_report(&failing, IncidentProofReportGateConfig::default());
    assert!(failing_validation.accepted, "{failing_validation:#?}");
}

#[test]
fn validation_rejects_required_fields_redaction_missing_commands_and_non_rch_commands() {
    let mut report = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    report.incident_id.clear();
    let validation =
        validate_incident_proof_report(&report, IncidentProofReportGateConfig::default());
    assert!(
        validation.contains_issue(IncidentProofReportValidationIssueKind::MissingRequiredField)
    );

    let mut report = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    report.redaction_passed = false;
    let validation =
        validate_incident_proof_report(&report, IncidentProofReportGateConfig::default());
    assert!(validation.contains_issue(IncidentProofReportValidationIssueKind::RedactionFailure));

    let mut report = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    report.proof_commands.clear();
    let validation =
        validate_incident_proof_report(&report, IncidentProofReportGateConfig::default());
    assert!(validation.contains_issue(IncidentProofReportValidationIssueKind::MissingProofCommand));

    let mut report = proof_report_for_promotion_scenario("promote-crashpack-unit-proof");
    let command = report
        .proof_commands
        .first_mut()
        .expect("proof command is present");
    command.command.program = "cargo".to_string();
    command.command_line = "cargo test -p asupersync --test incident_proof_report".to_string();
    command.executable_through_rch = false;
    let validation =
        validate_incident_proof_report(&report, IncidentProofReportGateConfig::default());
    assert!(validation.contains_issue(IncidentProofReportValidationIssueKind::ProofCommandNotRch));

    let malformed =
        validate_incident_proof_report_json("{not-json", IncidentProofReportGateConfig::default());
    assert!(malformed.contains_issue(IncidentProofReportValidationIssueKind::MalformedJson));
}

#[test]
fn summaries_are_concise_and_preserve_blocked_and_no_win_status_words() {
    let blocked = proof_report_for_promotion_scenario("block-stale-fixture-hash");
    assert!(blocked.human_summary.contains("status=blocked"));
    assert!(blocked.human_summary.contains("stale_fixture_hash"));

    let no_win = proof_report_for_minimizer_scenario(
        "budget-exhausted",
        placeholder_blocked_promotion("budget"),
    );
    assert!(no_win.human_summary.contains("status=no_win"));
    assert!(no_win.human_summary.contains("proof_commands=0"));
}

#[test]
fn fixture_script_emits_required_rows_and_fails_closed_for_bad_inputs() {
    let artifact = proof_report_contract();
    assert_eq!(artifact["e2e_script"].as_str(), Some(SCRIPT_PATH));
    assert!(std::path::Path::new(SCRIPT_PATH).exists());

    let output_root = "target/incident-proof-report-test";
    let run_id = "rust-test";
    let status = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("--output-root")
        .arg(output_root)
        .arg("--run-id")
        .arg(run_id)
        .status()
        .expect("proof report validation script runs");
    assert!(status.success(), "script exited with {status}");

    let log_path = format!("{output_root}/{run_id}/incident-proof-report-events.ndjson");
    let log = std::fs::read_to_string(&log_path).expect("read script log");
    let events = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON parses"))
        .collect::<Vec<_>>();
    let statuses = events
        .iter()
        .map(|event| event["status"].as_str().expect("status").to_string())
        .collect::<BTreeSet<_>>();
    for expected in ["pass", "blocked", "flaky", "unsupported", "no_win"] {
        assert!(statuses.contains(expected), "missing status {expected}");
    }
    assert!(
        events.iter().any(|event| event["validation_issue_kinds"]
            .as_array()
            .expect("issue kinds")
            .iter()
            .any(|kind| kind.as_str() == Some("malformed_json"))),
        "script must emit a malformed JSON gate row"
    );
    assert!(
        events
            .iter()
            .filter_map(|event| event["proof_command"].as_str())
            .any(|command| command.contains("rch exec")),
        "script must record an rch proof command"
    );

    let missing_artifact = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("--artifact")
        .arg("target/incident-proof-report-test/missing-artifact.json")
        .status()
        .expect("missing artifact check runs");
    assert!(!missing_artifact.success(), "missing artifact must fail");

    std::fs::create_dir_all("target/incident-proof-report-test").expect("create test output dir");
    let malformed_jsonl = "target/incident-proof-report-test/malformed.ndjson";
    std::fs::write(malformed_jsonl, "{not-json\n").expect("write malformed jsonl");
    let malformed_status = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("--input-jsonl")
        .arg(malformed_jsonl)
        .status()
        .expect("malformed JSONL check runs");
    assert!(!malformed_status.success(), "malformed JSONL must fail");

    let mut unsupported = proof_report_for_promotion_scenario("unsupported-conformance-target");
    unsupported.human_summary = render_incident_proof_report_summary(&unsupported);
    let unsupported_path = "target/incident-proof-report-test/unsupported-report.json";
    std::fs::write(
        unsupported_path,
        serde_json::to_string_pretty(&unsupported).expect("unsupported report serializes"),
    )
    .expect("write unsupported report");
    let unsupported_status = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("--gate-report")
        .arg(unsupported_path)
        .status()
        .expect("unsupported report gate runs");
    assert!(
        !unsupported_status.success(),
        "unsupported source report must fail the CI gate mode"
    );
}
