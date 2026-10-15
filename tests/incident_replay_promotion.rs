//! Contract tests for minimized incident repro promotion.

use asupersync::trace::{
    INCIDENT_REGRESSION_PROOF_SCHEMA_VERSION, IncidentBundle, IncidentMinimizedReplayRepro,
    IncidentOracleKind, IncidentRegressionPromotionBlockKind, IncidentRegressionPromotionPolicy,
    IncidentRegressionPromotionVerdict, IncidentRegressionProofTarget,
    IncidentReplayMinimizationConfig, IncidentReplayOracle, IncidentReplayPackage,
    promote_minimized_incident_repro,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;

const PROMOTION_CONTRACT_PATH: &str = "artifacts/incident_replay_promotion_contract_v1.json";
const MINIMIZATION_CONTRACT_PATH: &str = "artifacts/incident_replay_minimization_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_incident_replay_promotion.sh";

fn json_file(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
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

fn repro_for_minimization_scenario(id: &str) -> IncidentMinimizedReplayRepro {
    let artifact = minimization_contract();
    let scenario_value = scenario(&artifact, id);
    scenario_package(&artifact, scenario_value)
        .minimize_repro(
            scenario_oracle(&artifact, scenario_value),
            scenario_config(scenario_value),
        )
        .repro
        .unwrap_or_else(|| panic!("scenario {id} emits a repro"))
}

fn policy_for_scenario(
    promotion_artifact: &Value,
    scenario_value: &Value,
) -> IncidentRegressionPromotionPolicy {
    let mut policy: IncidentRegressionPromotionPolicy =
        serde_json::from_value(scenario_value["policy"].clone()).expect("promotion policy parses");
    if let Some(reference) = scenario_value["duplicate_seed_from_scenario"].as_str() {
        let base = scenario(promotion_artifact, reference);
        let base_repro = repro_for_minimization_scenario(
            base["minimization_scenario"]
                .as_str()
                .expect("base minimization scenario"),
        );
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

fn target_tags() -> BTreeSet<String> {
    [
        IncidentRegressionProofTarget::UnitTest,
        IncidentRegressionProofTarget::IntegrationTest,
        IncidentRegressionProofTarget::GoldenArtifact,
        IncidentRegressionProofTarget::FuzzSeed,
        IncidentRegressionProofTarget::ConformanceFixture,
        IncidentRegressionProofTarget::FixtureOnly,
        IncidentRegressionProofTarget::BlockerBead,
    ]
    .into_iter()
    .map(|target| target.as_str().to_string())
    .collect()
}

fn verdict_tags() -> BTreeSet<String> {
    [
        IncidentRegressionPromotionVerdict::Promoted,
        IncidentRegressionPromotionVerdict::FixtureOnly,
        IncidentRegressionPromotionVerdict::Blocked,
    ]
    .into_iter()
    .map(|verdict| {
        serde_json::to_value(verdict)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
    .collect()
}

fn block_tags() -> BTreeSet<String> {
    [
        IncidentRegressionPromotionBlockKind::UnsupportedPromotionTarget,
        IncidentRegressionPromotionBlockKind::DuplicateSeed,
        IncidentRegressionPromotionBlockKind::StaleFixtureHash,
        IncidentRegressionPromotionBlockKind::MissingRedactionPolicy,
        IncidentRegressionPromotionBlockKind::ProofCommandNotRch,
        IncidentRegressionPromotionBlockKind::MissingBlockerBead,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

#[test]
fn artifact_catalog_matches_rust_promotion_tags() {
    let artifact = promotion_contract();
    let artifact_targets = artifact["promotion_targets"]
        .as_array()
        .expect("promotion targets")
        .iter()
        .map(|value| value.as_str().expect("target is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_verdicts = artifact["promotion_verdicts"]
        .as_array()
        .expect("promotion verdicts")
        .iter()
        .map(|value| value.as_str().expect("verdict is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_blocks = artifact["block_kinds"]
        .as_array()
        .expect("block kinds")
        .iter()
        .map(|value| value.as_str().expect("block is string").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(artifact_targets, target_tags());
    assert_eq!(artifact_verdicts, verdict_tags());
    assert_eq!(artifact_blocks, block_tags());
    assert_eq!(
        artifact["regression_proof_schema_version"].as_u64(),
        Some(u64::from(INCIDENT_REGRESSION_PROOF_SCHEMA_VERSION))
    );
}

#[test]
fn contract_scenarios_promote_or_block_as_declared() {
    let artifact = promotion_contract();
    for scenario_value in artifact["scenarios"].as_array().expect("scenarios") {
        let sid = scenario_value["scenario_id"].as_str().expect("scenario id");
        let repro = repro_for_minimization_scenario(
            scenario_value["minimization_scenario"]
                .as_str()
                .expect("minimization scenario"),
        );
        let policy = policy_for_scenario(&artifact, scenario_value);
        let report = promote_minimized_incident_repro(&repro, policy);
        let verdict = serde_json::to_value(report.verdict)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(
            verdict,
            scenario_value["expected_verdict"]
                .as_str()
                .expect("expected verdict"),
            "{sid}: {report:#?}"
        );
        assert_eq!(
            report.target.as_str(),
            scenario_value["expected_target"]
                .as_str()
                .expect("expected target"),
            "{sid}: {report:#?}"
        );
        if let Some(expected_blocks) = scenario_value["expected_block_kinds"].as_array() {
            let expected_blocks = expected_blocks
                .iter()
                .map(|value| value.as_str().expect("block is string").to_string())
                .collect::<BTreeSet<_>>();
            let actual_blocks = report
                .blocks
                .iter()
                .map(|block| block.kind.as_str().to_string())
                .collect::<BTreeSet<_>>();
            assert!(
                expected_blocks.is_subset(&actual_blocks),
                "{sid}: expected {expected_blocks:?}, got {actual_blocks:?}"
            );
        }
    }
}

#[test]
fn promoted_proof_preserves_oracle_summary_provenance_and_rch_command() {
    let artifact = promotion_contract();
    let scenario_value = scenario(&artifact, "promote-crashpack-unit-proof");
    let repro = repro_for_minimization_scenario(
        scenario_value["minimization_scenario"]
            .as_str()
            .expect("minimization scenario"),
    );
    let report =
        promote_minimized_incident_repro(&repro, policy_for_scenario(&artifact, scenario_value));
    let proof = report.proof.expect("promoted proof emitted");

    assert_eq!(proof.oracle, repro.oracle);
    assert_eq!(proof.oracle.kind, IncidentOracleKind::Panic);
    assert_eq!(proof.minimization_summary, repro.summary);
    assert_eq!(proof.retained_feature_flags, repro.retained_feature_flags);
    assert_eq!(proof.provenance, repro.provenance);
    assert_eq!(proof.redaction_policy_id, "incident-redaction-v1");
    assert_eq!(
        proof.retained_source_hashes["crashpack-main"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let command = proof
        .proof_commands
        .first()
        .expect("proof command is present");
    assert!(command.executable_through_rch);
    assert!(command.command_line.contains("rch exec"));
    assert!(command.command_line.contains("cargo test"));
}

#[test]
fn fixture_e2e_script_declares_required_logs_and_emits_promoted_and_blocked_rows() {
    let artifact = promotion_contract();
    assert_eq!(artifact["e2e_script"].as_str(), Some(SCRIPT_PATH));
    assert!(std::path::Path::new(SCRIPT_PATH).exists());

    let required_log_fields = artifact["required_log_fields"]
        .as_array()
        .expect("required log fields")
        .iter()
        .map(|value| value.as_str().expect("field is string").to_string())
        .collect::<BTreeSet<_>>();
    for field in [
        "scenario_id",
        "bead_id",
        "verdict",
        "target",
        "proof_id",
        "block_kinds",
        "source_repro_id",
        "oracle_kind",
        "proof_command",
        "artifact_path",
    ] {
        assert!(
            required_log_fields.contains(field),
            "missing log field {field}"
        );
    }

    let output_root = "target/incident-replay-promotion-test";
    let run_id = "rust-test";
    let status = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("--output-root")
        .arg(output_root)
        .arg("--run-id")
        .arg(run_id)
        .status()
        .expect("promotion validation script runs");
    assert!(status.success(), "script exited with {status}");

    let log_path = format!("{output_root}/{run_id}/incident-replay-promotion-events.ndjson");
    let log = std::fs::read_to_string(&log_path).expect("read script log");
    let events = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON parses"))
        .collect::<Vec<_>>();
    assert!(
        events.iter().any(|event| event["verdict"] == "promoted"),
        "script must emit a promoted row"
    );
    assert!(
        events.iter().any(|event| event["verdict"] == "blocked"),
        "script must emit a blocked row"
    );
    assert!(
        events
            .iter()
            .filter_map(|event| event["proof_command"].as_str())
            .any(|command| command.contains("rch exec")),
        "script must record an rch proof command"
    );
}
