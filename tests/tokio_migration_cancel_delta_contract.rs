#![allow(missing_docs)]

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/tokio_migration_cancel_delta_contract_v1.json";
const SHADOW_CONTRACT_PATH: &str = "artifacts/tokio_migration_shadow_workload_contract_v1.json";

#[derive(Debug, Deserialize)]
struct CancelDeltaContract {
    contract_version: String,
    schema_version: String,
    generated_for_bead: String,
    shadow_runner: String,
    source_workload_contract: String,
    comparison_policy: String,
    required_delta_ids: Vec<String>,
    required_report_fields: Vec<String>,
    golden_artifacts: Vec<GoldenArtifact>,
    validation_commands: Vec<String>,
    deltas: Vec<CancelDelta>,
}

#[derive(Debug, Deserialize)]
struct GoldenArtifact {
    artifact_id: String,
    delta_id: String,
    classification: String,
    projection_hash: u64,
}

#[derive(Debug, Deserialize)]
struct CancelDelta {
    delta_id: String,
    source_shadow_scenario_id: String,
    tokio_idiom: String,
    invariant_name: String,
    classification: String,
    tokio_reference_observation: String,
    asupersync_proof_row: String,
    caveat_text: String,
    safe_migration_rewrite: String,
    expected_projection: Value,
}

fn repo_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn load_contract() -> CancelDeltaContract {
    let text = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .expect("cancel delta contract should exist");
    serde_json::from_str(&text).expect("cancel delta contract should parse")
}

fn load_shadow_scenario_ids() -> BTreeSet<String> {
    let text = std::fs::read_to_string(repo_path(SHADOW_CONTRACT_PATH))
        .expect("shadow workload contract should exist");
    let value: Value = serde_json::from_str(&text).expect("shadow workload contract should parse");
    value["scenarios"]
        .as_array()
        .expect("shadow scenarios should be an array")
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("shadow scenario id should be a string")
                .to_string()
        })
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn projection_hash(delta: &CancelDelta) -> u64 {
    let projection = json!({
        "delta_id": delta.delta_id,
        "source_shadow_scenario_id": delta.source_shadow_scenario_id,
        "invariant_name": delta.invariant_name,
        "classification": delta.classification,
        "expected_projection": delta.expected_projection,
    });
    let bytes = serde_json::to_vec(&projection).expect("projection should serialize");
    fnv1a64(&bytes)
}

fn report_row(delta: &CancelDelta) -> Value {
    json!({
        "delta_id": delta.delta_id,
        "source_shadow_scenario_id": delta.source_shadow_scenario_id,
        "tokio_idiom": delta.tokio_idiom,
        "invariant_name": delta.invariant_name,
        "tokio_reference_observation": delta.tokio_reference_observation,
        "asupersync_proof_row": delta.asupersync_proof_row,
        "caveat_text": delta.caveat_text,
        "safe_migration_rewrite": delta.safe_migration_rewrite,
        "classification": delta.classification,
        "projection_hash": projection_hash(delta),
    })
}

#[test]
fn contract_declares_stable_version_and_runner_inputs() {
    let contract = load_contract();

    assert_eq!(contract.contract_version, "tokio-migration-cancel-delta-v1");
    assert_eq!(
        contract.schema_version,
        "tokio-migration-cancel-delta-schema-v1"
    );
    assert_eq!(contract.generated_for_bead, "asupersync-candeb");
    assert_eq!(
        contract.shadow_runner,
        "scripts/run_tokio_migration_shadow_workload_smoke.sh"
    );
    assert_eq!(
        contract.source_workload_contract,
        "artifacts/tokio_migration_shadow_workload_contract_v1.json"
    );
    assert_eq!(
        contract.comparison_policy,
        "conservative_reference_observation_not_marketing_claim"
    );
}

#[test]
fn all_required_migration_deltas_are_covered_once() {
    let contract = load_contract();
    let required: BTreeSet<_> = contract.required_delta_ids.iter().cloned().collect();
    let actual: BTreeSet<_> = contract
        .deltas
        .iter()
        .map(|delta| delta.delta_id.clone())
        .collect();

    assert_eq!(actual, required);
    assert_eq!(
        contract.deltas.len(),
        actual.len(),
        "delta ids must be unique"
    );

    for expected in [
        "two_phase_send_no_loss",
        "losers_drained",
        "region_close_quiescence",
        "no_obligation_leak",
    ] {
        assert!(
            contract
                .deltas
                .iter()
                .any(|delta| delta.invariant_name == expected),
            "missing invariant {expected}"
        );
    }
}

#[test]
fn every_delta_links_to_a_shadow_workload_scenario() {
    let contract = load_contract();
    let shadow_ids = load_shadow_scenario_ids();

    for delta in &contract.deltas {
        assert!(
            shadow_ids.contains(&delta.source_shadow_scenario_id),
            "delta {} references missing shadow scenario {}",
            delta.delta_id,
            delta.source_shadow_scenario_id
        );
    }
}

#[test]
fn report_rows_include_reference_candidate_caveat_and_rewrite() {
    let contract = load_contract();
    let required_fields: BTreeSet<_> = contract.required_report_fields.iter().cloned().collect();

    for delta in &contract.deltas {
        let row = report_row(delta);
        for field in &required_fields {
            assert!(row.get(field).is_some(), "missing field {field}: {row}");
        }
        assert!(
            delta.tokio_reference_observation.contains("Tokio")
                || delta.tokio_reference_observation.contains("tokio"),
            "reference observation should name Tokio: {}",
            delta.tokio_reference_observation
        );
        assert!(
            delta.asupersync_proof_row.contains("asupersync")
                || delta.asupersync_proof_row.contains("Scope")
                || delta.asupersync_proof_row.contains("Sender"),
            "proof row should name the asupersync side: {}",
            delta.asupersync_proof_row
        );
        assert!(
            !delta.caveat_text.is_empty() && !delta.safe_migration_rewrite.is_empty(),
            "delta {} needs caveat and rewrite guidance",
            delta.delta_id
        );
    }
}

#[test]
fn golden_loss_and_no_loss_projection_hashes_are_stable() {
    let contract = load_contract();
    let by_id: BTreeMap<_, _> = contract
        .deltas
        .iter()
        .map(|delta| (delta.delta_id.as_str(), delta))
        .collect();

    for golden in &contract.golden_artifacts {
        assert!(
            golden.artifact_id.starts_with("TM-CANCEL-GOLDEN-"),
            "unstable golden id {}",
            golden.artifact_id
        );
        let delta = by_id
            .get(golden.delta_id.as_str())
            .unwrap_or_else(|| panic!("golden references missing delta {}", golden.delta_id));
        assert_eq!(golden.classification, delta.classification);
        assert_eq!(
            projection_hash(delta),
            golden.projection_hash,
            "golden projection hash drifted for {}",
            golden.artifact_id
        );
    }

    let classes: BTreeSet<_> = contract
        .golden_artifacts
        .iter()
        .map(|golden| golden.classification.as_str())
        .collect();
    assert!(classes.contains("loss_case"));
    assert!(classes.contains("no_loss_case"));
}

#[test]
fn validation_commands_route_expensive_work_through_rch_and_runner_modes() {
    let contract = load_contract();
    let joined = contract.validation_commands.join("\n");

    assert!(joined.contains("rch exec -- rustfmt"));
    assert!(joined.contains("rch exec -- env CARGO_INCREMENTAL=0"));
    assert!(joined.contains("--dry-run"));
    assert!(joined.contains("--execute"));
    assert!(
        joined.contains("scripts/run_tokio_migration_shadow_workload_smoke.sh"),
        "validation should use the shadow runner"
    );
}
