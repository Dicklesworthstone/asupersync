#![allow(missing_docs)]

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const SIGNOFF_PATH: &str = "artifacts/tokio_migration_proof_pack_signoff_v1.json";
const NO_TOKIO_GRAPH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_migsgn_no_tokio cargo tree -e normal -p asupersync -i tokio";
const STALE_NO_TOKIO_GRAPH_COMMAND: &str =
    "rch exec -- cargo tree -e normal -p asupersync -i tokio";

#[derive(Debug, Deserialize)]
struct Signoff {
    contract_version: String,
    schema_version: String,
    generated_for_bead: String,
    proof_pack_epic: String,
    final_verdict: String,
    proof_pack_hash: u64,
    required_child_beads: Vec<String>,
    source_contracts: BTreeMap<String, SourceContract>,
    child_evidence: Vec<ChildEvidence>,
    no_tokio_graph_proof: NoTokioGraphProof,
    graph_health: GraphHealth,
    dirty_tree_scope: DirtyTreeScope,
    validation_commands: Vec<String>,
    residual_limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SourceContract {
    path: String,
    contract_version: String,
}

#[derive(Debug, Deserialize)]
struct ChildEvidence {
    bead_id: String,
    status: String,
    commits: Vec<String>,
    touched_file_groups: Vec<String>,
    rch_commands: Vec<String>,
    local_commands: Vec<String>,
    generated_artifact_paths: Vec<String>,
    projection_hashes: BTreeMap<String, u64>,
    no_win_hold_verdicts: Vec<String>,
    residual_limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NoTokioGraphProof {
    command: String,
    expected_stdout: String,
    observed_stdout: String,
}

#[derive(Debug, Deserialize)]
struct GraphHealth {
    command: String,
    result: String,
    blocks_signoff: bool,
    operator_note: String,
}

#[derive(Debug, Deserialize)]
struct DirtyTreeScope {
    migration_paths_dirty: Vec<String>,
    known_unrelated_active_paths: Vec<String>,
    operator_note: String,
}

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn load_signoff() -> Signoff {
    let text =
        std::fs::read_to_string(repo_path(SIGNOFF_PATH)).expect("signoff contract should exist");
    serde_json::from_str(&text).expect("signoff contract should parse")
}

fn load_json(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_path(path))
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("failed to parse {path}: {err}"))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn proof_pack_text(signoff: &Signoff) -> String {
    let mut parts = vec![
        signoff.contract_version.clone(),
        signoff.final_verdict.clone(),
    ];
    for child in &signoff.child_evidence {
        parts.push(format!(
            "{}:{}:{}",
            child.bead_id,
            child.status,
            child.commits.join(",")
        ));
    }
    parts.join("|")
}

fn projection_hash(signoff: &Signoff) -> u64 {
    fnv1a64(proof_pack_text(signoff).as_bytes())
}

#[test]
fn signoff_declares_stable_version_and_final_verdict() {
    let signoff = load_signoff();

    assert_eq!(
        signoff.contract_version,
        "tokio-migration-proof-pack-signoff-v1"
    );
    assert_eq!(
        signoff.schema_version,
        "tokio-migration-proof-pack-signoff-schema-v1"
    );
    assert_eq!(signoff.generated_for_bead, "asupersync-migsgn");
    assert_eq!(signoff.proof_pack_epic, "asupersync-migprf");
    assert_eq!(
        signoff.final_verdict,
        "ready_for_operator_review_with_conservative_fallbacks"
    );
    assert_eq!(projection_hash(&signoff), signoff.proof_pack_hash);
}

#[test]
fn source_contract_versions_match_live_artifacts() {
    let signoff = load_signoff();

    for source in signoff.source_contracts.values() {
        let value = load_json(&source.path);
        assert_eq!(
            value["contract_version"], source.contract_version,
            "source contract version mismatch for {}",
            source.path
        );
    }
}

#[test]
fn all_child_beads_are_closed_in_live_tracker_and_evidence_rows() {
    let signoff = load_signoff();
    let required: BTreeSet<_> = signoff.required_child_beads.iter().cloned().collect();
    let actual: BTreeSet<_> = signoff
        .child_evidence
        .iter()
        .map(|child| child.bead_id.clone())
        .collect();

    assert_eq!(actual, required);
    for child in &signoff.child_evidence {
        assert_eq!(child.status, "closed", "child row is not closed: {child:?}");
        assert!(!child.commits.is_empty(), "missing commits: {child:?}");
        assert!(
            child
                .commits
                .iter()
                .all(|commit| commit.len() >= 8 && commit.chars().all(|c| c.is_ascii_hexdigit())),
            "commit ids should be concrete abbreviated hashes: {child:?}"
        );
        assert!(
            !child.touched_file_groups.is_empty(),
            "missing touched files: {child:?}"
        );
        assert!(
            !child.rch_commands.is_empty() || !child.local_commands.is_empty(),
            "missing validation commands: {child:?}"
        );
        assert!(
            !child.generated_artifact_paths.is_empty(),
            "missing generated artifacts: {child:?}"
        );
        assert!(
            !child.projection_hashes.is_empty(),
            "missing projection hashes or proof hash: {child:?}"
        );
        assert!(
            !child.residual_limitations.is_empty(),
            "every child needs residual limitation text: {child:?}"
        );
        if matches!(
            child.bead_id.as_str(),
            "asupersync-candeb" | "asupersync-miglat" | "asupersync-migrep"
        ) {
            assert!(
                !child.no_win_hold_verdicts.is_empty(),
                "child should carry no-win/hold/ready verdicts: {child:?}"
            );
        }
    }
}

#[test]
fn child_projection_hashes_match_source_contracts() {
    let signoff = load_signoff();
    let by_child: BTreeMap<_, _> = signoff
        .child_evidence
        .iter()
        .map(|child| (child.bead_id.as_str(), child))
        .collect();

    let cancel = load_json("artifacts/tokio_migration_cancel_delta_contract_v1.json");
    let cancel_hashes: BTreeMap<_, _> = cancel["golden_artifacts"]
        .as_array()
        .expect("cancel golden artifacts")
        .iter()
        .map(|golden| {
            (
                golden["artifact_id"].as_str().expect("artifact id"),
                golden["projection_hash"].as_u64().expect("projection hash"),
            )
        })
        .collect();
    assert_eq!(
        by_child["asupersync-candeb"].projection_hashes,
        cancel_hashes
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    );

    let perf = load_json("artifacts/tokio_migration_perf_report_contract_v1.json");
    for card in perf["report_cards"].as_array().expect("report cards") {
        let id = card["report_id"].as_str().expect("report id");
        let hash = card["projection_hash"].as_u64().expect("projection hash");
        assert_eq!(
            by_child["asupersync-miglat"].projection_hashes[id], hash,
            "perf projection hash mismatch for {id}"
        );
    }

    let operator = load_json("artifacts/tokio_migration_operator_report_contract_v1.json");
    for golden in operator["golden_reports"]
        .as_array()
        .expect("operator goldens")
    {
        let id = golden["artifact_id"].as_str().expect("artifact id");
        let hash = golden["projection_hash"].as_u64().expect("projection hash");
        assert_eq!(
            by_child["asupersync-migrep"].projection_hashes[id], hash,
            "operator projection hash mismatch for {id}"
        );
    }
}

#[test]
fn validation_commands_and_no_tokio_proof_are_explicit() {
    let signoff = load_signoff();
    let commands = signoff.validation_commands.join("\n");

    assert!(commands.contains("rch exec -- rustfmt"));
    assert!(commands.contains("rch exec -- env CARGO_INCREMENTAL=0"));
    assert!(commands.contains(NO_TOKIO_GRAPH_COMMAND));
    assert!(!commands.contains(STALE_NO_TOKIO_GRAPH_COMMAND));
    assert!(commands.contains("timeout 30s br dep cycles --json --blocking-only"));

    for command in signoff
        .validation_commands
        .iter()
        .filter(|command| command.starts_with("rch exec --") && command.contains(" cargo "))
    {
        assert!(
            command.contains("CARGO_TARGET_DIR="),
            "cargo validation commands must set CARGO_TARGET_DIR: {command}"
        );
    }

    for child in &signoff.child_evidence {
        assert!(
            child
                .rch_commands
                .iter()
                .all(|command| command.starts_with("rch exec --")),
            "all expensive child proof commands must use rch: {child:?}"
        );
        for command in child
            .rch_commands
            .iter()
            .filter(|command| command.starts_with("rch exec --") && command.contains(" cargo "))
        {
            assert_ne!(
                command, STALE_NO_TOKIO_GRAPH_COMMAND,
                "child no-Tokio graph proof must not use stale bare cargo routing: {child:?}"
            );
            assert!(
                command.contains("CARGO_TARGET_DIR="),
                "child cargo proof commands must set CARGO_TARGET_DIR: {command}"
            );
        }
    }

    assert_eq!(signoff.no_tokio_graph_proof.command, NO_TOKIO_GRAPH_COMMAND);
    assert_eq!(
        signoff.no_tokio_graph_proof.expected_stdout,
        "warning: nothing to print."
    );
    assert_eq!(
        signoff.no_tokio_graph_proof.observed_stdout,
        "warning: nothing to print."
    );
}

#[test]
fn graph_timeout_dirty_tree_scope_and_limitations_are_recorded() {
    let signoff = load_signoff();

    assert_eq!(
        signoff.graph_health.command,
        "timeout 30s br dep cycles --json --blocking-only"
    );
    assert_eq!(signoff.graph_health.result, "timeout_exit_124_no_output");
    assert!(
        !signoff.graph_health.blocks_signoff,
        "bounded graph-health timeout is recorded but should not erase child evidence"
    );
    assert!(signoff.graph_health.operator_note.contains("timeout"));

    assert!(
        signoff.dirty_tree_scope.migration_paths_dirty.is_empty(),
        "migration proof-pack paths must not be dirty at signoff"
    );
    assert!(
        signoff
            .dirty_tree_scope
            .known_unrelated_active_paths
            .iter()
            .any(|path| path.contains("signed_profile_bundle")),
        "known unrelated signed-profile work should be scoped away"
    );
    assert!(
        signoff
            .dirty_tree_scope
            .known_unrelated_active_paths
            .iter()
            .any(|path| path == "src/bytes/buf/buf_trait.rs"),
        "known unrelated Buf work should be scoped away"
    );
    assert!(
        signoff
            .dirty_tree_scope
            .operator_note
            .contains("No dirty tokio_migration")
    );

    let limitations = signoff.residual_limitations.join("\n");
    assert!(limitations.contains("real-host rollout"));
    assert!(limitations.contains("small-mode proxy"));
    assert!(limitations.contains("signed profile bundle"));
}
