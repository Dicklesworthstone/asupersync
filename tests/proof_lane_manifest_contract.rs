#![allow(missing_docs)]

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CARGO_PATH: &str = "Cargo.toml";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const MANIFEST_PROJECTION_GOLDEN_PATH: &str =
    "tests/fixtures/proof_lane_manifest/manifest_projection.json";
const README_PATH: &str = "README.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn manifest() -> Value {
    serde_json::from_str(&read_repo_file(MANIFEST_PATH))
        .unwrap_or_else(|err| panic!("parse {MANIFEST_PATH}: {err}"))
}

fn manifest_projection_golden() -> Value {
    serde_json::from_str(&read_repo_file(MANIFEST_PROJECTION_GOLDEN_PATH))
        .unwrap_or_else(|err| panic!("parse {MANIFEST_PROJECTION_GOLDEN_PATH}: {err}"))
}

fn manifest_projection(manifest: &Value) -> Value {
    let lanes = array(manifest, "lanes")
        .iter()
        .map(|lane| {
            json!({
                "lane_id": lane["lane_id"].clone(),
                "kind": lane["kind"].clone(),
                "package": lane["package"].clone(),
                "command": lane["command"].clone(),
                "guarantee_ids": lane["guarantee_ids"].clone(),
                "feature_flags": lane["feature_flags"].clone(),
                "expected_signal": lane["expected_signal"].clone(),
                "source_paths": lane["source_paths"].clone(),
            })
        })
        .collect::<Vec<_>>();
    let guarantees = array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            json!({
                "guarantee_id": guarantee["guarantee_id"].clone(),
                "lane_ids": guarantee["lane_ids"].clone(),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "contract_version": manifest["contract_version"].clone(),
        "bead_id": manifest["bead_id"].clone(),
        "command_policy": manifest["command_policy"].clone(),
        "source_of_truth": manifest["source_of_truth"].clone(),
        "documentation_contract": manifest["documentation_contract"].clone(),
        "required_guarantee_ids": manifest["required_guarantee_ids"].clone(),
        "lanes": lanes,
        "guarantees": guarantees,
    })
}

#[derive(Serialize)]
struct ManifestProjectionText {
    contract_version: Value,
    bead_id: Value,
    command_policy: CommandPolicyProjectionText,
    source_of_truth: SourceOfTruthProjectionText,
    documentation_contract: DocumentationContractProjectionText,
    required_guarantee_ids: Value,
    lanes: Vec<LaneProjectionText>,
    guarantees: Vec<GuaranteeProjectionText>,
}

#[derive(Serialize)]
struct CommandPolicyProjectionText {
    all_commands_must_start_with: Value,
    cpu_intensive_validation_must_use_rch: Value,
    rch_must_fail_closed_to_remote: Value,
    formal_lean_build_must_not_shell_wrap: Value,
    broad_validation_is_frontier_evidence_not_local_change_proof: Value,
}

#[derive(Serialize)]
struct SourceOfTruthProjectionText {
    manifest: Value,
    contract_test: Value,
    cargo_manifest: Value,
    agent_instructions: Value,
    readme: Value,
}

#[derive(Serialize)]
struct DocumentationContractProjectionText {
    docs_must_reference_manifest: Value,
    required_marker: Value,
    verifier_marker: Value,
}

#[derive(Serialize)]
struct LaneProjectionText {
    lane_id: Value,
    kind: Value,
    package: Value,
    command: Value,
    guarantee_ids: Value,
    feature_flags: Value,
    expected_signal: Value,
    source_paths: Value,
}

#[derive(Serialize)]
struct GuaranteeProjectionText {
    guarantee_id: Value,
    lane_ids: Value,
}

fn manifest_projection_text(manifest: &Value) -> ManifestProjectionText {
    let command_policy = &manifest["command_policy"];
    let source_of_truth = &manifest["source_of_truth"];
    let documentation_contract = &manifest["documentation_contract"];

    ManifestProjectionText {
        contract_version: manifest["contract_version"].clone(),
        bead_id: manifest["bead_id"].clone(),
        command_policy: CommandPolicyProjectionText {
            all_commands_must_start_with: command_policy["all_commands_must_start_with"].clone(),
            cpu_intensive_validation_must_use_rch:
                command_policy["cpu_intensive_validation_must_use_rch"].clone(),
            rch_must_fail_closed_to_remote: command_policy["rch_must_fail_closed_to_remote"]
                .clone(),
            formal_lean_build_must_not_shell_wrap:
                command_policy["formal_lean_build_must_not_shell_wrap"].clone(),
            broad_validation_is_frontier_evidence_not_local_change_proof:
                command_policy["broad_validation_is_frontier_evidence_not_local_change_proof"]
                    .clone(),
        },
        source_of_truth: SourceOfTruthProjectionText {
            manifest: source_of_truth["manifest"].clone(),
            contract_test: source_of_truth["contract_test"].clone(),
            cargo_manifest: source_of_truth["cargo_manifest"].clone(),
            agent_instructions: source_of_truth["agent_instructions"].clone(),
            readme: source_of_truth["readme"].clone(),
        },
        documentation_contract: DocumentationContractProjectionText {
            docs_must_reference_manifest: documentation_contract["docs_must_reference_manifest"]
                .clone(),
            required_marker: documentation_contract["required_marker"].clone(),
            verifier_marker: documentation_contract["verifier_marker"].clone(),
        },
        required_guarantee_ids: manifest["required_guarantee_ids"].clone(),
        lanes: array(manifest, "lanes")
            .iter()
            .map(|lane| LaneProjectionText {
                lane_id: lane["lane_id"].clone(),
                kind: lane["kind"].clone(),
                package: lane["package"].clone(),
                command: lane["command"].clone(),
                guarantee_ids: lane["guarantee_ids"].clone(),
                feature_flags: lane["feature_flags"].clone(),
                expected_signal: lane["expected_signal"].clone(),
                source_paths: lane["source_paths"].clone(),
            })
            .collect(),
        guarantees: array(manifest, "guarantees")
            .iter()
            .map(|guarantee| GuaranteeProjectionText {
                guarantee_id: guarantee["guarantee_id"].clone(),
                lane_ids: guarantee["lane_ids"].clone(),
            })
            .collect(),
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn nonempty_string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn cargo_feature_names() -> BTreeSet<String> {
    let cargo = read_repo_file(CARGO_PATH);
    let mut in_features = false;
    let mut names = BTreeSet::new();

    for line in cargo.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') {
            break;
        }
        if !in_features || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            names.insert(name.trim().to_string());
        }
    }

    assert!(
        !names.is_empty(),
        "Cargo.toml feature names must be detected"
    );
    names
}

fn repo_path_exists_or_directory(relative: &str) -> bool {
    let path = repo_path(relative);
    path.exists() || relative == "fuzz/fuzz_targets" || relative == "tests" || relative == "src"
}

#[test]
fn manifest_records_required_lanes_and_doc_sources() {
    let manifest = manifest();
    assert_eq!(
        manifest.get("contract_version").and_then(Value::as_str),
        Some("proof-lane-manifest-v1")
    );
    assert_eq!(
        manifest.get("bead_id").and_then(Value::as_str),
        Some("asupersync-aj7lx3.1")
    );

    let lanes = array(&manifest, "lanes");
    assert!(
        lanes.len() >= 10,
        "manifest should cover production, feature, fuzz, test, lint, docs, and formal lanes"
    );

    let lane_ids = lanes
        .iter()
        .map(|lane| nonempty_string(lane, "lane_id").to_string())
        .collect::<BTreeSet<_>>();
    for required in [
        "default-production-tokio-tree",
        "metrics-production-tokio-tree",
        "fuzz-tokio-quarantine-tree",
        "workspace-normal-tokio-audit",
        "full-feature-tokio-audit",
        "native-feature-smoke",
        "fuzz-manifest-smoke",
        "lib-tests",
        "all-targets-check",
        "clippy-all-targets",
        "rustdoc-api",
        "formal-lean-build",
        "dirty-tree-ownership-receipt-contract",
        "proof-lane-manifest-contract",
    ] {
        assert!(lane_ids.contains(required), "missing lane {required}");
    }

    let source = manifest
        .get("source_of_truth")
        .expect("source_of_truth object");
    assert_eq!(
        source.get("manifest").and_then(Value::as_str),
        Some(MANIFEST_PATH)
    );
    assert_eq!(
        source.get("contract_test").and_then(Value::as_str),
        Some("tests/proof_lane_manifest_contract.rs")
    );
}

#[test]
fn manifest_projection_matches_golden() {
    let manifest = manifest();
    assert_eq!(
        manifest_projection(&manifest),
        manifest_projection_golden(),
        "proof-lane manifest projection changed; update the golden only after reviewing lane command, guarantee, and source-path semantics"
    );
}

#[test]
fn manifest_projection_text_matches_reviewed_golden() {
    let manifest = manifest();
    let projection = manifest_projection_text(&manifest);
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&projection).expect("serialize manifest projection")
    );
    let expected = read_repo_file(MANIFEST_PROJECTION_GOLDEN_PATH);
    assert_eq!(
        actual, expected,
        "proof-lane manifest projection text changed; review stable ordering and formatting before updating the golden"
    );
}

#[test]
fn every_lane_has_rch_command_scope_limits_and_live_paths() {
    let manifest = manifest();
    let feature_names = cargo_feature_names();
    let required_prefix = manifest["command_policy"]["all_commands_must_start_with"]
        .as_str()
        .expect("command prefix string");

    for lane in array(&manifest, "lanes") {
        let lane_id = nonempty_string(lane, "lane_id");
        let command = nonempty_string(lane, "command");
        assert!(
            command.starts_with(required_prefix),
            "{lane_id}: command must start with {required_prefix:?}: {command}"
        );
        assert!(
            command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "{lane_id}: proof lane must fail closed instead of falling back to local execution: {command}"
        );
        if command.contains(" cargo ") {
            assert!(
                command.contains("CARGO_TARGET_DIR="),
                "{lane_id}: cargo command must isolate target output: {command}"
            );
            assert!(
                !command.contains("rch exec -- cargo"),
                "{lane_id}: cargo command must not use bare rch cargo routing: {command}"
            );
        }
        assert!(
            !string_set(lane, "guarantee_ids").is_empty(),
            "{lane_id}: guarantee_ids must be nonempty"
        );
        for key in [
            "covers",
            "explicit_not_covered",
            "expected_signal",
            "escalation_notes",
        ] {
            nonempty_string(lane, key);
        }
        assert!(
            !array(lane, "common_unrelated_blockers").is_empty(),
            "{lane_id}: common_unrelated_blockers must be nonempty"
        );

        for feature in string_set(lane, "feature_flags") {
            assert!(
                feature_names.contains(&feature),
                "{lane_id}: feature {feature} must exist in Cargo.toml"
            );
        }

        for path in string_set(lane, "source_paths") {
            assert!(
                repo_path_exists_or_directory(&path),
                "{lane_id}: source path must exist or be an allowed source directory: {path}"
            );
        }

        if lane_id == "formal-lean-build" {
            assert!(
                !command.contains("bash") && !command.contains("cd formal/lean"),
                "formal Lean lane must use direct lake argv: {command}"
            );
        }
    }
}

#[test]
fn guarantees_and_lanes_are_bidirectionally_mapped() {
    let manifest = manifest();
    let required = string_set(&manifest, "required_guarantee_ids");
    let lanes = array(&manifest, "lanes");
    let guarantees = array(&manifest, "guarantees");

    let lane_ids = lanes
        .iter()
        .map(|lane| nonempty_string(lane, "lane_id").to_string())
        .collect::<BTreeSet<_>>();
    let guarantee_ids = guarantees
        .iter()
        .map(|guarantee| nonempty_string(guarantee, "guarantee_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required, guarantee_ids,
        "required_guarantee_ids must exactly match guarantee rows"
    );

    let mut lane_referenced_guarantees = BTreeSet::new();
    for lane in lanes {
        for guarantee in string_set(lane, "guarantee_ids") {
            assert!(
                guarantee_ids.contains(&guarantee),
                "{} references unknown guarantee {guarantee}",
                nonempty_string(lane, "lane_id")
            );
            lane_referenced_guarantees.insert(guarantee);
        }
    }
    assert_eq!(
        guarantee_ids, lane_referenced_guarantees,
        "every guarantee must be covered by at least one lane"
    );

    for guarantee in guarantees {
        let guarantee_id = nonempty_string(guarantee, "guarantee_id");
        let mapped_lanes = string_set(guarantee, "lane_ids");
        assert!(
            !mapped_lanes.is_empty(),
            "{guarantee_id}: lane_ids must be nonempty"
        );
        for lane_id in mapped_lanes {
            assert!(
                lane_ids.contains(&lane_id),
                "{guarantee_id}: unknown lane {lane_id}"
            );
            let lane = lanes
                .iter()
                .find(|lane| lane["lane_id"].as_str() == Some(&lane_id))
                .expect("mapped lane present");
            assert!(
                string_set(lane, "guarantee_ids").contains(guarantee_id),
                "{guarantee_id}: lane {lane_id} must map back to guarantee"
            );
        }
    }
}

#[test]
fn docs_point_to_manifest_and_verifier() {
    let manifest = manifest();
    let docs = manifest
        .get("documentation_contract")
        .expect("documentation_contract object");
    let marker = nonempty_string(docs, "required_marker");
    let verifier = nonempty_string(docs, "verifier_marker");

    for path in string_set(docs, "docs_must_reference_manifest") {
        let text = read_repo_file(&path);
        assert!(text.contains(marker), "{path} must reference {marker}");
        assert!(text.contains(verifier), "{path} must reference {verifier}");
    }

    assert!(read_repo_file(README_PATH).contains(marker));
    assert!(read_repo_file(AGENTS_PATH).contains(marker));
}
