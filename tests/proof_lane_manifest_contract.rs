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
const PROOF_REUSE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
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

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))?;
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn required_bool(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn string_set_result(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))?;
    let mut set = BTreeSet::new();
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| format!("{key} entries must be strings"))?;
        if text.trim().is_empty() {
            return Err(format!("{key} entries must be nonempty"));
        }
        set.insert(text.to_string());
    }
    Ok(set)
}

fn string_set_from_value(value: &Value, context: &str) -> Result<BTreeSet<String>, String> {
    let items = value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?;
    let mut set = BTreeSet::new();
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| format!("{context} entries must be strings"))?;
        if text.trim().is_empty() {
            return Err(format!("{context} entries must be nonempty"));
        }
        set.insert(text.to_string());
    }
    Ok(set)
}

fn validate_lane_proof_reuse_policy(lane: &Value, manifest: &Value) -> Result<(), String> {
    let lane_id = required_string(lane, "lane_id")?;
    let guarantee_ids = string_set_result(lane, "guarantee_ids")?;
    let lane_kind = required_string(lane, "kind")?;
    let top_policy = manifest
        .get("proof_reuse_policy")
        .ok_or_else(|| "manifest missing proof_reuse_policy".to_string())?;
    let field_sets = top_policy
        .get("required_match_field_sets")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "proof_reuse_policy.required_match_field_sets must be an object".to_string()
        })?;
    let lane_policy = lane
        .get("proof_reuse_policy")
        .ok_or_else(|| format!("{lane_id}: missing proof_reuse_policy"))?;
    let cache_hits_allowed = required_bool(lane_policy, "cache_hits_allowed")?;
    let required_field_set = required_string(lane_policy, "required_match_field_set")?;
    let required_fields = field_sets
        .get(required_field_set)
        .ok_or_else(|| format!("{lane_id}: unknown required match field set {required_field_set}"))
        .and_then(|value| string_set_from_value(value, required_field_set))?;
    let allowed_scopes = string_set_result(lane_policy, "allowed_claim_scopes")?;
    let non_citeable_scopes = string_set_result(lane_policy, "non_citeable_claim_scopes")?;
    let requires_dirty_rerun =
        required_bool(lane_policy, "requires_fresh_rerun_when_dirty_overlap")?;

    for required in [
        "manifest_lane_id",
        "command_fingerprint",
        "source_tree_fingerprint",
        "toolchain_fingerprint",
        "head_commit",
        "dirty_frontier_status",
        "touched_file_hashes",
        "status",
        "rch_remote_worker",
        "local_fallback_markers",
    ] {
        if !required_fields.contains(required) {
            return Err(format!(
                "{lane_id}: required match field set must include {required}"
            ));
        }
    }

    for scope in ["fresh-rch-pass", "release-readiness", "workspace-health"] {
        if !non_citeable_scopes.contains(scope) {
            return Err(format!("{lane_id}: missing non-citeable scope {scope}"));
        }
        if allowed_scopes.contains(scope) {
            return Err(format!(
                "{lane_id}: broad cache-hit scope {scope} is citeable"
            ));
        }
    }

    if cache_hits_allowed {
        if allowed_scopes.is_empty() {
            return Err(format!(
                "{lane_id}: cache-hit-enabled lanes need allowed claim scopes"
            ));
        }
        if !allowed_scopes.is_subset(&guarantee_ids) {
            return Err(format!(
                "{lane_id}: cache-hit claim scopes must be explicit lane guarantee ids"
            ));
        }
        if !requires_dirty_rerun {
            return Err(format!(
                "{lane_id}: cache-hit-enabled lanes must rerun on dirty overlap"
            ));
        }
    }

    if lane_kind.ends_with("_frontier") && !requires_dirty_rerun {
        return Err(format!(
            "{lane_id}: frontier lanes must require fresh rerun on dirty overlap"
        ));
    }

    Ok(())
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
        "swarm-proof-lane-planner-contract",
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
fn every_lane_declares_fail_closed_proof_reuse_policy() {
    let manifest = manifest();
    let policy = manifest
        .get("proof_reuse_policy")
        .expect("manifest proof_reuse_policy");
    assert_eq!(
        policy.get("policy_id").and_then(Value::as_str),
        Some("strict-rch-proof-reuse-policy-v1")
    );
    assert_eq!(
        policy
            .get("proof_reuse_cache_contract")
            .and_then(Value::as_str),
        Some(PROOF_REUSE_CONTRACT_PATH)
    );
    assert_eq!(
        policy
            .get("cache_hit_is_never_fresh_rch_pass")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        repo_path(PROOF_REUSE_CONTRACT_PATH).exists(),
        "proof reuse cache contract source must exist"
    );

    let lanes = array(&manifest, "lanes");
    for lane in lanes {
        validate_lane_proof_reuse_policy(lane, &manifest).unwrap_or_else(|error| panic!("{error}"));
    }

    let proof_manifest_lane = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("proof-lane-manifest-contract"))
        .expect("proof manifest lane");
    assert!(
        string_set(
            &proof_manifest_lane["proof_reuse_policy"],
            "allowed_claim_scopes"
        )
        .contains("proof-lane-manifest-verifier"),
        "focused manifest verifier lane must be cache-citeable by guarantee id"
    );

    let all_targets = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("all-targets-check"))
        .expect("all targets lane");
    assert_eq!(
        all_targets["proof_reuse_policy"]["requires_fresh_rerun_when_dirty_overlap"].as_bool(),
        Some(true),
        "all-target frontier cache hits must force rerun on dirty overlap"
    );
}

#[test]
fn synthetic_cache_policy_overclaims_are_rejected() {
    let manifest = manifest();
    let lanes = array(&manifest, "lanes");
    let base = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("proof-lane-manifest-contract"))
        .expect("proof manifest lane");

    let mut missing_policy = base.clone();
    missing_policy
        .as_object_mut()
        .expect("lane object")
        .remove("proof_reuse_policy");
    let error = validate_lane_proof_reuse_policy(&missing_policy, &manifest).unwrap_err();
    assert!(
        error.contains("missing proof_reuse_policy"),
        "unexpected missing-policy error: {error}"
    );

    let mut broad_claim = base.clone();
    broad_claim["proof_reuse_policy"]["allowed_claim_scopes"]
        .as_array_mut()
        .expect("allowed scopes")
        .push(json!("workspace-health"));
    let error = validate_lane_proof_reuse_policy(&broad_claim, &manifest).unwrap_err();
    assert!(
        error.contains("workspace-health"),
        "unexpected broad-claim error: {error}"
    );

    let mut dirty_overlap_unsafe = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("all-targets-check"))
        .expect("all targets lane")
        .clone();
    dirty_overlap_unsafe["proof_reuse_policy"]["requires_fresh_rerun_when_dirty_overlap"] =
        Value::Bool(false);
    let error = validate_lane_proof_reuse_policy(&dirty_overlap_unsafe, &manifest).unwrap_err();
    assert!(
        error.contains("dirty overlap") || error.contains("frontier"),
        "unexpected dirty-overlap error: {error}"
    );
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
