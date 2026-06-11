#![allow(missing_docs)]

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CARGO_PATH: &str = "Cargo.toml";
const DURABLE_RECEIPT_CONTRACT_PATH: &str = "artifacts/durable_rch_proof_receipt_contract_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const MANIFEST_PROJECTION_GOLDEN_PATH: &str =
    "tests/fixtures/proof_lane_manifest/manifest_projection.json";
const PROOF_REUSE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const RCH_STALE_PROGRESS_RECEIPT_CONTRACT_PATH: &str =
    "artifacts/rch_stale_progress_receipt_contract_v1.json";
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
                "resource_envelope_class": lane["resource_envelope_class"].clone(),
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
        "resource_envelope_policy": manifest["resource_envelope_policy"].clone(),
        "validation_frontier_v2_policy": manifest["validation_frontier_v2_policy"].clone(),
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
    resource_envelope_policy: ResourceEnvelopePolicyProjectionText,
    validation_frontier_v2_policy: Value,
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
struct ResourceEnvelopePolicyProjectionText {
    policy_id: Value,
    schema_version: Value,
    scope_note: Value,
    operator_log_fields: Value,
    classes: Vec<ResourceEnvelopeClassProjectionText>,
}

#[derive(Serialize)]
struct ResourceEnvelopeClassProjectionText {
    class_id: Value,
    lane_kinds: Value,
    timeout_seconds: Value,
    memory_mb: Value,
    remote_required: Value,
    local_fallback_allowed: Value,
    resource_pressure: Value,
    description: Value,
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
    resource_envelope_class: Value,
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
    let resource_envelope_policy = &manifest["resource_envelope_policy"];
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
        resource_envelope_policy: ResourceEnvelopePolicyProjectionText {
            policy_id: resource_envelope_policy["policy_id"].clone(),
            schema_version: resource_envelope_policy["schema_version"].clone(),
            scope_note: resource_envelope_policy["scope_note"].clone(),
            operator_log_fields: resource_envelope_policy["operator_log_fields"].clone(),
            classes: array(resource_envelope_policy, "classes")
                .iter()
                .map(|class| ResourceEnvelopeClassProjectionText {
                    class_id: class["class_id"].clone(),
                    lane_kinds: class["lane_kinds"].clone(),
                    timeout_seconds: class["timeout_seconds"].clone(),
                    memory_mb: class["memory_mb"].clone(),
                    remote_required: class["remote_required"].clone(),
                    local_fallback_allowed: class["local_fallback_allowed"].clone(),
                    resource_pressure: class["resource_pressure"].clone(),
                    description: class["description"].clone(),
                })
                .collect(),
        },
        validation_frontier_v2_policy: manifest["validation_frontier_v2_policy"].clone(),
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
                resource_envelope_class: lane["resource_envelope_class"].clone(),
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

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    let amount = value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{key} must be a positive integer"))?;
    if amount <= 0 {
        return Err(format!("{key} must be a positive integer"));
    }
    Ok(amount as u64)
}

fn required_object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
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

fn resource_envelope_classes(manifest: &Value) -> Result<BTreeMap<String, Value>, String> {
    let policy = manifest
        .get("resource_envelope_policy")
        .ok_or_else(|| "manifest missing resource_envelope_policy".to_string())?;
    let _policy_object = required_object(manifest, "resource_envelope_policy")?;

    if required_string(policy, "policy_id")? != "proof-lane-resource-envelope-policy-v1" {
        return Err("resource_envelope_policy.policy_id has unexpected value".to_string());
    }
    if required_string(policy, "schema_version")? != "proof-lane-resource-envelope-v1" {
        return Err("resource_envelope_policy.schema_version has unexpected value".to_string());
    }

    let scope_note = required_string(policy, "scope_note")?;
    if !(scope_note.contains("Proof metadata only") && scope_note.contains("cgroup")) {
        return Err(
            "resource_envelope_policy.scope_note must distinguish metadata from cgroup enforcement"
                .to_string(),
        );
    }

    let operator_fields = string_set_result(policy, "operator_log_fields")?;
    for required in [
        "lane_id",
        "command_prefix",
        "resource_envelope_class",
        "timeout_seconds",
        "memory_mb",
        "remote_required",
        "local_fallback_allowed",
        "fail_closed_reason",
    ] {
        if !operator_fields.contains(required) {
            return Err(format!(
                "resource_envelope_policy.operator_log_fields missing {required}"
            ));
        }
    }

    let classes = policy
        .get("classes")
        .and_then(Value::as_array)
        .ok_or_else(|| "resource_envelope_policy.classes must be an array".to_string())?;
    if classes.is_empty() {
        return Err("resource_envelope_policy.classes must be nonempty".to_string());
    }

    let mut by_id = BTreeMap::new();
    for class in classes {
        let class_id = required_string(class, "class_id")?.to_string();
        if by_id.contains_key(&class_id) {
            return Err(format!("duplicate resource envelope class {class_id}"));
        }

        let lane_kinds = string_set_result(class, "lane_kinds")?;
        if lane_kinds.is_empty() {
            return Err(format!("{class_id}: lane_kinds must be nonempty"));
        }

        required_u64(class, "timeout_seconds").map_err(|error| format!("{class_id}: {error}"))?;
        required_u64(class, "memory_mb").map_err(|error| format!("{class_id}: {error}"))?;

        if !required_bool(class, "remote_required")? {
            return Err(format!("{class_id}: remote_required must be true"));
        }
        if required_bool(class, "local_fallback_allowed")? {
            return Err(format!("{class_id}: local_fallback_allowed must be false"));
        }

        match required_string(class, "resource_pressure")? {
            "low" | "medium" | "high" => {}
            pressure => {
                return Err(format!(
                    "{class_id}: resource_pressure must be low, medium, or high, got {pressure}"
                ));
            }
        }
        required_string(class, "description").map_err(|error| format!("{class_id}: {error}"))?;

        by_id.insert(class_id, class.clone());
    }

    Ok(by_id)
}

fn find_resource_envelope_class<'a>(manifest: &'a Value, class_id: &str) -> Option<&'a Value> {
    manifest
        .get("resource_envelope_policy")
        .and_then(|policy| policy.get("classes"))
        .and_then(Value::as_array)
        .and_then(|classes| {
            classes
                .iter()
                .find(|class| class.get("class_id").and_then(Value::as_str) == Some(class_id))
        })
}

fn validate_lane_resource_envelope(lane: &Value, manifest: &Value) -> Result<(), String> {
    let lane_id = required_string(lane, "lane_id")?;
    let lane_kind = required_string(lane, "kind")?;
    let command = required_string(lane, "command")?;
    let required_prefix =
        required_string(&manifest["command_policy"], "all_commands_must_start_with")
            .map_err(|error| format!("{lane_id}: {error}"))?;

    if !command.starts_with(required_prefix) {
        return Err(format!(
            "{lane_id}: command_prefix {required_prefix:?} is required for a remote-required proof lane"
        ));
    }

    let envelope_class_id = required_string(lane, "resource_envelope_class")
        .map_err(|error| format!("{lane_id}: {error}"))?;
    let classes =
        resource_envelope_classes(manifest).map_err(|error| format!("{lane_id}: {error}"))?;
    let envelope = classes
        .get(envelope_class_id)
        .ok_or_else(|| format!("{lane_id}: unknown resource_envelope_class {envelope_class_id}"))?;

    let allowed_kinds = string_set_result(envelope, "lane_kinds")
        .map_err(|error| format!("{lane_id}: {envelope_class_id}: {error}"))?;
    if !allowed_kinds.contains(lane_kind) {
        return Err(format!(
            "{lane_id}: resource_envelope_class {envelope_class_id} does not admit lane kind {lane_kind}"
        ));
    }

    let timeout_seconds = required_u64(envelope, "timeout_seconds")
        .map_err(|error| format!("{lane_id}: {envelope_class_id}: {error}"))?;
    let memory_mb = required_u64(envelope, "memory_mb")
        .map_err(|error| format!("{lane_id}: {envelope_class_id}: {error}"))?;
    let remote_required = required_bool(envelope, "remote_required")
        .map_err(|error| format!("{lane_id}: {envelope_class_id}: {error}"))?;
    let local_fallback_allowed = required_bool(envelope, "local_fallback_allowed")
        .map_err(|error| format!("{lane_id}: {envelope_class_id}: {error}"))?;

    if timeout_seconds == 0 || memory_mb == 0 {
        return Err(format!(
            "{lane_id}: resource envelope must declare nonzero timeout_seconds and memory_mb"
        ));
    }
    if !remote_required {
        return Err(format!(
            "{lane_id}: remote_required must be true for rch proof lanes"
        ));
    }
    if local_fallback_allowed {
        return Err(format!(
            "{lane_id}: local_fallback_allowed must be false for remote-required proof lanes"
        ));
    }

    Ok(())
}

fn resource_envelope_failure_row(lane: &Value, manifest: &Value, error: &str) -> Value {
    let command_prefix = manifest["command_policy"]["all_commands_must_start_with"]
        .as_str()
        .unwrap_or("<missing>");
    let envelope_class = lane
        .get("resource_envelope_class")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    let envelope = find_resource_envelope_class(manifest, envelope_class)
        .cloned()
        .unwrap_or(Value::Null);

    json!({
        "lane_id": lane.get("lane_id").cloned().unwrap_or(Value::Null),
        "command_prefix": command_prefix,
        "resource_envelope_class": lane.get("resource_envelope_class").cloned().unwrap_or(Value::Null),
        "resource_envelope": envelope,
        "timeout_seconds": find_resource_envelope_class(manifest, envelope_class)
            .and_then(|class| class.get("timeout_seconds"))
            .cloned()
            .unwrap_or(Value::Null),
        "memory_mb": find_resource_envelope_class(manifest, envelope_class)
            .and_then(|class| class.get("memory_mb"))
            .cloned()
            .unwrap_or(Value::Null),
        "remote_required": find_resource_envelope_class(manifest, envelope_class)
            .and_then(|class| class.get("remote_required"))
            .cloned()
            .unwrap_or(Value::Null),
        "local_fallback_allowed": find_resource_envelope_class(manifest, envelope_class)
            .and_then(|class| class.get("local_fallback_allowed"))
            .cloned()
            .unwrap_or(Value::Null),
        "fail_closed_reason": error,
    })
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

fn validation_frontier_policy(manifest: &Value) -> Result<&Value, String> {
    let policy = manifest
        .get("validation_frontier_v2_policy")
        .ok_or_else(|| "manifest missing validation_frontier_v2_policy".to_string())?;

    if required_string(policy, "policy_id")? != "validation-frontier-v2-lane-semantics" {
        return Err("validation frontier policy id drifted".to_string());
    }
    if required_string(policy, "schema_version")? != "validation-frontier-v2" {
        return Err("validation frontier schema version drifted".to_string());
    }

    let stale = policy
        .get("default_stale_progress_policy")
        .ok_or_else(|| "validation frontier policy missing stale policy".to_string())?;
    if required_string(stale, "policy_id")? != "rch-stale-progress-fail-closed-v1" {
        return Err("stale progress policy id drifted".to_string());
    }
    if required_string(stale, "receipt_schema_version")? != "rch-stale-progress-receipt-v1" {
        return Err("stale progress receipt schema version drifted".to_string());
    }
    if required_string(stale, "receipt_contract")? != RCH_STALE_PROGRESS_RECEIPT_CONTRACT_PATH {
        return Err("stale progress receipt contract path drifted".to_string());
    }
    if !repo_path(RCH_STALE_PROGRESS_RECEIPT_CONTRACT_PATH).exists() {
        return Err("stale progress receipt contract source must exist".to_string());
    }
    for required_true in [
        "wait_for_fresh_heartbeat",
        "never_cancel_peer_owned_builds",
        "receipt_required_before_retry",
    ] {
        if !required_bool(stale, required_true)? {
            return Err(format!("stale progress policy must set {required_true}"));
        }
    }
    if required_bool(stale, "code_evidence_claimable")? {
        return Err("stale progress policy must not make code evidence claimable".to_string());
    }
    required_string(stale, "retry_policy")?;

    Ok(policy)
}

fn lane_validation_semantics(lane: &Value, manifest: &Value) -> Result<Value, String> {
    let policy = validation_frontier_policy(manifest)?;
    let lane_id = required_string(lane, "lane_id")?;
    let lane_kind = required_string(lane, "kind")?;

    if let Some(override_row) = policy
        .get("lane_overrides")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        })
    {
        return Ok(override_row.clone());
    }

    let mut matched = Vec::new();
    for class in policy
        .get("lane_classes")
        .and_then(Value::as_array)
        .ok_or_else(|| "validation frontier lane_classes must be an array".to_string())?
    {
        let class_kinds = string_set_result(class, "lane_kinds")?;
        if class_kinds.contains(lane_kind) {
            matched.push(class.clone());
        }
    }

    match matched.len() {
        1 => Ok(matched.remove(0)),
        0 => Err(format!(
            "{lane_id}: lane kind {lane_kind} has no validation frontier class"
        )),
        _ => Err(format!(
            "{lane_id}: lane kind {lane_kind} maps to multiple validation frontier classes"
        )),
    }
}

fn validate_lane_validation_frontier_v2(lane: &Value, manifest: &Value) -> Result<(), String> {
    let lane_id = required_string(lane, "lane_id")?;
    let semantics = lane_validation_semantics(lane, manifest)?;
    let lane_class = required_string(&semantics, "lane_class")?;
    let roots = string_set_result(&semantics, "expected_graph_roots")?;
    let _heavy_edges = string_set_result(&semantics, "expected_heavy_edges")?;
    let no_claims = string_set_result(&semantics, "no_claim_boundaries")?;
    let max_expected_crates = required_u64(&semantics, "max_expected_crates")?;

    if roots.is_empty() {
        return Err(format!("{lane_id}: expected_graph_roots must be nonempty"));
    }
    if no_claims.is_empty() {
        return Err(format!("{lane_id}: no_claim_boundaries must be nonempty"));
    }
    if max_expected_crates == 0 {
        return Err(format!("{lane_id}: max_expected_crates must be positive"));
    }

    match lane_class {
        "dependency_graph" | "compile_only" | "broad_frontier" | "run_exact" | "run_filtered"
        | "conformance" | "rustdoc" | "fuzz_smoke" | "formal" | "artifact_contract" => {}
        other => {
            return Err(format!("{lane_id}: unknown lane_class {other}"));
        }
    }

    if lane_class == "compile_only" {
        for forbidden_claim in ["test-execution", "runtime-behavior", "release-readiness"] {
            if !no_claims.contains(forbidden_claim) {
                return Err(format!(
                    "{lane_id}: compile_only lane must not claim {forbidden_claim}"
                ));
            }
        }
    }

    if lane_class == "conformance" {
        let guard = required_object(
            validation_frontier_policy(manifest)?,
            "conformance_masquerade_guard",
        )?;
        let required_root = guard
            .get("required_expected_graph_root")
            .and_then(Value::as_str)
            .ok_or_else(|| "conformance guard missing required root".to_string())?;
        let required_boundary = guard
            .get("required_no_claim_boundary")
            .and_then(Value::as_str)
            .ok_or_else(|| "conformance guard missing required boundary".to_string())?;
        if !roots.contains(required_root) {
            return Err(format!(
                "{lane_id}: conformance lane must declare expected graph root {required_root}"
            ));
        }
        if !no_claims.contains(required_boundary) {
            return Err(format!(
                "{lane_id}: conformance lane must not claim {required_boundary}"
            ));
        }
    }

    if lane_id == "channel-mpsc-select-e2e-public-run" {
        if lane_class != "run_exact" {
            return Err("channel focused lane must remain run_exact".to_string());
        }
        if roots.contains("conformance") {
            return Err("channel focused lane must not include conformance graph root".to_string());
        }
        for boundary in [
            "broad-lib-test-frontier",
            "conformance-crate",
            "release-readiness",
        ] {
            if !no_claims.contains(boundary) {
                return Err(format!(
                    "channel focused lane missing no-claim boundary {boundary}"
                ));
            }
        }
        if max_expected_crates > 200 {
            return Err("channel focused lane graph budget is too broad".to_string());
        }
    }

    Ok(())
}

fn validate_durable_receipt_candidate_policy(manifest: &Value) -> Result<(), String> {
    let proof_reuse_policy = manifest
        .get("proof_reuse_policy")
        .ok_or_else(|| "manifest missing proof_reuse_policy".to_string())?;
    let durable_policy = proof_reuse_policy
        .get("durable_receipt_candidate_policy")
        .ok_or_else(|| "proof_reuse_policy missing durable_receipt_candidate_policy".to_string())?;

    if required_string(durable_policy, "policy_id")?
        != "durable-rch-proof-receipt-candidate-policy-v1"
    {
        return Err("durable receipt policy id drifted".to_string());
    }
    if required_string(durable_policy, "receipt_schema_version")? != "durable-rch-proof-receipt-v1"
    {
        return Err("durable receipt schema version drifted".to_string());
    }
    if required_string(durable_policy, "receipt_contract")? != DURABLE_RECEIPT_CONTRACT_PATH {
        return Err("durable receipt contract path drifted".to_string());
    }
    if !repo_path(DURABLE_RECEIPT_CONTRACT_PATH).exists() {
        return Err("durable receipt contract source must exist".to_string());
    }

    for required_true in [
        "candidate_evidence_only",
        "must_pass_through_reuse_and_citation_classifiers",
        "requires_main_branch",
        "requires_clean_dirty_frontier",
        "requires_remote_required_command",
    ] {
        if !required_bool(durable_policy, required_true)? {
            return Err(format!("durable receipt policy must set {required_true}"));
        }
    }
    if required_bool(durable_policy, "local_fallback_allowed")? {
        return Err("durable receipt policy must forbid local fallback".to_string());
    }
    if required_string(durable_policy, "required_terminal_lifecycle_state")? != "terminal_pass" {
        return Err("durable receipt lifecycle policy must require terminal_pass".to_string());
    }
    if required_string(durable_policy, "required_terminal_classification")? != "pass" {
        return Err("durable receipt classification policy must require pass".to_string());
    }
    if required_string(durable_policy, "required_proof_evidence_status")? != "fresh-rch-pass" {
        return Err("durable receipt policy must require fresh-rch-pass".to_string());
    }

    let required_fields = string_set_result(durable_policy, "required_receipt_fields")?;
    for required in [
        "manifest_lane_id",
        "manifest_guarantee_ids",
        "claim_scope",
        "command.command",
        "command.command_fingerprint",
        "command.remote_required",
        "command.local_fallback_allowed",
        "command.local_fallback_markers",
        "source.branch",
        "source.head_commit",
        "source.expected_head",
        "source.source_tree_fingerprint",
        "source.dirty_frontier_status",
        "source.touched_files",
        "source.touched_file_hashes",
        "rch_provenance.worker_id",
        "rch_provenance.remote_route_segments",
        "outcome.status",
        "outcome.output_digest",
        "claim_boundaries.citable",
        "claim_boundaries.explicit_not_covered",
        "claim_boundaries.refusal_reason_codes",
    ] {
        if !required_fields.contains(required) {
            return Err(format!("durable receipt policy must require {required}"));
        }
    }

    let non_citeable_scopes = string_set_result(durable_policy, "non_citeable_claim_scopes")?;
    for scope in [
        "fresh-rch-pass",
        "release-readiness",
        "workspace-health",
        "live-rch-fleet-availability",
    ] {
        if !non_citeable_scopes.contains(scope) {
            return Err(format!(
                "durable receipt policy must reject broad/non-proof scope {scope}"
            ));
        }
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

fn lane_by_id<'a>(lanes: &'a [Value], lane_id: &str) -> &'a Value {
    lanes
        .iter()
        .find(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        .unwrap_or_else(|| panic!("missing lane {lane_id}"))
}

fn resource_envelope_class_mut<'a>(manifest: &'a mut Value, class_id: &str) -> &'a mut Value {
    manifest
        .get_mut("resource_envelope_policy")
        .and_then(|policy| policy.get_mut("classes"))
        .and_then(Value::as_array_mut)
        .and_then(|classes| {
            classes
                .iter_mut()
                .find(|class| class.get("class_id").and_then(Value::as_str) == Some(class_id))
        })
        .unwrap_or_else(|| panic!("missing resource envelope class {class_id}"))
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
        "runtime-pressure-control-evidence-contract",
        "fourth-wave-governor-schema-contract",
        "fourth-wave-governor-policy-engine",
        "fourth-wave-swarm-replay-corpus",
        "fourth-wave-runtime-bridge-contract",
        "fourth-wave-benchmark-contract",
        "fourth-wave-governor-signoff-runbook",
        "dirty-tree-ownership-receipt-contract",
        "durable-rch-proof-final-signoff",
        "swarm-proof-lane-planner-contract",
        "migration-readiness-planner-signoff-contract",
        "unsafe-boundary-ledger-contract",
        "proof-lane-manifest-contract",
        "rch-topology-preflight-canary",
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
        validate_lane_resource_envelope(lane, &manifest).unwrap_or_else(|error| panic!("{error}"));
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
fn every_lane_has_validation_frontier_v2_semantics() {
    let manifest = manifest();
    validation_frontier_policy(&manifest).unwrap_or_else(|error| panic!("{error}"));

    let lanes = array(&manifest, "lanes");
    for lane in lanes {
        validate_lane_validation_frontier_v2(lane, &manifest)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    let channel = lane_by_id(lanes, "channel-mpsc-select-e2e-public-run");
    let channel_semantics =
        lane_validation_semantics(channel, &manifest).expect("channel lane semantics");
    assert_eq!(
        channel_semantics["lane_class"].as_str(),
        Some("run_exact"),
        "channel focused public runner must remain an exact execution lane"
    );
    assert!(
        string_set_result(&channel_semantics, "no_claim_boundaries")
            .expect("channel no-claim boundaries")
            .contains("conformance-crate"),
        "channel focused public runner must explicitly not claim conformance coverage"
    );
}

#[test]
fn validation_frontier_v2_overclaims_are_rejected() {
    let manifest = manifest();
    let lanes = array(&manifest, "lanes");

    let mut compile_overclaim = manifest.clone();
    let compile_class = compile_overclaim["validation_frontier_v2_policy"]["lane_classes"]
        .as_array_mut()
        .expect("lane classes")
        .iter_mut()
        .find(|class| class["lane_class"].as_str() == Some("compile_only"))
        .expect("compile_only class");
    compile_class["no_claim_boundaries"]
        .as_array_mut()
        .expect("compile no-claim boundaries")
        .retain(|boundary| boundary.as_str() != Some("test-execution"));
    let error = validate_lane_validation_frontier_v2(
        lane_by_id(lanes, "all-targets-check"),
        &compile_overclaim,
    )
    .unwrap_err();
    assert!(
        error.contains("test-execution"),
        "compile-only overclaim should reject missing test-execution boundary: {error}"
    );

    let mut conformance_masquerade = manifest.clone();
    let channel_override =
        conformance_masquerade["validation_frontier_v2_policy"]["lane_overrides"]
            .as_array_mut()
            .expect("lane overrides")
            .iter_mut()
            .find(|override_row| {
                override_row["lane_id"].as_str() == Some("channel-mpsc-select-e2e-public-run")
            })
            .expect("channel override");
    channel_override["lane_class"] = json!("conformance");
    let error = validate_lane_validation_frontier_v2(
        lane_by_id(lanes, "channel-mpsc-select-e2e-public-run"),
        &conformance_masquerade,
    )
    .unwrap_err();
    assert!(
        error.contains("conformance") || error.contains("focused-feature-proof"),
        "conformance masquerade should be rejected: {error}"
    );

    let mut stale_policy_overclaim = manifest.clone();
    stale_policy_overclaim["validation_frontier_v2_policy"]["default_stale_progress_policy"]["never_cancel_peer_owned_builds"] =
        json!(false);
    let error = validate_lane_validation_frontier_v2(
        lane_by_id(lanes, "proof-lane-manifest-contract"),
        &stale_policy_overclaim,
    )
    .unwrap_err();
    assert!(
        error.contains("never_cancel_peer_owned_builds"),
        "stale policy must fail closed on peer-cancel ambiguity: {error}"
    );
}

#[test]
fn every_lane_declares_fail_closed_resource_envelope() {
    let manifest = manifest();
    let classes = resource_envelope_classes(&manifest)
        .unwrap_or_else(|error| panic!("resource envelope policy invalid: {error}"));
    let lanes = array(&manifest, "lanes");

    let covered_kinds = classes
        .values()
        .flat_map(|class| string_set_result(class, "lane_kinds").expect("class lane kinds"))
        .collect::<BTreeSet<_>>();
    for required in [
        "dependency_graph",
        "compile_frontier",
        "test_frontier",
        "lint_frontier",
        "format_frontier",
        "documentation_frontier",
        "formal_frontier",
        "artifact_contract",
        "dependency_audit",
    ] {
        assert!(
            covered_kinds.contains(required),
            "resource envelope classes must cover lane kind {required}"
        );
    }

    for lane in lanes {
        validate_lane_resource_envelope(lane, &manifest).unwrap_or_else(|error| panic!("{error}"));
    }

    for (lane_id, expected_class) in [
        ("lib-tests", "test-frontier-heavy"),
        ("channel-mpsc-select-e2e-public-run", "test-frontier-heavy"),
        ("all-targets-check", "compile-frontier-heavy"),
        ("clippy-all-targets", "lint-frontier-heavy"),
        ("fuzz-manifest-smoke", "compile-frontier-heavy"),
        (
            "runtime-pressure-control-evidence-contract",
            "artifact-contract-medium",
        ),
        (
            "fourth-wave-governor-schema-contract",
            "artifact-contract-medium",
        ),
        (
            "fourth-wave-governor-policy-engine",
            "artifact-contract-medium",
        ),
        (
            "fourth-wave-swarm-replay-corpus",
            "artifact-contract-medium",
        ),
        (
            "fourth-wave-runtime-bridge-contract",
            "artifact-contract-medium",
        ),
        ("fourth-wave-benchmark-contract", "artifact-contract-medium"),
        (
            "fourth-wave-governor-signoff-runbook",
            "artifact-contract-medium",
        ),
        (
            "migration-readiness-planner-signoff-contract",
            "artifact-contract-medium",
        ),
        (
            "durable-rch-proof-final-signoff",
            "artifact-contract-medium",
        ),
        (
            "unsafe-boundary-ledger-contract",
            "artifact-contract-medium",
        ),
        ("rustdoc-api", "documentation-frontier-medium"),
        ("proof-lane-manifest-contract", "artifact-contract-medium"),
        ("rch-topology-preflight-canary", "artifact-contract-medium"),
    ] {
        let lane = lane_by_id(lanes, lane_id);
        assert_eq!(
            lane.get("resource_envelope_class").and_then(Value::as_str),
            Some(expected_class),
            "{lane_id}: unexpected resource envelope class"
        );

        let diagnostic =
            resource_envelope_failure_row(lane, &manifest, "operator diagnostic preview");
        assert_eq!(diagnostic["lane_id"].as_str(), Some(lane_id));
        assert_eq!(
            diagnostic["command_prefix"].as_str(),
            Some("RCH_REQUIRE_REMOTE=1 rch exec -- ")
        );
        assert_eq!(
            diagnostic["resource_envelope_class"].as_str(),
            Some(expected_class)
        );
        assert!(
            diagnostic["timeout_seconds"].as_u64().unwrap_or_default() > 0,
            "{lane_id}: diagnostic must expose timeout_seconds"
        );
        assert!(
            diagnostic["memory_mb"].as_u64().unwrap_or_default() > 0,
            "{lane_id}: diagnostic must expose memory_mb"
        );
        assert_eq!(diagnostic["remote_required"].as_bool(), Some(true));
        assert_eq!(diagnostic["local_fallback_allowed"].as_bool(), Some(false));
        assert_eq!(
            diagnostic["fail_closed_reason"].as_str(),
            Some("operator diagnostic preview")
        );
    }
}

#[test]
fn synthetic_resource_envelope_defects_are_rejected_with_diagnostics() {
    let manifest = manifest();
    let lanes = array(&manifest, "lanes");
    let lib_tests = lane_by_id(lanes, "lib-tests");
    let mut diagnostics = Vec::new();

    let mut missing_envelope = lib_tests.clone();
    missing_envelope
        .as_object_mut()
        .expect("lane object")
        .remove("resource_envelope_class");
    let error = validate_lane_resource_envelope(&missing_envelope, &manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(&missing_envelope, &manifest, &error);
    assert!(
        error.contains("lib-tests") && error.contains("resource_envelope_class"),
        "unexpected missing-envelope error: {error}"
    );
    assert_eq!(diagnostic["lane_id"].as_str(), Some("lib-tests"));
    assert_eq!(diagnostic["resource_envelope_class"], Value::Null);
    assert_eq!(
        diagnostic["fail_closed_reason"].as_str(),
        Some(error.as_str())
    );
    diagnostics.push(diagnostic);

    let mut zero_timeout_manifest = manifest.clone();
    resource_envelope_class_mut(&mut zero_timeout_manifest, "test-frontier-heavy")["timeout_seconds"] =
        json!(0);
    let error = validate_lane_resource_envelope(lib_tests, &zero_timeout_manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(lib_tests, &zero_timeout_manifest, &error);
    assert!(
        error.contains("lib-tests") && error.contains("timeout_seconds"),
        "unexpected zero-timeout error: {error}"
    );
    assert_eq!(diagnostic["timeout_seconds"].as_i64(), Some(0));
    assert!(
        diagnostic["memory_mb"].as_i64().unwrap_or_default() > 0,
        "diagnostic should preserve memory_mb when timeout is malformed"
    );
    diagnostics.push(diagnostic);

    let mut negative_memory_manifest = manifest.clone();
    resource_envelope_class_mut(&mut negative_memory_manifest, "test-frontier-heavy")["memory_mb"] =
        json!(-1);
    let error = validate_lane_resource_envelope(lib_tests, &negative_memory_manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(lib_tests, &negative_memory_manifest, &error);
    assert!(
        error.contains("lib-tests") && error.contains("memory_mb"),
        "unexpected negative-memory error: {error}"
    );
    assert_eq!(diagnostic["memory_mb"].as_i64(), Some(-1));
    diagnostics.push(diagnostic);

    let mut mismatched_class = lane_by_id(lanes, "all-targets-check").clone();
    mismatched_class["resource_envelope_class"] = json!("dependency-graph-light");
    let error = validate_lane_resource_envelope(&mismatched_class, &manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(&mismatched_class, &manifest, &error);
    assert!(
        error.contains("all-targets-check")
            && error.contains("dependency-graph-light")
            && error.contains("compile_frontier"),
        "unexpected mismatched-class error: {error}"
    );
    diagnostics.push(diagnostic);

    let mut local_command = lib_tests.clone();
    local_command["command"] = json!("cargo test -p asupersync --lib");
    let error = validate_lane_resource_envelope(&local_command, &manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(&local_command, &manifest, &error);
    assert!(
        error.contains("lib-tests") && error.contains("command_prefix"),
        "unexpected local-command error: {error}"
    );
    assert_eq!(
        diagnostic["command_prefix"].as_str(),
        Some("RCH_REQUIRE_REMOTE=1 rch exec -- ")
    );
    diagnostics.push(diagnostic);

    let mut fallback_allowed_manifest = manifest.clone();
    resource_envelope_class_mut(&mut fallback_allowed_manifest, "compile-frontier-heavy")["local_fallback_allowed"] =
        json!(true);
    let all_targets = lane_by_id(lanes, "all-targets-check");
    let error =
        validate_lane_resource_envelope(all_targets, &fallback_allowed_manifest).unwrap_err();
    let diagnostic = resource_envelope_failure_row(all_targets, &fallback_allowed_manifest, &error);
    assert!(
        error.contains("all-targets-check") && error.contains("local_fallback_allowed"),
        "unexpected fallback-allowed error: {error}"
    );
    assert_eq!(diagnostic["local_fallback_allowed"].as_bool(), Some(true));
    diagnostics.push(diagnostic);

    eprintln!(
        "proof_lane_resource_envelope_failure_rows={}",
        serde_json::to_string_pretty(&diagnostics)
            .expect("serialize resource envelope diagnostics")
    );
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
    validate_durable_receipt_candidate_policy(&manifest).unwrap_or_else(|error| panic!("{error}"));

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
