#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CONTRACT_PATH: &str = "artifacts/proof_reuse_handoff_receipt_contract_v1.json";
const CONTRACT_TEST_PATH: &str = "tests/proof_reuse_handoff_receipt_contract.rs";
const FRESHNESS_HELPER_PATH: &str = "scripts/proof_artifact_freshness_receipt.py";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_REUSE_CACHE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> Value {
    json(CONTRACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => {
            assert!(!text.trim().is_empty(), "{key} must be nonempty if present");
            Some(text)
        }
        _ => panic!("{key} must be a string or null"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"));
            assert!(!text.trim().is_empty(), "{key} entries must be nonempty");
            text.to_string()
        })
        .collect()
}

fn manifest_lanes() -> BTreeMap<String, Value> {
    array(&json(MANIFEST_PATH), "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn proof_evidence_statuses() -> BTreeSet<String> {
    array(&json(SNAPSHOT_PATH), "proof_evidence_status_catalog")
        .iter()
        .map(|status| string(status, "status").to_string())
        .collect()
}

fn ensure_no_disallowed_fields(value: &Value, disallowed: &BTreeSet<String>) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if disallowed.contains(key) {
                    return Err(format!("disallowed field {key} present"));
                }
                ensure_no_disallowed_fields(child, disallowed)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                ensure_no_disallowed_fields(item, disallowed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn ensure_no_secret_like_strings(value: &Value, markers: &BTreeSet<String>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            for marker in markers {
                if lower.contains(marker) {
                    return Err(format!("secret-like marker {marker} present"));
                }
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                ensure_no_secret_like_strings(child, markers)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                ensure_no_secret_like_strings(item, markers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_stage_log(handoff: &Value) -> Result<(), String> {
    let example_id = string(handoff, "example_id");
    let stages = array(handoff, "stage_log");
    if stages.is_empty() {
        return Err(format!("{example_id}: stage_log must be nonempty"));
    }
    for stage in stages {
        string(stage, "stage");
        string(stage, "status");
        string(stage, "detail");
    }
    Ok(())
}

fn validate_handoff(
    handoff: &Value,
    contract: &Value,
    lanes: &BTreeMap<String, Value>,
    proof_statuses: &BTreeSet<String>,
) -> Result<(), String> {
    let example_id = string(handoff, "example_id");
    let policy = contract.get("policy").expect("policy");
    let required_fields = string_set(contract, "required_handoff_fields");
    for field in &required_fields {
        if handoff.get(field).is_none() {
            return Err(format!("{example_id}: missing required field {field}"));
        }
    }

    ensure_no_disallowed_fields(handoff, &string_set(contract, "disallowed_fields"))?;
    ensure_no_secret_like_strings(handoff, &string_set(contract, "secret_like_markers"))?;
    validate_stage_log(handoff)?;

    let decision = string(handoff, "decision");
    let proof_status = string(handoff, "proof_evidence_status");
    let lane_id = string(handoff, "requested_lane_id");
    let claim_scope = string(handoff, "claim_scope");
    let rerun_command = string(handoff, "rerun_command");
    let redaction_class = string(handoff, "redaction_class");
    let lane = lanes
        .get(lane_id)
        .ok_or_else(|| format!("{example_id}: unknown manifest lane {lane_id}"))?;
    let lane_policy = lane
        .get("proof_reuse_policy")
        .ok_or_else(|| format!("{lane_id}: missing proof_reuse_policy"))?;
    let allowed_scopes = string_set(lane_policy, "allowed_claim_scopes");
    let refusal_reasons = string_set(handoff, "refusal_reason_codes");
    let provenance = handoff
        .get("rch_remote_provenance")
        .ok_or_else(|| format!("{example_id}: missing rch_remote_provenance"))?;
    let dirty_frontier = handoff
        .get("dirty_frontier")
        .ok_or_else(|| format!("{example_id}: missing dirty_frontier"))?;
    let touched_coverage = handoff
        .get("touched_surface_coverage")
        .ok_or_else(|| format!("{example_id}: missing touched_surface_coverage"))?;
    let operator_statement = string(handoff, "operator_statement").to_ascii_lowercase();

    if !string_set(policy, "allowed_decisions").contains(decision) {
        return Err(format!("{example_id}: unknown handoff decision {decision}"));
    }
    if !proof_statuses.contains(proof_status) {
        return Err(format!(
            "{example_id}: proof evidence status {proof_status} is not in snapshot catalog"
        ));
    }
    if !string_set(policy, "allowed_redaction_classes").contains(redaction_class) {
        return Err(format!(
            "{example_id}: unknown redaction class {redaction_class}"
        ));
    }
    if bool_field(handoff, "cache_hit_is_fresh_rch_pass") {
        return Err(format!(
            "{example_id}: cache hit cannot be marked as fresh RCH pass"
        ));
    }
    if rerun_command != string(lane, "command") {
        return Err(format!(
            "{example_id}: rerun command must match manifest lane command"
        ));
    }
    if !rerun_command.starts_with(string(policy, "required_rerun_command_prefix")) {
        return Err(format!("{example_id}: rerun command must use remote RCH"));
    }
    if !bool_field(provenance, "remote_required") {
        return Err(format!("{example_id}: remote_required must be true"));
    }
    if array(touched_coverage, "covered_paths").is_empty() {
        return Err(format!("{example_id}: covered paths must be nonempty"));
    }

    match decision {
        "approved-cache-hit" => {
            if optional_string(handoff, "chosen_proof_id").is_none() {
                return Err(format!("{example_id}: approved cache hit needs proof id"));
            }
            if !refusal_reasons.is_empty() {
                return Err(format!(
                    "{example_id}: approved cache hit must not carry refusal reasons"
                ));
            }
            if !allowed_scopes.contains(claim_scope) {
                return Err(format!(
                    "{example_id}: claim scope {claim_scope} is not allowed by manifest"
                ));
            }
            if !bool_field(provenance, "local_fallback_absent") {
                return Err(format!(
                    "{example_id}: approved cache hit requires absent local fallback"
                ));
            }
            if string(dirty_frontier, "verdict") != "clean" {
                return Err(format!(
                    "{example_id}: approved cache hit requires clean dirty frontier"
                ));
            }
            if !operator_statement.contains("not a fresh rch rerun") {
                return Err(format!(
                    "{example_id}: approved cache hit must state it is not a fresh RCH rerun"
                ));
            }
        }
        "refused" | "rerun-required" => {
            if !refusal_reasons.is_empty() && optional_string(handoff, "chosen_proof_id").is_some()
            {
                return Err(format!(
                    "{example_id}: refused/rerun rows must not name a chosen proof"
                ));
            }
            if refusal_reasons.is_empty() {
                return Err(format!(
                    "{example_id}: refused/rerun rows need reason codes"
                ));
            }
        }
        other => return Err(format!("{example_id}: unsupported decision {other}")),
    }

    if refusal_reasons.contains("broad-claim-unsupported") && allowed_scopes.contains(claim_scope) {
        return Err(format!(
            "{example_id}: unsupported claim scope is unexpectedly citeable"
        ));
    }
    if refusal_reasons.contains("dirty-frontier-overlap") {
        if string(dirty_frontier, "verdict") != "dirty-overlap" {
            return Err(format!(
                "{example_id}: dirty-overlap refusal needs dirty-overlap verdict"
            ));
        }
        if array(dirty_frontier, "overlap_paths").is_empty()
            || array(touched_coverage, "uncovered_paths").is_empty()
        {
            return Err(format!(
                "{example_id}: dirty-overlap refusal needs overlap and uncovered paths"
            ));
        }
    }
    if refusal_reasons.contains("local-fallback-marker") {
        if bool_field(provenance, "local_fallback_absent") {
            return Err(format!(
                "{example_id}: local-fallback refusal must record fallback presence"
            ));
        }
        if redaction_class != "refused" {
            return Err(format!(
                "{example_id}: local-fallback refusal must use refused redaction"
            ));
        }
    }

    Ok(())
}

#[test]
fn handoff_contract_declares_sources_and_fail_closed_policy() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("proof-reuse-handoff-receipt-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-5pziae.5")
    );

    let source = contract.get("source_of_truth").expect("source_of_truth");
    assert_eq!(source["contract"].as_str(), Some(CONTRACT_PATH));
    assert_eq!(source["contract_test"].as_str(), Some(CONTRACT_TEST_PATH));
    assert_eq!(
        source["proof_reuse_cache_contract"].as_str(),
        Some(PROOF_REUSE_CACHE_CONTRACT_PATH)
    );
    assert_eq!(source["proof_lane_manifest"].as_str(), Some(MANIFEST_PATH));
    assert_eq!(
        source["proof_status_snapshot"].as_str(),
        Some(SNAPSHOT_PATH)
    );
    assert_eq!(
        source["proof_freshness_helper"].as_str(),
        Some(FRESHNESS_HELPER_PATH)
    );
    assert_eq!(source["agent_instructions"].as_str(), Some(AGENTS_PATH));

    for path in [
        CONTRACT_PATH,
        CONTRACT_TEST_PATH,
        PROOF_REUSE_CACHE_CONTRACT_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        FRESHNESS_HELPER_PATH,
        AGENTS_PATH,
    ] {
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let policy = contract.get("policy").expect("policy");
    assert!(!bool_field(policy, "network_access_required"));
    assert!(!bool_field(policy, "tracker_mutation_allowed"));
    assert!(!bool_field(policy, "raw_agent_mail_bodies_allowed"));
    assert!(bool_field(policy, "cache_hit_is_never_fresh_rch_pass"));
}

#[test]
fn handoff_examples_cover_required_decisions_and_refusal_modes() {
    let contract = contract();
    let examples = array(&contract, "handoff_examples");
    let example_ids = examples
        .iter()
        .map(|example| string(example, "example_id").to_string())
        .collect::<BTreeSet<_>>();

    for required in [
        "approved-cache-hit-handoff",
        "refused-unsupported-claim-handoff",
        "dirty-overlap-rerun-handoff",
        "local-fallback-refusal-handoff",
    ] {
        assert!(example_ids.contains(required), "missing example {required}");
    }

    let decisions = examples
        .iter()
        .map(|example| string(example, "decision").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        decisions,
        BTreeSet::from([
            "approved-cache-hit".to_string(),
            "refused".to_string(),
            "rerun-required".to_string(),
        ])
    );
}

#[test]
fn handoff_examples_validate_against_manifest_status_and_redaction_policy() {
    let contract = contract();
    let lanes = manifest_lanes();
    let proof_statuses = proof_evidence_statuses();

    for handoff in array(&contract, "handoff_examples") {
        validate_handoff(handoff, &contract, &lanes, &proof_statuses)
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn synthetic_bad_handoffs_are_rejected() {
    let contract = contract();
    let lanes = manifest_lanes();
    let proof_statuses = proof_evidence_statuses();
    let examples = array(&contract, "handoff_examples");
    let approved = examples
        .iter()
        .find(|example| example["example_id"].as_str() == Some("approved-cache-hit-handoff"))
        .expect("approved handoff");
    let dirty = examples
        .iter()
        .find(|example| example["example_id"].as_str() == Some("dirty-overlap-rerun-handoff"))
        .expect("dirty handoff");
    let local_fallback = examples
        .iter()
        .find(|example| example["example_id"].as_str() == Some("local-fallback-refusal-handoff"))
        .expect("local fallback handoff");

    let mut fresh_claim = approved.clone();
    fresh_claim["operator_statement"] = Value::String("This is a fresh RCH pass.".to_string());
    let error = validate_handoff(&fresh_claim, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("not a fresh RCH rerun"),
        "unexpected fresh-claim error: {error}"
    );

    let mut missing_rerun = dirty.clone();
    missing_rerun
        .as_object_mut()
        .expect("handoff object")
        .remove("rerun_command");
    let error = validate_handoff(&missing_rerun, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("rerun_command"),
        "unexpected missing-rerun error: {error}"
    );

    let mut dirty_without_verdict = dirty.clone();
    dirty_without_verdict["dirty_frontier"]["verdict"] = Value::String("clean".to_string());
    let error =
        validate_handoff(&dirty_without_verdict, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("dirty-overlap verdict"),
        "unexpected dirty-verdict error: {error}"
    );

    let mut fallback_underredacted = local_fallback.clone();
    fallback_underredacted["redaction_class"] = Value::String("metadata_only".to_string());
    let error =
        validate_handoff(&fallback_underredacted, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("refused redaction"),
        "unexpected fallback-redaction error: {error}"
    );

    let mut raw_mail = approved.clone();
    raw_mail["raw_agent_mail_body"] = Value::String("verbatim coordination body".to_string());
    let error = validate_handoff(&raw_mail, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("raw_agent_mail_body"),
        "unexpected raw-mail error: {error}"
    );

    let mut secret_text = approved.clone();
    secret_text["operator_statement"] = Value::String("token=should-not-appear".to_string());
    let error = validate_handoff(&secret_text, &contract, &lanes, &proof_statuses).unwrap_err();
    assert!(
        error.contains("token="),
        "unexpected secret-text error: {error}"
    );
}
