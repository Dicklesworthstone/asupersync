#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const BEADS_PATH: &str = ".beads/issues.jsonl";
const CACHE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const CONTRACT_PATH: &str = "artifacts/proof_reuse_signoff_contract_v1.json";
const E2E_CONTRACT_PATH: &str = "artifacts/proof_reuse_e2e_contract_v1.json";
const HANDOFF_CONTRACT_PATH: &str = "artifacts/proof_reuse_handoff_receipt_contract_v1.json";
const LARGE_CORPUS_CONTRACT_PATH: &str = "artifacts/proof_reuse_large_corpus_contract_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const REQUIRED_RCH_PREFIX: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- ";
const SCHEMA_VERSION: &str = "proof-reuse-signoff-contract-v1";

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

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    let Some(text) = value.get(key).and_then(Value::as_str) else {
        return Err(format!("{key} must be a string"));
    };
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => {
            assert!(
                !text.trim().is_empty(),
                "{key} must be nonempty when present"
            );
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

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
}

fn array_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    value
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn command_mut<'a>(contract: &'a mut Value, command_id: &str) -> &'a mut Value {
    array_mut(contract, "required_validation_commands")
        .iter_mut()
        .find(|command| command.get("command_id").and_then(Value::as_str) == Some(command_id))
        .unwrap_or_else(|| panic!("missing mutable command {command_id}"))
}

fn command_map(contract: &Value) -> BTreeMap<String, Value> {
    array(contract, "required_validation_commands")
        .iter()
        .map(|command| (string(command, "command_id").to_string(), command.clone()))
        .collect()
}

fn sha256_file(relative: &str) -> String {
    let bytes =
        std::fs::read(repo_path(relative)).unwrap_or_else(|err| panic!("read {relative}: {err}"));
    let digest = Sha256::digest(&bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn source_paths(contract: &Value) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for value in object(contract, "source_of_truth")
        .as_object()
        .expect("source_of_truth must be an object")
        .values()
    {
        let path = value
            .as_str()
            .unwrap_or_else(|| panic!("source_of_truth values must be strings"));
        assert!(
            !path.trim().is_empty(),
            "source_of_truth path must be nonempty"
        );
        paths.insert(path.to_string());
    }
    paths
}

fn validate_signoff_schema(contract: &Value) -> Result<(), String> {
    if required_string(contract, "schema_version")? != SCHEMA_VERSION {
        return Err("signoff schema version drifted".to_string());
    }
    if required_string(contract, "bead_id")? != "asupersync-5pziae.8" {
        return Err("unexpected signoff bead id".to_string());
    }
    if required_string(contract, "epic_id")? != "asupersync-5pziae" {
        return Err("unexpected signoff epic id".to_string());
    }
    Ok(())
}

fn validate_source_artifact_hashes(contract: &Value) -> Result<(), String> {
    for artifact in array(contract, "source_artifact_hashes") {
        let path = string(artifact, "path");
        let expected = string(artifact, "sha256");
        if expected.len() != 64
            || !expected
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        {
            return Err(format!("{path}: sha256 must be a lowercase hex digest"));
        }
        if sha256_file(path) != expected {
            return Err(format!("source hash mismatch for {path}"));
        }
        string(artifact, "covers");
    }
    Ok(())
}

fn validate_validation_commands(contract: &Value) -> Result<(), String> {
    let commands = command_map(contract);
    let gate_command_ids = array(contract, "required_child_gates")
        .iter()
        .map(|gate| string(gate, "command_id").to_string())
        .collect::<BTreeSet<_>>();
    for command_id in &gate_command_ids {
        if !commands.contains_key(command_id) {
            return Err(format!("missing command for child gate {command_id}"));
        }
    }
    for required in ["signoff-contract-test", "signoff-contract-clippy"] {
        if !commands.contains_key(required) {
            return Err(format!("missing {required}"));
        }
    }

    for command in commands.values() {
        let command_id = string(command, "command_id");
        let text = string(command, "command");
        if !text.starts_with(REQUIRED_RCH_PREFIX) {
            return Err(format!("{command_id}: command is not remote-required RCH"));
        }
        if !text.contains(" CARGO_TARGET_DIR=") {
            return Err(format!(
                "{command_id}: command must isolate CARGO_TARGET_DIR"
            ));
        }
        if !(text.contains(" cargo test ") || text.contains(" cargo clippy ")) {
            return Err(format!("{command_id}: command must be Cargo validation"));
        }
        if text.contains("RCH_ALLOW_LOCAL=1") || text.contains("RCH_REQUIRE_REMOTE=0") {
            return Err(format!(
                "{command_id}: command contains local fallback marker"
            ));
        }
        string(command, "bead_id");
        string(command, "exact_output_must_report");
    }

    Ok(())
}

fn validate_first_blocker_policy(output: &Value) -> Result<(), String> {
    let final_verdict = output
        .get("final_verdict")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let blocked = output
        .get("blocked")
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let blocker_present = output
        .get("first_blocker_line")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty());

    if (blocked || matches!(final_verdict, "blocked" | "no-win")) && !blocker_present {
        return Err("missing first blocker line".to_string());
    }
    Ok(())
}

fn validate_output_fixture(output: &Value, contract: &Value) -> Result<(), String> {
    validate_first_blocker_policy(output)?;

    if string(output, "scenario_id") != "final-proof-reuse-signoff-v1" {
        return Err("unexpected final scenario id".to_string());
    }
    if string(output, "schema_version") != SCHEMA_VERSION {
        return Err("final output schema version drifted".to_string());
    }
    if string(output, "final_verdict") != "pass" {
        return Err("positive final output must pass".to_string());
    }
    if bool_field(output, "blocked") {
        return Err("positive final output must not be blocked".to_string());
    }
    if optional_string(output, "first_blocker_line").is_some() {
        return Err("positive final output must not carry a blocker".to_string());
    }
    if bool_field(output, "cache_hit_is_fresh_rch_pass") {
        return Err("cache hit evidence cannot be a fresh RCH pass".to_string());
    }

    let commands = command_map(contract);
    let command_ids = string_set(output, "exact_command_ids");
    let expected_command_ids = commands.keys().cloned().collect::<BTreeSet<_>>();
    if command_ids != expected_command_ids {
        return Err("final output must cite every exact validation command".to_string());
    }

    let fresh_expected: u64 = commands
        .values()
        .filter(|command| bool_field(command, "fresh_rch_required_for_final_signoff"))
        .count()
        .try_into()
        .expect("fresh command count fits in u64");
    let cache_expected: u64 =
        u64::try_from(commands.len()).expect("command count fits in u64") - fresh_expected;
    if u64_field(output, "fresh_rch_pass_count") != fresh_expected {
        return Err("fresh RCH pass count must match fresh signoff commands".to_string());
    }
    if u64_field(output, "approved_cache_hit_count") != cache_expected {
        return Err("approved cache hit count must match cited child gates".to_string());
    }

    let hashed_paths = array(contract, "source_artifact_hashes")
        .iter()
        .map(|artifact| string(artifact, "path").to_string())
        .collect::<BTreeSet<_>>();
    if string_set(output, "source_artifacts") != hashed_paths {
        return Err("final output must list every hashed source artifact".to_string());
    }

    let text = string(output, "operator_closeout_text").to_ascii_lowercase();
    for required in [
        "fresh rch passes",
        "approved cache hits",
        "not a fresh rch pass",
        "no workspace-health",
        "git push origin main:master",
    ] {
        if !text.contains(required) {
            return Err(format!("operator closeout text missing {required}"));
        }
    }
    for forbidden in [
        "cache evidence proves workspace-health",
        "cache evidence proves release-readiness",
        "approved cache hits prove workspace-health",
        "approved cache hits prove release-readiness",
    ] {
        if text.contains(forbidden) {
            return Err(format!("unsupported broad claim: {forbidden}"));
        }
    }

    Ok(())
}

fn validate_negative_fixture(fixture: &Value) -> Result<(), String> {
    let scenario_id = string(fixture, "scenario_id");
    if string(fixture, "expected_verdict") != "blocked" {
        return Err(format!("{scenario_id}: negative fixture must block"));
    }
    let reason = string(fixture, "expected_reason_code");
    let expected = match scenario_id {
        "missing-schema" => "missing-schema",
        "stale-cache-hit" => "stale-cache-hit",
        "local-fallback" => "local-fallback-marker",
        "missing-rch-command" => "missing-rch-command",
        "unsupported-broad-claim" => "unsupported-broad-claim",
        "missing-first-blocker-line" => "missing-first-blocker-line",
        other => return Err(format!("unknown negative fixture {other}")),
    };
    if reason != expected {
        return Err(format!("{scenario_id}: wrong reason {reason}"));
    }
    if scenario_id == "missing-first-blocker-line" {
        if optional_string(fixture, "first_blocker_line").is_some() {
            return Err(format!(
                "{scenario_id}: missing-blocker fixture must omit blocker text"
            ));
        }
    } else if optional_string(fixture, "first_blocker_line").is_none() {
        return Err(format!(
            "{scenario_id}: negative fixture needs blocker text"
        ));
    }
    if array(fixture, "mutations").is_empty() {
        return Err(format!("{scenario_id}: mutation list must be nonempty"));
    }
    Ok(())
}

fn expect_rejection(result: Result<(), String>, expected: &str) {
    match result {
        Ok(()) => panic!("expected rejection containing {expected}"),
        Err(actual) => assert!(
            actual.contains(expected),
            "expected rejection containing {expected}, got {actual}"
        ),
    }
}

#[test]
fn signoff_sources_exist_and_hashes_match_current_child_artifacts() {
    let contract = contract();
    validate_signoff_schema(&contract).expect("signoff schema should be current");

    let sources = source_paths(&contract);
    for required in [
        CONTRACT_PATH,
        "tests/proof_reuse_signoff_contract.rs",
        BEADS_PATH,
        AGENTS_PATH,
        CACHE_CONTRACT_PATH,
        E2E_CONTRACT_PATH,
        HANDOFF_CONTRACT_PATH,
        LARGE_CORPUS_CONTRACT_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
    ] {
        assert!(
            sources.contains(required),
            "missing source_of_truth {required}"
        );
        assert!(
            repo_path(required).exists(),
            "source path must exist: {required}"
        );
    }

    validate_source_artifact_hashes(&contract).expect("source artifact hashes should be current");
}

#[test]
fn child_gates_are_closed_and_artifact_versions_are_current() {
    let contract = contract();
    let close_gate = object(&contract, "epic_close_gate");
    let tracker = object(close_gate, "tracker_snapshot");
    let child_statuses = array(tracker, "child_statuses")
        .iter()
        .map(|child| {
            (
                string(child, "bead_id").to_string(),
                string(child, "status").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(string(close_gate, "parent_bead"), "asupersync-5pziae");
    assert_eq!(string(tracker, "parent_status"), "open");
    assert_eq!(
        string_set(close_gate, "parent_must_depend_on"),
        string_set(tracker, "parent_dependencies"),
        "parent epic must depend on every child gate"
    );
    string(tracker, "captured_with");

    for bead_id in string_set(
        close_gate,
        "closed_child_gates_required_before_signoff_close",
    ) {
        let status = child_statuses
            .get(&bead_id)
            .unwrap_or_else(|| panic!("missing bead {bead_id}"));
        assert_eq!(
            status, "closed",
            "{bead_id}: child gate must be closed before signoff closes"
        );
    }

    let allowed_signoff_states = string_set(close_gate, "signoff_status_allowed_while_validating");
    let signoff_status = child_statuses
        .get("asupersync-5pziae.8")
        .expect("signoff status exists");
    assert!(
        allowed_signoff_states.contains(signoff_status),
        "signoff may be in_progress during validation and closed after commit"
    );

    for gate in array(&contract, "required_child_gates") {
        let bead_id = string(gate, "bead_id");
        let status = child_statuses
            .get(bead_id)
            .unwrap_or_else(|| panic!("missing child gate bead {bead_id}"));
        assert_eq!(status, string(gate, "required_status"));
        assert!(repo_path(string(gate, "artifact")).exists());
        assert!(repo_path(string(gate, "contract_test")).exists());

        if let Some(version_field) = optional_string(gate, "artifact_version_field") {
            let artifact = json(string(gate, "artifact"));
            assert_eq!(
                artifact.get(version_field).and_then(Value::as_str),
                optional_string(gate, "artifact_version"),
                "{bead_id}: artifact version drifted"
            );
        }
    }
}

#[test]
fn validation_commands_are_remote_required_exact_and_cover_every_gate() {
    let contract = contract();
    validate_validation_commands(&contract).expect("validation commands should be exact RCH");

    let closeout_policy = object(&contract, "closeout_policy");
    assert!(bool_field(
        closeout_policy,
        "exact_rch_commands_must_be_cited"
    ));
    assert!(bool_field(
        closeout_policy,
        "cache_hit_is_never_fresh_rch_pass"
    ));
    assert!(bool_field(
        closeout_policy,
        "unsupported_broad_claims_fail_closed"
    ));
    assert_eq!(
        string(closeout_policy, "post_push_sync_command"),
        "git push origin main:master"
    );
    assert_eq!(string(closeout_policy, "required_branch"), "main");
    assert_eq!(string(closeout_policy, "forbidden_branch"), "master");
}

#[test]
fn signoff_reuses_child_contracts_without_broadening_their_claims() {
    let contract = contract();
    assert_eq!(
        json(CACHE_CONTRACT_PATH)
            .get("contract_version")
            .and_then(Value::as_str),
        Some("proof-reuse-cache-contract-v1")
    );
    assert_eq!(
        json(HANDOFF_CONTRACT_PATH)
            .get("contract_version")
            .and_then(Value::as_str),
        Some("proof-reuse-handoff-receipt-contract-v1")
    );
    assert_eq!(
        json(LARGE_CORPUS_CONTRACT_PATH)
            .get("schema_version")
            .and_then(Value::as_str),
        Some("proof-reuse-large-corpus-contract-v1")
    );
    assert!(
        json(E2E_CONTRACT_PATH)
            .get("policy")
            .and_then(|policy| policy.get("cache_hit_is_never_fresh_rch_pass"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );

    let graph = object(&contract, "graph_alert_evidence");
    assert_eq!(string(graph, "command"), "bv --robot-alerts");
    assert_eq!(u64_field(object(graph, "summary"), "total"), 0);
    assert!(
        array(graph, "relevant_alerts").is_empty(),
        "epic must have no relevant graph alerts at signoff"
    );

    validate_output_fixture(object(&contract, "final_output_fixture"), &contract)
        .expect("final output fixture should be citeable");
}

#[test]
fn negative_fixtures_cover_fail_closed_signoff_paths() {
    let contract = contract();
    let fixtures = array(&contract, "negative_fixtures");
    let scenario_ids = fixtures
        .iter()
        .map(|fixture| string(fixture, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scenario_ids,
        BTreeSet::from([
            "local-fallback".to_string(),
            "missing-first-blocker-line".to_string(),
            "missing-rch-command".to_string(),
            "missing-schema".to_string(),
            "stale-cache-hit".to_string(),
            "unsupported-broad-claim".to_string(),
        ])
    );

    for fixture in fixtures {
        validate_negative_fixture(fixture).expect("negative fixture must fail closed");
    }
}

#[test]
fn synthetic_bad_signoff_scenarios_are_rejected() {
    let contract = contract();

    let mut missing_schema = contract.clone();
    missing_schema
        .as_object_mut()
        .expect("contract must be an object")
        .remove("schema_version");
    expect_rejection(
        validate_signoff_schema(&missing_schema),
        "schema_version must be a string",
    );

    let mut stale_cache_hit = contract.clone();
    let first_hash = array_mut(&mut stale_cache_hit, "source_artifact_hashes")
        .first_mut()
        .expect("source artifact hash fixture exists");
    first_hash
        .as_object_mut()
        .expect("source artifact hash must be an object")
        .insert("sha256".to_string(), Value::String("0".repeat(64)));
    expect_rejection(
        validate_source_artifact_hashes(&stale_cache_hit),
        "source hash mismatch",
    );

    let mut local_fallback = contract.clone();
    let signoff_test = command_mut(&mut local_fallback, "signoff-contract-test");
    let local_command = string(signoff_test, "command")
        .strip_prefix(REQUIRED_RCH_PREFIX)
        .expect("fixture command should start with remote-required prefix")
        .to_string();
    signoff_test
        .as_object_mut()
        .expect("command must be an object")
        .insert("command".to_string(), Value::String(local_command));
    expect_rejection(
        validate_validation_commands(&local_fallback),
        "not remote-required RCH",
    );

    let mut missing_command = object(&contract, "final_output_fixture").clone();
    array_mut(&mut missing_command, "exact_command_ids")
        .retain(|command_id| command_id.as_str() != Some("large-corpus-contract"));
    expect_rejection(
        validate_output_fixture(&missing_command, &contract),
        "cite every exact validation command",
    );

    let mut broad_claim = object(&contract, "final_output_fixture").clone();
    broad_claim
        .as_object_mut()
        .expect("final output fixture must be an object")
        .insert(
            "operator_closeout_text".to_string(),
            Value::String(
                "Final proof reuse signoff passed. Fresh RCH passes: signoff-contract-test and signoff-contract-clippy. Approved cache hits: cache-schema-contract, classifier-contract, index-query-contract, manifest-status-contract, handoff-receipt-contract, e2e-scenarios-contract, and large-corpus-contract. Approved cache hit evidence is not a fresh RCH pass. No workspace-health or release-readiness claim is made from cache evidence. Cache evidence proves workspace-health. After committing, push main and mirror with git push origin main:master."
                    .to_string(),
            ),
        );
    expect_rejection(
        validate_output_fixture(&broad_claim, &contract),
        "unsupported broad claim",
    );

    let mut missing_blocker = object(&contract, "final_output_fixture").clone();
    let output = missing_blocker
        .as_object_mut()
        .expect("final output fixture must be an object");
    output.insert(
        "final_verdict".to_string(),
        Value::String("blocked".to_string()),
    );
    output.insert("blocked".to_string(), Value::Bool(true));
    output.insert("first_blocker_line".to_string(), Value::Null);
    expect_rejection(
        validate_first_blocker_policy(&missing_blocker),
        "missing first blocker line",
    );
}
