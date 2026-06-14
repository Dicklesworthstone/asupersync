#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const DURABLE_RECEIPT_FIXTURE_ROOT: &str = "tests/fixtures/durable_rch_proof_receipt";
const FRONTIER_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
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

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_string(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn frontier_fixture_map(frontier: &Value) -> BTreeMap<String, Value> {
    array(frontier, "fixtures")
        .iter()
        .map(|fixture| (string(fixture, "fixture_id").to_string(), fixture.clone()))
        .collect()
}

fn proof_commands_for_lanes(
    lane_ids: &BTreeSet<String>,
    lanes: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    lane_ids
        .iter()
        .map(|lane_id| {
            let lane = lanes
                .get(lane_id)
                .unwrap_or_else(|| panic!("snapshot references missing lane {lane_id}"));
            string(lane, "command").to_string()
        })
        .collect()
}

fn lane_reuse_policy<'a>(lane: &'a Value, lane_id: &str) -> Result<&'a Value, String> {
    lane.get("proof_reuse_policy")
        .ok_or_else(|| format!("{lane_id}: missing proof_reuse_policy"))
}

fn validate_proof_reuse_status_row(
    row: &Value,
    lanes: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let row_id = string(row, "row_id");
    let status = string(row, "proof_evidence_status");
    let lane_id = string(row, "manifest_lane_id");
    let claim_scope = string(row, "claim_scope");
    let dirty_status = string(row, "dirty_frontier_status");
    let reason_codes = string_set(row, "reason_codes");
    let rerun_command = string(row, "rerun_command");
    let lane = lanes
        .get(lane_id)
        .ok_or_else(|| format!("{row_id}: unknown lane {lane_id}"))?;
    let lane_command = string(lane, "command");
    let reuse_policy = lane_reuse_policy(lane, lane_id)?;
    let allowed_scopes = string_set(reuse_policy, "allowed_claim_scopes");
    let non_citeable_scopes = string_set(reuse_policy, "non_citeable_claim_scopes");

    if rerun_command != lane_command {
        return Err(format!(
            "{row_id}: rerun command must match manifest lane command"
        ));
    }
    if bool_field(row, "cache_hit_is_fresh_rch_pass") {
        return Err(format!("{row_id}: cache hit cannot be a fresh RCH pass"));
    }

    match status {
        "fresh-rch-pass" => {
            if dirty_status != "clean" || !reason_codes.is_empty() {
                return Err(format!(
                    "{row_id}: fresh pass rows must be clean and reason-free"
                ));
            }
        }
        "approved-cache-hit" => {
            if !bool_field(reuse_policy, "cache_hits_allowed") {
                return Err(format!("{row_id}: lane does not allow cache hits"));
            }
            if !allowed_scopes.contains(claim_scope) {
                return Err(format!(
                    "{row_id}: claim scope {claim_scope} is not allowed for lane {lane_id}"
                ));
            }
            if non_citeable_scopes.contains(claim_scope) {
                return Err(format!(
                    "{row_id}: claim scope {claim_scope} is explicitly non-citeable"
                ));
            }
            if dirty_status != "clean" || !reason_codes.is_empty() {
                return Err(format!(
                    "{row_id}: approved cache hits must be clean and reason-free"
                ));
            }
        }
        "rerun-required" => {
            if dirty_status == "dirty-overlap"
                && !bool_field(reuse_policy, "requires_fresh_rerun_when_dirty_overlap")
            {
                return Err(format!(
                    "{row_id}: dirty-overlap rerun requires manifest policy support"
                ));
            }
            if dirty_status == "dirty-overlap" && !reason_codes.contains("dirty-frontier-overlap") {
                return Err(format!(
                    "{row_id}: dirty-overlap rerun rows must include dirty-frontier-overlap"
                ));
            }
        }
        "stale-evidence" => {
            if !reason_codes.contains("stale-head") {
                return Err(format!("{row_id}: stale rows must carry stale-head"));
            }
        }
        "blocked" => {
            if reason_codes.is_empty() {
                return Err(format!("{row_id}: blocked rows need reason codes"));
            }
        }
        "no-win" => {
            if reason_codes.iter().all(|reason| !reason.contains("no-win")) {
                return Err(format!("{row_id}: no-win rows need a no-win reason"));
            }
        }
        "unsupported" => {
            if !reason_codes.contains("broad-claim-unsupported") {
                return Err(format!(
                    "{row_id}: unsupported rows need broad-claim-unsupported"
                ));
            }
            if allowed_scopes.contains(claim_scope) && !non_citeable_scopes.contains(claim_scope) {
                return Err(format!(
                    "{row_id}: unsupported claim scope unexpectedly allowed by manifest"
                ));
            }
        }
        other => return Err(format!("{row_id}: unknown proof evidence status {other}")),
    }

    Ok(())
}

fn nested_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(key)?;
    }
    Some(cursor)
}

fn nested_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    nested_value(value, path).and_then(Value::as_str)
}

fn nested_bool(value: &Value, path: &[&str]) -> Option<bool> {
    nested_value(value, path).and_then(Value::as_bool)
}

fn nested_string_set(value: &Value, path: &[&str]) -> BTreeSet<String> {
    nested_value(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| panic!("{path:?} entries must be strings"))
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn durable_receipt_fixture(name: &str) -> Value {
    let relative = format!("{DURABLE_RECEIPT_FIXTURE_ROOT}/{name}");
    json(&relative)
}

fn durable_receipt_from_row(row: &Value) -> Value {
    let fixture = durable_receipt_fixture(string(row, "fixture"));
    let mut receipt = fixture
        .get("receipt")
        .unwrap_or_else(|| panic!("{}: fixture missing receipt", string(row, "row_id")))
        .clone();

    for mutation in row
        .get("synthetic_mutations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match mutation
            .as_str()
            .unwrap_or_else(|| panic!("{}: mutation must be a string", string(row, "row_id")))
        {
            "wrong-command-envelope" => {
                receipt["command"]["command"] = Value::String(
                    "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wrong_durable_receipt CARGO_INCREMENTAL=0 cargo test -p asupersync --test wrong_contract -- --nocapture".to_string(),
                );
            }
            other => panic!(
                "{}: unknown durable receipt mutation {other}",
                string(row, "row_id")
            ),
        }
    }

    receipt
}

fn durable_non_citeable_scopes(manifest: &Value) -> BTreeSet<String> {
    manifest
        .get("proof_reuse_policy")
        .and_then(|policy| policy.get("durable_receipt_candidate_policy"))
        .map(|policy| string_set(policy, "non_citeable_claim_scopes"))
        .unwrap_or_default()
}

fn classify_durable_receipt_candidate(
    receipt: &Value,
    row: &Value,
    manifest: &Value,
    lanes: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    let mut reasons = BTreeSet::new();
    let receipt_lane_id = optional_string(receipt, "manifest_lane_id").unwrap_or("");
    let claim_scope = optional_string(receipt, "claim_scope").unwrap_or("");
    let durable_non_citeable = durable_non_citeable_scopes(manifest);

    if optional_string(receipt, "schema_version") != Some("durable-rch-proof-receipt-v1") {
        reasons.insert("invalid-receipt-schema".to_string());
    }
    if optional_string(receipt, "lifecycle_state") != Some("terminal_pass")
        || optional_string(receipt, "terminal_classification") != Some("pass")
        || optional_string(receipt, "proof_evidence_status") != Some("fresh-rch-pass")
        || nested_string(receipt, &["outcome", "status"]) != Some("pass")
    {
        reasons.insert("not-terminal-pass".to_string());
    }

    if nested_bool(receipt, &["command", "remote_required"]) != Some(true)
        || nested_bool(receipt, &["command", "local_fallback_allowed"]) != Some(false)
        || !nested_string_set(receipt, &["command", "local_fallback_markers"]).is_empty()
    {
        reasons.insert("local-fallback-detected".to_string());
    }

    if nested_string(receipt, &["source", "branch"]) != Some("main") {
        reasons.insert("non-main-branch".to_string());
    }
    if nested_string(receipt, &["source", "head_commit"])
        != nested_string(receipt, &["source", "expected_head"])
    {
        reasons.insert("stale-head".to_string());
    }
    if nested_string(receipt, &["source", "dirty_frontier_status"]) != Some("clean") {
        reasons.insert("dirty-frontier-overlap".to_string());
    }

    let lane = match lanes.get(receipt_lane_id) {
        Some(lane) => lane,
        None => {
            reasons.insert("missing-manifest-lane".to_string());
            return reasons;
        }
    };

    if nested_string(receipt, &["command", "command"]) != Some(string(lane, "command")) {
        reasons.insert("command-envelope-mismatch".to_string());
    }

    let receipt_guarantees = string_set(receipt, "manifest_guarantee_ids");
    let lane_guarantees = string_set(lane, "guarantee_ids");
    if receipt_guarantees.is_empty() || receipt_guarantees.is_disjoint(&lane_guarantees) {
        reasons.insert("manifest-guarantee-mismatch".to_string());
    }

    let expected_feature_flags = string_set(row, "expected_feature_flags");
    let lane_feature_flags = string_set(lane, "feature_flags");
    if expected_feature_flags != lane_feature_flags {
        reasons.insert("wrong-feature-set".to_string());
    }

    let proof_reuse_policy = lane
        .get("proof_reuse_policy")
        .unwrap_or_else(|| panic!("{receipt_lane_id}: missing proof_reuse_policy"));
    let allowed_scopes = string_set(proof_reuse_policy, "allowed_claim_scopes");
    let non_citeable_scopes = string_set(proof_reuse_policy, "non_citeable_claim_scopes");
    if durable_non_citeable.contains(claim_scope) || non_citeable_scopes.contains(claim_scope) {
        reasons.insert("broad-claim-unsupported".to_string());
    } else if !allowed_scopes.contains(claim_scope) {
        reasons.insert("claim-scope-not-allowed".to_string());
    }

    reasons
}

fn validate_durable_receipt_status_row(
    row: &Value,
    manifest: &Value,
    lanes: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let row_id = string(row, "row_id");
    let row_lane_id = string(row, "manifest_lane_id");
    let row_lane = lanes
        .get(row_lane_id)
        .ok_or_else(|| format!("{row_id}: unknown row lane {row_lane_id}"))?;
    if string(row, "rerun_command") != string(row_lane, "command") {
        return Err(format!(
            "{row_id}: rerun command must match the row manifest lane command"
        ));
    }

    let receipt = durable_receipt_from_row(row);
    let actual_reasons = classify_durable_receipt_candidate(&receipt, row, manifest, lanes);
    let expected_reasons = string_set(row, "reason_codes");
    if actual_reasons != expected_reasons {
        return Err(format!(
            "{row_id}: durable receipt reasons drifted: expected {expected_reasons:?}, got {actual_reasons:?}"
        ));
    }

    match string(row, "expected_decision") {
        "accepted" if !actual_reasons.is_empty() => {
            return Err(format!("{row_id}: accepted row has refusal reasons"));
        }
        "refused" if actual_reasons.is_empty() => {
            return Err(format!("{row_id}: refused row has no refusal reasons"));
        }
        "accepted" | "refused" => {}
        other => return Err(format!("{row_id}: unknown expected_decision {other}")),
    }

    let expected_status = if actual_reasons.is_empty() {
        "fresh-rch-pass"
    } else if actual_reasons.contains("broad-claim-unsupported") {
        "unsupported"
    } else if actual_reasons.contains("stale-head") {
        "stale-evidence"
    } else {
        "blocked"
    };
    if string(row, "proof_evidence_status") != expected_status {
        return Err(format!(
            "{row_id}: proof_evidence_status must be {expected_status}"
        ));
    }

    Ok(())
}

fn validate_claim_lane_mapping(
    entry: &Value,
    lanes: &BTreeMap<String, Value>,
    guarantees: &BTreeMap<String, Value>,
) -> Result<BTreeSet<String>, String> {
    let claim_id = string(entry, "claim_id");
    let lane_ids = string_set(entry, "manifest_lane_ids");
    let guarantee_ids = string_set(entry, "manifest_guarantee_ids");
    if lane_ids.is_empty() {
        return Err(format!("{claim_id}: missing lane ids"));
    }
    if guarantee_ids.is_empty() {
        return Err(format!("{claim_id}: missing guarantee ids"));
    }

    for lane_id in &lane_ids {
        if !lanes.contains_key(lane_id) {
            return Err(format!("{claim_id}: unknown lane {lane_id}"));
        }
    }
    for guarantee_id in &guarantee_ids {
        if !guarantees.contains_key(guarantee_id) {
            return Err(format!("{claim_id}: unknown guarantee {guarantee_id}"));
        }
    }

    for guarantee_id in &guarantee_ids {
        let guarantee = guarantees
            .get(guarantee_id)
            .expect("guarantee existence checked above");
        let mapped_lanes = string_set(guarantee, "lane_ids");
        if mapped_lanes.is_disjoint(&lane_ids) {
            return Err(format!(
                "{claim_id}: guarantee {guarantee_id} must share at least one listed lane"
            ));
        }
    }

    for lane_id in &lane_ids {
        let lane = lanes.get(lane_id).expect("lane existence checked above");
        let lane_guarantees = string_set(lane, "guarantee_ids");
        if lane_guarantees.is_disjoint(&guarantee_ids) {
            return Err(format!(
                "{claim_id}: lane {lane_id} must cover at least one listed guarantee"
            ));
        }
    }

    let expected_commands = proof_commands_for_lanes(&lane_ids, lanes);
    let snapshot_commands = string_set(entry, "proof_commands");
    if expected_commands != snapshot_commands {
        return Err(format!(
            "{claim_id}: proof commands must match the manifest lane commands"
        ));
    }

    Ok(snapshot_commands)
}

fn validate_status_support(entry: &Value, lanes: &BTreeMap<String, Value>) -> Result<(), String> {
    let claim_id = string(entry, "claim_id");
    let status = string(entry, "status");
    let lane_ids = string_set(entry, "manifest_lane_ids");
    let lane_kinds = lane_ids
        .iter()
        .map(|lane_id| {
            lanes
                .get(lane_id)
                .map(|lane| string(lane, "kind").to_string())
                .ok_or_else(|| format!("{claim_id}: unknown lane {lane_id}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    match status {
        "green" => {
            let frontier_only_kinds = [
                "compile_frontier",
                "test_frontier",
                "lint_frontier",
                "format_frontier",
                "documentation_frontier",
            ];
            if lane_kinds
                .iter()
                .any(|kind| frontier_only_kinds.contains(&kind.as_str()))
            {
                return Err(format!(
                    "{claim_id}: frontier lane kinds cannot be represented as green: {lane_kinds:?}"
                ));
            }
        }
        "yellow_frontier" => {
            if !lane_kinds.iter().any(|kind| kind.ends_with("_frontier")) {
                return Err(format!(
                    "{claim_id}: yellow_frontier row must include at least one frontier lane"
                ));
            }
        }
        "yellow_scoped" => {
            let notes = string(entry, "notes").to_ascii_lowercase();
            if !(notes.contains("scoped") || notes.contains("quarantine")) {
                return Err(format!(
                    "{claim_id}: yellow_scoped row must explain its scope or quarantine"
                ));
            }
        }
        "red_blocked_external" => {}
        other => return Err(format!("{claim_id}: unknown status {other}")),
    }

    Ok(())
}

fn validate_blocked_frontier_record(
    blocked: &Value,
    fixtures: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let blocked = blocked
        .as_object()
        .ok_or_else(|| "red row must have a blocked_frontier object".to_string())?;
    let fixture_id = blocked
        .get("fixture_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "blocked fixture_id".to_string())?;
    let fixture = fixtures
        .get(fixture_id)
        .ok_or_else(|| format!("missing frontier fixture {fixture_id}"))?;
    let expected = fixture
        .get("expected_record")
        .ok_or_else(|| format!("{fixture_id}: missing expected_record"))?;
    let first_failure = expected
        .get("first_failure")
        .ok_or_else(|| format!("{fixture_id}: missing expected first_failure"))?;
    let blocked_failure = blocked
        .get("first_failure")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{fixture_id}: blocked first_failure must be an object"))?;

    for (blocked_key, expected_value) in [
        ("command", fixture.get("command")),
        ("decision", expected.get("decision")),
        ("error_class", expected.get("error_class")),
        ("summary", expected.get("summary")),
        (
            "supplemental_proof_command",
            fixture.get("supplemental_proof_command"),
        ),
    ] {
        if blocked.get(blocked_key) != expected_value {
            return Err(format!(
                "{fixture_id}: blocked_frontier.{blocked_key} no longer matches validation frontier fixture"
            ));
        }
    }

    for key in ["crate_or_surface", "target", "file", "line"] {
        if blocked_failure.get(key) != first_failure.get(key) {
            return Err(format!(
                "{fixture_id}: first_failure.{key} must match validation frontier fixture"
            ));
        }
    }

    Ok(())
}

fn validate_external_blocker_record(blocked: &Value) -> Result<(), String> {
    let blocked = blocked
        .as_object()
        .ok_or_else(|| "blocked proof evidence row must have a blocker object".to_string())?;

    for key in ["blocker_id", "blocked_at", "reason", "required_followup"] {
        let value = blocked
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("blocked proof evidence row must include {key}"))?;
        if value.trim().is_empty() {
            return Err(format!("blocked proof evidence row {key} must be nonempty"));
        }
    }

    let blocked_at = blocked
        .get("blocked_at")
        .and_then(Value::as_str)
        .expect("blocked_at checked above");
    if !(blocked_at.contains('T') && blocked_at.ends_with('Z')) {
        return Err("blocked_at must be an ISO-8601 UTC timestamp".to_string());
    }

    let followup = blocked
        .get("required_followup")
        .and_then(Value::as_str)
        .expect("required_followup checked above");
    if !followup.contains("Rerun") {
        return Err("blocked proof evidence rows must require a rerun follow-up".to_string());
    }

    Ok(())
}

#[test]
fn snapshot_declares_schema_sources_and_required_categories() {
    let snapshot = json(SNAPSHOT_PATH);
    assert_eq!(
        snapshot.get("contract_version").and_then(Value::as_str),
        Some("proof-status-snapshot-v1")
    );
    assert_eq!(
        snapshot.get("bead_id").and_then(Value::as_str),
        Some("asupersync-aj7lx3.5")
    );

    let source = snapshot
        .get("source_of_truth")
        .expect("source_of_truth object");
    assert_eq!(source["snapshot"].as_str(), Some(SNAPSHOT_PATH));
    assert_eq!(source["proof_lane_manifest"].as_str(), Some(MANIFEST_PATH));
    assert_eq!(
        source["validation_frontier_ledger"].as_str(),
        Some(FRONTIER_PATH)
    );
    assert_eq!(source["readme"].as_str(), Some(README_PATH));
    assert_eq!(source["agent_instructions"].as_str(), Some(AGENTS_PATH));

    let required = string_set(&snapshot, "required_claim_categories");
    let actual = array(&snapshot, "claim_categories")
        .iter()
        .map(|entry| string(entry, "category").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required, actual,
        "required claim categories must exactly match snapshot entries"
    );
    assert_eq!(
        actual.len(),
        28,
        "snapshot must cover the requested claim list"
    );
}

#[test]
fn statuses_are_known_and_include_live_green_and_frontier_rows() {
    let snapshot = json(SNAPSHOT_PATH);
    let allowed = array(&snapshot, "status_catalog")
        .iter()
        .map(|entry| string(entry, "status").to_string())
        .collect::<BTreeSet<_>>();
    for expected in [
        "green",
        "yellow_scoped",
        "yellow_frontier",
        "red_blocked_external",
    ] {
        assert!(allowed.contains(expected), "missing status {expected}");
    }

    let mut seen = BTreeSet::new();
    for entry in array(&snapshot, "claim_categories") {
        let status = string(entry, "status");
        assert!(allowed.contains(status), "unknown status {status}");
        seen.insert(status.to_string());
    }
    for required in ["green", "yellow_frontier"] {
        assert!(
            seen.contains(required),
            "dashboard must contain at least one {required} row"
        );
    }

    let evidence_allowed = array(&snapshot, "proof_evidence_status_catalog")
        .iter()
        .map(|entry| string(entry, "status").to_string())
        .collect::<BTreeSet<_>>();
    for expected in [
        "fresh-rch-pass",
        "approved-cache-hit",
        "rerun-required",
        "stale-evidence",
        "blocked",
        "no-win",
        "unsupported",
    ] {
        assert!(
            evidence_allowed.contains(expected),
            "missing proof evidence status {expected}"
        );
    }

    for entry in array(&snapshot, "claim_categories") {
        let proof_status = string(entry, "proof_evidence_status");
        assert!(
            evidence_allowed.contains(proof_status),
            "{}: unknown proof evidence status {proof_status}",
            string(entry, "claim_id")
        );
    }
}

#[test]
fn every_claim_maps_to_manifest_lanes_guarantees_and_commands() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);

    for entry in array(&snapshot, "claim_categories") {
        let claim_id = string(entry, "claim_id");
        let snapshot_commands = validate_claim_lane_mapping(entry, &lanes, &guarantees)
            .unwrap_or_else(|error| panic!("{error}"));
        for command in &snapshot_commands {
            assert!(
                command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
                "{claim_id}: proof command must require remote rch execution: {command}"
            );
            if command.contains(" cargo ") {
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "{claim_id}: cargo proof command must isolate target output: {command}"
                );
                assert!(
                    !command.contains("rch exec -- cargo"),
                    "{claim_id}: cargo proof command must not use bare rch cargo routing: {command}"
                );
            }
        }
    }
}

#[test]
fn status_rows_do_not_overstate_frontier_or_scoped_claims() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);

    for entry in array(&snapshot, "claim_categories") {
        validate_status_support(entry, &lanes).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn fourth_wave_status_rows_preserve_child_lane_boundaries() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let rows = array(&snapshot, "claim_categories");
    let by_claim = rows
        .iter()
        .map(|entry| (string(entry, "claim_id").to_string(), entry))
        .collect::<BTreeMap<_, _>>();
    let expected_lanes = BTreeSet::from([
        "fourth-wave-governor-schema-contract".to_string(),
        "fourth-wave-governor-policy-engine".to_string(),
        "fourth-wave-swarm-replay-corpus".to_string(),
        "fourth-wave-runtime-bridge-contract".to_string(),
        "fourth-wave-benchmark-contract".to_string(),
        "fourth-wave-governor-signoff-runbook".to_string(),
        "fourth-wave-governor-final-signoff".to_string(),
    ]);

    for claim_id in [
        "fourth-wave-governor-schema-proof",
        "fourth-wave-governor-policy-engine-proof",
        "fourth-wave-swarm-replay-corpus",
        "fourth-wave-runtime-bridge",
        "fourth-wave-benchmark-no-claim-contract",
        "fourth-wave-final-aggregated-signoff",
    ] {
        let entry = by_claim
            .get(claim_id)
            .unwrap_or_else(|| panic!("missing fourth-wave claim {claim_id}"));
        validate_claim_lane_mapping(entry, &lanes, &guarantees)
            .unwrap_or_else(|error| panic!("{error}"));
        let proof_evidence_status = string(entry, "proof_evidence_status");
        assert!(
            ["blocked", "rerun-required"].contains(&proof_evidence_status),
            "{claim_id}: fourth-wave status rows require a rerun or explicit blocker before proof citation"
        );
        if proof_evidence_status == "blocked" {
            validate_external_blocker_record(
                entry
                    .get("blocked_frontier")
                    .unwrap_or_else(|| panic!("{claim_id}: missing blocked_frontier")),
            )
            .unwrap_or_else(|error| panic!("{claim_id}: {error}"));
        }
        assert!(
            string(entry, "notes").contains("does not prove")
                || string(entry, "notes").contains("no-claim"),
            "{claim_id}: notes must preserve non-claim language"
        );
    }

    let aggregate = by_claim
        .get("fourth-wave-final-aggregated-signoff")
        .expect("aggregate row");
    assert_eq!(string(aggregate, "status"), "yellow_scoped");
    assert_eq!(string_set(aggregate, "manifest_lane_ids"), expected_lanes);
    assert!(
        string(aggregate, "notes").contains("operator checklist")
            && string(aggregate, "notes").contains("live performance improvement")
            && string(aggregate, "notes").contains("production-on-by-default"),
        "aggregate row must stay scoped and non-performance"
    );
}

#[test]
fn browser_ga_status_row_preserves_js_ts_scope_and_no_claim_boundaries() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let rows = array(&snapshot, "claim_categories");
    let by_claim = rows
        .iter()
        .map(|entry| (string(entry, "claim_id").to_string(), entry))
        .collect::<BTreeMap<_, _>>();
    let row = by_claim
        .get("browser-ga-final-signoff")
        .expect("browser GA final signoff claim row");

    validate_claim_lane_mapping(row, &lanes, &guarantees).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(string(row, "status"), "yellow_scoped");
    assert_eq!(string(row, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(row, "manifest_lane_ids"),
        BTreeSet::from(["browser-ga-final-signoff".to_string()])
    );
    assert_eq!(
        string_set(row, "manifest_guarantee_ids"),
        BTreeSet::from(["browser-ga-final-signoff".to_string()])
    );
    let notes = string(row, "notes");
    for boundary in [
        "scoped JS/TS package GA",
        "does not execute npm publish",
        "broad workspace health",
        "Rust browser API to stable",
        "service-worker direct runtime",
        "shared-worker direct runtime",
    ] {
        assert!(
            notes.contains(boundary),
            "browser GA row must preserve boundary {boundary:?}"
        );
    }
}

#[test]
fn stale_progress_receipt_status_row_preserves_no_claim_boundaries() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let rows = array(&snapshot, "claim_categories");
    let by_claim = rows
        .iter()
        .map(|entry| (string(entry, "claim_id").to_string(), entry))
        .collect::<BTreeMap<_, _>>();
    let row = by_claim
        .get("rch-stale-progress-receipts")
        .expect("stale progress receipt claim row");

    validate_claim_lane_mapping(row, &lanes, &guarantees).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(string(row, "status"), "green");
    assert_eq!(string(row, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(row, "manifest_lane_ids"),
        BTreeSet::from(["rch-stale-progress-receipt-contract".to_string()])
    );
    let notes = string(row, "notes");
    for non_claim in [
        "does not prove source correctness",
        "release readiness",
        "live RCH fleet availability",
        "permission to cancel peer-owned builds",
    ] {
        assert!(
            notes.contains(non_claim),
            "stale progress receipt row must preserve non-claim {non_claim:?}"
        );
    }
}

#[test]
fn proof_reuse_status_rows_preserve_cache_hit_and_rerun_distinctions() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let rows = array(&snapshot, "proof_reuse_status_rows");
    let statuses = rows
        .iter()
        .map(|row| string(row, "proof_evidence_status").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        statuses,
        BTreeSet::from([
            "approved-cache-hit".to_string(),
            "blocked".to_string(),
            "fresh-rch-pass".to_string(),
            "no-win".to_string(),
            "rerun-required".to_string(),
            "stale-evidence".to_string(),
            "unsupported".to_string(),
        ]),
        "proof reuse status rows must keep every operator outcome distinct"
    );

    for row in rows {
        validate_proof_reuse_status_row(row, &lanes).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn rch_topology_preflight_status_row_preserves_blocked_infrastructure_receipt() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let frontier = json(FRONTIER_PATH);
    let lanes = manifest_lanes(&manifest);
    let fixtures = frontier_fixture_map(&frontier);
    let row = array(&snapshot, "proof_reuse_status_rows")
        .iter()
        .find(|row| row["row_id"].as_str() == Some("rch-topology-preflight-blocked"))
        .expect("topology preflight blocked row");

    validate_proof_reuse_status_row(row, &lanes).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(string(row, "proof_evidence_status"), "blocked");
    assert_eq!(
        string(row, "manifest_lane_id"),
        "rch-topology-preflight-canary"
    );
    assert_eq!(
        string_set(row, "reason_codes"),
        BTreeSet::from(["blocked_infrastructure:rch_topology_preflight".to_string()])
    );
    validate_blocked_frontier_record(
        row.get("blocked_frontier")
            .expect("topology preflight row must carry exact blocker fixture"),
        &fixtures,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let notes = string(row, "notes");
    for required in [
        "before Cargo starts",
        "not a source failure",
        "local or direct-SSH Cargo runs are not valid proof substitutes",
    ] {
        assert!(
            notes.contains(required),
            "topology preflight row must preserve boundary note {required:?}"
        );
    }
}

#[test]
fn durable_rch_receipt_status_rows_preserve_manifest_and_claim_boundaries() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let rows = array(&snapshot, "durable_receipt_status_rows");
    let row_ids = rows
        .iter()
        .map(|row| string(row, "row_id").to_string())
        .collect::<BTreeSet<_>>();

    for required in [
        "durable-receipt-terminal-pass-candidate",
        "durable-receipt-missing-manifest-lane",
        "durable-receipt-stale-head",
        "durable-receipt-wrong-command-envelope",
        "durable-receipt-wrong-feature-set",
        "durable-receipt-local-fallback-refused",
        "durable-receipt-unsupported-broad-claim",
    ] {
        assert!(
            row_ids.contains(required),
            "durable receipt status rows must include {required}"
        );
    }

    for row in rows {
        validate_durable_receipt_status_row(row, &manifest, &lanes)
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn synthetic_cache_hit_overclaims_are_rejected() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let reusable = array(&snapshot, "proof_reuse_status_rows")
        .iter()
        .find(|row| row["row_id"].as_str() == Some("focused-contract-approved-cache-hit"))
        .expect("approved cache hit row");

    let mut broad_cache_hit = reusable.clone();
    broad_cache_hit["claim_scope"] = Value::String("workspace-health".to_string());
    let error = validate_proof_reuse_status_row(&broad_cache_hit, &lanes).unwrap_err();
    assert!(
        error.contains("not allowed") || error.contains("non-citeable"),
        "unexpected broad-cache-hit error: {error}"
    );

    let mut dirty_cache_hit = reusable.clone();
    dirty_cache_hit["dirty_frontier_status"] = Value::String("dirty-overlap".to_string());
    dirty_cache_hit["reason_codes"] = serde_json::json!(["dirty-frontier-overlap"]);
    let error = validate_proof_reuse_status_row(&dirty_cache_hit, &lanes).unwrap_err();
    assert!(
        error.contains("clean and reason-free"),
        "unexpected dirty-cache-hit error: {error}"
    );

    let mut stale_without_reason = array(&snapshot, "proof_reuse_status_rows")
        .iter()
        .find(|row| row["proof_evidence_status"].as_str() == Some("stale-evidence"))
        .expect("stale row")
        .clone();
    stale_without_reason["reason_codes"] = serde_json::json!([]);
    let error = validate_proof_reuse_status_row(&stale_without_reason, &lanes).unwrap_err();
    assert!(
        error.contains("stale-head"),
        "unexpected stale-cache-hit error: {error}"
    );
}

#[test]
fn doc_claim_markers_are_present_in_readme_and_agents() {
    let snapshot = json(SNAPSHOT_PATH);
    let docs = BTreeMap::from([
        (README_PATH, read_repo_file(README_PATH)),
        (AGENTS_PATH, read_repo_file(AGENTS_PATH)),
    ]);
    let required_docs = docs.keys().copied().collect::<BTreeSet<_>>();

    for entry in array(&snapshot, "claim_categories") {
        let claim_id = string(entry, "claim_id");
        let markers = entry
            .get("doc_claim_markers")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{claim_id}: doc_claim_markers must be an object"));
        let marker_docs = markers.keys().map(String::as_str).collect::<BTreeSet<_>>();
        assert_eq!(
            marker_docs, required_docs,
            "{claim_id}: each proof claim must carry README and AGENTS markers"
        );
        for (path, marker_values) in markers {
            let doc = docs
                .get(path.as_str())
                .unwrap_or_else(|| panic!("{claim_id}: unexpected doc path {path}"));
            let marker_array = marker_values
                .as_array()
                .unwrap_or_else(|| panic!("{claim_id}: markers for {path} must be an array"));
            assert!(
                !marker_array.is_empty(),
                "{claim_id}: markers for {path} must be nonempty"
            );
            for marker in marker_array {
                let marker = marker
                    .as_str()
                    .unwrap_or_else(|| panic!("{claim_id}: marker must be a string"));
                assert!(
                    doc.contains(marker),
                    "{claim_id}: {path} must contain marker {marker:?}"
                );
            }
        }
    }
}

#[test]
fn red_rows_carry_exact_validation_frontier_records() {
    let snapshot = json(SNAPSHOT_PATH);
    let frontier = json(FRONTIER_PATH);
    let fixtures = frontier_fixture_map(&frontier);

    for entry in array(&snapshot, "claim_categories") {
        let status = string(entry, "status");
        let proof_evidence_status = string(entry, "proof_evidence_status");
        let blocked = entry.get("blocked_frontier").expect("blocked_frontier");
        if status == "red_blocked_external" {
            validate_blocked_frontier_record(blocked, &fixtures)
                .unwrap_or_else(|error| panic!("{error}"));
        } else if proof_evidence_status == "blocked" {
            validate_external_blocker_record(blocked).unwrap_or_else(|error| panic!("{error}"));
        } else {
            assert!(
                blocked.is_null(),
                "non-red rows must not attach blocked frontier records"
            );
        }
    }
}

#[test]
fn synthetic_missing_lane_and_unsupported_green_claims_are_rejected() {
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let missing_lane = serde_json::json!({
        "claim_id": "synthetic-missing-lane",
        "status": "yellow_frontier",
        "manifest_guarantee_ids": ["all-target-compile-frontier"],
        "manifest_lane_ids": ["not-a-real-proof-lane"],
        "proof_commands": [],
        "blocked_frontier": null,
        "notes": "frontier fixture"
    });
    let missing_lane_error =
        validate_claim_lane_mapping(&missing_lane, &lanes, &guarantees).unwrap_err();
    assert!(
        missing_lane_error.contains("unknown lane not-a-real-proof-lane"),
        "unexpected missing-lane error: {missing_lane_error}"
    );

    let unsupported_green = serde_json::json!({
        "claim_id": "synthetic-frontier-green",
        "status": "green",
        "manifest_lane_ids": ["all-targets-check"],
        "notes": "would overstate broad compile-frontier evidence"
    });
    let status_error = validate_status_support(&unsupported_green, &lanes).unwrap_err();
    assert!(
        status_error.contains("frontier lane kinds cannot be represented as green"),
        "unexpected unsupported-green error: {status_error}"
    );
}

#[test]
fn synthetic_stale_blocker_rows_are_rejected() {
    let frontier = json(FRONTIER_PATH);
    let fixtures = frontier_fixture_map(&frontier);
    let fixture = fixtures
        .get("VF-RUSTC-COMPILE-STOP")
        .expect("fixture exists");
    let expected = fixture
        .get("expected_record")
        .expect("fixture expected_record");
    let stale_blocker = serde_json::json!({
        "fixture_id": "VF-RUSTC-COMPILE-STOP",
        "command": fixture["command"].clone(),
        "decision": expected["decision"].clone(),
        "error_class": expected["error_class"].clone(),
        "summary": "stale summary that no longer matches the validation frontier fixture",
        "supplemental_proof_command": fixture["supplemental_proof_command"].clone(),
        "first_failure": expected["first_failure"].clone()
    });

    let error = validate_blocked_frontier_record(&stale_blocker, &fixtures).unwrap_err();
    assert!(
        error.contains("blocked_frontier.summary no longer matches"),
        "unexpected stale-blocker error: {error}"
    );
}

#[test]
fn documentation_points_to_snapshot_and_verifier() {
    let snapshot = json(SNAPSHOT_PATH);
    let docs = snapshot
        .get("documentation_contract")
        .expect("documentation_contract");
    let marker = string(docs, "required_marker");
    let verifier = string(docs, "verifier_marker");

    for path in string_vec(docs, "docs_must_reference_snapshot") {
        let text = read_repo_file(&path);
        assert!(text.contains(marker), "{path} must reference {marker}");
        assert!(text.contains(verifier), "{path} must reference {verifier}");
    }
}

#[test]
fn null_and_string_field_helpers_cover_blocked_shape() {
    let snapshot = json(SNAPSHOT_PATH);
    let rows = array(&snapshot, "claim_categories");
    let non_red = rows
        .iter()
        .find(|entry| string(entry, "status") != "red_blocked_external")
        .expect("at least one non-red row");
    assert!(optional_string(non_red, "missing_optional").is_none());
}
