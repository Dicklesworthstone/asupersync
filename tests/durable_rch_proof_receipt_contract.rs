#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CONTRACT_PATH: &str = "artifacts/durable_rch_proof_receipt_contract_v1.json";
const FIXTURE_ROOT: &str = "tests/fixtures/durable_rch_proof_receipt";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_REUSE_CACHE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    decision: String,
    reason_codes: BTreeSet<String>,
}

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

fn fixture(name: &str) -> Value {
    json(&format!("{FIXTURE_ROOT}/{name}"))
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

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::String(text)) if !text.trim().is_empty() => Some(text),
        Some(Value::String(_) | Value::Null) | None => None,
        _ => panic!("{key} must be a string or null"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn i64_field(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{key} must be an integer"))
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

fn expected_verdict(fixture: &Value) -> Verdict {
    let expected = object(fixture, "expected_contract_verdict");
    Verdict {
        decision: string(expected, "decision").to_string(),
        reason_codes: string_set(expected, "reason_codes"),
    }
}

fn validate_contract_shape(contract: &Value) -> Result<(), String> {
    if string(contract, "contract_version") != "durable-rch-proof-receipt-contract-v1" {
        return Err("unexpected contract version".to_string());
    }
    if string(contract, "receipt_schema_version") != "durable-rch-proof-receipt-v1" {
        return Err("unexpected receipt schema version".to_string());
    }
    if string(contract, "bead_id") != "asupersync-durable-rch-proof-submission-zxnnhe.1" {
        return Err("contract bead id drifted".to_string());
    }

    let source = object(contract, "source_of_truth");
    for key in [
        "contract",
        "contract_test",
        "fixture_root",
        "proof_lane_manifest",
        "proof_status_snapshot",
        "proof_reuse_cache_contract",
        "agent_instructions",
    ] {
        let path = string(source, key);
        if !repo_path(path).exists() {
            return Err(format!("source path does not exist: {path}"));
        }
    }

    let policy = object(contract, "decision_policy");
    if !bool_field(policy, "remote_required") {
        return Err("remote_required must be true".to_string());
    }
    if bool_field(policy, "local_fallback_allowed") {
        return Err("local fallback must be disallowed".to_string());
    }
    if bool_field(policy, "network_access_required_for_contract_tests")
        || bool_field(policy, "live_agent_mail_required_for_contract_tests")
        || bool_field(policy, "tracker_mutation_allowed_for_contract_tests")
    {
        return Err("contract tests must be deterministic and non-mutating".to_string());
    }
    if string(policy, "required_command_prefix") != "RCH_REQUIRE_REMOTE=1 rch exec -- " {
        return Err("unexpected RCH command prefix".to_string());
    }
    if string(policy, "required_branch") != "main" {
        return Err("required branch must be main".to_string());
    }

    let reasons = string_set(contract, "refusal_reason_codes");
    for required in [
        "broad-claim-unsupported",
        "dirty-frontier-overlap",
        "invalid-required-field",
        "local-fallback-marker",
        "missing-manifest-lane",
        "missing-required-field",
        "missing-schema-version",
        "missing-terminal-classification",
        "stale-head",
        "unknown-lifecycle-state",
    ] {
        if !reasons.contains(required) {
            return Err(format!("missing required reason code {required}"));
        }
    }

    let required_sections = string_set(contract, "required_receipt_sections");
    let required_fields = array(contract, "required_fields_by_section");
    if required_fields.is_empty() {
        return Err("required_fields_by_section must be nonempty".to_string());
    }
    for section in required_fields {
        let section_name = string(section, "section");
        let fields = string_set(section, "required_fields");
        if fields.is_empty() {
            return Err(format!("{section_name}: required_fields must be nonempty"));
        }
        if section_name != "identity" && !required_sections.contains(section_name) {
            return Err(format!(
                "{section_name}: required field section missing from required_receipt_sections"
            ));
        }
    }

    Ok(())
}

fn ensure_required_sections(receipt: &Value, contract: &Value) -> Result<(), String> {
    for section in string_set(contract, "required_receipt_sections") {
        if receipt.get(&section).is_none() {
            return Err(format!("missing receipt section {section}"));
        }
    }
    Ok(())
}

fn nullable_required_field(section: &str, field: &str) -> bool {
    matches!(
        (section, field),
        ("outcome", "cancellation_reason" | "staleness_reason")
    )
}

fn required_field_missing(section: &str, field: &str, value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) => !nullable_required_field(section, field),
        None => true,
        Some(Value::String(text)) => text.trim().is_empty(),
        _ => false,
    }
}

fn has_specific_missing_reason(section: &str, field: &str) -> bool {
    matches!(
        (section, field),
        (
            "identity",
            "schema_version" | "manifest_lane_id" | "terminal_classification"
        ) | ("command", "command_fingerprint")
            | ("source", "touched_files")
    )
}

fn required_field_has_valid_type(section: &str, field: &str, value: &Value) -> bool {
    match (section, field) {
        (
            "identity",
            "schema_version"
            | "receipt_id"
            | "submission_id"
            | "generated_at"
            | "manifest_lane_id"
            | "claim_scope"
            | "proof_evidence_status"
            | "lifecycle_state"
            | "terminal_classification",
        )
        | ("command", "command" | "command_fingerprint" | "env_fingerprint")
        | (
            "source",
            "branch"
            | "head_commit"
            | "expected_head"
            | "source_tree_fingerprint"
            | "dirty_frontier_status",
        )
        | ("rch_provenance", "worker_id" | "submitted_at" | "started_at" | "finished_at")
        | ("outcome", "status" | "output_digest")
        | ("claim_boundaries", "covers") => {
            value.as_str().is_some_and(|text| !text.trim().is_empty())
        }

        ("identity", "manifest_guarantee_ids")
        | ("command", "argv" | "env_allowlist" | "local_fallback_markers")
        | ("source", "dirty_frontier_paths" | "touched_files")
        | ("rch_provenance", "remote_route_segments")
        | ("outcome", "first_blocker_lines")
        | ("claim_boundaries", "explicit_not_covered" | "refusal_reason_codes") => value.is_array(),

        ("source", "touched_file_hashes") => value.is_object(),

        ("command", "remote_required" | "local_fallback_allowed")
        | ("rch_provenance", "detector_progress_stale" | "detector_heartbeat_stale")
        | ("claim_boundaries", "citable") => value.is_boolean(),

        ("outcome", "exit_code") => value.is_i64(),

        ("outcome", "cancellation_reason" | "staleness_reason") => {
            value.is_null() || value.as_str().is_some_and(|text| !text.trim().is_empty())
        }

        _ => panic!("missing required field type contract for {section}.{field}"),
    }
}

fn invalid_required_fields(receipt: &Value, contract: &Value) -> BTreeSet<String> {
    let mut invalid = BTreeSet::new();
    for section in array(contract, "required_fields_by_section") {
        let section_name = string(section, "section");
        let container = if section_name == "identity" {
            Some(receipt)
        } else {
            receipt.get(section_name)
        };
        let Some(container) = container else {
            continue;
        };
        for field in string_set(section, "required_fields") {
            if let Some(value) = container.get(&field)
                && !required_field_missing(section_name, &field, Some(value))
                && !required_field_has_valid_type(section_name, &field, value)
            {
                invalid.insert(format!("{section_name}.{field}"));
            }
        }
    }
    invalid
}

fn generic_missing_required_fields(receipt: &Value, contract: &Value) -> BTreeSet<String> {
    let mut missing = BTreeSet::new();
    for section in array(contract, "required_fields_by_section") {
        let section_name = string(section, "section");
        let container = if section_name == "identity" {
            Some(receipt)
        } else {
            receipt.get(section_name)
        };
        if container.is_none() {
            continue;
        }
        for field in string_set(section, "required_fields") {
            if has_specific_missing_reason(section_name, &field) {
                continue;
            }
            if required_field_missing(
                section_name,
                &field,
                container.and_then(|container| container.get(&field)),
            ) {
                missing.insert(format!("{section_name}.{field}"));
            }
        }
    }
    missing
}

fn allowed_lifecycle_states(contract: &Value) -> BTreeSet<String> {
    string_set(contract, "allowed_lifecycle_states")
}

fn terminal_lifecycle_states(contract: &Value) -> BTreeSet<String> {
    string_set(contract, "terminal_lifecycle_states")
}

fn validate_receipt(receipt: &Value, contract: &Value, lanes: &BTreeMap<String, Value>) -> Verdict {
    let policy = object(contract, "decision_policy");
    let mut reasons = BTreeSet::new();

    if ensure_required_sections(receipt, contract).is_err() {
        reasons.insert("missing-required-section".to_string());
    }
    if !generic_missing_required_fields(receipt, contract).is_empty() {
        reasons.insert("missing-required-field".to_string());
        return Verdict {
            decision: string(policy, "default_decision").to_string(),
            reason_codes: reasons,
        };
    }
    if !invalid_required_fields(receipt, contract).is_empty() {
        reasons.insert("invalid-required-field".to_string());
        return Verdict {
            decision: string(policy, "default_decision").to_string(),
            reason_codes: reasons,
        };
    }

    match optional_string(receipt, "schema_version") {
        Some(version) if version == string(contract, "receipt_schema_version") => {}
        Some(_) => {
            reasons.insert("schema-version-mismatch".to_string());
        }
        None => {
            reasons.insert("missing-schema-version".to_string());
        }
    }

    let lane = match optional_string(receipt, "manifest_lane_id") {
        Some(lane_id) => match lanes.get(lane_id) {
            Some(lane) => Some(lane),
            None => {
                reasons.insert("missing-manifest-lane".to_string());
                None
            }
        },
        None => {
            reasons.insert("missing-manifest-lane".to_string());
            None
        }
    };

    if let Some(lane) = lane {
        let lane_guarantees = string_set(lane, "guarantee_ids");
        let receipt_guarantees = string_set(receipt, "manifest_guarantee_ids");
        if receipt_guarantees.is_empty() || receipt_guarantees.is_disjoint(&lane_guarantees) {
            reasons.insert("lane-mismatch".to_string());
        }

        if let Some(command) = receipt.get("command") {
            let receipt_command = string(command, "command");
            if receipt_command != string(lane, "command")
                || !receipt_command.starts_with(string(policy, "required_command_prefix"))
            {
                reasons.insert("command-mismatch".to_string());
            }
        }

        let claim_scope = optional_string(receipt, "claim_scope").unwrap_or("");
        let lane_policy = object(lane, "proof_reuse_policy");
        let allowed_scopes = string_set(lane_policy, "allowed_claim_scopes");
        let non_citeable_scopes = string_set(lane_policy, "non_citeable_claim_scopes");
        if !allowed_scopes.contains(claim_scope) || non_citeable_scopes.contains(claim_scope) {
            reasons.insert("broad-claim-unsupported".to_string());
        }
    }

    if let Some(command) = receipt.get("command") {
        if !bool_field(command, "remote_required") || bool_field(command, "local_fallback_allowed")
        {
            reasons.insert("command-mismatch".to_string());
        }
        if !array(command, "local_fallback_markers").is_empty() {
            reasons.insert("local-fallback-marker".to_string());
        }
        if optional_string(command, "command_fingerprint").is_none() {
            reasons.insert("missing-command-fingerprint".to_string());
        }
    }

    if let Some(source) = receipt.get("source") {
        if string(source, "branch") != string(policy, "required_branch") {
            reasons.insert("branch-mismatch".to_string());
        }
        if string(source, "head_commit") != string(source, "expected_head") {
            reasons.insert("stale-head".to_string());
        }
        if string(source, "dirty_frontier_status") != "clean"
            || !array(source, "dirty_frontier_paths").is_empty()
        {
            reasons.insert("dirty-frontier-overlap".to_string());
        }
        if source
            .get("touched_files")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            reasons.insert("missing-touched-files".to_string());
        }
    }

    let lifecycle_state = optional_string(receipt, "lifecycle_state").unwrap_or("");
    let terminal_states = terminal_lifecycle_states(contract);
    if !allowed_lifecycle_states(contract).contains(lifecycle_state) {
        reasons.insert("unknown-lifecycle-state".to_string());
    }
    if terminal_states.contains(lifecycle_state)
        && optional_string(receipt, "terminal_classification").is_none()
    {
        reasons.insert("missing-terminal-classification".to_string());
    }

    let status = optional_string(receipt, "proof_evidence_status").unwrap_or("");
    if !proof_evidence_statuses().contains(status) {
        reasons.insert("failed-proof-status".to_string());
    }

    let outcome = receipt.get("outcome");
    if lifecycle_state == string(policy, "accepted_lifecycle_state")
        && optional_string(receipt, "terminal_classification")
            != Some(string(policy, "accepted_terminal_classification"))
    {
        reasons.insert("missing-terminal-classification".to_string());
    }
    if lifecycle_state == string(policy, "accepted_lifecycle_state")
        && (status != string(policy, "accepted_proof_evidence_status")
            || outcome.is_some_and(|outcome| {
                string(outcome, "status") != "pass" || i64_field(outcome, "exit_code") != 0
            }))
    {
        reasons.insert("failed-proof-status".to_string());
    }

    let citable = if let Some(boundaries) = receipt.get("claim_boundaries") {
        let explicit_not_covered = string_set(boundaries, "explicit_not_covered");
        for required in string_set(contract, "required_explicit_not_covered") {
            if !explicit_not_covered.contains(&required) {
                reasons.insert("broad-claim-unsupported".to_string());
            }
        }
        let citable = bool_field(boundaries, "citable");
        if citable && !reasons.is_empty() {
            reasons.insert("citable-receipt-has-refusal-reasons".to_string());
        }
        citable
    } else {
        false
    };

    let decision = if reasons.is_empty()
        && lifecycle_state == string(policy, "accepted_lifecycle_state")
        && citable
    {
        string(policy, "accepted_decision").to_string()
    } else {
        string(policy, "default_decision").to_string()
    };

    Verdict {
        decision,
        reason_codes: reasons,
    }
}

fn assert_fixture_verdict(name: &str) {
    let fixture = fixture(name);
    let receipt = object(&fixture, "receipt");
    let actual = validate_receipt(receipt, &contract(), &manifest_lanes());
    let expected = expected_verdict(&fixture);
    let embedded_reasons = receipt
        .get("claim_boundaries")
        .map(|boundaries| string_set(boundaries, "refusal_reason_codes"));
    assert_eq!(&actual, &expected, "fixture verdict drifted for {name}");
    if let Some(embedded_reasons) = embedded_reasons {
        assert_eq!(
            embedded_reasons, expected.reason_codes,
            "embedded receipt refusal reasons drifted for {name}"
        );
    }
}

fn missing_required_fields(receipt: &Value, contract: &Value) -> BTreeSet<String> {
    let mut missing = BTreeSet::new();
    for section in array(contract, "required_fields_by_section") {
        let section_name = string(section, "section");
        for field in string_set(section, "required_fields") {
            let container = if section_name == "identity" {
                Some(receipt)
            } else {
                receipt.get(section_name)
            };
            if required_field_missing(
                section_name,
                &field,
                container.and_then(|container| container.get(&field)),
            ) {
                missing.insert(format!("{section_name}.{field}"));
            }
        }
    }
    missing
}

#[test]
fn contract_declares_source_paths_and_fail_closed_policy() {
    let contract = contract();
    validate_contract_shape(&contract).expect("durable RCH receipt contract shape");

    let source = object(&contract, "source_of_truth");
    assert_eq!(string(source, "contract"), CONTRACT_PATH);
    assert_eq!(
        string(source, "contract_test"),
        "tests/durable_rch_proof_receipt_contract.rs"
    );
    assert_eq!(string(source, "fixture_root"), FIXTURE_ROOT);
    assert_eq!(string(source, "proof_lane_manifest"), MANIFEST_PATH);
    assert_eq!(string(source, "proof_status_snapshot"), SNAPSHOT_PATH);
    assert_eq!(
        string(source, "proof_reuse_cache_contract"),
        PROOF_REUSE_CACHE_CONTRACT_PATH
    );
    assert_eq!(string(source, "agent_instructions"), AGENTS_PATH);
}

#[test]
fn refusal_reasons_reuse_existing_proof_vocabulary_where_possible() {
    let durable_reasons = string_set(&contract(), "refusal_reason_codes");
    let reuse_reasons = string_set(
        &json(PROOF_REUSE_CACHE_CONTRACT_PATH),
        "refusal_reason_codes",
    );
    for shared in [
        "broad-claim-unsupported",
        "command-mismatch",
        "dirty-frontier-overlap",
        "failed-proof-status",
        "lane-mismatch",
        "local-fallback-marker",
        "missing-command-fingerprint",
        "missing-touched-files",
        "stale-head",
        "toolchain-mismatch",
    ] {
        assert!(
            durable_reasons.contains(shared),
            "durable contract must include {shared}"
        );
        assert!(
            reuse_reasons.contains(shared),
            "proof reuse cache contract must include shared reason {shared}"
        );
    }
}

#[test]
fn accepted_terminal_pass_receipt_is_citable_for_exact_manifest_lane_only() {
    assert_fixture_verdict("terminal_pass.json");
}

#[test]
fn rejected_fixtures_fail_closed_with_one_primary_reason() {
    for name in [
        "missing_schema_version.json",
        "missing_manifest_lane.json",
        "missing_command_section.json",
        "missing_source_section.json",
        "missing_rch_provenance_section.json",
        "missing_outcome_section.json",
        "missing_claim_boundaries_section.json",
        "local_fallback_marker.json",
        "stale_head.json",
        "dirty_overlap.json",
        "unsupported_broad_claim.json",
        "unknown_lifecycle_state.json",
        "missing_terminal_classification.json",
    ] {
        assert_fixture_verdict(name);
    }
}

#[test]
fn fixtures_match_declared_required_field_contract() {
    let contract = contract();
    for (name, expected_missing) in [
        ("terminal_pass.json", BTreeSet::new()),
        (
            "missing_schema_version.json",
            BTreeSet::from(["identity.schema_version".to_string()]),
        ),
        ("missing_manifest_lane.json", BTreeSet::new()),
        (
            "missing_command_section.json",
            BTreeSet::from([
                "command.argv".to_string(),
                "command.command".to_string(),
                "command.command_fingerprint".to_string(),
                "command.env_allowlist".to_string(),
                "command.env_fingerprint".to_string(),
                "command.local_fallback_allowed".to_string(),
                "command.local_fallback_markers".to_string(),
                "command.remote_required".to_string(),
            ]),
        ),
        (
            "missing_source_section.json",
            BTreeSet::from([
                "source.branch".to_string(),
                "source.dirty_frontier_paths".to_string(),
                "source.dirty_frontier_status".to_string(),
                "source.expected_head".to_string(),
                "source.head_commit".to_string(),
                "source.source_tree_fingerprint".to_string(),
                "source.touched_file_hashes".to_string(),
                "source.touched_files".to_string(),
            ]),
        ),
        (
            "missing_rch_provenance_section.json",
            BTreeSet::from([
                "rch_provenance.detector_heartbeat_stale".to_string(),
                "rch_provenance.detector_progress_stale".to_string(),
                "rch_provenance.finished_at".to_string(),
                "rch_provenance.remote_route_segments".to_string(),
                "rch_provenance.started_at".to_string(),
                "rch_provenance.submitted_at".to_string(),
                "rch_provenance.worker_id".to_string(),
            ]),
        ),
        (
            "missing_outcome_section.json",
            BTreeSet::from([
                "outcome.cancellation_reason".to_string(),
                "outcome.exit_code".to_string(),
                "outcome.first_blocker_lines".to_string(),
                "outcome.output_digest".to_string(),
                "outcome.staleness_reason".to_string(),
                "outcome.status".to_string(),
            ]),
        ),
        (
            "missing_claim_boundaries_section.json",
            BTreeSet::from([
                "claim_boundaries.citable".to_string(),
                "claim_boundaries.covers".to_string(),
                "claim_boundaries.explicit_not_covered".to_string(),
                "claim_boundaries.refusal_reason_codes".to_string(),
            ]),
        ),
        ("local_fallback_marker.json", BTreeSet::new()),
        ("stale_head.json", BTreeSet::new()),
        ("dirty_overlap.json", BTreeSet::new()),
        ("unsupported_broad_claim.json", BTreeSet::new()),
        ("unknown_lifecycle_state.json", BTreeSet::new()),
        (
            "missing_terminal_classification.json",
            BTreeSet::from(["identity.terminal_classification".to_string()]),
        ),
    ] {
        let fixture = fixture(name);
        let receipt = object(&fixture, "receipt");
        assert_eq!(
            missing_required_fields(receipt, &contract),
            expected_missing,
            "required-field omissions drifted for {name}"
        );
    }
}

#[test]
fn fixture_list_matches_contract_inventory() {
    let contract = contract();
    let fixture_contract = object(&contract, "fixture_contract");
    let mut listed = BTreeSet::new();
    listed.insert(string(fixture_contract, "accepted_fixture").to_string());
    listed.extend(string_set(fixture_contract, "rejected_fixtures"));

    let expected = BTreeSet::from([
        "dirty_overlap.json".to_string(),
        "local_fallback_marker.json".to_string(),
        "missing_claim_boundaries_section.json".to_string(),
        "missing_command_section.json".to_string(),
        "missing_manifest_lane.json".to_string(),
        "missing_outcome_section.json".to_string(),
        "missing_rch_provenance_section.json".to_string(),
        "missing_schema_version.json".to_string(),
        "missing_source_section.json".to_string(),
        "missing_terminal_classification.json".to_string(),
        "stale_head.json".to_string(),
        "terminal_pass.json".to_string(),
        "unknown_lifecycle_state.json".to_string(),
        "unsupported_broad_claim.json".to_string(),
    ]);
    assert_eq!(listed, expected, "fixture inventory drifted");
    for name in listed {
        assert!(
            repo_path(&format!("{FIXTURE_ROOT}/{name}")).exists(),
            "listed fixture must exist: {name}"
        );
    }
}

#[test]
fn every_required_receipt_section_has_missing_section_fixture() {
    let contract = contract();
    let sections = string_set(&contract, "required_receipt_sections");
    let fixture_contract = object(&contract, "fixture_contract");
    let rejected_fixtures = string_set(fixture_contract, "rejected_fixtures");

    let expected_missing_section_fixtures = sections
        .iter()
        .map(|section| format!("missing_{section}_section.json"))
        .collect::<BTreeSet<_>>();
    let actual_missing_section_fixtures = rejected_fixtures
        .iter()
        .filter(|fixture| fixture.starts_with("missing_") && fixture.ends_with("_section.json"))
        .cloned()
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual_missing_section_fixtures, expected_missing_section_fixtures,
        "required section fixture coverage drifted"
    );
}

#[test]
fn required_receipt_field_omissions_fail_closed() {
    let contract = contract();
    let lanes = manifest_lanes();

    for section in array(&contract, "required_fields_by_section") {
        let section_name = string(section, "section");
        for field in string_set(section, "required_fields") {
            let mut receipt = object(&fixture("terminal_pass.json"), "receipt").clone();
            if section_name == "identity" {
                receipt
                    .as_object_mut()
                    .unwrap_or_else(|| panic!("{section_name} fixture container must be an object"))
                    .remove(&field);
            } else {
                receipt
                    .get_mut(section_name)
                    .and_then(Value::as_object_mut)
                    .unwrap_or_else(|| panic!("{section_name} fixture container must be an object"))
                    .remove(&field);
            }

            let verdict = validate_receipt(&receipt, &contract, &lanes);
            let expected_reason = match (section_name, field.as_str()) {
                ("identity", "schema_version") => "missing-schema-version",
                ("identity", "manifest_lane_id") => "missing-manifest-lane",
                ("identity", "terminal_classification") => "missing-terminal-classification",
                ("command", "command_fingerprint") => "missing-command-fingerprint",
                ("source", "touched_files") => "missing-touched-files",
                _ => "missing-required-field",
            };

            assert_eq!(
                verdict.decision, "refused",
                "{section_name}.{field} omission must be refused"
            );
            assert!(
                verdict.reason_codes.contains(expected_reason),
                "{section_name}.{field} omission must include {expected_reason}; got {:?}",
                verdict.reason_codes
            );
        }
    }
}

#[test]
fn required_receipt_field_type_errors_fail_closed() {
    let contract = contract();
    let lanes = manifest_lanes();

    for section in array(&contract, "required_fields_by_section") {
        let section_name = string(section, "section");
        for field in string_set(section, "required_fields") {
            let mut receipt = object(&fixture("terminal_pass.json"), "receipt").clone();
            let invalid_value = match (section_name, field.as_str()) {
                ("command", "remote_required" | "local_fallback_allowed")
                | ("rch_provenance", "detector_progress_stale" | "detector_heartbeat_stale")
                | ("claim_boundaries", "citable") => Value::String("not-a-bool".to_string()),
                ("outcome", "exit_code") => Value::String("not-an-integer".to_string()),
                _ => Value::Bool(false),
            };

            if section_name == "identity" {
                receipt
                    .as_object_mut()
                    .unwrap_or_else(|| panic!("{section_name} fixture container must be an object"))
                    .insert(field.clone(), invalid_value);
            } else {
                receipt
                    .get_mut(section_name)
                    .and_then(Value::as_object_mut)
                    .unwrap_or_else(|| panic!("{section_name} fixture container must be an object"))
                    .insert(field.clone(), invalid_value);
            }

            let verdict = validate_receipt(&receipt, &contract, &lanes);
            assert_eq!(
                verdict.decision, "refused",
                "{section_name}.{field} invalid type must be refused"
            );
            assert!(
                verdict.reason_codes.contains("invalid-required-field"),
                "{section_name}.{field} invalid type must include invalid-required-field; got {:?}",
                verdict.reason_codes
            );
        }
    }
}
