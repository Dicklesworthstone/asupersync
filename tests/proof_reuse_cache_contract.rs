#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const FRESHNESS_HELPER_PATH: &str = "scripts/proof_artifact_freshness_receipt.py";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
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

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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

fn section_map(contract: &Value) -> BTreeMap<String, BTreeSet<String>> {
    array(contract, "fingerprint_sections")
        .iter()
        .map(|section| {
            (
                string(section, "section").to_string(),
                string_set(section, "required_fields"),
            )
        })
        .collect()
}

fn manifest_lane_ids() -> BTreeSet<String> {
    array(&json(MANIFEST_PATH), "lanes")
        .iter()
        .map(|lane| string(lane, "lane_id").to_string())
        .collect()
}

fn manifest_lane_map() -> BTreeMap<String, Value> {
    array(&json(MANIFEST_PATH), "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn validate_contract_shape(contract: &Value) -> Result<(), String> {
    if contract.get("contract_version").and_then(Value::as_str)
        != Some("proof-reuse-cache-contract-v1")
    {
        return Err("unexpected contract version".to_string());
    }

    let source = contract
        .get("source_of_truth")
        .ok_or_else(|| "missing source_of_truth".to_string())?;
    for key in [
        "contract",
        "contract_test",
        "proof_lane_manifest",
        "proof_status_snapshot",
        "proof_freshness_helper",
        "agent_instructions",
    ] {
        if source.get(key).and_then(Value::as_str).is_none() {
            return Err(format!("missing source_of_truth.{key}"));
        }
    }

    let policy = contract
        .get("decision_policy")
        .ok_or_else(|| "missing decision_policy".to_string())?;
    if !bool_field(policy, "remote_route_required") {
        return Err("remote route must be required".to_string());
    }
    if !bool_field(policy, "cache_hit_is_never_fresh_rch_pass") {
        return Err("cache hits must not claim fresh RCH passes".to_string());
    }
    if bool_field(policy, "tracker_mutation_allowed") {
        return Err("reuse query must not mutate tracker state".to_string());
    }
    let required_prefix = string(policy, "required_command_prefix");
    if required_prefix != "RCH_REQUIRE_REMOTE=1 rch exec -- " {
        return Err("unexpected command prefix".to_string());
    }

    for section in ["command", "source", "toolchain", "outcome", "reuse_policy"] {
        let fields = section_map(contract)
            .remove(section)
            .ok_or_else(|| format!("missing fingerprint section {section}"))?;
        if fields.is_empty() {
            return Err(format!("{section} required fields must be nonempty"));
        }
    }

    let outcomes = contract
        .get("outcome_policy")
        .ok_or_else(|| "missing outcome_policy".to_string())?;
    if string_set(outcomes, "reusable_statuses") != BTreeSet::from(["pass".to_string()]) {
        return Err("only pass status may be reusable".to_string());
    }
    for status in [
        "fail",
        "failed",
        "blocked",
        "stale",
        "unsupported",
        "malformed",
    ] {
        if !string_set(outcomes, "non_reusable_statuses").contains(status) {
            return Err(format!("missing non-reusable status {status}"));
        }
    }

    let reason_codes = string_set(contract, "refusal_reason_codes");
    for required in [
        "broad-claim-unsupported",
        "command-mismatch",
        "dirty-frontier-overlap",
        "failed-proof-status",
        "local-fallback-marker",
        "missing-dirty-frontier-status",
        "missing-touched-files",
        "source-hash-mismatch",
        "stale-head",
        "toolchain-mismatch",
    ] {
        if !reason_codes.contains(required) {
            return Err(format!("missing refusal reason {required}"));
        }
    }

    Ok(())
}

#[test]
fn contract_declares_sources_and_fail_closed_policy() {
    let contract = contract();
    validate_contract_shape(&contract).expect("proof reuse cache contract shape");
    assert_eq!(string(&contract, "bead_id"), "asupersync-5pziae.1");

    let source = contract.get("source_of_truth").expect("source_of_truth");
    assert_eq!(source["contract"].as_str(), Some(CONTRACT_PATH));
    assert_eq!(
        source["contract_test"].as_str(),
        Some("tests/proof_reuse_cache_contract.rs")
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
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        FRESHNESS_HELPER_PATH,
        AGENTS_PATH,
    ] {
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }
}

#[test]
fn fingerprint_sections_cover_the_reuse_trust_boundary() {
    let sections = section_map(&contract());
    let expected = BTreeMap::from([
        (
            "command",
            [
                "argv",
                "cargo_manifest_path",
                "cargo_target_selector",
                "command_fingerprint",
                "env_allowlist",
                "feature_flags",
            ],
        ),
        (
            "source",
            [
                "branch",
                "dirty_frontier_status",
                "head_commit",
                "source_tree_fingerprint",
                "touched_file_hashes",
                "touched_files",
            ],
        ),
        (
            "toolchain",
            [
                "cargo_lock_hash",
                "cargo_version",
                "rust_toolchain_toml_hash",
                "rustc_version",
                "target_dir_identity",
                "target_triple",
            ],
        ),
        (
            "outcome",
            [
                "exit_code",
                "first_blocker_line",
                "local_fallback_markers",
                "rch_remote_route_segments",
                "rch_remote_worker",
                "status",
            ],
        ),
        (
            "reuse_policy",
            [
                "allowed_cache_hit_claims",
                "claim_scope",
                "explicit_not_covered",
                "manifest_guarantee_ids",
                "manifest_lane_id",
                "rerun_only_claims",
            ],
        ),
    ]);

    for (section, required_fields) in expected {
        let actual = sections
            .get(section)
            .unwrap_or_else(|| panic!("missing {section} section"));
        for field in required_fields {
            assert!(
                actual.contains(field),
                "{section} fingerprint must include {field}"
            );
        }
    }
}

#[test]
fn manifest_policy_examples_reference_real_lanes_and_forbid_overclaiming() {
    let contract = contract();
    let lane_ids = manifest_lane_ids();
    let lanes = manifest_lane_map();
    let examples = array(&contract, "manifest_lane_policy_examples");
    assert!(
        examples.len() >= 3,
        "contract should cover focused and frontier lane policies"
    );

    for example in examples {
        let lane_id = string(example, "lane_id");
        assert!(
            lane_ids.contains(lane_id),
            "policy example references unknown lane {lane_id}"
        );
        let lane = lanes
            .get(lane_id)
            .unwrap_or_else(|| panic!("missing manifest lane {lane_id}"));
        let lane_policy = lane
            .get("proof_reuse_policy")
            .unwrap_or_else(|| panic!("{lane_id}: missing manifest proof_reuse_policy"));
        assert_eq!(
            string(example, "lane_kind"),
            string(lane, "kind"),
            "{lane_id}: policy example kind must match manifest lane kind"
        );
        assert_eq!(
            bool_field(example, "cache_reuse_allowed"),
            bool_field(lane_policy, "cache_hits_allowed"),
            "{lane_id}: policy example cache flag must match manifest lane policy"
        );
        assert_eq!(
            string_set(example, "allowed_claim_scopes"),
            string_set(lane_policy, "allowed_claim_scopes"),
            "{lane_id}: policy example claim scopes must match manifest lane policy"
        );
        assert!(
            bool_field(example, "requires_fresh_rerun_when_dirty_overlap"),
            "{lane_id}: dirty overlap must force rerun"
        );
        assert_eq!(
            bool_field(example, "requires_fresh_rerun_when_dirty_overlap"),
            bool_field(lane_policy, "requires_fresh_rerun_when_dirty_overlap"),
            "{lane_id}: dirty-overlap policy must match manifest lane policy"
        );
        let prohibited = string_set(example, "prohibited_claim_scopes");
        for scope in ["fresh-rch-pass", "release-readiness", "workspace-health"] {
            assert!(
                prohibited.contains(scope),
                "{lane_id}: cache hits must not claim {scope}"
            );
        }
    }
}

#[test]
fn decision_examples_cover_required_hit_miss_and_refusal_cases() {
    let contract = contract();
    let known_reason_codes = string_set(&contract, "refusal_reason_codes");
    let examples = array(&contract, "decision_examples");
    let example_ids = examples
        .iter()
        .map(|example| string(example, "example_id").to_string())
        .collect::<BTreeSet<_>>();

    for required in [
        "focused-contract-cache-hit",
        "missing-dirty-frontier-status",
        "missing-touched-files",
        "local-fallback-marker",
        "failed-status",
        "stale-head",
        "unsupported-broad-claim",
        "toolchain-mismatch",
        "command-mismatch",
        "source-hash-mismatch",
        "dirty-overlap-frontier",
        "unrelated-lane-miss",
    ] {
        assert!(example_ids.contains(required), "missing example {required}");
    }

    let mut decisions = BTreeSet::new();
    for example in examples {
        let decision = string(example, "expected_decision");
        decisions.insert(decision.to_string());
        assert!(
            !bool_field(example, "cache_hit_is_fresh_rch_pass"),
            "{} must not present cache reuse as a fresh RCH pass",
            string(example, "example_id")
        );

        let reasons = string_set(example, "reason_codes");
        for reason in &reasons {
            assert!(
                known_reason_codes.contains(reason),
                "{} references unknown reason code {reason}",
                string(example, "example_id")
            );
        }
        if decision == "refused" {
            assert!(
                !reasons.is_empty(),
                "{}: refused examples need reason codes",
                string(example, "example_id")
            );
        }
    }

    assert_eq!(
        decisions,
        BTreeSet::from([
            "miss".to_string(),
            "refused".to_string(),
            "reusable".to_string()
        ])
    );
}

#[test]
fn reusable_example_keeps_rch_remote_command_and_touched_surface() {
    let contract = contract();
    let lanes = manifest_lane_map();
    let reusable = array(&contract, "decision_examples")
        .iter()
        .find(|example| string(example, "example_id") == "focused-contract-cache-hit")
        .expect("reusable example present");
    let request = reusable.get("request").expect("request object");
    let candidate = reusable.get("candidate").expect("candidate object");
    let lane_id = string(request, "manifest_lane_id");
    let lane = lanes
        .get(lane_id)
        .unwrap_or_else(|| panic!("missing manifest lane {lane_id}"));
    let lane_policy = lane
        .get("proof_reuse_policy")
        .unwrap_or_else(|| panic!("{lane_id}: missing proof_reuse_policy"));
    let command = string(candidate, "command");
    assert_eq!(
        command,
        string(lane, "command"),
        "reusable example command must match the manifest lane command"
    );
    assert!(
        string_set(lane_policy, "allowed_claim_scopes").contains(string(request, "claim_scope")),
        "reusable example claim scope must be citeable by the manifest lane policy"
    );
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
        "reusable proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR="),
        "reusable cargo proof must isolate target dir: {command}"
    );
    assert_eq!(candidate["status"].as_str(), Some("pass"));
    assert!(
        !array(candidate, "touched_files").is_empty(),
        "reusable proof must name touched files"
    );
    assert!(
        array(candidate, "local_fallback_markers").is_empty(),
        "reusable proof must not contain local fallback markers"
    );
}

#[test]
fn shape_validator_rejects_missing_sources_policy_and_reason_codes() {
    let base = contract();

    let mut missing_source = base.clone();
    missing_source["source_of_truth"]
        .as_object_mut()
        .expect("source object")
        .remove("proof_freshness_helper");
    assert!(
        validate_contract_shape(&missing_source)
            .expect_err("missing source should be rejected")
            .contains("proof_freshness_helper")
    );

    let mut local_allowed = base.clone();
    local_allowed["decision_policy"]["remote_route_required"] = Value::Bool(false);
    assert!(
        validate_contract_shape(&local_allowed)
            .expect_err("local fallback should be rejected")
            .contains("remote route")
    );

    let mut missing_reason = base;
    let reasons = missing_reason["refusal_reason_codes"]
        .as_array_mut()
        .expect("reason array");
    reasons.retain(|reason| reason.as_str() != Some("failed-proof-status"));
    assert!(
        validate_contract_shape(&missing_reason)
            .expect_err("missing reason should be rejected")
            .contains("failed-proof-status")
    );
}
