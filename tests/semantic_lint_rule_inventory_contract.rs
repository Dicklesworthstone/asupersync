#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/semantic_lint_rule_inventory_v1.json";
const DOCS_PATH: &str = "docs/semantic_lint_rule_inventory.md";
const TEST_PATH: &str = "tests/semantic_lint_rule_inventory_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.3.1";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH))
        .unwrap_or_else(|err| panic!("parse {CONTRACT_PATH}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn child<'a>(value: &'a Value, key: &str) -> &'a Value {
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

fn rows_by_id(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "rule_rows")
        .iter()
        .map(|row| (string(row, "rule_id").to_string(), row))
        .collect()
}

#[test]
fn contract_declares_sources_policy_and_no_runtime_effect() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("semantic-lint-rule-inventory-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some(BEAD_ID));

    let source = child(&contract, "source_of_truth");
    for key in [
        "contract",
        "contract_test",
        "docs",
        "runtime_invariants",
        "testing_contract",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo path: {path}"
        );
    }
    assert_eq!(string(source, "contract"), CONTRACT_PATH);
    assert_eq!(string(source, "contract_test"), TEST_PATH);
    assert_eq!(string(source, "docs"), DOCS_PATH);

    let policy = child(&contract, "policy");
    assert_eq!(string(policy, "default_mode"), "inventory_only");
    assert!(bool_field(policy, "implementation_must_be_fail_closed"));
    assert!(bool_field(policy, "no_runtime_behavior_change"));
    assert!(bool_field(policy, "allow_marker_requires_owner_bead"));
    assert!(bool_field(policy, "allow_marker_requires_reason"));
}

#[test]
fn inventory_covers_exact_required_rule_set() {
    let contract = contract();
    let required = string_set(&contract, "required_rule_ids");
    let rows = rows_by_id(&contract);
    let actual = rows.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual, required);

    let expected = BTreeSet::from([
        "ambient-time-or-entropy-in-lab-sensitive-code".to_string(),
        "await-while-holding-capability-resource".to_string(),
        "core-tokio-feature-leakage".to_string(),
        "drop-based-race-loser-handling".to_string(),
        "ignored-outcome-severity".to_string(),
        "loop-without-cx-checkpoint".to_string(),
        "unbounded-cleanup-budget".to_string(),
    ]);
    assert_eq!(required, expected);
}

#[test]
fn each_rule_has_engine_policy_owner_and_tests() {
    let contract = contract();
    let allowed = child(&contract, "allowed_values");
    let risk_classes = string_set(allowed, "risk_classes");
    let statuses = string_set(allowed, "rule_statuses");
    let engines = string_set(allowed, "detection_engines");
    let modes = string_set(allowed, "false_positive_modes");

    for row in array(&contract, "rule_rows") {
        let rule_id = string(row, "rule_id");
        assert!(
            risk_classes.contains(string(row, "risk_class")),
            "{rule_id}: unknown risk class"
        );
        assert!(
            statuses.contains(string(row, "status")),
            "{rule_id}: unknown status"
        );
        assert!(
            engines.contains(string(row, "selected_engine")),
            "{rule_id}: unknown engine"
        );
        assert!(
            string(row, "owner_bead").starts_with("asupersync-"),
            "{rule_id}: owner_bead must be explicit"
        );
        assert!(
            !array(row, "target_paths").is_empty(),
            "{rule_id}: target_paths required"
        );
        assert!(
            !array(row, "source_patterns").is_empty(),
            "{rule_id}: source_patterns required"
        );
        assert!(
            !array(row, "tests_required").is_empty(),
            "{rule_id}: tests_required required"
        );

        let decision = child(row, "engine_decision");
        assert!(
            !string(decision, "rationale").is_empty(),
            "{rule_id}: engine rationale required"
        );

        let false_positive = child(row, "false_positive_policy");
        let mode = string(false_positive, "mode");
        assert!(modes.contains(mode), "{rule_id}: unknown FP mode");
        assert!(
            !array(false_positive, "expected_false_positives").is_empty(),
            "{rule_id}: expected false positives must be documented"
        );
        let marker = string(false_positive, "allow_marker");
        assert!(
            marker.contains(rule_id),
            "{rule_id}: allow marker must include rule id"
        );
        assert!(
            marker.contains("reason=") && marker.contains("owner="),
            "{rule_id}: allow marker must require reason and owner"
        );
    }
}

#[test]
fn engine_decisions_pick_least_brittle_substrate_for_known_high_risk_rules() {
    let contract = contract();
    let rows = rows_by_id(&contract);

    assert_eq!(
        string(rows["core-tokio-feature-leakage"], "selected_engine"),
        "cargo-metadata",
        "tokio leakage is a graph invariant, not source syntax"
    );
    assert_eq!(
        string(
            rows["ambient-time-or-entropy-in-lab-sensitive-code"],
            "selected_engine"
        ),
        "ast-grep",
        "ambient deterministic hazards are stable syntax in path-scoped modules"
    );
    assert_eq!(
        string(
            rows["await-while-holding-capability-resource"],
            "selected_engine"
        ),
        "rustc-hir",
        "guard lifetime across await needs type-aware analysis"
    );
    assert_eq!(
        string(rows["ignored-outcome-severity"], "selected_engine"),
        "rustc-hir",
        "Outcome severity preservation needs type-aware analysis"
    );
    assert_eq!(
        string(rows["drop-based-race-loser-handling"], "selected_engine"),
        "hybrid-rustc-hir-ast-grep",
        "race loser detection needs candidate syntax plus type-aware ownership"
    );
}

#[test]
fn docs_render_contract_markers_and_all_rule_ids() {
    let contract = contract();
    let docs = read_repo_file(DOCS_PATH);

    for marker in array(&contract, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs must contain marker {marker:?}");
    }

    for rule_id in string_set(&contract, "required_rule_ids") {
        assert!(
            docs.contains(&rule_id),
            "docs must render rule id {rule_id}"
        );
    }
}

#[test]
fn no_claims_and_proof_command_are_explicit() {
    let contract = contract();
    let no_claims = array(&contract, "no_claims");
    assert!(
        no_claims.len() >= 4,
        "semantic lint inventory must name no-claim boundaries"
    );
    let joined = no_claims
        .iter()
        .map(|claim| claim.as_str().expect("no_claim string"))
        .collect::<Vec<_>>()
        .join("\n");
    for phrase in [
        "does not implement any lint rule",
        "does not certify",
        "does not replace",
        "does not authorize local Cargo fallback",
    ] {
        assert!(
            joined.contains(phrase),
            "no_claims missing boundary phrase {phrase:?}"
        );
    }

    let proof_command = string(&contract, "proof_command");
    assert!(
        proof_command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "proof command must require remote RCH execution"
    );
    assert!(
        proof_command.contains("--test semantic_lint_rule_inventory_contract"),
        "proof command must target this contract test"
    );
}
