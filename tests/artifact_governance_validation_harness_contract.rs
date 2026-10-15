#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const HARNESS_PATH: &str = "artifacts/artifact_governance_validation_harness_v1.json";
const MARKDOWN_PATH: &str = "docs/proof/artifact_governance_validation_harness.md";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const SCANNER_PATH: &str = "artifacts/artifact_governance_scanner_v1.json";
const OPERATOR_REPORT_PATH: &str = "artifacts/artifact_governance_operator_report_v1.json";
const PRODUCER_CHECKLIST_PATH: &str = "artifacts/artifact_governance_producer_checklist_v1.json";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.8";

const REQUIRED_UNITS: &[&str] = &[
    "schema_parser_edges",
    "citation_policy_edges",
    "supersession_edges",
    "e2e_flow_log",
];

const REQUIRED_FIXTURE_KINDS: &[&str] = &[
    "valid_citeable_proof_row",
    "missing_owner_row",
    "duplicate_path_row",
    "malformed_no_claim_boundary",
    "allowed_citation",
    "rejected_overclaim",
    "advisory_only",
    "current_successor",
    "superseded_with_successor",
    "superseded_missing_successor",
    "ledger_scan_report_signoff",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn harness() -> Value {
    repo_json(HARNESS_PATH)
}

fn ledger() -> Value {
    repo_json(LEDGER_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
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
            assert!(!text.trim().is_empty(), "{key} must be nonempty when set");
            Some(text)
        }
        Some(_) => panic!("{key} must be null or string"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be nonempty strings"))
                .to_owned()
        })
        .collect()
}

fn assert_repo_file_exists(path: &str) {
    assert!(repo_path(path).is_file(), "repo file must exist: {path}");
}

fn rows_by_id() -> BTreeMap<String, Value> {
    let ledger = ledger();
    let mut rows = BTreeMap::new();
    for row in array(&ledger, "rows") {
        let artifact_id = string(row, "artifact_id").to_owned();
        assert!(
            rows.insert(artifact_id.clone(), row.clone()).is_none(),
            "duplicate ledger row {artifact_id}"
        );
    }
    rows
}

fn fixture_catalog(harness: &Value) -> BTreeMap<String, Value> {
    object(harness, "fixture_catalog")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn contains_destructive_action(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("delete file")
        || lower.contains("rm -rf")
        || lower.contains("git clean")
        || lower.contains("git reset")
        || lower.contains("worktree add")
        || lower.contains("checkout -b")
        || lower.contains("switch -c")
        || lower.contains("local cargo fallback")
}

fn validate_schema_case(case: &Value) -> Result<(), String> {
    let expected = string(case, "expected_result");
    let owning_bead = optional_string(case, "owning_bead");
    let no_claims = string_set(case, "no_claim_boundaries");

    if owning_bead.is_none() {
        return expect_failure(case, expected, "missing_owner");
    }
    if string(case, "fixture_kind") == "duplicate_path_row" {
        return expect_failure(case, expected, "duplicate_artifact_path");
    }
    if no_claims
        .iter()
        .any(|claim| !claim.starts_with("does_not_"))
    {
        return expect_failure(case, expected, "malformed_no_claim_boundary");
    }
    if array(case, "checked_by_tests").is_empty() || array(case, "source_references").is_empty() {
        return Err("missing_checks_or_sources".to_owned());
    }

    if expected == "pass" {
        Ok(())
    } else {
        Err(format!(
            "{} expected failure but validated",
            string(case, "case_id")
        ))
    }
}

fn validate_citation_case(case: &Value) -> Result<(), String> {
    let expected = string(case, "expected_result");
    let class = string(case, "citeability_class");
    let claim = string(case, "requested_claim");
    let allowed = string_set(case, "allowed_claims");

    if class != "proof-bearing" {
        let expected_error = if class == "advisory" {
            "advisory_not_closure_proof"
        } else {
            "citation_overclaim"
        };
        return expect_failure(case, expected, expected_error);
    }

    if !allowed.contains(claim) {
        return expect_failure(case, expected, "citation_overclaim");
    }

    if expected == "pass" {
        Ok(())
    } else {
        Err(format!(
            "{} expected failure but validated",
            string(case, "case_id")
        ))
    }
}

fn validate_supersession_case(case: &Value) -> Result<(), String> {
    let expected = string(case, "expected_result");
    if string(case, "fixture_kind") == "superseded_missing_successor"
        && optional_string(case, "superseded_by").is_none()
    {
        return expect_failure(case, expected, "missing_successor");
    }

    if expected == "pass" {
        Ok(())
    } else {
        Err(format!(
            "{} expected failure but validated",
            string(case, "case_id")
        ))
    }
}

fn expect_failure(case: &Value, expected: &str, expected_error: &str) -> Result<(), String> {
    if expected != "fail" {
        return Err(format!(
            "{} failed with {expected_error}, but expected {expected}",
            string(case, "case_id")
        ));
    }
    if optional_string(case, "expected_error") != Some(expected_error) {
        return Err(format!(
            "{} expected_error must be {expected_error}",
            string(case, "case_id")
        ));
    }
    if let Some(action) = optional_string(case, "operator_action") {
        if contains_destructive_action(action) {
            return Err(format!(
                "{} suggests a forbidden action: {action}",
                string(case, "case_id")
            ));
        }
    }
    Ok(())
}

#[test]
fn validation_harness_schema_sources_and_policy_are_bounded() {
    let harness = harness();
    assert_eq!(
        harness.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-validation-harness-v1")
    );
    assert_eq!(
        harness.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );

    for path in object(&harness, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path string"))
    {
        assert_repo_file_exists(path);
    }

    let policy = object(&harness, "harness_policy");
    let policy_value = Value::Object(policy.clone());
    assert!(!bool_field(&policy_value, "full_corpus_claim"));
    assert!(bool_field(&policy_value, "no_local_fallback"));

    let non_destructive = string(&policy_value, "non_destructive_policy");
    for required in [
        "does not delete",
        "branches",
        "worktrees",
        "local Cargo fallback",
    ] {
        assert!(
            non_destructive.contains(required),
            "non_destructive_policy must mention {required}"
        );
    }

    let remote_command = string(&policy_value, "remote_required_validation_command");
    assert!(remote_command.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(remote_command.contains("artifact_governance_validation_harness_contract"));
    assert!(remote_command.contains("artifact_governance_ledger_contract"));
}

#[test]
fn validation_units_and_fixture_catalog_are_complete() {
    let harness = harness();
    let units = array(&harness, "validation_units")
        .iter()
        .map(|unit| string(unit, "unit_id").to_owned())
        .collect::<BTreeSet<_>>();
    let expected_units = REQUIRED_UNITS
        .iter()
        .map(|unit| (*unit).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(units, expected_units, "validation unit catalog drifted");

    let catalog = fixture_catalog(&harness);
    let actual_kinds = catalog.keys().cloned().collect::<BTreeSet<_>>();
    let expected_kinds = REQUIRED_FIXTURE_KINDS
        .iter()
        .map(|kind| (*kind).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_kinds, expected_kinds, "fixture catalog drifted");

    let mut required_from_units = BTreeSet::new();
    for unit in array(&harness, "validation_units") {
        assert_eq!(
            string(unit, "checked_by"),
            "tests/artifact_governance_validation_harness_contract.rs"
        );
        for kind in string_set(unit, "required_fixture_kinds") {
            assert!(
                catalog.contains_key(&kind),
                "{} requires missing fixture kind {kind}",
                string(unit, "unit_id")
            );
            required_from_units.insert(kind);
        }
    }
    assert_eq!(required_from_units, expected_kinds);

    for (kind, fixture) in catalog {
        let expected_result = string(&fixture, "expected_result");
        assert!(matches!(expected_result, "pass" | "fail"));
        if expected_result == "fail" {
            string(&fixture, "expected_error");
        }
        assert!(
            string(&fixture, "no_claim_boundary").starts_with("does_not_"),
            "{kind}: fixture no-claim boundary must be machine-readable"
        );
    }
}

#[test]
fn schema_citation_and_supersession_fixtures_validate_expected_failures() {
    let harness = harness();
    let mut expected_passes = 0_u64;
    let mut expected_failures = 0_u64;

    for case in array(&harness, "schema_fixture_cases") {
        validate_schema_case(case).unwrap_or_else(|error| panic!("schema fixture failed: {error}"));
        match string(case, "expected_result") {
            "pass" => expected_passes += 1,
            "fail" => expected_failures += 1,
            other => panic!("unknown expected_result {other}"),
        }
    }

    for case in array(&harness, "citation_fixture_cases") {
        validate_citation_case(case)
            .unwrap_or_else(|error| panic!("citation fixture failed: {error}"));
        match string(case, "expected_result") {
            "pass" => expected_passes += 1,
            "fail" => expected_failures += 1,
            other => panic!("unknown expected_result {other}"),
        }
    }

    for case in array(&harness, "supersession_fixture_cases") {
        validate_supersession_case(case)
            .unwrap_or_else(|error| panic!("supersession fixture failed: {error}"));
        match string(case, "expected_result") {
            "pass" => expected_passes += 1,
            "fail" => expected_failures += 1,
            other => panic!("unknown expected_result {other}"),
        }
    }

    let e2e = object(&harness, "e2e_flow_log");
    let e2e_value = Value::Object(e2e.clone());
    let counts = object(&e2e_value, "fixture_counts");
    let count_value = Value::Object(counts.clone());
    assert_eq!(
        u64_field(&count_value, "expected_pass"),
        expected_passes + 1
    );
    assert_eq!(u64_field(&count_value, "expected_fail"), expected_failures);
    assert_eq!(
        u64_field(&count_value, "schema"),
        array(&harness, "schema_fixture_cases").len() as u64
    );
    assert_eq!(
        u64_field(&count_value, "citation"),
        array(&harness, "citation_fixture_cases").len() as u64
    );
    assert_eq!(
        u64_field(&count_value, "supersession"),
        array(&harness, "supersession_fixture_cases").len() as u64
    );
}

#[test]
fn e2e_flow_log_matches_committed_governance_artifacts() {
    let harness = harness();
    let ledger_rows = rows_by_id();
    let flow = object(&harness, "e2e_flow_log");
    let flow_value = Value::Object(flow.clone());

    for path in array(&flow_value, "input_artifacts") {
        assert_repo_file_exists(path.as_str().expect("input artifact path"));
    }
    for path in array(&flow_value, "output_artifacts") {
        assert_repo_file_exists(path.as_str().expect("output artifact path"));
    }

    let mut actual_counts: BTreeMap<String, u64> = BTreeMap::new();
    for row in ledger_rows.values() {
        *actual_counts
            .entry(string(row, "citeability_class").to_owned())
            .or_insert(0) += 1;
    }
    let expected_counts = object(&flow_value, "artifact_counts_by_class");
    for (class, expected) in expected_counts {
        assert_eq!(
            expected.as_u64(),
            actual_counts.get(class).copied(),
            "{class}: class count drifted"
        );
    }

    assert_eq!(
        string(&flow_value, "structured_log_golden"),
        "schema=4 citation=3 supersession=3 e2e=1 pass=5 fail=6 first_blocker=validation-frontier-inventory"
    );
    assert_eq!(
        string(&flow_value, "first_blocker"),
        "validation-frontier-inventory"
    );
    assert!(ledger_rows.contains_key(string(&flow_value, "first_blocker")));
    assert!(
        string(&flow_value, "recommended_next_action").contains("do not run local Cargo fallback")
    );

    let operator_report = repo_json(OPERATOR_REPORT_PATH);
    assert_eq!(
        object(&operator_report, "operator_summary")["first_blocker"].as_str(),
        Some("validation-frontier-inventory")
    );
    let scanner = repo_json(SCANNER_PATH);
    assert!(
        array(&scanner, "rows")
            .iter()
            .any(|row| string(row, "artifact_path") == "artifacts/proof_lane_manifest_v1.json")
    );
    let checklist = repo_json(PRODUCER_CHECKLIST_PATH);
    assert!(
        string(&checklist["guard_output_contract"], "operator_message").contains("Do not delete")
    );
}

#[test]
fn markdown_report_matches_json_summary_boundaries_and_no_fallback() {
    let harness = harness();
    let markdown = read_repo_file(MARKDOWN_PATH);
    let flow = object(&harness, "e2e_flow_log");
    let flow_value = Value::Object(flow.clone());
    let golden = string(&flow_value, "structured_log_golden");
    assert!(
        markdown.contains(golden),
        "markdown must include structured log golden"
    );

    for unit in REQUIRED_UNITS {
        assert!(markdown.contains(unit), "markdown missing unit {unit}");
    }
    for boundary in string_set(&harness, "no_claim_boundaries") {
        assert!(
            markdown.contains(&boundary),
            "markdown missing boundary {boundary}"
        );
    }
    assert!(markdown.contains("do not run local Cargo fallback"));
    assert!(markdown.contains("does not authorize deletion"));
    assert!(markdown.contains("does not prove release readiness"));
}

#[test]
fn validation_harness_is_registered_in_the_governance_ledger() {
    let rows = rows_by_id();
    let row = rows
        .get("artifact-governance-validation-harness")
        .expect("validation harness ledger row");

    assert_eq!(string(row, "path"), HARNESS_PATH);
    assert_eq!(string(row, "owning_bead"), BEAD_ID);
    assert_eq!(string(row, "artifact_family"), "artifact_governance");
    assert_eq!(string(row, "citeability_class"), "proof-bearing");
    assert!(
        array(row, "checked_by_tests")
            .iter()
            .any(|test| test.as_str()
                == Some("tests/artifact_governance_validation_harness_contract.rs"))
    );
    assert!(
        string_set(row, "no_claim_boundaries").contains("does_not_authorize_local_cargo_fallback")
    );
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_close_artifact_beads"));
}
