#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CHECKLIST_PATH: &str = "artifacts/artifact_governance_producer_checklist_v1.json";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const REPORT_PATH: &str = "docs/proof/artifact_governance_producer_checklist.md";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.5";

const REQUIRED_STEPS: &[&str] = &[
    "classify_path",
    "assign_owner",
    "declare_citeability",
    "declare_freshness",
    "attach_no_claim_boundaries",
    "wire_checks_and_docs",
];

const REQUIRED_METADATA: &[&str] = &[
    "artifact_id",
    "path",
    "path_status",
    "owning_bead",
    "producing_lane",
    "artifact_family",
    "checked_by_tests",
    "citeability_class",
    "freshness_policy",
    "no_claim_boundaries",
    "evidence_scope",
    "source_references",
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

fn checklist() -> Value {
    repo_json(CHECKLIST_PATH)
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

fn exclusions_by_id(checklist: &Value) -> BTreeMap<String, Value> {
    let mut exclusions = BTreeMap::new();
    for exclusion in array(checklist, "explicit_exclusions") {
        let id = string(exclusion, "id").to_owned();
        assert!(
            exclusions.insert(id.clone(), exclusion.clone()).is_none(),
            "duplicate exclusion {id}"
        );
    }
    exclusions
}

fn explicit_reference_exclusion_paths(checklist: &Value) -> BTreeSet<String> {
    let exclusions = object(checklist, "explicit_reference_exclusions");
    let exclusions_value = Value::Object(exclusions.clone());
    let reason = string(&exclusions_value, "reason");
    assert!(
        reason.contains("does not authorize deletion"),
        "reference exclusion reason must preserve non-destructive policy"
    );
    for boundary in string_set(&exclusions_value, "no_claim_boundaries") {
        assert!(
            boundary.starts_with("does_not_"),
            "reference exclusion boundary must be a does_not token: {boundary}"
        );
    }

    string_set(&exclusions_value, "artifact_paths")
}

fn extract_artifact_json_paths(text: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut cursor = 0;

    while let Some(start_offset) = text[cursor..].find("artifacts/") {
        let start = cursor + start_offset;
        let mut end = start;
        for (offset, ch) in text[start..].char_indices() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '<' | '>') {
                end = start + offset + ch.len_utf8();
            } else {
                break;
            }
        }

        if end > start {
            let candidate = &text[start..end];
            if candidate.ends_with(".json") {
                paths.insert(candidate.to_owned());
            }
            cursor = end;
        } else {
            cursor = start + "artifacts/".len();
        }
    }

    paths
}

fn row_for_fixture(fixture: &Value, rows: &BTreeMap<String, Value>) -> Option<Value> {
    if let Some(row) = fixture.get("fixture_row") {
        return Some(row.clone());
    }

    if let Some(row_id) = optional_string(fixture, "ledger_row") {
        return rows.get(row_id).cloned();
    }

    let referenced_path = string(fixture, "referenced_path");
    rows.values()
        .find(|row| string(row, "path") == referenced_path)
        .cloned()
}

fn contains_destructive_action(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("delete")
        || lower.contains("remove ")
        || lower.contains("clean ")
        || lower.contains("git reset")
        || lower.contains("git clean")
        || lower.contains("worktree")
        || lower.contains("branch")
}

fn validate_metadata_row(row: &Value, referenced_path: &str) -> Result<(), String> {
    if string(row, "path") != referenced_path {
        return Err("row_path_mismatch".to_owned());
    }

    for key in REQUIRED_METADATA {
        string_or_array_metadata(row, key)?;
    }

    let no_claims = string_set(row, "no_claim_boundaries");
    if no_claims.len() < 3 || !no_claims.iter().all(|claim| claim.starts_with("does_not_")) {
        return Err("missing_no_claim_boundaries".to_owned());
    }

    if array(row, "checked_by_tests").is_empty() || array(row, "source_references").is_empty() {
        return Err("missing_checks_or_sources".to_owned());
    }

    Ok(())
}

fn string_or_array_metadata(row: &Value, key: &str) -> Result<(), String> {
    match row.get(key) {
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(()),
        Some(Value::Array(values)) if !values.is_empty() => {
            if values
                .iter()
                .all(|entry| entry.as_str().is_some_and(|text| !text.trim().is_empty()))
            {
                Ok(())
            } else {
                Err(format!("invalid_metadata:{key}"))
            }
        }
        _ => Err(format!("missing_metadata:{key}")),
    }
}

fn validate_guard_fixture(
    checklist: &Value,
    rows: &BTreeMap<String, Value>,
    fixture: &Value,
) -> Result<(), String> {
    if let Some(action) = optional_string(fixture, "suggested_action") {
        if contains_destructive_action(action) {
            return Err("destructive_suggestion".to_owned());
        }
    }

    match string(fixture, "classification") {
        "explicit_exclusion" => {
            let exclusion_id = string(fixture, "exclusion");
            let exclusions = exclusions_by_id(checklist);
            let exclusion = exclusions
                .get(exclusion_id)
                .ok_or_else(|| "missing_ledger_row_or_exclusion".to_owned())?;
            let reason = string(exclusion, "reason").to_ascii_lowercase();
            if reason.contains("delete") {
                return Err("destructive_suggestion".to_owned());
            }
            let no_claims = string_set(exclusion, "required_no_claim_boundaries");
            if no_claims.len() < 3 || !no_claims.iter().all(|claim| claim.starts_with("does_not_"))
            {
                return Err("missing_no_claim_boundaries".to_owned());
            }
            Ok(())
        }
        "durable_artifact" => {
            let referenced_path = string(fixture, "referenced_path");
            let row = row_for_fixture(fixture, rows)
                .ok_or_else(|| "missing_ledger_row_or_exclusion".to_owned())?;
            validate_metadata_row(&row, referenced_path)
        }
        other => Err(format!("unknown_classification:{other}")),
    }
}

#[test]
fn guarded_reference_sources_require_ledger_rows_or_explicit_exclusions() {
    let checklist = checklist();
    let rows = rows_by_id();
    let ledger_paths = rows
        .values()
        .map(|row| string(row, "path").to_owned())
        .collect::<BTreeSet<_>>();
    let explicit_exclusions = explicit_reference_exclusion_paths(&checklist);
    let mut all_references = BTreeSet::new();
    let mut missing = Vec::new();

    for source in array(&checklist["guard_scope"], "guarded_reference_sources") {
        let source_path = string(source, "path");
        assert_repo_file_exists(source_path);
        let references = extract_artifact_json_paths(&read_repo_file(source_path));
        assert!(
            !references.is_empty(),
            "{source_path}: guarded source must contain artifact references"
        );
        for reference in &references {
            if !ledger_paths.contains(reference) && !explicit_exclusions.contains(reference) {
                missing.push(format!("{source_path}:{reference}"));
            }
        }
        all_references.extend(references);
    }

    assert!(
        missing.is_empty(),
        "guarded references need a ledger row or explicit exclusion: {missing:?}"
    );
    for excluded in explicit_exclusions {
        assert!(
            all_references.contains(&excluded),
            "explicit reference exclusion is stale or absent from guarded sources: {excluded}"
        );
    }
}

#[test]
fn checklist_schema_sources_and_scope_are_non_destructive() {
    let checklist = checklist();

    assert_eq!(
        checklist.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-producer-checklist-v1")
    );
    assert_eq!(
        checklist.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );

    for path in object(&checklist, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path"))
    {
        assert_repo_file_exists(path);
    }

    let scope = object(&checklist, "scope");
    assert_eq!(
        scope["corpus_coverage"].as_str(),
        Some("representative_guard_not_full_corpus")
    );
    assert!(!bool_field(&checklist["scope"], "full_corpus_claim"));
    assert!(bool_field(&checklist["scope"], "non_destructive"));

    let guard_policy = string(&checklist["scope"], "guard_result_policy");
    assert!(guard_policy.contains("never ask"));
    assert!(guard_policy.contains("delete files"));
    assert!(guard_policy.contains("local Cargo fallback"));

    let output = object(&checklist, "guard_output_contract");
    assert_eq!(
        output["fail_action"].as_str(),
        Some("add_ownership_metadata")
    );
    let forbidden = string_set(&checklist["guard_output_contract"], "forbidden_actions");
    for action in [
        "delete_file",
        "clean_generated_output",
        "create_branch",
        "create_worktree",
        "local_cargo_fallback",
    ] {
        assert!(
            forbidden.contains(action),
            "missing forbidden action {action}"
        );
    }
    let operator_message = output["operator_message"]
        .as_str()
        .expect("operator_message string");
    assert!(
        operator_message.contains("Do not delete files"),
        "operator message must keep the guard non-destructive"
    );
}

#[test]
fn producer_workflow_requires_ownership_citeability_freshness_and_boundaries() {
    let checklist = checklist();

    let actual_steps = array(&checklist, "producer_workflow")
        .iter()
        .map(|step| string(step, "step").to_owned())
        .collect::<BTreeSet<_>>();
    let expected_steps = REQUIRED_STEPS
        .iter()
        .map(|step| (*step).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_steps, expected_steps, "producer workflow drifted");

    for step in array(&checklist, "producer_workflow") {
        string(step, "required_output");
        string(step, "check");
    }

    let actual_metadata = string_set(&checklist, "required_metadata");
    let expected_metadata = REQUIRED_METADATA
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_metadata, expected_metadata,
        "required metadata drifted"
    );

    let no_claims = string_set(&checklist, "no_claim_boundaries");
    for required in [
        "does_not_prove_full_corpus_coverage",
        "does_not_authorize_deletion",
        "does_not_prove_fresh_rch_pass",
        "does_not_close_future_artifact_gaps",
    ] {
        assert!(no_claims.contains(required), "missing {required}");
    }
}

#[test]
fn explicit_exclusions_preserve_no_delete_boundaries() {
    let checklist = checklist();
    let exclusions = exclusions_by_id(&checklist);

    for required in ["remote-build-target-cache-roots", "local-target-cache-root"] {
        let exclusion = exclusions
            .get(required)
            .unwrap_or_else(|| panic!("missing exclusion {required}"));
        string(exclusion, "path_pattern");
        let reason = string(exclusion, "reason");
        assert!(
            !contains_destructive_action(reason),
            "{required}: exclusion reason must not ask for cleanup"
        );
        let no_claims = string_set(exclusion, "required_no_claim_boundaries");
        assert!(no_claims.contains("does_not_authorize_deletion"));
        assert!(no_claims.contains("does_not_hide_future_durable_receipts"));
        assert!(no_claims.contains("does_not_prove_artifact_absence"));
    }
}

#[test]
fn guard_fixtures_pass_or_fail_for_metadata_only_reasons() {
    let checklist = checklist();
    let rows = rows_by_id();
    let fixtures = array(&checklist, "guard_fixtures");
    assert!(
        fixtures.len() >= 5,
        "A5 needs representative guard fixtures"
    );

    for fixture in fixtures {
        let result = validate_guard_fixture(&checklist, &rows, fixture);
        match string(fixture, "expected_result") {
            "pass" => {
                result.unwrap_or_else(|error| panic!("{}: {error}", string(fixture, "id")));
                let source_path = string(fixture, "source_path");
                let source = read_repo_file(source_path);
                let referenced_path = string(fixture, "referenced_path");
                assert!(
                    source.contains(referenced_path),
                    "{source_path} must reference {referenced_path}"
                );
            }
            "fail" => {
                let expected = string(fixture, "expected_error");
                let error = result.expect_err("negative fixture must fail");
                assert!(
                    error.contains(expected),
                    "{} expected {expected}, got {error}",
                    string(fixture, "id")
                );
            }
            other => panic!("unknown expected_result {other}"),
        }
    }
}

#[test]
fn checklist_is_registered_in_the_governance_ledger() {
    let rows = rows_by_id();
    let row = rows
        .get("artifact-governance-producer-checklist")
        .expect("producer checklist ledger row");

    assert_eq!(string(row, "path"), CHECKLIST_PATH);
    assert_eq!(string(row, "owning_bead"), BEAD_ID);
    assert_eq!(string(row, "citeability_class"), "proof-bearing");
    assert_eq!(string(row, "artifact_family"), "artifact_governance");
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_authorize_deletion"));
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_close_future_artifact_gaps"));

    for path in [CHECKLIST_PATH, REPORT_PATH] {
        assert_repo_file_exists(path);
    }

    let report = read_repo_file(REPORT_PATH);
    for required in [
        CHECKLIST_PATH,
        BEAD_ID,
        "does not prove full-corpus coverage",
        "does not authorize deletion",
        "does not prove a fresh RCH pass",
        "does not close future artifact gaps",
    ] {
        assert!(report.contains(required), "report missing {required}");
    }
}
