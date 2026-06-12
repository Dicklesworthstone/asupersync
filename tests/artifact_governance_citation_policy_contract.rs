#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "artifacts/artifact_governance_citation_policy_v1.json";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const REPORT_PATH: &str = "docs/proof/artifact_governance_citation_policy.md";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.3";

const REQUIRED_CONTEXTS: &[&str] = &[
    "readme_agents_discoverability",
    "proof_status_claim",
    "bead_closeout",
    "release_signoff",
    "operator_runbook",
    "internal_fixture",
];

#[derive(Debug, Clone)]
struct LedgerRow {
    path: String,
    citeability_class: String,
    no_claim_boundaries: BTreeSet<String>,
}

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

fn policy() -> Value {
    repo_json(POLICY_PATH)
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

fn ledger_rows() -> BTreeMap<String, LedgerRow> {
    let ledger = ledger();
    let mut rows = BTreeMap::new();
    for row in array(&ledger, "rows") {
        let artifact_id = string(row, "artifact_id").to_owned();
        let ledger_row = LedgerRow {
            path: string(row, "path").to_owned(),
            citeability_class: string(row, "citeability_class").to_owned(),
            no_claim_boundaries: string_set(row, "no_claim_boundaries"),
        };
        assert!(
            rows.insert(artifact_id.clone(), ledger_row).is_none(),
            "duplicate ledger row {artifact_id}"
        );
    }
    rows
}

fn ledger_classes() -> BTreeSet<String> {
    object(&ledger(), "classification_catalog")
        .keys()
        .cloned()
        .collect()
}

fn contexts() -> BTreeSet<String> {
    REQUIRED_CONTEXTS
        .iter()
        .map(|context| (*context).to_owned())
        .collect()
}

fn validate_citation(
    policy: &Value,
    rows: &BTreeMap<String, LedgerRow>,
    citation: &Value,
) -> Result<(), String> {
    let context = string(citation, "context");
    let claim_kind = string(citation, "claim_kind");
    let citation_text = string(citation, "citation_text");

    let class = match citation.get("ledger_row").and_then(Value::as_str) {
        Some(row_id) => rows
            .get(row_id)
            .map(|row| row.citeability_class.as_str())
            .ok_or_else(|| format!("unknown_ledger_row:{row_id}"))?,
        None => string(citation, "citeability_class"),
    };

    let context_catalog = object(policy, "context_catalog");
    let class_policy = object(policy, "class_policy");
    let context_entry = context_catalog
        .get(context)
        .ok_or_else(|| format!("unknown_context:{context}"))?;
    let class_entry = class_policy
        .get(class)
        .ok_or_else(|| format!("unknown_class:{class}"))?;

    let context_allowed = string_set(context_entry, "allowed_classes");
    let class_allowed = string_set(class_entry, "allowed_contexts");
    if !context_allowed.contains(class) || !class_allowed.contains(context) {
        return Err("context_disallows_class".to_owned());
    }

    let mut denied = string_set(context_entry, "denied_claims");
    denied.extend(string_set(class_entry, "denied_claims"));
    if denied.contains(claim_kind) {
        return Err("denied_claim".to_owned());
    }

    if bool_field(context_entry, "requires_no_claim_text")
        || bool_field(class_entry, "must_include_no_claim_boundaries")
    {
        if !citation_text.contains("does_not_") {
            return Err("missing_no_claim_text".to_owned());
        }
        for boundary in string_set(citation, "required_no_claim_boundaries") {
            if !citation_text.contains(&boundary) {
                return Err(format!("missing_boundary:{boundary}"));
            }
        }
    }

    if let Some(row_id) = citation.get("ledger_row").and_then(Value::as_str) {
        let row = rows
            .get(row_id)
            .ok_or_else(|| format!("unknown_ledger_row:{row_id}"))?;
        for boundary in string_set(citation, "required_no_claim_boundaries") {
            if !row.no_claim_boundaries.contains(&boundary) {
                return Err(format!("boundary_not_in_ledger:{boundary}"));
            }
        }
    }

    Ok(())
}

#[test]
fn citation_policy_schema_contexts_and_sources_are_valid() {
    let policy = policy();
    assert_eq!(
        policy.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-citation-policy-v1")
    );
    assert_eq!(policy.get("bead_id").and_then(Value::as_str), Some(BEAD_ID));

    for path in object(&policy, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path"))
    {
        assert_repo_file_exists(path);
    }

    let actual_contexts = object(&policy, "context_catalog")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_contexts, contexts(), "context catalog drifted");

    let actual_classes = object(&policy, "class_policy")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_classes,
        ledger_classes(),
        "policy must cover every ledger citeability class"
    );

    for context in REQUIRED_CONTEXTS {
        let entry = &policy["context_catalog"][*context];
        string(entry, "meaning");
        assert!(
            !string_set(entry, "allowed_classes").is_empty(),
            "{context}: must allow at least one class"
        );
        for class in string_set(entry, "allowed_classes") {
            assert!(
                actual_classes.contains(&class),
                "{context}: unknown {class}"
            );
        }
    }
}

#[test]
fn allowed_citations_are_ledger_backed_and_attach_no_claim_boundaries() {
    let policy = policy();
    let rows = ledger_rows();
    let citations = array(&policy, "allowed_citations");
    assert!(
        citations.len() >= 3,
        "A3 needs representative allowed citations"
    );

    for citation in citations {
        let row_id = string(citation, "ledger_row");
        let row = rows
            .get(row_id)
            .unwrap_or_else(|| panic!("allowed citation references missing row {row_id}"));
        assert_repo_file_exists(&row.path);
        validate_citation(&policy, &rows, citation)
            .unwrap_or_else(|error| panic!("{row_id}: {error}"));
    }
}

#[test]
fn overclaim_fixtures_are_rejected() {
    let policy = policy();
    let rows = ledger_rows();
    let fixtures = array(&policy, "negative_fixtures");
    assert!(fixtures.len() >= 3, "A3 requires at least three fixtures");

    let fixture_ids = fixtures
        .iter()
        .map(|fixture| string(fixture, "id").to_owned())
        .collect::<BTreeSet<_>>();
    for required in [
        "fixture_only_as_release_proof",
        "blocked_frontier_as_green_proof",
        "runtime_pressure_as_production_enforcement",
    ] {
        assert!(fixture_ids.contains(required), "missing fixture {required}");
    }

    for fixture in fixtures {
        let expected = string(fixture, "expected_error");
        let error = validate_citation(&policy, &rows, fixture)
            .expect_err("negative fixture must be rejected");
        assert!(
            error.contains(expected),
            "{} expected {expected}, got {error}",
            string(fixture, "id")
        );
    }
}

#[test]
fn readme_agents_and_proof_status_references_resolve_to_ledger_rows() {
    let policy = policy();
    let rows = ledger_rows();

    for reference in array(&policy, "representative_reference_checks") {
        let source_path = string(reference, "source_path");
        let needle = string(reference, "match");
        let row_id = string(reference, "ledger_row");
        let context = string(reference, "context");
        assert!(contexts().contains(context), "unknown context {context}");

        let source = read_repo_file(source_path);
        assert!(
            source.contains(needle),
            "{source_path} must contain representative artifact {needle}"
        );
        let row = rows
            .get(row_id)
            .unwrap_or_else(|| panic!("{source_path}: missing ledger row {row_id}"));
        assert_eq!(
            row.path, needle,
            "{source_path}: reference must point at ledger row path"
        );
    }
}

#[test]
fn citation_policy_is_registered_in_the_governance_ledger() {
    let rows = ledger_rows();
    let row = rows
        .get("artifact-governance-citation-policy")
        .expect("policy ledger row");

    assert_eq!(row.path, POLICY_PATH);
    assert_eq!(row.citeability_class, "proof-bearing");
    assert!(
        row.no_claim_boundaries
            .contains("does_not_authorize_overclaims")
    );

    let report = read_repo_file(REPORT_PATH);
    for required in [
        POLICY_PATH,
        BEAD_ID,
        "does not prove full-corpus coverage",
        "does not authorize overclaims",
        "does not prove a fresh RCH pass",
    ] {
        assert!(report.contains(required), "report missing {required}");
    }
}
