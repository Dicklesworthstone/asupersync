#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const SCANNER_PATH: &str = "artifacts/artifact_governance_scanner_v1.json";
const REPORT_PATH: &str = "docs/proof/artifact_governance_scanner.md";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.2";

const REQUIRED_CATEGORIES: &[&str] = &[
    "exact_ownership",
    "inferred_ownership",
    "orphan",
    "ambiguous",
    "stale",
    "excluded",
];

const REQUIRED_CONFIDENCE_KINDS: &[&str] = &[
    "exact_bead_id_field",
    "domain_specific_owner_field",
    "proof_manifest_source_path",
    "proof_status_lane_mapping",
    "readme_agents_reference",
    "test_constant_path",
    "manual_ledger_override",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn scanner() -> Value {
    serde_json::from_str(&read_repo_file(SCANNER_PATH))
        .unwrap_or_else(|error| panic!("parse {SCANNER_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))?;
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match value.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(Some(text)),
        Some(Value::String(_)) => Err(format!("{key} must be nonempty when set")),
        Some(_) => Err(format!("{key} must be null or string")),
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{key} entries must be nonempty strings"))
        })
        .collect()
}

fn assert_repo_file_exists(path: &str) -> Result<(), String> {
    if repo_path(path).is_file() {
        Ok(())
    } else {
        Err(format!("referenced repo file must exist: {path}"))
    }
}

fn validate_source_match(source: &Value) -> Result<String, String> {
    let kind = string(source, "kind")?;
    let path = string(source, "path")?;
    let needle = string(source, "match")?;
    assert_repo_file_exists(path)?;
    let haystack = read_repo_file(path);
    if !haystack.contains(needle) {
        return Err(format!("{path} does not contain scanner match {needle}"));
    }
    Ok(kind.to_owned())
}

fn validate_scanner(scan: &Value) -> Result<(), String> {
    if scan.get("schema_version").and_then(Value::as_str) != Some("artifact-governance-scanner-v1")
    {
        return Err("unexpected schema_version".to_owned());
    }
    if scan.get("bead_id").and_then(Value::as_str) != Some(BEAD_ID) {
        return Err("unexpected bead_id".to_owned());
    }

    for path in object(scan, "source_of_truth")?.values().map(|value| {
        value
            .as_str()
            .ok_or("source_of_truth values must be strings")
    }) {
        assert_repo_file_exists(path.map_err(str::to_owned)?)?;
    }

    let coverage = object(scan, "coverage_policy")?;
    if bool_field(&Value::Object(coverage.clone()), "full_corpus_claim")? {
        return Err("scanner must not claim full corpus coverage".to_owned());
    }
    if !bool_field(&Value::Object(coverage.clone()), "non_destructive")? {
        return Err("scanner must be non-destructive".to_owned());
    }
    let parser_policy = string(&Value::Object(coverage.clone()), "parser_policy")?;
    for required in ["JSON", "does not rewrite", "delete"] {
        if !parser_policy.contains(required) {
            return Err(format!("parser_policy must mention {required}"));
        }
    }

    let confidence_catalog = object(scan, "confidence_catalog")?;
    let confidence_keys = confidence_catalog
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_confidence = REQUIRED_CONFIDENCE_KINDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if confidence_keys != expected_confidence {
        return Err("confidence catalog drifted".to_owned());
    }
    let mut ranks = BTreeSet::new();
    for kind in REQUIRED_CONFIDENCE_KINDS {
        let entry = object(&scan["confidence_catalog"], kind)?;
        string(&Value::Object(entry.clone()), "meaning")?;
        string(&Value::Object(entry.clone()), "false_positive_boundary")?;
        let rank = entry
            .get("rank")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{kind} rank must be u64"))?;
        if !ranks.insert(rank) {
            return Err(format!("duplicate confidence rank {rank}"));
        }
    }

    let category_catalog = object(scan, "category_catalog")?;
    let categories = category_catalog
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_categories = REQUIRED_CATEGORIES.iter().copied().collect::<BTreeSet<_>>();
    if categories != expected_categories {
        return Err("category catalog drifted".to_owned());
    }
    for category in REQUIRED_CATEGORIES {
        let entry = object(&scan["category_catalog"], category)?;
        string(&Value::Object(entry.clone()), "meaning")?;
        string(&Value::Object(entry.clone()), "scanner_rule")?;
        for boundary in string_set(&Value::Object(entry.clone()), "no_claim_boundaries")? {
            if !boundary.starts_with("does_not_") {
                return Err(format!(
                    "{category}: no-claim boundary must be does_not token"
                ));
            }
        }
    }

    let rows = array(scan, "rows")?;
    let mut last_sort_key = String::new();
    let mut paths = BTreeSet::new();
    let mut category_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut confidence_seen = BTreeSet::new();

    for row in rows {
        let path = string(row, "artifact_path")?;
        let category = string(row, "category")?;
        if !category_catalog.contains_key(category) {
            return Err(format!("{path}: unknown category {category}"));
        }
        let sort_key = format!("{path}\0{category}");
        if !last_sort_key.is_empty() && sort_key <= last_sort_key {
            return Err(format!("{path}: rows must use stable bytewise order"));
        }
        last_sort_key = sort_key;
        if !paths.insert(path.to_owned()) {
            return Err(format!("duplicate artifact_path {path}"));
        }

        if category == "excluded" {
            if optional_string(row, "exclusion_reason")?.is_none() {
                return Err(format!("{path}: excluded row needs exclusion_reason"));
            }
        } else {
            assert_repo_file_exists(path)?;
            if optional_string(row, "exclusion_reason")?.is_some() {
                return Err(format!(
                    "{path}: non-excluded row must not carry exclusion_reason"
                ));
            }
        }

        let ownership = object(row, "ownership")?;
        let ownership_value = Value::Object(ownership.clone());
        let bead_ids = string_set(&ownership_value, "bead_ids")?;
        if bead_ids.is_empty() {
            return Err(format!("{path}: ownership bead_ids must not be empty"));
        }
        let confidence_level = string(&ownership_value, "confidence_level")?;
        if !confidence_catalog.contains_key(confidence_level) {
            return Err(format!(
                "{path}: unknown confidence level {confidence_level}"
            ));
        }
        for source in array(&ownership_value, "confidence_sources")? {
            let kind = validate_source_match(source)?;
            if !confidence_catalog.contains_key(&kind) {
                return Err(format!("{path}: unknown confidence source kind {kind}"));
            }
            confidence_seen.insert(kind);
        }

        for test_path in array(row, "checked_by_tests")? {
            assert_repo_file_exists(
                test_path
                    .as_str()
                    .ok_or("checked_by_tests entries must be strings")?,
            )?;
        }
        for doc_path in array(row, "docs_references")? {
            assert_repo_file_exists(
                doc_path
                    .as_str()
                    .ok_or("docs_references entries must be strings")?,
            )?;
        }
        for boundary in string_set(row, "no_claim_boundaries")? {
            if !boundary.starts_with("does_not_") {
                return Err(format!("{path}: no-claim boundary must be does_not token"));
            }
        }

        match category {
            "orphan" => {
                if !array(row, "ledger_rows")?.is_empty()
                    || !array(row, "proof_manifest_rows")?.is_empty()
                    || !array(row, "proof_status_rows")?.is_empty()
                {
                    return Err(format!(
                        "{path}: orphan rows must not have governance mappings"
                    ));
                }
            }
            "ambiguous" => {
                if bead_ids.len() < 2 {
                    return Err(format!("{path}: ambiguous rows need conflicting owners"));
                }
            }
            "stale" => {
                let successor = optional_string(row, "superseded_by")?
                    .ok_or_else(|| format!("{path}: stale rows need superseded_by"))?;
                if successor == path || !repo_path(successor).is_file() {
                    return Err(format!(
                        "{path}: supersession target must be a different file"
                    ));
                }
                string(row, "stale_reason")?;
            }
            _ => {
                if optional_string(row, "superseded_by")?.is_some() {
                    return Err(format!("{path}: only stale rows may carry superseded_by"));
                }
            }
        }

        *category_counts.entry(category.to_owned()).or_default() += 1;
    }

    let summary = object(scan, "summary")?;
    if summary.get("row_count").and_then(Value::as_u64) != Some(rows.len() as u64) {
        return Err("summary row_count drifted".to_owned());
    }
    for category in REQUIRED_CATEGORIES {
        if !category_counts.contains_key(*category) {
            return Err(format!("missing required category {category}"));
        }
        let expected = summary["category_counts"][*category]
            .as_u64()
            .ok_or_else(|| format!("summary missing category {category}"))?;
        if category_counts[*category] != expected {
            return Err(format!("summary count drifted for {category}"));
        }
    }
    for kind in REQUIRED_CONFIDENCE_KINDS {
        if !confidence_seen.contains(*kind) {
            return Err(format!("missing confidence source kind {kind}"));
        }
    }

    Ok(())
}

#[test]
fn scanner_artifact_schema_and_links_are_valid() {
    let scan = scanner();
    validate_scanner(&scan).expect("scanner artifact must satisfy A2 contract");
}

#[test]
fn scanner_report_is_concise_and_matches_artifact_boundaries() {
    let report = read_repo_file(REPORT_PATH);
    for required in [
        SCANNER_PATH,
        BEAD_ID,
        "does not claim full-corpus coverage",
        "never rewrites, moves, or deletes artifacts",
        "orphan",
        "ambiguous",
        "stale",
        "excluded",
    ] {
        assert!(
            report.contains(required),
            "scanner report must contain {required}"
        );
    }
}

#[test]
fn scanner_is_registered_in_the_governance_ledger() {
    let ledger: Value = serde_json::from_str(&read_repo_file(LEDGER_PATH)).expect("parse ledger");
    let rows = ledger["rows"].as_array().expect("ledger rows");
    let row = rows
        .iter()
        .find(|row| row["artifact_id"].as_str() == Some("artifact-governance-scanner"))
        .expect("ledger row for scanner");

    assert_eq!(row["path"].as_str(), Some(SCANNER_PATH));
    assert_eq!(row["owning_bead"].as_str(), Some(BEAD_ID));
    assert_eq!(row["artifact_family"].as_str(), Some("artifact_governance"));
    assert_eq!(row["citeability_class"].as_str(), Some("proof-bearing"));
}

#[test]
fn malformed_json_fixture_is_rejected() {
    let error = serde_json::from_str::<Value>("{ not valid json")
        .expect_err("malformed scanner JSON must fail to parse");
    assert!(
        error.to_string().contains("expected")
            || error.to_string().contains("key")
            || error.to_string().contains("EOF"),
        "malformed-json diagnostic should be explicit: {error}"
    );
}

#[test]
fn missing_owner_field_fixture_is_rejected() {
    let mut scan = scanner();
    let first_row = scan["rows"][0]
        .as_object_mut()
        .expect("row object for fixture mutation");
    first_row.remove("ownership");

    let error = validate_scanner(&scan).expect_err("missing ownership should fail");
    assert!(error.contains("ownership"), "unexpected error: {error}");
}

#[test]
fn duplicate_artifact_path_fixture_is_rejected() {
    let mut scan = scanner();
    let duplicate = scan["rows"][0].clone();
    scan["rows"]
        .as_array_mut()
        .expect("rows array")
        .insert(1, duplicate);

    let error = validate_scanner(&scan).expect_err("duplicate path should fail");
    assert!(
        error.contains("duplicate artifact_path") || error.contains("stable bytewise order"),
        "unexpected error: {error}"
    );
}

#[test]
fn self_supersession_fixture_is_rejected() {
    let mut scan = scanner();
    let stale = scan["rows"]
        .as_array_mut()
        .expect("rows array")
        .iter_mut()
        .find(|row| row["category"].as_str() == Some("stale"))
        .expect("stale fixture row");
    let path = stale["artifact_path"].clone();
    stale["superseded_by"] = path;

    let error = validate_scanner(&scan).expect_err("self-supersession should fail");
    assert!(error.contains("supersession"), "unexpected error: {error}");
}
