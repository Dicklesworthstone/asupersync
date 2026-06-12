#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const REPORT_PATH: &str = "artifacts/artifact_governance_operator_report_v1.json";
const MARKDOWN_PATH: &str = "docs/proof/artifact_governance_operator_report.md";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const SCANNER_PATH: &str = "artifacts/artifact_governance_scanner_v1.json";
const BACKFILL_PATH: &str = "artifacts/artifact_governance_seed_backfill_v1.json";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.4";

const REQUIRED_ACTIONS: &[&str] = &[
    "ambiguous_ownership",
    "blocked",
    "citeable",
    "excluded",
    "missing_tests",
    "operator_context",
    "owner_missing",
    "stale_superseded",
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

fn report() -> Value {
    repo_json(REPORT_PATH)
}

fn ledger() -> Value {
    repo_json(LEDGER_PATH)
}

fn scanner() -> Value {
    repo_json(SCANNER_PATH)
}

fn backfill() -> Value {
    repo_json(BACKFILL_PATH)
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

fn ledger_rows() -> BTreeMap<String, Value> {
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

fn scanner_rows() -> BTreeMap<String, Value> {
    let scanner = scanner();
    let mut rows = BTreeMap::new();
    for row in array(&scanner, "rows") {
        let path = string(row, "artifact_path").to_owned();
        assert!(
            rows.insert(path.clone(), row.clone()).is_none(),
            "duplicate scanner row {path}"
        );
    }
    rows
}

fn backfill_rows() -> BTreeMap<String, Value> {
    let backfill = backfill();
    let mut rows = BTreeMap::new();
    for row in array(&backfill, "seed_rows") {
        let ledger_row = string(row, "ledger_row").to_owned();
        assert!(
            rows.insert(ledger_row.clone(), row.clone()).is_none(),
            "duplicate backfill seed row {ledger_row}"
        );
    }
    rows
}

fn bucket_map(report: &Value) -> BTreeMap<String, Value> {
    let mut buckets = BTreeMap::new();
    let mut last = String::new();
    for bucket in array(report, "report_buckets") {
        let action_id = string(bucket, "action_id").to_owned();
        assert!(
            last.is_empty() || action_id > last,
            "buckets must be sorted by action_id"
        );
        last = action_id.clone();
        assert!(
            buckets.insert(action_id.clone(), bucket.clone()).is_none(),
            "duplicate bucket {action_id}"
        );
    }
    buckets
}

fn all_items(report: &Value) -> Vec<(String, Value)> {
    let mut items = Vec::new();
    for bucket in array(report, "report_buckets") {
        let action_id = string(bucket, "action_id").to_owned();
        let mut last = String::new();
        for item in array(bucket, "items") {
            let item_id = string(item, "item_id").to_owned();
            assert!(
                last.is_empty() || item_id > last,
                "{action_id}: items must be sorted by item_id"
            );
            last = item_id;
            items.push((action_id.clone(), item.clone()));
        }
    }
    items
}

fn assert_no_destructive_suggestion(text: &str) {
    let lower = text.to_ascii_lowercase();
    for forbidden in [
        "rm -rf",
        "git clean",
        "git reset",
        "worktree add",
        "checkout -b",
        "switch -c",
        "local cargo fallback",
    ] {
        assert!(
            !lower.contains(forbidden),
            "operator action contains forbidden suggestion {forbidden}: {text}"
        );
    }
}

#[test]
fn operator_report_schema_sources_and_policy_are_bounded() {
    let report = report();
    assert_eq!(
        report.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-operator-report-v1")
    );
    assert_eq!(report.get("bead_id").and_then(Value::as_str), Some(BEAD_ID));

    for path in object(&report, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path string"))
    {
        assert_repo_file_exists(path);
    }

    let policy = object(&report, "report_policy");
    assert!(!bool_field(
        &Value::Object(policy.clone()),
        "full_corpus_claim"
    ));
    let policy_value = Value::Object(policy.clone());
    let non_destructive = string(&policy_value, "non_destructive_policy");
    for required in [
        "does not delete",
        "branch",
        "worktree",
        "local Cargo fallback",
    ] {
        assert!(
            non_destructive.contains(required),
            "non_destructive_policy must mention {required}"
        );
    }

    let actions = object(&report, "action_catalog")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = REQUIRED_ACTIONS
        .iter()
        .map(|action| (*action).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actions, expected, "action catalog drifted");
}

#[test]
fn buckets_are_ledger_scanner_and_backfill_aligned() {
    let report = report();
    let ledger_rows = ledger_rows();
    let scanner_rows = scanner_rows();
    let backfill_rows = backfill_rows();

    for action in REQUIRED_ACTIONS {
        assert!(
            bucket_map(&report).contains_key(*action),
            "missing action bucket {action}"
        );
    }

    for (action_id, item) in all_items(&report) {
        let item_id = string(&item, "item_id");
        let artifact_path = string(&item, "artifact_path");
        let next_action = string(&item, "next_action");
        assert_no_destructive_suggestion(next_action);

        let no_claims = string_set(&item, "no_claim_boundaries");
        assert!(
            no_claims.len() >= 3 && no_claims.iter().all(|claim| claim.starts_with("does_not_")),
            "{item_id}: no-claim boundaries must be machine-readable"
        );
        let mut allowed_boundaries = string_set(&report, "no_claim_boundaries");

        if let Some(row_id) = optional_string(&item, "ledger_row") {
            let row = ledger_rows
                .get(row_id)
                .unwrap_or_else(|| panic!("{item_id}: missing ledger row {row_id}"));
            assert_eq!(string(row, "path"), artifact_path);
            allowed_boundaries.extend(string_set(row, "no_claim_boundaries"));

            match action_id.as_str() {
                "blocked" | "ambiguous_ownership" => {
                    assert_eq!(string(row, "citeability_class"), "blocked-frontier");
                }
                "citeable" => assert_eq!(string(row, "citeability_class"), "proof-bearing"),
                "excluded" | "missing_tests" => {
                    assert_eq!(string(row, "citeability_class"), "excluded");
                }
                "operator_context" => {
                    assert_eq!(string(row, "citeability_class"), "operator-report");
                }
                "stale_superseded" => {
                    assert_eq!(string(row, "citeability_class"), "superseded");
                    assert_eq!(
                        optional_string(&item, "superseded_by"),
                        optional_string(row, "superseded_by")
                    );
                }
                "owner_missing" => unreachable!("owner_missing items must not have ledger rows"),
                _ => {}
            }
        }

        if let Some(category) = optional_string(&item, "scanner_category") {
            let scanner_row = scanner_rows
                .get(artifact_path)
                .unwrap_or_else(|| panic!("{item_id}: missing scanner row for {artifact_path}"));
            assert_eq!(string(scanner_row, "category"), category);
            allowed_boundaries.extend(string_set(scanner_row, "no_claim_boundaries"));
        }

        if let Some(seed_row) = optional_string(&item, "seed_row") {
            let seed = backfill_rows
                .get(seed_row)
                .unwrap_or_else(|| panic!("{item_id}: missing seed row {seed_row}"));
            assert_eq!(string(seed, "artifact_path"), artifact_path);
            allowed_boundaries.extend(string_set(seed, "no_claim_boundaries"));
        }

        for boundary in &no_claims {
            assert!(
                allowed_boundaries.contains(boundary),
                "{item_id}: boundary {boundary} missing from ledger, scanner, seed, or report boundary sources"
            );
        }
    }
}

#[test]
fn operator_summary_counts_and_golden_text_are_stable() {
    let report = report();
    let summary = object(&report, "operator_summary");
    let buckets = bucket_map(&report);

    assert_eq!(
        u64_field(&Value::Object(summary.clone()), "bucket_count"),
        8
    );
    assert_eq!(
        u64_field(&Value::Object(summary.clone()), "item_count"),
        all_items(&report).len() as u64
    );

    let expected_counts = [
        ("ambiguous_ownership", "ambiguous_item_count", 1),
        ("blocked", "blocked_item_count", 3),
        ("citeable", "citeable_item_count", 2),
        ("excluded", "excluded_item_count", 1),
        ("missing_tests", "missing_tests_item_count", 1),
        ("operator_context", "operator_context_item_count", 1),
        ("owner_missing", "owner_missing_item_count", 1),
        ("stale_superseded", "stale_or_superseded_item_count", 1),
    ];

    for (bucket, field, expected) in expected_counts {
        assert_eq!(
            array(&buckets[bucket], "items").len() as u64,
            expected,
            "{bucket}: bucket item count drifted"
        );
        assert_eq!(
            u64_field(&Value::Object(summary.clone()), field),
            expected,
            "{field}: summary count drifted"
        );
    }

    assert_eq!(
        string(&Value::Object(summary.clone()), "golden_summary"),
        "citeable=2 blocked=3 ambiguous=1 owner_missing=1 stale_superseded=1 excluded=1 missing_tests=1 operator_context=1"
    );
    assert_eq!(
        string(&Value::Object(summary.clone()), "first_blocker"),
        "validation-frontier-inventory"
    );
}

#[test]
fn markdown_report_matches_json_summary_and_boundaries() {
    let report = report();
    let markdown = read_repo_file(MARKDOWN_PATH);
    let summary = object(&report, "operator_summary");
    let summary_value = Value::Object(summary.clone());
    let golden = string(&summary_value, "golden_summary");
    assert!(
        markdown.contains(golden),
        "markdown report must include golden summary"
    );

    for action in REQUIRED_ACTIONS {
        assert!(
            markdown.contains(action),
            "markdown report missing action bucket {action}"
        );
    }

    for boundary in string_set(&report, "no_claim_boundaries") {
        assert!(
            markdown.contains(&boundary),
            "markdown report missing report boundary {boundary}"
        );
    }

    assert!(markdown.contains("select no winner"));
    assert!(markdown.contains("does not authorize deletion"));
    assert!(markdown.contains("does not prove a fresh RCH pass"));
}

#[test]
fn operator_report_is_registered_in_the_governance_ledger() {
    let rows = ledger_rows();
    let row = rows
        .get("artifact-governance-operator-report")
        .expect("operator report ledger row");

    assert_eq!(string(row, "path"), REPORT_PATH);
    assert_eq!(
        string(row, "owning_bead"),
        "asupersync-artifact-governance-awdiwy.4"
    );
    assert_eq!(string(row, "artifact_family"), "artifact_governance");
    assert_eq!(string(row, "citeability_class"), "operator-report");
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_close_artifact_beads"));
    assert!(
        array(row, "checked_by_tests")
            .iter()
            .any(|test| test.as_str()
                == Some("tests/artifact_governance_operator_report_contract.rs"))
    );
}
