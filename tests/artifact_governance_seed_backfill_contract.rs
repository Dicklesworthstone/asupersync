#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const BACKFILL_PATH: &str = "artifacts/artifact_governance_seed_backfill_v1.json";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const SCANNER_PATH: &str = "artifacts/artifact_governance_scanner_v1.json";
const REPORT_PATH: &str = "docs/proof/artifact_governance_seed_backfill.md";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.7";

const REQUIRED_CONFIDENCE_CLASSES: &[&str] = &[
    "ledger_exact_owner",
    "scanner_exact_owner",
    "ledger_route_plus_artifact_bead",
    "ambiguous_owner_signals",
    "generated_fixture_inventory",
    "explicit_exclusion",
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

fn backfill() -> Value {
    repo_json(BACKFILL_PATH)
}

fn ledger() -> Value {
    repo_json(LEDGER_PATH)
}

fn scanner() -> Value {
    repo_json(SCANNER_PATH)
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

fn usize_field(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an integer")) as usize
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

fn confidence_classes(backfill: &Value) -> BTreeSet<String> {
    object(backfill, "ownership_confidence_catalog")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn seed_backfill_schema_sources_and_policy_are_bounded() {
    let backfill = backfill();

    assert_eq!(
        backfill.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-seed-backfill-v1")
    );
    assert_eq!(
        backfill.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );

    for path in object(&backfill, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path"))
    {
        assert_repo_file_exists(path);
    }

    let policy = object(&backfill, "coverage_policy");
    assert_eq!(
        policy["corpus_coverage"].as_str(),
        Some("curated_representative_seed_backfill_not_exhaustive")
    );
    assert!(!bool_field(
        &backfill["coverage_policy"],
        "full_corpus_claim"
    ));
    assert!(usize_field(&backfill["coverage_policy"], "minimum_artifact_families") >= 8);
    assert!(string(&backfill["coverage_policy"], "ambiguous_owner_policy").contains("do not"));
    assert!(string(&backfill["coverage_policy"], "non_destructive_policy").contains("does not"));

    let expected = REQUIRED_CONFIDENCE_CLASSES
        .iter()
        .map(|class| (*class).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(confidence_classes(&backfill), expected);
    for class in REQUIRED_CONFIDENCE_CLASSES {
        let entry = object(&backfill["ownership_confidence_catalog"], class);
        string(&Value::Object(entry.clone()), "meaning");
        assert!(
            string(&Value::Object(entry.clone()), "no_claim_boundary").starts_with("does_not_"),
            "{class}: confidence boundary must be machine-readable"
        );
    }
}

#[test]
fn seed_rows_match_ledger_rows_and_cover_high_value_families() {
    let backfill = backfill();
    let ledger_rows = rows_by_id();
    let confidence_classes = confidence_classes(&backfill);
    let mut families = BTreeSet::new();

    for seed in array(&backfill, "seed_rows") {
        let ledger_row = string(seed, "ledger_row");
        let ledger = ledger_rows
            .get(ledger_row)
            .unwrap_or_else(|| panic!("missing ledger row {ledger_row}"));

        assert_eq!(string(seed, "artifact_path"), string(ledger, "path"));
        assert_eq!(
            string(seed, "artifact_family"),
            string(ledger, "artifact_family")
        );
        assert_eq!(
            string(seed, "citeability_class"),
            string(ledger, "citeability_class")
        );
        assert!(
            confidence_classes.contains(string(seed, "ownership_confidence")),
            "{ledger_row}: unknown ownership confidence"
        );
        assert!(
            !string_set(seed, "owner_beads").is_empty(),
            "{ledger_row}: owner_beads must be explicit"
        );
        if let Some(selected_owner) = optional_string(seed, "selected_owner") {
            assert!(
                string_set(seed, "owner_beads").contains(selected_owner),
                "{ledger_row}: selected owner must come from owner_beads"
            );
        }
        string(seed, "next_action");
        let no_claims = string_set(seed, "no_claim_boundaries");
        assert!(
            no_claims.len() >= 3,
            "{ledger_row}: missing no-claim boundaries"
        );
        assert!(
            no_claims.iter().all(|claim| claim.starts_with("does_not_")),
            "{ledger_row}: no-claim boundaries must be does_not tokens"
        );

        families.insert(string(seed, "artifact_family").to_owned());
    }

    assert!(
        families.len() >= usize_field(&backfill["coverage_policy"], "minimum_artifact_families"),
        "seed rows must cover the configured minimum family count"
    );
    for required in [
        "proof_manifest",
        "validation_frontier",
        "rch_stale_receipt",
        "runtime_pressure",
        "swarm_agent",
        "browser_wasm",
        "raptorq",
        "generated_fixture",
        "excluded",
        "artifact_governance",
    ] {
        assert!(
            families.contains(required),
            "missing seed family {required}"
        );
    }
}

#[test]
fn ambiguous_rows_are_explicit_without_fake_owner_selection() {
    let backfill = backfill();
    let ambiguous = array(&backfill, "seed_rows")
        .iter()
        .filter(|row| string(row, "ownership_confidence") == "ambiguous_owner_signals")
        .collect::<Vec<_>>();

    assert!(!ambiguous.is_empty(), "A7 must preserve ambiguous examples");
    let ids = ambiguous
        .iter()
        .map(|row| string(row, "ledger_row").to_owned())
        .collect::<BTreeSet<_>>();
    assert!(ids.contains("rch-stale-progress-receipt-contract"));

    for row in ambiguous {
        assert!(
            string_set(row, "owner_beads").len() >= 2,
            "{} must name competing owner signals",
            string(row, "ledger_row")
        );
        assert!(
            optional_string(row, "selected_owner").is_none(),
            "{} must not choose an owner",
            string(row, "ledger_row")
        );
        string(row, "ambiguity_reason");
        assert!(
            string_set(row, "no_claim_boundaries").contains("does_not_select_a_winner"),
            "{} must carry does_not_select_a_winner",
            string(row, "ledger_row")
        );
    }
}

#[test]
fn scanner_and_operator_report_explain_backfill_without_cleanup_claims() {
    let scanner = scanner();
    let scanner_rows = array(&scanner, "rows");
    assert!(
        scanner_rows.iter().any(|row| {
            row.get("artifact_path").and_then(Value::as_str)
                == Some("artifacts/rch_stale_progress_receipt_contract_v1.json")
                && row.get("category").and_then(Value::as_str) == Some("ambiguous")
        }),
        "scanner must retain the ambiguous RCH receipt example"
    );

    let report = read_repo_file(REPORT_PATH);
    for required in [
        BACKFILL_PATH,
        BEAD_ID,
        "proof_manifest",
        "rch_stale_receipt",
        "ambiguous_owner_signals",
        "does not prove full-corpus coverage",
        "does not select ambiguous owners",
        "does not authorize deletion",
        "does not prove a fresh RCH pass",
    ] {
        assert!(report.contains(required), "report missing {required}");
    }
}

#[test]
fn seed_backfill_is_registered_in_the_governance_ledger() {
    let rows = rows_by_id();
    let row = rows
        .get("artifact-governance-seed-backfill")
        .expect("seed backfill ledger row");

    assert_eq!(string(row, "path"), BACKFILL_PATH);
    assert_eq!(string(row, "owning_bead"), BEAD_ID);
    assert_eq!(string(row, "artifact_family"), "artifact_governance");
    assert_eq!(string(row, "citeability_class"), "proof-bearing");
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_select_ambiguous_owners"));
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_authorize_deletion"));
}
