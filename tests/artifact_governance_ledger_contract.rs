#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const TEST_PATH: &str = "tests/artifact_governance_ledger_contract.rs";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.1";

const REQUIRED_ROW_FIELDS: &[&str] = &[
    "artifact_id",
    "path",
    "path_status",
    "owning_bead",
    "producing_lane",
    "domain",
    "artifact_family",
    "checked_by_tests",
    "citeability_class",
    "freshness_policy",
    "superseded_by",
    "no_claim_boundaries",
    "exclusion_reason",
    "evidence_scope",
    "source_references",
];

const REQUIRED_CLASSES: &[&str] = &[
    "proof-bearing",
    "advisory",
    "blocked-frontier",
    "superseded",
    "generated-fixture",
    "operator-report",
    "excluded",
];

const REQUIRED_FAMILIES: &[&str] = &[
    "proof_manifest",
    "validation_frontier",
    "rch_stale_receipt",
    "runtime_pressure",
    "swarm_agent",
    "browser_wasm",
    "artifact_governance",
    "raptorq",
    "generated_fixture",
    "excluded",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn ledger() -> Value {
    serde_json::from_str(&read_repo_file(LEDGER_PATH))
        .unwrap_or_else(|error| panic!("parse {LEDGER_PATH}: {error}"))
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
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn rows_by_id(ledger: &Value) -> BTreeMap<String, &Value> {
    let mut rows = BTreeMap::new();
    for row in array(ledger, "rows") {
        let artifact_id = string(row, "artifact_id").to_owned();
        assert!(
            rows.insert(artifact_id.clone(), row).is_none(),
            "duplicate artifact_id {artifact_id}"
        );
    }
    rows
}

fn assert_repo_file_exists(path: &str) {
    assert!(
        repo_path(path).is_file(),
        "referenced repo file must exist: {path}"
    );
}

#[test]
fn ledger_schema_is_self_describing_and_non_destructive() {
    let ledger = ledger();

    assert_eq!(
        ledger.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-ledger-v1")
    );
    assert_eq!(ledger.get("bead_id").and_then(Value::as_str), Some(BEAD_ID));

    let source = object(&ledger, "source_of_truth");
    assert_eq!(source["ledger"].as_str(), Some(LEDGER_PATH));
    assert_eq!(source["contract_test"].as_str(), Some(TEST_PATH));
    assert_eq!(source["agent_instructions"].as_str(), Some("AGENTS.md"));
    assert_eq!(
        source["testing_decision_tree"].as_str(),
        Some("TESTING_FOR_AGENTS.md")
    );
    for path in source
        .values()
        .map(|value| value.as_str().expect("path string"))
    {
        assert_repo_file_exists(path);
    }

    let policy = object(&ledger, "coverage_policy");
    assert_eq!(
        policy["corpus_coverage"].as_str(),
        Some("seeded_representative_not_exhaustive")
    );
    assert!(!bool_field(&ledger["coverage_policy"], "full_corpus_claim"));
    for key in [
        "exclusion_policy",
        "missing_artifact_policy",
        "non_destructive_policy",
    ] {
        let text = string(&ledger["coverage_policy"], key);
        assert!(
            text.contains("not") || text.contains("never") || text.contains("does not"),
            "{key} must explicitly constrain over-claiming"
        );
    }
    assert!(
        string(&ledger["coverage_policy"], "non_destructive_policy").contains("does not delete")
    );

    let field_definitions = object(&ledger, "field_definitions");
    let expected_fields = REQUIRED_ROW_FIELDS.iter().copied().collect::<BTreeSet<_>>();
    let actual_fields = field_definitions
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_fields, expected_fields,
        "every row field must have exactly one field definition"
    );
    for field in REQUIRED_ROW_FIELDS {
        let definition = object(&ledger["field_definitions"], field);
        string(&Value::Object(definition.clone()), "meaning");
        string(&Value::Object(definition.clone()), "no_claim_boundary");
    }
}

#[test]
fn citeability_taxonomy_is_complete_and_exercised() {
    let ledger = ledger();
    let catalog = object(&ledger, "classification_catalog");
    let expected = REQUIRED_CLASSES.iter().copied().collect::<BTreeSet<_>>();
    let actual = catalog.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "citeability catalog drifted");

    for class in REQUIRED_CLASSES {
        let entry = object(&ledger["classification_catalog"], class);
        string(&Value::Object(entry.clone()), "meaning");
        string(&Value::Object(entry.clone()), "cite_rule");
        assert!(
            !array(&Value::Object(entry.clone()), "does_not_prove").is_empty(),
            "{class} must declare no-claim boundaries"
        );
    }

    let exercised = array(&ledger, "rows")
        .iter()
        .map(|row| string(row, "citeability_class").to_owned())
        .collect::<BTreeSet<_>>();
    for class in REQUIRED_CLASSES {
        assert!(exercised.contains(*class), "{class} must have a seed row");
    }
}

#[test]
fn rows_have_valid_taxonomy_paths_and_no_claim_boundaries() {
    let ledger = ledger();
    let field_definitions = object(&ledger, "field_definitions");
    let classification_catalog = object(&ledger, "classification_catalog");
    let path_status_catalog = object(&ledger, "path_status_catalog");
    let required_families = string_set(&ledger, "required_family_seed_coverage");

    for row in array(&ledger, "rows") {
        let artifact_id = string(row, "artifact_id");

        let row_object = row.as_object().expect("row must be an object");
        let row_fields = row_object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_fields = REQUIRED_ROW_FIELDS.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            row_fields, expected_fields,
            "{artifact_id}: row field drift"
        );
        for key in row_object.keys() {
            assert!(
                field_definitions.contains_key(key),
                "{artifact_id}: {key} missing field definition"
            );
        }

        let path = string(row, "path");
        match string(row, "path_status") {
            "tracked" => assert_repo_file_exists(path),
            "missing_expected_artifact" => assert!(
                !repo_path(path).exists(),
                "{artifact_id}: missing_expected_artifact path unexpectedly exists: {path}"
            ),
            "generated_or_ignored" => assert!(
                path.contains('*') || path.starts_with('.') || path.starts_with("${"),
                "{artifact_id}: generated_or_ignored paths should be explicit patterns"
            ),
            other => panic!("{artifact_id}: unknown path_status {other}"),
        }
        assert!(
            path_status_catalog.contains_key(string(row, "path_status")),
            "{artifact_id}: path_status missing from catalog"
        );

        let class = string(row, "citeability_class");
        assert!(
            classification_catalog.contains_key(class),
            "{artifact_id}: class {class} missing from catalog"
        );
        let family = string(row, "artifact_family");
        assert!(
            required_families.contains(family),
            "{artifact_id}: family {family} is not listed in required coverage"
        );

        for test_path in array(row, "checked_by_tests") {
            let test_path = test_path
                .as_str()
                .unwrap_or_else(|| panic!("{artifact_id}: checked_by_tests entries are strings"));
            assert_repo_file_exists(test_path);
        }
        for source_path in array(row, "source_references") {
            let source_path = source_path
                .as_str()
                .unwrap_or_else(|| panic!("{artifact_id}: source_references entries are strings"));
            assert_repo_file_exists(source_path);
        }

        let no_claims = string_set(row, "no_claim_boundaries");
        assert!(
            no_claims.iter().all(|claim| claim.starts_with("does_not_")),
            "{artifact_id}: no-claim boundaries must be machine-readable does_not tokens"
        );
        assert!(
            no_claims.len() >= 3,
            "{artifact_id}: each row must carry at least three no-claim boundaries"
        );

        match class {
            "excluded" => assert!(
                optional_string(row, "exclusion_reason").is_some(),
                "{artifact_id}: excluded rows require exclusion_reason"
            ),
            "superseded" => {
                assert!(
                    optional_string(row, "exclusion_reason").is_none(),
                    "{artifact_id}: superseded rows are not exclusions"
                );
                let successor = optional_string(row, "superseded_by")
                    .unwrap_or_else(|| panic!("{artifact_id}: superseded rows need successor"));
                assert_repo_file_exists(successor);
            }
            _ => {
                assert!(
                    optional_string(row, "exclusion_reason").is_none(),
                    "{artifact_id}: non-excluded rows must not carry exclusion_reason"
                );
                assert!(
                    optional_string(row, "superseded_by").is_none(),
                    "{artifact_id}: only superseded rows may carry superseded_by"
                );
            }
        }
    }
}

#[test]
fn seed_rows_cover_requested_families_without_full_corpus_claim() {
    let ledger = ledger();
    assert!(!bool_field(&ledger["coverage_policy"], "full_corpus_claim"));

    let required = REQUIRED_FAMILIES
        .iter()
        .map(|family| (*family).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        string_set(&ledger, "required_family_seed_coverage"),
        required,
        "required family list must match the A1 seed-scope contract"
    );

    let covered = array(&ledger, "rows")
        .iter()
        .map(|row| string(row, "artifact_family").to_owned())
        .collect::<BTreeSet<_>>();
    for family in REQUIRED_FAMILIES {
        assert!(
            covered.contains(*family),
            "seed rows must cover requested family {family}"
        );
    }
}

#[test]
fn specific_seed_rows_preserve_fail_closed_citation_boundaries() {
    let ledger = ledger();
    let rows = rows_by_id(&ledger);

    let proof_manifest = rows["proof-lane-manifest-canonical"];
    assert_eq!(string(proof_manifest, "path_status"), "tracked");
    assert_eq!(
        string(proof_manifest, "citeability_class"),
        "blocked-frontier"
    );
    assert!(
        string_set(proof_manifest, "no_claim_boundaries")
            .contains("does_not_authorize_local_cargo_fallback")
    );

    let scanner = rows["artifact-governance-scanner"];
    assert_eq!(string(scanner, "path_status"), "tracked");
    assert_eq!(string(scanner, "artifact_family"), "artifact_governance");
    assert_eq!(
        string(scanner, "owning_bead"),
        "asupersync-artifact-governance-awdiwy.2"
    );
    assert!(string_set(scanner, "no_claim_boundaries").contains("does_not_authorize_deletion"));

    let rch = rows["rch-stale-progress-receipt-contract"];
    assert_eq!(string(rch, "path_status"), "tracked");
    assert!(string_set(rch, "no_claim_boundaries").contains("does_not_prove_source_correctness"));

    let runtime = rows["runtime-pressure-control-evidence-contract"];
    assert_eq!(string(runtime, "path_status"), "tracked");
    assert!(
        string_set(runtime, "no_claim_boundaries")
            .contains("does_not_prove_adaptive_controls_are_production_enabled")
    );

    let wasm = rows["browser-wasm-artifact-integrity-manifest"];
    assert_eq!(string(wasm, "citeability_class"), "proof-bearing");
    assert!(string_set(wasm, "no_claim_boundaries").contains("does_not_execute_npm_publish"));

    let raptorq_v3 = rows["raptorq-gf256-multiscenario-refresh-v3"];
    assert_eq!(string(raptorq_v3, "citeability_class"), "superseded");
    assert_eq!(
        optional_string(raptorq_v3, "superseded_by"),
        Some("artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json")
    );
    assert!(string_set(raptorq_v3, "no_claim_boundaries").contains("does_not_authorize_deletion"));

    let generated = rows["generated-smoke-artifact-inventory"];
    assert_eq!(string(generated, "citeability_class"), "generated-fixture");
    assert!(string_set(generated, "no_claim_boundaries").contains("does_not_authorize_deletion"));

    let excluded = rows["remote-build-target-cache-roots"];
    assert_eq!(string(excluded, "citeability_class"), "excluded");
    assert!(
        optional_string(excluded, "exclusion_reason")
            .expect("exclusion reason")
            .contains("ephemeral")
    );
}
