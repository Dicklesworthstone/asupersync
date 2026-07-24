//! Dependency replacement safety-taxonomy contract.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.1
//! Scenario: dependency_safety_taxonomy_contract_v1
//! Fixture: artifacts/dependency_safety_taxonomy_v1.json

#![allow(missing_docs)]

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const DOC_PATH: &str = "docs/dependency_safety_taxonomy.md";
const PLAN_PATH: &str = "COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md";
const UNSAFE_LEDGER_PATH: &str = "artifacts/unsafe_boundary_ledger_v1.json";
const UNSAFE_DOC_PATH: &str = "docs/unsafe_boundary_ledger.md";
const SCENARIO_ID: &str = "dependency_safety_taxonomy_contract_v1";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_safety_taxonomy\" cargo test -p asupersync --test dependency_safety_taxonomy_contract -- --nocapture";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .expect("failed to read dependency safety taxonomy contract input")
}

fn taxonomy() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .expect("dependency safety taxonomy must be valid JSON")
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .expect("required taxonomy field must be an object")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .expect("required taxonomy field must be an array")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .expect("required taxonomy field must be a string")
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("taxonomy array entries must be strings")
                .to_owned()
        })
        .collect()
}

fn nonempty_string_array(value: &Value, key: &str) {
    let entries = array(value, key);
    assert!(!entries.is_empty(), "{key} must not be empty");
    for entry in entries {
        assert!(
            entry.as_str().is_some_and(|text| !text.trim().is_empty()),
            "{key} entries must be nonempty strings"
        );
    }
}

fn class_by_id<'a>(taxonomy: &'a Value, class_id: &str) -> &'a Value {
    array(taxonomy, "classes")
        .iter()
        .find(|class| string(class, "class_id") == class_id)
        .expect("required safety class must exist")
}

fn classification_by_id<'a>(taxonomy: &'a Value, candidate_id: &str) -> &'a Value {
    array(taxonomy, "classifications")
        .iter()
        .find(|row| string(row, "candidate_id") == candidate_id)
        .expect("required classification row must exist")
}

fn expected_classifications() -> BTreeMap<&'static str, &'static str> {
    [
        ("hex-codec", "SAFE-OWN"),
        ("base64-codec", "SAFE-OWN"),
        ("future-utilities", "SAFE-OWN"),
        ("token-slab", "SAFE-OWN"),
        ("visibility-attribute", "SAFE-OWN"),
        ("rfc3339-formatter", "SAFE-OWN"),
        ("typed-symbol-bincode-codec", "SAFE-OWN"),
        ("typed-symbol-msgpack-codec", "SAFE-OWN"),
        ("config-schema-migration", "SAFE-OWN"),
        ("cli-parser", "SAFE-OWN"),
        ("regex-scanners", "SAFE-OWN"),
        ("nkey-codec", "SAFE-OWN"),
        ("proto-codec", "SAFE-OWN"),
        ("otlp-metrics", "SAFE-OWN"),
        ("chrono-time", "SAFE-OWN"),
        ("parking-lot-wrapper", "SAFE-OWN"),
        ("lz4-codec", "SAFE-OWN"),
        ("deflate-codec", "SAFE-OWN"),
        ("polling-reactor", "BOUNDARY-UNSAFE"),
        ("socket-platform", "BOUNDARY-UNSAFE"),
        ("signal-platform", "BOUNDARY-UNSAFE"),
        ("host-introspection", "BOUNDARY-UNSAFE"),
        ("extended-attributes", "BOUNDARY-UNSAFE"),
        ("x509-residual-parser", "BOUNDARY-UNSAFE"),
        ("simd-dispatch-boundary", "BOUNDARY-UNSAFE"),
        ("lock-free-queue", "ALGORITHMIC-UNSAFE"),
        ("inline-storage", "ALGORITHMIC-UNSAFE"),
        ("pin-projection", "ALGORITHMIC-UNSAFE"),
        ("raw-lock-parking-protocol", "ALGORITHMIC-UNSAFE"),
    ]
    .into_iter()
    .collect()
}

fn classification_errors(
    row: &Value,
    allowed_eligibility: &BTreeMap<String, BTreeSet<String>>,
    exception_fields: &BTreeSet<String>,
) -> Vec<String> {
    let candidate_id = string(row, "candidate_id");
    let class_id = string(row, "class_id");
    let eligibility = string(row, "eligibility");
    let mut errors = Vec::new();

    match allowed_eligibility.get(class_id) {
        Some(allowed) if !allowed.contains(eligibility) => errors.push(format!(
            "{candidate_id}: {eligibility} is not allowed for {class_id}"
        )),
        None => errors.push(format!("{candidate_id}: unknown class {class_id}")),
        Some(_) => {}
    }

    let unsafe_techniques = array(row, "unsafe_techniques");
    if class_id == "SAFE-OWN" && !unsafe_techniques.is_empty() {
        errors.push(format!(
            "{candidate_id}: SAFE-OWN cannot list unsafe techniques"
        ));
    }
    if class_id != "SAFE-OWN" && unsafe_techniques.is_empty() {
        errors.push(format!(
            "{candidate_id}: {class_id} must name its unsafe techniques"
        ));
    }

    let exception = row
        .get("exception_record")
        .expect("classification row must include exception_record");
    if eligibility == "exception_approved" {
        let Some(record) = exception.as_object() else {
            errors.push(format!(
                "{candidate_id}: exception_approved requires an object record"
            ));
            return errors;
        };
        let actual_fields = record.keys().cloned().collect::<BTreeSet<_>>();
        if &actual_fields != exception_fields {
            errors.push(format!(
                "{candidate_id}: exception fields {actual_fields:?} do not match {exception_fields:?}"
            ));
        }
        for field in exception_fields {
            if record
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|text| text.trim().is_empty())
            {
                errors.push(format!(
                    "{candidate_id}: exception field {field} must be a nonempty string"
                ));
            }
        }
    } else if !exception.is_null() {
        errors.push(format!(
            "{candidate_id}: {eligibility} row must not carry an exception record"
        ));
    }

    errors
}

#[test]
fn artifact_schema_and_source_metadata_are_pinned() {
    let taxonomy = taxonomy();

    assert_eq!(
        taxonomy.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        taxonomy.get("artifact_id").and_then(Value::as_str),
        Some("dependency-safety-taxonomy-v1")
    );
    assert_eq!(
        taxonomy.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        taxonomy.get("program_id").and_then(Value::as_str),
        Some(PROGRAM_ID)
    );

    let generated_from = object(&taxonomy, "generated_from");
    assert_eq!(
        generated_from.get("plan_path").and_then(Value::as_str),
        Some(PLAN_PATH)
    );
    assert_eq!(
        generated_from.get("plan_revision").and_then(Value::as_str),
        Some("Rev 3")
    );
    assert_eq!(
        generated_from.get("plan_commit").and_then(Value::as_str),
        Some("bf759eabc")
    );

    for path in [
        PLAN_PATH,
        UNSAFE_LEDGER_PATH,
        UNSAFE_DOC_PATH,
        ARTIFACT_PATH,
    ] {
        assert!(
            repo_root().join(path).is_file(),
            "required file missing: {path}"
        );
    }
}

#[test]
fn class_inventory_is_complete_and_fail_closed() {
    let taxonomy = taxonomy();
    let expected_ids = BTreeSet::from([
        "SAFE-OWN".to_owned(),
        "BOUNDARY-UNSAFE".to_owned(),
        "ALGORITHMIC-UNSAFE".to_owned(),
    ]);
    let actual_ids = array(&taxonomy, "classes")
        .iter()
        .map(|class| string(class, "class_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);
    assert_eq!(
        actual_ids.len(),
        array(&taxonomy, "classes").len(),
        "class ids must be unique"
    );

    let required_fields = string_set(&taxonomy, "class_required_fields");
    let expected_fields = BTreeSet::from([
        "class_id".to_owned(),
        "definition".to_owned(),
        "default_eligibility".to_owned(),
        "allowed_row_eligibility".to_owned(),
        "unsafe_scope".to_owned(),
        "required_evidence".to_owned(),
        "review_rules".to_owned(),
        "explicit_no_claims".to_owned(),
    ]);
    assert_eq!(required_fields, expected_fields);

    let expected_defaults = [
        ("SAFE-OWN", "eligible"),
        ("BOUNDARY-UNSAFE", "eligible_with_required_evidence"),
        ("ALGORITHMIC-UNSAFE", "prohibited"),
    ];
    for (class_id, default_eligibility) in expected_defaults {
        let class = class_by_id(&taxonomy, class_id);
        for field in &required_fields {
            assert!(
                class.get(field).is_some(),
                "{class_id}: missing required field {field}"
            );
        }
        assert_eq!(string(class, "default_eligibility"), default_eligibility);
        assert!(!string(class, "definition").trim().is_empty());
        assert!(!string(class, "unsafe_scope").trim().is_empty());
        nonempty_string_array(class, "allowed_row_eligibility");
        nonempty_string_array(class, "required_evidence");
        nonempty_string_array(class, "review_rules");
        nonempty_string_array(class, "explicit_no_claims");
    }
}

#[test]
fn class_definitions_preserve_the_programs_substantive_policy() {
    let taxonomy = taxonomy();
    let safe = class_by_id(&taxonomy, "SAFE-OWN");
    let boundary = class_by_id(&taxonomy, "BOUNDARY-UNSAFE");
    let algorithmic = class_by_id(&taxonomy, "ALGORITHMIC-UNSAFE");

    assert!(string(safe, "definition").contains("#![forbid(unsafe_code)]"));
    assert!(string(boundary, "definition").contains("OS/FFI"));
    assert!(string(boundary, "definition").contains("CPU-dispatch"));

    let boundary_evidence = array(boundary, "required_evidence")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "function-scoped #[allow(unsafe_code)]",
        UNSAFE_LEDGER_PATH,
        UNSAFE_DOC_PATH,
        "Miri",
        "UBS",
        "RCH",
    ] {
        assert!(
            boundary_evidence.contains(required),
            "BOUNDARY-UNSAFE evidence must mention {required}"
        );
    }

    let algorithmic_policy = format!(
        "{}\n{}",
        string(algorithmic, "definition"),
        array(algorithmic, "review_rules")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
    for required in [
        "ownership",
        "liveness",
        "initialization",
        "pinning",
        "weak-memory",
        "Loom does not prove liveness or linearizability",
        "Miri does not model weak memory",
        "A 48-hour soak is not a proof",
        "increases risk",
    ] {
        assert!(
            algorithmic_policy.contains(required),
            "ALGORITHMIC-UNSAFE policy must mention {required}"
        );
    }
}

#[test]
fn classification_inventory_and_required_assignments_are_exact() {
    let taxonomy = taxonomy();
    let expected = expected_classifications();
    let rows = array(&taxonomy, "classifications");
    let actual = rows
        .iter()
        .map(|row| (string(row, "candidate_id"), string(row, "class_id")))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual, expected);
    assert_eq!(
        actual.len(),
        rows.len(),
        "candidate ids must be unique and nonempty"
    );

    for candidate in [
        "hex-codec",
        "base64-codec",
        "future-utilities",
        "token-slab",
        "visibility-attribute",
        "nkey-codec",
        "proto-codec",
        "typed-symbol-msgpack-codec",
        "config-schema-migration",
        "cli-parser",
        "regex-scanners",
        "parking-lot-wrapper",
    ] {
        assert_eq!(
            string(classification_by_id(&taxonomy, candidate), "class_id"),
            "SAFE-OWN",
            "{candidate} must remain SAFE-OWN"
        );
    }
    for candidate in [
        "polling-reactor",
        "socket-platform",
        "signal-platform",
        "host-introspection",
        "extended-attributes",
    ] {
        assert_eq!(
            string(classification_by_id(&taxonomy, candidate), "class_id"),
            "BOUNDARY-UNSAFE",
            "{candidate} must remain BOUNDARY-UNSAFE"
        );
    }
    for candidate in [
        "lock-free-queue",
        "inline-storage",
        "pin-projection",
        "raw-lock-parking-protocol",
    ] {
        let row = classification_by_id(&taxonomy, candidate);
        assert_eq!(string(row, "class_id"), "ALGORITHMIC-UNSAFE");
        assert_eq!(string(row, "eligibility"), "prohibited");
    }
}

#[test]
fn every_classification_obeys_its_class_eligibility_and_exception_rules() {
    let taxonomy = taxonomy();
    let required_fields = string_set(&taxonomy, "classification_required_fields");
    let expected_fields = BTreeSet::from([
        "candidate_id".to_owned(),
        "incumbents".to_owned(),
        "replacement_surface".to_owned(),
        "program_phase".to_owned(),
        "program_verdict".to_owned(),
        "class_id".to_owned(),
        "eligibility".to_owned(),
        "unsafe_techniques".to_owned(),
        "program_gates".to_owned(),
        "exception_record".to_owned(),
        "notes".to_owned(),
    ]);
    assert_eq!(required_fields, expected_fields);

    let allowed_eligibility = array(&taxonomy, "classes")
        .iter()
        .map(|class| {
            (
                string(class, "class_id").to_owned(),
                string_set(class, "allowed_row_eligibility"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let exception_fields = string_set(
        taxonomy
            .get("algorithmic_unsafe_exception_process")
            .expect("missing exception process"),
        "required_fields",
    );

    let mut all_errors = Vec::new();
    for row in array(&taxonomy, "classifications") {
        let candidate_id = string(row, "candidate_id");
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "{candidate_id}: missing required field {field}"
            );
        }
        for field in [
            "candidate_id",
            "replacement_surface",
            "program_phase",
            "program_verdict",
            "class_id",
            "eligibility",
            "notes",
        ] {
            assert!(
                !string(row, field).trim().is_empty(),
                "{candidate_id}: {field} must be nonempty"
            );
        }
        let _incumbents = array(row, "incumbents");
        nonempty_string_array(row, "program_gates");
        all_errors.extend(classification_errors(
            row,
            &allowed_eligibility,
            &exception_fields,
        ));
    }
    assert!(
        all_errors.is_empty(),
        "classification eligibility errors:\n{}",
        all_errors.join("\n")
    );
}

#[test]
fn algorithmic_unsafe_exception_process_is_complete_and_partial_evidence_fails_closed() {
    let taxonomy = taxonomy();
    let process = taxonomy
        .get("algorithmic_unsafe_exception_process")
        .expect("missing algorithmic unsafe exception process");
    assert_eq!(string(process, "default_eligibility"), "prohibited");
    assert_eq!(string(process, "partial_evidence_policy"), "fail_closed");
    assert_eq!(
        process
            .get("decision_record_required")
            .and_then(Value::as_bool),
        Some(true)
    );

    let required_fields = string_set(process, "required_fields");
    let expected_fields = BTreeSet::from([
        "measured_incumbent_performance_defect".to_owned(),
        "safe_alternative_benchmark".to_owned(),
        "safe_alternative_rejection_rationale".to_owned(),
        "owner_signoff".to_owned(),
    ]);
    assert_eq!(required_fields, expected_fields);
    let requirements = object(process, "requirements");
    assert_eq!(
        requirements.keys().cloned().collect::<BTreeSet<_>>(),
        required_fields
    );
    for value in requirements.values() {
        assert!(
            value
                .as_str()
                .is_some_and(|requirement| !requirement.trim().is_empty()),
            "exception requirements must be nonempty strings"
        );
    }
    nonempty_string_array(process, "no_implicit_approval");

    let allowed_eligibility = array(&taxonomy, "classes")
        .iter()
        .map(|class| {
            (
                string(class, "class_id").to_owned(),
                string_set(class, "allowed_row_eligibility"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut incomplete = classification_by_id(&taxonomy, "lock-free-queue").clone();
    let incomplete = incomplete
        .as_object_mut()
        .expect("classification fixture must be an object");
    incomplete.insert(
        "eligibility".to_owned(),
        Value::String("exception_approved".to_owned()),
    );
    incomplete.insert(
        "exception_record".to_owned(),
        serde_json::json!({
            "measured_incumbent_performance_defect": "benchmark-ref"
        }),
    );
    let incomplete = Value::Object(incomplete.clone());
    let errors = classification_errors(&incomplete, &allowed_eligibility, &required_fields);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("exception fields")),
        "partial exception evidence must fail closed: {errors:?}"
    );
}

#[test]
fn summary_counts_are_derived_from_rows() {
    let taxonomy = taxonomy();
    let summary = taxonomy
        .get("summary")
        .expect("taxonomy must include summary");
    let rows = array(&taxonomy, "classifications");

    let class_counts = rows.iter().fold(BTreeMap::new(), |mut counts, row| {
        *counts.entry(string(row, "class_id")).or_insert(0_u64) += 1;
        counts
    });
    let eligibility_counts = rows.iter().fold(BTreeMap::new(), |mut counts, row| {
        *counts.entry(string(row, "eligibility")).or_insert(0_u64) += 1;
        counts
    });

    assert_eq!(
        summary.get("class_count").and_then(Value::as_u64),
        Some(array(&taxonomy, "classes").len() as u64)
    );
    assert_eq!(
        summary.get("classification_count").and_then(Value::as_u64),
        Some(rows.len() as u64)
    );
    for (class_id, count) in class_counts {
        assert_eq!(
            summary
                .get("classification_counts_by_class")
                .and_then(|value| value.get(class_id))
                .and_then(Value::as_u64),
            Some(count),
            "summary class count drifted for {class_id}"
        );
    }
    for eligibility in [
        "eligible",
        "eligible_with_required_evidence",
        "prohibited",
        "exception_approved",
    ] {
        let expected = eligibility_counts.get(eligibility).copied().unwrap_or(0);
        assert_eq!(
            summary
                .get("classification_counts_by_eligibility")
                .and_then(|value| value.get(eligibility))
                .and_then(Value::as_u64),
            Some(expected),
            "summary eligibility count drifted for {eligibility}"
        );
    }
}

#[test]
fn policy_scope_and_citation_contract_prevent_overclaiming() {
    let taxonomy = taxonomy();
    let policy_scope = taxonomy.get("policy_scope").expect("missing policy_scope");
    nonempty_string_array(policy_scope, "governs");
    nonempty_string_array(policy_scope, "does_not_govern");
    let no_claim_boundary = string(policy_scope, "no_claim_boundary");
    for required in [
        "prospective dependency-replacement approvals only",
        "does not retroactively judge",
        "existing ledgered unsafe boundaries",
        "not proof",
        "separate program gates",
    ] {
        assert!(
            no_claim_boundary.contains(required),
            "no-claim boundary must mention {required}"
        );
    }

    let citation = taxonomy
        .get("citation_contract")
        .expect("missing citation_contract");
    assert_eq!(string(citation, "artifact_path"), ARTIFACT_PATH);
    let required_fields = string_set(citation, "required_fields");
    assert_eq!(
        required_fields,
        BTreeSet::from([
            "taxonomy_artifact".to_owned(),
            "candidate_id".to_owned(),
            "class_id".to_owned(),
            "eligibility".to_owned(),
            "evidence_refs".to_owned(),
            "explicit_no_claims".to_owned(),
        ])
    );
    let example = citation.get("example").expect("missing citation example");
    for field in required_fields {
        assert!(
            example.get(&field).is_some(),
            "citation example missing {field}"
        );
    }
    assert_eq!(string(example, "taxonomy_artifact"), ARTIFACT_PATH);
    let row = classification_by_id(&taxonomy, string(example, "candidate_id"));
    assert_eq!(string(example, "class_id"), string(row, "class_id"));
    assert_eq!(string(example, "eligibility"), string(row, "eligibility"));
    nonempty_string_array(example, "evidence_refs");
    nonempty_string_array(example, "explicit_no_claims");
}

#[test]
fn docs_publish_the_citation_workflow_and_no_claim_boundary() {
    let docs = read_repo_file(DOC_PATH);
    for section in [
        "Purpose and Scope",
        "The Three Classes",
        "Safety Eligibility Is Not Program Approval",
        "How an Implementation Bead Cites the Taxonomy",
        "Algorithmic-Unsafe Exception Process",
        "No-Claim Boundaries",
        "Validation",
    ] {
        assert!(docs.contains(section), "docs missing section {section}");
    }
    for required in [
        BEAD_ID,
        ARTIFACT_PATH,
        "tests/dependency_safety_taxonomy_contract.rs",
        UNSAFE_LEDGER_PATH,
        UNSAFE_DOC_PATH,
        "SAFE-OWN",
        "BOUNDARY-UNSAFE",
        "ALGORITHMIC-UNSAFE",
        "candidate_id",
        "evidence_refs",
        "explicit_no_claims",
        "does not retroactively",
        PROOF_COMMAND,
    ] {
        assert!(docs.contains(required), "docs must mention {required}");
    }
}

#[test]
fn source_plan_and_validation_metadata_remain_discoverable() {
    let taxonomy = taxonomy();
    let plan = read_repo_file(PLAN_PATH);
    for required in [
        "## 3. Safety taxonomy",
        "SAFE-OWN",
        "BOUNDARY-UNSAFE",
        "ALGORITHMIC-UNSAFE",
        "Moving this class of unsafe",
    ] {
        assert!(
            plan.contains(required),
            "source plan must mention {required}"
        );
    }

    let validation = taxonomy
        .get("validation")
        .expect("missing validation metadata");
    assert_eq!(string(validation, "scenario_id"), SCENARIO_ID);
    assert_eq!(string(validation, "seed_or_fixture"), ARTIFACT_PATH);
    assert_eq!(
        string(validation, "contract_test"),
        "tests/dependency_safety_taxonomy_contract.rs"
    );
    assert_eq!(string(validation, "command"), PROOF_COMMAND);
    assert_eq!(string(validation, "artifact_path"), ARTIFACT_PATH);
    assert_eq!(string(validation, "expected_outcome"), "pass");
}
