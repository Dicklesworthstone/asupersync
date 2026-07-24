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
        ("public-stream-migration", "SAFE-OWN"),
        ("token-slab", "SAFE-OWN"),
        ("visibility-attribute", "SAFE-OWN"),
        ("rfc3339-formatter", "SAFE-OWN"),
        ("atp-version-scanner", "SAFE-OWN"),
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
        ("safe-queue-prototype", "SAFE-OWN"),
        ("cache-padded-experiment", "SAFE-OWN"),
        ("polling-reactor", "BOUNDARY-UNSAFE"),
        ("socket-platform", "BOUNDARY-UNSAFE"),
        ("signal-platform", "BOUNDARY-UNSAFE"),
        ("host-introspection", "BOUNDARY-UNSAFE"),
        ("extended-attributes", "BOUNDARY-UNSAFE"),
        ("x509-residual-parser", "SAFE-OWN"),
        ("simd-dispatch-boundary", "BOUNDARY-UNSAFE"),
        ("lock-free-queue", "ALGORITHMIC-UNSAFE"),
        ("inline-storage", "ALGORITHMIC-UNSAFE"),
        ("pin-projection", "ALGORITHMIC-UNSAFE"),
        ("raw-lock-parking-protocol", "ALGORITHMIC-UNSAFE"),
    ]
    .into_iter()
    .collect()
}

fn expected_sensitivities() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    [
        ("hex-codec", &["ordinary"][..]),
        (
            "base64-codec",
            &["security-sensitive-parser", "wire-format-parser"][..],
        ),
        (
            "future-utilities",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        (
            "public-stream-migration",
            &[
                "concurrency-liveness",
                "public-api-redesign",
                "runtime-hot-path",
            ][..],
        ),
        (
            "token-slab",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        ("visibility-attribute", &["public-api-redesign"][..]),
        ("rfc3339-formatter", &["persistent-format"][..]),
        (
            "atp-version-scanner",
            &["security-sensitive-parser", "wire-format-parser"][..],
        ),
        (
            "typed-symbol-bincode-codec",
            &[
                "persistent-format",
                "public-api-redesign",
                "wire-format-parser",
            ][..],
        ),
        (
            "typed-symbol-msgpack-codec",
            &[
                "persistent-format",
                "public-api-redesign",
                "wire-format-parser",
            ][..],
        ),
        (
            "config-schema-migration",
            &["persistent-format", "public-api-redesign"][..],
        ),
        ("cli-parser", &["public-api-redesign"][..]),
        (
            "regex-scanners",
            &["runtime-hot-path", "security-sensitive-parser"][..],
        ),
        (
            "nkey-codec",
            &[
                "cryptographic-format",
                "persistent-format",
                "security-sensitive-parser",
                "wire-format-parser",
            ][..],
        ),
        (
            "proto-codec",
            &[
                "public-api-redesign",
                "security-sensitive-parser",
                "wire-format-parser",
            ][..],
        ),
        (
            "otlp-metrics",
            &["public-api-redesign", "wire-format-parser"][..],
        ),
        ("chrono-time", &["persistent-format"][..]),
        (
            "parking-lot-wrapper",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        (
            "lz4-codec",
            &[
                "persistent-format",
                "security-sensitive-parser",
                "wire-format-parser",
            ][..],
        ),
        (
            "deflate-codec",
            &["security-sensitive-parser", "wire-format-parser"][..],
        ),
        (
            "safe-queue-prototype",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        (
            "cache-padded-experiment",
            &["platform-boundary", "runtime-hot-path"][..],
        ),
        (
            "polling-reactor",
            &[
                "concurrency-liveness",
                "platform-boundary",
                "runtime-hot-path",
            ][..],
        ),
        (
            "socket-platform",
            &["platform-boundary", "runtime-hot-path"][..],
        ),
        (
            "signal-platform",
            &["concurrency-liveness", "platform-boundary"][..],
        ),
        ("host-introspection", &["platform-boundary"][..]),
        ("extended-attributes", &["platform-boundary"][..]),
        (
            "x509-residual-parser",
            &["security-sensitive-parser", "wire-format-parser"][..],
        ),
        (
            "simd-dispatch-boundary",
            &["platform-boundary", "runtime-hot-path"][..],
        ),
        (
            "lock-free-queue",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        ("inline-storage", &["runtime-hot-path"][..]),
        (
            "pin-projection",
            &["concurrency-liveness", "runtime-hot-path"][..],
        ),
        (
            "raw-lock-parking-protocol",
            &[
                "concurrency-liveness",
                "platform-boundary",
                "runtime-hot-path",
            ][..],
        ),
    ]
    .into_iter()
    .map(|(candidate, tags)| (candidate, tags.iter().copied().collect()))
    .collect()
}

fn classification_errors(
    row: &Value,
    allowed_eligibility: &BTreeMap<String, BTreeSet<String>>,
    exception_fields: &BTreeSet<String>,
    review_tag_ids: &BTreeSet<String>,
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

    let sensitivity_tags = string_set(row, "review_sensitivity_tags");
    if sensitivity_tags.is_empty() {
        errors.push(format!(
            "{candidate_id}: review_sensitivity_tags must not be empty"
        ));
    }
    if sensitivity_tags.len() != array(row, "review_sensitivity_tags").len() {
        errors.push(format!(
            "{candidate_id}: review_sensitivity_tags must be unique"
        ));
    }
    let unknown_tags = sensitivity_tags
        .difference(review_tag_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_tags.is_empty() {
        errors.push(format!(
            "{candidate_id}: unknown review-sensitivity tags {unknown_tags:?}"
        ));
    }
    if sensitivity_tags.contains("ordinary") && sensitivity_tags.len() != 1 {
        errors.push(format!(
            "{candidate_id}: ordinary must not be combined with another tag"
        ));
    }

    let sensitivity_evidence = object(row, "sensitivity_evidence_requirements");
    let evidence_tags = sensitivity_evidence
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if evidence_tags != sensitivity_tags {
        errors.push(format!(
            "{candidate_id}: sensitivity evidence keys {evidence_tags:?} do not match tags {sensitivity_tags:?}"
        ));
    }
    for (tag, evidence) in sensitivity_evidence {
        if evidence.as_array().is_none_or(|entries| {
            entries.is_empty()
                || entries
                    .iter()
                    .any(|entry| entry.as_str().is_none_or(|text| text.trim().is_empty()))
        }) {
            errors.push(format!(
                "{candidate_id}: sensitivity evidence for {tag} must be a nonempty string array"
            ));
        }
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
    assert_eq!(
        generated_from
            .get("tracker_contract_revision")
            .and_then(Value::as_str),
        Some("Rev 4")
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
fn review_sensitivity_axis_is_complete_and_substantive() {
    let taxonomy = taxonomy();
    let expected_ids = BTreeSet::from([
        "ordinary".to_owned(),
        "public-api-redesign".to_owned(),
        "persistent-format".to_owned(),
        "wire-format-parser".to_owned(),
        "security-sensitive-parser".to_owned(),
        "cryptographic-format".to_owned(),
        "concurrency-liveness".to_owned(),
        "platform-boundary".to_owned(),
        "runtime-hot-path".to_owned(),
    ]);
    let tags = array(&taxonomy, "review_sensitivity_tags");
    let actual_ids = tags
        .iter()
        .map(|tag| string(tag, "tag_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);
    assert_eq!(actual_ids.len(), tags.len(), "tag ids must be unique");

    let required_fields = string_set(&taxonomy, "review_sensitivity_tag_required_fields");
    assert_eq!(
        required_fields,
        BTreeSet::from([
            "tag_id".to_owned(),
            "definition".to_owned(),
            "required_evidence".to_owned(),
            "review_rules".to_owned(),
            "explicit_no_claims".to_owned(),
        ])
    );
    for tag in tags {
        let tag_id = string(tag, "tag_id");
        for field in &required_fields {
            assert!(
                tag.get(field).is_some(),
                "{tag_id}: missing required field {field}"
            );
        }
        assert!(!string(tag, "definition").trim().is_empty());
        nonempty_string_array(tag, "required_evidence");
        nonempty_string_array(tag, "review_rules");
        nonempty_string_array(tag, "explicit_no_claims");
    }

    let wire = tags
        .iter()
        .find(|tag| string(tag, "tag_id") == "wire-format-parser")
        .expect("wire-format-parser tag must exist");
    let wire_policy = format!(
        "{}\n{}",
        string(wire, "definition"),
        array(wire, "review_rules")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(wire_policy.contains("safe Rust remains SAFE-OWN"));

    let security = tags
        .iter()
        .find(|tag| string(tag, "tag_id") == "security-sensitive-parser")
        .expect("security-sensitive-parser tag must exist");
    let security_policy = format!(
        "{}\n{}",
        string(security, "definition"),
        array(security, "required_evidence")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
    for marker in [
        "authentication",
        "Independent security review",
        "fail-closed",
        "resource-bound",
    ] {
        assert!(
            security_policy.contains(marker),
            "security-sensitive-parser policy must mention {marker}"
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
        "public-stream-migration",
        "token-slab",
        "visibility-attribute",
        "atp-version-scanner",
        "nkey-codec",
        "proto-codec",
        "typed-symbol-msgpack-codec",
        "config-schema-migration",
        "cli-parser",
        "regex-scanners",
        "parking-lot-wrapper",
        "safe-queue-prototype",
        "cache-padded-experiment",
        "x509-residual-parser",
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
fn review_sensitivity_assignments_are_exact_and_cover_every_row() {
    let taxonomy = taxonomy();
    let expected = expected_sensitivities();
    let rows = array(&taxonomy, "classifications");
    let actual = rows
        .iter()
        .map(|row| {
            (
                string(row, "candidate_id"),
                array(row, "review_sensitivity_tags")
                    .iter()
                    .map(|tag| {
                        tag.as_str()
                            .expect("review sensitivity tag must be a string")
                    })
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual, expected);
    assert_eq!(
        actual.len(),
        rows.len(),
        "every candidate must have one exact sensitivity assignment"
    );
}

#[test]
fn safe_parsers_are_not_misclassified_as_boundary_unsafe() {
    let taxonomy = taxonomy();

    for candidate in [
        "base64-codec",
        "atp-version-scanner",
        "proto-codec",
        "lz4-codec",
        "deflate-codec",
        "x509-residual-parser",
    ] {
        let row = classification_by_id(&taxonomy, candidate);
        assert_eq!(
            string(row, "class_id"),
            "SAFE-OWN",
            "{candidate}: parser sensitivity is not boundary unsafe"
        );
        assert!(
            array(row, "unsafe_techniques").is_empty(),
            "{candidate}: SAFE-OWN parser cannot list unsafe techniques"
        );
        let tags = string_set(row, "review_sensitivity_tags");
        assert!(
            tags.contains("wire-format-parser"),
            "{candidate}: safe parser must retain wire review sensitivity"
        );
    }

    for candidate in [
        "base64-codec",
        "atp-version-scanner",
        "proto-codec",
        "lz4-codec",
        "deflate-codec",
        "x509-residual-parser",
    ] {
        assert!(
            string_set(
                classification_by_id(&taxonomy, candidate),
                "review_sensitivity_tags"
            )
            .contains("security-sensitive-parser"),
            "{candidate}: security-sensitive parser tag must not be dropped"
        );
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
        "review_sensitivity_tags".to_owned(),
        "sensitivity_evidence_requirements".to_owned(),
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
    let review_tag_ids = array(&taxonomy, "review_sensitivity_tags")
        .iter()
        .map(|tag| string(tag, "tag_id").to_owned())
        .collect::<BTreeSet<_>>();

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
            &review_tag_ids,
        ));
    }
    assert!(
        all_errors.is_empty(),
        "classification eligibility errors:\n{}",
        all_errors.join("\n")
    );
}

#[test]
fn missing_review_sensitivity_evidence_fails_closed() {
    let taxonomy = taxonomy();
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
    let review_tag_ids = array(&taxonomy, "review_sensitivity_tags")
        .iter()
        .map(|tag| string(tag, "tag_id").to_owned())
        .collect::<BTreeSet<_>>();

    let mut incomplete = classification_by_id(&taxonomy, "base64-codec").clone();
    incomplete
        .get_mut("sensitivity_evidence_requirements")
        .and_then(Value::as_object_mut)
        .expect("sensitivity evidence fixture must be an object")
        .remove("security-sensitive-parser");
    let errors = classification_errors(
        &incomplete,
        &allowed_eligibility,
        &exception_fields,
        &review_tag_ids,
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("sensitivity evidence keys")),
        "missing review sensitivity evidence must fail closed: {errors:?}"
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
    let review_tag_ids = array(&taxonomy, "review_sensitivity_tags")
        .iter()
        .map(|tag| string(tag, "tag_id").to_owned())
        .collect::<BTreeSet<_>>();
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
    let errors = classification_errors(
        &incomplete,
        &allowed_eligibility,
        &required_fields,
        &review_tag_ids,
    );
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
    let sensitivity_counts = rows.iter().fold(BTreeMap::new(), |mut counts, row| {
        for tag in array(row, "review_sensitivity_tags") {
            *counts
                .entry(
                    tag.as_str()
                        .expect("review sensitivity tag must be a string"),
                )
                .or_insert(0_u64) += 1;
        }
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
    assert_eq!(
        summary
            .get("review_sensitivity_tag_count")
            .and_then(Value::as_u64),
        Some(array(&taxonomy, "review_sensitivity_tags").len() as u64)
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
    for tag in array(&taxonomy, "review_sensitivity_tags") {
        let tag_id = string(tag, "tag_id");
        assert_eq!(
            summary
                .get("classification_counts_by_review_sensitivity_tag")
                .and_then(|value| value.get(tag_id))
                .and_then(Value::as_u64),
            sensitivity_counts.get(tag_id).copied(),
            "summary review-sensitivity count drifted for {tag_id}"
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
            "review_sensitivity_tags".to_owned(),
            "evidence_refs".to_owned(),
            "sensitivity_evidence_refs".to_owned(),
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
    assert_eq!(
        string_set(example, "review_sensitivity_tags"),
        string_set(row, "review_sensitivity_tags")
    );
    nonempty_string_array(example, "evidence_refs");
    nonempty_string_array(example, "explicit_no_claims");
    let sensitivity_evidence = object(example, "sensitivity_evidence_refs");
    assert_eq!(
        sensitivity_evidence
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        string_set(example, "review_sensitivity_tags")
    );
    for refs in sensitivity_evidence.values() {
        assert!(
            refs.as_array().is_some_and(|entries| !entries.is_empty()),
            "citation sensitivity evidence must be nonempty"
        );
    }
}

#[test]
fn docs_publish_the_citation_workflow_and_no_claim_boundary() {
    let docs = read_repo_file(DOC_PATH);
    for section in [
        "Purpose and Scope",
        "Axis A: Implementation Unsafety",
        "Axis B: Review-Sensitivity Tags",
        "The Two Axes Are Not Program Approval",
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
        "ordinary",
        "public-api-redesign",
        "persistent-format",
        "wire-format-parser",
        "security-sensitive-parser",
        "cryptographic-format",
        "concurrency-liveness",
        "platform-boundary",
        "runtime-hot-path",
        "candidate_id",
        "review_sensitivity_tags",
        "evidence_refs",
        "sensitivity_evidence_refs",
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
