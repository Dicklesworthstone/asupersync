//! Differential-oracle governance contract for dependency sovereignty.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.3
//! Scenario: dependency_oracle_policy_contract_v1
//! Fixture: artifacts/dependency_oracle_policy_v1.json

#![allow(missing_docs)]

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.3";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_oracle_policy_v1.json";
const DOC_PATH: &str = "docs/dependency_oracle_policy.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const MANIFEST_PATH: &str = "Cargo.toml";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const SCENARIO_ID: &str = "dependency_oracle_policy_contract_v1";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_oracle_policy\" cargo test -p asupersync --test dependency_oracle_policy_contract -- --nocapture";

const PURE_RUST: &str = "PURE_RUST_IN_WORKSPACE_ORACLE";
const NATIVE: &str = "NATIVE_OR_C_ORACLE";
const REVERSE: &str = "REVERSE_DEPENDENCY_ORACLE";
const SECURITY: &str = "SECURITY_PROTOCOL_ORACLE";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn policy() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .expect("dependency oracle policy must be valid JSON")
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn integer(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a nonnegative integer"))
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

fn profile_ids(policy: &Value) -> BTreeSet<String> {
    array(policy, "profile_definitions")
        .iter()
        .map(|profile| string(profile, "profile_id").to_owned())
        .collect()
}

fn is_iso_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if !(bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit()))
    {
        return false;
    }

    let Ok(year) = date[..4].parse::<u16>() else {
        return false;
    };
    let Ok(month) = date[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = date[8..10].parse::<u8>() else {
        return false;
    };
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

fn class_map(policy: &Value) -> BTreeMap<String, &Value> {
    array(policy, "oracle_classes")
        .iter()
        .map(|class| (string(class, "class_id").to_owned(), class))
        .collect()
}

fn row_by_id<'a>(policy: &'a Value, oracle_id: &str) -> &'a Value {
    array(policy, "oracle_registry")
        .iter()
        .find(|row| string(row, "oracle_id") == oracle_id)
        .unwrap_or_else(|| panic!("missing oracle row {oracle_id}"))
}

fn row_by_id_mut<'a>(policy: &'a mut Value, oracle_id: &str) -> &'a mut Value {
    policy
        .get_mut("oracle_registry")
        .and_then(Value::as_array_mut)
        .expect("oracle_registry must be an array")
        .iter_mut()
        .find(|row| string(row, "oracle_id") == oracle_id)
        .unwrap_or_else(|| panic!("missing mutable oracle row {oracle_id}"))
}

fn set_string(row: &mut Value, key: &str, value: &str) {
    row.as_object_mut()
        .expect("oracle row must be an object")
        .insert(key.to_owned(), Value::String(value.to_owned()));
}

fn set_string_array(row: &mut Value, key: &str, values: &[&str]) {
    row.as_object_mut()
        .expect("oracle row must be an object")
        .insert(
            key.to_owned(),
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::String((*value).to_owned()))
                    .collect(),
            ),
        );
}

fn nonempty_string(value: &Value, key: &str, errors: &mut Vec<String>, oracle_id: &str) {
    if value
        .get(key)
        .and_then(Value::as_str)
        .is_none_or(|text| text.trim().is_empty())
    {
        errors.push(format!("{oracle_id}: {key} must be a nonempty string"));
    }
}

fn validate_extension(row: &Value, errors: &mut Vec<String>, oracle_id: &str) {
    let Some(extension) = row.get("extension_signoff").and_then(Value::as_object) else {
        errors.push(format!("{oracle_id}: extension_signoff must be an object"));
        return;
    };
    let status = extension
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(status, "none" | "approved" | "permanent-keep-approved") {
        errors.push(format!(
            "{oracle_id}: unsupported extension status {status}"
        ));
    }
    if matches!(status, "approved" | "permanent-keep-approved") {
        for key in ["approved_by", "approved_at_utc", "reason"] {
            if extension
                .get(key)
                .and_then(Value::as_str)
                .is_none_or(|text| text.trim().is_empty())
            {
                errors.push(format!("{oracle_id}: approved extension requires {key}"));
            }
        }
        if status == "approved"
            && extension
                .get("new_expiry_release")
                .and_then(Value::as_str)
                .is_none_or(|text| text.trim().is_empty())
        {
            errors.push(format!(
                "{oracle_id}: approved extension requires new_expiry_release"
            ));
        }
        if status == "approved" {
            let new_expiry_release = extension
                .get("new_expiry_release")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if row
                .get("expiry_release")
                .and_then(Value::as_str)
                .is_some_and(|expiry| expiry != new_expiry_release)
            {
                errors.push(format!(
                    "{oracle_id}: approved extension must update expiry_release"
                ));
            }
            let expiry_date = row
                .get("expiry_date_utc")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_iso_date(expiry_date) {
                errors.push(format!(
                    "{oracle_id}: approved extension must update expiry_date_utc"
                ));
            }
        }
    }
}

fn validate_oracle_row(policy: &Value, row: &Value) -> Vec<String> {
    let oracle_id = row
        .get("oracle_id")
        .and_then(Value::as_str)
        .unwrap_or("<missing-oracle-id>");
    let mut errors = Vec::new();

    for field in array(policy, "registry_required_fields") {
        let field = field
            .as_str()
            .expect("registry_required_fields entries must be strings");
        if row.get(field).is_none() {
            errors.push(format!("{oracle_id}: missing required field {field}"));
        }
    }
    if !errors.is_empty() {
        return errors;
    }

    for key in [
        "oracle_id",
        "oracle_class",
        "lifecycle_state",
        "current_graph_state",
        "native_status",
        "unsafe_status",
        "harness_location",
        "fixture_source",
        "fixture_license",
        "introduction_release",
        "expiry_release",
        "retirement_bead",
        "owner",
        "feature_unification_check",
        "cycle_safety",
        "corpus_provenance",
        "secret_redaction",
        "no_claim_boundary",
    ] {
        nonempty_string(row, key, &mut errors, oracle_id);
    }
    for key in [
        "replacement_candidate_ids",
        "replaced_package_ids",
        "allowed_profiles",
        "forbidden_profiles",
    ] {
        let values = string_set(row, key);
        if values.is_empty() {
            errors.push(format!("{oracle_id}: {key} must not be empty"));
        }
        if values.len() != array(row, key).len() {
            errors.push(format!("{oracle_id}: {key} entries must be unique"));
        }
    }

    let classes = class_map(policy);
    let class_id = string(row, "oracle_class");
    let Some(class) = classes.get(class_id).copied() else {
        errors.push(format!("{oracle_id}: unknown oracle class {class_id}"));
        return errors;
    };

    let allowed = string_set(row, "allowed_profiles");
    let forbidden = string_set(row, "forbidden_profiles");
    let known_profiles = profile_ids(policy);
    let unknown_profiles = allowed
        .union(&forbidden)
        .filter(|profile| !known_profiles.contains(*profile))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_profiles.is_empty() {
        errors.push(format!(
            "{oracle_id}: unknown graph profiles: {unknown_profiles:?}"
        ));
    }
    let overlap = allowed
        .intersection(&forbidden)
        .cloned()
        .collect::<Vec<_>>();
    if !overlap.is_empty() {
        errors.push(format!(
            "{oracle_id}: profiles cannot be both allowed and forbidden: {overlap:?}"
        ));
    }
    let class_allowed = string_set(class, "allowed_profiles");
    let class_forbidden = string_set(class, "forbidden_profiles");
    let outside_class = allowed
        .difference(&class_allowed)
        .cloned()
        .collect::<Vec<_>>();
    if !outside_class.is_empty() {
        errors.push(format!(
            "{oracle_id}: profiles not allowed by {class_id}: {outside_class:?}"
        ));
    }
    let required_forbidden_missing = class_forbidden
        .difference(&forbidden)
        .cloned()
        .collect::<Vec<_>>();
    if !required_forbidden_missing.is_empty() {
        errors.push(format!(
            "{oracle_id}: required forbidden profiles missing: {required_forbidden_missing:?}"
        ));
    }

    let max_retention = integer(row, "max_retention_releases");
    if max_retention == 0 || max_retention > integer(class, "max_retention_releases") {
        errors.push(format!(
            "{oracle_id}: retention window {max_retention} exceeds class limit"
        ));
    }

    let lifecycle = string(row, "lifecycle_state");
    match lifecycle {
        "planned" => {
            if string(row, "introduction_release") != "CUTOVER_RELEASE" {
                errors.push(format!(
                    "{oracle_id}: planned oracle introduction must be CUTOVER_RELEASE"
                ));
            }
            if string(row, "expiry_release") != "CUTOVER_RELEASE_PLUS_2_MAX" {
                errors.push(format!(
                    "{oracle_id}: planned oracle expiry must be CUTOVER_RELEASE_PLUS_2_MAX"
                ));
            }
            if row
                .get("expiry_date_utc")
                .is_some_and(|date| !date.is_null())
            {
                errors.push(format!(
                    "{oracle_id}: planned oracle cannot claim a concrete expiry date"
                ));
            }
        }
        "active" => {
            if matches!(
                string(row, "introduction_release"),
                "CUTOVER_RELEASE" | "CUTOVER_RELEASE_PLUS_2_MAX"
            ) || matches!(
                string(row, "expiry_release"),
                "CUTOVER_RELEASE" | "CUTOVER_RELEASE_PLUS_2_MAX"
            ) {
                errors.push(format!(
                    "{oracle_id}: active oracle requires concrete release values"
                ));
            }
            let expiry_date = row
                .get("expiry_date_utc")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_iso_date(expiry_date) {
                errors.push(format!(
                    "{oracle_id}: active oracle requires ISO-8601 expiry_date_utc"
                ));
            } else if expiry_date < string(policy, "policy_as_of_date_utc") {
                let extension_status = object(row, "extension_signoff")
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if extension_status != "approved" {
                    errors.push(format!(
                        "{oracle_id}: active oracle is expired without approved extension"
                    ));
                } else {
                    errors.push(format!(
                        "{oracle_id}: approved extension must update expiry_date_utc"
                    ));
                }
            }
        }
        "retired" => {}
        "permanent_keep" => {
            let extension_status = object(row, "extension_signoff")
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if class_id != SECURITY || extension_status != "permanent-keep-approved" {
                errors.push(format!(
                    "{oracle_id}: permanent_keep requires security class and owner approval"
                ));
            }
        }
        other => errors.push(format!("{oracle_id}: unsupported lifecycle_state {other}")),
    }

    if string(row, "feature_unification_check") == "not-applicable" {
        errors.push(format!(
            "{oracle_id}: feature-unification check may not be skipped"
        ));
    }

    match class_id {
        NATIVE => {
            if !string(row, "harness_location").starts_with("external-harness://") {
                errors.push(format!(
                    "{oracle_id}: native oracle must use an external harness"
                ));
            }
            for profile in [
                "workspace-normal",
                "workspace-dev",
                "workspace-build",
                "workspace-release",
                "workspace-fuzz-quarantine",
            ] {
                if allowed.contains(profile) {
                    errors.push(format!("{oracle_id}: native oracle cannot allow {profile}"));
                }
            }
        }
        REVERSE => {
            if allowed
                .iter()
                .any(|profile| profile.starts_with("workspace-"))
            {
                errors.push(format!(
                    "{oracle_id}: reverse dependency cannot enter a workspace profile"
                ));
            }
            if !string(row, "cycle_safety").contains("must-not-enter-asupersync-workspace") {
                errors.push(format!(
                    "{oracle_id}: reverse dependency must explicitly forbid workspace re-entry"
                ));
            }
        }
        SECURITY => {
            if string(row, "secret_redaction") == "not-applicable"
                || !string(row, "secret_redaction").contains("required")
            {
                errors.push(format!(
                    "{oracle_id}: security oracle requires explicit secret redaction"
                ));
            }
            if string(row, "corpus_provenance").trim().is_empty() {
                errors.push(format!(
                    "{oracle_id}: security oracle requires corpus provenance"
                ));
            }
            if allowed.contains("workspace-dev") {
                errors.push(format!(
                    "{oracle_id}: security oracle must use fuzz or external quarantine, not workspace-dev"
                ));
            }
        }
        PURE_RUST => {}
        _ => {}
    }

    validate_extension(row, &mut errors, oracle_id);
    errors
}

fn expected_oracles() -> BTreeMap<&'static str, &'static str> {
    [
        ("hex-reference", PURE_RUST),
        ("base64-reference", PURE_RUST),
        ("futures-lite-reference", PURE_RUST),
        ("slab-reference", PURE_RUST),
        ("visibility-reference", PURE_RUST),
        ("bincode-next-reference", PURE_RUST),
        ("messagepack-reference", PURE_RUST),
        ("toml-reference", PURE_RUST),
        ("serde-yaml-reference", PURE_RUST),
        ("clap-reference", PURE_RUST),
        ("regex-reference", PURE_RUST),
        ("nkeys-reference", PURE_RUST),
        ("prost-reference", PURE_RUST),
        ("time-chrono-reference", PURE_RUST),
        ("parking-lot-reference", PURE_RUST),
        ("lz4-reference", PURE_RUST),
        ("deflate-reference", PURE_RUST),
        ("sysinfo-reference", PURE_RUST),
        ("x509-parser-security-reference", SECURITY),
        ("otlp-generated-security-reference", SECURITY),
        ("rdkafka-librdkafka-external-reference", NATIVE),
        ("rusqlite-libsqlite-external-reference", NATIVE),
        ("sqlparser-native-exposure-reference", NATIVE),
        ("frankensqlite-reverse-dependency-reference", REVERSE),
    ]
    .into_iter()
    .collect()
}

fn tracker_issue_ids() -> BTreeSet<String> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .expect("tracker lines must remain valid JSON")
                .get("id")
                .and_then(Value::as_str)
                .expect("tracker issue requires id")
                .to_owned()
        })
        .collect()
}

#[test]
fn artifact_metadata_and_profile_catalog_are_stable() {
    let policy = policy();
    assert_eq!(integer(&policy, "schema_version"), 1);
    assert_eq!(
        string(&policy, "artifact_id"),
        "dependency-oracle-policy-v1"
    );
    assert_eq!(string(&policy, "program_id"), PROGRAM_ID);
    assert_eq!(string(&policy, "bead_id"), BEAD_ID);
    assert_eq!(string(&policy, "policy_as_of_release"), "0.3.9");
    assert_eq!(string(&policy, "policy_as_of_date_utc"), "2026-07-24");

    let profiles = array(&policy, "profile_definitions")
        .iter()
        .map(|profile| string(profile, "profile_id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        profiles.len(),
        array(&policy, "profile_definitions").len(),
        "profile IDs must be unique"
    );
    assert_eq!(
        profiles,
        [
            "workspace-normal",
            "workspace-dev",
            "workspace-build",
            "workspace-release",
            "workspace-fuzz-quarantine",
            "external-cargo-harness",
            "downstream-project",
            "neutral-synthesized-consumer",
            "frozen-fixture-only",
        ]
        .into_iter()
        .collect()
    );

    let required_fields = string_set(&policy, "registry_required_fields");
    assert_eq!(
        required_fields.len(),
        array(&policy, "registry_required_fields").len(),
        "required registry fields must be unique"
    );
    assert_eq!(
        required_fields,
        [
            "oracle_id",
            "replacement_candidate_ids",
            "replaced_package_ids",
            "oracle_class",
            "lifecycle_state",
            "current_graph_state",
            "allowed_profiles",
            "forbidden_profiles",
            "native_status",
            "unsafe_status",
            "harness_location",
            "fixture_source",
            "fixture_license",
            "introduction_release",
            "expiry_release",
            "expiry_date_utc",
            "max_retention_releases",
            "retirement_bead",
            "owner",
            "feature_unification_check",
            "cycle_safety",
            "corpus_provenance",
            "secret_redaction",
            "extension_signoff",
            "no_claim_boundary",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn oracle_class_rules_are_exact_and_fail_closed() {
    let policy = policy();
    let classes = class_map(&policy);
    assert_eq!(classes.len(), 4);
    assert_eq!(
        classes.len(),
        array(&policy, "oracle_classes").len(),
        "oracle class IDs must be unique"
    );
    assert_eq!(
        classes.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        [PURE_RUST, NATIVE, REVERSE, SECURITY].into_iter().collect()
    );
    for (class_id, class) in classes {
        assert!(!string(class, "description").trim().is_empty());
        assert_eq!(integer(class, "max_retention_releases"), 2);
        assert!(
            class
                .get("requires_feature_unification_check")
                .and_then(Value::as_bool)
                == Some(true),
            "{class_id} must require feature-unification proof"
        );
        assert!(
            class.get("requires_cycle_check").and_then(Value::as_bool) == Some(true),
            "{class_id} must require cycle proof"
        );
        assert!(
            string_set(class, "allowed_profiles")
                .is_disjoint(&string_set(class, "forbidden_profiles"))
        );
    }
}

#[test]
fn registry_inventory_is_complete_and_unique() {
    let policy = policy();
    let expected = expected_oracles();
    assert_eq!(
        array(&policy, "oracle_registry").len(),
        expected.len(),
        "oracle IDs must be unique and the inventory must be exact"
    );
    let actual = array(&policy, "oracle_registry")
        .iter()
        .map(|row| (string(row, "oracle_id"), string(row, "oracle_class")))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual, expected);

    let packages = array(&policy, "oracle_registry")
        .iter()
        .flat_map(|row| string_set(row, "replaced_package_ids"))
        .collect::<BTreeSet<_>>();
    for required in [
        "nkeys",
        "prost",
        "bincode-next",
        "rmp-serde",
        "regex",
        "hex",
        "base64",
        "time",
        "chrono",
        "rdkafka",
        "rusqlite",
        "sqlparser",
        "x509-parser",
        "frankensqlite",
    ] {
        assert!(
            packages.contains(required),
            "required oracle package {required} is missing"
        );
    }
}

#[test]
fn every_registry_row_satisfies_policy() {
    let policy = policy();
    let errors = array(&policy, "oracle_registry")
        .iter()
        .flat_map(|row| validate_oracle_row(&policy, row))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "oracle policy errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn retirement_beads_and_aggregate_owners_exist_in_tracker() {
    let policy = policy();
    let ids = tracker_issue_ids();
    for row in array(&policy, "oracle_registry") {
        let bead = string(row, "retirement_bead");
        assert!(ids.contains(bead), "retirement bead {bead} does not exist");
        assert_eq!(string(row, "owner"), format!("bead:{bead}"));
    }
    let validation = object(&policy, "validation");
    for key in ["aggregate_e2e_owner", "aggregate_signoff_owner"] {
        let bead = validation
            .get(key)
            .and_then(Value::as_str)
            .expect("aggregate owner must be a bead id");
        assert!(ids.contains(bead), "{key} bead {bead} does not exist");
    }
}

#[test]
fn current_native_incumbents_are_explicit_and_not_dev_dependencies() {
    let policy = policy();
    let manifest: toml::Value =
        toml::from_str(&read_repo_file(MANIFEST_PATH)).expect("Cargo.toml must parse");
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("dependencies table must exist");
    let dev_dependencies = manifest
        .get("dev-dependencies")
        .and_then(toml::Value::as_table)
        .expect("dev-dependencies table must exist");

    for package in ["rdkafka", "rusqlite", "sqlparser"] {
        assert!(
            dependencies.contains_key(package),
            "{package} remains an incumbent until conditional cutover"
        );
        assert!(
            !dev_dependencies.contains_key(package),
            "{package} must not be retained as an ordinary dev oracle"
        );
    }
    for oracle_id in [
        "rdkafka-librdkafka-external-reference",
        "rusqlite-libsqlite-external-reference",
        "sqlparser-native-exposure-reference",
    ] {
        let row = row_by_id(&policy, oracle_id);
        assert_eq!(string(row, "lifecycle_state"), "planned");
        assert!(
            string(row, "current_graph_state").contains("incumbent-optional-production-edge"),
            "{oracle_id} must not falsely claim the incumbent edge is already gone"
        );
        assert_eq!(
            string_set(row, "allowed_profiles"),
            ["external-cargo-harness", "frozen-fixture-only"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }
}

#[test]
fn frankensqlite_reverse_cycle_is_absent_from_workspace_manifest() {
    let policy = policy();
    let manifest = read_repo_file(MANIFEST_PATH);
    let row = row_by_id(&policy, "frankensqlite-reverse-dependency-reference");
    assert_eq!(string(row, "oracle_class"), REVERSE);
    assert!(
        !manifest.to_ascii_lowercase().contains("frankensqlite"),
        "FrankenSQLite must not be added to the asupersync workspace manifest"
    );
    assert!(string(row, "cycle_safety").contains("must-not-enter-asupersync-workspace"));
}

#[test]
fn pure_rust_rows_use_bounded_symbolic_planned_retention() {
    let policy = policy();
    for row in array(&policy, "oracle_registry")
        .iter()
        .filter(|row| string(row, "oracle_class") == PURE_RUST)
    {
        assert_eq!(string(row, "lifecycle_state"), "planned");
        assert_eq!(string(row, "introduction_release"), "CUTOVER_RELEASE");
        assert_eq!(string(row, "expiry_release"), "CUTOVER_RELEASE_PLUS_2_MAX");
        assert_eq!(integer(row, "max_retention_releases"), 2);
        assert_ne!(string(row, "feature_unification_check"), "not-applicable");
    }
}

#[test]
fn security_rows_require_quarantine_provenance_and_redaction() {
    let policy = policy();
    for row in array(&policy, "oracle_registry")
        .iter()
        .filter(|row| string(row, "oracle_class") == SECURITY)
    {
        assert!(!string_set(row, "allowed_profiles").contains("workspace-dev"));
        assert!(string(row, "secret_redaction").contains("required"));
        assert!(!string(row, "corpus_provenance").trim().is_empty());
    }
}

#[test]
fn summary_counts_match_registry() {
    let policy = policy();
    let summary_value = policy.get("summary").expect("summary must exist");
    let registry = array(&policy, "oracle_registry");
    assert_eq!(
        integer(summary_value, "oracle_count") as usize,
        registry.len()
    );

    let actual_counts = registry.iter().fold(BTreeMap::new(), |mut counts, row| {
        *counts
            .entry(string(row, "oracle_class").to_owned())
            .or_insert(0_u64) += 1;
        counts
    });
    let summary_counts = object(summary_value, "counts_by_class")
        .iter()
        .map(|(class, count)| {
            (
                class.to_owned(),
                count.as_u64().expect("summary class count must be integer"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual_counts, summary_counts);
    assert_eq!(
        integer(
            summary_value,
            "native_or_reverse_allowed_in_ordinary_workspace_profiles"
        ),
        0
    );
}

#[test]
fn validation_packet_and_operator_docs_name_exact_evidence_scope() {
    let policy = policy();
    let validation = object(&policy, "validation");
    assert_eq!(
        validation.get("scenario_id").and_then(Value::as_str),
        Some(SCENARIO_ID)
    );
    assert_eq!(
        validation.get("artifact_path").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(
        validation.get("proof_command").and_then(Value::as_str),
        Some(PROOF_COMMAND)
    );
    assert_eq!(
        validation
            .get("aggregate_e2e_owner")
            .and_then(Value::as_str),
        Some("asupersync-dep-p1-foundations-upksjk.6.2")
    );
    assert_eq!(
        string_set(
            policy
                .get("validation")
                .expect("validation packet must exist"),
            "required_negative_fixtures"
        ),
        [
            "missing-retirement-disposition",
            "native-oracle-in-workspace-dev",
            "reverse-dependency-in-workspace-dev",
            "expired-active-oracle-without-extension",
            "approved-extension-with-stale-expiry",
            "security-oracle-without-redaction",
            "pure-rust-oracle-without-feature-unification-check",
            "allowed-and-forbidden-profile-overlap",
            "unknown-graph-profile",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        BEAD_ID,
        ARTIFACT_PATH,
        "Current incumbent is not retained oracle",
        PURE_RUST,
        NATIVE,
        REVERSE,
        SECURITY,
        "CUTOVER_RELEASE_PLUS_2_MAX",
        "asupersync-dep-p1-foundations-upksjk.6.2",
        PROOF_COMMAND,
        "No-claim boundaries",
    ] {
        assert!(
            docs.contains(marker),
            "operator docs missing marker: {marker}"
        );
    }
}

#[test]
fn negative_fixture_missing_retirement_disposition_fails() {
    let mut policy = policy();
    set_string(
        row_by_id_mut(&mut policy, "hex-reference"),
        "retirement_bead",
        "",
    );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "hex-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("retirement_bead must be a nonempty string"))
    );
}

#[test]
fn negative_fixture_native_oracle_in_workspace_dev_fails() {
    let mut policy = policy();
    set_string_array(
        row_by_id_mut(&mut policy, "rdkafka-librdkafka-external-reference"),
        "allowed_profiles",
        &["workspace-dev", "external-cargo-harness"],
    );
    let row = row_by_id(&policy, "rdkafka-librdkafka-external-reference");
    let errors = validate_oracle_row(&policy, row);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("native oracle cannot allow workspace-dev"))
    );
}

#[test]
fn negative_fixture_reverse_dependency_in_workspace_dev_fails() {
    let mut policy = policy();
    set_string_array(
        row_by_id_mut(&mut policy, "frankensqlite-reverse-dependency-reference"),
        "allowed_profiles",
        &["workspace-dev", "neutral-synthesized-consumer"],
    );
    let row = row_by_id(&policy, "frankensqlite-reverse-dependency-reference");
    let errors = validate_oracle_row(&policy, row);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("reverse dependency cannot enter a workspace profile"))
    );
}

#[test]
fn negative_fixture_expired_active_oracle_without_extension_fails() {
    let mut policy = policy();
    let row = row_by_id_mut(&mut policy, "hex-reference");
    set_string(row, "lifecycle_state", "active");
    set_string(row, "introduction_release", "0.3.7");
    set_string(row, "expiry_release", "0.3.8");
    row.as_object_mut()
        .expect("oracle row must be object")
        .insert(
            "expiry_date_utc".to_owned(),
            Value::String("2026-07-23".to_owned()),
        );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "hex-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("expired without approved extension"))
    );
}

#[test]
fn approved_extension_requires_complete_owner_receipt() {
    let mut policy = policy();
    let row = row_by_id_mut(&mut policy, "hex-reference");
    let extension = row
        .get_mut("extension_signoff")
        .and_then(Value::as_object_mut)
        .expect("extension_signoff must be object");
    extension.insert("status".to_owned(), Value::String("approved".to_owned()));
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "hex-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("approved extension requires approved_by"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("approved extension requires new_expiry_release"))
    );
}

#[test]
fn negative_fixture_approved_extension_must_advance_expiry_fields() {
    let mut policy = policy();
    let row = row_by_id_mut(&mut policy, "hex-reference");
    set_string(row, "lifecycle_state", "active");
    set_string(row, "introduction_release", "0.3.7");
    set_string(row, "expiry_release", "0.3.8");
    row.as_object_mut()
        .expect("oracle row must be object")
        .insert(
            "expiry_date_utc".to_owned(),
            Value::String("2026-07-23".to_owned()),
        );
    let extension = row
        .get_mut("extension_signoff")
        .and_then(Value::as_object_mut)
        .expect("extension_signoff must be object");
    extension.insert("status".to_owned(), Value::String("approved".to_owned()));
    extension.insert(
        "approved_by".to_owned(),
        Value::String("dependency-sovereignty-owner".to_owned()),
    );
    extension.insert(
        "approved_at_utc".to_owned(),
        Value::String("2026-07-24T07:00:00Z".to_owned()),
    );
    extension.insert(
        "new_expiry_release".to_owned(),
        Value::String("0.3.10".to_owned()),
    );
    extension.insert(
        "reason".to_owned(),
        Value::String("Independent-vector corpus is not complete.".to_owned()),
    );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "hex-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("approved extension must update expiry_release"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("approved extension must update expiry_date_utc")),
        "an approval must not legitimize an unchanged expired date"
    );
}

#[test]
fn negative_fixture_security_oracle_without_redaction_fails() {
    let mut policy = policy();
    set_string(
        row_by_id_mut(&mut policy, "x509-parser-security-reference"),
        "secret_redaction",
        "not-applicable",
    );
    let row = row_by_id(&policy, "x509-parser-security-reference");
    let errors = validate_oracle_row(&policy, row);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("security oracle requires explicit secret redaction"))
    );
}

#[test]
fn negative_fixture_missing_feature_unification_check_fails() {
    let mut policy = policy();
    set_string(
        row_by_id_mut(&mut policy, "prost-reference"),
        "feature_unification_check",
        "not-applicable",
    );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "prost-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("feature-unification check may not be skipped"))
    );
}

#[test]
fn negative_fixture_allowed_and_forbidden_overlap_fails() {
    let mut policy = policy();
    set_string_array(
        row_by_id_mut(&mut policy, "base64-reference"),
        "allowed_profiles",
        &["workspace-dev", "workspace-normal"],
    );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "base64-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("both allowed and forbidden"))
    );
}

#[test]
fn negative_fixture_unknown_profile_fails() {
    let mut policy = policy();
    set_string_array(
        row_by_id_mut(&mut policy, "base64-reference"),
        "allowed_profiles",
        &["workspace-dev", "mystery-profile"],
    );
    let errors = validate_oracle_row(&policy, row_by_id(&policy, "base64-reference"));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown graph profiles"))
    );
}

#[test]
fn taxonomy_candidates_referenced_by_registry_are_known_or_campaign_scoped() {
    let policy = policy();
    let taxonomy: Value = serde_json::from_str(&read_repo_file(TAXONOMY_PATH))
        .expect("dependency safety taxonomy must be valid JSON");
    let known_candidates = array(&taxonomy, "classifications")
        .iter()
        .map(|row| string(row, "candidate_id"))
        .chain(["kafka-native-client", "sqlite-cycle-safe-integration"])
        .collect::<BTreeSet<_>>();
    for row in array(&policy, "oracle_registry") {
        for candidate in array(row, "replacement_candidate_ids") {
            let candidate = candidate
                .as_str()
                .expect("replacement candidate must be a string");
            assert!(
                known_candidates.contains(candidate),
                "unknown replacement candidate {candidate}"
            );
        }
    }
}
