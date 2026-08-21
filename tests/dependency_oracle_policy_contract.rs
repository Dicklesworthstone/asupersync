//! Differential-oracle governance contract for dependency sovereignty.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.3
//! Scenario: dependency_oracle_policy_contract_v1
//! Fixture: artifacts/dependency_oracle_policy_v1.json

#![allow(missing_docs)]

use chrono::{NaiveDate, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.3";
const RECONCILIATION_BEAD_ID: &str = "asupersync-mnotoo.4.1";
const RETIREMENT_SWEEP_BEAD_ID: &str = "asupersync-mnotoo.4.3";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_oracle_policy_v1.json";
const DOC_PATH: &str = "docs/dependency_oracle_policy.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const MANIFEST_PATH: &str = "Cargo.toml";
const LOCK_PATH: &str = "Cargo.lock";
const NIGHTLY_WORKFLOW_PATH: &str = ".github/workflows/nightly-differential-stress.yml";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const SCENARIO_ID: &str = "dependency_oracle_policy_contract_v1";
const RECONCILIATION_CONTRACT_ID: &str = "dependency-oracle-manifest-reconciliation-v1";
const ORACLE_EXPIRY_CRON: &str = "0 4 * * *";
const ORACLE_EXPIRY_COMMAND: &str =
    "cargo test -p asupersync --test dependency_oracle_policy_contract -- --nocapture";
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

fn reconciliation(policy: &Value) -> &Value {
    policy
        .get("manifest_reconciliation")
        .expect("manifest_reconciliation must exist")
}

fn retirement_sweep(policy: &Value) -> &Value {
    reconciliation(policy)
        .get("retirement_sweep")
        .expect("retirement_sweep must exist")
}

fn active_registry(policy: &Value) -> &[Value] {
    array(reconciliation(policy), "active_oracle_registry")
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn object_object<'a>(value: &'a Map<String, Value>, key: &str) -> &'a Map<String, Value> {
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

fn object_string<'a>(value: &'a Map<String, Value>, key: &str) -> &'a str {
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

fn object_integer(value: &Map<String, Value>, key: &str) -> u64 {
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

fn object_string_set(value: &Map<String, Value>, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn line_count(bytes: &[u8]) -> usize {
    std::str::from_utf8(bytes)
        .expect("pinned manifest source is UTF-8")
        .lines()
        .count()
}

fn active_row_by_id<'a>(policy: &'a Value, oracle_id: &str) -> &'a Value {
    active_registry(policy)
        .iter()
        .find(|row| string(row, "oracle_id") == oracle_id)
        .unwrap_or_else(|| panic!("missing active oracle row {oracle_id}"))
}

fn active_row_by_id_mut<'a>(policy: &'a mut Value, oracle_id: &str) -> &'a mut Value {
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("active_oracle_registry"))
        .and_then(Value::as_array_mut)
        .expect("active_oracle_registry must be an array")
        .iter_mut()
        .find(|row| string(row, "oracle_id") == oracle_id)
        .unwrap_or_else(|| panic!("missing mutable active oracle row {oracle_id}"))
}

fn expected_active_oracle_edges() -> BTreeSet<String> {
    [
        "Cargo.toml::dev-dependencies::httparse",
        "Cargo.toml::dev-dependencies::opentelemetry-proto",
        "Cargo.toml::dev-dependencies::opentelemetry_sdk",
        "Cargo.toml::dev-dependencies::raptorq",
        "Cargo.toml::dev-dependencies::redis",
        "Cargo.toml::dev-dependencies::sqlx",
        "Cargo.toml::dev-dependencies::tokio",
        "Cargo.toml::dev-dependencies::tokio-util",
        "conformance/Cargo.toml::dependencies::h2",
        "conformance/Cargo.toml::dependencies::opentelemetry-proto",
        "conformance/Cargo.toml::dependencies::opentelemetry_sdk",
        "conformance/Cargo.toml::dependencies::prometheus-client",
        "conformance/Cargo.toml::dev-dependencies::h2",
        "conformance/Cargo.toml::dev-dependencies::opentelemetry-proto",
        "fuzz/conformance/Cargo.toml::dependencies::h2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn expected_manifest_source_pins() -> BTreeSet<String> {
    [
        "Cargo.lock",
        "Cargo.toml",
        "asupersync-browser-core/Cargo.toml",
        "asupersync-macros/Cargo.toml",
        "asupersync-tokio-compat/Cargo.toml",
        "asupersync-wasm/Cargo.toml",
        "conformance/Cargo.toml",
        "drop_unwrap_finder/Cargo.toml",
        "franken_decision/Cargo.toml",
        "franken_evidence/Cargo.toml",
        "franken_kernel/Cargo.toml",
        "frankenlab/Cargo.toml",
        "fuzz/Cargo.toml",
        "fuzz/conformance/Cargo.toml",
        "tests/conformance/grpc_connect/Cargo.toml",
        "tests/conformance/raptorq_differential/Cargo.toml",
        "tests/conformance/raptorq_rfc6330/differential/Cargo.toml",
        "tests/conformance/raptorq_rfc6330/golden/Cargo.toml",
        "tests/conformance/raptorq_rfc6330/reporting/Cargo.toml",
    ]
    .into_iter()
    .map(str::to_owned)
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

fn parse_release_triplet(release: &str) -> Option<(u64, u64, u64)> {
    let mut components = release.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    (components.next().is_none()).then_some((major, minor, patch))
}

fn release_is_due(current: &str, expiry: &str) -> bool {
    match (
        parse_release_triplet(current),
        parse_release_triplet(expiry),
    ) {
        (Some(current), Some(expiry)) => current >= expiry,
        _ => true,
    }
}

fn current_package_release() -> String {
    let manifest: toml::Value =
        toml::from_str(&read_repo_file(MANIFEST_PATH)).expect("Cargo.toml must parse");
    manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .expect("root package.version must exist")
        .to_owned()
}

fn current_utc_date() -> String {
    Utc::now().date_naive().format("%Y-%m-%d").to_string()
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

fn nonempty_object_string(
    value: &Map<String, Value>,
    key: &str,
    errors: &mut Vec<String>,
    oracle_id: &str,
) {
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

fn manifest_dependency(manifest_path: &str, section: &str, alias: &str) -> Option<toml::Value> {
    let manifest: toml::Value = toml::from_str(&read_repo_file(manifest_path))
        .unwrap_or_else(|error| panic!("{manifest_path} must parse as TOML: {error}"));
    manifest
        .get(section)
        .and_then(toml::Value::as_table)
        .and_then(|dependencies| dependencies.get(alias))
        .cloned()
}

fn dependency_version(value: &toml::Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .as_table()
            .and_then(|table| table.get("version"))
            .and_then(toml::Value::as_str)
    })
}

fn dependency_features(value: &toml::Value) -> BTreeSet<String> {
    value
        .as_table()
        .and_then(|table| table.get("features"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .map(|feature| {
            feature
                .as_str()
                .expect("dependency features must be strings")
                .to_owned()
        })
        .collect()
}

fn dependency_default_features(value: &toml::Value) -> bool {
    value
        .as_table()
        .and_then(|table| table.get("default-features"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
}

fn locked_package(package_name: &str, resolved_version: &str) -> Option<toml::Value> {
    let lock: toml::Value =
        toml::from_str(&read_repo_file(LOCK_PATH)).expect("Cargo.lock must parse as TOML");
    lock.get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .find(|package| {
            package
                .get("name")
                .and_then(toml::Value::as_str)
                .is_some_and(|name| name == package_name)
                && package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|version| version == resolved_version)
        })
        .cloned()
}

fn validate_active_oracle_row(policy: &Value, row: &Value) -> Vec<String> {
    let reconciliation = reconciliation(policy);
    let oracle_id = row
        .get("oracle_id")
        .and_then(Value::as_str)
        .unwrap_or("<missing-active-oracle-id>");
    let mut errors = Vec::new();

    for field in array(reconciliation, "active_registry_required_fields") {
        let field = field
            .as_str()
            .expect("active registry required fields must be strings");
        if row.get(field).is_none() {
            errors.push(format!(
                "{oracle_id}: missing required active field {field}"
            ));
        }
    }
    if !errors.is_empty() {
        return errors;
    }

    for key in [
        "oracle_id",
        "package_name",
        "package_id",
        "resolved_version",
        "lock_source",
        "lock_checksum",
        "oracle_class",
        "lifecycle_state",
        "graph_class",
        "owner",
        "removal_bead",
        "no_claim_boundary",
    ] {
        nonempty_string(row, key, &mut errors, oracle_id);
    }

    if string(row, "lifecycle_state") != "active" {
        errors.push(format!("{oracle_id}: manifest oracle must be active"));
    }
    if string(row, "graph_class") != "dev" {
        errors.push(format!(
            "{oracle_id}: active oracle edge must be classed as dev"
        ));
    }
    if !matches!(string(row, "oracle_class"), PURE_RUST | SECURITY) {
        errors.push(format!(
            "{oracle_id}: active workspace oracle must be pure-Rust or security protocol"
        ));
    }
    if !string(row, "owner").starts_with("bead:") {
        errors.push(format!("{oracle_id}: owner must be a bead authority"));
    }
    if string_set(row, "requested_versions").is_empty() {
        errors.push(format!("{oracle_id}: requested_versions must not be empty"));
    }

    let expected_package_id = format!(
        "{}#{}@{}",
        string(row, "lock_source"),
        string(row, "package_name"),
        string(row, "resolved_version")
    );
    if string(row, "package_id") != expected_package_id {
        errors.push(format!(
            "{oracle_id}: package_id does not match lock source, name and version"
        ));
    }

    match locked_package(string(row, "package_name"), string(row, "resolved_version")) {
        Some(package) => {
            if package
                .get("source")
                .and_then(toml::Value::as_str)
                .is_none_or(|source| source != string(row, "lock_source"))
            {
                errors.push(format!("{oracle_id}: lock source mismatch"));
            }
            if package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .is_none_or(|checksum| checksum != string(row, "lock_checksum"))
            {
                errors.push(format!("{oracle_id}: lock checksum mismatch"));
            }
        }
        None => errors.push(format!(
            "{oracle_id}: resolved package is absent from Cargo.lock"
        )),
    }

    let manifest_edges = array(row, "manifest_edges");
    if manifest_edges.is_empty() {
        errors.push(format!("{oracle_id}: manifest_edges must not be empty"));
    }
    let mut edge_ids = BTreeSet::new();
    for edge in manifest_edges {
        for key in [
            "edge_id",
            "manifest_path",
            "section",
            "alias",
            "requested_version",
            "status",
        ] {
            nonempty_string(edge, key, &mut errors, oracle_id);
        }
        let edge_id = string(edge, "edge_id");
        if !edge_ids.insert(edge_id) {
            errors.push(format!("{oracle_id}: duplicate manifest edge {edge_id}"));
        }
        let expected_edge_id = format!(
            "{}::{}::{}",
            string(edge, "manifest_path"),
            string(edge, "section"),
            string(edge, "alias")
        );
        if edge_id != expected_edge_id {
            errors.push(format!("{oracle_id}: malformed manifest edge ID {edge_id}"));
        }
        let Some(dependency) = manifest_dependency(
            string(edge, "manifest_path"),
            string(edge, "section"),
            string(edge, "alias"),
        ) else {
            errors.push(format!(
                "{oracle_id}: registered manifest edge {edge_id} does not exist"
            ));
            continue;
        };
        if dependency_version(&dependency) != Some(string(edge, "requested_version")) {
            errors.push(format!("{oracle_id}: requested version drift at {edge_id}"));
        }
        if dependency_features(&dependency) != string_set(edge, "features") {
            errors.push(format!("{oracle_id}: feature drift at {edge_id}"));
        }
        if dependency_default_features(&dependency)
            != edge
                .get("default_features")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        {
            errors.push(format!("{oracle_id}: default-feature drift at {edge_id}"));
        }
        if !string_set(row, "requested_versions").contains(string(edge, "requested_version")) {
            errors.push(format!(
                "{oracle_id}: edge requested version missing from row catalog"
            ));
        }
    }

    let test_scope = object(row, "test_scope");
    nonempty_object_string(test_scope, "status", &mut errors, oracle_id);
    let source_paths = object_string_set(test_scope, "source_paths");
    if source_paths.is_empty() {
        errors.push(format!(
            "{oracle_id}: test scope source_paths must not be empty"
        ));
    }
    for path in &source_paths {
        if path.contains('*') || !repo_root().join(path).is_file() {
            errors.push(format!(
                "{oracle_id}: test scope path must be exact and exist: {path}"
            ));
        }
    }
    let proof_commands = object_string_set(test_scope, "proof_commands");
    if proof_commands.is_empty()
        || proof_commands
            .iter()
            .any(|command| !command.starts_with("cargo test "))
    {
        errors.push(format!(
            "{oracle_id}: test scope requires exact cargo test proof commands"
        ));
    }

    let exclusion = object(row, "production_exclusion_proof");
    for key in ["status", "expected", "no_claim"] {
        nonempty_object_string(exclusion, key, &mut errors, oracle_id);
    }
    let exclusion_commands = object_string_set(exclusion, "commands");
    if exclusion_commands.is_empty()
        || exclusion_commands
            .iter()
            .any(|command| !command.starts_with("cargo tree "))
    {
        errors.push(format!(
            "{oracle_id}: production exclusion requires exact cargo tree commands"
        ));
    }

    let introduction = object(row, "introduction");
    for key in ["revision", "date_utc", "evidence"] {
        nonempty_object_string(introduction, key, &mut errors, oracle_id);
    }
    let revision = object_string(introduction, "revision");
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        errors.push(format!(
            "{oracle_id}: introduction revision must be a full Git object ID"
        ));
    }
    if !is_iso_date(object_string(introduction, "date_utc")) {
        errors.push(format!("{oracle_id}: introduction date must be ISO-8601"));
    }

    let expiry = object(row, "expiry");
    for key in ["release", "date_utc", "status"] {
        nonempty_object_string(expiry, key, &mut errors, oracle_id);
    }
    let expiry_date = object_string(expiry, "date_utc");
    if !is_iso_date(expiry_date) {
        errors.push(format!("{oracle_id}: expiry date must be ISO-8601"));
    } else if expiry_date < string(reconciliation, "as_of_date_utc") {
        errors.push(format!("{oracle_id}: active manifest oracle is expired"));
    }
    let expiry_release = object_string(expiry, "release");
    if parse_release_triplet(expiry_release).is_none()
        || parse_release_triplet(string(reconciliation, "as_of_release")).is_none()
    {
        errors.push(format!(
            "{oracle_id}: active expiry release must use numeric major.minor.patch"
        ));
    } else if release_is_due(string(reconciliation, "as_of_release"), expiry_release) {
        errors.push(format!(
            "{oracle_id}: active manifest oracle reached release expiry"
        ));
    }
    if object_integer(expiry, "max_retention_releases") == 0
        || object_integer(expiry, "max_retention_releases") > 2
    {
        errors.push(format!(
            "{oracle_id}: active retention exceeds two releases"
        ));
    }

    let corpus = object(row, "independent_corpus");
    for key in ["status", "provenance"] {
        nonempty_object_string(corpus, key, &mut errors, oracle_id);
    }
    let corpus_paths = object_string_set(corpus, "paths");
    if corpus_paths.is_empty() {
        errors.push(format!(
            "{oracle_id}: independent corpus paths must not be empty"
        ));
    }
    for path in &corpus_paths {
        if path.contains('*') || !repo_root().join(path).is_file() {
            errors.push(format!(
                "{oracle_id}: independent corpus path must be exact and exist: {path}"
            ));
        }
    }

    let renewal = object(row, "renewal");
    nonempty_object_string(renewal, "authority", &mut errors, oracle_id);
    if !object_string(renewal, "authority").starts_with("bead:")
        || object_string_set(renewal, "required_receipts").is_empty()
    {
        errors.push(format!(
            "{oracle_id}: renewal requires bead authority and receipts"
        ));
    }

    errors
}

fn validate_active_expiry_at(
    row: &Value,
    current_release: &str,
    current_date: &str,
) -> Vec<String> {
    let oracle_id = string(row, "oracle_id");
    let expiry = object(row, "expiry");
    let expiry_release = object_string(expiry, "release");
    let expiry_date = object_string(expiry, "date_utc");
    let mut errors = Vec::new();

    if parse_release_triplet(current_release).is_none()
        || parse_release_triplet(expiry_release).is_none()
    {
        errors.push(format!(
            "{oracle_id}: live release expiry requires numeric major.minor.patch values"
        ));
    } else if release_is_due(current_release, expiry_release) {
        errors.push(format!(
            "{oracle_id}: active oracle reached release expiry {expiry_release} at {current_release}"
        ));
    }

    match (
        NaiveDate::parse_from_str(current_date, "%Y-%m-%d"),
        NaiveDate::parse_from_str(expiry_date, "%Y-%m-%d"),
    ) {
        (Ok(current), Ok(expiry)) if current >= expiry => errors.push(format!(
            "{oracle_id}: active oracle reached UTC date expiry {expiry_date} at {current_date}"
        )),
        (Ok(_), Ok(_)) => {}
        _ => errors.push(format!(
            "{oracle_id}: live date expiry requires valid ISO-8601 calendar dates"
        )),
    }

    errors
}

fn validate_retirement_sweep(policy: &Value) -> Vec<String> {
    let reconciliation = reconciliation(policy);
    let sweep = retirement_sweep(policy);
    let mut errors = Vec::new();

    for key in [
        "schema_version",
        "bead_id",
        "capability_id",
        "as_of_release",
        "as_of_date_utc",
        "decision_policy",
        "profile_remeasurement_status",
    ] {
        nonempty_string(sweep, key, &mut errors, "retirement-sweep");
    }
    if string(sweep, "schema_version") != "dependency-oracle-retirement-sweep-v1" {
        errors.push("retirement sweep schema drifted".to_owned());
    }
    if string(sweep, "bead_id") != RETIREMENT_SWEEP_BEAD_ID {
        errors.push("retirement sweep bead authority drifted".to_owned());
    }
    if string(sweep, "capability_id") != "CAP-VERIFICATION-PROFILES" {
        errors.push("retirement sweep capability drifted".to_owned());
    }
    if string(sweep, "as_of_release") != string(reconciliation, "as_of_release")
        || string(sweep, "as_of_date_utc") != string(reconciliation, "as_of_date_utc")
    {
        errors.push("retirement sweep freshness must match manifest reconciliation".to_owned());
    }

    let approval = object(sweep, "owner_approval");
    for key in ["status", "authority", "basis"] {
        nonempty_object_string(approval, key, &mut errors, "retirement-sweep");
    }
    if object_string(approval, "status") != "approved"
        || object_string(approval, "authority") != "bead:asupersync-mnotoo.4"
    {
        errors.push("retirement sweep requires approved parent-bead authority".to_owned());
    }

    let active_ids = active_registry(policy)
        .iter()
        .map(|row| string(row, "oracle_id").to_owned())
        .collect::<BTreeSet<_>>();
    let decisions = array(sweep, "decisions");
    let decision_ids = decisions
        .iter()
        .map(|decision| string(decision, "oracle_id").to_owned())
        .collect::<BTreeSet<_>>();
    if decisions.len() != decision_ids.len() {
        errors.push("retirement sweep oracle decisions must be unique".to_owned());
    }
    if decision_ids != active_ids {
        errors
            .push("every active oracle requires exactly one retirement sweep decision".to_owned());
    }

    let active_by_id = active_registry(policy)
        .iter()
        .map(|row| (string(row, "oracle_id"), row))
        .collect::<BTreeMap<_, _>>();
    let mut renewed_count = 0_u64;
    let mut retired_count = 0_u64;
    let mut pending_count = 0_u64;
    for decision in decisions {
        let oracle_id = string(decision, "oracle_id");
        for key in [
            "disposition",
            "reviewed_release",
            "reviewed_date_utc",
            "previous_expiry_release",
            "previous_expiry_date_utc",
            "new_expiry_release",
            "new_expiry_date_utc",
            "approved_by",
            "production_exclusion_status",
            "next_action",
        ] {
            nonempty_string(decision, key, &mut errors, oracle_id);
        }
        let disposition = string(decision, "disposition");
        match disposition {
            "renewed" => renewed_count += 1,
            "retired" => retired_count += 1,
            _ => pending_count += 1,
        }
        let Some(row) = active_by_id.get(oracle_id).copied() else {
            continue;
        };
        if disposition != "renewed" {
            errors.push(format!(
                "{oracle_id}: an active registry row must have a renewed sweep disposition"
            ));
        }
        if string(decision, "approved_by") != object_string(object(row, "renewal"), "authority") {
            errors.push(format!(
                "{oracle_id}: renewal approval must come from the registered authority"
            ));
        }
        if string(decision, "reviewed_release") != string(sweep, "as_of_release")
            || string(decision, "reviewed_date_utc") != string(sweep, "as_of_date_utc")
        {
            errors.push(format!(
                "{oracle_id}: decision freshness must match the retirement sweep"
            ));
        }
        let missing_evidence = string_set(decision, "missing_evidence");
        let retained_invariants = string_set(decision, "retained_invariants");
        if missing_evidence.is_empty() || retained_invariants.is_empty() {
            errors.push(format!(
                "{oracle_id}: renewal requires concrete missing evidence and retained invariants"
            ));
        }

        let expiry = object(row, "expiry");
        if object_string(expiry, "status") != "renewed"
            || object_string(expiry, "release") != string(decision, "new_expiry_release")
            || object_string(expiry, "date_utc") != string(decision, "new_expiry_date_utc")
        {
            errors.push(format!(
                "{oracle_id}: active expiry must match the approved renewal decision"
            ));
        }
        let previous_date_due = match (
            NaiveDate::parse_from_str(string(decision, "reviewed_date_utc"), "%Y-%m-%d"),
            NaiveDate::parse_from_str(string(decision, "previous_expiry_date_utc"), "%Y-%m-%d"),
        ) {
            (Ok(reviewed), Ok(previous)) => reviewed >= previous,
            _ => {
                errors.push(format!(
                    "{oracle_id}: prior expiry requires valid ISO-8601 calendar dates"
                ));
                false
            }
        };
        let previous_release_due = release_is_due(
            string(decision, "reviewed_release"),
            string(decision, "previous_expiry_release"),
        );
        if !previous_release_due && !previous_date_due {
            errors.push(format!(
                "{oracle_id}: renewal must record a prior expiry due by release or UTC date"
            ));
        }
        match (
            parse_release_triplet(string(decision, "reviewed_release")),
            parse_release_triplet(string(decision, "new_expiry_release")),
        ) {
            (
                Some((review_major, review_minor, review_patch)),
                Some((new_major, new_minor, new_patch)),
            ) if review_major == new_major
                && review_minor == new_minor
                && new_patch > review_patch
                && new_patch <= review_patch + 2 => {}
            _ => errors.push(format!(
                "{oracle_id}: renewal must expire within two subsequent patch releases"
            )),
        }
        match (
            NaiveDate::parse_from_str(string(decision, "reviewed_date_utc"), "%Y-%m-%d"),
            NaiveDate::parse_from_str(string(decision, "new_expiry_date_utc"), "%Y-%m-%d"),
        ) {
            (Ok(reviewed), Ok(next)) if next > reviewed => {}
            _ => errors.push(format!(
                "{oracle_id}: renewal date must advance beyond the reviewed date"
            )),
        }
    }

    let summary = object(sweep, "summary");
    let due_count = object_integer(summary, "due_count");
    if due_count != decisions.len() as u64
        || object_integer(summary, "renewed_count") != renewed_count
        || object_integer(summary, "retired_count") != retired_count
        || object_integer(summary, "pending_count") != pending_count
        || pending_count != 0
    {
        errors.push("retirement sweep summary counts drifted".to_owned());
    }
    if array(sweep, "removal_receipts").len() as u64 != retired_count {
        errors.push("retirement sweep removal receipts must match retired count".to_owned());
    }
    if retired_count == 0
        && string(sweep, "profile_remeasurement_status")
            != "not-applicable-no-manifest-edge-retired"
    {
        errors.push(
            "zero-retirement sweep must explicitly mark remeasurement not applicable".to_owned(),
        );
    }

    let scheduled_ci = object(sweep, "scheduled_ci");
    for key in ["workflow_path", "event", "cron", "command"] {
        nonempty_object_string(scheduled_ci, key, &mut errors, "retirement-sweep");
    }
    if object_string(scheduled_ci, "workflow_path") != NIGHTLY_WORKFLOW_PATH
        || object_string(scheduled_ci, "event") != "schedule"
        || object_string(scheduled_ci, "cron") != ORACLE_EXPIRY_CRON
        || object_string(scheduled_ci, "command") != ORACLE_EXPIRY_COMMAND
    {
        errors.push("retirement sweep scheduled CI contract drifted".to_owned());
    }
    if string_set(sweep, "no_claim_boundaries").is_empty() {
        errors.push("retirement sweep requires explicit no-claim boundaries".to_owned());
    }

    errors
}

fn active_edge_ids(policy: &Value) -> BTreeSet<String> {
    active_registry(policy)
        .iter()
        .flat_map(|row| array(row, "manifest_edges"))
        .map(|edge| string(edge, "edge_id").to_owned())
        .collect()
}

fn validate_manifest_source_pins(policy: &Value) -> Vec<String> {
    let reconciliation = reconciliation(policy);
    let mut errors = Vec::new();
    let pins = array(reconciliation, "source_pins");
    let actual_paths = pins
        .iter()
        .map(|pin| string(pin, "path").to_owned())
        .collect::<BTreeSet<_>>();
    let expected_paths = expected_manifest_source_pins();
    for path in expected_paths.difference(&actual_paths) {
        errors.push(format!("missing manifest source pin: {path}"));
    }
    for path in actual_paths.difference(&expected_paths) {
        errors.push(format!("unexpected manifest source pin: {path}"));
    }
    if actual_paths.len() != pins.len() {
        errors.push("manifest source pin paths must be unique".to_owned());
    }

    for pin in pins {
        let path = string(pin, "path");
        let bytes = match std::fs::read(repo_root().join(path)) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(format!("pinned source {path} cannot be read: {error}"));
                continue;
            }
        };
        if sha256_hex(&bytes) != string(pin, "sha256") {
            errors.push(format!("manifest source pin hash drift: {path}"));
        }
        if line_count(&bytes) != integer(pin, "line_count") as usize {
            errors.push(format!("manifest source pin line-count drift: {path}"));
        }
        if pin
            .get("scope")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            errors.push(format!("manifest source pin lacks scope: {path}"));
        }
    }
    errors
}

fn validate_manifest_reconciliation(policy: &Value) -> Vec<String> {
    let reconciliation = reconciliation(policy);
    let mut errors = validate_manifest_source_pins(policy);
    errors.extend(
        active_registry(policy)
            .iter()
            .flat_map(|row| validate_active_oracle_row(policy, row)),
    );
    errors.extend(validate_retirement_sweep(policy));

    let edge_ids = active_edge_ids(policy);
    let expected_edges = expected_active_oracle_edges();
    for edge in expected_edges.difference(&edge_ids) {
        errors.push(format!("unregistered oracle edge: {edge}"));
    }
    for edge in edge_ids.difference(&expected_edges) {
        errors.push(format!("unknown registered oracle edge: {edge}"));
    }

    let report = object(reconciliation, "report");
    if object_integer(report, "active_oracle_package_count") as usize
        != active_registry(policy).len()
    {
        errors.push("report active package count drift".to_owned());
    }
    if object_integer(report, "active_oracle_manifest_edge_count") as usize != edge_ids.len() {
        errors.push("report active edge count drift".to_owned());
    }
    if object_integer(report, "unregistered_oracle_edge_count") != 0 {
        errors.push("report must fail closed on unregistered edges".to_owned());
    }
    if object_integer(report, "expired_active_oracle_count") != 0 {
        errors.push("report must fail closed on expired active oracles".to_owned());
    }
    if object_integer(report, "missing_required_field_count") != 0 {
        errors.push("report must fail closed on missing required fields".to_owned());
    }

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
fn manifest_reconciliation_metadata_and_required_fields_are_exact() {
    let policy = policy();
    let reconciliation = reconciliation(&policy);
    assert_eq!(
        string(reconciliation, "contract_id"),
        RECONCILIATION_CONTRACT_ID
    );
    assert_eq!(string(reconciliation, "bead_id"), RECONCILIATION_BEAD_ID);
    assert_eq!(
        string(reconciliation, "capability_id"),
        "CAP-VERIFICATION-PROFILES"
    );
    assert_eq!(string(reconciliation, "as_of_release"), "0.4.9");
    assert_eq!(string(reconciliation, "as_of_date_utc"), "2026-08-21");
    assert_eq!(
        reconciliation
            .get("cutover_authorized")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        string_set(reconciliation, "active_registry_required_fields"),
        [
            "expiry",
            "graph_class",
            "independent_corpus",
            "introduction",
            "lifecycle_state",
            "lock_checksum",
            "lock_source",
            "manifest_edges",
            "no_claim_boundary",
            "oracle_class",
            "oracle_id",
            "owner",
            "package_id",
            "package_name",
            "production_exclusion_proof",
            "removal_bead",
            "renewal",
            "requested_versions",
            "resolved_version",
            "test_scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(
        string_set(reconciliation, "required_negative_fixtures"),
        [
            "expired-active-oracle",
            "live-date-expiry",
            "live-release-expiry",
            "lock-version-source-checksum-mismatch",
            "manifest-pin-drift",
            "missing-independent-corpus",
            "missing-owner",
            "missing-removal-bead",
            "missing-retirement-sweep-decision",
            "missing-test-scope",
            "report-count-drift",
            "scheduled-ci-drift",
            "unapproved-retirement-renewal",
            "unregistered-oracle-edge",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn every_manifest_and_lockfile_pin_is_current() {
    let policy = policy();
    let errors = validate_manifest_source_pins(&policy);
    assert!(
        errors.is_empty(),
        "manifest source pin errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn active_manifest_oracle_registry_is_complete_and_valid() {
    let policy = policy();
    let actual_packages = active_registry(&policy)
        .iter()
        .map(|row| string(row, "package_name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_packages,
        [
            "h2",
            "httparse",
            "opentelemetry-proto",
            "opentelemetry_sdk",
            "prometheus-client",
            "raptorq",
            "redis",
            "sqlx",
            "tokio",
            "tokio-util",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(active_registry(&policy).len(), 10);
    assert_eq!(active_edge_ids(&policy), expected_active_oracle_edges());

    let errors = validate_manifest_reconciliation(&policy);
    assert!(
        errors.is_empty(),
        "manifest reconciliation errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn retirement_sweep_is_complete_bounded_and_approved() {
    let policy = policy();
    let errors = validate_retirement_sweep(&policy);
    assert!(
        errors.is_empty(),
        "retirement sweep errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn live_package_release_and_utc_date_have_not_reached_active_expiry() {
    let policy = policy();
    let release = current_package_release();
    let date = current_utc_date();
    let errors = active_registry(&policy)
        .iter()
        .flat_map(|row| validate_active_expiry_at(row, &release, &date))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "active dependency-oracle expiry errors at release {release} on {date}:\n{}",
        errors.join("\n")
    );
}

#[test]
fn scheduled_nightly_workflow_runs_oracle_expiry_contract() {
    let policy = policy();
    let scheduled_ci = object(retirement_sweep(&policy), "scheduled_ci");
    let workflow = read_repo_file(NIGHTLY_WORKFLOW_PATH);
    let quoted_cron = format!("cron: '{}'", object_string(scheduled_ci, "cron"));
    assert!(
        workflow.contains(&quoted_cron),
        "nightly workflow must retain the registered oracle-expiry cron"
    );
    assert!(
        workflow.contains("name: Enforce dependency-oracle expiry and retirement receipts"),
        "nightly workflow must name the oracle-expiry gate"
    );
    assert!(
        workflow.contains(object_string(scheduled_ci, "command")),
        "nightly workflow must run the registered oracle-expiry command"
    );
}

#[test]
fn active_oracle_owners_removal_and_renewal_authorities_exist() {
    let policy = policy();
    let tracker_ids = tracker_issue_ids();
    for row in active_registry(&policy) {
        let owner = string(row, "owner")
            .strip_prefix("bead:")
            .expect("owner must be a bead authority");
        let renewal = object_string(object(row, "renewal"), "authority")
            .strip_prefix("bead:")
            .expect("renewal authority must be a bead");
        let removal = string(row, "removal_bead");
        for bead in [owner, renewal, removal] {
            assert!(
                tracker_ids.contains(bead),
                "active oracle authority {bead} is absent from tracker"
            );
        }
    }
}

#[test]
fn deterministic_class_report_separates_zero_and_active_classes() {
    let policy = policy();
    let report = object(reconciliation(&policy), "report");
    assert_eq!(object_integer(report, "active_oracle_package_count"), 10);
    assert_eq!(
        object_integer(report, "active_oracle_manifest_edge_count"),
        15
    );
    let classes = object_object(report, "classes");
    assert_eq!(
        classes.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        ["build", "dev", "native", "production", "reverse_cycle"]
            .into_iter()
            .collect()
    );
    for class in ["production", "build", "native", "reverse_cycle"] {
        assert_eq!(
            object_integer(
                classes
                    .get(class)
                    .and_then(Value::as_object)
                    .expect("class report row"),
                "active_oracle_edge_count"
            ),
            0,
            "{class} must remain an explicit zero-active class"
        );
    }
    assert_eq!(
        object_integer(
            classes
                .get("dev")
                .and_then(Value::as_object)
                .expect("dev class report"),
            "active_oracle_edge_count"
        ),
        15
    );
    assert_eq!(
        object_string_set(report, "deterministic_markdown_columns"),
        [
            "class",
            "corpus_status",
            "expiry",
            "lifecycle",
            "manifest_edges",
            "no_claim_boundary",
            "oracle_id",
            "owner",
            "package_id",
            "removal_bead",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn negative_fixture_manifest_pin_drift_fails_closed() {
    let mut policy = policy();
    let first_pin = policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("source_pins"))
        .and_then(Value::as_array_mut)
        .and_then(|pins| pins.first_mut())
        .expect("source pin fixture");
    set_string(first_pin, "sha256", &"0".repeat(64));
    let errors = validate_manifest_source_pins(&policy);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("manifest source pin hash drift"))
    );
}

#[test]
fn negative_fixture_unregistered_oracle_edge_fails_closed() {
    let mut policy = policy();
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("active_oracle_registry"))
        .and_then(Value::as_array_mut)
        .expect("active registry fixture")
        .retain(|row| string(row, "oracle_id") != "active-httparse-http1-reference");
    let errors = validate_manifest_reconciliation(&policy);
    assert!(errors.iter().any(|error| {
        error.contains("unregistered oracle edge: Cargo.toml::dev-dependencies::httparse")
    }));
}

#[test]
fn negative_fixtures_missing_owner_scope_corpus_and_removal_fail_closed() {
    for (field, expected) in [
        ("owner", "missing required active field owner"),
        ("test_scope", "missing required active field test_scope"),
        (
            "independent_corpus",
            "missing required active field independent_corpus",
        ),
        ("removal_bead", "missing required active field removal_bead"),
    ] {
        let mut policy = policy();
        active_row_by_id_mut(&mut policy, "active-httparse-http1-reference")
            .as_object_mut()
            .expect("active row must be object")
            .remove(field);
        let row = active_row_by_id(&policy, "active-httparse-http1-reference");
        let errors = validate_active_oracle_row(&policy, row);
        assert!(
            errors.iter().any(|error| error.contains(expected)),
            "missing {field} did not fail closed: {errors:?}"
        );
    }
}

#[test]
fn negative_fixture_expired_active_manifest_oracle_fails_closed() {
    let mut policy = policy();
    let expiry = active_row_by_id_mut(&mut policy, "active-httparse-http1-reference")
        .get_mut("expiry")
        .and_then(Value::as_object_mut)
        .expect("expiry fixture");
    expiry.insert(
        "date_utc".to_owned(),
        Value::String("2026-07-24".to_owned()),
    );
    let row = active_row_by_id(&policy, "active-httparse-http1-reference");
    let errors = validate_active_oracle_row(&policy, row);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("active manifest oracle is expired"))
    );
}

#[test]
fn negative_fixture_missing_retirement_sweep_decision_fails_closed() {
    let mut policy = policy();
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("retirement_sweep"))
        .and_then(|value| value.get_mut("decisions"))
        .and_then(Value::as_array_mut)
        .expect("retirement decisions fixture")
        .pop();
    let errors = validate_retirement_sweep(&policy);
    assert!(
        errors.iter().any(|error| error
            .contains("every active oracle requires exactly one retirement sweep decision")),
        "missing decision did not fail closed: {errors:?}"
    );
}

#[test]
fn negative_fixture_unapproved_retirement_renewal_fails_closed() {
    let mut policy = policy();
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("retirement_sweep"))
        .and_then(|value| value.get_mut("owner_approval"))
        .and_then(Value::as_object_mut)
        .expect("owner approval fixture")
        .insert("status".to_owned(), Value::String("pending".to_owned()));
    let errors = validate_retirement_sweep(&policy);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("requires approved parent-bead authority")),
        "unapproved renewal did not fail closed: {errors:?}"
    );
}

#[test]
fn negative_fixture_live_release_expiry_fails_closed() {
    let policy = policy();
    let row = active_row_by_id(&policy, "active-httparse-http1-reference");
    let errors = validate_active_expiry_at(row, "0.4.11", "2026-08-21");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("reached release expiry 0.4.11 at 0.4.11")),
        "live release expiry did not fail closed: {errors:?}"
    );
}

#[test]
fn negative_fixture_live_date_expiry_fails_closed() {
    let policy = policy();
    let row = active_row_by_id(&policy, "active-httparse-http1-reference");
    let errors = validate_active_expiry_at(row, "0.4.10", "2026-10-21");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("reached UTC date expiry 2026-10-21")),
        "live UTC date expiry did not fail closed: {errors:?}"
    );
}

#[test]
fn negative_fixture_scheduled_ci_drift_fails_closed() {
    let mut policy = policy();
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("retirement_sweep"))
        .and_then(|value| value.get_mut("scheduled_ci"))
        .and_then(Value::as_object_mut)
        .expect("scheduled CI fixture")
        .insert("cron".to_owned(), Value::String("0 0 1 1 *".to_owned()));
    let errors = validate_retirement_sweep(&policy);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("scheduled CI contract drifted")),
        "scheduled CI drift did not fail closed: {errors:?}"
    );
}

#[test]
fn negative_fixture_lock_checksum_mismatch_fails_closed() {
    let mut policy = policy();
    set_string(
        active_row_by_id_mut(&mut policy, "active-redis-rs-reference"),
        "lock_checksum",
        &"f".repeat(64),
    );
    let row = active_row_by_id(&policy, "active-redis-rs-reference");
    let errors = validate_active_oracle_row(&policy, row);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("lock checksum mismatch"))
    );
}

#[test]
fn negative_fixture_report_count_drift_fails_closed() {
    let mut policy = policy();
    policy
        .get_mut("manifest_reconciliation")
        .and_then(|value| value.get_mut("report"))
        .and_then(Value::as_object_mut)
        .expect("report fixture")
        .insert(
            "active_oracle_manifest_edge_count".to_owned(),
            Value::from(14_u64),
        );
    let errors = validate_manifest_reconciliation(&policy);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("report active edge count drift"))
    );
}

#[test]
fn reconciliation_docs_preserve_current_and_planned_no_claim_boundaries() {
    let docs = read_repo_file(DOC_PATH);
    for marker in [
        RECONCILIATION_BEAD_ID,
        RECONCILIATION_CONTRACT_ID,
        "10 active reference packages",
        "15 exact manifest edges",
        "Production | 0",
        "Dev / conformance | 15",
        "Build | 0",
        "Native | 0 active, 3 planned",
        "Reverse-cycle | 0 active, 1 planned",
        "declared-reference-not-wired",
        "cutover_authorized = false",
        RETIREMENT_SWEEP_BEAD_ID,
        "retired zero and renewed all",
        "release `0.4.11` or UTC date `2026-10-21`",
        NIGHTLY_WORKFLOW_PATH,
        ORACLE_EXPIRY_CRON,
        "Manifest and lockfile pins prove only",
    ] {
        assert!(
            docs.contains(marker),
            "operator docs missing reconciliation marker: {marker}"
        );
    }
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
