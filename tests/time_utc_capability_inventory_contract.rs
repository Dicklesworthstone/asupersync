//! Fail-closed static contract for the UTC and RFC3339 capability inventory.
//!
//! Bead: asupersync-5z2scg.6.1
//! Fixture: artifacts/time_utc_capability_inventory_v1.json
//!
//! This contract checks source classification and artifact structure. It does
//! not establish runtime behavior, dependency parity, or cutover eligibility.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/time_utc_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/time_utc_capability_inventory.md";
const CONTRACT_PATH: &str = "tests/time_utc_capability_inventory_contract.rs";
const ARTIFACT_ID: &str = "time-utc-capability-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const PARENT_BEAD_ID: &str = "asupersync-5z2scg.6";
const BEAD_ID: &str = "asupersync-5z2scg.6.1";
const CAPABILITY_ID: &str = "CAP-TIME-UTC-RFC3339";
const ADR_ID: &str = "DEP-ADR-011";
const BASELINE_REVISION: &str = "1afde84d564bd8ea876459624116f90028b80835";
const ARTIFACT_SHA256: &str =
    "6984ba7e7ad070209c392b25b66c0cc18b8af1edbf41156265022f2746c44a09";
const DOC_BEGIN: &str = "<!-- BEGIN TIME UTC CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END TIME UTC CAPABILITY INVENTORY -->";
const CHRONO_TOKEN: &str = concat!("chrono", "::");
const EXTERNAL_TIME_TOKEN: &str = concat!("time", "::");
const CENSUS_PROJECTION_SHA256: &str =
    "f8fd5086d737eb83440e89530d8929d8bcd25dc68449e16ea57f12fcd116c7de";
const CENSUS_PATHS_SHA256: &str =
    "f16dea3b2143a0502579cdde842a5b00694031ec504eb674750554f6030f9700";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn artifact() -> Value {
    let bytes = read_repo_bytes(ARTIFACT_PATH);
    assert_eq!(
        sha256_hex(&bytes),
        ARTIFACT_SHA256,
        "inventory artifact digest drifted"
    );
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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

fn number_set(value: &Value, key: &str) -> BTreeSet<u64> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .unwrap_or_else(|| panic!("{key} entries must be unsigned integers"))
        })
        .collect()
}

fn require_exact_ids(
    rows: &[Value],
    key: &str,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let expected: BTreeSet<String> = expected.iter().map(|id| (*id).to_owned()).collect();
    if rows.len() != expected.len() || row_ids(rows, key) != expected {
        return Err(format!("{label} exact unique {key} set drifted"));
    }
    Ok(())
}

fn require_exact_strings(value: &Value, key: &str, expected: &[&str]) -> Result<(), String> {
    let expected: BTreeSet<String> = expected.iter().map(|item| (*item).to_owned()).collect();
    if array(value, key).len() != expected.len() || string_set(value, key) != expected {
        return Err(format!("{key} exact unique string set drifted"));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(LOWER[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn contains_unclassified_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains("UNKNOWN"),
        Value::Array(values) => values.iter().any(contains_unclassified_value),
        Value::Object(values) => values.values().any(contains_unclassified_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn validate_identity(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1)
        || text(inventory, "artifact_id") != ARTIFACT_ID
        || text(inventory, "program_id") != PROGRAM_ID
        || text(inventory, "parent_bead_id") != PARENT_BEAD_ID
        || text(inventory, "bead_id") != BEAD_ID
        || text(inventory, "capability_id") != CAPABILITY_ID
        || text(inventory, "baseline_revision") != BASELINE_REVISION
        || text(inventory, "evidence_mode") != "STATIC_SOURCE_INVENTORY"
    {
        return Err("inventory identity drifted".to_owned());
    }

    let authority = object(inventory, "authority");
    if text(&Value::Object(authority.clone()), "adr_id") != ADR_ID
        || authority.get("decision").and_then(Value::as_str) != Some("ADDITIVE_COEXISTENCE")
        || authority.get("disposition").and_then(Value::as_str)
            != Some("PRESERVE_AND_REPLACE_IF_PARITY")
        || authority.get("evidence_state").and_then(Value::as_str) != Some("BASELINE_PLANNED")
        || authority.get("cutover_state").and_then(Value::as_str)
            != Some("BLOCKED_PENDING_EVIDENCE")
        || authority
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("authority or cutover disposition drifted".to_owned());
    }
    require_exact_strings(
        &Value::Object(authority.clone()),
        "primary_authorities",
        &[PARENT_BEAD_ID],
    )?;
    require_exact_strings(
        &Value::Object(authority.clone()),
        "secondary_compatibility_consumers",
        &[
            "asupersync-d24mms.4",
            "asupersync-dep-p3-api-adrs-h3jspm.13",
        ],
    )?;

    let snapshot = object(inventory, "source_snapshot");
    if snapshot.get("git_head").and_then(Value::as_str) != Some(BASELINE_REVISION) {
        return Err("source snapshot revision drifted".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy
            .get("unclassified_chrono_paths")
            .and_then(Value::as_u64)
            != Some(0)
        || policy.get("a1_execution_state").and_then(Value::as_str)
            != Some("NOT_EXECUTED_THIS_TURN")
        || policy.get("source_classification_state").and_then(Value::as_str)
            != Some("PATH_COUNT_AND_ALIAS_REFERENCES_COMPLETE_PER_USE_DETAIL_PARTIAL")
        || policy.get("bead_acceptance_state").and_then(Value::as_str)
            != Some("PARTIAL_STATIC_INVENTORY_ONLY")
        || policy.get("bead_close_allowed").and_then(Value::as_bool) != Some(false)
        || policy
            .get("unresolved_behavioral_gap_count")
            .and_then(Value::as_u64)
            != Some(7)
        || policy
            .get("unresolved_static_detail_gap_count")
            .and_then(Value::as_u64)
            != Some(1)
        || policy.get("acceptance_zero_unknown_met").and_then(Value::as_bool) != Some(false)
        || policy.get("alias_aware_use_inventory_state").and_then(Value::as_str)
            != Some("IMPORT_BINDINGS_AND_DIRECT_REFERENCES_COMPLETE_DERIVED_CLASSIFICATION_PARTIAL")
        || contains_unclassified_value(inventory)
    {
        return Err("classification or execution policy drifted".to_owned());
    }
    Ok(())
}

fn validate_exact_row_sets(inventory: &Value) -> Result<(), String> {
    require_exact_ids(
        array(inventory, "dependency_profiles"),
        "profile_id",
        &[
            "TIME-PROFILE-DEFAULT",
            "TIME-PROFILE-CLI",
            "TIME-PROFILE-BENCHMARK-ADAPTERS",
            "TIME-PROFILE-OFFLINE-TUNER",
            "TIME-PROFILE-TLS-TRANSITIVE",
            "TIME-PROFILE-TLS-NATIVE-ROOTS",
            "TIME-PROFILE-TLS-WEBPKI-ROOTS",
            "TIME-PROFILE-ATP-CLI-TRANSITIVE",
            "TIME-PROFILE-ATPD-DAEMON",
            "TIME-PROFILE-CI-CROSS-PLATFORM",
            "TIME-PROFILE-ROOT-DEV",
            "TIME-PROFILE-CONFORMANCE-MEMBER",
            "TIME-PROFILE-EXCLUDED-FUZZ-WORKSPACE",
            "TIME-PROFILE-EXCLUDED-CONFORMANCE",
            "TIME-PROFILE-STANDALONE-GOLDEN",
            "TIME-PROFILE-STANDALONE-REPORTING",
        ],
        "dependency profiles",
    )?;
    let profiles: BTreeMap<_, _> = array(inventory, "dependency_profiles")
        .iter()
        .map(|row| (text(row, "profile_id"), row))
        .collect();
    let fuzz_root = profiles["TIME-PROFILE-EXCLUDED-FUZZ-WORKSPACE"];
    if fuzz_root.get("direct_chrono_edge").and_then(Value::as_bool) != Some(false)
        || fuzz_root.get("transitive_chrono_edge").and_then(Value::as_bool) != Some(true)
        || fuzz_root.get("direct_time_edge").and_then(Value::as_bool) != Some(false)
        || fuzz_root.get("transitive_time_edge").and_then(Value::as_bool) != Some(true)
        || text(fuzz_root, "manifest") != "fuzz/Cargo.toml"
    {
        return Err("excluded fuzz workspace dependency profile drifted".to_owned());
    }
    require_exact_strings(fuzz_root, "root_dependency_features", &["benchmark-adapters", "tls"])?;
    let offline = profiles["TIME-PROFILE-OFFLINE-TUNER"];
    require_exact_strings(offline, "cargo_features", &["cli", "simd-intrinsics"])?;
    require_exact_strings(offline, "target_kinds", &["offline_tuner binary"])?;

    let census = &inventory["chrono_census"];
    require_exact_ids(
        array(census, "classification_groups"),
        "group_id",
        &[
            "TIME-CHRONO-PRODUCTION-CLI",
            "TIME-CHRONO-PRODUCTION-BENCHMARK",
            "TIME-CHRONO-ROOT-BENCH",
            "TIME-CHRONO-ROOT-DATABASE-MESSAGING-TESTS",
            "TIME-CHRONO-ROOT-REAL-E2E-SOURCES",
            "TIME-CHRONO-ROOT-INTEGRATION-SOURCES",
            "TIME-CHRONO-CONFORMANCE-MEMBER",
            "TIME-CHRONO-CONFORMANCE-RAPTORQ-REPORTING",
            "TIME-CHRONO-EXCLUDED-CONFORMANCE",
            "TIME-CHRONO-STANDALONE-GOLDEN",
            "TIME-CHRONO-STANDALONE-REPORTING",
        ],
        "source classification groups",
    )?;

    require_exact_ids(
        array(inventory, "public_datetime_fields"),
        "field_id",
        &[
            "TIME-PUB-CLI-STATUS-TIMESTAMP",
            "TIME-PUB-CLI-BENCH-SYSTEM-TIMESTAMP",
            "TIME-PUB-CLI-CI-TIMESTAMP",
            "TIME-PUB-CLI-CI-EXPIRES",
            "TIME-PUB-CLI-DATASET-UPDATED",
            "TIME-PUB-CLI-RELEASE-PUBLISHED",
            "TIME-PUB-CLI-ARCHIVE-ARCHIVED",
            "TIME-PUB-CLI-ARCHIVE-EXPIRES",
            "TIME-PUB-CLI-ARCHIVE-VERIFIED",
            "TIME-PUB-CLI-INTEGRITY-LAST-CHECK",
            "TIME-PUB-BENCH-ENVIRONMENT-TIMESTAMP",
            "TIME-PUB-BENCH-REPORT-TIMESTAMP",
            "TIME-PUB-CONFORMANCE-H2-DATA-END",
            "TIME-PUB-CONFORMANCE-H2-GOAWAY",
            "TIME-PUB-CONFORMANCE-H2-PING",
            "TIME-PUB-CONFORMANCE-H2-PRIORITY",
            "TIME-PUB-CONFORMANCE-H2-SETTINGS",
            "TIME-PUB-CONFORMANCE-HPACK",
        ],
        "typed public fields",
    )?;

    require_exact_ids(
        array(inventory, "public_chrono_generated_string_fields"),
        "field_id",
        &[
            "TIME-PUB-CONFORMANCE-H1-EXPECT-STRING",
            "TIME-PUB-CONFORMANCE-H1-REQUEST-STRING",
            "TIME-PUB-CONFORMANCE-H1-RESPONSE-STRING",
            "TIME-PUB-CONFORMANCE-H2-ENABLE-PUSH-STRING",
            "TIME-PUB-CONFORMANCE-H2-CONNECT-STRING",
            "TIME-PUB-CONFORMANCE-H2-CONTINUATION-STRING",
            "TIME-PUB-CONFORMANCE-HPACK-ENCODER-STRING",
            "TIME-PUB-CONFORMANCE-RAPTORQ-REFERENCE-UPDATED",
            "TIME-PUB-CONFORMANCE-RAPTORQ-COVERAGE-GENERATED",
            "TIME-PUB-CONFORMANCE-RAPTORQ-RECORD-TIMESTAMP",
            "TIME-PUB-CONFORMANCE-RAPTORQ-HISTORY-UPDATED",
            "TIME-PUB-EXCLUDED-CONFORMANCE-PING-REPORT-TIMESTAMP",
        ],
        "rendered public fields",
    )?;

    require_exact_ids(
        array(inventory, "test_profile_datetime_fields"),
        "field_id",
        &[
            "TIME-TEST-ROOT-HPACK-FIXTURE-GENERATED",
            "TIME-TEST-GOLDEN-FIXTURE-GENERATED",
            "TIME-TEST-GOLDEN-METADATA-UPDATED",
            "TIME-TEST-REPORT-COVERAGE-GENERATED",
            "TIME-TEST-REPORT-MAINTENANCE-TIMESTAMP",
            "TIME-TEST-REPORT-FILE-MODIFIED",
            "TIME-TEST-REPORT-SNAPSHOT-TIMESTAMP",
        ],
        "test profile datetime fields",
    )?;

    require_exact_ids(
        array(inventory, "persisted_and_output_surfaces"),
        "surface_id",
        &[
            "TIME-SURFACE-CLI-NESTED-SERDE",
            "TIME-SURFACE-CLI-CI-INDEX",
            "TIME-SURFACE-CLI-DATASET-INDEX",
            "TIME-SURFACE-CLI-RELEASE-INDEX",
            "TIME-SURFACE-CLI-ARCHIVE-METADATA",
            "TIME-SURFACE-BENCHMARK-SERDE",
            "TIME-SURFACE-RAPTORQ-BENCHMARK-STDERR-EVENT",
            "TIME-SURFACE-TRACE-METADATA-CLI-UTC",
            "TIME-SURFACE-ATP-EVENT-LOG-JSONL",
            "TIME-SURFACE-JETSTREAM-START-TIME-WIRE",
            "TIME-SURFACE-OFFLINE-TUNER-TEMPORAL-METADATA",
            "TIME-SURFACE-CONFORMANCE-REPORTS",
            "TIME-SURFACE-CONFORMANCE-NONCHRONO-TEMPORAL",
            "TIME-SURFACE-EXCLUDED-CONFORMANCE-PING-REPORT",
            "TIME-SURFACE-CONFORMANCE-HISTORY",
            "TIME-SURFACE-STANDALONE-TEST-ARTIFACTS",
        ],
        "persisted and output surfaces",
    )?;

    require_exact_ids(
        array(inventory, "semantic_contracts"),
        "contract_id",
        &[
            "TIME-SEM-PUBLIC-TYPE",
            "TIME-SEM-OPTION-ABSENCE",
            "TIME-SEM-CLI-CLOCK",
            "TIME-SEM-DURATION-CONVERSION",
            "TIME-SEM-STORE-IO",
            "TIME-SEM-BENCHMARK",
            "TIME-SEM-POSTGRES-ORACLE",
            "TIME-SEM-CONFORMANCE-STRING-TIMESTAMPS",
            "TIME-SEM-REDIS-TESTS",
            "TIME-SEM-OWNED-UTC-FOUNDATION",
            "TIME-SEM-OWNED-RELEASE-PROOF-PARSER",
            "TIME-SEM-OWNED-EMITTERS",
            "TIME-SEM-LOGICAL-SEPARATION",
            "TIME-SEM-NONDEPENDENCY-TEMPORAL-SCHEMAS",
        ],
        "semantic contracts",
    )?;

    require_exact_ids(
        array(inventory, "migration_groups"),
        "group_id",
        &[
            "TIME-MIG-UTC-CALENDAR-CORE",
            "TIME-MIG-RFC3339-SERDE",
            "TIME-MIG-CLI-PUBLIC-PERSISTED",
            "TIME-MIG-BENCHMARK-REPORTS",
            "TIME-MIG-DATABASE-MESSAGING-ORACLES",
            "TIME-MIG-DOWNSTREAM-CORPUS",
            "TIME-MIG-CONFORMANCE-TOOLS",
            "TIME-MIG-TERMINAL-CUTOVER",
        ],
        "migration groups",
    )?;

    require_exact_ids(
        array(inventory, "registry_reconciliation"),
        "gap_id",
        &[
            "TIME-RECON-01",
            "TIME-RECON-02",
            "TIME-RECON-03",
            "TIME-RECON-04",
            "TIME-RECON-05",
            "TIME-RECON-06",
            "TIME-RECON-07",
            "TIME-RECON-08",
            "TIME-RECON-09",
            "TIME-RECON-10",
            "TIME-RECON-11",
            "TIME-RECON-12",
        ],
        "reconciliation gaps",
    )?;

    require_exact_ids(
        array(inventory, "known_gaps"),
        "gap_id",
        &[
            "TIME-GAP-A1-RANGE-CORPUS",
            "TIME-GAP-A1-PARSE-FORMAT",
            "TIME-GAP-A1-PERSISTED-BYTES",
            "TIME-GAP-A1-BENCHMARK-ARTIFACT",
            "TIME-GAP-A1-DATABASE-MESSAGING",
            "TIME-GAP-A1-DOWNSTREAM",
            "TIME-GAP-A1-CUTOVER",
        ],
        "known gaps",
    )?;
    require_exact_ids(
        array(inventory, "static_inventory_gaps"),
        "gap_id",
        &["TIME-STATIC-GAP-PER-USE-CLASSIFICATION"],
        "static inventory gaps",
    )?;
    require_exact_ids(
        array(inventory, "resolved_static_details"),
        "detail_id",
        &["TIME-STATIC-RESOLVED-ALIAS-BINDINGS"],
        "resolved static details",
    )?;
    require_exact_ids(
        array(inventory, "scope_boundaries"),
        "boundary_id",
        &["TIME-SCOPE-NONDEPENDENCY-TEMPORAL-SCHEMAS"],
        "scope boundaries",
    )?;
    let resolved_alias = &array(inventory, "resolved_static_details")[0];
    let nondependency_boundary = &array(inventory, "scope_boundaries")[0];
    if text(resolved_alias, "state") != "RESOLVED_BY_STATIC_ALIAS_INVENTORY"
        || text(nondependency_boundary, "semantic_contract_id")
            != "TIME-SEM-NONDEPENDENCY-TEMPORAL-SCHEMAS"
    {
        return Err("resolved detail or scope-boundary routing drifted".to_owned());
    }
    Ok(())
}

fn validate_locked_packages(inventory: &Value) -> Result<(), String> {
    let rows = array(inventory, "locked_packages");
    require_exact_ids(rows, "package", &["chrono", "time"], "locked packages")?;
    let by_name: BTreeMap<_, _> = rows
        .iter()
        .map(|row| (text(row, "package"), row))
        .collect();
    let chrono = by_name["chrono"];
    if text(chrono, "version") != "0.4.45"
        || text(chrono, "checksum")
            != "1aa79e62e7697b8e29b513a68abacf485adcd1fe8284a4316c5ae868e6633327"
    {
        return Err("locked chrono identity drifted".to_owned());
    }
    require_exact_strings(
        chrono,
        "direct_locked_dependers",
        &["asupersync 0.3.10", "asupersync-conformance 0.3.5"],
    )?;
    let time = by_name["time"];
    if text(time, "version") != "0.3.54"
        || text(time, "checksum")
            != "3e1d5e639ff6bab73cb6885cc7e7b1de96c3f32c68ec55f3952614bec1092244"
    {
        return Err("locked time identity drifted".to_owned());
    }
    require_exact_strings(
        time,
        "direct_locked_dependers",
        &[
            "asn1-rs 0.7.2",
            "asupersync 0.3.10",
            "x509-parser 0.18.1",
        ],
    )?;
    Ok(())
}

fn validate_public_and_persisted_counts(inventory: &Value) -> Result<(), String> {
    let typed = array(inventory, "public_datetime_fields");
    let rendered = array(inventory, "public_chrono_generated_string_fields");
    let test_profile = array(inventory, "test_profile_datetime_fields");
    let root_fields = typed
        .iter()
        .filter(|row| row.get("crate").and_then(Value::as_str) == Some("asupersync"))
        .count();
    let conformance_fields = typed.len() - root_fields;
    let optional_root = typed
        .iter()
        .filter(|row| row.get("crate").and_then(Value::as_str) == Some("asupersync"))
        .filter(|row| row.get("optional").and_then(Value::as_bool) == Some(true))
        .count();
    let excluded_rendered = rendered
        .iter()
        .filter(|row| {
            row.get("profile_id").and_then(Value::as_str)
                == Some("TIME-PROFILE-EXCLUDED-CONFORMANCE")
        })
        .count();
    let rendered_serialize_only = rendered
        .iter()
        .filter(|row| {
            row.get("serde_direction").and_then(Value::as_str) == Some("SERIALIZE_ONLY")
        })
        .count();
    let rendered_roundtrip = rendered
        .iter()
        .filter(|row| {
            row.get("serde_direction").and_then(Value::as_str)
                == Some("SERIALIZE_AND_DESERIALIZE")
        })
        .count();
    let test_publicly_reachable = test_profile
        .iter()
        .filter(|row| {
            row.get("visibility")
                .and_then(Value::as_str)
                .is_some_and(|visibility| visibility.starts_with("PUBLIC_"))
        })
        .count();
    let test_pub_private_module = test_profile
        .iter()
        .filter(|row| {
            row.get("visibility").and_then(Value::as_str)
                == Some("PUB_ITEM_IN_PRIVATE_TEST_MODULE")
        })
        .count();
    let test_private = test_profile
        .iter()
        .filter(|row| {
            row.get("visibility").and_then(Value::as_str)
                == Some("PRIVATE_SERIALIZED_TEST_ARTIFACT")
        })
        .count();
    let test_fields: BTreeMap<_, _> = test_profile
        .iter()
        .map(|row| (text(row, "field_id"), row))
        .collect();
    let typed_fields: BTreeMap<_, _> = typed
        .iter()
        .map(|row| (text(row, "field_id"), row))
        .collect();
    let optional_datetime = format!("Option<{}DateTime<{}Utc>>", CHRONO_TOKEN, CHRONO_TOKEN);
    if text(typed_fields["TIME-PUB-CONFORMANCE-H2-SETTINGS"], "struct")
        != "ComplianceReport"
        || text(typed_fields["TIME-PUB-CONFORMANCE-HPACK"], "struct")
            != "ComplianceReport"
        || text(
            test_fields["TIME-TEST-ROOT-HPACK-FIXTURE-GENERATED"],
            "visibility",
        ) != "PUB_ITEM_IN_PRIVATE_TEST_MODULE"
        || test_fields["TIME-TEST-GOLDEN-METADATA-UPDATED"]
            .get("optional")
            .and_then(Value::as_bool)
            != Some(true)
        || text(
            test_fields["TIME-TEST-GOLDEN-METADATA-UPDATED"],
            "rust_type",
        ) != optional_datetime.as_str()
        || test_profile.iter().any(|row| {
            row.get("optional").and_then(Value::as_bool).is_none()
                || text(row, "rust_type").is_empty()
        })
    {
        return Err("test-profile field semantics drifted".to_owned());
    }
    if root_fields != 12
        || conformance_fields != 6
        || rendered.len() != 12
        || excluded_rendered != 1
        || rendered_serialize_only != 7
        || rendered_roundtrip != 5
        || test_profile.len() != 7
        || test_publicly_reachable != 5
        || test_pub_private_module != 1
        || test_private != 1
        || optional_root != 3
    {
        return Err("public timestamp field counts drifted".to_owned());
    }

    let totals = object(inventory, "public_field_totals");
    if totals.get("root_asupersync_fields").and_then(Value::as_u64) != Some(12)
        || totals.get("root_asupersync_structs").and_then(Value::as_u64) != Some(9)
        || totals.get("root_asupersync_modules").and_then(Value::as_u64) != Some(3)
        || totals.get("conformance_member_fields").and_then(Value::as_u64) != Some(6)
        || totals
            .get("conformance_member_chrono_generated_string_fields")
            .and_then(Value::as_u64)
            != Some(11)
        || totals
            .get("root_conformance_member_chrono_backed_timestamp_fields")
            .and_then(Value::as_u64)
            != Some(17)
        || totals
            .get("excluded_conformance_chrono_generated_string_fields")
            .and_then(Value::as_u64)
            != Some(1)
        || totals
            .get("all_public_chrono_backed_timestamp_fields")
            .and_then(Value::as_u64)
            != Some(30)
        || totals.get("test_profile_datetime_fields").and_then(Value::as_u64) != Some(7)
        || totals
            .get("test_profile_publicly_reachable_fields")
            .and_then(Value::as_u64)
            != Some(5)
        || totals
            .get("test_profile_pub_in_private_module_fields")
            .and_then(Value::as_u64)
            != Some(1)
        || totals
            .get("test_profile_private_serialized_fields")
            .and_then(Value::as_u64)
            != Some(1)
        || totals.get("all_inventory_field_rows").and_then(Value::as_u64) != Some(37)
        || totals.get("syntactically_pub_field_rows").and_then(Value::as_u64) != Some(36)
        || totals
            .get("externally_reachable_public_field_rows")
            .and_then(Value::as_u64)
            != Some(35)
        || totals.get("private_field_rows").and_then(Value::as_u64) != Some(1)
        || totals.get("all_serde_field_rows").and_then(Value::as_u64) != Some(35)
        || totals
            .get("all_distinct_serde_container_count")
            .and_then(Value::as_u64)
            != Some(32)
    {
        return Err("public field total receipt drifted".to_owned());
    }

    let stores: Vec<_> = array(inventory, "persisted_and_output_surfaces")
        .iter()
        .filter(|row| {
            row.get("kind").and_then(Value::as_str) == Some("READ_WRITE_PRETTY_JSON_STORE")
                && row.get("profile_id").and_then(Value::as_str) == Some("TIME-PROFILE-CLI")
        })
        .collect();
    let stored_fields: usize = stores
        .iter()
        .map(|row| array(row, "timestamp_fields").len())
        .sum();
    if stores.len() != 4 || stored_fields != 7 {
        return Err("four-store seven-field persistence matrix drifted".to_owned());
    }
    if stores.iter().any(|row| {
        row.get("temporal_assertion_state").and_then(Value::as_str) != Some("MISSING")
            || row.get("byte_golden_state").and_then(Value::as_str) != Some("MISSING")
    }) {
        return Err("missing persisted evidence was overstated".to_owned());
    }
    let all_stores: Vec<_> = array(inventory, "persisted_and_output_surfaces")
        .iter()
        .filter(|row| {
            row.get("kind").and_then(Value::as_str) == Some("READ_WRITE_PRETTY_JSON_STORE")
        })
        .collect();
    let all_stored_fields: usize = all_stores
        .iter()
        .map(|row| array(row, "timestamp_fields").len())
        .sum();
    if all_stores.len() != 5 || all_stored_fields != 9 {
        return Err("complete persisted store inventory drifted".to_owned());
    }
    Ok(())
}

fn expected_census(inventory: &Value) -> Result<BTreeMap<String, u64>, String> {
    let census = &inventory["chrono_census"];
    if number(census, "path_count") != 71
        || number(census, "matching_line_count") != 159
        || text(census, "path_and_line_count_projection_sha256") != CENSUS_PROJECTION_SHA256
        || text(census, "paths_projection_sha256") != CENSUS_PATHS_SHA256
    {
        return Err("census totals or projection fingerprints drifted".to_owned());
    }

    let profiles = row_ids(array(inventory, "dependency_profiles"), "profile_id");
    let migrations = row_ids(array(inventory, "migration_groups"), "group_id");
    let mut rows = BTreeMap::new();
    let mut summed_paths = 0_u64;
    let mut summed_lines = 0_u64;
    for group in array(census, "classification_groups") {
        if !profiles.contains(text(group, "profile_id"))
            || !migrations.contains(text(group, "migration_group_id"))
        {
            return Err(format!(
                "{} references an unregistered profile or migration group",
                text(group, "group_id")
            ));
        }
        let paths = array(group, "paths");
        let declared_paths = number(group, "path_count");
        let declared_lines = number(group, "matching_line_count");
        let actual_lines: u64 = paths
            .iter()
            .map(|row| number(row, "matching_line_count"))
            .sum();
        if declared_paths != paths.len() as u64 || declared_lines != actual_lines {
            return Err(format!("{} group totals drifted", text(group, "group_id")));
        }
        for row in paths {
            let path = text(row, "path").to_owned();
            let count = number(row, "matching_line_count");
            if rows.insert(path.clone(), count).is_some() {
                return Err(format!("duplicate census path {path}"));
            }
        }
        summed_paths += declared_paths;
        summed_lines += declared_lines;
    }
    if summed_paths != 71 || summed_lines != 159 || rows.len() != 71 {
        return Err("classified census aggregate drifted".to_owned());
    }
    Ok(rows)
}

fn collect_rs_files(root: &Path, output: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()))
        .map(|entry| entry.expect("directory entry must be readable"))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
        if file_type.is_dir() {
            let name = entry.file_name();
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            collect_rs_files(&path, output);
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

fn actual_census() -> BTreeMap<String, u64> {
    let root = repo_root();
    let mut files = Vec::new();
    for scope in ["src", "tests", "benches", "conformance", "fuzz/conformance"] {
        collect_rs_files(&root.join(scope), &mut files);
    }
    files.sort();
    files.dedup();

    let mut rows = BTreeMap::new();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let matching_lines = source
            .lines()
            .filter(|line| line.contains(CHRONO_TOKEN))
            .count() as u64;
        if matching_lines == 0 {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .expect("census path must be repository-relative")
            .to_string_lossy()
            .replace('\\', "/");
        rows.insert(relative, matching_lines);
    }
    rows
}

fn census_projection(rows: &BTreeMap<String, u64>) -> String {
    rows.iter()
        .map(|(path, count)| format!("{path}\t{count}\n"))
        .collect()
}

fn census_paths_projection(rows: &BTreeMap<String, u64>) -> String {
    rows.keys().map(|path| format!("{path}\n")).collect()
}

fn validate_census(inventory: &Value) -> Result<(), String> {
    let expected = expected_census(inventory)?;
    let actual = actual_census();
    if actual != expected {
        return Err("repository source census drifted from the exact classified map".to_owned());
    }
    if sha256_hex(census_projection(&actual).as_bytes()) != CENSUS_PROJECTION_SHA256
        || sha256_hex(census_paths_projection(&actual).as_bytes()) != CENSUS_PATHS_SHA256
    {
        return Err("repository census projection digest drifted".to_owned());
    }
    Ok(())
}

fn validate_alias_inventory(inventory: &Value) -> Result<(), String> {
    let alias = &inventory["alias_aware_chrono_uses"];
    if text(alias, "state")
        != "IMPORT_BINDINGS_AND_DIRECT_REFERENCES_COMPLETE_DERIVED_CLASSIFICATION_PARTIAL"
        || number(alias, "binding_path_count") != 4
        || number(alias, "binding_count") != 4
        || number(alias, "direct_reference_line_count") != 32
        || number(alias, "imported_symbol_occurrence_count") != 45
        || number(alias, "literal_namespace_overlap_line_count") != 4
        || number(alias, "new_line_count_beyond_literal_census") != 28
        || number(alias, "literal_or_alias_unique_line_count") != 187
        || number(alias, "derived_operation_anchor_line_count") != 8
    {
        return Err("alias-aware inventory totals drifted".to_owned());
    }
    require_exact_strings(
        alias,
        "absent_forms",
        &[
            "Chrono crate rename import",
            "extern crate Chrono declaration",
            "renamed imported Chrono symbol",
            "Chrono-backed type alias",
        ],
    )?;

    let bindings = array(alias, "bindings");
    require_exact_ids(
        bindings,
        "binding_id",
        &[
            "TIME-ALIAS-CLI-WORKFLOWS",
            "TIME-ALIAS-ROOT-HPACK-DIFFERENTIAL-TEST",
            "TIME-ALIAS-STANDALONE-MAINTENANCE",
            "TIME-ALIAS-STANDALONE-REGRESSION",
        ],
        "direct Chrono alias bindings",
    )?;
    let binding_by_id: BTreeMap<_, _> = bindings
        .iter()
        .map(|row| (text(row, "binding_id"), row))
        .collect();
    let expected_binding_facts = [
        (
            "TIME-ALIAS-CLI-WORKFLOWS",
            "src/cli/atp_workflows.rs",
            35_u64,
            format!("use {}Utc;", CHRONO_TOKEN),
            vec!["Utc"],
        ),
        (
            "TIME-ALIAS-ROOT-HPACK-DIFFERENTIAL-TEST",
            "tests/conformance/hpack_rfc7541/differential_tests.rs",
            358,
            format!("use {}Utc;", CHRONO_TOKEN),
            vec!["Utc"],
        ),
        (
            "TIME-ALIAS-STANDALONE-MAINTENANCE",
            "tests/conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs",
            12,
            format!("use {}{{DateTime, Duration, Utc}};", CHRONO_TOKEN),
            vec!["DateTime", "Duration", "Utc"],
        ),
        (
            "TIME-ALIAS-STANDALONE-REGRESSION",
            "tests/conformance/raptorq_rfc6330/reporting/src/regression_detection.rs",
            10,
            format!("use {}{{DateTime, Utc}};", CHRONO_TOKEN),
            vec!["DateTime", "Utc"],
        ),
    ];
    for (binding_id, path, import_line, import_source, imported_symbols) in
        expected_binding_facts
    {
        let binding = binding_by_id[binding_id];
        if text(binding, "path") != path
            || number(binding, "import_line") != import_line
            || text(binding, "import_source") != import_source
        {
            return Err(format!("{binding_id} import binding drifted"));
        }
        require_exact_strings(binding, "imported_symbols", &imported_symbols)?;
    }

    let profiles = row_ids(array(inventory, "dependency_profiles"), "profile_id");
    let migrations = row_ids(array(inventory, "migration_groups"), "group_id");
    let mut binding_paths = BTreeSet::new();
    let mut direct_pairs = BTreeSet::new();
    let mut overlap_pairs = BTreeSet::new();
    let mut derived_pairs = BTreeSet::new();
    let mut excluded_pairs = BTreeSet::new();
    let mut declared_occurrences = 0_u64;
    for binding in bindings {
        let path = text(binding, "path");
        binding_paths.insert(path.to_owned());
        if !profiles.contains(text(binding, "profile_id"))
            || !migrations.contains(text(binding, "migration_group_id"))
            || text(binding, "cfg_or_wiring").is_empty()
            || text(binding, "exposure").is_empty()
            || !text(binding, "owner_bead").starts_with("asupersync-")
        {
            return Err(format!(
                "{} classification metadata drifted",
                text(binding, "binding_id")
            ));
        }

        let direct_lines = number_set(binding, "direct_reference_lines");
        let overlap_lines = number_set(binding, "literal_namespace_overlap_lines");
        let derived_lines = number_set(binding, "derived_operation_lines");
        let excluded_lines = number_set(binding, "excluded_nonchrono_shadow_lines");
        if direct_lines.len() != array(binding, "direct_reference_lines").len()
            || overlap_lines.len() != array(binding, "literal_namespace_overlap_lines").len()
            || derived_lines.len() != array(binding, "derived_operation_lines").len()
            || excluded_lines.len() != array(binding, "excluded_nonchrono_shadow_lines").len()
            || !overlap_lines.is_subset(&direct_lines)
        {
            return Err(format!(
                "{} line sets drifted",
                text(binding, "binding_id")
            ));
        }
        for line in direct_lines {
            direct_pairs.insert((path.to_owned(), line));
        }
        for line in overlap_lines {
            overlap_pairs.insert((path.to_owned(), line));
        }
        for line in derived_lines {
            derived_pairs.insert((path.to_owned(), line));
        }
        for line in excluded_lines {
            excluded_pairs.insert((path.to_owned(), line));
        }
        declared_occurrences += number(binding, "imported_symbol_occurrence_count");
    }
    if binding_paths.len() != 4
        || direct_pairs.len() != 32
        || overlap_pairs.len() != 4
        || derived_pairs.len() != 8
        || declared_occurrences != 45
    {
        return Err("alias binding aggregates drifted".to_owned());
    }
    let expected_overlap_pairs: BTreeSet<_> = [236_u64, 399, 458, 1298]
        .into_iter()
        .map(|line| ("src/cli/atp_workflows.rs".to_owned(), line))
        .collect();
    if overlap_pairs != expected_overlap_pairs {
        return Err("literal and alias overlap set drifted".to_owned());
    }
    let expected_derived_pairs: BTreeSet<_> = [277_u64, 297, 394, 448, 504, 575, 580]
        .into_iter()
        .map(|line| {
            (
                "tests/conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs"
                    .to_owned(),
                line,
            )
        })
        .chain(std::iter::once((
            "tests/conformance/raptorq_rfc6330/reporting/src/regression_detection.rs"
                .to_owned(),
            314,
        )))
        .collect();
    if derived_pairs != expected_derived_pairs {
        return Err("derived temporal operation anchors drifted".to_owned());
    }
    let expected_excluded_pairs = BTreeSet::from([(
        "tests/conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs"
            .to_owned(),
        751_u64,
    )]);
    if excluded_pairs != expected_excluded_pairs {
        return Err("non-Chrono shadow exclusion set drifted".to_owned());
    }
    let Some(reconciled_new_lines) = number(alias, "direct_reference_line_count")
        .checked_sub(number(alias, "literal_namespace_overlap_line_count"))
    else {
        return Err("literal and alias overlap exceeds the direct line count".to_owned());
    };
    let Some(reconciled_union) = number(&inventory["chrono_census"], "matching_line_count")
        .checked_add(reconciled_new_lines)
    else {
        return Err("literal and alias union overflowed".to_owned());
    };
    if number(alias, "new_line_count_beyond_literal_census") != reconciled_new_lines
        || number(alias, "literal_or_alias_unique_line_count") != reconciled_union
    {
        return Err("literal and alias reconciliation arithmetic drifted".to_owned());
    }

    let operation_rows = array(alias, "operation_rows");
    if operation_rows.len() != 32
        || row_ids(operation_rows, "use_id").len() != operation_rows.len()
    {
        return Err("direct alias operation row identity drifted".to_owned());
    }
    let mut operation_pairs = BTreeSet::new();
    let mut operation_occurrences = 0_usize;
    for row in operation_rows {
        let binding_id = text(row, "binding_id");
        let Some(binding) = binding_by_id.get(binding_id).copied() else {
            return Err(format!("{} references an unknown binding", text(row, "use_id")));
        };
        let pair = (text(row, "path").to_owned(), number(row, "line"));
        if !operation_pairs.insert(pair.clone()) || !direct_pairs.contains(&pair) {
            return Err(format!("{} direct-use pair drifted", text(row, "use_id")));
        }
        if text(row, "path") != text(binding, "path")
            || text(row, "profile_id") != text(binding, "profile_id")
            || text(row, "cfg_or_wiring") != text(binding, "cfg_or_wiring")
            || text(row, "migration_group_id") != text(binding, "migration_group_id")
            || text(row, "owner_bead") != text(binding, "owner_bead")
            || text(row, "operation").is_empty()
            || text(row, "exposure").is_empty()
            || text(row, "persistence_or_public_association").is_empty()
        {
            return Err(format!("{} classification drifted", text(row, "use_id")));
        }
        let used_symbols = string_set(row, "imported_symbols_used");
        let imported_symbols = string_set(binding, "imported_symbols");
        if used_symbols.is_empty() || !used_symbols.is_subset(&imported_symbols) {
            return Err(format!("{} imported-symbol set drifted", text(row, "use_id")));
        }
        operation_occurrences += used_symbols.len();
        if row
            .get("literal_namespace_overlap")
            .and_then(Value::as_bool)
            != Some(overlap_pairs.contains(&pair))
        {
            return Err(format!("{} overlap classification drifted", text(row, "use_id")));
        }
    }
    if operation_pairs != direct_pairs || operation_occurrences != 45 {
        return Err(
            "direct alias references lack one-to-one operation and symbol rows".to_owned(),
        );
    }
    Ok(())
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_count(line: &str, identifier: &str) -> usize {
    line.match_indices(identifier)
        .filter(|(index, _)| {
            let bytes = line.as_bytes();
            let start = *index;
            let end = start + identifier.len();
            let left_boundary = start == 0 || !is_identifier_byte(bytes[start - 1]);
            let right_boundary = end == bytes.len() || !is_identifier_byte(bytes[end]);
            left_boundary && right_boundary
        })
        .count()
}

fn strip_keyword<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    let value = value.trim_start();
    let remainder = value.strip_prefix(keyword)?;
    if remainder
        .as_bytes()
        .first()
        .is_some_and(|byte| is_identifier_byte(*byte))
    {
        None
    } else {
        Some(remainder)
    }
}

fn after_leading_attributes(mut value: &str) -> &str {
    loop {
        value = value.trim_start();
        let Some(attribute) = value
            .strip_prefix("#[")
            .or_else(|| value.strip_prefix("#!["))
        else {
            return value;
        };
        let mut nesting = 1_u64;
        let mut end = None;
        for (index, character) in attribute.char_indices() {
            match character {
                '[' => nesting += 1,
                ']' => {
                    nesting -= 1;
                    if nesting == 0 {
                        end = Some(index + character.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            return value;
        };
        value = &attribute[end..];
    }
}

fn after_optional_visibility(value: &str) -> &str {
    let value = after_leading_attributes(value);
    let Some(remainder) = strip_keyword(value, "pub") else {
        return value;
    };
    let remainder = remainder.trim_start();
    if let Some(visibility) = remainder.strip_prefix('(')
        && let Some(end) = visibility.find(')')
    {
        return visibility[end + 1..].trim_start();
    }
    remainder
}

fn starts_direct_crate_path(value: &str, crate_name: &str) -> bool {
    let value = value.trim_start();
    let value = value
        .strip_prefix("::")
        .map_or(value, str::trim_start);
    let value = value.strip_prefix("r#").unwrap_or(value);
    let Some(remainder) = value.strip_prefix(crate_name) else {
        return false;
    };
    remainder
        .as_bytes()
        .first()
        .is_none_or(|byte| !is_identifier_byte(*byte))
}

fn root_use_group_contains_crate(value: &str, crate_name: &str) -> bool {
    let Some(group) = value.trim_start().strip_prefix('{') else {
        return false;
    };
    let mut nesting = 0_u64;
    let mut branch_start = 0_usize;
    for (index, character) in group.char_indices() {
        match character {
            '{' | '(' | '[' => nesting += 1,
            '}' | ')' | ']' if nesting > 0 => nesting -= 1,
            ',' if nesting == 0 => {
                if starts_direct_crate_path(&group[branch_start..index], crate_name) {
                    return true;
                }
                branch_start = index + character.len_utf8();
            }
            '}' if nesting == 0 => {
                return starts_direct_crate_path(&group[branch_start..index], crate_name);
            }
            _ => {}
        }
    }
    starts_direct_crate_path(&group[branch_start..], crate_name)
}

fn direct_crate_use_tree(value: &str, crate_name: &str) -> bool {
    let value = value.trim_start();
    starts_direct_crate_path(value, crate_name)
        || value
            .strip_prefix("::")
            .is_some_and(|value| root_use_group_contains_crate(value, crate_name))
        || root_use_group_contains_crate(value, crate_name)
}

fn find_last_keyword(value: &str, keyword: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    value
        .match_indices(keyword)
        .rev()
        .find_map(|(index, _)| {
            let end = index + keyword.len();
            let left_boundary = index == 0 || !is_identifier_byte(bytes[index - 1]);
            let right_boundary = end == bytes.len() || !is_identifier_byte(bytes[end]);
            let raw_identifier = index >= 2 && bytes.get(index - 2..index) == Some(b"r#");
            (left_boundary && right_boundary && !raw_identifier).then_some(index)
        })
}

fn statement_line(statement: &str, start_line: u64, keyword_index: usize) -> u64 {
    start_line
        + statement[..keyword_index]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count() as u64
}

fn direct_chrono_binding_line(
    statement: &str,
    start_line: u64,
    chrono_name: &str,
) -> Option<u64> {
    if let Some(use_index) = find_last_keyword(statement, "use")
        && direct_crate_use_tree(&statement[use_index + "use".len()..], chrono_name)
    {
        return Some(statement_line(statement, start_line, use_index));
    }
    if let Some(extern_index) = find_last_keyword(statement, "extern") {
        let remainder = &statement[extern_index + "extern".len()..];
        if let Some(crate_tail) = strip_keyword(remainder, "crate")
            && starts_direct_crate_path(crate_tail, chrono_name)
        {
            return Some(statement_line(statement, start_line, extern_index));
        }
    }
    None
}

#[derive(Default)]
struct RustLexState {
    block_comment_depth: usize,
    in_quoted_string: bool,
    quoted_escape: bool,
    raw_string_hashes: Option<usize>,
}

fn raw_string_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut cursor = start;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hash_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    Some((cursor + 1 - start, cursor - hash_start))
}

fn char_literal_consumed(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let content = start + 1;
    let closing = if bytes.get(content) == Some(&b'\\') {
        match (bytes.get(content + 1), bytes.get(content + 2)) {
            (Some(b'u'), Some(b'{')) => {
                let end = bytes.get(content + 3..)?.iter().position(|byte| *byte == b'}')?;
                content + 4 + end
            }
            (Some(b'x'), _) => content + 4,
            (Some(_), _) => content + 2,
            _ => return None,
        }
    } else {
        let character = std::str::from_utf8(bytes.get(content..)?).ok()?.chars().next()?;
        content + character.len_utf8()
    };
    (bytes.get(closing) == Some(&b'\'')).then_some(closing + 1 - start)
}

fn strip_rust_non_code(line: &str, state: &mut RustLexState) -> String {
    let bytes = line.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        let pair = bytes.get(index..index + 2);
        if state.block_comment_depth > 0 {
            if pair == Some(b"/*") {
                state.block_comment_depth += 1;
                index += 2;
            } else if pair == Some(b"*/") {
                state.block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
        } else if let Some(hash_count) = state.raw_string_hashes {
            let hash_end = index + 1 + hash_count;
            if bytes[index] == b'"'
                && bytes
                    .get(index + 1..hash_end)
                    .is_some_and(|hashes| hashes.iter().all(|byte| *byte == b'#'))
            {
                state.raw_string_hashes = None;
                index = hash_end;
            } else {
                index += 1;
            }
        } else if state.in_quoted_string {
            if state.quoted_escape {
                state.quoted_escape = false;
            } else if bytes[index] == b'\\' {
                state.quoted_escape = true;
            } else if bytes[index] == b'"' {
                state.in_quoted_string = false;
            }
            index += 1;
        } else if pair == Some(b"//") {
            break;
        } else if pair == Some(b"/*") {
            state.block_comment_depth += 1;
            index += 2;
            output.push(b' ');
        } else if let Some((consumed, hash_count)) = raw_string_open(bytes, index) {
            state.raw_string_hashes = Some(hash_count);
            index += consumed;
            output.push(b' ');
        } else if let Some(consumed) = char_literal_consumed(bytes, index) {
            index += consumed;
            output.push(b' ');
        } else if bytes[index] == b'"' {
            state.in_quoted_string = true;
            state.quoted_escape = false;
            index += 1;
            output.push(b' ');
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    if state.in_quoted_string {
        state.quoted_escape = false;
    }
    String::from_utf8(output).expect("lexically stripped Rust source must remain UTF-8")
}

fn validate_alias_sources(inventory: &Value) -> Result<(), String> {
    let alias = &inventory["alias_aware_chrono_uses"];
    let bindings = array(alias, "bindings");
    let root = repo_root();
    let mut files = Vec::new();
    for scope in ["src", "tests", "benches", "conformance", "fuzz/conformance"] {
        collect_rs_files(&root.join(scope), &mut files);
    }
    files.sort();
    files.dedup();

    let chrono_name = CHRONO_TOKEN.trim_end_matches("::");
    let direct_namespace = format!("{chrono_name}::");
    let mut actual_binding_lines = BTreeSet::new();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .expect("alias path must be repository-relative")
            .to_string_lossy()
            .replace('\\', "/");
        let mut lex_state = RustLexState::default();
        let mut statement = String::new();
        let mut statement_start_line = 1_u64;
        for (index, line) in source.lines().enumerate() {
            let line_number = index as u64 + 1;
            let code = strip_rust_non_code(line, &mut lex_state);
            let trimmed = code.trim();
            let is_type_declaration =
                strip_keyword(after_optional_visibility(trimmed), "type").is_some();
            if is_type_declaration && trimmed.contains(&direct_namespace) {
                return Err(format!(
                    "fully qualified Chrono-backed type alias appeared at {relative}:{line_number}"
                ));
            }

            let mut remainder = code.as_str();
            loop {
                if statement.is_empty() {
                    statement_start_line = line_number;
                }
                if let Some(end) = remainder.find(';') {
                    statement.push_str(&remainder[..=end]);
                    if let Some(binding_line) =
                        direct_chrono_binding_line(&statement, statement_start_line, chrono_name)
                    {
                        actual_binding_lines.insert((relative.clone(), binding_line));
                    }
                    statement.clear();
                    remainder = &remainder[end + 1..];
                    if remainder.is_empty() {
                        break;
                    }
                } else {
                    statement.push_str(remainder);
                    statement.push('\n');
                    break;
                }
            }
        }
        if let Some(binding_line) =
            direct_chrono_binding_line(&statement, statement_start_line, chrono_name)
        {
            actual_binding_lines.insert((relative, binding_line));
        }
    }
    let expected_binding_lines: BTreeSet<_> = bindings
        .iter()
        .map(|binding| {
            (
                text(binding, "path").to_owned(),
                number(binding, "import_line"),
            )
        })
        .collect();
    if actual_binding_lines != expected_binding_lines {
        return Err("repository direct Chrono import set drifted".to_owned());
    }

    let operation_rows = array(alias, "operation_rows");
    let mut actual_occurrences = 0_u64;
    for binding in bindings {
        let path = text(binding, "path");
        let source = read_repo_file(path);
        let lines: Vec<_> = source.lines().collect();
        let import_line = number(binding, "import_line");
        let import_index = usize::try_from(import_line - 1)
            .map_err(|_| format!("{path} import line overflowed usize"))?;
        if lines.get(import_index).map(|line| line.trim())
            != Some(text(binding, "import_source"))
        {
            return Err(format!("{path} import source drifted"));
        }
        let imported_symbols = string_set(binding, "imported_symbols");
        let excluded_lines = number_set(binding, "excluded_nonchrono_shadow_lines");
        let expected_lines = number_set(binding, "direct_reference_lines");
        let expected_overlap = number_set(binding, "literal_namespace_overlap_lines");
        let mut actual_lines = BTreeSet::new();
        let mut actual_overlap = BTreeSet::new();
        let mut binding_occurrences = 0_u64;
        for (index, line) in lines.iter().enumerate() {
            let line_number = index as u64 + 1;
            let trimmed = line.trim_start();
            if line_number == import_line
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
            {
                continue;
            }
            let occurrences: usize = imported_symbols
                .iter()
                .map(|symbol| identifier_count(line, symbol))
                .sum();
            let is_type_declaration =
                strip_keyword(after_optional_visibility(trimmed), "type").is_some();
            if is_type_declaration && occurrences > 0 {
                return Err(format!(
                    "import-backed Chrono type alias appeared at {path}:{line_number}"
                ));
            }
            if occurrences == 0 || excluded_lines.contains(&line_number) {
                continue;
            }
            actual_lines.insert(line_number);
            binding_occurrences += occurrences as u64;
            if line.contains(CHRONO_TOKEN) {
                actual_overlap.insert(line_number);
            }
        }
        if actual_lines != expected_lines
            || actual_overlap != expected_overlap
            || binding_occurrences != number(binding, "imported_symbol_occurrence_count")
        {
            return Err(format!("{path} direct alias references drifted"));
        }
        actual_occurrences += binding_occurrences;

        for row in operation_rows
            .iter()
            .filter(|row| text(row, "binding_id") == text(binding, "binding_id"))
        {
            let line_number = number(row, "line");
            let index = usize::try_from(line_number - 1)
                .map_err(|_| format!("{path}:{line_number} overflowed usize"))?;
            let line = lines
                .get(index)
                .ok_or_else(|| format!("{path}:{line_number} is outside the source file"))?;
            let actual_symbols: BTreeSet<_> = imported_symbols
                .iter()
                .filter(|symbol| identifier_count(line, symbol) > 0)
                .cloned()
                .collect();
            if actual_symbols != string_set(row, "imported_symbols_used")
                || row
                    .get("literal_namespace_overlap")
                    .and_then(Value::as_bool)
                    != Some(line.contains(CHRONO_TOKEN))
            {
                return Err(format!("{} source classification drifted", text(row, "use_id")));
            }
        }
    }
    if actual_occurrences != number(alias, "imported_symbol_occurrence_count") {
        return Err("direct imported-symbol occurrence total drifted".to_owned());
    }
    Ok(())
}

fn validate_source_pins(inventory: &Value) -> Result<(), String> {
    let pins = array(&inventory["source_snapshot"], "files");
    if pins.len() != 67 {
        return Err("source pin count drifted".to_owned());
    }
    let mut paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        if !paths.insert(path.to_owned()) {
            return Err(format!("duplicate source pin {path}"));
        }
        let bytes = read_repo_bytes(path);
        if sha256_hex(&bytes) != text(pin, "sha256") {
            return Err(format!("source pin hash drifted for {path}"));
        }
        let source = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("source pin {path} must be UTF-8: {error}"));
        if source.lines().count() as u64 != number(pin, "line_count") {
            return Err(format!("source pin line count drifted for {path}"));
        }
    }
    Ok(())
}

fn count_matching_lines(source: &str, token: &str) -> usize {
    source.lines().filter(|line| line.contains(token)).count()
}

fn validate_source_markers(inventory: &Value) -> Result<(), String> {
    let manifest = read_repo_file("Cargo.toml");
    for marker in [
        "time = { version = \">=0.3\", features = [\"formatting\"], optional = true }",
        "chrono = { version = \"0.4\", features = [\"serde\"], optional = true }",
        "tls-native-roots = [\"tls\", \"dep:rustls-native-certs\"]",
        "tls-webpki-roots = [\"tls\", \"dep:webpki-roots\"]",
        "atp-cli = [\"dep:clap\", \"tls\", \"dep:rustls-native-certs\"]",
        "atpd-daemon = [\"cli\", \"dep:tracing-subscriber\"]",
    ] {
        if !manifest.contains(marker) {
            return Err(format!("root manifest marker drifted: {marker}"));
        }
    }
    if !manifest.contains("\"dep:time\"")
        || !manifest.contains("\"dep:chrono\"")
        || !manifest.contains("benchmark-adapters = [")
        || !manifest.contains("ci-cross-platform = [")
    {
        return Err("root feature edge markers drifted".to_owned());
    }
    if !manifest.contains("name = \"offline_tuner\"")
        || !manifest.contains("path = \"src/bin/offline_tuner.rs\"")
        || !manifest.contains("required-features = [\"cli\", \"simd-intrinsics\"]")
    {
        return Err("offline tuner target profile drifted".to_owned());
    }
    let fuzz_manifest = read_repo_file("fuzz/Cargo.toml");
    if !fuzz_manifest.contains("[workspace]\nmembers = [\"conformance\"]")
        || !fuzz_manifest.contains("\"tls\"")
        || !fuzz_manifest.contains("\"benchmark-adapters\"")
    {
        return Err("excluded fuzz workspace feature route drifted".to_owned());
    }
    let excluded_conformance_manifest = read_repo_file("fuzz/conformance/Cargo.toml");
    let external_chrono_dependency = format!(
        "{} = {{ version = \"0.4\", features = [\"serde\"] }}",
        CHRONO_TOKEN.trim_end_matches("::")
    );
    if !excluded_conformance_manifest.contains(&external_chrono_dependency) {
        return Err("excluded conformance direct chrono edge drifted".to_owned());
    }

    let owned_time = read_repo_file("src/time/utc.rs");
    let owned_mod = read_repo_file("src/time/mod.rs");
    if owned_time.contains(CHRONO_TOKEN)
        || owned_time.contains("OffsetDateTime")
        || owned_mod.contains(CHRONO_TOKEN)
        || !owned_time.contains("pub fn format_unix_nanos_rfc3339(unix_nanos: u64) -> String")
        || !owned_mod.contains("pub use utc::format_unix_nanos_rfc3339;")
    {
        return Err("owned UTC formatter boundary drifted".to_owned());
    }

    let cli_binary = read_repo_file("src/bin/asupersync.rs");
    let old_call = format!("{}OffsetDateTime", EXTERNAL_TIME_TOKEN);
    if !cli_binary.contains("format_unix_nanos_rfc3339(recorded_at_nanos)")
        || cli_binary.contains(&old_call)
    {
        return Err("CLI owned formatter route drifted".to_owned());
    }

    let command_tree = read_repo_file("src/cli/atp_command_tree.rs");
    let workflows = read_repo_file("src/cli/atp_workflows.rs");
    let benchmark_mod = read_repo_file("src/atp/benchmark/mod.rs");
    let benchmark_reports = read_repo_file("src/atp/benchmark/reports.rs");
    let duration_default = format!(
        "{}Duration::from_std(duration).unwrap_or_default()",
        CHRONO_TOKEN
    );
    let duration_optional = format!("{}Duration::from_std(duration).ok()", CHRONO_TOKEN);
    if count_matching_lines(&command_tree, CHRONO_TOKEN) != 10
        || count_matching_lines(&workflows, CHRONO_TOKEN) != 5
        || count_matching_lines(&benchmark_mod, CHRONO_TOKEN) != 3
        || count_matching_lines(&benchmark_reports, CHRONO_TOKEN) != 2
        || !workflows.contains(&duration_default)
        || count_matching_lines(&workflows, &duration_optional) != 3
        || !workflows.contains("serde_json::to_vec_pretty")
        || !workflows.contains("serde_json::from_slice")
    {
        return Err("production chrono owner or arithmetic markers drifted".to_owned());
    }

    let root_type = format!("{}DateTime<{}Utc>", CHRONO_TOKEN, CHRONO_TOKEN);
    let root_public_lines = command_tree
        .lines()
        .chain(benchmark_mod.lines())
        .chain(benchmark_reports.lines())
        .filter(|line| line.contains("pub ") && line.contains(&root_type))
        .count();
    if root_public_lines != 12 {
        return Err("root public concrete UTC field count drifted".to_owned());
    }

    let conformance_public_lines: usize = [
        "conformance/src/h2_data_end_stream_conformance.rs",
        "conformance/src/h2_goaway_conformance.rs",
        "conformance/src/h2_ping_conformance.rs",
        "conformance/src/h2_priority_conformance.rs",
        "conformance/src/h2_settings_conformance.rs",
        "conformance/src/hpack_conformance.rs",
    ]
    .iter()
    .map(|path| {
        read_repo_file(path)
            .lines()
            .filter(|line| line.contains("pub timestamp:") && line.contains(&root_type))
            .count()
    })
    .sum();
    if conformance_public_lines != 6 {
        return Err("conformance concrete UTC field count drifted".to_owned());
    }
    for path in [
        "conformance/src/h2_settings_conformance.rs",
        "conformance/src/hpack_conformance.rs",
    ] {
        if !read_repo_file(path).contains("pub struct ComplianceReport") {
            return Err(format!("typed conformance report name drifted in {path}"));
        }
    }

    let conformance_lib = read_repo_file("conformance/src/lib.rs");
    let reporting_mod = read_repo_file("conformance/raptorq_rfc6330/reporting/src/mod.rs");
    if !conformance_lib.contains("#[path = \"../raptorq_rfc6330/reporting/src/mod.rs\"]")
        || !conformance_lib.contains("pub mod raptorq_rfc6330_reporting;")
        || !reporting_mod.contains("pub mod coverage_matrix;")
        || !reporting_mod.contains("pub mod maintenance_workflows;")
        || !reporting_mod.contains("pub mod regression_detection;")
    {
        return Err("wired conformance RaptorQ reporting route drifted".to_owned());
    }
    let root_conformance_target = read_repo_file("tests/conformance.rs");
    let root_conformance_mod = read_repo_file("tests/conformance/mod.rs");
    let hpack_mod = read_repo_file("tests/conformance/hpack_rfc7541/mod.rs");
    let jetstream_target = read_repo_file("tests/jetstream_real_server.rs");
    if !root_conformance_target.contains("#[path = \"conformance/mod.rs\"]\nmod conformance;")
        || !root_conformance_mod.contains("// pub mod codec_framing;")
        || !root_conformance_mod.contains("pub mod hpack_rfc7541;")
        || !hpack_mod.contains("mod differential_tests;")
        || !hpack_mod.contains("mod fixtures;")
        || !jetstream_target
            .contains("#[path = \"integration/jetstream_real_server.rs\"]\nmod jetstream_real_server;")
    {
        return Err("root integration wiring classification drifted".to_owned());
    }

    let rendered_call = format!("let timestamp = {}Utc::now().to_rfc3339();", CHRONO_TOKEN);
    for (path, structure) in [
        (
            "conformance/src/h1_expect_continue_conformance.rs",
            "pub struct ExpectContinueComplianceReport",
        ),
        (
            "conformance/src/h1_request_building_conformance.rs",
            "pub struct RequestBuildingComplianceReport",
        ),
        (
            "conformance/src/h1_response_building_conformance.rs",
            "pub struct ResponseBuildingComplianceReport",
        ),
        (
            "conformance/src/h2_enable_push_conformance.rs",
            "pub struct EnablePushComplianceReport",
        ),
        (
            "conformance/src/h2_connect_method_conformance.rs",
            "pub struct ConnectMethodComplianceReport",
        ),
        (
            "conformance/src/h2_continuation_conformance.rs",
            "pub struct ContinuationComplianceReport",
        ),
        (
            "conformance/src/hpack_encoder_conformance.rs",
            "pub struct HpackEncoderComplianceReport",
        ),
    ] {
        let source = read_repo_file(path);
        if !source.contains(structure)
            || !source.contains("#[derive(Debug, Clone, Serialize)]")
            || !source.contains("pub timestamp: String")
            || !source.contains(&rendered_call)
        {
            return Err(format!("public rendered timestamp surface drifted in {path}"));
        }
    }

    let now_render = format!("{}Utc::now().to_rfc3339()", CHRONO_TOKEN);
    for (path, structure, field, assignment) in [
        (
            "conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs",
            "pub struct ReferenceVersion",
            "pub last_updated: String",
            format!("last_updated: {now_render}"),
        ),
        (
            "conformance/raptorq_rfc6330/reporting/src/coverage_matrix.rs",
            "pub struct CoverageMatrix",
            "pub generated_at: String",
            format!("generated_at: {now_render}"),
        ),
        (
            "conformance/raptorq_rfc6330/reporting/src/regression_detection.rs",
            "pub struct ConformanceRecord",
            "pub timestamp: String",
            "timestamp: matrix.generated_at.clone()".to_owned(),
        ),
        (
            "conformance/raptorq_rfc6330/reporting/src/regression_detection.rs",
            "pub struct ConformanceHistory",
            "pub last_updated: String",
            format!("last_updated: {now_render}"),
        ),
    ] {
        let source = read_repo_file(path);
        if !source.contains(structure)
            || !source.contains("#[derive(Debug, Clone, Serialize, Deserialize)]")
            || !source.contains(field)
            || !source.contains(&assignment)
        {
            return Err(format!("wired RaptorQ timestamp surface drifted in {path}"));
        }
    }

    let excluded_ping =
        read_repo_file("fuzz/conformance/src/h2_ping_rtt_measurement_conformance.rs");
    if !excluded_ping.contains("pub struct ConformanceReport")
        || !excluded_ping.contains("#[derive(Debug, Clone, Serialize, Deserialize)]")
        || !excluded_ping.contains("pub timestamp: String")
        || count_matching_lines(&excluded_ping, &now_render) != 2
    {
        return Err("excluded conformance timestamp report drifted".to_owned());
    }
    let history =
        read_repo_file("conformance/raptorq_rfc6330/reporting/src/regression_detection.rs");
    if !history.contains("serde_json::from_str(&contents)")
        || !history.contains("r.timestamp.as_str() > since")
    {
        return Err("plain-string conformance history semantics drifted".to_owned());
    }

    let release_proof = read_repo_file("src/agent_swarm/release_proof_aggregator.rs");
    if !release_proof.contains("fn parse_utc_system_time(value: &str) -> Option<SystemTime>")
        || !release_proof.contains("split_rfc3339_time_and_offset")
        || !release_proof.contains(".split('.')")
        || !release_proof.contains("second > 60")
        || !release_proof.contains("utc_seconds < 0")
    {
        return Err("owned release-proof timestamp parser drifted".to_owned());
    }

    let conformance_rfc = read_repo_file("conformance/src/raptorq_rfc6330.rs");
    if !conformance_rfc.contains("pub timestamp: std::time::SystemTime")
        || !conformance_rfc.contains("pub generated_at: std::time::SystemTime")
        || !conformance_rfc.contains("pub struct ConformanceLogEntry")
        || !conformance_rfc.contains(".unwrap_or_default()\n                .as_secs()\n                .to_string()")
    {
        return Err("non-chrono conformance temporal surface drifted".to_owned());
    }

    let trace = read_repo_file("src/trace/replay.rs");
    if !trace.contains("pub recorded_at: u64")
        || !trace.contains("recorded_at: 0")
        || !cli_binary.contains("created_at: format_timestamp(recorded_at)")
        || !cli_binary.contains("if recorded_at_nanos == 0")
    {
        return Err("trace metadata UTC rendering surface drifted".to_owned());
    }
    let atp_log = read_repo_file("src/atp/logging/mod.rs");
    let atp_golden = read_repo_file("tests/atp/golden_logs/direct_success.jsonl");
    if !atp_log.contains("pub struct AtpEvent")
        || !atp_log.contains("pub timestamp: String")
        || !atp_log.contains("serde_json::to_string(event)")
        || !atp_log.contains("duration_since(std::time::UNIX_EPOCH)\n        .map_or(0")
        || !atp_golden.contains("\"timestamp\":\"2026-05-24T00:00:00Z\"")
    {
        return Err("ATP event log timestamp surface drifted".to_owned());
    }
    let jetstream = read_repo_file("src/messaging/jetstream.rs");
    if !jetstream.contains(r#"\"opt_start_time\":\"{}\""#)
        || !jetstream.contains("fn format_system_time_rfc3339(time: SystemTime) -> String")
        || !jetstream.contains(".{nanos:09}Z")
    {
        return Err("JetStream start-time wire surface drifted".to_owned());
    }
    let offline_library = read_repo_file("src/raptorq/offline_tuner.rs");
    let offline_binary = read_repo_file("src/bin/offline_tuner.rs");
    if !offline_library.contains("pub benchmark_timestamp: String")
        || !offline_library.contains("benchmark_timestamp: format!(\"t_ns={}")
        || !offline_binary.contains("\"generated_at\": format!(\"{:?}\", std::time::SystemTime::now())")
    {
        return Err("offline tuner temporal metadata drifted".to_owned());
    }
    let raptorq_benchmark = read_repo_file("benches/raptorq_benchmark.rs");
    let chrono_now = format!("{}Utc::now().format", CHRONO_TOKEN);
    if count_matching_lines(&raptorq_benchmark, &chrono_now) != 2
        || !raptorq_benchmark.contains("%Y-%m-%dT%H:%M:%S%.3fZ")
    {
        return Err("RaptorQ benchmark event timestamp drifted".to_owned());
    }

    for path in ["src/database/postgres.rs", "src/messaging/redis.rs"] {
        let source = read_repo_file(path);
        let test_module = source
            .find("\nmod tests {\n")
            .ok_or_else(|| format!("{path} lost its test boundary"))?;
        let prefix = &source[..test_module];
        let Some(cfg_guard) = prefix.rfind("#[cfg(test)]") else {
            return Err(format!("{path} test module lost its cfg guard"));
        };
        if prefix[cfg_guard..].lines().count() > 8 {
            return Err(format!("{path} test module cfg guard moved away from the module"));
        }
        if prefix.contains(CHRONO_TOKEN) {
            return Err(format!("{path} gained a production chrono reference"));
        }
        if count_matching_lines(&source[test_module..], CHRONO_TOKEN) != 4
            || count_matching_lines(&source, CHRONO_TOKEN) != 4
        {
            return Err(format!("{path} test chrono census drifted"));
        }
    }
    let postgres = read_repo_file("src/database/postgres.rs");
    let chrono_date = format!("{}NaiveDate::from_ymd_opt", CHRONO_TOKEN);
    let chrono_delta = format!("{}TimeDelta::microseconds", CHRONO_TOKEN);
    if !postgres.contains(&chrono_date)
        || !postgres.contains(&chrono_delta)
        || !postgres.contains("fn sqlx_reference_interval_to_text(data: &[u8]) -> String")
        || !postgres.contains("render_interval_text(months, days, microseconds)")
    {
        return Err("PostgreSQL temporal oracle scope drifted".to_owned());
    }

    let external_import = format!(
        "use {}format_description::well_known::Rfc3339;",
        EXTERNAL_TIME_TOKEN
    );
    let external_call = format!(
        "let incumbent = {}OffsetDateTime::from_unix_timestamp_nanos",
        EXTERNAL_TIME_TOKEN
    );
    let prior_contract = read_repo_file("tests/time_utc_rfc3339_foundation_contract.rs");
    if !prior_contract.contains(&external_import) || !prior_contract.contains(&external_call) {
        return Err("prior external-time oracle source shape drifted".to_owned());
    }

    let external_offset = format!("{}OffsetDateTime", EXTERNAL_TIME_TOKEN);
    let external_format = format!("{}format_description", EXTERNAL_TIME_TOKEN);
    let external_use = format!("use {}", EXTERNAL_TIME_TOKEN);
    let absolute_external_use = format!("use ::{}", EXTERNAL_TIME_TOKEN);
    let mut production_candidates = Vec::new();
    let mut production_files = Vec::new();
    collect_rs_files(&repo_root().join("src"), &mut production_files);
    for path in production_files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for (line_index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with(&external_use)
                || trimmed.starts_with(&absolute_external_use)
                || line.contains(&external_offset)
                || line.contains(&external_format)
            {
                production_candidates.push(format!("{}:{}", path.display(), line_index + 1));
            }
        }
    }
    if !production_candidates.is_empty() {
        return Err(format!(
            "bounded external-time production scan gained candidates: {}",
            production_candidates.join(", ")
        ));
    }
    let external = object(inventory, "external_time_crate_census");
    if external.get("production_source_path_count").and_then(Value::as_u64) != Some(0)
        || external.get("production_call_count").and_then(Value::as_u64) != Some(0)
        || external.get("classification").and_then(Value::as_str)
            != Some("DIRECT_EDGE_RETAINED_WITHOUT_PRODUCTION_CALL")
    {
        return Err("external-time source classification drifted".to_owned());
    }
    Ok(())
}

fn validate_foundation_boundary(inventory: &Value) -> Result<(), String> {
    let foundation = object(inventory, "foundation_cross_reference");
    if foundation.get("bead_id").and_then(Value::as_str) != Some("asupersync-d24mms.4")
        || foundation.get("artifact").and_then(Value::as_str)
            != Some("artifacts/time_utc_rfc3339_foundation_v1.json")
        || foundation.get("evidence_reuse").and_then(Value::as_str)
            != Some("PRIOR_SCOPED_ONLY")
    {
        return Err("prior foundation boundary drifted".to_owned());
    }
    require_exact_strings(
        &Value::Object(foundation.clone()),
        "excluded_from_a1_claims",
        &[
            "dependency removal",
            "fresh execution in A1",
            "leap seconds",
            "negative instants",
            "numeric offsets",
            "persisted chrono documents",
            "public chrono fields",
            "RFC3339 parsing",
            "timezone database semantics",
        ],
    )?;

    let validation = object(inventory, "validation");
    if validation.get("contract_path").and_then(Value::as_str) != Some(CONTRACT_PATH) {
        return Err("validation contract path drifted".to_owned());
    }
    if validation.get("doc_path").and_then(Value::as_str) != Some(DOC_PATH)
        || validation.get("contract_execution").and_then(Value::as_str)
            != Some("NOT_EXECUTED_THIS_TURN")
    {
        return Err("validation no-execution receipt drifted".to_owned());
    }
    require_exact_strings(
        inventory,
        "no_claim_boundaries",
        &[
            "No compiler, formatter, test, contract, benchmark, service, remote job, or runtime lane was executed for A1.",
            "This inventory does not establish calendar, parser, formatter, serde, arithmetic, or clock correctness.",
            "This inventory does not establish persisted readback, exact bytes, atomicity, migration compatibility, or historical-corpus coverage.",
            "This inventory does not establish PostgreSQL, Redis, conformance, external-service, sparse-feature, cross-platform, or downstream behavior.",
            "This inventory does not establish resource bounds, malformed-input safety, performance, broad workspace health, or release readiness.",
            "Prior foundation receipts are not fresh A1 execution evidence and remain limited to their recorded scope.",
            "No dependency removal, cutover, tracker closure, or permission to delete files follows from this artifact.",
        ],
    )?;
    if array(inventory, "registry_reconciliation").iter().any(|row| {
        row.get("state").and_then(Value::as_str) != Some("ROUTED_NOT_MUTATED_BY_A1")
            || text(row, "finding").is_empty()
            || text(row, "current_fact").is_empty()
    }) {
        return Err("registry reconciliation routing drifted".to_owned());
    }
    if array(inventory, "migration_groups").iter().any(|row| {
        !text(row, "owner_bead").starts_with("asupersync-")
            || text(row, "responsibility").is_empty()
            || text(row, "collision_boundary").is_empty()
    }) {
        return Err("migration ownership or collision boundary drifted".to_owned());
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    validate_identity(inventory)?;
    validate_exact_row_sets(inventory)?;
    validate_locked_packages(inventory)?;
    validate_public_and_persisted_counts(inventory)?;
    expected_census(inventory)?;
    validate_alias_inventory(inventory)?;
    validate_foundation_boundary(inventory)?;
    Ok(())
}

#[test]
fn time_utc_inventory_is_exact_and_source_pinned() {
    let inventory = artifact();
    validate_inventory(&inventory).expect("inventory structure must remain fail-closed");
    validate_source_pins(&inventory).expect("source pins must match the frozen snapshot");
    validate_census(&inventory).expect("all source paths must remain exactly classified");
    validate_alias_sources(&inventory)
        .expect("direct Chrono imports and imported-symbol references must remain exact");
    validate_source_markers(&inventory).expect("source and manifest markers must remain current");

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "12 concrete Chrono UTC fields",
        "four timestamp-bearing JSON families",
        "32 alias-bearing code lines",
        "187 unique",
        "bounded lexical scan of production source finds zero external",
        "This is not compiler-resolved name analysis.",
        "17 public Chrono-backed timestamp fields",
        "partial static inventory only",
        "bead_close_allowed=false",
        "the bead must not be closed",
        "No compiler, formatter, test, benchmark, service, remote job, or runtime lane",
    ] {
        assert!(docs.contains(marker), "documentation marker drifted: {marker}");
    }
}

#[test]
fn time_utc_inventory_rejects_cutover_and_completeness_drift() {
    let inventory = artifact();

    let mut cutover = inventory.clone();
    cutover["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&cutover).is_err());

    let mut unclassified = inventory.clone();
    unclassified["policy"]["unclassified_chrono_paths"] = Value::from(1_u64);
    assert!(validate_inventory(&unclassified).is_err());

    let mut public_field = inventory.clone();
    public_field["public_datetime_fields"]
        .as_array_mut()
        .expect("public fields must be an array")
        .pop();
    assert!(validate_inventory(&public_field).is_err());

    let mut store = inventory.clone();
    store["persisted_and_output_surfaces"]
        .as_array_mut()
        .expect("surfaces must be an array")
        .retain(|row| row["surface_id"] != "TIME-SURFACE-CLI-DATASET-INDEX");
    assert!(validate_inventory(&store).is_err());

    let mut alias_binding = inventory.clone();
    alias_binding["alias_aware_chrono_uses"]["bindings"]
        .as_array_mut()
        .expect("alias bindings must be an array")
        .pop();
    assert!(validate_inventory(&alias_binding).is_err());

    let mut alias_operation = inventory.clone();
    alias_operation["alias_aware_chrono_uses"]["operation_rows"]
        .as_array_mut()
        .expect("alias operations must be an array")
        .pop();
    assert!(validate_inventory(&alias_operation).is_err());

    let mut alias_total = inventory.clone();
    alias_total["alias_aware_chrono_uses"]["direct_reference_line_count"] =
        Value::from(31_u64);
    assert!(validate_inventory(&alias_total).is_err());

    let mut path = inventory;
    path["chrono_census"]["classification_groups"][0]["paths"]
        .as_array_mut()
        .expect("census paths must be an array")
        .pop();
    assert!(validate_inventory(&path).is_err());
}

#[test]
fn time_utc_alias_binding_lexer_covers_legal_lexical_forms() {
    let chrono_name = CHRONO_TOKEN.trim_end_matches("::");
    let cases = [
        (format!("use {chrono_name};"), 11_u64, 11_u64),
        (format!("pub(crate) use ::r#{chrono_name};"), 12, 12),
        (format!("use {{other, {chrono_name}}};"), 13, 13),
        (format!("use other; use {chrono_name};"), 14, 14),
        (format!("fn local() {{ use {chrono_name}; }}"), 15, 15),
        (format!("extern\ncrate {chrono_name};"), 16, 16),
        (format!("#[cfg(test)]\nuse {chrono_name};"), 17, 18),
    ];
    for (statement, start_line, expected_line) in cases {
        assert_eq!(
            direct_chrono_binding_line(&statement, start_line, chrono_name),
            Some(expected_line)
        );
    }

    for source in [
        format!("let text = \"use {chrono_name};\"; use {chrono_name};"),
        format!("let text = r#\"use {chrono_name};\"#; use {chrono_name};"),
        format!("/* use {chrono_name}; */ use {chrono_name};"),
        format!("let marker = ';'; use {chrono_name};"),
    ] {
        let mut state = RustLexState::default();
        let code = strip_rust_non_code(&source, &mut state);
        assert_eq!(direct_chrono_binding_line(&code, 1, chrono_name), Some(1));
    }
}

#[test]
fn time_utc_prior_foundation_stays_prior_and_scoped() {
    let inventory = artifact();
    validate_foundation_boundary(&inventory).expect("foundation scope must remain bounded");

    let foundation = &inventory["foundation_cross_reference"];
    assert_eq!(foundation["evidence_reuse"], "PRIOR_SCOPED_ONLY");
    assert!(
        array(foundation, "excluded_from_a1_claims")
            .iter()
            .any(|value| value == "fresh execution in A1")
    );
    assert_eq!(inventory["validation"]["contract_execution"], "NOT_EXECUTED_THIS_TURN");
}
