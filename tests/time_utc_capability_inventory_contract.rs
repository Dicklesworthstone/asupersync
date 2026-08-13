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
const ARTIFACT_SHA256: &str = "5e45ef82a80c2c58bfeac84dc5a6bffc88a0886c89393dc545f3687f4ad5fb33";
const DOC_BEGIN: &str = "<!-- BEGIN TIME UTC CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END TIME UTC CAPABILITY INVENTORY -->";
const CHRONO_TOKEN: &str = concat!("chrono", "::");
const EXTERNAL_TIME_TOKEN: &str = concat!("time", "::");
const CENSUS_PROJECTION_SHA256: &str =
    "f8fd5086d737eb83440e89530d8929d8bcd25dc68449e16ea57f12fcd116c7de";
const CENSUS_PATHS_SHA256: &str =
    "f16dea3b2143a0502579cdde842a5b00694031ec504eb674750554f6030f9700";
const LITERAL_OPERATION_PROJECTION_SHA256: &str =
    "a99e910a9793650e07f345f91dbbbabec6e28f118ac57887035344dd040125ac";
const LITERAL_SOURCE_PROJECTION_SHA256: &str =
    "5ef63aba768de40b2cf0a84e514fc184df6d57f93869f2a8108b3c2b9c4a87e2";
const PATH_CLASSIFICATION_PROJECTION_SHA256: &str =
    "5f60bb8b7deb36b1aac2123747fd1be426f1888fc759f46afe3baae103dc3b63";
const LITERAL_OVERRIDE_PROJECTION_SHA256: &str =
    "ea3196fcf2526570e2d848036125a226047dccc9acf570dbe53cd92835287f02";
const ALIAS_CLASSIFICATION_PROJECTION_SHA256: &str =
    "867c7f39911b829635b5a28413179e8cc2d4156f0cfe2a1218fbb3f4819c5118";
const ADDITIONAL_DERIVED_PROJECTION_SHA256: &str =
    "df697103ce3389ef4c0fe5db8cb04f75fee90336c4e917401bf763fd454889f2";
const RAPTORQ_LINEAGE_ADDITIONAL_DERIVED_PROJECTION_SHA256: &str =
    "6b1a4e86af89748dd08fef01e10c2417b9641ba1bf0f262a59ce57f0dd21ad44";
const CROSS_FILE_CONSUMER_PROJECTION_SHA256: &str =
    "ca8cec49608f6762b7984ba4bc3b6e3b816ecee73cb008510ea11c1677fa728c";
const PUBLIC_CARRIER_LINEAGE_PROJECTION_SHA256: &str =
    "c14a1beb11f2c57890a9907a2c29092183974a56f2c2b521f0b37ae40c077eb7";
const TEST_PROFILE_CARRIER_LINEAGE_PROJECTION_SHA256: &str =
    "e4a4a3575ac7b11028672c0fdbe6b342775e0908cfa9df4ad32aa19053ee6e43";
const ROOT_CLI_REFRESH_REVISIONS: &[&str] = &[
    "fbbd4d065ae4768b84e4161a00d10e5acba04b39",
    "75778fbf0846be2d3bc965a2809a705aeb1dfe25",
    "ab1bdba3f6a303da9d51216cb2b8794395daed95",
    "0b2c1beaa0447d9e1e7d26f4c598ef68a1fdd087",
];
const POSTGRES_REFRESH_REVISIONS: &[&str] = &[
    "2e89fda041c6a5bb8b0c2907b3fe76a068180280",
    "0b2c1beaa0447d9e1e7d26f4c598ef68a1fdd087",
];
const SEMANTIC_CONSUMER_BOUNDARY: &str = concat!(
    "Include nonliteral consumers through the first semantic compare, arithmetic, format, ",
    "serialize, persist, retain, return, extract, or embed boundary in a Chrono-bearing ",
    "source path; exclude cross-file propagation, external consumers, and later container ",
    "or arbitrary-byte taint.",
);
const CROSS_FILE_CONSUMER_BOUNDARY: &str = concat!(
    "Include the first explicit embedding, constructor, return, or statically generic JSON ",
    "value serialization boundary in a different source file when a timestamp-bearing public ",
    "carrier flows from a direct Chrono producer to a declared in-repository consumer; exclude ",
    "later encoding or rendering calls, later container propagation, distinct file or ",
    "standard-output sink anchors, dynamic dispatch, external consumers, and ambiguous ",
    "provenance.",
);

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
        || policy
            .get("source_classification_state")
            .and_then(Value::as_str)
            != Some("COMPLETE_BOUNDED_STATIC_INVENTORY")
        || policy.get("bead_acceptance_state").and_then(Value::as_str)
            != Some("STATIC_INVENTORY_ACCEPTANCE_MET_BEHAVIORAL_EVIDENCE_ROUTED")
        || policy.get("bead_close_allowed").and_then(Value::as_bool) != Some(true)
        || policy
            .get("unresolved_behavioral_gap_count")
            .and_then(Value::as_u64)
            != Some(7)
        || policy
            .get("unresolved_static_detail_gap_count")
            .and_then(Value::as_u64)
            != Some(0)
        || policy
            .get("static_zero_unclassified_use_met")
            .and_then(Value::as_bool)
            != Some(true)
        || policy
            .get("acceptance_zero_unknown_met")
            .and_then(Value::as_bool)
            != Some(true)
        || policy
            .get("alias_aware_use_inventory_state")
            .and_then(Value::as_str)
            != Some("IMPORT_BINDINGS_DIRECT_REFERENCES_AND_DECLARED_DERIVED_ANCHORS_COMPLETE")
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
        || fuzz_root
            .get("transitive_chrono_edge")
            .and_then(Value::as_bool)
            != Some(true)
        || fuzz_root.get("direct_time_edge").and_then(Value::as_bool) != Some(false)
        || fuzz_root
            .get("transitive_time_edge")
            .and_then(Value::as_bool)
            != Some(true)
        || text(fuzz_root, "manifest") != "fuzz/Cargo.toml"
    {
        return Err("excluded fuzz workspace dependency profile drifted".to_owned());
    }
    require_exact_strings(
        fuzz_root,
        "root_dependency_features",
        &["benchmark-adapters", "tls"],
    )?;
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
            "TIME-SEM-POST-FIRST-BOUNDARY-PROPAGATION",
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
    if !array(inventory, "static_inventory_gaps").is_empty() {
        return Err("bounded static inventory gaps must be empty at A1 signoff".to_owned());
    }
    require_exact_ids(
        array(inventory, "resolved_static_details"),
        "detail_id",
        &[
            "TIME-STATIC-RESOLVED-ALIAS-BINDINGS",
            "TIME-STATIC-RESOLVED-DECLARED-DERIVED-CONSUMERS",
            "TIME-STATIC-RESOLVED-DIRECT-PER-USE-CLASSIFICATION",
            "TIME-STATIC-RESOLVED-FIRST-BOUNDARY-CARRIER-LINEAGE",
        ],
        "resolved static details",
    )?;
    require_exact_ids(
        array(inventory, "scope_boundaries"),
        "boundary_id",
        &[
            "TIME-SCOPE-NONDEPENDENCY-TEMPORAL-SCHEMAS",
            "TIME-SCOPE-POST-FIRST-BOUNDARY-PROPAGATION",
        ],
        "scope boundaries",
    )?;
    let resolved_alias = &array(inventory, "resolved_static_details")[0];
    let resolved_per_use = &array(inventory, "resolved_static_details")[1];
    let resolved_derived = &array(inventory, "resolved_static_details")[2];
    let resolved_first_boundary = &array(inventory, "resolved_static_details")[3];
    let nondependency_boundary = &array(inventory, "scope_boundaries")[0];
    let propagation_boundary = &array(inventory, "scope_boundaries")[1];
    if text(resolved_alias, "state") != "RESOLVED_BY_STATIC_ALIAS_INVENTORY"
        || text(resolved_per_use, "state") != "RESOLVED_BY_STATIC_DIRECT_PER_USE_CLASSIFICATION"
        || text(resolved_derived, "state") != "RESOLVED_BY_STATIC_DECLARED_DERIVED_CLASSIFICATION"
        || !text(resolved_derived, "summary")
            .contains("Forty-seven declared in-file consumer anchors")
        || !text(resolved_derived, "summary").contains("76 unique direct source anchors")
        || text(resolved_first_boundary, "state")
            != "RESOLVED_BY_COMPLETE_BOUNDED_FIRST_BOUNDARY_CLASSIFICATION"
        || !text(resolved_first_boundary, "summary")
            .contains("All 30 public and seven test-profile Chrono-backed timestamp carriers")
        || array(inventory, "resolved_static_details")
            .iter()
            .any(|row| text(row, "owner_bead") != BEAD_ID)
        || text(nondependency_boundary, "semantic_contract_id")
            != "TIME-SEM-NONDEPENDENCY-TEMPORAL-SCHEMAS"
        || text(propagation_boundary, "semantic_contract_id")
            != "TIME-SEM-POST-FIRST-BOUNDARY-PROPAGATION"
        || !text(propagation_boundary, "effect").contains("A4, A5, and A7")
        || text(propagation_boundary, "owner_bead") != BEAD_ID
    {
        return Err("resolved detail or scope-boundary routing drifted".to_owned());
    }
    Ok(())
}

fn validate_locked_packages(inventory: &Value) -> Result<(), String> {
    let rows = array(inventory, "locked_packages");
    require_exact_ids(rows, "package", &["chrono", "time"], "locked packages")?;
    let by_name: BTreeMap<_, _> = rows.iter().map(|row| (text(row, "package"), row)).collect();
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
        &["asn1-rs 0.7.2", "asupersync 0.3.10", "x509-parser 0.18.1"],
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
        .filter(|row| row.get("serde_direction").and_then(Value::as_str) == Some("SERIALIZE_ONLY"))
        .count();
    let rendered_roundtrip = rendered
        .iter()
        .filter(|row| {
            row.get("serde_direction").and_then(Value::as_str) == Some("SERIALIZE_AND_DESERIALIZE")
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
            row.get("visibility").and_then(Value::as_str) == Some("PUB_ITEM_IN_PRIVATE_TEST_MODULE")
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
    if text(typed_fields["TIME-PUB-CONFORMANCE-H2-SETTINGS"], "struct") != "ComplianceReport"
        || text(typed_fields["TIME-PUB-CONFORMANCE-HPACK"], "struct") != "ComplianceReport"
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
        || totals
            .get("root_asupersync_structs")
            .and_then(Value::as_u64)
            != Some(9)
        || totals
            .get("root_asupersync_modules")
            .and_then(Value::as_u64)
            != Some(3)
        || totals
            .get("conformance_member_fields")
            .and_then(Value::as_u64)
            != Some(6)
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
        || totals
            .get("test_profile_datetime_fields")
            .and_then(Value::as_u64)
            != Some(7)
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
        || totals
            .get("all_inventory_field_rows")
            .and_then(Value::as_u64)
            != Some(37)
        || totals
            .get("syntactically_pub_field_rows")
            .and_then(Value::as_u64)
            != Some(36)
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
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
        {
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

fn actual_literal_lines() -> Vec<(String, u64, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for scope in ["src", "tests", "benches", "conformance", "fuzz/conformance"] {
        collect_rs_files(&root.join(scope), &mut files);
    }
    files.sort();
    files.dedup();

    let mut rows = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .expect("literal path must be repository-relative")
            .to_string_lossy()
            .replace('\\', "/");
        for (index, line) in source.lines().enumerate() {
            if line.contains(CHRONO_TOKEN) {
                rows.push((relative.clone(), index as u64 + 1, line.to_owned()));
            }
        }
    }
    rows.sort();
    rows
}

fn literal_source_projection(rows: &[(String, u64, String)]) -> Vec<u8> {
    let mut projection = Vec::new();
    for (path, line, source) in rows {
        projection.extend_from_slice(path.as_bytes());
        projection.push(0);
        let line_text = line.to_string();
        projection.extend_from_slice(line_text.as_bytes());
        projection.push(0);
        projection.extend_from_slice(source.as_bytes());
        projection.push(0);
    }
    projection
}

fn source_line(path: &str, line: u64) -> Result<String, String> {
    let index = line
        .checked_sub(1)
        .ok_or_else(|| format!("{path} line numbers are one-based"))?;
    let index = usize::try_from(index).map_err(|_| format!("{path}:{line} overflowed usize"))?;
    read_repo_file(path)
        .lines()
        .nth(index)
        .map(str::trim)
        .map(str::to_owned)
        .ok_or_else(|| format!("{path}:{line} is outside the source file"))
}

fn path_classification_projection(path_sets: &[Value]) -> String {
    let mut rows = Vec::new();
    for set in path_sets {
        for path in array(set, "paths") {
            let path = path
                .as_str()
                .expect("path classification entries must be strings");
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                text(set, "set_id"),
                text(set, "group_id"),
                path,
                text(set, "profile_id"),
                text(set, "migration_group_id"),
                text(set, "cfg_or_wiring"),
                text(set, "exposure"),
                text(set, "owner_bead"),
            ));
        }
    }
    rows.sort();
    rows.concat()
}

fn literal_override_projection(overrides: &[Value]) -> String {
    let mut rows: Vec<_> = overrides
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                text(row, "use_id"),
                text(row, "path"),
                number(row, "line"),
                text(row, "source_anchor"),
                text(row, "operation"),
                text(row, "cfg_or_wiring"),
                text(row, "exposure"),
                text(row, "persistence_or_public_association"),
            )
        })
        .collect();
    rows.sort();
    rows.concat()
}

fn additional_derived_projection(rows: &[Value]) -> String {
    let mut rows: Vec<_> = rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                text(row, "use_id"),
                sorted_strings(row, "derivation_sources"),
                text(row, "consumer_category_id"),
                text(row, "path"),
                number(row, "line"),
                text(row, "source_anchor"),
                text(row, "operation"),
                text(row, "cfg_or_wiring"),
                text(row, "exposure"),
                text(row, "persistence_or_public_association"),
            )
        })
        .collect();
    rows.sort();
    rows.concat()
}

fn cross_file_consumer_projection(rows: &[Value]) -> String {
    let mut rows: Vec<_> = rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                text(row, "use_id"),
                sorted_strings(row, "derivation_sources"),
                text(row, "consumer_category_id"),
                text(row, "profile_id"),
                text(row, "path"),
                number(row, "line"),
                text(row, "source_anchor"),
                text(row, "operation"),
                text(row, "cfg_or_wiring"),
                text(row, "exposure"),
                text(row, "persistence_or_public_association"),
            )
        })
        .collect();
    rows.sort();
    rows.concat()
}

fn public_carrier_lineage_projection(rows: &[Value]) -> String {
    let mut rows: Vec<_> = rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\t{}\n",
                text(row, "field_id"),
                text(row, "inventory_section"),
                text(row, "state"),
                sorted_strings(row, "consumer_ids"),
            )
        })
        .collect();
    rows.sort();
    rows.concat()
}

fn test_profile_carrier_lineage_projection(rows: &[Value]) -> String {
    let mut rows: Vec<_> = rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\n",
                text(row, "field_id"),
                text(row, "state"),
                sorted_strings(row, "consumer_ids"),
            )
        })
        .collect();
    rows.sort();
    rows.concat()
}

fn sorted_strings(value: &Value, key: &str) -> String {
    string_set(value, key)
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

fn sorted_numbers(value: &Value, key: &str) -> String {
    number_set(value, key)
        .into_iter()
        .map(|number| number.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn alias_classification_projection(alias: &Value) -> String {
    let mut rows = Vec::new();
    for binding in array(alias, "bindings") {
        rows.push(format!(
            "binding\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            text(binding, "binding_id"),
            text(binding, "path"),
            number(binding, "import_line"),
            text(binding, "import_source"),
            sorted_strings(binding, "imported_symbols"),
            text(binding, "profile_id"),
            text(binding, "cfg_or_wiring"),
            text(binding, "exposure"),
            text(binding, "migration_group_id"),
            text(binding, "owner_bead"),
            sorted_numbers(binding, "direct_reference_lines"),
            number(binding, "imported_symbol_occurrence_count"),
            sorted_numbers(binding, "literal_namespace_overlap_lines"),
            sorted_numbers(binding, "derived_operation_lines"),
            sorted_numbers(binding, "excluded_nonchrono_shadow_lines"),
        ));
    }
    for row in array(alias, "operation_rows") {
        rows.push(format!(
            "direct\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            text(row, "use_id"),
            text(row, "binding_id"),
            text(row, "path"),
            number(row, "line"),
            sorted_strings(row, "imported_symbols_used"),
            text(row, "operation"),
            text(row, "exposure"),
            text(row, "persistence_or_public_association"),
            text(row, "profile_id"),
            text(row, "cfg_or_wiring"),
            text(row, "migration_group_id"),
            text(row, "owner_bead"),
            row.get("literal_namespace_overlap")
                .and_then(Value::as_bool)
                .expect("literal_namespace_overlap must be a bool"),
        ));
    }
    for row in array(alias, "derived_operation_rows") {
        rows.push(format!(
            "derived\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            text(row, "use_id"),
            text(row, "binding_id"),
            text(row, "path"),
            number(row, "line"),
            text(row, "source_anchor"),
            text(row, "operation"),
            text(row, "exposure"),
            text(row, "persistence_or_public_association"),
            text(row, "profile_id"),
            text(row, "cfg_or_wiring"),
            text(row, "migration_group_id"),
            text(row, "owner_bead"),
        ));
    }
    rows.sort();
    rows.concat()
}

fn validate_per_use_classification(inventory: &Value) -> Result<(), String> {
    let per_use = &inventory["per_use_classification"];
    let alias = &inventory["alias_aware_chrono_uses"];
    if text(per_use, "state") != "LITERAL_DIRECT_ALIAS_AND_FIRST_BOUNDARY_CARRIERS_COMPLETE"
        || number(per_use, "path_count") != 71
        || number(per_use, "literal_line_count") != 159
        || number(per_use, "direct_alias_line_count") != 32
        || number(per_use, "literal_alias_overlap_line_count") != 1
        || number(per_use, "literal_or_alias_unique_line_count") != 190
        || number(per_use, "literal_use_override_count") != 36
        || text(per_use, "literal_operation_projection_sha256")
            != LITERAL_OPERATION_PROJECTION_SHA256
        || text(per_use, "literal_source_projection_sha256") != LITERAL_SOURCE_PROJECTION_SHA256
        || text(per_use, "path_classification_projection_sha256")
            != PATH_CLASSIFICATION_PROJECTION_SHA256
        || text(per_use, "literal_override_projection_sha256") != LITERAL_OVERRIDE_PROJECTION_SHA256
        || text(per_use, "additional_derived_projection_sha256")
            != ADDITIONAL_DERIVED_PROJECTION_SHA256
        || text(per_use, "cross_file_consumer_projection_sha256")
            != CROSS_FILE_CONSUMER_PROJECTION_SHA256
        || text(per_use, "semantic_consumer_boundary") != SEMANTIC_CONSUMER_BOUNDARY
        || text(per_use, "cross_file_consumer_boundary") != CROSS_FILE_CONSUMER_BOUNDARY
        || text(per_use, "inheritance_rule").is_empty()
        || text(per_use, "no_claim").is_empty()
    {
        return Err("per-use classification receipt drifted".to_owned());
    }
    require_exact_strings(
        per_use,
        "derived_consumer_category_ids",
        &[
            "TIME-CONSUMER-CLI-CUTOFF-EXPIRY",
            "TIME-CONSUMER-CONFORMANCE-OUTPUT",
            "TIME-CONSUMER-DATABASE-MESSAGING-ARITHMETIC",
            "TIME-CONSUMER-JETSTREAM-WIRE-INSERTION",
            "TIME-CONSUMER-REAL-E2E-BOUNDARY",
            "TIME-CONSUMER-STANDALONE-PERSISTENCE",
            "TIME-CONSUMER-TEST-PROFILE-CARRIER",
        ],
    )?;
    require_exact_strings(
        per_use,
        "cross_file_consumer_category_ids",
        &[
            "TIME-CROSS-FILE-BENCHMARK-PUBLIC-CONSTRUCTOR",
            "TIME-CROSS-FILE-BENCHMARK-RESULT",
            "TIME-CROSS-FILE-CONFORMANCE-JSON",
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINTENANCE",
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-CONSTRUCTOR",
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT",
            "TIME-CROSS-FILE-EXCLUDED-CONFORMANCE-JSON",
            "TIME-CROSS-FILE-ROOT-CLI-JSON",
            "TIME-CROSS-FILE-STANDALONE-JSON",
        ],
    )?;

    let mut group_by_path = BTreeMap::new();
    for group in array(&inventory["chrono_census"], "classification_groups") {
        for row in array(group, "paths") {
            let path = text(row, "path").to_owned();
            let metadata = (
                text(group, "group_id").to_owned(),
                text(group, "profile_id").to_owned(),
                text(group, "migration_group_id").to_owned(),
            );
            if group_by_path.insert(path.clone(), metadata).is_some() {
                return Err(format!("duplicate classified path {path}"));
            }
        }
    }

    let path_sets = array(per_use, "path_classification_sets");
    let profiles = row_ids(array(inventory, "dependency_profiles"), "profile_id");
    let migrations = row_ids(array(inventory, "migration_groups"), "group_id");
    require_exact_ids(
        path_sets,
        "set_id",
        &[
            "TIME-PATHSET-AUTOMATIC-INTEGRATION-TARGETS",
            "TIME-PATHSET-BENCHMARK-ADAPTERS",
            "TIME-PATHSET-CLI-PRODUCTION",
            "TIME-PATHSET-CONFORMANCE-BINS",
            "TIME-PATHSET-CONFORMANCE-LIBRARY",
            "TIME-PATHSET-CONFORMANCE-RAPTORQ-REPORTING",
            "TIME-PATHSET-CONFORMANCE-ROOT-MODULE",
            "TIME-PATHSET-DORMANT-CODEC-CONFORMANCE",
            "TIME-PATHSET-DORMANT-REAL-E2E-DATABASE-MESSAGING",
            "TIME-PATHSET-DORMANT-REAL-E2E-DOWNSTREAM",
            "TIME-PATHSET-EXCLUDED-CONFORMANCE",
            "TIME-PATHSET-H3-WEBSOCKET-E2E",
            "TIME-PATHSET-HPACK-DIFFERENTIAL",
            "TIME-PATHSET-HPACK-FIXTURES",
            "TIME-PATHSET-JETSTREAM-INTEGRATION",
            "TIME-PATHSET-KAFKA-INTEGRATION",
            "TIME-PATHSET-POSTGRES-UNIT-ORACLE",
            "TIME-PATHSET-REDIS-UNIT-DIAGNOSTICS",
            "TIME-PATHSET-ROOT-BENCH",
            "TIME-PATHSET-STANDALONE-GOLDEN",
            "TIME-PATHSET-STANDALONE-REPORTING-BINS",
            "TIME-PATHSET-STANDALONE-REPORTING-LIBRARY",
        ],
        "per-use path classification sets",
    )?;
    if sha256_hex(path_classification_projection(path_sets).as_bytes())
        != PATH_CLASSIFICATION_PROJECTION_SHA256
    {
        return Err("per-use path classification projection drifted".to_owned());
    }
    let mut classified_paths = BTreeMap::new();
    for set in path_sets {
        let group_id = text(set, "group_id");
        let profile_id = text(set, "profile_id");
        let migration_group_id = text(set, "migration_group_id");
        let cfg_or_wiring = text(set, "cfg_or_wiring");
        let exposure = text(set, "exposure");
        let owner_bead = text(set, "owner_bead");
        if !profiles.contains(profile_id)
            || !migrations.contains(migration_group_id)
            || cfg_or_wiring.is_empty()
            || exposure.is_empty()
            || !owner_bead.starts_with("asupersync-")
        {
            return Err(format!("{} metadata drifted", text(set, "set_id")));
        }
        let paths = string_set(set, "paths");
        if paths.is_empty() || paths.len() != array(set, "paths").len() {
            return Err(format!("{} path set drifted", text(set, "set_id")));
        }
        for path in paths {
            let Some((actual_group, _, _)) = group_by_path.get(&path) else {
                return Err(format!(
                    "{} references non-census path {path}",
                    text(set, "set_id")
                ));
            };
            if actual_group.as_str() != group_id {
                return Err(format!(
                    "{} group route drifted for {path}",
                    text(set, "set_id")
                ));
            }
            let metadata = (
                actual_group.clone(),
                profile_id.to_owned(),
                migration_group_id.to_owned(),
                cfg_or_wiring.to_owned(),
                exposure.to_owned(),
                owner_bead.to_owned(),
            );
            if classified_paths.insert(path.clone(), metadata).is_some() {
                return Err(format!("duplicate per-use path classification {path}"));
            }
        }
    }
    let expected_paths: BTreeSet<_> = group_by_path.keys().cloned().collect();
    let actual_paths: BTreeSet<_> = classified_paths.keys().cloned().collect();
    if actual_paths != expected_paths || actual_paths.len() != 71 {
        return Err("per-use path coverage drifted".to_owned());
    }

    let rules = array(per_use, "literal_operation_rules");
    let expected_rules = [
        (
            "DIRECT_IMPORT_BINDING",
            concat!("use ", "chrono", "::"),
            "direct Chrono symbol binding",
            4_u64,
        ),
        (
            "UTC_DATETIME_TYPE",
            concat!("chrono", "::DateTime<", "chrono", "::Utc>"),
            "concrete UTC datetime type exposure",
            22,
        ),
        (
            "SYSTEM_TIME_TO_UTC",
            concat!("chrono", "::DateTime::<", "chrono", "::Utc>::from"),
            "system time converted to UTC datetime",
            1,
        ),
        (
            "UNIX_TIMESTAMP_TO_DATETIME",
            concat!("chrono", "::DateTime::from_timestamp"),
            "Unix seconds and nanoseconds converted to datetime",
            1,
        ),
        (
            "RFC3339_NANOSECOND_RENDER",
            concat!("chrono", "::SecondsFormat::Nanos"),
            "UTC datetime rendered as RFC3339 with nanosecond precision",
            1,
        ),
        (
            "CALENDAR_DATE_CONSTRUCTION",
            concat!("chrono", "::NaiveDate::from_ymd_opt"),
            "PostgreSQL calendar epoch construction",
            2,
        ),
        (
            "CALENDAR_ARITHMETIC",
            concat!("chrono", "::TimeDelta::"),
            "PostgreSQL day or microsecond calendar arithmetic",
            2,
        ),
        (
            "STD_DURATION_CONVERSION",
            concat!("chrono", "::Duration::from_std"),
            "standard duration converted to signed calendar duration",
            4,
        ),
        (
            "AMBIENT_UTC_TO_UNIX_MILLIS",
            concat!("chrono", "::Utc::now().timestamp_millis()"),
            "ambient UTC acquired and converted to Unix milliseconds",
            3,
        ),
        (
            "AMBIENT_UTC_TO_UNIX_SECONDS",
            concat!("chrono", "::Utc::now().timestamp()"),
            "ambient UTC acquired and converted to Unix seconds",
            1,
        ),
        (
            "AMBIENT_UTC_FIXED_FORMAT",
            concat!("chrono", "::Utc::now().format("),
            "ambient UTC acquired and rendered with a fixed format",
            9,
        ),
        (
            "AMBIENT_UTC_RFC3339",
            concat!("chrono", "::Utc::now().to_rfc3339()"),
            "ambient UTC acquired and rendered as RFC3339",
            86,
        ),
        (
            "AMBIENT_UTC_TYPED",
            concat!("chrono", "::Utc::now()"),
            "ambient UTC acquired as a typed datetime",
            23,
        ),
    ];
    if rules.len() != expected_rules.len() {
        return Err("literal operation rule precedence drifted".to_owned());
    }
    for (index, (rule, expected)) in rules.iter().zip(expected_rules.iter()).enumerate() {
        let &(operation_id, needle, operation, matching_line_count) = expected;
        if number(rule, "precedence") != index as u64 + 1
            || text(rule, "operation_id") != operation_id
            || text(rule, "needle") != needle
            || text(rule, "operation") != operation
            || number(rule, "matching_line_count") != matching_line_count
        {
            return Err(format!(
                "{} rule metadata drifted",
                text(rule, "operation_id")
            ));
        }
    }

    let literal_rows = actual_literal_lines();
    let literal_pairs: BTreeSet<_> = literal_rows
        .iter()
        .map(|(path, line, _)| (path.clone(), *line))
        .collect();
    if literal_rows.len() != 159 || literal_pairs.len() != 159 {
        return Err("literal per-use source set drifted".to_owned());
    }
    if sha256_hex(&literal_source_projection(&literal_rows)) != LITERAL_SOURCE_PROJECTION_SHA256 {
        return Err("literal source projection drifted".to_owned());
    }
    let mut rule_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut projection = String::new();
    for (path, line, source) in &literal_rows {
        if !classified_paths.contains_key(path) {
            return Err(format!(
                "literal use lacks a path classification at {path}:{line}"
            ));
        }
        let Some(rule) = rules
            .iter()
            .find(|rule| source.contains(text(rule, "needle")))
        else {
            return Err(format!("literal use lacks an operation at {path}:{line}"));
        };
        let operation_id = text(rule, "operation_id");
        *rule_counts.entry(operation_id.to_owned()).or_default() += 1;
        projection.push_str(&format!("{path}\t{line}\t{operation_id}\n"));
    }
    for rule in rules {
        if rule_counts
            .get(text(rule, "operation_id"))
            .copied()
            .unwrap_or(0)
            != number(rule, "matching_line_count")
        {
            return Err(format!("{} rule count drifted", text(rule, "operation_id")));
        }
    }
    if sha256_hex(projection.as_bytes()) != LITERAL_OPERATION_PROJECTION_SHA256 {
        return Err("literal operation projection drifted".to_owned());
    }

    let mut override_pairs = BTreeSet::new();
    let literal_overrides = array(per_use, "literal_use_overrides");
    if number(per_use, "literal_use_override_count") != 36
        || literal_overrides.len() != 36
        || row_ids(literal_overrides, "use_id").len() != literal_overrides.len()
        || sha256_hex(literal_override_projection(literal_overrides).as_bytes())
            != LITERAL_OVERRIDE_PROJECTION_SHA256
    {
        return Err("literal override identity, total, or projection drifted".to_owned());
    }
    for row in literal_overrides {
        let path = text(row, "path");
        let line = number(row, "line");
        let pair = (path.to_owned(), line);
        if !literal_pairs.contains(&pair)
            || !override_pairs.insert(pair)
            || !classified_paths.contains_key(path)
            || text(row, "source_anchor") != source_line(path, line)?
            || text(row, "operation").is_empty()
            || text(row, "cfg_or_wiring").is_empty()
            || text(row, "exposure").is_empty()
            || text(row, "persistence_or_public_association").is_empty()
        {
            return Err(format!("{} literal override drifted", text(row, "use_id")));
        }
    }

    let direct_pairs: BTreeSet<_> = array(alias, "operation_rows")
        .iter()
        .map(|row| (text(row, "path").to_owned(), number(row, "line")))
        .collect();
    let overlap_pairs: BTreeSet<_> = literal_pairs.intersection(&direct_pairs).cloned().collect();
    if overlap_pairs.len() != 1
        || number(per_use, "literal_alias_overlap_line_count") != overlap_pairs.len() as u64
    {
        return Err("literal and alias overlap drifted".to_owned());
    }
    let mut direct_union = literal_pairs.clone();
    direct_union.extend(direct_pairs);
    if direct_union.len() != 190
        || number(per_use, "literal_or_alias_unique_line_count") != direct_union.len() as u64
    {
        return Err("literal-or-alias union drifted".to_owned());
    }
    let direct_source_ids: BTreeSet<_> = direct_union
        .iter()
        .map(|(path, line)| format!("{path}:{line}"))
        .collect();

    let mut derived_pairs: BTreeSet<_> = array(alias, "derived_operation_rows")
        .iter()
        .map(|row| (text(row, "path").to_owned(), number(row, "line")))
        .collect();
    if !derived_pairs.is_disjoint(&direct_union) {
        return Err("derived alias anchors overlap direct uses".to_owned());
    }
    let additional_derived = array(per_use, "additional_derived_operation_rows");
    if number(per_use, "additional_derived_operation_anchor_count")
        != additional_derived.len() as u64
        || row_ids(additional_derived, "use_id").len() != additional_derived.len()
        || sha256_hex(additional_derived_projection(additional_derived).as_bytes())
            != ADDITIONAL_DERIVED_PROJECTION_SHA256
    {
        return Err("additional derived identity, total, or projection drifted".to_owned());
    }
    let declared_categories = string_set(per_use, "derived_consumer_category_ids");
    let mut actual_categories = BTreeSet::new();
    let mut declared_consumer_direct_source_ids = BTreeSet::new();
    for row in additional_derived {
        let path = text(row, "path");
        let line = number(row, "line");
        let pair = (path.to_owned(), line);
        let derivation_sources = array(row, "derivation_sources");
        let derivation_source_set = string_set(row, "derivation_sources");
        let category = text(row, "consumer_category_id");
        if direct_union.contains(&pair)
            || !derived_pairs.insert(pair)
            || !classified_paths.contains_key(path)
            || derivation_sources.is_empty()
            || derivation_sources.len() != derivation_source_set.len()
            || !derivation_source_set.is_subset(&direct_source_ids)
            || !declared_categories.contains(category)
            || text(row, "source_anchor") != source_line(path, line)?
            || text(row, "operation").is_empty()
            || text(row, "cfg_or_wiring").is_empty()
            || text(row, "exposure").is_empty()
            || text(row, "persistence_or_public_association").is_empty()
        {
            return Err(format!(
                "{} additional derived row drifted",
                text(row, "use_id")
            ));
        }
        actual_categories.insert(category.to_owned());
        declared_consumer_direct_source_ids.extend(derivation_source_set);
    }
    if actual_categories != declared_categories {
        return Err("derived consumer category coverage drifted".to_owned());
    }

    let cross_file_rows = array(per_use, "cross_file_consumer_rows");
    if number(per_use, "cross_file_consumer_anchor_count") != cross_file_rows.len() as u64
        || row_ids(cross_file_rows, "use_id").len() != cross_file_rows.len()
        || sha256_hex(cross_file_consumer_projection(cross_file_rows).as_bytes())
            != CROSS_FILE_CONSUMER_PROJECTION_SHA256
    {
        return Err("cross-file consumer identity, total, or projection drifted".to_owned());
    }
    let declared_cross_file_categories = string_set(per_use, "cross_file_consumer_category_ids");
    let conformance_manifest = read_repo_file("conformance/Cargo.toml");
    let conformance_root_lib = read_repo_file("conformance/src/lib.rs");
    let raptorq_reporting_module =
        read_repo_file("conformance/raptorq_rfc6330/reporting/src/mod.rs");
    let raptorq_maintenance_bin =
        read_repo_file("conformance/raptorq_rfc6330/reporting/bin/maintain_fixtures.rs");
    let excluded_conformance_manifest = read_repo_file("fuzz/conformance/Cargo.toml");
    let standalone_reporting_manifest =
        read_repo_file("tests/conformance/raptorq_rfc6330/reporting/Cargo.toml");
    let root_lib = read_repo_file("src/lib.rs");
    let atp_module = read_repo_file("src/atp/mod.rs");
    let benchmark_module = read_repo_file("src/atp/benchmark/mod.rs");
    let cli_module = read_repo_file("src/cli/mod.rs");
    let mut actual_cross_file_categories = BTreeSet::new();
    let mut cross_file_pairs = BTreeSet::new();
    let mut cross_file_direct_source_ids = BTreeSet::new();
    for row in cross_file_rows {
        let path = text(row, "path");
        let line = number(row, "line");
        let pair = (path.to_owned(), line);
        let derivation_sources = array(row, "derivation_sources");
        let derivation_source_set = string_set(row, "derivation_sources");
        let category = text(row, "consumer_category_id");
        let same_file_prefix = format!("{path}:");
        let route_is_valid = match category {
            "TIME-CROSS-FILE-BENCHMARK-PUBLIC-CONSTRUCTOR" => {
                text(row, "profile_id") == "TIME-PROFILE-BENCHMARK-ADAPTERS"
                    && path == "src/atp/benchmark/suite.rs"
                    && text(row, "cfg_or_wiring") == "FEATURE_BENCHMARK_ADAPTERS"
                    && text(row, "exposure") == "PUBLIC_FEATURE_GATED_SERDE_REPORT"
                    && atp_module.contains(
                        "#[cfg(feature = \"benchmark-adapters\")]\npub mod benchmark;",
                    )
                    && benchmark_module.contains("pub mod suite;")
                    && benchmark_module.contains("pub use suite::BenchmarkSuite;")
                    && benchmark_module.contains(
                        "pub use reports::{BenchmarkMetrics, BenchmarkReport, BenchmarkResult, ComparisonReport};",
                    )
            }
            "TIME-CROSS-FILE-BENCHMARK-RESULT" => {
                text(row, "profile_id") == "TIME-PROFILE-BENCHMARK-ADAPTERS"
                    && matches!(
                        path,
                        "src/atp/benchmark/adapters.rs" | "src/atp/benchmark/profiles.rs"
                    )
                    && text(row, "cfg_or_wiring") == "FEATURE_BENCHMARK_ADAPTERS"
                    && text(row, "exposure") == "PUBLIC_FEATURE_GATED_SERDE_REPORT"
                    && atp_module.contains(
                        "#[cfg(feature = \"benchmark-adapters\")]\npub mod benchmark;",
                    )
                    && benchmark_module.contains("pub mod adapters;")
                    && benchmark_module.contains("pub mod profiles;")
                    && benchmark_module.contains(
                        "pub use reports::{BenchmarkMetrics, BenchmarkReport, BenchmarkResult, ComparisonReport};",
                    )
            }
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINTENANCE" => {
                text(row, "profile_id") == "TIME-PROFILE-CONFORMANCE-MEMBER"
                    && path
                        == "conformance/raptorq_rfc6330/reporting/bin/maintain_fixtures.rs"
                    && text(row, "cfg_or_wiring")
                        == "EXPLICIT_CARGO_BIN_WITH_PATH_INCLUDED_MODULE"
                    && text(row, "exposure") == "CONFORMANCE_EXECUTABLE_PRIVATE_CARRIER"
                    && conformance_manifest.contains(
                        "path = \"raptorq_rfc6330/reporting/bin/maintain_fixtures.rs\"",
                    )
                    && raptorq_maintenance_bin.contains(
                        "#[path = \"../src/maintenance_workflows.rs\"]\nmod maintenance_workflows;",
                    )
            }
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-CONSTRUCTOR" => {
                text(row, "profile_id") == "TIME-PROFILE-CONFORMANCE-MEMBER"
                    && path == "conformance/raptorq_rfc6330/reporting/src/mod.rs"
                    && text(row, "cfg_or_wiring") == "PUBLIC_CONFORMANCE_LIBRARY_REEXPORT"
                    && text(row, "exposure") == "PUBLIC_CONFORMANCE_REPORTING_PIPELINE"
                    && conformance_root_lib.contains(
                        "#[path = \"../raptorq_rfc6330/reporting/src/mod.rs\"]\npub mod raptorq_rfc6330_reporting;",
                    )
                    && raptorq_reporting_module.contains("pub mod coverage_matrix;")
                    && raptorq_reporting_module.contains("pub mod regression_detection;")
            }
            "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT" => {
                text(row, "profile_id") == "TIME-PROFILE-CONFORMANCE-MEMBER"
                    && path
                        == "conformance/raptorq_rfc6330/reporting/src/compliance_report.rs"
                    && text(row, "cfg_or_wiring") == "PUBLIC_CONFORMANCE_LIBRARY_REEXPORT"
                    && text(row, "exposure") == "PUBLIC_CONFORMANCE_REPORT_OUTPUT"
                    && conformance_root_lib.contains(
                        "#[path = \"../raptorq_rfc6330/reporting/src/mod.rs\"]\npub mod raptorq_rfc6330_reporting;",
                    )
                    && raptorq_reporting_module.contains("pub mod compliance_report;")
                    && raptorq_reporting_module.contains(
                        "pub use compliance_report::{\n    ComplianceReportGenerator, OutputFormat, ReportConfig, generate_ci_summary,\n};",
                    )
            }
            "TIME-CROSS-FILE-CONFORMANCE-JSON" => {
                text(row, "profile_id") == "TIME-PROFILE-CONFORMANCE-MEMBER"
                    && path.starts_with("conformance/src/bin/")
                    && text(row, "cfg_or_wiring") == "EXPLICIT_CARGO_BIN"
                    && text(row, "exposure") == "CONFORMANCE_EXECUTABLE_REPORT_OUTPUT"
                    && conformance_manifest.contains(&format!(
                        "path = \"{}\"",
                        path.strip_prefix("conformance/")
                            .expect("main conformance consumer prefix must match")
                    ))
            }
            "TIME-CROSS-FILE-EXCLUDED-CONFORMANCE-JSON" => {
                text(row, "profile_id") == "TIME-PROFILE-EXCLUDED-CONFORMANCE"
                    && path.starts_with("fuzz/conformance/src/bin/")
                    && text(row, "cfg_or_wiring") == "EXCLUDED_WORKSPACE_EXPLICIT_BIN"
                    && text(row, "exposure") == "SEPARATE_WORKSPACE_REPORT_OUTPUT"
                    && excluded_conformance_manifest.contains(&format!(
                        "path = \"{}\"",
                        path.strip_prefix("fuzz/conformance/")
                            .expect("excluded conformance consumer prefix must match")
                    ))
            }
            "TIME-CROSS-FILE-STANDALONE-JSON" => {
                text(row, "profile_id") == "TIME-PROFILE-STANDALONE-REPORTING"
                    && path.starts_with("tests/conformance/raptorq_rfc6330/reporting/bin/")
                    && text(row, "cfg_or_wiring") == "NESTED_STANDALONE_BIN"
                    && text(row, "exposure") == "STANDALONE_TOOL_OUTPUT"
                    && standalone_reporting_manifest.contains(&format!(
                        "path = \"{}\"",
                        path.strip_prefix("tests/conformance/raptorq_rfc6330/reporting/")
                            .expect("standalone reporting consumer prefix must match")
                    ))
            }
            "TIME-CROSS-FILE-ROOT-CLI-JSON" => {
                text(row, "profile_id") == "TIME-PROFILE-CLI"
                    && path == "src/cli/output.rs"
                    && text(row, "cfg_or_wiring") == "FEATURE_CLI_NATIVE_ONLY"
                    && text(row, "exposure") == "PUBLIC_CLI_JSON_OUTPUT"
                    && root_lib.contains("#[cfg(feature = \"cli\")]\npub mod cli;")
                    && cli_module.contains("pub mod output;")
                    && cli_module.contains(
                        "pub use output::{ColorChoice, Output, OutputFormat, Outputtable};",
                    )
            }
            _ => false,
        };
        if direct_union.contains(&pair)
            || derived_pairs.contains(&pair)
            || !cross_file_pairs.insert(pair)
            || derivation_sources.is_empty()
            || derivation_sources.len() != derivation_source_set.len()
            || !derivation_source_set.is_subset(&direct_source_ids)
            || derivation_source_set
                .iter()
                .any(|source| source.starts_with(&same_file_prefix))
            || !declared_cross_file_categories.contains(category)
            || !route_is_valid
            || !profiles.contains(text(row, "profile_id"))
            || text(row, "source_anchor") != source_line(path, line)?
            || text(row, "operation").is_empty()
            || text(row, "cfg_or_wiring").is_empty()
            || text(row, "exposure").is_empty()
            || text(row, "persistence_or_public_association").is_empty()
        {
            return Err(format!(
                "{} cross-file consumer row drifted",
                text(row, "use_id")
            ));
        }
        actual_cross_file_categories.insert(category.to_owned());
        cross_file_direct_source_ids.extend(derivation_source_set.iter().cloned());
        declared_consumer_direct_source_ids.extend(derivation_source_set);
    }
    if actual_cross_file_categories != declared_cross_file_categories {
        return Err("cross-file consumer category coverage drifted".to_owned());
    }
    if number(per_use, "cross_file_direct_source_anchor_count")
        != cross_file_direct_source_ids.len() as u64
        || number(
            per_use,
            "declared_consumer_unique_direct_source_anchor_count",
        ) != declared_consumer_direct_source_ids.len() as u64
    {
        return Err("declared consumer direct-source totals drifted".to_owned());
    }
    if number(per_use, "derived_operation_anchor_count") != derived_pairs.len() as u64
        || number(per_use, "classified_anchor_count")
            != (direct_union.len() + derived_pairs.len() + cross_file_pairs.len()) as u64
    {
        return Err("classified anchor totals drifted".to_owned());
    }
    Ok(())
}

fn validate_alias_inventory(inventory: &Value) -> Result<(), String> {
    let alias = &inventory["alias_aware_chrono_uses"];
    if text(alias, "state")
        != "IMPORT_BINDINGS_DIRECT_REFERENCES_AND_DECLARED_DERIVED_ANCHORS_COMPLETE"
        || number(alias, "binding_path_count") != 4
        || number(alias, "binding_count") != 4
        || number(alias, "direct_reference_line_count") != 32
        || number(alias, "imported_symbol_occurrence_count") != 45
        || number(alias, "literal_namespace_overlap_line_count") != 1
        || number(alias, "new_line_count_beyond_literal_census") != 31
        || number(alias, "literal_or_alias_unique_line_count") != 190
        || number(alias, "derived_operation_anchor_line_count") != 8
        || text(alias, "classification_projection_sha256") != ALIAS_CLASSIFICATION_PROJECTION_SHA256
    {
        return Err("alias-aware inventory totals drifted".to_owned());
    }
    if sha256_hex(alias_classification_projection(alias).as_bytes())
        != ALIAS_CLASSIFICATION_PROJECTION_SHA256
    {
        return Err("alias classification projection drifted".to_owned());
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
    for (binding_id, path, import_line, import_source, imported_symbols) in expected_binding_facts {
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
    let mut path_routes = BTreeMap::new();
    for set in array(
        &inventory["per_use_classification"],
        "path_classification_sets",
    ) {
        let route = (
            text(set, "profile_id").to_owned(),
            text(set, "migration_group_id").to_owned(),
            text(set, "owner_bead").to_owned(),
        );
        for source_path in string_set(set, "paths") {
            if path_routes
                .insert(source_path.clone(), route.clone())
                .is_some()
            {
                return Err(format!("duplicate per-use route for {source_path}"));
            }
        }
    }
    let mut binding_paths = BTreeSet::new();
    let mut direct_pairs = BTreeSet::new();
    let mut overlap_pairs = BTreeSet::new();
    let mut derived_pairs = BTreeSet::new();
    let mut excluded_pairs = BTreeSet::new();
    let mut declared_occurrences = 0_u64;
    for binding in bindings {
        let path = text(binding, "path");
        binding_paths.insert(path.to_owned());
        let Some((route_profile, route_migration, route_owner)) = path_routes.get(path) else {
            return Err(format!(
                "{} lacks a per-use path route",
                text(binding, "binding_id")
            ));
        };
        if text(binding, "profile_id") != route_profile.as_str()
            || text(binding, "migration_group_id") != route_migration.as_str()
            || text(binding, "owner_bead") != route_owner.as_str()
            || !profiles.contains(text(binding, "profile_id"))
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
            return Err(format!("{} line sets drifted", text(binding, "binding_id")));
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
        || overlap_pairs.len() != 1
        || derived_pairs.len() != 8
        || declared_occurrences != 45
    {
        return Err("alias binding aggregates drifted".to_owned());
    }
    let expected_overlap_pairs: BTreeSet<_> = std::iter::once(236_u64)
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
            "tests/conformance/raptorq_rfc6330/reporting/src/regression_detection.rs".to_owned(),
            314,
        )))
        .collect();
    if derived_pairs != expected_derived_pairs {
        return Err("derived temporal operation anchors drifted".to_owned());
    }
    let expected_excluded_pairs = BTreeSet::from([(
        "tests/conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs".to_owned(),
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
    if operation_rows.len() != 32 || row_ids(operation_rows, "use_id").len() != operation_rows.len()
    {
        return Err("direct alias operation row identity drifted".to_owned());
    }
    let mut operation_pairs = BTreeSet::new();
    let mut operation_occurrences = 0_usize;
    for row in operation_rows {
        let binding_id = text(row, "binding_id");
        let Some(binding) = binding_by_id.get(binding_id).copied() else {
            return Err(format!(
                "{} references an unknown binding",
                text(row, "use_id")
            ));
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
        if used_symbols.is_empty()
            || used_symbols.len() != array(row, "imported_symbols_used").len()
            || !used_symbols.is_subset(&imported_symbols)
        {
            return Err(format!(
                "{} imported-symbol set drifted",
                text(row, "use_id")
            ));
        }
        operation_occurrences += used_symbols.len();
        if row
            .get("literal_namespace_overlap")
            .and_then(Value::as_bool)
            != Some(overlap_pairs.contains(&pair))
        {
            return Err(format!(
                "{} overlap classification drifted",
                text(row, "use_id")
            ));
        }
    }
    if operation_pairs != direct_pairs || operation_occurrences != 45 {
        return Err("direct alias references lack one-to-one operation and symbol rows".to_owned());
    }

    let derived_rows = array(alias, "derived_operation_rows");
    if derived_rows.len() != 8 || row_ids(derived_rows, "use_id").len() != derived_rows.len() {
        return Err("derived alias operation row identity drifted".to_owned());
    }
    let mut classified_derived_pairs = BTreeSet::new();
    for row in derived_rows {
        let binding_id = text(row, "binding_id");
        let Some(binding) = binding_by_id.get(binding_id).copied() else {
            return Err(format!(
                "{} references an unknown binding",
                text(row, "use_id")
            ));
        };
        let pair = (text(row, "path").to_owned(), number(row, "line"));
        if !classified_derived_pairs.insert(pair.clone()) || !derived_pairs.contains(&pair) {
            return Err(format!("{} derived-use pair drifted", text(row, "use_id")));
        }
        if text(row, "path") != text(binding, "path")
            || text(row, "profile_id") != text(binding, "profile_id")
            || text(row, "cfg_or_wiring") != text(binding, "cfg_or_wiring")
            || text(row, "migration_group_id") != text(binding, "migration_group_id")
            || text(row, "owner_bead") != text(binding, "owner_bead")
            || text(row, "source_anchor").is_empty()
            || text(row, "operation").is_empty()
            || text(row, "exposure").is_empty()
            || text(row, "persistence_or_public_association").is_empty()
        {
            return Err(format!(
                "{} derived classification drifted",
                text(row, "use_id")
            ));
        }
    }
    if classified_derived_pairs != derived_pairs {
        return Err("derived alias anchors lack one-to-one operation rows".to_owned());
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
    let value = value.strip_prefix("::").map_or(value, str::trim_start);
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
    value.rmatch_indices(keyword).find_map(|(index, _)| {
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

fn direct_chrono_binding_line(statement: &str, start_line: u64, chrono_name: &str) -> Option<u64> {
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
                let end = bytes
                    .get(content + 3..)?
                    .iter()
                    .position(|byte| *byte == b'}')?;
                content + 4 + end
            }
            (Some(b'x'), _) => content + 4,
            (Some(_), _) => content + 2,
            _ => return None,
        }
    } else {
        let character = std::str::from_utf8(bytes.get(content..)?)
            .ok()?
            .chars()
            .next()?;
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
        if lines.get(import_index).map(|line| line.trim()) != Some(text(binding, "import_source")) {
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
                return Err(format!(
                    "{} source classification drifted",
                    text(row, "use_id")
                ));
            }
        }
        for row in array(alias, "derived_operation_rows")
            .iter()
            .filter(|row| text(row, "binding_id") == text(binding, "binding_id"))
        {
            let line_number = number(row, "line");
            let index = usize::try_from(line_number - 1)
                .map_err(|_| format!("{path}:{line_number} overflowed usize"))?;
            let line = lines
                .get(index)
                .ok_or_else(|| format!("{path}:{line_number} is outside the source file"))?;
            if line.trim() != text(row, "source_anchor") {
                return Err(format!("{} source anchor drifted", text(row, "use_id")));
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
    if pins.len() != 74 {
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

fn validate_post_a1_provenance_refresh(inventory: &Value) -> Result<(), String> {
    let refresh = inventory
        .get("post_a1_provenance_refresh")
        .ok_or_else(|| "post_a1_provenance_refresh is required".to_owned())?;
    for (key, expected) in [
        ("captured_date_utc", "2026-08-05"),
        ("base_commit", "2f9314377d9418c5819bd6baf656e0f4f19b5200"),
        ("refresh_state", "STATIC_SOURCE_PIN_MAINTENANCE"),
        ("required_disposition", "KEEP_OPEN"),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
    ] {
        if refresh.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("post-A1 refresh {key} must be {expected}"));
        }
    }
    if refresh.get("source_pin_path_count").and_then(Value::as_u64) != Some(68)
        || refresh.get("stale_path_count").and_then(Value::as_u64) != Some(1)
        || refresh.get("refreshed_path_count").and_then(Value::as_u64) != Some(1)
    {
        return Err("post-A1 refresh counts drifted".to_owned());
    }
    for key in [
        "source_pin_path_set_changed",
        "historical_a1_revision_changed",
        "a1_inventory_counts_changed",
        "dependency_exit_allowed",
    ] {
        if refresh.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("post-A1 refresh {key} must remain false"));
        }
    }

    let rows = array(refresh, "refreshed_paths");
    if rows.len() != 1 {
        return Err("post-A1 refresh must retain one exact path".to_owned());
    }
    let baseline = &rows[0];
    if text(baseline, "path") != "artifacts/dependency_capability_baseline_v1.json"
        || text(baseline, "classification") != "APPEND_ONLY_INDEPENDENT_STATIC_AUDITS"
        || text(baseline, "previous_sha256") != "88575b016105828ce8a3687ef6be2509e0412dee949cda8"
        || baseline.get("previous_line_count").and_then(Value::as_u64) != Some(1357)
        || text(baseline, "current_sha256")
            != "2cc72453659c2209713d6779c6d12aa6a114201893cbbd6e840d9f73786d38a3"
        || baseline.get("current_line_count").and_then(Value::as_u64) != Some(3210)
        || baseline.get("added_line_count").and_then(Value::as_u64) != Some(1853)
        || baseline.get("deleted_line_count").and_then(Value::as_u64) != Some(0)
        || baseline
            .get("time_acceptance_semantics_changed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("post-A1 baseline provenance drifted".to_owned());
    }
    let projections = object(baseline, "unchanged_time_projection_sha256");
    for (key, expected) in [
        (
            "capability_baseline",
            "809e86ccbcc413b96ebf6cc9bcc13488ae86c9ce51a62421629689b64d20543b",
        ),
        (
            "time_and_cli_evidence",
            "c44aa84d1e28042349340011b9b5238fd90c8d9e4814d7f51f2b21fe65ae2dab",
        ),
        (
            "registry_artifact",
            "823a83454efa037e72659307fbaad0cf4be21eaf47e457e30b28feda27eac76e",
        ),
        (
            "runner_contract",
            "8d85ab755084182064c6835af47e0db2af00814637ff5c260d61df352a58fb0b",
        ),
    ] {
        if projections.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("post-A1 projection {key} drifted"));
        }
    }
    if !text(refresh, "no_claim_boundary").contains("does not rerun A1")
        || !text(refresh, "no_claim_boundary").contains("derived-consumer inventory")
        || !text(refresh, "no_claim_boundary").contains("dependency exit")
    {
        return Err("post-A1 refresh no-claim boundary is incomplete".to_owned());
    }
    Ok(())
}

fn validate_post_a1_cli_output_extension(inventory: &Value) -> Result<(), String> {
    let extension = inventory
        .get("post_a1_cli_output_extension")
        .ok_or_else(|| "post_a1_cli_output_extension is required".to_owned())?;
    for (key, expected) in [
        ("extension_id", "TIME-A1-ROOT-CLI-JSON-2026-08-06"),
        ("captured_date_utc", "2026-08-06"),
        (
            "extension_state",
            "STATIC_DECLARED_CROSS_FILE_CONSUMER_EXTENSION",
        ),
        (
            "cross_file_consumer_id",
            "TIME-CROSS-FILE-ROOT-CLI-OUTPUTTABLE-JSON-0156",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        ("required_disposition", "KEEP_OPEN"),
    ] {
        if extension.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("post-A1 CLI extension {key} must be {expected}"));
        }
    }
    if extension
        .get("source_pin_path_count")
        .and_then(Value::as_u64)
        != Some(69)
        || extension
            .get("direct_timestamp_field_count")
            .and_then(Value::as_u64)
            != Some(8)
        || extension
            .get("stale_existing_pin_count")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err("post-A1 CLI extension counts drifted".to_owned());
    }
    require_exact_strings(
        extension,
        "wrapper_types",
        &[
            "AtpArchiveOutput",
            "AtpCiOutput",
            "AtpDatasetOutput",
            "AtpReleaseOutput",
        ],
    )?;

    let added_pin = &extension["added_source_pin"];
    if text(added_pin, "path") != "src/cli/output.rs"
        || text(added_pin, "sha256")
            != "6ae4f717fd64141039fc4a4b6ed34285ded9ccc3274ff61efa63b3b0a06457c6"
        || number(added_pin, "line_count") != 907
    {
        return Err("post-A1 CLI extension source pin drifted".to_owned());
    }
    let matching_pin = array(&inventory["source_snapshot"], "files")
        .iter()
        .find(|pin| pin.get("path").and_then(Value::as_str) == Some("src/cli/output.rs"))
        .ok_or_else(|| "root CLI output source pin is missing".to_owned())?;
    if matching_pin != added_pin {
        return Err("post-A1 CLI extension and source snapshot pin disagree".to_owned());
    }

    let refreshed = array(extension, "refreshed_existing_pins");
    require_exact_ids(
        refreshed,
        "path",
        &["src/bin/asupersync.rs", "src/database/postgres.rs"],
        "post-A1 refreshed existing pins",
    )?;
    let refreshed_by_path: BTreeMap<_, _> = refreshed
        .iter()
        .map(|row| (text(row, "path"), row))
        .collect();
    for (
        source_path,
        previous_revision,
        previous_sha256,
        previous_lines,
        current_revision,
        current_sha256,
        current_lines,
        inserted_lines,
        deleted_lines,
        classification,
        revisions,
    ) in [
        (
            "src/bin/asupersync.rs",
            "03ae793105ce744c10b878d78d4d0723d23aa81f",
            "397f3800f4a40ccb4f25366bb10ce641d12b4947b9e1b230359db69c5af1e283",
            16_700,
            "0b2c1beaa0447d9e1e7d26f4c598ef68a1fdd087",
            "39719e72f1c00122ec4730aab2e2404086292ac46ced4e9290bb206a3b618ec7",
            16_791,
            116,
            25,
            "INDEPENDENT_REPLAY_ARTIFACT_AND_DIAGNOSTIC_CHANGES",
            ROOT_CLI_REFRESH_REVISIONS,
        ),
        (
            "src/database/postgres.rs",
            "e9705807ec1b5079d7da267d63ffba179314ff41",
            "8794fe1b0ad93d741d576c05aa1ccfe09ddd82eff0a25429ede34a909ce2dc27",
            19_716,
            "0b2c1beaa0447d9e1e7d26f4c598ef68a1fdd087",
            "c4050dea66a46e0719ec53925beb64db42997a7612ea9de0cc9e9e775513e32d",
            19_779,
            90,
            27,
            "INDEPENDENT_READ_CANCELLATION_TEST_SEAM",
            POSTGRES_REFRESH_REVISIONS,
        ),
    ] {
        let row = refreshed_by_path[source_path];
        if text(row, "previous_revision") != previous_revision
            || text(row, "previous_sha256") != previous_sha256
            || number(row, "previous_line_count") != previous_lines
            || text(row, "current_revision") != current_revision
            || text(row, "current_sha256") != current_sha256
            || number(row, "current_line_count") != current_lines
            || number(row, "inserted_lines") != inserted_lines
            || number(row, "deleted_lines") != deleted_lines
            || text(row, "classification") != classification
            || row
                .get("time_acceptance_semantics_changed")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(format!("post-A1 refreshed pin {source_path} drifted"));
        }
        require_exact_strings(row, "change_revisions", revisions)?;
        let current_pin = array(&inventory["source_snapshot"], "files")
            .iter()
            .find(|pin| pin.get("path").and_then(Value::as_str) == Some(source_path))
            .ok_or_else(|| format!("current source pin is missing for {source_path}"))?;
        if text(current_pin, "sha256") != current_sha256
            || number(current_pin, "line_count") != current_lines
        {
            return Err(format!(
                "post-A1 refreshed pin receipt and source snapshot disagree for {source_path}"
            ));
        }
    }

    let boundary = &extension["first_semantic_boundary"];
    if text(boundary, "path") != "src/cli/output.rs"
        || number(boundary, "line") != 156
        || text(boundary, "source_anchor") != "serde_json::to_value(self)"
        || boundary
            .get("later_encoding_and_sink_anchors_included")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("post-A1 CLI semantic boundary drifted".to_owned());
    }

    let row = array(
        &inventory["per_use_classification"],
        "cross_file_consumer_rows",
    )
    .iter()
    .find(|row| {
        row.get("use_id").and_then(Value::as_str)
            == Some("TIME-CROSS-FILE-ROOT-CLI-OUTPUTTABLE-JSON-0156")
    })
    .ok_or_else(|| "root CLI cross-file consumer row is missing".to_owned())?;
    require_exact_strings(
        row,
        "derivation_sources",
        &[
            "src/cli/atp_command_tree.rs:1283",
            "src/cli/atp_command_tree.rs:1285",
            "src/cli/atp_command_tree.rs:1348",
            "src/cli/atp_command_tree.rs:1480",
            "src/cli/atp_command_tree.rs:1553",
            "src/cli/atp_command_tree.rs:1555",
            "src/cli/atp_command_tree.rs:1557",
            "src/cli/atp_command_tree.rs:1589",
        ],
    )?;
    if text(row, "path") != text(boundary, "path")
        || number(row, "line") != number(boundary, "line")
        || text(row, "source_anchor") != text(boundary, "source_anchor")
    {
        return Err("post-A1 CLI receipt and consumer row disagree".to_owned());
    }
    let command_tree = read_repo_file("src/cli/atp_command_tree.rs");
    for wrapper in [
        "AtpArchiveOutput",
        "AtpCiOutput",
        "AtpDatasetOutput",
        "AtpReleaseOutput",
    ] {
        if !command_tree.contains(&format!("pub struct {wrapper}"))
            || !command_tree.contains(&format!("impl_atp_output!(\n    {wrapper},"))
        {
            return Err(format!("root CLI output wrapper {wrapper} wiring drifted"));
        }
    }
    for association in [
        "pub artifacts: Vec<AtpCiArtifact>",
        "pub datasets: Vec<AtpDatasetInfo>",
        "pub releases: Vec<AtpReleaseInfo>",
        "pub archives: Vec<AtpArchiveEntry>",
        "pub storage_stats: Option<AtpArchiveStorageStats>",
        "pub integrity_check_status: AtpIntegrityStatus",
    ] {
        if !command_tree.contains(association) {
            return Err(format!(
                "root CLI timestamp association drifted: {association}"
            ));
        }
    }
    let workflows = read_repo_file("src/cli/atp_workflows.rs");
    if !workflows.contains("fn write_output<T: Outputtable>")
        || !workflows.contains("self.output.write(output)")
    {
        return Err("root CLI workflow output delegation drifted".to_owned());
    }
    let output = read_repo_file("src/cli/output.rs");
    if !output.contains("fn json(&self) -> Result<serde_json::Value, serde_json::Error>")
        || !output.contains("serde_json::to_value(self)")
        || !output.contains("pub fn write<T: Outputtable>")
    {
        return Err("root CLI generic JSON boundary wiring drifted".to_owned());
    }

    let preservation = object(extension, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "time_acceptance_semantics_changed",
        "static_remainder_closed",
        "bead_close_allowed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 CLI preservation boundary drifted".to_owned());
    }

    let no_claim = text(extension, "no_claim_boundary");
    for required in [
        "does not execute the CLI",
        "prove emitted bytes or round trips",
        "no TIME acceptance-semantic change",
        "complete the derived-consumer inventory",
        "authorize dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!("post-A1 CLI no-claim boundary missing {required}"));
        }
    }
    Ok(())
}

fn validate_post_a1_benchmark_lineage_extension(inventory: &Value) -> Result<(), String> {
    let extension = inventory
        .get("post_a1_benchmark_lineage_extension")
        .ok_or_else(|| "post_a1_benchmark_lineage_extension is required".to_owned())?;
    for (key, expected) in [
        ("extension_id", "TIME-A1-BENCHMARK-LINEAGE-2026-08-06"),
        ("captured_date_utc", "2026-08-06"),
        (
            "extension_state",
            "STATIC_ROOT_PUBLIC_CARRIER_LINEAGE_EXTENSION",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        ("required_disposition", "KEEP_OPEN"),
    ] {
        if extension.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "post-A1 benchmark lineage extension {key} must be {expected}"
            ));
        }
    }
    for (key, expected) in [
        ("source_pin_path_count", 72_u64),
        ("root_public_datetime_field_count", 12),
        ("declared_first_boundary_field_count", 10),
        ("no_in_tree_producer_field_count", 2),
        ("unclassified_root_public_datetime_field_count", 0),
        ("cross_file_consumer_anchor_count", 23),
        ("cross_file_direct_source_anchor_count", 37),
        ("declared_consumer_unique_direct_source_anchor_count", 69),
        ("classified_anchor_count", 259),
    ] {
        if extension.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!(
                "post-A1 benchmark lineage extension {key} must be {expected}"
            ));
        }
    }

    let added_pins = array(extension, "added_source_pins");
    require_exact_ids(
        added_pins,
        "path",
        &[
            "src/atp/benchmark/adapters.rs",
            "src/atp/benchmark/profiles.rs",
            "src/atp/benchmark/suite.rs",
        ],
        "post-A1 benchmark lineage source pins",
    )?;
    let source_pins: BTreeMap<_, _> = array(&inventory["source_snapshot"], "files")
        .iter()
        .map(|pin| (text(pin, "path"), pin))
        .collect();
    for (path, sha256, lines) in [
        (
            "src/atp/benchmark/adapters.rs",
            "e3c62fcd9d4da96ac550143f816cfdd21d01fbbaa81fef4585cd795be4f0161c",
            1_091,
        ),
        (
            "src/atp/benchmark/profiles.rs",
            "c58666954514a9b16a1744b4e0b911b7da69ccd705fe8c4e54fcc1a40b7d7e5b",
            613,
        ),
        (
            "src/atp/benchmark/suite.rs",
            "4c53f1453815ab28acd88ceff677cc837200044bf65a5739f464d1120b7f11a9",
            341,
        ),
    ] {
        let added = added_pins
            .iter()
            .find(|pin| text(pin, "path") == path)
            .ok_or_else(|| format!("post-A1 benchmark lineage pin is missing for {path}"))?;
        if text(added, "sha256") != sha256 || number(added, "line_count") != lines {
            return Err(format!("post-A1 benchmark lineage pin drifted for {path}"));
        }
        if source_pins.get(path).copied() != Some(added) {
            return Err(format!(
                "post-A1 benchmark lineage and source snapshot pins disagree for {path}"
            ));
        }
    }

    let expected_consumers = [
        "TIME-CROSS-FILE-BENCHMARK-ATP-RESULT-0204",
        "TIME-CROSS-FILE-BENCHMARK-CURL-RESULT-0961",
        "TIME-CROSS-FILE-BENCHMARK-RCLONE-RESULT-0692",
        "TIME-CROSS-FILE-BENCHMARK-REPORT-CONSTRUCTOR-0099",
        "TIME-CROSS-FILE-BENCHMARK-RSYNC-RESULT-0511",
        "TIME-CROSS-FILE-BENCHMARK-SCP-RESULT-0279",
    ];
    require_exact_strings(extension, "cross_file_consumer_ids", &expected_consumers)?;
    let cross_file_rows = array(
        &inventory["per_use_classification"],
        "cross_file_consumer_rows",
    );
    let cross_file_ids = row_ids(cross_file_rows, "use_id");
    let expected_consumer_set: BTreeSet<String> = expected_consumers
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    if !expected_consumer_set.is_subset(&cross_file_ids) {
        return Err("post-A1 benchmark lineage consumer rows are missing".to_owned());
    }
    for (use_id, path, line, anchor) in [
        (
            "TIME-CROSS-FILE-BENCHMARK-SCP-RESULT-0279",
            "src/atp/benchmark/adapters.rs",
            279_u64,
            "environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,",
        ),
        (
            "TIME-CROSS-FILE-BENCHMARK-RSYNC-RESULT-0511",
            "src/atp/benchmark/adapters.rs",
            511,
            "environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,",
        ),
        (
            "TIME-CROSS-FILE-BENCHMARK-RCLONE-RESULT-0692",
            "src/atp/benchmark/adapters.rs",
            692,
            "environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,",
        ),
        (
            "TIME-CROSS-FILE-BENCHMARK-CURL-RESULT-0961",
            "src/atp/benchmark/adapters.rs",
            961,
            "environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,",
        ),
        (
            "TIME-CROSS-FILE-BENCHMARK-ATP-RESULT-0204",
            "src/atp/benchmark/profiles.rs",
            204,
            "environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,",
        ),
        (
            "TIME-CROSS-FILE-BENCHMARK-REPORT-CONSTRUCTOR-0099",
            "src/atp/benchmark/suite.rs",
            99,
            "let report = BenchmarkReport::new(",
        ),
    ] {
        let row = cross_file_rows
            .iter()
            .find(|row| text(row, "use_id") == use_id)
            .ok_or_else(|| format!("post-A1 benchmark consumer row is missing for {use_id}"))?;
        if text(row, "path") != path
            || number(row, "line") != line
            || text(row, "source_anchor") != anchor
        {
            return Err(format!(
                "post-A1 benchmark consumer row drifted for {use_id}"
            ));
        }
    }

    let dispositions = array(extension, "root_public_carrier_dispositions");
    require_exact_ids(
        dispositions,
        "disposition_id",
        &[
            "TIME-CARRIER-DISPOSITION-BENCHMARK-ENVIRONMENT",
            "TIME-CARRIER-DISPOSITION-BENCHMARK-REPORT",
            "TIME-CARRIER-DISPOSITION-CLI-GENERIC-JSON",
            "TIME-CARRIER-DISPOSITION-CLI-NO-PRODUCER",
        ],
        "post-A1 root public carrier dispositions",
    )?;
    let root_public_field_ids: BTreeSet<String> = array(inventory, "public_datetime_fields")
        .iter()
        .filter(|row| text(row, "crate") == "asupersync")
        .map(|row| text(row, "field_id").to_owned())
        .collect();
    let mut disposition_field_ids = BTreeSet::new();
    for disposition in dispositions {
        let disposition_id = text(disposition, "disposition_id");
        let (state, field_ids, consumer_ids): (&str, &[&str], &[&str]) = match disposition_id {
            "TIME-CARRIER-DISPOSITION-CLI-GENERIC-JSON" => (
                "DECLARED_FIRST_CROSS_FILE_JSON_BOUNDARY",
                &[
                    "TIME-PUB-CLI-ARCHIVE-ARCHIVED",
                    "TIME-PUB-CLI-ARCHIVE-EXPIRES",
                    "TIME-PUB-CLI-ARCHIVE-VERIFIED",
                    "TIME-PUB-CLI-CI-EXPIRES",
                    "TIME-PUB-CLI-CI-TIMESTAMP",
                    "TIME-PUB-CLI-DATASET-UPDATED",
                    "TIME-PUB-CLI-INTEGRITY-LAST-CHECK",
                    "TIME-PUB-CLI-RELEASE-PUBLISHED",
                ],
                &["TIME-CROSS-FILE-ROOT-CLI-OUTPUTTABLE-JSON-0156"],
            ),
            "TIME-CARRIER-DISPOSITION-CLI-NO-PRODUCER" => (
                "NO_IN_TREE_PRODUCER_IN_PINNED_SNAPSHOT",
                &[
                    "TIME-PUB-CLI-BENCH-SYSTEM-TIMESTAMP",
                    "TIME-PUB-CLI-STATUS-TIMESTAMP",
                ],
                &[],
            ),
            "TIME-CARRIER-DISPOSITION-BENCHMARK-ENVIRONMENT" => (
                "DECLARED_FIRST_CROSS_FILE_EMBEDDINGS",
                &["TIME-PUB-BENCH-ENVIRONMENT-TIMESTAMP"],
                &[
                    "TIME-CROSS-FILE-BENCHMARK-ATP-RESULT-0204",
                    "TIME-CROSS-FILE-BENCHMARK-CURL-RESULT-0961",
                    "TIME-CROSS-FILE-BENCHMARK-RCLONE-RESULT-0692",
                    "TIME-CROSS-FILE-BENCHMARK-RSYNC-RESULT-0511",
                    "TIME-CROSS-FILE-BENCHMARK-SCP-RESULT-0279",
                ],
            ),
            "TIME-CARRIER-DISPOSITION-BENCHMARK-REPORT" => (
                "DECLARED_FIRST_CROSS_FILE_CONSTRUCTOR",
                &["TIME-PUB-BENCH-REPORT-TIMESTAMP"],
                &["TIME-CROSS-FILE-BENCHMARK-REPORT-CONSTRUCTOR-0099"],
            ),
            _ => return Err(format!("unexpected root public carrier {disposition_id}")),
        };
        if text(disposition, "state") != state {
            return Err(format!(
                "root public carrier state drifted for {disposition_id}"
            ));
        }
        require_exact_strings(disposition, "field_ids", field_ids)?;
        require_exact_strings(disposition, "consumer_ids", consumer_ids)?;
        for field_id in field_ids {
            if !disposition_field_ids.insert((*field_id).to_owned()) {
                return Err(format!("duplicate root public carrier field {field_id}"));
            }
        }
    }
    if disposition_field_ids != root_public_field_ids || root_public_field_ids.len() != 12 {
        return Err("root public DateTime carrier coverage drifted".to_owned());
    }

    let preservation = object(extension, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "time_acceptance_semantics_changed",
        "static_remainder_closed",
        "bead_close_allowed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 benchmark lineage preservation boundary drifted".to_owned());
    }
    let no_claim = text(extension, "no_claim_boundary");
    for required in [
        "does not execute the benchmark feature",
        "prove serialized bytes",
        "second-order propagation",
        "close A1",
        "authorize dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!(
                "post-A1 benchmark lineage no-claim boundary missing {required}"
            ));
        }
    }
    Ok(())
}

fn validate_post_a1_conformance_raptorq_lineage_extension(inventory: &Value) -> Result<(), String> {
    let extension = inventory
        .get("post_a1_conformance_raptorq_lineage_extension")
        .ok_or_else(|| "post_a1_conformance_raptorq_lineage_extension is required".to_owned())?;
    for (key, expected) in [
        (
            "extension_id",
            "TIME-A1-CONFORMANCE-RAPTORQ-LINEAGE-2026-08-06",
        ),
        ("captured_date_utc", "2026-08-06"),
        (
            "extension_state",
            "STATIC_DECLARED_CONFORMANCE_RAPTORQ_CARRIER_LINEAGE_EXTENSION",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        ("required_disposition", "KEEP_OPEN"),
    ] {
        if extension.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "post-A1 conformance RaptorQ extension {key} must be {expected}"
            ));
        }
    }
    for (key, expected) in [
        ("source_pin_path_count", 74_u64),
        ("main_conformance_raptorq_public_string_field_count", 4),
        ("direct_producer_anchor_count", 5),
        ("derived_carrier_field_count", 1),
        ("additional_derived_operation_anchor_count", 39),
        ("derived_operation_anchor_count", 47),
        ("cross_file_consumer_anchor_count", 34),
        ("cross_file_direct_source_anchor_count", 41),
        ("declared_consumer_unique_direct_source_anchor_count", 72),
        ("classified_anchor_count", 271),
    ] {
        if extension.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!(
                "post-A1 conformance RaptorQ extension {key} must be {expected}"
            ));
        }
    }

    let added_pins = array(extension, "added_source_pins");
    require_exact_ids(
        added_pins,
        "path",
        &[
            "conformance/raptorq_rfc6330/reporting/bin/maintain_fixtures.rs",
            "conformance/raptorq_rfc6330/reporting/src/compliance_report.rs",
        ],
        "post-A1 conformance RaptorQ source pins",
    )?;
    let source_pins: BTreeMap<_, _> = array(&inventory["source_snapshot"], "files")
        .iter()
        .map(|pin| (text(pin, "path"), pin))
        .collect();
    for (path, sha256, lines) in [
        (
            "conformance/raptorq_rfc6330/reporting/bin/maintain_fixtures.rs",
            "137cecd6089b99b0ca6d733c5c14951466e814632fd031533456b5cf8c5b5c78",
            524_u64,
        ),
        (
            "conformance/raptorq_rfc6330/reporting/src/compliance_report.rs",
            "5f1b2c5427243361f20d5343c0f78743132bdc8322c1e0947eff1965a5750db2",
            501,
        ),
    ] {
        let added = added_pins
            .iter()
            .find(|pin| text(pin, "path") == path)
            .ok_or_else(|| format!("post-A1 conformance RaptorQ pin missing for {path}"))?;
        if text(added, "sha256") != sha256 || number(added, "line_count") != lines {
            return Err(format!(
                "post-A1 conformance RaptorQ pin drifted for {path}"
            ));
        }
        if source_pins.get(path).copied() != Some(added) {
            return Err(format!(
                "post-A1 conformance RaptorQ and source snapshot pins disagree for {path}"
            ));
        }
    }

    let reconciliation = extension
        .get("line_sensitive_pin_reconciliation")
        .filter(|value| value.is_object())
        .ok_or_else(|| "line_sensitive_pin_reconciliation must be an object".to_owned())?;
    if text(reconciliation, "path") != "src/database/postgres.rs"
        || text(reconciliation, "current_sha256")
            != "c4050dea66a46e0719ec53925beb64db42997a7612ea9de0cc9e9e775513e32d"
        || number(reconciliation, "current_line_count") != 19_779
        || number(reconciliation, "uniform_line_delta") != 63
        || number(reconciliation, "refreshed_explicit_anchor_count") != 3
        || number(reconciliation, "refreshed_direct_source_reference_count") != 1
        || text(reconciliation, "previous_direct_source_id") != "src/database/postgres.rs:18086"
        || text(reconciliation, "current_direct_source_id") != "src/database/postgres.rs:18149"
        || text(reconciliation, "classification")
            != "LINE_ONLY_SHIFT_FROM_PREVIOUSLY_CLASSIFIED_READ_CANCELLATION_SEAM"
        || reconciliation
            .get("additional_derived_projection_change_includes_new_history_row")
            .and_then(Value::as_bool)
            != Some(true)
        || reconciliation
            .get("time_acceptance_semantics_changed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("post-A1 line-sensitive PostgreSQL reconciliation drifted".to_owned());
    }
    require_exact_strings(
        reconciliation,
        "refreshed_anchor_ids",
        &[
            "TIME-DERIVED-POSTGRES-MIDNIGHT-CONSTRUCTION-18151",
            "TIME-LITERAL-OVERRIDE-POSTGRES-18142",
            "TIME-LITERAL-OVERRIDE-POSTGRES-18153",
        ],
    )?;
    let previous_projections = object(reconciliation, "previous_projection_sha256");
    let current_projections = object(reconciliation, "current_projection_sha256");
    for (key, previous, current) in [
        (
            "literal_operation",
            "a533497be94a3a8c649a061117053acff88821c102e9cedbe16cb4da0b66990b",
            LITERAL_OPERATION_PROJECTION_SHA256,
        ),
        (
            "literal_source",
            "5c4020cfe41d10dbfcab19c64f3677ee78941c65441c12da93dc7e3cd6946f2d",
            LITERAL_SOURCE_PROJECTION_SHA256,
        ),
        (
            "literal_override",
            "81f3549c7644361eabee937044ba098315b3aeffbd079d9c644eb1d60ccc3f84",
            LITERAL_OVERRIDE_PROJECTION_SHA256,
        ),
        (
            "additional_derived",
            "b20b65d03be1995802d929275531ac96a8a66ec06c1c64f0bf887ee27803f674",
            RAPTORQ_LINEAGE_ADDITIONAL_DERIVED_PROJECTION_SHA256,
        ),
    ] {
        if previous_projections.get(key).and_then(Value::as_str) != Some(previous)
            || current_projections.get(key).and_then(Value::as_str) != Some(current)
        {
            return Err(format!("post-A1 line-sensitive projection {key} drifted"));
        }
    }

    require_exact_strings(
        extension,
        "direct_producer_ids",
        &[
            "conformance/raptorq_rfc6330/reporting/src/coverage_matrix.rs:229",
            "conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs:44",
            "conformance/raptorq_rfc6330/reporting/src/maintenance_workflows.rs:80",
            "conformance/raptorq_rfc6330/reporting/src/regression_detection.rs:64",
            "conformance/raptorq_rfc6330/reporting/src/regression_detection.rs:84",
        ],
    )?;
    let expected_derived = [
        "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-FIELD-0039",
        "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-SERIALIZE-0077",
    ];
    require_exact_strings(extension, "derived_consumer_ids", &expected_derived)?;
    let expected_cross_file = [
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-CONFIGURED-0164",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-DIFFERENTIAL-0218",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-GOLDEN-0199",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-CI-MATRIX-0111",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-HISTORY-CONSTRUCTOR-0039",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-HISTORY-UPDATE-0100",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-REGRESSION-MATRIX-0092",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-REPORT-MATRIX-0080",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-HTML-0298",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-JSON-0277",
        "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-MARKDOWN-0095",
    ];
    require_exact_strings(extension, "cross_file_consumer_ids", &expected_cross_file)?;
    let derived_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "additional_derived_operation_rows",
        ),
        "use_id",
    );
    let cross_file_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "cross_file_consumer_rows",
        ),
        "use_id",
    );
    if !expected_derived.iter().all(|id| derived_ids.contains(*id))
        || !expected_cross_file
            .iter()
            .all(|id| cross_file_ids.contains(*id))
    {
        return Err("post-A1 conformance RaptorQ consumer rows are missing".to_owned());
    }

    let dispositions = array(extension, "carrier_dispositions");
    require_exact_ids(
        dispositions,
        "disposition_id",
        &[
            "TIME-CARRIER-DISPOSITION-RAPTORQ-CONFORMANCE-HISTORY",
            "TIME-CARRIER-DISPOSITION-RAPTORQ-CONFORMANCE-RECORD",
            "TIME-CARRIER-DISPOSITION-RAPTORQ-COVERAGE-MATRIX",
            "TIME-CARRIER-DISPOSITION-RAPTORQ-REFERENCE-VERSION",
        ],
        "post-A1 conformance RaptorQ carrier dispositions",
    )?;
    let public_field_ids: BTreeSet<String> =
        array(inventory, "public_chrono_generated_string_fields")
            .iter()
            .filter(|row| text(row, "module").starts_with("raptorq_rfc6330_reporting::"))
            .map(|row| text(row, "field_id").to_owned())
            .collect();
    let all_consumer_ids: BTreeSet<String> = derived_ids.union(&cross_file_ids).cloned().collect();
    let mut disposition_field_ids = BTreeSet::new();
    for disposition in dispositions {
        let disposition_id = text(disposition, "disposition_id");
        let (state, field_ids, consumer_ids): (&str, &[&str], &[&str]) = match disposition_id {
            "TIME-CARRIER-DISPOSITION-RAPTORQ-REFERENCE-VERSION" => (
                "PRIVATE_EXECUTABLE_CONSTRUCTORS_WITH_NO_TIMESTAMP_SINK_AND_NO_IN_TREE_UPDATE_CALLER",
                &["TIME-PUB-CONFORMANCE-RAPTORQ-REFERENCE-UPDATED"],
                &[
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-CONFIGURED-0164",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-DIFFERENTIAL-0218",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-MAINT-GOLDEN-0199",
                ],
            ),
            "TIME-CARRIER-DISPOSITION-RAPTORQ-COVERAGE-MATRIX" => (
                "PUBLIC_PIPELINE_REPORT_AND_HISTORY_BOUNDARIES_DECLARED",
                &["TIME-PUB-CONFORMANCE-RAPTORQ-COVERAGE-GENERATED"],
                &[
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-CI-MATRIX-0111",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-HISTORY-UPDATE-0100",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-REGRESSION-MATRIX-0092",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-REPORT-MATRIX-0080",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-HTML-0298",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-JSON-0277",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-REPORT-MARKDOWN-0095",
                    "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-FIELD-0039",
                    "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-SERIALIZE-0077",
                ],
            ),
            "TIME-CARRIER-DISPOSITION-RAPTORQ-CONFORMANCE-RECORD" => (
                "DERIVED_FROM_COVERAGE_MATRIX_AND_PERSISTED_WITH_HISTORY",
                &["TIME-PUB-CONFORMANCE-RAPTORQ-RECORD-TIMESTAMP"],
                &[
                    "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-FIELD-0039",
                    "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-SERIALIZE-0077",
                ],
            ),
            "TIME-CARRIER-DISPOSITION-RAPTORQ-CONFORMANCE-HISTORY" => (
                "PUBLIC_PIPELINE_CONSTRUCTION_UPDATE_AND_PERSISTENCE_DECLARED",
                &["TIME-PUB-CONFORMANCE-RAPTORQ-HISTORY-UPDATED"],
                &[
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-HISTORY-CONSTRUCTOR-0039",
                    "TIME-CROSS-FILE-CONFORMANCE-RAPTORQ-PIPELINE-HISTORY-UPDATE-0100",
                    "TIME-DERIVED-CONFORMANCE-RAPTORQ-HISTORY-SERIALIZE-0077",
                ],
            ),
            _ => {
                return Err(format!(
                    "unexpected conformance RaptorQ carrier {disposition_id}"
                ));
            }
        };
        if text(disposition, "state") != state {
            return Err(format!(
                "conformance RaptorQ carrier state drifted for {disposition_id}"
            ));
        }
        require_exact_strings(disposition, "field_ids", field_ids)?;
        require_exact_strings(disposition, "consumer_ids", consumer_ids)?;
        for field_id in field_ids {
            if !disposition_field_ids.insert((*field_id).to_owned()) {
                return Err(format!(
                    "duplicate conformance RaptorQ carrier field {field_id}"
                ));
            }
        }
        if !consumer_ids
            .iter()
            .all(|consumer_id| all_consumer_ids.contains(*consumer_id))
        {
            return Err(format!(
                "conformance RaptorQ carrier consumer drifted for {disposition_id}"
            ));
        }
    }
    if disposition_field_ids != public_field_ids || public_field_ids.len() != 4 {
        return Err("conformance RaptorQ public carrier coverage drifted".to_owned());
    }
    let public_strings = array(inventory, "public_chrono_generated_string_fields");
    let reference_field = public_strings
        .iter()
        .find(|row| {
            row.get("field_id").and_then(Value::as_str)
                == Some("TIME-PUB-CONFORMANCE-RAPTORQ-REFERENCE-UPDATED")
        })
        .ok_or_else(|| "RaptorQ ReferenceVersion field is missing".to_owned())?;
    if text(reference_field, "in_tree_persistence")
        != "EXCLUDED_FROM_PRIVATE_FIXTURE_VERSION_METADATA"
    {
        return Err("RaptorQ ReferenceVersion persistence boundary drifted".to_owned());
    }
    let maintenance_bin =
        read_repo_file("conformance/raptorq_rfc6330/reporting/bin/maintain_fixtures.rs");
    if maintenance_bin.contains(".update_from_git(") || maintenance_bin.contains("last_updated") {
        return Err("RaptorQ private maintenance timestamp sink drifted".to_owned());
    }

    let preservation = object(extension, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "time_acceptance_semantics_changed",
        "static_remainder_closed",
        "bead_close_allowed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 conformance RaptorQ preservation boundary drifted".to_owned());
    }
    let no_claim = text(extension, "no_claim_boundary");
    for required in [
        "does not execute conformance tools",
        "prove emitted or persisted bytes",
        "prove readback",
        "second-order propagation",
        "close A1",
        "authorize dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!(
                "post-A1 conformance RaptorQ no-claim boundary missing {required}"
            ));
        }
    }
    Ok(())
}

fn validate_post_a1_public_carrier_lineage_extension(inventory: &Value) -> Result<(), String> {
    let extension = inventory
        .get("post_a1_public_carrier_lineage_extension")
        .ok_or_else(|| "post_a1_public_carrier_lineage_extension is required".to_owned())?;
    for (key, expected) in [
        ("extension_id", "TIME-A1-PUBLIC-CARRIER-LINEAGE-2026-08-06"),
        ("captured_date_utc", "2026-08-06"),
        (
            "extension_state",
            "STATIC_COMPLETE_PUBLIC_CARRIER_FIRST_BOUNDARY_DISPOSITION",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        ("required_disposition", "KEEP_OPEN"),
    ] {
        if extension.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "post-A1 public carrier lineage extension {key} must be {expected}"
            ));
        }
    }
    for (key, expected) in [
        ("source_pin_path_count", 74_u64),
        ("public_datetime_field_count", 18),
        ("public_chrono_generated_string_field_count", 12),
        ("all_public_chrono_backed_timestamp_field_count", 30),
        ("declared_first_boundary_field_count", 28),
        ("no_in_tree_producer_field_count", 2),
        ("unclassified_public_carrier_field_count", 0),
        ("public_cross_file_consumer_id_count", 32),
        ("public_derived_consumer_id_count", 2),
        ("declared_public_consumer_id_count", 34),
    ] {
        if extension.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!(
                "post-A1 public carrier lineage extension {key} must be {expected}"
            ));
        }
    }

    let datetime_ids = row_ids(array(inventory, "public_datetime_fields"), "field_id");
    let string_ids = row_ids(
        array(inventory, "public_chrono_generated_string_fields"),
        "field_id",
    );
    let public_field_ids: BTreeSet<String> = datetime_ids.union(&string_ids).cloned().collect();
    if datetime_ids.len() != 18
        || string_ids.len() != 12
        || public_field_ids.len() != 30
        || !datetime_ids.is_disjoint(&string_ids)
    {
        return Err("public timestamp carrier inventory totals drifted".to_owned());
    }

    let mut expected: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();
    for (extension_key, disposition_key) in [
        (
            "post_a1_benchmark_lineage_extension",
            "root_public_carrier_dispositions",
        ),
        (
            "post_a1_conformance_raptorq_lineage_extension",
            "carrier_dispositions",
        ),
    ] {
        let source_extension = inventory
            .get(extension_key)
            .ok_or_else(|| format!("{extension_key} is required"))?;
        for disposition in array(source_extension, disposition_key) {
            let state = text(disposition, "state").to_owned();
            let consumers = string_set(disposition, "consumer_ids");
            for field_id in array(disposition, "field_ids") {
                let field_id = field_id
                    .as_str()
                    .ok_or_else(|| format!("{disposition_key} field IDs must be strings"))?;
                if expected
                    .insert(field_id.to_owned(), (state.clone(), consumers.clone()))
                    .is_some()
                {
                    return Err(format!(
                        "duplicate public carrier disposition for {field_id}"
                    ));
                }
            }
        }
    }
    for (field_id, state, consumer_id) in [
        (
            "TIME-PUB-CONFORMANCE-H1-EXPECT-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H1-EXPECT-JSON-0093",
        ),
        (
            "TIME-PUB-CONFORMANCE-H1-REQUEST-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H1-REQUEST-JSON-0093",
        ),
        (
            "TIME-PUB-CONFORMANCE-H1-RESPONSE-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H1-RESPONSE-JSON-0093",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-CONNECT-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H2-CONNECT-JSON-0097",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-CONTINUATION-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H2-CONTINUATION-JSON-0097",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-DATA-END",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-DATA-END-JSON-0098",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-ENABLE-PUSH-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-H2-ENABLE-PUSH-JSON-0094",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-GOAWAY",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-GOAWAY-JSON-0093",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-PING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-PING-JSON-0100",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-PRIORITY",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-PRIORITY-JSON-0093",
        ),
        (
            "TIME-PUB-CONFORMANCE-H2-SETTINGS",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-SETTINGS-JSON-0094",
        ),
        (
            "TIME-PUB-CONFORMANCE-HPACK",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-HPACK-JSON-0094",
        ),
        (
            "TIME-PUB-CONFORMANCE-HPACK-ENCODER-STRING",
            "DECLARED_EXECUTABLE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-CONFORMANCE-HPACK-ENCODER-JSON-0097",
        ),
        (
            "TIME-PUB-EXCLUDED-CONFORMANCE-PING-REPORT-TIMESTAMP",
            "DECLARED_EXCLUDED_WORKSPACE_PRETTY_JSON_BOUNDARY",
            "TIME-CROSS-FILE-EXCLUDED-PING-JSON-0051",
        ),
    ] {
        let consumers: BTreeSet<String> = std::iter::once(consumer_id.to_owned()).collect();
        if expected
            .insert(field_id.to_owned(), (state.to_owned(), consumers))
            .is_some()
        {
            return Err(format!(
                "duplicate public carrier disposition for {field_id}"
            ));
        }
    }
    if expected.len() != 30 || expected.keys().cloned().collect::<BTreeSet<_>>() != public_field_ids
    {
        return Err("public carrier expected disposition coverage drifted".to_owned());
    }

    let lineage_rows = array(extension, "field_lineage_rows");
    let expected_field_ids: Vec<_> = public_field_ids.iter().map(String::as_str).collect();
    require_exact_ids(
        lineage_rows,
        "field_id",
        &expected_field_ids,
        "post-A1 public carrier lineage rows",
    )?;
    let cross_file_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "cross_file_consumer_rows",
        ),
        "use_id",
    );
    let derived_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "additional_derived_operation_rows",
        ),
        "use_id",
    );
    let known_consumer_ids: BTreeSet<String> =
        cross_file_ids.union(&derived_ids).cloned().collect();
    let mut referenced_consumer_ids = BTreeSet::new();
    let mut declared_boundary_fields = 0_u64;
    let mut no_producer_fields = 0_u64;
    for row in lineage_rows {
        let field_id = text(row, "field_id");
        let (expected_state, expected_consumers) = expected
            .get(field_id)
            .ok_or_else(|| format!("unexpected public carrier lineage row {field_id}"))?;
        let expected_section = if datetime_ids.contains(field_id) {
            "public_datetime_fields"
        } else {
            "public_chrono_generated_string_fields"
        };
        let consumers = string_set(row, "consumer_ids");
        if text(row, "inventory_section") != expected_section
            || text(row, "state") != expected_state.as_str()
            || &consumers != expected_consumers
            || !consumers.is_subset(&known_consumer_ids)
        {
            return Err(format!("public carrier lineage drifted for {field_id}"));
        }
        if consumers.is_empty() {
            no_producer_fields += 1;
        } else {
            declared_boundary_fields += 1;
        }
        referenced_consumer_ids.extend(consumers);
    }
    let referenced_cross_file_count = referenced_consumer_ids
        .intersection(&cross_file_ids)
        .count();
    let referenced_derived_count = referenced_consumer_ids.intersection(&derived_ids).count();
    if declared_boundary_fields != 28
        || no_producer_fields != 2
        || referenced_cross_file_count != 32
        || referenced_derived_count != 2
        || referenced_consumer_ids.len() != 34
    {
        return Err("public carrier lineage aggregate counts drifted".to_owned());
    }
    if text(extension, "public_carrier_lineage_projection_sha256")
        != PUBLIC_CARRIER_LINEAGE_PROJECTION_SHA256
        || sha256_hex(public_carrier_lineage_projection(lineage_rows).as_bytes())
            != PUBLIC_CARRIER_LINEAGE_PROJECTION_SHA256
    {
        return Err("public carrier lineage projection drifted".to_owned());
    }

    let preservation = object(extension, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "time_acceptance_semantics_changed",
        "test_profile_carrier_remainder_closed",
        "second_order_propagation_closed",
        "static_remainder_closed",
        "bead_close_allowed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 public carrier preservation boundary drifted".to_owned());
    }
    let no_claim = text(extension, "no_claim_boundary");
    for required in [
        "all 30 public Chrono-backed timestamp carriers",
        "does not execute any producer or consumer",
        "prove serialized or persisted bytes",
        "seven test-profile fields",
        "second-order propagation",
        "close A1",
        "authorize dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!(
                "post-A1 public carrier no-claim boundary missing {required}"
            ));
        }
    }
    Ok(())
}

fn validate_post_a1_test_profile_carrier_lineage_extension(
    inventory: &Value,
) -> Result<(), String> {
    let extension = inventory
        .get("post_a1_test_profile_carrier_lineage_extension")
        .ok_or_else(|| "post_a1_test_profile_carrier_lineage_extension is required".to_owned())?;
    for (key, expected) in [
        (
            "extension_id",
            "TIME-A1-TEST-PROFILE-CARRIER-LINEAGE-2026-08-06",
        ),
        ("captured_date_utc", "2026-08-06"),
        (
            "extension_state",
            "STATIC_COMPLETE_TEST_PROFILE_CARRIER_FIRST_BOUNDARY_DISPOSITION",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        ("required_disposition", "KEEP_OPEN"),
    ] {
        if extension.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "post-A1 test-profile carrier extension {key} must be {expected}"
            ));
        }
    }
    for (key, expected) in [
        ("source_pin_path_count", 74_u64),
        ("test_profile_datetime_field_count", 7),
        ("test_profile_publicly_reachable_field_count", 5),
        ("test_profile_pub_in_private_module_field_count", 1),
        ("test_profile_private_serialized_field_count", 1),
        ("declared_first_boundary_field_count", 7),
        ("unclassified_test_profile_carrier_field_count", 0),
        ("added_derived_consumer_id_count", 8),
        ("referenced_derived_consumer_id_count", 12),
        ("referenced_cross_file_consumer_id_count", 2),
        ("declared_test_profile_consumer_id_count", 14),
        ("additional_derived_operation_anchor_count", 47),
        ("derived_operation_anchor_count", 55),
        ("declared_consumer_unique_direct_source_anchor_count", 76),
        ("classified_anchor_count", 279),
    ] {
        if extension.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!(
                "post-A1 test-profile carrier extension {key} must be {expected}"
            ));
        }
    }
    if extension
        .get("test_profile_first_boundary_disposition_complete")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("test-profile first-boundary completion state drifted".to_owned());
    }

    let added_ids = [
        "TIME-DERIVED-STANDALONE-GOLDEN-METADATA-ASSOCIATE-0605",
        "TIME-DERIVED-STANDALONE-MATRIX-REPORT-JSON-0254",
        "TIME-DERIVED-STANDALONE-MATRIX-SAVE-JSON-0464",
        "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0101",
        "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0118",
        "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0131",
        "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0148",
        "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0165",
    ];
    require_exact_strings(extension, "added_derived_consumer_ids", &added_ids)?;

    let field_ids = row_ids(array(inventory, "test_profile_datetime_fields"), "field_id");
    let lineage_rows = array(extension, "field_lineage_rows");
    let expected_field_ids: Vec<_> = field_ids.iter().map(String::as_str).collect();
    if field_ids.len() != 7 {
        return Err("test-profile field inventory total drifted".to_owned());
    }
    require_exact_ids(
        lineage_rows,
        "field_id",
        &expected_field_ids,
        "post-A1 test-profile carrier lineage rows",
    )?;

    let derived_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "additional_derived_operation_rows",
        ),
        "use_id",
    );
    let cross_file_ids = row_ids(
        array(
            &inventory["per_use_classification"],
            "cross_file_consumer_rows",
        ),
        "use_id",
    );
    let known_consumer_ids: BTreeSet<String> =
        derived_ids.union(&cross_file_ids).cloned().collect();
    if !added_ids.iter().all(|id| derived_ids.contains(*id)) {
        return Err("test-profile added derived consumer rows are missing".to_owned());
    }

    let mut referenced_consumer_ids = BTreeSet::new();
    for row in lineage_rows {
        let field_id = text(row, "field_id");
        let (expected_state, expected_consumers): (&str, &[&str]) = match field_id {
            "TIME-TEST-GOLDEN-FIXTURE-GENERATED" => (
                "PRIVATE_SERIALIZED_FIXTURE_BOUNDARY_DECLARED",
                &["TIME-DERIVED-STANDALONE-GOLDEN-SERIALIZE-0197"],
            ),
            "TIME-TEST-GOLDEN-METADATA-UPDATED" => (
                "PUBLIC_TEST_CARRIER_ASSOCIATION_DECLARED_NO_FIELD_READ_OR_SERIALIZATION",
                &["TIME-DERIVED-STANDALONE-GOLDEN-METADATA-ASSOCIATE-0605"],
            ),
            "TIME-TEST-REPORT-COVERAGE-GENERATED" => (
                "PUBLIC_STANDALONE_TEMPLATE_AND_JSON_BOUNDARIES_DECLARED",
                &[
                    "TIME-DERIVED-STANDALONE-MATRIX-REPORT-JSON-0254",
                    "TIME-DERIVED-STANDALONE-MATRIX-SAVE-JSON-0464",
                    "TIME-DERIVED-STANDALONE-TEMPLATE-FIELD-0221",
                ],
            ),
            "TIME-TEST-REPORT-FILE-MODIFIED" => (
                "PUBLIC_STANDALONE_RETENTION_AND_JSON_BOUNDARIES_DECLARED",
                &[
                    "TIME-CROSS-FILE-STANDALONE-MAINT-HEALTH-JSON-0239",
                    "TIME-DERIVED-STANDALONE-HEALTH-RETAIN-0280",
                ],
            ),
            "TIME-TEST-REPORT-MAINTENANCE-TIMESTAMP" => (
                "PUBLIC_STANDALONE_JSON_BOUNDARY_DECLARED",
                &["TIME-CROSS-FILE-STANDALONE-MAINT-RESULT-JSON-0552"],
            ),
            "TIME-TEST-REPORT-SNAPSHOT-TIMESTAMP" => (
                "PUBLIC_STANDALONE_SNAPSHOT_JSON_BOUNDARY_DECLARED",
                &["TIME-DERIVED-STANDALONE-SNAPSHOT-SERIALIZE-0287"],
            ),
            "TIME-TEST-ROOT-HPACK-FIXTURE-GENERATED" => (
                "PRIVATE_TEST_FIXTURE_CLONE_EMBEDDINGS_DECLARED_NO_FIELD_READ_OR_SERIALIZATION",
                &[
                    "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0101",
                    "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0118",
                    "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0131",
                    "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0148",
                    "TIME-DERIVED-TEST-HPACK-METADATA-RETAIN-0165",
                ],
            ),
            _ => return Err(format!("unexpected test-profile carrier row {field_id}")),
        };
        if text(row, "state") != expected_state {
            return Err(format!("test-profile carrier state drifted for {field_id}"));
        }
        require_exact_strings(row, "consumer_ids", expected_consumers)?;
        referenced_consumer_ids.extend(string_set(row, "consumer_ids"));
    }
    let referenced_derived_count = referenced_consumer_ids.intersection(&derived_ids).count();
    let referenced_cross_file_count = referenced_consumer_ids
        .intersection(&cross_file_ids)
        .count();
    if referenced_derived_count != 12
        || referenced_cross_file_count != 2
        || referenced_consumer_ids.len() != 14
        || !referenced_consumer_ids.is_subset(&known_consumer_ids)
    {
        return Err("test-profile carrier aggregate consumer counts drifted".to_owned());
    }
    if text(extension, "test_profile_carrier_lineage_projection_sha256")
        != TEST_PROFILE_CARRIER_LINEAGE_PROJECTION_SHA256
        || sha256_hex(test_profile_carrier_lineage_projection(lineage_rows).as_bytes())
            != TEST_PROFILE_CARRIER_LINEAGE_PROJECTION_SHA256
    {
        return Err("test-profile carrier lineage projection drifted".to_owned());
    }

    let hpack = read_repo_file("tests/conformance/hpack_rfc7541/fixtures.rs");
    if count_matching_lines(&hpack, "metadata: metadata.clone(),") != 5
        || hpack.contains("metadata.generated_at")
        || !hpack
            .contains("#[derive(Debug, Clone)]\n#[allow(dead_code)]\npub struct FixtureMetadata")
    {
        return Err("HPACK private fixture metadata boundary drifted".to_owned());
    }

    let preservation = object(extension, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "time_acceptance_semantics_changed",
        "external_consumer_remainder_closed",
        "second_order_propagation_closed",
        "static_remainder_closed",
        "bead_close_allowed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 test-profile preservation boundary drifted".to_owned());
    }
    let no_claim = text(extension, "no_claim_boundary");
    for required in [
        "all seven test-profile DateTime carriers",
        "does not execute a test or standalone tool",
        "prove serialized or persisted bytes",
        "external consumers",
        "second-order propagation",
        "close A1",
        "authorize dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!(
                "post-A1 test-profile no-claim boundary missing {required}"
            ));
        }
    }
    Ok(())
}

fn validate_post_a1_static_inventory_signoff(inventory: &Value) -> Result<(), String> {
    let signoff = inventory
        .get("post_a1_static_inventory_signoff")
        .ok_or_else(|| "post_a1_static_inventory_signoff is required".to_owned())?;
    for (key, expected) in [
        ("signoff_id", "TIME-A1-STATIC-INVENTORY-SIGNOFF-2026-08-06"),
        ("captured_date_utc", "2026-08-06"),
        (
            "signoff_state",
            "STATIC_INVENTORY_ACCEPTANCE_MET_BEHAVIORAL_EVIDENCE_ROUTED",
        ),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
        (
            "required_disposition",
            "CLOSE_A1_KEEP_DEPENDENCIES_AND_BEHAVIORAL_GAPS",
        ),
    ] {
        if signoff.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "post-A1 static inventory signoff {key} must be {expected}"
            ));
        }
    }

    for (key, expected) in [
        ("source_snapshot_pin_count", 74_u64),
        ("dependency_profile_count", 16),
        ("literal_chrono_line_count", 159),
        ("direct_alias_line_count", 32),
        ("literal_or_alias_unique_line_count", 190),
        ("alias_derived_anchor_count", 8),
        ("additional_derived_anchor_count", 47),
        ("cross_file_consumer_anchor_count", 34),
        ("declared_consumer_unique_direct_source_anchor_count", 76),
        ("classified_anchor_count", 279),
        ("public_carrier_field_count", 30),
        ("test_profile_carrier_field_count", 7),
        ("semantic_contract_count", 15),
        ("persisted_and_output_surface_count", 16),
        ("migration_group_count", 8),
        ("unknown_row_count", 0),
        ("unclassified_chrono_path_count", 0),
        ("unresolved_static_gap_count", 0),
        ("routed_behavioral_gap_count", 7),
    ] {
        if signoff.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("post-A1 static inventory signoff {key} drifted"));
        }
    }

    let per_use = &inventory["per_use_classification"];
    let alias = &inventory["alias_aware_chrono_uses"];
    let public_carrier_count = array(inventory, "public_datetime_fields").len()
        + array(inventory, "public_chrono_generated_string_fields").len();
    if number(signoff, "source_snapshot_pin_count")
        != array(&inventory["source_snapshot"], "files").len() as u64
        || number(signoff, "dependency_profile_count")
            != array(inventory, "dependency_profiles").len() as u64
        || number(signoff, "literal_chrono_line_count")
            != number(&inventory["chrono_census"], "matching_line_count")
        || number(signoff, "direct_alias_line_count")
            != number(alias, "direct_reference_line_count")
        || number(signoff, "literal_or_alias_unique_line_count")
            != number(per_use, "literal_or_alias_unique_line_count")
        || number(signoff, "alias_derived_anchor_count")
            != number(alias, "derived_operation_anchor_line_count")
        || number(signoff, "additional_derived_anchor_count")
            != array(per_use, "additional_derived_operation_rows").len() as u64
        || number(signoff, "cross_file_consumer_anchor_count")
            != array(per_use, "cross_file_consumer_rows").len() as u64
        || number(
            signoff,
            "declared_consumer_unique_direct_source_anchor_count",
        ) != number(
            per_use,
            "declared_consumer_unique_direct_source_anchor_count",
        )
        || number(signoff, "classified_anchor_count") != number(per_use, "classified_anchor_count")
        || number(signoff, "public_carrier_field_count") != public_carrier_count as u64
        || number(signoff, "test_profile_carrier_field_count")
            != array(inventory, "test_profile_datetime_fields").len() as u64
        || number(signoff, "semantic_contract_count")
            != array(inventory, "semantic_contracts").len() as u64
        || number(signoff, "persisted_and_output_surface_count")
            != array(inventory, "persisted_and_output_surfaces").len() as u64
        || number(signoff, "migration_group_count")
            != array(inventory, "migration_groups").len() as u64
        || number(signoff, "unresolved_static_gap_count")
            != array(inventory, "static_inventory_gaps").len() as u64
        || number(signoff, "routed_behavioral_gap_count")
            != array(inventory, "known_gaps").len() as u64
    {
        return Err("post-A1 static inventory signoff aggregate drifted".to_owned());
    }

    require_exact_strings(
        signoff,
        "resolved_static_detail_ids",
        &[
            "TIME-STATIC-RESOLVED-ALIAS-BINDINGS",
            "TIME-STATIC-RESOLVED-DECLARED-DERIVED-CONSUMERS",
            "TIME-STATIC-RESOLVED-DIRECT-PER-USE-CLASSIFICATION",
            "TIME-STATIC-RESOLVED-FIRST-BOUNDARY-CARRIER-LINEAGE",
        ],
    )?;
    require_exact_strings(
        signoff,
        "scope_boundary_ids",
        &[
            "TIME-SCOPE-NONDEPENDENCY-TEMPORAL-SCHEMAS",
            "TIME-SCOPE-POST-FIRST-BOUNDARY-PROPAGATION",
        ],
    )?;
    require_exact_strings(
        signoff,
        "routed_behavioral_gap_ids",
        &[
            "TIME-GAP-A1-BENCHMARK-ARTIFACT",
            "TIME-GAP-A1-CUTOVER",
            "TIME-GAP-A1-DATABASE-MESSAGING",
            "TIME-GAP-A1-DOWNSTREAM",
            "TIME-GAP-A1-PARSE-FORMAT",
            "TIME-GAP-A1-PERSISTED-BYTES",
            "TIME-GAP-A1-RANGE-CORPUS",
        ],
    )?;
    if string_set(signoff, "resolved_static_detail_ids")
        != row_ids(array(inventory, "resolved_static_details"), "detail_id")
        || string_set(signoff, "scope_boundary_ids")
            != row_ids(array(inventory, "scope_boundaries"), "boundary_id")
        || string_set(signoff, "routed_behavioral_gap_ids")
            != row_ids(array(inventory, "known_gaps"), "gap_id")
    {
        return Err("post-A1 static inventory signoff routed ID set drifted".to_owned());
    }

    let expected_gap_owners = [
        ("TIME-GAP-A1-RANGE-CORPUS", "asupersync-5z2scg.6.2"),
        ("TIME-GAP-A1-PARSE-FORMAT", "asupersync-5z2scg.6.3"),
        ("TIME-GAP-A1-PERSISTED-BYTES", "asupersync-5z2scg.6.4"),
        ("TIME-GAP-A1-BENCHMARK-ARTIFACT", "asupersync-5z2scg.6.5"),
        ("TIME-GAP-A1-DATABASE-MESSAGING", "asupersync-5z2scg.6.6"),
        ("TIME-GAP-A1-DOWNSTREAM", "asupersync-5z2scg.6.7"),
        ("TIME-GAP-A1-CUTOVER", "asupersync-5z2scg.6.8"),
    ];
    let known_gap_owners: BTreeMap<_, _> = array(inventory, "known_gaps")
        .iter()
        .map(|row| (text(row, "gap_id"), text(row, "owner_bead")))
        .collect();
    if expected_gap_owners
        .iter()
        .any(|(gap_id, owner)| known_gap_owners.get(gap_id).copied() != Some(*owner))
    {
        return Err("post-A1 behavioral gap ownership drifted".to_owned());
    }

    let scope = object(signoff, "scope_interpretation");
    if scope
        .get("repository_dependency_source_uses_complete")
        .and_then(Value::as_bool)
        != Some(true)
        || scope
            .get("first_semantic_consumer_boundaries_complete")
            .and_then(Value::as_bool)
            != Some(true)
        || scope
            .get("public_and_test_profile_carrier_dispositions_complete")
            .and_then(Value::as_bool)
            != Some(true)
        || scope
            .get("external_consumers_are_repository_source_uses")
            .and_then(Value::as_bool)
            != Some(false)
        || scope
            .get("post_first_boundary_propagation_is_an_unclassified_dependency_use")
            .and_then(Value::as_bool)
            != Some(false)
        || scope
            .get("behavioral_evidence_is_complete")
            .and_then(Value::as_bool)
            != Some(false)
        || scope
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || signoff
            .get("static_acceptance_met")
            .and_then(Value::as_bool)
            != Some(true)
        || signoff.get("bead_close_allowed").and_then(Value::as_bool) != Some(true)
        || signoff
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("post-A1 static inventory signoff scope interpretation drifted".to_owned());
    }

    let preservation = object(signoff, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "production_source_changed",
        "historical_a1_revision_changed",
        "behavioral_gap_count_changed",
        "behavioral_evidence_state_changed",
        "time_acceptance_semantics_changed",
        "dependency_cutover_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if preservation.keys().cloned().collect::<BTreeSet<_>>() != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("post-A1 static inventory signoff preservation drifted".to_owned());
    }

    let propagation_semantic = array(inventory, "semantic_contracts")
        .iter()
        .find(|row| {
            row.get("contract_id").and_then(Value::as_str)
                == Some("TIME-SEM-POST-FIRST-BOUNDARY-PROPAGATION")
        })
        .ok_or_else(|| "post-first-boundary semantic contract is required".to_owned())?;
    if text(propagation_semantic, "scope_policy")
        != "STATIC_SOURCE_ACCEPTANCE_COMPLETE_DOWNSTREAM_BEHAVIOR_ROUTED"
        || text(propagation_semantic, "later_owner") != "asupersync-5z2scg.6.7"
    {
        return Err("post-first-boundary semantic contract drifted".to_owned());
    }

    let semantic_by_id: BTreeMap<_, _> = array(inventory, "semantic_contracts")
        .iter()
        .map(|row| (text(row, "contract_id"), row))
        .collect();
    if semantic_by_id
        .values()
        .any(|row| text(row, "current_semantics").is_empty())
    {
        return Err("semantic contract current-state inventory drifted".to_owned());
    }
    let required_dimension_fields: [(&str, &[&str]); 9] = [
        (
            "TIME-SEM-PUBLIC-TYPE",
            &[
                "range_policy",
                "precision_policy",
                "offset_policy",
                "parse_policy",
                "format_policy",
                "error_policy",
            ],
        ),
        (
            "TIME-SEM-OPTION-ABSENCE",
            &["output_policy", "roundtrip_state", "evidence_state"],
        ),
        ("TIME-SEM-CLI-CLOCK", &["deterministic_clock_policy"]),
        ("TIME-SEM-DURATION-CONVERSION", &["overflow_policy"]),
        (
            "TIME-SEM-STORE-IO",
            &["compatibility_policy", "atomicity_policy"],
        ),
        ("TIME-SEM-POSTGRES-ORACLE", &["oracle_scope"]),
        (
            "TIME-SEM-CONFORMANCE-STRING-TIMESTAMPS",
            &["migration_policy", "evidence_state"],
        ),
        (
            "TIME-SEM-OWNED-RELEASE-PROOF-PARSER",
            &[
                "accepted_syntax",
                "calendar_validation",
                "error_policy",
                "precision_policy",
                "leap_second_policy",
                "evidence_state",
            ],
        ),
        (
            "TIME-SEM-POST-FIRST-BOUNDARY-PROPAGATION",
            &["scope_policy", "later_owner"],
        ),
    ];
    for (contract_id, fields) in required_dimension_fields {
        let Some(row) = semantic_by_id.get(contract_id).copied() else {
            return Err(format!(
                "acceptance dimension contract missing {contract_id}"
            ));
        };
        if fields.iter().any(|field| text(row, field).is_empty()) {
            return Err(format!(
                "acceptance dimension contract fields drifted for {contract_id}"
            ));
        }
    }

    let no_claim = text(signoff, "no_claim_boundary");
    for required in [
        "bounded static source inventory",
        "Closing A1",
        "does not execute or satisfy A2-A8 behavioral work",
        "serialized or persisted bytes",
        "dependency exit",
    ] {
        if !no_claim.contains(required) {
            return Err(format!(
                "post-A1 static signoff no-claim missing {required}"
            ));
        }
    }
    Ok(())
}

fn count_matching_lines(source: &str, token: &str) -> usize {
    source.lines().filter(|line| line.contains(token)).count()
}

// This source-inventory contract intentionally matches a literal Rust format
// string, including its formatting placeholder.
#[allow(clippy::literal_string_with_formatting_args)]
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
        || !jetstream_target.contains(
            "#[path = \"integration/jetstream_real_server.rs\"]\nmod jetstream_real_server;",
        )
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
            return Err(format!(
                "public rendered timestamp surface drifted in {path}"
            ));
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
        || !conformance_rfc.contains(
            ".unwrap_or_default()\n                .as_secs()\n                .to_string()",
        )
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
        || !offline_binary
            .contains("\"generated_at\": format!(\"{:?}\", std::time::SystemTime::now())")
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
            return Err(format!(
                "{path} test module cfg guard moved away from the module"
            ));
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
    if external
        .get("production_source_path_count")
        .and_then(Value::as_u64)
        != Some(0)
        || external
            .get("production_call_count")
            .and_then(Value::as_u64)
            != Some(0)
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
        || foundation.get("evidence_reuse").and_then(Value::as_str) != Some("PRIOR_SCOPED_ONLY")
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
            "No dependency removal, cutover, downstream-bead closure, or permission to delete files follows from this artifact; A1 tracker closure records bounded static-inventory completion only.",
        ],
    )?;
    if array(inventory, "registry_reconciliation")
        .iter()
        .any(|row| {
            row.get("state").and_then(Value::as_str) != Some("ROUTED_NOT_MUTATED_BY_A1")
                || text(row, "finding").is_empty()
                || text(row, "current_fact").is_empty()
        })
    {
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
    validate_per_use_classification(inventory)?;
    validate_alias_inventory(inventory)?;
    validate_foundation_boundary(inventory)?;
    validate_post_a1_provenance_refresh(inventory)?;
    validate_post_a1_cli_output_extension(inventory)?;
    validate_post_a1_benchmark_lineage_extension(inventory)?;
    validate_post_a1_conformance_raptorq_lineage_extension(inventory)?;
    validate_post_a1_public_carrier_lineage_extension(inventory)?;
    validate_post_a1_test_profile_carrier_lineage_extension(inventory)?;
    validate_post_a1_static_inventory_signoff(inventory)?;
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
        "190 unique",
        "Thirteen ordered literal-operation rules",
        "one same-line overlap",
        "47 exact rows",
        "34 exact cross-file consumer rows",
        "279 classified",
        "TIME-A1-ROOT-CLI-JSON-2026-08-06",
        "src/cli/output.rs:156",
        "69th current source pin",
        "TIME-A1-BENCHMARK-LINEAGE-2026-08-06",
        "src/atp/benchmark/suite.rs:99",
        "72 current source pins",
        "all 12 root public DateTime fields",
        "TIME-A1-CONFORMANCE-RAPTORQ-LINEAGE-2026-08-06",
        "74 current source pins",
        "conformance/raptorq_rfc6330/reporting/src/regression_detection.rs:77",
        "conformance/raptorq_rfc6330/reporting/src/compliance_report.rs:298",
        "uniform `+60` lines",
        "TIME-A1-PUBLIC-CARRIER-LINEAGE-2026-08-06",
        "18 public",
        "12 public Chrono-generated string fields",
        "Twenty-eight",
        "32 exact cross-file consumer IDs",
        "no unclassified public carrier",
        "TIME-A1-TEST-PROFILE-CARRIER-LINEAGE-2026-08-06",
        "five HPACK private-fixture",
        "line 605",
        "lines 254 and 464",
        "12 exact derived consumer IDs",
        "seven test-profile",
        "+116/-25",
        "+90/-27",
        "literal-source",
        "bounded lexical scan of production source finds zero external",
        "This is not compiler-resolved name analysis.",
        "17 public Chrono-backed timestamp fields",
        "TIME-A1-STATIC-INVENTORY-SIGNOFF-2026-08-06",
        "zero unresolved static gaps",
        "bead_close_allowed=true",
        "post-first-boundary scope policy",
        "seven remaining behavioral gaps",
        "A1 only",
        "1,853 append-only audit lines",
        "source-pin maintenance only",
        "No compiler, formatter, test, contract, benchmark, service, remote job, or",
    ] {
        assert!(
            docs.contains(marker),
            "documentation marker drifted: {marker}"
        );
    }
}

#[test]
fn time_utc_inventory_rejects_cutover_and_completeness_drift() {
    let inventory = artifact();

    let mut cutover = inventory.clone();
    cutover["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&cutover).is_err());

    let mut maintenance_cutover = inventory.clone();
    maintenance_cutover["post_a1_provenance_refresh"]["dependency_exit_allowed"] =
        Value::Bool(true);
    assert!(validate_inventory(&maintenance_cutover).is_err());

    let mut signoff_cutover = inventory.clone();
    signoff_cutover["post_a1_static_inventory_signoff"]["dependency_exit_allowed"] =
        Value::Bool(true);
    assert!(validate_inventory(&signoff_cutover).is_err());

    let mut signoff_count = inventory.clone();
    signoff_count["post_a1_static_inventory_signoff"]["classified_anchor_count"] =
        Value::from(278_u64);
    assert!(validate_inventory(&signoff_count).is_err());

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

    let mut alias_derived = inventory.clone();
    alias_derived["alias_aware_chrono_uses"]["derived_operation_rows"]
        .as_array_mut()
        .expect("derived alias operations must be an array")
        .pop();
    assert!(validate_inventory(&alias_derived).is_err());

    let mut alias_semantic = inventory.clone();
    alias_semantic["alias_aware_chrono_uses"]["derived_operation_rows"][0]["operation"] =
        Value::String("nonempty alias semantic drift".to_owned());
    assert!(validate_inventory(&alias_semantic).is_err());

    let mut alias_duplicate_symbol = inventory.clone();
    alias_duplicate_symbol["alias_aware_chrono_uses"]["operation_rows"][0]["imported_symbols_used"]
        .as_array_mut()
        .expect("imported symbols must be an array")
        .push(Value::String("Utc".to_owned()));
    assert!(validate_inventory(&alias_duplicate_symbol).is_err());

    let mut literal_override = inventory.clone();
    literal_override["per_use_classification"]["literal_use_overrides"]
        .as_array_mut()
        .expect("literal overrides must be an array")
        .pop();
    literal_override["per_use_classification"]["literal_use_override_count"] = Value::from(35_u64);
    assert!(validate_inventory(&literal_override).is_err());

    let mut rule_definition = inventory.clone();
    rule_definition["per_use_classification"]["literal_operation_rules"][0]["operation"] =
        Value::String("nonempty semantic drift".to_owned());
    assert!(validate_inventory(&rule_definition).is_err());

    let mut path_route = inventory.clone();
    path_route["per_use_classification"]["path_classification_sets"][0]["exposure"] =
        Value::String("NONEMPTY_ROUTE_DRIFT".to_owned());
    assert!(validate_inventory(&path_route).is_err());

    let mut derived_semantic = inventory.clone();
    derived_semantic["per_use_classification"]["additional_derived_operation_rows"][0]["operation"] =
        Value::String("nonempty derived semantic drift".to_owned());
    assert!(validate_inventory(&derived_semantic).is_err());

    let mut duplicate_derivation_source = inventory.clone();
    let duplicate_source =
        duplicate_derivation_source["per_use_classification"]["additional_derived_operation_rows"]
            [0]["derivation_sources"][0]
            .clone();
    duplicate_derivation_source["per_use_classification"]
        ["additional_derived_operation_rows"][0]["derivation_sources"]
        .as_array_mut()
        .expect("derivation sources must be an array")
        .push(duplicate_source);
    assert!(validate_inventory(&duplicate_derivation_source).is_err());

    let mut orphan_derivation_source = inventory.clone();
    orphan_derivation_source["per_use_classification"]["additional_derived_operation_rows"][0]["derivation_sources"]
        [0] = Value::String("src/cli/atp_workflows.rs:1".to_owned());
    assert!(validate_inventory(&orphan_derivation_source).is_err());

    let mut derived_category = inventory.clone();
    derived_category["per_use_classification"]["additional_derived_operation_rows"][0]["consumer_category_id"] =
        Value::String("TIME-CONSUMER-UNDECLARED".to_owned());
    assert!(validate_inventory(&derived_category).is_err());

    let mut cross_file_missing = inventory.clone();
    cross_file_missing["per_use_classification"]["cross_file_consumer_rows"]
        .as_array_mut()
        .expect("cross-file consumers must be an array")
        .pop();
    assert!(validate_inventory(&cross_file_missing).is_err());

    let mut cross_file_semantic = inventory.clone();
    cross_file_semantic["per_use_classification"]["cross_file_consumer_rows"][0]["operation"] =
        Value::String("nonempty cross-file semantic drift".to_owned());
    assert!(validate_inventory(&cross_file_semantic).is_err());

    let mut cross_file_duplicate_source = inventory.clone();
    let cross_file_source = cross_file_duplicate_source["per_use_classification"]
        ["cross_file_consumer_rows"][0]["derivation_sources"][0]
        .clone();
    cross_file_duplicate_source["per_use_classification"]["cross_file_consumer_rows"][0]
        ["derivation_sources"]
        .as_array_mut()
        .expect("cross-file derivation sources must be an array")
        .push(cross_file_source);
    assert!(validate_inventory(&cross_file_duplicate_source).is_err());

    let mut cross_file_orphan_source = inventory.clone();
    cross_file_orphan_source["per_use_classification"]["cross_file_consumer_rows"][0]["derivation_sources"]
        [0] = Value::String("conformance/src/h2_data_end_stream_conformance.rs:1".to_owned());
    assert!(validate_inventory(&cross_file_orphan_source).is_err());

    let mut cross_file_category = inventory.clone();
    cross_file_category["per_use_classification"]["cross_file_consumer_rows"][0]["consumer_category_id"] =
        Value::String("TIME-CROSS-FILE-UNDECLARED".to_owned());
    assert!(validate_inventory(&cross_file_category).is_err());

    let mut cross_file_lineage_total = inventory.clone();
    cross_file_lineage_total["per_use_classification"]["declared_consumer_unique_direct_source_anchor_count"] =
        Value::from(64_u64);
    assert!(validate_inventory(&cross_file_lineage_total).is_err());

    let mut cli_extension_overclaim = inventory.clone();
    cli_extension_overclaim["post_a1_cli_output_extension"]["preservation"]["static_remainder_closed"] =
        Value::Bool(true);
    assert!(validate_inventory(&cli_extension_overclaim).is_err());

    let mut benchmark_extension_overclaim = inventory.clone();
    benchmark_extension_overclaim["post_a1_benchmark_lineage_extension"]["preservation"]["static_remainder_closed"] =
        Value::Bool(true);
    assert!(validate_inventory(&benchmark_extension_overclaim).is_err());

    let mut raptorq_extension_overclaim = inventory.clone();
    raptorq_extension_overclaim["post_a1_conformance_raptorq_lineage_extension"]["preservation"]
        ["static_remainder_closed"] = Value::Bool(true);
    assert!(validate_inventory(&raptorq_extension_overclaim).is_err());

    let mut stale_postgres_lineage = inventory.clone();
    stale_postgres_lineage["post_a1_conformance_raptorq_lineage_extension"]["line_sensitive_pin_reconciliation"]
        ["current_direct_source_id"] = Value::String("src/database/postgres.rs:18086".to_owned());
    assert!(validate_inventory(&stale_postgres_lineage).is_err());

    let mut public_carrier_overclaim = inventory.clone();
    public_carrier_overclaim["post_a1_public_carrier_lineage_extension"]["preservation"]["test_profile_carrier_remainder_closed"] =
        Value::Bool(true);
    assert!(validate_inventory(&public_carrier_overclaim).is_err());

    let mut missing_public_carrier = inventory.clone();
    missing_public_carrier["post_a1_public_carrier_lineage_extension"]["field_lineage_rows"]
        .as_array_mut()
        .expect("public carrier lineage rows must be mutable")
        .pop();
    assert!(validate_inventory(&missing_public_carrier).is_err());

    let mut test_profile_overclaim = inventory.clone();
    test_profile_overclaim["post_a1_test_profile_carrier_lineage_extension"]["preservation"]["static_remainder_closed"] =
        Value::Bool(true);
    assert!(validate_inventory(&test_profile_overclaim).is_err());

    let mut missing_test_profile_carrier = inventory.clone();
    missing_test_profile_carrier["post_a1_test_profile_carrier_lineage_extension"]
        ["field_lineage_rows"]
        .as_array_mut()
        .expect("test-profile carrier lineage rows must be mutable")
        .pop();
    assert!(validate_inventory(&missing_test_profile_carrier).is_err());

    let mut alias_route = inventory.clone();
    for binding in alias_route["alias_aware_chrono_uses"]["bindings"]
        .as_array_mut()
        .expect("alias bindings must be an array")
    {
        if binding["binding_id"] == "TIME-ALIAS-STANDALONE-MAINTENANCE" {
            binding["profile_id"] = Value::String("TIME-PROFILE-ROOT-DEV".to_owned());
            binding["migration_group_id"] = Value::String("TIME-MIG-DOWNSTREAM-CORPUS".to_owned());
            binding["owner_bead"] = Value::String("asupersync-5z2scg.6.6".to_owned());
        }
    }
    for collection in ["operation_rows", "derived_operation_rows"] {
        for row in alias_route["alias_aware_chrono_uses"][collection]
            .as_array_mut()
            .expect("alias operation rows must be an array")
        {
            if row["binding_id"] == "TIME-ALIAS-STANDALONE-MAINTENANCE" {
                row["profile_id"] = Value::String("TIME-PROFILE-ROOT-DEV".to_owned());
                row["migration_group_id"] = Value::String("TIME-MIG-DOWNSTREAM-CORPUS".to_owned());
                row["owner_bead"] = Value::String("asupersync-5z2scg.6.6".to_owned());
            }
        }
    }
    assert!(validate_inventory(&alias_route).is_err());

    let mut static_gap = inventory.clone();
    static_gap["static_inventory_gaps"] =
        Value::Array(vec![Value::String("unexpected static gap".to_owned())]);
    assert!(validate_inventory(&static_gap).is_err());

    let mut alias_total = inventory.clone();
    alias_total["alias_aware_chrono_uses"]["direct_reference_line_count"] = Value::from(31_u64);
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
    assert_eq!(
        inventory["validation"]["contract_execution"],
        "NOT_EXECUTED_THIS_TURN"
    );
}
