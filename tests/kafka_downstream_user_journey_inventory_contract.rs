//! Static contract for the Kafka K0.3 downstream and user-journey inventory.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.1.3
//! Fixture: artifacts/kafka_downstream_user_journey_inventory_v1.json
//!
//! This source performs only repository-file inspection. It does not start
//! processes, access a broker or network, inspect ambient service state, or
//! turn planned, skipped, deterministic, mock, wire-only, or compile-only
//! evidence into real-broker evidence.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_downstream_user_journey_inventory_v1.json";
const DOC_PATH: &str = "docs/kafka_downstream_user_journey_inventory.md";
const K0_1_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const ADR_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const ARTIFACT_SHA256: &str = "dd8277e09864965f74d97d70406d722fd149636a010decb12113f6f7cd67dca3";
const DOC_SHA256: &str = "3c2f0b4fa956bc45fc5b9738f5f2349024dafb577509195e998fa72ec0d9dbb1";
const ARTIFACT_ID: &str = "kafka-downstream-user-journey-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.3";
const REFRESH_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.14.1";
const DOCUMENTATION_OWNER_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.10.5";
const BASELINE_REVISION: &str = "ae22e710d87412b38e546b32e9702106619481d5";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const OCCURRENCE_PATH_COUNT: usize = 245;
const OCCURRENCE_PATH_MAP_SHA256: &str =
    "9c815cfcba11f5345e7abced6b0afa21bfb650f9bb280e71bb3da74ebbb55089";
const K0_1_SYMBOL_COUNT: usize = 30;
const K0_1_SYMBOL_MAP_SHA256: &str =
    "307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28";
const K0_2_SEMANTIC_COUNT: usize = 97;
const K0_2_SEMANTIC_MAP_SHA256: &str =
    "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7";
const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K0.3 DOWNSTREAM INVENTORY -->";
const DOC_END: &str = "<!-- END KAFKA K0.3 DOWNSTREAM INVENTORY -->";
const SOURCE_PIN_COUNT: usize = 225;
const LOCAL_CONSUMER_COUNT: usize = 15;
const LOCAL_ROW_COUNT: usize = 34;
const ATOMIC_CASE_COUNT: usize = 16;
const DOCUMENTATION_CLAIM_COUNT: usize = 31;
const JOURNEY_COUNT: usize = 15;
const EXTERNAL_SEARCH_COUNT: usize = 7;
const OWNED_UNKNOWN_COUNT: usize = 8;
const ROUTED_GAP_COUNT: usize = 23;
const TEST_DECLARATION_GROUP_COUNT: usize = 35;
const TEST_DECLARATION_COUNT: usize = 940;
const EXACT_TEST_DECLARATION_COUNT: usize = 892;
const TOKIO_TEST_DECLARATION_COUNT: usize = 48;
const TOKIO_TEST_DECLARATION_TUPLE_SHA256: &str =
    "c21dd6b0021dc189e82e6a3cf95dd37f1cddb100cf9688595fbe7a969b09b80d";
const TEST_DECLARATION_GROUP_PATH_SHA256: &str =
    "720d9d8fca6a4b23d06d5cfa400eef884c016edb39ac71ce74cde44036b26011";
const TEST_DECLARATION_GROUP_PATH_PIN_SHA256: &str =
    "5eb3a4a99955992f5a8ef5bbd79969dce668e908499872bd9588fa7214b4b2ae";
const COMPILATION_PROFILE_SEMANTIC_TUPLE_SHA256: &str =
    "dd718eca06f6c1309e8e073dc65cc4e0c836e4705747bbaa72d7986dc1d31c61";
const CALL_SITE_GROUP_COUNT: usize = 48;
const CALL_SITE_COUNT: usize = 1_363;
const CALL_SITE_ID_SET_SHA256: &str =
    "8eebdef6b89dab9aa58f7c59299a6431de095a99196825488785b325ed3a51c7";
const CALL_SITE_PATH_SET_SHA256: &str =
    "612152c18e6daff98c7d0c3c7d907df8aa7100a8bab45e88a701d08588718d9c";
const DOWNSTREAM_HELPER_TUPLE_SHA256: &str =
    "a2c49e5cb2519afa11a2d29bee72d97c60532292b2817f725466683b3a93a777";
const PROVIDER_TEST_CANDIDATE_TUPLE_SHA256: &str =
    "1c1f5c263973f83026f7a4235cbe21252de23b4f22ba8833d5fd433659a2e255";
const DOCUMENTATION_ACTUAL_SURFACE_COUNT: usize = 149;
const DOCUMENTATION_SURFACE_COUNT: usize = 150;
const DOCUMENTATION_OCCURRENCE_COUNT: usize = 9_180;
const DOCUMENTATION_MATCHING_LINE_COUNT: usize = 7_778;
const DOCUMENTATION_CANONICAL_OCCURRENCE_COUNT: usize = 37;
const DOCUMENTATION_REMAINDER_OCCURRENCE_COUNT: usize = 9_143;
const DOCUMENTATION_OCCURRENCE_GROUP_COUNT: usize = 173;
const DOCUMENTATION_PATH_SHA256: &str =
    "092daf94a5e428430bc2e6fab7a13a30649aca53e30680c300f9eb76cbbfec67";
const DOCUMENTATION_OCCURRENCE_TUPLE_SHA256: &str =
    "abc0e0d95b9c595e0cbbca6c4ba341b42272b9af1f00ecc18353fd2a14ad5788";
const DOCUMENTATION_LINE_TUPLE_SHA256: &str =
    "1f1f4b72166ed928795d1e7a632777eeec32fc43504c7ec1274c1b3ceab1c31f";
const DOCUMENTATION_OCCURRENCE_ID_SHA256: &str =
    "c76336d845ac06346416ac961d032c99b1df802f60eae8f17385b1153212403e";
const DOCUMENTATION_CANONICAL_ID_SHA256: &str =
    "eb639a6c63291a29da23d7f002dcb0b26a38f34c42ed857f6949db3a92b5328e";
const DOCUMENTATION_REMAINDER_ID_SHA256: &str =
    "eef508dd64ec36e9adc75beaf628b972aaad91602d294ad92d977df74387004e";
const DOCUMENTATION_GROUP_ID_SHA256: &str =
    "5e36b023be812fd3887b84af75d46e7b220c0138317b2a4face21917bdf180dd";
const DOCUMENTATION_SOURCE_PIN_TUPLE_SHA256: &str =
    "24425b9d52e7f82a2f0ae596ba4a17ea55c4fdb565ca8f5b8998f334e6d6fb74";
const DOCUMENTATION_SURFACE_TUPLE_SHA256: &str =
    "71d1cc5d04e71d3005d4449a11758af96d4d787f28bb63ec86102f902ce32970";
const DOCUMENTATION_ACTUAL_SURFACE_TUPLE_SHA256: &str =
    "94ccd2b31c37be2c9a899d9d33cdcabc794f035107f1ca69615dbc0cc633082e";
const DOCUMENTATION_REMAINDER_GROUP_SHA256: &str =
    "a52b98d4cb5460c4731c64e085e4852990fd408196c67b9c67d46cc9c5acb7d1";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_file(path: &str) -> String {
    String::from_utf8(read_repo_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
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

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn count_u64(value: usize, label: &str) -> u64 {
    u64::try_from(value).unwrap_or_else(|error| panic!("{label} count overflow: {error}"))
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

fn optional_string_set(value: &Value, key: &str) -> BTreeSet<String> {
    match value.get(key) {
        Some(Value::Array(_)) => string_set(value, key),
        Some(_) => panic!("{key} must be an array when present"),
        None => BTreeSet::new(),
    }
}

fn require_owner(value: &Value, label: &str) -> Result<(), String> {
    if value
        .get("owner_bead")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(format!("{label} must have a non-empty owner_bead"));
    }
    Ok(())
}

fn pin_paths(inventory: &Value) -> BTreeMap<String, String> {
    array(inventory, "source_pins")
        .iter()
        .map(|pin| (text(pin, "pin_id").to_owned(), text(pin, "path").to_owned()))
        .collect()
}

fn local_row_source_is_accounted(row: &Value, pins: &BTreeMap<String, String>) -> bool {
    match row.get("source_pin_id") {
        Some(Value::String(pin_id)) => pins
            .get(pin_id)
            .is_some_and(|path| row.get("path").and_then(Value::as_str) == Some(path.as_str())),
        Some(Value::Null) => {
            matches!(
                row.get("row_kind").and_then(Value::as_str),
                Some("EXAMPLE" | "FIXTURE_ABSENCE" | "WORKFLOW_ABSENCE")
            ) && row
                .get("source_anchor")
                .and_then(Value::as_str)
                .is_some_and(|anchor| !anchor.is_empty())
                && row
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| !path.is_empty())
        }
        _ => false,
    }
}

fn expected_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|value| (*value).to_owned()).collect()
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn require_exact_ids(
    rows: &[Value],
    key: &str,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let expected = expected_set(expected);
    if rows.len() != expected.len() || row_ids(rows, key) != expected {
        return Err(format!("{label} exact unique {key} set drifted"));
    }
    Ok(())
}

fn require_unique_ids(rows: &[Value], key: &str, label: &str) -> Result<(), String> {
    if rows.len() != row_ids(rows, key).len() {
        return Err(format!("{label} {key} values must be unique"));
    }
    Ok(())
}

fn require_exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let keys = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"))
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if keys != expected_set(expected) {
        return Err(format!("{label} key set drifted"));
    }
    Ok(())
}

fn sorted_newline_sha256(values: &BTreeSet<String>) -> String {
    let mut map = String::new();
    for value in values {
        map.push_str(value);
        map.push('\n');
    }
    sha256_hex(map.as_bytes())
}

fn newline_sha256(values: &[String]) -> String {
    let mut map = values.join("\n");
    if !values.is_empty() {
        map.push('\n');
    }
    sha256_hex(map.as_bytes())
}

fn validate_identity(inventory: &Value) -> Result<(), String> {
    require_exact_keys(
        inventory,
        &[
            "artifact_id",
            "atomic_test_cases",
            "authority",
            "authority_revision",
            "baseline_revision",
            "bead_id",
            "call_site_groups",
            "call_site_scope",
            "capability_id",
            "captured_date_utc",
            "compilation_profiles",
            "coverage_joins",
            "coverage_receipt",
            "documentation_claims",
            "documentation_claim_occurrence_groups",
            "documentation_claim_scope",
            "documentation_claim_surfaces",
            "evidence_claims",
            "external_searches",
            "feature_platform_cells",
            "feature_platform_evidence_state",
            "inventory_state",
            "k0_1_symbol_dispositions",
            "k0_2_semantic_dispositions",
            "k14_1_refresh_handoff",
            "local_consumers",
            "local_inventory_rows",
            "no_claim_boundaries",
            "non_consumer_dispositions",
            "occurrence_disposition_groups",
            "owned_unknowns",
            "policy",
            "program_id",
            "routed_gaps",
            "schema_version",
            "search_queries",
            "search_scope",
            "source_pins",
            "taxonomies",
            "test_declaration_group_classifications",
            "test_declaration_groups",
            "test_declaration_scope",
            "test_declaration_scope_pin_ids",
            "user_journeys",
        ],
        "inventory",
    )?;
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", "CAP-KAFKA"),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", BASELINE_REVISION),
        (
            "inventory_state",
            "K0_3_LOCAL_STATIC_AND_CALL_SITE_CENSUS_FROZEN_EXTERNAL_UNKNOWN",
        ),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }
    Ok(())
}

fn validate_authority_and_policy(inventory: &Value) -> Result<(), String> {
    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        ("k0_3_downstream_inventory_owner", BEAD_ID),
        ("claim_time_refresh_owner", REFRESH_BEAD_ID),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    for key in [
        "dependency_exit_allowed",
        "feature_removal_allowed",
        "api_removal_allowed",
        "capability_removal_allowed",
        "deletion_authority",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("authority.{key} must remain false"));
        }
    }

    let policy = object(inventory, "policy");
    for key in [
        "absence_authorizes_removal",
        "external_search_executed",
        "planned_evidence_counts_as_executed",
        "proof_only_counts_as_real_broker",
        "deterministic_counts_as_real_broker",
        "mock_or_simulated_counts_as_real_broker",
        "stale_counts_as_current",
        "silent_skip_counts_as_pass",
        "compile_only_counts_as_runtime",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("policy.{key} must remain false"));
        }
    }
    for key in [
        "local_static_scope_complete_required",
        "external_unknown_blocks_migration",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("policy.{key} must remain true"));
        }
    }
    let boundaries = string_vec(inventory, "no_claim_boundaries");
    if boundaries.len() != 14
        || boundaries.iter().collect::<BTreeSet<_>>().len() != boundaries.len()
    {
        return Err("no-claim boundaries must remain fourteen unique statements".to_owned());
    }
    let boundary_text = boundaries.join("\n");
    for required in [
        "1,363-node declared candidate grammar",
        "266 are explicit lexical exclusions",
        "892 exact #[test] and 48 exact #[tokio::test]",
        "EXACT_BASELINE_ABSENCE digest token",
        "UNKNOWN usage",
        "no compiler, formatter, test, runtime, broker, external-search, or network execution",
        "not real-broker evidence",
        "No absence",
        "migration eligibility",
    ] {
        if !boundary_text.contains(required) {
            return Err(format!(
                "no-claim boundaries lost required phrase: {required}"
            ));
        }
    }
    Ok(())
}

fn validate_taxonomies(inventory: &Value) -> Result<(), String> {
    let taxonomies = inventory
        .get("taxonomies")
        .unwrap_or_else(|| panic!("taxonomies must exist"));
    for (key, expected) in [
        (
            "execution_state",
            &["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"][..],
        ),
        ("knowledge_state", &["KNOWN", "UNKNOWN"][..]),
        (
            "freshness_state",
            &["CURRENT_SOURCE_PINNED", "STALE", "HISTORICAL", "UNPINNED"][..],
        ),
        (
            "wiring_state",
            &["WIRED", "UNWIRED", "DECLARED_ONLY", "NOT_APPLICABLE"][..],
        ),
        (
            "claim_disposition",
            &[
                "CURRENT",
                "STALE",
                "OVERCLAIM",
                "HISTORICAL",
                "PLANNED",
                "BLOCKED",
            ][..],
        ),
    ] {
        if string_set(taxonomies, key) != expected_set(expected) {
            return Err(format!("taxonomies.{key} drifted"));
        }
    }
    let evidence = string_set(taxonomies, "evidence_class");
    for required in [
        "STATIC_SOURCE",
        "COMPILE_ONLY",
        "DETERMINISTIC_ONLY",
        "MOCK_OR_SIMULATED",
        "PROOF_ONLY",
        "REAL_BROKER_CAPABLE",
        "REAL_BROKER_RECEIPT",
        "WIRE_CODEC_ONLY",
        "HISTORICAL",
        "PLANNED",
    ] {
        if !evidence.contains(required) {
            return Err(format!("evidence taxonomy missing {required}"));
        }
    }
    Ok(())
}

fn validate_state_row(row: &Value, label: &str, taxonomies: &Value) -> Result<(), String> {
    for key in [
        "execution_state",
        "knowledge_state",
        "freshness_state",
        "wiring_state",
        "claim_disposition",
        "evidence_class",
    ] {
        if let Some(value) = row.get(key) {
            let value = value
                .as_str()
                .unwrap_or_else(|| panic!("{label}.{key} must be a string"));
            if !string_set(taxonomies, key).contains(value) {
                return Err(format!("{label}.{key} uses unknown value {value}"));
            }
        }
    }

    let execution = row.get("execution_state").and_then(Value::as_str);
    let evidence = row.get("evidence_class").and_then(Value::as_str);
    let wiring = row.get("wiring_state").and_then(Value::as_str);
    let freshness = row.get("freshness_state").and_then(Value::as_str);
    let disposition = row.get("claim_disposition").and_then(Value::as_str);

    if matches!(execution, Some("PASS" | "FAIL"))
        && !matches!(evidence, Some("STATIC_SOURCE" | "REAL_BROKER_RECEIPT"))
    {
        return Err(format!(
            "{label} cannot promote non-static evidence without a receipt"
        ));
    }
    if evidence == Some("REAL_BROKER_CAPABLE") && !matches!(execution, Some("NOT_RUN" | "BLOCKED"))
    {
        return Err(format!(
            "{label} capability cannot masquerade as broker proof"
        ));
    }
    if wiring == Some("UNWIRED") && execution != Some("NOT_RUN") {
        return Err(format!("{label} unwired source must remain NOT_RUN"));
    }
    if execution == Some("BLOCKED")
        && [
            "blocker",
            "skip_or_blocker",
            "limitation",
            "proof_scope_note",
        ]
        .iter()
        .all(|key| {
            row.get(*key)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(format!("{label} BLOCKED state requires a stated blocker"));
    }
    if disposition == Some("CURRENT")
        && freshness.is_some_and(|state| state != "CURRENT_SOURCE_PINNED")
    {
        return Err(format!("{label} CURRENT claim is not source-current"));
    }
    if disposition == Some("STALE") && freshness.is_some_and(|state| state != "STALE") {
        return Err(format!("{label} STALE claim has incompatible freshness"));
    }
    if disposition == Some("HISTORICAL") && freshness.is_some_and(|state| state != "HISTORICAL") {
        return Err(format!(
            "{label} HISTORICAL claim has incompatible freshness"
        ));
    }
    Ok(())
}

fn validate_state_compatibility(inventory: &Value) -> Result<(), String> {
    let taxonomies = inventory
        .get("taxonomies")
        .unwrap_or_else(|| panic!("taxonomies must exist"));
    for (array_key, id_key) in [
        ("local_consumers", "consumer_id"),
        ("local_inventory_rows", "row_id"),
        ("atomic_test_cases", "case_id"),
        ("call_site_groups", "group_id"),
        ("documentation_claims", "claim_id"),
        ("compilation_profiles", "profile_id"),
        ("feature_platform_cells", "cell_id"),
        ("user_journeys", "journey_id"),
        ("evidence_claims", "evidence_id"),
    ] {
        for row in array(inventory, array_key) {
            validate_state_row(row, text(row, id_key), taxonomies)?;
        }
    }
    Ok(())
}

fn validate_counts_and_ids(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins");
    let local_consumers = array(inventory, "local_consumers");
    let local_rows = array(inventory, "local_inventory_rows");
    let atomic_cases = array(inventory, "atomic_test_cases");
    let call_site_groups = array(inventory, "call_site_groups");
    let doc_claims = array(inventory, "documentation_claims");
    let profiles = array(inventory, "compilation_profiles");
    let cells = array(inventory, "feature_platform_cells");
    let journeys = array(inventory, "user_journeys");
    let evidence = array(inventory, "evidence_claims");
    let external = array(inventory, "external_searches");
    let unknowns = array(inventory, "owned_unknowns");
    let gaps = array(inventory, "routed_gaps");

    for (rows, key, label) in [
        (pins, "pin_id", "source pins"),
        (local_consumers, "consumer_id", "local consumers"),
        (local_rows, "row_id", "local rows"),
        (atomic_cases, "case_id", "atomic test cases"),
        (call_site_groups, "group_id", "call-site groups"),
        (doc_claims, "claim_id", "documentation claims"),
        (profiles, "profile_id", "compilation profiles"),
        (cells, "cell_id", "feature-platform cells"),
        (journeys, "journey_id", "journeys"),
        (evidence, "evidence_id", "evidence claims"),
        (external, "external_id", "external searches"),
        (unknowns, "unknown_id", "owned unknowns"),
        (gaps, "gap_id", "routed gaps"),
    ] {
        require_unique_ids(rows, key, label)?;
    }
    for (actual, expected, label) in [
        (pins.len(), SOURCE_PIN_COUNT, "source pins"),
        (
            local_consumers.len(),
            LOCAL_CONSUMER_COUNT,
            "local consumers",
        ),
        (local_rows.len(), LOCAL_ROW_COUNT, "local rows"),
        (atomic_cases.len(), ATOMIC_CASE_COUNT, "atomic test cases"),
        (
            call_site_groups.len(),
            CALL_SITE_GROUP_COUNT,
            "call-site groups",
        ),
        (
            doc_claims.len(),
            DOCUMENTATION_CLAIM_COUNT,
            "documentation claims",
        ),
        (profiles.len(), 17, "compilation profiles"),
        (cells.len(), 8, "feature-platform cells"),
        (journeys.len(), JOURNEY_COUNT, "journeys"),
        (evidence.len(), 6, "evidence claims"),
        (external.len(), EXTERNAL_SEARCH_COUNT, "external searches"),
        (unknowns.len(), OWNED_UNKNOWN_COUNT, "owned unknowns"),
        (gaps.len(), ROUTED_GAP_COUNT, "routed gaps"),
    ] {
        if actual != expected {
            return Err(format!("{label} count drifted: {actual} != {expected}"));
        }
    }
    require_exact_ids(
        journeys,
        "journey_id",
        &[
            "kfk-journey-feature-disabled",
            "kfk-journey-produce",
            "kfk-journey-transaction",
            "kfk-journey-consume-group",
            "kfk-journey-secure-connect",
            "kfk-journey-real-broker-proof",
            "kfk-journey-compression-config",
            "kfk-journey-rebalance",
            "kfk-journey-error-taxonomy",
            "kfk-journey-migration",
            "kfk-journey-http-publish",
            "kfk-journey-observability",
            "kfk-journey-broker-recovery",
            "kfk-journey-payment-delivery",
            "kfk-journey-replay-without-commit",
        ],
        "journeys",
    )?;
    require_exact_ids(
        atomic_cases,
        "case_id",
        &[
            "KAFKA-K0-3-CASE-001",
            "KAFKA-K0-3-CASE-002",
            "KAFKA-K0-3-CASE-003",
            "KAFKA-K0-3-CASE-004",
            "KAFKA-K0-3-CASE-005",
            "KAFKA-K0-3-CASE-006",
            "KAFKA-K0-3-CASE-007",
            "KAFKA-K0-3-CASE-008",
            "KAFKA-K0-3-CASE-009",
            "KAFKA-K0-3-CASE-010",
            "KAFKA-K0-3-CASE-011",
            "KAFKA-K0-3-CASE-012",
            "KAFKA-K0-3-CASE-013",
            "KAFKA-K0-3-CASE-014",
            "KAFKA-K0-3-CASE-015",
            "KAFKA-K0-3-CASE-016",
        ],
        "atomic test cases",
    )?;
    Ok(())
}

fn validate_local_joins(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins");
    let pin_ids = row_ids(pins, "pin_id");
    let pin_paths = pin_paths(inventory);
    if pin_paths.len() != pins.len()
        || pin_paths.values().collect::<BTreeSet<_>>().len() != pins.len()
    {
        return Err("source pin paths must be unique".to_owned());
    }
    let pinned_paths = pin_paths.values().cloned().collect::<BTreeSet<_>>();

    let consumer_rows = array(inventory, "local_consumers");
    let consumers = row_ids(consumer_rows, "consumer_id");
    for consumer in consumer_rows {
        let consumer_id = text(consumer, "consumer_id");
        require_owner(consumer, consumer_id)?;
        let consumer_paths = string_set(consumer, "paths");
        if consumer_paths.is_empty()
            || consumer_paths.len() != array(consumer, "paths").len()
            || !consumer_paths.is_subset(&pinned_paths)
        {
            return Err(format!(
                "{consumer_id} must retain nonempty unique source-pinned paths"
            ));
        }
    }
    let journeys = row_ids(array(inventory, "user_journeys"), "journey_id");
    let local_rows = array(inventory, "local_inventory_rows");
    let local_row_ids = row_ids(local_rows, "row_id");
    let mut local_rows_by_journey = BTreeMap::<String, BTreeSet<String>>::new();
    for row in local_rows {
        let row_id = text(row, "row_id");
        require_exact_keys(
            row,
            &[
                "atomic_case_ids",
                "claim_disposition",
                "consumer_id",
                "evidence_class",
                "execution_state",
                "journey_ids",
                "k0_1_symbol_ids",
                "k0_2_semantic_ids",
                "owner_bead",
                "path",
                "public_entry_points",
                "refresh_owner_bead",
                "row_id",
                "row_kind",
                "skip_or_blocker",
                "source_anchor",
                "source_pin_id",
                "wiring_state",
            ],
            row_id,
        )?;
        if !local_row_source_is_accounted(row, &pin_paths) {
            return Err(format!(
                "{row_id} must reference a matching source pin or an explicit absence row"
            ));
        }
        require_owner(row, row_id)?;
        if text(row, "refresh_owner_bead") != REFRESH_BEAD_ID {
            return Err(format!("{row_id} must retain the K14.1 refresh owner"));
        }
        if let Some(consumer_id) = row.get("consumer_id").and_then(Value::as_str)
            && !consumers.contains(consumer_id)
        {
            return Err(format!(
                "{row_id} references unknown consumer {consumer_id}"
            ));
        }
        let row_journeys = string_set(row, "journey_ids");
        if row_journeys.len() != array(row, "journey_ids").len() {
            return Err(format!("{row_id} journey references must be unique"));
        }
        for journey in row_journeys {
            if !journeys.contains(&journey) {
                return Err(format!("{row_id} references unknown journey {journey}"));
            }
            local_rows_by_journey
                .entry(journey)
                .or_default()
                .insert(row_id.to_owned());
        }
    }

    let atomic_cases = array(inventory, "atomic_test_cases");
    let atomic_case_ids = row_ids(atomic_cases, "case_id");
    let mut cases_by_local_row = BTreeMap::<String, BTreeSet<String>>::new();
    let mut cases_by_journey = BTreeMap::<String, BTreeSet<String>>::new();
    for case in atomic_cases {
        let case_id = text(case, "case_id");
        require_exact_keys(
            case,
            &[
                "blocker",
                "case_id",
                "claim_disposition",
                "evidence_class",
                "execution_state",
                "journey_ids",
                "k0_1_symbol_ids",
                "k0_2_semantic_ids",
                "local_row_id",
                "owner_bead",
                "path",
                "source_anchor",
                "source_pin_id",
                "test_name",
            ],
            case_id,
        )?;
        let local_row_id = text(case, "local_row_id");
        if !local_row_ids.contains(local_row_id) {
            return Err(format!(
                "{case_id} references unknown local row {local_row_id}"
            ));
        }
        let pin_id = text(case, "source_pin_id");
        let expected_path = pin_paths
            .get(pin_id)
            .ok_or_else(|| format!("{case_id} references unknown source pin {pin_id}"))?;
        if text(case, "path") != expected_path.as_str() {
            return Err(format!("{case_id} path does not match {pin_id}"));
        }
        let local_row = local_rows
            .iter()
            .find(|row| text(row, "row_id") == local_row_id)
            .unwrap_or_else(|| panic!("known local row {local_row_id} must exist"));
        if text(local_row, "path") != text(case, "path")
            || local_row.get("source_pin_id").and_then(Value::as_str) != Some(pin_id)
        {
            return Err(format!("{case_id} does not refine its declared local row"));
        }
        require_owner(case, case_id)?;
        if text(case, "test_name").is_empty() || text(case, "blocker").is_empty() {
            return Err(format!("{case_id} must name its test and blocker"));
        }
        let expected_evidence = if case_id == "KAFKA-K0-3-CASE-010" {
            "DETERMINISTIC_ONLY"
        } else {
            "REAL_BROKER_CAPABLE"
        };
        if text(case, "evidence_class") != expected_evidence
            || text(case, "execution_state") != "NOT_RUN"
        {
            return Err(format!(
                "{case_id} atomic evidence class or execution boundary drifted"
            ));
        }
        let case_journeys = string_set(case, "journey_ids");
        if case_journeys.is_empty() || case_journeys.len() != array(case, "journey_ids").len() {
            return Err(format!(
                "{case_id} journey references must be nonempty and unique"
            ));
        }
        for journey in case_journeys {
            if !journeys.contains(&journey) {
                return Err(format!("{case_id} references unknown journey {journey}"));
            }
            cases_by_journey
                .entry(journey)
                .or_default()
                .insert(case_id.to_owned());
        }
        cases_by_local_row
            .entry(local_row_id.to_owned())
            .or_default()
            .insert(case_id.to_owned());
    }

    for row in local_rows {
        let row_id = text(row, "row_id");
        let expected_cases = cases_by_local_row.remove(row_id).unwrap_or_default();
        let declared_cases = optional_string_set(row, "atomic_case_ids");
        let declared_case_count = row
            .get("atomic_case_ids")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if declared_cases.len() != declared_case_count || declared_cases != expected_cases {
            return Err(format!("{row_id} atomic case backreferences drifted"));
        }
    }
    if !cases_by_local_row.is_empty() {
        return Err("atomic cases reference local rows absent from the local table".to_owned());
    }

    for journey in array(inventory, "user_journeys") {
        let journey_id = text(journey, "journey_id");
        require_owner(journey, journey_id)?;
        let journey_local_rows = string_set(journey, "local_row_ids");
        if journey_local_rows.is_empty()
            || journey_local_rows.len() != array(journey, "local_row_ids").len()
        {
            return Err(format!(
                "{journey_id} local row references must be nonempty and unique"
            ));
        }
        for row_id in journey_local_rows {
            if !local_row_ids.contains(&row_id) {
                return Err(format!("journey references unknown local row {row_id}"));
            }
        }
        let expected_local_rows = local_rows_by_journey.remove(journey_id).unwrap_or_default();
        if string_set(journey, "local_row_ids") != expected_local_rows {
            return Err(format!(
                "{journey_id} local-row references are not the exact inverse join"
            ));
        }
        let expected_cases = cases_by_journey.remove(journey_id).unwrap_or_default();
        let declared_cases = optional_string_set(journey, "atomic_case_ids");
        let declared_case_count = journey
            .get("atomic_case_ids")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if declared_cases.len() != declared_case_count || declared_cases != expected_cases {
            return Err(format!("{journey_id} atomic case backreferences drifted"));
        }
        for case_id in declared_cases {
            if !atomic_case_ids.contains(&case_id) {
                return Err(format!(
                    "{journey_id} references unknown atomic case {case_id}"
                ));
            }
        }
    }
    if !cases_by_journey.is_empty() {
        return Err("atomic cases reference journeys absent from the journey table".to_owned());
    }
    if !local_rows_by_journey.is_empty() {
        return Err("local rows reference journeys absent from the journey table".to_owned());
    }

    for claim in array(inventory, "documentation_claims") {
        let claim_id = text(claim, "claim_id");
        require_owner(claim, claim_id)?;
        let claim_paths = string_set(claim, "paths");
        if claim_paths.is_empty() {
            return Err(format!("{claim_id} must retain at least one claim path"));
        }
        let claim_pin_ids = string_set(claim, "source_pin_ids");
        if claim_pin_ids.is_empty() || claim_pin_ids.len() != array(claim, "source_pin_ids").len() {
            return Err(format!(
                "{claim_id} source pins must be nonempty and unique"
            ));
        }
        for pin_id in claim_pin_ids {
            if !pin_ids.contains(&pin_id) {
                return Err(format!(
                    "documentation claim references unknown pin {pin_id}"
                ));
            }
            let path = pin_paths
                .get(&pin_id)
                .unwrap_or_else(|| panic!("known pin {pin_id} must have a path"));
            if !claim_paths.contains(path) {
                return Err(format!("{claim_id} omits pinned claim path {path}"));
            }
        }
    }
    Ok(())
}

fn validate_profiles_and_cells(inventory: &Value) -> Result<(), String> {
    let profiles = array(inventory, "compilation_profiles");
    let pin_ids = row_ids(array(inventory, "source_pins"), "pin_id");
    let profile_ids = row_ids(profiles, "profile_id");
    require_exact_ids(
        profiles,
        "profile_id",
        &[
            "KAFKA-K0-3-COMPILE-001",
            "KAFKA-K0-3-COMPILE-002",
            "KAFKA-K0-3-COMPILE-003",
            "KAFKA-K0-3-COMPILE-004",
            "KAFKA-K0-3-COMPILE-005",
            "KAFKA-K0-3-COMPILE-006",
            "KAFKA-K0-3-COMPILE-007",
            "KAFKA-K0-3-COMPILE-008",
            "KAFKA-K0-3-COMPILE-009",
            "KAFKA-K0-3-COMPILE-010",
            "KAFKA-K0-3-COMPILE-011",
            "KAFKA-K0-3-COMPILE-012",
            "KAFKA-K0-3-COMPILE-013",
            "KAFKA-K0-3-COMPILE-014",
            "KAFKA-K0-3-COMPILE-015",
            "KAFKA-K0-3-COMPILE-016",
            "KAFKA-K0-3-COMPILE-017",
        ],
        "compilation profiles",
    )?;
    let expected_k0_1 = expected_set(&[
        "KAFKA-PROFILE-NATIVE-DEFAULT-RELEASE",
        "KAFKA-PROFILE-NATIVE-DEFAULT-DEBUG",
        "KAFKA-PROFILE-NATIVE-KAFKA-RELEASE",
        "KAFKA-PROFILE-NATIVE-KAFKA-DEBUG",
        "KAFKA-PROFILE-UNIT-NO-KAFKA",
        "KAFKA-PROFILE-UNIT-WITH-KAFKA",
        "KAFKA-PROFILE-DOWNSTREAM-NO-KAFKA",
        "KAFKA-PROFILE-TEST-INTERNALS-NO-KAFKA",
        "KAFKA-PROFILE-FUZZ-WORKSPACE",
        "KAFKA-PROFILE-CI-CROSS-PLATFORM",
        "KAFKA-PROFILE-NATIVE-ALL-FEATURES",
        "KAFKA-PROFILE-WASM-NO-KAFKA",
        "KAFKA-PROFILE-WASM-WITH-KAFKA",
    ]);
    let mut canonical_k0_1 = BTreeSet::new();
    let mut profile_semantic_tuples = BTreeSet::new();
    for profile in profiles {
        let profile_id = text(profile, "profile_id");
        require_exact_keys(
            profile,
            &[
                "cfg",
                "derived_from_profile_ids",
                "evidence_class",
                "execution_state",
                "k0_1_profile_id",
                "owner_bead",
                "profile_id",
                "profile_kind",
                "refresh_owner_bead",
                "source_pin_ids",
                "surface_state",
                "target",
            ],
            profile_id,
        )?;
        require_owner(profile, profile_id)?;
        if text(profile, "refresh_owner_bead") != REFRESH_BEAD_ID {
            return Err(format!("{profile_id} must retain the K14.1 refresh owner"));
        }
        let source_pin_ids = string_set(profile, "source_pin_ids");
        if source_pin_ids.is_empty()
            || source_pin_ids.len() != array(profile, "source_pin_ids").len()
            || !source_pin_ids.is_subset(&pin_ids)
        {
            return Err(format!("{profile_id} must reference known source pins"));
        }
        if text(profile, "execution_state") != "NOT_RUN" {
            return Err(format!(
                "{profile_id} has no creation-session compile receipt"
            ));
        }
        let derived_vec = string_vec(profile, "derived_from_profile_ids");
        let derived = derived_vec.iter().cloned().collect::<BTreeSet<_>>();
        if text(profile, "target").is_empty()
            || text(profile, "cfg").is_empty()
            || text(profile, "surface_state").is_empty()
            || text(profile, "evidence_class").is_empty()
        {
            return Err(format!(
                "{profile_id} semantic profile fields must be explicit"
            ));
        }
        profile_semantic_tuples.insert(format!(
            "{profile_id}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            text(profile, "k0_1_profile_id"),
            text(profile, "profile_kind"),
            derived_vec.join(","),
            text(profile, "target"),
            text(profile, "cfg"),
            text(profile, "surface_state"),
            text(profile, "evidence_class"),
        ));
        match text(profile, "profile_kind") {
            "K0_1_CANONICAL" => {
                if !derived.is_empty() {
                    return Err(format!("{profile_id} canonical profile cannot be derived"));
                }
                canonical_k0_1.insert(text(profile, "k0_1_profile_id").to_owned());
            }
            kind if kind.starts_with("LOCAL_DERIVED_") => {
                if derived.len() != 1
                    || derived.len() != array(profile, "derived_from_profile_ids").len()
                    || !derived.is_subset(&profile_ids)
                {
                    return Err(format!("{profile_id} must derive from one known profile"));
                }
                let parent_id = derived
                    .iter()
                    .next()
                    .unwrap_or_else(|| panic!("one derived profile ID must exist"));
                let parent = profiles
                    .iter()
                    .find(|candidate| text(candidate, "profile_id") == parent_id.as_str())
                    .unwrap_or_else(|| panic!("known parent profile {parent_id} must exist"));
                if text(parent, "profile_kind") != "K0_1_CANONICAL"
                    || text(parent, "k0_1_profile_id") != text(profile, "k0_1_profile_id")
                {
                    return Err(format!(
                        "{profile_id} must derive from its matching canonical K0.1 profile"
                    ));
                }
            }
            kind => return Err(format!("{profile_id} has unknown profile_kind {kind}")),
        }
    }
    if canonical_k0_1 != expected_k0_1 {
        return Err("canonical K0.1 profile coverage drifted".to_owned());
    }
    if sorted_newline_sha256(&profile_semantic_tuples) != COMPILATION_PROFILE_SEMANTIC_TUPLE_SHA256
    {
        return Err("compilation profile target/cfg/surface/evidence joins drifted".to_owned());
    }

    let cells = array(inventory, "feature_platform_cells");
    require_exact_ids(
        cells,
        "cell_id",
        &[
            "KAFKA-K0-3-CELL-001",
            "KAFKA-K0-3-CELL-002",
            "KAFKA-K0-3-CELL-003",
            "KAFKA-K0-3-CELL-004",
            "KAFKA-K0-3-CELL-005",
            "KAFKA-K0-3-CELL-006",
            "KAFKA-K0-3-CELL-007",
            "KAFKA-K0-3-CELL-008",
        ],
        "feature-platform cells",
    )?;
    let expected_cells: [(&str, &str, &str, &[&str], &str); 8] = [
        (
            "KAFKA-K0-3-CELL-001",
            "linux",
            "DISABLED",
            &["linux-x86_64-gnu", "linux-aarch64-gnu"],
            "FACADE_PRESENT_FAIL_CLOSED",
        ),
        (
            "KAFKA-K0-3-CELL-002",
            "linux",
            "ENABLED",
            &["linux-x86_64-gnu", "linux-aarch64-gnu"],
            "RDKAFKA_REAL_BACKEND_EXPECTED",
        ),
        (
            "KAFKA-K0-3-CELL-003",
            "macos",
            "DISABLED",
            &["macos-aarch64", "macos-x86_64"],
            "FACADE_PRESENT_FAIL_CLOSED",
        ),
        (
            "KAFKA-K0-3-CELL-004",
            "macos",
            "ENABLED",
            &["macos-aarch64", "macos-x86_64"],
            "RDKAFKA_REAL_BACKEND_EXPECTED",
        ),
        (
            "KAFKA-K0-3-CELL-005",
            "windows",
            "DISABLED",
            &["windows-x86_64-msvc"],
            "FACADE_PRESENT_FAIL_CLOSED",
        ),
        (
            "KAFKA-K0-3-CELL-006",
            "windows",
            "ENABLED",
            &["windows-x86_64-msvc"],
            "RDKAFKA_REAL_BACKEND_EXPECTED",
        ),
        (
            "KAFKA-K0-3-CELL-007",
            "wasm32-browser",
            "DISABLED",
            &["wasm32-browser"],
            "MESSAGING_MODULE_ABSENT",
        ),
        (
            "KAFKA-K0-3-CELL-008",
            "wasm32-browser",
            "ENABLED",
            &["wasm32-browser"],
            "HARD_COMPILE_ERROR_EXPECTED",
        ),
    ];
    for cell in cells {
        let cell_id = text(cell, "cell_id");
        require_exact_keys(
            cell,
            &[
                "blocker",
                "cell_id",
                "evidence_class",
                "execution_state",
                "feature_state",
                "owner_bead",
                "platform",
                "refresh_owner_bead",
                "source_pin_ids",
                "surface_state",
                "target_ids",
            ],
            cell_id,
        )?;
        require_owner(cell, cell_id)?;
        if text(cell, "refresh_owner_bead") != REFRESH_BEAD_ID {
            return Err(format!("{cell_id} must retain the K14.1 refresh owner"));
        }
        let source_pin_ids = string_set(cell, "source_pin_ids");
        if source_pin_ids.is_empty()
            || source_pin_ids.len() != array(cell, "source_pin_ids").len()
            || !source_pin_ids.is_subset(&pin_ids)
        {
            return Err(format!("{cell_id} must reference known source pins"));
        }
        if text(cell, "execution_state") != "NOT_RUN" || text(cell, "blocker").is_empty() {
            return Err(format!(
                "{cell_id} must remain blocked on fresh target evidence"
            ));
        }
        let (_, platform, feature_state, target_ids, surface_state) = expected_cells
            .iter()
            .find(|(expected_id, _, _, _, _)| *expected_id == cell_id)
            .ok_or_else(|| format!("{cell_id} lacks an exact cell mapping"))?;
        let expected_target_ids = target_ids
            .iter()
            .map(|target| (*target).to_owned())
            .collect::<Vec<_>>();
        if text(cell, "platform") != *platform
            || text(cell, "feature_state") != *feature_state
            || string_vec(cell, "target_ids") != expected_target_ids
            || text(cell, "surface_state") != *surface_state
            || text(cell, "evidence_class") != "COMPILE_ONLY"
        {
            return Err(format!(
                "{cell_id} platform/feature/target/surface mapping drifted"
            ));
        }
    }
    let state = object(inventory, "feature_platform_evidence_state");
    if state.get("knowledge_state").and_then(Value::as_str) != Some("UNKNOWN")
        || state
            .get("linux_real_service_runtime")
            .and_then(Value::as_str)
            != Some("BLOCKED_EXTERNAL")
        || state.get("no_cross_compile_claim").and_then(Value::as_bool) != Some(true)
        || state.get("no_runtime_claim").and_then(Value::as_bool) != Some(true)
    {
        return Err("feature-platform evidence state drifted".to_owned());
    }
    Ok(())
}

fn validate_canonical_journeys(inventory: &Value) -> Result<(), String> {
    let journeys = array(inventory, "user_journeys");
    if pin_paths(inventory)
        .get("KAFKA-K0-3-PIN-API-ADR-REGISTRY")
        .map(String::as_str)
        != Some(ADR_REGISTRY_PATH)
    {
        return Err("canonical journey source pin must resolve to the ADR registry".to_owned());
    }
    let registry = parse_repo_json(ADR_REGISTRY_PATH);
    let kafka_adr = array(&registry, "adrs")
        .iter()
        .find(|adr| optional_string_set(adr, "capability_ids").contains("CAP-KAFKA"))
        .ok_or_else(|| "dependency ADR registry lost CAP-KAFKA".to_owned())?;
    let canonical_registry_journeys = array(kafka_adr, "user_journeys");
    let canonical_inventory_journeys = journeys
        .iter()
        .filter(|journey| {
            journey
                .get("canonical_source_pin_id")
                .and_then(Value::as_str)
                == Some("KAFKA-K0-3-PIN-API-ADR-REGISTRY")
        })
        .collect::<Vec<_>>();
    if canonical_registry_journeys.len() != 6 || canonical_inventory_journeys.len() != 6 {
        return Err("canonical Kafka ADR journey count drifted".to_owned());
    }
    let canonical_registry_rows = canonical_registry_journeys
        .iter()
        .map(|journey| (text(journey, "id"), text(journey, "description")))
        .collect::<BTreeSet<_>>();
    let canonical_inventory_rows = canonical_inventory_journeys
        .iter()
        .map(|journey| (text(journey, "journey_id"), text(journey, "description")))
        .collect::<BTreeSet<_>>();
    if canonical_inventory_rows != canonical_registry_rows {
        return Err("canonical Kafka ADR journey IDs or descriptions drifted".to_owned());
    }
    for (journey_id, expected_entries) in [
        (
            "kfk-journey-feature-disabled",
            &[
                "ProducerConfig::new",
                "KafkaProducer::new",
                "KafkaProducer::send",
                "KafkaConsumerConfig::new",
                "KafkaConsumer::new",
                "KafkaConsumer::subscribe",
                "KafkaConsumer::poll",
                "KafkaConsumer::commit_offsets",
            ][..],
        ),
        (
            "kfk-journey-produce",
            &[
                "ProducerConfig::new",
                "ProducerConfig::enable_idempotence",
                "KafkaProducer::new",
                "KafkaProducer::send_with_headers",
                "KafkaProducer::flush",
                "KafkaProducer::close",
            ][..],
        ),
        (
            "kfk-journey-transaction",
            &[
                "TransactionalConfig::new",
                "TransactionalProducer::new",
                "TransactionalProducer::begin_transaction",
                "Transaction::send",
                "Transaction::commit",
                "Transaction::abort",
            ][..],
        ),
        (
            "kfk-journey-consume-group",
            &[
                "KafkaConsumerConfig::new",
                "KafkaConsumer::new",
                "KafkaConsumer::subscribe",
                "KafkaConsumer::poll",
                "KafkaConsumer::commit_offsets",
                "KafkaConsumer::seek",
                "KafkaConsumer::rebalance",
                "KafkaConsumer::assigned_partitions",
                "KafkaConsumer::rebalance_generation",
                "KafkaConsumer::last_revoked",
                "KafkaConsumer::close",
            ][..],
        ),
        (
            "kfk-journey-secure-connect",
            &[
                "KafkaTlsConfig",
                "KafkaSaslConfig",
                "KafkaSecurityConfig",
                "ProducerConfig::security",
            ][..],
        ),
        (
            "kfk-journey-real-broker-proof",
            &[
                "KafkaProducer::send",
                "KafkaConsumer::poll",
                "KafkaConsumer::commit_offsets",
                "KafkaProducer::close",
                "KafkaConsumer::close",
            ][..],
        ),
    ] {
        let journey = journeys
            .iter()
            .find(|row| row.get("journey_id").and_then(Value::as_str) == Some(journey_id))
            .ok_or_else(|| format!("missing canonical journey {journey_id}"))?;
        if journey
            .get("canonical_source_pin_id")
            .and_then(Value::as_str)
            != Some("KAFKA-K0-3-PIN-API-ADR-REGISTRY")
            || string_vec(journey, "ordered_public_entry_points")
                != expected_entries
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect::<Vec<_>>()
        {
            return Err(format!("{journey_id} canonical ADR semantics drifted"));
        }
    }

    let transaction = journeys
        .iter()
        .find(|row| text(row, "journey_id") == "kfk-journey-transaction")
        .unwrap_or_else(|| panic!("canonical transaction journey must exist"));
    if transaction
        .get("drop_guard_required")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("transaction journey must preserve its dangling-transaction guard".to_owned());
    }
    let proof = journeys
        .iter()
        .find(|row| text(row, "journey_id") == "kfk-journey-real-broker-proof")
        .unwrap_or_else(|| panic!("canonical real-broker journey must exist"));
    if proof
        .get("proof_scope_note")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("real-broker journey must retain its proof-scope boundary".to_owned());
    }
    for journey_id in [
        "kfk-journey-broker-recovery",
        "kfk-journey-payment-delivery",
        "kfk-journey-replay-without-commit",
    ] {
        let journey = journeys
            .iter()
            .find(|row| text(row, "journey_id") == journey_id)
            .unwrap_or_else(|| panic!("extended journey {journey_id} must exist"));
        if !matches!(text(journey, "claim_disposition"), "BLOCKED" | "OVERCLAIM")
            || text(journey, "limitation").is_empty()
            || matches!(text(journey, "execution_state"), "PASS" | "FAIL")
        {
            return Err(format!("{journey_id} must remain bounded and unexecuted"));
        }
    }
    Ok(())
}

fn validate_evidence_and_external(inventory: &Value) -> Result<(), String> {
    if text(inventory, "captured_date_utc") != CAPTURED_DATE_UTC {
        return Err("captured_date_utc drifted".to_owned());
    }
    let queries = array(inventory, "search_queries");
    require_exact_ids(
        queries,
        "query_id",
        &[
            "KAFKA-K0-3-QUERY-001",
            "KAFKA-K0-3-QUERY-002",
            "KAFKA-K0-3-QUERY-003",
            "KAFKA-K0-3-QUERY-004",
            "KAFKA-K0-3-QUERY-005",
            "KAFKA-K0-3-QUERY-006",
            "KAFKA-K0-3-QUERY-007",
        ],
        "search queries",
    )?;
    let expected_query_metadata = [
        (
            "KAFKA-K0-3-QUERY-001",
            "RUST_PATH_OR_SYMBOL",
            "public and module-level call sites",
        ),
        (
            "KAFKA-K0-3-QUERY-002",
            "DEPENDENCY_IDENTITY",
            "backend and dependency mentions",
        ),
        (
            "KAFKA-K0-3-QUERY-003",
            "FEATURE_AND_CFG",
            "feature, profile, and target wiring",
        ),
        (
            "KAFKA-K0-3-QUERY-004",
            "SERVICE_ENVIRONMENT",
            "real-service admission and skip paths",
        ),
        (
            "KAFKA-K0-3-QUERY-005",
            "FILENAME_OR_DOCUMENTATION",
            "case-insensitive path and documentation census",
        ),
        (
            "KAFKA-K0-3-QUERY-006",
            "E2E_WIRING",
            "test target, scenario, and runner wiring",
        ),
        (
            "KAFKA-K0-3-QUERY-007",
            "MIGRATION_LANGUAGE",
            "cutover and migration claims",
        ),
    ]
    .into_iter()
    .map(|(id, matcher, purpose)| (id, (matcher, purpose)))
    .collect::<BTreeMap<_, _>>();
    for query in queries {
        let query_id = text(query, "query_id");
        require_exact_keys(
            query,
            &["literals", "matcher_kind", "purpose", "query_id"],
            query_id,
        )?;
        let literals = string_vec(query, "literals");
        let unique_literals = literals.iter().collect::<BTreeSet<_>>();
        let (expected_matcher, expected_purpose) = expected_query_metadata
            .get(query_id)
            .ok_or_else(|| format!("{query_id} is not a declared search query"))?;
        if literals.is_empty()
            || unique_literals.len() != literals.len()
            || literals.iter().any(String::is_empty)
            || text(query, "matcher_kind") != *expected_matcher
            || text(query, "purpose") != *expected_purpose
        {
            return Err(format!("{query_id} search grammar or purpose drifted"));
        }
    }

    let evidence_claims = array(inventory, "evidence_claims");
    require_exact_ids(
        evidence_claims,
        "evidence_id",
        &[
            "KAFKA-K0-3-EVIDENCE-001",
            "KAFKA-K0-3-EVIDENCE-002",
            "KAFKA-K0-3-EVIDENCE-003",
            "KAFKA-K0-3-EVIDENCE-004",
            "KAFKA-K0-3-EVIDENCE-005",
            "KAFKA-K0-3-EVIDENCE-006",
        ],
        "evidence claims",
    )?;
    let expected_evidence_states = [
        (
            "KAFKA-K0-3-EVIDENCE-001",
            "STATIC_SOURCE",
            "PASS",
            "CURRENT_SOURCE_PINNED",
            "NONE",
        ),
        (
            "KAFKA-K0-3-EVIDENCE-002",
            "COMPILE_ONLY",
            "NOT_RUN",
            "CURRENT_SOURCE_PINNED",
            "NONE",
        ),
        (
            "KAFKA-K0-3-EVIDENCE-003",
            "REAL_BROKER_CAPABLE",
            "NOT_RUN",
            "CURRENT_SOURCE_PINNED",
            "NOT_ATTEMPTED",
        ),
        (
            "KAFKA-K0-3-EVIDENCE-004",
            "PROOF_ONLY",
            "NOT_RUN",
            "CURRENT_SOURCE_PINNED",
            "NOT_ATTEMPTED",
        ),
        (
            "KAFKA-K0-3-EVIDENCE-005",
            "PLANNED",
            "BLOCKED",
            "CURRENT_SOURCE_PINNED",
            "BLOCKED_EXTERNAL",
        ),
        (
            "KAFKA-K0-3-EVIDENCE-006",
            "MOCK_OR_SIMULATED",
            "NOT_RUN",
            "STALE",
            "NONE",
        ),
    ]
    .into_iter()
    .map(|(id, class, execution, freshness, contact)| (id, (class, execution, freshness, contact)))
    .collect::<BTreeMap<_, _>>();
    for evidence in evidence_claims {
        let evidence_id = text(evidence, "evidence_id");
        require_exact_keys(
            evidence,
            &[
                "broker_contact_state",
                "broker_version",
                "evidence_class",
                "evidence_id",
                "exact_command",
                "executed_at_utc",
                "execution_state",
                "freshness_state",
                "limitation",
                "result_summary",
                "retained_artifacts",
                "service_identity",
                "source_revision",
                "subject",
            ],
            evidence_id,
        )?;
        let class = text(evidence, "evidence_class");
        let execution = text(evidence, "execution_state");
        let (expected_class, expected_execution, expected_freshness, expected_contact) =
            expected_evidence_states
                .get(evidence_id)
                .ok_or_else(|| format!("{evidence_id} is not a declared evidence row"))?;
        if class != *expected_class
            || execution != *expected_execution
            || text(evidence, "freshness_state") != *expected_freshness
            || text(evidence, "broker_contact_state") != *expected_contact
            || text(evidence, "source_revision") != BASELINE_REVISION
            || evidence.get("executed_at_utc") != Some(&Value::Null)
            || evidence.get("exact_command") != Some(&Value::Null)
            || evidence.get("broker_version") != Some(&Value::Null)
            || evidence.get("service_identity") != Some(&Value::Null)
            || !array(evidence, "retained_artifacts").is_empty()
            || text(evidence, "subject").is_empty()
            || text(evidence, "result_summary").is_empty()
            || text(evidence, "limitation").is_empty()
        {
            return Err(format!(
                "{evidence_id} evidence distinction or receipt boundary drifted"
            ));
        }
    }
    if evidence_claims
        .iter()
        .any(|row| text(row, "evidence_class") == "REAL_BROKER_RECEIPT")
    {
        return Err("K0.3 must not contain a real-broker receipt".to_owned());
    }

    let external = array(inventory, "external_searches");
    require_exact_ids(
        external,
        "external_id",
        &[
            "KAFKA-K0-3-EXTERNAL-001",
            "KAFKA-K0-3-EXTERNAL-002",
            "KAFKA-K0-3-EXTERNAL-003",
            "KAFKA-K0-3-EXTERNAL-004",
            "KAFKA-K0-3-EXTERNAL-005",
            "KAFKA-K0-3-EXTERNAL-006",
            "KAFKA-K0-3-EXTERNAL-007",
        ],
        "external searches",
    )?;
    for row in external {
        let external_id = text(row, "external_id");
        require_exact_keys(
            row,
            &[
                "absence_authority",
                "attempted_at_utc",
                "blocks_migration",
                "domain_kind",
                "domain_name",
                "exact_queries",
                "external_id",
                "inventory_owner_bead",
                "knowledge_state",
                "limitations",
                "recorded_date_utc",
                "repository_or_package_set",
                "resolution_owner_bead",
                "result_count",
                "result_provenance",
                "results",
                "search_status",
            ],
            external_id,
        )?;
        let exact_queries = string_vec(row, "exact_queries");
        if text(row, "domain_kind").is_empty()
            || text(row, "domain_name").is_empty()
            || text(row, "recorded_date_utc") != CAPTURED_DATE_UTC
            || exact_queries.is_empty()
            || exact_queries.iter().any(String::is_empty)
            || exact_queries.iter().collect::<BTreeSet<_>>().len() != exact_queries.len()
            || text(row, "search_status") != "NOT_RUN"
            || text(row, "knowledge_state") != "UNKNOWN"
            || row.get("attempted_at_utc") != Some(&Value::Null)
            || row.get("result_count") != Some(&Value::Null)
            || !array(row, "results").is_empty()
            || !array(row, "result_provenance").is_empty()
            || !array(row, "repository_or_package_set").is_empty()
            || text(row, "inventory_owner_bead") != BEAD_ID
            || text(row, "resolution_owner_bead") != REFRESH_BEAD_ID
            || !bool_field(row, "blocks_migration")
            || text(row, "absence_authority") != "NONE"
            || text(row, "limitations").is_empty()
        {
            return Err(format!("{external_id} must remain owned NOT_RUN/UNKNOWN"));
        }
    }
    for row in array(inventory, "owned_unknowns") {
        let unknown_id = text(row, "unknown_id");
        if !bool_field(row, "blocks_migration")
            || text(row, "subject_id").is_empty()
            || text(row, "reason").is_empty()
            || text(row, "resolution_gate").is_empty()
            || text(row, "resolution_owner_bead").is_empty()
        {
            return Err(format!(
                "{unknown_id} must remain owned and migration-blocking"
            ));
        }
    }
    for row in array(inventory, "routed_gaps") {
        let gap_id = text(row, "gap_id");
        if text(row, "finding").is_empty() {
            return Err(format!("{gap_id} must retain a concrete finding"));
        }
        require_owner(row, gap_id)?;
    }
    Ok(())
}

fn validate_handoff_and_receipt(inventory: &Value) -> Result<(), String> {
    let handoff = object(inventory, "k14_1_refresh_handoff");
    if handoff.get("owner_bead").and_then(Value::as_str) != Some(REFRESH_BEAD_ID)
        || handoff.get("trigger").and_then(Value::as_str)
            != Some("CLAIM_TIME_BEFORE_MIGRATION_OR_CUTOVER")
        || handoff
            .get("baseline_counts_authoritative_at_claim_time")
            .and_then(Value::as_bool)
            != Some(false)
        || handoff
            .get("unknown_blocks_migration")
            .and_then(Value::as_bool)
            != Some(true)
        || handoff
            .get("regression_blocks_migration")
            .and_then(Value::as_bool)
            != Some(true)
        || handoff
            .get("may_authorize_deletion")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("K14.1 handoff drifted".to_owned());
    }

    let receipt_value = inventory
        .get("coverage_receipt")
        .unwrap_or_else(|| panic!("coverage_receipt must exist"));
    let receipt = receipt_value
        .as_object()
        .unwrap_or_else(|| panic!("coverage_receipt must be an object"));
    require_exact_keys(
        receipt_value,
        &[
            "all_documentation_claims_semantically_resolved",
            "all_inventoried_claim_rows_classified",
            "all_k0_1_profiles_mapped",
            "all_k0_2_semantics_dispositioned_by_exact_join_rule",
            "all_local_rows_owned",
            "all_local_rows_source_pinned_or_explicit_absence",
            "all_user_journeys_mapped",
            "ambiguous_binding_call_site_count",
            "atomic_case_count",
            "baseline_git_tree_receipt_complete",
            "baseline_occurrence_path_count",
            "call_site_census_complete",
            "call_site_group_count",
            "call_site_id_set_sha256",
            "call_site_k0_reference_or_reason_complete",
            "call_site_node_count",
            "call_site_owner_join_complete",
            "call_site_partition_complete",
            "call_site_path_set_sha256",
            "call_site_referenced_path_count",
            "call_site_source_pin_join_complete",
            "candidate_call_shaped_count",
            "contract_execution_evidence",
            "contract_source_execution_claimed",
            "creation_session_validation_mode",
            "documentation_claim_actual_surface_count",
            "documentation_claim_canonical_projection_group_count",
            "documentation_claim_canonical_projection_occurrence_count",
            "documentation_claim_derived_remainder_group_count",
            "documentation_claim_literal_occurrence_count",
            "documentation_claim_matching_line_count",
            "documentation_claim_occurrence_group_count",
            "documentation_claim_occurrence_partition_complete",
            "documentation_claim_owned_unresolved_occurrence_count",
            "documentation_claim_referenced_path_count",
            "documentation_claim_surface_count",
            "documentation_claim_virtual_surface_count",
            "exact_test_declaration_count",
            "exact_tokio_test_declaration_count",
            "excluded_comment_or_string_candidate_count",
            "excluded_name_collision_call_site_count",
            "excluded_pattern_only_candidate_count",
            "exhaustive_documentation_claim_census_complete",
            "exhaustive_documentation_claim_identity_and_ownership_census_complete",
            "exhaustive_test_declaration_semantic_classification_complete",
            "explicit_exclusion_candidate_count",
            "external_downstream_search_complete",
            "external_searches_not_run_count",
            "inventory_receipt_complete",
            "k0_1_ids_without_resolved_call_sites_count",
            "k0_2_ids_without_resolved_call_sites_count",
            "legacy_local_row_only_unknown_k0_1_usage_count",
            "legacy_local_row_only_unknown_k0_2_usage_count",
            "local_row_referenced_path_count",
            "local_static_scope_complete",
            "local_static_scope_definition",
            "migration_blockers",
            "migration_eligible",
            "non_consumer_dispositioned_path_count",
            "occurrence_disposition_group_count",
            "occurrence_path_partition_complete",
            "policy_or_context_retained_path_count",
            "real_broker_cases_without_receipt_count",
            "real_broker_evidence_complete",
            "receipt_scope",
            "required_aggregate_atomic_case_split_complete",
            "resolved_current_k0_call_site_count",
            "resolved_stale_unwired_k0_call_site_count",
            "source_pin_count",
            "test_declaration_census_complete",
            "test_declaration_classification_rule",
            "test_declaration_count",
            "test_declaration_group_classification_count",
            "test_declaration_group_count",
            "test_declarations_with_atomic_case_overrides",
            "test_declarations_with_inherited_group_classification",
            "tokio_test_declaration_tuple_sha256",
            "unclassified_inventoried_claim_rows",
            "unknown_local_rows",
            "unmapped_k0_1_profiles",
            "unmapped_user_journeys",
            "unowned_local_rows",
            "unresolved_stale_call_site_count",
        ],
        "coverage_receipt",
    )?;

    validate_baseline_occurrence_paths(inventory)?;
    validate_occurrence_disposition_groups(inventory)?;
    validate_test_declaration_groups(inventory)?;
    validate_test_declaration_group_classifications(inventory)?;
    validate_documentation_claim_census(inventory)?;
    validate_call_site_scope_and_groups(inventory)?;

    let pins = pin_paths(inventory);
    let local_rows = array(inventory, "local_inventory_rows");
    let unknown_local_rows = local_rows
        .iter()
        .filter(|row| !local_row_source_is_accounted(row, &pins))
        .map(|row| text(row, "row_id").to_owned())
        .collect::<BTreeSet<_>>();
    let unowned_local_rows = local_rows
        .iter()
        .filter(|row| {
            row.get("owner_bead")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(|row| text(row, "row_id").to_owned())
        .collect::<BTreeSet<_>>();
    let taxonomies = inventory
        .get("taxonomies")
        .unwrap_or_else(|| panic!("taxonomies must exist"));
    let dispositions = string_set(taxonomies, "claim_disposition");
    let freshness_states = string_set(taxonomies, "freshness_state");
    let evidence_classes = string_set(taxonomies, "evidence_class");
    let unclassified_claim_rows = array(inventory, "documentation_claims")
        .iter()
        .filter(|claim| {
            !claim
                .get("claim_disposition")
                .and_then(Value::as_str)
                .is_some_and(|value| dispositions.contains(value))
                || !claim
                    .get("freshness_state")
                    .and_then(Value::as_str)
                    .is_some_and(|value| freshness_states.contains(value))
                || !claim
                    .get("evidence_class")
                    .and_then(Value::as_str)
                    .is_some_and(|value| evidence_classes.contains(value))
        })
        .map(|claim| text(claim, "claim_id").to_owned())
        .collect::<BTreeSet<_>>();
    let k0_1 = parse_repo_json(K0_1_PATH);
    let expected_profiles = row_ids(array(&k0_1, "compilation_profiles"), "profile_id");
    let mapped_profiles = array(inventory, "compilation_profiles")
        .iter()
        .filter(|profile| text(profile, "profile_kind") == "K0_1_CANONICAL")
        .map(|profile| text(profile, "k0_1_profile_id").to_owned())
        .collect::<BTreeSet<_>>();
    let unmapped_k0_1_profiles = expected_profiles
        .difference(&mapped_profiles)
        .cloned()
        .collect::<BTreeSet<_>>();
    let unmapped_user_journeys = array(inventory, "user_journeys")
        .iter()
        .filter(|journey| {
            array(journey, "local_row_ids").is_empty()
                || array(journey, "ordered_public_entry_points").is_empty()
                || journey
                    .get("owner_bead")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
        })
        .map(|journey| text(journey, "journey_id").to_owned())
        .collect::<BTreeSet<_>>();
    for (key, expected) in [
        ("unknown_local_rows", &unknown_local_rows),
        ("unowned_local_rows", &unowned_local_rows),
        (
            "unclassified_inventoried_claim_rows",
            &unclassified_claim_rows,
        ),
        ("unmapped_k0_1_profiles", &unmapped_k0_1_profiles),
        ("unmapped_user_journeys", &unmapped_user_journeys),
    ] {
        if string_set(receipt_value, key) != *expected
            || array(receipt_value, key).len() != expected.len()
        {
            return Err(format!("coverage_receipt.{key} is not derived"));
        }
    }

    let occurrence_groups = array(inventory, "occurrence_disposition_groups");
    let disposition_count = |name: &str| {
        occurrence_groups
            .iter()
            .find(|group| text(group, "disposition") == name)
            .map_or(0, |group| array(group, "paths").len())
    };
    let declaration_groups = array(inventory, "test_declaration_groups");
    let declaration_count = declaration_groups
        .iter()
        .map(|group| array(group, "tests").len())
        .sum::<usize>();
    let tokio_count = declaration_groups
        .iter()
        .flat_map(|group| array(group, "tests"))
        .filter(|test| test.get("attribute_kind").and_then(Value::as_str) == Some("tokio::test"))
        .count();
    let exact_test_count = declaration_count - tokio_count;
    let atomic_cases = array(inventory, "atomic_test_cases");
    let atomic_override_count = atomic_cases.len();
    let inherited_count = declaration_count - atomic_override_count;
    let call_groups = array(inventory, "call_site_groups");
    let call_sites = call_groups
        .iter()
        .flat_map(|group| array(group, "atomic_sites"))
        .collect::<Vec<_>>();
    let state_count = |state: &str| {
        call_sites
            .iter()
            .filter(|site| text(site, "resolution_state") == state)
            .count()
    };
    let candidate_call_shaped = state_count("RESOLVED_CURRENT_K0")
        + state_count("RESOLVED_STALE_UNWIRED_K0")
        + state_count("UNRESOLVED_STALE_SURFACE");
    let explicit_exclusions = state_count("EXCLUDED_NAME_COLLISION")
        + state_count("EXCLUDED_PATTERN_ONLY")
        + state_count("EXCLUDED_COMMENT_OR_STRING");
    let resolved_states = ["RESOLVED_CURRENT_K0", "RESOLVED_STALE_UNWIRED_K0"];
    let resolved_k0_1 = call_sites
        .iter()
        .filter(|site| resolved_states.contains(&text(site, "resolution_state")))
        .filter_map(|site| site.get("k0_1_symbol_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let resolved_k0_2 = call_sites
        .iter()
        .filter(|site| resolved_states.contains(&text(site, "resolution_state")))
        .flat_map(|site| string_set(site, "k0_2_semantic_ids"))
        .collect::<BTreeSet<_>>();
    let missing_k0_1 = k0_1_symbol_ids().len() - resolved_k0_1.len();
    let missing_k0_2 = k0_2_semantic_ids().len() - resolved_k0_2.len();
    let legacy_unknown_k0_1 = array(inventory, "k0_1_symbol_dispositions")
        .iter()
        .filter(|row| text(row, "usage_knowledge_state") == "UNKNOWN")
        .count();
    let legacy_unknown_k0_2 = array(inventory, "k0_2_semantic_dispositions")
        .iter()
        .filter(|row| text(row, "usage_knowledge_state") == "UNKNOWN")
        .count();
    let external_not_run = array(inventory, "external_searches")
        .iter()
        .filter(|row| text(row, "search_status") == "NOT_RUN")
        .count();
    let real_broker_without_receipt = atomic_cases
        .iter()
        .filter(|case| {
            text(case, "evidence_class") == "REAL_BROKER_CAPABLE"
                && text(case, "execution_state") == "NOT_RUN"
        })
        .count();
    if missing_k0_1 != 9 || missing_k0_2 != 22 || real_broker_without_receipt != 15 {
        return Err(
            "K0 call-coverage gaps or real-broker-capable atomic case count drifted".to_owned(),
        );
    }
    let documentation_scope = inventory
        .get("documentation_claim_scope")
        .unwrap_or_else(|| panic!("documentation_claim_scope must exist"));
    let numeric_receipts = [
        ("baseline_occurrence_path_count", OCCURRENCE_PATH_COUNT),
        (
            "occurrence_disposition_group_count",
            occurrence_groups.len(),
        ),
        (
            "local_row_referenced_path_count",
            disposition_count("LOCAL_ROW_REFERENCED"),
        ),
        (
            "documentation_claim_referenced_path_count",
            disposition_count("DOCUMENTATION_CLAIM_REFERENCED"),
        ),
        (
            "call_site_referenced_path_count",
            disposition_count("CALL_SITE_REFERENCED"),
        ),
        (
            "non_consumer_dispositioned_path_count",
            disposition_count("NON_CONSUMER_DISPOSITIONED"),
        ),
        (
            "policy_or_context_retained_path_count",
            disposition_count("POLICY_OR_CONTEXT_RETAINED"),
        ),
        ("source_pin_count", array(inventory, "source_pins").len()),
        (
            "documentation_claim_actual_surface_count",
            DOCUMENTATION_ACTUAL_SURFACE_COUNT,
        ),
        ("documentation_claim_virtual_surface_count", 1),
        (
            "documentation_claim_surface_count",
            DOCUMENTATION_SURFACE_COUNT,
        ),
        (
            "documentation_claim_literal_occurrence_count",
            DOCUMENTATION_OCCURRENCE_COUNT,
        ),
        (
            "documentation_claim_matching_line_count",
            DOCUMENTATION_MATCHING_LINE_COUNT,
        ),
        (
            "documentation_claim_canonical_projection_group_count",
            DOCUMENTATION_CLAIM_COUNT,
        ),
        (
            "documentation_claim_canonical_projection_occurrence_count",
            DOCUMENTATION_CANONICAL_OCCURRENCE_COUNT,
        ),
        (
            "documentation_claim_owned_unresolved_occurrence_count",
            DOCUMENTATION_REMAINDER_OCCURRENCE_COUNT,
        ),
        ("documentation_claim_derived_remainder_group_count", 142),
        (
            "documentation_claim_occurrence_group_count",
            DOCUMENTATION_OCCURRENCE_GROUP_COUNT,
        ),
        ("test_declaration_group_count", declaration_groups.len()),
        (
            "test_declaration_group_classification_count",
            array(inventory, "test_declaration_group_classifications").len(),
        ),
        ("test_declaration_count", declaration_count),
        ("exact_test_declaration_count", exact_test_count),
        ("exact_tokio_test_declaration_count", tokio_count),
        ("atomic_case_count", atomic_cases.len()),
        (
            "test_declarations_with_atomic_case_overrides",
            atomic_override_count,
        ),
        (
            "test_declarations_with_inherited_group_classification",
            inherited_count,
        ),
        ("call_site_group_count", call_groups.len()),
        ("call_site_node_count", call_sites.len()),
        ("candidate_call_shaped_count", candidate_call_shaped),
        ("explicit_exclusion_candidate_count", explicit_exclusions),
        (
            "resolved_current_k0_call_site_count",
            state_count("RESOLVED_CURRENT_K0"),
        ),
        (
            "resolved_stale_unwired_k0_call_site_count",
            state_count("RESOLVED_STALE_UNWIRED_K0"),
        ),
        (
            "excluded_name_collision_call_site_count",
            state_count("EXCLUDED_NAME_COLLISION"),
        ),
        (
            "unresolved_stale_call_site_count",
            state_count("UNRESOLVED_STALE_SURFACE"),
        ),
        (
            "excluded_pattern_only_candidate_count",
            state_count("EXCLUDED_PATTERN_ONLY"),
        ),
        (
            "excluded_comment_or_string_candidate_count",
            state_count("EXCLUDED_COMMENT_OR_STRING"),
        ),
        ("ambiguous_binding_call_site_count", 0),
        ("k0_1_ids_without_resolved_call_sites_count", missing_k0_1),
        ("k0_2_ids_without_resolved_call_sites_count", missing_k0_2),
        (
            "legacy_local_row_only_unknown_k0_1_usage_count",
            legacy_unknown_k0_1,
        ),
        (
            "legacy_local_row_only_unknown_k0_2_usage_count",
            legacy_unknown_k0_2,
        ),
        ("external_searches_not_run_count", external_not_run),
        (
            "real_broker_cases_without_receipt_count",
            real_broker_without_receipt,
        ),
    ];
    for (key, expected) in numeric_receipts {
        if receipt.get(key).and_then(Value::as_u64) != Some(count_u64(expected, key)) {
            return Err(format!("coverage_receipt.{key} is not derived"));
        }
    }
    if documentation_scope
        .get("literal_occurrence_count")
        .and_then(Value::as_u64)
        != receipt
            .get("documentation_claim_literal_occurrence_count")
            .and_then(Value::as_u64)
    {
        return Err("documentation receipt/source scope count drifted".to_owned());
    }
    for (key, expected) in [
        ("call_site_id_set_sha256", CALL_SITE_ID_SET_SHA256),
        ("call_site_path_set_sha256", CALL_SITE_PATH_SET_SHA256),
        (
            "tokio_test_declaration_tuple_sha256",
            TOKIO_TEST_DECLARATION_TUPLE_SHA256,
        ),
    ] {
        if receipt.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("coverage_receipt.{key} drifted"));
        }
    }

    let local_static_complete = unknown_local_rows.is_empty()
        && unowned_local_rows.is_empty()
        && unclassified_claim_rows.is_empty()
        && unmapped_k0_1_profiles.is_empty()
        && mapped_profiles.len() == expected_profiles.len()
        && unmapped_user_journeys.is_empty();
    for (key, expected) in [
        ("baseline_git_tree_receipt_complete", true),
        ("occurrence_path_partition_complete", true),
        ("test_declaration_census_complete", true),
        ("required_aggregate_atomic_case_split_complete", true),
        (
            "exhaustive_test_declaration_semantic_classification_complete",
            true,
        ),
        ("call_site_census_complete", true),
        ("call_site_partition_complete", true),
        ("call_site_source_pin_join_complete", true),
        ("call_site_owner_join_complete", true),
        ("call_site_k0_reference_or_reason_complete", true),
        ("exhaustive_documentation_claim_census_complete", true),
        (
            "exhaustive_documentation_claim_identity_and_ownership_census_complete",
            true,
        ),
        ("documentation_claim_occurrence_partition_complete", true),
        ("all_documentation_claims_semantically_resolved", false),
        ("external_downstream_search_complete", false),
        ("real_broker_evidence_complete", false),
        (
            "all_local_rows_source_pinned_or_explicit_absence",
            unknown_local_rows.is_empty(),
        ),
        ("all_local_rows_owned", unowned_local_rows.is_empty()),
        (
            "all_inventoried_claim_rows_classified",
            unclassified_claim_rows.is_empty(),
        ),
        (
            "all_k0_1_profiles_mapped",
            unmapped_k0_1_profiles.is_empty() && mapped_profiles.len() == expected_profiles.len(),
        ),
        ("all_k0_2_semantics_dispositioned_by_exact_join_rule", true),
        (
            "all_user_journeys_mapped",
            unmapped_user_journeys.is_empty(),
        ),
        ("local_static_scope_complete", local_static_complete),
        ("inventory_receipt_complete", local_static_complete),
        ("migration_eligible", false),
    ] {
        if receipt.get(key).and_then(Value::as_bool) != Some(expected) {
            return Err(format!("coverage_receipt.{key} is not derived"));
        }
    }

    let expected_blockers = vec![
        "9 K0.1 public-symbol IDs have no resolved invocation in the declared call-site grammar; non-call use is outside that grammar and K14 synthesis remains required".to_owned(),
        "22 K0.2 semantic IDs have no resolved invocation in the declared call-site grammar and require K14 synthesis before migration".to_owned(),
        "8 stale call-site candidate nodes remain unresolved against the current K0.1 surface".to_owned(),
        "162 baseline occurrence paths are explicitly owned and conservatively POLICY_OR_CONTEXT_RETAINED pending K14 recheck".to_owned(),
        "924 of 940 literal test declarations use owned group-inherited classifications rather than individual atomic migration analysis".to_owned(),
        "9,143 literal documentation occurrences have stable identity and ownership but remain semantically UNKNOWN and migration-blocking".to_owned(),
        "all seven external downstream search domains are NOT_RUN and UNKNOWN".to_owned(),
        "all fifteen real-broker-capable atomic cases are NOT_RUN and retain no immutable broker receipt".to_owned(),
    ];
    if string_vec(receipt_value, "migration_blockers") != expected_blockers
        || receipt.get("receipt_scope").and_then(Value::as_str)
            != Some("K0_3_STATIC_INVENTORY_AND_DECLARED_CALL_SITE_CENSUS")
        || receipt
            .get("local_static_scope_definition")
            .and_then(Value::as_str)
            != Some(
                "the exact 245-path five-tier occurrence partition, 940 named declarations across exact test and tokio::test attributes, 16 atomic overrides, 1,363-node candidate call-site grammar, and 9,180-occurrence documentation-claim identity and ownership partition are complete; 266 call-site candidates are explicit exclusions and 9,143 documentation occurrences remain semantically UNKNOWN",
            )
        || receipt
            .get("test_declaration_classification_rule")
            .and_then(Value::as_str)
            != Some(
                "every named exact #[test] or #[tokio::test] declaration inherits its exact path-and-source-pin group classification unless that group lists its case ID as an atomic override",
            )
        || receipt
            .get("contract_source_execution_claimed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .get("creation_session_validation_mode")
            .and_then(Value::as_str)
            != Some("STATIC_INSPECTION_ONLY")
        || receipt
            .get("contract_execution_evidence")
            .and_then(Value::as_str)
            != Some("NOT_RECORDED_IN_THIS_ARTIFACT")
    {
        return Err("static honesty receipt drifted".to_owned());
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    validate_identity(inventory)?;
    validate_authority_and_policy(inventory)?;
    validate_taxonomies(inventory)?;
    validate_counts_and_ids(inventory)?;
    validate_baseline_occurrence_paths(inventory)?;
    validate_occurrence_disposition_groups(inventory)?;
    validate_local_joins(inventory)?;
    validate_call_site_scope_and_groups(inventory)?;
    validate_test_declaration_groups(inventory)?;
    validate_test_declaration_group_classifications(inventory)?;
    validate_documentation_claim_census(inventory)?;
    validate_k0_dispositions(inventory)?;
    validate_profiles_and_cells(inventory)?;
    validate_canonical_journeys(inventory)?;
    validate_state_compatibility(inventory)?;
    validate_evidence_and_external(inventory)?;
    validate_handoff_and_receipt(inventory)?;
    Ok(())
}

fn validate_baseline_occurrence_paths(inventory: &Value) -> Result<(), String> {
    let scope = inventory
        .get("search_scope")
        .unwrap_or_else(|| panic!("search_scope must exist"));
    let expected_roots = expected_set(&[
        ".claude",
        ".github",
        "artifacts",
        "conformance",
        "docs",
        "examples",
        "formal",
        "fuzz",
        "refactor",
        "scripts",
        "skills",
        "src",
        "tests",
    ]);
    if string_set(scope, "roots") != expected_roots {
        return Err("search roots drifted".to_owned());
    }
    let expected_root_files = expected_set(&[
        "AGENTS.md",
        "CHANGELOG.md",
        "COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md",
        "Cargo.lock",
        "Cargo.toml",
        "README.md",
        "TESTING.md",
        "UPGRADE_LOG.md",
        "audit_index.jsonl",
        "e2e_hardening_14_analysis.md",
        "e2e_hardening_8_analysis.md",
        "e2e_hardening_summary.md",
    ]);
    if string_set(scope, "root_files") != expected_root_files {
        return Err("search root files drifted".to_owned());
    }

    if scope.get("scope_basis").and_then(Value::as_str) != Some("BASELINE_GIT_TREE_RECEIPT")
        || scope.get("baseline_revision").and_then(Value::as_str) != Some(BASELINE_REVISION)
        || scope
            .get("current_worktree_claimed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("search scope must remain an immutable baseline-tree receipt".to_owned());
    }
    let declared_paths = string_vec(scope, "baseline_occurrence_paths");
    let path_set = declared_paths.iter().cloned().collect::<BTreeSet<_>>();
    let sorted_paths = path_set.iter().cloned().collect::<Vec<_>>();
    if declared_paths.len() != OCCURRENCE_PATH_COUNT
        || path_set.len() != OCCURRENCE_PATH_COUNT
        || declared_paths != sorted_paths
        || sorted_newline_sha256(&path_set) != OCCURRENCE_PATH_MAP_SHA256
        || scope
            .get("baseline_occurrence_path_count")
            .and_then(Value::as_u64)
            != Some(
                u64::try_from(OCCURRENCE_PATH_COUNT)
                    .unwrap_or_else(|error| panic!("occurrence count overflow: {error}")),
            )
        || scope
            .get("baseline_occurrence_path_digest_sha256")
            .and_then(Value::as_str)
            != Some(OCCURRENCE_PATH_MAP_SHA256)
        || scope
            .get("tracked_occurrence_path_count")
            .and_then(Value::as_u64)
            != Some(
                u64::try_from(OCCURRENCE_PATH_COUNT)
                    .unwrap_or_else(|error| panic!("occurrence count overflow: {error}")),
            )
        || scope
            .get("sorted_newline_path_map_sha256")
            .and_then(Value::as_str)
            != Some(OCCURRENCE_PATH_MAP_SHA256)
        || scope.get("inventory_owner_bead").and_then(Value::as_str) != Some(BEAD_ID)
        || scope.get("refresh_owner_bead").and_then(Value::as_str) != Some(REFRESH_BEAD_ID)
    {
        return Err("baseline occurrence-path receipt drifted".to_owned());
    }
    if path_set.iter().any(|path| {
        path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
    }) {
        return Err("baseline occurrence paths must be normalized repository paths".to_owned());
    }
    Ok(())
}

fn validate_occurrence_disposition_groups(inventory: &Value) -> Result<(), String> {
    let baseline = string_set(
        inventory
            .get("search_scope")
            .unwrap_or_else(|| panic!("search_scope must exist")),
        "baseline_occurrence_paths",
    );
    let groups = array(inventory, "occurrence_disposition_groups");
    require_exact_ids(
        groups,
        "disposition_id",
        &[
            "KAFKA-K0-3-OCCURRENCE-GROUP-001",
            "KAFKA-K0-3-OCCURRENCE-GROUP-002",
            "KAFKA-K0-3-OCCURRENCE-GROUP-003",
            "KAFKA-K0-3-OCCURRENCE-GROUP-004",
            "KAFKA-K0-3-OCCURRENCE-GROUP-005",
        ],
        "occurrence disposition groups",
    )?;
    let expected_dispositions = [
        ("KAFKA-K0-3-OCCURRENCE-GROUP-001", "LOCAL_ROW_REFERENCED"),
        (
            "KAFKA-K0-3-OCCURRENCE-GROUP-002",
            "DOCUMENTATION_CLAIM_REFERENCED",
        ),
        ("KAFKA-K0-3-OCCURRENCE-GROUP-003", "CALL_SITE_REFERENCED"),
        (
            "KAFKA-K0-3-OCCURRENCE-GROUP-004",
            "NON_CONSUMER_DISPOSITIONED",
        ),
        (
            "KAFKA-K0-3-OCCURRENCE-GROUP-005",
            "POLICY_OR_CONTEXT_RETAINED",
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let mut union = BTreeSet::new();
    let mut paths_by_disposition = BTreeMap::<String, BTreeSet<String>>::new();
    for group in groups {
        let group_id = text(group, "disposition_id");
        require_exact_keys(
            group,
            &["disposition", "disposition_id", "owner_bead", "paths"],
            group_id,
        )?;
        let disposition = text(group, "disposition");
        if expected_dispositions.get(group_id).copied() != Some(disposition)
            || text(group, "owner_bead") != REFRESH_BEAD_ID
        {
            return Err(format!("{group_id} disposition or owner drifted"));
        }
        let paths = string_set(group, "paths");
        if paths.is_empty() || paths.len() != array(group, "paths").len() {
            return Err(format!("{group_id} paths must be nonempty and unique"));
        }
        for path in &paths {
            if !union.insert(path.clone()) {
                return Err(format!("occurrence path {path} has multiple dispositions"));
            }
        }
        paths_by_disposition.insert(disposition.to_owned(), paths);
    }
    if union != baseline {
        return Err("occurrence disposition groups must exactly partition the baseline".to_owned());
    }

    let local_paths = array(inventory, "local_inventory_rows")
        .iter()
        .map(|row| text(row, "path").to_owned())
        .filter(|path| baseline.contains(path))
        .collect::<BTreeSet<_>>();
    let documentation_candidates = array(inventory, "documentation_claims")
        .iter()
        .flat_map(|claim| string_set(claim, "paths"))
        .filter(|path| baseline.contains(path))
        .collect::<BTreeSet<_>>();
    let documentation_paths = documentation_candidates
        .difference(&local_paths)
        .cloned()
        .collect::<BTreeSet<_>>();

    let prior_paths = local_paths
        .union(&documentation_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let call_site_paths = array(inventory, "call_site_groups")
        .iter()
        .filter(|group| {
            let path = text(group, "path");
            baseline.contains(path)
                && !prior_paths.contains(path)
                && array(group, "atomic_sites").iter().any(|site| {
                    matches!(
                        text(site, "resolution_state"),
                        "RESOLVED_CURRENT_K0"
                            | "RESOLVED_STALE_UNWIRED_K0"
                            | "UNRESOLVED_STALE_SURFACE"
                    )
                })
        })
        .map(|group| text(group, "path").to_owned())
        .collect::<BTreeSet<_>>();

    let non_consumers = array(inventory, "non_consumer_dispositions");
    require_exact_ids(
        non_consumers,
        "disposition_id",
        &[
            "KAFKA-K0-3-NONCONSUMER-001",
            "KAFKA-K0-3-NONCONSUMER-002",
            "KAFKA-K0-3-NONCONSUMER-003",
            "KAFKA-K0-3-NONCONSUMER-004",
        ],
        "non-consumer dispositions",
    )?;
    let mut non_consumer_candidates = BTreeSet::new();
    for row in non_consumers {
        let row_id = text(row, "disposition_id");
        require_owner(row, row_id)?;
        let paths = string_set(row, "paths");
        if paths.is_empty() || paths.len() != array(row, "paths").len() {
            return Err(format!("{row_id} must enumerate unique non-consumer paths"));
        }
        non_consumer_candidates.extend(paths.into_iter().filter(|path| baseline.contains(path)));
    }
    let already_classified = prior_paths
        .union(&call_site_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let non_consumer_paths = non_consumer_candidates
        .difference(&already_classified)
        .cloned()
        .collect::<BTreeSet<_>>();
    let specifically_classified = already_classified
        .union(&non_consumer_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let retained_paths = baseline
        .difference(&specifically_classified)
        .cloned()
        .collect::<BTreeSet<_>>();
    if [
        local_paths.len(),
        documentation_paths.len(),
        call_site_paths.len(),
        non_consumer_paths.len(),
        retained_paths.len(),
    ] != [30, 31, 5, 17, 162]
    {
        return Err("five-tier occurrence partition cardinalities drifted".to_owned());
    }

    for (disposition, expected_paths) in [
        ("LOCAL_ROW_REFERENCED", local_paths),
        ("DOCUMENTATION_CLAIM_REFERENCED", documentation_paths),
        ("CALL_SITE_REFERENCED", call_site_paths),
        ("NON_CONSUMER_DISPOSITIONED", non_consumer_paths),
        ("POLICY_OR_CONTEXT_RETAINED", retained_paths),
    ] {
        if paths_by_disposition.get(disposition) != Some(&expected_paths) {
            return Err(format!("{disposition} path classification drifted"));
        }
    }
    Ok(())
}

fn is_documentation_candidate_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".md", ".json", ".jsonl", ".yml", ".snap"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn kafka_match_count(line: &str) -> usize {
    let lower = line.as_bytes().to_ascii_lowercase();
    let mut count = 0_usize;
    let mut offset = 0_usize;
    while offset + 5 <= lower.len() {
        let Some(relative) = lower[offset..]
            .windows(5)
            .position(|window| window == b"kafka")
        else {
            break;
        };
        count += 1;
        offset += relative + 5;
    }
    count
}

fn validate_documentation_claim_census(inventory: &Value) -> Result<(), String> {
    let scope = inventory
        .get("documentation_claim_scope")
        .unwrap_or_else(|| panic!("documentation_claim_scope must exist"));
    require_exact_keys(
        scope,
        &[
            "actual_candidate_extension_counts",
            "actual_candidate_path_list_sha256",
            "actual_candidate_surface_count",
            "all_documentation_claims_semantically_resolved",
            "baseline_revision",
            "candidate_surface_extensions",
            "candidate_surface_selector",
            "canonical_documentation_claim_count",
            "canonical_projection_occurrence_count",
            "canonical_projection_occurrence_id_list_sha256",
            "identity_and_ownership_census_complete",
            "literal_matcher",
            "literal_occurrence_count",
            "matching_line_count",
            "matching_line_locator_tuple_sha256",
            "migration_blocking",
            "no_removal_authority",
            "occurrence_group_count",
            "occurrence_group_id_list_sha256",
            "occurrence_id_list_sha256",
            "occurrence_id_rule",
            "occurrence_locator_tuple",
            "occurrence_locator_tuple_sha256",
            "occurrence_partition_complete",
            "owned_unresolved_occurrence_count",
            "owned_unresolved_occurrence_id_list_sha256",
            "scope_id",
            "source_pin_count_for_actual_candidate_surfaces",
            "source_pin_join_cardinality",
            "surface_id_path_source_pin_tuple_rule",
            "surface_id_path_source_pin_tuple_sha256",
            "surface_id_path_tuple_sha256",
            "total_surface_count",
            "virtual_source_pin_digest_token",
            "virtual_surface_count",
        ],
        "documentation_claim_scope",
    )?;
    if text(scope, "scope_id") != "KAFKA-K0-3-DOCUMENTATION-CLAIM-CENSUS-001"
        || text(scope, "baseline_revision") != BASELINE_REVISION
        || text(scope, "virtual_source_pin_digest_token") != "EXACT_BASELINE_ABSENCE"
        || string_set(scope, "candidate_surface_extensions")
            != expected_set(&["md", "json", "jsonl", "yml", "snap"])
    {
        return Err("documentation claim scope identity or selector drifted".to_owned());
    }

    let baseline_paths = string_vec(
        inventory
            .get("search_scope")
            .unwrap_or_else(|| panic!("search_scope must exist")),
        "baseline_occurrence_paths",
    );
    let candidate_paths = baseline_paths
        .into_iter()
        .filter(|path| is_documentation_candidate_path(path))
        .collect::<Vec<_>>();
    if candidate_paths.len() != DOCUMENTATION_ACTUAL_SURFACE_COUNT
        || newline_sha256(&candidate_paths) != DOCUMENTATION_PATH_SHA256
    {
        return Err("documentation candidate path census drifted".to_owned());
    }
    let path_to_pin = array(inventory, "source_pins")
        .iter()
        .map(|pin| (text(pin, "path").to_owned(), text(pin, "pin_id").to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut surface_tuples = Vec::new();
    let mut source_pin_tuples = Vec::new();
    let mut occurrence_tuples = Vec::new();
    let mut line_tuples = Vec::new();
    let mut occurrence_ids = Vec::new();
    let mut occurrence_path = BTreeMap::new();
    let mut occurrence_ids_by_surface = BTreeMap::<usize, Vec<String>>::new();
    let mut extension_counts = BTreeMap::<String, usize>::new();
    for (surface_index, path) in candidate_paths.iter().enumerate() {
        let surface_ordinal = surface_index + 1;
        let surface_id = format!("KAFKA-K0-3-DOC-SURFACE-{surface_ordinal:03}");
        let pin_id = path_to_pin
            .get(path)
            .ok_or_else(|| format!("documentation surface {path} lacks a source pin"))?;
        let extension = path
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .ok_or_else(|| format!("documentation surface {path} lacks an extension"))?;
        *extension_counts.entry(extension).or_default() += 1;
        surface_tuples.push(format!("{surface_id}\t{path}"));
        source_pin_tuples.push(format!("{surface_id}\t{path}\t{pin_id}"));
        for (line_index, line) in read_repo_file(path).lines().enumerate() {
            let line_number = line_index + 1;
            let matches = kafka_match_count(line);
            if matches != 0 {
                line_tuples.push(format!("{path}\t{line_number}"));
            }
            for match_ordinal in 1..=matches {
                let occurrence_id = format!(
                    "KAFKA-K0-3-DOC-OCC-{surface_ordinal:03}-L{line_number:06}-M{match_ordinal:03}"
                );
                occurrence_tuples.push(format!("{path}\t{line_number}\t{match_ordinal}"));
                occurrence_path.insert(occurrence_id.clone(), path.clone());
                occurrence_ids_by_surface
                    .entry(surface_ordinal)
                    .or_default()
                    .push(occurrence_id.clone());
                occurrence_ids.push(occurrence_id);
            }
        }
    }
    let expected_extensions = [
        ("json".to_owned(), 55_usize),
        ("jsonl".to_owned(), 1),
        ("md".to_owned(), 90),
        ("snap".to_owned(), 2),
        ("yml".to_owned(), 1),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let declared_extensions = scope
        .get("actual_candidate_extension_counts")
        .unwrap_or_else(|| panic!("actual_candidate_extension_counts must exist"));
    require_exact_keys(
        declared_extensions,
        &["json", "jsonl", "md", "snap", "yml"],
        "documentation_claim_scope.actual_candidate_extension_counts",
    )?;
    for (extension, count) in &expected_extensions {
        if declared_extensions.get(extension).and_then(Value::as_u64)
            != Some(count_u64(*count, "documentation extension"))
        {
            return Err(format!(
                "documentation extension count for {extension} drifted"
            ));
        }
    }
    if extension_counts != expected_extensions
        || occurrence_ids.len() != DOCUMENTATION_OCCURRENCE_COUNT
        || line_tuples.len() != DOCUMENTATION_MATCHING_LINE_COUNT
        || newline_sha256(&occurrence_tuples) != DOCUMENTATION_OCCURRENCE_TUPLE_SHA256
        || newline_sha256(&line_tuples) != DOCUMENTATION_LINE_TUPLE_SHA256
        || newline_sha256(&occurrence_ids) != DOCUMENTATION_OCCURRENCE_ID_SHA256
        || newline_sha256(&surface_tuples) != DOCUMENTATION_ACTUAL_SURFACE_TUPLE_SHA256
    {
        return Err("documentation literal occurrence regeneration drifted".to_owned());
    }

    let surfaces = inventory
        .get("documentation_claim_surfaces")
        .unwrap_or_else(|| panic!("documentation_claim_surfaces must exist"));
    require_exact_keys(
        surfaces,
        &[
            "actual_surface_derivation",
            "representation",
            "virtual_absence_no_claim",
            "virtual_surfaces",
        ],
        "documentation_claim_surfaces",
    )?;
    let derivation = surfaces
        .get("actual_surface_derivation")
        .unwrap_or_else(|| panic!("actual_surface_derivation must exist"));
    require_exact_keys(
        derivation,
        &[
            "all_derived_surfaces_have_at_least_one_literal_occurrence",
            "classification_rule",
            "derived_surface_count",
            "derived_surface_id_path_tuple_sha256",
            "documentation_claim_join_rule",
            "exact_path_locator_rule",
            "filter",
            "migration_blocking",
            "no_removal_authority",
            "occurrence_set_rule",
            "ordering",
            "owner_bead",
            "refresh_owner_bead",
            "semantic_state_for_noncanonical_occurrences",
            "source_array",
            "source_pin_join_rule",
            "surface_id_path_source_pin_tuple_rule",
            "surface_id_rule",
        ],
        "documentation_claim_surfaces.actual_surface_derivation",
    )?;
    if text(derivation, "source_array") != "search_scope.baseline_occurrence_paths"
        || text(derivation, "filter") != "case-insensitive \\.(md|json|jsonl|yml|snap)$"
        || text(derivation, "ordering") != "preserve source-array order"
        || text(derivation, "surface_id_rule")
            != "KAFKA-K0-3-DOC-SURFACE-{three-digit 1-based filtered-array ordinal}"
        || text(derivation, "exact_path_locator_rule")
            != "the filtered source-array element at the same ordinal"
        || text(derivation, "source_pin_join_rule")
            != "the unique source_pins row whose path equals the exact path locator"
        || text(derivation, "documentation_claim_join_rule")
            != "all documentation_claims rows whose paths array contains the exact path locator"
        || text(derivation, "occurrence_set_rule")
            != "all occurrence IDs whose three-digit surface ordinal equals the surface ordinal"
        || text(derivation, "classification_rule")
            != "CURATED_CLAIM_PROJECTION_ONLY when the surface has a canonical projection and no set-difference remainder; CURATED_AND_OWNED_UNRESOLVED_CLAIMS when it has both; otherwise OWNED_UNRESOLVED_CLAIM_SURFACE"
        || text(derivation, "owner_bead") != DOCUMENTATION_OWNER_BEAD_ID
        || text(derivation, "refresh_owner_bead") != REFRESH_BEAD_ID
        || derivation
            .get("derived_surface_count")
            .and_then(Value::as_u64)
            != Some(count_u64(candidate_paths.len(), "documentation surfaces"))
        || text(derivation, "derived_surface_id_path_tuple_sha256")
            != DOCUMENTATION_ACTUAL_SURFACE_TUPLE_SHA256
        || text(derivation, "semantic_state_for_noncanonical_occurrences") != "UNKNOWN"
        || !bool_field(
            derivation,
            "all_derived_surfaces_have_at_least_one_literal_occurrence",
        )
        || !bool_field(derivation, "migration_blocking")
        || !bool_field(derivation, "no_removal_authority")
        || text(derivation, "surface_id_path_source_pin_tuple_rule")
            != "actual surfaces use the exact joined source_pin_id; virtual surfaces use their explicit source_pin_digest_token"
    {
        return Err("documentation actual-surface derivation drifted".to_owned());
    }
    let virtual_surfaces = array(surfaces, "virtual_surfaces");
    if virtual_surfaces.len() != 1 {
        return Err("documentation census must have exactly one virtual surface".to_owned());
    }
    let virtual_surface = &virtual_surfaces[0];
    require_exact_keys(
        virtual_surface,
        &[
            "absence_anchor",
            "classification",
            "migration_blocking",
            "no_removal_authority",
            "occurrence_count",
            "occurrence_id_list_sha256",
            "owner_bead",
            "path",
            "refresh_owner_bead",
            "semantic_state",
            "source_pin_digest_token",
            "source_pin_id",
            "surface_id",
            "surface_kind",
        ],
        "documentation virtual surface",
    )?;
    if text(virtual_surface, "surface_id") != "KAFKA-K0-3-DOC-SURFACE-150"
        || text(virtual_surface, "path") != "examples/"
        || text(virtual_surface, "surface_kind") != "VIRTUAL_EXACT_BASELINE_ABSENCE"
        || text(virtual_surface, "classification") != "OWNED_VIRTUAL_EXAMPLES_ABSENCE"
        || virtual_surface.get("source_pin_id") != Some(&Value::Null)
        || text(virtual_surface, "absence_anchor")
            != "baseline revision + search_scope roots entry examples + search_scope matcher; no tracked candidate path or non-binary content occurrence"
        || text(virtual_surface, "source_pin_digest_token") != "EXACT_BASELINE_ABSENCE"
        || virtual_surface
            .get("occurrence_count")
            .and_then(Value::as_u64)
            != Some(0)
        || text(virtual_surface, "occurrence_id_list_sha256") != sha256_hex(b"")
        || text(virtual_surface, "owner_bead") != DOCUMENTATION_OWNER_BEAD_ID
        || text(virtual_surface, "refresh_owner_bead") != REFRESH_BEAD_ID
        || text(virtual_surface, "semantic_state") != "EXACT_LOCAL_ABSENCE_ONLY"
        || !bool_field(virtual_surface, "migration_blocking")
        || !bool_field(virtual_surface, "no_removal_authority")
    {
        return Err("documentation virtual absence surface drifted".to_owned());
    }
    surface_tuples.push("KAFKA-K0-3-DOC-SURFACE-150\texamples/".to_owned());
    source_pin_tuples
        .push("KAFKA-K0-3-DOC-SURFACE-150\texamples/\tEXACT_BASELINE_ABSENCE".to_owned());
    if newline_sha256(&surface_tuples) != DOCUMENTATION_SURFACE_TUPLE_SHA256
        || newline_sha256(&source_pin_tuples) != DOCUMENTATION_SOURCE_PIN_TUPLE_SHA256
    {
        return Err("documentation surface tuple serialization drifted".to_owned());
    }

    let groups = inventory
        .get("documentation_claim_occurrence_groups")
        .unwrap_or_else(|| panic!("documentation_claim_occurrence_groups must exist"));
    require_exact_keys(
        groups,
        &[
            "canonical_group_inheritance",
            "canonical_projection_groups",
            "derived_remainder_groups",
            "negative_fixture_invariants",
            "partition_contract",
            "representation",
        ],
        "documentation_claim_occurrence_groups",
    )?;
    let canonical_inheritance = groups
        .get("canonical_group_inheritance")
        .unwrap_or_else(|| panic!("canonical_group_inheritance must exist"));
    require_exact_keys(
        canonical_inheritance,
        &[
            "classification",
            "migration_blocking",
            "no_removal_authority",
            "owner_join_rule",
            "refresh_owner_bead",
            "semantic_state_join_rule",
        ],
        "documentation canonical group inheritance",
    )?;
    if text(canonical_inheritance, "classification") != "CANONICAL_DOCUMENTATION_CLAIM_PROJECTION"
        || text(canonical_inheritance, "owner_join_rule")
            != "documentation_claims row with matching claim_id supplies owner_bead"
        || text(canonical_inheritance, "semantic_state_join_rule")
            != "documentation_claims row with matching claim_id supplies freshness_state, claim_disposition, and evidence_class"
        || text(canonical_inheritance, "refresh_owner_bead") != REFRESH_BEAD_ID
        || !bool_field(canonical_inheritance, "migration_blocking")
        || !bool_field(canonical_inheritance, "no_removal_authority")
    {
        return Err("canonical documentation inheritance metadata drifted".to_owned());
    }
    let canonical_groups = array(groups, "canonical_projection_groups");
    let claims = array(inventory, "documentation_claims");
    let claims_by_id = claims
        .iter()
        .map(|claim| (text(claim, "claim_id"), claim))
        .collect::<BTreeMap<_, _>>();
    let mut canonical_ids = Vec::new();
    let mut canonical_id_set = BTreeSet::new();
    let mut canonical_group_ids = Vec::new();
    for (index, group) in canonical_groups.iter().enumerate() {
        let ordinal = index + 1;
        let group_id = format!("KAFKA-K0-3-DOC-OCC-GROUP-C{ordinal:03}");
        let claim_id = format!("KAFKA-K0-3-DOC-CLAIM-{ordinal:03}");
        if text(group, "group_id") != group_id
            || text(group, "claim_id") != claim_id
            || text(group, "selector_kind") != "EXPLICIT_OCCURRENCE_IDS"
        {
            return Err(format!("canonical documentation group {ordinal} drifted"));
        }
        let ids = string_vec(group, "occurrence_ids");
        if ids.is_empty()
            || ids.len() != ids.iter().collect::<BTreeSet<_>>().len()
            || group.get("occurrence_count").and_then(Value::as_u64)
                != Some(count_u64(ids.len(), "canonical occurrences"))
            || text(group, "occurrence_id_list_sha256") != newline_sha256(&ids)
        {
            return Err(format!("{group_id} occurrence receipt drifted"));
        }
        let claim = claims_by_id
            .get(claim_id.as_str())
            .ok_or_else(|| format!("{group_id} lacks its documentation claim"))?;
        if string_set(claim, "occurrence_group_ids") != BTreeSet::from([group_id.clone()]) {
            return Err(format!("{claim_id} canonical reverse join drifted"));
        }
        let claim_paths = string_set(claim, "paths");
        for id in ids {
            let path = occurrence_path
                .get(&id)
                .ok_or_else(|| format!("{group_id} references unknown occurrence {id}"))?;
            if !claim_paths.contains(path) || !canonical_id_set.insert(id.clone()) {
                return Err(format!(
                    "{group_id} occurrence path or disjointness drifted"
                ));
            }
            canonical_ids.push(id);
        }
        canonical_group_ids.push(group_id);
    }
    if canonical_groups.len() != DOCUMENTATION_CLAIM_COUNT
        || canonical_ids.len() != DOCUMENTATION_CANONICAL_OCCURRENCE_COUNT
        || newline_sha256(&canonical_ids) != DOCUMENTATION_CANONICAL_ID_SHA256
    {
        return Err("canonical documentation projection census drifted".to_owned());
    }

    let mut remainder_ids = Vec::new();
    let mut remainder_group_ids = Vec::new();
    let mut zero_remainder_surface_ids = BTreeSet::new();
    for surface_ordinal in 1..=DOCUMENTATION_ACTUAL_SURFACE_COUNT {
        let ids = occurrence_ids_by_surface
            .get(&surface_ordinal)
            .cloned()
            .unwrap_or_default();
        let remainder = ids
            .into_iter()
            .filter(|id| !canonical_id_set.contains(id))
            .collect::<Vec<_>>();
        if remainder.is_empty() {
            zero_remainder_surface_ids
                .insert(format!("KAFKA-K0-3-DOC-SURFACE-{surface_ordinal:03}"));
        } else {
            remainder_group_ids.push(format!("KAFKA-K0-3-DOC-OCC-GROUP-R{surface_ordinal:03}"));
            remainder_ids.extend(remainder);
        }
    }
    let derived = groups
        .get("derived_remainder_groups")
        .unwrap_or_else(|| panic!("derived_remainder_groups must exist"));
    require_exact_keys(
        derived,
        &[
            "classification",
            "derived_group_count",
            "derived_group_id_list_sha256",
            "evidence_class",
            "generation_domain",
            "group_id_rule",
            "member_rule",
            "migration_blocking",
            "no_removal_authority",
            "occurrence_count",
            "occurrence_id_list_sha256",
            "owner_bead",
            "refresh_owner_bead",
            "selector_kind",
            "semantic_state",
            "zero_remainder_surface_ids",
        ],
        "documentation derived remainder groups",
    )?;
    if text(derived, "selector_kind") != "SURFACE_SET_DIFFERENCE"
        || text(derived, "generation_domain")
            != "each actual surface whose occurrence set minus the union of all canonical explicit occurrence IDs is non-empty"
        || text(derived, "group_id_rule")
            != "KAFKA-K0-3-DOC-OCC-GROUP-R{same three-digit surface ordinal}"
        || text(derived, "member_rule")
            != "all occurrence IDs for that surface minus the union of canonical_projection_groups occurrence_ids, preserving baseline occurrence order"
        || string_set(derived, "zero_remainder_surface_ids") != zero_remainder_surface_ids
        || derived.get("derived_group_count").and_then(Value::as_u64)
            != Some(count_u64(remainder_group_ids.len(), "remainder groups"))
        || text(derived, "derived_group_id_list_sha256") != DOCUMENTATION_REMAINDER_GROUP_SHA256
        || derived.get("occurrence_count").and_then(Value::as_u64)
            != Some(count_u64(remainder_ids.len(), "remainder occurrences"))
        || text(derived, "occurrence_id_list_sha256") != DOCUMENTATION_REMAINDER_ID_SHA256
        || text(derived, "classification") != "OWNED_UNRESOLVED_CLAIM"
        || text(derived, "semantic_state") != "UNKNOWN"
        || text(derived, "evidence_class") != "NON_BROKER_STATIC_IDENTITY_ONLY"
        || derived.get("owner_bead").and_then(Value::as_str) != Some(DOCUMENTATION_OWNER_BEAD_ID)
        || derived.get("refresh_owner_bead").and_then(Value::as_str) != Some(REFRESH_BEAD_ID)
        || !bool_field(derived, "migration_blocking")
        || !bool_field(derived, "no_removal_authority")
        || remainder_ids.len() != DOCUMENTATION_REMAINDER_OCCURRENCE_COUNT
        || newline_sha256(&remainder_ids) != DOCUMENTATION_REMAINDER_ID_SHA256
        || newline_sha256(&remainder_group_ids) != DOCUMENTATION_REMAINDER_GROUP_SHA256
    {
        return Err("derived documentation remainder partition drifted".to_owned());
    }
    canonical_group_ids.extend(remainder_group_ids);
    if canonical_group_ids.len() != DOCUMENTATION_OCCURRENCE_GROUP_COUNT
        || newline_sha256(&canonical_group_ids) != DOCUMENTATION_GROUP_ID_SHA256
        || canonical_id_set.len() + remainder_ids.len() != occurrence_ids.len()
    {
        return Err("documentation canonical/remainder union drifted".to_owned());
    }

    let partition = groups
        .get("partition_contract")
        .unwrap_or_else(|| panic!("partition_contract must exist"));
    require_exact_keys(
        partition,
        &[
            "canonical_and_remainder_groups_are_pairwise_disjoint",
            "canonical_and_remainder_union_equals_all_literal_occurrences",
            "canonical_claim_reverse_join_is_bijective",
            "expected_group_count",
            "expected_group_id_list_sha256",
            "expected_union_occurrence_count",
            "expected_union_occurrence_id_list_sha256",
        ],
        "documentation occurrence partition contract",
    )?;
    if !bool_field(
        partition,
        "canonical_and_remainder_groups_are_pairwise_disjoint",
    ) || !bool_field(
        partition,
        "canonical_and_remainder_union_equals_all_literal_occurrences",
    ) || !bool_field(partition, "canonical_claim_reverse_join_is_bijective")
        || partition
            .get("expected_union_occurrence_count")
            .and_then(Value::as_u64)
            != Some(count_u64(
                occurrence_ids.len(),
                "documentation partition union",
            ))
        || text(partition, "expected_union_occurrence_id_list_sha256")
            != DOCUMENTATION_OCCURRENCE_ID_SHA256
        || partition
            .get("expected_group_count")
            .and_then(Value::as_u64)
            != Some(count_u64(
                canonical_group_ids.len(),
                "documentation partition groups",
            ))
        || text(partition, "expected_group_id_list_sha256") != DOCUMENTATION_GROUP_ID_SHA256
    {
        return Err("documentation occurrence partition receipt drifted".to_owned());
    }

    for (key, expected) in [
        (
            "actual_candidate_surface_count",
            DOCUMENTATION_ACTUAL_SURFACE_COUNT,
        ),
        ("virtual_surface_count", 1),
        ("total_surface_count", DOCUMENTATION_SURFACE_COUNT),
        ("literal_occurrence_count", occurrence_ids.len()),
        ("matching_line_count", line_tuples.len()),
        (
            "canonical_documentation_claim_count",
            canonical_groups.len(),
        ),
        (
            "canonical_projection_occurrence_count",
            canonical_id_set.len(),
        ),
        ("owned_unresolved_occurrence_count", remainder_ids.len()),
        ("occurrence_group_count", canonical_group_ids.len()),
        (
            "source_pin_count_for_actual_candidate_surfaces",
            candidate_paths.len(),
        ),
    ] {
        if scope.get(key).and_then(Value::as_u64) != Some(count_u64(expected, key)) {
            return Err(format!("documentation_claim_scope.{key} is not derived"));
        }
    }
    for (key, expected) in [
        (
            "actual_candidate_path_list_sha256",
            DOCUMENTATION_PATH_SHA256,
        ),
        (
            "surface_id_path_tuple_sha256",
            DOCUMENTATION_SURFACE_TUPLE_SHA256,
        ),
        (
            "surface_id_path_source_pin_tuple_sha256",
            DOCUMENTATION_SOURCE_PIN_TUPLE_SHA256,
        ),
        (
            "occurrence_locator_tuple_sha256",
            DOCUMENTATION_OCCURRENCE_TUPLE_SHA256,
        ),
        (
            "matching_line_locator_tuple_sha256",
            DOCUMENTATION_LINE_TUPLE_SHA256,
        ),
        (
            "occurrence_id_list_sha256",
            DOCUMENTATION_OCCURRENCE_ID_SHA256,
        ),
        (
            "canonical_projection_occurrence_id_list_sha256",
            DOCUMENTATION_CANONICAL_ID_SHA256,
        ),
        (
            "owned_unresolved_occurrence_id_list_sha256",
            DOCUMENTATION_REMAINDER_ID_SHA256,
        ),
        (
            "occurrence_group_id_list_sha256",
            DOCUMENTATION_GROUP_ID_SHA256,
        ),
    ] {
        if scope.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("documentation_claim_scope.{key} drifted"));
        }
    }
    if !bool_field(scope, "identity_and_ownership_census_complete")
        || !bool_field(scope, "occurrence_partition_complete")
        || bool_field(scope, "all_documentation_claims_semantically_resolved")
        || !bool_field(scope, "migration_blocking")
        || !bool_field(scope, "no_removal_authority")
        || text(scope, "source_pin_join_cardinality")
            != "exactly one source_pins row for every actual candidate path"
    {
        return Err("documentation claim completion boundary drifted".to_owned());
    }
    Ok(())
}

type TestDeclaration = (String, u64, String, Option<u64>);

fn literal_test_declarations(path: &str) -> Result<BTreeSet<TestDeclaration>, String> {
    let source = read_repo_file(path);
    let mut declarations = BTreeSet::new();
    let mut pending_test_attribute: Option<(&str, u64)> = None;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let attribute_kind = match trimmed {
            "#[test]" => Some("test"),
            "#[tokio::test]" => Some("tokio::test"),
            _ => None,
        };
        if let Some(attribute_kind) = attribute_kind {
            if pending_test_attribute.is_some() {
                return Err(format!("{path} has consecutive unresolved test attributes"));
            }
            pending_test_attribute = Some((
                attribute_kind,
                u64::try_from(index + 1)
                    .map_err(|error| format!("{path} attribute line overflow: {error}"))?,
            ));
            continue;
        }
        let Some((attribute_kind, attribute_line)) = pending_test_attribute else {
            continue;
        };
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("#[") && trimmed.ends_with(']') {
            continue;
        }
        let signature = line.trim_start();
        let prefixes: &[&str] = if attribute_kind == "tokio::test" {
            &["async fn ", "pub async fn "]
        } else {
            &["fn ", "pub fn "]
        };
        let Some(function_tail) = prefixes
            .iter()
            .copied()
            .find_map(|prefix| signature.strip_prefix(prefix))
        else {
            return Err(format!(
                "{path}:{} is the first nonempty non-attribute line after #[{attribute_kind}] but is not its required function signature",
                index + 1
            ));
        };
        let name = function_tail
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        if name.is_empty() || !function_tail[name.len()..].trim_start().starts_with('(') {
            return Err(format!(
                "{path}:{} has an unnamed test or lacks an opening parenthesis",
                index + 1
            ));
        }
        let line_number = u64::try_from(index + 1)
            .map_err(|error| format!("{path} test line overflow: {error}"))?;
        let explicit_attribute_line = (attribute_kind == "tokio::test").then_some(attribute_line);
        if !declarations.insert((
            name.clone(),
            line_number,
            attribute_kind.to_owned(),
            explicit_attribute_line,
        )) {
            return Err(format!("{path}:{line_number} duplicates test {name}"));
        }
        pending_test_attribute = None;
    }
    if pending_test_attribute.is_some() {
        return Err(format!("{path} ends with an unresolved test attribute"));
    }
    Ok(declarations)
}

fn source_anchor_line(case: &Value) -> Result<u64, String> {
    let case_id = text(case, "case_id");
    text(case, "source_anchor")
        .strip_prefix("line ")
        .ok_or_else(|| format!("{case_id} source anchor must be `line N`"))?
        .parse::<u64>()
        .map_err(|error| format!("{case_id} source anchor line is invalid: {error}"))
}

fn validate_test_declaration_groups(inventory: &Value) -> Result<(), String> {
    let declaration_scope = inventory
        .get("test_declaration_scope")
        .unwrap_or_else(|| panic!("test_declaration_scope must exist"));
    require_exact_keys(
        declaration_scope,
        &[
            "baseline_revision",
            "exact_test_declaration_count",
            "exact_test_scanner",
            "exact_tokio_test_declaration_count",
            "exact_tokio_test_scanner",
            "included_attribute_kinds",
            "row_line_rule",
            "scope_id",
            "source_pin_join_rule",
            "tokio_test_declaration_tuple",
            "tokio_test_declaration_tuple_sha256",
            "total_test_declaration_count",
        ],
        "test_declaration_scope",
    )?;
    if text(declaration_scope, "scope_id") != "KAFKA-K0-3-TEST-DECLARATION-CENSUS-001"
        || text(declaration_scope, "baseline_revision") != BASELINE_REVISION
        || string_set(declaration_scope, "included_attribute_kinds")
            != expected_set(&["test", "tokio::test"])
        || text(declaration_scope, "tokio_test_declaration_tuple_sha256")
            != TOKIO_TEST_DECLARATION_TUPLE_SHA256
        || text(declaration_scope, "exact_test_scanner")
            != "trimmed line equals #[test], then allow only blank lines or zero or more non-test Rust attribute lines whose trimmed form begins #[ and ends ]; bind the first other nonempty line matching optional pub plus fn NAME with an opening parenthesis; consecutive test attributes, other intervening lines, unresolved bindings, and EOF fail closed"
        || text(declaration_scope, "exact_tokio_test_scanner")
            != "trimmed line equals #[tokio::test], then allow only blank lines or zero or more non-test Rust attribute lines whose trimmed form begins #[ and ends ]; bind the first other nonempty line matching optional pub plus async fn NAME with an opening parenthesis; consecutive test attributes, other intervening lines, unresolved bindings, and EOF fail closed"
        || text(declaration_scope, "row_line_rule")
            != "every declaration row line is the exact function-signature line; tokio::test rows additionally carry attribute_kind and attribute_line for the canonical alternate-attribute receipt"
        || text(declaration_scope, "source_pin_join_rule")
            != "every declaration group joins exactly one listed test_declaration_scope_pin_ids source pin by exact path"
        || text(declaration_scope, "tokio_test_declaration_tuple")
            != "path<TAB>attribute-line<TAB>tokio::test<TAB>function-name, UTF-8 lexicographically sorted and LF-terminated"
    {
        return Err("test declaration scope identity or grammar drifted".to_owned());
    }
    let pins = pin_paths(inventory);
    let scope_pin_ids = string_set(inventory, "test_declaration_scope_pin_ids");
    let groups = array(inventory, "test_declaration_groups");
    let group_pin_ids = groups
        .iter()
        .map(|group| text(group, "source_pin_id").to_owned())
        .collect::<BTreeSet<_>>();
    let group_paths = groups
        .iter()
        .map(|group| text(group, "path").to_owned())
        .collect::<BTreeSet<_>>();
    let group_path_pins = groups
        .iter()
        .map(|group| format!("{}\t{}", text(group, "path"), text(group, "source_pin_id")))
        .collect::<BTreeSet<_>>();
    if groups.len() != TEST_DECLARATION_GROUP_COUNT
        || scope_pin_ids.len() != TEST_DECLARATION_GROUP_COUNT
        || group_pin_ids != scope_pin_ids
        || group_paths.len() != groups.len()
        || sorted_newline_sha256(&group_paths) != TEST_DECLARATION_GROUP_PATH_SHA256
        || sorted_newline_sha256(&group_path_pins) != TEST_DECLARATION_GROUP_PATH_PIN_SHA256
    {
        return Err("test declaration scope/group set drifted".to_owned());
    }

    let mut declared_count = 0_usize;
    let mut atomic_test_ids = BTreeSet::new();
    let mut exact_test_count = 0_usize;
    let mut tokio_test_count = 0_usize;
    let mut tokio_tuples = BTreeSet::new();
    let mut declarations_by_path = BTreeMap::<String, BTreeSet<TestDeclaration>>::new();
    for group in groups {
        let path = text(group, "path");
        require_exact_keys(
            group,
            &[
                "owner_bead",
                "path",
                "refresh_owner_bead",
                "source_pin_id",
                "tests",
            ],
            path,
        )?;
        let pin_id = text(group, "source_pin_id");
        if pins.get(pin_id).map(String::as_str) != Some(path) {
            return Err(format!(
                "test declaration group {path} does not match {pin_id}"
            ));
        }
        require_owner(group, path)?;
        if text(group, "refresh_owner_bead") != REFRESH_BEAD_ID {
            return Err(format!(
                "test declaration group {path} lost its refresh owner"
            ));
        }
        let mut declared = BTreeSet::new();
        for test in array(group, "tests") {
            let attribute_kind = test
                .get("attribute_kind")
                .and_then(Value::as_str)
                .unwrap_or("test");
            let expected_keys: &[&str] = if attribute_kind == "tokio::test" {
                &["attribute_kind", "attribute_line", "line", "name"]
            } else {
                &["line", "name"]
            };
            require_exact_keys(test, expected_keys, "test declaration")?;
            let name = text(test, "name");
            let line = test
                .get("line")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{path}::{name} line must be an integer"));
            let attribute_line = if attribute_kind == "tokio::test" {
                tokio_test_count += 1;
                let attribute_line = test
                    .get("attribute_line")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("{path}::{name} lacks its attribute line"))?;
                tokio_tuples.insert(format!("{path}\t{attribute_line}\ttokio::test\t{name}"));
                Some(attribute_line)
            } else if attribute_kind == "test" {
                exact_test_count += 1;
                None
            } else {
                return Err(format!("{path}::{name} has an unsupported test attribute"));
            };
            if name.is_empty()
                || !declared.insert((
                    name.to_owned(),
                    line,
                    attribute_kind.to_owned(),
                    attribute_line,
                ))
            {
                return Err(format!("{path} has a duplicate or empty test declaration"));
            }
            if !atomic_test_ids.insert(format!("{path}::{name}")) {
                return Err(format!(
                    "duplicate stable test declaration ID {path}::{name}"
                ));
            }
        }
        let live = literal_test_declarations(path)?;
        if declared != live {
            return Err(format!("{path} literal #[test] declaration set drifted"));
        }
        declared_count += declared.len();
        declarations_by_path.insert(path.to_owned(), declared);
    }
    if declared_count != TEST_DECLARATION_COUNT
        || atomic_test_ids.len() != TEST_DECLARATION_COUNT
        || exact_test_count != EXACT_TEST_DECLARATION_COUNT
        || tokio_test_count != TOKIO_TEST_DECLARATION_COUNT
        || sorted_newline_sha256(&tokio_tuples) != TOKIO_TEST_DECLARATION_TUPLE_SHA256
        || declaration_scope
            .get("exact_test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(exact_test_count, "exact test declarations"))
        || declaration_scope
            .get("exact_tokio_test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(tokio_test_count, "tokio test declarations"))
        || declaration_scope
            .get("total_test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(declared_count, "test declarations"))
    {
        return Err("test declaration count or stable ID set drifted".to_owned());
    }

    // Derive the test-bearing subset independently from the declared call-site
    // census. This prevents a test group, its pin, and its classification from
    // being deleted together while leaving the three declared arrays mutually
    // self-consistent.
    let source_relevant_resolutions = expected_set(&[
        "RESOLVED_CURRENT_K0",
        "RESOLVED_STALE_UNWIRED_K0",
        "UNRESOLVED_STALE_SURFACE",
    ]);
    let mut source_required_test_paths = BTreeSet::new();
    for call_group in array(inventory, "call_site_groups") {
        let has_relevant_candidate = array(call_group, "atomic_sites")
            .iter()
            .any(|site| source_relevant_resolutions.contains(text(site, "resolution_state")));
        if has_relevant_candidate {
            let path = text(call_group, "path");
            if !literal_test_declarations(path)?.is_empty() {
                source_required_test_paths.insert(path.to_owned());
            }
        }
    }
    if source_required_test_paths.len() != 20 || !source_required_test_paths.is_subset(&group_paths)
    {
        return Err(
            "every test-bearing resolved or unresolved call-site path must be declared".to_owned(),
        );
    }

    let mut classified_test_ids = BTreeSet::new();
    for case in array(inventory, "atomic_test_cases") {
        let case_id = text(case, "case_id");
        let expected_name = text(case, "test_name");
        let expected_line = source_anchor_line(case)?;
        if !classified_test_ids.insert(format!(
            "{}::{}",
            text(case, "path"),
            text(case, "test_name")
        )) {
            return Err(format!(
                "{case_id} duplicates an atomic test classification"
            ));
        }
        if !declarations_by_path
            .get(text(case, "path"))
            .is_some_and(|declarations| {
                declarations
                    .iter()
                    .any(|(name, line, _, _)| name == expected_name && *line == expected_line)
            })
        {
            return Err(format!(
                "{case_id} does not anchor an exact test declaration"
            ));
        }
    }
    Ok(())
}

fn validate_test_declaration_group_classifications(inventory: &Value) -> Result<(), String> {
    let groups = array(inventory, "test_declaration_groups");
    let group_keys = groups
        .iter()
        .map(|group| {
            (
                text(group, "path").to_owned(),
                text(group, "source_pin_id").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let classifications = array(inventory, "test_declaration_group_classifications");
    let classification_keys = classifications
        .iter()
        .map(|row| {
            (
                text(row, "path").to_owned(),
                text(row, "source_pin_id").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    if classifications.len() != TEST_DECLARATION_GROUP_COUNT
        || classification_keys.len() != classifications.len()
        || classification_keys != group_keys
    {
        return Err("test declaration classifications must join 1:1 by path and pin".to_owned());
    }

    let taxonomies = inventory
        .get("taxonomies")
        .unwrap_or_else(|| panic!("taxonomies must exist"));
    let dispositions = string_set(taxonomies, "claim_disposition");
    let evidence_classes = string_set(taxonomies, "evidence_class");
    let execution_states = string_set(taxonomies, "execution_state");
    let wiring_states = string_set(taxonomies, "wiring_state");
    let freshness_states = string_set(taxonomies, "freshness_state");
    let atomic_cases = array(inventory, "atomic_test_cases");
    let atomic_case_ids = row_ids(atomic_cases, "case_id");
    let mut classified_atomic_cases = BTreeSet::new();
    for row in classifications {
        let path = text(row, "path");
        require_exact_keys(
            row,
            &[
                "atomic_case_ids",
                "execution_state",
                "freshness_state",
                "inherited_disposition",
                "inherited_evidence_class",
                "owner_bead",
                "path",
                "refresh_owner_bead",
                "source_pin_id",
                "wiring_state",
            ],
            path,
        )?;
        require_owner(row, path)?;
        if text(row, "refresh_owner_bead") != REFRESH_BEAD_ID
            || !dispositions.contains(text(row, "inherited_disposition"))
            || !evidence_classes.contains(text(row, "inherited_evidence_class"))
            || !execution_states.contains(text(row, "execution_state"))
            || !wiring_states.contains(text(row, "wiring_state"))
            || !freshness_states.contains(text(row, "freshness_state"))
        {
            return Err(format!("{path} inherited classification or owner drifted"));
        }
        if text(row, "execution_state") != "NOT_RUN"
            || text(row, "inherited_evidence_class") == "REAL_BROKER_RECEIPT"
        {
            return Err(format!(
                "{path} declaration classification cannot claim test execution or a receipt"
            ));
        }
        if (text(row, "inherited_disposition") == "CURRENT"
            && text(row, "freshness_state") != "CURRENT_SOURCE_PINNED")
            || (text(row, "inherited_disposition") == "STALE"
                && text(row, "freshness_state") != "STALE")
            || (text(row, "inherited_disposition") == "HISTORICAL"
                && text(row, "freshness_state") != "HISTORICAL")
        {
            return Err(format!("{path} default disposition and freshness disagree"));
        }

        let overrides = string_set(row, "atomic_case_ids");
        if overrides.len() != array(row, "atomic_case_ids").len()
            || !overrides.is_subset(&atomic_case_ids)
        {
            return Err(format!(
                "{path} atomic overrides must be unique known cases"
            ));
        }
        let expected_overrides = atomic_cases
            .iter()
            .filter(|case| text(case, "path") == path)
            .map(|case| text(case, "case_id").to_owned())
            .collect::<BTreeSet<_>>();
        if overrides != expected_overrides {
            return Err(format!(
                "{path} atomic overrides do not match same-path cases"
            ));
        }
        for case_id in overrides {
            if classified_atomic_cases.contains(&case_id) {
                return Err(format!(
                    "atomic override {case_id} is classified more than once"
                ));
            }
            classified_atomic_cases.insert(case_id);
        }
    }
    if classified_atomic_cases != atomic_case_ids {
        return Err("every atomic case must override exactly one declaration group".to_owned());
    }
    Ok(())
}

fn byte_line_column(bytes: &[u8], offset: usize) -> Result<(u64, u64), String> {
    if offset > bytes.len() {
        return Err(format!(
            "source byte offset {offset} exceeds file length {}",
            bytes.len()
        ));
    }
    let prefix = &bytes[..offset];
    let line = memchr::memchr_iter(b'\n', prefix).count() + 1;
    let column = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(offset + 1, |newline| offset - newline);
    Ok((
        count_u64(line, "source line"),
        count_u64(column, "source column"),
    ))
}

fn parse_usize_field(raw: &str, label: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|error| format!("{label} is not a positive integer: {error}"))
}

fn call_site_kind_code(kind: &str) -> Option<&'static str> {
    match kind {
        "ASSOCIATED_CALL" => Some("AC"),
        "INSTANCE_METHOD_CALL" => Some("IM"),
        "TRAIT_METHOD_PROJECTION" => Some("TP"),
        "CONTEXT_INFERRED_DEFAULT_CALL" => Some("CD"),
        "STRUCT_LITERAL_CONSTRUCTION" => Some("SL"),
        "FREE_FUNCTION_CALL" => Some("FF"),
        _ => None,
    }
}

fn validate_call_site_locator(
    site: &Value,
    group_ordinal: usize,
    path: &str,
    source: &[u8],
) -> Result<(), String> {
    let site_id = text(site, "site_id");
    let kind = text(site, "site_kind");
    let kind_code = call_site_kind_code(kind)
        .ok_or_else(|| format!("{site_id} uses unknown site kind {kind}"))?;
    let locator = text(site, "source_locator");
    let literal = text(site, "source_literal");
    if literal.is_empty() {
        return Err(format!("{site_id} must retain a source literal"));
    }

    if let Some(rest) = locator.strip_prefix("bytes ") {
        if matches!(
            kind,
            "TRAIT_METHOD_PROJECTION" | "CONTEXT_INFERRED_DEFAULT_CALL"
        ) {
            return Err(format!(
                "{site_id} trait projection must use a line/ordinal locator"
            ));
        }
        let (byte_range, line_range) = rest
            .split_once("; line ")
            .ok_or_else(|| format!("{site_id} byte locator is malformed"))?;
        let (start, end) = byte_range
            .split_once("..")
            .ok_or_else(|| format!("{site_id} byte range is malformed"))?;
        let start = parse_usize_field(start, &format!("{site_id} start byte"))?;
        let end = parse_usize_field(end, &format!("{site_id} end byte"))?;
        let (start_position, end_position) = line_range
            .split_once('-')
            .ok_or_else(|| format!("{site_id} line range is malformed"))?;
        let (start_line, start_column) = start_position
            .split_once(':')
            .ok_or_else(|| format!("{site_id} start position is malformed"))?;
        let (end_line, end_column) = end_position
            .split_once(':')
            .ok_or_else(|| format!("{site_id} end position is malformed"))?;
        let start_line = parse_usize_field(start_line, &format!("{site_id} start line"))?;
        let start_column = parse_usize_field(start_column, &format!("{site_id} start column"))?;
        let end_line = parse_usize_field(end_line, &format!("{site_id} end line"))?;
        let end_column = parse_usize_field(end_column, &format!("{site_id} end column"))?;
        if start >= end || end > source.len() {
            return Err(format!("{site_id} byte range is outside {path}"));
        }
        let actual_start = byte_line_column(source, start)?;
        let actual_end = byte_line_column(source, end)?;
        if actual_start
            != (
                count_u64(start_line, "call-site start line"),
                count_u64(start_column, "call-site start column"),
            )
            || actual_end
                != (
                    count_u64(end_line, "call-site end line"),
                    count_u64(end_column, "call-site end column"),
                )
            || locator
                != format!(
                    "bytes {start}..{end}; line {start_line}:{start_column}-{end_line}:{end_column}"
                )
        {
            return Err(format!("{site_id} byte and line-column locators disagree"));
        }
        let token = std::str::from_utf8(&source[start..end])
            .map_err(|error| format!("{site_id} token is not UTF-8: {error}"))?;
        let expected_literal = match kind {
            "ASSOCIATED_CALL" | "FREE_FUNCTION_CALL" => format!("{token}()"),
            "INSTANCE_METHOD_CALL" => format!(".{token}()"),
            "STRUCT_LITERAL_CONSTRUCTION" => format!("{token} {{...}}"),
            _ => return Err(format!("{site_id} cannot use a byte locator")),
        };
        let expected_id = format!("KAFKA-K0-3-CS-{group_ordinal:03}-{kind_code}-B{start}-E{end}");
        if literal != expected_literal || site_id != expected_id {
            return Err(format!(
                "{site_id} byte locator, stable ID, or source literal drifted"
            ));
        }
        return Ok(());
    }

    let rest = locator
        .strip_prefix("line ")
        .ok_or_else(|| format!("{site_id} locator has an unknown form"))?;
    let (line, rest) = rest
        .split_once("; callee ")
        .ok_or_else(|| format!("{site_id} line locator is malformed"))?;
    let (callee, occurrence) = rest
        .split_once("; same-line occurrence ")
        .ok_or_else(|| format!("{site_id} line occurrence locator is malformed"))?;
    let line = parse_usize_field(line, &format!("{site_id} line"))?;
    let occurrence = parse_usize_field(occurrence, &format!("{site_id} occurrence"))?;
    if line == 0 || occurrence == 0 || call_site_kind_code(kind).is_none() {
        return Err(format!(
            "{site_id} line/ordinal locator has an invalid domain"
        ));
    }
    if literal != callee
        || locator != format!("line {line}; callee {callee}; same-line occurrence {occurrence}")
    {
        return Err(format!("{site_id} line locator and literal disagree"));
    }
    let source =
        std::str::from_utf8(source).map_err(|error| format!("{path} is not UTF-8: {error}"))?;
    let source_line = source
        .lines()
        .nth(line - 1)
        .ok_or_else(|| format!("{site_id} line {line} is outside {path}"))?;
    let source_token = if kind == "STRUCT_LITERAL_CONSTRUCTION" {
        callee
            .strip_suffix(" {...}")
            .ok_or_else(|| format!("{site_id} struct locator must end in ` {{...}}`"))?
    } else {
        callee
            .strip_suffix("()")
            .ok_or_else(|| format!("{site_id} line locator callee must end in ()"))?
    };
    if source_line.match_indices(source_token).count() < occurrence {
        return Err(format!(
            "{site_id} line {line} lacks same-line occurrence {occurrence} of {source_token}"
        ));
    }
    let stable_callee = match kind {
        "INSTANCE_METHOD_CALL" => source_token
            .strip_prefix('.')
            .filter(|value| {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
            })
            .map(str::to_owned),
        "TRAIT_METHOD_PROJECTION" if source_token.starts_with('.') => {
            source_token.strip_prefix('.').map(str::to_owned)
        }
        "TRAIT_METHOD_PROJECTION" | "ASSOCIATED_CALL" => Some(source_token.replace("::", "_")),
        "FREE_FUNCTION_CALL" | "STRUCT_LITERAL_CONSTRUCTION" => source_token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
            .then(|| source_token.to_owned())
            .filter(|value| !value.is_empty()),
        "CONTEXT_INFERRED_DEFAULT_CALL" if source_token == "Default::default" => {
            Some("Default_default".to_owned())
        }
        _ => None,
    }
    .ok_or_else(|| format!("{site_id} line locator callee is not canonical"))?;
    let expected_id = format!(
        "KAFKA-K0-3-CS-{group_ordinal:03}-{kind_code}-L{line:04}-M{stable_callee}-O{occurrence:02}"
    );
    if site_id != expected_id {
        return Err(format!("{site_id} line/ordinal stable ID drifted"));
    }
    Ok(())
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn call_token_positions(line: &str, token: &str, require_identifier_boundary: bool) -> Vec<usize> {
    let bytes = line.as_bytes();
    line.match_indices(token)
        .filter_map(|(start, _)| {
            let end = start + token.len();
            if require_identifier_boundary
                && ((start != 0 && is_identifier_byte(bytes[start - 1]))
                    || (end < bytes.len() && is_identifier_byte(bytes[end])))
            {
                return None;
            }
            let mut suffix = end;
            while suffix < bytes.len() && bytes[suffix].is_ascii_whitespace() {
                suffix += 1;
            }
            (suffix < bytes.len() && bytes[suffix] == b'(').then_some(start)
        })
        .collect()
}

fn provider_candidate_tuples(
    receipt: &Value,
) -> Result<(BTreeSet<String>, BTreeMap<String, usize>), String> {
    let type_tokens = string_vec(receipt, "type_tokens");
    let public_methods = string_vec(receipt, "public_method_tokens");
    let trait_methods = string_vec(receipt, "trait_projection_tokens");
    let helper_tokens = string_vec(receipt, "free_function_tokens");
    let ufcs_token = text(receipt, "ufcs_trait_token");
    let mut tuples = BTreeSet::new();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    for region in array(receipt, "regions") {
        let path = text(region, "path");
        let first_line = region
            .get("first_line")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{path} provider region lacks first_line"))?;
        let last_line = region
            .get("last_line")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{path} provider region lacks last_line"))?;
        let first_line = usize::try_from(first_line)
            .map_err(|error| format!("{path} first_line overflow: {error}"))?;
        let last_line = usize::try_from(last_line)
            .map_err(|error| format!("{path} last_line overflow: {error}"))?;
        let lines = read_repo_file(path)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if first_line == 0 || last_line < first_line || last_line > lines.len() {
            return Err(format!("{path} provider region is outside the source"));
        }
        let before = tuples.len();
        for line_number in first_line..=last_line {
            let line = &lines[line_number - 1];
            let bytes = line.as_bytes();
            let mut emit = |kind: &str, token: String, count: usize| {
                for ordinal in 1..=count {
                    tuples.insert(format!("{kind}\t{path}\t{line_number}\t{token}\t{ordinal}"));
                    *kind_counts.entry(kind.to_owned()).or_default() += 1;
                }
            };

            for type_token in &type_tokens {
                let prefix = format!("{type_token}::");
                let mut tokens = BTreeMap::<String, usize>::new();
                for (start, _) in line.match_indices(&prefix) {
                    if start != 0 && is_identifier_byte(bytes[start - 1]) {
                        continue;
                    }
                    let identifier_start = start + prefix.len();
                    let mut identifier_end = identifier_start;
                    while identifier_end < bytes.len() && is_identifier_byte(bytes[identifier_end])
                    {
                        identifier_end += 1;
                    }
                    if identifier_end == identifier_start {
                        continue;
                    }
                    let mut suffix = identifier_end;
                    while suffix < bytes.len() && bytes[suffix].is_ascii_whitespace() {
                        suffix += 1;
                    }
                    if suffix < bytes.len() && bytes[suffix] == b'(' {
                        let token =
                            format!("{type_token}::{}", &line[identifier_start..identifier_end]);
                        *tokens.entry(token).or_default() += 1;
                    }
                }
                for (token, count) in tokens {
                    emit("ASSOCIATED_CANDIDATE", token, count);
                }
            }
            for method in &public_methods {
                let token = format!(".{method}");
                emit(
                    "INSTANCE_PUBLIC_METHOD_CANDIDATE",
                    token.clone(),
                    call_token_positions(line, &token, false).len(),
                );
            }
            for method in &trait_methods {
                let token = format!(".{method}");
                emit(
                    "TRAIT_PROJECTION_CANDIDATE",
                    token.clone(),
                    call_token_positions(line, &token, false).len(),
                );
            }
            for type_token in &type_tokens {
                let positions = line
                    .match_indices(type_token)
                    .filter(|(start, _)| {
                        let end = start + type_token.len();
                        if (*start != 0 && is_identifier_byte(bytes[*start - 1]))
                            || (end < bytes.len() && is_identifier_byte(bytes[end]))
                        {
                            return false;
                        }
                        let mut suffix = end;
                        while suffix < bytes.len() && bytes[suffix].is_ascii_whitespace() {
                            suffix += 1;
                        }
                        if suffix >= bytes.len() || bytes[suffix] != b'{' {
                            return false;
                        }
                        !line[..*start].trim_end().ends_with("->")
                    })
                    .count();
                emit("STRUCT_LITERAL_CONSTRUCTION", type_token.clone(), positions);
            }
            emit(
                "INFERRED_DEFAULT_CALL",
                "Default::default".to_owned(),
                call_token_positions(line, "Default::default", true).len(),
            );
            for helper in &helper_tokens {
                emit(
                    "FREE_FUNCTION_CALL",
                    helper.clone(),
                    call_token_positions(line, helper, true).len(),
                );
            }
            emit(
                "TRAIT_METHOD_PROJECTION",
                ufcs_token.to_owned(),
                call_token_positions(line, ufcs_token, true).len(),
            );
        }
        let count = tuples.len() - before;
        if region.get("candidate_count").and_then(Value::as_u64)
            != Some(count_u64(count, "provider candidates"))
        {
            return Err(format!("{path} provider candidate count drifted"));
        }
    }
    Ok((tuples, kind_counts))
}

fn validate_downstream_helper_receipt(inventory: &Value, receipt: &Value) -> Result<(), String> {
    require_exact_keys(
        receipt,
        &[
            "call_count",
            "helper_tokens",
            "provider_paths_excluded",
            "tuple_rule",
            "tuple_sha256",
        ],
        "downstream_helper_call_receipt",
    )?;
    let helper_tokens = string_vec(receipt, "helper_tokens");
    if helper_tokens.iter().cloned().collect::<BTreeSet<_>>()
        != expected_set(&[
            "fuzz_parse_delivery_result",
            "fuzz_parse_kafka_error_response",
            "fuzz_parse_response_metadata",
            "fuzz_validate_response_frame",
        ])
        || string_set(receipt, "provider_paths_excluded")
            != expected_set(&["src/messaging/kafka.rs", "src/messaging/kafka_consumer.rs"])
    {
        return Err("downstream helper scanner token scope drifted".to_owned());
    }
    let excluded = string_set(receipt, "provider_paths_excluded");
    let paths = string_set(
        inventory
            .get("search_scope")
            .unwrap_or_else(|| panic!("search_scope must exist")),
        "baseline_occurrence_paths",
    )
    .into_iter()
    .filter(|path| {
        Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            && !excluded.contains(path)
    })
    .collect::<BTreeSet<_>>();
    let mut tuples = BTreeSet::new();
    for path in paths {
        for (line_index, line) in read_repo_file(&path).lines().enumerate() {
            let line_number = line_index + 1;
            for helper in &helper_tokens {
                let count = call_token_positions(line, helper, true).len();
                for ordinal in 1..=count {
                    tuples.insert(format!("{path}\t{line_number}\t{helper}\t{ordinal}"));
                }
            }
        }
    }
    if tuples.len() != 35
        || sorted_newline_sha256(&tuples) != DOWNSTREAM_HELPER_TUPLE_SHA256
        || receipt.get("call_count").and_then(Value::as_u64) != Some(35)
        || text(receipt, "tuple_sha256") != DOWNSTREAM_HELPER_TUPLE_SHA256
        || text(receipt, "tuple_rule")
            != "path<TAB>line<TAB>callee<TAB>same-line-ordinal, UTF-8 lexicographically sorted and LF-terminated"
    {
        return Err("downstream response-helper source census drifted".to_owned());
    }
    Ok(())
}

fn provider_site_candidate_tuple(site: &Value, path: &str) -> Result<String, String> {
    let site_id = text(site, "site_id");
    let rest = text(site, "source_locator")
        .strip_prefix("line ")
        .ok_or_else(|| format!("{site_id} provider locator must be line-based"))?;
    let (line, rest) = rest
        .split_once("; callee ")
        .ok_or_else(|| format!("{site_id} provider locator lacks a callee"))?;
    let (callee, ordinal) = rest
        .split_once("; same-line occurrence ")
        .ok_or_else(|| format!("{site_id} provider locator lacks an ordinal"))?;
    let line = parse_usize_field(line, &format!("{site_id} line"))?;
    let ordinal = parse_usize_field(ordinal, &format!("{site_id} ordinal"))?;
    let (candidate_kind, token) = match text(site, "site_kind") {
        "ASSOCIATED_CALL" => (
            "ASSOCIATED_CANDIDATE",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} associated callee drifted"))?,
        ),
        "INSTANCE_METHOD_CALL" => (
            "INSTANCE_PUBLIC_METHOD_CANDIDATE",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} instance callee drifted"))?,
        ),
        "TRAIT_METHOD_PROJECTION" if callee.starts_with('.') => (
            "TRAIT_PROJECTION_CANDIDATE",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} trait callee drifted"))?,
        ),
        "TRAIT_METHOD_PROJECTION" => (
            "TRAIT_METHOD_PROJECTION",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} UFCS callee drifted"))?,
        ),
        "STRUCT_LITERAL_CONSTRUCTION" => (
            "STRUCT_LITERAL_CONSTRUCTION",
            callee
                .strip_suffix(" {...}")
                .ok_or_else(|| format!("{site_id} struct callee drifted"))?,
        ),
        "CONTEXT_INFERRED_DEFAULT_CALL" => (
            "INFERRED_DEFAULT_CALL",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} default callee drifted"))?,
        ),
        "FREE_FUNCTION_CALL" => (
            "FREE_FUNCTION_CALL",
            callee
                .strip_suffix("()")
                .ok_or_else(|| format!("{site_id} helper callee drifted"))?,
        ),
        kind => return Err(format!("{site_id} has unsupported provider kind {kind}")),
    };
    Ok(format!(
        "{candidate_kind}\t{path}\t{line}\t{token}\t{ordinal}"
    ))
}

fn validate_call_site_scope_and_groups(inventory: &Value) -> Result<(), String> {
    let scope_value = inventory
        .get("call_site_scope")
        .unwrap_or_else(|| panic!("call_site_scope must exist"));
    require_exact_keys(
        scope_value,
        &[
            "associated_matcher",
            "baseline_revision",
            "binding_resolution_rule",
            "call_site_id_set_sha256",
            "call_site_path_set_sha256",
            "candidate_identity_rule",
            "context_inferred_default_matcher",
            "default_scope",
            "derived_counts",
            "digest_algorithm",
            "downstream_helper_call_receipt",
            "enum_and_struct_scope",
            "free_function_matcher",
            "generated_or_self_reference_exclusions",
            "group_dispositions",
            "included_site_kinds",
            "instance_candidate_matcher",
            "language",
            "locator_rule",
            "partition_rule",
            "provider_declaration_exclusions",
            "provider_test_candidate_receipt",
            "raw_counts",
            "resolution_states",
            "scope_id",
            "site_id_rule",
            "struct_matcher",
        ],
        "call_site_scope",
    )?;
    if text(scope_value, "scope_id") != "KAFKA-K0-3-CALL-SITE-SCOPE-001"
        || text(scope_value, "baseline_revision") != BASELINE_REVISION
        || text(scope_value, "language") != "Rust"
        || text(scope_value, "digest_algorithm")
            != "SHA-256 of UTF-8 lexicographically sorted values joined by LF with one trailing LF"
    {
        return Err("call-site scope identity or digest algorithm drifted".to_owned());
    }
    for (key, expected) in [
        (
            "generated_or_self_reference_exclusions",
            expected_set(&[
                ARTIFACT_PATH,
                "tests/kafka_downstream_user_journey_inventory_contract.rs",
                DOC_PATH,
            ]),
        ),
        (
            "included_site_kinds",
            expected_set(&[
                "ASSOCIATED_CALL",
                "INSTANCE_METHOD_CALL",
                "TRAIT_METHOD_PROJECTION",
                "CONTEXT_INFERRED_DEFAULT_CALL",
                "STRUCT_LITERAL_CONSTRUCTION",
                "FREE_FUNCTION_CALL",
            ]),
        ),
        (
            "resolution_states",
            expected_set(&[
                "RESOLVED_CURRENT_K0",
                "RESOLVED_STALE_UNWIRED_K0",
                "EXCLUDED_NAME_COLLISION",
                "UNRESOLVED_STALE_SURFACE",
                "EXCLUDED_PATTERN_ONLY",
                "EXCLUDED_COMMENT_OR_STRING",
            ]),
        ),
        (
            "group_dispositions",
            expected_set(&[
                "CONFIRMED_CURRENT_K0_CALLS",
                "CONFIRMED_STALE_UNWIRED_K0_CALLS",
                "EXCLUDED_NAME_COLLISIONS",
                "UNRESOLVED_STALE_SURFACE",
                "EXCLUDED_PATTERN_ONLY",
                "EXCLUDED_COMMENT_OR_STRING",
                "MIXED_CALL_SITE_DISPOSITIONS",
            ]),
        ),
    ] {
        let actual = string_set(scope_value, key);
        if actual != expected || array(scope_value, key).len() != expected.len() {
            return Err(format!("call_site_scope.{key} drifted"));
        }
    }
    for (key, expected) in [
        (
            "associated_matcher",
            "Rust call-shaped expressions whose associated type token exactly matches a pinned K0.1 declaration or facade export; provider-region lexical overmatches are retained and dispositioned",
        ),
        (
            "instance_candidate_matcher",
            "Rust method-call expressions on the import-resolved or stale-candidate downstream paths whose method token matches a declared K0.1/K0.2 method, plus the exact provider-test-region public-method token scanner",
        ),
        (
            "binding_resolution_rule",
            "the independent binding-resolved downstream set overrides exact path+line+callee+same-line-ordinal lexical candidates; every unmatched lexical candidate and every provider-region candidate remains as an owned resolution or exclusion",
        ),
        (
            "struct_matcher",
            "Rust struct and struct-like enum construction candidates whose leading type token matches a K0.1 spelling; provider signatures are excluded before candidate emission",
        ),
        (
            "free_function_matcher",
            "exact calls to the four response-parser helper exports outside provider implementation plus exact provider-test helper tokens",
        ),
        (
            "context_inferred_default_matcher",
            "Default::default() expressions whose receiving field or typed binding resolves exactly to a pinned K0 type",
        ),
        (
            "locator_rule",
            "AST-visible downstream sites use exact UTF-8 byte and one-based line-column token ranges; macro-token, independent binding-only, inferred-default, and provider-test-region candidates use pinned line, exact callee literal, and same-line ordinal",
        ),
        (
            "site_id_rule",
            "existing groups KAFKA-K0-3-CSG-001 through -045 retain stable IDs and order; groups -046 through -048 append line/callee/ordinal IDs using kind codes FF, AC, IM, TP, SL, and CD",
        ),
        (
            "default_scope",
            "type-qualified K0Type::default() and exactly typed context-inferred Default::default() candidates are included; untyped context defaults remain outside scope",
        ),
        (
            "enum_and_struct_scope",
            "tuple-like enum variant calls and struct-like enum/struct constructions are included; provider-region pattern-only spellings are retained as EXCLUDED_PATTERN_ONLY candidates, while unit-variant paths, imports, type annotations, and ordinary field reads remain outside scope",
        ),
        (
            "candidate_identity_rule",
            "all 1,363 nodes are candidate identities; 1,097 are resolved-current, resolved-stale, or unresolved-stale K0 call-shaped nodes, while 266 are explicit name-collision, pattern-only, or comment/string exclusions and are not Kafka calls",
        ),
        (
            "partition_rule",
            "every declared candidate appears exactly once in one path group and exactly one resolution state; resolved K0 nodes have a nonnull K0.1 ID, and K0.2 IDs are nonempty exactly when no_k0_2_reason is null",
        ),
    ] {
        if text(scope_value, key) != expected {
            return Err(format!("call_site_scope.{key} drifted"));
        }
    }

    let pins = pin_paths(inventory);
    let symbol_ids = k0_1_symbol_ids();
    let semantic_ids = k0_2_semantic_ids();
    let groups = array(inventory, "call_site_groups");
    if groups.len() != CALL_SITE_GROUP_COUNT {
        return Err("call-site group count drifted".to_owned());
    }
    let declared_paths = groups
        .iter()
        .map(|group| text(group, "path").to_owned())
        .collect::<Vec<_>>();
    let path_set = declared_paths.iter().cloned().collect::<BTreeSet<_>>();
    if path_set.len() != groups.len()
        || sorted_newline_sha256(&path_set) != CALL_SITE_PATH_SET_SHA256
        || text(scope_value, "call_site_path_set_sha256") != CALL_SITE_PATH_SET_SHA256
    {
        return Err("call-site path uniqueness or digest drifted".to_owned());
    }
    let provider_exclusions = array(scope_value, "provider_declaration_exclusions");
    if provider_exclusions.len() != 2 {
        return Err("provider declaration exclusion regions drifted".to_owned());
    }
    for (row, path, excluded, included) in [
        (
            &provider_exclusions[0],
            "src/messaging/kafka.rs",
            "lines 1-2724",
            "lines 2725-4335",
        ),
        (
            &provider_exclusions[1],
            "src/messaging/kafka_consumer.rs",
            "lines 1-1672",
            "lines 1673-2757",
        ),
    ] {
        require_exact_keys(
            row,
            &["excluded_region", "included_provider_test_region", "path"],
            path,
        )?;
        if text(row, "path") != path
            || text(row, "excluded_region") != excluded
            || text(row, "included_provider_test_region") != included
            || !path_set.contains(path)
        {
            return Err(format!("provider region split for {path} drifted"));
        }
    }
    let excluded_paths = string_set(scope_value, "generated_or_self_reference_exclusions");
    if !path_set.is_disjoint(&excluded_paths) {
        return Err("call-site groups include generated/self-reference exclusions".to_owned());
    }

    let allowed_kinds = string_set(scope_value, "included_site_kinds");
    let allowed_resolutions = string_set(scope_value, "resolution_states");
    let allowed_group_dispositions = string_set(scope_value, "group_dispositions");
    let mut group_pin_ids = BTreeSet::new();
    let mut site_ids = BTreeSet::new();
    let mut path_locators = BTreeSet::new();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    let mut resolution_counts = BTreeMap::<String, usize>::new();
    let mut lexical_instance_candidates = 0_usize;
    let mut binding_resolved_instance_sites = 0_usize;
    let mut lexical_binding_overlap = 0_usize;
    let mut unmatched_lexical_instance_candidates = 0_usize;
    let provider_paths =
        expected_set(&["src/messaging/kafka.rs", "src/messaging/kafka_consumer.rs"]);
    let mut provider_site_tuples = BTreeSet::new();
    let mut provider_resolution_counts = BTreeMap::<String, usize>::new();

    for (index, group) in groups.iter().enumerate() {
        let group_ordinal = index + 1;
        let expected_group_id = format!("KAFKA-K0-3-CSG-{group_ordinal:03}");
        let group_id = text(group, "group_id");
        let path = text(group, "path");
        require_exact_keys(
            group,
            &[
                "atomic_sites",
                "call_site_disposition",
                "claim_disposition",
                "evidence_class",
                "execution_state",
                "freshness_state",
                "group_id",
                "import_resolution_state",
                "owner_bead",
                "path",
                "refresh_owner_bead",
                "resolution_reason",
                "source_pin_id",
                "wiring_state",
            ],
            group_id,
        )?;
        if group_id != expected_group_id {
            return Err(format!("{group_id} is not the stable ordinal for {path}"));
        }
        let pin_id = text(group, "source_pin_id");
        if pins.get(pin_id).map(String::as_str) != Some(path)
            || !group_pin_ids.insert(pin_id.to_owned())
        {
            return Err(format!("{group_id} path/pin join is not unique and exact"));
        }
        require_owner(group, group_id)?;
        if text(group, "refresh_owner_bead") != REFRESH_BEAD_ID
            || text(group, "execution_state") != "NOT_RUN"
            || text(group, "evidence_class") == "REAL_BROKER_RECEIPT"
            || !allowed_group_dispositions.contains(text(group, "call_site_disposition"))
        {
            return Err(format!(
                "{group_id} ownership or static classification drifted"
            ));
        }
        let sites = array(group, "atomic_sites");
        if sites.is_empty() {
            return Err(format!("{group_id} must own at least one atomic site"));
        }
        let source = read_repo_bytes(path);
        let mut group_resolutions = BTreeSet::new();
        for site in sites {
            require_exact_keys(
                site,
                &[
                    "binding_evidence",
                    "k0_1_symbol_id",
                    "k0_2_semantic_ids",
                    "no_k0_2_reason",
                    "resolution_state",
                    "site_id",
                    "site_kind",
                    "source_literal",
                    "source_locator",
                ],
                text(site, "site_id"),
            )?;
            let site_id = text(site, "site_id");
            let kind = text(site, "site_kind");
            let resolution = text(site, "resolution_state");
            if !site_ids.insert(site_id.to_owned())
                || !path_locators.insert((path.to_owned(), text(site, "source_locator").to_owned()))
                || !allowed_kinds.contains(kind)
                || !allowed_resolutions.contains(resolution)
            {
                return Err(format!(
                    "{site_id} has a duplicate identity/locator or unknown partition value"
                ));
            }
            if text(site, "binding_evidence").is_empty() {
                return Err(format!("{site_id} must retain binding evidence"));
            }
            group_resolutions.insert(resolution.to_owned());
            *kind_counts.entry(kind.to_owned()).or_default() += 1;
            *resolution_counts.entry(resolution.to_owned()).or_default() += 1;

            let k0_1 = site.get("k0_1_symbol_id");
            match k0_1 {
                Some(Value::String(symbol_id)) if symbol_ids.contains(symbol_id) => {
                    if matches!(
                        resolution,
                        "EXCLUDED_NAME_COLLISION"
                            | "EXCLUDED_PATTERN_ONLY"
                            | "EXCLUDED_COMMENT_OR_STRING"
                    ) {
                        return Err(format!(
                            "{site_id} exclusion cannot claim a resolved K0.1 symbol"
                        ));
                    }
                }
                Some(Value::Null)
                    if matches!(
                        resolution,
                        "EXCLUDED_NAME_COLLISION"
                            | "EXCLUDED_PATTERN_ONLY"
                            | "EXCLUDED_COMMENT_OR_STRING"
                            | "UNRESOLVED_STALE_SURFACE"
                    ) => {}
                _ => {
                    return Err(format!(
                        "{site_id} must reference a known K0.1 symbol or an owned unresolved partition"
                    ));
                }
            }
            let k0_2 = string_set(site, "k0_2_semantic_ids");
            if k0_2.len() != array(site, "k0_2_semantic_ids").len()
                || !k0_2.is_subset(&semantic_ids)
            {
                return Err(format!(
                    "{site_id} K0.2 references must be unique and known"
                ));
            }
            let no_k0_2_reason = site.get("no_k0_2_reason");
            if (k0_2.is_empty()
                && !matches!(no_k0_2_reason, Some(Value::String(reason)) if !reason.is_empty()))
                || (!k0_2.is_empty() && no_k0_2_reason != Some(&Value::Null))
            {
                return Err(format!(
                    "{site_id} must carry either K0.2 semantics or one explicit no-semantic reason"
                ));
            }
            validate_call_site_locator(site, group_ordinal, path, &source)?;
            if provider_paths.contains(path) {
                provider_site_tuples.insert(provider_site_candidate_tuple(site, path)?);
                *provider_resolution_counts
                    .entry(resolution.to_owned())
                    .or_default() += 1;
            }

            let is_instance = matches!(kind, "INSTANCE_METHOD_CALL" | "TRAIT_METHOD_PROJECTION");
            let is_byte_locator = text(site, "source_locator").starts_with("bytes ");
            let is_binding_resolved = matches!(
                resolution,
                "RESOLVED_CURRENT_K0" | "RESOLVED_STALE_UNWIRED_K0"
            );
            if !provider_paths.contains(path) && is_instance && is_byte_locator {
                lexical_instance_candidates += 1;
                if is_binding_resolved {
                    lexical_binding_overlap += 1;
                } else {
                    unmatched_lexical_instance_candidates += 1;
                }
            }
            if !provider_paths.contains(path) && is_instance && is_binding_resolved {
                binding_resolved_instance_sites += 1;
            }
        }

        let resolution_reason = group_resolutions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" + ");
        if text(group, "resolution_reason") != resolution_reason {
            return Err(format!("{group_id} resolution reason is not derived"));
        }
        let (expected_disposition, expected_import_state) = if group_resolutions.len() > 1 {
            ("MIXED_CALL_SITE_DISPOSITIONS", "MIXED")
        } else {
            match group_resolutions.iter().next().map(String::as_str) {
                Some("RESOLVED_CURRENT_K0") => {
                    ("CONFIRMED_CURRENT_K0_CALLS", "RESOLVED_CURRENT_K0")
                }
                Some("RESOLVED_STALE_UNWIRED_K0") => (
                    "CONFIRMED_STALE_UNWIRED_K0_CALLS",
                    "RESOLVED_STALE_UNWIRED_K0",
                ),
                Some("EXCLUDED_NAME_COLLISION") => {
                    ("EXCLUDED_NAME_COLLISIONS", "EXCLUDED_NAME_COLLISION")
                }
                Some("UNRESOLVED_STALE_SURFACE") => {
                    ("UNRESOLVED_STALE_SURFACE", "UNRESOLVED_STALE_SURFACE")
                }
                Some("EXCLUDED_PATTERN_ONLY") => ("EXCLUDED_PATTERN_ONLY", "EXCLUDED_PATTERN_ONLY"),
                Some("EXCLUDED_COMMENT_OR_STRING") => {
                    ("EXCLUDED_COMMENT_OR_STRING", "EXCLUDED_COMMENT_OR_STRING")
                }
                _ => return Err(format!("{group_id} has no classified atomic sites")),
            }
        };
        if text(group, "call_site_disposition") != expected_disposition
            || text(group, "import_resolution_state") != expected_import_state
        {
            return Err(format!(
                "{group_id} import-resolution partition is not derived from its sites"
            ));
        }
    }

    if site_ids.len() != CALL_SITE_COUNT
        || sorted_newline_sha256(&site_ids) != CALL_SITE_ID_SET_SHA256
        || text(scope_value, "call_site_id_set_sha256") != CALL_SITE_ID_SET_SHA256
    {
        return Err("call-site ID count, uniqueness, or digest drifted".to_owned());
    }
    let expected_kind_counts = [
        ("ASSOCIATED_CALL", 501_usize),
        ("CONTEXT_INFERRED_DEFAULT_CALL", 8),
        ("FREE_FUNCTION_CALL", 40),
        ("INSTANCE_METHOD_CALL", 654),
        ("STRUCT_LITERAL_CONSTRUCTION", 23),
        ("TRAIT_METHOD_PROJECTION", 137),
    ]
    .into_iter()
    .map(|(key, count)| (key.to_owned(), count))
    .collect::<BTreeMap<_, _>>();
    let expected_resolution_counts = [
        ("EXCLUDED_COMMENT_OR_STRING", 3_usize),
        ("EXCLUDED_NAME_COLLISION", 232),
        ("EXCLUDED_PATTERN_ONLY", 31),
        ("RESOLVED_CURRENT_K0", 1_063),
        ("RESOLVED_STALE_UNWIRED_K0", 26),
        ("UNRESOLVED_STALE_SURFACE", 8),
    ]
    .into_iter()
    .map(|(key, count)| (key.to_owned(), count))
    .collect::<BTreeMap<_, _>>();
    if kind_counts != expected_kind_counts || resolution_counts != expected_resolution_counts {
        return Err("call-site kind or resolution-state partition drifted".to_owned());
    }
    if lexical_instance_candidates != 338
        || binding_resolved_instance_sites != 375
        || lexical_binding_overlap != 280
        || unmatched_lexical_instance_candidates != 58
    {
        return Err("downstream instance binding census drifted".to_owned());
    }
    let derived_union = lexical_instance_candidates
        .checked_add(binding_resolved_instance_sites)
        .and_then(|count| count.checked_sub(lexical_binding_overlap))
        .ok_or_else(|| "call-site instance-union arithmetic underflowed".to_owned())?;
    if derived_union != 433
        || lexical_instance_candidates
            != lexical_binding_overlap + unmatched_lexical_instance_candidates
    {
        return Err("downstream instance-union arithmetic drifted".to_owned());
    }

    let helper_receipt = scope_value
        .get("downstream_helper_call_receipt")
        .unwrap_or_else(|| panic!("downstream_helper_call_receipt must exist"));
    validate_downstream_helper_receipt(inventory, helper_receipt)?;

    let provider_receipt = scope_value
        .get("provider_test_candidate_receipt")
        .unwrap_or_else(|| panic!("provider_test_candidate_receipt must exist"));
    require_exact_keys(
        provider_receipt,
        &[
            "candidate_count",
            "candidate_kind_counts",
            "candidate_kind_tokens",
            "excluded_false_return_signatures",
            "free_function_tokens",
            "public_method_tokens",
            "regions",
            "resolution_counts",
            "trait_projection_tokens",
            "tuple_rule",
            "tuple_sha256",
            "type_tokens",
            "ufcs_trait_token",
        ],
        "provider_test_candidate_receipt",
    )?;
    let expected_types = expected_set(&[
        "Acks",
        "AutoOffsetReset",
        "BrokerBackend",
        "Compression",
        "ConsumerConfig",
        "ConsumerRecord",
        "DeterministicBrokerBackend",
        "DeterministicBrokerTestGuard",
        "DeterministicConsumer",
        "IsolationLevel",
        "KafkaClient",
        "KafkaConsumer",
        "KafkaConsumerConfig",
        "KafkaConsumerRecord",
        "KafkaConsumerTrait",
        "KafkaError",
        "KafkaFeatureRequirement",
        "KafkaProducer",
        "KafkaSaslConfig",
        "KafkaSaslMechanism",
        "KafkaSecurityConfig",
        "KafkaTlsConfig",
        "ProducerConfig",
        "RealBrokerBackend",
        "RebalanceResult",
        "RecordMetadata",
        "TopicAwareConsumer",
        "TopicPartitionOffset",
        "Transaction",
        "TransactionalConfig",
        "TransactionalProducer",
    ]);
    let authority = parse_repo_json(K0_1_PATH);
    let expected_public_methods = array(&authority, "public_symbols")
        .iter()
        .flat_map(|symbol| string_set(symbol, "public_methods"))
        .collect::<BTreeSet<_>>();
    if string_set(provider_receipt, "type_tokens") != expected_types
        || string_set(provider_receipt, "public_method_tokens") != expected_public_methods
        || expected_public_methods.len() != 74
        || string_set(provider_receipt, "trait_projection_tokens")
            != expected_set(&["clone", "source", "to_string"])
        || string_set(provider_receipt, "free_function_tokens")
            != expected_set(&[
                "deterministic_broker_end_offset",
                "lock_deterministic_broker_for_tests",
                "reset_deterministic_broker_for_tests",
            ])
        || text(provider_receipt, "ufcs_trait_token") != "std::error::Error::source"
        || string_set(provider_receipt, "excluded_false_return_signatures")
            != expected_set(&["-> DeterministicBrokerTestGuard {"])
    {
        return Err("provider test scanner token grammar drifted".to_owned());
    }
    let candidate_kind_tokens = object(provider_receipt, "candidate_kind_tokens");
    let expected_candidate_kind_tokens = [
        ("ASSOCIATED_CANDIDATE", "Type::callee"),
        ("FREE_FUNCTION_CALL", "helper"),
        ("INFERRED_DEFAULT_CALL", "Default::default"),
        ("INSTANCE_PUBLIC_METHOD_CANDIDATE", ".callee"),
        ("STRUCT_LITERAL_CONSTRUCTION", "Type"),
        ("TRAIT_METHOD_PROJECTION", "std::error::Error::source"),
        ("TRAIT_PROJECTION_CANDIDATE", ".clone/.to_string/.source"),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    if candidate_kind_tokens.len() != expected_candidate_kind_tokens.len()
        || expected_candidate_kind_tokens.iter().any(|(kind, token)| {
            candidate_kind_tokens.get(*kind).and_then(Value::as_str) != Some(*token)
        })
        || text(provider_receipt, "tuple_rule")
            != "candidate-kind<TAB>path<TAB>line<TAB>candidate-token<TAB>same-line-ordinal, UTF-8 lexicographically sorted and LF-terminated"
    {
        return Err("provider candidate tuple grammar drifted".to_owned());
    }
    let regions = array(provider_receipt, "regions");
    if regions.len() != 2 {
        return Err("provider test scanner region count drifted".to_owned());
    }
    for (row, path, first, last, count) in [
        (
            &regions[0],
            "src/messaging/kafka.rs",
            2_725_u64,
            4_335_u64,
            341_u64,
        ),
        (
            &regions[1],
            "src/messaging/kafka_consumer.rs",
            1_673_u64,
            2_757_u64,
            294_u64,
        ),
    ] {
        require_exact_keys(
            row,
            &["candidate_count", "first_line", "last_line", "path"],
            path,
        )?;
        if text(row, "path") != path
            || row.get("first_line").and_then(Value::as_u64) != Some(first)
            || row.get("last_line").and_then(Value::as_u64) != Some(last)
            || row.get("candidate_count").and_then(Value::as_u64) != Some(count)
        {
            return Err(format!("provider scanner region {path} drifted"));
        }
    }
    let (provider_tuples, provider_kind_counts) = provider_candidate_tuples(provider_receipt)?;
    let expected_provider_kind_counts = [
        ("ASSOCIATED_CANDIDATE", 254_usize),
        ("FREE_FUNCTION_CALL", 5),
        ("INFERRED_DEFAULT_CALL", 6),
        ("INSTANCE_PUBLIC_METHOD_CANDIDATE", 249),
        ("STRUCT_LITERAL_CONSTRUCTION", 12),
        ("TRAIT_METHOD_PROJECTION", 3),
        ("TRAIT_PROJECTION_CANDIDATE", 106),
    ]
    .into_iter()
    .map(|(key, count)| (key.to_owned(), count))
    .collect::<BTreeMap<_, _>>();
    let expected_provider_resolution_counts = [
        ("EXCLUDED_COMMENT_OR_STRING", 3_usize),
        ("EXCLUDED_NAME_COLLISION", 92),
        ("EXCLUDED_PATTERN_ONLY", 31),
        ("RESOLVED_CURRENT_K0", 509),
    ]
    .into_iter()
    .map(|(key, count)| (key.to_owned(), count))
    .collect::<BTreeMap<_, _>>();
    if provider_tuples.len() != 635
        || provider_site_tuples != provider_tuples
        || sorted_newline_sha256(&provider_tuples) != PROVIDER_TEST_CANDIDATE_TUPLE_SHA256
        || provider_kind_counts != expected_provider_kind_counts
        || provider_resolution_counts != expected_provider_resolution_counts
        || provider_receipt
            .get("candidate_count")
            .and_then(Value::as_u64)
            != Some(635)
        || text(provider_receipt, "tuple_sha256") != PROVIDER_TEST_CANDIDATE_TUPLE_SHA256
    {
        return Err("provider test candidate source census drifted".to_owned());
    }
    for (key, expected) in [
        ("candidate_kind_counts", &expected_provider_kind_counts),
        ("resolution_counts", &expected_provider_resolution_counts),
    ] {
        let actual = object(provider_receipt, key);
        if actual.len() != expected.len()
            || expected.iter().any(|(name, count)| {
                actual.get(name).and_then(Value::as_u64) != Some(count_u64(*count, name))
            })
        {
            return Err(format!("provider_test_candidate_receipt.{key} drifted"));
        }
    }

    let raw_counts_value = scope_value
        .get("raw_counts")
        .unwrap_or_else(|| panic!("call_site_scope.raw_counts must exist"));
    require_exact_keys(
        raw_counts_value,
        &[
            "binding_resolved_instance_sites",
            "downstream_associated_candidates",
            "downstream_context_inferred_default_calls",
            "downstream_free_function_calls",
            "downstream_instance_union_sites",
            "downstream_struct_constructions",
            "lexical_instance_candidates",
            "lexical_instance_overlap_with_binding_set",
            "provider_test_candidates",
            "unmatched_lexical_instance_candidates",
        ],
        "call_site_scope.raw_counts",
    )?;
    for (key, count) in [
        ("downstream_associated_candidates", 247_usize),
        ("downstream_struct_constructions", 11),
        ("downstream_free_function_calls", 35),
        ("downstream_context_inferred_default_calls", 2),
        ("lexical_instance_candidates", 338),
        ("binding_resolved_instance_sites", 375),
        ("lexical_instance_overlap_with_binding_set", 280),
        ("unmatched_lexical_instance_candidates", 58),
        ("downstream_instance_union_sites", 433),
        ("provider_test_candidates", 635),
    ] {
        if raw_counts_value.get(key).and_then(Value::as_u64) != Some(count_u64(count, key)) {
            return Err(format!("call_site_scope.raw_counts.{key} is not derived"));
        }
    }

    let derived_counts_value = scope_value
        .get("derived_counts")
        .unwrap_or_else(|| panic!("call_site_scope.derived_counts must exist"));
    require_exact_keys(
        derived_counts_value,
        &[
            "call_site_group_count",
            "call_site_node_count",
            "candidate_call_shaped_count",
            "explicit_exclusion_candidate_count",
            "resolution_state_counts",
            "site_kind_counts",
        ],
        "call_site_scope.derived_counts",
    )?;
    if derived_counts_value
        .get("call_site_group_count")
        .and_then(Value::as_u64)
        != Some(count_u64(groups.len(), "call-site groups"))
        || derived_counts_value
            .get("call_site_node_count")
            .and_then(Value::as_u64)
            != Some(count_u64(site_ids.len(), "call sites"))
        || derived_counts_value
            .get("candidate_call_shaped_count")
            .and_then(Value::as_u64)
            != Some(1_097)
        || derived_counts_value
            .get("explicit_exclusion_candidate_count")
            .and_then(Value::as_u64)
            != Some(266)
    {
        return Err("call-site derived group or node count drifted".to_owned());
    }
    for (key, expected) in [
        ("site_kind_counts", &kind_counts),
        ("resolution_state_counts", &resolution_counts),
    ] {
        let actual = object(derived_counts_value, key);
        if actual.len() != expected.len()
            || expected.iter().any(|(name, count)| {
                actual.get(name).and_then(Value::as_u64) != Some(count_u64(*count, name))
            })
        {
            return Err(format!(
                "call_site_scope.derived_counts.{key} is not derived"
            ));
        }
    }
    Ok(())
}

fn k0_1_symbol_ids() -> BTreeSet<String> {
    array(&parse_repo_json(K0_1_PATH), "public_symbols")
        .iter()
        .map(|row| text(row, "symbol_id").to_owned())
        .collect()
}

fn k0_2_semantic_ids() -> BTreeSet<String> {
    let matrix = parse_repo_json(K0_2_PATH);
    [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ]
    .into_iter()
    .flat_map(|key| {
        array(&matrix, key)
            .iter()
            .map(|row| text(row, "semantic_id").to_owned())
            .collect::<Vec<_>>()
    })
    .collect()
}

type ReferenceMap = BTreeMap<String, BTreeSet<String>>;

fn validate_k0_disposition_table(
    inventory: &Value,
    table_key: &str,
    id_key: &str,
    expected_ids: &BTreeSet<String>,
) -> Result<(ReferenceMap, ReferenceMap), String> {
    let rows = array(inventory, table_key);
    let actual_ids = row_ids(rows, id_key);
    if rows.len() != expected_ids.len() || &actual_ids != expected_ids {
        return Err(format!("{table_key} exact {id_key} set drifted"));
    }

    let local_row_ids = row_ids(array(inventory, "local_inventory_rows"), "row_id");
    let atomic_case_ids = row_ids(array(inventory, "atomic_test_cases"), "case_id");
    let journey_ids = row_ids(array(inventory, "user_journeys"), "journey_id");
    let mut local_references = BTreeMap::new();
    let mut atomic_references = BTreeMap::new();
    for row in rows {
        let id = text(row, id_key);
        require_exact_keys(
            row,
            &[
                id_key,
                "atomic_case_ids",
                "disposition",
                "journey_ids",
                "local_row_ids",
                "owner_bead",
                "preservation_required",
                "synthesis_required",
                "usage_knowledge_state",
            ],
            id,
        )?;
        if text(row, "disposition") != "PRESERVE_AND_RECHECK_AT_K14"
            || !bool_field(row, "preservation_required")
            || !bool_field(row, "synthesis_required")
            || text(row, "owner_bead") != REFRESH_BEAD_ID
        {
            return Err(format!(
                "{id} lost its exact K14 preserve-and-recheck disposition"
            ));
        }

        let local = string_set(row, "local_row_ids");
        let atomic = string_set(row, "atomic_case_ids");
        let journeys = string_set(row, "journey_ids");
        for (key, values, known) in [
            ("local_row_ids", &local, &local_row_ids),
            ("atomic_case_ids", &atomic, &atomic_case_ids),
            ("journey_ids", &journeys, &journey_ids),
        ] {
            if array(row, key).len() != values.len() || !values.is_subset(known) {
                return Err(format!("{id}.{key} must be unique known references"));
            }
        }
        let has_references = !local.is_empty() || !atomic.is_empty() || !journeys.is_empty();
        let expected_state = if has_references {
            "KNOWN_LOCAL_REFERENCES"
        } else {
            "UNKNOWN"
        };
        if text(row, "usage_knowledge_state") != expected_state {
            return Err(format!(
                "{id} usage knowledge does not match its references"
            ));
        }
        local_references.insert(id.to_owned(), local);
        atomic_references.insert(id.to_owned(), atomic);
    }
    Ok((local_references, atomic_references))
}

fn reverse_references(references: &ReferenceMap, referenced_id: &str) -> BTreeSet<String> {
    references
        .iter()
        .filter(|(_, ids)| ids.contains(referenced_id))
        .map(|(id, _)| id.clone())
        .collect()
}

fn validate_k0_dispositions(inventory: &Value) -> Result<(), String> {
    let pins = pin_paths(inventory);
    for (pin_id, expected_path) in [
        ("KAFKA-K0-3-PIN-K0-1-ARTIFACT", K0_1_PATH),
        ("KAFKA-K0-3-PIN-K0-2-ARTIFACT", K0_2_PATH),
    ] {
        if pins.get(pin_id).map(String::as_str) != Some(expected_path) {
            return Err(format!("{pin_id} must resolve to {expected_path}"));
        }
    }
    let symbols = k0_1_symbol_ids();
    let semantics = k0_2_semantic_ids();
    if symbols.len() != K0_1_SYMBOL_COUNT
        || sorted_newline_sha256(&symbols) != K0_1_SYMBOL_MAP_SHA256
        || semantics.len() != K0_2_SEMANTIC_COUNT
        || sorted_newline_sha256(&semantics) != K0_2_SEMANTIC_MAP_SHA256
    {
        return Err("K0.1 or K0.2 source authority ID set drifted".to_owned());
    }

    let joins_value = inventory
        .get("coverage_joins")
        .unwrap_or_else(|| panic!("coverage_joins must exist"));
    let joins = joins_value
        .as_object()
        .unwrap_or_else(|| panic!("coverage_joins must be an object"));
    require_exact_keys(
        joins_value,
        &[
            "absence_authorizes_removal",
            "default_gap_owner_bead",
            "k0_1_public_symbol_count",
            "k0_1_public_symbol_id_set_sha256",
            "k0_2_semantic_id_set_sha256",
            "k0_2_semantic_row_count",
            "public_symbol_usage_rule",
            "semantic_usage_rule",
        ],
        "coverage_joins",
    )?;
    if joins
        .get("k0_1_public_symbol_count")
        .and_then(Value::as_u64)
        != Some(
            u64::try_from(K0_1_SYMBOL_COUNT)
                .unwrap_or_else(|error| panic!("K0.1 symbol count overflow: {error}")),
        )
        || joins
            .get("k0_1_public_symbol_id_set_sha256")
            .and_then(Value::as_str)
            != Some(K0_1_SYMBOL_MAP_SHA256)
        || joins.get("k0_2_semantic_row_count").and_then(Value::as_u64)
            != Some(
                u64::try_from(K0_2_SEMANTIC_COUNT)
                    .unwrap_or_else(|error| panic!("K0.2 semantic count overflow: {error}")),
            )
        || joins
            .get("k0_2_semantic_id_set_sha256")
            .and_then(Value::as_str)
            != Some(K0_2_SEMANTIC_MAP_SHA256)
        || joins.get("default_gap_owner_bead").and_then(Value::as_str) != Some(REFRESH_BEAD_ID)
        || joins
            .get("public_symbol_usage_rule")
            .and_then(Value::as_str)
            != Some(
                "every K0.1 ID is preserved and rechecked at K14; references record only proven local observations, while empty references remain UNKNOWN and require synthesis",
            )
        || joins.get("semantic_usage_rule").and_then(Value::as_str)
            != Some(
                "every K0.2 ID is preserved and rechecked at K14; references record only proven local observations, while empty references remain UNKNOWN and require synthesis",
            )
        || joins
            .get("absence_authorizes_removal")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("K0 coverage join receipt drifted".to_owned());
    }

    let (symbol_local, symbol_atomic) = validate_k0_disposition_table(
        inventory,
        "k0_1_symbol_dispositions",
        "symbol_id",
        &symbols,
    )?;
    let (semantic_local, semantic_atomic) = validate_k0_disposition_table(
        inventory,
        "k0_2_semantic_dispositions",
        "semantic_id",
        &semantics,
    )?;

    for row in array(inventory, "local_inventory_rows") {
        let row_id = text(row, "row_id");
        let row_symbols = string_set(row, "k0_1_symbol_ids");
        let row_semantics = string_set(row, "k0_2_semantic_ids");
        if row_symbols.len() != array(row, "k0_1_symbol_ids").len()
            || row_symbols != reverse_references(&symbol_local, row_id)
            || row_semantics.len() != array(row, "k0_2_semantic_ids").len()
            || row_semantics != reverse_references(&semantic_local, row_id)
        {
            return Err(format!("{row_id} K0 disposition backreferences drifted"));
        }
    }
    for case in array(inventory, "atomic_test_cases") {
        let case_id = text(case, "case_id");
        let case_symbols = string_set(case, "k0_1_symbol_ids");
        let case_semantics = string_set(case, "k0_2_semantic_ids");
        if case_symbols.is_empty()
            || case_symbols.len() != array(case, "k0_1_symbol_ids").len()
            || case_symbols != reverse_references(&symbol_atomic, case_id)
            || case_semantics.is_empty()
            || case_semantics.len() != array(case, "k0_2_semantic_ids").len()
            || case_semantics != reverse_references(&semantic_atomic, case_id)
        {
            return Err(format!("{case_id} K0 disposition backreferences drifted"));
        }
    }
    Ok(())
}

#[test]
fn inventory_identity_authority_ownership_and_evidence_are_fail_closed() {
    validate_inventory(&artifact()).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn all_source_pins_match_live_bytes_and_record_counts() {
    let inventory = artifact();
    for pin in array(&inventory, "source_pins") {
        let pin_id = text(pin, "pin_id");
        require_exact_keys(
            pin,
            &["path", "pin_id", "record_count", "role", "sha256"],
            pin_id,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let path = text(pin, "path");
        assert!(!text(pin, "role").is_empty(), "{pin_id} role must be owned");
        let bytes = read_repo_bytes(path);
        let content = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("{pin_id} {path} must be UTF-8: {error}"));
        let expected_count = pin
            .get("record_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("{pin_id} record_count must be an integer"));
        assert_eq!(
            u64::try_from(content.lines().count())
                .unwrap_or_else(|error| panic!("{pin_id} record count overflow: {error}")),
            expected_count,
            "{pin_id} record count drifted"
        );
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "{pin_id} hash drifted"
        );
    }
}

#[test]
fn baseline_occurrence_receipt_is_explicitly_and_exhaustively_dispositioned() {
    let inventory = artifact();
    validate_baseline_occurrence_paths(&inventory).unwrap_or_else(|error| panic!("{error}"));
    validate_occurrence_disposition_groups(&inventory).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn k0_1_public_symbols_and_k0_2_semantics_are_exactly_joined() {
    let inventory = artifact();
    validate_k0_dispositions(&inventory).unwrap_or_else(|error| panic!("{error}"));
    let symbols = k0_1_symbol_ids();
    let semantics = k0_2_semantic_ids();
    assert_eq!(symbols.len(), K0_1_SYMBOL_COUNT);
    assert_eq!(sorted_newline_sha256(&symbols), K0_1_SYMBOL_MAP_SHA256);
    assert_eq!(semantics.len(), K0_2_SEMANTIC_COUNT);
    assert_eq!(sorted_newline_sha256(&semantics), K0_2_SEMANTIC_MAP_SHA256);

    let joins = object(&inventory, "coverage_joins");
    assert_eq!(
        joins
            .get("k0_1_public_symbol_count")
            .and_then(Value::as_u64),
        Some(30)
    );
    assert_eq!(
        joins
            .get("k0_1_public_symbol_id_set_sha256")
            .and_then(Value::as_str),
        Some(K0_1_SYMBOL_MAP_SHA256)
    );
    assert_eq!(
        joins.get("k0_2_semantic_row_count").and_then(Value::as_u64),
        Some(97)
    );
    assert_eq!(
        joins
            .get("k0_2_semantic_id_set_sha256")
            .and_then(Value::as_str),
        Some(K0_2_SEMANTIC_MAP_SHA256)
    );
}

#[test]
fn test_declaration_scope_and_atomic_cases_are_exactly_pinned() {
    let inventory = artifact();
    validate_test_declaration_groups(&inventory).unwrap_or_else(|error| panic!("{error}"));
    validate_test_declaration_group_classifications(&inventory)
        .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn documentation_claim_identity_ownership_and_partition_are_source_derived() {
    validate_documentation_claim_census(&artifact()).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn companion_document_and_packet_bytes_are_pinned() {
    assert_eq!(sha256_hex(&read_repo_bytes(ARTIFACT_PATH)), ARTIFACT_SHA256);
    assert_eq!(sha256_hex(&read_repo_bytes(DOC_PATH)), DOC_SHA256);
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        "<!-- KAFKA-K0-3-AUTHORITY -->",
        "<!-- KAFKA-K0-3-LOCAL-CENSUS -->",
        "<!-- KAFKA-K0-3-COMPILE-CELLS -->",
        "<!-- KAFKA-K0-3-JOURNEYS -->",
        "<!-- KAFKA-K0-3-EVIDENCE -->",
        "<!-- KAFKA-K0-3-EXTERNAL-UNKNOWN -->",
        "<!-- KAFKA-K0-3-K14-HANDOFF -->",
        "<!-- KAFKA-K0-3-NO-CLAIMS -->",
        DOC_END,
    ] {
        assert_eq!(doc.matches(marker).count(), 1, "marker drifted: {marker}");
    }
    for phrase in [
        "KEEP_INCUMBENT",
        "REAL_BROKER_CAPABLE",
        "REAL_BROKER_RECEIPT",
        "NOT_RUN",
        "UNKNOWN",
        "asupersync-dep-p7-kafka-removal-sarszu.2.14.1",
        "baseline Git-tree receipt includes `examples/`",
        "rdkafka path-or-content match there",
        "EXACT_BASELINE_ABSENCE",
        "9,142",
        "1,363",
        PROVIDER_TEST_CANDIDATE_TUPLE_SHA256,
        TOKIO_TEST_DECLARATION_TUPLE_SHA256,
        "provides no permission to remove",
    ] {
        assert!(
            doc.contains(phrase),
            "documentation phrase missing: {phrase}"
        );
    }
}

#[test]
fn fail_closed_mutations_are_rejected() {
    let inventory = artifact();

    let mut removal = inventory.clone();
    removal["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_authority_and_policy(&removal).is_err());

    let mut external_zero = inventory.clone();
    external_zero["external_searches"][0]["result_count"] = Value::from(0_u64);
    assert!(validate_evidence_and_external(&external_zero).is_err());

    let mut promoted = inventory.clone();
    promoted["evidence_claims"][2]["evidence_class"] =
        Value::String("REAL_BROKER_RECEIPT".to_owned());
    assert!(validate_evidence_and_external(&promoted).is_err());

    let mut misleading_command = inventory.clone();
    misleading_command["evidence_claims"][1]["exact_command"] =
        Value::String("cargo check --features kafka".to_owned());
    assert!(validate_evidence_and_external(&misleading_command).is_err());

    let mut query_purpose_removed = inventory.clone();
    query_purpose_removed["search_queries"][0]["purpose"] = Value::String(String::new());
    assert!(validate_evidence_and_external(&query_purpose_removed).is_err());

    let mut missing_journey = inventory.clone();
    missing_journey["user_journeys"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("user_journeys must be an array"))
        .pop();
    assert!(validate_counts_and_ids(&missing_journey).is_err());

    let mut missing_handoff = inventory.clone();
    missing_handoff["k14_1_refresh_handoff"]["owner_bead"] = Value::Null;
    assert!(validate_handoff_and_receipt(&missing_handoff).is_err());

    let mut self_attested_incomplete = inventory.clone();
    self_attested_incomplete["coverage_receipt"]["inventory_receipt_complete"] = Value::Bool(false);
    assert!(validate_handoff_and_receipt(&self_attested_incomplete).is_err());

    let mut migration_promoted = inventory.clone();
    migration_promoted["coverage_receipt"]["migration_eligible"] = Value::Bool(true);
    assert!(validate_handoff_and_receipt(&migration_promoted).is_err());

    let mut inherited_count_drift = inventory.clone();
    inherited_count_drift["coverage_receipt"]["test_declarations_with_inherited_group_classification"] =
        Value::from(919_u64);
    assert!(validate_handoff_and_receipt(&inherited_count_drift).is_err());
}

#[test]
fn baseline_partition_and_test_census_mutations_are_rejected() {
    let inventory = artifact();

    let mut missing_baseline_path = inventory.clone();
    missing_baseline_path["search_scope"]["baseline_occurrence_paths"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("baseline_occurrence_paths must be an array"))
        .pop();
    assert!(validate_baseline_occurrence_paths(&missing_baseline_path).is_err());

    let mut live_claim = inventory.clone();
    live_claim["search_scope"]["current_worktree_claimed"] = Value::Bool(true);
    assert!(validate_baseline_occurrence_paths(&live_claim).is_err());

    let mut duplicate_disposition = inventory.clone();
    let duplicate_path =
        duplicate_disposition["occurrence_disposition_groups"][0]["paths"][0].clone();
    duplicate_disposition["occurrence_disposition_groups"][1]["paths"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("occurrence group paths must be an array"))
        .push(duplicate_path);
    assert!(validate_occurrence_disposition_groups(&duplicate_disposition).is_err());

    let mut scope_pin_removed = inventory.clone();
    scope_pin_removed["test_declaration_scope_pin_ids"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("test_declaration_scope_pin_ids must be an array"))
        .pop();
    assert!(validate_test_declaration_groups(&scope_pin_removed).is_err());

    let mut declaration_renamed = inventory.clone();
    declaration_renamed["test_declaration_groups"][0]["tests"][0]["name"] =
        Value::String("invented_test_name".to_owned());
    assert!(validate_test_declaration_groups(&declaration_renamed).is_err());

    let mut atomic_anchor_drift = inventory.clone();
    atomic_anchor_drift["atomic_test_cases"][0]["source_anchor"] =
        Value::String("line 1".to_owned());
    assert!(validate_test_declaration_groups(&atomic_anchor_drift).is_err());

    let mut tokio_attribute_line_drift = inventory.clone();
    tokio_attribute_line_drift["test_declaration_groups"][32]["tests"][0]["attribute_line"] =
        Value::from(1_u64);
    assert!(validate_test_declaration_groups(&tokio_attribute_line_drift).is_err());

    let mut test_scope_rule_drift = inventory.clone();
    test_scope_rule_drift["test_declaration_scope"]["row_line_rule"] =
        Value::String("trust the declared row".to_owned());
    assert!(validate_test_declaration_groups(&test_scope_rule_drift).is_err());

    let mut classification_removed = inventory.clone();
    classification_removed["test_declaration_group_classifications"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("test_declaration_group_classifications must be an array"))
        .pop();
    assert!(validate_test_declaration_group_classifications(&classification_removed).is_err());

    let mut cross_path_override = inventory.clone();
    cross_path_override["test_declaration_group_classifications"][0]["atomic_case_ids"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("atomic_case_ids must be an array"))
        .push(Value::String("KAFKA-K0-3-CASE-001".to_owned()));
    assert!(validate_test_declaration_group_classifications(&cross_path_override).is_err());
}

#[test]
fn documentation_and_call_site_receipt_mutations_are_rejected() {
    let inventory = artifact();

    let mut virtual_sentinel_drift = inventory.clone();
    virtual_sentinel_drift["documentation_claim_surfaces"]["virtual_surfaces"][0]["source_pin_digest_token"] =
        Value::String("ABSENT".to_owned());
    assert!(validate_documentation_claim_census(&virtual_sentinel_drift).is_err());

    let mut documentation_owner_removed = inventory.clone();
    documentation_owner_removed["documentation_claim_occurrence_groups"]["derived_remainder_groups"]
        ["owner_bead"] = Value::Null;
    assert!(validate_documentation_claim_census(&documentation_owner_removed).is_err());

    let mut extension_count_drift = inventory.clone();
    extension_count_drift["documentation_claim_scope"]["actual_candidate_extension_counts"]["md"] =
        Value::from(89_u64);
    assert!(validate_documentation_claim_census(&extension_count_drift).is_err());

    let mut provider_region_drift = inventory.clone();
    provider_region_drift["call_site_scope"]["provider_test_candidate_receipt"]["regions"][0]["first_line"] =
        Value::from(2_724_u64);
    assert!(validate_call_site_scope_and_groups(&provider_region_drift).is_err());

    let mut helper_digest_drift = inventory.clone();
    helper_digest_drift["call_site_scope"]["downstream_helper_call_receipt"]["tuple_sha256"] =
        Value::String("0".repeat(64));
    assert!(validate_call_site_scope_and_groups(&helper_digest_drift).is_err());
}

#[test]
fn disposition_owner_journey_and_state_mutations_are_rejected() {
    let inventory = artifact();

    let mut unpinned_consumer_path = inventory.clone();
    unpinned_consumer_path["local_consumers"][0]["paths"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("consumer paths must be an array"))
        .push(Value::String("untracked/kafka_consumer.rs".to_owned()));
    assert!(validate_local_joins(&unpinned_consumer_path).is_err());

    let mut missing_symbol = inventory.clone();
    missing_symbol["k0_1_symbol_dispositions"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("k0_1_symbol_dispositions must be an array"))
        .pop();
    assert!(validate_k0_dispositions(&missing_symbol).is_err());

    let mut unknown_reference = inventory.clone();
    unknown_reference["k0_2_semantic_dispositions"][0]["local_row_ids"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("local_row_ids must be an array"))
        .push(Value::String("KAFKA-K0-3-MISSING-ROW".to_owned()));
    assert!(validate_k0_dispositions(&unknown_reference).is_err());

    let mut asymmetric_case = inventory.clone();
    asymmetric_case["atomic_test_cases"][0]["k0_2_semantic_ids"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("k0_2_semantic_ids must be an array"))
        .pop();
    assert!(validate_k0_dispositions(&asymmetric_case).is_err());

    let mut profile_owner_removed = inventory.clone();
    profile_owner_removed["compilation_profiles"][0]["owner_bead"] = Value::Null;
    assert!(validate_profiles_and_cells(&profile_owner_removed).is_err());

    let mut profile_cfg_drift = inventory.clone();
    profile_cfg_drift["compilation_profiles"][0]["cfg"] = Value::String("feature=kafka".to_owned());
    assert!(validate_profiles_and_cells(&profile_cfg_drift).is_err());

    let mut cell_pins_removed = inventory.clone();
    cell_pins_removed["feature_platform_cells"][0]["source_pin_ids"] = Value::Array(Vec::new());
    assert!(validate_profiles_and_cells(&cell_pins_removed).is_err());

    let mut cell_target_drift = inventory.clone();
    cell_target_drift["feature_platform_cells"][0]["target_ids"] =
        Value::Array(vec![Value::String("linux-x86_64-gnu".to_owned())]);
    assert!(validate_profiles_and_cells(&cell_target_drift).is_err());

    let mut journey_order_changed = inventory.clone();
    journey_order_changed["user_journeys"][0]["ordered_public_entry_points"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("ordered_public_entry_points must be an array"))
        .swap(0, 1);
    assert!(validate_canonical_journeys(&journey_order_changed).is_err());

    let mut asymmetric_journey_row = inventory.clone();
    asymmetric_journey_row["user_journeys"][3]["local_row_ids"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("local_row_ids must be an array"))
        .remove(0);
    assert!(validate_local_joins(&asymmetric_journey_row).is_err());

    let mut capability_promoted = inventory.clone();
    capability_promoted["atomic_test_cases"][0]["execution_state"] =
        Value::String("PASS".to_owned());
    assert!(validate_state_compatibility(&capability_promoted).is_err());

    let mut deterministic_case_reclassified = inventory.clone();
    deterministic_case_reclassified["atomic_test_cases"][9]["evidence_class"] =
        Value::String("REAL_BROKER_CAPABLE".to_owned());
    assert!(validate_local_joins(&deterministic_case_reclassified).is_err());
}
