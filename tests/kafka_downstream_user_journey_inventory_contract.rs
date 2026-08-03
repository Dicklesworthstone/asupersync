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
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_downstream_user_journey_inventory_v1.json";
const DOC_PATH: &str = "docs/kafka_downstream_user_journey_inventory.md";
const K0_1_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const ARTIFACT_SHA256: &str =
    "5542c2272faef150c1390809a14f8edb416f9c43aed001f8bcf393bf2af078db";
const DOC_SHA256: &str =
    "f46570a74ed8c407f65acb8af8f5580e5e8d458d5ca3b441fe3ff52252832dff";
const ARTIFACT_ID: &str = "kafka-downstream-user-journey-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.3";
const REFRESH_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.14.1";
const BASELINE_REVISION: &str = "ae22e710d87412b38e546b32e9702106619481d5";
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

fn expected_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|value| (*value).to_owned()).collect()
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

fn validate_identity(inventory: &Value) -> Result<(), String> {
    require_exact_keys(
        inventory,
        &[
            "artifact_id",
            "authority",
            "authority_revision",
            "baseline_revision",
            "bead_id",
            "capability_id",
            "captured_date_utc",
            "compilation_profiles",
            "coverage_joins",
            "coverage_receipt",
            "documentation_claims",
            "evidence_claims",
            "external_searches",
            "feature_platform_cells",
            "feature_platform_evidence_state",
            "inventory_state",
            "k14_1_refresh_handoff",
            "local_consumers",
            "local_inventory_rows",
            "no_claim_boundaries",
            "non_consumer_dispositions",
            "owned_unknowns",
            "policy",
            "program_id",
            "routed_gaps",
            "schema_version",
            "search_queries",
            "search_scope",
            "source_pins",
            "taxonomies",
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
            "K0_3_LOCAL_STATIC_CENSUS_FROZEN_EXTERNAL_UNKNOWN",
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

fn validate_counts_and_ids(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins");
    let local_consumers = array(inventory, "local_consumers");
    let local_rows = array(inventory, "local_inventory_rows");
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
        (pins.len(), 61, "source pins"),
        (local_consumers.len(), 11, "local consumers"),
        (local_rows.len(), 25, "local rows"),
        (doc_claims.len(), 13, "documentation claims"),
        (profiles.len(), 17, "compilation profiles"),
        (cells.len(), 8, "feature-platform cells"),
        (journeys.len(), 12, "journeys"),
        (evidence.len(), 6, "evidence claims"),
        (external.len(), 5, "external searches"),
        (unknowns.len(), 6, "owned unknowns"),
        (gaps.len(), 15, "routed gaps"),
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
        ],
        "journeys",
    )?;
    Ok(())
}

fn validate_local_joins(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins");
    let pin_ids = row_ids(pins, "pin_id");
    let pin_paths = pins
        .iter()
        .map(|pin| text(pin, "path").to_owned())
        .collect::<BTreeSet<_>>();
    if pin_paths.len() != pins.len() {
        return Err("source pin paths must be unique".to_owned());
    }

    let consumers = row_ids(array(inventory, "local_consumers"), "consumer_id");
    let journeys = row_ids(array(inventory, "user_journeys"), "journey_id");
    let local_rows = array(inventory, "local_inventory_rows");
    let local_row_ids = row_ids(local_rows, "row_id");
    for row in local_rows {
        let row_id = text(row, "row_id");
        match row.get("source_pin_id") {
            Some(Value::String(pin_id)) if pin_ids.contains(pin_id) => {}
            Some(Value::Null) if text(row, "row_kind") == "EXAMPLE" => {}
            _ => return Err(format!("{row_id} must reference a source pin or explicit example absence")),
        }
        if let Some(consumer_id) = row.get("consumer_id").and_then(Value::as_str)
            && !consumers.contains(consumer_id)
        {
            return Err(format!("{row_id} references unknown consumer {consumer_id}"));
        }
        for journey in array(row, "journey_ids") {
            let journey = journey
                .as_str()
                .unwrap_or_else(|| panic!("journey_ids entries must be strings"));
            if !journeys.contains(journey) {
                return Err(format!("{row_id} references unknown journey {journey}"));
            }
        }
    }

    for journey in array(inventory, "user_journeys") {
        for row_id in array(journey, "local_row_ids") {
            let row_id = row_id
                .as_str()
                .unwrap_or_else(|| panic!("local_row_ids entries must be strings"));
            if !local_row_ids.contains(row_id) {
                return Err(format!("journey references unknown local row {row_id}"));
            }
        }
    }

    for claim in array(inventory, "documentation_claims") {
        for pin_id in array(claim, "source_pin_ids") {
            let pin_id = pin_id
                .as_str()
                .unwrap_or_else(|| panic!("source_pin_ids entries must be strings"));
            if !pin_ids.contains(pin_id) {
                return Err(format!("documentation claim references unknown pin {pin_id}"));
            }
        }
    }
    Ok(())
}

fn validate_profiles_and_cells(inventory: &Value) -> Result<(), String> {
    let profiles = array(inventory, "compilation_profiles");
    let expected_k0_1 = [
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
    ];
    for (index, expected) in expected_k0_1.iter().enumerate() {
        let row = profiles
            .get(index)
            .unwrap_or_else(|| panic!("missing profile index {index}"));
        if text(row, "k0_1_profile_id") != *expected {
            return Err(format!("K0.1 profile mapping drifted at index {index}"));
        }
    }

    require_exact_ids(
        array(inventory, "feature_platform_cells"),
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
    let state = object(inventory, "feature_platform_evidence_state");
    if state.get("knowledge_state").and_then(Value::as_str) != Some("UNKNOWN")
        || state.get("linux_real_service_runtime").and_then(Value::as_str)
            != Some("BLOCKED_EXTERNAL")
        || state.get("no_cross_compile_claim").and_then(Value::as_bool) != Some(true)
        || state.get("no_runtime_claim").and_then(Value::as_bool) != Some(true)
    {
        return Err("feature-platform evidence state drifted".to_owned());
    }
    Ok(())
}

fn validate_evidence_and_external(inventory: &Value) -> Result<(), String> {
    for evidence in array(inventory, "evidence_claims") {
        let evidence_id = text(evidence, "evidence_id");
        let class = text(evidence, "evidence_class");
        let execution = text(evidence, "execution_state");
        if class == "REAL_BROKER_RECEIPT" {
            if !matches!(execution, "PASS" | "FAIL")
                || evidence.get("executed_at_utc").and_then(Value::as_str).is_none()
                || evidence.get("exact_command").and_then(Value::as_str).is_none()
                || evidence.get("broker_version").and_then(Value::as_str).is_none()
                || evidence.get("service_identity").and_then(Value::as_str).is_none()
                || array(evidence, "retained_artifacts").is_empty()
            {
                return Err(format!("{evidence_id} is not a complete real-broker receipt"));
            }
        }
    }
    if array(inventory, "evidence_claims")
        .iter()
        .any(|row| text(row, "evidence_class") == "REAL_BROKER_RECEIPT")
    {
        return Err("K0.3 must not contain a real-broker receipt".to_owned());
    }

    for row in array(inventory, "external_searches") {
        let external_id = text(row, "external_id");
        if text(row, "search_status") != "NOT_RUN"
            || text(row, "knowledge_state") != "UNKNOWN"
            || row.get("attempted_at_utc") != Some(&Value::Null)
            || row.get("result_count") != Some(&Value::Null)
            || !array(row, "results").is_empty()
            || !array(row, "result_provenance").is_empty()
            || text(row, "resolution_owner_bead") != REFRESH_BEAD_ID
            || !bool_field(row, "blocks_migration")
            || text(row, "absence_authority") != "NONE"
        {
            return Err(format!("{external_id} must remain owned NOT_RUN/UNKNOWN"));
        }
    }
    for row in array(inventory, "owned_unknowns") {
        if !bool_field(row, "blocks_migration") {
            return Err(format!("{} must block migration", text(row, "unknown_id")));
        }
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
        || handoff.get("unknown_blocks_migration").and_then(Value::as_bool) != Some(true)
        || handoff.get("regression_blocks_migration").and_then(Value::as_bool) != Some(true)
        || handoff.get("may_authorize_deletion").and_then(Value::as_bool) != Some(false)
    {
        return Err("K14.1 handoff drifted".to_owned());
    }
    let receipt = object(inventory, "coverage_receipt");
    for key in [
        "all_local_rows_source_pinned_or_explicit_absence",
        "all_local_rows_owned",
        "all_claims_classified",
        "all_k0_1_profiles_mapped",
        "all_k0_2_semantics_dispositioned_by_exact_join_rule",
        "all_user_journeys_mapped",
        "local_static_scope_complete",
    ] {
        if receipt.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("coverage_receipt.{key} must remain true"));
        }
    }
    if receipt.get("migration_eligible").and_then(Value::as_bool) != Some(false)
        || receipt
            .get("contract_source_execution_claimed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt.get("creation_session_validation_mode").and_then(Value::as_str)
            != Some("STATIC_INSPECTION_ONLY")
        || receipt.get("contract_execution_evidence").and_then(Value::as_str)
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
    validate_local_joins(inventory)?;
    validate_profiles_and_cells(inventory)?;
    validate_evidence_and_external(inventory)?;
    validate_handoff_and_receipt(inventory)?;
    Ok(())
}

fn excluded_component(name: &str) -> bool {
    matches!(name, ".git" | ".beads" | ".ntm" | ".wrangler" | "target")
}

fn excluded_path(path: &str) -> bool {
    matches!(
        path,
        "tests/tests"
            | "artifacts/audit"
            | "artifacts/perf"
            | "artifacts/atp_bench_matrix"
            | "artifacts/stub_placeholder_inventory_markers.json"
            | "artifacts/kafka_downstream_user_journey_inventory_v1.json"
            | "docs/kafka_downstream_user_journey_inventory.md"
            | "tests/kafka_downstream_user_journey_inventory_contract.rs"
    ) || path.starts_with("tests/tests/")
        || path.ends_with(".proptest-regressions")
}

fn contains_kafka_ascii(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
        && bytes
            .windows(b"kafka".len())
            .any(|window| window.eq_ignore_ascii_case(b"kafka"))
}

fn collect_kafka_paths(
    absolute: &Path,
    relative: &Path,
    paths: &mut BTreeSet<String>,
) -> Result<(), String> {
    let relative_text = relative.to_string_lossy().replace('\\', "/");
    if excluded_path(&relative_text) {
        return Ok(());
    }
    if relative
        .components()
        .any(|component| excluded_component(&component.as_os_str().to_string_lossy()))
    {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(absolute)
        .map_err(|error| format!("failed to inspect {relative_text}: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        if relative_text.starts_with("artifacts/")
            && relative_text != "artifacts/wave2"
            && !relative_text.starts_with("artifacts/wave2/")
        {
            return Ok(());
        }
        let mut entries = std::fs::read_dir(absolute)
            .map_err(|error| format!("failed to list {relative_text}: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("failed to enumerate {relative_text}: {error}"))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            collect_kafka_paths(
                &entry.path(),
                &relative.join(entry.file_name()),
                paths,
            )?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Ok(());
    }
    let path_match = relative_text.to_ascii_lowercase().contains("kafka");
    let bytes = std::fs::read(absolute)
        .map_err(|error| format!("failed to read {relative_text}: {error}"))?;
    if path_match || contains_kafka_ascii(&bytes) {
        paths.insert(relative_text);
    }
    Ok(())
}

fn live_occurrence_paths(inventory: &Value) -> Result<BTreeSet<String>, String> {
    let scope = inventory
        .get("search_scope")
        .unwrap_or_else(|| panic!("search_scope must exist"));
    let expected_roots = expected_set(&[
        ".claude",
        ".github",
        "artifacts",
        "conformance",
        "docs",
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

    let mut paths = BTreeSet::new();
    for relative in expected_roots.iter().chain(expected_root_files.iter()) {
        collect_kafka_paths(
            &repo_root().join(relative),
            Path::new(relative),
            &mut paths,
        )?;
    }
    Ok(paths)
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

#[test]
fn inventory_identity_authority_ownership_and_evidence_are_fail_closed() {
    validate_inventory(&artifact()).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn all_source_pins_match_live_bytes_and_record_counts() {
    let inventory = artifact();
    for pin in array(&inventory, "source_pins") {
        let pin_id = text(pin, "pin_id");
        let path = text(pin, "path");
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
        assert_eq!(sha256_hex(&bytes), text(pin, "sha256"), "{pin_id} hash drifted");
    }
}

#[test]
fn occurrence_path_census_matches_declared_static_scope() {
    let inventory = artifact();
    let paths = live_occurrence_paths(&inventory).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(paths.len(), OCCURRENCE_PATH_COUNT);
    assert_eq!(sorted_newline_sha256(&paths), OCCURRENCE_PATH_MAP_SHA256);
    let scope = object(&inventory, "search_scope");
    assert_eq!(
        scope.get("tracked_occurrence_path_count").and_then(Value::as_u64),
        Some(
            u64::try_from(OCCURRENCE_PATH_COUNT)
                .unwrap_or_else(|error| panic!("occurrence count overflow: {error}"))
        )
    );
    assert_eq!(
        scope.get("sorted_newline_path_map_sha256").and_then(Value::as_str),
        Some(OCCURRENCE_PATH_MAP_SHA256)
    );
}

#[test]
fn k0_1_public_symbols_and_k0_2_semantics_are_exactly_joined() {
    let inventory = artifact();
    let symbols = k0_1_symbol_ids();
    let semantics = k0_2_semantic_ids();
    assert_eq!(symbols.len(), K0_1_SYMBOL_COUNT);
    assert_eq!(sorted_newline_sha256(&symbols), K0_1_SYMBOL_MAP_SHA256);
    assert_eq!(semantics.len(), K0_2_SEMANTIC_COUNT);
    assert_eq!(sorted_newline_sha256(&semantics), K0_2_SEMANTIC_MAP_SHA256);

    let joins = object(&inventory, "coverage_joins");
    assert_eq!(
        joins.get("k0_1_public_symbol_count").and_then(Value::as_u64),
        Some(30)
    );
    assert_eq!(
        joins.get("k0_1_public_symbol_id_set_sha256").and_then(Value::as_str),
        Some(K0_1_SYMBOL_MAP_SHA256)
    );
    assert_eq!(
        joins.get("k0_2_semantic_row_count").and_then(Value::as_u64),
        Some(97)
    );
    assert_eq!(
        joins.get("k0_2_semantic_id_set_sha256").and_then(Value::as_str),
        Some(K0_2_SEMANTIC_MAP_SHA256)
    );
    for row in array(&inventory, "local_inventory_rows") {
        for symbol in array(row, "k0_1_symbol_ids") {
            let symbol = symbol
                .as_str()
                .unwrap_or_else(|| panic!("k0_1_symbol_ids entries must be strings"));
            assert!(symbols.contains(symbol), "unknown K0.1 symbol {symbol}");
        }
    }
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
        "no tracked Kafka or rdkafka use under `examples/`",
        "provides no permission to remove",
    ] {
        assert!(doc.contains(phrase), "documentation phrase missing: {phrase}");
    }
}

#[test]
fn fail_closed_mutations_are_rejected() {
    let inventory = artifact();

    let mut removal = inventory.clone();
    removal["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&removal).is_err());

    let mut external_zero = inventory.clone();
    external_zero["external_searches"][0]["result_count"] = Value::from(0_u64);
    assert!(validate_inventory(&external_zero).is_err());

    let mut promoted = inventory.clone();
    promoted["evidence_claims"][2]["evidence_class"] =
        Value::String("REAL_BROKER_RECEIPT".to_owned());
    assert!(validate_inventory(&promoted).is_err());

    let mut missing_journey = inventory.clone();
    missing_journey["user_journeys"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("user_journeys must be an array"))
        .pop();
    assert!(validate_inventory(&missing_journey).is_err());

    let mut missing_handoff = inventory.clone();
    missing_handoff["k14_1_refresh_handoff"]["owner_bead"] = Value::Null;
    assert!(validate_inventory(&missing_handoff).is_err());
}
