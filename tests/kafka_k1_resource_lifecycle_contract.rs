//! Static contract for Kafka K1.4 resource and lifecycle ownership policy.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.2.1.4
//! Fixture: artifacts/kafka_k1_resource_lifecycle_contract_v1.json
//!
//! This integration test reads checked-in repository bytes only. It does not
//! compile a Kafka profile, contact a broker, execute lifecycle behavior, or
//! promote static inventory into runtime, leak, quiescence, or cutover proof.

#![allow(dead_code, missing_docs)]

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k1_resource_lifecycle_contract_v1.json";
const DOC_PATH: &str = "docs/kafka_k1_resource_lifecycle_contract.md";
const K1_1_PATH: &str = "artifacts/kafka_k1_obligation_index_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const K0_4_PATH: &str = "artifacts/kafka_broker_fixture_provenance_matrix_v1.json";
const K1_2_PATH: &str = "artifacts/kafka_k1_protocol_security_support_policy_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";

const ARTIFACT_SHA256: &str = "cfc4ef9c94aa6e3a32148977a57c6789a98bc20d96bef9abb17fdee9aa14bd30";
const DOC_SHA256: &str = "01f51a8331ed57529fcc6d744aa29e0fceb38d83b30a97c58382851a0e18e805";

const ARTIFACT_ID: &str = "kafka-k1-resource-lifecycle-contract-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1.4";
const PARENT_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const ADR_ID: &str = "DEP-ADR-009";
const CAPTURED_DATE_UTC: &str = "2026-08-04";
const BASELINE_REVISION: &str = "4b99ef71dbb1b7adbfbef4a3a9a4c2377fcbd6dd";
const INVENTORY_STATE: &str = "K1_4_RESOURCE_LIFECYCLE_OWNERSHIP_CONTRACT_FROZEN_KEEP_INCUMBENT";

const RESOURCE_COUNT: usize = 42;
const RESOURCE_SEMANTIC_BINDING_COUNT: usize = 43;
const RESOURCE_LIMIT_DIMENSION_COUNT: usize = 43;
const COMPOSITE_RESOURCE_COUNT: usize = 16;
const OPERATION_COUNT: usize = 19;
const DIMENSION_COUNT: usize = 7;
const TRANSITION_COUNT: usize = 133;
const SEMANTIC_COUNT: usize = 97;
const AUTHORITY_REFERENCE_COUNT: usize = 63;
const AUTHORITY_INPUT_COUNT: usize = 15;

const RESOURCE_ID_SHA256: &str = "e21f2fbe16b7d974b60cda3958e35e7cd0736eaa62c7003a8b7f6a0dbb194fcd";
const RESOURCE_CONTRACT_SHA256: &str =
    "7a7ecaaf1815c011b63a549623a33ecea4272f287f507adf49dba7a2f8617e5d";
const SEMANTIC_RESOURCE_BINDING_SHA256: &str =
    "bc625fbcca3de75d72d2bc2919cecc7636a94d6b25943bb37743d6c92b63ead9";
const RESOURCE_LIMIT_DIMENSION_SHA256: &str =
    "3aaf18e4916c55d659cb5e89bdc0f474d60d54fa1472957e549fd9138c06ee6e";
const OPERATION_ID_SHA256: &str =
    "e608943f31a0b005a825e5a70a3ee926462ed24c1bb5ae155ada73acae2a77ec";
const OPERATION_CONTRACT_SHA256: &str =
    "678914aed5298760076fd50b510a1862498805aab87f5295856da54d7d13d974";
const TRANSITION_CONTRACT_SHA256: &str =
    "2e3005cb5fec2a8f5aeef551619c65e22817e3dac4e2e2413d71e06771c499f3";
const AUTHORITY_REFERENCE_SHA256: &str =
    "634bb51f85fe7d54015ccc24a83b52590d23b77c11c9aa522dc89d9af88357e7";
const AUTHORITY_CONTRACT_SHA256: &str =
    "6a51fa1221869f3125a3ec478dc5e729eac868efc200a4779fdcaff35599cbf7";
const AUTHORITY_INPUT_CONTRACT_SHA256: &str =
    "914247782be90e795347fe0b17ef2c24f5739c873de7a6e277a5aa83b5ebbbe3";
const AUTHORITY_VIEWS_CONTRACT_SHA256: &str =
    "b7c9cb4e15efb45cdca0c64316e4869b9cd93302205a52e4cf12ad88a19cb6b7";
const POLICY_CONTRACT_SHA256: &str =
    "ec236faf14c33462c00c5c365e188b1a7089a3215329dd856699633ca4c2b396";
const SEMANTIC_COVERAGE_CONTRACT_SHA256: &str =
    "b86d984aa4061fe4770c4aeb7f639750193540deb4226522e48e1dfd6a441b27";
const CROSS_CUTTING_INVARIANT_SHA256: &str =
    "88438c4ffdb88a2320e223c994da4974d201d7569326dccf121bc4f6cd819492";
const OWNERSHIP_AND_GATES_SHA256: &str =
    "e9158de45af6a6143374b2770dfb28f3dffd969bca527a65a080221c05a8e88f";
const DISPOSITION_RECEIPT_SHA256: &str =
    "a07ad3388a220f670c68c8c01a3b4e7bc99aaf0ed641d4aacdf1556758f72023";
const PROJECTION_RULE_SHA256: &str =
    "582e80ec017c82800001a82312074b53957d79c8c688c50ed3c93a751b284718";
const NO_CLAIM_SHA256: &str = "bc5703ea9ef717f0796db249350ceafac85544acc31ef47f2da2b6ac33be9ce3";
const SEMANTIC_ID_SHA256: &str = "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7";
const SEMANTIC_ROW_SHA256: &str =
    "d19103e0fb6dd8b291405b1925c15d14cfacdf970901c766c10e06fcdbd7beab";
const SEMANTIC_CLASSIFICATION_SHA256: &str =
    "6bfbbd0e034be578cc508b99b2f7256f9511650632249fa485c5ab5bf1519e35";
const SHARED_OBLIGATION_SHA256: &str =
    "33d6b682820cff9f656ea6a3b6a88a32393c0f927ebce7a6b5ab2d5ab955752c";
const ROUTED_FINDING_ID_SHA256: &str =
    "752d9b0be528ea09c4eb06100e6b1ab1992d92f52cd8a8f9400f0d805e5223b0";
const ROUTED_FINDING_ROW_SHA256: &str =
    "cb04492d3a8e82d415833d06533ec311b72159c1a5e2b9051469e7b6e74ecae5";
const FAULT_VECTOR_ID_SHA256: &str =
    "c3da429cee7ac2fca222b5a288b9f76f78d88e01e5b6e32b4278104baa07c121";
const FAULT_VECTOR_ROW_SHA256: &str =
    "42e6f63b2040dea01e488ebd3f50b023ff3033ba18e25a3dd039ceac02237bf4";
const NEGOTIATION_ID_SHA256: &str =
    "851cd1f07553e7e8d3be8ae41b72ec95adf828b28140faa35e6c34890be802cd";
const BINDING_ID_SHA256: &str = "68a0173f6078475c82b908ba1c47daaa30e02a4cbf60aec3e000a707f47dd376";

const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K1.4 RESOURCE LIFECYCLE CONTRACT -->";
const DOC_END: &str = "<!-- END KAFKA K1.4 RESOURCE LIFECYCLE CONTRACT -->";

const ROOT_KEYS: &[&str] = &[
    "adr_id",
    "artifact_id",
    "authority",
    "authority_inputs",
    "authority_views",
    "baseline_revision",
    "bead_id",
    "capability_id",
    "captured_date_utc",
    "coverage_receipt",
    "cross_cutting_invariants",
    "disposition_receipt",
    "inventory_state",
    "lifecycle_operations",
    "no_claim_boundaries",
    "ownership_and_gates",
    "parent_bead_id",
    "policy",
    "program_id",
    "resource_classes",
    "resource_limit_dimensions",
    "schema_version",
    "semantic_coverage",
    "semantic_resource_bindings",
    "transition_dimensions",
];

const AUTHORITY_KEYS: &[&str] = &[
    "aggregate_contract_owner",
    "api_removal_allowed",
    "capability_removal_allowed",
    "claim_time_refresh_owner",
    "current_action",
    "cutover_allowed",
    "dependency_exit_allowed",
    "feature_removal_allowed",
    "file_deletion_allowed",
    "k0_semantic_authority",
    "k1_1_artifact",
    "k1_1_bead",
    "k1_2_artifact",
    "k1_2_bead",
    "k1_3_artifact",
    "k1_3_bead",
    "oracle_retirement_allowed",
    "production_wiring_allowed",
    "real_service_terminal_owner",
    "registry_disposition",
    "sole_conditional_cutover_owner",
    "verification_terminal_owner",
];

const POLICY_KEYS: &[&str] = &[
    "admission_rule",
    "backpressure_field_rule",
    "canonicalization_id",
    "changed_projection_state",
    "closed_flag_counts_as_quiescent",
    "composite_dimension_rule",
    "configured_hint_counts_as_local_cap",
    "cx_rule",
    "dependency_owned_counts_as_bounded",
    "duplicate_row_state",
    "extra_row_state",
    "incumbent_rule",
    "missing_input_state",
    "missing_row_state",
    "mode",
    "numeric_rule",
    "planned_counts_as_executed",
    "quiescence_rule",
    "resource_semantic_binding_rule",
    "runtime_claim_from_static_state",
    "static_counts_as_runtime",
    "transition_rule",
    "unowned_row_state",
];

const OWNERSHIP_KEYS: &[&str] = &[
    "aggregate_contract_owner",
    "claim_time_refresh_owner",
    "configuration_and_outcome_owner",
    "connection_owner",
    "consumer_flow_owner",
    "deterministic_quiescence_owner",
    "group_owner",
    "independent_terminal_owner",
    "lifecycle_model_owner",
    "migration_gate",
    "offset_owner",
    "policy_owner",
    "producer_owner",
    "real_lifecycle_terminal_owner",
    "real_service_terminal_owner",
    "resource_ledger_owner",
    "sole_cutover_owner",
    "transaction_owner",
    "unowned_operation_count",
    "unowned_resource_count",
];

const COVERAGE_KEYS: &[&str] = &[
    "authority_contract_sha256",
    "authority_input_contract_sha256",
    "authority_views_contract_sha256",
    "composite_resource_count",
    "cross_cutting_invariant_sha256",
    "disposition_receipt_sha256",
    "lifecycle_operation_count",
    "no_claim_boundary_sha256",
    "operation_contract_sha256",
    "operation_id_sha256",
    "ownership_and_gates_sha256",
    "policy_contract_sha256",
    "projection_rule",
    "projection_rule_sha256",
    "resource_class_count",
    "resource_contract_sha256",
    "resource_id_sha256",
    "resource_limit_dimension_count",
    "resource_limit_dimension_sha256",
    "resource_semantic_binding_count",
    "semantic_coverage_contract_sha256",
    "semantic_resource_binding_sha256",
    "source_authority_reference_sha256",
    "transition_cell_count",
    "transition_contract_sha256",
    "transition_dimension_count",
    "unique_source_authority_reference_count",
];

const DISPOSITION_KEYS: &[&str] = &[
    "api_removal_allowed",
    "capability_removal_allowed",
    "cutover_allowed",
    "dependency_exit_allowed",
    "dynamic_execution_claimed",
    "feature_removal_allowed",
    "file_deletion_allowed",
    "incumbent_disposition",
    "k1_1_complete",
    "k1_2_complete",
    "k1_3_complete",
    "k1_4_static_contract_complete",
    "k1_5_complete",
    "k1_parent_complete",
    "leak_freedom_proven",
    "migration_eligible",
    "on_missing_extra_duplicate_changed_unowned_unknown_unbounded_or_ambiguous",
    "oracle_retirement_allowed",
    "production_wiring_allowed",
    "quiescence_proven",
    "required_numeric_policy_complete",
    "runtime_lifecycle_proven",
    "runtime_resource_bounds_proven",
];

const AUTHORITY_INPUT_KEYS: &[&str] = &[
    "byte_count",
    "input_id",
    "path",
    "record_count",
    "role",
    "sha256",
];

const RESOURCE_KEYS: &[&str] = &[
    "accounting_invariant",
    "admission_outcome",
    "current_default",
    "current_maximum_or_hard_cap",
    "current_minimum",
    "current_numeric_state",
    "gap_state",
    "implementation_owner",
    "overflow_behavior",
    "owner_scope",
    "release_point",
    "required_default",
    "required_maximum_or_hard_cap",
    "required_minimum",
    "required_numeric_state",
    "resource_class",
    "resource_id",
    "source_authority_ids",
    "terminal_gates",
    "unit",
    "verification_owner",
];

const SEMANTIC_RESOURCE_BINDING_KEYS: &[&str] = &["resource_ids", "semantic_id"];

const RESOURCE_LIMIT_DIMENSION_KEYS: &[&str] = &[
    "current_default",
    "current_maximum_or_hard_cap",
    "current_minimum",
    "current_numeric_state",
    "dimension_id",
    "required_default",
    "required_maximum_or_hard_cap",
    "required_minimum",
    "required_numeric_state",
    "resource_id",
    "unit",
];

const OPERATION_KEYS: &[&str] = &[
    "current_evidence_state",
    "entry_admission",
    "gate_state",
    "implementation_owner",
    "operation",
    "operation_id",
    "release_accounting",
    "source_authority_ids",
    "state_set",
    "terminal_gates",
    "transitions",
    "verification_owner",
];

const TRANSITION_KEYS: &[&str] = &[
    "certainty",
    "current_rule",
    "current_to_states",
    "dimension",
    "from_states",
    "gate_state",
    "owner",
    "required_to_state",
];

const TRANSITION_DIMENSIONS: &[&str] = &[
    "timeout",
    "cancellation",
    "shutdown",
    "panic",
    "retry",
    "restart",
    "ambiguous_outcome",
];

const RESOURCE_CLASSES: &[&str] = &[
    "broker_connections",
    "inflight_requests_and_correlations",
    "metadata_routing_and_coordinator_cache",
    "producer_message_payload",
    "producer_topic_key_headers_and_framing",
    "producer_batch_target",
    "producer_delivery_queue",
    "producer_retry_attempt_budget",
    "producer_request_timer_budget",
    "producer_active_operations",
    "deterministic_broker_records",
    "transaction_handles",
    "transaction_staged_records",
    "transaction_coordinator_partition_and_offset_state",
    "consumer_subscription_topics",
    "consumer_group_assignment_and_rebalance_state",
    "consumer_buffered_outcome",
    "consumer_fetched_record_memory",
    "consumer_commit_batch",
    "consumer_offset_and_position_maps",
    "consumer_retry_attempt_budget",
    "cx_blocking_pool_pending_tasks",
    "fallback_blocking_threads",
    "fallback_blocking_waiters",
    "retained_configuration_state_errors_and_diagnostics",
    "native_background_threads_callbacks_and_queues",
    "producer_linger_timer_budget",
    "producer_retry_backoff_timer_budget",
    "producer_flush_close_caller_deadline",
    "producer_flush_close_poll_slice",
    "transaction_timeout_budget",
    "consumer_session_timeout_budget",
    "consumer_heartbeat_interval_budget",
    "consumer_commit_retry_backoff_timer_budget",
    "consumer_auto_commit_interval_budget",
    "consumer_fetch_wait_budget",
    "consumer_poll_caller_deadline",
    "consumer_broker_poll_slice",
    "consumer_seek_timeout_budget",
    "diagnostic_kafka_client_session_timeout_budget",
    "diagnostic_kafka_client_consumer_slot",
    "consumer_broker_operation_mutex_holders_and_waiters",
];

const COMPOSITE_RESOURCE_IDS: &[&str] = &[
    "K1R-003", "K1R-005", "K1R-007", "K1R-011", "K1R-013", "K1R-014", "K1R-015", "K1R-016",
    "K1R-018", "K1R-019", "K1R-020", "K1R-022", "K1R-025", "K1R-026", "K1R-041", "K1R-042",
];

const OPERATIONS: &[&str] = &[
    "producer_construction_and_native_lifetime",
    "producer_send_and_delivery",
    "producer_flush",
    "producer_close",
    "transactional_producer_construction",
    "transaction_begin_and_recovery",
    "transaction_send_and_delivery",
    "transaction_commit",
    "transaction_abort",
    "unfinished_transaction_drop_recovery",
    "consumer_construction_and_native_lifetime",
    "consumer_subscribe",
    "consumer_rebalance",
    "consumer_poll",
    "consumer_commit_offsets",
    "consumer_seek",
    "consumer_close",
    "kafka_client_diagnostic_consumer_lifetime",
    "dependency_auto_commit_heartbeat_and_background_state",
];

#[derive(Clone)]
struct Inputs {
    artifact: Value,
    k1_1: Value,
    k0_2: Value,
    k0_4: Value,
    k1_2: Value,
    tracker: Vec<Value>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_bytes(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    fs::read(root.join(path)).map_err(|error| format!("failed to read {path}: {error}"))
}

fn read_text(root: &Path, path: &str) -> Result<String, String> {
    String::from_utf8(read_bytes(root, path)?)
        .map_err(|error| format!("{path} is not UTF-8: {error}"))
}

fn parse_json(root: &Path, path: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(root, path)?)
        .map_err(|error| format!("invalid JSON in {path}: {error}"))
}

fn parse_jsonl(root: &Path, path: &str) -> Result<Vec<Value>, String> {
    read_text(root, path)?
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("invalid JSONL in {path} line {}: {error}", index + 1))
        })
        .collect()
}

fn load_inputs(root: &Path) -> Result<Inputs, String> {
    Ok(Inputs {
        artifact: parse_json(root, ARTIFACT_PATH)?,
        k1_1: parse_json(root, K1_1_PATH)?,
        k0_2: parse_json(root, K0_2_PATH)?,
        k0_4: parse_json(root, K0_4_PATH)?,
        k1_2: parse_json(root, K1_2_PATH)?,
        tracker: parse_jsonl(root, TRACKER_PATH)?,
    })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sorted_newline_sha256(mut rows: Vec<String>) -> String {
    rows.sort();
    rows.dedup();
    let mut hasher = Sha256::new();
    for row in rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = Map::new();
            for (key, nested) in entries {
                canonical.insert(key.clone(), canonicalize(nested));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(&canonicalize(value))
        .map_err(|error| format!("failed to canonicalize JSON: {error}"))
}

fn canonical_rows_sha256(rows: &[Value]) -> Result<String, String> {
    let canonical_rows = rows
        .iter()
        .map(canonical_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(sorted_newline_sha256(canonical_rows))
}

fn canonical_value_sha256(value: &Value) -> Result<String, String> {
    canonical_rows_sha256(std::slice::from_ref(value))
}

fn is_promoted_state(state: &str) -> bool {
    let delimited = format!("_{state}_");
    [
        "SUPPORTED",
        "PASS",
        "EXECUTED",
        "REAL_BROKER_RECEIPT",
        "ACTUAL_BINARY_RECEIPT",
        "MIGRATION_ELIGIBLE",
        "VERIFIED_GREEN",
        "PROVEN",
    ]
    .iter()
    .any(|forbidden| delimited.contains(&format!("_{forbidden}_")))
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("{key} must be non-empty text"))
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn count(value: &Value, key: &str) -> Result<usize, String> {
    usize::try_from(number(value, key)?).map_err(|_| format!("{key} does not fit in usize"))
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{label} key drift: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn string_set(values: &[Value], label: &str) -> Result<BTreeSet<String>, String> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|field| !field.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} contains non-text or empty value"))
        })
        .collect()
}

fn ids(rows: &[Value], key: &str) -> Result<Vec<String>, String> {
    rows.iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect()
}

fn ensure_unique(values: &[String], label: &str) -> Result<(), String> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{label} contains duplicates"));
    }
    Ok(())
}

fn expect_text(value: &Value, key: &str, expected: &str) -> Result<(), String> {
    let actual = text(value, key)?;
    if actual != expected {
        return Err(format!("{key} mismatch: expected {expected}, got {actual}"));
    }
    Ok(())
}

fn expect_number(value: &Value, key: &str, expected: u64) -> Result<(), String> {
    let actual = number(value, key)?;
    if actual != expected {
        return Err(format!("{key} mismatch: expected {expected}, got {actual}"));
    }
    Ok(())
}

fn expect_bool(value: &Value, key: &str, expected: bool) -> Result<(), String> {
    let actual = bool_field(value, key)?;
    if actual != expected {
        return Err(format!("{key} mismatch: expected {expected}, got {actual}"));
    }
    Ok(())
}

fn semantic_rows(k0_2: &Value) -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        rows.extend(array(k0_2, collection)?.iter().cloned());
    }
    Ok(rows)
}

fn validate_identity(artifact: &Value) -> Result<(), String> {
    exact_keys(artifact, ROOT_KEYS, "artifact root")?;
    expect_number(artifact, "schema_version", 1)?;
    expect_text(artifact, "artifact_id", ARTIFACT_ID)?;
    expect_text(artifact, "program_id", PROGRAM_ID)?;
    expect_text(artifact, "bead_id", BEAD_ID)?;
    expect_text(artifact, "parent_bead_id", PARENT_BEAD_ID)?;
    expect_text(artifact, "capability_id", CAPABILITY_ID)?;
    expect_text(artifact, "adr_id", ADR_ID)?;
    expect_text(artifact, "captured_date_utc", CAPTURED_DATE_UTC)?;
    expect_text(artifact, "baseline_revision", BASELINE_REVISION)?;
    expect_text(artifact, "inventory_state", INVENTORY_STATE)?;

    let authority = artifact
        .get("authority")
        .ok_or_else(|| "authority is missing".to_owned())?;
    exact_keys(authority, AUTHORITY_KEYS, "authority")?;
    expect_text(authority, "current_action", "KEEP_INCUMBENT")?;
    expect_text(authority, "registry_disposition", "KEEP_UNTIL_PARITY")?;
    for key in [
        "dependency_exit_allowed",
        "feature_removal_allowed",
        "api_removal_allowed",
        "capability_removal_allowed",
        "file_deletion_allowed",
        "production_wiring_allowed",
        "oracle_retirement_allowed",
        "cutover_allowed",
    ] {
        expect_bool(authority, key, false)?;
    }

    let policy = artifact
        .get("policy")
        .ok_or_else(|| "policy is missing".to_owned())?;
    exact_keys(policy, POLICY_KEYS, "policy")?;
    expect_text(policy, "mode", "STATIC_ONLY_FAIL_CLOSED")?;
    expect_text(
        policy,
        "canonicalization_id",
        "KAFKA_K1_4_RESOURCE_LIFECYCLE_CONTRACT_V1",
    )?;
    for key in [
        "planned_counts_as_executed",
        "static_counts_as_runtime",
        "dependency_owned_counts_as_bounded",
        "configured_hint_counts_as_local_cap",
        "closed_flag_counts_as_quiescent",
    ] {
        expect_bool(policy, key, false)?;
    }
    Ok(())
}

fn validate_file_hashes_and_inputs(root: &Path, artifact: &Value) -> Result<(), String> {
    let artifact_bytes = read_bytes(root, ARTIFACT_PATH)?;
    if sha256_bytes(&artifact_bytes) != ARTIFACT_SHA256 {
        return Err("artifact byte hash drift".to_owned());
    }
    let doc_bytes = read_bytes(root, DOC_PATH)?;
    if sha256_bytes(&doc_bytes) != DOC_SHA256 {
        return Err("document byte hash drift".to_owned());
    }

    let rows = array(artifact, "authority_inputs")?;
    if rows.len() != AUTHORITY_INPUT_COUNT {
        return Err(format!(
            "authority input count mismatch: expected {AUTHORITY_INPUT_COUNT}, got {}",
            rows.len()
        ));
    }
    let input_ids = ids(rows, "input_id")?;
    ensure_unique(&input_ids, "authority input IDs")?;
    let paths = ids(rows, "path")?;
    ensure_unique(&paths, "authority input paths")?;

    for row in rows {
        exact_keys(row, AUTHORITY_INPUT_KEYS, "authority input")?;
        text(row, "role")?;
        let path = text(row, "path")?;
        let bytes = read_bytes(root, path)?;
        let expected_bytes = count(row, "byte_count")?;
        if bytes.len() != expected_bytes {
            return Err(format!(
                "authority input {path} byte count drift: expected {expected_bytes}, got {}",
                bytes.len()
            ));
        }
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| format!("authority input {path} is not UTF-8: {error}"))?;
        let expected_records = count(row, "record_count")?;
        if source.lines().count() != expected_records {
            return Err(format!(
                "authority input {path} record count drift: expected {expected_records}, got {}",
                source.lines().count()
            ));
        }
        let expected_hash = text(row, "sha256")?;
        let actual_hash = sha256_bytes(&bytes);
        if actual_hash != expected_hash {
            return Err(format!(
                "authority input {path} hash drift: expected {expected_hash}, got {actual_hash}"
            ));
        }
    }
    Ok(())
}

fn validate_authority_views(inputs: &Inputs) -> Result<BTreeSet<String>, String> {
    let views = inputs
        .artifact
        .get("authority_views")
        .ok_or_else(|| "authority_views is missing".to_owned())?;

    let shared_view = views
        .get("k1_4_shared_obligations")
        .ok_or_else(|| "k1_4_shared_obligations view is missing".to_owned())?;
    expect_number(shared_view, "row_count", 3)?;
    expect_text(
        shared_view,
        "canonical_row_sha256",
        SHARED_OBLIGATION_SHA256,
    )?;
    let shared_rows = array(shared_view, "rows")?;
    let actual_shared = inputs
        .k1_1
        .get("namespace_projection")
        .and_then(|value| value.get("derived_shared_obligations"))
        .and_then(|value| value.get("rows"))
        .and_then(Value::as_array)
        .ok_or_else(|| "K1.1 derived shared obligations are missing".to_owned())?
        .iter()
        .filter(|row| row.get("k1_policy_owner").and_then(Value::as_str) == Some(BEAD_ID))
        .map(|row| {
            Ok(json!({
                "obligation_id": text(row, "obligation_id")?,
                "source_key": text(row, "source_key")?,
                "protocol_binding_policy": text(row, "protocol_binding_policy")?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if actual_shared.len() != 3
        || canonical_rows_sha256(&actual_shared)? != SHARED_OBLIGATION_SHA256
        || canonical_rows_sha256(shared_rows)? != SHARED_OBLIGATION_SHA256
    {
        return Err("K1.4 shared-obligation projection drift".to_owned());
    }

    let semantic_rows = semantic_rows(&inputs.k0_2)?;
    if semantic_rows.len() != SEMANTIC_COUNT {
        return Err(format!(
            "K0.2 semantic row count mismatch: expected {SEMANTIC_COUNT}, got {}",
            semantic_rows.len()
        ));
    }
    let semantic_ids = ids(&semantic_rows, "semantic_id")?;
    ensure_unique(&semantic_ids, "K0.2 semantic IDs")?;
    if sorted_newline_sha256(semantic_ids.clone()) != SEMANTIC_ID_SHA256
        || canonical_rows_sha256(&semantic_rows)? != SEMANTIC_ROW_SHA256
    {
        return Err("K0.2 semantic authority digest drift".to_owned());
    }
    let semantic_view = views
        .get("k0_2_semantic_rows")
        .ok_or_else(|| "k0_2_semantic_rows view is missing".to_owned())?;
    expect_number(semantic_view, "row_count", 97)?;
    expect_text(semantic_view, "id_set_sha256", SEMANTIC_ID_SHA256)?;
    expect_text(semantic_view, "canonical_row_sha256", SEMANTIC_ROW_SHA256)?;

    let coverage = inputs
        .artifact
        .get("semantic_coverage")
        .ok_or_else(|| "semantic_coverage is missing".to_owned())?;
    expect_number(coverage, "classified_row_count", 97)?;
    expect_number(coverage, "unclassified_row_count", 0)?;
    expect_number(coverage, "duplicate_classification_count", 0)?;
    expect_text(
        coverage,
        "classification_projection_sha256",
        SEMANTIC_CLASSIFICATION_SHA256,
    )?;
    let classifications = array(coverage, "classifications")?;
    if classifications.len() != 3
        || canonical_rows_sha256(classifications)? != SEMANTIC_CLASSIFICATION_SHA256
    {
        return Err("semantic classification projection drift".to_owned());
    }
    let mut classification_counts = BTreeMap::new();
    let mut classified_ids = Vec::new();
    for row in classifications {
        let classification = text(row, "classification")?;
        let row_ids = array(row, "semantic_ids")?;
        classification_counts.insert(classification, row_ids.len());
        classified_ids.extend(string_set(row_ids, "semantic classification IDs")?);
        text(row, "reason")?;
    }
    let expected_counts = BTreeMap::from([
        ("CONTEXT_ONLY_NOT_A_DISTINCT_LONG_LIVED_OPERATION", 28usize),
        ("RESOURCE", 43usize),
        ("RESOURCE_AND_LIFECYCLE", 26usize),
    ]);
    if classification_counts != expected_counts {
        return Err(format!(
            "semantic classification counts drift: expected {expected_counts:?}, got {classification_counts:?}"
        ));
    }
    ensure_unique(&classified_ids, "classified semantic IDs")?;
    if classified_ids.into_iter().collect::<BTreeSet<_>>()
        != semantic_ids.into_iter().collect::<BTreeSet<_>>()
    {
        return Err("semantic coverage does not exactly equal K0.2 authority".to_owned());
    }

    let findings = array(&inputs.k0_2, "routed_findings")?;
    let finding_ids = ids(findings, "finding_id")?;
    ensure_unique(&finding_ids, "K0.2 routed finding IDs")?;
    if finding_ids.len() != 23
        || sorted_newline_sha256(finding_ids.clone()) != ROUTED_FINDING_ID_SHA256
        || canonical_rows_sha256(findings)? != ROUTED_FINDING_ROW_SHA256
    {
        return Err("K0.2 routed-finding authority drift".to_owned());
    }
    let finding_view = views
        .get("k0_2_routed_findings")
        .ok_or_else(|| "k0_2_routed_findings view is missing".to_owned())?;
    expect_number(finding_view, "row_count", 23)?;
    expect_text(finding_view, "id_set_sha256", ROUTED_FINDING_ID_SHA256)?;
    expect_text(
        finding_view,
        "canonical_row_sha256",
        ROUTED_FINDING_ROW_SHA256,
    )?;

    let faults = array(&inputs.k0_4, "fault_lifecycle_vectors")?;
    let fault_ids = ids(faults, "vector_id")?;
    ensure_unique(&fault_ids, "K0.4 fault vector IDs")?;
    if fault_ids.len() != 6
        || sorted_newline_sha256(fault_ids.clone()) != FAULT_VECTOR_ID_SHA256
        || canonical_rows_sha256(faults)? != FAULT_VECTOR_ROW_SHA256
    {
        return Err("K0.4 fault-vector authority drift".to_owned());
    }
    let fault_view = views
        .get("k0_4_fault_vectors")
        .ok_or_else(|| "k0_4_fault_vectors view is missing".to_owned())?;
    expect_number(fault_view, "row_count", 6)?;
    expect_text(fault_view, "id_set_sha256", FAULT_VECTOR_ID_SHA256)?;
    expect_text(fault_view, "canonical_row_sha256", FAULT_VECTOR_ROW_SHA256)?;
    if string_set(array(fault_view, "required_ids")?, "required fault IDs")?
        != fault_ids.iter().cloned().collect()
    {
        return Err("K0.4 required fault-vector IDs drift".to_owned());
    }

    let negotiation = array(&inputs.k1_2, "negotiation_transition_cells")?;
    let negotiation_ids = ids(negotiation, "cell_id")?;
    if negotiation.len() != 10 || sorted_newline_sha256(negotiation_ids) != NEGOTIATION_ID_SHA256 {
        return Err("K1.2 negotiation-transition authority drift".to_owned());
    }
    let negotiation_view = views
        .get("k1_2_negotiation_transitions")
        .ok_or_else(|| "k1_2_negotiation_transitions view is missing".to_owned())?;
    expect_number(negotiation_view, "row_count", 10)?;
    expect_text(negotiation_view, "id_set_sha256", NEGOTIATION_ID_SHA256)?;

    let bindings = array(&inputs.k1_2, "protocol_binding_groups")?;
    let binding_ids = ids(bindings, "cell_id")?;
    if bindings.len() != 10 || sorted_newline_sha256(binding_ids) != BINDING_ID_SHA256 {
        return Err("K1.2 protocol-binding authority drift".to_owned());
    }
    let binding_view = views
        .get("k1_2_protocol_binding_groups")
        .ok_or_else(|| "k1_2_protocol_binding_groups view is missing".to_owned())?;
    expect_number(binding_view, "row_count", 10)?;
    expect_text(binding_view, "id_set_sha256", BINDING_ID_SHA256)?;
    if !text(binding_view, "coverage_limitation")?.contains("not exhaustive") {
        return Err("K1.2 binding coverage limitation was weakened".to_owned());
    }

    let mut authority_ids = BTreeSet::new();
    authority_ids.extend(
        actual_shared
            .iter()
            .map(|row| text(row, "obligation_id").map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?,
    );
    authority_ids.extend(
        semantic_rows
            .iter()
            .map(|row| text(row, "semantic_id").map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?,
    );
    authority_ids.extend(finding_ids);
    authority_ids.extend(fault_ids);
    Ok(authority_ids)
}

fn optional_u64(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be null or an unsigned integer")),
        None => Err(format!("{key} is missing")),
    }
}

fn validate_numeric_order(row: &Value, prefix: &str, row_id: &str) -> Result<(), String> {
    let minimum = optional_u64(row, &format!("{prefix}_minimum"))?;
    let default = optional_u64(row, &format!("{prefix}_default"))?;
    let maximum = optional_u64(row, &format!("{prefix}_maximum_or_hard_cap"))?;
    if minimum
        .zip(default)
        .is_some_and(|(min, default)| min > default)
        || default
            .zip(maximum)
            .is_some_and(|(default, max)| default > max)
        || minimum.zip(maximum).is_some_and(|(min, max)| min > max)
    {
        return Err(format!("{row_id} has invalid {prefix} numeric ordering"));
    }
    Ok(())
}

fn validate_resource_rows(
    artifact: &Value,
    authority_ids: &BTreeSet<String>,
) -> Result<Vec<Value>, String> {
    let rows = array(artifact, "resource_classes")?;
    if rows.len() != RESOURCE_COUNT {
        return Err(format!(
            "resource count mismatch: expected {RESOURCE_COUNT}, got {}",
            rows.len()
        ));
    }
    let row_ids = ids(rows, "resource_id")?;
    ensure_unique(&row_ids, "resource IDs")?;
    let expected_ids = (1..=RESOURCE_COUNT)
        .map(|index| format!("K1R-{index:03}"))
        .collect::<BTreeSet<_>>();
    if row_ids.iter().cloned().collect::<BTreeSet<_>>() != expected_ids {
        return Err("resource ID set drift".to_owned());
    }
    let classes = ids(rows, "resource_class")?;
    ensure_unique(&classes, "resource classes")?;
    if classes.iter().map(String::as_str).collect::<BTreeSet<_>>()
        != RESOURCE_CLASSES.iter().copied().collect()
    {
        return Err("resource class set drift".to_owned());
    }

    for row in rows {
        exact_keys(row, RESOURCE_KEYS, "resource row")?;
        let row_id = text(row, "resource_id")?;
        for key in [
            "unit",
            "current_numeric_state",
            "required_numeric_state",
            "admission_outcome",
            "overflow_behavior",
            "owner_scope",
            "release_point",
            "accounting_invariant",
            "implementation_owner",
            "verification_owner",
        ] {
            text(row, key)?;
        }
        validate_numeric_order(row, "current", row_id)?;
        validate_numeric_order(row, "required", row_id)?;
        let current_state = text(row, "current_numeric_state")?;
        let required_state = text(row, "required_numeric_state")?;
        let gap_state = text(row, "gap_state")?;
        if is_promoted_state(current_state)
            || is_promoted_state(required_state)
            || is_promoted_state(gap_state)
            || !required_state.contains("BLOCKING")
            || !gap_state.starts_with("BLOCKING")
        {
            return Err(format!("{row_id} promoted a blocking numeric or gap state"));
        }
        let required_numbers = [
            optional_u64(row, "required_default")?,
            optional_u64(row, "required_minimum")?,
            optional_u64(row, "required_maximum_or_hard_cap")?,
        ];
        if required_numbers.iter().any(Option::is_none) && !required_state.contains("BLOCKING") {
            return Err(format!(
                "{row_id} has an unblocked null required numeric field"
            ));
        }
        if required_state.contains("HARD_CAP")
            && optional_u64(row, "required_maximum_or_hard_cap")?.is_none()
        {
            return Err(format!("{row_id} removed its declared required hard cap"));
        }
        let refs = string_set(
            array(row, "source_authority_ids")?,
            "resource authority IDs",
        )?;
        if refs.is_empty() || !refs.is_subset(authority_ids) {
            return Err(format!("{row_id} has unresolved source authority"));
        }
        let gates = string_set(array(row, "terminal_gates")?, "resource terminal gates")?;
        if gates.is_empty() {
            return Err(format!("{row_id} has no terminal gate"));
        }
    }

    let by_id = rows
        .iter()
        .map(|row| Ok((text(row, "resource_id")?, row)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if optional_u64(by_id["K1R-004"], "current_default")? != Some(1_048_576)
        || optional_u64(by_id["K1R-006"], "current_default")? != Some(16_384)
        || optional_u64(by_id["K1R-012"], "required_maximum_or_hard_cap")? != Some(1)
        || optional_u64(by_id["K1R-017"], "current_maximum_or_hard_cap")? != Some(1)
        || optional_u64(by_id["K1R-023"], "current_maximum_or_hard_cap")? != Some(256)
        || optional_u64(by_id["K1R-024"], "current_maximum_or_hard_cap")?.is_some()
        || optional_u64(by_id["K1R-028"], "current_maximum_or_hard_cap")? != Some(250)
        || optional_u64(by_id["K1R-030"], "current_default")?.is_some()
        || optional_u64(by_id["K1R-030"], "current_minimum")? != Some(1)
        || optional_u64(by_id["K1R-030"], "current_maximum_or_hard_cap")? != Some(10_000_000)
        || optional_u64(by_id["K1R-031"], "current_default")? != Some(60_000)
        || optional_u64(by_id["K1R-032"], "current_default")? != Some(45_000)
        || optional_u64(by_id["K1R-033"], "current_default")? != Some(3_000)
        || optional_u64(by_id["K1R-034"], "current_maximum_or_hard_cap")? != Some(5_000)
        || optional_u64(by_id["K1R-035"], "current_default")? != Some(5_000)
        || optional_u64(by_id["K1R-036"], "current_default")? != Some(500)
        || optional_u64(by_id["K1R-038"], "current_default")?.is_some()
        || optional_u64(by_id["K1R-038"], "current_maximum_or_hard_cap")? != Some(50)
        || optional_u64(by_id["K1R-039"], "current_maximum_or_hard_cap")? != Some(1_000)
        || optional_u64(by_id["K1R-040"], "current_maximum_or_hard_cap")? != Some(6_000)
        || optional_u64(by_id["K1R-041"], "current_maximum_or_hard_cap")? != Some(1)
        || optional_u64(by_id["K1R-042"], "current_maximum_or_hard_cap")?.is_some()
    {
        return Err("high-risk resource numeric facts drift".to_owned());
    }
    if !text(by_id["K1R-018"], "admission_outcome")?.contains("max_poll_records")
        || !text(by_id["K1R-018"], "admission_outcome")?.contains("inert")
        || !text(by_id["K1R-023"], "owner_scope")?.contains("Process-global")
        || !text(by_id["K1R-024"], "current_numeric_state")?.contains("UNBOUNDED")
        || !text(by_id["K1R-010"], "current_numeric_state")?.contains("ATOMIC_USIZE")
        || !text(by_id["K1R-010"], "release_point")?.contains("cancellation")
        || !text(by_id["K1R-010"], "release_point")?.contains("unwind")
        || !text(by_id["K1R-034"], "current_numeric_state")?.contains("TRUNCATION")
        || !text(by_id["K1R-042"], "current_numeric_state")?.contains("INLINE_EXECUTION")
    {
        return Err("high-risk resource boundary wording drift".to_owned());
    }
    let fallback_consumer_operations = [
        "KCO-OP-004",
        "KCO-OP-005",
        "KCO-OP-006",
        "KCO-OP-007",
        "KCO-OP-008",
        "KCO-OP-009",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for resource_id in ["K1R-023", "K1R-024", "K1R-042"] {
        let refs = string_set(
            array(by_id[resource_id], "source_authority_ids")?,
            "fallback consumer operation authority IDs",
        )?;
        if !fallback_consumer_operations.is_subset(&refs) {
            return Err(format!(
                "{resource_id} omits a consumer operation sharing the fallback bridge"
            ));
        }
    }
    let pool_refs = string_set(
        array(by_id["K1R-022"], "source_authority_ids")?,
        "Cx blocking-pool authority IDs",
    )?;
    let producer_blocking_operations = ["KPR-OP-010", "KPR-OP-013", "KPR-OP-014"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if !pool_refs.is_disjoint(&fallback_consumer_operations) {
        return Err(
            "K1R-022 falsely attributes a direct fallback consumer operation to the Cx pool"
                .to_owned(),
        );
    }
    if !producer_blocking_operations.is_subset(&pool_refs) {
        return Err("K1R-022 omits a producer operation that can use the Cx pool".to_owned());
    }
    for resource_id in ["K1R-023", "K1R-024"] {
        let refs = string_set(
            array(by_id[resource_id], "source_authority_ids")?,
            "fallback producer operation authority IDs",
        )?;
        if !producer_blocking_operations.is_subset(&refs) {
            return Err(format!(
                "{resource_id} omits a producer operation sharing the fallback bridge"
            ));
        }
    }
    Ok(rows.clone())
}

fn validate_resource_semantic_bindings(
    artifact: &Value,
    resource_rows: &[Value],
    operation_rows: &[Value],
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let resource_ids = ids(resource_rows, "resource_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let classifications = array(
        artifact
            .get("semantic_coverage")
            .ok_or_else(|| "semantic_coverage is missing".to_owned())?,
        "classifications",
    )?;
    let resource_semantic_ids = classifications
        .iter()
        .find(|row| row.get("classification").and_then(Value::as_str) == Some("RESOURCE"))
        .ok_or_else(|| "RESOURCE semantic classification is missing".to_owned())
        .and_then(|row| string_set(array(row, "semantic_ids")?, "RESOURCE semantic IDs"))?;
    let lifecycle_semantic_ids = classifications
        .iter()
        .find(|row| {
            row.get("classification").and_then(Value::as_str) == Some("RESOURCE_AND_LIFECYCLE")
        })
        .ok_or_else(|| "RESOURCE_AND_LIFECYCLE semantic classification is missing".to_owned())
        .and_then(|row| {
            string_set(
                array(row, "semantic_ids")?,
                "RESOURCE_AND_LIFECYCLE semantic IDs",
            )
        })?;
    let direct_authority_joins = resource_rows
        .iter()
        .chain(operation_rows)
        .flat_map(|row| {
            row.get("source_authority_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let missing_lifecycle_joins = lifecycle_semantic_ids
        .difference(&direct_authority_joins)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_lifecycle_joins.is_empty() {
        return Err(format!(
            "RESOURCE_AND_LIFECYCLE semantics lack direct authority joins: {missing_lifecycle_joins:?}"
        ));
    }

    let bindings = array(artifact, "semantic_resource_bindings")?;
    if bindings.len() != RESOURCE_SEMANTIC_BINDING_COUNT {
        return Err(format!(
            "resource semantic binding count mismatch: expected {RESOURCE_SEMANTIC_BINDING_COUNT}, got {}",
            bindings.len()
        ));
    }
    let binding_ids = ids(bindings, "semantic_id")?;
    ensure_unique(&binding_ids, "resource semantic binding IDs")?;
    if binding_ids.iter().cloned().collect::<BTreeSet<_>>() != resource_semantic_ids {
        return Err(
            "RESOURCE semantic classification is not exactly bound to resources".to_owned(),
        );
    }

    let mut by_semantic = BTreeMap::new();
    for row in bindings {
        exact_keys(
            row,
            SEMANTIC_RESOURCE_BINDING_KEYS,
            "semantic resource binding",
        )?;
        let semantic_id = text(row, "semantic_id")?;
        let bound = string_set(array(row, "resource_ids")?, "bound resource IDs")?;
        if bound.is_empty() || !bound.is_subset(&resource_ids) {
            return Err(format!(
                "{semantic_id} has an empty or unresolved resource binding"
            ));
        }
        by_semantic.insert(semantic_id, bound);
    }
    for (semantic_id, expected) in [
        ("KPR-CFG-004", &["K1R-027", "K1R-028"][..]),
        ("KPR-CFG-025", &["K1R-031"][..]),
        ("KCO-CFG-004", &["K1R-032"][..]),
        ("KCO-CFG-005", &["K1R-033", "K1R-034"][..]),
        ("KCO-CFG-008", &["K1R-035"][..]),
        ("KCO-CFG-012", &["K1R-036"][..]),
    ] {
        let expected = expected.iter().map(|value| (*value).to_owned()).collect();
        if by_semantic.get(semantic_id) != Some(&expected) {
            return Err(format!("{semantic_id} timer binding drift"));
        }
    }

    let dimensions = array(artifact, "resource_limit_dimensions")?;
    if dimensions.len() != RESOURCE_LIMIT_DIMENSION_COUNT {
        return Err(format!(
            "resource limit dimension count mismatch: expected {RESOURCE_LIMIT_DIMENSION_COUNT}, got {}",
            dimensions.len()
        ));
    }
    let mut dimension_keys = BTreeSet::new();
    let mut dimension_resource_ids = BTreeSet::new();
    for row in dimensions {
        exact_keys(
            row,
            RESOURCE_LIMIT_DIMENSION_KEYS,
            "resource limit dimension",
        )?;
        let resource_id = text(row, "resource_id")?;
        let dimension_id = text(row, "dimension_id")?;
        if !resource_ids.contains(resource_id)
            || !dimension_keys.insert((resource_id.to_owned(), dimension_id.to_owned()))
        {
            return Err(format!(
                "duplicate or unresolved resource limit dimension {resource_id}/{dimension_id}"
            ));
        }
        text(row, "unit")?;
        validate_numeric_order(row, "current", dimension_id)?;
        validate_numeric_order(row, "required", dimension_id)?;
        let current_state = text(row, "current_numeric_state")?;
        let required_state = text(row, "required_numeric_state")?;
        if is_promoted_state(current_state)
            || is_promoted_state(required_state)
            || !required_state.starts_with("BLOCKING_")
        {
            return Err(format!(
                "{resource_id}/{dimension_id} promoted a limit state"
            ));
        }
        dimension_resource_ids.insert(resource_id.to_owned());
    }
    let expected_composite = COMPOSITE_RESOURCE_IDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    if dimension_resource_ids != expected_composite
        || dimension_resource_ids.len() != COMPOSITE_RESOURCE_COUNT
    {
        return Err("composite resource limit-dimension coverage drift".to_owned());
    }

    let dimensions_by_key = dimensions
        .iter()
        .map(|row| {
            Ok((
                (
                    text(row, "resource_id")?.to_owned(),
                    text(row, "dimension_id")?.to_owned(),
                ),
                row,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    for dimension_id in [
        "delivery_queue_record_count",
        "delivery_queue_record_and_envelope_bytes",
    ] {
        let row = dimensions_by_key
            .get(&("K1R-007".to_owned(), dimension_id.to_owned()))
            .ok_or_else(|| format!("K1R-007/{dimension_id} is missing"))?;
        if optional_u64(row, "current_default")?.is_some()
            || optional_u64(row, "current_minimum")?.is_some()
            || optional_u64(row, "current_maximum_or_hard_cap")?.is_some()
            || text(row, "current_numeric_state")? != "DEPENDENCY_OWNED_UNKNOWN"
        {
            return Err(format!(
                "K1R-007/{dimension_id} promoted an unknown dependency-owned queue bound"
            ));
        }
    }
    for dimension_id in [
        "coordinator_entry_count",
        "enrolled_partition_count",
        "enrolled_offset_count",
    ] {
        let row = dimensions_by_key
            .get(&("K1R-014".to_owned(), dimension_id.to_owned()))
            .ok_or_else(|| format!("K1R-014/{dimension_id} is missing"))?;
        if optional_u64(row, "current_default")?.is_some()
            || optional_u64(row, "current_minimum")?.is_some()
            || optional_u64(row, "current_maximum_or_hard_cap")?.is_some()
            || text(row, "current_numeric_state")? != "DEPENDENCY_OWNED_UNKNOWN"
        {
            return Err(format!(
                "K1R-014/{dimension_id} promoted an unknown dependency-owned count"
            ));
        }
    }
    for dimension_id in ["commit_offset_entry_count", "commit_topic_bytes"] {
        let row = dimensions_by_key
            .get(&("K1R-019".to_owned(), dimension_id.to_owned()))
            .ok_or_else(|| format!("K1R-019/{dimension_id} is missing"))?;
        if optional_u64(row, "current_default")?.is_some()
            || optional_u64(row, "current_minimum")? != Some(1)
            || optional_u64(row, "required_default")?.is_some()
            || optional_u64(row, "required_minimum")? != Some(1)
        {
            return Err(format!(
                "K1R-019/{dimension_id} disagrees with the admitted nonempty batch"
            ));
        }
    }

    Ok((bindings.clone(), dimensions.clone()))
}

fn validate_operation_rows(
    artifact: &Value,
    authority_ids: &BTreeSet<String>,
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let rows = array(artifact, "lifecycle_operations")?;
    if rows.len() != OPERATION_COUNT {
        return Err(format!(
            "operation count mismatch: expected {OPERATION_COUNT}, got {}",
            rows.len()
        ));
    }
    let row_ids = ids(rows, "operation_id")?;
    ensure_unique(&row_ids, "lifecycle operation IDs")?;
    let expected_ids = (1..=OPERATION_COUNT)
        .map(|index| format!("K1L-{index:03}"))
        .collect::<BTreeSet<_>>();
    if row_ids.iter().cloned().collect::<BTreeSet<_>>() != expected_ids {
        return Err("lifecycle operation ID set drift".to_owned());
    }
    let operations = ids(rows, "operation")?;
    ensure_unique(&operations, "lifecycle operation names")?;
    if operations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != OPERATIONS.iter().copied().collect()
    {
        return Err("lifecycle operation set drift".to_owned());
    }

    let required_dimensions = TRANSITION_DIMENSIONS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if string_set(
        array(artifact, "transition_dimensions")?,
        "transition dimensions",
    )? != required_dimensions
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
    {
        return Err("root transition dimension set drift".to_owned());
    }

    let mut transition_projection = Vec::new();
    let mut total_transitions = 0usize;
    for row in rows {
        exact_keys(row, OPERATION_KEYS, "lifecycle operation row")?;
        let operation_id = text(row, "operation_id")?;
        let state_set = string_set(array(row, "state_set")?, "operation states")?;
        if state_set.len() < 5 {
            return Err(format!("{operation_id} has an incomplete state set"));
        }
        text(row, "entry_admission")?;
        text(row, "release_accounting")?;
        text(row, "implementation_owner")?;
        text(row, "verification_owner")?;
        if !matches!(
            text(row, "current_evidence_state")?,
            "DEPENDENCY_OWNED_UNKNOWN" | "ROUTED_GAP" | "STATIC_SOURCE_GAP"
        ) || text(row, "gate_state")? != "BLOCKING_KEEP_INCUMBENT"
        {
            return Err(format!("{operation_id} promoted lifecycle evidence"));
        }
        let refs = string_set(
            array(row, "source_authority_ids")?,
            "operation authority IDs",
        )?;
        if refs.is_empty() || !refs.is_subset(authority_ids) {
            return Err(format!("{operation_id} has unresolved source authority"));
        }
        if array(row, "terminal_gates")?.is_empty() {
            return Err(format!("{operation_id} has no terminal gate"));
        }

        let transitions = array(row, "transitions")?;
        if transitions.len() != DIMENSION_COUNT {
            return Err(format!(
                "{operation_id} transition count mismatch: expected {DIMENSION_COUNT}, got {}",
                transitions.len()
            ));
        }
        let mut dimensions = BTreeSet::new();
        for transition in transitions {
            exact_keys(transition, TRANSITION_KEYS, "lifecycle transition")?;
            let dimension = text(transition, "dimension")?;
            if !required_dimensions.contains(dimension) || !dimensions.insert(dimension) {
                return Err(format!(
                    "{operation_id} has duplicate or unknown transition dimension {dimension}"
                ));
            }
            let from = string_set(array(transition, "from_states")?, "transition sources")?;
            let to = string_set(
                array(transition, "current_to_states")?,
                "transition destinations",
            )?;
            if from.is_empty()
                || to.is_empty()
                || !from.is_subset(&state_set)
                || !to.is_subset(&state_set)
            {
                return Err(format!(
                    "{operation_id} {dimension} transition references an invalid state"
                ));
            }
            text(transition, "current_rule")?;
            let certainty = text(transition, "certainty")?;
            text(transition, "required_to_state")?;
            text(transition, "owner")?;
            expect_text(transition, "gate_state", "BLOCKING")?;
            if dimension == "ambiguous_outcome"
                && !certainty.contains("AMBIGUOUS")
                && !certainty.contains("UNKNOWN")
            {
                return Err(format!(
                    "{operation_id} normalized ambiguous outcome to {certainty}"
                ));
            }
            transition_projection.push(json!({
                "operation_id": operation_id,
                "transition": transition,
            }));
            total_transitions += 1;
        }
        if dimensions != required_dimensions {
            return Err(format!(
                "{operation_id} transition dimension coverage drift"
            ));
        }
    }
    if total_transitions != TRANSITION_COUNT {
        return Err(format!(
            "transition cell count mismatch: expected {TRANSITION_COUNT}, got {total_transitions}"
        ));
    }
    Ok((rows.clone(), transition_projection))
}

fn validate_cross_cutting_and_gates(
    artifact: &Value,
    tracker: &[Value],
    resource_rows: &[Value],
    operation_rows: &[Value],
) -> Result<(), String> {
    let invariants = array(artifact, "cross_cutting_invariants")?;
    if invariants.len() != 8 {
        return Err("cross-cutting invariant count drift".to_owned());
    }
    let invariant_ids = ids(invariants, "invariant_id")?;
    ensure_unique(&invariant_ids, "cross-cutting invariant IDs")?;
    let expected = (1..=8)
        .map(|index| format!("K1I-{index:03}-"))
        .collect::<Vec<_>>();
    for (row, prefix) in invariants.iter().zip(expected) {
        exact_keys(
            row,
            &["gate_state", "invariant_id", "owner", "rule"],
            "cross-cutting invariant",
        )?;
        if !text(row, "invariant_id")?.starts_with(&prefix) {
            return Err("cross-cutting invariant ID order drift".to_owned());
        }
        text(row, "owner")?;
        text(row, "rule")?;
        expect_text(row, "gate_state", "BLOCKING")?;
    }

    let tracker_ids = tracker
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let is_resolved = |value: &Value| {
        value.as_str().is_some_and(|id| {
            id.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") && tracker_ids.contains(id)
        })
    };

    let unowned_resource_count = resource_rows
        .iter()
        .filter(|row| {
            !row.get("implementation_owner").is_some_and(&is_resolved)
                || !row.get("verification_owner").is_some_and(&is_resolved)
                || row
                    .get("terminal_gates")
                    .and_then(Value::as_array)
                    .is_none_or(|gates| {
                        gates.is_empty() || gates.iter().any(|gate| !is_resolved(gate))
                    })
        })
        .count();
    let unowned_operation_count = operation_rows
        .iter()
        .filter(|row| {
            !row.get("implementation_owner").is_some_and(&is_resolved)
                || !row.get("verification_owner").is_some_and(&is_resolved)
                || row
                    .get("terminal_gates")
                    .and_then(Value::as_array)
                    .is_none_or(|gates| {
                        gates.is_empty() || gates.iter().any(|gate| !is_resolved(gate))
                    })
                || row
                    .get("transitions")
                    .and_then(Value::as_array)
                    .is_none_or(|transitions| {
                        transitions
                            .iter()
                            .any(|transition| !transition.get("owner").is_some_and(&is_resolved))
                    })
        })
        .count();
    if unowned_resource_count != 0 || unowned_operation_count != 0 {
        return Err(format!(
            "unresolved tracker ownership: {unowned_resource_count} resource rows, {unowned_operation_count} operation rows"
        ));
    }

    for invariant in invariants {
        if !invariant.get("owner").is_some_and(&is_resolved) {
            return Err(format!(
                "{} has an unresolved invariant owner",
                text(invariant, "invariant_id")?
            ));
        }
    }

    let authority = artifact
        .get("authority")
        .ok_or_else(|| "authority is missing".to_owned())?;
    for key in AUTHORITY_KEYS.iter().filter(|key| key.ends_with("_owner")) {
        if !authority.get(*key).is_some_and(&is_resolved) {
            return Err(format!(
                "authority field {key} has an unresolved tracker owner"
            ));
        }
    }

    let gates = artifact
        .get("ownership_and_gates")
        .ok_or_else(|| "ownership_and_gates is missing".to_owned())?;
    exact_keys(gates, OWNERSHIP_KEYS, "ownership_and_gates")?;
    for key in OWNERSHIP_KEYS.iter().filter(|key| key.ends_with("_owner")) {
        if !gates.get(*key).is_some_and(&is_resolved) {
            return Err(format!(
                "ownership field {key} has an unresolved tracker owner"
            ));
        }
    }
    expect_number(
        gates,
        "unowned_resource_count",
        u64::try_from(unowned_resource_count)
            .map_err(|_| "unowned resource count does not fit u64".to_owned())?,
    )?;
    expect_number(
        gates,
        "unowned_operation_count",
        u64::try_from(unowned_operation_count)
            .map_err(|_| "unowned operation count does not fit u64".to_owned())?,
    )?;
    expect_text(gates, "migration_gate", "BLOCKING_KEEP_INCUMBENT")?;
    Ok(())
}

fn validate_coverage_receipt(
    artifact: &Value,
    resource_rows: &[Value],
    binding_rows: &[Value],
    limit_dimension_rows: &[Value],
    operation_rows: &[Value],
    transition_rows: &[Value],
) -> Result<(), String> {
    let receipt = artifact
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt is missing".to_owned())?;
    exact_keys(receipt, COVERAGE_KEYS, "coverage_receipt")?;
    for (key, expected) in [
        ("resource_class_count", 42),
        ("resource_semantic_binding_count", 43),
        ("resource_limit_dimension_count", 43),
        ("composite_resource_count", 16),
        ("lifecycle_operation_count", 19),
        ("transition_dimension_count", 7),
        ("transition_cell_count", 133),
        ("unique_source_authority_reference_count", 63),
    ] {
        expect_number(receipt, key, expected)?;
    }

    let resource_ids = ids(resource_rows, "resource_id")?;
    let operation_ids = ids(operation_rows, "operation_id")?;
    let refs = resource_rows
        .iter()
        .chain(operation_rows)
        .flat_map(|row| {
            row.get("source_authority_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "source authority reference must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unique_refs = refs.iter().cloned().collect::<BTreeSet<_>>();
    if unique_refs.len() != AUTHORITY_REFERENCE_COUNT {
        return Err(format!(
            "unique source-authority reference count mismatch: expected {AUTHORITY_REFERENCE_COUNT}"
        ));
    }

    let actual = [
        (
            "resource_id_sha256",
            sorted_newline_sha256(resource_ids),
            RESOURCE_ID_SHA256,
        ),
        (
            "resource_contract_sha256",
            canonical_rows_sha256(resource_rows)?,
            RESOURCE_CONTRACT_SHA256,
        ),
        (
            "semantic_resource_binding_sha256",
            canonical_rows_sha256(binding_rows)?,
            SEMANTIC_RESOURCE_BINDING_SHA256,
        ),
        (
            "resource_limit_dimension_sha256",
            canonical_rows_sha256(limit_dimension_rows)?,
            RESOURCE_LIMIT_DIMENSION_SHA256,
        ),
        (
            "operation_id_sha256",
            sorted_newline_sha256(operation_ids),
            OPERATION_ID_SHA256,
        ),
        (
            "operation_contract_sha256",
            canonical_rows_sha256(operation_rows)?,
            OPERATION_CONTRACT_SHA256,
        ),
        (
            "transition_contract_sha256",
            canonical_rows_sha256(transition_rows)?,
            TRANSITION_CONTRACT_SHA256,
        ),
        (
            "source_authority_reference_sha256",
            sorted_newline_sha256(unique_refs.into_iter().collect()),
            AUTHORITY_REFERENCE_SHA256,
        ),
    ];
    for (key, digest, expected) in actual {
        if digest != expected || text(receipt, key)? != expected {
            return Err(format!(
                "{key} drift: expected {expected}, computed {digest}, recorded {}",
                text(receipt, key)?
            ));
        }
    }

    let invariants = array(artifact, "cross_cutting_invariants")?;
    let projection_rule = text(receipt, "projection_rule")?;
    let static_sections = [
        (
            "authority_contract_sha256",
            canonical_value_sha256(
                artifact
                    .get("authority")
                    .ok_or_else(|| "authority is missing".to_owned())?,
            )?,
            AUTHORITY_CONTRACT_SHA256,
        ),
        (
            "authority_input_contract_sha256",
            canonical_rows_sha256(array(artifact, "authority_inputs")?)?,
            AUTHORITY_INPUT_CONTRACT_SHA256,
        ),
        (
            "authority_views_contract_sha256",
            canonical_value_sha256(
                artifact
                    .get("authority_views")
                    .ok_or_else(|| "authority_views is missing".to_owned())?,
            )?,
            AUTHORITY_VIEWS_CONTRACT_SHA256,
        ),
        (
            "policy_contract_sha256",
            canonical_value_sha256(
                artifact
                    .get("policy")
                    .ok_or_else(|| "policy is missing".to_owned())?,
            )?,
            POLICY_CONTRACT_SHA256,
        ),
        (
            "semantic_coverage_contract_sha256",
            canonical_value_sha256(
                artifact
                    .get("semantic_coverage")
                    .ok_or_else(|| "semantic_coverage is missing".to_owned())?,
            )?,
            SEMANTIC_COVERAGE_CONTRACT_SHA256,
        ),
        (
            "cross_cutting_invariant_sha256",
            canonical_rows_sha256(invariants)?,
            CROSS_CUTTING_INVARIANT_SHA256,
        ),
        (
            "ownership_and_gates_sha256",
            canonical_value_sha256(
                artifact
                    .get("ownership_and_gates")
                    .ok_or_else(|| "ownership_and_gates is missing".to_owned())?,
            )?,
            OWNERSHIP_AND_GATES_SHA256,
        ),
        (
            "disposition_receipt_sha256",
            canonical_value_sha256(
                artifact
                    .get("disposition_receipt")
                    .ok_or_else(|| "disposition_receipt is missing".to_owned())?,
            )?,
            DISPOSITION_RECEIPT_SHA256,
        ),
        (
            "projection_rule_sha256",
            sorted_newline_sha256(vec![projection_rule.to_owned()]),
            PROJECTION_RULE_SHA256,
        ),
    ];
    for (key, digest, expected) in static_sections {
        if digest != expected || text(receipt, key)? != expected {
            return Err(format!(
                "{key} drift: expected {expected}, computed {digest}, recorded {}",
                text(receipt, key)?
            ));
        }
    }

    let boundaries = array(artifact, "no_claim_boundaries")?;
    if boundaries.len() != 7 {
        return Err("no-claim boundary count drift".to_owned());
    }
    let no_claim_digest = sorted_newline_sha256(
        boundaries
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| !text.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| "no-claim boundary must be non-empty text".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    if no_claim_digest != NO_CLAIM_SHA256
        || text(receipt, "no_claim_boundary_sha256")? != NO_CLAIM_SHA256
    {
        return Err("no-claim boundary digest drift".to_owned());
    }
    Ok(())
}

fn validate_disposition_and_doc(root: &Path, artifact: &Value) -> Result<(), String> {
    let disposition = artifact
        .get("disposition_receipt")
        .ok_or_else(|| "disposition_receipt is missing".to_owned())?;
    exact_keys(disposition, DISPOSITION_KEYS, "disposition_receipt")?;
    for key in [
        "k1_1_complete",
        "k1_2_complete",
        "k1_3_complete",
        "k1_4_static_contract_complete",
    ] {
        expect_bool(disposition, key, true)?;
    }
    for key in [
        "k1_5_complete",
        "k1_parent_complete",
        "runtime_resource_bounds_proven",
        "runtime_lifecycle_proven",
        "leak_freedom_proven",
        "quiescence_proven",
        "required_numeric_policy_complete",
        "dynamic_execution_claimed",
        "migration_eligible",
        "production_wiring_allowed",
        "dependency_exit_allowed",
        "feature_removal_allowed",
        "api_removal_allowed",
        "capability_removal_allowed",
        "file_deletion_allowed",
        "oracle_retirement_allowed",
        "cutover_allowed",
    ] {
        expect_bool(disposition, key, false)?;
    }
    expect_text(disposition, "incumbent_disposition", "KEEP_INCUMBENT")?;
    expect_text(
        disposition,
        "on_missing_extra_duplicate_changed_unowned_unknown_unbounded_or_ambiguous",
        "KEEP_INCUMBENT",
    )?;

    let doc = read_text(root, DOC_PATH)?;
    if doc.matches(DOC_BEGIN).count() != 1
        || doc.matches(DOC_END).count() != 1
        || doc.find(DOC_BEGIN) >= doc.find(DOC_END)
    {
        return Err("document marker drift".to_owned());
    }
    for required in [
        "42 unique resource rows",
        "All 43 K0.2 configuration semantics",
        "43 per-unit limit dimensions",
        "19 lifecycle rows",
        "133 transition cells",
        "max_poll_records=500",
        "256 fallback-thread cap does not cap accepted jobs or waiting callers",
        "KEEP_INCUMBENT",
        "does not prove compilation",
        "does not authorize production wiring",
    ] {
        if !doc.contains(required) {
            return Err(format!("document is missing required boundary: {required}"));
        }
    }
    Ok(())
}

fn validate(root: &Path, inputs: &Inputs) -> Result<(), String> {
    validate_identity(&inputs.artifact)?;
    validate_file_hashes_and_inputs(root, &inputs.artifact)?;
    let authority_ids = validate_authority_views(inputs)?;
    let resource_rows = validate_resource_rows(&inputs.artifact, &authority_ids)?;
    let (operation_rows, transition_rows) =
        validate_operation_rows(&inputs.artifact, &authority_ids)?;
    let (binding_rows, limit_dimension_rows) =
        validate_resource_semantic_bindings(&inputs.artifact, &resource_rows, &operation_rows)?;
    validate_cross_cutting_and_gates(
        &inputs.artifact,
        &inputs.tracker,
        &resource_rows,
        &operation_rows,
    )?;
    validate_coverage_receipt(
        &inputs.artifact,
        &resource_rows,
        &binding_rows,
        &limit_dimension_rows,
        &operation_rows,
        &transition_rows,
    )?;
    validate_disposition_and_doc(root, &inputs.artifact)?;
    Ok(())
}

fn assert_mutation_rejected(mutator: impl FnOnce(&mut Value)) {
    let root = repo_root();
    let mut inputs = load_inputs(&root).expect("checked-in K1.4 inputs must parse");
    validate(&root, &inputs).expect("positive K1.4 baseline must validate before mutation");
    mutator(&mut inputs.artifact);
    assert!(
        validate(&root, &inputs).is_err(),
        "high-risk K1.4 mutation must fail closed"
    );
}

#[test]
fn kafka_k1_resource_lifecycle_contract_is_exact_and_fail_closed() {
    let root = repo_root();
    let inputs = load_inputs(&root).expect("checked-in K1.4 inputs must parse");
    validate(&root, &inputs).expect("K1.4 static resource/lifecycle contract must validate");
}

#[test]
fn numeric_limit_drift_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][3]["current_default"] = json!(1_048_577u64);
    });
}

#[test]
fn required_hard_cap_removal_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][11]["required_maximum_or_hard_cap"] = Value::Null;
    });
}

#[test]
fn semantic_resource_binding_gap_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["semantic_resource_bindings"][3]["resource_ids"]
            .as_array_mut()
            .expect("resource IDs must be an array")
            .pop();
    });
}

#[test]
fn composite_limit_dimension_drift_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["resource_limit_dimensions"][0]["unit"] = json!("mutated unit");
    });
}

#[test]
fn nested_policy_and_invariant_drift_fail_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["policy"]["numeric_rule"] = json!("weakened");
    });
    assert_mutation_rejected(|artifact| {
        artifact["cross_cutting_invariants"][0]["rule"] = json!("weakened");
    });
}

#[test]
fn arbitrary_owner_text_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["ownership_and_gates"]["producer_owner"] = json!("nobody");
    });
}

#[test]
fn promoted_resource_and_lifecycle_states_fail_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][0]["required_numeric_state"] = json!("BLOCKING_SUPPORTED");
    });
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][0]["required_numeric_state"] =
            json!("BLOCKING_ACTUAL_BINARY_RECEIPT_PENDING");
    });
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][0]["required_numeric_state"] =
            json!("BLOCKING_VERIFIED_GREEN");
    });
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][0]["required_numeric_state"] = json!("BLOCKING_PROVEN");
    });
    assert_mutation_rejected(|artifact| {
        artifact["lifecycle_operations"][0]["current_evidence_state"] = json!("PASS");
    });
}

#[test]
fn missing_transition_dimension_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["lifecycle_operations"][1]["transitions"]
            .as_array_mut()
            .expect("transitions must be an array")
            .pop();
    });
}

#[test]
fn ambiguous_outcome_promotion_fails_closed() {
    assert_mutation_rejected(|artifact| {
        let transitions = artifact["lifecycle_operations"][1]["transitions"]
            .as_array_mut()
            .expect("transitions must be an array");
        let ambiguous = transitions
            .iter_mut()
            .find(|row| row["dimension"] == "ambiguous_outcome")
            .expect("ambiguous transition must exist");
        ambiguous["certainty"] = json!("DEFINITIVE_SUCCESS");
    });
}

#[test]
fn unresolved_authority_reference_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["resource_classes"][0]["source_authority_ids"]
            .as_array_mut()
            .expect("source authority IDs must be an array")
            .push(json!("KAFKA-K1-UNRESOLVED"));
    });
}

#[test]
fn invalid_state_transition_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["lifecycle_operations"][13]["transitions"][0]["current_to_states"] =
            json!(["STATE_NOT_IN_OPERATION"]);
    });
}

#[test]
fn semantic_coverage_gap_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["semantic_coverage"]["classifications"][0]["semantic_ids"]
            .as_array_mut()
            .expect("semantic IDs must be an array")
            .pop();
    });
}

#[test]
fn cutover_permission_fails_closed() {
    assert_mutation_rejected(|artifact| {
        artifact["disposition_receipt"]["cutover_allowed"] = json!(true);
    });
}
