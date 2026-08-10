//! Static contract for the Kafka K1.2 protocol and connection policy.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.2.1.2
//! Fixture: artifacts/kafka_k1_protocol_security_support_policy_v1.json
//!
//! This integration test reads checked-in repository bytes only. It does not
//! compile a Kafka feature profile, contact a broker, or promote inventory into
//! protocol, connection, interoperability, migration, or cutover evidence.

#![allow(dead_code, missing_docs)]

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k1_protocol_security_support_policy_v1.json";
const DOC_PATH: &str = "docs/kafka_k1_protocol_security_support_policy.md";
const PRODUCER_PATH: &str = "src/messaging/kafka.rs";
const MANIFEST_PATH: &str = "Cargo.toml";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_009_kafka_client.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";

const ARTIFACT_SHA256: &str = "e4386f4ce35e4f791deef638bd7eef66dbb4299a5d793bb65245398f01dafbc3";
const DOC_SHA256: &str = "c9142b9d00a0b07187a50d224534e9268e5226829dfc5e0bbd04de80bf2a4949";

const ARTIFACT_ID: &str = "kafka-k1-protocol-security-support-policy-v1";
const PROGRAM_ID: &str = "dependency-sovereignty-rev5";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1.2";
const PARENT_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const ADR_ID: &str = "DEP-ADR-009";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const BASELINE_REVISION: &str = "f3a02fe6e6e5d0dca6db91204fcf2da53c22a5c7";
const INVENTORY_STATE: &str = "K1_2_PROTOCOL_BROKER_AND_SECURITY_POLICY_FROZEN_KEEP_INCUMBENT";
const POLICY_ROW_SHA256: &str = "a95fe46e59be4859e5fd1d7b106d6e2542a7adba4314050fc2d6616bb91ed60e";
const NO_CLAIM_SHA256: &str = "0de9d792c3348c6fc5c76e1f54d2dd8fbf9bec3f87e9700de27ca08ce2f2345e";

const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K1.2 PROTOCOL SECURITY SUPPORT POLICY -->";
const DOC_END: &str = "<!-- END KAFKA K1.2 PROTOCOL SECURITY SUPPORT POLICY -->";

const ROOT_KEYS: &[&str] = &[
    "adr_id",
    "api_key_cells",
    "api_schema_closure",
    "artifact_id",
    "authority",
    "authority_inputs",
    "authority_views",
    "baseline_revision",
    "bead_id",
    "broker_support_cells",
    "capability_id",
    "captured_date_utc",
    "coverage_receipt",
    "credential_cells",
    "disposition_receipt",
    "flexible_encoding_cells",
    "header_cells",
    "inventory_state",
    "negative_authentication_cells",
    "negotiation_transition_cells",
    "no_claim_boundaries",
    "ownership_and_gates",
    "parent_bead_id",
    "policy",
    "program_id",
    "protocol_binding_groups",
    "schema_version",
    "transport_security_cells",
];

const INPUT_PATHS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "artifacts/kafka_broker_fixture_provenance_matrix_v1.json",
    "artifacts/kafka_incumbent_semantics_matrix_v1.json",
    "artifacts/kafka_k0_baseline_disposition_v1.json",
    "artifacts/kafka_k1_obligation_index_v1.json",
    "artifacts/kafka_k1_public_api_contract_v1.json",
    "docs/adr/dep_plan_adr_009_kafka_client.md",
    "docs/kafka_k1_client_contract.md",
    "fuzz/fuzz_targets/kafka_protocol.rs",
    "src/messaging/kafka.rs",
    "src/messaging/kafka_consumer.rs",
    "tests/integration/kafka_real_broker.rs",
    "tests/kafka_k1_client_contract.rs",
    "tests/kafka_sasl_authentication_audit.rs",
];

const AUTHORITY_ID_PATHS: &[&str] = &[
    "artifacts/kafka_k1_obligation_index_v1.json",
    "artifacts/kafka_broker_fixture_provenance_matrix_v1.json",
    "artifacts/kafka_incumbent_semantics_matrix_v1.json",
    "artifacts/kafka_k1_public_api_contract_v1.json",
];

const CELL_COLLECTIONS: &[(&str, usize, &str)] = &[
    (
        "broker_support_cells",
        6,
        "9f19c6588ee851edb2cb830d7e70c5c84afdc08ac3670903e6d5caa0691e7bd2",
    ),
    (
        "api_key_cells",
        20,
        "c0559f7943a51afb8444cd0281ac91e84bd4b0b96e17ea39844eeabe56051199",
    ),
    (
        "header_cells",
        5,
        "36aae947317b724f66ed6a28339d6dc45231be3dfbe87f61b874d1215937615e",
    ),
    (
        "flexible_encoding_cells",
        8,
        "bde4a18b610b48e13664170839b15db6ddaa680ca86ad85d0a4ebb38074a6463",
    ),
    (
        "negotiation_transition_cells",
        10,
        "851cd1f07553e7e8d3be8ae41b72ec95adf828b28140faa35e6c34890be802cd",
    ),
    (
        "transport_security_cells",
        8,
        "9e8ea385f932295452af42733de1b599e658b15d24fc0073b3d672cf80b0bea9",
    ),
    (
        "credential_cells",
        8,
        "b41183a6098ce061f6ccf76fb86040785c9e9a3d16a11d3bbca563d9b5e4c973",
    ),
    (
        "negative_authentication_cells",
        15,
        "aebb51c7541eac7f0caf77d21fce1c483b2b8109f2ee48cb1e0b8f977d3fc9dc",
    ),
    (
        "protocol_binding_groups",
        10,
        "68a0173f6078475c82b908ba1c47daaa30e02a4cbf60aec3e000a707f47dd376",
    ),
];

const API_KEYS: &[(u64, &str)] = &[
    (0, "Produce"),
    (1, "Fetch"),
    (2, "ListOffsets"),
    (3, "Metadata"),
    (8, "OffsetCommit"),
    (9, "OffsetFetch"),
    (10, "FindCoordinator"),
    (11, "JoinGroup"),
    (12, "Heartbeat"),
    (13, "LeaveGroup"),
    (14, "SyncGroup"),
    (17, "SaslHandshake"),
    (18, "ApiVersions"),
    (22, "InitProducerId"),
    (23, "OffsetForLeaderEpoch"),
    (24, "AddPartitionsToTxn"),
    (25, "AddOffsetsToTxn"),
    (26, "EndTxn"),
    (28, "TxnOffsetCommit"),
    (36, "SaslAuthenticate"),
];

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

fn parse_artifact() -> Result<Value, String> {
    serde_json::from_str(include_str!(
        "../artifacts/kafka_k1_protocol_security_support_policy_v1.json"
    ))
    .map_err(|error| format!("invalid JSON in {ARTIFACT_PATH}: {error}"))
}

fn parse_json(root: &Path, path: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(root, path)?)
        .map_err(|error| format!("invalid JSON in {path}: {error}"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sorted_newline_sha256(rows: impl IntoIterator<Item = String>) -> String {
    let mut rows = rows.into_iter().collect::<Vec<_>>();
    rows.sort();
    rows.dedup();

    let mut hasher = Sha256::new();
    for row in rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn ordered_newline_sha256(rows: impl IntoIterator<Item = String>) -> String {
    let mut hasher = Sha256::new();
    for row in rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(&canonicalize(value))
        .map_err(|error| format!("failed to serialize canonical JSON: {error}"))
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
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{key} must be non-empty text"))
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn expect_text(value: &Value, key: &str, expected: &str) -> Result<(), String> {
    let actual = text(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{key} mismatch: expected {expected:?}, got {actual:?}"
        ))
    }
}

fn expect_number(value: &Value, key: &str, expected: u64) -> Result<(), String> {
    let actual = number(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{key} mismatch: expected {expected}, got {actual}"))
    }
}

fn expect_bool(value: &Value, key: &str, expected: bool) -> Result<(), String> {
    let actual = boolean(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{key} mismatch: expected {expected}, got {actual}"))
    }
}

fn exact_keys(value: &Value, expected: &[&str], context: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{context} keys differ: expected {expected:?}, got {actual:?}"
        ))
    }
}

fn check_metadata(artifact: &Value) -> Result<(), String> {
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
    expect_text(authority, "registry_disposition", "KEEP_UNTIL_PARITY")?;
    expect_text(authority, "current_action", "KEEP_INCUMBENT")?;
    expect_text(
        authority,
        "schema_and_range_owner",
        "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
    )?;
    expect_text(
        authority,
        "negotiation_owner",
        "asupersync-dep-p7-kafka-removal-sarszu.2.2.4",
    )?;
    expect_text(
        authority,
        "sole_conditional_cutover_owner",
        "asupersync-dep-p7-kafka-removal-sarszu.2.15",
    )?;
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

    let ownership = artifact
        .get("ownership_and_gates")
        .ok_or_else(|| "ownership_and_gates is missing".to_owned())?;
    exact_keys(
        ownership,
        &[
            "aggregate_k1_owner",
            "bounded_primitive_codec_owner",
            "claim_time_refresh_owner",
            "connection_security_terminal_owner",
            "connectivity_owner",
            "exact_reachable_schema_and_range_owner",
            "independent_protocol_corpus_owner",
            "independent_security_review_owner",
            "independent_terminal_owner",
            "metadata_routing_owner",
            "migration_gate",
            "negotiation_correlation_and_reuse_owner",
            "pinned_service_harness_owner",
            "policy_owner",
            "protocol_terminal_owner",
            "real_service_terminal_owner",
            "sasl_owner",
            "security_fault_real_service_owner",
            "sole_cutover_owner",
            "tls_owner",
            "unowned_cell_count",
            "versioned_schema_and_flexible_owner",
        ],
        "ownership_and_gates",
    )?;
    for (key, expected) in [
        ("policy_owner", BEAD_ID),
        (
            "aggregate_k1_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
        ),
        (
            "exact_reachable_schema_and_range_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
        ),
        (
            "bounded_primitive_codec_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.2.2",
        ),
        (
            "versioned_schema_and_flexible_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.2.3",
        ),
        (
            "negotiation_correlation_and_reuse_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.2.4",
        ),
        (
            "protocol_terminal_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.2.5",
        ),
        (
            "connectivity_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.3.1",
        ),
        ("tls_owner", "asupersync-dep-p7-kafka-removal-sarszu.2.3.2"),
        ("sasl_owner", "asupersync-dep-p7-kafka-removal-sarszu.2.3.3"),
        (
            "metadata_routing_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.3.4",
        ),
        (
            "connection_security_terminal_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.3.5",
        ),
        (
            "independent_protocol_corpus_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.1",
        ),
        (
            "independent_security_review_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.4",
        ),
        (
            "independent_terminal_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
        ),
        (
            "pinned_service_harness_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.13.1",
        ),
        (
            "security_fault_real_service_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.13.5",
        ),
        (
            "real_service_terminal_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.13.6",
        ),
        (
            "claim_time_refresh_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.14.1",
        ),
        (
            "sole_cutover_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.15",
        ),
    ] {
        expect_text(ownership, key, expected)?;
    }
    expect_number(ownership, "unowned_cell_count", 0)?;
    expect_text(ownership, "migration_gate", "BLOCKING_KEEP_INCUMBENT")?;
    Ok(())
}

fn check_input_pins(root: &Path, artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "authority_inputs")?;
    if rows.len() != INPUT_PATHS.len() {
        return Err(format!(
            "authority input count mismatch: expected {}, got {}",
            INPUT_PATHS.len(),
            rows.len()
        ));
    }

    let expected_paths = INPUT_PATHS.iter().copied().collect::<BTreeSet<_>>();
    let mut paths = BTreeSet::new();
    let mut ids = BTreeSet::new();

    for row in rows {
        let input_id = text(row, "input_id")?;
        let role = text(row, "role")?;
        let path = text(row, "path")?;
        if !input_id.starts_with("K1-2-INPUT-") {
            return Err(format!("unexpected authority input id {input_id}"));
        }
        if role.trim().is_empty() {
            return Err(format!("authority input {input_id} has an empty role"));
        }
        if !ids.insert(input_id) {
            return Err(format!("duplicate authority input id {input_id}"));
        }
        if !paths.insert(path) {
            return Err(format!("duplicate authority input path {path}"));
        }

        let bytes = read_bytes(root, path)?;
        let source =
            std::str::from_utf8(&bytes).map_err(|error| format!("{path} is not UTF-8: {error}"))?;
        let expected_bytes = usize::try_from(number(row, "byte_count")?)
            .map_err(|_| format!("byte_count for {path} does not fit usize"))?;
        let expected_records = usize::try_from(number(row, "record_count")?)
            .map_err(|_| format!("record_count for {path} does not fit usize"))?;

        if bytes.len() != expected_bytes {
            return Err(format!(
                "byte count drift for {path}: expected {expected_bytes}, got {}",
                bytes.len()
            ));
        }
        if source.lines().count() != expected_records {
            return Err(format!(
                "record count drift for {path}: expected {expected_records}, got {}",
                source.lines().count()
            ));
        }
        let actual_sha = sha256_bytes(&bytes);
        let expected_sha = text(row, "sha256")?;
        if actual_sha != expected_sha {
            return Err(format!(
                "sha256 drift for {path}: expected {expected_sha}, got {actual_sha}"
            ));
        }
    }

    if paths == expected_paths {
        Ok(())
    } else {
        Err(format!(
            "authority input paths differ: expected {expected_paths:?}, got {paths:?}"
        ))
    }
}

fn check_authority_views(artifact: &Value) -> Result<(), String> {
    let views = artifact
        .get("authority_views")
        .ok_or_else(|| "authority_views is missing".to_owned())?;
    exact_keys(
        views,
        &[
            "broker_api_version_vectors",
            "k1_obligation_projection",
            "owned_unknowns",
            "routed_gaps",
            "security_enum_semantics",
            "transport_auth_vectors",
        ],
        "authority_views",
    )?;

    let expected = [
        (
            "k1_obligation_projection",
            279,
            "normalized_projection_sha256",
            "cd4ff24ac2deed867d81d1fb9d81c08f31e57de5c7e77c84e1ea3657e2fa0f37",
        ),
        (
            "broker_api_version_vectors",
            7,
            "sorted_id_lf_sha256",
            "d177d8683bcea7c1300df130e478e6c67213187b29f0e1421be4fa2faf7b24be",
        ),
        (
            "transport_auth_vectors",
            6,
            "sorted_id_lf_sha256",
            "0bb5025302793f30c41568fd6ea8bd24d20d1b44acfac9cf2425343d5bf458ce",
        ),
        (
            "owned_unknowns",
            9,
            "sorted_id_lf_sha256",
            "99a6c6fd294d433f026e7866935f3afa338c78df04fc93172ba5d55c68fed61e",
        ),
        (
            "routed_gaps",
            26,
            "sorted_id_lf_sha256",
            "645440a0ca7817df3d9602cc6f053f6f4040a288b22e784ab5fb82e55a1462c5",
        ),
    ];

    for (view_name, count, digest_key, digest) in expected {
        let view = views
            .get(view_name)
            .ok_or_else(|| format!("missing authority view {view_name}"))?;
        expect_number(view, "row_count", count)?;
        expect_text(view, digest_key, digest)?;
    }

    let security = views
        .get("security_enum_semantics")
        .ok_or_else(|| "missing security_enum_semantics view".to_owned())?;
    expect_text(
        security,
        "sorted_id_lf_sha256",
        "887555b0fe226e0d8f5e640fa28e0f99a8336aa4c943b6bca51f89a593c3c11f",
    )?;
    let semantic_ids = array(security, "semantic_ids")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "security semantic id must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if semantic_ids != ["KAFKA-ENUM-004", "KAFKA-ENUM-005"] {
        return Err(format!(
            "unexpected security semantic IDs: {semantic_ids:?}"
        ));
    }
    Ok(())
}

fn collect_tracker_references(value: &Value, references: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_tracker_references(value, references);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                if key.ends_with("owner") {
                    if let Some(owner) = value.as_str() {
                        references.insert(owner.to_owned());
                    }
                }
                if key == "terminal_gates" {
                    if let Some(gates) = value.as_array() {
                        for gate in gates.iter().filter_map(Value::as_str) {
                            references.insert(gate.to_owned());
                        }
                    }
                }
                collect_tracker_references(value, references);
            }
        }
        _ => {}
    }
}

fn check_tracker_routes(root: &Path, artifact: &Value) -> Result<(), String> {
    let tracker = read_text(root, TRACKER_PATH)?;
    let mut tracker_ids = BTreeSet::new();
    for (index, line) in tracker.lines().enumerate() {
        let row: Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "invalid JSONL in {TRACKER_PATH} line {}: {error}",
                index + 1
            )
        })?;
        let id = text(&row, "id")?;
        tracker_ids.insert(id.to_owned());
    }

    let mut references = BTreeSet::new();
    collect_tracker_references(artifact, &mut references);
    if references.len() != 36 {
        return Err(format!(
            "owner and terminal reference count mismatch: expected 36, got {}",
            references.len()
        ));
    }
    for reference in references {
        if !reference.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") {
            return Err(format!(
                "out-of-program owner or terminal reference {reference}"
            ));
        }
        if !tracker_ids.contains(&reference) {
            return Err(format!(
                "owner or terminal reference is absent from tracker: {reference}"
            ));
        }
    }
    Ok(())
}

fn collect_authority_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_authority_ids(value, ids);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                if key.ends_with("_id") {
                    if let Some(id) = value.as_str() {
                        ids.insert(id.to_owned());
                    }
                }
                collect_authority_ids(value, ids);
            }
        }
        _ => {}
    }
}

fn check_source_authority_resolution(root: &Path, artifact: &Value) -> Result<(), String> {
    let mut authority_ids = BTreeSet::new();
    for path in AUTHORITY_ID_PATHS {
        collect_authority_ids(&parse_json(root, path)?, &mut authority_ids);
    }
    authority_ids.insert(ADR_ID.to_owned());

    let mut referenced_tokens = BTreeSet::new();
    for (collection, _, _) in CELL_COLLECTIONS {
        let authority_key = if *collection == "protocol_binding_groups" {
            "authority_rows"
        } else {
            "source_authority_ids"
        };
        for row in array(artifact, collection)? {
            let cell_id = text(row, "cell_id")?;
            let references = array(row, authority_key)?;
            if references.is_empty() {
                return Err(format!("cell {cell_id} has no {authority_key}"));
            }
            for reference in references {
                let reference = reference
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("cell {cell_id} has an invalid authority token"))?;
                if !authority_ids.contains(reference) {
                    return Err(format!(
                        "cell {cell_id} authority token is unresolved: {reference}"
                    ));
                }
                referenced_tokens.insert(reference.to_owned());
            }
        }
    }

    for required_reference in [
        "KAFKA-K1-SHARED-009",
        "KAFKA-K1-SHARED-011",
        "KAFKA-K0-4-UNKNOWN-001",
        "KAFKA-K0-4-UNKNOWN-007",
        "KAFKA-K0-4-GAP-020-NEGOTIATION-CORRELATION-RECOVERY",
    ] {
        if !referenced_tokens.contains(required_reference) {
            return Err(format!(
                "required K1.2 authority token is not joined: {required_reference}"
            ));
        }
    }
    Ok(())
}

fn find_cell<'a>(artifact: &'a Value, collection: &str, id: &str) -> Result<&'a Value, String> {
    array(artifact, collection)?
        .iter()
        .find(|row| row.get("cell_id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("missing {collection} cell {id}"))
}

fn check_policy_cells(artifact: &Value) -> Result<(), String> {
    let allowed_states = [
        "BLOCKED",
        "BLOCKED_EXTERNAL",
        "CONFIG_ONLY",
        "LOCAL_MODEL_ONLY",
        "PROOF_ONLY",
        "ROUTED_GAP",
        "STATIC_SOURCE",
        "UNKNOWN",
        "UNPINNED",
        "WIRE_CODEC_ONLY",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    let expected_state_counts = [
        ("BLOCKED", 10usize),
        ("BLOCKED_EXTERNAL", 20),
        ("CONFIG_ONLY", 12),
        ("LOCAL_MODEL_ONLY", 1),
        ("ROUTED_GAP", 2),
        ("STATIC_SOURCE", 7),
        ("UNKNOWN", 25),
        ("UNPINNED", 1),
        ("WIRE_CODEC_ONLY", 12),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    let mut all_ids = BTreeSet::new();
    let mut state_counts = BTreeMap::new();
    let mut canonical_rows = Vec::new();
    let mut total = 0usize;

    for (collection, expected_count, expected_id_digest) in CELL_COLLECTIONS {
        let rows = array(artifact, collection)?;
        if rows.len() != *expected_count {
            return Err(format!(
                "{collection} count mismatch: expected {expected_count}, got {}",
                rows.len()
            ));
        }

        let id_digest = sorted_newline_sha256(
            rows.iter()
                .map(|row| text(row, "cell_id").map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?,
        );
        if id_digest != *expected_id_digest {
            return Err(format!(
                "{collection} ID digest mismatch: expected {expected_id_digest}, got {id_digest}"
            ));
        }

        for row in rows {
            canonical_rows.push(canonical_json(&json!({
                "collection": collection,
                "row": row,
            }))?);
            total += 1;
            let cell_id = text(row, "cell_id")?;
            if !cell_id.starts_with("KAFKA-K1-2-") {
                return Err(format!("unexpected policy cell id {cell_id}"));
            }
            if !all_ids.insert(cell_id) {
                return Err(format!("duplicate policy cell id {cell_id}"));
            }

            text(row, "required_state")?;
            let current_state = text(row, "current_evidence_state")?;
            if !allowed_states.contains(current_state) {
                return Err(format!(
                    "cell {cell_id} has promoted or unknown current state {current_state}"
                ));
            }
            *state_counts.entry(current_state).or_insert(0usize) += 1;

            for owner_key in ["implementation_owner", "verification_owner"] {
                let owner = text(row, owner_key)?;
                if !owner.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") {
                    return Err(format!(
                        "cell {cell_id} has out-of-program {owner_key} {owner}"
                    ));
                }
            }
            if let Some(real_service_owner) = row.get("real_service_owner") {
                let owner = real_service_owner
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        format!("cell {cell_id} real_service_owner must be non-empty text")
                    })?;
                if !owner.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") {
                    return Err(format!(
                        "cell {cell_id} has out-of-program real_service_owner {owner}"
                    ));
                }
            }

            let gates = array(row, "terminal_gates")?;
            if gates.is_empty() {
                return Err(format!("cell {cell_id} has incomplete terminal gates"));
            }
            for gate in gates {
                let gate = gate
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("cell {cell_id} has an empty terminal gate"))?;
                if !gate.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") {
                    return Err(format!(
                        "cell {cell_id} has out-of-program terminal gate {gate}"
                    ));
                }
            }
            let authority_key = if *collection == "protocol_binding_groups" {
                "authority_rows"
            } else {
                "source_authority_ids"
            };
            let authority_ids = array(row, authority_key)?;
            if authority_ids.is_empty()
                || authority_ids
                    .iter()
                    .any(|id| id.as_str().is_none_or(str::is_empty))
            {
                return Err(format!("cell {cell_id} has incomplete source authority"));
            }
        }
    }

    if total != 90 || all_ids.len() != 90 {
        return Err(format!(
            "combined policy coverage mismatch: total {total}, unique {}",
            all_ids.len()
        ));
    }
    let canonical_row_digest = sorted_newline_sha256(canonical_rows);
    if canonical_row_digest != POLICY_ROW_SHA256 {
        return Err(format!(
            "canonical policy-row drift: expected {POLICY_ROW_SHA256}, got {canonical_row_digest}"
        ));
    }
    if state_counts != expected_state_counts {
        return Err(format!(
            "current-state distribution mismatch: expected {expected_state_counts:?}, got {state_counts:?}"
        ));
    }

    let api_rows = array(artifact, "api_key_cells")?;
    let mut api_pairs = api_rows
        .iter()
        .map(|row| Ok((number(row, "api_key")?, text(row, "api_name")?)))
        .collect::<Result<Vec<_>, String>>()?;
    api_pairs.sort_unstable();
    if api_pairs.as_slice() != API_KEYS {
        return Err(format!(
            "semantic API-key set differs: expected {API_KEYS:?}, got {api_pairs:?}"
        ));
    }
    if api_rows.iter().any(|row| {
        row.get("accepted_version_range")
            .is_none_or(|range| !range.is_null())
    }) {
        return Err("K1.2 must not record an accepted numeric API-version range".to_owned());
    }
    let api_pair_digest =
        ordered_newline_sha256(api_pairs.iter().map(|(key, name)| format!("{key}\t{name}")));
    if api_pair_digest != "3aca9d044b63403f051110d8e9d76173b5c61403f494bd269176c892309dafad" {
        return Err(format!(
            "semantic API-key projection drift: {api_pair_digest}"
        ));
    }

    let api_names = API_KEYS
        .iter()
        .map(|(_, name)| *name)
        .collect::<BTreeSet<_>>();
    for row in array(artifact, "protocol_binding_groups")? {
        let cell_id = text(row, "cell_id")?;
        for message in array(row, "message_names")? {
            let message = message
                .as_str()
                .ok_or_else(|| format!("binding {cell_id} message name must be text"))?;
            if !api_names.contains(message) {
                return Err(format!(
                    "binding {cell_id} names undeclared semantic API {message}"
                ));
            }
        }
    }

    let all_id_digest = sorted_newline_sha256(all_ids.iter().map(|id| (*id).to_owned()));
    if all_id_digest != "700a61ffbd8ee3bcd3354f334567b6f3e237b40022b774a519c5b44249bd5ada" {
        return Err(format!("combined policy-cell ID drift: {all_id_digest}"));
    }

    check_special_policy_rows(artifact)?;
    check_policy_receipts(artifact)?;
    Ok(())
}

fn check_special_policy_rows(artifact: &Value) -> Result<(), String> {
    let loopback = find_cell(
        artifact,
        "transport_security_cells",
        "KAFKA-K1-2-SEC-001-LOOPBACK-PLAINTEXT",
    )?;
    expect_text(
        loopback,
        "required_state",
        "REQUIRED_PRESERVE_LOOPBACK_ONLY",
    )?;

    let remote = find_cell(
        artifact,
        "transport_security_cells",
        "KAFKA-K1-2-SEC-002-REMOTE-PLAINTEXT",
    )?;
    expect_text(remote, "required_state", "FORBIDDEN_FAIL_CLOSED")?;

    let cleartext_auth = find_cell(
        artifact,
        "transport_security_cells",
        "KAFKA-K1-2-SEC-007-SASL-PLAINTEXT",
    )?;
    expect_text(
        cleartext_auth,
        "required_state",
        "FORBIDDEN_NOT_EXPOSED_NOT_NEGOTIATED",
    )?;

    let bypass = find_cell(
        artifact,
        "transport_security_cells",
        "KAFKA-K1-2-SEC-008-INSECURE-BYPASS",
    )?;
    expect_text(
        bypass,
        "required_state",
        "REQUIRED_TEST_ONLY_NOT_DOWNSTREAM_DEBUG",
    )?;
    expect_text(bypass, "current_evidence_state", "ROUTED_GAP")?;

    for api_cell in [
        "KAFKA-K1-2-API-025-ADD-OFFSETS-TO-TXN",
        "KAFKA-K1-2-API-028-TXN-OFFSET-COMMIT",
    ] {
        let row = find_cell(artifact, "api_key_cells", api_cell)?;
        expect_text(
            row,
            "implementation_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.3",
        )?;
        expect_text(
            row,
            "real_service_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.13.3",
        )?;
    }

    let salt = find_cell(
        artifact,
        "negative_authentication_cells",
        "KAFKA-K1-2-NEG-AUTH-014-SALT-LENGTH",
    )?;
    expect_text(
        salt,
        "required_state",
        "REQUIRED_REJECT_SALT_SHORTER_THAN_8_BYTES_NO_APPLICATION_EFFECT",
    )?;
    expect_text(salt, "current_evidence_state", "STATIC_SOURCE")?;

    let iterations = find_cell(
        artifact,
        "negative_authentication_cells",
        "KAFKA-K1-2-NEG-AUTH-015-ITERATION-COUNT",
    )?;
    expect_text(
        iterations,
        "required_state",
        "REQUIRED_REJECT_ITERATIONS_OUTSIDE_4096_TO_65536_NO_APPLICATION_EFFECT",
    )?;
    expect_text(iterations, "current_evidence_state", "STATIC_SOURCE")?;

    for row in array(artifact, "negative_authentication_cells")? {
        let cell_id = text(row, "cell_id")?;
        let authority_ids = array(row, "source_authority_ids")?
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for required_authority in ["KAFKA-K1-SHARED-011", "KAFKA-K0-4-UNKNOWN-007"] {
            if !authority_ids.contains(required_authority) {
                return Err(format!(
                    "negative cell {cell_id} is missing direct authority {required_authority}"
                ));
            }
        }
    }

    let correlation = find_cell(
        artifact,
        "negotiation_transition_cells",
        "KAFKA-K1-2-NEG-006-CORRELATION",
    )?;
    expect_text(correlation, "current_evidence_state", "ROUTED_GAP")?;
    let correlation_authority = array(correlation, "source_authority_ids")?;
    let expected_correlation_authority =
        [json!("KAFKA-K0-4-GAP-020-NEGOTIATION-CORRELATION-RECOVERY")];
    if correlation_authority.as_slice() != expected_correlation_authority.as_slice() {
        return Err(format!(
            "correlation transition authority drift: {correlation_authority:?}"
        ));
    }

    let closure = artifact
        .get("api_schema_closure")
        .ok_or_else(|| "api_schema_closure is missing".to_owned())?;
    expect_number(closure, "minimum_semantic_key_count", 20)?;
    expect_bool(closure, "minimum_is_not_complete_reachability", true)?;
    expect_number(closure, "numeric_range_count_in_this_packet", 0)?;
    expect_bool(closure, "local_model_maxima_normative", false)?;
    if array(closure, "local_model_maxima")?.len() != 5 {
        return Err("local_model_maxima must retain exactly five non-normative rows".to_owned());
    }

    let policy = artifact
        .get("policy")
        .ok_or_else(|| "policy is missing".to_owned())?;
    expect_text(policy, "mode", "STATIC_ONLY_FAIL_CLOSED")?;
    expect_text(
        policy,
        "canonicalization_id",
        "KAFKA_K1_2_PROTOCOL_SECURITY_SUPPORT_POLICY_V1",
    )?;
    expect_text(policy, "missing_cell_state", "BLOCKING_MISSING")?;
    expect_text(policy, "extra_cell_state", "BLOCKING_UNDECLARED_EXTRA")?;
    expect_text(policy, "duplicate_cell_state", "BLOCKING_DUPLICATE")?;
    expect_text(policy, "changed_authority_state", "BLOCKING_SOURCE_DRIFT")?;
    expect_text(policy, "unowned_cell_state", "BLOCKING_UNOWNED")?;
    expect_text(
        policy,
        "unsupported_required_state",
        "BLOCKING_KEEP_INCUMBENT",
    )?;
    for key in [
        "planned_counts_as_executed",
        "static_counts_as_runtime",
        "local_model_counts_as_broker_parity",
        "wire_codec_counts_as_broker_parity",
        "config_counts_as_authentication",
    ] {
        expect_bool(policy, key, false)?;
    }

    let support_rule = text(policy, "support_rule")?;
    if !support_rule.starts_with(
        "Required target support and current evidence are independent. Every policy cell remains blocking",
    ) {
        return Err("support_rule does not cover every policy cell".to_owned());
    }
    for marker in [
        "UNKNOWN",
        "BLOCKED",
        "BLOCKED_EXTERNAL",
        "NOT_RUN",
        "CONFIG_ONLY",
        "WIRE_CODEC_ONLY",
        "LOCAL_MODEL_ONLY",
        "PROOF_ONLY",
        "UNPINNED",
        "STATIC_SOURCE",
        "ROUTED_GAP",
    ] {
        if !support_rule.contains(marker) {
            return Err(format!("support_rule is missing blocking state {marker}"));
        }
    }

    let security_rule = text(policy, "security_rule")?;
    for marker in [
        "Loopback plaintext remains accepted",
        "remote plaintext remains refused",
        "SASL exposes only SCRAM-SHA-256 or SCRAM-SHA-512 over TLS",
        "SASL_PLAINTEXT is forbidden",
    ] {
        if !security_rule.contains(marker) {
            return Err(format!("security_rule is missing marker {marker:?}"));
        }
    }
    Ok(())
}

fn check_policy_receipts(artifact: &Value) -> Result<(), String> {
    let receipt = artifact
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt is missing".to_owned())?;
    let counts = [
        ("authority_input_count", 15),
        ("broker_support_cell_count", 6),
        ("api_key_cell_count", 20),
        ("header_cell_count", 5),
        ("flexible_encoding_cell_count", 8),
        ("negotiation_transition_cell_count", 10),
        ("transport_security_cell_count", 8),
        ("credential_cell_count", 8),
        ("negative_authentication_cell_count", 15),
        ("protocol_binding_group_count", 10),
        ("total_policy_cell_count", 90),
        ("accepted_numeric_version_range_count", 0),
        ("promoted_supported_cell_count", 0),
        ("current_real_broker_receipt_count", 0),
        ("current_actual_native_binary_receipt_count", 0),
    ];
    for (key, expected) in counts {
        expect_number(receipt, key, expected)?;
    }
    for key in [
        "unique_cell_ids",
        "required_state_complete",
        "current_evidence_state_complete",
        "implementation_owner_complete",
        "verification_owner_complete",
        "terminal_gate_complete",
        "all_required_cells_block_migration",
        "k2_1_reachability_expansion_required",
        "unknown_or_blocked_cells_retained",
    ] {
        expect_bool(receipt, key, true)?;
    }
    expect_bool(receipt, "dynamic_execution_claimed", false)?;
    if !array(receipt, "missing_owner_rows")?.is_empty()
        || !array(receipt, "unowned_rows")?.is_empty()
    {
        return Err("coverage receipt contains missing or unowned rows".to_owned());
    }

    let disposition = artifact
        .get("disposition_receipt")
        .ok_or_else(|| "disposition_receipt is missing".to_owned())?;
    expect_bool(disposition, "k1_1_complete", true)?;
    expect_bool(disposition, "k1_2_policy_complete", true)?;
    expect_bool(disposition, "k1_3_complete", true)?;
    for key in [
        "k1_4_complete",
        "k1_5_complete",
        "k1_parent_complete",
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
        "on_missing_extra_duplicate_changed_unowned_unknown_unsupported_or_regression",
        "KEEP_INCUMBENT",
    )?;

    let boundaries = array(artifact, "no_claim_boundaries")?;
    if boundaries.len() != 9
        || boundaries
            .iter()
            .any(|boundary| boundary.as_str().is_none_or(str::is_empty))
    {
        return Err("no_claim_boundaries must contain nine non-empty rows".to_owned());
    }
    let boundary_digest = sorted_newline_sha256(
        boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .as_str()
                    .ok_or_else(|| "no-claim boundary must be text".to_owned())
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    if boundary_digest != NO_CLAIM_SHA256 {
        return Err(format!(
            "no-claim boundary drift: expected {NO_CLAIM_SHA256}, got {boundary_digest}"
        ));
    }
    let joined = boundaries
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "records no accepted numeric broker or API-version range",
        "does not prove compilation",
        "does not prove actual native-library linkage",
        "does not authorize production wiring",
    ] {
        if !joined.contains(marker) {
            return Err(format!("no-claim boundary missing marker {marker:?}"));
        }
    }
    Ok(())
}

fn check_source_and_document(root: &Path) -> Result<(), String> {
    let artifact_bytes = read_bytes(root, ARTIFACT_PATH)?;
    let artifact_sha = sha256_bytes(&artifact_bytes);
    if artifact_sha != ARTIFACT_SHA256 {
        return Err(format!(
            "artifact digest mismatch: expected {ARTIFACT_SHA256}, got {artifact_sha}"
        ));
    }
    let doc_bytes = read_bytes(root, DOC_PATH)?;
    let doc_sha = sha256_bytes(&doc_bytes);
    if doc_sha != DOC_SHA256 {
        return Err(format!(
            "document digest mismatch: expected {DOC_SHA256}, got {doc_sha}"
        ));
    }

    let doc = std::str::from_utf8(&doc_bytes)
        .map_err(|error| format!("{DOC_PATH} is not UTF-8: {error}"))?;
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("policy document must contain exactly one marker pair".to_owned());
    }
    let begin_position = doc
        .find(DOC_BEGIN)
        .ok_or_else(|| "policy document begin marker is missing".to_owned())?;
    let end_position = doc
        .find(DOC_END)
        .ok_or_else(|| "policy document end marker is missing".to_owned())?;
    if begin_position >= end_position {
        return Err("policy document markers are out of order".to_owned());
    }
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "The contract contains exactly 90 unique cells",
        "This list is a minimum semantic seed, not reachability closure",
        "No cell is promoted to `SUPPORTED`",
        "This packet was produced and inspected statically",
        "Any missing, extra, duplicate, changed, unowned, unknown, unsupported, or regressed",
    ] {
        if !doc.contains(marker) {
            return Err(format!("policy document is missing marker {marker:?}"));
        }
    }

    let producer = read_text(root, PRODUCER_PATH)?;
    for marker in [
        "pub enum KafkaSaslMechanism {\n    /// SCRAM with SHA-256.\n    ScramSha256,\n    /// SCRAM with SHA-512.\n    ScramSha512,\n}",
        "Self::ScramSha256 => \"SCRAM-SHA-256\",\n            Self::ScramSha512 => \"SCRAM-SHA-512\"",
        "must reject salts shorter than 8 bytes,\n/// reject iteration counts outside `4096..=65536`, verify server-final proofs",
        "pub enum KafkaSecurityConfig {\n    /// Plaintext transport. Valid only for loopback brokers unless the",
        "Tls(KafkaTlsConfig),\n    /// SASL/SCRAM over TLS. SASL_PLAINTEXT is intentionally not exposed.\n    SaslSsl(KafkaSaslConfig),",
        "KafkaSecurityConfig::SaslSsl(sasl) => {\n            client.set(\"security.protocol\", \"sasl_ssl\");\n            client.set(\"sasl.mechanisms\", sasl.mechanism.as_librdkafka_str());",
        "#[cfg(any(test, debug_assertions))]\n    #[must_use]\n    pub const fn allow_insecure_transport_for_testing",
    ] {
        if !producer.contains(marker) {
            return Err(format!("producer source is missing marker {marker:?}"));
        }
    }
    if producer.contains("SaslPlaintext") {
        return Err("producer source unexpectedly exposes a SaslPlaintext variant".to_owned());
    }

    let manifest = read_text(root, MANIFEST_PATH)?;
    if !manifest
        .contains("rdkafka = { version = \"0.39\", default-features = false, optional = true }")
    {
        return Err("root rdkafka declaration drifted".to_owned());
    }

    let adr = read_text(root, ADR_PATH)?;
    for marker in [
        "SASL only over SSL",
        "plaintext **refused**",
        "credentials",
        "zeroized and redacted",
        "insecure opt-out **test-only**",
    ] {
        if !adr.contains(marker) {
            return Err(format!("ADR is missing policy marker {marker:?}"));
        }
    }
    Ok(())
}

#[test]
fn kafka_k1_2_packet_is_exact_owned_and_fail_closed() {
    let root = repo_root();
    let artifact = parse_artifact().expect("K1.2 artifact must parse");
    check_metadata(&artifact).expect("K1.2 metadata must remain exact");
    check_input_pins(&root, &artifact).expect("K1.2 authority inputs must remain byte-pinned");
    check_authority_views(&artifact).expect("K1.2 authority views must remain exact");
    check_tracker_routes(&root, &artifact).expect("K1.2 owners and gates must exist in tracker");
    check_source_authority_resolution(&root, &artifact)
        .expect("K1.2 policy rows must resolve to pinned authority tokens");
    check_policy_cells(&artifact).expect("K1.2 policy cells must remain exact and fail-closed");
    check_source_and_document(&root)
        .expect("K1.2 source facts and operator document must remain exact");
}

#[test]
fn kafka_k1_2_mutations_fail_closed() {
    let artifact = parse_artifact().expect("K1.2 artifact must parse");
    check_policy_cells(&artifact).expect("the unmodified K1.2 policy must satisfy its checker");

    let mut promoted = artifact.clone();
    promoted["api_key_cells"][0]["current_evidence_state"] = json!("SUPPORTED");
    assert!(
        check_policy_cells(&promoted).is_err(),
        "a static cell must not be promotable to supported"
    );

    let mut invented_range = artifact.clone();
    invented_range["api_key_cells"][0]["accepted_version_range"] = json!({"min": 0, "max": 9});
    assert!(
        check_policy_cells(&invented_range).is_err(),
        "an invented production version range must fail closed"
    );

    let mut missing_negative = artifact.clone();
    missing_negative["negative_authentication_cells"]
        .as_array_mut()
        .expect("negative cells must be an array")
        .pop();
    assert!(
        check_policy_cells(&missing_negative).is_err(),
        "a missing negative cell must fail closed"
    );

    let mut weakened_transport = artifact.clone();
    let transport_cells = weakened_transport["transport_security_cells"]
        .as_array_mut()
        .expect("transport cells must be an array");
    let cleartext_index = transport_cells
        .iter()
        .position(|row| {
            row.get("cell_id").and_then(Value::as_str) == Some("KAFKA-K1-2-SEC-007-SASL-PLAINTEXT")
        })
        .expect("cleartext authentication cell must exist");
    transport_cells[cleartext_index]["required_state"] = json!("ACCEPTED");
    assert!(
        check_policy_cells(&weakened_transport).is_err(),
        "weakening the connection policy must fail closed"
    );

    let mut duplicate = artifact.clone();
    let first_id = duplicate["api_key_cells"][0]["cell_id"].clone();
    duplicate["api_key_cells"][1]["cell_id"] = first_id;
    assert!(
        check_policy_cells(&duplicate).is_err(),
        "a duplicate policy cell must fail closed"
    );

    let mut changed_required = artifact.clone();
    changed_required["api_key_cells"][0]["required_state"] = json!("ACCEPTED");
    assert!(
        check_policy_cells(&changed_required).is_err(),
        "changing a non-special required state must fail closed"
    );

    let mut swapped_owners = artifact.clone();
    let first_owner = swapped_owners["broker_support_cells"][0]["implementation_owner"].clone();
    let second_owner = swapped_owners["broker_support_cells"][2]["implementation_owner"].clone();
    swapped_owners["broker_support_cells"][0]["implementation_owner"] = second_owner;
    swapped_owners["broker_support_cells"][2]["implementation_owner"] = first_owner;
    assert!(
        check_policy_cells(&swapped_owners).is_err(),
        "swapping otherwise-valid owners must fail closed"
    );

    let mut weakened_boundary = artifact.clone();
    weakened_boundary["no_claim_boundaries"][0] =
        json!("This packet proves every production behavior.");
    assert!(
        check_policy_cells(&weakened_boundary).is_err(),
        "weakening a no-claim boundary must fail closed"
    );

    let mut unbacked = artifact.clone();
    unbacked["negotiation_transition_cells"][0]
        .as_object_mut()
        .expect("negotiation cell must be an object")
        .remove("source_authority_ids");
    assert!(
        check_policy_cells(&unbacked).is_err(),
        "removing a source-authority join must fail closed"
    );

    let mut unowned = artifact;
    unowned["broker_support_cells"][0]["implementation_owner"] = json!("");
    assert!(
        check_policy_cells(&unowned).is_err(),
        "an unowned policy cell must fail closed"
    );
}
