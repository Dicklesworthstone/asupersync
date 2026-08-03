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

const ARTIFACT_SHA256: &str =
    "6275dc59f144df73eed6b64f68f5b9a37707578a3b9fded2ef5aeaa157d0c581";
const DOC_SHA256: &str =
    "9ee510559ec9c3d314c49afc135516e721a02718dda426fb418e6019dc45293f";

const ARTIFACT_ID: &str = "kafka-k1-protocol-security-support-policy-v1";
const PROGRAM_ID: &str = "dependency-sovereignty-rev5";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1.2";
const PARENT_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const ADR_ID: &str = "DEP-ADR-009";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const BASELINE_REVISION: &str = "f3a02fe6e6e5d0dca6db91204fcf2da53c22a5c7";
const INVENTORY_STATE: &str =
    "K1_2_PROTOCOL_BROKER_AND_SECURITY_POLICY_FROZEN_KEEP_INCUMBENT";

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
        13,
        "de444d7e578ce2727334ae83afdc299711e634b682133e6a78b457e682d746e3",
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

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
    format!("{hasher:x}")
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
        Err(format!("{key} mismatch: expected {expected:?}, got {actual:?}"))
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
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| format!("{path} is not UTF-8: {error}"))?;
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
        return Err(format!("unexpected security semantic IDs: {semantic_ids:?}"));
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
        ("PROOF_ONLY", 1),
        ("ROUTED_GAP", 1),
        ("STATIC_SOURCE", 5),
        ("UNKNOWN", 25),
        ("UNPINNED", 1),
        ("WIRE_CODEC_ONLY", 12),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    let mut all_ids = BTreeSet::new();
    let mut state_counts = BTreeMap::new();
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
                let owner = real_service_owner.as_str().filter(|value| !value.is_empty()).ok_or_else(
                    || format!("cell {cell_id} real_service_owner must be non-empty text"),
                )?;
                if !owner.starts_with("asupersync-dep-p7-kafka-removal-sarszu.2.") {
                    return Err(format!(
                        "cell {cell_id} has out-of-program real_service_owner {owner}"
                    ));
                }
            }

            let gates = array(row, "terminal_gates")?;
            if gates.is_empty()
                || gates
                    .iter()
                    .any(|gate| gate.as_str().is_none_or(str::is_empty))
            {
                return Err(format!("cell {cell_id} has incomplete terminal gates"));
            }
            if let Some(authority_ids) = row.get("source_authority_ids") {
                let authority_ids = authority_ids
                    .as_array()
                    .ok_or_else(|| format!("cell {cell_id} source_authority_ids must be an array"))?;
                if authority_ids.is_empty()
                    || authority_ids
                        .iter()
                        .any(|id| id.as_str().is_none_or(str::is_empty))
                {
                    return Err(format!("cell {cell_id} has incomplete source authority"));
                }
            }
        }
    }

    if total != 88 || all_ids.len() != 88 {
        return Err(format!(
            "combined policy coverage mismatch: total {total}, unique {}",
            all_ids.len()
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
    if api_pairs != API_KEYS {
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
    let api_pair_digest = sorted_newline_sha256(
        api_pairs
            .iter()
            .map(|(key, name)| format!("{key}\t{name}"))
            .collect::<Vec<_>>(),
    );
    if api_pair_digest != "3aca9d044b63403f051110d8e9d76173b5c61403f494bd269176c892309dafad" {
        return Err(format!("semantic API-key projection drift: {api_pair_digest}"));
    }

    let api_names = API_KEYS.iter().map(|(_, name)| *name).collect::<BTreeSet<_>>();
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
    if all_id_digest != "68829645b478a101cc22799cd727e35513dbcd7eb94306e65e6d2da33351eb89" {
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
        ("negative_authentication_cell_count", 13),
        ("protocol_binding_group_count", 10),
        ("total_policy_cell_count", 88),
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
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "The contract contains exactly 88 unique cells",
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
        "pub enum KafkaSaslMechanism",
        "ScramSha256",
        "ScramSha512",
        "pub enum KafkaSecurityConfig",
        "Plaintext",
        "Tls(KafkaTlsConfig)",
        "SaslSsl(KafkaSaslConfig)",
        "cfg(any(test, debug_assertions))",
    ] {
        if !producer.contains(marker) {
            return Err(format!("producer source is missing marker {marker:?}"));
        }
    }
    if producer.contains("SaslPlaintext") {
        return Err("producer source unexpectedly exposes a SaslPlaintext variant".to_owned());
    }

    let manifest = read_text(root, MANIFEST_PATH)?;
    if !manifest.contains(
        "rdkafka = { version = \"0.39\", default-features = false, optional = true }",
    ) {
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
    check_policy_cells(&artifact).expect("K1.2 policy cells must remain exact and fail-closed");
    check_source_and_document(&root)
        .expect("K1.2 source facts and operator document must remain exact");
}

#[test]
fn kafka_k1_2_mutations_fail_closed() {
    let artifact = parse_artifact().expect("K1.2 artifact must parse");

    let mut promoted = artifact.clone();
    promoted["api_key_cells"][0]["current_evidence_state"] = json!("SUPPORTED");
    assert!(
        check_policy_cells(&promoted).is_err(),
        "a static cell must not be promotable to supported"
    );

    let mut invented_range = artifact.clone();
    invented_range["api_key_cells"][0]["accepted_version_range"] =
        json!({"min": 0, "max": 9});
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
            row.get("cell_id").and_then(Value::as_str)
                == Some("KAFKA-K1-2-SEC-007-SASL-PLAINTEXT")
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

    let mut unowned = artifact;
    unowned["broker_support_cells"][0]["implementation_owner"] = json!("");
    assert!(
        check_policy_cells(&unowned).is_err(),
        "an unowned policy cell must fail closed"
    );
}
