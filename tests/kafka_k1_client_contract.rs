//! Static contract for the first Kafka K1 client-contract slice.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.2.1.1
//! Fixture: artifacts/kafka_k1_obligation_index_v1.json
//!
//! This integration test reads checked-in repository bytes only. It does not
//! contact a broker, execute a client, or promote planned, local-model,
//! wire-only, compile-only, UNKNOWN, or blocked evidence into runtime proof.

#![allow(dead_code, missing_docs)]

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k1_obligation_index_v1.json";
const DOC_PATH: &str = "docs/kafka_k1_client_contract.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const ARTIFACT_SHA256: &str = "62becb6593cd86f48ef3e73145d65ea7b46e3b278744ed27c43a9ce4290cc07a";
const DOC_SHA256: &str = "3657c47298408fdd5f6906376265ac3c587085ba5b0df67988fac7266fd6e116";

const ARTIFACT_ID: &str = "kafka-k1-obligation-index-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1.1";
const PARENT_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const ADR_ID: &str = "DEP-ADR-009";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const BASELINE_REVISION: &str = "03dea9e1556eac3d60a393a61bbcf875d49a96dd";
const INVENTORY_STATE: &str = "K1_1_AUTHORITY_AND_OBLIGATION_NAMESPACE_FROZEN_KEEP_INCUMBENT";

const K0_1_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const K0_3_PATH: &str = "artifacts/kafka_downstream_user_journey_inventory_v1.json";
const K0_4_PATH: &str = "artifacts/kafka_broker_fixture_provenance_matrix_v1.json";
const K0_5_PATH: &str = "artifacts/kafka_k0_baseline_disposition_v1.json";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const ADR_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";

const ALL_DEFINITION_AND_REFERENCE_COUNT: usize = 1_030;
const PRIMARY_DEFINITION_COUNT: usize = 903;
const CORE_DEFINITION_COUNT: usize = 892;
const CONTRADICTION_INPUT_COUNT: usize = 11;
const AUTHORITY_REFERENCE_COUNT: usize = 127;
const K0_5_AGGREGATE_ID_COUNT: usize = 32;
const K1_OBLIGATION_COUNT: usize = 279;
const LOW_EVIDENCE_STATE_COUNT: usize = 446;

const PRIMARY_ID_SHA256: &str = "38eb986feff75d2e1e172e444e7d488c765ab42910b6b470056852dea3b0cb6e";
const CORE_ID_SHA256: &str = "43d9deb2ff6bfa772ec058e8e32e4eb4fb3be099d93c3b152685721be05d4eea";
const CONTRADICTION_ID_SHA256: &str =
    "60a656176b398a9b045b8c5cc1c2f2cede611683d3330c2a519a70ebf9bb72f0";
const AUTHORITY_REFERENCE_ID_SHA256: &str =
    "a2336ba563186e1bc4a0a935ced3731e2292e8a6d54b0858311662113b267a94";
const AUTHORITY_REFERENCE_MAPPING_SHA256: &str =
    "0a88e36135222e48bfeab5095be3896ef946cc9fa05f38cbd19d2cb656107cf9";
const K0_5_AGGREGATE_ID_SHA256: &str =
    "b37d690dd8293c23a0ed2449bcd019864341f97fe0651798583602804da2fd45";
const NORMALIZED_OBLIGATION_SHA256: &str =
    "cd4ff24ac2deed867d81d1fb9d81c08f31e57de5c7e77c84e1ea3657e2fa0f37";
const SOURCE_PRECISE_OBLIGATION_SHA256: &str =
    "846a643da80fa9ad9dd78b9e13520981ef8811b91839686608ec7c80a45a4414";
const LOW_EVIDENCE_STATE_SHA256: &str =
    "8d8e318ffbbcd5e26cb5320ba3fc03075624a974b214ea0cf2d10e769838543f";
const EXPOSURE_SHA256: &str = "cec04b907f94b381e8c1e4e9c38a5cdee6d0d89508f52aab5f2c92eab15fb70f";
const COARSE_EXPOSURE_SHA256: &str =
    "d1ebf84a5bd4654ec12cedb880eab9f7f1751fbd758267ce4395549de8affade";
const DERIVED_SHARED_SHA256: &str =
    "0c50366802e6fbe8d8c2eccfebcd60a20d7daeed1f0304741ee464fb368a717f";
const TRACKER_PROJECTION_SHA256: &str =
    "6ea2a9c24adbe6c1618be0e946116e71c20a4ed2bfefde2459f17534cfd53372";

const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K1 CLIENT CONTRACT -->";
const DOC_END: &str = "<!-- END KAFKA K1 CLIENT CONTRACT -->";

const ROOT_KEYS: &[&str] = &[
    "adr_id",
    "artifact_id",
    "authority",
    "authority_inputs",
    "authority_row_pins",
    "baseline_revision",
    "bead_id",
    "capability_id",
    "captured_date_utc",
    "coverage_receipt",
    "disposition_receipt",
    "exposure_model",
    "inventory_state",
    "k1_owner_handoffs",
    "namespace_projection",
    "no_claim_boundaries",
    "parent_bead_id",
    "policy",
    "program_id",
    "protocol_binding_model",
    "schema_version",
    "standalone_owner_boundaries",
    "state_model",
    "tracker_topology",
];

const NAMESPACE_KEYS: &[&str] = &[
    "authority_reference_views",
    "canonicalization",
    "claims_projection",
    "cross_authority_reference_views",
    "definition_reference_census",
    "derived_shared_obligations",
    "k0_5_aggregate_namespace",
    "k1_obligation_projection",
    "low_evidence_state_projection",
    "named_definition_views",
    "non_obligation_id_fields",
    "primary_definitions",
    "route_ownership",
    "source_pin_rollup",
    "typed_nested_reference_classes",
    "unknown_blockers",
];

const AUTHORITY_INPUT_PATHS: &[&str] = &[
    "Cargo.toml",
    "artifacts/kafka_k0_baseline_disposition_v1.json",
    "conformance/src/kafka_record_batch_v2.rs",
    "docs/adr/dep_plan_adr_009_kafka_client.md",
    "docs/kafka_k0_baseline_disposition.md",
    "src/messaging/kafka.rs",
    "src/messaging/kafka_consumer.rs",
    "src/messaging/mod.rs",
    "tests/kafka_k0_baseline_disposition_contract.rs",
];

const K1_TRACKER_IDS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.2.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.1.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.1.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.1.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.2",
];

const LOW_EVIDENCE_STATES: &[&str] = &[
    "UNKNOWN",
    "BLOCKED",
    "BLOCKED_EXTERNAL",
    "NOT_RUN",
    "UNPINNED",
    "LOCAL_MODEL_ONLY",
    "WIRE_CODEC_ONLY",
];

#[derive(Clone)]
struct AuthorityInputs {
    k0_1: Value,
    k0_2: Value,
    k0_3: Value,
    k0_4: Value,
    k0_5: Value,
    capability_registry: Value,
    adr_registry: Value,
    tracker_rows: Vec<Value>,
}

#[derive(Clone)]
struct Definition {
    stage: String,
    collection: String,
    raw_id: String,
    authority_reference: bool,
    contradiction_input: bool,
}

impl Definition {
    fn tuple(&self) -> String {
        format!("{}\t{}\t{}", self.stage, self.collection, self.raw_id)
    }
}

#[derive(Clone)]
struct ObligationRow {
    stage: String,
    collection: String,
    id: String,
}

impl ObligationRow {
    fn tuple(&self) -> String {
        format!("{}\t{}\t{}", self.stage, self.collection, self.id)
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_bytes(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    fs::read(root.join(path)).map_err(|error| format!("failed to read {path}: {error}"))
}

fn read_text(root: &Path, path: &str) -> Result<String, String> {
    String::from_utf8(read_bytes(root, path)?)
        .map_err(|error| format!("{path} is not UTF-8 text: {error}"))
}

fn parse_json(root: &Path, path: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(root, path)?)
        .map_err(|error| format!("invalid JSON in {path}: {error}"))
}

fn parse_jsonl(root: &Path, path: &str) -> Result<Vec<Value>, String> {
    let text = read_text(root, path)?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("invalid JSONL in {path} at line {}: {error}", index + 1))
        })
        .collect()
}

fn load_inputs(root: &Path) -> Result<AuthorityInputs, String> {
    Ok(AuthorityInputs {
        k0_1: parse_json(root, K0_1_PATH)?,
        k0_2: parse_json(root, K0_2_PATH)?,
        k0_3: parse_json(root, K0_3_PATH)?,
        k0_4: parse_json(root, K0_4_PATH)?,
        k0_5: parse_json(root, K0_5_PATH)?,
        capability_registry: parse_json(root, CAPABILITY_REGISTRY_PATH)?,
        adr_registry: parse_json(root, ADR_REGISTRY_PATH)?,
        tracker_rows: parse_jsonl(root, TRACKER_PATH)?,
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
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(canonical)
        }
        Value::Array(rows) => Value::Array(rows.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn canonical_rows_sha256(rows: Vec<&Value>) -> Result<String, String> {
    rows.into_iter()
        .map(|row| {
            serde_json::to_string(&canonicalize(row))
                .map_err(|error| format!("failed to serialize canonical JSON: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(sorted_newline_sha256)
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn object_mut<'a>(value: &'a mut Value, name: &str) -> Result<&'a mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} must be an array"))
}

fn array_mut<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, String> {
    value
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("{field} must be an array"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be text"))
}

fn uint(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field} must be an unsigned integer"))
}

fn flag(value: &Value, field: &str) -> Result<bool, String> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{field} must be boolean"))
}

fn at<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value, String> {
    value
        .pointer(pointer)
        .ok_or_else(|| format!("missing JSON pointer {pointer}"))
}

fn at_text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    at(value, pointer)?
        .as_str()
        .ok_or_else(|| format!("{pointer} must be text"))
}

fn at_uint(value: &Value, pointer: &str) -> Result<u64, String> {
    at(value, pointer)?
        .as_u64()
        .ok_or_else(|| format!("{pointer} must be an unsigned integer"))
}

fn find_unique<'a>(rows: &'a [Value], field: &str, expected: &str) -> Result<&'a Value, String> {
    let matches = rows
        .iter()
        .filter(|row| row.get(field).and_then(Value::as_str) == Some(expected))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one {field}={expected}, found {}",
            matches.len()
        ));
    }
    Ok(matches[0])
}

fn find_unique_in<'a>(
    value: &'a Value,
    collection: &str,
    field: &str,
    expected: &str,
) -> Result<&'a Value, String> {
    find_unique(array(value, collection)?, field, expected)
}

fn exact_text_set(value: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn validate_root_identity_and_policy(packet: &Value) -> Result<(), String> {
    let actual_keys = object(packet, "packet")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_keys = ROOT_KEYS.iter().copied().collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err("K1.1 root key set drifted".to_owned());
    }
    let namespace = at(packet, "/namespace_projection")?;
    let actual_namespace_keys = object(namespace, "namespace_projection")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_namespace_keys = NAMESPACE_KEYS.iter().copied().collect::<BTreeSet<_>>();
    if actual_namespace_keys != expected_namespace_keys {
        return Err("K1.1 namespace key set drifted".to_owned());
    }
    for (field, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("parent_bead_id", PARENT_BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("adr_id", ADR_ID),
        ("captured_date_utc", CAPTURED_DATE_UTC),
        ("baseline_revision", BASELINE_REVISION),
        ("inventory_state", INVENTORY_STATE),
    ] {
        if text(packet, field)? != expected {
            return Err(format!("{field} drifted"));
        }
    }
    if uint(packet, "schema_version")? != 1 {
        return Err("schema_version drifted".to_owned());
    }

    let policy = packet
        .get("policy")
        .ok_or_else(|| "policy is missing".to_owned())?;
    for (field, expected) in [
        ("mode", "STATIC_ONLY_FAIL_CLOSED"),
        ("missing_input_state", "BLOCKING_MISSING"),
        ("missing_row_state", "BLOCKING_MISSING"),
        ("extra_row_state", "BLOCKING_UNDECLARED_EXTRA"),
        (
            "duplicate_definition_state",
            "BLOCKING_DUPLICATE_DEFINITION",
        ),
        ("unowned_row_state", "BLOCKING_UNOWNED"),
        ("invalid_reference_state", "BLOCKING_INVALID_REFERENCE"),
    ] {
        if text(policy, field)? != expected {
            return Err(format!("policy.{field} drifted"));
        }
    }
    for field in [
        "child_rows_duplicated",
        "planned_counts_as_executed",
        "silent_skip_counts_as_pass",
        "static_counts_as_runtime",
        "wire_codec_counts_as_client_parity",
    ] {
        if flag(policy, field)? {
            return Err(format!("policy.{field} must stay false"));
        }
    }

    let authority = packet
        .get("authority")
        .ok_or_else(|| "authority is missing".to_owned())?;
    if text(authority, "registry_disposition")? != "KEEP_UNTIL_PARITY"
        || text(authority, "current_action")? != "KEEP_INCUMBENT"
        || text(authority, "k1_terminal_bead")? != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
        || text(authority, "sole_conditional_cutover_bead")?
            != "asupersync-dep-p7-kafka-removal-sarszu.2.15"
    {
        return Err("authority disposition or terminal ownership drifted".to_owned());
    }
    for field in [
        "dependency_exit_allowed",
        "feature_removal_allowed",
        "api_removal_allowed",
        "capability_removal_allowed",
        "file_deletion_allowed",
        "production_wiring_allowed",
        "oracle_retirement_allowed",
        "cutover_allowed",
    ] {
        if flag(authority, field)? {
            return Err(format!("authority.{field} must stay false"));
        }
    }
    Ok(())
}

fn validate_authority_input_pins(packet: &Value, root: &Path) -> Result<(), String> {
    let rows = array(packet, "authority_inputs")?;
    if rows.len() != AUTHORITY_INPUT_PATHS.len() {
        return Err("authority input count drifted".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for row in rows {
        let input_id = text(row, "input_id")?;
        let path = text(row, "path")?;
        if !ids.insert(input_id.to_owned()) || !paths.insert(path.to_owned()) {
            return Err("authority input ID or path duplicated".to_owned());
        }
        let bytes = read_bytes(root, path)?;
        let input_text = std::str::from_utf8(&bytes)
            .map_err(|error| format!("authority input {path} is not text: {error}"))?;
        if bytes.len() as u64 != uint(row, "byte_count")?
            || input_text.lines().count() as u64 != uint(row, "record_count")?
            || sha256_bytes(&bytes) != text(row, "sha256")?
        {
            return Err(format!("authority input pin drifted for {path}"));
        }
        if text(row, "role")?.is_empty() {
            return Err(format!("authority input role missing for {path}"));
        }
    }
    let expected = AUTHORITY_INPUT_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    if paths != expected {
        return Err("authority input path set drifted".to_owned());
    }
    Ok(())
}

fn validate_inherited_child_artifact_pins(
    packet: &Value,
    root: &Path,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    let child_revisions = at(packet, "/authority/k0_child_baseline_revisions")?;
    for (packet_id, path, artifact) in [
        ("K0.1", K0_1_PATH, &inputs.k0_1),
        ("K0.2", K0_2_PATH, &inputs.k0_2),
        ("K0.3", K0_3_PATH, &inputs.k0_3),
        ("K0.4", K0_4_PATH, &inputs.k0_4),
    ] {
        let child = find_unique_in(&inputs.k0_5, "child_packets", "packet_id", packet_id)?;
        let artifact_pin = find_unique(array(child, "files")?, "role", "ARTIFACT")?;
        let bytes = read_bytes(root, path)?;
        let input_text = std::str::from_utf8(&bytes)
            .map_err(|error| format!("inherited child artifact {path} is not text: {error}"))?;
        if text(artifact_pin, "path")? != path
            || bytes.len() as u64 != uint(artifact_pin, "byte_count")?
            || input_text.lines().count() as u64 != uint(artifact_pin, "record_count")?
            || sha256_bytes(&bytes) != text(artifact_pin, "sha256")?
        {
            return Err(format!("K0.5 child artifact pin drifted for {packet_id}"));
        }
        if text(artifact, "artifact_id")? != text(child, "artifact_id")?
            || uint(artifact, "schema_version")? != uint(child, "schema_version")?
            || text(artifact, "baseline_revision")? != text(child, "baseline_revision")?
            || text(artifact, "inventory_state")? != text(child, "inventory_state")?
            || text(child_revisions, packet_id)? != text(child, "baseline_revision")?
        {
            return Err(format!("K0.5 child identity drifted for {packet_id}"));
        }
    }
    Ok(())
}

fn selected_pin_rows<'a>(
    pin_id: &str,
    inputs: &'a AuthorityInputs,
) -> Result<Vec<&'a Value>, String> {
    match pin_id {
        "K1-ROW-CAPABILITY" => Ok(array(&inputs.capability_registry, "capabilities")?
            .iter()
            .filter(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
            .collect()),
        "K1-ROW-CAPABILITY-TERMINAL-OWNERS" => Ok(array(
            inputs
                .capability_registry
                .get("graph_signoff_report")
                .ok_or_else(|| "graph_signoff_report missing".to_owned())?,
            "terminal_owner_remaps",
        )?
        .iter()
        .filter(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .collect()),
        "K1-ROW-CAPABILITY-JOURNEY" => Ok(array(&inputs.capability_registry, "journey_inventory")?
            .iter()
            .filter(|row| {
                row.get("capability_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(CAPABILITY_ID)))
            })
            .collect()),
        "K1-ROW-ADR-ROSTER" => Ok(array(&inputs.adr_registry, "roster")?
            .iter()
            .filter(|row| row.get("adr_id").and_then(Value::as_str) == Some(ADR_ID))
            .collect()),
        "K1-ROW-ADR-DECISION" => Ok(array(&inputs.adr_registry, "adrs")?
            .iter()
            .filter(|row| row.get("adr_id").and_then(Value::as_str) == Some(ADR_ID))
            .collect()),
        "K1-ROW-ADR-LOSS-FIXTURE" => Ok(array(&inputs.adr_registry, "known_loss_fixtures")?
            .iter()
            .filter(|row| row.get("adr_id").and_then(Value::as_str) == Some(ADR_ID))
            .collect()),
        _ => Err(format!("unknown authority row pin {pin_id}")),
    }
}

fn validate_authority_row_pins(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let pins = array(packet, "authority_row_pins")?;
    let expected_ids = [
        "K1-ROW-CAPABILITY",
        "K1-ROW-CAPABILITY-TERMINAL-OWNERS",
        "K1-ROW-CAPABILITY-JOURNEY",
        "K1-ROW-ADR-ROSTER",
        "K1-ROW-ADR-DECISION",
        "K1-ROW-ADR-LOSS-FIXTURE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let mut actual_ids = BTreeSet::new();
    for pin in pins {
        let pin_id = text(pin, "pin_id")?;
        if !actual_ids.insert(pin_id.to_owned()) {
            return Err(format!("duplicate authority row pin {pin_id}"));
        }
        let selected = selected_pin_rows(pin_id, inputs)?;
        if selected.len() as u64 != uint(pin, "row_count")? {
            return Err(format!("authority row count drifted for {pin_id}"));
        }
        if canonical_rows_sha256(selected)? != text(pin, "sha256")? {
            return Err(format!("authority row hash drifted for {pin_id}"));
        }
    }
    if actual_ids != expected_ids {
        return Err("authority row pin set drifted".to_owned());
    }
    Ok(())
}

fn validate_governing_authority(inputs: &AuthorityInputs) -> Result<(), String> {
    let capability = find_unique_in(
        &inputs.capability_registry,
        "capabilities",
        "capability_id",
        CAPABILITY_ID,
    )?;
    if text(capability, "disposition")? != "KEEP_UNTIL_PARITY"
        || text(capability, "evidence_state")? != "BASELINE_PLANNED"
        || text(capability, "cutover_state")? != "KEEP_INCUMBENT"
        || !exact_text_set(capability, "features")?.contains("kafka")
        || !text(capability, "no_claim_boundary")?.contains("not a Kafka client")
    {
        return Err("live CAP-KAFKA authority drifted".to_owned());
    }
    let owners = exact_text_set(capability, "dependency_owners")?;
    if owners
        != ["librdkafka", "rdkafka"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("CAP-KAFKA dependency owners drifted".to_owned());
    }

    let adr = find_unique_in(&inputs.adr_registry, "adrs", "adr_id", ADR_ID)?;
    if text(adr, "state")? != "RESOLVED"
        || text(adr, "decision")? != "KEEP_UNTIL_PARITY"
        || !exact_text_set(adr, "capability_ids")?.contains(CAPABILITY_ID)
        || !text(adr, "no_claim_boundary")?.contains("does not prove")
    {
        return Err("live DEP-ADR-009 authority drifted".to_owned());
    }

    if text(&inputs.k0_5, "artifact_id")? != "kafka-k0-baseline-disposition-v1"
        || text(&inputs.k0_5, "capability_id")? != CAPABILITY_ID
        || at_text(&inputs.k0_5, "/authority/current_action")? != "KEEP_INCUMBENT"
        || at_text(&inputs.k0_5, "/disposition_receipt/incumbent_disposition")? != "KEEP_INCUMBENT"
        || at(&inputs.k0_5, "/disposition_receipt/migration_eligible")?.as_bool() != Some(false)
        || at(&inputs.k0_5, "/disposition_receipt/cutover_allowed")?.as_bool() != Some(false)
    {
        return Err("K0.5 governing disposition drifted".to_owned());
    }
    Ok(())
}

fn add_definitions(
    definitions: &mut Vec<Definition>,
    stage: &str,
    artifact: &Value,
    collection: &str,
    id_field: &str,
    authority_reference: bool,
    contradiction_input: bool,
) -> Result<(), String> {
    for row in array(artifact, collection)? {
        definitions.push(Definition {
            stage: stage.to_owned(),
            collection: collection.to_owned(),
            raw_id: text(row, id_field)?.to_owned(),
            authority_reference,
            contradiction_input,
        });
    }
    Ok(())
}

fn collect_definitions(inputs: &AuthorityInputs) -> Result<Vec<Definition>, String> {
    let mut definitions = Vec::new();
    for (collection, id_field) in [
        ("source_pins", "pin_id"),
        ("compilation_profiles", "profile_id"),
        ("public_symbols", "symbol_id"),
        ("backend_bindings", "binding_id"),
        ("cfg_branch_inventory", "branch_id"),
        ("feature_disabled_behavior", "behavior_id"),
        ("routed_gaps", "gap_id"),
    ] {
        add_definitions(
            &mut definitions,
            "K0.1",
            &inputs.k0_1,
            collection,
            id_field,
            false,
            false,
        )?;
    }
    for (collection, id_field) in [
        ("source_pins", "pin_id"),
        ("profile_disposition_groups", "profile_group_id"),
        ("configuration_fields", "semantic_id"),
        ("enum_semantics", "semantic_id"),
        ("operations", "semantic_id"),
        ("callable_helpers", "semantic_id"),
        ("explicit_absences", "absence_id"),
        ("routed_findings", "finding_id"),
    ] {
        add_definitions(
            &mut definitions,
            "K0.2",
            &inputs.k0_2,
            collection,
            id_field,
            false,
            false,
        )?;
    }
    for (collection, id_field, authority_reference) in [
        ("source_pins", "pin_id", false),
        ("occurrence_disposition_groups", "disposition_id", false),
        ("search_queries", "query_id", false),
        ("k0_1_symbol_dispositions", "symbol_id", true),
        ("k0_2_semantic_dispositions", "semantic_id", true),
        ("non_consumer_dispositions", "disposition_id", false),
        ("local_consumers", "consumer_id", false),
        ("local_inventory_rows", "row_id", false),
        ("atomic_test_cases", "case_id", false),
        ("documentation_claims", "claim_id", false),
        ("compilation_profiles", "profile_id", false),
        ("feature_platform_cells", "cell_id", false),
        ("user_journeys", "journey_id", false),
        ("evidence_claims", "evidence_id", false),
        ("external_searches", "external_id", false),
        ("owned_unknowns", "unknown_id", false),
        ("routed_gaps", "gap_id", false),
        ("call_site_groups", "group_id", false),
    ] {
        add_definitions(
            &mut definitions,
            "K0.3",
            &inputs.k0_3,
            collection,
            id_field,
            authority_reference,
            false,
        )?;
    }
    for (collection, id_field, contradiction_input) in [
        ("direct_source_pins", "pin_id", false),
        (
            "fixture_classification_profiles",
            "classification_profile_id",
            false,
        ),
        ("fixture_census", "fixture_id", false),
        ("environment_identities", "environment_id", false),
        ("locked_dependency_identity", "vector_id", false),
        ("native_build_vectors", "vector_id", false),
        ("broker_api_version_vectors", "vector_id", false),
        ("compression_vectors", "vector_id", false),
        ("transport_auth_vectors", "vector_id", false),
        ("topology_vectors", "vector_id", false),
        ("fault_lifecycle_vectors", "vector_id", false),
        ("source_contradictions", "contradiction_id", true),
        ("evidence_claims", "claim_id", false),
        ("owned_unknowns", "unknown_id", false),
        ("routed_gaps", "gap_id", false),
    ] {
        add_definitions(
            &mut definitions,
            "K0.4",
            &inputs.k0_4,
            collection,
            id_field,
            false,
            contradiction_input,
        )?;
    }
    Ok(definitions)
}

fn validate_full_definition_census(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let definitions = collect_definitions(inputs)?;
    if definitions.len() != ALL_DEFINITION_AND_REFERENCE_COUNT {
        return Err("full K0 definition/reference row count drifted".to_owned());
    }
    let namespaced = definitions
        .iter()
        .map(Definition::tuple)
        .collect::<BTreeSet<_>>();
    if namespaced.len() != definitions.len() {
        return Err("namespaced K0 rows are not unique".to_owned());
    }
    let primary = definitions
        .iter()
        .filter(|row| !row.authority_reference)
        .collect::<Vec<_>>();
    let core = primary
        .iter()
        .copied()
        .filter(|row| !row.contradiction_input)
        .collect::<Vec<_>>();
    let contradictions = primary
        .iter()
        .copied()
        .filter(|row| row.contradiction_input)
        .collect::<Vec<_>>();
    let authority_reference_count = definitions
        .iter()
        .filter(|row| row.authority_reference)
        .count();
    if primary.len() != PRIMARY_DEFINITION_COUNT
        || core.len() != CORE_DEFINITION_COUNT
        || contradictions.len() != CONTRADICTION_INPUT_COUNT
        || authority_reference_count != AUTHORITY_REFERENCE_COUNT
    {
        return Err("K0 primary/core/contradiction/reference counts drifted".to_owned());
    }
    if primary
        .iter()
        .map(|row| row.raw_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != PRIMARY_DEFINITION_COUNT
    {
        return Err("primary raw IDs are not unique".to_owned());
    }
    if sorted_newline_sha256(primary.iter().map(|row| row.tuple()).collect()) != PRIMARY_ID_SHA256
        || sorted_newline_sha256(core.iter().map(|row| row.tuple()).collect()) != CORE_ID_SHA256
        || sorted_newline_sha256(contradictions.iter().map(|row| row.tuple()).collect())
            != CONTRADICTION_ID_SHA256
    {
        return Err("K0 definition digests drifted".to_owned());
    }

    let mut raw_groups: BTreeMap<&str, Vec<&Definition>> = BTreeMap::new();
    for definition in &definitions {
        raw_groups
            .entry(definition.raw_id.as_str())
            .or_default()
            .push(definition);
    }
    let collisions = raw_groups
        .values()
        .filter(|rows| rows.len() > 1)
        .collect::<Vec<_>>();
    if collisions.len() != AUTHORITY_REFERENCE_COUNT
        || sorted_newline_sha256(
            collisions
                .iter()
                .map(|rows| rows[0].raw_id.clone())
                .collect(),
        ) != AUTHORITY_REFERENCE_ID_SHA256
    {
        return Err("sanctioned authority-reference collision set drifted".to_owned());
    }
    let mut mapping = Vec::new();
    for rows in collisions {
        if rows.len() != 2
            || rows.iter().filter(|row| row.authority_reference).count() != 1
            || rows.iter().filter(|row| !row.authority_reference).count() != 1
        {
            return Err("unexpected raw-ID collision escaped the allowset".to_owned());
        }
        let reference = rows
            .iter()
            .find(|row| row.authority_reference)
            .ok_or_else(|| "authority reference missing".to_owned())?;
        let authority = rows
            .iter()
            .find(|row| !row.authority_reference)
            .ok_or_else(|| "authority definition missing".to_owned())?;
        let valid = (reference.collection == "k0_1_symbol_dispositions"
            && authority.stage == "K0.1"
            && authority.collection == "public_symbols")
            || (reference.collection == "k0_2_semantic_dispositions"
                && authority.stage == "K0.2"
                && matches!(
                    authority.collection.as_str(),
                    "configuration_fields" | "enum_semantics" | "operations" | "callable_helpers"
                ));
        if !valid {
            return Err(format!(
                "unsanctioned authority reference for {}",
                reference.raw_id
            ));
        }
        mapping.push(format!(
            "{}\t{}\t{}\tK0.3\t{}\t{}",
            authority.stage,
            authority.collection,
            authority.raw_id,
            reference.collection,
            reference.raw_id
        ));
    }
    if sorted_newline_sha256(mapping) != AUTHORITY_REFERENCE_MAPPING_SHA256 {
        return Err("authority-reference mapping digest drifted".to_owned());
    }

    let census = at(packet, "/namespace_projection/definition_reference_census")?;
    if uint(census, "all_definition_and_reference_row_count")?
        != ALL_DEFINITION_AND_REFERENCE_COUNT as u64
        || uint(census, "primary_definition_count")? != PRIMARY_DEFINITION_COUNT as u64
        || uint(census, "sanctioned_authority_reference_count")? != AUTHORITY_REFERENCE_COUNT as u64
        || text(census, "sanctioned_authority_reference_id_set_sha256")?
            != AUTHORITY_REFERENCE_ID_SHA256
        || text(census, "sanctioned_authority_reference_mapping_sha256")?
            != AUTHORITY_REFERENCE_MAPPING_SHA256
    {
        return Err("packet definition/reference census drifted".to_owned());
    }
    let primary_receipt = at(packet, "/namespace_projection/primary_definitions")?;
    if uint(primary_receipt, "primary_stable_id_count")? != PRIMARY_DEFINITION_COUNT as u64
        || uint(primary_receipt, "core_definition_count")? != CORE_DEFINITION_COUNT as u64
        || uint(primary_receipt, "contradiction_input_count")? != CONTRADICTION_INPUT_COUNT as u64
        || text(primary_receipt, "all_primary_typed_tuple_sha256")? != PRIMARY_ID_SHA256
        || text(primary_receipt, "core_definition_typed_tuple_sha256")? != CORE_ID_SHA256
        || text(primary_receipt, "contradiction_input_typed_tuple_sha256")?
            != CONTRADICTION_ID_SHA256
    {
        return Err("packet primary definition receipt drifted".to_owned());
    }
    Ok(())
}

fn validate_k0_5_aggregate_namespace(
    packet: &Value,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    let mut rows = vec![
        format!(
            "policy_canonicalization\t{}",
            at_text(&inputs.k0_5, "/policy/canonicalization_id")?
        ),
        format!(
            "claims_canonicalization\t{}",
            at_text(&inputs.k0_5, "/claims_projection/canonicalization_id")?
        ),
    ];
    rows.extend(
        array(&inputs.k0_5, "exact_joins")?
            .iter()
            .map(|row| text(row, "join_id").map(|id| format!("exact_joins\t{id}")))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rows.extend(
        array(at(&inputs.k0_5, "/unknown_disposition")?, "selectors")?
            .iter()
            .map(|row| text(row, "selector_id").map(|id| format!("unknown_selectors\t{id}")))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rows.extend(
        array(at(&inputs.k0_5, "/claims_projection")?, "aggregate_claims")?
            .iter()
            .map(|row| text(row, "claim_id").map(|id| format!("aggregate_claims\t{id}")))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rows.extend(
        array(&inputs.k0_5, "independent_terminal_gates")?
            .iter()
            .map(|row| text(row, "gate_id").map(|id| format!("terminal_gates\t{id}")))
            .collect::<Result<Vec<_>, _>>()?,
    );
    if rows.len() != K0_5_AGGREGATE_ID_COUNT
        || rows.iter().collect::<BTreeSet<_>>().len() != rows.len()
        || sorted_newline_sha256(rows) != K0_5_AGGREGATE_ID_SHA256
    {
        return Err("K0.5 aggregate namespace drifted".to_owned());
    }
    let receipt = at(packet, "/namespace_projection/k0_5_aggregate_namespace")?;
    if uint(receipt, "row_count")? != K0_5_AGGREGATE_ID_COUNT as u64
        || text(receipt, "projection_sha256")? != K0_5_AGGREGATE_ID_SHA256
    {
        return Err("packet K0.5 aggregate namespace receipt drifted".to_owned());
    }
    Ok(())
}

fn validate_inherited_k0_5_receipts(
    packet: &Value,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    for (packet_pointer, k0_pointer) in [
        (
            "/namespace_projection/source_pin_rollup/row_count",
            "/coverage_sets/source_pin_rollup/row_count",
        ),
        (
            "/namespace_projection/source_pin_rollup/stage_counts",
            "/coverage_sets/source_pin_rollup/stage_counts",
        ),
        (
            "/namespace_projection/source_pin_rollup/canonical_json_sha256",
            "/coverage_sets/source_pin_rollup/canonical_json_sha256",
        ),
        (
            "/namespace_projection/source_pin_rollup/unique_path_count",
            "/coverage_sets/source_pin_rollup/unique_path_count",
        ),
        (
            "/namespace_projection/source_pin_rollup/unique_path_set_sha256",
            "/coverage_sets/source_pin_rollup/unique_path_set_sha256",
        ),
        (
            "/namespace_projection/source_pin_rollup/overlap_group_count",
            "/coverage_sets/source_pin_rollup/overlap_group_count",
        ),
        (
            "/namespace_projection/source_pin_rollup/overlap_pin_row_count",
            "/coverage_sets/source_pin_rollup/overlap_pin_row_count",
        ),
        (
            "/namespace_projection/source_pin_rollup/overlap_pin_projection_sha256",
            "/coverage_sets/source_pin_rollup/overlap_pin_projection_sha256",
        ),
        (
            "/namespace_projection/source_pin_rollup/conflicting_overlap_groups",
            "/coverage_sets/source_pin_rollup/conflicting_overlap_groups",
        ),
        (
            "/namespace_projection/route_ownership/route_row_count",
            "/gap_routing/route_row_count",
        ),
        (
            "/namespace_projection/route_ownership/route_projection_sha256",
            "/gap_routing/route_projection_sha256",
        ),
        (
            "/namespace_projection/route_ownership/route_edge_count",
            "/gap_routing/route_edge_count",
        ),
        (
            "/namespace_projection/route_ownership/route_edge_projection_sha256",
            "/gap_routing/route_edge_projection_sha256",
        ),
        (
            "/namespace_projection/route_ownership/owner_id_count",
            "/gap_routing/owner_id_count",
        ),
        (
            "/namespace_projection/route_ownership/owner_id_set_sha256",
            "/gap_routing/owner_id_set_sha256",
        ),
        (
            "/namespace_projection/route_ownership/internal_k0_handoff_edge_count",
            "/gap_routing/internal_k0_handoff_edge_count",
        ),
        (
            "/namespace_projection/route_ownership/internal_k0_handoff_projection_sha256",
            "/gap_routing/internal_k0_handoff_projection_sha256",
        ),
        (
            "/namespace_projection/route_ownership/unresolved_internal_handoffs",
            "/gap_routing/unresolved_internal_handoffs",
        ),
        (
            "/namespace_projection/route_ownership/missing_owner_rows",
            "/gap_routing/missing_owner_rows",
        ),
        (
            "/namespace_projection/route_ownership/unowned_route_rows",
            "/gap_routing/unowned_route_rows",
        ),
        (
            "/namespace_projection/unknown_blockers/explicit_owned_unknown_count",
            "/unknown_disposition/explicit_owned_unknowns/count",
        ),
        (
            "/namespace_projection/unknown_blockers/explicit_owned_unknown_id_set_sha256",
            "/unknown_disposition/explicit_owned_unknowns/id_set_sha256",
        ),
        (
            "/namespace_projection/unknown_blockers/owner_edge_count",
            "/unknown_disposition/explicit_owned_unknowns/owner_edge_count",
        ),
        (
            "/namespace_projection/unknown_blockers/owner_edge_sha256",
            "/unknown_disposition/explicit_owned_unknowns/owner_edge_sha256",
        ),
        (
            "/namespace_projection/unknown_blockers/resolution_owner_count",
            "/unknown_disposition/explicit_owned_unknowns/resolution_owner_count",
        ),
        (
            "/namespace_projection/unknown_blockers/resolution_owner_id_set_sha256",
            "/unknown_disposition/explicit_owned_unknowns/resolution_owner_id_set_sha256",
        ),
        (
            "/namespace_projection/unknown_blockers/selector_row_count",
            "/unknown_disposition/selector_projection/row_count",
        ),
        (
            "/namespace_projection/unknown_blockers/selector_projection_sha256",
            "/unknown_disposition/selector_projection/sha256",
        ),
        (
            "/namespace_projection/unknown_blockers/missing_or_unowned_blocks",
            "/unknown_disposition/missing_or_unowned_blocks",
        ),
        (
            "/namespace_projection/unknown_blockers/unexpected_unknown_blocks",
            "/unknown_disposition/unexpected_unknown_blocks",
        ),
        (
            "/namespace_projection/claims_projection/child_claim_record_count",
            "/claims_projection/child_claim_record_count",
        ),
        (
            "/namespace_projection/claims_projection/child_claim_projection_sha256",
            "/claims_projection/child_claim_projection_sha256",
        ),
        (
            "/namespace_projection/claims_projection/aggregate_claim_count",
            "/claims_projection/aggregate_claim_count",
        ),
        (
            "/namespace_projection/claims_projection/aggregate_claim_projection_sha256",
            "/claims_projection/aggregate_claim_projection_sha256",
        ),
    ] {
        if at(packet, packet_pointer)? != at(&inputs.k0_5, k0_pointer)? {
            return Err(format!(
                "inherited K0.5 receipt drifted at {packet_pointer}"
            ));
        }
    }
    let claims = at(packet, "/namespace_projection/claims_projection")?;
    if text(claims, "migration_claim_state")? != "BLOCKED"
        || text(claims, "incumbent_claim_state")? != "KEEP_INCUMBENT"
        || text(claims, "native_scope_state")? != "PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY"
    {
        return Err("inherited K0.5 claim states drifted".to_owned());
    }
    Ok(())
}

fn add_obligations(
    rows: &mut Vec<ObligationRow>,
    stage: &str,
    artifact: &Value,
    collection: &str,
    id_field: &str,
) -> Result<(), String> {
    for row in array(artifact, collection)? {
        rows.push(ObligationRow {
            stage: stage.to_owned(),
            collection: collection.to_owned(),
            id: text(row, id_field)?.to_owned(),
        });
    }
    Ok(())
}

fn collect_source_precise_obligations(
    inputs: &AuthorityInputs,
) -> Result<Vec<ObligationRow>, String> {
    let mut rows = Vec::new();
    add_obligations(
        &mut rows,
        "K0.1",
        &inputs.k0_1,
        "public_symbols",
        "symbol_id",
    )?;
    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        add_obligations(&mut rows, "K0.2", &inputs.k0_2, collection, "semantic_id")?;
    }
    for key in object(
        inputs
            .k0_2
            .get("shared_semantics")
            .ok_or_else(|| "K0.2 shared_semantics missing".to_owned())?,
        "K0.2 shared_semantics",
    )?
    .keys()
    {
        rows.push(ObligationRow {
            stage: "K0.2".to_owned(),
            collection: "shared_semantics".to_owned(),
            id: key.clone(),
        });
    }
    add_obligations(
        &mut rows,
        "K0.2",
        &inputs.k0_2,
        "explicit_absences",
        "absence_id",
    )?;
    add_obligations(
        &mut rows,
        "K0.3",
        &inputs.k0_3,
        "user_journeys",
        "journey_id",
    )?;
    for collection in [
        "locked_dependency_identity",
        "native_build_vectors",
        "broker_api_version_vectors",
        "compression_vectors",
        "transport_auth_vectors",
        "topology_vectors",
        "fault_lifecycle_vectors",
    ] {
        add_obligations(&mut rows, "K0.4", &inputs.k0_4, collection, "vector_id")?;
    }
    add_obligations(&mut rows, "K0.1", &inputs.k0_1, "routed_gaps", "gap_id")?;
    add_obligations(
        &mut rows,
        "K0.2",
        &inputs.k0_2,
        "routed_findings",
        "finding_id",
    )?;
    add_obligations(&mut rows, "K0.3", &inputs.k0_3, "routed_gaps", "gap_id")?;
    add_obligations(&mut rows, "K0.4", &inputs.k0_4, "routed_gaps", "gap_id")?;
    Ok(rows)
}

fn ids_from(value: &Value, collection: &str, field: &str) -> Result<Vec<String>, String> {
    array(value, collection)?
        .iter()
        .map(|row| text(row, field).map(str::to_owned))
        .collect()
}

fn find_named_view<'a>(packet: &'a Value, view_id: &str) -> Result<&'a Value, String> {
    find_unique(
        array(
            at(packet, "/namespace_projection")?,
            "named_definition_views",
        )?,
        "view_id",
        view_id,
    )
}

fn validate_named_view(
    packet: &Value,
    view_id: &str,
    count: usize,
    digest: &str,
) -> Result<(), String> {
    let row = find_named_view(packet, view_id)?;
    if uint(row, "count")? != count as u64 || text(row, "id_set_sha256")? != digest {
        return Err(format!("named definition view drifted for {view_id}"));
    }
    Ok(())
}

fn validate_named_view_metadata(packet: &Value) -> Result<(), String> {
    let expectations = [
        json!({
            "view_id": "K1-VIEW-PUBLIC-SYMBOLS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
            "protocol_binding_policy": "ROW_SPECIFIC_PENDING_K1_2_AND_K1_3",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.5"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-SEMANTIC-ROWS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
            "protocol_binding_policy": "ROW_SPECIFIC_PENDING_K1_2_TO_K1_4",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.11.1"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-SHARED-SEMANTICS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.4",
            "protocol_binding_policy": "LOCAL_ONLY_OR_CONFIG_MAPPING_PENDING_ROW_REVIEW",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.11.1"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-EXPLICIT-ABSENCES",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
            "protocol_binding_policy": "ABSENT_GAP",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.6.3",
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.12.5"
            ],
            "downstream_owner_source": null,
            "required_state": "BLOCKING_UNTIL_REVIEWED_DISPOSITION_AND_EVIDENCE"
        }),
        json!({
            "view_id": "K1-VIEW-COMPILATION-PROFILES",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
            "protocol_binding_policy": "INVENTORY_ONLY",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.5",
                "asupersync-dep-p7-kafka-removal-sarszu.2.12.5"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-DOWNSTREAM-JOURNEYS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
            "protocol_binding_policy": "JOURNEY_SPECIFIC_PENDING_K1_2_TO_K1_5",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.10.5",
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.6",
                "asupersync-dep-p7-kafka-removal-sarszu.2.14.1"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-EXECUTABLE-VECTORS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
            "protocol_binding_policy": "VECTOR_SPECIFIC",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.6"
            ],
            "downstream_owner_source": null,
            "required_state": "BLOCKING_WHERE_UNKNOWN_OR_BLOCKED"
        }),
        json!({
            "view_id": "K1-VIEW-FIXTURES",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
            "protocol_binding_policy": "INVENTORY_ONLY",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.12.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.1"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-FIXTURE-PROFILES",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
            "protocol_binding_policy": "INVENTORY_ONLY",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.1"
            ],
            "downstream_owner_source": null,
            "required_state": null
        }),
        json!({
            "view_id": "K1-VIEW-ENVIRONMENTS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
            "protocol_binding_policy": "INVENTORY_ONLY",
            "downstream_owners": [
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.1",
                "asupersync-dep-p7-kafka-removal-sarszu.2.13.6"
            ],
            "downstream_owner_source": null,
            "required_state": "BLOCKING_WHERE_UNKNOWN_OR_BLOCKED"
        }),
        json!({
            "view_id": "K1-VIEW-ROUTED-GAPS-FINDINGS",
            "k1_policy_owner": "asupersync-dep-p7-kafka-removal-sarszu.2.1.1",
            "protocol_binding_policy": "INVENTORY_ONLY",
            "downstream_owners": null,
            "downstream_owner_source": "K0.5 gap_routing exact owner-edge ledger",
            "required_state": "ROUTED_WITHOUT_CLOSURE_PROMOTION"
        }),
    ];
    let views = array(
        at(packet, "/namespace_projection")?,
        "named_definition_views",
    )?;
    if views.len() != expectations.len() {
        return Err("named definition view count drifted".to_owned());
    }
    for expected in expectations {
        let view_id = text(&expected, "view_id")?.to_owned();
        let actual = find_unique(views, "view_id", &view_id)?;
        let actual_metadata = json!({
            "view_id": actual.get("view_id").cloned().unwrap_or(Value::Null),
            "k1_policy_owner": actual
                .get("k1_policy_owner")
                .cloned()
                .unwrap_or(Value::Null),
            "protocol_binding_policy": actual
                .get("protocol_binding_policy")
                .cloned()
                .unwrap_or(Value::Null),
            "downstream_owners": actual
                .get("downstream_owners")
                .cloned()
                .unwrap_or(Value::Null),
            "downstream_owner_source": actual
                .get("downstream_owner_source")
                .cloned()
                .unwrap_or(Value::Null),
            "required_state": actual
                .get("required_state")
                .cloned()
                .unwrap_or(Value::Null)
        });
        if actual_metadata != expected {
            return Err(format!(
                "named definition view metadata drifted for {view_id}"
            ));
        }
    }
    Ok(())
}

fn validate_obligation_projection(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let source_rows = collect_source_precise_obligations(inputs)?;
    if source_rows.len() != K1_OBLIGATION_COUNT
        || source_rows
            .iter()
            .map(ObligationRow::tuple)
            .collect::<BTreeSet<_>>()
            .len()
            != K1_OBLIGATION_COUNT
    {
        return Err("K1 obligation row count or uniqueness drifted".to_owned());
    }
    if sorted_newline_sha256(source_rows.iter().map(ObligationRow::tuple).collect())
        != SOURCE_PRECISE_OBLIGATION_SHA256
    {
        return Err("source-precise K1 obligation digest drifted".to_owned());
    }
    let normalized = source_rows
        .iter()
        .map(|row| {
            let collection = if row.stage == "K0.4"
                && matches!(
                    row.collection.as_str(),
                    "locked_dependency_identity"
                        | "native_build_vectors"
                        | "broker_api_version_vectors"
                        | "compression_vectors"
                        | "transport_auth_vectors"
                        | "topology_vectors"
                        | "fault_lifecycle_vectors"
                ) {
                "fixture_vectors"
            } else {
                row.collection.as_str()
            };
            format!("{}\t{}\t{}", row.stage, collection, row.id)
        })
        .collect::<Vec<_>>();
    if normalized.iter().collect::<BTreeSet<_>>().len() != K1_OBLIGATION_COUNT
        || sorted_newline_sha256(normalized) != NORMALIZED_OBLIGATION_SHA256
    {
        return Err("normalized K1 obligation digest drifted".to_owned());
    }
    let receipt = at(packet, "/namespace_projection/k1_obligation_projection")?;
    if uint(receipt, "raw_row_count")? != K1_OBLIGATION_COUNT as u64
        || uint(receipt, "unique_row_count")? != K1_OBLIGATION_COUNT as u64
        || uint(receipt, "stable_k0_definition_row_count")? != 267
        || uint(receipt, "derived_unided_k0_2_shared_key_count")? != 12
        || text(receipt, "normalized_projection_sha256")? != NORMALIZED_OBLIGATION_SHA256
        || text(receipt, "source_precise_projection_sha256")? != SOURCE_PRECISE_OBLIGATION_SHA256
    {
        return Err("packet K1 obligation receipt drifted".to_owned());
    }

    let public_ids = ids_from(&inputs.k0_1, "public_symbols", "symbol_id")?;
    let mut semantic_ids = Vec::new();
    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        semantic_ids.extend(ids_from(&inputs.k0_2, collection, "semantic_id")?);
    }
    let shared_ids = object(
        inputs
            .k0_2
            .get("shared_semantics")
            .ok_or_else(|| "K0.2 shared_semantics missing".to_owned())?,
        "K0.2 shared_semantics",
    )?
    .keys()
    .cloned()
    .collect::<Vec<_>>();
    let absence_ids = ids_from(&inputs.k0_2, "explicit_absences", "absence_id")?;
    let profile_ids = ids_from(&inputs.k0_1, "compilation_profiles", "profile_id")?;
    let journey_ids = ids_from(&inputs.k0_3, "user_journeys", "journey_id")?;
    let mut vector_ids = Vec::new();
    for collection in [
        "locked_dependency_identity",
        "native_build_vectors",
        "broker_api_version_vectors",
        "compression_vectors",
        "transport_auth_vectors",
        "topology_vectors",
        "fault_lifecycle_vectors",
    ] {
        vector_ids.extend(ids_from(&inputs.k0_4, collection, "vector_id")?);
    }
    let fixture_ids = ids_from(&inputs.k0_4, "fixture_census", "fixture_id")?;
    let fixture_profile_ids = ids_from(
        &inputs.k0_4,
        "fixture_classification_profiles",
        "classification_profile_id",
    )?;
    let environment_ids = ids_from(&inputs.k0_4, "environment_identities", "environment_id")?;
    let gap_ids = source_rows
        .iter()
        .filter(|row| matches!(row.collection.as_str(), "routed_gaps" | "routed_findings"))
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    for (view_id, rows, expected_digest) in [
        (
            "K1-VIEW-PUBLIC-SYMBOLS",
            public_ids,
            "307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28",
        ),
        (
            "K1-VIEW-SEMANTIC-ROWS",
            semantic_ids,
            "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7",
        ),
        (
            "K1-VIEW-SHARED-SEMANTICS",
            shared_ids,
            "92ab055d5d14e4971daf298e54c9f5036ecf71c490d579270f4789b889fc86a5",
        ),
        (
            "K1-VIEW-EXPLICIT-ABSENCES",
            absence_ids,
            "e3093d2ad2db7b56d4cb6a56ee7d382891192515d76c10aa9e6ff6e07e737a6b",
        ),
        (
            "K1-VIEW-COMPILATION-PROFILES",
            profile_ids,
            "882b6f73ee7c5abfe73080804fcd082c05dddd9c4002ee61ff9336f0a0d439eb",
        ),
        (
            "K1-VIEW-DOWNSTREAM-JOURNEYS",
            journey_ids,
            "c5a9f1947a5ecf55898c61414bb39bf753cd236fe33157083994acd63176367f",
        ),
        (
            "K1-VIEW-EXECUTABLE-VECTORS",
            vector_ids,
            "73491562ae3df3f7ea6729c30834cf3cb134a002ec5d682255277df5e508e73f",
        ),
        (
            "K1-VIEW-FIXTURES",
            fixture_ids,
            "bb8f922cc63f97efcfb0c76a6e26fdf923775650af8cd613f50da55c95cbb376",
        ),
        (
            "K1-VIEW-FIXTURE-PROFILES",
            fixture_profile_ids,
            "b1848945221e425d78007ee47bced23e62b700a5e43fc6a8300124d42c8d8d09",
        ),
        (
            "K1-VIEW-ENVIRONMENTS",
            environment_ids,
            "372de832a4de112e3ee8bc45b3af978d749b24c3f825416bd8e8b2d4523d831e",
        ),
        (
            "K1-VIEW-ROUTED-GAPS-FINDINGS",
            gap_ids,
            "2158c08ad42f7fb1c62733e26b0405c1b85df60d020851b3abf17dffd7bf56cd",
        ),
    ] {
        let count = rows.len();
        let digest = sorted_newline_sha256(rows);
        if digest != expected_digest {
            return Err(format!("live ID view drifted for {view_id}"));
        }
        validate_named_view(packet, view_id, count, expected_digest)?;
    }
    validate_named_view_metadata(packet)?;
    Ok(())
}

fn validate_derived_shared_obligations(
    packet: &Value,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    let receipt = at(packet, "/namespace_projection/derived_shared_obligations")?;
    let rows = array(receipt, "rows")?;
    if rows.len() != 12 || uint(receipt, "row_count")? != 12 {
        return Err("derived shared-obligation count drifted".to_owned());
    }
    let source_keys = object(
        inputs
            .k0_2
            .get("shared_semantics")
            .ok_or_else(|| "K0.2 shared_semantics missing".to_owned())?,
        "K0.2 shared_semantics",
    )?
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
    let mut projected = Vec::new();
    let mut row_keys = BTreeSet::new();
    let mut obligation_ids = BTreeSet::new();
    for row in rows {
        let obligation_id = text(row, "obligation_id")?;
        let source_key = text(row, "source_key")?;
        let owner = text(row, "k1_policy_owner")?;
        let binding = text(row, "protocol_binding_policy")?;
        if !row_keys.insert(source_key.to_owned())
            || !obligation_ids.insert(obligation_id.to_owned())
        {
            return Err("derived shared obligation duplicated".to_owned());
        }
        if !matches!(binding, "MESSAGE_SET" | "LOCAL_ONLY" | "CONFIG_MAPPING") {
            return Err(format!("invalid shared-obligation binding {binding}"));
        }
        projected.push(format!("{obligation_id}\t{source_key}\t{owner}\t{binding}"));
    }
    if row_keys != source_keys
        || sorted_newline_sha256(projected) != DERIVED_SHARED_SHA256
        || text(receipt, "projection_sha256")? != DERIVED_SHARED_SHA256
    {
        return Err("derived shared-obligation projection drifted".to_owned());
    }
    Ok(())
}

fn validate_cross_authority_references(
    packet: &Value,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    let adr = find_unique_in(&inputs.adr_registry, "adrs", "adr_id", ADR_ID)?;
    let adr_journeys = array(adr, "user_journeys")?
        .iter()
        .map(|row| text(row, "id").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let k0_journeys = ids_from(&inputs.k0_3, "user_journeys", "journey_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if adr_journeys.len() != 6
        || !adr_journeys.iter().all(|id| k0_journeys.contains(id))
        || sorted_newline_sha256(adr_journeys)
            != "d59b078cda4909d1b5f7a966b6137931f9a91d55bd7eba721db1eb7e2fb3e2a4"
    {
        return Err("ADR journey references drifted".to_owned());
    }
    let capability = find_unique_in(
        &inputs.capability_registry,
        "capabilities",
        "capability_id",
        CAPABILITY_ID,
    )?;
    let capability_scenarios = exact_text_set(capability, "scenario_ids")?;
    let adr_scenarios = exact_text_set(
        adr.get("evidence")
            .ok_or_else(|| "ADR evidence missing".to_owned())?,
        "scenario_ids",
    )?;
    if capability_scenarios.len() != 4
        || capability_scenarios != adr_scenarios
        || sorted_newline_sha256(capability_scenarios.into_iter().collect())
            != "e2c1e1a961c5673a05db93ab0782556ad756f6582319cd356f3138ad0569c0f5"
    {
        return Err("planned capability scenario references drifted".to_owned());
    }
    let journey_rows = selected_pin_rows("K1-ROW-CAPABILITY-JOURNEY", inputs)?;
    if journey_rows.len() != 1
        || text(journey_rows[0], "journey_id")? != "J-USER-KAFKA"
        || text(journey_rows[0], "baseline_state")? != "planned"
    {
        return Err("CAP-KAFKA journey inventory row drifted".to_owned());
    }
    let views = array(
        at(packet, "/namespace_projection")?,
        "cross_authority_reference_views",
    )?;
    let expected_views = [
        json!({
            "view_id": "K1-CROSS-REFERENCE-ADR-JOURNEYS",
            "reference_locator": "DEP-ADR-009.user_journeys[].id",
            "definition_locator": "K0.3.user_journeys[].journey_id",
            "reference_count": 6,
            "unique_definition_count": 6,
            "id_set_sha256": "d59b078cda4909d1b5f7a966b6137931f9a91d55bd7eba721db1eb7e2fb3e2a4",
            "state": "EXACT_SUBSET_REFERENCE_TO_K0_3_DEFINITIONS"
        }),
        json!({
            "view_id": "K1-CROSS-REFERENCE-CAPABILITY-SCENARIOS",
            "definition_locator": "CAP-KAFKA.scenario_ids[]",
            "reference_locator": "DEP-ADR-009.evidence.scenario_ids[]",
            "definition_count": 4,
            "reference_count": 4,
            "id_set_sha256": "e2c1e1a961c5673a05db93ab0782556ad756f6582319cd356f3138ad0569c0f5",
            "current_evidence_state": "BASELINE_PLANNED",
            "state": "EXACT_PLANNED_AUTHORITY_REFERENCE_NOT_EXECUTION_EVIDENCE"
        }),
        json!({
            "view_id": "K1-CROSS-REFERENCE-CAPABILITY-JOURNEY-INVENTORY",
            "source_locator": "capability registry journey_inventory[capability_ids contains CAP-KAFKA]",
            "journey_id": "J-USER-KAFKA",
            "row_count": 1,
            "current_evidence_state": "PLANNED",
            "definition_relation": "REGISTRY_INVENTORY_REFERENCE_OUTSIDE_K0_5_PRIMARY_CENSUS",
            "state": "PINNED_PLANNED_REFERENCE_NOT_EXECUTION_EVIDENCE"
        }),
    ];
    if views.len() != expected_views.len() {
        return Err("cross-authority reference view count drifted".to_owned());
    }
    for expected in expected_views {
        let view_id = text(&expected, "view_id")?.to_owned();
        let actual = find_unique(views, "view_id", &view_id)?;
        if actual != &expected {
            return Err(format!(
                "cross-authority reference view drifted for {view_id}"
            ));
        }
    }
    Ok(())
}

fn validate_exposure_and_binding(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let mut detailed_rows = Vec::new();
    let mut detailed_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut coarse_rows = Vec::new();
    let mut coarse_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in array(&inputs.k0_1, "public_symbols")? {
        let symbol_id = text(row, "symbol_id")?;
        let facade = array(row, "facade_exports")?;
        let detailed = if !facade.is_empty() {
            "FACADE"
        } else if matches!(symbol_id, "KPR-PUB-002" | "KPR-PUB-021") {
            "CFG_TEST_ONLY"
        } else if symbol_id == "KPR-PUB-023" {
            "CFG_FUZZING"
        } else {
            "MODULE_PUBLIC"
        };
        let coarse = if facade.is_empty() {
            "MODULE_PUBLIC_ONLY"
        } else {
            "FACADE_REEXPORTED"
        };
        *detailed_counts.entry(detailed).or_default() += 1;
        *coarse_counts.entry(coarse).or_default() += 1;
        detailed_rows.push(format!("{symbol_id}\t{detailed}"));
        coarse_rows.push(format!("{symbol_id}\t{coarse}"));
    }
    if detailed_counts
        != BTreeMap::from([
            ("CFG_FUZZING", 1),
            ("CFG_TEST_ONLY", 2),
            ("FACADE", 15),
            ("MODULE_PUBLIC", 12),
        ])
        || sorted_newline_sha256(detailed_rows) != EXPOSURE_SHA256
        || coarse_counts != BTreeMap::from([("FACADE_REEXPORTED", 15), ("MODULE_PUBLIC_ONLY", 15)])
        || sorted_newline_sha256(coarse_rows) != COARSE_EXPOSURE_SHA256
    {
        return Err("live public exposure projection drifted".to_owned());
    }
    let exposure = packet
        .get("exposure_model")
        .ok_or_else(|| "exposure_model missing".to_owned())?;
    if uint(exposure, "row_count")? != 30
        || text(exposure, "projection_sha256")? != EXPOSURE_SHA256
        || at_text(exposure, "/coarse_projection/projection_sha256")? != COARSE_EXPOSURE_SHA256
    {
        return Err("packet exposure projection drifted".to_owned());
    }
    let allowed_exposure = exact_text_set(exposure, "allowed_classes")?;
    if allowed_exposure
        != [
            "CFG_FUZZING",
            "CFG_TEST_ONLY",
            "FACADE",
            "MODULE_PUBLIC",
            "PRIVATE",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    {
        return Err("exposure class taxonomy drifted".to_owned());
    }

    let binding = packet
        .get("protocol_binding_model")
        .ok_or_else(|| "protocol_binding_model missing".to_owned())?;
    let binding_kinds = object(
        binding
            .get("allowed_kinds")
            .ok_or_else(|| "allowed_kinds missing".to_owned())?,
        "allowed_kinds",
    )?
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
    if binding_kinds
        != [
            "ABSENT_GAP",
            "CONFIG_MAPPING",
            "INVENTORY_ONLY",
            "LOCAL_ONLY",
            "MESSAGE_SET",
            "REFERENCE_ONLY",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
        || flag(binding, "assignment_complete")?
        || text(binding, "assignment_state")? != "BLOCKING_PENDING_K1_2_TO_K1_4"
    {
        return Err("protocol binding taxonomy or pending state drifted".to_owned());
    }
    Ok(())
}

fn walk_low_evidence_states(
    child: &str,
    value: &Value,
    path: &mut Vec<Value>,
    rows: &mut Vec<String>,
    child_counts: &mut BTreeMap<String, usize>,
    state_counts: &mut BTreeMap<String, usize>,
) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                path.push(Value::String(key.clone()));
                walk_low_evidence_states(child, nested, path, rows, child_counts, state_counts)?;
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                path.push(json!(index));
                walk_low_evidence_states(child, nested, path, rows, child_counts, state_counts)?;
                path.pop();
            }
        }
        Value::String(state) if LOW_EVIDENCE_STATES.contains(&state.as_str()) => {
            *child_counts.entry(child.to_owned()).or_default() += 1;
            *state_counts.entry(state.clone()).or_default() += 1;
            let row = json!({"child": child, "path": path, "state": state});
            rows.push(
                serde_json::to_string(&canonicalize(&row))
                    .map_err(|error| format!("state row serialization failed: {error}"))?,
            );
        }
        _ => {}
    }
    Ok(())
}

fn validate_low_evidence_state_projection(
    packet: &Value,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    let mut rows = Vec::new();
    let mut child_counts = BTreeMap::new();
    let mut state_counts = BTreeMap::new();
    for (child, artifact) in [
        ("K0.1", &inputs.k0_1),
        ("K0.2", &inputs.k0_2),
        ("K0.3", &inputs.k0_3),
        ("K0.4", &inputs.k0_4),
    ] {
        walk_low_evidence_states(
            child,
            artifact,
            &mut Vec::new(),
            &mut rows,
            &mut child_counts,
            &mut state_counts,
        )?;
    }
    if rows.len() != LOW_EVIDENCE_STATE_COUNT
        || rows.iter().collect::<BTreeSet<_>>().len() != rows.len()
        || sorted_newline_sha256(rows) != LOW_EVIDENCE_STATE_SHA256
        || child_counts != BTreeMap::from([("K0.3".to_owned(), 314), ("K0.4".to_owned(), 132)])
        || state_counts
            != BTreeMap::from([
                ("BLOCKED".to_owned(), 77),
                ("BLOCKED_EXTERNAL".to_owned(), 15),
                ("LOCAL_MODEL_ONLY".to_owned(), 6),
                ("NOT_RUN".to_owned(), 225),
                ("UNKNOWN".to_owned(), 97),
                ("UNPINNED".to_owned(), 6),
                ("WIRE_CODEC_ONLY".to_owned(), 20),
            ])
    {
        return Err("low-evidence state projection drifted".to_owned());
    }
    let receipt = at(
        packet,
        "/namespace_projection/low_evidence_state_projection",
    )?;
    let expected_child_counts = json!({
        "K0.1": 0,
        "K0.2": 0,
        "K0.3": 314,
        "K0.4": 132
    });
    let expected_state_counts = json!({
        "UNKNOWN": 97,
        "BLOCKED": 77,
        "BLOCKED_EXTERNAL": 15,
        "NOT_RUN": 225,
        "UNPINNED": 6,
        "LOCAL_MODEL_ONLY": 6,
        "WIRE_CODEC_ONLY": 20
    });
    if uint(receipt, "row_count")? != LOW_EVIDENCE_STATE_COUNT as u64
        || text(receipt, "projection_sha256")? != LOW_EVIDENCE_STATE_SHA256
        || exact_text_set(receipt, "selected_states")?
            != LOW_EVIDENCE_STATES
                .iter()
                .map(|state| (*state).to_owned())
                .collect()
        || receipt.get("child_counts") != Some(&expected_child_counts)
        || receipt.get("state_counts") != Some(&expected_state_counts)
        || flag(receipt, "promotion_allowed")?
        || text(receipt, "state")? != "EXACT_RETAINED_LOW_EVIDENCE_STATE_CENSUS"
    {
        return Err("packet low-evidence state receipt drifted".to_owned());
    }

    let state_model = packet
        .get("state_model")
        .ok_or_else(|| "state_model missing".to_owned())?;
    if exact_text_set(state_model, "required_columns")?
        != [
            "current_evidence_state",
            "implementation_owner",
            "required_target_state",
            "terminal_gate",
            "verification_owner",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
        || exact_text_set(state_model, "current_evidence_states_preserved")?
            != [
                "AMBIENT_UNPINNED",
                "BLOCKED",
                "BLOCKED_EXTERNAL",
                "COMPILE_ONLY",
                "LOCAL_MODEL_ONLY",
                "NOT_RUN",
                "OPT_IN",
                "PLANNED",
                "PROOF_ONLY",
                "REAL_BROKER_CAPABLE",
                "SILENT_SKIP",
                "STATIC",
                "UNKNOWN",
                "UNPINNED",
                "WIRE_CODEC_ONLY",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        || exact_text_set(
            state_model,
            "promoted_states_forbidden_without_terminal_receipt",
        )? != [
            "ACTUAL_BINARY_RECEIPT",
            "EXECUTED",
            "MIGRATION_ELIGIBLE",
            "PASS",
            "REAL_BROKER_RECEIPT",
            "SUPPORTED",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
        || !flag(
            state_model,
            "target_policy_does_not_rewrite_current_evidence",
        )?
        || flag(state_model, "unknown_defaults_to_supported")?
        || flag(state_model, "blocked_defaults_to_supported")?
        || flag(state_model, "static_defaults_to_runtime")?
    {
        return Err("state model drifted or promoted low evidence".to_owned());
    }
    Ok(())
}

fn tracker_issue<'a>(rows: &'a [Value], issue_id: &str) -> Result<&'a Value, String> {
    find_unique(rows, "id", issue_id)
}

fn dependency_targets(issue: &Value, dependency_type: &str) -> Result<Vec<String>, String> {
    let dependencies = issue
        .get("dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut targets = dependencies
        .iter()
        .filter(|dependency| {
            dependency.get("type").and_then(Value::as_str) == Some(dependency_type)
        })
        .map(|dependency| text(dependency, "depends_on_id").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn visit_cycle(
    node: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node.to_owned()) {
        return true;
    }
    if let Some(targets) = graph.get(node) {
        for target in targets {
            if graph.contains_key(target) && visit_cycle(target, graph, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_owned());
    false
}

fn active_tracker_has_cycle(rows: &[Value]) -> Result<bool, String> {
    let active_ids = K1_TRACKER_IDS
        .iter()
        .map(|issue_id| tracker_issue(rows, issue_id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| {
            !matches!(
                row.get("status").and_then(Value::as_str),
                Some("closed" | "tombstone")
            )
        })
        .map(|row| text(row, "id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut graph = BTreeMap::new();
    for issue_id in &active_ids {
        let row = tracker_issue(rows, issue_id)?;
        graph.insert(issue_id.clone(), dependency_targets(row, "blocks")?);
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for issue_id in graph.keys() {
        if visit_cycle(issue_id, &graph, &mut visiting, &mut visited) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_tracker_topology(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let mut rows = Vec::new();
    for issue_id in K1_TRACKER_IDS {
        let issue = tracker_issue(&inputs.tracker_rows, issue_id)?;
        let parents = dependency_targets(issue, "parent-child")?.join(",");
        let blocks = dependency_targets(issue, "blocks")?.join(",");
        rows.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            issue_id,
            text(issue, "issue_type")?,
            uint(issue, "estimated_minutes")?,
            parents,
            blocks
        ));
    }
    if rows.len() != 9
        || sorted_newline_sha256(rows) != TRACKER_PROJECTION_SHA256
        || active_tracker_has_cycle(&inputs.tracker_rows)?
    {
        return Err("tracker topology, estimate, dependency, or cycle receipt drifted".to_owned());
    }
    let child_minutes = K1_TRACKER_IDS[1..6]
        .iter()
        .map(|issue_id| tracker_issue(&inputs.tracker_rows, issue_id))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(|issue| uint(issue, "estimated_minutes"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u64>();
    if child_minutes != 1_920 {
        return Err("K1 child estimates no longer total 1,920 minutes".to_owned());
    }
    let receipt = packet
        .get("tracker_topology")
        .ok_or_else(|| "tracker_topology missing".to_owned())?;
    if uint(receipt, "row_count")? != 9
        || uint(receipt, "child_count")? != 5
        || uint(receipt, "child_estimate_minutes")? != 1_920
        || uint(receipt, "active_cycle_count")? != 0
        || text(receipt, "projection_sha256")? != TRACKER_PROJECTION_SHA256
        || text(receipt, "k2_epic_gate")? != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
        || text(receipt, "k2_schema_gate")? != "asupersync-dep-p7-kafka-removal-sarszu.2.1.2"
        || text(receipt, "k2_codec_aggregate_gate")?
            != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
    {
        return Err("packet tracker topology receipt drifted".to_owned());
    }
    Ok(())
}

fn collect_bead_references(value: &Value, owner_context: bool, refs: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let next_context = owner_context
                    || key.contains("owner")
                    || key.contains("bead")
                    || key == "downstream_owners";
                collect_bead_references(nested, next_context, refs);
            }
        }
        Value::Array(rows) => {
            for row in rows {
                collect_bead_references(row, owner_context, refs);
            }
        }
        Value::String(reference) if owner_context && reference.starts_with("asupersync-") => {
            refs.insert(reference.clone());
        }
        _ => {}
    }
}

fn validate_owner_references(packet: &Value, inputs: &AuthorityInputs) -> Result<(), String> {
    let tracker_ids = inputs
        .tracker_rows
        .iter()
        .map(|row| text(row, "id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut refs = BTreeSet::new();
    collect_bead_references(packet, false, &mut refs);
    let missing = refs.difference(&tracker_ids).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "packet references missing tracker owners: {missing:?}"
        ));
    }
    let handoffs = array(packet, "k1_owner_handoffs")?;
    if handoffs.len() != 5 {
        return Err("K1 owner handoff count drifted".to_owned());
    }
    for (index, row) in handoffs.iter().enumerate() {
        let expected_id = format!("asupersync-dep-p7-kafka-removal-sarszu.2.1.{}", index + 1);
        let expected_state = if index == 0 {
            "FROZEN_BY_THIS_PACKET"
        } else {
            "BLOCKING_PENDING"
        };
        if text(row, "child_bead")? != expected_id || text(row, "state")? != expected_state {
            return Err("K1 owner handoff order or state drifted".to_owned());
        }
    }
    let standalone = array(packet, "standalone_owner_boundaries")?;
    let expected_standalone = [
        "asupersync-messaging-resp3-kafka-commit-o9ujbk",
        "asupersync-ne8jdw",
        "asupersync-o82yd7",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let actual_standalone = standalone
        .iter()
        .map(|row| text(row, "bead_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_standalone != expected_standalone {
        return Err("standalone owner boundary set drifted".to_owned());
    }
    for row in standalone {
        if flag(row, "absorption_allowed")? || flag(row, "closure_claimed")? {
            return Err("standalone owner was absorbed or claimed closed".to_owned());
        }
    }
    Ok(())
}

fn validate_disposition_and_coverage(packet: &Value) -> Result<(), String> {
    let disposition = packet
        .get("disposition_receipt")
        .ok_or_else(|| "disposition_receipt missing".to_owned())?;
    if !flag(disposition, "k1_1_contract_complete")?
        || flag(disposition, "k1_2_complete")?
        || flag(disposition, "k1_3_complete")?
        || flag(disposition, "k1_4_complete")?
        || flag(disposition, "k1_5_complete")?
        || flag(disposition, "k1_parent_complete")?
        || text(disposition, "incumbent_disposition")? != "KEEP_INCUMBENT"
    {
        return Err("K1 completion or incumbent disposition drifted".to_owned());
    }
    for field in [
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
        if flag(disposition, field)? {
            return Err(format!("disposition.{field} must stay false"));
        }
    }
    let coverage = packet
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt missing".to_owned())?;
    for (field, expected) in [
        ("authority_input_count", 9),
        ("authority_row_pin_count", 6),
        ("tracker_projection_row_count", 9),
        ("k1_child_count", 5),
        ("k1_child_estimate_minutes", 1_920),
        ("primary_definition_count", 903),
        ("definition_and_reference_row_count", 1_030),
        ("sanctioned_authority_reference_count", 127),
        ("k0_5_aggregate_definition_count", 32),
        ("k1_obligation_projection_row_count", 279),
        ("low_evidence_state_projection_row_count", 446),
        ("named_definition_view_count", 11),
        ("authority_reference_view_count", 6),
        ("cross_authority_reference_view_count", 3),
        ("derived_shared_obligation_count", 12),
    ] {
        if uint(coverage, field)? != expected {
            return Err(format!("coverage.{field} drifted"));
        }
    }
    for field in [
        "tracker_projection_complete",
        "primary_definitions_complete_and_unique",
        "source_pin_rollup_complete",
        "direct_source_inputs_match_inherited_k0_pins",
        "public_exposure_projection_complete",
        "unknown_and_blocked_rows_retained",
        "route_owner_edges_complete",
    ] {
        if !flag(coverage, field)? {
            return Err(format!("coverage.{field} must stay true"));
        }
    }
    for field in [
        "protocol_binding_assignment_complete",
        "later_k1_children_complete",
        "migration_eligible",
        "dynamic_execution_claimed",
    ] {
        if flag(coverage, field)? {
            return Err(format!("coverage.{field} must stay false"));
        }
    }
    if text(coverage, "disposition")? != "KEEP_INCUMBENT"
        || text(coverage, "validation_mode")?
            != "STATIC_JSON_HASH_EXACT_JOIN_AND_TRACKER_PROJECTION_ONLY"
    {
        return Err("coverage disposition or validation mode drifted".to_owned());
    }
    let no_claims = array(packet, "no_claim_boundaries")?;
    if no_claims.len() != 7 {
        return Err("no-claim boundary count drifted".to_owned());
    }
    let joined = no_claims
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "no-claim boundary must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for required in [
        "does not prove compilation",
        "does not prove Kafka protocol correctness",
        "does not prove native linkage",
        "does not prove TLS",
        "does not prove resource bounds",
        "does not close or absorb",
        "does not authorize production wiring",
    ] {
        if !joined.contains(required) {
            return Err(format!("no-claim boundary lost {required}"));
        }
    }
    Ok(())
}

fn validate_docs(doc: &str) -> Result<(), String> {
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("K1 documentation markers drifted".to_owned());
    }
    for required in [
        ARTIFACT_PATH,
        BEAD_ID,
        "KEEP_INCUMBENT",
        "1,030",
        "903",
        "279",
        "446",
        PRIMARY_ID_SHA256,
        K0_5_AGGREGATE_ID_SHA256,
        NORMALIZED_OBLIGATION_SHA256,
        SOURCE_PRECISE_OBLIGATION_SHA256,
        LOW_EVIDENCE_STATE_SHA256,
        TRACKER_PROJECTION_SHA256,
        "records no execution receipt",
        "does not prove",
        "sole conditional cutover owner",
    ] {
        if !doc.contains(required) {
            return Err(format!("K1 documentation lost {required}"));
        }
    }
    Ok(())
}

fn validate_packet_value(
    packet: &Value,
    doc: &str,
    root: &Path,
    inputs: &AuthorityInputs,
) -> Result<(), String> {
    validate_root_identity_and_policy(packet)?;
    validate_authority_input_pins(packet, root)?;
    validate_inherited_child_artifact_pins(packet, root, inputs)?;
    validate_authority_row_pins(packet, inputs)?;
    validate_governing_authority(inputs)?;
    validate_full_definition_census(packet, inputs)?;
    validate_k0_5_aggregate_namespace(packet, inputs)?;
    validate_inherited_k0_5_receipts(packet, inputs)?;
    validate_obligation_projection(packet, inputs)?;
    validate_derived_shared_obligations(packet, inputs)?;
    validate_cross_authority_references(packet, inputs)?;
    validate_exposure_and_binding(packet, inputs)?;
    validate_low_evidence_state_projection(packet, inputs)?;
    validate_tracker_topology(packet, inputs)?;
    validate_owner_references(packet, inputs)?;
    validate_disposition_and_coverage(packet)?;
    validate_docs(doc)?;
    Ok(())
}

fn replace_first_exact_state(value: &mut Value, from: &str, to: &str) -> bool {
    match value {
        Value::Object(map) => map
            .values_mut()
            .any(|nested| replace_first_exact_state(nested, from, to)),
        Value::Array(rows) => rows
            .iter_mut()
            .any(|nested| replace_first_exact_state(nested, from, to)),
        Value::String(state) if state == from => {
            to.clone_into(state);
            true
        }
        _ => false,
    }
}

#[test]
fn kafka_k1_obligation_index_contract() {
    let root = repo_root();
    let artifact_bytes = read_bytes(&root, ARTIFACT_PATH).expect("artifact must be readable");
    let doc_bytes = read_bytes(&root, DOC_PATH).expect("document must be readable");
    assert_eq!(sha256_bytes(&artifact_bytes), ARTIFACT_SHA256);
    assert_eq!(sha256_bytes(&doc_bytes), DOC_SHA256);
    let packet: Value =
        serde_json::from_slice(&artifact_bytes).expect("artifact must be valid JSON");
    let doc = String::from_utf8(doc_bytes).expect("document must be UTF-8");
    let inputs = load_inputs(&root).expect("authority inputs must load");
    validate_packet_value(&packet, &doc, &root, &inputs)
        .expect("K1.1 static authority and obligation packet must validate");
}

#[test]
fn kafka_k1_packet_mutations_fail_closed() {
    let root = repo_root();
    let packet = parse_json(&root, ARTIFACT_PATH).expect("artifact must parse");
    let doc = read_text(&root, DOC_PATH).expect("document must load");
    let inputs = load_inputs(&root).expect("authority inputs must load");
    let mut mutations = Vec::new();

    let mut extra_root = packet.clone();
    object_mut(&mut extra_root, "packet")
        .expect("packet object")
        .insert("unexpected".to_owned(), json!(true));
    mutations.push(("extra root key", extra_root));

    let mut missing_input = packet.clone();
    array_mut(&mut missing_input, "authority_inputs")
        .expect("authority inputs")
        .pop();
    mutations.push(("missing authority input", missing_input));

    let mut primary_count = packet.clone();
    *primary_count
        .pointer_mut("/namespace_projection/primary_definitions/primary_stable_id_count")
        .expect("primary count") = json!(902);
    mutations.push(("primary definition count", primary_count));

    let mut obligation_digest = packet.clone();
    *obligation_digest
        .pointer_mut("/namespace_projection/k1_obligation_projection/normalized_projection_sha256")
        .expect("obligation digest") = json!("0");
    mutations.push(("obligation digest", obligation_digest));

    let mut state_digest = packet.clone();
    *state_digest
        .pointer_mut("/namespace_projection/low_evidence_state_projection/projection_sha256")
        .expect("state digest") = json!("0");
    mutations.push(("low-evidence digest", state_digest));

    let mut exposure = packet.clone();
    *exposure
        .pointer_mut("/exposure_model/projection_sha256")
        .expect("exposure digest") = json!("0");
    mutations.push(("exposure projection", exposure));

    let mut binding_complete = packet.clone();
    *binding_complete
        .pointer_mut("/protocol_binding_model/assignment_complete")
        .expect("binding state") = json!(true);
    mutations.push(("premature binding completion", binding_complete));

    let mut owner = packet.clone();
    *owner
        .pointer_mut("/namespace_projection/derived_shared_obligations/rows/0/k1_policy_owner")
        .expect("derived owner") = json!("");
    mutations.push(("missing derived owner", owner));

    let mut reassigned_view = packet.clone();
    *reassigned_view
        .pointer_mut("/namespace_projection/named_definition_views/0/k1_policy_owner")
        .expect("named view owner") = json!("asupersync-dep-p7-kafka-removal-sarszu.2.1.4");
    mutations.push((
        "named view reassigned to another valid bead",
        reassigned_view,
    ));

    let mut promoted_reference = packet.clone();
    *promoted_reference
        .pointer_mut(
            "/namespace_projection/cross_authority_reference_views/1/current_evidence_state",
        )
        .expect("cross-authority evidence state") = json!("EXECUTED");
    mutations.push((
        "planned cross-authority reference promoted",
        promoted_reference,
    ));

    let mut selected_state = packet.clone();
    *selected_state
        .pointer_mut("/namespace_projection/low_evidence_state_projection/selected_states/0")
        .expect("selected low-evidence state") = json!("SUPPORTED");
    mutations.push(("low-evidence selector promoted", selected_state));

    let mut state_default = packet.clone();
    *state_default
        .pointer_mut("/state_model/unknown_defaults_to_supported")
        .expect("UNKNOWN default") = json!(true);
    mutations.push(("UNKNOWN defaults to supported", state_default));

    let mut tracker_digest = packet.clone();
    *tracker_digest
        .pointer_mut("/tracker_topology/projection_sha256")
        .expect("tracker digest") = json!("0");
    mutations.push(("tracker projection", tracker_digest));

    let mut inherited_route = packet.clone();
    *inherited_route
        .pointer_mut("/namespace_projection/route_ownership/route_edge_projection_sha256")
        .expect("inherited route receipt") = json!("0");
    mutations.push(("inherited K0.5 route receipt", inherited_route));

    let mut migration = packet.clone();
    *migration
        .pointer_mut("/disposition_receipt/migration_eligible")
        .expect("migration state") = json!(true);
    mutations.push(("migration eligibility", migration));

    let mut absorbed = packet.clone();
    *absorbed
        .pointer_mut("/standalone_owner_boundaries/0/absorption_allowed")
        .expect("absorption state") = json!(true);
    mutations.push(("standalone absorption", absorbed));

    for (name, mutated) in mutations {
        assert!(
            validate_packet_value(&mutated, &doc, &root, &inputs).is_err(),
            "mutation unexpectedly validated: {name}"
        );
    }

    let broken_doc = doc.replacen(DOC_BEGIN, "", 1);
    assert!(validate_packet_value(&packet, &broken_doc, &root, &inputs).is_err());
}

#[test]
fn kafka_k1_authority_input_mutations_fail_closed() {
    let root = repo_root();
    let packet = parse_json(&root, ARTIFACT_PATH).expect("artifact must parse");
    let doc = read_text(&root, DOC_PATH).expect("document must load");
    let inputs = load_inputs(&root).expect("authority inputs must load");

    let mut missing_public = inputs.clone();
    array_mut(&mut missing_public.k0_1, "public_symbols")
        .expect("public symbols")
        .pop();
    assert!(validate_packet_value(&packet, &doc, &root, &missing_public).is_err());

    let mut duplicate_adr = inputs.clone();
    let adr = find_unique_in(&duplicate_adr.adr_registry, "adrs", "adr_id", ADR_ID)
        .expect("ADR row")
        .clone();
    array_mut(&mut duplicate_adr.adr_registry, "adrs")
        .expect("ADR rows")
        .push(adr);
    assert!(validate_packet_value(&packet, &doc, &root, &duplicate_adr).is_err());

    let mut broken_child_pin = inputs.clone();
    *broken_child_pin
        .k0_5
        .pointer_mut("/child_packets/0/files/0/sha256")
        .expect("K0.1 artifact pin") = json!("0");
    assert!(validate_packet_value(&packet, &doc, &root, &broken_child_pin).is_err());

    let mut broken_reference = inputs.clone();
    *array_mut(&mut broken_reference.k0_3, "k0_1_symbol_dispositions")
        .expect("symbol references")[0]
        .get_mut("symbol_id")
        .expect("symbol_id") = json!("KPR-PUB-BROKEN");
    assert!(validate_packet_value(&packet, &doc, &root, &broken_reference).is_err());

    let mut promoted_state = inputs.clone();
    assert!(replace_first_exact_state(
        &mut promoted_state.k0_3,
        "UNKNOWN",
        "PASS"
    ));
    assert!(validate_packet_value(&packet, &doc, &root, &promoted_state).is_err());

    let mut missing_tracker_gate = inputs;
    missing_tracker_gate.tracker_rows.retain(|row| {
        row.get("id").and_then(Value::as_str)
            != Some("asupersync-dep-p7-kafka-removal-sarszu.2.1.5")
    });
    assert!(validate_packet_value(&packet, &doc, &root, &missing_tracker_gate).is_err());
}
