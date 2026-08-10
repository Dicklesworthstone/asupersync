//! Fail-closed contract for the source-pinned Kafka incumbent semantics matrix.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.1.2
//! Fixture: artifacts/kafka_incumbent_semantics_matrix_v1.json
//!
//! This contract reads repository files only. It starts no process, runtime,
//! broker, network request, timer, fuzz target, compiler, or remote job.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const DOC_PATH: &str = "docs/kafka_incumbent_semantics_matrix.md";
const K0_1_ARTIFACT_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const ARTIFACT_ID: &str = "kafka-incumbent-semantics-matrix-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.2";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const BASELINE_REVISION: &str = "b4997e8fe4de098a5a30ff468418460b59ca414a";
const ARTIFACT_SHA256: &str = "2e27c15302548ee50be3a5f3e07a86497893220b03b04b6700481e3ed7dd36fd";
const DOC_SHA256: &str = "7cf46fb6eaa7ded66b6d1d04a7c711f4ce687252bb42eaa05d77e3a5e4b79ff5";
const SOURCE_PIN_MAP_SHA256: &str =
    "3107f0fb6defac17117c5c63db1809602ced15ef8a753f29f602430e206dace2";
const ALL_ROW_SOURCE_ANCHOR_MAP_SHA256: &str =
    "a895bcf372e6fcdd834fea2ca918e1bbc22623193098e0f4ebda684ef7735d33";
const PUBLIC_ENTRY_ANCHOR_MAP_SHA256: &str =
    "8deea5e3080636eed2b7282749ce52b9b22642829b7f74b101bf8769817428e6";
const ROW_GAP_OWNER_MAP_SHA256: &str =
    "5c4cb0c1edc74b5f8de090bd8f166de14e8f263d4b681d5fa23cdcb20a1ea760";
const FINDING_OWNER_MAP_SHA256: &str =
    "fb2c14f5416a2499c4d006c36929319afbd0d79a90b68deb7d937c538f46c5cd";
const PROFILE_MEMBERSHIP_SHA256: &str =
    "0ec7486c89bbf4555625068ffccfb1d7ee976bb5feb0c459be99f1415ef63d54";
const PROFILE_GAP_OWNER_MAP_SHA256: &str =
    "05ef0ea1f1b842cc805d2b8a7ec1b2f2a9555fe9d1c71c3f3598a9f5898a0286";
const DOC_BEGIN: &str = "<!-- BEGIN KAFKA INCUMBENT SEMANTICS MATRIX -->";
const DOC_END: &str = "<!-- END KAFKA INCUMBENT SEMANTICS MATRIX -->";

const REQUIRED_ROW_KEYS: &[&str] = &[
    "semantic_id",
    "surface",
    "public_entry_points",
    "source_anchor",
    "source_owner",
    "cfg_visibility",
    "default",
    "accepted_values",
    "rejected_values",
    "broker_mapping",
    "success_outcome",
    "error_outcome",
    "retry_rule",
    "timeout_rule",
    "cancellation_rule",
    "shutdown_rule",
    "resource_bound",
    "credential_payload_rule",
    "gap_owners",
];

const ALLOWED_GAP_OWNERS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.1.2",
    "asupersync-dep-p7-kafka-removal-sarszu.1.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.3.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.3.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.3.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.5.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.5.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.5.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.5.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.6.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.6.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.6.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.7.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.7.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.7.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.8.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.8.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.8.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.8.5",
    "asupersync-dep-p7-kafka-removal-sarszu.2.9",
    "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.10.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.10.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.10.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.11.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.11.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.11.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.11.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.4",
    "asupersync-ne8jdw",
    "asupersync-z2kt29",
];

const REQUIRED_TEXT_ROW_KEYS: &[&str] = &[
    "semantic_id",
    "surface",
    "source_anchor",
    "source_owner",
    "cfg_visibility",
    "default",
    "accepted_values",
    "rejected_values",
    "broker_mapping",
    "success_outcome",
    "error_outcome",
    "retry_rule",
    "timeout_rule",
    "cancellation_rule",
    "shutdown_rule",
    "resource_bound",
    "credential_payload_rule",
];

const PROFILE_GROUP_KEYS: &[&str] = &[
    "profile_group_id",
    "semantic_ids",
    "no_feature_behavior",
    "deterministic_behavior",
    "release_test_internals_behavior",
    "gap_owners",
];

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

fn string_value(value: &Value, label: &str) -> String {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{label} must be a string"))
        .to_owned()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| string_value(entry, key))
        .collect()
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn expected_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|item| (*item).to_owned()).collect()
}

fn numbered_ids(prefix: &str, end: usize) -> BTreeSet<String> {
    (1..=end)
        .map(|number| format!("{prefix}{number:03}"))
        .collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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

fn parse_anchor_line(value: &str, row_id: &str) -> Result<usize, String> {
    let line = value
        .parse::<usize>()
        .map_err(|error| format!("{row_id} has invalid source-anchor line {value}: {error}"))?;
    if line == 0 {
        return Err(format!("{row_id} source-anchor lines are one-based"));
    }
    Ok(line)
}

fn anchored_source(row: &Value, sources: &BTreeMap<String, String>) -> Result<String, String> {
    let row_id = text(row, "semantic_id");
    let anchor = text(row, "source_anchor");
    let anchor_segments: Vec<&str> = anchor.split(';').collect();
    let owner_paths: Vec<&str> = text(row, "source_owner").split(';').collect();
    if anchor_segments.is_empty()
        || anchor_segments.len() != owner_paths.len()
        || owner_paths.iter().copied().collect::<BTreeSet<_>>().len() != owner_paths.len()
    {
        return Err(format!(
            "{row_id} source owners must exactly match unique anchor-path segments"
        ));
    }
    let mut excerpt = String::new();

    for (anchor_segment, expected_owner) in anchor_segments.iter().zip(owner_paths) {
        let (source_path, spans) = anchor_segment
            .split_once(':')
            .ok_or_else(|| format!("{row_id} source anchor must contain path:spans"))?;
        if source_path != expected_owner {
            return Err(format!("{row_id} source owner must equal its anchor path"));
        }
        let source = sources
            .get(source_path)
            .ok_or_else(|| format!("{row_id} anchor path {source_path} is not source-pinned"))?;
        let source_lines: Vec<&str> = source.lines().collect();
        let mut prior_end = 0;

        for span in spans.split(',') {
            let (start, end) = match span.split_once('-') {
                Some((start, end)) => (
                    parse_anchor_line(start, row_id)?,
                    parse_anchor_line(end, row_id)?,
                ),
                None => {
                    let line = parse_anchor_line(span, row_id)?;
                    (line, line)
                }
            };
            if start > end || end > source_lines.len() {
                return Err(format!(
                    "{row_id} source-anchor span {span} is outside {source_path}"
                ));
            }
            if start <= prior_end {
                return Err(format!(
                    "{row_id} source-anchor spans must be strictly ordered and nonoverlapping"
                ));
            }
            for source_line in &source_lines[start - 1..end] {
                excerpt.push_str(source_line);
                excerpt.push('\n');
            }
            prior_end = end;
        }
    }

    if excerpt.is_empty() {
        return Err(format!("{row_id} source anchor produced an empty excerpt"));
    }
    Ok(excerpt)
}

fn validate_source_anchors(matrix: &Value) -> Result<(), String> {
    let sources: BTreeMap<String, String> = [
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
        "src/runtime/spawn_blocking.rs",
        "src/runtime/blocking_pool.rs",
    ]
    .into_iter()
    .map(|source_path| (source_path.to_owned(), read_repo_file(source_path)))
    .collect();
    let mut all_row_anchor_map = String::new();
    let mut entry_anchor_map = String::new();

    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        for row in array(matrix, collection) {
            let excerpt = anchored_source(row, &sources)?;
            all_row_anchor_map.push_str(text(row, "semantic_id"));
            all_row_anchor_map.push('=');
            all_row_anchor_map.push_str(text(row, "source_owner"));
            all_row_anchor_map.push('|');
            all_row_anchor_map.push_str(text(row, "source_anchor"));
            all_row_anchor_map.push('\n');
            let entries = array(row, "public_entry_points");
            if entries.is_empty() {
                let row_id = text(row, "semantic_id");
                let surface = text(row, "surface");
                if row_id == "KPR-OP-021" {
                    if !excerpt.contains("fn mark_transaction_dropped(")
                        || !excerpt.contains("impl Drop for Transaction")
                    {
                        return Err("KPR-OP-021 lifecycle anchor drifted".to_owned());
                    }
                } else if let Some((_, field)) = surface.rsplit_once('.') {
                    if !excerpt.contains(&format!("{field}:")) {
                        return Err(format!("{row_id} anchor does not contain field {field}"));
                    }
                } else if !excerpt.contains(&format!("enum {surface}")) {
                    return Err(format!("{row_id} anchor does not contain enum {surface}"));
                }
            }
            for entry in entries {
                let entry = entry
                    .as_str()
                    .ok_or_else(|| format!("{collection} entry point must be text"))?;
                let declaration_path = entry.split_once('(').map_or(entry, |(path, _)| path);
                let function = declaration_path
                    .rsplit("::")
                    .next()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| format!("invalid public entry point {entry}"))?;
                entry_anchor_map.push_str(entry);
                entry_anchor_map.push('=');
                entry_anchor_map.push_str(text(row, "semantic_id"));
                entry_anchor_map.push('|');
                entry_anchor_map.push_str(text(row, "source_owner"));
                entry_anchor_map.push('|');
                entry_anchor_map.push_str(text(row, "source_anchor"));
                entry_anchor_map.push('\n');
                let ordinary_declaration = format!("fn {function}(");
                let generic_declaration = format!("fn {function}<");
                if !excerpt.contains(&ordinary_declaration)
                    && !excerpt.contains(&generic_declaration)
                {
                    return Err(format!(
                        "{} anchor does not contain public entry point {entry}",
                        text(row, "semantic_id")
                    ));
                }
            }
        }
    }
    let all_row_anchor_digest = sha256_hex(all_row_anchor_map.as_bytes());
    if all_row_anchor_digest != ALL_ROW_SOURCE_ANCHOR_MAP_SHA256
        || object(matrix, "coverage_receipt")
            .get("all_row_source_anchor_map_sha256")
            .and_then(Value::as_str)
            != Some(ALL_ROW_SOURCE_ANCHOR_MAP_SHA256)
    {
        return Err("all-row source-owner/source-anchor map drifted".to_owned());
    }
    let entry_anchor_digest = sha256_hex(entry_anchor_map.as_bytes());
    if entry_anchor_digest != PUBLIC_ENTRY_ANCHOR_MAP_SHA256
        || object(matrix, "coverage_receipt")
            .get("public_entry_anchor_map_sha256")
            .and_then(Value::as_str)
            != Some(PUBLIC_ENTRY_ANCHOR_MAP_SHA256)
    {
        return Err("public entry-point source-anchor map drifted".to_owned());
    }
    Ok(())
}

fn canonical_owner_map(
    matrix: &Value,
    collections: &[&str],
    id_key: &str,
    owner_key: &str,
) -> Result<String, String> {
    let mut canonical = String::new();
    for collection in collections {
        for row in array(matrix, collection) {
            let row_id = text(row, id_key);
            let owners = array(row, owner_key);
            let owner_set: BTreeSet<String> = owners
                .iter()
                .map(|owner| string_value(owner, owner_key))
                .collect();
            if owners.len() != owner_set.len() {
                return Err(format!("{row_id} has duplicate {owner_key} entries"));
            }
            canonical.push_str(row_id);
            canonical.push('=');
            canonical.push_str(&owner_set.into_iter().collect::<Vec<_>>().join(","));
            canonical.push('\n');
        }
    }
    Ok(sha256_hex(canonical.as_bytes()))
}

fn validate_no_exact_unknown(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{path} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_exact_unknown(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_exact_unknown(child, &format!("{path}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_identity_and_authority(matrix: &Value) -> Result<(), String> {
    if sha256_hex(&read_repo_bytes(ARTIFACT_PATH)) != ARTIFACT_SHA256 {
        return Err("artifact byte digest drifted".to_owned());
    }
    if sha256_hex(&read_repo_bytes(DOC_PATH)) != DOC_SHA256 {
        return Err("documentation byte digest drifted".to_owned());
    }
    if matrix.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", BASELINE_REVISION),
        ("inventory_state", "K0_2_INCUMBENT_SEMANTICS_FROZEN"),
    ] {
        if matrix.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(matrix, "authority");
    for (key, expected) in [
        ("adr_id", "DEP-ADR-009"),
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        (
            "source_inventory_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.1",
        ),
        ("semantic_inventory_owner", BEAD_ID),
        (
            "downstream_inventory_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.3",
        ),
        (
            "broker_provenance_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.4",
        ),
        (
            "terminal_inventory_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.5",
        ),
        (
            "conditional_cutover_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.15",
        ),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("authority must forbid dependency exit".to_owned());
    }

    let policy = object(matrix, "policy");
    if policy.get("incumbent_truth_only").and_then(Value::as_bool) != Some(true) {
        return Err("policy must freeze incumbent truth".to_owned());
    }
    for key in [
        "future_native_design_projected_backward",
        "behavior_changes_allowed",
        "dependency_changes_allowed",
        "missing_operation_may_be_implicit",
        "unowned_semantic_row_allowed",
        "planned_evidence_counts_as_executed",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("policy.{key} must remain false"));
        }
    }
    if policy.get("missing_row_state").and_then(Value::as_str) != Some("BLOCKING_MISSING")
        || policy.get("routed_gap_state").and_then(Value::as_str) != Some("ROUTED")
    {
        return Err("policy gap-state taxonomy drifted".to_owned());
    }

    let allowed_gap_owners = string_set(matrix, "gap_owner_allowset");
    if allowed_gap_owners != expected_set(ALLOWED_GAP_OWNERS)
        || array(matrix, "gap_owner_allowset").len() != ALLOWED_GAP_OWNERS.len()
    {
        return Err("gap owner allowset drifted".to_owned());
    }

    validate_no_exact_unknown(matrix, "$")
}

fn validate_source_pins(matrix: &Value) -> Result<(), String> {
    let pins = array(matrix, "source_pins");
    let expected_ids = expected_set(&[
        "KAFKA-K0-2-PIN-PRODUCER",
        "KAFKA-K0-2-PIN-CONSUMER",
        "KAFKA-K0-2-PIN-BLOCKING-BRIDGE",
        "KAFKA-K0-2-PIN-BLOCKING-POOL",
        "KAFKA-K0-2-PIN-K0-1-ARTIFACT",
        "KAFKA-K0-2-PIN-K0-1-DOC",
        "KAFKA-K0-2-PIN-ADR",
        "KAFKA-K0-2-PIN-REGISTRY",
    ]);
    if pins.len() != expected_ids.len() || row_ids(pins, "pin_id") != expected_ids {
        return Err("source pin identity set drifted".to_owned());
    }

    let expected_paths = expected_set(&[
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
        "src/runtime/spawn_blocking.rs",
        "src/runtime/blocking_pool.rs",
        K0_1_ARTIFACT_PATH,
        "docs/kafka_capability_inventory.md",
        "docs/adr/dep_plan_adr_009_kafka_client.md",
        "artifacts/dependency_capability_registry_v1.json",
    ]);
    let actual_paths: BTreeSet<String> = pins
        .iter()
        .map(|pin| text(pin, "path").to_owned())
        .collect();
    if actual_paths != expected_paths {
        return Err("source pin path set drifted".to_owned());
    }

    let mut source_pin_map = BTreeMap::new();
    for pin in pins {
        let pin_id = text(pin, "pin_id");
        let path = text(pin, "path");
        let record_count = pin
            .get("record_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("source pin record_count must be u64 for {path}"))?;
        let role = text(pin, "role");
        let mapping = format!("{path}|{record_count}|{}|{role}", text(pin, "sha256"));
        if source_pin_map.insert(pin_id.to_owned(), mapping).is_some() {
            return Err(format!("duplicate source pin identity {pin_id}"));
        }
        let bytes = read_repo_bytes(path);
        if sha256_hex(&bytes) != text(pin, "sha256") {
            return Err(format!("source pin hash drifted for {path}"));
        }
        let records = u64::try_from(read_repo_file(path).lines().count())
            .map_err(|_| format!("source pin record count overflowed for {path}"))?;
        if pin.get("record_count").and_then(Value::as_u64) != Some(records) {
            return Err(format!("source pin record count drifted for {path}"));
        }
    }
    let canonical_pin_map = source_pin_map
        .into_iter()
        .map(|(pin_id, mapping)| format!("{pin_id}={mapping}\n"))
        .collect::<String>();
    if sha256_hex(canonical_pin_map.as_bytes()) != SOURCE_PIN_MAP_SHA256
        || object(matrix, "coverage_receipt")
            .get("source_pin_map_sha256")
            .and_then(Value::as_str)
            != Some(SOURCE_PIN_MAP_SHA256)
    {
        return Err("source pin identity/path/count/hash/role map drifted".to_owned());
    }
    Ok(())
}

fn validate_required_row_shape(rows: &[Value], label: &str) -> Result<(), String> {
    let ids = row_ids(rows, "semantic_id");
    if ids.len() != rows.len() {
        return Err(format!("{label} semantic IDs must be unique"));
    }
    let required_keys = expected_set(REQUIRED_ROW_KEYS);
    let allowed_owners = expected_set(ALLOWED_GAP_OWNERS);
    for row in rows {
        let id = text(row, "semantic_id");
        let row_object = row
            .as_object()
            .ok_or_else(|| format!("{label} {id} must be an object"))?;
        let actual_keys: BTreeSet<String> = row_object.keys().cloned().collect();
        if actual_keys != required_keys {
            return Err(format!("{label} {id} key set must be exact"));
        }
        for key in REQUIRED_TEXT_ROW_KEYS {
            if text(row, key).trim().is_empty() {
                return Err(format!("{label} {id} has empty {key}"));
            }
        }
        if array(row, "public_entry_points")
            .iter()
            .any(|entry| entry.as_str().is_none_or(|entry| entry.trim().is_empty()))
        {
            return Err(format!("{label} {id} has an invalid public entry point"));
        }
        let owners = array(row, "gap_owners");
        if owners.is_empty()
            || owners.iter().any(|owner| {
                owner
                    .as_str()
                    .is_none_or(|owner| !allowed_owners.contains(owner))
            })
        {
            return Err(format!(
                "{label} {id} must have exact Asupersync gap owners"
            ));
        }
    }
    Ok(())
}

fn validate_configuration_coverage(matrix: &Value) -> Result<(), String> {
    let rows = array(matrix, "configuration_fields");
    validate_required_row_shape(rows, "configuration field")?;

    let mut expected_ids = numbered_ids("KPR-CFG-", 25);
    expected_ids.extend(numbered_ids("KCO-CFG-", 18));
    if rows.len() != 43 || row_ids(rows, "semantic_id") != expected_ids {
        return Err("configuration field ID set must be exact".to_owned());
    }

    let expected_surfaces = expected_set(&[
        "ProducerConfig.bootstrap_servers",
        "ProducerConfig.client_id",
        "ProducerConfig.batch_size",
        "ProducerConfig.linger_ms",
        "ProducerConfig.compression",
        "ProducerConfig.enable_idempotence",
        "ProducerConfig.acks",
        "ProducerConfig.retries",
        "ProducerConfig.request_timeout",
        "ProducerConfig.max_message_size",
        "ProducerConfig.security",
        "ProducerConfig.feature_requirement",
        "ProducerConfig.allow_insecure_transport_for_testing",
        "ProducerConfig.allow_deterministic_broker_for_testing",
        "KafkaTlsConfig.ca_location",
        "KafkaTlsConfig.certificate_location",
        "KafkaTlsConfig.key_location",
        "KafkaTlsConfig.key_password",
        "KafkaSaslConfig.mechanism",
        "KafkaSaslConfig.username",
        "KafkaSaslConfig.password",
        "KafkaSaslConfig.tls",
        "TransactionalConfig.producer",
        "TransactionalConfig.transaction_id",
        "TransactionalConfig.transaction_timeout",
        "ConsumerConfig.bootstrap_servers",
        "ConsumerConfig.group_id",
        "ConsumerConfig.client_id",
        "ConsumerConfig.session_timeout",
        "ConsumerConfig.heartbeat_interval",
        "ConsumerConfig.auto_offset_reset",
        "ConsumerConfig.enable_auto_commit",
        "ConsumerConfig.auto_commit_interval",
        "ConsumerConfig.max_poll_records",
        "ConsumerConfig.fetch_min_bytes",
        "ConsumerConfig.fetch_max_bytes",
        "ConsumerConfig.fetch_max_wait",
        "ConsumerConfig.isolation_level",
        "ConsumerConfig.security",
        "ConsumerConfig.force_real_kafka",
        "ConsumerConfig.retries",
        "ConsumerConfig.allow_insecure_transport_for_testing",
        "ConsumerConfig.allow_deterministic_broker_for_testing",
    ]);
    let actual_surfaces: BTreeSet<String> = rows
        .iter()
        .map(|row| text(row, "surface").to_owned())
        .collect();
    if actual_surfaces != expected_surfaces {
        return Err("configuration field surface set drifted".to_owned());
    }
    for row in rows {
        if text(row, "cfg_visibility").contains("private")
            && array(row, "public_entry_points").is_empty()
        {
            return Err(format!(
                "private configuration field {} must name a public writer",
                text(row, "semantic_id")
            ));
        }
    }

    let manual = find_row(rows, "semantic_id", "KCO-CFG-007");
    if text(manual, "default") != "false, manual commit"
        || !text(manual, "success_outcome").contains("stores before returning")
        || !text(manual, "shutdown_rule").contains("no explicit real-broker auto-commit flush")
    {
        return Err("manual/auto commit incumbent semantics drifted".to_owned());
    }
    let idempotence = find_row(rows, "semantic_id", "KPR-CFG-006");
    if text(idempotence, "default") != "true"
        || !text(idempotence, "broker_mapping").contains("forcibly overwrites")
        || !text(idempotence, "credential_payload_rule").contains("do not deduplicate")
    {
        return Err("producer idempotence semantics drifted".to_owned());
    }
    for id in ["KPR-CFG-013", "KCO-CFG-017"] {
        let bypass = find_row(rows, "semantic_id", id);
        if !text(bypass, "cfg_visibility").contains("debug_assertions")
            || text(bypass, "default") != "false"
        {
            return Err(format!("{id} debug/test bypass semantics drifted"));
        }
    }
    for id in ["KPR-CFG-014", "KCO-CFG-018"] {
        let harness = find_row(rows, "semantic_id", id);
        let serialized = serde_json::to_string(harness)
            .map_err(|error| format!("failed to serialize {id}: {error}"))?;
        if !serialized.contains("release test-internals") || !serialized.contains("panic guard") {
            return Err(format!("{id} release harness guard must remain explicit"));
        }
    }
    Ok(())
}

fn expected_public_methods(source_inventory: &Value) -> Result<BTreeSet<String>, String> {
    let mut methods = BTreeSet::new();
    for symbol in array(source_inventory, "public_symbols") {
        let declarations = array(symbol, "declarations");
        let declaration = declarations
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| "public symbol declaration must be text".to_owned())?;
        let owner = declaration
            .split('@')
            .next()
            .ok_or_else(|| format!("invalid declaration {declaration}"))?;
        for method in array(symbol, "public_methods") {
            let method = method
                .as_str()
                .ok_or_else(|| "public method must be text".to_owned())?;
            methods.insert(format!("{owner}::{method}"));
        }
    }
    Ok(methods)
}

fn validate_public_method_coverage(matrix: &Value) -> Result<(), String> {
    let source_inventory = parse_repo_json(K0_1_ARTIFACT_PATH);
    let expected = expected_public_methods(&source_inventory)?;
    if expected.len() != 96 {
        return Err("K0.1 public method authority must contain exactly 96 paths".to_owned());
    }

    let mut actual = Vec::new();
    for key in ["configuration_fields", "enum_semantics", "operations"] {
        for row in array(matrix, key) {
            for entry in array(row, "public_entry_points") {
                actual.push(string_value(entry, "public_entry_points entry"));
            }
        }
    }
    let unique: BTreeSet<String> = actual.iter().cloned().collect();
    let trait_operations = expected_set(&[
        "KafkaError::fmt",
        "KafkaError::source",
        "KafkaError::from(io::Error)",
    ]);
    let inherent: BTreeSet<String> = unique.difference(&trait_operations).cloned().collect();
    if actual.len() != 99
        || unique.len() != 99
        || !trait_operations.is_subset(&unique)
        || inherent != expected
    {
        return Err(
            "all 96 K0.1 methods and three KafkaError trait operations must be covered exactly once"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_profile_dispositions(matrix: &Value) -> Result<(), String> {
    let groups = array(matrix, "profile_disposition_groups");
    if groups.len() != 17
        || row_ids(groups, "profile_group_id") != numbered_ids("KAFKA-PROFILE-", 17)
    {
        return Err("profile disposition group ID set drifted".to_owned());
    }

    let required_keys = expected_set(PROFILE_GROUP_KEYS);
    let allowed_owners = expected_set(ALLOWED_GAP_OWNERS);
    let mut covered_ids = Vec::new();
    let mut canonical_membership = String::new();
    for group in groups {
        let group_id = text(group, "profile_group_id");
        let group_object = group
            .as_object()
            .ok_or_else(|| format!("{group_id} must be an object"))?;
        if group_object.keys().cloned().collect::<BTreeSet<_>>() != required_keys {
            return Err(format!("{group_id} key set must be exact"));
        }
        for key in [
            "no_feature_behavior",
            "deterministic_behavior",
            "release_test_internals_behavior",
        ] {
            if text(group, key).trim().is_empty() {
                return Err(format!("{group_id} has empty {key}"));
            }
        }

        let members = array(group, "semantic_ids");
        let member_set: BTreeSet<String> = members
            .iter()
            .map(|member| string_value(member, "profile semantic ID"))
            .collect();
        if members.is_empty() || members.len() != member_set.len() {
            return Err(format!(
                "{group_id} semantic IDs must be nonempty and unique"
            ));
        }
        covered_ids.extend(member_set.iter().cloned());
        canonical_membership.push_str(group_id);
        canonical_membership.push('=');
        canonical_membership.push_str(&member_set.into_iter().collect::<Vec<_>>().join(","));
        canonical_membership.push('\n');

        let owners = array(group, "gap_owners");
        let owner_set: BTreeSet<String> = owners
            .iter()
            .map(|owner| string_value(owner, "profile gap owner"))
            .collect();
        if owners.is_empty()
            || owners.len() != owner_set.len()
            || owner_set
                .iter()
                .any(|owner| !allowed_owners.contains(owner))
        {
            return Err(format!("{group_id} gap owners must be unique and allowed"));
        }
    }

    let mut expected_ids = BTreeSet::new();
    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        expected_ids.extend(row_ids(array(matrix, collection), "semantic_id"));
    }
    let unique_covered: BTreeSet<String> = covered_ids.iter().cloned().collect();
    if expected_ids.len() != 97
        || covered_ids.len() != 97
        || unique_covered.len() != 97
        || unique_covered != expected_ids
    {
        return Err("all 97 semantic rows must have exactly one profile disposition".to_owned());
    }
    if sha256_hex(canonical_membership.as_bytes()) != PROFILE_MEMBERSHIP_SHA256 {
        return Err("profile disposition membership drifted".to_owned());
    }

    let commit = find_row(groups, "profile_group_id", "KAFKA-PROFILE-009");
    let commit_release = text(commit, "release_test_internals_behavior");
    if string_set(commit, "semantic_ids") != expected_set(&["KPR-OP-013"])
        || !commit_release.contains("empty")
        || !commit_release.contains("nonempty")
        || !commit_release.contains("NeedsAbortRecovery")
    {
        return Err("transaction-commit profile disposition drifted".to_owned());
    }
    let client_consumer = find_row(groups, "profile_group_id", "KAFKA-PROFILE-011");
    if string_set(client_consumer, "semantic_ids") != expected_set(&["KPR-OP-020"])
        || !text(client_consumer, "deterministic_behavior").contains("crate-test cfg branch")
        || !text(client_consumer, "release_test_internals_behavior").contains("FeatureDisabled")
    {
        return Err("parallel-client consumer profile disposition drifted".to_owned());
    }
    Ok(())
}

fn require_exact_gap_owners(row: &Value, expected: &[&str]) -> Result<(), String> {
    let owners = string_set(row, "gap_owners");
    if owners != expected_set(expected) || array(row, "gap_owners").len() != expected.len() {
        return Err(format!(
            "{} exact gap-owner set drifted",
            text(row, "semantic_id")
        ));
    }
    Ok(())
}

fn validate_high_risk_semantics(matrix: &Value) -> Result<(), String> {
    let fields = array(matrix, "configuration_fields");
    let key_password = find_row(fields, "semantic_id", "KPR-CFG-018");
    require_exact_gap_owners(
        key_password,
        &[
            "asupersync-dep-p7-kafka-removal-sarszu.2.3.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.4",
        ],
    )?;
    if text(key_password, "source_anchor") != "src/messaging/kafka.rs:934-956,988-993,1169-1171"
        || !text(key_password, "credential_payload_rule").contains("not ZeroizeOnDrop")
        || !text(key_password, "credential_payload_rule").contains("plaintext copies")
    {
        return Err("TLS key-password retention semantics drifted".to_owned());
    }

    let transaction_timeout = find_row(fields, "semantic_id", "KPR-CFG-025");
    require_exact_gap_owners(
        transaction_timeout,
        &[
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.4",
            "asupersync-ne8jdw",
        ],
    )?;
    if text(transaction_timeout, "source_anchor")
        != "src/messaging/kafka.rs:440-482,1834-1835,1846,1851-1854,2030-2031,2057-2059,2154-2156,2209-2211;src/runtime/spawn_blocking.rs:1-12,40-63,113-130,146-177,239-253,264-315;src/runtime/blocking_pool.rs:284-317,436-457,626-645,866-884,973-990,1293-1310"
        || !text(transaction_timeout, "broker_mapping").contains("u128 decimal text")
        || !text(transaction_timeout, "broker_mapping").contains("does not saturate to u64")
        || !text(transaction_timeout, "broker_mapping").contains("original Duration")
        || !text(transaction_timeout, "timeout_rule").contains("queue delay")
        || !text(transaction_timeout, "timeout_rule").contains("begin_transaction takes no timeout")
    {
        return Err("transaction-timeout conversion semantics drifted".to_owned());
    }

    let producer_admission = find_row(fields, "semantic_id", "KPR-CFG-014");
    if text(producer_admission, "source_anchor")
        != "src/messaging/kafka.rs:627-745,1229-1231,1250-1251,1386-1410,1605-1609,1672-1676,1903-1918"
        || !text(producer_admission, "broker_mapping")
            .contains("gates KafkaProducer send and TransactionalProducer::begin_transaction")
        || !text(producer_admission, "broker_mapping")
            .contains("already-created Transaction handle do not recheck")
        || !text(producer_admission, "error_outcome")
            .contains("does not gate consumer or kafka-feature operations")
    {
        return Err("producer deterministic-admission scope drifted".to_owned());
    }

    let heartbeat = find_row(fields, "semantic_id", "KCO-CFG-005");
    if !text(heartbeat, "broker_mapping").contains("saturated at u64::MAX")
        || !text(heartbeat, "retry_rule").contains("casts as_millis().max(1) to u64")
        || !text(heartbeat, "retry_rule").contains("produce a zero delay")
    {
        return Err("consumer heartbeat conversion semantics drifted".to_owned());
    }

    let auto_commit = find_row(fields, "semantic_id", "KCO-CFG-007");
    if !text(auto_commit, "success_outcome").contains("real-broker path")
        || !text(auto_commit, "success_outcome")
            .contains("never updates committed_offsets automatically")
        || !text(auto_commit, "accepted_values").contains("can redeliver")
    {
        return Err("consumer auto-commit profile semantics drifted".to_owned());
    }

    let consumer_security = find_row(fields, "semantic_id", "KCO-CFG-014");
    if text(consumer_security, "source_anchor")
        != "src/messaging/kafka_consumer.rs:133-134,178,292-326,564-579;src/messaging/kafka.rs:894-931,1131-1192"
        || text(consumer_security, "source_owner")
            != "src/messaging/kafka_consumer.rs;src/messaging/kafka.rs"
        || !text(consumer_security, "broker_mapping").contains("apply_security_config")
    {
        return Err("consumer shared-security mapping evidence drifted".to_owned());
    }

    let feature_requirement = find_row(fields, "semantic_id", "KPR-CFG-012");
    for diagnostic in [
        "Kafka cargo feature is enabled; real broker integration is available",
        "Kafka cargo feature is optional for this config and is not enabled; non-test broker operations return FeatureDisabled",
        "Kafka cargo feature is required by this config but is not enabled; rebuild with --features kafka",
    ] {
        if !text(feature_requirement, "broker_mapping").contains(diagnostic) {
            return Err(format!(
                "feature diagnostic must retain exact text: {diagnostic}"
            ));
        }
    }

    let operations = array(matrix, "operations");
    let error_classifiers = find_row(operations, "semantic_id", "KPR-OP-001");
    let trait_semantics = text(error_classifiers, "success_outcome");
    for exact_behavior in [
        "Kafka I/O error: {source}",
        "Kafka protocol error: {message}",
        "Kafka broker error: {message}",
        "Kafka producer queue is full",
        "Kafka message too large: {size} bytes (max: {max_size})",
        "Invalid Kafka topic: {topic}",
        "Kafka transaction error: {message}",
        "Kafka operation cancelled",
        "Kafka future polled after completion",
        "Kafka configuration error: {message}",
        "Kafka authentication failed: {message}",
        "Kafka is unavailable: the `kafka` cargo feature is not enabled in this build",
        "Error::source returns Some only for Io",
        "From<io::Error> preserves the supplied error inside Io",
    ] {
        if !trait_semantics.contains(exact_behavior) {
            return Err(format!("KafkaError trait semantics lost {exact_behavior}"));
        }
    }
    let producer_send = find_row(operations, "semantic_id", "KPR-OP-004");
    let producer_send_semantics = serde_json::to_string(producer_send)
        .map_err(|error| format!("failed to serialize KPR-OP-004: {error}"))?;
    for exact_behavior in [
        "offset equal to the pre-push per-topic/partition vector length",
        "timestamp None",
        "CreateTime and LogAppendTime",
        "InvalidTopic(`unknown`)",
        "CRITICAL: attempted to publish to production topic",
        "CRITICAL: deterministic Kafka harness attempted to run in production build",
        "WARNING: publishing to critical topic",
    ] {
        if !producer_send_semantics.contains(exact_behavior) {
            return Err(format!("producer send semantics lost {exact_behavior}"));
        }
    }
    let begin = find_row(operations, "semantic_id", "KPR-OP-010");
    require_exact_gap_owners(
        begin,
        &[
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.3",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.4",
            "asupersync-ne8jdw",
        ],
    )?;
    if !text(begin, "broker_mapping").contains("Concurrent Idle begins")
        || !text(begin, "broker_mapping").contains("two callers can both start abort recovery")
        || !text(begin, "success_outcome").contains("both return handles")
        || !text(begin, "error_outcome").contains("reset Idle while another active handle")
        || !text(begin, "accepted_values").contains("admission flag must be true")
        || !text(begin, "error_outcome").contains("FeatureDisabled")
        || !text(begin, "cancellation_rule").contains("phase is set Active")
        || !text(begin, "cancellation_rule").contains("no handle")
        || !text(begin, "timeout_rule").contains("begin_transaction itself takes no timeout")
    {
        return Err("transaction initialization concurrency semantics drifted".to_owned());
    }

    let commit = find_row(operations, "semantic_id", "KPR-OP-013");
    require_exact_gap_owners(
        commit,
        &[
            "asupersync-dep-p7-kafka-removal-sarszu.2.5.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.3",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.4",
            "asupersync-ne8jdw",
        ],
    )?;
    if text(commit, "source_anchor")
        != "src/messaging/kafka.rs:351-374,463-482,716-745,1971-2020,2143-2196,2229-2237;src/runtime/spawn_blocking.rs:1-12,40-63,113-130,146-177,239-253,264-315;src/runtime/blocking_pool.rs:284-317,436-457,626-645,866-884,973-990,1293-1310"
        || !text(commit, "error_outcome").contains("empty staged commit succeeds locally")
        || !text(commit, "error_outcome").contains("nonempty staged commit panics")
        || !text(commit, "error_outcome").contains("Duplicate native handles")
        || !text(commit, "cancellation_rule").contains("unfinished-drop poisoning")
    {
        return Err("transaction commit profile semantics drifted".to_owned());
    }

    let abort = find_row(operations, "semantic_id", "KPR-OP-014");
    require_exact_gap_owners(
        abort,
        &[
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.3",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.11.4",
            "asupersync-ne8jdw",
        ],
    )?;
    if text(abort, "source_anchor")
        != "src/messaging/kafka.rs:351-374,463-482,1971-2020,2198-2237;src/runtime/spawn_blocking.rs:1-12,40-63,113-130,146-177,239-253,264-315;src/runtime/blocking_pool.rs:284-317,436-457,626-645,866-884,973-990,1293-1310"
        || !text(abort, "broker_mapping").contains("every no-feature branch")
        || !text(abort, "error_outcome").contains("succeeds locally")
        || !text(abort, "error_outcome").contains("Duplicate native handles")
        || !text(abort, "cancellation_rule").contains("NeedsAbortRecovery")
    {
        return Err("transaction abort profile semantics drifted".to_owned());
    }
    for id in ["KPR-OP-010", "KPR-OP-013", "KPR-OP-014"] {
        let row = find_row(operations, "semantic_id", id);
        if !text(row, "source_owner").contains("src/runtime/spawn_blocking.rs")
            || !text(row, "source_owner").contains("src/runtime/blocking_pool.rs")
            || !text(row, "resource_bound").contains("successfully spawned blocking threads at 256")
            || !text(row, "resource_bound").contains("SegQueue")
            || !text(row, "resource_bound").contains("uncapped")
            || !text(row, "cancellation_rule").contains("no-pool")
            || !text(row, "cancellation_rule").contains("queued")
            || !text(row, "cancellation_rule").contains("execut")
            || !text(row, "timeout_rule").contains("queued indefinitely")
            || !text(row, "error_outcome")
                .contains("blocking operation ended without producing a result")
            || !text(row, "error_outcome").contains("panic")
        {
            return Err(format!("{id} blocking-bridge semantics drifted"));
        }
    }

    let subscribe = find_row(operations, "semantic_id", "KCO-OP-004");
    let poll = find_row(operations, "semantic_id", "KCO-OP-006");
    let close = find_row(operations, "semantic_id", "KCO-OP-009");
    if !text(subscribe, "shutdown_rule").contains("subscribe the already-cleaned backend")
        || !text(poll, "shutdown_rule").contains("return a record after close")
        || !text(poll, "success_outcome").contains("discard it if offset storage")
        || !text(poll, "success_outcome").contains("nonnegative absolute Offset")
        || !text(poll, "credential_payload_rule").contains("CreateTime versus LogAppendTime")
        || !text(poll, "timeout_rule").contains("u64::MAX nanoseconds")
        || !text(close, "error_outcome").contains("concurrent second close")
        || !text(close, "shutdown_rule").contains("concurrent close calls are not joined")
        || !text(close, "shutdown_rule").contains("admitted subscribe/poll work is not fenced")
    {
        return Err("consumer close-race semantics drifted".to_owned());
    }

    let consumer_constructor = find_row(operations, "semantic_id", "KCO-OP-003");
    if !text(consumer_constructor, "broker_mapping").contains("enable.partition.eof=true")
        || !text(consumer_constructor, "error_outcome").contains("ClientCreation")
        || !text(consumer_constructor, "credential_payload_rule").contains("can expose a password")
    {
        return Err("consumer construction semantics drifted".to_owned());
    }
    for id in [
        "KCO-OP-004",
        "KCO-OP-005",
        "KCO-OP-006",
        "KCO-OP-007",
        "KCO-OP-008",
        "KCO-OP-009",
    ] {
        let row = find_row(operations, "semantic_id", id);
        if !text(row, "source_owner").contains("src/runtime/spawn_blocking.rs")
            || !text(row, "resource_bound").contains("successfully spawned blocking threads at 256")
            || !text(row, "cancellation_rule").contains("without consulting this operation Cx")
            || !text(row, "error_outcome").contains("blocking-closure panic")
            || !text(row, "resource_bound").contains("inline on the async worker")
        {
            return Err(format!("{id} blocking-bridge semantics drifted"));
        }
    }
    for id in ["KCO-OP-004", "KCO-OP-005", "KCO-OP-006", "KCO-OP-008"] {
        let serialized = serde_json::to_string(find_row(operations, "semantic_id", id))
            .map_err(|error| format!("failed to serialize {id}: {error}"))?;
        if !serialized.contains("buffered") {
            return Err(format!("{id} buffered-outcome lifecycle drifted"));
        }
    }
    let commit_offsets = find_row(operations, "semantic_id", "KCO-OP-007");
    if !text(commit_offsets, "success_outcome").contains("reverse continuation order")
        || !text(poll, "shutdown_rule").contains("newer assignment epoch")
        || !text(poll, "broker_mapping").contains("retained poll_cursor")
    {
        return Err("consumer continuation-order semantics drifted".to_owned());
    }
    Ok(())
}

fn validate_exact_owner_maps(matrix: &Value) -> Result<(), String> {
    let row_digest = canonical_owner_map(
        matrix,
        &[
            "configuration_fields",
            "enum_semantics",
            "operations",
            "callable_helpers",
        ],
        "semantic_id",
        "gap_owners",
    )?;
    let finding_digest =
        canonical_owner_map(matrix, &["routed_findings"], "finding_id", "owner_beads")?;
    let profile_owner_digest = canonical_owner_map(
        matrix,
        &["profile_disposition_groups"],
        "profile_group_id",
        "gap_owners",
    )?;
    let receipt = object(matrix, "coverage_receipt");
    if row_digest != ROW_GAP_OWNER_MAP_SHA256
        || receipt
            .get("row_gap_owner_map_sha256")
            .and_then(Value::as_str)
            != Some(ROW_GAP_OWNER_MAP_SHA256)
    {
        return Err("semantic-row exact gap-owner map drifted".to_owned());
    }
    if finding_digest != FINDING_OWNER_MAP_SHA256
        || receipt
            .get("finding_owner_map_sha256")
            .and_then(Value::as_str)
            != Some(FINDING_OWNER_MAP_SHA256)
    {
        return Err("routed-finding exact owner map drifted".to_owned());
    }
    if receipt
        .get("profile_membership_sha256")
        .and_then(Value::as_str)
        != Some(PROFILE_MEMBERSHIP_SHA256)
    {
        return Err("profile membership receipt drifted".to_owned());
    }
    if profile_owner_digest != PROFILE_GAP_OWNER_MAP_SHA256
        || receipt
            .get("profile_gap_owner_map_sha256")
            .and_then(Value::as_str)
            != Some(PROFILE_GAP_OWNER_MAP_SHA256)
    {
        return Err("profile exact gap-owner map drifted".to_owned());
    }
    Ok(())
}

fn validate_enum_and_operation_rows(matrix: &Value) -> Result<(), String> {
    let enums = array(matrix, "enum_semantics");
    validate_required_row_shape(enums, "enum")?;
    if enums.len() != 7 || row_ids(enums, "semantic_id") != numbered_ids("KAFKA-ENUM-", 7) {
        return Err("enum semantic ID set drifted".to_owned());
    }
    let expected_enum_surfaces = expected_set(&[
        "Compression",
        "Acks",
        "KafkaFeatureRequirement",
        "KafkaSaslMechanism",
        "KafkaSecurityConfig",
        "AutoOffsetReset",
        "IsolationLevel",
    ]);
    let actual_enum_surfaces: BTreeSet<String> = enums
        .iter()
        .map(|row| text(row, "surface").to_owned())
        .collect();
    if actual_enum_surfaces != expected_enum_surfaces {
        return Err("enum surface set drifted".to_owned());
    }

    let operations = array(matrix, "operations");
    validate_required_row_shape(operations, "operation")?;
    let mut expected_operation_ids = numbered_ids("KPR-OP-", 21);
    expected_operation_ids.extend(numbered_ids("KCO-OP-", 17));
    if operations.len() != 38 || row_ids(operations, "semantic_id") != expected_operation_ids {
        return Err("operation semantic ID set drifted".to_owned());
    }

    for (id, marker) in [
        ("KPR-OP-004", "Cancellation after enqueue"),
        ("KPR-OP-005", "not a stable barrier"),
        ("KPR-OP-006", "uncertain drain state"),
        ("KPR-OP-013", "no typed ambiguous outcome"),
        ("KPR-OP-021", "no broker abort"),
        ("KCO-OP-005", "caller assignment"),
        ("KCO-OP-006", "missing payload becomes empty bytes"),
        ("KCO-OP-007", "No transactional offset enrollment"),
        ("KCO-OP-009", "cannot retry cleanup"),
    ] {
        let row = find_row(operations, "semantic_id", id);
        let serialized = serde_json::to_string(row)
            .map_err(|error| format!("failed to serialize {id}: {error}"))?;
        if !serialized.contains(marker) {
            return Err(format!("{id} must retain marker {marker}"));
        }
    }
    Ok(())
}

fn validate_helpers_and_absences(matrix: &Value) -> Result<(), String> {
    let helpers = array(matrix, "callable_helpers");
    validate_required_row_shape(helpers, "callable helper")?;
    if helpers.len() != 9 || row_ids(helpers, "semantic_id") != numbered_ids("KPR-HLP-", 9) {
        return Err("callable helper ID set drifted".to_owned());
    }
    let expected_helper_entries = expected_set(&[
        "deterministic_broker_end_offset",
        "reset_deterministic_broker_for_tests",
        "lock_deterministic_broker_for_tests",
        "Acks::from(u8)",
        "Compression::from(u8)",
        "fuzz_parse_kafka_error_response",
        "fuzz_parse_response_metadata",
        "fuzz_validate_response_frame",
        "fuzz_parse_delivery_result",
    ]);
    let actual_helper_entries: BTreeSet<String> = helpers
        .iter()
        .flat_map(|row| array(row, "public_entry_points").iter())
        .map(|entry| string_value(entry, "helper entry"))
        .collect();
    if actual_helper_entries != expected_helper_entries {
        return Err("callable helper entry-point set drifted".to_owned());
    }
    let compression = find_row(helpers, "semantic_id", "KPR-HLP-005");
    if !text(compression, "rejected_values").contains("Zstd is unreachable") {
        return Err("compression helper must retain the Zstd gap".to_owned());
    }
    let reset = find_row(helpers, "semantic_id", "KPR-HLP-002");
    if !text(reset, "success_outcome").contains("otherwise reset is a no-op") {
        return Err("deterministic broker reset semantics drifted".to_owned());
    }
    let lock = find_row(helpers, "semantic_id", "KPR-HLP-003");
    if text(lock, "source_anchor") != "src/messaging/kafka.rs:761-782"
        || !text(lock, "success_outcome").contains("Returns guard")
        || !text(lock, "shutdown_rule").contains("Guard drop resets")
        || !text(lock, "resource_bound").contains("BTreeMap clear removes entries")
        || !text(lock, "resource_bound").contains("no secure-erasure guarantee")
    {
        return Err("deterministic broker lock-guard semantics drifted".to_owned());
    }
    let parsed_error = find_row(helpers, "semantic_id", "KPR-HLP-006");
    for marker in [
        "2..=10 Broker(message)",
        "size=code*100",
        "61..=70 Cancelled",
        "71..=255 Protocol(unknown error code: {code})",
    ] {
        if !text(parsed_error, "success_outcome").contains(marker) {
            return Err(format!("Kafka error parser mapping lost {marker}"));
        }
    }
    let parsed_metadata = find_row(helpers, "semantic_id", "KPR-HLP-007");
    for marker in [
        "big-endian offset and partition",
        "timestamp_low*1000",
        "big-endian u16 topic length",
        "all remaining suffix bytes when truncated",
        "16 or 17 total bytes use topic default",
    ] {
        if !text(parsed_metadata, "success_outcome").contains(marker) {
            return Err(format!("Kafka metadata parser mapping lost {marker}"));
        }
    }

    let absences = array(matrix, "explicit_absences");
    let expected_absence_ids = expected_set(&["KAFKA-ABS-001", "KAFKA-ABS-002"]);
    if absences.len() != 2 || row_ids(absences, "absence_id") != expected_absence_ids {
        return Err("explicit absence set drifted".to_owned());
    }
    let offsets = find_row(absences, "absence_id", "KAFKA-ABS-001");
    if text(offsets, "shipped_state") != "ABSENT_NOT_PARITY"
        || text(offsets, "disposition_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.12.5"
        || text(offsets, "implementation_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.6.3"
        || text(offsets, "verification_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.13.3"
        || !text(offsets, "no_claim").contains("not consume-process-produce exactly-once")
    {
        return Err("transactional offset absence must remain explicit".to_owned());
    }
    let admin = find_row(absences, "absence_id", "KAFKA-ABS-002");
    if text(admin, "shipped_state") != "ABSENT_NOT_PARITY"
        || text(admin, "disposition_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.12.5"
        || text(admin, "api_contract_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.10.1"
        || text(admin, "implementation_owner_state") != "NOT_ALLOCATED_PENDING_API_DISPOSITION"
        || text(admin, "verification_owner") != "asupersync-dep-p7-kafka-removal-sarszu.2.12.5"
        || admin.get("implementation_owner").is_some()
        || !text(admin, "no_claim").contains("does not invent")
    {
        return Err("admin absence must remain explicit and uninvented".to_owned());
    }
    Ok(())
}

fn validate_shared_semantics_and_findings(matrix: &Value) -> Result<(), String> {
    let shared = object(matrix, "shared_semantics");
    for (key, marker) in [
        ("manual_commit_default", "defaults false"),
        ("auto_commit_opt_in", "before returning"),
        ("idempotence", "forces broker enable.idempotence=true"),
        ("caller_driven_rebalance", "caller"),
        ("remote_plaintext_policy", "debug_assertions"),
        ("secret_redaction", "without zeroization"),
        ("no_feature_lane", "release test-internals"),
        ("error_taxonomy", "no stable ASUP-Exxx"),
        ("cancellation_model", "ambiguous"),
        ("shutdown_model", "cannot retry cleanup"),
        ("resource_model", "max_poll_records is inert"),
        ("observability_model", "stderr"),
    ] {
        let value = shared
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("shared_semantics.{key} must be text"))?;
        if !value.contains(marker) {
            return Err(format!("shared_semantics.{key} must retain {marker}"));
        }
    }
    for (key, marker) in [
        ("remote_plaintext_policy", "IPv4-mapped IPv6"),
        ("remote_plaintext_policy", "first ]"),
        ("error_taxonomy", "MessageProduction QueueFull"),
        ("error_taxonomy", "ClientCreation or Subscription"),
        ("error_taxonomy", "Broker: Authentication failed"),
    ] {
        let value = shared
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("shared_semantics.{key} must be text"))?;
        if !value.contains(marker) {
            return Err(format!("shared_semantics.{key} must retain {marker}"));
        }
    }

    let findings = array(matrix, "routed_findings");
    let expected_finding_ids: BTreeSet<String> = (1..=23)
        .map(|number| format!("KAFKA-K0-2-GAP-{number:02}"))
        .collect();
    if findings.len() != 23 || row_ids(findings, "finding_id") != expected_finding_ids {
        return Err("routed finding ID set drifted".to_owned());
    }
    let allowed_owners = expected_set(ALLOWED_GAP_OWNERS);
    for finding in findings {
        let owners = array(finding, "owner_beads");
        let owner_set: BTreeSet<String> = owners
            .iter()
            .map(|owner| string_value(owner, "finding owner"))
            .collect();
        if text(finding, "state") != "ROUTED"
            || owners.is_empty()
            || owners.len() != owner_set.len()
            || owner_set
                .iter()
                .any(|owner| !allowed_owners.contains(owner))
        {
            return Err(format!(
                "{} must be routed to exact owners",
                text(finding, "finding_id")
            ));
        }
    }
    let profile_correction = find_row(findings, "finding_id", "KAFKA-K0-2-GAP-01");
    if !string_set(profile_correction, "owner_beads").contains("asupersync-z2kt29") {
        return Err("workspace test profile correction must retain its live owner".to_owned());
    }
    let recovery_race = find_row(findings, "finding_id", "KAFKA-K0-2-GAP-17");
    if !text(recovery_race, "finding").contains("admit multiple transaction handles")
        || !text(recovery_race, "finding").contains("leave Idle while a handle remains active")
        || !text(recovery_race, "finding").contains("mixed finalization")
        || !text(recovery_race, "finding").contains("poison the winner's Finalizing")
    {
        return Err("transaction recovery race finding drifted".to_owned());
    }
    let shared_poll_slot = find_row(findings, "finding_id", "KAFKA-K0-2-GAP-18");
    if !text(shared_poll_slot, "finding").contains("transfer")
        || !text(shared_poll_slot, "finding").contains("overwrite")
        || !text(shared_poll_slot, "finding").contains("auto-commit offset")
    {
        return Err("shared poll-slot finding drifted".to_owned());
    }
    for (id, markers) in [
        (
            "KAFKA-K0-2-GAP-19",
            [
                "uncapped pending SegQueue",
                "shutdown enqueue rejection",
                "256",
            ],
        ),
        (
            "KAFKA-K0-2-GAP-20",
            [
                "without an ordering fence",
                "older buffered snapshot",
                "revoked",
            ],
        ),
        (
            "KAFKA-K0-2-GAP-21",
            [
                "rejected configuration value",
                "without redaction",
                "plaintext credentials",
            ],
        ),
        (
            "KAFKA-K0-2-GAP-22",
            ["not reset", "modulo", "prior polling history"],
        ),
        (
            "KAFKA-K0-2-GAP-23",
            [
                "phase Active",
                "no handle or Drop hook",
                "no public recovery path",
            ],
        ),
    ] {
        let finding = find_row(findings, "finding_id", id);
        for marker in markers {
            if !text(finding, "finding").contains(marker) {
                return Err(format!("{id} lost {marker}"));
            }
        }
    }
    Ok(())
}

fn validate_coverage_receipt_and_docs(matrix: &Value) -> Result<(), String> {
    let model_value = matrix
        .get("coverage_model")
        .ok_or_else(|| "coverage_model must exist".to_owned())?;
    let model = object(matrix, "coverage_model");
    for (key, expected) in [
        ("exact_unique_public_method_count", 96),
        ("reachable_trait_operation_count", 3),
        ("total_public_entry_point_count", 99),
        ("configuration_field_count", 43),
        ("enum_semantic_count", 7),
        ("operation_row_count", 38),
        ("callable_helper_count", 9),
        ("explicit_absence_count", 2),
        ("routed_finding_count", 23),
        ("profile_disposition_group_count", 17),
        ("profile_semantic_row_count", 97),
    ] {
        if model.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("coverage_model.{key} must be {expected}"));
        }
    }
    let required_keys: BTreeSet<String> = array(model_value, "row_required_keys")
        .iter()
        .map(|value| string_value(value, "row_required_keys entry"))
        .collect();
    if required_keys != expected_set(REQUIRED_ROW_KEYS) {
        return Err("coverage model required-key set drifted".to_owned());
    }

    let receipt_value = matrix
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt must exist".to_owned())?;
    let receipt = object(matrix, "coverage_receipt");
    for key in [
        "configuration_ids_unique",
        "enum_ids_unique",
        "operation_ids_unique",
        "helper_ids_unique",
        "public_methods_exactly_once",
        "configuration_fields_exactly_once",
    ] {
        if receipt.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("coverage_receipt.{key} must be true"));
        }
    }
    for key in [
        "implicit_operation_rows",
        "unowned_semantic_rows",
        "unknown_rows",
    ] {
        if !array(receipt_value, key).is_empty() {
            return Err(format!("coverage_receipt.{key} must be empty"));
        }
    }
    if receipt
        .get("creation_session_validation_mode")
        .and_then(Value::as_str)
        != Some("STATIC_INSPECTION_ONLY")
        || receipt
            .get("contract_source_execution_claimed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .get("contract_execution_evidence")
            .and_then(Value::as_str)
            != Some("NOT_RECORDED_IN_THIS_ARTIFACT")
    {
        return Err("creation-session execution evidence must remain honest".to_owned());
    }

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        ARTIFACT_PATH,
        BEAD_ID,
        "src/runtime/spawn_blocking.rs",
        "src/runtime/blocking_pool.rs",
        "43",
        "96",
        "Total explicit public entry points | 99",
        "Routed semantic findings | 23",
        "23 routed owned gaps",
        "Manual commit is the default",
        "caller-driven",
        "release `test-internals`",
        "Kafka is unavailable: the `kafka` cargo feature is not enabled in this build",
        "WARNING: publishing to critical topic",
        "Transactional consumer-offset enrollment is absent",
        "administration",
        "has not been executed",
        "does not prove compilation",
        "does not permit removing `rdkafka`",
    ] {
        if !docs.contains(marker) {
            return Err(format!("documentation must contain {marker}"));
        }
    }
    if docs.matches(DOC_BEGIN).count() != 1 || docs.matches(DOC_END).count() != 1 {
        return Err("documentation markers must occur exactly once".to_owned());
    }
    Ok(())
}

fn validate_no_claim_boundaries(matrix: &Value) -> Result<(), String> {
    let claims: Vec<&str> = array(matrix, "no_claim_boundaries")
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("no_claim_boundaries entries must be text"))
        })
        .collect();
    if claims.len() < 8 {
        return Err("no-claim boundary is too narrow".to_owned());
    }
    let joined = claims.join(" ");
    for marker in [
        "incumbent semantics only",
        "does not prove compilation",
        "broker interoperability",
        "cancellation correctness",
        "release readiness",
        "deterministic broker or parser hooks as Kafka parity",
        "missing transactional consumer offsets",
        "does not permit removing rdkafka",
        "no Cargo, RCH, broker, fuzz, runtime, or network execution evidence",
    ] {
        if !joined.contains(marker) {
            return Err(format!("no-claim boundary must contain {marker}"));
        }
    }
    Ok(())
}

#[test]
fn kafka_incumbent_semantics_matrix_contract() -> Result<(), String> {
    let matrix = artifact();
    validate_identity_and_authority(&matrix)?;
    validate_source_pins(&matrix)?;
    validate_source_anchors(&matrix)?;
    validate_configuration_coverage(&matrix)?;
    validate_enum_and_operation_rows(&matrix)?;
    validate_public_method_coverage(&matrix)?;
    validate_profile_dispositions(&matrix)?;
    validate_high_risk_semantics(&matrix)?;
    validate_helpers_and_absences(&matrix)?;
    validate_shared_semantics_and_findings(&matrix)?;
    validate_exact_owner_maps(&matrix)?;
    validate_coverage_receipt_and_docs(&matrix)?;
    validate_no_claim_boundaries(&matrix)?;
    Ok(())
}
