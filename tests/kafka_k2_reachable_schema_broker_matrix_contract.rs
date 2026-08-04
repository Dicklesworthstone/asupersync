//! Static fail-closed contract for the Kafka K2.1 reachability packet.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.2.2.1
//! Fixture: artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json
//!
//! This test reads checked-in bytes only. It does not compile a Kafka feature
//! profile, contact a broker, run a protocol session, or promote the blocked
//! packet into schema, interoperability, migration, or cutover evidence.

#![allow(dead_code, missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json";
const DOC_PATH: &str = "docs/kafka_k2_reachable_schema_broker_matrix.md";
const ARTIFACT_SHA256: &str =
    "104f56fe22fe537a9267bc8315a66b73a756fe26f4bb4681eb4f69b050739a43";
const DOC_SHA256: &str =
    "d669aa8f7d5d984ccf31a1366aa89b900abb2a3ddade534634bf13dffe9a6568";

const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->";
const DOC_END: &str = "<!-- END KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->";

const ROOT_KEYS: &[&str] = &[
    "adr_id",
    "artifact_id",
    "authority_inputs",
    "baseline_revision",
    "bead_id",
    "broker_profile_rows",
    "capability_id",
    "captured_date_utc",
    "completion_gaps",
    "coverage_receipt",
    "disposition",
    "error_projection_rows",
    "existing_probe_disposition",
    "explicit_non_reachable_rows",
    "external_authorities",
    "field_projection_rows",
    "header_contract",
    "incumbent_source_observations",
    "inventory_state",
    "no_claim_boundaries",
    "parent_bead_id",
    "policy",
    "program_id",
    "reachable_api_rows",
    "schema_source_rows",
    "schema_version",
    "static_validation_receipt",
];

const INPUT_PATHS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "artifacts/kafka_broker_fixture_provenance_matrix_v1.json",
    "artifacts/kafka_k1_aggregate_evidence_gate_v1.json",
    "artifacts/kafka_k1_protocol_security_support_policy_v1.json",
    "artifacts/kafka_k1_public_api_contract_v1.json",
    "src/messaging/kafka.rs",
    "src/messaging/kafka_consumer.rs",
];

const POLICY_FALSE_KEYS: &[&str] = &[
    "accepted_numeric_ranges",
    "field_projection_complete",
    "error_projection_complete",
    "oldest_broker_admitted",
    "current_broker_admitted",
    "schema_probe_executed",
    "k2_1_complete",
    "k2_2_unblocked",
    "production_wiring_authorized",
    "dependency_cutover_authorized",
];

const JOURNEY_CLASSES: &[&str] = &[
    "authentication",
    "connection",
    "consumer",
    "fetch",
    "group",
    "idempotence",
    "liveness",
    "negotiation",
    "offset",
    "producer",
    "rebalance",
    "recovery",
    "routing",
    "shutdown",
    "telemetry",
    "transaction",
];

const EXPECTED_APIS: &[(u64, &str, bool, u64, &str, &str, Option<u64>)] = &[
    (0, "Produce", true, 10, "3-13", "3-10", Some(9)),
    (1, "Fetch", true, 16, "4-18", "4-16", Some(12)),
    (2, "ListOffsets", true, 7, "1-11", "1-7", Some(6)),
    (3, "Metadata", true, 13, "0-13", "0-13", Some(9)),
    (8, "OffsetCommit", true, 9, "2-10", "2-9", Some(8)),
    (9, "OffsetFetch", true, 9, "1-10", "1-9", Some(6)),
    (10, "FindCoordinator", true, 2, "0-6", "0-2", Some(3)),
    (11, "JoinGroup", true, 5, "0-9", "0-5", Some(6)),
    (12, "Heartbeat", true, 3, "0-4", "0-3", Some(4)),
    (13, "LeaveGroup", true, 1, "0-5", "0-1", Some(4)),
    (14, "SyncGroup", true, 3, "0-5", "0-3", Some(4)),
    (17, "SaslHandshake", true, 1, "0-1", "0-1", None),
    (18, "ApiVersions", true, 3, "0-4", "0-3", Some(3)),
    (22, "InitProducerId", true, 4, "0-6", "0-4", Some(2)),
    (
        23,
        "OffsetForLeaderEpoch",
        true,
        2,
        "2-4",
        "2",
        Some(4),
    ),
    (24, "AddPartitionsToTxn", true, 0, "0-5", "0", Some(3)),
    (25, "AddOffsetsToTxn", true, 0, "0-4", "0", Some(3)),
    (26, "EndTxn", true, 1, "0-5", "0-1", Some(3)),
    (28, "TxnOffsetCommit", true, 3, "0-5", "0-3", Some(3)),
    (36, "SaslAuthenticate", true, 1, "0-2", "0-1", Some(2)),
    (
        71,
        "GetTelemetrySubscriptions",
        false,
        0,
        "0",
        "0",
        Some(0),
    ),
    (72, "PushTelemetry", false, 0, "0", "0", Some(0)),
];

const EXTERNAL_SOURCE_ROWS: &[(&str, &str, &str, &str)] = &[
    (
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "4.3.1",
        "a07059eb9b5bac1bfdbb1e74313f2fae4ca20fd9",
        "26b251a451ce941d3d7a55e6487bcb7f16b5ad48",
    ),
    (
        "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        "0.8.0",
        "2c20a71a010659e25af075a024cbd692c87d4c89",
        "15bb3961d9171c1c54c4c840a554ce2c76168163",
    ),
    (
        "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        "0.11.0.2",
        "fac05f594ad98cff6508400a9b572c0966997469",
        "73be1e1168f91ee2a9d68e1d1c75c14018cf7d3a",
    ),
    (
        "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        "1.0.0",
        "3ed24acba855ec00d4c0323a7aaf1fac1d8f99d4",
        "aaa7af6d4a11b29d3da9c5d6084530b8fa69be64",
    ),
];

const NON_REACHABLE_ROWS: &[(&str, &[u64], &str, &str, &str)] = &[
    (
        "KAFKA-K2-1-NONREACH-ADMIN",
        &[],
        "ADMIN_FACADE",
        "DEFERRED_TO_K10_1",
        "ABSENT_NOT_PARITY",
    ),
    (
        "KAFKA-K2-1-NONREACH-CONSUMER-GROUP-PROTOCOL",
        &[68],
        "CURRENT_CONSUMER_CONFIGURATION",
        "EXACT",
        "NOT_REACHABLE_FROM_ACCEPTED_CURRENT_CONFIG",
    ),
    (
        "KAFKA-K2-1-NONREACH-CONSUMER-GROUP-DESCRIBE",
        &[69],
        "ADMIN_FACADE",
        "EXACT",
        "ABSENT_NOT_PARITY",
    ),
];

const INCUMBENT_OBSERVATIONS: &[(&str, u64, u64, &str)] = &[
    (
        "librdkafka/INTRODUCTION.md",
        130_924,
        2_481,
        "299579b2e96e02e7117188ad314f904fc229b9e304f709ab0893a4f6ffa9655a",
    ),
    (
        "librdkafka/src/rdkafka_request.c",
        291_398,
        7_089,
        "0b265bf870e735b4c288647924ce5352e8f1828c2965702cd40bfaf8b848d46b",
    ),
    (
        "librdkafka/src/rdkafka_broker.c",
        250_967,
        6_337,
        "228271f55ba611c93c4507e3f8be3e2fdc8510196370c45b85f58ddfcd58a19b",
    ),
    (
        "librdkafka/src/rdkafka_telemetry.c",
        31_372,
        760,
        "6ad27c01ae0dc41a038ec03b2433006df1e47f0a74cbf7605c22b03cf82ca2a9",
    ),
    (
        "librdkafka/src/rdkafka_conf.c",
        211_291,
        4_880,
        "14d379fcc6744d2677cea5e6b21aea2585b08f702d83a52f9f8c2a0469493c15",
    ),
    (
        "librdkafka/src/rdkafka_feature.c",
        30_329,
        898,
        "7905d821c02f60166dccf3526160af023da1994127fff44cb19f92a782e7fe4d",
    ),
    (
        "librdkafka/src/rdkafka_protocol.h",
        5_625,
        128,
        "2960180d0082b2ad36db9536f395c82c5dfbcaed802ce3034388a0b189e15808",
    ),
    (
        "librdkafka/src/rdkafka_cgrp.c",
        309_960,
        7_587,
        "003f551029dfd756b567e1f89bd95b98f772c7739a104836ee9d6600da2bf7f6",
    ),
    (
        "librdkafka/src/rdkafka_txnmgr.c",
        126_637,
        3_256,
        "bee7f3cad8926bc2eb458cf3e008601a42cd03ff34494ea95a3f5dd9751c6ebd",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parse_artifact() -> Result<Value, String> {
    serde_json::from_str(include_str!(
        "../artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json"
    ))
    .map_err(|error| format!("invalid JSON in {ARTIFACT_PATH}: {error}"))
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
        Err(format!(
            "{key} mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn expect_boolean(value: &Value, key: &str, expected: bool) -> Result<(), String> {
    let actual = boolean(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{key} mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn numeric_array(value: &Value, key: &str) -> Result<Vec<u64>, String> {
    array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .ok_or_else(|| format!("{key} entries must be unsigned integers"))
        })
        .collect()
}

fn validate_identity_and_policy(artifact: &Value) -> Result<(), String> {
    let object = artifact
        .as_object()
        .ok_or_else(|| "artifact root must be an object".to_owned())?;
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_keys = ROOT_KEYS.iter().copied().collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(format!(
            "root keys mismatch: expected {expected_keys:?}, got {actual_keys:?}"
        ));
    }

    expect_text(
        artifact,
        "artifact_id",
        "kafka-k2-reachable-schema-broker-matrix-v1",
    )?;
    expect_number(artifact, "schema_version", 1)?;
    expect_text(
        artifact,
        "bead_id",
        "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
    )?;
    expect_text(artifact, "program_id", "dependency-sovereignty-rev5")?;
    expect_text(artifact, "captured_date_utc", "2026-08-04")?;
    expect_text(
        artifact,
        "baseline_revision",
        "00baf573d2bc6fcae461a74dc37c78d205dec8fd",
    )?;
    expect_text(
        artifact,
        "parent_bead_id",
        "asupersync-dep-p7-kafka-removal-sarszu.2.2",
    )?;
    expect_text(artifact, "capability_id", "CAP-KAFKA")?;
    expect_text(artifact, "adr_id", "DEP-ADR-009")?;
    expect_text(
        artifact,
        "inventory_state",
        "STATIC_REACHABILITY_FRONTIER_FROZEN_SCHEMA_AND_BROKER_PROOF_BLOCKED",
    )?;
    expect_text(artifact, "disposition", "KEEP_INCUMBENT_BLOCK_K2_2")?;

    let policy = artifact
        .get("policy")
        .ok_or_else(|| "policy must exist".to_owned())?;
    let policy_keys = policy
        .as_object()
        .ok_or_else(|| "policy must be an object".to_owned())?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_policy_keys = POLICY_FALSE_KEYS.iter().copied().collect::<BTreeSet<_>>();
    if policy_keys != expected_policy_keys {
        return Err("policy keys changed".to_owned());
    }
    for key in POLICY_FALSE_KEYS {
        expect_boolean(policy, key, false)?;
    }
    Ok(())
}

fn validate_authority_inputs(artifact: &Value, root: &Path) -> Result<(), String> {
    let inputs = array(artifact, "authority_inputs")?;
    if inputs.len() != INPUT_PATHS.len() {
        return Err(format!(
            "expected {} authority inputs, got {}",
            INPUT_PATHS.len(),
            inputs.len()
        ));
    }

    let actual_paths = inputs
        .iter()
        .map(|row| text(row, "path").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_paths = INPUT_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        return Err(format!(
            "authority input paths mismatch: expected {expected_paths:?}, got {actual_paths:?}"
        ));
    }

    for row in inputs {
        let path = text(row, "path")?;
        let bytes = fs::read(root.join(path))
            .map_err(|error| format!("failed to read {path}: {error}"))?;
        let byte_count = u64::try_from(bytes.len())
            .map_err(|error| format!("byte count overflow for {path}: {error}"))?;
        let record_count = u64::try_from(String::from_utf8_lossy(&bytes).lines().count())
            .map_err(|error| format!("record count overflow for {path}: {error}"))?;
        expect_number(row, "byte_count", byte_count)?;
        expect_number(row, "record_count", record_count)?;
        expect_text(row, "sha256", &sha256_bytes(&bytes))?;
        let _ = text(row, "authority_class")?;
    }
    Ok(())
}

fn validate_external_authorities(artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "external_authorities")?;
    if rows.len() != 5 {
        return Err(format!("expected five external authorities, got {}", rows.len()));
    }

    for (authority_id, tag, tag_object, commit) in EXTERNAL_SOURCE_ROWS {
        let row = rows
            .iter()
            .find(|row| row.get("authority_id").and_then(Value::as_str) == Some(*authority_id))
            .ok_or_else(|| format!("missing external authority {authority_id}"))?;
        expect_text(row, "repository", "https://github.com/apache/kafka.git")?;
        expect_text(row, "tag", tag)?;
        expect_text(row, "tag_object", tag_object)?;
        expect_text(row, "commit", commit)?;
    }

    let incumbent = rows
        .iter()
        .find(|row| {
            row.get("authority_id").and_then(Value::as_str)
                == Some("KAFKA-K2-1-AUTH-LIBRDKAFKA-2-12-1")
        })
        .ok_or_else(|| "missing pinned incumbent authority".to_owned())?;
    expect_text(incumbent, "package", "rdkafka-sys 4.10.0+2.12.1")?;
    expect_text(incumbent, "native_version", "2.12.1")?;
    expect_text(
        incumbent,
        "package_checksum",
        "e234cf318915c1059d4921ef7f75616b5219b10b46e9f3a511a15eb4b56a3f77",
    )?;
    Ok(())
}

fn validate_incumbent_observations(artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "incumbent_source_observations")?;
    if rows.len() != INCUMBENT_OBSERVATIONS.len() {
        return Err(format!(
            "expected {} incumbent observations, got {}",
            INCUMBENT_OBSERVATIONS.len(),
            rows.len()
        ));
    }
    for (path, bytes, records, sha256) in INCUMBENT_OBSERVATIONS {
        let row = rows
            .iter()
            .find(|row| row.get("package_relative_path").and_then(Value::as_str) == Some(*path))
            .ok_or_else(|| format!("missing incumbent observation {path}"))?;
        expect_number(row, "byte_count", *bytes)?;
        expect_number(row, "record_count", *records)?;
        expect_text(row, "sha256", sha256)?;
        let _ = text(row, "semantic_role")?;
    }
    Ok(())
}

fn validate_reachable_rows(artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "reachable_api_rows")?;
    if rows.len() != EXPECTED_APIS.len() {
        return Err(format!(
            "expected {} reachable APIs, got {}",
            EXPECTED_APIS.len(),
            rows.len()
        ));
    }

    let actual_keys = rows
        .iter()
        .map(|row| number(row, "api_key"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_keys = EXPECTED_APIS
        .iter()
        .map(|row| row.0)
        .collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(format!(
            "reachable API keys mismatch: expected {expected_keys:?}, got {actual_keys:?}"
        ));
    }
    let row_ids = rows
        .iter()
        .map(|row| text(row, "row_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if row_ids.len() != EXPECTED_APIS.len() {
        return Err("reachable API row IDs must be unique".to_owned());
    }
    let allowed_journeys = JOURNEY_CLASSES.iter().copied().collect::<BTreeSet<_>>();

    for (api_key, name, k1_seed, client_max, valid, intersection, flex_first) in
        EXPECTED_APIS
    {
        let row = rows
            .iter()
            .find(|row| row.get("api_key").and_then(Value::as_u64) == Some(*api_key))
            .ok_or_else(|| format!("missing API key {api_key}"))?;
        expect_text(row, "api_name", name)?;
        expect_boolean(row, "k1_seed", *k1_seed)?;
        let expected_client_min = if *api_key == 23 { 2 } else { 0 };
        expect_number(row, "librdkafka_client_min", expected_client_min)?;
        expect_number(row, "librdkafka_client_max", *client_max)?;
        expect_text(row, "apache_4_3_1_valid_versions", valid)?;
        expect_text(row, "candidate_current_intersection", intersection)?;
        let (expected_reachability, expected_probe) = match *api_key {
            17 | 36 => ("CURRENT_EXPLICIT_BLOCKED_NATIVE_CAPABILITY", "BLOCKED_EXTERNAL"),
            25 | 28 => ("REQUIRED_ADDITIVE_ABSENT", "BLOCKED_NOT_SHIPPED"),
            71 | 72 => ("CURRENT_IMPLICIT_DEFAULT_TELEMETRY", "NOT_RUN"),
            _ => ("CURRENT_EXPLICIT", "NOT_RUN"),
        };
        expect_text(row, "reachability_class", expected_reachability)?;
        expect_text(row, "broker_probe_state", expected_probe)?;
        let journeys = array(row, "journey_classes")?;
        if journeys.is_empty() {
            return Err(format!("API key {api_key} has no journey class"));
        }
        for journey in journeys {
            let journey = journey
                .as_str()
                .ok_or_else(|| format!("API key {api_key} journey class must be text"))?;
            if !allowed_journeys.contains(journey) {
                return Err(format!("API key {api_key} has unknown journey class {journey:?}"));
            }
        }
        if row.get("accepted_version_range") != Some(&Value::Null) {
            return Err(format!("API key {api_key} acquired an accepted range"));
        }

        match flex_first {
            Some(expected) => expect_number(row, "flexible_version_first", *expected)?,
            None if row.get("flexible_version_first") == Some(&Value::Null) => {}
            None => return Err(format!("API key {api_key} flexible threshold changed")),
        }

        let reaches_flexible = flex_first.is_some_and(|first| first <= *client_max);
        let expected_request_headers: &[u64] = if reaches_flexible { &[1, 2] } else { &[1] };
        let expected_response_headers: &[u64] =
            if *api_key == 18 || !reaches_flexible { &[0] } else { &[0, 1] };
        if numeric_array(row, "candidate_request_header_versions")?.as_slice()
            != expected_request_headers
        {
            return Err(format!("API key {api_key} request header selection changed"));
        }
        if numeric_array(row, "candidate_response_header_versions")?.as_slice()
            != expected_response_headers
        {
            return Err(format!("API key {api_key} response header selection changed"));
        }
        expect_text(
            row,
            "schema_projection_state",
            "SOURCE_SELECTED_FIELDS_NOT_PROJECTED",
        )?;
    }

    let telemetry = rows
        .iter()
        .filter(|row| matches!(row.get("api_key").and_then(Value::as_u64), Some(71) | Some(72)))
        .collect::<Vec<_>>();
    if telemetry.len() != 2 {
        return Err("telemetry reachability rows are incomplete".to_owned());
    }
    for row in telemetry {
        expect_boolean(row, "k1_seed", false)?;
        expect_text(
            row,
            "reachability_class",
            "CURRENT_IMPLICIT_DEFAULT_TELEMETRY",
        )?;
    }
    Ok(())
}

fn validate_schema_sources(artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "schema_source_rows")?;
    if rows.len() != EXPECTED_APIS.len() {
        return Err(format!(
            "expected {} schema pairs, got {}",
            EXPECTED_APIS.len(),
            rows.len()
        ));
    }
    let keys = rows
        .iter()
        .map(|row| number(row, "api_key"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = EXPECTED_APIS.iter().map(|row| row.0).collect::<BTreeSet<_>>();
    if keys != expected {
        return Err("schema pair keys do not match the reachability frontier".to_owned());
    }
    for (api_key, name, ..) in EXPECTED_APIS {
        let row = rows
            .iter()
            .find(|row| row.get("api_key").and_then(Value::as_u64) == Some(*api_key))
            .ok_or_else(|| format!("missing schema pair for API key {api_key}"))?;
        let request = format!("clients/src/main/resources/common/message/{name}Request.json");
        let response = format!("clients/src/main/resources/common/message/{name}Response.json");
        expect_text(row, "request_path", &request)?;
        expect_text(row, "response_path", &response)?;
    }
    Ok(())
}

fn validate_blocked_evidence(artifact: &Value) -> Result<(), String> {
    if !array(artifact, "field_projection_rows")?.is_empty()
        || !array(artifact, "error_projection_rows")?.is_empty()
    {
        return Err("partial field or error projections must not masquerade as closure".to_owned());
    }

    let header = artifact
        .get("header_contract")
        .ok_or_else(|| "header_contract must exist".to_owned())?;
    if numeric_array(header, "reachable_request_header_versions_in_22_row_frontier")? != [1, 2]
        || numeric_array(header, "reachable_response_header_versions_in_22_row_frontier")?
            != [0, 1]
    {
        return Err("header frontier changed".to_owned());
    }
    expect_text(
        header,
        "selection_state",
        "CANDIDATE_SCHEMA_DERIVED_NOT_ACCEPTED",
    )?;
    expect_text(
        header,
        "api_versions_response_header_exception",
        "ApiVersions flexible bodies retain response header v0 for backward compatibility",
    )?;

    let non_reachable = array(artifact, "explicit_non_reachable_rows")?;
    if non_reachable.len() != NON_REACHABLE_ROWS.len() {
        return Err(format!(
            "expected {} explicit non-reachable rows, got {}",
            NON_REACHABLE_ROWS.len(),
            non_reachable.len()
        ));
    }
    for (row_id, api_keys, surface_scope, enumeration_state, state) in NON_REACHABLE_ROWS {
        let row = non_reachable
            .iter()
            .find(|row| row.get("row_id").and_then(Value::as_str) == Some(*row_id))
            .ok_or_else(|| format!("missing explicit non-reachable row {row_id}"))?;
        if numeric_array(row, "api_keys")?.as_slice() != *api_keys {
            return Err(format!("non-reachable API keys changed for {row_id}"));
        }
        expect_text(row, "surface_scope", surface_scope)?;
        expect_text(row, "enumeration_state", enumeration_state)?;
        expect_text(row, "state", state)?;
        let _ = text(row, "reason")?;
    }

    let brokers = array(artifact, "broker_profile_rows")?;
    if brokers.len() != 4 {
        return Err(format!("expected four blocked broker profiles, got {}", brokers.len()));
    }
    let versions = brokers
        .iter()
        .map(|row| text(row, "candidate_version").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_versions = ["0.8.0", "0.11.0.2", "1.0.0", "4.3.1"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if versions != expected_versions {
        return Err("broker candidate versions changed".to_owned());
    }
    for row in brokers {
        expect_text(row, "state", "BLOCKED_EXTERNAL")?;
        if row.get("immutable_runtime_identity") != Some(&Value::Null)
            || row.get("schema_probe_receipt") != Some(&Value::Null)
        {
            return Err("a broker profile was admitted without terminal evidence".to_owned());
        }
    }

    let probe = artifact
        .get("existing_probe_disposition")
        .ok_or_else(|| "existing_probe_disposition must exist".to_owned())?;
    expect_text(
        probe,
        "path",
        "scripts/kafka_broker_parity_proof_runner.sh",
    )?;
    expect_text(probe, "classification", "PROOF_ONLY_NONTERMINAL")?;
    expect_boolean(probe, "executed_for_k2_1", false)?;

    let gaps = array(artifact, "completion_gaps")?;
    if gaps.len() != 7 {
        return Err(format!("expected seven completion gaps, got {}", gaps.len()));
    }
    let gap_ids = gaps
        .iter()
        .map(|row| text(row, "gap_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if gap_ids.len() != 7 {
        return Err("completion gap IDs must be unique".to_owned());
    }
    Ok(())
}

fn validate_receipts_and_boundaries(artifact: &Value) -> Result<(), String> {
    let coverage = artifact
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt must exist".to_owned())?;
    for (key, expected) in [
        ("k1_seed_api_count", 20),
        ("added_implicit_api_count", 2),
        ("reachable_frontier_api_count", 22),
        ("schema_source_pair_count", 22),
        ("accepted_numeric_range_count", 0),
        ("field_projection_row_count", 0),
        ("error_projection_row_count", 0),
        ("admitted_broker_profile_count", 0),
        ("schema_probe_receipt_count", 0),
        ("completion_gap_count", 7),
    ] {
        expect_number(coverage, key, expected)?;
    }

    let validation = artifact
        .get("static_validation_receipt")
        .ok_or_else(|| "static_validation_receipt must exist".to_owned())?;
    expect_text(validation, "execution_scope", "STATIC_ONLY")?;
    for key in [
        "compiler_run",
        "formatter_run",
        "test_run",
        "broker_contacted",
        "service_started",
        "remote_job_started",
    ] {
        expect_boolean(validation, key, false)?;
    }

    let boundaries = array(artifact, "no_claim_boundaries")?;
    let joined = boundaries
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "not a complete Kafka request/response schema contract",
        "not accepted production version ranges",
        "No field, default, nullability, tagged-field, or error-code projection is complete",
        "No compiler, formatter, test, broker, service, container, network protocol, or remote execution evidence is claimed",
        "does not authorize K2.2",
    ] {
        if !joined.contains(needle) {
            return Err(format!("missing no-claim boundary containing {needle:?}"));
        }
    }
    Ok(())
}

fn validate_document(root: &Path) -> Result<(), String> {
    let document = fs::read_to_string(root.join(DOC_PATH))
        .map_err(|error| format!("failed to read {DOC_PATH}: {error}"))?;
    if document.matches(DOC_BEGIN).count() != 1 || document.matches(DOC_END).count() != 1 {
        return Err("document markers must each occur exactly once".to_owned());
    }
    for needle in [
        "static 22-key reachability frontier",
        "GetTelemetrySubscriptions",
        "PushTelemetry",
        "no numeric range is accepted",
        "K2.2 therefore remains blocked",
        "The packet does not prove schema completeness",
    ] {
        if !document.contains(needle) {
            return Err(format!("document is missing {needle:?}"));
        }
    }
    Ok(())
}

fn validate_checked_in_hashes(root: &Path) -> Result<(), String> {
    for (path, expected) in [
        (ARTIFACT_PATH, ARTIFACT_SHA256),
        (DOC_PATH, DOC_SHA256),
    ] {
        let bytes =
            fs::read(root.join(path)).map_err(|error| format!("failed to read {path}: {error}"))?;
        let actual = sha256_bytes(&bytes);
        if actual != expected {
            return Err(format!(
                "{path} hash mismatch: expected {expected}, got {actual}"
            ));
        }
    }
    Ok(())
}

fn validate_artifact(artifact: &Value, root: &Path) -> Result<(), String> {
    validate_identity_and_policy(artifact)?;
    validate_authority_inputs(artifact, root)?;
    validate_external_authorities(artifact)?;
    validate_incumbent_observations(artifact)?;
    validate_reachable_rows(artifact)?;
    validate_schema_sources(artifact)?;
    validate_blocked_evidence(artifact)?;
    validate_receipts_and_boundaries(artifact)?;
    Ok(())
}

fn expect_invalid(artifact: &Value, root: &Path, label: &str) -> Result<(), String> {
    if validate_artifact(artifact, root).is_err() {
        Ok(())
    } else {
        Err(format!("mutation {label} unexpectedly validated"))
    }
}

#[test]
fn kafka_k2_static_frontier_is_exact_and_fail_closed() -> Result<(), String> {
    let root = repo_root();
    let artifact = parse_artifact()?;
    validate_checked_in_hashes(&root)?;
    validate_artifact(&artifact, &root)?;
    validate_document(&root)
}

#[test]
fn kafka_k2_packet_rejects_completion_inflation() -> Result<(), String> {
    let root = repo_root();
    let artifact = parse_artifact()?;

    let mut missing_telemetry = artifact.clone();
    let rows = missing_telemetry
        .get_mut("reachable_api_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "reachable_api_rows mutation target missing".to_owned())?;
    rows.retain(|row| row.get("api_key").and_then(Value::as_u64) != Some(72));
    expect_invalid(&missing_telemetry, &root, "missing telemetry API")?;

    let mut invented_range = artifact.clone();
    let first_api = invented_range
        .get_mut("reachable_api_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "reachable API mutation target missing".to_owned())?;
    first_api.insert("accepted_version_range".to_owned(), Value::String("3-10".to_owned()));
    expect_invalid(&invented_range, &root, "invented accepted range")?;

    let mut admitted_broker = artifact.clone();
    let first_broker = admitted_broker
        .get_mut("broker_profile_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "broker mutation target missing".to_owned())?;
    first_broker.insert("state".to_owned(), Value::String("ADMITTED".to_owned()));
    expect_invalid(&admitted_broker, &root, "broker admission without receipt")?;

    let mut unblocked_child = artifact;
    let policy = unblocked_child
        .get_mut("policy")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "policy mutation target missing".to_owned())?;
    policy.insert("k2_2_unblocked".to_owned(), Value::Bool(true));
    expect_invalid(&unblocked_child, &root, "premature K2.2 authorization")
}
