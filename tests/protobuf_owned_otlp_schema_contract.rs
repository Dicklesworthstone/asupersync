//! Fail-closed contract for the finite owned OTLP protobuf schema authority.
//!
//! Bead: asupersync-5z2scg.1.3
//! Fixture: `artifacts/protobuf_owned_otlp_schema_v1.json`
//!
//! This test freezes the reviewed v1.10.0 schema inventory, its resource and
//! evolution policy, live repository pins, operator documentation, and the
//! boundary that keeps the public generic protobuf capability and incumbents.
//! It records the complete private 43-message
//! common/resource/metrics/trace/logs/collector source slice plus a native
//! library typecheck without claiming unit-test execution, wire parity,
//! interoperability, collector contact, production wiring, or dependency
//! removal.

#![allow(missing_docs)]
// The verification matrix owns these exact double-underscore test prefixes.
#![allow(non_snake_case)]

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/protobuf_owned_otlp_schema_v1.json";
const DOC_PATH: &str = "docs/protobuf_owned_otlp_schema.md";
const ARTIFACT_SHA256: &str = "86dfc597e681a8d71ff67d1554284d4d8e32da8043e8f6054e2c45392ca2eb5f";
const DOC_SHA256: &str = "17360f46fff6ba94487780ce5e5b692c5af80c3be19442cd5d89c0317fb2337f";
const SCHEMA_SIGNATURE_SHA256: &str =
    "2b9311b5c766da1b2fb88262aeb89e125c41f8ea4d8406e534a2e9b42839256b";
const ENUM_SIGNATURE_SHA256: &str =
    "b7183057aad8a555c3e163782b4d5e8df248194467444918e11f3aa8fc50d3f3";
const SERVICE_SIGNATURE_SHA256: &str =
    "47c499ae0dc4725b1232c814051228c889b6fd43145c618a4d7d1893ed93fde0";
const ORACLE_PIN_SIGNATURE_SHA256: &str =
    "f8d06b6ad60ce88a932eb3426a68007013ae428270159c57c1a889e46f333544";
const REPOSITORY_PIN_SIGNATURE_SHA256: &str =
    "eb5f2193b6ae6e029bf027d05e147a987b8ebe4d81127488680d1dee1753cb60";
const DOC_BEGIN: &str = "<!-- BEGIN PROTOBUF OWNED OTLP SCHEMA -->";
const DOC_END: &str = "<!-- END PROTOBUF OWNED OTLP SCHEMA -->";

const EXPECTED_PLANNED_MUTATIONS: [&str; 9] = [
    "remove one message family",
    "duplicate or renumber a tag",
    "change one wire kind or packed bit",
    "remove unknown fields from one message",
    "set one count or byte cap to zero/unbounded",
    "promote fuzz Cargo.lock 0.31.0 to authority",
    "label wrapper commit as upstream schema commit",
    "allow post-decode-only resource validation",
    "authorize public prost removal or transport cutover",
];

const EXPECTED_NO_CLAIMS: [&str; 10] = [
    "This packet records source, unit-test bodies, and a terminal native default-plus-metrics library check for the complete private 43-message common/resource/metrics/trace/logs/collector slice; it does not execute the unit tests.",
    "It does not represent any valid, malformed, resource, property, differential, or fuzz vector as passing evidence.",
    "It does not prove byte parity with opentelemetry-proto, another language, or a live collector.",
    "It does not wire metrics, traces, logs, partial-success responses, HTTP, gRPC, retry, cancellation, batching, or shutdown.",
    "It does not establish incumbent parity for the new A3 semantic limits; downstream adapters must prove chunking, rejection, or counted truncation per capability.",
    "It does not add opentelemetry-proto, tonic, tokio, or another runtime to a production graph.",
    "It adds only the recorded source-compatible generic protobuf authoring methods and non-exhaustive error variants; it adds no public OTLP schema type and removes or narrows no generic downstream capability, feature, target, persisted format, or user journey.",
    "It does not authorize removing prost, opentelemetry, opentelemetry_sdk, or any generated differential oracle.",
    "It does not authorize production cutover, transport integration, dependency retirement, or tracker closure.",
    "It does not prove performance, allocation, RSS, throughput, latency, broad workspace health, release readiness, live RCH fleet availability, local Cargo fallback approval, or permission to delete files.",
];

type ValidationResult<T = ()> = Result<T, String>;

struct UniqueJsonValue(Value);

struct UniqueJsonVisitor;

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON object key {key}")));
            }
            let UniqueJsonValue(value) = entries.next_value()?;
            values.insert(key, value);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

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

fn artifact() -> Value {
    parse_unique_json(&read_repo_bytes(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be strict JSON: {error}"))
}

fn parse_unique_json(bytes: &[u8]) -> ValidationResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJsonValue(value) = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|error| format!("invalid or ambiguous JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON input: {error}"))?;
    Ok(value)
}

fn object<'value>(value: &'value Value, key: &str) -> ValidationResult<&'value Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'value>(value: &'value Value, key: &str) -> ValidationResult<&'value [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'value>(value: &'value Value, key: &str) -> ValidationResult<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn unsigned(value: &Value, key: &str) -> ValidationResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> ValidationResult<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be boolean"))
}

fn optional_text<'value>(value: &'value Value, key: &str) -> ValidationResult<&'value str> {
    match value.get(key) {
        None | Some(Value::Null) => Ok("-"),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(format!("{key} must be text when present")),
    }
}

fn require_text(value: &Value, key: &str, expected: &str) -> ValidationResult {
    let actual = text(value, key)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, got {actual}"));
    }
    Ok(())
}

fn require_unsigned(value: &Value, key: &str, expected: u64) -> ValidationResult {
    let actual = unsigned(value, key)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, got {actual}"));
    }
    Ok(())
}

fn require_boolean(value: &Value, key: &str, expected: bool) -> ValidationResult {
    let actual = boolean(value, key)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, got {actual}"));
    }
    Ok(())
}

fn require_exact_keys(value: &Value, expected: &[&str], context: &str) -> ValidationResult {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{context} keys differ: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn require_allowed_keys(value: &Value, allowed: &[&str], context: &str) -> ValidationResult {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if !actual.is_subset(&allowed) {
        return Err(format!("{context} has unknown keys: {actual:?}"));
    }
    Ok(())
}

fn require_exact_field_keys(field: &Value, context: &str) -> ValidationResult {
    let metadata_keys = ["element_wire", "oneof", "presence"]
        .into_iter()
        .filter(|key| field.get(*key).is_some())
        .collect::<Vec<_>>();
    if metadata_keys.len() > 1 {
        return Err(format!(
            "{context} must have at most one metadata key, got {metadata_keys:?}"
        ));
    }

    let mut expected = vec!["tag", "name", "type", "cardinality", "wire", "packed"];
    if let Some(metadata_key) = metadata_keys.first() {
        text(field, metadata_key)?;
        expected.push(metadata_key);
    }
    require_exact_keys(field, &expected, context)
}

fn string_set(values: &[Value], key: &str) -> ValidationResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| text(value, key).map(str::to_owned))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn digest_rows(mut rows: Vec<String>) -> String {
    rows.sort_unstable();
    let mut canonical = rows.join("\n");
    canonical.push('\n');
    sha256_hex(canonical.as_bytes())
}

fn schema_signature(value: &Value) -> ValidationResult<String> {
    let mut rows = Vec::new();
    for family in array(value, "schema_families")? {
        let family_name = text(family, "family")?;
        for message in array(family, "messages")? {
            let message_name = text(message, "name")?;
            let mut reserved = array(message, "reserved_tags")?
                .iter()
                .map(|tag| {
                    tag.as_u64()
                        .ok_or_else(|| format!("{message_name} reserved tags must be unsigned"))
                })
                .collect::<ValidationResult<Vec<_>>>()?;
            reserved.sort_unstable();
            let reserved = reserved
                .into_iter()
                .map(|tag| tag.to_string())
                .collect::<Vec<_>>()
                .join(",");
            rows.push(format!(
                "M\t{family_name}\t{message_name}\t{reserved}\t{}",
                text(message, "unknown_fields")?
            ));
            for field in array(message, "fields")? {
                rows.push(format!(
                    "F\t{message_name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    unsigned(field, "tag")?,
                    text(field, "name")?,
                    text(field, "type")?,
                    text(field, "cardinality")?,
                    text(field, "wire")?,
                    boolean(field, "packed")?,
                    optional_text(field, "element_wire")?,
                    optional_text(field, "oneof")?,
                    optional_text(field, "presence")?,
                ));
            }
        }
    }
    Ok(digest_rows(rows))
}

fn enum_signature(value: &Value) -> ValidationResult<String> {
    let mut rows = Vec::new();
    for enum_row in array(value, "enum_contract")? {
        let name = text(enum_row, "name")?;
        let ((Some(unknown_policy), None) | (None, Some(unknown_policy))) = (
            enum_row.get("unknown_values").and_then(Value::as_str),
            enum_row.get("unknown_bits").and_then(Value::as_str),
        ) else {
            return Err(format!("{name} must have exactly one unknown-value policy"));
        };
        rows.push(format!(
            "E\t{name}\t{}\t{unknown_policy}",
            text(enum_row, "storage")?
        ));
        for (variant, number) in object(enum_row, "values")? {
            let number = number
                .as_i64()
                .ok_or_else(|| format!("{name}.{variant} must be an integer"))?;
            rows.push(format!("V\t{name}\t{variant}\t{number}"));
        }
    }
    Ok(digest_rows(rows))
}

fn service_signature(value: &Value) -> ValidationResult<String> {
    let rows = array(value, "service_contract")?
        .iter()
        .map(|service| {
            Ok(format!(
                "S\t{}\t{}\t{}\t{}\t{}\t{}",
                text(service, "service")?,
                text(service, "method")?,
                text(service, "request")?,
                text(service, "response")?,
                text(service, "streaming")?,
                text(service, "transport_implementation_state")?,
            ))
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    Ok(digest_rows(rows))
}

fn oracle_pin_signature(value: &Value) -> ValidationResult<String> {
    let authority = value
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    let mut rows = Vec::new();
    for (key, prefix) in [
        ("proto_source_pins", "P"),
        ("generated_rust_oracle_pins", "G"),
    ] {
        for pin in array(authority, key)? {
            rows.push(format!(
                "{prefix}\t{}\t{}",
                text(pin, "path")?,
                text(pin, "sha256")?
            ));
        }
    }
    Ok(digest_rows(rows))
}

fn repository_pin_signature(value: &Value) -> ValidationResult<String> {
    let authority = value
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    let rows = array(authority, "repository_source_baseline")?
        .iter()
        .map(|pin| {
            Ok(format!(
                "R\t{}\t{}\t{}",
                text(pin, "path")?,
                text(pin, "sha256")?,
                text(pin, "role")?,
            ))
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    Ok(digest_rows(rows))
}

#[allow(clippy::too_many_lines)]
fn validate_identity_and_authority(value: &Value) -> ValidationResult {
    require_exact_keys(
        value,
        &[
            "schema_version",
            "artifact_id",
            "program_id",
            "bead_id",
            "capability_id",
            "captured_at_utc",
            "state",
            "summary",
            "decision",
            "authority",
            "wire_contract",
            "schema_families",
            "enum_contract",
            "service_contract",
            "evolution_contract",
            "resource_contract",
            "implementation_contract",
            "feature_contract",
            "evidence_handoff",
            "planned_contract",
            "no_claim_boundaries",
        ],
        "root",
    )?;
    require_unsigned(value, "schema_version", 1)?;
    for (key, expected) in [
        ("artifact_id", "protobuf-owned-otlp-schema-v1"),
        ("program_id", "asupersync-ir2uf0"),
        ("bead_id", "asupersync-5z2scg.1.3"),
        ("capability_id", "CAP-PROTOBUF-GENERIC"),
        (
            "state",
            "AUTHORITY_PINNED_ALL_FINITE_SCHEMA_SOURCE_PRESENT_A3_EVIDENCE_PENDING",
        ),
    ] {
        require_text(value, key, expected)?;
    }

    let decision = value
        .get("decision")
        .ok_or_else(|| "decision is required".to_owned())?;
    require_exact_keys(
        decision,
        &[
            "finite_internal_schema_authorized",
            "crate_private_only",
            "native_non_wasm_scope",
            "public_generic_protobuf_surface_preserved",
            "public_prost_removal_authorized",
            "production_transport_wiring_authorized",
            "dependency_cutover_authorized",
            "implementation_state",
            "evidence_state",
        ],
        "decision",
    )?;
    for key in [
        "finite_internal_schema_authorized",
        "crate_private_only",
        "native_non_wasm_scope",
        "public_generic_protobuf_surface_preserved",
    ] {
        require_boolean(decision, key, true)?;
    }
    for key in [
        "public_prost_removal_authorized",
        "production_transport_wiring_authorized",
        "dependency_cutover_authorized",
    ] {
        require_boolean(decision, key, false)?;
    }
    require_text(
        decision,
        "implementation_state",
        "ALL_43_FINITE_SCHEMA_MESSAGES_PRESENT_A3_EVIDENCE_PENDING",
    )?;
    require_text(
        decision,
        "evidence_state",
        "NATIVE_DEFAULT_METRICS_LIBRARY_CHECK_GREEN_FOR_43_MESSAGE_SLICE_UNIT_TEST_EXECUTION_PENDING",
    )?;

    let authority = value
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    require_exact_keys(
        authority,
        &[
            "root_workspace_reference",
            "wire_schema_release",
            "semantic_conventions",
            "excluded_authorities",
            "proto_source_pins",
            "generated_rust_oracle_pins",
            "repository_source_baseline",
        ],
        "authority",
    )?;
    let root = authority
        .get("root_workspace_reference")
        .ok_or_else(|| "root workspace reference is required".to_owned())?;
    require_exact_keys(
        root,
        &[
            "crate",
            "crate_version",
            "crates_io_checksum_sha256",
            "cargo_lock_path",
            "cargo_lock_sha256",
            "wrapper_repository",
            "wrapper_repository_commit",
            "path_in_wrapper_repository",
            "enabled_reference_features",
            "production_role",
        ],
        "authority.root_workspace_reference",
    )?;
    for (key, expected) in [
        ("crate", "opentelemetry-proto"),
        ("crate_version", "0.32.0"),
        (
            "crates_io_checksum_sha256",
            "56d658ba1faf63f7b9c492cfbe6e0ec365440a16132d3270c1065f7b33f1b638",
        ),
        ("cargo_lock_path", "Cargo.lock"),
        (
            "cargo_lock_sha256",
            "83c11d5b3882a757b586ba96e2bd3b86d8c49c516ea0896909f148f3f9bee53e",
        ),
        (
            "wrapper_repository",
            "https://github.com/open-telemetry/opentelemetry-rust",
        ),
        (
            "wrapper_repository_commit",
            "ec289cb3c6f8260951699c51df968560943c1451",
        ),
        ("path_in_wrapper_repository", "opentelemetry-proto"),
        ("production_role", "TEST_AND_FUZZ_ORACLE_ONLY"),
    ] {
        require_text(root, key, expected)?;
    }
    let features = array(root, "enabled_reference_features")?
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .ok_or_else(|| "reference features must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    if features
        != [
            "gen-tonic-messages".to_owned(),
            "trace".to_owned(),
            "metrics".to_owned(),
            "logs".to_owned(),
        ]
    {
        return Err("reference feature authority changed".to_owned());
    }

    let release = authority
        .get("wire_schema_release")
        .ok_or_else(|| "wire schema release is required".to_owned())?;
    require_exact_keys(
        release,
        &[
            "repository",
            "release",
            "release_date",
            "release_url",
            "evidence",
            "upstream_commit_sha",
            "upstream_commit_claim",
            "authority_rule",
        ],
        "authority.wire_schema_release",
    )?;
    require_text(
        release,
        "repository",
        "https://github.com/open-telemetry/opentelemetry-proto",
    )?;
    require_text(release, "release", "v1.10.0")?;
    require_text(release, "release_date", "2026-03-09")?;
    require_text(
        release,
        "release_url",
        "https://github.com/open-telemetry/opentelemetry-proto/releases/tag/v1.10.0",
    )?;
    require_text(
        release,
        "evidence",
        "opentelemetry-proto crate 0.32.0 CHANGELOG declares the vendored definitions are v1.10.0",
    )?;
    if !release
        .get("upstream_commit_sha")
        .is_some_and(Value::is_null)
    {
        return Err("published crate must not invent an upstream schema SHA".to_owned());
    }
    require_text(
        release,
        "upstream_commit_claim",
        "NOT_RECORDED_IN_THE_PUBLISHED_RUST_CRATE",
    )?;
    require_text(
        release,
        "authority_rule",
        "The v1.10.0 release identity plus every vendored source digest below is binding. The wrapper repository commit is not represented as an upstream schema commit.",
    )?;
    let semantics = authority
        .get("semantic_conventions")
        .ok_or_else(|| "semantic_conventions is required".to_owned())?;
    require_exact_keys(
        semantics,
        &["default_schema_url", "relationship"],
        "authority.semantic_conventions",
    )?;
    require_text(
        semantics,
        "default_schema_url",
        "https://opentelemetry.io/schemas/1.37.0",
    )?;
    require_text(
        semantics,
        "relationship",
        "This is the current semantic-conventions schema URL used by asupersync. It is independent of and must not be confused with the OTLP wire-schema release v1.10.0.",
    )?;

    let excluded = array(authority, "excluded_authorities")?;
    if excluded.len() != 3
        || string_set(excluded, "path")?.len() != excluded.len()
        || string_set(excluded, "path")?
            != BTreeSet::from([
                "fuzz/Cargo.lock".to_owned(),
                "src/observability/otel.rs::otlp_request_builder".to_owned(),
                "tests/otlp_metrics_request_golden.rs".to_owned(),
            ])
    {
        return Err("excluded authority set changed".to_owned());
    }
    for row in excluded {
        match text(row, "path")? {
            "fuzz/Cargo.lock" => {
                require_exact_keys(
                    row,
                    &["path", "sha256", "resolved_crate_version", "reason"],
                    "excluded stale lock authority",
                )?;
                require_text(
                    row,
                    "sha256",
                    "d91db6afd228ec60aa57d5782cbe5ae3bf7170f5e2c37dd15280e7b476e95271",
                )?;
                require_text(row, "resolved_crate_version", "0.31.0")?;
                require_text(
                    row,
                    "reason",
                    "The fuzz manifest requests 0.32 but its lock remains at 0.31.0. It is stale and cannot define A3 schema authority.",
                )?;
            }
            "src/observability/otel.rs::otlp_request_builder" => {
                require_exact_keys(row, &["path", "reason"], "excluded request builder")?;
                require_text(
                    row,
                    "reason",
                    "Generated request builders are test/fuzz gated and are differential fixtures, not owned production schema authority.",
                )?;
            }
            "tests/otlp_metrics_request_golden.rs" => {
                require_exact_keys(row, &["path", "reason"], "excluded JSON fixture")?;
                require_text(
                    row,
                    "reason",
                    "The JSON-shaped fixture is not protobuf wire evidence.",
                )?;
            }
            path => return Err(format!("unexpected excluded authority {path}")),
        }
    }

    for (key, expected_len, expected_keys) in [
        ("proto_source_pins", 8, &["path", "sha256"][..]),
        ("generated_rust_oracle_pins", 8, &["path", "sha256"][..]),
        (
            "repository_source_baseline",
            7,
            &["path", "sha256", "role"][..],
        ),
    ] {
        let pins = array(authority, key)?;
        if pins.len() != expected_len || string_set(pins, "path")?.len() != pins.len() {
            return Err(format!(
                "authority.{key} must contain {expected_len} unique paths"
            ));
        }
        for pin in pins {
            require_exact_keys(pin, expected_keys, &format!("authority.{key} row"))?;
        }
    }

    if oracle_pin_signature(value)? != ORACLE_PIN_SIGNATURE_SHA256 {
        return Err("proto or generated oracle authority changed".to_owned());
    }
    if repository_pin_signature(value)? != REPOSITORY_PIN_SIGNATURE_SHA256 {
        return Err("repository source authority changed".to_owned());
    }
    Ok(())
}

const fn valid_field_number(tag: u64) -> bool {
    tag > 0 && tag <= 536_870_911 && !(tag >= 19_000 && tag <= 19_999)
}

fn base_wire_type(
    field_type: &str,
    message_names: &BTreeSet<String>,
    enum_names: &BTreeSet<String>,
) -> ValidationResult<&'static str> {
    let wire = match field_type {
        "bool" | "int32" | "int64" | "uint32" | "uint64" | "sint32" => "VARINT",
        "fixed32" => "FIXED32",
        "double" | "fixed64" | "sfixed64" => "FIXED64",
        "bytes" | "string" => "LENGTH_DELIMITED",
        _ if message_names.contains(field_type) => "LENGTH_DELIMITED",
        _ if enum_names.contains(field_type) => "VARINT",
        _ => return Err(format!("unresolved protobuf field type {field_type}")),
    };
    Ok(wire)
}

fn validate_field_shape(
    field: &Value,
    message_name: &str,
    message_names: &BTreeSet<String>,
    enum_names: &BTreeSet<String>,
) -> ValidationResult {
    let name = text(field, "name")?;
    let field_type = text(field, "type")?;
    let cardinality = text(field, "cardinality")?;
    let wire = text(field, "wire")?;
    let base_wire = base_wire_type(field_type, message_names, enum_names)?;
    let packed = boolean(field, "packed")?;
    let oneof = optional_text(field, "oneof")?;
    let presence = optional_text(field, "presence")?;
    let is_message = message_names.contains(field_type);

    if packed {
        if cardinality != "repeated"
            || base_wire == "LENGTH_DELIMITED"
            || wire != "LENGTH_DELIMITED"
            || optional_text(field, "element_wire")? != base_wire
        {
            return Err(format!(
                "{message_name}.{name} has inconsistent packed metadata"
            ));
        }
    } else if wire != base_wire {
        return Err(format!(
            "{message_name}.{name} uses {wire}, expected {base_wire}"
        ));
    }

    if cardinality == "repeated" {
        if presence != "-" || oneof != "-" {
            return Err(format!(
                "{message_name}.{name} repeated metadata is invalid"
            ));
        }
        if base_wire != "LENGTH_DELIMITED" && !packed {
            return Err(format!(
                "{message_name}.{name} packable repeat must be packed"
            ));
        }
    }
    if oneof != "-" && presence != "-" {
        return Err(format!(
            "{message_name}.{name} cannot be both oneof and present"
        ));
    }
    if presence == "optional" && (cardinality != "singular" || is_message) {
        return Err(format!(
            "{message_name}.{name} has invalid optional presence"
        ));
    }
    if is_message && cardinality == "singular" && oneof == "-" && presence != "message" {
        return Err(format!(
            "{message_name}.{name} must retain message presence"
        ));
    }
    if !is_message && presence == "message" {
        return Err(format!("{message_name}.{name} cannot use message presence"));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_schema_registry(value: &Value) -> ValidationResult {
    let families = array(value, "schema_families")?;
    if families.len() != 8
        || string_set(families, "family")?.len() != families.len()
        || string_set(families, "family")?
            != BTreeSet::from([
                "collector_logs".to_owned(),
                "collector_metrics".to_owned(),
                "collector_trace".to_owned(),
                "common".to_owned(),
                "logs".to_owned(),
                "metrics".to_owned(),
                "resource".to_owned(),
                "trace".to_owned(),
            ])
    {
        return Err("schema families must be the exact finite OTLP set".to_owned());
    }

    let mut message_names = BTreeSet::new();
    let mut family_counts = BTreeMap::new();
    let mut message_count = 0usize;
    let mut field_count = 0usize;
    let mut reserved_count = 0usize;
    let mut oneof_count = 0usize;
    let mut presence_count = 0usize;
    let mut optional_count = 0usize;
    let mut packed_count = 0usize;
    for family in families {
        require_exact_keys(family, &["family", "messages"], "schema family")?;
        let family_name = text(family, "family")?;
        let messages = array(family, "messages")?;
        let mut family_field_count = 0usize;
        for message in messages {
            require_exact_keys(
                message,
                &["name", "reserved_tags", "unknown_fields", "fields"],
                "schema message",
            )?;
            message_count += 1;
            let message_name = text(message, "name")?;
            if !message_names.insert(message_name.to_owned()) {
                return Err(format!("duplicate message {message_name}"));
            }
            require_text(message, "unknown_fields", "REQUIRED")?;
            let mut tags = BTreeSet::new();
            let mut names = BTreeSet::new();
            let mut prior_reserved = None;
            for reserved in array(message, "reserved_tags")? {
                let tag = reserved
                    .as_u64()
                    .ok_or_else(|| format!("{message_name} has a nonnumeric reserved tag"))?;
                if !valid_field_number(tag)
                    || prior_reserved.is_some_and(|prior| tag <= prior)
                    || !tags.insert(tag)
                {
                    return Err(format!("{message_name} has an invalid reserved tag {tag}"));
                }
                prior_reserved = Some(tag);
                reserved_count += 1;
            }
            let mut prior_field_tag = None;
            for field in array(message, "fields")? {
                require_exact_field_keys(field, "schema field")?;
                field_count += 1;
                family_field_count += 1;
                let tag = unsigned(field, "tag")?;
                let name = text(field, "name")?;
                if !valid_field_number(tag)
                    || prior_field_tag.is_some_and(|prior| tag <= prior)
                    || !tags.insert(tag)
                {
                    return Err(format!("{message_name} has duplicate or invalid tag {tag}"));
                }
                prior_field_tag = Some(tag);
                if !names.insert(name) {
                    return Err(format!("{message_name} has duplicate field {name}"));
                }
                match text(field, "cardinality")? {
                    "singular" | "repeated" => {}
                    other => return Err(format!("{message_name}.{name} cardinality {other}")),
                }
                let packed = boolean(field, "packed")?;
                if packed {
                    packed_count += 1;
                    if text(field, "cardinality")? != "repeated"
                        || text(field, "wire")? != "LENGTH_DELIMITED"
                        || optional_text(field, "element_wire")? == "-"
                    {
                        return Err(format!("{message_name}.{name} has invalid packed metadata"));
                    }
                } else if optional_text(field, "element_wire")? != "-" {
                    return Err(format!(
                        "{message_name}.{name} has stray element wire metadata"
                    ));
                }
                if optional_text(field, "oneof")? != "-" {
                    oneof_count += 1;
                    if text(field, "cardinality")? != "singular" {
                        return Err(format!("{message_name}.{name} oneof must be singular"));
                    }
                }
                match optional_text(field, "presence")? {
                    "-" => {}
                    "message" => presence_count += 1,
                    "optional" => {
                        presence_count += 1;
                        optional_count += 1;
                    }
                    other => {
                        return Err(format!(
                            "{message_name}.{name} has invalid presence {other}"
                        ));
                    }
                }
            }
        }
        if family_counts
            .insert(family_name.to_owned(), (messages.len(), family_field_count))
            .is_some()
        {
            return Err(format!("duplicate family row {family_name}"));
        }
    }
    let expected_family_counts = BTreeMap::from([
        ("collector_logs".to_owned(), (3, 4)),
        ("collector_metrics".to_owned(), (3, 4)),
        ("collector_trace".to_owned(), (3, 4)),
        ("common".to_owned(), (6, 21)),
        ("logs".to_owned(), (4, 18)),
        ("metrics".to_owned(), (16, 74)),
        ("resource".to_owned(), (1, 3)),
        ("trace".to_owned(), (7, 35)),
    ]);
    if family_counts != expected_family_counts {
        return Err(format!(
            "schema family partition changed: {family_counts:?}"
        ));
    }
    for (label, actual, expected) in [
        ("messages", message_count, 43),
        ("fields", field_count, 163),
        ("reserved tags", reserved_count, 12),
        ("oneof members", oneof_count, 17),
        ("presence fields", presence_count, 20),
        ("optional fields", optional_count, 6),
        ("packed fields", packed_count, 3),
    ] {
        if actual != expected {
            return Err(format!(
                "schema must contain {expected} {label}, got {actual}"
            ));
        }
    }
    if schema_signature(value)? != SCHEMA_SIGNATURE_SHA256 {
        return Err("exact message and field signature changed".to_owned());
    }

    let enums = array(value, "enum_contract")?;
    if enums.len() != 7 || string_set(enums, "name")?.len() != 7 {
        return Err("seven unique enum or bitmask contracts are required".to_owned());
    }
    for enum_row in enums {
        require_allowed_keys(
            enum_row,
            &[
                "name",
                "storage",
                "unknown_values",
                "unknown_bits",
                "values",
            ],
            "enum contract",
        )?;
        if enum_row.as_object().is_none_or(|row| row.len() != 4) {
            return Err("each enum contract must have exactly four keys".to_owned());
        }
        let values = object(enum_row, "values")?;
        let numeric_values = values
            .values()
            .map(|value| {
                value
                    .as_i64()
                    .ok_or_else(|| "enum values must be integers".to_owned())
            })
            .collect::<ValidationResult<BTreeSet<_>>>()?;
        if numeric_values.len() != values.len() {
            return Err(format!(
                "{} has duplicate enum numeric values",
                text(enum_row, "name")?
            ));
        }
    }
    let enum_values = enums
        .iter()
        .map(|row| object(row, "values").map(Map::len))
        .sum::<ValidationResult<usize>>()?;
    if enum_values != 45 || enum_signature(value)? != ENUM_SIGNATURE_SHA256 {
        return Err("exact enum registry changed".to_owned());
    }

    let enum_names = string_set(enums, "name")?;
    for family in families {
        for message in array(family, "messages")? {
            let message_name = text(message, "name")?;
            for field in array(message, "fields")? {
                validate_field_shape(field, message_name, &message_names, &enum_names)?;
            }
        }
    }

    let services = array(value, "service_contract")?;
    if services.len() != 3
        || string_set(services, "service")?.len() != 3
        || !services.iter().all(|row| {
            row.get("streaming").and_then(Value::as_str) == Some("UNARY")
                && row
                    .get("transport_implementation_state")
                    .and_then(Value::as_str)
                    == Some("OUT_OF_SCOPE")
        })
        || service_signature(value)? != SERVICE_SIGNATURE_SHA256
    {
        return Err("exact unary service registry changed".to_owned());
    }
    for service in services {
        require_exact_keys(
            service,
            &[
                "service",
                "method",
                "request",
                "response",
                "streaming",
                "transport_implementation_state",
            ],
            "service contract",
        )?;
        for key in ["request", "response"] {
            if !message_names.contains(text(service, key)?) {
                return Err(format!("service {key} type does not resolve"));
            }
        }
    }
    Ok(())
}

fn validate_exact_numeric_map(
    value: &Value,
    key: &str,
    expected: &[(&str, u64)],
) -> ValidationResult {
    let actual = object(value, key)?;
    if actual.len() != expected.len() {
        return Err(format!(
            "{key} must contain {} exact limits",
            expected.len()
        ));
    }
    for &(name, limit) in expected {
        require_unsigned(value.get(key).expect("object was checked"), name, limit)?;
        if limit == 0 {
            return Err(format!("{key}.{name} must never be unbounded"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_resource_and_implementation(value: &Value) -> ValidationResult {
    let resources = value
        .get("resource_contract")
        .ok_or_else(|| "resource_contract is required".to_owned())?;
    require_exact_keys(
        resources,
        &[
            "policy_class",
            "failure_mode",
            "merge_failure_atomicity",
            "producer_truncation_boundary",
            "generic_wire_limits",
            "shared_semantic_budget",
            "collection_limits",
            "string_and_bytes_limits",
            "limit_provenance",
            "semantic_invariant_completeness",
            "required_semantic_invariants",
        ],
        "resource_contract",
    )?;
    require_text(
        resources,
        "policy_class",
        "NEW_A3_SCHEMA_POLICY_NOT_INCUMBENT_PARITY",
    )?;
    require_text(
        resources,
        "failure_mode",
        "TYPED_HARD_REJECT_WITHOUT_RETURNING_A_PARTIAL_MODEL_OR_OUTPUT_FROM_FRESH_DECODE",
    )?;
    let generic = resources
        .get("generic_wire_limits")
        .ok_or_else(|| "generic_wire_limits is required".to_owned())?;
    require_exact_keys(
        generic,
        &[
            "max_message_bytes",
            "max_length_delimited_field_bytes",
            "max_wire_fields",
            "max_wire_depth",
            "max_wire_work_bytes",
            "source",
        ],
        "resource_contract.generic_wire_limits",
    )?;
    for (key, expected) in [
        ("max_message_bytes", 4_194_304),
        ("max_length_delimited_field_bytes", 4_194_304),
        ("max_wire_fields", 65_536),
        ("max_wire_depth", 100),
        ("max_wire_work_bytes", 16_777_216),
    ] {
        require_unsigned(generic, key, expected)?;
    }
    let shared = resources
        .get("shared_semantic_budget")
        .ok_or_else(|| "shared_semantic_budget is required".to_owned())?;
    require_exact_keys(
        shared,
        &[
            "max_total_repeated_items",
            "max_total_any_value_nodes",
            "max_total_owned_string_and_bytes_payload",
            "accounting",
        ],
        "resource_contract.shared_semantic_budget",
    )?;
    for (key, expected) in [
        ("max_total_repeated_items", 65_536),
        ("max_total_any_value_nodes", 4_096),
        ("max_total_owned_string_and_bytes_payload", 4_194_304),
    ] {
        require_unsigned(shared, key, expected)?;
    }
    if !text(shared, "accounting")?.contains("charged before reserve/push")
        || !text(shared, "accounting")?.contains("charged before allocation")
    {
        return Err("shared semantic accounting must remain pre-allocation".to_owned());
    }
    validate_exact_numeric_map(
        resources,
        "collection_limits",
        &[
            ("resource_groups_per_request", 64),
            ("scopes_per_resource_group", 128),
            ("metrics_per_scope", 4_096),
            ("data_points_per_metric", 1_000),
            ("spans_per_scope", 4_096),
            ("log_records_per_scope", 4_096),
            ("attributes_per_owner", 128),
            ("metric_metadata_entries", 128),
            ("resource_entity_refs", 128),
            ("entity_ref_id_keys", 128),
            ("entity_ref_description_keys", 128),
            ("any_value_depth", 16),
            ("any_value_array_items", 128),
            ("any_value_kvlist_items", 128),
            ("exemplars_per_data_point", 128),
            ("histogram_bucket_counts", 4_096),
            ("histogram_explicit_bounds", 4_095),
            ("exponential_histogram_buckets_per_sign", 4_096),
            ("summary_quantiles", 1_024),
            ("events_per_span", 128),
            ("links_per_span", 128),
        ],
    )?;
    let message_bytes = unsigned(generic, "max_message_bytes")?;
    let field_bytes = unsigned(generic, "max_length_delimited_field_bytes")?;
    let work_bytes = unsigned(generic, "max_wire_work_bytes")?;
    if field_bytes > message_bytes
        || message_bytes.checked_mul(4) != Some(work_bytes)
        || unsigned(
            resources
                .get("collection_limits")
                .ok_or_else(|| "collection_limits is required".to_owned())?,
            "histogram_explicit_bounds",
        )?
        .checked_add(1)
            != Some(unsigned(
                resources
                    .get("collection_limits")
                    .ok_or_else(|| "collection_limits is required".to_owned())?,
                "histogram_bucket_counts",
            )?)
        || unsigned(
            resources
                .get("collection_limits")
                .ok_or_else(|| "collection_limits is required".to_owned())?,
            "any_value_depth",
        )? > unsigned(generic, "max_wire_depth")?
    {
        return Err("resource-limit cross-check failed".to_owned());
    }
    let repeated_limit = unsigned(shared, "max_total_repeated_items")?;
    if object(resources, "collection_limits")?
        .values()
        .any(|limit| limit.as_u64().is_none_or(|limit| limit > repeated_limit))
    {
        return Err("per-collection limits must fit the shared repeat budget".to_owned());
    }
    validate_exact_numeric_map(
        resources,
        "string_and_bytes_limits",
        &[
            ("attribute_key_bytes", 1_024),
            ("attribute_string_or_bytes_value_bytes", 4_096),
            ("schema_url_bytes", 2_048),
            ("scope_name_bytes", 1_024),
            ("scope_version_bytes", 1_024),
            ("metric_name_bytes", 1_024),
            ("metric_description_bytes", 4_096),
            ("metric_unit_bytes", 256),
            ("span_name_bytes", 1_024),
            ("trace_state_bytes", 512),
            ("event_name_bytes", 1_024),
            ("log_severity_text_bytes", 1_024),
            ("log_event_name_bytes", 1_024),
            ("partial_success_error_message_bytes", 4_096),
            ("trace_id_bytes", 16),
            ("span_id_bytes", 8),
        ],
    )?;
    let semantic_scope = text(resources, "semantic_invariant_completeness")?;
    if !semantic_scope.starts_with("NON_EXHAUSTIVE_MINIMUM") {
        return Err("semantic invariant list must remain explicitly non-exhaustive".to_owned());
    }
    let semantic_invariants = array(resources, "required_semantic_invariants")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "semantic invariants must be text".to_owned())
        })
        .collect::<ValidationResult<Vec<_>>>()?
        .join("\n");
    for marker in [
        "Attribute keys are unique",
        "nonzero exact 16-byte value",
        "Link IDs are exact nonempty widths",
        "Span and span-event names are nonempty",
        "W3C tracestate syntax",
        "count equals the checked sum of bucket_counts",
        "Summary quantile values are not negative",
        "Unknown enum values and unknown flag bits survive",
    ] {
        if !semantic_invariants.contains(marker) {
            return Err(format!("semantic minimum missing {marker}"));
        }
    }

    let implementation = value
        .get("implementation_contract")
        .ok_or_else(|| "implementation_contract is required".to_owned())?;
    require_exact_keys(
        implementation,
        &[
            "recommended_private_leaf",
            "recommended_module_gate",
            "public_reexport",
            "required_submodules",
            "current_authoring_gaps",
            "allowed_resolution",
            "forbidden_resolution",
            "all_messages_require_unknown_fields_member",
            "enum_storage",
            "known_field_encoding",
            "unknown_field_encoding",
            "signal_construction_separation",
            "implementation_progress",
        ],
        "implementation_contract",
    )?;
    require_text(
        implementation,
        "recommended_private_leaf",
        "src/observability/otlp_proto.rs",
    )?;
    require_boolean(implementation, "public_reexport", false)?;
    require_boolean(
        implementation,
        "all_messages_require_unknown_fields_member",
        true,
    )?;
    require_text(
        implementation,
        "recommended_module_gate",
        "all(feature = \"metrics\", not(target_arch = \"wasm32\"))",
    )?;
    require_text(
        implementation,
        "enum_storage",
        "RAW_NUMERIC_WITH_TYPED_KNOWN_VALUE_HELPERS",
    )?;
    require_text(implementation, "known_field_encoding", "ASCENDING_TAG")?;
    require_text(
        implementation,
        "unknown_field_encoding",
        "RAW_UNKNOWN_BYTES_AFTER_KNOWN_FIELDS",
    )?;
    let submodules = array(implementation, "required_submodules")?;
    if submodules.len() != 6
        || submodules
            .iter()
            .map(|row| {
                row.as_str()
                    .ok_or_else(|| "required submodules must be text".to_owned())
                    .map(str::to_owned)
            })
            .collect::<ValidationResult<BTreeSet<_>>>()?
            != BTreeSet::from([
                "collector".to_owned(),
                "common_and_resource".to_owned(),
                "limits_and_error".to_owned(),
                "logs".to_owned(),
                "metrics".to_owned(),
                "trace".to_owned(),
            ])
    {
        return Err("six exact private schema concerns are required".to_owned());
    }
    let gaps = array(implementation, "current_authoring_gaps")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "authoring gaps must be text".to_owned())
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    if gaps.len() != 7
        || !gaps
            .iter()
            .any(|gap| gap.contains("oneof decoding replaces"))
        || !gaps.iter().any(|gap| {
            gap.contains("ordinary Vec growth")
                && gap.contains("safe downstream shared nested-writer")
        })
    {
        return Err("all seven current authoring blockers must remain explicit".to_owned());
    }
    for (key, marker) in [
        ("allowed_resolution", "stage and commit atomically"),
        ("forbidden_resolution", "validate() only after decode"),
    ] {
        if !text(implementation, key)?.contains(marker) {
            return Err(format!("implementation.{key} missing {marker}"));
        }
    }

    let progress = implementation
        .get("implementation_progress")
        .ok_or_else(|| "implementation_progress is required".to_owned())?;
    require_exact_keys(
        progress,
        &[
            "implemented_submodules",
            "implemented_messages",
            "pending_submodules",
            "implemented_message_count",
            "pending_message_count",
            "execution_state",
            "public_surface_delta",
        ],
        "implementation_progress",
    )?;
    let implemented_submodules = array(progress, "implemented_submodules")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "implemented submodules must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    let pending_submodules = array(progress, "pending_submodules")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "pending submodules must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    if array(progress, "implemented_submodules")?.len() != 6
        || !array(progress, "pending_submodules")?.is_empty()
        || implemented_submodules
            != BTreeSet::from([
                "collector".to_owned(),
                "common_and_resource".to_owned(),
                "limits_and_error".to_owned(),
                "logs".to_owned(),
                "metrics".to_owned(),
                "trace".to_owned(),
            ])
        || !pending_submodules.is_empty()
    {
        return Err("complete implementation submodule partition changed".to_owned());
    }

    let implemented_messages = array(progress, "implemented_messages")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "implemented messages must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    let mut expected_implemented_messages = BTreeSet::new();
    for family in array(value, "schema_families")? {
        for message in array(family, "messages")? {
            expected_implemented_messages.insert(text(message, "name")?.to_owned());
        }
    }
    if array(progress, "implemented_messages")?.len() != 43
        || implemented_messages != expected_implemented_messages
    {
        return Err("all 43 finite messages must be implemented".to_owned());
    }
    require_unsigned(progress, "implemented_message_count", 43)?;
    require_unsigned(progress, "pending_message_count", 0)?;
    require_text(
        progress,
        "execution_state",
        "NATIVE_DEFAULT_METRICS_LIBRARY_CHECK_GREEN_FOR_43_MESSAGE_SLICE_UNIT_TEST_EXECUTION_PENDING",
    )?;

    let public_delta = progress
        .get("public_surface_delta")
        .ok_or_else(|| "public_surface_delta is required".to_owned())?;
    require_exact_keys(
        public_delta,
        &[
            "kind",
            "added_methods",
            "added_non_exhaustive_error_variants",
            "removed_or_narrowed_capabilities",
            "public_otlp_schema_types_added",
        ],
        "public_surface_delta",
    )?;
    require_text(public_delta, "kind", "ADDITIVE_SOURCE_COMPATIBLE")?;
    require_boolean(public_delta, "removed_or_narrowed_capabilities", false)?;
    require_boolean(public_delta, "public_otlp_schema_types_added", false)?;
    let added_methods = array(public_delta, "added_methods")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "added methods must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    if array(public_delta, "added_methods")?.len() != 4
        || added_methods
            != BTreeSet::from([
                "ProtobufWireEncoder::charge_schema_work".to_owned(),
                "ProtobufWireEncoder::remaining_work".to_owned(),
                "UnknownFields::try_record".to_owned(),
                "UnknownFields::try_record_raw".to_owned(),
            ])
    {
        return Err("additive generic protobuf method registry changed".to_owned());
    }
    let added_errors = array(public_delta, "added_non_exhaustive_error_variants")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "added error variants must be text".to_owned())
                .map(str::to_owned)
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    if array(public_delta, "added_non_exhaustive_error_variants")?.len() != 3
        || added_errors
            != BTreeSet::from([
                "ProtobufWireError::AllocationFailed".to_owned(),
                "ProtobufWireError::SchemaInvariant".to_owned(),
                "ProtobufWireError::SchemaLimitExceeded".to_owned(),
            ])
    {
        return Err("additive non-exhaustive wire-error registry changed".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_evolution_features_and_handoff(value: &Value) -> ValidationResult {
    let wire = value
        .get("wire_contract")
        .ok_or_else(|| "wire_contract is required".to_owned())?;
    require_exact_keys(
        wire,
        &[
            "syntax",
            "canonical_known_field_order",
            "repeated_element_order",
            "packed_encoder_policy",
            "packed_decoder_policy",
            "scalar_wire_types",
            "singular_scalar_presence",
            "singular_message_presence",
            "oneof_semantics",
            "reserved_tag_policy",
            "unknown_field_placement_on_encode",
            "byte_identity_claim",
        ],
        "wire_contract",
    )?;
    require_text(wire, "syntax", "proto3")?;
    require_text(wire, "canonical_known_field_order", "ASCENDING_TAG")?;
    require_text(wire, "repeated_element_order", "PRESERVE_INPUT_ORDER")?;
    let oneof = text(wire, "oneof_semantics")?;
    if !oneof.contains("REPEATED_SAME_MESSAGE_MEMBER_MERGES")
        || !oneof.contains("A_DIFFERENT_MEMBER_REPLACES")
    {
        return Err("oneof merge and replacement semantics must stay exact".to_owned());
    }
    require_text(
        wire,
        "unknown_field_placement_on_encode",
        "KNOWN_FIELDS_FIRST_THEN_RAW_UNKNOWNS_IN_ORIGINAL_UNKNOWN_ENCOUNTER_ORDER",
    )?;
    let scalar_wires = wire
        .get("scalar_wire_types")
        .ok_or_else(|| "scalar_wire_types is required".to_owned())?;
    require_exact_keys(
        scalar_wires,
        &[
            "bool", "int32", "int64", "uint32", "uint64", "sint32", "enum", "fixed32", "fixed64",
            "sfixed64", "double", "string", "bytes", "message", "packed",
        ],
        "wire_contract.scalar_wire_types",
    )?;
    for (kind, expected) in [
        ("bool", "VARINT"),
        ("int32", "VARINT"),
        ("int64", "VARINT"),
        ("uint32", "VARINT"),
        ("uint64", "VARINT"),
        ("sint32", "VARINT"),
        ("enum", "VARINT"),
        ("fixed32", "FIXED32"),
        ("fixed64", "FIXED64"),
        ("sfixed64", "FIXED64"),
        ("double", "FIXED64"),
        ("string", "LENGTH_DELIMITED"),
        ("bytes", "LENGTH_DELIMITED"),
        ("message", "LENGTH_DELIMITED"),
        ("packed", "LENGTH_DELIMITED"),
    ] {
        require_text(scalar_wires, kind, expected)?;
    }

    let evolution = value
        .get("evolution_contract")
        .ok_or_else(|| "evolution_contract is required".to_owned())?;
    require_exact_keys(
        evolution,
        &[
            "every_message_owns_unknown_fields",
            "unknown_field_representation",
            "unknown_groups",
            "unknown_enum_values",
            "known_tag_wrong_wire_type",
            "duplicate_singular_scalar",
            "duplicate_singular_message",
            "duplicate_oneof",
            "reserved_tag_reuse",
            "field_removal",
            "authority_drift",
            "string_index_fields",
        ],
        "evolution_contract",
    )?;
    require_boolean(evolution, "every_message_owns_unknown_fields", true)?;
    for (key, expected) in [
        (
            "unknown_field_representation",
            "EXACT_RAW_FIELD_BYTES_IN_ENCOUNTER_ORDER",
        ),
        (
            "known_tag_wrong_wire_type",
            "TYPED_ERROR_NOT_UNKNOWN_FALLBACK",
        ),
        (
            "duplicate_oneof",
            "REPEATED_SAME_MESSAGE_MEMBER_MERGES; A_DIFFERENT_MEMBER_REPLACES; SCALAR_OR_DIFFERENT_MEMBER_USES_LAST_RECOGNIZED_VALUE",
        ),
        ("reserved_tag_reuse", "FORBIDDEN"),
        ("field_removal", "MOVE_TAG_AND_NAME_TO_RESERVED_SET"),
    ] {
        require_text(evolution, key, expected)?;
    }

    let feature_rows = array(value, "feature_contract")?;
    for row in feature_rows {
        require_exact_keys(row, &["profile", "expectation"], "feature contract")?;
    }
    let feature_matrix = feature_rows
        .iter()
        .map(|row| Ok((text(row, "profile")?, text(row, "expectation")?)))
        .collect::<ValidationResult<BTreeMap<_, _>>>()?;
    if feature_rows.len() != 6
        || feature_matrix.len() != feature_rows.len()
        || feature_matrix
            != BTreeMap::from([
                (
                    "default",
                    "Additive source-compatible generic protobuf authoring errors and fallible methods are present; no generated OTLP reference dependency or public OTLP schema type is added.",
                ),
                (
                    "metrics",
                    "Private owned schemas compile on native targets without opentelemetry-proto, tonic, or tokio normal edges.",
                ),
                (
                    "metrics,tracing-integration",
                    "The same owned schema module compiles; generated reference messages remain test/fuzz oracle-only.",
                ),
                (
                    "no-default-features,metrics",
                    "Private owned schemas compile without assuming the optional proc-macros feature.",
                ),
                (
                    "fuzz",
                    "The generated oracle remains quarantined; its stale lock must be refreshed by its owner before it can claim v0.32 parity. A3 does not modify the fuzz lock.",
                ),
                (
                    "wasm32",
                    "Native OTLP finite-schema integration remains excluded unless a later owner supplies a wasm-safe wire boundary and evidence.",
                ),
            ])
    {
        return Err("feature and target matrix changed".to_owned());
    }

    let handoff = array(value, "evidence_handoff")?;
    if handoff.len() != 4
        || string_set(handoff, "owner")?.len() != handoff.len()
        || string_set(handoff, "owner")?
            != BTreeSet::from([
                "asupersync-5z2scg.1.3".to_owned(),
                "asupersync-5z2scg.1.4".to_owned(),
                "asupersync-5z2scg.1.7".to_owned(),
                "asupersync-5z2scg.2.6".to_owned(),
            ])
    {
        return Err("evidence handoff owners changed".to_owned());
    }
    for row in handoff {
        let owner = text(row, "owner")?;
        if text(row, "scope")?.is_empty() {
            return Err(format!("{owner} handoff scope must be nonempty"));
        }
        if owner == "asupersync-5z2scg.1.3" {
            require_exact_keys(
                row,
                &[
                    "owner",
                    "scope",
                    "required_test_prefixes",
                    "prefix_scope",
                    "current_state",
                ],
                "A3 handoff",
            )?;
            require_text(
                row,
                "current_state",
                "ALL_43_FINITE_SCHEMA_MESSAGES_PRESENT_LIBRARY_CHECK_GREEN_TEST_EXECUTION_PENDING",
            )?;
        } else {
            require_exact_keys(
                row,
                &["owner", "scope", "current_state"],
                "downstream handoff",
            )?;
            let expected_state = match owner {
                "asupersync-5z2scg.1.4" => "BLOCKED_BY_A3",
                "asupersync-5z2scg.1.7" => "BLOCKED_BY_A3_AND_A4",
                "asupersync-5z2scg.2.6" => "DOWNSTREAM_NOT_AUTHORIZED_BY_THIS_PACKET",
                _ => return Err(format!("unexpected handoff owner {owner}")),
            };
            require_text(row, "current_state", expected_state)?;
        }
    }
    let a3 = handoff
        .iter()
        .find(|row| row.get("owner").and_then(Value::as_str) == Some("asupersync-5z2scg.1.3"))
        .ok_or_else(|| "A3 handoff row is required".to_owned())?;
    let expected_prefix_scopes = BTreeMap::from([
        (
            "ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants",
            "A3 finite schema, field, semantic, and resource invariants only.",
        ),
        (
            "ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix",
            "A3 schema-local encode/decode and limit properties; independent/reference conformance remains A4.",
        ),
        (
            "ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle",
            "A3 deterministic shared-budget lifecycle and fresh-decode failure-state checks only; no runtime, task, cancellation, shutdown, or transport claim.",
        ),
        (
            "ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__downstream_consumer",
            "A3 source-level compile/use test bodies for the complete finite metrics, traces, logs, and all three collector request/response shapes through the existing owned generic codec; the unit tests have not executed and no signal adapter, framing, collector contact, transport, or user-journey claim is made.",
        ),
    ]);
    let expected_prefixes = expected_prefix_scopes
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let prefixes = array(a3, "required_test_prefixes")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "test prefixes must be text".to_owned())
        })
        .collect::<ValidationResult<BTreeSet<_>>>()?;
    let prefix_scopes = object(a3, "prefix_scope")?
        .iter()
        .map(|(prefix, scope)| {
            scope
                .as_str()
                .ok_or_else(|| format!("prefix scope {prefix} must be text"))
                .map(|scope| (prefix.as_str(), scope))
        })
        .collect::<ValidationResult<BTreeMap<_, _>>>()?;
    if array(a3, "required_test_prefixes")?.len() != 4
        || prefixes != expected_prefixes
        || prefix_scopes != expected_prefix_scopes
    {
        return Err("A3 prefix registry or bounded scopes changed".to_owned());
    }

    let planned = value
        .get("planned_contract")
        .ok_or_else(|| "planned_contract is required".to_owned())?;
    require_exact_keys(
        planned,
        &[
            "artifact_path",
            "docs_path",
            "test_path",
            "test_implementation_state",
            "validator_shape",
            "negative_mutations",
            "proof_state",
            "no_local_cargo_fallback",
        ],
        "planned_contract",
    )?;
    for (key, expected) in [
        ("artifact_path", ARTIFACT_PATH),
        ("docs_path", DOC_PATH),
        ("test_path", "tests/protobuf_owned_otlp_schema_contract.rs"),
        ("proof_state", "STATIC_VALIDATION_REFRESH_PENDING"),
    ] {
        require_text(planned, key, expected)?;
    }
    require_text(
        planned,
        "test_implementation_state",
        "PRESENT_REFRESH_VALIDATION_PENDING",
    )?;
    require_boolean(planned, "no_local_cargo_fallback", true)?;
    let planned_mutations = array(planned, "negative_mutations")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "planned mutations must be text".to_owned())
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    if planned_mutations != EXPECTED_PLANNED_MUTATIONS {
        return Err("planned fail-closed mutation registry changed".to_owned());
    }

    let no_claim_rows = array(value, "no_claim_boundaries")?;
    let no_claims = no_claim_rows
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "no-claim boundaries must be text".to_owned())
        })
        .collect::<ValidationResult<Vec<_>>>()?;
    if no_claims != EXPECTED_NO_CLAIMS {
        return Err("no-claim boundaries changed".to_owned());
    }
    Ok(())
}

fn validate_contract(value: &Value) -> ValidationResult {
    validate_identity_and_authority(value)?;
    validate_schema_registry(value)?;
    validate_resource_and_implementation(value)?;
    validate_evolution_features_and_handoff(value)
}

fn validate_live_repository_pins(value: &Value) -> ValidationResult {
    let authority = value
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    let root = authority
        .get("root_workspace_reference")
        .ok_or_else(|| "root workspace reference is required".to_owned())?;
    let lock_path = text(root, "cargo_lock_path")?;
    let lock_bytes = read_repo_bytes(lock_path);
    if sha256_hex(&lock_bytes) != text(root, "cargo_lock_sha256")? {
        return Err("root Cargo.lock drifted from authority".to_owned());
    }
    let lock = String::from_utf8(lock_bytes).map_err(|error| error.to_string())?;
    let package_blocks = lock
        .split("[[package]]")
        .filter(|block| block.contains("name = \"opentelemetry-proto\""))
        .collect::<Vec<_>>();
    if package_blocks.len() != 1
        || !package_blocks[0].contains("version = \"0.32.0\"")
        || !package_blocks[0].contains(
            "checksum = \"56d658ba1faf63f7b9c492cfbe6e0ec365440a16132d3270c1065f7b33f1b638\"",
        )
    {
        return Err("root lock must resolve the exact opentelemetry-proto authority".to_owned());
    }

    for pin in array(authority, "repository_source_baseline")? {
        let path = text(pin, "path")?;
        if sha256_hex(&read_repo_bytes(path)) != text(pin, "sha256")? {
            return Err(format!("live repository source drifted: {path}"));
        }
    }
    let stale_lock = array(authority, "excluded_authorities")?
        .iter()
        .find(|row| row.get("path").and_then(Value::as_str) == Some("fuzz/Cargo.lock"))
        .ok_or_else(|| "stale fuzz lock exclusion is required".to_owned())?;
    let stale_path = text(stale_lock, "path")?;
    let stale_bytes = read_repo_bytes(stale_path);
    if sha256_hex(&stale_bytes) != text(stale_lock, "sha256")? {
        return Err("excluded fuzz lock drifted from its recorded stale state".to_owned());
    }
    let stale_text = String::from_utf8(stale_bytes).map_err(|error| error.to_string())?;
    let stale_packages = stale_text
        .split("[[package]]")
        .filter(|block| block.contains("name = \"opentelemetry-proto\""))
        .collect::<Vec<_>>();
    if stale_packages.len() != 1 || !stale_packages[0].contains("version = \"0.31.0\"") {
        return Err("excluded fuzz lock must remain explicitly stale at 0.31.0".to_owned());
    }
    Ok(())
}

fn validate_operator_doc(doc: &str, value: &Value) -> ValidationResult {
    if sha256_hex(doc.as_bytes()) != DOC_SHA256 {
        return Err("operator document bytes changed without authority review".to_owned());
    }
    if doc.match_indices(DOC_BEGIN).count() != 1 || doc.match_indices(DOC_END).count() != 1 {
        return Err("operator document markers must occur exactly once".to_owned());
    }
    let begin = doc
        .find(DOC_BEGIN)
        .ok_or_else(|| "operator document begin marker is required".to_owned())?;
    let end = doc
        .find(DOC_END)
        .ok_or_else(|| "operator document end marker is required".to_owned())?;
    if begin >= end || !doc[end + DOC_END.len()..].trim().is_empty() {
        return Err("operator document markers are misordered or followed by claims".to_owned());
    }
    for marker in [
        ARTIFACT_PATH,
        "tests/protobuf_owned_otlp_schema_contract.rs",
        "asupersync-5z2scg.1.3",
        "CAP-PROTOBUF-GENERIC",
        "opentelemetry-proto` Rust crate `0.32.0",
        "56d658ba1faf63f7b9c492cfbe6e0ec365440a16132d3270c1065f7b33f1b638",
        "ec289cb3c6f8260951699c51df968560943c1451",
        "OTLP proto release `v1.10.0",
        "https://opentelemetry.io/schemas/1.37.0",
        "8 families, 43 messages, 163 fields, 7 enum or",
        "3 unary collector methods",
        "message-valued oneof member merge",
        "non-exhaustive minimum",
        "one reusable fail-closed validator",
        "complete 43-message finite source slice",
        "all nine collector request, response, and",
        "all three collector request/response shapes",
        "Canonical unit-test execution",
        "W3C tracestate",
        "cargo check --locked -p asupersync --lib --features metrics -j 4",
        "local Cargo fallback",
        "or file deletion",
        "No-claim boundary",
    ] {
        if !doc.contains(marker) {
            return Err(format!("operator document missing {marker}"));
        }
    }
    let authority = value
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    for pin in array(authority, "proto_source_pins")? {
        let path = text(pin, "path")?
            .strip_prefix("opentelemetry/proto/")
            .ok_or_else(|| "proto source pin path must use canonical prefix".to_owned())?;
        let digest = text(pin, "sha256")?;
        let association = format!("| `{path}` | `{digest}` |");
        if doc.match_indices(&association).count() != 1 {
            return Err(format!("operator document missing source pin {path}"));
        }
    }
    Ok(())
}

fn assert_rejected(mutated: &Value, label: &str) {
    assert!(
        validate_contract(mutated).is_err(),
        "{label} mutation must fail closed"
    );
}

#[test]
fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants__canonical_packet_is_exact() {
    let value = artifact();
    validate_contract(&value).expect("canonical authority packet must validate");
    validate_live_repository_pins(&value).expect("live repository pins must match");
    assert_eq!(sha256_hex(&read_repo_bytes(ARTIFACT_PATH)), ARTIFACT_SHA256);
    assert_eq!(sha256_hex(&read_repo_bytes(DOC_PATH)), DOC_SHA256);
}

#[test]
fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants__operator_doc_is_fail_closed() {
    let value = artifact();
    let doc = read_repo_file(DOC_PATH);
    validate_operator_doc(&doc, &value).expect("operator document must validate");
}

#[test]
fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix__ambiguous_json_is_rejected() {
    for raw in [
        br#"{"decision":{"public_prost_removal_authorized":true,"public_prost_removal_authorized":false}}"#
            .as_slice(),
        br#"{"schema_families":[],"schema_families":[]}"#.as_slice(),
    ] {
        assert!(
            parse_unique_json(raw)
                .expect_err("duplicate JSON key must fail")
                .contains("duplicate JSON object key")
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix__negative_mutations_fail_closed() {
    let canonical = artifact();

    let mut unknown_root_key = canonical.clone();
    unknown_root_key["production_cutover_override"] = Value::Bool(true);
    assert_rejected(&unknown_root_key, "unknown root key");

    let mut missing_family = canonical.clone();
    missing_family["schema_families"]
        .as_array_mut()
        .expect("schema families")
        .pop();
    assert_rejected(&missing_family, "missing family");

    let mut duplicate_family = canonical.clone();
    let family = duplicate_family["schema_families"][0].clone();
    duplicate_family["schema_families"]
        .as_array_mut()
        .expect("schema families")
        .push(family);
    assert_rejected(&duplicate_family, "duplicate family");

    let mut duplicate_tag = canonical.clone();
    duplicate_tag["schema_families"][0]["messages"][0]["fields"][1]["tag"] = Value::from(1);
    assert_rejected(&duplicate_tag, "duplicate tag");

    let mut wrong_wire = canonical.clone();
    wrong_wire["schema_families"][0]["messages"][0]["fields"][0]["wire"] =
        Value::String("VARINT".to_owned());
    assert_rejected(&wrong_wire, "wrong wire kind");

    let mut wrong_packed = canonical.clone();
    wrong_packed["schema_families"][2]["messages"][10]["fields"][4]["packed"] = Value::Bool(false);
    assert_rejected(&wrong_packed, "wrong packed metadata");

    let mut null_field_metadata = canonical.clone();
    null_field_metadata["schema_families"][0]["messages"][0]["fields"][0]["presence"] = Value::Null;
    assert_rejected(&null_field_metadata, "null field metadata");

    let mut missing_unknowns = canonical.clone();
    missing_unknowns["schema_families"][0]["messages"][0]["unknown_fields"] = Value::Null;
    assert_rejected(&missing_unknowns, "missing unknown fields");

    let mut unbounded = canonical.clone();
    unbounded["resource_contract"]["collection_limits"]["attributes_per_owner"] = Value::from(0);
    assert_rejected(&unbounded, "zero resource limit");

    let mut missing_limit = canonical.clone();
    missing_limit["resource_contract"]["collection_limits"]
        .as_object_mut()
        .expect("collection limits")
        .remove("attributes_per_owner");
    assert_rejected(&missing_limit, "missing resource limit");

    for replacement in [Value::Null, Value::String("unbounded".to_owned())] {
        let mut mistyped_limit = canonical.clone();
        mistyped_limit["resource_contract"]["collection_limits"]["attributes_per_owner"] =
            replacement;
        assert_rejected(&mistyped_limit, "mistyped resource limit");
    }

    for section in [
        "generic_wire_limits",
        "shared_semantic_budget",
        "collection_limits",
        "string_and_bytes_limits",
    ] {
        let numeric_limits = canonical["resource_contract"][section]
            .as_object()
            .expect("resource limit section")
            .iter()
            .filter_map(|(key, value)| value.as_u64().map(|limit| (key.clone(), limit)))
            .collect::<Vec<_>>();
        for (key, limit) in numeric_limits {
            for replacement in [0, limit.checked_add(1).expect("frozen limits are bounded")] {
                let mut weakened = canonical.clone();
                weakened["resource_contract"][section][key.as_str()] = Value::from(replacement);
                assert_rejected(&weakened, &format!("{section}.{key}={replacement}"));
            }
        }
    }

    let mut dependency_exit = canonical.clone();
    dependency_exit["decision"]["public_prost_removal_authorized"] = Value::Bool(true);
    assert_rejected(&dependency_exit, "public prost removal");

    let mut public_reexport = canonical.clone();
    public_reexport["implementation_contract"]
        .as_object_mut()
        .expect("implementation contract")
        .remove("public_reexport");
    assert_rejected(&public_reexport, "missing public reexport decision");

    let mut invented_upstream = canonical.clone();
    invented_upstream["authority"]["wire_schema_release"]["upstream_commit_sha"] =
        Value::String("0000000000000000000000000000000000000000".to_owned());
    assert_rejected(&invented_upstream, "invented upstream commit");

    let mut missing_upstream = canonical.clone();
    missing_upstream["authority"]["wire_schema_release"]
        .as_object_mut()
        .expect("wire schema release")
        .remove("upstream_commit_sha");
    assert_rejected(&missing_upstream, "missing explicit upstream null");

    let mut false_authority_rule = canonical.clone();
    false_authority_rule["authority"]["wire_schema_release"]["authority_rule"] =
        Value::String("The wrapper commit is the upstream schema commit.".to_owned());
    assert_rejected(&false_authority_rule, "false upstream authority rule");

    let mut promoted_stale_lock = canonical.clone();
    promoted_stale_lock["authority"]["excluded_authorities"][0]["resolved_crate_version"] =
        Value::String("0.32.0".to_owned());
    assert_rejected(&promoted_stale_lock, "stale lock promotion");

    let mut unknown_excluded_key = canonical.clone();
    unknown_excluded_key["authority"]["excluded_authorities"][0]["production_authority"] =
        Value::Bool(true);
    assert_rejected(&unknown_excluded_key, "unknown excluded-authority key");

    let mut duplicate_reference_feature = canonical.clone();
    duplicate_reference_feature["authority"]["root_workspace_reference"]
        ["enabled_reference_features"]
        .as_array_mut()
        .expect("enabled reference features")
        .push(Value::String("gen-tonic-messages".to_owned()));
    assert_rejected(&duplicate_reference_feature, "duplicate reference feature");

    let mut post_decode_only = canonical.clone();
    post_decode_only["implementation_contract"]["forbidden_resolution"] =
        Value::String("post-decode validation is sufficient".to_owned());
    assert_rejected(&post_decode_only, "post-decode-only budgeting");

    let mut replaced_message_oneof = canonical.clone();
    replaced_message_oneof["wire_contract"]["oneof_semantics"] =
        Value::String("LAST_RECOGNIZED_MEMBER_WINS".to_owned());
    assert_rejected(&replaced_message_oneof, "message-valued oneof replacement");

    let mut missing_prefix_scope = canonical.clone();
    missing_prefix_scope["evidence_handoff"][0]["prefix_scope"]
        .as_object_mut()
        .expect("prefix scope")
        .remove("ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle");
    assert_rejected(&missing_prefix_scope, "missing prefix scope");

    let mut overclaimed_prefix_scope = canonical.clone();
    overclaimed_prefix_scope["evidence_handoff"][0]["prefix_scope"]["ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle"] =
        Value::String("A3 proves production runtime behavior.".to_owned());
    assert_rejected(&overclaimed_prefix_scope, "overclaimed prefix scope");

    let mut overclaimed_feature = canonical.clone();
    overclaimed_feature["feature_contract"][1]["expectation"] =
        Value::String("Public generated messages and runtime edges are authorized.".to_owned());
    assert_rejected(&overclaimed_feature, "overclaimed feature expectation");

    let mut duplicate_profile = canonical.clone();
    let profile = duplicate_profile["feature_contract"][0].clone();
    duplicate_profile["feature_contract"]
        .as_array_mut()
        .expect("feature contract")
        .push(profile);
    assert_rejected(&duplicate_profile, "duplicate feature profile");

    let mut duplicate_no_claim = canonical.clone();
    let first_no_claim = duplicate_no_claim["no_claim_boundaries"][0].clone();
    duplicate_no_claim["no_claim_boundaries"][1] = first_no_claim;
    assert_rejected(&duplicate_no_claim, "duplicate no-claim boundary");

    let mut qualified_no_claim = canonical.clone();
    qualified_no_claim["no_claim_boundaries"][8] = Value::String(
        "It does not authorize production cutover unless separately requested.".to_owned(),
    );
    assert_rejected(&qualified_no_claim, "qualified no-claim boundary");

    let mut duplicate_planned_mutation = canonical.clone();
    let first_mutation =
        duplicate_planned_mutation["planned_contract"]["negative_mutations"][0].clone();
    duplicate_planned_mutation["planned_contract"]["negative_mutations"][1] = first_mutation;
    assert_rejected(&duplicate_planned_mutation, "duplicate planned mutation");

    let mut duplicate_doc_marker = read_repo_file(DOC_PATH);
    duplicate_doc_marker.push_str(DOC_BEGIN);
    assert!(
        validate_operator_doc(&duplicate_doc_marker, &canonical).is_err(),
        "duplicate document marker must fail"
    );

    let mut cutover_claim = canonical;
    cutover_claim["no_claim_boundaries"] = Value::Array(Vec::new());
    assert_rejected(&cutover_claim, "removed no-claim boundary");
}
