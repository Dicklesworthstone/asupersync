//! Static contract for the Kafka K0.4 broker/fixture provenance matrix.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.1.4
//! Fixture: artifacts/kafka_broker_fixture_provenance_matrix_v1.json
//!
//! This contract reads checked-in repository files only. It starts no broker,
//! process, container, or network activity and does not convert source,
//! planned, compile-only, deterministic, wire-only, proof-only, opt-in, or
//! silent-skip evidence into executed real-broker evidence.

#![allow(dead_code, missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/kafka_broker_fixture_provenance_matrix_v1.json";
const DOC_PATH: &str = "docs/kafka_broker_fixture_provenance_matrix.md";
const K0_3_PATH: &str = "artifacts/kafka_downstream_user_journey_inventory_v1.json";
const ARTIFACT_SHA256: &str = "fec2b0994bd6da153400cd94fcb9d36ff6285aa45407b6111fc7d68c319bc95e";
const DOC_SHA256: &str = "46155f321b98e2e72c3b24ca5137c8929d5fa52f6e8b8c5d6714c13a793a720b";
const ARTIFACT_ID: &str = "kafka-broker-fixture-provenance-matrix-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.4";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const BASELINE_REVISION: &str = "012c13714db267a4fba928db9f900b70d6c1d25a";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const INVENTORY_STATE: &str = "K0_4_STATIC_FIXTURE_AND_PROVENANCE_MATRIX_FROZEN_RUNTIME_UNKNOWN";
const K0_3_ARTIFACT_ID: &str = "kafka-downstream-user-journey-inventory-v1";
const K0_3_BASELINE_REVISION: &str = "ae22e710d87412b38e546b32e9702106619481d5";
const K0_3_SHA256: &str = "dd8277e09864965f74d97d70406d722fd149636a010decb12113f6f7cd67dca3";
const K0_3_TEST_GROUP_COUNT: usize = 35;
const K0_3_TEST_DECLARATION_COUNT: usize = 940;
const K0_3_EXACT_TEST_DECLARATION_COUNT: usize = 892;
const K0_3_TOKIO_TEST_DECLARATION_COUNT: usize = 48;
const K0_3_LOCAL_ROW_COUNT: usize = 34;
const K0_3_ATOMIC_CASE_COUNT: usize = 16;
const K0_3_TEST_GROUP_PATH_SHA256: &str =
    "720d9d8fca6a4b23d06d5cfa400eef884c016edb39ac71ce74cde44036b26011";
const K0_3_TEST_GROUP_PATH_PIN_SHA256: &str =
    "5eb3a4a99955992f5a8ef5bbd79969dce668e908499872bd9588fa7214b4b2ae";
const K0_3_TOKIO_DECLARATION_TUPLE_SHA256: &str =
    "c21dd6b0021dc189e82e6a3cf95dd37f1cddb100cf9688595fbe7a969b09b80d";
const K0_3_LOCAL_ROW_TUPLE_SHA256: &str =
    "fa731b53ebbee2de55851a791880638cfdc79c54758072f06bf0b73fe6a39fb3";
const K0_3_ATOMIC_CASE_TUPLE_SHA256: &str =
    "bf82029b0357c9fae711e2ace5925ec325dc67930affb87629e01fd44c42ebb4";
const DIRECT_SOURCE_PIN_COUNT: usize = 20;
const DIRECT_FIXTURE_PIN_COUNT: usize = 19;
const INHERITED_FIXTURE_PIN_COUNT: usize = 48;
const FIXTURE_PATH_COUNT: usize = 67;
const FIXTURE_PATH_SHA256: &str =
    "d9542095b391dbd44a0f8d855d6cfb87e41b981642430a0de662a2965ad26db0";
const FIXTURE_CENSUS_TUPLE_SHA256: &str =
    "c960cdaaadbedc04423abd8dbcd9852f78077ac11e3654fa84e178a65d9ca26b";
const VECTOR_STATE_OWNER_ENV_TUPLE_SHA256: &str =
    "c359a6c9b5387c2ee8ef97ce2833a4fb10959a0d3a3ee245e8882cbcc9b6d489";
const CODEC_CELL_COUNT: usize = 5;
const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K0.4 BROKER FIXTURE PROVENANCE -->";
const DOC_END: &str = "<!-- END KAFKA K0.4 BROKER FIXTURE PROVENANCE -->";
const K14_REFRESH_OWNER: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.14.1";
const K15_CUTOVER_OWNER: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.15";

const DIRECT_FIXTURE_PINS: &[(&str, &str, u64, u64, &str)] = &[
    (
        "conformance/src/kafka_record_batch_v2.rs",
        "eb9d3ccf193e3fe34e82fe2b32ee76ee1d3e376e98ac82eec8d428ea91de676f",
        49_117,
        1_460,
        "UTF8_LINES",
    ),
    (
        "fuzz/corpus/kafka_protocol/api_versions_tagged_fields",
        "db799bc1fb6da0a9ba18d68e0925b283f17278be130a1e071dc28592c6ff0500",
        65,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_protocol/invalid_api_version_header",
        "445f88f6befb68cd7ce6f96e86630a35bac514f7fe1ded1d482d64bbdf9e1f7c",
        49,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_protocol/oversized_request_frame",
        "acb2b8901d0e4246dc77a574462e462263a740df72f97e368df24c758db98a0f",
        58,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_response_frames/empty",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        0,
        0,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_response_frames/error_response",
        "b2386ded5fb9864f800fc5f71fcdd568bda5cd5eff4f215b21e5489b6938dfbb",
        16,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_response_frames/malformed_length",
        "a7a433f4573f250a0d70abad78d3f73a0d41431750c77c5583c0966151f65ef4",
        8,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/corpus/kafka_response_frames/success_response",
        "91f06235671ba18eb5f8270590be31f5ae3797ee3fdedbbaa00b29fd2ec6caf2",
        12,
        1,
        "BINARY_FILE",
    ),
    (
        "fuzz/fuzz_targets/kafka_fetch_response.rs",
        "26ba1f480788efb0579847c8de902011d467cf966cdef01b3b2910720c20344e",
        23_452,
        767,
        "UTF8_LINES",
    ),
    (
        "fuzz/fuzz_targets/messaging_kafka_record_batch.rs",
        "12c42531e21385a71975ad01b721a1090879aa244b9cd1069b12e058c5b8a957",
        8_088,
        241,
        "UTF8_LINES",
    ),
    (
        "tests/conformance/kafka_record_batch_v2/format.rs",
        "aac8c4dda43a119bcb1784b8c3b6c777a6ab2a7ff5346ae9167ed014cb43cb3e",
        20_622,
        706,
        "UTF8_LINES",
    ),
    (
        "tests/conformance/kafka_record_batch_v2/golden_tests.rs",
        "f4cb1812da5c702dd77bc37d404c38f48e7a120a49afecdeb4fba296c1eda730",
        15_550,
        439,
        "UTF8_LINES",
    ),
    (
        "tests/conformance/kafka_record_batch_v2/harness.rs",
        "fbf70b139e233a4625325447e79b83bb4c5e6becb8cf2481fd24d23103727c82",
        26_157,
        761,
        "UTF8_LINES",
    ),
    (
        "tests/conformance/kafka_record_batch_v2/mod.rs",
        "8c3a54c2981cfcecb8f1281b9bcc2bd0b6705a448311f026d5550b67613e1a4d",
        3_785,
        107,
        "UTF8_LINES",
    ),
    (
        "tests/conformance/kafka_record_batch_v2/test_vectors.rs",
        "8f846b4a1868ca6fc7cfc71924cdba2da5a130cf2ea39aaa592d52bd7b260242",
        11_040,
        344,
        "UTF8_LINES",
    ),
    (
        "tests/dependency_real_service_fixture_contract.rs",
        "1005032290ee46ec083a0e9b2a2d9310e8ea274a17c23d8052cc6168da0ca3c0",
        12_779,
        335,
        "UTF8_LINES",
    ),
    (
        "tests/kafka_capability_inventory_contract.rs",
        "204ff7d5911aa8759a9e5e87df7707e1de406dbdf92bd1ba0787a63093354634",
        28_870,
        853,
        "UTF8_LINES",
    ),
    (
        "tests/kafka_incumbent_semantics_matrix_contract.rs",
        "919826590975e812ee6cae135bca03140bdb98ea71bb79773ab21304a8165276",
        69_501,
        1_696,
        "UTF8_LINES",
    ),
    (
        "tests/kafka_record_batch_v2_integration.rs",
        "c9ee73c0a200a4f95934aa48383031fd8ccfc4f2721211977067b82c95522f23",
        1_500,
        53,
        "UTF8_LINES",
    ),
];

const FIXTURE_SCOPE_ANCHORS: &[&str] = &[
    ".github/no_mock_policy.json",
    "artifacts/adapter_certification_matrix_v1.json",
    "artifacts/dependency_real_service_fixture_matrix_v1.json",
    "conformance/src/lib.rs",
    "docs/dependency_real_service_fixtures.md",
    "tests/dependency_real_service_fixture_contract.rs",
];

const TRUTH_CLASSES: &[&str] = &[
    "CURRENT_SOURCE_PINNED",
    "LOCKFILE_DECLARED",
    "PACKAGE_SOURCE_EXPECTATION",
    "CONFIG_ONLY",
    "WIRE_CODEC_ONLY",
    "LOCAL_MODEL_ONLY",
    "OVERCLAIM",
    "STALE_CONTRADICTED",
    "UNPINNED",
    "UNKNOWN",
    "BLOCKED_EXTERNAL",
    "ACTUAL_BINARY_RECEIPT",
    "REAL_BROKER_RECEIPT",
];

const EVIDENCE_CLASSES: &[&str] = &[
    "STATIC_SOURCE",
    "LOCKFILE_DECLARED",
    "PACKAGE_SOURCE_EXPECTATION",
    "CONFIG_ONLY",
    "ACTUAL_BINARY_RECEIPT",
    "COMPILE_ONLY",
    "WIRE_CODEC_ONLY",
    "LOCAL_MODEL_ONLY",
    "MOCK_OR_SIMULATED",
    "PROOF_ONLY",
    "REAL_BROKER_CAPABLE",
    "REAL_BROKER_RECEIPT",
    "HISTORICAL",
    "PLANNED",
];

const K2_OWNERS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.2.5",
];

const K4_OWNERS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.5.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.5.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.5.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.5.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.5",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.6",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.6.7",
    "asupersync-dep-p7-kafka-removal-sarszu.2.4.7",
];

const K12_OWNERS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
];

const K13_OWNERS: &[&str] = &[
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.1",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.2",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.3",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.4",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.5",
    "asupersync-dep-p7-kafka-removal-sarszu.2.13.6",
];

const REQUIRED_FUTURE_RECEIPT_FIELDS: &[&str] = &[
    "receipt_id",
    "vector_id",
    "captured_at_utc",
    "source_revision",
    "command",
    "exit_code",
    "non_skip_assertion",
    "broker_contact_assertion",
    "broker_coordinate_id",
    "broker_semantic_version",
    "broker_binary_or_image_digest",
    "environment_id",
    "host_os",
    "host_arch",
    "target_triple",
    "rdkafka_version",
    "rdkafka_sys_version",
    "native_library_version",
    "native_library_sha256",
    "security_mode",
    "codec_mode",
    "fault_mode",
    "stdout_sha256",
    "stderr_sha256",
    "artifact_sha256",
    "cleanup_completed",
    "teardown_receipt_sha256",
    "execution_owner_bead",
];

const REQUIRED_NATIVE_BUILD_RECEIPT_FIELDS: &[&str] = &[
    "receipt_schema_version",
    "source_revision",
    "dirty or overlay path set",
    "Cargo.toml sha256",
    "Cargo.lock sha256",
    "rdkafka package id and checksum",
    "rdkafka-sys package id and checksum",
    "Cargo feature set",
    "target triple",
    "host OS and architecture",
    "kernel identity",
    "libc identity",
    "Rust toolchain",
    "C compiler identity",
    "linker identity",
    "build image or worker identity",
    "resource envelope",
    "pkg-config version and sanitized search environment",
    "selected .pc absolute path, sha256, Version, Libs, and Cflags",
    "selected native library absolute path, sha256, SONAME, and static-or-dynamic link mode",
    "native build or discovery branch",
    "configure and capability flags",
    "reported native library version and built-in feature list",
    "consuming binary sha256",
    "terminal command outcome",
];

const REQUIRED_BROKER_RECEIPT_FIELDS: &[&str] = &[
    "environment_id",
    "scenario_id",
    "immutable image repository@sha256 or equivalent immutable service identity",
    "auxiliary-service immutable identities",
    "broker vendor and reported version",
    "cluster ID",
    "negotiated API versions and canonical hash",
    "broker configuration sha256",
    "listener and advertised-listener map",
    "topology including broker, controller, leader, coordinator, partition, replication, and ISR identities",
    "security protocol",
    "certificate and public-key fingerprints",
    "certificate validity metadata",
    "SASL mechanism and principal identity",
    "non-secret credential-fixture identities",
    "semantic readiness receipt",
    "oldest-or-current support role",
];

const REQUIRED_EXECUTION_RECEIPT_FIELDS: &[&str] = &[
    "receipt_id",
    "capability_id",
    "bead_id",
    "scenario_id",
    "step_id",
    "broker_id",
    "API_id",
    "codec_id",
    "security_id",
    "fault_id",
    "UTC start timestamp",
    "UTC end timestamp",
    "source revision and every fixture pin",
    "exact sanitized command",
    "replay metadata",
    "worker or host identity",
    "client package identity",
    "actual native identity",
    "consuming binary sha256",
    "broker environment identity",
    "terminal exit status",
    "explicit non-skip assertion",
    "expected and actual result",
    "normalized outcome",
    "payload and artifact sha256 values",
    "per-process log manifest and sha256 digests",
    "message, acknowledgement, offset, partition, transaction, group-generation, reconnect, and error-taxonomy fields as applicable",
    "client-to-broker direction",
];

const REQUIRED_TEARDOWN_RECEIPT_FIELDS: &[&str] = &[
    "reverse-order teardown step IDs",
    "each teardown terminal status",
    "pre-execution resource inventory",
    "post-execution resource inventory",
    "broker, controller, network, volume, topic, credential, certificate, and generated-file residue checks",
    "residual resource count",
    "idempotent teardown retry result",
    "zero-residue assertion",
    "cleanup log sha256",
    "failure-path cleanup result",
];

const REQUIRED_REDACTION_RECEIPT_FIELDS: &[&str] = &[
    "redaction policy version",
    "secret-field allow and deny lists",
    "credential and private-key non-persistence assertion",
    "bootstrap credential redaction assertion",
    "sanitized configuration",
    "sanitized receipt sha256",
    "canary-based redaction result",
    "independent redaction verifier result",
];

const STANDALONE_GAP_OWNERS: &[&str] = &[
    "asupersync-o82yd7",
    "asupersync-messaging-resp3-kafka-commit-o9ujbk",
    "asupersync-ne8jdw",
];

const REQUIRED_CONTRADICTION_SUBJECTS: &[&str] = &[
    "SYSTEM_LIBRDKAFKA_REQUIRED",
    "CROSS_PLATFORM_SUPPORT_OVERCLAIM",
    "FULL_API_RANGE_OVERCLAIM",
    "REAL_BROKER_COMPLETENESS_OVERCLAIM",
    "PRODUCTION_HOST_GUARD_OVERCLAIM",
    "WORKFLOW_EXAMPLE_UNTRACKED",
    "PERFORMANCE_EVIDENCE_ABSENT",
    "SCENARIO_LIST_INCOMPLETE",
    "BROKER_VERSION_IDENTITY_UNKNOWN",
    "MUTABLE_CONTAINER_TAGS",
    "PUBLIC_SURFACE_BUILD_AVAILABILITY_GAP",
    "AD_HOC_CORPUS_NOT_NORMATIVE",
];

const REQUIRED_NEGATIVE_FIXTURE_IDS: &[&str] = &[
    "KAFKA-K0-4-NEG-001",
    "KAFKA-K0-4-NEG-002",
    "KAFKA-K0-4-NEG-003",
    "KAFKA-K0-4-NEG-004",
    "KAFKA-K0-4-NEG-005",
    "KAFKA-K0-4-NEG-006",
    "KAFKA-K0-4-NEG-007",
    "KAFKA-K0-4-NEG-008",
    "KAFKA-K0-4-NEG-009",
    "KAFKA-K0-4-NEG-010",
    "KAFKA-K0-4-NEG-011",
    "KAFKA-K0-4-NEG-012",
];

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

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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

fn sorted_newline_sha256(values: &BTreeSet<String>) -> String {
    let mut canonical = String::new();
    for value in values {
        canonical.push_str(value);
        canonical.push('\n');
    }
    sha256_hex(canonical.as_bytes())
}

fn tuple_sha256(rows: &[Value], fields: &[&str]) -> String {
    let mut tuples = rows
        .iter()
        .map(|row| {
            fields
                .iter()
                .map(|field| row.get(*field).and_then(Value::as_str).unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\t")
        })
        .collect::<Vec<_>>();
    tuples.sort();
    let mut canonical = tuples.join("\n");
    if !tuples.is_empty() {
        canonical.push('\n');
    }
    sha256_hex(canonical.as_bytes())
}

fn require_exact_top_level_keys(matrix: &Value) -> Result<(), String> {
    let expected = expected_set(&[
        "api_version_ranges",
        "artifact_id",
        "authority",
        "authority_revision",
        "baseline_revision",
        "bead_id",
        "broker_coordinates",
        "capability_id",
        "captured_date_utc",
        "compression_capability_cells",
        "coverage_joins",
        "coverage_receipt",
        "current_real_broker_receipts",
        "environment_identities",
        "evidence_vectors",
        "fault_restart_teardown_cells",
        "fixture_atomic_overrides",
        "fixture_groups",
        "fixture_local_rows",
        "group_topology_cells",
        "inventory_state",
        "metadata_topology_cells",
        "native_build_profiles",
        "negative_fixture_invariants",
        "no_claim_boundaries",
        "owned_unknowns",
        "owner_routing",
        "policy",
        "program_id",
        "required_future_receipt_fields",
        "routed_gaps",
        "schema_version",
        "source_contradictions",
        "source_pin_scope",
        "source_pins",
        "standalone_gap_inputs",
        "taxonomies",
        "transport_auth_cells",
        "upstream_package_provenance",
    ]);
    let actual = matrix
        .as_object()
        .ok_or_else(|| "matrix must be an object".to_owned())?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("matrix top-level key set drifted".to_owned());
    }
    Ok(())
}

fn validate_identity_authority_policy(matrix: &Value) -> Result<(), String> {
    require_exact_top_level_keys(matrix)?;
    if matrix.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("captured_date_utc", CAPTURED_DATE_UTC),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", BASELINE_REVISION),
        ("inventory_state", INVENTORY_STATE),
    ] {
        if matrix.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(matrix, "authority");
    for (key, expected) in [
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        ("k0_4_owner", BEAD_ID),
        (
            "k0_5_terminal_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.5",
        ),
        ("claim_time_refresh_owner", K14_REFRESH_OWNER),
        ("conditional_cutover_owner", K15_CUTOVER_OWNER),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    for key in [
        "dependency_exit_allowed",
        "migration_allowed",
        "removal_allowed",
        "feature_removal_allowed",
        "deletion_authority",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("authority.{key} must remain false"));
        }
    }

    let policy = object(matrix, "policy");
    for key in [
        "starts_broker_or_process",
        "starts_container",
        "network_access_performed",
        "planned_counts_as_real_broker",
        "opt_in_counts_as_real_broker",
        "silent_skip_counts_as_pass",
        "proof_only_counts_as_real_broker",
        "wire_only_counts_as_real_broker",
        "local_model_counts_as_real_broker",
        "package_source_counts_as_actual_binary",
        "mutable_tag_counts_as_immutable_identity",
        "absence_authorizes_removal",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("policy.{key} must remain false"));
        }
    }
    for key in ["repository_static_only", "unknown_blocks_migration"] {
        if policy.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("policy.{key} must remain true"));
        }
    }

    let taxonomies = object(matrix, "taxonomies");
    if string_set(&Value::Object(taxonomies.clone()), "truth_class") != expected_set(TRUTH_CLASSES)
        || string_set(&Value::Object(taxonomies.clone()), "evidence_class")
            != expected_set(EVIDENCE_CLASSES)
        || string_set(&Value::Object(taxonomies.clone()), "knowledge_state")
            != expected_set(&["KNOWN", "UNKNOWN"])
        || string_set(&Value::Object(taxonomies.clone()), "execution_state")
            != expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
        || string_set(&Value::Object(taxonomies.clone()), "freshness_state")
            != expected_set(&[
                "CURRENT_SOURCE_PINNED",
                "RERUN_REQUIRED",
                "STALE",
                "HISTORICAL",
            ])
    {
        return Err("truth/evidence/state taxonomies drifted".to_owned());
    }
    Ok(())
}

fn validate_direct_source_pins(matrix: &Value) -> Result<BTreeMap<String, String>, String> {
    let pins = array(matrix, "source_pins");
    if pins.len() != DIRECT_SOURCE_PIN_COUNT
        || row_ids(pins, "pin_id").len() != DIRECT_SOURCE_PIN_COUNT
        || row_ids(pins, "path").len() != DIRECT_SOURCE_PIN_COUNT
    {
        return Err("direct source pins must have exact unique IDs and paths".to_owned());
    }

    let expected_paths = std::iter::once(K0_3_PATH.to_owned())
        .chain(
            DIRECT_FIXTURE_PINS
                .iter()
                .map(|(path, _, _, _, _)| (*path).to_owned()),
        )
        .collect::<BTreeSet<_>>();
    if row_ids(pins, "path") != expected_paths {
        return Err("direct source-pin path set drifted".to_owned());
    }

    let mut pin_paths = BTreeMap::new();
    for pin in pins {
        let pin_id = text(pin, "pin_id");
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        if !pin_id.starts_with("KAFKA-K0-4-PIN-")
            || pin.get("byte_count").and_then(Value::as_u64) != Some(count_u64(bytes.len(), path))
            || text(pin, "sha256") != sha256_hex(&bytes)
        {
            return Err(format!("{pin_id} byte/hash receipt drifted"));
        }
        let expected_records = match text(pin, "record_count_rule") {
            "UTF8_LINES" => count_u64(
                std::str::from_utf8(&bytes)
                    .map_err(|error| format!("{path} must be UTF-8: {error}"))?
                    .lines()
                    .count(),
                path,
            ),
            "BINARY_FILE" => u64::from(!bytes.is_empty()),
            other => {
                return Err(format!(
                    "{pin_id} has unsupported record_count_rule {other}"
                ));
            }
        };
        if pin.get("record_count").and_then(Value::as_u64) != Some(expected_records) {
            return Err(format!("{pin_id} record-count receipt drifted"));
        }
        pin_paths.insert(pin_id.to_owned(), path.to_owned());
    }

    let authority_pin = find_row(pins, "path", K0_3_PATH);
    if text(authority_pin, "sha256") != K0_3_SHA256
        || text(authority_pin, "record_count_rule") != "UTF8_LINES"
    {
        return Err("K0.3 authority pin drifted".to_owned());
    }
    for (path, expected_hash, expected_bytes, expected_records, expected_rule) in
        DIRECT_FIXTURE_PINS
    {
        let pin = find_row(pins, "path", path);
        if text(pin, "sha256") != *expected_hash
            || pin.get("byte_count").and_then(Value::as_u64) != Some(*expected_bytes)
            || pin.get("record_count").and_then(Value::as_u64) != Some(*expected_records)
            || text(pin, "record_count_rule") != *expected_rule
        {
            return Err(format!("direct fixture pin {path} drifted"));
        }
    }
    Ok(pin_paths)
}

fn validate_k0_3_import_and_fixture_scope(matrix: &Value) -> Result<(), String> {
    let k0_3_bytes = read_repo_bytes(K0_3_PATH);
    if sha256_hex(&k0_3_bytes) != K0_3_SHA256 {
        return Err("K0.3 authority artifact hash drifted".to_owned());
    }
    let k0_3 = parse_repo_json(K0_3_PATH);
    for (key, expected) in [
        ("artifact_id", K0_3_ARTIFACT_ID),
        ("baseline_revision", K0_3_BASELINE_REVISION),
    ] {
        if k0_3.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("K0.3 {key} drifted"));
        }
    }

    let groups = array(&k0_3, "test_declaration_groups");
    let local_rows = array(&k0_3, "local_inventory_rows");
    let atomic_cases = array(&k0_3, "atomic_test_cases");
    let k0_3_receipt = object(&k0_3, "coverage_receipt");
    if groups.len() != K0_3_TEST_GROUP_COUNT
        || local_rows.len() != K0_3_LOCAL_ROW_COUNT
        || atomic_cases.len() != K0_3_ATOMIC_CASE_COUNT
        || k0_3_receipt
            .get("test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(K0_3_TEST_DECLARATION_COUNT, "K0.3 declarations"))
        || k0_3_receipt
            .get("exact_test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(
                K0_3_EXACT_TEST_DECLARATION_COUNT,
                "K0.3 exact tests",
            ))
        || k0_3_receipt
            .get("exact_tokio_test_declaration_count")
            .and_then(Value::as_u64)
            != Some(count_u64(
                K0_3_TOKIO_TEST_DECLARATION_COUNT,
                "K0.3 Tokio tests",
            ))
    {
        return Err("K0.3 imported counts drifted".to_owned());
    }

    let group_paths = row_ids(groups, "path");
    if sorted_newline_sha256(&group_paths) != K0_3_TEST_GROUP_PATH_SHA256
        || tuple_sha256(groups, &["path", "source_pin_id"]) != K0_3_TEST_GROUP_PATH_PIN_SHA256
        || tuple_sha256(local_rows, &["row_id", "path", "source_pin_id"])
            != K0_3_LOCAL_ROW_TUPLE_SHA256
        || tuple_sha256(atomic_cases, &["case_id", "path", "test_name"])
            != K0_3_ATOMIC_CASE_TUPLE_SHA256
        || object(&k0_3, "test_declaration_scope")
            .get("tokio_test_declaration_tuple_sha256")
            .and_then(Value::as_str)
            != Some(K0_3_TOKIO_DECLARATION_TUPLE_SHA256)
    {
        return Err("K0.3 imported tuple receipts drifted".to_owned());
    }

    let joins = object(matrix, "coverage_joins");
    let imported = joins
        .get("k0_3_import")
        .ok_or_else(|| "coverage_joins.k0_3_import is required".to_owned())?;
    for (key, expected) in [
        ("artifact_id", K0_3_ARTIFACT_ID),
        ("artifact_sha256", K0_3_SHA256),
        ("baseline_revision", K0_3_BASELINE_REVISION),
        (
            "test_declaration_group_path_sha256",
            K0_3_TEST_GROUP_PATH_SHA256,
        ),
        (
            "test_declaration_group_path_pin_sha256",
            K0_3_TEST_GROUP_PATH_PIN_SHA256,
        ),
        (
            "tokio_test_declaration_tuple_sha256",
            K0_3_TOKIO_DECLARATION_TUPLE_SHA256,
        ),
        (
            "local_inventory_row_tuple_sha256",
            K0_3_LOCAL_ROW_TUPLE_SHA256,
        ),
        ("atomic_case_tuple_sha256", K0_3_ATOMIC_CASE_TUPLE_SHA256),
    ] {
        if imported.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("coverage_joins.k0_3_import.{key} drifted"));
        }
    }
    for (key, expected) in [
        ("test_declaration_group_count", K0_3_TEST_GROUP_COUNT),
        ("test_declaration_count", K0_3_TEST_DECLARATION_COUNT),
        (
            "exact_test_declaration_count",
            K0_3_EXACT_TEST_DECLARATION_COUNT,
        ),
        (
            "exact_tokio_test_declaration_count",
            K0_3_TOKIO_TEST_DECLARATION_COUNT,
        ),
        ("local_inventory_row_count", K0_3_LOCAL_ROW_COUNT),
        ("atomic_case_count", K0_3_ATOMIC_CASE_COUNT),
    ] {
        if imported.get(key).and_then(Value::as_u64) != Some(count_u64(expected, key)) {
            return Err(format!("coverage_joins.k0_3_import.{key} drifted"));
        }
    }

    let direct_pin_paths = validate_direct_source_pins(matrix)?;
    let k0_3_pin_paths = array(&k0_3, "source_pins")
        .iter()
        .map(|pin| (text(pin, "pin_id").to_owned(), text(pin, "path").to_owned()))
        .collect::<BTreeMap<_, _>>();
    let scope = matrix
        .get("source_pin_scope")
        .ok_or_else(|| "source_pin_scope is required".to_owned())?;
    if text(scope, "authority_path") != K0_3_PATH
        || text(scope, "authority_sha256") != K0_3_SHA256
        || scope.get("fixture_path_count").and_then(Value::as_u64)
            != Some(count_u64(FIXTURE_PATH_COUNT, "fixture paths"))
        || text(scope, "fixture_path_sha256") != FIXTURE_PATH_SHA256
    {
        return Err("source-pin authority/scope receipt drifted".to_owned());
    }
    let fixture_paths = string_set(scope, "fixture_paths");
    if fixture_paths.len() != FIXTURE_PATH_COUNT
        || sorted_newline_sha256(&fixture_paths) != FIXTURE_PATH_SHA256
        || fixture_paths.contains(K0_3_PATH)
    {
        return Err("67-path fixture scope drifted".to_owned());
    }
    let inherited_ids = string_set(scope, "inherited_k0_3_source_pin_ids");
    let direct_fixture_ids = string_set(scope, "direct_fixture_pin_ids");
    if inherited_ids.len() != INHERITED_FIXTURE_PIN_COUNT
        || direct_fixture_ids.len() != DIRECT_FIXTURE_PIN_COUNT
    {
        return Err("direct fixture-pin count drifted".to_owned());
    }
    let inherited_paths = inherited_ids
        .iter()
        .map(|pin_id| {
            k0_3_pin_paths
                .get(pin_id)
                .cloned()
                .ok_or_else(|| format!("unknown inherited K0.3 pin {pin_id}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let direct_fixture_paths = direct_fixture_ids
        .iter()
        .map(|pin_id| {
            direct_pin_paths
                .get(pin_id)
                .cloned()
                .ok_or_else(|| format!("unknown direct fixture pin {pin_id}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if inherited_paths
        .union(&direct_fixture_paths)
        .cloned()
        .collect::<BTreeSet<_>>()
        != fixture_paths
        || direct_fixture_paths
            != DIRECT_FIXTURE_PINS
                .iter()
                .map(|(path, _, _, _, _)| (*path).to_owned())
                .collect()
        || !group_paths.is_subset(&fixture_paths)
        || !expected_set(FIXTURE_SCOPE_ANCHORS).is_subset(&fixture_paths)
    {
        return Err("fixture scope is not exactly covered by inherited and direct pins".to_owned());
    }

    let baseline_paths = string_set(
        k0_3.get("search_scope")
            .ok_or_else(|| "K0.3 search_scope is required".to_owned())?,
        "baseline_occurrence_paths",
    );
    let anchors = expected_set(FIXTURE_SCOPE_ANCHORS);
    if fixture_paths.iter().any(|path| {
        !(group_paths.contains(path)
            || anchors.contains(path)
            || baseline_paths.contains(path)
                && ["tests/", "fuzz/", "conformance/", "scripts/"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix)))
    }) {
        return Err("fixture scope contains a path outside the declared derivation".to_owned());
    }

    let fixture_groups = array(matrix, "fixture_groups");
    if fixture_groups.len() != K0_3_TEST_GROUP_COUNT
        || row_ids(fixture_groups, "path") != group_paths
    {
        return Err("K0.3 test-group import is incomplete".to_owned());
    }
    for fixture in fixture_groups {
        let source = find_row(groups, "path", text(fixture, "path"));
        if text(fixture, "source_pin_id") != text(source, "source_pin_id")
            || fixture.get("declared_test_count").and_then(Value::as_u64)
                != Some(count_u64(
                    array(source, "tests").len(),
                    "group declarations",
                ))
        {
            return Err(format!("fixture group {} drifted", text(fixture, "path")));
        }
    }

    let imported_local = array(matrix, "fixture_local_rows");
    if imported_local.len() != K0_3_LOCAL_ROW_COUNT
        || row_ids(imported_local, "k0_3_row_id") != row_ids(local_rows, "row_id")
    {
        return Err("K0.3 local-row import is incomplete".to_owned());
    }
    let imported_atomic = array(matrix, "fixture_atomic_overrides");
    if imported_atomic.len() != K0_3_ATOMIC_CASE_COUNT
        || row_ids(imported_atomic, "k0_3_case_id") != row_ids(atomic_cases, "case_id")
    {
        return Err("K0.3 atomic-case import is incomplete".to_owned());
    }
    Ok(())
}

fn all_later_owners(matrix: &Value) -> Result<BTreeSet<String>, String> {
    let routing = matrix
        .get("owner_routing")
        .ok_or_else(|| "owner_routing is required".to_owned())?;
    for (key, expected) in [
        ("k2", K2_OWNERS),
        ("k4", K4_OWNERS),
        ("k12", K12_OWNERS),
        ("k13", K13_OWNERS),
    ] {
        if string_set(routing, key) != expected_set(expected) {
            return Err(format!("owner_routing.{key} drifted"));
        }
    }
    if text(routing, "k14_refresh") != K14_REFRESH_OWNER
        || text(routing, "k15_cutover") != K15_CUTOVER_OWNER
    {
        return Err("K14.1/K15 routing drifted".to_owned());
    }
    Ok(K2_OWNERS
        .iter()
        .chain(K4_OWNERS)
        .chain(K12_OWNERS)
        .chain(K13_OWNERS)
        .chain([K14_REFRESH_OWNER, K15_CUTOVER_OWNER].iter())
        .map(|owner| (*owner).to_owned())
        .collect())
}

fn validate_environments_and_matrix_rows(matrix: &Value) -> Result<(), String> {
    let later_owners = all_later_owners(matrix)?;
    let direct_pins = validate_direct_source_pins(matrix)?;
    let k0_3 = parse_repo_json(K0_3_PATH);
    let inherited_pins = array(&k0_3, "source_pins")
        .iter()
        .map(|pin| text(pin, "pin_id").to_owned())
        .collect::<BTreeSet<_>>();
    let package_ids = row_ids(array(matrix, "upstream_package_provenance"), "package_id");
    let provenance_ids = direct_pins
        .keys()
        .cloned()
        .chain(inherited_pins)
        .chain(package_ids)
        .collect::<BTreeSet<_>>();
    let broker_ids = row_ids(array(matrix, "broker_coordinates"), "broker_coordinate_id");
    let build_ids = row_ids(array(matrix, "native_build_profiles"), "build_profile_id");
    let unknown_ids = row_ids(array(matrix, "owned_unknowns"), "unknown_id");
    let environments = array(matrix, "environment_identities");
    let environment_ids = row_ids(environments, "environment_id");
    if environments.is_empty() || environments.len() != environment_ids.len() {
        return Err("environment identities must be nonempty and unique".to_owned());
    }
    for environment in environments {
        let environment_id = text(environment, "environment_id");
        for key in [
            "host_os",
            "host_arch",
            "host_triple",
            "target_triple",
            "libc_abi",
            "rust_toolchain",
            "cargo_profile",
            "evidence_class",
            "knowledge_state",
            "execution_state",
        ] {
            if text(environment, key).is_empty() {
                return Err(format!("{environment_id}.{key} must be nonempty"));
            }
        }
        if text(environment, "source_revision") != BASELINE_REVISION
            || !build_ids.contains(text(environment, "native_build_profile_id"))
            || !string_set(environment, "source_pin_ids").is_subset(&provenance_ids)
            || !string_set(environment, "broker_coordinate_ids").is_subset(&broker_ids)
            || environment.get("receipt_id") != Some(&Value::Null)
        {
            return Err(format!(
                "{environment_id} identity/reference receipt drifted"
            ));
        }
    }

    let mut global_row_ids = BTreeSet::new();
    for (collection, id_key) in [
        ("native_build_profiles", "build_profile_id"),
        ("api_version_ranges", "api_range_id"),
        ("compression_capability_cells", "codec_cell_id"),
        ("transport_auth_cells", "auth_cell_id"),
        ("metadata_topology_cells", "topology_cell_id"),
        ("group_topology_cells", "topology_cell_id"),
        ("fault_restart_teardown_cells", "fault_cell_id"),
    ] {
        let rows = array(matrix, collection);
        if rows.is_empty() || rows.len() != row_ids(rows, id_key).len() {
            return Err(format!("{collection} IDs must be nonempty and unique"));
        }
        for row in rows {
            let row_id = text(row, id_key);
            if !row_id.starts_with("KAFKA-K0-4-") || !global_row_ids.insert(row_id.to_owned()) {
                return Err(format!("{row_id} must be a globally unique K0.4 row ID"));
            }
            let owner = text(row, "owner_bead");
            let execution_owner = text(row, "execution_owner_bead");
            if owner != BEAD_ID && !later_owners.contains(owner) {
                return Err(format!("{row_id} has an invalid owner"));
            }
            if !later_owners.contains(execution_owner)
                || text(row, "refresh_owner_bead") != K14_REFRESH_OWNER
                || string_set(row, "provenance_ids").is_empty()
                || !string_set(row, "provenance_ids").is_subset(&provenance_ids)
                || string_set(row, "environment_ids").is_empty()
                || !string_set(row, "environment_ids").is_subset(&environment_ids)
                || !string_set(row, "unknown_ids").is_subset(&unknown_ids)
            {
                return Err(format!(
                    "{row_id} owner/provenance/environment join drifted"
                ));
            }
            if !expected_set(TRUTH_CLASSES).contains(text(row, "truth_class"))
                || !expected_set(EVIDENCE_CLASSES).contains(text(row, "evidence_class"))
                || !expected_set(&["KNOWN", "UNKNOWN"]).contains(text(row, "knowledge_state"))
                || !expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
                    .contains(text(row, "execution_state"))
                || !expected_set(&[
                    "CURRENT_SOURCE_PINNED",
                    "RERUN_REQUIRED",
                    "STALE",
                    "HISTORICAL",
                ])
                .contains(text(row, "freshness_state"))
            {
                return Err(format!("{row_id} state taxonomy drifted"));
            }
            if text(row, "knowledge_state") == "UNKNOWN"
                && (text(row, "truth_class") != "BLOCKED"
                    || text(row, "execution_state") != "BLOCKED"
                    || string_set(row, "unknown_ids").is_empty())
            {
                return Err(format!(
                    "{row_id} UNKNOWN must fail closed as owned BLOCKED"
                ));
            }
        }
    }
    Ok(())
}

fn require_blocked_unknown(
    row: &Value,
    expected_owner: &str,
    unknown_ids: &BTreeSet<String>,
) -> Result<(), String> {
    let row_id = row
        .as_object()
        .and_then(|values| {
            values
                .iter()
                .find_map(|(key, value)| key.ends_with("_id").then(|| value.as_str()).flatten())
        })
        .unwrap_or("required-cell");
    if text(row, "truth_class") != "BLOCKED"
        || text(row, "knowledge_state") != "UNKNOWN"
        || text(row, "execution_state") != "BLOCKED"
        || text(row, "execution_owner_bead") != expected_owner
        || string_set(row, "unknown_ids").is_empty()
        || !string_set(row, "unknown_ids").is_subset(unknown_ids)
    {
        return Err(format!("{row_id} must remain owned UNKNOWN/BLOCKED"));
    }
    Ok(())
}

fn validate_required_cells(matrix: &Value) -> Result<(), String> {
    let unknown_ids = row_ids(array(matrix, "owned_unknowns"), "unknown_id");
    let brokers = array(matrix, "broker_coordinates");
    for role in ["OLDEST_SUPPORTED", "CURRENT_SUPPORTED"] {
        require_blocked_unknown(
            find_row(brokers, "coordinate_role", role),
            K13_OWNERS[0],
            &unknown_ids,
        )?;
    }
    require_blocked_unknown(
        find_row(
            array(matrix, "api_version_ranges"),
            "range_role",
            "FULL_ACCEPTED_API_RANGE",
        ),
        K2_OWNERS[0],
        &unknown_ids,
    )?;
    let auth = array(matrix, "transport_auth_cells");
    for mode in ["TLS", "SASL_SCRAM_SHA_256", "SASL_SCRAM_SHA_512"] {
        require_blocked_unknown(
            find_row(auth, "auth_mode", mode),
            K13_OWNERS[4],
            &unknown_ids,
        )?;
    }
    let faults = array(matrix, "fault_restart_teardown_cells");
    for (kind, owner) in [
        ("BROKER_RESTART", K13_OWNERS[2]),
        ("REQUEST_CANCELLATION", K13_OWNERS[4]),
        ("TEARDOWN", K13_OWNERS[5]),
    ] {
        require_blocked_unknown(find_row(faults, "fault_kind", kind), owner, &unknown_ids)?;
    }

    let codecs = array(matrix, "compression_capability_cells");
    if codecs.len() != CODEC_CELL_COUNT
        || row_ids(codecs, "codec") != expected_set(&["NONE", "GZIP", "SNAPPY", "LZ4", "ZSTD"])
    {
        return Err("compression matrix must preserve exactly five codec subjects".to_owned());
    }
    Ok(())
}

fn cargo_lock_package<'a>(lock: &'a str, name: &str) -> &'a str {
    lock.split("[[package]]")
        .find(|block| {
            block
                .lines()
                .any(|line| line == format!("name = \"{name}\""))
        })
        .unwrap_or_else(|| panic!("Cargo.lock package {name} is missing"))
}

fn validate_package_and_real_receipt_boundaries(matrix: &Value) -> Result<(), String> {
    let packages = array(matrix, "upstream_package_provenance");
    if row_ids(packages, "package_name") != expected_set(&["rdkafka", "rdkafka-sys"])
        || packages.len() != 2
        || row_ids(packages, "package_id").len() != 2
    {
        return Err("upstream package provenance must freeze rdkafka and rdkafka-sys".to_owned());
    }
    let expected = [
        (
            "rdkafka",
            "0.39.0",
            "d7956f9ac12b5712e50372d9749a3102f4810a8d42481c5eae3748d36d585bcf",
        ),
        (
            "rdkafka-sys",
            "4.10.0+2.12.1",
            "e234cf318915c1059d4921ef7f75616b5219b10b46e9f3a511a15eb4b56a3f77",
        ),
    ];
    let lock = read_repo_file("Cargo.lock");
    for (name, version, checksum) in expected {
        let row = find_row(packages, "package_name", name);
        let block = cargo_lock_package(&lock, name);
        if text(row, "version") != version
            || text(row, "cargo_lock_checksum") != checksum
            || text(row, "provenance_class") != "PACKAGE_SOURCE_EXPECTATION"
            || row.get("actual_binary_receipt_id") != Some(&Value::Null)
            || !block
                .lines()
                .any(|line| line == format!("version = \"{version}\""))
            || !block
                .lines()
                .any(|line| line == format!("checksum = \"{checksum}\""))
        {
            return Err(format!("{name} package-source provenance drifted"));
        }
    }
    let rdkafka_sys = find_row(packages, "package_name", "rdkafka-sys");
    if text(rdkafka_sys, "expected_native_source_version") != "2.12.1" {
        return Err("+2.12.1 suffix must remain a source expectation".to_owned());
    }

    if !array(matrix, "current_real_broker_receipts").is_empty() {
        return Err("current_real_broker_receipts must remain exactly empty".to_owned());
    }
    for collection in [
        "native_build_profiles",
        "broker_coordinates",
        "api_version_ranges",
        "compression_capability_cells",
        "transport_auth_cells",
        "metadata_topology_cells",
        "group_topology_cells",
        "fault_restart_teardown_cells",
        "evidence_vectors",
    ] {
        for row in array(matrix, collection) {
            if row.get("truth_class").and_then(Value::as_str) == Some("REAL")
                || row.get("evidence_class").and_then(Value::as_str) == Some("EXECUTED_REAL_BROKER")
                || row
                    .get("receipt_id")
                    .is_some_and(|receipt| !receipt.is_null())
            {
                return Err(format!(
                    "{collection} cannot claim executed real-broker evidence"
                ));
            }
            if matches!(
                row.get("evidence_class").and_then(Value::as_str),
                Some(
                    "PLANNED"
                        | "OPT_IN_REAL_BROKER_CAPABLE"
                        | "SILENT_SKIP_CAPABLE"
                        | "PROOF_ONLY"
                        | "WIRE_ONLY"
                        | "LOCAL_MODEL_ONLY"
                )
            ) && row.get("execution_state").and_then(Value::as_str) == Some("PASS")
            {
                return Err(format!("{collection} non-runtime evidence cannot be PASS"));
            }
        }
    }
    for broker in array(matrix, "broker_coordinates") {
        let image = broker
            .get("image_reference")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !image.is_empty() && !image.contains("@sha256:") {
            if bool_field(broker, "immutable_identity")
                || text(broker, "identity_state") != "MUTABLE_TAG_ONLY"
                || text(broker, "truth_class") != "BLOCKED"
            {
                return Err("mutable image tag cannot become immutable broker identity".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_vectors_unknowns_and_contradictions(matrix: &Value) -> Result<(), String> {
    let later_owners = all_later_owners(matrix)?;
    let provenance_ids = row_ids(array(matrix, "source_pins"), "pin_id")
        .into_iter()
        .chain(string_set(
            matrix
                .get("source_pin_scope")
                .ok_or_else(|| "source_pin_scope is required".to_owned())?,
            "inherited_k0_3_source_pin_ids",
        ))
        .chain(row_ids(
            array(matrix, "upstream_package_provenance"),
            "package_id",
        ))
        .collect::<BTreeSet<_>>();
    let environment_ids = row_ids(array(matrix, "environment_identities"), "environment_id");
    let broker_ids = row_ids(array(matrix, "broker_coordinates"), "broker_coordinate_id");
    let fixture_ids = row_ids(array(matrix, "fixture_groups"), "fixture_group_id");
    let unknowns = array(matrix, "owned_unknowns");
    let unknown_ids = row_ids(unknowns, "unknown_id");
    if unknowns.is_empty() || unknowns.len() != unknown_ids.len() {
        return Err("owned_unknowns must be nonempty and unique".to_owned());
    }
    for unknown in unknowns {
        if !bool_field(unknown, "blocks_migration")
            || !later_owners.contains(text(unknown, "resolution_owner_bead"))
            || string_set(unknown, "subject_ids").is_empty()
        {
            return Err(format!(
                "{} must be owned and migration-blocking",
                text(unknown, "unknown_id")
            ));
        }
    }

    let vectors = array(matrix, "evidence_vectors");
    if vectors.is_empty() || vectors.len() != row_ids(vectors, "vector_id").len() {
        return Err("evidence vectors must be nonempty and unique".to_owned());
    }
    for vector in vectors {
        let vector_id = text(vector, "vector_id");
        let owner = text(vector, "owner_bead");
        let vector_provenance_ids = string_set(vector, "provenance_ids");
        let vector_unknown_ids = string_set(vector, "unknown_ids");
        if vector_provenance_ids.is_empty()
            || !vector_provenance_ids.is_subset(&provenance_ids)
            || string_set(vector, "environment_ids").is_empty()
            || !string_set(vector, "environment_ids").is_subset(&environment_ids)
            || !string_set(vector, "broker_coordinate_ids").is_subset(&broker_ids)
            || string_set(vector, "fixture_group_ids").is_empty()
            || !string_set(vector, "fixture_group_ids").is_subset(&fixture_ids)
            || !vector_unknown_ids.is_subset(&unknown_ids)
            || (owner != BEAD_ID && !later_owners.contains(owner))
            || !later_owners.contains(text(vector, "execution_owner_bead"))
            || text(vector, "refresh_owner_bead") != K14_REFRESH_OWNER
        {
            return Err(format!("{vector_id} evidence joins drifted"));
        }
        if !expected_set(TRUTH_CLASSES).contains(text(vector, "truth_class"))
            || !expected_set(EVIDENCE_CLASSES).contains(text(vector, "evidence_class"))
            || !expected_set(&["KNOWN", "UNKNOWN"]).contains(text(vector, "knowledge_state"))
            || !expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
                .contains(text(vector, "execution_state"))
            || !expected_set(&[
                "CURRENT_SOURCE_PINNED",
                "RERUN_REQUIRED",
                "STALE",
                "HISTORICAL",
            ])
            .contains(text(vector, "freshness_state"))
        {
            return Err(format!("{vector_id} state taxonomy drifted"));
        }
        if text(vector, "knowledge_state") == "UNKNOWN"
            && (text(vector, "truth_class") != "BLOCKED"
                || text(vector, "execution_state") != "BLOCKED"
                || vector_unknown_ids.is_empty())
        {
            return Err(format!(
                "{vector_id} UNKNOWN must fail closed as owned BLOCKED"
            ));
        }
    }

    let contradictions = array(matrix, "source_contradictions");
    if row_ids(contradictions, "subject") != expected_set(REQUIRED_CONTRADICTION_SUBJECTS)
        || contradictions.len() != REQUIRED_CONTRADICTION_SUBJECTS.len()
        || row_ids(contradictions, "contradiction_id").len() != contradictions.len()
    {
        return Err("source contradiction inventory drifted".to_owned());
    }
    for contradiction in contradictions {
        if string_set(contradiction, "source_pin_ids").is_empty()
            || text(contradiction, "claim").is_empty()
            || text(contradiction, "observed_static_fact").is_empty()
            || !later_owners.contains(text(contradiction, "owner_bead"))
        {
            return Err(format!(
                "{} contradiction provenance/ownership drifted",
                text(contradiction, "contradiction_id")
            ));
        }
    }

    let standalone = array(matrix, "standalone_gap_inputs");
    if standalone.len() != row_ids(standalone, "gap_input_id").len() {
        return Err("standalone gap-input IDs must be unique".to_owned());
    }
    for gap in standalone {
        if bool_field(gap, "dependency_edge_allowed")
            || bool_field(gap, "automatically_closed_by_k0_4")
            || text(gap, "owner_bead").is_empty()
        {
            return Err("standalone gap input was promoted into K0.4 ownership".to_owned());
        }
    }
    let routed = array(matrix, "routed_gaps");
    if routed.len() != row_ids(routed, "gap_id").len() {
        return Err("routed gap IDs must be unique".to_owned());
    }
    for gap in routed {
        if !later_owners.contains(text(gap, "owner_bead"))
            || !string_set(gap, "unknown_ids").is_subset(&unknown_ids)
        {
            return Err(format!("{} routing drifted", text(gap, "gap_id")));
        }
    }
    Ok(())
}

fn validate_receipt_schema_and_coverage(matrix: &Value) -> Result<(), String> {
    if string_set(matrix, "required_future_receipt_fields")
        != expected_set(REQUIRED_FUTURE_RECEIPT_FIELDS)
    {
        return Err("required future real-broker receipt fields drifted".to_owned());
    }
    let negatives = array(matrix, "negative_fixture_invariants");
    if negatives.len() != REQUIRED_NEGATIVE_FIXTURE_IDS.len()
        || row_ids(negatives, "fixture_id") != expected_set(REQUIRED_NEGATIVE_FIXTURE_IDS)
    {
        return Err("negative fixture invariant set drifted".to_owned());
    }
    for negative in negatives {
        if text(negative, "mutation").is_empty() || text(negative, "expected_failure").is_empty() {
            return Err("negative fixture rows require mutation and expected_failure".to_owned());
        }
    }

    let receipt = object(matrix, "coverage_receipt");
    for key in ["inventory_receipt_complete", "fixture_scope_complete"] {
        if receipt.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("coverage_receipt.{key} must be true"));
        }
    }
    for key in [
        "real_broker_evidence_complete",
        "fixture_execution_performed",
        "migration_eligible",
        "dependency_exit_allowed",
    ] {
        if receipt.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("coverage_receipt.{key} must be false"));
        }
    }
    if receipt.get("source_pin_count").and_then(Value::as_u64)
        != Some(count_u64(DIRECT_SOURCE_PIN_COUNT, "source pins"))
        || receipt.get("fixture_path_count").and_then(Value::as_u64)
            != Some(count_u64(FIXTURE_PATH_COUNT, "fixture paths"))
        || receipt.get("fixture_path_sha256").and_then(Value::as_str) != Some(FIXTURE_PATH_SHA256)
        || receipt
            .get("current_real_broker_receipt_count")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err("coverage receipt fixed counts/digests drifted".to_owned());
    }

    let collection_specs = [
        ("source_pins", "pin_id"),
        ("upstream_package_provenance", "package_id"),
        ("native_build_profiles", "build_profile_id"),
        ("environment_identities", "environment_id"),
        ("broker_coordinates", "broker_coordinate_id"),
        ("api_version_ranges", "api_range_id"),
        ("compression_capability_cells", "codec_cell_id"),
        ("transport_auth_cells", "auth_cell_id"),
        ("metadata_topology_cells", "topology_cell_id"),
        ("group_topology_cells", "topology_cell_id"),
        ("fault_restart_teardown_cells", "fault_cell_id"),
        ("fixture_groups", "fixture_group_id"),
        ("fixture_local_rows", "k0_3_row_id"),
        ("fixture_atomic_overrides", "k0_3_case_id"),
        ("evidence_vectors", "vector_id"),
        ("source_contradictions", "contradiction_id"),
        ("standalone_gap_inputs", "gap_input_id"),
        ("owned_unknowns", "unknown_id"),
        ("routed_gaps", "gap_id"),
        ("negative_fixture_invariants", "fixture_id"),
        ("current_real_broker_receipts", "receipt_id"),
    ];
    let collection_receipts = array(
        receipt
            .get("collection_receipts")
            .ok_or_else(|| "coverage_receipt.collection_receipts is required".to_owned())?,
        "rows",
    );
    if collection_receipts.len() != collection_specs.len() {
        return Err("collection receipt count drifted".to_owned());
    }
    for (collection, id_key) in collection_specs {
        let rows = array(matrix, collection);
        let ids = row_ids(rows, id_key);
        let row = find_row(collection_receipts, "collection", collection);
        if row.get("row_count").and_then(Value::as_u64) != Some(count_u64(rows.len(), collection))
            || text(row, "id_set_sha256") != sorted_newline_sha256(&ids)
        {
            return Err(format!("{collection} coverage count/digest drifted"));
        }
    }
    Ok(())
}

fn validate_no_claims_and_docs(matrix: &Value) -> Result<(), String> {
    let boundaries = array(matrix, "no_claim_boundaries")
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("no_claim_boundaries entries must be strings"))
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    for fragment in [
        "native linkage",
        "broker interoperability",
        "api-version range",
        "codec",
        "tls/sasl",
        "restart",
        "fault",
        "performance",
        "broad workspace health",
        "migration",
        "removal",
        "deletion",
    ] {
        if !boundaries.contains(fragment) {
            return Err(format!("no-claim boundaries must mention {fragment}"));
        }
    }

    let doc = read_repo_file(DOC_PATH);
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("documentation markers must each occur exactly once".to_owned());
    }
    for phrase in [
        "KEEP_INCUMBENT",
        "starts no broker, process, container, or network",
        "does not prove native linkage or broker interoperability",
        "does not authorize migration, removal, or deletion",
    ] {
        if !doc.contains(phrase) {
            return Err(format!(
                "documentation must retain no-claim phrase: {phrase}"
            ));
        }
    }
    if sha256_hex(&read_repo_bytes(ARTIFACT_PATH)) != ARTIFACT_SHA256
        || sha256_hex(doc.as_bytes()) != DOC_SHA256
    {
        return Err("artifact/document golden hash drifted".to_owned());
    }
    Ok(())
}

fn actual_string_vec(value: &Value, key: &str) -> Vec<String> {
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

fn actual_require_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected_set(expected) {
        return Err(format!("{label} key set drifted"));
    }
    Ok(())
}

fn actual_require_keys_with_optional(
    value: &Value,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required = expected_set(required);
    let allowed = required
        .iter()
        .cloned()
        .chain(optional.iter().map(|key| (*key).to_owned()))
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&actual) || !actual.is_subset(&allowed) {
        return Err(format!("{label} key set drifted"));
    }
    Ok(())
}

fn actual_validate_identity(matrix: &Value) -> Result<(), String> {
    actual_require_keys(
        matrix,
        &[
            "artifact_id",
            "authority",
            "baseline_revision",
            "bead_id",
            "broker_api_version_vectors",
            "capability_id",
            "captured_date_utc",
            "compression_vectors",
            "coverage_receipt",
            "current_real_broker_receipts",
            "direct_source_pins",
            "environment_identities",
            "evidence_claims",
            "fault_lifecycle_vectors",
            "fixture_census",
            "fixture_classification_profiles",
            "inventory_state",
            "k14_1_refresh_handoff",
            "locked_dependency_identity",
            "native_build_vectors",
            "no_claim_boundaries",
            "owned_unknowns",
            "policy",
            "program_id",
            "required_future_receipt_fields",
            "routed_gaps",
            "schema_version",
            "source_contradictions",
            "source_scope",
            "taxonomies",
            "topology_vectors",
            "transport_auth_vectors",
        ],
        "matrix",
    )?;
    if matrix.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("captured_date_utc", CAPTURED_DATE_UTC),
        ("baseline_revision", BASELINE_REVISION),
        ("inventory_state", INVENTORY_STATE),
    ] {
        if matrix.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = matrix
        .get("authority")
        .ok_or_else(|| "authority is required".to_owned())?;
    actual_require_keys(
        authority,
        &[
            "api_removal_allowed",
            "capability_removal_allowed",
            "conditional_cutover_owner_bead",
            "current_action",
            "deletion_authority",
            "dependency_exit_allowed",
            "feature_removal_allowed",
            "inventory_owner_bead",
            "later_owner_preservation",
            "refresh_owner_bead",
            "registry_disposition",
        ],
        "authority",
    )?;
    for (key, expected) in [
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        ("inventory_owner_bead", BEAD_ID),
        ("refresh_owner_bead", K14_REFRESH_OWNER),
        ("conditional_cutover_owner_bead", K15_CUTOVER_OWNER),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    for key in [
        "api_removal_allowed",
        "capability_removal_allowed",
        "deletion_authority",
        "dependency_exit_allowed",
        "feature_removal_allowed",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("authority.{key} must remain false"));
        }
    }
    let owner_rows = array(authority, "later_owner_preservation");
    let expected_epics = BTreeMap::from([
        ("K2", "asupersync-dep-p7-kafka-removal-sarszu.2.2"),
        ("K4", "asupersync-dep-p7-kafka-removal-sarszu.2.4"),
        ("K12", "asupersync-dep-p7-kafka-removal-sarszu.2.12"),
        ("K13", "asupersync-dep-p7-kafka-removal-sarszu.2.13"),
        ("K14.1", K14_REFRESH_OWNER),
        ("K15", K15_CUTOVER_OWNER),
    ]);
    if owner_rows.len() != expected_epics.len() {
        return Err("later-owner family count drifted".to_owned());
    }
    for (family, bead_id) in expected_epics {
        let row = find_row(owner_rows, "owner_family", family);
        if text(row, "bead_id") != bead_id || text(row, "preserved_scope").is_empty() {
            return Err(format!("later owner {family} drifted"));
        }
    }

    let policy = matrix
        .get("policy")
        .ok_or_else(|| "policy is required".to_owned())?;
    if text(policy, "mode") != "STATIC_ONLY_FAIL_CLOSED"
        || !bool_field(policy, "source_revision_is_authoritative_for_this_packet")
    {
        return Err("static fail-closed policy drifted".to_owned());
    }
    for key in [
        "planned_or_opt_in_is_executed_evidence",
        "silent_skip_is_executed_evidence",
        "proof_schema_is_executed_broker_evidence",
        "wire_codec_is_executed_broker_evidence",
        "local_model_is_executed_broker_evidence",
        "package_coordinate_is_actual_native_identity",
        "package_source_expectation_is_actual_native_identity",
        "mutable_image_tag_is_immutable_broker_identity",
        "environment_variable_presence_is_authenticated_transport_evidence",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("policy.{key} must remain false"));
        }
    }
    for key in ["required_receipt_rule", "unknown_rule", "scope_rule"] {
        if text(policy, key).is_empty() {
            return Err(format!("policy.{key} must remain explicit"));
        }
    }

    let taxonomies = matrix
        .get("taxonomies")
        .ok_or_else(|| "taxonomies are required".to_owned())?;
    if string_set(taxonomies, "evidence_class") != expected_set(EVIDENCE_CLASSES)
        || string_set(taxonomies, "truth_class") != expected_set(TRUTH_CLASSES)
        || string_set(taxonomies, "knowledge_state")
            != expected_set(&["KNOWN", "UNKNOWN", "BLOCKED"])
        || string_set(taxonomies, "execution_state")
            != expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
        || string_set(taxonomies, "provenance_class")
            != expected_set(&[
                "SOURCE_PINNED",
                "LOCKFILE_PINNED",
                "PACKAGE_SOURCE_EXPECTATION",
                "MUTABLE_TAG",
                "AMBIENT_UNPINNED",
                "IMMUTABLE_IMAGE",
                "ACTUAL_BINARY",
                "ABSENT",
            ])
        || string_set(taxonomies, "claim_disposition")
            != expected_set(&[
                "CURRENT",
                "STALE",
                "OVERCLAIM",
                "HISTORICAL",
                "PLANNED",
                "BLOCKED",
            ])
    {
        return Err("artifact taxonomies drifted".to_owned());
    }
    Ok(())
}

fn actual_record_count(path: &str, bytes: &[u8]) -> Result<u64, String> {
    if DIRECT_FIXTURE_PINS
        .iter()
        .any(|(candidate, _, _, _, rule)| *candidate == path && *rule == "BINARY_FILE")
    {
        return Ok(u64::from(!bytes.is_empty()));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("{path} must be UTF-8 for record counting: {error}"))?;
    Ok(count_u64(source.lines().count(), path))
}

fn actual_validate_source_scope(matrix: &Value) -> Result<(), String> {
    let direct = array(matrix, "direct_source_pins");
    if direct.len() != DIRECT_SOURCE_PIN_COUNT
        || row_ids(direct, "pin_id").len() != DIRECT_SOURCE_PIN_COUNT
        || row_ids(direct, "path").len() != DIRECT_SOURCE_PIN_COUNT
    {
        return Err("direct source-pin identity/count drifted".to_owned());
    }
    for pin in direct {
        actual_require_keys(
            pin,
            &["byte_count", "path", "pin_id", "record_count", "sha256"],
            text(pin, "pin_id"),
        )?;
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        if text(pin, "sha256") != sha256_hex(&bytes)
            || pin.get("byte_count").and_then(Value::as_u64) != Some(count_u64(bytes.len(), path))
            || pin.get("record_count").and_then(Value::as_u64)
                != Some(actual_record_count(path, &bytes)?)
        {
            return Err(format!("direct source pin {path} drifted"));
        }
    }
    let authority_pin = find_row(direct, "path", K0_3_PATH);
    if text(authority_pin, "pin_id") != "KAFKA-K0-4-PIN-001-K0-3-AUTHORITY"
        || text(authority_pin, "sha256") != K0_3_SHA256
    {
        return Err("K0.3 direct authority pin drifted".to_owned());
    }
    for (path, hash, byte_count, record_count, _) in DIRECT_FIXTURE_PINS {
        let pin = find_row(direct, "path", path);
        if text(pin, "sha256") != *hash
            || pin.get("byte_count").and_then(Value::as_u64) != Some(*byte_count)
            || pin.get("record_count").and_then(Value::as_u64) != Some(*record_count)
        {
            return Err(format!("direct fixture pin {path} drifted"));
        }
    }

    let k0_3_bytes = read_repo_bytes(K0_3_PATH);
    if sha256_hex(&k0_3_bytes) != K0_3_SHA256 {
        return Err("K0.3 artifact bytes drifted".to_owned());
    }
    let k0_3 = parse_repo_json(K0_3_PATH);
    let scope = matrix
        .get("source_scope")
        .ok_or_else(|| "source_scope is required".to_owned())?;
    actual_require_keys(
        scope,
        &[
            "authority_anchor",
            "fixture_path_count",
            "fixture_path_digest_sha256",
            "fixture_paths",
            "fixture_scope_derivation",
            "inherited_counts",
            "inherited_digests",
        ],
        "source_scope",
    )?;
    let derivation = scope
        .get("fixture_scope_derivation")
        .ok_or_else(|| "source_scope.fixture_scope_derivation is required".to_owned())?;
    actual_require_keys(
        derivation,
        &[
            "authority_anchor_exclusion",
            "direct_pin_join",
            "duplicate_rule",
            "inherited_pin_join",
            "missing_rule",
            "normalization",
            "rule_a",
            "rule_b",
            "rule_c",
        ],
        "source_scope.fixture_scope_derivation",
    )?;
    for (key, expected) in [
        (
            "rule_a",
            "Take every exact path from the K0.3 authority artifact at .test_declaration_groups[].path.",
        ),
        (
            "rule_b",
            "From .search_scope.baseline_occurrence_paths[], take paths rooted at tests/, fuzz/, conformance/, or scripts/ whose case-insensitive path contains kafka or record_batch.",
        ),
        (
            "rule_c",
            "Add exactly six anchors: conformance/src/lib.rs, artifacts/dependency_real_service_fixture_matrix_v1.json, docs/dependency_real_service_fixtures.md, tests/dependency_real_service_fixture_contract.rs, .github/no_mock_policy.json, and artifacts/adapter_certification_matrix_v1.json.",
        ),
        (
            "normalization",
            "Take the bytewise sorted unique union and serialize each path as UTF-8 followed by one LF.",
        ),
        (
            "authority_anchor_exclusion",
            "artifacts/kafka_downstream_user_journey_inventory_v1.json is a direct authority pin but is not a fixture path.",
        ),
        (
            "inherited_pin_join",
            "A fixture path already present in K0.3 source_pins inherits that exact pin by path and must fail closed if the current bytes no longer match.",
        ),
        (
            "direct_pin_join",
            "A fixture path absent from K0.3 source_pins must resolve to exactly one direct_source_pins row by path; the K0.3 authority anchor is the sole direct pin intentionally outside fixture_paths.",
        ),
        (
            "duplicate_rule",
            "No path may resolve to more than one direct pin or more than one fixture-path entry.",
        ),
        (
            "missing_rule",
            "Any fixture path without an inherited or direct pin is UNKNOWN and blocks freshness admission.",
        ),
    ] {
        if derivation.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "source_scope.fixture_scope_derivation.{key} drifted"
            ));
        }
    }
    let anchor = scope
        .get("authority_anchor")
        .ok_or_else(|| "source_scope.authority_anchor is required".to_owned())?;
    for (key, expected) in [
        ("artifact_id", K0_3_ARTIFACT_ID),
        ("path", K0_3_PATH),
        ("sha256", K0_3_SHA256),
        ("authority_revision", K0_3_BASELINE_REVISION),
        ("captured_date_utc", CAPTURED_DATE_UTC),
        (
            "inventory_state",
            "K0_3_LOCAL_STATIC_AND_CALL_SITE_CENSUS_FROZEN_EXTERNAL_UNKNOWN",
        ),
    ] {
        if anchor.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("source_scope.authority_anchor.{key} drifted"));
        }
    }

    let counts = scope
        .get("inherited_counts")
        .ok_or_else(|| "inherited_counts is required".to_owned())?;
    for (key, expected) in [
        ("source_pins", 225),
        ("baseline_occurrence_paths", 245),
        ("k0_1_public_symbols", 30),
        ("k0_2_semantic_rows", 97),
        ("test_declaration_groups", K0_3_TEST_GROUP_COUNT),
        ("test_declarations", K0_3_TEST_DECLARATION_COUNT),
        ("exact_test_declarations", K0_3_EXACT_TEST_DECLARATION_COUNT),
        ("tokio_test_declarations", K0_3_TOKIO_TEST_DECLARATION_COUNT),
        ("local_inventory_rows", K0_3_LOCAL_ROW_COUNT),
        ("atomic_test_cases", K0_3_ATOMIC_CASE_COUNT),
        ("call_site_groups", 48),
        ("call_sites", 1_363),
        ("documentation_claims", 31),
        ("user_journeys", 15),
    ] {
        if counts.get(key).and_then(Value::as_u64) != Some(count_u64(expected, key)) {
            return Err(format!("source_scope.inherited_counts.{key} drifted"));
        }
    }
    let digests = scope
        .get("inherited_digests")
        .ok_or_else(|| "inherited_digests is required".to_owned())?;
    for (key, expected) in [
        (
            "baseline_occurrence_path_map_sha256",
            "9c815cfcba11f5345e7abced6b0afa21bfb650f9bb280e71bb3da74ebbb55089",
        ),
        (
            "k0_1_public_symbol_id_set_sha256",
            "307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28",
        ),
        (
            "k0_2_semantic_id_set_sha256",
            "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7",
        ),
        (
            "tokio_test_declaration_tuple_sha256",
            K0_3_TOKIO_DECLARATION_TUPLE_SHA256,
        ),
        (
            "test_declaration_group_path_sha256",
            K0_3_TEST_GROUP_PATH_SHA256,
        ),
        (
            "test_declaration_group_path_pin_sha256",
            K0_3_TEST_GROUP_PATH_PIN_SHA256,
        ),
        (
            "compilation_profile_semantic_tuple_sha256",
            "dd718eca06f6c1309e8e073dc65cc4e0c836e4705747bbaa72d7986dc1d31c61",
        ),
        (
            "call_site_id_set_sha256",
            "27ac17b660888d65f1d6a92c924becec669a96b4b1c09795450c89a350aabe2c",
        ),
        (
            "call_site_path_set_sha256",
            "612152c18e6daff98c7d0c3c7d907df8aa7100a8bab45e88a701d08588718d9c",
        ),
        (
            "downstream_helper_tuple_sha256",
            "a2c49e5cb2519afa11a2d29bee72d97c60532292b2817f725466683b3a93a777",
        ),
        (
            "provider_test_candidate_tuple_sha256",
            "1c1f5c263973f83026f7a4235cbe21252de23b4f22ba8833d5fd433659a2e255",
        ),
        (
            "documentation_candidate_path_sha256",
            "092daf94a5e428430bc2e6fab7a13a30649aca53e30680c300f9eb76cbbfec67",
        ),
        (
            "documentation_occurrence_tuple_sha256",
            "1045749285eb5a01933adfee3bd79dc34ed30f2e7cd1b7117caab51c89043dbc",
        ),
        (
            "documentation_matching_line_tuple_sha256",
            "93d84baac784b880d19fc7c790a19488d1c62547aadbce1ce5056582dafb7545",
        ),
        (
            "documentation_occurrence_id_sha256",
            "577ca40dd5f40101a2c4bdca225fcb6930ed2925353a1419404adc0ca5e30b3d",
        ),
        (
            "documentation_canonical_occurrence_id_sha256",
            "96dcbefec213d04a2a8f29e5255bf8ca1b55b229c993b9997f28c3209365c5ab",
        ),
        (
            "documentation_remainder_occurrence_id_sha256",
            "db4e006cdb3cde6fee615f3d64753df484c0848474dcd68a412ab055b0ffced0",
        ),
        (
            "documentation_group_id_sha256",
            "5e36b023be812fd3887b84af75d46e7b220c0138317b2a4face21917bdf180dd",
        ),
        (
            "documentation_source_pin_tuple_sha256",
            "24425b9d52e7f82a2f0ae596ba4a17ea55c4fdb565ca8f5b8998f334e6d6fb74",
        ),
        (
            "documentation_surface_tuple_sha256",
            "71d1cc5d04e71d3005d4449a11758af96d4d787f28bb63ec86102f902ce32970",
        ),
        (
            "documentation_actual_surface_tuple_sha256",
            "94ccd2b31c37be2c9a899d9d33cdcabc794f035107f1ca69615dbc0cc633082e",
        ),
        (
            "documentation_remainder_group_sha256",
            "a52b98d4cb5460c4731c64e085e4852990fd408196c67b9c67d46cc9c5acb7d1",
        ),
    ] {
        if digests.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("source_scope.inherited_digests.{key} drifted"));
        }
    }

    let mut expected_paths = row_ids(array(&k0_3, "test_declaration_groups"), "path");
    for path in string_set(
        k0_3.get("search_scope")
            .ok_or_else(|| "K0.3 search_scope is required".to_owned())?,
        "baseline_occurrence_paths",
    ) {
        let lower = path.to_ascii_lowercase();
        if ["tests/", "fuzz/", "conformance/", "scripts/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
            && (lower.contains("kafka") || lower.contains("record_batch"))
        {
            expected_paths.insert(path);
        }
    }
    expected_paths.extend(expected_set(FIXTURE_SCOPE_ANCHORS));
    let declared_path_vec = actual_string_vec(scope, "fixture_paths");
    let declared_paths = declared_path_vec.iter().cloned().collect::<BTreeSet<_>>();
    if declared_path_vec != declared_paths.iter().cloned().collect::<Vec<_>>()
        || declared_paths != expected_paths
        || declared_paths.len() != FIXTURE_PATH_COUNT
        || sorted_newline_sha256(&declared_paths) != FIXTURE_PATH_SHA256
        || scope.get("fixture_path_count").and_then(Value::as_u64)
            != Some(count_u64(FIXTURE_PATH_COUNT, "fixture paths"))
        || text(scope, "fixture_path_digest_sha256") != FIXTURE_PATH_SHA256
        || declared_paths.contains(K0_3_PATH)
    {
        return Err("derived 67-path fixture scope drifted".to_owned());
    }

    let direct_paths = row_ids(direct, "path");
    let direct_fixture_paths = direct_paths
        .iter()
        .filter(|path| path.as_str() != K0_3_PATH)
        .cloned()
        .collect::<BTreeSet<_>>();
    if direct_fixture_paths.len() != DIRECT_FIXTURE_PIN_COUNT
        || !direct_fixture_paths.is_subset(&declared_paths)
    {
        return Err("19-path direct fixture classification drifted".to_owned());
    }
    let inherited_paths = declared_paths
        .difference(&direct_fixture_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    if inherited_paths.len() != INHERITED_FIXTURE_PIN_COUNT {
        return Err("48-path inherited fixture classification drifted".to_owned());
    }
    let k0_3_pins = array(&k0_3, "source_pins");
    let k0_3_pin_paths = k0_3_pins
        .iter()
        .map(|pin| (text(pin, "path").to_owned(), pin))
        .collect::<BTreeMap<_, _>>();
    if k0_3_pins.len() != 225 || k0_3_pin_paths.len() != 225 {
        return Err("K0.3 source-pin paths must be unique".to_owned());
    }
    for path in inherited_paths {
        let pin = k0_3_pin_paths
            .get(&path)
            .ok_or_else(|| format!("inherited fixture {path} has no K0.3 source pin"))?;
        let bytes = read_repo_bytes(&path);
        if text(pin, "sha256") != sha256_hex(&bytes)
            || pin.get("record_count").and_then(Value::as_u64)
                != Some(actual_record_count(&path, &bytes)?)
        {
            return Err(format!("inherited K0.3 fixture pin {path} drifted"));
        }
    }
    Ok(())
}

fn actual_later_owners() -> BTreeSet<String> {
    K2_OWNERS
        .iter()
        .chain(K4_OWNERS)
        .chain(K12_OWNERS)
        .chain(K13_OWNERS)
        .chain([K14_REFRESH_OWNER, K15_CUTOVER_OWNER].iter())
        .map(|owner| (*owner).to_owned())
        .collect()
}

fn actual_validate_environments(matrix: &Value) -> Result<BTreeSet<String>, String> {
    let environments = array(matrix, "environment_identities");
    let environment_ids = row_ids(environments, "environment_id");
    let expected_environment_states = [
        (
            "KAFKA-K0-4-ENV-001-STATIC-BASELINE",
            "REPOSITORY_STATIC_BASELINE",
            "CURRENT_SOURCE_PINNED",
            "KNOWN",
            "NOT_RUN",
        ),
        (
            "KAFKA-K0-4-ENV-002-PACKAGE-SOURCE",
            "PACKAGE_SOURCE_EXPECTATION",
            "PACKAGE_SOURCE_EXPECTATION",
            "KNOWN",
            "NOT_RUN",
        ),
        (
            "KAFKA-K0-4-ENV-003-ACTUAL-BUILD-HOST",
            "ACTUAL_NATIVE_BUILD_HOST",
            "UNKNOWN",
            "BLOCKED",
            "BLOCKED",
        ),
        (
            "KAFKA-K0-4-ENV-004-MUTABLE-PROVISIONER",
            "MUTABLE_PROVISIONER_PROPOSAL",
            "UNPINNED",
            "KNOWN",
            "NOT_RUN",
        ),
        (
            "KAFKA-K0-4-ENV-005-AMBIENT-BROKER",
            "AMBIENT_BROKER",
            "UNPINNED",
            "UNKNOWN",
            "NOT_RUN",
        ),
        (
            "KAFKA-K0-4-ENV-006-OLDEST-BROKER",
            "REQUIRED_OLDEST_SUPPORTED_BROKER",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
        ),
        (
            "KAFKA-K0-4-ENV-007-CURRENT-BROKER",
            "REQUIRED_CURRENT_SUPPORTED_BROKER",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
        ),
        (
            "KAFKA-K0-4-ENV-008-AUTHENTICATED-BROKER",
            "REQUIRED_AUTHENTICATED_BROKER",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
        ),
    ];
    let declared_environment_order = environments
        .iter()
        .map(|environment| text(environment, "environment_id"))
        .collect::<Vec<_>>();
    if environments.len() != expected_environment_states.len()
        || environment_ids.len() != expected_environment_states.len()
        || declared_environment_order
            != expected_environment_states
                .iter()
                .map(|environment| environment.0)
                .collect::<Vec<_>>()
    {
        return Err("environment identity count/uniqueness drifted".to_owned());
    }
    for environment in environments {
        actual_require_keys(
            environment,
            &[
                "environment_id",
                "execution_state",
                "identity",
                "kind",
                "knowledge_state",
                "limitation",
                "source_refs",
                "truth_class",
            ],
            text(environment, "environment_id"),
        )?;
        let environment_id = text(environment, "environment_id");
        if !environment_id.starts_with("KAFKA-K0-4-ENV-")
            || text(environment, "kind").is_empty()
            || text(environment, "limitation").is_empty()
            || string_set(environment, "source_refs").is_empty()
            || !expected_set(TRUTH_CLASSES).contains(text(environment, "truth_class"))
            || !expected_set(&["KNOWN", "UNKNOWN", "BLOCKED"])
                .contains(text(environment, "knowledge_state"))
            || !expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
                .contains(text(environment, "execution_state"))
            || text(environment, "execution_state") == "PASS"
            || matches!(
                text(environment, "truth_class"),
                "ACTUAL_BINARY_RECEIPT" | "REAL_BROKER_RECEIPT"
            )
        {
            return Err(format!("{environment_id} identity/state drifted"));
        }
        if text(environment, "knowledge_state") == "BLOCKED"
            && (text(environment, "execution_state") != "BLOCKED"
                || environment.get("identity") != Some(&Value::Null))
        {
            return Err(format!("{environment_id} must remain explicitly blocked"));
        }
    }
    for (environment_id, kind, truth, knowledge, execution) in expected_environment_states {
        let environment = find_row(environments, "environment_id", environment_id);
        if text(environment, "kind") != kind
            || text(environment, "truth_class") != truth
            || text(environment, "knowledge_state") != knowledge
            || text(environment, "execution_state") != execution
        {
            return Err(format!("{environment_id} exact state drifted"));
        }
    }

    let static_environment = find_row(
        environments,
        "environment_id",
        "KAFKA-K0-4-ENV-001-STATIC-BASELINE",
    );
    let static_identity = static_environment
        .get("identity")
        .ok_or_else(|| "static environment identity is required".to_owned())?;
    if text(static_identity, "revision") != BASELINE_REVISION
        || text(static_identity, "captured_date_utc") != CAPTURED_DATE_UTC
    {
        return Err("static baseline environment drifted".to_owned());
    }
    let package_environment = find_row(
        environments,
        "environment_id",
        "KAFKA-K0-4-ENV-002-PACKAGE-SOURCE",
    );
    let package_identity = package_environment
        .get("identity")
        .ok_or_else(|| "package environment identity is required".to_owned())?;
    actual_require_keys(
        package_identity,
        &[
            "actual_execution_receipt",
            "expected_branch",
            "expected_build_mechanism",
            "expected_disabled_capabilities",
            "expected_source_capabilities",
            "rdkafka_default_features",
            "rdkafka_package_checksum",
            "rdkafka_package_name",
            "rdkafka_package_version",
            "rdkafka_sys_package_checksum",
            "rdkafka_sys_package_name",
            "rdkafka_sys_package_version",
            "rdkafka_to_rdkafka_sys_default_features",
            "rust_rdkafka_vcs_commit",
            "vendored_header_version",
            "vendored_header_version_hex",
        ],
        "package-source identity",
    )?;
    for (key, expected) in [
        ("rdkafka_package_name", "rdkafka"),
        ("rdkafka_package_version", "0.39.0"),
        (
            "rdkafka_package_checksum",
            "d7956f9ac12b5712e50372d9749a3102f4810a8d42481c5eae3748d36d585bcf",
        ),
        ("rdkafka_sys_package_name", "rdkafka-sys"),
        ("rdkafka_sys_package_version", "4.10.0+2.12.1"),
        (
            "rdkafka_sys_package_checksum",
            "e234cf318915c1059d4921ef7f75616b5219b10b46e9f3a511a15eb4b56a3f77",
        ),
        (
            "rust_rdkafka_vcs_commit",
            "47a17d8de72b8bfa89589a84a4a0c600c54df1e0",
        ),
        ("vendored_header_version_hex", "0x020c01ff"),
        ("vendored_header_version", "2.12.1"),
        ("expected_branch", "VENDORED_STATIC"),
        ("expected_build_mechanism", "configure+make"),
    ] {
        if package_identity.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("package environment {key} drifted"));
        }
    }
    if package_identity.get("rdkafka_default_features") != Some(&Value::Bool(false))
        || package_identity.get("rdkafka_to_rdkafka_sys_default_features")
            != Some(&Value::Bool(false))
        || package_identity.get("actual_execution_receipt") != Some(&Value::Null)
        || string_set(package_identity, "expected_disabled_capabilities")
            != expected_set(&["SSL", "GSSAPI", "zlib", "curl", "Zstd", "external LZ4"])
        || string_set(package_identity, "expected_source_capabilities")
            != expected_set(&["built-in Snappy", "internal LZ4 1.9.4"])
    {
        return Err("package-source capability expectation drifted".to_owned());
    }
    let mutable_environment = find_row(
        environments,
        "environment_id",
        "KAFKA-K0-4-ENV-004-MUTABLE-PROVISIONER",
    );
    let mutable_identity = mutable_environment
        .get("identity")
        .ok_or_else(|| "mutable provisioner identity is required".to_owned())?;
    if text(mutable_identity, "kafka_image") != "confluentinc/cp-kafka:7.4.0"
        || text(mutable_identity, "zookeeper_image") != "confluentinc/cp-zookeeper:7.4.0"
        || mutable_identity.get("image_digests") != Some(&Value::Null)
        || text(mutable_environment, "truth_class") != "UNPINNED"
    {
        return Err("mutable provisioner must not become immutable identity".to_owned());
    }
    let known_source_ids = row_ids(array(matrix, "direct_source_pins"), "pin_id");
    for environment in environments {
        for reference in actual_string_vec(environment, "source_refs") {
            if !actual_source_ref_resolves(&reference, &known_source_ids) {
                return Err(format!(
                    "{} has unresolved source ref {reference}",
                    text(environment, "environment_id")
                ));
            }
        }
    }
    Ok(environment_ids)
}

fn actual_source_ref_resolves(reference: &str, known_ids: &BTreeSet<String>) -> bool {
    if known_ids.contains(reference)
        || matches!(
            reference,
            "source_scope.fixture_paths" | "direct_source_pins" | "current_real_broker_receipts"
        )
    {
        return true;
    }
    if reference.starts_with("rdkafka-sys-4.10.0+2.12.1/") {
        return true;
    }
    let path = reference
        .split_once(':')
        .map_or(reference, |(path, _)| path);
    repo_root().join(path).is_file()
}

fn actual_validate_vectors(matrix: &Value) -> Result<BTreeSet<String>, String> {
    let environment_ids = actual_validate_environments(matrix)?;
    let direct_pin_ids = row_ids(array(matrix, "direct_source_pins"), "pin_id");
    let provenance_ids = environment_ids
        .iter()
        .cloned()
        .chain(direct_pin_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let later_owners = actual_later_owners();
    let specs = [
        ("locked_dependency_identity", 3),
        ("native_build_vectors", 5),
        ("broker_api_version_vectors", 7),
        ("compression_vectors", 5),
        ("transport_auth_vectors", 6),
        ("topology_vectors", 4),
        ("fault_lifecycle_vectors", 6),
    ];
    let mut all_vector_ids = BTreeSet::new();
    let mut state_owner_environment_tuples = BTreeSet::new();
    for (collection, expected_count) in specs {
        let rows = array(matrix, collection);
        if rows.len() != expected_count || rows.len() != row_ids(rows, "vector_id").len() {
            return Err(format!("{collection} count/ID uniqueness drifted"));
        }
        for row in rows {
            let vector_id = text(row, "vector_id");
            actual_require_keys_with_optional(
                row,
                &[
                    "current_evidence",
                    "environment_ids",
                    "executable_owner",
                    "execution_state",
                    "inventory_owner",
                    "knowledge_state",
                    "limitation",
                    "provenance_refs",
                    "refresh_owner",
                    "source_refs",
                    "subject",
                    "truth_class",
                    "vector_id",
                ],
                &["actual_execution_receipt", "evidence_class"],
                vector_id,
            )?;
            let row_environments = string_set(row, "environment_ids");
            let row_provenance = string_set(row, "provenance_refs");
            if !all_vector_ids.insert(vector_id.to_owned())
                || !vector_id.starts_with("KAFKA-K0-4-")
                || text(row, "subject").is_empty()
                || text(row, "current_evidence").is_empty()
                || text(row, "limitation").is_empty()
                || string_set(row, "source_refs").is_empty()
                || row_environments.is_empty()
                || !row_environments.is_subset(&environment_ids)
                || row_provenance.is_empty()
                || !row_provenance.is_subset(&provenance_ids)
                || text(row, "inventory_owner") != BEAD_ID
                || !later_owners.contains(text(row, "executable_owner"))
                || text(row, "refresh_owner") != K14_REFRESH_OWNER
                || !expected_set(TRUTH_CLASSES).contains(text(row, "truth_class"))
                || !expected_set(&["KNOWN", "UNKNOWN", "BLOCKED"])
                    .contains(text(row, "knowledge_state"))
                || !expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
                    .contains(text(row, "execution_state"))
                || row
                    .get("actual_execution_receipt")
                    .is_some_and(|receipt| !receipt.is_null())
                || row.get("evidence_class").is_some_and(|evidence| {
                    evidence
                        .as_str()
                        .is_none_or(|class| !expected_set(EVIDENCE_CLASSES).contains(class))
                })
            {
                return Err(format!("{vector_id} vector contract drifted"));
            }
            if text(row, "execution_state") == "PASS"
                || matches!(
                    text(row, "truth_class"),
                    "ACTUAL_BINARY_RECEIPT" | "REAL_BROKER_RECEIPT"
                )
                || matches!(
                    row.get("evidence_class").and_then(Value::as_str),
                    Some("ACTUAL_BINARY_RECEIPT" | "REAL_BROKER_RECEIPT")
                )
                || (text(row, "knowledge_state") == "BLOCKED"
                    && text(row, "execution_state") != "BLOCKED")
            {
                return Err(format!("{vector_id} improperly promotes absent execution"));
            }
            state_owner_environment_tuples.insert(
                [
                    collection.to_owned(),
                    vector_id.to_owned(),
                    text(row, "truth_class").to_owned(),
                    text(row, "knowledge_state").to_owned(),
                    text(row, "execution_state").to_owned(),
                    row_environments
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                    row_provenance.iter().cloned().collect::<Vec<_>>().join(","),
                    text(row, "inventory_owner").to_owned(),
                    text(row, "executable_owner").to_owned(),
                    text(row, "refresh_owner").to_owned(),
                ]
                .join("\u{1f}"),
            );
        }
    }
    if sorted_newline_sha256(&state_owner_environment_tuples) != VECTOR_STATE_OWNER_ENV_TUPLE_SHA256
    {
        return Err("vector state/owner/environment matrix drifted".to_owned());
    }

    let mut known_source_ids = all_vector_ids.clone();
    known_source_ids.extend(environment_ids);
    known_source_ids.extend(direct_pin_ids);
    for collection in [
        "locked_dependency_identity",
        "native_build_vectors",
        "broker_api_version_vectors",
        "compression_vectors",
        "transport_auth_vectors",
        "topology_vectors",
        "fault_lifecycle_vectors",
    ] {
        for row in array(matrix, collection) {
            for reference in actual_string_vec(row, "source_refs") {
                if !actual_source_ref_resolves(&reference, &known_source_ids) {
                    return Err(format!(
                        "{} has unresolved source ref {reference}",
                        text(row, "vector_id")
                    ));
                }
            }
        }
    }

    let codecs = array(matrix, "compression_vectors");
    if row_ids(codecs, "subject")
        != expected_set(&[
            "None compression",
            "Gzip compression",
            "Snappy compression",
            "Lz4 compression",
            "Zstd compression",
        ])
    {
        return Err("exact five-codec subject set drifted".to_owned());
    }
    for (collection, vector_id, truth, knowledge, execution, owner) in [
        (
            "native_build_vectors",
            "KAFKA-K0-4-NATIVE-003-ACTUAL-LIBRARY",
            "UNKNOWN",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[0],
        ),
        (
            "broker_api_version_vectors",
            "KAFKA-K0-4-BROKER-003-OLDEST",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[0],
        ),
        (
            "broker_api_version_vectors",
            "KAFKA-K0-4-BROKER-004-CURRENT",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[0],
        ),
        (
            "broker_api_version_vectors",
            "KAFKA-K0-4-API-001-NEGOTIATION",
            "UNKNOWN",
            "BLOCKED",
            "BLOCKED",
            K2_OWNERS[0],
        ),
        (
            "transport_auth_vectors",
            "KAFKA-K0-4-AUTH-002-TLS",
            "CONFIG_ONLY",
            "UNKNOWN",
            "NOT_RUN",
            K13_OWNERS[4],
        ),
        (
            "transport_auth_vectors",
            "KAFKA-K0-4-AUTH-003-SCRAM-SHA-256",
            "CONFIG_ONLY",
            "UNKNOWN",
            "NOT_RUN",
            K13_OWNERS[4],
        ),
        (
            "transport_auth_vectors",
            "KAFKA-K0-4-AUTH-004-SCRAM-SHA-512",
            "CONFIG_ONLY",
            "UNKNOWN",
            "NOT_RUN",
            K13_OWNERS[4],
        ),
        (
            "transport_auth_vectors",
            "KAFKA-K0-4-AUTH-006-NEGATIVE-MATRIX",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[4],
        ),
        (
            "fault_lifecycle_vectors",
            "KAFKA-K0-4-FAULT-003-RESTART",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[2],
        ),
        (
            "fault_lifecycle_vectors",
            "KAFKA-K0-4-FAULT-005-TEARDOWN",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[5],
        ),
        (
            "fault_lifecycle_vectors",
            "KAFKA-K0-4-FAULT-006-CANCELLATION-RECONCILIATION",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            K13_OWNERS[2],
        ),
    ] {
        let row = find_row(array(matrix, collection), "vector_id", vector_id);
        if text(row, "truth_class") != truth
            || text(row, "knowledge_state") != knowledge
            || text(row, "execution_state") != execution
            || text(row, "executable_owner") != owner
        {
            return Err(format!("required missing cell {vector_id} drifted"));
        }
    }
    Ok(all_vector_ids)
}

fn actual_validate_fixture_census(matrix: &Value) -> Result<(), String> {
    let environment_ids = row_ids(array(matrix, "environment_identities"), "environment_id");
    let later_owners = actual_later_owners();
    let profiles = array(matrix, "fixture_classification_profiles");
    let profile_ids = row_ids(profiles, "classification_profile_id");
    let expected_profiles: &[(&str, &str, &str, &str, &str, &[&str], &str)] = &[
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-001-POLICY-CONTEXT",
            "STATIC_SOURCE",
            "CURRENT_SOURCE_PINNED",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-001-STATIC-BASELINE"],
            K14_REFRESH_OWNER,
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-002-COMPILE-STATIC-CONTRACT",
            "COMPILE_ONLY",
            "CURRENT_SOURCE_PINNED",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-001-STATIC-BASELINE"],
            K12_OWNERS[4],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-003-LOCAL-MODEL",
            "LOCAL_MODEL_ONLY",
            "LOCAL_MODEL_ONLY",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-001-STATIC-BASELINE"],
            K12_OWNERS[4],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-004-WIRE-CORPUS",
            "WIRE_CODEC_ONLY",
            "WIRE_CODEC_ONLY",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-001-STATIC-BASELINE"],
            K12_OWNERS[2],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-005-RECORD-BATCH-LOCAL-MODEL",
            "WIRE_CODEC_ONLY",
            "LOCAL_MODEL_ONLY",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-001-STATIC-BASELINE"],
            K12_OWNERS[0],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-006-PROOF-ONLY",
            "PROOF_ONLY",
            "CURRENT_SOURCE_PINNED",
            "KNOWN",
            "NOT_RUN",
            &[
                "KAFKA-K0-4-ENV-001-STATIC-BASELINE",
                "KAFKA-K0-4-ENV-005-AMBIENT-BROKER",
            ],
            K13_OWNERS[5],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-007-PLANNED-PROVISIONER",
            "PLANNED",
            "UNPINNED",
            "KNOWN",
            "NOT_RUN",
            &["KAFKA-K0-4-ENV-004-MUTABLE-PROVISIONER"],
            K13_OWNERS[0],
        ),
        (
            "KAFKA-K0-4-FIXTURE-PROFILE-008-OPT-IN-REAL-BROKER",
            "REAL_BROKER_CAPABLE",
            "BLOCKED_EXTERNAL",
            "BLOCKED",
            "BLOCKED",
            &[
                "KAFKA-K0-4-ENV-005-AMBIENT-BROKER",
                "KAFKA-K0-4-ENV-006-OLDEST-BROKER",
                "KAFKA-K0-4-ENV-007-CURRENT-BROKER",
            ],
            K13_OWNERS[5],
        ),
    ];
    let declared_profile_order = profiles
        .iter()
        .map(|profile| text(profile, "classification_profile_id"))
        .collect::<Vec<_>>();
    let expected_profile_order = expected_profiles
        .iter()
        .map(|profile| profile.0)
        .collect::<Vec<_>>();
    if profiles.len() != expected_profiles.len()
        || profile_ids.len() != expected_profiles.len()
        || declared_profile_order != expected_profile_order
    {
        return Err("fixture classification profile count/uniqueness drifted".to_owned());
    }
    for profile in profiles {
        let profile_id = text(profile, "classification_profile_id");
        actual_require_keys(
            profile,
            &[
                "classification_profile_id",
                "environment_ids",
                "evidence_class",
                "executable_owner",
                "execution_state",
                "inventory_owner",
                "knowledge_state",
                "limitation",
                "refresh_owner",
                "truth_class",
            ],
            profile_id,
        )?;
        let profile_environments = string_set(profile, "environment_ids");
        if !profile_id.starts_with("KAFKA-K0-4-FIXTURE-PROFILE-")
            || !expected_set(EVIDENCE_CLASSES).contains(text(profile, "evidence_class"))
            || !expected_set(TRUTH_CLASSES).contains(text(profile, "truth_class"))
            || !expected_set(&["KNOWN", "UNKNOWN", "BLOCKED"])
                .contains(text(profile, "knowledge_state"))
            || !expected_set(&["NOT_RUN", "PASS", "FAIL", "BLOCKED", "UNSUPPORTED"])
                .contains(text(profile, "execution_state"))
            || profile_environments.is_empty()
            || !profile_environments.is_subset(&environment_ids)
            || text(profile, "inventory_owner") != BEAD_ID
            || !later_owners.contains(text(profile, "executable_owner"))
            || text(profile, "refresh_owner") != K14_REFRESH_OWNER
            || text(profile, "limitation").is_empty()
            || text(profile, "execution_state") == "PASS"
            || matches!(
                text(profile, "truth_class"),
                "ACTUAL_BINARY_RECEIPT" | "REAL_BROKER_RECEIPT"
            )
            || matches!(
                text(profile, "evidence_class"),
                "ACTUAL_BINARY_RECEIPT" | "REAL_BROKER_RECEIPT"
            )
        {
            return Err(format!("fixture profile {profile_id} drifted"));
        }
        if text(profile, "knowledge_state") == "BLOCKED"
            && text(profile, "execution_state") != "BLOCKED"
        {
            return Err(format!("fixture profile {profile_id} must fail closed"));
        }
    }
    for (profile_id, evidence, truth, knowledge, execution, environments, owner) in
        expected_profiles
    {
        let profile = find_row(profiles, "classification_profile_id", profile_id);
        if text(profile, "evidence_class") != *evidence
            || text(profile, "truth_class") != *truth
            || text(profile, "knowledge_state") != *knowledge
            || text(profile, "execution_state") != *execution
            || string_set(profile, "environment_ids") != expected_set(environments)
            || text(profile, "executable_owner") != *owner
        {
            return Err(format!(
                "fixture profile {profile_id} classification drifted"
            ));
        }
    }

    let scope = matrix
        .get("source_scope")
        .ok_or_else(|| "source_scope is required".to_owned())?;
    let scope_path_order = actual_string_vec(scope, "fixture_paths");
    let scope_paths = scope_path_order.iter().cloned().collect::<BTreeSet<_>>();
    let direct_pins = array(matrix, "direct_source_pins");
    let direct_by_path = direct_pins
        .iter()
        .filter(|pin| text(pin, "path") != K0_3_PATH)
        .map(|pin| (text(pin, "path").to_owned(), text(pin, "pin_id").to_owned()))
        .collect::<BTreeMap<_, _>>();
    let k0_3 = parse_repo_json(K0_3_PATH);
    let inherited_by_path = array(&k0_3, "source_pins")
        .iter()
        .map(|pin| (text(pin, "path").to_owned(), text(pin, "pin_id").to_owned()))
        .collect::<BTreeMap<_, _>>();
    let census = array(matrix, "fixture_census");
    let declared_fixture_order = census
        .iter()
        .map(|fixture| text(fixture, "fixture_id"))
        .collect::<Vec<_>>();
    let declared_census_path_order = census
        .iter()
        .map(|fixture| text(fixture, "path").to_owned())
        .collect::<Vec<_>>();
    if census.len() != FIXTURE_PATH_COUNT
        || row_ids(census, "fixture_id").len() != FIXTURE_PATH_COUNT
        || row_ids(census, "path") != scope_paths
        || declared_census_path_order != scope_path_order
    {
        return Err("67-row fixture census identity/path join drifted".to_owned());
    }
    let expected_fixture_order = (1..=FIXTURE_PATH_COUNT)
        .map(|index| format!("KAFKA-K0-4-FIXTURE-{index:03}"))
        .collect::<Vec<_>>();
    if declared_fixture_order
        != expected_fixture_order
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err("fixture census stable ID set drifted".to_owned());
    }
    let census_tuples = census
        .iter()
        .map(|fixture| {
            [
                text(fixture, "fixture_id"),
                text(fixture, "path"),
                text(fixture, "pin_origin"),
                text(fixture, "source_pin_id"),
                text(fixture, "classification_profile_id"),
            ]
            .join("\u{1f}")
        })
        .collect::<BTreeSet<_>>();
    if sorted_newline_sha256(&census_tuples) != FIXTURE_CENSUS_TUPLE_SHA256 {
        return Err("exact fixture census tuple digest drifted".to_owned());
    }
    let mut inherited_count = 0;
    let mut direct_count = 0;
    let mut profile_counts = BTreeMap::<String, usize>::new();
    for fixture in census {
        let fixture_id = text(fixture, "fixture_id");
        actual_require_keys(
            fixture,
            &[
                "classification_profile_id",
                "fixture_id",
                "path",
                "pin_origin",
                "source_pin_id",
            ],
            fixture_id,
        )?;
        let path = text(fixture, "path");
        let source_pin_id = text(fixture, "source_pin_id");
        let profile_id = text(fixture, "classification_profile_id");
        if !profile_ids.contains(profile_id) {
            return Err(format!("{fixture_id} has unknown classification profile"));
        }
        *profile_counts.entry(profile_id.to_owned()).or_default() += 1;
        match text(fixture, "pin_origin") {
            "K0_3_INHERITED" => {
                inherited_count += 1;
                if inherited_by_path.get(path).map(String::as_str) != Some(source_pin_id)
                    || direct_by_path.contains_key(path)
                {
                    return Err(format!("{fixture_id} inherited pin join drifted"));
                }
            }
            "K0_4_DIRECT" => {
                direct_count += 1;
                if direct_by_path.get(path).map(String::as_str) != Some(source_pin_id) {
                    return Err(format!("{fixture_id} direct pin join drifted"));
                }
            }
            other => return Err(format!("{fixture_id} has invalid pin_origin {other}")),
        }
    }
    if inherited_count != INHERITED_FIXTURE_PIN_COUNT
        || direct_count != DIRECT_FIXTURE_PIN_COUNT
        || profile_counts.values().sum::<usize>() != FIXTURE_PATH_COUNT
        || profile_counts.len() != profiles.len()
    {
        return Err("fixture census origin/profile partition drifted".to_owned());
    }
    let expected_profile_counts = BTreeMap::from([
        (expected_profiles[0].0.to_owned(), 5),
        (expected_profiles[1].0.to_owned(), 18),
        (expected_profiles[2].0.to_owned(), 14),
        (expected_profiles[3].0.to_owned(), 14),
        (expected_profiles[4].0.to_owned(), 8),
        (expected_profiles[5].0.to_owned(), 2),
        (expected_profiles[6].0.to_owned(), 1),
        (expected_profiles[7].0.to_owned(), 5),
    ]);
    if profile_counts != expected_profile_counts {
        return Err("exact fixture profile partition drifted".to_owned());
    }

    let coverage = matrix
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt is required".to_owned())?;
    actual_require_keys(
        coverage,
        &[
            "actual_binary_receipt_count",
            "authority_anchor_count",
            "broker_api_version_vector_count",
            "compression_vector_count",
            "current_real_broker_receipt_count",
            "direct_fixture_pin_count",
            "direct_source_pin_count",
            "executed_broker_evidence_count",
            "fault_lifecycle_vector_count",
            "fixture_census_count",
            "fixture_classification_profile_count",
            "fixture_path_count",
            "fixture_path_digest_sha256",
            "fixture_profile_counts",
            "inherited_fixture_pin_count",
            "limitation",
            "locked_dependency_vector_count",
            "native_build_vector_count",
            "source_contradiction_count",
            "source_revision",
            "status",
            "topology_vector_count",
            "transport_auth_vector_count",
            "validation_mode",
        ],
        "coverage_receipt",
    )?;
    if coverage
        .get("inherited_fixture_pin_count")
        .and_then(Value::as_u64)
        != Some(count_u64(INHERITED_FIXTURE_PIN_COUNT, "inherited fixtures"))
        || coverage
            .get("fixture_classification_profile_count")
            .and_then(Value::as_u64)
            != Some(count_u64(profiles.len(), "fixture profiles"))
        || coverage.get("fixture_census_count").and_then(Value::as_u64)
            != Some(count_u64(census.len(), "fixture census"))
    {
        return Err("fixture coverage receipt counts drifted".to_owned());
    }
    let declared_profile_counts = coverage
        .get("fixture_profile_counts")
        .and_then(Value::as_object)
        .ok_or_else(|| "coverage_receipt.fixture_profile_counts is required".to_owned())?;
    if declared_profile_counts.len() != profile_counts.len() {
        return Err("fixture profile receipt key set drifted".to_owned());
    }
    for (profile_id, count) in profile_counts {
        if declared_profile_counts
            .get(&profile_id)
            .and_then(Value::as_u64)
            != Some(count_u64(count, &profile_id))
        {
            return Err(format!("fixture profile count {profile_id} drifted"));
        }
    }
    Ok(())
}

fn actual_validate_claims_unknowns_and_routes(matrix: &Value) -> Result<(), String> {
    let vector_ids = actual_validate_vectors(matrix)?;
    let environment_ids = row_ids(array(matrix, "environment_identities"), "environment_id");
    let direct_pin_ids = row_ids(array(matrix, "direct_source_pins"), "pin_id");
    let later_owners = actual_later_owners();

    let unknowns = array(matrix, "owned_unknowns");
    let unknown_ids = row_ids(unknowns, "unknown_id");
    if unknowns.len() != 9 || unknown_ids.len() != 9 {
        return Err("owned unknown count/uniqueness drifted".to_owned());
    }
    for unknown in unknowns {
        actual_require_keys(
            unknown,
            &[
                "knowledge_state",
                "owner_bead",
                "resolution_owner_bead",
                "subject",
                "unknown_id",
            ],
            text(unknown, "unknown_id"),
        )?;
        if text(unknown, "knowledge_state") != "BLOCKED"
            || text(unknown, "owner_bead") != BEAD_ID
            || !later_owners.contains(text(unknown, "resolution_owner_bead"))
            || text(unknown, "subject").is_empty()
        {
            return Err(format!(
                "{} ownership/state drifted",
                text(unknown, "unknown_id")
            ));
        }
    }

    let contradictions = array(matrix, "source_contradictions");
    let contradiction_ids = row_ids(contradictions, "contradiction_id");
    if contradictions.len() != 11 || contradiction_ids.len() != 11 {
        return Err("source contradiction count/uniqueness drifted".to_owned());
    }
    let mut source_ids = vector_ids.clone();
    source_ids.extend(environment_ids);
    source_ids.extend(direct_pin_ids);
    source_ids.extend(contradiction_ids.clone());
    for contradiction in contradictions {
        actual_require_keys(
            contradiction,
            &[
                "contradiction_id",
                "finding",
                "kind",
                "limitation",
                "owner_bead",
                "source_refs",
                "truth_class",
            ],
            text(contradiction, "contradiction_id"),
        )?;
        let owner = text(contradiction, "owner_bead");
        if text(contradiction, "kind").is_empty()
            || text(contradiction, "finding").is_empty()
            || text(contradiction, "limitation").is_empty()
            || !expected_set(TRUTH_CLASSES).contains(text(contradiction, "truth_class"))
            || (owner != BEAD_ID && !later_owners.contains(owner))
            || string_set(contradiction, "source_refs").is_empty()
        {
            return Err(format!(
                "{} contradiction drifted",
                text(contradiction, "contradiction_id")
            ));
        }
        for reference in actual_string_vec(contradiction, "source_refs") {
            if !actual_source_ref_resolves(&reference, &source_ids) {
                return Err(format!(
                    "{} has unresolved source ref {reference}",
                    text(contradiction, "contradiction_id")
                ));
            }
        }
    }

    let claims = array(matrix, "evidence_claims");
    if claims.len() != 6 || row_ids(claims, "claim_id").len() != 6 {
        return Err("evidence claim count/uniqueness drifted".to_owned());
    }
    for claim in claims {
        actual_require_keys(
            claim,
            &[
                "claim_id",
                "evidence_class",
                "limitation",
                "source_refs",
                "statement",
            ],
            text(claim, "claim_id"),
        )?;
        if !expected_set(EVIDENCE_CLASSES).contains(text(claim, "evidence_class"))
            || matches!(
                text(claim, "evidence_class"),
                "REAL_BROKER_RECEIPT" | "ACTUAL_BINARY_RECEIPT"
            )
            || text(claim, "statement").is_empty()
            || text(claim, "limitation").is_empty()
            || string_set(claim, "source_refs").is_empty()
        {
            return Err(format!(
                "{} evidence claim drifted",
                text(claim, "claim_id")
            ));
        }
        for reference in actual_string_vec(claim, "source_refs") {
            if !actual_source_ref_resolves(&reference, &source_ids) {
                return Err(format!(
                    "{} has unresolved source ref {reference}",
                    text(claim, "claim_id")
                ));
            }
        }
    }

    let routed = array(matrix, "routed_gaps");
    if routed.len() != 26 || row_ids(routed, "gap_id").len() != 26 {
        return Err("routed gap count/uniqueness drifted".to_owned());
    }
    let standalone = expected_set(STANDALONE_GAP_OWNERS);
    for gap in routed {
        let owner = text(gap, "owner_bead");
        if text(gap, "route").is_empty()
            || (!later_owners.contains(owner) && !standalone.contains(owner))
        {
            return Err(format!("{} route/owner drifted", text(gap, "gap_id")));
        }
        match gap.get("relation") {
            Some(Value::String(relation)) => {
                if relation != "INVENTORY_INPUT_ONLY" || !standalone.contains(owner) {
                    return Err(format!("{} relation drifted", text(gap, "gap_id")));
                }
            }
            Some(_) => return Err(format!("{} relation must be text", text(gap, "gap_id"))),
            None if standalone.contains(owner) => {
                return Err(format!(
                    "{} standalone relation is missing",
                    text(gap, "gap_id")
                ));
            }
            None => {}
        }
    }
    let cancellation = find_row(routed, "gap_id", "KAFKA-K0-4-GAP-012-GROUPS");
    if text(cancellation, "owner_bead") != K13_OWNERS[3]
        || !text(cancellation, "route")
            .to_ascii_lowercase()
            .contains("cancellation")
    {
        return Err("cancellation obligation routing drifted".to_owned());
    }
    for owner in [
        K2_OWNERS[3],
        K4_OWNERS[0],
        K4_OWNERS[2],
        K4_OWNERS[3],
        K4_OWNERS[7],
        K4_OWNERS[14],
        K12_OWNERS[1],
    ] {
        if !routed.iter().any(|gap| text(gap, "owner_bead") == owner) {
            return Err(format!("required child route owner {owner} is missing"));
        }
    }

    let handoff = matrix
        .get("k14_1_refresh_handoff")
        .ok_or_else(|| "k14_1_refresh_handoff is required".to_owned())?;
    if text(handoff, "owner_bead") != K14_REFRESH_OWNER
        || bool_field(handoff, "carry_forward_allowed")
        || text(handoff, "required_at").is_empty()
        || array(handoff, "refresh_steps").len() != 10
        || array(handoff, "drift_failures").len() != 10
    {
        return Err("K14.1 refresh handoff drifted".to_owned());
    }
    Ok(())
}

fn actual_validate_future_receipt_fields(matrix: &Value) -> Result<(), String> {
    let required = matrix
        .get("required_future_receipt_fields")
        .ok_or_else(|| "required_future_receipt_fields is required".to_owned())?;
    actual_require_keys(
        required,
        &[
            "broker",
            "execution",
            "native_build",
            "redaction",
            "teardown",
        ],
        "required_future_receipt_fields",
    )?;
    for (group, expected) in [
        ("native_build", REQUIRED_NATIVE_BUILD_RECEIPT_FIELDS),
        ("broker", REQUIRED_BROKER_RECEIPT_FIELDS),
        ("execution", REQUIRED_EXECUTION_RECEIPT_FIELDS),
        ("teardown", REQUIRED_TEARDOWN_RECEIPT_FIELDS),
        ("redaction", REQUIRED_REDACTION_RECEIPT_FIELDS),
    ] {
        if string_set(required, group) != expected_set(expected)
            || array(required, group).len() != expected.len()
        {
            return Err(format!("required_future_receipt_fields.{group} drifted"));
        }
    }
    Ok(())
}

fn actual_validate_coverage_and_no_claims(matrix: &Value) -> Result<(), String> {
    if !array(matrix, "current_real_broker_receipts").is_empty() {
        return Err("current_real_broker_receipts must remain exactly empty".to_owned());
    }
    let coverage = matrix
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt is required".to_owned())?;
    for (key, expected) in [
        ("authority_anchor_count", 1),
        ("direct_source_pin_count", DIRECT_SOURCE_PIN_COUNT),
        ("direct_fixture_pin_count", DIRECT_FIXTURE_PIN_COUNT),
        ("inherited_fixture_pin_count", INHERITED_FIXTURE_PIN_COUNT),
        ("fixture_path_count", FIXTURE_PATH_COUNT),
        ("fixture_classification_profile_count", 8),
        ("fixture_census_count", FIXTURE_PATH_COUNT),
        ("locked_dependency_vector_count", 3),
        ("native_build_vector_count", 5),
        ("broker_api_version_vector_count", 7),
        ("compression_vector_count", 5),
        ("transport_auth_vector_count", 6),
        ("topology_vector_count", 4),
        ("fault_lifecycle_vector_count", 6),
        ("source_contradiction_count", 11),
        ("current_real_broker_receipt_count", 0),
        ("executed_broker_evidence_count", 0),
        ("actual_binary_receipt_count", 0),
    ] {
        if coverage.get(key).and_then(Value::as_u64) != Some(count_u64(expected, key)) {
            return Err(format!("coverage_receipt.{key} drifted"));
        }
    }
    for (key, expected) in [
        ("source_revision", BASELINE_REVISION),
        ("fixture_path_digest_sha256", FIXTURE_PATH_SHA256),
        ("validation_mode", "STATIC_JSON_AND_EXACT_FILE_DIFF_ONLY"),
        (
            "status",
            "STATIC_INVENTORY_COMPLETE_RUNTIME_PROVENANCE_BLOCKED",
        ),
    ] {
        if coverage.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("coverage_receipt.{key} drifted"));
        }
    }
    if text(coverage, "limitation").is_empty() {
        return Err("coverage_receipt limitation is required".to_owned());
    }

    let boundaries = array(matrix, "no_claim_boundaries")
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("no_claim_boundaries entries must be strings"))
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if array(matrix, "no_claim_boundaries").len() != 22 {
        return Err("no-claim boundary count drifted".to_owned());
    }
    for fragment in [
        "compiled",
        "native",
        "broker interoperability",
        "api-version ranges",
        "compression",
        "tls",
        "sasl",
        "restart",
        "fault",
        "performance",
        "broad workspace health",
        "remove",
    ] {
        if !boundaries.contains(fragment) {
            return Err(format!("no-claim boundaries must retain {fragment}"));
        }
    }

    let doc = read_repo_file(DOC_PATH);
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("documentation markers must each occur exactly once".to_owned());
    }
    for phrase in [
        "KEEP_INCUMBENT",
        "starts no broker, process, container, or network",
        "does not prove native linkage or broker interoperability",
        "does not authorize migration, removal, or deletion",
    ] {
        if !doc.contains(phrase) {
            return Err(format!(
                "documentation must retain no-claim phrase: {phrase}"
            ));
        }
    }
    if sha256_hex(&read_repo_bytes(ARTIFACT_PATH)) != ARTIFACT_SHA256
        || sha256_hex(doc.as_bytes()) != DOC_SHA256
    {
        return Err("artifact/document golden hash drifted".to_owned());
    }
    Ok(())
}

fn validate_matrix(matrix: &Value) -> Result<(), String> {
    actual_validate_identity(matrix)?;
    actual_validate_source_scope(matrix)?;
    actual_validate_fixture_census(matrix)?;
    actual_validate_environments(matrix)?;
    actual_validate_vectors(matrix)?;
    actual_validate_claims_unknowns_and_routes(matrix)?;
    actual_validate_future_receipt_fields(matrix)?;
    actual_validate_coverage_and_no_claims(matrix)?;
    Ok(())
}

#[test]
fn kafka_broker_fixture_provenance_matrix_is_acceptance_complete_and_fail_closed() {
    validate_matrix(&artifact()).expect("Kafka K0.4 provenance matrix must remain valid");
}

#[test]
fn source_scope_is_exactly_k0_3_plus_nineteen_direct_fixture_pins() {
    let matrix = artifact();
    actual_validate_source_scope(&matrix)
        .expect("K0.3 imports and the 67-path fixture scope must remain exact");
    actual_validate_fixture_census(&matrix)
        .expect("the 67-row fixture census and eight profiles must remain exact");
}

#[test]
fn no_static_or_skippable_evidence_can_be_promoted_to_real_broker_evidence() {
    let matrix = artifact();
    actual_validate_vectors(&matrix).expect("vector evidence must remain static and fail closed");
    actual_validate_coverage_and_no_claims(&matrix)
        .expect("real-broker and actual-binary receipts must remain absent");

    let mut promoted = matrix.clone();
    promoted["locked_dependency_identity"][0]["truth_class"] =
        Value::String("REAL_BROKER_RECEIPT".to_owned());
    promoted["locked_dependency_identity"][0]["execution_state"] = Value::String("PASS".to_owned());
    assert!(actual_validate_vectors(&promoted).is_err());

    let mut package_promoted = matrix.clone();
    package_promoted["native_build_vectors"][0]["actual_execution_receipt"] =
        Value::String("invented-receipt".to_owned());
    assert!(actual_validate_vectors(&package_promoted).is_err());

    let mut receipt_promoted = matrix;
    receipt_promoted["current_real_broker_receipts"] =
        Value::Array(vec![Value::String("invented-receipt".to_owned())]);
    assert!(actual_validate_coverage_and_no_claims(&receipt_promoted).is_err());
}

#[test]
fn unknown_environment_and_source_scope_mutations_fail_closed() {
    let matrix = artifact();

    let mut orphan_environment = matrix.clone();
    orphan_environment["broker_api_version_vectors"][0]["environment_ids"] =
        Value::Array(vec![Value::String("missing-environment".to_owned())]);
    assert!(actual_validate_vectors(&orphan_environment).is_err());

    let mut scope_drift = matrix.clone();
    scope_drift["source_scope"]["fixture_path_digest_sha256"] = Value::String(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
    );
    assert!(actual_validate_source_scope(&scope_drift).is_err());

    let mut exit_promoted = matrix;
    exit_promoted["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(actual_validate_identity(&exit_promoted).is_err());
}
