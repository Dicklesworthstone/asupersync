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
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json";
const DOC_PATH: &str = "docs/kafka_k2_reachable_schema_broker_matrix.md";
const ARTIFACT_SHA256: &str = "c95e5acb199878716063e467fa0cdf35eba13056a40dcef00643c9d3a8f834e9";
const DOC_SHA256: &str = "949f40c1c68009357dc38ea108509d8a51b63e43e7fc7a39feaa2c52cb42785f";

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
    "field_error_projection_source_rows",
    "field_projection_rows",
    "header_contract",
    "historical_profile_api_range_rows",
    "historical_schema_source_contracts",
    "historical_schema_source_rows",
    "incumbent_source_observations",
    "inventory_state",
    "no_claim_boundaries",
    "parent_bead_id",
    "policy",
    "program_id",
    "reachable_api_rows",
    "schema_source_identity_contract",
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
    (23, "OffsetForLeaderEpoch", true, 2, "2-4", "2", Some(4)),
    (24, "AddPartitionsToTxn", true, 0, "0-5", "0", Some(3)),
    (25, "AddOffsetsToTxn", true, 0, "0-4", "0", Some(3)),
    (26, "EndTxn", true, 1, "0-5", "0-1", Some(3)),
    (28, "TxnOffsetCommit", true, 3, "0-5", "0-3", Some(3)),
    (36, "SaslAuthenticate", true, 1, "0-2", "0-1", Some(2)),
    (71, "GetTelemetrySubscriptions", false, 0, "0", "0", Some(0)),
    (72, "PushTelemetry", false, 0, "0", "0", Some(0)),
];

const SCHEMA_SOURCE_IDENTITY_KEYS: &[&str] = &[
    "canonical_root_tree",
    "current_schema_file_count",
    "historical_schema_file_count",
    "identity_domain",
    "identity_scheme",
    "path_root",
    "payload_normalization",
    "recursive_tree_truncated",
    "schema_pair_count",
    "sorted_path_object_id_size_projection_sha256",
    "sorted_projection_encoding",
    "source_authority_id",
    "source_commit",
    "state",
    "total_payload_byte_count",
];

const EXPECTED_SCHEMA_SOURCES: &[(u64, &str, &str, u64, &str, u64)] = &[
    (
        0,
        "KAFKA-K2-1-SCHEMA-000-PRODUCE",
        "3b46a1ff5f46805ce192c90b0025ac85944e0d92",
        4_011,
        "adf08e94a35d4719519d0df5652f8f6eb6a816a7",
        6_128,
    ),
    (
        1,
        "KAFKA-K2-1-SCHEMA-001-FETCH",
        "9ebf86ac424c95e2ec0602e505eb38f73565a926",
        8_063,
        "36dc05ff60ca421d5efad5032805e5fa38926714",
        7_753,
    ),
    (
        2,
        "KAFKA-K2-1-SCHEMA-002-LIST-OFFSETS",
        "1a2de6ca30a2fa91c32904cd9930682acd86b7d7",
        3_727,
        "1407273bf4d8c7e9100faf566542f982a6a402f0",
        3_372,
    ),
    (
        3,
        "KAFKA-K2-1-SCHEMA-003-METADATA",
        "349f88b7c64d2ddbe8003a25a29824f738f4af36",
        2_958,
        "07ee7010e5e540845a50816921723ca193e9b40e",
        6_026,
    ),
    (
        8,
        "KAFKA-K2-1-SCHEMA-008-OFFSET-COMMIT",
        "bf15153be0897b3c903d9f554057a25b9b463164",
        3_952,
        "0228733ce6bb039bc421af8b541fccc9d28ae24a",
        3_442,
    ),
    (
        9,
        "KAFKA-K2-1-SCHEMA-009-OFFSET-FETCH",
        "5f6ead1ef7cfa876039737fdbe05f04fbe681cca",
        4_184,
        "91de93441e5ae1b512cf970143891f4d728bfdff",
        5_641,
    ),
    (
        10,
        "KAFKA-K2-1-SCHEMA-010-FIND-COORDINATOR",
        "2807f40c857af9d46b8582a1d2d98b110f795b83",
        1_788,
        "40c43b65f9ccfddc8d224266da55589a7cf8b0ec",
        3_074,
    ),
    (
        11,
        "KAFKA-K2-1-SCHEMA-011-JOIN-GROUP",
        "31afdb1a32ae8dcaf27843d1b1bf553711971df1",
        3_305,
        "d2f016f62f66c75b4681db5d12144acef5b046ce",
        3_405,
    ),
    (
        12,
        "KAFKA-K2-1-SCHEMA-012-HEARTBEAT",
        "57ef18e922471dffb1ac4166824598906ef68946",
        1_733,
        "280ba1103b437562f8e71ea0374c06eecf71de8e",
        1_638,
    ),
    (
        13,
        "KAFKA-K2-1-SCHEMA-013-LEAVE-GROUP",
        "929f4fb468c95c916eb7e2acb93892e6719c0d06",
        2_137,
        "d3c8784b04f790dc3c1aff494d6c70cd0731fa89",
        2_223,
    ),
    (
        14,
        "KAFKA-K2-1-SCHEMA-014-SYNC-GROUP",
        "1b53df27757f28b6709ac8f8ecf7620750003a47",
        2_726,
        "4aa17e0d79ad983a9b33af5c0c80f1372e25667f",
        2_233,
    ),
    (
        17,
        "KAFKA-K2-1-SCHEMA-017-SASL-HANDSHAKE",
        "d2189d826ead18f0453a3c451a0c3bbb547a3389",
        1_313,
        "a1567c6692169e86cd24b984dd2836a47a8a10cf",
        1_398,
    ),
    (
        18,
        "KAFKA-K2-1-SCHEMA-018-API-VERSIONS",
        "56170c9667350df0b4ac2511075fd832cb608d3a",
        1_535,
        "1017f2443604740abad4dea8c1a69076cc6595b2",
        4_478,
    ),
    (
        22,
        "KAFKA-K2-1-SCHEMA-022-INIT-PRODUCER-ID",
        "e8ab48b399b74c833aadb7e80bc8b775d74aa06f",
        2_764,
        "c070c92f4e0ed3c31e94354f4bbd9cc5b2923f5f",
        2_498,
    ),
    (
        23,
        "KAFKA-K2-1-SCHEMA-023-OFFSET-FOR-LEADER-EPOCH",
        "dd559bc8777f83c492956e6b0d2f6b26985e91dd",
        2_820,
        "f82aa09b7ed843916ca056bd19780e5bcd30502c",
        2_487,
    ),
    (
        24,
        "KAFKA-K2-1-SCHEMA-024-ADD-PARTITIONS-TO-TXN",
        "68a45cdd0aca2a0d3ebcd8c1b118acb92e712911",
        3_573,
        "a621740decc14a204ec6632b327494992d0739a1",
        3_107,
    ),
    (
        25,
        "KAFKA-K2-1-SCHEMA-025-ADD-OFFSETS-TO-TXN",
        "9bebc8366cf1db2ccbb41986e2e71b9108499e4d",
        1_823,
        "6a713fea1af62325b0b5fb826956201476cdcbb9",
        1_602,
    ),
    (
        26,
        "KAFKA-K2-1-SCHEMA-026-END-TXN",
        "f11c7a3268f131b3842951756de915e019e29dc0",
        1_884,
        "7f9017eda74342353dd32fc27ad64ed0d3041d60",
        2_059,
    ),
    (
        28,
        "KAFKA-K2-1-SCHEMA-028-TXN-OFFSET-COMMIT",
        "59a1f05e0972fb51828d33e8c3ff7163bfe646bb",
        3_793,
        "9769ed2aa97bb97b9af2e6b88c418e44032a19a1",
        2_259,
    ),
    (
        36,
        "KAFKA-K2-1-SCHEMA-036-SASL-AUTHENTICATE",
        "cdb4247b8a95ac5fe825bfe52be499197660c815",
        1_234,
        "edf383b9c58d4980c3d3b293398dc1a1360e0f37",
        1_731,
    ),
    (
        71,
        "KAFKA-K2-1-SCHEMA-071-GET-TELEMETRY-SUBSCRIPTIONS",
        "3f2c5f99e4c0018b605cf83a12ebfff7d3c9a2d5",
        1_150,
        "7fc6af81aa896de75e2bcc4ee65ee94534677bca",
        2_640,
    ),
    (
        72,
        "KAFKA-K2-1-SCHEMA-072-PUSH-TELEMETRY",
        "dd39bbf1ce6e93efe316e13d0519844862fd32be",
        1_693,
        "56ddfe8bc4737aee1f46a3d28c2c24f104a82d7e",
        1_314,
    ),
];

const HISTORICAL_CONTRACT_KEYS: &[&str] = &[
    "api_range_row_count",
    "blocking_observations",
    "canonical_root_tree",
    "covered_api_keys",
    "full_frontier_blocker",
    "full_frontier_state",
    "nested_payload_state",
    "profile_id",
    "recursive_tree_truncated",
    "schema_declaration_model",
    "semantic_role_projection_encoding",
    "scope_state",
    "sorted_path_object_id_size_projection_sha256",
    "sorted_path_semantic_role_projection_sha256",
    "sorted_projection_encoding",
    "source_authority_id",
    "source_commit",
    "source_file_count",
    "source_tree_entry_count",
    "total_payload_byte_count",
];

const HISTORICAL_SOURCE_ROW_KEYS: &[&str] = &[
    "byte_count",
    "git_blob_sha1",
    "path",
    "profile_id",
    "semantic_role",
    "source_authority_id",
];

const HISTORICAL_RANGE_ROW_KEYS: &[&str] = &[
    "accepted_version_range",
    "api_key",
    "api_name",
    "broker_declared_versions",
    "incumbent_candidate_intersection",
    "profile_id",
    "source_authority_id",
    "state",
];

const FIELD_ERROR_PROJECTION_SOURCE_KEYS: &[&str] = &[
    "byte_count",
    "git_blob_sha1",
    "path",
    "semantic_role",
    "source_authority_id",
    "source_id",
];

const FIELD_PROJECTION_ROW_KEYS: &[&str] = &[
    "accepted_version_range",
    "api_key",
    "canonical_field_id",
    "direction",
    "element_type",
    "error_set_id",
    "effective_default_literal",
    "effective_default_state",
    "effective_default_versions",
    "excluded_source_versions",
    "field_order",
    "ignorable_versions",
    "logical_type",
    "map_key",
    "nested_projection_state",
    "nested_type_name",
    "nullable_versions",
    "owning_struct_tag_buffer_projected_versions",
    "parent_row_id",
    "profile_id",
    "projected_compact_versions",
    "projected_tag_ids",
    "projected_tagged_versions",
    "projected_versions",
    "projection_state",
    "row_id",
    "schema_default_literal",
    "schema_default_state",
    "sensitivity",
    "source_authority_id",
    "source_declared_versions",
    "source_field_name",
    "source_refs",
    "source_versions",
    "version_exclusion_state",
    "wire_type",
];

const ERROR_PROJECTION_ROW_KEYS: &[&str] = &[
    "accepted_version_range",
    "api_comment_error_code",
    "api_key",
    "canonical_error_code",
    "code_consistency_state",
    "downgrade_policy_state",
    "enum_membership_state",
    "error_name",
    "error_set_id",
    "excluded_source_versions",
    "membership_basis",
    "outcome_class",
    "profile_id",
    "projected_versions",
    "projection_state",
    "retry_policy_state",
    "row_id",
    "source_authority_id",
    "source_refs",
    "source_versions",
    "wire_enum_closed",
];

const EXPECTED_PROJECTION_SOURCES: &[(&str, &str, &str, &str, u64, &str)] = &[
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-ERRORS",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
        "a27a7fcf23c77ce01da71a002901195b32f831c8",
        36_636,
        "CANONICAL_ERROR_ENUM",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-MESSAGE-DEFINITION-README",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/resources/common/message/README.md",
        "ee6de73dee663b7696ff8832335d9089e2a26cd7",
        12_494,
        "MESSAGE_DEFAULT_FLEXIBLE_AND_TAG_SEMANTICS",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-FIELD-SPEC",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "generator/src/main/java/org/apache/kafka/message/FieldSpec.java",
        "fcbfc2f8ed3affc4c65abcf623ea15206d825420",
        28_231,
        "GENERATED_FIELD_DEFAULT_RESOLUTION",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-MESSAGE-DATA-GENERATOR",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "generator/src/main/java/org/apache/kafka/message/MessageDataGenerator.java",
        "8d2e4e09c54f85c69fdd18cdb296a29e7af9be7d",
        89_368,
        "GENERATED_DEFAULT_ASSIGNMENT_AND_ABSENT_VERSION_RESET",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-SASL-AUTHENTICATE-RESPONSE",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
        "12d16ee41843ea96bde8d40b960ce12656d1027a",
        2_843,
        "API_036_ERROR_MEMBERSHIP_AND_COMMENT_CONFLICT",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-SASL-HANDSHAKE-REQUEST",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeRequest.java",
        "710700257ab34e7123abe88420db07327dd18aa9",
        3_023,
        "API_017_EXCEPTION_TO_ERROR_MAPPING",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-SASL-HANDSHAKE-RESPONSE",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
        "40de2ceff30ddf7d0e651cecc6d3e65ae9847a55",
        2_536,
        "API_017_ERROR_MEMBERSHIP",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-CURRENT-SASL-SERVER-AUTHENTICATOR",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        "b84b5dc2abc94d2b86b6c1e377c8e2c6cf272dee",
        38_132,
        "CURRENT_DEDICATED_HANDLER_OUTCOMES",
    ),
    (
        "KAFKA-K2-1-PROJECTION-SOURCE-HISTORICAL-SASL-SERVER-AUTHENTICATOR",
        "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        "1a2aaf497b9ca02eeb715639b6bb7fefcd5723b2",
        25_876,
        "HISTORICAL_DEDICATED_HANDLER_OUTCOMES",
    ),
];

struct ExpectedFieldProjection {
    row_id: &'static str,
    profile_id: &'static str,
    authority_id: &'static str,
    source_refs: &'static [&'static str],
    api_key: u64,
    direction: &'static str,
    canonical_field_id: &'static str,
    source_field_name: &'static str,
    field_order: u64,
    source_versions: &'static str,
    projected_versions: &'static str,
    excluded_versions: &'static str,
    logical_type: &'static str,
    wire_type: &'static str,
    element_type: Option<&'static str>,
    nullable_versions: &'static str,
    default_state: &'static str,
    default_literal: Option<&'static str>,
    ignorable_versions: &'static str,
    sensitivity: &'static str,
    error_set_id: Option<&'static str>,
    nested_projection_state: &'static str,
}

const EXPECTED_FIELD_PROJECTIONS: &[ExpectedFieldProjection] = &[
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-017-REQUEST-000-MECHANISM",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &["clients/src/main/resources/common/message/SaslHandshakeRequest.json"],
        api_key: 17,
        direction: "REQUEST",
        canonical_field_id: "API17.REQUEST.MECHANISM",
        source_field_name: "Mechanism",
        field_order: 0,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "STRING",
        wire_type: "STRING",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "AUTH_NEGOTIATION_METADATA",
        error_set_id: None,
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-017-RESPONSE-000-ERROR-CODE",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &["clients/src/main/resources/common/message/SaslHandshakeResponse.json"],
        api_key: 17,
        direction: "RESPONSE",
        canonical_field_id: "API17.RESPONSE.ERROR_CODE",
        source_field_name: "ErrorCode",
        field_order: 0,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "INT16",
        wire_type: "INT16",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "NON_SECRET_CONTROL_METADATA",
        error_set_id: Some("KAFKA-K2-1-ERROR-SET-CURRENT-API-017"),
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-017-RESPONSE-001-MECHANISMS",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &["clients/src/main/resources/common/message/SaslHandshakeResponse.json"],
        api_key: 17,
        direction: "RESPONSE",
        canonical_field_id: "API17.RESPONSE.MECHANISMS",
        source_field_name: "Mechanisms",
        field_order: 1,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "ARRAY",
        wire_type: "ARRAY",
        element_type: Some("STRING"),
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "AUTH_NEGOTIATION_METADATA",
        error_set_id: None,
        nested_projection_state: "SCALAR_STRING_ELEMENT_PROJECTED",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-036-REQUEST-000-AUTH-BYTES",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/resources/common/message/SaslAuthenticateRequest.json",
            "clients/src/main/resources/common/message/README.md",
        ],
        api_key: 36,
        direction: "REQUEST",
        canonical_field_id: "API36.REQUEST.AUTH_BYTES",
        source_field_name: "AuthBytes",
        field_order: 0,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        logical_type: "BYTES",
        wire_type: "BYTES",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SECRET_BEARING_OPAQUE_AUTH_MATERIAL",
        error_set_id: None,
        nested_projection_state: "OPAQUE_SASL_MECHANISM_BYTES_NOT_PROJECTED",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-000-ERROR-CODE",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/resources/common/message/SaslAuthenticateResponse.json",
            "clients/src/main/resources/common/message/README.md",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.ERROR_CODE",
        source_field_name: "ErrorCode",
        field_order: 0,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        logical_type: "INT16",
        wire_type: "INT16",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "NON_SECRET_CONTROL_METADATA",
        error_set_id: Some("KAFKA-K2-1-ERROR-SET-CURRENT-API-036"),
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-001-ERROR-MESSAGE",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/resources/common/message/SaslAuthenticateResponse.json",
            "clients/src/main/resources/common/message/README.md",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.ERROR_MESSAGE",
        source_field_name: "ErrorMessage",
        field_order: 1,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        logical_type: "STRING",
        wire_type: "NULLABLE_STRING",
        element_type: None,
        nullable_versions: "0-2",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SENSITIVE_DIAGNOSTIC_REDACT",
        error_set_id: None,
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-002-AUTH-BYTES",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/resources/common/message/SaslAuthenticateResponse.json",
            "clients/src/main/resources/common/message/README.md",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.AUTH_BYTES",
        source_field_name: "AuthBytes",
        field_order: 2,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        logical_type: "BYTES",
        wire_type: "BYTES",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SECRET_BEARING_OPAQUE_AUTH_MATERIAL",
        error_set_id: None,
        nested_projection_state: "OPAQUE_SASL_MECHANISM_BYTES_NOT_PROJECTED",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-003-SESSION-LIFETIME-MS",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/resources/common/message/SaslAuthenticateResponse.json",
            "clients/src/main/resources/common/message/README.md",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.SESSION_LIFETIME_MS",
        source_field_name: "SessionLifetimeMs",
        field_order: 3,
        source_versions: "1-2",
        projected_versions: "1-2",
        excluded_versions: "none",
        logical_type: "INT64",
        wire_type: "INT64",
        element_type: None,
        nullable_versions: "none",
        default_state: "EXPLICIT_LITERAL",
        default_literal: Some("0"),
        ignorable_versions: "1-2",
        sensitivity: "NON_SECRET_CONTROL_METADATA",
        error_set_id: None,
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-017-REQUEST-000-MECHANISM",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeRequest.java",
        ],
        api_key: 17,
        direction: "REQUEST",
        canonical_field_id: "API17.REQUEST.MECHANISM",
        source_field_name: "mechanism",
        field_order: 0,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "STRING",
        wire_type: "STRING",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "AUTH_NEGOTIATION_METADATA",
        error_set_id: None,
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-017-RESPONSE-000-ERROR-CODE",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/CommonFields.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
        ],
        api_key: 17,
        direction: "RESPONSE",
        canonical_field_id: "API17.RESPONSE.ERROR_CODE",
        source_field_name: "error_code",
        field_order: 0,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "INT16",
        wire_type: "INT16",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "NON_SECRET_CONTROL_METADATA",
        error_set_id: Some("KAFKA-K2-1-ERROR-SET-HISTORICAL-API-017"),
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-017-RESPONSE-001-MECHANISMS",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
        ],
        api_key: 17,
        direction: "RESPONSE",
        canonical_field_id: "API17.RESPONSE.MECHANISMS",
        source_field_name: "enabled_mechanisms",
        field_order: 1,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        logical_type: "ARRAY",
        wire_type: "ARRAY",
        element_type: Some("STRING"),
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "AUTH_NEGOTIATION_METADATA",
        error_set_id: None,
        nested_projection_state: "SCALAR_STRING_ELEMENT_PROJECTED",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-036-REQUEST-000-AUTH-BYTES",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateRequest.java",
        ],
        api_key: 36,
        direction: "REQUEST",
        canonical_field_id: "API36.REQUEST.AUTH_BYTES",
        source_field_name: "sasl_auth_bytes",
        field_order: 0,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        logical_type: "BYTES",
        wire_type: "BYTES",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SECRET_BEARING_OPAQUE_AUTH_MATERIAL",
        error_set_id: None,
        nested_projection_state: "OPAQUE_SASL_MECHANISM_BYTES_NOT_PROJECTED",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-000-ERROR-CODE",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/CommonFields.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.ERROR_CODE",
        source_field_name: "error_code",
        field_order: 0,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        logical_type: "INT16",
        wire_type: "INT16",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "NON_SECRET_CONTROL_METADATA",
        error_set_id: Some("KAFKA-K2-1-ERROR-SET-HISTORICAL-API-036"),
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-001-ERROR-MESSAGE",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/CommonFields.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.ERROR_MESSAGE",
        source_field_name: "error_message",
        field_order: 1,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        logical_type: "STRING",
        wire_type: "NULLABLE_STRING",
        element_type: None,
        nullable_versions: "0",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SENSITIVE_DIAGNOSTIC_REDACT",
        error_set_id: None,
        nested_projection_state: "NOT_APPLICABLE",
    },
    ExpectedFieldProjection {
        row_id: "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-002-AUTH-BYTES",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
        ],
        api_key: 36,
        direction: "RESPONSE",
        canonical_field_id: "API36.RESPONSE.AUTH_BYTES",
        source_field_name: "sasl_auth_bytes",
        field_order: 2,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        logical_type: "BYTES",
        wire_type: "BYTES",
        element_type: None,
        nullable_versions: "none",
        default_state: "NOT_EXPLICITLY_DECLARED",
        default_literal: None,
        ignorable_versions: "none",
        sensitivity: "SECRET_BEARING_OPAQUE_AUTH_MATERIAL",
        error_set_id: None,
        nested_projection_state: "OPAQUE_SASL_MECHANISM_BYTES_NOT_PROJECTED",
    },
];

const EXPECTED_API10_FIELD_ROW_IDS: &[&str] = &[
    "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-000-KEY",
    "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-001-KEY-TYPE",
    "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-002-COORDINATOR-KEYS",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-000-THROTTLE-TIME-MS",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-001-ERROR-CODE",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-002-ERROR-MESSAGE",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-003-NODE-ID",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-004-HOST",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-005-PORT",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-000-KEY",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-001-NODE-ID",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-002-HOST",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-003-PORT",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-004-ERROR-CODE",
    "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-005-ERROR-MESSAGE",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V0-000-GROUP-ID",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V1-000-COORDINATOR-KEY",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V1-001-COORDINATOR-TYPE",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-000-ERROR-CODE",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-000-NODE-ID",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-001-HOST",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-002-PORT",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-000-THROTTLE-TIME-MS",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-001-ERROR-CODE",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-002-ERROR-MESSAGE",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-000-NODE-ID",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-001-HOST",
    "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-002-PORT",
];

const EXPECTED_API18_FIELD_ROW_IDS: &[&str] = &[
    "KAFKA-K2-1-FIELD-CURRENT-018-REQUEST-000-CLIENT-SOFTWARE-NAME",
    "KAFKA-K2-1-FIELD-CURRENT-018-REQUEST-001-CLIENT-SOFTWARE-VERSION",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-000-ERROR-CODE",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-000-API-KEY",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-001-MIN-VERSION",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-002-MAX-VERSION",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-002-THROTTLE-TIME-MS",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-000-NAME",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-001-MIN-VERSION",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-002-MAX-VERSION",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-004-FINALIZED-FEATURES-EPOCH",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-000-NAME",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-001-MAX-VERSION-LEVEL",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-002-MIN-VERSION-LEVEL",
    "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-006-ZK-MIGRATION-READY",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-000-ERROR-CODE",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-000-API-KEY",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-001-MIN-VERSION",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-002-MAX-VERSION",
    "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-002-THROTTLE-TIME-MS",
];

const EXPECTED_API22_FIELD_ROW_IDS: &[&str] = &[
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-000-TRANSACTIONAL-ID",
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-001-TRANSACTION-TIMEOUT-MS",
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-002-PRODUCER-ID",
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-003-PRODUCER-EPOCH",
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-004-ENABLE-2-PC",
    "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-005-KEEP-PREPARED-TXN",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-000-THROTTLE-TIME-MS",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-001-ERROR-CODE",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-002-PRODUCER-ID",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-003-PRODUCER-EPOCH",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-004-ONGOING-TXN-PRODUCER-ID",
    "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-005-ONGOING-TXN-PRODUCER-EPOCH",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-REQUEST-000-TRANSACTIONAL-ID",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-REQUEST-001-TRANSACTION-TIMEOUT-MS",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-000-THROTTLE-TIME-MS",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-001-ERROR-CODE",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-002-PRODUCER-ID",
    "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-003-PRODUCER-EPOCH",
];

fn expected_field_source_refs(expected: &ExpectedFieldProjection) -> Vec<String> {
    let mut source_refs = expected
        .source_refs
        .iter()
        .map(|source_ref| (*source_ref).to_owned())
        .collect::<Vec<_>>();
    let handler_position = source_refs
        .iter()
        .position(|source_ref| source_ref.ends_with("/SaslServerAuthenticator.java"))
        .unwrap_or(source_refs.len());

    if expected.profile_id == "KAFKA-K2-1-BROKER-CURRENT" {
        let readme = "clients/src/main/resources/common/message/README.md";
        if !source_refs.iter().any(|source_ref| source_ref == readme) {
            source_refs.insert(handler_position, readme.to_owned());
        }
        let handler_position = source_refs
            .iter()
            .position(|source_ref| source_ref.ends_with("/SaslServerAuthenticator.java"))
            .unwrap_or(source_refs.len());
        source_refs.insert(
            handler_position,
            "generator/src/main/java/org/apache/kafka/message/FieldSpec.java".to_owned(),
        );
        source_refs.insert(
            handler_position + 1,
            "generator/src/main/java/org/apache/kafka/message/MessageDataGenerator.java".to_owned(),
        );
    } else {
        source_refs.insert(
            handler_position,
            "clients/src/main/java/org/apache/kafka/common/protocol/types/Field.java".to_owned(),
        );
        source_refs.insert(
            handler_position + 1,
            "clients/src/main/java/org/apache/kafka/common/protocol/types/Type.java".to_owned(),
        );
        let struct_position = if expected.canonical_field_id.ends_with(".MECHANISMS") {
            source_refs.insert(
                handler_position + 2,
                "clients/src/main/java/org/apache/kafka/common/protocol/types/ArrayOf.java"
                    .to_owned(),
            );
            handler_position + 3
        } else {
            handler_position + 2
        };
        source_refs.insert(
            struct_position,
            "clients/src/main/java/org/apache/kafka/common/protocol/types/Struct.java".to_owned(),
        );
    }
    source_refs
}

fn expected_effective_default(
    row_id: &str,
) -> Option<(&'static str, Option<&'static str>, &'static str)> {
    match row_id {
        "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-001-KEY-TYPE" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("0"),
            "0-6",
        )),
        "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-000-KEY"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-002-ERROR-MESSAGE"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-004-HOST" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "0-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-010-REQUEST-002-COORDINATOR-KEYS"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("[]"), "0-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-000-THROTTLE-TIME-MS"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-001-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-003-NODE-ID"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-005-PORT" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "0-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-000-KEY"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-002-HOST"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-005-ERROR-MESSAGE" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "4-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-001-NODE-ID"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-003-PORT"
        | "KAFKA-K2-1-FIELD-CURRENT-010-RESPONSE-006-COORDINATORS-004-ERROR-CODE" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "4-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-017-REQUEST-000-MECHANISM" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "0-1"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-017-RESPONSE-000-ERROR-CODE" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "0-1"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-017-RESPONSE-001-MECHANISMS" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("[]"), "0-1"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-036-REQUEST-000-AUTH-BYTES"
        | "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-002-AUTH-BYTES" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0x"), "0-2"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-000-ERROR-CODE" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "0-2"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-001-ERROR-MESSAGE" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "0-2"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-003-SESSION-LIFETIME-MS" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("0"),
            "0-2",
        )),
        "KAFKA-K2-1-FIELD-CURRENT-018-REQUEST-000-CLIENT-SOFTWARE-NAME"
        | "KAFKA-K2-1-FIELD-CURRENT-018-REQUEST-001-CLIENT-SOFTWARE-VERSION" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "0-4"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-000-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-000-API-KEY"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-001-MIN-VERSION"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS-002-MAX-VERSION"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-002-THROTTLE-TIME-MS" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "0-4"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-001-API-KEYS"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("[]"), "0-4"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-000-NAME"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-000-NAME" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "3-4"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-001-MIN-VERSION"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-003-SUPPORTED-FEATURES-002-MAX-VERSION"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-001-MAX-VERSION-LEVEL"
        | "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-005-FINALIZED-FEATURES-002-MIN-VERSION-LEVEL" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "3-4"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-004-FINALIZED-FEATURES-EPOCH" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("-1"),
            "0-4",
        )),
        "KAFKA-K2-1-FIELD-CURRENT-018-RESPONSE-006-ZK-MIGRATION-READY" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("false"),
            "0-4",
        )),
        "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-000-TRANSACTIONAL-ID" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("\"\""), "0-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-001-TRANSACTION-TIMEOUT-MS"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-000-THROTTLE-TIME-MS"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-001-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-003-PRODUCER-EPOCH" => {
            Some(("IMPLICIT_GENERATED_TYPE_DEFAULT", Some("0"), "0-6"))
        }
        "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-002-PRODUCER-ID"
        | "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-003-PRODUCER-EPOCH"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-002-PRODUCER-ID"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-004-ONGOING-TXN-PRODUCER-ID"
        | "KAFKA-K2-1-FIELD-CURRENT-022-RESPONSE-005-ONGOING-TXN-PRODUCER-EPOCH" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("-1"),
            "0-6",
        )),
        "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-004-ENABLE-2-PC"
        | "KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-005-KEEP-PREPARED-TXN" => Some((
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT",
            Some("false"),
            "0-6",
        )),
        "KAFKA-K2-1-FIELD-HISTORICAL-022-REQUEST-000-TRANSACTIONAL-ID" => {
            Some(("IMPLICIT_NULLABLE_STRUCT_DEFAULT", Some("null"), "0"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-000-THROTTLE-TIME-MS" => {
            Some(("EXPLICIT_SCHEMA_LITERAL_STRUCT_DEFAULT", Some("0"), "0"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-022-REQUEST-001-TRANSACTION-TIMEOUT-MS"
        | "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-001-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-002-PRODUCER-ID"
        | "KAFKA-K2-1-FIELD-HISTORICAL-022-RESPONSE-003-PRODUCER-EPOCH" => {
            Some(("REQUIRED_NO_DEFAULT", None, "none"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-001-ERROR-MESSAGE" => {
            Some(("IMPLICIT_NULLABLE_STRUCT_DEFAULT", Some("null"), "0"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-002-ERROR-MESSAGE" => {
            Some(("IMPLICIT_NULLABLE_STRUCT_DEFAULT", Some("null"), "1"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-000-THROTTLE-TIME-MS"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-002-THROTTLE-TIME-MS" => {
            Some(("EXPLICIT_SCHEMA_LITERAL_STRUCT_DEFAULT", Some("0"), "1"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V0-000-GROUP-ID"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V1-000-COORDINATOR-KEY"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-REQUEST-V1-001-COORDINATOR-TYPE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-000-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-000-NODE-ID"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-001-HOST"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V0-001-COORDINATOR-002-PORT"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-001-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-000-NODE-ID"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-001-HOST"
        | "KAFKA-K2-1-FIELD-HISTORICAL-010-RESPONSE-V1-003-COORDINATOR-002-PORT" => {
            Some(("REQUIRED_NO_DEFAULT", None, "none"))
        }
        "KAFKA-K2-1-FIELD-HISTORICAL-017-REQUEST-000-MECHANISM"
        | "KAFKA-K2-1-FIELD-HISTORICAL-017-RESPONSE-000-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-017-RESPONSE-001-MECHANISMS"
        | "KAFKA-K2-1-FIELD-HISTORICAL-036-REQUEST-000-AUTH-BYTES"
        | "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-000-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-002-AUTH-BYTES"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-000-ERROR-CODE"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-000-API-KEY"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-001-MIN-VERSION"
        | "KAFKA-K2-1-FIELD-HISTORICAL-018-RESPONSE-001-API-VERSIONS-002-MAX-VERSION" => {
            Some(("REQUIRED_NO_DEFAULT", None, "none"))
        }
        _ => None,
    }
}

struct ExpectedErrorProjection {
    row_id: &'static str,
    error_set_id: &'static str,
    profile_id: &'static str,
    authority_id: &'static str,
    source_refs: &'static [&'static str],
    api_key: u64,
    source_versions: &'static str,
    projected_versions: &'static str,
    excluded_versions: &'static str,
    error_name: &'static str,
    error_code: u64,
    comment_code: Option<u64>,
    outcome_class: &'static str,
    consistency_state: &'static str,
}

const EXPECTED_ERROR_PROJECTIONS: &[ExpectedErrorProjection] = &[
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-CURRENT-017-000-NONE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-CURRENT-API-017",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "NONE",
        error_code: 0,
        comment_code: None,
        outcome_class: "SUCCESS_SENTINEL",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-CURRENT-017-033-UNSUPPORTED-SASL-MECHANISM",
        error_set_id: "KAFKA-K2-1-ERROR-SET-CURRENT-API-017",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "UNSUPPORTED_SASL_MECHANISM",
        error_code: 33,
        comment_code: Some(33),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-CURRENT-017-034-ILLEGAL-SASL-STATE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-CURRENT-API-017",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeRequest.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "ILLEGAL_SASL_STATE",
        error_code: 34,
        comment_code: Some(34),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-CURRENT-036-000-NONE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-CURRENT-API-036",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        error_name: "NONE",
        error_code: 0,
        comment_code: None,
        outcome_class: "SUCCESS_SENTINEL",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-CURRENT-036-058-SASL-AUTHENTICATION-FAILED",
        error_set_id: "KAFKA-K2-1-ERROR-SET-CURRENT-API-036",
        profile_id: "KAFKA-K2-1-BROKER-CURRENT",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-CURRENT",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        source_versions: "0-2",
        projected_versions: "0-2",
        excluded_versions: "none",
        error_name: "SASL_AUTHENTICATION_FAILED",
        error_code: 58,
        comment_code: Some(57),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "STALE_API_COMMENT_57_CANONICAL_ENUM_58",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-HISTORICAL-017-000-NONE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-HISTORICAL-API-017",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "NONE",
        error_code: 0,
        comment_code: None,
        outcome_class: "SUCCESS_SENTINEL",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-HISTORICAL-017-033-UNSUPPORTED-SASL-MECHANISM",
        error_set_id: "KAFKA-K2-1-ERROR-SET-HISTORICAL-API-017",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "UNSUPPORTED_SASL_MECHANISM",
        error_code: 33,
        comment_code: Some(33),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-HISTORICAL-017-034-ILLEGAL-SASL-STATE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-HISTORICAL-API-017",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeRequest.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslHandshakeResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 17,
        source_versions: "0-1",
        projected_versions: "0-1",
        excluded_versions: "none",
        error_name: "ILLEGAL_SASL_STATE",
        error_code: 34,
        comment_code: Some(34),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-HISTORICAL-036-000-NONE",
        error_set_id: "KAFKA-K2-1-ERROR-SET-HISTORICAL-API-036",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        error_name: "NONE",
        error_code: 0,
        comment_code: None,
        outcome_class: "SUCCESS_SENTINEL",
        consistency_state: "CONSISTENT",
    },
    ExpectedErrorProjection {
        row_id: "KAFKA-K2-1-ERROR-HISTORICAL-036-058-SASL-AUTHENTICATION-FAILED",
        error_set_id: "KAFKA-K2-1-ERROR-SET-HISTORICAL-API-036",
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        source_refs: &[
            "clients/src/main/java/org/apache/kafka/common/protocol/Errors.java",
            "clients/src/main/java/org/apache/kafka/common/requests/SaslAuthenticateResponse.java",
            "clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslServerAuthenticator.java",
        ],
        api_key: 36,
        source_versions: "0",
        projected_versions: "0",
        excluded_versions: "none",
        error_name: "SASL_AUTHENTICATION_FAILED",
        error_code: 58,
        comment_code: Some(57),
        outcome_class: "DECLARED_PROTOCOL_ERROR",
        consistency_state: "STALE_API_COMMENT_57_CANONICAL_ENUM_58",
    },
];

const HISTORICAL_FULL_FRONTIER_BLOCKER_KEYS: &[&str] = &[
    "accepted_version_range",
    "api_key",
    "api_name",
    "broker_declared_max",
    "broker_declared_min",
    "incumbent_max",
    "incumbent_min",
    "intersection",
    "state",
];

struct ExpectedHistoricalContract {
    profile_id: &'static str,
    authority_id: &'static str,
    commit: &'static str,
    root_tree: &'static str,
    tree_entries: u64,
    schema_model: &'static str,
    covered_api_keys: &'static [u64],
    range_rows: u64,
    source_files: u64,
    source_bytes: u64,
    projection_sha256: &'static str,
    semantic_role_projection_sha256: &'static str,
    nested_payload_state: &'static str,
    full_frontier_state: &'static str,
    blocking_observation: &'static str,
    source_path_prefix: &'static str,
}

const EXPECTED_HISTORICAL_CONTRACTS: &[ExpectedHistoricalContract] = &[
    ExpectedHistoricalContract {
        profile_id: "KAFKA-K2-1-BROKER-BASIC-LEGACY",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        commit: "15bb3961d9171c1c54c4c840a554ce2c76168163",
        root_tree: "2a734e8136c0c514d4d105cc513cc5b3fb53169c",
        tree_entries: 842,
        schema_model: "SCALA_WRITE_PARSE_METHODS_WITH_SHARED_ENVELOPE_AND_LEGACY_MESSAGE_SET",
        covered_api_keys: &[0, 1, 2, 3],
        range_rows: 4,
        source_files: 22,
        source_bytes: 95_596,
        projection_sha256: "808a785e9aaaf3794baf77b4cf6a079436064fdb0480c63c00a469a8cac308c3",
        semantic_role_projection_sha256: "b287fc3b07d99a92fc2fecf508da081971a2e24943a766bc1ca485d60b54f130",
        nested_payload_state: "LEGACY_MESSAGE_AND_COMPRESSION_SOURCES_PINNED_INTEROPERABILITY_NOT_PROVED",
        full_frontier_state: "NOT_EVALUATED_PROFILE_SCOPE_ONLY",
        blocking_observation: "Only keys 0-3 at v0 are covered; full current-facade support is not evaluated.",
        source_path_prefix: "core/src/main/scala/kafka/",
    },
    ExpectedHistoricalContract {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        commit: "73be1e1168f91ee2a9d68e1d1c75c14018cf7d3a",
        root_tree: "41ed42d9c90a6d3903e32573eb6f2c4c2d84d2a2",
        tree_entries: 2_604,
        schema_model: "CENTRAL_JAVA_PROTOCOL_SCHEMA_ARRAYS_WITH_TYPE_ENCODINGS",
        covered_api_keys: &[0, 3, 10, 18, 22, 24, 25, 26, 28],
        range_rows: 9,
        source_files: 10,
        source_bytes: 210_904,
        projection_sha256: "bdd0b4c71280124cda67095fedfada10647d9b310c7ea9ba92e3c6eade0be414",
        semantic_role_projection_sha256: "8f5f6a0924973f4cf90cd775e124329d6eb5963a679f77ae277e1194b03a9a46",
        nested_payload_state: "API10_SCALAR_STRUCT_API18_NAMED_ARRAY_STRUCT_AND_API22_FLAT_BODY_FIELDS_PROJECTED_MAGIC_V2_RECORD_PAYLOAD_SOURCES_EXCLUDED_OWNED_BY_K4_1",
        full_frontier_state: "KNOWN_EMPTY_INTERSECTION_API_23_BROKER_V0_INCUMBENT_V2",
        blocking_observation: "Only API 10 and API 18 v0-1 plus API 22 v0 body fields are projected for this profile and no range or broker behavior is accepted; API 23 OffsetForLeaderEpoch is broker v0 while the incumbent minimum is v2, so the full-frontier intersection remains empty.",
        source_path_prefix: "clients/src/main/java/org/apache/kafka/common/",
    },
    ExpectedHistoricalContract {
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        commit: "aaa7af6d4a11b29d3da9c5d6084530b8fa69be64",
        root_tree: "b53c9e1ce151dc0e21aed0fd65d4e6d3f293c824",
        tree_entries: 2_874,
        schema_model: "PER_REQUEST_JAVA_SCHEMA_ARRAYS_WITH_TYPE_ENCODINGS",
        covered_api_keys: &[17, 36],
        range_rows: 2,
        source_files: 14,
        source_bytes: 118_304,
        projection_sha256: "2cb5fa14d4be90ac72126ad3ff2f480cbb3cb8c71d786d392ae8ddf6687b4790",
        semantic_role_projection_sha256: "a6d6df3c0b7c74a8633acb807a1d9bb4bc303537ec9884887afba6847d3d87b4",
        nested_payload_state: "AUTH_BODY_FIELDS_PROJECTED_OPAQUE_MECHANISM_PAYLOAD_NOT_PROJECTED",
        full_frontier_state: "NOT_EVALUATED_PROFILE_SCOPE_ONLY",
        blocking_observation: "Only candidate body fields and source-established outcome membership for keys 17 and 36 are projected; full current-facade support is not evaluated.",
        source_path_prefix: "clients/src/main/java/org/apache/kafka/common/",
    },
];

struct ExpectedHistoricalBlocker {
    profile_id: &'static str,
    api_key: u64,
    api_name: &'static str,
    broker_min: u64,
    broker_max: u64,
    incumbent_min: u64,
    incumbent_max: u64,
    state: &'static str,
}

const EXPECTED_HISTORICAL_BLOCKERS: &[ExpectedHistoricalBlocker] = &[ExpectedHistoricalBlocker {
    profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
    api_key: 23,
    api_name: "OffsetForLeaderEpoch",
    broker_min: 0,
    broker_max: 0,
    incumbent_min: 2,
    incumbent_max: 2,
    state: "EMPTY_INTERSECTION_BLOCKS_FULL_CURRENT_FACADE",
}];

struct ExpectedHistoricalRange {
    profile_id: &'static str,
    authority_id: &'static str,
    api_key: u64,
    api_name: &'static str,
    broker_versions: &'static str,
    intersection: &'static str,
    state: &'static str,
}

const EXPECTED_HISTORICAL_RANGES: &[ExpectedHistoricalRange] = &[
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-BASIC-LEGACY",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        api_key: 0,
        api_name: "Produce",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-BASIC-LEGACY",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        api_key: 1,
        api_name: "Fetch",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-BASIC-LEGACY",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        api_key: 2,
        api_name: "ListOffsets",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-BASIC-LEGACY",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC",
        api_key: 3,
        api_name: "Metadata",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 0,
        api_name: "Produce",
        broker_versions: "0-3",
        intersection: "0-3",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 3,
        api_name: "Metadata",
        broker_versions: "0-4",
        intersection: "0-4",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 10,
        api_name: "FindCoordinator",
        broker_versions: "0-1",
        intersection: "0-1",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 18,
        api_name: "ApiVersions",
        broker_versions: "0-1",
        intersection: "0-1",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 22,
        api_name: "InitProducerId",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 24,
        api_name: "AddPartitionsToTxn",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 25,
        api_name: "AddOffsetsToTxn",
        broker_versions: "0",
        intersection: "0",
        state: "REQUIRED_ADDITIVE_ABSENT_SOURCE_RANGE_ONLY",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 26,
        api_name: "EndTxn",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
        api_key: 28,
        api_name: "TxnOffsetCommit",
        broker_versions: "0",
        intersection: "0",
        state: "REQUIRED_ADDITIVE_ABSENT_SOURCE_RANGE_ONLY",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        api_key: 17,
        api_name: "SaslHandshake",
        broker_versions: "0-1",
        intersection: "0-1",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
    ExpectedHistoricalRange {
        profile_id: "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
        authority_id: "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
        api_key: 36,
        api_name: "SaslAuthenticate",
        broker_versions: "0",
        intersection: "0",
        state: "CANDIDATE_SOURCE_DERIVED_NOT_ACCEPTED",
    },
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

fn nullable_text<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text)),
        _ => Err(format!("{key} must be non-empty text or null")),
    }
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

fn expect_boolean(value: &Value, key: &str, expected: bool) -> Result<(), String> {
    let actual = boolean(value, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{key} mismatch: expected {expected}, got {actual}"))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn expect_exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} keys mismatch: expected {expected:?}, got {actual:?}"
        ))
    }
}

fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn text_array(value: &Value, key: &str) -> Result<Vec<String>, String> {
    array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries must be non-empty text"))
        })
        .collect()
}

fn version_set(specification: &str) -> Result<BTreeSet<u64>, String> {
    if specification == "none" {
        return Ok(BTreeSet::new());
    }
    let (minimum, maximum) = match specification.split_once('-') {
        Some((minimum, maximum)) => (
            minimum
                .parse::<u64>()
                .map_err(|error| format!("invalid minimum version {minimum:?}: {error}"))?,
            maximum
                .parse::<u64>()
                .map_err(|error| format!("invalid maximum version {maximum:?}: {error}"))?,
        ),
        None => {
            let version = specification
                .parse::<u64>()
                .map_err(|error| format!("invalid version {specification:?}: {error}"))?;
            (version, version)
        }
    };
    if maximum < minimum {
        return Err(format!(
            "version interval {specification:?} has descending bounds"
        ));
    }
    Ok((minimum..=maximum).collect())
}

fn sorted_json_rows_sha256(rows: &[Value]) -> Result<String, String> {
    let mut encoded_rows = rows
        .iter()
        .map(|row| {
            Ok((
                text(row, "row_id")?.to_owned(),
                serde_json::to_string(row)
                    .map_err(|error| format!("failed to serialize projection row: {error}"))?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    encoded_rows.sort_by(|left, right| left.0.cmp(&right.0));
    let projection = encoded_rows
        .into_iter()
        .map(|(_, row)| format!("{row}\n"))
        .collect::<String>();
    Ok(sha256_bytes(projection.as_bytes()))
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
        "STATIC_REACHABILITY_FRONTIER_FROZEN_API10_API18_API22_AND_AUTH_BODY_PARTIAL_SCHEMA_AND_BROKER_PROOF_BLOCKED",
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
        let bytes =
            fs::read(root.join(path)).map_err(|error| format!("failed to read {path}: {error}"))?;
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
        return Err(format!(
            "expected five external authorities, got {}",
            rows.len()
        ));
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

    for (api_key, name, k1_seed, client_max, valid, intersection, flex_first) in EXPECTED_APIS {
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
            17 | 36 => (
                "CURRENT_EXPLICIT_BLOCKED_NATIVE_CAPABILITY",
                "BLOCKED_EXTERNAL",
            ),
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
                return Err(format!(
                    "API key {api_key} has unknown journey class {journey:?}"
                ));
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

        let (expected_request_headers, expected_response_headers): (&[u64], &[u64]) =
            match flex_first {
                Some(first) if *first <= expected_client_min => {
                    (&[2], if *api_key == 18 { &[0] } else { &[1] })
                }
                Some(first) if *first <= *client_max => {
                    (&[1, 2], if *api_key == 18 { &[0] } else { &[0, 1] })
                }
                _ => (&[1], &[0]),
            };
        if numeric_array(row, "candidate_request_header_versions")?.as_slice()
            != expected_request_headers
        {
            return Err(format!(
                "API key {api_key} request header selection changed"
            ));
        }
        if numeric_array(row, "candidate_response_header_versions")?.as_slice()
            != expected_response_headers
        {
            return Err(format!(
                "API key {api_key} response header selection changed"
            ));
        }
        let expected_projection_state = match *api_key {
            10 => "FIND_COORDINATOR_BODY_CURRENT_AND_DEFAULT_FLOOR_PROJECTED_NOT_ACCEPTED",
            17 | 36 => "AUTH_BODY_PARTIAL_CURRENT_AND_HISTORICAL_PROFILE_PROJECTED_NOT_ACCEPTED",
            18 => "API_VERSIONS_BODY_CURRENT_AND_DEFAULT_FLOOR_PROJECTED_NOT_ACCEPTED",
            22 => "INIT_PRODUCER_ID_BODY_CURRENT_AND_DEFAULT_FLOOR_PROJECTED_NOT_ACCEPTED",
            _ => "SOURCE_SELECTED_FIELDS_NOT_PROJECTED",
        };
        expect_text(row, "schema_projection_state", expected_projection_state)?;
    }

    let telemetry = rows
        .iter()
        .filter(|row| matches!(row.get("api_key").and_then(Value::as_u64), Some(71 | 72)))
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
    let identity = artifact
        .get("schema_source_identity_contract")
        .ok_or_else(|| "schema_source_identity_contract must exist".to_owned())?;
    let identity_keys = identity
        .as_object()
        .ok_or_else(|| "schema_source_identity_contract must be an object".to_owned())?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_identity_keys = SCHEMA_SOURCE_IDENTITY_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if identity_keys != expected_identity_keys {
        return Err("schema source identity contract keys changed".to_owned());
    }
    expect_text(
        identity,
        "source_authority_id",
        "KAFKA-K2-1-AUTH-APACHE-CURRENT",
    )?;
    expect_text(
        identity,
        "source_commit",
        "26b251a451ce941d3d7a55e6487bcb7f16b5ad48",
    )?;
    expect_text(
        identity,
        "canonical_root_tree",
        "789c1b8ccd3c1b9d14e718035ae8b3f0a7a66a75",
    )?;
    expect_text(
        identity,
        "path_root",
        "clients/src/main/resources/common/message",
    )?;
    expect_text(identity, "identity_scheme", "GIT_BLOB_OBJECT_ID_SHA1")?;
    expect_text(
        identity,
        "identity_domain",
        "git blob header plus exact payload bytes",
    )?;
    expect_text(identity, "payload_normalization", "NONE")?;
    expect_boolean(identity, "recursive_tree_truncated", false)?;
    expect_number(identity, "schema_pair_count", 22)?;
    expect_number(identity, "current_schema_file_count", 44)?;
    expect_number(identity, "historical_schema_file_count", 0)?;
    expect_number(identity, "total_payload_byte_count", 132_674)?;
    expect_text(
        identity,
        "sorted_projection_encoding",
        "UTF-8 path TAB object_id TAB payload_byte_count LF, bytewise path sort",
    )?;
    expect_text(
        identity,
        "sorted_path_object_id_size_projection_sha256",
        "a41d9f64bf226d638b9673a3ce6f0110ff439a62b605575169b0099bcf300b53",
    )?;
    expect_text(
        identity,
        "state",
        "CURRENT_SOURCE_GIT_BLOB_IDENTITIES_PINNED_API10_API18_API22_AND_AUTH_BODY_PARTIAL_FIELDS_AND_ERRORS_PROJECTED",
    )?;

    let current_authority = array(artifact, "external_authorities")?
        .iter()
        .find(|row| {
            row.get("authority_id").and_then(Value::as_str)
                == Some("KAFKA-K2-1-AUTH-APACHE-CURRENT")
        })
        .ok_or_else(|| "current Apache schema authority is missing".to_owned())?;
    if text(identity, "source_authority_id")? != text(current_authority, "authority_id")?
        || text(identity, "source_commit")? != text(current_authority, "commit")?
    {
        return Err("schema identity contract does not resolve to its authority".to_owned());
    }
    expect_text(
        current_authority,
        "content_state",
        "CURRENT_SCHEMA_IDENTITIES_PINNED_API10_API18_API22_AND_AUTH_BODY_PARTIAL_FIELDS_AND_ERRORS_PROJECTED",
    )?;

    let rows = array(artifact, "schema_source_rows")?;
    if rows.len() != EXPECTED_SCHEMA_SOURCES.len() {
        return Err(format!(
            "expected {} schema pairs, got {}",
            EXPECTED_SCHEMA_SOURCES.len(),
            rows.len()
        ));
    }
    let keys = rows
        .iter()
        .map(|row| number(row, "api_key"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = EXPECTED_APIS
        .iter()
        .map(|row| row.0)
        .collect::<BTreeSet<_>>();
    if keys != expected {
        return Err("schema pair keys do not match the reachability frontier".to_owned());
    }

    let mut source_paths = BTreeSet::new();
    let mut projection = Vec::with_capacity(rows.len() * 2);
    let mut total_payload_byte_count = 0_u64;
    for (api_key, name, ..) in EXPECTED_APIS {
        let row = rows
            .iter()
            .find(|row| row.get("api_key").and_then(Value::as_u64) == Some(*api_key))
            .ok_or_else(|| format!("missing schema pair for API key {api_key}"))?;
        let expected_source = EXPECTED_SCHEMA_SOURCES
            .iter()
            .find(|source| source.0 == *api_key)
            .ok_or_else(|| format!("missing expected source identity for API key {api_key}"))?;
        let (_, pair_id, request_object_id, request_bytes, response_object_id, response_bytes) =
            *expected_source;
        let request = format!("clients/src/main/resources/common/message/{name}Request.json");
        let response = format!("clients/src/main/resources/common/message/{name}Response.json");
        expect_text(row, "schema_pair_id", pair_id)?;
        expect_text(row, "request_path", &request)?;
        expect_text(row, "request_git_blob_sha1", request_object_id)?;
        expect_number(row, "request_byte_count", request_bytes)?;
        expect_text(row, "response_path", &response)?;
        expect_text(row, "response_git_blob_sha1", response_object_id)?;
        expect_number(row, "response_byte_count", response_bytes)?;

        for (label, object_id) in [
            ("request", request_object_id),
            ("response", response_object_id),
        ] {
            if !is_lower_hex(object_id, 40) {
                return Err(format!(
                    "API key {api_key} {label} Git blob object ID is not 40 lowercase hex digits"
                ));
            }
        }
        if !source_paths.insert(request.clone()) || !source_paths.insert(response.clone()) {
            return Err(format!("API key {api_key} reuses a schema source path"));
        }
        projection.push((request, request_object_id, request_bytes));
        projection.push((response, response_object_id, response_bytes));
        total_payload_byte_count += request_bytes + response_bytes;
    }
    if source_paths.len() != 44 || total_payload_byte_count != 132_674 {
        return Err("schema source path or payload-byte coverage changed".to_owned());
    }
    projection.sort_by(|left, right| left.0.cmp(&right.0));
    let projection = projection
        .into_iter()
        .map(|(path, object_id, byte_count)| format!("{path}\t{object_id}\t{byte_count}\n"))
        .collect::<String>();
    let projection_sha256 = sha256_bytes(projection.as_bytes());
    if projection_sha256 != text(identity, "sorted_path_object_id_size_projection_sha256")? {
        return Err("schema source identity projection digest changed".to_owned());
    }
    Ok(())
}

fn validate_historical_schema_sources(artifact: &Value) -> Result<(), String> {
    let contracts = array(artifact, "historical_schema_source_contracts")?;
    let source_rows = array(artifact, "historical_schema_source_rows")?;
    let range_rows = array(artifact, "historical_profile_api_range_rows")?;
    if contracts.len() != EXPECTED_HISTORICAL_CONTRACTS.len() {
        return Err(format!(
            "expected {} historical source contracts, got {}",
            EXPECTED_HISTORICAL_CONTRACTS.len(),
            contracts.len()
        ));
    }
    if source_rows.len() != 46 {
        return Err(format!(
            "expected 46 historical source rows, got {}",
            source_rows.len()
        ));
    }
    if range_rows.len() != EXPECTED_HISTORICAL_RANGES.len() {
        return Err(format!(
            "expected {} historical API range rows, got {}",
            EXPECTED_HISTORICAL_RANGES.len(),
            range_rows.len()
        ));
    }

    let external_authorities = array(artifact, "external_authorities")?;
    let broker_profiles = array(artifact, "broker_profile_rows")?;
    let reachable_api_rows = array(artifact, "reachable_api_rows")?;
    let mut all_source_keys = BTreeSet::new();
    let mut all_object_ids = BTreeSet::new();
    let mut all_source_bytes = 0_u64;
    for expected in EXPECTED_HISTORICAL_CONTRACTS {
        let contract = contracts
            .iter()
            .find(|row| row.get("profile_id").and_then(Value::as_str) == Some(expected.profile_id))
            .ok_or_else(|| {
                format!(
                    "missing historical source contract for {}",
                    expected.profile_id
                )
            })?;
        expect_exact_keys(
            contract,
            HISTORICAL_CONTRACT_KEYS,
            "historical source contract",
        )?;
        expect_text(contract, "source_authority_id", expected.authority_id)?;
        expect_text(contract, "source_commit", expected.commit)?;
        expect_text(contract, "canonical_root_tree", expected.root_tree)?;
        expect_number(contract, "source_tree_entry_count", expected.tree_entries)?;
        expect_boolean(contract, "recursive_tree_truncated", false)?;
        expect_text(contract, "schema_declaration_model", expected.schema_model)?;
        if numeric_array(contract, "covered_api_keys")?.as_slice() != expected.covered_api_keys {
            return Err(format!(
                "covered historical API keys changed for {}",
                expected.profile_id
            ));
        }
        expect_number(contract, "api_range_row_count", expected.range_rows)?;
        expect_number(contract, "source_file_count", expected.source_files)?;
        expect_number(contract, "total_payload_byte_count", expected.source_bytes)?;
        expect_text(
            contract,
            "sorted_projection_encoding",
            "UTF-8 path TAB object_id TAB payload_byte_count LF, bytewise path sort",
        )?;
        expect_text(
            contract,
            "sorted_path_object_id_size_projection_sha256",
            expected.projection_sha256,
        )?;
        expect_text(
            contract,
            "semantic_role_projection_encoding",
            "UTF-8 path TAB semantic_role LF, bytewise path sort",
        )?;
        expect_text(
            contract,
            "sorted_path_semantic_role_projection_sha256",
            expected.semantic_role_projection_sha256,
        )?;
        let expected_scope_state = match expected.profile_id {
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR" => {
                "PROFILE_SCOPED_CANDIDATE_SOURCE_IDENTITIES_PINNED_AUTH_BODY_PARTIAL_NOT_ACCEPTED"
            }
            "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR" => {
                "PROFILE_SCOPED_CANDIDATE_SOURCE_IDENTITIES_PINNED_API10_API18_API22_BODY_PROJECTED_NOT_ACCEPTED"
            }
            _ => "PROFILE_SCOPED_CANDIDATE_SOURCE_IDENTITIES_PINNED_NOT_ACCEPTED",
        };
        expect_text(contract, "scope_state", expected_scope_state)?;
        expect_text(
            contract,
            "nested_payload_state",
            expected.nested_payload_state,
        )?;
        expect_text(
            contract,
            "full_frontier_state",
            expected.full_frontier_state,
        )?;
        let expected_blocker = EXPECTED_HISTORICAL_BLOCKERS
            .iter()
            .find(|blocker| blocker.profile_id == expected.profile_id);
        match expected_blocker {
            Some(expected_blocker) => {
                let blocker = contract
                    .get("full_frontier_blocker")
                    .ok_or_else(|| "full-frontier blocker must exist".to_owned())?;
                expect_exact_keys(
                    blocker,
                    HISTORICAL_FULL_FRONTIER_BLOCKER_KEYS,
                    "historical full-frontier blocker",
                )?;
                expect_number(blocker, "api_key", expected_blocker.api_key)?;
                expect_text(blocker, "api_name", expected_blocker.api_name)?;
                expect_number(blocker, "broker_declared_min", expected_blocker.broker_min)?;
                expect_number(blocker, "broker_declared_max", expected_blocker.broker_max)?;
                expect_number(blocker, "incumbent_min", expected_blocker.incumbent_min)?;
                expect_number(blocker, "incumbent_max", expected_blocker.incumbent_max)?;
                if blocker.get("intersection") != Some(&Value::Null)
                    || blocker.get("accepted_version_range") != Some(&Value::Null)
                {
                    return Err("empty full-frontier blocker gained a range".to_owned());
                }
                expect_text(blocker, "state", expected_blocker.state)?;
                if number(blocker, "broker_declared_max")? >= number(blocker, "incumbent_min")? {
                    return Err(
                        "full-frontier blocker does not encode an empty intersection".to_owned(),
                    );
                }
                let reachable = reachable_api_rows
                    .iter()
                    .find(|row| {
                        row.get("api_key").and_then(Value::as_u64) == Some(expected_blocker.api_key)
                    })
                    .ok_or_else(|| {
                        format!(
                            "full-frontier blocker API {} escaped the reachable frontier",
                            expected_blocker.api_key
                        )
                    })?;
                expect_text(reachable, "api_name", expected_blocker.api_name)?;
                expect_number(
                    reachable,
                    "librdkafka_client_min",
                    expected_blocker.incumbent_min,
                )?;
                expect_number(
                    reachable,
                    "librdkafka_client_max",
                    expected_blocker.incumbent_max,
                )?;
            }
            None => {
                if contract.get("full_frontier_blocker") != Some(&Value::Null) {
                    return Err(format!(
                        "unexpected full-frontier blocker for {}",
                        expected.profile_id
                    ));
                }
            }
        }
        let observations = array(contract, "blocking_observations")?;
        if observations.len() != 1
            || observations[0].as_str() != Some(expected.blocking_observation)
        {
            return Err(format!(
                "blocking observation changed for {}",
                expected.profile_id
            ));
        }

        let authority = external_authorities
            .iter()
            .find(|row| {
                row.get("authority_id").and_then(Value::as_str) == Some(expected.authority_id)
            })
            .ok_or_else(|| format!("missing historical authority {}", expected.authority_id))?;
        expect_text(authority, "commit", expected.commit)?;
        let expected_content_state = match expected.profile_id {
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR" => {
                "PROFILE_SCOPED_SCHEMA_IDENTITIES_PINNED_AUTH_BODY_PARTIAL_FIELDS_AND_ERRORS_PROJECTED"
            }
            "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR" => {
                "PROFILE_SCOPED_SCHEMA_IDENTITIES_PINNED_API10_API18_API22_BODY_PARTIAL_FIELDS_PROJECTED_ERRORS_NOT_PROJECTED"
            }
            _ => "PROFILE_SCOPED_SCHEMA_SOURCE_IDENTITIES_PINNED_FIELDS_AND_ERRORS_NOT_PROJECTED",
        };
        expect_text(authority, "content_state", expected_content_state)?;
        let profile = broker_profiles
            .iter()
            .find(|row| row.get("profile_id").and_then(Value::as_str) == Some(expected.profile_id))
            .ok_or_else(|| format!("missing broker profile {}", expected.profile_id))?;
        expect_text(profile, "source_authority_id", expected.authority_id)?;
        expect_text(profile, "state", "BLOCKED_EXTERNAL")?;

        let profile_sources = source_rows
            .iter()
            .filter(|row| {
                row.get("source_authority_id").and_then(Value::as_str)
                    == Some(expected.authority_id)
            })
            .collect::<Vec<_>>();
        if profile_sources.len() != usize::try_from(expected.source_files).unwrap_or(usize::MAX) {
            return Err(format!(
                "historical source count changed for {}",
                expected.profile_id
            ));
        }
        let mut projection = Vec::with_capacity(profile_sources.len());
        let mut semantic_role_projection = Vec::with_capacity(profile_sources.len());
        let mut profile_source_bytes = 0_u64;
        for row in profile_sources {
            expect_exact_keys(row, HISTORICAL_SOURCE_ROW_KEYS, "historical source row")?;
            expect_text(row, "profile_id", expected.profile_id)?;
            expect_text(row, "source_authority_id", expected.authority_id)?;
            let path = text(row, "path")?;
            if !path.starts_with(expected.source_path_prefix) {
                return Err(format!(
                    "historical source path {path} escaped {}",
                    expected.source_path_prefix
                ));
            }
            let object_id = text(row, "git_blob_sha1")?;
            if !is_lower_hex(object_id, 40) {
                return Err(format!(
                    "historical source {path} has an invalid Git blob object ID"
                ));
            }
            let byte_count = number(row, "byte_count")?;
            let semantic_role = text(row, "semantic_role")?;
            if byte_count == 0 {
                return Err(format!("historical source {path} lacks bounded metadata"));
            }
            if !all_source_keys.insert((expected.authority_id.to_owned(), path.to_owned())) {
                return Err(format!(
                    "historical authority {} repeats source path {path}",
                    expected.authority_id
                ));
            }
            profile_source_bytes += byte_count;
            all_source_bytes += byte_count;
            all_object_ids.insert(object_id.to_owned());
            projection.push((path, object_id, byte_count));
            semantic_role_projection.push((path, semantic_role));
        }
        if profile_source_bytes != expected.source_bytes {
            return Err(format!(
                "historical source bytes changed for {}",
                expected.profile_id
            ));
        }
        projection.sort_by(|left, right| left.0.cmp(right.0));
        let projection = projection
            .into_iter()
            .map(|(path, object_id, byte_count)| format!("{path}\t{object_id}\t{byte_count}\n"))
            .collect::<String>();
        if sha256_bytes(projection.as_bytes()) != expected.projection_sha256 {
            return Err(format!(
                "historical source projection changed for {}",
                expected.profile_id
            ));
        }
        semantic_role_projection.sort_by(|left, right| left.0.cmp(right.0));
        let semantic_role_projection = semantic_role_projection
            .into_iter()
            .map(|(path, semantic_role)| format!("{path}\t{semantic_role}\n"))
            .collect::<String>();
        if sha256_bytes(semantic_role_projection.as_bytes())
            != expected.semantic_role_projection_sha256
        {
            return Err(format!(
                "historical semantic-role projection changed for {}",
                expected.profile_id
            ));
        }

        let actual_range_keys = range_rows
            .iter()
            .filter(|row| {
                row.get("profile_id").and_then(Value::as_str) == Some(expected.profile_id)
            })
            .map(|row| number(row, "api_key"))
            .collect::<Result<Vec<_>, _>>()?;
        if actual_range_keys.as_slice() != expected.covered_api_keys {
            return Err(format!(
                "historical profile range keys changed for {}",
                expected.profile_id
            ));
        }
    }
    if all_source_keys.len() != source_rows.len() || all_source_bytes != 424_804 {
        return Err("historical source identity coverage changed".to_owned());
    }
    if all_object_ids.len() != 44 {
        return Err("historical distinct Git blob coverage changed".to_owned());
    }

    let mut range_keys = BTreeSet::new();
    for expected in EXPECTED_HISTORICAL_RANGES {
        let row = range_rows
            .iter()
            .find(|row| {
                row.get("profile_id").and_then(Value::as_str) == Some(expected.profile_id)
                    && row.get("api_key").and_then(Value::as_u64) == Some(expected.api_key)
            })
            .ok_or_else(|| {
                format!(
                    "missing historical range row {} API {}",
                    expected.profile_id, expected.api_key
                )
            })?;
        expect_exact_keys(row, HISTORICAL_RANGE_ROW_KEYS, "historical API range row")?;
        expect_text(row, "source_authority_id", expected.authority_id)?;
        expect_text(row, "api_name", expected.api_name)?;
        expect_text(row, "broker_declared_versions", expected.broker_versions)?;
        expect_text(
            row,
            "incumbent_candidate_intersection",
            expected.intersection,
        )?;
        if row.get("accepted_version_range") != Some(&Value::Null) {
            return Err(format!(
                "historical range {} API {} was accepted without terminal evidence",
                expected.profile_id, expected.api_key
            ));
        }
        expect_text(row, "state", expected.state)?;
        if !range_keys.insert((expected.profile_id.to_owned(), expected.api_key)) {
            return Err(format!(
                "duplicate historical range {} API {}",
                expected.profile_id, expected.api_key
            ));
        }
        let reachable_name = EXPECTED_APIS
            .iter()
            .find(|api| api.0 == expected.api_key)
            .map(|api| api.1)
            .ok_or_else(|| format!("historical API {} escaped the frontier", expected.api_key))?;
        if reachable_name != expected.api_name {
            return Err(format!(
                "historical API name changed for key {}",
                expected.api_key
            ));
        }
    }
    if range_keys.len() != range_rows.len() {
        return Err("historical API range keys must be unique".to_owned());
    }
    Ok(())
}

fn validate_partial_body_projection(artifact: &Value) -> Result<(), String> {
    let support_rows = array(artifact, "field_error_projection_source_rows")?;
    if support_rows.len() != EXPECTED_PROJECTION_SOURCES.len() {
        return Err(format!(
            "expected {} field/error support sources, got {}",
            EXPECTED_PROJECTION_SOURCES.len(),
            support_rows.len()
        ));
    }

    let mut support_ids = BTreeSet::new();
    let mut support_keys = BTreeSet::new();
    let mut support_projection = Vec::new();
    let mut support_bytes = 0_u64;
    for row in support_rows {
        expect_exact_keys(
            row,
            FIELD_ERROR_PROJECTION_SOURCE_KEYS,
            "field/error projection source",
        )?;
        let source_id = text(row, "source_id")?;
        let authority = text(row, "source_authority_id")?;
        let path = text(row, "path")?;
        let object_id = text(row, "git_blob_sha1")?;
        let byte_count = number(row, "byte_count")?;
        let semantic_role = text(row, "semantic_role")?;
        let expected = EXPECTED_PROJECTION_SOURCES
            .iter()
            .find(|expected| expected.0 == source_id)
            .ok_or_else(|| format!("unexpected field/error support source {source_id}"))?;
        expect_text(row, "source_authority_id", expected.1)?;
        expect_text(row, "path", expected.2)?;
        expect_text(row, "git_blob_sha1", expected.3)?;
        expect_number(row, "byte_count", expected.4)?;
        expect_text(row, "semantic_role", expected.5)?;
        if !matches!(
            authority,
            "KAFKA-K2-1-AUTH-APACHE-CURRENT" | "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR"
        ) {
            return Err(format!(
                "field/error projection source {source_id} escaped the two-profile slice"
            ));
        }
        if !is_lower_hex(object_id, 40) || byte_count == 0 {
            return Err(format!(
                "field/error projection source {source_id} lacks bounded Git identity"
            ));
        }
        if !support_ids.insert(source_id.to_owned())
            || !support_keys.insert((authority.to_owned(), path.to_owned()))
        {
            return Err(
                "field/error projection support source identities must be unique".to_owned(),
            );
        }
        support_bytes += byte_count;
        support_projection.push((
            authority.to_owned(),
            path.to_owned(),
            object_id.to_owned(),
            byte_count,
            semantic_role.to_owned(),
        ));
    }
    if support_bytes != 239_139 {
        return Err("field/error projection support byte coverage changed".to_owned());
    }
    support_projection.sort();
    let support_projection = support_projection
        .into_iter()
        .map(|(authority, path, object_id, byte_count, semantic_role)| {
            format!("{authority}\t{path}\t{object_id}\t{byte_count}\t{semantic_role}\n")
        })
        .collect::<String>();
    let support_projection_sha256 = sha256_bytes(support_projection.as_bytes());
    if support_projection_sha256
        != "9a32a3cb6572e4683cdb4f04ed2b4cc533d8af588b13fb748c014b26531ddef3"
    {
        return Err("field/error projection support digest changed".to_owned());
    }

    let mut pinned_sources = support_keys;
    for row in array(artifact, "schema_source_rows")? {
        pinned_sources.insert((
            "KAFKA-K2-1-AUTH-APACHE-CURRENT".to_owned(),
            text(row, "request_path")?.to_owned(),
        ));
        pinned_sources.insert((
            "KAFKA-K2-1-AUTH-APACHE-CURRENT".to_owned(),
            text(row, "response_path")?.to_owned(),
        ));
    }
    for row in array(artifact, "historical_schema_source_rows")? {
        pinned_sources.insert((
            text(row, "source_authority_id")?.to_owned(),
            text(row, "path")?.to_owned(),
        ));
    }

    let fields = array(artifact, "field_projection_rows")?;
    let expected_field_count = EXPECTED_FIELD_PROJECTIONS.len()
        + EXPECTED_API10_FIELD_ROW_IDS.len()
        + EXPECTED_API18_FIELD_ROW_IDS.len()
        + EXPECTED_API22_FIELD_ROW_IDS.len();
    if fields.len() != expected_field_count {
        return Err(format!(
            "expected {expected_field_count} partial API 10, API 18, API 22 and authentication field rows, got {}",
            fields.len()
        ));
    }
    let mut field_row_ids = BTreeSet::new();
    let mut field_profiles = BTreeMap::<String, usize>::new();
    let mut field_api_keys = BTreeSet::new();
    let mut field_api_profiles = BTreeSet::new();
    let mut field_api_versions = BTreeSet::new();
    let mut field_orders =
        BTreeMap::<(String, u64, String, Option<String>, Option<u64>), BTreeSet<u64>>::new();
    let mut field_version_cells = 0_usize;
    let mut explicit_schema_defaults = 0_usize;
    let mut implicit_generated_defaults = 0_usize;
    let mut explicit_generated_defaults = 0_usize;
    let mut explicit_struct_defaults = 0_usize;
    let mut implicit_nullable_struct_defaults = 0_usize;
    let mut required_no_defaults = 0_usize;
    let mut effective_default_value_rows = 0_usize;
    let mut effective_default_version_cells = 0_usize;
    let mut field_error_sets = BTreeSet::new();

    for row in fields {
        expect_exact_keys(row, FIELD_PROJECTION_ROW_KEYS, "field projection row")?;
        let row_id = text(row, "row_id")?;
        if !field_row_ids.insert(row_id.to_owned()) {
            return Err(format!("duplicate field projection row {row_id}"));
        }
        let legacy_expected = EXPECTED_FIELD_PROJECTIONS
            .iter()
            .find(|expected| expected.row_id == row_id);
        if legacy_expected.is_none()
            && !EXPECTED_API10_FIELD_ROW_IDS.contains(&row_id)
            && !EXPECTED_API18_FIELD_ROW_IDS.contains(&row_id)
            && !EXPECTED_API22_FIELD_ROW_IDS.contains(&row_id)
        {
            return Err(format!("unexpected field projection row {row_id}"));
        }
        if let Some(expected) = legacy_expected {
            expect_text(row, "profile_id", expected.profile_id)?;
            expect_text(row, "source_authority_id", expected.authority_id)?;
            let expected_source_refs = expected_field_source_refs(expected);
            if text_array(row, "source_refs")? != expected_source_refs {
                return Err(format!("field row {row_id} source references changed"));
            }
            expect_number(row, "api_key", expected.api_key)?;
            expect_text(row, "direction", expected.direction)?;
            expect_text(row, "canonical_field_id", expected.canonical_field_id)?;
            expect_text(row, "source_field_name", expected.source_field_name)?;
            expect_number(row, "field_order", expected.field_order)?;
            expect_text(row, "source_versions", expected.source_versions)?;
            expect_text(row, "projected_versions", expected.projected_versions)?;
            expect_text(row, "excluded_source_versions", expected.excluded_versions)?;
            expect_text(row, "logical_type", expected.logical_type)?;
            expect_text(row, "wire_type", expected.wire_type)?;
            match expected.element_type {
                Some(element_type) => expect_text(row, "element_type", element_type)?,
                None if row.get("element_type") == Some(&Value::Null) => {}
                None => return Err(format!("field row {row_id} invented an element type")),
            }
            expect_text(row, "nullable_versions", expected.nullable_versions)?;
            expect_text(row, "schema_default_state", expected.default_state)?;
            match expected.default_literal {
                Some(default_literal) => {
                    expect_text(row, "schema_default_literal", default_literal)?
                }
                None if row.get("schema_default_literal") == Some(&Value::Null) => {}
                None => return Err(format!("field row {row_id} invented a schema default")),
            }
        }
        let (effective_state, effective_literal, effective_versions) =
            expected_effective_default(row_id)
                .ok_or_else(|| format!("field row {row_id} lacks an effective-default oracle"))?;
        expect_text(row, "effective_default_state", effective_state)?;
        match effective_literal {
            Some(literal) => {
                expect_text(row, "effective_default_literal", literal)?;
                effective_default_value_rows += 1;
            }
            None if row.get("effective_default_literal") == Some(&Value::Null) => {}
            None => {
                return Err(format!(
                    "field row {row_id} invented an effective default literal"
                ));
            }
        }
        expect_text(row, "effective_default_versions", effective_versions)?;
        effective_default_version_cells += version_set(effective_versions)?.len();
        match effective_state {
            "IMPLICIT_GENERATED_TYPE_DEFAULT" => implicit_generated_defaults += 1,
            "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT" => explicit_generated_defaults += 1,
            "EXPLICIT_SCHEMA_LITERAL_STRUCT_DEFAULT" => explicit_struct_defaults += 1,
            "IMPLICIT_NULLABLE_STRUCT_DEFAULT" => implicit_nullable_struct_defaults += 1,
            "REQUIRED_NO_DEFAULT" => required_no_defaults += 1,
            state => {
                return Err(format!(
                    "field row {row_id} has unknown default state {state}"
                ));
            }
        }
        if let Some(expected) = legacy_expected {
            expect_text(row, "ignorable_versions", expected.ignorable_versions)?;
            expect_text(row, "sensitivity", expected.sensitivity)?;
            match expected.error_set_id {
                Some(error_set_id) => expect_text(row, "error_set_id", error_set_id)?,
                None if row.get("error_set_id") == Some(&Value::Null) => {}
                None => return Err(format!("field row {row_id} invented an error set")),
            }
            expect_text(
                row,
                "nested_projection_state",
                expected.nested_projection_state,
            )?;
        }
        let profile = text(row, "profile_id")?;
        let authority = text(row, "source_authority_id")?;
        let expected_authority = match profile {
            "KAFKA-K2-1-BROKER-CURRENT" => "KAFKA-K2-1-AUTH-APACHE-CURRENT",
            "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR" => "KAFKA-K2-1-AUTH-APACHE-DEFAULT-FLOOR",
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR" => "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
            _ => {
                return Err(format!(
                    "field row {row_id} escaped the three-profile slice"
                ));
            }
        };
        if authority != expected_authority {
            return Err(format!("field row {row_id} crossed source authorities"));
        }
        *field_profiles.entry(profile.to_owned()).or_default() += 1;

        let api_key = number(row, "api_key")?;
        if !matches!(api_key, 10 | 17 | 18 | 22 | 36) {
            return Err(format!(
                "field row {row_id} escaped APIs 10, 17, 18, 22 and 36"
            ));
        }
        field_api_keys.insert(api_key);
        field_api_profiles.insert((profile.to_owned(), api_key));

        let canonical_field = text(row, "canonical_field_id")?;
        let effective_version_set = version_set(text(row, "effective_default_versions")?)?;
        if profile == "KAFKA-K2-1-BROKER-CURRENT" {
            let coherent_default_versions = match api_key {
                10 => {
                    effective_version_set == BTreeSet::from([0, 1, 2, 3, 4, 5, 6])
                        || effective_version_set == BTreeSet::from([4, 5, 6])
                }
                17 => effective_version_set == BTreeSet::from([0, 1]),
                18 => {
                    effective_version_set == BTreeSet::from([0, 1, 2, 3, 4])
                        || effective_version_set == BTreeSet::from([3, 4])
                }
                22 => effective_version_set == BTreeSet::from([0, 1, 2, 3, 4, 5, 6]),
                36 => effective_version_set == BTreeSet::from([0, 1, 2]),
                _ => false,
            };
            if !coherent_default_versions
                || !matches!(
                    effective_state,
                    "IMPLICIT_GENERATED_TYPE_DEFAULT" | "EXPLICIT_SCHEMA_LITERAL_GENERATED_DEFAULT"
                )
            {
                return Err(format!(
                    "current field row {row_id} has incoherent generated defaults"
                ));
            }
            if canonical_field.ends_with(".ERROR_MESSAGE") {
                expect_text(row, "effective_default_literal", "\"\"")?;
            }
        } else if matches!(
            (profile, api_key, canonical_field),
            (
                "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                22,
                "API22.REQUEST.TRANSACTIONAL_ID"
            )
        ) {
            if effective_state != "IMPLICIT_NULLABLE_STRUCT_DEFAULT"
                || effective_version_set != BTreeSet::from([0])
            {
                return Err("historical transactional ID default changed".to_owned());
            }
            expect_text(row, "effective_default_literal", "null")?;
        } else if canonical_field.ends_with(".ERROR_MESSAGE") {
            let expected_nullable_default_versions = match (profile, api_key) {
                ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", 10) => BTreeSet::from([1]),
                ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 36) => BTreeSet::from([0]),
                _ => {
                    return Err(format!(
                        "historical nullable error message row {row_id} escaped its profile"
                    ));
                }
            };
            if effective_state != "IMPLICIT_NULLABLE_STRUCT_DEFAULT"
                || effective_version_set != expected_nullable_default_versions
            {
                return Err("historical nullable error message default changed".to_owned());
            }
            expect_text(row, "effective_default_literal", "null")?;
        } else if matches!(
            (profile, api_key, canonical_field),
            (
                "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                10,
                "API10.RESPONSE.THROTTLE_TIME_MS"
            ) | (
                "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                18,
                "API18.RESPONSE.THROTTLE_TIME_MS"
            ) | (
                "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                22,
                "API22.RESPONSE.THROTTLE_TIME_MS"
            )
        ) {
            let expected_versions = if api_key == 22 {
                BTreeSet::from([0])
            } else {
                BTreeSet::from([1])
            };
            if effective_state != "EXPLICIT_SCHEMA_LITERAL_STRUCT_DEFAULT"
                || effective_version_set != expected_versions
            {
                return Err("historical throttle Struct default changed".to_owned());
            }
            expect_text(row, "effective_default_literal", "0")?;
        } else if effective_state != "REQUIRED_NO_DEFAULT"
            || !effective_version_set.is_empty()
            || row.get("effective_default_literal") != Some(&Value::Null)
        {
            return Err(format!(
                "historical required field row {row_id} acquired a default"
            ));
        }

        let source_versions = version_set(text(row, "source_versions")?)?;
        let projected_versions = version_set(text(row, "projected_versions")?)?;
        let excluded_versions = version_set(text(row, "excluded_source_versions")?)?;
        if projected_versions.is_empty()
            || !projected_versions.is_subset(&source_versions)
            || !excluded_versions.is_subset(&source_versions)
            || !projected_versions.is_disjoint(&excluded_versions)
        {
            return Err(format!("field row {row_id} has incoherent version sets"));
        }
        let projected_and_excluded = projected_versions
            .union(&excluded_versions)
            .copied()
            .collect::<BTreeSet<_>>();
        if projected_and_excluded != source_versions {
            return Err(format!(
                "field row {row_id} does not partition its source versions"
            ));
        }
        let expected_exclusion_state = if excluded_versions.is_empty() {
            "NONE"
        } else {
            "OUTSIDE_INCUMBENT_CANDIDATE_INTERSECTION_FLEXIBLE_ENCODING_UNPROJECTED"
        };
        expect_text(row, "version_exclusion_state", expected_exclusion_state)?;

        let candidate_versions = if profile == "KAFKA-K2-1-BROKER-CURRENT" {
            let reachable = array(artifact, "reachable_api_rows")?
                .iter()
                .find(|candidate| candidate.get("api_key").and_then(Value::as_u64) == Some(api_key))
                .ok_or_else(|| format!("missing current candidate range for API {api_key}"))?;
            version_set(text(reachable, "candidate_current_intersection")?)?
        } else {
            let historical = array(artifact, "historical_profile_api_range_rows")?
                .iter()
                .find(|candidate| {
                    candidate.get("profile_id").and_then(Value::as_str) == Some(profile)
                        && candidate.get("api_key").and_then(Value::as_u64) == Some(api_key)
                })
                .ok_or_else(|| format!("missing historical candidate range for API {api_key}"))?;
            version_set(text(historical, "incumbent_candidate_intersection")?)?
        };
        let candidate_source_versions = candidate_versions
            .intersection(&source_versions)
            .copied()
            .collect::<BTreeSet<_>>();
        if !candidate_source_versions.is_subset(&projected_versions) {
            return Err(format!(
                "field row {row_id} does not cover its source/candidate intersection"
            ));
        }
        let projected_outside_candidate = projected_versions
            .difference(&candidate_versions)
            .copied()
            .collect::<BTreeSet<_>>();
        let allowed_outside_candidate = match (profile, api_key) {
            ("KAFKA-K2-1-BROKER-CURRENT", 10) => BTreeSet::from([3, 4, 5, 6]),
            ("KAFKA-K2-1-BROKER-CURRENT", 18) => BTreeSet::from([4]),
            ("KAFKA-K2-1-BROKER-CURRENT", 22) => BTreeSet::from([5, 6]),
            ("KAFKA-K2-1-BROKER-CURRENT", 36) => BTreeSet::from([2]),
            _ => BTreeSet::new(),
        };
        if !projected_outside_candidate.is_subset(&allowed_outside_candidate) {
            return Err(format!(
                "field row {row_id} projected an unauthorized outside-candidate version"
            ));
        }

        let direction = text(row, "direction")?;
        if !matches!(direction, "REQUEST" | "RESPONSE") {
            return Err(format!("field row {row_id} has invalid direction"));
        }
        let parent_row_id = match row.get("parent_row_id") {
            Some(Value::Null) => None,
            Some(Value::String(parent)) => Some(parent.clone()),
            _ => return Err(format!("field row {row_id} has invalid parent_row_id")),
        };
        let field_order = number(row, "field_order")?;
        let order_version_slice =
            if profile == "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR" && api_key == 10 {
                if projected_versions.len() != 1 {
                    return Err(format!(
                        "historical API 10 field row {row_id} is not version-sliced"
                    ));
                }
                projected_versions.first().copied()
            } else {
                None
            };
        let order_key = (
            profile.to_owned(),
            api_key,
            direction.to_owned(),
            parent_row_id,
            order_version_slice,
        );
        if !field_orders
            .entry(order_key)
            .or_default()
            .insert(field_order)
        {
            return Err(format!("field row {row_id} duplicates a sibling order"));
        }
        for version in &projected_versions {
            field_api_versions.insert((profile.to_owned(), api_key, *version));
        }
        field_version_cells += projected_versions.len();

        for source_ref in text_array(row, "source_refs")? {
            if !pinned_sources.contains(&(authority.to_owned(), source_ref.clone())) {
                return Err(format!(
                    "field row {row_id} references unpinned source {source_ref}"
                ));
            }
        }
        let current_flexible_api_36 = profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 36;
        let expected_compact_versions = if current_flexible_api_36
            && (canonical_field.ends_with(".AUTH_BYTES")
                || canonical_field.ends_with(".ERROR_MESSAGE"))
        {
            "2"
        } else if profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 10 {
            match canonical_field {
                "API10.REQUEST.KEY" | "API10.RESPONSE.ERROR_MESSAGE" | "API10.RESPONSE.HOST" => "3",
                "API10.REQUEST.COORDINATOR_KEYS"
                | "API10.RESPONSE.COORDINATORS"
                | "API10.RESPONSE.COORDINATORS[].KEY"
                | "API10.RESPONSE.COORDINATORS[].HOST"
                | "API10.RESPONSE.COORDINATORS[].ERROR_MESSAGE" => "4-6",
                _ => "none",
            }
        } else if profile == "KAFKA-K2-1-BROKER-CURRENT"
            && api_key == 18
            && (direction == "REQUEST"
                || matches!(
                    canonical_field,
                    "API18.RESPONSE.API_KEYS"
                        | "API18.RESPONSE.SUPPORTED_FEATURES"
                        | "API18.RESPONSE.SUPPORTED_FEATURES[].NAME"
                        | "API18.RESPONSE.FINALIZED_FEATURES"
                        | "API18.RESPONSE.FINALIZED_FEATURES[].NAME"
                ))
        {
            "3-4"
        } else if profile == "KAFKA-K2-1-BROKER-CURRENT"
            && api_key == 22
            && canonical_field == "API22.REQUEST.TRANSACTIONAL_ID"
        {
            "2-6"
        } else {
            "none"
        };
        expect_text(row, "projected_compact_versions", expected_compact_versions)?;
        let expected_tag: Option<u64> = match canonical_field {
            "API18.RESPONSE.SUPPORTED_FEATURES" => Some(0),
            "API18.RESPONSE.FINALIZED_FEATURES_EPOCH" => Some(1),
            "API18.RESPONSE.FINALIZED_FEATURES" => Some(2),
            "API18.RESPONSE.ZK_MIGRATION_READY" => Some(3),
            _ => None,
        };
        expect_text(
            row,
            "projected_tagged_versions",
            if expected_tag.is_some() {
                "3-4"
            } else {
                "none"
            },
        )?;
        expect_text(
            row,
            "owning_struct_tag_buffer_projected_versions",
            if current_flexible_api_36 {
                "2"
            } else if profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 10 {
                if canonical_field.starts_with("API10.RESPONSE.COORDINATORS[].") {
                    "4-6"
                } else {
                    "3-6"
                }
            } else if profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 18 {
                "3-4"
            } else if profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 22 {
                "2-6"
            } else {
                "none"
            },
        )?;
        let actual_tag_ids = numeric_array(row, "projected_tag_ids")?;
        match expected_tag {
            Some(tag) if actual_tag_ids.as_slice() == [tag].as_slice() => {}
            None if actual_tag_ids.is_empty() => {}
            _ => return Err(format!("field row {row_id} tag IDs changed")),
        }
        if row.get("accepted_version_range") != Some(&Value::Null) {
            return Err(format!("field row {row_id} acquired an accepted range"));
        }
        expect_text(
            row,
            "projection_state",
            "SOURCE_BODY_FIELD_PROJECTED_PARTIAL_PACKET_NOT_ACCEPTED",
        )?;

        match text(row, "schema_default_state")? {
            "NOT_EXPLICITLY_DECLARED"
                if row.get("schema_default_literal") == Some(&Value::Null) => {}
            "EXPLICIT_LITERAL" => {
                explicit_schema_defaults += 1;
                let expected_literal = match (profile, api_key, canonical_field) {
                    ("KAFKA-K2-1-BROKER-CURRENT", 10, "API10.REQUEST.KEY_TYPE") => "0",
                    ("KAFKA-K2-1-BROKER-CURRENT", 36, "API36.RESPONSE.SESSION_LIFETIME_MS") => "0",
                    (
                        "KAFKA-K2-1-BROKER-CURRENT",
                        18,
                        "API18.RESPONSE.FINALIZED_FEATURES_EPOCH",
                    ) => "-1",
                    ("KAFKA-K2-1-BROKER-CURRENT", 18, "API18.RESPONSE.ZK_MIGRATION_READY") => {
                        "false"
                    }
                    (
                        "KAFKA-K2-1-BROKER-CURRENT",
                        22,
                        "API22.REQUEST.PRODUCER_ID"
                        | "API22.REQUEST.PRODUCER_EPOCH"
                        | "API22.RESPONSE.PRODUCER_ID"
                        | "API22.RESPONSE.ONGOING_TXN_PRODUCER_ID"
                        | "API22.RESPONSE.ONGOING_TXN_PRODUCER_EPOCH",
                    ) => "-1",
                    (
                        "KAFKA-K2-1-BROKER-CURRENT",
                        22,
                        "API22.REQUEST.ENABLE_2_PC" | "API22.REQUEST.KEEP_PREPARED_TXN",
                    ) => "false",
                    (
                        "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                        10,
                        "API10.RESPONSE.THROTTLE_TIME_MS",
                    )
                    | (
                        "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                        18,
                        "API18.RESPONSE.THROTTLE_TIME_MS",
                    )
                    | (
                        "KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR",
                        22,
                        "API22.RESPONSE.THROTTLE_TIME_MS",
                    ) => "0",
                    _ => {
                        return Err(format!(
                            "field row {row_id} invented an explicit schema default"
                        ));
                    }
                };
                expect_text(row, "schema_default_literal", expected_literal)?;
            }
            state => {
                return Err(format!(
                    "field row {row_id} has inconsistent schema default state {state}"
                ));
            }
        }

        if canonical_field.ends_with(".ERROR_CODE") && matches!(api_key, 17 | 36) {
            field_error_sets.insert(text(row, "error_set_id")?.to_owned());
        } else if canonical_field.ends_with(".ERROR_CODE")
            && matches!(api_key, 10 | 18 | 22)
            && row.get("error_set_id") != Some(&Value::Null)
        {
            return Err(format!(
                "unprojected API 10, API 18 or API 22 error field row {row_id} acquired an error set"
            ));
        } else if row.get("error_set_id") != Some(&Value::Null) {
            return Err(format!(
                "non-error field row {row_id} acquired an error set"
            ));
        }
        if canonical_field.ends_with(".AUTH_BYTES") {
            expect_text(row, "sensitivity", "SECRET_BEARING_OPAQUE_AUTH_MATERIAL")?;
            expect_text(
                row,
                "nested_projection_state",
                "OPAQUE_SASL_MECHANISM_BYTES_NOT_PROJECTED",
            )?;
        }
        if canonical_field.ends_with(".SESSION_LIFETIME_MS") {
            if profile != "KAFKA-K2-1-BROKER-CURRENT"
                || api_key != 36
                || projected_versions != BTreeSet::from([1, 2])
            {
                return Err("session lifetime escaped current API 36 v1-v2".to_owned());
            }
            expect_text(row, "ignorable_versions", "1-2")?;
        }
        if canonical_field.ends_with(".ERROR_MESSAGE") {
            let expected_nullable = match (profile, api_key, canonical_field) {
                ("KAFKA-K2-1-BROKER-CURRENT", 10, "API10.RESPONSE.ERROR_MESSAGE") => "1-3",
                (
                    "KAFKA-K2-1-BROKER-CURRENT",
                    10,
                    "API10.RESPONSE.COORDINATORS[].ERROR_MESSAGE",
                ) => "4-6",
                ("KAFKA-K2-1-BROKER-CURRENT", 36, _) => "0-2",
                ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", 10, _) => "1",
                ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 36, _) => "0",
                _ => {
                    return Err(format!(
                        "error message row {row_id} escaped its nullable-version oracle"
                    ));
                }
            };
            expect_text(row, "nullable_versions", expected_nullable)?;
            expect_text(row, "wire_type", "NULLABLE_STRING")?;
        }
        if api_key == 22 {
            if row.get("parent_row_id") != Some(&Value::Null)
                || row.get("element_type") != Some(&Value::Null)
                || row.get("nested_type_name") != Some(&Value::Null)
                || boolean(row, "map_key")?
            {
                return Err(format!("API 22 field row {row_id} stopped being flat"));
            }
            expect_text(row, "nested_projection_state", "NOT_APPLICABLE")?;
            let transactional_id = canonical_field == "API22.REQUEST.TRANSACTIONAL_ID";
            if transactional_id {
                let (
                    expected_source_name,
                    expected_nullable,
                    expected_effective_state,
                    expected_literal,
                ) = if profile == "KAFKA-K2-1-BROKER-CURRENT" {
                    (
                        "TransactionalId",
                        "0-6",
                        "IMPLICIT_GENERATED_TYPE_DEFAULT",
                        "\"\"",
                    )
                } else {
                    (
                        "transactional_id",
                        "0",
                        "IMPLICIT_NULLABLE_STRUCT_DEFAULT",
                        "null",
                    )
                };
                expect_text(row, "source_field_name", expected_source_name)?;
                expect_text(row, "logical_type", "STRING")?;
                expect_text(row, "wire_type", "NULLABLE_STRING")?;
                expect_text(row, "nullable_versions", expected_nullable)?;
                expect_text(row, "effective_default_state", expected_effective_state)?;
                expect_text(row, "effective_default_literal", expected_literal)?;
                expect_text(row, "sensitivity", "TRANSACTIONAL_ID_IDENTIFIER_REDACT")?;
            } else {
                expect_text(row, "nullable_versions", "none")?;
                expect_text(row, "sensitivity", "NON_SECRET_CONTROL_METADATA")?;
            }
            expect_text(
                row,
                "ignorable_versions",
                if profile == "KAFKA-K2-1-BROKER-CURRENT"
                    && canonical_field == "API22.RESPONSE.THROTTLE_TIME_MS"
                {
                    "0-6"
                } else {
                    "none"
                },
            )?;
        }
    }

    let field_rows_by_id = fields
        .iter()
        .map(|row| Ok((text(row, "row_id")?.to_owned(), row)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let mut top_level_rows = 0_usize;
    let mut nested_rows = 0_usize;
    let mut named_struct_parents = 0_usize;
    let mut map_key_rows = 0_usize;
    let mut tagged_rows = 0_usize;
    let mut tagged_version_cells = 0_usize;
    let mut compact_version_cells = 0_usize;
    let mut tag_buffer_rows = 0_usize;
    let mut tag_buffer_version_cells = 0_usize;
    let mut max_depth = 0_usize;
    let mut owner_tag_buffers = BTreeMap::<(String, u64, String, Option<String>), String>::new();
    let mut tag_ids_by_scope =
        BTreeMap::<(String, u64, String, Option<String>), BTreeSet<u64>>::new();

    for row in fields {
        let row_id = text(row, "row_id")?;
        let profile = text(row, "profile_id")?;
        let authority = text(row, "source_authority_id")?;
        let api_key = number(row, "api_key")?;
        let direction = text(row, "direction")?;
        let canonical_field = text(row, "canonical_field_id")?;
        let canonical_prefix = format!("API{api_key}.{direction}.");
        if !canonical_field.starts_with(&canonical_prefix) || canonical_field.contains(".HEADER.") {
            return Err(format!(
                "field row {row_id} escaped its API body canonical path"
            ));
        }

        let message_versions = match (profile, api_key) {
            ("KAFKA-K2-1-BROKER-CURRENT", 10) => BTreeSet::from([0, 1, 2, 3, 4, 5, 6]),
            ("KAFKA-K2-1-BROKER-CURRENT", 17) => BTreeSet::from([0, 1]),
            ("KAFKA-K2-1-BROKER-CURRENT", 18) => BTreeSet::from([0, 1, 2, 3, 4]),
            ("KAFKA-K2-1-BROKER-CURRENT", 22) => BTreeSet::from([0, 1, 2, 3, 4, 5, 6]),
            ("KAFKA-K2-1-BROKER-CURRENT", 36) => BTreeSet::from([0, 1, 2]),
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", 18) => BTreeSet::from([0, 1]),
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", 10) => BTreeSet::from([0, 1]),
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", 22) => BTreeSet::from([0]),
            ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 17) => BTreeSet::from([0, 1]),
            ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 36) => BTreeSet::from([0]),
            _ => return Err(format!("field row {row_id} has no message domain")),
        };
        let declared_versions = version_set(text(row, "source_declared_versions")?)?;
        let source_versions = version_set(text(row, "source_versions")?)?;
        let parent_row_id = nullable_text(row, "parent_row_id")?;
        let mut expected_source_versions = declared_versions
            .intersection(&message_versions)
            .copied()
            .collect::<BTreeSet<_>>();

        let mut depth = 0_usize;
        if let Some(parent_row_id) = parent_row_id {
            nested_rows += 1;
            let parent = field_rows_by_id
                .get(parent_row_id)
                .ok_or_else(|| format!("field row {row_id} has an orphan parent"))?;
            if text(parent, "profile_id")? != profile
                || text(parent, "source_authority_id")? != authority
                || number(parent, "api_key")? != api_key
                || text(parent, "direction")? != direction
            {
                return Err(format!("field row {row_id} crossed its parent scope"));
            }
            expect_text(
                parent,
                "nested_projection_state",
                "NAMED_STRUCT_CHILDREN_PROJECTED_COMPLETE",
            )?;
            let parent_logical_type = text(parent, "logical_type")?;
            let _ = text(parent, "nested_type_name")?;
            let parent_canonical = text(parent, "canonical_field_id")?;
            let expected_child_prefix = match parent_logical_type {
                "ARRAY" => {
                    expect_text(parent, "element_type", "STRUCT")?;
                    format!("{parent_canonical}[].")
                }
                "STRUCT" if parent.get("element_type") == Some(&Value::Null) => {
                    format!("{parent_canonical}.")
                }
                _ => {
                    return Err(format!("field row {row_id} has a non-struct named parent"));
                }
            };
            if !canonical_field.starts_with(&expected_child_prefix) {
                return Err(format!(
                    "field row {row_id} flattened its named-struct canonical path"
                ));
            }
            let parent_source_versions = version_set(text(parent, "source_versions")?)?;
            expected_source_versions = expected_source_versions
                .intersection(&parent_source_versions)
                .copied()
                .collect();
            let projected_versions = version_set(text(row, "projected_versions")?)?;
            let parent_projected_versions = version_set(text(parent, "projected_versions")?)?;
            if !projected_versions.is_subset(&parent_projected_versions) {
                return Err(format!(
                    "field row {row_id} projected outside its parent versions"
                ));
            }

            let mut cursor = Some(parent_row_id);
            let mut ancestors = BTreeSet::new();
            while let Some(ancestor_id) = cursor {
                if !ancestors.insert(ancestor_id.to_owned()) {
                    return Err(format!("field row {row_id} has a parent cycle"));
                }
                let ancestor = field_rows_by_id
                    .get(ancestor_id)
                    .ok_or_else(|| format!("field row {row_id} has an orphan ancestor"))?;
                depth += 1;
                cursor = nullable_text(ancestor, "parent_row_id")?;
            }
        } else {
            top_level_rows += 1;
        }
        max_depth = max_depth.max(depth);
        if source_versions != expected_source_versions {
            return Err(format!(
                "field row {row_id} source versions do not match its declaration and ancestors"
            ));
        }

        let expected_nested_type = match (profile, canonical_field) {
            ("KAFKA-K2-1-BROKER-CURRENT", "API10.RESPONSE.COORDINATORS") => Some("Coordinator"),
            ("KAFKA-K2-1-BROKER-CURRENT", "API18.RESPONSE.API_KEYS") => Some("ApiVersion"),
            ("KAFKA-K2-1-BROKER-CURRENT", "API18.RESPONSE.SUPPORTED_FEATURES") => {
                Some("SupportedFeatureKey")
            }
            ("KAFKA-K2-1-BROKER-CURRENT", "API18.RESPONSE.FINALIZED_FEATURES") => {
                Some("FinalizedFeatureKey")
            }
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", "API18.RESPONSE.API_KEYS") => {
                Some("API_VERSIONS_V0")
            }
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR", "API10.RESPONSE.COORDINATOR") => {
                Some("FIND_COORDINATOR_BROKER_V0")
            }
            _ => None,
        };
        match (
            nullable_text(row, "nested_type_name")?,
            expected_nested_type,
        ) {
            (Some(actual), Some(expected)) if actual == expected => {
                named_struct_parents += 1;
            }
            (None, None) => {}
            _ => return Err(format!("field row {row_id} named struct changed")),
        }

        let expected_map_key = profile == "KAFKA-K2-1-BROKER-CURRENT"
            && matches!(
                canonical_field,
                "API18.RESPONSE.API_KEYS[].API_KEY"
                    | "API18.RESPONSE.SUPPORTED_FEATURES[].NAME"
                    | "API18.RESPONSE.FINALIZED_FEATURES[].NAME"
            );
        if boolean(row, "map_key")? != expected_map_key {
            return Err(format!("field row {row_id} map-key placement changed"));
        }
        if expected_map_key {
            map_key_rows += 1;
            if parent_row_id.is_none() || text(row, "projected_tagged_versions")? != "none" {
                return Err(format!("field row {row_id} has an invalid map key"));
            }
        }

        let nullable_versions = version_set(text(row, "nullable_versions")?)?;
        let compact_versions = version_set(text(row, "projected_compact_versions")?)?;
        let tagged_versions = version_set(text(row, "projected_tagged_versions")?)?;
        let projected_versions = version_set(text(row, "projected_versions")?)?;
        if !nullable_versions.is_subset(&source_versions)
            || !compact_versions.is_subset(&projected_versions)
            || !tagged_versions.is_subset(&projected_versions)
        {
            return Err(format!(
                "field row {row_id} has a field-scoped version escape"
            ));
        }
        compact_version_cells += compact_versions.len();
        if !tagged_versions.is_empty() {
            tagged_rows += 1;
            tagged_version_cells += tagged_versions.len();
        }

        let scope = (
            profile.to_owned(),
            api_key,
            direction.to_owned(),
            parent_row_id.map(str::to_owned),
        );
        let tag_buffer_text = text(row, "owning_struct_tag_buffer_projected_versions")?;
        if let Some(previous) = owner_tag_buffers.get(&scope) {
            if previous != tag_buffer_text {
                return Err(format!(
                    "field row {row_id} disagrees with sibling tag-buffer versions"
                ));
            }
        } else {
            owner_tag_buffers.insert(scope.clone(), tag_buffer_text.to_owned());
        }
        let tag_buffer_versions = version_set(tag_buffer_text)?;
        if !tag_buffer_versions.is_empty() {
            tag_buffer_rows += 1;
            tag_buffer_version_cells += tag_buffer_versions.len();
        }
        for tag_id in numeric_array(row, "projected_tag_ids")? {
            if !tag_ids_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(tag_id)
            {
                return Err(format!("field row {row_id} duplicates a tag ID"));
            }
        }
    }

    for parent in fields {
        if nullable_text(parent, "nested_type_name")?.is_none() {
            continue;
        }
        let parent_id = text(parent, "row_id")?;
        let mut child_orders = BTreeSet::new();
        let mut child_count = 0_usize;
        for child in fields {
            if nullable_text(child, "parent_row_id")? == Some(parent_id) {
                child_count += 1;
                child_orders.insert(number(child, "field_order")?);
            }
        }
        let expected_child_count: usize =
            if text(parent, "canonical_field_id")? == "API10.RESPONSE.COORDINATORS" {
                6
            } else {
                3
            };
        let expected_child_orders = if expected_child_count == 6 {
            BTreeSet::from([0, 1, 2, 3, 4, 5])
        } else {
            BTreeSet::from([0, 1, 2])
        };
        if child_count != expected_child_count || child_orders != expected_child_orders {
            return Err(format!(
                "named-struct parent {parent_id} lost its complete child set"
            ));
        }
    }
    let expected_tag_scope = (
        "KAFKA-K2-1-BROKER-CURRENT".to_owned(),
        18,
        "RESPONSE".to_owned(),
        None,
    );
    if tag_ids_by_scope != BTreeMap::from([(expected_tag_scope, BTreeSet::from([0, 1, 2, 3]))])
        || top_level_rows != 64
        || nested_rows != 24
        || named_struct_parents != 7
        || map_key_rows != 3
        || tagged_rows != 4
        || tagged_version_cells != 8
        || compact_version_cells != 40
        || tag_buffer_rows != 51
        || tag_buffer_version_cells != 159
        || max_depth != 1
    {
        return Err("field tree, compact or tag coverage changed".to_owned());
    }

    if field_profiles
        != BTreeMap::from([
            ("KAFKA-K2-1-BROKER-CURRENT".to_owned(), 54),
            ("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR".to_owned(), 27),
            ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR".to_owned(), 7),
        ])
        || field_api_keys != BTreeSet::from([10, 17, 18, 22, 36])
        || field_api_profiles.len() != 10
        || field_api_versions.len() != 32
        || field_version_cells != 228
        || explicit_schema_defaults != 14
        || implicit_generated_defaults != 43
        || explicit_generated_defaults != 11
        || explicit_struct_defaults != 3
        || implicit_nullable_struct_defaults != 3
        || required_no_defaults != 28
        || effective_default_value_rows != 60
        || effective_default_version_cells != 271
        || implicit_generated_defaults
            + explicit_generated_defaults
            + explicit_struct_defaults
            + implicit_nullable_struct_defaults
            + required_no_defaults
            != fields.len()
    {
        return Err("partial field projection coverage changed".to_owned());
    }
    for ((profile, api_key, direction, parent_row_id, version_slice), orders) in field_orders {
        let maximum = orders
            .last()
            .copied()
            .ok_or_else(|| "projected field order set must not be empty".to_owned())?;
        let expected_orders = (0..=maximum).collect::<BTreeSet<_>>();
        if orders != expected_orders {
            return Err(format!(
                "field order is not contiguous for {profile} API {api_key} {direction} parent {parent_row_id:?} version {version_slice:?}"
            ));
        }
    }
    if sorted_json_rows_sha256(fields)?
        != "a36a2029619156f3788a1185dfa3363a7225560346713fc22f16693ceafb5360"
    {
        return Err("field projection digest changed".to_owned());
    }

    let errors = array(artifact, "error_projection_rows")?;
    if errors.len() != EXPECTED_ERROR_PROJECTIONS.len() {
        return Err(format!(
            "expected {} partial authentication outcome rows, got {}",
            EXPECTED_ERROR_PROJECTIONS.len(),
            errors.len()
        ));
    }
    let expected_error_tuples = [
        ("KAFKA-K2-1-BROKER-CURRENT", 17, 0, "NONE"),
        (
            "KAFKA-K2-1-BROKER-CURRENT",
            17,
            33,
            "UNSUPPORTED_SASL_MECHANISM",
        ),
        ("KAFKA-K2-1-BROKER-CURRENT", 17, 34, "ILLEGAL_SASL_STATE"),
        ("KAFKA-K2-1-BROKER-CURRENT", 36, 0, "NONE"),
        (
            "KAFKA-K2-1-BROKER-CURRENT",
            36,
            58,
            "SASL_AUTHENTICATION_FAILED",
        ),
        ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 17, 0, "NONE"),
        (
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
            17,
            33,
            "UNSUPPORTED_SASL_MECHANISM",
        ),
        (
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
            17,
            34,
            "ILLEGAL_SASL_STATE",
        ),
        ("KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR", 36, 0, "NONE"),
        (
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR",
            36,
            58,
            "SASL_AUTHENTICATION_FAILED",
        ),
    ]
    .into_iter()
    .map(|(profile, api_key, error_code, error_name)| {
        (
            profile.to_owned(),
            api_key,
            error_code,
            error_name.to_owned(),
        )
    })
    .collect::<BTreeSet<_>>();

    let mut actual_error_tuples = BTreeSet::new();
    let mut error_row_ids = BTreeSet::new();
    let mut error_sets = BTreeSet::new();
    let mut error_profiles = BTreeSet::new();
    let mut error_version_cells = 0_usize;
    let mut conflict_rows = 0_usize;
    for row in errors {
        expect_exact_keys(row, ERROR_PROJECTION_ROW_KEYS, "error projection row")?;
        let row_id = text(row, "row_id")?;
        if !error_row_ids.insert(row_id.to_owned()) {
            return Err(format!("duplicate error projection row {row_id}"));
        }
        let expected = EXPECTED_ERROR_PROJECTIONS
            .iter()
            .find(|expected| expected.row_id == row_id)
            .ok_or_else(|| format!("unexpected error projection row {row_id}"))?;
        expect_text(row, "error_set_id", expected.error_set_id)?;
        expect_text(row, "profile_id", expected.profile_id)?;
        expect_text(row, "source_authority_id", expected.authority_id)?;
        let expected_source_refs = expected
            .source_refs
            .iter()
            .map(|source_ref| (*source_ref).to_owned())
            .collect::<Vec<_>>();
        if text_array(row, "source_refs")? != expected_source_refs {
            return Err(format!("error row {row_id} source references changed"));
        }
        expect_number(row, "api_key", expected.api_key)?;
        expect_text(row, "source_versions", expected.source_versions)?;
        expect_text(row, "projected_versions", expected.projected_versions)?;
        expect_text(row, "excluded_source_versions", expected.excluded_versions)?;
        expect_text(row, "error_name", expected.error_name)?;
        expect_number(row, "canonical_error_code", expected.error_code)?;
        match expected.comment_code {
            Some(comment_code) => expect_number(row, "api_comment_error_code", comment_code)?,
            None if row.get("api_comment_error_code") == Some(&Value::Null) => {}
            None => return Err(format!("error row {row_id} invented a comment code")),
        }
        expect_text(row, "outcome_class", expected.outcome_class)?;
        expect_text(row, "code_consistency_state", expected.consistency_state)?;
        let profile = text(row, "profile_id")?;
        let authority = text(row, "source_authority_id")?;
        let expected_authority = match profile {
            "KAFKA-K2-1-BROKER-CURRENT" => "KAFKA-K2-1-AUTH-APACHE-CURRENT",
            "KAFKA-K2-1-BROKER-WRAPPED-SASL-FLOOR" => "KAFKA-K2-1-AUTH-APACHE-WRAPPED-SASL-FLOOR",
            _ => return Err(format!("error row {row_id} escaped the two-profile slice")),
        };
        if authority != expected_authority {
            return Err(format!("error row {row_id} crossed source authorities"));
        }
        let api_key = number(row, "api_key")?;
        let error_code = number(row, "canonical_error_code")?;
        let error_name = text(row, "error_name")?;
        actual_error_tuples.insert((
            profile.to_owned(),
            api_key,
            error_code,
            error_name.to_owned(),
        ));
        error_profiles.insert(profile.to_owned());
        error_sets.insert(text(row, "error_set_id")?.to_owned());

        let source_versions = version_set(text(row, "source_versions")?)?;
        let projected_versions = version_set(text(row, "projected_versions")?)?;
        let excluded_versions = version_set(text(row, "excluded_source_versions")?)?;
        if projected_versions.is_empty()
            || !projected_versions.is_subset(&source_versions)
            || !excluded_versions.is_subset(&source_versions)
            || !projected_versions.is_disjoint(&excluded_versions)
            || projected_versions
                .union(&excluded_versions)
                .copied()
                .collect::<BTreeSet<_>>()
                != source_versions
        {
            return Err(format!("error row {row_id} has incoherent version sets"));
        }
        let candidate_versions = if profile == "KAFKA-K2-1-BROKER-CURRENT" {
            let reachable = array(artifact, "reachable_api_rows")?
                .iter()
                .find(|candidate| candidate.get("api_key").and_then(Value::as_u64) == Some(api_key))
                .ok_or_else(|| format!("missing current candidate range for API {api_key}"))?;
            version_set(text(reachable, "candidate_current_intersection")?)?
        } else {
            let historical = array(artifact, "historical_profile_api_range_rows")?
                .iter()
                .find(|candidate| {
                    candidate.get("profile_id").and_then(Value::as_str) == Some(profile)
                        && candidate.get("api_key").and_then(Value::as_u64) == Some(api_key)
                })
                .ok_or_else(|| format!("missing historical candidate range for API {api_key}"))?;
            version_set(text(historical, "incumbent_candidate_intersection")?)?
        };
        let candidate_source_versions = candidate_versions
            .intersection(&source_versions)
            .copied()
            .collect::<BTreeSet<_>>();
        if !candidate_source_versions.is_subset(&projected_versions) {
            return Err(format!(
                "error row {row_id} does not cover its source/candidate intersection"
            ));
        }
        let projected_outside_candidate = projected_versions
            .difference(&candidate_versions)
            .copied()
            .collect::<BTreeSet<_>>();
        let allowed_outside_candidate = if profile == "KAFKA-K2-1-BROKER-CURRENT" && api_key == 36 {
            BTreeSet::from([2])
        } else {
            BTreeSet::new()
        };
        if !projected_outside_candidate.is_subset(&allowed_outside_candidate) {
            return Err(format!(
                "error row {row_id} projected an unauthorized outside-candidate version"
            ));
        }
        error_version_cells += projected_versions.len();
        for source_ref in text_array(row, "source_refs")? {
            if !pinned_sources.contains(&(authority.to_owned(), source_ref.clone())) {
                return Err(format!(
                    "error row {row_id} references unpinned source {source_ref}"
                ));
            }
        }

        if boolean(row, "wire_enum_closed")? {
            return Err(format!(
                "error row {row_id} closed an open INT16 wire field"
            ));
        }
        expect_text(row, "enum_membership_state", "CONFIRMED_CANONICAL_ENUM")?;
        expect_text(row, "retry_policy_state", "UNPROJECTED_BLOCKING")?;
        expect_text(row, "downgrade_policy_state", "UNPROJECTED_BLOCKING")?;
        expect_text(
            row,
            "projection_state",
            "SOURCE_DERIVED_NORMAL_CASE_PARTIAL_NOT_ACCEPTED",
        )?;
        if row.get("accepted_version_range") != Some(&Value::Null) {
            return Err(format!("error row {row_id} acquired an accepted range"));
        }

        if error_code == 58 {
            expect_number(row, "api_comment_error_code", 57)?;
            expect_text(
                row,
                "code_consistency_state",
                "STALE_API_COMMENT_57_CANONICAL_ENUM_58",
            )?;
            conflict_rows += 1;
        } else {
            expect_text(row, "code_consistency_state", "CONSISTENT")?;
            if error_code == 0 {
                if row.get("api_comment_error_code") != Some(&Value::Null) {
                    return Err(format!("success row {row_id} invented a comment code"));
                }
                expect_text(row, "outcome_class", "SUCCESS_SENTINEL")?;
            } else {
                expect_number(row, "api_comment_error_code", error_code)?;
            }
        }
        expect_text(row, "membership_basis", "DEDICATED_HANDLER_EMITTED")?;
    }
    if actual_error_tuples != expected_error_tuples
        || error_profiles.len() != 2
        || error_sets != field_error_sets
        || error_sets.len() != 4
        || error_version_cells != 20
        || conflict_rows != 2
    {
        return Err("partial error projection coverage changed".to_owned());
    }
    if sorted_json_rows_sha256(errors)?
        != "2dae2b05d2c68aafb37233f613f58f94b6d2d6978ae4ec4f2ee2019d887feb5d"
    {
        return Err("error projection digest changed".to_owned());
    }

    let coverage = artifact
        .get("coverage_receipt")
        .ok_or_else(|| "coverage_receipt must exist".to_owned())?;
    for (key, expected) in [
        ("field_error_projection_source_row_count", 9),
        ("field_error_projection_source_total_byte_count", 239_139),
        ("partial_projection_profile_count", 3),
        ("partial_projection_api_key_count", 5),
        ("partial_projection_api_profile_count", 10),
        ("partial_projection_api_version_count", 32),
        ("field_projection_row_count", 88),
        ("field_projection_version_cell_count", 228),
        ("effective_default_projected_row_count", 88),
        ("effective_default_version_cell_count", 271),
        ("implicit_generated_type_default_row_count", 43),
        ("explicit_schema_literal_generated_default_row_count", 11),
        ("explicit_schema_literal_struct_default_row_count", 3),
        ("implicit_nullable_struct_default_row_count", 3),
        ("required_no_default_row_count", 28),
        ("effective_default_value_row_count", 60),
        ("error_projection_row_count", 10),
        ("error_projection_version_cell_count", 20),
        ("error_projection_source_conflict_row_count", 2),
        ("complete_field_projection_api_key_count", 0),
        ("complete_error_projection_api_key_count", 0),
        ("untouched_reachable_api_key_count", 17),
    ] {
        expect_number(coverage, key, expected)?;
    }
    expect_text(
        coverage,
        "field_error_projection_source_sorted_encoding",
        "UTF-8 authority_id TAB path TAB object_id TAB payload_byte_count TAB semantic_role LF, authority_id then path sort",
    )?;
    expect_text(
        coverage,
        "field_error_projection_source_projection_sha256",
        "9a32a3cb6572e4683cdb4f04ed2b4cc533d8af588b13fb748c014b26531ddef3",
    )?;
    expect_text(
        coverage,
        "field_projection_sorted_encoding",
        "RFC 8259 compact JSON with lexicographically sorted object keys, bytewise row_id sort, one LF per row",
    )?;
    expect_text(
        coverage,
        "field_projection_sha256",
        "a36a2029619156f3788a1185dfa3363a7225560346713fc22f16693ceafb5360",
    )?;
    expect_text(
        coverage,
        "error_projection_sorted_encoding",
        "RFC 8259 compact JSON with lexicographically sorted object keys, bytewise row_id sort, one LF per row",
    )?;
    expect_text(
        coverage,
        "error_projection_sha256",
        "2dae2b05d2c68aafb37233f613f58f94b6d2d6978ae4ec4f2ee2019d887feb5d",
    )?;
    Ok(())
}

fn validate_blocked_evidence(artifact: &Value) -> Result<(), String> {
    let header = artifact
        .get("header_contract")
        .ok_or_else(|| "header_contract must exist".to_owned())?;
    if numeric_array(
        header,
        "reachable_request_header_versions_in_22_row_frontier",
    )? != [1, 2]
        || numeric_array(
            header,
            "reachable_response_header_versions_in_22_row_frontier",
        )? != [0, 1]
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
        return Err(format!(
            "expected four blocked broker profiles, got {}",
            brokers.len()
        ));
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
    expect_text(probe, "path", "scripts/kafka_broker_parity_proof_runner.sh")?;
    expect_text(probe, "classification", "PROOF_ONLY_NONTERMINAL")?;
    expect_boolean(probe, "executed_for_k2_1", false)?;

    let gaps = array(artifact, "completion_gaps")?;
    if gaps.len() != 7 {
        return Err(format!(
            "expected seven completion gaps, got {}",
            gaps.len()
        ));
    }
    let gap_ids = gaps
        .iter()
        .map(|row| text(row, "gap_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if gap_ids.len() != 7 {
        return Err("completion gap IDs must be unique".to_owned());
    }
    let current_projection_gap = gaps
        .iter()
        .find(|row| row.get("gap_id").and_then(Value::as_str) == Some("KAFKA-K2-1-GAP-001"))
        .ok_or_else(|| "current and historical schema projection gap is missing".to_owned())?;
    expect_text(
        current_projection_gap,
        "description",
        "Extend the partial API 10, API 18, API 22 and authentication-body projection across the other 17 reachable APIs and any historical profile selected by broker-floor adjudication; pin each newly required interpretation source.",
    )?;
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
        ("current_schema_identity_pair_count", 22),
        ("current_schema_identity_file_count", 44),
        ("current_schema_identity_total_byte_count", 132_674),
        ("historical_schema_source_contract_count", 3),
        ("historical_schema_identity_profile_path_row_count", 46),
        ("historical_schema_identity_distinct_blob_count", 44),
        ("historical_schema_identity_total_byte_count", 424_804),
        ("historical_profile_api_range_row_count", 15),
        ("accepted_numeric_range_count", 0),
        ("field_projection_row_count", 88),
        ("error_projection_row_count", 10),
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
        "The 88 field rows cover API 10, API 18 and API 22 bodies",
        "API 10 body rows preserve current multi-coordinator and historical version-sliced scalar-coordinator trees",
        "API 18 body rows preserve the parent-linked named-struct tree",
        "API 22 body rows preserve flat source field order",
        "current generated empty-string TransactionalId default versus the historical nullable Struct null fallback",
        "current API 22 v6 is declared unstable by its source",
        "API 36 v2 flexible body, tag-buffer encoding and generated default behavior are statically projected",
        "Effective defaults are projected only for the 88 API 10, API 18, API 22 and authentication-body field rows",
        "historical two-argument SaslAuthenticateResponse convenience overload",
        "InitProducerId wrapper timeout, producer-ID sentinel or epoch behavior outside the declared schemas is likewise excluded",
        "do not claim that decoding ignores a field value present on the wire",
        "SASL_AUTHENTICATION_FAILED code 58",
        "stale code 57",
        "Pinned Git blob object IDs establish current and profile-scoped historical source identity only",
        "not per-file raw-byte SHA-256 security attestations",
        "Historical profile API ranges are candidate source-derived overlaps only",
        "empty API 23 intersection",
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
        "all 44 selected current request/response files",
        "not per-file raw-byte SHA-256 security attestations",
        "current-source object identity only",
        "three historical candidate profiles",
        "44 distinct",
        "OffsetForLeaderEpoch",
        "95,596",
        "88 field rows cover `FindCoordinator`, `ApiVersions`,\n`InitProducerId`",
        "source-established outcome-membership rows",
        "Nine additional projection-support source rows",
        "239,139",
        "Thirty-one rows project the API 10 body tree",
        "historical rows preserve v0\nand v1 separately",
        "`KeyType=0` is the one explicit current\nschema literal",
        "duplicate sibling ordinals are permitted\nonly across disjoint singleton version slices",
        "API 36 source v2 is now projected",
        "Twenty-four rows project the complete body-field tree declared for API 18",
        "Every flexible owning body struct has a tag buffer",
        "The separately selected API 18 response header remains",
        "Eighteen rows project the flat `InitProducerId` body",
        "generated\nempty string (`\"\"`) across v0-v6",
        "historical nullable field instead uses\nthe legacy `Struct` fallback and resolves to null",
        "five producer identifiers or epochs use `-1`",
        "source marks v6 unstable",
        "current API 36 source-only v2 form does not expand",
        "nullability alone does not make null the\ngenerated default",
        "historical nullable field instead falls back to null",
        "`Type` (and `ArrayOf` for mechanisms)",
        "two-argument `SaslAuthenticateResponse` convenience overload",
        "do not mean decoding ignores a value that",
        "SASL_AUTHENTICATION_FAILED=58",
        "stale code 57",
        "GetTelemetrySubscriptions",
        "PushTelemetry",
        "no numeric range is\naccepted",
        "K2.2 therefore remains blocked",
        "The packet does not prove full schema or error completeness",
        "defaults outside\nthe 88 API 10, API 18, API 22, and authentication-body rows",
        "protocol error or fallback behavior beyond the recorded schema defaults",
    ] {
        if !document.contains(needle) {
            return Err(format!("document is missing {needle:?}"));
        }
    }
    Ok(())
}

fn validate_checked_in_hashes(root: &Path) -> Result<(), String> {
    for (path, expected) in [(ARTIFACT_PATH, ARTIFACT_SHA256), (DOC_PATH, DOC_SHA256)] {
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
    validate_historical_schema_sources(artifact)?;
    validate_partial_body_projection(artifact)?;
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
    first_api.insert(
        "accepted_version_range".to_owned(),
        Value::String("3-10".to_owned()),
    );
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

    let mut changed_blob_identity = artifact.clone();
    let first_schema = changed_blob_identity
        .get_mut("schema_source_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "schema source mutation target missing".to_owned())?;
    first_schema.insert(
        "request_git_blob_sha1".to_owned(),
        Value::String("0000000000000000000000000000000000000000".to_owned()),
    );
    expect_invalid(
        &changed_blob_identity,
        &root,
        "changed current schema blob identity",
    )?;

    let mut wrong_source_authority = artifact.clone();
    let identity = wrong_source_authority
        .get_mut("schema_source_identity_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "schema identity contract mutation target missing".to_owned())?;
    identity.insert(
        "source_authority_id".to_owned(),
        Value::String("KAFKA-K2-1-AUTH-APACHE-LEGACY-BASIC".to_owned()),
    );
    expect_invalid(
        &wrong_source_authority,
        &root,
        "wrong schema source authority",
    )?;

    let mut changed_historical_blob = artifact.clone();
    let first_historical_source = changed_historical_blob
        .get_mut("historical_schema_source_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical schema source mutation target missing".to_owned())?;
    first_historical_source.insert(
        "git_blob_sha1".to_owned(),
        Value::String("0000000000000000000000000000000000000000".to_owned()),
    );
    expect_invalid(
        &changed_historical_blob,
        &root,
        "changed historical schema blob identity",
    )?;

    let mut changed_historical_role = artifact.clone();
    let first_historical_source = changed_historical_role
        .get_mut("historical_schema_source_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical semantic-role mutation target missing".to_owned())?;
    first_historical_source.insert(
        "semantic_role".to_owned(),
        Value::String("UNPINNED_ROLE".to_owned()),
    );
    expect_invalid(
        &changed_historical_role,
        &root,
        "changed historical semantic role",
    )?;

    let mut weakened_full_frontier_blocker = artifact.clone();
    let full_frontier_blocker = weakened_full_frontier_blocker
        .get_mut("historical_schema_source_contracts")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("profile_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-BROKER-DEFAULT-IDEMPOTENCE-FLOOR")
            })
        })
        .and_then(|row| row.get_mut("full_frontier_blocker"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "full-frontier blocker mutation target missing".to_owned())?;
    full_frontier_blocker.insert("broker_declared_max".to_owned(), Value::from(2));
    expect_invalid(
        &weakened_full_frontier_blocker,
        &root,
        "nonempty historical full-frontier intersection",
    )?;

    let mut accepted_historical_range = artifact.clone();
    let first_historical_range = accepted_historical_range
        .get_mut("historical_profile_api_range_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical profile range mutation target missing".to_owned())?;
    first_historical_range.insert(
        "accepted_version_range".to_owned(),
        Value::String("0".to_owned()),
    );
    expect_invalid(
        &accepted_historical_range,
        &root,
        "accepted historical range without terminal evidence",
    )?;

    let mut weakened_auth_bytes = artifact.clone();
    let auth_bytes = weakened_auth_bytes
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("canonical_field_id").and_then(Value::as_str)
                    == Some("API36.REQUEST.AUTH_BYTES")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "opaque authentication field mutation target missing".to_owned())?;
    auth_bytes.insert(
        "sensitivity".to_owned(),
        Value::String("NON_SECRET_CONTROL_METADATA".to_owned()),
    );
    expect_invalid(
        &weakened_auth_bytes,
        &root,
        "weakened opaque authentication material classification",
    )?;

    let mut omitted_flexible_encoding = artifact.clone();
    let current_api_36 = omitted_flexible_encoding
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-036-REQUEST-000-AUTH-BYTES")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "flexible-version mutation target missing".to_owned())?;
    current_api_36.insert(
        "projected_compact_versions".to_owned(),
        Value::String("none".to_owned()),
    );
    expect_invalid(
        &omitted_flexible_encoding,
        &root,
        "projected API 36 v2 without compact encoding contract",
    )?;

    let mut omitted_tag_buffer = artifact.clone();
    let current_api_36_response = omitted_tag_buffer
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-000-ERROR-CODE")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "flexible response mutation target missing".to_owned())?;
    current_api_36_response.insert(
        "owning_struct_tag_buffer_projected_versions".to_owned(),
        Value::String("none".to_owned()),
    );
    expect_invalid(
        &omitted_tag_buffer,
        &root,
        "projected API 36 v2 without owning-struct tag buffer contract",
    )?;

    let mut nullable_current_defaulted_to_null = artifact.clone();
    let current_error_message = nullable_current_defaulted_to_null
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-001-ERROR-MESSAGE")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "current error-message default mutation target missing".to_owned())?;
    current_error_message.insert(
        "effective_default_literal".to_owned(),
        Value::String("null".to_owned()),
    );
    expect_invalid(
        &nullable_current_defaulted_to_null,
        &root,
        "current nullable error message changed from empty string to null default",
    )?;

    let mut current_transactional_id_defaulted_to_null = artifact.clone();
    let current_transactional_id = current_transactional_id_defaulted_to_null
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-000-TRANSACTIONAL-ID")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "current transactional-ID default mutation target missing".to_owned())?;
    current_transactional_id.insert(
        "effective_default_literal".to_owned(),
        Value::String("null".to_owned()),
    );
    expect_invalid(
        &current_transactional_id_defaulted_to_null,
        &root,
        "current nullable transactional ID changed from empty string to null default",
    )?;

    let mut omitted_transactional_id_compact_encoding = artifact.clone();
    let current_transactional_id = omitted_transactional_id_compact_encoding
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-022-REQUEST-000-TRANSACTIONAL-ID")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "current transactional-ID compact mutation target missing".to_owned())?;
    current_transactional_id.insert(
        "projected_compact_versions".to_owned(),
        Value::String("none".to_owned()),
    );
    expect_invalid(
        &omitted_transactional_id_compact_encoding,
        &root,
        "projected API 22 v2-v6 transactional ID without compact encoding contract",
    )?;

    let mut historical_nullable_defaulted_to_empty = artifact.clone();
    let historical_error_message = historical_nullable_defaulted_to_empty
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-HISTORICAL-036-RESPONSE-001-ERROR-MESSAGE")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical error-message default mutation target missing".to_owned())?;
    historical_error_message.insert(
        "effective_default_state".to_owned(),
        Value::String("IMPLICIT_GENERATED_TYPE_DEFAULT".to_owned()),
    );
    historical_error_message.insert(
        "effective_default_literal".to_owned(),
        Value::String("\"\"".to_owned()),
    );
    expect_invalid(
        &historical_nullable_defaulted_to_empty,
        &root,
        "historical nullable Struct fallback changed from null to empty string",
    )?;

    let mut historical_transactional_id_defaulted_to_empty = artifact.clone();
    let historical_transactional_id = historical_transactional_id_defaulted_to_empty
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-HISTORICAL-022-REQUEST-000-TRANSACTIONAL-ID")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical transactional-ID default mutation target missing".to_owned())?;
    historical_transactional_id.insert(
        "effective_default_state".to_owned(),
        Value::String("IMPLICIT_GENERATED_TYPE_DEFAULT".to_owned()),
    );
    historical_transactional_id.insert(
        "effective_default_literal".to_owned(),
        Value::String("\"\"".to_owned()),
    );
    expect_invalid(
        &historical_transactional_id_defaulted_to_empty,
        &root,
        "historical transactional-ID Struct fallback changed from null to empty string",
    )?;

    let mut historical_required_default_invented = artifact.clone();
    let historical_mechanism = historical_required_default_invented
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-HISTORICAL-017-REQUEST-000-MECHANISM")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "historical required-field mutation target missing".to_owned())?;
    historical_mechanism.insert(
        "effective_default_literal".to_owned(),
        Value::String("\"\"".to_owned()),
    );
    expect_invalid(
        &historical_required_default_invented,
        &root,
        "invented default for historical required mechanism",
    )?;

    let mut narrowed_absent_version_default = artifact.clone();
    let session_lifetime = narrowed_absent_version_default
        .get_mut("field_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-FIELD-CURRENT-036-RESPONSE-003-SESSION-LIFETIME-MS")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "session-lifetime default mutation target missing".to_owned())?;
    session_lifetime.insert(
        "effective_default_versions".to_owned(),
        Value::String("1-2".to_owned()),
    );
    expect_invalid(
        &narrowed_absent_version_default,
        &root,
        "session lifetime default omitted for absent v0 field",
    )?;

    let mut normalized_stale_comment = artifact.clone();
    let authentication_failure = normalized_stale_comment
        .get_mut("error_projection_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("row_id").and_then(Value::as_str)
                    == Some("KAFKA-K2-1-ERROR-CURRENT-036-058-SASL-AUTHENTICATION-FAILED")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "error-code conflict mutation target missing".to_owned())?;
    authentication_failure.insert("canonical_error_code".to_owned(), Value::from(57));
    expect_invalid(
        &normalized_stale_comment,
        &root,
        "normalized stale comment over canonical error 58",
    )?;

    let mut unblocked_child = artifact;
    let policy = unblocked_child
        .get_mut("policy")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "policy mutation target missing".to_owned())?;
    policy.insert("k2_2_unblocked".to_owned(), Value::Bool(true));
    expect_invalid(&unblocked_child, &root, "premature K2.2 authorization")
}
