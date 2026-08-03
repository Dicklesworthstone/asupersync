//! Static contract for the Kafka K0.5 aggregate baseline disposition.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.1.5
//! Fixture: artifacts/kafka_k0_baseline_disposition_v1.json
//!
//! The contract reads checked-in repository bytes only. It does not contact a
//! broker, inspect ambient services, or promote planned, skipped, deterministic,
//! compile-only, wire-only, proof-only, or UNKNOWN evidence into runtime proof.

#![allow(missing_docs)]
#![deny(dead_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/kafka_k0_baseline_disposition_v1.json";
const DOC_PATH: &str = "docs/kafka_k0_baseline_disposition.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const ARTIFACT_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const DOC_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const ARTIFACT_ID: &str = "kafka-k0-baseline-disposition-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.5";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const BASELINE_REVISION: &str = "d4db2d3f072bd92281f35829dc1a5c92bc69f376";
const INVENTORY_STATE: &str = "K0_5_AGGREGATE_FROZEN_KEEP_INCUMBENT";
const NATIVE_EPIC: &str = "asupersync-dep-p7-kafka-removal-sarszu.2";
const K1_GATE: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const K12_TERMINAL: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.12.5";
const K13_TERMINAL: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.13.6";
const K14_REFRESH: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.14.1";
const K15_CUTOVER: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.15";
const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K0.5 BASELINE DISPOSITION -->";
const DOC_END: &str = "<!-- END KAFKA K0.5 BASELINE DISPOSITION -->";

const IMPORTED_SOURCE_PIN_COUNT: usize = 266;
const UNIQUE_SOURCE_PATH_COUNT: usize = 247;
const SOURCE_PATH_OVERLAP_GROUP_COUNT: usize = 15;
const ALL_DEFINITION_AND_REFERENCE_COUNT: usize = 1_030;
const PRIMARY_STABLE_ID_COUNT: usize = 903;
const CORE_DEFINITION_ID_COUNT: usize = 892;
const CONTRADICTION_INPUT_ID_COUNT: usize = 11;
const AUTHORITY_REFERENCE_COUNT: usize = 127;
const PUBLIC_SYMBOL_JOIN_COUNT: usize = 30;
const SEMANTIC_JOIN_COUNT: usize = 97;
const K0_1_PROFILE_COUNT: usize = 13;
const K0_3_PROFILE_MAPPING_COUNT: usize = 17;
const K0_4_FIXTURE_COUNT: usize = 67;
const K0_3_INHERITED_FIXTURE_COUNT: usize = 48;
const K0_4_DIRECT_FIXTURE_COUNT: usize = 19;
const LEXICAL_COLLISION_GROUP_COUNT: usize = 34;
const LEXICAL_COLLISION_SITE_COUNT: usize = 232;
const ROUTE_ROW_COUNT: usize = 87;
const ROUTE_EDGE_COUNT: usize = 126;
const ROUTE_OWNER_COUNT: usize = 49;
const EXPLICIT_OWNED_UNKNOWN_COUNT: usize = 17;
const REDUCED_UNKNOWN_SELECTOR_COUNT: usize = 142;

const PRIMARY_ID_SHA256: &str =
    "38eb986feff75d2e1e172e444e7d488c765ab42910b6b470056852dea3b0cb6e";
const CORE_ID_SHA256: &str =
    "43d9deb2ff6bfa772ec058e8e32e4eb4fb3be099d93c3b152685721be05d4eea";
const CONTRADICTION_ID_SHA256: &str =
    "60a656176b398a9b045b8c5cc1c2f2cede611683d3330c2a519a70ebf9bb72f0";
const K0_1_SYMBOL_ID_SHA256: &str =
    "307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28";
const K0_2_SEMANTIC_ID_SHA256: &str =
    "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7";
const K0_1_PROFILE_ID_SHA256: &str =
    "882b6f73ee7c5abfe73080804fcd082c05dddd9c4002ee61ff9336f0a0d439eb";
const K0_3_PROFILE_MAPPING_SHA256: &str =
    "535d71b0db091352aa1b1df6418af9f0989b34c7c89584fe5e15b3614dce0438";
const K0_4_FIXTURE_JOIN_SHA256: &str =
    "f0200bd742a0a7a6374cd7dc87d9b1832c8f6d5a79e1f363db6464acfbe2bba2";
const LEXICAL_COLLISION_SHA256: &str =
    "48d272658eef24ca2a4f32d33de082846b52f720d3b5f6ce63b6ea33b50eb9c3";
const ROUTE_PROJECTION_SHA256: &str =
    "78ac2d846c8c21a1ed741ddb6a17c13c73cc57da86ae97a28577d2a061670dbc";
const ROUTE_OWNER_ID_SHA256: &str =
    "8eb70d75bda5b08007d844cee45bca48383d875ddf795610c9e0f936d1f92e88";
const REDUCED_UNKNOWN_SELECTOR_SHA256: &str =
    "5c7fb727bc79d4f8be1c979fadda8bcfd261da0953e972a32a89bef27a28b18c";
const SOURCE_PIN_FULL_ROW_SHA256: &str =
    "24dbef7eff2ceb1bc09c1558802f81352f0ba2e78e8940547ca7d15d8583a0d2";
const SOURCE_PIN_PATH_SHA256: &str =
    "d5631183e1560d87aeb50ca953d836b4405110b30f81c98aab099c6a5f1eb4c3";
const SOURCE_PIN_OVERLAP_SHA256: &str =
    "401cc0ed50ca786de031643b8faf34376fde06a2c2aa2f9badcde66cca19c414";
const JOURNEY_ID_SHA256: &str =
    "c5a9f1947a5ecf55898c61414bb39bf753cd236fe33157083994acd63176367f";
const VECTOR_ID_SHA256: &str =
    "73491562ae3df3f7ea6729c30834cf3cb134a002ec5d682255277df5e508e73f";
const FIXTURE_ID_SHA256: &str =
    "bb8f922cc63f97efcfb0c76a6e26fdf923775650af8cd613f50da55c95cbb376";
const FIXTURE_PATH_SHA256: &str =
    "d9542095b391dbd44a0f8d855d6cfb87e41b981642430a0de662a2965ad26db0";
const FIXTURE_PROFILE_ID_SHA256: &str =
    "b1848945221e425d78007ee47bced23e62b700a5e43fc6a8300124d42c8d8d09";
const ENVIRONMENT_ID_SHA256: &str =
    "372de832a4de112e3ee8bc45b3af978d749b24c3f825416bd8e8b2d4523d831e";
const AUTHORITY_REFERENCE_ID_SHA256: &str =
    "a2336ba563186e1bc4a0a935ced3731e2292e8a6d54b0858311662113b267a94";
const EXPLICIT_UNKNOWN_ID_SHA256: &str =
    "33c9cdf3dca86570c906c46a902b2ec7ad8ee19aa074b0375afda36d64e63d20";
const ROUTE_FULL_ROW_SHA256: &str =
    "efbc7795ffa4c5144ffcedf6ac2659603e9a298800b6d7130df1081d47722b43";
const CLAIMS_FULL_ROW_SHA256: &str =
    "7aa4a92f32d0c69a67a6cedbb1d5b5157b2f9b7d4243bd53c3a4491007bb3727";
const AGGREGATE_CLAIMS_SHA256: &str =
    "2a4867239016cef413e38d68bc1d788de89a23bac7ac08890632256013b4d1b6";
const FIXTURE_PROFILE_MAPPING_SHA256: &str =
    "0c1a77c6b9db4bc3efc478ba4313a65193ab849f7020d5f1f3b2fa4d73c1be9d";
const AUTHORITY_REFERENCE_MAPPING_SHA256: &str =
    "0a88e36135222e48bfeab5095be3896ef946cc9fa05f38cbd19d2cb656107cf9";
const LEXICAL_GROUP_ID_SHA256: &str =
    "e6a23cd6c436c1dd6b775481d2683eb53ca860a928572306f2ea910af3c8231b";
const LEXICAL_SITE_ID_SHA256: &str =
    "5daaea539090869d6391f8d3011fa0a116cb15a6f29f540aa3cceccff4961440";
const LEXICAL_MAPPING_SHA256: &str =
    "bdd6ae2026e2675419b2a9b4614fd10e713b6077e1c4a945f5770f5f469888aa";
const EXPLICIT_UNKNOWN_OWNER_EDGE_SHA256: &str =
    "7b36d67eb6a635bf112838ea0104aab9b45ad918798af627ec176d01c61e554c";
const EXPLICIT_UNKNOWN_OWNER_ID_SHA256: &str =
    "54a6d2f9844b771aed0b2b714d4682ea2ba40092447beeef08df0231c9e08df4";
const INTERNAL_HANDOFF_SHA256: &str =
    "461050ab95066ce754a177798c2c22453a008992ff5c9c1e98d807383a240851";

const ROOT_KEYS: &[&str] = &[
    "schema_version",
    "artifact_id",
    "program_id",
    "bead_id",
    "capability_id",
    "captured_date_utc",
    "baseline_revision",
    "inventory_state",
    "authority",
    "policy",
    "child_packets",
    "coverage_sets",
    "exact_joins",
    "collision_groups",
    "unknown_disposition",
    "gap_routing",
    "claims_projection",
    "disposition_receipt",
    "independent_terminal_gates",
    "no_claim_boundaries",
    "coverage_receipt",
];

#[derive(Clone, Copy)]
struct ChildFilePin {
    packet_id: &'static str,
    role: &'static str,
    path: &'static str,
    sha256: &'static str,
    byte_count: u64,
    record_count: u64,
}

const CHILD_FILE_PINS: &[ChildFilePin] = &[
    ChildFilePin {
        packet_id: "K0.1",
        role: "artifact_file",
        path: "artifacts/kafka_capability_inventory_v1.json",
        sha256: "5dfe71df6daaa056f8f4d22d08fa934b5398baeeff0d5ff27eb0f544405251d6",
        byte_count: 41_921,
        record_count: 1_015,
    },
    ChildFilePin {
        packet_id: "K0.1",
        role: "document_file",
        path: "docs/kafka_capability_inventory.md",
        sha256: "1b76345e60be52b33fe1ba94ee26c2116859126114c0e30959fdf9eb2a8dac51",
        byte_count: 9_106,
        record_count: 189,
    },
    ChildFilePin {
        packet_id: "K0.1",
        role: "contract_file",
        path: "tests/kafka_capability_inventory_contract.rs",
        sha256: "d1e7492185f798b5affc7dea4c62761552bc6a8804f1b61b14d379f75df23c5e",
        byte_count: 28_908,
        record_count: 858,
    },
    ChildFilePin {
        packet_id: "K0.2",
        role: "artifact_file",
        path: "artifacts/kafka_incumbent_semantics_matrix_v1.json",
        sha256: "fec9ac1a1e9ac63ce25393962c843f9169cae804c16c470ada2bf670ab0fc4ec",
        byte_count: 228_933,
        record_count: 2_560,
    },
    ChildFilePin {
        packet_id: "K0.2",
        role: "document_file",
        path: "docs/kafka_incumbent_semantics_matrix.md",
        sha256: "7cf46fb6eaa7ded66b6d1d04a7c711f4ce687252bb42eaa05d77e3a5e4b79ff5",
        byte_count: 31_495,
        record_count: 536,
    },
    ChildFilePin {
        packet_id: "K0.2",
        role: "contract_file",
        path: "tests/kafka_incumbent_semantics_matrix_contract.rs",
        sha256: "36bd4fe722d8ac79c05c21a29772d592211c8f8e3b5a78c0ba6ebd7aeb41caf9",
        byte_count: 69_301,
        record_count: 1_692,
    },
    ChildFilePin {
        packet_id: "K0.3",
        role: "artifact_file",
        path: "artifacts/kafka_downstream_user_journey_inventory_v1.json",
        sha256: "52f8dc9a2695a170b14c85c9b29b6e60f95e05bd013d3d9db0dab8d94a1ced09",
        byte_count: 1_171_732,
        record_count: 17_988,
    },
    ChildFilePin {
        packet_id: "K0.3",
        role: "document_file",
        path: "docs/kafka_downstream_user_journey_inventory.md",
        sha256: "12ccb95710c004751634d7c41218a0d6855675870b4246ab680aa0eb63d90434",
        byte_count: 40_663,
        record_count: 612,
    },
    ChildFilePin {
        packet_id: "K0.3",
        role: "contract_file",
        path: "tests/kafka_downstream_user_journey_inventory_contract.rs",
        sha256: "a0f1d8dd4f66ba2c9617ef0ba7bce4113203ae14a0b4bcd1dc7b725f1f9edf37",
        byte_count: 215_240,
        record_count: 5_290,
    },
    ChildFilePin {
        packet_id: "K0.4",
        role: "artifact_file",
        path: "artifacts/kafka_broker_fixture_provenance_matrix_v1.json",
        sha256: "03406fe1146345ef7c50ec5e4077f0c6131db963e3776215629e9d34a781a643",
        byte_count: 119_245,
        record_count: 2_187,
    },
    ChildFilePin {
        packet_id: "K0.4",
        role: "document_file",
        path: "docs/kafka_broker_fixture_provenance_matrix.md",
        sha256: "e9b4e04d8d3dd5ccf967182dabcb9f1e16cb712e7a154123d82bfe0318a201a9",
        byte_count: 25_259,
        record_count: 346,
    },
    ChildFilePin {
        packet_id: "K0.4",
        role: "contract_file",
        path: "tests/kafka_broker_fixture_provenance_matrix_contract.rs",
        sha256: "824dc03bc9636378f9b554f44affa8a24def57b89c34d6a631429304b00ee73b",
        byte_count: 128_726,
        record_count: 3_410,
    },
];

#[derive(Clone, Copy)]
struct ChildIdentity {
    packet_id: &'static str,
    artifact_id: &'static str,
    bead_id: &'static str,
    baseline_revision: &'static str,
    inventory_state: &'static str,
    artifact_path: &'static str,
    authority_revision: Option<&'static str>,
    authority_revision_state: &'static str,
}

const CHILD_IDENTITIES: &[ChildIdentity] = &[
    ChildIdentity {
        packet_id: "K0.1",
        artifact_id: "kafka-capability-inventory-v1",
        bead_id: "asupersync-dep-p7-kafka-removal-sarszu.1.1",
        baseline_revision: "2d811170e956966e960db122a0d634a5b60c56e0",
        inventory_state: "K0_1_SOURCE_REACHABILITY_FROZEN",
        artifact_path: "artifacts/kafka_capability_inventory_v1.json",
        authority_revision: Some("2d811170e956966e960db122a0d634a5b60c56e0"),
        authority_revision_state: "PRESENT_MATCHES_BASELINE",
    },
    ChildIdentity {
        packet_id: "K0.2",
        artifact_id: "kafka-incumbent-semantics-matrix-v1",
        bead_id: "asupersync-dep-p7-kafka-removal-sarszu.1.2",
        baseline_revision: "b4997e8fe4de098a5a30ff468418460b59ca414a",
        inventory_state: "K0_2_INCUMBENT_SEMANTICS_FROZEN",
        artifact_path: "artifacts/kafka_incumbent_semantics_matrix_v1.json",
        authority_revision: Some("b4997e8fe4de098a5a30ff468418460b59ca414a"),
        authority_revision_state: "PRESENT_MATCHES_BASELINE",
    },
    ChildIdentity {
        packet_id: "K0.3",
        artifact_id: "kafka-downstream-user-journey-inventory-v1",
        bead_id: "asupersync-dep-p7-kafka-removal-sarszu.1.3",
        baseline_revision: "ae22e710d87412b38e546b32e9702106619481d5",
        inventory_state: "K0_3_LOCAL_STATIC_AND_CALL_SITE_CENSUS_FROZEN_EXTERNAL_UNKNOWN",
        artifact_path: "artifacts/kafka_downstream_user_journey_inventory_v1.json",
        authority_revision: Some("ae22e710d87412b38e546b32e9702106619481d5"),
        authority_revision_state: "PRESENT_MATCHES_BASELINE",
    },
    ChildIdentity {
        packet_id: "K0.4",
        artifact_id: "kafka-broker-fixture-provenance-matrix-v1",
        bead_id: "asupersync-dep-p7-kafka-removal-sarszu.1.4",
        baseline_revision: "012c13714db267a4fba928db9f900b70d6c1d25a",
        inventory_state: "K0_4_STATIC_FIXTURE_AND_PROVENANCE_MATRIX_FROZEN_RUNTIME_UNKNOWN",
        artifact_path: "artifacts/kafka_broker_fixture_provenance_matrix_v1.json",
        authority_revision: None,
        authority_revision_state: "ABSENT_BY_CHILD_SCHEMA",
    },
];

struct ChildArtifacts {
    k0_1: Value,
    k0_2: Value,
    k0_3: Value,
    k0_4: Value,
}

impl ChildArtifacts {
    fn get(&self, packet_id: &str) -> &Value {
        match packet_id {
            "K0.1" => &self.k0_1,
            "K0.2" => &self.k0_2,
            "K0.3" => &self.k0_3,
            "K0.4" => &self.k0_4,
            _ => panic!("unsupported child packet {packet_id}"),
        }
    }
}

#[derive(Clone, Debug)]
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

    fn namespace(&self) -> String {
        format!("{}/{}/{}", self.stage, self.collection, self.raw_id)
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

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn load_children() -> ChildArtifacts {
    ChildArtifacts {
        k0_1: parse_repo_json(CHILD_IDENTITIES[0].artifact_path),
        k0_2: parse_repo_json(CHILD_IDENTITIES[1].artifact_path),
        k0_3: parse_repo_json(CHILD_IDENTITIES[2].artifact_path),
        k0_4: parse_repo_json(CHILD_IDENTITIES[3].artifact_path),
    }
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

fn unsigned(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn require_exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected_set(expected) {
        return Err(format!("{label} exact key set drifted"));
    }
    Ok(())
}

fn require_equal(actual: &Value, expected: Value, label: &str) -> Result<(), String> {
    if actual != &expected {
        return Err(format!("{label} drifted"));
    }
    Ok(())
}

fn sorted_newline_sha256(values: impl IntoIterator<Item = String>) -> String {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    let mut projection = String::new();
    for value in values {
        projection.push_str(&value);
        projection.push('\n');
    }
    sha256_hex(projection.as_bytes())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("scalar JSON serialization cannot fail")
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{values}]")
        }
        Value::Object(object) => {
            let fields = object
                .iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key)
                        .expect("JSON object key serialization cannot fail");
                    format!("{key}:{}", canonical_json(value))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
    }
}

fn compare_record_ids(left: &Value, right: &Value) -> std::cmp::Ordering {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left
            .as_u64()
            .expect("record IDs must be nonnegative integers")
            .cmp(
                &right
                    .as_u64()
                    .expect("record IDs must be nonnegative integers"),
            ),
        (Value::String(left), Value::String(right)) => left.cmp(right),
        _ => canonical_json(left).cmp(&canonical_json(right)),
    }
}

fn canonical_record_projection_sha256(
    mut records: Vec<(String, String, Value, Value)>,
) -> String {
    records.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| compare_record_ids(&left.2, &right.2))
    });
    let mut projection = String::new();
    for (child, collection, id, row) in records {
        let record = serde_json::json!({
            "child": child,
            "collection": collection,
            "id": id,
            "row": row,
        });
        projection.push_str(&canonical_json(&record));
        projection.push('\n');
    }
    sha256_hex(projection.as_bytes())
}

fn require_unique_string_field(rows: &[Value], key: &str, label: &str) -> Result<(), String> {
    let ids = rows
        .iter()
        .map(|row| text(row, key).to_owned())
        .collect::<BTreeSet<_>>();
    if ids.len() != rows.len() {
        return Err(format!("{label} {key} values must be unique"));
    }
    Ok(())
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing row where {key}={expected}"))
}

fn validate_live_child_file_pins() -> Result<(), String> {
    if CHILD_FILE_PINS.len() != 12 {
        return Err("exactly twelve child files must be pinned".to_owned());
    }
    let mut paths = BTreeSet::new();
    for pin in CHILD_FILE_PINS {
        if !paths.insert(pin.path) {
            return Err(format!("duplicate child-file path {}", pin.path));
        }
        let bytes = read_repo_bytes(pin.path);
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| format!("{} must be UTF-8: {error}", pin.path))?;
        if sha256_hex(&bytes) != pin.sha256
            || u64::try_from(bytes.len()).expect("child byte count must fit u64")
                != pin.byte_count
            || u64::try_from(source.lines().count()).expect("child line count must fit u64")
                != pin.record_count
        {
            return Err(format!("child-file byte pin drifted: {}", pin.path));
        }
    }
    Ok(())
}

fn validate_child_identities(children: &ChildArtifacts) -> Result<(), String> {
    for expected in CHILD_IDENTITIES {
        let child = children.get(expected.packet_id);
        let child_authority_revision = child.get("authority_revision").and_then(Value::as_str);
        if child.get("schema_version").and_then(Value::as_u64) != Some(1)
            || text(child, "artifact_id") != expected.artifact_id
            || text(child, "program_id") != PROGRAM_ID
            || text(child, "capability_id") != CAPABILITY_ID
            || text(child, "bead_id") != expected.bead_id
            || text(child, "baseline_revision") != expected.baseline_revision
            || text(child, "inventory_state") != expected.inventory_state
            || child_authority_revision != expected.authority_revision
        {
            return Err(format!("{} child identity drifted", expected.packet_id));
        }
        if expected.authority_revision.is_some()
            && child_authority_revision != Some(expected.baseline_revision)
        {
            return Err(format!(
                "{} authority revision must equal its baseline",
                expected.packet_id
            ));
        }
    }
    Ok(())
}

fn validate_aggregate_child_packet_pins(packet: &Value) -> Result<(), String> {
    let children = array(packet, "child_packets");
    if children.len() != CHILD_IDENTITIES.len() {
        return Err("aggregate must contain exactly four child packets".to_owned());
    }
    require_unique_string_field(children, "packet_id", "child packets")?;
    for expected in CHILD_IDENTITIES {
        let child = find_row(children, "packet_id", expected.packet_id);
        require_exact_keys(
            child,
            &[
                "packet_id",
                "bead_id",
                "artifact_id",
                "schema_version",
                "baseline_revision",
                "authority_revision",
                "authority_revision_state",
                "inventory_state",
                "files",
            ],
            expected.packet_id,
        )?;
        if text(child, "artifact_id") != expected.artifact_id
            || text(child, "bead_id") != expected.bead_id
            || unsigned(child, "schema_version") != 1
            || text(child, "baseline_revision") != expected.baseline_revision
            || child.get("authority_revision").and_then(Value::as_str)
                != expected.authority_revision
            || text(child, "authority_revision_state") != expected.authority_revision_state
            || text(child, "inventory_state") != expected.inventory_state
        {
            return Err(format!("{} aggregate child identity drifted", expected.packet_id));
        }
        let files = array(child, "files");
        if files.len() != 3 {
            return Err(format!("{} must pin exactly three files", expected.packet_id));
        }
        require_unique_string_field(files, "role", expected.packet_id)?;
        for expected_file in CHILD_FILE_PINS
            .iter()
            .filter(|pin| pin.packet_id == expected.packet_id)
        {
            let role = match expected_file.role {
                "artifact_file" => "ARTIFACT",
                "document_file" => "DOCUMENT",
                "contract_file" => "CONTRACT",
                other => panic!("unsupported child file role {other}"),
            };
            let actual = find_row(files, "role", role);
            require_exact_keys(
                actual,
                &["role", "path", "byte_count", "record_count", "sha256"],
                expected_file.path,
            )?;
            if text(actual, "role") != role
                || text(actual, "path") != expected_file.path
                || text(actual, "sha256") != expected_file.sha256
                || unsigned(actual, "byte_count") != expected_file.byte_count
                || unsigned(actual, "record_count") != expected_file.record_count
            {
                return Err(format!("{} aggregate file pin drifted", expected_file.path));
            }
        }
    }
    Ok(())
}

fn validate_one_source_pin(
    stage: &str,
    pin: &Value,
    direct_k0_4: bool,
) -> Result<(String, String, u64), String> {
    let path = text(pin, "path");
    let bytes = read_repo_bytes(path);
    let expected_hash = text(pin, "sha256");
    if sha256_hex(&bytes) != expected_hash {
        return Err(format!("{stage} source pin hash drifted for {path}"));
    }
    let expected_records = if direct_k0_4 && path.starts_with("fuzz/corpus/") {
        u64::from(!bytes.is_empty())
    } else {
        u64::try_from(
            std::str::from_utf8(&bytes)
                .map_err(|error| format!("{path} must be UTF-8: {error}"))?
                .lines()
                .count(),
        )
        .expect("source record count must fit u64")
    };
    if unsigned(pin, "record_count") != expected_records {
        return Err(format!("{stage} source pin record count drifted for {path}"));
    }
    if let Some(byte_count) = pin.get("byte_count").and_then(Value::as_u64)
        && byte_count != u64::try_from(bytes.len()).expect("source byte count must fit u64")
    {
        return Err(format!("{stage} source pin byte count drifted for {path}"));
    }
    Ok((path.to_owned(), expected_hash.to_owned(), expected_records))
}

fn validate_source_pin_rollup(children: &ChildArtifacts) -> Result<(), String> {
    let groups = [
        (
            "K0.1",
            "source_pins",
            array(&children.k0_1, "source_pins"),
            "pin_id",
            false,
        ),
        (
            "K0.2",
            "source_pins",
            array(&children.k0_2, "source_pins"),
            "pin_id",
            false,
        ),
        (
            "K0.3",
            "source_pins",
            array(&children.k0_3, "source_pins"),
            "pin_id",
            false,
        ),
        (
            "K0.4",
            "direct_source_pins",
            array(&children.k0_4, "direct_source_pins"),
            "pin_id",
            true,
        ),
    ];
    let mut imported_count = 0usize;
    let mut paths: BTreeMap<String, Vec<(String, String, String, u64)>> = BTreeMap::new();
    let mut canonical_rows = Vec::new();
    for (stage, collection, rows, id_field, direct_k0_4) in groups {
        require_unique_string_field(rows, id_field, stage)?;
        imported_count += rows.len();
        for row in rows {
            let (path, hash, records) = validate_one_source_pin(stage, row, direct_k0_4)?;
            paths.entry(path).or_default().push((
                stage.to_owned(),
                text(row, id_field).to_owned(),
                hash,
                records,
            ));
            canonical_rows.push((
                stage.to_owned(),
                collection.to_owned(),
                Value::String(text(row, id_field).to_owned()),
                row.clone(),
            ));
        }
    }
    if imported_count != IMPORTED_SOURCE_PIN_COUNT || paths.len() != UNIQUE_SOURCE_PATH_COUNT {
        return Err("source-pin imported/unique counts drifted".to_owned());
    }
    if canonical_record_projection_sha256(canonical_rows) != SOURCE_PIN_FULL_ROW_SHA256
        || sorted_newline_sha256(paths.keys().cloned()) != SOURCE_PIN_PATH_SHA256
    {
        return Err("source-pin canonical row/path digest drifted".to_owned());
    }
    let overlaps = paths.values().filter(|rows| rows.len() > 1).count();
    if overlaps != SOURCE_PATH_OVERLAP_GROUP_COUNT {
        return Err("source-pin overlap-group count drifted".to_owned());
    }
    let overlap_pin_rows = paths
        .iter()
        .filter(|(_, rows)| rows.len() > 1)
        .flat_map(|(path, rows)| {
            rows.iter().map(move |(child, pin_id, hash, _)| {
                format!("{path}\t{child}\t{pin_id}\t{hash}")
            })
        })
        .collect::<Vec<_>>();
    if overlap_pin_rows.len() != 34
        || sorted_newline_sha256(overlap_pin_rows) != SOURCE_PIN_OVERLAP_SHA256
    {
        return Err("source-pin overlap tuple projection drifted".to_owned());
    }
    for (path, rows) in paths {
        if rows
            .iter()
            .map(|(_, _, hash, records)| (hash, records))
            .collect::<BTreeSet<_>>()
            .len()
            != 1
        {
            return Err(format!("conflicting source pins for {path}"));
        }
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
) {
    definitions.extend(array(artifact, collection).iter().map(|row| Definition {
        stage: stage.to_owned(),
        collection: collection.to_owned(),
        raw_id: text(row, id_field).to_owned(),
        authority_reference,
        contradiction_input,
    }));
}

fn collect_definitions(children: &ChildArtifacts) -> Vec<Definition> {
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
            &children.k0_1,
            collection,
            id_field,
            false,
            false,
        );
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
            &children.k0_2,
            collection,
            id_field,
            false,
            false,
        );
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
            &children.k0_3,
            collection,
            id_field,
            authority_reference,
            false,
        );
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
            &children.k0_4,
            collection,
            id_field,
            false,
            contradiction_input,
        );
    }
    definitions
}

fn validate_definition_census(children: &ChildArtifacts) -> Result<(), String> {
    let definitions = collect_definitions(children);
    if definitions.len() != ALL_DEFINITION_AND_REFERENCE_COUNT {
        return Err("definition/reference row count drifted".to_owned());
    }
    let namespaces = definitions
        .iter()
        .map(Definition::namespace)
        .collect::<BTreeSet<_>>();
    if namespaces.len() != definitions.len() {
        return Err("namespaced stable IDs must be unique".to_owned());
    }
    let primary = definitions
        .iter()
        .filter(|definition| !definition.authority_reference)
        .collect::<Vec<_>>();
    let core = primary
        .iter()
        .copied()
        .filter(|definition| !definition.contradiction_input)
        .collect::<Vec<_>>();
    let contradictions = primary
        .iter()
        .copied()
        .filter(|definition| definition.contradiction_input)
        .collect::<Vec<_>>();
    if primary.len() != PRIMARY_STABLE_ID_COUNT
        || core.len() != CORE_DEFINITION_ID_COUNT
        || contradictions.len() != CONTRADICTION_INPUT_ID_COUNT
    {
        return Err("primary/core/contradiction stable-ID counts drifted".to_owned());
    }
    if sorted_newline_sha256(primary.iter().map(|definition| definition.tuple()))
        != PRIMARY_ID_SHA256
        || sorted_newline_sha256(core.iter().map(|definition| definition.tuple()))
            != CORE_ID_SHA256
        || sorted_newline_sha256(contradictions.iter().map(|definition| definition.tuple()))
            != CONTRADICTION_ID_SHA256
    {
        return Err("primary/core/contradiction stable-ID digest drifted".to_owned());
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
        .filter(|group| group.len() > 1)
        .collect::<Vec<_>>();
    if collisions.len() != AUTHORITY_REFERENCE_COUNT {
        return Err("sanctioned raw-ID collision-group count drifted".to_owned());
    }
    if sorted_newline_sha256(
        collisions
            .iter()
            .map(|group| group[0].raw_id.to_owned()),
    ) != AUTHORITY_REFERENCE_ID_SHA256
    {
        return Err("authority-reference ID set drifted".to_owned());
    }
    let mut authority_mapping = Vec::new();
    for group in collisions {
        if group.len() != 2
            || group.iter().filter(|row| row.authority_reference).count() != 1
            || group.iter().filter(|row| !row.authority_reference).count() != 1
        {
            return Err("unexpected definition collision escaped the allowlist".to_owned());
        }
        let reference = group
            .iter()
            .find(|row| row.authority_reference)
            .expect("one authority reference is required");
        let authority = group
            .iter()
            .find(|row| !row.authority_reference)
            .expect("one authority definition is required");
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
            return Err(format!("unsanctioned raw-ID collision for {}", reference.raw_id));
        }
        authority_mapping.push(format!(
            "{}\t{}\t{}\tK0.3\t{}\t{}",
            authority.stage,
            authority.collection,
            authority.raw_id,
            reference.collection,
            reference.raw_id
        ));
    }
    if sorted_newline_sha256(authority_mapping) != AUTHORITY_REFERENCE_MAPPING_SHA256 {
        return Err("authority-reference mapping digest drifted".to_owned());
    }
    Ok(())
}

fn ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn validate_exact_typed_joins(children: &ChildArtifacts) -> Result<(), String> {
    let public_symbols = ids(array(&children.k0_1, "public_symbols"), "symbol_id");
    let symbol_refs = ids(
        array(&children.k0_3, "k0_1_symbol_dispositions"),
        "symbol_id",
    );
    if public_symbols.len() != PUBLIC_SYMBOL_JOIN_COUNT
        || public_symbols != symbol_refs
        || sorted_newline_sha256(public_symbols.iter().cloned()) != K0_1_SYMBOL_ID_SHA256
    {
        return Err("K0.1 public-symbol to K0.3 disposition join drifted".to_owned());
    }

    let mut semantic_ids = BTreeSet::new();
    for collection in [
        "configuration_fields",
        "enum_semantics",
        "operations",
        "callable_helpers",
    ] {
        semantic_ids.extend(ids(array(&children.k0_2, collection), "semantic_id"));
    }
    let semantic_refs = ids(
        array(&children.k0_3, "k0_2_semantic_dispositions"),
        "semantic_id",
    );
    if semantic_ids.len() != SEMANTIC_JOIN_COUNT
        || semantic_ids != semantic_refs
        || sorted_newline_sha256(semantic_ids.iter().cloned()) != K0_2_SEMANTIC_ID_SHA256
    {
        return Err("K0.2 semantic to K0.3 disposition join drifted".to_owned());
    }

    let profile_ids = ids(array(&children.k0_1, "compilation_profiles"), "profile_id");
    let profile_rows = array(&children.k0_3, "compilation_profiles");
    let profile_mapping = profile_rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}",
                text(row, "k0_1_profile_id"),
                text(row, "profile_id")
            )
        })
        .collect::<Vec<_>>();
    let profile_targets = profile_rows
        .iter()
        .map(|row| text(row, "k0_1_profile_id").to_owned())
        .collect::<BTreeSet<_>>();
    if profile_ids.len() != K0_1_PROFILE_COUNT
        || profile_rows.len() != K0_3_PROFILE_MAPPING_COUNT
        || profile_targets != profile_ids
        || sorted_newline_sha256(profile_ids.iter().cloned()) != K0_1_PROFILE_ID_SHA256
        || sorted_newline_sha256(profile_mapping) != K0_3_PROFILE_MAPPING_SHA256
    {
        return Err("K0.1 profile to K0.3 expanded-profile join drifted".to_owned());
    }

    let inherited_pins = ids(array(&children.k0_3, "source_pins"), "pin_id");
    let direct_pins = ids(array(&children.k0_4, "direct_source_pins"), "pin_id");
    let fixtures = array(&children.k0_4, "fixture_census");
    let mut inherited_count = 0usize;
    let mut direct_count = 0usize;
    let mut fixture_projection = Vec::new();
    for fixture in fixtures {
        let origin = text(fixture, "pin_origin");
        let pin_id = text(fixture, "source_pin_id");
        let valid = match origin {
            "K0_3_INHERITED" => {
                inherited_count += 1;
                inherited_pins.contains(pin_id)
            }
            "K0_4_DIRECT" => {
                direct_count += 1;
                direct_pins.contains(pin_id)
            }
            _ => false,
        };
        if !valid {
            return Err(format!("fixture {} has an invalid typed pin join", text(fixture, "fixture_id")));
        }
        fixture_projection.push(format!(
            "{}\t{}\t{}\t{}",
            origin,
            pin_id,
            text(fixture, "fixture_id"),
            text(fixture, "path")
        ));
    }
    if fixtures.len() != K0_4_FIXTURE_COUNT
        || inherited_count != K0_3_INHERITED_FIXTURE_COUNT
        || direct_count != K0_4_DIRECT_FIXTURE_COUNT
        || sorted_newline_sha256(fixture_projection) != K0_4_FIXTURE_JOIN_SHA256
    {
        return Err("K0.4 fixture typed-pin join drifted".to_owned());
    }

    let profile_ids = ids(
        array(&children.k0_4, "fixture_classification_profiles"),
        "classification_profile_id",
    );
    let fixture_profile_references = fixtures
        .iter()
        .map(|fixture| text(fixture, "classification_profile_id").to_owned())
        .collect::<Vec<_>>();
    let fixture_profile_projection = fixtures
        .iter()
        .map(|fixture| {
            format!(
                "{}\t{}\t{}",
                text(fixture, "classification_profile_id"),
                text(fixture, "fixture_id"),
                text(fixture, "path")
            )
        })
        .collect::<Vec<_>>();
    if profile_ids.len() != 8
        || fixture_profile_references.len() != K0_4_FIXTURE_COUNT
        || !fixture_profile_references
            .iter()
            .all(|profile| profile_ids.contains(profile))
        || sorted_newline_sha256(fixture_profile_projection)
            != FIXTURE_PROFILE_MAPPING_SHA256
    {
        return Err("K0.4 fixture classification-profile join drifted".to_owned());
    }
    Ok(())
}

fn validate_child_coverage_ids(children: &ChildArtifacts) -> Result<(), String> {
    let journeys = ids(array(&children.k0_3, "user_journeys"), "journey_id");
    if journeys.len() != 15
        || sorted_newline_sha256(journeys) != JOURNEY_ID_SHA256
    {
        return Err("downstream journey ID set drifted".to_owned());
    }

    let vector_groups = [
        ("locked_dependency_identity", 3usize),
        ("native_build_vectors", 5),
        ("broker_api_version_vectors", 7),
        ("compression_vectors", 5),
        ("transport_auth_vectors", 6),
        ("topology_vectors", 4),
        ("fault_lifecycle_vectors", 6),
    ];
    let mut vector_ids = BTreeSet::new();
    for (collection, expected_count) in vector_groups {
        let rows = array(&children.k0_4, collection);
        if rows.len() != expected_count {
            return Err(format!("{collection} vector count drifted"));
        }
        vector_ids.extend(ids(rows, "vector_id"));
    }
    if vector_ids.len() != 36
        || sorted_newline_sha256(vector_ids) != VECTOR_ID_SHA256
    {
        return Err("K0.4 vector ID set drifted".to_owned());
    }

    let fixtures = array(&children.k0_4, "fixture_census");
    let fixture_ids = ids(fixtures, "fixture_id");
    let fixture_paths = ids(fixtures, "path");
    if fixture_ids.len() != K0_4_FIXTURE_COUNT
        || sorted_newline_sha256(fixture_ids) != FIXTURE_ID_SHA256
        || sorted_newline_sha256(fixture_paths) != FIXTURE_PATH_SHA256
    {
        return Err("K0.4 fixture ID/path set drifted".to_owned());
    }
    let profiles = ids(
        array(&children.k0_4, "fixture_classification_profiles"),
        "classification_profile_id",
    );
    if profiles.len() != 8
        || sorted_newline_sha256(profiles) != FIXTURE_PROFILE_ID_SHA256
    {
        return Err("K0.4 fixture profile ID set drifted".to_owned());
    }
    let environments = ids(
        array(&children.k0_4, "environment_identities"),
        "environment_id",
    );
    if environments.len() != 8
        || sorted_newline_sha256(environments) != ENVIRONMENT_ID_SHA256
    {
        return Err("K0.4 environment ID set drifted".to_owned());
    }
    Ok(())
}

fn validate_lexical_collision_receipt(children: &ChildArtifacts) -> Result<(), String> {
    let mut group_count = 0usize;
    let mut site_count = 0usize;
    let mut projection = Vec::new();
    let mut group_ids = Vec::new();
    let mut site_ids = Vec::new();
    let mut mapping = Vec::new();
    for group in array(&children.k0_3, "call_site_groups") {
        let collision_sites = array(group, "atomic_sites")
            .iter()
            .filter(|site| {
                site.get("resolution_state").and_then(Value::as_str)
                    == Some("EXCLUDED_NAME_COLLISION")
            })
            .collect::<Vec<_>>();
        if !collision_sites.is_empty() {
            group_count += 1;
            site_count += collision_sites.len();
            group_ids.push(text(group, "group_id").to_owned());
            projection.push(format!(
                "{}\t{}\t{}",
                text(group, "group_id"),
                text(group, "path"),
                collision_sites.len()
            ));
            for site in collision_sites {
                site_ids.push(text(site, "site_id").to_owned());
                mapping.push(canonical_json(&serde_json::json!({
                    "group_id":text(group, "group_id"),
                    "path":text(group, "path"),
                    "site":site
                })));
            }
        }
    }
    if group_count != LEXICAL_COLLISION_GROUP_COUNT
        || site_count != LEXICAL_COLLISION_SITE_COUNT
        || sorted_newline_sha256(projection) != LEXICAL_COLLISION_SHA256
        || sorted_newline_sha256(group_ids) != LEXICAL_GROUP_ID_SHA256
        || sorted_newline_sha256(site_ids) != LEXICAL_SITE_ID_SHA256
        || sorted_newline_sha256(mapping) != LEXICAL_MAPPING_SHA256
    {
        return Err("K0.3 lexical name-collision receipt drifted".to_owned());
    }
    Ok(())
}

fn collect_route_edges(children: &ChildArtifacts) -> Result<Vec<String>, String> {
    let mut edges = Vec::new();
    for row in array(&children.k0_1, "routed_gaps") {
        edges.push(format!(
            "K0.1\t{}\t{}",
            text(row, "gap_id"),
            text(row, "owner_bead")
        ));
    }
    for row in array(&children.k0_2, "routed_findings") {
        let owners = array(row, "owner_beads");
        if owners.is_empty() {
            return Err(format!("{} must retain an owner", text(row, "finding_id")));
        }
        for owner in owners {
            let owner = owner
                .as_str()
                .ok_or_else(|| "K0.2 owner_beads entries must be strings".to_owned())?;
            edges.push(format!("K0.2\t{}\t{}", text(row, "finding_id"), owner));
        }
    }
    for row in array(&children.k0_3, "routed_gaps") {
        edges.push(format!(
            "K0.3\t{}\t{}",
            text(row, "gap_id"),
            text(row, "owner_bead")
        ));
    }
    for row in array(&children.k0_4, "routed_gaps") {
        edges.push(format!(
            "K0.4\t{}\t{}",
            text(row, "gap_id"),
            text(row, "owner_bead")
        ));
    }
    Ok(edges)
}

fn collect_route_records(children: &ChildArtifacts) -> Vec<(String, String, Value, Value)> {
    let mut records = Vec::new();
    for (child, artifact, collection, id_field) in [
        ("K0.1", &children.k0_1, "routed_gaps", "gap_id"),
        (
            "K0.2",
            &children.k0_2,
            "routed_findings",
            "finding_id",
        ),
        ("K0.3", &children.k0_3, "routed_gaps", "gap_id"),
        ("K0.4", &children.k0_4, "routed_gaps", "gap_id"),
    ] {
        records.extend(array(artifact, collection).iter().map(|row| {
            (
                child.to_owned(),
                collection.to_owned(),
                Value::String(text(row, id_field).to_owned()),
                row.clone(),
            )
        }));
    }
    records
}

fn tracker_ids() -> Result<BTreeSet<String>, String> {
    let mut ids = BTreeSet::new();
    for (index, line) in read_repo_file(TRACKER_PATH).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(line)
            .map_err(|error| format!("tracker line {} is invalid JSON: {error}", index + 1))?;
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("tracker line {} lacks id", index + 1))?;
        ids.insert(id.to_owned());
    }
    Ok(ids)
}

fn validate_gap_routes(children: &ChildArtifacts, tracker: &BTreeSet<String>) -> Result<(), String> {
    let row_count = array(&children.k0_1, "routed_gaps").len()
        + array(&children.k0_2, "routed_findings").len()
        + array(&children.k0_3, "routed_gaps").len()
        + array(&children.k0_4, "routed_gaps").len();
    let edges = collect_route_edges(children)?;
    let owners = edges
        .iter()
        .map(|edge| edge.rsplit_once('\t').expect("route tuple has owner").1.to_owned())
        .collect::<BTreeSet<_>>();
    let child_handoff_owners = expected_set(&[
        "asupersync-dep-p7-kafka-removal-sarszu.1.2",
        "asupersync-dep-p7-kafka-removal-sarszu.1.3",
        "asupersync-dep-p7-kafka-removal-sarszu.1.4",
    ]);
    let internal_handoffs = edges
        .iter()
        .filter(|edge| {
            let owner = edge
                .rsplit_once('\t')
                .expect("route tuple has owner")
                .1;
            child_handoff_owners.contains(owner)
        })
        .cloned()
        .collect::<Vec<_>>();
    if row_count != ROUTE_ROW_COUNT
        || edges.len() != ROUTE_EDGE_COUNT
        || owners.len() != ROUTE_OWNER_COUNT
        || sorted_newline_sha256(edges) != ROUTE_PROJECTION_SHA256
        || sorted_newline_sha256(owners.iter().cloned()) != ROUTE_OWNER_ID_SHA256
        || canonical_record_projection_sha256(collect_route_records(children))
            != ROUTE_FULL_ROW_SHA256
        || internal_handoffs.len() != 11
        || sorted_newline_sha256(internal_handoffs) != INTERNAL_HANDOFF_SHA256
    {
        return Err("gap route row/edge/owner receipt drifted".to_owned());
    }
    let missing = owners
        .difference(tracker)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!("gap route owners missing from tracker: {missing:?}"));
    }
    Ok(())
}

fn explicit_unknown_owner_ids(children: &ChildArtifacts) -> Result<BTreeSet<String>, String> {
    let mut owners = BTreeSet::new();
    for row in array(&children.k0_3, "owned_unknowns") {
        if !bool_field(row, "blocks_migration") {
            return Err(format!("{} must block migration", text(row, "unknown_id")));
        }
        owners.insert(text(row, "resolution_owner_bead").to_owned());
    }
    for row in array(&children.k0_4, "owned_unknowns") {
        if text(row, "knowledge_state") != "BLOCKED" {
            return Err(format!("{} must remain BLOCKED", text(row, "unknown_id")));
        }
        owners.insert(text(row, "resolution_owner_bead").to_owned());
    }
    Ok(owners)
}

fn validate_explicit_unknowns(
    children: &ChildArtifacts,
    tracker: &BTreeSet<String>,
) -> Result<(), String> {
    let rows = array(&children.k0_3, "owned_unknowns")
        .iter()
        .chain(array(&children.k0_4, "owned_unknowns"));
    let ids = rows
        .clone()
        .map(|row| text(row, "unknown_id").to_owned())
        .collect::<Vec<_>>();
    let owner_edges = rows
        .map(|row| {
            format!(
                "{}\t{}",
                text(row, "unknown_id"),
                text(row, "resolution_owner_bead")
            )
        })
        .collect::<Vec<_>>();
    if ids.len() != EXPLICIT_OWNED_UNKNOWN_COUNT
        || sorted_newline_sha256(ids) != EXPLICIT_UNKNOWN_ID_SHA256
        || sorted_newline_sha256(owner_edges) != EXPLICIT_UNKNOWN_OWNER_EDGE_SHA256
    {
        return Err("explicit owned-UNKNOWN row count drifted".to_owned());
    }
    let owners = explicit_unknown_owner_ids(children)?;
    if sorted_newline_sha256(owners.iter().cloned()) != EXPLICIT_UNKNOWN_OWNER_ID_SHA256 {
        return Err("explicit UNKNOWN resolution-owner digest drifted".to_owned());
    }
    let missing = owners
        .difference(tracker)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!("UNKNOWN resolution owners missing from tracker: {missing:?}"));
    }
    Ok(())
}

fn direct_matched_states(row: &Value) -> BTreeSet<String> {
    row.as_object()
        .into_iter()
        .flat_map(|object| object.values())
        .filter_map(Value::as_str)
        .filter(|state| matches!(*state, "UNKNOWN" | "BLOCKED" | "BLOCKED_EXTERNAL"))
        .map(str::to_owned)
        .collect()
}

fn selector_row_id(row: &Value) -> &str {
    for key in [
        "row_id",
        "symbol_id",
        "semantic_id",
        "consumer_id",
        "case_id",
        "claim_id",
        "journey_id",
        "evidence_id",
        "external_id",
        "group_id",
        "unknown_id",
        "classification_profile_id",
        "environment_id",
        "vector_id",
        "path",
    ] {
        if let Some(value) = row.get(key).and_then(Value::as_str) {
            return value;
        }
    }
    "NO_ID"
}

fn selector_owner(row: &Value) -> &str {
    for key in [
        "owner_bead",
        "resolution_owner_bead",
        "inventory_owner_bead",
        "executable_owner",
    ] {
        if let Some(value) = row.get(key).and_then(Value::as_str) {
            return value;
        }
    }
    "NO_OWNER"
}

fn collect_reduced_unknown_selectors(children: &ChildArtifacts) -> Vec<String> {
    let mut selectors = Vec::new();
    for (stage, artifact) in [("K0.3", &children.k0_3), ("K0.4", &children.k0_4)] {
        for (section, value) in artifact
            .as_object()
            .expect("child artifact roots must be objects")
        {
            let Some(rows) = value.as_array() else {
                continue;
            };
            for row in rows {
                let states = direct_matched_states(row);
                if states.is_empty() {
                    continue;
                }
                selectors.push(format!(
                    "{}\t{}\t{}\t{}\t{}",
                    stage,
                    section,
                    selector_row_id(row),
                    selector_owner(row),
                    states.into_iter().collect::<Vec<_>>().join(",")
                ));
            }
        }
    }
    for row in array(&children.k0_3, "owned_unknowns") {
        selectors.push(format!(
            "K0.3\towned_unknowns\t{}\t{}\tOWNED_UNKNOWN",
            text(row, "unknown_id"),
            text(row, "resolution_owner_bead")
        ));
    }
    selectors
}

fn validate_reduced_unknown_selectors(children: &ChildArtifacts) -> Result<(), String> {
    let selectors = collect_reduced_unknown_selectors(children);
    if selectors.len() != REDUCED_UNKNOWN_SELECTOR_COUNT
        || selectors.iter().collect::<BTreeSet<_>>().len() != selectors.len()
        || sorted_newline_sha256(selectors.clone()) != REDUCED_UNKNOWN_SELECTOR_SHA256
    {
        return Err("UNKNOWN/BLOCKED reduced selector ledger drifted".to_owned());
    }
    let no_owner_ids = selectors
        .iter()
        .filter_map(|selector| {
            let fields = selector.split('\t').collect::<Vec<_>>();
            (fields.get(3) == Some(&"NO_OWNER")).then(|| fields[2].to_owned())
        })
        .collect::<BTreeSet<_>>();
    if no_owner_ids
        != expected_set(&[
            "KAFKA-K0-3-EVIDENCE-005",
            "KAFKA-K0-4-ENV-003-ACTUAL-BUILD-HOST",
            "KAFKA-K0-4-ENV-005-AMBIENT-BROKER",
            "KAFKA-K0-4-ENV-006-OLDEST-BROKER",
            "KAFKA-K0-4-ENV-007-CURRENT-BROKER",
            "KAFKA-K0-4-ENV-008-AUTHENTICATED-BROKER",
        ])
    {
        return Err("indirect-owner UNKNOWN selector set drifted".to_owned());
    }
    let referenced_environments = [
        "locked_dependency_identity",
        "native_build_vectors",
        "broker_api_version_vectors",
        "compression_vectors",
        "transport_auth_vectors",
        "topology_vectors",
        "fault_lifecycle_vectors",
    ]
    .into_iter()
    .flat_map(|collection| array(&children.k0_4, collection))
    .flat_map(|row| array(row, "environment_ids"))
    .filter_map(Value::as_str)
    .collect::<BTreeSet<_>>();
    for environment in no_owner_ids
        .iter()
        .filter(|id| id.starts_with("KAFKA-K0-4-ENV-"))
    {
        if !referenced_environments.contains(environment.as_str()) {
            return Err(format!("{environment} lacks a routed vector owner join"));
        }
    }
    Ok(())
}

fn validate_packet_identity_and_policy(packet: &Value) -> Result<(), String> {
    require_exact_keys(packet, ROOT_KEYS, "aggregate root")?;
    if unsigned(packet, "schema_version") != 1
        || text(packet, "artifact_id") != ARTIFACT_ID
        || text(packet, "program_id") != PROGRAM_ID
        || text(packet, "bead_id") != BEAD_ID
        || text(packet, "capability_id") != CAPABILITY_ID
        || text(packet, "captured_date_utc") != CAPTURED_DATE_UTC
        || text(packet, "baseline_revision") != BASELINE_REVISION
        || text(packet, "inventory_state") != INVENTORY_STATE
    {
        return Err("aggregate identity drifted".to_owned());
    }
    require_equal(
        packet
            .get("authority")
            .ok_or_else(|| "aggregate lacks authority".to_owned())?,
        serde_json::json!({
            "adr_id": "DEP-ADR-009",
            "registry_disposition": "KEEP_UNTIL_PARITY",
            "current_action": "KEEP_INCUMBENT",
            "aggregate_owner_bead": BEAD_ID,
            "native_epic_bead": NATIVE_EPIC,
            "first_contract_gate_bead": K1_GATE,
            "verification_terminal_bead": K12_TERMINAL,
            "real_service_terminal_bead": K13_TERMINAL,
            "claim_time_refresh_bead": K14_REFRESH,
            "conditional_cutover_bead": K15_CUTOVER,
            "dependency_exit_allowed": false,
            "feature_removal_allowed": false,
            "api_removal_allowed": false,
            "capability_removal_allowed": false,
            "file_deletion_allowed": false,
        }),
        "aggregate authority",
    )?;
    require_equal(
        packet
            .get("policy")
            .ok_or_else(|| "aggregate lacks policy".to_owned())?,
        serde_json::json!({
            "mode": "STATIC_ONLY_FAIL_CLOSED",
            "child_rows_duplicated": false,
            "canonicalization_id": "KAFKA_K0_5_CANONICAL_PROJECTION_V1",
            "missing_row_state": "BLOCKING_MISSING",
            "unowned_row_state": "BLOCKING_UNOWNED",
            "unexpected_collision_state": "BLOCKING_UNDECLARED_COLLISION",
            "unknown_rule": "UNKNOWN is admissible only for a stable identified row selected by the declared ledger, with an exact owner and later resolution gate; it remains migration-blocking.",
            "blocked_rule": "BLOCKED never defaults to supported, executed, or migration-eligible.",
            "planned_counts_as_executed": false,
            "silent_skip_counts_as_pass": false,
            "static_counts_as_runtime": false,
            "internal_k0_handoff_rule": "A route into an included K0.1-K0.4 child is satisfied only as an inventory handoff; executable authority must continue through that child's later-owner routes.",
        }),
        "aggregate policy",
    )
}

fn validate_aggregate_coverage_sets(packet: &Value) -> Result<(), String> {
    let coverage = packet
        .get("coverage_sets")
        .ok_or_else(|| "aggregate lacks coverage_sets".to_owned())?;
    require_exact_keys(
        coverage,
        &[
            "canonicalization",
            "child_file_count",
            "source_pin_rollup",
            "primary_stable_ids",
            "public_symbol_ids",
            "semantic_ids",
            "downstream_journey_ids",
            "k0_4_vector_ids",
            "fixture_ids",
            "fixture_profile_ids",
            "environment_ids",
        ],
        "coverage_sets",
    )?;
    require_equal(
        coverage
            .get("canonicalization")
            .ok_or_else(|| "coverage_sets lacks canonicalization".to_owned())?,
        serde_json::json!({
            "record_count_semantics": "Rust str::lines semantics: one record per logical line, with no synthetic empty record after a final LF.",
            "file_hash_semantics": "SHA-256 of exact repository bytes.",
            "id_set_semantics": "Bytewise sort unique UTF-8 IDs and serialize each ID followed by one LF.",
            "typed_primary_semantics": "Serialize bytewise-sorted stage<TAB>collection<TAB>id records with one trailing LF per record.",
            "canonical_json_semantics": "Recursively sort object keys, emit compact JSON, bytewise sort records by child, collection, and id, and append one LF per record.",
            "source_pin_row_semantics": "Wrap each source-pin row as an object with child, collection, id, and row fields; sort by child, collection, and id; recursively sort object keys; emit compact JSON with one LF per record.",
            "route_row_semantics": "Wrap each child route row as an object with child, collection, id, and row fields; sort by child, collection, and id; recursively sort object keys; emit compact JSON with one LF per record.",
            "route_edge_semantics": "Bytewise sort unique stage<TAB>gap-or-finding-id<TAB>owner records and append one LF per record.",
            "aggregate_claim_semantics": "Sort claims by claim_id, recursively sort each claim object's keys, emit one compact JSON object per claim, and append one LF per record.",
        }),
        "coverage canonicalization",
    )?;
    if unsigned(coverage, "child_file_count") != 12 {
        return Err("coverage child_file_count drifted".to_owned());
    }

    let source = coverage
        .get("source_pin_rollup")
        .ok_or_else(|| "coverage lacks source_pin_rollup".to_owned())?;
    require_exact_keys(
        source,
        &[
            "row_count",
            "stage_counts",
            "canonical_json_sha256",
            "unique_path_count",
            "unique_path_set_sha256",
            "overlap_group_count",
            "overlap_pin_row_count",
            "overlap_pin_tuple_rule",
            "overlap_pin_projection_sha256",
            "conflicting_overlap_groups",
        ],
        "source_pin_rollup",
    )?;
    if unsigned(source, "row_count") != IMPORTED_SOURCE_PIN_COUNT as u64
        || source.get("stage_counts")
            != Some(&serde_json::json!({"K0.1":13,"K0.2":8,"K0.3":225,"K0.4":20}))
        || text(source, "canonical_json_sha256") != SOURCE_PIN_FULL_ROW_SHA256
        || unsigned(source, "unique_path_count") != UNIQUE_SOURCE_PATH_COUNT as u64
        || text(source, "unique_path_set_sha256") != SOURCE_PIN_PATH_SHA256
        || unsigned(source, "overlap_group_count") != SOURCE_PATH_OVERLAP_GROUP_COUNT as u64
        || unsigned(source, "overlap_pin_row_count") != 34
        || text(source, "overlap_pin_tuple_rule")
            != "For each source-pin row whose path occurs in more than one child packet, serialize path<TAB>child<TAB>pin_id<TAB>sha256; bytewise sort the records and append one LF per row."
        || text(source, "overlap_pin_projection_sha256") != SOURCE_PIN_OVERLAP_SHA256
        || !array(source, "conflicting_overlap_groups").is_empty()
    {
        return Err("aggregate source-pin rollup drifted".to_owned());
    }

    require_equal(
        coverage
            .get("primary_stable_ids")
            .ok_or_else(|| "coverage lacks primary_stable_ids".to_owned())?,
        serde_json::json!({
            "stage_counts": {"K0.1":96,"K0.2":147,"K0.3":469,"K0.4":191},
            "core_definition_count": CORE_DEFINITION_ID_COUNT,
            "core_definition_typed_tuple_sha256": CORE_ID_SHA256,
            "contradiction_input_count": CONTRADICTION_INPUT_ID_COUNT,
            "contradiction_input_typed_tuple_sha256": CONTRADICTION_ID_SHA256,
            "primary_stable_id_count": PRIMARY_STABLE_ID_COUNT,
            "typed_unique_count": PRIMARY_STABLE_ID_COUNT,
            "raw_unique_count": PRIMARY_STABLE_ID_COUNT,
            "all_primary_typed_tuple_sha256": PRIMARY_ID_SHA256,
        }),
        "primary stable IDs",
    )?;
    require_equal(
        coverage
            .get("public_symbol_ids")
            .ok_or_else(|| "coverage lacks public_symbol_ids".to_owned())?,
        serde_json::json!({"count":PUBLIC_SYMBOL_JOIN_COUNT,"id_set_sha256":K0_1_SYMBOL_ID_SHA256}),
        "public symbol IDs",
    )?;
    require_equal(
        coverage
            .get("semantic_ids")
            .ok_or_else(|| "coverage lacks semantic_ids".to_owned())?,
        serde_json::json!({
            "count":SEMANTIC_JOIN_COUNT,
            "configuration_count":43,
            "enum_count":7,
            "operation_count":38,
            "helper_count":9,
            "id_set_sha256":K0_2_SEMANTIC_ID_SHA256,
        }),
        "semantic IDs",
    )?;
    require_equal(
        coverage
            .get("downstream_journey_ids")
            .ok_or_else(|| "coverage lacks downstream_journey_ids".to_owned())?,
        serde_json::json!({"count":15,"id_set_sha256":JOURNEY_ID_SHA256}),
        "downstream journey IDs",
    )?;
    require_equal(
        coverage
            .get("k0_4_vector_ids")
            .ok_or_else(|| "coverage lacks k0_4_vector_ids".to_owned())?,
        serde_json::json!({
            "count":36,
            "locked_dependency_count":3,
            "native_build_count":5,
            "broker_api_version_count":7,
            "compression_count":5,
            "transport_auth_count":6,
            "topology_count":4,
            "fault_lifecycle_count":6,
            "id_set_sha256":VECTOR_ID_SHA256,
        }),
        "K0.4 vector IDs",
    )?;
    require_equal(
        coverage
            .get("fixture_ids")
            .ok_or_else(|| "coverage lacks fixture_ids".to_owned())?,
        serde_json::json!({
            "count":K0_4_FIXTURE_COUNT,
            "id_set_sha256":FIXTURE_ID_SHA256,
            "path_set_sha256":FIXTURE_PATH_SHA256,
        }),
        "fixture IDs",
    )?;
    require_equal(
        coverage
            .get("fixture_profile_ids")
            .ok_or_else(|| "coverage lacks fixture_profile_ids".to_owned())?,
        serde_json::json!({"count":8,"id_set_sha256":FIXTURE_PROFILE_ID_SHA256}),
        "fixture profile IDs",
    )?;
    require_equal(
        coverage
            .get("environment_ids")
            .ok_or_else(|| "coverage lacks environment_ids".to_owned())?,
        serde_json::json!({"count":8,"id_set_sha256":ENVIRONMENT_ID_SHA256}),
        "environment IDs",
    )
}

fn validate_aggregate_joins_and_collisions(packet: &Value) -> Result<(), String> {
    require_equal(
        packet
            .get("exact_joins")
            .ok_or_else(|| "aggregate lacks exact_joins".to_owned())?,
        serde_json::json!([
            {
                "join_id":"KAFKA-K0-5-JOIN-001-PUBLIC-DISPOSITION",
                "join_kind":"AUTHORITY_REFERENCE",
                "left_locator":"K0.1.public_symbols[].symbol_id",
                "right_locator":"K0.3.k0_1_symbol_dispositions[].symbol_id",
                "left_count":30,
                "right_count":30,
                "unique_target_count":30,
                "mapping_count":30,
                "id_set_sha256":K0_1_SYMBOL_ID_SHA256,
                "status":"EXACT"
            },
            {
                "join_id":"KAFKA-K0-5-JOIN-002-SEMANTIC-DISPOSITION",
                "join_kind":"AUTHORITY_REFERENCE",
                "left_locator":"K0.2 configuration_fields+enum_semantics+operations+callable_helpers semantic_id",
                "right_locator":"K0.3.k0_2_semantic_dispositions[].semantic_id",
                "left_count":97,
                "right_count":97,
                "unique_target_count":97,
                "mapping_count":97,
                "id_set_sha256":K0_2_SEMANTIC_ID_SHA256,
                "status":"EXACT"
            },
            {
                "join_id":"KAFKA-K0-5-JOIN-003-COMPILATION-PROFILES",
                "join_kind":"TYPED_REFERENCE",
                "left_locator":"K0.1.compilation_profiles[].profile_id",
                "right_locator":"K0.3.compilation_profiles[].k0_1_profile_id",
                "left_count":13,
                "right_count":17,
                "unique_target_count":13,
                "mapping_count":17,
                "id_set_sha256":K0_1_PROFILE_ID_SHA256,
                "mapping_sha256":K0_3_PROFILE_MAPPING_SHA256,
                "status":"EXACT_WITH_FOUR_DECLARED_DOUBLE_MAPPINGS",
                "limitation":"DOWNSTREAM-NO-KAFKA, NATIVE-KAFKA-RELEASE, TEST-INTERNALS-NO-KAFKA, and UNIT-WITH-KAFKA each map to two K0.3 profiles."
            },
            {
                "join_id":"KAFKA-K0-5-JOIN-004-FIXTURE-PINS",
                "join_kind":"TYPED_REFERENCE",
                "left_locator":"K0.3.source_pins or K0.4.direct_source_pins",
                "right_locator":"K0.4.fixture_census[].source_pin_id",
                "left_count":266,
                "right_count":67,
                "unique_target_count":67,
                "mapping_count":67,
                "mapping_rule":"Bytewise sort unique pin_origin<TAB>source_pin_id<TAB>fixture_id<TAB>path records and append one LF per row.",
                "mapping_sha256":K0_4_FIXTURE_JOIN_SHA256,
                "status":"EXACT_48_INHERITED_19_DIRECT",
                "limitation":"The twentieth K0.4 direct pin is the K0.3 authority artifact and is intentionally outside the fixture census."
            },
            {
                "join_id":"KAFKA-K0-5-JOIN-005-FIXTURE-PROFILES",
                "join_kind":"TYPED_REFERENCE",
                "left_locator":"K0.4.fixture_classification_profiles[].classification_profile_id",
                "right_locator":"K0.4.fixture_census[].classification_profile_id",
                "left_count":8,
                "right_count":67,
                "unique_target_count":8,
                "mapping_count":67,
                "mapping_rule":"Bytewise sort unique classification_profile_id<TAB>fixture_id<TAB>path records and append one LF per row.",
                "mapping_sha256":FIXTURE_PROFILE_MAPPING_SHA256,
                "status":"EXACT"
            },
            {
                "join_id":"KAFKA-K0-5-JOIN-006-ROUTE-OWNERS",
                "join_kind":"TRACKER_OWNER_REFERENCE",
                "left_locator":"K0.1-K0.4 routed gap/finding owner edges",
                "right_locator":".beads/issues.jsonl issue IDs",
                "left_count":126,
                "right_count":49,
                "unique_target_count":49,
                "mapping_count":126,
                "mapping_sha256":ROUTE_PROJECTION_SHA256,
                "status":"EXACT"
            }
        ]),
        "exact joins",
    )?;
    require_equal(
        packet
            .get("collision_groups")
            .ok_or_else(|| "aggregate lacks collision_groups".to_owned())?,
        serde_json::json!({
            "authority_id_joins": {
                "group_count":2,
                "row_count":AUTHORITY_REFERENCE_COUNT,
                "combined_id_set_sha256":AUTHORITY_REFERENCE_ID_SHA256,
                "mapping_sha256":AUTHORITY_REFERENCE_MAPPING_SHA256
            },
            "typed_reference_joins": {
                "compilation_profile_reference_count":17,
                "cross_child_fixture_pin_reference_count":48,
                "direct_fixture_pin_reference_count":19,
                "fixture_profile_reference_count":67,
                "definition_collision_count":0
            },
            "lexical_name_collisions": {
                "group_count":LEXICAL_COLLISION_GROUP_COUNT,
                "site_count":LEXICAL_COLLISION_SITE_COUNT,
                "group_id_set_sha256":LEXICAL_GROUP_ID_SHA256,
                "site_id_set_sha256":LEXICAL_SITE_ID_SHA256,
                "mapping_rule":"For every atomic site classified EXCLUDED_NAME_COLLISION, recursively key-sort and compactly serialize an object with the parent group_id, parent path, and the complete site object; bytewise sort the records and append one LF per row.",
                "mapping_sha256":LEXICAL_MAPPING_SHA256,
                "classification":"NON_KAFKA_LEXICAL_EXCLUSIONS"
            },
            "shared_authority_references": [
                "program_id",
                "capability_id",
                "DEP-ADR-009",
                "child artifact paths and IDs"
            ],
            "unexpected_definition_collisions": []
        }),
        "collision groups",
    )
}

fn validate_aggregate_unknown_disposition(
    packet: &Value,
    children: &ChildArtifacts,
    tracker: &BTreeSet<String>,
) -> Result<(), String> {
    let unknown = packet
        .get("unknown_disposition")
        .ok_or_else(|| "aggregate lacks unknown_disposition".to_owned())?;
    require_exact_keys(
        unknown,
        &[
            "missing_or_unowned_blocks",
            "unexpected_unknown_blocks",
            "explicit_owned_unknowns",
            "selector_projection",
            "selectors",
            "owner_join_rule",
            "promotion_rule",
        ],
        "unknown_disposition",
    )?;
    if !bool_field(unknown, "missing_or_unowned_blocks")
        || !bool_field(unknown, "unexpected_unknown_blocks")
    {
        return Err("UNKNOWN/BLOCKED fail-closed booleans drifted".to_owned());
    }
    require_equal(
        unknown
            .get("explicit_owned_unknowns")
            .ok_or_else(|| "unknown_disposition lacks explicit_owned_unknowns".to_owned())?,
        serde_json::json!({
            "count":EXPLICIT_OWNED_UNKNOWN_COUNT,
            "id_set_sha256":EXPLICIT_UNKNOWN_ID_SHA256,
            "owner_edge_count":EXPLICIT_OWNED_UNKNOWN_COUNT,
            "owner_edge_tuple_rule":"Bytewise sort unique unknown_id<TAB>resolution_owner_bead records and append one LF per row.",
            "owner_edge_sha256":EXPLICIT_UNKNOWN_OWNER_EDGE_SHA256,
            "resolution_owner_count":7,
            "resolution_owner_id_set_sha256":EXPLICIT_UNKNOWN_OWNER_ID_SHA256
        }),
        "explicit owned UNKNOWN receipt",
    )?;
    require_equal(
        unknown
            .get("selector_projection")
            .ok_or_else(|| "unknown_disposition lacks selector_projection".to_owned())?,
        serde_json::json!({
            "row_count":REDUCED_UNKNOWN_SELECTOR_COUNT,
            "tuple_rule":"For each selected row, lexically sort and deduplicate matched states, join them with commas, then bytewise-sort stage<TAB>section<TAB>id<TAB>owner<TAB>matched-states records and append one LF per row.",
            "sha256":REDUCED_UNKNOWN_SELECTOR_SHA256
        }),
        "UNKNOWN selector projection",
    )?;
    require_equal(
        unknown
            .get("selectors")
            .ok_or_else(|| "unknown_disposition lacks selectors".to_owned())?,
        serde_json::json!([
            {
                "selector_id":"K0.1-NO-UNKNOWN",
                "locator":"coverage_receipt source_unknown_rows+manifest_unknown_rows+public_surface_unknown_rows+unowned_gap_rows",
                "matched_count":0,
                "required_owner":"NONE_BECAUSE_EMPTY",
                "blocking":true
            },
            {
                "selector_id":"K0.2-NO-UNKNOWN",
                "locator":"coverage_receipt unknown_rows+unowned_semantic_rows+implicit_operation_rows",
                "matched_count":0,
                "required_owner":"NONE_BECAUSE_EMPTY",
                "blocking":true
            },
            {
                "selector_id":"K0.3-PUBLIC-USAGE-UNKNOWN",
                "locator":"k0_1_symbol_dispositions[usage_knowledge_state=UNKNOWN]",
                "matched_count":13,
                "id_field":"symbol_id",
                "id_set_sha256":"19de29fa24f8d298f24adb4e81de5ab835ef74c13b516279a2d824a6d5fb0771",
                "owner_field":"owner_bead",
                "required_owner":K14_REFRESH,
                "blocking":true
            },
            {
                "selector_id":"K0.3-SEMANTIC-USAGE-UNKNOWN",
                "locator":"k0_2_semantic_dispositions[usage_knowledge_state=UNKNOWN]",
                "matched_count":52,
                "id_field":"semantic_id",
                "id_set_sha256":"6327718095f204c777e7b98116005ebae8f943aa65297da5fb508ea635f211c7",
                "owner_field":"owner_bead",
                "required_owner":K14_REFRESH,
                "blocking":true
            },
            {
                "selector_id":"K0.3-EXTERNAL-SEARCH-UNKNOWN",
                "locator":"external_searches[knowledge_state=UNKNOWN]",
                "matched_count":7,
                "id_field":"external_id",
                "id_set_sha256":"59297614f447d10871b58b172c05635b5b791c36e0d93b194c8c2ec2f303d06f",
                "owner_field":"resolution_owner_bead",
                "required_owner":K14_REFRESH,
                "blocking":true
            },
            {
                "selector_id":"K0.3-DOCUMENTATION-UNKNOWN",
                "locator":"documentation_claim_occurrence_groups.derived_remainder_groups",
                "matched_count":8599,
                "id_field":"derived occurrence ID",
                "id_set_sha256":"db4e006cdb3cde6fee615f3d64753df484c0848474dcd68a412ab055b0ffced0",
                "required_owner":"asupersync-dep-p7-kafka-removal-sarszu.2.10.5",
                "refresh_owner":K14_REFRESH,
                "blocking":true
            },
            {
                "selector_id":"K0.3-FEATURE-CELLS-NONPASS",
                "locator":"feature_platform_cells[execution_state!=PASS]",
                "matched_count":8,
                "id_field":"cell_id",
                "id_set_sha256":"021bcdf10af9b68a57a52d401124830cc884f4a1a8165a3f9440da92b398f68d",
                "owner_field":"owner_bead",
                "required_owner":K12_TERMINAL,
                "refresh_owner":K14_REFRESH,
                "blocking":true
            },
            {
                "selector_id":"K0.3-OWNED-UNKNOWN",
                "locator":"owned_unknowns",
                "matched_count":8,
                "id_field":"unknown_id",
                "id_set_sha256":"0dd1f13bfb3d018f73e299ad4f8a24c7d654dd6dc09d25852c074f719d2b3278",
                "owner_field":"resolution_owner_bead",
                "blocking":true
            },
            {
                "selector_id":"K0.4-FIXTURE-PROFILE-BLOCKED",
                "locator":"fixture_classification_profiles[knowledge_state in UNKNOWN|BLOCKED]",
                "matched_count":1,
                "id_field":"classification_profile_id",
                "id_set_sha256":"854442fb990364ed9a5cab191305743b95b790be9ee263df8f1f0087557178ca",
                "owner_field":"executable_owner",
                "blocking":true
            },
            {
                "selector_id":"K0.4-ENVIRONMENT-UNRESOLVED",
                "locator":"environment_identities[knowledge_state in UNKNOWN|BLOCKED]",
                "matched_count":5,
                "id_field":"environment_id",
                "id_set_sha256":"b38364137fa24dcb19607c1ff137716ac33884e77bf1b2a5e557006364f20bb7",
                "owner_join":"owned_unknowns and evidence vectors by subject/environment_ids",
                "blocking":true
            },
            {
                "selector_id":"K0.4-VECTOR-UNRESOLVED",
                "locator":"native+broker_api+compression+transport_auth+topology+fault vectors[knowledge_state in UNKNOWN|BLOCKED]",
                "matched_count":23,
                "id_field":"vector_id",
                "id_set_sha256":"2fa4c57fe931c5528d8ec49305490f7ace1084d9d848642e3471294f342e583b",
                "owner_field":"executable_owner",
                "blocking":true
            },
            {
                "selector_id":"K0.4-OWNED-UNKNOWN",
                "locator":"owned_unknowns[knowledge_state=BLOCKED]",
                "matched_count":9,
                "id_field":"unknown_id",
                "id_set_sha256":"99a6c6fd294d433f026e7866935f3afa338c78df04fc93172ba5d55c68fed61e",
                "owner_field":"resolution_owner_bead",
                "blocking":true
            }
        ]),
        "UNKNOWN selectors",
    )?;
    if text(unknown, "owner_join_rule")
        != "Every selected row has a direct owner field or the declared environment-to-vector/owned-unknown join, and every resulting owner exists in the routed owner set or an independent terminal gate."
        || text(unknown, "promotion_rule")
            != "UNKNOWN, BLOCKED, NOT_RUN, UNPINNED, planned, static, compile-only, local-model, wire-only, proof-only, opt-in, or silent-skip state cannot become PASS, REAL_BROKER_RECEIPT, ACTUAL_BINARY_RECEIPT, or migration evidence without a new terminal receipt."
    {
        return Err("UNKNOWN ownership/promotion rule drifted".to_owned());
    }

    for selector in array(unknown, "selectors") {
        if !bool_field(selector, "blocking") {
            return Err(format!("{} must remain blocking", text(selector, "selector_id")));
        }
        for owner_key in ["required_owner", "refresh_owner"] {
            if let Some(owner) = selector.get(owner_key).and_then(Value::as_str)
                && owner != "NONE_BECAUSE_EMPTY"
                && !tracker.contains(owner)
            {
                return Err(format!("selector owner {owner} is absent from tracker"));
            }
        }
    }

    let route_owners = collect_route_edges(children)?
        .into_iter()
        .map(|edge| {
            edge.rsplit_once('\t')
                .expect("route tuple has owner")
                .1
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let terminal_gates = expected_set(&[K12_TERMINAL, K13_TERMINAL, K14_REFRESH, K15_CUTOVER]);
    for selector in collect_reduced_unknown_selectors(children) {
        let fields = selector.split('\t').collect::<Vec<_>>();
        let owner = fields[3];
        if owner != "NO_OWNER"
            && !route_owners.contains(owner)
            && !terminal_gates.contains(owner)
        {
            return Err(format!("selected UNKNOWN owner {owner} has no route or terminal gate"));
        }
    }
    let evidence = find_row(
        array(&children.k0_3, "evidence_claims"),
        "evidence_id",
        "KAFKA-K0-3-EVIDENCE-005",
    );
    let gap = find_row(
        array(&children.k0_3, "routed_gaps"),
        "gap_id",
        "KAFKA-K0-3-GAP-007",
    );
    if text(evidence, "subject") != "canonical real-service fixture matrix"
        || text(gap, "owner_bead") != "asupersync-dep-p7-kafka-removal-sarszu.1.4"
        || !text(gap, "finding").contains("canonical real-service Kafka")
    {
        return Err("K0.3 indirect evidence-to-gap ownership join drifted".to_owned());
    }
    Ok(())
}

fn validate_aggregate_gap_routing(packet: &Value) -> Result<(), String> {
    require_equal(
        packet
            .get("gap_routing")
            .ok_or_else(|| "aggregate lacks gap_routing".to_owned())?,
        serde_json::json!({
            "route_row_count":ROUTE_ROW_COUNT,
            "route_stage_counts":{"K0.1":15,"K0.2":23,"K0.3":23,"K0.4":26},
            "route_projection_sha256":ROUTE_FULL_ROW_SHA256,
            "route_edge_count":ROUTE_EDGE_COUNT,
            "route_edge_projection_sha256":ROUTE_PROJECTION_SHA256,
            "owner_id_count":ROUTE_OWNER_COUNT,
            "owner_id_set_sha256":ROUTE_OWNER_ID_SHA256,
            "internal_k0_handoffs":[
                {"from":"K0.1","to":"K0.2","edge_count":6,"state":"SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD"},
                {"from":"K0.1","to":"K0.3","edge_count":2,"state":"SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD"},
                {"from":"K0.1","to":"K0.4","edge_count":2,"state":"SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD"},
                {"from":"K0.3","to":"K0.4","edge_count":1,"state":"SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD"}
            ],
            "internal_k0_handoff_edge_count":11,
            "internal_k0_handoff_projection_rule":"Select route-owner edges whose owner is the included K0.2, K0.3, or K0.4 child bead; bytewise sort unique stage<TAB>gap-or-finding-id<TAB>owner records and append one LF per row.",
            "internal_k0_handoff_projection_sha256":INTERNAL_HANDOFF_SHA256,
            "inventory_input_only_count":3,
            "unresolved_internal_handoffs":[],
            "missing_owner_rows":[],
            "unowned_route_rows":[]
        }),
        "gap routing",
    )
}

fn child_claim_records(children: &ChildArtifacts) -> Vec<(String, String, Value, Value)> {
    let mut records = Vec::new();
    for (child, artifact) in [
        ("K0.1", &children.k0_1),
        ("K0.2", &children.k0_2),
        ("K0.3", &children.k0_3),
        ("K0.4", &children.k0_4),
    ] {
        records.extend(
            array(artifact, "no_claim_boundaries")
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    (
                        child.to_owned(),
                        "no_claim_boundaries".to_owned(),
                        Value::from(
                            u64::try_from(index).expect("no-claim index must fit in u64"),
                        ),
                        row.clone(),
                    )
                }),
        );
    }
    for row in array(&children.k0_3, "documentation_claims") {
        records.push((
            "K0.3".to_owned(),
            "documentation_claims".to_owned(),
            Value::String(text(row, "claim_id").to_owned()),
            row.clone(),
        ));
    }
    for row in array(&children.k0_3, "evidence_claims") {
        records.push((
            "K0.3".to_owned(),
            "evidence_claims".to_owned(),
            Value::String(text(row, "evidence_id").to_owned()),
            row.clone(),
        ));
    }
    for row in array(&children.k0_4, "evidence_claims") {
        records.push((
            "K0.4".to_owned(),
            "evidence_claims".to_owned(),
            Value::String(text(row, "claim_id").to_owned()),
            row.clone(),
        ));
    }
    records
}

fn aggregate_claim_projection_sha256(claims: &[Value]) -> String {
    let mut claims = claims.iter().collect::<Vec<_>>();
    claims.sort_by(|left, right| text(left, "claim_id").cmp(text(right, "claim_id")));
    let mut projection = String::new();
    for claim in claims {
        projection.push_str(&canonical_json(claim));
        projection.push('\n');
    }
    sha256_hex(projection.as_bytes())
}

fn validate_claims_projection(packet: &Value, children: &ChildArtifacts) -> Result<(), String> {
    let claims = packet
        .get("claims_projection")
        .ok_or_else(|| "aggregate lacks claims_projection".to_owned())?;
    require_exact_keys(
        claims,
        &[
            "canonicalization_id",
            "canonicalization_rule",
            "child_claim_canonicalization_rule",
            "child_claim_record_count",
            "child_claim_projection_sha256",
            "child_claim_groups",
            "aggregate_claims",
            "aggregate_claim_count",
            "aggregate_claim_projection_sha256",
        ],
        "claims_projection",
    )?;
    if text(claims, "canonicalization_id") != "KAFKA_K0_5_CANONICAL_JSON_CLAIMS_V1"
        || text(claims, "canonicalization_rule")
            != "Sort claims by claim_id, recursively sort each claim object's keys, emit one compact JSON object per claim, and append one LF per record."
        || text(claims, "child_claim_canonicalization_rule")
            != "Wrap each child claim or no-claim row as an object with child, collection, id, and row fields; use the zero-based numeric array index as id for no-claim rows and the child's declared claim or evidence ID otherwise; sort by child, collection, and id; recursively sort object keys; emit compact JSON with one LF per record."
        || unsigned(claims, "child_claim_record_count") != 93
        || text(claims, "child_claim_projection_sha256") != CLAIMS_FULL_ROW_SHA256
        || canonical_record_projection_sha256(child_claim_records(children))
            != CLAIMS_FULL_ROW_SHA256
    {
        return Err("child claim projection drifted".to_owned());
    }
    require_equal(
        claims
            .get("child_claim_groups")
            .ok_or_else(|| "claims_projection lacks child_claim_groups".to_owned())?,
        serde_json::json!({
            "K0.1_no_claim":6,
            "K0.2_no_claim":8,
            "K0.3_documentation_claim":31,
            "K0.3_evidence_claim":6,
            "K0.3_no_claim":14,
            "K0.4_evidence_claim":6,
            "K0.4_no_claim":22
        }),
        "child claim groups",
    )?;
    let aggregate_claims = array(claims, "aggregate_claims");
    require_unique_string_field(aggregate_claims, "claim_id", "aggregate claims")?;
    require_equal(
        claims
            .get("aggregate_claims")
            .expect("claims_projection aggregate_claims was read as an array"),
        serde_json::json!([
            {"claim_id":"KAFKA-K0-5-CLAIM-001","subject":"source reachability","state":"STATIC_SOURCE_PINNED","source_packets":["K0.1"],"limitation":"No semantic or runtime claim."},
            {"claim_id":"KAFKA-K0-5-CLAIM-002","subject":"incumbent semantics","state":"STATIC_SOURCE_PINNED","source_packets":["K0.2"],"limitation":"No broker or lifecycle claim."},
            {"claim_id":"KAFKA-K0-5-CLAIM-003","subject":"repository-local downstream census","state":"STATIC_SOURCE_PINNED_EXTERNAL_UNKNOWN","source_packets":["K0.3"],"limitation":"External downstream population remains UNKNOWN."},
            {"claim_id":"KAFKA-K0-5-CLAIM-004","subject":"broker build and fixture provenance","state":"STATIC_SOURCE_PINNED_RUNTIME_BLOCKED","source_packets":["K0.4"],"limitation":"No actual native-binary or real-broker receipt exists."},
            {"claim_id":"KAFKA-K0-5-CLAIM-005","subject":"migration eligibility","state":"BLOCKED","source_packets":["K0.1","K0.2","K0.3","K0.4"],"limitation":"UNKNOWN and independent terminal gates remain."},
            {"claim_id":"KAFKA-K0-5-CLAIM-006","subject":"incumbent disposition","state":"KEEP_INCUMBENT","source_packets":["K0.1","K0.2","K0.3","K0.4"],"limitation":"No cutover or removal authority."},
            {"claim_id":"KAFKA-K0-5-CLAIM-007","subject":"native scope","state":"PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY","source_packets":["K0.1","K0.2","K0.3","K0.4"],"limitation":"Experimentation is quarantined from production and cannot retire the incumbent."}
        ]),
        "aggregate claims",
    )?;
    if unsigned(claims, "aggregate_claim_count") != 7
        || text(claims, "aggregate_claim_projection_sha256") != AGGREGATE_CLAIMS_SHA256
        || aggregate_claim_projection_sha256(aggregate_claims) != AGGREGATE_CLAIMS_SHA256
    {
        return Err("aggregate claim count/digest drifted".to_owned());
    }
    Ok(())
}

fn validate_disposition_gates_and_receipt(packet: &Value) -> Result<(), String> {
    require_equal(
        packet
            .get("disposition_receipt")
            .ok_or_else(|| "aggregate lacks disposition_receipt".to_owned())?,
        serde_json::json!({
            "incumbent_disposition":"KEEP_INCUMBENT",
            "native_scope":"PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY",
            "native_scope_owner":NATIVE_EPIC,
            "first_native_contract_gate":K1_GATE,
            "migration_eligible":false,
            "production_wiring_allowed":false,
            "dependency_exit_allowed":false,
            "feature_removal_allowed":false,
            "api_removal_allowed":false,
            "capability_removal_allowed":false,
            "file_deletion_allowed":false,
            "oracle_retirement_allowed":false,
            "cutover_allowed":false,
            "sole_conditional_cutover_owner":K15_CUTOVER,
            "on_missing_unowned_unknown_or_regression":"KEEP_INCUMBENT"
        }),
        "disposition receipt",
    )?;
    require_equal(
        packet
            .get("independent_terminal_gates")
            .ok_or_else(|| "aggregate lacks independent_terminal_gates".to_owned())?,
        serde_json::json!([
            {"gate_id":"K12.5","bead_id":K12_TERMINAL,"scope":"independent protocol, state, corpus, and oracle verification","state":"REQUIRED_NOT_PROVEN_BY_K0"},
            {"gate_id":"K13.6","bead_id":K13_TERMINAL,"scope":"terminal immutable real-service receipts and teardown","state":"REQUIRED_NOT_PROVEN_BY_K0"},
            {"gate_id":"K14.1","bead_id":K14_REFRESH,"scope":"claim-time source, downstream, fixture, owner, and receipt refresh","state":"REQUIRED_NOT_PROVEN_BY_K0"},
            {"gate_id":"K15","bead_id":K15_CUTOVER,"scope":"conditional no-loss cutover or terminal KEEP","state":"SOLE_CUTOVER_AUTHORITY"}
        ]),
        "independent terminal gates",
    )?;
    require_equal(
        packet
            .get("no_claim_boundaries")
            .ok_or_else(|| "aggregate lacks no_claim_boundaries".to_owned())?,
        serde_json::json!([
            "This aggregate proves only the exact static joins, hashes, ownership, collision accounting, and fail-closed disposition recorded from K0.1 through K0.4.",
            "It does not prove protocol correctness or supported API-version behavior.",
            "It does not prove native linkage, actual native capability flags, broker interoperability, or broker-version support.",
            "It does not prove complete TLS, SASL, credential, security, fault, restart, rolling-version, or recovery coverage.",
            "It does not prove cancellation, shutdown, rebalance, transaction, lifecycle, teardown, or residue correctness.",
            "It does not prove performance, resource bounds, reliability, absence of defects, release readiness, or broad workspace health.",
            "It records no compiler, formatter, test, runtime, broker, external-search, network, service, container, or remote-execution evidence from this aggregate session.",
            "It does not authorize migration, production wiring, oracle retirement, feature or dependency removal, API or capability removal, file deletion, or cutover."
        ]),
        "no-claim boundaries",
    )?;
    require_equal(
        packet
            .get("coverage_receipt")
            .ok_or_else(|| "aggregate lacks coverage_receipt".to_owned())?,
        serde_json::json!({
            "child_packet_count":4,
            "child_file_pin_count":12,
            "source_pin_rollup_complete":true,
            "source_pin_conflict_count":0,
            "primary_ids_complete_and_unique":true,
            "authority_reference_joins_complete":true,
            "typed_reference_joins_complete":true,
            "lexical_collision_groups_accounted":true,
            "unexpected_definition_collisions":[],
            "unknown_and_blocked_rows_accounted":true,
            "unowned_unknown_rows":[],
            "route_owner_edges_complete":true,
            "internal_handoffs_resolved":true,
            "claims_projection_complete":true,
            "migration_eligible":false,
            "disposition":"KEEP_INCUMBENT",
            "validation_mode":"STATIC_JSON_HASH_AND_EXACT_DIFF_ONLY",
            "dynamic_execution_claimed":false
        }),
        "coverage receipt",
    )
}

fn validate_docs(doc: &str) -> Result<(), String> {
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("K0.5 documentation markers must each occur exactly once".to_owned());
    }
    let begin = doc
        .find(DOC_BEGIN)
        .expect("the unique begin marker must have an offset");
    let end = doc
        .find(DOC_END)
        .expect("the unique end marker must have an offset");
    if begin >= end {
        return Err("K0.5 documentation markers are out of order".to_owned());
    }
    for required in [
        ARTIFACT_ID,
        BEAD_ID,
        "STATIC_ONLY_FAIL_CLOSED",
        "KEEP_INCUMBENT",
        "PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY",
        "The primary stable-ID receipt contains 903 unique IDs",
        "892 are core",
        "11 are K0.4 contradiction",
        "Source-pin canonical JSON | 266",
        "Unique source-pin paths | 247",
        "Source-pin overlap paths | 15",
        "Source-pin rows on overlap paths | 34",
        SOURCE_PIN_FULL_ROW_SHA256,
        SOURCE_PIN_OVERLAP_SHA256,
        PRIMARY_ID_SHA256,
        ROUTE_FULL_ROW_SHA256,
        ROUTE_PROJECTION_SHA256,
        REDUCED_UNKNOWN_SELECTOR_SHA256,
        AGGREGATE_CLAIMS_SHA256,
        "migration_eligible=false",
        "production_wiring_allowed=false",
        "oracle_retirement_allowed=false",
        "cutover_allowed=false",
        "permission to remove or delete",
    ] {
        if !doc.contains(required) {
            return Err(format!("K0.5 documentation lacks required phrase {required}"));
        }
    }
    Ok(())
}
