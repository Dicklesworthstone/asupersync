//! Static contract for Kafka K1.3 public API and migration policy.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.2.1.3
//! Fixture: artifacts/kafka_k1_public_api_contract_v1.json
//!
//! This integration test reads checked-in repository bytes only. It does not
//! compile a Kafka profile, contact a broker, or promote static inventory into
//! runtime, interoperability, migration, or cutover evidence.

#![allow(dead_code, missing_docs)]

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k1_public_api_contract_v1.json";
const DOC_PATH: &str = "docs/kafka_k1_public_api_contract.md";
const K0_1_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const K0_3_PATH: &str = "artifacts/kafka_downstream_user_journey_inventory_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";

const ARTIFACT_SHA256: &str = "e73eb1a20040b4fe7bc33dc9038de795beba16a7a86129d9d3aa8a12f24bb3bc";
const DOC_SHA256: &str = "ee938c6af5aa904c824b46697a996973c6248fdc6de56bf6db1d158ab54ba153";

const ARTIFACT_ID: &str = "kafka-k1-public-api-contract-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1.3";
const PARENT_BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.2.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const ADR_ID: &str = "DEP-ADR-009";
const CAPTURED_DATE_UTC: &str = "2026-08-03";
const BASELINE_REVISION: &str = "816cb7f89a881656f639c734d0aa4795300738c7";
const INVENTORY_STATE: &str =
    "K1_3_PUBLIC_API_CONFIG_ERROR_AND_MIGRATION_CONTRACT_FROZEN_KEEP_INCUMBENT";

const CORE_COUNT: usize = 129;
const SUPPORTING_COUNT: usize = 50;
const COMBINED_COUNT: usize = 179;
const CORE_SHA256: &str = "f1ebad598d91e38b86206686c8d35ec6f013bbf93cd422f4b68308fbf89efb7a";
const SUPPORTING_SHA256: &str = "1deac57a9c2330e41f67afccffb2353998e5719f3663ba39bde926090f262265";
const COMBINED_SHA256: &str = "36c6470809d8f8ed98291f0265db34d6003462889c730d1c029cf84690126cc3";

const PUBLIC_ID_SHA256: &str = "307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28";
const PUBLIC_ROW_SHA256: &str = "18ba7fa4a9db025263b9df4ae5ce5f36641ca5e9334d4eeaf8fd64b2bb66e4f2";
const EXPOSURE_SHA256: &str = "cec04b907f94b381e8c1e4e9c38a5cdee6d0d89508f52aab5f2c92eab15fb70f";
const FACADE_EXPORT_SHA256: &str =
    "8a63a3ae3410057e3aedcd063187e491529cd0bb978804c7cc41a8bffb9a7e5e";
const RENAMED_ALIAS_SHA256: &str =
    "eee9f608a39846d1df1ec81a830c0f7b079667a09f923a3a398c2cdd64ca1fb1";

const SEMANTIC_ID_SHA256: &str = "a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7";
const SEMANTIC_ROW_SHA256: &str =
    "d19103e0fb6dd8b291405b1925c15d14cfacdf970901c766c10e06fcdbd7beab";
const SHARED_ID_SHA256: &str = "92ab055d5d14e4971daf298e54c9f5036ecf71c490d579270f4789b889fc86a5";
const SHARED_OBJECT_SHA256: &str =
    "558e38b863ad5a8e423a7d2f3731ada112a7d0bea16cf60484fd5c383efdfcb0";
const ABSENCE_ROW_SHA256: &str = "9892212d2641f933ded02b730993ff3c81f21ea65f7565b74b4a038b5a69afc5";
const JOURNEY_ROW_SHA256: &str = "3124cf3daff343142b56bbadceba66f8d0fb21862f771957e667f4d6c393260f";
const JOURNEY_ID_SHA256: &str = "c5a9f1947a5ecf55898c61414bb39bf753cd236fe33157083994acd63176367f";
const FINDING_ROW_SHA256: &str = "cb04492d3a8e82d415833d06533ec311b72159c1a5e2b9051469e7b6e74ecae5";

const PROFILE_ROW_SHA256: &str = "8a2b2437daa7b2b4c8189875502bf5d4b049d6c9ce408d390279deaf8d8b5815";
const PROFILE_ID_SHA256: &str = "882b6f73ee7c5abfe73080804fcd082c05dddd9c4002ee61ff9336f0a0d439eb";
const PROFILE_GROUP_ROW_SHA256: &str =
    "75bedc39680e2df6ea1be48212fa6a0f9c397767cab43dcae769d29e99526c29";
const PROFILE_GROUP_ID_SHA256: &str =
    "7bb8ea31cc9a88c8f068f6a18a8656a1eea52056229aa11302ffb7f9473b938c";
const PROFILE_MEMBERSHIP_SHA256: &str =
    "60e296aa42497ee03292a481dd867919b873eb309cecbfbc7877e9338fe47925";
const PUBLIC_JOURNEY_EDGE_SHA256: &str =
    "2dc041692d554c03a1e123ba9e720967bf88288e402ebdc0ec7ddfe7a821f43a";
const SEMANTIC_JOURNEY_EDGE_SHA256: &str =
    "d48356bc797bf7af527f4e77915ae45bf6c442fa178f99a14f7350e7b42ffae9";
const FINDING_OWNER_EDGE_SHA256: &str =
    "1e4aea3a7dbe623f8e4c2c51b5bb5edbdec3e6ac0b002f5261d79edbcbc4a860";
const CONFLICT_ROW_SHA256: &str =
    "f684298a32b76973e88f91fc243e16ecba70a11b709832873792cbaf396fb390";
const HANDOFF_ROW_SHA256: &str = "e41627d1890e05487e9f76055d95015ff4309701e141f2f443b71bfd830df89b";
const NO_CLAIM_SHA256: &str = "761b33cf8a1c0e8a3c83ffb8f4597e1c2f526e14a6689e05d8113e09b917d7a6";

const DOC_BEGIN: &str = "<!-- BEGIN KAFKA K1.3 PUBLIC API CONTRACT -->";
const DOC_END: &str = "<!-- END KAFKA K1.3 PUBLIC API CONTRACT -->";

const ROOT_KEYS: &[&str] = &[
    "adr_id",
    "artifact_id",
    "authority",
    "authority_conflicts",
    "authority_inputs",
    "baseline_revision",
    "bead_id",
    "capability_id",
    "captured_date_utc",
    "coverage_model",
    "disposition_receipt",
    "error_and_outcome_contract",
    "explicit_absence_contract",
    "inventory_state",
    "journey_migration_contract",
    "no_claim_boundaries",
    "ownership_and_gates",
    "parent_bead_id",
    "policy",
    "profile_contract",
    "program_id",
    "public_api_contract",
    "schema_version",
    "semantic_contract",
];

const SEMANTIC_COLLECTIONS: &[(&str, &str)] = &[
    ("configuration_fields", "configuration_fields"),
    ("enum_semantics", "enum_semantics"),
    ("operations", "operations"),
    ("callable_helpers", "callable_helpers"),
];

const SEMANTIC_ROW_KEYS: &[&str] = &[
    "accepted_values",
    "broker_mapping",
    "cancellation_rule",
    "cfg_visibility",
    "credential_payload_rule",
    "default",
    "error_outcome",
    "gap_owners",
    "public_entry_points",
    "rejected_values",
    "resource_bound",
    "retry_rule",
    "semantic_id",
    "shutdown_rule",
    "source_anchor",
    "source_owner",
    "success_outcome",
    "surface",
    "timeout_rule",
];

#[derive(Clone)]
struct Inputs {
    artifact: Value,
    k0_1: Value,
    k0_2: Value,
    k0_3: Value,
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
        k0_1: parse_json(root, K0_1_PATH)?,
        k0_2: parse_json(root, K0_2_PATH)?,
        k0_3: parse_json(root, K0_3_PATH)?,
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

fn canonical_rows_sha256(rows: &[Value]) -> Result<String, String> {
    Ok(sorted_newline_sha256(
        rows.iter()
            .map(canonical_json)
            .collect::<Result<Vec<_>, _>>()?,
    ))
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
        .ok_or_else(|| format!("{key} must be text"))
}

fn count(value: &Value, key: &str) -> Result<usize, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("{key} must be a nonnegative count"))
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn string_set(values: &[Value]) -> Result<BTreeSet<String>, String> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "array entry must be text".to_owned())
        })
        .collect()
}

fn object_key_set(value: &Value) -> Result<BTreeSet<String>, String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .ok_or_else(|| "value must be an object".to_owned())
}

fn ids(rows: &[Value], key: &str) -> Result<Vec<String>, String> {
    rows.iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect()
}

fn unique(values: &[String], label: &str) -> Result<(), String> {
    let set = values.iter().collect::<BTreeSet<_>>();
    if set.len() == values.len() {
        Ok(())
    } else {
        Err(format!("{label} contains duplicates"))
    }
}

fn row_by_id<'a>(rows: &'a [Value], key: &str, id: &str) -> Result<&'a Value, String> {
    let matches = rows
        .iter()
        .filter(|row| row.get(key).and_then(Value::as_str) == Some(id))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [row] => Ok(row),
        _ => Err(format!(
            "expected exactly one {key}={id}, found {}",
            matches.len()
        )),
    }
}

fn validate_array_view(
    view: &Value,
    rows: &[Value],
    id_key: &str,
    disposition: &str,
) -> Result<(), String> {
    let row_ids = ids(rows, id_key)?;
    unique(&row_ids, &format!("{} IDs", text(view, "domain")?))?;
    assert_eq_value(count(view, "row_count")?, rows.len(), "domain row count")?;
    assert_eq_value(
        text(view, "id_set_sha256")?.to_owned(),
        sorted_newline_sha256(row_ids),
        "domain ID hash",
    )?;
    assert_eq_value(
        text(view, "canonical_row_sha256")?.to_owned(),
        canonical_rows_sha256(rows)?,
        "domain canonical row hash",
    )?;
    assert_eq_value(
        text(view, "disposition")?,
        disposition,
        "domain disposition",
    )?;
    Ok(())
}

fn assert_eq_value<T>(actual: T, expected: T, label: &str) -> Result<(), String>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected:?}, got {actual:?}"))
    }
}

fn semantic_rows(k0_2: &Value) -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for (collection, _) in SEMANTIC_COLLECTIONS {
        rows.extend(array(k0_2, collection)?.iter().cloned());
    }
    Ok(rows)
}

fn disposition_rows(inputs: &Inputs) -> Result<(Vec<String>, Vec<String>), String> {
    let mut core = Vec::new();
    let mut supporting = Vec::new();

    for row in array(&inputs.k0_1, "public_symbols")? {
        core.push(format!(
            "public_symbols\t{}\tPRESERVE",
            text(row, "symbol_id")?
        ));
    }
    for (collection, domain) in SEMANTIC_COLLECTIONS {
        for row in array(&inputs.k0_2, collection)? {
            core.push(format!("{domain}\t{}\tPRESERVE", text(row, "semantic_id")?));
        }
    }
    for row in array(&inputs.k0_2, "explicit_absences")? {
        core.push(format!(
            "explicit_absences\t{}\tADDITIVE_GAP",
            text(row, "absence_id")?
        ));
    }

    for key in object(&inputs.k0_2, "shared_semantics")?.keys() {
        supporting.push(format!("shared_semantics\t{key}\tPRESERVE"));
    }
    for row in array(&inputs.k0_3, "user_journeys")? {
        supporting.push(format!(
            "user_journeys\t{}\tPRESERVE",
            text(row, "journey_id")?
        ));
    }
    for row in array(&inputs.k0_2, "routed_findings")? {
        supporting.push(format!(
            "routed_findings\t{}\tREVIEWED_EVOLUTION_INPUT",
            text(row, "finding_id")?
        ));
    }

    Ok((core, supporting))
}

fn validate_identity(artifact: &Value) -> Result<(), String> {
    assert_eq_value(
        object_key_set(artifact)?,
        ROOT_KEYS.iter().map(|key| (*key).to_owned()).collect(),
        "root keys",
    )?;
    assert_eq_value(count(artifact, "schema_version")?, 1, "schema version")?;
    assert_eq_value(text(artifact, "artifact_id")?, ARTIFACT_ID, "artifact id")?;
    assert_eq_value(text(artifact, "program_id")?, PROGRAM_ID, "program id")?;
    assert_eq_value(text(artifact, "bead_id")?, BEAD_ID, "bead id")?;
    assert_eq_value(
        text(artifact, "parent_bead_id")?,
        PARENT_BEAD_ID,
        "parent bead",
    )?;
    assert_eq_value(
        text(artifact, "capability_id")?,
        CAPABILITY_ID,
        "capability id",
    )?;
    assert_eq_value(text(artifact, "adr_id")?, ADR_ID, "ADR id")?;
    assert_eq_value(
        text(artifact, "captured_date_utc")?,
        CAPTURED_DATE_UTC,
        "capture date",
    )?;
    assert_eq_value(
        text(artifact, "baseline_revision")?,
        BASELINE_REVISION,
        "baseline",
    )?;
    assert_eq_value(
        text(artifact, "inventory_state")?,
        INVENTORY_STATE,
        "inventory state",
    )?;

    let policy = artifact.get("policy").ok_or("policy missing")?;
    assert_eq_value(
        text(policy, "mode")?,
        "STATIC_ONLY_FAIL_CLOSED",
        "policy mode",
    )?;
    assert_eq_value(
        text(policy, "canonicalization_id")?,
        "KAFKA_K1_3_PUBLIC_API_CONTRACT_V1",
        "canonicalization id",
    )?;
    for (key, expected) in [
        ("missing_input_state", "BLOCKING_MISSING"),
        ("missing_row_state", "BLOCKING_MISSING"),
        ("extra_row_state", "BLOCKING_UNDECLARED_EXTRA"),
        ("duplicate_row_state", "BLOCKING_DUPLICATE"),
        ("changed_projection_state", "BLOCKING_SOURCE_DRIFT"),
        ("unowned_row_state", "BLOCKING_UNOWNED"),
    ] {
        assert_eq_value(text(policy, key)?, expected, key)?;
    }
    for (key, phrase) in [
        ("current_contract_rule", "Every accepted present"),
        (
            "two_axis_rule",
            "Contract disposition and gate state are independent",
        ),
        (
            "evolution_rule",
            "current behavior, target behavior, migration impact",
        ),
        ("unknown_rule", "migration-blocking"),
        (
            "profile_rule",
            "Native no-feature builds retain the typed facade",
        ),
        (
            "alias_rule",
            "Facade aliases and module-public names are distinct",
        ),
    ] {
        if !text(policy, key)?.contains(phrase) {
            return Err(format!("policy {key} omits {phrase:?}"));
        }
    }
    for key in [
        "planned_counts_as_executed",
        "static_counts_as_runtime",
        "local_model_counts_as_broker_parity",
        "compile_only_counts_as_runtime",
    ] {
        assert_eq_value(bool_field(policy, key)?, false, key)?;
    }
    Ok(())
}

fn validate_authority_inputs(root: &Path, artifact: &Value) -> Result<(), String> {
    let rows = array(artifact, "authority_inputs")?;
    assert_eq_value(rows.len(), 12, "authority input count")?;
    let allowed = [
        "Cargo.toml",
        "artifacts/kafka_capability_inventory_v1.json",
        "artifacts/kafka_downstream_user_journey_inventory_v1.json",
        "artifacts/kafka_incumbent_semantics_matrix_v1.json",
        "artifacts/kafka_k0_baseline_disposition_v1.json",
        "artifacts/kafka_k1_obligation_index_v1.json",
        "docs/adr/dep_plan_adr_009_kafka_client.md",
        "docs/kafka_k1_client_contract.md",
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
        "src/messaging/mod.rs",
        "tests/kafka_k1_client_contract.rs",
    ];
    let actual_paths = rows
        .iter()
        .map(|row| text(row, "path").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq_value(
        actual_paths,
        allowed.iter().map(|path| (*path).to_owned()).collect(),
        "authority paths",
    )?;

    let input_ids = ids(rows, "input_id")?;
    unique(&input_ids, "authority input IDs")?;
    for row in rows {
        let path = text(row, "path")?;
        let bytes = read_bytes(root, path)?;
        assert_eq_value(
            bytes.len(),
            count(row, "byte_count")?,
            &format!("{path} bytes"),
        )?;
        let record_count = std::str::from_utf8(&bytes)
            .map_err(|error| format!("{path} is not UTF-8: {error}"))?
            .lines()
            .count();
        assert_eq_value(
            record_count,
            count(row, "record_count")?,
            &format!("{path} records"),
        )?;
        assert_eq_value(
            sha256_bytes(&bytes),
            text(row, "sha256")?.to_owned(),
            &format!("{path} hash"),
        )?;
    }
    Ok(())
}

fn validate_coverage(inputs: &Inputs) -> Result<(), String> {
    let coverage = inputs
        .artifact
        .get("coverage_model")
        .ok_or("coverage_model missing")?;
    let core_contract = coverage
        .get("core_contract")
        .ok_or("core_contract missing")?;
    let supporting_contract = coverage
        .get("supporting_contract")
        .ok_or("supporting_contract missing")?;
    let combined_contract = coverage
        .get("combined_contract")
        .ok_or("combined_contract missing")?;
    let (core, supporting) = disposition_rows(inputs)?;
    let mut combined = core.clone();
    combined.extend(supporting.clone());
    unique(&core, "core disposition rows")?;
    unique(&supporting, "supporting disposition rows")?;
    unique(&combined, "combined disposition rows")?;

    assert_eq_value(core.len(), CORE_COUNT, "core row count")?;
    assert_eq_value(supporting.len(), SUPPORTING_COUNT, "supporting row count")?;
    assert_eq_value(combined.len(), COMBINED_COUNT, "combined row count")?;
    assert_eq_value(
        count(core_contract, "row_count")?,
        CORE_COUNT,
        "recorded core count",
    )?;
    assert_eq_value(
        count(supporting_contract, "row_count")?,
        SUPPORTING_COUNT,
        "recorded supporting count",
    )?;
    assert_eq_value(
        count(combined_contract, "row_count")?,
        COMBINED_COUNT,
        "recorded combined count",
    )?;
    assert_eq_value(
        sorted_newline_sha256(core),
        CORE_SHA256.to_owned(),
        "core hash",
    )?;
    assert_eq_value(
        sorted_newline_sha256(supporting),
        SUPPORTING_SHA256.to_owned(),
        "supporting hash",
    )?;
    assert_eq_value(
        sorted_newline_sha256(combined),
        COMBINED_SHA256.to_owned(),
        "combined hash",
    )?;
    assert_eq_value(
        text(core_contract, "projection_sha256")?,
        CORE_SHA256,
        "recorded core hash",
    )?;
    assert_eq_value(
        text(supporting_contract, "projection_sha256")?,
        SUPPORTING_SHA256,
        "recorded supporting hash",
    )?;
    assert_eq_value(
        text(combined_contract, "projection_sha256")?,
        COMBINED_SHA256,
        "recorded combined hash",
    )?;

    let views = array(coverage, "domain_views")?;
    assert_eq_value(views.len(), 9, "domain view count")?;
    unique(&ids(views, "domain")?, "domain names")?;
    validate_array_view(
        row_by_id(views, "domain", "public_symbols")?,
        array(&inputs.k0_1, "public_symbols")?,
        "symbol_id",
        "PRESERVE",
    )?;
    for (collection, domain) in SEMANTIC_COLLECTIONS {
        validate_array_view(
            row_by_id(views, "domain", domain)?,
            array(&inputs.k0_2, collection)?,
            "semantic_id",
            "PRESERVE",
        )?;
    }
    validate_array_view(
        row_by_id(views, "domain", "explicit_absences")?,
        array(&inputs.k0_2, "explicit_absences")?,
        "absence_id",
        "ADDITIVE_GAP",
    )?;
    validate_array_view(
        row_by_id(views, "domain", "user_journeys")?,
        array(&inputs.k0_3, "user_journeys")?,
        "journey_id",
        "PRESERVE",
    )?;
    validate_array_view(
        row_by_id(views, "domain", "routed_findings")?,
        array(&inputs.k0_2, "routed_findings")?,
        "finding_id",
        "REVIEWED_EVOLUTION_INPUT",
    )?;
    let shared_view = row_by_id(views, "domain", "shared_semantics")?;
    let shared = inputs
        .k0_2
        .get("shared_semantics")
        .ok_or("shared_semantics missing")?;
    let shared_keys = object_key_set(shared)?;
    assert_eq_value(
        count(shared_view, "row_count")?,
        shared_keys.len(),
        "shared view count",
    )?;
    assert_eq_value(
        text(shared_view, "id_set_sha256")?.to_owned(),
        sorted_newline_sha256(shared_keys.iter().cloned().collect()),
        "shared view ID hash",
    )?;
    assert_eq_value(
        text(shared_view, "canonical_object_sha256")?.to_owned(),
        sha256_bytes(format!("{}\n", canonical_json(shared)?).as_bytes()),
        "shared view object hash",
    )?;
    assert_eq_value(
        text(shared_view, "disposition")?,
        "PRESERVE",
        "shared disposition",
    )?;
    let sum = views
        .iter()
        .map(|view| count(view, "row_count"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    assert_eq_value(sum, COMBINED_COUNT, "domain count sum")?;
    for view in views {
        let disposition = text(view, "disposition")?;
        if !["PRESERVE", "ADDITIVE_GAP", "REVIEWED_EVOLUTION_INPUT"].contains(&disposition) {
            return Err(format!("unexpected disposition {disposition}"));
        }
        if !text(view, "gate_state")?.starts_with("BLOCKING") {
            return Err(format!("domain {} is not blocking", text(view, "domain")?));
        }
    }
    Ok(())
}

fn validate_public_surface(inputs: &Inputs) -> Result<(), String> {
    let rows = array(&inputs.k0_1, "public_symbols")?;
    assert_eq_value(rows.len(), 30, "public symbol count")?;
    let symbol_ids = ids(rows, "symbol_id")?;
    unique(&symbol_ids, "public symbol IDs")?;
    assert_eq_value(
        sorted_newline_sha256(symbol_ids),
        PUBLIC_ID_SHA256.to_owned(),
        "public ID hash",
    )?;
    assert_eq_value(
        canonical_rows_sha256(rows)?,
        PUBLIC_ROW_SHA256.to_owned(),
        "public row hash",
    )?;

    let mut exposure_rows = Vec::new();
    let mut exposure_counts = BTreeMap::<String, usize>::new();
    let mut facade_rows = Vec::new();
    let mut aliases = Vec::new();
    for row in rows {
        let id = text(row, "symbol_id")?;
        let exports = array(row, "facade_exports")?;
        let class = if !exports.is_empty() {
            "FACADE"
        } else if id == "KPR-PUB-002" || id == "KPR-PUB-021" {
            "CFG_TEST_ONLY"
        } else if id == "KPR-PUB-023" {
            "CFG_FUZZING"
        } else {
            "MODULE_PUBLIC"
        };
        exposure_rows.push(format!("{id}\t{class}"));
        *exposure_counts.entry(class.to_owned()).or_default() += 1;
        if !exports.is_empty() {
            let names = exports
                .iter()
                .map(|value| value.as_str().ok_or("facade export must be text"))
                .collect::<Result<Vec<_>, _>>()?;
            facade_rows.push(format!("{id}\t{}", names.join(",")));
            let declaration = array(row, "declarations")?
                .first()
                .and_then(Value::as_str)
                .ok_or("public declaration must be text")?;
            let module_name = declaration
                .split('@')
                .next()
                .ok_or("missing declaration name")?;
            for facade_name in names {
                if facade_name != module_name {
                    let mut alias = Map::new();
                    alias.insert("symbol_id".to_owned(), Value::String(id.to_owned()));
                    alias.insert(
                        "module_name".to_owned(),
                        Value::String(module_name.to_owned()),
                    );
                    alias.insert(
                        "facade_name".to_owned(),
                        Value::String(facade_name.to_owned()),
                    );
                    aliases.push(Value::Object(alias));
                }
            }
        }
    }
    assert_eq_value(
        sorted_newline_sha256(exposure_rows),
        EXPOSURE_SHA256.to_owned(),
        "exposure hash",
    )?;
    assert_eq_value(
        sorted_newline_sha256(facade_rows),
        FACADE_EXPORT_SHA256.to_owned(),
        "facade hash",
    )?;
    assert_eq_value(
        exposure_counts.get("FACADE").copied(),
        Some(15),
        "facade count",
    )?;
    assert_eq_value(
        exposure_counts.get("MODULE_PUBLIC").copied(),
        Some(12),
        "module-public count",
    )?;
    assert_eq_value(
        exposure_counts.get("CFG_TEST_ONLY").copied(),
        Some(2),
        "test-only count",
    )?;
    assert_eq_value(
        exposure_counts.get("CFG_FUZZING").copied(),
        Some(1),
        "fuzz count",
    )?;

    let public_contract = inputs
        .artifact
        .get("public_api_contract")
        .ok_or("public_api_contract missing")?;
    assert_eq_value(
        count(public_contract, "public_symbol_count")?,
        30,
        "recorded public count",
    )?;
    assert_eq_value(
        text(public_contract, "canonical_public_row_sha256")?,
        PUBLIC_ROW_SHA256,
        "recorded public row hash",
    )?;
    let exposure = public_contract
        .get("exposure_projection")
        .ok_or("exposure_projection missing")?;
    assert_eq_value(count(exposure, "row_count")?, 30, "recorded exposure count")?;
    assert_eq_value(
        text(exposure, "projection_sha256")?,
        EXPOSURE_SHA256,
        "recorded exposure hash",
    )?;
    let recorded_counts = object(exposure, "class_counts")?;
    for (class, expected) in [
        ("FACADE", 15),
        ("MODULE_PUBLIC", 12),
        ("CFG_TEST_ONLY", 2),
        ("CFG_FUZZING", 1),
        ("PRIVATE", 0),
    ] {
        let actual = recorded_counts
            .get(class)
            .and_then(Value::as_u64)
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| format!("missing exposure count {class}"))?;
        assert_eq_value(actual, expected, class)?;
    }
    let facade = public_contract
        .get("facade_export_projection")
        .ok_or("facade_export_projection missing")?;
    assert_eq_value(count(facade, "row_count")?, 15, "recorded facade count")?;
    assert_eq_value(
        text(facade, "projection_sha256")?,
        FACADE_EXPORT_SHA256,
        "recorded facade hash",
    )?;
    let alias_contract = public_contract
        .get("renamed_facade_aliases")
        .ok_or("renamed_facade_aliases missing")?;
    assert_eq_value(
        count(alias_contract, "row_count")?,
        2,
        "recorded alias count",
    )?;
    assert_eq_value(
        text(alias_contract, "projection_sha256")?,
        RENAMED_ALIAS_SHA256,
        "recorded alias hash",
    )?;
    let expected_aliases = array(alias_contract, "rows")?;
    assert_eq_value(aliases.len(), 2, "derived alias count")?;
    assert_eq_value(
        canonical_rows_sha256(&aliases)?,
        canonical_rows_sha256(expected_aliases)?,
        "alias rows",
    )?;
    let alias_projection = aliases
        .iter()
        .map(|row| {
            Ok(format!(
                "{}\t{}\t{}",
                text(row, "symbol_id")?,
                text(row, "module_name")?,
                text(row, "facade_name")?
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    assert_eq_value(
        sorted_newline_sha256(alias_projection),
        RENAMED_ALIAS_SHA256.to_owned(),
        "renamed alias hash",
    )?;

    let kafka_client = row_by_id(rows, "symbol_id", "KPR-PUB-022")?;
    assert_eq_value(
        array(kafka_client, "declarations")?.len(),
        2,
        "KafkaClient declarations",
    )?;
    if !text(kafka_client, "cfg")?.contains("mutually exclusive") {
        return Err("KafkaClient cfg no longer states mutual exclusion".to_owned());
    }
    Ok(())
}

fn validate_semantics_and_profiles(inputs: &Inputs) -> Result<(), String> {
    let rows = semantic_rows(&inputs.k0_2)?;
    assert_eq_value(rows.len(), 97, "semantic row count")?;
    let semantic_ids = ids(&rows, "semantic_id")?;
    unique(&semantic_ids, "semantic IDs")?;
    assert_eq_value(
        sorted_newline_sha256(semantic_ids.clone()),
        SEMANTIC_ID_SHA256.to_owned(),
        "semantic ID hash",
    )?;
    assert_eq_value(
        canonical_rows_sha256(&rows)?,
        SEMANTIC_ROW_SHA256.to_owned(),
        "semantic row hash",
    )?;
    let required_keys = SEMANTIC_ROW_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    for row in &rows {
        assert_eq_value(
            object_key_set(row)?,
            required_keys.clone(),
            &format!("semantic keys for {}", text(row, "semantic_id")?),
        )?;
    }

    let semantic_contract = inputs
        .artifact
        .get("semantic_contract")
        .ok_or("semantic_contract missing")?;
    assert_eq_value(
        count(semantic_contract, "semantic_row_count")?,
        97,
        "recorded semantic count",
    )?;
    assert_eq_value(
        text(semantic_contract, "semantic_id_set_sha256")?,
        SEMANTIC_ID_SHA256,
        "recorded semantic ID hash",
    )?;
    assert_eq_value(
        text(semantic_contract, "canonical_semantic_row_sha256")?,
        SEMANTIC_ROW_SHA256,
        "recorded semantic hash",
    )?;
    assert_eq_value(
        string_set(array(semantic_contract, "required_row_fields")?)?,
        required_keys,
        "required semantic fields",
    )?;
    let collection_counts = object(semantic_contract, "collection_counts")?;
    for (collection, expected) in [
        ("configuration_fields", 43),
        ("enum_semantics", 7),
        ("operations", 38),
        ("callable_helpers", 9),
    ] {
        let recorded = collection_counts
            .get(collection)
            .and_then(Value::as_u64)
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| format!("missing semantic collection count {collection}"))?;
        assert_eq_value(recorded, expected, collection)?;
        assert_eq_value(array(&inputs.k0_2, collection)?.len(), expected, collection)?;
    }

    let config_rows = array(&inputs.k0_2, "configuration_fields")?;
    let mut owner_counts = BTreeMap::<String, usize>::new();
    for row in config_rows {
        let owner = text(row, "surface")?
            .split('.')
            .next()
            .ok_or("configuration surface lacks an owner prefix")?;
        *owner_counts.entry(owner.to_owned()).or_default() += 1;
    }
    let recorded_owner_counts = object(semantic_contract, "configuration_owner_counts")?;
    for (owner, expected) in [
        ("ProducerConfig", 14),
        ("KafkaTlsConfig", 4),
        ("KafkaSaslConfig", 4),
        ("TransactionalConfig", 3),
        ("ConsumerConfig", 18),
    ] {
        assert_eq_value(owner_counts.get(owner).copied(), Some(expected), owner)?;
        let recorded = recorded_owner_counts
            .get(owner)
            .and_then(Value::as_u64)
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| format!("missing recorded configuration owner {owner}"))?;
        assert_eq_value(recorded, expected, &format!("recorded {owner}"))?;
    }
    assert_eq_value(
        text(
            row_by_id(config_rows, "semantic_id", "KPR-CFG-006")?,
            "default",
        )?,
        "true",
        "idempotence default",
    )?;
    assert_eq_value(
        text(
            row_by_id(config_rows, "semantic_id", "KCO-CFG-007")?,
            "default",
        )?,
        "false, manual commit",
        "manual commit default",
    )?;
    let rebalance = row_by_id(
        array(&inputs.k0_2, "operations")?,
        "semantic_id",
        "KCO-OP-005",
    )?;
    assert_eq_value(
        text(rebalance, "surface")?,
        "KafkaConsumer caller-driven rebalance",
        "rebalance surface",
    )?;
    let invariants = array(semantic_contract, "headline_invariants")?;
    assert_eq_value(invariants.len(), 4, "headline invariant count")?;
    unique(&ids(invariants, "invariant_id")?, "headline invariant IDs")?;
    assert_eq_value(
        text(
            row_by_id(
                invariants,
                "invariant_id",
                "K1-3-INVARIANT-IDEMPOTENCE-DEFAULT",
            )?,
            "required_current_value",
        )?,
        "true",
        "recorded idempotence default",
    )?;
    assert_eq_value(
        text(
            row_by_id(
                invariants,
                "invariant_id",
                "K1-3-INVARIANT-MANUAL-COMMIT-DEFAULT",
            )?,
            "required_current_value",
        )?,
        "false, manual commit",
        "recorded manual commit default",
    )?;
    let no_feature = row_by_id(
        invariants,
        "invariant_id",
        "K1-3-INVARIANT-NO-FEATURE-TYPED-FAILURE",
    )?;
    assert_eq_value(
        string_set(array(no_feature, "source_rows")?)?,
        [
            "KCO-OP-003",
            "KCO-OP-004",
            "KCO-OP-005",
            "KCO-OP-006",
            "KCO-OP-007",
            "KCO-OP-008",
            "KPR-OP-002",
            "KPR-OP-003",
            "KPR-PUB-001",
            "KPR-PUB-005",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "no-feature invariant sources",
    )?;

    let shared = inputs
        .k0_2
        .get("shared_semantics")
        .ok_or("shared_semantics missing")?;
    let shared_keys = object_key_set(shared)?;
    assert_eq_value(shared_keys.len(), 12, "shared semantic count")?;
    assert_eq_value(
        sorted_newline_sha256(shared_keys.iter().cloned().collect()),
        SHARED_ID_SHA256.to_owned(),
        "shared ID hash",
    )?;
    assert_eq_value(
        sha256_bytes(format!("{}\n", canonical_json(shared)?).as_bytes()),
        SHARED_OBJECT_SHA256.to_owned(),
        "shared object hash",
    )?;
    let shared_contract = semantic_contract
        .get("shared_semantics")
        .ok_or("semantic shared contract missing")?;
    assert_eq_value(
        count(shared_contract, "row_count")?,
        12,
        "recorded shared count",
    )?;
    assert_eq_value(
        string_set(array(shared_contract, "keys")?)?,
        shared_keys,
        "recorded shared keys",
    )?;
    assert_eq_value(
        text(shared_contract, "id_set_sha256")?,
        SHARED_ID_SHA256,
        "recorded shared ID hash",
    )?;
    assert_eq_value(
        text(shared_contract, "canonical_object_sha256")?,
        SHARED_OBJECT_SHA256,
        "recorded shared object hash",
    )?;

    let profiles = array(&inputs.k0_1, "compilation_profiles")?;
    assert_eq_value(profiles.len(), 13, "compilation profile count")?;
    assert_eq_value(
        sorted_newline_sha256(ids(profiles, "profile_id")?),
        PROFILE_ID_SHA256.to_owned(),
        "profile ID hash",
    )?;
    assert_eq_value(
        canonical_rows_sha256(profiles)?,
        PROFILE_ROW_SHA256.to_owned(),
        "profile hash",
    )?;
    let profile_groups = array(&inputs.k0_2, "profile_disposition_groups")?;
    assert_eq_value(profile_groups.len(), 17, "profile group count")?;
    assert_eq_value(
        sorted_newline_sha256(ids(profile_groups, "profile_group_id")?),
        PROFILE_GROUP_ID_SHA256.to_owned(),
        "profile group ID hash",
    )?;
    assert_eq_value(
        canonical_rows_sha256(profile_groups)?,
        PROFILE_GROUP_ROW_SHA256.to_owned(),
        "profile group hash",
    )?;
    let mut memberships = Vec::new();
    let mut seen_semantics = Vec::new();
    for group in profile_groups {
        let group_id = text(group, "profile_group_id")?;
        for semantic_id in array(group, "semantic_ids")? {
            let semantic_id = semantic_id
                .as_str()
                .ok_or("semantic profile member must be text")?;
            memberships.push(format!("{semantic_id}\t{group_id}"));
            seen_semantics.push(semantic_id.to_owned());
        }
    }
    assert_eq_value(memberships.len(), 97, "profile membership count")?;
    unique(&seen_semantics, "profile semantic memberships")?;
    assert_eq_value(
        seen_semantics.into_iter().collect::<BTreeSet<_>>(),
        semantic_ids.into_iter().collect(),
        "profile semantic coverage",
    )?;
    assert_eq_value(
        sorted_newline_sha256(memberships),
        PROFILE_MEMBERSHIP_SHA256.to_owned(),
        "profile membership hash",
    )?;
    let profile_contract = inputs
        .artifact
        .get("profile_contract")
        .ok_or("profile_contract missing")?;
    assert_eq_value(
        count(profile_contract, "compilation_profile_count")?,
        13,
        "recorded profile count",
    )?;
    assert_eq_value(
        text(profile_contract, "compilation_profile_id_set_sha256")?,
        PROFILE_ID_SHA256,
        "recorded profile ID hash",
    )?;
    assert_eq_value(
        text(profile_contract, "canonical_compilation_profile_sha256")?,
        PROFILE_ROW_SHA256,
        "recorded profile hash",
    )?;
    assert_eq_value(
        count(profile_contract, "semantic_profile_group_count")?,
        17,
        "recorded profile group count",
    )?;
    assert_eq_value(
        text(profile_contract, "semantic_profile_group_id_set_sha256")?,
        PROFILE_GROUP_ID_SHA256,
        "recorded profile group ID hash",
    )?;
    assert_eq_value(
        text(profile_contract, "canonical_semantic_profile_group_sha256")?,
        PROFILE_GROUP_ROW_SHA256,
        "recorded profile group hash",
    )?;
    assert_eq_value(
        count(profile_contract, "semantic_profile_membership_count")?,
        97,
        "recorded profile membership count",
    )?;
    assert_eq_value(
        text(profile_contract, "semantic_profile_membership_sha256")?,
        PROFILE_MEMBERSHIP_SHA256,
        "recorded profile membership hash",
    )?;

    let error_contract = inputs
        .artifact
        .get("error_and_outcome_contract")
        .ok_or("error_and_outcome_contract missing")?;
    let error_row = row_by_id(
        array(&inputs.k0_1, "public_symbols")?,
        "symbol_id",
        "KPR-PUB-001",
    )?;
    assert_eq_value(
        array(error_contract, "required_variants")?,
        array(error_row, "public_variants")?,
        "KafkaError variants",
    )?;
    assert_eq_value(
        array(error_contract, "required_classifiers")?,
        array(error_row, "public_methods")?,
        "KafkaError classifiers",
    )?;
    for (key, expected) in [
        ("public_error_symbol", "KPR-PUB-001"),
        ("error_type", "KafkaError"),
        (
            "implementation_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.3",
        ),
        (
            "privacy_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.4",
        ),
        (
            "independent_verification_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
        ),
        (
            "disposition",
            "PRESERVE_CURRENT_AND_REQUIRE_REVIEWED_EVOLUTION",
        ),
        (
            "gate_state",
            "BLOCKING_PENDING_TYPED_OUTCOME_AND_PRIVACY_RECEIPTS",
        ),
    ] {
        assert_eq_value(text(error_contract, key)?, expected, key)?;
    }
    Ok(())
}

fn validate_absences_conflicts_and_journeys(inputs: &Inputs) -> Result<(), String> {
    let source_absences = array(&inputs.k0_2, "explicit_absences")?;
    assert_eq_value(source_absences.len(), 2, "source absence count")?;
    assert_eq_value(
        canonical_rows_sha256(source_absences)?,
        ABSENCE_ROW_SHA256.to_owned(),
        "absence hash",
    )?;
    let absence_contract = inputs
        .artifact
        .get("explicit_absence_contract")
        .ok_or("explicit_absence_contract missing")?;
    assert_eq_value(
        count(absence_contract, "row_count")?,
        2,
        "recorded absence count",
    )?;
    assert_eq_value(
        text(absence_contract, "canonical_source_row_sha256")?,
        ABSENCE_ROW_SHA256,
        "recorded absence hash",
    )?;
    let absence_rows = array(absence_contract, "rows")?;
    assert_eq_value(absence_rows.len(), 2, "contract absence count")?;
    assert_eq_value(
        ids(absence_rows, "absence_id")?
            .into_iter()
            .collect::<BTreeSet<_>>(),
        ids(source_absences, "absence_id")?.into_iter().collect(),
        "absence IDs",
    )?;
    for row in absence_rows {
        let source = row_by_id(source_absences, "absence_id", text(row, "absence_id")?)?;
        for key in [
            "absence_id",
            "surface",
            "shipped_state",
            "disposition_owner",
            "implementation_owner",
            "verification_owner",
            "api_contract_owner",
            "implementation_owner_state",
        ] {
            if let Some(expected) = source.get(key) {
                assert_eq_value(row.get(key), Some(expected), &format!("absence {key}"))?;
            }
        }
        assert_eq_value(
            text(row, "disposition")?,
            "ADDITIVE_GAP",
            "absence disposition",
        )?;
        if !text(row, "gate_state")?.starts_with("BLOCKING") {
            return Err(format!(
                "absence {} is not blocking",
                text(row, "absence_id")?
            ));
        }
    }
    assert_eq_value(
        bool_field(absence_contract, "normalization_forbidden")?,
        true,
        "absence normalization",
    )?;
    assert_eq_value(
        bool_field(absence_contract, "absence_authorizes_removal")?,
        false,
        "absence removal",
    )?;
    assert_eq_value(
        bool_field(absence_contract, "absence_counts_as_parity")?,
        false,
        "absence parity",
    )?;

    let conflicts = inputs
        .artifact
        .get("authority_conflicts")
        .ok_or("authority_conflicts missing")?;
    assert_eq_value(count(conflicts, "row_count")?, 5, "recorded conflict count")?;
    let conflict_rows = array(conflicts, "rows")?;
    assert_eq_value(conflict_rows.len(), 5, "conflict count")?;
    assert_eq_value(
        canonical_rows_sha256(conflict_rows)?,
        CONFLICT_ROW_SHA256.to_owned(),
        "conflict row hash",
    )?;
    unique(&ids(conflict_rows, "conflict_id")?, "conflict IDs")?;
    for row in conflict_rows {
        if !text(row, "gate_state")?.starts_with("BLOCKING") {
            return Err(format!(
                "conflict {} is not blocking",
                text(row, "conflict_id")?
            ));
        }
        if array(row, "current_authority_refs")?.is_empty() || array(row, "owners")?.is_empty() {
            return Err(format!(
                "conflict {} lacks authority or owner",
                text(row, "conflict_id")?
            ));
        }
    }

    let journeys = array(&inputs.k0_3, "user_journeys")?;
    assert_eq_value(journeys.len(), 15, "journey count")?;
    assert_eq_value(
        sorted_newline_sha256(ids(journeys, "journey_id")?),
        JOURNEY_ID_SHA256.to_owned(),
        "journey ID hash",
    )?;
    assert_eq_value(
        canonical_rows_sha256(journeys)?,
        JOURNEY_ROW_SHA256.to_owned(),
        "journey hash",
    )?;
    let journey_contract = inputs
        .artifact
        .get("journey_migration_contract")
        .ok_or("journey_migration_contract missing")?;
    assert_eq_value(
        count(journey_contract, "journey_count")?,
        15,
        "recorded journey count",
    )?;
    assert_eq_value(
        text(journey_contract, "journey_id_set_sha256")?,
        JOURNEY_ID_SHA256,
        "recorded journey ID hash",
    )?;
    assert_eq_value(
        text(journey_contract, "canonical_journey_row_sha256")?,
        JOURNEY_ROW_SHA256,
        "recorded journey hash",
    )?;

    let usage = journey_contract
        .get("usage_coverage")
        .ok_or("usage_coverage missing")?;
    let public_dispositions = array(&inputs.k0_3, "k0_1_symbol_dispositions")?;
    let semantic_dispositions = array(&inputs.k0_3, "k0_2_semantic_dispositions")?;
    let allowed_usage_states = ["KNOWN_LOCAL_REFERENCES", "UNKNOWN"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let public_usage_states = public_dispositions
        .iter()
        .map(|row| text(row, "usage_knowledge_state").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let semantic_usage_states = semantic_dispositions
        .iter()
        .map(|row| text(row, "usage_knowledge_state").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq_value(
        public_usage_states,
        allowed_usage_states.clone(),
        "public usage states",
    )?;
    assert_eq_value(
        semantic_usage_states,
        allowed_usage_states,
        "semantic usage states",
    )?;
    let public_known = public_dispositions
        .iter()
        .filter(|row| {
            row.get("usage_knowledge_state").and_then(Value::as_str)
                == Some("KNOWN_LOCAL_REFERENCES")
        })
        .count();
    let semantic_known = semantic_dispositions
        .iter()
        .filter(|row| {
            row.get("usage_knowledge_state").and_then(Value::as_str)
                == Some("KNOWN_LOCAL_REFERENCES")
        })
        .count();
    assert_eq_value(public_known, 17, "known public usage")?;
    assert_eq_value(
        public_dispositions.len() - public_known,
        13,
        "unknown public usage",
    )?;
    assert_eq_value(semantic_known, 45, "known semantic usage")?;
    assert_eq_value(
        semantic_dispositions.len() - semantic_known,
        52,
        "unknown semantic usage",
    )?;
    assert_eq_value(
        count(usage, "public_known_local_references")?,
        17,
        "recorded public known",
    )?;
    assert_eq_value(
        count(usage, "public_symbol_rows")?,
        30,
        "recorded public usage rows",
    )?;
    assert_eq_value(
        count(usage, "public_unknown")?,
        13,
        "recorded public unknown",
    )?;
    assert_eq_value(
        count(usage, "semantic_known_local_references")?,
        45,
        "recorded semantic known",
    )?;
    assert_eq_value(
        count(usage, "semantic_rows")?,
        97,
        "recorded semantic usage rows",
    )?;
    assert_eq_value(
        count(usage, "semantic_unknown")?,
        52,
        "recorded semantic unknown",
    )?;

    let mut public_edges = Vec::new();
    for row in public_dispositions {
        let symbol_id = text(row, "symbol_id")?;
        for journey_id in array(row, "journey_ids")? {
            public_edges.push(format!(
                "{symbol_id}\t{}",
                journey_id
                    .as_str()
                    .ok_or("public journey ID must be text")?
            ));
        }
    }
    let mut semantic_edges = Vec::new();
    for row in semantic_dispositions {
        let semantic_id = text(row, "semantic_id")?;
        for journey_id in array(row, "journey_ids")? {
            semantic_edges.push(format!(
                "{semantic_id}\t{}",
                journey_id
                    .as_str()
                    .ok_or("semantic journey ID must be text")?
            ));
        }
    }
    unique(&public_edges, "public journey edges")?;
    unique(&semantic_edges, "semantic journey edges")?;
    assert_eq_value(public_edges.len(), 109, "public journey edge count")?;
    assert_eq_value(semantic_edges.len(), 216, "semantic journey edge count")?;
    assert_eq_value(
        count(usage, "public_journey_edge_count")?,
        109,
        "recorded public edge count",
    )?;
    assert_eq_value(
        count(usage, "semantic_journey_edge_count")?,
        216,
        "recorded semantic edge count",
    )?;
    assert_eq_value(
        sorted_newline_sha256(public_edges),
        PUBLIC_JOURNEY_EDGE_SHA256.to_owned(),
        "public journey edge hash",
    )?;
    assert_eq_value(
        sorted_newline_sha256(semantic_edges),
        SEMANTIC_JOURNEY_EDGE_SHA256.to_owned(),
        "semantic journey edge hash",
    )?;
    assert_eq_value(
        text(usage, "public_journey_edge_sha256")?,
        PUBLIC_JOURNEY_EDGE_SHA256,
        "recorded public edge hash",
    )?;
    assert_eq_value(
        text(usage, "semantic_journey_edge_sha256")?,
        SEMANTIC_JOURNEY_EDGE_SHA256,
        "recorded semantic edge hash",
    )?;
    assert_eq_value(
        bool_field(usage, "usage_evidence_is_completeness_proof")?,
        false,
        "usage completeness claim",
    )?;
    assert_eq_value(
        bool_field(usage, "unknown_blocks_migration")?,
        true,
        "unknown gate",
    )?;

    let findings = array(&inputs.k0_2, "routed_findings")?;
    assert_eq_value(findings.len(), 23, "finding count")?;
    assert_eq_value(
        canonical_rows_sha256(findings)?,
        FINDING_ROW_SHA256.to_owned(),
        "finding hash",
    )?;
    let mut owner_edges = Vec::new();
    for row in findings {
        let finding_id = text(row, "finding_id")?;
        for owner in array(row, "owner_beads")? {
            owner_edges.push(format!(
                "{finding_id}\t{}",
                owner.as_str().ok_or("finding owner must be text")?
            ));
        }
    }
    unique(&owner_edges, "finding owner edges")?;
    assert_eq_value(owner_edges.len(), 62, "finding owner edge count")?;
    assert_eq_value(
        sorted_newline_sha256(owner_edges),
        FINDING_OWNER_EDGE_SHA256.to_owned(),
        "finding owner edge hash",
    )?;
    let ownership = inputs
        .artifact
        .get("ownership_and_gates")
        .ok_or("ownership_and_gates missing")?;
    assert_eq_value(
        count(ownership, "finding_owner_edge_count")?,
        62,
        "recorded owner edge count",
    )?;
    assert_eq_value(
        text(ownership, "finding_owner_edge_sha256")?,
        FINDING_OWNER_EDGE_SHA256,
        "recorded owner edge hash",
    )?;
    assert_eq_value(
        count(ownership, "unowned_row_count")?,
        0,
        "unowned row count",
    )?;
    for (key, expected) in [
        ("policy_owner", BEAD_ID),
        (
            "aggregate_contract_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
        ),
        (
            "independent_verification_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
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
        ("migration_gate", "BLOCKING_KEEP_INCUMBENT"),
    ] {
        assert_eq_value(text(ownership, key)?, expected, key)?;
    }
    let implementation_epics = object(ownership, "implementation_epics")?;
    for (key, expected) in [
        (
            "producer_delivery_and_idempotence",
            "asupersync-dep-p7-kafka-removal-sarszu.2.5",
        ),
        (
            "transactions_and_atomic_offsets",
            "asupersync-dep-p7-kafka-removal-sarszu.2.6",
        ),
        (
            "fetch_isolation_and_cursors",
            "asupersync-dep-p7-kafka-removal-sarszu.2.7",
        ),
        (
            "group_and_rebalance",
            "asupersync-dep-p7-kafka-removal-sarszu.2.8",
        ),
        (
            "offset_policy_and_recovery",
            "asupersync-dep-p7-kafka-removal-sarszu.2.9",
        ),
        (
            "public_api_config_errors_privacy_docs_and_migration",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10",
        ),
    ] {
        assert_eq_value(
            implementation_epics.get(key).and_then(Value::as_str),
            Some(expected),
            key,
        )?;
    }
    let public_owners = object(ownership, "public_surface_owners")?;
    for (key, expected) in [
        (
            "api_and_cfg_contract",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
        ),
        (
            "configuration_and_defaults",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.2",
        ),
        (
            "typed_errors_and_outcomes",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.3",
        ),
        (
            "telemetry_privacy_and_redaction",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.4",
        ),
        (
            "documentation_and_migration",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.5",
        ),
    ] {
        assert_eq_value(
            public_owners.get(key).and_then(Value::as_str),
            Some(expected),
            key,
        )?;
    }

    let handoffs = array(journey_contract, "ordered_handoffs")?;
    assert_eq_value(handoffs.len(), 7, "handoff count")?;
    assert_eq_value(
        canonical_rows_sha256(handoffs)?,
        HANDOFF_ROW_SHA256.to_owned(),
        "handoff row hash",
    )?;
    for (index, handoff) in handoffs.iter().enumerate() {
        assert_eq_value(count(handoff, "sequence")?, index + 1, "handoff sequence")?;
        if index > 0 && !text(handoff, "state")?.starts_with("BLOCKING") {
            return Err(format!("handoff {} is not blocking", index + 1));
        }
    }
    let standalone = array(journey_contract, "standalone_owner_boundaries")?;
    assert_eq_value(standalone.len(), 3, "standalone owner count")?;
    assert_eq_value(
        ids(standalone, "bead_id")?
            .into_iter()
            .collect::<BTreeSet<_>>(),
        [
            "asupersync-messaging-resp3-kafka-commit-o9ujbk",
            "asupersync-ne8jdw",
            "asupersync-o82yd7",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "standalone owner IDs",
    )?;
    for row in standalone {
        assert_eq_value(
            bool_field(row, "absorbed_or_closed_by_k1_3")?,
            false,
            "standalone absorption",
        )?;
    }

    let tracker_ids = inputs
        .tracker
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut referenced_beads = BTreeSet::new();
    collect_bead_ids(&inputs.artifact, &mut referenced_beads);
    for bead_id in referenced_beads {
        if bead_id != PROGRAM_ID && !tracker_ids.contains(bead_id.as_str()) {
            return Err(format!("referenced bead does not exist: {bead_id}"));
        }
    }
    Ok(())
}

fn collect_bead_ids(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(text) if text.starts_with("asupersync-") => {
            output.insert(text.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_bead_ids(value, output);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_bead_ids(value, output);
            }
        }
        _ => {}
    }
}

fn validate_gates_and_docs(root: &Path, artifact: &Value) -> Result<(), String> {
    let authority = artifact.get("authority").ok_or("authority missing")?;
    let receipt = artifact
        .get("disposition_receipt")
        .ok_or("disposition_receipt missing")?;
    for (key, expected) in [
        ("k1_1_bead", "asupersync-dep-p7-kafka-removal-sarszu.2.1.1"),
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        (
            "k1_terminal_bead",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.5",
        ),
        (
            "verification_terminal_bead",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.5",
        ),
        (
            "real_service_terminal_bead",
            "asupersync-dep-p7-kafka-removal-sarszu.2.13.6",
        ),
        (
            "claim_time_refresh_bead",
            "asupersync-dep-p7-kafka-removal-sarszu.2.14.1",
        ),
        (
            "sole_conditional_cutover_bead",
            "asupersync-dep-p7-kafka-removal-sarszu.2.15",
        ),
    ] {
        assert_eq_value(text(authority, key)?, expected, key)?;
    }
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
        assert_eq_value(
            bool_field(authority, key)?,
            false,
            &format!("authority {key}"),
        )?;
        assert_eq_value(bool_field(receipt, key)?, false, &format!("receipt {key}"))?;
    }
    assert_eq_value(
        bool_field(receipt, "k1_3_contract_complete")?,
        true,
        "K1.3 completion",
    )?;
    for key in [
        "k1_2_complete",
        "k1_4_complete",
        "k1_5_complete",
        "k1_parent_complete",
    ] {
        assert_eq_value(bool_field(receipt, key)?, false, key)?;
    }
    assert_eq_value(
        bool_field(receipt, "migration_eligible")?,
        false,
        "migration eligibility",
    )?;
    assert_eq_value(
        text(receipt, "incumbent_disposition")?,
        "KEEP_INCUMBENT",
        "incumbent",
    )?;

    let boundaries = array(artifact, "no_claim_boundaries")?;
    assert_eq_value(boundaries.len(), 7, "no-claim boundary count")?;
    assert_eq_value(
        sorted_newline_sha256(
            boundaries
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "no-claim boundary must be text".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        NO_CLAIM_SHA256.to_owned(),
        "no-claim hash",
    )?;
    let joined = boundaries
        .iter()
        .map(|value| value.as_str().ok_or("no-claim boundary must be text"))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for phrase in [
        "does not prove compilation",
        "does not prove Kafka protocol correctness",
        "does not prove delivery certainty",
        "does not prove complete credential zeroization",
        "does not close or absorb",
        "does not authorize",
    ] {
        if !joined.contains(phrase) {
            return Err(format!("no-claim boundaries omit {phrase:?}"));
        }
    }

    let artifact_bytes = read_bytes(root, ARTIFACT_PATH)?;
    let doc_bytes = read_bytes(root, DOC_PATH)?;
    assert_eq_value(
        sha256_bytes(&artifact_bytes),
        ARTIFACT_SHA256.to_owned(),
        "artifact hash",
    )?;
    assert_eq_value(
        sha256_bytes(&doc_bytes),
        DOC_SHA256.to_owned(),
        "document hash",
    )?;
    let doc =
        String::from_utf8(doc_bytes).map_err(|error| format!("document is not UTF-8: {error}"))?;
    assert_eq_value(doc.matches(DOC_BEGIN).count(), 1, "document begin marker")?;
    assert_eq_value(doc.matches(DOC_END).count(), 1, "document end marker")?;
    for phrase in [
        "The core contract contains exactly 129 rows",
        "The supporting contract contains exactly 50 rows",
        "Two independent axes: disposition and gate state",
        "No compiler, formatter, linter, test, fuzz target, broker",
        "K15 remains the sole conditional cutover authority",
    ] {
        if !doc.contains(phrase) {
            return Err(format!("document omits {phrase:?}"));
        }
    }
    Ok(())
}

fn validate(root: &Path, inputs: &Inputs) -> Result<(), String> {
    validate_identity(&inputs.artifact)?;
    validate_authority_inputs(root, &inputs.artifact)?;
    validate_coverage(inputs)?;
    validate_public_surface(inputs)?;
    validate_semantics_and_profiles(inputs)?;
    validate_absences_conflicts_and_journeys(inputs)?;
    validate_gates_and_docs(root, &inputs.artifact)?;
    Ok(())
}

#[test]
fn kafka_k1_public_api_contract_is_exact_and_fail_closed() {
    let root = repo_root();
    let inputs = load_inputs(&root).expect("static K1.3 inputs must parse");
    validate(&root, &inputs).expect("K1.3 public API contract must remain exact");
}

#[test]
fn changed_disposition_fails_closed() {
    let root = repo_root();
    let mut inputs = load_inputs(&root).expect("static K1.3 inputs must parse");
    inputs.artifact["coverage_model"]["domain_views"][0]["disposition"] =
        Value::String("REMOVE".to_owned());
    let error = validate(&root, &inputs).expect_err("changed disposition must fail");
    assert!(
        error.contains("domain disposition"),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_conflict_fails_closed() {
    let root = repo_root();
    let mut inputs = load_inputs(&root).expect("static K1.3 inputs must parse");
    inputs.artifact["authority_conflicts"]["rows"]
        .as_array_mut()
        .expect("conflict rows must be an array")
        .pop();
    let error = validate(&root, &inputs).expect_err("missing conflict must fail");
    assert!(
        error.contains("conflict count"),
        "unexpected error: {error}"
    );
}

#[test]
fn cutover_permission_fails_closed() {
    let root = repo_root();
    let mut inputs = load_inputs(&root).expect("static K1.3 inputs must parse");
    inputs.artifact["disposition_receipt"]["cutover_allowed"] = Value::Bool(true);
    let error = validate(&root, &inputs).expect_err("cutover permission must fail");
    assert!(
        error.contains("cutover_allowed"),
        "unexpected error: {error}"
    );
}

#[test]
fn alias_narrowing_fails_closed() {
    let root = repo_root();
    let mut inputs = load_inputs(&root).expect("static K1.3 inputs must parse");
    inputs.artifact["public_api_contract"]["renamed_facade_aliases"]["rows"]
        .as_array_mut()
        .expect("alias rows must be an array")
        .pop();
    let error = validate(&root, &inputs).expect_err("alias narrowing must fail");
    assert!(error.contains("alias rows"), "unexpected error: {error}");
}

#[test]
fn high_risk_policy_mutations_fail_closed() {
    let root = repo_root();
    let original = load_inputs(&root).expect("static K1.3 inputs must parse");

    let mut profile = original.clone();
    profile.artifact["profile_contract"]["semantic_profile_membership_sha256"] =
        Value::String("0".repeat(64));
    let error = validate(&root, &profile).expect_err("profile drift must fail");
    assert!(
        error.contains("recorded profile membership hash"),
        "unexpected error: {error}"
    );

    let mut absence = original.clone();
    absence.artifact["explicit_absence_contract"]["rows"][0]["implementation_owner"] =
        Value::String(BEAD_ID.to_owned());
    let error = validate(&root, &absence).expect_err("absence owner drift must fail");
    assert!(
        error.contains("absence implementation_owner"),
        "unexpected error: {error}"
    );

    let mut conflict = original.clone();
    conflict.artifact["authority_conflicts"]["rows"][0]["claim"] =
        Value::String("normalized away".to_owned());
    let error = validate(&root, &conflict).expect_err("conflict drift must fail");
    assert!(
        error.contains("conflict row hash"),
        "unexpected error: {error}"
    );

    let mut journey = original.clone();
    journey.artifact["journey_migration_contract"]["usage_coverage"]["public_journey_edge_sha256"] =
        Value::String("0".repeat(64));
    let error = validate(&root, &journey).expect_err("journey edge drift must fail");
    assert!(
        error.contains("recorded public edge hash"),
        "unexpected error: {error}"
    );

    let mut handoff = original.clone();
    handoff.artifact["journey_migration_contract"]["ordered_handoffs"][6]["owner"] =
        Value::String(BEAD_ID.to_owned());
    let error = validate(&root, &handoff).expect_err("handoff drift must fail");
    assert!(
        error.contains("handoff row hash"),
        "unexpected error: {error}"
    );

    let mut boundary = original;
    boundary.artifact["no_claim_boundaries"][0] = Value::String("claim widened".to_owned());
    let error = validate(&root, &boundary).expect_err("no-claim drift must fail");
    assert!(error.contains("no-claim hash"), "unexpected error: {error}");
}
