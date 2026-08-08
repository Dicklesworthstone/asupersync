use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/kafka_k1_aggregate_evidence_gate_v1.json";
const DOCUMENT_PATH: &str = "docs/kafka_k1_aggregate_evidence_gate.md";
const MARKER_START: &str = "<!-- KAFKA_K1_5_AGGREGATE_EVIDENCE_GATE_V1:START -->";
const MARKER_END: &str = "<!-- KAFKA_K1_5_AGGREGATE_EVIDENCE_GATE_V1:END -->";

const CHILDREN: [(&str, &str); 4] = [
    ("K1.1", "artifacts/kafka_k1_obligation_index_v1.json"),
    (
        "K1.2",
        "artifacts/kafka_k1_protocol_security_support_policy_v1.json",
    ),
    ("K1.3", "artifacts/kafka_k1_public_api_contract_v1.json"),
    (
        "K1.4",
        "artifacts/kafka_k1_resource_lifecycle_contract_v1.json",
    ),
];

const DIRECT_INPUTS: [(&str, &str, &str, &str); 12] = [
    (
        "K1-5-INPUT-K1-1-ARTIFACT",
        "K1.1",
        "AUTHORITY_NAMESPACE_AND_OBLIGATION_PACKET",
        "artifacts/kafka_k1_obligation_index_v1.json",
    ),
    (
        "K1-5-INPUT-K1-1-DOCUMENT",
        "K1.1",
        "AUTHORITY_NAMESPACE_OPERATOR_DOCUMENT",
        "docs/kafka_k1_client_contract.md",
    ),
    (
        "K1-5-INPUT-K1-1-CONTRACT",
        "K1.1",
        "AUTHORITY_NAMESPACE_STATIC_CONTRACT_SOURCE",
        "tests/kafka_k1_client_contract.rs",
    ),
    (
        "K1-5-INPUT-K1-2-ARTIFACT",
        "K1.2",
        "PROTOCOL_SECURITY_AND_SUPPORT_PACKET",
        "artifacts/kafka_k1_protocol_security_support_policy_v1.json",
    ),
    (
        "K1-5-INPUT-K1-2-DOCUMENT",
        "K1.2",
        "PROTOCOL_SECURITY_OPERATOR_DOCUMENT",
        "docs/kafka_k1_protocol_security_support_policy.md",
    ),
    (
        "K1-5-INPUT-K1-2-CONTRACT",
        "K1.2",
        "PROTOCOL_SECURITY_STATIC_CONTRACT_SOURCE",
        "tests/kafka_k1_protocol_security_support_policy_contract.rs",
    ),
    (
        "K1-5-INPUT-K1-3-ARTIFACT",
        "K1.3",
        "PUBLIC_API_CONFIGURATION_ERROR_AND_MIGRATION_PACKET",
        "artifacts/kafka_k1_public_api_contract_v1.json",
    ),
    (
        "K1-5-INPUT-K1-3-DOCUMENT",
        "K1.3",
        "PUBLIC_API_OPERATOR_DOCUMENT",
        "docs/kafka_k1_public_api_contract.md",
    ),
    (
        "K1-5-INPUT-K1-3-CONTRACT",
        "K1.3",
        "PUBLIC_API_STATIC_CONTRACT_SOURCE",
        "tests/kafka_k1_public_api_contract.rs",
    ),
    (
        "K1-5-INPUT-K1-4-ARTIFACT",
        "K1.4",
        "RESOURCE_AND_LIFECYCLE_PACKET",
        "artifacts/kafka_k1_resource_lifecycle_contract_v1.json",
    ),
    (
        "K1-5-INPUT-K1-4-DOCUMENT",
        "K1.4",
        "RESOURCE_AND_LIFECYCLE_OPERATOR_DOCUMENT",
        "docs/kafka_k1_resource_lifecycle_contract.md",
    ),
    (
        "K1-5-INPUT-K1-4-CONTRACT",
        "K1.4",
        "RESOURCE_AND_LIFECYCLE_STATIC_CONTRACT_SOURCE",
        "tests/kafka_k1_resource_lifecycle_contract.rs",
    ),
];

const CHILD_RECEIPTS: [(&str, &str, &str, &str, &str); 4] = [
    (
        "K1.1",
        "artifacts/kafka_k1_obligation_index_v1.json",
        "8e6987a20",
        "ACCEPTED_STATIC_AUTHORITY",
        "k1_1_contract_complete",
    ),
    (
        "K1.2",
        "artifacts/kafka_k1_protocol_security_support_policy_v1.json",
        "82468f2d3",
        "ACCEPTED_STATIC_POLICY",
        "k1_2_policy_complete",
    ),
    (
        "K1.3",
        "artifacts/kafka_k1_public_api_contract_v1.json",
        "b09a2670f",
        "ACCEPTED_STATIC_API_CONTRACT",
        "k1_3_contract_complete",
    ),
    (
        "K1.4",
        "artifacts/kafka_k1_resource_lifecycle_contract_v1.json",
        "4290cb3e3",
        "ACCEPTED_STATIC_RESOURCE_CONTRACT",
        "k1_4_static_contract_complete",
    ),
];

const K0_1_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const K0_2_PATH: &str = "artifacts/kafka_incumbent_semantics_matrix_v1.json";
const K0_4_PATH: &str = "artifacts/kafka_broker_fixture_provenance_matrix_v1.json";
const HISTORICAL_ROW_TYPING_SHA256: &str =
    "ce317ee496fa450c1676161c21eeb0221041e502450d211504fbcfb333ca7a01";
const NO_CLAIM_BOUNDARY_SHA256: &str =
    "5c626eb148630a40e1c003fa94e2296fbdb89a05fc0014b745a565e99b2ae1bb";
const VECTOR_CATEGORY_MAPPING_SHA256: &str =
    "180bb499a516f563cea8367a3e4b28e0fc74d19373b01e61dc0c3a399e3555e2";
const SOURCE_PROFILE_MAPPING_SHA256: &str =
    "4bc88aad41381aa47eb2962f8f270399e0dfd3b2f3af2835459835c859a5d90e";
const SHADOW_OPERATION_ID_SHA256: &str =
    "01a40fb40520c2ee2016e0b6c51ca9083fd6cb019bbb369d28e86fca73f88eed";
const SHADOW_OPERATIONAL_SUBTYPE_SHA256: &str =
    "a3bc7018bb1f69beac51f09685644976a422d4e7cc94a859faf725e308bb06b1";
const SHADOW_CLASS_MAPPING_SHA256: &str =
    "8c2562a4b3b09ca575b7e5a4163725dfc6a99bf12553bf84317020fec673c4ac";

const PROJECTION_SCOPES: [(&str, &str, &str); 17] = [
    (
        "authority_input_projection_sha256",
        "/authority_inputs",
        "ROW_SET_V1",
    ),
    (
        "child_receipt_projection_sha256",
        "/child_packet_receipts",
        "ROW_SET_V1",
    ),
    (
        "lineage_conflict_projection_sha256",
        "/lineage_and_conflict_ledger",
        "VALUE_V1",
    ),
    (
        "obligation_partition_projection_sha256",
        "/cross_child_join_model/obligation_partitions",
        "ROW_SET_V1",
    ),
    (
        "semantic_resource_lifecycle_join_projection_sha256",
        "/cross_child_join_model/k1_3_k1_4_semantic_resource_lifecycle_join",
        "VALUE_V1",
    ),
    (
        "semantic_binding_adjudication_projection_sha256",
        "/semantic_binding_adjudication",
        "VALUE_V1",
    ),
    (
        "capability_evidence_contract_projection_sha256",
        "/capability_evidence_contract",
        "VALUE_V1",
    ),
    (
        "capability_route_projection_sha256",
        "/capability_routes",
        "ROW_SET_V1",
    ),
    (
        "feature_coexistence_mode_projection_sha256",
        "/feature_coexistence_modes",
        "ROW_SET_V1",
    ),
    (
        "feature_profile_projection_sha256",
        "/feature_profile_contract",
        "VALUE_V1",
    ),
    (
        "shadow_class_projection_sha256",
        "/shadow_classes",
        "ROW_SET_V1",
    ),
    (
        "shadow_policy_summary_projection_sha256",
        "/shadow_operations",
        "ROW_SET_V1",
    ),
    (
        "shadow_semantic_partition_projection_sha256",
        "/shadow_semantic_operation_partition",
        "VALUE_V1",
    ),
    (
        "stop_condition_projection_sha256",
        "/stop_conditions",
        "ROW_SET_V1",
    ),
    (
        "rollback_contract_projection_sha256",
        "/rollback_contract",
        "VALUE_V1",
    ),
    (
        "approval_projection_sha256",
        "/approval_gates",
        "ROW_SET_V1",
    ),
    (
        "no_claim_boundary_sha256",
        "/no_claim_boundaries",
        "STRING_SET_V1",
    ),
];

struct Inputs {
    root: PathBuf,
    artifact: Value,
    children: BTreeMap<&'static str, Value>,
    k0_1: Value,
    k0_2: Value,
    k0_4: Value,
}

impl Inputs {
    fn load() -> Result<Self, String> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let artifact = load_json(&root, ARTIFACT_PATH)?;
        let children = CHILDREN
            .iter()
            .map(|(stage, path)| Ok((*stage, load_json(&root, path)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        Ok(Self {
            root: root.clone(),
            artifact,
            children,
            k0_1: load_json(&root, K0_1_PATH)?,
            k0_2: load_json(&root, K0_2_PATH)?,
            k0_4: load_json(&root, K0_4_PATH)?,
        })
    }
}

fn load_json(root: &Path, relative: &str) -> Result<Value, String> {
    let bytes = fs::read(root.join(relative))
        .map_err(|error| format!("failed to read {relative}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid JSON in {relative}: {error}"))
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
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("{key} must be non-empty text"))
}

fn count(value: &Value, key: &str) -> Result<usize, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("{key} must be an unsigned count"))
}

fn flag(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be boolean"))
}

fn ids(rows: &[Value], key: &str) -> Result<Vec<String>, String> {
    rows.iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect()
}

fn string_set(rows: &[Value], label: &str) -> Result<BTreeSet<String>, String> {
    let values = rows
        .iter()
        .map(|row| {
            row.as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} contains non-text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure_unique(&values, label)?;
    Ok(values.into_iter().collect())
}

fn ensure_unique(values: &[String], label: &str) -> Result<(), String> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{label} contains duplicates"));
    }
    Ok(())
}

fn expect_set(actual: &[Value], expected: &[&str], label: &str) -> Result<(), String> {
    let actual = string_set(actual, label)?;
    let expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{label} drift: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sorted_newline_sha256(mut rows: Vec<String>) -> String {
    rows.sort();
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
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = Map::new();
            for (key, nested) in entries {
                canonical.insert(key.clone(), canonicalize(nested));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(&canonicalize(value))
        .map_err(|error| format!("canonical JSON failed: {error}"))
}

fn canonical_rows_sha256(rows: &[Value]) -> Result<String, String> {
    let canonical = rows
        .iter()
        .map(canonical_json)
        .collect::<Result<Vec<_>, _>>()?;
    ensure_unique(&canonical, "canonical projection rows")?;
    Ok(sorted_newline_sha256(canonical))
}

fn canonical_value_sha256(value: &Value) -> Result<String, String> {
    Ok(sorted_newline_sha256(vec![canonical_json(value)?]))
}

fn validate_file_pin(root: &Path, row: &Value) -> Result<(), String> {
    let path = text(row, "path")?;
    let bytes =
        fs::read(root.join(path)).map_err(|error| format!("failed to read {path}: {error}"))?;
    let content =
        std::str::from_utf8(&bytes).map_err(|error| format!("{path} is not UTF-8: {error}"))?;
    if bytes.len() != count(row, "byte_count")?
        || content.lines().count() != count(row, "record_count")?
        || sha256(&bytes) != text(row, "sha256")?
    {
        return Err(format!("exact input pin drift for {path}"));
    }
    Ok(())
}

fn validate_identity_and_inputs(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    if count(artifact, "schema_version")? != 1
        || text(artifact, "artifact_id")? != "kafka-k1-aggregate-evidence-gate-v1"
        || text(artifact, "program_id")? != "asupersync-ir2uf0"
        || text(artifact, "bead_id")? != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
        || text(artifact, "capability_id")? != "CAP-KAFKA"
        || text(artifact, "adr_id")? != "DEP-ADR-009"
    {
        return Err("root identity drift".to_owned());
    }
    let authority = &artifact["authority"];
    if text(authority, "registry_disposition")? != "KEEP_UNTIL_PARITY"
        || text(authority, "current_action")? != "KEEP_INCUMBENT"
        || text(authority, "aggregate_contract_owner")?
            != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
        || text(authority, "sole_conditional_cutover_owner")?
            != "asupersync-dep-p7-kafka-removal-sarszu.2.15"
    {
        return Err("root authority identity drift".to_owned());
    }
    for key in [
        "dependency_exit_allowed",
        "feature_removal_allowed",
        "api_removal_allowed",
        "capability_removal_allowed",
        "file_deletion_allowed",
        "production_wiring_allowed",
        "shadow_execution_allowed",
        "oracle_retirement_allowed",
        "cutover_allowed",
    ] {
        if flag(authority, key)? {
            return Err(format!("root authority unexpectedly enables {key}"));
        }
    }
    let authority_inputs = array(artifact, "authority_inputs")?;
    if authority_inputs.len() != 12 {
        return Err("K1.5 must pin exactly 12 direct inputs".to_owned());
    }
    let input_ids = ids(authority_inputs, "input_id")?;
    ensure_unique(&input_ids, "K1.5 input IDs")?;
    for (input_id, stage, role, path) in DIRECT_INPUTS {
        let row = authority_inputs
            .iter()
            .find(|row| row.get("input_id").and_then(Value::as_str) == Some(input_id))
            .ok_or_else(|| format!("missing exact direct input {input_id}"))?;
        if text(row, "stage")? != stage || text(row, "role")? != role || text(row, "path")? != path
        {
            return Err(format!("direct input identity drift: {input_id}"));
        }
    }
    for row in authority_inputs {
        validate_file_pin(&inputs.root, row)?;
    }

    let receipts = array(artifact, "child_packet_receipts")?;
    if receipts.len() != 4 {
        return Err("K1.5 must contain four child receipts".to_owned());
    }
    for (stage, artifact_path, content_commit, static_state, completion_field) in CHILD_RECEIPTS {
        let child = &inputs.children[stage];
        let receipt = receipts
            .iter()
            .find(|row| row.get("stage").and_then(Value::as_str) == Some(stage))
            .ok_or_else(|| format!("missing {stage} child receipt"))?;
        if text(receipt, "artifact_id")? != text(child, "artifact_id")?
            || text(receipt, "bead_id")? != text(child, "bead_id")?
            || text(receipt, "artifact_path")? != artifact_path
            || text(receipt, "content_commit")? != content_commit
            || text(receipt, "required_tracker_status")? != "closed"
            || text(receipt, "static_contract_state")? != static_state
            || !flag(&child["disposition_receipt"], completion_field)?
        {
            return Err(format!("{stage} child identity/state drift"));
        }
    }

    let tracker = fs::read_to_string(inputs.root.join(".beads/issues.jsonl"))
        .map_err(|error| format!("failed to read tracker: {error}"))?;
    for receipt in receipts {
        let bead_id = text(receipt, "bead_id")?;
        let mut status = None;
        for line in tracker.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line)
                .map_err(|error| format!("invalid tracker JSONL: {error}"))?;
            if row.get("id").and_then(Value::as_str) == Some(bead_id) {
                status = row.get("status").and_then(Value::as_str).map(str::to_owned);
            }
        }
        if status.as_deref() != Some("closed") {
            return Err(format!("child tracker state is not closed: {bead_id}"));
        }
    }

    let mut nested_rows = 0usize;
    let mut by_path = BTreeMap::<String, BTreeSet<String>>::new();
    for child in inputs.children.values() {
        for row in array(child, "authority_inputs")? {
            nested_rows += 1;
            by_path
                .entry(text(row, "path")?.to_owned())
                .or_default()
                .insert(text(row, "sha256")?.to_owned());
        }
    }
    let repeated = by_path.values().filter(|hashes| hashes.len() == 1).count();
    let shared = {
        let mut counts = BTreeMap::<String, usize>::new();
        for child in inputs.children.values() {
            for row in array(child, "authority_inputs")? {
                *counts.entry(text(row, "path")?.to_owned()).or_default() += 1;
            }
        }
        counts.values().filter(|count| **count > 1).count()
    };
    if nested_rows != 51
        || by_path.len() != 24
        || shared != 13
        || repeated != 24
        || by_path.values().any(|hashes| hashes.len() != 1)
    {
        return Err("shared child input consistency drift".to_owned());
    }
    let receipt = &artifact["cross_child_join_model"]["shared_child_input_consistency"];
    if count(receipt, "child_input_row_count")? != nested_rows
        || count(receipt, "unique_path_count")? != by_path.len()
        || count(receipt, "shared_path_count")? != shared
        || count(receipt, "conflicting_path_count")? != 0
    {
        return Err("shared-input receipt drift".to_owned());
    }
    Ok(())
}

fn validate_conflicts_and_obligations(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let ledger = &artifact["lineage_and_conflict_ledger"];
    let rows = array(ledger, "rows")?;
    if rows.len() != 4
        || count(ledger, "observed_cross_child_reconciliation_conflict_count")? != 4
        || count(
            ledger,
            "unresolved_cross_child_reconciliation_conflict_count",
        )? != 0
        || count(ledger, "preserved_child_blocker_count")? != 5
        || flag(ledger, "identity_consistency_claimed")?
    {
        return Err("lineage/conflict ledger count drift".to_owned());
    }
    let migration_blockers = rows
        .iter()
        .filter(|row| row.get("blocks_migration").and_then(Value::as_bool) == Some(true))
        .count();
    if migration_blockers != 2 || count(ledger, "migration_blocking_reconciliation_row_count")? != 2
    {
        return Err("migration-blocking reconciliation count drift".to_owned());
    }
    let expected_conflicts = BTreeMap::from([
        (
            "K1-5-CONFLICT-001-PROGRAM-LABEL",
            (
                "child program_id variance",
                "CHILD_METADATA_VARIANCE_RETAINED_FOR_KEEP_ONLY_GATE",
                true,
            ),
        ),
        (
            "K1-5-CONFLICT-002-SIBLING-PIN",
            (
                "K1.2 hidden selected-sibling authority edge",
                "REDUNDANT_UNDECLARED_SIBLING_BYTE_PIN",
                false,
            ),
        ),
        (
            "K1-5-CONFLICT-003-COARSE-BINDINGS",
            (
                "K1.2 FETCH, GROUP, and OFFSETS authority-row joins",
                "CORRECTED_BY_K1_5_TYPED_SEMANTIC_OVERLAY",
                false,
            ),
        ),
        (
            "K1-5-CONFLICT-004-HISTORICAL-SNAPSHOTS",
            (
                "child-local completion snapshots and preserved K1.3 authority conflicts",
                "PRESERVE_CHILD_LOCAL_HISTORY_AND_DOWNSTREAM_BLOCKERS",
                true,
            ),
        ),
    ]);
    let conflict_ids = ids(rows, "conflict_id")?;
    ensure_unique(&conflict_ids, "cross-child conflict IDs")?;
    for row in rows {
        let conflict_id = text(row, "conflict_id")?;
        let (subject, resolution, blocks_migration) = expected_conflicts
            .get(conflict_id)
            .ok_or_else(|| format!("unexpected cross-child conflict {conflict_id}"))?;
        if text(row, "subject")? != *subject
            || text(row, "resolution")? != *resolution
            || flag(row, "blocks_migration")? != *blocks_migration
            || flag(row, "blocks_static_aggregation_after_adjudication")?
        {
            return Err(format!("cross-child conflict drift: {conflict_id}"));
        }
    }
    let sibling_pin = rows
        .iter()
        .find(|row| {
            row.get("conflict_id").and_then(Value::as_str) == Some("K1-5-CONFLICT-002-SIBLING-PIN")
        })
        .ok_or_else(|| "missing sibling-pin conflict".to_owned())?;
    if count(sibling_pin, "semantic_reference_count")? != 0
        || flag(sibling_pin, "completion_authority")?
    {
        return Err("sibling pin acquired semantic or completion authority".to_owned());
    }
    let source_owner = &ledger["source_owner_reconciliation"];
    if text(source_owner, "historical_gap_id")? != "KFK-GAP-01"
        || text(source_owner, "historical_gap_state")? != "RESOLVED_BY_K0_1"
        || !flag(source_owner, "consumer_source_present")?
    {
        return Err("CAP-KAFKA source-owner reconciliation drift".to_owned());
    }
    expect_set(
        array(source_owner, "current_registry_source_owners")?,
        &[
            "Cargo.toml",
            "src/messaging/kafka.rs",
            "src/messaging/kafka_consumer.rs",
        ],
        "CAP-KAFKA source owners",
    )?;
    let child_conflicts = &inputs.children["K1.3"]["authority_conflicts"];
    let expected_blockers = array(child_conflicts, "rows")?;
    let preserved = array(ledger, "preserved_child_blockers")?;
    if expected_blockers.len() != 5 || preserved.len() != 5 {
        return Err("K1.3 blocker count drift".to_owned());
    }
    for child_row in expected_blockers {
        let id = text(child_row, "conflict_id")?;
        let aggregate = preserved
            .iter()
            .find(|row| row.get("conflict_id").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| format!("missing preserved K1.3 blocker {id}"))?;
        if text(aggregate, "subject")? != text(child_row, "subject")?
            || text(aggregate, "gate_state")? != text(child_row, "gate_state")?
            || string_set(array(aggregate, "owners")?, "aggregate blocker owners")?
                != string_set(array(child_row, "owners")?, "child blocker owners")?
        {
            return Err(format!("preserved blocker drift: {id}"));
        }
    }

    let join = &artifact["cross_child_join_model"];
    let expected_counts = BTreeMap::from([
        ("public_symbols", 30usize),
        ("semantic_rows", 97),
        ("shared_semantic_keys", 12),
        ("explicit_absences", 2),
        ("downstream_journeys", 15),
        ("fixture_vectors", 36),
        ("routed_gaps_and_findings", 87),
    ]);
    let mut actual_counts = BTreeMap::new();
    for row in array(join, "obligation_partitions")? {
        if actual_counts
            .insert(text(row, "domain")?, count(row, "row_count")?)
            .is_some()
        {
            return Err("duplicate obligation partition".to_owned());
        }
    }
    if actual_counts != expected_counts || actual_counts.values().sum::<usize>() != 279 {
        return Err("279-row obligation partition drift".to_owned());
    }

    let shared_authority = array(
        &inputs.children["K1.1"]["namespace_projection"]["derived_shared_obligations"],
        "rows",
    )?;
    let expected_shared = ids(shared_authority, "obligation_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let shared_split = array(join, "shared_semantic_policy_split")?;
    let expected_split = [
        (
            "K1.2",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.2",
            &["KAFKA-K1-SHARED-009", "KAFKA-K1-SHARED-011"] as &[&str],
        ),
        (
            "K1.3",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.3",
            &[
                "KAFKA-K1-SHARED-001",
                "KAFKA-K1-SHARED-002",
                "KAFKA-K1-SHARED-004",
                "KAFKA-K1-SHARED-005",
                "KAFKA-K1-SHARED-006",
                "KAFKA-K1-SHARED-007",
                "KAFKA-K1-SHARED-008",
            ],
        ),
        (
            "K1.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.1.4",
            &[
                "KAFKA-K1-SHARED-003",
                "KAFKA-K1-SHARED-010",
                "KAFKA-K1-SHARED-012",
            ],
        ),
    ];
    let mut split = Vec::new();
    for (stage, owner, expected_ids) in expected_split {
        let row = shared_split
            .iter()
            .find(|row| row.get("policy_stage").and_then(Value::as_str) == Some(stage))
            .ok_or_else(|| format!("missing shared policy split for {stage}"))?;
        if text(row, "policy_owner")? != owner || count(row, "row_count")? != expected_ids.len() {
            return Err(format!("shared policy owner/count drift for {stage}"));
        }
        expect_set(
            array(row, "obligation_ids")?,
            expected_ids,
            "shared policy split IDs",
        )?;
        let row_ids = string_set(array(row, "obligation_ids")?, "shared split IDs")?;
        split.extend(row_ids);
    }
    ensure_unique(&split, "shared policy split IDs")?;
    if shared_split.len() != 3 || split.into_iter().collect::<BTreeSet<_>>() != expected_shared {
        return Err("2/7/3 shared policy split drift".to_owned());
    }
    Ok(())
}

fn validate_semantic_resource_join(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let coverage = &inputs.children["K1.4"]["semantic_coverage"];
    let classifications = array(coverage, "classifications")?;
    let mut counts = BTreeMap::new();
    let mut all_ids = Vec::new();
    for row in classifications {
        let row_ids = string_set(array(row, "semantic_ids")?, "semantic classification IDs")?;
        counts.insert(text(row, "classification")?, row_ids.len());
        all_ids.extend(row_ids);
    }
    ensure_unique(&all_ids, "classified semantic IDs")?;
    if counts
        != BTreeMap::from([
            ("RESOURCE", 43usize),
            ("RESOURCE_AND_LIFECYCLE", 26),
            ("CONTEXT_ONLY_NOT_A_DISTINCT_LONG_LIVED_OPERATION", 28),
        ])
        || all_ids.len() != 97
    {
        return Err("97-to-43/26/28 semantic classification drift".to_owned());
    }
    let receipt = &artifact["cross_child_join_model"]["k1_3_k1_4_semantic_resource_lifecycle_join"];
    let semantic_id_sha256 = sorted_newline_sha256(all_ids.clone());
    let classification_sha256 = canonical_rows_sha256(classifications)?;
    if semantic_id_sha256
        != text(
            &inputs.children["K1.3"]["semantic_contract"],
            "semantic_id_set_sha256",
        )?
        || count(
            &inputs.children["K1.3"]["semantic_contract"],
            "semantic_row_count",
        )? != all_ids.len()
        || classification_sha256 != text(coverage, "classification_projection_sha256")?
        || classification_sha256 != text(receipt, "classification_projection_sha256")?
        || count(coverage, "classified_row_count")? != all_ids.len()
        || count(coverage, "unclassified_row_count")? != 0
        || count(coverage, "duplicate_classification_count")? != 0
    {
        return Err("semantic authority/classification projection drift".to_owned());
    }

    let mut config_edges = Vec::new();
    let resource_bindings = array(&inputs.children["K1.4"], "semantic_resource_bindings")?;
    let resource_binding_sha256 = canonical_rows_sha256(resource_bindings)?;
    if resource_bindings.len() != 43
        || count(receipt, "resource_semantic_binding_count")? != resource_bindings.len()
        || text(receipt, "resource_semantic_binding_sha256")? != resource_binding_sha256
    {
        return Err("resource semantic binding receipt drift".to_owned());
    }
    for row in resource_bindings {
        let semantic = text(row, "semantic_id")?;
        for resource in array(row, "resource_ids")? {
            let resource = resource
                .as_str()
                .ok_or_else(|| "resource ID must be text".to_owned())?;
            config_edges.push(format!("{semantic}\t{resource}"));
        }
    }
    ensure_unique(&config_edges, "config-resource edges")?;
    let config_edge_sha256 = sorted_newline_sha256(config_edges.clone());
    if config_edges.len() != 61
        || config_edge_sha256 != "9f790461b8d57091300ca27366a9759f7462e0064a1277df21d4e18a7d8ca6f3"
        || text(receipt, "config_to_resource_edge_sha256")? != config_edge_sha256
    {
        return Err("config-resource expanded edge drift".to_owned());
    }

    let lifecycle_ids = classifications
        .iter()
        .find(|row| {
            row.get("classification").and_then(Value::as_str) == Some("RESOURCE_AND_LIFECYCLE")
        })
        .ok_or_else(|| "missing lifecycle semantic class".to_owned())
        .and_then(|row| string_set(array(row, "semantic_ids")?, "lifecycle semantic IDs"))?;
    let context_ids = classifications
        .iter()
        .find(|row| {
            row.get("classification").and_then(Value::as_str)
                == Some("CONTEXT_ONLY_NOT_A_DISTINCT_LONG_LIVED_OPERATION")
        })
        .ok_or_else(|| "missing context semantic class".to_owned())
        .and_then(|row| string_set(array(row, "semantic_ids")?, "context semantic IDs"))?;
    let mut lifecycle_edges = Vec::new();
    let mut seen_lifecycle = BTreeSet::new();
    let mut context_refs = 0usize;
    for (kind, rows, id_key) in [
        (
            "resource",
            array(&inputs.children["K1.4"], "resource_classes")?,
            "resource_id",
        ),
        (
            "lifecycle",
            array(&inputs.children["K1.4"], "lifecycle_operations")?,
            "operation_id",
        ),
    ] {
        for row in rows {
            let target = text(row, id_key)?;
            for source in array(row, "source_authority_ids")? {
                let source = source
                    .as_str()
                    .ok_or_else(|| "source authority ID must be text".to_owned())?;
                if lifecycle_ids.contains(source) {
                    seen_lifecycle.insert(source.to_owned());
                    lifecycle_edges.push(format!("{source}\t{kind}\t{target}"));
                }
                if context_ids.contains(source) {
                    context_refs += 1;
                }
            }
        }
    }
    ensure_unique(&lifecycle_edges, "lifecycle semantic target edges")?;
    let lifecycle_edge_sha256 = sorted_newline_sha256(lifecycle_edges.clone());
    if seen_lifecycle != lifecycle_ids
        || lifecycle_edges.len() != 119
        || context_refs != 0
        || lifecycle_edge_sha256
            != "16774cada71f64fe1d8b55519f219eddd98d58c6a7f7039d0805e8bc2c486874"
        || text(receipt, "lifecycle_semantic_target_edge_sha256")? != lifecycle_edge_sha256
    {
        return Err("lifecycle semantic target edge drift".to_owned());
    }
    if count(receipt, "semantic_row_count")? != 97
        || object(receipt, "classification_counts")?
            != &Map::from_iter([
                ("RESOURCE".to_owned(), Value::from(43)),
                ("RESOURCE_AND_LIFECYCLE".to_owned(), Value::from(26)),
                (
                    "CONTEXT_ONLY_NOT_A_DISTINCT_LONG_LIVED_OPERATION".to_owned(),
                    Value::from(28),
                ),
            ])
        || count(receipt, "missing_semantic_count")? != 0
        || count(receipt, "duplicate_semantic_count")? != 0
        || count(receipt, "config_to_resource_edge_count")? != 61
        || count(receipt, "lifecycle_semantic_target_edge_count")? != 119
        || count(
            receipt,
            "context_direct_resource_or_lifecycle_reference_count",
        )? != 0
        || text(receipt, "join_state")? != "EXACT_DISJOINT_EXHAUSTIVE_STATIC_JOIN"
    {
        return Err("semantic-resource-lifecycle receipt drift".to_owned());
    }
    Ok(())
}

fn overlay_set(overlay: &Value, key: &str, expected: &[&str]) -> Result<(), String> {
    expect_set(array(overlay, key)?, expected, key)
}

fn validate_bindings(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let adjudication = &artifact["semantic_binding_adjudication"];
    let allowed = object(
        &inputs.children["K1.1"]["protocol_binding_model"],
        "allowed_kinds",
    )?
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
    if allowed
        != BTreeSet::from([
            "ABSENT_GAP".to_owned(),
            "CONFIG_MAPPING".to_owned(),
            "INVENTORY_ONLY".to_owned(),
            "LOCAL_ONLY".to_owned(),
            "MESSAGE_SET".to_owned(),
            "REFERENCE_ONLY".to_owned(),
        ])
        || string_set(
            array(adjudication, "allowed_binding_kinds")?,
            "allowed binding kinds",
        )? != allowed
    {
        return Err("binding kind allowset drift".to_owned());
    }
    let child_groups = array(&inputs.children["K1.2"], "protocol_binding_groups")?;
    let typed_groups = array(adjudication, "historical_row_typing")?;
    if child_groups.len() != 10 || typed_groups.len() != 10 {
        return Err("all ten binding groups must be row-typed".to_owned());
    }
    let mut typed_edge_count = 0usize;
    let mut typed_projection_rows = Vec::new();
    for group in child_groups {
        let binding = text(group, "cell_id")?;
        let typed = typed_groups
            .iter()
            .find(|row| row.get("binding_ref").and_then(Value::as_str) == Some(binding))
            .ok_or_else(|| format!("missing row typing for {binding}"))?;
        let historical = string_set(array(group, "authority_rows")?, "historical binding rows")?;
        let edges = array(typed, "typed_edges")?;
        typed_edge_count += edges.len();
        let edge_ids = ids(edges, "authority_row_id")?;
        ensure_unique(&edge_ids, "typed binding edge IDs")?;
        if edge_ids.into_iter().collect::<BTreeSet<_>>() != historical {
            return Err(format!("typed edge membership drift for {binding}"));
        }
        for edge in edges {
            if !allowed.contains(text(edge, "kind")?) {
                return Err(format!("unknown binding kind in {binding}"));
            }
            let id = text(edge, "authority_row_id")?;
            typed_projection_rows.push(format!("{binding}\t{id}\t{}", text(edge, "kind")?));
            if id.starts_with("KAFKA-ABS-") && text(edge, "kind")? != "ABSENT_GAP" {
                return Err(format!("explicit absence acquired a fake binding: {id}"));
            }
            if id == "KAFKA-K0-4-UNKNOWN-007" && text(edge, "kind")? != "INVENTORY_ONLY" {
                return Err("K0.4 unknown must remain inventory-only".to_owned());
            }
        }
    }
    if typed_edge_count != 52
        || count(adjudication, "historical_binding_group_count")? != child_groups.len()
        || count(adjudication, "row_typed_binding_group_count")? != typed_groups.len()
        || count(adjudication, "historical_row_typing_edge_count")? != typed_edge_count
        || sorted_newline_sha256(typed_projection_rows) != HISTORICAL_ROW_TYPING_SHA256
        || text(adjudication, "historical_row_typing_projection_sha256")?
            != HISTORICAL_ROW_TYPING_SHA256
    {
        return Err("52 historical row-typing edges drift".to_owned());
    }

    let overlays = array(adjudication, "overlays")?;
    if overlays.len() != 3 {
        return Err("exactly three membership overlays are required".to_owned());
    }
    let overlay_refs = ids(overlays, "binding_ref")?;
    ensure_unique(&overlay_refs, "membership overlay refs")?;
    if overlay_refs.into_iter().collect::<BTreeSet<_>>()
        != BTreeSet::from([
            "KAFKA-K1-2-BIND-004-FETCH".to_owned(),
            "KAFKA-K1-2-BIND-005-GROUP".to_owned(),
            "KAFKA-K1-2-BIND-006-OFFSETS".to_owned(),
        ])
    {
        return Err("membership overlay ref set drift".to_owned());
    }
    for overlay in overlays {
        let binding = text(overlay, "binding_ref")?;
        let child = child_groups
            .iter()
            .find(|row| row.get("cell_id").and_then(Value::as_str) == Some(binding))
            .ok_or_else(|| format!("overlay has unknown binding {binding}"))?;
        if string_set(
            array(overlay, "superseded_authority_rows")?,
            "superseded rows",
        )? != string_set(array(child, "authority_rows")?, "child authority rows")?
            || array(overlay, "message_names")? != array(child, "message_names")?
        {
            return Err(format!(
                "superseded membership or message-name drift for {binding}"
            ));
        }
        let mut categorized_rows = Vec::new();
        for key in [
            "message_set_rows",
            "config_mapping_rows",
            "local_only_rows",
            "inventory_only_rows",
            "reference_only_rows",
        ] {
            for row in array(overlay, key)? {
                categorized_rows.push(
                    row.as_str()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| format!("{binding} {key} contains non-text"))?
                        .to_owned(),
                );
            }
        }
        ensure_unique(&categorized_rows, &format!("{binding} typed overlay rows"))?;
        match binding {
            "KAFKA-K1-2-BIND-004-FETCH" => {
                overlay_set(overlay, "message_set_rows", &["KCO-OP-006"])?;
                overlay_set(overlay, "local_only_rows", &["KCO-OP-016"])?;
                overlay_set(
                    overlay,
                    "config_mapping_rows",
                    &[
                        "KCO-CFG-006",
                        "KCO-CFG-009",
                        "KCO-CFG-010",
                        "KCO-CFG-011",
                        "KCO-CFG-012",
                        "KCO-CFG-013",
                    ],
                )?;
                overlay_set(overlay, "inventory_only_rows", &[])?;
                overlay_set(
                    overlay,
                    "reference_only_rows",
                    &["KAFKA-ENUM-006", "KAFKA-ENUM-007"],
                )?;
            }
            "KAFKA-K1-2-BIND-005-GROUP" => {
                overlay_set(
                    overlay,
                    "message_set_rows",
                    &["KCO-OP-004", "KCO-OP-006", "KCO-OP-009"],
                )?;
                overlay_set(
                    overlay,
                    "config_mapping_rows",
                    &["KCO-CFG-002", "KCO-CFG-003", "KCO-CFG-004", "KCO-CFG-005"],
                )?;
                overlay_set(
                    overlay,
                    "local_only_rows",
                    &[
                        "KCO-OP-005",
                        "KCO-OP-011",
                        "KCO-OP-012",
                        "KCO-OP-013",
                        "KCO-OP-014",
                        "KCO-OP-017",
                        "KAFKA-K1-SHARED-002",
                    ],
                )?;
                overlay_set(overlay, "inventory_only_rows", &[])?;
                overlay_set(overlay, "reference_only_rows", &[])?;
            }
            "KAFKA-K1-2-BIND-006-OFFSETS" => {
                overlay_set(overlay, "message_set_rows", &["KCO-OP-006", "KCO-OP-007"])?;
                overlay_set(
                    overlay,
                    "config_mapping_rows",
                    &[
                        "KCO-CFG-002",
                        "KCO-CFG-005",
                        "KCO-CFG-006",
                        "KCO-CFG-007",
                        "KCO-CFG-008",
                        "KCO-CFG-016",
                        "KAFKA-K1-SHARED-001",
                        "KAFKA-K1-SHARED-006",
                    ],
                )?;
                overlay_set(
                    overlay,
                    "local_only_rows",
                    &["KCO-OP-002", "KCO-OP-008", "KCO-OP-015", "KCO-OP-016"],
                )?;
                overlay_set(overlay, "inventory_only_rows", &[])?;
                overlay_set(overlay, "reference_only_rows", &["KAFKA-ENUM-006"])?;
            }
            _ => return Err(format!("unexpected membership overlay {binding}")),
        }
    }
    let shared_support = array(adjudication, "shared_support_edges")?;
    if shared_support.len() != 1
        || text(&shared_support[0], "authority_row_id")? != "KCO-OP-003"
        || text(&shared_support[0], "kind")? != "CONFIG_MAPPING"
    {
        return Err("shared support edge identity drift".to_owned());
    }
    expect_set(
        array(&shared_support[0], "applies_to_binding_refs")?,
        &[
            "KAFKA-K1-2-BIND-004-FETCH",
            "KAFKA-K1-2-BIND-005-GROUP",
            "KAFKA-K1-2-BIND-006-OFFSETS",
        ],
        "shared support binding refs",
    )?;

    if count(adjudication, "membership_adjudicated_binding_group_count")? != overlays.len()
        || count(adjudication, "historical_membership_preserved_group_count")? != 7
        || count(adjudication, "observed_misjoined_group_count")? != 3
        || count(adjudication, "unresolved_misjoined_group_count")? != 0
        || count(adjudication, "zero_message_set_edge_group_count")? != 2
        || count(adjudication, "unresolved_zero_message_set_edge_group_count")? != 2
        || flag(adjudication, "per_message_attribution_complete")?
    {
        return Err("message-attribution boundary drift".to_owned());
    }
    let gaps = typed_groups
        .iter()
        .filter(|row| {
            row.get("message_names_attribution_state")
                .and_then(Value::as_str)
                == Some("BLOCKING_NO_DIRECT_MESSAGE_AUTHORITY_ROW")
        })
        .map(|row| text(row, "binding_ref").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if gaps
        != BTreeSet::from([
            "KAFKA-K1-2-BIND-007-METADATA".to_owned(),
            "KAFKA-K1-2-BIND-009-SASL".to_owned(),
        ])
    {
        return Err("zero-message-set group set drift".to_owned());
    }

    let absence_routes = array(adjudication, "absence_routes")?;
    if absence_routes.len() != 2 {
        return Err("two explicit absence routes are required".to_owned());
    }
    let absence_ids = ids(absence_routes, "authority_row_id")?;
    ensure_unique(&absence_ids, "absence route IDs")?;
    if absence_ids.into_iter().collect::<BTreeSet<_>>()
        != BTreeSet::from(["KAFKA-ABS-001".to_owned(), "KAFKA-ABS-002".to_owned()])
    {
        return Err("absence route ID set drift".to_owned());
    }
    let source_absences = array(
        &inputs.children["K1.3"]["explicit_absence_contract"],
        "rows",
    )?;
    for route in absence_routes {
        let id = text(route, "authority_row_id")?;
        let source = source_absences
            .iter()
            .find(|row| row.get("absence_id").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| format!("unknown absence route {id}"))?;
        if text(route, "kind")? != "ABSENT_GAP"
            || flag(route, "inherits_group_route")?
            || !array(route, "real_service_scenario_ids")?.is_empty()
            || text(route, "shipped_state")? != text(source, "shipped_state")?
            || text(route, "gate_state")? != text(source, "gate_state")?
            || text(route, "disposition_owner")? != text(source, "disposition_owner")?
            || text(route, "verification_owner")? != text(source, "verification_owner")?
        {
            return Err(format!("absence route widened or drifted: {id}"));
        }
        match id {
            "KAFKA-ABS-001" => {
                if text(route, "binding_ref")? != "KAFKA-K1-2-BIND-003-TRANSACTION"
                    || text(route, "implementation_owner")? != text(source, "implementation_owner")?
                    || route.get("api_contract_owner").is_some()
                {
                    return Err("KAFKA-ABS-001 owner route drift".to_owned());
                }
            }
            "KAFKA-ABS-002" => {
                if text(route, "binding_ref")? != "KAFKA-K1-2-BIND-010-LOCAL"
                    || text(route, "api_contract_owner")? != text(source, "api_contract_owner")?
                    || text(route, "implementation_owner_state")?
                        != text(source, "implementation_owner_state")?
                    || !route
                        .get("implementation_owner")
                        .is_some_and(Value::is_null)
                {
                    return Err("KAFKA-ABS-002 owner route drift".to_owned());
                }
            }
            _ => return Err(format!("unexpected absence route {id}")),
        }
    }
    let coverage = &artifact["coverage_receipt"];
    if count(coverage, "row_typed_binding_group_count")? != typed_groups.len()
        || count(coverage, "historical_binding_row_typing_edge_count")? != typed_edge_count
        || count(coverage, "membership_adjudicated_binding_group_count")? != overlays.len()
        || count(coverage, "zero_message_set_edge_group_count")? != gaps.len()
        || count(coverage, "absence_route_count")? != absence_routes.len()
        || count(coverage, "adjudicated_binding_group_count")? != overlays.len()
        || count(coverage, "unresolved_misjoined_binding_group_count")? != 0
        || count(coverage, "unresolved_zero_message_set_edge_group_count")? != gaps.len()
    {
        return Err("binding adjudication coverage receipt drift".to_owned());
    }
    Ok(())
}

fn all_k0_4_vectors(k0_4: &Value) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for key in [
        "locked_dependency_identity",
        "native_build_vectors",
        "broker_api_version_vectors",
        "compression_vectors",
        "transport_auth_vectors",
        "topology_vectors",
        "fault_lifecycle_vectors",
    ] {
        values.extend(ids(array(k0_4, key)?, "vector_id")?);
    }
    Ok(values)
}

fn validate_evidence_routes(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let contract = &artifact["capability_evidence_contract"];
    let namespace = &contract["accepted_evidence_namespace"];
    let authority_bytes = fs::read(inputs.root.join(K0_4_PATH))
        .map_err(|error| format!("failed to read K0.4 authority: {error}"))?;
    if authority_bytes.len() != count(namespace, "authority_byte_count")?
        || sha256(&authority_bytes) != text(namespace, "authority_sha256")?
    {
        return Err("K0.4 evidence authority pin drift".to_owned());
    }
    let authority_vectors = all_k0_4_vectors(&inputs.k0_4)?;
    ensure_unique(&authority_vectors, "K0.4 vector IDs")?;
    if authority_vectors.len() != 36
        || sorted_newline_sha256(authority_vectors.clone())
            != text(namespace, "executable_vector_id_set_sha256")?
    {
        return Err("36-vector authority drift".to_owned());
    }
    let class_ids = ids(
        array(contract, "evidence_vector_classes")?,
        "vector_class_id",
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let scenario_ids = ids(array(contract, "real_service_scenarios")?, "scenario_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut routed_vectors = Vec::new();
    let mut mapping_rows = Vec::new();
    for category in array(namespace, "category_routes")? {
        let category_id = text(category, "category_id")?;
        let vector_ids = string_set(array(category, "vector_ids")?, "category vector IDs")?;
        for vector_id in vector_ids {
            mapping_rows.push(format!("{vector_id}\t{category_id}"));
            routed_vectors.push(vector_id);
        }
        for class in string_set(
            array(category, "required_evidence_class_ids")?,
            "category evidence classes",
        )? {
            if !class_ids.contains(&class) {
                return Err(format!("unknown category evidence class {class}"));
            }
        }
        for scenario in string_set(
            array(category, "real_service_scenario_ids")?,
            "category scenarios",
        )? {
            if !scenario_ids.contains(&scenario) {
                return Err(format!("unknown category scenario {scenario}"));
            }
        }
        if array(category, "terminal_gates")?.is_empty() {
            return Err(format!("{category_id} has no terminal gates"));
        }
    }
    ensure_unique(&routed_vectors, "routed vector IDs")?;
    ensure_unique(&mapping_rows, "vector-category mapping rows")?;
    let vector_mapping_sha256 = sorted_newline_sha256(mapping_rows);
    let category_counts = &namespace["vector_category_counts"];
    let knowledge_counts = &namespace["knowledge_state_counts"];
    let execution_counts = &namespace["execution_state_counts"];
    if routed_vectors.into_iter().collect::<BTreeSet<_>>()
        != authority_vectors.into_iter().collect::<BTreeSet<_>>()
        || vector_mapping_sha256 != VECTOR_CATEGORY_MAPPING_SHA256
        || text(namespace, "vector_category_mapping_sha256")? != VECTOR_CATEGORY_MAPPING_SHA256
        || array(namespace, "category_routes")?.len() != 7
        || count(category_counts, "LOCKED_DEPENDENCY")? != 3
        || count(category_counts, "NATIVE_BUILD")? != 5
        || count(category_counts, "BROKER_API_VERSION")? != 7
        || count(category_counts, "COMPRESSION")? != 5
        || count(category_counts, "TRANSPORT_AUTH")? != 6
        || count(category_counts, "TOPOLOGY")? != 4
        || count(category_counts, "FAULT_LIFECYCLE")? != 6
        || count(knowledge_counts, "KNOWN")? != 13
        || count(knowledge_counts, "UNKNOWN")? != 12
        || count(knowledge_counts, "BLOCKED")? != 11
        || count(execution_counts, "NOT_RUN")? != 25
        || count(execution_counts, "BLOCKED")? != 11
        || count(namespace, "executed_vector_count")? != 0
    {
        return Err("exact vector routing drift".to_owned());
    }
    let inventory = &namespace["fixture_inventory_receipt"];
    for (key, rows_key, id_key, expected_count, expected_hash) in [
        (
            "fixture_count",
            "fixture_census",
            "fixture_id",
            67usize,
            "bb8f922cc63f97efcfb0c76a6e26fdf923775650af8cd613f50da55c95cbb376",
        ),
        (
            "fixture_profile_count",
            "fixture_classification_profiles",
            "classification_profile_id",
            8,
            "b1848945221e425d78007ee47bced23e62b700a5e43fc6a8300124d42c8d8d09",
        ),
        (
            "environment_count",
            "environment_identities",
            "environment_id",
            8,
            "372de832a4de112e3ee8bc45b3af978d749b24c3f825416bd8e8b2d4523d831e",
        ),
    ] {
        let inventory_ids = ids(array(&inputs.k0_4, rows_key)?, id_key)?;
        ensure_unique(&inventory_ids, rows_key)?;
        if count(inventory, key)? != expected_count
            || inventory_ids.len() != expected_count
            || sorted_newline_sha256(inventory_ids) != expected_hash
        {
            return Err(format!("{rows_key} inventory drift"));
        }
    }
    let source_gap = &inputs.children["K1.1"]["namespace_projection"]["route_ownership"];
    let gap = &namespace["routed_gap_receipt"];
    for (left, right) in [
        ("route_row_count", "route_row_count"),
        ("route_edge_count", "route_owner_edge_count"),
        ("owner_id_count", "owner_id_count"),
    ] {
        if count(source_gap, left)? != count(gap, right)? {
            return Err(format!("routed-gap count drift: {left}"));
        }
    }
    for (left, right) in [
        ("route_projection_sha256", "route_row_sha256"),
        ("route_edge_projection_sha256", "route_owner_edge_sha256"),
        ("owner_id_set_sha256", "owner_id_set_sha256"),
    ] {
        if text(source_gap, left)? != text(gap, right)? {
            return Err(format!("routed-gap digest drift: {left}"));
        }
    }

    let binding_refs = array(&inputs.children["K1.2"], "protocol_binding_groups")?
        .iter()
        .map(|row| text(row, "cell_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let state_owners = string_set(array(contract, "state_owners")?, "state owner registry")?;
    let route_gates = string_set(
        array(contract, "route_terminal_gates")?,
        "route terminal gates",
    )?;
    let routes = array(artifact, "capability_routes")?;
    let route_refs = routes
        .iter()
        .map(|row| text(row, "protocol_binding_ref").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if routes.len() != 10 || route_refs != binding_refs {
        return Err("ten-route protocol binding coverage drift".to_owned());
    }
    for route in routes {
        if !state_owners.contains(text(route, "state_owner")?) {
            return Err(format!(
                "unregistered route state owner: {}",
                text(route, "route_id")?
            ));
        }
        for field in ["unit_owner", "model_owner", "property_owner", "fuzz_owner"] {
            text(route, field)?;
        }
        let terminals = string_set(array(route, "terminal_gates")?, "route terminal gates")?;
        if !terminals.is_subset(&route_gates)
            || !terminals.contains("asupersync-dep-p7-kafka-removal-sarszu.2.12.5")
            || !terminals.contains("asupersync-dep-p7-kafka-removal-sarszu.2.13.6")
        {
            return Err(format!(
                "route terminal coverage drift: {}",
                text(route, "route_id")?
            ));
        }
        if array(route, "real_service_scenario_ids")?.is_empty()
            || array(route, "real_service_owners")?.is_empty()
        {
            return Err(format!(
                "route lacks real-service mapping: {}",
                text(route, "route_id")?
            ));
        }
        let state = text(route, "state_owner")?;
        let overlaps = ["unit_owner", "model_owner", "property_owner", "fuzz_owner"]
            .iter()
            .any(|field| route.get(*field).and_then(Value::as_str) == Some(state));
        if overlaps && text(route, "role_overlap_reason")?.starts_with("NONE_") {
            return Err(format!(
                "unexplained state-owner overlap: {}",
                text(route, "route_id")?
            ));
        }
    }
    Ok(())
}

fn validate_profiles_and_shadow(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let profiles = &artifact["feature_profile_contract"];
    let source_rows = array(&inputs.k0_1, "compilation_profiles")?;
    let source_ids = ids(source_rows, "profile_id")?;
    ensure_unique(&source_ids, "source compilation profile IDs")?;
    if source_ids.len() != 13
        || sorted_newline_sha256(source_ids.clone())
            != text(profiles, "source_compilation_profile_id_set_sha256")?
        || canonical_rows_sha256(source_rows)?
            != text(profiles, "source_compilation_profile_canonical_rows_sha256")?
        || profiles.get("native_feature_id") != Some(&Value::Null)
    {
        return Err("13-profile source authority drift".to_owned());
    }
    let policy_rows = array(profiles, "profiles")?;
    let mut mapped = Vec::new();
    let mut mapping = Vec::new();
    for row in policy_rows {
        let policy_id = text(row, "profile_id")?;
        for source in string_set(array(row, "source_profile_ids")?, "mapped source profiles")? {
            mapping.push(format!("{source}\t{policy_id}"));
            mapped.push(source);
        }
        if matches!(policy_id, "K1FP-FUTURE-NATIVE-ONLY" | "K1FP-FUTURE-BOTH")
            && !array(row, "source_profile_ids")?.is_empty()
        {
            return Err(format!(
                "unallocated native profile acquired source rows: {policy_id}"
            ));
        }
    }
    ensure_unique(&mapped, "13-to-policy profile memberships")?;
    ensure_unique(&mapping, "profile mapping rows")?;
    let profile_mapping_sha256 = sorted_newline_sha256(mapping);
    if mapped.into_iter().collect::<BTreeSet<_>>()
        != source_ids.into_iter().collect::<BTreeSet<_>>()
        || policy_rows.len() != 7
        || count(profiles, "profile_count")? != policy_rows.len()
        || count(profiles, "source_compilation_profile_count")? != 13
        || count(profiles, "missing_source_compilation_profile_count")? != 0
        || count(profiles, "duplicate_source_compilation_profile_count")? != 0
        || text(profiles, "native_feature_allocation_state")? != "UNALLOCATED_BLOCKING"
        || profile_mapping_sha256 != SOURCE_PROFILE_MAPPING_SHA256
        || text(profiles, "source_to_policy_profile_mapping_sha256")?
            != SOURCE_PROFILE_MAPPING_SHA256
        || policy_rows
            .iter()
            .any(|row| row.get("native_effects_allowed").and_then(Value::as_bool) != Some(false))
    {
        return Err("13-to-7 profile mapping drift".to_owned());
    }
    let wasm = policy_rows
        .iter()
        .find(|row| row.get("profile_id").and_then(Value::as_str) == Some("K1FP-WASM"))
        .ok_or_else(|| "missing wasm policy profile".to_owned())?;
    let wasm_states = array(wasm, "source_profile_expected_states")?;
    if wasm.get("production_allowed").and_then(Value::as_str) != Some("SOURCE_PROFILE_DEPENDENT")
        || wasm_states.len() != 2
        || !wasm_states.iter().any(|row| {
            row.get("source_profile_id").and_then(Value::as_str)
                == Some("KAFKA-PROFILE-WASM-NO-KAFKA")
                && row.get("surface_state").and_then(Value::as_str)
                    == Some("MESSAGING_MODULE_ABSENT")
                && row.get("backend_state").and_then(Value::as_str) == Some("NOT_APPLICABLE")
                && row.get("production_allowed").and_then(Value::as_bool) == Some(true)
        })
        || !wasm_states.iter().any(|row| {
            row.get("source_profile_id").and_then(Value::as_str)
                == Some("KAFKA-PROFILE-WASM-WITH-KAFKA")
                && row.get("surface_state").and_then(Value::as_str) == Some("HARD_COMPILE_ERROR")
                && row.get("backend_state").and_then(Value::as_str) == Some("NOT_APPLICABLE")
                && row.get("production_allowed").and_then(Value::as_bool) == Some(false)
        })
    {
        return Err("wasm hard-compile-error profile drift".to_owned());
    }
    let coexistence = array(artifact, "feature_coexistence_modes")?;
    let coexistence_ids = ids(coexistence, "mode_id")?;
    ensure_unique(&coexistence_ids, "coexistence mode IDs")?;
    if coexistence.len() != 5
        || coexistence
            .iter()
            .filter(|row| row.get("currently_allowed").and_then(Value::as_bool) == Some(true))
            .count()
            != 1
        || coexistence
            .iter()
            .any(|row| row.get("native_effects_allowed").and_then(Value::as_bool) != Some(false))
        || !coexistence.iter().any(|row| {
            row.get("mode_id").and_then(Value::as_str) == Some("K1C-INCUMBENT-ONLY")
                && row.get("currently_allowed").and_then(Value::as_bool) == Some(true)
        })
    {
        return Err("feature coexistence authorization drift".to_owned());
    }

    let shadow = &artifact["shadow_semantic_operation_partition"];
    let authority_ids = ids(array(&inputs.k0_2, "operations")?, "semantic_id")?;
    ensure_unique(&authority_ids, "K0.2 operation IDs")?;
    let classes = array(shadow, "classes")?;
    let mut subtype_ids = Vec::new();
    let mut subtype_mapping = Vec::new();
    let mut shadow_mapping = Vec::new();
    for class in classes {
        let subtype = text(class, "partition_class_id")?;
        let semantic_ids = string_set(array(class, "semantic_ids")?, "shadow subtype IDs")?;
        if semantic_ids.len() != count(class, "row_count")? {
            return Err(format!("shadow subtype count drift: {subtype}"));
        }
        for semantic in &semantic_ids {
            subtype_ids.push(semantic.clone());
            subtype_mapping.push(format!("{semantic}\t{subtype}"));
        }
        if let Some(subpartitions) = class
            .get("shadow_class_subpartitions")
            .and_then(Value::as_array)
        {
            let mut nested = Vec::new();
            for sub in subpartitions {
                let class_id = text(sub, "shadow_class_id")?;
                for semantic in
                    string_set(array(sub, "semantic_ids")?, "shadow class subpartition")?
                {
                    nested.push(semantic.clone());
                    shadow_mapping.push(format!("{semantic}\t{class_id}"));
                }
            }
            ensure_unique(&nested, "nested shadow class membership")?;
            if nested.into_iter().collect::<BTreeSet<_>>() != semantic_ids {
                return Err(format!("nested shadow class partition drift: {subtype}"));
            }
        } else {
            let class_refs = string_set(array(class, "shadow_class_ids")?, "shadow class refs")?;
            if class_refs.len() != 1 {
                return Err(format!("{subtype} requires one shadow class ref"));
            }
            let class_id = class_refs.into_iter().next().expect("one class ref");
            for semantic in semantic_ids {
                shadow_mapping.push(format!("{semantic}\t{class_id}"));
            }
        }
    }
    ensure_unique(&subtype_ids, "shadow subtype semantic IDs")?;
    ensure_unique(&shadow_mapping, "shadow class mapping")?;
    let operation_id_sha256 = sorted_newline_sha256(authority_ids.clone());
    let subtype_sha256 = sorted_newline_sha256(subtype_mapping);
    let shadow_mapping_sha256 = sorted_newline_sha256(shadow_mapping.clone());
    if subtype_ids.into_iter().collect::<BTreeSet<_>>()
        != authority_ids.iter().cloned().collect::<BTreeSet<_>>()
        || shadow_mapping.len() != 38
        || operation_id_sha256 != SHADOW_OPERATION_ID_SHA256
        || text(shadow, "semantic_operation_id_set_sha256")? != SHADOW_OPERATION_ID_SHA256
        || subtype_sha256 != SHADOW_OPERATIONAL_SUBTYPE_SHA256
        || text(shadow, "operational_subtype_mapping_sha256")? != SHADOW_OPERATIONAL_SUBTYPE_SHA256
        || shadow_mapping_sha256 != SHADOW_CLASS_MAPPING_SHA256
        || text(shadow, "shadow_class_mapping_sha256")? != SHADOW_CLASS_MAPPING_SHA256
        || flag(shadow, "per_operation_owner_routing_complete")?
        || flag(shadow, "current_execution_authorized")?
    {
        return Err("exact 38-operation shadow partition drift".to_owned());
    }
    let declared_classes = ids(array(artifact, "shadow_classes")?, "class_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if declared_classes
        != BTreeSet::from([
            "K1S-LOCAL-PURE".to_owned(),
            "K1S-BROKER-READ-PROBE".to_owned(),
            "K1S-RESOURCE-CONSTRUCTION-OBSERVE-ONLY".to_owned(),
            "K1S-ISOLATED-SIDE-EFFECT-CANARY".to_owned(),
            "K1S-DUPLICATE-FORBIDDEN".to_owned(),
            "K1S-NON-COMPARABLE".to_owned(),
        ])
        || array(artifact, "shadow_classes")?.iter().any(|row| {
            row.get("current_execution_authorized")
                .and_then(Value::as_bool)
                != Some(false)
        })
    {
        return Err("shadow class authorization drift".to_owned());
    }
    let summary_rows = array(artifact, "shadow_operations")?;
    let summary_ids = ids(summary_rows, "operation_id")?;
    ensure_unique(&summary_ids, "shadow summary IDs")?;
    if summary_rows.len() != 13 {
        return Err("shadow summary count drift".to_owned());
    }
    let summary_classes = summary_rows
        .iter()
        .map(|row| text(row, "class_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let used_classes = shadow_mapping
        .iter()
        .map(|row| {
            row.split_once('\t')
                .map(|(_, class)| class.to_owned())
                .unwrap()
        })
        .collect::<BTreeSet<_>>();
    if !used_classes.is_subset(&summary_classes) || !summary_classes.is_subset(&declared_classes) {
        return Err("shadow class/summary routing drift".to_owned());
    }
    let stop_ids = ids(array(artifact, "stop_conditions")?, "stop_condition_id")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for summary in summary_rows {
        if text(summary, "owner")? != "asupersync-dep-p7-kafka-removal-sarszu.2.14.3" {
            return Err(format!(
                "shadow summary owner drift: {}",
                text(summary, "operation_id")?
            ));
        }
        let refs = string_set(array(summary, "stop_condition_ids")?, "shadow stop refs")?;
        if refs.is_empty() || !refs.is_subset(&stop_ids) {
            return Err(format!(
                "unresolved shadow stop refs: {}",
                text(summary, "operation_id")?
            ));
        }
    }
    Ok(())
}

fn validate_rollback_approval_and_disposition(artifact: &Value) -> Result<(), String> {
    let stops = array(artifact, "stop_conditions")?;
    let stop_ids = ids(stops, "stop_condition_id")?;
    ensure_unique(&stop_ids, "stop condition IDs")?;
    if stops.len() != 12 {
        return Err("stop-condition count drift".to_owned());
    }
    let rollback = &artifact["rollback_contract"];
    let cases = array(rollback, "in_flight_cases")?;
    let case_ids = ids(cases, "case_id")?;
    ensure_unique(&case_ids, "rollback case IDs")?;
    if cases.len() != 7
        || array(rollback, "global_sequence")?.len() != 7
        || array(rollback, "rollback_complete_requires")?.len() < 6
        || flag(rollback, "rollback_claimed_complete")?
    {
        return Err("rollback contract drift".to_owned());
    }
    for case in cases {
        text(case, "state_owner")?;
        text(case, "required_action")?;
    }
    let approvals = array(artifact, "approval_gates")?;
    let approval_ids = ids(approvals, "approval_id")?;
    ensure_unique(&approval_ids, "approval IDs")?;
    if approval_ids.into_iter().collect::<BTreeSet<_>>()
        != BTreeSet::from([
            "K1APP-001-STATIC-K1".to_owned(),
            "K1APP-002-IMPLEMENTATION".to_owned(),
            "K1APP-003-INDEPENDENT".to_owned(),
            "K1APP-004-REAL-SERVICE".to_owned(),
            "K1APP-005-REFRESH".to_owned(),
            "K1APP-006-ROLLOUT-ROLLBACK".to_owned(),
            "K1APP-007-CUTOVER".to_owned(),
        ])
        || approvals
            .iter()
            .any(|row| row.get("authorizes_cutover").and_then(Value::as_bool) != Some(false))
    {
        return Err("approval gate drift".to_owned());
    }
    for approval in approvals {
        let approval_id = text(approval, "approval_id")?;
        let expected_state = if approval_id == "K1APP-001-STATIC-K1" {
            "SATISFIED_BY_THIS_STATIC_PACKET"
        } else {
            "BLOCKING_PENDING"
        };
        if text(approval, "state")? != expected_state {
            return Err(format!("approval state drift: {approval_id}"));
        }
    }
    let static_approval = approvals
        .iter()
        .find(|row| row.get("approval_id").and_then(Value::as_str) == Some("K1APP-001-STATIC-K1"))
        .ok_or_else(|| "missing K1 static approval".to_owned())?;
    let cutover_approval = approvals
        .iter()
        .find(|row| row.get("approval_id").and_then(Value::as_str) == Some("K1APP-007-CUTOVER"))
        .ok_or_else(|| "missing K15 cutover approval".to_owned())?;
    if text(static_approval, "owner")? != "asupersync-dep-p7-kafka-removal-sarszu.2.1.5"
        || text(cutover_approval, "owner")? != "asupersync-dep-p7-kafka-removal-sarszu.2.15"
    {
        return Err("static or cutover approval owner drift".to_owned());
    }
    let disposition = &artifact["disposition_receipt"];
    if text(disposition, "incumbent_disposition")? != "KEEP_INCUMBENT"
        || !flag(disposition, "k1_5_static_gate_complete")?
        || !flag(disposition, "k1_parent_static_contract_complete")?
        || !flag(
            disposition,
            "k1_5_typed_binding_membership_adjudication_complete",
        )?
        || flag(disposition, "k1_5_per_message_attribution_complete")?
    {
        return Err("scoped K1.5 disposition drift".to_owned());
    }
    for permission in [
        "runtime_protocol_proven",
        "runtime_resource_lifecycle_proven",
        "unit_model_property_fuzz_evidence_executed",
        "real_service_evidence_executed",
        "coexistence_executed",
        "shadow_execution_authorized",
        "rollback_drill_executed",
        "owner_cutover_approvals_complete",
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
        if flag(disposition, permission)? {
            return Err(format!(
                "forbidden permission or claim enabled: {permission}"
            ));
        }
    }
    Ok(())
}

fn validate_projections(artifact: &Value) -> Result<(), String> {
    let coverage = &artifact["coverage_receipt"];
    let scopes = object(coverage, "projection_scopes")?;
    if scopes.len() != PROJECTION_SCOPES.len() {
        return Err("projection scope count drift".to_owned());
    }
    for (field, pointer, rule) in PROJECTION_SCOPES {
        let scope = scopes
            .get(field)
            .ok_or_else(|| format!("missing exact projection scope: {field}"))?;
        if text(scope, "pointer")? != pointer || text(scope, "rule")? != rule {
            return Err(format!("projection scope declaration drift: {field}"));
        }
    }
    for (field, scope) in scopes {
        let pointer = text(scope, "pointer")?;
        let rule = text(scope, "rule")?;
        let selected = artifact
            .pointer(pointer)
            .ok_or_else(|| format!("projection pointer does not resolve: {pointer}"))?;
        let actual = match rule {
            "ROW_SET_V1" => canonical_rows_sha256(
                selected
                    .as_array()
                    .ok_or_else(|| format!("ROW_SET projection is not an array: {pointer}"))?,
            )?,
            "VALUE_V1" => canonical_value_sha256(selected)?,
            "STRING_SET_V1" => {
                let rows = selected
                    .as_array()
                    .ok_or_else(|| format!("STRING_SET projection is not an array: {pointer}"))?;
                let values = rows
                    .iter()
                    .map(|row| {
                        row.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| "STRING_SET contains non-text".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ensure_unique(&values, "STRING_SET projection")?;
                sorted_newline_sha256(values)
            }
            _ => return Err(format!("unknown projection rule: {rule}")),
        };
        let expected = text(coverage, field)?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || actual != expected
        {
            return Err(format!("projection digest drift: {field}"));
        }
    }
    let serialized = serde_json::to_string(artifact)
        .map_err(|error| format!("failed to serialize artifact: {error}"))?;
    if serialized.contains("PENDING_STATIC_DIGEST") || flag(coverage, "dynamic_execution_claimed")?
    {
        return Err("pending digest or dynamic execution claim found".to_owned());
    }
    Ok(())
}

fn validate_document_and_no_claims(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    let document = fs::read_to_string(inputs.root.join(DOCUMENT_PATH))
        .map_err(|error| format!("failed to read K1.5 document: {error}"))?;
    for required in [
        MARKER_START,
        MARKER_END,
        "KEEP_INCUMBENT",
        "No compiler, formatter, linter, test process, fuzz harness, benchmark",
        "K15 remains",
        "the sole conditional cutover owner",
    ] {
        if !document.contains(required) {
            return Err(format!("document marker/boundary missing: {required}"));
        }
    }
    let boundaries = array(artifact, "no_claim_boundaries")?;
    let boundary_strings = boundaries
        .iter()
        .map(|row| {
            row.as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| "no-claim boundary contains non-text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure_unique(&boundary_strings, "no-claim boundaries")?;
    if boundaries.len() != 17
        || sorted_newline_sha256(boundary_strings) != NO_CLAIM_BOUNDARY_SHA256
        || text(&artifact["coverage_receipt"], "no_claim_boundary_sha256")?
            != NO_CLAIM_BOUNDARY_SHA256
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|text| text.contains("No compiler, formatter, linter"))
        })
    {
        return Err("no-claim boundary drift".to_owned());
    }
    Ok(())
}

fn validate(inputs: &Inputs, artifact: &Value) -> Result<(), String> {
    validate_identity_and_inputs(inputs, artifact)?;
    validate_conflicts_and_obligations(inputs, artifact)?;
    validate_semantic_resource_join(inputs, artifact)?;
    validate_bindings(inputs, artifact)?;
    validate_evidence_routes(inputs, artifact)?;
    validate_profiles_and_shadow(inputs, artifact)?;
    validate_rollback_approval_and_disposition(artifact)?;
    validate_projections(artifact)?;
    validate_document_and_no_claims(inputs, artifact)?;
    Ok(())
}

#[test]
fn kafka_k1_aggregate_gate_is_exact_and_fail_closed() {
    let inputs = Inputs::load().expect("load K1.5 contract inputs");
    validate(&inputs, &inputs.artifact).expect("K1.5 aggregate gate must remain exact");
}

#[test]
fn kafka_k1_aggregate_gate_rejects_representative_mutations() {
    let inputs = Inputs::load().expect("load K1.5 contract inputs");
    let mut mutations = Vec::new();

    let mut pin = inputs.artifact.clone();
    pin["authority_inputs"][0]["sha256"] = Value::String("0".repeat(64));
    mutations.push(("input pin", pin));

    let mut conflict = inputs.artifact.clone();
    conflict["lineage_and_conflict_ledger"]["migration_blocking_reconciliation_row_count"] =
        Value::from(1);
    mutations.push(("conflict blocker", conflict));

    let mut binding = inputs.artifact.clone();
    binding["semantic_binding_adjudication"]["historical_row_typing"][9]["typed_edges"][4]["kind"] =
        Value::String("MESSAGE_SET".to_owned());
    mutations.push(("fake absence message binding", binding));

    let mut vector = inputs.artifact.clone();
    vector["capability_evidence_contract"]["accepted_evidence_namespace"]["category_routes"][0]
        ["vector_ids"]
        .as_array_mut()
        .expect("vector ID array")
        .pop();
    mutations.push(("vector omission", vector));

    let mut profile = inputs.artifact.clone();
    let duplicate =
        profile["feature_profile_contract"]["profiles"][0]["source_profile_ids"][0].clone();
    profile["feature_profile_contract"]["profiles"][1]["source_profile_ids"]
        .as_array_mut()
        .expect("profile ID array")
        .push(duplicate);
    mutations.push(("profile duplication", profile));

    let mut shadow = inputs.artifact.clone();
    shadow["shadow_semantic_operation_partition"]["current_execution_authorized"] =
        Value::Bool(true);
    mutations.push(("shadow authorization", shadow));

    let mut rollback = inputs.artifact.clone();
    rollback["rollback_contract"]["rollback_claimed_complete"] = Value::Bool(true);
    mutations.push(("rollback completion", rollback));

    let mut digest = inputs.artifact.clone();
    digest["coverage_receipt"]["authority_input_projection_sha256"] = Value::String("f".repeat(64));
    mutations.push(("projection digest", digest));

    let mut permission = inputs.artifact.clone();
    permission["disposition_receipt"]["cutover_allowed"] = Value::Bool(true);
    mutations.push(("cutover permission", permission));

    for (label, mutation) in mutations {
        assert!(
            validate(&inputs, &mutation).is_err(),
            "mutation unexpectedly passed: {label}"
        );
    }
}
