//! Fail-closed contract for the source-pinned Kafka capability inventory.
//!
//! Bead: asupersync-dep-p7-kafka-removal-sarszu.1.1
//! Fixture: artifacts/kafka_capability_inventory_v1.json
//!
//! This contract checks static source, manifest, export, cfg, ownership, and
//! registry coordinates. It performs no external process, network, timing,
//! broker, or environment-dependent work.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/kafka_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/kafka_capability_inventory.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const REGISTRY_DOC_PATH: &str = "docs/dependency_capability_registry.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_009_kafka_client.md";
const ARTIFACT_ID: &str = "kafka-capability-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-dep-p7-kafka-removal-sarszu.1.1";
const CAPABILITY_ID: &str = "CAP-KAFKA";
const BASELINE_REVISION: &str = "2d811170e956966e960db122a0d634a5b60c56e0";
const DOC_BEGIN: &str = "<!-- BEGIN KAFKA CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END KAFKA CAPABILITY INVENTORY -->";

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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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

fn expected_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|item| (*item).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn require_exact_ids(
    rows: &[Value],
    key: &str,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let expected = expected_set(expected);
    if rows.len() != expected.len() || row_ids(rows, key) != expected {
        return Err(format!("{label} exact unique {key} set drifted"));
    }
    Ok(())
}

fn require_exact_strings(value: &Value, key: &str, expected: &[&str]) -> Result<(), String> {
    let expected = expected_set(expected);
    if array(value, key).len() != expected.len() || string_set(value, key) != expected {
        return Err(format!("{key} exact unique string set drifted"));
    }
    Ok(())
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

fn validate_identity_and_authority(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", BASELINE_REVISION),
        ("inventory_state", "K0_1_SOURCE_REACHABILITY_FROZEN"),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", "DEP-ADR-009"),
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        ("source_inventory_owner", BEAD_ID),
        (
            "semantic_inventory_owner",
            "asupersync-dep-p7-kafka-removal-sarszu.1.2",
        ),
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

    let policy = object(inventory, "policy");
    for key in [
        "source_public_surface_unknown_allowed",
        "behavior_changes_allowed",
        "export_changes_allowed",
        "dependency_changes_allowed",
        "planned_evidence_counts_as_executed",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("policy.{key} must remain false"));
        }
    }
    if policy.get("routed_gap_state").and_then(Value::as_str) != Some("ROUTED")
        || policy.get("missing_row_state").and_then(Value::as_str) != Some("BLOCKING_MISSING")
    {
        return Err("policy gap states drifted".to_owned());
    }

    validate_no_exact_unknown(inventory, "$")
}

fn validate_source_pins(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins");
    require_exact_ids(
        pins,
        "pin_id",
        &[
            "KAFKA-PIN-ROOT-MANIFEST",
            "KAFKA-PIN-ROOT-LOCK",
            "KAFKA-PIN-FUZZ-MANIFEST",
            "KAFKA-PIN-CRATE-ROOT",
            "KAFKA-PIN-MESSAGING-MODULE",
            "KAFKA-PIN-PRODUCER-SOURCE",
            "KAFKA-PIN-CONSUMER-SOURCE",
            "KAFKA-PIN-UNWIRED-CONSUMER-SOURCE",
            "KAFKA-PIN-CAPABILITY-REGISTRY",
            "KAFKA-PIN-CAPABILITY-REGISTRY-DOC",
            "KAFKA-PIN-ADR",
            "KAFKA-PIN-ADR-REGISTRY",
            "KAFKA-PIN-MARGINAL-LEDGER",
        ],
        "source pins",
    )?;

    let expected_paths = expected_set(&[
        "Cargo.toml",
        "Cargo.lock",
        "fuzz/Cargo.toml",
        "src/lib.rs",
        "src/messaging/mod.rs",
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
        "src/real_kafka_consumer_group_rebalance_e2e_tests.rs",
        REGISTRY_PATH,
        REGISTRY_DOC_PATH,
        ADR_PATH,
        "artifacts/dependency_api_adr_registry_v1.json",
        "artifacts/dependency_marginal_ledger_v1.json",
    ]);
    let actual_paths: BTreeSet<String> = pins
        .iter()
        .map(|row| text(row, "path").to_owned())
        .collect();
    if actual_paths != expected_paths {
        return Err("source pin path set drifted".to_owned());
    }

    for pin in pins {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        if sha256_hex(&bytes) != text(pin, "sha256") {
            return Err(format!("{path} SHA-256 drifted"));
        }
        let records = u64::try_from(read_repo_file(path).lines().count())
            .expect("source record count must fit u64");
        if pin.get("record_count").and_then(Value::as_u64) != Some(records) {
            return Err(format!("{path} record count drifted"));
        }
    }
    Ok(())
}

fn validate_dependency_and_profiles(inventory: &Value) -> Result<(), String> {
    let dependency = inventory
        .get("dependency_resolution")
        .expect("dependency_resolution must exist");
    for (key, expected) in [
        ("root_edge_kind", "optional normal dependency"),
        ("target_condition", "none"),
        ("feature_id", "kafka"),
        ("manifest_requirement", "0.39"),
    ] {
        if dependency.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("dependency_resolution.{key} drifted"));
        }
    }
    require_exact_strings(dependency, "feature_members", &["dep:rdkafka"])?;
    require_exact_strings(
        dependency,
        "locked_rdkafka_sys_dependencies",
        &["libc", "num_enum", "pkg-config"],
    )?;
    for key in [
        "manifest_default_features",
        "direct_rdkafka_sys_import",
        "direct_c_ffi",
        "unsafe_block_in_primary_sources",
        "fuzz_workspace_enables_kafka",
        "fuzz_lock_tracked",
        "ci_cross_platform_enables_kafka",
    ] {
        if dependency.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("dependency_resolution.{key} must remain false"));
        }
    }
    for key in ["manifest_optional", "native_all_features_enables_kafka"] {
        if dependency.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("dependency_resolution.{key} must remain true"));
        }
    }

    let packages = array(dependency, "resolved_packages");
    require_exact_ids(
        packages,
        "package",
        &["rdkafka", "rdkafka-sys"],
        "resolved packages",
    )?;
    if text(find_row(packages, "package", "rdkafka"), "version") != "0.39.0"
        || text(find_row(packages, "package", "rdkafka-sys"), "version") != "4.10.0+2.12.1"
    {
        return Err("resolved package versions drifted".to_owned());
    }

    require_exact_ids(
        array(inventory, "compilation_profiles"),
        "profile_id",
        &[
            "KAFKA-PROFILE-NATIVE-DEFAULT-RELEASE",
            "KAFKA-PROFILE-NATIVE-DEFAULT-DEBUG",
            "KAFKA-PROFILE-NATIVE-KAFKA-RELEASE",
            "KAFKA-PROFILE-NATIVE-KAFKA-DEBUG",
            "KAFKA-PROFILE-UNIT-NO-KAFKA",
            "KAFKA-PROFILE-UNIT-WITH-KAFKA",
            "KAFKA-PROFILE-DOWNSTREAM-NO-KAFKA",
            "KAFKA-PROFILE-TEST-INTERNALS-NO-KAFKA",
            "KAFKA-PROFILE-FUZZ-WORKSPACE",
            "KAFKA-PROFILE-CI-CROSS-PLATFORM",
            "KAFKA-PROFILE-NATIVE-ALL-FEATURES",
            "KAFKA-PROFILE-WASM-NO-KAFKA",
            "KAFKA-PROFILE-WASM-WITH-KAFKA",
        ],
        "compilation profiles",
    )
}

fn validate_public_surface(inventory: &Value) -> Result<(), String> {
    let topology = inventory
        .get("module_topology")
        .expect("module_topology must exist");
    require_exact_strings(
        topology,
        "facade_exports",
        &[
            "Acks",
            "AutoOffsetReset",
            "Compression",
            "IsolationLevel",
            "KafkaConsumer",
            "KafkaConsumerConfig",
            "KafkaConsumerRecord",
            "KafkaError",
            "KafkaProducer",
            "ProducerConfig",
            "RecordMetadata",
            "TopicPartitionOffset",
            "Transaction",
            "TransactionalConfig",
            "TransactionalProducer",
        ],
    )?;
    if !array(topology, "crate_root_exports").is_empty() {
        return Err("Kafka crate-root exports must remain empty".to_owned());
    }
    require_exact_strings(
        topology,
        "general_module_only_public_paths",
        &[
            "BrokerBackend",
            "KafkaClient",
            "KafkaConsumerTrait",
            "KafkaFeatureRequirement",
            "KafkaSaslConfig",
            "KafkaSaslMechanism",
            "KafkaSecurityConfig",
            "KafkaTlsConfig",
            "RebalanceResult",
        ],
    )?;
    require_exact_ids(
        array(topology, "feature_ungated_modules"),
        "module_id",
        &["KAFKA-MODULE-PRODUCER", "KAFKA-MODULE-CONSUMER"],
        "feature-ungated modules",
    )?;

    let symbols = array(inventory, "public_symbols");
    require_exact_ids(
        symbols,
        "symbol_id",
        &[
            "KPR-PUB-001",
            "KPR-PUB-002",
            "KPR-PUB-003",
            "KPR-PUB-004",
            "KPR-PUB-005",
            "KPR-PUB-006",
            "KPR-PUB-007",
            "KPR-PUB-008",
            "KPR-PUB-009",
            "KPR-PUB-010",
            "KPR-PUB-011",
            "KPR-PUB-012",
            "KPR-PUB-013",
            "KPR-PUB-014",
            "KPR-PUB-015",
            "KPR-PUB-016",
            "KPR-PUB-017",
            "KPR-PUB-018",
            "KPR-PUB-019",
            "KPR-PUB-020",
            "KPR-PUB-021",
            "KPR-PUB-022",
            "KPR-PUB-023",
            "KCO-PUB-001",
            "KCO-PUB-002",
            "KCO-PUB-003",
            "KCO-PUB-004",
            "KCO-PUB-005",
            "KCO-PUB-006",
            "KCO-PUB-007",
        ],
        "public symbols",
    )?;
    let owner_paths: BTreeSet<String> = symbols
        .iter()
        .map(|row| text(row, "owner_path").to_owned())
        .collect();
    if owner_paths != expected_set(&["src/messaging/kafka.rs", "src/messaging/kafka_consumer.rs"]) {
        return Err("public symbol owner set drifted".to_owned());
    }
    let field_count = symbols
        .iter()
        .map(|row| array(row, "public_fields").len())
        .sum::<usize>();
    let method_count = symbols
        .iter()
        .map(|row| array(row, "public_methods").len())
        .sum::<usize>();
    if field_count != 54 || method_count != 96 {
        return Err("public symbol field or method projection drifted".to_owned());
    }
    let projected_facade: BTreeSet<String> = symbols
        .iter()
        .flat_map(|row| array(row, "facade_exports"))
        .map(|entry| {
            entry
                .as_str()
                .expect("facade exports must be strings")
                .to_owned()
        })
        .collect();
    if projected_facade != string_set(topology, "facade_exports") {
        return Err("public symbol facade projection drifted".to_owned());
    }

    let census = object(inventory, "occurrence_census");
    for (key, expected) in [
        ("public_top_level_declarations", 37),
        ("unique_public_top_level_paths", 36),
        ("public_symbol_groups", 30),
        ("syntactic_public_inherent_method_declarations", 95),
        ("unique_public_inherent_method_paths", 91),
        ("public_trait_methods", 5),
        ("syntactic_public_fields", 60),
        ("crate_private_record_fields", 6),
        ("downstream_visible_public_fields", 54),
        ("facade_export_names", 15),
    ] {
        if census.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("occurrence_census.{key} must remain {expected}"));
        }
    }
    Ok(())
}

fn validate_behavior_and_routing(inventory: &Value) -> Result<(), String> {
    require_exact_ids(
        array(inventory, "backend_bindings"),
        "binding_id",
        &[
            "KAFKA-BACKEND-REAL-PRODUCER",
            "KAFKA-BACKEND-REAL-CONSUMER",
            "KAFKA-BACKEND-DETERMINISTIC-QUARANTINE",
            "KAFKA-BACKEND-NOFEATURE-DESCRIPTOR",
            "KAFKA-BACKEND-SECURITY-SECRET",
            "KAFKA-BACKEND-CONSUMER-STATE",
        ],
        "backend bindings",
    )?;
    require_exact_ids(
        array(inventory, "cfg_branch_inventory"),
        "branch_id",
        &[
            "KAFKA-CFG-REAL",
            "KAFKA-CFG-DETERMINISTIC",
            "KAFKA-CFG-DETERMINISTIC-CONTROL",
            "KAFKA-CFG-INSECURE-BYPASS",
            "KAFKA-CFG-PARSER-HOOKS",
            "KAFKA-CFG-CONSUMER-TEST-REAL-SELECTION",
            "KAFKA-CFG-NATIVE-MODULE",
            "KAFKA-CFG-WASM-REFUSAL",
        ],
        "cfg branches",
    )?;
    require_exact_ids(
        array(inventory, "feature_disabled_behavior"),
        "behavior_id",
        &[
            "KAFKA-NOFEATURE-MODULES",
            "KAFKA-NOFEATURE-REQUIRED-CONFIG",
            "KAFKA-NOFEATURE-OPTIONAL-CONSTRUCTORS",
            "KAFKA-NOFEATURE-PRODUCE",
            "KAFKA-NOFEATURE-PRODUCER-LOCAL-LIFECYCLE",
            "KAFKA-NOFEATURE-TRANSACTION-BEGIN",
            "KAFKA-NOFEATURE-CONSUMER-CONSTRUCTOR",
            "KAFKA-NOFEATURE-CONSUMER-BROKER-OPS",
            "KAFKA-NOFEATURE-CONSUMER-LOCAL-LIFECYCLE",
            "KAFKA-NOFEATURE-KAFKA-CLIENT",
            "KAFKA-NOFEATURE-TEST-INTERNALS",
        ],
        "no-feature behavior",
    )?;

    let quarantine = object(inventory, "deterministic_broker_quarantine");
    if quarantine.get("evidence_class").and_then(Value::as_str)
        != Some("DETERMINISTIC_ONLY_NOT_BROKER_EVIDENCE")
        || quarantine.get("public_control_cfg").and_then(Value::as_str)
            != Some("not(feature=kafka) and feature=test-internals")
    {
        return Err("deterministic broker quarantine drifted".to_owned());
    }

    let gaps = array(inventory, "routed_gaps");
    require_exact_ids(
        gaps,
        "gap_id",
        &[
            "KAFKA-K0-1-GAP-01",
            "KAFKA-K0-1-GAP-02",
            "KAFKA-K0-1-GAP-03",
            "KAFKA-K0-1-GAP-04",
            "KAFKA-K0-1-GAP-05",
            "KAFKA-K0-1-GAP-06",
            "KAFKA-K0-1-GAP-07",
            "KAFKA-K0-1-GAP-08",
            "KAFKA-K0-1-GAP-09",
            "KAFKA-K0-1-GAP-10",
            "KAFKA-K0-1-GAP-11",
            "KAFKA-K0-1-GAP-12",
            "KAFKA-K0-1-GAP-13",
            "KAFKA-K0-1-GAP-14",
            "KAFKA-K0-1-GAP-15",
        ],
        "routed gaps",
    )?;
    for gap in gaps {
        if gap.get("state").and_then(Value::as_str) != Some("ROUTED")
            || gap
                .get("owner_bead")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(format!(
                "{} must remain routed and owned",
                text(gap, "gap_id")
            ));
        }
    }
    let owners: BTreeSet<String> = gaps
        .iter()
        .map(|gap| text(gap, "owner_bead").to_owned())
        .collect();
    if owners
        != expected_set(&[
            "asupersync-dep-p7-kafka-removal-sarszu.1.2",
            "asupersync-dep-p7-kafka-removal-sarszu.1.3",
            "asupersync-dep-p7-kafka-removal-sarszu.1.4",
            "asupersync-dep-p7-kafka-removal-sarszu.2.10.1",
            "asupersync-dep-p7-kafka-removal-sarszu.2.12.3",
        ])
    {
        return Err("routed gap owner set drifted".to_owned());
    }

    let coverage = object(inventory, "coverage_receipt");
    for key in [
        "source_pin_ids_unique",
        "public_symbol_ids_unique",
        "profile_ids_unique",
        "cfg_branch_ids_unique",
        "behavior_ids_unique",
        "gap_ids_unique",
    ] {
        if coverage.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("coverage_receipt.{key} must remain true"));
        }
    }
    for key in [
        "source_unknown_rows",
        "manifest_unknown_rows",
        "public_surface_unknown_rows",
        "unowned_gap_rows",
    ] {
        if !array(
            inventory
                .get("coverage_receipt")
                .expect("coverage_receipt must exist"),
            key,
        )
        .is_empty()
        {
            return Err(format!("coverage_receipt.{key} must remain empty"));
        }
    }
    Ok(())
}

fn validate_registry_reconciliation(inventory: &Value) -> Result<(), String> {
    let reconciliation = inventory
        .get("registry_reconciliation")
        .expect("registry_reconciliation must exist");
    if reconciliation.get("capability_id").and_then(Value::as_str) != Some(CAPABILITY_ID)
        || reconciliation
            .get("inventory_artifact")
            .and_then(Value::as_str)
            != Some(ARTIFACT_PATH)
        || reconciliation.get("baseline_owner").and_then(Value::as_str)
            != Some("asupersync-dep-p7-kafka-removal-sarszu.1.5")
    {
        return Err("registry reconciliation identity drifted".to_owned());
    }
    require_exact_strings(
        reconciliation,
        "source_owners",
        &[
            "src/messaging/kafka.rs",
            "src/messaging/kafka_consumer.rs",
            "Cargo.toml",
        ],
    )?;
    let mapping = reconciliation
        .get("mapping_rule")
        .expect("mapping_rule must exist");
    if mapping.get("scope").and_then(Value::as_str) != Some("prefix")
        || mapping.get("bead_id").and_then(Value::as_str)
            != Some("asupersync-dep-p7-kafka-removal-sarszu.1.")
    {
        return Err("registry reconciliation mapping rule drifted".to_owned());
    }
    require_exact_strings(mapping, "capability_ids", &[CAPABILITY_ID])?;

    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    if capability.get("inventory_artifact").and_then(Value::as_str) != Some(ARTIFACT_PATH)
        || capability.get("disposition").and_then(Value::as_str) != Some("KEEP_UNTIL_PARITY")
        || capability.get("cutover_state").and_then(Value::as_str) != Some("KEEP_INCUMBENT")
    {
        return Err("live CAP-KAFKA authority drifted".to_owned());
    }
    require_exact_strings(
        capability,
        "source_owners",
        &[
            "src/messaging/kafka.rs",
            "src/messaging/kafka_consumer.rs",
            "Cargo.toml",
        ],
    )?;
    let baseline = object(capability, "baseline");
    if baseline.get("owner_bead").and_then(Value::as_str)
        != Some("asupersync-dep-p7-kafka-removal-sarszu.1.5")
    {
        return Err("live CAP-KAFKA baseline owner drifted".to_owned());
    }

    let live_mapping = array(&registry, "bead_mapping_rules")
        .iter()
        .find(|row| {
            row.get("scope").and_then(Value::as_str) == Some("prefix")
                && row.get("bead_id").and_then(Value::as_str)
                    == Some("asupersync-dep-p7-kafka-removal-sarszu.1.")
        })
        .ok_or_else(|| "live K0 prefix mapping is missing".to_owned())?;
    require_exact_strings(live_mapping, "capability_ids", &[CAPABILITY_ID])?;

    let graph = object(&registry, "graph_signoff_report");
    let expected_graph = object(reconciliation, "graph_signoff_counts");
    for key in [
        "dep_plan_issue_count",
        "non_epic_work_count",
        "mapping_rule_count",
    ] {
        if graph.get(key).and_then(Value::as_u64) != expected_graph.get(key).and_then(Value::as_u64)
        {
            return Err(format!("graph signoff {key} disagrees with inventory"));
        }
    }
    Ok(())
}

fn validate_static_source_and_docs(inventory: &Value) -> Result<(), String> {
    let manifest = read_repo_file("Cargo.toml");
    let crate_root = read_repo_file("src/lib.rs");
    let module = read_repo_file("src/messaging/mod.rs");
    let producer = read_repo_file("src/messaging/kafka.rs");
    let consumer = read_repo_file("src/messaging/kafka_consumer.rs");
    for required in ["kafka = [\"dep:rdkafka\"]", "rdkafka"] {
        if !manifest.contains(required) {
            return Err(format!("Cargo.toml lost {required}"));
        }
    }
    if !crate_root.contains("target_arch = \"wasm32\"")
        || !crate_root.contains("feature = \"kafka\"")
        || !module.contains("pub mod kafka;")
        || !module.contains("pub mod kafka_consumer;")
    {
        return Err("native module or wasm refusal tokens drifted".to_owned());
    }
    if producer.matches("pub struct KafkaClient").count() != 2
        || !producer.contains("pub struct KafkaProducer")
        || !producer.contains("pub struct TransactionalProducer")
        || !consumer.contains("pub struct KafkaConsumer")
        || !consumer.contains("pub struct RebalanceResult")
    {
        return Err("primary public declaration tokens drifted".to_owned());
    }

    let doc = read_repo_file(DOC_PATH);
    for required in [
        DOC_BEGIN,
        DOC_END,
        ARTIFACT_PATH,
        BEAD_ID,
        CAPABILITY_ID,
        "KEEP_UNTIL_PARITY",
        "37",
        "30",
        "54",
        "15 source-level facts",
        "These are static reachability coordinates. They are not compiler-run receipts.",
        "It also does not prove protocol correctness",
    ] {
        if !doc.contains(required) {
            return Err(format!("Kafka inventory document lost {required}"));
        }
    }
    if doc.find(DOC_BEGIN) >= doc.find(DOC_END) {
        return Err("Kafka inventory document markers are out of order".to_owned());
    }

    let registry_doc = read_repo_file(REGISTRY_DOC_PATH);
    if !registry_doc.contains(ARTIFACT_PATH)
        || !registry_doc.contains("all 419 canonical `dep-plan` issues")
        || !registry_doc.contains("through 109")
    {
        return Err("capability registry document lost Kafka reconciliation".to_owned());
    }
    let adr = read_repo_file(ADR_PATH);
    if !adr.contains("KFK-GAP-01") || !adr.contains(BEAD_ID) || !adr.contains("pkg-config") {
        return Err("DEP-ADR-009 lost K0.1 reconciliation".to_owned());
    }

    let no_claims = array(inventory, "no_claim_boundaries");
    let no_claim_text = no_claims
        .iter()
        .map(|entry| entry.as_str().expect("no-claim entries must be strings"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "K0.2",
        "K0.3",
        "K0.4",
        "K0.5",
        "permission to remove rdkafka",
    ] {
        if !no_claim_text.contains(required) {
            return Err(format!("no-claim boundaries lost {required}"));
        }
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    validate_identity_and_authority(inventory)?;
    validate_source_pins(inventory)?;
    validate_dependency_and_profiles(inventory)?;
    validate_public_surface(inventory)?;
    validate_behavior_and_routing(inventory)?;
    validate_registry_reconciliation(inventory)?;
    validate_static_source_and_docs(inventory)
}

#[test]
fn kafka_inventory_is_source_pinned_and_complete() {
    validate_inventory(&artifact()).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn kafka_inventory_rejects_missing_public_symbol_rows() {
    let mut inventory = artifact();
    inventory["public_symbols"]
        .as_array_mut()
        .expect("public_symbols must be mutable")
        .pop();
    assert!(validate_inventory(&inventory).is_err());
}

#[test]
fn kafka_inventory_rejects_unowned_routed_gaps() {
    let mut inventory = artifact();
    inventory["routed_gaps"][0]["owner_bead"] = Value::String(String::new());
    assert!(validate_inventory(&inventory).is_err());
}

#[test]
fn kafka_inventory_rejects_exact_unknown_states() {
    let mut inventory = artifact();
    inventory["inventory_state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&inventory).is_err());
}
