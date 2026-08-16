//! Fail-closed contract for the source-pinned HEX capability inventory.
//!
//! Bead: asupersync-d24mms.9.1
//! Fixture: artifacts/hex_capability_inventory_v1.json
//!
//! This contract checks the inventory, not replacement correctness or
//! dependency cutover. It deliberately performs no external process,
//! network, timing, or environment-dependent work.

#![allow(missing_docs)]

#[cfg(not(target_arch = "wasm32"))]
use asupersync::net::atp::sdk::object::ObjectHash;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/hex_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/hex_capability_inventory.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const MATRIX_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const API_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const IGNORE_PATH: &str = ".gitignore";
const CONFORMANCE_MANIFEST_PATH: &str = "conformance/Cargo.toml";
const NESTED_CONFORMANCE_LIB_PATH: &str = "tests/conformance/raptorq_rfc6330/golden/src/lib.rs";
const NESTED_CONFORMANCE_MOD_PATH: &str = "tests/conformance/raptorq_rfc6330/golden/src/mod.rs";
const ARTIFACT_ID: &str = "hex-capability-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-d24mms.9.1";
const CAPABILITY_ID: &str = "CAP-HEX-CODEC";
const BASELINE_REVISION: &str = "8793ef7097f23622b2bdea1cd9a60afbb11517f1";
const DOC_BEGIN: &str = "<!-- BEGIN HEX CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END HEX CAPABILITY INVENTORY -->";
const PATH_TOKEN: &str = concat!("hex", "::");
const SOURCE_PIN_PATHS_SHA256: &str =
    "8ff7aa63a3c44e801fc536f894aff787d209a9032de2ac69d163bcca1f6cb156";
const CLAIMS_PROJECTION_SHA256: &str =
    "14c2c7f6cd9b084f8b857bed97400453d5216bac22e5a1237c29ee9daf4d3e46";

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

fn value_array<'a>(value: &'a Value, label: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label} must be an array"))
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

fn require_exact_ids(
    rows: &[Value],
    key: &str,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let expected: BTreeSet<String> = expected.iter().map(|id| (*id).to_owned()).collect();
    if rows.len() != expected.len() || row_ids(rows, key) != expected {
        return Err(format!("{label} exact unique {key} set drifted"));
    }
    Ok(())
}

fn require_exact_strings(value: &Value, key: &str, expected: &[&str]) -> Result<(), String> {
    let rows = array(value, key);
    let expected: BTreeSet<String> = expected.iter().map(|item| (*item).to_owned()).collect();
    if rows.len() != expected.len() || string_set(value, key) != expected {
        return Err(format!("{key} exact unique string set drifted"));
    }
    Ok(())
}

fn owner_map(rows: &[Value], id_key: &str) -> BTreeMap<String, String> {
    rows.iter()
        .map(|row| (text(row, id_key).to_owned(), text(row, "owner").to_owned()))
        .collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => output.push_str(&number.to_string()),
        Value::String(text) => output.push_str(
            &serde_json::to_string(text).expect("JSON string serialization must succeed"),
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(child, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("JSON key serialization must succeed"),
                );
                output.push(':');
                write_canonical_json(
                    values.get(key).expect("canonical JSON key must exist"),
                    output,
                );
            }
            output.push('}');
        }
    }
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut output = String::new();
    write_canonical_json(value, &mut output);
    output.into_bytes()
}

fn claims_projection(inventory: &Value) -> Value {
    serde_json::json!({
        "authority": inventory["authority"].clone(),
        "policy": inventory["policy"].clone(),
        "source_pin_scope": inventory["source_pin_scope"].clone(),
        "dependency_resolution": inventory["dependency_resolution"].clone(),
        "call_compilation_profiles": inventory["call_compilation_profiles"].clone(),
        "incumbent_api": inventory["incumbent_api"].clone(),
        "unused_incumbent_api": inventory["unused_incumbent_api"].clone(),
        "incumbent_semantics": inventory["incumbent_semantics"].clone(),
        "semantic_corpus": inventory["semantic_corpus"].clone(),
        "occurrence_census": inventory["occurrence_census"].clone(),
        "call_sites": inventory["call_sites"].clone(),
        "migration_reservation_groups": inventory["migration_reservation_groups"].clone(),
        "public_surface": inventory["public_surface"].clone(),
        "manual_collision_surfaces": inventory["manual_collision_surfaces"].clone(),
        "persisted_and_wire_formats": inventory["persisted_and_wire_formats"].clone(),
        "downstream_and_e2e": inventory["downstream_and_e2e"].clone(),
        "gaps": inventory["gaps"].clone(),
        "rollback_triggers": inventory["rollback_triggers"].clone(),
        "no_claim_boundaries": inventory["no_claim_boundaries"].clone(),
    })
}

fn validate_no_unknown(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{path} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unknown(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_unknown(child, &format!("{path}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_objects_with_text_field<'a>(
    value: &'a Value,
    key: &str,
    expected: &str,
    rows: &mut Vec<&'a Value>,
) {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_objects_with_text_field(child, key, expected, rows);
            }
        }
        Value::Object(values) => {
            if values.get(key).and_then(Value::as_str) == Some(expected) {
                rows.push(value);
            }
            for child in values.values() {
                collect_objects_with_text_field(child, key, expected, rows);
            }
        }
        _ => {}
    }
}

fn symbol_map(row: &Value, key: &str) -> BTreeMap<String, u64> {
    row.get(key)
        .and_then(Value::as_object)
        .map(|symbols| {
            symbols
                .iter()
                .map(|(name, count)| {
                    (
                        name.clone(),
                        count
                            .as_u64()
                            .unwrap_or_else(|| panic!("{key}.{name} must be u64")),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn combined_symbol_map(row: &Value) -> BTreeMap<String, u64> {
    let mut combined = symbol_map(row, "symbols");
    for (name, count) in symbol_map(row, "comment_symbols") {
        *combined.entry(name).or_default() += count;
    }
    combined
}

fn symbol_total(symbols: &BTreeMap<String, u64>) -> u64 {
    symbols.values().sum()
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
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
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        (
            "source",
            "artifacts/dependency_capability_registry_v1.json#CAP-HEX-CODEC",
        ),
        ("registry_disposition", "PRESERVE_AND_REPLACE_IF_PARITY"),
        ("current_action", "KEEP_INCUMBENT"),
        ("cutover_state", "BLOCKED_PENDING_EVIDENCE"),
        ("implementation_owner", "asupersync-d24mms.9.2"),
        ("migration_owner", "asupersync-d24mms.9.3"),
        ("journey_owner", "asupersync-d24mms.9.4"),
        ("terminal_cutover_owner", "asupersync-d24mms.9.5"),
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
        return Err("A1 must not authorize dependency exit".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("inventory_state").and_then(Value::as_str)
            != Some("BASELINED_WITH_ROUTED_GAPS")
        || policy.get("evidence_state").and_then(Value::as_str)
            != Some("EXECUTABLE_PARTIAL_BLOCKING")
    {
        return Err("policy must remain zero-unknown and partial-blocking".to_owned());
    }
    require_exact_strings(
        inventory.get("policy").expect("policy required"),
        "accepted_states",
        &[
            "BASELINED",
            "PRESENT",
            "ABSENT",
            "PLANNED",
            "BLOCKED",
            "ROUTED",
            "OUT_OF_SCOPE",
            "NOT_RUN_BY_A1",
        ],
    )?;
    validate_no_unknown(inventory, "$")?;

    let pin_scope = object(inventory, "source_pin_scope");
    if pin_scope.get("state").and_then(Value::as_str) != Some("BASELINED")
        || pin_scope.get("path_count").and_then(Value::as_u64) != Some(81)
    {
        return Err("source pin scope must retain 81 baselined paths".to_owned());
    }

    let resolution = object(inventory, "dependency_resolution");
    if resolution
        .get("manifest_requirement")
        .and_then(Value::as_str)
        != Some("0.4")
        || resolution.get("resolved_version").and_then(Value::as_str) != Some("0.4.3")
        || resolution.get("checksum").and_then(Value::as_str)
            != Some("7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70")
        || resolution.get("edge_id").and_then(Value::as_str) != Some("normal:hex")
        || resolution.get("edge_kind").and_then(Value::as_str) != Some("normal")
        || resolution.get("optional").and_then(Value::as_bool) != Some(false)
        || !resolution
            .get("target_condition")
            .is_some_and(Value::is_null)
        || resolution
            .get("root_default_features")
            .and_then(Value::as_bool)
            != Some(true)
        || resolution
            .get("synthesized_consumer_cells")
            .and_then(Value::as_u64)
            != Some(48)
        || resolution
            .get("workspace_dev_build_audit_cells")
            .and_then(Value::as_u64)
            != Some(4)
        || resolution
            .get("synthesized_consumer_marginal_package_count_per_cell")
            .and_then(Value::as_u64)
            != Some(1)
        || resolution
            .get("workspace_dev_build_audit_marginal_package_count_per_cell")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err("dependency resolution or marginal cell count drifted".to_owned());
    }
    require_exact_strings(
        inventory
            .get("dependency_resolution")
            .expect("dependency_resolution required"),
        "upstream_declared_default_features",
        &["std"],
    )?;
    require_exact_strings(
        inventory
            .get("dependency_resolution")
            .expect("dependency_resolution required"),
        "upstream_default_feature_closure",
        &["std", "alloc"],
    )?;
    require_exact_strings(
        inventory
            .get("dependency_resolution")
            .expect("dependency_resolution required"),
        "canonical_synthesized_consumer_profiles",
        &[
            "minimal",
            "default",
            "tls",
            "sqlite",
            "kafka",
            "metrics",
            "cli",
            "compression",
            "trace-compression",
            "io-uring",
            "loom-tests",
            "fuzz-quarantine",
        ],
    )?;
    require_exact_strings(
        inventory
            .get("dependency_resolution")
            .expect("dependency_resolution required"),
        "canonical_target_triples",
        &[
            "aarch64-apple-darwin",
            "wasm32-unknown-unknown",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ],
    )?;
    for empty_key in ["build_scripts", "proc_macros", "native_code"] {
        if !array(
            inventory
                .get("dependency_resolution")
                .expect("dependency_resolution required"),
            empty_key,
        )
        .is_empty()
        {
            return Err(format!("dependency_resolution.{empty_key} must stay empty"));
        }
    }
    let profiles = array(inventory, "call_compilation_profiles");
    let profile_ids = row_ids(profiles, "profile_id");
    require_exact_ids(
        profiles,
        "profile_id",
        &[
            "portable-library",
            "native-atp-library",
            "cli-module",
            "atp-cli-binary",
            "postgres",
            "legacy-internal-lib-tests",
            "serialization-golden-lib-tests",
            "default-lib-tests",
            "test-or-test-internals",
            "root-auto-ungated",
            "root-auto-atp-cli-windows",
            "root-auto-test-internals",
            "root-explicit-kafka",
            "root-nested-object-journal",
            "root-nested-multi-peer",
            "conformance-workspace",
            "unwired-lexical-fixture",
            "examples",
            "benches",
            "separate-fuzz-workspace",
        ],
        "call compilation profiles",
    )?;

    require_exact_ids(
        array(inventory, "incumbent_api"),
        "api",
        &["encode", "decode", "decode_to_slice", "FromHexError"],
        "incumbent API",
    )?;
    require_exact_strings(
        inventory,
        "unused_incumbent_api",
        &["encode_upper", "encode_to_slice", "ToHex", "FromHex"],
    )?;
    require_exact_ids(
        array(inventory, "semantic_corpus"),
        "case_id",
        &[
            "HEX-SEM-01",
            "HEX-SEM-02",
            "HEX-SEM-03",
            "HEX-SEM-04",
            "HEX-SEM-05",
            "HEX-SEM-06",
            "HEX-SEM-07",
            "HEX-SEM-08",
            "HEX-SEM-09",
            "HEX-SEM-10",
            "HEX-SEM-11",
            "HEX-SEM-12",
        ],
        "semantic corpus",
    )?;

    let census = object(inventory, "occurrence_census");
    for (key, expected) in [
        ("files", 104),
        ("lexical_tokens", 253),
        ("code_or_type_references", 250),
        ("comment_tokens", 3),
        ("cfg_any_disabled_reference_count", 4),
        ("cfg_test_references_embedded_in_production_files", 25),
        ("test_or_test_internals_module_references", 2),
        ("test_or_conformance_group_references", 124),
        ("active_production_references", 95),
        ("unknown_occurrences", 0),
    ] {
        if census.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("occurrence_census.{key} must be {expected}"));
        }
    }
    let census_value = inventory
        .get("occurrence_census")
        .expect("occurrence_census required");
    if symbol_map(census_value, "symbols")
        != BTreeMap::from([
            ("FromHexError".to_owned(), 4),
            ("decode".to_owned(), 36),
            ("decode_to_slice".to_owned(), 11),
            ("encode".to_owned(), 201),
            ("tests".to_owned(), 1),
        ])
        || symbol_map(census_value, "code_or_type_symbols")
            != BTreeMap::from([
                ("FromHexError".to_owned(), 4),
                ("decode".to_owned(), 34),
                ("decode_to_slice".to_owned(), 11),
                ("encode".to_owned(), 201),
            ])
    {
        return Err("occurrence symbol summaries drifted".to_owned());
    }
    let roots = array(census_value, "by_root");
    require_exact_ids(
        roots,
        "root",
        &["src", "tests", "conformance", "examples", "benches", "fuzz"],
        "occurrence roots",
    )?;
    let expected_root_counts = BTreeMap::from([
        ("src", (51, 182)),
        ("tests", (52, 69)),
        ("conformance", (1, 2)),
        ("examples", (0, 0)),
        ("benches", (0, 0)),
        ("fuzz", (0, 0)),
    ]);
    for root in roots {
        let expected = expected_root_counts
            .get(text(root, "root"))
            .expect("root count fixture");
        if root.get("files").and_then(Value::as_u64) != Some(expected.0)
            || root.get("lexical_tokens").and_then(Value::as_u64) != Some(expected.1)
        {
            return Err(format!("occurrence root {} drifted", text(root, "root")));
        }
    }
    let call_sites = array(inventory, "call_sites");
    if call_sites.len() != 104 || row_ids(call_sites, "path").len() != 104 {
        return Err("call_sites must contain 104 unique paths".to_owned());
    }
    if call_sites.iter().any(|row| {
        text(row, "profile").is_empty()
            || !profile_ids.contains(text(row, "profile"))
            || text(row, "group_id").is_empty()
            || (symbol_map(row, "symbols").is_empty()
                && symbol_map(row, "comment_symbols").is_empty())
    }) {
        return Err(
            "every call site needs a declared profile, group, and symbol or comment map".to_owned(),
        );
    }
    for row in call_sites {
        if let Some(additional) = row.get("additional_profiles") {
            let additional = value_array(additional, "additional_profiles");
            let unique: BTreeSet<_> = additional
                .iter()
                .map(|profile| {
                    profile
                        .as_str()
                        .expect("additional profile must be text")
                        .to_owned()
                })
                .collect();
            if unique.len() != additional.len()
                || unique.contains(text(row, "profile"))
                || !unique.iter().all(|profile| profile_ids.contains(profile))
            {
                return Err(format!(
                    "additional profile membership drifted for {}",
                    text(row, "path")
                ));
            }
        }
    }

    let groups = array(inventory, "migration_reservation_groups");
    require_exact_ids(
        groups,
        "group_id",
        &[
            "HEX-A3-ATP-PROTOCOL-CLI",
            "HEX-A3-SECURITY-OBSERVABILITY",
            "HEX-A3-DATABASE",
            "HEX-A3-TEST-CONFORMANCE",
        ],
        "migration reservation groups",
    )?;
    if groups.iter().any(|row| {
        text(row, "owner") != "asupersync-d24mms.9.3"
            || text(row, "journey_owner") != "asupersync-d24mms.9.4"
    }) {
        return Err("migration and journey ownership must remain explicit".to_owned());
    }

    let public = array(inventory, "public_surface");
    require_exact_ids(
        public,
        "surface_id",
        &[
            "HEX-PUB-OBJECT-HASH",
            "HEX-PRIVATE-SDK-DECODE-32",
            "HEX-PUB-KEY-FINGERPRINT",
            "HEX-PUB-TRANSCRIPT-HASH",
            "HEX-PUB-PEER-ID",
            "HEX-PUB-W3C-IDS",
            "HEX-PUB-ATP-FIXED-IDS",
            "HEX-PUB-ATP-IDENTITY-DIAGNOSTICS",
            "HEX-PUB-PROOF-CONTENT-ID",
            "HEX-PUB-ATP-REPAIR-AUTH-DOMAIN",
            "HEX-PUB-BONDED-AUTH-KEY",
        ],
        "public surface",
    )?;
    if public
        .iter()
        .any(|row| text(row, "state") != "PRESENT" || text(row, "owner") != "asupersync-d24mms.9.3")
    {
        return Err("public surface state or owner drifted".to_owned());
    }

    let collisions = array(inventory, "manual_collision_surfaces");
    require_exact_ids(
        collisions,
        "surface_id",
        &[
            "HEX-COLLISION-PLAN-HASH",
            "HEX-COLLISION-PROOF-HASH",
            "HEX-COLLISION-DIST-TRACE-ID",
            "HEX-COLLISION-COLOR",
            "HEX-COLLISION-TRANSPORT-COMMON",
            "HEX-COLLISION-FIXED-ID-ENCODERS",
            "HEX-COLLISION-TLS-SHORT",
            "HEX-COLLISION-EXAMPLE-BENCH-HELPERS",
        ],
        "manual collision surfaces",
    )?;
    if collisions
        .iter()
        .any(|row| text(row, "state") != "PRESENT" || text(row, "disposition").is_empty())
    {
        return Err("manual collision disposition drifted".to_owned());
    }

    let formats = array(inventory, "persisted_and_wire_formats");
    require_exact_ids(
        formats,
        "format_id",
        &[
            "HEX-FMT-W3C-TRACEPARENT",
            "HEX-FMT-POSTGRES-BYTEA",
            "HEX-FMT-MAILBOX-PEER-ID",
            "HEX-FMT-MAILBOX-TRANSFER-ID",
            "HEX-FMT-MAILBOX-SHA256",
            "HEX-FMT-ATP-DETACHED-SIGNATURE",
            "HEX-FMT-BONDED-AUTH-DESCRIPTOR",
            "HEX-FMT-ATP-DELTA-ROOTS",
            "HEX-FMT-ATP-OBJECT-MANIFEST-STATE",
            "HEX-FMT-ATP-SYNC-PROOFS",
            "HEX-FMT-ATP-STREAM-CONSUMER-SIGNATURE",
            "HEX-FMT-ATP-GRANT-STATE",
            "HEX-FMT-ATP-SESSION-STATE",
            "HEX-FMT-ATP-HANDSHAKE-TRACE",
            "HEX-FMT-ATP-REPAIR-AUTH-DOMAIN",
            "HEX-FMT-ATP-LAB-ARTIFACTS",
            "HEX-FMT-CLI-WORKFLOW-ARTIFACTS",
            "HEX-FMT-KEYS-SIGNATURES-EVIDENCE",
            "HEX-FMT-GOLDEN-EVIDENCE-DIGESTS",
        ],
        "persisted and wire formats",
    )?;
    if formats.iter().any(|row| {
        text(row, "state") != "PRESENT"
            || text(row, "owner") != "asupersync-d24mms.9.3"
            || text(row, "journey_owner") != "asupersync-d24mms.9.4"
    }) {
        return Err("persisted format state or ownership drifted".to_owned());
    }

    let pin_paths = row_ids(array(inventory, "source_pins"), "path");
    for row in public.iter().chain(collisions).chain(formats) {
        for key in ["source_paths", "paths"] {
            if let Some(paths) = row.get(key) {
                for path in value_array(paths, key) {
                    let path = path.as_str().expect("semantic source path must be text");
                    if path.starts_with("src/")
                        || path.starts_with("tests/")
                        || path.starts_with("examples/")
                        || path.starts_with("benches/")
                    {
                        if !pin_paths.contains(path) {
                            return Err(format!("semantic source path is not pinned: {path}"));
                        }
                    }
                }
            }
        }
    }

    let gaps = array(inventory, "gaps");
    let expected_gap_ids: Vec<String> = (1..=15)
        .map(|suffix| format!("HEX-A1-GAP-{suffix:02}"))
        .collect();
    let expected_gap_refs: Vec<&str> = expected_gap_ids.iter().map(String::as_str).collect();
    require_exact_ids(gaps, "gap_id", &expected_gap_refs, "routed gaps")?;
    if gaps
        .iter()
        .any(|gap| text(gap, "state") != "ROUTED" || text(gap, "owner").is_empty())
    {
        return Err("every gap must be routed to an owner".to_owned());
    }
    let expected_gap_owners = BTreeMap::from([
        (
            "HEX-A1-GAP-01".to_owned(),
            "asupersync-d24mms.9.5".to_owned(),
        ),
        (
            "HEX-A1-GAP-02".to_owned(),
            "asupersync-d24mms.9.5".to_owned(),
        ),
        (
            "HEX-A1-GAP-03".to_owned(),
            "asupersync-d24mms.9.2".to_owned(),
        ),
        (
            "HEX-A1-GAP-04".to_owned(),
            "asupersync-d24mms.9.4".to_owned(),
        ),
        (
            "HEX-A1-GAP-05".to_owned(),
            "asupersync-d24mms.9.4".to_owned(),
        ),
        (
            "HEX-A1-GAP-06".to_owned(),
            "asupersync-d24mms.9.3".to_owned(),
        ),
        (
            "HEX-A1-GAP-07".to_owned(),
            "asupersync-d24mms.9.4".to_owned(),
        ),
        (
            "HEX-A1-GAP-08".to_owned(),
            "asupersync-d24mms.9.5".to_owned(),
        ),
        (
            "HEX-A1-GAP-09".to_owned(),
            "asupersync-d24mms.9.3".to_owned(),
        ),
        (
            "HEX-A1-GAP-10".to_owned(),
            "asupersync-d24mms.9.2".to_owned(),
        ),
        (
            "HEX-A1-GAP-11".to_owned(),
            "asupersync-d24mms.9.2".to_owned(),
        ),
        (
            "HEX-A1-GAP-12".to_owned(),
            "asupersync-d24mms.9.4".to_owned(),
        ),
        (
            "HEX-A1-GAP-13".to_owned(),
            "asupersync-d24mms.9.3".to_owned(),
        ),
        (
            "HEX-A1-GAP-14".to_owned(),
            "asupersync-d24mms.9.5".to_owned(),
        ),
        (
            "HEX-A1-GAP-15".to_owned(),
            "asupersync-d24mms.9.3".to_owned(),
        ),
    ]);
    if owner_map(gaps, "gap_id") != expected_gap_owners {
        return Err("routed gap owner map drifted".to_owned());
    }

    let downstream = object(inventory, "downstream_and_e2e");
    for (key, expected) in [
        ("unit_owner", "asupersync-d24mms.9.2"),
        ("migration_owner", "asupersync-d24mms.9.3"),
        ("journey_owner", "asupersync-d24mms.9.4"),
        ("cutover_owner", "asupersync-d24mms.9.5"),
        ("a1_execution_state", "NOT_RUN_BY_A1"),
    ] {
        if downstream.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("downstream_and_e2e.{key} drifted"));
        }
    }
    let downstream_value = inventory
        .get("downstream_and_e2e")
        .expect("downstream_and_e2e required");
    let registry_scenarios = array(downstream_value, "registry_scenarios");
    require_exact_ids(
        registry_scenarios,
        "scenario_id",
        &["hex_public_api", "hex_protocol_artifact", "hex_protocols"],
        "registry scenarios",
    )?;
    if registry_scenarios.iter().any(|row| {
        text(row, "state") != "PLANNED"
            || text(row, "runner_registration") != "ABSENT"
            || text(row, "owner") != "asupersync-d24mms.9.4"
    }) {
        return Err("registry scenario routing drifted".to_owned());
    }
    let matrix_scenarios = array(downstream_value, "matrix_scenarios");
    require_exact_ids(
        matrix_scenarios,
        "scenario_id",
        &[
            "dep-sovereignty-asupersync_d24mms_9_1_4939213e52e5",
            "dep-sovereignty-asupersync_d24mms_9_3_a9d28abfe142",
            "dep-sovereignty-asupersync_d24mms_9_4_662600494c81",
            "dep-sovereignty-asupersync_d24mms_9_5_392fdc9ab884",
        ],
        "matrix scenarios",
    )?;
    let expected_matrix_owners = BTreeMap::from([
        (
            "dep-sovereignty-asupersync_d24mms_9_1_4939213e52e5".to_owned(),
            "asupersync-d24mms.9.1".to_owned(),
        ),
        (
            "dep-sovereignty-asupersync_d24mms_9_3_a9d28abfe142".to_owned(),
            "asupersync-d24mms.9.3".to_owned(),
        ),
        (
            "dep-sovereignty-asupersync_d24mms_9_4_662600494c81".to_owned(),
            "asupersync-d24mms.9.4".to_owned(),
        ),
        (
            "dep-sovereignty-asupersync_d24mms_9_5_392fdc9ab884".to_owned(),
            "asupersync-d24mms.9.5".to_owned(),
        ),
    ]);
    if owner_map(matrix_scenarios, "scenario_id") != expected_matrix_owners
        || matrix_scenarios
            .iter()
            .any(|row| text(row, "state") != "PLANNED")
    {
        return Err("matrix scenario owner or state drifted".to_owned());
    }
    let rollback = value_array(
        inventory
            .get("rollback_triggers")
            .ok_or_else(|| "rollback_triggers required".to_owned())?,
        "rollback_triggers",
    );
    let rollback_unique: BTreeSet<_> = rollback
        .iter()
        .map(|row| row.as_str().expect("rollback trigger must be text"))
        .collect();
    if rollback.len() != 10 || rollback_unique.len() != 10 {
        return Err("rollback trigger set must retain 10 unique rows".to_owned());
    }

    let projection = claims_projection(inventory);
    let projection_bytes = canonical_json_bytes(&projection);
    if sha256_hex(&projection_bytes) != CLAIMS_PROJECTION_SHA256 {
        return Err("exact claims projection drifted".to_owned());
    }
    Ok(())
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry must be readable"))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to stat {}: {error}", entry.path().display()));
        if file_type.is_dir() {
            collect_rust_files(&entry.path(), files);
        } else if file_type.is_file()
            && entry.path().extension().and_then(|ext| ext.to_str()) == Some("rs")
        {
            files.push(entry.path());
        }
    }
}

fn source_symbol_map(contents: &str) -> BTreeMap<String, u64> {
    let mut symbols = BTreeMap::new();
    let mut cursor = 0;
    while let Some(relative) = contents[cursor..].find(PATH_TOKEN) {
        let symbol_start = cursor + relative + PATH_TOKEN.len();
        let symbol: String = contents[symbol_start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if !symbol.is_empty() {
            *symbols.entry(symbol.clone()).or_default() += 1;
        }
        cursor = symbol_start + symbol.len();
    }
    symbols
}

fn source_census() -> BTreeMap<String, BTreeMap<String, u64>> {
    let mut files = Vec::new();
    for root in ["src", "tests", "examples", "benches", "conformance", "fuzz"] {
        collect_rust_files(&repo_root().join(root), &mut files);
    }
    let mut census = BTreeMap::new();
    for path in files {
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let symbols = source_symbol_map(&contents);
        if !symbols.is_empty() {
            let relative = path
                .strip_prefix(repo_root())
                .expect("scanned path must be under the repository");
            census.insert(relative.to_string_lossy().replace('\\', "/"), symbols);
        }
    }
    census
}

fn expected_group(path: &str) -> &'static str {
    const TEST_MODULES: &[&str] = &[
        "src/atp/cache_seeding_integration_tests.rs",
        "src/codec/hex.rs",
        "src/deterministic_state_golden_tests.rs",
        "src/golden_artifacts_tests.rs",
        "src/observability/span_id_collision_audit_test.rs",
        "src/observability/w3c_trace_id_randomness_audit_test.rs",
        "src/protocol_serialization_golden_tests.rs",
        "src/public_api_golden_tests.rs",
    ];
    const SECURITY_OBSERVABILITY: &[&str] = &[
        "src/agent_swarm/control_plane.rs",
        "src/agent_swarm/handoff_verifier.rs",
        "src/distributed/consensus/types.rs",
        "src/lab/crashpack/mod.rs",
        "src/lab/crashpack/replay.rs",
        "src/observability/w3c_trace_context.rs",
        "src/security/keys/mod.rs",
        "src/test_logging.rs",
        "src/trace/crashpack.rs",
    ];

    if path.starts_with("tests/")
        || path.starts_with("conformance/")
        || TEST_MODULES.contains(&path)
    {
        "HEX-A3-TEST-CONFORMANCE"
    } else if path == "src/database/postgres.rs" {
        "HEX-A3-DATABASE"
    } else if path.starts_with("src/atp/")
        || path.starts_with("src/net/atp/")
        || matches!(path, "src/bin/atp.rs" | "src/cli/atp_workflows.rs")
    {
        "HEX-A3-ATP-PROTOCOL-CLI"
    } else if SECURITY_OBSERVABILITY.contains(&path) {
        "HEX-A3-SECURITY-OBSERVABILITY"
    } else {
        panic!("unclassified direct path {path}")
    }
}

fn expected_artifact_census(inventory: &Value) -> BTreeMap<String, BTreeMap<String, u64>> {
    array(inventory, "call_sites")
        .iter()
        .map(|row| (text(row, "path").to_owned(), combined_symbol_map(row)))
        .collect()
}

#[test]
fn inventory_is_fail_closed_and_fully_owned() {
    let inventory = artifact();
    validate_inventory(&inventory).expect("canonical inventory must validate");

    let mut unknown = inventory.clone();
    unknown["gaps"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());

    let mut missing = inventory.clone();
    missing["call_sites"]
        .as_array_mut()
        .expect("call_sites array")
        .pop();
    assert!(validate_inventory(&missing).is_err());

    let mut duplicate_gap = inventory.clone();
    let first_gap = duplicate_gap["gaps"][0].clone();
    duplicate_gap["gaps"][13] = first_gap;
    assert!(validate_inventory(&duplicate_gap).is_err());

    let mut semantic_drift = inventory.clone();
    semantic_drift["semantic_corpus"][0]["expected"] = Value::String("00".to_owned());
    assert!(validate_inventory(&semantic_drift).is_err());
}

#[test]
fn source_pins_match_exact_bytes_and_line_counts() {
    let inventory = artifact();
    let pins = array(&inventory, "source_pins");
    assert_eq!(pins.len(), 81);
    let paths = row_ids(pins, "path");
    assert_eq!(paths.len(), 81, "source pin paths must be unique");
    let mut projection = String::new();
    for path in &paths {
        projection.push_str(path);
        projection.push('\n');
    }
    assert_eq!(
        sha256_hex(projection.as_bytes()),
        SOURCE_PIN_PATHS_SHA256,
        "source pin path set drifted"
    );
    for pin in pins {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source pin hash drifted for {path}"
        );
        let contents = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("{path} must remain UTF-8: {error}"));
        assert_eq!(
            contents.lines().count() as u64,
            pin.get("line_count")
                .and_then(Value::as_u64)
                .expect("line_count must be u64"),
            "source pin line count drifted for {path}"
        );
    }
}

#[test]
fn complete_direct_path_census_matches_source() {
    let inventory = artifact();
    let actual = source_census();
    let expected = expected_artifact_census(&inventory);
    assert_eq!(actual, expected);

    let mut lexical_symbols = BTreeMap::<String, u64>::new();
    for symbols in actual.values() {
        for (name, count) in symbols {
            *lexical_symbols.entry(name.clone()).or_default() += count;
        }
    }
    assert_eq!(actual.len(), 104);
    assert_eq!(lexical_symbols.values().sum::<u64>(), 253);
    assert_eq!(
        lexical_symbols,
        BTreeMap::from([
            ("FromHexError".to_owned(), 4),
            ("decode".to_owned(), 36),
            ("decode_to_slice".to_owned(), 11),
            ("encode".to_owned(), 201),
            ("tests".to_owned(), 1),
        ])
    );

    let code_symbols = array(&inventory, "call_sites")
        .iter()
        .flat_map(|row| symbol_map(row, "symbols"))
        .fold(
            BTreeMap::<String, u64>::new(),
            |mut totals, (name, count)| {
                *totals.entry(name).or_default() += count;
                totals
            },
        );
    assert_eq!(code_symbols.values().sum::<u64>(), 250);
    assert_eq!(code_symbols.get("decode"), Some(&34));
}

#[test]
fn reservation_groups_are_disjoint_complete_and_digest_pinned() {
    let inventory = artifact();
    let actual = source_census();
    let call_sites: BTreeMap<_, _> = array(&inventory, "call_sites")
        .iter()
        .map(|row| (text(row, "path"), row))
        .collect();
    let mut projections = BTreeMap::<String, String>::new();
    let mut counts = BTreeMap::<String, (u64, u64)>::new();

    for (path, symbols) in &actual {
        let group = expected_group(path);
        let row = call_sites
            .get(path.as_str())
            .unwrap_or_else(|| panic!("missing call-site row for {path}"));
        assert_eq!(text(row, "group_id"), group);
        projections
            .entry(group.to_owned())
            .or_default()
            .push_str(&format!("{path}\t{}\n", symbol_total(symbols)));
        let entry = counts.entry(group.to_owned()).or_default();
        entry.0 += 1;
        entry.1 += symbol_total(symbols);
    }

    for group in array(&inventory, "migration_reservation_groups") {
        let group_id = text(group, "group_id");
        let (files, tokens) = counts
            .get(group_id)
            .copied()
            .unwrap_or_else(|| panic!("missing computed group {group_id}"));
        assert_eq!(group.get("files").and_then(Value::as_u64), Some(files));
        assert_eq!(
            group.get("lexical_tokens").and_then(Value::as_u64),
            Some(tokens)
        );
        assert_eq!(
            sha256_hex(
                projections
                    .get(group_id)
                    .expect("group projection")
                    .as_bytes()
            ),
            text(group, "projection_sha256")
        );
    }
    assert_eq!(counts.values().map(|row| row.0).sum::<u64>(), 104);
    assert_eq!(counts.values().map(|row| row.1).sum::<u64>(), 253);
}

#[test]
fn comments_and_disabled_rows_remain_separate_from_active_behavior() {
    let inventory = artifact();
    let census = object(&inventory, "occurrence_census");
    let comment_rows = value_array(
        census
            .get("comment_references")
            .expect("comment_references required"),
        "comment_references",
    );
    let disabled_rows = value_array(
        census
            .get("cfg_any_disabled_references")
            .expect("cfg_any_disabled_references required"),
        "cfg_any_disabled_references",
    );
    let cfg_test_rows = value_array(
        census
            .get("cfg_test_embedded_files")
            .expect("cfg_test_embedded_files required"),
        "cfg_test_embedded_files",
    );
    assert_eq!(comment_rows.len(), 3);
    assert_eq!(disabled_rows.len(), 4);
    assert_eq!(cfg_test_rows.len(), 5);

    let comment_keys: BTreeSet<_> = comment_rows
        .iter()
        .map(|row| {
            (
                text(row, "path").to_owned(),
                row.get("line").and_then(Value::as_u64).expect("line"),
                text(row, "symbol").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        comment_keys,
        BTreeSet::from([
            ("src/codec/hex.rs".to_owned(), 296, "tests".to_owned()),
            (
                "src/database/postgres.rs".to_owned(),
                12_714,
                "decode".to_owned()
            ),
            (
                "src/observability/w3c_trace_context.rs".to_owned(),
                576,
                "decode".to_owned()
            ),
        ])
    );
    let disabled_keys: BTreeSet<_> = disabled_rows
        .iter()
        .map(|row| {
            (
                text(row, "path").to_owned(),
                row.get("line").and_then(Value::as_u64).expect("line"),
                text(row, "symbol").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        disabled_keys,
        BTreeSet::from([
            ("src/bin/atp.rs".to_owned(), 7_810, "encode".to_owned()),
            ("src/bin/atp.rs".to_owned(), 7_992, "encode".to_owned()),
            ("src/bin/atp.rs".to_owned(), 8_009, "decode".to_owned()),
            (
                "src/net/atp/transport_tcp/mod.rs".to_owned(),
                569,
                "decode_to_slice".to_owned(),
            ),
        ])
    );

    let call_site_cfg_test_total: u64 = array(&inventory, "call_sites")
        .iter()
        .map(|row| symbol_total(&symbol_map(row, "cfg_test_symbols")))
        .sum();
    let census_cfg_test_total: u64 = cfg_test_rows
        .iter()
        .map(|row| symbol_total(&symbol_map(row, "symbols")))
        .sum();
    assert_eq!(call_site_cfg_test_total, 25);
    assert_eq!(census_cfg_test_total, 25);

    let call_site_disabled_total: u64 = array(&inventory, "call_sites")
        .iter()
        .map(|row| symbol_total(&symbol_map(row, "cfg_any_disabled_symbols")))
        .sum();
    let test_conformance_total: u64 = array(&inventory, "call_sites")
        .iter()
        .filter(|row| text(row, "group_id") == "HEX-A3-TEST-CONFORMANCE")
        .map(|row| symbol_total(&symbol_map(row, "symbols")))
        .sum();
    assert_eq!(call_site_disabled_total, 4);
    assert_eq!(test_conformance_total, 124);

    let logging = find_row(
        array(&inventory, "call_sites"),
        "path",
        "src/test_logging.rs",
    );
    assert_eq!(text(logging, "profile"), "test-or-test-internals");
    assert_eq!(
        text(logging, "module_gate"),
        "cfg(any(test, feature = test-internals))"
    );
    assert_eq!(symbol_total(&symbol_map(logging, "symbols")), 2);
    assert_eq!(250 - test_conformance_total - 25 - 2 - 4, 95);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn public_object_hash_freezes_external_error_behavior() {
    let bytes = [0xab; 32];
    let hash = ObjectHash::new(bytes);
    assert_eq!(hash.hex(), "ab".repeat(32));
    assert_eq!(
        ObjectHash::from_hex(&"AB".repeat(32))
            .expect("mixed uppercase must decode")
            .as_bytes(),
        &bytes
    );
    assert_eq!(
        ObjectHash::from_hex("0g")
            .expect_err("invalid low nibble must fail")
            .to_string(),
        "Invalid character 'g' at position 1"
    );
    assert_eq!(
        ObjectHash::from_hex("g")
            .expect_err("odd length must win")
            .to_string(),
        "Odd number of digits"
    );
    assert_eq!(
        ObjectHash::from_hex("")
            .expect_err("empty decoded length is not an object hash")
            .to_string(),
        "Invalid string length"
    );
}

#[test]
fn governance_sources_confirm_every_routed_gap() {
    let registry = parse_repo_json(REGISTRY_PATH);
    let registry_row = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(registry_row, "evidence_state"), "BASELINE_PLANNED");
    assert!(
        string_set(registry_row, "source_owners").contains("src/encoding.rs"),
        "the routed stale source owner must remain visible"
    );
    assert_eq!(
        string_set(registry_row, "features"),
        ["cli", "default", "sqlite", "tls"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        text(baseline_row, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert!(array(baseline_row, "downstream_profiles").is_empty());

    let matrix = parse_repo_json(MATRIX_PATH);
    for scenario in [
        "dep-sovereignty-asupersync_d24mms_9_1_4939213e52e5",
        "dep-sovereignty-asupersync_d24mms_9_3_a9d28abfe142",
        "dep-sovereignty-asupersync_d24mms_9_4_662600494c81",
        "dep-sovereignty-asupersync_d24mms_9_5_392fdc9ab884",
    ] {
        let mut rows = Vec::new();
        collect_objects_with_text_field(&matrix, "scenario_id", scenario, &mut rows);
        assert_eq!(rows.len(), 1, "matrix scenario {scenario} must be unique");
        let row = rows[0];
        assert_eq!(row.get("no_mock").and_then(Value::as_bool), Some(true));
        assert_eq!(
            text(row, "aggregate_owner"),
            "asupersync-dep-p1-foundations-upksjk.6.2"
        );
        assert_eq!(array(row, "required_artifacts").len(), 4);
    }

    let runner = read_repo_file(RUNNER_PATH);
    for alias in ["hex_public_api", "hex_protocol_artifact", "hex_protocols"] {
        assert!(
            !runner.contains(alias),
            "{alias} is now registered; refresh A1"
        );
    }
    let api_map = read_repo_file(API_MAP_PATH);
    assert!(!api_map.contains("ObjectHash"));

    let direct_declaration = format!("{} = ", PATH_TOKEN.trim_end_matches("::"));
    let conformance_manifest = read_repo_file(CONFORMANCE_MANIFEST_PATH);
    assert!(
        !conformance_manifest.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&direct_declaration)
        }),
        "{CONFORMANCE_MANIFEST_PATH} direct dependency gap was resolved; refresh A1"
    );

    let nested_lib = read_repo_file(NESTED_CONFORMANCE_LIB_PATH);
    let nested_mod = read_repo_file(NESTED_CONFORMANCE_MOD_PATH);
    assert!(!nested_lib.contains("golden_file_manager_simple"));
    assert!(!nested_lib.contains("#[path = \"mod.rs\"]"));
    assert!(nested_mod.contains("pub mod golden_file_manager_simple;"));

    let root_manifest = read_repo_file("Cargo.toml");
    let kafka_start = root_manifest
        .find("name = \"kafka_real_broker\"")
        .expect("kafka test target must remain declared");
    let kafka_tail = &root_manifest[kafka_start..];
    let kafka_end = kafka_tail.find("\n[[").unwrap_or(kafka_tail.len());
    let kafka_section = &kafka_tail[..kafka_end];
    assert!(kafka_section.contains("path = \"tests/integration/kafka_real_broker.rs\""));
    assert!(!kafka_section.contains("required-features"));
}

#[test]
fn documentation_and_ignore_boundary_are_discoverable() {
    let doc = read_repo_file(DOC_PATH);
    assert!(doc.contains(DOC_BEGIN));
    assert!(doc.contains(DOC_END));
    for required in [
        ARTIFACT_PATH,
        BEAD_ID,
        CAPABILITY_ID,
        "KEEP_INCUMBENT",
        "HEX-A3-ATP-PROTOCOL-CLI",
        "HEX-A3-SECURITY-OBSERVABILITY",
        "HEX-A3-DATABASE",
        "HEX-A3-TEST-CONFORMANCE",
        "ObjectHash::from_hex",
        "W3CSpanId",
        "nineteen format families",
        "HEX-A1-GAP-13",
        "HEX-A1-GAP-14",
        "HEX-A1-GAP-15",
        "EVD-HEX-GOLDENS",
        "NOT_RUN_BY_A1",
    ] {
        assert!(doc.contains(required), "documentation missing {required}");
    }

    let ignore = read_repo_file(IGNORE_PATH);
    assert!(
        ignore
            .lines()
            .any(|line| line == "!artifacts/hex_capability_inventory_v1.json")
    );
}

#[test]
fn no_claim_boundary_remains_explicit() {
    let inventory = artifact();
    let boundaries = array(&inventory, "no_claim_boundaries");
    assert_eq!(boundaries.len(), 10);
    let joined = boundaries
        .iter()
        .map(|row| row.as_str().expect("boundary must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "does not authorize",
        "No Cargo",
        "do not prove compilation",
        "No performance",
        "conformance manifest gap",
        "not terminal execution evidence",
        "Broad workspace health",
    ] {
        assert!(
            joined.contains(required),
            "missing no-claim phrase {required}"
        );
    }
}
