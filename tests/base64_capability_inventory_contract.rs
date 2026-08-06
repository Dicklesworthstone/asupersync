//! Fail-closed static contract for the source-pinned Base64 capability inventory.
//!
//! Bead: asupersync-d24mms.10.1
//! Fixture: artifacts/base64_capability_inventory_v1.json
//!
//! This contract checks inventory structure and repository source projection.
//! It does not execute codec behavior and performs no external process,
//! network, timing, or environment-dependent work.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/base64_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/base64_capability_inventory.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const MATRIX_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const ROOT_MANIFEST_PATH: &str = "Cargo.toml";
const FUZZ_MANIFEST_PATH: &str = "fuzz/Cargo.toml";
const RAPTORQ_MANIFEST_PATH: &str = "tests/conformance/raptorq_differential/Cargo.toml";
const IGNORE_PATH: &str = ".gitignore";
const ARTIFACT_ID: &str = "base64-capability-inventory-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-d24mms.10.1";
const CAPABILITY_ID: &str = "CAP-BASE64-CODEC";
const AUTHORITY_REVISION: &str = "470dab2839742dc36cbb1241ff219e1c8d2f451b";
const DOC_BEGIN: &str = "<!-- BEGIN BASE64 CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END BASE64 CAPABILITY INVENTORY -->";
const PATH_TOKEN: &str = concat!("base", "64::");
const SOURCE_PIN_PATHS_SHA256: &str =
    "996efa7ae8c2105ab6d8a059f8cafef646c323e1791e40895becc43f68157fe4";
const RECORDED_OPERATION_SEMANTICS_SHA256: &str =
    "bddb32296014409a7237fb9cd68ebc94a4eb538ca47fbaa22a6d4aa2b0217b5d";
const CLAIMS_PROJECTION_SHA256: &str =
    "067fce80f3a0289e540f0e0847aba0c64786a4657fc9d8fd9fabc0952f8e1610";

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

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
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

fn require_exact_strings(value: &Value, key: &str, expected: &[&str]) -> Result<(), String> {
    let expected: BTreeSet<String> = expected.iter().map(|item| (*item).to_owned()).collect();
    if array(value, key).len() != expected.len() || string_set(value, key) != expected {
        return Err(format!("{key} exact unique string set drifted"));
    }
    Ok(())
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
        "capability_ids": inventory["capability_ids"].clone(),
        "authority": inventory["authority"].clone(),
        "policy": inventory["policy"].clone(),
        "static_refresh_receipt": inventory["static_refresh_receipt"].clone(),
        "source_pin_scope": inventory["source_pin_scope"].clone(),
        "source_pins": inventory["source_pins"].clone(),
        "dependency_resolution": inventory["dependency_resolution"].clone(),
        "engines": inventory["engines"].clone(),
        "incumbent_api": inventory["incumbent_api"].clone(),
        "decode_error_contract": inventory["decode_error_contract"].clone(),
        "security_roles": inventory["security_roles"].clone(),
        "owned_error_mappings": inventory["owned_error_mappings"].clone(),
        "operation_matrix_progress": inventory["operation_matrix_progress"].clone(),
        "operation_contracts": inventory["operation_contracts"].clone(),
        "nonpublic_consumer_relations": inventory["nonpublic_consumer_relations"].clone(),
        "semantic_vector_authority": inventory["semantic_vector_authority"].clone(),
        "semantic_corpus": inventory["semantic_corpus"].clone(),
        "call_compilation_profiles": inventory["call_compilation_profiles"].clone(),
        "profile_gate_contracts": inventory["profile_gate_contracts"].clone(),
        "profile_baseline_relations": inventory["profile_baseline_relations"].clone(),
        "occurrence_census": inventory["occurrence_census"].clone(),
        "call_sites": inventory["call_sites"].clone(),
        "migration_reservation_groups": inventory["migration_reservation_groups"].clone(),
        "public_surface": inventory["public_surface"].clone(),
        "manual_collision_surfaces": inventory["manual_collision_surfaces"].clone(),
        "downstream_and_e2e": inventory["downstream_and_e2e"].clone(),
        "gaps": inventory["gaps"].clone(),
        "rollback_triggers": inventory["rollback_triggers"].clone(),
        "no_claim_boundaries": inventory["no_claim_boundaries"].clone(),
    })
}

fn contains_unknown_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains("UNKNOWN"),
        Value::Array(values) => values.iter().any(contains_unknown_value),
        Value::Object(values) => values.values().any(contains_unknown_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn sum_nested(rows: &[Value], section: &str, key: &str) -> u64 {
    rows.iter()
        .map(|row| {
            row.get(section)
                .and_then(Value::as_object)
                .and_then(|values| values.get(key))
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{section}.{key} must be an unsigned integer"))
        })
        .sum()
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1)
        || text(inventory, "artifact_id") != ARTIFACT_ID
        || text(inventory, "program_id") != PROGRAM_ID
        || text(inventory, "bead_id") != BEAD_ID
        || text(inventory, "capability_id") != CAPABILITY_ID
        || text(inventory, "captured_date_utc") != "2026-08-06"
        || text(inventory, "authority_revision") != AUTHORITY_REVISION
    {
        return Err("inventory identity drifted".to_owned());
    }
    if contains_unknown_value(inventory) {
        return Err("inventory contains an UNKNOWN value".to_owned());
    }
    require_exact_strings(
        inventory,
        "capability_ids",
        &["CAP-AUTH-CREDENTIALS", "CAP-BASE64-CODEC"],
    )?;

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("a1_execution_state").and_then(Value::as_str) != Some("NOT_RUN_BY_A1")
    {
        return Err("zero-UNKNOWN or A1 execution policy drifted".to_owned());
    }
    let refresh = object(inventory, "static_refresh_receipt");
    if refresh
        .get("previous_authority_revision")
        .and_then(Value::as_str)
        != Some("7bb939ab2d18c1c102671809cf74b922d2ed0437")
        || refresh
            .get("current_authority_revision")
            .and_then(Value::as_str)
            != Some(AUTHORITY_REVISION)
        || refresh.get("review_method").and_then(Value::as_str) != Some("SOURCE_ONLY_NO_EXECUTION")
        || refresh
            .get("direct_rust_census_state")
            .and_then(Value::as_str)
            != Some("UNCHANGED_36_PATHS_166_TOKENS")
        || refresh.get("execution_state").and_then(Value::as_str) != Some("NOT_RUN_BY_A1")
    {
        return Err("static refresh receipt drifted".to_owned());
    }
    require_exact_strings(
        &inventory["static_refresh_receipt"],
        "changed_source_pin_paths",
        &[
            "artifacts/dependency_capability_baseline_v1.json",
            "src/database/postgres.rs",
            "src/grpc/server.rs",
            "src/grpc/status.rs",
            "src/grpc/web.rs",
            "src/io/browser_storage.rs",
            "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
        ],
    )?;
    require_exact_strings(
        &inventory["static_refresh_receipt"],
        "added_source_pin_paths",
        &[
            ".gitignore",
            "asupersync-wasm/Cargo.toml",
            "asupersync-wasm/src/lib.rs",
            "fuzz/create_postgres_scram_seeds.py",
            "fuzz/create_tls_seeds.py",
            "tests/wasm_service_worker_broker_contract.rs",
        ],
    )?;
    require_exact_strings(
        &inventory["static_refresh_receipt"],
        "removed_nonrepository_pin_paths",
        &["fuzz/Cargo.lock"],
    )?;
    let authority = object(inventory, "authority");
    if authority.get("current_action").and_then(Value::as_str) != Some("KEEP_INCUMBENT")
        || authority.get("cutover_state").and_then(Value::as_str)
            != Some("BLOCKED_PENDING_EVIDENCE")
        || authority
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("authority disposition drifted".to_owned());
    }

    let source_scope = object(inventory, "source_pin_scope");
    if source_scope.get("path_count").and_then(Value::as_u64) != Some(75)
        || source_scope.get("paths_sha256").and_then(Value::as_str) != Some(SOURCE_PIN_PATHS_SHA256)
        || array(inventory, "source_pins").len() != 75
    {
        return Err("source-pin scope drifted".to_owned());
    }
    require_exact_strings(
        &inventory["source_pin_scope"],
        "excluded_generated_paths",
        &["asupersync-wasm/Cargo.lock", "fuzz/Cargo.lock"],
    )?;

    let resolution = object(inventory, "dependency_resolution");
    if resolution["root"]["manifest_requirement"].as_str() != Some("0.23")
        || resolution["root"]["resolved_version"].as_str() != Some("0.23.0")
        || resolution["root"]["default_features"].as_bool() != Some(false)
        || resolution["root_transitive_retained"]["resolved_version"].as_str() != Some("0.22.1")
        || resolution["root_transitive_retained"]["direct_0_23_edge_removal_effect"].as_str()
            != Some("DOES_NOT_REMOVE_ALL_BASE64_PACKAGES_FROM_ROOT_LOCKED_GRAPH")
        || resolution["excluded_fuzz_workspace"]["repository_lock_state"].as_str()
            != Some("ABSENT_IGNORED")
        || resolution["excluded_fuzz_workspace"]["local_snapshot"]["state"].as_str()
            != Some("OBSERVED_NOT_REPOSITORY_PINNED")
        || resolution["excluded_fuzz_workspace"]["local_snapshot"]["resolved_version"].as_str()
            != Some("0.22.1")
        || resolution["excluded_wasm_scaffold"]["manifest_path_requirement"].as_str()
            != Some("asupersync ^0.3.5")
        || resolution["excluded_wasm_scaffold"]["current_path_package_version"].as_str()
            != Some("0.3.10")
        || resolution["excluded_wasm_scaffold"]["repository_lock_state"].as_str()
            != Some("ABSENT_IGNORED")
        || resolution["excluded_wasm_scaffold"]["local_snapshot"]["state"].as_str()
            != Some("STALE_OBSERVED_NOT_REPOSITORY_PINNED")
        || resolution["excluded_wasm_scaffold"]["local_snapshot"]["locked_asupersync_version"]
            .as_str()
            != Some("0.3.2")
        || resolution["excluded_wasm_scaffold"]["local_snapshot"]["locked_base64_version"].as_str()
            != Some("0.22.1")
        || resolution["excluded_wasm_scaffold"]["scope"].as_str()
            != Some("EXCLUDED_WORKSPACE_NOT_ROOT_PRODUCTION_GRAPH")
        || resolution["standalone_raptorq_workspace"]["resolved_version_state"].as_str()
            != Some("NOT_LOCKED_IN_REPOSITORY")
        || resolution["synthesized_consumer_profile_count"].as_u64() != Some(12)
        || resolution["workspace_dev_build_audit_profile_count"].as_u64() != Some(1)
        || resolution["canonical_ledger_cells"].as_u64() != Some(52)
    {
        return Err("dependency version or graph boundary drifted".to_owned());
    }
    require_exact_strings(
        &inventory["dependency_resolution"]["root_transitive_retained"],
        "consumers",
        &[
            "opentelemetry-proto@0.32.0",
            "sqlx-core@0.9.0",
            "tonic@0.14.6",
        ],
    )?;
    require_exact_strings(
        &inventory["dependency_resolution"],
        "canonical_ledger_profile_ids",
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
            "workspace-dev-build-audit",
        ],
    )?;
    require_exact_strings(
        &inventory["dependency_resolution"],
        "canonical_ledger_target_triples",
        &[
            "aarch64-apple-darwin",
            "wasm32-unknown-unknown",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ],
    )?;

    require_exact_ids(
        array(inventory, "engines"),
        "engine_id",
        &[
            "B64-ENGINE-STANDARD-PAD",
            "B64-ENGINE-STANDARD-NO-PAD",
            "B64-ENGINE-URL-SAFE-PAD",
            "B64-ENGINE-URL-SAFE-NO-PAD",
        ],
        "engines",
    )?;
    for engine in array(inventory, "engines") {
        if engine
            .get("rejects_nonzero_trailing_bits")
            .and_then(Value::as_bool)
            != Some(true)
            || engine.get("rejects_whitespace").and_then(Value::as_bool) != Some(true)
            || engine.get("empty_input").and_then(Value::as_str) != Some("ACCEPT_AS_EMPTY")
            || text(engine, "current_acceptance_rule").is_empty()
        {
            return Err(format!(
                "engine {} semantics drifted",
                text(engine, "engine_id")
            ));
        }
    }

    require_exact_strings(
        &inventory["decode_error_contract"],
        "root_0_23_variants",
        &[
            "InvalidByte(usize,u8)",
            "InvalidLength(usize)",
            "InvalidLastSymbol{offset,symbol,symbol_value}",
            "InvalidPadding",
        ],
    )?;
    require_exact_strings(
        &inventory["decode_error_contract"],
        "fuzz_and_possible_raptorq_0_22_variants",
        &[
            "InvalidByte(usize,u8)",
            "InvalidLength(usize)",
            "InvalidLastSymbol(usize,u8)",
            "InvalidPadding",
        ],
    )?;
    if inventory["decode_error_contract"]["public_upstream_error_exposure"].as_str()
        != Some("ABSENT")
    {
        return Err("upstream error exposure boundary drifted".to_owned());
    }
    require_exact_ids(
        array(inventory, "security_roles"),
        "role_id",
        &[
            "B64-ROLE-RUNTIME-PROFILE-SIGNATURE",
            "B64-ROLE-NATS-NONCE-SIGNATURE",
            "B64-ROLE-NATS-JWT-SEGMENT",
            "B64-ROLE-POSTGRES-SCRAM-NONCE",
            "B64-ROLE-POSTGRES-SCRAM-SALT",
            "B64-ROLE-POSTGRES-SCRAM-CHANNEL-BINDING",
            "B64-ROLE-POSTGRES-SCRAM-CLIENT-PROOF",
            "B64-ROLE-POSTGRES-SCRAM-SERVER-SIGNATURE",
            "B64-ROLE-POSTGRES-SCRAM-TEST-BOUNDARY",
            "B64-ROLE-TLS-SPKI-PIN",
            "B64-ROLE-TLS-CERT-PIN",
            "B64-ROLE-TLS-PIN-SERIALIZATION",
            "B64-ROLE-HTTP-ORIGIN-BASIC-CREDENTIALS",
            "B64-ROLE-HTTP-PROXY-BASIC-CREDENTIALS",
            "B64-ROLE-BROWSER-LOCALSTORAGE-ADDRESS",
            "B64-ROLE-BROWSER-LOCALSTORAGE-VALUE",
            "B64-ROLE-BROWSER-INDEXEDDB-ADDRESS",
            "B64-ROLE-WEBSOCKET-ACCEPT-DIGEST",
            "B64-ROLE-WEBSOCKET-CLIENT-KEY",
            "B64-ROLE-WEBSOCKET-TEST-BOUNDARY",
            "B64-ROLE-WEBSOCKET-DEBUG-UNVALIDATED-ACCEPT",
            "B64-ROLE-GRPC-SERVER-INBOUND-BINARY-METADATA",
            "B64-ROLE-GRPC-SERVER-OUTBOUND-BINARY-METADATA",
            "B64-ROLE-GRPC-SERVER-STATUS-DETAILS",
            "B64-ROLE-GRPC-STATUS-SNAPSHOT",
            "B64-ROLE-GRPC-WEB-TRAILER-BINARY-METADATA",
            "B64-ROLE-GRPC-WEB-TEXT-WHOLE",
            "B64-ROLE-GRPC-WEB-TEXT-STREAM",
            "B64-ROLE-GRPC-WEB-TEST-FIXTURE",
            "B64-ROLE-GRPC-FUZZ-BOUNDARY",
            "B64-ROLE-NATS-FUZZ-JWT",
            "B64-ROLE-POSTGRES-SCRAM-FUZZ",
            "B64-ROLE-POSTGRES-FOUR-ENGINE-ORACLE",
            "B64-ROLE-TLS-FUZZ-PEM",
            "B64-ROLE-ATP-DELTA-MANIFEST",
            "B64-ROLE-ATP-POWERSHELL-TRANSPORT",
            "B64-ROLE-DATABASE-LEGACY-SCRAM-FIXTURE",
            "B64-ROLE-H2C-SETTINGS-HEADER",
            "B64-ROLE-RAPTORQ-PERSISTED-FIXTURE",
            "B64-ROLE-TLS-PIN-TEST-BOUNDARY",
            "B64-ROLE-GRPC-CONFORMANCE-FIXTURE",
            "B64-ROLE-PERF-COMMAND-FIXTURE",
            "B64-ROLE-EXCLUDED-LOCAL-HELPER",
        ],
        "recorded operation security roles",
    )?;
    for role in array(inventory, "security_roles") {
        if text(role, "category").is_empty()
            || role
                .get("security_critical")
                .and_then(Value::as_bool)
                .is_none()
            || text(role, "description").is_empty()
        {
            return Err(format!(
                "security role {} is incomplete",
                text(role, "role_id")
            ));
        }
    }
    require_exact_ids(
        array(inventory, "owned_error_mappings"),
        "error_id",
        &[
            "B64-ERROR-INFALLIBLE-ENCODE",
            "B64-ERROR-RUNTIME-PROFILE-REFUSAL",
            "B64-ERROR-NATS-FALLBACK-SUPPRESSED",
            "B64-ERROR-NATS-INVALID-AUTH",
            "B64-ERROR-POSTGRES-AUTHENTICATION",
            "B64-ERROR-TEST-ASSERTION",
            "B64-ERROR-TLS-CERTIFICATE",
            "B64-ERROR-BROWSER-KEY-OMISSION",
            "B64-ERROR-BROWSER-VALUE-STRING",
            "B64-ERROR-WEBSOCKET-HANDSHAKE-INVALID-KEY",
            "B64-ERROR-WEBSOCKET-EXTRACTION-BAD-REQUEST",
            "B64-ERROR-GRPC-SERVER-FALLBACK-SUPPRESSED",
            "B64-ERROR-GRPC-SERVER-INVALID-METADATA",
            "B64-ERROR-GRPC-WEB-PROTOCOL",
            "B64-ERROR-FUZZ-DIAGNOSTIC",
            "B64-ERROR-FUZZ-POSTGRES-STRING",
            "B64-ERROR-ATP-CLI-STRING",
            "B64-ERROR-H3-WEBSOCKET-FIXTURE",
            "B64-ERROR-H2C-CONFORMANCE-STRING",
            "B64-ERROR-RAPTORQ-FIXTURE",
        ],
        "recorded operation owned error mappings",
    )?;
    for error in array(inventory, "owned_error_mappings") {
        if error.get("upstream_error_exposed").and_then(Value::as_bool) != Some(false)
            || text(error, "owned_boundary").is_empty()
            || text(error, "detail").is_empty()
        {
            return Err(format!(
                "owned error mapping {} is incomplete",
                text(error, "error_id")
            ));
        }
    }
    let vector_authority = object(inventory, "semantic_vector_authority");
    if vector_authority
        .get("positive_vectors")
        .and_then(Value::as_str)
        != Some("RFC 4648 section 10")
        || vector_authority
            .get("independence_boundary")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("semantic vector authority drifted".to_owned());
    }

    require_exact_ids(
        array(inventory, "call_compilation_profiles"),
        "profile_id",
        &[
            "B64-PROFILE-PORTABLE-LIBRARY",
            "B64-PROFILE-NATIVE-MESSAGING",
            "B64-PROFILE-NATIVE-GRPC",
            "B64-PROFILE-POSTGRES",
            "B64-PROFILE-WASM32-BROWSER",
            "B64-PROFILE-ATP-CLI",
            "B64-PROFILE-CFG-TEST",
            "B64-PROFILE-LEGACY-INTERNAL",
            "B64-PROFILE-H3-WEBSOCKET-E2E",
            "B64-PROFILE-UNWIRED-SOURCE",
            "B64-PROFILE-STANDALONE-RAPTORQ",
            "B64-PROFILE-EXCLUDED-FUZZ",
            "B64-PROFILE-EXCLUDED-WASM-SCAFFOLD",
            "B64-PROFILE-LOCAL-MOCK-OR-COMMENT",
        ],
        "compilation profiles",
    )?;
    let excluded_wasm_profile = array(inventory, "call_compilation_profiles")
        .iter()
        .find(|row| {
            row.get("profile_id").and_then(Value::as_str)
                == Some("B64-PROFILE-EXCLUDED-WASM-SCAFFOLD")
        })
        .ok_or_else(|| "excluded wasm profile is missing".to_owned())?;
    if excluded_wasm_profile.get("state").and_then(Value::as_str) != Some("PRESENT")
        || excluded_wasm_profile
            .get("profile_kind")
            .and_then(Value::as_str)
            != Some("DEPENDENCY_ONLY_NO_DIRECT_CALLS")
    {
        return Err("excluded wasm profile boundary drifted".to_owned());
    }

    let call_sites = array(inventory, "call_sites");
    let expected_call_ids: Vec<String> = (1..=36)
        .map(|index| format!("B64-CALL-{index:03}"))
        .collect();
    let expected_call_refs: Vec<&str> = expected_call_ids.iter().map(String::as_str).collect();
    require_exact_ids(call_sites, "call_id", &expected_call_refs, "call sites")?;

    let engine_ids = row_ids(array(inventory, "engines"), "engine_id");
    let profile_ids = row_ids(array(inventory, "call_compilation_profiles"), "profile_id");
    let mut paths = BTreeSet::new();
    for row in call_sites {
        let path = text(row, "path");
        if !paths.insert(path.to_owned()) {
            return Err(format!("duplicate call-site path {path}"));
        }
        if !profile_ids.contains(text(row, "profile")) {
            return Err(format!("unregistered profile at {path}"));
        }
        if text(row, "role").is_empty()
            || text(row, "error_mapping").is_empty()
            || text(row, "acceptance_rule").is_empty()
        {
            return Err(format!("unclassified role/error/acceptance at {path}"));
        }
        let row_engines = array(row, "engines");
        let classification = text(row, "classification");
        let external = !matches!(classification, "LOCAL_MOCK" | "COMMENT_ONLY");
        if external && row_engines.is_empty() {
            return Err(format!("external row {path} has no engine"));
        }
        if !external && !row_engines.is_empty() {
            return Err(format!("nonexternal row {path} names an engine"));
        }
        for engine in row_engines {
            let engine = engine
                .as_str()
                .ok_or_else(|| format!("engine id at {path} must be text"))?;
            if !engine_ids.contains(engine) {
                return Err(format!("unregistered engine {engine} at {path}"));
            }
        }
    }
    if call_sites.len() != 36
        || call_sites
            .iter()
            .map(|row| number(row, "literal_tokens"))
            .sum::<u64>()
            != 166
        || sum_nested(call_sites, "production", "encode") != 23
        || sum_nested(call_sites, "production", "decode") != 20
        || sum_nested(call_sites, "nonproduction", "encode") != 52
        || sum_nested(call_sites, "nonproduction", "decode") != 28
    {
        return Err("call-site census totals drifted".to_owned());
    }

    let occurrence = object(inventory, "occurrence_census");
    require_exact_strings(
        &inventory["occurrence_census"],
        "roots",
        &[
            "src",
            "tests",
            "fuzz",
            "examples",
            "benches",
            "conformance",
            "asupersync-wasm/src",
        ],
    )?;
    require_exact_ids(
        array(&inventory["occurrence_census"], "root_totals"),
        "root",
        &[
            "src",
            "tests",
            "fuzz",
            "examples",
            "benches",
            "conformance",
            "asupersync-wasm/src",
        ],
        "literal census roots",
    )?;
    let expected_root_totals = BTreeMap::from([
        ("src", (20, 89)),
        ("tests", (9, 19)),
        ("fuzz", (7, 58)),
        ("examples", (0, 0)),
        ("benches", (0, 0)),
        ("conformance", (0, 0)),
        ("asupersync-wasm/src", (0, 0)),
    ]);
    let actual_root_totals: BTreeMap<_, _> = array(&inventory["occurrence_census"], "root_totals")
        .iter()
        .map(|row| {
            (
                text(row, "root"),
                (number(row, "paths"), number(row, "literal_tokens")),
            )
        })
        .collect();
    if actual_root_totals != expected_root_totals {
        return Err("literal census root totals drifted".to_owned());
    }
    if occurrence.get("path_count").and_then(Value::as_u64) != Some(36)
        || occurrence
            .get("literal_token_count")
            .and_then(Value::as_u64)
            != Some(166)
        || occurrence.get("local_mock_paths").and_then(Value::as_u64) != Some(2)
        || occurrence.get("comment_only_paths").and_then(Value::as_u64) != Some(1)
    {
        return Err("occurrence summary drifted".to_owned());
    }
    let external_totals = occurrence
        .get("external_call_totals")
        .and_then(Value::as_object)
        .ok_or_else(|| "external_call_totals must be an object".to_owned())?;
    if external_totals.get("all_encode").and_then(Value::as_u64) != Some(75)
        || external_totals.get("all_decode").and_then(Value::as_u64) != Some(48)
    {
        return Err("external call totals drifted".to_owned());
    }
    let expected_engine_totals = BTreeMap::from([
        ("B64-ENGINE-STANDARD-PAD", (57, 35)),
        ("B64-ENGINE-STANDARD-NO-PAD", (4, 5)),
        ("B64-ENGINE-URL-SAFE-PAD", (0, 2)),
        ("B64-ENGINE-URL-SAFE-NO-PAD", (14, 6)),
    ]);
    let actual_engine_totals: BTreeMap<_, _> =
        array(&inventory["occurrence_census"], "engine_call_totals")
            .iter()
            .map(|row| {
                (
                    text(row, "engine_id"),
                    (number(row, "encode"), number(row, "decode")),
                )
            })
            .collect();
    if actual_engine_totals != expected_engine_totals {
        return Err("per-engine call totals drifted".to_owned());
    }

    require_exact_ids(
        array(inventory, "migration_reservation_groups"),
        "group_id",
        &["B64-A3-AUTH", "B64-A4-WEB-GRPC", "B64-A5-REMAINING"],
        "migration groups",
    )?;
    let expected_group_owners = BTreeMap::from([
        ("B64-A3-AUTH", "asupersync-d24mms.10.3"),
        ("B64-A4-WEB-GRPC", "asupersync-d24mms.10.4"),
        ("B64-A5-REMAINING", "asupersync-d24mms.10.5"),
    ]);
    for row in array(inventory, "migration_reservation_groups") {
        if expected_group_owners.get(text(row, "group_id")).copied() != Some(text(row, "owner")) {
            return Err("migration group owner drifted".to_owned());
        }
    }
    let group_ids = row_ids(array(inventory, "migration_reservation_groups"), "group_id");
    if call_sites
        .iter()
        .any(|row| !group_ids.contains(text(row, "group")))
    {
        return Err("call site has an unregistered migration group".to_owned());
    }
    let collisions = array(inventory, "manual_collision_surfaces");
    if collisions
        .iter()
        .any(|row| !group_ids.contains(text(row, "group")))
    {
        return Err("collision has an unregistered migration group".to_owned());
    }
    let mut all_reserved_paths = BTreeSet::new();
    for group in array(inventory, "migration_reservation_groups") {
        let group_id = text(group, "group_id");
        let expected_paths: BTreeSet<String> = call_sites
            .iter()
            .filter(|row| text(row, "group") == group_id)
            .chain(
                collisions
                    .iter()
                    .filter(|row| text(row, "group") == group_id),
            )
            .map(|row| text(row, "path").to_owned())
            .collect();
        if string_set(group, "reservation_paths") != expected_paths
            || number(group, "reservation_path_count") != expected_paths.len() as u64
        {
            return Err(format!("reservation path union drifted for {group_id}"));
        }
        let mut projection = String::new();
        for path in &expected_paths {
            if !all_reserved_paths.insert(path.clone()) {
                return Err(format!(
                    "reservation path {path} belongs to multiple groups"
                ));
            }
            projection.push_str(path);
            projection.push('\n');
        }
        if sha256_hex(projection.as_bytes()) != text(group, "reservation_paths_sha256") {
            return Err(format!("reservation path digest drifted for {group_id}"));
        }
    }
    if all_reserved_paths.len() != 44 {
        return Err("reservation path union count drifted".to_owned());
    }

    require_exact_ids(
        array(inventory, "public_surface"),
        "surface_id",
        &[
            "B64-PUBLIC-GRPC-WEB",
            "B64-PROTOCOL-GRPC-SERVER-METADATA",
            "B64-PUBLIC-TLS-PIN",
            "B64-PUBLIC-HTTP-BASIC",
            "B64-PUBLIC-WEBSOCKET",
            "B64-PERSISTED-BROWSER",
            "B64-PERSISTED-RUNTIME-PROFILE",
            "B64-AUTH-NATS",
            "B64-AUTH-POSTGRES",
            "B64-CLI-ATP",
        ],
        "public and protocol surfaces",
    )?;
    if array(inventory, "public_surface")
        .iter()
        .any(|row| row.get("upstream_error_exposed").and_then(Value::as_bool) != Some(false))
    {
        return Err("a public surface exposes the upstream error".to_owned());
    }
    let consumers = array(&inventory["downstream_and_e2e"], "consumer_obligations");
    require_exact_ids(
        consumers,
        "consumer_id",
        &[
            "B64-CONSUMER-GRPC-WEB",
            "B64-CONSUMER-GRPC-SERVER-METADATA",
            "B64-CONSUMER-TLS-PIN",
            "B64-CONSUMER-HTTP-BASIC",
            "B64-CONSUMER-WEBSOCKET",
            "B64-CONSUMER-BROWSER-PERSISTENCE",
            "B64-CONSUMER-RUNTIME-PROFILE",
            "B64-CONSUMER-NATS-AUTH",
            "B64-CONSUMER-POSTGRES-SCRAM",
            "B64-CONSUMER-ATP-CLI",
        ],
        "downstream consumers",
    )?;
    let call_ids = row_ids(call_sites, "call_id");
    let collision_ids = row_ids(collisions, "collision_id");
    let capability_ids = string_set(inventory, "capability_ids");
    let surface_ids = row_ids(array(inventory, "public_surface"), "surface_id");
    let consumer_ids = row_ids(consumers, "consumer_id");
    for surface in array(inventory, "public_surface") {
        let surface_id = text(surface, "surface_id");
        let consumer_id = text(surface, "consumer_id");
        if !consumer_ids.contains(consumer_id)
            || !profile_ids.contains(text(surface, "profile_id"))
            || !group_ids.contains(text(surface, "group_id"))
            || !string_set(surface, "call_ids").is_subset(&call_ids)
            || !string_set(surface, "collision_ids").is_subset(&collision_ids)
            || !string_set(surface, "capability_ids").is_subset(&capability_ids)
        {
            return Err(format!("public surface relation drifted for {surface_id}"));
        }
        let consumer = consumers
            .iter()
            .find(|row| text(row, "consumer_id") == consumer_id)
            .ok_or_else(|| format!("consumer {consumer_id} is missing"))?;
        if string_set(consumer, "surface_ids") != BTreeSet::from([surface_id.to_owned()])
            || string_set(consumer, "call_ids") != string_set(surface, "call_ids")
            || string_set(consumer, "collision_ids") != string_set(surface, "collision_ids")
            || string_set(consumer, "capability_ids") != string_set(surface, "capability_ids")
            || string_set(consumer, "profile_ids")
                != BTreeSet::from([text(surface, "profile_id").to_owned()])
            || string_set(consumer, "group_ids")
                != BTreeSet::from([text(surface, "group_id").to_owned()])
        {
            return Err(format!("consumer relation drifted for {consumer_id}"));
        }
    }
    for consumer in consumers {
        let consumer_id = text(consumer, "consumer_id");
        if text(consumer, "state") != "BLOCKED"
            || !text(consumer, "implementation_owner").starts_with("asupersync-d24mms.10.")
            || text(consumer, "evidence_owner") != "asupersync-d24mms.10.6"
            || text(consumer, "scenario_id").is_empty()
            || text(consumer, "evidence_boundary").is_empty()
            || !string_set(consumer, "surface_ids").is_subset(&surface_ids)
            || !string_set(consumer, "call_ids").is_subset(&call_ids)
            || !string_set(consumer, "collision_ids").is_subset(&collision_ids)
            || !string_set(consumer, "capability_ids").is_subset(&capability_ids)
            || !string_set(consumer, "profile_ids").is_subset(&profile_ids)
            || !string_set(consumer, "group_ids").is_subset(&group_ids)
        {
            return Err(format!("consumer obligation drifted for {consumer_id}"));
        }
    }
    let nonpublic_consumers = array(inventory, "nonpublic_consumer_relations");
    require_exact_ids(
        nonpublic_consumers,
        "consumer_id",
        &[
            "B64-CONSUMER-GRPC-STATUS-SNAPSHOT",
            "B64-CONSUMER-GRPC-FUZZ",
            "B64-CONSUMER-NATS-FUZZ",
            "B64-CONSUMER-POSTGRES-SCRAM-FUZZ",
            "B64-CONSUMER-TLS-X509-FUZZ",
            "B64-CONSUMER-WEBSOCKET-FUZZ",
            "B64-CONSUMER-DATABASE-LEGACY-FIXTURES",
            "B64-CONSUMER-WEBSOCKET-E2E-FIXTURES",
            "B64-CONSUMER-H2C-CONFORMANCE",
            "B64-CONSUMER-RAPTORQ-FIXTURES",
            "B64-CONSUMER-TLS-CONFORMANCE",
            "B64-CONSUMER-WEBSOCKET-CONFORMANCE",
            "B64-CONSUMER-GRPC-STATUS-GOLDEN",
            "B64-CONSUMER-GRPC-TRAILERS-CONFORMANCE",
            "B64-CONSUMER-GRPC-WEB-AUDIT",
            "B64-CONSUMER-PERF-COMMAND-FIXTURE",
            "B64-CONSUMER-EXCLUDED-LOCAL-HELPERS",
        ],
        "nonpublic consumer relations",
    )?;
    for consumer in nonpublic_consumers {
        let consumer_id = text(consumer, "consumer_id");
        if !text(consumer, "classification").starts_with("NONPUBLIC_")
            || text(consumer, "state") != "STATIC_RELATION_ONLY"
            || !text(consumer, "implementation_owner").starts_with("asupersync-d24mms.10.")
            || text(consumer, "relation_boundary").is_empty()
            || !string_set(consumer, "call_ids").is_subset(&call_ids)
            || !string_set(consumer, "capability_ids").is_subset(&capability_ids)
            || !string_set(consumer, "profile_ids").is_subset(&profile_ids)
            || !string_set(consumer, "group_ids").is_subset(&group_ids)
        {
            return Err(format!(
                "nonpublic consumer relation drifted for {consumer_id}"
            ));
        }
    }
    let nonpublic_consumer_ids = row_ids(nonpublic_consumers, "consumer_id");
    if !consumer_ids.is_disjoint(&nonpublic_consumer_ids) {
        return Err("public and nonpublic consumer IDs overlap".to_owned());
    }
    let operation_consumer_ids: BTreeSet<String> = consumer_ids
        .union(&nonpublic_consumer_ids)
        .cloned()
        .collect();

    let profile_gates = array(inventory, "profile_gate_contracts");
    if profile_gates.len() != 14 || row_ids(profile_gates, "profile_id") != profile_ids {
        return Err("profile-gate contract ID closure drifted".to_owned());
    }
    let mut gated_call_ids = BTreeSet::new();
    for gate in profile_gates {
        let profile_id = text(gate, "profile_id");
        if text(gate, "manifest_path").is_empty()
            || text(gate, "workspace_relation").is_empty()
            || text(gate, "target_gate").is_empty()
            || text(gate, "feature_gate").is_empty()
            || text(gate, "rust_cfg_gate").is_empty()
            || text(gate, "state").is_empty()
            || text(gate, "no_claim").is_empty()
            || !string_set(gate, "consumer_ids").is_subset(&operation_consumer_ids)
            || !string_set(gate, "group_ids").is_subset(&group_ids)
        {
            return Err(format!("profile gate {profile_id} is incomplete"));
        }
        for call_id in string_set(gate, "call_ids") {
            if !call_ids.contains(&call_id) || !gated_call_ids.insert(call_id.clone()) {
                return Err(format!("profile gate {profile_id} call partition drifted"));
            }
            let call = call_sites
                .iter()
                .find(|row| text(row, "call_id") == call_id.as_str())
                .expect("gated call must exist");
            if text(call, "profile") != profile_id {
                return Err(format!("profile gate {profile_id} call profile drifted"));
            }
        }
    }
    if gated_call_ids != call_ids {
        return Err("profile gates do not partition every call exactly once".to_owned());
    }
    let wasm_gate = profile_gates
        .iter()
        .find(|gate| text(gate, "profile_id") == "B64-PROFILE-EXCLUDED-WASM-SCAFFOLD")
        .expect("excluded wasm profile gate must exist");
    if text(wasm_gate, "state") != "DEPENDENCY_ONLY_NO_DIRECT_CALLS"
        || !array(wasm_gate, "call_ids").is_empty()
        || !array(wasm_gate, "consumer_ids").is_empty()
        || !array(wasm_gate, "group_ids").is_empty()
    {
        return Err("excluded wasm zero-call profile gate drifted".to_owned());
    }
    let profile_baselines = array(inventory, "profile_baseline_relations");
    if profile_baselines.len() != 14 || row_ids(profile_baselines, "profile_id") != profile_ids {
        return Err("profile baseline relation ID closure drifted".to_owned());
    }
    for baseline in profile_baselines {
        let profile_id = text(baseline, "profile_id");
        let baseline_capabilities = string_set(baseline, "capability_ids");
        let mut expected_capabilities = BTreeSet::new();
        let gate = profile_gates
            .iter()
            .find(|gate| text(gate, "profile_id") == profile_id)
            .expect("profile baseline gate must exist");
        for consumer_id in string_set(gate, "consumer_ids") {
            let consumer = consumers
                .iter()
                .chain(nonpublic_consumers.iter())
                .find(|row| text(row, "consumer_id") == consumer_id)
                .expect("profile baseline consumer must exist");
            expected_capabilities.extend(string_set(consumer, "capability_ids"));
        }
        if profile_id == "B64-PROFILE-EXCLUDED-WASM-SCAFFOLD" {
            expected_capabilities.insert("CAP-BASE64-CODEC".to_owned());
        }
        let expected_evidence_ids = if expected_capabilities.contains("CAP-AUTH-CREDENTIALS") {
            BTreeSet::from([
                "EVD-AUTH-POLICY".to_owned(),
                "EVD-BASE64-PROTOCOL".to_owned(),
                "EVD-CONSUMER-DEFAULT".to_owned(),
                "EVD-NKEY-SIGNED-PROFILE".to_owned(),
            ])
        } else {
            BTreeSet::from([
                "EVD-BASE64-PROTOCOL".to_owned(),
                "EVD-CONSUMER-DEFAULT".to_owned(),
            ])
        };
        if baseline_capabilities != expected_capabilities
            || text(baseline, "baseline_state") != "EXECUTABLE_PARTIAL_BLOCKING"
            || string_set(baseline, "evidence_ids") != expected_evidence_ids
            || text(baseline, "relation_boundary").is_empty()
        {
            return Err(format!("profile baseline {profile_id} relation drifted"));
        }
    }

    let operation_progress = object(inventory, "operation_matrix_progress");
    if operation_progress.get("state").and_then(Value::as_str) != Some("ALL_GROUPS_RECORDED")
        || operation_progress
            .get("external_operation_total")
            .and_then(Value::as_u64)
            != Some(123)
        || operation_progress
            .get("recorded_operation_total")
            .and_then(Value::as_u64)
            != Some(123)
        || operation_progress
            .get("remaining_operation_total")
            .and_then(Value::as_u64)
            != Some(0)
        || text(&inventory["operation_matrix_progress"], "count_semantics").is_empty()
    {
        return Err("operation-matrix progress drifted".to_owned());
    }
    require_exact_strings(
        &inventory["operation_matrix_progress"],
        "recorded_group_ids",
        &["B64-A3-AUTH", "B64-A4-WEB-GRPC", "B64-A5-REMAINING"],
    )?;
    require_exact_strings(
        &inventory["operation_matrix_progress"],
        "remaining_group_ids",
        &[],
    )?;

    let operations = array(inventory, "operation_contracts");
    if operations.len() != 123 || row_ids(operations, "operation_id").len() != 123 {
        return Err("operation contract count or ID uniqueness drifted".to_owned());
    }
    let prior_operations: Vec<Value> = operations
        .iter()
        .filter(|operation| text(operation, "group_id") != "B64-A5-REMAINING")
        .cloned()
        .collect();
    require_exact_ids(
        &prior_operations,
        "operation_id",
        &[
            "B64-A3-OP-RUNTIME-PROFILE-SIGNATURE-ENCODE",
            "B64-A3-OP-RUNTIME-PROFILE-SIGNATURE-DECODE",
            "B64-A3-OP-NATS-NONCE-SIGNATURE-ENCODE",
            "B64-A3-OP-NATS-JWT-DECODE-NOPAD",
            "B64-A3-OP-NATS-JWT-DECODE-PAD-FALLBACK",
            "B64-A3-OP-NATS-TEST-JWT-HEADER-ENCODE",
            "B64-A3-OP-NATS-TEST-JWT-PAYLOAD-ENCODE",
            "B64-A3-OP-NATS-TEST-JWT-SIGNATURE-ENCODE",
            "B64-A3-OP-PG-SCRAM-CLIENT-NONCE-ENCODE",
            "B64-A3-OP-PG-SCRAM-SALT-DECODE",
            "B64-A3-OP-PG-SCRAM-CHANNEL-BINDING-ENCODE",
            "B64-A3-OP-PG-SCRAM-CLIENT-PROOF-ENCODE",
            "B64-A3-OP-PG-SCRAM-SERVER-SIGNATURE-DECODE",
            "B64-A3-OP-PG-TEST-SALT64-ENCODE",
            "B64-A3-OP-PG-TEST-SALT65-ENCODE",
            "B64-A3-OP-PG-TEST-RFC-SIGNATURE-DECODE",
            "B64-A3-OP-PG-TEST-TRUNCATED-SIGNATURE-ENCODE",
            "B64-A3-OP-PG-TEST-SIGNATURE31-ENCODE",
            "B64-A3-OP-PG-TEST-SIGNATURE33-ENCODE",
            "B64-A3-OP-TLS-SPKI-PIN-DECODE",
            "B64-A3-OP-TLS-CERT-PIN-DECODE",
            "B64-A3-OP-TLS-PIN-ENCODE",
            "B64-A4-OP-GRPC-SERVER-INBOUND-METADATA-DECODE-PAD",
            "B64-A4-OP-GRPC-SERVER-INBOUND-METADATA-DECODE-NOPAD-FALLBACK",
            "B64-A4-OP-GRPC-SERVER-RESPONSE-METADATA-ENCODE",
            "B64-A4-OP-GRPC-SERVER-STATUS-DETAILS-ENCODE",
            "B64-A4-OP-GRPC-STATUS-SNAPSHOT-DETAILS-ENCODE",
            "B64-A4-OP-GRPC-WEB-TRAILER-METADATA-ENCODE",
            "B64-A4-OP-GRPC-WEB-TRAILER-METADATA-DECODE",
            "B64-A4-OP-GRPC-WEB-TEXT-WHOLE-ENCODE",
            "B64-A4-OP-GRPC-WEB-TEXT-WHOLE-DECODE",
            "B64-A4-OP-GRPC-WEB-TEXT-STREAM-PADDED-FINAL-DECODE",
            "B64-A4-OP-GRPC-WEB-TEXT-STREAM-COMPLETE-QUADS-DECODE",
            "B64-A4-OP-GRPC-WEB-TEXT-STREAM-FINAL-TAIL-DECODE",
            "B64-A4-OP-GRPC-WEB-TEST-SNAPSHOT-METADATA-ENCODE",
            "B64-A4-OP-GRPC-WEB-TEST-SPEC-METADATA-DECODE",
            "B64-A4-OP-HTTP-ORIGIN-BASIC-ENCODE",
            "B64-A4-OP-HTTP-PROXY-BASIC-ENCODE",
            "B64-A4-OP-BROWSER-LOCALSTORAGE-NAMESPACE-ENCODE",
            "B64-A4-OP-BROWSER-LOCALSTORAGE-KEY-ENCODE",
            "B64-A4-OP-BROWSER-LOCALSTORAGE-KEY-DECODE",
            "B64-A4-OP-BROWSER-LOCALSTORAGE-VALUE-ENCODE",
            "B64-A4-OP-BROWSER-LOCALSTORAGE-VALUE-DECODE",
            "B64-A4-OP-BROWSER-INDEXEDDB-NAMESPACE-ENCODE",
            "B64-A4-OP-BROWSER-INDEXEDDB-KEY-ENCODE",
            "B64-A4-OP-BROWSER-INDEXEDDB-KEY-DECODE",
            "B64-A4-OP-WS-ACCEPT-DIGEST-ENCODE",
            "B64-A4-OP-WS-CLIENT-KEY-ENCODE",
            "B64-A4-OP-WS-CLIENT-KEY-DECODE",
            "B64-A4-OP-WS-TEST-GENERATED-KEY-DECODE",
            "B64-A4-OP-WS-GOLDEN-KEY-DECODE",
            "B64-A4-OP-WS-GOLDEN-ACCEPT-ENCODE",
            "B64-A4-OP-WS-GOLDEN-WRONG-GUID-ENCODE",
            "B64-A4-OP-DEBUG-WS-ACCEPT-DIGEST-ENCODE",
            "B64-A4-OP-WEB-WS-CLIENT-KEY-DECODE",
        ],
        "recorded operation contracts",
    )?;
    let operation_semantics: BTreeMap<String, Value> = operations
        .iter()
        .map(|operation| {
            let operation_id = text(operation, "operation_id").to_owned();
            let mut semantics = operation.clone();
            semantics
                .as_object_mut()
                .expect("operation contract must be an object")
                .remove("operation_id");
            (operation_id, semantics)
        })
        .collect();
    let operation_semantics = serde_json::to_value(operation_semantics)
        .expect("operation semantic projection must serialize");
    if sha256_hex(&canonical_json_bytes(&operation_semantics))
        != RECORDED_OPERATION_SEMANTICS_SHA256
    {
        return Err("recorded keyed operation semantics drifted".to_owned());
    }
    let role_ids = row_ids(array(inventory, "security_roles"), "role_id");
    let error_ids = row_ids(array(inventory, "owned_error_mappings"), "error_id");
    let mut used_engine_ids = BTreeSet::new();
    let mut used_group_ids = BTreeSet::new();
    let mut used_capability_ids = BTreeSet::new();
    let mut used_consumer_ids = BTreeSet::new();
    let mut used_role_ids = BTreeSet::new();
    let mut used_error_ids = BTreeSet::new();
    let mut source_locations = BTreeSet::new();
    let mut operation_totals: BTreeMap<String, [u64; 4]> = BTreeMap::new();
    for operation in operations {
        let operation_id = text(operation, "operation_id");
        let call_id = text(operation, "call_id");
        let path = text(operation, "path");
        let direction = text(operation, "direction");
        let classification = text(operation, "classification");
        let count = number(operation, "count");
        let source_line = number(operation, "source_line");
        if count != 1
            || source_line == 0
            || text(operation, "source_anchor").is_empty()
            || text(operation, "acceptance_rule").is_empty()
            || !matches!(
                text(operation, "group_id"),
                "B64-A3-AUTH" | "B64-A4-WEB-GRPC" | "B64-A5-REMAINING"
            )
        {
            return Err(format!("operation {operation_id} is incomplete"));
        }
        if !source_locations.insert((path.to_owned(), source_line)) {
            return Err(format!(
                "operation {operation_id} source location is duplicated"
            ));
        }
        let bucket_index = match (classification, direction) {
            ("PRODUCTION", "ENCODE") => 0,
            ("PRODUCTION", "DECODE") => 1,
            ("NONPRODUCTION", "ENCODE") => 2,
            ("NONPRODUCTION", "DECODE") => 3,
            _ => return Err(format!("operation {operation_id} classification drifted")),
        };
        let source_line_index = usize::try_from(source_line - 1)
            .map_err(|_| format!("operation {operation_id} source line overflowed"))?;
        let source = read_repo_file(path);
        let source_text = source
            .lines()
            .nth(source_line_index)
            .ok_or_else(|| format!("operation {operation_id} source line is absent"))?;
        let direction_marker = direction.to_ascii_lowercase();
        if !source_text.contains(direction_marker.as_str()) {
            return Err(format!("operation {operation_id} source direction drifted"));
        }

        let call = call_sites
            .iter()
            .find(|row| text(row, "call_id") == call_id)
            .ok_or_else(|| format!("operation {operation_id} call is absent"))?;
        let engine_id = text(operation, "engine_id");
        if path != text(call, "path")
            || text(operation, "profile_id") != text(call, "profile")
            || text(operation, "group_id") != text(call, "group")
            || !string_set(call, "engines").contains(engine_id)
            || !engine_ids.contains(engine_id)
        {
            return Err(format!("operation {operation_id} call relation drifted"));
        }
        used_engine_ids.insert(engine_id.to_owned());
        used_group_ids.insert(text(operation, "group_id").to_owned());
        used_capability_ids.extend(string_set(operation, "capability_ids"));

        let role_id = text(operation, "role_id");
        let error_id = text(operation, "error_id");
        if !role_ids.contains(role_id) || !error_ids.contains(error_id) {
            return Err(format!(
                "operation {operation_id} registry relation drifted"
            ));
        }
        used_role_ids.insert(role_id.to_owned());
        used_error_ids.insert(error_id.to_owned());

        let operation_consumers = string_set(operation, "consumer_ids");
        if operation_consumers.len() != 1 {
            return Err(format!("operation {operation_id} must name one consumer"));
        }
        let consumer_id = operation_consumers
            .iter()
            .next()
            .expect("one operation consumer must exist");
        used_consumer_ids.insert(consumer_id.to_owned());
        let consumer = consumers
            .iter()
            .chain(nonpublic_consumers.iter())
            .find(|row| text(row, "consumer_id") == consumer_id)
            .ok_or_else(|| format!("operation {operation_id} consumer is absent"))?;
        if !operation_consumer_ids.contains(consumer_id)
            || !string_set(consumer, "call_ids").contains(call_id)
            || !string_set(consumer, "profile_ids").contains(text(operation, "profile_id"))
            || !string_set(consumer, "group_ids").contains(text(operation, "group_id"))
            || string_set(operation, "capability_ids") != string_set(consumer, "capability_ids")
        {
            return Err(format!(
                "operation {operation_id} consumer relation drifted"
            ));
        }
        operation_totals.entry(call_id.to_owned()).or_default()[bucket_index] += count;
    }
    if used_engine_ids != engine_ids
        || used_group_ids != group_ids
        || used_capability_ids != capability_ids
    {
        return Err("engine, group, or capability relation contains an orphan".to_owned());
    }
    for relation in consumers.iter().chain(nonpublic_consumers.iter()) {
        let relation_roles = string_set(relation, "role_ids");
        let relation_errors = string_set(relation, "error_ids");
        if relation_roles.is_empty()
            || relation_errors.is_empty()
            || !relation_roles.is_subset(&role_ids)
            || !relation_errors.is_subset(&error_ids)
        {
            return Err(format!(
                "consumer {} role/error registry relation drifted",
                text(relation, "consumer_id")
            ));
        }
        used_role_ids.extend(relation_roles);
        used_error_ids.extend(relation_errors);
    }
    for collision in collisions {
        let collision_id = text(collision, "collision_id");
        let collision_roles = string_set(collision, "role_ids");
        let collision_errors = string_set(collision, "error_ids");
        let collision_consumers = string_set(collision, "consumer_ids");
        if collision_roles.is_empty()
            || collision_errors.is_empty()
            || collision_consumers.is_empty()
            || !collision_roles.is_subset(&role_ids)
            || !collision_errors.is_subset(&error_ids)
            || !collision_consumers.is_subset(&operation_consumer_ids)
        {
            return Err(format!("collision {collision_id} registry relation drifted"));
        }
        for consumer_id in collision_consumers {
            used_consumer_ids.insert(consumer_id.clone());
            let consumer = consumers
                .iter()
                .chain(nonpublic_consumers.iter())
                .find(|row| text(row, "consumer_id") == consumer_id)
                .ok_or_else(|| format!("collision {collision_id} consumer is absent"))?;
            if !string_set(consumer, "collision_ids").contains(collision_id) {
                return Err(format!(
                    "collision {collision_id} is not linked back by {consumer_id}"
                ));
            }
        }
        used_role_ids.extend(collision_roles);
        used_error_ids.extend(collision_errors);
    }
    for consumer in consumers.iter().chain(nonpublic_consumers.iter()) {
        let consumer_id = text(consumer, "consumer_id");
        let mut expected_roles = BTreeSet::new();
        let mut expected_errors = BTreeSet::new();
        for operation in operations
            .iter()
            .filter(|row| string_set(row, "consumer_ids").contains(consumer_id))
        {
            expected_roles.insert(text(operation, "role_id").to_owned());
            expected_errors.insert(text(operation, "error_id").to_owned());
        }
        for collision in collisions
            .iter()
            .filter(|row| string_set(row, "consumer_ids").contains(consumer_id))
        {
            expected_roles.extend(string_set(collision, "role_ids"));
            expected_errors.extend(string_set(collision, "error_ids"));
        }
        if string_set(consumer, "role_ids") != expected_roles
            || string_set(consumer, "error_ids") != expected_errors
        {
            return Err(format!(
                "consumer {consumer_id} role/error closure drifted"
            ));
        }
    }
    if used_role_ids != role_ids || used_error_ids != error_ids {
        return Err("recorded role or error registry contains an orphan".to_owned());
    }
    if used_consumer_ids != operation_consumer_ids {
        return Err("consumer relation contains an orphan".to_owned());
    }
    let expected_recorded_call_ids: BTreeSet<String> = call_sites
        .iter()
        .filter(|row| {
            number(&row["production"], "encode")
                + number(&row["production"], "decode")
                + number(&row["nonproduction"], "encode")
                + number(&row["nonproduction"], "decode")
                > 0
        })
        .map(|row| text(row, "call_id").to_owned())
        .collect();
    if operation_totals.keys().cloned().collect::<BTreeSet<_>>() != expected_recorded_call_ids {
        return Err("recorded operation call coverage drifted".to_owned());
    }
    for call in call_sites
        .iter()
        .filter(|row| {
            number(&row["production"], "encode")
                + number(&row["production"], "decode")
                + number(&row["nonproduction"], "encode")
                + number(&row["nonproduction"], "decode")
                > 0
        })
    {
        let actual = operation_totals
            .get(text(call, "call_id"))
            .expect("covered recorded call must have operation totals");
        let expected = [
            call["production"]["encode"]
                .as_u64()
                .expect("production encode must be an unsigned integer"),
            call["production"]["decode"]
                .as_u64()
                .expect("production decode must be an unsigned integer"),
            call["nonproduction"]["encode"]
                .as_u64()
                .expect("nonproduction encode must be an unsigned integer"),
            call["nonproduction"]["decode"]
                .as_u64()
                .expect("nonproduction decode must be an unsigned integer"),
        ];
        if *actual != expected {
            return Err(format!(
                "recorded operation totals drifted for {}",
                text(call, "call_id")
            ));
        }
    }
    let recorded_totals = object(&inventory["operation_matrix_progress"], "recorded_totals");
    let aggregate_totals: [u64; 4] = [
        operation_totals.values().map(|counts| counts[0]).sum(),
        operation_totals.values().map(|counts| counts[1]).sum(),
        operation_totals.values().map(|counts| counts[2]).sum(),
        operation_totals.values().map(|counts| counts[3]).sum(),
    ];
    if aggregate_totals != [23, 20, 52, 28]
        || recorded_totals
            .get("production_encode")
            .and_then(Value::as_u64)
            != Some(aggregate_totals[0])
        || recorded_totals
            .get("production_decode")
            .and_then(Value::as_u64)
            != Some(aggregate_totals[1])
        || recorded_totals
            .get("nonproduction_encode")
            .and_then(Value::as_u64)
            != Some(aggregate_totals[2])
        || recorded_totals
            .get("nonproduction_decode")
            .and_then(Value::as_u64)
            != Some(aggregate_totals[3])
        || aggregate_totals.iter().sum::<u64>() != 123
    {
        return Err("recorded operation aggregate drifted".to_owned());
    }

    require_exact_ids(
        array(inventory, "gaps"),
        "gap_id",
        &[
            "B64-GAP-REGISTRY-SOURCES",
            "B64-GAP-REGISTRY-PROFILES",
            "B64-GAP-PARTIAL-BASELINE",
            "B64-GAP-GLOBAL-BOUND",
            "B64-GAP-CONSTANT-TIME",
            "B64-GAP-GRPC-BUFFER",
            "B64-GAP-MANUAL-HTTP",
            "B64-GAP-BROWSER-HOST",
            "B64-GAP-HOST-COMMAND",
            "B64-GAP-VERSION-SKEW",
            "B64-GAP-EXCLUDED-WASM-LOCK",
            "B64-GAP-ORPHAN-SOURCES",
            "B64-GAP-LOCAL-MOCKS",
            "B64-GAP-DEBUG-WS-KEY",
            "B64-GAP-URL-SAFE-PAD-ONLY-DECODE",
            "B64-GAP-CALL-LEVEL-RELATIONS",
            "B64-GAP-PROFILE-GATE-RELATIONS",
            "B64-GAP-ERROR-ROLE-REGISTRY",
            "B64-GAP-A1-NOT-EXECUTED",
        ],
        "routed gaps",
    )?;
    for gap in array(inventory, "gaps") {
        if !matches!(text(gap, "state"), "ROUTED" | "BLOCKED" | "RESOLVED")
            || !text(gap, "owner").starts_with("asupersync-d24mms.10.")
            || text(gap, "detail").is_empty()
        {
            return Err(format!("gap {} is not fully routed", text(gap, "gap_id")));
        }
    }

    require_exact_ids(
        array(inventory, "semantic_corpus"),
        "case_id",
        &[
            "B64-VEC-EMPTY",
            "B64-VEC-F",
            "B64-VEC-FO",
            "B64-VEC-FOO",
            "B64-VEC-FOOB",
            "B64-VEC-FOOBA",
            "B64-VEC-FOOBAR",
            "B64-VEC-ALPHABET",
            "B64-ERR-WHITESPACE",
            "B64-ERR-MIXED-STANDARD",
            "B64-ERR-MIXED-URL",
            "B64-ERR-PADDING-IN-NO-PAD",
            "B64-ERR-MISSING-PADDING",
            "B64-ERR-ONE-SYMBOL",
            "B64-ERR-TRAILING-BITS",
        ],
        "semantic corpus",
    )?;
    if array(inventory, "semantic_corpus")
        .iter()
        .any(|row| text(row, "provenance").is_empty())
    {
        return Err("semantic corpus provenance drifted".to_owned());
    }
    require_exact_ids(
        array(inventory, "manual_collision_surfaces"),
        "collision_id",
        &[
            "B64-COLLISION-HTTP-REQUEST",
            "B64-COLLISION-JETSTREAM-TEST",
            "B64-COLLISION-BROWSER-TS",
            "B64-COLLISION-HOST-SHELL",
            "B64-COLLISION-TLS-PIN-TEST",
            "B64-COLLISION-OTEL-MOCK",
            "B64-COLLISION-WEBSOCKET-MOCK",
            "B64-COLLISION-POSTGRES-PYTHON-SEEDS",
            "B64-COLLISION-TLS-PYTHON-SEEDS",
            "B64-COLLISION-SERVICE-WORKER-NODE",
            "B64-COLLISION-ATP-POWERSHELL",
        ],
        "manual collisions",
    )?;
    if array(inventory, "semantic_corpus").len() != 15
        || array(inventory, "manual_collision_surfaces").len() != 11
        || array(inventory, "rollback_triggers").len() != 7
        || array(inventory, "no_claim_boundaries").len() != 7
    {
        return Err("corpus, collision, rollback, or no-claim coverage drifted".to_owned());
    }
    Ok(())
}

fn validate_claims_projection(inventory: &Value) -> Result<(), String> {
    validate_inventory(inventory)?;
    let actual = sha256_hex(&canonical_json_bytes(&claims_projection(inventory)));
    if actual != CLAIMS_PROJECTION_SHA256 {
        return Err("canonical claims projection drifted".to_owned());
    }
    Ok(())
}

fn collect_rust_files(directory: &Path, output: &mut Vec<PathBuf>) {
    if !directory.exists() {
        return;
    }
    let mut entries: Vec<_> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry must be readable").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, output);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

fn live_literal_census() -> BTreeMap<String, u64> {
    let root = repo_root();
    let mut files = Vec::new();
    for directory in [
        "src",
        "tests",
        "fuzz",
        "examples",
        "benches",
        "conformance",
        "asupersync-wasm/src",
    ] {
        collect_rust_files(&root.join(directory), &mut files);
    }
    let mut census = BTreeMap::new();
    for path in files {
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let count = content.matches(PATH_TOKEN).count() as u64;
        if count != 0 {
            let relative = path
                .strip_prefix(&root)
                .expect("scanned file must be under repository root")
                .to_string_lossy()
                .replace('\\', "/");
            census.insert(relative, count);
        }
    }
    census
}

fn artifact_literal_census(inventory: &Value) -> BTreeMap<String, u64> {
    array(inventory, "call_sites")
        .iter()
        .map(|row| (text(row, "path").to_owned(), number(row, "literal_tokens")))
        .collect()
}

#[test]
fn identity_policy_engines_profiles_and_routed_gaps_are_exact() {
    validate_claims_projection(&artifact()).expect("Base64 inventory claims must remain exact");
}

#[test]
fn source_pins_cover_every_claimed_path_and_match_bytes() {
    let inventory = artifact();
    let pins = array(&inventory, "source_pins");
    assert_eq!(pins.len(), 75);

    let mut pinned_paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(
            pinned_paths.insert(path.to_owned()),
            "duplicate source pin {path}"
        );
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source hash drifted for {path}"
        );
        let content = String::from_utf8(bytes).expect("pinned sources must be UTF-8");
        assert_eq!(
            content.lines().count() as u64,
            number(pin, "line_count"),
            "line count drifted for {path}"
        );
    }

    let mut projection = String::new();
    for path in &pinned_paths {
        projection.push_str(path);
        projection.push('\n');
    }
    assert_eq!(sha256_hex(projection.as_bytes()), SOURCE_PIN_PATHS_SHA256);
    assert_eq!(
        text(&inventory["source_pin_scope"], "paths_sha256"),
        SOURCE_PIN_PATHS_SHA256
    );

    for row in array(&inventory, "call_sites") {
        assert!(
            pinned_paths.contains(text(row, "path")),
            "call-site path is not pinned"
        );
    }
    for row in array(&inventory, "manual_collision_surfaces") {
        assert!(
            pinned_paths.contains(text(row, "path")),
            "collision path is not pinned"
        );
    }
}

#[test]
fn literal_path_token_census_and_reservation_digests_are_exact() {
    let inventory = artifact();
    assert_eq!(live_literal_census(), artifact_literal_census(&inventory));

    let call_sites = array(&inventory, "call_sites");
    for group in array(&inventory, "migration_reservation_groups") {
        let group_id = text(group, "group_id");
        let mut projection = BTreeMap::new();
        for row in call_sites
            .iter()
            .filter(|row| text(row, "group") == group_id)
        {
            projection.insert(text(row, "path").to_owned(), number(row, "literal_tokens"));
        }
        assert_eq!(projection.len() as u64, number(group, "path_count"));
        assert_eq!(
            projection.values().sum::<u64>(),
            number(group, "literal_token_count")
        );
        let mut bytes = String::new();
        for (path, count) in projection {
            bytes.push_str(&path);
            bytes.push('\t');
            bytes.push_str(&count.to_string());
            bytes.push('\n');
        }
        assert_eq!(
            sha256_hex(bytes.as_bytes()),
            text(group, "projection_sha256")
        );
    }
}

#[test]
fn dependency_governance_sources_remain_blocking_and_version_skew_is_explicit() {
    let inventory = artifact();
    let registry = parse_repo_json(REGISTRY_PATH);
    let registry_row = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("registry must contain the Base64 capability");
    assert_eq!(
        text(registry_row, "disposition"),
        "PRESERVE_AND_REPLACE_IF_PARITY"
    );
    assert_eq!(text(registry_row, "evidence_state"), "BASELINE_PLANNED");
    assert_eq!(
        text(registry_row, "cutover_state"),
        "BLOCKED_PENDING_EVIDENCE"
    );
    assert_eq!(
        registry_row["baseline"]["owner_bead"].as_str(),
        Some(BEAD_ID)
    );
    let auth_registry_row = array(&registry, "capabilities")
        .iter()
        .find(|row| {
            row.get("capability_id").and_then(Value::as_str) == Some("CAP-AUTH-CREDENTIALS")
        })
        .expect("registry must contain the authentication capability");
    assert_eq!(
        text(auth_registry_row, "disposition"),
        "PRESERVE_AND_REPLACE_IF_PARITY"
    );
    assert_eq!(
        text(auth_registry_row, "evidence_state"),
        "BASELINE_PLANNED"
    );
    assert_eq!(
        text(auth_registry_row, "cutover_state"),
        "BLOCKED_PENDING_EVIDENCE"
    );

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = array(&baseline, "capability_baselines")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("baseline must contain the Base64 capability");
    assert_eq!(
        text(baseline_row, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert_eq!(baseline_row["cutover_eligible"].as_bool(), Some(false));
    assert_eq!(
        baseline_row["downstream_profiles"],
        serde_json::json!(["consumer-default"])
    );
    let auth_baseline_row = array(&baseline, "capability_baselines")
        .iter()
        .find(|row| {
            row.get("capability_id").and_then(Value::as_str) == Some("CAP-AUTH-CREDENTIALS")
        })
        .expect("baseline must contain the authentication capability");
    assert_eq!(
        text(auth_baseline_row, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert_eq!(auth_baseline_row["cutover_eligible"].as_bool(), Some(false));
    assert_eq!(
        auth_baseline_row["downstream_profiles"],
        serde_json::json!([])
    );
    require_exact_strings(
        auth_baseline_row,
        "evidence_ids",
        &["EVD-AUTH-POLICY", "EVD-NKEY-SIGNED-PROFILE"],
    )
    .expect("authentication evidence IDs must remain exact");
    require_exact_ids(
        array(&inventory["downstream_and_e2e"], "capability_baselines"),
        "capability_id",
        &["CAP-AUTH-CREDENTIALS", "CAP-BASE64-CODEC"],
        "inventory capability baselines",
    )
    .expect("inventory capability baselines must remain exact");
    let evidence_ids = row_ids(array(&baseline, "evidence_catalog"), "evidence_id");
    for row in array(&inventory["downstream_and_e2e"], "capability_baselines") {
        let capability_id = text(row, "capability_id");
        let authority_row = array(&baseline, "capability_baselines")
            .iter()
            .find(|candidate| text(candidate, "capability_id") == capability_id)
            .expect("inventory capability baseline must have an authority row");
        assert_eq!(
            text(row, "baseline_state"),
            text(authority_row, "baseline_state")
        );
        assert_eq!(
            row["cutover_eligible"].as_bool(),
            authority_row["cutover_eligible"].as_bool()
        );
        assert_eq!(
            string_set(row, "evidence_ids"),
            string_set(authority_row, "evidence_ids")
        );
        assert_eq!(
            string_set(row, "downstream_profiles"),
            string_set(authority_row, "downstream_profiles")
        );
    }
    for consumer in array(&inventory["downstream_and_e2e"], "consumer_obligations") {
        assert!(
            string_set(consumer, "current_evidence_ids").is_subset(&evidence_ids),
            "consumer evidence ID must exist in the baseline catalog"
        );
    }

    let matrix = parse_repo_json(MATRIX_PATH);
    let rows: Vec<_> = array(&matrix, "matrix")
        .iter()
        .filter(|row| {
            row.get("bead_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("asupersync-d24mms.10."))
        })
        .filter(|row| {
            array(row, "capability_ids")
                .iter()
                .any(|id| id.as_str() == Some(CAPABILITY_ID))
        })
        .collect();
    assert_eq!(rows.len(), 6);
    for row in rows {
        assert_eq!(text(row, "cutover_state"), "BLOCKED_PENDING_EVIDENCE");
        assert!(array(row, "evidence_plans").iter().all(|plan| {
            plan.get("plan_state").and_then(Value::as_str) == Some("PLANNED_BLOCKING")
        }));
    }

    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    assert_eq!(array(&ledger, "canonical_profiles").len(), 13);
    assert_eq!(array(&ledger, "canonical_target_triples").len(), 4);
    require_exact_ids(
        array(&ledger, "canonical_profiles"),
        "profile_id",
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
            "workspace-dev-build-audit",
        ],
        "marginal-ledger profiles",
    )
    .expect("marginal-ledger profiles must remain exact");
    require_exact_strings(
        &ledger,
        "canonical_target_triples",
        &[
            "aarch64-apple-darwin",
            "wasm32-unknown-unknown",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ],
    )
    .expect("marginal-ledger targets must remain exact");
    let base64_measurements: Vec<_> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("direct_root_edge").and_then(Value::as_str) == Some("normal:base64"))
        .collect();
    assert_eq!(base64_measurements.len(), 52);
    assert_eq!(
        base64_measurements
            .iter()
            .map(|row| text(row, "feature_profile"))
            .collect::<BTreeSet<_>>()
            .len(),
        13
    );
    assert_eq!(
        base64_measurements
            .iter()
            .map(|row| text(row, "target_triple"))
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert!(base64_measurements.iter().all(|row| {
        row.get("marginal_package_version_count")
            .and_then(Value::as_u64)
            == Some(1)
            && row.get("marginal_package_versions")
                .and_then(Value::as_array)
                .is_some_and(|packages| {
                    packages.len() == 1
                        && packages[0].as_str()
                            == Some(
                                "registry+https://github.com/rust-lang/crates.io-index#base64@0.23.0",
                            )
                })
    }));

    let root_manifest = read_repo_file(ROOT_MANIFEST_PATH);
    assert!(root_manifest.contains(
        "base64 = { version = \"0.23\", default-features = false, features = [\"std\"] }"
    ));
    let root_lock = read_repo_file("Cargo.lock");
    for needle in [
        concat!(
            "name = \"base64\"\n",
            "version = \"0.22.1\"\n",
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
            "checksum = \"72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6\"",
        ),
        concat!(
            "name = \"base64\"\n",
            "version = \"0.23.0\"\n",
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
            "checksum = \"b25655df2c3cdd83c5e5b293b88acd880332b2ddadd7c30ac43144fdc0033da9\"",
        ),
        "name = \"opentelemetry-proto\"\nversion = \"0.32.0\"",
        "name = \"sqlx-core\"\nversion = \"0.9.0\"",
        "name = \"tonic\"\nversion = \"0.14.6\"",
    ] {
        assert!(
            root_lock.contains(needle),
            "root lock boundary missing: {needle}"
        );
    }
    assert_eq!(root_lock.matches(" \"base64 0.22.1\",").count(), 3);
    assert!(read_repo_file(FUZZ_MANIFEST_PATH).contains("base64 = \"0.22\""));
    assert!(read_repo_file(RAPTORQ_MANIFEST_PATH).contains("base64 = \"0.22\""));
    let excluded_wasm_manifest = read_repo_file("asupersync-wasm/Cargo.toml");
    assert!(
        excluded_wasm_manifest.contains(
            "asupersync = { version = \"0.3.5\", path = \"..\", default-features = false }"
        )
    );
    assert!(
        read_repo_file("asupersync-wasm/src/lib.rs")
            .contains("Non-canonical Browser Edition binding scaffold.")
    );
}

#[test]
fn docs_ignore_and_no_claim_markers_remain_discoverable() {
    let docs = read_repo_file(DOC_PATH);
    assert_eq!(docs.matches(DOC_BEGIN).count(), 1);
    assert_eq!(docs.matches(DOC_END).count(), 1);
    for needle in [
        "NOT_RUN_BY_A1",
        "36 Rust paths and 166 literal",
        "75 tracked source hashes",
        "request trailers",
        "RFC 4648 section 10",
        "asupersync-wasm",
        "Structured downstream obligations",
        "CAP-AUTH-CREDENTIALS",
        "44 unique reservation paths",
        "23 | 20 | 43",
        "52 | 28 | 80",
        "B64-A3-AUTH",
        "B64-A4-WEB-GRPC",
        "B64-A5-REMAINING",
        "22 of 123 external call expressions",
        "12 stable A3 security-role IDs",
        "7 stable A3 owned-error IDs",
        "55 of 123 external call expressions",
        "68 A5 expressions remaining",
        "29 stable security-role IDs",
        "14 stable owned-error IDs",
        "B64-CONSUMER-GRPC-STATUS-SNAPSHOT",
        "all 123 external operations",
        "43 stable roles and 20 owned error mappings",
        "14 profile-gate contracts",
        "14-row profile-baseline relation",
        "10 public and 17 explicit nonpublic consumer",
        "CALL-019`, `CALL-021`, and `CALL-032",
        "no constant-time claim",
        "does not prove compilation",
        "Only A6",
    ] {
        assert!(
            docs.contains(needle),
            "documentation marker missing: {needle}"
        );
    }
    assert!(
        read_repo_file(IGNORE_PATH)
            .lines()
            .any(|line| line == "!artifacts/base64_capability_inventory_v1.json")
    );
    assert!(
        read_repo_file(IGNORE_PATH)
            .lines()
            .any(|line| line == "Cargo.lock")
    );
}

#[test]
fn safe_negative_mutations_fail_closed() {
    let original = artifact();

    let mut with_unknown = original.clone();
    with_unknown["authority"]["current_action"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_claims_projection(&with_unknown).is_err());

    let mut missing_call = original.clone();
    missing_call["call_sites"]
        .as_array_mut()
        .expect("call_sites must be mutable array")
        .pop();
    assert!(validate_claims_projection(&missing_call).is_err());

    let mut unrouted_gap = original.clone();
    unrouted_gap["gaps"][0]["owner"] = Value::String(String::new());
    assert!(validate_claims_projection(&unrouted_gap).is_err());

    let mut changed_vector = original.clone();
    changed_vector["semantic_corpus"][1]["expected"]["STANDARD"] =
        Value::String("drifted".to_owned());
    assert!(validate_claims_projection(&changed_vector).is_err());

    let mut changed_classification = original.clone();
    changed_classification["call_sites"][0]["classification"] =
        Value::String("EXTERNAL_PRODUCTION".to_owned());
    assert!(validate_claims_projection(&changed_classification).is_err());

    let mut changed_group = original.clone();
    changed_group["call_sites"][0]["group"] = Value::String("B64-A3-AUTH".to_owned());
    assert!(validate_claims_projection(&changed_group).is_err());

    let mut invalid_operation_engine = original.clone();
    invalid_operation_engine["operation_contracts"][0]["engine_id"] =
        Value::String("B64-ENGINE-NOT-REGISTERED".to_owned());
    assert!(validate_inventory(&invalid_operation_engine).is_err());

    let mut registered_operation_engine_swap = original.clone();
    registered_operation_engine_swap["operation_contracts"][3]["engine_id"] =
        Value::String("B64-ENGINE-URL-SAFE-PAD".to_owned());
    assert!(validate_inventory(&registered_operation_engine_swap).is_err());

    let mut registered_error_reassignment = original.clone();
    registered_error_reassignment["operation_contracts"][0]["error_id"] =
        Value::String("B64-ERROR-RUNTIME-PROFILE-REFUSAL".to_owned());
    assert!(validate_inventory(&registered_error_reassignment).is_err());

    let mut duplicate_profile_gate_call = original.clone();
    let duplicated_call_ids =
        duplicate_profile_gate_call["profile_gate_contracts"][0]["call_ids"].clone();
    duplicate_profile_gate_call["profile_gate_contracts"][1]["call_ids"] =
        duplicated_call_ids;
    assert!(validate_inventory(&duplicate_profile_gate_call).is_err());

    let mut incomplete_profile_baseline = original.clone();
    incomplete_profile_baseline["profile_baseline_relations"][0]["evidence_ids"] =
        Value::Array(Vec::new());
    assert!(validate_inventory(&incomplete_profile_baseline).is_err());

    let mut missing_collision_backlink = original.clone();
    missing_collision_backlink["downstream_and_e2e"]["consumer_obligations"][2]["collision_ids"] =
        Value::Array(Vec::new());
    assert!(validate_inventory(&missing_collision_backlink).is_err());

    let mut exposed_error = original;
    exposed_error["public_surface"][0]["upstream_error_exposed"] = Value::Bool(true);
    assert!(validate_claims_projection(&exposed_error).is_err());
}
