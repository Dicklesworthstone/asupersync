//! Fail-closed YAML scenario capability inventory contract.
//!
//! Beads: asupersync-5z2scg.5.1, asupersync-5z2scg.5.2,
//! asupersync-5z2scg.5.3.1
//! Scenario: scenario-yaml-capability-inventory-contract
//! Fixture: artifacts/scenario_yaml_capability_inventory_v1.json
//!
//! This proves source-pinned loader, typed-schema, observed grammar, checked-in
//! corpus, canonical JSON, workflow, diagnostic, resource, current YAML
//! consumers/writers, and acceptance-satisfiability,
//! execution-consumption, child-owner, and gap inventories. It does not prove
//! arbitrary YAML, parser replacement, runtime semantics for validation-only
//! fields, CLI conversion UX, or permission to remove the incumbent
//! `serde_yaml` dependency.

#![allow(missing_docs)]

use asupersync::lab::{OracleRegistry, Scenario};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/scenario_yaml_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/scenario_yaml_capability_inventory.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_004_config_scenario_formats.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const CAPABILITY_BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const BEAD_ID: &str = "asupersync-5z2scg.5.1";
const A3_BEAD_ID: &str = "asupersync-5z2scg.5.3.1";
const A3_PARENT_BEAD_ID: &str = "asupersync-5z2scg.5.3";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-SCENARIO-YAML-JSON";
const BASELINE_REVISION: &str = "295136459f9e3e38e7373394e713866ec0693a8d";
const AUTHORITY_REVISION: &str = "673a905631c5580cdc8037315569b72bd636ecca";
const A3_CAPTURED_REVISION: &str = "207a435d59bad452239caa773f3a7c64c8b5edbc";
const A3_SOURCE_PIN_PATHS_SHA256: &str =
    "1c532b020668307d39cec4db9c5c66e52442f1fd433546a7a2b7ce78c50e985b";
const DOC_BEGIN: &str = "<!-- BEGIN SCENARIO YAML CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END SCENARIO YAML CAPABILITY INVENTORY -->";

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

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn source_item<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing source marker {marker}"));
    let end = source[start..]
        .find("\n}\n")
        .map(|offset| start + offset + 2)
        .unwrap_or(source.len());
    &source[start..end]
}

fn validate_state_fields(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_state_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                let child_path = format!("{path}.{key}");
                if matches!(key.as_str(), "inventory_state" | "evidence_state")
                    && child.as_str() == Some("UNKNOWN")
                {
                    return Err(format!("{child_path} must not be UNKNOWN"));
                }
                validate_state_fields(child, &child_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_a3_acceptance_satisfiability(inventory: &Value) -> Result<(), String> {
    let audit = inventory
        .get("a3_acceptance_satisfiability_audit")
        .ok_or_else(|| "a3_acceptance_satisfiability_audit is required".to_owned())?;
    for (key, expected) in [
        ("bead_id", A3_BEAD_ID),
        ("parent_bead_id", A3_PARENT_BEAD_ID),
        ("captured_revision", A3_CAPTURED_REVISION),
        ("audit_state", "LIVE_SOURCE_BOUND_STATIC_AUDIT"),
        ("execution_state", "NOT_RUN_BY_A3_1_STATIC_LANE"),
    ] {
        if audit.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("a3 audit {key} must be {expected}"));
        }
    }

    let authority = object(audit, "authority");
    for (key, expected) in [
        ("current_disposition", "KEEP_INCUMBENT"),
        ("required_disposition", "KEEP_INCUMBENT"),
        ("audit_owner_bead", A3_BEAD_ID),
        ("durable_receipt_owner_bead", "asupersync-5z2scg.5.3.2"),
        ("additive_authoring_owner_bead", "asupersync-5z2scg.5.4"),
        ("terminal_cutover_authority_bead", "asupersync-5z2scg.5.5"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("a3 authority {key} must be {expected}"));
        }
    }
    for key in [
        "dependency_exit_allowed",
        "input_narrowing_allowed",
        "owned_parser_present",
        "owned_writer_present",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("a3 authority {key} must remain false"));
        }
    }
    if !authority
        .get("owner_policy_receipt")
        .is_some_and(Value::is_null)
    {
        return Err("A3.1 must not invent an owner policy receipt".to_owned());
    }

    let authority_revisions = object(audit, "authority_source_revisions");
    for (key, expected) in [
        (
            "capability_registry_revision",
            "5f208e04f24d8addaa051c9bf7465f7b398848fe",
        ),
        (
            "capability_baseline_revision",
            "7390d33f4ac297cd28138c8e1ece38f60b278660",
        ),
        (
            "api_surface_map_revision",
            "2c7f2dd883cbbac1df6581f65673cf23eb40ee3d",
        ),
    ] {
        if authority_revisions.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("A3.1 authority revision {key} must be {expected}"));
        }
    }

    let a1_a2_join = object(audit, "a1_a2_join");
    for (key, expected) in [
        (
            "a1_inventory_commit",
            "b89b713164e161ca58697e17d129229c94e2254e",
        ),
        (
            "a2_canonical_json_commit",
            "bf5bdd619a087e8a9aef1c983726cbee7adea7fd",
        ),
        ("a1_content_baseline_revision", BASELINE_REVISION),
        (
            "prior_executable_evidence_state",
            "EXECUTED_AT_A1_A2_REVISIONS_NOT_RERUN_BY_A3_1",
        ),
        (
            "a3_1_evidence_kind",
            "STATIC_SOURCE_AND_ARTIFACT_AUDIT_ONLY",
        ),
    ] {
        if a1_a2_join.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("A3.1 A1/A2 join {key} must be {expected}"));
        }
    }
    for (key, expected) in [
        ("grammar_construct_count", 23),
        ("typed_corpus_file_count", 13),
        ("diagnostic_contract_count", 10),
        ("resource_contract_count", 8),
    ] {
        if a1_a2_join.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("A3.1 A1/A2 join {key} must be {expected}"));
        }
    }
    if a1_a2_join
        .get("all_corpus_fingerprints_match_current_files")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("A3.1 A1/A2 join must preserve current corpus fingerprints".to_owned());
    }

    let pin_refresh = object(audit, "source_pin_refresh");
    if pin_refresh
        .get("previous_path_count")
        .and_then(Value::as_u64)
        != Some(17)
        || pin_refresh
            .get("current_path_count")
            .and_then(Value::as_u64)
            != Some(32)
        || pin_refresh
            .get("refreshed_stale_path_count")
            .and_then(Value::as_u64)
            != Some(6)
        || pin_refresh
            .get("added_path_count")
            .and_then(Value::as_u64)
            != Some(15)
        || pin_refresh
            .get("sorted_path_projection_sha256")
            .and_then(Value::as_str)
            != Some(A3_SOURCE_PIN_PATHS_SHA256)
        || array(
            audit.get("source_pin_refresh").expect("source pin refresh"),
            "refreshed_stale_paths",
        )
        .len()
            != 6
        || array(audit.get("source_pin_refresh").expect("source pin refresh"), "added_paths")
            .len()
            != 15
    {
        return Err("A3.1 source-pin refresh counts or projection drifted".to_owned());
    }
    let expected_refreshed_paths: BTreeSet<String> = [
        "Cargo.lock",
        "Cargo.toml",
        "TESTING_FOR_AGENTS.md",
        "examples/metadata.json",
        "src/bin/asupersync.rs",
        "src/lab/mod.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_added_paths: BTreeSet<String> = [
        ".github/workflows/methodology-gates.yml",
        "artifacts/api_surface_map_v1.json",
        "artifacts/dependency_capability_baseline_v1.json",
        "artifacts/dependency_capability_registry_v1.json",
        "pnpm-workspace.yaml",
        "scripts/provision_kafka_test_env.rs",
        "scripts/validate_npm_pack_smoke.sh",
        "scripts/validate_package_build.sh",
        "src/conformance/mod.rs",
        "src/http/h1/codec.rs",
        "src/observability/diagnostics.rs",
        "tests/examples_metadata_contract.rs",
        "tests/phase6_methodology_gate_contract.rs",
        "tests/scenario_yaml_capability_inventory_contract.rs",
        "tools/demos/time_travel.yaml",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(
        audit.get("source_pin_refresh").expect("source pin refresh"),
        "refreshed_stale_paths",
    ) != expected_refreshed_paths
        || string_set(
            audit.get("source_pin_refresh").expect("source pin refresh"),
            "added_paths",
        ) != expected_added_paths
    {
        return Err("A3.1 source-pin refresh path sets drifted".to_owned());
    }

    let dependency_edges = array(audit, "dependency_edges");
    let expected_dependency_edges: BTreeSet<String> = [
        "SCN-A3-EDGE-FRANKENLAB-NORMAL",
        "SCN-A3-EDGE-ROOT-CLI-NORMAL",
        "SCN-A3-EDGE-ROOT-DEV",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if dependency_edges.len() != 3
        || row_ids(dependency_edges, "edge_id") != expected_dependency_edges
    {
        return Err("A3.1 must freeze the exact three direct serde_yaml edges".to_owned());
    }
    for (edge_id, package, edge_kind, manifest_path, declaration, activation, default_profile) in [
        (
            "SCN-A3-EDGE-ROOT-CLI-NORMAL",
            "asupersync",
            "OPTIONAL_NORMAL",
            "Cargo.toml",
            "serde_yaml = { version = \"0.9\", optional = true }",
            "cli -> dep:serde_yaml",
            false,
        ),
        (
            "SCN-A3-EDGE-ROOT-DEV",
            "asupersync",
            "DEV",
            "Cargo.toml",
            "serde_yaml = \"0.9\"",
            "root tests and adjacent workflow contract",
            false,
        ),
        (
            "SCN-A3-EDGE-FRANKENLAB-NORMAL",
            "frankenlab",
            "NORMAL",
            "frankenlab/Cargo.toml",
            "serde_yaml = \"0.9\"",
            "frankenlab binary and tests",
            true,
        ),
    ] {
        let row = find_row(dependency_edges, "edge_id", edge_id);
        for (key, expected) in [
            ("package", package),
            ("edge_kind", edge_kind),
            ("manifest_path", manifest_path),
            ("declaration", declaration),
            ("activation", activation),
            ("evidence_state", "SOURCE_BASELINED"),
        ] {
            if row.get(key).and_then(Value::as_str) != Some(expected) {
                return Err(format!("A3.1 dependency edge {edge_id} {key} drifted"));
            }
        }
        if row
            .get("default_profile_includes_edge")
            .and_then(Value::as_bool)
            != Some(default_profile)
        {
            return Err(format!("A3.1 dependency edge {edge_id} profile drifted"));
        }
    }
    let locked = object(audit, "locked_dependency");
    for (key, expected) in [
        ("package", "serde_yaml"),
        ("version", "0.9.34+deprecated"),
        (
            "checksum",
            "6a8b1a1a2ebf674015cc02edccce75287f1a0130d394307b36743c2f5d504b47",
        ),
        ("backend_package", "unsafe-libyaml"),
        ("backend_version", "0.2.11"),
        (
            "backend_checksum",
            "673aac59facbab8a9007c7f6108d11f63b603f7cabff99fabf650fea5c32b861",
        ),
    ] {
        if locked.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("locked dependency {key} must be {expected}"));
        }
    }

    let consumer_scope = object(audit, "consumer_matrix_scope");
    for (key, expected) in [
        (
            "included_surface",
            "EVERY_TRACKED_RUST_SOURCE_WITH_DIRECT_SERDE_YAML_SYNTAX",
        ),
        (
            "writer_scope",
            "EVERY_CURRENT_EXPLICIT_YAML_WRITER_FOUND_BY_STATIC_SOURCE_INVENTORY",
        ),
        ("inventory_state", "FROZEN"),
        ("evidence_state", "SOURCE_BASELINED"),
    ] {
        if consumer_scope.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("A3.1 consumer scope {key} must be {expected}"));
        }
    }
    for (key, expected) in [
        ("included_direct_source_count", 7),
        ("included_live_semantic_consumer_count", 6),
        ("included_documentation_only_reference_count", 1),
        ("included_live_production_loader_count", 2),
        ("included_adjacent_semantic_parser_count", 1),
    ] {
        if consumer_scope.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("A3.1 consumer scope {key} must be {expected}"));
        }
    }
    if consumer_scope
        .get("raw_references_do_not_retain_serde_yaml")
        .and_then(Value::as_bool)
        != Some(true)
        || !text(
            audit.get("consumer_matrix_scope").expect("consumer matrix scope"),
            "raw_reference_policy",
        )
        .contains("excluded from the direct parser/reference matrix")
    {
        return Err("A3.1 raw-reference exclusion must remain explicit".to_owned());
    }

    let consumers = array(audit, "consumer_matrix");
    let expected_consumers: BTreeSet<String> = [
        "SCN-A3-CONSUMER-A1-CONTRACT",
        "SCN-A3-CONSUMER-ADOPTION-FUNNEL",
        "SCN-A3-CONSUMER-FRANKENLAB",
        "SCN-A3-CONSUMER-METHODOLOGY-WORKFLOW",
        "SCN-A3-CONSUMER-ROOT-CLI",
        "SCN-A3-CONSUMER-ROOT-INTEGRATION",
        "SCN-A3-CONSUMER-RUNNER-DOC-EXAMPLE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if consumers.len() != 7 || row_ids(consumers, "consumer_id") != expected_consumers {
        return Err("A3.1 consumer matrix identity set drifted".to_owned());
    }
    for (consumer_id, category, path, dependency_edge, operation, bound, evidence_state) in [
        (
            "SCN-A3-CONSUMER-ROOT-CLI",
            "PRODUCTION_SCENARIO_LOADER",
            "src/bin/asupersync.rs",
            Some("SCN-A3-EDGE-ROOT-CLI-NORMAL"),
            "WHOLE_FILE_READ_THEN_TYPED_DESERIALIZE",
            "NONE",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-CONSUMER-FRANKENLAB",
            "PRODUCTION_SCENARIO_LOADER",
            "frankenlab/src/main.rs",
            Some("SCN-A3-EDGE-FRANKENLAB-NORMAL"),
            "WHOLE_FILE_READ_THEN_TYPED_DESERIALIZE",
            "NONE",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-CONSUMER-ROOT-INTEGRATION",
            "TEST_SCENARIO_LOADER_AND_WRITER",
            "tests/frankenlab_integration.rs",
            Some("SCN-A3-EDGE-ROOT-DEV"),
            "TYPED_DESERIALIZE_AND_TEST_ONLY_SERIALIZE",
            "FIXTURE_ONLY_NO_APPLICATION_POLICY",
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-CONSUMER-ADOPTION-FUNNEL",
            "TEST_SCENARIO_LOADER",
            "frankenlab/tests/adoption_funnel.rs",
            Some("SCN-A3-EDGE-FRANKENLAB-NORMAL"),
            "WHOLE_FILE_READ_THEN_TYPED_DESERIALIZE",
            "FIXTURE_ONLY_NO_APPLICATION_POLICY",
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-CONSUMER-A1-CONTRACT",
            "TEST_GRAMMAR_AND_CORPUS_CONTRACT",
            "tests/scenario_yaml_capability_inventory_contract.rs",
            Some("SCN-A3-EDGE-ROOT-DEV"),
            "TYPED_DESERIALIZE_AND_STATIC_SOURCE_ASSERTIONS",
            "FIXTURE_ONLY_NO_APPLICATION_POLICY",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-CONSUMER-METHODOLOGY-WORKFLOW",
            "ADJACENT_SEMANTIC_YAML_PARSER",
            "tests/phase6_methodology_gate_contract.rs",
            Some("SCN-A3-EDGE-ROOT-DEV"),
            "WHOLE_FILE_READ_THEN_VALUE_DESERIALIZE",
            "FIXTURE_ONLY_NO_APPLICATION_POLICY",
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-CONSUMER-RUNNER-DOC-EXAMPLE",
            "DOCUMENTATION_ONLY_YAML_EXAMPLE",
            "src/lab/scenario_runner.rs",
            None,
            "DOCUMENTED_TYPED_DESERIALIZE_NOT_LIVE_LOADER",
            "NOT_APPLICABLE_DOCUMENTATION_ONLY",
            "SOURCE_BASELINED",
        ),
    ] {
        let row = find_row(consumers, "consumer_id", consumer_id);
        for (key, expected) in [
            ("category", category),
            ("path", path),
            ("operation", operation),
            ("application_input_bound", bound),
            ("evidence_state", evidence_state),
        ] {
            if row.get(key).and_then(Value::as_str) != Some(expected) {
                return Err(format!("A3.1 consumer {consumer_id} {key} drifted"));
            }
        }
        if row.get("dependency_edge_id").and_then(Value::as_str) != dependency_edge {
            return Err(format!("A3.1 consumer {consumer_id} dependency edge drifted"));
        }
    }
    let doc_reference = find_row(
        consumers,
        "consumer_id",
        "SCN-A3-CONSUMER-RUNNER-DOC-EXAMPLE",
    );
    if doc_reference
        .get("documented_dependency_name")
        .and_then(Value::as_str)
        != Some("serde_yaml")
    {
        return Err("A3.1 documentation reference must not masquerade as an edge".to_owned());
    }
    let production_loader_count = consumers
        .iter()
        .filter(|row| text(row, "category") == "PRODUCTION_SCENARIO_LOADER")
        .count();
    if production_loader_count != 2
        || consumers
            .iter()
            .filter(|row| text(row, "category") == "PRODUCTION_SCENARIO_LOADER")
            .any(|row| text(row, "application_input_bound") != "NONE")
    {
        return Err(
            "both production loaders must remain present and application-unbounded".to_owned(),
        );
    }

    let expected_semantic_sources: BTreeSet<String> = [
        "frankenlab/src/main.rs",
        "frankenlab/tests/adoption_funnel.rs",
        "src/bin/asupersync.rs",
        "src/lab/scenario_runner.rs",
        "tests/frankenlab_integration.rs",
        "tests/phase6_methodology_gate_contract.rs",
        "tests/scenario_yaml_capability_inventory_contract.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(audit, "semantic_serde_yaml_source_allowset") != expected_semantic_sources {
        return Err("direct serde_yaml source allowset drifted".to_owned());
    }

    let writers = array(audit, "writer_matrix");
    let expected_writers: BTreeSet<String> = [
        "SCN-A3-WRITER-CONFORMANCE-MANIFEST",
        "SCN-A3-WRITER-DIAGNOSTIC-SNAPSHOT",
        "SCN-A3-WRITER-HTTP-SNAPSHOT",
        "SCN-A3-WRITER-KAFKA-COMPOSE",
        "SCN-A3-WRITER-PRODUCTION-SCENARIO",
        "SCN-A3-WRITER-TEST-SCENARIO",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if writers.len() != 6 || row_ids(writers, "writer_id") != expected_writers {
        return Err("A3.1 writer matrix identity set drifted".to_owned());
    }
    for (writer_id, category, path, operation, retains_serde_yaml, evidence_state) in [
        (
            "SCN-A3-WRITER-PRODUCTION-SCENARIO",
            "PRODUCTION_SCENARIO_YAML_WRITER",
            None,
            "ABSENT",
            false,
            "EXPLICIT_UNSUPPORTED",
        ),
        (
            "SCN-A3-WRITER-TEST-SCENARIO",
            "TEST_SCENARIO_YAML_WRITER",
            Some("tests/frankenlab_integration.rs"),
            "serde_yaml::to_string for typed round trip",
            true,
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-WRITER-KAFKA-COMPOSE",
            "ADJACENT_RAW_YAML_WRITER",
            Some("scripts/provision_kafka_test_env.rs"),
            "write static Docker Compose YAML text",
            false,
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-WRITER-CONFORMANCE-MANIFEST",
            "ADJACENT_TEST_MANUAL_YAML_WRITER",
            Some("src/conformance/mod.rs"),
            "render_conformance_manifest_yaml builds a deterministic test snapshot",
            false,
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-WRITER-HTTP-SNAPSHOT",
            "ADJACENT_TEST_YAML_SNAPSHOT_WRITER",
            Some("src/http/h1/codec.rs"),
            "insta::assert_yaml_snapshot in test module",
            false,
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-WRITER-DIAGNOSTIC-SNAPSHOT",
            "ADJACENT_TEST_YAML_SNAPSHOT_WRITER",
            Some("src/observability/diagnostics.rs"),
            "insta::assert_yaml_snapshot in test module",
            false,
            "EXISTING_TEST",
        ),
    ] {
        let row = find_row(writers, "writer_id", writer_id);
        for (key, expected) in [
            ("category", category),
            ("operation", operation),
            ("evidence_state", evidence_state),
        ] {
            if row.get(key).and_then(Value::as_str) != Some(expected) {
                return Err(format!("A3.1 writer {writer_id} {key} drifted"));
            }
        }
        if row.get("path").and_then(Value::as_str) != path
            || row.get("retains_serde_yaml_edge").and_then(Value::as_bool)
                != Some(retains_serde_yaml)
        {
            return Err(format!("A3.1 writer {writer_id} source join drifted"));
        }
    }
    let production_writer = find_row(
        writers,
        "writer_id",
        "SCN-A3-WRITER-PRODUCTION-SCENARIO",
    );
    if text(production_writer, "operation") != "ABSENT"
        || production_writer
            .get("retains_serde_yaml_edge")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("A3.1 must not claim a production Scenario YAML writer".to_owned());
    }

    let grammar = array(inventory, "grammar_constructs");
    let partition = object(audit, "grammar_partition");
    let mut partition_ids = BTreeSet::new();
    for key in [
        "accepted_or_accepted_with_documented_projection",
        "rejected_by_typed_parse",
        "parsed_then_rejected_semantically",
        "parser_internal_boundaries",
        "typed_deserialization_behavior_boundaries",
    ] {
        for id in string_set(audit.get("grammar_partition").expect("grammar partition"), key) {
            if !partition_ids.insert(id.clone()) {
                return Err(format!("grammar partition duplicates {id}"));
            }
        }
    }
    if partition.get("construct_count").and_then(Value::as_u64) != Some(23)
        || partition
            .get("partition_is_disjoint_and_complete")
            .and_then(Value::as_bool)
            != Some(true)
        || partition_ids != row_ids(grammar, "construct_id")
    {
        return Err("A3.1 grammar partition must be the exact 23-row A1 set".to_owned());
    }
    let expected_accepted: BTreeSet<String> = [
        "SCN-YAML-ANCHOR-ALIAS",
        "SCN-YAML-COMMENTS",
        "SCN-YAML-FLOW-COLLECTIONS",
        "SCN-YAML-HEX-OCTAL-BINARY-INTEGER",
        "SCN-YAML-MAPPING",
        "SCN-YAML-MERGE-KEY",
        "SCN-YAML-NULL-IN-OPTION",
        "SCN-YAML-NULL-IN-STRING",
        "SCN-YAML-QUOTED-AND-BLOCK-STRINGS",
        "SCN-YAML-SEQUENCE",
        "SCN-YAML-TAGGED-SCALAR",
        "SCN-YAML-U64-MAX",
        "SCN-YAML-UNICODE",
        "SCN-YAML-UNKNOWN-FIELD",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_rejected: BTreeSet<String> = [
        "SCN-YAML-DUPLICATE-MAPPING-KEY",
        "SCN-YAML-EMPTY-DOCUMENT",
        "SCN-YAML-LEGACY-YES-NO-BOOL",
        "SCN-YAML-MULTI-DOCUMENT",
        "SCN-YAML-U64-OVERFLOW",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for (key, expected_ids) in [
        (
            "accepted_or_accepted_with_documented_projection",
            expected_accepted,
        ),
        ("rejected_by_typed_parse", expected_rejected),
        (
            "parsed_then_rejected_semantically",
            ["SCN-YAML-NAN-INFINITY"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        (
            "parser_internal_boundaries",
            ["SCN-YAML-ALIAS-REPETITION", "SCN-YAML-RECURSION"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        (
            "typed_deserialization_behavior_boundaries",
            ["SCN-YAML-ARBITRARY-TAGS"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
    ] {
        if string_set(audit.get("grammar_partition").expect("grammar partition"), key)
            != expected_ids
        {
            return Err(format!("A3.1 grammar bucket {key} drifted"));
        }
    }

    let corpus_join = object(audit, "corpus_join");
    if corpus_join
        .get("required_file_count")
        .and_then(Value::as_u64)
        != Some(13)
        || corpus_join
            .get("root_example_count")
            .and_then(Value::as_u64)
            != Some(10)
        || corpus_join
            .get("frankenlab_example_count")
            .and_then(Value::as_u64)
            != Some(3)
        || corpus_join
            .get("all_current_fingerprints_match")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("A3.1 corpus join must preserve all thirteen current files".to_owned());
    }

    let unknown_fields = object(audit, "unknown_field_contract");
    if unknown_fields
        .get("root_typed_struct")
        .and_then(Value::as_str)
        != Some("ACCEPT_AND_IGNORE")
        || unknown_fields
            .get("nested_typed_structs")
            .and_then(Value::as_str)
            != Some("ACCEPT_AND_IGNORE")
        || unknown_fields
            .get("deny_unknown_fields_present")
            .and_then(Value::as_bool)
            != Some(false)
        || unknown_fields
            .get("tightening_requires_owner_policy")
            .and_then(Value::as_bool)
            != Some(true)
        || unknown_fields
            .get("owner_policy_approved")
            .and_then(Value::as_bool)
            != Some(false)
        || string_set(
            audit.get("unknown_field_contract").expect("unknown field contract"),
            "preserved_extension_maps",
        )
            != ["faults[].args", "metadata", "participants[].properties"]
                .into_iter()
                .map(str::to_owned)
                .collect()
    {
        return Err("A3.1 unknown-field policy drifted or was tightened".to_owned());
    }

    let diagnostics = array(audit, "diagnostic_matrix");
    let expected_diagnostic_surfaces: BTreeSet<String> = [
        "SCN-A3-DIAGNOSTIC-FRANKENLAB",
        "SCN-A3-DIAGNOSTIC-ORACLE-AND-REPLAY",
        "SCN-A3-DIAGNOSTIC-PARSER-BOUNDARIES",
        "SCN-A3-DIAGNOSTIC-ROOT-CLI",
        "SCN-A3-DIAGNOSTIC-SEMANTIC",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(diagnostics, "surface_id") != expected_diagnostic_surfaces {
        return Err("A3.1 diagnostic surface identities drifted".to_owned());
    }
    for (surface_id, contract_ids, behavior, evidence_state) in [
        (
            "SCN-A3-DIAGNOSTIC-ROOT-CLI",
            ["SCN-DIAG-READ-ASUP", "SCN-DIAG-PARSE-ASUP"],
            "structured scenario_parse_error USER_ERROR with path, parser text and available location, plus generic hint",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-DIAGNOSTIC-FRANKENLAB",
            ["SCN-DIAG-READ-FRANKEN", "SCN-DIAG-PARSE-FRANKEN"],
            "plain string with path, I/O or parser text and available location, plus generic hint",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-DIAGNOSTIC-SEMANTIC",
            ["SCN-DIAG-SEMANTIC", "SCN-DIAG-VERSION"],
            "aggregate field-like validation paths without YAML source spans",
            "EXISTING_TEST",
        ),
        (
            "SCN-A3-DIAGNOSTIC-ORACLE-AND-REPLAY",
            ["SCN-DIAG-REPLAY-DIVERGENCE", "SCN-DIAG-UNKNOWN-ORACLE"],
            "unknown oracles are rejected; runner owns ASUP-E401 while both CLI adapters omit that token",
            "SOURCE_BASELINED",
        ),
        (
            "SCN-A3-DIAGNOSTIC-PARSER-BOUNDARIES",
            ["SCN-DIAG-DUPLICATE", "SCN-DIAG-MULTI-DOCUMENT"],
            "duplicate keys are located and multiple documents are rejected",
            "SOURCE_BASELINED",
        ),
    ] {
        let row = find_row(diagnostics, "surface_id", surface_id);
        let expected_contract_ids: BTreeSet<String> =
            contract_ids.into_iter().map(str::to_owned).collect();
        if string_set(row, "contract_ids") != expected_contract_ids
            || text(row, "behavior") != behavior
            || text(row, "evidence_state") != evidence_state
            || row
                .get("yaml_source_spans_for_semantic_errors")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(format!("A3.1 diagnostic surface {surface_id} drifted"));
        }
    }
    let diagnostic_ids: BTreeSet<String> = diagnostics
        .iter()
        .flat_map(|row| string_set(row, "contract_ids"))
        .collect();
    let diagnostic_assignment_count: usize = diagnostics
        .iter()
        .map(|row| array(row, "contract_ids").len())
        .sum();
    if diagnostics.len() != 5
        || diagnostic_assignment_count != 10
        || diagnostic_ids != row_ids(array(inventory, "diagnostic_contracts"), "diagnostic_id")
    {
        return Err("A3.1 diagnostic matrix must cover all ten A1 contracts".to_owned());
    }

    let limits = array(audit, "application_limit_matrix");
    let expected_limits: BTreeSet<String> = [
        "SCN-A3-LIMIT-ALIAS-REPETITION",
        "SCN-A3-LIMIT-DOCUMENT-BYTES",
        "SCN-A3-LIMIT-FAULT-COUNT",
        "SCN-A3-LIMIT-INCLUDE-PATH",
        "SCN-A3-LIMIT-MAPPING-COUNT",
        "SCN-A3-LIMIT-NESTING",
        "SCN-A3-LIMIT-PARSE-WORK",
        "SCN-A3-LIMIT-RUNTIME-STEPS",
        "SCN-A3-LIMIT-SCALAR-LENGTH",
        "SCN-A3-LIMIT-SEQUENCE-COUNT",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if limits.len() != 10 || row_ids(limits, "limit_id") != expected_limits {
        return Err("A3.1 application-limit matrix identity set drifted".to_owned());
    }
    for (limit_id, policy, finite_replacement_bound_required) in [
        ("SCN-A3-LIMIT-DOCUMENT-BYTES", "NONE", true),
        ("SCN-A3-LIMIT-SCALAR-LENGTH", "NONE", true),
        ("SCN-A3-LIMIT-MAPPING-COUNT", "NONE", true),
        ("SCN-A3-LIMIT-SEQUENCE-COUNT", "NONE", true),
        ("SCN-A3-LIMIT-PARSE-WORK", "NONE", true),
        ("SCN-A3-LIMIT-NESTING", "NONE", true),
        ("SCN-A3-LIMIT-ALIAS-REPETITION", "NONE", true),
        (
            "SCN-A3-LIMIT-INCLUDE-PATH",
            "PER_ENTRY_SEMANTIC_VALIDATION_ONLY",
            false,
        ),
        (
            "SCN-A3-LIMIT-FAULT-COUNT",
            "OPTIONAL_AUTHOR_SELECTED_POST_PARSE_CAP",
            false,
        ),
        (
            "SCN-A3-LIMIT-RUNTIME-STEPS",
            "OPTIONAL_EXECUTION_CONTROL_NOT_PARSE_BOUND",
            false,
        ),
    ] {
        let row = find_row(limits, "limit_id", limit_id);
        if text(row, "current_application_policy") != policy
            || row
                .get("finite_replacement_bound_required")
                .and_then(Value::as_bool)
                != Some(finite_replacement_bound_required)
        {
            return Err(format!("A3.1 limit policy {limit_id} drifted"));
        }
    }
    for limit_id in [
        "SCN-A3-LIMIT-DOCUMENT-BYTES",
        "SCN-A3-LIMIT-MAPPING-COUNT",
        "SCN-A3-LIMIT-PARSE-WORK",
        "SCN-A3-LIMIT-SCALAR-LENGTH",
        "SCN-A3-LIMIT-SEQUENCE-COUNT",
    ] {
        let row = find_row(limits, "limit_id", limit_id);
        if text(row, "current_application_policy") != "NONE"
            || row
                .get("finite_replacement_bound_required")
                .and_then(Value::as_bool)
                != Some(true)
            || row
                .get("independent_unsat_witness")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(format!("{limit_id} must retain its finite-bound contradiction"));
        }
    }
    for limit_id in ["SCN-A3-LIMIT-NESTING", "SCN-A3-LIMIT-ALIAS-REPETITION"] {
        let row = find_row(limits, "limit_id", limit_id);
        if text(row, "current_application_policy") != "NONE"
            || row
                .get("incumbent_internal_limit")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(format!("{limit_id} must distinguish parser-internal policy"));
        }
    }
    for limit_id in [
        "SCN-A3-LIMIT-INCLUDE-PATH",
        "SCN-A3-LIMIT-FAULT-COUNT",
        "SCN-A3-LIMIT-RUNTIME-STEPS",
    ] {
        if find_row(limits, "limit_id", limit_id)
            .get("post_parse_or_execution_control")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(format!("{limit_id} must retain its non-parse control boundary"));
        }
    }

    let decision = object(audit, "satisfiability_decision");
    for (key, expected) in [
        ("satisfiability", "UNSATISFIABLE_UNDER_CURRENT_ACCEPTANCE"),
        ("policy_resolution", "OWNER_POLICY_REQUIRED"),
        ("required_disposition", "KEEP_INCUMBENT"),
    ] {
        if decision.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("A3.1 decision {key} must be {expected}"));
        }
    }
    if decision
        .get("owner_policy_approved")
        .and_then(Value::as_bool)
        != Some(false)
        || decision
            .get("owned_candidate_present")
            .and_then(Value::as_bool)
            != Some(false)
        || decision
            .get("all_currently_accepted_documents_must_remain_accepted")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("all_replacement_bounds_must_be_finite")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("witness_families_are_flat_and_semantically_valid")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("A3.1 satisfiability premises must fail closed to KEEP".to_owned());
    }

    let unresolved = array(audit, "unresolved_rows");
    let expected_unresolved: BTreeSet<String> = [
        "SCN-A3-UNRESOLVED-CONSUMER-CUTOVER",
        "SCN-A3-UNRESOLVED-DIAGNOSTIC-PARITY",
        "SCN-A3-UNRESOLVED-GRAMMAR-DIFFERENTIAL",
        "SCN-A3-UNRESOLVED-OWNED-PARSER",
        "SCN-A3-UNRESOLVED-OWNED-WRITER",
        "SCN-A3-UNRESOLVED-OWNER-INPUT-POLICY",
        "SCN-A3-UNRESOLVED-WRITER-PARITY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if unresolved.len() != 7 || row_ids(unresolved, "row_id") != expected_unresolved {
        return Err("A3.1 unresolved row identities drifted".to_owned());
    }
    for (row_id, owner, state) in [
        (
            "SCN-A3-UNRESOLVED-OWNER-INPUT-POLICY",
            "product owner",
            "MISSING",
        ),
        (
            "SCN-A3-UNRESOLVED-OWNED-PARSER",
            "future replacement campaign",
            "ABSENT",
        ),
        (
            "SCN-A3-UNRESOLVED-OWNED-WRITER",
            "future replacement campaign",
            "ABSENT",
        ),
        (
            "SCN-A3-UNRESOLVED-GRAMMAR-DIFFERENTIAL",
            "future replacement campaign",
            "NOT_RUN",
        ),
        (
            "SCN-A3-UNRESOLVED-DIAGNOSTIC-PARITY",
            "future replacement campaign",
            "NOT_PROVEN",
        ),
        (
            "SCN-A3-UNRESOLVED-WRITER-PARITY",
            "future replacement campaign",
            "NOT_PROVEN",
        ),
        (
            "SCN-A3-UNRESOLVED-CONSUMER-CUTOVER",
            "asupersync-5z2scg.5.5",
            "NOT_AUTHORIZED",
        ),
    ] {
        let row = find_row(unresolved, "row_id", row_id);
        if text(row, "owner") != owner
            || text(row, "state") != state
            || row.get("blocking").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!("A3.1 unresolved row {row_id} drifted"));
        }
    }
    let handoff = object(audit, "downstream_handoff");
    if handoff
        .get("on_missing_or_regressed_row")
        .and_then(Value::as_str)
        != Some("KEEP_INCUMBENT")
        || handoff
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || !text(audit, "no_claim_boundary").contains("only A5")
    {
        return Err("A3.1 handoff and no-claim boundary must remain fail closed".to_owned());
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "scenario-yaml-capability-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }
    if string_set(inventory, "mapped_capability_ids")
        != [CAPABILITY_ID, "CAP-LAB-DETERMINISM"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("mapped capabilities must freeze scenario format and lab determinism".into());
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", "DEP-ADR-004"),
        ("decision", "ADDITIVE_COEXISTENCE"),
        ("disposition", "KEEP_UNTIL_PARITY"),
        ("cutover_state", "KEEP_INCUMBENT"),
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
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy
            .get("accepted_yaml_must_remain_accepted")
            .and_then(Value::as_bool)
            != Some(true)
        || policy.get("json_is_additive").and_then(Value::as_bool) != Some(true)
    {
        return Err(
            "policy must preserve YAML, make JSON additive, and report zero unknowns".into(),
        );
    }
    for key in ["allowed_inventory_states", "allowed_evidence_states"] {
        if string_set(inventory.get("policy").expect("policy"), key).contains("UNKNOWN") {
            return Err(format!("{key} must not permit UNKNOWN"));
        }
    }
    validate_state_fields(inventory, "$")?;

    let expected_profiles: BTreeSet<String> = [
        "SCN-PROFILE-LIBRARY-DEFAULT",
        "SCN-PROFILE-ASUPERSYNC-CLI",
        "SCN-PROFILE-FRANKENLAB",
        "SCN-PROFILE-ROOT-TEST",
        "SCN-PROFILE-MESSAGING-FABRIC-OVERLAY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "feature_profiles"), "profile_id") != expected_profiles {
        return Err("feature profiles must cover the exact five live profiles".to_owned());
    }

    let expected_loaders: BTreeSet<String> = [
        "SCN-LOADER-ASUPERSYNC-CLI",
        "SCN-LOADER-FRANKENLAB",
        "SCN-LOADER-ROOT-INTEGRATION",
        "SCN-LOADER-ADOPTION-FUNNEL",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "loader_surfaces"), "loader_id") != expected_loaders {
        return Err("loader inventory must contain the two live and two test-local loaders".into());
    }

    let schema = inventory
        .get("typed_schema")
        .ok_or_else(|| "typed_schema is required".to_owned())?;
    if schema.get("root_field_count").and_then(Value::as_u64) != Some(16)
        || array(schema, "root_fields").len() != 16
        || array(schema, "required_root_fields") != &vec![Value::String("id:String".to_owned())]
    {
        return Err("typed root schema must freeze 16 fields with required id only".to_owned());
    }
    let nested = array(schema, "nested_sections");
    if nested.len() != 11 {
        return Err("typed schema must enumerate eleven nested section shapes".to_owned());
    }
    for row in nested {
        let count = row
            .get("field_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| "nested field_count is required".to_owned())?;
        if array(row, "fields").len() != count as usize {
            return Err(format!(
                "{} field_count does not match fields",
                text(row, "section")
            ));
        }
    }
    if array(schema, "dynamic_fault_arg_keys_validated").len() != 9 {
        return Err("nine dynamic fault argument keys must be frozen".to_owned());
    }

    let enum_counts = [
        ("SCN-ENUM-CHAOS", 4),
        ("SCN-ENUM-NETWORK", 7),
        ("SCN-ENUM-LATENCY", 3),
        ("SCN-ENUM-FAULT", 11),
        ("SCN-ENUM-CANCELLATION", 7),
        ("SCN-ENUM-GOLDEN-FORMAT", 2),
        ("SCN-EXPECTED-INVARIANTS", 5),
    ];
    let enum_domains = array(inventory, "enum_domains");
    if enum_domains.len() != enum_counts.len() {
        return Err("enum inventory must contain seven exact domains".to_owned());
    }
    for (domain_id, count) in enum_counts {
        if array(find_row(enum_domains, "domain_id", domain_id), "values").len() != count {
            return Err(format!("{domain_id} value count drifted"));
        }
    }

    let grammar = array(inventory, "grammar_constructs");
    if grammar.len() != 23 || row_ids(grammar, "construct_id").len() != 23 {
        return Err("grammar inventory must contain twenty-three unique constructs".to_owned());
    }
    let corpus = array(inventory, "corpus_files");
    if corpus.len() != 13 || row_ids(corpus, "corpus_id").len() != 13 {
        return Err("typed corpus must contain thirteen unique files".to_owned());
    }
    if array(inventory, "adjacent_yaml_files").len() != 3 {
        return Err("adjacent YAML inventory must contain three explicit classes".to_owned());
    }
    let workflows = array(inventory, "author_workflows");
    if workflows.len() != 11 || row_ids(workflows, "workflow_id").len() != 11 {
        return Err("author workflow inventory must contain eleven unique rows".to_owned());
    }
    let diagnostics = array(inventory, "diagnostic_contracts");
    if diagnostics.len() != 10 || row_ids(diagnostics, "diagnostic_id").len() != 10 {
        return Err("diagnostic inventory must contain ten unique rows".to_owned());
    }
    let resources = array(inventory, "resource_contracts");
    if resources.len() != 8 || row_ids(resources, "resource_id").len() != 8 {
        return Err("resource inventory must contain eight unique rows".to_owned());
    }

    let consumption = array(inventory, "execution_consumption");
    if consumption.len() != 13 {
        return Err("execution-consumption inventory must contain thirteen groups".to_owned());
    }
    let consumption_states: BTreeSet<String> = consumption
        .iter()
        .map(|row| text(row, "state").to_owned())
        .collect();
    if consumption_states
        != ["ACTIVE", "PARTIAL", "VALIDATION_ONLY"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err(
            "execution consumption must distinguish active, partial, and validation-only".into(),
        );
    }

    let expected_children: BTreeSet<String> = (1..=5)
        .map(|suffix| format!("asupersync-5z2scg.5.{suffix}"))
        .collect();
    let children = array(inventory, "child_capability_rows");
    if row_ids(children, "owner_bead") != expected_children {
        return Err("every SCN A1-A5 child must own exactly one row".to_owned());
    }
    for row in children {
        if array(row, "required_evidence").is_empty() || text(row, "no_claim").trim().is_empty() {
            return Err(format!(
                "{} must retain evidence and a no-claim boundary",
                text(row, "owner_bead")
            ));
        }
    }

    let expected_gaps: BTreeSet<String> = (1..=16)
        .map(|suffix| format!("SCN-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "known_gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("known scenario gaps must retain the exact routed set".to_owned());
    }
    for row in gaps {
        if text(row, "owner_bead").is_empty() || text(row, "evidence_state") != "BLOCKED_GAP" {
            return Err(format!(
                "{} must be routed and fail closed",
                text(row, "gap_id")
            ));
        }
    }
    if text(inventory, "no_claim_boundary").trim().is_empty() {
        return Err("top-level no-claim boundary is required".to_owned());
    }
    validate_a3_acceptance_satisfiability(inventory)?;
    Ok(())
}

#[test]
fn inventory_is_complete_source_pinned_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    let mut paths = BTreeSet::new();
    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        assert!(paths.insert(path.to_owned()), "duplicate source pin {path}");
        let bytes = read_repo_bytes(path);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "{path} source pin drifted");
        let line_count = read_repo_file(path).lines().count() as u64;
        assert_eq!(
            Some(line_count),
            pin.get("line_count").and_then(Value::as_u64),
            "{path} line count drifted"
        );
    }
    assert_eq!(paths.len(), 32, "A3.1 must retain 32 current source pins");
    let path_projection = paths.into_iter().collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(
        hex::encode(Sha256::digest(path_projection.as_bytes())),
        A3_SOURCE_PIN_PATHS_SHA256,
        "A3.1 sorted source-pin path projection drifted",
    );
}

#[test]
fn authority_profiles_and_live_loader_routes_are_truthful() {
    let adr = read_repo_file(ADR_PATH);
    for marker in [
        "ADDITIVE_COEXISTENCE",
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "CFG-GAP-03",
        "CFG-GAP-04",
        "asupersync-5z2scg.5.1",
    ] {
        assert!(adr.contains(marker), "ADR must retain {marker}");
    }

    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("capability registry must retain CAP-SCENARIO-YAML-JSON");
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );

    let baseline = parse_repo_json(CAPABILITY_BASELINE_PATH);
    let baseline_capability = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        text(baseline_capability, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert_eq!(
        baseline_capability
            .get("cutover_eligible")
            .and_then(Value::as_bool),
        Some(false)
    );

    let api_map = parse_repo_json(API_SURFACE_MAP_PATH);
    let api_map_text = api_map.to_string();
    assert!(
        api_map_text.contains("lab_scenario_yaml")
            && api_map_text.contains("lab::ScenarioRunner"),
        "API surface map must retain the YAML scenario journey"
    );

    let root_manifest = read_repo_file("Cargo.toml");
    let franken_manifest = read_repo_file("frankenlab/Cargo.toml");
    assert!(root_manifest.contains("\"dep:serde_yaml\""));
    assert!(root_manifest.contains("serde_yaml = { version = \"0.9\", optional = true }"));
    assert!(root_manifest.contains("serde_yaml = \"0.9\""));
    assert!(franken_manifest.contains("serde_yaml = \"0.9\""));

    let root_cli = read_repo_file("src/bin/asupersync.rs");
    let franken_cli = read_repo_file("frankenlab/src/main.rs");
    let scenario_model = read_repo_file("src/lab/scenario.rs");
    for source in [&root_cli, &franken_cli] {
        assert!(source.contains("fs::read_to_string"));
        assert!(source.contains("serde_yaml::from_str"));
    }
    assert!(!scenario_model.contains("serde_yaml::"));
    assert!(scenario_model.contains("pub fn from_json("));
    assert!(scenario_model.contains("pub fn to_json("));

    assert_eq!(OracleRegistry::reported_names().len(), 24);
    assert!(OracleRegistry::reported_names().contains(&"quiescence"));
    assert!(OracleRegistry::reported_names().contains(&"obligation_leak"));
}

#[test]
fn a3_current_consumers_writers_bounds_and_keep_decision_are_source_bound() {
    let inventory = artifact();
    validate_a3_acceptance_satisfiability(&inventory)
        .unwrap_or_else(|error| panic!("{error}"));

    let root_cli = read_repo_file("src/bin/asupersync.rs");
    let root_loader = source_item(&root_cli, "fn load_scenario(path: &Path)");
    assert!(root_loader.contains("fs::read_to_string(path)"));
    assert!(root_loader.contains("serde_yaml::from_str(&yaml)"));
    assert!(root_loader.contains("\"scenario_parse_error\""));
    assert!(root_cli.contains("fn load_scenario_parse_error_is_user_error("));
    assert!(root_cli.contains("fn lab_validate_json_uses_output_writer_and_user_error("));

    let franken_cli = read_repo_file("frankenlab/src/main.rs");
    let franken_parser = source_item(&franken_cli, "fn parse_scenario(path: &Path, yaml: &str)");
    let franken_loader = source_item(&franken_cli, "fn load_scenario(path: &Path)");
    assert!(franken_parser.contains("serde_yaml::from_str(yaml)"));
    assert!(franken_loader.contains("fs::read_to_string(path)"));
    assert!(franken_loader.contains("parse_scenario(path, &yaml)"));
    assert!(franken_cli.contains("fn find_scenarios_dir("));
    assert!(franken_cli.contains("fn collect_yaml_files("));

    for (surface, body) in [
        ("root loader", root_loader),
        ("frankenlab parser", franken_parser),
        ("frankenlab loader", franken_loader),
    ] {
        for forbidden_bound_marker in [
            "MAX_DOCUMENT",
            "MAX_SCALAR",
            "MAX_COLLECTION",
            "MAX_PARSE_WORK",
            "metadata(path)",
        ] {
            assert!(
                !body.contains(forbidden_bound_marker),
                "{surface} gained {forbidden_bound_marker}; refresh A3.1 bounds and decision"
            );
        }
    }

    for workflow_call in [
        "let scenario = load_scenario(&args.scenario)?;",
        "parse_scenario(path, raw).map(MinimizeInput::ScenarioYaml)",
    ] {
        assert!(
            root_cli.contains(workflow_call) || franken_cli.contains(workflow_call),
            "missing current workflow route {workflow_call}"
        );
    }

    let scenario = read_repo_file("src/lab/scenario.rs");
    assert!(scenario.contains("pub description: String"));
    assert!(scenario.contains("pub participants: Vec<Participant>"));
    assert!(scenario.contains("pub metadata: BTreeMap<String, String>"));
    assert!(!scenario.contains("deny_unknown_fields"));
    assert!(!scenario.contains("validate_description"));
    assert!(!scenario.contains("validate_metadata"));
    assert!(scenario.contains("if include.path.len() > 255"));
    assert!(scenario.contains("pub max_fault_events: Option<usize>"));
    assert!(scenario.contains("pub max_steps: Option<u64>"));

    let integration = read_repo_file("tests/frankenlab_integration.rs");
    let adoption = read_repo_file("frankenlab/tests/adoption_funnel.rs");
    let methodology = read_repo_file("tests/phase6_methodology_gate_contract.rs");
    let workflow = read_repo_file(".github/workflows/methodology-gates.yml");
    assert!(integration.contains("serde_yaml::to_string(&scenario)"));
    assert!(integration.contains("serde_yaml::from_str(&raw)"));
    assert!(adoption.contains("serde_yaml::from_str(&yaml)"));
    assert!(methodology.contains("serde_yaml::from_str(&workflow_text)"));
    assert!(methodology.contains(".github/workflows/methodology-gates.yml"));
    assert!(workflow.contains("pull_request:"));
    assert!(!root_cli.contains("serde_yaml::to_string"));
    assert!(!franken_cli.contains("serde_yaml::to_string"));

    let kafka_writer = read_repo_file("scripts/provision_kafka_test_env.rs");
    let conformance_writer = read_repo_file("src/conformance/mod.rs");
    let http_snapshot = read_repo_file("src/http/h1/codec.rs");
    let diagnostic_snapshot = read_repo_file("src/observability/diagnostics.rs");
    assert!(kafka_writer.contains("docker-compose-kafka-test.yml"));
    assert!(conformance_writer.contains("fn render_conformance_manifest_yaml("));
    assert!(http_snapshot.contains("insta::assert_yaml_snapshot!"));
    assert!(diagnostic_snapshot.contains("insta::assert_yaml_snapshot!"));

    let root_manifest = read_repo_file("Cargo.toml");
    let franken_manifest = read_repo_file("frankenlab/Cargo.toml");
    let lock = read_repo_file("Cargo.lock");
    assert!(root_manifest.contains("\"dep:serde_yaml\""));
    assert!(root_manifest.contains("serde_yaml = { version = \"0.9\", optional = true }"));
    assert!(root_manifest.contains("serde_yaml = \"0.9\""));
    assert!(franken_manifest.contains("serde_yaml = \"0.9\""));
    assert!(lock.contains("name = \"serde_yaml\"\nversion = \"0.9.34+deprecated\""));
    assert!(lock.contains("name = \"unsafe-libyaml\"\nversion = \"0.2.11\""));

    let audit = inventory
        .get("a3_acceptance_satisfiability_audit")
        .expect("A3.1 audit");
    let decision = object(audit, "satisfiability_decision");
    assert_eq!(
        text(decision, "satisfiability"),
        "UNSATISFIABLE_UNDER_CURRENT_ACCEPTANCE"
    );
    assert_eq!(text(decision, "policy_resolution"), "OWNER_POLICY_REQUIRED");
    assert_eq!(text(decision, "required_disposition"), "KEEP_INCUMBENT");
    assert_eq!(
        decision
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn canonical_json_contract_is_executable_and_residual_work_is_routed() {
    let inventory = artifact();
    let canonical = inventory
        .get("canonical_json_contract")
        .expect("canonical_json_contract must exist");
    assert_eq!(text(canonical, "encoder"), "Scenario::to_json");
    assert_eq!(text(canonical, "encoding"), "UTF-8");
    assert_eq!(
        text(canonical, "object_order"),
        "recursive lexicographic key order"
    );
    assert_eq!(
        text(canonical, "array_order"),
        "preserve typed source order"
    );
    assert_eq!(text(canonical, "evidence_state"), "EXECUTED");
    assert_eq!(
        string_set(canonical, "preserved_extension_channels"),
        ["faults[].args", "metadata", "participants[].properties",]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(string_set(canonical, "focused_evidence").len(), 5);

    let implicit = Scenario::from_json(r#"{"id":"test-scenario","description":"minimal test"}"#)
        .expect("parse defaulted v1 scenario");
    let explicit = Scenario::from_json(
        r#"{"schema_version":1,"id":"test-scenario","description":"minimal test"}"#,
    )
    .expect("parse explicit v1 scenario");
    assert_eq!(implicit, explicit);
    assert!(implicit.validate().is_empty());

    let canonical_bytes = implicit.to_json().expect("encode canonical scenario");
    assert_eq!(
        canonical_bytes,
        r#"{"cancellation":null,"chaos":{"preset":"off"},"description":"minimal test","expected_invariants":["quiescence","losers_drained","no_obligation_leaks","deterministic_replay"],"faults":[],"golden_projection":{"canonicalized":true,"format":"json","redacted":true},"id":"test-scenario","include":[],"lab":{"entropy_seed":null,"futurelock_max_idle_steps":10000,"max_steps":100000,"panic_on_futurelock":true,"panic_on_obligation_leak":true,"replay_recording":false,"seed":42,"trace_capacity":4096,"worker_count":1},"metadata":{},"minimization":{"enabled":false,"max_counterexample_events":null,"max_evaluations":null},"network":{"links":{},"preset":"ideal"},"oracles":["all"],"participants":[],"resource_caps":{"max_artifact_bytes":null,"max_counterexample_events":null,"max_fault_events":null},"schema_version":1}"#
    );
    assert_eq!(canonical_bytes, explicit.to_json().unwrap());
    assert_eq!(
        implicit,
        Scenario::from_json(&canonical_bytes).expect("round-trip canonical scenario")
    );

    let dynamic = Scenario::from_json(
        r#"{
            "id": "recursive-objects",
            "participants": [{
                "name": "worker",
                "properties": {
                    "z": {"beta": 2, "alpha": 1},
                    "a": [{"delta": 4, "charlie": 3}]
                }
            }]
        }"#,
    )
    .expect("parse recursive free-form objects");
    assert!(
        dynamic
            .to_json()
            .unwrap()
            .contains(r#""properties":{"a":[{"charlie":3,"delta":4}],"z":{"alpha":1,"beta":2}}"#)
    );

    let unsupported = Scenario::from_json(r#"{"schema_version":2,"id":"future"}"#)
        .expect("unsupported version remains parseable for validation diagnostics");
    assert!(
        unsupported
            .validate()
            .iter()
            .any(|error| error.field == "schema_version")
    );

    let scenario_model = read_repo_file("src/lab/scenario.rs");
    for marker in [
        "fn canonicalize_json_value(",
        "canonical_contract_full_json_roundtrip",
        "canonical_contract_matches_byte_golden",
        "canonical_contract_orders_dynamic_objects_recursively",
        "canonical_contract_migrates_missing_version_without_meaning_change",
    ] {
        assert!(
            scenario_model.contains(marker),
            "missing source marker {marker}"
        );
    }
    assert!(!scenario_model.contains("serde_yaml::"));

    let integration = read_repo_file("tests/frankenlab_integration.rs");
    assert!(integration.contains("canonical_contract_preserves_yaml_replay_identity"));
    assert!(integration.contains("assert_eq!(authored, reparsed)"));
    assert!(integration.contains("authored_run.certificate"));
    assert!(integration.contains("authored.expected_invariants"));

    let children = array(&inventory, "child_capability_rows");
    let a2 = find_row(children, "owner_bead", "asupersync-5z2scg.5.2");
    assert_eq!(text(a2, "evidence_state"), "EXECUTED");

    let gaps = array(&inventory, "known_gaps");
    for gap_id in ["SCN-GAP-06", "SCN-GAP-09"] {
        assert_eq!(
            text(find_row(gaps, "gap_id", gap_id), "owner_bead"),
            "asupersync-5z2scg.5.4"
        );
    }

    let doc = read_repo_file(DOC_PATH);
    for marker in [
        "### Canonical JSON contract",
        "compact UTF-8 with no trailing newline",
        "executed contract",
        "neither CLI exposes dump/conversion",
    ] {
        assert!(
            doc.contains(marker),
            "missing documentation marker {marker}"
        );
    }
}

#[test]
fn observed_yaml_grammar_matches_typed_parser_behavior() {
    let anchored: Scenario =
        serde_yaml::from_str("id: &scenario_id anchored\ndescription: *scenario_id\n")
            .expect("anchors and aliases must resolve");
    assert_eq!(anchored.id, "anchored");
    assert_eq!(anchored.description, "anchored");

    let merged: Scenario = serde_yaml::from_str(
        "base: &base\n  seed: 9\n  worker_count: 2\nid: merge\nlab:\n  <<: *base\n",
    )
    .expect("merge key is syntactically accepted as an ignored typed field");
    assert_eq!(
        merged.lab.seed, 42,
        "typed loader must not claim merge-key application"
    );
    assert_eq!(merged.lab.worker_count, 1);

    let tagged: Scenario = serde_yaml::from_str("id: !scenario tagged\n")
        .expect("tested scalar tag must be transparent");
    assert_eq!(tagged.id, "tagged");

    let duplicate = serde_yaml::from_str::<Scenario>("id: first\nid: second\n")
        .expect_err("duplicate mapping keys must fail");
    assert!(duplicate.to_string().contains("duplicate"));
    assert!(
        duplicate.location().is_some(),
        "duplicate error must be located"
    );

    let null_string: Scenario = serde_yaml::from_str("id: null-description\ndescription: null\n")
        .expect("serde_yaml 0.9 coerces null to a literal string for String targets");
    assert_eq!(null_string.description, "null");
    let null_option: Scenario = serde_yaml::from_str("id: null-max\nlab:\n  max_steps: null\n")
        .expect("null must map to None for Option");
    assert_eq!(null_option.lab.max_steps, None);

    let max: Scenario = serde_yaml::from_str("id: max-seed\nlab:\n  seed: 18446744073709551615\n")
        .expect("u64::MAX must parse");
    assert_eq!(max.lab.seed, u64::MAX);
    assert!(
        serde_yaml::from_str::<Scenario>("id: overflow-seed\nlab:\n  seed: 18446744073709551616\n")
            .is_err(),
        "u64 overflow must fail"
    );
    for (literal, expected) in [("0x2a", 42), ("0o52", 42), ("0b101010", 42)] {
        let yaml = format!("id: radix\nlab:\n  seed: {literal}\n");
        let scenario: Scenario = serde_yaml::from_str(&yaml).expect("radix integer must parse");
        assert_eq!(scenario.lab.seed, expected);
    }

    assert!(
        serde_yaml::from_str::<Scenario>("id: bool\nlab:\n  replay_recording: yes\n").is_err(),
        "legacy YAML 1.1 yes must not resolve as a bool"
    );
    let multi = serde_yaml::from_str::<Scenario>("---\nid: first\n---\nid: second\n")
        .expect_err("multiple documents must fail");
    assert!(
        multi.to_string().contains("more than one document"),
        "multi-document diagnostic drifted: {multi}"
    );

    let unknown: Scenario =
        serde_yaml::from_str("id: unknown\nfuture_root: true\nlab:\n  future_nested: 7\n")
            .expect("unknown root and nested fields are currently ignored");
    assert_eq!(unknown.lab.seed, 42);
    assert!(serde_yaml::from_str::<Scenario>("").is_err());

    let non_finite: Scenario = serde_yaml::from_str(
        "id: non-finite\nchaos:\n  preset: custom\n  cancel_probability: .nan\n",
    )
    .expect("non-finite YAML float must reach semantic validation");
    assert!(
        non_finite
            .validate()
            .iter()
            .any(|error| error.field == "chaos.cancel_probability"
                && error.message.contains("finite"))
    );

    let rich: Scenario = serde_yaml::from_str(
        "id: unicode-λ\n# discarded comment\ndescription: |\n  first line\n  second line\nmetadata: {emoji: \"🧪\"}\n",
    )
    .expect("Unicode, comments, block scalars, and flow mappings must parse");
    assert_eq!(rich.id, "unicode-λ");
    assert_eq!(rich.metadata.get("emoji").map(String::as_str), Some("🧪"));
    assert!(rich.description.contains("second line"));
}

#[test]
fn exact_checked_in_typed_corpus_parses_and_validates() {
    let inventory = artifact();
    for row in array(&inventory, "corpus_files") {
        let path = text(row, "path");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            text(row, "sha256"),
            "{path} corpus digest drifted"
        );
        assert_eq!(
            Some(bytes.len() as u64),
            row.get("byte_count").and_then(Value::as_u64),
            "{path} byte count drifted"
        );
        assert_eq!(
            Some(read_repo_file(path).lines().count() as u64),
            row.get("line_count").and_then(Value::as_u64),
            "{path} line count drifted"
        );
        let scenario: Scenario = serde_yaml::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{path} must parse as Scenario: {error}"));
        let errors = scenario.validate();
        assert!(
            errors.is_empty(),
            "{path} must validate: {}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    let composed: Scenario = serde_yaml::from_str(&read_repo_file(
        "examples/scenarios/composed_partition_test.yaml",
    ))
    .expect("composed fixture must parse");
    assert_eq!(composed.include.len(), 1);
    assert_eq!(composed.lab.seed, 55_555);
    assert_eq!(
        composed.lab.worker_count, 1,
        "include is not resolved; base worker_count=2 must not be claimed"
    );
    assert!(matches!(
        composed.chaos,
        asupersync::lab::scenario::ChaosSection::Off
    ));

    let adjacent = read_repo_file("tools/demos/time_travel.yaml");
    assert!(
        serde_yaml::from_str::<Scenario>(&adjacent).is_err(),
        "time-travel demo must remain explicitly classified as non-Scenario"
    );
    let source_reads = [
        read_repo_file("src/bin/asupersync.rs"),
        read_repo_file("frankenlab/src/main.rs"),
        read_repo_file("examples/demo_benchmark.rs"),
        read_repo_file("Makefile"),
    ]
    .join("\n");
    assert!(
        !source_reads.contains("tools/demos/time_travel.yaml"),
        "time-travel YAML gained a live reader and must be reclassified"
    );
}

#[test]
fn execution_consumption_diagnostics_and_gap_routing_stay_truthful() {
    let inventory = artifact();
    let runner = read_repo_file("src/lab/scenario_runner.rs");
    let scenario = read_repo_file("src/lab/scenario.rs");
    let root_cli = read_repo_file("src/bin/asupersync.rs");
    let franken_cli = read_repo_file("frankenlab/src/main.rs");

    for active in [
        "scenario.lab",
        "scenario.oracles",
        "scenario.faults",
        "scenario.resource_caps",
        "scenario.minimization",
        "scenario.golden_projection.redacted",
    ] {
        assert!(
            runner.contains(active),
            "runner active route {active} drifted"
        );
    }
    for validation_only in [
        "scenario.network",
        "scenario.cancellation",
        "scenario.expected_invariants",
        "scenario.include",
    ] {
        assert!(
            !runner.contains(validation_only),
            "{validation_only} gained runner consumption; update inventory and gap"
        );
    }
    assert!(scenario.contains("validate_network"));
    assert!(scenario.contains("validate_cancellation"));
    assert!(scenario.contains("validate_expected_invariants"));
    assert!(scenario.contains("validate_includes"));
    assert!(scenario.contains("Included fields are merged with the current file"));
    assert!(!root_cli.contains("apply_merge"));
    assert!(!franken_cli.contains("apply_merge"));

    assert!(root_cli.contains("\"scenario_parse_error\""));
    assert!(root_cli.contains("Hint: check indentation and field names"));
    assert!(root_cli.contains("fn write_replay_artifact("));
    assert!(root_cli.contains("fs::write(path, payload)"));
    assert!(scenario.contains("pub struct ValidationError"));
    assert!(runner.contains("[ASUP-E401]"));
    assert!(!root_cli.contains("[ASUP-E401]"));
    assert!(!franken_cli.contains("[ASUP-E401]"));

    let gaps = array(&inventory, "known_gaps");
    for gap_id in [
        "SCN-GAP-01",
        "SCN-GAP-02",
        "SCN-GAP-03",
        "SCN-GAP-08",
        "SCN-GAP-10",
        "SCN-GAP-15",
        "SCN-GAP-16",
    ] {
        assert_eq!(
            text(find_row(gaps, "gap_id", gap_id), "evidence_state"),
            "BLOCKED_GAP"
        );
    }
}

#[test]
fn documentation_workflows_and_no_claim_boundary_are_complete() {
    let inventory = artifact();
    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("documentation begin marker");
    let end = doc.find(DOC_END).expect("documentation end marker");
    assert!(begin < end);

    for marker in [
        CAPABILITY_ID,
        "CAP-LAB-DETERMINISM",
        BEAD_ID,
        A3_BEAD_ID,
        BASELINE_REVISION,
        A3_CAPTURED_REVISION,
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "UNSATISFIABLE_UNDER_CURRENT_ACCEPTANCE",
        "OWNER_POLICY_REQUIRED",
        "dependency_exit_allowed=false",
        "A3.1 did not rerun",
        "13 files",
        "validation-only",
        "does not schedule an application workload",
        "SCN-GAP-01",
        "SCN-GAP-16",
        "No-claim boundary",
        "RCH_REQUIRE_REMOTE=1",
        "--clean-overlay",
    ] {
        assert!(doc.contains(marker), "documentation must retain {marker}");
    }

    let workflows = array(&inventory, "author_workflows");
    for command in [
        "asupersync lab run <scenario>",
        "asupersync lab validate <scenario>",
        "asupersync lab replay <scenario>",
        "asupersync lab explore <scenario>",
        "frankenlab run <scenario>",
        "frankenlab validate <scenario>",
        "frankenlab replay <scenario>",
        "frankenlab explore <scenario>",
        "frankenlab minimize <input>",
        "frankenlab demo",
    ] {
        assert!(
            workflows
                .iter()
                .any(|row| row.get("command_surface").and_then(Value::as_str) == Some(command)),
            "missing workflow {command}"
        );
    }
    let unsupported = find_row(workflows, "workflow_id", "SCN-WORKFLOW-SCENARIO-DUMP");
    assert_eq!(text(unsupported, "evidence_state"), "EXPLICIT_UNSUPPORTED");
    assert!(text(&inventory, "no_claim_boundary").contains("permission to remove serde_yaml"));
}

#[test]
fn fail_closed_mutations_reject_cutover_unknown_missing_surface_bound_and_policy_drift() {
    let inventory = artifact();

    let mut cutover = inventory.clone();
    cutover["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&cutover).is_err());

    let mut unknown = inventory.clone();
    unknown["grammar_constructs"][0]["evidence_state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());

    let mut missing_gap = inventory.clone();
    missing_gap["known_gaps"]
        .as_array_mut()
        .expect("known_gaps array")
        .pop();
    assert!(validate_inventory(&missing_gap).is_err());

    let mut schema_drift = inventory.clone();
    schema_drift["typed_schema"]["root_field_count"] = Value::from(15);
    assert!(validate_inventory(&schema_drift).is_err());

    let mut missing_consumer = inventory.clone();
    missing_consumer["a3_acceptance_satisfiability_audit"]["consumer_matrix"]
        .as_array_mut()
        .expect("consumer matrix")
        .pop();
    assert!(validate_inventory(&missing_consumer).is_err());

    let mut false_application_bound = inventory.clone();
    let limits = false_application_bound["a3_acceptance_satisfiability_audit"]
        ["application_limit_matrix"]
        .as_array_mut()
        .expect("application limit matrix");
    let bytes = limits
        .iter_mut()
        .find(|row| {
            row.get("limit_id").and_then(Value::as_str)
                == Some("SCN-A3-LIMIT-DOCUMENT-BYTES")
        })
        .expect("document byte limit row");
    bytes["current_application_policy"] = Value::String("FINITE".to_owned());
    assert!(validate_inventory(&false_application_bound).is_err());

    let mut tightened_unknowns = inventory.clone();
    tightened_unknowns["a3_acceptance_satisfiability_audit"]["unknown_field_contract"]
        ["root_typed_struct"] = Value::String("REJECT".to_owned());
    assert!(validate_inventory(&tightened_unknowns).is_err());

    let mut invented_owner_policy = inventory.clone();
    invented_owner_policy["a3_acceptance_satisfiability_audit"]["satisfiability_decision"]
        ["owner_policy_approved"] = Value::Bool(true);
    assert!(validate_inventory(&invented_owner_policy).is_err());

    let mut false_satisfiability = inventory.clone();
    false_satisfiability["a3_acceptance_satisfiability_audit"]["satisfiability_decision"]
        ["satisfiability"] = Value::String("SATISFIABLE".to_owned());
    false_satisfiability["a3_acceptance_satisfiability_audit"]["satisfiability_decision"]
        ["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&false_satisfiability).is_err());

    let mut unrouted = inventory;
    unrouted["known_gaps"][0]["owner_bead"] = Value::String(String::new());
    assert!(validate_inventory(&unrouted).is_err());
}
