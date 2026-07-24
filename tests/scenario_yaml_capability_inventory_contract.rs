//! Fail-closed YAML scenario capability inventory contract.
//!
//! Bead: asupersync-5z2scg.5.1
//! Scenario: scenario-yaml-capability-inventory-contract
//! Fixture: artifacts/scenario_yaml_capability_inventory_v1.json
//!
//! This proves source-pinned loader, typed-schema, observed grammar, checked-in
//! corpus, workflow, diagnostic, resource, execution-consumption, child-owner,
//! and gap inventories. It does not prove arbitrary YAML, additive JSON,
//! parser replacement, runtime semantics for validation-only fields, or
//! permission to remove the incumbent `serde_yaml` dependency.

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
const BEAD_ID: &str = "asupersync-5z2scg.5.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-SCENARIO-YAML-JSON";
const BASELINE_REVISION: &str = "295136459f9e3e38e7373394e713866ec0693a8d";
const AUTHORITY_REVISION: &str = "673a905631c5580cdc8037315569b72bd636ecca";
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
    Ok(())
}

#[test]
fn inventory_is_complete_source_pinned_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
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
        BASELINE_REVISION,
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
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
fn fail_closed_mutations_reject_cutover_unknown_missing_gap_and_schema_drift() {
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

    let mut unrouted = inventory;
    unrouted["known_gaps"][0]["owner_bead"] = Value::String(String::new());
    assert!(validate_inventory(&unrouted).is_err());
}
