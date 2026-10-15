#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/typed_format_final_signoff_v1.json";
const REGISTRY_PATH: &str = "artifacts/typed_format_registry_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const MANIFEST_PATH: &str = "Cargo.toml";
const LOCK_PATH: &str = "Cargo.lock";
const SOURCE_PATH: &str = "src/types/typed_symbol.rs";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const DOC_PATH: &str = "docs/typed_format_final_signoff.md";
const REGISTRY_DOC_PATH: &str = "docs/typed_format_registry.md";
const BEAD_ID: &str = "asupersync-5z2scg.3.5";
const PHASE5_SIGNOFF_ID: &str = "asupersync-5z2scg.10";
const SCENARIO_ID: &str = "dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|entry| !entry.trim().is_empty())
        .unwrap_or_else(|| panic!("{key} must be a non-empty string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|item| !item.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be non-empty strings"))
                .to_owned()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn tracker_issues() -> BTreeMap<String, Value> {
    let mut issues = BTreeMap::new();
    for (line_number, line) in read_repo_file(TRACKER_PATH).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let issue: Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!("parse {TRACKER_PATH} line {}: {error}", line_number + 1)
        });
        let id = text(&issue, "id").to_owned();
        assert!(
            issues.insert(id.clone(), issue).is_none(),
            "duplicate tracker issue {id}"
        );
    }
    issues
}

fn blocking_dependency_ids(issue: &Value) -> BTreeSet<String> {
    array(issue, "dependencies")
        .iter()
        .filter(|dependency| dependency["type"] == "blocks")
        .map(|dependency| text(dependency, "depends_on_id").to_owned())
        .collect()
}

fn find_by<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn package(lock: &str, name: &str) -> BTreeMap<String, String> {
    lock.split("[[package]]")
        .find_map(|section| {
            let fields = section
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .map(|(key, value)| {
                    (
                        key.trim().to_owned(),
                        value.trim().trim_matches('"').to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            (fields.get("name").map(String::as_str) == Some(name)).then_some(fields)
        })
        .unwrap_or_else(|| panic!("missing Cargo.lock package {name}"))
}

fn persisted_state_counts(registry: &Value) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for surface in array(registry, "persisted_surfaces") {
        *counts.entry(text(surface, "state").to_owned()).or_default() += 1;
    }
    counts
}

fn validate_terminal_packet(packet: &Value, registry: &Value) -> Result<(), String> {
    if packet["artifact_id"] != "typed-format-final-signoff-v1" || packet["bead_id"] != BEAD_ID {
        return Err("terminal packet identity drift".to_owned());
    }

    let verdict = &packet["terminal_verdict"];
    if verdict["outcome"] != "KEEP_INCUMBENTS_WITH_SCOPED_PERSISTED_PARITY"
        || verdict["phase5_terminal_receipt"] != true
        || verdict["dependency_exit_allowed"] != false
        || verdict["format_variant_removal_allowed"] != false
        || verdict["public_surface_narrowing_allowed"] != false
        || verdict["production_manifest_changed"] != false
    {
        return Err("terminal verdict is not fail-closed KEEP".to_owned());
    }

    let expected_children = BTreeSet::from([
        "asupersync-5z2scg.3.1".to_owned(),
        "asupersync-5z2scg.3.2".to_owned(),
        "asupersync-5z2scg.3.3".to_owned(),
        "asupersync-5z2scg.3.4".to_owned(),
        "asupersync-5z2scg.3.6".to_owned(),
        "asupersync-5z2scg.3.7".to_owned(),
    ]);
    let child_ids = array(packet, "child_receipts")
        .iter()
        .map(|receipt| text(receipt, "bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    if child_ids != expected_children {
        return Err("terminal packet child closure drift".to_owned());
    }

    let decisions = array(packet, "per_codec_decisions");
    if decisions.len() != 2 {
        return Err("terminal packet must decide exactly two generic binary codecs".to_owned());
    }
    for (format, package_name) in [("MessagePack", "rmp-serde"), ("Bincode", "bincode-next")] {
        let decision = decisions
            .iter()
            .find(|row| row["format"] == format)
            .ok_or_else(|| format!("missing {format} decision"))?;
        if decision["incumbent_package"] != package_name
            || decision["disposition"] != "KEEP"
            || decision["dependency_exit_allowed"] != false
            || decision["public_variant_required"] != true
            || array(decision, "replacement_blockers").is_empty()
        {
            return Err(format!("{format} decision is not a complete KEEP receipt"));
        }
    }

    let reconciliation = &packet["registry_reconciliation"];
    for (key, registry_key) in [
        ("format_profile_count", "format_profiles"),
        ("persisted_surface_count", "persisted_surfaces"),
        ("downstream_consumer_count", "downstream_consumers"),
        ("corpus_count", "corpora"),
        (
            "generic_dependency_decision_count",
            "generic_dependency_decisions",
        ),
        ("source_pin_count", "source_pins"),
        ("production_backend_file_count", "production_backend_files"),
    ] {
        let expected = array(registry, registry_key).len() as u64;
        if reconciliation[key].as_u64() != Some(expected) {
            return Err(format!("{key} does not match live registry"));
        }
    }
    if reconciliation["unknown_blocker_count"].as_u64()
        != Some(array(registry, "unknown_blockers").len() as u64)
        || reconciliation["unknown_blocker_count"] != 0
    {
        return Err("unknown blockers are not reconciled".to_owned());
    }

    for surface in array(registry, "persisted_surfaces") {
        if surface
            .get("state")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || surface
                .get("no_claim_boundary")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err("persisted surface lacks state or no-claim boundary".to_owned());
        }
    }

    let fuzz = &packet["fuzz_and_gap_disposition"];
    if fuzz["replacement_grade_complete"] != false
        || fuzz["disposition"] != "EXPLICIT_KEEP_BLOCKER"
        || array(fuzz, "bounded_fuzz_assets").is_empty()
    {
        return Err("fuzz gaps were silently promoted to replacement proof".to_owned());
    }

    if packet["canonical_scenario"]["scenario_id"] != SCENARIO_ID
        || packet["canonical_scenario"]["expected_outcome"] != "PASSED"
    {
        return Err("canonical terminal scenario drift".to_owned());
    }

    if array(packet, "no_claim_boundaries").len() < 5 {
        return Err("terminal no-claim boundary is incomplete".to_owned());
    }
    Ok(())
}

#[test]
fn terminal_identity_child_closure_and_phase5_edge_are_exact() {
    let packet = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    validate_terminal_packet(&packet, &registry).expect("valid terminal packet");

    assert_eq!(packet["schema_version"], 1);
    assert_eq!(packet["epic_id"], "asupersync-5z2scg.3");
    assert_eq!(packet["program_id"], "asupersync-ir2uf0");
    assert_eq!(
        string_set(&packet, "capability_ids"),
        BTreeSet::from([
            "CAP-PERSISTED-TRACE-SNAPSHOT".to_owned(),
            "CAP-SERDE-GENERIC".to_owned(),
        ])
    );

    let issues = tracker_issues();
    for receipt in array(&packet, "child_receipts") {
        let bead_id = text(receipt, "bead_id");
        assert_eq!(text(receipt, "required_status"), "closed");
        assert_eq!(
            issues
                .get(bead_id)
                .unwrap_or_else(|| panic!("missing child {bead_id}"))["status"],
            "closed",
            "{bead_id} must remain closed"
        );
        text(receipt, "role");
        assert!(!array(receipt, "content_commits").is_empty());
    }

    let own = issues.get(BEAD_ID).expect("A5 tracker row");
    assert_eq!(
        blocking_dependency_ids(own),
        BTreeSet::from([
            "asupersync-5z2scg.3.4".to_owned(),
            "asupersync-5z2scg.3.7".to_owned(),
        ])
    );
    assert!(
        blocking_dependency_ids(
            issues
                .get(PHASE5_SIGNOFF_ID)
                .expect("Phase 5 aggregate tracker row")
        )
        .contains(BEAD_ID),
        "typed-format A5 must remain an explicit Phase 5 blocker"
    );
}

#[test]
fn every_terminal_source_contract_is_content_pinned() {
    let packet = json(ARTIFACT_PATH);
    let contracts = array(&packet, "source_contracts");
    assert_eq!(contracts.len(), 14);

    let mut paths = BTreeSet::new();
    for contract in contracts {
        let path = text(contract, "path");
        assert!(paths.insert(path), "duplicate source contract {path}");
        let expected = text(contract, "sha256");
        assert_eq!(expected.len(), 64, "{path} must use SHA-256");
        assert_eq!(
            sha256_hex(read_repo_file(path).as_bytes()),
            expected,
            "{path} drifted after A5 aggregation"
        );
        text(contract, "role");
    }
}

#[test]
fn registry_rows_and_evidence_states_reconcile_without_promotion() {
    let packet = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let reconciliation = &packet["registry_reconciliation"];

    assert_eq!(array(&registry, "format_profiles").len(), 4);
    assert_eq!(array(&registry, "persisted_surfaces").len(), 13);
    assert_eq!(array(&registry, "downstream_consumers").len(), 6);
    assert_eq!(array(&registry, "corpora").len(), 5);
    assert_eq!(array(&registry, "generic_dependency_decisions").len(), 2);
    assert_eq!(array(&registry, "source_pins").len(), 48);
    assert_eq!(array(&registry, "production_backend_files").len(), 3);
    assert!(array(&registry, "unknown_blockers").is_empty());

    let counts = persisted_state_counts(&registry);
    assert_eq!(counts.get("HISTORICAL_CORPUS_VERIFIED"), Some(&7));
    assert_eq!(counts.get("CURRENT_CORPUS_ONLY"), Some(&5));
    assert_eq!(counts.get("BASELINE_EXISTING"), Some(&1));
    assert_eq!(reconciliation["historical_surface_count"], 7);
    assert_eq!(reconciliation["current_only_surface_count"], 5);
    assert_eq!(reconciliation["baseline_surface_count"], 1);

    for surface in array(&registry, "persisted_surfaces") {
        assert!(
            matches!(
                text(surface, "state"),
                "HISTORICAL_CORPUS_VERIFIED" | "CURRENT_CORPUS_ONLY" | "BASELINE_EXISTING"
            ),
            "{} has an unexpected state",
            text(surface, "surface_id")
        );
        text(surface, "no_claim_boundary");
    }

    let registry_decisions = array(&registry, "generic_dependency_decisions");
    assert_eq!(
        registry_decisions
            .iter()
            .map(|row| text(row, "format").to_owned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["Bincode".to_owned(), "MessagePack".to_owned()])
    );
    for decision in registry_decisions {
        assert_eq!(text(decision, "disposition"), "KEEP");
        assert_eq!(decision["evidence_state"], "CURRENT_CORPUS_ONLY");
        text(decision, "replacement_gate");
        text(decision, "no_claim_boundary");
    }
}

#[test]
fn live_manifest_lock_and_public_surface_preserve_both_incumbents() {
    let packet = json(ARTIFACT_PATH);
    let manifest = read_repo_file(MANIFEST_PATH);
    let lock = read_repo_file(LOCK_PATH);
    let source = read_repo_file(SOURCE_PATH);

    for decision in array(&packet, "per_codec_decisions") {
        let requirement = text(decision, "manifest_requirement");
        assert!(
            manifest.contains(requirement),
            "manifest lost checked requirement {requirement}"
        );
        let locked = package(&lock, text(decision, "incumbent_package"));
        assert_eq!(
            locked.get("version").map(String::as_str),
            Some(text(decision, "locked_version"))
        );
        assert_eq!(
            locked.get("checksum").map(String::as_str),
            Some(text(decision, "locked_checksum"))
        );
        assert_eq!(decision["disposition"], "KEEP");
        assert_eq!(decision["dependency_exit_allowed"], false);
    }

    for marker in [
        "pub enum SerializationFormat",
        "MessagePack,",
        "Bincode,",
        "Json,",
        "Custom,",
        "Self::MessagePack => 1,",
        "Self::Bincode => 2,",
        "Self::Json => 3,",
        "Self::Custom => 255,",
        "pub struct SerdeCodec;",
        "impl<T: Serialize> Serializer<T> for SerdeCodec",
        "impl<T: DeserializeOwned> Deserializer<T> for SerdeCodec",
        "bincode::config::legacy()",
    ] {
        assert!(
            source.contains(marker),
            "public codec marker drifted: {marker}"
        );
    }
}

#[test]
fn capability_keep_fuzz_gap_and_rollback_boundaries_are_explicit() {
    let packet = json(ARTIFACT_PATH);
    let decisions = array(&packet, "capability_decisions");
    assert_eq!(decisions.len(), 2);

    let generic = find_by(decisions, "capability_id", "CAP-SERDE-GENERIC");
    assert_eq!(generic["outcome"], "KEEP_INCUMBENT");
    assert_eq!(generic["same_or_better_for_exit"], false);
    assert_eq!(
        string_set(generic, "preserved_surfaces"),
        BTreeSet::from([
            "SerializationFormat::MessagePack".to_owned(),
            "SerializationFormat::Bincode".to_owned(),
            "SerializationFormat::Json".to_owned(),
            "SerializationFormat::Custom".to_owned(),
            "SerdeCodec".to_owned(),
            "downstream Serializer<T> and Deserializer<T> injection".to_owned(),
        ])
    );
    text(generic, "no_claim_boundary");

    let persisted = find_by(decisions, "capability_id", "CAP-PERSISTED-TRACE-SNAPSHOT");
    assert_eq!(
        persisted["outcome"],
        "PASS_SCOPED_ADDITIVE_OWNERSHIP_KEEP_BACKENDS"
    );
    assert_eq!(persisted["same_or_better_for_exit"], false);
    text(persisted, "no_claim_boundary");

    let fuzz = &packet["fuzz_and_gap_disposition"];
    assert_eq!(fuzz["replacement_grade_complete"], false);
    assert_eq!(fuzz["disposition"], "EXPLICIT_KEEP_BLOCKER");
    for path in strings(fuzz, "bounded_fuzz_assets") {
        assert!(
            repo_path(&path).is_file(),
            "missing bounded fuzz asset {path}"
        );
    }
    assert_eq!(
        string_set(fuzz, "current_corpus_ids"),
        BTreeSet::from([
            "CORPUS-DISTRIBUTED-SNAPSHOT-SEEDS".to_owned(),
            "CORPUS-TYPED-SYMBOL-FUZZ".to_owned(),
        ])
    );

    let rollback = &packet["rollback_contract"];
    assert_eq!(rollback["manifest_rollback_required"], false);
    for key in ["reason", "artifact_rule", "operator_action"] {
        text(rollback, key);
    }
    assert_eq!(array(&packet, "no_claim_boundaries").len(), 5);
}

#[test]
fn canonical_runner_and_documentation_are_discoverable() {
    let packet = json(ARTIFACT_PATH);
    let runner = read_repo_file(RUNNER_PATH);
    let doc = read_repo_file(DOC_PATH);
    let registry_doc = read_repo_file(REGISTRY_DOC_PATH);

    assert_eq!(packet["canonical_scenario"]["scenario_id"], SCENARIO_ID);
    for marker in [
        SCENARIO_ID,
        "tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml",
        "tests/fixtures/typed-format-cross-version-consumer/Cargo.toml",
        "--test typed_format_registry_contract",
        "--test runtime_snapshot_codec_e2e",
        "--test replay_e2e_suite",
        "--test typed_format_cross_version_e2e",
        "--test typed_format_final_signoff_contract",
    ] {
        assert!(runner.contains(marker), "runner lacks A5 marker {marker}");
    }

    for marker in [
        "KEEP_INCUMBENTS_WITH_SCOPED_PERSISTED_PARITY",
        "`rmp-serde 1.3.1`",
        "`bincode-next 3.1.1`",
        "EXPLICIT_KEEP_BLOCKER",
        SCENARIO_ID,
        "No-claim boundary",
    ] {
        assert!(doc.contains(marker), "terminal doc lacks marker {marker}");
    }
    for marker in [
        "## A5 terminal decision",
        "typed_format_final_signoff.md",
        "KEEP_INCUMBENTS_WITH_SCOPED_PERSISTED_PARITY",
    ] {
        assert!(
            registry_doc.contains(marker),
            "registry doc lacks A5 marker {marker}"
        );
    }
}

#[test]
fn malformed_terminal_packets_fail_closed() {
    let packet = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    validate_terminal_packet(&packet, &registry).expect("positive packet");

    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "dependency exit",
            Box::new(|value| value["terminal_verdict"]["dependency_exit_allowed"] = true.into()),
        ),
        (
            "replace MessagePack",
            Box::new(|value| value["per_codec_decisions"][0]["disposition"] = "REPLACE".into()),
        ),
        (
            "drop child",
            Box::new(|value| {
                value["child_receipts"]
                    .as_array_mut()
                    .expect("child array")
                    .pop();
            }),
        ),
        (
            "promote fuzz",
            Box::new(|value| {
                value["fuzz_and_gap_disposition"]["replacement_grade_complete"] = true.into();
            }),
        ),
        (
            "remove no-claim boundaries",
            Box::new(|value| value["no_claim_boundaries"] = Value::Array(Vec::new())),
        ),
    ];

    for (name, mutation) in mutations {
        let mut invalid = packet.clone();
        mutation(&mut invalid);
        assert!(
            validate_terminal_packet(&invalid, &registry).is_err(),
            "{name} mutation must fail closed"
        );
    }

    let mut missing_boundary_registry = registry;
    missing_boundary_registry["persisted_surfaces"][0]["no_claim_boundary"] = "".into();
    assert!(
        validate_terminal_packet(&packet, &missing_boundary_registry).is_err(),
        "missing registry no-claim boundary must fail closed"
    );
}
