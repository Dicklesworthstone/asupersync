//! Fail-closed OTLP ecosystem capability inventory contract.
//!
//! Bead: asupersync-5z2scg.2.1
//! Scenario: otlp-capability-inventory-contract
//! Fixture: artifacts/otlp_capability_inventory_v1.json
//!
//! This proves source-pinned inventory completeness, authority joins, explicit
//! child routing, named reference versions, executable baseline receipts, and
//! rejection of unknown or cutover-authorizing mutations. It does not prove
//! live collector interoperability, runtime parity, performance, or permission
//! to remove an incumbent dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/otlp_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/otlp_capability_inventory.md";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const ADR_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BEAD_ID: &str = "asupersync-5z2scg.2.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-OTLP-ECOSYSTEM";
const ADR_ID: &str = "DEP-ADR-003";
const BASELINE_REVISION: &str = "da06fe447d5e1d0b03a0be0c2b76d1db44a3c8d4";
const AUTHORITY_REVISION: &str = "673a905631c5580cdc8037315569b72bd636ecca";
const DOC_BEGIN: &str = "<!-- BEGIN OTLP CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END OTLP CAPABILITY INVENTORY -->";

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

fn string_set(values: &Value, key: &str) -> BTreeSet<String> {
    array(values, key)
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn validate_evidence_state(
    row: &Value,
    allowed: &BTreeSet<String>,
    context: &str,
) -> Result<(), String> {
    let state = row
        .get("evidence_state")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} must name evidence_state"))?;
    if state == "UNKNOWN" || !allowed.contains(state) {
        return Err(format!(
            "{context} has forbidden or unrecognized evidence_state {state}"
        ));
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "otlp-capability-inventory-v1"),
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

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", ADR_ID),
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
    {
        return Err("policy must require and report zero unknown rows".to_owned());
    }
    let allowed_evidence: BTreeSet<String> = policy
        .get("allowed_evidence_states")
        .and_then(Value::as_array)
        .ok_or_else(|| "policy.allowed_evidence_states must be an array".to_owned())?
        .iter()
        .map(|state| {
            state
                .as_str()
                .ok_or_else(|| "allowed evidence states must be strings".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    if allowed_evidence.contains("UNKNOWN") {
        return Err("UNKNOWN must not be an allowed evidence state".to_owned());
    }

    let expected_profiles: BTreeSet<String> = [
        "OTLP-PROFILE-DEFAULT",
        "OTLP-PROFILE-METRICS",
        "OTLP-PROFILE-METRICS-COMPRESSION",
        "OTLP-PROFILE-METRICS-TRACING",
        "OTLP-PROFILE-FUZZ",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let profiles = array(inventory, "feature_profiles");
    if row_ids(profiles, "profile_id") != expected_profiles {
        return Err("feature profiles must cover the exact supported matrix".to_owned());
    }
    for row in profiles {
        validate_evidence_state(row, &allowed_evidence, text(row, "profile_id"))?;
        if text(row, "inventory_state") == "UNKNOWN" {
            return Err("profile inventory state must never be UNKNOWN".to_owned());
        }
    }

    let groups = array(inventory, "adr_public_surface_groups");
    if groups.len() != 6 {
        return Err("ADR public surface must contain six groups".to_owned());
    }
    if groups
        .iter()
        .map(|group| array(group, "symbols").len())
        .sum::<usize>()
        != 72
    {
        return Err("ADR public surface must contain 72 symbols".to_owned());
    }

    let module_rows = array(inventory, "module_public_items");
    if module_rows.len() != 5 {
        return Err("module public inventory must contain five source modules".to_owned());
    }
    let mut public_item_count = 0usize;
    for row in module_rows {
        let items = string_set(row, "items");
        if items.len() != array(row, "items").len() {
            return Err(format!(
                "{} has duplicate public items",
                text(row, "source_path")
            ));
        }
        public_item_count += items.len();
    }
    if public_item_count != 88 {
        return Err("module public inventory must contain 88 unique per-module items".to_owned());
    }

    let expected_signals: BTreeSet<String> = ["external_meter_bridge", "logs", "metrics", "traces"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let signals = array(inventory, "signals_and_integrations");
    if row_ids(signals, "signal_id") != expected_signals {
        return Err("all three signals and the external Meter bridge are required".to_owned());
    }
    for row in signals {
        if text(row, "inventory_state") != "FROZEN" {
            return Err(format!("{} must remain frozen", text(row, "signal_id")));
        }
    }

    if array(inventory, "configuration_contracts").len() != 13 {
        return Err("all thirteen configuration contracts are required".to_owned());
    }

    let expected_children: BTreeSet<String> = (1..=11)
        .map(|suffix| format!("asupersync-5z2scg.2.{suffix}"))
        .collect();
    let child_rows = array(inventory, "child_capability_rows");
    if row_ids(child_rows, "owner_bead") != expected_children {
        return Err("every A1-A11 child must own exactly one capability row".to_owned());
    }
    for row in child_rows {
        validate_evidence_state(row, &allowed_evidence, text(row, "owner_bead"))?;
        if text(row, "inventory_state") != "FROZEN" {
            return Err(format!("{} must remain frozen", text(row, "owner_bead")));
        }
        if array(row, "evidence").is_empty() || text(row, "no_claim").trim().is_empty() {
            return Err(format!(
                "{} must name evidence and a no-claim boundary",
                text(row, "owner_bead")
            ));
        }
    }

    let references = array(inventory, "reference_versions");
    for row in references {
        validate_evidence_state(row, &allowed_evidence, text(row, "reference_id"))?;
    }
    let collectors: BTreeSet<String> = references
        .iter()
        .filter(|row| row.get("kind").and_then(Value::as_str) == Some("real-collector-version"))
        .map(|row| text(row, "version").to_owned())
        .collect();
    let expected_collectors = ["0.88.0", "0.90.0"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if collectors != expected_collectors {
        return Err("real collector targets must name exactly 0.88.0 and 0.90.0".to_owned());
    }
    for row in references
        .iter()
        .filter(|row| row.get("kind").and_then(Value::as_str) == Some("real-collector-version"))
    {
        if text(row, "evidence_state") != "BLOCKED_INERT_FIXTURE" {
            return Err("collector version names must not be presented as executed".to_owned());
        }
    }

    let journeys = array(inventory, "user_journeys");
    if journeys.len() != 6 || row_ids(journeys, "journey_id").len() != 6 {
        return Err("exactly six uniquely named user journeys are required".to_owned());
    }
    for row in journeys {
        validate_evidence_state(row, &allowed_evidence, text(row, "journey_id"))?;
        if array(row, "owner_beads").is_empty() || text(row, "required_completion").is_empty() {
            return Err(format!(
                "{} must have owners and a completion contract",
                text(row, "journey_id")
            ));
        }
    }

    let expected_gaps: BTreeSet<String> = (1..=7)
        .map(|suffix| format!("OTLP-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "known_gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("known gaps must cover OTLP-GAP-01 through OTLP-GAP-07".to_owned());
    }
    for row in gaps {
        validate_evidence_state(row, &allowed_evidence, text(row, "gap_id"))?;
        for key in ["upstream_owner", "program_child_owner"] {
            if text(row, key).is_empty() {
                return Err(format!("{} must name {key}", text(row, "gap_id")));
            }
        }
    }

    let baselines = array(inventory, "baseline_runs");
    if row_ids(baselines, "baseline_id").len() != baselines.len() {
        return Err("baseline ids must be unique".to_owned());
    }
    for row in baselines {
        validate_evidence_state(row, &allowed_evidence, text(row, "baseline_id"))?;
        if text(row, "command").trim().is_empty() || text(row, "result").trim().is_empty() {
            return Err(format!(
                "{} must record command and result",
                text(row, "baseline_id")
            ));
        }
        match text(row, "evidence_state") {
            "EXECUTED" if row.get("exit_code").and_then(Value::as_i64) != Some(0) => {
                return Err(format!(
                    "{} executed without exit code zero",
                    text(row, "baseline_id")
                ));
            }
            "BLOCKED_RCH_POLICY"
                if row.get("exit_code").and_then(Value::as_i64) != Some(1)
                    || !text(row, "result").contains("[RCH-E301]") =>
            {
                return Err(format!(
                    "{} must retain its RCH-E301 blocker",
                    text(row, "baseline_id")
                ));
            }
            "PLANNED" if !row.get("exit_code").is_some_and(Value::is_null) => {
                return Err(format!(
                    "{} planned evidence must have a null exit code",
                    text(row, "baseline_id")
                ));
            }
            _ => {}
        }
    }
    if baselines
        .iter()
        .filter(|row| row.get("evidence_state").and_then(Value::as_str) == Some("EXECUTED"))
        .count()
        != 4
        || baselines
            .iter()
            .filter(|row| {
                row.get("evidence_state").and_then(Value::as_str) == Some("BLOCKED_RCH_POLICY")
            })
            .count()
            != 3
    {
        return Err(
            "baseline ledger must retain four executed and three RCH-blocked rows".to_owned(),
        );
    }

    let cutover = object(inventory, "final_cutover_mapping");
    if cutover
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
        || cutover.get("current_decision").and_then(Value::as_str) != Some("KEEP")
    {
        return Err("final cutover must remain KEEP and forbid dependency exit".to_owned());
    }
    let mapped_children: BTreeSet<String> = cutover
        .get("required_child_rows")
        .and_then(Value::as_array)
        .ok_or_else(|| "final cutover must map required_child_rows".to_owned())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "required child ids must be strings".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    if mapped_children != expected_children {
        return Err("final cutover must consume all A1-A11 rows".to_owned());
    }

    let summary = object(inventory, "summary");
    for (key, actual) in [
        ("source_pin_count", array(inventory, "source_pins").len()),
        ("feature_profile_count", profiles.len()),
        ("adr_public_surface_group_count", groups.len()),
        ("adr_public_symbol_count", 72),
        ("module_public_item_count", public_item_count),
        ("signal_and_integration_count", signals.len()),
        (
            "configuration_contract_count",
            array(inventory, "configuration_contracts").len(),
        ),
        ("child_capability_row_count", child_rows.len()),
        ("reference_version_count", references.len()),
        ("real_collector_version_count", collectors.len()),
        ("user_journey_count", journeys.len()),
        ("known_gap_count", gaps.len()),
        ("executed_baseline_count", 4),
        ("blocked_rch_policy_count", 3),
        ("unknown_row_count", 0),
    ] {
        if summary.get(key).and_then(Value::as_u64) != Some(actual as u64) {
            return Err(format!("summary.{key} must equal {actual}"));
        }
    }

    if array(inventory, "no_claim_boundary").len() < 5 {
        return Err("inventory must retain at least five no-claim boundaries".to_owned());
    }
    Ok(())
}

fn normalized_adr_groups(registry: &Value) -> Vec<(String, Option<String>, Vec<String>)> {
    let adr = array(registry, "adrs")
        .iter()
        .find(|row| row.get("adr_id").and_then(Value::as_str) == Some(ADR_ID))
        .expect("DEP-ADR-003 must exist");
    array(adr, "preserved_public_symbols")
        .iter()
        .map(|group| {
            (
                text(group, "module_path").to_owned(),
                group
                    .get("feature_gate")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                array(group, "symbols")
                    .iter()
                    .map(|symbol| symbol.as_str().expect("symbol").to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn normalized_inventory_groups(inventory: &Value) -> Vec<(String, Option<String>, Vec<String>)> {
    array(inventory, "adr_public_surface_groups")
        .iter()
        .map(|group| {
            (
                text(group, "module_path").to_owned(),
                group
                    .get("feature_gate")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                array(group, "symbols")
                    .iter()
                    .map(|symbol| symbol.as_str().expect("symbol").to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn declaration_name(line: &str) -> Option<String> {
    if !line.starts_with("pub ") {
        return None;
    }
    let words: Vec<&str> = line.split_whitespace().collect();
    let raw = match words.as_slice() {
        [
            "pub",
            "struct" | "enum" | "trait" | "type" | "mod",
            name,
            ..,
        ] => *name,
        ["pub", "fn", name, ..] => *name,
        ["pub", "const", "fn", name, ..] => *name,
        ["pub", "const", name, ..] => *name,
        _ => return None,
    };
    let end = raw.find(['<', '(', ':', ';', '{']).unwrap_or(raw.len());
    Some(raw[..end].to_owned())
}

fn live_top_level_public_items(path: &str) -> BTreeSet<String> {
    read_repo_file(path)
        .lines()
        .filter_map(declaration_name)
        .collect()
}

#[test]
fn inventory_schema_is_complete_and_fail_closed() {
    validate_inventory(&artifact()).expect("canonical OTLP inventory must validate");
}

#[test]
fn every_source_pin_matches_live_bytes_and_line_count() {
    let inventory = artifact();
    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let actual_hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            actual_hash,
            text(pin, "sha256"),
            "{path} source pin drifted"
        );
        let source = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("{path} must remain UTF-8: {error}"));
        assert_eq!(
            source.lines().count() as u64,
            pin.get("line_count").and_then(Value::as_u64).unwrap(),
            "{path} line count drifted"
        );
    }
}

#[test]
fn public_surface_matches_adr_and_live_modules() {
    let inventory = artifact();
    let adr_registry = parse_repo_json(ADR_REGISTRY_PATH);
    assert_eq!(
        normalized_inventory_groups(&inventory),
        normalized_adr_groups(&adr_registry),
        "the six ADR-authoritative surface groups must remain exact"
    );

    for row in array(&inventory, "module_public_items") {
        let path = text(row, "source_path");
        let expected = string_set(row, "items");
        assert_eq!(
            live_top_level_public_items(path),
            expected,
            "{path} top-level public item inventory drifted"
        );
    }
}

#[test]
fn authority_features_signals_configuration_and_gaps_join_live_registries() {
    let inventory = artifact();
    let adr_registry = parse_repo_json(ADR_REGISTRY_PATH);
    let capability_registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let adr = array(&adr_registry, "adrs")
        .iter()
        .find(|row| row.get("adr_id").and_then(Value::as_str) == Some(ADR_ID))
        .expect("DEP-ADR-003 must exist");

    assert_eq!(text(adr, "state"), "RESOLVED");
    assert_eq!(text(adr, "decision"), "ADDITIVE_COEXISTENCE");
    assert_eq!(
        adr.get("cutover")
            .and_then(Value::as_object)
            .and_then(|cutover| cutover.get("dependency_exit_allowed"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        array(adr, "capability_ids")
            .iter()
            .any(|id| id.as_str() == Some(CAPABILITY_ID))
    );

    let manifest = read_repo_file("Cargo.toml");
    let adr_features: BTreeSet<String> = array(adr, "preserved_feature_flags")
        .iter()
        .map(|row| {
            let definition = text(row, "cargo_definition");
            assert!(
                manifest.contains(definition),
                "Cargo.toml must retain exact feature definition {definition}"
            );
            text(row, "name").to_owned()
        })
        .collect();
    assert_eq!(
        adr_features,
        ["compression", "fuzz", "metrics", "tracing-integration"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let adr_signals: BTreeMap<String, String> = array(adr, "preserved_surfaces")
        .iter()
        .map(|row| {
            (
                text(row, "surface").to_owned(),
                text(row, "state").to_owned(),
            )
        })
        .collect();
    let inventory_signals: BTreeMap<String, String> = array(&inventory, "signals_and_integrations")
        .iter()
        .map(|row| {
            (
                text(row, "signal_id").to_owned(),
                text(row, "authority_state").to_owned(),
            )
        })
        .collect();
    assert_eq!(inventory_signals, adr_signals);

    assert_eq!(
        row_ids(array(&inventory, "configuration_contracts"), "name"),
        row_ids(array(adr, "preserved_config_semantics"), "name")
    );
    assert_eq!(
        row_ids(array(&inventory, "known_gaps"), "gap_id"),
        row_ids(array(adr, "known_gaps"), "gap_id")
    );

    let capability = array(&capability_registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("CAP-OTLP-ECOSYSTEM must exist");
    assert_eq!(text(capability, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(capability, "cutover_state"), "KEEP_INCUMBENT");
    assert_eq!(
        capability
            .get("baseline")
            .and_then(Value::as_object)
            .and_then(|baseline| baseline.get("owner_bead"))
            .and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert!(
        array(&capability_registry, "bead_mapping_rules")
            .iter()
            .any(|row| text(row, "bead_id") == "asupersync-5z2scg.2."
                && array(row, "capability_ids")
                    .iter()
                    .any(|id| id.as_str() == Some(CAPABILITY_ID)))
    );

    let api_surface_map = parse_repo_json(API_SURFACE_MAP_PATH);
    let prometheus_entry = array(&api_surface_map, "entry_points")
        .iter()
        .find(|row| row.get("use_case").and_then(Value::as_str) == Some("prometheus_metrics"))
        .expect("API surface map must retain the Prometheus metrics journey");
    assert_eq!(text(prometheus_entry, "symbol"), "observability");
    assert_eq!(
        prometheus_entry
            .get("example")
            .and_then(Value::as_object)
            .and_then(|example| example.get("path"))
            .and_then(Value::as_str),
        Some("examples/prometheus_metrics.rs")
    );
}

#[test]
fn baseline_receipts_versions_and_journeys_remain_truthful() {
    let inventory = artifact();
    let baselines: BTreeMap<_, _> = array(&inventory, "baseline_runs")
        .iter()
        .map(|row| (text(row, "baseline_id"), row))
        .collect();
    for id in [
        "OTLP-BASELINE-METRICS",
        "OTLP-BASELINE-TRACE",
        "OTLP-BASELINE-DOWNSTREAM",
        "OTLP-BASELINE-PROMETHEUS-EXAMPLE",
    ] {
        let row = baselines.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(text(row, "evidence_state"), "EXECUTED");
        assert_eq!(row.get("exit_code").and_then(Value::as_i64), Some(0));
        assert_eq!(text(row, "revision"), BASELINE_REVISION);
    }
    for id in [
        "OTLP-GRAPH-DEFAULT",
        "OTLP-GRAPH-METRICS",
        "OTLP-GRAPH-FUZZ",
    ] {
        let row = baselines.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(text(row, "evidence_state"), "BLOCKED_RCH_POLICY");
        assert!(text(row, "result").contains("[RCH-E301]"));
    }

    let references: BTreeMap<_, _> = array(&inventory, "reference_versions")
        .iter()
        .map(|row| (text(row, "reference_id"), text(row, "version")))
        .collect();
    for (id, version) in [
        ("OTEL-API-0.32.0", "0.32.0"),
        ("OTEL-SDK-0.32.1", "0.32.1"),
        ("OTEL-PROTO-0.32.0", "0.32.0"),
        ("PROST-0.14.4", "0.14.4"),
        ("OTEL-PROMETHEUS-0.17", "0.17"),
        ("OTLP-COLLECTOR-0.88.0", "0.88.0"),
        ("OTLP-COLLECTOR-0.90.0", "0.90.0"),
    ] {
        assert_eq!(references.get(id).copied(), Some(version));
    }
    assert_eq!(array(&inventory, "user_journeys").len(), 6);
}

#[test]
fn operator_document_preserves_discoverability_blockers_and_no_claims() {
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        BEAD_ID,
        CAPABILITY_ID,
        ADR_ID,
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "zero `UNKNOWN`",
        "OpenTelemetry Collector 0.88.0",
        "OpenTelemetry Collector 0.90.0",
        "[RCH-E301]",
        "scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario otlp_multisignal",
        "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay",
        "No-claim boundary",
    ] {
        assert!(doc.contains(marker), "operator document missing {marker}");
    }
    for gap in 1..=7 {
        let gap_id = format!("OTLP-GAP-{gap:02}");
        assert!(doc.contains(&gap_id), "operator document missing {gap_id}");
    }
}

#[test]
fn negative_mutations_fail_closed_for_every_acceptance_gate() {
    let canonical = artifact();

    let mut missing_child = canonical.clone();
    missing_child["child_capability_rows"]
        .as_array_mut()
        .expect("child rows")
        .pop();
    assert!(
        validate_inventory(&missing_child)
            .expect_err("missing child must fail")
            .contains("A1-A11")
    );

    let mut unknown = canonical.clone();
    unknown["child_capability_rows"][0]["evidence_state"] = Value::String("UNKNOWN".to_owned());
    assert!(
        validate_inventory(&unknown)
            .expect_err("UNKNOWN evidence must fail")
            .contains("forbidden")
    );

    let mut missing_collector = canonical.clone();
    missing_collector["reference_versions"]
        .as_array_mut()
        .expect("reference versions")
        .retain(|row| row.get("version").and_then(Value::as_str) != Some("0.90.0"));
    assert!(
        validate_inventory(&missing_collector)
            .expect_err("missing collector version must fail")
            .contains("collector targets")
    );

    let mut dependency_exit = canonical.clone();
    dependency_exit["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(
        validate_inventory(&dependency_exit)
            .expect_err("dependency exit authorization must fail")
            .contains("forbid dependency exit")
    );

    let mut greenwashed_graph = canonical.clone();
    let graph_row = greenwashed_graph["baseline_runs"]
        .as_array_mut()
        .expect("baseline runs")
        .iter_mut()
        .find(|row| row.get("baseline_id").and_then(Value::as_str) == Some("OTLP-GRAPH-METRICS"))
        .expect("metrics graph row");
    graph_row["evidence_state"] = Value::String("EXECUTED".to_owned());
    graph_row["exit_code"] = Value::from(0);
    assert!(
        validate_inventory(&greenwashed_graph)
            .expect_err("greenwashed graph blocker must fail")
            .contains("four executed and three RCH-blocked")
    );
}
