//! Contract tests for the validation frontier inventory.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/proof/validation_frontier_inventory.md";
const INVENTORY_PATH: &str = "artifacts/validation_frontier_inventory_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn load_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn inventory() -> Value {
    load_json(INVENTORY_PATH)
}

fn manifest() -> Value {
    load_json(MANIFEST_PATH)
}

fn doc() -> String {
    read_repo_file(DOC_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn enum_values<'a>(inventory: &'a Value, key: &str) -> BTreeSet<&'a str> {
    inventory["classification_enums"][key]
        .as_array()
        .unwrap_or_else(|| panic!("classification_enums.{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("classification_enums.{key} entries must be strings"))
        })
        .collect()
}

fn inventory_rows(inventory: &Value) -> &[Value] {
    inventory["lanes"]
        .as_array()
        .expect("inventory lanes must be an array")
}

fn rows_by_id(inventory: &Value) -> BTreeMap<String, &Value> {
    let mut rows = BTreeMap::new();
    for row in inventory_rows(inventory) {
        let lane_id = string_field(row, "lane_id").to_string();
        assert!(
            rows.insert(lane_id.clone(), row).is_none(),
            "duplicate inventory lane {lane_id}"
        );
    }
    rows
}

#[test]
fn inventory_schema_is_self_describing() {
    let inventory = inventory();
    assert_eq!(
        string_field(&inventory, "contract_version"),
        "validation-frontier-inventory-v1"
    );
    assert_eq!(
        string_field(&inventory, "bead_id"),
        "asupersync-validation-frontier-v2-b5cjsv.1"
    );

    let source_of_truth = inventory["source_of_truth"]
        .as_object()
        .expect("source_of_truth must be an object");
    for (key, expected) in [
        ("inventory", INVENTORY_PATH),
        (
            "contract_test",
            "tests/validation_frontier_inventory_contract.rs",
        ),
        ("documentation", DOC_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("agent_instructions", "AGENTS.md"),
        ("cargo_manifest", "Cargo.toml"),
    ] {
        assert_eq!(
            source_of_truth.get(key).and_then(Value::as_str),
            Some(expected),
            "source_of_truth.{key}"
        );
    }

    for key in [
        "lane_source",
        "target_kind",
        "cfg_test_enabled",
        "dev_dependency_edges",
        "conformance_expected",
        "normal_edge_tokio_expectation",
        "current_rch_behavior",
    ] {
        assert!(
            !enum_values(&inventory, key).is_empty(),
            "classification enum {key} must be nonempty"
        );
    }
}

#[test]
fn every_manifest_lane_has_inventory_row() {
    let inventory = inventory();
    let manifest = manifest();
    let rows = rows_by_id(&inventory);

    for lane in array(&manifest, "lanes") {
        let lane_id = string_field(lane, "lane_id");
        let row = rows
            .get(lane_id)
            .unwrap_or_else(|| panic!("manifest lane {lane_id} missing inventory row"));
        assert_eq!(
            string_field(row, "source"),
            "proof_lane_manifest_v1",
            "{lane_id} source"
        );
        assert_eq!(
            string_field(row, "command"),
            string_field(lane, "command"),
            "{lane_id} command must mirror manifest"
        );
        assert_eq!(
            string_field(row, "resource_envelope_class"),
            string_field(lane, "resource_envelope_class"),
            "{lane_id} resource envelope must mirror manifest"
        );
    }
}

#[test]
fn lane_rows_have_explicit_graph_expectations() {
    let inventory = inventory();
    let source_values = enum_values(&inventory, "lane_source");
    let target_values = enum_values(&inventory, "target_kind");
    let cfg_values = enum_values(&inventory, "cfg_test_enabled");
    let dev_values = enum_values(&inventory, "dev_dependency_edges");
    let conformance_values = enum_values(&inventory, "conformance_expected");
    let tokio_values = enum_values(&inventory, "normal_edge_tokio_expectation");
    let rch_values = enum_values(&inventory, "current_rch_behavior");

    for row in inventory_rows(&inventory) {
        let lane_id = string_field(row, "lane_id");
        assert!(
            string_field(row, "command").starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "{lane_id}: command must be remote-required"
        );
        assert!(
            !array(row, "features")
                .iter()
                .any(|feature| feature.as_str().is_none_or(str::is_empty)),
            "{lane_id}: features must be strings when present"
        );
        assert!(
            source_values.contains(string_field(row, "source")),
            "{lane_id}: invalid source"
        );
        assert!(
            target_values.contains(string_field(row, "target_kind")),
            "{lane_id}: invalid target_kind"
        );
        assert!(
            cfg_values.contains(string_field(row, "cfg_test_enabled")),
            "{lane_id}: invalid cfg_test_enabled"
        );
        assert!(
            dev_values.contains(string_field(row, "dev_dependency_edges")),
            "{lane_id}: invalid dev_dependency_edges"
        );
        assert!(
            conformance_values.contains(string_field(row, "conformance_expected")),
            "{lane_id}: invalid conformance_expected"
        );
        assert!(
            tokio_values.contains(string_field(row, "normal_edge_tokio_expectation")),
            "{lane_id}: invalid normal_edge_tokio_expectation"
        );
        assert!(
            rch_values.contains(string_field(row, "current_rch_behavior")),
            "{lane_id}: invalid current_rch_behavior"
        );
        string_field(row, "intended_guarantee");
        string_field(row, "package_or_surface");
        string_field(row, "resource_envelope_class");
    }
}

#[test]
fn focused_channel_regression_rows_capture_rch_stale_boundary() {
    let inventory = inventory();
    let rows = rows_by_id(&inventory);

    let green = rows
        .get("channel-mpsc-select-e2e-lib-check")
        .expect("green channel lib check row");
    assert_eq!(string_field(green, "source"), "focused_observed");
    assert_eq!(
        string_field(green, "current_rch_behavior"),
        "green_observed"
    );
    assert_eq!(string_field(green, "conformance_expected"), "not_expected");

    for lane_id in [
        "channel-mpsc-select-e2e-lib-tests-check",
        "channel-mpsc-select-e2e-filtered-run",
        "mpsc-recv-many-wake-cascade-exact-run",
    ] {
        let row = rows.get(lane_id).unwrap_or_else(|| panic!("{lane_id} row"));
        assert_eq!(string_field(row, "source"), "focused_observed");
        assert_eq!(
            string_field(row, "current_rch_behavior"),
            "stale_progress_observed",
            "{lane_id}: stale RCH behavior must be explicit"
        );
        assert_eq!(
            string_field(row, "conformance_expected"),
            "unknown_needs_vf2",
            "{lane_id}: conformance boundary must be explicit handoff"
        );
        assert!(
            !array(row, "observed_builds").is_empty(),
            "{lane_id}: observed builds must be captured"
        );
    }

    let blockers = array(&inventory, "known_regressions_or_blockers");
    let stale_blocker = blockers
        .iter()
        .find(|blocker| {
            blocker["blocker_id"].as_str() == Some("channel-mpsc-select-e2e-conformance-tail-stale")
        })
        .expect("channel conformance-tail stale blocker");
    let summary = string_field(stale_blocker, "summary");
    assert!(
        summary.contains("asupersync-conformance") && summary.contains("progress-stale"),
        "stale blocker summary must name conformance tail and RCH progress-stale"
    );
}

#[test]
fn documentation_cites_inventory_and_no_claim_boundaries() {
    let doc = doc();
    for required in [
        "<!-- validation-frontier-inventory-v1 -->",
        "artifacts/validation_frontier_inventory_v1.json",
        "tests/validation_frontier_inventory_contract.rs",
        "channel-mpsc-select-e2e",
        "unknown_needs_vf2",
        "compile_only",
        "RCH stale-progress evidence must not be cited as code failure evidence",
    ] {
        assert!(doc.contains(required), "doc missing {required}");
    }
}
