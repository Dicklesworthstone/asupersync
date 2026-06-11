//! Contract tests for VF6 cargo graph budget rows.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/validation_frontier_graph_budgets_v1.json";
const DOC_PATH: &str = "docs/validation_frontier_graph_budgets.md";
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

fn artifact() -> Value {
    load_json(ARTIFACT_PATH)
}

fn manifest() -> Value {
    load_json(MANIFEST_PATH)
}

fn inventory() -> Value {
    load_json(INVENTORY_PATH)
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

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn number_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned number"))
}

fn rows_by_id<'a>(rows: &'a [Value], key: &str) -> BTreeMap<String, &'a Value> {
    let mut by_id = BTreeMap::new();
    for row in rows {
        let id = string_field(row, key).to_string();
        assert!(
            by_id.insert(id.clone(), row).is_none(),
            "duplicate {key} row {id}"
        );
    }
    by_id
}

fn enum_values<'a>(artifact: &'a Value, key: &str) -> BTreeSet<&'a str> {
    artifact["classification_enums"][key]
        .as_array()
        .unwrap_or_else(|| panic!("classification_enums.{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("classification_enums.{key} entry must be string"))
        })
        .collect()
}

#[test]
fn graph_budget_contract_is_self_describing() {
    let artifact = artifact();
    assert_eq!(
        string_field(&artifact, "contract_version"),
        "validation-frontier-graph-budgets-v1"
    );
    assert_eq!(
        string_field(&artifact, "bead_id"),
        "asupersync-validation-frontier-v2-b5cjsv.6"
    );

    let source = object(&artifact, "source_of_truth");
    for (key, expected) in [
        ("artifact", ARTIFACT_PATH),
        (
            "contract_test",
            "tests/validation_frontier_graph_budgets_contract.rs",
        ),
        ("documentation", DOC_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("validation_frontier_inventory", INVENTORY_PATH),
        ("cargo_manifest", "Cargo.toml"),
        ("agent_instructions", "AGENTS.md"),
    ] {
        assert_eq!(
            source.get(key).and_then(Value::as_str),
            Some(expected),
            "source_of_truth.{key}"
        );
    }

    for key in [
        "budget_class",
        "graph_source",
        "tokio_policy",
        "conformance_policy",
    ] {
        assert!(
            !enum_values(&artifact, key).is_empty(),
            "{key} enum must be nonempty"
        );
    }

    let policy = object(&artifact, "budget_policy");
    for key in [
        "focused_lane_rule",
        "forbidden_edge_rule",
        "conformance_masquerade_rule",
        "tokio_boundary_rule",
    ] {
        assert!(string_field(&Value::Object(policy.clone()), key).contains("must"));
    }
}

#[test]
fn budget_rows_reference_manifest_and_inventory_rows() {
    let artifact = artifact();
    let manifest = manifest();
    let inventory = inventory();
    let manifest_rows = rows_by_id(array(&manifest, "lanes"), "lane_id");
    let inventory_rows = rows_by_id(array(&inventory, "lanes"), "lane_id");

    for budget in array(&artifact, "lane_budgets") {
        let lane_id = string_field(budget, "lane_id");
        let manifest_row = manifest_rows
            .get(lane_id)
            .unwrap_or_else(|| panic!("{lane_id} missing from manifest"));
        let inventory_row = inventory_rows
            .get(lane_id)
            .unwrap_or_else(|| panic!("{lane_id} missing from inventory"));

        assert!(bool_field(budget, "manifest_lane_required"));
        assert!(bool_field(budget, "inventory_row_required"));
        assert!(bool_field(budget, "command_must_match_manifest"));
        assert_eq!(
            string_field(manifest_row, "command"),
            string_field(inventory_row, "command"),
            "{lane_id}: inventory command must mirror manifest"
        );
        assert!(
            string_field(manifest_row, "command").starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "{lane_id}: manifest command must be remote-required"
        );

        let fixture = object(budget, "fixture_graph");
        let command_excerpt = fixture
            .get("command_excerpt")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{lane_id}: fixture command excerpt must be a string"));
        assert!(
            string_field(manifest_row, "command").contains(command_excerpt),
            "{lane_id}: fixture command excerpt should be part of manifest command"
        );
    }
}

#[test]
fn budget_rows_have_enforceable_graph_limits_and_boundaries() {
    let artifact = artifact();
    let budget_classes = enum_values(&artifact, "budget_class");
    let graph_sources = enum_values(&artifact, "graph_source");
    let tokio_policies = enum_values(&artifact, "tokio_policy");
    let conformance_policies = enum_values(&artifact, "conformance_policy");

    for budget in array(&artifact, "lane_budgets") {
        let lane_id = string_field(budget, "lane_id");
        assert!(
            budget_classes.contains(string_field(budget, "budget_class")),
            "{lane_id}: invalid budget_class"
        );
        assert!(
            tokio_policies.contains(string_field(budget, "tokio_policy")),
            "{lane_id}: invalid tokio_policy"
        );
        assert!(
            conformance_policies.contains(string_field(budget, "conformance_policy")),
            "{lane_id}: invalid conformance_policy"
        );
        assert!(
            !array(budget, "expected_graph_roots").is_empty(),
            "{lane_id}: graph roots required"
        );
        assert!(
            !array(budget, "no_claim_boundaries").is_empty(),
            "{lane_id}: no-claim boundaries required"
        );
        assert!(
            number_field(budget, "max_package_count") > 0,
            "{lane_id}: max package count required"
        );
        assert!(
            number_field(budget, "max_direct_normal_edges") > 0,
            "{lane_id}: max direct edge count required"
        );
        let fixture = object(budget, "fixture_graph");
        assert!(
            graph_sources.contains(string_field(
                &Value::Object(fixture.clone()),
                "graph_source"
            )),
            "{lane_id}: invalid graph source"
        );
        assert!(
            number_field(&Value::Object(fixture.clone()), "observed_package_count")
                <= number_field(budget, "max_package_count"),
            "{lane_id}: fixture package count exceeds budget"
        );
        assert!(
            !array(&Value::Object(fixture.clone()), "tree_excerpt").is_empty(),
            "{lane_id}: fixture tree excerpt required"
        );
    }
}

#[test]
fn fixtures_do_not_hide_forbidden_packages() {
    let artifact = artifact();
    for budget in array(&artifact, "lane_budgets") {
        let lane_id = string_field(budget, "lane_id");
        let allowed = array(budget, "allowed_heavy_edges")
            .iter()
            .map(|edge| string_field(edge, "package"))
            .collect::<BTreeSet<_>>();
        let tree_text = array(&budget["fixture_graph"], "tree_excerpt")
            .iter()
            .map(|line| {
                line.as_str()
                    .unwrap_or_else(|| panic!("{lane_id}: tree excerpt line must be string"))
            })
            .collect::<Vec<_>>()
            .join("\n");

        for package in array(budget, "forbidden_packages") {
            let package = package
                .as_str()
                .unwrap_or_else(|| panic!("{lane_id}: forbidden package must be string"));
            assert!(
                !tree_text.contains(package) || allowed.contains(package),
                "{lane_id}: fixture includes forbidden package {package} without scoped allowance"
            );
        }

        if string_field(budget, "tokio_policy") == "forbidden" {
            assert!(
                !tree_text.contains("tokio"),
                "{lane_id}: tokio-forbidden lane fixture includes tokio"
            );
        }
        if string_field(budget, "conformance_policy") == "forbidden" {
            assert!(
                !tree_text.contains("asupersync-conformance"),
                "{lane_id}: conformance-forbidden lane fixture includes conformance"
            );
        }
    }
}

#[test]
fn representative_rows_capture_vf6_regression_boundaries() {
    let artifact = artifact();
    let rows = rows_by_id(array(&artifact, "lane_budgets"), "lane_id");

    for lane_id in [
        "default-production-tokio-tree",
        "metrics-production-tokio-tree",
    ] {
        let row = rows.get(lane_id).unwrap_or_else(|| panic!("{lane_id} row"));
        assert_eq!(string_field(row, "tokio_policy"), "forbidden");
        assert_eq!(string_field(row, "conformance_policy"), "forbidden");
        assert_eq!(
            string_field(&row["fixture_graph"], "expected_signal"),
            "warning: nothing to print."
        );
    }

    let channel = rows
        .get("channel-mpsc-select-e2e-public-run")
        .expect("channel public run budget");
    assert!(
        array(channel, "forbidden_packages")
            .iter()
            .any(|package| package.as_str() == Some("asupersync-conformance")),
        "focused channel lane must forbid conformance masquerade"
    );
    assert!(
        array(channel, "no_claim_boundaries")
            .iter()
            .any(|boundary| boundary.as_str() == Some("broad-lib-test-frontier")),
        "focused channel lane must not claim broad lib tests"
    );

    let fuzz = rows
        .get("fuzz-manifest-smoke")
        .expect("fuzz manifest budget");
    assert_eq!(string_field(fuzz, "tokio_policy"), "allowed_scoped");
    let allowed = array(fuzz, "allowed_heavy_edges")
        .iter()
        .map(|edge| string_field(edge, "package"))
        .collect::<BTreeSet<_>>();
    for package in ["opentelemetry-proto", "tonic", "tokio"] {
        assert!(
            allowed.contains(package),
            "fuzz lane must scope allowance for {package}"
        );
    }
}

#[test]
fn documentation_cites_budget_contract_and_no_claim_boundaries() {
    let doc = doc();
    for required in [
        "<!-- validation-frontier-graph-budgets-v1 -->",
        "artifacts/validation_frontier_graph_budgets_v1.json",
        "tests/validation_frontier_graph_budgets_contract.rs",
        "artifacts/proof_lane_manifest_v1.json",
        "artifacts/validation_frontier_inventory_v1.json",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "asupersync-conformance",
        "opentelemetry-proto -> tonic -> tokio",
        "no-claim boundaries",
    ] {
        assert!(doc.contains(required), "doc missing {required}");
    }
}
