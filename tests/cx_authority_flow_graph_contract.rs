#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const GRAPH_PATH: &str = "artifacts/cx_authority_flow_graph_v1.json";
const DOCS_PATH: &str = "docs/cx_authority_flow_graph.md";
const TEST_PATH: &str = "tests/cx_authority_flow_graph_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.6";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
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

fn graph() -> Value {
    json_file(GRAPH_PATH)
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

#[test]
fn graph_declares_sources_docs_and_remote_validation() {
    let graph = graph();
    assert_eq!(
        graph.get("schema_version").and_then(Value::as_str),
        Some("cx-authority-flow-graph-v1")
    );
    assert_eq!(graph.get("bead_id").and_then(Value::as_str), Some(BEAD_ID));
    assert_eq!(
        graph.get("artifact_path").and_then(Value::as_str),
        Some(GRAPH_PATH)
    );

    let source = object(&graph, "source_of_truth");
    assert_eq!(
        source.get("artifact").and_then(Value::as_str),
        Some(GRAPH_PATH)
    );
    assert_eq!(source.get("docs").and_then(Value::as_str), Some(DOCS_PATH));
    assert_eq!(
        source.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );
    for path in [GRAPH_PATH, DOCS_PATH, TEST_PATH] {
        assert_live_path(path);
    }
    for path in array(&graph, "source_paths") {
        assert_live_path(path.as_str().expect("source path string"));
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(GRAPH_PATH), "docs must link graph artifact");
    assert!(docs.contains(BEAD_ID), "docs must link owner bead");
    for marker in array(&graph, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = graph.get("validation").expect("validation must be present");
    let command = string(validation, "rch_command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("cargo test -p asupersync --test cx_authority_flow_graph_contract"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn capability_bits_cover_public_effect_classes() {
    let graph = graph();
    let required = BTreeSet::from([
        "spawn".to_owned(),
        "time".to_owned(),
        "random".to_owned(),
        "io".to_owned(),
        "remote".to_owned(),
    ]);
    let bits = array(&graph, "capability_bits")
        .iter()
        .map(|row| string(row, "bit").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(bits, required);

    let expected_traits = BTreeMap::from([
        ("spawn", "HasSpawn"),
        ("time", "HasTime"),
        ("random", "HasRandom"),
        ("io", "HasIo"),
        ("remote", "HasRemote"),
    ]);
    for row in array(&graph, "capability_bits") {
        let bit = string(row, "bit");
        assert_eq!(
            string(row, "cap_trait"),
            expected_traits[bit],
            "{bit} must map to the correct sealed marker trait"
        );
        assert!(
            string(row, "runtime_mask_bit").starts_with("CapMask::"),
            "{bit} must name its runtime mask bit"
        );
        assert!(
            !array(row, "primary_methods").is_empty(),
            "{bit} must cite effect entry points"
        );
        assert!(
            string(row, "denied_when_missing").contains("None")
                || string(row, "denied_when_missing").contains("unavailable")
                || string(row, "denied_when_missing").contains("not part"),
            "{bit} must explain denial behavior"
        );
    }
}

#[test]
fn context_rows_are_monotone_and_include_denial_boundaries() {
    let graph = graph();
    let rows = array(&graph, "context_rows");
    let by_id = rows
        .iter()
        .map(|row| (string(row, "context_id").to_owned(), row))
        .collect::<BTreeMap<_, _>>();

    for required in [
        "full_cx",
        "no_caps_cx",
        "web_context",
        "grpc_context",
        "background_context",
        "pure_context",
        "entropy_caps",
    ] {
        assert!(
            by_id.contains_key(required),
            "missing context row {required}"
        );
    }

    assert_eq!(
        string_set(by_id["full_cx"], "capabilities"),
        BTreeSet::from([
            "spawn".to_owned(),
            "time".to_owned(),
            "random".to_owned(),
            "io".to_owned(),
            "remote".to_owned(),
        ])
    );
    assert!(string_set(by_id["no_caps_cx"], "capabilities").is_empty());
    assert!(string_set(by_id["pure_context"], "capabilities").is_empty());
    assert_eq!(
        string_set(by_id["web_context"], "capabilities"),
        BTreeSet::from(["io".to_owned(), "time".to_owned()])
    );
    assert_eq!(
        string_set(by_id["background_context"], "capabilities"),
        BTreeSet::from(["spawn".to_owned(), "time".to_owned()])
    );

    for row in rows {
        assert_live_path(string(row, "source_path"));
        assert!(
            !string(row, "construction_path").is_empty(),
            "{} must document construction path",
            string(row, "context_id")
        );
    }
}

#[test]
fn graph_edges_and_denied_examples_are_cited_and_fail_closed() {
    let graph = graph();
    let mut edge_ids = BTreeSet::new();
    for edge in array(&graph, "flow_edges") {
        let edge_id = string(edge, "edge_id");
        assert!(
            edge_ids.insert(edge_id.to_owned()),
            "duplicate edge {edge_id}"
        );
        for path in array(edge, "source_paths") {
            assert_live_path(path.as_str().expect("source path string"));
        }
        assert!(
            [
                "trusted-root",
                "type-level-narrow",
                "runtime-mask-restrict",
                "ambient-denial"
            ]
            .contains(&string(edge, "kind")),
            "{edge_id} has unsupported edge kind"
        );
    }
    assert!(
        edge_ids.contains("ambient-current-observes-innermost-mask"),
        "ambient current restriction edge must be explicit"
    );

    let mut denied_ids = BTreeSet::new();
    for example in array(&graph, "denied_examples") {
        let example_id = string(example, "example_id");
        assert!(
            denied_ids.insert(example_id.to_owned()),
            "duplicate denied example {example_id}"
        );
        let expected = string(example, "expected_denial");
        assert!(
            expected.contains("compile-time")
                || expected.contains("returns None")
                || expected.contains("runtime mask"),
            "{example_id} must describe a concrete denial mechanism"
        );
        for path in array(example, "evidence_refs") {
            assert_live_path(path.as_str().expect("evidence path string"));
        }
    }
    for required in [
        "web-denies-spawn",
        "pure-denies-io",
        "restricted-current-denies-remote",
        "background-denies-io",
    ] {
        assert!(
            denied_ids.contains(required),
            "missing denied example {required}"
        );
    }
}

#[test]
fn graph_preserves_no_claim_boundaries() {
    let graph = graph();
    let no_claims = array(&graph, "no_claims")
        .iter()
        .map(|entry| entry.as_str().expect("no_claim string"))
        .collect::<Vec<_>>();
    assert!(no_claims.len() >= 4);
    for required in [
        "does not prove static whole-program security",
        "does not prove broad workspace health, release readiness, or live RCH fleet availability",
    ] {
        assert!(
            no_claims.iter().any(|claim| claim == &required),
            "missing no-claim boundary: {required}"
        );
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(
        docs.contains("not a static whole-program security proof")
            || docs.contains("does not prove static whole-program security"),
        "docs must keep the static-proof no-claim visible"
    );
}
