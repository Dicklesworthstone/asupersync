#![allow(warnings)]
#![allow(clippy::all)]
//! Runtime tail-latency taxonomy contract invariants (AA-01.1).

#![allow(missing_docs)]

use asupersync::observability::{
    TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION, tail_latency_taxonomy_contract,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_tail_latency_taxonomy_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_tail_latency_taxonomy_v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load runtime tail latency taxonomy doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load runtime tail latency taxonomy artifact");
    serde_json::from_str(&raw).expect("failed to parse taxonomy artifact")
}

fn artifact_required_fields(value: &Value) -> BTreeMap<String, (String, bool)> {
    value["required_log_fields"]
        .as_array()
        .expect("required_log_fields must be an array")
        .iter()
        .map(|field| {
            (
                field["key"]
                    .as_str()
                    .expect("field key must be string")
                    .to_string(),
                (
                    field["unit"]
                        .as_str()
                        .expect("field unit must be string")
                        .to_string(),
                    field["required"]
                        .as_bool()
                        .expect("field required must be bool"),
                ),
            )
        })
        .collect()
}

fn artifact_signal_inventory(value: &Value) -> BTreeMap<String, BTreeSet<String>> {
    value["terms"]
        .as_array()
        .expect("terms must be array")
        .iter()
        .map(|term| {
            let term_id = term["term_id"]
                .as_str()
                .expect("term_id must be string")
                .to_string();
            let signals = term["signals"]
                .as_array()
                .expect("signals must be array")
                .iter()
                .map(|signal| {
                    format!(
                        "{}|{}|{}|{}|{}|{}",
                        signal["structured_log_key"]
                            .as_str()
                            .expect("structured_log_key must be string"),
                        signal["unit"].as_str().expect("unit must be string"),
                        signal["producer_symbol"]
                            .as_str()
                            .expect("producer_symbol must be string"),
                        signal["producer_file"]
                            .as_str()
                            .expect("producer_file must be string"),
                        signal["measurement_class"]
                            .as_str()
                            .expect("measurement_class must be string"),
                        signal["core"].as_bool().expect("core must be bool"),
                    )
                })
                .collect();
            (term_id, signals)
        })
        .collect()
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "runtime tail latency taxonomy doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.1.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Canonical Equation",
        "Required Core Log Fields",
        "Term Mapping",
        "Unknown Bucket Policy",
        "Sampling Policy",
        "Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|section| format!("  - {section}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_test_and_source() {
    let doc = load_doc();
    let refs = [
        "artifacts/runtime_tail_latency_taxonomy_v1.json",
        "tests/runtime_tail_latency_taxonomy_contract.rs",
        "src/observability/diagnostics.rs",
    ];
    for reference in refs {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-greenmountain-aa0114 cargo test --features cli --test runtime_tail_latency_taxonomy_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn artifact_contract_version_and_equation_match_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION)
    );
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(contract.contract_version.as_str())
    );
    assert_eq!(
        artifact["equation"].as_str(),
        Some(contract.equation.as_str())
    );
    assert_eq!(
        artifact["total_latency_key"].as_str(),
        Some(contract.total_latency_key.as_str())
    );
    assert_eq!(
        artifact["unknown_bucket_key"].as_str(),
        Some(contract.unknown_bucket_key.as_str())
    );
}

#[test]
fn artifact_required_field_inventory_matches_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    let expected: BTreeMap<String, (String, bool)> = contract
        .required_log_fields
        .into_iter()
        .map(|field| (field.key, (field.unit, field.required)))
        .collect();
    assert_eq!(artifact_required_fields(&artifact), expected);
}

#[test]
fn artifact_term_and_signal_inventory_matches_code() {
    let artifact = load_artifact();
    let contract = tail_latency_taxonomy_contract();

    let expected: BTreeMap<String, BTreeSet<String>> = contract
        .terms
        .into_iter()
        .map(|term| {
            (
                term.term_id,
                term.signals
                    .into_iter()
                    .map(|signal| {
                        format!(
                            "{}|{}|{}|{}|{}|{}",
                            signal.structured_log_key,
                            signal.unit,
                            signal.producer_symbol,
                            signal.producer_file,
                            signal.measurement_class,
                            signal.core
                        )
                    })
                    .collect(),
            )
        })
        .collect();

    assert_eq!(artifact_signal_inventory(&artifact), expected);
}

#[test]
fn artifact_producer_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();

    for term in artifact["terms"].as_array().expect("terms must be array") {
        for signal in term["signals"].as_array().expect("signals must be array") {
            let producer_file = signal["producer_file"]
                .as_str()
                .expect("producer_file must be string");
            assert!(
                root.join(producer_file).exists(),
                "producer file must exist: {producer_file}"
            );
        }
    }
}

#[test]
fn contract_covers_all_required_terms() {
    let contract = tail_latency_taxonomy_contract();
    let term_ids: BTreeSet<&str> = contract
        .terms
        .iter()
        .map(|term| term.term_id.as_str())
        .collect();
    assert_eq!(
        term_ids,
        BTreeSet::from([
            "allocator_or_cache",
            "io_or_network",
            "queueing",
            "retries",
            "service",
            "synchronization",
            "unknown",
        ]),
        "contract must cover the canonical decomposition terms"
    );
}
