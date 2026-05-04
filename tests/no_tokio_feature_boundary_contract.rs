#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

const AGENTS_PATH: &str = "AGENTS.md";
const CARGO_PATH: &str = "Cargo.toml";
const CONTRACT_PATH: &str = "artifacts/no_tokio_feature_boundary_contract_v1.json";
const README_PATH: &str = "README.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> JsonValue {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH)).expect("parse no-Tokio boundary contract")
}

fn cargo_manifest() -> TomlValue {
    toml::from_str(&read_repo_file(CARGO_PATH)).expect("parse Cargo.toml")
}

fn toml_array_string_set(value: &TomlValue, label: &str) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{label} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn json_string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

#[test]
fn cargo_features_keep_metrics_separate_from_otlp_proto_fuzz_helpers() {
    let cargo = cargo_manifest();
    let features = cargo
        .get("features")
        .and_then(TomlValue::as_table)
        .expect("Cargo.toml must contain [features]");
    let contract = contract();
    let cargo_contract = contract
        .get("cargo_feature_contract")
        .expect("cargo_feature_contract object");

    let metrics =
        toml_array_string_set(features.get("metrics").expect("metrics feature"), "metrics");
    let metrics_must_include = json_string_set(cargo_contract, "metrics_must_include");
    let metrics_must_not_include = json_string_set(cargo_contract, "metrics_must_not_include");
    for expected in &metrics_must_include {
        assert!(
            metrics.contains(expected),
            "metrics must include {expected}"
        );
    }
    for forbidden in &metrics_must_not_include {
        assert!(
            !metrics.contains(forbidden),
            "metrics must not include {forbidden}"
        );
    }

    let fuzz = toml_array_string_set(features.get("fuzz").expect("fuzz feature"), "fuzz");
    let fuzz_must_include = json_string_set(cargo_contract, "fuzz_must_include");
    for expected in &fuzz_must_include {
        assert!(fuzz.contains(expected), "fuzz must include {expected}");
    }
}

#[test]
fn opentelemetry_proto_is_tonic_generated_and_not_metrics_backed() {
    let cargo = cargo_manifest();
    let dependencies = cargo
        .get("dependencies")
        .and_then(TomlValue::as_table)
        .expect("Cargo.toml must contain [dependencies]");
    let proto = dependencies
        .get("opentelemetry-proto")
        .expect("opentelemetry-proto dependency");
    assert_eq!(
        proto.get("optional").and_then(TomlValue::as_bool),
        Some(true),
        "opentelemetry-proto must remain optional in production dependencies"
    );

    let proto_features = toml_array_string_set(
        proto
            .get("features")
            .expect("opentelemetry-proto dependency features"),
        "opentelemetry-proto features",
    );
    let expected = json_string_set(
        contract()
            .get("cargo_feature_contract")
            .expect("cargo_feature_contract"),
        "opentelemetry_proto_features",
    );
    assert_eq!(proto_features, expected);
    assert!(
        proto_features.contains("gen-tonic-messages"),
        "OTLP proto dependency must make the Tokio-carrying generated-message edge explicit"
    );
}

#[test]
fn boundary_contract_records_default_metrics_and_fuzz_proofs() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("no-tokio-feature-boundary-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rcktok")
    );

    let guarantees = contract
        .get("production_guarantees")
        .and_then(JsonValue::as_array)
        .expect("production_guarantees array");
    let profiles: BTreeSet<_> = guarantees
        .iter()
        .map(|item| item["profile"].as_str().expect("profile string"))
        .collect();
    assert!(profiles.contains("default-production"));
    assert!(profiles.contains("metrics-production"));
    for guarantee in guarantees {
        let command = guarantee["proof_command"]
            .as_str()
            .expect("proof_command string");
        assert!(command.starts_with("rch exec -- cargo tree "));
        assert_eq!(
            guarantee.get("status").and_then(JsonValue::as_str),
            Some("tokio_free_normal_graph")
        );
        assert_eq!(
            guarantee.get("expected_signal").and_then(JsonValue::as_str),
            Some("warning: nothing to print.")
        );
    }

    let quarantined = contract
        .get("quarantined_tokio_carrying_profiles")
        .and_then(JsonValue::as_array)
        .expect("quarantined profiles array");
    assert_eq!(quarantined.len(), 1);
    let fuzz = &quarantined[0];
    assert_eq!(
        fuzz.get("profile").and_then(JsonValue::as_str),
        Some("fuzz")
    );
    assert_eq!(
        fuzz.get("status").and_then(JsonValue::as_str),
        Some("tokio_carrying_quarantined")
    );
    let fragments = json_string_set(fuzz, "expected_path_fragments");
    for required in ["opentelemetry-proto", "tonic", "tonic-prost", "tokio"] {
        assert!(fragments.contains(required), "missing {required}");
    }
}

#[test]
fn docs_describe_metrics_as_clean_and_fuzz_as_quarantined() {
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    for required in [
        "The optional `metrics` feature also has no normal-edge dependency on tokio",
        "The `fuzz` feature is intentionally outside this guarantee",
        "artifacts/no_tokio_feature_boundary_contract_v1.json",
    ] {
        assert!(
            readme.contains(required),
            "README must contain `{required}`"
        );
    }
    for required in [
        "The optional `metrics` feature also has no normal-edge dependency on tokio",
        "The `fuzz` feature deliberately enables `opentelemetry-proto`",
    ] {
        assert!(
            agents.contains(required),
            "AGENTS.md must contain `{required}`"
        );
    }

    for stale in [
        "metrics feature pulls tokio",
        "metrics feature still pulls tokio",
        "no-tokio guarantee does not yet extend to that feature",
    ] {
        assert!(
            !readme.contains(stale),
            "README must not preserve stale claim `{stale}`"
        );
        assert!(
            !agents.contains(stale),
            "AGENTS.md must not preserve stale claim `{stale}`"
        );
    }
}
