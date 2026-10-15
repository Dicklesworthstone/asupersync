#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn json_string_field<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn assert_target_dir_rch_cargo_command(label: &str, command: &str) {
    assert!(
        !command.starts_with("rch exec -- cargo "),
        "{label} must not use bare rch cargo routing: {command}"
    );
    assert!(
        command.starts_with("rch exec -- env "),
        "{label} must route through rch env: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR="),
        "{label} must pin CARGO_TARGET_DIR: {command}"
    );
    assert!(
        command.contains(" cargo "),
        "{label} must invoke cargo after the rch env prefix: {command}"
    );
}

fn cargo_args_from_rch_command(command: &str) -> Vec<&str> {
    assert_target_dir_rch_cargo_command("proof command", command);
    let mut parts = command.split_whitespace();
    for part in parts.by_ref() {
        if part == "cargo" {
            return parts.collect();
        }
    }
    panic!("proof command must include cargo after rch env prefix: {command}");
}

fn no_tokio_signal_present(output: &str, expected_signal: &str) -> bool {
    output.contains(expected_signal)
        || output.contains("nothing depends on")
        || output.contains("no matches found")
        || output.contains("not found in the graph")
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

    let verifier = contract
        .get("regression_verifier")
        .expect("regression_verifier object");
    assert_eq!(
        verifier.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-aj7lx3.2")
    );
    assert_eq!(
        verifier.get("test").and_then(JsonValue::as_str),
        Some("production_cargo_tree_commands_fail_if_tokio_enters_default_or_metrics_graphs")
    );
    assert!(
        json_string_field(verifier, "command").starts_with("rch exec -- "),
        "regression verifier command must be rch-routed"
    );
    let diagnostics = json_string_field(verifier, "diagnostics");
    for required in ["profile", "feature args", "stdout", "stderr"] {
        assert!(
            diagnostics.contains(required),
            "diagnostics must mention {required}"
        );
    }

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
        assert_target_dir_rch_cargo_command("production guarantee proof_command", command);
        let args = cargo_args_from_rch_command(command);
        assert_eq!(
            args.first().copied(),
            Some("tree"),
            "production guarantee proof_command must invoke cargo tree"
        );
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
    let fuzz_command = json_string_field(fuzz, "proof_command");
    assert_target_dir_rch_cargo_command("fuzz quarantine proof_command", fuzz_command);
    let fuzz_args = cargo_args_from_rch_command(fuzz_command);
    assert_eq!(
        fuzz_args.first().copied(),
        Some("tree"),
        "fuzz quarantine proof_command must invoke cargo tree"
    );
    let fragments = json_string_set(fuzz, "expected_path_fragments");
    for required in ["opentelemetry-proto", "tonic", "tonic-prost", "tokio"] {
        assert!(fragments.contains(required), "missing {required}");
    }
}

#[test]
fn scoped_audit_profiles_do_not_weaken_production_guarantees() {
    let contract = contract();
    let audits = contract
        .get("scoped_audit_profiles")
        .and_then(JsonValue::as_array)
        .expect("scoped_audit_profiles array");
    let profiles: BTreeSet<_> = audits
        .iter()
        .map(|item| json_string_field(item, "profile"))
        .collect();
    assert!(profiles.contains("workspace-normal-audit"));
    assert!(profiles.contains("full-feature-dev-audit"));

    for audit in audits {
        let profile = json_string_field(audit, "profile");
        let command = json_string_field(audit, "proof_command");
        assert_target_dir_rch_cargo_command("scoped audit proof_command", command);
        let args = cargo_args_from_rch_command(command);
        assert_eq!(
            args.first().copied(),
            Some("tree"),
            "{profile}: scoped audit proof_command must invoke cargo tree"
        );
        assert_eq!(
            audit.get("status").and_then(JsonValue::as_str),
            Some("tokio_carrying_scoped_audit")
        );
        assert!(
            command.contains("--workspace"),
            "{profile}: scoped audit command must be workspace-scoped"
        );
        let fragments = json_string_set(audit, "expected_path_fragments");
        assert!(
            fragments.contains("tokio"),
            "{profile}: scoped audit must classify tokio-carrying output"
        );
        let rationale = json_string_field(audit, "rationale").to_ascii_lowercase();
        assert!(
            rationale.contains("not") && rationale.contains("production"),
            "{profile}: rationale must state this is not production proof"
        );
    }

    let full = audits
        .iter()
        .find(|item| item["profile"].as_str() == Some("full-feature-dev-audit"))
        .expect("full-feature-dev-audit profile");
    let full_command = json_string_field(full, "proof_command");
    assert!(
        full_command.contains("-e features")
            && full_command.contains("--workspace")
            && full_command.contains("--invert tokio"),
        "full graph audit command must match the AGENTS full-graph interpretation: {full_command}"
    );
    let full_fragments = json_string_set(full, "expected_path_fragments");
    for required in [
        "opentelemetry_sdk",
        "tokio-stream",
        "tokio-util",
        "sqlx",
        "asupersync-tokio-compat",
        "asupersync-conformance",
        "tokio",
    ] {
        assert!(
            full_fragments.contains(required),
            "full-feature-dev-audit missing {required}"
        );
    }

    for guarantee in contract
        .get("production_guarantees")
        .and_then(JsonValue::as_array)
        .expect("production_guarantees array")
    {
        let command = json_string_field(guarantee, "proof_command");
        assert!(
            !command.contains("--workspace"),
            "production guarantees must stay package-scoped, not workspace audits: {command}"
        );
    }
}

#[test]
fn production_cargo_tree_commands_fail_if_tokio_enters_default_or_metrics_graphs() {
    let contract = contract();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let guarantees = contract
        .get("production_guarantees")
        .and_then(JsonValue::as_array)
        .expect("production_guarantees array");

    for guarantee in guarantees {
        let profile = json_string_field(guarantee, "profile");
        let feature_args = json_string_field(guarantee, "feature_args");
        let proof_command = json_string_field(guarantee, "proof_command");
        let expected_signal = json_string_field(guarantee, "expected_signal");
        let args = cargo_args_from_rch_command(proof_command);
        assert_eq!(
            args.first().copied(),
            Some("tree"),
            "{profile}: proof command must invoke cargo tree"
        );

        let output = Command::new(&cargo)
            .args(&args)
            .env("CARGO_TERM_COLOR", "never")
            .output()
            .unwrap_or_else(|err| {
                panic!(
                    "{profile}: failed to run `{cargo} {}`: {err}",
                    args.join(" ")
                )
            });
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
        let clean_signal = no_tokio_signal_present(&combined, expected_signal);

        assert!(
            output.status.success() || clean_signal,
            "{profile}: cargo tree command failed without a no-Tokio signal\n\
             feature args: {feature_args}\n\
             command: {proof_command}\n\
             status: {}\n\
             {combined}",
            output.status
        );
        assert!(
            clean_signal,
            "{profile}: expected no-Tokio signal `{expected_signal}` from production graph\n\
             feature args: {feature_args}\n\
             command: {proof_command}\n\
             status: {}\n\
             {combined}",
            output.status
        );
        assert!(
            !stdout
                .lines()
                .any(|line| line.trim_start().starts_with("tokio v")),
            "{profile}: tokio is present in the production normal dependency graph\n\
             feature args: {feature_args}\n\
             command: {proof_command}\n\
             status: {}\n\
             {combined}",
            output.status
        );
    }
}

#[test]
fn docs_describe_metrics_as_clean_and_fuzz_as_quarantined() {
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    for required in [
        "The optional `metrics` feature also has no normal-edge dependency on tokio",
        "The `fuzz` feature is intentionally outside this guarantee",
        "full-graph cargo-tree output is likewise an audit surface",
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
        "full graph including dev-deps",
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
