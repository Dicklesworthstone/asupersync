//! WASM QA evidence matrix contract invariants (3qv04.8.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/wasm_qa_evidence_matrix_contract.md";
const ARTIFACT_PATH: &str = "artifacts/wasm_qa_evidence_matrix_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_wasm_qa_evidence_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load wasm qa evidence doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load wasm qa evidence artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// -- Doc existence and structure --

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-3qv04.8.1"),
        "doc must reference foundational bead id"
    );
    assert!(
        doc.contains("asupersync-3qv04.8.4.4"),
        "doc must reference log-schema hardening bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Evidence Layers",
        "Structured Logging Contract",
        "E2E Log Schema",
        "Artifact Bundle Layout",
        "Retention Policy",
        "Comparator-Smoke Runner",
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
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_runner_and_test() {
    let doc = load_doc();
    for reference in [
        "artifacts/wasm_qa_evidence_matrix_v1.json",
        "scripts/run_wasm_qa_evidence_smoke.sh",
        "tests/wasm_qa_evidence_matrix_contract.rs",
        "tests/wasm_cfg_compile_invariants.rs",
        "src/types/wasm_abi.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-qa cargo test --test wasm_qa_evidence_matrix_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn doc_references_cfg_compile_harness_commands() {
    let doc = load_doc();
    for command in [
        "cargo test --test wasm_cfg_compile_invariants wasm_profile_matrix_compile_closure_holds -- --ignored --nocapture",
        "cargo test --test wasm_cfg_compile_invariants native_all_targets_backstop_holds -- --ignored --nocapture",
    ] {
        assert!(
            doc.contains(command),
            "doc must reference compile harness command: {command}"
        );
    }
}

// -- Artifact schema and version stability --

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("wasm-qa-evidence-matrix-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("wasm-qa-evidence-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("wasm-qa-evidence-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["artifact_bundle_schema_version"].as_str(),
        Some("wasm-qa-artifact-bundle-v1")
    );
    assert_eq!(
        artifact["e2e_log_schema_version"].as_str(),
        Some("wasm-qa-e2e-log-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_wasm_qa_evidence_smoke.sh")
    );
}

// -- Evidence layer catalog --

#[test]
fn layer_ids_are_complete() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["evidence_layers"]
        .as_array()
        .expect("evidence_layers must be array")
        .iter()
        .map(|l| l["layer_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(actual, expected, "evidence layers must be L1-L8");
}

#[test]
fn each_layer_has_name_and_evidence_items() {
    let artifact = load_artifact();
    for layer in artifact["evidence_layers"].as_array().unwrap() {
        let lid = layer["layer_id"].as_str().unwrap();
        assert!(layer.get("name").is_some(), "layer {lid} missing name");
        let items = layer["evidence_items"]
            .as_array()
            .expect("evidence_items must be array");
        assert!(
            !items.is_empty(),
            "layer {lid} must have at least one evidence item"
        );
    }
}

#[test]
fn evidence_ids_are_globally_unique() {
    let artifact = load_artifact();
    let mut all_ids = BTreeSet::new();
    for layer in artifact["evidence_layers"].as_array().unwrap() {
        for item in layer["evidence_items"].as_array().unwrap() {
            let eid = item["evidence_id"].as_str().unwrap().to_string();
            assert!(all_ids.insert(eid.clone()), "duplicate evidence id: {eid}");
        }
    }
    // Should have at least 25 evidence items across all layers
    assert!(
        all_ids.len() >= 25,
        "must have at least 25 evidence items, got {}",
        all_ids.len()
    );
}

#[test]
fn evidence_ids_are_prefixed_by_layer() {
    let artifact = load_artifact();
    for layer in artifact["evidence_layers"].as_array().unwrap() {
        let lid = layer["layer_id"].as_str().unwrap();
        for item in layer["evidence_items"].as_array().unwrap() {
            let eid = item["evidence_id"].as_str().unwrap();
            assert!(
                eid.starts_with(lid),
                "evidence {eid} must be prefixed by layer {lid}"
            );
        }
    }
}

#[test]
fn each_evidence_item_has_required_fields() {
    let artifact = load_artifact();
    for layer in artifact["evidence_layers"].as_array().unwrap() {
        let lid = layer["layer_id"].as_str().unwrap();
        for item in layer["evidence_items"].as_array().unwrap() {
            let eid = item["evidence_id"].as_str().unwrap_or("<missing>");
            for field in ["evidence_id", "description", "tool"] {
                assert!(
                    item.get(field).is_some(),
                    "evidence {eid} in {lid} missing field: {field}"
                );
            }
        }
    }
}

// -- WASM profiles --

#[test]
fn profile_catalog_has_expected_profiles() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["wasm_profiles"]
        .as_array()
        .expect("wasm_profiles must be array")
        .iter()
        .map(|p| p.as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "wasm-browser-minimal",
        "wasm-browser-dev",
        "wasm-browser-prod",
        "wasm-browser-deterministic",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "wasm profiles must remain stable");
}

// -- Cfg-gated files --

#[test]
fn cfg_gated_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for file in artifact["cfg_gated_files"].as_array().unwrap() {
        let path = file.as_str().unwrap();
        assert!(
            root.join(path).exists(),
            "cfg-gated file must exist: {path}"
        );
    }
}

#[test]
fn cfg_gated_files_cover_known_leak_frontier() {
    let artifact = load_artifact();
    let files: BTreeSet<&str> = artifact["cfg_gated_files"]
        .as_array()
        .expect("cfg_gated_files must be array")
        .iter()
        .map(|file| file.as_str().expect("cfg_gated_files entry must be string"))
        .collect();
    for expected in [
        "src/config.rs",
        "src/runtime/reactor/source.rs",
        "src/net/tcp/socket.rs",
        "src/trace/file.rs",
    ] {
        assert!(
            files.contains(expected),
            "cfg-gated files must include known leak hotspot: {expected}"
        );
    }
}

// -- Structured log fields --

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");
    assert!(!fields.is_empty());
    let mut set = BTreeSet::new();
    for field in fields {
        let f = field.as_str().expect("field must be string").to_string();
        assert!(!f.is_empty());
        assert!(set.insert(f.clone()), "duplicate field: {f}");
    }
}

#[test]
fn structured_log_fields_cover_forensics_bundle_requirements() {
    let artifact = load_artifact();
    let fields: BTreeSet<&str> = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("structured_log_fields_required entry must be string")
        })
        .collect();
    for required in [
        "schema_version",
        "event_kind",
        "scenario_id",
        "run_id",
        "timestamp_utc",
        "module_fingerprint",
        "command_exit_code",
        "bundle_manifest_path",
        "retention_class",
        "retention_until_utc",
    ] {
        assert!(
            fields.contains(required),
            "structured log fields must include {required}"
        );
    }
}

#[test]
fn artifact_bundle_layout_is_stable() {
    let artifact = load_artifact();
    let files: BTreeSet<&str> = artifact["artifact_bundle_layout_required"]
        .as_array()
        .expect("artifact_bundle_layout_required must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("artifact bundle layout entry must be string")
        })
        .collect();
    for required in [
        "bundle_manifest.json",
        "run_report.json",
        "run.log",
        "events.ndjson",
    ] {
        assert!(
            files.contains(required),
            "artifact bundle layout must include {required}"
        );
    }
}

#[test]
fn retention_policy_declares_hot_warm_cold_classes() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["retention_policy"]["schema_version"].as_str(),
        Some("wasm-qa-artifact-retention-v1")
    );
    let mut classes = BTreeSet::new();
    for class in artifact["retention_policy"]["classes"]
        .as_array()
        .expect("retention_policy.classes must be array")
    {
        let class_name = class["class"]
            .as_str()
            .expect("retention class name must be string");
        let min_days = class["min_days"]
            .as_i64()
            .expect("retention class min_days must be integer");
        assert!(
            min_days >= 7,
            "retention class {class_name} must retain >=7 days"
        );
        classes.insert(class_name.to_string());
    }
    let expected: BTreeSet<String> = ["hot", "warm", "cold"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(classes, expected, "retention classes must be hot/warm/cold");
}

// -- Smoke runner and scenarios --

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    assert!(!scenarios.is_empty());
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.contains("rch exec --"), "scenario {sid} must use rch");
    }
}

#[test]
fn smoke_scenarios_cover_cfg_compile_execution() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    let ids: BTreeSet<&str> = scenarios
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("scenario_id must be string")
        })
        .collect();
    for expected in [
        "WASM-QA-SMOKE-CFG-MATRIX",
        "WASM-QA-SMOKE-NATIVE-BACKSTOP",
        "WASM-QA-SMOKE-PACKAGED-BOOTSTRAP",
        "WASM-QA-SMOKE-HOST-BRIDGE",
    ] {
        assert!(
            ids.contains(expected),
            "smoke scenarios must include {expected}"
        );
    }

    for scenario in scenarios {
        let id = scenario["scenario_id"].as_str().unwrap();
        if matches!(
            id,
            "WASM-QA-SMOKE-CFG-MATRIX" | "WASM-QA-SMOKE-NATIVE-BACKSTOP"
        ) {
            let command = scenario["command"].as_str().unwrap();
            assert!(
                command.contains("wasm_cfg_compile_invariants"),
                "scenario {id} must invoke wasm_cfg_compile_invariants"
            );
            assert!(
                command.contains("--ignored"),
                "scenario {id} must execute ignored compile harness tests"
            );
        }
    }
}

#[test]
fn packaged_bootstrap_smoke_scenario_routes_through_harness_profile() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    let scenario = scenarios
        .iter()
        .find(|entry| entry["scenario_id"] == "WASM-QA-SMOKE-PACKAGED-BOOTSTRAP")
        .expect("missing packaged bootstrap smoke scenario");
    let command = scenario["command"]
        .as_str()
        .expect("packaged bootstrap command must be string");
    for token in [
        "HARNESS_PROFILE=packaged_bootstrap",
        "HARNESS_DRY_RUN=1",
        "scripts/test_wasm_cross_framework_e2e.sh",
    ] {
        assert!(
            command.contains(token),
            "packaged bootstrap smoke scenario missing token: {token}"
        );
    }
}

#[test]
fn host_bridge_smoke_scenario_routes_through_harness_profile() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    let scenario = scenarios
        .iter()
        .find(|entry| entry["scenario_id"] == "WASM-QA-SMOKE-HOST-BRIDGE")
        .expect("missing host bridge smoke scenario");
    let command = scenario["command"]
        .as_str()
        .expect("host bridge command must be string");
    for token in [
        "HARNESS_PROFILE=host_bridge",
        "HARNESS_DRY_RUN=1",
        "scripts/test_wasm_cross_framework_e2e.sh",
    ] {
        assert!(
            command.contains(token),
            "host bridge smoke scenario missing token: {token}"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "wasm-qa-evidence-smoke-bundle-v1",
        "wasm-qa-evidence-smoke-run-report-v1",
        "wasm-qa-e2e-log-v1",
        "events.ndjson",
        "retention_class",
        "retention_until_utc",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// -- Downstream beads --

#[test]
fn downstream_beads_are_in_wasm_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-3qv04.") || bead.starts_with("asupersync-1508v."),
            "downstream bead must be in project namespace: {bead}"
        );
    }
}
