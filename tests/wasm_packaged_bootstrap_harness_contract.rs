//! Contract invariants for the packaged bootstrap/load/reload harness
//! (asupersync-3qv04.8.4.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/wasm_packaged_bootstrap_harness_contract.md";
const ARTIFACT_PATH: &str = "artifacts/wasm_packaged_bootstrap_harness_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/test_wasm_packaged_bootstrap_e2e.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load harness contract doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load harness artifact");
    serde_json::from_str(&raw).expect("failed to parse harness artifact")
}

#[test]
fn doc_exists_and_references_bead_and_contract_id() {
    assert!(Path::new(DOC_PATH).exists(), "contract doc must exist");
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-3qv04.8.4.1"),
        "doc must reference bead id"
    );
    assert!(
        doc.contains("wasm-packaged-bootstrap-harness-v1"),
        "doc must reference contract id"
    );
}

#[test]
fn doc_references_runner_artifact_and_tests() {
    let doc = load_doc();
    for token in [
        "artifacts/wasm_packaged_bootstrap_harness_v1.json",
        "scripts/test_wasm_packaged_bootstrap_e2e.sh",
        "tests/wasm_packaged_bootstrap_harness_contract.rs",
        "artifacts/wasm_e2e_log_schema_v1.json",
        "artifacts/wasm_packaged_bootstrap_perf_summary.json",
    ] {
        assert!(doc.contains(token), "doc missing reference: {token}");
    }
}

#[test]
fn artifact_schema_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("wasm-packaged-bootstrap-harness-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-3qv04.8.4.1"));
    assert_eq!(
        artifact["log_schema_version"].as_str(),
        Some("wasm-e2e-log-schema-v1")
    );
    assert_eq!(
        artifact["run_metadata_schema_version"].as_str(),
        Some("wasm-e2e-run-metadata-v1")
    );
    assert_eq!(
        artifact["suite_summary_schema_version"].as_str(),
        Some("e2e-suite-summary-v3")
    );
    assert_eq!(
        artifact["perf_summary_schema_version"].as_str(),
        Some("wasm-budget-summary-v1")
    );
}

#[test]
fn artifact_declares_required_bundle_layout_files() {
    let artifact = load_artifact();
    let required: BTreeSet<&str> = artifact["bundle_layout_required"]
        .as_array()
        .expect("bundle_layout_required must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("bundle_layout_required entry must be string")
        })
        .collect();
    for token in [
        "run-metadata.json",
        "log.jsonl",
        "perf-summary.json",
        "summary.json",
        "steps.ndjson",
    ] {
        assert!(
            required.contains(token),
            "bundle layout must include {token}"
        );
    }
}

#[test]
fn artifact_declares_perf_metrics_and_models() {
    let artifact = load_artifact();
    let startup_metrics: BTreeSet<&str> = artifact["startup_latency_metrics"]
        .as_array()
        .expect("startup_latency_metrics must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("startup_latency_metrics entry must be string")
        })
        .collect();
    assert!(startup_metrics.contains("M-PERF-02A"));
    assert!(startup_metrics.contains("M-PERF-02B"));
    let memory_metrics: BTreeSet<&str> = artifact["steady_state_memory_metrics"]
        .as_array()
        .expect("steady_state_memory_metrics must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("steady_state_memory_metrics entry must be string")
        })
        .collect();
    assert!(memory_metrics.contains("M-PERF-03A"));
    assert_eq!(
        artifact["startup_latency_model"]["model_id"].as_str(),
        Some("artifact-budget-model-v1")
    );
    assert_eq!(
        artifact["steady_state_memory_model"]["model_id"].as_str(),
        Some("artifact-memory-envelope-v1")
    );
    assert_eq!(
        artifact["perf_summary_export_path"].as_str(),
        Some("artifacts/wasm_packaged_bootstrap_perf_summary.json")
    );
}

#[test]
fn artifact_step_catalog_is_complete_and_ordered() {
    let artifact = load_artifact();
    let steps = artifact["steps"].as_array().expect("steps must be array");
    assert_eq!(steps.len(), 4, "must have exactly four baseline steps");

    let ids: Vec<&str> = steps
        .iter()
        .map(|step| step["step_id"].as_str().expect("step_id must be string"))
        .collect();
    assert_eq!(
        ids,
        vec![
            "packaged_module_load",
            "bootstrap_to_runtime_ready",
            "reload_remount_cycle",
            "clean_shutdown",
        ]
    );
}

#[test]
fn artifact_step_commands_are_rch_routed() {
    let artifact = load_artifact();
    let steps = artifact["steps"].as_array().expect("steps must be array");
    for step in steps {
        let step_id = step["step_id"].as_str().unwrap_or("<missing-step-id>");
        let command = step["command"].as_str().unwrap_or("");
        assert!(
            command.contains("rch exec --"),
            "step {step_id} must use rch exec routing"
        );
        assert!(
            command.contains("cargo test"),
            "step {step_id} must execute cargo test"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_schema_and_bundle_files() {
    let script_path = repo_root().join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");
    let script = std::fs::read_to_string(script_path).expect("read runner script");
    for token in [
        "wasm-e2e-run-metadata-v1",
        "\"schema_version\": \"e2e-suite-summary-v3\"",
        "run-metadata.json",
        "log.jsonl",
        "perf-summary.json",
        "summary.json",
        "steps.ndjson",
        "artifacts/wasm_packaged_bootstrap_perf_summary.json",
        "artifact-budget-model-v1",
        "artifact-memory-envelope-v1",
        "M-PERF-02A",
        "M-PERF-02B",
        "M-PERF-03A",
        "packaged_module_load",
        "bootstrap_to_runtime_ready",
        "reload_remount_cycle",
        "clean_shutdown",
        "RCH_BIN",
        "rch is required",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

#[test]
fn runner_script_uses_rch_for_all_step_commands() {
    let script = std::fs::read_to_string(repo_root().join(RUNNER_SCRIPT_PATH))
        .expect("read harness runner script");
    assert!(
        script.contains("step_command=\"${RCH_BIN} exec --"),
        "step command wrapper must route through rch"
    );
}

#[test]
fn orchestrator_registers_packaged_bootstrap_suite() {
    let run_all = std::fs::read_to_string(repo_root().join("scripts/run_all_e2e.sh"))
        .expect("read run_all_e2e.sh");
    for token in [
        "[wasm-packaged-bootstrap]=\"test_wasm_packaged_bootstrap_e2e.sh\"",
        "[wasm-packaged-bootstrap]=\"target/e2e-results/wasm_packaged_bootstrap\"",
        "[wasm-packaged-bootstrap]=\"E2E-SUITE-WASM-PACKAGED-BOOTSTRAP\"",
    ] {
        assert!(
            run_all.contains(token),
            "run_all_e2e.sh must include token: {token}"
        );
    }
}

#[test]
fn e2e_log_quality_test_list_includes_packaged_bootstrap_runner() {
    let content = std::fs::read_to_string(repo_root().join("tests/e2e_log_quality_schema.rs"))
        .expect("read e2e_log_quality_schema.rs");
    assert!(
        content.contains("\"scripts/test_wasm_packaged_bootstrap_e2e.sh\""),
        "e2e log quality schema test must include packaged bootstrap runner"
    );
}

#[test]
fn downstream_beads_stay_in_project_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"]
        .as_array()
        .expect("downstream_beads must be array")
    {
        let bead = bead.as_str().expect("downstream bead must be string");
        assert!(
            bead.starts_with("asupersync-3qv04."),
            "downstream bead must stay in project namespace: {bead}"
        );
    }
}
