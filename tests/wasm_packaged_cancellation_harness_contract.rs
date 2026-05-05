//! Contract invariants for the packaged cancellation/quiescence harness
//! (asupersync-3qv04.8.4.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/wasm_packaged_cancellation_harness_contract.md";
const ARTIFACT_PATH: &str = "artifacts/wasm_packaged_cancellation_harness_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/test_wasm_packaged_cancellation_e2e.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(path: &str) -> String {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        !content.is_empty(),
        "expected non-empty contract file at {}",
        path.display()
    );
    content
}

fn load_artifact() -> Value {
    let raw = read_file(ARTIFACT_PATH);
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

#[test]
fn doc_exists_and_references_bead_and_contract_id() {
    assert!(Path::new(DOC_PATH).exists(), "contract doc must exist");
    let doc = read_file(DOC_PATH);
    assert!(
        doc.contains("asupersync-3qv04.8.4.2"),
        "doc must reference bead id"
    );
    assert!(
        doc.contains("wasm-packaged-cancellation-harness-v1"),
        "doc must reference contract id"
    );
}

#[test]
fn doc_references_runner_artifact_and_tests() {
    let doc = read_file(DOC_PATH);
    for token in [
        "artifacts/wasm_packaged_cancellation_harness_v1.json",
        "scripts/test_wasm_packaged_cancellation_e2e.sh",
        "tests/wasm_packaged_cancellation_harness_contract.rs",
        "artifacts/wasm_e2e_log_schema_v1.json",
        "artifacts/wasm_packaged_cancellation_perf_summary.json",
        "tests/nextjs_bootstrap_harness.rs",
        "tests/react_wasm_strictmode_harness.rs",
        "tests/close_quiescence_regression.rs",
        "tests/cancel_obligation_invariants.rs",
    ] {
        assert!(doc.contains(token), "doc missing reference: {token}");
    }
}

#[test]
fn artifact_schema_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("wasm-packaged-cancellation-harness-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-3qv04.8.4.2"));
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
    let empty = Vec::new();
    let required: BTreeSet<&str> = artifact["bundle_layout_required"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_str)
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
fn artifact_declares_cancellation_budget_metric_and_model() {
    let artifact = load_artifact();
    let empty = Vec::new();
    let metrics: BTreeSet<&str> = artifact["cancellation_response_metrics"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(metrics.contains("M-PERF-03B"));
    assert_eq!(
        artifact["cancellation_response_model"]["model_id"].as_str(),
        Some("cancellation-step-budget-model-v1")
    );
    assert_eq!(
        artifact["perf_summary_export_path"].as_str(),
        Some("artifacts/wasm_packaged_cancellation_perf_summary.json")
    );
}

#[test]
fn artifact_step_catalog_covers_interrupt_restart_quiescence_and_cleanup() {
    let artifact = load_artifact();
    let empty = Vec::new();
    let steps = artifact["steps"].as_array().unwrap_or(&empty);
    assert_eq!(steps.len(), 4, "must have exactly four cancellation steps");

    let ids: Vec<&str> = steps
        .iter()
        .filter_map(|step| step["step_id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "cancelled_bootstrap_retry_recovery",
            "render_restart_loser_drain",
            "nested_cancel_cascade_quiescence",
            "shutdown_obligation_cleanup",
        ]
    );
}

#[test]
fn artifact_step_commands_are_rch_routed() {
    let artifact = load_artifact();
    let empty = Vec::new();
    let steps = artifact["steps"].as_array().unwrap_or(&empty);
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
fn runner_script_exists_and_declares_schema_and_step_tokens() {
    let script_path = repo_root().join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");
    let script = read_file(RUNNER_SCRIPT_PATH);
    for token in [
        "wasm-e2e-run-metadata-v1",
        "\"schema_version\": \"e2e-suite-summary-v3\"",
        "run-metadata.json",
        "log.jsonl",
        "perf-summary.json",
        "summary.json",
        "steps.ndjson",
        "artifacts/wasm_packaged_cancellation_perf_summary.json",
        "cancellation-step-budget-model-v1",
        "M-PERF-03B",
        "cancelled_bootstrap_retry_recovery",
        "render_restart_loser_drain",
        "nested_cancel_cascade_quiescence",
        "shutdown_obligation_cleanup",
        "cancelled_bootstrap_supports_retryable_recovery_path",
        "concurrent_render_restart_pattern_cancels_and_drains_losers",
        "browser_nested_cancel_cascade_reaches_quiescence",
        "shutdown_cancel_still_resolves_obligations",
        "RCH_BIN",
        "rch is required",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

#[test]
fn runner_script_routes_all_steps_through_rch() {
    let script = read_file(RUNNER_SCRIPT_PATH);
    assert!(
        script.contains("step_command=\"${RCH_BIN} exec --"),
        "step command wrapper must route through rch"
    );
}

#[test]
fn downstream_beads_stay_in_project_namespace() {
    let artifact = load_artifact();
    let empty = Vec::new();
    for bead in artifact["downstream_beads"].as_array().unwrap_or(&empty) {
        let bead = bead.as_str().unwrap_or("");
        assert!(
            bead.starts_with("asupersync-3qv04."),
            "downstream bead must stay in project namespace: {bead}"
        );
    }
}
