//! WASM QA evidence matrix contract invariants (3qv04.8.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const DOC_PATH: &str = "docs/wasm_qa_evidence_matrix_contract.md";
const ARTIFACT_PATH: &str = "artifacts/wasm_qa_evidence_matrix_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_wasm_qa_evidence_smoke.sh";
const PRIMARY_E2E_SCRIPT_PATH: &str = "scripts/run_all_e2e.sh";
const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const CI_MATRIX_POLICY_PATH: &str = ".github/ci_matrix_policy.json";

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

fn load_ci_workflow() -> String {
    std::fs::read_to_string(repo_root().join(CI_WORKFLOW_PATH)).expect("failed to load ci workflow")
}

fn load_ci_matrix_policy() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(CI_MATRIX_POLICY_PATH))
        .expect("failed to load ci matrix policy");
    serde_json::from_str(&raw).expect("failed to parse ci matrix policy")
}

fn repo_relative_or_absolute(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        repo_root().join(path)
    }
}

fn run_all_dry_run_summary() -> (TempDir, String, Value) {
    let suite_root = tempfile::tempdir().expect("suite root tempdir");
    let output = Command::new("bash")
        .arg(RUNNER_SCRIPT_PATH)
        .arg("--all")
        .arg("--dry-run")
        .current_dir(repo_root())
        .env("WASM_QA_SMOKE_SUITE_ROOT", suite_root.path())
        .env("WASM_QA_SMOKE_RUN_ID", "run_contract_summary")
        .output()
        .expect("failed to execute wasm qa smoke runner");

    assert!(
        output.status.success(),
        "runner dry-run failed:\nstdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("runner stdout must be utf-8");
    let summary_path = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Summary: ").map(str::trim))
        .expect("runner output must include Summary: <path>")
        .to_string();
    let summary_raw = std::fs::read_to_string(repo_relative_or_absolute(&summary_path))
        .expect("failed to read emitted suite summary");
    let summary =
        serde_json::from_str(&summary_raw).expect("failed to parse emitted suite summary");
    (suite_root, summary_path, summary)
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
    assert!(
        doc.contains("asupersync-1ky3w.1"),
        "doc must reference vNext surface matrix bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Evidence Layers",
        "VNext Surface Matrix",
        "VNext Certification Lane",
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
            "${RCH_BIN:-rch} exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-qa cargo test --test wasm_qa_evidence_matrix_contract -- --nocapture"
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

#[test]
fn doc_names_vnext_surfaces_and_certification_artifacts() {
    let doc = load_doc();
    for token in [
        "dedicated-worker direct runtime",
        "Durable storage + artifact persistence",
        "Rust-authored browser path",
        "WebTransport guarded lane",
        "Worker offload / guarded parallel preview lane",
        "wasm-browser-vnext-surfaces",
        "artifacts/wasm_browser_vnext_surface_summary.json",
        "tests/wasm_browser_feasibility_matrix.rs",
        "tests/wasm_js_exports_coverage_contract.rs",
        "tests/wasm_rust_browser_example_contract.rs",
        "tests/wasm_pilot_observability_contract.rs",
        "python3 scripts/run_browser_onboarding_checks.py --scenario worker --dry-run --out-dir artifacts/onboarding_vnext",
    ] {
        assert!(
            doc.contains(token),
            "doc must name vNext surface contract token: {token}"
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
    let extension_beads: BTreeSet<&str> = artifact["extension_beads"]
        .as_array()
        .expect("extension_beads must be array")
        .iter()
        .map(|entry| entry.as_str().expect("extension bead must be string"))
        .collect();
    assert!(
        extension_beads.contains("asupersync-1ky3w.1"),
        "extension bead list must include asupersync-1ky3w.1"
    );
}

#[test]
fn artifact_vnext_surface_matrix_is_complete() {
    let artifact = load_artifact();
    let matrix = artifact["vnext_surface_matrix"]
        .as_array()
        .expect("vnext_surface_matrix must be array");
    let surface_ids: BTreeSet<&str> = matrix
        .iter()
        .map(|entry| {
            entry["surface_id"]
                .as_str()
                .expect("surface_id must be string")
        })
        .collect();
    let expected: BTreeSet<&str> = [
        "dedicated_worker_direct_runtime",
        "durable_storage_artifact_persistence",
        "rust_authored_browser_path",
        "guarded_webtransport_lane",
        "worker_offload_parallel_preview",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        surface_ids, expected,
        "vNext surface matrix must enumerate every named browser vNext surface"
    );

    for entry in matrix {
        let support_level = entry["support_level"]
            .as_str()
            .expect("support_level must be string");
        let lane = entry["ci_or_release_lane"]
            .as_str()
            .expect("ci_or_release_lane must be string");
        let evidence = entry["required_evidence"]
            .as_array()
            .expect("required_evidence must be array");
        let fail_closed_rule = entry["fail_closed_rule"]
            .as_str()
            .expect("fail_closed_rule must be string");
        assert!(
            !support_level.is_empty(),
            "support_level must not be empty for {entry:?}",
        );
        assert!(
            lane.contains("wasm-browser-vnext-surfaces"),
            "each vNext surface entry must point at the explicit certification lane"
        );
        assert!(
            !evidence.is_empty(),
            "required_evidence must not be empty for {entry:?}",
        );
        assert!(
            !fail_closed_rule.is_empty(),
            "fail_closed_rule must not be empty for {entry:?}",
        );
    }
}

#[test]
fn artifact_certification_lane_matches_vnext_ci_contract() {
    let artifact = load_artifact();
    let lane = &artifact["certification_lane"];
    assert_eq!(
        lane["lane_id"].as_str(),
        Some("wasm-browser-vnext-surfaces")
    );
    assert_eq!(
        lane["workflow_step_name"].as_str(),
        Some("WASM browser vNext surface certification")
    );
    assert_eq!(
        lane["artifact_name"].as_str(),
        Some("wasm-browser-vnext-surface-certification")
    );
    assert_eq!(
        lane["summary_artifact"].as_str(),
        Some("artifacts/wasm_browser_vnext_surface_summary.json")
    );
    assert_eq!(
        lane["log_artifact"].as_str(),
        Some("artifacts/wasm_browser_vnext_surface_test.log")
    );
    let replay_command = lane["replay_command"]
        .as_str()
        .expect("replay_command must be string");
    for token in [
        "run_browser_onboarding_checks.py --scenario worker --dry-run --out-dir artifacts/onboarding_vnext",
        "rch exec -- bash -lc",
        "wasm_browser_feasibility_matrix",
        "wasm_js_exports_coverage_contract",
        "wasm_rust_browser_example_contract",
        "wasm_pilot_observability_contract",
    ] {
        assert!(
            replay_command.contains(token),
            "vNext certification replay command missing token: {token}"
        );
    }
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
        assert!(
            cmd.contains("${RCH_BIN:-rch} exec --"),
            "scenario {sid} must use the RCH_BIN placeholder"
        );
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
        "WASM-QA-SMOKE-PACKAGED-CANCELLATION",
        "WASM-QA-SMOKE-HOST-BRIDGE",
        "WASM-QA-SMOKE-CROSS-BROWSER",
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
fn packaged_cancellation_smoke_scenario_routes_through_direct_runner() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    let scenario = scenarios
        .iter()
        .find(|entry| entry["scenario_id"] == "WASM-QA-SMOKE-PACKAGED-CANCELLATION")
        .expect("missing packaged cancellation smoke scenario");
    let command = scenario["command"]
        .as_str()
        .expect("packaged cancellation command must be string");
    for token in [
        "scripts/build_browser_core_artifacts.sh prod",
        "WASM_PACKAGED_CANCELLATION_DRY_RUN=1",
        "WASM_PERF_PROFILE=core-min",
        "RCH_BIN=/bin/true",
        "scripts/test_wasm_packaged_cancellation_e2e.sh",
    ] {
        assert!(
            command.contains(token),
            "packaged cancellation smoke scenario missing token: {token}"
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
fn cross_browser_smoke_scenario_routes_through_explicit_matrix() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    let scenario = scenarios
        .iter()
        .find(|entry| entry["scenario_id"] == "WASM-QA-SMOKE-CROSS-BROWSER")
        .expect("missing cross-browser smoke scenario");
    let command = scenario["command"]
        .as_str()
        .expect("cross-browser command must be string");
    for token in [
        "HARNESS_PROFILE=full",
        "HARNESS_DRY_RUN=1",
        "BROWSER_MATRIX=chromium-headless,firefox-headless,webkit-headless",
        "scripts/test_wasm_cross_framework_e2e.sh",
    ] {
        assert!(
            command.contains(token),
            "cross-browser smoke scenario missing token: {token}"
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
        "--all",
        "--scenario",
        "--dry-run",
        "--execute",
        "wasm-qa-evidence-smoke-bundle-v1",
        "wasm-qa-evidence-smoke-run-report-v1",
        "wasm-qa-e2e-log-v1",
        "e2e-suite-summary-v3",
        "events.ndjson",
        "Summary:",
        "target/e2e-results/wasm_qa_evidence_smoke",
        "retention_class",
        "retention_until_utc",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

#[test]
fn runner_is_wired_into_primary_e2e_orchestrator() {
    let root = repo_root();
    let script_path = root.join(PRIMARY_E2E_SCRIPT_PATH);
    assert!(script_path.exists(), "primary e2e orchestrator must exist");
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "[wasm-qa-evidence-smoke]=\"run_wasm_qa_evidence_smoke.sh\"",
        "[wasm-qa-evidence-smoke]=\"target/e2e-results/wasm_qa_evidence_smoke\"",
        "[wasm-qa-evidence-smoke]=\"summary.json\"",
        "[wasm-qa-evidence-smoke]=\"run_*\"",
        "[wasm-qa-evidence-smoke]=\"E2E-SUITE-WASM-QA-EVIDENCE-SMOKE\"",
        "wasm-qa-evidence-smoke doctor-workspace-scan",
    ] {
        assert!(
            script.contains(token),
            "primary e2e orchestrator missing token: {token}"
        );
    }
}

#[test]
fn runner_all_dry_run_emits_populated_suite_summary() {
    let (suite_root, summary_path, summary) = run_all_dry_run_summary();

    assert_eq!(
        summary["schema_version"].as_str(),
        Some("e2e-suite-summary-v3")
    );
    assert_eq!(
        summary["suite_id"].as_str(),
        Some("wasm-qa-evidence-smoke_e2e")
    );
    assert_eq!(
        summary["scenario_id"].as_str(),
        Some("E2E-SUITE-WASM-QA-EVIDENCE-SMOKE")
    );
    assert_eq!(summary["seed"].as_str(), Some("0xDEADBEEF"));
    assert!(summary["started_ts"].as_str().is_some());
    assert!(summary["ended_ts"].as_str().is_some());
    assert_eq!(summary["status"].as_str(), Some("passed"));
    assert_eq!(
        summary["repro_command"].as_str(),
        Some("bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --dry-run")
    );
    assert_eq!(
        summary["artifact_path"].as_str(),
        Some(summary_path.as_str())
    );
    assert_eq!(
        summary["suite"].as_str(),
        Some("wasm-qa-evidence-smoke_e2e")
    );
    assert!(summary["timestamp"].as_str().is_some());
    assert_eq!(summary["test_log_level"].as_str(), Some("info"));
    assert_eq!(summary["tests_passed"].as_i64(), Some(0));
    assert_eq!(summary["tests_failed"].as_i64(), Some(0));
    assert_eq!(summary["exit_code"].as_i64(), Some(0));
    assert_eq!(summary["pattern_failures"].as_i64(), Some(0));
    assert!(summary["log_file"].as_str().is_some());
    assert!(summary["artifact_dir"].as_str().is_some());
    assert_eq!(summary["checks_passed"].as_i64(), Some(0));
    assert_eq!(summary["run_id"].as_str(), Some("run_contract_summary"));
    assert_eq!(summary["mode"].as_str(), Some("dry-run"));
    assert!(
        summary["repro_command"]
            .as_str()
            .is_some_and(|command| command.ends_with("--dry-run")),
        "dry-run summary repro_command must preserve the generating mode"
    );
    assert_eq!(
        summary["suite_name"].as_str(),
        Some("wasm-qa-evidence-smoke_e2e")
    );

    let aggregate_run_dir = suite_root.path().join("run_contract_summary");
    assert_eq!(
        repo_relative_or_absolute(&summary_path),
        aggregate_run_dir.join("summary.json")
    );
    let scenario_dirs = std::fs::read_dir(&aggregate_run_dir)
        .expect("aggregate run dir must exist")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|ft| ft.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert!(
        !scenario_dirs.is_empty(),
        "aggregate dry-run should emit per-scenario bundle directories"
    );
    for scenario_dir in scenario_dirs {
        assert!(
            scenario_dir.join("bundle_manifest.json").exists(),
            "aggregate scenario bundle should include bundle_manifest.json"
        );
        assert!(
            scenario_dir.join("run_report.json").exists(),
            "aggregate scenario bundle should include run_report.json"
        );
    }
}

#[test]
fn runner_execute_mode_honors_rch_bin_override() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake_rch = temp.path().join("fake-rch");
    let fake_log = temp.path().join("fake-rch.log");
    std::fs::write(
        &fake_rch,
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > {}\n",
            fake_log.display()
        ),
    )
    .expect("write fake rch");

    let mut perms = std::fs::metadata(&fake_rch)
        .expect("fake rch metadata")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rch, perms).expect("chmod fake rch");
    }

    let single_root = temp.path().join("runner-out");
    let output = Command::new("bash")
        .arg(RUNNER_SCRIPT_PATH)
        .arg("--scenario")
        .arg("WASM-QA-SMOKE-LAYERS")
        .arg("--execute")
        .current_dir(repo_root())
        .env("RCH_BIN", &fake_rch)
        .env("WASM_QA_SMOKE_SINGLE_ROOT", &single_root)
        .env("WASM_QA_SMOKE_RUN_ID", "run_fake_rch")
        .output()
        .expect("execute smoke runner with fake rch");

    assert!(
        output.status.success(),
        "runner execute mode failed with fake rch:\nstdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let argv = std::fs::read_to_string(&fake_log).expect("fake rch log");
    for token in [
        "exec",
        "--",
        "env",
        "CARGO_INCREMENTAL=0",
        "CARGO_TARGET_DIR=/tmp/rch-codex-wasm-qa",
        "cargo",
        "test",
        "--test",
        "wasm_qa_evidence_matrix_contract",
        "layer",
        "--nocapture",
    ] {
        assert!(
            argv.contains(token),
            "fake rch invocation missing token: {token}\nlogged argv:\n{argv}"
        );
    }

    let run_dir = single_root
        .join("run_fake_rch")
        .join("WASM-QA-SMOKE-LAYERS");
    assert!(
        run_dir.join("run_report.json").exists(),
        "execute mode should emit run_report.json"
    );
    assert!(
        run_dir.join("bundle_manifest.json").exists(),
        "execute mode should emit bundle_manifest.json"
    );
}

#[test]
fn ci_workflow_runs_aggregate_dry_run_and_uploads_aggregate_artifacts() {
    let workflow = load_ci_workflow();
    for token in [
        "WASM QA smoke runner (dry-run bundle contract)",
        "bash scripts/run_wasm_qa_evidence_smoke.sh --all --dry-run",
        "Upload WASM QA smoke bundles",
        "name: wasm-qa-smoke-bundles",
        "path: target/e2e-results/wasm_qa_evidence_smoke/*/*/",
        "Upload WASM QA smoke suite summaries",
        "name: wasm-qa-smoke-suite-summaries",
        "path: target/e2e-results/wasm_qa_evidence_smoke/*/summary.json",
    ] {
        assert!(workflow.contains(token), "workflow missing token: {token}");
    }
}

#[test]
fn ci_workflow_runs_vnext_surface_certification_and_uploads_artifact() {
    let workflow = load_ci_workflow();
    for token in [
        "WASM browser vNext surface certification",
        "python3 scripts/run_browser_onboarding_checks.py \\",
        "--scenario worker \\",
        "--out-dir artifacts/onboarding_vnext",
        "RCH_BIN=\"${HOME}/.local/bin/rch\"",
        "rch is required for WASM browser vNext surface certification",
        "cargo test -p asupersync --test wasm_browser_feasibility_matrix -- --nocapture",
        "cargo test -p asupersync --test wasm_js_exports_coverage_contract -- --nocapture",
        "cargo test -p asupersync --test wasm_rust_browser_example_contract -- --nocapture",
        "cargo test -p asupersync --test wasm_pilot_observability_contract -- --nocapture",
        "artifacts/wasm_browser_vnext_surface_summary.json",
        "artifacts/wasm_browser_vnext_surface_test.log",
        "Upload WASM browser vNext surface certification artifacts",
        "name: wasm-browser-vnext-surface-certification",
    ] {
        assert!(
            workflow.contains(token),
            "workflow missing vNext surface certification token: {token}"
        );
    }
}

#[test]
fn ci_matrix_policy_tracks_suite_summary_artifact_contract() {
    let policy = load_ci_matrix_policy();
    let lane = policy["lanes"]
        .as_array()
        .expect("ci matrix policy lanes must be array")
        .iter()
        .find(|lane| lane["lane_id"] == "wasm-browser-qa-smoke")
        .expect("missing wasm-browser-qa-smoke lane");

    let required_artifacts: BTreeSet<&str> = lane["required_artifact_names"]
        .as_array()
        .expect("required_artifact_names must be array")
        .iter()
        .map(|artifact| {
            artifact
                .as_str()
                .expect("required artifact name must be string")
        })
        .collect();
    for artifact in [
        "wasm-browser-onboarding-smoke",
        "wasm-qa-smoke-bundles",
        "wasm-qa-smoke-suite-summaries",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "wasm-browser-qa-smoke lane missing artifact: {artifact}"
        );
    }

    assert_eq!(
        lane["replay_command"].as_str(),
        Some(
            "python3 scripts/run_browser_onboarding_checks.py --scenario all --dry-run --out-dir artifacts/onboarding && bash scripts/run_wasm_qa_evidence_smoke.sh --all --dry-run"
        )
    );
    assert_eq!(
        lane["thresholds"]["required_artifacts_min"].as_i64(),
        Some(3)
    );

    let failure_taxonomy: BTreeSet<&str> = lane["failure_taxonomy"]
        .as_array()
        .expect("failure_taxonomy must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("failure taxonomy entry must be string")
        })
        .collect();
    assert!(
        failure_taxonomy.contains("suite_summary_artifact_missing"),
        "wasm-browser-qa-smoke lane must track missing suite summary artifacts"
    );
}

#[test]
fn ci_matrix_policy_tracks_vnext_surface_certification_lane() {
    let policy = load_ci_matrix_policy();
    let lane = policy["lanes"]
        .as_array()
        .expect("ci matrix policy lanes must be array")
        .iter()
        .find(|lane| lane["lane_id"] == "wasm-browser-vnext-surfaces")
        .expect("missing wasm-browser-vnext-surfaces lane");

    let required_steps: BTreeSet<&str> = lane["required_step_names"]
        .as_array()
        .expect("required_step_names must be array")
        .iter()
        .map(|step| step.as_str().expect("required step name must be string"))
        .collect();
    assert!(
        required_steps.contains("WASM browser vNext surface certification"),
        "vNext surface lane missing certification step"
    );

    let required_artifacts: BTreeSet<&str> = lane["required_artifact_names"]
        .as_array()
        .expect("required_artifact_names must be array")
        .iter()
        .map(|artifact| {
            artifact
                .as_str()
                .expect("required artifact name must be string")
        })
        .collect();
    assert!(
        required_artifacts.contains("wasm-browser-vnext-surface-certification"),
        "vNext surface lane missing uploaded artifact"
    );

    assert_eq!(lane["require_rch"].as_bool(), Some(true));
    let rch_steps: BTreeSet<&str> = lane["rch_required_step_names"]
        .as_array()
        .expect("rch_required_step_names must be array")
        .iter()
        .map(|step| step.as_str().expect("rch step name must be string"))
        .collect();
    assert!(
        rch_steps.contains("WASM browser vNext surface certification"),
        "vNext surface lane must require rch for the certification step"
    );

    let replay_command = lane["replay_command"]
        .as_str()
        .expect("replay_command must be string");
    for token in [
        "run_browser_onboarding_checks.py --scenario worker --dry-run --out-dir artifacts/onboarding_vnext",
        "rch exec -- bash -lc",
        "wasm_browser_feasibility_matrix",
        "wasm_js_exports_coverage_contract",
        "wasm_rust_browser_example_contract",
        "wasm_pilot_observability_contract",
    ] {
        assert!(
            replay_command.contains(token),
            "vNext surface lane replay command missing token: {token}"
        );
    }

    let failure_taxonomy: BTreeSet<&str> = lane["failure_taxonomy"]
        .as_array()
        .expect("failure_taxonomy must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("failure taxonomy entry must be string")
        })
        .collect();
    for token in [
        "rch_routing_violation",
        "vnext_surface_matrix_drift",
        "worker_support_regression",
        "preview_lane_contract_regression",
    ] {
        assert!(
            failure_taxonomy.contains(token),
            "vNext surface lane failure taxonomy missing token: {token}"
        );
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
