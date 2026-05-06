//! Contract tests for the maintained Rust-browser consumer fixture (`asupersync-4l9iw.2`).
//!
//! This suite keeps the repository-maintained Rust-authored browser example
//! wired to a real wasm package layout without implying broad public
//! `RuntimeBuilder` parity for external Rust consumers.

use std::path::PathBuf;

const RUST_BROWSER_EVIDENCE_ARTIFACT_PATH: &str =
    "artifacts/wave2/browser_rust_runtime_api_stability_evidence.json";
const WAVE2_REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";
const RUST_BROWSER_VALIDATOR_PATH: &str = "scripts/validate_rust_browser_consumer.sh";
const RUST_BROWSER_FIXTURE_PATH: &str = "tests/fixtures/rust-browser-consumer";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(path: &str) -> String {
    let path = repo_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))
}

fn read_json(path: &str) -> serde_json::Value {
    let path = repo_root().join(path);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).unwrap_or_else(|_| panic!("invalid JSON {}", path.display()))
}

fn string_array<'a>(value: &'a serde_json::Value, key: &str) -> Vec<&'a str> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entry must be a string"))
        })
        .collect()
}

fn assert_contains_all(haystack: &str, label: &str, markers: &[&str]) {
    for marker in markers {
        assert!(
            haystack.contains(marker),
            "{label} missing marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_consumer_fixture_exists_with_required_files() {
    let fixture = repo_root().join("tests/fixtures/rust-browser-consumer");
    assert!(
        fixture.exists(),
        "Rust browser consumer fixture directory must exist"
    );

    for rel in [
        "README.md",
        "package.json",
        "index.html",
        "vite.config.ts",
        "src/main.ts",
        "src/worker.ts",
        "scripts/check-bundle.mjs",
        "scripts/check-browser-run.mjs",
        "crate/Cargo.toml",
        "crate/src/lib.rs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn rust_browser_runtime_stability_artifact_matches_registry_runner_and_fixture() {
    let artifact = read_json(RUST_BROWSER_EVIDENCE_ARTIFACT_PATH);
    let registry = read_json(WAVE2_REGISTRY_PATH);
    let runner = read_file(RUST_BROWSER_VALIDATOR_PATH);
    let fixture_source = read_file("tests/fixtures/rust-browser-consumer/src/main.ts");
    let fixture_worker = read_file("tests/fixtures/rust-browser-consumer/src/worker.ts");
    let fixture_crate = read_file("tests/fixtures/rust-browser-consumer/crate/src/lib.rs");
    let browser_check =
        read_file("tests/fixtures/rust-browser-consumer/scripts/check-browser-run.mjs");
    let fixture_readme = read_file("tests/fixtures/rust-browser-consumer/README.md");
    let wasm_doc = read_file("docs/WASM.md");
    let integration_doc = read_file("docs/integration.md");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("browser-rust-runtime-api-stability-evidence-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-j1xbon.1"));
    assert_eq!(
        artifact["parent_bead_id"].as_str(),
        Some("asupersync-j1xbon")
    );
    assert_eq!(
        artifact["capability_id"].as_str(),
        Some("browser_rust_runtime_api_stability")
    );
    assert_eq!(
        artifact["fixture_path"].as_str(),
        Some(RUST_BROWSER_FIXTURE_PATH)
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some(RUST_BROWSER_VALIDATOR_PATH)
    );
    assert_eq!(
        artifact["run_report_schema_version"].as_str(),
        Some("browser-rust-runtime-api-stability-run-report-v1")
    );

    assert_eq!(
        string_array(&artifact, "required_log_fields"),
        vec![
            "bead_id",
            "scenario_id",
            "profile",
            "host_context",
            "api_version",
            "consumer_version",
            "selected_lane",
            "unsupported_surfaces",
            "wasm_artifact_path",
            "browser_run_artifact_path",
            "expected_output",
            "actual_output",
            "verdict",
            "first_failure",
        ]
    );

    let scenarios = artifact["scenario_matrix"]
        .as_array()
        .expect("scenario_matrix");
    let scenario_ids = scenarios
        .iter()
        .map(|row| row["scenario_id"].as_str().expect("scenario_id"))
        .collect::<Vec<_>>();
    assert_eq!(
        scenario_ids,
        vec![
            "main_thread_browser_runtime_selection",
            "dedicated_worker_browser_runtime_selection",
            "service_worker_direct_runtime_fail_closed",
            "shared_worker_direct_runtime_fail_closed",
            "missing_webassembly_downgrade",
        ]
    );

    let row = registry["capability_rows"]
        .as_array()
        .expect("capability_rows")
        .iter()
        .find(|row| row["capability_id"].as_str() == Some("browser_rust_runtime_api_stability"))
        .expect("browser_rust_runtime_api_stability registry row");
    let decision = &artifact["support_decision"];
    assert_eq!(
        row["support_class_after"].as_str(),
        decision["support_class_after"].as_str()
    );
    assert_eq!(
        row["promotion_state"].as_str(),
        decision["promotion_state"].as_str()
    );
    assert_eq!(
        row["support_class_after"].as_str(),
        Some("artifact-contract-backed")
    );
    assert_eq!(row["promotion_state"].as_str(), Some("evidence-ready"));
    assert!(
        row["artifact_paths"]
            .as_array()
            .expect("artifact_paths")
            .iter()
            .any(|path| path.as_str() == Some(RUST_BROWSER_EVIDENCE_ARTIFACT_PATH)),
        "registry must link the Rust browser runtime API evidence artifact"
    );
    assert_eq!(
        row["planned_artifact_paths"].as_array().map(Vec::len),
        Some(0)
    );

    assert_contains_all(
        &runner,
        RUST_BROWSER_VALIDATOR_PATH,
        &[
            "--run-id",
            "--output-root",
            "browser-rust-runtime-api-stability-run-report-v1",
            "asupersync-j1xbon.1",
            "runtime-builder-browser-preview-v1",
            "unsupported_surfaces",
            "wasm_artifact_path",
            "browser_run_artifact_path",
            "RUST_BROWSER_RUNTIME_API_SCENARIO",
        ],
    );
    assert_contains_all(
        &fixture_crate,
        "tests/fixtures/rust-browser-consumer/crate/src/lib.rs",
        &[
            "RuntimeBuilder::browser()",
            "preferred_lane",
            "build_selection()",
            "missing_webassembly",
        ],
    );
    assert_contains_all(
        &fixture_source,
        "tests/fixtures/rust-browser-consumer/src/main.ts",
        &[
            "select_rust_browser_runtime",
            "select_rust_browser_runtime_preferred_dedicated_worker",
            "collectDedicatedWorkerMatrix",
            "withDeletedGlobalProperty(\"WebAssembly\"",
            "downgrade_browser_selection",
        ],
    );
    assert_contains_all(
        &fixture_worker,
        "tests/fixtures/rust-browser-consumer/src/worker.ts",
        &[
            "select_rust_browser_runtime",
            "select_rust_browser_runtime_preferred_main_thread",
            "rust-browser-worker-ready",
        ],
    );
    assert_contains_all(
        &browser_check,
        "tests/fixtures/rust-browser-consumer/scripts/check-browser-run.mjs",
        &[
            "main_thread_browser_selection_lane",
            "dedicated_worker_browser_selection_lane",
            "downgrade_reason_code",
            "missing_webassembly",
            "service_worker_direct_runtime_not_shipped",
            "shared_worker_direct_runtime_not_shipped",
        ],
    );
    assert_contains_all(
        &fixture_readme,
        "tests/fixtures/rust-browser-consumer/README.md",
        &[
            "preview public Rust browser builder",
            "maintained in-repo lane",
            "service_worker_fail_closed_reason_code",
            "shared_worker_fail_closed_reason_code",
            "downgrade_reason_code",
        ],
    );
    assert_contains_all(
        &wasm_doc,
        "docs/WASM.md",
        &[
            "RuntimeBuilder::browser()",
            "Preview public lane",
            "scripts/validate_rust_browser_consumer.sh",
            "not broad stable parity",
        ],
    );
    assert_contains_all(
        &integration_doc,
        "docs/integration.md",
        &[
            "RuntimeBuilder::browser()",
            "Preview public lane",
            "tests/fixtures/rust-browser-consumer",
            "asupersync-browser-core",
        ],
    );
}

#[test]
fn rust_browser_consumer_crate_declares_expected_dependencies() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/crate/Cargo.toml");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "asupersync = { path = \"../../../..\", default-features = false, features = [\"wasm-browser-dev\"] }",
        "wasm-bindgen = \"0.2\"",
        "serde-wasm-bindgen = \"0.6\"",
        "web-sys = { version = \"0.3\", features = [\"Document\", \"Window\"] }",
    ] {
        assert!(
            content.contains(marker),
            "crate manifest missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_source_uses_provider_helpers_and_structured_teardown() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/crate/src/lib.rs");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "ReactProviderState",
        "create_child_scope",
        "spawn_task",
        "complete_task",
        ".unmount()",
        "WasmAbiSymbol::TaskCancel",
        "repository_maintained_rust_browser_fixture",
        "RuntimeBuilder::browser()",
        "build_selection()",
        "inspect_browser_execution_ladder",
        "inspect_browser_execution_ladder_with_preferred_lane",
        "inspect_browser_service_worker_broker_support_for_probe",
        "inspect_browser_shared_worker_coordinator_support_for_probe",
        "BrowserServiceWorkerBrokerSupportReason",
        "BrowserSharedWorkerCoordinatorSupportReason",
        "select_rust_browser_runtime",
        "select_rust_browser_runtime_preferred_dedicated_worker",
        "BrowserExecutionLane::DedicatedWorkerDirectRuntime",
        "missing_webassembly",
    ] {
        assert!(
            content.contains(marker),
            "fixture source missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_frontend_imports_generated_pkg() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/src/main.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "../pkg/asupersync_rust_browser_consumer_fixture.js",
        "run_rust_browser_consumer_demo",
        "inspect_rust_browser_execution_ladder",
        "inspect_rust_browser_execution_ladder_preferred_dedicated_worker",
        "select_rust_browser_runtime",
        "select_rust_browser_runtime_preferred_dedicated_worker",
        "new Worker(new URL(\"./worker.ts\", import.meta.url)",
        "\"WebAssembly\"",
        "\"matrix\"",
        "\"rust-browser-consumer\"",
    ] {
        assert!(
            content.contains(marker),
            "frontend source missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_readme_documents_synthetic_unsupported_worker_evidence() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/README.md");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "synthetic service-worker and shared-worker fail-closed ladder snapshots",
        "bounded service-worker broker and shared-worker coordinator support diagnostics",
        "guarded advanced-capability snapshots such as `localStorage`, `indexedDB`, and `WebTransport`",
        "Service-worker and shared-worker snapshots in this fixture are synthetic ladder inspections",
        "bounded service-worker broker and shared-worker coordinator snapshots are host-class preflight diagnostics only",
        "`service_worker_fail_closed_reason_code`, `shared_worker_fail_closed_reason_code`, and `downgrade_reason_code`",
    ] {
        assert!(
            content.contains(marker),
            "fixture README missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_validation_script_exists_and_offloads_wasm_builds_via_rch() {
    let path = repo_root().join("scripts/validate_rust_browser_consumer.sh");
    assert!(
        path.exists(),
        "validate_rust_browser_consumer.sh must exist"
    );
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");

    for needle in [
        "tests/fixtures/rust-browser-consumer",
        "CRATE_DIR=\"${FIXTURE_DIR}/crate\"",
        "WORK_DIR=\"$(mktemp -d \"${RUN_DIR}/work.XXXXXX\")\"",
        "CARGO_WRAPPER=\"${WORK_DIR}/cargo-rch\"",
        "TARGET_DIR=\"${WORK_DIR}/target\"",
        "PKG_DIR=\"${WORK_DIR}/pkg\"",
        "BROWSER_RUN_FILE=\"${RUN_DIR}/browser-run.json\"",
        "cat > \"${CARGO_WRAPPER}\" <<EOF",
        "exec rch exec -- env CARGO_TARGET_DIR=\"${TARGET_DIR}\" cargo \"\\$@\"",
        "CARGO=\"${CARGO_WRAPPER}\" wasm-pack build",
        "cp -R \"${PKG_DIR}/.\" \"${CONSUMER_DIR}/pkg/\"",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "npm run check:browser -- \"${BROWSER_RUN_FILE}\"",
        "\"browser_run\": {",
        "\"status\": browser_run[\"status\"]",
        "\"support_lane\": browser_run[\"support_lane\"]",
        "\"real_browser_run_ok\": browser_run[\"status\"] == \"ok\"",
        "\"ready_phase_is_ready\": browser_run[\"ready_phase\"] == \"ready\"",
        "\"disposed_phase_is_disposed\": browser_run[\"disposed_phase\"] == \"disposed\"",
        "\"completed_task_outcome_is_ok\": browser_run[\"completed_task_outcome\"] == \"ok\"",
        "\"cancel_event_count_is_one\": browser_run[\"cancel_event_count\"] == 1",
        "\"main_thread_selected_lane\": browser_run[\"main_thread_selected_lane\"]",
        "\"main_thread_browser_selection_lane\": browser_run[\"main_thread_browser_selection_lane\"]",
        "\"service_worker_fail_closed_reason_code\": browser_run[\"service_worker_fail_closed_reason_code\"]",
        "\"shared_worker_fail_closed_reason_code\": browser_run[\"shared_worker_fail_closed_reason_code\"]",
        "\"service_worker_broker_reason\": browser_run[\"service_worker_broker_reason\"]",
        "\"shared_worker_coordinator_main_thread_reason\": browser_run[\"shared_worker_coordinator_main_thread_reason\"]",
        "\"shared_worker_coordinator_dedicated_worker_reason\": browser_run[\"shared_worker_coordinator_dedicated_worker_reason\"]",
        "\"downgrade_reason_code\": browser_run[\"downgrade_reason_code\"]",
        "\"downgrade_browser_selection_lane\": browser_run[\"downgrade_browser_selection_lane\"]",
        "\"dedicated_worker_selected_lane\": browser_run[\"dedicated_worker_selected_lane\"]",
        "\"dedicated_worker_browser_selection_lane\": browser_run[\"dedicated_worker_browser_selection_lane\"]",
        "\"dedicated_worker_local_storage_unavailable\": browser_run[\"dedicated_worker_local_storage\"] is False",
        "\"event_symbols_include_task_cancel\": \"task_cancel\" in browser_run[\"event_symbols\"]",
        "\"capabilities_has_webassembly\": browser_run[\"capabilities\"][\"has_webassembly\"] is True",
        "L6-RUST-BROWSER-CONSUMER",
        "asupersync-4l9iw.8",
        "asupersync-4l9iw.11",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
}

#[test]
fn browser_core_build_script_exists_and_offloads_wasm_builds_via_rch() {
    let path = repo_root().join("scripts/build_browser_core_artifacts.sh");
    assert!(path.exists(), "build_browser_core_artifacts.sh must exist");
    let content = std::fs::read_to_string(&path).expect("failed to read build script");

    #[allow(clippy::literal_string_with_formatting_args)]
    for needle in [
        "RCH_BIN=\"${RCH_BIN:-rch}\"",
        "WRAPPER_ROOT=\"${REPO_ROOT}/target/browser-core-build\"",
        "WORK_DIR=\"$(mktemp -d \"${WRAPPER_ROOT}/${PROFILE}.XXXXXX\")\"",
        "CARGO_WRAPPER=\"${WORK_DIR}/cargo-rch\"",
        "TARGET_DIR=\"${WORK_DIR}/target\"",
        "cat > \"${CARGO_WRAPPER}\" <<EOF",
        "exec \"${RCH_BIN}\" exec -- env CARGO_TARGET_DIR=\"${TARGET_DIR}\" cargo \"\\$@\"",
        "CARGO=\"${CARGO_WRAPPER}\" wasm-pack build",
    ] {
        assert!(
            content.contains(needle),
            "build script missing expected marker: {needle}"
        );
    }
}

#[test]
fn rust_browser_fixture_uses_relative_vite_base_and_portable_bundle_checks() {
    let vite_config = repo_root().join("tests/fixtures/rust-browser-consumer/vite.config.ts");
    let vite_content = std::fs::read_to_string(&vite_config)
        .unwrap_or_else(|_| panic!("missing {}", vite_config.display()));
    assert!(
        vite_content.contains("base: \"./\""),
        "vite config must pin a relative base for subpath/file portability"
    );

    let bundle_check =
        repo_root().join("tests/fixtures/rust-browser-consumer/scripts/check-bundle.mjs");
    let bundle_content = std::fs::read_to_string(&bundle_check)
        .unwrap_or_else(|_| panic!("missing {}", bundle_check.display()));
    for marker in [
        "(?:\\.\\/)?assets\\/",
        "Expected at least two JavaScript assets in dist/assets for main-thread + worker bundles",
        "rust-browser-worker-ready",
        "rust-browser-downgrade-missing-webassembly",
    ] {
        assert!(
            bundle_content.contains(marker),
            "bundle check missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_declares_browser_run_check_and_headless_contract() {
    let package_json = repo_root().join("tests/fixtures/rust-browser-consumer/package.json");
    let package_content = std::fs::read_to_string(&package_json)
        .unwrap_or_else(|_| panic!("missing {}", package_json.display()));
    for marker in [
        "\"check:browser\": \"node ./scripts/check-browser-run.mjs\"",
        "\"playwright-core\": \"^1.51.1\"",
    ] {
        assert!(
            package_content.contains(marker),
            "fixture package must preserve browser-run marker: {marker}"
        );
    }

    let browser_check =
        repo_root().join("tests/fixtures/rust-browser-consumer/scripts/check-browser-run.mjs");
    let browser_content = std::fs::read_to_string(&browser_check)
        .unwrap_or_else(|_| panic!("missing {}", browser_check.display()));
    for marker in [
        "import { chromium } from \"playwright-core\";",
        "application/wasm",
        "path.relative(distDir, resolved)",
        "#status",
        "RUST-BROWSER-CONSUMER",
        "repository_maintained_rust_browser_fixture",
        "harness_mode === \"matrix\"",
        "ready_phase === \"ready\"",
        "disposed_phase === \"disposed\"",
        "child_scope_count_before_unmount === 1",
        "active_task_count_before_unmount === 1",
        "completed_task_outcome === \"ok\"",
        "cancel_event_count === 1",
        "main_thread_local_storage === true",
        "dedicated_worker_local_storage === false",
        "main_thread_selected_lane",
        "service_worker_fail_closed_reason_code",
        "shared_worker_fail_closed_reason_code",
        "service_worker_broker_reason",
        "shared_worker_coordinator_main_thread_reason",
        "shared_worker_coordinator_dedicated_worker_reason",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
        "runtime_context: \"service_worker\"",
        "runtime_context: \"shared_worker\"",
        "wasm-service-worker-broker-contract-v1",
        "wasm-shared-worker-tenancy-lifecycle-v1",
        "serviceWorkerFailClosed?.capabilities?.storage?.has_indexed_db === true",
        "serviceWorkerFailClosed?.capabilities?.storage?.has_local_storage === false",
        "sharedWorkerFailClosed?.capabilities?.storage?.has_indexed_db === true",
        "sharedWorkerFailClosed?.capabilities?.storage?.has_local_storage === false",
        "main_thread_browser_selection_lane",
        "dedicated_worker_selected_lane",
        "dedicated_worker_browser_selection_lane",
        "runtime_available === expected.runtime_available",
        "missing_webassembly",
        "candidate_host_role_mismatch",
        "status: \"error\"",
    ] {
        assert!(
            browser_content.contains(marker),
            "browser-run checker missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_worker_fixture_source_preserves_dedicated_worker_matrix_markers() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/src/worker.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "/// <reference lib=\"webworker\" />",
        "run_rust_browser_consumer_demo",
        "inspect_rust_browser_execution_ladder",
        "inspect_rust_browser_execution_ladder_preferred_main_thread",
        "select_rust_browser_runtime",
        "select_rust_browser_runtime_preferred_main_thread",
        "rust-browser-worker-ready",
        "rust-browser-worker-bootstrap",
    ] {
        assert!(
            content.contains(marker),
            "worker source missing expected marker: {marker}"
        );
    }
}
