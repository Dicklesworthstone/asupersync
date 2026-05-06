//! Contract checks for the browser-native messaging and WHATWG stream
//! external-consumer evidence runner (`asupersync-41hk0t`).

use std::path::PathBuf;
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/wave2/browser_native_message_and_stream_apis_evidence.json";
const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";
const RUNNER_PATH: &str = "scripts/run_browser_native_message_stream_evidence.sh";
const WASM_DOC_PATH: &str = "docs/WASM.md";
const INTEGRATION_DOC_PATH: &str = "docs/integration.md";
const README_PATH: &str = "README.md";
const PACKAGE_MANIFEST_PATH: &str = "packages/browser/package.json";
const PACKAGE_SOURCE_PATH: &str = "packages/browser/src/index.ts";
const FIXTURE_MAIN_PATH: &str = "tests/fixtures/browser-native-message-stream-consumer/src/main.ts";
const FIXTURE_BROWSER_CHECK_PATH: &str =
    "tests/fixtures/browser-native-message-stream-consumer/scripts/check-browser-run.mjs";
const FIXTURE_BUNDLE_CHECK_PATH: &str =
    "tests/fixtures/browser-native-message-stream-consumer/scripts/check-bundle.mjs";

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
fn artifact_pins_required_row_schema_and_complete_scenario_matrix() {
    let artifact = read_json(ARTIFACT_PATH);
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("browser-native-message-stream-evidence-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-41hk0t"));
    assert_eq!(
        artifact["capability_id"].as_str(),
        Some("browser_native_message_and_stream_apis")
    );
    assert_eq!(
        artifact["fixture_path"].as_str(),
        Some("tests/fixtures/browser-native-message-stream-consumer")
    );
    assert_eq!(artifact["runner_script"].as_str(), Some(RUNNER_PATH));

    let required_fields = string_array(&artifact, "required_log_fields");
    assert_eq!(
        required_fields,
        vec![
            "bead_id",
            "scenario_id",
            "host_context",
            "api_surface",
            "capability_granted",
            "degraded_mode",
            "bytes_sent",
            "bytes_received",
            "messages_sent",
            "messages_received",
            "close_kind",
            "expected_error",
            "actual_error",
            "verdict",
            "first_failure",
        ]
    );

    let scenarios = artifact["scenario_matrix"]
        .as_array()
        .expect("scenario_matrix must be an array");
    let scenario_ids = scenarios
        .iter()
        .map(|row| row["scenario_id"].as_str().expect("scenario_id"))
        .collect::<Vec<_>>();
    assert_eq!(
        scenario_ids,
        vec![
            "message_channel_text_roundtrip",
            "message_channel_bytes_roundtrip",
            "message_port_close_rejects_send",
            "message_port_abort_is_sticky",
            "broadcast_channel_delivery",
            "readable_stream_bytes",
            "writable_stream_bytes",
            "capability_denied",
            "degraded_mode_denied",
        ]
    );

    for scenario in scenarios {
        for field in &required_fields {
            if matches!(*field, "bead_id" | "verdict" | "first_failure") {
                continue;
            }
            assert!(
                scenario.get(*field).is_some(),
                "{} missing required field {field}",
                scenario["scenario_id"]
            );
        }
    }
}

#[test]
fn fixture_imports_only_public_browser_package_and_exercises_required_surfaces() {
    let fixture = read_file(FIXTURE_MAIN_PATH);
    let browser_check = read_file(FIXTURE_BROWSER_CHECK_PATH);
    let bundle_check = read_file(FIXTURE_BUNDLE_CHECK_PATH);

    assert!(
        fixture.contains("from \"@asupersync/browser\""),
        "fixture must import only public @asupersync/browser entrypoints"
    );
    for forbidden in [
        "packages/browser/src",
        "../packages/browser",
        "../../packages/browser",
        "@asupersync/browser/src",
    ] {
        assert!(
            !fixture.contains(forbidden),
            "fixture must not deep-import browser internals: {forbidden}"
        );
    }

    for marker in [
        "detectBrowserNativeMessagingSupport",
        "createBrowserMessageChannel",
        "createBrowserBroadcastChannel",
        "detectBrowserNativeStreamSupport",
        "createBrowserReadableStream",
        "createBrowserWritableStream",
        "BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE",
        "BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE",
        "BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE",
        "capability_not_granted",
        "degraded_mode_denied",
        "ambientAccessed",
        "streamAccessed",
    ] {
        assert!(fixture.contains(marker), "fixture missing marker: {marker}");
    }

    for marker in [
        "message_channel_text_roundtrip",
        "message_channel_bytes_roundtrip",
        "message_port_close_rejects_send",
        "message_port_abort_is_sticky",
        "broadcast_channel_delivery",
        "readable_stream_bytes",
        "writable_stream_bytes",
        "capability_denied",
        "degraded_mode_denied",
    ] {
        assert!(
            fixture.contains(marker)
                && browser_check.contains(marker)
                && bundle_check.contains(marker),
            "fixture validation surface missing marker: {marker}"
        );
    }
}

#[test]
fn promoted_docs_package_registry_and_artifact_claim_the_same_public_boundary() {
    let wasm_doc = read_file(WASM_DOC_PATH);
    let integration_doc = read_file(INTEGRATION_DOC_PATH);
    let readme = read_file(README_PATH);
    let package_manifest = read_file(PACKAGE_MANIFEST_PATH);
    let package_source = read_file(PACKAGE_SOURCE_PATH);
    let registry = read_json(REGISTRY_PATH);
    let artifact = read_json(ARTIFACT_PATH);

    let artifact_entrypoints = string_array(&artifact, "public_entrypoints");
    for entrypoint in &artifact_entrypoints {
        assert!(
            package_source.contains(entrypoint),
            "artifact public entrypoint missing from package source: {entrypoint}"
        );
    }

    assert_contains_all(
        &package_manifest,
        PACKAGE_MANIFEST_PATH,
        &[
            "\"name\": \"@asupersync/browser\"",
            "\"types\": \"./dist/index.d.ts\"",
            "\"dist\"",
        ],
    );
    assert_contains_all(
        &package_source,
        PACKAGE_SOURCE_PATH,
        &[
            "BROWSER_NATIVE_MESSAGING_CONTRACT_ID",
            "BROWSER_NATIVE_STREAM_CONTRACT_ID",
            "BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE",
            "BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE",
            "BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE",
            "BROWSER_NATIVE_STREAM_OPERATION_FAILED_CODE",
            "\"ASUPERSYNC_BROWSER_NATIVE_MESSAGING_UNSUPPORTED\"",
            "\"ASUPERSYNC_BROWSER_NATIVE_MESSAGING_OPERATION_FAILED\"",
            "\"ASUPERSYNC_BROWSER_NATIVE_STREAM_UNSUPPORTED\"",
            "\"ASUPERSYNC_BROWSER_NATIVE_STREAM_OPERATION_FAILED\"",
            "\"capability_not_granted\"",
            "\"degraded_mode_denied\"",
            "supportClass: supported ? \"direct_runtime_supported\" : \"unsupported\"",
            "export type BrowserNativeMessagingSurface",
            "export type BrowserNativeStreamSurface",
            "BrowserNativeMessagingCapability",
            "BrowserNativeStreamCapability",
            "BrowserMessagePort",
            "BrowserMessageChannel",
            "BrowserBroadcastChannel",
            "BrowserReadableStream",
            "BrowserWritableStream",
            "BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE",
            "BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE",
            "BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE",
            "BROWSER_NATIVE_STREAM_OPERATION_FAILED_CODE",
        ],
    );

    assert_contains_all(
        &wasm_doc,
        WASM_DOC_PATH,
        &[
            "guarded-public-browser-boundary",
            ARTIFACT_PATH,
            RUNNER_PATH,
            "Browser-native messaging surfaces",
            "MessageChannel",
            "MessagePort",
            "BroadcastChannel",
            "BrowserNativeMessagingCapability",
            "detectBrowserNativeMessagingSupport()",
            "assertBrowserNativeMessagingSupport()",
            "WHATWG `ReadableStream` / `WritableStream` browser-native helpers",
            "BrowserReadableStream",
            "BrowserWritableStream",
            "BrowserNativeStreamCapability",
            "detectBrowserNativeStreamSupport()",
            "assertBrowserNativeStreamSupport()",
            "capability_not_granted",
            "degraded_mode_denied",
            "ASUPERSYNC_BROWSER_NATIVE_MESSAGING_UNSUPPORTED",
            "ASUPERSYNC_BROWSER_NATIVE_MESSAGING_OPERATION_FAILED",
            "ASUPERSYNC_BROWSER_NATIVE_STREAM_UNSUPPORTED",
            "ASUPERSYNC_BROWSER_NATIVE_STREAM_OPERATION_FAILED",
            "cross-origin",
            "raw transport",
            "process",
            "Rust `AsyncRead` / `AsyncWrite` browser-core ABI remains substrate-only",
        ],
    );
    assert_contains_all(
        &integration_doc,
        INTEGRATION_DOC_PATH,
        &[
            "Guarded public browser boundary",
            "guarded-public-browser-boundary",
            ARTIFACT_PATH,
            RUNNER_PATH,
            "createBrowserMessageChannel()",
            "createBrowserMessagePort()",
            "createBrowserBroadcastChannel()",
            "createBrowserReadableStream()",
            "createBrowserWritableStream()",
            "BrowserNativeMessagingCapability",
            "BrowserNativeStreamCapability",
            "capability_not_granted",
            "degraded_mode_denied",
            "ASUPERSYNC_BROWSER_NATIVE_MESSAGING_UNSUPPORTED",
            "ASUPERSYNC_BROWSER_NATIVE_MESSAGING_OPERATION_FAILED",
            "ASUPERSYNC_BROWSER_NATIVE_STREAM_UNSUPPORTED",
            "ASUPERSYNC_BROWSER_NATIVE_STREAM_OPERATION_FAILED",
            "raw TCP/UDP/filesystem/process",
            "cross-origin federation",
            "service-worker or shared-worker direct-runtime support",
            "`AsyncRead` / `AsyncWrite` browser-core wasm ABI",
        ],
    );
    assert!(
        !integration_doc.contains("public messaging-surface APIs"),
        "integration guide must not retain the stale unpromoted messaging row"
    );
    assert_contains_all(
        &readme,
        README_PATH,
        &[
            "Browser-native application-boundary helpers",
            ARTIFACT_PATH,
            "MessageChannel",
            "MessagePort",
            "BroadcastChannel",
            "ReadableStream",
            "WritableStream",
            "BrowserNativeMessagingCapability",
            "BrowserNativeStreamCapability",
            "capability_not_granted",
            "degraded_mode_denied",
            "ASUPERSYNC_BROWSER_NATIVE_*",
            "cross-origin federation",
            "service/shared-worker direct runtime",
            "public Rust `AsyncRead` / `AsyncWrite` browser-core",
        ],
    );

    let row = registry["capability_rows"]
        .as_array()
        .expect("registry capability_rows")
        .iter()
        .find(|row| row["capability_id"].as_str() == Some("browser_native_message_and_stream_apis"))
        .expect("browser_native_message_and_stream_apis registry row");
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
        Some("guarded-public-browser-boundary")
    );
    assert_eq!(
        row["artifact_paths"]
            .as_array()
            .expect("artifact_paths")
            .iter()
            .filter(|path| path.as_str() == Some(ARTIFACT_PATH))
            .count(),
        1
    );
    assert_eq!(
        row["planned_artifact_paths"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn runner_uses_rch_and_preserves_timeout_after_remote_success_classification() {
    let runner = read_file(RUNNER_PATH);
    for marker in [
        "rch exec --",
        "cargo test -p asupersync --test browser_native_message_stream_evidence_contract",
        "Remote command finished: exit=0",
        "test result: ok",
        "retrieval_timeout_after_remote_success",
        "target/browser-native-message-stream-evidence",
        "run_report.json",
        "run.log",
        "BROWSER_NATIVE_MESSAGE_STREAM_SCENARIO",
        "--contract-only",
        "browser-native-message-stream-consumer",
    ] {
        assert!(runner.contains(marker), "runner missing marker: {marker}");
    }
}

#[test]
fn contract_only_runner_smoke_writes_valid_report_without_browser_fixture() {
    let output_root = tempfile::tempdir().expect("tempdir");
    let output_root_path = output_root.path().to_string_lossy().into_owned();
    let output = Command::new("bash")
        .current_dir(repo_root())
        .arg(RUNNER_PATH)
        .arg("--contract-only")
        .arg("--run-id")
        .arg("contract-smoke")
        .arg("--output-root")
        .arg(&output_root_path)
        .output()
        .expect("run contract-only evidence script");

    assert!(
        output.status.success(),
        "contract-only runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root
        .path()
        .join("run_contract-smoke")
        .join("run_report.json");
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|_| panic!("missing {}", report_path.display())),
    )
    .expect("valid run_report.json");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("browser-native-message-stream-run-report-v1")
    );
    assert_eq!(report["contract_only"].as_bool(), Some(true));
    assert_eq!(report["validation_passed"].as_bool(), Some(true));
    assert_eq!(
        report["missing_scenarios"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(report["drifts"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["scenario_rows"].as_array().map(Vec::len), Some(9));
}

#[test]
fn registry_lists_promoted_artifact_and_truthful_non_goals() {
    let registry = read_json(REGISTRY_PATH);
    let capabilities = registry["capability_rows"]
        .as_array()
        .expect("registry capability_rows");
    let row = capabilities
        .iter()
        .find(|row| row["capability_id"].as_str() == Some("browser_native_message_and_stream_apis"))
        .expect("browser_native_message_and_stream_apis registry row");

    assert_eq!(row["owner_bead_id"].as_str(), Some("asupersync-b35gbf"));
    assert_eq!(
        row["support_class_after"].as_str(),
        Some("guarded-public-browser-boundary")
    );
    assert_eq!(row["promotion_state"].as_str(), Some("evidence-ready"));
    assert!(
        row["artifact_paths"]
            .as_array()
            .expect("artifact_paths")
            .iter()
            .any(|path| path.as_str() == Some(ARTIFACT_PATH)),
        "registry row must list the browser-native message/stream artifact"
    );
    assert_eq!(
        row["planned_artifact_paths"].as_array().map(Vec::len),
        Some(0)
    );

    let source_paths = row["source_paths"].as_array().expect("source_paths");
    for expected in [
        RUNNER_PATH,
        ARTIFACT_PATH,
        FIXTURE_MAIN_PATH,
        FIXTURE_BROWSER_CHECK_PATH,
        "packages/browser/src/index.ts",
    ] {
        assert!(
            source_paths
                .iter()
                .any(|path| path.as_str() == Some(expected)),
            "registry source_paths missing {expected}"
        );
    }

    let registry_text = read_file(REGISTRY_PATH);
    for marker in [
        "Raw TCP/UDP/filesystem/process parity is not implied.",
        "Rust AsyncRead/AsyncWrite browser-core ABI remains out of scope.",
        "same-browser public package helpers",
    ] {
        assert!(
            registry_text.contains(marker),
            "registry missing non-goal marker: {marker}"
        );
    }
}
