#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const BROWSER_SRC_PATH: &str = "packages/browser/src/index.ts";
const BUILDER_SRC_PATH: &str = "src/runtime/builder.rs";
const CONTRACT_PATH: &str = "artifacts/wasm_browser_support_boundary_contract_v1.json";
const INTEGRATION_DOC_PATH: &str = "docs/integration.md";
const POLICY_PATH: &str = ".github/wasm_worker_offload_policy.json";
const REACTOR_SRC_PATH: &str = "src/runtime/reactor/browser.rs";
const WASM_DOC_PATH: &str = "docs/WASM.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn contains_words(text: &str, phrase: &str) -> bool {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .contains(phrase)
}

fn contract() -> JsonValue {
    json_file(CONTRACT_PATH)
}

#[test]
fn support_boundary_contract_names_canonical_docs_tests_and_scope_limits() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("wasm-browser-support-boundary-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rckwas")
    );

    let docs = string_set(&contract, "canonical_docs");
    for required in [
        WASM_DOC_PATH,
        INTEGRATION_DOC_PATH,
        "docs/wasm_service_worker_broker_contract.md",
        "docs/wasm_shared_worker_tenancy_lifecycle_contract.md",
        "docs/wasm_troubleshooting_compendium.md",
    ] {
        assert!(docs.contains(required), "missing canonical doc {required}");
    }

    let tests = string_set(&contract, "canonical_tests");
    for required in [
        "tests/wasm_browser_support_boundary_contract.rs",
        "tests/wasm_browser_feasibility_matrix.rs",
        "tests/wasm_js_exports_coverage_contract.rs",
        "tests/wasm_service_worker_broker_contract.rs",
        "tests/wasm_shared_worker_tenancy_lifecycle_contract.rs",
    ] {
        assert!(
            tests.contains(required),
            "missing canonical test {required}"
        );
    }

    let scope = contract.get("scope_limits").expect("scope_limits object");
    for forbidden_claim in [
        "service_worker_direct_runtime_shipped",
        "shared_worker_direct_runtime_shipped",
        "webtransport_implies_raw_socket_parity",
    ] {
        assert_eq!(
            scope.get(forbidden_claim).and_then(JsonValue::as_bool),
            Some(false),
            "{forbidden_claim} must stay false"
        );
    }
    for shipped_claim in [
        "message_channel_public_browser_sdk_shipped",
        "broadcast_channel_public_browser_sdk_shipped",
    ] {
        assert_eq!(
            scope.get(shipped_claim).and_then(JsonValue::as_bool),
            Some(true),
            "{shipped_claim} must be true after asupersync-b35gbf.1"
        );
    }
}

#[test]
fn direct_runtime_contexts_are_supported_only_for_main_thread_and_dedicated_worker() {
    let contract = contract();
    let browser_src = read_repo_file(BROWSER_SRC_PATH);
    let builder_src = read_repo_file(BUILDER_SRC_PATH);
    let policy = read_repo_file(POLICY_PATH);

    for context in array(&contract, "runtime_contexts") {
        let name = context
            .get("context")
            .and_then(JsonValue::as_str)
            .expect("context string");
        let direct_runtime_supported = context
            .get("direct_runtime_supported")
            .and_then(JsonValue::as_bool)
            .expect("direct_runtime_supported bool");
        let package_reason = context
            .get("package_reason")
            .and_then(JsonValue::as_str)
            .expect("package_reason string");
        let runtime_reason_code = context
            .get("runtime_reason_code")
            .and_then(JsonValue::as_str)
            .expect("runtime_reason_code string");

        assert!(
            browser_src.contains(name) || builder_src.contains(name),
            "{name} must be named by package or runtime source"
        );
        assert!(
            browser_src.contains(package_reason) || builder_src.contains(package_reason),
            "{name} package reason {package_reason} must be visible"
        );
        assert!(
            builder_src.contains(runtime_reason_code) || policy.contains(runtime_reason_code),
            "{name} runtime reason {runtime_reason_code} must be visible"
        );

        if matches!(name, "browser_main_thread" | "dedicated_worker") {
            assert!(
                direct_runtime_supported,
                "{name} should be a supported direct-runtime context"
            );
        } else {
            assert!(
                !direct_runtime_supported,
                "{name} direct runtime must stay fail-closed"
            );
            assert!(
                runtime_reason_code.ends_with("_direct_runtime_not_shipped"),
                "{name} must use an explicit not-shipped reason code"
            );
        }

        for marker in array(context, "required_markers") {
            let marker = marker.as_str().expect("required marker string");
            assert!(
                browser_src.contains(marker)
                    || builder_src.contains(marker)
                    || policy.contains(marker),
                "{name} required marker missing: {marker}"
            );
        }
    }
}

#[test]
fn service_and_shared_worker_helpers_do_not_widen_direct_runtime_claims() {
    let browser_src = read_repo_file(BROWSER_SRC_PATH);
    let builder_src = read_repo_file(BUILDER_SRC_PATH);
    let wasm_doc = read_repo_file(WASM_DOC_PATH);
    let integration = read_repo_file(INTEGRATION_DOC_PATH);

    for marker in [
        "detectBrowserServiceWorkerBrokerSupport(",
        "BrowserServiceWorkerBrokerStore",
        "registerBroker(",
        "persistDurableHandoff(",
        "reason: \"service_worker_not_yet_shipped\"",
        "BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped",
        "lane.browser.service_worker.broker",
    ] {
        assert!(
            browser_src.contains(marker) || builder_src.contains(marker),
            "service-worker boundary marker missing: {marker}"
        );
    }

    for marker in [
        "detectBrowserSharedWorkerCoordinatorSupport(",
        "createBrowserSharedWorkerCoordinatorSelection(",
        "BrowserSharedWorkerCoordinatorClient",
        "shared_worker_not_yet_shipped",
        "BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped",
        "lane.browser.shared_worker.coordinator",
    ] {
        assert!(
            browser_src.contains(marker) || builder_src.contains(marker),
            "shared-worker boundary marker missing: {marker}"
        );
    }

    for marker in [
        "direct runtime remains fail-closed",
        "service_worker_not_yet_shipped",
        "shared_worker_direct_runtime_not_shipped",
        "validate_service_worker_broker_consumer.sh",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            contains_words(&wasm_doc, marker) || contains_words(&integration, marker),
            "worker docs must preserve marker: {marker}"
        );
    }
}

#[test]
fn browser_native_messaging_is_guarded_public_sdk_surface_without_raw_transport_claim() {
    let contract = contract();
    let browser_src = read_repo_file(BROWSER_SRC_PATH);
    let reactor_src = read_repo_file(REACTOR_SRC_PATH);
    let wasm_doc = read_repo_file(WASM_DOC_PATH);

    let messaging = array(&contract, "capability_surfaces")
        .iter()
        .find(|surface| {
            surface.get("surface").and_then(JsonValue::as_str) == Some("browser_native_messaging")
        })
        .expect("browser_native_messaging surface");
    assert_eq!(
        messaging.get("public_label").and_then(JsonValue::as_str),
        Some("guarded_package_level_support")
    );

    for marker in array(messaging, "allowed_internal_markers") {
        let marker = marker.as_str().expect("allowed marker string");
        assert!(
            reactor_src.contains(marker) || browser_src.contains(marker),
            "internal messaging marker must remain visible: {marker}"
        );
    }

    for marker in array(messaging, "required_public_export_markers") {
        let marker = marker.as_str().expect("public marker string");
        assert!(
            browser_src.contains(marker),
            "browser SDK must export guarded messaging marker: {marker}"
        );
    }

    for marker in [
        "Browser-native messaging surfaces (`MessageChannel`, `MessagePort`, `BroadcastChannel`)",
        "guarded public Browser Edition helpers",
        "explicit BrowserNativeMessagingCapability",
        "not an asupersync channel, raw transport, or cross-origin bridge",
    ] {
        assert!(
            wasm_doc.contains(marker),
            "docs/WASM.md must preserve messaging boundary marker: {marker}"
        );
    }
}

#[test]
fn webtransport_is_guarded_and_documents_websocket_or_fetch_fallback() {
    let contract = contract();
    let browser_src = read_repo_file(BROWSER_SRC_PATH);
    let wasm_doc = read_repo_file(WASM_DOC_PATH);
    let integration = read_repo_file(INTEGRATION_DOC_PATH);

    let webtransport = array(&contract, "capability_surfaces")
        .iter()
        .find(|surface| {
            surface.get("surface").and_then(JsonValue::as_str) == Some("webtransport_datagrams")
        })
        .expect("webtransport_datagrams surface");
    assert_eq!(
        webtransport.get("public_label").and_then(JsonValue::as_str),
        Some("guarded_direct_runtime_support")
    );
    assert_eq!(
        webtransport
            .get("fallback_required")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    for marker in array(webtransport, "required_markers") {
        let marker = marker.as_str().expect("required marker string");
        assert!(
            browser_src.contains(marker)
                || wasm_doc.contains(marker)
                || integration.contains(marker),
            "WebTransport required marker missing: {marker}"
        );
    }
    assert!(
        wasm_doc.contains("this does not imply raw-socket parity")
            || integration.contains("raw TCP/UDP"),
        "WebTransport docs must not imply raw-socket parity"
    );
}

#[test]
fn docs_point_to_the_bead_specific_support_boundary_contract() {
    let wasm_doc = read_repo_file(WASM_DOC_PATH);
    for marker in [
        "artifacts/wasm_browser_support_boundary_contract_v1.json",
        "tests/wasm_browser_support_boundary_contract.rs",
        "asupersync-rckwas",
    ] {
        assert!(
            wasm_doc.contains(marker),
            "docs/WASM.md must mention {marker}"
        );
    }
}
