//! Authoritative browser-feasibility support matrix contract tests.
//!
//! Bead: asupersync-1tte9
//!
//! Encodes the four-bucket classification for every major Browser Edition
//! runtime context and capability family into executable form:
//!
//! 1. **Direct-runtime supported** — shipped, tested, public JS/TS API
//! 2. **Direct-runtime feasible but not yet shipped** — Rust substrate
//!    exists but no public package surface
//! 3. **Guarded optional** — requires deployment prerequisites (e.g.
//!    cross-origin isolation for SharedArrayBuffer)
//! 4. **Impossible for direct browser runtime** — must remain bridge-only
//!    or unsupported (e.g. raw TCP, filesystem, process/signal)
//!
//! If this file's assertions fail, the live tree has drifted from the
//! authoritative matrix and follow-on beads must reconcile.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))
}

fn read_json(rel: &str) -> serde_json::Value {
    let path = repo_root().join(rel);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).unwrap_or_else(|_| panic!("invalid JSON {}", path.display()))
}

fn file_exists(rel: &str) -> bool {
    repo_root().join(rel).exists()
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 1: Runtime Context Classification
// ══════════════════════════════════════════════════════════════════════

// ── Direct-runtime supported contexts ────────────────────────────────

#[test]
fn browser_main_thread_is_direct_runtime_supported() {
    // Evidence: packages/browser/src/index.ts detects window+document and
    // returns supportClass: "direct_runtime_supported", runtimeContext:
    // "browser_main_thread".
    let src = read_file("packages/browser/src/index.ts");
    assert!(
        src.contains("browser_main_thread"),
        "browser SDK must detect main-thread context"
    );
    assert!(
        src.contains("direct_runtime_supported"),
        "browser SDK must classify main thread as direct_runtime_supported"
    );
}

#[test]
fn dedicated_worker_is_direct_runtime_supported() {
    // Evidence: packages/browser/src/index.ts detects
    // DedicatedWorkerGlobalScope and returns direct_runtime_supported.
    let src = read_file("packages/browser/src/index.ts");
    assert!(
        src.contains("DedicatedWorkerGlobalScope"),
        "browser SDK must detect dedicated worker globals"
    );
    assert!(
        src.contains("dedicated_worker"),
        "browser SDK must expose dedicated_worker runtime context"
    );
}

#[test]
fn browser_core_fetch_routes_through_worker_global_scope() {
    // Evidence: asupersync-browser-core/src/lib.rs routes fetch through
    // WorkerGlobalScope when window is unavailable, confirming the
    // dedicated-worker fetch host is wired.
    let src = read_file("asupersync-browser-core/src/lib.rs");
    assert!(
        src.contains("WorkerGlobalScope"),
        "browser-core must import WorkerGlobalScope for worker-context fetch"
    );
}

// ── Direct-runtime feasible but not yet shipped contexts ─────────────

#[test]
fn service_worker_direct_runtime_is_unshipped_but_bounded_broker_support_is_explicit() {
    // Evidence: the browser package now ships bounded service-worker broker
    // helpers, but direct runtime creation still remains fail-closed on that
    // host. The runtime builder mirrors that truth with an explicit
    // ServiceWorkerGlobalScope host-role classification, service_worker
    // runtime_context, and a not-yet-shipped reason.
    let browser_src = read_file("packages/browser/src/index.ts");
    for marker in [
        "detectBrowserServiceWorkerBrokerSupport(",
        "BrowserServiceWorkerBrokerStore",
        "reason: \"service_worker_not_yet_shipped\"",
    ] {
        assert!(
            browser_src.contains(marker),
            "browser SDK must preserve bounded service-worker marker: {marker}"
        );
    }

    let builder_src = read_file("src/runtime/builder.rs");
    for marker in [
        "ServiceWorker,",
        "runtime_context: BrowserRuntimeContext::ServiceWorker",
        "Some(\"ServiceWorkerGlobalScope\") => BrowserExecutionHostRole::ServiceWorker",
        "BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped",
        "inspect_browser_service_worker_broker_support_for_probe",
        "wasm-service-worker-broker-contract-v1",
        "lane.browser.service_worker.broker",
    ] {
        assert!(
            builder_src.contains(marker),
            "runtime builder must preserve service-worker fail-closed marker: {marker}"
        );
    }
}

#[test]
fn shared_worker_direct_runtime_is_unshipped_but_bounded_attach_support_is_explicit() {
    // Evidence: the browser package now ships bounded shared-worker
    // coordinator helpers for browser main-thread and dedicated-worker
    // callers, while direct runtime creation still remains fail-closed for the
    // SharedWorker host itself. The Rust-side ladder should still expose the
    // shared_worker runtime_context explicitly instead of collapsing it to
    // unknown.
    let browser_src = read_file("packages/browser/src/index.ts");
    for marker in [
        "detectBrowserSharedWorkerCoordinatorSupport(",
        "createBrowserSharedWorkerCoordinatorSelection(",
        "BrowserSharedWorkerCoordinatorClient",
        "@asupersync/browser shared-worker coordinator prerequisites are available; direct BrowserRuntime creation remains fail-closed inside the shared-worker host and attach must downgrade explicitly on denial or loss.",
    ] {
        assert!(
            browser_src.contains(marker),
            "browser SDK must preserve bounded shared-worker marker: {marker}"
        );
    }

    let builder_src = read_file("src/runtime/builder.rs");
    for marker in [
        "SharedWorker,",
        "runtime_context: BrowserRuntimeContext::SharedWorker",
        "Some(\"SharedWorkerGlobalScope\") => BrowserExecutionHostRole::SharedWorker",
        "BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped",
        "inspect_browser_shared_worker_coordinator_support_for_probe",
        "wasm-shared-worker-tenancy-lifecycle-v1",
        "lane.browser.shared_worker.coordinator",
    ] {
        assert!(
            builder_src.contains(marker),
            "runtime builder must preserve shared-worker fail-closed marker: {marker}"
        );
    }
}

#[test]
fn worker_docs_distinguish_fail_closed_direct_runtime_from_bounded_package_helpers() {
    let census = read_file("docs/wasm_api_surface_census.md");
    for marker in [
        "Direct runtime remains fail-closed; bounded package-level broker/coordinator support exists",
        "detectBrowserServiceWorkerBrokerSupport()",
        "BrowserServiceWorkerBrokerStore",
        "detectBrowserSharedWorkerCoordinatorSupport()",
        "createBrowserSharedWorkerCoordinatorSelection()",
        "Keep direct runtime creation out of these hosts themselves",
    ] {
        assert!(
            census.contains(marker),
            "wasm_api_surface_census.md must preserve worker docs marker: {marker}"
        );
    }

    let topology = read_file("docs/wasm_typescript_package_topology.md");
    for marker in [
        "No direct-runtime package surface; bounded broker/coordinator helpers exist",
        "detectBrowserServiceWorkerBrokerSupport()",
        "BrowserServiceWorkerBrokerStore",
        "detectBrowserSharedWorkerCoordinatorSupport()",
        "createBrowserSharedWorkerCoordinatorSelection()",
    ] {
        assert!(
            topology.contains(marker),
            "wasm_typescript_package_topology.md must preserve worker package marker: {marker}"
        );
    }
}

#[test]
fn shared_worker_fixture_is_wired_into_primary_docs_and_onboarding_contracts() {
    assert!(
        file_exists("scripts/validate_shared_worker_consumer.sh"),
        "shared-worker validator must stay in-tree"
    );
    assert!(
        file_exists("tests/fixtures/shared-worker-consumer/README.md"),
        "shared-worker fixture docs must stay in-tree"
    );

    let onboarding = read_file("scripts/run_browser_onboarding_checks.py");
    for marker in [
        "\"shared_worker\": [",
        "shared_worker.support_matrix",
        "shared_worker.coordinator_fixture",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            onboarding.contains(marker),
            "onboarding runner must preserve shared-worker marker: {marker}"
        );
    }

    let wasm_doc = read_file("docs/WASM.md");
    for marker in [
        "Shared-worker bounded coordinator attach",
        "shared-worker-consumer",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            wasm_doc.contains(marker),
            "docs/WASM.md must preserve shared-worker fixture marker: {marker}"
        );
    }

    let integration = read_file("docs/integration.md");
    for marker in [
        "Browser shared worker",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            integration.contains(marker),
            "integration guide must preserve shared-worker fixture marker: {marker}"
        );
    }

    let canonical_examples = read_file("docs/wasm_canonical_examples.md");
    for marker in [
        "shared_worker_attach_baseline",
        "shared_worker_protocol_mismatch_fallback",
        "shared-worker-consumer",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            canonical_examples.contains(marker),
            "canonical examples doc must preserve shared-worker fixture marker: {marker}"
        );
    }

    let evidence_matrix = read_file("docs/wasm_evidence_matrix_contract.md");
    for marker in [
        "Guarded shared-worker coordinator lane",
        "shared_worker_consumer",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            evidence_matrix.contains(marker),
            "evidence matrix must preserve shared-worker fixture marker: {marker}"
        );
    }

    let troubleshooting = read_file("docs/wasm_troubleshooting_compendium.md");
    for marker in [
        "Shared-worker packaged-consumer validation",
        "artifacts/onboarding/shared_worker.summary.json",
        "validate_shared_worker_consumer.sh",
    ] {
        assert!(
            troubleshooting.contains(marker),
            "troubleshooting compendium must preserve shared-worker fixture marker: {marker}"
        );
    }
}

#[test]
fn rust_authored_wasm_consumer_path_exposes_preview_public_builder() {
    // Evidence: the semantic core compiles to wasm32 (BrowserReactor exists,
    // types are target-agnostic), and the crate now exposes a preview public
    // RuntimeBuilder browser constructor that truthfully negotiates the
    // execution ladder and fail-closes to structured diagnostics when no
    // direct-runtime lane exists. This remains a narrower preview lane than
    // the shipped JS/TS Browser Edition product, but it is no longer accurate
    // to describe the Rust side as constructor-less.
    assert!(
        file_exists("src/runtime/reactor/browser.rs"),
        "browser reactor substrate must exist"
    );
    let builder_src = read_file("src/runtime/builder.rs");
    assert!(
        builder_src.contains("pub fn browser() -> BrowserRuntimeBuilder"),
        "RuntimeBuilder should expose a preview public browser builder"
    );
    assert!(
        builder_src.contains("pub struct BrowserRuntimeBuilder"),
        "builder should publish the preview browser builder type"
    );
    assert!(
        builder_src.contains("pub struct BrowserRuntimeSelectionResult"),
        "builder should publish the no-throw selection result type"
    );
    assert!(
        builder_src.contains("pub struct BrowserRuntime"),
        "builder should publish the dispatcher-backed preview browser runtime type"
    );
    assert!(
        builder_src.contains("pub enum BrowserRuntimeBuildError"),
        "builder should publish structured preview browser build errors"
    );
    assert!(
        builder_src.contains("pub struct BrowserExecutionLadderDiagnostics"),
        "builder should publish structured Rust-side execution-ladder diagnostics"
    );
    assert!(
        builder_src.contains("pub fn build_selection(self) -> BrowserRuntimeSelectionResult"),
        "preview browser builder should expose a no-throw selection helper"
    );
    assert!(
        builder_src
            .contains("pub fn build(self) -> Result<BrowserRuntime, BrowserRuntimeBuildError>"),
        "preview browser builder should expose a structured build helper"
    );
    assert!(
        builder_src.contains("RuntimeHostServices"),
        "runtime startup evidence should still name the host-services seam"
    );
    assert!(
        builder_src.contains("BrowserHostServicesContract"),
        "runtime startup evidence should still pin the browser host contract"
    );
    assert!(
        builder_src.contains("NativeThreadHostServices"),
        "runtime startup evidence should still isolate the shipped native implementation"
    );
    assert!(
        builder_src.contains("dispatcher-backed"),
        "preview browser docs should explain the dispatcher-backed scope of the new lane"
    );
}

#[test]
fn rust_browser_host_services_smoke_harness_is_pinned() {
    assert!(
        file_exists("scripts/validate_rust_browser_consumer.sh"),
        "browser smoke harness script must stay in-tree"
    );
    assert!(
        file_exists("tests/fixtures/rust-browser-consumer/README.md"),
        "browser smoke harness fixture docs must stay in-tree"
    );

    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("validate_rust_browser_consumer.sh"),
        "WASM guide must point to the maintained browser smoke harness"
    );
    assert!(
        doc.contains("rust-browser-consumer"),
        "WASM guide must point to the maintained Rust browser fixture"
    );
}

#[test]
fn rust_browser_docs_pin_preview_public_builder_contract() {
    let readme = read_file("README.md");
    for marker in [
        "RuntimeBuilder::browser()",
        "inspect_browser_execution_ladder()",
        "build_selection()",
        "selected_lane",
        "host_role",
        "reason_code",
        "preferred_lane",
        "downgrade_order",
    ] {
        assert!(
            readme.contains(marker),
            "README must preserve Rust browser preview marker: {marker}"
        );
    }

    let wasm_doc = read_file("docs/WASM.md");
    for marker in [
        "Preview public lane",
        "RuntimeBuilder::browser()",
        "build_selection()",
        "selected_lane",
        "host_role",
        "reason_code",
        "downgrade_order",
        "validate_rust_browser_consumer.sh",
    ] {
        assert!(
            wasm_doc.contains(marker),
            "WASM guide must preserve Rust browser preview marker: {marker}"
        );
    }

    let quickstart = read_file("docs/wasm_quickstart_migration.md");
    for marker in [
        "RuntimeBuilder::browser()",
        "inspect_browser_execution_ladder()",
        "inspect_browser_execution_ladder_with_preferred_lane",
        "build_selection()",
        "selected_lane",
        "host_role",
        "reason_code",
        "preferred_lane",
        "downgrade_order",
    ] {
        assert!(
            quickstart.contains(marker),
            "WASM quickstart must preserve Rust browser preview marker: {marker}"
        );
    }

    let integration = read_file("docs/integration.md");
    for marker in [
        "Preview public lane",
        "RuntimeBuilder::browser()",
        "selected_lane",
        "host_role",
        "reason_code",
        "preferred_lane",
        "downgrade_order",
    ] {
        assert!(
            integration.contains(marker),
            "integration guide must preserve Rust browser preview marker: {marker}"
        );
    }
}

// ── Bridge-only / impossible contexts ────────────────────────────────

#[test]
fn node_ssr_edge_are_bridge_only() {
    // Evidence: packages/next/src/index.ts classifies server and edge
    // targets as bridge_only with explicit reasons.
    let src = read_file("packages/next/src/index.ts");
    assert!(
        src.contains("bridge_only"),
        "Next adapter must classify server/edge as bridge_only"
    );
    assert!(
        src.contains("bridge_only_server_target"),
        "Next adapter must have bridge_only_server_target reason"
    );
    assert!(
        src.contains("bridge_only_edge_target"),
        "Next adapter must have bridge_only_edge_target reason"
    );
}

// ── Guarded optional contexts ────────────────────────────────────────

#[test]
fn shared_array_buffer_parallelism_is_guarded_optional() {
    // Evidence: docs/WASM.md describes SharedArrayBuffer + cross-origin
    // isolation as a Phase 2 guarded optional lane.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("SharedArrayBuffer"),
        "WASM docs must discuss SharedArrayBuffer"
    );
    assert!(
        doc.contains("cross-origin isolation") || doc.contains("Cross-Origin"),
        "WASM docs must name the cross-origin isolation prerequisite"
    );
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 2: Capability Family Classification
// ══════════════════════════════════════════════════════════════════════

// ── Direct-runtime supported capabilities ────────────────────────────

#[test]
fn structured_concurrency_is_direct_runtime_supported() {
    // Evidence: browser-core exports runtime_create, scope_enter,
    // scope_close, task_spawn, task_join, task_cancel.
    let dts = read_file("packages/browser-core/asupersync.d.ts");
    for symbol in [
        "runtime_create",
        "scope_enter",
        "scope_close",
        "task_spawn",
        "task_join",
        "task_cancel",
    ] {
        assert!(
            dts.contains(symbol),
            "browser-core .d.ts must export {symbol}"
        );
    }
}

#[test]
fn fetch_is_direct_runtime_supported() {
    // Evidence: browser-core exports fetch_request; lib.rs wires through
    // window.fetch() and WorkerGlobalScope.fetch().
    let dts = read_file("packages/browser-core/asupersync.d.ts");
    assert!(
        dts.contains("fetch_request"),
        "browser-core must export fetch_request"
    );
    let lib = read_file("asupersync-browser-core/src/lib.rs");
    assert!(
        lib.contains("INFLIGHT_FETCHES"),
        "browser-core lib must manage in-flight fetch handles"
    );
}

#[test]
fn websocket_is_direct_runtime_supported() {
    // Evidence: browser-core exports websocket_open/send/recv/close/cancel;
    // lib.rs wires through web_sys::WebSocket.
    let dts = read_file("packages/browser-core/asupersync.d.ts");
    for symbol in [
        "websocket_open",
        "websocket_send",
        "websocket_recv",
        "websocket_close",
    ] {
        assert!(dts.contains(symbol), "browser-core must export {symbol}");
    }
}

#[test]
fn four_valued_outcomes_are_direct_runtime_supported() {
    // Evidence: browser SDK exposes ok/err/cancelled/panicked branching.
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("cancelled") && browser_src.contains("panicked"),
        "browser SDK must expose four-valued outcome branching"
    );
}

#[test]
fn abi_versioning_is_direct_runtime_supported() {
    // Evidence: browser-core exports abi_version and abi_fingerprint.
    let dts = read_file("packages/browser-core/asupersync.d.ts");
    assert!(dts.contains("abi_version"), "must export abi_version");
    assert!(
        dts.contains("abi_fingerprint"),
        "must export abi_fingerprint"
    );
}

// ── Browser capabilities with real substrate/package evidence ────────

#[test]
fn indexeddb_is_direct_runtime_supported_with_real_host_backend() {
    // Evidence: src/io/browser_storage.rs has a complete
    // IndexedDbHostBackend with set/get/clear/list_keys wired through
    // web_sys::IdbFactory. The policy layer in src/io/cap.rs validates
    // requests, and the public @asupersync/browser package now exposes
    // a BrowserStorage API for the shipped JS/TS surface.
    let storage_src = read_file("src/io/browser_storage.rs");
    assert!(
        storage_src.contains("IndexedDbHostBackend"),
        "IndexedDB host backend must exist in browser_storage.rs"
    );
    assert!(
        storage_src.contains("IdbFactory"),
        "IndexedDB host must use IdbFactory"
    );
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("BrowserStorage")
            && browser_src.contains("detectBrowserStorageSupport")
            && browser_src.contains("indexeddb"),
        "browser SDK must export IndexedDB storage APIs once shipped"
    );
}

#[test]
fn localstorage_has_guarded_package_level_support() {
    // Evidence: src/io/browser_storage.rs has LocalStorageHostBackend
    // wired through web_sys::Storage and the browser SDK now exposes it
    // as a guarded package-level backend.
    let storage_src = read_file("src/io/browser_storage.rs");
    assert!(
        storage_src.contains("LocalStorage") || storage_src.contains("localStorage"),
        "localStorage host backend must exist"
    );
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("localstorage") || browser_src.contains("localStorage"),
        "browser SDK must surface localStorage as an explicit backend"
    );
}

#[test]
fn browser_runtime_artifact_persistence_is_direct_runtime_supported() {
    // Evidence: the browser SDK now exposes an explicit BrowserArtifactStore
    // on top of BrowserStorage for trace/crash/evidence persistence with
    // export flows and bounded retention.
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("BrowserArtifactStore")
            && browser_src.contains("createBrowserArtifactStore")
            && browser_src.contains("persistTraceRecord")
            && browser_src.contains("exportArchive"),
        "browser SDK must expose explicit runtime artifact persistence helpers"
    );
}

#[test]
fn browser_main_thread_storage_artifact_download_flow_is_supported() {
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("browser_main_thread")
            && browser_src.contains("createBrowserStorage")
            && browser_src.contains("createBrowserArtifactStore")
            && browser_src.contains("downloadArtifact")
            && browser_src.contains("downloadArchive"),
        "browser main thread must retain the explicit storage + download artifact flow"
    );
}

#[test]
fn dedicated_worker_storage_export_flow_is_supported() {
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("dedicated_worker")
            && browser_src.contains("createBrowserStorage")
            && browser_src.contains("exportArchive")
            && browser_src.contains(
                "browser artifact archive downloads require a browser main-thread document; use exportArchive() in workers",
            ),
        "dedicated workers must retain storage/export support plus main-thread-only download guidance"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn dedicated_worker_validation_harness_preserves_storage_artifact_markers() {
    let worker_src = read_file("tests/fixtures/dedicated-worker-consumer/src/worker.ts");
    for marker in [
        "worker-runtime-selection-baseline",
        "worker-scope-selection-baseline",
        "worker-scope-selection-preferred-main-thread",
        "worker-lane-health-retrying",
        "worker-execution-ladder-retrying",
        "worker-lane-health-demotion",
        "worker-runtime-selection-demoted",
        "worker-runtime-selection-prerequisite-loss",
        "worker-lane-health-reset",
        "worker-runtime-selection-recovered",
        "worker-storage-support",
        "worker-storage-roundtrip",
        "worker-storage-artifact-export-handoff",
        "worker-artifact-archive",
        "worker-artifact-download-unavailable",
        "worker-artifact-quota-guard",
        "worker-artifact-cleanup",
    ] {
        assert!(
            worker_src.contains(marker),
            "dedicated-worker fixture must preserve storage/artifact marker: {marker}"
        );
    }

    let validator = read_file("scripts/validate_dedicated_worker_consumer.sh");
    for marker in [
        "BROWSER_RUN_FILE",
        "npm run check:browser",
        "real_browser_run_ok",
        "normalize_artifact_keys",
        "normalize_scenario_inventory",
        "browser_baseline_selected_lane",
        "browser_retrying_status",
        "browser_retrying_selected_lane",
        "browser_retrying_retry_budget_remaining",
        "browser_demotion_failure_count",
        "browser_demotion_last_trigger",
        "browser_demotion_demoted_to_lane_id",
        "browser_demoted_selected_lane",
        "browser_demoted_health_last_trigger",
        "browser_demoted_health_demoted_to_lane_id",
        "browser_prerequisite_loss_simulated",
        "browser_prerequisite_loss_reason_code",
        "browser_prerequisite_loss_health_status",
        "browser_prerequisite_loss_health_demoted_to_lane_id",
        "browser_prerequisite_loss_worker_candidate_reason",
        "browser_recovered_selected_lane",
        "browser_final_phase_is_shutdown_complete",
        "browser_shutdown_reason",
        "browser_shutdown_reason_is_fixture_handoff_complete",
        "graceful_shutdown_handoff",
        "worker_lane_health_retrying_marker",
        "worker_execution_ladder_retrying_marker",
        "worker_runtime_selection_prerequisite_loss_marker",
        "worker_storage_support_marker",
        "worker_storage_roundtrip_marker",
        "storage_artifact_marker",
        "worker_artifact_export_marker",
        "worker_artifact_download_guard_marker",
        "worker_artifact_quota_guard_marker",
        "worker_artifact_cleanup_marker",
    ] {
        assert!(
            validator.contains(marker),
            "dedicated-worker validator must preserve storage/artifact summary marker: {marker}"
        );
    }

    let browser_check =
        read_file("tests/fixtures/dedicated-worker-consumer/scripts/check-browser-run.mjs");
    for marker in [
        "DEDICATED-WORKER-CONSUMER",
        "lane.browser.dedicated_worker.direct_runtime",
        "lane.browser.main_thread.direct_runtime",
        "lane.unsupported",
        "missing_webassembly",
        "candidate_lane_unhealthy",
        "candidate_prerequisite_missing",
        "prerequisite_loss_reason_code",
        "demotion_last_trigger",
        "demotion_demoted_to_lane_id",
        "demoted_health_last_trigger",
        "demoted_health_demoted_to_lane_id",
        "prerequisite_loss_health_demoted_to_lane_id",
        "fixture-handoff-complete",
        "graceful_shutdown_handoff",
        "shutdown_complete",
    ] {
        assert!(
            browser_check.contains(marker),
            "dedicated-worker browser-run checker must preserve marker: {marker}"
        );
    }

    let bundle_check =
        read_file("tests/fixtures/dedicated-worker-consumer/scripts/check-bundle.mjs");
    for marker in [
        "worker-runtime-selection-prerequisite-loss",
        "sawRuntimeSelectionPrerequisiteLossMarker",
    ] {
        assert!(
            bundle_check.contains(marker),
            "dedicated-worker bundle checker must preserve marker: {marker}"
        );
    }
}

#[test]
fn message_port_reactor_binding_exists_as_substrate() {
    // Evidence: src/runtime/reactor/browser.rs imports web_sys::MessagePort
    // and has register_message_port(). Not yet exposed in public packages.
    let reactor_src = read_file("src/runtime/reactor/browser.rs");
    assert!(
        reactor_src.contains("MessagePort"),
        "browser reactor must reference MessagePort"
    );
}

#[test]
fn broadcast_channel_reactor_binding_exists_as_substrate() {
    // Evidence: src/runtime/reactor/browser.rs imports
    // web_sys::BroadcastChannel and has register_broadcast_channel().
    let reactor_src = read_file("src/runtime/reactor/browser.rs");
    assert!(
        reactor_src.contains("BroadcastChannel"),
        "browser reactor must reference BroadcastChannel"
    );
}

#[test]
fn web_transport_is_capability_gated_in_public_packages() {
    // Evidence: src/io/cap.rs defines BrowserTransportKind::WebTransport
    // and the public JS packages now expose a guarded datagram lane.
    let cap_src = read_file("src/io/cap.rs");
    assert!(
        cap_src.contains("WebTransport"),
        "cap.rs must model WebTransport capability"
    );
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("detectWebTransportSupport")
            && browser_src.contains("openWebTransport")
            && browser_src.contains("WebTransportHandle"),
        "browser SDK must expose the capability-gated WebTransport lane"
    );
}

#[test]
fn web_transport_docs_name_fetch_and_websocket_fallbacks() {
    let wasm_doc = read_file("docs/WASM.md");
    assert!(
        wasm_doc.contains("fall back to `WebSocket` or `fetch`"),
        "docs/WASM.md must name WebSocket/fetch fallback for WebTransport"
    );

    let troubleshooting = read_file("docs/wasm_troubleshooting_compendium.md");
    assert!(
        troubleshooting.contains(
            "WebTransport reports unsupported/runtime-denied or session/datagram setup fails"
        ) && troubleshooting.contains("fall back to `WebSocket` or `fetch`"),
        "troubleshooting compendium must carry WebTransport fallback guidance"
    );
}

#[test]
fn browser_stream_bridge_exists_as_substrate() {
    // Evidence: src/io/browser_stream.rs bridges WHATWG
    // ReadableStream/WritableStream to Asupersync AsyncRead/AsyncWrite.
    assert!(
        file_exists("src/io/browser_stream.rs"),
        "browser stream bridge module must exist"
    );
    let stream_src = read_file("src/io/browser_stream.rs");
    assert!(
        stream_src.contains("ReadableStream") || stream_src.contains("readable_stream"),
        "browser stream bridge must reference ReadableStream"
    );
}

#[test]
fn browser_message_wrappers_use_non_clobbering_event_listeners() {
    let stream_src = read_file("src/io/browser_stream.rs");
    for marker in [
        "EventTarget",
        "attach_browser_message_listeners",
        "detach_browser_message_listeners",
        "add_event_listener_with_callback",
        "remove_event_listener_with_callback",
    ] {
        assert!(
            stream_src.contains(marker),
            "browser stream bridge must preserve non-clobbering listener marker: {marker}"
        );
    }

    for legacy in [
        "port.set_onmessage(Some(",
        "port.set_onmessageerror(Some(",
        "self.port.set_onmessage(None)",
        "self.port.set_onmessageerror(None)",
        "channel.set_onmessage(Some(",
        "channel.set_onmessageerror(Some(",
        "self.channel.set_onmessage(None)",
        "self.channel.set_onmessageerror(None)",
    ] {
        assert!(
            !stream_src.contains(legacy),
            "browser stream bridge wrappers must not clobber host handler slot: {legacy}"
        );
    }
}

#[test]
fn browser_reactor_message_bindings_use_non_clobbering_event_listeners() {
    let reactor_src = read_file("src/runtime/reactor/browser.rs");
    for marker in [
        "EventTarget",
        "attach_browser_message_listeners",
        "detach_browser_message_listeners",
        "add_event_listener_with_callback",
        "remove_event_listener_with_callback",
    ] {
        assert!(
            reactor_src.contains(marker),
            "browser reactor must preserve non-clobbering listener marker: {marker}"
        );
    }

    for legacy in [
        "port.set_onmessage(Some(",
        "port.set_onmessageerror(Some(",
        "self.port.set_onmessage(None)",
        "self.port.set_onmessageerror(None)",
        "channel.set_onmessage(Some(",
        "channel.set_onmessageerror(Some(",
        "self.channel.set_onmessage(None)",
        "self.channel.set_onmessageerror(None)",
    ] {
        assert!(
            !reactor_src.contains(legacy),
            "browser reactor bindings must not clobber host handler slot: {legacy}"
        );
    }
}

// ── Impossible for direct browser runtime ────────────────────────────

#[test]
fn raw_tcp_udp_is_impossible_for_browser() {
    // Evidence: src/net/tcp/ and src/net/udp/ are cfg-gated for native.
    // Browser networking is limited to fetch and WebSocket.
    assert!(
        file_exists("src/net/tcp/stream.rs"),
        "TCP stream module exists for native"
    );
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("No raw TCP/UDP") || doc.contains("Raw TCP/UDP"),
        "WASM docs must acknowledge TCP/UDP impossibility"
    );
}

#[test]
fn filesystem_is_impossible_for_browser() {
    // Evidence: src/fs/ modules are cfg-gated out on wasm32.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("No filesystem access") || doc.contains("filesystem"),
        "WASM docs must acknowledge filesystem impossibility"
    );
}

#[test]
fn process_signal_is_impossible_for_browser() {
    // Evidence: src/signal/ and process.rs are native-only.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("No process/signal") || doc.contains("process/signal"),
        "WASM docs must acknowledge process/signal impossibility"
    );
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 3: Live Contradictions / Mismatches
// ══════════════════════════════════════════════════════════════════════

#[test]
fn docs_wasm_md_has_authoritative_matrix_section() {
    // The support matrix in docs/WASM.md must be the canonical source.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("Authoritative Support Matrix"),
        "docs/WASM.md must contain the Authoritative Support Matrix section"
    );
}

#[test]
fn docs_wasm_md_classifies_indexeddb_accurately() {
    // IndexedDB has a real host backend and a public browser package surface.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("IndexedDB"),
        "docs/WASM.md must discuss IndexedDB classification"
    );
}

#[test]
fn docs_wasm_md_classifies_browser_artifact_persistence() {
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("BrowserArtifactStore")
            && doc.contains("exportArtifact()")
            && doc.contains("exportArchive()"),
        "docs/WASM.md must describe explicit browser artifact persistence/export flows"
    );
}

#[test]
fn docs_wasm_md_classifies_dedicated_worker_as_direct_runtime() {
    // Dedicated workers are direct-runtime supported.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("Dedicated Web Worker") || doc.contains("DedicatedWorkerGlobalScope"),
        "docs/WASM.md must classify dedicated workers"
    );
}

#[test]
fn execution_ladder_policy_pins_lane_ids_and_host_role_ordering() {
    let policy = read_json(".github/wasm_worker_offload_policy.json");
    let ladder = policy["execution_ladder"]
        .as_object()
        .expect("policy.execution_ladder must exist");
    assert_eq!(
        ladder["schema_version"].as_str(),
        Some("wasm-browser-execution-ladder-v1"),
        "execution ladder schema version must be pinned"
    );

    let lanes = ladder["lanes"].as_array().expect("execution_ladder.lanes");
    let lane_ids: Vec<&str> = lanes
        .iter()
        .map(|lane| lane["id"].as_str().expect("lane.id"))
        .collect();
    assert_eq!(
        lane_ids,
        vec![
            "lane.browser.main_thread.direct_runtime",
            "lane.browser.dedicated_worker.direct_runtime",
            "lane.next.server.bridge",
            "lane.next.edge.bridge",
            "lane.unsupported"
        ],
        "execution ladder must pin the stable lane ordering"
    );

    let host_roles = ladder["host_role_classification"]
        .as_array()
        .expect("execution_ladder.host_role_classification");
    let service_worker = host_roles
        .iter()
        .find(|entry| entry["id"].as_str() == Some("service_worker"))
        .expect("service_worker host role");
    assert_eq!(
        service_worker["support_class"].as_str(),
        Some("unsupported"),
        "service worker must fail closed in the current ladder"
    );
    assert_eq!(
        service_worker["default_reason_code"].as_str(),
        Some("service_worker_direct_runtime_not_shipped"),
        "service worker must carry the canonical policy-denial reason"
    );

    let next_server = host_roles
        .iter()
        .find(|entry| entry["id"].as_str() == Some("next_server"))
        .expect("next_server host role");
    let next_server_order: Vec<&str> = next_server["selection_order"]
        .as_array()
        .expect("next_server.selection_order")
        .iter()
        .map(|value| value.as_str().expect("selection_order entry"))
        .collect();
    assert_eq!(
        next_server_order,
        vec!["lane.next.server.bridge", "lane.unsupported"],
        "server hosts must downgrade to the explicit bridge lane before unsupported"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn execution_ladder_policy_pins_reason_codes_log_fields_and_non_goals() {
    let policy = read_json(".github/wasm_worker_offload_policy.json");
    let ladder = &policy["execution_ladder"];

    let reason_codes = ladder["reason_codes"]
        .as_object()
        .expect("execution_ladder.reason_codes");
    let downgrade_codes: Vec<&str> = reason_codes["downgrade"]
        .as_array()
        .expect("execution_ladder.reason_codes.downgrade")
        .iter()
        .map(|value| value.as_str().expect("downgrade reason"))
        .collect();
    assert!(
        downgrade_codes.contains(&"downgrade_to_server_bridge")
            && downgrade_codes.contains(&"downgrade_to_edge_bridge")
            && downgrade_codes.contains(&"downgrade_to_websocket_or_fetch")
            && downgrade_codes.contains(&"downgrade_to_export_bytes_for_download"),
        "execution ladder must pin stable downgrade reason codes"
    );

    assert!(
        reason_codes["health"]
            .as_array()
            .expect("execution_ladder.reason_codes.health")
            .iter()
            .map(|value| value.as_str().expect("health reason"))
            .any(|value| value == "demote_due_to_lane_health"),
        "execution ladder must pin lane-health demotion reason codes"
    );

    let log_fields: Vec<&str> = ladder["required_log_fields"]
        .as_array()
        .expect("execution_ladder.required_log_fields")
        .iter()
        .map(|value| value.as_str().expect("log field"))
        .collect();
    for field in [
        "lane_id",
        "lane_kind",
        "lane_rank",
        "host_role",
        "support_class",
        "reason_code",
        "fallback_lane_id",
        "lane_health_status",
        "lane_health_failure_count",
        "lane_health_retry_budget_remaining",
        "lane_health_cooldown_until_ms",
        "lane_health_last_trigger",
        "demoted_lane_id",
        "policy_schema_version",
        "repro_command",
    ] {
        assert!(
            log_fields.contains(&field),
            "execution ladder must require log field {field}"
        );
    }

    let lane_health = ladder["lane_health"]
        .as_object()
        .expect("execution_ladder.lane_health");
    assert_eq!(
        lane_health["demotion_behavior"].as_str(),
        Some("bounded_retry_then_fail_closed"),
        "lane-health policy must pin bounded retry before demotion"
    );
    assert_eq!(
        lane_health["demotion_fallback_lane_id"].as_str(),
        Some("lane.unsupported"),
        "lane-health demotion must fail closed to lane.unsupported"
    );
    assert_eq!(
        lane_health["default_policy"]["max_consecutive_failures"].as_u64(),
        Some(2),
        "lane-health default retry budget must stay pinned"
    );
    assert_eq!(
        lane_health["default_policy"]["cooldown_ms"].as_u64(),
        Some(30_000),
        "lane-health cooldown must stay pinned"
    );
    let triggers: Vec<&str> = lane_health["failure_triggers"]
        .as_array()
        .expect("execution_ladder.lane_health.failure_triggers")
        .iter()
        .map(|value| value.as_str().expect("lane-health trigger"))
        .collect();
    for trigger in [
        "runtime_init_failure",
        "worker_bootstrap_timeout",
        "worker_crash",
        "replay_integrity_failure",
        "prerequisite_drift",
        "overload_instability",
    ] {
        assert!(
            triggers.contains(&trigger),
            "execution ladder must preserve lane-health trigger {trigger}"
        );
    }

    let repro = &ladder["repro_command_convention"];
    assert_eq!(
        repro["format"].as_str(),
        Some(
            "pnpm --filter <package> test:e2e -- --lane <lane_id> --host-role <host_role> --reason <reason_code>"
        ),
        "execution ladder must pin the deterministic repro-command format"
    );

    let non_goals: Vec<&str> = ladder["explicit_non_goals"]
        .as_array()
        .expect("execution_ladder.explicit_non_goals")
        .iter()
        .map(|value| value.as_str().expect("non-goal"))
        .collect();
    for non_goal in [
        "service_worker_general_runtime_without_bounded_broker_contract",
        "shared_worker_general_runtime_without_tenancy_and_lifecycle_contract",
        "ambient_message_channel_promotion",
        "shared_array_buffer_multi_worker_default_lane",
        "raw_socket_filesystem_process_parity",
    ] {
        assert!(
            non_goals.contains(&non_goal),
            "execution ladder must preserve explicit non-goal {non_goal}"
        );
    }
}

#[test]
fn docs_wasm_md_pins_execution_ladder_contract_markers() {
    let doc = read_file("docs/WASM.md");
    for marker in [
        "### Execution Ladder Contract",
        "lane.browser.main_thread.direct_runtime",
        "lane.browser.dedicated_worker.direct_runtime",
        "lane.next.server.bridge",
        "lane.next.edge.bridge",
        "lane.unsupported",
        "candidate_host_role_mismatch",
        "candidate_prerequisite_missing",
        "candidate_lane_unhealthy",
        "demote_due_to_lane_health",
        "downgrade_to_server_bridge",
        "downgrade_to_edge_bridge",
        "downgrade_to_websocket_or_fetch",
        "downgrade_to_export_bytes_for_download",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
        "shared_array_buffer_requires_cross_origin_isolation",
        "lane_health_status",
        "lane_health_failure_count",
        "lane_health_retry_budget_remaining",
        "lane_health_cooldown_until_ms",
        "lane_health_last_trigger",
        "demoted_lane_id",
        "max_consecutive_failures=2",
        "cooldown_ms=30000",
        "runtime_init_failure",
        "worker_bootstrap_timeout",
        "worker_crash",
        "replay_integrity_failure",
        "prerequisite_drift",
        "overload_instability",
        "manual_reset",
        "pnpm --filter <package> test:e2e -- --lane <lane_id> --host-role <host_role> --reason <reason_code>",
        "service_worker_general_runtime_without_bounded_broker_contract",
        "shared_worker_general_runtime_without_tenancy_and_lifecycle_contract",
    ] {
        assert!(
            doc.contains(marker),
            "docs/WASM.md must preserve execution-ladder marker: {marker}"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 4: Contradictions Tracking
// ══════════════════════════════════════════════════════════════════════

/// This test encodes the known live mismatches between code, docs, and
/// packages as of 2026-03-15 (bead asupersync-1tte9). Each mismatch
/// should be resolved by follow-on beads, at which point the assertion
/// direction flips (from "contradiction exists" to "contradiction is
/// resolved").
#[test]
fn known_contradictions_are_tracked() {
    // Resolved contradiction 1: IndexedDB host backend is complete in Rust
    // and the public @asupersync/browser package now exposes BrowserStorage.
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        browser_src.contains("BrowserStorage")
            && browser_src.contains("detectBrowserStorageSupport"),
        "IndexedDB BrowserStorage surface should now be shipped"
    );

    // Boundary 2: the public SDK still must not turn generic browser-native
    // messaging into a broad surface area, but the bounded SharedWorker
    // coordinator lane is now allowed to name MessagePort explicitly.
    assert!(
        !browser_src.contains("BroadcastChannel"),
        "public browser SDK must not silently export BroadcastChannel"
    );
    assert!(
        browser_src.contains("BrowserSharedWorkerCoordinatorClient")
            && browser_src.contains("MessagePort"),
        "bounded shared-worker coordinator scaffolding may now name MessagePort explicitly"
    );

    // Resolved contradiction 3: localStorage host backend is now elevated
    // to an explicit package-level backend.
    assert!(
        browser_src.contains("localstorage") || browser_src.contains("localStorage"),
        "localStorage package surface should now be explicit"
    );

    // Contradiction 4: Browser stream bridge (ReadableStream/WritableStream
    // → AsyncRead/AsyncWrite) exists in Rust but has no public JS/TS API.
    assert!(
        !browser_src.contains("ReadableStream") && !browser_src.contains("WritableStream"),
        "When WHATWG stream bridges are shipped, update this test"
    );
}

#[test]
fn messaging_surfaces_remain_public_sdk_unshipped_but_explicitly_documented() {
    let browser_src = read_file("packages/browser/src/index.ts");
    assert!(
        !browser_src.contains("MessageChannel") && !browser_src.contains("BroadcastChannel"),
        "browser SDK must not silently export generic browser-native messaging APIs"
    );
    assert!(
        browser_src.contains("createBrowserSharedWorkerCoordinatorSelection(")
            && browser_src.contains("MessagePort"),
        "the bounded shared-worker coordinator helper may use MessagePort explicitly"
    );

    let wasm_doc = read_file("docs/WASM.md");
    for marker in [
        "Browser-native messaging surfaces (`MessageChannel`, `MessagePort`, `BroadcastChannel`)",
        "Direct-runtime feasible but not yet shipped as public Browser Edition APIs",
        "bootstrap a Browser Edition runtime inside a dedicated worker",
        "keep `MessageChannel` / `BroadcastChannel` at the application boundary",
        "use bridge-only adapters",
    ] {
        assert!(
            wasm_doc.contains(marker),
            "docs/WASM.md must preserve messaging boundary marker: {marker}"
        );
    }

    let census_doc = read_file("docs/wasm_api_surface_census.md");
    for marker in [
        "Browser-native messaging surfaces (`MessageChannel`, `MessagePort`, `BroadcastChannel`)",
        "Direct-runtime feasible substrate, not yet shipped as public Browser Edition APIs",
        "direct off-main-thread execution belongs in a dedicated worker runtime",
    ] {
        assert!(
            census_doc.contains(marker),
            "wasm_api_surface_census.md must preserve messaging boundary marker: {marker}"
        );
    }

    let troubleshooting = read_file("docs/wasm_troubleshooting_compendium.md");
    for marker in [
        "`MessageChannel` / `MessagePort` / `BroadcastChannel` expected as public Browser Edition APIs, but nothing is exported",
        "dedicated-worker direct-runtime support",
        "same-origin app coordination",
        "bridge-only adapters",
    ] {
        assert!(
            troubleshooting.contains(marker),
            "troubleshooting compendium must preserve messaging fallback marker: {marker}"
        );
    }
}

#[test]
fn messaging_host_bindings_have_targeted_error_path_coverage() {
    let reactor_src = read_file("src/runtime/reactor/browser.rs");
    for marker in [
        "browser_reactor_message_port_interest_validation_accepts_readable_and_error",
        "browser_reactor_message_port_interest_validation_rejects_empty_interest",
        "browser_reactor_broadcast_channel_interest_validation_rejects_writable_flags",
    ] {
        assert!(
            reactor_src.contains(marker),
            "browser reactor must preserve messaging coverage marker: {marker}"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 5: Framework Adapter Classification
// ══════════════════════════════════════════════════════════════════════

#[test]
fn react_adapter_enforces_client_rendered_only() {
    // Evidence: @asupersync/react rejects SSR / server-side rendering.
    assert!(
        file_exists("packages/react/src/index.ts"),
        "React adapter package must exist"
    );
}

#[test]
fn next_adapter_has_five_render_environments() {
    // Evidence: @asupersync/next classifies client_ssr, client_hydrated,
    // server_component, node_server, edge_runtime.
    let src = read_file("packages/next/src/index.ts");
    for env in [
        "client_ssr",
        "client_hydrated",
        "server_component",
        "node_server",
        "edge_runtime",
    ] {
        assert!(
            src.contains(env),
            "Next adapter must classify render environment: {env}"
        );
    }
}

#[test]
fn next_adapter_defers_until_hydrated_for_client_ssr() {
    let src = read_file("packages/next/src/index.ts");
    assert!(
        src.contains("defer_until_hydrated"),
        "Next adapter must offer defer_until_hydrated fallback"
    );
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 6: Cross-Doc Alignment (bead asupersync-2w5tu)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn docs_wasm_md_indexeddb_mentions_real_host_backend() {
    // After bead 2w5tu, docs/WASM.md must acknowledge that IndexedDB
    // has a real Rust host backend, not just policy/model layers.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("IndexedDbHostBackend") || doc.contains("host backend is complete"),
        "docs/WASM.md must acknowledge the real IndexedDB host backend"
    );
}

#[test]
fn docs_wasm_md_dedicated_worker_says_shipped() {
    // After bead 2w5tu, dedicated worker must say "Shipped" or equivalent,
    // not just "QA/examples are still catching up".
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("Shipped") && doc.contains("DedicatedWorkerGlobalScope"),
        "docs/WASM.md must clearly state dedicated worker is shipped"
    );
}

#[test]
fn census_doc_indexeddb_mentions_real_host_backend() {
    // The API surface census must reflect the real IndexedDB implementation.
    let doc = read_file("docs/wasm_api_surface_census.md");
    assert!(
        doc.contains("IndexedDbHostBackend") || doc.contains("host backend is complete"),
        "census doc must acknowledge IndexedDB host backend"
    );
}

#[test]
fn census_doc_mentions_browser_artifact_store() {
    let doc = read_file("docs/wasm_api_surface_census.md");
    assert!(
        doc.contains("BrowserArtifactStore")
            && doc.contains("exportArchive()")
            && doc.contains("downloadArtifact()"),
        "census doc must describe the explicit browser artifact persistence lane"
    );
}

#[test]
fn integration_doc_classifies_dedicated_worker_as_supported() {
    // integration.md must classify dedicated workers as supported.
    let doc = read_file("docs/integration.md");
    assert!(
        doc.contains("DedicatedWorkerGlobalScope") && doc.contains("supported"),
        "integration.md must classify dedicated workers as supported"
    );
}

// ══════════════════════════════════════════════════════════════════════
//  SECTION 7: Release-Blocking Boundary Guards (bead asupersync-g6uho.1)
//
//  These tests prevent silent boundary expansion. If a new direct-runtime
//  surface is added without deliberate bead work, these tests fail.
// ══════════════════════════════════════════════════════════════════════

#[test]
fn browser_sdk_support_classes_are_exactly_two() {
    // The browser SDK must only declare "direct_runtime_supported" and
    // "unsupported". Adding a new support class (e.g. "guarded") requires
    // deliberate bead work and updating this test.
    let src = read_file("packages/browser/src/index.ts");
    assert!(
        src.contains("\"direct_runtime_supported\"") && src.contains("\"unsupported\""),
        "browser SDK must declare exactly direct_runtime_supported and unsupported"
    );
    // Guard against silent addition of new support classes
    assert!(
        !src.contains("\"guarded\"") && !src.contains("\"bridge_only\""),
        "browser SDK must NOT silently add guarded or bridge_only support classes"
    );
}

#[test]
fn browser_sdk_runtime_contexts_preserve_explicit_service_and_shared_worker_hosts() {
    // The browser SDK now preserves explicit service_worker/shared_worker
    // runtime-context values for truthful fail-closed diagnostics while
    // keeping direct-runtime support limited to browser_main_thread and
    // dedicated_worker.
    let src = read_file("packages/browser/src/index.ts");
    let context_block = src
        .split("export type BrowserRuntimeContext =")
        .nth(1)
        .and_then(|tail| tail.split("export type BrowserRuntimeSupportReason =").next())
        .expect("browser src/index.ts must define BrowserRuntimeContext before BrowserRuntimeSupportReason");
    assert!(
        context_block.contains("\"browser_main_thread\"")
            && context_block.contains("\"dedicated_worker\"")
            && context_block.contains("\"service_worker\"")
            && context_block.contains("\"shared_worker\"")
            && context_block.contains("\"unknown\""),
        "browser SDK must preserve the full runtime-context taxonomy"
    );
    assert!(
        !context_block.contains("\"non_browser_or_unknown\""),
        "browser SDK must not confuse host-role labels with runtime-context labels"
    );
}

#[test]
fn browser_sdk_execution_ladder_surfaces_service_and_shared_worker_as_unavailable() {
    let src = read_file("packages/browser/src/index.ts");
    for marker in [
        "export type BrowserExecutionLane =",
        "\"shared_worker\"",
        "\"service_worker\"",
        "\"shared_worker_not_yet_shipped\"",
        "\"service_worker_not_yet_shipped\"",
        "@asupersync/browser does not yet ship direct runtime APIs for shared-worker hosts.",
        "@asupersync/browser does not yet ship direct runtime APIs for service-worker hosts.",
    ] {
        assert!(
            src.contains(marker),
            "browser SDK must explicitly preserve fail-closed execution-ladder marker: {marker}"
        );
    }
}

#[test]
fn browser_sdk_exposes_bounded_shared_worker_coordinator_scaffolding() {
    let src = read_file("packages/browser/src/index.ts");
    for marker in [
        "BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID",
        "BROWSER_SHARED_WORKER_COORDINATOR_LANE",
        "lane.browser.shared_worker.coordinator",
        "export function detectBrowserSharedWorkerCoordinatorSupport(",
        "export async function createBrowserSharedWorkerCoordinatorSelection(",
        "export class BrowserSharedWorkerCoordinatorClient",
        "direct BrowserRuntime creation remains fail-closed inside the shared-worker host",
    ] {
        assert!(
            src.contains(marker),
            "browser SDK must preserve bounded shared-worker coordinator marker: {marker}"
        );
    }
}

#[test]
fn browser_core_does_not_silently_add_new_host_bindings() {
    // browser-core must NOT add WebTransport, IndexedDB, or
    // SharedArrayBuffer host bindings without deliberate bead work.
    let src = read_file("asupersync-browser-core/src/lib.rs");
    assert!(
        !src.contains("WebTransport"),
        "browser-core must NOT silently add WebTransport host binding"
    );
    assert!(
        !src.contains("SharedArrayBuffer"),
        "browser-core must NOT silently add SharedArrayBuffer support"
    );
    // IndexedDB: the Rust host backend exists in browser_storage.rs,
    // but browser-core should not wire it without a deliberate bead.
    assert!(
        !src.contains("IndexedDB") && !src.contains("indexeddb"),
        "browser-core must NOT silently wire IndexedDB without deliberate bead"
    );
}

#[test]
fn next_adapter_support_classes_include_bridge_only() {
    // Next adapter must maintain bridge_only for server/edge targets.
    // Upgrading server/edge to direct_runtime would require deliberate work.
    let src = read_file("packages/next/src/index.ts");
    assert!(
        src.contains("bridge_only_server_target") && src.contains("bridge_only_edge_target"),
        "Next adapter must keep server/edge as bridge_only"
    );
}

#[test]
fn docs_wasm_md_has_admission_rule() {
    // The admission rule must exist so future contributors know how to
    // classify new browser surface requests.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("Maintainer Admission Rule"),
        "docs/WASM.md must contain the Maintainer Admission Rule section"
    );
    // Rule must reference the invariant gate
    assert!(
        doc.contains("structured concurrency") && doc.contains("cancellation"),
        "admission rule must reference core invariants"
    );
}

#[test]
fn docs_wasm_md_has_contract_test_pointer() {
    // docs/WASM.md must reference the contract test file so maintainers
    // know to update tests when they change the boundary.
    let doc = read_file("docs/WASM.md");
    assert!(
        doc.contains("wasm_browser_feasibility_matrix"),
        "docs/WASM.md must reference the contract test file"
    );
}
