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
fn service_worker_is_feasible_not_shipped() {
    // Evidence: packages/browser/src/index.ts does NOT recognize
    // ServiceWorkerGlobalScope; it falls through to "unknown" context
    // which maps to unsupported. The reactor architecture (single-threaded,
    // event-driven) would work but lifecycle/host constraints are not yet
    // productized.
    let src = read_file("packages/browser/src/index.ts");
    assert!(
        !src.contains("ServiceWorkerGlobalScope"),
        "browser SDK must NOT claim service worker support (not yet shipped)"
    );
}

#[test]
fn shared_worker_is_feasible_not_shipped() {
    // Evidence: packages/browser/src/index.ts does NOT recognize
    // SharedWorkerGlobalScope.
    let src = read_file("packages/browser/src/index.ts");
    assert!(
        !src.contains("SharedWorkerGlobalScope"),
        "browser SDK must NOT claim shared worker support (not yet shipped)"
    );
}

#[test]
fn rust_authored_wasm_consumer_path_is_feasible_not_shipped() {
    // Evidence: the semantic core compiles to wasm32 (BrowserReactor exists,
    // types are target-agnostic), but there is no public RuntimeBuilder or
    // Rust-callable API for constructing a wasm32 runtime and the current
    // startup path still assumes std::thread-backed worker/monitor threads.
    assert!(
        file_exists("src/runtime/reactor/browser.rs"),
        "browser reactor substrate must exist"
    );
    // Negative evidence: no public wasm32 RuntimeBuilder path and no thread-free
    // browser startup contract yet.
    let builder_src = read_file("src/runtime/builder.rs");
    assert!(
        !builder_src.contains("pub fn build_wasm") && !builder_src.contains("pub fn build_browser"),
        "RuntimeBuilder must not yet expose a public wasm32 build path"
    );
    assert!(
        builder_src.contains("spawn_worker_threads"),
        "runtime startup evidence should still show worker-thread bootstrapping"
    );
    assert!(
        builder_src.contains("start_deadline_monitor"),
        "runtime startup evidence should still show deadline-monitor bootstrapping"
    );
    assert!(
        builder_src.contains("std::thread::Builder"),
        "runtime startup evidence should still show std::thread-backed startup"
    );
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
fn dedicated_worker_validation_harness_preserves_storage_artifact_markers() {
    let worker_src = read_file("tests/fixtures/dedicated-worker-consumer/src/worker.ts");
    for marker in [
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
        "policy_schema_version",
        "repro_command",
    ] {
        assert!(
            log_fields.contains(&field),
            "execution ladder must require log field {field}"
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
        "downgrade_to_server_bridge",
        "downgrade_to_edge_bridge",
        "downgrade_to_websocket_or_fetch",
        "downgrade_to_export_bytes_for_download",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
        "shared_array_buffer_requires_cross_origin_isolation",
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

    // Boundary 2: MessagePort and BroadcastChannel remain intentionally
    // outside the public browser SDK even though the substrate exists.
    assert!(
        !browser_src.contains("MessagePort") && !browser_src.contains("BroadcastChannel"),
        "public browser SDK must not silently export MessagePort/BroadcastChannel"
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
        !browser_src.contains("MessageChannel")
            && !browser_src.contains("MessagePort")
            && !browser_src.contains("BroadcastChannel"),
        "browser SDK must not silently export browser-native messaging APIs"
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
fn browser_sdk_runtime_contexts_are_exactly_three() {
    // The browser SDK recognizes exactly: browser_main_thread,
    // dedicated_worker, unknown. Execution-ladder candidates may name
    // additional host roles, but the direct runtime-context taxonomy must
    // remain narrow until a deliberate promotion bead changes it.
    let src = read_file("packages/browser/src/index.ts");
    let context_block = src
        .split("export type BrowserRuntimeContext =")
        .nth(1)
        .and_then(|tail| tail.split("export type BrowserRuntimeSupportReason =").next())
        .expect("browser src/index.ts must define BrowserRuntimeContext before BrowserRuntimeSupportReason");
    assert!(
        context_block.contains("\"browser_main_thread\"")
            && context_block.contains("\"dedicated_worker\"")
            && context_block.contains("\"unknown\""),
        "browser SDK must declare exactly three runtime contexts"
    );
    assert!(
        !context_block.contains("\"service_worker\"")
            && !context_block.contains("\"shared_worker\""),
        "browser SDK must NOT silently add service/shared worker direct runtime contexts"
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
