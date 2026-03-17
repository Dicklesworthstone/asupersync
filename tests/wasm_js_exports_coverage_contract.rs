//! Contract tests for JS/TS exports, type declarations, module-resolution
//! entrypoints, and diagnostics semantics
//! (asupersync-3qv04.8.3.1, asupersync-3qv04.8.3.2).
//!
//! Validates that the published package entrypoints look correct from the
//! perspective of JavaScript and TypeScript consumers before heavier
//! consumer-app validation starts.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_pkg(pkg: &str) -> serde_json::Value {
    let path = repo_root().join("packages").join(pkg).join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}

fn read_source(path: &str) -> String {
    let path = repo_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))
}

fn read_json(path: &str) -> serde_json::Value {
    let path = repo_root().join(path);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).unwrap_or_else(|_| panic!("invalid JSON {}", path.display()))
}

// ── Export Map Structure ─────────────────────────────────────────────

#[test]
fn browser_core_exports_have_conditional_root_with_three_conditions() {
    let v = read_pkg("browser-core");
    let root = v["exports"]["."].as_object().expect("root must be object");
    assert!(root.contains_key("types"), "root export missing 'types'");
    assert!(root.contains_key("import"), "root export missing 'import'");
    assert!(
        root.contains_key("default"),
        "root export missing 'default'"
    );
}

#[test]
fn browser_core_types_export_is_separate_subpath() {
    let v = read_pkg("browser-core");
    let exports = v["exports"].as_object().unwrap();
    assert!(
        exports.contains_key("./types"),
        "browser-core must export ./types subpath for type-only imports"
    );
    let types_export = exports["./types"].as_object().unwrap();
    assert!(
        types_export.contains_key("types"),
        "./types export must have types condition"
    );
}

#[test]
fn browser_exports_tracing_subpath() {
    let v = read_pkg("browser");
    let exports = v["exports"].as_object().unwrap();
    if exports.contains_key("./tracing") {
        let tracing = exports["./tracing"].as_object().unwrap();
        assert!(
            tracing.contains_key("types"),
            "./tracing export must have types condition"
        );
        assert!(
            tracing.contains_key("import") || tracing.contains_key("default"),
            "./tracing export must have import or default condition"
        );
    }
    // ./tracing is optional; test passes if absent
}

#[test]
fn no_package_exports_package_json_subpath() {
    // Consumers should not be able to deep-import package.json
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let exports = v["exports"].as_object().unwrap();
        assert!(
            !exports.contains_key("./package.json"),
            "{pkg} must not export ./package.json (prevents accidental dependency on internals)"
        );
    }
}

// ── Type Declaration Consistency ─────────────────────────────────────

#[test]
fn top_level_types_field_matches_exports_types() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let top_types = v["types"].as_str().unwrap();
        let export_types = v["exports"]["."]["types"].as_str().unwrap();
        assert_eq!(
            top_types, export_types,
            "{pkg}: top-level 'types' ({top_types}) must match exports[\".\"].types ({export_types})"
        );
    }
}

#[test]
fn browser_core_types_file_listed_in_files_array() {
    let v = read_pkg("browser-core");
    let types_path = v["types"].as_str().unwrap().trim_start_matches("./");
    let has_types_path = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .any(|x| x == types_path);
    assert!(
        has_types_path,
        "browser-core types file {types_path} not in files array"
    );
}

#[test]
fn higher_level_packages_types_in_dist() {
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg(pkg);
        let types = v["types"].as_str().unwrap();
        assert!(
            types.starts_with("./dist/"),
            "{pkg} types must be in dist/, got {types}"
        );
        assert!(
            types.ends_with(".d.ts"),
            "{pkg} types must end with .d.ts, got {types}"
        );
    }
}

// ── Module Resolution Patterns ───────────────────────────────────────

#[test]
fn all_packages_are_esm_with_module_field() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        assert_eq!(v["type"].as_str().unwrap(), "module", "{pkg} must be ESM");
        // module field should match main for ESM packages
        let main = v["main"].as_str().unwrap();
        let module = v["module"].as_str().unwrap_or(main);
        assert_eq!(
            main, module,
            "{pkg}: main and module should match for pure ESM packages"
        );
    }
}

#[test]
fn browser_core_main_is_js_not_wasm() {
    let v = read_pkg("browser-core");
    let main = v["main"].as_str().unwrap();
    assert!(
        std::path::Path::new(main)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("js")),
        "browser-core main must be .js (not .wasm), got {main}"
    );
}

#[test]
fn higher_level_main_points_to_dist_index() {
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg(pkg);
        let main = v["main"].as_str().unwrap();
        assert!(
            main.starts_with("./dist/")
                && std::path::Path::new(main)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("js")),
            "{pkg} main must be ./dist/*.js, got {main}"
        );
    }
}

// ── Source File Presence for Higher-Level Packages ────────────────────

#[test]
fn browser_src_index_exports_from_browser_core() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser-core"),
        "browser src/index.ts must import from @asupersync/browser-core"
    );
}

#[test]
fn browser_src_index_defines_high_level_sdk_wrappers() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "export class BrowserRuntime",
        "export class RegionHandle",
        "export class TaskHandle",
        "export class BrowserArtifactStore",
        "export class BrowserStorage",
        "export class WebTransportHandle",
        "export class CancellationToken",
        "export function createBrowserArtifactOperationError",
        "export function createBrowserArtifactDownloadUnsupportedError",
        "export function createBrowserArtifactStore",
        "export function detectBrowserStorageSupport",
        "export function createBrowserStorageUnsupportedError",
        "export function createBrowserStorageOperationError",
        "export function createBrowserStorage",
        "export function createCancellationToken",
        "export async function createBrowserRuntime",
        "export async function createBrowserScope",
        "export function createBrowserSdkDiagnostics",
        "export function detectWebTransportSupport",
        "export function createWebTransportUnsupportedError",
        "export function assertWebTransportSupport",
        "export function unwrapOutcome",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must define marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_exposes_no_throw_selection_helpers() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "export interface BrowserRuntimeSelectionResult",
        "export interface BrowserScopeSelectionResult",
        "executionLadder: BrowserExecutionLadderDiagnostics;",
        "runtime: BrowserRuntime | null;",
        "scope: RegionHandle | null;",
        "export async function createBrowserRuntimeSelection",
        "export async function createBrowserScopeSelection",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve no-throw selection marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_exposes_browser_artifact_persistence_lane() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "export type BrowserArtifactKind = \"trace\" | \"crashpack\" | \"evidence\" | \"custom\";",
        "quotaStrategy: \"evict_oldest\" | \"fail\";",
        "export class BrowserArtifactStore",
        "async persistTraceRecord(",
        "async persistCrashArtifact(",
        "async persistEvidenceArtifact(",
        "async exportArchive(): Promise<BrowserArtifactArchiveExport>",
        "async downloadArtifact(id: string): Promise<BrowserArtifactExport>",
        "async downloadArchive(): Promise<BrowserArtifactArchiveExport>",
        "browser artifact downloads require a browser main-thread document; use exportArtifact() in workers",
        "export function createBrowserArtifactStore(",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve BrowserArtifactStore marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_exposes_storage_and_artifact_diagnostics() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "ASUPERSYNC_BROWSER_STORAGE_UNSUPPORTED",
        "ASUPERSYNC_BROWSER_STORAGE_OPERATION_FAILED",
        "ASUPERSYNC_BROWSER_ARTIFACT_OPERATION_FAILED",
        "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED",
        "\"quota_exceeded\"",
        "\"corrupt_index\"",
        "\"download_unavailable\"",
        "retentionPolicy(): BrowserArtifactRetentionPolicy",
        "async listArtifacts(): Promise<BrowserArtifactRecord[]>",
        "async deleteArtifact(id: string): Promise<boolean>",
        "async clearArtifacts(): Promise<number>",
        "Use exportArtifact() or exportArchive() in dedicated workers or non-DOM runtimes, then hand the bytes to a browser main-thread UI for download.",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve storage/artifact diagnostics marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_exposes_browser_storage_lane() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "hasIndexedDb: browserIndexedDbFactory(globalObject) !== null",
        "hasLocalStorage: browserLocalStorage(globalObject) !== null",
        "export type BrowserStorageBackend = \"indexeddb\" | \"localstorage\";",
        "export class BrowserStorage",
        "async listKeys(namespace: string): Promise<string[]>",
        "async clearNamespace(namespace: string): Promise<number>",
        "case \"blocked_upgrade\":",
        "case \"quota_exceeded\":",
        "IndexedDB open blocked by another connection",
        "localStorage is unavailable in this browser/runtime.",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve BrowserStorage marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_exposes_capability_gated_webtransport_lane() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "hasWebTransport: typeof globalObject?.WebTransport === \"function\"",
        "openWebTransport(",
        "sendDatagram(",
        "recvDatagram(",
        "WebTransport is unavailable in this browser/runtime.",
        "Use WebSocket or fetch when WebTransport support is unavailable.",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve WebTransport marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_preserves_low_level_aliases_for_core_surface() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "CoreRuntimeHandle",
        "CoreRegionHandle",
        "CoreTaskHandle",
        "CoreCancellationToken",
        "webtransportCancel,",
        "@asupersync/browser-core/abi-metadata.json",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve core alias marker: {marker}"
        );
    }
}

#[test]
fn browser_dist_index_preserves_low_level_aliases_for_core_surface() {
    let js_path = repo_root().join("packages/browser/dist/index.js");
    let dts_path = repo_root().join("packages/browser/dist/index.d.ts");
    if !js_path.exists() || !dts_path.exists() {
        return;
    }
    let js = std::fs::read_to_string(&js_path)
        .unwrap_or_else(|_| panic!("missing {}", js_path.display()));
    let dts = std::fs::read_to_string(&dts_path)
        .unwrap_or_else(|_| panic!("missing {}", dts_path.display()));
    for marker in [
        "webtransportCancel,",
        "webtransportClose,",
        "webtransportOpen,",
    ] {
        assert!(
            js.contains(marker),
            "browser dist/index.js must preserve core alias marker: {marker}"
        );
        assert!(
            dts.contains(marker),
            "browser dist/index.d.ts must preserve core alias marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_preserves_webtransport_cleanup_order() {
    let content = read_source("packages/browser/src/index.ts");

    assert!(
        content.contains("const ready = Promise.all([reader, writer]).then(() => undefined);"),
        "WebTransport readiness must wait for datagram reader/writer acquisition"
    );

    let reader_cancel = content
        .find("reader.cancel?.(reason)")
        .expect("reader cleanup must cancel before releasing the lock");
    let reader_release = content
        .find("reader.releaseLock?.();")
        .expect("reader cleanup must release the lock");
    assert!(
        reader_cancel < reader_release,
        "reader cleanup must cancel before releasing the lock"
    );

    let writer_abort = content
        .find("writer.abort?.(reason)")
        .expect("writer cleanup must abort with a reason before releasing the lock");
    let writer_close = content
        .find("writer.close?.()")
        .expect("writer cleanup must close without a reason before releasing the lock");
    let writer_release = content
        .find("writer.releaseLock?.();")
        .expect("writer cleanup must release the lock");
    assert!(
        writer_abort < writer_release && writer_close < writer_release,
        "writer cleanup must close or abort before releasing the lock"
    );
}

#[test]
fn browser_src_index_threads_runtime_reference_through_scope_handles() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "readonly runtime: BrowserRuntime | null = null",
        "new RegionHandle(entered.value, consumerVersion, this)",
        "new RegionHandle(entered.value, consumerVersion, this.runtime)",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve runtime-threading marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_defines_unsupported_runtime_diagnostics() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "export interface BrowserRuntimeSupportDiagnostics",
        "export function detectBrowserRuntimeSupport",
        "export function createUnsupportedRuntimeError",
        "export function assertBrowserRuntimeSupport",
        "ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME",
        "browser main-thread or dedicated-worker boundaries",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must define unsupported-runtime marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_pins_runtime_support_taxonomy_and_capabilities() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "export type BrowserRuntimeSupportClass =",
        "\"direct_runtime_supported\"",
        "\"unsupported\"",
        "export type BrowserRuntimeContext =",
        "\"browser_main_thread\"",
        "\"dedicated_worker\"",
        "\"unknown\"",
        "\"missing_global_this\"",
        "\"service_worker_not_yet_shipped\"",
        "\"shared_worker_not_yet_shipped\"",
        "\"unsupported_runtime_context\"",
        "\"missing_webassembly\"",
        "\"supported\"",
        "\"[object DedicatedWorkerGlobalScope]\"",
        "skipWaiting",
        "\"onconnect\" in globalObject",
        "hasAbortController",
        "hasDocument",
        "hasFetch",
        "hasWebAssembly",
        "hasWebSocket",
        "hasWindow",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must pin runtime-support taxonomy/capability marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_requires_actionable_guidance_and_structured_error_payloads() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "Load @asupersync/browser only in browser main-thread or dedicated-worker boundaries.",
        "prefer @asupersync/next bridge-only adapters instead of direct BrowserRuntime creation.",
        "Move BrowserRuntime creation into a browser main-thread entrypoint or a dedicated worker bootstrap module.",
        "Use a browser/runtime with WebAssembly enabled before initializing Browser Edition.",
        "@asupersync/browser does not yet ship direct runtime APIs for service-worker hosts.",
        "@asupersync/browser does not yet ship direct runtime APIs for shared-worker hosts.",
        "Use a dedicated worker bootstrap today if you need shipped direct Browser Edition execution.",
        "Keep service-worker orchestration at the application boundary until this host is promoted.",
        "Keep shared-worker coordination at the application boundary until this host is promoted.",
        "supportClass: \"unsupported\"",
        "supportClass: \"direct_runtime_supported\"",
        "@asupersync/browser dedicated-worker runtime prerequisites are available.",
        "@asupersync/browser browser main-thread runtime prerequisites are available.",
        "error.code = BROWSER_UNSUPPORTED_RUNTIME_CODE;",
        "error.diagnostics = diagnostics;",
        "`${diagnostics.packageName}: ${diagnostics.message} ${diagnostics.guidance.join(\" \")}`",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve actionable diagnostic marker: {marker}"
        );
    }
    assert_eq!(
        content.matches("assertBrowserRuntimeSupport();").count(),
        1,
        "browser scope entry should keep a fail-fast unsupported-runtime guard while the no-throw selection helpers stay additive"
    );
}

#[test]
fn browser_core_fetch_bridge_supports_window_or_worker_hosts() {
    let content = read_source("asupersync-browser-core/src/lib.rs");
    for marker in [
        "WorkerGlobalScope",
        "web_sys::window()",
        "js_sys::global().dyn_into::<WorkerGlobalScope>()",
        "window.fetch_with_str_and_init(url, init)",
        "worker.fetch_with_str_and_init(url, init)",
        "window or WorkerGlobalScope fetch host is not available in this host context",
    ] {
        assert!(
            content.contains(marker),
            "browser-core src/lib.rs must preserve worker fetch-host marker: {marker}"
        );
    }
}

#[test]
fn browser_core_package_exposes_low_level_webtransport_surface() {
    let content = read_source("packages/browser-core/index.js");
    for marker in [
        "const INFLIGHT_WEBTRANSPORTS = new Map();",
        "openWebTransport(url, options = undefined, consumerVersion = null)",
        "export function webtransport_open(",
        "export function webtransport_send(",
        "export function webtransport_recv(",
        "export function webtransport_close(",
        "export function webtransport_cancel(",
        "export const webtransportOpen = webtransport_open;",
        "export const webtransportSend = webtransport_send;",
        "export const webtransportRecv = webtransport_recv;",
        "export const webtransportClose = webtransport_close;",
        "export const webtransportCancel = webtransport_cancel;",
    ] {
        assert!(
            content.contains(marker),
            "browser-core package must preserve WebTransport export marker: {marker}"
        );
    }
}

#[test]
fn browser_core_webtransport_terminal_paths_close_and_retire_host_state() {
    let content = read_source("packages/browser-core/index.js");
    for marker in [
        "function isTerminalOutcome(outcome) {",
        "\"read_closed\",",
        "\"read_failure\",",
        "\"session_closed_error\",",
        "closeHostWebTransportState(state, closeReason);",
        "closeHostWebTransportState(state, reason);",
        "if (isTerminalOutcome(result)) {",
        "INFLIGHT_WEBTRANSPORTS.delete(sessionKey);",
    ] {
        assert!(
            content.contains(marker),
            "browser-core WebTransport cleanup marker missing: {marker}"
        );
    }
}

#[test]
fn browser_core_types_declare_webtransport_requests_and_exports() {
    let content = read_source("packages/browser-core/index.d.ts");
    for marker in [
        "export interface WebTransportOpenRequest",
        "export interface WebTransportSendRequest",
        "export interface WebTransportRecvRequest",
        "export interface WebTransportCloseRequest",
        "export interface WebTransportCancelRequest",
        "openWebTransport(",
        "export declare function webtransport_open(",
        "export declare function webtransport_send(",
        "export declare function webtransport_recv(",
        "export declare function webtransport_close(",
        "export declare function webtransport_cancel(",
        "export declare const webtransportOpen: typeof webtransport_open;",
        "export declare const webtransportSend: typeof webtransport_send;",
        "export declare const webtransportRecv: typeof webtransport_recv;",
        "export declare const webtransportClose: typeof webtransport_close;",
        "export declare const webtransportCancel: typeof webtransport_cancel;",
    ] {
        assert!(
            content.contains(marker),
            "browser-core types must preserve WebTransport marker: {marker}"
        );
    }
}

#[test]
fn react_src_index_exports_from_browser() {
    let path = repo_root().join("packages/react/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser"),
        "react src/index.ts must import from @asupersync/browser"
    );
}

#[test]
fn react_src_index_defines_runtime_support_helpers() {
    let path = repo_root().join("packages/react/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "export interface ReactRuntimeSupportDiagnostics",
        "export function detectReactRuntimeSupport",
        "export function createReactUnsupportedRuntimeError",
        "export function assertReactRuntimeSupport",
        "ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME",
    ] {
        assert!(
            content.contains(marker),
            "react src/index.ts must define runtime-support marker: {marker}"
        );
    }
}

#[test]
fn react_src_index_keeps_package_specific_guidance_and_error_identity() {
    let content = read_source("packages/react/src/index.ts");
    for marker in [
        "packageName: \"@asupersync/react\"",
        "Use @asupersync/react from client-rendered React trees only.",
        "error.code = REACT_UNSUPPORTED_RUNTIME_CODE;",
        "error.diagnostics = diagnostics;",
        "throw createReactUnsupportedRuntimeError(diagnostics);",
    ] {
        assert!(
            content.contains(marker),
            "react src/index.ts must preserve package-specific diagnostic marker: {marker}"
        );
    }
    assert!(
        !content.contains("assertBrowserRuntimeSupport(diagnostics);"),
        "react runtime-support assertion must throw the react-specific error, not defer to browser assertion"
    );
}

#[test]
fn next_src_index_exports_from_browser() {
    let path = repo_root().join("packages/next/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser"),
        "next src/index.ts must import from @asupersync/browser"
    );
}

#[test]
fn next_src_index_defines_runtime_support_helpers() {
    let path = repo_root().join("packages/next/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "export type NextRuntimeTarget",
        "export interface NextRuntimeSupportDiagnostics",
        "export function detectNextRuntimeSupport",
        "export function createNextUnsupportedRuntimeError",
        "export function assertNextRuntimeSupport",
        "ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must define runtime-support marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_pins_client_server_and_edge_runtime_guidance() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export type NextRuntimeTarget = \"client\" | \"server\" | \"edge\";",
        "export type NextRuntimeSupportReason =",
        "export type NextRuntimeSupportClass =",
        "target !== \"client\"",
        "supportClass: \"bridge_only\"",
        "\"bridge_only_server_target\"",
        "\"bridge_only_edge_target\"",
        "Next server runtimes are bridge-only for direct Browser Edition execution.",
        "Next edge runtimes are bridge-only for direct Browser Edition execution.",
        "Move BrowserRuntime creation into a client component or browser-only module.",
        "Use the Next server bridge helpers to serialize work across the server/browser boundary.",
        "Use the Next edge bridge helpers to serialize work across the edge/browser boundary.",
        "Import @asupersync/next from client components only.",
        "error.code = NEXT_UNSUPPORTED_RUNTIME_CODE;",
        "error.diagnostics = diagnostics;",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must preserve runtime-target diagnostic marker: {marker}"
        );
    }
}

#[test]
fn wasm_docs_pin_authoritative_support_matrix_and_diagnostic_taxonomy() {
    let content = read_source("docs/WASM.md");
    for marker in [
        "## Authoritative Support Matrix (live tree)",
        "`supportClass: \"direct_runtime_supported\" | \"unsupported\"`",
        "`runtimeContext: \"browser_main_thread\" | \"dedicated_worker\" | \"unknown\"`",
        "`supportClass: \"bridge_only\"`",
        "| Browser main thread (`window` + `document` + `WebAssembly`) | Direct-runtime supported |",
        "| Dedicated Web Worker (`DedicatedWorkerGlobalScope`) | Direct-runtime supported |",
        "| Node / SSR / edge direct runtime via `@asupersync/browser` | Impossible for direct browser runtime; bridge-only or unsupported |",
        "| Rust-authored `wasm32-unknown-unknown` consumer path | Direct-runtime feasible but not yet shipped |",
        "| Multi-worker / `SharedArrayBuffer` parallel execution | Guarded optional, not shipped |",
    ] {
        assert!(
            content.contains(marker),
            "docs/WASM.md must preserve authoritative browser-matrix marker: {marker}"
        );
    }
}

#[test]
fn wasm_docs_pin_execution_ladder_alias_mapping_and_required_fields() {
    let content = read_source("docs/WASM.md");
    for marker in [
        "### Execution Ladder Contract",
        "| `service_worker_not_yet_shipped` | `service_worker_direct_runtime_not_shipped` |",
        "| `shared_worker_not_yet_shipped` | `shared_worker_direct_runtime_not_shipped` |",
        "| `bridge_only_server_target` | `downgrade_to_server_bridge` |",
        "| `bridge_only_edge_target` | `downgrade_to_edge_bridge` |",
        "`lane_id`",
        "`lane_kind`",
        "`lane_rank`",
        "`host_role`",
        "`support_class`",
        "`reason_code`",
        "`fallback_lane_id`",
        "`lane_health_status`",
        "`lane_health_failure_count`",
        "`lane_health_retry_budget_remaining`",
        "`lane_health_cooldown_until_ms`",
        "`lane_health_last_trigger`",
        "`demoted_lane_id`",
        "`candidate_lane_unhealthy`",
        "`demote_due_to_lane_health`",
        "`max_consecutive_failures=2`",
        "`cooldown_ms=30000`",
        "`runtime_init_failure`",
        "`worker_bootstrap_timeout`",
        "`worker_crash`",
        "`replay_integrity_failure`",
        "`prerequisite_drift`",
        "`overload_instability`",
        "`manual_reset`",
        "`policy_schema_version`",
        "`repro_command`",
        "`--lane`",
        "`--host-role`",
        "`--reason`",
    ] {
        assert!(
            content.contains(marker),
            "docs/WASM.md must preserve execution-ladder diagnostic marker: {marker}"
        );
    }
}

#[test]
fn wasm_worker_policy_pins_execution_ladder_aliases_and_repro_tokens() {
    let policy = read_json(".github/wasm_worker_offload_policy.json");
    let ladder = &policy["execution_ladder"];
    assert_eq!(
        ladder["schema_version"].as_str(),
        Some("wasm-browser-execution-ladder-v1"),
        "policy must pin execution ladder schema version"
    );

    let aliases = ladder["current_package_reason_aliases"]
        .as_object()
        .expect("execution_ladder.current_package_reason_aliases");
    let expected_aliases = [
        (
            "service_worker_not_yet_shipped",
            "service_worker_direct_runtime_not_shipped",
        ),
        (
            "shared_worker_not_yet_shipped",
            "shared_worker_direct_runtime_not_shipped",
        ),
        ("bridge_only_server_target", "downgrade_to_server_bridge"),
        ("bridge_only_edge_target", "downgrade_to_edge_bridge"),
    ];
    for (from, to) in expected_aliases {
        assert_eq!(
            aliases.get(from).and_then(serde_json::Value::as_str),
            Some(to),
            "execution ladder alias mapping must pin {from} -> {to}"
        );
    }

    let health_codes: Vec<&str> = ladder["reason_codes"]["health"]
        .as_array()
        .expect("execution_ladder.reason_codes.health")
        .iter()
        .map(|value| value.as_str().expect("health code"))
        .collect();
    assert_eq!(
        health_codes,
        vec!["demote_due_to_lane_health"],
        "execution ladder must pin the lane-health demotion reason code"
    );

    let lane_health = ladder["lane_health"]
        .as_object()
        .expect("execution_ladder.lane_health");
    assert_eq!(
        lane_health["demotion_behavior"].as_str(),
        Some("bounded_retry_then_fail_closed"),
        "policy must pin bounded retry before fail-closed demotion"
    );
    assert_eq!(
        lane_health["default_policy"]["max_consecutive_failures"].as_u64(),
        Some(2),
        "policy must pin lane-health retry budget"
    );
    assert_eq!(
        lane_health["default_policy"]["cooldown_ms"].as_u64(),
        Some(30_000),
        "policy must pin lane-health cooldown"
    );

    let repro = ladder["repro_command_convention"]
        .as_object()
        .expect("execution_ladder.repro_command_convention");
    let must_include: Vec<&str> = repro["must_include_tokens"]
        .as_array()
        .expect("repro_command_convention.must_include_tokens")
        .iter()
        .map(|value| value.as_str().expect("repro token"))
        .collect();
    assert_eq!(
        must_include,
        vec!["--lane", "--host-role", "--reason"],
        "execution ladder must pin deterministic repro-command tokens"
    );
}

#[test]
fn browser_src_index_exports_lane_health_control_plane_markers() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "export type BrowserLaneHealthStatus =",
        "export type BrowserLaneHealthTrigger =",
        "export interface BrowserLaneHealthPolicy",
        "export interface BrowserLaneHealthDiagnostics",
        "\"candidate_lane_unhealthy\"",
        "\"demote_due_to_lane_health\"",
        "export function inspectBrowserLaneHealth",
        "export function reportBrowserLaneUnhealthy",
        "export function resetBrowserLaneHealth",
        "laneAvailabilityOutcome(",
        "reportLaneUnhealthy(",
        "resetLaneHealth(",
        "lane_health_status=",
        "failure_count=",
        "retry_budget_remaining=",
        "cooldown_until_ms=",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve lane-health marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_defines_client_bootstrap_adapter_surface() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export type NextBootstrapPhase",
        "export type NextRenderEnvironment",
        "export type NextNavigationType",
        "export type NextBootstrapRecoveryAction",
        "export interface NextBootstrapSnapshot",
        "export interface NextBootstrapLogEvent",
        "export interface NextClientBootstrapOptions",
        "export function createNextBootstrapLogFields",
        "export class NextClientBootstrapAdapter",
        "async initializeRuntime()",
        "async ensureRuntimeReady()",
        "async hydrateAndInitialize()",
        "export function createNextBootstrapAdapter",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must define bootstrap-adapter marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_pins_bootstrap_lifecycle_and_invalidation_markers() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "\"server_rendered\"",
        "\"hydrating\"",
        "\"hydrated\"",
        "\"runtime_ready\"",
        "\"runtime_failed\"",
        "\"soft_navigation\"",
        "\"hard_navigation\"",
        "\"popstate\"",
        "\"reset_to_hydrating\"",
        "\"retry_runtime_init\"",
        "cache_revalidation_scope_reset",
        "hard_navigation_scope_reset",
        "hot_reload_scope_reset",
        "scopeInvalidationCount",
        "runtimeReinitRequiredCount",
        "activeScopeGeneration",
        "lastInvalidatedScopeGeneration",
        "boundary_mode: \"client\"",
        "cache_revalidation_count",
        "scope_invalidation_count",
        "runtime_reinit_required_count",
        "active_scope_generation",
        "last_invalidated_scope_generation",
        "navigation_count",
        "wasm_module_loaded",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must preserve lifecycle/invalidation marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_defines_server_bridge_adapter_surface() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export type NextBoundaryMode",
        "export type NextRuntimeFallback",
        "export type NextServerBridgeEnvironment",
        "export type NextBridgeValue",
        "export interface NextServerBridgeDiagnostics",
        "export interface NextServerBridgeRequest",
        "export interface NextServerBridgeResponse",
        "export interface NextServerBridgeAdapterOptions",
        "export interface NextServerBridgeResponseError",
        "export function nextBoundaryModeForEnvironment",
        "export function nextRuntimeFallbackForEnvironment",
        "export function nextRuntimeFallbackReason",
        "export function createNextServerBridgeDiagnostics",
        "export function createNextBridgeLogFields",
        "export function createNextServerBridgeResponseFromOutcome",
        "export function unwrapNextServerBridgeResponse",
        "export class NextServerBridgeAdapter",
        "fromOutcome(",
        "unwrapResponse(",
        "export function createNextServerBridgeAdapter",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must define server-bridge marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_defines_edge_bridge_adapter_surface() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export type NextEdgeBridgeEnvironment",
        "export interface NextEdgeBridgeDiagnostics",
        "export interface NextEdgeBridgeRequest",
        "export interface NextEdgeBridgeResponse",
        "export interface NextEdgeBridgeAdapterOptions",
        "export interface NextEdgeBridgeResponseError",
        "export function createNextEdgeBridgeDiagnostics",
        "export function createNextEdgeBridgeResponseFromOutcome",
        "export function unwrapNextEdgeBridgeResponse",
        "export class NextEdgeBridgeAdapter",
        "fromOutcome(",
        "unwrapResponse(",
        "export function createNextEdgeBridgeAdapter",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must define edge-bridge marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_pins_server_bridge_policy_and_diagnostics_markers() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "\"server_component\"",
        "\"node_server\"",
        "\"use_server_bridge\"",
        "\"use_edge_bridge\"",
        "\"explicit_status\"",
        "\"panicked\"",
        "runtime unavailable in server boundary: route through serialized node/server bridge",
        "boundary_mode: diagnostics.boundaryMode",
        "render_environment: diagnostics.renderEnvironment",
        "runtime_fallback: diagnostics.runtimeFallback",
        "repro_command: diagnostics.reproCommand",
        "NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE",
        "createNextUnsupportedRuntimeError(",
        "bridgeDiagnostics",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must preserve server-bridge marker: {marker}"
        );
    }
}

#[test]
fn next_src_index_pins_edge_bridge_policy_and_diagnostics_markers() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "\"edge_runtime\"",
        "\"use_edge_bridge\"",
        "runtime unavailable in edge boundary: route through serialized edge bridge",
        "target: \"edge\"",
        "boundaryMode: \"edge\"",
        "renderEnvironment: NextEdgeBridgeEnvironment",
        "runtimeFallback: \"use_edge_bridge\"",
        "const runtimeSupport = detectNextRuntimeSupport(\"edge\");",
        "boundary_mode: diagnostics.boundaryMode",
        "render_environment: diagnostics.renderEnvironment",
        "runtime_fallback: diagnostics.runtimeFallback",
        "repro_command: diagnostics.reproCommand",
        "NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE",
        "bridgeDiagnostics",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must preserve edge-bridge marker: {marker}"
        );
    }
}

// ── TypeScript Config for Resolution ─────────────────────────────────

#[test]
fn browser_core_tsconfig_uses_composite() {
    let path = repo_root().join("packages/browser-core/tsconfig.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        v["compilerOptions"]["composite"], true,
        "browser-core tsconfig must enable composite for project references"
    );
}

#[test]
fn higher_level_tsconfigs_reference_dependencies() {
    let browser_ts = repo_root().join("packages/browser/tsconfig.json");
    let content = std::fs::read_to_string(&browser_ts).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    let refs = v["references"]
        .as_array()
        .expect("browser must have references");
    let ref_paths: Vec<&str> = refs.iter().filter_map(|r| r["path"].as_str()).collect();
    assert!(
        ref_paths.iter().any(|p| p.contains("browser-core")),
        "browser tsconfig must reference browser-core"
    );
}

#[test]
fn tsconfig_base_uses_bundler_resolution() {
    let path = repo_root().join("tsconfig.base.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    let resolution = v["compilerOptions"]["moduleResolution"]
        .as_str()
        .unwrap_or("");
    assert!(
        resolution == "bundler" || resolution == "Bundler",
        "tsconfig.base must use bundler moduleResolution for ESM exports support, got {resolution}"
    );
}

// ── Package Name Scoping ─────────────────────────────────────────────

#[test]
fn all_packages_are_scoped_under_asupersync() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap();
        assert!(
            name.starts_with("@asupersync/"),
            "{pkg} name must be scoped under @asupersync/, got {name}"
        );
    }
}

#[test]
fn package_directory_matches_scope_name() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap();
        let expected_suffix = name.split('/').next_back().unwrap();
        assert_eq!(
            expected_suffix, *pkg,
            "package directory {pkg} must match scope name suffix {expected_suffix}"
        );
    }
}
