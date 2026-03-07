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
        "export class CancellationToken",
        "export function createCancellationToken",
        "export async function createBrowserRuntime",
        "export async function createBrowserScope",
        "export function createBrowserSdkDiagnostics",
        "export function unwrapOutcome",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must define marker: {marker}"
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
        "@asupersync/browser-core/abi-metadata.json",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must preserve core alias marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_threads_runtime_reference_through_scope_handles() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "readonly runtime: BrowserRuntime | null = null",
        "new RegionHandle(handle, consumerVersion, this)",
        "new RegionHandle(handle, consumerVersion, this.runtime)",
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
        "client-hydrated browser boundaries",
    ] {
        assert!(
            content.contains(marker),
            "browser src/index.ts must define unsupported-runtime marker: {marker}"
        );
    }
}

#[test]
fn browser_src_index_pins_runtime_support_reason_taxonomy_and_capabilities() {
    let content = read_source("packages/browser/src/index.ts");
    for marker in [
        "\"missing_global_this\"",
        "\"missing_browser_dom\"",
        "\"missing_webassembly\"",
        "\"supported\"",
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
        "Load @asupersync/browser only in client-hydrated browser boundaries.",
        "prefer @asupersync/next bridge-only adapters instead of direct BrowserRuntime creation.",
        "Move BrowserRuntime creation behind a browser-only entrypoint.",
        "Use a browser/runtime with WebAssembly enabled before initializing Browser Edition.",
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
        2,
        "browser runtime creation and scope entry must both guard unsupported runtimes"
    );
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
        "target !== \"client\"",
        "Direct Browser Edition runtime execution is unsupported in Next ${target} runtimes.",
        "Move BrowserRuntime creation into a client component or browser-only module.",
        "Use bridge-only adapters rather than direct @asupersync/browser runtime calls in Next ${target} code.",
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
        "export function nextBoundaryModeForEnvironment",
        "export function nextRuntimeFallbackForEnvironment",
        "export function nextRuntimeFallbackReason",
        "export function createNextServerBridgeDiagnostics",
        "export function createNextBridgeLogFields",
        "export class NextServerBridgeAdapter",
        "export function createNextServerBridgeAdapter",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must define server-bridge marker: {marker}"
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
        "runtime unavailable in server boundary: route through serialized node/server bridge",
        "boundary_mode: diagnostics.boundaryMode",
        "render_environment: diagnostics.renderEnvironment",
        "runtime_fallback: diagnostics.runtimeFallback",
        "repro_command: diagnostics.reproCommand",
        "createNextUnsupportedRuntimeError(",
        "bridgeDiagnostics",
    ] {
        assert!(
            content.contains(marker),
            "next src/index.ts must preserve server-bridge marker: {marker}"
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
