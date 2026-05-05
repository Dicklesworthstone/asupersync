//! Contract tests for Next Browser Edition adapter lifecycle/helper semantics
//! (asupersync-3qv04.8.3 / 3qv04.8.3.3).
//!
//! These checks pin framework-facing helper behavior in `packages/next/src/index.ts`
//! so refactors cannot silently regress bridge/fallback/lifecycle contracts.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_next_source() -> String {
    let path = repo_root().join("packages/next/src/index.ts");
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))
}

#[test]
fn next_source_maps_render_environment_to_boundary_mode() {
    let content = read_next_source();
    for marker in [
        "export function nextBoundaryModeForEnvironment(",
        "case \"client_ssr\":",
        "case \"client_hydrated\":",
        "return \"client\";",
        "case \"server_component\":",
        "case \"node_server\":",
        "return \"server\";",
        "case \"edge_runtime\":",
        "return \"edge\";",
    ] {
        assert!(
            content.contains(marker),
            "next boundary-mode mapping marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_maps_render_environment_to_runtime_fallback_mode() {
    let content = read_next_source();
    for marker in [
        "export function nextRuntimeFallbackForEnvironment(",
        "case \"client_hydrated\":",
        "return \"none_required\";",
        "case \"client_ssr\":",
        "return \"defer_until_hydrated\";",
        "case \"server_component\":",
        "case \"node_server\":",
        "return \"use_server_bridge\";",
        "case \"edge_runtime\":",
        "return \"use_edge_bridge\";",
    ] {
        assert!(
            content.contains(marker),
            "next runtime-fallback mapping marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_pins_human_actionable_fallback_reason_text() {
    let content = read_next_source();
    for marker in [
        "runtime capability available: execute directly in hydrated client boundary",
        "runtime unavailable during SSR client pass: defer initialization until hydration completes",
        "runtime unavailable in server boundary: route through serialized node/server bridge",
        "runtime unavailable in edge boundary: route through serialized edge bridge",
    ] {
        assert!(
            content.contains(marker),
            "next fallback-reason marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_pins_server_and_edge_bridge_diagnostics_defaults() {
    let content = read_next_source();
    for marker in [
        "export function createNextServerBridgeDiagnostics(",
        "const renderEnvironment = options.renderEnvironment ?? \"node_server\";",
        "const runtimeSupport = detectNextRuntimeSupport(\"server\");",
        "runtimeFallback: \"use_server_bridge\",",
        "export function createNextEdgeBridgeDiagnostics(",
        "const renderEnvironment = options.renderEnvironment ?? \"edge_runtime\";",
        "const runtimeSupport = detectNextRuntimeSupport(\"edge\");",
        "runtimeFallback: \"use_edge_bridge\",",
        "options.reproCommand ??",
        "cargo test --test wasm_js_exports_coverage_contract -- --nocapture",
    ] {
        assert!(
            content.contains(marker),
            "next bridge-diagnostics default marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_exposes_bridge_helper_methods_for_server_and_edge_adapters() {
    let content = read_next_source();
    for marker in [
        "export class NextServerBridgeAdapter",
        "createRequest<TPayload extends NextBridgeValue>(",
        "ok<TPayload extends NextBridgeValue>(",
        "err(errorMessage: string): NextServerBridgeResponse",
        "cancelled(errorMessage = \"cancelled\"): NextServerBridgeResponse",
        "fromOutcome<TPayload extends NextBridgeValue>(",
        "unwrapResponse<TPayload extends NextBridgeValue>(",
        "unsupportedRuntimeError(): NextServerBridgeRuntimeError",
        "export class NextEdgeBridgeAdapter",
        "err(errorMessage: string): NextEdgeBridgeResponse",
        "cancelled(errorMessage = \"cancelled\"): NextEdgeBridgeResponse",
        "unsupportedRuntimeError(): NextEdgeBridgeRuntimeError",
    ] {
        assert!(
            content.contains(marker),
            "next bridge-helper marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_pins_bridge_response_unwrap_error_contract() {
    let content = read_next_source();
    for marker in [
        "NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE",
        "NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE",
        "createNextServerBridgeResponseError(",
        "createNextEdgeBridgeResponseError(",
        "export function unwrapNextServerBridgeResponse<",
        "export function unwrapNextEdgeBridgeResponse<TPayload extends NextBridgeValue>(",
        "bridgeDiagnostics",
        "response.outcome === \"ok\" && response.payload !== undefined",
    ] {
        assert!(
            content.contains(marker),
            "next bridge response-error/unwrap marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_pins_bootstrap_lifecycle_transition_guards() {
    let content = read_next_source();
    for marker in [
        "function isValidBootstrapTransition(",
        "from === to",
        "createNextBootstrapStateError(",
        "initializeRuntime requires a hydrated client boundary; current phase is ${this.snapshotState.phase}",
        "runtimeInitFailed is only valid from hydrated; current phase is ${this.snapshotState.phase}",
        "cacheRevalidated requires hydrated or runtime_ready; current phase is ${this.snapshotState.phase}",
        "reset_to_hydrating",
        "retry_runtime_init",
    ] {
        assert!(
            content.contains(marker),
            "next bootstrap lifecycle marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_preserves_browser_runtime_options_through_client_bootstrap() {
    let content = read_next_source();
    for marker in [
        "export function detectNextRuntimeSupport(",
        "globalObject: Record<string, unknown> | undefined = undefined,",
        "const browserDiagnostics = detectBrowserRuntimeSupport(globalObject);",
        "function nextClientBrowserRuntimeOptions(",
        "globalObject: options.globalObject,",
        "preferredLane: options.preferredLane,",
        "healthPolicy: options.healthPolicy,",
        "healthScopeKey: options.healthScopeKey,",
        "now: options.now,",
        "detectNextRuntimeSupport(\"client\", this.options.globalObject)",
        "nextClientBrowserRuntimeOptions(this.options)",
    ] {
        assert!(
            content.contains(marker),
            "next client-bootstrap BrowserRuntimeOptions marker missing: {marker}"
        );
    }
}

#[test]
fn next_source_pins_bootstrap_and_bridge_log_field_shape() {
    let content = read_next_source();
    for marker in [
        "export function createNextBridgeLogFields(",
        "boundary_mode: diagnostics.boundaryMode",
        "render_environment: diagnostics.renderEnvironment",
        "runtime_fallback: diagnostics.runtimeFallback",
        "repro_command: diagnostics.reproCommand",
        "export function createNextBootstrapLogFields(",
        "action: event.action",
        "from_phase: event.fromPhase",
        "to_phase: event.toPhase",
        "hydration_context: bootstrapHydrationContext(snapshot.phase)",
        "navigation_count: String(navigationCount(snapshot))",
        "wasm_module_loaded: String(snapshot.runtimeInitialized)",
    ] {
        assert!(
            content.contains(marker),
            "next log-field schema marker missing: {marker}"
        );
    }
}
