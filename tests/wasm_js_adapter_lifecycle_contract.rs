#![allow(clippy::all)]
//! Contract tests for React/Next adapter lifecycle helpers and bootstrap
//! state-machine surfaces (asupersync-3qv04.8.3.3).
//!
//! These tests intentionally validate the published helper layer by reading the
//! package sources directly. That keeps the assertions deterministic and avoids
//! depending on a JS package manager or generated wasm artifacts.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_source(path: &str) -> String {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        !content.is_empty(),
        "expected non-empty source file at {}",
        path.display()
    );
    content
}

#[test]
fn react_adapter_exposes_provider_context_and_scope_hooks() {
    let content = read_source("packages/react/src/index.ts");
    for marker in [
        "export interface ReactRuntimeContextValue",
        "export interface ReactRuntimeProviderProps",
        "export interface ReactScopeOptions",
        "export interface ReactScopeState",
        "export function ReactRuntimeProvider",
        "export function useReactRuntimeContext",
        "export function useReactRuntime",
        "export function useReactRuntimeDiagnostics",
        "export function useReactScope",
        "const ReactRuntimeContext = createContext<ReactRuntimeContextValue | null>(null);",
    ] {
        assert!(
            content.contains(marker),
            "react adapter must preserve lifecycle helper marker: {marker}"
        );
    }
}

#[test]
fn react_adapter_preserves_strictmode_safe_bootstrap_and_runtime_cleanup() {
    let content = read_source("packages/react/src/index.ts");
    for marker in [
        "const consumerVersionMajor = runtimeOptions?.consumerVersion?.major ?? null;",
        "const consumerVersionMinor = runtimeOptions?.consumerVersion?.minor ?? null;",
        "const globalObject = runtimeOptions?.globalObject;",
        "const healthPolicyCooldownMs = runtimeOptions?.healthPolicy?.cooldownMs ?? null;",
        "const healthPolicyMaxConsecutiveFailures =",
        "const healthScopeKey = runtimeOptions?.healthScopeKey ?? null;",
        "const preferredLane = runtimeOptions?.preferredLane ?? null;",
        "const wasmInput = runtimeOptions?.wasmInput;",
        "const [reloadNonce, setReloadNonce] = useState(0);",
        "const epochRef = useRef(0);",
        "const reload = useCallback(() => {",
        "setReloadNonce((value) => value + 1);",
        "const previousRuntime = runtimeRef.current;",
        "closeRuntime(previousRuntime);",
        "// StrictMode-safe init: stale bootstrap completions are ignored/closed.",
        "let disposed = false;",
        "const epoch = ++epochRef.current;",
        "if (disposed || epoch !== epochRef.current) {",
        "closeRuntime(created.value);",
        "runtimeRef.current = created.value;",
        "setRuntime(created.value);",
        "setStatus(\"ready\");",
        "const activeRuntime = runtimeRef.current;",
        "closeRuntime(activeRuntime);",
    ] {
        assert!(
            content.contains(marker),
            "react adapter must preserve bootstrap/cleanup marker: {marker}"
        );
    }
    assert!(
        !content.contains("}, [reloadNonce, runtimeOptions]);"),
        "react adapter must not key bootstrap churn on raw runtimeOptions identity"
    );
}

#[test]
fn react_adapter_scope_helpers_propagate_failures_and_close_scopes() {
    let content = read_source("packages/react/src/index.ts");
    for marker in [
        "function closeScope(scope: RegionHandle | null, consumerVersion?: AbiVersion | null): void {",
        "scope.close(consumerVersion ?? scope.consumerVersion);",
        "throw new Error(",
        "\"ReactRuntimeProvider is required before calling useReactRuntimeContext().\"",
        "`Browser runtime is not ready (status=${status}). Wrap the tree in ReactRuntimeProvider and wait for initialization.`",
        "const activeScope = scopeRef.current;",
        "closeScope(activeScope, options.consumerVersion);",
        "setStatus(\"opening\");",
        "const opened = runtime.enterScope(",
        "setError(new Error(formatOutcomeFailure(opened)));",
        "scopeRef.current = opened.value;",
        "setStatus(\"ready\");",
        "return () => {",
        "close();",
    ] {
        assert!(
            content.contains(marker),
            "react adapter must preserve scope/error marker: {marker}"
        );
    }
}

#[test]
fn next_adapter_defines_bootstrap_types_snapshots_and_log_surface() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export type NextBootstrapPhase =",
        "\"server_rendered\"",
        "\"hydrating\"",
        "\"hydrated\"",
        "\"runtime_ready\"",
        "\"runtime_failed\"",
        "export type NextRenderEnvironment =",
        "\"client_ssr\"",
        "\"client_hydrated\"",
        "\"server_component\"",
        "\"node_server\"",
        "\"edge_runtime\"",
        "export type NextNavigationType =",
        "\"soft_navigation\"",
        "\"hard_navigation\"",
        "\"popstate\"",
        "export type NextBootstrapRecoveryAction =",
        "\"reset_to_hydrating\"",
        "\"retry_runtime_init\"",
        "export interface NextBootstrapSnapshot",
        "phaseHistory: NextBootstrapPhase[];",
        "export interface NextBootstrapLogEvent",
        "export interface NextClientBootstrapOptions",
        "export interface NextBootstrapLogFieldOverrides",
        "export const NEXT_BOOTSTRAP_STATE_ERROR_CODE =",
        "export const NEXT_BOOTSTRAP_PHASES = [",
        "export const NEXT_NAVIGATION_TYPES = [",
        "export const NEXT_BOOTSTRAP_RECOVERY_ACTIONS = [",
    ] {
        assert!(
            content.contains(marker),
            "next adapter must preserve bootstrap surface marker: {marker}"
        );
    }
}

#[test]
fn next_adapter_preserves_log_field_and_state_transition_helpers() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "function supportsWasmRuntime(environment: NextRenderEnvironment): boolean {",
        "function bootstrapHydrationContext(phase: NextBootstrapPhase): string {",
        "function navigationCount(snapshot: NextBootstrapSnapshot): number {",
        "function createInitialSnapshot(",
        "function isValidBootstrapTransition(",
        "export function createNextBootstrapStateError(",
        "export function createNextBootstrapLogFields(",
        "from_phase: event.fromPhase,",
        "to_phase: event.toPhase,",
        "route_segment: snapshot.routeSegment,",
        "bootstrap_phase: snapshot.phase,",
        "hydration_context: bootstrapHydrationContext(snapshot.phase),",
        "navigation_count: String(navigationCount(snapshot)),",
        "wasm_module_loaded: String(snapshot.runtimeInitialized),",
    ] {
        assert!(
            content.contains(marker),
            "next adapter must preserve logging/transition helper marker: {marker}"
        );
    }
}

#[test]
fn next_adapter_tracks_hydration_navigation_recovery_and_cleanup_flows() {
    let content = read_source("packages/next/src/index.ts");
    for marker in [
        "export class NextClientBootstrapAdapter",
        "events(): readonly NextBootstrapLogEvent[] {",
        "createLogFields(",
        "beginHydration(): NextBootstrapLogEvent {",
        "this.transitionTo(\"hydrating\", \"beginHydration\");",
        "return this.recordEvent(\"begin_hydration\", from);",
        "completeHydration(): NextBootstrapLogEvent {",
        "this.transitionTo(\"hydrated\", \"completeHydration\");",
        "return this.recordEvent(\"complete_hydration\", from);",
        "async initializeRuntime(): Promise<BrowserOutcome<RegionHandle>> {",
        "assertNextRuntimeSupport(",
        "const runtime = await createBrowserRuntime(",
        "const entered = runtime.value.enterScope(",
        "this.transitionTo(\"runtime_ready\", \"initializeRuntime\");",
        "return OutcomeFactory.ok(entered.value);",
        "async ensureRuntimeReady(): Promise<BrowserOutcome<RegionHandle>> {",
        "async hydrateAndInitialize(): Promise<BrowserOutcome<RegionHandle>> {",
        "runtimeInitFailed(reason: string): NextBootstrapLogEvent {",
        "cancelBootstrap(reason: string): NextBootstrapLogEvent {",
        "hydrationMismatch(reason: string): NextBootstrapLogEvent {",
        "recover(action: NextBootstrapRecoveryAction): NextBootstrapLogEvent {",
        "navigate(",
        "\"soft_navigation\"",
        "\"hard_navigation\"",
        "\"popstate\"",
        "hotReload(): NextBootstrapLogEvent {",
        "cacheRevalidated(): NextBootstrapLogEvent {",
        "close(reason = \"manual_close\"): NextBootstrapLogEvent {",
        "private invalidateRuntimeScope(reason: string): void {",
        "private cleanupHandles(): string[] {",
        "scope_close=${formatOutcomeFailure(closeScope)}",
        "runtime_close=${formatOutcomeFailure(closeRuntime)}",
        "private recordEvent(",
        "this.options.onLogEvent?.(event, this.snapshot());",
        "export function createNextBootstrapAdapter(",
    ] {
        assert!(
            content.contains(marker),
            "next adapter must preserve lifecycle/state-machine marker: {marker}"
        );
    }
}
