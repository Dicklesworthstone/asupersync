/**
 * @asupersync/next — Next.js adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser and adds a
 * hydration-safe bootstrap adapter for client-rendered Next.js boundaries.
 */

import {
  type AbiFailure,
  type BrowserRuntime,
  type BrowserRuntimeOptions,
  type BrowserRuntimeSupportClass,
  type BrowserRuntimeSupportDiagnostics,
  type BrowserRuntimeSupportReason,
  createBrowserRuntime,
  detectBrowserRuntimeSupport,
  formatOutcomeFailure,
  type Outcome,
  Outcome as OutcomeFactory,
  type RegionHandle,
} from "@asupersync/browser";
import * as BrowserSdk from "@asupersync/browser";

export * from "@asupersync/browser";

export type NextRuntimeTarget = "client" | "server" | "edge";
export type NextRuntimeSupportReason =
  | BrowserRuntimeSupportReason
  | "bridge_only_server_target"
  | "bridge_only_edge_target";
export type NextRuntimeSupportClass = BrowserRuntimeSupportClass | "bridge_only";
export type NextBootstrapPhase =
  | "server_rendered"
  | "hydrating"
  | "hydrated"
  | "runtime_ready"
  | "runtime_failed";
export type NextRenderEnvironment =
  | "client_ssr"
  | "client_hydrated"
  | "server_component"
  | "node_server"
  | "edge_runtime";
export type NextNavigationType = "soft_navigation" | "hard_navigation" | "popstate";
export type NextBootstrapRecoveryAction = "none" | "reset_to_hydrating" | "retry_runtime_init";

export interface NextRuntimeSupportDiagnostics
  extends Omit<BrowserRuntimeSupportDiagnostics, "packageName" | "reason" | "supportClass"> {
  packageName: "@asupersync/next";
  target: NextRuntimeTarget;
  reason: NextRuntimeSupportReason;
  supportClass: NextRuntimeSupportClass;
}

export interface NextBootstrapSnapshot {
  phase: NextBootstrapPhase;
  environment: NextRenderEnvironment;
  routeSegment: string;
  runtimeInitialized: boolean;
  runtimeInitAttempts: number;
  runtimeInitSuccesses: number;
  runtimeFailureCount: number;
  cancellationCount: number;
  hydrationMismatchCount: number;
  softNavigationCount: number;
  hardNavigationCount: number;
  popstateNavigationCount: number;
  cacheRevalidationCount: number;
  scopeInvalidationCount: number;
  runtimeReinitRequiredCount: number;
  activeScopeGeneration: number;
  lastInvalidatedScopeGeneration: number | null;
  hotReloadCount: number;
  lastRecoveryAction: NextBootstrapRecoveryAction;
  lastError: string | null;
  phaseHistory: NextBootstrapPhase[];
}

export interface NextBootstrapLogEvent {
  action: string;
  fromPhase: NextBootstrapPhase;
  toPhase: NextBootstrapPhase;
  fromEnvironment: NextRenderEnvironment;
  toEnvironment: NextRenderEnvironment;
  routeSegment: string;
  recoveryAction: NextBootstrapRecoveryAction;
  detail?: string;
  navigationType?: NextNavigationType;
}

export interface NextClientBootstrapOptions extends BrowserRuntimeOptions {
  initialRouteSegment?: string;
  label?: string;
  popstatePreservesRuntime?: boolean;
  onLogEvent?: (event: NextBootstrapLogEvent, snapshot: NextBootstrapSnapshot) => void;
}

export interface NextBootstrapLogFieldOverrides {
  scenario_id?: string;
  deployment_target?: string;
  [key: string]: string | number | boolean | null | undefined;
}

export type NextBoundaryMode = "client" | "server" | "edge";
export type NextRuntimeFallback =
  | "none_required"
  | "defer_until_hydrated"
  | "use_server_bridge"
  | "use_edge_bridge";
export type NextServerBridgeEnvironment = "server_component" | "node_server";
export type NextEdgeBridgeEnvironment = "edge_runtime";
export type NextBridgeOutcome = "ok" | "err" | "cancelled" | "panicked";
export type NextBridgeValue =
  | string
  | number
  | boolean
  | null
  | NextBridgeValue[]
  | { [key: string]: NextBridgeValue };

export interface NextServerBridgeDiagnostics {
  target: "server";
  boundaryMode: "server";
  renderEnvironment: NextServerBridgeEnvironment;
  runtimeFallback: "use_server_bridge";
  reason: string;
  reproCommand: string;
  directRuntimeSupported: false;
  runtimeSupport: NextRuntimeSupportDiagnostics;
}

export interface NextServerBridgeRequestOptions {
  requestId?: string;
  routeSegment?: string;
}

export interface NextServerBridgeRequest<TPayload extends NextBridgeValue = NextBridgeValue> {
  operation: string;
  payload: TPayload;
  routeSegment: string;
  requestId?: string;
  boundaryMode: "server";
  renderEnvironment: NextServerBridgeEnvironment;
  runtimeFallback: "use_server_bridge";
  cancellationMode: "explicit_status";
}

export interface NextServerBridgeResponse<TPayload extends NextBridgeValue = NextBridgeValue> {
  outcome: NextBridgeOutcome;
  payload?: TPayload;
  errorMessage?: string;
  diagnostics: NextServerBridgeDiagnostics;
}

export interface NextServerBridgeAdapterOptions {
  renderEnvironment?: NextServerBridgeEnvironment;
  routeSegment?: string;
  reproCommand?: string;
}

export interface NextServerBridgeRuntimeError extends Error {
  bridgeDiagnostics: NextServerBridgeDiagnostics;
}

export interface NextEdgeBridgeDiagnostics {
  target: "edge";
  boundaryMode: "edge";
  renderEnvironment: NextEdgeBridgeEnvironment;
  runtimeFallback: "use_edge_bridge";
  reason: string;
  reproCommand: string;
  directRuntimeSupported: false;
  runtimeSupport: NextRuntimeSupportDiagnostics;
}

export interface NextEdgeBridgeRequestOptions {
  requestId?: string;
  routeSegment?: string;
}

export interface NextEdgeBridgeRequest<TPayload extends NextBridgeValue = NextBridgeValue> {
  operation: string;
  payload: TPayload;
  routeSegment: string;
  requestId?: string;
  boundaryMode: "edge";
  renderEnvironment: NextEdgeBridgeEnvironment;
  runtimeFallback: "use_edge_bridge";
  cancellationMode: "explicit_status";
}

export interface NextEdgeBridgeResponse<TPayload extends NextBridgeValue = NextBridgeValue> {
  outcome: NextBridgeOutcome;
  payload?: TPayload;
  errorMessage?: string;
  diagnostics: NextEdgeBridgeDiagnostics;
}

export interface NextEdgeBridgeAdapterOptions {
  renderEnvironment?: NextEdgeBridgeEnvironment;
  routeSegment?: string;
  reproCommand?: string;
}

export interface NextEdgeBridgeRuntimeError extends Error {
  bridgeDiagnostics: NextEdgeBridgeDiagnostics;
}

export const NEXT_UNSUPPORTED_RUNTIME_CODE = "ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME";
export const NEXT_BOOTSTRAP_STATE_ERROR_CODE = "ASUPERSYNC_NEXT_BOOTSTRAP_STATE_ERROR";
export const NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE = "ASUPERSYNC_NEXT_SERVER_BRIDGE_RESPONSE";
export const NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE = "ASUPERSYNC_NEXT_EDGE_BRIDGE_RESPONSE";
export const NEXT_BOOTSTRAP_PHASES = [
  "server_rendered",
  "hydrating",
  "hydrated",
  "runtime_ready",
  "runtime_failed",
] as const;
export const NEXT_NAVIGATION_TYPES = ["soft_navigation", "hard_navigation", "popstate"] as const;
export const NEXT_BOOTSTRAP_RECOVERY_ACTIONS = [
  "none",
  "reset_to_hydrating",
  "retry_runtime_init",
] as const;
export const NEXT_BOUNDARY_MODES = ["client", "server", "edge"] as const;
export const NEXT_RUNTIME_FALLBACKS = [
  "none_required",
  "defer_until_hydrated",
  "use_server_bridge",
  "use_edge_bridge",
] as const;
export const NEXT_SERVER_BRIDGE_ENVIRONMENTS = ["server_component", "node_server"] as const;
export const NEXT_EDGE_BRIDGE_ENVIRONMENTS = ["edge_runtime"] as const;

type BrowserOutcome<T = unknown> = Outcome<T, AbiFailure>;

function nextBootstrapCleanupError(error: unknown): string {
  try {
    return String(error).slice(0, 1024);
  } catch {
    return "cleanup threw an unprintable value";
  }
}

interface NextRuntimeInitializationAttempt {
  result: Promise<BrowserOutcome<RegionHandle>>;
  cancelled: BrowserOutcome<never> | null;
  owner: NextBootstrapOwner;
}

interface NextBootstrapOwnedHandle {
  readonly asynchronous: boolean;
  readonly close: () => unknown;
  closed: boolean;
}

interface NextBootstrapOwner {
  runtime: NextBootstrapOwnedHandle | null;
  scope: NextBootstrapOwnedHandle | null;
  readonly initialized: Promise<void>;
  readonly initialize: () => void;
  initializedDone: boolean;
  published: boolean;
  closing: boolean;
  closed: boolean;
  attempt: Promise<BrowserOutcome<void>> | null;
  receipt: BrowserOutcome<void> | null;
  failures: string[];
}

function nextCleanupFailure(error: unknown): BrowserOutcome<void> {
  return Object.freeze(OutcomeFactory.err("internal_failure", "transient",
    `Next bootstrap cleanup failed: ${nextBootstrapCleanupError(error)}`));
}

function nextCleanupReceipt(value: unknown): BrowserOutcome<void> {
  try {
    if (!value || typeof value !== "object") throw new TypeError("Missing cleanup receipt");
    const result = value as BrowserOutcome<void>;
    if (result.outcome === "ok" && result.value === undefined) {
      return Object.freeze(OutcomeFactory.ok(undefined));
    }
    if (result.outcome === "err") {
      const { code, recoverability, message } = result.failure;
      if (typeof code !== "string" || typeof recoverability !== "string" || typeof message !== "string") {
        throw new TypeError("Invalid cleanup failure");
      }
      return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
    }
    if (result.outcome === "cancelled") {
      return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({ ...result.cancellation }) });
    }
    if (result.outcome === "panicked" && typeof result.message === "string") {
      return Object.freeze({ outcome: "panicked", message: result.message });
    }
    throw new TypeError("Invalid cleanup receipt");
  } catch (error) { return nextCleanupFailure(error); }
}

function captureNextBootstrapOwner(owner: BrowserRuntime | RegionHandle): NextBootstrapOwnedHandle {
  try {
    const rawVersion = owner.consumerVersion;
    const version = rawVersion == null ? null
      : Object.freeze({ major: rawVersion.major, minor: rawVersion.minor });
    const nativeRuntime = typeof BrowserSdk.BrowserRuntime === "function"
      && owner instanceof BrowserSdk.BrowserRuntime;
    const nativeScope = typeof BrowserSdk.RegionHandle === "function"
      && owner instanceof BrowserSdk.RegionHandle;
    if (nativeRuntime || nativeScope) {
      // Public SDK facades are mutable JavaScript objects. Retain an independent
      // frozen core identity so replacing facade.core or its close methods can
      // neither abandon this owner nor redirect cleanup to an unrelated owner.
      const raw = owner.core.toJSON();
      const kind = nativeRuntime ? "runtime" : "region";
      if (raw.kind !== kind) throw new TypeError("Unexpected bootstrap owner kind");
      const fields = { slot: raw.slot, generation: raw.generation, owner_token: raw.owner_token };
      const core = nativeRuntime
        ? new BrowserSdk.CoreRuntimeHandle({ ...fields, kind: "runtime" })
        : new BrowserSdk.CoreRegionHandle({ ...fields, kind: "region" });
      const receiver = Object.freeze({ core, consumerVersion: version });
      const close = nativeRuntime
        ? BrowserSdk.BrowserRuntime.prototype.closeAsync : BrowserSdk.RegionHandle.prototype.closeAsync;
      return { asynchronous: true, closed: false, close: () => Reflect.apply(close, receiver, [version]) };
    }
    const asynchronous = owner.closeAsync;
    const close = typeof asynchronous === "function" ? asynchronous : owner.close;
    if (typeof close !== "function") throw new TypeError("Owner cannot be closed");
    return { asynchronous: typeof asynchronous === "function", closed: false,
      close: () => Reflect.apply(close, owner, [version]) };
  } catch (error) {
    const failure = nextCleanupFailure(error);
    return { asynchronous: true, closed: false, close: () => failure };
  }
}

function supportsWasmRuntime(environment: NextRenderEnvironment): boolean {
  return environment === "client_hydrated";
}

function cloneNextRuntimeSupportDiagnostics(
  diagnostics: NextRuntimeSupportDiagnostics,
): NextRuntimeSupportDiagnostics {
  return {
    ...diagnostics,
    guidance: [...diagnostics.guidance],
    capabilities: { ...diagnostics.capabilities },
  };
}

function cloneNextServerBridgeDiagnostics(
  diagnostics: NextServerBridgeDiagnostics,
): NextServerBridgeDiagnostics {
  return {
    ...diagnostics,
    runtimeSupport: cloneNextRuntimeSupportDiagnostics(diagnostics.runtimeSupport),
  };
}

function cloneNextEdgeBridgeDiagnostics(
  diagnostics: NextEdgeBridgeDiagnostics,
): NextEdgeBridgeDiagnostics {
  return {
    ...diagnostics,
    runtimeSupport: cloneNextRuntimeSupportDiagnostics(diagnostics.runtimeSupport),
  };
}

function bootstrapHydrationContext(phase: NextBootstrapPhase): string {
  return phase;
}

function navigationCount(snapshot: NextBootstrapSnapshot): number {
  return (
    snapshot.softNavigationCount + snapshot.hardNavigationCount + snapshot.popstateNavigationCount
  );
}

function cloneSnapshot(snapshot: NextBootstrapSnapshot): NextBootstrapSnapshot {
  return {
    ...snapshot,
    phaseHistory: [...snapshot.phaseHistory],
  };
}

function createInitialSnapshot(options: NextClientBootstrapOptions): NextBootstrapSnapshot {
  return {
    phase: "server_rendered",
    environment: "client_ssr",
    routeSegment: options.initialRouteSegment ?? "/",
    runtimeInitialized: false,
    runtimeInitAttempts: 0,
    runtimeInitSuccesses: 0,
    runtimeFailureCount: 0,
    cancellationCount: 0,
    hydrationMismatchCount: 0,
    softNavigationCount: 0,
    hardNavigationCount: 0,
    popstateNavigationCount: 0,
    cacheRevalidationCount: 0,
    scopeInvalidationCount: 0,
    runtimeReinitRequiredCount: 0,
    activeScopeGeneration: 0,
    lastInvalidatedScopeGeneration: null,
    hotReloadCount: 0,
    lastRecoveryAction: "none",
    lastError: null,
    phaseHistory: ["server_rendered"],
  };
}

function isValidBootstrapTransition(from: NextBootstrapPhase, to: NextBootstrapPhase): boolean {
  if (from === to) {
    return true;
  }

  switch (from) {
    case "server_rendered":
      return to === "hydrating";
    case "hydrating":
      return to === "hydrated" || to === "runtime_failed";
    case "hydrated":
      return to === "runtime_ready" || to === "runtime_failed" || to === "server_rendered";
    case "runtime_ready":
    case "runtime_failed":
      return to === "hydrating" || to === "server_rendered";
    default:
      return false;
  }
}

export function nextBoundaryModeForEnvironment(
  environment: NextRenderEnvironment,
): NextBoundaryMode {
  switch (environment) {
    case "client_ssr":
    case "client_hydrated":
      return "client";
    case "server_component":
    case "node_server":
      return "server";
    case "edge_runtime":
      return "edge";
  }
}

export function nextRuntimeFallbackForEnvironment(
  environment: NextRenderEnvironment,
): NextRuntimeFallback {
  switch (environment) {
    case "client_hydrated":
      return "none_required";
    case "client_ssr":
      return "defer_until_hydrated";
    case "server_component":
    case "node_server":
      return "use_server_bridge";
    case "edge_runtime":
      return "use_edge_bridge";
  }
}

export function nextRuntimeFallbackReason(environment: NextRenderEnvironment): string {
  switch (nextRuntimeFallbackForEnvironment(environment)) {
    case "none_required":
      return "runtime capability available: execute directly in hydrated client boundary";
    case "defer_until_hydrated":
      return "runtime unavailable during SSR client pass: defer initialization until hydration completes";
    case "use_server_bridge":
      return "runtime unavailable in server boundary: route through serialized node/server bridge";
    case "use_edge_bridge":
      return "runtime unavailable in edge boundary: route through serialized edge bridge";
  }
}

export function createNextServerBridgeDiagnostics(
  options: NextServerBridgeAdapterOptions = {},
): NextServerBridgeDiagnostics {
  const renderEnvironment = options.renderEnvironment ?? "node_server";
  const runtimeSupport = detectNextRuntimeSupport("server");
  return {
    target: "server",
    boundaryMode: "server",
    renderEnvironment,
    runtimeFallback: "use_server_bridge",
    reason: nextRuntimeFallbackReason(renderEnvironment),
    reproCommand:
      options.reproCommand ??
      "rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture",
    directRuntimeSupported: false,
    runtimeSupport,
  };
}

export function createNextEdgeBridgeDiagnostics(
  options: NextEdgeBridgeAdapterOptions = {},
): NextEdgeBridgeDiagnostics {
  const renderEnvironment = options.renderEnvironment ?? "edge_runtime";
  const runtimeSupport = detectNextRuntimeSupport("edge");
  return {
    target: "edge",
    boundaryMode: "edge",
    renderEnvironment,
    runtimeFallback: "use_edge_bridge",
    reason: nextRuntimeFallbackReason(renderEnvironment),
    reproCommand:
      options.reproCommand ??
      "rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture",
    directRuntimeSupported: false,
    runtimeSupport,
  };
}

export function createNextBridgeLogFields(
  diagnostics: NextServerBridgeDiagnostics | NextEdgeBridgeDiagnostics,
  overrides: NextBootstrapLogFieldOverrides = {},
): Record<string, string> {
  const fields: Record<string, string> = {
    boundary_mode: diagnostics.boundaryMode,
    render_environment: diagnostics.renderEnvironment,
    runtime_fallback: diagnostics.runtimeFallback,
    repro_command: diagnostics.reproCommand,
  };

  for (const key of Object.keys(overrides).sort()) {
    const value = overrides[key];
    if (value !== undefined && value !== null) {
      fields[key] = String(value);
    }
  }

  return fields;
}

export interface NextServerBridgeResponseError extends Error {
  code: typeof NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE;
  bridgeDiagnostics: NextServerBridgeDiagnostics;
  response: NextServerBridgeResponse;
}

export interface NextEdgeBridgeResponseError extends Error {
  code: typeof NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE;
  bridgeDiagnostics: NextEdgeBridgeDiagnostics;
  response: NextEdgeBridgeResponse;
}

export function createNextServerBridgeResponseFromOutcome<TPayload extends NextBridgeValue>(
  outcome: BrowserOutcome<TPayload>,
  options: NextServerBridgeAdapterOptions = {},
): NextServerBridgeResponse<TPayload> {
  const diagnostics = createNextServerBridgeDiagnostics(options);
  switch (outcome.outcome) {
    case "ok":
      return {
        outcome: "ok",
        payload: outcome.value,
        diagnostics,
      };
    case "err":
      return {
        outcome: "err",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
    case "cancelled":
      return {
        outcome: "cancelled",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
    case "panicked":
      return {
        outcome: "panicked",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
  }
}

export function createNextEdgeBridgeResponseFromOutcome<TPayload extends NextBridgeValue>(
  outcome: BrowserOutcome<TPayload>,
  options: NextEdgeBridgeAdapterOptions = {},
): NextEdgeBridgeResponse<TPayload> {
  const diagnostics = createNextEdgeBridgeDiagnostics(options);
  switch (outcome.outcome) {
    case "ok":
      return {
        outcome: "ok",
        payload: outcome.value,
        diagnostics,
      };
    case "err":
      return {
        outcome: "err",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
    case "cancelled":
      return {
        outcome: "cancelled",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
    case "panicked":
      return {
        outcome: "panicked",
        errorMessage: formatOutcomeFailure(outcome),
        diagnostics,
      };
  }
}

function createNextServerBridgeResponseError(
  response: NextServerBridgeResponse,
): NextServerBridgeResponseError {
  const message = response.errorMessage ?? "bridge response did not include a payload";
  const error = new Error(
    `${response.diagnostics.renderEnvironment}: ${response.outcome}: ${message}`,
  ) as NextServerBridgeResponseError;
  error.code = NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE;
  error.bridgeDiagnostics = cloneNextServerBridgeDiagnostics(response.diagnostics);
  error.response = {
    ...response,
    diagnostics: cloneNextServerBridgeDiagnostics(response.diagnostics),
  };
  return error;
}

function createNextEdgeBridgeResponseError(
  response: NextEdgeBridgeResponse,
): NextEdgeBridgeResponseError {
  const message = response.errorMessage ?? "bridge response did not include a payload";
  const error = new Error(
    `${response.diagnostics.renderEnvironment}: ${response.outcome}: ${message}`,
  ) as NextEdgeBridgeResponseError;
  error.code = NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE;
  error.bridgeDiagnostics = cloneNextEdgeBridgeDiagnostics(response.diagnostics);
  error.response = {
    ...response,
    diagnostics: cloneNextEdgeBridgeDiagnostics(response.diagnostics),
  };
  return error;
}

export function unwrapNextServerBridgeResponse<TPayload extends NextBridgeValue>(
  response: NextServerBridgeResponse<TPayload>,
): TPayload {
  if (response.outcome === "ok" && response.payload !== undefined) {
    return response.payload;
  }
  throw createNextServerBridgeResponseError(response);
}

export function unwrapNextEdgeBridgeResponse<TPayload extends NextBridgeValue>(
  response: NextEdgeBridgeResponse<TPayload>,
): TPayload {
  if (response.outcome === "ok" && response.payload !== undefined) {
    return response.payload;
  }
  throw createNextEdgeBridgeResponseError(response);
}

export interface NextBootstrapStateError extends Error {
  code: typeof NEXT_BOOTSTRAP_STATE_ERROR_CODE;
  action: string;
  phase: NextBootstrapPhase;
}

export function createNextBootstrapStateError(
  action: string,
  phase: NextBootstrapPhase,
  message: string,
): NextBootstrapStateError {
  const error = new Error(message) as NextBootstrapStateError;
  error.code = NEXT_BOOTSTRAP_STATE_ERROR_CODE;
  error.action = action;
  error.phase = phase;
  return error;
}

export function detectNextRuntimeSupport(
  target: NextRuntimeTarget = "client",
  globalObject: Record<string, unknown> | undefined = undefined,
): NextRuntimeSupportDiagnostics {
  const browserDiagnostics = detectBrowserRuntimeSupport(globalObject);
  if (target !== "client") {
    const isServerTarget = target === "server";
    return {
      ...browserDiagnostics,
      supported: false,
      packageName: "@asupersync/next",
      target,
      supportClass: "bridge_only",
      reason: isServerTarget ? "bridge_only_server_target" : "bridge_only_edge_target",
      message: isServerTarget
        ? "Next server runtimes are bridge-only for direct Browser Edition execution."
        : "Next edge runtimes are bridge-only for direct Browser Edition execution.",
      guidance: [
        "Move BrowserRuntime creation into a client component or browser-only module.",
        isServerTarget
          ? "Use the Next server bridge helpers to serialize work across the server/browser boundary."
          : "Use the Next edge bridge helpers to serialize work across the edge/browser boundary.",
      ],
    };
  }

  return {
    ...browserDiagnostics,
    packageName: "@asupersync/next",
    target,
    guidance: browserDiagnostics.supported
      ? []
      : ["Import @asupersync/next from client components only.", ...browserDiagnostics.guidance],
  };
}

function nextClientBrowserRuntimeOptions(
  options: NextClientBootstrapOptions,
): BrowserRuntimeOptions {
  return {
    wasmInput: options.wasmInput,
    consumerVersion: options.consumerVersion,
    eagerInit: options.eagerInit,
    globalObject: options.globalObject,
    preferredLane: options.preferredLane,
    healthPolicy: options.healthPolicy,
    healthScopeKey: options.healthScopeKey,
    now: options.now,
    fetchAuthority: options.fetchAuthority,
  };
}

export function createNextUnsupportedRuntimeError(
  diagnostics: NextRuntimeSupportDiagnostics = detectNextRuntimeSupport(),
): Error & {
  code: typeof NEXT_UNSUPPORTED_RUNTIME_CODE;
  diagnostics: NextRuntimeSupportDiagnostics;
} {
  const error = new Error(
    `${diagnostics.packageName}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof NEXT_UNSUPPORTED_RUNTIME_CODE;
    diagnostics: NextRuntimeSupportDiagnostics;
  };
  error.code = NEXT_UNSUPPORTED_RUNTIME_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertNextRuntimeSupport(
  target: NextRuntimeTarget = "client",
  diagnostics: NextRuntimeSupportDiagnostics = detectNextRuntimeSupport(target),
): NextRuntimeSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createNextUnsupportedRuntimeError(diagnostics);
  }
  return diagnostics;
}

export function createNextBootstrapLogFields(
  event: NextBootstrapLogEvent,
  snapshot: NextBootstrapSnapshot,
  overrides: NextBootstrapLogFieldOverrides = {},
): Record<string, string> {
  const fields: Record<string, string> = {
    action: event.action,
    from_phase: event.fromPhase,
    to_phase: event.toPhase,
    from_environment: event.fromEnvironment,
    to_environment: event.toEnvironment,
    route_segment: snapshot.routeSegment,
    recovery_action: event.recoveryAction,
    bootstrap_phase: snapshot.phase,
    hydration_context: bootstrapHydrationContext(snapshot.phase),
    boundary_mode: "client",
    navigation_type: event.navigationType ?? "none",
    active_provider_count: "0",
    navigation_count: String(navigationCount(snapshot)),
    wasm_module_loaded: String(snapshot.runtimeInitialized),
    cache_revalidation_count: String(snapshot.cacheRevalidationCount),
    scope_invalidation_count: String(snapshot.scopeInvalidationCount),
    runtime_reinit_required_count: String(snapshot.runtimeReinitRequiredCount),
    active_scope_generation: String(snapshot.activeScopeGeneration),
    last_invalidated_scope_generation:
      snapshot.lastInvalidatedScopeGeneration === null
        ? "none"
        : String(snapshot.lastInvalidatedScopeGeneration),
  };

  if (event.detail) {
    fields.detail = event.detail;
  }

  for (const key of Object.keys(overrides).sort()) {
    const value = overrides[key];
    if (value !== undefined && value !== null) {
      fields[key] = String(value);
    }
  }

  return fields;
}

export class NextServerBridgeAdapter {
  private readonly diagnosticsState: NextServerBridgeDiagnostics;
  private readonly routeSegment: string;

  constructor(private readonly options: NextServerBridgeAdapterOptions = {}) {
    this.diagnosticsState = createNextServerBridgeDiagnostics(options);
    this.routeSegment = options.routeSegment ?? "/";
  }

  diagnostics(): NextServerBridgeDiagnostics {
    return cloneNextServerBridgeDiagnostics(this.diagnosticsState);
  }

  createLogFields(overrides: NextBootstrapLogFieldOverrides = {}): Record<string, string> {
    return createNextBridgeLogFields(this.diagnosticsState, overrides);
  }

  createRequest<TPayload extends NextBridgeValue>(
    operation: string,
    payload: TPayload,
    options: NextServerBridgeRequestOptions = {},
  ): NextServerBridgeRequest<TPayload> {
    return {
      operation,
      payload,
      routeSegment: options.routeSegment ?? this.routeSegment,
      ...(options.requestId ? { requestId: options.requestId } : {}),
      boundaryMode: "server",
      renderEnvironment: this.diagnosticsState.renderEnvironment,
      runtimeFallback: "use_server_bridge",
      cancellationMode: "explicit_status",
    };
  }

  ok<TPayload extends NextBridgeValue>(payload: TPayload): NextServerBridgeResponse<TPayload> {
    return {
      outcome: "ok",
      payload,
      diagnostics: this.diagnostics(),
    };
  }

  err(errorMessage: string): NextServerBridgeResponse {
    return {
      outcome: "err",
      errorMessage,
      diagnostics: this.diagnostics(),
    };
  }

  cancelled(errorMessage = "cancelled"): NextServerBridgeResponse {
    return {
      outcome: "cancelled",
      errorMessage,
      diagnostics: this.diagnostics(),
    };
  }

  fromOutcome(outcome: BrowserOutcome<NextBridgeValue>): NextServerBridgeResponse<NextBridgeValue>;
  fromOutcome<TPayload extends NextBridgeValue>(
    outcome: BrowserOutcome<TPayload>,
  ): NextServerBridgeResponse<TPayload> {
    return createNextServerBridgeResponseFromOutcome(outcome, this.options);
  }

  unwrapResponse(response: NextServerBridgeResponse<NextBridgeValue>): NextBridgeValue;
  unwrapResponse<TPayload extends NextBridgeValue>(
    response: NextServerBridgeResponse<TPayload>,
  ): TPayload {
    return unwrapNextServerBridgeResponse(response);
  }

  unsupportedRuntimeError(): NextServerBridgeRuntimeError {
    return Object.assign(createNextUnsupportedRuntimeError(this.diagnosticsState.runtimeSupport), {
      bridgeDiagnostics: this.diagnostics(),
    });
  }
}

export class NextEdgeBridgeAdapter {
  private readonly diagnosticsState: NextEdgeBridgeDiagnostics;
  private readonly routeSegment: string;

  constructor(private readonly options: NextEdgeBridgeAdapterOptions = {}) {
    this.diagnosticsState = createNextEdgeBridgeDiagnostics(options);
    this.routeSegment = options.routeSegment ?? "/";
  }

  diagnostics(): NextEdgeBridgeDiagnostics {
    return cloneNextEdgeBridgeDiagnostics(this.diagnosticsState);
  }

  createLogFields(overrides: NextBootstrapLogFieldOverrides = {}): Record<string, string> {
    return createNextBridgeLogFields(this.diagnosticsState, overrides);
  }

  createRequest<TPayload extends NextBridgeValue>(
    operation: string,
    payload: TPayload,
    options: NextEdgeBridgeRequestOptions = {},
  ): NextEdgeBridgeRequest<TPayload> {
    return {
      operation,
      payload,
      routeSegment: options.routeSegment ?? this.routeSegment,
      ...(options.requestId ? { requestId: options.requestId } : {}),
      boundaryMode: "edge",
      renderEnvironment: this.diagnosticsState.renderEnvironment,
      runtimeFallback: "use_edge_bridge",
      cancellationMode: "explicit_status",
    };
  }

  ok<TPayload extends NextBridgeValue>(payload: TPayload): NextEdgeBridgeResponse<TPayload> {
    return {
      outcome: "ok",
      payload,
      diagnostics: this.diagnostics(),
    };
  }

  err(errorMessage: string): NextEdgeBridgeResponse {
    return {
      outcome: "err",
      errorMessage,
      diagnostics: this.diagnostics(),
    };
  }

  cancelled(errorMessage = "cancelled"): NextEdgeBridgeResponse {
    return {
      outcome: "cancelled",
      errorMessage,
      diagnostics: this.diagnostics(),
    };
  }

  fromOutcome(outcome: BrowserOutcome<NextBridgeValue>): NextEdgeBridgeResponse<NextBridgeValue>;
  fromOutcome<TPayload extends NextBridgeValue>(
    outcome: BrowserOutcome<TPayload>,
  ): NextEdgeBridgeResponse<TPayload> {
    return createNextEdgeBridgeResponseFromOutcome(outcome, this.options);
  }

  unwrapResponse(response: NextEdgeBridgeResponse<NextBridgeValue>): NextBridgeValue;
  unwrapResponse<TPayload extends NextBridgeValue>(
    response: NextEdgeBridgeResponse<TPayload>,
  ): TPayload {
    return unwrapNextEdgeBridgeResponse(response);
  }

  unsupportedRuntimeError(): NextEdgeBridgeRuntimeError {
    return Object.assign(createNextUnsupportedRuntimeError(this.diagnosticsState.runtimeSupport), {
      bridgeDiagnostics: this.diagnostics(),
    });
  }
}

export class NextClientBootstrapAdapter {
  private runtime: BrowserRuntime | null = null;
  private scope: RegionHandle | null = null;
  private owner: NextBootstrapOwner | null = null;
  private readonly owners = new Set<NextBootstrapOwner>();
  private initializationAttempt: NextRuntimeInitializationAttempt | null = null;
  private readonly logEvents: NextBootstrapLogEvent[] = [];
  private snapshotState: NextBootstrapSnapshot;

  constructor(private readonly options: NextClientBootstrapOptions = {}) {
    this.snapshotState = createInitialSnapshot(options);
  }

  snapshot(): NextBootstrapSnapshot {
    return cloneSnapshot(this.snapshotState);
  }

  events(): readonly NextBootstrapLogEvent[] {
    return [...this.logEvents];
  }

  currentRuntime(): BrowserRuntime | null {
    return this.runtime;
  }

  currentScope(): RegionHandle | null {
    return this.scope;
  }

  createLogFields(
    event: NextBootstrapLogEvent,
    overrides: NextBootstrapLogFieldOverrides = {},
  ): Record<string, string> {
    return createNextBootstrapLogFields(event, this.snapshotState, overrides);
  }

  beginHydration(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.transitionTo("hydrating", "beginHydration");
    this.invalidateRuntimeScope("begin_hydration_scope_reset");
    return this.recordEvent("begin_hydration", from);
  }

  completeHydration(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.transitionTo("hydrated", "completeHydration");
    this.snapshotState.environment = "client_hydrated";
    return this.recordEvent("complete_hydration", from);
  }

  async initializeRuntime(): Promise<BrowserOutcome<RegionHandle>> {
    if (this.initializationAttempt) {
      return this.initializationAttempt.result;
    }

    let resolve!: (outcome: BrowserOutcome<RegionHandle>) => void;
    let reject!: (reason: unknown) => void;
    const result = new Promise<BrowserOutcome<RegionHandle>>((onResolve, onReject) => {
      resolve = onResolve;
      reject = onReject;
    });
    let initialize!: () => void;
    const owner: NextBootstrapOwner = {
      runtime: null, scope: null,
      initialized: new Promise<void>((done) => { initialize = done; }), initialize: () => initialize(),
      initializedDone: false, published: false, closing: false, closed: false,
      attempt: null, receipt: null, failures: [],
    };
    this.owners.add(owner);
    const attempt: NextRuntimeInitializationAttempt = { result, cancelled: null, owner };
    // Publish before support detection, option getters, or the factory can reenter.
    this.initializationAttempt = attempt;
    void this.initializeRuntimeAttempt(attempt).then(
      (outcome) => {
        if (this.initializationAttempt === attempt) {
          this.initializationAttempt = null;
        }
        resolve(attempt.cancelled ?? outcome);
      },
      (error: unknown) => {
        if (this.initializationAttempt === attempt) {
          this.initializationAttempt = null;
        }
        if (attempt.cancelled) {
          resolve(attempt.cancelled);
        } else {
          reject(error);
        }
      },
    );
    return result;
  }

  private async initializeRuntimeAttempt(
    attempt: NextRuntimeInitializationAttempt,
  ): Promise<BrowserOutcome<RegionHandle>> {
    const owner = attempt.owner;
    try {
      assertNextRuntimeSupport(
        "client",
        detectNextRuntimeSupport("client", this.options.globalObject),
      );
      if (attempt.cancelled) {
        return attempt.cancelled;
      }

      if (this.snapshotState.phase === "runtime_ready" && this.scope) {
        return OutcomeFactory.ok(this.scope);
      }

      if (this.snapshotState.phase === "runtime_ready") {
        this.snapshotState.runtimeInitialized = false;
        this.forceTransition("hydrated");
        this.snapshotState.environment = "client_hydrated";
        this.cleanupHandles();
        if (attempt.cancelled) {
          return attempt.cancelled;
        }
      }

      if (
        !supportsWasmRuntime(this.snapshotState.environment) ||
        this.snapshotState.phase !== "hydrated"
      ) {
        throw createNextBootstrapStateError(
          "initializeRuntime",
          this.snapshotState.phase,
          `initializeRuntime requires a hydrated client boundary; current phase is ${this.snapshotState.phase}`,
        );
      }

      // A superseded factory may still return a runtime. Its generation was
      // retained before allocation, so replacement cannot overtake its drain.
      const previous = [...this.owners].filter((entry) => entry !== owner && entry.closing);
      if (previous.length > 0) {
        const cleanup = await this.closeOwners(previous);
        if (attempt.cancelled) return attempt.cancelled;
        if (cleanup.outcome !== "ok") return cleanup;
      }

      const from = this.captureTransitionPoint();
      const runtimeOptions = nextClientBrowserRuntimeOptions(this.options);
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      this.snapshotState.runtimeInitAttempts += 1;
      const runtime = await createBrowserRuntime(runtimeOptions);
      if (runtime.outcome === "ok") {
        owner.runtime = captureNextBootstrapOwner(runtime.value);
      }
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      if (runtime.outcome !== "ok") {
        this.markRuntimeFailure(formatOutcomeFailure(runtime), from);
        return attempt.cancelled ?? runtime;
      }

      const label = this.options.label ?? "next-client-bootstrap";
      const consumerVersion = runtime.value.consumerVersion;
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      const entered = runtime.value.enterScope(label, consumerVersion);
      if (entered.outcome === "ok") {
        owner.scope = captureNextBootstrapOwner(entered.value);
      }
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      if (entered.outcome !== "ok") {
        owner.closing = true;
        if (attempt.cancelled) {
          return attempt.cancelled;
        }
        this.markRuntimeFailure(formatOutcomeFailure(entered), from);
        return attempt.cancelled ?? entered;
      }

      this.runtime = runtime.value;
      this.scope = entered.value;
      this.owner = owner;
      owner.published = true;
      this.transitionTo("runtime_ready", "initializeRuntime");
      this.snapshotState.runtimeInitialized = true;
      this.snapshotState.runtimeInitSuccesses += 1;
      this.snapshotState.activeScopeGeneration += 1;
      this.snapshotState.lastError = null;
      this.recordEvent("initialize_runtime", from);
      // A log hook may close this owner and start another initialization.
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      return OutcomeFactory.ok(entered.value);
    } catch (error) {
      if (attempt.cancelled) {
        return attempt.cancelled;
      }
      throw error;
    } finally {
      // Release the acquisition witness before joining cleanup: a close that
      // arrived during the factory already waits on this exact generation.
      owner.initializedDone = true;
      owner.initialize();
      if (!owner.published || owner.closing || attempt.cancelled) {
        await this.closeOwner(owner);
      }
    }
  }

  async ensureRuntimeReady(): Promise<BrowserOutcome<RegionHandle>> {
    if (this.snapshotState.phase === "server_rendered") {
      this.beginHydration();
    }
    if (this.snapshotState.phase === "runtime_failed") {
      this.recover("retry_runtime_init");
    }
    if (this.snapshotState.phase === "hydrating") {
      this.completeHydration();
    }
    return this.initializeRuntime();
  }

  async hydrateAndInitialize(): Promise<BrowserOutcome<RegionHandle>> {
    return this.ensureRuntimeReady();
  }

  runtimeInitFailed(reason: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    if (this.snapshotState.phase !== "hydrated") {
      throw createNextBootstrapStateError(
        "runtimeInitFailed",
        this.snapshotState.phase,
        `runtimeInitFailed is only valid from hydrated; current phase is ${this.snapshotState.phase}`,
      );
    }
    this.transitionTo("runtime_failed", "runtimeInitFailed");
    this.invalidateInitialization(reason);
    this.snapshotState.runtimeFailureCount += 1;
    this.snapshotState.lastError = reason;
    return this.recordEvent("runtime_init_failed", from, reason);
  }

  cancelBootstrap(reason: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.invalidateInitialization(reason);
    this.snapshotState.cancellationCount += 1;
    this.snapshotState.runtimeFailureCount += 1;
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = reason;
    this.cleanupHandles();
    return this.recordEvent("cancel_bootstrap", from, reason);
  }

  hydrationMismatch(reason: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.invalidateInitialization(reason);
    this.snapshotState.hydrationMismatchCount += 1;
    this.snapshotState.runtimeFailureCount += 1;
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = reason;
    this.cleanupHandles();
    return this.recordEvent("hydration_mismatch", from, reason);
  }

  recover(action: NextBootstrapRecoveryAction): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.lastRecoveryAction = action;
    switch (action) {
      case "none":
        break;
      case "reset_to_hydrating":
        this.snapshotState.environment = "client_ssr";
        this.forceTransition("hydrating");
        this.invalidateRuntimeScope("reset_to_hydrating");
        break;
      case "retry_runtime_init":
        this.snapshotState.environment = "client_hydrated";
        this.forceTransition("hydrated");
        this.invalidateRuntimeScope("retry_runtime_init");
        break;
    }
    return this.recordEvent("recover", from, action, undefined, action);
  }

  navigate(navigationType: NextNavigationType, routeSegment: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.routeSegment = routeSegment;

    switch (navigationType) {
      case "soft_navigation":
        this.snapshotState.softNavigationCount += 1;
        break;
      case "hard_navigation":
        this.snapshotState.hardNavigationCount += 1;
        this.snapshotState.environment = "client_ssr";
        this.forceTransition("server_rendered");
        this.invalidateRuntimeScope("hard_navigation_scope_reset");
        break;
      case "popstate":
        this.snapshotState.popstateNavigationCount += 1;
        if (
          !(
            (this.options.popstatePreservesRuntime ?? true) &&
            this.snapshotState.phase === "runtime_ready"
          )
        ) {
          this.snapshotState.environment = "client_ssr";
          this.forceTransition("server_rendered");
          this.invalidateRuntimeScope("popstate_scope_reset");
        }
        break;
    }

    return this.recordEvent(
      "navigate",
      from,
      `nav=${navigationType}, route=${routeSegment}`,
      navigationType,
    );
  }

  hotReload(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.hotReloadCount += 1;
    this.snapshotState.environment = "client_ssr";
    this.forceTransition("hydrating");
    this.invalidateRuntimeScope("hot_reload_scope_reset");
    return this.recordEvent("hot_reload", from);
  }

  cacheRevalidated(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    if (this.snapshotState.phase !== "hydrated" && this.snapshotState.phase !== "runtime_ready") {
      throw createNextBootstrapStateError(
        "cacheRevalidated",
        this.snapshotState.phase,
        `cacheRevalidated requires hydrated or runtime_ready; current phase is ${this.snapshotState.phase}`,
      );
    }

    this.snapshotState.cacheRevalidationCount += 1;
    if (this.snapshotState.phase === "runtime_ready" || this.initializationAttempt) {
      this.snapshotState.environment = "client_hydrated";
      this.forceTransition("hydrated");
      this.invalidateRuntimeScope("cache_revalidation_scope_reset");
    }

    return this.recordEvent("cache_revalidated", from);
  }

  close(reason = "manual_close"): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.invalidateInitialization(reason);
    this.snapshotState.runtimeInitialized = false;
    if (this.snapshotState.phase === "runtime_ready") {
      this.forceTransition("hydrated");
      this.snapshotState.environment = "client_hydrated";
    }
    const failures = this.cleanupHandles();
    this.snapshotState.lastError = failures.length > 0 ? `${reason}; ${failures.join("; ")}` : null;
    return this.recordEvent("close_runtime", from, this.snapshotState.lastError ?? reason);
  }

  /**
   * Detach the current generation and join every owner captured by this call,
   * including a bootstrap that has not returned its runtime yet. Failed owners
   * remain private and retryable; replacement initialization cannot bypass them.
   * Success describes cleanup, independently of the invalidated operation.
   */
  closeAsync(reason = "manual_close"): Promise<BrowserOutcome<void>> {
    if (typeof reason !== "string") {
      return Promise.resolve(nextCleanupFailure("close reason must be a string"));
    }
    const owners = [...this.owners];
    // Only failures already observed before this explicit call may be retried.
    // A new failure from its initial cleanup cannot be hidden by an immediate
    // second native/ABI attempt in the same retirement operation.
    const retries = new Set(owners.filter((entry) => entry.receipt !== null
      && entry.receipt.outcome !== "ok" && entry.attempt === null));
    try { this.close(reason); }
    catch { /* A log observer cannot detach or erase retained cleanup ownership. */ }
    return this.closeOwners(owners, retries);
  }

  /** Retry retained cleanup without admitting a replacement runtime. */
  retire(reason = "manual_close"): Promise<BrowserOutcome<void>> {
    return this.closeAsync(reason);
  }

  private captureTransitionPoint(): {
    phase: NextBootstrapPhase;
    environment: NextRenderEnvironment;
  } {
    this.snapshotState.lastRecoveryAction = "none";
    this.snapshotState.lastError = null;
    return {
      phase: this.snapshotState.phase,
      environment: this.snapshotState.environment,
    };
  }

  private transitionTo(phase: NextBootstrapPhase, action: string): void {
    if (!isValidBootstrapTransition(this.snapshotState.phase, phase)) {
      throw createNextBootstrapStateError(
        action,
        this.snapshotState.phase,
        `${action} cannot transition ${this.snapshotState.phase} -> ${phase}`,
      );
    }
    this.forceTransition(phase);
  }

  private forceTransition(phase: NextBootstrapPhase): void {
    if (this.snapshotState.phase !== phase) {
      this.snapshotState.phase = phase;
      this.snapshotState.phaseHistory = [...this.snapshotState.phaseHistory, phase];
    }
  }

  private markRuntimeFailure(
    detail: string,
    from: {
      phase: NextBootstrapPhase;
      environment: NextRenderEnvironment;
    },
  ): void {
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeFailureCount += 1;
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = detail;
    this.cleanupHandles();
    this.recordEvent("runtime_init_failed", from, detail);
  }

  private invalidateRuntimeScope(reason: string): void {
    this.invalidateInitialization(reason);
    if (this.snapshotState.runtimeInitialized) {
      this.snapshotState.scopeInvalidationCount += 1;
      this.snapshotState.runtimeReinitRequiredCount += 1;
      this.snapshotState.cancellationCount += 1;
      this.snapshotState.lastInvalidatedScopeGeneration = this.snapshotState.activeScopeGeneration;
      this.snapshotState.lastError = reason;
    }
    this.snapshotState.runtimeInitialized = false;
    this.cleanupHandles();
  }

  private invalidateInitialization(reason: string): void {
    const attempt = this.initializationAttempt;
    if (attempt) {
      attempt.owner.closing = true;
      attempt.cancelled = OutcomeFactory.cancelled({
        kind: "next_bootstrap_invalidated",
        phase: "completed",
        origin_region: "next-client-bootstrap",
        origin_task: null,
        timestamp_nanos: 0,
        message: reason,
        truncated: false,
      });
      this.initializationAttempt = null;
    }
  }

  private cleanupHandles(): string[] {
    const owner = this.owner;
    // Close callbacks must never observe or clear a newer owner's handles.
    this.scope = null;
    this.runtime = null;
    this.owner = null;
    if (owner) owner.closing = true;
    const closing = [...this.owners].filter((entry) => entry.closing);
    for (const entry of closing) void this.closeOwner(entry);
    return closing.flatMap((entry) => entry.failures);
  }

  private closeOwner(owner: NextBootstrapOwner, retry = false): Promise<BrowserOutcome<void>> {
    owner.closing = true;
    if (owner.closed) return Promise.resolve(OutcomeFactory.ok(undefined));
    if (owner.attempt) return owner.attempt;
    if (!retry && owner.receipt !== null) return Promise.resolve(owner.receipt);
    let finish!: (receipt: BrowserOutcome<void>) => void;
    const attempt = new Promise<BrowserOutcome<void>>((resolve) => { finish = resolve; });
    owner.attempt = attempt;
    owner.receipt = null;
    owner.failures = [];
    // This record is published before invoking either captured close callback.
    // Legacy synchronous providers still run their callbacks synchronously.
    void (async () => {
      let receipt: BrowserOutcome<void> = OutcomeFactory.ok(undefined);
      try {
        if (!owner.initializedDone) await owner.initialized;
        const asynchronous = owner.scope?.asynchronous || owner.runtime?.asynchronous;
        for (const [kind, handle] of [["scope", owner.scope], ["runtime", owner.runtime]] as const) {
          if (!handle || handle.closed) continue;
          // An async parent may only retire after its child positively drained.
          // Legacy synchronous providers retain their independent best-effort
          // callback order, but even their first refusal remains observable.
          if (receipt.outcome !== "ok" && asynchronous) break;
          let result: BrowserOutcome<void>;
          try {
            const raw = handle.close();
            const awaited = raw !== null && (typeof raw === "object" || typeof raw === "function")
              && typeof (raw as { then?: unknown }).then === "function" ? await raw : raw;
            result = nextCleanupReceipt(awaited);
            if (result.outcome !== "ok") owner.failures.push(`${kind}_close=${formatOutcomeFailure(result)}`);
          } catch (error) {
            result = nextCleanupFailure(error);
            owner.failures.push(`${kind}_close=${nextBootstrapCleanupError(error)}`);
          }
          if (result.outcome === "ok") handle.closed = true;
          else if (receipt.outcome === "ok") receipt = result;
        }
      } catch (error) {
        receipt = nextCleanupFailure(error);
        owner.failures.push(`cleanup=${nextBootstrapCleanupError(error)}`);
      }
      owner.receipt = receipt;
      if (receipt.outcome === "ok") {
        owner.closed = true;
        this.owners.delete(owner);
      }
      if (owner.attempt === attempt) owner.attempt = null;
      finish(receipt);
    })();
    return attempt;
  }

  private async closeOwners(
    owners: readonly NextBootstrapOwner[],
    retries: ReadonlySet<NextBootstrapOwner> = new Set(),
  ): Promise<BrowserOutcome<void>> {
    // Fence every captured generation before its first callback can reenter.
    for (const owner of owners) owner.closing = true;
    const receipts = await Promise.all(owners.map((owner) => this.closeOwner(owner, retries.has(owner))));
    return receipts.find((receipt) => receipt.outcome !== "ok") ?? OutcomeFactory.ok(undefined);
  }

  private recordEvent(
    action: string,
    from: {
      phase: NextBootstrapPhase;
      environment: NextRenderEnvironment;
    },
    detail?: string,
    navigationType?: NextNavigationType,
    recoveryAction: NextBootstrapRecoveryAction = this.snapshotState.lastRecoveryAction,
  ): NextBootstrapLogEvent {
    const event: NextBootstrapLogEvent = {
      action,
      fromPhase: from.phase,
      toPhase: this.snapshotState.phase,
      fromEnvironment: from.environment,
      toEnvironment: this.snapshotState.environment,
      routeSegment: this.snapshotState.routeSegment,
      recoveryAction,
      ...(detail ? { detail } : {}),
      ...(navigationType ? { navigationType } : {}),
    };
    this.logEvents.push(event);
    this.options.onLogEvent?.(event, this.snapshot());
    return event;
  }
}

export function createNextBootstrapAdapter(
  options: NextClientBootstrapOptions = {},
): NextClientBootstrapAdapter {
  return new NextClientBootstrapAdapter(options);
}

export function createNextServerBridgeAdapter(
  options: NextServerBridgeAdapterOptions = {},
): NextServerBridgeAdapter {
  return new NextServerBridgeAdapter(options);
}

export function createNextEdgeBridgeAdapter(
  options: NextEdgeBridgeAdapterOptions = {},
): NextEdgeBridgeAdapter {
  return new NextEdgeBridgeAdapter(options);
}
