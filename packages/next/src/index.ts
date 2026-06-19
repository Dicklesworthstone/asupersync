/**
 * @asupersync/next — Next.js adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser and adds a
 * hydration-safe bootstrap adapter for client-rendered Next.js boundaries.
 */

import {
  Outcome as OutcomeFactory,
  BrowserRuntime,
  RegionHandle,
  createBrowserRuntime,
  detectBrowserRuntimeSupport,
  formatOutcomeFailure,
  type BrowserRuntimeSupportClass,
  type BrowserRuntimeSupportDiagnostics,
  type BrowserRuntimeOptions,
  type BrowserRuntimeSupportReason,
  type AbiFailure,
  type Outcome,
} from "@asupersync/browser";

export * from "@asupersync/browser";

export type NextRuntimeTarget = "client" | "server" | "edge";
export type NextRuntimeSupportReason =
  | BrowserRuntimeSupportReason
  | "bridge_only_server_target"
  | "bridge_only_edge_target";
export type NextRuntimeSupportClass =
  | BrowserRuntimeSupportClass
  | "bridge_only";
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
export type NextNavigationType =
  | "soft_navigation"
  | "hard_navigation"
  | "popstate";
export type NextBootstrapRecoveryAction =
  | "none"
  | "reset_to_hydrating"
  | "retry_runtime_init";

export interface NextRuntimeSupportDiagnostics
  extends Omit<
    BrowserRuntimeSupportDiagnostics,
    "packageName" | "reason" | "supportClass"
  > {
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
  onLogEvent?: (
    event: NextBootstrapLogEvent,
    snapshot: NextBootstrapSnapshot,
  ) => void;
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
export type NextServerBridgeEnvironment =
  | "server_component"
  | "node_server";
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

export interface NextServerBridgeRequest<
  TPayload extends NextBridgeValue = NextBridgeValue,
> {
  operation: string;
  payload: TPayload;
  routeSegment: string;
  requestId?: string;
  boundaryMode: "server";
  renderEnvironment: NextServerBridgeEnvironment;
  runtimeFallback: "use_server_bridge";
  cancellationMode: "explicit_status";
}

export interface NextServerBridgeResponse<
  TPayload extends NextBridgeValue = NextBridgeValue,
> {
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

export interface NextEdgeBridgeRequest<
  TPayload extends NextBridgeValue = NextBridgeValue,
> {
  operation: string;
  payload: TPayload;
  routeSegment: string;
  requestId?: string;
  boundaryMode: "edge";
  renderEnvironment: NextEdgeBridgeEnvironment;
  runtimeFallback: "use_edge_bridge";
  cancellationMode: "explicit_status";
}

export interface NextEdgeBridgeResponse<
  TPayload extends NextBridgeValue = NextBridgeValue,
> {
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

export const NEXT_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME";
export const NEXT_BOOTSTRAP_STATE_ERROR_CODE =
  "ASUPERSYNC_NEXT_BOOTSTRAP_STATE_ERROR";
export const NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE =
  "ASUPERSYNC_NEXT_SERVER_BRIDGE_RESPONSE";
export const NEXT_EDGE_BRIDGE_RESPONSE_ERROR_CODE =
  "ASUPERSYNC_NEXT_EDGE_BRIDGE_RESPONSE";
export const NEXT_BOOTSTRAP_PHASES = [
  "server_rendered",
  "hydrating",
  "hydrated",
  "runtime_ready",
  "runtime_failed",
] as const;
export const NEXT_NAVIGATION_TYPES = [
  "soft_navigation",
  "hard_navigation",
  "popstate",
] as const;
export const NEXT_BOOTSTRAP_RECOVERY_ACTIONS = [
  "none",
  "reset_to_hydrating",
  "retry_runtime_init",
] as const;
export const NEXT_BOUNDARY_MODES = [
  "client",
  "server",
  "edge",
] as const;
export const NEXT_RUNTIME_FALLBACKS = [
  "none_required",
  "defer_until_hydrated",
  "use_server_bridge",
  "use_edge_bridge",
] as const;
export const NEXT_SERVER_BRIDGE_ENVIRONMENTS = [
  "server_component",
  "node_server",
] as const;
export const NEXT_EDGE_BRIDGE_ENVIRONMENTS = ["edge_runtime"] as const;

type BrowserOutcome<T = unknown> = Outcome<T, AbiFailure>;

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
    snapshot.softNavigationCount +
    snapshot.hardNavigationCount +
    snapshot.popstateNavigationCount
  );
}

function cloneSnapshot(
  snapshot: NextBootstrapSnapshot,
): NextBootstrapSnapshot {
  return {
    ...snapshot,
    phaseHistory: [...snapshot.phaseHistory],
  };
}

function createInitialSnapshot(
  options: NextClientBootstrapOptions,
): NextBootstrapSnapshot {
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

function isValidBootstrapTransition(
  from: NextBootstrapPhase,
  to: NextBootstrapPhase,
): boolean {
  if (from === to) {
    return true;
  }

  switch (from) {
    case "server_rendered":
      return to === "hydrating";
    case "hydrating":
      return to === "hydrated" || to === "runtime_failed";
    case "hydrated":
      return (
        to === "runtime_ready" ||
        to === "runtime_failed" ||
        to === "server_rendered"
      );
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

export function nextRuntimeFallbackReason(
  environment: NextRenderEnvironment,
): string {
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

export function createNextServerBridgeResponseFromOutcome<
  TPayload extends NextBridgeValue,
>(
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

export function createNextEdgeBridgeResponseFromOutcome<
  TPayload extends NextBridgeValue,
>(
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
  const message =
    response.errorMessage ?? "bridge response did not include a payload";
  const error = new Error(
    `${response.diagnostics.renderEnvironment}: ${response.outcome}: ${message}`,
  ) as NextServerBridgeResponseError;
  error.code = NEXT_SERVER_BRIDGE_RESPONSE_ERROR_CODE;
  error.bridgeDiagnostics = cloneNextServerBridgeDiagnostics(
    response.diagnostics,
  );
  error.response = {
    ...response,
    diagnostics: cloneNextServerBridgeDiagnostics(response.diagnostics),
  };
  return error;
}

function createNextEdgeBridgeResponseError(
  response: NextEdgeBridgeResponse,
): NextEdgeBridgeResponseError {
  const message =
    response.errorMessage ?? "bridge response did not include a payload";
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

export function unwrapNextServerBridgeResponse<
  TPayload extends NextBridgeValue,
>(response: NextServerBridgeResponse<TPayload>): TPayload {
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
      reason: isServerTarget
        ? "bridge_only_server_target"
        : "bridge_only_edge_target",
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
      : [
          "Import @asupersync/next from client components only.",
          ...browserDiagnostics.guidance,
        ],
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

  createLogFields(
    overrides: NextBootstrapLogFieldOverrides = {},
  ): Record<string, string> {
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

  ok<TPayload extends NextBridgeValue>(
    payload: TPayload,
  ): NextServerBridgeResponse<TPayload> {
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

  fromOutcome(
    outcome: BrowserOutcome<NextBridgeValue>,
  ): NextServerBridgeResponse<NextBridgeValue>;
  fromOutcome<TPayload extends NextBridgeValue>(
    outcome: BrowserOutcome<TPayload>,
  ): NextServerBridgeResponse<TPayload> {
    return createNextServerBridgeResponseFromOutcome(outcome, this.options);
  }

  unwrapResponse(
    response: NextServerBridgeResponse<NextBridgeValue>,
  ): NextBridgeValue;
  unwrapResponse<TPayload extends NextBridgeValue>(
    response: NextServerBridgeResponse<TPayload>,
  ): TPayload {
    return unwrapNextServerBridgeResponse(response);
  }

  unsupportedRuntimeError(): NextServerBridgeRuntimeError {
    return Object.assign(
      createNextUnsupportedRuntimeError(this.diagnosticsState.runtimeSupport),
      { bridgeDiagnostics: this.diagnostics() },
    );
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

  createLogFields(
    overrides: NextBootstrapLogFieldOverrides = {},
  ): Record<string, string> {
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

  ok<TPayload extends NextBridgeValue>(
    payload: TPayload,
  ): NextEdgeBridgeResponse<TPayload> {
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

  fromOutcome(
    outcome: BrowserOutcome<NextBridgeValue>,
  ): NextEdgeBridgeResponse<NextBridgeValue>;
  fromOutcome<TPayload extends NextBridgeValue>(
    outcome: BrowserOutcome<TPayload>,
  ): NextEdgeBridgeResponse<TPayload> {
    return createNextEdgeBridgeResponseFromOutcome(outcome, this.options);
  }

  unwrapResponse(
    response: NextEdgeBridgeResponse<NextBridgeValue>,
  ): NextBridgeValue;
  unwrapResponse<TPayload extends NextBridgeValue>(
    response: NextEdgeBridgeResponse<TPayload>,
  ): TPayload {
    return unwrapNextEdgeBridgeResponse(response);
  }

  unsupportedRuntimeError(): NextEdgeBridgeRuntimeError {
    return Object.assign(
      createNextUnsupportedRuntimeError(this.diagnosticsState.runtimeSupport),
      { bridgeDiagnostics: this.diagnostics() },
    );
  }
}

export class NextClientBootstrapAdapter {
  private runtime: BrowserRuntime | null = null;
  private scope: RegionHandle | null = null;
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
    return this.recordEvent("begin_hydration", from);
  }

  completeHydration(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.transitionTo("hydrated", "completeHydration");
    this.snapshotState.environment = "client_hydrated";
    return this.recordEvent("complete_hydration", from);
  }

  async initializeRuntime(): Promise<BrowserOutcome<RegionHandle>> {
    assertNextRuntimeSupport(
      "client",
      detectNextRuntimeSupport("client", this.options.globalObject),
    );

    if (this.snapshotState.phase === "runtime_ready" && this.scope) {
      return OutcomeFactory.ok(this.scope);
    }

    if (this.snapshotState.phase === "runtime_ready") {
      this.cleanupHandles();
      this.snapshotState.runtimeInitialized = false;
      this.forceTransition("hydrated");
      this.snapshotState.environment = "client_hydrated";
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

    const from = this.captureTransitionPoint();
    this.snapshotState.runtimeInitAttempts += 1;

    const runtime = await createBrowserRuntime(
      nextClientBrowserRuntimeOptions(this.options),
    );
    if (runtime.outcome !== "ok") {
      this.markRuntimeFailure(formatOutcomeFailure(runtime), from);
      return runtime;
    }

    const entered = runtime.value.enterScope(
      this.options.label ?? "next-client-bootstrap",
      this.options.consumerVersion,
    );
    if (entered.outcome !== "ok") {
      runtime.value.close(this.options.consumerVersion);
      this.markRuntimeFailure(formatOutcomeFailure(entered), from);
      return entered;
    }

    this.runtime = runtime.value;
    this.scope = entered.value;
    this.transitionTo("runtime_ready", "initializeRuntime");
    this.snapshotState.runtimeInitialized = true;
    this.snapshotState.runtimeInitSuccesses += 1;
    this.snapshotState.activeScopeGeneration += 1;
    this.snapshotState.lastError = null;
    this.recordEvent("initialize_runtime", from);
    return OutcomeFactory.ok(entered.value);
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
    this.snapshotState.runtimeFailureCount += 1;
    this.snapshotState.lastError = reason;
    return this.recordEvent("runtime_init_failed", from, reason);
  }

  cancelBootstrap(reason: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.cancellationCount += 1;
    this.snapshotState.runtimeFailureCount += 1;
    this.cleanupHandles();
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = reason;
    return this.recordEvent("cancel_bootstrap", from, reason);
  }

  hydrationMismatch(reason: string): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.hydrationMismatchCount += 1;
    this.snapshotState.runtimeFailureCount += 1;
    this.cleanupHandles();
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = reason;
    return this.recordEvent("hydration_mismatch", from, reason);
  }

  recover(action: NextBootstrapRecoveryAction): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    switch (action) {
      case "none":
        break;
      case "reset_to_hydrating":
        this.snapshotState.environment = "client_ssr";
        this.snapshotState.runtimeInitialized = false;
        this.forceTransition("hydrating");
        break;
      case "retry_runtime_init":
        this.snapshotState.environment = "client_hydrated";
        this.forceTransition("hydrated");
        break;
    }
    this.snapshotState.lastRecoveryAction = action;
    return this.recordEvent("recover", from, action, undefined, action);
  }

  navigate(
    navigationType: NextNavigationType,
    routeSegment: string,
  ): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    this.snapshotState.routeSegment = routeSegment;

    switch (navigationType) {
      case "soft_navigation":
        this.snapshotState.softNavigationCount += 1;
        break;
      case "hard_navigation":
        this.snapshotState.hardNavigationCount += 1;
        this.invalidateRuntimeScope("hard_navigation_scope_reset");
        this.snapshotState.environment = "client_ssr";
        this.forceTransition("server_rendered");
        break;
      case "popstate":
        this.snapshotState.popstateNavigationCount += 1;
        if (
          !(
            (this.options.popstatePreservesRuntime ?? true) &&
            this.snapshotState.phase === "runtime_ready"
          )
        ) {
          this.invalidateRuntimeScope("popstate_scope_reset");
          this.snapshotState.environment = "client_ssr";
          this.forceTransition("server_rendered");
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
    this.invalidateRuntimeScope("hot_reload_scope_reset");
    this.snapshotState.environment = "client_ssr";
    this.forceTransition("hydrating");
    return this.recordEvent("hot_reload", from);
  }

  cacheRevalidated(): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    if (
      this.snapshotState.phase !== "hydrated" &&
      this.snapshotState.phase !== "runtime_ready"
    ) {
      throw createNextBootstrapStateError(
        "cacheRevalidated",
        this.snapshotState.phase,
        `cacheRevalidated requires hydrated or runtime_ready; current phase is ${this.snapshotState.phase}`,
      );
    }

    this.snapshotState.cacheRevalidationCount += 1;
    if (this.snapshotState.phase === "runtime_ready") {
      this.invalidateRuntimeScope("cache_revalidation_scope_reset");
      this.snapshotState.environment = "client_hydrated";
      this.forceTransition("hydrated");
    }

    return this.recordEvent("cache_revalidated", from);
  }

  close(reason = "manual_close"): NextBootstrapLogEvent {
    const from = this.captureTransitionPoint();
    const failures = this.cleanupHandles();
    this.snapshotState.runtimeInitialized = false;
    if (this.snapshotState.phase === "runtime_ready") {
      this.forceTransition("hydrated");
      this.snapshotState.environment = "client_hydrated";
    }
    this.snapshotState.lastError =
      failures.length > 0 ? `${reason}; ${failures.join("; ")}` : null;
    return this.recordEvent(
      "close_runtime",
      from,
      this.snapshotState.lastError ?? reason,
    );
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

  private transitionTo(
    phase: NextBootstrapPhase,
    action: string,
  ): void {
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
      this.snapshotState.phaseHistory = [
        ...this.snapshotState.phaseHistory,
        phase,
      ];
    }
  }

  private markRuntimeFailure(
    detail: string,
    from: {
      phase: NextBootstrapPhase;
      environment: NextRenderEnvironment;
    },
  ): void {
    this.cleanupHandles();
    this.forceTransition("runtime_failed");
    this.snapshotState.runtimeFailureCount += 1;
    this.snapshotState.runtimeInitialized = false;
    this.snapshotState.lastError = detail;
    this.recordEvent("runtime_init_failed", from, detail);
  }

  private invalidateRuntimeScope(reason: string): void {
    if (this.snapshotState.runtimeInitialized) {
      this.snapshotState.scopeInvalidationCount += 1;
      this.snapshotState.runtimeReinitRequiredCount += 1;
      this.snapshotState.cancellationCount += 1;
      this.snapshotState.lastInvalidatedScopeGeneration =
        this.snapshotState.activeScopeGeneration;
      this.snapshotState.lastError = reason;
    }
    this.cleanupHandles();
    this.snapshotState.runtimeInitialized = false;
  }

  private cleanupHandles(): string[] {
    const failures: string[] = [];

    if (this.scope) {
      const closeScope = this.scope.close(this.options.consumerVersion);
      if (closeScope.outcome !== "ok") {
        failures.push(`scope_close=${formatOutcomeFailure(closeScope)}`);
      }
      this.scope = null;
    }

    if (this.runtime) {
      const closeRuntime = this.runtime.close(this.options.consumerVersion);
      if (closeRuntime.outcome !== "ok") {
        failures.push(`runtime_close=${formatOutcomeFailure(closeRuntime)}`);
      }
      this.runtime = null;
    }

    return failures;
  }

  private recordEvent(
    action: string,
    from: {
      phase: NextBootstrapPhase;
      environment: NextRenderEnvironment;
    },
    detail?: string,
    navigationType?: NextNavigationType,
    recoveryAction: NextBootstrapRecoveryAction = this.snapshotState
      .lastRecoveryAction,
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
