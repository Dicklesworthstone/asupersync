/**
 * @asupersync/browser — High-level Browser Edition SDK surface.
 *
 * Wraps the low-level runtime bindings from @asupersync/browser-core with a
 * deterministic, diagnostics-friendly package API for ordinary browser users.
 */

import initWasm, {
  BUDGET_BOUNDS,
  CANCELLATION_PHASE_ORDER,
  ERROR_CODES,
  RECOVERABILITY_LEVELS,
  BaseHandle,
  CancellationToken as CoreCancellationToken,
  FetchHandle as CoreFetchHandle,
  Outcome as OutcomeFactory,
  RegionHandle as CoreRegionHandle,
  RuntimeHandle as CoreRuntimeHandle,
  TaskHandle as CoreTaskHandle,
  abiFingerprint,
  abiVersion,
  createBudget,
  fetchRequest,
  rawBindings,
  runtimeClose,
  runtimeCreate,
  scopeClose,
  scopeEnter,
  taskCancel,
  taskJoin,
  taskSpawn,
  websocketClose,
  websocketOpen,
  websocketRecv,
  websocketSend,
  type AbiCancellation,
  type AbiFailure,
  type AbiVersion,
  type Budget,
  type ErrorCode,
  type FetchRequest,
  type HandleKind,
  type HandleRef,
  type InitInput,
  type Outcome,
  type Recoverability,
  type ScopeEnterRequest,
  type TaskCancelRequest,
  type TaskSpawnRequest,
  type WasmValue,
  type WebSocketCancelRequest,
  type WebSocketCloseRequest,
  type WebSocketOpenRequest,
  type WebSocketRecvRequest,
  type WebSocketSendRequest,
} from "@asupersync/browser-core";
import abiMetadata from "@asupersync/browser-core/abi-metadata.json";

export {
  BUDGET_BOUNDS,
  CANCELLATION_PHASE_ORDER,
  ERROR_CODES,
  RECOVERABILITY_LEVELS,
  BaseHandle,
  CoreCancellationToken,
  CoreFetchHandle,
  CoreRegionHandle,
  CoreRuntimeHandle,
  CoreTaskHandle,
  OutcomeFactory as Outcome,
  abiFingerprint,
  abiMetadata,
  abiVersion,
  createBudget,
  fetchRequest,
  initWasm as init,
  rawBindings,
  runtimeClose,
  runtimeCreate,
  scopeClose,
  scopeEnter,
  taskCancel,
  taskJoin,
  taskSpawn,
  websocketClose,
  websocketOpen,
  websocketRecv,
  websocketSend,
};

export type {
  AbiCancellation,
  AbiFailure,
  AbiVersion,
  Budget,
  ErrorCode,
  FetchRequest,
  HandleKind,
  HandleRef,
  InitInput,
  Outcome,
  Recoverability,
  ScopeEnterRequest,
  TaskCancelRequest,
  TaskSpawnRequest,
  WasmValue,
  WebSocketCancelRequest,
  WebSocketCloseRequest,
  WebSocketOpenRequest,
  WebSocketRecvRequest,
  WebSocketSendRequest,
};

export type BrowserAbiMetadata = typeof abiMetadata;
type BrowserOutcome<T = unknown> = Outcome<T, AbiFailure>;

export interface BrowserRuntimeOptions {
  wasmInput?: InitInput;
  consumerVersion?: AbiVersion | null;
  eagerInit?: boolean;
}

export interface BrowserScopeOptions {
  label?: string;
  consumerVersion?: AbiVersion | null;
}

export interface BrowserSdkDiagnostics {
  abiVersion: AbiVersion;
  abiFingerprint: number;
  abiMetadata: BrowserAbiMetadata;
  consumerVersion: AbiVersion | null;
}

export interface CancellationTokenOptions {
  kind: string;
  message?: string;
  consumerVersion?: AbiVersion | null;
}

export interface BrowserCapabilitySnapshot {
  hasAbortController: boolean;
  hasDocument: boolean;
  hasFetch: boolean;
  hasWebAssembly: boolean;
  hasWebSocket: boolean;
  hasWindow: boolean;
}

export type BrowserRuntimeSupportReason =
  | "missing_global_this"
  | "missing_browser_dom"
  | "missing_webassembly"
  | "supported";

export interface BrowserRuntimeSupportDiagnostics {
  supported: boolean;
  packageName: "@asupersync/browser";
  reason: BrowserRuntimeSupportReason;
  message: string;
  guidance: string[];
  capabilities: BrowserCapabilitySnapshot;
}

export const BROWSER_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME";

function browserCapabilitySnapshot(
  globalObject: Record<string, unknown> | undefined,
): BrowserCapabilitySnapshot {
  return {
    hasAbortController: typeof globalObject?.AbortController === "function",
    hasDocument: typeof globalObject?.document === "object",
    hasFetch: typeof globalObject?.fetch === "function",
    hasWebAssembly: typeof globalObject?.WebAssembly === "object",
    hasWebSocket: typeof globalObject?.WebSocket === "function",
    hasWindow: typeof globalObject?.window === "object",
  };
}

export function detectBrowserRuntimeSupport(
  globalObject:
    | Record<string, unknown>
    | undefined = typeof globalThis === "object" && globalThis !== null
    ? (globalThis as unknown as Record<string, unknown>)
    : undefined,
): BrowserRuntimeSupportDiagnostics {
  const capabilities = browserCapabilitySnapshot(globalObject);
  const sharedGuidance = [
    "Load @asupersync/browser only in client-hydrated browser boundaries.",
    "For Next.js server or edge code, prefer @asupersync/next bridge-only adapters instead of direct BrowserRuntime creation.",
  ];

  if (!globalObject) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      reason: "missing_global_this",
      message:
        "@asupersync/browser requires a browser-like globalThis to create or enter runtime scopes.",
      guidance: sharedGuidance,
      capabilities,
    };
  }

  if (!capabilities.hasWindow || !capabilities.hasDocument) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      reason: "missing_browser_dom",
      message:
        "@asupersync/browser direct runtime APIs are unsupported outside a real browser window/document environment.",
      guidance: [
        "Move BrowserRuntime creation behind a browser-only entrypoint.",
        ...sharedGuidance,
      ],
      capabilities,
    };
  }

  if (!capabilities.hasWebAssembly) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      reason: "missing_webassembly",
      message:
        "@asupersync/browser requires WebAssembly support in the current browser runtime.",
      guidance: [
        "Use a browser/runtime with WebAssembly enabled before initializing Browser Edition.",
        ...sharedGuidance,
      ],
      capabilities,
    };
  }

  return {
    supported: true,
    packageName: "@asupersync/browser",
    reason: "supported",
    message: "@asupersync/browser runtime prerequisites are available.",
    guidance: [],
    capabilities,
  };
}

export function createUnsupportedRuntimeError(
  diagnostics: BrowserRuntimeSupportDiagnostics,
): Error & {
  code: typeof BROWSER_UNSUPPORTED_RUNTIME_CODE;
  diagnostics: BrowserRuntimeSupportDiagnostics;
} {
  const error = new Error(
    `${diagnostics.packageName}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_UNSUPPORTED_RUNTIME_CODE;
    diagnostics: BrowserRuntimeSupportDiagnostics;
  };
  error.code = BROWSER_UNSUPPORTED_RUNTIME_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertBrowserRuntimeSupport(
  diagnostics: BrowserRuntimeSupportDiagnostics = detectBrowserRuntimeSupport(),
): BrowserRuntimeSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createUnsupportedRuntimeError(diagnostics);
  }
  return diagnostics;
}

function mapOutcome<T, U>(
  outcome: BrowserOutcome<T>,
  map: (value: T) => U,
): BrowserOutcome<U> {
  if (outcome.outcome === "ok") {
    return OutcomeFactory.ok(map(outcome.value));
  }
  return outcome as BrowserOutcome<U>;
}

function asCoreRegionHandle(
  handle: RegionHandle | CoreRegionHandle | HandleRef,
): CoreRegionHandle {
  if (handle instanceof RegionHandle) {
    return handle.core;
  }
  if (handle instanceof CoreRegionHandle) {
    return handle;
  }
  return new CoreRegionHandle(handle);
}

function asCoreTaskHandle(
  handle: TaskHandle | CoreTaskHandle | HandleRef,
): CoreTaskHandle {
  if (handle instanceof TaskHandle) {
    return handle.core;
  }
  if (handle instanceof CoreTaskHandle) {
    return handle;
  }
  return new CoreTaskHandle(handle);
}

function asCoreFetchHandle(
  handle: FetchHandle | CoreFetchHandle | HandleRef,
): CoreFetchHandle {
  if (handle instanceof FetchHandle) {
    return handle.core;
  }
  if (handle instanceof CoreFetchHandle) {
    return handle;
  }
  return new CoreFetchHandle(handle);
}

export function createBrowserSdkDiagnostics(
  consumerVersion: AbiVersion | null = null,
): BrowserSdkDiagnostics {
  return {
    abiVersion: abiVersion(),
    abiFingerprint: abiFingerprint(),
    abiMetadata,
    consumerVersion,
  };
}

export function formatOutcomeFailure(outcome: Exclude<BrowserOutcome, { outcome: "ok" }>): string {
  switch (outcome.outcome) {
    case "err":
      return `${outcome.failure.code}: ${outcome.failure.message}`;
    case "cancelled":
      return `${outcome.cancellation.kind}: ${outcome.cancellation.message ?? "cancelled"}`;
    case "panicked":
      return `panicked: ${outcome.message}`;
  }
}

export function unwrapOutcome<T>(outcome: BrowserOutcome<T>): T {
  if (outcome.outcome === "ok") {
    return outcome.value;
  }
  throw new Error(formatOutcomeFailure(outcome));
}

export class BrowserRuntime {
  readonly diagnostics: BrowserSdkDiagnostics;

  constructor(
    readonly core: CoreRuntimeHandle,
    readonly consumerVersion: AbiVersion | null = null,
  ) {
    this.diagnostics = createBrowserSdkDiagnostics(consumerVersion);
  }

  toJSON(): HandleRef {
    return this.core.toJSON();
  }

  close(
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    return runtimeClose(this.core, consumerVersion);
  }

  enterScope(
    label?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<RegionHandle> {
    return mapOutcome(
      scopeEnter({ parent: this.core, label }, consumerVersion),
      (handle) => new RegionHandle(handle, consumerVersion, this),
    );
  }

  async withScope<T>(
    fn: (scope: RegionHandle) => Promise<BrowserOutcome<T>> | BrowserOutcome<T>,
    options: BrowserScopeOptions = {},
  ): Promise<BrowserOutcome<T>> {
    const consumerVersion = options.consumerVersion ?? this.consumerVersion;
    const entered = this.enterScope(options.label, consumerVersion);
    if (entered.outcome !== "ok") {
      return entered;
    }
    const scope = entered.value;
    try {
      return await fn(scope);
    } finally {
      scope.close(consumerVersion);
    }
  }
}

export class RegionHandle {
  constructor(
    readonly core: CoreRegionHandle,
    readonly consumerVersion: AbiVersion | null = null,
    readonly runtime: BrowserRuntime | null = null,
  ) {}

  toJSON(): HandleRef {
    return this.core.toJSON();
  }

  close(
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    return scopeClose(this.core, consumerVersion);
  }

  enterScope(
    label?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<RegionHandle> {
    return mapOutcome(
      scopeEnter({ parent: this.core, label }, consumerVersion),
      (handle) => new RegionHandle(handle, consumerVersion, this.runtime),
    );
  }

  spawnTask(
    options: Omit<TaskSpawnRequest, "scope"> = {},
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<TaskHandle> {
    return mapOutcome(
      taskSpawn({ scope: this.core, ...options }, consumerVersion),
      (handle) => new TaskHandle(handle, consumerVersion),
    );
  }

  fetchRequest(
    options: Omit<FetchRequest, "scope">,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<FetchHandle> {
    return mapOutcome(
      fetchRequest({ scope: this.core, ...options }, consumerVersion),
      (handle) => new FetchHandle(handle, consumerVersion),
    );
  }

  openWebSocket(
    url: string,
    protocols?: string[],
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<TaskHandle> {
    return mapOutcome(
      websocketOpen({ scope: this.core, url, protocols }, consumerVersion),
      (handle) => new TaskHandle(handle, consumerVersion),
    );
  }
}

export class TaskHandle {
  constructor(
    readonly core: CoreTaskHandle,
    readonly consumerVersion: AbiVersion | null = null,
  ) {}

  toJSON(): HandleRef {
    return this.core.toJSON();
  }

  join(
    outcome: BrowserOutcome,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<WasmValue> {
    return taskJoin(this.core, outcome, consumerVersion);
  }

  cancel(
    tokenOrKind: CancellationToken | string,
    message?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    if (tokenOrKind instanceof CancellationToken) {
      return tokenOrKind.cancel(this, consumerVersion);
    }
    return taskCancel(
      { task: this.core, kind: tokenOrKind, message },
      consumerVersion,
    );
  }
}

export class FetchHandle {
  constructor(
    readonly core: CoreFetchHandle,
    readonly consumerVersion: AbiVersion | null = null,
  ) {}

  toJSON(): HandleRef {
    return this.core.toJSON();
  }
}

export class CancellationToken {
  readonly kind: string;
  readonly message?: string;
  readonly consumerVersion: AbiVersion | null;

  constructor(
    kindOrOptions: string | CancellationTokenOptions,
    message?: string,
    consumerVersion: AbiVersion | null = null,
  ) {
    if (typeof kindOrOptions === "string") {
      this.kind = kindOrOptions;
      this.message = message;
      this.consumerVersion = consumerVersion;
      return;
    }
    this.kind = kindOrOptions.kind;
    this.message = kindOrOptions.message;
    this.consumerVersion = kindOrOptions.consumerVersion ?? null;
  }

  static user(
    message?: string,
    consumerVersion: AbiVersion | null = null,
  ): CancellationToken {
    return new CancellationToken("user", message, consumerVersion);
  }

  static timeout(
    message?: string,
    consumerVersion: AbiVersion | null = null,
  ): CancellationToken {
    return new CancellationToken("timeout", message, consumerVersion);
  }

  withMessage(message?: string): CancellationToken {
    return new CancellationToken(this.kind, message, this.consumerVersion);
  }

  cancel(
    task: TaskHandle | CoreTaskHandle | HandleRef,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    return taskCancel(
      {
        task: asCoreTaskHandle(task),
        kind: this.kind,
        message: this.message,
      },
      consumerVersion,
    );
  }

  toCancellation(
    phase: AbiCancellation["phase"] = "requested",
  ): AbiCancellation {
    return {
      kind: this.kind,
      phase,
      origin_region: "browser-sdk",
      origin_task: null,
      timestamp_nanos: 0,
      message: this.message ?? null,
      truncated: false,
    };
  }
}

export function createCancellationToken(
  kindOrOptions: string | CancellationTokenOptions,
  message?: string,
  consumerVersion: AbiVersion | null = null,
): CancellationToken {
  return new CancellationToken(kindOrOptions, message, consumerVersion);
}

export async function createBrowserRuntime(
  options: BrowserRuntimeOptions = {},
): Promise<BrowserOutcome<BrowserRuntime>> {
  const consumerVersion = options.consumerVersion ?? null;
  assertBrowserRuntimeSupport();
  if (options.eagerInit !== false) {
    await initWasm(options.wasmInput);
  }
  return mapOutcome(runtimeCreate(consumerVersion), (handle) => {
    return new BrowserRuntime(handle, consumerVersion);
  });
}

export async function createBrowserScope(
  options: BrowserRuntimeOptions & BrowserScopeOptions = {},
): Promise<BrowserOutcome<RegionHandle>> {
  assertBrowserRuntimeSupport();
  const runtime = await createBrowserRuntime(options);
  if (runtime.outcome !== "ok") {
    return runtime;
  }
  const consumerVersion = options.consumerVersion ?? null;
  const entered = runtime.value.enterScope(options.label, consumerVersion);
  if (entered.outcome !== "ok") {
    runtime.value.close(consumerVersion);
    return entered;
  }
  return entered;
}

export default initWasm;
