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
  webtransportCancel,
  webtransportClose,
  webtransportOpen,
  webtransportRecv,
  webtransportSend,
  type AbiCancellation,
  type AbiFailure,
  type AbiVersion,
  type Budget,
  type ErrorCode,
  type FetchRequest,
  type HandleKind,
  type HandleRef,
  type InitInput,
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
  type WebTransportCancelRequest,
  type WebTransportCloseRequest,
  type WebTransportOpenRequest,
  type WebTransportRecvRequest,
  type WebTransportSendRequest,
} from "@asupersync/browser-core";
import abiMetadata from "@asupersync/browser-core/abi-metadata.json";
import type { BrowserTraceRecord } from "./tracing.js";

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
  webtransportCancel,
  webtransportClose,
  webtransportOpen,
  webtransportRecv,
  webtransportSend,
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
  WebTransportCancelRequest,
  WebTransportCloseRequest,
  WebTransportOpenRequest,
  WebTransportRecvRequest,
  WebTransportSendRequest,
};

export type BrowserAbiMetadata = typeof abiMetadata;
type BrowserOutcome<T = unknown> = import("@asupersync/browser-core").Outcome<T, AbiFailure>;

export interface BrowserRuntimeOptions {
  wasmInput?: InitInput;
  consumerVersion?: AbiVersion | null;
  eagerInit?: boolean;
  globalObject?: Record<string, unknown>;
  preferredLane?: BrowserExecutionLane | null;
  healthPolicy?: Partial<BrowserLaneHealthPolicy>;
  healthScopeKey?: string | null;
  now?: () => number;
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
  executionLadder: BrowserExecutionLadderDiagnostics;
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
  hasIndexedDb: boolean;
  hasLocalStorage: boolean;
  hasWebAssembly: boolean;
  hasWebTransport: boolean;
  hasWebSocket: boolean;
  hasWindow: boolean;
}

export type BrowserRuntimeSupportClass =
  | "direct_runtime_supported"
  | "unsupported";

export type BrowserRuntimeContext =
  | "browser_main_thread"
  | "dedicated_worker"
  | "unknown";

export type BrowserRuntimeSupportReason =
  | "missing_global_this"
  | "service_worker_not_yet_shipped"
  | "shared_worker_not_yet_shipped"
  | "unsupported_runtime_context"
  | "missing_webassembly"
  | "supported";

export interface BrowserRuntimeSupportDiagnostics {
  supported: boolean;
  packageName: "@asupersync/browser";
  supportClass: BrowserRuntimeSupportClass;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserRuntimeSupportReason;
  message: string;
  guidance: string[];
  capabilities: BrowserCapabilitySnapshot;
}

export const BROWSER_EXECUTION_POLICY_SCHEMA_VERSION =
  "wasm-browser-execution-ladder-v1";
export const BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE =
  "lane.browser.main_thread.direct_runtime";
export const BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE =
  "lane.browser.dedicated_worker.direct_runtime";
export const BROWSER_UNSUPPORTED_LANE = "lane.unsupported";

export type BrowserExecutionHostRole =
  | "browser_main_thread"
  | "dedicated_worker"
  | "service_worker"
  | "shared_worker"
  | "non_browser_or_unknown";

export type BrowserExecutionLane =
  | typeof BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE
  | typeof BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
  | typeof BROWSER_UNSUPPORTED_LANE;

export type BrowserExecutionLaneKind = "direct_runtime" | "unsupported";

export type BrowserExecutionReasonCode =
  | "supported"
  | "candidate_host_role_mismatch"
  | "candidate_prerequisite_missing"
  | "candidate_lane_unhealthy"
  | "demote_due_to_lane_health"
  | "downgrade_to_server_bridge"
  | "downgrade_to_edge_bridge"
  | "downgrade_to_websocket_or_fetch"
  | "downgrade_to_export_bytes_for_download"
  | "service_worker_direct_runtime_not_shipped"
  | "shared_worker_direct_runtime_not_shipped"
  | "shared_array_buffer_requires_cross_origin_isolation"
  | "missing_global_this"
  | "missing_webassembly"
  | "unsupported_runtime_context"
  | "non_browser_runtime";

export type BrowserExecutionLaneReason = BrowserExecutionReasonCode;

export type BrowserLaneHealthStatus =
  | "healthy"
  | "retrying"
  | "demoted";

export type BrowserLaneHealthTrigger =
  | "runtime_init_failure"
  | "worker_bootstrap_timeout"
  | "worker_crash"
  | "replay_integrity_failure"
  | "prerequisite_drift"
  | "overload_instability"
  | "manual_reset";

export interface BrowserLaneHealthPolicy {
  maxConsecutiveFailures: number;
  cooldownMs: number;
}

export interface BrowserLaneHealthSnapshot {
  laneId: BrowserExecutionLane;
  status: BrowserLaneHealthStatus;
  failureCount: number;
  retryBudgetRemaining: number;
  cooldownMs: number;
  cooldownUntilMs: number | null;
  lastTrigger: BrowserLaneHealthTrigger | null;
  lastMessage: string | null;
  lastTransitionAtMs: number | null;
  demotedToLaneId: BrowserExecutionLane | null;
}

export interface BrowserLaneHealthDiagnostics extends BrowserLaneHealthSnapshot {
  scopeKey: string;
}

export interface BrowserLaneHealthOptions {
  globalObject?: Record<string, unknown>;
  laneId?: BrowserExecutionLane;
  healthPolicy?: Partial<BrowserLaneHealthPolicy>;
  healthScopeKey?: string | null;
  now?: () => number;
}

export interface BrowserLaneHealthEventOptions extends BrowserLaneHealthOptions {
  trigger: Exclude<BrowserLaneHealthTrigger, "manual_reset">;
  message?: string;
}

export interface BrowserExecutionLaneCandidate {
  laneId: BrowserExecutionLane;
  laneKind: BrowserExecutionLaneKind;
  laneRank: number;
  hostRole: BrowserExecutionHostRole;
  supportClass: BrowserRuntimeSupportClass;
  fallbackLaneId: BrowserExecutionLane | null;
  available: boolean;
  selected: boolean;
  reasonCode: BrowserExecutionReasonCode;
  message: string;
  guidance: string[];
}

export interface BrowserExecutionLadderDiagnostics {
  supported: boolean;
  preferredLane: BrowserExecutionLane | null;
  selectedLane: BrowserExecutionLane;
  laneId: BrowserExecutionLane;
  laneKind: BrowserExecutionLaneKind;
  laneRank: number;
  hostRole: BrowserExecutionHostRole;
  supportClass: BrowserRuntimeSupportClass;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserExecutionReasonCode;
  reasonCode: BrowserExecutionReasonCode;
  message: string;
  guidance: string[];
  fallbackLaneId: BrowserExecutionLane | null;
  downgradeOrder: BrowserExecutionLane[];
  policySchemaVersion: typeof BROWSER_EXECUTION_POLICY_SCHEMA_VERSION;
  reproCommand: string;
  candidates: BrowserExecutionLaneCandidate[];
  health: BrowserLaneHealthDiagnostics;
  runtimeSupport: BrowserRuntimeSupportDiagnostics;
  capabilities: BrowserCapabilitySnapshot;
}

export interface BrowserRuntimeSelectionResult {
  executionLadder: BrowserExecutionLadderDiagnostics;
  runtime: BrowserRuntime | null;
  outcome: BrowserOutcome<BrowserRuntime> | null;
}

export interface BrowserScopeSelectionResult {
  executionLadder: BrowserExecutionLadderDiagnostics;
  runtime: BrowserRuntime | null;
  scope: RegionHandle | null;
  outcome: BrowserOutcome<RegionHandle> | null;
}

export const BROWSER_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME";
export const BROWSER_WEBTRANSPORT_UNSUPPORTED_CODE =
  "ASUPERSYNC_BROWSER_WEBTRANSPORT_UNSUPPORTED";
export const BROWSER_STORAGE_UNSUPPORTED_CODE =
  "ASUPERSYNC_BROWSER_STORAGE_UNSUPPORTED";
export const BROWSER_STORAGE_OPERATION_FAILED_CODE =
  "ASUPERSYNC_BROWSER_STORAGE_OPERATION_FAILED";
export const BROWSER_ARTIFACT_OPERATION_FAILED_CODE =
  "ASUPERSYNC_BROWSER_ARTIFACT_OPERATION_FAILED";
export const BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE =
  "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED";

export type BrowserWebTransportSupportReason =
  | BrowserRuntimeSupportReason
  | "missing_webtransport"
  | "missing_datagrams";

export interface BrowserWebTransportSupportDiagnostics {
  supported: boolean;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserWebTransportSupportReason;
  message: string;
  guidance: string[];
  capabilities: BrowserCapabilitySnapshot;
}

export interface BrowserWebTransportOpenOptions {
  allowPooling?: boolean;
  cancelKind?: string;
  closeCode?: number;
  congestionControl?: "default" | "low-latency" | "throughput";
  label?: string;
  requireUnreliableDatagrams?: boolean;
}

export interface BrowserWebTransportCloseOptions {
  closeCode?: number;
  reason?: string;
}

export type BrowserWebTransportPayload =
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView
  | number[];

export type BrowserStorageBackend = "indexeddb" | "localstorage";

export type BrowserStorageSupportReason =
  | BrowserRuntimeSupportReason
  | "missing_indexeddb"
  | "missing_local_storage";

export interface BrowserStorageSupportDiagnostics {
  supported: boolean;
  backend: BrowserStorageBackend;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserStorageSupportReason;
  message: string;
  guidance: string[];
  capabilities: BrowserCapabilitySnapshot;
}

export interface BrowserStorageOptions {
  backend?: BrowserStorageBackend;
  dbName?: string;
  globalObject?: Record<string, unknown>;
  storeName?: string;
  version?: number;
}

export type BrowserStorageValue =
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView
  | number[];

export type BrowserStorageOperation =
  | "get"
  | "set"
  | "delete"
  | "list_keys"
  | "clear_namespace";

export type BrowserStorageOperationFailureReason =
  | "unsupported_environment"
  | "blocked_upgrade"
  | "access_denied"
  | "quota_exceeded"
  | "transaction_failed"
  | "transaction_aborted"
  | "request_failed";

export interface BrowserStorageOperationDiagnostics {
  backend: BrowserStorageBackend;
  operation: BrowserStorageOperation;
  namespace: string;
  key?: string;
  reason: BrowserStorageOperationFailureReason;
  message: string;
  guidance: string[];
  runtimeContext: BrowserRuntimeContext;
  capabilities: BrowserCapabilitySnapshot;
}

export type BrowserArtifactKind = "trace" | "crashpack" | "evidence" | "custom";

export type BrowserArtifactFormat = "binary" | "json" | "text";

export type BrowserArtifactOperation =
  | "persist"
  | "list"
  | "export"
  | "export_archive"
  | "delete"
  | "clear"
  | "download"
  | "download_archive";

export type BrowserArtifactFailureReason =
  | "unsupported_environment"
  | "payload_too_large"
  | "quota_exceeded"
  | "artifact_not_found"
  | "storage_failed"
  | "serialization_failed"
  | "corrupt_index"
  | "download_unavailable";

export interface BrowserArtifactRetentionPolicy {
  maxArtifacts: number;
  maxTotalBytes: number;
  maxArtifactBytes: number;
  quotaStrategy: "evict_oldest" | "fail";
}

export interface BrowserArtifactStoreOptions extends BrowserStorageOptions {
  namespace?: string;
  retention?: Partial<BrowserArtifactRetentionPolicy>;
}

export type BrowserArtifactValue =
  | BrowserStorageValue
  | string
  | object
  | number
  | boolean
  | null;

export interface BrowserArtifactPersistRequest {
  kind: BrowserArtifactKind;
  value: BrowserArtifactValue;
  id?: string;
  filename?: string;
  format?: BrowserArtifactFormat;
  contentType?: string;
  tags?: string[];
}

export interface BrowserArtifactRecord {
  id: string;
  kind: BrowserArtifactKind;
  format: BrowserArtifactFormat;
  filename: string;
  contentType: string;
  byteLength: number;
  sequence: number;
  tags: string[];
}

export interface BrowserArtifactPersistResult {
  artifact: BrowserArtifactRecord;
  evictedArtifactIds: string[];
  totalArtifacts: number;
  totalBytes: number;
}

export interface BrowserArtifactExport {
  artifact: BrowserArtifactRecord;
  bytes: Uint8Array;
  blob: Blob | null;
  contentType: string;
  filename: string;
}

export interface BrowserArtifactArchiveEntry {
  artifact: BrowserArtifactRecord;
  payloadBase64: string;
}

export interface BrowserArtifactArchive {
  schemaVersion: 1;
  namespace: string;
  retention: BrowserArtifactRetentionPolicy;
  artifacts: BrowserArtifactArchiveEntry[];
}

export interface BrowserArtifactArchiveExport {
  archive: BrowserArtifactArchive;
  bytes: Uint8Array;
  blob: Blob | null;
  contentType: "application/json";
  filename: string;
}

export interface BrowserArtifactOperationDiagnostics {
  backend: BrowserStorageBackend;
  namespace: string;
  operation: BrowserArtifactOperation;
  artifactId?: string;
  reason: BrowserArtifactFailureReason;
  message: string;
  guidance: string[];
  runtimeContext: BrowserRuntimeContext;
  capabilities: BrowserCapabilitySnapshot;
}

const DEDICATED_WORKER_GLOBAL_SCOPE_TAG = "[object DedicatedWorkerGlobalScope]";
const INDEXEDDB_STORAGE_KEY_PREFIX = "asupersync:indexeddb:v1:";
const LOCAL_STORAGE_KEY_PREFIX = "asupersync:storage:v1:";
const DEFAULT_INDEXEDDB_NAME = "asupersync_storage_v1";
const DEFAULT_INDEXEDDB_STORE = "entries";
const DEFAULT_INDEXEDDB_VERSION = 1;
const BROWSER_ARTIFACT_INDEX_KEY = "__artifact_index__";
const BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION = 1;
const DEFAULT_BROWSER_ARTIFACT_NAMESPACE = "runtime_artifacts_v1";
const DEFAULT_BROWSER_LANE_HEALTH_SCOPE_KEY = "@asupersync/browser::default";
const DEFAULT_BROWSER_LANE_HEALTH_POLICY: BrowserLaneHealthPolicy = {
  maxConsecutiveFailures: 2,
  cooldownMs: 30_000,
};
const DEFAULT_BROWSER_ARTIFACT_RETENTION: BrowserArtifactRetentionPolicy = {
  maxArtifacts: 32,
  maxTotalBytes: 4 * 1024 * 1024,
  maxArtifactBytes: 512 * 1024,
  quotaStrategy: "evict_oldest",
};

interface BrowserArtifactIndexEntry extends BrowserArtifactRecord {
  payloadKey: string;
}

interface BrowserArtifactIndex {
  schemaVersion: number;
  nextSequence: number;
  retention: BrowserArtifactRetentionPolicy;
  entries: BrowserArtifactIndexEntry[];
}

interface BrowserWebTransportReadableLike {
  getReader(): BrowserWebTransportReaderLike;
}

interface BrowserWebTransportWritableLike {
  getWriter(): BrowserWebTransportWriterLike;
}

interface BrowserWebTransportReaderLike {
  cancel?(reason?: unknown): Promise<void>;
  read(): Promise<{ done: boolean; value?: Uint8Array | ArrayBuffer }>;
  releaseLock?(): void;
}

interface BrowserWebTransportWriterLike {
  abort?(reason?: unknown): Promise<void>;
  close?(): Promise<void>;
  releaseLock?(): void;
  write(chunk: Uint8Array): Promise<void>;
}

interface BrowserWebTransportSessionLike {
  close(options?: BrowserWebTransportCloseOptions): void;
  closed: Promise<unknown>;
  datagrams?: {
    readable?: BrowserWebTransportReadableLike;
    writable?: BrowserWebTransportWritableLike;
  };
  ready: Promise<unknown>;
}

type BrowserWebTransportConstructorLike = new (
  url: string,
  options?: Record<string, unknown>,
) => BrowserWebTransportSessionLike;

interface BrowserWebTransportState {
  consumerVersion: AbiVersion | null;
  reader: Promise<BrowserWebTransportReaderLike>;
  ready: Promise<void>;
  session: BrowserWebTransportSessionLike;
  settled: boolean;
  scopeKey: string;
  writer: Promise<BrowserWebTransportWriterLike>;
}

interface BrowserWebTransportTerminalState {
  outcome: BrowserOutcome<WasmValue>;
  scopeKey: string;
}

type BrowserHandleLike = {
  toJSON(): HandleRef;
};

interface BrowserStorageGlobalLike {
  TextDecoder?: typeof TextDecoder;
  TextEncoder?: typeof TextEncoder;
  atob?: (value: string) => string;
  btoa?: (value: string) => string;
  indexedDB?: IDBFactory | null;
  localStorage?: Storage;
}

const REGION_PARENTS = new Map<string, string>();
const INFLIGHT_WEBTRANSPORTS = new Map<string, BrowserWebTransportState>();
const TERMINAL_WEBTRANSPORTS = new Map<
  string,
  BrowserWebTransportTerminalState
>();
const BROWSER_LANE_HEALTH_REGISTRY = new Map<
  string,
  Map<BrowserExecutionLane, BrowserLaneHealthSnapshot>
>();

function browserCapabilitySnapshot(
  globalObject: Record<string, unknown> | undefined,
): BrowserCapabilitySnapshot {
  return {
    hasAbortController: typeof globalObject?.AbortController === "function",
    hasDocument: typeof globalObject?.document === "object",
    hasFetch: typeof globalObject?.fetch === "function",
    hasIndexedDb: browserIndexedDbFactory(globalObject) !== null,
    hasLocalStorage: browserLocalStorage(globalObject) !== null,
    hasWebAssembly: typeof globalObject?.WebAssembly === "object",
    hasWebTransport: typeof globalObject?.WebTransport === "function",
    hasWebSocket: typeof globalObject?.WebSocket === "function",
    hasWindow: typeof globalObject?.window === "object",
  };
}

function isDedicatedWorkerGlobal(
  globalObject: Record<string, unknown> | undefined,
): boolean {
  return (
    globalObject !== undefined &&
    Object.prototype.toString.call(globalObject) ===
      DEDICATED_WORKER_GLOBAL_SCOPE_TAG
  );
}

function isServiceWorkerLikeGlobal(
  globalObject: Record<string, unknown> | undefined,
): boolean {
  return (
    globalObject !== undefined &&
    !isDedicatedWorkerGlobal(globalObject) &&
    typeof globalObject.skipWaiting === "function" &&
    typeof globalObject.clients === "object" &&
    typeof globalObject.registration === "object"
  );
}

function isSharedWorkerLikeGlobal(
  globalObject: Record<string, unknown> | undefined,
): boolean {
  return (
    globalObject !== undefined &&
    !isDedicatedWorkerGlobal(globalObject) &&
    "onconnect" in globalObject &&
    typeof globalObject.importScripts === "function"
  );
}

function deferredBrowserHostDiagnostics(
  globalObject: Record<string, unknown> | undefined,
): Pick<BrowserRuntimeSupportDiagnostics, "reason" | "message" | "guidance">
  | null {
  if (isServiceWorkerLikeGlobal(globalObject)) {
    return {
      reason: "service_worker_not_yet_shipped",
      message:
        "@asupersync/browser does not yet ship direct runtime APIs for service-worker hosts.",
      guidance: [
        "Use a dedicated worker bootstrap today if you need shipped direct Browser Edition execution.",
        "Keep service-worker orchestration at the application boundary until this host is promoted.",
      ],
    };
  }

  if (isSharedWorkerLikeGlobal(globalObject)) {
    return {
      reason: "shared_worker_not_yet_shipped",
      message:
        "@asupersync/browser does not yet ship direct runtime APIs for shared-worker hosts.",
      guidance: [
        "Use a dedicated worker bootstrap today if you need shipped direct Browser Edition execution.",
        "Keep shared-worker coordination at the application boundary until this host is promoted.",
      ],
    };
  }

  return null;
}

function browserExecutionHostRole(
  globalObject: Record<string, unknown> | undefined,
  capabilities: BrowserCapabilitySnapshot,
): BrowserExecutionHostRole {
  if (isServiceWorkerLikeGlobal(globalObject)) {
    return "service_worker";
  }
  if (isSharedWorkerLikeGlobal(globalObject)) {
    return "shared_worker";
  }
  if (isDedicatedWorkerGlobal(globalObject)) {
    return "dedicated_worker";
  }
  if (capabilities.hasWindow && capabilities.hasDocument) {
    return "browser_main_thread";
  }
  return "non_browser_or_unknown";
}

function browserRuntimeContext(
  globalObject: Record<string, unknown> | undefined,
  capabilities: BrowserCapabilitySnapshot,
): BrowserRuntimeContext {
  const hostRole = browserExecutionHostRole(globalObject, capabilities);
  if (hostRole === "dedicated_worker") {
    return "dedicated_worker";
  }
  if (hostRole === "browser_main_thread") {
    return "browser_main_thread";
  }
  return "unknown";
}

export function detectBrowserRuntimeSupport(
  globalObject:
    | Record<string, unknown>
    | undefined = typeof globalThis === "object" && globalThis !== null
    ? (globalThis as unknown as Record<string, unknown>)
    : undefined,
): BrowserRuntimeSupportDiagnostics {
  const capabilities = browserCapabilitySnapshot(globalObject);
  const runtimeContext = browserRuntimeContext(globalObject, capabilities);
  const sharedGuidance = [
    "Load @asupersync/browser only in browser main-thread or dedicated-worker boundaries.",
    "For Next.js server or edge code, prefer @asupersync/next bridge-only adapters instead of direct BrowserRuntime creation.",
  ];

  if (!globalObject) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      supportClass: "unsupported",
      runtimeContext,
      reason: "missing_global_this",
      message:
        "@asupersync/browser requires a browser-like globalThis to create or enter runtime scopes.",
      guidance: sharedGuidance,
      capabilities,
    };
  }

  const deferredHost = deferredBrowserHostDiagnostics(globalObject);
  if (deferredHost) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      supportClass: "unsupported",
      runtimeContext,
      reason: deferredHost.reason,
      message: deferredHost.message,
      guidance: [...deferredHost.guidance, ...sharedGuidance],
      capabilities,
    };
  }

  if (runtimeContext === "unknown") {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      supportClass: "unsupported",
      runtimeContext,
      reason: "unsupported_runtime_context",
      message:
        "@asupersync/browser direct runtime APIs are unsupported outside a browser main-thread or dedicated worker environment.",
      guidance: [
        "Move BrowserRuntime creation into a browser main-thread entrypoint or a dedicated worker bootstrap module.",
        ...sharedGuidance,
      ],
      capabilities,
    };
  }

  if (!capabilities.hasWebAssembly) {
    return {
      supported: false,
      packageName: "@asupersync/browser",
      supportClass: "unsupported",
      runtimeContext,
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
    supportClass: "direct_runtime_supported",
    runtimeContext,
    reason: "supported",
    message:
      runtimeContext === "dedicated_worker"
        ? "@asupersync/browser dedicated-worker runtime prerequisites are available."
        : "@asupersync/browser browser main-thread runtime prerequisites are available.",
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

function browserExecutionReasonCodeFromRuntimeSupport(
  reason: BrowserRuntimeSupportReason,
): BrowserExecutionReasonCode {
  switch (reason) {
    case "service_worker_not_yet_shipped":
      return "service_worker_direct_runtime_not_shipped";
    case "shared_worker_not_yet_shipped":
      return "shared_worker_direct_runtime_not_shipped";
    default:
      return reason;
  }
}

function browserExecutionLaneKind(
  laneId: BrowserExecutionLane,
): BrowserExecutionLaneKind {
  return laneId === BROWSER_UNSUPPORTED_LANE ? "unsupported" : "direct_runtime";
}

function browserExecutionLaneRank(laneId: BrowserExecutionLane): number {
  switch (laneId) {
    case BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE:
      return 10;
    case BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE:
      return 20;
    case BROWSER_UNSUPPORTED_LANE:
      return 99;
  }
}

function browserLaneHealthScopeKey(
  healthScopeKey: string | null | undefined,
): string {
  const normalized = healthScopeKey?.trim() ?? "";
  return normalized || DEFAULT_BROWSER_LANE_HEALTH_SCOPE_KEY;
}

function browserLaneHealthPolicy(
  healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined,
): BrowserLaneHealthPolicy {
  return {
    maxConsecutiveFailures: Math.max(
      1,
      healthPolicy?.maxConsecutiveFailures ??
        DEFAULT_BROWSER_LANE_HEALTH_POLICY.maxConsecutiveFailures,
    ),
    cooldownMs: Math.max(
      0,
      healthPolicy?.cooldownMs ?? DEFAULT_BROWSER_LANE_HEALTH_POLICY.cooldownMs,
    ),
  };
}

function createHealthyBrowserLaneHealthSnapshot(
  laneId: BrowserExecutionLane,
  policy: BrowserLaneHealthPolicy,
  lastTrigger: BrowserLaneHealthTrigger | null = null,
  lastMessage: string | null = null,
  lastTransitionAtMs: number | null = null,
): BrowserLaneHealthSnapshot {
  return {
    laneId,
    status: "healthy",
    failureCount: 0,
    retryBudgetRemaining: policy.maxConsecutiveFailures,
    cooldownMs: policy.cooldownMs,
    cooldownUntilMs: null,
    lastTrigger,
    lastMessage,
    lastTransitionAtMs,
    demotedToLaneId: null,
  };
}

function browserLaneHealthRegistry(
  scopeKey: string,
): Map<BrowserExecutionLane, BrowserLaneHealthSnapshot> {
  let registry = BROWSER_LANE_HEALTH_REGISTRY.get(scopeKey);
  if (!registry) {
    registry = new Map();
    BROWSER_LANE_HEALTH_REGISTRY.set(scopeKey, registry);
  }
  return registry;
}

function refreshBrowserLaneHealthSnapshot(
  snapshot: BrowserLaneHealthSnapshot,
  policy: BrowserLaneHealthPolicy,
  nowMs: number,
): BrowserLaneHealthSnapshot {
  if (
    snapshot.status === "demoted" &&
    snapshot.cooldownUntilMs !== null &&
    nowMs >= snapshot.cooldownUntilMs
  ) {
    return createHealthyBrowserLaneHealthSnapshot(
      snapshot.laneId,
      policy,
      snapshot.lastTrigger,
      snapshot.lastMessage,
      nowMs,
    );
  }
  return snapshot;
}

function readBrowserLaneHealthSnapshot(
  laneId: BrowserExecutionLane,
  healthScopeKey: string | null | undefined,
  healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined,
  now: (() => number) | undefined,
): BrowserLaneHealthDiagnostics {
  const policy = browserLaneHealthPolicy(healthPolicy);
  const scopeKey = browserLaneHealthScopeKey(healthScopeKey);
  const nowMs = (now ?? Date.now)();
  const registry = browserLaneHealthRegistry(scopeKey);
  const stored =
    registry.get(laneId) ?? createHealthyBrowserLaneHealthSnapshot(laneId, policy);
  const refreshed = refreshBrowserLaneHealthSnapshot(stored, policy, nowMs);
  if (refreshed !== stored) {
    registry.set(laneId, refreshed);
  }
  return {
    scopeKey,
    ...refreshed,
  };
}

function writeBrowserLaneHealthSnapshot(
  laneId: BrowserExecutionLane,
  snapshot: BrowserLaneHealthSnapshot,
  healthScopeKey: string | null | undefined,
): BrowserLaneHealthDiagnostics {
  const scopeKey = browserLaneHealthScopeKey(healthScopeKey);
  browserLaneHealthRegistry(scopeKey).set(laneId, snapshot);
  return {
    scopeKey,
    ...snapshot,
  };
}

function recordBrowserLaneHealthEvent(
  laneId: BrowserExecutionLane,
  trigger: BrowserLaneHealthTrigger,
  message: string | undefined,
  healthScopeKey: string | null | undefined,
  healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined,
  now: (() => number) | undefined,
): BrowserLaneHealthDiagnostics {
  const policy = browserLaneHealthPolicy(healthPolicy);
  const nowMs = (now ?? Date.now)();
  const current = readBrowserLaneHealthSnapshot(
    laneId,
    healthScopeKey,
    healthPolicy,
    now,
  );
  const base = refreshBrowserLaneHealthSnapshot(current, policy, nowMs);

  if (trigger === "manual_reset") {
    return writeBrowserLaneHealthSnapshot(
      laneId,
      createHealthyBrowserLaneHealthSnapshot(
        laneId,
        policy,
        trigger,
        message ?? null,
        nowMs,
      ),
      healthScopeKey,
    );
  }

  const failureCount = base.failureCount + 1;
  const retryBudgetRemaining = Math.max(
    0,
    policy.maxConsecutiveFailures - failureCount,
  );
  const demoted = retryBudgetRemaining === 0;
  return writeBrowserLaneHealthSnapshot(
    laneId,
    {
      laneId,
      status: demoted ? "demoted" : "retrying",
      failureCount,
      retryBudgetRemaining,
      cooldownMs: policy.cooldownMs,
      cooldownUntilMs: demoted ? nowMs + policy.cooldownMs : null,
      lastTrigger: trigger,
      lastMessage: message ?? null,
      lastTransitionAtMs: nowMs,
      demotedToLaneId: demoted ? browserExecutionFallbackLane(laneId) : null,
    },
    healthScopeKey,
  );
}

function clearBrowserLaneHealth(
  laneId: BrowserExecutionLane,
  healthScopeKey: string | null | undefined,
  healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined,
  now: (() => number) | undefined,
): BrowserLaneHealthDiagnostics {
  const policy = browserLaneHealthPolicy(healthPolicy);
  const current = readBrowserLaneHealthSnapshot(
    laneId,
    healthScopeKey,
    healthPolicy,
    now,
  );
  if (current.status === "healthy" && current.failureCount === 0) {
    return current;
  }
  return writeBrowserLaneHealthSnapshot(
    laneId,
    createHealthyBrowserLaneHealthSnapshot(
      laneId,
      policy,
      current.lastTrigger,
      current.lastMessage,
      (now ?? Date.now)(),
    ),
    healthScopeKey,
  );
}

function browserLaneHealthMessageFragment(
  health: BrowserLaneHealthDiagnostics,
): string {
  const cooldown =
    health.cooldownUntilMs === null
      ? "cooldown_until_ms=null"
      : `cooldown_until_ms=${health.cooldownUntilMs}`;
  const trigger = health.lastTrigger ?? "runtime_init_failure";
  return `lane_health_status=${health.status}; failure_count=${health.failureCount}; retry_budget_remaining=${health.retryBudgetRemaining}; ${cooldown}; last_trigger=${trigger}`;
}

function browserExecutionLaneUnhealthyMessage(
  laneId: BrowserExecutionLane,
  health: BrowserLaneHealthDiagnostics,
): string {
  return `${laneId} is temporarily unavailable because ${browserLaneHealthMessageFragment(health)}.`;
}

function browserExecutionLaneUnhealthyGuidance(
  laneId: BrowserExecutionLane,
  health: BrowserLaneHealthDiagnostics,
): string[] {
  const guidance = [
    `Wait for the cooldown window to elapse or call resetBrowserLaneHealth({ laneId: "${laneId}" }) after the host is stable again.`,
  ];
  if (health.lastMessage) {
    guidance.push(`Latest health event detail: ${health.lastMessage}`);
  }
  return guidance;
}

function browserExecutionHealthDemotionMessage(
  laneId: BrowserExecutionLane,
  health: BrowserLaneHealthDiagnostics,
): string {
  return `Browser Edition demoted from ${laneId} to ${BROWSER_UNSUPPORTED_LANE} because ${browserLaneHealthMessageFragment(health)}.`;
}

function browserExecutionHealthDemotionGuidance(
  laneId: BrowserExecutionLane,
  health: BrowserLaneHealthDiagnostics,
): string[] {
  return [
    `Treat ${BROWSER_UNSUPPORTED_LANE} as the fail-closed circuit-breaker lane until ${laneId} becomes healthy again.`,
    ...browserExecutionLaneUnhealthyGuidance(laneId, health),
  ];
}

function browserExecutionFallbackLane(
  laneId: BrowserExecutionLane,
): BrowserExecutionLane | null {
  return laneId === BROWSER_UNSUPPORTED_LANE ? null : BROWSER_UNSUPPORTED_LANE;
}

function browserExecutionDirectLaneForHostRole(
  hostRole: BrowserExecutionHostRole,
): BrowserExecutionLane | null {
  switch (hostRole) {
    case "browser_main_thread":
      return BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE;
    case "dedicated_worker":
      return BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE;
    default:
      return null;
  }
}

function browserExecutionDowngradeOrder(
  hostRole: BrowserExecutionHostRole,
): BrowserExecutionLane[] {
  const directLane = browserExecutionDirectLaneForHostRole(hostRole);
  return directLane === null
    ? [BROWSER_UNSUPPORTED_LANE]
    : [directLane, BROWSER_UNSUPPORTED_LANE];
}

function browserExecutionSelectedLane(
  hostRole: BrowserExecutionHostRole,
  runtimeSupport: BrowserRuntimeSupportDiagnostics,
): BrowserExecutionLane {
  if (!runtimeSupport.supported) {
    return BROWSER_UNSUPPORTED_LANE;
  }
  return (
    browserExecutionDirectLaneForHostRole(hostRole) ??
    BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE
  );
}

function browserExecutionReproCommand(
  laneId: BrowserExecutionLane,
  hostRole: BrowserExecutionHostRole,
  reasonCode: BrowserExecutionReasonCode,
): string {
  return `pnpm --filter @asupersync/browser test:e2e -- --lane ${laneId} --host-role ${hostRole} --reason ${reasonCode}`;
}

function createBrowserExecutionLaneCandidate(
  laneId: BrowserExecutionLane,
  hostRole: BrowserExecutionHostRole,
  supportClass: BrowserRuntimeSupportClass,
  available: boolean,
  selected: boolean,
  reasonCode: BrowserExecutionReasonCode,
  message: string,
  guidance: string[],
): BrowserExecutionLaneCandidate {
  return {
    laneId,
    laneKind: browserExecutionLaneKind(laneId),
    laneRank: browserExecutionLaneRank(laneId),
    hostRole,
    supportClass,
    fallbackLaneId: browserExecutionFallbackLane(laneId),
    available,
    selected,
    reasonCode,
    message,
    guidance,
  };
}

function browserExecutionHostMismatchMessage(
  laneId: BrowserExecutionLane,
): string {
  switch (laneId) {
    case BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE:
      return `${laneId} only applies when Browser Edition is running on the browser main thread.`;
    case BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE:
      return `${laneId} only applies when Browser Edition is already executing inside a dedicated worker bootstrap.`;
    case BROWSER_UNSUPPORTED_LANE:
      return `${laneId} is the terminal fail-closed lane and is only selected after a truthful downgrade.`;
  }
}

function browserExecutionHostMismatchGuidance(
  laneId: BrowserExecutionLane,
): string[] {
  switch (laneId) {
    case BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE:
      return [
        "Initialize Browser Edition from a browser main-thread entrypoint before pinning this lane.",
      ];
    case BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE:
      return [
        "Move Browser Edition creation into a dedicated worker bootstrap before pinning this lane.",
      ];
    case BROWSER_UNSUPPORTED_LANE:
      return [
        "Treat lane.unsupported as the terminal fail-closed lane when no truthful runtime lane remains.",
      ];
  }
}

function browserExecutionMissingPrerequisiteMessage(
  laneId: BrowserExecutionLane,
): string {
  if (laneId === BROWSER_UNSUPPORTED_LANE) {
    return "lane.unsupported remains the terminal fail-closed fallback if the current direct-runtime lane loses truthful prerequisites.";
  }
  return `${laneId} matches the current host role but is unavailable until the required Browser Edition prerequisites are restored.`;
}

function browserExecutionMissingPrerequisiteGuidance(
  laneId: BrowserExecutionLane,
): string[] {
  if (laneId === BROWSER_UNSUPPORTED_LANE) {
    return [
      "Expect Browser Edition to demote here instead of throwing when direct-runtime prerequisites disappear.",
    ];
  }
  return [
    "Restore the missing Browser Edition prerequisites before pinning this lane again.",
  ];
}

function browserExecutionCandidates(
  selectedLane: BrowserExecutionLane,
  hostRole: BrowserExecutionHostRole,
  supportClass: BrowserRuntimeSupportClass,
  selectedReasonCode: BrowserExecutionReasonCode,
  selectedMessage: string,
  selectedGuidance: string[],
  laneHealth: BrowserLaneHealthDiagnostics,
): BrowserExecutionLaneCandidate[] {
  const directLaneForHost = browserExecutionDirectLaneForHostRole(hostRole);

  const laneIds: BrowserExecutionLane[] = [
    BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
    BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    BROWSER_UNSUPPORTED_LANE,
  ];

  return laneIds.map((laneId) => {
    if (laneId === selectedLane) {
      return createBrowserExecutionLaneCandidate(
        laneId,
        hostRole,
        supportClass,
        true,
        true,
        selectedReasonCode,
        selectedMessage,
        selectedGuidance,
      );
    }

    const laneUnhealthy =
      directLaneForHost === laneId && laneHealth.status === "demoted";
    if (laneUnhealthy) {
      return createBrowserExecutionLaneCandidate(
        laneId,
        hostRole,
        supportClass,
        false,
        false,
        "candidate_lane_unhealthy",
        browserExecutionLaneUnhealthyMessage(laneId, laneHealth),
        browserExecutionLaneUnhealthyGuidance(laneId, laneHealth),
      );
    }

    const prerequisiteMissing =
      laneId === BROWSER_UNSUPPORTED_LANE
        ? selectedLane !== BROWSER_UNSUPPORTED_LANE &&
          selectedReasonCode !== "demote_due_to_lane_health"
        : directLaneForHost === laneId && selectedLane === BROWSER_UNSUPPORTED_LANE;

    if (prerequisiteMissing) {
      return createBrowserExecutionLaneCandidate(
        laneId,
        hostRole,
        supportClass,
        false,
        false,
        "candidate_prerequisite_missing",
        browserExecutionMissingPrerequisiteMessage(laneId),
        browserExecutionMissingPrerequisiteGuidance(laneId),
      );
    }

    return createBrowserExecutionLaneCandidate(
      laneId,
      hostRole,
      supportClass,
      false,
      false,
      "candidate_host_role_mismatch",
      browserExecutionHostMismatchMessage(laneId),
      browserExecutionHostMismatchGuidance(laneId),
    );
  });
}

function buildBrowserExecutionLadder(
  runtimeSupport: BrowserRuntimeSupportDiagnostics,
  preferredLane: BrowserExecutionLane | null,
  globalObject: Record<string, unknown> | undefined,
  healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined,
  healthScopeKey: string | null | undefined,
  now: (() => number) | undefined,
): BrowserExecutionLadderDiagnostics {
  const hostRole = browserExecutionHostRole(globalObject, runtimeSupport.capabilities);
  const directLaneForHost = browserExecutionDirectLaneForHostRole(hostRole);
  const nominalLane = browserExecutionSelectedLane(hostRole, runtimeSupport);
  const laneHealth = readBrowserLaneHealthSnapshot(
    directLaneForHost ?? nominalLane,
    healthScopeKey,
    healthPolicy,
    now,
  );
  const healthDemotion =
    runtimeSupport.supported &&
    directLaneForHost !== null &&
    laneHealth.status === "demoted";
  const selectedLane = healthDemotion
    ? laneHealth.demotedToLaneId ?? BROWSER_UNSUPPORTED_LANE
    : nominalLane;
  const supportClass = runtimeSupport.supportClass;
  const fallbackLaneId = browserExecutionFallbackLane(selectedLane);
  const reasonCode = healthDemotion
    ? "demote_due_to_lane_health"
    : runtimeSupport.supported
      ? "supported"
      : browserExecutionReasonCodeFromRuntimeSupport(runtimeSupport.reason);
  let message = runtimeSupport.message;
  let guidance = [...runtimeSupport.guidance];

  if (healthDemotion && directLaneForHost !== null) {
    message = browserExecutionHealthDemotionMessage(directLaneForHost, laneHealth);
    guidance = browserExecutionHealthDemotionGuidance(directLaneForHost, laneHealth);
  } else if (runtimeSupport.supported) {
    message =
      selectedLane === BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
        ? `Browser Edition selected ${BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE} for the dedicated-worker host role.`
        : `Browser Edition selected ${BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE} for the browser main-thread host role.`;
    guidance = [
      selectedLane === BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
        ? "Keep Browser Edition inside the dedicated worker bootstrap to preserve the direct-runtime lane."
        : "Keep Browser Edition inside the browser main-thread entrypoint while worker/offload lanes remain separate follow-on work.",
    ];
  }

  if (preferredLane !== null && preferredLane !== selectedLane) {
    message = `${message} Preferred lane ${preferredLane} is not truthful for host role ${hostRole}, so Browser Edition stayed on ${selectedLane}.`;
    guidance = [
      ...guidance,
      `Use ${selectedLane} for this host role, or switch entrypoints before pinning ${preferredLane}.`,
    ];
  }

  return {
    supported: runtimeSupport.supported && selectedLane !== BROWSER_UNSUPPORTED_LANE,
    preferredLane,
    selectedLane,
    laneId: selectedLane,
    laneKind: browserExecutionLaneKind(selectedLane),
    laneRank: browserExecutionLaneRank(selectedLane),
    hostRole,
    supportClass,
    runtimeContext: runtimeSupport.runtimeContext,
    reason: reasonCode,
    reasonCode,
    message,
    guidance,
    fallbackLaneId,
    downgradeOrder: browserExecutionDowngradeOrder(hostRole),
    policySchemaVersion: BROWSER_EXECUTION_POLICY_SCHEMA_VERSION,
    reproCommand: browserExecutionReproCommand(selectedLane, hostRole, reasonCode),
    candidates: browserExecutionCandidates(
      selectedLane,
      hostRole,
      supportClass,
      reasonCode,
      message,
      guidance,
      laneHealth,
    ),
    health: laneHealth,
    runtimeSupport,
    capabilities: runtimeSupport.capabilities,
  };
}

export function detectBrowserExecutionLadder(
  options: {
    globalObject?: Record<string, unknown>;
    preferredLane?: BrowserExecutionLane | null;
    healthPolicy?: Partial<BrowserLaneHealthPolicy>;
    healthScopeKey?: string | null;
    now?: () => number;
  } = {},
): BrowserExecutionLadderDiagnostics {
  const preferredLane = options.preferredLane ?? null;
  const runtimeSupport = detectBrowserRuntimeSupport(options.globalObject);
  return buildBrowserExecutionLadder(
    runtimeSupport,
    preferredLane,
    options.globalObject,
    options.healthPolicy,
    options.healthScopeKey,
    options.now,
  );
}

export function inspectBrowserLaneHealth(
  options: BrowserLaneHealthOptions = {},
): BrowserLaneHealthDiagnostics {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const runtimeSupport = detectBrowserRuntimeSupport(globalObject);
  const hostRole = browserExecutionHostRole(globalObject, runtimeSupport.capabilities);
  const laneId =
    options.laneId ??
    browserExecutionDirectLaneForHostRole(hostRole) ??
    BROWSER_UNSUPPORTED_LANE;
  return readBrowserLaneHealthSnapshot(
    laneId,
    options.healthScopeKey,
    options.healthPolicy,
    options.now,
  );
}

export function reportBrowserLaneUnhealthy(
  options: BrowserLaneHealthEventOptions,
): BrowserLaneHealthDiagnostics {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const runtimeSupport = detectBrowserRuntimeSupport(globalObject);
  const hostRole = browserExecutionHostRole(globalObject, runtimeSupport.capabilities);
  const laneId =
    options.laneId ??
    browserExecutionDirectLaneForHostRole(hostRole) ??
    BROWSER_UNSUPPORTED_LANE;
  return recordBrowserLaneHealthEvent(
    laneId,
    options.trigger,
    options.message,
    options.healthScopeKey,
    options.healthPolicy,
    options.now,
  );
}

export function resetBrowserLaneHealth(
  options: BrowserLaneHealthOptions = {},
): BrowserLaneHealthDiagnostics {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const runtimeSupport = detectBrowserRuntimeSupport(globalObject);
  const hostRole = browserExecutionHostRole(globalObject, runtimeSupport.capabilities);
  const laneId =
    options.laneId ??
    browserExecutionDirectLaneForHostRole(hostRole) ??
    BROWSER_UNSUPPORTED_LANE;
  return recordBrowserLaneHealthEvent(
    laneId,
    "manual_reset",
    "manual lane-health reset",
    options.healthScopeKey,
    options.healthPolicy,
    options.now,
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return String(error);
}

function defaultGlobalObject():
  | Record<string, unknown>
  | undefined {
  return typeof globalThis === "object" && globalThis !== null
    ? (globalThis as unknown as Record<string, unknown>)
    : undefined;
}

function browserWebTransportConstructor(
  globalObject: Record<string, unknown> | undefined,
): BrowserWebTransportConstructorLike | null {
  if (typeof globalObject?.WebTransport !== "function") {
    return null;
  }
  return globalObject.WebTransport as BrowserWebTransportConstructorLike;
}

export function detectWebTransportSupport(
  globalObject: Record<string, unknown> | undefined = defaultGlobalObject(),
): BrowserWebTransportSupportDiagnostics {
  const runtime = detectBrowserRuntimeSupport(globalObject);
  if (!runtime.supported) {
    return {
      supported: false,
      runtimeContext: runtime.runtimeContext,
      reason: runtime.reason,
      message: runtime.message,
      guidance: runtime.guidance,
      capabilities: runtime.capabilities,
    };
  }

  if (!runtime.capabilities.hasWebTransport) {
    return {
      supported: false,
      runtimeContext: runtime.runtimeContext,
      reason: "missing_webtransport",
      message: "WebTransport is unavailable in this browser/runtime.",
      guidance: [
        "Use HTTPS on a browser/runtime that exposes globalThis.WebTransport.",
        "Use WebSocket or fetch when WebTransport support is unavailable.",
      ],
      capabilities: runtime.capabilities,
    };
  }

  return {
    supported: true,
    runtimeContext: runtime.runtimeContext,
    reason: "supported",
    message:
      runtime.runtimeContext === "dedicated_worker"
        ? "@asupersync/browser WebTransport prerequisites are available in this dedicated worker."
        : "@asupersync/browser WebTransport prerequisites are available on the browser main thread.",
    guidance: [],
    capabilities: runtime.capabilities,
  };
}

export function createWebTransportUnsupportedError(
  diagnostics: BrowserWebTransportSupportDiagnostics,
): Error & {
  code: typeof BROWSER_WEBTRANSPORT_UNSUPPORTED_CODE;
  diagnostics: BrowserWebTransportSupportDiagnostics;
} {
  const error = new Error(
    `${BROWSER_WEBTRANSPORT_UNSUPPORTED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_WEBTRANSPORT_UNSUPPORTED_CODE;
    diagnostics: BrowserWebTransportSupportDiagnostics;
  };
  error.code = BROWSER_WEBTRANSPORT_UNSUPPORTED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertWebTransportSupport(
  diagnostics: BrowserWebTransportSupportDiagnostics = detectWebTransportSupport(),
): BrowserWebTransportSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createWebTransportUnsupportedError(diagnostics);
  }
  return diagnostics;
}

function browserStorageGlobals(
  globalObject: Record<string, unknown> | undefined,
): BrowserStorageGlobalLike | undefined {
  return globalObject as BrowserStorageGlobalLike | undefined;
}

function browserIndexedDbFactory(
  globalObject: Record<string, unknown> | undefined,
): IDBFactory | null {
  try {
    return browserStorageGlobals(globalObject)?.indexedDB ?? null;
  } catch {
    return null;
  }
}

function browserLocalStorage(
  globalObject: Record<string, unknown> | undefined,
): Storage | null {
  try {
    return browserStorageGlobals(globalObject)?.localStorage ?? null;
  } catch {
    return null;
  }
}

function browserTextEncoder(globalObject: Record<string, unknown> | undefined): TextEncoder {
  const ctor = browserStorageGlobals(globalObject)?.TextEncoder ?? TextEncoder;
  return new ctor();
}

function browserTextDecoder(globalObject: Record<string, unknown> | undefined): TextDecoder {
  const ctor = browserStorageGlobals(globalObject)?.TextDecoder ?? TextDecoder;
  return new ctor();
}

function browserBtoa(globalObject: Record<string, unknown> | undefined): ((value: string) => string) | null {
  const candidate = browserStorageGlobals(globalObject)?.btoa;
  if (typeof candidate === "function") {
    return candidate.bind(globalObject);
  }
  if (typeof btoa === "function") {
    return btoa;
  }
  return null;
}

function browserAtob(globalObject: Record<string, unknown> | undefined): ((value: string) => string) | null {
  const candidate = browserStorageGlobals(globalObject)?.atob;
  if (typeof candidate === "function") {
    return candidate.bind(globalObject);
  }
  if (typeof atob === "function") {
    return atob;
  }
  return null;
}

function encodeBrowserStorageSegment(
  value: string,
  globalObject: Record<string, unknown> | undefined,
): string {
  return encodeBrowserStorageBytes(browserTextEncoder(globalObject).encode(value), globalObject);
}

function encodeBrowserStorageBytes(
  value: Uint8Array,
  globalObject: Record<string, unknown> | undefined,
): string {
  const btoaImpl = browserBtoa(globalObject);
  if (!btoaImpl) {
    throw new Error("browser storage key encoding requires base64 support in the current runtime");
  }

  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoaImpl(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function decodeBrowserStorageSegment(
  value: string,
  globalObject: Record<string, unknown> | undefined,
): string | null {
  const decoded = decodeBrowserStorageBytes(value, globalObject);
  if (decoded === null) {
    return null;
  }
  return browserTextDecoder(globalObject).decode(decoded);
}

function decodeBrowserStorageBytes(
  value: string,
  globalObject: Record<string, unknown> | undefined,
): Uint8Array | null {
  const atobImpl = browserAtob(globalObject);
  if (!atobImpl) {
    return null;
  }

  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const withPadding = padded.padEnd(Math.ceil(padded.length / 4) * 4, "=");
  const binary = atobImpl(withPadding);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function normalizeBrowserStorageNamespace(namespace: string): string {
  const normalized = namespace.trim();
  if (!normalized) {
    throw new TypeError("browser storage namespace must not be empty");
  }
  return normalized;
}

function normalizeBrowserStorageKey(key: string): string {
  const normalized = key.trim();
  if (!normalized) {
    throw new TypeError("browser storage key must not be empty");
  }
  return normalized;
}

function normalizeBrowserStorageValue(
  value: BrowserStorageValue,
): Uint8Array {
  return normalizeWebTransportPayload(value);
}

function encodeIndexedDbStorageKey(
  namespace: string,
  key: string,
  globalObject: Record<string, unknown> | undefined,
): string {
  return `${INDEXEDDB_STORAGE_KEY_PREFIX}${encodeBrowserStorageSegment(namespace, globalObject)}:${encodeBrowserStorageSegment(key, globalObject)}`;
}

function indexedDbNamespacePrefix(
  namespace: string,
  globalObject: Record<string, unknown> | undefined,
): string {
  return `${INDEXEDDB_STORAGE_KEY_PREFIX}${encodeBrowserStorageSegment(namespace, globalObject)}:`;
}

function decodeIndexedDbStorageKey(
  encoded: string,
  namespace: string,
  globalObject: Record<string, unknown> | undefined,
): string | null {
  const prefix = indexedDbNamespacePrefix(namespace, globalObject);
  if (!encoded.startsWith(prefix)) {
    return null;
  }
  return decodeBrowserStorageSegment(encoded.slice(prefix.length), globalObject);
}

function encodeLocalStorageKey(
  namespace: string,
  key: string,
  globalObject: Record<string, unknown> | undefined,
): string {
  return `${LOCAL_STORAGE_KEY_PREFIX}${encodeBrowserStorageSegment(namespace, globalObject)}:${encodeBrowserStorageSegment(key, globalObject)}`;
}

function localStorageNamespacePrefix(
  namespace: string,
  globalObject: Record<string, unknown> | undefined,
): string {
  return `${LOCAL_STORAGE_KEY_PREFIX}${encodeBrowserStorageSegment(namespace, globalObject)}:`;
}

function decodeLocalStorageKey(
  encoded: string,
  namespace: string,
  globalObject: Record<string, unknown> | undefined,
): string | null {
  const prefix = localStorageNamespacePrefix(namespace, globalObject);
  if (!encoded.startsWith(prefix)) {
    return null;
  }
  return decodeBrowserStorageSegment(encoded.slice(prefix.length), globalObject);
}

function browserStorageLabel(backend: BrowserStorageBackend): string {
  return backend === "indexeddb" ? "IndexedDB" : "localStorage";
}

function browserStorageSupportGuidance(
  backend: BrowserStorageBackend,
  reason: BrowserStorageSupportReason,
): string[] {
  switch (reason) {
    case "missing_indexeddb":
      return [
        "Use a browser main thread or dedicated worker that exposes globalThis.indexedDB.",
        "Fall back to localStorage only for small, non-durable preference-style data.",
      ];
    case "missing_local_storage":
      return [
        "Use localStorage only on the browser main thread where window.localStorage is available.",
        "Prefer IndexedDB for durable storage in dedicated workers.",
      ];
    default:
      return [
        "Load @asupersync/browser only in browser main-thread or dedicated-worker boundaries.",
        "Use detectBrowserStorageSupport() before constructing durable storage flows in uncertain runtimes.",
      ];
  }
}

export function detectBrowserStorageSupport(
  backend: BrowserStorageBackend = "indexeddb",
  globalObject: Record<string, unknown> | undefined = defaultGlobalObject(),
): BrowserStorageSupportDiagnostics {
  const runtime = detectBrowserRuntimeSupport(globalObject);
  if (!runtime.supported) {
    return {
      supported: false,
      backend,
      runtimeContext: runtime.runtimeContext,
      reason: runtime.reason,
      message: runtime.message,
      guidance: runtime.guidance,
      capabilities: runtime.capabilities,
    };
  }

  if (backend === "indexeddb" && !runtime.capabilities.hasIndexedDb) {
    return {
      supported: false,
      backend,
      runtimeContext: runtime.runtimeContext,
      reason: "missing_indexeddb",
      message: "IndexedDB is unavailable in this browser/runtime.",
      guidance: browserStorageSupportGuidance(backend, "missing_indexeddb"),
      capabilities: runtime.capabilities,
    };
  }

  if (backend === "localstorage" && !runtime.capabilities.hasLocalStorage) {
    return {
      supported: false,
      backend,
      runtimeContext: runtime.runtimeContext,
      reason: "missing_local_storage",
      message: "localStorage is unavailable in this browser/runtime.",
      guidance: browserStorageSupportGuidance(backend, "missing_local_storage"),
      capabilities: runtime.capabilities,
    };
  }

  return {
    supported: true,
    backend,
    runtimeContext: runtime.runtimeContext,
    reason: "supported",
    message:
      backend === "indexeddb"
        ? `${browserStorageLabel(backend)} storage prerequisites are available in this browser/runtime.`
        : `${browserStorageLabel(backend)} support is available on this browser main-thread runtime.`,
    guidance: [],
    capabilities: runtime.capabilities,
  };
}

export function createBrowserStorageUnsupportedError(
  diagnostics: BrowserStorageSupportDiagnostics,
): Error & {
  code: typeof BROWSER_STORAGE_UNSUPPORTED_CODE;
  diagnostics: BrowserStorageSupportDiagnostics;
} {
  const error = new Error(
    `${BROWSER_STORAGE_UNSUPPORTED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_STORAGE_UNSUPPORTED_CODE;
    diagnostics: BrowserStorageSupportDiagnostics;
  };
  error.code = BROWSER_STORAGE_UNSUPPORTED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertBrowserStorageSupport(
  diagnostics: BrowserStorageSupportDiagnostics,
): BrowserStorageSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createBrowserStorageUnsupportedError(diagnostics);
  }
  return diagnostics;
}

function browserStorageFailureReason(
  message: string,
): BrowserStorageOperationFailureReason {
  const normalized = message.toLowerCase();
  if (normalized.includes("blocked")) {
    return "blocked_upgrade";
  }
  if (normalized.includes("quota")) {
    return "quota_exceeded";
  }
  if (
    normalized.includes("securityerror")
    || normalized.includes("denied")
    || normalized.includes("notallowed")
  ) {
    return "access_denied";
  }
  if (normalized.includes("aborted")) {
    return "transaction_aborted";
  }
  if (normalized.includes("transaction")) {
    return "transaction_failed";
  }
  return "request_failed";
}

function browserStorageFailureGuidance(
  backend: BrowserStorageBackend,
  reason: BrowserStorageOperationFailureReason,
): string[] {
  switch (reason) {
    case "blocked_upgrade":
      return [
        `Close other tabs or workers that still hold the ${browserStorageLabel(backend)} database open.`,
        "Retry after the upgrade lock is released.",
      ];
    case "quota_exceeded":
      return [
        "Free site storage space or reduce the payload size before retrying.",
        `Consider clearing older ${browserStorageLabel(backend)} entries for this origin.`,
      ];
    case "access_denied":
      return [
        "Check browser privacy mode and site-storage permissions before retrying.",
        "Retry in a standard browser profile if the current mode denies durable storage.",
      ];
    case "transaction_aborted":
    case "transaction_failed":
      return [
        `Retry the ${browserStorageLabel(backend)} operation after the current transaction settles.`,
        "Inspect the operation diagnostics message for the browser-reported failure.",
      ];
    default:
      return [
        "Inspect the storage diagnostics message for the browser-reported failure.",
        "Retry in a supported browser main-thread or dedicated-worker environment.",
      ];
  }
}

function createBrowserStorageOperationDiagnostics(
  backend: BrowserStorageBackend,
  operation: BrowserStorageOperation,
  namespace: string,
  key: string | undefined,
  message: string,
  globalObject: Record<string, unknown> | undefined,
): BrowserStorageOperationDiagnostics {
  const support = detectBrowserStorageSupport(backend, globalObject);
  const reason = browserStorageFailureReason(message);
  return {
    backend,
    operation,
    namespace,
    key,
    reason,
    message,
    guidance: browserStorageFailureGuidance(backend, reason),
    runtimeContext: support.runtimeContext,
    capabilities: support.capabilities,
  };
}

export function createBrowserStorageOperationError(
  diagnostics: BrowserStorageOperationDiagnostics,
): Error & {
  code: typeof BROWSER_STORAGE_OPERATION_FAILED_CODE;
  diagnostics: BrowserStorageOperationDiagnostics;
} {
  const error = new Error(
    `${BROWSER_STORAGE_OPERATION_FAILED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_STORAGE_OPERATION_FAILED_CODE;
    diagnostics: BrowserStorageOperationDiagnostics;
  };
  error.code = BROWSER_STORAGE_OPERATION_FAILED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

async function awaitIndexedDbRequest(request: IDBRequest): Promise<unknown> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

async function awaitIndexedDbTransaction(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(new Error("IndexedDB transaction aborted"));
  });
}

async function openIndexedDbDatabase(
  globalObject: Record<string, unknown> | undefined,
  dbName: string,
  storeName: string,
  version: number,
): Promise<IDBDatabase> {
  const factory = browserIndexedDbFactory(globalObject);
  if (!factory) {
    throw createBrowserStorageUnsupportedError(
      detectBrowserStorageSupport("indexeddb", globalObject),
    );
  }

  return new Promise((resolve, reject) => {
    const request = factory.open(dbName, version);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(storeName)) {
        database.createObjectStore(storeName);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onblocked = () => {
      reject(new Error("IndexedDB open blocked by another connection"));
    };
  });
}

function openIndexedDbStore(
  database: IDBDatabase,
  storeName: string,
  mode: IDBTransactionMode,
): { transaction: IDBTransaction; store: IDBObjectStore } {
  const transaction = database.transaction(storeName, mode);
  return {
    transaction,
    store: transaction.objectStore(storeName),
  };
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

function normalizeBrowserWebTransportUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new TypeError("WebTransport requires a non-empty absolute https:// URL.");
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (error) {
    throw new TypeError(
      `WebTransport requires an absolute https:// URL: ${errorMessage(error)}`,
    );
  }

  if (parsed.protocol !== "https:") {
    throw new TypeError(
      `WebTransport requires an https:// URL; received ${parsed.href}`,
    );
  }

  return parsed.href;
}

function normalizeWebTransportPayload(
  value: BrowserWebTransportPayload,
): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (
    Array.isArray(value) &&
    value.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    return Uint8Array.from(value);
  }
  throw new TypeError(
    "WebTransport datagrams must be Uint8Array, ArrayBuffer, ArrayBufferView, or byte[].",
  );
}

function browserWebTransportStateKey(
  handle: BrowserHandleLike,
): string {
  const raw = handle.toJSON();
  return `${raw.kind}:${raw.slot}:${raw.generation}`;
}

function recordRegionParent(
  parent: BrowserHandleLike,
  region: CoreRegionHandle,
): void {
  REGION_PARENTS.set(
    browserWebTransportStateKey(region),
    browserWebTransportStateKey(parent),
  );
}

function collectOwnedRegionKeys(rootKey: string): Set<string> {
  const owned = new Set<string>([rootKey]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [regionKey, parentKey] of REGION_PARENTS) {
      if (owned.has(parentKey) && !owned.has(regionKey)) {
        owned.add(regionKey);
        changed = true;
      }
    }
  }
  return owned;
}

function deleteOwnedRegionKeys(rootKey: string): Set<string> {
  const owned = collectOwnedRegionKeys(rootKey);
  for (const regionKey of owned) {
    REGION_PARENTS.delete(regionKey);
  }
  return owned;
}

function lookupWebTransportState(
  handle: CoreTaskHandle,
): BrowserWebTransportState | null {
  return INFLIGHT_WEBTRANSPORTS.get(browserWebTransportStateKey(handle)) ?? null;
}

function takeTerminalWebTransportOutcome(
  handle: BrowserHandleLike,
): BrowserOutcome<WasmValue> | null {
  const key = browserWebTransportStateKey(handle);
  const terminal = TERMINAL_WEBTRANSPORTS.get(key);
  if (!terminal) {
    return null;
  }
  TERMINAL_WEBTRANSPORTS.delete(key);
  return terminal.outcome;
}

function invalidHandleOutcome(message: string): BrowserOutcome<never> {
  return OutcomeFactory.err("invalid_handle", "permanent", message);
}

function webTransportFailureOutcome(
  message: string,
  recoverability: Recoverability = "transient",
): BrowserOutcome<never> {
  return OutcomeFactory.err("internal_failure", recoverability, message);
}

function webTransportCapabilityDenied(
  diagnostics: BrowserWebTransportSupportDiagnostics,
): BrowserOutcome<never> {
  return OutcomeFactory.err(
    "capability_denied",
    "permanent",
    `${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  );
}

function webTransportCancellationOutcome(
  kind: string,
  message?: string,
  phase: AbiCancellation["phase"] = "completed",
): BrowserOutcome<never> {
  return OutcomeFactory.cancelled({
    kind,
    phase,
    origin_region: "browser-sdk",
    origin_task: null,
    timestamp_nanos: 0,
    message: message ?? null,
    truncated: false,
  });
}

function collapseTaskOutcome(
  outcome: BrowserOutcome<WasmValue>,
): BrowserOutcome<void> {
  if (outcome.outcome === "ok") {
    return OutcomeFactory.ok(undefined);
  }
  return outcome as BrowserOutcome<void>;
}

function settleWebTransportTask(
  handle: CoreTaskHandle,
  outcome: BrowserOutcome<WasmValue>,
  consumerVersion: AbiVersion | null,
): BrowserOutcome<WasmValue> {
  const key = browserWebTransportStateKey(handle);
  const state = lookupWebTransportState(handle);
  if (state) {
    state.settled = true;
    TERMINAL_WEBTRANSPORTS.set(key, {
      outcome,
      scopeKey: state.scopeKey,
    });
    INFLIGHT_WEBTRANSPORTS.delete(key);
  } else {
    const terminal = TERMINAL_WEBTRANSPORTS.get(key);
    if (terminal) {
      return terminal.outcome;
    }
  }
  return taskJoin(handle, outcome, consumerVersion);
}

function cleanupWebTransportState(
  state: BrowserWebTransportState,
  reason?: string,
): void {
  // Best-effort cleanup must close/abort before releasing the lock; otherwise
  // Web Streams can reject with a released-reader/writer error on teardown.
  void state.reader
    .then((reader) =>
      Promise.resolve()
        .then(() => reader.cancel?.(reason))
        .catch(() => undefined)
        .finally(() => {
          try {
            reader.releaseLock?.();
          } catch {
            // Ignore cleanup races while the session is already tearing down.
          }
        }),
    )
    .catch(() => undefined);
  void state.writer
    .then((writer) =>
      Promise.resolve()
        .then(() =>
          reason !== undefined ? writer.abort?.(reason) : writer.close?.(),
        )
        .catch(() => undefined)
        .finally(() => {
          try {
            writer.releaseLock?.();
          } catch {
            // Ignore cleanup races while the session is already tearing down.
          }
        }),
    )
    .catch(() => undefined);
}

function closeTrackedWebTransportState(
  state: BrowserWebTransportState,
  reason?: string,
): void {
  state.settled = true;
  cleanupWebTransportState(state, reason);
  try {
    state.session.close(
      reason === undefined ? undefined : { reason },
    );
  } catch {
    // Ignore close races during scope/runtime teardown.
  }
}

function closeOwnedWebTransports(
  ownerKeys: Set<string>,
  reason?: string,
): void {
  for (const [taskKey, state] of INFLIGHT_WEBTRANSPORTS) {
    if (!ownerKeys.has(state.scopeKey)) {
      continue;
    }
    closeTrackedWebTransportState(state, reason);
    INFLIGHT_WEBTRANSPORTS.delete(taskKey);
  }
  for (const [taskKey, terminal] of TERMINAL_WEBTRANSPORTS) {
    if (ownerKeys.has(terminal.scopeKey)) {
      TERMINAL_WEBTRANSPORTS.delete(taskKey);
    }
  }
}

function cleanupScopeOwnedWebTransports(
  handle: CoreRegionHandle,
): void {
  closeOwnedWebTransports(
    deleteOwnedRegionKeys(browserWebTransportStateKey(handle)),
    "scope_close",
  );
}

function cleanupRuntimeOwnedWebTransports(
  handle: CoreRuntimeHandle,
): void {
  closeOwnedWebTransports(
    deleteOwnedRegionKeys(browserWebTransportStateKey(handle)),
    "runtime_close",
  );
}

function createBrowserWebTransportState(
  handle: CoreTaskHandle,
  consumerVersion: AbiVersion | null,
  session: BrowserWebTransportSessionLike,
  scopeKey: string,
): BrowserWebTransportState {
  const handshakeReady = session.ready.then(() => undefined);
  const reader = handshakeReady.then(() => {
    const readable = session.datagrams?.readable;
    if (!readable) {
      throw new Error("WebTransport datagram readable stream is unavailable.");
    }
    return readable.getReader();
  });
  const writer = handshakeReady.then(() => {
    const writable = session.datagrams?.writable;
    if (!writable) {
      throw new Error("WebTransport datagram writable stream is unavailable.");
    }
    return writable.getWriter();
  });
  const ready = Promise.all([reader, writer]).then(() => undefined);

  const state: BrowserWebTransportState = {
    consumerVersion,
    reader,
    ready,
    session,
    settled: false,
    scopeKey,
    writer,
  };

  ready.catch((error) => {
    if (state.settled) {
      return;
    }
    cleanupWebTransportState(state, errorMessage(error));
    settleWebTransportTask(
      handle,
      webTransportFailureOutcome(
        `browser WebTransport failed during ready(): ${errorMessage(error)}`,
      ),
      consumerVersion,
    );
  });

  void session.closed
    .then(() => {
      if (state.settled) {
        return;
      }
      cleanupWebTransportState(state, "webtransport closed");
      settleWebTransportTask(
        handle,
        webTransportCancellationOutcome(
          "webtransport_close",
          "WebTransport session closed.",
        ),
        consumerVersion,
      );
    })
    .catch((error) => {
      if (state.settled) {
        return;
      }
      cleanupWebTransportState(state, errorMessage(error));
      settleWebTransportTask(
        handle,
        webTransportFailureOutcome(
          `browser WebTransport closed with error: ${errorMessage(error)}`,
        ),
        consumerVersion,
      );
    });

  return state;
}

export function createBrowserSdkDiagnostics(
  consumerVersion: AbiVersion | null = null,
  executionLadder: BrowserExecutionLadderDiagnostics = detectBrowserExecutionLadder(),
): BrowserSdkDiagnostics {
  return {
    abiVersion: abiVersion(),
    abiFingerprint: abiFingerprint(),
    abiMetadata,
    consumerVersion,
    executionLadder,
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

  return "unknown outcome failure";
}

export function unwrapOutcome<T>(outcome: BrowserOutcome<T>): T {
  if (outcome.outcome === "ok") {
    return outcome.value;
  }
  throw new Error(formatOutcomeFailure(outcome));
}

export class BrowserRuntime {
  diagnostics: BrowserSdkDiagnostics;
  private readonly globalObject: Record<string, unknown> | undefined;
  private readonly healthPolicy: Partial<BrowserLaneHealthPolicy> | undefined;
  private readonly healthScopeKey: string | null;
  private readonly now: () => number;

  constructor(
    readonly core: CoreRuntimeHandle,
    readonly consumerVersion: AbiVersion | null = null,
    executionLadder: BrowserExecutionLadderDiagnostics = detectBrowserExecutionLadder(),
    options: BrowserLaneHealthOptions = {},
  ) {
    this.globalObject = options.globalObject;
    this.healthPolicy = options.healthPolicy;
    this.healthScopeKey = options.healthScopeKey ?? null;
    this.now = options.now ?? Date.now;
    this.diagnostics = createBrowserSdkDiagnostics(consumerVersion, executionLadder);
  }

  private currentExecutionLadder(): BrowserExecutionLadderDiagnostics {
    return detectBrowserExecutionLadder({
      globalObject: this.globalObject,
      preferredLane: this.diagnostics.executionLadder.preferredLane,
      healthPolicy: this.healthPolicy,
      healthScopeKey: this.healthScopeKey,
      now: this.now,
    });
  }

  private refreshDiagnostics(): BrowserExecutionLadderDiagnostics {
    const ladder = this.currentExecutionLadder();
    this.diagnostics = createBrowserSdkDiagnostics(this.consumerVersion, ladder);
    return ladder;
  }

  laneAvailabilityOutcome(
    operation: string,
  ): BrowserOutcome<never> | null {
    const ladder = this.refreshDiagnostics();
    if (ladder.supported) {
      return null;
    }
    const recoverability: Recoverability =
      ladder.reasonCode === "demote_due_to_lane_health"
        ? "transient"
        : "permanent";
    return OutcomeFactory.err(
      "capability_denied",
      recoverability,
      `Cannot ${operation}: ${ladder.message} ${ladder.guidance.join(" ")}`.trim(),
    );
  }

  laneHealth(): BrowserLaneHealthDiagnostics {
    return this.refreshDiagnostics().health;
  }

  reportLaneUnhealthy(
    trigger: Exclude<BrowserLaneHealthTrigger, "manual_reset">,
    message?: string,
  ): BrowserLaneHealthDiagnostics {
    const laneId = this.refreshDiagnostics().health.laneId;
    const diagnostics = recordBrowserLaneHealthEvent(
      laneId,
      trigger,
      message,
      this.healthScopeKey,
      this.healthPolicy,
      this.now,
    );
    this.refreshDiagnostics();
    return diagnostics;
  }

  resetLaneHealth(message = "manual lane-health reset"): BrowserLaneHealthDiagnostics {
    const laneId = this.refreshDiagnostics().health.laneId;
    const diagnostics = recordBrowserLaneHealthEvent(
      laneId,
      "manual_reset",
      message,
      this.healthScopeKey,
      this.healthPolicy,
      this.now,
    );
    this.refreshDiagnostics();
    return diagnostics;
  }

  toJSON(): HandleRef {
    return this.core.toJSON();
  }

  close(
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    const closed = runtimeClose(this.core, consumerVersion);
    if (closed.outcome === "ok") {
      cleanupRuntimeOwnedWebTransports(this.core);
    }
    return closed;
  }

  enterScope(
    label?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<RegionHandle> {
    const laneOutcome = this.laneAvailabilityOutcome("enter a Browser Edition scope");
    if (laneOutcome) {
      return laneOutcome;
    }
    const entered = scopeEnter({ parent: this.core, label }, consumerVersion);
    if (entered.outcome !== "ok") {
      return entered;
    }
    recordRegionParent(this.core, entered.value);
    return OutcomeFactory.ok(
      new RegionHandle(entered.value, consumerVersion, this),
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
    const closed = scopeClose(this.core, consumerVersion);
    if (closed.outcome === "ok") {
      cleanupScopeOwnedWebTransports(this.core);
    }
    return closed;
  }

  enterScope(
    label?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<RegionHandle> {
    const laneOutcome = this.runtime?.laneAvailabilityOutcome(
      "enter a nested Browser Edition scope",
    );
    if (laneOutcome) {
      return laneOutcome;
    }
    const entered = scopeEnter({ parent: this.core, label }, consumerVersion);
    if (entered.outcome !== "ok") {
      return entered;
    }
    recordRegionParent(this.core, entered.value);
    return OutcomeFactory.ok(
      new RegionHandle(entered.value, consumerVersion, this.runtime),
    );
  }

  spawnTask(
    options: Omit<TaskSpawnRequest, "scope"> = {},
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<TaskHandle> {
    const laneOutcome = this.runtime?.laneAvailabilityOutcome(
      "spawn work on a demoted Browser Edition runtime",
    );
    if (laneOutcome) {
      return laneOutcome;
    }
    return mapOutcome(
      taskSpawn({ scope: this.core, ...options }, consumerVersion),
      (handle) => new TaskHandle(handle, consumerVersion),
    );
  }

  fetchRequest(
    options: Omit<FetchRequest, "scope">,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<FetchHandle> {
    const laneOutcome = this.runtime?.laneAvailabilityOutcome(
      "issue fetch work on a demoted Browser Edition runtime",
    );
    if (laneOutcome) {
      return laneOutcome;
    }
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
    const laneOutcome = this.runtime?.laneAvailabilityOutcome(
      "open a WebSocket on a demoted Browser Edition runtime",
    );
    if (laneOutcome) {
      return laneOutcome;
    }
    return mapOutcome(
      websocketOpen({ scope: this.core, url, protocols }, consumerVersion),
      (handle) => new TaskHandle(handle, consumerVersion),
    );
  }

  openWebTransport(
    url: string,
    options: BrowserWebTransportOpenOptions = {},
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<WebTransportHandle> {
    const laneOutcome = this.runtime?.laneAvailabilityOutcome(
      "open WebTransport on a demoted Browser Edition runtime",
    );
    if (laneOutcome) {
      return laneOutcome;
    }
    const diagnostics = detectWebTransportSupport();
    if (!diagnostics.supported) {
      return webTransportCapabilityDenied(diagnostics);
    }

    let normalizedUrl: string;
    try {
      normalizedUrl = normalizeBrowserWebTransportUrl(url);
    } catch (error) {
      return webTransportFailureOutcome(errorMessage(error), "permanent");
    }

    const globalObject = defaultGlobalObject();
    const WebTransportCtor = browserWebTransportConstructor(globalObject);
    if (!WebTransportCtor) {
      return webTransportCapabilityDenied(detectWebTransportSupport(globalObject));
    }

    const spawned = taskSpawn(
      {
        scope: this.core,
        label: options.label ?? "browser-webtransport",
        cancel_kind: options.cancelKind ?? "abort_signal",
      },
      consumerVersion,
    );
    if (spawned.outcome !== "ok") {
      return spawned;
    }

    try {
      const session = new WebTransportCtor(normalizedUrl, {
        allowPooling: options.allowPooling ?? false,
        congestionControl: options.congestionControl,
        requireUnreliable: options.requireUnreliableDatagrams ?? false,
      });
      const state = createBrowserWebTransportState(
        spawned.value,
        consumerVersion,
        session,
        browserWebTransportStateKey(this.core),
      );
      INFLIGHT_WEBTRANSPORTS.set(
        browserWebTransportStateKey(spawned.value),
        state,
      );
    } catch (error) {
      const failure = webTransportFailureOutcome(
        `failed to construct browser WebTransport: ${errorMessage(error)}`,
        "permanent",
      );
      settleWebTransportTask(spawned.value, failure, consumerVersion);
      return failure;
    }

    return OutcomeFactory.ok(
      new WebTransportHandle(spawned.value, consumerVersion),
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
    outcome: BrowserOutcome<WasmValue>,
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

export class WebTransportHandle {
  constructor(
    readonly core: CoreTaskHandle,
    readonly consumerVersion: AbiVersion | null = null,
  ) {}

  toJSON(): HandleRef {
    return this.core.toJSON();
  }

  async ready(
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): Promise<BrowserOutcome<void>> {
    const state = lookupWebTransportState(this.core);
    if (!state) {
      const terminal = takeTerminalWebTransportOutcome(this.core);
      if (terminal) {
        return collapseTaskOutcome(terminal);
      }
      return invalidHandleOutcome(
        "unknown WebTransport handle; the session may already be closed",
      );
    }

    try {
      await state.ready;
      return OutcomeFactory.ok(undefined);
    } catch (error) {
      takeTerminalWebTransportOutcome(this.core);
      return webTransportFailureOutcome(
        `browser WebTransport readiness failed: ${errorMessage(error)}`,
      );
    }
  }

  async sendDatagram(
    value: BrowserWebTransportPayload,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): Promise<BrowserOutcome<void>> {
    const state = lookupWebTransportState(this.core);
    if (!state) {
      const terminal = takeTerminalWebTransportOutcome(this.core);
      if (terminal) {
        return collapseTaskOutcome(terminal);
      }
      return invalidHandleOutcome(
        "unknown WebTransport handle; the session may already be closed",
      );
    }

    try {
      const writer = await state.writer;
      await writer.write(normalizeWebTransportPayload(value));
      return OutcomeFactory.ok(undefined);
    } catch (error) {
      takeTerminalWebTransportOutcome(this.core);
      return webTransportFailureOutcome(
        `browser WebTransport datagram send failed: ${errorMessage(error)}`,
      );
    }
  }

  async recvDatagram(
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): Promise<BrowserOutcome<Uint8Array>> {
    const state = lookupWebTransportState(this.core);
    if (!state) {
      const terminal = takeTerminalWebTransportOutcome(this.core);
      if (terminal) {
        return terminal as BrowserOutcome<Uint8Array>;
      }
      return invalidHandleOutcome(
        "unknown WebTransport handle; the session may already be closed",
      );
    }

    try {
      const reader = await state.reader;
      const result = await reader.read();
      if (result.done || result.value === undefined) {
        const cancelled = webTransportCancellationOutcome(
          "webtransport_close",
          "WebTransport datagram reader reached end-of-stream.",
        );
        settleWebTransportTask(
          this.core,
          cancelled,
          consumerVersion,
        );
        return cancelled as BrowserOutcome<Uint8Array>;
      }
      return OutcomeFactory.ok(
        result.value instanceof Uint8Array
          ? result.value
          : new Uint8Array(result.value),
      );
    } catch (error) {
      takeTerminalWebTransportOutcome(this.core);
      return webTransportFailureOutcome(
        `browser WebTransport datagram receive failed: ${errorMessage(error)}`,
      );
    }
  }

  close(
    options: BrowserWebTransportCloseOptions = {},
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    const state = lookupWebTransportState(this.core);
    if (!state) {
      const terminal = takeTerminalWebTransportOutcome(this.core);
      if (terminal) {
        return collapseTaskOutcome(terminal);
      }
      return invalidHandleOutcome(
        "unknown WebTransport handle; the session may already be closed",
      );
    }

    try {
      cleanupWebTransportState(state, options.reason);
      state.session.close(options);
      return collapseTaskOutcome(
        settleWebTransportTask(
          this.core,
          webTransportCancellationOutcome(
            "webtransport_close",
            options.reason ?? "WebTransport session closed by caller.",
          ),
          consumerVersion,
        ),
      );
    } catch (error) {
      return webTransportFailureOutcome(
        `browser WebTransport close failed: ${errorMessage(error)}`,
      );
    }
  }

  cancel(
    tokenOrKind: CancellationToken | string,
    message?: string,
    consumerVersion: AbiVersion | null = this.consumerVersion,
  ): BrowserOutcome<void> {
    const token =
      tokenOrKind instanceof CancellationToken
        ? tokenOrKind
        : new CancellationToken(tokenOrKind, message, consumerVersion);
    const state = lookupWebTransportState(this.core);
    if (!state) {
      const terminal = takeTerminalWebTransportOutcome(this.core);
      if (terminal) {
        return collapseTaskOutcome(terminal);
      }
      return invalidHandleOutcome(
        "unknown WebTransport handle; the session may already be closed",
      );
    }

    const cancelOutcome = taskCancel(
      {
        task: this.core,
        kind: token.kind,
        message: token.message,
      },
      consumerVersion,
    );
    if (cancelOutcome.outcome !== "ok") {
      return cancelOutcome;
    }

    try {
      cleanupWebTransportState(state, token.message);
      state.session.close(
        token.message === undefined ? undefined : { reason: token.message },
      );
    } catch (error) {
      return webTransportFailureOutcome(
        `browser WebTransport cancel failed: ${errorMessage(error)}`,
      );
    }

    return collapseTaskOutcome(
      settleWebTransportTask(
        this.core,
        webTransportCancellationOutcome(
          token.kind,
          token.message,
          "cancelling",
        ) as BrowserOutcome<WasmValue>,
        consumerVersion,
      ),
    );
  }
}

export class BrowserStorage {
  readonly backend: BrowserStorageBackend;
  readonly dbName: string;
  readonly globalObject: Record<string, unknown> | undefined;
  readonly storeName: string;
  readonly version: number;

  constructor(options: BrowserStorageOptions = {}) {
    this.backend = options.backend ?? "indexeddb";
    this.dbName = options.dbName ?? DEFAULT_INDEXEDDB_NAME;
    this.globalObject = options.globalObject ?? defaultGlobalObject();
    this.storeName = options.storeName ?? DEFAULT_INDEXEDDB_STORE;
    this.version = options.version ?? DEFAULT_INDEXEDDB_VERSION;
  }

  diagnostics(): BrowserStorageSupportDiagnostics {
    return detectBrowserStorageSupport(this.backend, this.globalObject);
  }

  async get(namespace: string, key: string): Promise<Uint8Array | null> {
    const normalizedNamespace = normalizeBrowserStorageNamespace(namespace);
    const normalizedKey = normalizeBrowserStorageKey(key);
    assertBrowserStorageSupport(this.diagnostics());

    try {
      if (this.backend === "indexeddb") {
        const database = await openIndexedDbDatabase(
          this.globalObject,
          this.dbName,
          this.storeName,
          this.version,
        );
        try {
          const { store } = openIndexedDbStore(
            database,
            this.storeName,
            "readonly",
          );
          const request = store.get(
            encodeIndexedDbStorageKey(
              normalizedNamespace,
              normalizedKey,
              this.globalObject,
            ),
          );
          const result = await awaitIndexedDbRequest(request);
          if (result === undefined || result === null) {
            return null;
          }
          return result instanceof Uint8Array
            ? result
            : new Uint8Array(result as ArrayBufferLike);
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw createBrowserStorageUnsupportedError(this.diagnostics());
      }
      const result = storage.getItem(
        encodeLocalStorageKey(
          normalizedNamespace,
          normalizedKey,
          this.globalObject,
        ),
      );
      if (result === null) {
        return null;
      }
      const decoded = decodeBrowserStorageBytes(result, this.globalObject);
      if (decoded === null) {
        throw new Error("localStorage value could not be decoded from the BrowserStorage format");
      }
      return decoded;
    } catch (error) {
      throw createBrowserStorageOperationError(
        createBrowserStorageOperationDiagnostics(
          this.backend,
          "get",
          normalizedNamespace,
          normalizedKey,
          errorMessage(error),
          this.globalObject,
        ),
      );
    }
  }

  async set(namespace: string, key: string, value: BrowserStorageValue): Promise<void> {
    const normalizedNamespace = normalizeBrowserStorageNamespace(namespace);
    const normalizedKey = normalizeBrowserStorageKey(key);
    const normalizedValue = normalizeBrowserStorageValue(value);
    assertBrowserStorageSupport(this.diagnostics());

    try {
      if (this.backend === "indexeddb") {
        const database = await openIndexedDbDatabase(
          this.globalObject,
          this.dbName,
          this.storeName,
          this.version,
        );
        try {
          const { transaction, store } = openIndexedDbStore(
            database,
            this.storeName,
            "readwrite",
          );
          store.put(
            normalizedValue,
            encodeIndexedDbStorageKey(
              normalizedNamespace,
              normalizedKey,
              this.globalObject,
            ),
          );
          await awaitIndexedDbTransaction(transaction);
          return;
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw createBrowserStorageUnsupportedError(this.diagnostics());
      }
      storage.setItem(
        encodeLocalStorageKey(
          normalizedNamespace,
          normalizedKey,
          this.globalObject,
        ),
        encodeBrowserStorageBytes(normalizedValue, this.globalObject),
      );
    } catch (error) {
      throw createBrowserStorageOperationError(
        createBrowserStorageOperationDiagnostics(
          this.backend,
          "set",
          normalizedNamespace,
          normalizedKey,
          errorMessage(error),
          this.globalObject,
        ),
      );
    }
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    const normalizedNamespace = normalizeBrowserStorageNamespace(namespace);
    const normalizedKey = normalizeBrowserStorageKey(key);
    assertBrowserStorageSupport(this.diagnostics());

    try {
      if (this.backend === "indexeddb") {
        const database = await openIndexedDbDatabase(
          this.globalObject,
          this.dbName,
          this.storeName,
          this.version,
        );
        try {
          const { transaction, store } = openIndexedDbStore(
            database,
            this.storeName,
            "readwrite",
          );
          const storageKey = encodeIndexedDbStorageKey(
            normalizedNamespace,
            normalizedKey,
            this.globalObject,
          );
          const existing = await awaitIndexedDbRequest(store.get(storageKey));
          store.delete(storageKey);
          await awaitIndexedDbTransaction(transaction);
          return existing !== undefined && existing !== null;
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw createBrowserStorageUnsupportedError(this.diagnostics());
      }
      const storageKey = encodeLocalStorageKey(
        normalizedNamespace,
        normalizedKey,
        this.globalObject,
      );
      const existed = storage.getItem(storageKey) !== null;
      storage.removeItem(storageKey);
      return existed;
    } catch (error) {
      throw createBrowserStorageOperationError(
        createBrowserStorageOperationDiagnostics(
          this.backend,
          "delete",
          normalizedNamespace,
          normalizedKey,
          errorMessage(error),
          this.globalObject,
        ),
      );
    }
  }

  async listKeys(namespace: string): Promise<string[]> {
    const normalizedNamespace = normalizeBrowserStorageNamespace(namespace);
    assertBrowserStorageSupport(this.diagnostics());

    try {
      if (this.backend === "indexeddb") {
        const database = await openIndexedDbDatabase(
          this.globalObject,
          this.dbName,
          this.storeName,
          this.version,
        );
        try {
          const { store } = openIndexedDbStore(
            database,
            this.storeName,
            "readonly",
          );
          const request = store.getAllKeys();
          const rawKeys = await awaitIndexedDbRequest(request);
          const keys = Array.from(rawKeys as ArrayLike<unknown>)
            .map((value) =>
              typeof value === "string"
                ? decodeIndexedDbStorageKey(
                    value,
                    normalizedNamespace,
                    this.globalObject,
                  )
                : null,
            )
            .filter((value): value is string => value !== null);
          keys.sort();
          return Array.from(new Set(keys));
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw createBrowserStorageUnsupportedError(this.diagnostics());
      }
      const prefix = localStorageNamespacePrefix(
        normalizedNamespace,
        this.globalObject,
      );
      const keys: string[] = [];
      for (let index = 0; index < storage.length; index += 1) {
        const maybeKey = storage.key(index);
        if (!maybeKey || !maybeKey.startsWith(prefix)) {
          continue;
        }
        const decoded = decodeLocalStorageKey(
          maybeKey,
          normalizedNamespace,
          this.globalObject,
        );
        if (decoded !== null) {
          keys.push(decoded);
        }
      }
      keys.sort();
      return Array.from(new Set(keys));
    } catch (error) {
      throw createBrowserStorageOperationError(
        createBrowserStorageOperationDiagnostics(
          this.backend,
          "list_keys",
          normalizedNamespace,
          undefined,
          errorMessage(error),
          this.globalObject,
        ),
      );
    }
  }

  async clearNamespace(namespace: string): Promise<number> {
    const normalizedNamespace = normalizeBrowserStorageNamespace(namespace);
    assertBrowserStorageSupport(this.diagnostics());

    try {
      if (this.backend === "indexeddb") {
        const keys = await this.listKeys(normalizedNamespace);
        if (keys.length === 0) {
          return 0;
        }

        const database = await openIndexedDbDatabase(
          this.globalObject,
          this.dbName,
          this.storeName,
          this.version,
        );
        try {
          const { transaction, store } = openIndexedDbStore(
            database,
            this.storeName,
            "readwrite",
          );
          for (const key of keys) {
            store.delete(
              encodeIndexedDbStorageKey(
                normalizedNamespace,
                key,
                this.globalObject,
              ),
            );
          }
          await awaitIndexedDbTransaction(transaction);
          return keys.length;
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw createBrowserStorageUnsupportedError(this.diagnostics());
      }
      const keys = await this.listKeys(normalizedNamespace);
      for (const key of keys) {
        storage.removeItem(
          encodeLocalStorageKey(
            normalizedNamespace,
            key,
            this.globalObject,
          ),
        );
      }
      return keys.length;
    } catch (error) {
      throw createBrowserStorageOperationError(
        createBrowserStorageOperationDiagnostics(
          this.backend,
          "clear_namespace",
          normalizedNamespace,
          undefined,
          errorMessage(error),
          this.globalObject,
        ),
      );
    }
  }
}

function browserArtifactFailureGuidance(reason: BrowserArtifactFailureReason): string[] {
  switch (reason) {
    case "payload_too_large":
      return [
        "Reduce the artifact payload size or raise the explicit BrowserArtifactStore retention limits before retrying.",
        "Persist only redacted, support-grade payloads instead of full unbounded traces.",
      ];
    case "quota_exceeded":
      return [
        "Raise the explicit retention policy or clear older browser artifacts before retrying.",
        "Prefer IndexedDB over localStorage for larger durable artifact sets.",
      ];
    case "artifact_not_found":
      return [
        "Call listArtifacts() before export or download when artifact IDs may have been evicted by retention policy.",
      ];
    case "corrupt_index":
      return [
        "Call clearArtifacts() to reset the browser artifact store if the persisted index is no longer readable.",
        "Avoid mutating BrowserStorage keys for the artifact namespace outside BrowserArtifactStore.",
      ];
    case "download_unavailable":
      return [
        "Use exportArtifact() or exportArchive() in dedicated workers or non-DOM runtimes, then hand the bytes to a browser main-thread UI for download.",
      ];
    case "serialization_failed":
      return [
        "Pass binary data, plain text, or JSON-serializable values into BrowserArtifactStore.",
      ];
    case "unsupported_environment":
      return [
        "Use BrowserArtifactStore only in browser runtimes where the selected BrowserStorage backend is available.",
      ];
    default:
      return [
        "Inspect the artifact diagnostics message for the browser-reported failure and retry in a supported browser runtime.",
      ];
  }
}

export function createBrowserArtifactOperationError(
  diagnostics: BrowserArtifactOperationDiagnostics,
): Error & {
  code: typeof BROWSER_ARTIFACT_OPERATION_FAILED_CODE;
  diagnostics: BrowserArtifactOperationDiagnostics;
} {
  const error = new Error(
    `${BROWSER_ARTIFACT_OPERATION_FAILED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_ARTIFACT_OPERATION_FAILED_CODE;
    diagnostics: BrowserArtifactOperationDiagnostics;
  };
  error.code = BROWSER_ARTIFACT_OPERATION_FAILED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function createBrowserArtifactDownloadUnsupportedError(
  diagnostics: BrowserArtifactOperationDiagnostics,
): Error & {
  code: typeof BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE;
  diagnostics: BrowserArtifactOperationDiagnostics;
} {
  const error = new Error(
    `${BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE;
    diagnostics: BrowserArtifactOperationDiagnostics;
  };
  error.code = BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

function emptyBrowserArtifactIndex(
  retention: BrowserArtifactRetentionPolicy,
): BrowserArtifactIndex {
  return {
    schemaVersion: BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION,
    nextSequence: 0,
    retention,
    entries: [],
  };
}

function sumBrowserArtifactBytes(entries: BrowserArtifactIndexEntry[]): number {
  return entries.reduce((total, entry) => total + entry.byteLength, 0);
}

function isBrowserBinaryValue(value: unknown): value is BrowserStorageValue {
  return (
    value instanceof Uint8Array
    || value instanceof ArrayBuffer
    || ArrayBuffer.isView(value)
    || (
      Array.isArray(value)
      && value.every(
        (item) =>
          typeof item === "number"
          && Number.isInteger(item)
          && item >= 0
          && item <= 255,
      )
    )
  );
}

function normalizeBrowserArtifactRetentionPolicy(
  retention: Partial<BrowserArtifactRetentionPolicy> | undefined,
): BrowserArtifactRetentionPolicy {
  let maxArtifacts = Math.max(
    1,
    Math.trunc(retention?.maxArtifacts ?? DEFAULT_BROWSER_ARTIFACT_RETENTION.maxArtifacts),
  );
  let maxTotalBytes = Math.max(
    1024,
    Math.trunc(retention?.maxTotalBytes ?? DEFAULT_BROWSER_ARTIFACT_RETENTION.maxTotalBytes),
  );
  let maxArtifactBytes = Math.max(
    256,
    Math.trunc(retention?.maxArtifactBytes ?? DEFAULT_BROWSER_ARTIFACT_RETENTION.maxArtifactBytes),
  );
  if (maxArtifactBytes > maxTotalBytes) {
    maxArtifactBytes = maxTotalBytes;
  }
  if (maxArtifacts < 1) {
    maxArtifacts = 1;
  }
  if (maxTotalBytes < 1024) {
    maxTotalBytes = 1024;
  }
  return {
    maxArtifacts,
    maxTotalBytes,
    maxArtifactBytes,
    quotaStrategy: retention?.quotaStrategy ?? DEFAULT_BROWSER_ARTIFACT_RETENTION.quotaStrategy,
  };
}

function normalizeBrowserArtifactId(id: string): string {
  const normalized = id.trim();
  if (!normalized) {
    throw new TypeError("browser artifact id must not be empty");
  }
  return normalized;
}

function normalizeBrowserArtifactTags(tags: string[] | undefined): string[] {
  if (!tags) {
    return [];
  }
  const normalized = tags
    .map((tag) => tag.trim())
    .filter((tag) => tag.length > 0);
  normalized.sort();
  return Array.from(new Set(normalized));
}

function browserArtifactExtension(format: BrowserArtifactFormat): string {
  switch (format) {
    case "json":
      return "json";
    case "text":
      return "txt";
    default:
      return "bin";
  }
}

function defaultBrowserArtifactContentType(format: BrowserArtifactFormat): string {
  switch (format) {
    case "json":
      return "application/json";
    case "text":
      return "text/plain;charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

function normalizeBrowserArtifactFilename(
  kind: BrowserArtifactKind,
  id: string,
  format: BrowserArtifactFormat,
  filename: string | undefined,
): string {
  const candidate = (filename ?? `asupersync-${kind}-${id}.${browserArtifactExtension(format)}`).trim();
  if (!candidate) {
    return `asupersync-${kind}-${id}.${browserArtifactExtension(format)}`;
  }
  return candidate.replace(/[\\/]+/gu, "-");
}

function detectBrowserArtifactFormat(
  value: BrowserArtifactValue,
  requested: BrowserArtifactFormat | undefined,
): BrowserArtifactFormat {
  if (requested) {
    return requested;
  }
  if (isBrowserBinaryValue(value)) {
    return "binary";
  }
  if (typeof value === "string") {
    return "text";
  }
  return "json";
}

function normalizeBrowserArtifactBytes(
  value: BrowserArtifactValue,
  format: BrowserArtifactFormat,
  globalObject: Record<string, unknown> | undefined,
): Uint8Array {
  if (format === "binary") {
    if (isBrowserBinaryValue(value)) {
      return normalizeBrowserStorageValue(value);
    }
    if (typeof value === "string") {
      return browserTextEncoder(globalObject).encode(value);
    }
  }

  if (format === "text") {
    if (typeof value !== "string") {
      throw new TypeError("browser artifact text payload must be a string");
    }
    return browserTextEncoder(globalObject).encode(value);
  }

  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new TypeError("browser artifact payload must be binary, plain text, or JSON-serializable");
  }
  return browserTextEncoder(globalObject).encode(serialized);
}

function browserArtifactFailureReasonFromError(
  error: unknown,
  fallback: BrowserArtifactFailureReason,
): BrowserArtifactFailureReason {
  const code = typeof error === "object" && error !== null && "code" in error
    ? (error as { code?: string }).code
    : undefined;
  if (code === BROWSER_STORAGE_UNSUPPORTED_CODE) {
    return "unsupported_environment";
  }
  if (code === BROWSER_STORAGE_OPERATION_FAILED_CODE) {
    const diagnostics = typeof error === "object" && error !== null && "diagnostics" in error
      ? (error as { diagnostics?: BrowserStorageOperationDiagnostics }).diagnostics
      : undefined;
    if (diagnostics?.reason === "quota_exceeded") {
      return "quota_exceeded";
    }
    return "storage_failed";
  }
  return fallback;
}

function stripBrowserArtifactRecord(entry: BrowserArtifactIndexEntry): BrowserArtifactRecord {
  return {
    id: entry.id,
    kind: entry.kind,
    format: entry.format,
    filename: entry.filename,
    contentType: entry.contentType,
    byteLength: entry.byteLength,
    sequence: entry.sequence,
    tags: [...entry.tags],
  };
}

function browserBlobConstructor(
  globalObject: Record<string, unknown> | undefined,
): typeof Blob | null {
  const candidate = (globalObject as { Blob?: typeof Blob } | undefined)?.Blob;
  if (typeof candidate === "function") {
    return candidate;
  }
  if (typeof Blob === "function") {
    return Blob;
  }
  return null;
}

function createBrowserArtifactBlob(
  bytes: Uint8Array,
  contentType: string,
  globalObject: Record<string, unknown> | undefined,
): Blob | null {
  const ctor = browserBlobConstructor(globalObject);
  if (!ctor) {
    return null;
  }
  const stableBytes = new Uint8Array(bytes.byteLength);
  stableBytes.set(bytes);
  return new ctor([stableBytes.buffer], { type: contentType });
}

function browserDocumentLike(
  globalObject: Record<string, unknown> | undefined,
): Document | null {
  const candidate = (globalObject as { document?: Document } | undefined)?.document;
  if (candidate && typeof candidate.createElement === "function") {
    return candidate;
  }
  if (typeof document === "object" && document !== null && typeof document.createElement === "function") {
    return document;
  }
  return null;
}

function browserUrlLike(
  globalObject: Record<string, unknown> | undefined,
): Pick<typeof URL, "createObjectURL" | "revokeObjectURL"> | null {
  const candidate = (globalObject as { URL?: typeof URL } | undefined)?.URL;
  const urlLike = candidate ?? (typeof URL === "function" ? URL : null);
  if (!urlLike) {
    return null;
  }
  if (
    typeof urlLike.createObjectURL !== "function"
    || typeof urlLike.revokeObjectURL !== "function"
  ) {
    return null;
  }
  return urlLike;
}

export class BrowserArtifactStore {
  readonly namespace: string;
  readonly retention: BrowserArtifactRetentionPolicy;
  readonly storage: BrowserStorage;

  constructor(options: BrowserArtifactStoreOptions = {}) {
    this.storage = new BrowserStorage(options);
    this.namespace = normalizeBrowserStorageNamespace(
      options.namespace ?? DEFAULT_BROWSER_ARTIFACT_NAMESPACE,
    );
    this.retention = normalizeBrowserArtifactRetentionPolicy(options.retention);
  }

  diagnostics(): BrowserStorageSupportDiagnostics {
    return this.storage.diagnostics();
  }

  retentionPolicy(): BrowserArtifactRetentionPolicy {
    return { ...this.retention };
  }

  private operationDiagnostics(
    operation: BrowserArtifactOperation,
    reason: BrowserArtifactFailureReason,
    message: string,
    artifactId?: string,
  ): BrowserArtifactOperationDiagnostics {
    const support = this.diagnostics();
    return {
      backend: this.storage.backend,
      namespace: this.namespace,
      operation,
      artifactId,
      reason,
      message,
      guidance: browserArtifactFailureGuidance(reason),
      runtimeContext: support.runtimeContext,
      capabilities: support.capabilities,
    };
  }

  private operationError(
    operation: BrowserArtifactOperation,
    reason: BrowserArtifactFailureReason,
    message: string,
    artifactId?: string,
  ): Error & {
    code: typeof BROWSER_ARTIFACT_OPERATION_FAILED_CODE;
    diagnostics: BrowserArtifactOperationDiagnostics;
  } {
    return createBrowserArtifactOperationError(
      this.operationDiagnostics(operation, reason, message, artifactId),
    );
  }

  private downloadError(
    operation: "download" | "download_archive",
    message: string,
    artifactId?: string,
  ): Error & {
    code: typeof BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE;
    diagnostics: BrowserArtifactOperationDiagnostics;
  } {
    return createBrowserArtifactDownloadUnsupportedError(
      this.operationDiagnostics(operation, "download_unavailable", message, artifactId),
    );
  }

  private isCorruptIndexError(error: unknown): boolean {
    const code = typeof error === "object" && error !== null && "code" in error
      ? (error as { code?: string }).code
      : undefined;
    const diagnostics = typeof error === "object" && error !== null && "diagnostics" in error
      ? (error as { diagnostics?: BrowserArtifactOperationDiagnostics }).diagnostics
      : undefined;
    return (
      code === BROWSER_ARTIFACT_OPERATION_FAILED_CODE
      && diagnostics?.reason === "corrupt_index"
    );
  }

  private async namespaceKeys(
    operation: BrowserArtifactOperation,
  ): Promise<string[]> {
    try {
      return await this.storage.listKeys(this.namespace);
    } catch (error) {
      throw this.operationError(
        operation,
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
      );
    }
  }

  private async clearNamespace(
    operation: BrowserArtifactOperation,
  ): Promise<number> {
    try {
      return await this.storage.clearNamespace(this.namespace);
    } catch (error) {
      throw this.operationError(
        operation,
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
      );
    }
  }

  private async readIndex(operation: BrowserArtifactOperation): Promise<BrowserArtifactIndex> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.get(this.namespace, BROWSER_ARTIFACT_INDEX_KEY);
    } catch (error) {
      throw this.operationError(
        operation,
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
      );
    }

    if (raw === null) {
      return emptyBrowserArtifactIndex(this.retention);
    }

    try {
      const parsed = JSON.parse(
        browserTextDecoder(this.storage.globalObject).decode(raw),
      ) as Partial<BrowserArtifactIndex>;
      if (
        parsed.schemaVersion !== BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION
        || !Array.isArray(parsed.entries)
      ) {
        throw new Error("browser artifact index schema mismatch");
      }

      const entries = parsed.entries.map((entry) => {
        if (!entry || typeof entry !== "object") {
          throw new Error("browser artifact index entry must be an object");
        }
        const candidate = entry as Partial<BrowserArtifactIndexEntry>;
        if (
          typeof candidate.id !== "string"
          || typeof candidate.payloadKey !== "string"
          || typeof candidate.filename !== "string"
          || typeof candidate.contentType !== "string"
          || typeof candidate.byteLength !== "number"
          || typeof candidate.sequence !== "number"
        ) {
          throw new Error("browser artifact index entry is missing required fields");
        }
        if (
          candidate.kind !== "trace"
          && candidate.kind !== "crashpack"
          && candidate.kind !== "evidence"
          && candidate.kind !== "custom"
        ) {
          throw new Error("browser artifact index entry has an invalid kind");
        }
        if (
          candidate.format !== "binary"
          && candidate.format !== "json"
          && candidate.format !== "text"
        ) {
          throw new Error("browser artifact index entry has an invalid format");
        }
        const tags = Array.isArray(candidate.tags)
          ? candidate.tags.filter((tag): tag is string => typeof tag === "string")
          : [];
        return {
          id: candidate.id,
          kind: candidate.kind,
          format: candidate.format,
          filename: candidate.filename,
          contentType: candidate.contentType,
          byteLength: Math.max(0, Math.trunc(candidate.byteLength)),
          sequence: Math.max(0, Math.trunc(candidate.sequence)),
          tags: normalizeBrowserArtifactTags(tags),
          payloadKey: candidate.payloadKey,
        };
      });

      entries.sort((left, right) => right.sequence - left.sequence);
      const highestSequence = entries.reduce(
        (max, entry) => Math.max(max, entry.sequence),
        0,
      );

      return {
        schemaVersion: BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION,
        nextSequence: Math.max(
          highestSequence,
          Math.max(0, Math.trunc(parsed.nextSequence ?? highestSequence)),
        ),
        retention: this.retention,
        entries,
      };
    } catch (error) {
      throw this.operationError(
        operation,
        "corrupt_index",
        errorMessage(error),
      );
    }
  }

  private async writeIndex(
    index: BrowserArtifactIndex,
    operation: BrowserArtifactOperation,
  ): Promise<void> {
    try {
      if (index.entries.length === 0) {
        await this.storage.delete(this.namespace, BROWSER_ARTIFACT_INDEX_KEY);
        return;
      }
      const payload = browserTextEncoder(this.storage.globalObject).encode(
        JSON.stringify(index),
      );
      await this.storage.set(this.namespace, BROWSER_ARTIFACT_INDEX_KEY, payload);
    } catch (error) {
      throw this.operationError(
        operation,
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
      );
    }
  }

  async listArtifacts(): Promise<BrowserArtifactRecord[]> {
    const index = await this.readIndex("list");
    return index.entries.map(stripBrowserArtifactRecord);
  }

  async persistArtifact(
    request: BrowserArtifactPersistRequest,
  ): Promise<BrowserArtifactPersistResult> {
    const index = await this.readIndex("persist");
    const format = detectBrowserArtifactFormat(request.value, request.format);
    let bytes: Uint8Array;
    try {
      bytes = normalizeBrowserArtifactBytes(
        request.value,
        format,
        this.storage.globalObject,
      );
    } catch (error) {
      throw this.operationError(
        "persist",
        "serialization_failed",
        errorMessage(error),
        request.id,
      );
    }

    if (
      bytes.byteLength > this.retention.maxArtifactBytes
      || bytes.byteLength > this.retention.maxTotalBytes
    ) {
      throw this.operationError(
        "persist",
        "payload_too_large",
        `artifact payload is ${bytes.byteLength} bytes, which exceeds the explicit BrowserArtifactStore limits`,
        request.id,
      );
    }

    const sequence = index.nextSequence + 1;
    const id = normalizeBrowserArtifactId(
      request.id ?? `${request.kind}-${sequence.toString().padStart(6, "0")}`,
    );
    const filename = normalizeBrowserArtifactFilename(
      request.kind,
      id,
      format,
      request.filename,
    );
    const contentType =
      request.contentType ?? defaultBrowserArtifactContentType(format);
    const tags = normalizeBrowserArtifactTags(request.tags);
    const payloadKey = `artifact:${sequence.toString().padStart(6, "0")}:${encodeBrowserStorageSegment(id, this.storage.globalObject)}`;

    const existing = index.entries.find((entry) => entry.id === id);
    const retainedEntries = index.entries
      .filter((entry) => entry.id !== id)
      .sort((left, right) => left.sequence - right.sequence);
    const evictedEntries: BrowserArtifactIndexEntry[] = [];
    let totalBytes = bytes.byteLength + sumBrowserArtifactBytes(retainedEntries);

    if (this.retention.quotaStrategy === "evict_oldest") {
      while (
        retainedEntries.length + 1 > this.retention.maxArtifacts
        || totalBytes > this.retention.maxTotalBytes
      ) {
        const oldest = retainedEntries.shift();
        if (!oldest) {
          break;
        }
        totalBytes -= oldest.byteLength;
        evictedEntries.push(oldest);
      }
    }

    if (
      retainedEntries.length + 1 > this.retention.maxArtifacts
      || totalBytes > this.retention.maxTotalBytes
    ) {
      throw this.operationError(
        "persist",
        "quota_exceeded",
        "persisting this artifact would exceed the explicit BrowserArtifactStore retention policy",
        id,
      );
    }

    const entry: BrowserArtifactIndexEntry = {
      id,
      kind: request.kind,
      format,
      filename,
      contentType,
      byteLength: bytes.byteLength,
      sequence,
      tags,
      payloadKey,
    };

    try {
      await this.storage.set(this.namespace, payloadKey, bytes);
    } catch (error) {
      throw this.operationError(
        "persist",
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
        id,
      );
    }

    const nextIndex: BrowserArtifactIndex = {
      schemaVersion: BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION,
      nextSequence: sequence,
      retention: this.retention,
      entries: [...retainedEntries, entry].sort(
        (left, right) => right.sequence - left.sequence,
      ),
    };

    try {
      await this.writeIndex(nextIndex, "persist");
    } catch (error) {
      await this.storage.delete(this.namespace, payloadKey).catch(() => false);
      throw error;
    }

    const staleEntries = [
      ...(existing ? [existing] : []),
      ...evictedEntries,
    ];
    for (const stale of staleEntries) {
      await this.storage.delete(this.namespace, stale.payloadKey).catch(() => false);
    }

    return {
      artifact: stripBrowserArtifactRecord(entry),
      evictedArtifactIds: evictedEntries.map((stale) => stale.id),
      totalArtifacts: nextIndex.entries.length,
      totalBytes: sumBrowserArtifactBytes(nextIndex.entries),
    };
  }

  async persistTraceRecord(
    record: BrowserTraceRecord,
    options: Omit<BrowserArtifactPersistRequest, "kind" | "value"> = {},
  ): Promise<BrowserArtifactPersistResult> {
    return this.persistArtifact({
      ...options,
      kind: "trace",
      value: record,
      format: options.format ?? "json",
      contentType: options.contentType ?? "application/json",
    });
  }

  async persistCrashArtifact(
    artifact: BrowserArtifactValue,
    options: Omit<BrowserArtifactPersistRequest, "kind" | "value"> = {},
  ): Promise<BrowserArtifactPersistResult> {
    return this.persistArtifact({
      ...options,
      kind: "crashpack",
      value: artifact,
      format: options.format ?? "json",
      contentType: options.contentType ?? "application/json",
    });
  }

  async persistEvidenceArtifact(
    artifact: BrowserArtifactValue,
    options: Omit<BrowserArtifactPersistRequest, "kind" | "value"> = {},
  ): Promise<BrowserArtifactPersistResult> {
    return this.persistArtifact({
      ...options,
      kind: "evidence",
      value: artifact,
      format: options.format ?? "json",
      contentType: options.contentType ?? "application/json",
    });
  }

  async exportArtifact(id: string): Promise<BrowserArtifactExport> {
    const normalizedId = normalizeBrowserArtifactId(id);
    const index = await this.readIndex("export");
    const entry = index.entries.find((artifact) => artifact.id === normalizedId);
    if (!entry) {
      throw this.operationError(
        "export",
        "artifact_not_found",
        `browser artifact ${normalizedId} was not found in the current retention window`,
        normalizedId,
      );
    }

    let bytes: Uint8Array | null;
    try {
      bytes = await this.storage.get(this.namespace, entry.payloadKey);
    } catch (error) {
      throw this.operationError(
        "export",
        browserArtifactFailureReasonFromError(error, "storage_failed"),
        errorMessage(error),
        normalizedId,
      );
    }

    if (bytes === null) {
      throw this.operationError(
        "export",
        "corrupt_index",
        `browser artifact index references missing payload storage for ${normalizedId}`,
        normalizedId,
      );
    }

    return {
      artifact: stripBrowserArtifactRecord(entry),
      bytes,
      blob: createBrowserArtifactBlob(
        bytes,
        entry.contentType,
        this.storage.globalObject,
      ),
      contentType: entry.contentType,
      filename: entry.filename,
    };
  }

  async exportArchive(): Promise<BrowserArtifactArchiveExport> {
    const index = await this.readIndex("export_archive");
    const artifacts: BrowserArtifactArchiveEntry[] = [];

    for (const entry of index.entries) {
      let bytes: Uint8Array | null;
      try {
        bytes = await this.storage.get(this.namespace, entry.payloadKey);
      } catch (error) {
        throw this.operationError(
          "export_archive",
          browserArtifactFailureReasonFromError(error, "storage_failed"),
          errorMessage(error),
          entry.id,
        );
      }
      if (bytes === null) {
        throw this.operationError(
          "export_archive",
          "corrupt_index",
          `browser artifact index references missing payload storage for ${entry.id}`,
          entry.id,
        );
      }
      artifacts.push({
        artifact: stripBrowserArtifactRecord(entry),
        payloadBase64: encodeBrowserStorageBytes(bytes, this.storage.globalObject),
      });
    }

    const archive: BrowserArtifactArchive = {
      schemaVersion: 1,
      namespace: this.namespace,
      retention: this.retention,
      artifacts,
    };
    const bytes = browserTextEncoder(this.storage.globalObject).encode(
      JSON.stringify(archive),
    );
    return {
      archive,
      bytes,
      blob: createBrowserArtifactBlob(bytes, "application/json", this.storage.globalObject),
      contentType: "application/json",
      filename: `asupersync-browser-artifacts-${this.namespace}.json`,
    };
  }

  async deleteArtifact(id: string): Promise<boolean> {
    const normalizedId = normalizeBrowserArtifactId(id);
    const index = await this.readIndex("delete");
    const entry = index.entries.find((artifact) => artifact.id === normalizedId);
    if (!entry) {
      return false;
    }
    const nextIndex: BrowserArtifactIndex = {
      schemaVersion: BROWSER_ARTIFACT_INDEX_SCHEMA_VERSION,
      nextSequence: index.nextSequence,
      retention: this.retention,
      entries: index.entries.filter((artifact) => artifact.id !== normalizedId),
    };
    await this.writeIndex(nextIndex, "delete");
    await this.storage.delete(this.namespace, entry.payloadKey).catch(() => false);
    return true;
  }

  async clearArtifacts(): Promise<number> {
    try {
      const index = await this.readIndex("clear");
      await this.clearNamespace("clear");
      return index.entries.length;
    } catch (error) {
      if (!this.isCorruptIndexError(error)) {
        throw error;
      }

      // Recovery path: clear the raw namespace even when the persisted index
      // is unreadable, so the guidance for corrupt stores stays actionable.
      const keys = await this.namespaceKeys("clear");
      await this.clearNamespace("clear");
      return keys.filter((key) => key !== BROWSER_ARTIFACT_INDEX_KEY).length;
    }
  }

  async downloadArtifact(id: string): Promise<BrowserArtifactExport> {
    const exported = await this.exportArtifact(id);
    if (this.diagnostics().runtimeContext !== "browser_main_thread") {
      throw this.downloadError(
        "download",
        "browser artifact downloads require a browser main-thread document; use exportArtifact() in workers",
        exported.artifact.id,
      );
    }

    const blob = exported.blob;
    const urlApi = browserUrlLike(this.storage.globalObject);
    const doc = browserDocumentLike(this.storage.globalObject);
    if (!blob || !urlApi || !doc) {
      throw this.downloadError(
        "download",
        "browser artifact downloads require Blob, URL.createObjectURL(), and document support on the browser main thread",
        exported.artifact.id,
      );
    }

    const objectUrl = urlApi.createObjectURL(blob);
    try {
      const anchor = doc.createElement("a");
      anchor.href = objectUrl;
      anchor.download = exported.filename;
      anchor.rel = "noopener";
      anchor.click();
      return exported;
    } finally {
      urlApi.revokeObjectURL(objectUrl);
    }
  }

  async downloadArchive(): Promise<BrowserArtifactArchiveExport> {
    const exported = await this.exportArchive();
    if (this.diagnostics().runtimeContext !== "browser_main_thread") {
      throw this.downloadError(
        "download_archive",
        "browser artifact archive downloads require a browser main-thread document; use exportArchive() in workers",
      );
    }

    const blob = exported.blob;
    const urlApi = browserUrlLike(this.storage.globalObject);
    const doc = browserDocumentLike(this.storage.globalObject);
    if (!blob || !urlApi || !doc) {
      throw this.downloadError(
        "download_archive",
        "browser artifact archive downloads require Blob, URL.createObjectURL(), and document support on the browser main thread",
      );
    }

    const objectUrl = urlApi.createObjectURL(blob);
    try {
      const anchor = doc.createElement("a");
      anchor.href = objectUrl;
      anchor.download = exported.filename;
      anchor.rel = "noopener";
      anchor.click();
      return exported;
    } finally {
      urlApi.revokeObjectURL(objectUrl);
    }
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

export function createBrowserStorage(options: BrowserStorageOptions = {}): BrowserStorage {
  const storage = new BrowserStorage(options);
  assertBrowserStorageSupport(storage.diagnostics());
  return storage;
}

export function createBrowserArtifactStore(
  options: BrowserArtifactStoreOptions = {},
): BrowserArtifactStore {
  const store = new BrowserArtifactStore(options);
  assertBrowserStorageSupport(store.diagnostics());
  return store;
}

export async function createBrowserRuntimeSelection(
  options: BrowserRuntimeOptions = {},
): Promise<BrowserRuntimeSelectionResult> {
  const consumerVersion = options.consumerVersion ?? null;
  let executionLadder = detectBrowserExecutionLadder({
    globalObject: options.globalObject,
    preferredLane: options.preferredLane,
    healthPolicy: options.healthPolicy,
    healthScopeKey: options.healthScopeKey,
    now: options.now,
  });

  if (!executionLadder.supported) {
    return {
      executionLadder,
      runtime: null,
      outcome: null,
    };
  }

  if (options.eagerInit !== false) {
    try {
      await initWasm(options.wasmInput);
    } catch (error) {
      const health = recordBrowserLaneHealthEvent(
        executionLadder.health.laneId,
        "runtime_init_failure",
        `initWasm failed for ${executionLadder.laneId}: ${errorMessage(error)}`,
        options.healthScopeKey,
        options.healthPolicy,
        options.now,
      );
      executionLadder = detectBrowserExecutionLadder({
        globalObject: options.globalObject,
        preferredLane: options.preferredLane,
        healthPolicy: options.healthPolicy,
        healthScopeKey: options.healthScopeKey,
        now: options.now,
      });
      const outcome = OutcomeFactory.err(
        "internal_failure",
        health.status === "demoted" ? "transient" : "transient",
        `Browser Edition failed to initialize WebAssembly runtime: ${errorMessage(error)}`,
      );
      return {
        executionLadder,
        runtime: null,
        outcome: executionLadder.supported ? outcome : null,
      };
    }
  }

  const outcome = mapOutcome(runtimeCreate(consumerVersion), (handle) => {
    const stableLaneHealth = clearBrowserLaneHealth(
      executionLadder.health.laneId,
      options.healthScopeKey,
      options.healthPolicy,
      options.now,
    );
    const stableExecutionLadder = detectBrowserExecutionLadder({
      globalObject: options.globalObject,
      preferredLane: options.preferredLane,
      healthPolicy: options.healthPolicy,
      healthScopeKey: stableLaneHealth.scopeKey,
      now: options.now,
    });
    return new BrowserRuntime(handle, consumerVersion, stableExecutionLadder, {
      globalObject: options.globalObject,
      healthPolicy: options.healthPolicy,
      healthScopeKey: stableLaneHealth.scopeKey,
      now: options.now,
    });
  });

  if (outcome.outcome !== "ok") {
    const health = recordBrowserLaneHealthEvent(
      executionLadder.health.laneId,
      "runtime_init_failure",
      `runtimeCreate failed for ${executionLadder.laneId}: ${formatOutcomeFailure(outcome)}`,
      options.healthScopeKey,
      options.healthPolicy,
      options.now,
    );
    executionLadder = detectBrowserExecutionLadder({
      globalObject: options.globalObject,
      preferredLane: options.preferredLane,
      healthPolicy: options.healthPolicy,
      healthScopeKey: options.healthScopeKey,
      now: options.now,
    });
    return {
      executionLadder,
      runtime: null,
      outcome: health.status === "demoted" ? null : outcome,
    };
  }

  return {
    executionLadder: outcome.value.diagnostics.executionLadder,
    runtime: outcome.value,
    outcome,
  };
}

export async function createBrowserScopeSelection(
  options: BrowserRuntimeOptions & BrowserScopeOptions = {},
): Promise<BrowserScopeSelectionResult> {
  const runtimeSelection = await createBrowserRuntimeSelection(options);
  if (runtimeSelection.outcome !== null && runtimeSelection.outcome.outcome !== "ok") {
    return {
      executionLadder: runtimeSelection.executionLadder,
      runtime: null,
      scope: null,
      outcome: runtimeSelection.outcome as BrowserOutcome<RegionHandle>,
    };
  }

  if (runtimeSelection.runtime === null) {
    return {
      executionLadder: runtimeSelection.executionLadder,
      runtime: null,
      scope: null,
      outcome: null,
    };
  }

  const consumerVersion = options.consumerVersion ?? null;
  const entered = runtimeSelection.runtime.enterScope(options.label, consumerVersion);
  if (entered.outcome !== "ok") {
    runtimeSelection.runtime.close(consumerVersion);
    return {
      executionLadder: runtimeSelection.executionLadder,
      runtime: null,
      scope: null,
      outcome: entered,
    };
  }

  return {
    executionLadder: runtimeSelection.executionLadder,
    runtime: runtimeSelection.runtime,
    scope: entered.value,
    outcome: entered,
  };
}

export async function createBrowserRuntime(
  options: BrowserRuntimeOptions = {},
): Promise<BrowserOutcome<BrowserRuntime>> {
  const selection = await createBrowserRuntimeSelection(options);
  if (selection.outcome !== null) {
    return selection.outcome;
  }
  throw createUnsupportedRuntimeError(selection.executionLadder.runtimeSupport);
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
