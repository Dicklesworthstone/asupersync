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

export const BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID =
  "wasm-service-worker-broker-contract-v1";
export const BROWSER_SERVICE_WORKER_BROKER_LANE =
  "lane.browser.service_worker.broker";
export const BROWSER_BRIDGE_ONLY_FALLBACK_TARGET = "bridge_fallback";
export const BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID =
  "wasm-shared-worker-tenancy-lifecycle-v1";
export const BROWSER_SHARED_WORKER_COORDINATOR_LANE =
  "lane.browser.shared_worker.coordinator";
export const BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL =
  "asupersync.browser.shared_worker.handshake.v1";
export const BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED_CODE =
  "ASUPERSYNC_BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED";
export const BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE =
  "ASUPERSYNC_BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED";
export const BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED_CODE =
  "ASUPERSYNC_BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED";

export type BrowserServiceWorkerBrokerRequestedLane =
  typeof BROWSER_SERVICE_WORKER_BROKER_LANE;

export type BrowserServiceWorkerBrokerFallbackTarget =
  | typeof BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
  | typeof BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE
  | typeof BROWSER_BRIDGE_ONLY_FALLBACK_TARGET;

export type BrowserServiceWorkerBrokerLifecycleState =
  | "cold_start"
  | "validating_scope"
  | "reconciling_durable_state"
  | "brokering"
  | "draining"
  | "quiescent"
  | "terminated";

export type BrowserServiceWorkerBrokerSupportReason =
  | "supported"
  | "service_worker_api_missing"
  | "service_worker_registration_scope_mismatch"
  | "service_worker_controller_missing_when_required"
  | "app_namespace_mismatch"
  | "app_version_major_mismatch"
  | "broker_protocol_version_mismatch"
  | "durable_store_unavailable_for_restartable_profile"
  | "capability_manifest_mismatch_on_restart"
  | "background_event_kind_outside_broker_contract"
  | "broker_bootstrap_failure"
  | "broker_restart_reconciliation_failed"
  | "worker_reclaimed_by_browser"
  | "lane_health_demoted";

export type BrowserServiceWorkerBrokerOperation =
  | "read_registration"
  | "write_registration"
  | "clear_registration"
  | "set_lifecycle"
  | "list_work"
  | "persist_work"
  | "delete_work"
  | "list_handoffs"
  | "persist_handoff"
  | "clear_state";

export type BrowserServiceWorkerBrokerFailureReason =
  | BrowserServiceWorkerBrokerSupportReason
  | "storage_failed"
  | "serialization_failed";

export interface BrowserServiceWorkerBrokerAdmissionTuple {
  origin: string;
  registrationScope: string;
  appNamespace: string;
  appVersionMajor: number;
  brokerProtocolVersion: number;
  runProfile: string;
}

export interface BrowserServiceWorkerBrokerSupportOptions {
  allowBrowserMainThreadFallback?: boolean;
  allowDedicatedWorkerFallback?: boolean;
  appNamespace?: string | null;
  appVersionMajor?: number | null;
  backend?: BrowserStorageBackend;
  brokerProtocolVersion?: number | null;
  controllerPresent?: boolean;
  expectedAppNamespace?: string | null;
  expectedAppVersionMajor?: number | null;
  expectedBrokerProtocolVersion?: number | null;
  expectedRegistrationScope?: string | null;
  globalObject?: Record<string, unknown>;
  origin?: string | null;
  registrationScope?: string | null;
  requireController?: boolean;
  runProfile?: string | null;
}

export interface BrowserServiceWorkerBrokerSupportDiagnostics {
  supported: boolean;
  contractId: typeof BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID;
  requestedLane: BrowserServiceWorkerBrokerRequestedLane;
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  downgradeOrder: BrowserServiceWorkerBrokerFallbackTarget[];
  backend: BrowserStorageBackend;
  hostRole: BrowserExecutionHostRole;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserServiceWorkerBrokerSupportReason;
  message: string;
  guidance: string[];
  origin: string | null;
  registrationScope: string | null;
  controllerPresent: boolean;
  appNamespace: string | null;
  appVersionMajor: number | null;
  brokerProtocolVersion: number | null;
  runProfile: string;
  directRuntimeReason: BrowserRuntimeSupportReason;
  directExecutionReasonCode: BrowserExecutionReasonCode;
  runtimeSupport: BrowserRuntimeSupportDiagnostics;
  capabilities: BrowserCapabilitySnapshot;
}

export interface BrowserServiceWorkerBrokerStoreOptions
  extends BrowserStorageOptions {
  allowBrowserMainThreadFallback?: boolean;
  allowDedicatedWorkerFallback?: boolean;
  now?: () => number;
  namespace?: string;
}

export interface BrowserServiceWorkerBrokerRegistrationRequest {
  admission: BrowserServiceWorkerBrokerAdmissionTuple;
  capabilityManifestVersion: string;
  controllerPresent?: boolean;
  lifecycleState?: BrowserServiceWorkerBrokerLifecycleState;
}

export interface BrowserServiceWorkerBrokerRegistration {
  contractId: typeof BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID;
  requestedLane: BrowserServiceWorkerBrokerRequestedLane;
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  downgradeOrder: BrowserServiceWorkerBrokerFallbackTarget[];
  backend: BrowserStorageBackend;
  admission: BrowserServiceWorkerBrokerAdmissionTuple;
  capabilityManifestVersion: string;
  lifecycleState: BrowserServiceWorkerBrokerLifecycleState;
  controllerPresent: boolean;
  directExecutionReasonCode: BrowserExecutionReasonCode;
  registeredAtMs: number;
  updatedAtMs: number;
}

export interface BrowserServiceWorkerBrokerDescriptorRequest {
  artifactNamespace: string;
  brokerWorkId: string;
  capabilityManifestVersion: string;
  fallbackTarget?: BrowserServiceWorkerBrokerFallbackTarget | null;
  idempotencyKey: string;
  leaseEpoch: number;
  metadata?: Record<string, unknown> | null;
  sourceEventKind: string;
}

export interface BrowserServiceWorkerBrokerDescriptor {
  artifactNamespace: string;
  brokerWorkId: string;
  capabilityManifestVersion: string;
  createdAtMs: number;
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  idempotencyKey: string;
  leaseEpoch: number;
  metadata: Record<string, unknown> | null;
  requestedLane: BrowserServiceWorkerBrokerRequestedLane;
  sourceEventKind: string;
  updatedAtMs: number;
}

export interface BrowserServiceWorkerBrokerHandoffRequest {
  artifactNamespace: string;
  brokerWorkId: string;
  capabilityManifestVersion: string;
  fallbackTarget?: BrowserServiceWorkerBrokerFallbackTarget | null;
  idempotencyKey: string;
  leaseEpoch: number;
  metadata?: Record<string, unknown> | null;
  reason?: BrowserServiceWorkerBrokerSupportReason | BrowserExecutionReasonCode;
  sourceEventKind: string;
  targetLane?: BrowserServiceWorkerBrokerFallbackTarget | null;
}

export interface BrowserServiceWorkerBrokerHandoffRecord {
  artifactNamespace: string;
  brokerWorkId: string;
  capabilityManifestVersion: string;
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  idempotencyKey: string;
  leaseEpoch: number;
  metadata: Record<string, unknown> | null;
  reason: BrowserServiceWorkerBrokerSupportReason | BrowserExecutionReasonCode;
  recordedAtMs: number;
  requestedLane: BrowserServiceWorkerBrokerRequestedLane;
  sourceEventKind: string;
  targetLane: BrowserServiceWorkerBrokerFallbackTarget;
  targetLaneId: BrowserExecutionLane | null;
}

export interface BrowserServiceWorkerBrokerOperationDiagnostics {
  backend: BrowserStorageBackend;
  namespace: string;
  operation: BrowserServiceWorkerBrokerOperation;
  brokerWorkId?: string;
  reason: BrowserServiceWorkerBrokerFailureReason;
  message: string;
  guidance: string[];
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  directExecutionReasonCode: BrowserExecutionReasonCode;
  runtimeContext: BrowserRuntimeContext;
  capabilities: BrowserCapabilitySnapshot;
}

export type BrowserSharedWorkerCoordinatorRequestedLane =
  typeof BROWSER_SHARED_WORKER_COORDINATOR_LANE;

export type BrowserSharedWorkerCoordinatorFallbackTarget =
  | typeof BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
  | typeof BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE
  | typeof BROWSER_BRIDGE_ONLY_FALLBACK_TARGET;

export type BrowserSharedWorkerCoordinatorLifecycleState =
  | "bootstrapping"
  | "joining"
  | "active"
  | "draining"
  | "quiescent"
  | "terminated";

export type BrowserSharedWorkerCoordinatorSupportReason =
  | "supported"
  | "shared_worker_api_missing"
  | "origin_not_same_origin_or_opaque"
  | "app_namespace_mismatch"
  | "app_version_major_mismatch"
  | "coordinator_protocol_version_mismatch"
  | "durable_store_unavailable_for_recovery_required_profile"
  | "registration_schema_mismatch"
  | "coordinator_bootstrap_failure"
  | "coordinator_crash_or_browser_reclaim"
  | "operator_policy_disabled_shared_worker_lane"
  | "lane_health_demoted";

export interface BrowserSharedWorkerCoordinatorAdmissionTuple {
  origin: string;
  appNamespace: string;
  appVersionMajor: number;
  coordinatorProtocolVersion: number;
  runProfile: string;
}

export interface BrowserSharedWorkerClientRegistration {
  clientInstanceId: string;
  clientEpoch: number;
  clientKind: string;
  clientStartedAtMs: number;
  clientCapabilitySummary: Record<string, unknown> | null;
  clientArtifactNamespace: string;
}

export interface BrowserSharedWorkerCoordinatorFeatureRequest {
  required: string[];
  optional: string[];
}

export type BrowserSharedWorkerFactory = (
  scriptUrl: string,
  workerName: string | null,
) => BrowserSharedWorkerLike;

export interface BrowserSharedWorkerCoordinatorSupportOptions {
  allowBrowserMainThreadFallback?: boolean;
  allowDedicatedWorkerFallback?: boolean;
  appNamespace?: string | null;
  appVersionMajor?: number | null;
  backend?: BrowserStorageBackend;
  coordinatorProtocolVersion?: number | null;
  globalObject?: Record<string, unknown>;
  operatorEnabled?: boolean;
  origin?: string | null;
  runProfile?: string | null;
  scriptUrl?: string | URL | null;
  workerFactory?: BrowserSharedWorkerFactory | null;
  workerName?: string | null;
}

export interface BrowserSharedWorkerCoordinatorSelectionOptions
  extends BrowserRuntimeOptions, BrowserSharedWorkerCoordinatorSupportOptions {
  clientArtifactNamespace: string;
  clientCapabilitySummary?: Record<string, unknown> | null;
  clientEpoch?: number;
  clientInstanceId?: string | null;
  clientKind?: string | null;
  clientStartedAtMs?: number;
  handshakeTimeoutMs?: number;
  optionalCoordinatorFeatures?: string[];
  requiredCoordinatorFeatures?: string[];
}

export interface BrowserSharedWorkerCoordinatorSupportDiagnostics {
  supported: boolean;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  requestedLane: BrowserSharedWorkerCoordinatorRequestedLane;
  fallbackTarget: BrowserSharedWorkerCoordinatorFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  downgradeOrder: BrowserSharedWorkerCoordinatorFallbackTarget[];
  backend: BrowserStorageBackend;
  hostRole: BrowserExecutionHostRole;
  runtimeContext: BrowserRuntimeContext;
  reason: BrowserSharedWorkerCoordinatorSupportReason;
  message: string;
  guidance: string[];
  origin: string | null;
  appNamespace: string | null;
  appVersionMajor: number | null;
  coordinatorProtocolVersion: number | null;
  runProfile: string;
  scriptUrl: string | null;
  workerName: string | null;
  directRuntimeReason: BrowserRuntimeSupportReason;
  directExecutionReasonCode: BrowserExecutionReasonCode;
  runtimeSupport: BrowserRuntimeSupportDiagnostics;
  capabilities: BrowserCapabilitySnapshot;
}

export interface BrowserSharedWorkerCoordinatorAttachDiagnostics {
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  requestedLane: BrowserSharedWorkerCoordinatorRequestedLane;
  fallbackTarget: BrowserSharedWorkerCoordinatorFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
  admission: BrowserSharedWorkerCoordinatorAdmissionTuple;
  client: BrowserSharedWorkerClientRegistration;
  directExecutionLadder: BrowserExecutionLadderDiagnostics;
  lifecycleState: BrowserSharedWorkerCoordinatorLifecycleState;
  coordinatorFeatures: string[];
  scriptUrl: string;
  workerName: string | null;
}

export interface BrowserSharedWorkerCoordinatorHandshakeRequest {
  type: "asupersync.browser.shared_worker.handshake.request";
  protocol: typeof BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  admission: BrowserSharedWorkerCoordinatorAdmissionTuple;
  client: BrowserSharedWorkerClientRegistration;
  requestedFeatures: BrowserSharedWorkerCoordinatorFeatureRequest;
}

export interface BrowserSharedWorkerCoordinatorHandshakeResponse {
  type: "asupersync.browser.shared_worker.handshake.response";
  protocol: typeof BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  accepted: boolean;
  reason?: BrowserSharedWorkerCoordinatorSupportReason;
  message?: string;
  guidance?: string[];
  coordinatorFeatures?: string[];
  coordinatorProtocolVersion?: number;
  lifecycleState?: BrowserSharedWorkerCoordinatorLifecycleState;
}

export interface BrowserSharedWorkerCoordinatorSelectionResult {
  selectedMode: "shared_worker" | "fallback";
  support: BrowserSharedWorkerCoordinatorSupportDiagnostics;
  executionLadder: BrowserExecutionLadderDiagnostics;
  reason: BrowserSharedWorkerCoordinatorSupportReason | BrowserExecutionReasonCode;
  message: string;
  guidance: string[];
  coordinator: BrowserSharedWorkerCoordinatorClient | null;
  runtimeSelection: BrowserRuntimeSelectionResult | null;
  fallbackTarget: BrowserSharedWorkerCoordinatorFallbackTarget;
  fallbackLaneId: BrowserExecutionLane | null;
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
const BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY =
  "__service_worker_broker_registration__";
const BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX = "broker_work:";
const BROWSER_SERVICE_WORKER_BROKER_HANDOFF_PREFIX = "broker_handoff:";
const DEFAULT_BROWSER_SERVICE_WORKER_BROKER_NAMESPACE =
  "service_worker_broker_v1";
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

interface BrowserSharedWorkerPortLike {
  addEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
  close?(): void;
  postMessage(message: unknown): void;
  removeEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
  start?(): void;
}

interface BrowserSharedWorkerLike {
  port: BrowserSharedWorkerPortLike;
}

interface BrowserSharedWorkerConstructorLike {
  new (
    scriptUrl: string,
    options?: string | { name?: string },
  ): BrowserSharedWorkerLike;
}

interface BrowserSharedWorkerCoordinatorSelectionFailure {
  reason: BrowserSharedWorkerCoordinatorSupportReason;
  message: string;
  guidance: string[];
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
let BROWSER_SHARED_WORKER_CLIENT_SEQUENCE = 0;

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
      ? "lane_health_cooldown_until_ms=null"
      : `lane_health_cooldown_until_ms=${health.cooldownUntilMs}`;
  const trigger = health.lastTrigger ?? "runtime_init_failure";
  const demotedLaneId = health.demotedToLaneId ?? "null";
  return `lane_health_status=${health.status}; lane_health_failure_count=${health.failureCount}; lane_health_retry_budget_remaining=${health.retryBudgetRemaining}; ${cooldown}; lane_health_last_trigger=${trigger}; demoted_lane_id=${demotedLaneId}`;
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

function browserExecutionPreferredLaneMismatch(
  preferredLane: BrowserExecutionLane,
  selectedLane: BrowserExecutionLane,
  hostRole: BrowserExecutionHostRole,
  directLaneForHost: BrowserExecutionLane | null,
  reasonCode: BrowserExecutionReasonCode,
): { message: string; guidance: string[] } {
  if (
    preferredLane !== BROWSER_UNSUPPORTED_LANE &&
    preferredLane !== directLaneForHost
  ) {
    return {
      message: `Preferred lane ${preferredLane} is not truthful for host role ${hostRole}, so Browser Edition stayed on ${selectedLane}.`,
      guidance: [
        `Use ${selectedLane} for this host role, or switch entrypoints before pinning ${preferredLane}.`,
      ],
    };
  }

  if (reasonCode === "demote_due_to_lane_health") {
    return {
      message: `Preferred lane ${preferredLane} is temporarily unavailable because lane health demoted Browser Edition to ${selectedLane}.`,
      guidance: [
        `Wait for lane-health recovery or call resetBrowserLaneHealth() before pinning ${preferredLane} again.`,
      ],
    };
  }

  if (selectedLane === BROWSER_UNSUPPORTED_LANE) {
    return {
      message: `Preferred lane ${preferredLane} could not be selected because Browser Edition currently reports ${reasonCode} and stayed on ${selectedLane}.`,
      guidance: [
        `Restore the reported Browser Edition prerequisites before pinning ${preferredLane} again.`,
      ],
    };
  }

  return {
    message: `Preferred lane ${preferredLane} is a lower-priority fail-closed fallback, so Browser Edition stayed on ${selectedLane}.`,
    guidance: [
      `Only pin ${preferredLane} when you intentionally want the fail-closed fallback lane.`,
    ],
  };
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

    // Only surface lane-health as the candidate rejection reason when the
    // current ladder decision is an actual health-driven demotion. Hard
    // prerequisite failures such as missing WebAssembly must remain visible
    // even if the lane-health registry is still carrying older demotion state.
    const laneUnhealthy =
      selectedReasonCode === "demote_due_to_lane_health" &&
      directLaneForHost === laneId &&
      laneHealth.status === "demoted";
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
    const preferredLaneMismatch = browserExecutionPreferredLaneMismatch(
      preferredLane,
      selectedLane,
      hostRole,
      directLaneForHost,
      reasonCode,
    );
    message = `${message} ${preferredLaneMismatch.message}`;
    guidance = [...guidance, ...preferredLaneMismatch.guidance];
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

function browserServiceWorkerBrokerFallbackTargets(
  allowDedicatedWorkerFallback: boolean | undefined,
  allowBrowserMainThreadFallback: boolean | undefined,
): BrowserServiceWorkerBrokerFallbackTarget[] {
  const targets: BrowserServiceWorkerBrokerFallbackTarget[] = [];
  if (allowDedicatedWorkerFallback !== false) {
    targets.push(BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE);
  }
  if (allowBrowserMainThreadFallback !== false) {
    targets.push(BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE);
  }
  targets.push(BROWSER_BRIDGE_ONLY_FALLBACK_TARGET);
  return Array.from(new Set(targets));
}

function browserServiceWorkerBrokerFallbackLaneId(
  target: BrowserServiceWorkerBrokerFallbackTarget,
): BrowserExecutionLane | null {
  return target === BROWSER_BRIDGE_ONLY_FALLBACK_TARGET ? null : target;
}

function normalizeBrowserServiceWorkerBrokerString(
  value: string,
  label: string,
): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${label} must not be empty`);
  }
  return normalized;
}

function normalizeOptionalBrowserServiceWorkerBrokerString(
  value: string | null | undefined,
): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
}

function normalizeOptionalBrowserServiceWorkerBrokerVersion(
  value: number | null | undefined,
): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (!Number.isFinite(value)) {
    throw new TypeError("service-worker broker version fields must be finite numbers");
  }
  return Math.max(0, Math.trunc(value));
}

function browserServiceWorkerBrokerOrigin(
  globalObject: Record<string, unknown> | undefined,
): string | null {
  const candidate = (
    globalObject as { location?: { origin?: unknown } } | undefined
  )?.location?.origin;
  return typeof candidate === "string" ? candidate : null;
}

function browserServiceWorkerBrokerRegistrationScope(
  globalObject: Record<string, unknown> | undefined,
): string | null {
  const candidate = (
    globalObject as {
      registration?: { scope?: unknown };
    } | undefined
  )?.registration?.scope;
  return typeof candidate === "string" ? candidate : null;
}

function browserServiceWorkerBrokerControllerPresent(
  globalObject: Record<string, unknown> | undefined,
): boolean {
  const navigatorController = (
    globalObject as {
      navigator?: {
        serviceWorker?: { controller?: unknown };
      };
    } | undefined
  )?.navigator?.serviceWorker?.controller;
  return navigatorController !== null && navigatorController !== undefined;
}

function browserServiceWorkerBrokerGuidance(
  reason: BrowserServiceWorkerBrokerSupportReason,
): string[] {
  switch (reason) {
    case "service_worker_api_missing":
      return [
        "Call the bounded broker API only from a service-worker-like host.",
        "Keep direct BrowserRuntime creation on dedicated-worker or browser main-thread lanes.",
      ];
    case "service_worker_registration_scope_mismatch":
      return [
        "Persist a broker registration manifest whose registration_scope exactly matches the active service-worker registration.",
        "Fail closed and downgrade instead of replaying durable broker state against a drifted scope.",
      ];
    case "service_worker_controller_missing_when_required":
      return [
        "Require a controlling service worker only for flows that explicitly depend on controlled clients.",
        "Downgrade to a dedicated worker, browser main thread, or bridge-only handoff when no controller is present.",
      ];
    case "app_namespace_mismatch":
      return [
        "Keep the durable broker manifest scoped to one app_namespace and fail closed on drift.",
        "Write a fresh registration manifest before resuming restartable broker work after an app namespace change.",
      ];
    case "app_version_major_mismatch":
      return [
        "Treat app_version_major drift as a restart boundary and re-register the broker explicitly.",
        "Do not guess forward across major-version changes when reconciling durable broker work.",
      ];
    case "broker_protocol_version_mismatch":
      return [
        "Re-register the broker when the protocol contract changes instead of replaying older durable state.",
        "Keep the admission tuple's broker_protocol_version exact so downgrade decisions stay mechanical.",
      ];
    case "durable_store_unavailable_for_restartable_profile":
      return [
        "Use IndexedDB-backed durable storage before claiming restartable broker progress.",
        "If no durable store is available, downgrade immediately rather than pretending restartability.",
      ];
    case "capability_manifest_mismatch_on_restart":
      return [
        "Compare durable broker descriptors against the new capability manifest and fail closed on mismatch.",
        "Persist a new registration and handoff record instead of reviving stale authority.",
      ];
    case "background_event_kind_outside_broker_contract":
      return [
        "Restrict broker work to fetch, push, sync, or notification-style ingress that the contract admits explicitly.",
        "Route unsupported event kinds through an application-owned bridge instead of widening the broker surface.",
      ];
    case "broker_bootstrap_failure":
      return [
        "Register the broker before claiming restartable work or durable handoff.",
        "Persist the admission tuple and capability manifest before writing work descriptors.",
      ];
    case "broker_restart_reconciliation_failed":
      return [
        "Treat unreadable or schema-drifted durable broker state as an explicit restart reconciliation failure.",
        "Clear or re-register the broker state instead of guessing through corrupted durable records.",
      ];
    case "worker_reclaimed_by_browser":
      return [
        "Persist handoff metadata before browser reclaim becomes observable.",
        "Resume only through explicit downgrade or re-registration after worker reclaim.",
      ];
    case "lane_health_demoted":
      return [
        "Honor lane-health demotion by handing off to the next truthful fallback target.",
        "Do not keep brokering work in a host that the current health policy already demoted.",
      ];
    default:
      return [
        "Call registerBroker() before persistBrokerWork() so durable restart state is explicit.",
        "Keep BrowserRuntime creation fail-closed in service workers and hand execution off through the fallback target.",
      ];
  }
}

export function detectBrowserServiceWorkerBrokerSupport(
  options: BrowserServiceWorkerBrokerSupportOptions = {},
): BrowserServiceWorkerBrokerSupportDiagnostics {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const runtimeSupport = detectBrowserRuntimeSupport(globalObject);
  const fallbackTargets = browserServiceWorkerBrokerFallbackTargets(
    options.allowDedicatedWorkerFallback,
    options.allowBrowserMainThreadFallback,
  );
  const fallbackTarget = fallbackTargets[0];
  const fallbackLaneId = browserServiceWorkerBrokerFallbackLaneId(
    fallbackTarget,
  );
  const hostRole = browserExecutionHostRole(
    globalObject,
    runtimeSupport.capabilities,
  );
  const origin = normalizeOptionalBrowserServiceWorkerBrokerString(
    options.origin ?? browserServiceWorkerBrokerOrigin(globalObject),
  );
  const registrationScope = normalizeOptionalBrowserServiceWorkerBrokerString(
    options.registrationScope
      ?? browserServiceWorkerBrokerRegistrationScope(globalObject),
  );
  const appNamespace = normalizeOptionalBrowserServiceWorkerBrokerString(
    options.appNamespace,
  );
  const appVersionMajor = normalizeOptionalBrowserServiceWorkerBrokerVersion(
    options.appVersionMajor,
  );
  const brokerProtocolVersion =
    normalizeOptionalBrowserServiceWorkerBrokerVersion(
      options.brokerProtocolVersion,
    );
  const expectedRegistrationScope =
    normalizeOptionalBrowserServiceWorkerBrokerString(
      options.expectedRegistrationScope,
    );
  const expectedAppNamespace = normalizeOptionalBrowserServiceWorkerBrokerString(
    options.expectedAppNamespace,
  );
  const expectedAppVersionMajor =
    normalizeOptionalBrowserServiceWorkerBrokerVersion(
      options.expectedAppVersionMajor,
    );
  const expectedBrokerProtocolVersion =
    normalizeOptionalBrowserServiceWorkerBrokerVersion(
      options.expectedBrokerProtocolVersion,
    );
  const controllerPresent =
    options.controllerPresent
    ?? browserServiceWorkerBrokerControllerPresent(globalObject);
  const runProfile =
    normalizeOptionalBrowserServiceWorkerBrokerString(options.runProfile)
    ?? "restartable";
  const backend = options.backend ?? "indexeddb";

  let reason: BrowserServiceWorkerBrokerSupportReason = "supported";
  if (!isServiceWorkerLikeGlobal(globalObject)) {
    reason = "service_worker_api_missing";
  } else if (
    expectedRegistrationScope !== null
    && registrationScope !== expectedRegistrationScope
  ) {
    reason = "service_worker_registration_scope_mismatch";
  } else if (options.requireController && !controllerPresent) {
    reason = "service_worker_controller_missing_when_required";
  } else if (
    expectedAppNamespace !== null
    && appNamespace !== expectedAppNamespace
  ) {
    reason = "app_namespace_mismatch";
  } else if (
    expectedAppVersionMajor !== null
    && appVersionMajor !== expectedAppVersionMajor
  ) {
    reason = "app_version_major_mismatch";
  } else if (
    expectedBrokerProtocolVersion !== null
    && brokerProtocolVersion !== expectedBrokerProtocolVersion
  ) {
    reason = "broker_protocol_version_mismatch";
  } else if (
    runProfile !== "ephemeral"
    && (
      (backend === "indexeddb" && browserIndexedDbFactory(globalObject) === null)
      || (backend === "localstorage" && browserLocalStorage(globalObject) === null)
    )
  ) {
    reason = "durable_store_unavailable_for_restartable_profile";
  }

  const directExecutionReasonCode = browserExecutionReasonCodeFromRuntimeSupport(
    runtimeSupport.reason,
  );
  const guidance = browserServiceWorkerBrokerGuidance(reason);
  const message =
    reason === "supported"
      ? "@asupersync/browser service-worker broker prerequisites are available; direct BrowserRuntime creation remains fail-closed and all work must hand off explicitly."
      : `@asupersync/browser service-worker broker prerequisites are not satisfied: ${reason}.`;

  return {
    supported: reason === "supported",
    contractId: BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
    requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
    fallbackTarget,
    fallbackLaneId,
    downgradeOrder: fallbackTargets,
    backend,
    hostRole,
    runtimeContext: runtimeSupport.runtimeContext,
    reason,
    message,
    guidance,
    origin,
    registrationScope,
    controllerPresent,
    appNamespace,
    appVersionMajor,
    brokerProtocolVersion,
    runProfile,
    directRuntimeReason: runtimeSupport.reason,
    directExecutionReasonCode,
    runtimeSupport,
    capabilities: runtimeSupport.capabilities,
  };
}

export function createBrowserServiceWorkerBrokerUnsupportedError(
  diagnostics: BrowserServiceWorkerBrokerSupportDiagnostics,
): Error & {
  code: typeof BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED_CODE;
  diagnostics: BrowserServiceWorkerBrokerSupportDiagnostics;
} {
  const error = new Error(
    `${BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED_CODE;
    diagnostics: BrowserServiceWorkerBrokerSupportDiagnostics;
  };
  error.code = BROWSER_SERVICE_WORKER_BROKER_UNSUPPORTED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertBrowserServiceWorkerBrokerSupport(
  diagnostics: BrowserServiceWorkerBrokerSupportDiagnostics = detectBrowserServiceWorkerBrokerSupport(),
): BrowserServiceWorkerBrokerSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createBrowserServiceWorkerBrokerUnsupportedError(diagnostics);
  }
  return diagnostics;
}

function browserServiceWorkerBrokerOperationGuidance(
  reason: BrowserServiceWorkerBrokerFailureReason,
): string[] {
  if (reason === "storage_failed") {
    return [
      "Inspect the underlying IndexedDB or localStorage error and retry only after the durable substrate is healthy.",
      "Do not claim restartable broker progress until the durable handoff write succeeds.",
    ];
  }
  if (reason === "serialization_failed") {
    return [
      "Persist only JSON-serializable broker metadata and explicit string identifiers.",
      "Keep durable broker descriptors small, mechanical, and replay-friendly.",
    ];
  }
  return browserServiceWorkerBrokerGuidance(reason);
}

export function createBrowserServiceWorkerBrokerOperationError(
  diagnostics: BrowserServiceWorkerBrokerOperationDiagnostics,
): Error & {
  code: typeof BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE;
  diagnostics: BrowserServiceWorkerBrokerOperationDiagnostics;
} {
  const error = new Error(
    `${BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE;
    diagnostics: BrowserServiceWorkerBrokerOperationDiagnostics;
  };
  error.code = BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

function browserSharedWorkerCoordinatorFallbackTargets(
  hostRole: BrowserExecutionHostRole,
  allowDedicatedWorkerFallback: boolean | undefined,
  allowBrowserMainThreadFallback: boolean | undefined,
): BrowserSharedWorkerCoordinatorFallbackTarget[] {
  const targets: BrowserSharedWorkerCoordinatorFallbackTarget[] = [];
  if (hostRole === "dedicated_worker") {
    targets.push(BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE);
  }
  if (hostRole === "browser_main_thread") {
    targets.push(BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE);
  }
  if (allowDedicatedWorkerFallback !== false) {
    targets.push(BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE);
  }
  if (allowBrowserMainThreadFallback !== false) {
    targets.push(BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE);
  }
  targets.push(BROWSER_BRIDGE_ONLY_FALLBACK_TARGET);
  return Array.from(new Set(targets));
}

function browserSharedWorkerCoordinatorFallbackLaneId(
  target: BrowserSharedWorkerCoordinatorFallbackTarget,
): BrowserExecutionLane | null {
  return target === BROWSER_BRIDGE_ONLY_FALLBACK_TARGET ? null : target;
}

function normalizeBrowserSharedWorkerCoordinatorString(
  value: string,
  label: string,
): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${label} must not be empty`);
  }
  return normalized;
}

function normalizeOptionalBrowserSharedWorkerCoordinatorString(
  value: string | null | undefined,
): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
}

function normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
  value: number | null | undefined,
): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (!Number.isFinite(value)) {
    throw new TypeError("shared-worker coordinator version fields must be finite numbers");
  }
  return Math.max(0, Math.trunc(value));
}

function normalizeBrowserSharedWorkerCoordinatorFeatures(
  values: string[] | null | undefined,
): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(
    new Set(
      values
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    ),
  ).sort();
}

function normalizeBrowserSharedWorkerCoordinatorLifecycleState(
  value: string,
): BrowserSharedWorkerCoordinatorLifecycleState {
  switch (value) {
    case "bootstrapping":
    case "joining":
    case "active":
    case "draining":
    case "quiescent":
    case "terminated":
      return value;
    default:
      throw new TypeError("shared-worker coordinator lifecycle_state is invalid");
  }
}

function browserSharedWorkerConstructor(
  globalObject: Record<string, unknown> | undefined,
): BrowserSharedWorkerConstructorLike | null {
  if (typeof globalObject?.SharedWorker !== "function") {
    return null;
  }
  return globalObject.SharedWorker as BrowserSharedWorkerConstructorLike;
}

function browserSharedWorkerCoordinatorOrigin(
  globalObject: Record<string, unknown> | undefined,
): string | null {
  return browserServiceWorkerBrokerOrigin(globalObject);
}

function browserSharedWorkerCoordinatorResolvedScriptUrl(
  scriptUrl: string | URL | null | undefined,
  globalObject: Record<string, unknown> | undefined,
): string | null {
  if (scriptUrl === null || scriptUrl === undefined) {
    return null;
  }
  const raw =
    scriptUrl instanceof URL ? scriptUrl.toString() : scriptUrl.trim();
  if (!raw) {
    return null;
  }
  const hrefCandidate = (
    globalObject as {
      location?: {
        href?: unknown;
      };
    } | undefined
  )?.location?.href;
  try {
    if (typeof hrefCandidate === "string" && hrefCandidate.length > 0) {
      return new URL(raw, hrefCandidate).toString();
    }
    return new URL(raw).toString();
  } catch {
    return null;
  }
}

function browserSharedWorkerCoordinatorScriptOrigin(
  scriptUrl: string | null,
): string | null {
  if (scriptUrl === null) {
    return null;
  }
  try {
    return new URL(scriptUrl).origin;
  } catch {
    return null;
  }
}

function browserSharedWorkerCoordinatorGuidance(
  reason: BrowserSharedWorkerCoordinatorSupportReason,
  fallbackTarget: BrowserSharedWorkerCoordinatorFallbackTarget,
): string[] {
  switch (reason) {
    case "shared_worker_api_missing":
      return [
        "Call the bounded SharedWorker coordinator helper only from a browser main-thread or dedicated-worker host that exposes globalThis.SharedWorker.",
        "Fall back to the current truthful direct-runtime lane when the coordinator surface is unavailable.",
      ];
    case "origin_not_same_origin_or_opaque":
      return [
        "Keep the SharedWorker script same-origin with the calling page or worker and avoid opaque origins.",
        "Downgrade immediately instead of guessing across cross-origin or opaque-origin boundaries.",
      ];
    case "app_namespace_mismatch":
      return [
        "Keep the coordinator admission tuple scoped to one app_namespace and fail closed on drift.",
        "Start a fresh coordinator or downgrade instead of mixing tenants under one worker name.",
      ];
    case "app_version_major_mismatch":
      return [
        "Treat app_version_major drift as a restart boundary and attach a new coordinator explicitly.",
        "Do not guess forward across major-version changes when joining a shared coordinator.",
      ];
    case "coordinator_protocol_version_mismatch":
      return [
        "Keep the coordinator_protocol_version exact on both sides of the handshake.",
        "Downgrade instead of attaching to a coordinator that reports a different protocol contract.",
      ];
    case "durable_store_unavailable_for_recovery_required_profile":
      return [
        "Use IndexedDB-backed or localStorage-backed durability before claiming recovery-required SharedWorker reuse.",
        "Switch to the ephemeral profile or downgrade immediately when no durable substrate is available.",
      ];
    case "registration_schema_mismatch":
      return [
        "Send a complete admission tuple plus client registration record before treating a SharedWorker attach as admitted.",
        "Fail closed when required handshake fields or features drift.",
      ];
    case "coordinator_bootstrap_failure":
      return [
        "Provide a same-origin SharedWorker script URL or a custom workerFactory before attempting attach.",
        "Treat coordinator creation failure as a downgrade trigger, not as partial success.",
      ];
    case "coordinator_crash_or_browser_reclaim":
      return [
        "Downgrade immediately when the SharedWorker crashes or the browser reclaims it.",
        "Re-establish any capability-bearing handles explicitly after coordinator loss.",
      ];
    case "operator_policy_disabled_shared_worker_lane":
      return [
        "Leave the SharedWorker lane opt-in and policy-controlled rather than silently widening Browser Edition behavior.",
        "Keep runtime creation on the fallback lane while this policy flag is disabled.",
      ];
    case "lane_health_demoted":
      return [
        "Honor the current lane-health demotion and stay on the truthful fallback lane until it is reset.",
        "Do not keep attempting SharedWorker attach while the fallback lane is already in a fail-closed state.",
      ];
    default:
      return [
        `Use ${fallbackTarget} as the next truthful downgrade target when SharedWorker attach is denied or lost.`,
        "Keep direct BrowserRuntime creation fail-closed inside the shared-worker host itself.",
      ];
  }
}

export function detectBrowserSharedWorkerCoordinatorSupport(
  options: BrowserSharedWorkerCoordinatorSupportOptions = {},
): BrowserSharedWorkerCoordinatorSupportDiagnostics {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const runtimeSupport = detectBrowserRuntimeSupport(globalObject);
  const hostRole = browserExecutionHostRole(
    globalObject,
    runtimeSupport.capabilities,
  );
  const fallbackTargets = browserSharedWorkerCoordinatorFallbackTargets(
    hostRole,
    options.allowDedicatedWorkerFallback,
    options.allowBrowserMainThreadFallback,
  );
  const fallbackTarget = fallbackTargets[0];
  const fallbackLaneId = browserSharedWorkerCoordinatorFallbackLaneId(
    fallbackTarget,
  );
  const origin = normalizeOptionalBrowserSharedWorkerCoordinatorString(
    options.origin ?? browserSharedWorkerCoordinatorOrigin(globalObject),
  );
  const appNamespace = normalizeOptionalBrowserSharedWorkerCoordinatorString(
    options.appNamespace,
  );
  const appVersionMajor =
    normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
      options.appVersionMajor,
    );
  const coordinatorProtocolVersion =
    normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
      options.coordinatorProtocolVersion,
    );
  const runProfile =
    normalizeOptionalBrowserSharedWorkerCoordinatorString(options.runProfile)
    ?? "ephemeral";
  const backend = options.backend ?? "indexeddb";
  const workerName = normalizeOptionalBrowserSharedWorkerCoordinatorString(
    options.workerName,
  );
  const scriptUrl = browserSharedWorkerCoordinatorResolvedScriptUrl(
    options.scriptUrl,
    globalObject,
  );
  const scriptOrigin = browserSharedWorkerCoordinatorScriptOrigin(scriptUrl);
  const sharedWorkerCtor = options.workerFactory
    ? null
    : browserSharedWorkerConstructor(globalObject);

  let reason: BrowserSharedWorkerCoordinatorSupportReason = "supported";
  if (options.operatorEnabled === false) {
    reason = "operator_policy_disabled_shared_worker_lane";
  } else if (
    hostRole !== "browser_main_thread"
    && hostRole !== "dedicated_worker"
  ) {
    reason = "shared_worker_api_missing";
  } else if (!options.workerFactory && sharedWorkerCtor === null) {
    reason = "shared_worker_api_missing";
  } else if (!options.workerFactory && scriptUrl === null) {
    reason = "coordinator_bootstrap_failure";
  } else if (origin === null || origin === "null") {
    reason = "origin_not_same_origin_or_opaque";
  } else if (scriptOrigin !== null && scriptOrigin !== origin) {
    reason = "origin_not_same_origin_or_opaque";
  } else if (
    appNamespace === null
    || appVersionMajor === null
    || coordinatorProtocolVersion === null
  ) {
    reason = "registration_schema_mismatch";
  } else if (
    runProfile !== "ephemeral"
    && (
      (backend === "indexeddb" && browserIndexedDbFactory(globalObject) === null)
      || (backend === "localstorage"
        && browserLocalStorage(globalObject) === null)
    )
  ) {
    reason = "durable_store_unavailable_for_recovery_required_profile";
  }

  const guidance = browserSharedWorkerCoordinatorGuidance(
    reason,
    fallbackTarget,
  );
  const directExecutionReasonCode = browserExecutionReasonCodeFromRuntimeSupport(
    runtimeSupport.reason,
  );
  const message =
    reason === "supported"
      ? "@asupersync/browser shared-worker coordinator prerequisites are available; direct BrowserRuntime creation remains fail-closed inside the shared-worker host and attach must downgrade explicitly on denial or loss."
      : `@asupersync/browser shared-worker coordinator prerequisites are not satisfied: ${reason}.`;

  return {
    supported: reason === "supported",
    contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
    requestedLane: BROWSER_SHARED_WORKER_COORDINATOR_LANE,
    fallbackTarget,
    fallbackLaneId,
    downgradeOrder: fallbackTargets,
    backend,
    hostRole,
    runtimeContext: runtimeSupport.runtimeContext,
    reason,
    message,
    guidance,
    origin,
    appNamespace,
    appVersionMajor,
    coordinatorProtocolVersion,
    runProfile,
    scriptUrl,
    workerName,
    directRuntimeReason: runtimeSupport.reason,
    directExecutionReasonCode,
    runtimeSupport,
    capabilities: runtimeSupport.capabilities,
  };
}

export function createBrowserSharedWorkerCoordinatorUnsupportedError(
  diagnostics: BrowserSharedWorkerCoordinatorSupportDiagnostics,
): Error & {
  code: typeof BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED_CODE;
  diagnostics: BrowserSharedWorkerCoordinatorSupportDiagnostics;
} {
  const error = new Error(
    `${BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED_CODE}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED_CODE;
    diagnostics: BrowserSharedWorkerCoordinatorSupportDiagnostics;
  };
  error.code = BROWSER_SHARED_WORKER_COORDINATOR_UNSUPPORTED_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertBrowserSharedWorkerCoordinatorSupport(
  diagnostics: BrowserSharedWorkerCoordinatorSupportDiagnostics = detectBrowserSharedWorkerCoordinatorSupport(),
): BrowserSharedWorkerCoordinatorSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createBrowserSharedWorkerCoordinatorUnsupportedError(diagnostics);
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
    executionLadder: BrowserExecutionLadderDiagnostics | undefined = undefined,
    options: BrowserLaneHealthOptions = {},
  ) {
    this.globalObject = options.globalObject;
    this.healthPolicy = options.healthPolicy;
    this.healthScopeKey = options.healthScopeKey ?? null;
    this.now = options.now ?? Date.now;
    const initialExecutionLadder =
      executionLadder ??
      detectBrowserExecutionLadder({
        globalObject: this.globalObject,
        healthPolicy: this.healthPolicy,
        healthScopeKey: this.healthScopeKey,
        now: this.now,
      });
    this.diagnostics = createBrowserSdkDiagnostics(
      consumerVersion,
      initialExecutionLadder,
    );
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

function isBrowserServiceWorkerBrokerLifecycleState(
  value: unknown,
): value is BrowserServiceWorkerBrokerLifecycleState {
  return (
    value === "cold_start"
    || value === "validating_scope"
    || value === "reconciling_durable_state"
    || value === "brokering"
    || value === "draining"
    || value === "quiescent"
    || value === "terminated"
  );
}

function normalizeBrowserServiceWorkerBrokerLifecycleState(
  value: BrowserServiceWorkerBrokerLifecycleState | undefined,
): BrowserServiceWorkerBrokerLifecycleState {
  return value ?? "cold_start";
}

function normalizeBrowserServiceWorkerBrokerFallbackTarget(
  value: BrowserServiceWorkerBrokerFallbackTarget | null | undefined,
  fallbackTarget: BrowserServiceWorkerBrokerFallbackTarget,
): BrowserServiceWorkerBrokerFallbackTarget {
  const candidate = value ?? fallbackTarget;
  if (
    candidate === BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE
    || candidate === BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE
    || candidate === BROWSER_BRIDGE_ONLY_FALLBACK_TARGET
  ) {
    return candidate;
  }
  throw new TypeError("service-worker broker fallback target is invalid");
}

function normalizeBrowserServiceWorkerBrokerMetadata(
  value: Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (!value) {
    return null;
  }
  return { ...value };
}

function normalizeBrowserServiceWorkerBrokerLeaseEpoch(
  value: number,
): number {
  if (!Number.isFinite(value)) {
    throw new TypeError("service-worker broker lease_epoch must be a finite number");
  }
  return Math.max(0, Math.trunc(value));
}

function normalizeBrowserServiceWorkerBrokerAdmissionTuple(
  admission: BrowserServiceWorkerBrokerAdmissionTuple,
): BrowserServiceWorkerBrokerAdmissionTuple {
  return {
    origin: normalizeBrowserServiceWorkerBrokerString(
      admission.origin,
      "service-worker broker origin",
    ),
    registrationScope: normalizeBrowserServiceWorkerBrokerString(
      admission.registrationScope,
      "service-worker broker registration_scope",
    ),
    appNamespace: normalizeBrowserServiceWorkerBrokerString(
      admission.appNamespace,
      "service-worker broker app_namespace",
    ),
    appVersionMajor: Math.max(
      0,
      Math.trunc(
        normalizeOptionalBrowserServiceWorkerBrokerVersion(
          admission.appVersionMajor,
        ) ?? 0,
      ),
    ),
    brokerProtocolVersion: Math.max(
      0,
      Math.trunc(
        normalizeOptionalBrowserServiceWorkerBrokerVersion(
          admission.brokerProtocolVersion,
        ) ?? 0,
      ),
    ),
    runProfile: normalizeBrowserServiceWorkerBrokerString(
      admission.runProfile,
      "service-worker broker run_profile",
    ),
  };
}

function parseBrowserServiceWorkerBrokerAdmissionTuple(
  value: unknown,
): BrowserServiceWorkerBrokerAdmissionTuple {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("service-worker broker admission tuple must be an object");
  }
  const candidate = value as Partial<BrowserServiceWorkerBrokerAdmissionTuple>;
  if (
    typeof candidate.origin !== "string"
    || typeof candidate.registrationScope !== "string"
    || typeof candidate.appNamespace !== "string"
    || typeof candidate.appVersionMajor !== "number"
    || typeof candidate.brokerProtocolVersion !== "number"
    || typeof candidate.runProfile !== "string"
  ) {
    throw new Error("service-worker broker admission tuple is missing required fields");
  }
  return normalizeBrowserServiceWorkerBrokerAdmissionTuple(
    candidate as BrowserServiceWorkerBrokerAdmissionTuple,
  );
}

function parseBrowserServiceWorkerBrokerRegistration(
  value: unknown,
): BrowserServiceWorkerBrokerRegistration {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("service-worker broker registration must be an object");
  }
  const candidate = value as Partial<BrowserServiceWorkerBrokerRegistration>;
  if (
    candidate.contractId !== BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID
    || candidate.requestedLane !== BROWSER_SERVICE_WORKER_BROKER_LANE
    || typeof candidate.backend !== "string"
    || !Array.isArray(candidate.downgradeOrder)
    || typeof candidate.capabilityManifestVersion !== "string"
    || typeof candidate.controllerPresent !== "boolean"
    || typeof candidate.directExecutionReasonCode !== "string"
    || typeof candidate.registeredAtMs !== "number"
    || typeof candidate.updatedAtMs !== "number"
  ) {
    throw new Error("service-worker broker registration is missing required fields");
  }
  if (!isBrowserServiceWorkerBrokerLifecycleState(candidate.lifecycleState)) {
    throw new Error("service-worker broker registration lifecycle_state is invalid");
  }
  const fallbackTarget = normalizeBrowserServiceWorkerBrokerFallbackTarget(
    candidate.fallbackTarget,
    BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
  );
  return {
    contractId: BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
    requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
    fallbackTarget,
    fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
    downgradeOrder: candidate.downgradeOrder.map((target) =>
      normalizeBrowserServiceWorkerBrokerFallbackTarget(
        target,
        BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
      )
    ),
    backend:
      candidate.backend === "indexeddb" ? "indexeddb" : "localstorage",
    admission: parseBrowserServiceWorkerBrokerAdmissionTuple(candidate.admission),
    capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
      candidate.capabilityManifestVersion,
      "service-worker broker capability_manifest_version",
    ),
    lifecycleState: candidate.lifecycleState,
    controllerPresent: candidate.controllerPresent,
    directExecutionReasonCode: candidate.directExecutionReasonCode as BrowserExecutionReasonCode,
    registeredAtMs: Math.max(0, Math.trunc(candidate.registeredAtMs)),
    updatedAtMs: Math.max(0, Math.trunc(candidate.updatedAtMs)),
  };
}

function parseBrowserServiceWorkerBrokerDescriptor(
  value: unknown,
): BrowserServiceWorkerBrokerDescriptor {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("service-worker broker descriptor must be an object");
  }
  const candidate = value as Partial<BrowserServiceWorkerBrokerDescriptor>;
  if (
    candidate.requestedLane !== BROWSER_SERVICE_WORKER_BROKER_LANE
    || typeof candidate.artifactNamespace !== "string"
    || typeof candidate.brokerWorkId !== "string"
    || typeof candidate.capabilityManifestVersion !== "string"
    || typeof candidate.idempotencyKey !== "string"
    || typeof candidate.leaseEpoch !== "number"
    || typeof candidate.sourceEventKind !== "string"
    || typeof candidate.createdAtMs !== "number"
    || typeof candidate.updatedAtMs !== "number"
  ) {
    throw new Error("service-worker broker descriptor is missing required fields");
  }
  const fallbackTarget = normalizeBrowserServiceWorkerBrokerFallbackTarget(
    candidate.fallbackTarget,
    BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
  );
  return {
    artifactNamespace: normalizeBrowserServiceWorkerBrokerString(
      candidate.artifactNamespace,
      "service-worker broker artifact_namespace",
    ),
    brokerWorkId: normalizeBrowserServiceWorkerBrokerString(
      candidate.brokerWorkId,
      "service-worker broker broker_work_id",
    ),
    capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
      candidate.capabilityManifestVersion,
      "service-worker broker capability_manifest_version",
    ),
    createdAtMs: Math.max(0, Math.trunc(candidate.createdAtMs)),
    fallbackTarget,
    fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
    idempotencyKey: normalizeBrowserServiceWorkerBrokerString(
      candidate.idempotencyKey,
      "service-worker broker idempotency_key",
    ),
    leaseEpoch: normalizeBrowserServiceWorkerBrokerLeaseEpoch(
      candidate.leaseEpoch,
    ),
    metadata: normalizeBrowserServiceWorkerBrokerMetadata(
      (candidate.metadata as Record<string, unknown> | null | undefined),
    ),
    requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
    sourceEventKind: normalizeBrowserServiceWorkerBrokerString(
      candidate.sourceEventKind,
      "service-worker broker source_event_kind",
    ),
    updatedAtMs: Math.max(0, Math.trunc(candidate.updatedAtMs)),
  };
}

function parseBrowserServiceWorkerBrokerHandoffRecord(
  value: unknown,
): BrowserServiceWorkerBrokerHandoffRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("service-worker broker handoff record must be an object");
  }
  const candidate = value as Partial<BrowserServiceWorkerBrokerHandoffRecord>;
  if (
    candidate.requestedLane !== BROWSER_SERVICE_WORKER_BROKER_LANE
    || typeof candidate.artifactNamespace !== "string"
    || typeof candidate.brokerWorkId !== "string"
    || typeof candidate.capabilityManifestVersion !== "string"
    || typeof candidate.idempotencyKey !== "string"
    || typeof candidate.leaseEpoch !== "number"
    || typeof candidate.sourceEventKind !== "string"
    || typeof candidate.reason !== "string"
    || typeof candidate.recordedAtMs !== "number"
  ) {
    throw new Error("service-worker broker handoff record is missing required fields");
  }
  const fallbackTarget = normalizeBrowserServiceWorkerBrokerFallbackTarget(
    candidate.fallbackTarget,
    BROWSER_BRIDGE_ONLY_FALLBACK_TARGET,
  );
  const targetLane = normalizeBrowserServiceWorkerBrokerFallbackTarget(
    candidate.targetLane,
    fallbackTarget,
  );
  return {
    artifactNamespace: normalizeBrowserServiceWorkerBrokerString(
      candidate.artifactNamespace,
      "service-worker broker artifact_namespace",
    ),
    brokerWorkId: normalizeBrowserServiceWorkerBrokerString(
      candidate.brokerWorkId,
      "service-worker broker broker_work_id",
    ),
    capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
      candidate.capabilityManifestVersion,
      "service-worker broker capability_manifest_version",
    ),
    fallbackTarget,
    fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
    idempotencyKey: normalizeBrowserServiceWorkerBrokerString(
      candidate.idempotencyKey,
      "service-worker broker idempotency_key",
    ),
    leaseEpoch: normalizeBrowserServiceWorkerBrokerLeaseEpoch(
      candidate.leaseEpoch,
    ),
    metadata: normalizeBrowserServiceWorkerBrokerMetadata(
      (candidate.metadata as Record<string, unknown> | null | undefined),
    ),
    reason:
      normalizeBrowserServiceWorkerBrokerString(
        candidate.reason,
        "service-worker broker reason",
      ) as BrowserServiceWorkerBrokerSupportReason | BrowserExecutionReasonCode,
    recordedAtMs: Math.max(0, Math.trunc(candidate.recordedAtMs)),
    requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
    sourceEventKind: normalizeBrowserServiceWorkerBrokerString(
      candidate.sourceEventKind,
      "service-worker broker source_event_kind",
    ),
    targetLane,
    targetLaneId: browserServiceWorkerBrokerFallbackLaneId(targetLane),
  };
}

export class BrowserServiceWorkerBrokerStore {
  readonly allowBrowserMainThreadFallback: boolean;
  readonly allowDedicatedWorkerFallback: boolean;
  readonly backend: BrowserStorageBackend;
  readonly dbName: string;
  readonly globalObject: Record<string, unknown> | undefined;
  readonly namespace: string;
  readonly now: () => number;
  readonly storeName: string;
  readonly version: number;

  constructor(options: BrowserServiceWorkerBrokerStoreOptions = {}) {
    this.allowBrowserMainThreadFallback =
      options.allowBrowserMainThreadFallback !== false;
    this.allowDedicatedWorkerFallback =
      options.allowDedicatedWorkerFallback !== false;
    this.backend = options.backend ?? "indexeddb";
    this.dbName = options.dbName ?? DEFAULT_INDEXEDDB_NAME;
    this.globalObject = options.globalObject ?? defaultGlobalObject();
    this.namespace = normalizeBrowserStorageNamespace(
      options.namespace ?? DEFAULT_BROWSER_SERVICE_WORKER_BROKER_NAMESPACE,
    );
    this.now = options.now ?? (() => Date.now());
    this.storeName = options.storeName ?? DEFAULT_INDEXEDDB_STORE;
    this.version = options.version ?? DEFAULT_INDEXEDDB_VERSION;
  }

  diagnostics(
    overrides: Omit<
      BrowserServiceWorkerBrokerSupportOptions,
      | "allowBrowserMainThreadFallback"
      | "allowDedicatedWorkerFallback"
      | "backend"
      | "globalObject"
    > = {},
  ): BrowserServiceWorkerBrokerSupportDiagnostics {
    return detectBrowserServiceWorkerBrokerSupport({
      ...overrides,
      allowBrowserMainThreadFallback: this.allowBrowserMainThreadFallback,
      allowDedicatedWorkerFallback: this.allowDedicatedWorkerFallback,
      backend: this.backend,
      globalObject: this.globalObject,
    });
  }

  private assertSupported(
    overrides: Parameters<BrowserServiceWorkerBrokerStore["diagnostics"]>[0] = {},
  ): BrowserServiceWorkerBrokerSupportDiagnostics {
    return assertBrowserServiceWorkerBrokerSupport(this.diagnostics(overrides));
  }

  private operationDiagnostics(
    operation: BrowserServiceWorkerBrokerOperation,
    reason: BrowserServiceWorkerBrokerFailureReason,
    message: string,
    brokerWorkId?: string,
  ): BrowserServiceWorkerBrokerOperationDiagnostics {
    const support = this.diagnostics();
    return {
      backend: this.backend,
      namespace: this.namespace,
      operation,
      brokerWorkId,
      reason,
      message,
      guidance: browserServiceWorkerBrokerOperationGuidance(reason),
      fallbackTarget: support.fallbackTarget,
      fallbackLaneId: support.fallbackLaneId,
      directExecutionReasonCode: support.directExecutionReasonCode,
      runtimeContext: support.runtimeContext,
      capabilities: support.capabilities,
    };
  }

  private operationError(
    operation: BrowserServiceWorkerBrokerOperation,
    reason: BrowserServiceWorkerBrokerFailureReason,
    message: string,
    brokerWorkId?: string,
  ): Error & {
    code: typeof BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE;
    diagnostics: BrowserServiceWorkerBrokerOperationDiagnostics;
  } {
    return createBrowserServiceWorkerBrokerOperationError(
      this.operationDiagnostics(operation, reason, message, brokerWorkId),
    );
  }

  private isBrokerOperationError(error: unknown): boolean {
    return (
      typeof error === "object"
      && error !== null
      && "code" in error
      && (error as { code?: string }).code
        === BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED_CODE
    );
  }

  private async getRaw(
    key: string,
    operation: BrowserServiceWorkerBrokerOperation,
    brokerWorkId?: string,
  ): Promise<Uint8Array | null> {
    this.assertSupported();

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
            encodeIndexedDbStorageKey(this.namespace, key, this.globalObject),
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
        throw new Error("localStorage is unavailable in this browser/runtime");
      }
      const result = storage.getItem(
        encodeLocalStorageKey(this.namespace, key, this.globalObject),
      );
      if (result === null) {
        return null;
      }
      const decoded = decodeBrowserStorageBytes(result, this.globalObject);
      if (decoded === null) {
        throw new Error("service-worker broker durable state could not be decoded from storage");
      }
      return decoded;
    } catch (error) {
      throw this.operationError(
        operation,
        "storage_failed",
        errorMessage(error),
        brokerWorkId,
      );
    }
  }

  private async setRaw(
    key: string,
    value: Uint8Array,
    operation: BrowserServiceWorkerBrokerOperation,
    brokerWorkId?: string,
  ): Promise<void> {
    this.assertSupported();

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
            value,
            encodeIndexedDbStorageKey(this.namespace, key, this.globalObject),
          );
          await awaitIndexedDbTransaction(transaction);
          return;
        } finally {
          database.close();
        }
      }

      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw new Error("localStorage is unavailable in this browser/runtime");
      }
      storage.setItem(
        encodeLocalStorageKey(this.namespace, key, this.globalObject),
        encodeBrowserStorageBytes(value, this.globalObject),
      );
    } catch (error) {
      throw this.operationError(
        operation,
        "storage_failed",
        errorMessage(error),
        brokerWorkId,
      );
    }
  }

  private async deleteRaw(
    key: string,
    operation: BrowserServiceWorkerBrokerOperation,
    brokerWorkId?: string,
  ): Promise<boolean> {
    this.assertSupported();

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
            this.namespace,
            key,
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
        throw new Error("localStorage is unavailable in this browser/runtime");
      }
      const storageKey = encodeLocalStorageKey(
        this.namespace,
        key,
        this.globalObject,
      );
      const existed = storage.getItem(storageKey) !== null;
      storage.removeItem(storageKey);
      return existed;
    } catch (error) {
      throw this.operationError(
        operation,
        "storage_failed",
        errorMessage(error),
        brokerWorkId,
      );
    }
  }

  private async listNamespaceKeys(
    operation: BrowserServiceWorkerBrokerOperation,
  ): Promise<string[]> {
    this.assertSupported();

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
          const rawKeys = await awaitIndexedDbRequest(store.getAllKeys());
          const keys = Array.from(rawKeys as ArrayLike<unknown>)
            .map((value) =>
              typeof value === "string"
                ? decodeIndexedDbStorageKey(
                    value,
                    this.namespace,
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
        throw new Error("localStorage is unavailable in this browser/runtime");
      }
      const prefix = localStorageNamespacePrefix(
        this.namespace,
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
          this.namespace,
          this.globalObject,
        );
        if (decoded !== null) {
          keys.push(decoded);
        }
      }
      keys.sort();
      return Array.from(new Set(keys));
    } catch (error) {
      throw this.operationError(
        operation,
        "storage_failed",
        errorMessage(error),
      );
    }
  }

  private async clearNamespace(
    operation: BrowserServiceWorkerBrokerOperation,
  ): Promise<number> {
    const keys = await this.listNamespaceKeys(operation);
    if (keys.length === 0) {
      return 0;
    }

    if (this.backend === "indexeddb") {
      try {
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
              encodeIndexedDbStorageKey(this.namespace, key, this.globalObject),
            );
          }
          await awaitIndexedDbTransaction(transaction);
          return keys.length;
        } finally {
          database.close();
        }
      } catch (error) {
        throw this.operationError(
          operation,
          "storage_failed",
          errorMessage(error),
        );
      }
    }

    try {
      const storage = browserLocalStorage(this.globalObject);
      if (!storage) {
        throw new Error("localStorage is unavailable in this browser/runtime");
      }
      for (const key of keys) {
        storage.removeItem(
          encodeLocalStorageKey(this.namespace, key, this.globalObject),
        );
      }
      return keys.length;
    } catch (error) {
      throw this.operationError(
        operation,
        "storage_failed",
        errorMessage(error),
      );
    }
  }

  private decodeJsonRecord<T>(
    raw: Uint8Array,
    operation: BrowserServiceWorkerBrokerOperation,
    parser: (value: unknown) => T,
    brokerWorkId?: string,
  ): T {
    try {
      const candidate = JSON.parse(
        browserTextDecoder(this.globalObject).decode(raw),
      );
      return parser(candidate);
    } catch (error) {
      throw this.operationError(
        operation,
        "broker_restart_reconciliation_failed",
        errorMessage(error),
        brokerWorkId,
      );
    }
  }

  private async readJsonRecord<T>(
    key: string,
    operation: BrowserServiceWorkerBrokerOperation,
    parser: (value: unknown) => T,
    brokerWorkId?: string,
  ): Promise<T | null> {
    const raw = await this.getRaw(key, operation, brokerWorkId);
    if (raw === null) {
      return null;
    }
    return this.decodeJsonRecord(raw, operation, parser, brokerWorkId);
  }

  private async writeJsonRecord(
    key: string,
    value: unknown,
    operation: BrowserServiceWorkerBrokerOperation,
    brokerWorkId?: string,
  ): Promise<void> {
    try {
      const serialized = JSON.stringify(value);
      if (serialized === undefined) {
        throw new TypeError("service-worker broker durable state must be JSON-serializable");
      }
      await this.setRaw(
        key,
        browserTextEncoder(this.globalObject).encode(serialized),
        operation,
        brokerWorkId,
      );
    } catch (error) {
      if (this.isBrokerOperationError(error)) {
        throw error;
      }
      throw this.operationError(
        operation,
        "serialization_failed",
        errorMessage(error),
        brokerWorkId,
      );
    }
  }

  async readRegistration(): Promise<BrowserServiceWorkerBrokerRegistration | null> {
    return this.readJsonRecord(
      BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY,
      "read_registration",
      parseBrowserServiceWorkerBrokerRegistration,
    );
  }

  async registerBroker(
    request: BrowserServiceWorkerBrokerRegistrationRequest,
  ): Promise<BrowserServiceWorkerBrokerRegistration> {
    const admission = normalizeBrowserServiceWorkerBrokerAdmissionTuple(
      request.admission,
    );
    const support = this.assertSupported({
      appNamespace: admission.appNamespace,
      appVersionMajor: admission.appVersionMajor,
      brokerProtocolVersion: admission.brokerProtocolVersion,
      controllerPresent: request.controllerPresent,
      expectedRegistrationScope: admission.registrationScope,
      runProfile: admission.runProfile,
    });
    const existing = await this.readRegistration();
    const now = Math.max(0, Math.trunc(this.now()));
    const fallbackTarget = support.fallbackTarget;
    const registration: BrowserServiceWorkerBrokerRegistration = {
      contractId: BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
      requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
      fallbackTarget,
      fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
      downgradeOrder: [...support.downgradeOrder],
      backend: this.backend,
      admission,
      capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
        request.capabilityManifestVersion,
        "service-worker broker capability_manifest_version",
      ),
      lifecycleState: normalizeBrowserServiceWorkerBrokerLifecycleState(
        request.lifecycleState ?? "validating_scope",
      ),
      controllerPresent:
        request.controllerPresent ?? support.controllerPresent,
      directExecutionReasonCode: support.directExecutionReasonCode,
      registeredAtMs: existing?.registeredAtMs ?? now,
      updatedAtMs: now,
    };
    await this.writeJsonRecord(
      BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY,
      registration,
      "write_registration",
    );
    return registration;
  }

  async setLifecycleState(
    lifecycleState: BrowserServiceWorkerBrokerLifecycleState,
  ): Promise<BrowserServiceWorkerBrokerRegistration | null> {
    const registration = await this.readRegistration();
    if (!registration) {
      return null;
    }
    const updated: BrowserServiceWorkerBrokerRegistration = {
      ...registration,
      lifecycleState: normalizeBrowserServiceWorkerBrokerLifecycleState(
        lifecycleState,
      ),
      updatedAtMs: Math.max(0, Math.trunc(this.now())),
    };
    await this.writeJsonRecord(
      BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY,
      updated,
      "set_lifecycle",
    );
    return updated;
  }

  async clearRegistration(): Promise<boolean> {
    return this.deleteRaw(
      BROWSER_SERVICE_WORKER_BROKER_REGISTRATION_KEY,
      "clear_registration",
    );
  }

  async listPendingWork(): Promise<BrowserServiceWorkerBrokerDescriptor[]> {
    const keys = await this.listNamespaceKeys("list_work");
    const workKeys = keys.filter((key) =>
      key.startsWith(BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX)
    );
    const descriptors = await Promise.all(
      workKeys.map(async (key) => {
        const brokerWorkId = key.slice(
          BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX.length,
        );
        return this.readJsonRecord(
          key,
          "list_work",
          parseBrowserServiceWorkerBrokerDescriptor,
          brokerWorkId,
        );
      }),
    );
    return descriptors
      .filter(
        (descriptor): descriptor is BrowserServiceWorkerBrokerDescriptor =>
          descriptor !== null,
      )
      .sort((left, right) => right.updatedAtMs - left.updatedAtMs);
  }

  async persistBrokerWork(
    request: BrowserServiceWorkerBrokerDescriptorRequest,
  ): Promise<BrowserServiceWorkerBrokerDescriptor> {
    const registration = await this.readRegistration();
    if (!registration) {
      throw this.operationError(
        "persist_work",
        "broker_bootstrap_failure",
        "registerBroker() must succeed before persistBrokerWork() claims durable restartable work.",
        request.brokerWorkId,
      );
    }
    const brokerWorkId = normalizeBrowserServiceWorkerBrokerString(
      request.brokerWorkId,
      "service-worker broker broker_work_id",
    );
    const fallbackTarget = normalizeBrowserServiceWorkerBrokerFallbackTarget(
      request.fallbackTarget,
      registration.fallbackTarget,
    );
    const now = Math.max(0, Math.trunc(this.now()));
    const existing = await this.readJsonRecord(
      `${BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX}${brokerWorkId}`,
      "persist_work",
      parseBrowserServiceWorkerBrokerDescriptor,
      brokerWorkId,
    );
    const descriptor: BrowserServiceWorkerBrokerDescriptor = {
      artifactNamespace: normalizeBrowserServiceWorkerBrokerString(
        request.artifactNamespace,
        "service-worker broker artifact_namespace",
      ),
      brokerWorkId,
      capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
        request.capabilityManifestVersion,
        "service-worker broker capability_manifest_version",
      ),
      createdAtMs: existing?.createdAtMs ?? now,
      fallbackTarget,
      fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
      idempotencyKey: normalizeBrowserServiceWorkerBrokerString(
        request.idempotencyKey,
        "service-worker broker idempotency_key",
      ),
      leaseEpoch: normalizeBrowserServiceWorkerBrokerLeaseEpoch(
        request.leaseEpoch,
      ),
      metadata: normalizeBrowserServiceWorkerBrokerMetadata(request.metadata),
      requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
      sourceEventKind: normalizeBrowserServiceWorkerBrokerString(
        request.sourceEventKind,
        "service-worker broker source_event_kind",
      ),
      updatedAtMs: now,
    };
    await this.writeJsonRecord(
      `${BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX}${brokerWorkId}`,
      descriptor,
      "persist_work",
      brokerWorkId,
    );
    return descriptor;
  }

  async deleteBrokerWork(brokerWorkId: string): Promise<boolean> {
    const normalized = normalizeBrowserServiceWorkerBrokerString(
      brokerWorkId,
      "service-worker broker broker_work_id",
    );
    return this.deleteRaw(
      `${BROWSER_SERVICE_WORKER_BROKER_WORK_PREFIX}${normalized}`,
      "delete_work",
      normalized,
    );
  }

  async listDurableHandoffs(): Promise<BrowserServiceWorkerBrokerHandoffRecord[]> {
    const keys = await this.listNamespaceKeys("list_handoffs");
    const handoffKeys = keys.filter((key) =>
      key.startsWith(BROWSER_SERVICE_WORKER_BROKER_HANDOFF_PREFIX)
    );
    const records = await Promise.all(
      handoffKeys.map(async (key) => {
        const brokerWorkId = key.slice(
          BROWSER_SERVICE_WORKER_BROKER_HANDOFF_PREFIX.length,
        );
        return this.readJsonRecord(
          key,
          "list_handoffs",
          parseBrowserServiceWorkerBrokerHandoffRecord,
          brokerWorkId,
        );
      }),
    );
    return records
      .filter(
        (record): record is BrowserServiceWorkerBrokerHandoffRecord =>
          record !== null,
      )
      .sort((left, right) => right.recordedAtMs - left.recordedAtMs);
  }

  async persistDurableHandoff(
    request: BrowserServiceWorkerBrokerHandoffRequest,
  ): Promise<BrowserServiceWorkerBrokerHandoffRecord> {
    const registration = await this.readRegistration();
    if (!registration) {
      throw this.operationError(
        "persist_handoff",
        "broker_bootstrap_failure",
        "registerBroker() must succeed before persistDurableHandoff() records fallback metadata.",
        request.brokerWorkId,
      );
    }
    const brokerWorkId = normalizeBrowserServiceWorkerBrokerString(
      request.brokerWorkId,
      "service-worker broker broker_work_id",
    );
    const fallbackTarget = normalizeBrowserServiceWorkerBrokerFallbackTarget(
      request.fallbackTarget,
      registration.fallbackTarget,
    );
    const targetLane = normalizeBrowserServiceWorkerBrokerFallbackTarget(
      request.targetLane,
      fallbackTarget,
    );
    const record: BrowserServiceWorkerBrokerHandoffRecord = {
      artifactNamespace: normalizeBrowserServiceWorkerBrokerString(
        request.artifactNamespace,
        "service-worker broker artifact_namespace",
      ),
      brokerWorkId,
      capabilityManifestVersion: normalizeBrowserServiceWorkerBrokerString(
        request.capabilityManifestVersion,
        "service-worker broker capability_manifest_version",
      ),
      fallbackTarget,
      fallbackLaneId: browserServiceWorkerBrokerFallbackLaneId(fallbackTarget),
      idempotencyKey: normalizeBrowserServiceWorkerBrokerString(
        request.idempotencyKey,
        "service-worker broker idempotency_key",
      ),
      leaseEpoch: normalizeBrowserServiceWorkerBrokerLeaseEpoch(
        request.leaseEpoch,
      ),
      metadata: normalizeBrowserServiceWorkerBrokerMetadata(request.metadata),
      reason:
        (
          request.reason
          ?? registration.directExecutionReasonCode
        ) as BrowserServiceWorkerBrokerSupportReason | BrowserExecutionReasonCode,
      recordedAtMs: Math.max(0, Math.trunc(this.now())),
      requestedLane: BROWSER_SERVICE_WORKER_BROKER_LANE,
      sourceEventKind: normalizeBrowserServiceWorkerBrokerString(
        request.sourceEventKind,
        "service-worker broker source_event_kind",
      ),
      targetLane,
      targetLaneId: browserServiceWorkerBrokerFallbackLaneId(targetLane),
    };
    await this.writeJsonRecord(
      `${BROWSER_SERVICE_WORKER_BROKER_HANDOFF_PREFIX}${brokerWorkId}`,
      record,
      "persist_handoff",
      brokerWorkId,
    );
    return record;
  }

  async clearBrokerState(): Promise<number> {
    return this.clearNamespace("clear_state");
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

function createBrowserSharedWorkerCoordinatorAdmission(
  support: BrowserSharedWorkerCoordinatorSupportDiagnostics,
): BrowserSharedWorkerCoordinatorAdmissionTuple {
  return {
    origin: normalizeBrowserSharedWorkerCoordinatorString(
      support.origin ?? "",
      "shared-worker coordinator origin",
    ),
    appNamespace: normalizeBrowserSharedWorkerCoordinatorString(
      support.appNamespace ?? "",
      "shared-worker coordinator app_namespace",
    ),
    appVersionMajor: normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
      support.appVersionMajor,
    ) ?? 0,
    coordinatorProtocolVersion:
      normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
        support.coordinatorProtocolVersion,
      ) ?? 0,
    runProfile: normalizeBrowserSharedWorkerCoordinatorString(
      support.runProfile,
      "shared-worker coordinator run_profile",
    ),
  };
}

function createBrowserSharedWorkerClientRegistration(
  options: BrowserSharedWorkerCoordinatorSelectionOptions,
  executionLadder: BrowserExecutionLadderDiagnostics,
): BrowserSharedWorkerClientRegistration {
  const now = options.now ?? (() => Date.now());
  BROWSER_SHARED_WORKER_CLIENT_SEQUENCE += 1;
  const clientInstanceId =
    normalizeOptionalBrowserSharedWorkerCoordinatorString(
      options.clientInstanceId,
    )
    ?? `browser-shared-worker-client-${Math.max(0, Math.trunc(now()))}-${BROWSER_SHARED_WORKER_CLIENT_SEQUENCE}`;
  const clientKind =
    normalizeOptionalBrowserSharedWorkerCoordinatorString(options.clientKind)
    ?? (
      executionLadder.hostRole === "dedicated_worker"
        ? "dedicated_worker"
        : "browser_tab"
    );
  const clientCapabilitySummary =
    options.clientCapabilitySummary ?? { ...executionLadder.capabilities };
  return {
    clientInstanceId: normalizeBrowserSharedWorkerCoordinatorString(
      clientInstanceId,
      "shared-worker coordinator client_instance_id",
    ),
    clientEpoch:
      normalizeOptionalBrowserSharedWorkerCoordinatorVersion(
        options.clientEpoch,
      ) ?? 0,
    clientKind: normalizeBrowserSharedWorkerCoordinatorString(
      clientKind,
      "shared-worker coordinator client_kind",
    ),
    clientStartedAtMs: Math.max(
      0,
      Math.trunc(options.clientStartedAtMs ?? now()),
    ),
    clientCapabilitySummary,
    clientArtifactNamespace: normalizeBrowserSharedWorkerCoordinatorString(
      options.clientArtifactNamespace,
      "shared-worker coordinator client_artifact_namespace",
    ),
  };
}

function createBrowserSharedWorkerInstance(
  support: BrowserSharedWorkerCoordinatorSupportDiagnostics,
  options: BrowserSharedWorkerCoordinatorSelectionOptions,
  globalObject: Record<string, unknown> | undefined,
): BrowserSharedWorkerLike {
  const workerName = support.workerName;
  if (options.workerFactory) {
    return options.workerFactory(support.scriptUrl ?? "", workerName);
  }
  const ctor = browserSharedWorkerConstructor(globalObject);
  if (!ctor || support.scriptUrl === null) {
    throw {
      reason: "coordinator_bootstrap_failure",
      message:
        "SharedWorker coordinator attach requires either a same-origin scriptUrl or a custom workerFactory.",
      guidance: browserSharedWorkerCoordinatorGuidance(
        "coordinator_bootstrap_failure",
        support.fallbackTarget,
      ),
    } satisfies BrowserSharedWorkerCoordinatorSelectionFailure;
  }
  return workerName === null
    ? new ctor(support.scriptUrl)
    : new ctor(support.scriptUrl, { name: workerName });
}

function isBrowserSharedWorkerCoordinatorSelectionFailure(
  error: unknown,
): error is BrowserSharedWorkerCoordinatorSelectionFailure {
  return (
    typeof error === "object"
    && error !== null
    && "reason" in error
    && "message" in error
    && "guidance" in error
  );
}

function isBrowserSharedWorkerCoordinatorHandshakeResponse(
  value: unknown,
): value is BrowserSharedWorkerCoordinatorHandshakeResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<BrowserSharedWorkerCoordinatorHandshakeResponse>;
  return (
    candidate.type === "asupersync.browser.shared_worker.handshake.response"
    && candidate.protocol === BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL
    && candidate.contractId === BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID
    && typeof candidate.accepted === "boolean"
  );
}

function browserSharedWorkerMissingRequiredFeatures(
  required: string[],
  available: string[],
): string[] {
  const availableSet = new Set(available);
  return required.filter((feature) => !availableSet.has(feature));
}

async function awaitBrowserSharedWorkerCoordinatorHandshake(
  port: BrowserSharedWorkerPortLike,
  request: BrowserSharedWorkerCoordinatorHandshakeRequest,
  timeoutMs: number,
  fallbackTarget: BrowserSharedWorkerCoordinatorFallbackTarget,
): Promise<BrowserSharedWorkerCoordinatorHandshakeResponse> {
  return new Promise((resolve, reject) => {
    const fail = (
      reason: BrowserSharedWorkerCoordinatorSupportReason,
      message: string,
      guidance: string[],
    ) => {
      reject({
        reason,
        message,
        guidance,
      } satisfies BrowserSharedWorkerCoordinatorSelectionFailure);
    };

    const timer = setTimeout(() => {
      cleanup();
      fail(
        "coordinator_bootstrap_failure",
        `SharedWorker coordinator attach timed out after ${timeoutMs}ms.`,
        [
          "Keep the SharedWorker attach timeout bounded and deterministic.",
          `Downgrade immediately to ${fallbackTarget} when the coordinator does not answer in time.`,
        ],
      );
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timer);
      port.removeEventListener("message", onMessage);
      port.removeEventListener("messageerror", onMessageError);
    };

    const onMessage = (event: { data?: unknown }) => {
      if (!isBrowserSharedWorkerCoordinatorHandshakeResponse(event.data)) {
        return;
      }
      cleanup();
      resolve(event.data);
    };

    const onMessageError = () => {
      cleanup();
      fail(
        "registration_schema_mismatch",
        "SharedWorker coordinator handshake payload could not be decoded cleanly.",
        [
          "Keep handshake payloads JSON-serializable and pinned to the shared-worker coordinator contract schema.",
          "Fail closed rather than treating an unreadable handshake as partial success.",
        ],
      );
    };

    port.addEventListener("message", onMessage);
    port.addEventListener("messageerror", onMessageError);
    port.start?.();

    try {
      port.postMessage(request);
    } catch (error) {
      cleanup();
      fail(
        "coordinator_bootstrap_failure",
        `SharedWorker coordinator attach failed before the handshake could start: ${errorMessage(error)}`,
        browserSharedWorkerCoordinatorGuidance(
          "coordinator_bootstrap_failure",
          fallbackTarget,
        ),
      );
    }
  });
}

async function createBrowserSharedWorkerFallbackSelection(
  options: BrowserSharedWorkerCoordinatorSelectionOptions,
  support: BrowserSharedWorkerCoordinatorSupportDiagnostics,
  reason: BrowserSharedWorkerCoordinatorSupportReason | BrowserExecutionReasonCode,
  message: string,
  guidance: string[],
): Promise<BrowserSharedWorkerCoordinatorSelectionResult> {
  const runtimeSelection = await createBrowserRuntimeSelection({
    wasmInput: options.wasmInput,
    consumerVersion: options.consumerVersion,
    eagerInit: options.eagerInit,
    globalObject: options.globalObject,
    preferredLane: options.preferredLane,
    healthPolicy: options.healthPolicy,
    healthScopeKey: options.healthScopeKey,
    now: options.now,
  });

  const finalGuidance = [...guidance];
  let finalMessage = message;
  if (!runtimeSelection.executionLadder.supported) {
    finalMessage =
      `${finalMessage} Fallback runtime selection stayed on ${runtimeSelection.executionLadder.selectedLane} because Browser Edition currently reports ${runtimeSelection.executionLadder.reasonCode}.`;
    finalGuidance.push(...runtimeSelection.executionLadder.guidance);
    if (runtimeSelection.executionLadder.reasonCode === "demote_due_to_lane_health") {
      finalGuidance.push(
        ...browserSharedWorkerCoordinatorGuidance(
          "lane_health_demoted",
          support.fallbackTarget,
        ),
      );
    }
  }

  return {
    selectedMode: "fallback",
    support,
    executionLadder: runtimeSelection.executionLadder,
    reason,
    message: finalMessage,
    guidance: Array.from(new Set(finalGuidance)),
    coordinator: null,
    runtimeSelection,
    fallbackTarget: support.fallbackTarget,
    fallbackLaneId: support.fallbackLaneId,
  };
}

export class BrowserSharedWorkerCoordinatorClient {
  private readonly attachDiagnosticsSnapshot: Omit<
    BrowserSharedWorkerCoordinatorAttachDiagnostics,
    "lifecycleState"
  >;
  private readonly portHandle: BrowserSharedWorkerPortLike;
  private readonly workerHandle: BrowserSharedWorkerLike;
  private lifecycleStateValue: BrowserSharedWorkerCoordinatorLifecycleState;

  constructor(
    worker: BrowserSharedWorkerLike,
    port: BrowserSharedWorkerPortLike,
    attachDiagnostics: BrowserSharedWorkerCoordinatorAttachDiagnostics,
  ) {
    this.attachDiagnosticsSnapshot = {
      contractId: attachDiagnostics.contractId,
      requestedLane: attachDiagnostics.requestedLane,
      fallbackTarget: attachDiagnostics.fallbackTarget,
      fallbackLaneId: attachDiagnostics.fallbackLaneId,
      admission: { ...attachDiagnostics.admission },
      client: {
        ...attachDiagnostics.client,
        clientCapabilitySummary:
          attachDiagnostics.client.clientCapabilitySummary === null
            ? null
            : { ...attachDiagnostics.client.clientCapabilitySummary },
      },
      directExecutionLadder: attachDiagnostics.directExecutionLadder,
      coordinatorFeatures: [...attachDiagnostics.coordinatorFeatures],
      scriptUrl: attachDiagnostics.scriptUrl,
      workerName: attachDiagnostics.workerName,
    };
    this.lifecycleStateValue = attachDiagnostics.lifecycleState;
    this.portHandle = port;
    this.workerHandle = worker;
  }

  get lifecycleState(): BrowserSharedWorkerCoordinatorLifecycleState {
    return this.lifecycleStateValue;
  }

  diagnostics(): BrowserSharedWorkerCoordinatorAttachDiagnostics {
    return {
      ...this.attachDiagnosticsSnapshot,
      admission: { ...this.attachDiagnosticsSnapshot.admission },
      client: {
        ...this.attachDiagnosticsSnapshot.client,
        clientCapabilitySummary:
          this.attachDiagnosticsSnapshot.client.clientCapabilitySummary === null
            ? null
            : { ...this.attachDiagnosticsSnapshot.client.clientCapabilitySummary },
      },
      coordinatorFeatures: [...this.attachDiagnosticsSnapshot.coordinatorFeatures],
      lifecycleState: this.lifecycleStateValue,
    };
  }

  postMessage(message: unknown): void {
    this.portHandle.postMessage(message);
  }

  updateLifecycleState(
    lifecycleState: BrowserSharedWorkerCoordinatorLifecycleState,
  ): BrowserSharedWorkerCoordinatorAttachDiagnostics {
    this.lifecycleStateValue =
      normalizeBrowserSharedWorkerCoordinatorLifecycleState(lifecycleState);
    return this.diagnostics();
  }

  close(): void {
    if (this.lifecycleStateValue === "terminated") {
      return;
    }
    if (this.lifecycleStateValue !== "quiescent") {
      this.lifecycleStateValue = "draining";
    }
    try {
      this.portHandle.postMessage({
        type: "asupersync.browser.shared_worker.detach",
        protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
        contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
        clientInstanceId: this.attachDiagnosticsSnapshot.client.clientInstanceId,
        clientEpoch: this.attachDiagnosticsSnapshot.client.clientEpoch,
      });
    } catch {
      // Closing the client must stay best-effort because the browser may have
      // already reclaimed the coordinator or detached the port.
    }
    this.portHandle.close?.();
    void this.workerHandle;
    this.lifecycleStateValue = "terminated";
  }
}

export async function createBrowserSharedWorkerCoordinatorSelection(
  options: BrowserSharedWorkerCoordinatorSelectionOptions,
): Promise<BrowserSharedWorkerCoordinatorSelectionResult> {
  const globalObject = options.globalObject ?? defaultGlobalObject();
  const executionLadder = detectBrowserExecutionLadder({
    globalObject,
    preferredLane: options.preferredLane,
    healthPolicy: options.healthPolicy,
    healthScopeKey: options.healthScopeKey,
    now: options.now,
  });
  const support = detectBrowserSharedWorkerCoordinatorSupport({
    allowBrowserMainThreadFallback: options.allowBrowserMainThreadFallback,
    allowDedicatedWorkerFallback: options.allowDedicatedWorkerFallback,
    appNamespace: options.appNamespace,
    appVersionMajor: options.appVersionMajor,
    backend: options.backend,
    coordinatorProtocolVersion: options.coordinatorProtocolVersion,
    globalObject,
    operatorEnabled: options.operatorEnabled,
    origin: options.origin,
    runProfile: options.runProfile,
    scriptUrl: options.scriptUrl,
    workerFactory: options.workerFactory,
    workerName: options.workerName,
  });

  if (!support.supported) {
    return createBrowserSharedWorkerFallbackSelection(
      options,
      support,
      support.reason,
      support.message,
      support.guidance,
    );
  }

  const admission = createBrowserSharedWorkerCoordinatorAdmission(support);
  const client = createBrowserSharedWorkerClientRegistration(
    options,
    executionLadder,
  );
  const requestedFeatures = {
    required: normalizeBrowserSharedWorkerCoordinatorFeatures(
      options.requiredCoordinatorFeatures,
    ),
    optional: normalizeBrowserSharedWorkerCoordinatorFeatures(
      options.optionalCoordinatorFeatures,
    ),
  } satisfies BrowserSharedWorkerCoordinatorFeatureRequest;
  const handshakeTimeoutMs = Math.max(
    1,
    Math.trunc(options.handshakeTimeoutMs ?? 2_000),
  );

  try {
    const worker = createBrowserSharedWorkerInstance(
      support,
      options,
      globalObject,
    );
    const port = worker.port;
    if (
      !port
      || typeof port.postMessage !== "function"
      || typeof port.addEventListener !== "function"
      || typeof port.removeEventListener !== "function"
    ) {
      throw {
        reason: "coordinator_bootstrap_failure",
        message:
          "SharedWorker coordinator did not expose a usable MessagePort for attach.",
        guidance: browserSharedWorkerCoordinatorGuidance(
          "coordinator_bootstrap_failure",
          support.fallbackTarget,
        ),
      } satisfies BrowserSharedWorkerCoordinatorSelectionFailure;
    }

    const request: BrowserSharedWorkerCoordinatorHandshakeRequest = {
      type: "asupersync.browser.shared_worker.handshake.request",
      protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
      contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
      admission,
      client,
      requestedFeatures,
    };
    const response = await awaitBrowserSharedWorkerCoordinatorHandshake(
      port,
      request,
      handshakeTimeoutMs,
      support.fallbackTarget,
    );
    const responseReason = response.reason ?? "registration_schema_mismatch";
    if (!response.accepted) {
      port.close?.();
      return createBrowserSharedWorkerFallbackSelection(
        options,
        support,
        responseReason,
        response.message
          ?? `SharedWorker coordinator rejected attach with ${responseReason}.`,
        response.guidance
          ?? browserSharedWorkerCoordinatorGuidance(
            responseReason,
            support.fallbackTarget,
          ),
      );
    }

    if (
      response.coordinatorProtocolVersion !== undefined
      && response.coordinatorProtocolVersion !== admission.coordinatorProtocolVersion
    ) {
      port.close?.();
      return createBrowserSharedWorkerFallbackSelection(
        options,
        support,
        "coordinator_protocol_version_mismatch",
        `SharedWorker coordinator reported protocol ${response.coordinatorProtocolVersion}, expected ${admission.coordinatorProtocolVersion}.`,
        browserSharedWorkerCoordinatorGuidance(
          "coordinator_protocol_version_mismatch",
          support.fallbackTarget,
        ),
      );
    }

    const coordinatorFeatures =
      normalizeBrowserSharedWorkerCoordinatorFeatures(
        response.coordinatorFeatures,
      );
    const missingRequiredFeatures =
      browserSharedWorkerMissingRequiredFeatures(
        requestedFeatures.required,
        coordinatorFeatures,
      );
    if (missingRequiredFeatures.length > 0) {
      port.close?.();
      return createBrowserSharedWorkerFallbackSelection(
        options,
        support,
        "registration_schema_mismatch",
        `SharedWorker coordinator is missing required features: ${missingRequiredFeatures.join(", ")}.`,
        browserSharedWorkerCoordinatorGuidance(
          "registration_schema_mismatch",
          support.fallbackTarget,
        ),
      );
    }

    const lifecycleState =
      response.lifecycleState === undefined
        ? "active"
        : normalizeBrowserSharedWorkerCoordinatorLifecycleState(
          response.lifecycleState,
        );
    const coordinator = new BrowserSharedWorkerCoordinatorClient(
      worker,
      port,
      {
        contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
        requestedLane: BROWSER_SHARED_WORKER_COORDINATOR_LANE,
        fallbackTarget: support.fallbackTarget,
        fallbackLaneId: support.fallbackLaneId,
        admission,
        client,
        directExecutionLadder: executionLadder,
        lifecycleState,
        coordinatorFeatures,
        scriptUrl: support.scriptUrl ?? "<custom-worker-factory>",
        workerName: support.workerName,
      },
    );

    return {
      selectedMode: "shared_worker",
      support,
      executionLadder,
      reason: "supported",
      message:
        `@asupersync/browser attached a SharedWorker coordinator and preserved ${support.fallbackTarget} as the truthful downgrade lane.`,
      guidance: [
        "Treat the SharedWorker coordinator as an optional optimization over the current direct-runtime lane, not as a new ambient authority boundary.",
        "Downgrade immediately to the fallback lane whenever the coordinator denies attach, crashes, or is reclaimed by the browser.",
      ],
      coordinator,
      runtimeSelection: null,
      fallbackTarget: support.fallbackTarget,
      fallbackLaneId: support.fallbackLaneId,
    };
  } catch (error) {
    const failure: BrowserSharedWorkerCoordinatorSelectionFailure =
      isBrowserSharedWorkerCoordinatorSelectionFailure(error)
        ? error
        : {
          reason: "coordinator_bootstrap_failure",
          message: `SharedWorker coordinator attach failed: ${errorMessage(error)}`,
          guidance: browserSharedWorkerCoordinatorGuidance(
            "coordinator_bootstrap_failure",
            support.fallbackTarget,
          ),
        };
    return createBrowserSharedWorkerFallbackSelection(
      options,
      support,
      failure.reason,
      failure.message,
      failure.guidance,
    );
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

export function createBrowserServiceWorkerBrokerStore(
  options: BrowserServiceWorkerBrokerStoreOptions = {},
): BrowserServiceWorkerBrokerStore {
  const store = new BrowserServiceWorkerBrokerStore(options);
  assertBrowserServiceWorkerBrokerSupport(store.diagnostics());
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
