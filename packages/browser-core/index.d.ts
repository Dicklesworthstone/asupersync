export type InitInput =
  | RequestInfo
  | URL
  | Response
  | BufferSource
  | WebAssembly.Module
  | Promise<RequestInfo | URL | Response | BufferSource | WebAssembly.Module>;

export interface AbiVersion {
  major: number;
  minor: number;
}

export interface AbiMetadata {
  readonly abi_version: Readonly<AbiVersion>;
  readonly abi_signature_fingerprint_v1: number;
  readonly profile: string;
}

export interface Budget {
  pollQuota: number;
  deadlineMs: number;
  priority: number;
  cleanupQuota: number;
}

export type CancellationPhase =
  | "requested"
  | "cancelling"
  | "finalizing"
  | "completed";

export type ErrorCode =
  | "capability_denied"
  | "invalid_handle"
  | "decode_failure"
  | "compatibility_rejected"
  | "internal_failure";

export type Recoverability = "transient" | "permanent" | "unknown";

export type HandleKind =
  | "runtime"
  | "region"
  | "task"
  | "cancel_token"
  | "fetch_request";

export interface HandleRef {
  kind: HandleKind;
  slot: number;
  generation: number;
}

export interface AbiFailure {
  code: ErrorCode;
  recoverability: Recoverability;
  message: string;
}

export interface AbiCancellation {
  kind: string;
  phase: CancellationPhase;
  origin_region: string;
  origin_task: string | null;
  timestamp_nanos: number;
  message: string | null;
  truncated: boolean;
}

export type HandleLike =
  | HandleRef
  | RuntimeHandle
  | RegionHandle
  | TaskHandle
  | CancellationToken
  | FetchHandle;

export type WasmValue =
  | undefined
  | boolean
  | number
  | string
  | Uint8Array
  | HandleLike;

export type Outcome<T = WasmValue, E = AbiFailure> =
  | { outcome: "ok"; value: T }
  | { outcome: "err"; failure: E }
  | { outcome: "cancelled"; cancellation: AbiCancellation }
  | { outcome: "panicked"; message: string };

export interface ScopeEnterRequest {
  parent: RuntimeHandle | RegionHandle | HandleRef;
  label?: string;
}

export interface TaskSpawnRequest {
  scope: RegionHandle | HandleRef;
  label?: string;
  cancel_kind?: string;
}

export interface TaskCancelRequest {
  task: TaskHandle | HandleRef;
  kind: string;
  message?: string;
}

export interface FetchRequest {
  scope: RegionHandle | HandleRef;
  url: string;
  method: string;
  body?: Uint8Array | ArrayBuffer | ArrayBufferView | number[];
}

export interface WebSocketOpenRequest {
  scope: RegionHandle | HandleRef;
  url: string;
  protocols?: string[];
}

export interface WebSocketSendRequest {
  socket: TaskHandle | HandleRef;
  value: WasmValue;
}

export interface WebSocketRecvRequest {
  socket: TaskHandle | HandleRef;
}

export interface WebSocketCloseRequest {
  socket: TaskHandle | HandleRef;
  reason?: string;
}

export interface WebSocketCancelRequest {
  socket: TaskHandle | HandleRef;
  kind: string;
  message?: string;
}

export interface WebTransportOpenRequest {
  scope: RegionHandle | HandleRef;
  url: string;
  options?: Record<string, unknown>;
}

export interface WebTransportSendRequest {
  session: TaskHandle | HandleRef;
  value: string | Uint8Array | ArrayBuffer | ArrayBufferView | number[];
}

export interface WebTransportRecvRequest {
  session: TaskHandle | HandleRef;
}

export interface WebTransportCloseRequest {
  session: TaskHandle | HandleRef;
  reason?: string;
}

export interface WebTransportCancelRequest {
  session: TaskHandle | HandleRef;
  kind: string;
  message?: string;
}

export declare class BaseHandle {
  readonly kind: HandleKind;
  readonly slot: number;
  readonly generation: number;
  protected constructor(rawHandle: HandleRef, expectedKind?: HandleKind);
  toJSON(): HandleRef;
}

export declare class RuntimeHandle extends BaseHandle {
  constructor(rawHandle: HandleRef);
  close(consumerVersion?: AbiVersion | null): Outcome<void>;
  enterScope(label?: string, consumerVersion?: AbiVersion | null): Outcome<RegionHandle>;
}

export declare class RegionHandle extends BaseHandle {
  constructor(rawHandle: HandleRef);
  close(consumerVersion?: AbiVersion | null): Outcome<void>;
  enterScope(label?: string, consumerVersion?: AbiVersion | null): Outcome<RegionHandle>;
  spawnTask(
    options?: Omit<TaskSpawnRequest, "scope">,
    consumerVersion?: AbiVersion | null,
  ): Outcome<TaskHandle>;
  fetchRequest(
    options: Omit<FetchRequest, "scope">,
    consumerVersion?: AbiVersion | null,
  ): Outcome<FetchHandle>;
  openWebSocket(
    url: string,
    protocols?: string[],
    consumerVersion?: AbiVersion | null,
  ): Outcome<TaskHandle>;
  openWebTransport(
    url: string,
    options?: Record<string, unknown>,
    consumerVersion?: AbiVersion | null,
  ): Outcome<TaskHandle>;
}

export declare class TaskHandle extends BaseHandle {
  constructor(rawHandle: HandleRef);
  join(outcome: Outcome, consumerVersion?: AbiVersion | null): Outcome<WasmValue>;
  cancel(
    kind: string,
    message?: string,
    consumerVersion?: AbiVersion | null,
  ): Outcome<void>;
}

export declare class CancellationToken extends BaseHandle {
  constructor(rawHandle: HandleRef);
}

export declare class FetchHandle extends BaseHandle {
  constructor(rawHandle: HandleRef);
}

export declare const BUDGET_BOUNDS: Readonly<{
  pollQuota: Readonly<{ min: number; max: number }>;
  deadlineMs: Readonly<{ min: number; max: number }>;
  priority: Readonly<{ min: number; max: number }>;
  cleanupQuota: Readonly<{ min: number; max: number }>;
}>;

export declare const CANCELLATION_PHASE_ORDER: readonly CancellationPhase[];
export declare const ERROR_CODES: readonly ErrorCode[];
export declare const RECOVERABILITY_LEVELS: readonly Recoverability[];

export declare const Outcome: Readonly<{
  ok<T>(value: T): Outcome<T>;
  err(code: ErrorCode, recoverability: Recoverability, message: string): Outcome<never>;
  cancelled(cancellation: AbiCancellation): Outcome<never>;
  panicked(message: string): Outcome<never>;
}>;

export declare function createBudget(input?: Partial<Budget>): Budget;

export declare function init(input?: InitInput): Promise<unknown>;
export default init;

export declare function runtime_create(
  consumerVersion?: AbiVersion | null,
): Outcome<RuntimeHandle>;
export declare function runtime_close(
  runtimeHandle: RuntimeHandle | HandleRef,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function scope_enter(
  request: ScopeEnterRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<RegionHandle>;
export declare function scope_close(
  regionHandle: RegionHandle | HandleRef,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function task_spawn(
  request: TaskSpawnRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<TaskHandle>;
export declare function task_join(
  taskHandle: TaskHandle | HandleRef,
  outcome: Outcome,
  consumerVersion?: AbiVersion | null,
): Outcome<WasmValue>;
export declare function task_cancel(
  request: TaskCancelRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function fetch_request(
  request: FetchRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<FetchHandle>;
export declare function websocket_open(
  request: WebSocketOpenRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<TaskHandle>;
export declare function websocket_send(
  request: WebSocketSendRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function websocket_recv(
  request: WebSocketRecvRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<WasmValue>;
export declare function websocket_close(
  request: WebSocketCloseRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function websocket_cancel(
  request: WebSocketCancelRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function webtransport_open(
  request: WebTransportOpenRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<TaskHandle>;
export declare function webtransport_send(
  request: WebTransportSendRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function webtransport_recv(
  request: WebTransportRecvRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<WasmValue>;
export declare function webtransport_close(
  request: WebTransportCloseRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function webtransport_cancel(
  request: WebTransportCancelRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function abi_version(): AbiVersion;
export declare function abi_fingerprint(): number;

export declare const runtimeCreate: typeof runtime_create;
export declare const runtimeClose: typeof runtime_close;
export declare const scopeEnter: typeof scope_enter;
export declare const scopeClose: typeof scope_close;
export declare const taskSpawn: typeof task_spawn;
export declare const taskJoin: typeof task_join;
export declare const taskCancel: typeof task_cancel;
export declare const fetchRequest: typeof fetch_request;
export declare const websocketOpen: typeof websocket_open;
export declare const websocketSend: typeof websocket_send;
export declare const websocketRecv: typeof websocket_recv;
export declare const websocketClose: typeof websocket_close;
export declare const websocketCancel: typeof websocket_cancel;
export declare const webtransportOpen: typeof webtransport_open;
export declare const webtransportSend: typeof webtransport_send;
export declare const webtransportRecv: typeof webtransport_recv;
export declare const webtransportClose: typeof webtransport_close;
export declare const webtransportCancel: typeof webtransport_cancel;
export declare const abiVersion: typeof abi_version;
export declare const abiFingerprint: typeof abi_fingerprint;
export declare const abiMetadata: AbiMetadata;

export declare const rawBindings: Readonly<{
  init: typeof init;
  runtime_create(consumerVersionJson?: string): string;
  runtime_close(handleJson: string, consumerVersionJson?: string): string;
  scope_enter(requestJson: string, consumerVersionJson?: string): string;
  scope_close(handleJson: string, consumerVersionJson?: string): string;
  task_spawn(requestJson: string, consumerVersionJson?: string): string;
  task_join(
    handleJson: string,
    outcomeJson: string,
    consumerVersionJson?: string,
  ): string;
  task_cancel(requestJson: string, consumerVersionJson?: string): string;
  fetch_request(requestJson: string, consumerVersionJson?: string): string;
  websocket_open(requestJson: string, consumerVersionJson?: string): string;
  websocket_send(requestJson: string, consumerVersionJson?: string): string;
  websocket_recv(requestJson: string, consumerVersionJson?: string): string;
  websocket_close(requestJson: string, consumerVersionJson?: string): string;
  websocket_cancel(requestJson: string, consumerVersionJson?: string): string;
  abi_version(): string;
  abi_fingerprint(): number;
}>;
