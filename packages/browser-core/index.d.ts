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
  readonly abi_signature_fingerprint_v1: string;
  readonly profile: string;
}

export interface Budget {
  pollQuota: number;
  deadlineMs: number;
  priority: number;
  cleanupQuota: number;
}

export type CancellationPhase = "requested" | "cancelling" | "finalizing" | "completed";

export type ErrorCode =
  | "capability_denied"
  | "invalid_handle"
  | "decode_failure"
  | "compatibility_rejected"
  | "internal_failure";

export type Recoverability = "transient" | "permanent" | "unknown";

export type HandleKind = "runtime" | "region" | "task" | "cancel_token" | "fetch_request";

export interface HandleRef {
  kind: HandleKind;
  slot: number;
  generation: number;
  owner_token?: bigint | string | number;
}

export type RuntimeHandleRef = HandleRef & { kind: "runtime" };
export type RegionHandleRef = HandleRef & { kind: "region" };
export type TaskHandleRef = HandleRef & { kind: "task" };
export type CancellationTokenHandleRef = HandleRef & { kind: "cancel_token" };
export type FetchHandleRef = HandleRef & { kind: "fetch_request" };

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
  timestamp_nanos: number | bigint;
  message: string | null;
  truncated: boolean;
}

export type HandleLike =
  | RuntimeHandleLike
  | RegionHandleLike
  | TaskHandleLike
  | CancellationTokenLike
  | FetchHandleLike;

export type RuntimeHandleLike = RuntimeHandle | RuntimeHandleRef;
export type RegionHandleLike = RegionHandle | RegionHandleRef;
export type TaskHandleLike = TaskHandle | TaskHandleRef;
export type CancellationTokenLike = CancellationToken | CancellationTokenHandleRef;
export type FetchHandleLike = FetchHandle | FetchHandleRef;

export type WasmValue = undefined | boolean | number | bigint | string | Uint8Array | HandleLike;

export type Outcome<T = WasmValue, E = AbiFailure> =
  | { outcome: "ok"; value: T }
  | { outcome: "err"; failure: E }
  | { outcome: "cancelled"; cancellation: AbiCancellation }
  | { outcome: "panicked"; message: string };

export interface ScopeEnterRequest {
  parent: RuntimeHandleLike | RegionHandleLike;
  label?: string;
}

export interface TaskSpawnRequest {
  scope: RegionHandleLike;
  label?: string;
  cancel_kind?: string;
}

export interface TaskCancelRequest {
  task: TaskHandleLike;
  kind: string;
  message?: string;
}

export type FetchMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export interface FetchAuthority {
  allowedOrigins?: string[];
  allowedMethods?: FetchMethod[];
  allowCredentials?: boolean;
  maxHeaderCount?: number;
}

export interface RuntimeCreateOptions {
  fetchAuthority?: FetchAuthority;
}

export interface FetchRequest {
  scope: RegionHandleLike;
  url: string;
  method: FetchMethod;
  credentials?: boolean;
  body?: Uint8Array | ArrayBuffer | ArrayBufferView | number[];
}

export interface WebSocketOpenRequest {
  scope: RegionHandleLike;
  url: string;
  protocols?: string[];
}

export interface WebSocketSendRequest {
  socket: TaskHandleLike;
  value: WasmValue;
}

export interface WebSocketRecvRequest {
  socket: TaskHandleLike;
}

export interface WebSocketCloseRequest {
  socket: TaskHandleLike;
  reason?: string;
}

export interface WebSocketCancelRequest {
  socket: TaskHandleLike;
  kind: string;
  message?: string;
}

export interface WebTransportOpenRequest {
  scope: RegionHandleLike;
  url: string;
  options?: Record<string, unknown>;
}

export interface WebTransportSendRequest {
  session: TaskHandleLike;
  value: string | Uint8Array | ArrayBuffer | ArrayBufferView | number[];
}

export interface WebTransportRecvRequest {
  session: TaskHandleLike;
}

export interface WebTransportCloseRequest {
  session: TaskHandleLike;
  reason?: string;
}

export interface WebTransportCancelRequest {
  session: TaskHandleLike;
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
  constructor(rawHandle: RuntimeHandleRef);
  close(consumerVersion?: AbiVersion | null): Outcome<void>;
  enterScope(label?: string, consumerVersion?: AbiVersion | null): Outcome<RegionHandle>;
}

export declare class RegionHandle extends BaseHandle {
  constructor(rawHandle: RegionHandleRef);
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
  constructor(rawHandle: TaskHandleRef);
  join(outcome: Outcome, consumerVersion?: AbiVersion | null): Outcome<WasmValue>;
  cancel(kind: string, message?: string, consumerVersion?: AbiVersion | null): Outcome<void>;
}

export declare class CancellationToken extends BaseHandle {
  constructor(rawHandle: CancellationTokenHandleRef);
}

export declare class FetchHandle extends BaseHandle {
  constructor(rawHandle: FetchHandleRef);
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
  options?: RuntimeCreateOptions,
  consumerVersion?: AbiVersion | null,
): Outcome<RuntimeHandle>;
export declare function runtime_close(
  runtimeHandle: RuntimeHandleLike,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function scope_enter(
  request: ScopeEnterRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<RegionHandle>;
export declare function scope_close(
  regionHandle: RegionHandleLike,
  consumerVersion?: AbiVersion | null,
): Outcome<void>;
export declare function task_spawn(
  request: TaskSpawnRequest,
  consumerVersion?: AbiVersion | null,
): Outcome<TaskHandle>;
export declare function task_join(
  taskHandle: TaskHandleLike,
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
export declare function abi_fingerprint(): string;

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
  runtime_create(requestJson?: string): string;
  runtime_close(handleJson: string, consumerVersionJson?: string): string;
  scope_enter(requestJson: string, consumerVersionJson?: string): string;
  scope_close(handleJson: string, consumerVersionJson?: string): string;
  task_spawn(requestJson: string, consumerVersionJson?: string): string;
  task_join(handleJson: string, outcomeJson: string, consumerVersionJson?: string): string;
  task_cancel(requestJson: string, consumerVersionJson?: string): string;
  fetch_request(requestJson: string, consumerVersionJson?: string): string;
  websocket_open(requestJson: string, consumerVersionJson?: string): string;
  websocket_send(requestJson: string, consumerVersionJson?: string): string;
  websocket_recv(requestJson: string, consumerVersionJson?: string): string;
  websocket_close(requestJson: string, consumerVersionJson?: string): string;
  websocket_cancel(requestJson: string, consumerVersionJson?: string): string;
  abi_version(): string;
  abi_fingerprint(): bigint;
}>;

/** Limits on adapter-owned resources, not on browser/network buffering. */
export declare const WEBTRANSPORT_STREAM_LIMITS: Readonly<{
  maxStreamsPerSession: 64;
  maxWriteBytes: 1048576;
}>;

export type WebTransportStreamRead =
  | { done: true }
  | { done: false; value: Uint8Array };

/**
 * A reliable, ordered byte stream owned by an existing WebTransport session.
 * Write boundaries are not message boundaries; applications must frame messages.
 * One read and one write may run concurrently. Overlapping reads/writes in the
 * same direction fail transiently without admitting another host operation.
 * Cancellation cannot roll back bytes already transmitted. The old synchronous
 * session/scope close APIs initiate host cleanup; await this stream's closed
 * promise (and any pending open) to observe reliable-stream cleanup settlement.
 */
export interface WebTransportByteStream {
  readonly direction: "bidirectional";
  /** Resolves after both halves end, or all cancellation cleanup settles. */
  readonly closed: Promise<Outcome<void>>;
  read(): Promise<Outcome<WebTransportStreamRead>>;
  /** Copies at most maxWriteBytes and awaits host write/backpressure completion. */
  write(bytes: ArrayBuffer | ArrayBufferView): Promise<Outcome<void>>;
  /** Sends FIN after an admitted write; leaves the receive half available. */
  finish(): Promise<Outcome<void>>;
  /** Idempotently cancels both halves, awaiting in-flight host I/O settlement. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface WebTransportStreamOpenRequest {
  session: TaskHandleLike;
}

/** Explicit name for the existing bidirectional byte-stream contract. */
export type WebTransportBidirectionalStream = WebTransportByteStream;

/** An incoming unidirectional stream. No write authority is exposed. */
export interface WebTransportReadableStream {
  readonly direction: "unidirectional";
  readonly closed: Promise<Outcome<void>>;
  read(): Promise<Outcome<WebTransportStreamRead>>;
  /** Stops reception and waits for host cleanup before releasing capacity. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

/** An outgoing unidirectional stream. No read authority is exposed. */
export interface WebTransportWritableStream {
  readonly direction: "unidirectional";
  readonly closed: Promise<Outcome<void>>;
  write(bytes: ArrayBuffer | ArrayBufferView): Promise<Outcome<void>>;
  /** Sends FIN after admitted bytes and completes this one-way stream. */
  finish(): Promise<Outcome<void>>;
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface WebTransportStreamAcceptRequest {
  session: TaskHandleLike;
}

/**
 * Open an outgoing bidirectional stream. Pending creations count against the
 * session's 64-stream cap. Closing the owner before admission disposes any late
 * host stream before this promise resolves. It cannot force a non-settling host
 * creation/cleanup promise to settle and is not a deadline guarantee.
 */
export declare function webtransport_open_stream(
  request: WebTransportStreamOpenRequest,
): Promise<Outcome<WebTransportByteStream>>;
export declare const webtransportOpenStream: typeof webtransport_open_stream;

/**
 * Open a send-only stream under the same session capacity and cleanup rules as
 * webtransport_open_stream. FIN completes this stream without a receive half.
 */
export declare function webtransport_open_unidirectional_stream(
  request: WebTransportStreamOpenRequest,
): Promise<Outcome<WebTransportWritableStream>>;
export declare const webtransportOpenUnidirectionalStream:
  typeof webtransport_open_unidirectional_stream;

/**
 * Accept one server-initiated bidirectional stream, or null when the incoming
 * collection ends. Only one accept per direction may wait at a time. Pending
 * accepts share the session's 64-stream capacity with pending opens and live
 * streams. The adapter does not prefetch incoming streams.
 *
 * Session/scope close cancels a waiting accept and disposes any late stream.
 * Await the accept and admitted streams' closed promises for cleanup; the
 * synchronous owner-close APIs do not wait for host I/O to settle.
 */
export declare function webtransport_accept_bidirectional_stream(
  request: WebTransportStreamAcceptRequest,
): Promise<Outcome<WebTransportByteStream | null>>;
export declare const webtransportAcceptBidirectionalStream:
  typeof webtransport_accept_bidirectional_stream;

/** Accept one server-initiated receive-only stream, or null at collection EOF. */
export declare function webtransport_accept_unidirectional_stream(
  request: WebTransportStreamAcceptRequest,
): Promise<Outcome<WebTransportReadableStream | null>>;
export declare const webtransportAcceptUnidirectionalStream:
  typeof webtransport_accept_unidirectional_stream;

/**
 * Capture an awaitable reliable-stream shutdown barrier for a known session.
 * Call before closing its session/scope/runtime, because those operations
 * invalidate the handle. Observation does not close or reserve the session.
 * All observers share one promise, which remains pending while the owner is
 * live, even when it currently has no streams.
 *
 * After owner closure this resolves with the first owner outcome only when
 * every admitted reliable stream, pending open/accept, late-delivered endpoint,
 * and acquired incoming collection reader has settled its cleanup and released
 * its locks. Cleanup rejections are observed without replacing the owner cause.
 * This is not an aggregate child-result report or a deadline guarantee, and it
 * does not cover datagrams, fetches, WebSockets, unaccepted browser-buffered
 * streams, the underlying connection, or arbitrary user work. It cannot force
 * a non-settling host creation/write/cancellation promise to complete.
 */
export declare function webtransport_streams_closed(
  request: WebTransportStreamAcceptRequest,
): Promise<Outcome<void>>;
export declare const webtransportStreamsClosed: typeof webtransport_streams_closed;
