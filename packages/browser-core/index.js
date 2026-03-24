import initWasm, {
  abi_fingerprint as rawAbiFingerprint,
  abi_version as rawAbiVersion,
  fetch_request as rawFetchRequest,
  runtime_close as rawRuntimeClose,
  runtime_create as rawRuntimeCreate,
  scope_close as rawScopeClose,
  scope_enter as rawScopeEnter,
  task_cancel as rawTaskCancel,
  task_join as rawTaskJoin,
  task_spawn as rawTaskSpawn,
  websocket_cancel as rawWebSocketCancel,
  websocket_close as rawWebSocketClose,
  websocket_open as rawWebSocketOpen,
  websocket_recv as rawWebSocketRecv,
  websocket_send as rawWebSocketSend,
} from "./asupersync.js";

const HANDLE_KINDS = new Set([
  "runtime",
  "region",
  "task",
  "cancel_token",
  "fetch_request",
]);

const REGION_PARENTS = new Map();
const INFLIGHT_WEBTRANSPORTS = new Map();
const WEBTRANSPORT_TASK_LABEL = "browser-webtransport";
const WEBTRANSPORT_CANCEL_KIND = "abort_signal";
const WEBTRANSPORT_CLOSE_KIND = "webtransport_close";

const CANCELLATION_PHASE_ORDER = Object.freeze([
  "requested",
  "cancelling",
  "finalizing",
  "completed",
]);

const ERROR_CODES = Object.freeze([
  "capability_denied",
  "invalid_handle",
  "decode_failure",
  "compatibility_rejected",
  "internal_failure",
]);

const RECOVERABILITY_LEVELS = Object.freeze([
  "transient",
  "permanent",
  "unknown",
]);

export const abiMetadata = Object.freeze({
  abi_version: Object.freeze({
    major: 1,
    minor: 0,
  }),
  abi_signature_fingerprint_v1: 4558451663113424898,
  profile: "prod",
});

const BUDGET_BOUNDS = Object.freeze({
  pollQuota: Object.freeze({ min: 1, max: 1_000_000 }),
  deadlineMs: Object.freeze({ min: 0, max: 86_400_000 }),
  priority: Object.freeze({ min: 0, max: 255 }),
  cleanupQuota: Object.freeze({ min: 0, max: 1_000_000 }),
});

function parseJson(raw, label) {
  if (typeof raw !== "string") {
    throw new TypeError(`${label} must be a JSON string`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${label} returned invalid JSON: ${message}`);
  }
}

function vjson(consumerVersion) {
  return consumerVersion === null || consumerVersion === undefined
    ? undefined
    : JSON.stringify(consumerVersion);
}

function errorMessage(error) {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return String(error);
}

function normalizeFailure(error, label) {
  const message = errorMessage(error);
  try {
    const failure = JSON.parse(message);
    if (
      failure &&
      typeof failure === "object" &&
      typeof failure.code === "string" &&
      typeof failure.recoverability === "string" &&
      typeof failure.message === "string"
    ) {
      return failure;
    }
  } catch {
    // Fall through to the generic failure shape below.
  }
  return {
    code: "internal_failure",
    recoverability: "unknown",
    message: `${label} failed: ${message}`,
  };
}

function normalizeByteArray(bytes, label) {
  if (bytes instanceof Uint8Array) {
    return Array.from(bytes);
  }
  if (bytes instanceof ArrayBuffer) {
    return Array.from(new Uint8Array(bytes));
  }
  if (ArrayBuffer.isView(bytes)) {
    return Array.from(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  }
  if (
    Array.isArray(bytes) &&
    bytes.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    return [...bytes];
  }
  throw new TypeError(`${label} must be Uint8Array, ArrayBuffer, ArrayBufferView, or byte[]`);
}

function normalizeBudgetNumber(name, value) {
  if (!Number.isInteger(value)) {
    throw new TypeError(`Budget.${name} must be an integer`);
  }
  const bounds = BUDGET_BOUNDS[name];
  if (value < bounds.min || value > bounds.max) {
    throw new RangeError(
      `Budget.${name} must be between ${bounds.min} and ${bounds.max}; received ${value}`,
    );
  }
  return value;
}

export function createBudget(input = {}) {
  return {
    pollQuota: normalizeBudgetNumber("pollQuota", input.pollQuota ?? 1_024),
    deadlineMs: normalizeBudgetNumber("deadlineMs", input.deadlineMs ?? 30_000),
    priority: normalizeBudgetNumber("priority", input.priority ?? 100),
    cleanupQuota: normalizeBudgetNumber("cleanupQuota", input.cleanupQuota ?? 256),
  };
}

function isRawHandle(value) {
  return (
    Boolean(value) &&
    typeof value === "object" &&
    typeof value.kind === "string" &&
    HANDLE_KINDS.has(value.kind) &&
    Number.isInteger(value.slot) &&
    Number.isInteger(value.generation)
  );
}

function normHandle(handle, label, expectedKind) {
  const raw = handle instanceof BaseHandle ? handle.toJSON() : handle;
  if (!isRawHandle(raw)) {
    throw new TypeError(`${label} must be a browser-core handle`);
  }
  if (expectedKind && raw.kind !== expectedKind) {
    throw new TypeError(`${label} must be a ${expectedKind} handle; received ${raw.kind}`);
  }
  return {
    kind: raw.kind,
    slot: raw.slot,
    generation: raw.generation,
  };
}

function wrapHandle(rawHandle) {
  const handle = normHandle(rawHandle, "value");
  switch (handle.kind) {
    case "runtime":
      return new RuntimeHandle(handle);
    case "region":
      return new RegionHandle(handle);
    case "task":
      return new TaskHandle(handle);
    case "cancel_token":
      return new CancellationToken(handle);
    case "fetch_request":
      return new FetchHandle(handle);
    default:
      throw new TypeError(`Unsupported handle kind ${handle.kind}`);
  }
}

function parseHandleResult(rawHandle, label, expectedKind) {
  return wrapHandle(normHandle(parseJson(rawHandle, label), label, expectedKind));
}

function reviveValue(rawValue) {
  if (!rawValue || typeof rawValue !== "object" || typeof rawValue.kind !== "string") {
    throw new TypeError("Outcome value must use the WASM ABI tagged-value shape");
  }
  switch (rawValue.kind) {
    case "unit":
      return undefined;
    case "bool":
    case "i64":
    case "u64":
    case "string":
      return rawValue.value;
    case "bytes":
      return Uint8Array.from(rawValue.value ?? []);
    case "handle":
      return wrapHandle(rawValue.value);
    default:
      throw new TypeError(`Unsupported ABI value kind ${rawValue.kind}`);
  }
}

function encodeValue(value, label) {
  if (value === undefined) {
    return { kind: "unit" };
  }
  if (typeof value === "boolean") {
    return { kind: "bool", value };
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new TypeError(`${label} must be a finite integer`);
    }
    return value >= 0 ? { kind: "u64", value } : { kind: "i64", value };
  }
  if (typeof value === "string") {
    return { kind: "string", value };
  }
  if (
    value instanceof Uint8Array ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value) ||
    Array.isArray(value)
  ) {
    return { kind: "bytes", value: normalizeByteArray(value, label) };
  }
  if (value instanceof BaseHandle || isRawHandle(value)) {
    return { kind: "handle", value: normHandle(value, label) };
  }
  if (value && typeof value === "object" && typeof value.kind === "string") {
    return value;
  }
  throw new TypeError(`${label} is not encodable across the WASM ABI boundary`);
}

function reviveOutcomeEnvelope(rawOutcome, label) {
  const outcome = parseJson(rawOutcome, label);
  if (!outcome || typeof outcome !== "object" || typeof outcome.outcome !== "string") {
    throw new TypeError(`${label} must decode to a tagged outcome envelope`);
  }
  if (outcome.outcome === "ok") {
    return {
      outcome: "ok",
      value: reviveValue(outcome.value),
    };
  }
  return outcome;
}

function encodeOutcomeEnvelope(outcome, label) {
  if (!outcome || typeof outcome !== "object" || typeof outcome.outcome !== "string") {
    throw new TypeError(`${label} must be a tagged outcome envelope`);
  }
  if (outcome.outcome === "ok") {
    return {
      outcome: "ok",
      value: encodeValue(outcome.value, `${label}.value`),
    };
  }
  return outcome;
}

function invokeHandleOperation(label, expectedKind, fn) {
  try {
    return Outcome.ok(parseHandleResult(fn(), `${label}.response`, expectedKind));
  } catch (error) {
    return {
      outcome: "err",
      failure: normalizeFailure(error, label),
    };
  }
}

function invokeOutcomeOperation(label, fn) {
  try {
    return reviveOutcomeEnvelope(fn(), `${label}.response`);
  } catch (error) {
    return {
      outcome: "err",
      failure: normalizeFailure(error, label),
    };
  }
}

export const Outcome = Object.freeze({
  ok(value) {
    return { outcome: "ok", value };
  },
  err(code, recoverability, message) {
    return {
      outcome: "err",
      failure: { code, recoverability, message },
    };
  },
  cancelled(cancellation) {
    return { outcome: "cancelled", cancellation };
  },
  panicked(message) {
    return { outcome: "panicked", message };
  },
});

function failOut(code, recoverability, message) {
  return Outcome.err(code, recoverability, message);
}

function cancelOut(kind, phase, message, originTask = null) {
  return Outcome.cancelled({
    kind,
    phase,
    origin_region: "browser",
    origin_task: originTask,
    timestamp_nanos: 0,
    message,
    truncated: false,
  });
}

function keyOf(handle, label = "handle", expectedKind = undefined) {
  const normalized = normHandle(handle, label, expectedKind);
  return `${normalized.kind}:${normalized.slot}:${normalized.generation}`;
}

function recordRegionParent(parentHandle, regionHandle) {
  REGION_PARENTS.set(
    keyOf(regionHandle, "regionHandle", "region"),
    keyOf(parentHandle, "parentHandle"),
  );
}

function collectOwnedRegionKeys(rootKey) {
  const owned = new Set([rootKey]);
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

function deleteOwnedRegionKeys(rootKey) {
  const owned = collectOwnedRegionKeys(rootKey);
  for (const regionKey of owned) {
    if (regionKey !== rootKey) {
      REGION_PARENTS.delete(regionKey);
    }
  }
  return owned;
}

function closeOwnedWebTransports(ownerKeys, reason) {
  for (const [sessionKey, state] of INFLIGHT_WEBTRANSPORTS) {
    if (!ownerKeys.has(state.scopeKey)) {
      continue;
    }
    state.settled = true;
    closeHostWebTransportState(state, reason);
    INFLIGHT_WEBTRANSPORTS.delete(sessionKey);
  }
}

function cleanupScopeOwnedHostState(regionHandle) {
  const ownerKeys = deleteOwnedRegionKeys(keyOf(regionHandle, "regionHandle", "region"));
  closeOwnedWebTransports(ownerKeys, "scope_close");
}

function cleanupRuntimeOwnedHostState(runtimeHandle) {
  const ownerKeys = deleteOwnedRegionKeys(keyOf(runtimeHandle, "runtimeHandle", "runtime"));
  closeOwnedWebTransports(ownerKeys, "runtime_close");
}

function normalizeWebTransportUrl(url) {
  if (typeof url !== "string") {
    throw new TypeError("webtransport URL must be a string");
  }
  const trimmed = url.trim();
  if (!trimmed) {
    throw new TypeError("webtransport URL must not be empty");
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (error) {
    throw new TypeError(
      `webtransport URL must be an absolute https:// URL: ${errorMessage(error)}`,
    );
  }
  if (parsed.protocol !== "https:") {
    throw new TypeError(`webtransport URL must start with https://: ${parsed.href}`);
  }
  return parsed.href;
}

function resolveWebTransportConstructor() {
  const globalObject =
    typeof globalThis === "object" && globalThis !== null ? globalThis : undefined;
  if (!globalObject) {
    return failOut(
      "compatibility_rejected",
      "permanent",
      "WebTransport requires a browser-like globalThis. Use fetch or WebSocket in server, SSR, and edge contexts.",
    );
  }
  if (typeof globalObject.WebTransport !== "function") {
    return failOut(
      "compatibility_rejected",
      "permanent",
      "WebTransport is unavailable in this runtime. Use fetch or WebSocket unless the browser exposes globalThis.WebTransport over HTTPS.",
    );
  }
  return globalObject.WebTransport;
}

function encodeWebTransportDatagram(value, label) {
  if (typeof value === "string") {
    if (typeof TextEncoder !== "function") {
      throw new TypeError("webtransport string datagrams require TextEncoder support");
    }
    return new TextEncoder().encode(value);
  }
  return Uint8Array.from(normalizeByteArray(value, label));
}

function queueWebTransportOutcome(state, outcome, { terminal = false } = {}) {
  if (terminal) {
    if (state.terminalQueued) {
      return;
    }
    state.terminalQueued = true;
  }
  state.inbox.push(outcome);
}

function isTerminalOutcome(outcome) {
  return Boolean(outcome) && typeof outcome === "object" && outcome.outcome !== "ok";
}

function settleHostWebTransportState(state, outcome, closeReason = undefined) {
  if (state.settled) {
    return;
  }
  state.settled = true;
  INFLIGHT_WEBTRANSPORTS.delete(state.sessionKey);
  closeHostWebTransportState(state, closeReason);
  void task_join(state.taskHandle, outcome, state.consumerVersion);
}

function closeHostWebTransportState(state, reason = undefined) {
  if (state.closed) {
    return;
  }
  state.closed = true;
  if (state.reader && typeof state.reader.cancel === "function") {
    Promise.resolve(state.reader.cancel(reason ?? WEBTRANSPORT_CLOSE_KIND)).catch(() => {});
  }
  if (state.reader && typeof state.reader.releaseLock === "function") {
    try {
      state.reader.releaseLock();
    } catch {}
  }
  if (state.writer && typeof state.writer.close === "function") {
    Promise.resolve(state.writer.close()).catch(() => {});
  }
  if (state.writer && typeof state.writer.releaseLock === "function") {
    try {
      state.writer.releaseLock();
    } catch {}
  }
  if (state.transport && typeof state.transport.close === "function") {
    if (reason) {
      try {
        state.transport.close({ reason });
      } catch {
        try {
          state.transport.close();
        } catch {}
      }
      return;
    }
    try {
      state.transport.close();
    } catch {}
  }
}

function flushPendingWebTransportWrites(state, sessionOrigin) {
  if (state.flushPromise || state.closed || !state.ready || !state.writer) {
    return;
  }
  state.flushPromise = Promise.resolve()
    .then(async () => {
      while (!state.closed && state.pendingWrites.length > 0) {
        const datagram = state.pendingWrites.shift();
        try {
          await state.writer.write(datagram);
        } catch (error) {
          settleHostWebTransportState(
            state,
            failOut(
              "internal_failure",
              "transient",
              `webtransport datagram write failed: ${errorMessage(error)}`,
            ),
            "write_failure",
          );
          break;
        }
      }
    })
    .catch((error) => {
      if (!state.closed) {
        settleHostWebTransportState(
          state,
          failOut(
            "internal_failure",
            "transient",
            `webtransport write queue failed: ${errorMessage(error)}`,
          ),
          "write_queue_failure",
        );
      }
    })
    .finally(() => {
      state.flushPromise = null;
      if (!state.closed && state.ready && state.pendingWrites.length > 0) {
        flushPendingWebTransportWrites(state, sessionOrigin);
      }
    });
}

async function pumpWebTransportReads(state, sessionOrigin) {
  while (!state.closed && state.reader) {
    try {
      const { value, done } = await state.reader.read();
      if (done) {
        settleHostWebTransportState(
          state,
          cancelOut(
            WEBTRANSPORT_CLOSE_KIND,
            "completed",
            "webtransport datagram reader closed",
            sessionOrigin,
          ),
          "read_closed",
        );
        return;
      }
      if (value !== undefined) {
        queueWebTransportOutcome(
          state,
          Outcome.ok(Uint8Array.from(normalizeByteArray(value, "webtransport datagram"))),
        );
      }
    } catch (error) {
      if (!state.closed) {
        settleHostWebTransportState(
          state,
          failOut(
            "internal_failure",
            "transient",
            `webtransport datagram read failed: ${errorMessage(error)}`,
          ),
          "read_failure",
        );
      }
      return;
    }
  }
}

function monitorWebTransportClosure(state, sessionOrigin) {
  Promise.resolve(state.transport.closed).then(
    (closeInfo) => {
      if (state.closed) {
        return;
      }
      const reason =
        closeInfo && typeof closeInfo.reason === "string" && closeInfo.reason
          ? closeInfo.reason
          : "webtransport session closed";
      settleHostWebTransportState(
        state,
        cancelOut(WEBTRANSPORT_CLOSE_KIND, "completed", reason, sessionOrigin),
        reason,
      );
    },
    (error) => {
      if (state.closed) {
        return;
      }
      settleHostWebTransportState(
        state,
        failOut(
          "internal_failure",
          "transient",
          `webtransport session closed with error: ${errorMessage(error)}`,
        ),
        "session_closed_error",
      );
    },
  );
}

async function initializeWebTransportState(state, sessionOrigin) {
  try {
    await state.transport.ready;
    if (state.closed) {
      return;
    }
    const datagrams = state.transport.datagrams;
    const readable = datagrams?.readable;
    const writable = datagrams?.writable;
    if (
      !readable ||
      typeof readable.getReader !== "function" ||
      !writable ||
      typeof writable.getWriter !== "function"
    ) {
      throw new Error(
        "WebTransport datagrams are unavailable. This lane currently exposes explicit datagram transport, not bidirectional streams.",
      );
    }
    state.reader = readable.getReader();
    state.writer = writable.getWriter();
    state.ready = true;
    flushPendingWebTransportWrites(state, sessionOrigin);
    void pumpWebTransportReads(state, sessionOrigin);
    monitorWebTransportClosure(state, sessionOrigin);
  } catch (error) {
    if (state.closed) {
      return;
    }
    settleHostWebTransportState(
      state,
      failOut(
        "compatibility_rejected",
        "permanent",
        `webtransport handshake failed: ${errorMessage(error)}. Ensure the endpoint serves WebTransport over HTTPS/HTTP3 and that this browser exposes the WebTransport API.`,
      ),
      "handshake_failure",
    );
  }
}

function takeWebTransportState(sessionHandle) {
  const sessionKey = keyOf(sessionHandle, "sessionHandle", "task");
  const state = INFLIGHT_WEBTRANSPORTS.get(sessionKey);
  if (!state) {
    return { sessionKey, state: null };
  }
  INFLIGHT_WEBTRANSPORTS.delete(sessionKey);
  return { sessionKey, state };
}

export class BaseHandle {
  constructor(rawHandle, expectedKind) {
    const handle = normHandle(rawHandle, "handle", expectedKind);
    this.kind = handle.kind;
    this.slot = handle.slot;
    this.generation = handle.generation;
    Object.freeze(this);
  }

  toJSON() {
    return {
      kind: this.kind,
      slot: this.slot,
      generation: this.generation,
    };
  }
}

export class RuntimeHandle extends BaseHandle {
  constructor(rawHandle) {
    super(rawHandle, "runtime");
  }

  close(consumerVersion = null) {
    return runtime_close(this, consumerVersion);
  }

  enterScope(label = undefined, consumerVersion = null) {
    return scope_enter({ parent: this, label }, consumerVersion);
  }
}

export class RegionHandle extends BaseHandle {
  constructor(rawHandle) {
    super(rawHandle, "region");
  }

  close(consumerVersion = null) {
    return scope_close(this, consumerVersion);
  }

  enterScope(label = undefined, consumerVersion = null) {
    return scope_enter({ parent: this, label }, consumerVersion);
  }

  spawnTask(options = {}, consumerVersion = null) {
    return task_spawn({ scope: this, ...options }, consumerVersion);
  }

  fetchRequest(options, consumerVersion = null) {
    return fetch_request({ scope: this, ...options }, consumerVersion);
  }

  openWebSocket(url, protocols = undefined, consumerVersion = null) {
    return websocket_open({ scope: this, url, protocols }, consumerVersion);
  }

  openWebTransport(url, options = undefined, consumerVersion = null) {
    return webtransport_open({ scope: this, url, options }, consumerVersion);
  }
}

export class TaskHandle extends BaseHandle {
  constructor(rawHandle) {
    super(rawHandle, "task");
  }

  join(outcome, consumerVersion = null) {
    return task_join(this, outcome, consumerVersion);
  }

  cancel(kind, message = undefined, consumerVersion = null) {
    return task_cancel({ task: this, kind, message }, consumerVersion);
  }
}

export class CancellationToken extends BaseHandle {
  constructor(rawHandle) {
    super(rawHandle, "cancel_token");
  }
}

export class FetchHandle extends BaseHandle {
  constructor(rawHandle) {
    super(rawHandle, "fetch_request");
  }
}

async function init(input) {
  return initWasm(input);
}

export default init;
export { init };

export function runtime_create(consumerVersion = null) {
  return invokeHandleOperation("runtime_create", "runtime", () =>
    rawRuntimeCreate(vjson(consumerVersion)),
  );
}

export function runtime_close(runtimeHandle, consumerVersion = null) {
  const outcome = invokeOutcomeOperation("runtime_close", () =>
    rawRuntimeClose(
      JSON.stringify(normHandle(runtimeHandle, "runtimeHandle", "runtime")),
      vjson(consumerVersion),
    ),
  );
  if (outcome.outcome === "ok") {
    cleanupRuntimeOwnedHostState(runtimeHandle);
  }
  return outcome;
}

export function scope_enter(request, consumerVersion = null) {
  const outcome = invokeHandleOperation("scope_enter", "region", () =>
    rawScopeEnter(
      JSON.stringify({
        parent: normHandle(request.parent, "request.parent"),
        label: request.label ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
  if (outcome.outcome === "ok") {
    recordRegionParent(request.parent, outcome.value);
  }
  return outcome;
}

export function scope_close(regionHandle, consumerVersion = null) {
  const outcome = invokeOutcomeOperation("scope_close", () =>
    rawScopeClose(
      JSON.stringify(normHandle(regionHandle, "regionHandle", "region")),
      vjson(consumerVersion),
    ),
  );
  if (outcome.outcome === "ok") {
    cleanupScopeOwnedHostState(regionHandle);
  }
  return outcome;
}

export function task_spawn(request, consumerVersion = null) {
  return invokeHandleOperation("task_spawn", "task", () =>
    rawTaskSpawn(
      JSON.stringify({
        scope: normHandle(request.scope, "request.scope", "region"),
        label: request.label ?? undefined,
        cancel_kind: request.cancel_kind ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
}

export function task_join(taskHandle, outcome, consumerVersion = null) {
  return invokeOutcomeOperation("task_join", () =>
    rawTaskJoin(
      JSON.stringify(normHandle(taskHandle, "taskHandle", "task")),
      JSON.stringify(encodeOutcomeEnvelope(outcome, "outcome")),
      vjson(consumerVersion),
    ),
  );
}

export function task_cancel(request, consumerVersion = null) {
  return invokeOutcomeOperation("task_cancel", () =>
    rawTaskCancel(
      JSON.stringify({
        task: normHandle(request.task, "request.task", "task"),
        kind: request.kind,
        message: request.message ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
}

export function fetch_request(request, consumerVersion = null) {
  return invokeOutcomeOperation("fetch_request", () =>
    rawFetchRequest(
      JSON.stringify({
        scope: normHandle(request.scope, "request.scope", "region"),
        url: request.url,
        method: request.method,
        body:
          request.body === null || request.body === undefined
            ? undefined
            : normalizeByteArray(request.body, "request.body"),
      }),
      vjson(consumerVersion),
    ),
  );
}

export function websocket_open(request, consumerVersion = null) {
  return invokeOutcomeOperation("websocket_open", () =>
    rawWebSocketOpen(
      JSON.stringify({
        scope: normHandle(request.scope, "request.scope", "region"),
        url: request.url,
        protocols: request.protocols ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
}

export function websocket_send(request, consumerVersion = null) {
  return invokeOutcomeOperation("websocket_send", () =>
    rawWebSocketSend(
      JSON.stringify({
        socket: normHandle(request.socket, "request.socket", "task"),
        value: encodeValue(request.value, "request.value"),
      }),
      vjson(consumerVersion),
    ),
  );
}

export function websocket_recv(request, consumerVersion = null) {
  return invokeOutcomeOperation("websocket_recv", () =>
    rawWebSocketRecv(
      JSON.stringify({
        socket: normHandle(request.socket, "request.socket", "task"),
      }),
      vjson(consumerVersion),
    ),
  );
}

export function websocket_close(request, consumerVersion = null) {
  return invokeOutcomeOperation("websocket_close", () =>
    rawWebSocketClose(
      JSON.stringify({
        socket: normHandle(request.socket, "request.socket", "task"),
        reason: request.reason ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
}

export function websocket_cancel(request, consumerVersion = null) {
  return invokeOutcomeOperation("websocket_cancel", () =>
    rawWebSocketCancel(
      JSON.stringify({
        socket: normHandle(request.socket, "request.socket", "task"),
        kind: request.kind,
        message: request.message ?? undefined,
      }),
      vjson(consumerVersion),
    ),
  );
}

export function webtransport_open(request, consumerVersion = null) {
  let normalizedUrl;
  try {
    normalizedUrl = normalizeWebTransportUrl(request.url);
  } catch (error) {
    return failOut(
      "compatibility_rejected",
      "permanent",
      `webtransport_open rejected: ${errorMessage(error)}. Use fetch or WebSocket when a valid HTTPS WebTransport endpoint is unavailable.`,
    );
  }
  const WebTransportConstructor = resolveWebTransportConstructor();
  if (typeof WebTransportConstructor !== "function") {
    return WebTransportConstructor;
  }
  const spawned = task_spawn(
    {
      scope: request.scope,
      label: WEBTRANSPORT_TASK_LABEL,
      cancel_kind: WEBTRANSPORT_CANCEL_KIND,
    },
    consumerVersion,
  );
  if (spawned.outcome !== "ok") {
    return spawned;
  }
  const session = spawned.value;
  const sessionOrigin = keyOf(session, "session", "task");
  try {
    const transport = new WebTransportConstructor(normalizedUrl, request.options ?? undefined);
    const state = {
      consumerVersion,
      taskHandle: session,
      transport,
      sessionKey: sessionOrigin,
      scopeKey: keyOf(request.scope, "request.scope", "region"),
      inbox: [],
      pendingWrites: [],
      ready: false,
      closed: false,
      settled: false,
      terminalQueued: false,
      reader: null,
      writer: null,
      flushPromise: null,
    };
    INFLIGHT_WEBTRANSPORTS.set(sessionOrigin, state);
    void initializeWebTransportState(state, sessionOrigin);
    return Outcome.ok(session);
  } catch (error) {
    const failure = failOut(
      "compatibility_rejected",
      "permanent",
      `webtransport_open failed: ${errorMessage(error)}. Use fetch or WebSocket when this browser rejects WebTransport construction.`,
    );
    void task_join(session, failure, consumerVersion);
    return failure;
  }
}

export function webtransport_send(request, _consumerVersion = null) {
  let state;
  try {
    state = INFLIGHT_WEBTRANSPORTS.get(keyOf(request.session, "request.session", "task"));
  } catch (error) {
    return failOut(
      "invalid_handle",
      "permanent",
      `webtransport_send rejected: ${errorMessage(error)}`,
    );
  }
  if (!state) {
    return failOut(
      "invalid_handle",
      "permanent",
      "webtransport_send rejected: unknown WebTransport session handle",
    );
  }
  if (state.closed) {
    return failOut(
      "invalid_handle",
      "permanent",
      "webtransport_send rejected: WebTransport session is already closed",
    );
  }
  try {
    state.pendingWrites.push(
      encodeWebTransportDatagram(request.value, "request.value"),
    );
  } catch (error) {
    return failOut(
      "compatibility_rejected",
      "permanent",
      `webtransport_send rejected: ${errorMessage(error)}`,
    );
  }
  flushPendingWebTransportWrites(state, keyOf(request.session, "request.session", "task"));
  return Outcome.ok(undefined);
}

export function webtransport_recv(request, _consumerVersion = null) {
  let sessionKey;
  let state;
  try {
    sessionKey = keyOf(request.session, "request.session", "task");
    state = INFLIGHT_WEBTRANSPORTS.get(sessionKey);
  } catch (error) {
    return failOut(
      "invalid_handle",
      "permanent",
      `webtransport_recv rejected: ${errorMessage(error)}`,
    );
  }
  if (!state) {
    return failOut(
      "invalid_handle",
      "permanent",
      "webtransport_recv rejected: unknown WebTransport session handle",
    );
  }
  const result = state.inbox.shift() ?? Outcome.ok(undefined);
  if (isTerminalOutcome(result)) {
    INFLIGHT_WEBTRANSPORTS.delete(sessionKey);
  }
  return result;
}

export function webtransport_close(request, consumerVersion = null) {
  let taken;
  try {
    taken = takeWebTransportState(request.session);
  } catch (error) {
    return failOut(
      "invalid_handle",
      "permanent",
      `webtransport_close rejected: ${errorMessage(error)}`,
    );
  }
  if (!taken.state) {
    return failOut(
      "invalid_handle",
      "permanent",
      "webtransport_close rejected: unknown WebTransport session handle",
    );
  }
  taken.state.settled = true;
  closeHostWebTransportState(taken.state, request.reason);
  const outcome = cancelOut(
    WEBTRANSPORT_CLOSE_KIND,
    "completed",
    request.reason ?? "webtransport session closed by caller",
    taken.sessionKey,
  );
  return task_join(request.session, outcome, consumerVersion);
}

export function webtransport_cancel(request, consumerVersion = null) {
  const cancelled = task_cancel(
    {
      task: request.session,
      kind: request.kind,
      message: request.message ?? undefined,
    },
    consumerVersion,
  );
  if (cancelled.outcome !== "ok") {
    return cancelled;
  }
  let taken;
  try {
    taken = takeWebTransportState(request.session);
  } catch (error) {
    return failOut(
      "invalid_handle",
      "permanent",
      `webtransport_cancel rejected: ${errorMessage(error)}`,
    );
  }
  if (taken.state) {
    taken.state.settled = true;
    closeHostWebTransportState(taken.state, request.message);
  }
  return task_join(
    request.session,
    cancelOut(
      request.kind,
      "cancelling",
      request.message ?? null,
      taken.sessionKey,
    ),
    consumerVersion,
  );
}

export function abi_version() {
  return parseJson(rawAbiVersion(), "abi_version");
}

export function abi_fingerprint() {
  return rawAbiFingerprint();
}

export const runtimeCreate = runtime_create;
export const runtimeClose = runtime_close;
export const scopeEnter = scope_enter;
export const scopeClose = scope_close;
export const taskSpawn = task_spawn;
export const taskJoin = task_join;
export const taskCancel = task_cancel;
export const fetchRequest = fetch_request;
export const websocketOpen = websocket_open;
export const websocketSend = websocket_send;
export const websocketRecv = websocket_recv;
export const websocketClose = websocket_close;
export const websocketCancel = websocket_cancel;
export const webtransportOpen = webtransport_open;
export const webtransportSend = webtransport_send;
export const webtransportRecv = webtransport_recv;
export const webtransportClose = webtransport_close;
export const webtransportCancel = webtransport_cancel;
export const abiVersion = abi_version;
export const abiFingerprint = abi_fingerprint;

export const rawBindings = Object.freeze({
  init: initWasm,
  runtime_create: rawRuntimeCreate,
  runtime_close: rawRuntimeClose,
  scope_enter: rawScopeEnter,
  scope_close: rawScopeClose,
  task_spawn: rawTaskSpawn,
  task_join: rawTaskJoin,
  task_cancel: rawTaskCancel,
  fetch_request: rawFetchRequest,
  websocket_open: rawWebSocketOpen,
  websocket_send: rawWebSocketSend,
  websocket_recv: rawWebSocketRecv,
  websocket_close: rawWebSocketClose,
  websocket_cancel: rawWebSocketCancel,
  abi_version: rawAbiVersion,
  abi_fingerprint: rawAbiFingerprint,
});

export {
  BUDGET_BOUNDS,
  CANCELLATION_PHASE_ORDER,
  ERROR_CODES,
  RECOVERABILITY_LEVELS,
};
