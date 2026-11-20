/** Region-owned native WebSocket messages, without a second network connection. */
import type { Outcome } from "@asupersync/browser-core";

export const BROWSER_WEBSOCKET_LIMITS = Object.freeze({
  maxQueuedMessages: 64,
  maxQueuedBytes: 4_194_304,
  maxMessageBytes: 1_048_576,
  maxSendBufferedBytes: 1_048_576,
});

export type BrowserWebSocketMessage = string | Uint8Array;
export type BrowserWebSocketRead = { done: true } | { done: false; value: BrowserWebSocketMessage };
export interface BrowserWebSocketReady { readonly protocol: string; readonly extensions: string; }
export interface BrowserWebSocketOptions {
  /** Maximum queued messages, including empty ones. Default 64; at most 4,096. */
  maxQueuedMessages?: number;
  /** Maximum queued UTF-8/binary bytes. Default 4 MiB; at most 64 MiB. */
  maxQueuedBytes?: number;
  /** Maximum bytes in one received or sent message. Default 1 MiB; at most 16 MiB. */
  maxMessageBytes?: number;
  /** Admission cap for native bufferedAmount plus one send. Default 1 MiB. */
  maxSendBufferedBytes?: number;
  /** Borrowed unmodified same-realm native signal; no close deadline is fabricated. */
  signal?: AbortSignal | null;
}
export interface BrowserWebSocketCloseOptions { code?: number; reason?: string; }
export interface BrowserWebSocketHandle {
  readonly opened: Promise<Outcome<BrowserWebSocketReady>>;
  /** First terminal publication receipt, after native close and listener cleanup. */
  readonly closed: Promise<Outcome<void>>;
  /** At most one receive may be pending. Native stream conversion is exclusive. */
  receive(): Promise<Outcome<BrowserWebSocketRead>>;
  toReadableStream(): Outcome<ReadableStream<BrowserWebSocketMessage>>;
  /** Synchronous admission to native buffering, not delivery acknowledgement. */
  send(value: BrowserWebSocketMessage): Outcome<void>;
  close(options?: BrowserWebSocketCloseOptions): Promise<Outcome<void>>;
  cancel(reason?: string): Promise<Outcome<void>>;
  /** Independent cleanup receipt; retries refused cancellation/publication. */
  retire(reason?: string): Promise<Outcome<void>>;
}

/** Internal task adapter: the existing ABI owns identity and admission. */
export interface BrowserWebSocketTask {
  readonly key: string;
  cancel(kind: string, message: string): Outcome<void>;
  join(outcome: Outcome<void>): Outcome<void>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string, code: "compatibility_rejected" | "capability_denied" | "internal_failure" = "internal_failure"): Failure =>
  Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability: "permanent", message }) });
const severity = (value: Failure): number => value.outcome === "panicked" ? 3 : value.outcome === "cancelled" ? 2 : 1;
function cancellation(kind: string, reason: string): Failure {
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind, phase: "completed", origin_region: "browser-websocket", origin_task: null, timestamp_nanos: 0,
    message: reason.slice(0, 512), truncated: reason.length > 512,
  }) });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function checked(value: unknown): Outcome<void> {
  try {
    if (!value || typeof value !== "object") return fail("invalid WebSocket task receipt");
    const receipt = value as Outcome<void>;
    switch (receipt.outcome) {
      case "ok": return receipt.value === undefined ? ok(undefined) : fail("invalid WebSocket task success");
      case "err": {
        const { code, recoverability, message } = receipt.failure;
        if (["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            && ["transient", "permanent", "unknown"].includes(recoverability) && typeof message === "string") {
          return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
        }
        break;
      }
      case "panicked": {
        const message = receipt.message;
        if (typeof message === "string") return Object.freeze({ outcome: "panicked", message });
        break;
      }
      case "cancelled": {
        const { kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated } = receipt.cancellation;
        if (typeof kind === "string" && ["requested", "cancelling", "finalizing", "completed"].includes(phase)
            && typeof origin_region === "string" && (origin_task === null || typeof origin_task === "string")
            && (typeof timestamp_nanos === "bigint" || typeof timestamp_nanos === "number" && Number.isFinite(timestamp_nanos))
            && (message === null || typeof message === "string") && typeof truncated === "boolean") {
          return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
            kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated,
          }) });
        }
      }
    }
  } catch { /* Never render host exceptions or task authority. */ }
  return fail("invalid WebSocket task receipt");
}
function sameOutcome(expected: Outcome<void>, actual: Outcome<void>): boolean {
  if (expected.outcome !== actual.outcome) return false;
  switch (expected.outcome) {
    case "ok": return actual.outcome === "ok";
    case "err": return actual.outcome === "err" && expected.failure.code === actual.failure.code
      && expected.failure.recoverability === actual.failure.recoverability && expected.failure.message === actual.failure.message;
    case "panicked": return actual.outcome === "panicked" && expected.message === actual.message;
    case "cancelled": {
      if (actual.outcome !== "cancelled") return false;
      const a = expected.cancellation, b = actual.cancellation;
      return a.kind === b.kind && a.phase === b.phase && a.origin_region === b.origin_region
        && a.origin_task === b.origin_task && String(a.timestamp_nanos) === String(b.timestamp_nanos)
        && a.message === b.message && a.truncated === b.truncated;
    }
  }
}
function streamError(outcome: Failure): Error {
  const error = new Error("Owned WebSocket stream failed");
  Object.defineProperty(error, "cause", { value: outcome, configurable: true });
  return error;
}
function limit(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new TypeError("invalid WebSocket limit");
  return value;
}
/** UTF-8 length with early overflow, without allocating an encoded copy. */
function textBytes(value: string, maximum: number): number {
  let bytes = 0;
  for (let i = 0; i < value.length && bytes <= maximum; i += 1) {
    const point = value.charCodeAt(i);
    if (point < 0x80) bytes += 1;
    else if (point < 0x800) bytes += 2;
    else if (point >= 0xd800 && point <= 0xdbff && i + 1 < value.length
        && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) { bytes += 4; i += 1; }
    else bytes += 3;
  }
  return bytes;
}
const BUFFER_BYTES = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;
const TYPED = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_BYTES = Object.getOwnPropertyDescriptor(TYPED, "byteLength")!.get!;
const TYPED_TAG = Object.getOwnPropertyDescriptor(TYPED, Symbol.toStringTag)!.get!;

interface Host {
  prototype: object;
  state: (this: WebSocket) => number;
  buffered: (this: WebSocket) => number;
  protocol: (this: WebSocket) => string;
  extensions: (this: WebSocket) => string;
  binary: (this: WebSocket, value: string) => void;
  send: WebSocket["send"];
  close: WebSocket["close"];
  add: EventTarget["addEventListener"];
  remove: EventTarget["removeEventListener"];
  data: (this: MessageEvent) => unknown;
  Stream: typeof ReadableStream | undefined;
  signal?: AbortSignal;
  aborted?: (this: AbortSignal) => boolean;
}
function prepare(host: Record<string, unknown> | undefined, socket: WebSocket, options: BrowserWebSocketOptions) {
  const WebSocketClass = host?.WebSocket as typeof WebSocket | undefined;
  const EventTargetClass = host?.EventTarget as typeof EventTarget | undefined;
  const MessageEventClass = host?.MessageEvent as typeof MessageEvent | undefined;
  if (typeof WebSocketClass !== "function" || typeof EventTargetClass !== "function" || typeof MessageEventClass !== "function") {
    throw new TypeError("native WebSocket events are unavailable");
  }
  const prototype = WebSocketClass.prototype;
  const native: Host = {
    prototype,
    state: Object.getOwnPropertyDescriptor(prototype, "readyState")?.get!,
    buffered: Object.getOwnPropertyDescriptor(prototype, "bufferedAmount")?.get!,
    protocol: Object.getOwnPropertyDescriptor(prototype, "protocol")?.get!,
    extensions: Object.getOwnPropertyDescriptor(prototype, "extensions")?.get!,
    binary: Object.getOwnPropertyDescriptor(prototype, "binaryType")?.set!,
    send: prototype.send, close: prototype.close,
    add: EventTargetClass.prototype.addEventListener, remove: EventTargetClass.prototype.removeEventListener,
    data: Object.getOwnPropertyDescriptor(MessageEventClass.prototype, "data")?.get!,
    Stream: typeof host?.ReadableStream === "function" ? host.ReadableStream as typeof ReadableStream : undefined,
  };
  if (Object.getPrototypeOf(socket) !== prototype || [native.state, native.buffered, native.protocol, native.extensions,
    native.binary, native.send, native.close, native.add, native.remove, native.data].some(fn => typeof fn !== "function")) {
    throw new TypeError("expected a same-realm native WebSocket");
  }
  const state = Reflect.apply(native.state, socket, []);
  if (state !== 0 && state !== 1) throw new TypeError("WebSocket must be connecting or open");
  const maxQueuedMessages = limit(options.maxQueuedMessages ?? BROWSER_WEBSOCKET_LIMITS.maxQueuedMessages, 4096);
  const maxQueuedBytes = limit(options.maxQueuedBytes ?? BROWSER_WEBSOCKET_LIMITS.maxQueuedBytes, 67_108_864);
  const maxMessageBytes = limit(options.maxMessageBytes ?? BROWSER_WEBSOCKET_LIMITS.maxMessageBytes, 16_777_216);
  const maxSendBufferedBytes = limit(options.maxSendBufferedBytes ?? BROWSER_WEBSOCKET_LIMITS.maxSendBufferedBytes, 67_108_864);
  const suppliedSignal = options.signal;
  if (suppliedSignal != null) {
    const Signal = host?.AbortSignal as typeof AbortSignal | undefined;
    const aborted = Signal && Object.getOwnPropertyDescriptor(Signal.prototype, "aborted")?.get;
    if (!Signal || !aborted || typeof Signal.any !== "function" || Object.getPrototypeOf(suppliedSignal) !== Signal.prototype
        || Object.getOwnPropertyDescriptor(suppliedSignal, "aborted") || Object.getOwnPropertyDescriptor(suppliedSignal, "reason")) {
      throw new TypeError("expected an unmodified same-realm native AbortSignal");
    }
    Reflect.apply(aborted, suppliedSignal, []);
    native.signal = Reflect.apply(Signal.any, Signal, [[suppliedSignal]]) as AbortSignal;
    native.aborted = aborted;
    Reflect.apply(aborted, native.signal, []);
  }
  if (![0, 1].includes(Reflect.apply(native.state, socket, []))) throw new TypeError("WebSocket closed during preflight");
  return { native, maxQueuedMessages, maxQueuedBytes, maxMessageBytes, maxSendBufferedBytes };
}

/** Shared by SDK scopes. Does not construct sockets or acquire network authority. */
export function createBrowserWebSocketManager(dependencies: {
  globalObject(): Record<string, unknown> | undefined;
  isTracked(scopeKey: string): boolean;
  isClosing(scopeKey: string): boolean;
}) {
  const active = new Map<string, Operation>();
  const adopted = new WeakSet<object>();
  type Prepared = ReturnType<typeof prepare>;

  class Operation {
    readonly opened = deferred<Outcome<BrowserWebSocketReady>>();
    readonly closed = deferred<Outcome<void>>();
    readonly nativeClosed = deferred<void>();
    readonly activated = deferred<void>();
    readonly listeners = new Map<string, EventListener>();
    readonly queue: { value: BrowserWebSocketMessage; bytes: number }[] = [];
    queuedBytes = 0;
    wake: (() => void) | null = null;
    receiving = false;
    converted = false;
    stream: ReadableStream<BrowserWebSocketMessage> | null = null;
    streamController: ReadableStreamDefaultController<BrowserWebSocketMessage> | null = null;
    streamEnded = false;
    nativePulling = false;
    operation: Outcome<void> | null = null;
    publicationFailure: Failure | null = null;
    closing = false;
    closeSent = false;
    closeObserverReady = false;
    hostClosed = false;
    ownerReleased = false;
    released = false;
    needsCancel = false;
    cancelAccepted = false;
    kind = "websocket_cancel";
    reason = "WebSocket cancelled by caller";
    closeCode = 1000;
    closeReason = "";
    signalListener: EventListener | null = null;
    attempt: Promise<Outcome<void>> | null = null;
    constructor(readonly scopeKey: string, readonly task: BrowserWebSocketTask,
      readonly socket: WebSocket, readonly prepared: Prepared) {}

    handle(): BrowserWebSocketHandle {
      return Object.freeze({
        opened: this.opened.promise, closed: this.closed.promise,
        receive: () => this.receive(false), toReadableStream: () => this.toReadableStream(),
        send: (value: BrowserWebSocketMessage) => this.send(value),
        close: (options?: BrowserWebSocketCloseOptions) => this.close(options),
        cancel: (reason?: string) => this.cancel(reason), retire: (reason?: string) => this.retire(reason),
      });
    }
    notify(): void { this.wake?.(); this.wake = null; }
    clearQueue(): void { this.queue.length = 0; this.queuedBytes = 0; }
    add(type: string, listener: EventListener): void {
      // Keep the cleanup obligation even if a host throws after attaching.
      this.listeners.set(type, listener);
      Reflect.apply(this.prepared.native.add, this.socket, [type, listener]);
      if (type === "close") this.closeObserverReady = true;
    }
    activate(): void {
      try {
        this.add("close", event => this.onClose(event));
        this.add("error", () => this.stop(fail("WebSocket transport failed"), "websocket_error"));
        this.add("message", event => this.onMessage(event as MessageEvent));
        this.add("open", () => this.onOpen());
        Reflect.apply(this.prepared.native.binary, this.socket, ["arraybuffer"]);
        const native = this.prepared.native;
        if (native.signal) {
          this.signalListener = () => this.stop(cancellation("websocket_signal", "WebSocket cancelled by caller signal"), "websocket_signal");
          Reflect.apply(native.add, native.signal, ["abort", this.signalListener, { once: true }]);
          if (Reflect.apply(native.aborted!, native.signal, [])) {
            this.stop(cancellation("websocket_signal", "WebSocket cancelled by caller signal"), "websocket_signal");
          }
        }
        if (dependencies.isClosing(this.scopeKey) || !dependencies.isTracked(this.scopeKey)) {
          this.stop(cancellation("scope_close", "WebSocket owner is closing"), "scope_close");
        }
        const state = Reflect.apply(native.state, this.socket, []);
        if (state === 1) this.onOpen();
        else if (state === 3 && !this.hostClosed) {
          // A host can close during listener installation. CLOSED is native
          // state, not a caller-provided completion receipt.
          this.onClose();
        }
      } catch { this.stop(fail("WebSocket listener activation failed"), "websocket_setup"); }
      finally { this.activated.resolve(); }
    }
    onOpen(): void {
      if (this.closing || this.hostClosed) return;
      try {
        const native = this.prepared.native;
        if (Reflect.apply(native.state, this.socket, []) !== 1) return;
        this.opened.resolve(ok(Object.freeze({ protocol: Reflect.apply(native.protocol, this.socket, []),
          extensions: Reflect.apply(native.extensions, this.socket, []) })));
      } catch { this.stop(fail("WebSocket opening observation failed"), "websocket_error"); }
    }
    onMessage(event: MessageEvent): void {
      if (this.closing || this.hostClosed) return;
      try {
        const data = Reflect.apply(this.prepared.native.data, event, []);
        let value: BrowserWebSocketMessage, bytes: number;
        if (typeof data === "string") { value = data; bytes = textBytes(data, this.prepared.maxMessageBytes); }
        else {
          bytes = Reflect.apply(BUFFER_BYTES, data, []);
          if (bytes > this.prepared.maxMessageBytes || bytes > this.prepared.maxQueuedBytes - this.queuedBytes
              || this.queue.length >= this.prepared.maxQueuedMessages) {
            this.stop(fail("WebSocket receive buffer limit exceeded"), "websocket_overflow"); return;
          }
          value = new Uint8Array(new Uint8Array(data as ArrayBuffer));
        }
        if (bytes > this.prepared.maxMessageBytes || bytes > this.prepared.maxQueuedBytes - this.queuedBytes
            || this.queue.length >= this.prepared.maxQueuedMessages) {
          this.stop(fail("WebSocket receive buffer limit exceeded"), "websocket_overflow"); return;
        }
        this.queue.push({ value, bytes }); this.queuedBytes += bytes; this.notify();
      } catch { this.stop(fail("WebSocket message payload is unsupported"), "websocket_error"); }
    }
    onClose(event?: Event): void {
      if (this.hostClosed) return;
      try { if (Reflect.apply(this.prepared.native.state, this.socket, []) !== 3) return; }
      catch { return; }
      this.hostClosed = true;
      this.closing = true;
      if (!this.operation || this.operation.outcome === "ok") {
        let clean = false;
        try { clean = (event as CloseEvent | undefined)?.wasClean === true; } catch { /* Sanitized below. */ }
        this.operation = clean ? ok(undefined) : fail("WebSocket closed abnormally");
      }
      this.opened.resolve(this.operation.outcome === "ok" ? fail("WebSocket closed before opening") : this.operation);
      this.nativeClosed.resolve(); this.notify();
      void this.joinRetirement();
    }
    finishStream(): void {
      if (!this.streamController || this.streamEnded) return;
      const failure = this.publicationFailure ?? (this.operation?.outcome !== "ok" ? this.operation : null);
      if (failure) { this.streamEnded = true; this.streamController.error(streamError(failure)); }
      else if (this.released && this.queue.length === 0 && !this.nativePulling) { this.streamEnded = true; this.streamController.close(); }
    }
    stop(outcome: Failure, kind: string): void {
      if (this.released || this.hostClosed) return;
      if (!this.operation || this.operation.outcome === "ok" || severity(outcome) > severity(this.operation)) {
        this.operation = outcome; this.kind = kind;
      }
      this.closing = true; this.needsCancel = true;
      this.reason = this.operation.outcome === "cancelled" ? this.operation.cancellation.message ?? "WebSocket cancelled" : "WebSocket failed";
      this.clearQueue(); this.opened.resolve(this.operation as Failure); this.notify();
      void this.joinRetirement();
    }
    async receive(nativeConsumer: boolean): Promise<Outcome<BrowserWebSocketRead>> {
      if (this.converted && !nativeConsumer) return fail("WebSocket receive ownership was transferred", "compatibility_rejected");
      if (this.receiving) return fail("WebSocket already has a pending receive", "compatibility_rejected");
      this.receiving = true;
      try {
        for (;;) {
          if (this.publicationFailure) return this.publicationFailure;
          if (this.operation && this.operation.outcome !== "ok") {
            const terminal = await this.closed.promise;
            return terminal.outcome === "ok" ? this.operation as Failure : terminal;
          }
          const entry = this.queue.shift();
          if (entry) { this.queuedBytes -= entry.bytes; return ok({ done: false, value: entry.value }); }
          if (this.hostClosed) {
            const terminal = await this.closed.promise;
            return terminal.outcome === "ok" ? ok({ done: true }) : terminal;
          }
          await new Promise<void>(resolve => { this.wake = resolve; });
        }
      } finally { this.receiving = false; }
    }
    toReadableStream(): Outcome<ReadableStream<BrowserWebSocketMessage>> {
      if (this.stream) return ok(this.stream);
      if (this.receiving) return fail("WebSocket has a pending manual receive", "compatibility_rejected");
      const Stream = this.prepared.native.Stream;
      if (!Stream) return fail("WebSocket stream conversion requires native ReadableStream", "compatibility_rejected");
      try {
        const stream = new Stream<BrowserWebSocketMessage>({
          start: controller => { this.streamController = controller; },
          pull: async controller => {
            this.nativePulling = true;
            try {
              const next = await this.receive(true);
              if (this.streamEnded) return;
              if (next.outcome !== "ok") { this.streamEnded = true; controller.error(streamError(next)); }
              else if (next.value.done) { this.streamEnded = true; controller.close(); }
              else controller.enqueue(next.value.value);
            } finally { this.nativePulling = false; if (this.released || this.publicationFailure) this.finishStream(); }
          },
          cancel: async () => {
            this.streamEnded = true; this.clearQueue();
            const retired = await this.retire("WebSocket stream consumer exited");
            if (retired.outcome !== "ok") throw streamError(retired);
            const terminal = await this.closed.promise;
            if (terminal.outcome === "err" || terminal.outcome === "panicked") throw streamError(terminal);
          },
        }, { highWaterMark: 0 });
        this.converted = true; this.stream = stream;
        if (this.released || this.publicationFailure) this.finishStream();
        return ok(stream);
      } catch { return fail("WebSocket stream conversion failed", "compatibility_rejected"); }
    }
    send(value: BrowserWebSocketMessage): Outcome<void> {
      if (this.closing || this.hostClosed || this.released) return fail("WebSocket is closing", "compatibility_rejected");
      try {
        const native = this.prepared.native;
        if (Reflect.apply(native.state, this.socket, []) !== 1) return fail("WebSocket is not open", "compatibility_rejected");
        let bytes: number;
        if (typeof value === "string") bytes = textBytes(value, this.prepared.maxMessageBytes);
        else {
          if (Reflect.apply(TYPED_TAG, value, []) !== "Uint8Array") return fail("WebSocket send requires string or Uint8Array", "compatibility_rejected");
          bytes = Reflect.apply(TYPED_BYTES, value, []);
        }
        const buffered = Reflect.apply(native.buffered, this.socket, []);
        if (!Number.isSafeInteger(buffered) || buffered < 0 || bytes > this.prepared.maxMessageBytes
            || bytes > this.prepared.maxSendBufferedBytes - buffered) return fail("WebSocket send buffer limit exceeded", "capability_denied");
        if (this.closing || this.hostClosed || dependencies.isClosing(this.scopeKey)
            || Reflect.apply(native.state, this.socket, []) !== 1) return fail("WebSocket owner is closing", "capability_denied");
        Reflect.apply(native.send, this.socket, [value]); return ok(undefined);
      } catch { return fail("WebSocket send failed"); }
    }
    close(options: BrowserWebSocketCloseOptions = {}): Promise<Outcome<void>> {
      try {
        const code = options.code ?? 1000, reason = options.reason ?? "";
        if (!Number.isInteger(code) || code !== 1000 && (code < 3000 || code > 4999)
            || typeof reason !== "string" || textBytes(reason, 123) > 123) return Promise.resolve(fail("invalid WebSocket close options", "compatibility_rejected"));
        if (!this.closing && !this.hostClosed) {
          this.closeCode = code; this.closeReason = reason; this.closing = true;
          this.operation = ok(undefined);
          this.opened.resolve(fail("WebSocket closed before opening"));
        }
        return this.joinRetirement().then(receipt => receipt.outcome === "ok" ? this.closed.promise : receipt);
      } catch { return Promise.resolve(fail("invalid WebSocket close options", "compatibility_rejected")); }
    }
    cancel(reason = "WebSocket cancelled by caller"): Promise<Outcome<void>> {
      if (typeof reason !== "string") return Promise.resolve(fail("WebSocket cancellation reason must be a string", "compatibility_rejected"));
      this.clearQueue();
      if (this.released || this.publicationFailure) this.finishStream();
      return this.retire(reason).then(receipt => receipt.outcome === "ok" ? this.closed.promise : receipt);
    }
    retire(reason = "WebSocket retired by caller", kind = "websocket_cancel"): Promise<Outcome<void>> {
      if (typeof reason !== "string") return Promise.resolve(fail("WebSocket cancellation reason must be a string", "compatibility_rejected"));
      if (!this.hostClosed && (!this.closing || this.operation?.outcome === "ok")) this.stop(cancellation(kind, reason), kind);
      return this.joinRetirement();
    }
    joinRetirement(): Promise<Outcome<void>> {
      if (this.released) return Promise.resolve(ok(undefined));
      if (this.attempt) return this.attempt;
      const receipt = deferred<Outcome<void>>();
      this.attempt = receipt.promise;
      void (async () => {
        let issue: Failure | null = null;
        let attemptedCancel = false;
        const admitCancellation = (): void => {
          if (!this.needsCancel || this.cancelAccepted || this.ownerReleased || attemptedCancel) return;
          attemptedCancel = true;
          try {
            const admitted = checked(this.task.cancel(this.kind, this.reason));
            if (admitted.outcome === "ok") this.cancelAccepted = true;
            else issue ??= admitted;
          } catch { issue ??= fail("WebSocket cancellation admission failed"); }
        };
        try {
          await this.activated.promise;
          let observingClose = this.closeObserverReady;
          if (!this.hostClosed && !observingClose) {
            // Installation may have failed before OR after attaching. Reusing
            // the same listener is idempotent for EventTarget, and a positive
            // native CLOSED observation recovers an event already missed.
            try {
              if (Reflect.apply(this.prepared.native.state, this.socket, []) === 3) this.onClose();
              else {
                const listener = this.listeners.get("close");
                if (!listener) throw new TypeError("missing close observer");
                Reflect.apply(this.prepared.native.add, this.socket, ["close", listener]);
                this.closeObserverReady = observingClose = true;
              }
            } catch { issue = fail("WebSocket close observation failed"); }
          }
          admitCancellation();
          if (!this.hostClosed && !this.closeSent) {
            try { Reflect.apply(this.prepared.native.close, this.socket, [this.closeCode, this.closeReason]); this.closeSent = true; }
            catch { issue ??= fail("WebSocket native close failed"); receipt.resolve(issue); return; }
          }
          if (!this.hostClosed && !observingClose) {
            try { if (Reflect.apply(this.prepared.native.state, this.socket, []) === 3) this.onClose(); }
            catch { /* Retained ownership is reported below. */ }
            if (!this.hostClosed) {
              // Neither a close request nor a missing observer proves host
              // quiescence. An explicit retry can attach or observe CLOSED.
              receipt.resolve(issue ?? fail("WebSocket close observation is unavailable")); return;
            }
          }
          await this.nativeClosed.promise;
          // A caller/owner may cancel while a graceful handshake is pending.
          // Observe that strengthening before publishing Cancelled to the ABI.
          admitCancellation();
          for (const [type, listener] of this.listeners) {
            try { Reflect.apply(this.prepared.native.remove, this.socket, [type, listener]); this.listeners.delete(type); }
            catch { issue ??= fail("WebSocket listener cleanup failed"); }
          }
          if (this.signalListener && this.prepared.native.signal) {
            try {
              Reflect.apply(this.prepared.native.remove, this.prepared.native.signal, ["abort", this.signalListener]);
              this.signalListener = null;
            } catch { issue ??= fail("WebSocket signal cleanup failed"); }
          }
          const terminal = this.operation ?? ok(undefined);
          if (!issue && !this.ownerReleased) {
            const published = checked(this.task.join(terminal));
            if (!sameOutcome(terminal, published)) issue = published.outcome === "ok"
              ? fail("WebSocket terminal publication returned inconsistent success") : published;
          }
          if (issue) {
            this.publicationFailure ??= issue; this.clearQueue(); this.closed.resolve(issue); this.notify(); this.finishStream();
          } else {
            this.released = true; active.delete(this.task.key); adopted.delete(this.socket);
            this.closed.resolve(terminal); this.notify(); this.finishStream();
          }
          receipt.resolve(issue ?? ok(undefined));
        } catch {
          const issue = fail("WebSocket retirement failed");
          if (this.hostClosed) { this.publicationFailure ??= issue; this.closed.resolve(issue); this.notify(); this.finishStream(); }
          receipt.resolve(issue);
        } finally { if (this.attempt === receipt.promise) this.attempt = null; }
      })();
      return receipt.promise;
    }
  }

  return {
    adopt(scopeKey: string, spawn: () => Outcome<BrowserWebSocketTask>, socket: WebSocket,
      options: BrowserWebSocketOptions = {}): Outcome<BrowserWebSocketHandle> {
      let prepared: Prepared;
      try {
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("WebSocket owner is unavailable", "capability_denied");
        prepared = prepare(dependencies.globalObject(), socket, options);
        if (adopted.has(socket)) return fail("WebSocket already has an SDK owner", "compatibility_rejected");
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("WebSocket owner is closing", "capability_denied");
      } catch { return fail("WebSocket adoption requires a connecting/open native socket and valid options", "compatibility_rejected"); }
      // Reserve before task admission, which may reenter another adoption.
      adopted.add(socket);
      let spawned: Outcome<BrowserWebSocketTask>;
      try { spawned = spawn(); }
      catch { adopted.delete(socket); return fail("WebSocket task admission failed"); }
      if (spawned.outcome !== "ok") { adopted.delete(socket); return spawned; }
      const operation = new Operation(scopeKey, spawned.value, socket, prepared);
      active.set(spawned.value.key, operation);
      operation.activate();
      return ok(operation.handle());
    },
    cancelTask(taskKey: string, kind: string, reason = "WebSocket task cancelled"): void {
      const operation = active.get(taskKey);
      if (!operation) return;
      operation.cancelAccepted = true;
      operation.stop(cancellation(kind, reason), kind);
    },
    async drainScopes(scopeKeys: Set<string>, kind: string): Promise<Outcome<void>> {
      const receipts = await Promise.all([...active.values()].filter(operation => scopeKeys.has(operation.scopeKey))
        .map(operation => operation.retire("WebSocket owner is closing", kind)));
      return receipts.find(receipt => receipt.outcome !== "ok") ?? ok(undefined);
    },
    closeScopes(scopeKeys: Set<string>, kind: string): void {
      for (const operation of active.values()) {
        if (!scopeKeys.has(operation.scopeKey)) continue;
        operation.ownerReleased = true;
        operation.stop(cancellation(kind, "WebSocket owner was closed"), kind);
        void operation.joinRetirement();
      }
    },
  };
}
