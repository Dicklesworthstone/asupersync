/** Scope-owned browser fetch with explicit authority and bounded streamed bytes. */
import {
  Outcome as Outcomes, RegionHandle as CoreRegionHandle, taskCancel, taskJoin, taskSpawn,
  type AbiVersion, type FetchAuthority, type FetchMethod, type HandleRef,
  type Outcome, type RegionHandleRef, type TaskHandle,
  type WasmValue,
} from "@asupersync/browser-core";

export const BROWSER_FETCH_LIMITS = Object.freeze({
  maxRequestsPerRuntime: 64, maxRequestBytes: 1_048_576,
  maxResponseBytes: 16_777_216, maxChunkBytes: 1_048_576,
  maxResponseHeaders: 128, maxHeaderBytes: 65_536,
});

export interface BrowserFetchOptions {
  url: string;
  method?: FetchMethod;
  credentials?: boolean;
  headers?: Readonly<Record<string, string>> | readonly (readonly [string, string])[];
  body?: ArrayBuffer | ArrayBufferView;
  /** Actual decoded response bytes, independent of Content-Length. */
  maxResponseBytes?: number;
}

export interface BrowserFetchResponse {
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  readonly headers: readonly (readonly [string, string])[];
}

export type BrowserFetchRead = { done: true } | { done: false; value: Uint8Array };

/**
 * One admitted host fetch. Headers do not complete its task: EOF or cancelled
 * host cleanup does. Reads pull only on demand; returned bytes belong to the
 * caller and are outside the manager's active-operation memory envelope.
 * Synchronous scope/runtime close keeps its existing ABI refusal behavior.
 * Cancel this handle and await `closed` before closing an otherwise idle owner.
 * A host that never settles cannot be forcibly drained by JavaScript.
 */
export interface FetchStreamHandle {
  readonly closed: Promise<Outcome<void>>;
  response(): Promise<Outcome<BrowserFetchResponse>>;
  read(): Promise<Outcome<BrowserFetchRead>>;
  cancel(reason?: string): Promise<Outcome<void>>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
type Deferred<T> = { promise: Promise<T>; resolve(value: T): void };

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function message(error: unknown): string {
  try { return error instanceof Error ? error.message : String(error); }
  catch { return "unprintable host error"; }
}

function failure(text: string, code: "capability_denied" | "compatibility_rejected" | "internal_failure" = "compatibility_rejected", transient = false): Failure {
  return Outcomes.err(code, transient ? "transient" : "permanent", text) as Failure;
}

function cancelled(kind: string, reason: string | undefined, task: TaskHandle): Failure {
  const raw = task.toJSON();
  return Outcomes.cancelled({ kind, phase: "completed", origin_region: "browser-sdk",
    origin_task: `${raw.kind}:${raw.slot}:${raw.generation}`, timestamp_nanos: 0,
    message: reason ?? null, truncated: false }) as Failure;
}

export function browserFetchHandleKey(raw: HandleRef): string {
  return `${raw.kind}:${raw.slot}:${raw.generation}:${raw.owner_token ?? "legacy"}`;
}

function httpUrl(value: string): URL {
  if (typeof value !== "string" || value.length === 0) throw new TypeError("fetch URL must be nonempty");
  const url = new URL(value);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin === "null" || url.username || url.password) {
    throw new TypeError("fetch requires an absolute HTTP(S) URL without embedded credentials");
  }
  return url;
}

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/** Internal snapshot; the caller sends this same immutable grant to the ABI. */
export function prepareBrowserFetchAuthority(authority: FetchAuthority = {}): FetchAuthority {
  if (!authority || typeof authority !== "object" || Array.isArray(authority)) throw new TypeError("fetchAuthority must be an object");
  const origins = authority.allowedOrigins ?? [];
  const methods = authority.allowedMethods ?? [];
  const allowCredentials = authority.allowCredentials ?? false;
  const maxHeaderCount = authority.maxHeaderCount ?? 0;
  if (!Array.isArray(origins) || !Array.isArray(methods)) throw new TypeError("fetch authority origins and methods must be arrays");
  if (typeof allowCredentials !== "boolean" || !Number.isSafeInteger(maxHeaderCount) || maxHeaderCount < 0) throw new TypeError("invalid fetch credential/header authority");
  const allowedOrigins: string[] = [];
  const originCount = origins.length;
  const methodCount = methods.length;
  for (let index = 0; index < originCount; index += 1) {
    const origin = origins[index];
    allowedOrigins.push(origin === "*" ? "*" : httpUrl(origin).origin);
  }
  const allowedMethods: FetchMethod[] = [];
  for (let index = 0; index < methodCount; index += 1) {
    const value = methods[index];
    if (typeof value !== "string") throw new TypeError("fetch authority method must be a string");
    const method = value.trim().toUpperCase();
    if (!METHODS.has(method)) throw new TypeError("unsupported fetch authority method");
    allowedMethods.push(method as FetchMethod);
  }
  Object.freeze(allowedOrigins);
  Object.freeze(allowedMethods);
  return Object.freeze({ allowedOrigins, allowedMethods, allowCredentials, maxHeaderCount });
}

const TYPED_ARRAY = Object.getPrototypeOf(Uint8Array.prototype) as object;
const VIEW_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "buffer")!.get!;
const VIEW_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteOffset")!.get!;
const VIEW_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteLength")!.get!;
const DATA_BUFFER = Object.getOwnPropertyDescriptor(DataView.prototype, "buffer")!.get!;
const DATA_OFFSET = Object.getOwnPropertyDescriptor(DataView.prototype, "byteOffset")!.get!;
const DATA_LENGTH = Object.getOwnPropertyDescriptor(DataView.prototype, "byteLength")!.get!;
const BUFFER_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;

function byteView(value: unknown): Uint8Array {
  if (ArrayBuffer.isView(value)) {
    let buffer: ArrayBufferLike;
    let offset: number;
    let length: number;
    try {
      buffer = Reflect.apply(VIEW_BUFFER, value, []);
      offset = Reflect.apply(VIEW_OFFSET, value, []);
      length = Reflect.apply(VIEW_LENGTH, value, []);
    } catch {
      buffer = Reflect.apply(DATA_BUFFER, value, []);
      offset = Reflect.apply(DATA_OFFSET, value, []);
      length = Reflect.apply(DATA_LENGTH, value, []);
    }
    return new Uint8Array(buffer, offset, length);
  }
  const length = Reflect.apply(BUFFER_LENGTH, value, []) as number;
  return new Uint8Array(value as ArrayBuffer, 0, length);
}

interface Prepared {
  url: string;
  method: string;
  credentials: boolean;
  headers: [string, string][];
  body?: Uint8Array;
  maxResponseBytes: number;
}

function prepare(options: BrowserFetchOptions, grant: FetchAuthority): Prepared {
  if (!options || typeof options !== "object") throw new TypeError("fetch options must be an object");
  const { url: suppliedUrl, method: suppliedMethod = "GET", credentials = false,
    headers: suppliedHeaders = [], body, maxResponseBytes = BROWSER_FETCH_LIMITS.maxResponseBytes } = options;
  if (typeof suppliedUrl !== "string" || suppliedUrl.length * 2 > BROWSER_FETCH_LIMITS.maxHeaderBytes) throw new RangeError("fetch request URL exceeds limit");
  const url = httpUrl(suppliedUrl);
  if (typeof suppliedMethod !== "string") throw new TypeError("fetch method must be a string");
  const method = suppliedMethod.trim().toUpperCase();
  if (!METHODS.has(method)) throw new TypeError("unsupported fetch method");
  if (typeof credentials !== "boolean") throw new TypeError("fetch credentials must be a boolean");
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 0) throw new TypeError("maxResponseBytes must be a non-negative safe integer");
  if (!(grant.allowedOrigins?.includes("*") || grant.allowedOrigins?.includes(url.origin))
      || !grant.allowedMethods?.includes(method as FetchMethod)
      || (credentials && !grant.allowCredentials)) {
    throw failure("fetch request exceeds the owning runtime's authority", "capability_denied");
  }
  const headers: [string, string][] = [];
  let headerBytes = 0;
  const addHeader = (name: unknown, value: unknown) => {
    if (headers.length >= (grant.maxHeaderCount ?? 0)) throw failure("fetch request exceeds header-count authority", "capability_denied");
    if (typeof name !== "string" || typeof value !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0]/.test(value)) throw new TypeError("invalid fetch header");
    headerBytes += (name.length + value.length) * 2;
    if (headerBytes > BROWSER_FETCH_LIMITS.maxHeaderBytes) throw new RangeError("fetch request header bytes exceed limit");
    headers.push([name, value]);
  };
  if (Array.isArray(suppliedHeaders)) {
    if (suppliedHeaders.length > (grant.maxHeaderCount ?? 0)) throw failure("fetch request exceeds header-count authority", "capability_denied");
    for (const pair of suppliedHeaders) {
      if (!Array.isArray(pair) || pair.length !== 2) throw new TypeError("fetch header must be a name/value pair");
      addHeader(pair[0], pair[1]);
    }
  } else {
    if (!suppliedHeaders || typeof suppliedHeaders !== "object") throw new TypeError("fetch headers must be an object or pairs");
    for (const name of Object.keys(suppliedHeaders)) addHeader(name, (suppliedHeaders as Readonly<Record<string, string>>)[name]);
  }
  let copied: Uint8Array | undefined;
  if (body !== undefined) {
    if (method === "GET" || method === "HEAD") throw new TypeError("GET and HEAD do not permit a request body");
    const view = byteView(body);
    if (view.byteLength > BROWSER_FETCH_LIMITS.maxRequestBytes) throw new RangeError("fetch request body exceeds limit");
    copied = view.slice();
  }
  return { url: url.href, method, credentials, headers, body: copied, maxResponseBytes };
}

function asFailure(error: unknown): Failure {
  if (error && typeof error === "object" && "outcome" in error && error.outcome === "err") return error as Failure;
  return failure(`browser fetch failed: ${message(error)}`, "internal_failure", true);
}

function sameTerminal(proposed: Outcome<void>, receipt: Outcome<WasmValue>): boolean {
  if (proposed.outcome === "ok") return receipt.outcome === "ok" && receipt.value === undefined;
  if (proposed.outcome === "err") return receipt.outcome === "err"
    && proposed.failure.code === receipt.failure.code
    && proposed.failure.recoverability === receipt.failure.recoverability
    && proposed.failure.message === receipt.failure.message;
  if (proposed.outcome === "panicked") return receipt.outcome === "panicked" && proposed.message === receipt.message;
  if (receipt.outcome !== "cancelled") return false;
  const expected = proposed.cancellation;
  const actual = receipt.cancellation;
  return expected.kind === actual.kind && expected.phase === actual.phase
    && expected.origin_region === actual.origin_region && expected.origin_task === actual.origin_task
    && BigInt(expected.timestamp_nanos) === BigInt(actual.timestamp_nanos)
    && expected.message === actual.message && expected.truncated === actual.truncated;
}

async function attempt(operation: () => unknown): Promise<void> {
  try { await operation(); } catch { /* Preserve the first terminal outcome. */ }
}

export interface BrowserFetchGrant { rootKey: string; authority: FetchAuthority; }

/** Internal authority resolver and ownership registry, shared by all SDK scopes. */
export function createBrowserFetchManager(dependencies: {
  lookup(scopeKey: string): BrowserFetchGrant | null;
  globalObject(): Record<string, unknown> | undefined;
}) {
  const active = new Map<string, Operation>();
  const roots = new Map<string, number>();
  const releaseCredit = (rootKey: string) => {
    const count = roots.get(rootKey) ?? 1;
    if (count === 1) roots.delete(rootKey);
    else roots.set(rootKey, count - 1);
  };

  class Operation {
    readonly head = deferred<Outcome<BrowserFetchResponse>>();
    readonly closed = deferred<Outcome<void>>();
    readonly launched = deferred<void>();
    controller: AbortController | null = null;
    reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    reading: Deferred<void> | null = null;
    stopped: Failure | null = null;
    completed = false;
    ownerReleased = false;
    received = 0;
    terminalFailure: Failure | null = null;
    creditHeld = true;
    readonly taskKey: string;

    constructor(readonly scopeKey: string, readonly grant: BrowserFetchGrant,
      readonly task: TaskHandle, readonly version: AbiVersion | null, readonly request: Prepared) {
      this.taskKey = browserFetchHandleKey(task.toJSON());
    }

    handle(): FetchStreamHandle {
      return Object.freeze({ closed: this.closed.promise, response: () => this.head.promise,
        read: () => this.read(), cancel: (reason?: string) => this.cancel(reason) });
    }

    finish(outcome: Outcome<void>): void {
      if (this.completed) return;
      this.completed = true;
      let publicationFailed = false;
      if (!this.ownerReleased) {
        try {
          const receipt = taskJoin(this.task,
            outcome.outcome === "ok" ? Outcomes.ok(undefined) : outcome, this.version);
          // Mismatched receipts are publication failures and retain admission.
          // An identical non-ok envelope cannot distinguish a domain terminal
          // from an identical ABI refusal; actual owner close remains the
          // independent ledger barrier for that existing ABI limitation.
          if (!sameTerminal(outcome, receipt)) {
            publicationFailed = true;
            outcome = receipt.outcome === "ok"
              ? failure("fetch terminal publication returned an inconsistent success", "internal_failure")
              : receipt;
          }
        } catch (error) {
          publicationFailed = true;
          outcome = asFailure(error);
        }
      }
      if (outcome.outcome !== "ok") this.terminalFailure = outcome;
      if (!publicationFailed) this.retire();
      this.closed.resolve(outcome);
    }

    retire(): void {
      active.delete(this.taskKey);
      if (this.creditHeld) {
        this.creditHeld = false;
        releaseCredit(this.grant.rootKey);
      }
    }

    stop(outcome: Failure): void {
      if (this.stopped || this.completed) return;
      this.stopped = outcome;
      this.head.resolve(outcome);
      const reader = this.reader;
      const reading = this.reading;
      void (async () => {
        await Promise.all([
          attempt(() => this.controller?.abort()), attempt(() => reader?.cancel(outcome)),
          this.launched.promise, reading?.promise,
        ]);
        if (reader) { try { reader.releaseLock(); } catch { /* Already released. */ } }
        this.reader = null;
        this.finish(outcome);
      })();
    }

    async disposeResponse(response: Response): Promise<void> {
      await attempt(() => response.body?.cancel(this.stopped));
    }

    async launch(): Promise<void> {
      let response: Response | undefined;
      try {
        const host = dependencies.globalObject();
        const Controller = host?.AbortController;
        if (this.stopped) return;
        if (typeof Controller !== "function") throw new TypeError("AbortController is unavailable");
        this.controller = new (Controller as typeof AbortController)();
        if (this.stopped) { await attempt(() => this.controller?.abort()); return; }
        const fetch = host?.fetch;
        if (this.stopped) return;
        if (typeof fetch !== "function") throw new TypeError("browser fetch is unavailable");
        const signal = this.controller.signal;
        if (this.stopped) return;
        response = await Reflect.apply(fetch, host, [this.request.url, {
          method: this.request.method, headers: this.request.headers,
          body: this.request.body, credentials: this.request.credentials ? "include" : "omit",
          redirect: "error", signal,
        }]) as Response;
        this.request.body = undefined;
        if (this.stopped) { await this.disposeResponse(response); return; }
        const status = response.status;
        const statusText = response.statusText;
        const url = response.url;
        if (this.stopped) { await this.disposeResponse(response); return; }
        if (!Number.isInteger(status) || status < 100 || status > 599 || typeof statusText !== "string" || typeof url !== "string") throw new TypeError("invalid browser response metadata");
        let headerBytes = (statusText.length + url.length) * 2;
        const headers: (readonly [string, string])[] = [];
        const responseHeaders = response.headers;
        if (this.stopped) { await this.disposeResponse(response); return; }
        const entries = responseHeaders.entries;
        if (this.stopped) { await this.disposeResponse(response); return; }
        const iterator = Reflect.apply(entries, responseHeaders, []);
        if (this.stopped) { await this.disposeResponse(response); return; }
        for (;;) {
          const next = iterator.next;
          if (this.stopped) { await this.disposeResponse(response); return; }
          const item = Reflect.apply(next, iterator, []);
          if (this.stopped) { await this.disposeResponse(response); return; }
          const done = item.done;
          if (this.stopped) { await this.disposeResponse(response); return; }
          if (done === true) break;
          if (done !== false) throw new TypeError("invalid browser header iterator result");
          const [name, value] = item.value;
          if (this.stopped) { await this.disposeResponse(response); return; }
          if (typeof name !== "string" || typeof value !== "string") throw new TypeError("invalid browser response header");
          headerBytes += (name.length + value.length) * 2;
          if (headers.length >= BROWSER_FETCH_LIMITS.maxResponseHeaders || headerBytes > BROWSER_FETCH_LIMITS.maxHeaderBytes) throw new RangeError("fetch response headers exceed limits");
          headers.push(Object.freeze([name, value] as [string, string]));
        }
        if (headerBytes > BROWSER_FETCH_LIMITS.maxHeaderBytes) throw new RangeError("fetch response metadata exceeds limits");
        const body = response.body;
        if (this.stopped) { await this.disposeResponse(response); return; }
        if (body !== null) {
          const getReader = body.getReader;
          if (this.stopped) { await this.disposeResponse(response); return; }
          this.reader = Reflect.apply(getReader, body, []) as ReadableStreamDefaultReader<Uint8Array>;
          if (this.stopped) {
            await attempt(() => this.reader?.cancel(this.stopped));
            try { this.reader?.releaseLock(); } catch { /* Already released. */ }
            this.reader = null;
            return;
          }
          const readerClosed = this.reader.closed;
          void Promise.resolve(readerClosed).catch((error) => this.stop(asFailure(error)));
          if (this.stopped) return;
        }
        this.head.resolve(Outcomes.ok(Object.freeze({ status, statusText, url, headers: Object.freeze(headers) })));
        if (body === null) this.finish(Outcomes.ok(undefined));
      } catch (error) {
        this.stop(asFailure(error));
        if (response && !this.reader) await this.disposeResponse(response);
      } finally {
        this.request.body = undefined;
        this.launched.resolve();
      }
    }

    async read(): Promise<Outcome<BrowserFetchRead>> {
      if (this.completed) return this.terminalFailure ?? Outcomes.ok({ done: true });
      if (this.stopped) return this.stopped;
      if (this.reading) return failure("fetch already has a pending body read", "compatibility_rejected", true);
      const reading = deferred<void>();
      this.reading = reading;
      try {
        const head = await this.head.promise;
        if (head.outcome !== "ok") return head;
        if (this.stopped) return this.stopped;
        if (this.completed || !this.reader) return this.terminalFailure ?? Outcomes.ok({ done: true });
        const reader = this.reader;
        const read = reader.read;
        if (this.stopped) return this.stopped;
        const result = await Reflect.apply(read, reader, []);
        if (this.stopped) return this.stopped;
        const done = result.done;
        if (this.stopped) return this.stopped;
        if (typeof done !== "boolean") throw new TypeError("fetch body read result.done must be a boolean");
        if (done) {
          const release = reader.releaseLock;
          if (this.stopped) return this.stopped;
          // Keep the reader owned if its release callback requests cancel, so
          // stop() can await that cleanup before retiring the request.
          Reflect.apply(release, reader, []);
          if (this.stopped) return this.stopped;
          this.reader = null;
          this.finish(Outcomes.ok(undefined));
          return this.terminalFailure ?? Outcomes.ok({ done: true });
        }
        const value = result.value;
        if (this.stopped) return this.stopped;
        const bytes = byteView(value);
        if (bytes.byteLength > BROWSER_FETCH_LIMITS.maxChunkBytes || bytes.byteLength > this.request.maxResponseBytes - this.received) throw new RangeError("fetch response bytes exceed configured limits");
        const owned = bytes.slice();
        this.received += owned.byteLength;
        return Outcomes.ok({ done: false, value: owned });
      } catch (error) {
        const outcome = asFailure(error);
        this.stop(outcome);
        return this.stopped ?? outcome;
      } finally {
        this.reading = null;
        reading.resolve();
      }
    }

    cancel(reason = "fetch cancelled by caller"): Promise<Outcome<void>> {
      if (typeof reason !== "string") return Promise.resolve(failure("fetch cancel reason must be a string"));
      if (this.completed || this.stopped) return this.closed.promise;
      const admitted = taskCancel({ task: this.task, kind: "fetch_cancel", message: reason }, this.version);
      if (admitted.outcome !== "ok") return Promise.resolve(admitted);
      this.stop(cancelled("fetch_cancel", reason, this.task));
      return this.closed.promise;
    }
  }

  return {
    start(scope: CoreRegionHandle, options: BrowserFetchOptions, version: AbiVersion | null): Outcome<FetchStreamHandle> {
      try {
        const supplied = scope.toJSON();
        const validated = new CoreRegionHandle({ kind: supplied.kind,
          slot: supplied.slot, generation: supplied.generation, owner_token: supplied.owner_token } as RegionHandleRef).toJSON();
        const snapshot: RegionHandleRef = Object.freeze({ ...validated, kind: "region" });
        const consumerVersion = version === null ? null : Object.freeze({ major: version.major, minor: version.minor });
        if (consumerVersion && (!Number.isInteger(consumerVersion.major) || consumerVersion.major < 0 || consumerVersion.major > 65_535
            || !Number.isInteger(consumerVersion.minor) || consumerVersion.minor < 0 || consumerVersion.minor > 65_535)) {
          throw new TypeError("fetch ABI version fields must be unsigned 16-bit integers");
        }
        const scopeKey = browserFetchHandleKey(snapshot);
        const grant = dependencies.lookup(scopeKey);
        if (!grant) return failure("fetch requires a scope with retained explicit runtime authority", "capability_denied");
        const request = prepare(options, grant.authority);
        if (dependencies.lookup(scopeKey) !== grant) return failure("fetch owner closed during request preparation", "capability_denied");
        const count = roots.get(grant.rootKey) ?? 0;
        if (count >= BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) return failure("fetch runtime admission capacity exhausted", "compatibility_rejected", true);
        roots.set(grant.rootKey, count + 1);
        let spawned: ReturnType<typeof taskSpawn>;
        try {
          spawned = taskSpawn({ scope: snapshot, label: "browser-fetch-stream", cancel_kind: "fetch_cancel" }, consumerVersion);
        } catch (error) {
          releaseCredit(grant.rootKey);
          throw error;
        }
        if (spawned.outcome !== "ok") { releaseCredit(grant.rootKey); return spawned; }
        const operation = new Operation(scopeKey, grant, spawned.value, consumerVersion, request);
        active.set(operation.taskKey, operation);
        if (dependencies.lookup(scopeKey) !== grant) operation.ownerReleased = true;
        if (operation.ownerReleased) {
          operation.stop(cancelled("scope_close", "fetch owner closed during admission", operation.task));
          operation.launched.resolve();
        } else void operation.launch();
        return Outcomes.ok(operation.handle());
      } catch (error) { return asFailure(error); }
    },
    closeScopes(scopeKeys: Set<string>, reason: string): void {
      for (const operation of active.values()) {
        if (scopeKeys.has(operation.scopeKey)) {
          operation.ownerReleased = true;
          if (operation.completed) operation.retire();
          else operation.stop(cancelled(reason, reason, operation.task));
        }
      }
    },
    cancelTask(taskKey: string, kind: string, reason?: string): void {
      const operation = active.get(taskKey);
      if (operation) operation.stop(cancelled(kind, reason, operation.task));
    },
  };
}
