/** Pull-driven request transformation with an explicit producer/mapper join. */
import type { Outcome } from "@asupersync/browser-core";
import type { BrowserFetchOptions } from "./fetch.js";
import type { FetchBatchRequestSource } from "./fetch-batch.js";

/** Structurally compatible with record decoders and other owned producers. */
export interface FetchRequestMapSource<T> {
  readonly readable: ReadableStream<T>;
  /** Covers ALL source-owned work, independently of native stream EOF. */
  readonly closed: Promise<Outcome<void>>;
  /** Idempotent; works while readable is locked; never awaits downstream. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface FetchRequestMapOptions {
  /** Maximum mapped input records, including skipped ones. Default 100,000. */
  maxInputs?: number;
}

export interface FetchRequestFlatMapOptions extends FetchRequestMapOptions {
  /** Per-input descriptor cap, 1..1024. Default 64; empty arrays skip inputs. */
  maxRequestsPerInput?: number;
}

export type FetchRequestMapper<T, R> = (value: T, index: number, signal: AbortSignal) => R | PromiseLike<R>;
type Input<T> = ReadableStream<T> | FetchRequestMapSource<T>;
type Request = BrowserFetchOptions | null;
type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string, code: "compatibility_rejected" | "internal_failure" = "internal_failure"): Failure =>
  Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability: "permanent", message }) });
const panic = (): Failure => Object.freeze({ outcome: "panicked", message: "fetch request mapper threw or rejected" });
const cancelled = (message: string): Failure => Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
  kind: "fetch_request_map_cancel", phase: "completed", origin_region: "browser-request-map", origin_task: null,
  timestamp_nanos: 0, message, truncated: false,
}) });
const severity = (value: Failure): number => value.outcome === "panicked" ? 3 : value.outcome === "cancelled" ? 2 : 1;

function checked<T>(value: unknown): Outcome<T> {
  try {
    if (!value || typeof value !== "object") return fail("invalid request-mapping outcome");
    const envelope = value as Outcome<T>;
    const tag = envelope.outcome;
    switch (tag) {
      case "ok": return ok(envelope.value);
      case "err": {
        const { code, recoverability, message } = envelope.failure;
        if (["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            && ["transient", "permanent", "unknown"].includes(recoverability) && typeof message === "string") {
          return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
        }
        break;
      }
      case "panicked": {
        const message = envelope.message;
        if (typeof message === "string") return Object.freeze({ outcome: "panicked", message });
        break;
      }
      case "cancelled": {
        const { kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated } = envelope.cancellation;
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
  } catch { /* Never inspect exception presentation hooks. */ }
  return fail("invalid request-mapping outcome");
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const LOCKED = STREAM && Object.getOwnPropertyDescriptor(STREAM.prototype, "locked")?.get;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const READ = READER?.prototype.read, CANCEL = READER?.prototype.cancel, RELEASE = READER?.prototype.releaseLock;
const READER_CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;
const ABORT_CONTROLLER = typeof AbortController === "undefined" ? undefined : AbortController;
const ABORT = ABORT_CONTROLLER?.prototype.abort;

/**
 * Map records to request descriptors (null skips a record), in input order.
 * No fetch is admitted here. Pass the returned owner directly to streamMapFetches.
 * One native input read/async mapper is active at a time, only on output demand.
 * Cancellation fences output and signals the mapper immediately, then joins its
 * settlement, native input cancellation, owner cancellation and owner.closed.
 * A late mapper panic is not hidden by cancellation; its returned request is
 * never emitted after a stop. Already-delivered requests are not rolled back.
 *
 * Source ownership transfers only on successful setup. A raw stream has no
 * independent producer join; use an owned source to cover hidden producer work.
 * Mapper/source promises must cooperate and must not await this owner's own
 * closed/cancel barrier. No timer, runtime task or additional authority is added.
 * Request descriptors are forwarded by identity without probing their bodies;
 * downstream scope admission remains responsible for request validation. Discarded
 * records and unadmitted upload bodies remain the mapper/producer's responsibility.
 */
export function mapFetchRequests<T>(source: Input<T>, mapper: FetchRequestMapper<T, Request>,
  options: FetchRequestMapOptions = {}): Outcome<FetchBatchRequestSource> {
  return mapRequests(source, mapper, options, false);
}

/** Like mapFetchRequests, but explicit non-ok consumer Outcomes stop the stage.
 * Invalid envelopes become internal_failure; actual exceptions remain sanitized
 * panics. Successful null skips an input. Failure aggregation is monotone:
 * panicked > cancelled > err, preserving the first cause at equal severity.
 */
export function tryMapFetchRequests<T>(source: Input<T>, mapper: FetchRequestMapper<T, Outcome<Request>>,
  options: FetchRequestMapOptions = {}): Outcome<FetchBatchRequestSource> {
  return mapRequests(source, mapper, options, true);
}

/**
 * Expand each input into a bounded array of requests, preserving input/array order.
 * Snapshot and validate the entire descriptor list before emitting any member;
 * never inspect request fields or use a caller-provided iterator. Empty arrays
 * skip an input. Pull no further input until every current descriptor is emitted.
 * Cancellation discards unadmitted descriptors without acquiring their bodies.
 * Shares mapFetchRequests' mapper/producer join and non-rollback boundaries.
 */
export function flatMapFetchRequests<T>(source: Input<T>,
  mapper: FetchRequestMapper<T, readonly BrowserFetchOptions[]>,
  options: FetchRequestFlatMapOptions = {}): Outcome<FetchBatchRequestSource> {
  return mapRequests(source, mapper, options, false, true);
}

/** Typed-Outcome variant of flatMapFetchRequests; successful empty arrays skip. */
export function tryFlatMapFetchRequests<T>(source: Input<T>,
  mapper: FetchRequestMapper<T, Outcome<readonly BrowserFetchOptions[]>>,
  options: FetchRequestFlatMapOptions = {}): Outcome<FetchBatchRequestSource> {
  return mapRequests(source, mapper, options, true, true);
}

function mapRequests<T>(source: Input<T>, mapper: FetchRequestMapper<T, unknown>,
  options: FetchRequestFlatMapOptions, typed: boolean, expand = false): Outcome<FetchBatchRequestSource> {
  if (!STREAM || !LOCKED || !GET_READER || !READ || !CANCEL || !RELEASE || !READER_CLOSED || !ABORT_CONTROLLER || !ABORT) {
    return fail("request mapping requires native stream readers and AbortController", "compatibility_rejected");
  }
  let input: ReadableStream<T>;
  let owner: FetchRequestMapSource<T> | undefined;
  let ownerCancel: FetchRequestMapSource<T>["cancel"] | undefined;
  let ownerClosed: Promise<Outcome<void>> | undefined;
  let maxInputs: number, maxExpansion: number;
  try {
    maxInputs = options.maxInputs ?? 100_000;
    if (!Number.isSafeInteger(maxInputs) || maxInputs < 1 || typeof mapper !== "function") {
      return fail("request mapping requires a mapper and a positive safe maxInputs", "compatibility_rejected");
    }
    maxExpansion = expand ? options.maxRequestsPerInput ?? 64 : 1;
    if (!Number.isSafeInteger(maxExpansion) || maxExpansion < 1 || maxExpansion > 1024) {
      return fail("maxRequestsPerInput must be an integer in 1..1024", "compatibility_rejected");
    }
    let native = false;
    try { Reflect.apply(LOCKED, source, []); native = true; } catch { /* Try the explicit owner form. */ }
    if (native) input = source as ReadableStream<T>;
    else {
      owner = source as FetchRequestMapSource<T>;
      input = owner.readable;
      ownerCancel = owner.cancel;
      const receipt = owner.closed;
      if (typeof ownerCancel !== "function" || !receipt) throw new Error("invalid source owner");
      ownerClosed = Promise.resolve(receipt).then(value => checked<void>(value), () => fail("request source completion rejected"));
    }
    if (Reflect.apply(LOCKED, input, [])) throw new Error("source already locked");
  } catch { return fail("invalid or locked request mapping source", "compatibility_rejected"); }

  const completion = deferred<Outcome<void>>();
  const control = new ABORT_CONTROLLER();
  const ownedErrors = new WeakMap<object, Failure>();
  let reader: ReadableStreamDefaultReader<T>;
  let controller!: ReadableStreamDefaultController<BrowserFetchOptions>;
  let stopped: Failure | undefined, ended = false, ending = false, inputFault = false;
  let inputFailure: Failure | undefined;
  let active: Promise<void> | undefined;
  let retirement: Promise<void> | undefined;
  let finalizing = false, index = 0, consumerCancelled = false;
  let requests: BrowserFetchOptions[] = [], nextRequest = 0;

  function note(outcome: Failure): void {
    if (!stopped || severity(outcome) > severity(stopped)) stopped = outcome;
  }
  function error(outcome: Failure): Error {
    const result = Object.defineProperty(new Error("owned request mapping stopped"), "cause", { value: outcome });
    ownedErrors.set(result, outcome);
    return result;
  }
  function noteReceipt(outcome: Outcome<void>, expectedCancel: boolean): void {
    if (outcome.outcome !== "ok" && (outcome.outcome !== "cancelled" || !expectedCancel)) note(outcome);
  }
  function noteSource(outcome: Outcome<void>): void {
    // A native read rejection is only a provisional diagnosis. Replace THAT
    // fallback with its checked producer receipt, not a different owner/mapper
    // cause selected meanwhile. Never trust the native exception's .cause.
    if (inputFailure && stopped === inputFailure && outcome.outcome !== "ok") stopped = outcome;
    else noteReceipt(outcome, !!retirement && !inputFault);
  }
  function finalize(): void {
    if (finalizing) return;
    finalizing = true;
    // Never await this finalizer from an active read/mapper: cancellation of a
    // native stream does not itself wait for its pending pull computation.
    void (async () => {
      await active;
      if (ownerClosed) noteSource(await ownerClosed);
      if (retirement) await retirement;
      ended = true;
      try { Reflect.apply(RELEASE!, reader, []); } catch { /* Already released. */ }
      const outcome = stopped ?? ok(undefined);
      if (!consumerCancelled) {
        try { if (outcome.outcome === "ok") controller.close(); else controller.error(error(outcome)); }
        catch { /* Native cancellation may already have closed output. */ }
      }
      completion.resolve(outcome);
    })();
  }
  function stop(outcome: Failure): Promise<Outcome<void>> {
    if (ended) return completion.promise;
    note(outcome);
    ending = true; // Fence before any mapper/producer callback can re-enter.
    requests = []; nextRequest = 0;
    if (!retirement) {
      // Install before invoking callbacks, which may re-enter cancel().
      retirement = Promise.all([
        Promise.resolve().then(() => Reflect.apply(CANCEL!, reader, ["fetch request mapping stopped"]))
          .then(() => undefined, () => { note(fail("request input cancellation rejected")); }),
        ownerCancel ? Promise.resolve().then(() => Reflect.apply(ownerCancel!, owner, ["fetch request mapping stopped"]))
          .then(value => { noteReceipt(checked<void>(value), true); }, () => { note(fail("request source cancellation rejected")); }) : undefined,
      ]).then(() => undefined);
      finalize();
      try { Reflect.apply(ABORT!, control, [error(stopped!)]); } catch { /* Still join owned work. */ }
    }
    return completion.promise;
  }
  function sourceFault(): void {
    if (ending || ended) return;
    inputFault = true;
    inputFailure = fail("request mapping input failed");
    void stop(inputFailure);
  }
  function pull(): Promise<void> | undefined {
    if (ending || ended) return;
    const done = deferred<void>();
    active = done.promise; // Install before invoking even a synchronous mapper.
    void (async () => {
      while (!ending && !ended) {
        if (nextRequest < requests.length) {
          const request = requests[nextRequest];
          requests[nextRequest++] = undefined as unknown as BrowserFetchOptions;
          if (nextRequest === requests.length) { requests = []; nextRequest = 0; }
          controller.enqueue(request);
          return;
        }
        let item: ReadableStreamReadResult<T>;
        try { item = await Reflect.apply(READ!, reader, []); }
        catch { sourceFault(); return; }
        if (ending || ended) return;
        if (item.done) { ending = true; finalize(); return; }
        if (index === maxInputs) { void stop(fail("request mapping maxInputs exceeded", "compatibility_rejected")); return; }
        let value: unknown;
        try {
          value = await mapper(item.value, index++, control.signal);
          if (typed) {
            const outcome = checked<unknown>(value);
            if (outcome.outcome !== "ok") { void stop(outcome); return; }
            value = outcome.value;
          }
        } catch (thrown) {
          const own = thrown && (typeof thrown === "object" || typeof thrown === "function") ? ownedErrors.get(thrown) : undefined;
          void stop(own ?? panic()); return;
        }
        if (ending || ended) return;
        if (expand) {
          try {
            if (!Array.isArray(value)) throw new Error("not an array");
            const count = value.length;
            if (ending || ended) return;
            if (!Number.isSafeInteger(count) || count < 0 || count > maxExpansion) throw new Error("expansion limit");
            const snapshot: BrowserFetchOptions[] = [];
            for (let n = 0; n < count; n++) {
              const request: unknown = value[n];
              if (ending || ended) return;
              if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("not a request");
              snapshot.push(request as BrowserFetchOptions);
            }
            // Indexed accessors may re-enter cancellation. Never install or
            // publish their results after that ownership fence.
            if (ending || ended) return;
            requests = snapshot; nextRequest = 0;
          } catch {
            void stop(fail("request expansion requires a bounded array of request objects", "compatibility_rejected")); return;
          }
          continue;
        }
        if (value === null) continue;
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          void stop(fail("request mapper must return a request object or null", "compatibility_rejected")); return;
        }
        controller.enqueue(value as BrowserFetchOptions);
        return;
      }
    })().catch(() => { void stop(fail("request mapping driver failed")); }).finally(() => {
      active = undefined;
      done.resolve();
    });
    return done.promise;
  }
  try {
    const readable = new STREAM<BrowserFetchOptions>({
      start(value) { controller = value; }, pull,
      async cancel() {
        consumerCancelled = true;
        const outcome = await stop(cancelled("request mapping output cancelled"));
        if (outcome.outcome === "err" || outcome.outcome === "panicked") throw error(outcome);
      },
    }, { highWaterMark: 0 });
    reader = Reflect.apply(GET_READER, input, []) as ReadableStreamDefaultReader<T>;
    void Promise.resolve(Reflect.apply(READER_CLOSED, reader, [])).catch(sourceFault);
    if (ownerClosed) void ownerClosed.then(outcome => {
      if (ended || outcome.outcome === "ok") return;
      if (outcome.outcome === "cancelled" && retirement && !inputFault) return;
      noteSource(outcome);
      void stop(outcome);
    });
    return ok(Object.freeze({ readable, closed: completion.promise, cancel(reason = "request mapping cancelled by caller") {
      return typeof reason === "string" ? stop(cancelled(reason))
        : Promise.resolve(fail("request mapping cancellation reason must be a string", "compatibility_rejected"));
    } }));
  } catch {
    // No source read/mapper has run: native HWM=0 construction does not pull.
    try { if (reader!) Reflect.apply(RELEASE, reader, []); } catch { /* No owned lock. */ }
    return fail("request mapping setup refused", "compatibility_rejected");
  }
}
