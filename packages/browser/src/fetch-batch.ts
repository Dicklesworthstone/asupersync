/** Bounded request admission and processing under an existing SDK scope. */
import type { Outcome } from "@asupersync/browser-core";
import { BROWSER_FETCH_LIMITS, type BrowserFetchOptions, type BrowserFetchResponse, type FetchStreamHandle } from "./fetch.js";

export const FETCH_BATCH_LIMITS = Object.freeze({ maxConcurrency: 64, maxRequests: 100_000 });

/** Structurally implemented by the SDK Scope; never an ambient fetch function. */
export interface FetchBatchScope {
  fetch(options: BrowserFetchOptions): Outcome<FetchStreamHandle>;
}

export interface FetchBatchResponse {
  readonly index: number;
  readonly response: BrowserFetchResponse;
  /** Exclusive remaining body. Do not retain it after the consumer settles. */
  readonly body: ReadableStream<Uint8Array>;
  /** Batch stop notification for cooperative consumer work, not new authority. */
  readonly signal: AbortSignal;
}

export interface FetchBatchOptions {
  /** Active requests INCLUDING consumer work and cleanup. Default 4; 1..64. */
  concurrency?: number;
}

export interface FetchBatch<T> {
  /** Input-ordered results, only after every admitted request and consumer drains. */
  readonly result: Promise<Outcome<readonly T[]>>;
  /** Fences queued admission synchronously and joins active work. Idempotent. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const failure = (message: string, code: "compatibility_rejected" | "internal_failure" = "compatibility_rejected"): Failure =>
  Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability: "permanent", message }) });
const panic = (): Failure => Object.freeze({ outcome: "panicked", message: "fetch batch consumer threw or rejected" });
const cancelled = (reason: string): Failure => Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
  kind: "fetch_batch_cancel", phase: "completed", origin_region: "browser-fetch-batch", origin_task: null,
  timestamp_nanos: 0, message: reason, truncated: false,
}) });
const severity = (outcome: Failure): number => outcome.outcome === "panicked" ? 3 : outcome.outcome === "err" ? 2 : 1;
function streamError(outcome: Failure): Error {
  return Object.defineProperty(new Error("owned fetch batch stopped"), "cause", { value: outcome });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const READ = READER?.prototype.read, CANCEL = READER?.prototype.cancel, RELEASE = READER?.prototype.releaseLock;
const READER_CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;
const CONTROLLER = typeof AbortController === "undefined" ? undefined : AbortController;
const ABORT = CONTROLLER?.prototype.abort;

interface Member {
  index: number;
  ready: ReturnType<typeof deferred<void>>;
  fetch?: FetchStreamHandle;
  closed?: Promise<Outcome<void>>;
  reader?: ReadableStreamDefaultReader<Uint8Array>;
  controller: AbortController;
  bodyController?: ReadableStreamDefaultController<Uint8Array>;
  ended: boolean;
  retiring: boolean;
  drained?: Promise<Outcome<void>>;
}

/**
 * Start at most concurrency requests through an explicit SDK Scope. Invoke
 * consume after each header arrives; keep its slot until the consumer settles
 * AND the request's body/host cleanup and task publication settle. Results are
 * input-ordered. Returning early from consume cancels unread bytes. HTTP error
 * statuses are responses; throw from consume to reject application-level errors.
 *
 * First observed admission, transport or consumer failure fences new work and
 * cancels siblings in parallel. Cleanup errors remain visible and cleanup panic
 * outranks ordinary failure. cancel() also waits for consumer promises; consumers
 * that park outside the body must observe their signal to stop cooperatively.
 * No force-drain guarantee exists for nonsettling host or consumer promises.
 *
 * The request array is snapshotted; option objects/bodies are read only when
 * admitted and must not be mutated while queued. Unstarted bodies remain with
 * the caller. The caller owns returned values and their memory; only request
 * count, active work and each underlying fetch's buffers are bounded here.
 * No retries, additional runtime task, timer, or fetch authority are created.
 */
export function mapFetches<T>(scope: FetchBatchScope, requests: readonly BrowserFetchOptions[],
  consume: (response: FetchBatchResponse) => T | PromiseLike<T>, options: FetchBatchOptions = {}): Outcome<FetchBatch<T>> {
  let inputs: BrowserFetchOptions[];
  let start: FetchBatchScope["fetch"];
  let concurrency: number;
  try {
    if (!Array.isArray(requests)) return failure("fetch batch requests must be an array");
    const count = requests.length;
    if (!Number.isSafeInteger(count) || count < 0 || count > FETCH_BATCH_LIMITS.maxRequests) return failure("fetch batch requires at most maxRequests requests");
    concurrency = options.concurrency === undefined ? 4 : options.concurrency;
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) return failure("fetch batch concurrency must be an integer in 1..64");
    if (typeof consume !== "function") return failure("fetch batch requires a consumer function");
    start = scope.fetch;
    if (typeof start !== "function") return failure("fetch batch requires an explicit fetch scope");
    inputs = [];
    for (let index = 0; index < count; index += 1) inputs.push(requests[index]);
    if (inputs.length && (!STREAM || !GET_READER || !READ || !CANCEL || !RELEASE || !READER_CLOSED || !CONTROLLER || !ABORT)) {
      return failure("fetch batch requires native stream readers and AbortController");
    }
  } catch { return failure("invalid fetch batch configuration"); }

  if (!inputs.length) {
    const result = Promise.resolve(ok(Object.freeze([]) as readonly T[]));
    const settled = Promise.resolve(ok(undefined));
    return ok(Object.freeze({ result, cancel(reason = "fetch batch cancelled by caller") {
      return typeof reason === "string" ? settled : Promise.resolve(failure("fetch batch cancellation reason must be a string"));
    } }));
  }
  const completion = deferred<Outcome<readonly T[]>>();
  const settlement = completion.promise.then((outcome): Outcome<void> => outcome.outcome === "ok" ? ok(undefined) : outcome);
  const members = new Set<Member>();
  const results: T[] = new Array(inputs.length);
  let next = 0, stopped: Failure | undefined, finished = false;
  let cleanupFailure: { index: number; outcome: Failure } | undefined;

  function noteCleanup(index: number, outcome: Failure): void {
    if (!cleanupFailure || severity(outcome) > severity(cleanupFailure.outcome)
        || severity(outcome) === severity(cleanupFailure.outcome) && index < cleanupFailure.index) {
      cleanupFailure = { index, outcome };
    }
    stop(outcome);
  }
  function drain(member: Member): Promise<Outcome<void>> {
    if (member.drained) return member.drained;
    const done = deferred<Outcome<void>>();
    member.drained = done.promise;
    member.retiring = true;
    // Defer host callbacks until ownership is installed, including when scope
    // admission synchronously reenters cancel before returning its fetch.
    void (async () => {
      await member.ready.promise;
      let refused = false;
      try {
        if (member.reader) await Reflect.apply(CANCEL!, member.reader, ["fetch batch member retired"]);
        else if (member.fetch) {
          const receipt = await member.fetch.cancel("fetch batch member retired");
          refused = receipt.outcome === "err" || receipt.outcome === "panicked";
        }
      } catch { refused = true; }
      let terminal: Outcome<void>;
      try { terminal = member.closed ? await member.closed : ok(undefined); }
      catch { terminal = failure("fetch batch terminal publication rejected", "internal_failure"); }
      const outcome = terminal.outcome === "err" || terminal.outcome === "panicked" ? terminal
        : refused ? failure("fetch batch cancellation or terminal publication refused", "internal_failure") : ok(undefined);
      if (outcome.outcome !== "ok") noteCleanup(member.index, outcome);
      member.ended = true;
      if (member.bodyController) {
        try {
          const cause = stopped ?? (outcome.outcome !== "ok" ? outcome : undefined);
          if (cause) member.bodyController.error(streamError(cause));
          else member.bodyController.close();
        } catch { /* Consumer cancellation may already have closed the stream. */ }
      }
      try { if (member.reader) Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ }
      done.resolve(outcome);
    })().catch(() => {
      const outcome = failure("fetch batch cleanup threw", "internal_failure");
      noteCleanup(member.index, outcome);
      done.resolve(outcome);
    });
    return done.promise;
  }
  function stop(outcome: Failure): void {
    if (finished || stopped) return;
    stopped = outcome; // Admission fence precedes every host/user callback.
    results.fill(undefined as T);
    for (const member of members) {
      void drain(member);
      try { Reflect.apply(ABORT!, member.controller, [streamError(outcome)]); } catch { /* Preserve first cause. */ }
    }
  }
  function body(member: Member): ReadableStream<Uint8Array> {
    return new STREAM!<Uint8Array>({
      start(controller) { member.bodyController = controller; },
      async pull(controller) {
        if (member.ended || member.retiring) { await drain(member); return; }
        try {
          const value = await Reflect.apply(READ!, member.reader!, []) as ReadableStreamReadResult<Uint8Array>;
          if (member.ended || member.retiring) { await drain(member); return; }
          if (value.done) { member.ended = true; controller.close(); }
          else controller.enqueue(value.value);
        } catch {
          const outcome = member.closed ? await member.closed : failure("fetch batch body read failed", "internal_failure");
          stop(outcome.outcome === "ok" ? failure("fetch batch body read rejected", "internal_failure") : outcome);
          await drain(member);
        }
      },
      async cancel() {
        member.ended = true;
        const outcome = await drain(member);
        if (outcome.outcome !== "ok") throw streamError(outcome);
      },
    }, { highWaterMark: 0 });
  }
  async function worker(): Promise<void> {
    while (!stopped && next < inputs.length) {
      const index = next++;
      const member: Member = { index, ready: deferred<void>(), controller: new CONTROLLER!(), ended: false, retiring: false };
      members.add(member);
      let value!: T, consumed = false;
      try {
        try {
          const admitted = Reflect.apply(start, scope, [inputs[index]]) as Outcome<FetchStreamHandle>;
          inputs[index] = undefined as unknown as BrowserFetchOptions;
          if (admitted.outcome !== "ok") { stop(admitted); continue; }
          member.fetch = admitted.value;
          member.closed = Promise.resolve(member.fetch.closed);
          void member.closed.then((terminal) => {
            if (!member.retiring && terminal.outcome !== "ok") stop(terminal);
          }, () => stop(failure("fetch batch terminal publication rejected", "internal_failure")));
          const converted = member.fetch.toReadableStream();
          if (converted.outcome !== "ok") { stop(converted); continue; }
          member.reader = Reflect.apply(GET_READER!, converted.value, []) as ReadableStreamDefaultReader<Uint8Array>;
          void Promise.resolve(Reflect.apply(READER_CLOSED!, member.reader, [])).catch(() => {});
        } finally { member.ready.resolve(); }
        if (stopped) continue;
        const head = await member.fetch!.response();
        if (stopped) continue;
        if (head.outcome !== "ok") { stop(head); continue; }
        const item = Object.freeze({ index, response: head.value, body: body(member), signal: member.controller.signal });
        try { value = await consume(item); consumed = true; }
        catch { stop(panic()); }
      } catch { stop(failure("fetch batch admission or response failed", "internal_failure")); }
      finally {
        member.ready.resolve();
        await drain(member);
        members.delete(member);
      }
      if (!stopped && consumed) results[index] = value;
    }
  }
  // Return the cancellation handle before executing user scope admission.
  void Promise.resolve().then(async () => {
    try { await Promise.all(Array.from({ length: Math.min(concurrency, inputs.length) }, () => worker().catch(() => {
      stop(failure("fetch batch worker failed", "internal_failure"));
    }))); }
    catch { stop(failure("fetch batch driver failed", "internal_failure")); await Promise.all([...members].map(drain)); }
    finished = true;
    inputs.length = 0;
    const cleanup = cleanupFailure?.outcome;
    const outcome = cleanup && (!stopped || severity(cleanup) >= severity(stopped)) ? cleanup : stopped;
    completion.resolve(outcome ?? ok(Object.freeze(results)));
  });
  return ok(Object.freeze({ result: completion.promise, cancel(reason = "fetch batch cancelled by caller") {
    if (typeof reason !== "string") return Promise.resolve(failure("fetch batch cancellation reason must be a string"));
    stop(cancelled(reason));
    return settlement;
  } }));
}
