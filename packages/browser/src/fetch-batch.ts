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
  /** Parent cancellation; null is omission. The batch still joins all admitted work. */
  signal?: AbortSignal | null;
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
const severity = (outcome: Failure): number => outcome.outcome === "panicked" ? 3 : outcome.outcome === "cancelled" ? 2 : 1;
function streamError(outcome: Failure): Error {
  return Object.defineProperty(new Error("owned fetch batch stopped"), "cause", { value: outcome });
}
/** Copy a scope- or handle-supplied Outcome; a malformed envelope fails closed. */
function checked<T>(value: unknown): Outcome<T> {
  try {
    if (!value || typeof value !== "object") return failure("invalid fetch batch outcome", "internal_failure");
    const outcome = value as Outcome<T>;
    switch (outcome.outcome) {
      case "ok": return ok(outcome.value);
      case "err": {
        const { code, recoverability, message } = outcome.failure;
        if (["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            && ["transient", "permanent", "unknown"].includes(recoverability) && typeof message === "string") {
          return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
        }
        break;
      }
      case "panicked":
        if (typeof outcome.message === "string") return Object.freeze({ outcome: "panicked", message: outcome.message });
        break;
      case "cancelled": {
        const { kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated } = outcome.cancellation;
        if (typeof kind === "string" && ["requested", "cancelling", "finalizing", "completed"].includes(phase)
            && typeof origin_region === "string" && (origin_task === null || typeof origin_task === "string")
            && (typeof timestamp_nanos === "bigint" || typeof timestamp_nanos === "number" && Number.isFinite(timestamp_nanos))
            && (message === null || typeof message === "string") && typeof truncated === "boolean") {
          return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
            kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated,
          }) });
        }
        break;
      }
    }
  } catch { /* Malformed envelopes fail closed. */ }
  return failure("invalid fetch batch outcome", "internal_failure");
}
function thenable(value: unknown): boolean {
  return (typeof value === "object" && value !== null || typeof value === "function")
    && typeof (value as { then?: unknown }).then === "function";
}
/** A handle's terminal Outcome, checked; a rejected or malformed publication is a failure. */
function closedOf(fetch: FetchStreamHandle): Promise<Outcome<void>> {
  return Promise.resolve(fetch.closed).then((value) => checked<void>(value),
    () => failure("fetch batch terminal publication rejected", "internal_failure"));
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
const SIGNAL = typeof AbortSignal === "undefined" ? undefined : AbortSignal;
const ANY_SIGNAL = SIGNAL?.any;
const ABORTED = SIGNAL && Object.getOwnPropertyDescriptor(SIGNAL.prototype, "aborted")?.get;
const EVENT_TARGET = typeof EventTarget === "undefined" ? undefined : EventTarget;
const ADD_LISTENER = EVENT_TARGET?.prototype.addEventListener;
const REMOVE_LISTENER = EVENT_TARGET?.prototype.removeEventListener;

interface Member {
  index: number;
  ready: ReturnType<typeof deferred<void>>;
  /** What a refused promise-returning scope admits, retired by drain. */
  adopted?: Promise<Outcome<FetchStreamHandle>>;
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
 * cancels siblings in parallel. Until settlement, stronger failures replace
 * weaker ones: panicked > cancelled > err. Expected member cancellation during
 * cleanup is not a new owner failure. Genuine consumer exceptions remain panics;
 * rethrowing this batch's own body/signal error preserves its original Outcome.
 * cancel() also waits for consumer promises; consumers
 * that park outside the body must observe their signal to stop cooperatively.
 * No force-drain guarantee exists for nonsettling host or consumer promises.
 *
 * An optional parent signal uses the same admission fence and drain as cancel().
 * A pre-aborted signal starts no requests; empty input remains a successful
 * identity. Supply an unmodified same-realm native AbortSignal. Signal use
 * requires native AbortSignal.any: a private dependent signal prevents earlier
 * caller listeners from suppressing cancellation. Its arbitrary reason is not
 * inspected or included in diagnostics. The observer is removed at settlement;
 * aborting afterward cannot reclaim returned values or mutate the parent signal.
 * Callers may supply AbortSignal.timeout for deadlines; this function creates
 * no timer. Unsignalled calls retain their existing host requirements.
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
  let signal: AbortSignal | undefined;
  try {
    if (!Array.isArray(requests)) return failure("fetch batch requests must be an array");
    const count = requests.length;
    if (!Number.isSafeInteger(count) || count < 0 || count > FETCH_BATCH_LIMITS.maxRequests) return failure("fetch batch requires at most maxRequests requests");
    concurrency = options.concurrency === undefined ? 4 : options.concurrency;
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) return failure("fetch batch concurrency must be an integer in 1..64");
    if (typeof consume !== "function") return failure("fetch batch requires a consumer function");
    const suppliedSignal = options.signal;
    if (suppliedSignal != null) {
      if (!SIGNAL || !ANY_SIGNAL || !ABORTED || !ADD_LISTENER || !REMOVE_LISTENER) {
        return failure("fetch batch signals require native AbortSignal.any and EventTarget");
      }
      // Match the fetch/selection/group boundary. Native any() can inspect
      // public accessors, so reject customized signals before invoking it.
      if (Object.getPrototypeOf(suppliedSignal) !== SIGNAL.prototype
          || Object.getOwnPropertyDescriptor(suppliedSignal, "aborted")
          || Object.getOwnPropertyDescriptor(suppliedSignal, "reason")) {
        return failure("fetch batches require an unmodified same-realm native signal");
      }
      Reflect.apply(ABORTED, suppliedSignal, []);
      signal = Reflect.apply(ANY_SIGNAL, SIGNAL, [[suppliedSignal]]) as AbortSignal;
      Reflect.apply(ABORTED, signal, []);
    }
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
  // Recognize only errors created by THIS batch. Reading arbitrary .cause
  // properties would let a consumer forge a cancellation or run a getter.
  const ownedFailures = new WeakMap<object, Failure>();

  function ownedError(outcome: Failure): Error {
    const error = streamError(outcome);
    ownedFailures.set(error, outcome);
    return error;
  }

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
      if (member.adopted) {
        const adopted = await member.adopted;
        if (adopted.outcome === "ok") { member.fetch = adopted.value; member.closed = closedOf(adopted.value); }
        else noteCleanup(member.index, adopted);
      }
      let refusal: Failure | undefined;
      try {
        if (member.reader) await Reflect.apply(CANCEL!, member.reader, ["fetch batch member retired"]);
        else if (member.fetch) {
          const receipt = checked<void>(await member.fetch.cancel("fetch batch member retired"));
          if (receipt.outcome === "err" || receipt.outcome === "panicked") refusal = receipt;
        }
      } catch { refusal = failure("fetch batch cancellation or terminal publication refused", "internal_failure"); }
      let terminal: Outcome<void>;
      try { terminal = member.closed ? await member.closed : ok(undefined); }
      catch { terminal = failure("fetch batch terminal publication rejected", "internal_failure"); }
      // Successful cancellation normally produces a cancelled terminal. Only
      // treat that receipt as a cleanup failure when cancellation was refused.
      const terminalFailure = terminal.outcome === "err" || terminal.outcome === "panicked"
        || terminal.outcome === "cancelled" && refusal ? terminal : undefined;
      const outcome = terminalFailure && (!refusal || severity(terminalFailure) >= severity(refusal))
        ? terminalFailure : refusal ?? ok(undefined);
      if (outcome.outcome !== "ok") noteCleanup(member.index, outcome);
      member.ended = true;
      if (member.bodyController) {
        try {
          const cause = stopped ?? (outcome.outcome !== "ok" ? outcome : undefined);
          if (cause) member.bodyController.error(ownedError(cause));
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
    if (finished) return;
    if (stopped) {
      // The admission fence and notifications are one-shot, but the final
      // Outcome must still incorporate failures observed during cleanup.
      if (severity(outcome) > severity(stopped)) stopped = outcome;
      return;
    }
    stopped = outcome; // Admission fence precedes every host/user callback.
    results.fill(undefined as T);
    for (const member of members) {
      void drain(member);
      try { Reflect.apply(ABORT!, member.controller, [ownedError(outcome)]); } catch { /* Preserve first cause. */ }
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
        if (outcome.outcome !== "ok") throw ownedError(outcome);
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
          const raw: unknown = Reflect.apply(start, scope, [inputs[index]]);
          inputs[index] = undefined as unknown as BrowserFetchOptions;
          if (thenable(raw)) {
            // A later handle would bypass the admission fence. Refuse it, but
            // keep ownership: drain retires whatever the promise admits.
            member.adopted = Promise.resolve(raw).then((value) => checked<FetchStreamHandle>(value),
              () => failure("fetch batch scope admission rejected", "internal_failure"));
            stop(failure("fetch batch scope must return its admission Outcome synchronously"));
            continue;
          }
          const admitted = checked<FetchStreamHandle>(raw);
          if (admitted.outcome !== "ok") { stop(admitted); continue; }
          member.fetch = admitted.value;
          member.closed = closedOf(member.fetch);
          void member.closed.then((terminal) => {
            if (!member.retiring && terminal.outcome !== "ok") stop(terminal);
          });
          const converted = checked<ReadableStream<Uint8Array>>(member.fetch.toReadableStream());
          if (converted.outcome !== "ok") { stop(converted); continue; }
          member.reader = Reflect.apply(GET_READER!, converted.value, []) as ReadableStreamDefaultReader<Uint8Array>;
          void Promise.resolve(Reflect.apply(READER_CLOSED!, member.reader, [])).catch(() => {});
        } finally { member.ready.resolve(); }
        if (stopped) continue;
        const head = checked<BrowserFetchResponse>(await member.fetch!.response());
        if (stopped) continue;
        if (head.outcome !== "ok") { stop(head); continue; }
        const item = Object.freeze({ index, response: head.value, body: body(member), signal: member.controller.signal });
        try { value = await consume(item); consumed = true; }
        catch (error) {
          const owned = error && (typeof error === "object" || typeof error === "function")
            ? ownedFailures.get(error) : undefined;
          stop(owned ?? panic());
        }
      } catch { stop(failure("fetch batch admission or response failed", "internal_failure")); }
      finally {
        member.ready.resolve();
        await drain(member);
        members.delete(member);
      }
      if (!stopped && consumed) results[index] = value;
    }
  }
  const onAbort = () => stop(cancelled("fetch batch cancelled by signal"));
  function detachSignal(): void {
    if (!signal) return;
    try { Reflect.apply(REMOVE_LISTENER!, signal, ["abort", onAbort]); } catch { /* Do not prevent settlement. */ }
    signal = undefined;
  }
  if (signal) {
    try {
      Reflect.apply(ADD_LISTENER!, signal, ["abort", onAbort, { once: true }]);
      // Also catches a signal aborted while validating or snapshotting inputs.
      if (Reflect.apply(ABORTED!, signal, [])) onAbort();
    } catch {
      detachSignal();
      return failure("fetch batch signal observation refused");
    }
  }
  // Return the cancellation handle before executing user scope admission.
  void Promise.resolve().then(async () => {
    try { await Promise.all(Array.from({ length: Math.min(concurrency, inputs.length) }, () => worker().catch(() => {
      stop(failure("fetch batch worker failed", "internal_failure"));
    }))); }
    catch { stop(failure("fetch batch driver failed", "internal_failure")); await Promise.all([...members].map(drain)); }
    finished = true;
    detachSignal();
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
