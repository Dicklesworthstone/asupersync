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

/** An owned producer with a cleanup receipt independent of native stream EOF. */
export interface FetchBatchRequestSource {
  readonly readable: ReadableStream<BrowserFetchOptions>;
  /** Settles after all producer-owned work retires, including on cancellation. */
  readonly closed: Promise<Outcome<void>>;
  /** Idempotent; must work while readable is locked by the batch. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

/** Array snapshots, native request streams, or explicitly owned producers. */
export type FetchBatchRequests = readonly BrowserFetchOptions[] | ReadableStream<BrowserFetchOptions> | FetchBatchRequestSource;

export interface FetchBatchStreamOptions extends FetchBatchOptions {
  /** Stream-input admission limit; default 100,000. Arrays retain their fixed cap. */
  maxRequests?: number;
}

export interface FetchBatch<T> {
  /** Input-ordered results, only after every admitted request and consumer drains. */
  readonly result: Promise<Outcome<readonly T[]>>;
  /** Fences queued admission synchronously and joins active work. Idempotent. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

/** A completed, cleaned-up member; index still identifies its input request. */
export interface FetchBatchResult<T> {
  readonly index: number;
  readonly value: T;
}

export interface FetchBatchStream<T> {
  /** Completion-ordered results with backpressure, not an all-or-nothing array. */
  readonly results: ReadableStream<FetchBatchResult<T>>;
  /** Full consumer/cleanup barrier; consume results or cancel to reach it. */
  readonly closed: Promise<Outcome<void>>;
  /** Also releases workers waiting to deliver unread results. Idempotent. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

/** Private delivery seam: waiting to publish retains the worker's admission slot. */
interface BatchDelivery<T> {
  publish(index: number, value: T): Promise<void>;
  stop(): void;
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
/** Copy a supplied Outcome; a malformed envelope fails closed. */
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
      case "panicked": {
        const message = outcome.message;
        if (typeof message === "string") return Object.freeze({ outcome: "panicked", message });
        break;
      }
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
const STREAM_LOCKED = STREAM && Object.getOwnPropertyDescriptor(STREAM.prototype, "locked")?.get;
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
  retire?: () => unknown;
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
 * statuses are responses. Use tryMapFetches for typed application failures;
 * throwing from consume remains a panic, not an ordinary error.
 *
 * First observed admission, transport or consumer failure fences new work and
 * cancels siblings in parallel. Until settlement, stronger failures replace
 * weaker ones: panicked > cancelled > err. Expected member cancellation during
 * cleanup is not a new owner failure. Genuine consumer exceptions remain panics;
 * rethrowing this batch's own body/signal error preserves its original Outcome.
 * cancel() also waits for consumer promises; consumers
 * that park outside the body must observe their signal to stop cooperatively.
 * No force-drain guarantee exists for nonsettling host or consumer promises.
 * When a handle supplies independent retire(), its checked receipt is also
 * joined before releasing the worker slot or publishing a result. Failed
 * retirement fences admission immediately, even with another consumer parked.
 * Legacy handles keep their original operation-receipt-only cleanup boundary.
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
  return runFetchBatch<T>(scope, requests, consume, options, false);
}

/**
 * Bounded fetch processing with an explicit Outcome from each consumer.
 * Successful values are unwrapped into the input-ordered result array. A returned
 * err, cancelled or panicked Outcome fences queued admission and drains every
 * active consumer, body and terminal publication before result/cancel settles.
 * Ordinary application errors therefore need not masquerade as thrown panics.
 *
 * Shares mapFetches' scope authority, concurrency, parent signal, ownership and
 * cleanup rules. Late outcomes can strengthen a stop as panicked > cancelled >
 * err; first equal-severity consumer causes and input-order cleanup ties remain.
 * Malformed consumer envelopes fail closed as internal_failure. Envelopes are
 * copied and frozen before stop callbacks, but successful values retain their
 * identity and are not deep-frozen. Throws/rejections remain sanitized panics,
 * except rethrowing this batch's own body/signal error preserves its cause.
 *
 * This is fail-fast processing with full drain, not all-settled collection or
 * rollback. Already completed remote effects cannot be undone. mapFetches stays
 * unchanged: an Outcome returned to mapFetches is an ordinary result value.
 */
export function tryMapFetches<T>(scope: FetchBatchScope, requests: readonly BrowserFetchOptions[],
  consume: (response: FetchBatchResponse) => Outcome<T> | PromiseLike<Outcome<T>>,
  options: FetchBatchOptions = {}): Outcome<FetchBatch<T>> {
  return runFetchBatch<T>(scope, requests, consume, options, true);
}

/**
 * Process a batch without retaining an array of every consumer result. Results
 * arrive in completion order as { index, value }, after that member's body and
 * terminal cleanup. A slow output reader holds admission slots: at most
 * concurrency workers wait to deliver results. The native output has a zero
 * high-water mark; one in-flight pull can still enqueue if its reader releases
 * its lock. Payload byte size and caller/downstream queues are not bounded.
 * Arrays are snapshotted (at most maxRequests entries). A native request stream
 * is acquired exclusively after validation and pulled incrementally, with one
 * pending read at a time and no separate request backlog. Each read reserves a
 * worker slot. Stream indices follow input order, not request completion order.
 * Stream inputs may exceed the array cap via options.maxRequests, a positive
 * safe integer; encountering a further request fails before admitting it.
 *
 * On stop, request-stream cancellation runs in parallel with member cleanup and
 * its initiating promise is joined before closed. A successful input close does
 * not discard queued requests; an idle input error stops the batch. Native
 * cancellation cannot join arbitrary work hidden in the input's producer. The
 * producer owns cleanup of its queue and unadmitted upload bodies, including a
 * request produced concurrently with cancellation. No such body is acquired by
 * the batch before scope admission. Input/downstream queues are outside our
 * retained-work bound. Setup refusal unlocks without reading or cancelling.
 *
 * A FetchBatchRequestSource additionally provides an independent typed closed
 * receipt and idempotent cancel method. The batch joins that receipt even after
 * native EOF, observes idle producer failures, and calls owner cancellation in
 * parallel with native cancellation on stop. Producer failure severity is not
 * inferred from arbitrary stream error.cause properties. Expected retirement
 * cancellation does not invalidate a consumer's application error. The owner's
 * contract must cover all producer work; a nonsettling receipt keeps closed
 * pending. Methods/receipt are snapshotted before input ownership is acquired.
 *
 * Drain results concurrently with closed; awaiting closed without reading a
 * nonempty result stream intentionally applies backpressure. Cancelling the
 * output (including ordinary async-iteration break or pipeTo failure) stops
 * admission and joins active work. Native stream closure on cancel is NOT that
 * barrier: await the cancellation promise or closed. A failure errors results
 * only after drain, with the final Outcome in error.cause. Already delivered
 * values/effects cannot be rolled back. Releasing a reader lock is not cancel.
 *
 * Otherwise shares mapFetches' consumer, parent-signal and ownership semantics.
 * Consume/cancel each body inside consume; do not return live body resources.
 */
export function streamMapFetches<T>(scope: FetchBatchScope, requests: FetchBatchRequests,
  consume: (response: FetchBatchResponse) => T | PromiseLike<T>,
  options: FetchBatchStreamOptions = {}): Outcome<FetchBatchStream<T>> {
  return streamFetchBatch<T>(scope, requests, consume, options, false);
}

/** streamMapFetches with tryMapFetches' checked, explicit consumer Outcomes. */
export function tryStreamMapFetches<T>(scope: FetchBatchScope, requests: FetchBatchRequests,
  consume: (response: FetchBatchResponse) => Outcome<T> | PromiseLike<Outcome<T>>,
  options: FetchBatchStreamOptions = {}): Outcome<FetchBatchStream<T>> {
  return streamFetchBatch<T>(scope, requests, consume, options, true);
}

function streamFetchBatch<T>(scope: FetchBatchScope, requests: FetchBatchRequests,
  consume: ((response: FetchBatchResponse) => T | PromiseLike<T>)
    | ((response: FetchBatchResponse) => Outcome<T> | PromiseLike<Outcome<T>>),
  options: FetchBatchStreamOptions, consumerOutcomes: boolean): Outcome<FetchBatchStream<T>> {
  if (!STREAM) return failure("streaming fetch batches require native ReadableStream");
  const queue: { item: FetchBatchResult<T>; release: () => void }[] = [];
  let controller!: ReadableStreamDefaultController<FetchBatchResult<T>>;
  let demand: ReturnType<typeof deferred<void>> | undefined;
  let stopped = false;
  let batch: FetchBatch<T>;

  function deliver(): void {
    if (stopped || !demand || !queue.length) return;
    const entry = queue.shift()!;
    const waiting = demand;
    demand = undefined;
    // Only internal native-controller operations run here, never value hooks.
    // A value is wrapped, so nested thenables are not promise-assimilated.
    controller.enqueue(entry.item);
    entry.release();
    waiting.resolve();
  }
  const delivery: BatchDelivery<T> = {
    publish(index, value) {
      const accepted = deferred<void>();
      if (stopped) accepted.resolve();
      else {
        queue.push({ item: Object.freeze({ index, value }), release: accepted.resolve });
        deliver();
      }
      return accepted.promise;
    },
    stop() {
      stopped = true;
      for (const entry of queue) entry.release();
      queue.length = 0;
      // Pending reads observe the final, fully drained Outcome, not a guess
      // made when the first error or cancellation was observed.
    },
  };
  const results = new STREAM<FetchBatchResult<T>>({
    start(value) { controller = value; },
    pull() {
      const waiting = deferred<void>();
      demand = waiting;
      deliver();
      return waiting.promise;
    },
    async cancel() {
      // Do not inspect/format arbitrary native cancellation reasons.
      const outcome = await batch.cancel("fetch batch result stream cancelled");
      if (outcome.outcome === "err" || outcome.outcome === "panicked") throw streamError(outcome);
    },
  }, { highWaterMark: 0 });
  const admitted = runFetchBatch<T>(scope, requests, consume, options, consumerOutcomes, delivery);
  if (admitted.outcome !== "ok") {
    controller.close();
    return admitted;
  }
  batch = admitted.value;
  const closed = batch.result.then((outcome): Outcome<void> => {
    delivery.stop();
    // Native cancel closes the stream before its cleanup promise settles.
    // That state must not prevent publishing the independent cleanup receipt.
    try {
      if (outcome.outcome === "ok") controller.close();
      else controller.error(streamError(outcome));
    } catch { /* Output already cancelled. */ }
    demand?.resolve();
    demand = undefined;
    return outcome.outcome === "ok" ? ok(undefined) : outcome;
  });
  return ok(Object.freeze({ results, closed, cancel: batch.cancel }));
}

function runFetchBatch<T>(scope: FetchBatchScope, requests: FetchBatchRequests,
  consume: ((response: FetchBatchResponse) => T | PromiseLike<T>)
    | ((response: FetchBatchResponse) => Outcome<T> | PromiseLike<Outcome<T>>),
  options: FetchBatchStreamOptions, consumerOutcomes: boolean, delivery?: BatchDelivery<T>): Outcome<FetchBatch<T>> {
  let inputs: BrowserFetchOptions[];
  let requestReader: ReadableStreamDefaultReader<BrowserFetchOptions> | undefined;
  let requestClosed: Promise<unknown> | undefined;
  let requestOwner: { cancel: () => unknown; closed: Promise<Outcome<void>> } | undefined;
  let sourceFault = false;
  let requestLimit: number = FETCH_BATCH_LIMITS.maxRequests;
  let requestEof = false;
  let requestTurn = Promise.resolve();
  let inputRetirement: Promise<void> | undefined;
  function releaseRequests(): void {
    if (requestReader) {
      try { Reflect.apply(RELEASE!, requestReader, []); } catch { /* Already released. */ }
    }
  }
  let start: FetchBatchScope["fetch"];
  let concurrency: number;
  let signal: AbortSignal | undefined;
  try {
    const arrayInput = Array.isArray(requests);
    if (!arrayInput && !delivery) return failure("fetch batch requests must be an array");
    const count = arrayInput ? requests.length : 0;
    if (!Number.isSafeInteger(count) || count < 0 || count > FETCH_BATCH_LIMITS.maxRequests) return failure("fetch batch requires at most maxRequests requests");
    if (!arrayInput) {
      const suppliedLimit = options.maxRequests;
      requestLimit = suppliedLimit === undefined ? FETCH_BATCH_LIMITS.maxRequests : suppliedLimit;
      if (!Number.isSafeInteger(requestLimit) || requestLimit < 1) return failure("request stream maxRequests must be a positive safe integer");
    }
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
    for (let index = 0; index < count; index += 1) inputs.push((requests as readonly BrowserFetchOptions[])[index]);
    if ((!arrayInput || inputs.length) && (!STREAM || !GET_READER || !READ || !CANCEL || !RELEASE || !READER_CLOSED || !CONTROLLER || !ABORT)) {
      return failure("fetch batch requires native stream readers and AbortController");
    }
    if (!arrayInput) {
      let readable: unknown = requests;
      try { Reflect.apply(STREAM_LOCKED!, requests, []); }
      catch {
        // Snapshot explicit owner properties before taking the native lock.
        // A raw native stream never has its user-added properties inspected.
        const owner = requests as FetchBatchRequestSource;
        const stream = owner.readable, terminal = owner.closed, cancelOwner = owner.cancel;
        if (typeof cancelOwner !== "function" || !thenable(terminal)) return failure("invalid owned fetch request source");
        readable = stream;
        requestOwner = { cancel: () => Reflect.apply(cancelOwner, owner, ["fetch batch request source retired"]),
          closed: Promise.resolve(terminal).then(value => checked<void>(value),
            () => failure("fetch batch request source terminal publication rejected", "internal_failure")) };
      }
      // The intrinsic checks the native stream brand and refuses locked input.
      // Never call an arbitrary object's getReader method during admission.
      requestReader = Reflect.apply(GET_READER!, readable, []) as ReadableStreamDefaultReader<BrowserFetchOptions>;
      requestClosed = Promise.resolve(Reflect.apply(READER_CLOSED!, requestReader, []));
      void requestClosed.catch(() => {}); // Releasing on setup refusal rejects it.
    }
  } catch { releaseRequests(); return failure("invalid fetch batch configuration"); }

  if (!inputs.length && !requestReader) {
    const result = Promise.resolve(ok(Object.freeze([]) as readonly T[]));
    const settled = Promise.resolve(ok(undefined));
    return ok(Object.freeze({ result, cancel(reason = "fetch batch cancelled by caller") {
      return typeof reason === "string" ? settled : Promise.resolve(failure("fetch batch cancellation reason must be a string"));
    } }));
  }
  const completion = deferred<Outcome<readonly T[]>>();
  const settlement = completion.promise.then((outcome): Outcome<void> => outcome.outcome === "ok" ? ok(undefined) : outcome);
  const members = new Set<Member>();
  const results: T[] = delivery ? [] : new Array(inputs.length);
  let next = 0, stopped: Failure | undefined, finished = false;
  let cleanupFailure: { index: number; outcome: Failure } | undefined;
  // Recognize only errors created by THIS batch. Reading arbitrary .cause
  // properties would let a consumer forge a cancellation or run a getter.
  const ownedFailures = new WeakMap<object, Failure>();

  function retireRequests(): void {
    if (!requestReader || inputRetirement) return;
    const done = deferred<void>();
    inputRetirement = done.promise;
    // Install the receipt before user cancellation callbacks can reenter, and
    // let sibling retirement start without waiting for this source's cleanup.
    const native = Promise.resolve().then(() => Reflect.apply(CANCEL!, requestReader!, ["fetch batch request source retired"]))
      .then(() => undefined, () => failure("fetch batch request source cancellation refused", "internal_failure"));
    const ownerCancel = requestOwner ? Promise.resolve().then(() => requestOwner!.cancel())
      .then(value => checked<void>(value), () => failure("fetch batch request owner cancellation rejected", "internal_failure"))
      : Promise.resolve(ok(undefined));
    void Promise.all([native, ownerCancel, requestOwner?.closed ?? Promise.resolve(ok(undefined))])
      .then(([nativeFailure, receipt, terminal]) => {
        let issue = nativeFailure;
        const refusal = !!nativeFailure || receipt.outcome === "err" || receipt.outcome === "panicked";
        if (receipt.outcome === "err" || receipt.outcome === "panicked") {
          if (!issue || severity(receipt) >= severity(issue)) issue = receipt;
        }
        if (terminal.outcome === "err" || terminal.outcome === "panicked"
            || terminal.outcome === "cancelled" && (sourceFault || refusal)) {
          if (!issue || severity(terminal) >= severity(issue)) issue = terminal;
        }
        // Source cleanup follows member indices for equal-severity ties.
        if (issue) noteCleanup(Infinity, issue);
        done.resolve();
      });
  }

  async function takeRequest(): Promise<{ index: number; request: BrowserFetchOptions } | undefined> {
    const previous = requestTurn;
    const ready = deferred<void>();
    requestTurn = ready.promise;
    try {
      await previous;
      if (stopped || requestEof) return;
      const entry = await Reflect.apply(READ!, requestReader!, []) as ReadableStreamReadResult<BrowserFetchOptions>;
      // A read may finish in the same turn as cancellation. Never admit it
      // after the fence, nor inspect a body the scope never accepted.
      if (stopped) return;
      if (entry.done) { requestEof = true; return; }
      if (next >= requestLimit) {
        stop(failure("fetch batch request stream exceeds maxRequests"));
        return;
      }
      return { index: next++, request: entry.value };
    } catch {
      if (!inputRetirement) {
        sourceFault = true;
        stop(failure("fetch batch request source failed", "internal_failure"));
      }
      return;
    } finally { ready.resolve(); }
  }

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
  function ownFetch(member: Member, fetch: FetchStreamHandle): Failure | undefined {
    // Retain ownership before any provider getter can throw or re-enter stop.
    // A malformed optional method must not strand an already-admitted handle.
    member.fetch = fetch;
    let issue: Failure | undefined;
    try { member.closed = closedOf(fetch); }
    catch { issue = failure("fetch batch terminal observation failed", "internal_failure"); }
    try {
      const retire = fetch.retire;
      if (retire !== undefined && typeof retire !== "function") {
        issue ??= failure("invalid fetch batch retirement method", "internal_failure");
      } else if (retire) member.retire = () => Reflect.apply(retire, fetch, ["fetch batch member retired"]);
    } catch { issue ??= failure("fetch batch retirement observation failed", "internal_failure"); }
    return issue;
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
        if (adopted.outcome === "ok") {
          const issue = ownFetch(member, adopted.value);
          if (issue) noteCleanup(member.index, issue);
        }
        else noteCleanup(member.index, adopted);
      }
      // Start independent retirement alongside native body cancellation. Its
      // failure fences peers immediately; its settlement still joins all work.
      const retiring = member.retire ? Promise.resolve().then(member.retire).then(value => {
        const receipt = checked<void>(value);
        return receipt.outcome === "ok" && receipt.value !== undefined
          ? failure("invalid fetch batch retirement receipt", "internal_failure") : receipt;
      }, () => failure("fetch batch retirement rejected", "internal_failure")).then(receipt => {
        if (receipt.outcome !== "ok") noteCleanup(member.index, receipt);
        return receipt;
      }) : Promise.resolve(ok(undefined));
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
      const retired = await retiring;
      // Successful cancellation normally produces a cancelled terminal. Only
      // treat that receipt as a cleanup failure when cancellation was refused.
      const terminalFailure = terminal.outcome === "err" || terminal.outcome === "panicked"
        || terminal.outcome === "cancelled" && refusal && !member.retire ? terminal : undefined;
      let outcome = terminalFailure && (!refusal || severity(terminalFailure) >= severity(refusal))
        ? terminalFailure : refusal ?? ok(undefined);
      // With a separate retirement receipt, expected operation cancellation is
      // not evidence of failed cleanup. Genuine owner cancellation was already
      // observed by stop; do not manufacture a stronger cause during retirement.
      if (retired.outcome !== "ok" && (outcome.outcome === "ok" || severity(retired) >= severity(outcome))) outcome = retired;
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
    delivery?.stop();
    retireRequests();
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
    while (!stopped) {
      let entry = requestReader ? await takeRequest()
        : next < inputs.length ? { index: next, request: inputs[next++] } : undefined;
      if (!entry || stopped) break;
      const { index } = entry;
      const member: Member = { index, ready: deferred<void>(), controller: new CONTROLLER!(), ended: false, retiring: false };
      members.add(member);
      let value!: T, consumed = false;
      try {
        try {
          const raw: unknown = Reflect.apply(start, scope, [entry.request]);
          entry = undefined;
          if (!requestReader) inputs[index] = undefined as unknown as BrowserFetchOptions;
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
          const issue = ownFetch(member, admitted.value);
          if (issue) { stop(issue); continue; }
          void member.closed!.then((terminal) => {
            if (!member.retiring && terminal.outcome !== "ok") stop(terminal);
          });
          const converted = checked<ReadableStream<Uint8Array>>(admitted.value.toReadableStream());
          if (converted.outcome !== "ok") { stop(converted); continue; }
          member.reader = Reflect.apply(GET_READER!, converted.value, []) as ReadableStreamDefaultReader<Uint8Array>;
          void Promise.resolve(Reflect.apply(READER_CLOSED!, member.reader, [])).catch(() => {});
        } finally { member.ready.resolve(); }
        if (stopped) continue;
        const head = checked<BrowserFetchResponse>(await member.fetch!.response());
        if (stopped) continue;
        if (head.outcome !== "ok") { stop(head); continue; }
        const item = Object.freeze({ index, response: head.value, body: body(member), signal: member.controller.signal });
        try {
          const supplied = await consume(item);
          if (consumerOutcomes) {
            // Observe even a late consumer: a genuine stronger outcome during
            // drain must not disappear behind the first failure or cancellation.
            const outcome = checked<T>(supplied);
            if (outcome.outcome !== "ok") { stop(outcome); continue; }
            value = outcome.value;
          } else {
            // Legacy consumers may legitimately return an Outcome as DATA.
            value = supplied as T;
          }
          consumed = true;
        }
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
      if (!stopped && consumed) {
        if (delivery) await delivery.publish(index, value);
        else results[index] = value;
      }
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
      releaseRequests();
      return failure("fetch batch signal observation refused");
    }
  }
  // An idle source error is decisive even when every worker is waiting to
  // publish. Successful source closure is not permission to discard its queue.
  if (requestClosed) void requestClosed.catch(() => {
    if (!finished && !inputRetirement) {
      sourceFault = true;
      stop(failure("fetch batch request source failed", "internal_failure"));
    }
  });
  if (requestOwner) void requestOwner.closed.then(terminal => {
    if (!finished && !inputRetirement && terminal.outcome !== "ok") stop(terminal);
  });
  // Return the cancellation handle before executing source reads or admission.
  void Promise.resolve().then(async () => {
    try { await Promise.all(Array.from({ length: requestReader ? concurrency : Math.min(concurrency, inputs.length) }, () => worker().catch(() => {
      stop(failure("fetch batch worker failed", "internal_failure"));
    }))); }
    catch { stop(failure("fetch batch driver failed", "internal_failure")); await Promise.all([...members].map(drain)); }
    // Native EOF does not certify the producer's task/cleanup retirement.
    if (requestOwner) await requestOwner.closed;
    if (inputRetirement) await inputRetirement;
    finished = true;
    releaseRequests();
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
