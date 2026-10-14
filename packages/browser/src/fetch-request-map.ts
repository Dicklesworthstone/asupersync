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
  /** Input-order mapping window, including unread results. Default 1; 1..64. */
  concurrency?: number;
  /** Borrowed parent signal. Stops admission and joins all mapper/producer work. */
  signal?: AbortSignal | null;
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
const SIGNAL = typeof AbortSignal === "undefined" ? undefined : AbortSignal;
const ANY_SIGNAL = SIGNAL?.any;
const ABORTED = SIGNAL && Object.getOwnPropertyDescriptor(SIGNAL.prototype, "aborted")?.get;
const EVENT_TARGET = typeof EventTarget === "undefined" ? undefined : EventTarget;
const ADD_LISTENER = EVENT_TARGET?.prototype.addEventListener;
const REMOVE_LISTENER = EVENT_TARGET?.prototype.removeEventListener;

/**
 * Map records to request descriptors (null skips a record), in input order.
 * No fetch is admitted here. Pass the returned owner directly to streamMapFetches.
 * By default one native input read/async mapper is active at a time. Opt-in
 * concurrency reserves a bounded window on output demand: pending input,
 * running mappers and unread mapped results all retain a slot. Input reads stay
 * serialized and output stays in input order, even if mappers finish out of order.
 * Cancellation fences output and signals every mapper immediately, then joins
 * all mapper settlements, input cancellation, owner cancellation and owner.closed.
 * A late mapper panic is not hidden by cancellation; its returned request is
 * never emitted after a stop. Already-delivered requests are not rolled back.
 * An optional parent signal uses the same fence and join, including before the
 * first pull and during producer retirement after EOF. Supply an unmodified
 * same-realm native signal; native AbortSignal.any prevents earlier parent
 * listeners from suppressing observation. Arbitrary reasons are not inspected,
 * the parent is never mutated, and its observer is detached at settlement.
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
 * skip an input. Each expansion retains its mapping-window slot until every
 * descriptor is emitted. At default concurrency, no later input is pulled then.
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
  let maxInputs: number, maxExpansion: number, concurrency: number;
  let parent: AbortSignal | undefined;
  try {
    maxInputs = options.maxInputs ?? 100_000;
    if (!Number.isSafeInteger(maxInputs) || maxInputs < 1 || typeof mapper !== "function") {
      return fail("request mapping requires a mapper and a positive safe maxInputs", "compatibility_rejected");
    }
    const suppliedConcurrency = options.concurrency;
    concurrency = suppliedConcurrency === undefined ? 1 : suppliedConcurrency;
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
      return fail("request mapping concurrency must be an integer in 1..64", "compatibility_rejected");
    }
    maxExpansion = expand ? options.maxRequestsPerInput ?? 64 : 1;
    if (!Number.isSafeInteger(maxExpansion) || maxExpansion < 1 || maxExpansion > 1024) {
      return fail("maxRequestsPerInput must be an integer in 1..1024", "compatibility_rejected");
    }
    const suppliedSignal = options.signal;
    if (suppliedSignal != null) {
      if (!SIGNAL || !ANY_SIGNAL || !ABORTED || !ADD_LISTENER || !REMOVE_LISTENER) {
        return fail("request mapping signals require native AbortSignal.any and EventTarget", "compatibility_rejected");
      }
      // Native composition can inspect accessors. Match the existing batch
      // boundary without invoking customized aborted/reason properties.
      if (Object.getPrototypeOf(suppliedSignal) !== SIGNAL.prototype
          || Object.getOwnPropertyDescriptor(suppliedSignal, "aborted")
          || Object.getOwnPropertyDescriptor(suppliedSignal, "reason")) {
        return fail("request mapping requires an unmodified same-realm native signal", "compatibility_rejected");
      }
      Reflect.apply(ABORTED, suppliedSignal, []);
      parent = Reflect.apply(ANY_SIGNAL, SIGNAL, [[suppliedSignal]]) as AbortSignal;
      Reflect.apply(ABORTED, parent, []);
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
  // A slot is reserved BEFORE its input read, and released only after all of
  // its descriptors have been accepted by output pulls. A slow early mapper
  // cannot accumulate an unbounded reorder buffer behind it.
  type Slot = { requests?: BrowserFetchOptions[]; next: number };
  const slots: Slot[] = [];
  const mapping = new Set<Promise<void>>();
  let reading: Promise<void> | undefined, inputEof = false;
  let changed = deferred<void>();
  const onAbort = () => { void stop(cancelled("request mapping cancelled by signal")); };

  function detachParent(): void {
    if (!parent) return;
    try { Reflect.apply(REMOVE_LISTENER!, parent, ["abort", onAbort]); } catch { /* Preserve settlement. */ }
    parent = undefined;
  }

  function notify(): void {
    const previous = changed;
    changed = deferred<void>();
    previous.resolve();
  }

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
      // The stop/EOF fence prevents new work. Native cancellation can settle a
      // read without settling mappers that already own earlier input records.
      await reading;
      await Promise.all([...mapping]);
      if (ownerClosed) noteSource(await ownerClosed);
      if (retirement) await retirement;
      ended = true;
      detachParent();
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
    for (const slot of slots) slot.requests = undefined;
    slots.length = 0;
    notify();
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
  function mapSlot(slot: Slot, inputValue: T, inputIndex: number): void {
    const done = deferred<void>();
    // Register before user code can synchronously call cancel().
    mapping.add(done.promise);
    void (async () => {
      let value: unknown;
      try {
        value = await mapper(inputValue, inputIndex, control.signal);
        if (typed) {
          // A later failure must still strengthen a pending shutdown.
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
          // Indexed accessors may re-enter cancellation. Never publish their
          // results after that ownership fence, even behind a slower mapper.
          if (ending || ended) return;
          slot.requests = snapshot;
        } catch {
          void stop(fail("request expansion requires a bounded array of request objects", "compatibility_rejected"));
        }
      } else if (value === null) slot.requests = [];
      else if (!value || typeof value !== "object" || Array.isArray(value)) {
        void stop(fail("request mapper must return a request object or null", "compatibility_rejected"));
      } else slot.requests = [value as BrowserFetchOptions];
    })().catch(() => { void stop(fail("request mapping driver failed")); }).finally(() => {
      mapping.delete(done.promise);
      done.resolve();
      notify();
    });
  }
  function readSlot(): void {
    const slot: Slot = { next: 0 };
    slots.push(slot);
    const done = deferred<void>();
    reading = done.promise;
    void (async () => {
      let item: ReadableStreamReadResult<T>;
      try { item = await Reflect.apply(READ!, reader, []); }
      catch { sourceFault(); return; }
      if (ending || ended) return;
      if (item.done) {
        inputEof = true;
        // Reads are serialized, so the reserved read is always the last slot.
        slots.pop();
        return;
      }
      if (index === maxInputs) { void stop(fail("request mapping maxInputs exceeded", "compatibility_rejected")); return; }
      mapSlot(slot, item.value, index++);
    })().catch(() => { void stop(fail("request mapping driver failed")); }).finally(() => {
      reading = undefined;
      done.resolve();
      notify();
    });
  }
  function pull(): Promise<void> | undefined {
    if (ending || ended) return;
    const done = deferred<void>();
    active = done.promise; // Install before invoking even a synchronous mapper.
    void (async () => {
      while (!ending && !ended) {
        const waiting = changed.promise;
        const slot = slots[0];
        if (slot?.requests) {
          if (slot.next === slot.requests.length) { slots.shift(); continue; }
          const request = slot.requests[slot.next];
          slot.requests[slot.next++] = undefined as unknown as BrowserFetchOptions;
          if (slot.next === slot.requests.length) slots.shift();
          controller.enqueue(request);
          return;
        }
        if (inputEof && !slots.length) { ending = true; finalize(); return; }
        if (!inputEof && !reading && slots.length < concurrency) readSlot();
        // Do not await the next input directly: a parked source read must not
        // hide a completed earlier mapping result. Either can wake this driver.
        await waiting;
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
    if (parent) {
      Reflect.apply(ADD_LISTENER!, parent, ["abort", onAbort, { once: true }]);
      // Also catches parent aborts during caller-owned source property reads.
      if (Reflect.apply(ABORTED!, parent, [])) onAbort();
    }
    return ok(Object.freeze({ readable, closed: completion.promise, cancel(reason = "request mapping cancelled by caller") {
      return typeof reason === "string" ? stop(cancelled(reason))
        : Promise.resolve(fail("request mapping cancellation reason must be a string", "compatibility_rejected"));
    } }));
  } catch {
    // No source read/mapper has run: native HWM=0 construction does not pull.
    // Invalidate already-installed promise observers on refused signal setup.
    ending = true;
    ended = true;
    detachParent();
    try { if (reader!) Reflect.apply(RELEASE, reader, []); } catch { /* No owned lock. */ }
    return fail("request mapping setup refused", "compatibility_rejected");
  }
}

/** Bounds source count, pending reads and retained descriptors, not payload bytes. */
export const FETCH_REQUEST_MERGE_LIMITS = Object.freeze({ maxSources: 64 });

/**
 * Merge 0..64 exclusively owned request sources without a detached pipe pump.
 * A first output pull starts one native read per source. Each source retains at
 * most one pending read OR unread descriptor; another read needs output demand.
 * Ready sources are served in observation order, preserving each source's order.
 * A parked source cannot hold up a ready peer, and queued peers are not bypassed
 * by a source that becomes ready again. No cross-source total order is promised.
 *
 * Ownership transfers only if every source validates and every lock is acquired.
 * Setup refusal releases acquired locks without reading/cancelling caller work.
 * Native EOF is separate from an owned producer's completion: success joins both.
 * Any failure stops all sources, discards queued references, and joins outstanding
 * reads, native cancellation, owner cancellation and independent producer receipts.
 * Expected retirement cancellation is not a new failure; stronger failures during
 * drain remain visible. Same-severity cleanup failures use source input order.
 *
 * Pass the result directly to streamMapFetches/tryStreamMapFetches. No request is
 * admitted, body acquired, task spawned, timer installed or retry performed here.
 * Descriptors keep their identity. Unadmitted upload bodies, source queues, hidden
 * raw-stream producer work and downstream buffering remain caller responsibilities.
 * Read or cancel the output; waiting only for closed can intentionally stall.
 * Already delivered descriptors/effects cannot be rolled back. An owner must
 * truthfully join its work and must not await this merge's own closed/cancel.
 */
export function mergeFetchRequestSources(
  sources: readonly Input<BrowserFetchOptions>[],
): Outcome<FetchBatchRequestSource> {
  if (!STREAM || !LOCKED || !GET_READER || !READ || !CANCEL || !RELEASE || !READER_CLOSED) {
    return fail("request merging requires native stream readers", "compatibility_rejected");
  }
  interface Member {
    reader: ReadableStreamDefaultReader<BrowserFetchOptions>;
    terminal?: Promise<Outcome<void>>;
    cancelOwner?: () => unknown;
    reading?: Promise<void>;
    eof: boolean;
    queued: boolean;
    fault?: Failure;
  }
  const members: Member[] = [];
  const completion = deferred<Outcome<void>>();
  const ready: { index: number; value: BrowserFetchOptions }[] = [];
  let controller!: ReadableStreamDefaultController<BrowserFetchOptions>;
  let demand: ReturnType<typeof deferred<void>> | undefined;
  let accepted = false, ended = false, finalizing = false, consumerCancelled = false;
  let stopped: Failure | undefined;
  let cleanup: { index: number; outcome: Failure } | undefined;
  let retirement: Promise<void> | undefined;

  function release(): void {
    for (const member of members) {
      try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ }
    }
  }
  function note(outcome: Failure): void {
    if (!stopped || severity(outcome) > severity(stopped)) stopped = outcome;
  }
  function noteCleanup(index: number, outcome: Failure): void {
    if (!cleanup || severity(outcome) > severity(cleanup.outcome)
        || severity(outcome) === severity(cleanup.outcome) && index < cleanup.index) {
      cleanup = { index, outcome };
    }
    note(outcome);
  }
  function noteSource(index: number, outcome: Outcome<void>): void {
    if (outcome.outcome === "ok") return;
    const member = members[index];
    // Replace only this source's provisional native-read diagnosis. Never
    // authorize an exception's cause or replace another already selected cause.
    if (member.fault && stopped === member.fault) stopped = outcome;
    else if (outcome.outcome !== "cancelled" || !retirement || member.fault) note(outcome);
  }
  function finish(): void {
    if (finalizing) return;
    finalizing = true;
    // A native read may call finish; do not await the finalizer from that read.
    void (async () => {
      await Promise.all(members.map(member => member.reading));
      await Promise.all(members.map(async (member, index) => {
        if (member.terminal) {
          const outcome = await member.terminal;
          noteSource(index, outcome);
          if (outcome.outcome !== "ok" && !retirement) stop(outcome);
        }
      }));
      if (retirement) await retirement;
      ended = true;
      release();
      const outcome = cleanup && (!stopped || severity(cleanup.outcome) >= severity(stopped))
        ? cleanup.outcome : stopped ?? ok(undefined);
      try {
        if (!consumerCancelled) {
          if (outcome.outcome === "ok") controller.close();
          else controller.error(mergeError(outcome));
        }
      } catch { /* Native consumer cancellation already closed output. */ }
      demand?.resolve(); demand = undefined;
      completion.resolve(outcome);
    })();
  }
  function mergeError(outcome: Failure): Error {
    return Object.defineProperty(new Error("owned request merge stopped"), "cause", { value: outcome });
  }
  function stop(outcome: Failure): Promise<Outcome<void>> {
    if (ended) return completion.promise;
    note(outcome);
    if (!retirement) {
      const joined = deferred<void>();
      retirement = joined.promise; // Fence before every producer callback.
      ready.length = 0;
      for (const member of members) member.queued = false;
      void Promise.all(members.map(async (member, index) => {
        // Start native and owner cancellation independently. Either one can
        // legitimately need the other to run before its own promise settles.
        const native = Promise.resolve().then(() => Reflect.apply(CANCEL!, member.reader, ["request merge retired"]))
          .then(() => undefined, () => fail("request merge native cancellation rejected"));
        const owner = member.cancelOwner ? Promise.resolve().then(member.cancelOwner)
          .then(value => checked<void>(value), () => fail("request merge owner cancellation rejected"))
          : Promise.resolve(ok(undefined));
        const [refusal, receipt, terminal] = await Promise.all([
          native, owner, member.terminal ?? Promise.resolve(ok(undefined)), member.reading,
        ]);
        let issue = refusal;
        if (receipt.outcome === "err" || receipt.outcome === "panicked") {
          if (!issue || severity(receipt) >= severity(issue)) issue = receipt;
        }
        noteSource(index, terminal);
        if (terminal.outcome === "err" || terminal.outcome === "panicked"
            || terminal.outcome === "cancelled" && !!member.fault) {
          if (!issue || severity(terminal) >= severity(issue)) issue = terminal;
        }
        if (issue) noteCleanup(index, issue);
      })).then(() => joined.resolve());
      finish();
    }
    return completion.promise;
  }
  function fault(index: number): void {
    if (!accepted || ended || retirement) return;
    const cause = fail("request merge input failed");
    members[index].fault = cause;
    void stop(cause);
  }
  function deliver(): void {
    if (ended || retirement) return;
    if (demand && ready.length) {
      const item = ready.shift()!;
      members[item.index].queued = false;
      const pending = demand; demand = undefined;
      controller.enqueue(item.value);
      pending.resolve();
    }
    if (!ready.length && members.every(member => member.eof)) finish();
  }
  function read(index: number): void {
    const member = members[index];
    const done = deferred<void>();
    member.reading = done.promise; // Own before native pull callbacks can run.
    void (async () => {
      try {
        const item = await Reflect.apply(READ!, member.reader, []) as ReadableStreamReadResult<BrowserFetchOptions>;
        if (ended || retirement) return;
        if (item.done) member.eof = true;
        else { member.queued = true; ready.push({ index, value: item.value }); }
        deliver();
      } catch { fault(index); }
      finally { member.reading = undefined; done.resolve(); }
    })();
  }
  try {
    const count = Array.isArray(sources) ? sources.length : -1;
    if (!Number.isSafeInteger(count) || count < 0 || count > FETCH_REQUEST_MERGE_LIMITS.maxSources) {
      return fail("request merging requires an array of at most 64 sources", "compatibility_rejected");
    }
    const snapshots: { input: ReadableStream<BrowserFetchOptions>; terminal?: Promise<Outcome<void>>; cancelOwner?: () => unknown }[] = [];
    const seen = new Set<ReadableStream<BrowserFetchOptions>>();
    for (let index = 0; index < count; index++) {
      const source = sources[index];
      let input: ReadableStream<BrowserFetchOptions>, terminal: Promise<Outcome<void>> | undefined;
      let cancelOwner: (() => unknown) | undefined;
      let native = false;
      try { Reflect.apply(LOCKED, source, []); native = true; } catch { /* Explicit owner form. */ }
      if (native) input = source as ReadableStream<BrowserFetchOptions>;
      else {
        const owner = source as FetchBatchRequestSource;
        input = owner.readable;
        const cancel = owner.cancel, receipt = owner.closed;
        if (typeof cancel !== "function" || !receipt || typeof receipt.then !== "function") throw new Error("invalid owner");
        cancelOwner = () => Reflect.apply(cancel, owner, ["request merge retired"]);
        terminal = Promise.resolve(receipt).then(value => checked<void>(value), () => fail("request merge source completion rejected"));
      }
      if (seen.has(input) || Reflect.apply(LOCKED, input, [])) throw new Error("duplicate or locked source");
      seen.add(input);
      snapshots.push({ input, terminal, cancelOwner });
    }
    const readable = new STREAM<BrowserFetchOptions>({
      start(value) { controller = value; },
      pull() {
        if (ended || retirement) return completion.promise.then(() => undefined);
        const pending = deferred<void>(); demand = pending;
        // Snapshot eligibility before starting reads. Resolution uses microtasks,
        // so every source in this demand wave gets exactly one chance to read.
        for (let index = 0; index < members.length; index++) {
          const member = members[index];
          if (!member.eof && !member.queued && !member.reading) read(index);
        }
        deliver();
        return pending.promise;
      },
      async cancel() {
        consumerCancelled = true;
        const outcome = await stop(cancelled("request merge output cancelled"));
        if (outcome.outcome === "err" || outcome.outcome === "panicked") throw mergeError(outcome);
      },
    }, { highWaterMark: 0 });
    for (const snapshot of snapshots) {
      const reader = Reflect.apply(GET_READER, snapshot.input, []) as ReadableStreamDefaultReader<BrowserFetchOptions>;
      const index = members.length;
      members.push({ reader, terminal: snapshot.terminal, cancelOwner: snapshot.cancelOwner, eof: false, queued: false });
      void Promise.resolve(Reflect.apply(READER_CLOSED, reader, [])).catch(() => fault(index));
    }
    accepted = true;
    for (let index = 0; index < members.length; index++) {
      void members[index].terminal?.then(outcome => {
        if (!accepted || ended || outcome.outcome === "ok") return;
        noteSource(index, outcome);
        if (!retirement) void stop(outcome);
      });
    }
    if (!members.length) {
      ended = true;
      controller.close();
      completion.resolve(ok(undefined));
    }
    return ok(Object.freeze({ readable, closed: completion.promise, cancel(reason = "request merge cancelled by caller") {
      return typeof reason === "string" ? stop(cancelled(reason))
        : Promise.resolve(fail("request merge cancellation reason must be a string", "compatibility_rejected"));
    } }));
  } catch {
    accepted = false;
    release();
    return fail("invalid or locked request merge source", "compatibility_rejected");
  }
}
