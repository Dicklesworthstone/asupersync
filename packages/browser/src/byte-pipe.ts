/** Region-owned native byte-stream transfers with observed host retirement. */
import type { Outcome } from "@asupersync/browser-core";

export const BROWSER_BYTE_PIPE_LIMITS = Object.freeze({
  maxChunkBytes: 1_048_576,
  maxBytes: Number.MAX_SAFE_INTEGER,
});

export interface BrowserBytePipeOptions {
  /** Maximum bytes in one source chunk. Default 1 MiB; at most 16 MiB. */
  maxChunkBytes?: number;
  /** Maximum admitted bytes for this transfer, including empty-transfer limit 0. */
  maxBytes?: number;
  /** Borrowed unmodified same-realm native signal. */
  signal?: AbortSignal | null;
}

export interface BrowserBytePipeProgress {
  /** Bytes whose native write promises fulfilled; this is not peer delivery. */
  readonly bytesWritten: number;
  readonly chunksWritten: number;
}

export interface BrowserBytePipeHandle {
  /** First result after host settlement and an attempted task publication. */
  readonly completed: Promise<Outcome<BrowserBytePipeProgress>>;
  /** Independent immutable snapshot, also available after a partial failure. */
  progress(): BrowserBytePipeProgress;
  /** Request cancellation and await an independent retirement receipt. */
  cancel(reason?: string): Promise<Outcome<void>>;
  /** Retry refused task publication or lock release; never restart the transfer. */
  retire(reason?: string): Promise<Outcome<void>>;
}

/** Private SDK bridge: stream handles never expose the task's authority. */
export interface BrowserBytePipeTask {
  readonly key: string;
  cancel(kind: string, message: string): Outcome<void>;
  join(outcome: Outcome<void>): Outcome<void>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string, code: "compatibility_rejected" | "capability_denied" | "decode_failure" | "internal_failure" = "internal_failure"): Failure =>
  Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability: "permanent", message }) });
function cancellation(kind: string, reason: string): Failure {
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind, phase: "completed", origin_region: "browser-byte-pipe", origin_task: null,
    timestamp_nanos: 0, message: reason.slice(0, 512), truncated: reason.length > 512,
  }) });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

/** Snapshot receipts before another host callback can mutate their fields. */
function checked(value: unknown): Outcome<void> {
  try {
    if (!value || typeof value !== "object") return fail("Invalid stream task receipt");
    const receipt = value as Outcome<void>;
    switch (receipt.outcome) {
      case "ok": return receipt.value === undefined ? ok(undefined) : fail("Invalid stream task success");
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
  } catch { /* Do not stringify arbitrary host exceptions or owner authority. */ }
  return fail("Invalid stream task receipt");
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

const TYPED = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_TAG = Object.getOwnPropertyDescriptor(TYPED, Symbol.toStringTag)!.get!;
const TYPED_BYTES = Object.getOwnPropertyDescriptor(TYPED, "byteLength")!.get!;
const TYPED_BUFFER = Object.getOwnPropertyDescriptor(TYPED, "buffer")!.get!;
const TYPED_OFFSET = Object.getOwnPropertyDescriptor(TYPED, "byteOffset")!.get!;
const TYPED_VALUES = TYPED.values;
const TYPED_SET = TYPED.set;

interface Host {
  readableLocked: (this: ReadableStream<Uint8Array>) => boolean;
  writableLocked: (this: WritableStream<Uint8Array>) => boolean;
  getReader: ReadableStream<Uint8Array>["getReader"];
  getWriter: WritableStream<Uint8Array>["getWriter"];
  read: ReadableStreamDefaultReader<Uint8Array>["read"];
  cancel: ReadableStreamDefaultReader<Uint8Array>["cancel"];
  releaseReader: ReadableStreamDefaultReader<Uint8Array>["releaseLock"];
  readerClosed: (this: ReadableStreamDefaultReader<Uint8Array>) => Promise<void>;
  ready: (this: WritableStreamDefaultWriter<Uint8Array>) => Promise<void>;
  write: WritableStreamDefaultWriter<Uint8Array>["write"];
  close: WritableStreamDefaultWriter<Uint8Array>["close"];
  abort: WritableStreamDefaultWriter<Uint8Array>["abort"];
  releaseWriter: WritableStreamDefaultWriter<Uint8Array>["releaseLock"];
  writerClosed: (this: WritableStreamDefaultWriter<Uint8Array>) => Promise<void>;
  scheduleTurn: (callback: () => void) => unknown;
  cancelTurn: (handle: unknown) => void;
  signal?: AbortSignal;
  aborted?: (this: AbortSignal) => boolean;
  add?: EventTarget["addEventListener"];
  remove?: EventTarget["removeEventListener"];
}

interface HostTurn {
  handle: unknown;
  armed: boolean;
  cancelled: boolean;
  fire: (() => void) | null;
  resume(): void;
}

function limit(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError("Invalid stream limit");
  return value;
}

function prepare(host: Record<string, unknown> | undefined, source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>, options: BrowserBytePipeOptions) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Expected a byte stream options object");
  }
  const Readable = host?.ReadableStream as typeof ReadableStream | undefined;
  const Reader = host?.ReadableStreamDefaultReader as typeof ReadableStreamDefaultReader | undefined;
  const Writable = host?.WritableStream as typeof WritableStream | undefined;
  const Writer = host?.WritableStreamDefaultWriter as typeof WritableStreamDefaultWriter | undefined;
  const schedule = host?.setTimeout, unschedule = host?.clearTimeout;
  if (!Readable || !Reader || !Writable || !Writer || typeof schedule !== "function" || typeof unschedule !== "function"
      || Object.getPrototypeOf(source) !== Readable.prototype || Object.getPrototypeOf(destination) !== Writable.prototype) {
    throw new TypeError("Expected same-realm native streams");
  }
  const native: Host = {
    readableLocked: Object.getOwnPropertyDescriptor(Readable.prototype, "locked")?.get!,
    writableLocked: Object.getOwnPropertyDescriptor(Writable.prototype, "locked")?.get!,
    getReader: Readable.prototype.getReader, getWriter: Writable.prototype.getWriter,
    read: Reader.prototype.read, cancel: Reader.prototype.cancel, releaseReader: Reader.prototype.releaseLock,
    readerClosed: Object.getOwnPropertyDescriptor(Reader.prototype, "closed")?.get!,
    ready: Object.getOwnPropertyDescriptor(Writer.prototype, "ready")?.get!,
    write: Writer.prototype.write, close: Writer.prototype.close, abort: Writer.prototype.abort,
    releaseWriter: Writer.prototype.releaseLock,
    writerClosed: Object.getOwnPropertyDescriptor(Writer.prototype, "closed")?.get!,
    scheduleTurn: callback => Reflect.apply(schedule, host, [callback, 0]),
    cancelTurn: handle => { Reflect.apply(unschedule, host, [handle]); },
  };
  if (Object.values(native).some(value => typeof value !== "function")) throw new TypeError("Incomplete native streams");
  const maxChunkBytes = limit(options.maxChunkBytes ?? BROWSER_BYTE_PIPE_LIMITS.maxChunkBytes, 1, 16_777_216);
  const maxBytes = limit(options.maxBytes ?? BROWSER_BYTE_PIPE_LIMITS.maxBytes, 0, Number.MAX_SAFE_INTEGER);
  const signal = options.signal;
  if (signal != null) {
    const Signal = host?.AbortSignal as typeof AbortSignal | undefined;
    const Target = host?.EventTarget as typeof EventTarget | undefined;
    const aborted = Signal && Object.getOwnPropertyDescriptor(Signal.prototype, "aborted")?.get;
    if (!Signal || !Target || !aborted || typeof Signal.any !== "function"
        || Object.getPrototypeOf(signal) !== Signal.prototype
        || Object.getOwnPropertyDescriptor(signal, "aborted") || Object.getOwnPropertyDescriptor(signal, "reason")) {
      throw new TypeError("Expected an unmodified same-realm native AbortSignal");
    }
    Reflect.apply(aborted, signal, []);
    native.signal = Reflect.apply(Signal.any, Signal, [[signal]]) as AbortSignal;
    native.aborted = aborted;
    native.add = Target.prototype.addEventListener;
    native.remove = Target.prototype.removeEventListener;
    if (typeof native.add !== "function" || typeof native.remove !== "function") throw new TypeError("Incomplete native signal");
  }
  if (Reflect.apply(native.readableLocked, source, []) || Reflect.apply(native.writableLocked, destination, [])) {
    throw new TypeError("Stream is already locked");
  }
  return { native, maxChunkBytes, maxBytes };
}

/** Uses caller-supplied stream authority; does not create a network connection. */
export function createBrowserBytePipeManager(dependencies: {
  globalObject(): Record<string, unknown> | undefined;
  isTracked(scopeKey: string): boolean;
  isClosing(scopeKey: string): boolean;
  /** Shared SDK endpoint reservations, including tasks awaiting publication. */
  endpoints?: WeakSet<object>;
}) {
  const active = new Map<string, Operation>();
  const adopted = dependencies.endpoints ?? new WeakSet<object>();
  type Prepared = ReturnType<typeof prepare>;

  class Operation {
    readonly completed = deferred<Outcome<BrowserBytePipeProgress>>();
    readonly activated = deferred<void>();
    readonly work = deferred<void>();
    reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
    readerAcquisitionAttempted = false;
    writerAcquisitionAttempted = false;
    acquisitionFailure: Failure | null = null;
    readerTerminal = false;
    writerTerminal = false;
    readerReleased = false;
    writerReleased = false;
    sourceCleanup: Promise<Outcome<void>> | null = null;
    sinkCleanup: Promise<Outcome<void>> | null = null;
    signalListener: EventListener | null = null;
    operation: Outcome<void> | null = null;
    cancelAccepted = false;
    ownerReleased = false;
    released = false;
    publishing = false;
    bytesWritten = 0;
    chunksWritten = 0;
    attempt: Promise<Outcome<void>> | null = null;
    hostTurn: HostTurn | null = null;
    hostTurnFailure: Failure | null = null;

    constructor(readonly scopeKey: string, readonly task: BrowserBytePipeTask,
      readonly source: ReadableStream<Uint8Array>, readonly destination: WritableStream<Uint8Array>,
      readonly prepared: Prepared) {}

    handle(): BrowserBytePipeHandle {
      return Object.freeze({
        completed: this.completed.promise, progress: () => this.progress(),
        cancel: (reason?: string) => this.retire(reason), retire: (reason?: string) => this.retire(reason),
      });
    }
    progress(): BrowserBytePipeProgress {
      return Object.freeze({ bytesWritten: this.bytesWritten, chunksWritten: this.chunksWritten });
    }
    stop(terminal: Failure): void {
      if (this.released || this.publishing || this.operation !== null) return;
      this.operation = terminal;
      this.clearHostTurn();
      void this.joinRetirement();
    }

    cancelTimer(wait: HostTurn): void {
      if (!wait.armed) return;
      wait.armed = false;
      try { this.prepared.native.cancelTurn(wait.handle); }
      catch { this.hostTurnFailure ??= fail("Stream transfer host scheduling cleanup failed; ownership is retained"); }
    }
    clearHostTurn(): void {
      const wait = this.hostTurn;
      this.hostTurn = null;
      if (!wait) return;
      // Invalidate the callback before host cleanup can reenter. A suspended
      // timer must not keep pump()/scope drain pending once the transfer stops.
      wait.cancelled = true;
      wait.fire = null;
      this.cancelTimer(wait);
      wait.resume();
    }
    yieldToHost(): Promise<void> {
      const done = deferred<void>();
      const wait: HostTurn = { handle: undefined, armed: false, cancelled: false,
        fire: null, resume: done.resolve };
      wait.fire = () => {
        if (this.hostTurn !== wait) return;
        this.hostTurn = null;
        wait.resume();
      };
      this.hostTurn = wait;
      try {
        // The callback retains only this cell. Cancellation clears fire so an
        // already queued callback cannot retain or resume the stopped pump.
        wait.handle = this.prepared.native.scheduleTurn(() => {
          const fire = wait.fire;
          wait.fire = null;
          fire?.();
        });
        wait.armed = true;
        // A scheduler hook can synchronously cancel before returning its
        // handle. The stop fence is already installed; retire the late handle.
        if (wait.cancelled) this.cancelTimer(wait);
      } catch {
        if (this.hostTurn === wait) this.hostTurn = null;
        wait.fire = null;
        wait.resume();
        this.stop(fail("Stream transfer host scheduling failed"));
      }
      return done.promise;
    }
    signalAborted(): boolean {
      const { native } = this.prepared;
      return native.signal !== undefined && Reflect.apply(native.aborted!, native.signal, []);
    }

    activate(): void {
      const { native } = this.prepared;
      let pumping = false;
      try {
        if (!dependencies.isTracked(this.scopeKey) || dependencies.isClosing(this.scopeKey) || this.signalAborted()) {
          this.stop(cancellation("byte_pipe_cancel", "Stream transfer cancelled before activation"));
          return;
        }
        // Admission hooks can acquire a native lock after preflight. In that
        // case the caller retains both streams; only the admitted task retires.
        if (Reflect.apply(native.readableLocked, this.source, []) || Reflect.apply(native.writableLocked, this.destination, [])) {
          this.stop(fail("Stream became locked during admission", "compatibility_rejected"));
          return;
        }
        this.readerAcquisitionAttempted = true;
        this.reader = Reflect.apply(native.getReader, this.source, []) as ReadableStreamDefaultReader<Uint8Array>;
        void Promise.resolve(Reflect.apply(native.readerClosed, this.reader, [])).then(
          () => { this.readerTerminal = true; },
          () => {
            this.readerTerminal = true;
            if (!this.readerReleased) this.stop(fail("Source stream failed"));
          },
        );
        this.writerAcquisitionAttempted = true;
        this.writer = Reflect.apply(native.getWriter, this.destination, []);
        void Promise.resolve(Reflect.apply(native.writerClosed, this.writer, [])).then(
          () => { this.writerTerminal = true; },
          () => {
            this.writerTerminal = true;
            if (!this.writerReleased) this.stop(fail("Destination stream failed"));
          },
        );
        if (native.signal) {
          this.signalListener = () => this.stop(cancellation("byte_pipe_cancel", "Stream transfer aborted by signal"));
          Reflect.apply(native.add!, native.signal, ["abort", this.signalListener]);
        }
        if (!dependencies.isTracked(this.scopeKey) || dependencies.isClosing(this.scopeKey) || this.signalAborted()) {
          this.stop(cancellation("byte_pipe_cancel", "Stream transfer cancelled during activation"));
        }
        if (this.operation === null) {
          pumping = true;
          void this.pump().then(
            () => { this.work.resolve(); void this.joinRetirement(); },
            () => { this.stop(fail("Stream transfer failed")); this.work.resolve(); },
          );
        }
      } catch {
        // A host method can acquire a lock and then throw without returning
        // its handle. Do not mistake the missing handle for an unowned stream.
        // Capture this ambiguity immediately and retain it across retries:
        // another actor releasing the lock later does not prove that the
        // unreturned owner's I/O or cleanup was observed by this transfer.
        if (this.readerAcquisitionAttempted && this.reader == null) {
          try {
            if (Reflect.apply(native.readableLocked, this.source, [])) {
              this.acquisitionFailure = fail("Source stream lock acquired without a returned reader; ownership is retained");
            }
          } catch { this.acquisitionFailure = fail("Source stream lock acquisition could not be verified; ownership is retained"); }
        }
        if (this.writerAcquisitionAttempted && this.writer == null) {
          try {
            if (Reflect.apply(native.writableLocked, this.destination, [])) {
              this.acquisitionFailure ??= fail("Destination stream lock acquired without a returned writer; ownership is retained");
            }
          } catch { this.acquisitionFailure ??= fail("Destination stream lock acquisition could not be verified; ownership is retained"); }
        }
        this.stop(fail("Stream transfer activation failed"));
      }
      finally {
        if (!pumping) this.work.resolve();
        this.activated.resolve();
      }
    }

    async pump(): Promise<void> {
      const { native, maxChunkBytes, maxBytes } = this.prepared;
      let burst = 0;
      while (this.operation === null) {
        // At most one read and one write are owned. Backpressure is observed
        // before asking the source for another chunk, not after buffering it.
        await Reflect.apply(native.ready, this.writer!, []);
        if (this.operation !== null) return;
        const result = await Reflect.apply(native.read, this.reader!, []);
        if (this.operation !== null) return;
        if (result.done) {
          await Reflect.apply(native.close, this.writer!, []);
          this.operation ??= ok(undefined);
          return;
        }
        const chunk = result.value;
        // values() validates detached and out-of-bounds resizable views even
        // when their intrinsic byteLength misleadingly reads as zero.
        if (Reflect.apply(TYPED_TAG, chunk, []) !== "Uint8Array") {
          this.stop(fail("Source stream must produce Uint8Array chunks", "decode_failure")); return;
        }
        Reflect.apply(TYPED_VALUES, chunk, []);
        const length = Reflect.apply(TYPED_BYTES, chunk, []) as number;
        if (length > maxChunkBytes || length > maxBytes - this.bytesWritten || this.chunksWritten === Number.MAX_SAFE_INTEGER) {
          this.stop(fail("Stream transfer byte or chunk accounting limit exceeded", "capability_denied")); return;
        }
        const payload = new Uint8Array(length);
        const view = new Uint8Array(Reflect.apply(TYPED_BUFFER, chunk, []), Reflect.apply(TYPED_OFFSET, chunk, []), length);
        Reflect.apply(TYPED_SET, payload, [view]);
        if (this.operation !== null) return;
        await Promise.resolve(Reflect.apply(native.write, this.writer!, [payload])).then(() => {
          // Fulfilled writes remain part of the receipt even if cancellation
          // arrived while the sink was committing this particular chunk.
          this.bytesWritten += length;
          this.chunksWritten += 1;
        });
        burst += 1;
        if (burst === 64 && this.operation === null) {
          burst = 0;
          // Infinite in-memory sources must not starve timer/event aborts by
          // monopolizing the microtask queue. This is a host turn, not a timer
          // deadline or an assertion that arbitrary callbacks will terminate.
          await this.yieldToHost();
        }
      }
    }

    cleanup(): Promise<Outcome<void>> {
      const { native } = this.prepared;
      const invoke = (operation: () => unknown, message: string): Promise<Outcome<void>> => {
        try { return Promise.resolve(operation()).then(() => ok(undefined), () => fail(message)); }
        catch { return Promise.resolve(fail(message)); }
      };
      // Start both directions before awaiting either: source cancellation can
      // depend on destination abort (and vice versa). Retain the original
      // promises forever. Native cancel/abort can reject once and then resolve
      // on retry without re-invoking the failed underlying cleanup callback.
      this.sourceCleanup ??= this.reader === null || this.readerTerminal ? Promise.resolve(ok(undefined))
        : invoke(() => Reflect.apply(native.cancel, this.reader!, ["Owned stream transfer stopped"]), "Source stream cancellation failed; ownership is retained");
      this.sinkCleanup ??= this.writer === null || this.writerTerminal ? Promise.resolve(ok(undefined))
        : invoke(() => Reflect.apply(native.abort, this.writer!, ["Owned stream transfer stopped"]), "Destination stream abortion failed; ownership is retained");
      return Promise.all([this.sourceCleanup, this.sinkCleanup])
        .then(receipts => receipts.find(receipt => receipt.outcome !== "ok") ?? ok(undefined));
    }

    retire(reason = "Stream transfer cancelled by caller", kind = "byte_pipe_cancel"): Promise<Outcome<void>> {
      if (typeof reason !== "string") return Promise.resolve(fail("Stream cancellation reason must be a string", "compatibility_rejected"));
      this.stop(cancellation(kind, reason));
      return this.joinRetirement();
    }

    joinRetirement(): Promise<Outcome<void>> {
      if (this.released) return Promise.resolve(ok(undefined));
      if (this.attempt) return this.attempt;
      const receipt = deferred<Outcome<void>>();
      this.attempt = receipt.promise;
      void (async () => {
        let issue: Failure | null = null;
        try {
          await this.activated.promise;
          // Activation can reenter retirement before a throwing host getter
          // records an ambiguous acquisition. Observe that sticky failure only
          // after activation has finished, so the first attempt cannot retire
          // a task while an unreturned reader/writer may still own its lock.
          issue = this.acquisitionFailure ?? this.hostTurnFailure;
          const terminal = this.operation;
          if (terminal?.outcome === "cancelled" && !this.cancelAccepted && !this.ownerReleased) {
            try {
              const admitted = checked(this.task.cancel(terminal.cancellation.kind, terminal.cancellation.message ?? "Stream transfer cancelled"));
              if (admitted.outcome === "ok") this.cancelAccepted = true;
              else issue = admitted;
            } catch { issue = fail("Stream task cancellation admission failed"); }
          }
          const cleanup = terminal?.outcome === "ok" ? Promise.resolve(ok(undefined)) : this.cleanup();
          const [cleaned] = await Promise.all([cleanup, this.work.promise]);
          if (cleaned.outcome !== "ok") issue ??= cleaned;
          issue ??= this.hostTurnFailure;
          const { native } = this.prepared;
          if (this.signalListener && native.signal) {
            try {
              Reflect.apply(native.remove!, native.signal, ["abort", this.signalListener]);
              this.signalListener = null;
            } catch { issue ??= fail("Stream signal listener cleanup failed"); }
          }
          if (this.reader && !this.readerReleased) {
            try { Reflect.apply(native.releaseReader, this.reader, []); this.readerReleased = true; }
            catch { issue ??= fail("Source stream lock release failed"); }
          }
          if (this.writer && !this.writerReleased) {
            try { Reflect.apply(native.releaseWriter, this.writer, []); this.writerReleased = true; }
            catch { issue ??= fail("Destination stream lock release failed"); }
          }
          const outcome = this.operation ?? fail("Stream transfer finished without a terminal outcome");
          if (!issue && !this.ownerReleased) {
            // Publication is the commit point. Reentrant host cancellation
            // cannot change the proposed terminal while taskJoin is running.
            this.publishing = true;
            const published = checked(this.task.join(outcome));
            if (!sameOutcome(outcome, published)) issue = published.outcome === "ok"
              ? fail("Stream terminal publication returned inconsistent success") : published;
          }
          if (issue) this.completed.resolve(issue);
          else {
            this.released = true;
            active.delete(this.task.key); adopted.delete(this.source); adopted.delete(this.destination);
            this.completed.resolve(outcome.outcome === "ok" ? ok(this.progress()) : outcome);
          }
          receipt.resolve(issue ?? ok(undefined));
        } catch {
          const issue = fail("Stream task retirement failed; ownership is retained");
          this.completed.resolve(issue); receipt.resolve(issue);
        } finally {
          this.publishing = false;
          if (this.attempt === receipt.promise) this.attempt = null;
        }
      })();
      return receipt.promise;
    }
  }

  return {
    start(scopeKey: string, spawn: () => Outcome<BrowserBytePipeTask>, source: ReadableStream<Uint8Array>,
      destination: WritableStream<Uint8Array>, options: BrowserBytePipeOptions = {}): Outcome<BrowserBytePipeHandle> {
      let prepared: Prepared;
      try {
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("Stream owner is unavailable", "capability_denied");
        prepared = prepare(dependencies.globalObject(), source, destination, options);
        if (adopted.has(source) || adopted.has(destination)) return fail("Stream already has an SDK owner", "compatibility_rejected");
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("Stream owner is closing", "capability_denied");
        if (prepared.native.signal && Reflect.apply(prepared.native.aborted!, prepared.native.signal, [])) {
          return cancellation("byte_pipe_cancel", "Stream transfer aborted before admission");
        }
      } catch { return fail("Stream transfer requires unlocked native byte streams and valid options", "compatibility_rejected"); }
      adopted.add(source); adopted.add(destination);
      let spawned: Outcome<BrowserBytePipeTask>;
      try { spawned = spawn(); }
      catch { adopted.delete(source); adopted.delete(destination); return fail("Stream task admission failed"); }
      if (spawned.outcome !== "ok") { adopted.delete(source); adopted.delete(destination); return spawned; }
      const operation = new Operation(scopeKey, spawned.value, source, destination, prepared);
      active.set(spawned.value.key, operation);
      operation.activate();
      return ok(operation.handle());
    },
    cancelTask(key: string, kind: string, reason = "Stream task cancelled"): void {
      const operation = active.get(key);
      if (!operation) return;
      operation.cancelAccepted = true;
      operation.stop(cancellation(kind, reason));
    },
    async drainScopes(scopeKeys: Set<string>, kind: string): Promise<Outcome<void>> {
      const receipts = await Promise.all([...active.values()].filter(operation => scopeKeys.has(operation.scopeKey))
        .map(operation => operation.retire("Stream transfer owner is closing", kind)));
      return receipts.find(receipt => receipt.outcome !== "ok") ?? ok(undefined);
    },
    closeScopes(scopeKeys: Set<string>, kind: string): void {
      for (const operation of active.values()) {
        if (!scopeKeys.has(operation.scopeKey)) continue;
        operation.ownerReleased = true;
        operation.stop(cancellation(kind, "Stream transfer owner was closed"));
        void operation.joinRetirement();
      }
    },
  };
}
