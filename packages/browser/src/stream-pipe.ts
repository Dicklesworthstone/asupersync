/** Region-owned native WHATWG stream pipes. No new host authority is created. */
import type { Outcome } from "@asupersync/browser-core";

export interface BrowserStreamPipeOptions {
  /** Borrowed unmodified same-realm native signal; pre-abort takes no ownership. */
  signal?: AbortSignal | null;
}

export interface BrowserStreamPipeHandle {
  /** First terminal receipt, after native settlement, remaining cleanup and publication. */
  readonly closed: Promise<Outcome<void>>;
  /** Stop the pipe and await native settlement, remaining cleanup and publication. */
  cancel(reason?: string): Promise<Outcome<void>>;
  /** Independent cleanup receipt; retries refused cancellation/publication. */
  retire(reason?: string): Promise<Outcome<void>>;
}

/** Internal adapter to the region's existing ABI task ledger. */
export interface BrowserStreamPipeTask {
  readonly key: string;
  cancel(kind: string, message: string): Outcome<void>;
  join(outcome: Outcome<void>): Outcome<void>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = (): Outcome<void> => Object.freeze({ outcome: "ok", value: undefined });
const fail = (message: string, code: "capability_denied" | "compatibility_rejected" | "internal_failure" = "internal_failure",
  recoverability: "transient" | "permanent" = "permanent"): Failure =>
  Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
function cancelled(kind: string, reason: string): Failure {
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind, phase: "completed", origin_region: "browser-stream-pipe", origin_task: null,
    timestamp_nanos: 0, message: reason.slice(0, 512), truncated: reason.length > 512,
  }) });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function checked(value: unknown): Outcome<void> {
  try {
    if (!value || typeof value !== "object") return fail("Invalid stream pipe task receipt");
    const receipt = value as Outcome<void>;
    switch (receipt.outcome) {
      case "ok": return receipt.value === undefined ? ok() : fail("Invalid stream pipe task success");
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
  } catch { /* Receipt errors must not render host exceptions or authority. */ }
  return fail("Invalid stream pipe task receipt");
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

function prepare(host: Record<string, unknown> | undefined, readable: ReadableStream<unknown>,
  writable: WritableStream<unknown>, options: BrowserStreamPipeOptions) {
  if (!options || typeof options !== "object" || Array.isArray(options)) throw new TypeError("Invalid pipe options");
  const Readable = host?.ReadableStream as typeof ReadableStream | undefined;
  const Writable = host?.WritableStream as typeof WritableStream | undefined;
  const Controller = host?.AbortController as typeof AbortController | undefined;
  const Signal = host?.AbortSignal as typeof AbortSignal | undefined;
  const Events = host?.EventTarget as typeof EventTarget | undefined;
  if (typeof Readable !== "function" || typeof Writable !== "function" || typeof Controller !== "function"
      || typeof Signal !== "function" || typeof Events !== "function") throw new TypeError("Native pipe support is unavailable");
  const readableLocked = Object.getOwnPropertyDescriptor(Readable.prototype, "locked")?.get;
  const writableLocked = Object.getOwnPropertyDescriptor(Writable.prototype, "locked")?.get;
  const pipeTo = Readable.prototype.pipeTo;
  const cancelSource = Readable.prototype.cancel, abortDestination = Writable.prototype.abort;
  const abort = Controller.prototype.abort;
  const signalOf = Object.getOwnPropertyDescriptor(Controller.prototype, "signal")?.get;
  const aborted = Object.getOwnPropertyDescriptor(Signal.prototype, "aborted")?.get;
  const add = Events.prototype.addEventListener, remove = Events.prototype.removeEventListener;
  if ([readableLocked, writableLocked, pipeTo, cancelSource, abortDestination, abort, signalOf, aborted, add, remove]
      .some(fn => typeof fn !== "function")
      || Object.getPrototypeOf(readable) !== Readable.prototype || Object.getPrototypeOf(writable) !== Writable.prototype
      || Reflect.apply(readableLocked!, readable, []) || Reflect.apply(writableLocked!, writable, [])) {
    throw new TypeError("Expected unlocked same-realm native streams");
  }
  const controller = new Controller();
  const privateSignal = Reflect.apply(signalOf!, controller, []) as AbortSignal;
  Reflect.apply(aborted!, privateSignal, []);
  let signal: AbortSignal | undefined;
  const supplied = options.signal;
  if (supplied != null) {
    if (Object.getPrototypeOf(supplied) !== Signal.prototype || typeof Signal.any !== "function"
        || Object.getOwnPropertyDescriptor(supplied, "aborted") || Object.getOwnPropertyDescriptor(supplied, "reason")) {
      throw new TypeError("Expected an unmodified same-realm native AbortSignal");
    }
    Reflect.apply(aborted!, supplied, []);
    // An earlier caller listener cannot suppress the private dependent signal.
    signal = Reflect.apply(Signal.any, Signal, [[supplied]]) as AbortSignal;
    Reflect.apply(aborted!, signal, []);
  }
  // Options may execute caller getters. Recheck before taking ownership.
  if (Reflect.apply(readableLocked!, readable, []) || Reflect.apply(writableLocked!, writable, [])) {
    throw new TypeError("Stream locked during pipe preflight");
  }
  return { pipeTo, cancelSource, abortDestination, readableLocked: readableLocked!, writableLocked: writableLocked!,
    abort, controller, privateSignal, signal, aborted: aborted!, add, remove };
}

/**
 * Native pipeTo owns backpressure, error propagation and both stream locks.
 * Failed cancellation also retires endpoints left open by native pipeTo. Native
 * APIs cannot replay cleanup on terminal streams or expose earlier hook promises.
 * Chunks are not converted, copied, size-limited or rolled back; producer/consumer
 * queues stay host-owned, and arbitrary host promises cannot be forced to settle.
 */
export function createBrowserStreamPipeManager(dependencies: {
  globalObject(): Record<string, unknown> | undefined;
  isClosing(scopeKey: string): boolean;
  isTracked(scopeKey: string): boolean;
  /** Shared SDK endpoint reservations, including tasks awaiting publication. */
  endpoints?: WeakSet<object>;
}) {
  const active = new Map<string, Operation>();
  const owned = dependencies.endpoints ?? new WeakSet<object>();
  type Prepared = ReturnType<typeof prepare>;

  class Operation {
    readonly closed = deferred<Outcome<void>>();
    readonly nativeSettled = deferred<void>();
    readonly activated = deferred<void>();
    readonly abortReason = Object.freeze({ message: "Owned stream pipe cancelled" });
    terminal: Outcome<void> | null = null;
    cancellation: Failure | null = null;
    cleanupFailure: Failure | null = null;
    recoveryFailure: Failure | null = null;
    readonly recovered = { source: false, destination: false };
    nativeDone = false;
    needsCancel = false;
    cancelAccepted = false;
    abortRequested = false;
    ownerReleased = false;
    released = false;
    kind = "stream_pipe_cancel";
    reason = "Stream pipe cancelled by caller";
    signalListener: EventListener | null = null;
    attempt: Promise<Outcome<void>> | null = null;
    abortFailure: Failure | null = null;
    constructor(readonly scopeKey: string, readonly task: BrowserStreamPipeTask,
      readonly readable: ReadableStream<unknown>, readonly writable: WritableStream<unknown>, readonly prepared: Prepared) {}

    handle(): BrowserStreamPipeHandle {
      return Object.freeze({ closed: this.closed.promise,
        cancel: (reason?: string) => this.cancel(reason), retire: (reason?: string) => this.retire(reason) });
    }
    complete(failed: boolean, error?: unknown): void {
      if (this.nativeDone) return;
      this.nativeDone = true;
      // Native pipeTo returns our private reason only when abort cleanup was
      // successful. A distinct rejection is a real source/sink/cleanup error.
      this.terminal = failed
        ? error === this.abortReason && this.cancellation ? this.cancellation : fail("Native stream pipe failed")
        : this.cancellation ?? ok();
      if (failed && this.cancellation && error !== this.abortReason && this.terminal.outcome !== "ok") {
        this.cleanupFailure = this.terminal;
      }
      this.nativeSettled.resolve();
      void this.joinRetirement();
    }
    activate(): void {
      try {
        const native = this.prepared;
        if (native.signal) {
          this.signalListener = () => this.requestCancel("Stream pipe cancelled by caller signal", "stream_pipe_signal");
          Reflect.apply(native.add, native.signal, ["abort", this.signalListener, { once: true }]);
          if (Reflect.apply(native.aborted, native.signal, [])) this.requestCancel("Stream pipe cancelled by caller signal", "stream_pipe_signal");
        }
        if (dependencies.isClosing(this.scopeKey) || !dependencies.isTracked(this.scopeKey)) {
          this.requestCancel("Stream pipe owner is closing", "scope_close");
        }
        // This native call acquires both locks synchronously, before start()
        // returns. No caller getter can change the snapshotted pipe options.
        const pipe = Reflect.apply(native.pipeTo, this.readable, [this.writable, { signal: native.privateSignal }]) as Promise<void>;
        void Promise.resolve(pipe).then(() => this.complete(false), error => this.complete(true, error));
      } catch { this.complete(true); }
      finally { this.activated.resolve(); }
    }
    requestCancel(reason: string, kind: string): void {
      if (this.nativeDone || this.released) return;
      if (!this.cancellation) {
        this.kind = kind; this.reason = reason.slice(0, 512);
        this.cancellation = cancelled(kind, reason); this.needsCancel = true;
      }
      if (!this.abortRequested) {
        try {
          Reflect.apply(this.prepared.abort, this.prepared.controller, [this.abortReason]);
          this.abortRequested = true; this.abortFailure = null;
        } catch { this.abortFailure = fail("Stream pipe native cancellation failed"); }
      }
      void this.joinRetirement();
    }
    cancel(reason = "Stream pipe cancelled by caller"): Promise<Outcome<void>> {
      return this.retire(reason).then(receipt => receipt.outcome === "ok" ? this.closed.promise : receipt);
    }
    retire(reason = "Stream pipe retired by caller", kind = "stream_pipe_cancel"): Promise<Outcome<void>> {
      if (typeof reason !== "string") return Promise.resolve(fail("Stream pipe cancellation reason must be a string", "compatibility_rejected"));
      if (!this.nativeDone) this.requestCancel(reason, kind);
      return this.joinRetirement();
    }
    async recoverEndpoint(side: "source" | "destination"): Promise<Failure | null> {
      if (this.recovered[side]) return null;
      const native = this.prepared, source = side === "source";
      const endpoint = source ? this.readable : this.writable;
      const locked = source ? native.readableLocked : native.writableLocked;
      const cleanup = source ? native.cancelSource : native.abortDestination;
      try {
        // No await between the native lock check and admission. A locked stream
        // has refused cleanup; an unlocked native call makes it terminal even
        // if its underlying cleanup hook subsequently rejects.
        if (Reflect.apply(locked, endpoint, [])) {
          return fail("Stream pipe " + side + " cleanup is blocked by a native lock", "compatibility_rejected", "transient");
        }
        const completion = Reflect.apply(cleanup, endpoint, [this.abortReason]) as Promise<void>;
        try { await completion; }
        catch {
          this.recoveryFailure ??= fail(source
            ? "Stream pipe source cancellation failed" : "Stream pipe destination abort failed");
        }
        this.recovered[side] = true;
        return null;
      } catch {
        return fail("Stream pipe " + side + " cleanup could not start", "compatibility_rejected", "transient");
      }
    }
    joinRetirement(): Promise<Outcome<void>> {
      if (this.released) return Promise.resolve(ok());
      if (this.attempt) return this.attempt;
      const receipt = deferred<Outcome<void>>();
      this.attempt = receipt.promise;
      void (async () => {
        let issue: Failure | null = null;
        try {
          await this.activated.promise;
          if (this.needsCancel && !this.cancelAccepted && !this.ownerReleased) {
            try {
              const admitted = checked(this.task.cancel(this.kind, this.reason));
              if (admitted.outcome === "ok") this.cancelAccepted = true;
              else issue = admitted;
            } catch { issue = fail("Stream pipe task cancellation failed"); }
          }
          if (this.abortFailure && !this.nativeDone) { receipt.resolve(issue ?? this.abortFailure); return; }
          await this.nativeSettled.promise;
          if (this.cleanupFailure) {
            // An in-flight write rejection can make native pipeTo skip its
            // queued abort/cancel action. Recover after it releases the locks.
            // Each operation is idempotent on terminal native streams; an
            // errored writable cannot replay its underlying abort callback.
            // Run both even when ABI cancellation or the other endpoint failed.
            const recovery = await Promise.all([this.recoverEndpoint("source"), this.recoverEndpoint("destination")]);
            issue ??= recovery.find(failure => failure !== null) ?? null;
            if (Reflect.apply(this.prepared.readableLocked, this.readable, [])
                || Reflect.apply(this.prepared.writableLocked, this.writable, [])) {
              issue ??= fail("Stream pipe cleanup is blocked by a native lock", "compatibility_rejected", "transient");
            }
          }
          if (this.signalListener && this.prepared.signal) {
            try {
              Reflect.apply(this.prepared.remove, this.prepared.signal, ["abort", this.signalListener]);
              this.signalListener = null;
            } catch { issue ??= fail("Stream pipe signal cleanup failed"); }
          }
          const terminal = this.terminal ?? fail("Stream pipe terminal receipt is unavailable");
          if (!issue && !this.ownerReleased) {
            const published = checked(this.task.join(terminal));
            if (!sameOutcome(terminal, published)) issue = published.outcome === "ok"
              ? fail("Stream pipe terminal publication returned inconsistent success") : published;
          }
          if (issue) this.closed.resolve(issue);
          else {
            this.released = true; active.delete(this.task.key);
            owned.delete(this.readable); owned.delete(this.writable);
            this.closed.resolve(terminal);
          }
          // A native cleanup rejection is reported to the in-flight retirement
          // attempt even though the settled pipe has released both locks. The
          // accepted terminal task is retired; a later owner-close retry can
          // finish without pretending the first cleanup attempt succeeded.
          receipt.resolve(issue ?? this.recoveryFailure ?? this.cleanupFailure ?? ok());
        } catch {
          const issue = fail("Stream pipe retirement failed");
          if (this.nativeDone) this.closed.resolve(issue);
          receipt.resolve(issue);
        } finally { if (this.attempt === receipt.promise) this.attempt = null; }
      })();
      return receipt.promise;
    }
  }

  return {
    start(scopeKey: string, admit: () => Outcome<BrowserStreamPipeTask>, readable: ReadableStream<unknown>,
      writable: WritableStream<unknown>, options: BrowserStreamPipeOptions = {}): Outcome<BrowserStreamPipeHandle> {
      let prepared: Prepared;
      try {
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("Stream pipe owner is unavailable", "capability_denied");
        prepared = prepare(dependencies.globalObject(), readable, writable, options);
        if (owned.has(readable) || owned.has(writable)) return fail("Stream already has an SDK pipe owner", "compatibility_rejected");
        if (!dependencies.isTracked(scopeKey) || dependencies.isClosing(scopeKey)) return fail("Stream pipe owner is closing", "capability_denied");
        if (prepared.signal && Reflect.apply(prepared.aborted, prepared.signal, [])) {
          return cancelled("stream_pipe_signal", "Stream pipe cancelled by caller signal");
        }
      } catch { return fail("Stream pipe requires unlocked native streams and valid options", "compatibility_rejected"); }
      owned.add(readable); owned.add(writable);
      let task: BrowserStreamPipeTask;
      try {
        const admitted = admit();
        if (admitted.outcome !== "ok") {
          owned.delete(readable); owned.delete(writable);
          const refusal = checked(admitted);
          return refusal.outcome === "ok" ? fail("Invalid stream pipe task admission") : refusal;
        }
        const original = admitted.value;
        const key = original.key, cancel = original.cancel, join = original.join;
        if (typeof key !== "string" || key.length === 0 || active.has(key) || typeof cancel !== "function" || typeof join !== "function") {
          throw new TypeError("Invalid stream pipe task adapter");
        }
        task = { key, cancel: (kind, reason) => Reflect.apply(cancel, original, [kind, reason]) as Outcome<void>,
          join: terminal => Reflect.apply(join, original, [terminal]) as Outcome<void> };
      } catch {
        owned.delete(readable); owned.delete(writable);
        return fail("Stream pipe task admission failed");
      }
      const operation = new Operation(scopeKey, task, readable, writable, prepared);
      active.set(task.key, operation);
      operation.activate();
      return Object.freeze({ outcome: "ok", value: operation.handle() });
    },
    cancelTask(taskKey: string, kind: string, reason = "Stream pipe task cancelled"): void {
      const operation = active.get(taskKey);
      if (!operation) return;
      operation.cancelAccepted = true;
      operation.requestCancel(reason, kind);
    },
    async drainScopes(scopeKeys: Set<string>, kind: string): Promise<Outcome<void>> {
      const receipts = await Promise.all([...active.values()].filter(operation => scopeKeys.has(operation.scopeKey))
        .map(operation => operation.retire("Stream pipe owner is closing", kind)));
      return receipts.find(receipt => receipt.outcome !== "ok") ?? ok();
    },
    closeScopes(scopeKeys: Set<string>, kind: string): void {
      for (const operation of active.values()) {
        if (!scopeKeys.has(operation.scopeKey)) continue;
        operation.ownerReleased = true;
        operation.requestCancel("Stream pipe owner was closed", kind);
        void operation.joinRetirement();
      }
    },
  };
}
