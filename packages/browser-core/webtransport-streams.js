/**
 * Reliable byte streams attached to an existing, validated WebTransport session.
 * No transport, task, or ambient network authority is created here. The owning
 * facade closes this manager whenever its session or region is closed.
 */
export const WEBTRANSPORT_STREAM_LIMITS = Object.freeze({
  maxStreamsPerSession: 64,
  maxWriteBytes: 1_048_576,
});

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function message(error) {
  try {
    return error instanceof Error ? error.message : String(error);
  } catch {
    return "unprintable host error";
  }
}

// Both throws and rejected host promises are contained. All cleanup attempts
// start even when another resource fails; callers await their settlement.
function attempt(operation) {
  try {
    return Promise.resolve(operation()).catch(() => {});
  } catch {
    return Promise.resolve();
  }
}

function release(lock) {
  try { lock?.releaseLock(); } catch {}
}

function copyWriteBytes(value) {
  let view;
  if (ArrayBuffer.isView(value)) {
    view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  } else if (value instanceof ArrayBuffer) {
    view = new Uint8Array(value);
  } else {
    throw new TypeError("stream writes require an ArrayBuffer or ArrayBufferView");
  }
  if (view.byteLength > WEBTRANSPORT_STREAM_LIMITS.maxWriteBytes) {
    throw new RangeError("stream write exceeds maxWriteBytes; split the byte sequence into chunks");
  }
  // Own the bytes until host backpressure clears: caller mutation must not
  // modify an already-admitted write. Message boundaries are not preserved.
  return view.slice();
}

export function createReliableStreamManager({ lookup, ok, fail, cancelled }) {
  const sessions = new WeakMap();
  const error = (text, transient = false) => fail(
    "compatibility_rejected", transient ? "transient" : "permanent", text,
  );
  const hostError = (operation, cause) => fail(
    "internal_failure", "transient", `webtransport stream ${operation} failed: ${message(cause)}`,
  );

  function context(state) {
    let ctx = sessions.get(state);
    if (!ctx) {
      const incoming = () => ({ reader: null, pending: false, ended: false, terminal: null, cleanup: null });
      ctx = {
        state, entries: new Set(), readyWaiters: new Set(), stopped: null, drained: deferred(),
        incoming: { bidirectional: incoming(), unidirectional: incoming() },
      };
      sessions.set(state, ctx);
    }
    return ctx;
  }

  function closeSession(state, outcome) {
    // Latch closure even if this session has not admitted a stream yet. The
    // owning facade may mark state.closed only after this callback returns.
    const ctx = context(state);
    if (ctx.stopped) return;
    ctx.stopped = outcome;
    // Snapshot before any host cleanup callback can reenter. No new admission
    // can pass the stopped latch; late host results stay owned by these entries.
    const entries = [...ctx.entries];
    const pending = entries.flatMap((entry) => [entry.released.promise, entry.admitted.promise]);
    for (const notify of ctx.readyWaiters) notify();
    ctx.readyWaiters.clear();
    for (const source of Object.values(ctx.incoming)) pending.push(closeCollection(source, outcome));
    // Pending host creations/accepts retain their reservations until the host
    // settles and any late stream has completed its own cleanup.
    for (const entry of entries) entry.stop?.(outcome);
    // All members observe rejection internally and still settle only after
    // cleanup/lock release. Report the first owner outcome, not a second join.
    void Promise.all(pending).then(() => ctx.drained.resolve(outcome));
  }

  function whenClosed(state) {
    return context(state).drained.promise;
  }

  function closeSessionAndDrain(state, outcome) {
    closeSession(state, outcome);
    return whenClosed(state);
  }

  function closeCollection(source, outcome) {
    source.terminal ??= outcome;
    if (source.cleanup) return source.cleanup;
    if (!source.reader) return Promise.resolve();
    const reader = source.reader;
    // Publish before invoking cancel: host hooks may synchronously reenter.
    const completion = deferred();
    source.cleanup = completion.promise;
    void attempt(() => reader.cancel(outcome)).then(() => {
      release(reader);
      if (source.reader === reader) source.reader = null;
      completion.resolve();
    });
    return source.cleanup;
  }

  async function ready(ctx) {
    if (ctx.stopped) return ctx.stopped;
    const result = await new Promise((resolve) => {
      const stopped = () => resolve(ctx.stopped);
      ctx.readyWaiters.add(stopped);
      try {
        Promise.resolve(ctx.state.transport.ready).then(
          () => { ctx.readyWaiters.delete(stopped); resolve(null); },
          (cause) => { ctx.readyWaiters.delete(stopped); resolve(hostError("handshake", cause)); },
        );
      } catch (cause) {
        ctx.readyWaiters.delete(stopped);
        resolve(hostError("handshake", cause));
      }
    });
    return ctx.stopped ?? result;
  }

  async function discard(host, reader, writer, reason, direction, incoming) {
    const receives = direction === "bidirectional" || incoming;
    const sends = direction === "bidirectional" || !incoming;
    await Promise.all([
      receives ? attempt(() => reader ? reader.cancel(reason)
        : (direction === "bidirectional" ? host?.readable : host)?.cancel(reason)) : undefined,
      sends ? attempt(() => writer ? writer.abort(reason)
        : (direction === "bidirectional" ? host?.writable : host)?.abort(reason)) : undefined,
    ]);
    release(reader);
    release(writer);
  }

  function bind(ctx, entry, reader, writer, direction) {
    const origin = ctx.state.sessionOrigin;
    const completion = deferred();
    let stopping = null;
    let finished = false;
    let readDone = reader === null;
    let writeDone = writer === null;
    let reading = false;
    let writing = false;
    let finishing = null;

    function complete(outcome) {
      if (finished) return;
      finished = true;
      release(reader);
      release(writer);
      entry.finished = true;
      if (entry.admissionFinished) ctx.entries.delete(entry);
      entry.stop = null;
      ctx = null;
      reader = null;
      writer = null;
      completion.resolve(outcome);
      entry.released.resolve();
    }

    function stop(outcome) {
      if (finished || stopping) return completion.promise;
      stopping = outcome;
      // Native abort waits for an in-flight write. Do not declare the stream
      // drained or recycle admission capacity while host I/O still owns it.
      void discard(null, reader, writer, outcome, "bidirectional", true)
        .then(() => complete(outcome));
      return completion.promise;
    }
    entry.stop = stop;

    function maybeComplete() {
      if (readDone && writeDone && !stopping) complete(ok(undefined));
    }

    const stream = {
      direction,
      closed: completion.promise,
      cancel(reason = "stream cancelled by caller") {
        if (typeof reason !== "string") return Promise.resolve(error("stream cancel reason must be a string"));
        return stop(cancelled(reason, origin));
      },
    };
    if (reader) stream.read = async function read() {
        if (stopping) return completion.promise;
        if (readDone) return ok({ done: true });
        if (reading) return error("webtransport stream already has a pending read", true);
        reading = true;
        try {
          const read = reader.read;
          if (stopping) return completion.promise;
          const result = await read.call(reader);
          if (stopping) return completion.promise;
          const done = result?.done;
          if (stopping) return completion.promise;
          if (typeof done !== "boolean") {
            return stop(hostError("read", new TypeError("host returned an invalid read result")));
          }
          if (done) {
            readDone = true;
            const completedReader = reader;
            reader = null;
            release(completedReader);
            if (stopping) return completion.promise;
            maybeComplete();
            return ok({ done: true });
          }
          const value = result.value;
          if (stopping) return completion.promise;
          if (!(value instanceof Uint8Array)) {
            return stop(hostError("read", new TypeError("host returned a non-byte chunk")));
          }
          return ok({ done: false, value });
        } catch (cause) {
          return stop(hostError("read", cause));
        } finally {
          reading = false;
        }
    };
    if (writer) {
      stream.write = async function write(value) {
        if (stopping) return completion.promise;
        if (finished || writeDone || finishing) return error("webtransport stream write side is closed");
        if (writing) return error("webtransport stream already has a pending write", true);
        // Reserve before inspecting input: getters can synchronously reenter.
        writing = true;
        try {
          let bytes;
          try { bytes = copyWriteBytes(value); } catch (cause) {
            return stopping ? completion.promise : error(`webtransport stream write rejected: ${message(cause)}`);
          }
          if (stopping) return completion.promise;
          if (finishing) return error("webtransport stream write side is closing");
          const write = writer.write;
          if (stopping) return completion.promise;
          if (finishing) return error("webtransport stream write side is closing");
          await write.call(writer, bytes);
          return stopping ? completion.promise : ok(undefined);
        } catch (cause) {
          return stop(hostError("write", cause));
        } finally {
          writing = false;
        }
      };
      stream.finish = function finish() {
        if (stopping) return completion.promise;
        if (finishing) return finishing;
        if (writeDone) return Promise.resolve(ok(undefined));
        // Queue FIN behind the single admitted write. Publishing this promise
        // first also rejects writes reentered by a host close callback.
        const result = deferred();
        finishing = result.promise;
        void (async () => {
          try {
            const close = writer.close;
            if (stopping) return completion.promise;
            await close.call(writer);
            if (stopping) return completion.promise;
            writeDone = true;
            const completedWriter = writer;
            writer = null;
            release(completedWriter);
            if (stopping) return completion.promise;
            maybeComplete();
            return ok(undefined);
          } catch (cause) {
            return stop(hostError("finish", cause));
          }
        })().then(result.resolve);
        return finishing;
      };
    }
    // A reset can arrive while the caller is idle. Observe errors immediately,
    // but never treat readable.closed fulfillment as drained buffered bytes.
    function observe(lock, side) {
      if (!lock) return;
      const failed = (cause) => {
        if (!(side === "read" ? readDone : writeDone) && !finished && !stopping) {
          void stop(hostError(side, cause));
        }
      };
      try { void Promise.resolve(lock.closed).catch(failed); } catch (cause) { failed(cause); }
    }
    observe(reader, "read");
    observe(writer, "write");
    return Object.freeze(stream);
  }

  function admit(request, direction, incoming) {
    const operation = incoming ? "accept" : "open";
    if (direction !== "bidirectional" && direction !== "unidirectional") {
      return { outcome: error("webtransport stream direction must be bidirectional or unidirectional") };
    }
    let state;
    let ctx;
    try {
      state = lookup(request.session);
      if (!state || state.closed) {
        return { outcome: fail("invalid_handle", "permanent", `webtransport stream ${operation} requires a live session`) };
      }
      ctx = context(state);
    } catch (cause) {
      return { outcome: fail("invalid_handle", "permanent", `webtransport stream ${operation} rejected: ${message(cause)}`) };
    }
    if (ctx.stopped) return { outcome: ctx.stopped };
    const source = incoming ? ctx.incoming[direction] : null;
    if (source?.terminal) return { outcome: source.terminal };
    if (source?.ended) return { outcome: ok(null) };
    if (source?.pending) {
      return { outcome: error(`webtransport session already has a pending ${direction} accept`, true) };
    }
    if (ctx.entries.size >= WEBTRANSPORT_STREAM_LIMITS.maxStreamsPerSession) {
      return { outcome: error("webtransport session stream capacity exhausted", true) };
    }
    // No host getter or await occurs between checking and reserving both bounds.
    const entry = { released: deferred(), admitted: deferred() };
    ctx.entries.add(entry);
    if (source) source.pending = true;
    return { ctx, entry, source };
  }

  async function attach(ctx, entry, host, direction, incoming) {
    let reader = null;
    let writer = null;
    const operation = incoming ? "accept" : "open";
    try {
      if (!ctx.stopped && (direction === "bidirectional" || incoming)) {
        const readable = direction === "bidirectional" ? host.readable : host;
        if (!ctx.stopped) {
          const acquire = readable.getReader;
          if (!ctx.stopped) reader = acquire.call(readable);
        }
      }
      if (!ctx.stopped && (direction === "bidirectional" || !incoming)) {
        const writable = direction === "bidirectional" ? host.writable : host;
        if (!ctx.stopped) {
          const acquire = writable.getWriter;
          if (!ctx.stopped) writer = acquire.call(writable);
        }
      }
      if (ctx.stopped) {
        await discard(host, reader, writer, ctx.stopped, direction, incoming);
        return ctx.stopped;
      }
      if ((direction === "bidirectional" || incoming) && !reader
        || (direction === "bidirectional" || !incoming) && !writer) {
        throw new TypeError("host returned an invalid stream lock");
      }
      const stream = bind(ctx, entry, reader, writer, direction);
      entry.bound = true;
      if (ctx.stopped) {
        entry.stop?.(ctx.stopped);
        return await stream.closed;
      }
      return ok(stream);
    } catch (cause) {
      await discard(host, reader, writer, cause, direction, incoming);
      return ctx.stopped ?? hostError(operation, cause);
    }
  }

  async function open(request, direction = "bidirectional") {
    const admission = admit(request, direction, false);
    if (admission.outcome) return admission.outcome;
    const { ctx, entry } = admission;
    let host;
    try {
      const readiness = await ready(ctx);
      if (readiness) return readiness;
      const transport = ctx.state.transport;
      if (ctx.stopped) return ctx.stopped;
      const create = direction === "bidirectional"
        ? transport.createBidirectionalStream : transport.createUnidirectionalStream;
      if (ctx.stopped) return ctx.stopped;
      if (typeof create !== "function") return error(`WebTransport ${direction} streams are unavailable`);
      host = await create.call(transport);
      return await attach(ctx, entry, host, direction, false);
    } catch (cause) {
      await discard(host, null, null, cause, direction, false);
      return ctx.stopped ?? hostError("open", cause);
    } finally {
      finishAdmission(ctx, entry);
    }
  }

  async function accept(request, direction = "bidirectional") {
    const admission = admit(request, direction, true);
    if (admission.outcome) return admission.outcome;
    const { ctx, entry, source } = admission;
    try {
      const readiness = await ready(ctx);
      if (readiness) return readiness;
      if (!source.reader) {
        const transport = ctx.state.transport;
        if (ctx.stopped) return ctx.stopped;
        const collection = direction === "bidirectional"
          ? transport.incomingBidirectionalStreams : transport.incomingUnidirectionalStreams;
        if (ctx.stopped) return ctx.stopped;
        if (!collection) return error(`WebTransport incoming ${direction} streams are unavailable`);
        const acquire = collection.getReader;
        if (ctx.stopped) return ctx.stopped;
        source.reader = acquire.call(collection);
        if (!source.reader) throw new TypeError("host returned an invalid incoming collection reader");
        const reader = source.reader;
        // Observe failure while idle, but leave buffered incoming endpoints for
        // explicit accept calls even after the collection's producer closes.
        const failed = (cause) => {
          if (source.reader === reader && !source.ended && !ctx.stopped) {
            void closeCollection(source, hostError("accept", cause));
          }
        };
        try { void Promise.resolve(reader.closed).catch(failed); } catch (cause) { failed(cause); }
      }
      if (ctx.stopped || source.terminal) return ctx.stopped ?? source.terminal;
      const reader = source.reader;
      const read = reader.read;
      if (ctx.stopped || source.terminal) return ctx.stopped ?? source.terminal;
      const result = await read.call(reader);
      const done = result?.done;
      if (typeof done !== "boolean") {
        throw new TypeError("host returned an invalid incoming collection result");
      }
      if (done) {
        if (ctx.stopped || source.terminal) return ctx.stopped ?? source.terminal;
        source.ended = true;
        source.reader = null;
        release(reader);
        return ok(null);
      }
      // Even if owner cancellation won while read() was pending, attach owns
      // and disposes the delivered endpoint before admission capacity returns.
      return await attach(ctx, entry, result.value, direction, true);
    } catch (cause) {
      const outcome = ctx.stopped ?? source.terminal ?? hostError("accept", cause);
      if (source.reader) await closeCollection(source, outcome);
      return outcome;
    } finally {
      if (ctx.stopped || source.terminal) {
        await closeCollection(source, ctx.stopped ?? source.terminal);
      }
      source.pending = false;
      finishAdmission(ctx, entry);
    }
  }

  function finishAdmission(ctx, entry) {
    if (!entry.bound) {
      entry.finished = true;
      entry.released.resolve();
    }
    entry.admissionFinished = true;
    entry.admitted.resolve();
    if (entry.finished) ctx.entries.delete(entry);
  }

  return Object.freeze({ open, accept, closeSession, whenClosed, closeSessionAndDrain });
}
