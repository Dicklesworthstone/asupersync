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
      ctx = { state, entries: new Set(), readyWaiters: new Set(), stopped: null };
      sessions.set(state, ctx);
    }
    return ctx;
  }

  function closeSession(state, outcome) {
    const ctx = sessions.get(state);
    if (!ctx || ctx.stopped) return;
    ctx.stopped = outcome;
    for (const notify of ctx.readyWaiters) notify();
    ctx.readyWaiters.clear();
    // Pending host creations retain their reservation until the host settles;
    // open() then disposes any late stream before returning cancellation.
    for (const entry of ctx.entries) entry.stop?.(outcome);
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

  async function discard(host, reader, writer, reason) {
    await Promise.all([
      attempt(() => reader ? reader.cancel(reason) : host?.readable?.cancel(reason)),
      attempt(() => writer ? writer.abort(reason) : host?.writable?.abort(reason)),
    ]);
    release(reader);
    release(writer);
  }

  function bind(ctx, entry, reader, writer) {
    const origin = ctx.state.sessionOrigin;
    const completion = deferred();
    let stopping = null;
    let finished = false;
    let readDone = false;
    let writeDone = false;
    let reading = false;
    let writing = false;
    let finishing = null;

    function complete(outcome) {
      if (finished) return;
      finished = true;
      release(reader);
      release(writer);
      ctx.entries.delete(entry);
      entry.stop = null;
      ctx = null;
      reader = null;
      writer = null;
      completion.resolve(outcome);
    }

    function stop(outcome) {
      if (finished || stopping) return completion.promise;
      stopping = outcome;
      // Native abort waits for an in-flight write. Do not declare the stream
      // drained or recycle admission capacity while host I/O still owns it.
      void discard(null, reader, writer, outcome).then(() => complete(outcome));
      return completion.promise;
    }
    entry.stop = stop;

    function maybeComplete() {
      if (readDone && writeDone && !stopping) complete(ok(undefined));
    }

    const stream = Object.freeze({
      direction: "bidirectional",
      closed: completion.promise,
      async read() {
        if (stopping) return completion.promise;
        if (readDone) return ok({ done: true });
        if (reading) return error("webtransport stream already has a pending read", true);
        reading = true;
        try {
          const result = await reader.read();
          if (stopping) return completion.promise;
          if (result.done) {
            readDone = true;
            release(reader);
            maybeComplete();
            return ok({ done: true });
          }
          if (!(result.value instanceof Uint8Array)) {
            return stop(hostError("read", new TypeError("host returned a non-byte chunk")));
          }
          return ok({ done: false, value: result.value });
        } catch (cause) {
          return stop(hostError("read", cause));
        } finally {
          reading = false;
        }
      },
      async write(value) {
        if (stopping) return completion.promise;
        if (finished || writeDone || finishing) return error("webtransport stream write side is closed");
        if (writing) return error("webtransport stream already has a pending write", true);
        // Reserve before inspecting input: getters can synchronously reenter.
        writing = true;
        try {
          let bytes;
          try { bytes = copyWriteBytes(value); } catch (cause) {
            return error(`webtransport stream write rejected: ${message(cause)}`);
          }
          if (stopping) return completion.promise;
          if (finishing) return error("webtransport stream write side is closing");
          await writer.write(bytes);
          return stopping ? completion.promise : ok(undefined);
        } catch (cause) {
          return stop(hostError("write", cause));
        } finally {
          writing = false;
        }
      },
      finish() {
        if (stopping) return completion.promise;
        if (finishing) return finishing;
        if (writeDone) return Promise.resolve(ok(undefined));
        // Queue FIN behind the single admitted write. Publishing this promise
        // first also rejects writes reentered by a host close callback.
        const result = deferred();
        finishing = result.promise;
        void (async () => {
          try {
            await writer.close();
            if (stopping) return completion.promise;
            writeDone = true;
            release(writer);
            maybeComplete();
            return ok(undefined);
          } catch (cause) {
            return stop(hostError("finish", cause));
          }
        })().then(result.resolve);
        return finishing;
      },
      cancel(reason = "stream cancelled by caller") {
        if (typeof reason !== "string") return Promise.resolve(error("stream cancel reason must be a string"));
        return stop(cancelled(reason, origin));
      },
    });
    // A reset can arrive while the caller is idle. Observe errors immediately,
    // but never treat readable.closed fulfillment as drained buffered bytes.
    void Promise.resolve(reader.closed).catch((cause) => {
      if (!readDone && !finished && !stopping) void stop(hostError("read", cause));
    });
    void Promise.resolve(writer.closed).catch((cause) => {
      if (!writeDone && !finished && !stopping) void stop(hostError("write", cause));
    });
    return stream;
  }

  async function open(request) {
    let state;
    try {
      state = lookup(request.session);
    } catch (cause) {
      return fail("invalid_handle", "permanent", `webtransport stream open rejected: ${message(cause)}`);
    }
    if (!state || state.closed) {
      return fail("invalid_handle", "permanent", "webtransport stream open requires a live session");
    }
    const ctx = context(state);
    if (ctx.entries.size >= WEBTRANSPORT_STREAM_LIMITS.maxStreamsPerSession) {
      return error("webtransport session stream capacity exhausted", true);
    }
    const entry = {};
    ctx.entries.add(entry);
    let bound = false;
    let host;
    let reader;
    let writer;
    try {
      const readiness = await ready(ctx);
      if (readiness) return readiness;
      const create = state.transport.createBidirectionalStream;
      if (ctx.stopped) return ctx.stopped;
      if (typeof create !== "function") return error("WebTransport bidirectional streams are unavailable");
      host = await create.call(state.transport);
      if (ctx.stopped) {
        await discard(host, null, null, ctx.stopped);
        return ctx.stopped;
      }
      reader = host.readable.getReader();
      writer = host.writable.getWriter();
      const stream = bind(ctx, entry, reader, writer);
      bound = true;
      if (ctx.stopped) return await entry.stop(ctx.stopped);
      return ok(stream);
    } catch (cause) {
      await discard(host, reader, writer, cause);
      return ctx.stopped ?? hostError("open", cause);
    } finally {
      if (!bound) ctx.entries.delete(entry);
    }
  }

  return Object.freeze({ open, closeSession });
}
