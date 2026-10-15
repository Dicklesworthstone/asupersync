/** Owned streaming uploads against the actual SDK manager and native Streams.
 * The task ABI is an explicit double, not Rust/WASM integration evidence.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_uploads.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { openAsBlob, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_UPLOAD_SOURCE
  ?? new URL("../packages/browser/src/fetch.ts", import.meta.url), "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({ scenario_id: "browser-fetch-owned-uploads",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK, native Request/Streams, localhost HTTP, task-ABI double" }));
const ok = (value) => ({ outcome: "ok", value });
const error = (text) => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "transient", message: text } });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const turn = () => new Promise((resolve) => setImmediate(resolve));
const limits = { timeout: 5000 };

async function fixture(t, options = {}) {
  const calls = { spawn: [], cancel: [], join: [], fetch: [], timers: [], bytes: [] };
  const cleanup = [];
  const handles = [];
  let nextTask = 0;
  class Handle {
    constructor(raw) { this.raw = raw; }
    toJSON() { return { ...this.raw }; }
  }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
      cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn(request) {
      calls.spawn.push(request); options.onSpawn?.();
      return options.spawnReceipt ?? ok(new Handle({ kind: "task", slot: ++nextTask, generation: 1, owner_token: "uploads" }));
    },
    taskCancel(request) { calls.cancel.push(request); return options.cancelReceipt ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join.push({ task, outcome }); return options.joinReceipt ?? outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, Request, Blob, File, ...options.globals });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const module = new SourceTextModule(code, { context });
  await module.link((name) => { assert.equal(name, "@asupersync/browser-core"); return abi; });
  await module.evaluate();
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = module.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "uploads" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://upload.example.test";
  const grant = { rootKey: "runtime:1", authority: prepareBrowserFetchAuthority({
    allowedOrigins: [origin], allowedMethods: ["GET", "HEAD", "POST", "PUT"], maxHeaderCount: 4,
  }) };
  const host = {
    AbortController,
    async fetch(url, init) {
      calls.fetch.push({ url, init });
      if (options.fetch) return options.fetch(url, init);
      const reader = init.body.getReader();
      try {
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          calls.bytes.push(...part.value);
        }
      } finally { reader.releaseLock(); }
      return new Response(null, { status: 204 });
    },
    setTimeout(callback) { calls.timers.push(callback); return calls.timers.length; },
    clearTimeout() {},
  };
  const manager = createBrowserFetchManager({ lookup: (key) => key === scopeKey ? grant : null,
    isClosing: () => options.isClosing?.() ?? false, globalObject: () => host });
  const start = (extra = {}) => {
    const result = manager.start(scope, { url: `${origin}/upload`, method: "POST", ...extra }, null);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  };
  const admit = (body, extra = {}) => {
    const result = start({ body, ...extra });
    assert.equal(result.outcome, "ok", JSON.stringify(result));
    return result.value;
  };
  t.after(async () => {
    for (const release of cleanup) release();
    manager.closeScopes(new Set([scopeKey]), "fixture_cleanup");
    await Promise.all(handles.map((handle) => handle.closed));
  });
  return { calls, cleanup, handles, host, manager, scopeKey, start, admit };
}

function chunks(values, count = {}, onCancel) {
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      count.pulls = (count.pulls ?? 0) + 1;
      if (index < values.length) controller.enqueue(values[index++]);
      else controller.close();
    },
    cancel(reason) { count.cancels = (count.cancels ?? 0) + 1; count.reason = reason; return onCancel?.(reason); },
  }, { highWaterMark: 0 });
}

function parkedFetch(_url, init) {
  return new Promise((resolve, reject) => {
    if (init.signal.aborted) reject(new Error("aborted"));
    else init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
  });
}

async function consume(handle) {
  const parts = [];
  for (;;) {
    const result = await handle.read();
    assert.equal(result.outcome, "ok", JSON.stringify(result));
    if (result.value.done) break;
    parts.push(result.value.value);
  }
  return Buffer.concat(parts);
}

test("a streamed body reaches the peer in order with half duplex and no redirect replay", limits, async (t) => {
  const count = {};
  const body = chunks([Uint8Array.of(1, 2), Uint8Array.of(3)], count);
  const f = await fixture(t);
  const handle = f.admit(body);
  assert.equal((await handle.closed).outcome, "ok");
  assert.deepEqual(f.calls.bytes, [1, 2, 3]);
  assert.equal(f.calls.fetch[0].init.duplex, "half");
  assert.equal(f.calls.fetch[0].init.redirect, "error");
  assert.equal(count.cancels ?? 0, 0);
  assert.equal(body.locked, false);
  assert.equal(f.calls.join.length, 1);
});

test("upload demand is bounded and each admitted chunk is copied", limits, async (t) => {
  const response = deferred();
  const count = {};
  const first = Uint8Array.of(8, 9);
  const body = chunks([first, Uint8Array.of(10)], count);
  const f = await fixture(t, { fetch: () => response.promise });
  f.cleanup.push(() => response.resolve(new Response(null)));
  const handle = f.admit(body);
  await turn();
  assert.equal(count.pulls ?? 0, 0, "neither admission nor native Request validation prefetches");
  const reader = f.calls.fetch[0].init.body.getReader();
  const item = await reader.read();
  first.fill(0);
  assert.deepEqual(Array.from(item.value), [8, 9]);
  await turn();
  assert.equal(count.pulls, 1, "no adapter read-ahead");
  assert.deepEqual(Array.from((await reader.read()).value), [10]);
  assert.equal((await reader.read()).done, true);
  reader.releaseLock();
  assert.equal(f.calls.join.length, 0, "upload EOF alone cannot retire the request");
  response.resolve(new Response(null));
  assert.equal((await handle.closed).outcome, "ok");
});

for (const method of ["GET", "HEAD"]) {
  test(`${method} never acquires or cancels the caller's upload`, limits, async (t) => {
    const count = {};
    const body = chunks([], count);
    const f = await fixture(t);
    assert.equal(f.start({ method, body }).outcome, "err");
    assert.equal(body.locked, false);
    assert.equal(count.pulls ?? 0, 0);
    assert.equal(count.cancels ?? 0, 0);
    assert.equal(f.calls.spawn.length, 0);
    assert.equal(f.calls.fetch.length, 0);
  });
}

for (const maxUploadBytes of [-1, 0.25, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "4", null]) {
  test(`invalid upload limit ${String(maxUploadBytes)} refuses before admission`, limits, async (t) => {
    const body = chunks([]);
    const f = await fixture(t);
    const result = f.start({ body, maxUploadBytes });
    assert.equal(result.outcome, "err");
    assert.match(result.failure.message, /maxUploadBytes/);
    assert.equal(body.locked, false);
    assert.equal(f.calls.spawn.length, 0);
  });
}

test("native stream support is checked without converting it to a string", limits, async (t) => {
  const f = await fixture(t, { globals: { Request: undefined } });
  const body = chunks([]);
  const result = f.start({ body });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "compatibility_rejected");
  assert.equal(body.locked, false);
  assert.equal(f.calls.spawn.length, 0);
});

test("locked and disturbed sources fail without stealing their reader", limits, async (t) => {
  const f = await fixture(t);
  const body = chunks([Uint8Array.of(1)]);
  const reader = body.getReader();
  assert.equal(f.start({ body }).outcome, "err");
  await reader.read();
  reader.releaseLock();
  assert.equal(f.start({ body }).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(body.locked, false);
});

for (const invalid of ["text", new Uint16Array([1]), new Uint8Array(1_048_577)]) {
  test(`invalid upload chunk ${typeof invalid === "string" ? "string" : invalid.constructor.name + ":" + invalid.byteLength} is never sent`, limits, async (t) => {
    const count = {};
    const body = chunks([invalid], count);
    const f = await fixture(t);
    const handle = f.admit(body);
    const terminal = await handle.closed;
    assert.equal(terminal.outcome, "err");
    assert.match(terminal.failure.message, /upload/);
    assert.deepEqual(f.calls.bytes, []);
    assert.equal(body.locked, false);
    assert.equal(count.cancels, 1);
  });
}

test("cumulative upload limits reject an offending chunk before transmission", limits, async (t) => {
  const f = await fixture(t);
  const body = chunks([Uint8Array.of(1, 2), Uint8Array.of(3, 4)]);
  const handle = f.admit(body, { maxUploadBytes: 3 });
  assert.equal((await handle.closed).outcome, "err");
  assert.deepEqual(f.calls.bytes, [1, 2]);
  assert.equal(body.locked, false);
});

test("a zero-byte upload limit permits EOF but not data", limits, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.admit(chunks([]), { maxUploadBytes: 0 }).closed).outcome, "ok");
  assert.equal((await f.admit(chunks([Uint8Array.of(1)]), { maxUploadBytes: 0 }).closed).outcome, "err");
  assert.deepEqual(f.calls.bytes, []);
});

for (const trigger of ["caller", "signal", "deadline", "scope"]) {
  test(`${trigger} cancellation drains a parked upload before publishing its terminal`, limits, async (t) => {
    const held = deferred();
    const count = {};
    const body = new ReadableStream({
      pull() { count.pulls = (count.pulls ?? 0) + 1; },
      cancel() { count.cancels = (count.cancels ?? 0) + 1; return held.promise; },
    }, { highWaterMark: 0 });
    const f = await fixture(t);
    f.cleanup.push(held.resolve);
    const controller = new AbortController();
    const handle = f.admit(body, { signal: controller.signal, timeoutMs: 50 });
    await turn();
    if (trigger === "caller") void handle.cancel("stop upload");
    if (trigger === "signal") controller.abort("stop upload");
    if (trigger === "deadline") f.calls.timers[0]();
    if (trigger === "scope") f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
    assert.equal((await handle.response()).outcome, "cancelled");
    let closed = false;
    void handle.closed.then(() => { closed = true; });
    await turn();
    assert.equal(count.cancels, 1);
    assert.equal(closed, false);
    assert.equal(f.calls.join.length, 0);
    assert.equal(body.locked, true);
    held.resolve();
    assert.equal((await handle.closed).outcome, "cancelled");
    assert.equal(body.locked, false);
    assert.equal(f.calls.join.length, trigger === "scope" ? 0 : 1);
  });
}

test("an early response cancels unused upload bytes and waits for source cleanup", limits, async (t) => {
  const held = deferred();
  const count = {};
  const body = chunks([Uint8Array.of(7)], count, () => held.promise);
  const f = await fixture(t, { fetch: () => new Response("too large", { status: 413 }) });
  f.cleanup.push(held.resolve);
  const handle = f.admit(body);
  let headers = false;
  void handle.response().then(() => { headers = true; });
  await turn();
  assert.equal(headers, false);
  assert.equal(count.pulls ?? 0, 0);
  assert.equal(count.cancels, 1);
  assert.equal(f.calls.join.length, 0);
  held.resolve();
  assert.equal((await handle.response()).value.status, 413);
  assert.equal((await consume(handle)).toString(), "too large");
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(body.locked, false);
});

test("idle source errors abort the owned request even without upload demand", limits, async (t) => {
  let sourceController;
  const body = new ReadableStream({ start(controller) { sourceController = controller; } }, { highWaterMark: 0 });
  const f = await fixture(t, { fetch: parkedFetch });
  const handle = f.admit(body);
  sourceController.error(new Error("producer unavailable"));
  const terminal = await handle.closed;
  assert.equal(terminal.outcome, "err");
  assert.match(terminal.failure.message, /producer unavailable/);
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal(body.locked, false);
});

test("cleanup after cancellation keeps the operation's capacity reserved", limits, async (t) => {
  const held = deferred();
  const f = await fixture(t, { fetch: parkedFetch });
  f.cleanup.push(held.resolve);
  const first = f.admit(chunks([], {}, () => held.promise));
  for (let index = 1; index < 64; index += 1) f.admit(chunks([]));
  assert.equal(f.start({ body: chunks([]) }).outcome, "err");
  void first.cancel();
  await turn();
  assert.equal(f.start({ body: chunks([]) }).outcome, "err");
  held.resolve();
  await first.closed;
  assert.equal(f.start({ body: chunks([]) }).outcome, "ok");
});

for (const preempt of ["signal", "deadline"]) {
  test(`pre-admission ${preempt} cancels an acquired source without pulling or network I/O`, limits, async (t) => {
    const count = {};
    const body = chunks([Uint8Array.of(4)], count);
    const f = await fixture(t);
    const controller = new AbortController();
    controller.abort("already stopped");
    const handle = f.admit(body, preempt === "signal" ? { signal: controller.signal } : { timeoutMs: 0 });
    assert.equal((await handle.closed).outcome, "cancelled");
    assert.equal(f.calls.fetch.length, 0);
    assert.equal(count.pulls ?? 0, 0);
    assert.equal(count.cancels, 1);
    assert.equal(body.locked, false);
  });
}

test("late source locking during task admission fails without consuming another reader", limits, async (t) => {
  const body = chunks([Uint8Array.of(1)]);
  let reader;
  const f = await fixture(t, { onSpawn() { reader = body.getReader(); } });
  const handle = f.admit(body);
  assert.equal((await handle.closed).outcome, "err");
  assert.equal(f.calls.fetch.length, 0);
  assert.equal(body.locked, true);
  assert.deepEqual(Array.from((await reader.read()).value), [1]);
  reader.releaseLock();
});

test("early-response cleanup rejection cannot become successful terminal publication", limits, async (t) => {
  const body = chunks([], {}, () => Promise.reject(new Error("producer cleanup failed")));
  const f = await fixture(t, { fetch: () => new Response(null) });
  const handle = f.admit(body);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.match(outcome.failure.message, /producer cleanup failed/);
  assert.equal(body.locked, false);
  assert.equal(f.calls.join.length, 1);
});

test("source cleanup rejection preserves an already selected cancellation", limits, async (t) => {
  const body = chunks([], {}, () => Promise.reject(new Error("secondary cleanup error")));
  const f = await fixture(t, { fetch: parkedFetch });
  const handle = f.admit(body);
  const outcome = await handle.cancel("primary reason");
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.message, "primary reason");
  assert.equal(body.locked, false);
});

test("detached upload chunks are rejected instead of silently becoming empty", limits, async (t) => {
  const bytes = Uint8Array.of(1);
  structuredClone(bytes.buffer, { transfer: [bytes.buffer] });
  const f = await fixture(t);
  const body = chunks([bytes]);
  const outcome = await f.admit(body).closed;
  assert.equal(outcome.outcome, "err");
  assert.deepEqual(f.calls.bytes, []);
  assert.equal(body.locked, false);
});

test("source method shadows cannot divert upload reading or cleanup", limits, async (t) => {
  const body = chunks([Uint8Array.of(4, 5)]);
  Object.defineProperty(body, "getReader", { get() { throw new Error("shadow must not run"); } });
  Object.defineProperty(body, "cancel", { get() { throw new Error("shadow must not run"); } });
  const f = await fixture(t);
  assert.equal((await f.admit(body).closed).outcome, "ok");
  assert.deepEqual(f.calls.bytes, [4, 5]);
});

test("buffered bodies do not acquire streaming support or bypass their original cap", limits, async (t) => {
  const f = await fixture(t, { globals: { Request: undefined, ReadableStreamDefaultReader: undefined },
    fetch: (_url, init) => { assert.equal(init.duplex, undefined); return new Response(null); } });
  assert.equal((await f.admit(Uint8Array.of(1)).closed).outcome, "ok");
  assert.equal(f.start({ body: new Uint8Array(1_048_577), maxUploadBytes: 10_000_000 }).outcome, "err");
});

test("terminal-publication refusal keeps a drained upload's task credit", limits, async (t) => {
  const f = await fixture(t, { joinReceipt: error("publication refused") });
  const first = f.admit(chunks([Uint8Array.of(1)]));
  assert.equal((await first.closed).failure.message, "publication refused");
  for (let index = 1; index < 64; index += 1) f.admit(chunks([]));
  await Promise.all(f.handles.map((handle) => handle.closed));
  assert.equal(f.start({ body: chunks([]) }).outcome, "err");
  assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
});

async function httpServer(t, handler) {
  const server = createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

test("a real HTTP peer receives a multi-megabyte upload before its producer reaches EOF", { timeout: 10000 }, async (t) => {
  const firstByte = deferred();
  const release = deferred();
  let finishedSource = false;
  const origin = await httpServer(t, (request, response) => {
    let bytes = 0;
    const hash = createHash("sha256");
    request.on("data", (chunk) => { bytes += chunk.length; hash.update(chunk); firstByte.resolve(); });
    request.on("end", () => response.end(JSON.stringify({ bytes, digest: hash.digest("hex") })));
  });
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  f.cleanup.push(release.resolve);
  const block = new Uint8Array(131_072).fill(37);
  const total = 24;
  const expected = createHash("sha256");
  for (let index = 0; index < total; index += 1) expected.update(block);
  let produced = 0;
  const source = new ReadableStream({
    async pull(controller) {
      if (produced === 1) await release.promise;
      if (produced++ < total) controller.enqueue(block);
      else { finishedSource = true; controller.close(); }
    },
    cancel() { release.resolve(); },
  }, { highWaterMark: 0 });
  const handle = f.admit(source, { maxUploadBytes: total * block.length });
  await firstByte.promise;
  assert.equal(finishedSource, false, "a buffered implementation cannot satisfy this handshake");
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  const receipt = JSON.parse((await consume(handle)).toString());
  assert.equal(receipt.bytes, total * block.length);
  assert.equal(receipt.digest, expected.digest("hex"));
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(source.locked, false);
});

test("upload cancellation disconnects a real HTTP peer while the source is parked", { timeout: 10000 }, async (t) => {
  const received = deferred();
  const disconnected = deferred();
  const origin = await httpServer(t, (request, _response) => {
    request.on("data", () => received.resolve());
    request.on("close", disconnected.resolve);
  });
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  let sent = false;
  let cancels = 0;
  const source = new ReadableStream({
    pull(controller) { if (!sent) { sent = true; controller.enqueue(Uint8Array.of(1, 2)); } },
    cancel() { cancels += 1; },
  }, { highWaterMark: 0 });
  const handle = f.admit(source);
  await received.promise;
  assert.equal((await handle.cancel("stop live upload")).outcome, "cancelled");
  await disconnected.promise;
  assert.equal(cancels, 1);
  assert.equal(source.locked, false);
  assert.equal(f.calls.join.length, 1);
});


// Delay/fault doubles wrap native Blob slice/read primitives; no production
// injection hook is needed. The objects themselves retain native Blob slots.
function instrumentBlobs(options = {}) {
  const slices = [];
  const reads = [];
  function HostBlob() { throw new Error("the adapter must not construct a Blob"); }
  Object.defineProperty(HostBlob.prototype, "size", Object.getOwnPropertyDescriptor(Blob.prototype, "size"));
  HostBlob.prototype.slice = function (start, end) {
    slices.push([start, end]);
    return Reflect.apply(Blob.prototype.slice, this, [start, end]);
  };
  HostBlob.prototype.arrayBuffer = async function () {
    reads.push(this.size);
    await options.wait?.promise;
    if (options.reject) throw new Error("file read failed");
    const bytes = await Reflect.apply(Blob.prototype.arrayBuffer, this, []);
    return options.truncate ? bytes.slice(0, Math.max(0, bytes.byteLength - 1)) : bytes;
  };
  return { HostBlob, slices, reads };
}

test("Blob uploads send only raw bytes and leave MIME/header authority explicit", limits, async (t) => {
  const f = await fixture(t);
  const body = new Blob([Uint8Array.of(2, 4, 6)], { type: "application/private-format" });
  assert.equal((await f.admit(body).closed).outcome, "ok");
  assert.deepEqual(f.calls.bytes, [2, 4, 6]);
  assert.deepEqual(Array.from(f.calls.fetch[0].init.headers), []);
  assert.equal(f.calls.fetch[0].init.duplex, "half");
});

test("File uploads never synthesize filenames or multipart metadata", limits, async (t) => {
  const f = await fixture(t);
  const body = new File(["payload"], "private-name.txt", { type: "text/plain", lastModified: 1234 });
  assert.equal((await f.admit(body, { headers: { "content-type": "application/octet-stream" } }).closed).outcome, "ok");
  assert.equal(Buffer.from(f.calls.bytes).toString(), "payload");
  assert.deepEqual(Array.from(f.calls.fetch[0].init.headers, pair => Array.from(pair)), [["content-type", "application/octet-stream"]]);
});

test("known Blob size is rejected before task admission or file reads", limits, async (t) => {
  const io = instrumentBlobs();
  const f = await fixture(t, { globals: { Blob: io.HostBlob } });
  const result = f.start({ body: new Blob(["large"]), maxUploadBytes: 4 });
  assert.equal(result.outcome, "err");
  assert.match(result.failure.message, /maxUploadBytes/);
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(f.calls.fetch.length, 0);
  assert.deepEqual(io.slices, []);
  assert.deepEqual(io.reads, []);
});

test("Blob chunks are sliced only on demand and never exceed the chunk cap", limits, async (t) => {
  const io = instrumentBlobs();
  const ready = deferred();
  const f = await fixture(t, { globals: { Blob: io.HostBlob }, fetch: () => ready.promise });
  f.cleanup.push(() => ready.resolve(new Response(null)));
  const size = 2 * 1_048_576 + 17;
  const body = new Blob([new Uint8Array(size).fill(11)]);
  const handle = f.admit(body, { maxUploadBytes: size });
  await turn();
  assert.deepEqual(io.reads, [], "no eager file I/O at admission");
  const reader = f.calls.fetch[0].init.body.getReader();
  for (const [index, expected] of [1_048_576, 1_048_576, 17].entries()) {
    const item = await reader.read();
    assert.equal(item.value.byteLength, expected);
    assert.equal(item.value[0], 11);
    assert.equal(item.value.at(-1), 11);
    await turn();
    assert.equal(io.reads.length, index + 1, "no file-read prefetch");
  }
  assert.equal((await reader.read()).done, true);
  reader.releaseLock();
  assert.deepEqual(io.reads, [1_048_576, 1_048_576, 17]);
  assert.deepEqual(io.slices, [[0, 1_048_576], [1_048_576, 2_097_152], [2_097_152, size]]);
  ready.resolve(new Response(null));
  assert.equal((await handle.closed).outcome, "ok");
});

for (const trigger of ["caller", "signal", "deadline", "scope"]) {
  test(`${trigger} cancellation waits for an in-flight Blob read without admitting another slice`, limits, async (t) => {
    const held = deferred();
    const io = instrumentBlobs({ wait: held });
    const f = await fixture(t, { globals: { Blob: io.HostBlob } });
    f.cleanup.push(held.resolve);
    const controller = new AbortController();
    const handle = f.admit(new Blob(["pending data"]), { signal: controller.signal, timeoutMs: 10 });
    await turn();
    assert.deepEqual(io.reads, [12]);
    if (trigger === "caller") void handle.cancel("cancel file");
    if (trigger === "signal") controller.abort("cancel file");
    if (trigger === "deadline") f.calls.timers[0]();
    if (trigger === "scope") f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
    let settled = false;
    void handle.closed.then(() => { settled = true; });
    await turn();
    assert.equal(settled, false, "native read settlement remains an owned obligation");
    assert.equal(f.calls.join.length, 0);
    held.resolve();
    assert.equal((await handle.closed).outcome, "cancelled");
    assert.equal(io.slices.length, 1);
    assert.deepEqual(f.calls.bytes, [], "cancelled read's late bytes must not be transmitted");
  });
}

for (const fault of ["reject", "truncate"]) {
  test(`Blob ${fault} failure is not published as a successful upload`, limits, async (t) => {
    const io = instrumentBlobs({ [fault]: true });
    const f = await fixture(t, { globals: { Blob: io.HostBlob } });
    const result = await f.admit(new Blob(["abc"])).closed;
    assert.equal(result.outcome, "err");
    assert.deepEqual(f.calls.bytes, []);
    assert.equal(f.calls.join.length, 1);
  });
}

test("a Blob read rejection arriving after cancellation preserves the first cause", limits, async (t) => {
  const held = deferred();
  const io = instrumentBlobs({ wait: held, reject: true });
  const f = await fixture(t, { globals: { Blob: io.HostBlob } });
  f.cleanup.push(held.resolve);
  const handle = f.admit(new Blob(["pending"]));
  await turn();
  const cancel = handle.cancel("first reason");
  held.resolve();
  const result = await cancel;
  assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.message, "first reason");
});

for (const preempt of ["signal", "deadline"]) {
  test(`a preempting ${preempt} does not start a Blob read`, limits, async (t) => {
    const io = instrumentBlobs();
    const f = await fixture(t, { globals: { Blob: io.HostBlob } });
    const controller = new AbortController();
    controller.abort();
    const handle = f.admit(new Blob(["not read"]), preempt === "signal" ? { signal: controller.signal } : { timeoutMs: 0 });
    assert.equal((await handle.closed).outcome, "cancelled");
    assert.deepEqual(io.slices, []);
    assert.deepEqual(io.reads, []);
    assert.equal(f.calls.fetch.length, 0);
  });
}

test("Blob instance shadows do not alter size, bytes or implicit metadata", limits, async (t) => {
  const f = await fixture(t);
  const body = new File([Uint8Array.of(1, 3, 5)], "hidden.bin");
  for (const name of ["size", "slice", "arrayBuffer", "stream", "type", "name"]) {
    Object.defineProperty(body, name, { get() { throw new Error(`shadowed ${name}`); } });
  }
  assert.equal((await f.admit(body).closed).outcome, "ok");
  assert.deepEqual(f.calls.bytes, [1, 3, 5]);
});

test("empty Blob uploads require no slice reads and permit a zero byte limit", limits, async (t) => {
  const io = instrumentBlobs();
  const f = await fixture(t, { globals: { Blob: io.HostBlob } });
  assert.equal((await f.admit(new Blob(), { maxUploadBytes: 0 }).closed).outcome, "ok");
  assert.deepEqual(io.reads, []);
  assert.deepEqual(io.slices, []);
});

test("filesystem-backed Blob bytes reach a real HTTP peer with an exact digest", { timeout: 10000 }, async (t) => {
  const path = process.env.ASUPERSYNC_FETCH_UPLOAD_SOURCE
    ?? fileURLToPath(new URL("../packages/browser/src/fetch.ts", import.meta.url));
  const expected = readFileSync(path);
  const file = await openAsBlob(path);
  const origin = await httpServer(t, (request, response) => {
    const hash = createHash("sha256");
    let bytes = 0;
    request.on("data", chunk => { hash.update(chunk); bytes += chunk.length; });
    request.on("end", () => response.end(JSON.stringify({ bytes, digest: hash.digest("hex") })));
  });
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  const handle = f.admit(file);
  const receipt = JSON.parse((await consume(handle)).toString());
  assert.equal(receipt.bytes, expected.length);
  assert.equal(receipt.digest, createHash("sha256").update(expected).digest("hex"));
  assert.equal((await handle.closed).outcome, "ok");
});
