/**
 * Executes the actual browser SDK and native WHATWG stream implementations.
 * Only the unrelated generated WASM ABI exports are substituted (and any call
 * to them fails). This is JS/WHATWG boundary proof, not browser-engine or WASM
 * execution. Run with Node 24+:
 * node --experimental-vm-modules --test scripts/test_browser_native_stream_lifecycle.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sdkPath = process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url));
const source = readFileSync(sdkPath, "utf8");
const sdkJavaScript = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({
  scenario_id: "browser-native-stream-lifecycle",
  sdk_source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK, native WHATWG streams and controlled host edge cases",
  no_claim: ["browser-engine execution", "Rust dispatcher", "packaged WASM"],
}));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
const turn = () => new Promise((resolve) => setImmediate(resolve));
const observe = (promise) => promise.then(
  (value) => ({ ok: true, value }), (error) => ({ ok: false, error }),
);
async function promptly(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("operation ignored terminal stream state")), 750);
    })]);
  } finally { clearTimeout(timer); }
}
function rejected(result, reason) {
  assert.equal(result.ok, false, "operation must reject");
  assert.equal(result.error.code, "ASUPERSYNC_BROWSER_NATIVE_STREAM_OPERATION_FAILED");
  assert.equal(result.error.diagnostics.reason, reason);
  return result.error.diagnostics;
}

async function sdk() {
  const context = createContext({
    AbortController, ArrayBuffer, DataView, Uint8Array, URL, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, WebAssembly, Error, TypeError, RangeError,
    DOMException, structuredClone, queueMicrotask, setTimeout, clearTimeout,
    window: {}, document: {}, isSecureContext: true, fetch() { throw new Error("unexpected fetch"); },
  });
  const sources = {
    "@asupersync/browser-core": ["../packages/browser-core/index.js", false],
    "./fetch.js": ["../packages/browser/src/fetch.ts", true],
    "@asupersync/browser-core/webtransport-streams": ["../packages/browser-core/webtransport-streams.js", false],
  };
  const modules = new Map();
  for (const [name, [path, typescript]] of Object.entries(sources)) {
    const raw = readFileSync(new URL(path, import.meta.url), "utf8");
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(raw, { mode: "transform" }) : raw, { context },
    ));
  }
  modules.set("./webtransport-streams.js", modules.get("@asupersync/browser-core/webtransport-streams"));
  const names = ["default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter", "task_cancel",
    "task_join", "task_spawn", "websocket_cancel", "websocket_close", "websocket_open",
    "websocket_recv", "websocket_send"];
  modules.set("./asupersync.js", new SyntheticModule(names, function () {
    for (const name of names) this.setExport(name, () => { throw new Error(`unexpected ABI call: ${name}`); });
  }, { context }));
  const module = new SourceTextModule(sdkJavaScript, { context, identifier: sdkPath });
  await module.link((specifier) => {
    assert.ok(modules.has(specifier), `unhandled import ${specifier}`);
    return modules.get(specifier);
  });
  await module.evaluate();
  return module.namespace;
}
const authority = { capability: { capabilityGranted: true } };

test("NATIVE-STREAM: invalid budgets do not acquire reader or writer locks", async () => {
  const api = await sdk();
  const readable = new ReadableStream();
  const writable = new WritableStream();
  assert.throws(() => api.createBrowserReadableStream(readable, { ...authority, maxBytes: -1 }), RangeError);
  assert.throws(() => api.createBrowserWritableStream(writable, { ...authority, maxBytes: -1 }), RangeError);
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
});

test("NATIVE-STREAM: concurrent writes count bytes awaiting readiness against the quota", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const chunks = [];
  const stream = new WritableStream({
    write(bytes) { chunks.push(Array.from(bytes)); started.resolve(); return release.promise; },
  });
  const writer = api.createBrowserWritableStream(stream, { ...authority, maxBytes: 3 });
  const first = observe(writer.write(Uint8Array.of(1, 2)));
  await started.promise;
  const second = observe(writer.write(Uint8Array.of(3, 4)));
  try {
    rejected(await promptly(second), "write_limit_exceeded");
    assert.equal(writer.state, "errored");
  } finally { release.resolve(); }
  await first;
  await turn();
  assert.deepEqual(chunks, [[1, 2]], "over-quota bytes must never reach the host sink");
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: abort promptly rejects in-flight and ready-blocked writes with its reason", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const chunks = [];
  const events = [];
  const stream = new WritableStream({
    write(bytes) { chunks.push(Array.from(bytes)); started.resolve(); return release.promise; },
    abort(reason) { events.push(reason); },
  });
  const writer = api.createBrowserWritableStream(stream, authority);
  const first = observe(writer.write(Uint8Array.of(1)));
  await started.promise;
  const second = observe(writer.write(Uint8Array.of(2)));
  const abort = observe(writer.abort("owner left"));
  try {
    for (const result of await promptly(Promise.all([first, second]))) {
      assert.equal(rejected(result, "aborted").firstFailure, "owner left");
    }
    assert.equal(writer.state, "aborted");
  } finally { release.resolve(); }
  assert.equal((await abort).ok, true);
  assert.deepEqual(chunks, [[1]]);
  assert.deepEqual(events, ["owner left"]);
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: close drains writes already admitted before closing the host", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const events = [];
  const stream = new WritableStream({
    write(bytes) { events.push(Array.from(bytes)); started.resolve(); return release.promise; },
    close() { events.push("close"); },
  });
  const writer = api.createBrowserWritableStream(stream, authority);
  const first = observe(writer.write(Uint8Array.of(1)));
  await started.promise;
  const second = observe(writer.write(Uint8Array.of(2)));
  const close = observe(writer.close());
  try { rejected(await promptly(observe(writer.write(Uint8Array.of(3)))), "closed"); }
  finally { release.resolve(); }
  const results = await Promise.all([first, second, close]);
  assert.ok(results.every((result) => result.ok), JSON.stringify(results));
  assert.deepEqual(events, [[1], [2], "close"]);
  assert.equal(writer.bytesWritten, 2);
  assert.equal(writer.state, "closed");
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: write owns a right-sized snapshot while readiness is blocked", async () => {
  const api = await sdk();
  const ready = deferred();
  const chunks = [];
  const writer = api.createBrowserWritableStream({ getWriter() { return {
    ready: ready.promise,
    write(value) { chunks.push(value); return Promise.resolve(); },
    close() { return Promise.resolve(); }, releaseLock() {},
  }; } }, authority);
  const backing = Uint8Array.of(99, 1, 2, 98);
  const pending = writer.write(backing.subarray(1, 3));
  backing.fill(7);
  ready.resolve();
  assert.equal(await pending, 2);
  assert.deepEqual(Array.from(chunks[0]), [1, 2]);
  assert.equal(chunks[0].byteOffset, 0);
  assert.equal(chunks[0].buffer.byteLength, 2);
  await writer.close();
});

test("NATIVE-STREAM: cancel wins a pending native read without becoming EOF", async () => {
  const api = await sdk();
  const stream = new ReadableStream({}, { highWaterMark: 0 });
  const reader = api.createBrowserReadableStream(stream, authority);
  const pending = observe(reader.read());
  await turn();
  await reader.cancel("owner left");
  assert.equal(rejected(await pending, "cancelled").firstFailure, "owner left");
  assert.equal(reader.state, "cancelled");
  assert.equal(reader.bytesRead, 0);
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: rejected host cancellation still releases its reader lock", async () => {
  const api = await sdk();
  const error = new Error("upstream cancel failed");
  const stream = new ReadableStream({ cancel() { throw error; } });
  const reader = api.createBrowserReadableStream(stream, authority);
  await assert.rejects(reader.cancel("owner left"), (observed) => observed === error);
  assert.equal(reader.state, "cancelled");
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: rejected host abort still releases its writer lock", async () => {
  const api = await sdk();
  const error = new Error("upstream abort failed");
  const stream = new WritableStream({ abort() { throw error; } });
  const writer = api.createBrowserWritableStream(stream, authority);
  await assert.rejects(writer.abort("owner left"), (observed) => observed === error);
  assert.equal(writer.state, "aborted");
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: read quota failure cancels upstream and frees its lock", async () => {
  const api = await sdk();
  const cancellations = [];
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(Uint8Array.of(1, 2, 3)); },
    cancel(reason) { cancellations.push(reason); },
  }, { highWaterMark: 0 });
  const reader = api.createBrowserReadableStream(stream, { ...authority, maxBytes: 2 });
  rejected(await observe(reader.read()), "read_limit_exceeded");
  await turn();
  assert.equal(reader.state, "errored");
  assert.equal(reader.bytesRead, 0);
  assert.deepEqual(cancellations, ["read_limit_exceeded"]);
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: explicit release works when automatic release is disabled", async () => {
  const api = await sdk();
  const readable = new ReadableStream();
  const writable = new WritableStream();
  const reader = api.createBrowserReadableStream(readable, { ...authority, autoReleaseLock: false });
  const writer = api.createBrowserWritableStream(writable, { ...authority, autoReleaseLock: false });
  reader.releaseLock();
  writer.releaseLock();
  assert.equal(reader.state, "released");
  assert.equal(writer.state, "released");
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
});

test("NATIVE-STREAM: sequential read/write preserves exact-boundary bytes and EOF", async () => {
  const api = await sdk();
  const events = [];
  const stream = new WritableStream({ write(bytes) { events.push(Array.from(bytes)); } });
  const writer = api.createBrowserWritableStream(stream, { ...authority, maxBytes: 3 });
  assert.equal(await writer.write(Uint8Array.of(1)), 1);
  assert.equal(await writer.write(Uint8Array.of(2, 3)), 2);
  await writer.close();
  assert.deepEqual(events, [[1], [2, 3]]);
  const input = new ReadableStream({
    start(controller) { controller.enqueue(Uint8Array.of(1, 2, 3)); controller.close(); },
  });
  const reader = api.createBrowserReadableStream(input, { ...authority, maxBytes: 3 });
  assert.deepEqual(Array.from(await reader.readAll()), [1, 2, 3]);
  assert.equal(reader.bytesRead, 3);
  assert.equal(reader.state, "closed");
  assert.equal(input.locked, false);
});

test("NATIVE-STREAM: release promptly refuses a write still waiting for host readiness", async () => {
  const api = await sdk();
  const ready = deferred();
  const events = [];
  const writer = api.createBrowserWritableStream({ getWriter() { return {
    ready: ready.promise,
    write(bytes) { events.push(Array.from(bytes)); return Promise.resolve(); },
    releaseLock() { events.push("release"); },
  }; } }, authority);
  const pending = observe(writer.write(Uint8Array.of(1)));
  writer.releaseLock();
  rejected(await promptly(pending), "released");
  ready.resolve();
  await turn();
  assert.deepEqual(events, ["release"]);
  assert.equal(writer.bytesWritten, 0);
});

test("NATIVE-STREAM: a host that ignores cancellation cannot deliver a late read", async () => {
  const api = await sdk();
  const read = deferred();
  const cleanup = deferred();
  const events = [];
  const reader = api.createBrowserReadableStream({ getReader() { return {
    read() { return read.promise; },
    cancel(reason) { events.push(reason); return cleanup.promise; },
    releaseLock() { events.push("release"); },
  }; } }, authority);
  const pending = observe(reader.read());
  const cancelled = reader.cancel("owner left");
  try {
    rejected(await promptly(pending), "cancelled");
    read.resolve({ done: false, value: Uint8Array.of(9) });
    await turn();
    assert.equal(reader.state, "cancelled");
    assert.equal(reader.bytesRead, 0);
  } finally { cleanup.resolve(); }
  await cancelled;
  assert.deepEqual(events, ["owner left", "release"]);
});

test("NATIVE-STREAM: abort takes precedence over graceful close while writes drain", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const events = [];
  const stream = new WritableStream({
    write(bytes) { events.push(Array.from(bytes)); started.resolve(); return release.promise; },
    close() { events.push("close"); },
    abort(reason) { events.push(reason); },
  });
  const writer = api.createBrowserWritableStream(stream, authority);
  const pending = observe(writer.write(Uint8Array.of(1)));
  await started.promise;
  const closing = observe(writer.close());
  const abort = writer.abort("owner left");
  try {
    rejected(await promptly(pending), "aborted");
    rejected(await promptly(closing), "aborted");
    assert.equal(writer.state, "aborted");
  } finally { release.resolve(); }
  await abort;
  assert.deepEqual(events, [[1], "owner left"]);
  assert.equal(writer.bytesWritten, 0);
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: write quota is checked before reading array elements or copying bytes", async () => {
  const api = await sdk();
  let accessed = false;
  const input = [1, 2];
  Object.defineProperty(input, 0, { get() { accessed = true; return 1; } });
  const stream = new WritableStream();
  const writer = api.createBrowserWritableStream(stream, { ...authority, maxBytes: 1 });
  rejected(await observe(writer.write(input)), "write_limit_exceeded");
  await turn();
  assert.equal(accessed, false);
  assert.equal(stream.locked, false);
});

test("NATIVE-STREAM: copying reentrant array input cannot write after abort", async () => {
  const api = await sdk();
  const events = [];
  const writer = api.createBrowserWritableStream(new WritableStream({
    write(bytes) { events.push(Array.from(bytes)); },
    abort(reason) { events.push(reason); },
  }), authority);
  let abort;
  const input = [1];
  Object.defineProperty(input, 0, { get() { abort = writer.abort("reentrant abort"); return 1; } });
  rejected(await observe(writer.write(input)), "aborted");
  await abort;
  assert.deepEqual(events, ["reentrant abort"]);
  assert.equal(writer.bytesWritten, 0);
});

test("NATIVE-STREAM: readAll snapshots a host's reused byte buffer", async () => {
  const api = await sdk();
  const shared = Uint8Array.of(0);
  let count = 0;
  const reader = api.createBrowserReadableStream({ getReader() { return {
    read() {
      if (count === 2) return Promise.resolve({ done: true });
      shared[0] = ++count;
      return Promise.resolve({ done: false, value: shared });
    },
    releaseLock() {},
  }; } }, authority);
  assert.deepEqual(Array.from(await reader.readAll()), [1, 2]);
  assert.equal(reader.bytesRead, 2);
});

test("NATIVE-STREAM: UTF-8 and typed subview writes count exactly the accepted bytes", async () => {
  const api = await sdk();
  const chunks = [];
  const writer = api.createBrowserWritableStream(new WritableStream({
    write(bytes) { chunks.push(Array.from(bytes)); },
  }), { ...authority, maxBytes: 10 });
  assert.equal(await writer.write("A\ud83d\ude00\ud800"), 8);
  const data = Uint8Array.of(9, 1, 2, 9);
  assert.equal(await writer.write(new DataView(data.buffer, 1, 2)), 2);
  await writer.close();
  assert.deepEqual(chunks, [[65, 240, 159, 152, 128, 239, 191, 189], [1, 2]]);
  assert.equal(writer.bytesWritten, 10);
});

test("NATIVE-STREAM: lock transfer preserves submitted writes and refuses pre-host waits", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const events = [];
  const stream = new WritableStream({
    write(bytes) { events.push(Array.from(bytes)); started.resolve(); return release.promise; },
    abort(reason) { events.push(["abort", reason]); },
  });
  const writer = api.createBrowserWritableStream(stream, authority);
  const first = observe(writer.write(Uint8Array.of(1, 2)));
  await started.promise;
  const waiting = observe(writer.write(Uint8Array.of(3)));
  writer.releaseLock();
  try {
    rejected(await promptly(waiting), "released");
    assert.equal(writer.state, "released");
    assert.equal(stream.locked, false);
  } finally { release.resolve(); }
  assert.deepEqual(await first, { ok: true, value: 2 });
  assert.equal(writer.bytesWritten, 2);
  const nextOwner = stream.getWriter();
  await nextOwner.write(Uint8Array.of(4));
  await nextOwner.close();
  nextOwner.releaseLock();
  assert.deepEqual(events, [[1, 2], [4]]);
});

test("NATIVE-STREAM: abort reaches the host before an immediate explicit lock release", async () => {
  const api = await sdk();
  const events = [];
  const stream = new WritableStream({ abort(reason) { events.push(reason); } });
  const writer = api.createBrowserWritableStream(stream, authority);
  const abort = writer.abort("owner left");
  writer.releaseLock();
  await abort;
  const nextOwner = stream.getWriter();
  await assert.rejects(nextOwner.write(Uint8Array.of(1)), (error) => error === "owner left");
  nextOwner.releaseLock();
  assert.deepEqual(events, ["owner left"]);
});

test("NATIVE-STREAM: releasing an already-submitted close retains its host completion", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const stream = new WritableStream({ close() { started.resolve(); return release.promise; } });
  const writer = api.createBrowserWritableStream(stream, authority);
  const closing = observe(writer.close());
  await started.promise;
  writer.releaseLock();
  release.resolve();
  assert.deepEqual(await closing, { ok: true, value: undefined });
  assert.equal(writer.state, "released");
  const nextOwner = stream.getWriter();
  await assert.rejects(nextOwner.write(Uint8Array.of(1)), TypeError);
  nextOwner.releaseLock();
});

test("NATIVE-STREAM: release prevents a close that is still draining accepted writes", async () => {
  const api = await sdk();
  const started = deferred();
  const release = deferred();
  const events = [];
  const stream = new WritableStream({
    write(bytes) { events.push(Array.from(bytes)); started.resolve(); return release.promise; },
    close() { events.push("close"); },
  });
  const writer = api.createBrowserWritableStream(stream, authority);
  const first = writer.write(Uint8Array.of(1));
  await started.promise;
  const closing = observe(writer.close());
  writer.releaseLock();
  release.resolve();
  assert.equal(await first, 1);
  rejected(await closing, "released");
  assert.deepEqual(events, [[1]]);
  assert.equal(writer.state, "released");
  const nextOwner = stream.getWriter();
  await nextOwner.close();
  nextOwner.releaseLock();
});

test("NATIVE-STREAM: releasing a reader cannot discard its already-consumed chunk", async () => {
  const api = await sdk();
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(Uint8Array.of(1, 2)); controller.close(); },
  });
  const reader = api.createBrowserReadableStream(stream, authority);
  const pending = reader.read();
  reader.releaseLock();
  assert.deepEqual(Array.from(await pending), [1, 2]);
  assert.equal(reader.bytesRead, 2);
  assert.equal(reader.state, "released");
  const nextOwner = stream.getReader();
  assert.deepEqual(await nextOwner.read(), { done: true, value: undefined });
  nextOwner.releaseLock();
});

test("NATIVE-STREAM: releasing a genuinely pending native read rejects it promptly", async () => {
  const api = await sdk();
  const stream = new ReadableStream({}, { highWaterMark: 0 });
  const reader = api.createBrowserReadableStream(stream, authority);
  const pending = observe(reader.read());
  await turn();
  reader.releaseLock();
  rejected(await promptly(pending), "released");
  assert.equal(reader.state, "released");
  assert.equal(reader.bytesRead, 0);
  assert.equal(stream.locked, false);
});
