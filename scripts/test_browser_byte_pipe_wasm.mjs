/**
 * Byte piping through the actual SDK, checked-in generated JS/WASM handle
 * ledger, and Node's native WHATWG streams. Browser-like globals admit the SDK;
 * this is not a browser-engine run, Rust rebuild, or Rust executor proof.
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   scripts/test_browser_byte_pipe_wasm.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, runInContext } from "node:vm";

const files = [
  ["sdk", "packages/browser/src/index.ts", true],
  ["@asupersync/browser-core", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./byte-pipe.js", "packages/browser/src/byte-pipe.ts", true],
  ["./asupersync.js", "packages/browser-core/asupersync.js", false],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const inputs = new Map(), hashes = {};
for (const [, path] of files) {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  inputs.set(path, bytes.toString());
  hashes[path] = createHash("sha256").update(bytes).digest("hex");
}
const wasmPath = "packages/browser-core/asupersync_bg.wasm";
const wasmBytes = readFileSync(new URL(`../${wasmPath}`, import.meta.url));
hashes[wasmPath] = createHash("sha256").update(wasmBytes).digest("hex");
console.log(JSON.stringify({
  scenario_id: "browser-byte-pipe-packaged-wasm",
  evidence_scope: "actual SDK, checked-in generated JS/WASM handle ledger, native WHATWG streams",
  no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch", "network delivery"],
  source_sha256: hashes,
}));

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
const turn = () => new Promise(resolve => setImmediate(resolve));
function ok(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("WASM-owned pipe did not settle")), 5000);
    })]);
  } finally { clearTimeout(timer); }
}
async function pending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(settled, false, "native work still owns the unfinished task");
}
async function loadSdk() {
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket, TextEncoder, TextDecoder,
    ReadableStream, ReadableStreamDefaultReader, WritableStream, WritableStreamDefaultWriter,
    WebAssembly, Response, Request, structuredClone, queueMicrotask, setTimeout,
    clearTimeout, window: {}, document: {}, isSecureContext: true,
  });
  const modules = new Map();
  for (const [name, path, typescript] of files) {
    const text = inputs.get(path);
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(text, { mode: "transform" }) : text,
      { context, identifier: fileURLToPath(new URL(`../${path}`, import.meta.url)) },
    ));
  }
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const entry = modules.get("sdk");
  await entry.link(specifier => {
    assert.ok(modules.has(specifier), `unexpected SDK import ${specifier}`);
    return modules.get(specifier);
  });
  await entry.evaluate();
  context.sdk = entry.namespace;
  context.wasmBytes = wasmBytes;
  await runInContext("sdk.init({ module_or_path: wasmBytes })", context);
  const raw = modules.get("./asupersync.js").namespace;
  return { sdk: entry.namespace, snapshot: () => JSON.parse(raw.browser_operator_snapshot()) };
}
async function fixture(t, { retainedFailure = false } = {}) {
  const { sdk, snapshot } = await loadSdk();
  const runtime = ok(await sdk.createBrowserRuntime({ eagerInit: false }));
  const scope = ok(runtime.enterScope("byte-pipe-integration"));
  const gates = [];
  const gate = () => { const result = deferred(); gates.push(result); return result; };
  let runtimeClosed = false;
  const closeRuntime = async () => {
    if (runtimeClosed) return;
    const receipt = await bounded(runtime.closeAsync());
    if (retainedFailure) assert.equal(receipt.outcome, "err");
    else { ok(receipt); runtimeClosed = true; }
  };
  t.after(async () => {
    for (const waiter of gates) waiter.resolve();
    await closeRuntime();
  });
  function pair(options = {}) {
    let readController, writeController;
    const events = { reads: 0, writes: [], cancels: [], aborts: [], closes: 0 };
    const input = new ReadableStream({
      start(controller) { readController = controller; },
      pull(controller) { events.reads += 1; return options.pull?.(controller, events.reads); },
      cancel(reason) { events.cancels.push(reason); return options.cancel?.(reason); },
    }, { highWaterMark: 0 });
    const output = new WritableStream({
      start(controller) { writeController = controller; },
      write(chunk) { events.writes.push(chunk); return options.write?.(chunk, events.writes.length); },
      close() { events.closes += 1; return options.close?.(); },
      abort(reason) { events.aborts.push(reason); return options.abort?.(reason); },
    }, { highWaterMark: 1 });
    return { input, output, events, readController, writeController };
  }
  return { sdk, snapshot, runtime, scope, gate, pair, closeRuntime };
}

test("WASM task owns an exact byte transfer through delayed native write and close", async t => {
  const f = await fixture(t), writeStarted = f.gate(), finishWrite = f.gate(), closeStarted = f.gate(), finishClose = f.gate();
  const chunks = [Uint8Array.of(99, 1, 2, 3, 99).subarray(1, 4), Uint8Array.of(0, 255)];
  const streams = f.pair({
    pull(controller, index) { if (index <= chunks.length) controller.enqueue(chunks[index - 1]); else controller.close(); },
    write(_chunk, index) { if (index === 1) { writeStarted.resolve(); return finishWrite.promise; } },
    close() { closeStarted.resolve(); return finishClose.promise; },
  });
  assert.equal(f.snapshot().tasks.total, 0);
  const handle = ok(f.scope.pipeBytesTo(streams.input, streams.output));
  assert.equal(f.snapshot().tasks.total, 1, "SDK admission allocated an actual checked-in WASM task");
  await bounded(writeStarted.promise);
  await pending(handle.completed);
  assert.equal(f.snapshot().tasks.total, 1);
  assert.equal(streams.events.reads, 1);
  finishWrite.resolve();
  await bounded(closeStarted.promise);
  await pending(handle.completed);
  assert.equal(f.snapshot().tasks.total, 1, "native finalization retains its ledger task");
  finishClose.resolve();
  assert.deepEqual({ ...ok(await bounded(handle.completed)) }, { bytesWritten: 5, chunksWritten: 2 });
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), [[1, 2, 3], [0, 255]]);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(f.snapshot().tasks.cleanup_pending, 0);
  ok(await bounded(f.scope.closeAsync()));
  await f.closeRuntime();
  console.log(JSON.stringify({ scenario_id: "browser-byte-pipe-wasm-native-write-close", bytesWritten: 5,
    chunksWritten: 2, wasm_task_counts: [0, 1, 1, 1, 0], native_locks_released: true }));
});

test("WASM scope close awaits delayed source cancellation and destination abortion", async t => {
  const f = await fixture(t), readStarted = f.gate(), sourceStarted = f.gate(), sinkStarted = f.gate();
  const stopSource = f.gate(), stopSink = f.gate();
  const streams = f.pair({
    pull() { readStarted.resolve(); },
    cancel() { sourceStarted.resolve(); return stopSource.promise; },
    abort() { sinkStarted.resolve(); return stopSink.promise; },
  });
  const handle = ok(f.scope.pipeBytesTo(streams.input, streams.output));
  await bounded(readStarted.promise);
  const closing = f.scope.closeAsync();
  await bounded(Promise.all([sourceStarted.promise, sinkStarted.promise]));
  await pending(closing);
  await pending(handle.completed);
  assert.equal(f.snapshot().tasks.total, 1);
  const untouched = f.pair();
  assert.equal(f.scope.pipeBytesTo(untouched.input, untouched.output).outcome, "err");
  assert.equal(untouched.input.locked, false);
  assert.equal(untouched.output.locked, false);
  assert.equal(untouched.events.reads, 0);
  stopSource.resolve();
  await pending(closing);
  assert.equal(f.snapshot().tasks.total, 1);
  stopSink.resolve();
  ok(await bounded(closing));
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(f.snapshot().tasks.cleanup_pending, 0);
});

test("WASM runtime close drains descendant pipes while an active write holds native ownership", async t => {
  const f = await fixture(t), child = ok(f.scope.enterScope("pipe-child")), grandchild = ok(child.enterScope("pipe-grandchild"));
  const readStarted = f.gate(), writeStarted = f.gate(), finishWrite = f.gate();
  const first = f.pair({ pull() { readStarted.resolve(); } });
  const second = f.pair({ pull: controller => controller.enqueue(Uint8Array.of(4, 5)), write() { writeStarted.resolve(); return finishWrite.promise; } });
  const a = ok(child.pipeBytesTo(first.input, first.output)), b = ok(grandchild.pipeBytesTo(second.input, second.output));
  await bounded(Promise.all([readStarted.promise, writeStarted.promise]));
  assert.equal(f.snapshot().tasks.total, 2);
  const closing = f.closeRuntime();
  await pending(closing);
  assert.equal(first.events.cancels.length, 1, "all descendant cancellations start before a slow write finishes");
  assert.equal(second.events.writes.length, 1);
  assert.ok(f.snapshot().tasks.total >= 1);
  finishWrite.resolve();
  await bounded(closing);
  assert.equal((await bounded(a.completed)).outcome, "cancelled");
  assert.equal((await bounded(b.completed)).outcome, "cancelled");
  assert.equal(second.events.writes.length, 1);
  assert.equal(second.events.reads, 1);
  assert.equal(first.input.locked || first.output.locked || second.input.locked || second.output.locked, false);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(f.snapshot().tasks.cleanup_pending, 0);
});

test("WASM closing one scope preserves an independently owned sibling pipe", async t => {
  const f = await fixture(t), sibling = ok(f.runtime.enterScope("independent-pipe"));
  const firstRead = f.gate(), secondRead = f.gate();
  const first = f.pair({ pull() { firstRead.resolve(); } }), second = f.pair({ pull() { secondRead.resolve(); } });
  const a = ok(f.scope.pipeBytesTo(first.input, first.output)), b = ok(sibling.pipeBytesTo(second.input, second.output));
  await bounded(Promise.all([firstRead.promise, secondRead.promise]));
  ok(await bounded(f.scope.closeAsync()));
  assert.equal((await bounded(a.completed)).outcome, "cancelled");
  await pending(b.completed);
  assert.equal(second.events.cancels.length, 0);
  assert.equal(second.events.aborts.length, 0);
  assert.equal(f.snapshot().tasks.total, 1);
  ok(await bounded(b.cancel("done with sibling")));
  assert.equal((await bounded(b.completed)).outcome, "cancelled");
  assert.equal(f.snapshot().tasks.total, 0);
});

test("WASM byte caps and pre-aborted/locked admission preserve exact task accounting", async t => {
  const f = await fixture(t), refused = f.pair(), controller = new AbortController();
  controller.abort();
  assert.equal(f.scope.pipeBytesTo(refused.input, refused.output, { signal: controller.signal }).outcome, "cancelled");
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(refused.input.locked || refused.output.locked, false);
  const reader = refused.input.getReader();
  assert.equal(f.scope.pipeBytesTo(refused.input, refused.output).outcome, "err");
  assert.equal(f.snapshot().tasks.total, 0);
  reader.releaseLock();
  const streams = f.pair({ pull(controller, index) { controller.enqueue(index === 1 ? Uint8Array.of(1, 2) : Uint8Array.of(3, 4)); } });
  const handle = ok(f.scope.pipeBytesTo(streams.input, streams.output, { maxBytes: 3 }));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), [[1, 2]]);
  assert.deepEqual({ ...handle.progress() }, { bytesWritten: 2, chunksWritten: 1 });
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(f.snapshot().tasks.total, 0);
  ok(await bounded(handle.retire()));
});

test("WASM signal cancellation retires a parked operation through real task publication", async t => {
  const f = await fixture(t), readStarted = f.gate(), controller = new AbortController();
  const streams = f.pair({ pull() { readStarted.resolve(); } });
  const handle = ok(f.scope.pipeBytesTo(streams.input, streams.output, { signal: controller.signal }));
  await bounded(readStarted.promise);
  assert.equal(f.snapshot().tasks.total, 1);
  controller.abort();
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  ok(await bounded(handle.retire()));
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(streams.input.locked || streams.output.locked, false);
});

test("WASM untracked raw ABI scope cannot acquire native pipe authority", async t => {
  const f = await fixture(t), streams = f.pair();
  const raw = ok(f.sdk.scopeEnter({ parent: f.scope.core, label: "raw-untracked-pipe" }));
  const untracked = new f.sdk.RegionHandle(raw);
  assert.equal(untracked.pipeBytesTo(streams.input, streams.output).outcome, "err");
  assert.equal(streams.input.locked || streams.output.locked, false);
  assert.equal(streams.events.reads, 0);
  assert.equal(f.snapshot().tasks.total, 0);
});

test("WASM owner close drains generic and bounded byte pipes together without changing either API", async t => {
  const f = await fixture(t), genericRead = f.gate(), byteRead = f.gate();
  const generic = f.pair({ pull() { genericRead.resolve(); } });
  const bytes = f.pair({ pull() { byteRead.resolve(); } });
  const genericHandle = ok(f.scope.pipeTo(generic.input, generic.output));
  const byteHandle = ok(f.scope.pipeBytesTo(bytes.input, bytes.output, { maxBytes: 10 }));
  await bounded(Promise.all([genericRead.promise, byteRead.promise]));
  assert.equal(f.snapshot().tasks.total, 2);
  ok(await bounded(f.scope.closeAsync()));
  assert.equal((await bounded(genericHandle.closed)).outcome, "cancelled");
  assert.equal((await bounded(byteHandle.completed)).outcome, "cancelled");
  assert.deepEqual({ ...byteHandle.progress() }, { bytesWritten: 0, chunksWritten: 0 });
  assert.equal(generic.events.cancels.length, 1);
  assert.equal(bytes.events.cancels.length, 1);
  assert.equal(f.snapshot().tasks.total, 0);
});

test("WASM cleanup rejection retains the ledger task and keeps owner close unsuccessful on retry", async t => {
  const f = await fixture(t, { retainedFailure: true }), readStarted = f.gate();
  const streams = f.pair({ pull() { readStarted.resolve(); }, cancel() { return Promise.reject(new Error("native cleanup failed")); } });
  const handle = ok(f.scope.pipeBytesTo(streams.input, streams.output));
  await bounded(readStarted.promise);
  assert.equal((await bounded(f.scope.closeAsync())).outcome, "err");
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(f.snapshot().tasks.total, 1, "a failed native cleanup must not appear as ABI quiescence");
  assert.equal((await bounded(handle.retire())).outcome, "err");
  assert.equal((await bounded(f.scope.closeAsync())).outcome, "err");
  assert.equal(streams.events.cancels.length, 1, "native closed-state no-op cannot erase its rejected cleanup receipt");
  assert.equal(f.snapshot().tasks.total, 1);
});
