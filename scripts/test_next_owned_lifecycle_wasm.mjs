/**
 * Next bootstrap ownership through actual Next/Browser modules, the checked-in
 * generated JS/WASM ledger, and Node's native WHATWG streams. Only publication
 * of an actual runtime factory result and selected raw taskJoin refusals are
 * controlled. No fake runtime or always-successful close adapter is used.
 *
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   scripts/test_next_owned_lifecycle_wasm.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, runInContext, SourceTextModule, SyntheticModule } from "node:vm";

const files = [
  ["next", "packages/next/src/index.ts", true],
  ["browser", "packages/browser/src/index.ts", true],
  ["@asupersync/browser-core", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./byte-pipe.js", "packages/browser/src/byte-pipe.ts", true],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const sources = new Map(), hashes = {};
for (const [, path] of files) {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  sources.set(path, bytes.toString());
  hashes[path] = createHash("sha256").update(bytes).digest("hex");
}
const rawPath = "packages/browser-core/asupersync.js";
const rawSource = readFileSync(new URL(`../${rawPath}`, import.meta.url), "utf8");
const wasmPath = "packages/browser-core/asupersync_bg.wasm";
const wasmBytes = readFileSync(new URL(`../${wasmPath}`, import.meta.url));
hashes[rawPath] = createHash("sha256").update(rawSource).digest("hex");
hashes[wasmPath] = createHash("sha256").update(wasmBytes).digest("hex");
console.log(JSON.stringify({
  scenario_id: "next-bootstrap-owned-retirement-packaged-wasm",
  evidence_scope: "actual Next/Browser/core/packaged WASM with native WHATWG streams",
  injected_faults: ["delayed publication of an actual runtime factory result", "selected taskJoin refusal before real WASM call"],
  no_claim: ["Next browser rendering or hydration engine", "Rust rebuild", "Rust executor dispatch"],
  source_sha256: hashes,
}));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const turn = () => new Promise(resolve => setImmediate(resolve));
function ok(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
function cancelled(outcome) {
  assert.equal(outcome.outcome, "cancelled", JSON.stringify(outcome));
  return outcome.cancellation;
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Next owned lifecycle did not settle")), 5000);
    })]);
  } finally { clearTimeout(timer); }
}
async function pending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(settled, false, "old native ownership still blocks this lifecycle boundary");
}
const refusal = Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "compatibility_rejected", recoverability: "transient", message: "injected publication refusal",
}) });

async function fixture(t, options = {}) {
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket, TextEncoder, TextDecoder, DOMException,
    ReadableStream, ReadableStreamDefaultReader, WritableStream, WritableStreamDefaultWriter,
    WebAssembly, Response, Request, structuredClone, queueMicrotask, setTimeout,
    clearTimeout, window: {}, document: {}, isSecureContext: true,
  });
  const actualRaw = new SourceTextModule(rawSource, { context, identifier: rawPath });
  await actualRaw.link(() => { throw new Error("Unexpected generated WASM import"); });
  await actualRaw.evaluate();
  const raw = actualRaw.namespace;
  const calls = { runtimeCreate: [], scopeClose: [], runtimeClose: [], join: [], factories: [] };
  const controls = { joinResponse: null };
  const bindings = new SyntheticModule(Object.getOwnPropertyNames(raw), function () {
    for (const name of Object.getOwnPropertyNames(raw)) {
      let implementation = raw[name];
      const observed = { runtime_create: "runtimeCreate", scope_close: "scopeClose", runtime_close: "runtimeClose" }[name];
      if (observed) implementation = (...args) => {
        const response = raw[name](...args);
        calls[observed].push({ args, outcome: JSON.parse(response) });
        return response;
      };
      if (name === "task_join") implementation = (...args) => {
        calls.join.push({ task: JSON.parse(args[0]), outcome: JSON.parse(args[1]) });
        return controls.joinResponse === null ? raw.task_join(...args) : JSON.stringify(controls.joinResponse);
      };
      this.setExport(name, implementation);
    }
  }, { context, identifier: "observed-real-wasm-bindings" });
  const modules = new Map([["./asupersync.js", bindings]]);
  for (const [name, path, typescript] of files) {
    const source = sources.get(path);
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(source, { mode: "transform" }) : source,
      { context, identifier: fileURLToPath(new URL(`../${path}`, import.meta.url)) },
    ));
  }
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const browser = modules.get("browser");
  await browser.link(specifier => {
    assert.ok(modules.has(specifier), `Unexpected Browser import ${specifier}`);
    return modules.get(specifier);
  });
  await browser.evaluate();
  context.browser = browser.namespace;
  context.wasmBytes = wasmBytes;
  await runInContext("browser.init({ module_or_path: wasmBytes })", context);

  const gates = [], publications = [];
  const gate = () => { const result = deferred(); gates.push(result); return result; };
  const bridge = new SyntheticModule(Object.getOwnPropertyNames(browser.namespace), function () {
    for (const name of Object.getOwnPropertyNames(browser.namespace)) {
      let implementation = browser.namespace[name];
      if (name === "createBrowserRuntime") implementation = async runtimeOptions => {
        const publication = publications.shift();
        const record = { options: runtimeOptions, outcome: null };
        calls.factories.push(record);
        publication?.entered.resolve(record);
        const outcome = await browser.namespace.createBrowserRuntime(runtimeOptions);
        record.outcome = outcome;
        // Teardown must remain available when a regression deliberately
        // replaces the public runtime methods after admission.
        record.cleanup = outcome.outcome === "ok" ? outcome.value.closeAsync.bind(outcome.value) : null;
        publication?.created.resolve(outcome);
        if (publication) await publication.release.promise;
        return outcome;
      };
      this.setExport(name, implementation);
    }
  }, { context, identifier: "actual-browser-with-controlled-factory-publication" });
  const next = modules.get("next");
  await next.link(specifier => {
    assert.equal(specifier, "@asupersync/browser");
    return bridge;
  });
  await next.evaluate();
  const adapter = new next.namespace.NextClientBootstrapAdapter({ eagerInit: false, ...options });
  const snapshot = () => JSON.parse(raw.browser_operator_snapshot());
  t.after(async () => {
    controls.joinResponse = null;
    for (const waiter of gates) waiter.resolve();
    if (typeof adapter.retire === "function") await bounded(adapter.retire("test cleanup"));
    // A failing assertion must not strand an otherwise recoverable real owner.
    for (const record of calls.factories) {
      if (record.cleanup) await bounded(record.cleanup());
    }
  });
  function holdFactory() {
    const held = { entered: deferred(), created: deferred(), release: gate() };
    publications.push(held);
    return held;
  }
  function pair(behavior = {}) {
    let input, output;
    const pulled = deferred(), written = deferred(), cancelledSource = deferred(), abortedSink = deferred();
    const events = { writes: [], cancels: [], aborts: [] };
    const readable = new ReadableStream({
      start(controller) { input = controller; },
      pull() { pulled.resolve(); },
      cancel(reason) {
        events.cancels.push(reason); cancelledSource.resolve();
        return behavior.cancel?.(reason);
      },
    }, { highWaterMark: 0 });
    const writable = new WritableStream({
      start(controller) { output = controller; },
      write(chunk) {
        events.writes.push([...chunk]); written.resolve();
        return behavior.write?.(chunk);
      },
      abort(reason) {
        events.aborts.push(reason); abortedSink.resolve();
        return behavior.abort?.(reason);
      },
    });
    return { readable, writable, input, output, events, pulled, written, cancelledSource, abortedSink };
  }
  async function initialize() { return ok(await bounded(adapter.ensureRuntimeReady())); }
  function pipe(scope, endpoints) { return ok(scope.pipeBytesTo(endpoints.readable, endpoints.writable)); }
  return { adapter, sdk: browser.namespace, calls, controls, gate, holdFactory, pair, pipe, initialize, snapshot };
}

test("actual concurrent Next initialization admits one WASM runtime and scope", async t => {
  const f = await fixture(t);
  const outcomes = await bounded(Promise.all([
    f.adapter.ensureRuntimeReady(), f.adapter.ensureRuntimeReady(), f.adapter.initializeRuntime(),
  ]));
  const scope = ok(outcomes[0]);
  for (const outcome of outcomes) assert.equal(ok(outcome), scope);
  assert.equal(f.calls.factories.length, 1);
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 1);
  ok(await bounded(f.adapter.closeAsync()));
  assert.equal(f.adapter.currentRuntime(), null);
  assert.equal(f.adapter.currentScope(), null);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(f.calls.runtimeClose.filter(call => call.outcome.outcome === "ok").length, 1);
});

test("a real refused synchronous scope close remains owned through async Next shutdown", async t => {
  const f = await fixture(t), scope = await f.initialize();
  const cancel = f.gate(), abort = f.gate();
  const endpoints = f.pair({ cancel: () => cancel.promise, abort: () => abort.promise });
  const transfer = f.pipe(scope, endpoints);
  await bounded(endpoints.pulled.promise);
  assert.notEqual(scope.close({ major: 999, minor: 0 }).outcome, "ok",
    "the actual ABI refuses an incompatible synchronous close without releasing its owner");
  assert.equal(f.snapshot().tasks.total, 1);
  const event = f.adapter.close("route unmounted");
  assert.equal(event.action, "close_runtime");
  assert.equal(typeof event.then, "undefined", "legacy close remains synchronous");
  assert.equal(f.adapter.currentRuntime(), null);
  assert.equal(f.adapter.currentScope(), null);
  const shutdown = f.adapter.closeAsync("join unmount");
  await bounded(Promise.all([endpoints.cancelledSource.promise, endpoints.abortedSink.promise]));
  await pending(shutdown);
  assert.equal(f.snapshot().tasks.total, 1);
  assert.equal(f.calls.runtimeClose.length, 0, "runtime barrier follows successful child cleanup");
  cancel.resolve();
  await pending(shutdown);
  abort.resolve();
  ok(await bounded(shutdown));
  cancelled(await bounded(transfer.completed));
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(endpoints.readable.locked, false);
  assert.equal(endpoints.writable.locked, false);
  assert.equal(endpoints.events.cancels.length, 1);
  assert.equal(endpoints.events.aborts.length, 1);
});

test("cache replacement waits for an admitted native write and shares one new generation", async t => {
  const f = await fixture(t), oldScope = await f.initialize();
  const write = f.gate(), abort = f.gate();
  const endpoints = f.pair({ write: () => write.promise, abort: () => abort.promise });
  const transfer = f.pipe(oldScope, endpoints);
  endpoints.input.enqueue(Uint8Array.of(3, 4));
  await bounded(endpoints.written.promise);
  f.adapter.cacheRevalidated();
  const first = f.adapter.initializeRuntime(), second = f.adapter.ensureRuntimeReady();
  await pending(Promise.all([first, second]));
  assert.equal(f.calls.factories.length, 1, "no replacement factory while the old write owns bytes");
  assert.equal(f.snapshot().tasks.total, 1);
  assert.equal(f.calls.runtimeClose.length, 0);
  write.resolve();
  await bounded(endpoints.abortedSink.promise);
  await pending(first);
  assert.equal(f.calls.factories.length, 1);
  abort.resolve();
  const newScope = ok(await bounded(first));
  assert.equal(ok(await bounded(second)), newScope);
  assert.notEqual(newScope, oldScope);
  assert.equal(f.calls.factories.length, 2);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 2);
  assert.equal(f.adapter.snapshot().lastInvalidatedScopeGeneration, 1);
  cancelled(await bounded(transfer.completed));
  assert.deepEqual(endpoints.events.writes, [[3, 4]]);
  assert.equal(f.snapshot().tasks.total, 0);
});

test("failed task publication blocks replacement until explicit Next retirement retry", async t => {
  const f = await fixture(t), scope = await f.initialize();
  const endpoints = f.pair();
  const transfer = f.pipe(scope, endpoints);
  await bounded(endpoints.pulled.promise);
  f.controls.joinResponse = refusal;
  const first = await bounded(f.adapter.closeAsync("replace owner"));
  assert.equal(first.outcome, "err");
  assert.equal(f.calls.join.length, 1, "a failed child cleanup is not retried via runtime close");
  assert.equal(f.calls.runtimeClose.length, 0);
  assert.equal(f.snapshot().tasks.total, 1);
  const rejectedInit = await bounded(f.adapter.initializeRuntime());
  assert.equal(rejectedInit.outcome, "err");
  assert.equal(f.calls.factories.length, 1);
  assert.equal(f.calls.join.length, 1, "initialization does not implicitly retry retirement");
  f.controls.joinResponse = null;
  assert.equal((await bounded(f.adapter.initializeRuntime())).outcome, "err");
  assert.equal(f.calls.join.length, 1);
  ok(await bounded(f.adapter.retire("retry publication")));
  assert.equal(f.calls.join.length, 2);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal((await transfer.completed).outcome, "err", "historical transfer refusal is unchanged");
  const replacement = ok(await bounded(f.adapter.initializeRuntime()));
  assert.notEqual(replacement, scope);
  assert.equal(f.calls.factories.length, 2);
  assert.equal(endpoints.events.cancels.length, 1);
  assert.equal(endpoints.events.aborts.length, 1);
});

test("original native cleanup rejection remains owned and blocks all replacement attempts", async t => {
  const f = await fixture(t), scope = await f.initialize();
  const endpoints = f.pair({ cancel: () => Promise.reject(new Error("native cleanup rejected")) });
  f.pipe(scope, endpoints);
  await bounded(endpoints.pulled.promise);
  assert.equal((await bounded(f.adapter.closeAsync())).outcome, "err");
  assert.equal((await bounded(f.adapter.initializeRuntime())).outcome, "err");
  assert.equal((await bounded(f.adapter.retire())).outcome, "err");
  assert.equal(f.calls.factories.length, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.calls.runtimeClose.length, 0);
  assert.equal(f.snapshot().tasks.total, 1);
  assert.equal(endpoints.events.cancels.length, 1, "native no-op retries cannot erase the failed hook");
  assert.equal(endpoints.events.aborts.length, 1);
});

test("an obsolete real factory result retires before any replacement runtime is allocated", async t => {
  const f = await fixture(t), held = f.holdFactory();
  const old = f.adapter.ensureRuntimeReady();
  const oldRuntime = ok(await bounded(held.created.promise));
  assert.equal(f.calls.runtimeCreate.length, 1, "old result already owns a real WASM runtime");
  const event = f.adapter.close("obsolete bootstrap");
  assert.equal(event.action, "close_runtime");
  const replacement = f.adapter.initializeRuntime(), joined = f.adapter.initializeRuntime();
  await pending(Promise.all([old, replacement, joined]));
  assert.equal(f.calls.factories.length, 1);
  held.release.resolve();
  cancelled(await bounded(old));
  const current = ok(await bounded(replacement));
  assert.equal(ok(await bounded(joined)), current);
  assert.equal(f.calls.factories.length, 2);
  assert.equal(f.calls.runtimeClose.filter(call => call.outcome.outcome === "ok").length, 1);
  assert.notEqual(f.adapter.currentRuntime(), oldRuntime);
  assert.equal(f.adapter.snapshot().runtimeInitSuccesses, 1);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 1);
});

test("navigation invalidates a replacement waiting for cleanup without allocating a stray generation", async t => {
  const f = await fixture(t), scope = await f.initialize(), cancel = f.gate();
  const endpoints = f.pair({ cancel: () => cancel.promise });
  f.pipe(scope, endpoints);
  await bounded(endpoints.pulled.promise);
  f.adapter.cacheRevalidated();
  const obsolete = f.adapter.initializeRuntime();
  await pending(obsolete);
  f.adapter.navigate("hard_navigation", "/replacement");
  const current = f.adapter.ensureRuntimeReady();
  await pending(current);
  assert.equal(f.calls.factories.length, 1);
  cancel.resolve();
  cancelled(await bounded(obsolete));
  const currentScope = ok(await bounded(current));
  assert.equal(f.adapter.currentScope(), currentScope);
  assert.equal(f.calls.factories.length, 2);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 2);
  assert.equal(f.adapter.snapshot().routeSegment, "/replacement");
  assert.equal(f.adapter.snapshot().phase, "runtime_ready");
});

test("concurrent explicit shutdowns share actual cleanup without duplicating task publication", async t => {
  const f = await fixture(t), scope = await f.initialize(), cancel = f.gate();
  const endpoints = f.pair({ cancel: () => cancel.promise });
  f.pipe(scope, endpoints);
  await bounded(endpoints.pulled.promise);
  const first = f.adapter.closeAsync("first"), second = f.adapter.retire("second");
  await pending(Promise.all([first, second]));
  assert.equal(endpoints.events.cancels.length, 1);
  assert.equal(endpoints.events.aborts.length, 1);
  assert.equal(f.calls.join.length, 0);
  cancel.resolve();
  ok(await bounded(first));
  ok(await bounded(second));
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.calls.runtimeClose.filter(call => call.outcome.outcome === "ok").length, 1);
  ok(await bounded(f.adapter.retire()));
  assert.equal(f.calls.join.length, 1);
});

test("Next retirement retains the admitted SDK identity despite public handle mutation", async t => {
  const f = await fixture(t), ownedScope = await f.initialize();
  const ownedRuntime = f.adapter.currentRuntime();
  const identity = ({ kind, slot, generation }) => ({ kind, slot, generation });
  const originalScope = identity(ownedScope.toJSON());
  const originalRuntime = identity(ownedRuntime.toJSON());
  const unrelatedRuntime = ok(await f.sdk.createBrowserRuntime({ eagerInit: false }));
  const unrelatedScope = ok(unrelatedRuntime.enterScope("independent-owner"));
  const unrelatedIdentity = identity(unrelatedScope.toJSON());
  t.after(() => unrelatedRuntime.closeAsync());
  const ownedEndpoints = f.pair(), unrelatedEndpoints = f.pair();
  const ownedTransfer = f.pipe(ownedScope, ownedEndpoints);
  const unrelatedTransfer = f.pipe(unrelatedScope, unrelatedEndpoints);
  await bounded(Promise.all([ownedEndpoints.pulled.promise, unrelatedEndpoints.pulled.promise]));
  assert.equal(f.snapshot().tasks.total, 2);
  assert.notDeepEqual(originalScope, unrelatedIdentity);
  let publicCloseCalls = 0;
  const replacedClose = () => { publicCloseCalls += 1; throw new Error("replaced public close must not run"); };
  ownedScope.core = unrelatedScope.core;
  ownedScope.closeAsync = replacedClose;
  ownedScope.close = replacedClose;
  ownedRuntime.closeAsync = replacedClose;
  ownedRuntime.close = replacedClose;

  ok(await bounded(f.adapter.closeAsync("close captured generation")));
  assert.equal(publicCloseCalls, 0, "cleanup uses the methods captured at admission");
  assert.equal(f.snapshot().tasks.total, 1, "only the admitted Next task is retired");
  cancelled(await bounded(ownedTransfer.completed));
  await pending(unrelatedTransfer.completed);
  assert.equal(unrelatedEndpoints.events.cancels.length, 0);
  assert.equal(unrelatedEndpoints.events.aborts.length, 0);
  const closedScopes = f.calls.scopeClose.filter(call => call.outcome.outcome === "ok")
    .map(call => identity(JSON.parse(call.args[0])));
  const closedRuntimes = f.calls.runtimeClose.filter(call => call.outcome.outcome === "ok")
    .map(call => identity(JSON.parse(call.args[0])));
  assert.deepEqual(closedScopes, [originalScope], "the successful ABI close targets the captured original region");
  assert.deepEqual(closedRuntimes, [originalRuntime], "the original runtime follows its original child barrier");
  unrelatedEndpoints.input.enqueue(Uint8Array.of(9));
  unrelatedEndpoints.input.close();
  assert.equal(ok(await bounded(unrelatedTransfer.completed)).bytesWritten, 1);
  assert.deepEqual(unrelatedEndpoints.events.writes, [[9]]);
  assert.equal(f.snapshot().tasks.total, 0);
  ok(await unrelatedRuntime.closeAsync());
});
