/** Parent cancellation of the actual TypeScript batch implementation.
 * Native Streams, AbortSignals and a real loopback fetch execute here; the
 * scope/handle/terminal ABI and imported per-runtime request limit are doubles.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_batch_signal.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_BATCH_SOURCE
  ?? new URL("../packages/browser/src/fetch-batch.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario_id: "browser-fetch-batch-parent-signal", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual batch source, native Streams/signals/fetch; scope, terminal ABI and request-limit doubles" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "permanent", message } });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "test_cancel", phase: "completed", origin_region: "test",
  origin_task: null, timestamp_nanos: 0, message: "test cleanup", truncated: false } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }); await turn(); assert.equal(done, false, "cleanup/consumer barrier must remain pending"); }
async function load(globals = {}) {
  const context = createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, AbortSignal, EventTarget, ...globals });
  const dependency = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () {
    this.setExport("BROWSER_FETCH_LIMITS", Object.freeze({ maxRequestsPerRuntime: 64 }));
  }, { context });
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
  await module.link(name => { assert.equal(name, "./fetch.js"); return dependency; });
  await module.evaluate();
  return module.namespace;
}
async function fixture(t, options = {}) {
  const observers = { added: [], removed: [] };
  const EventTargetProbe = { prototype: {
    addEventListener(...args) { observers.added.push({ target: this, args }); return Reflect.apply(EventTarget.prototype.addEventListener, this, args); },
    removeEventListener(...args) { observers.removed.push({ target: this, args }); return Reflect.apply(EventTarget.prototype.removeEventListener, this, args); },
  } };
  const { mapFetches } = await load({ EventTarget: EventTargetProbe, ...options.globals });
  const calls = { admitted: [], converted: [], responses: [], cancelled: [], closed: [] };
  const handles = [], batches = [], releases = [];
  let active = 0, maxActive = 0;
  const scope = { fetch(request) {
    assert.equal(this, scope);
    const index = calls.admitted.length; calls.admitted.push(request); active++; maxActive = Math.max(active, maxActive);
    const terminal = deferred(), header = deferred();
    let sent = false, ended = false, retiring;
    const finish = result => { if (!ended) { ended = true; active--; calls.closed.push(index); terminal.resolve(result); } };
    const retire = () => {
      if (retiring) return retiring;
      calls.cancelled.push(index);
      header.resolve(cancelled());
      retiring = (async () => { await options.cleanup?.[index]?.promise; const result = options.terminal?.(index) ?? cancelled(); finish(result); return result; })();
      return retiring;
    };
    const stream = new ReadableStream({
      pull(controller) {
        if (options.idleBody) return;
        if (!sent) { sent = true; controller.enqueue(Uint8Array.of(index)); }
        else { controller.close(); finish(ok(undefined)); }
      },
      cancel() { return retire().then(() => {}); },
    }, { highWaterMark: 0 });
    if (!options.waitHeaders) header.resolve(ok({ status: 200 }));
    const handle = { closed: terminal.promise,
      response() { calls.responses.push(index); return header.promise; },
      toReadableStream() { calls.converted.push(index); return ok(stream); },
      cancel: retire,
    };
    handles.push(handle);
    options.admit?.(index);
    return ok(handle);
  } };
  const requests = count => Array.from({ length: count }, (_, i) => ({ url: `https://example.test/${i}` }));
  const map = (count, consume = async item => [...await new Response(item.body).bytes()], config) => {
    const admitted = mapFetches(scope, Array.isArray(count) ? count : requests(count), consume, config);
    assert.equal(admitted.outcome, "ok"); batches.push(admitted.value); return admitted.value;
  };
  t.after(async () => {
    releases.forEach(release => release());
    options.cleanup?.forEach(gate => gate.resolve());
    await Promise.all(batches.map(batch => batch.cancel("test cleanup")));
    await Promise.all(handles.map(handle => handle.cancel()));
  });
  return { mapFetches, scope, requests, map, calls, observers, releases, get maxActive() { return maxActive; } };
}

for (const signal of [{}, true, "abort", new AbortController(), Object.create(AbortSignal.prototype)]) {
  test(`invalid signal ${Object.prototype.toString.call(signal)} refuses before admission`, async t => {
    const f = await fixture(t);
    assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { signal }).outcome, "err");
    assert.equal(f.calls.admitted.length, 0); assert.equal(f.observers.added.length, 0);
  });
}
for (const property of ["aborted", "reason"]) test(`custom ${property} accessor is rejected without invocation`, async t => {
  const controller = new AbortController(); let reads = 0;
  Object.defineProperty(controller.signal, property, { get() { reads++; throw new Error("must not inspect"); } });
  const f = await fixture(t);
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { signal: controller.signal }).outcome, "err");
  assert.equal(reads, 0); assert.equal(f.calls.admitted.length, 0);
});
test("throwing option getter refuses before scope admission", async t => {
  const f = await fixture(t);
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { get signal() { throw 1; } }).outcome, "err");
  assert.equal(f.calls.admitted.length, 0);
});
test("null and omitted signals preserve hosts without signal-composition support", async t => {
  const f = await fixture(t, { globals: { AbortSignal: undefined, EventTarget: undefined } });
  for (const config of [{}, { signal: null }]) assert.equal((await f.map(2, undefined, config).result).outcome, "ok");
  const signal = new AbortController().signal;
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { signal }).outcome, "err");
  assert.equal(f.calls.admitted.length, 4);
});
test("missing native any refuses supplied signals without changing unsignalled batches", async t => {
  const f = await fixture(t, { globals: { AbortSignal: { prototype: AbortSignal.prototype, any: undefined } } });
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { signal: new AbortController().signal }).outcome, "err");
  assert.equal((await f.map(2).result).outcome, "ok");
});
test("pre-aborted signal admits no requests and does not inspect arbitrary reasons", async t => {
  const controller = new AbortController(); let inspected = 0;
  controller.abort({ get message() { inspected++; throw 1; }, toString() { inspected++; throw 1; } });
  const f = await fixture(t); const batch = f.map(10, () => assert.fail("no consumer"), { signal: controller.signal });
  const result = await batch.result;
  assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.message, "fetch batch cancelled by signal");
  assert.equal(inspected, 0); assert.equal(f.calls.admitted.length, 0);
  assert.equal(f.observers.added.length, 1); assert.equal(f.observers.removed.length, 1);
});
test("empty input remains successful with a valid pre-aborted parent", async t => {
  const controller = new AbortController(); controller.abort(); const f = await fixture(t);
  const result = await f.map(0, () => assert.fail(), { signal: controller.signal }).result;
  assert.equal(result.outcome, "ok"); assert.deepEqual([...result.value], []); assert.equal(f.observers.added.length, 0);
});
test("abort immediately after admission fences the first microtask", async t => {
  const controller = new AbortController(); const f = await fixture(t);
  const batch = f.map(10, () => assert.fail("no consumer"), { signal: controller.signal }); controller.abort();
  assert.equal((await batch.result).outcome, "cancelled"); assert.equal(f.calls.admitted.length, 0);
});
test("abort during request snapshot is caught after subscription", async t => {
  const controller = new AbortController(); const f = await fixture(t); const requests = f.requests(2);
  Object.defineProperty(requests, 0, { get() { controller.abort(); return { url: "https://example.test/a" }; } });
  assert.equal((await f.map(requests, () => assert.fail(), { signal: controller.signal }).result).outcome, "cancelled");
  assert.equal(f.calls.admitted.length, 0);
});
test("synchronous abort inside scope admission retires the returned handle", { timeout: 3000 }, async t => {
  const controller = new AbortController(); const f = await fixture(t, { admit() { controller.abort(); } });
  const result = await f.map(5, () => assert.fail("no consumer"), { signal: controller.signal }).result;
  assert.equal(result.outcome, "cancelled"); assert.equal(f.calls.admitted.length, 1);
  assert.deepEqual(f.calls.cancelled, [0]); assert.deepEqual(f.calls.closed, [0]); assert.equal(f.calls.responses.length, 0);
});
test("parent cancellation fences queued requests and joins every held header cleanup", { timeout: 3000 }, async t => {
  const controller = new AbortController(), cleanup = [deferred(), deferred(), deferred()];
  const f = await fixture(t, { cleanup, waitHeaders: true });
  const batch = f.map(9, () => assert.fail("no consumer"), { concurrency: 3, signal: controller.signal });
  await turn(); assert.equal(f.calls.responses.length, 3); controller.abort();
  await pending(batch.result); assert.deepEqual(f.calls.cancelled, [0, 1, 2]); assert.equal(f.calls.admitted.length, 3);
  cleanup[0].resolve(); cleanup[1].resolve(); await pending(batch.result); assert.equal(f.calls.closed.length, 2);
  cleanup[2].resolve(); assert.equal((await batch.result).outcome, "cancelled"); assert.equal(f.calls.closed.length, 3);
});
test("earlier stopImmediatePropagation cannot suppress batch cancellation", { timeout: 3000 }, async t => {
  const controller = new AbortController(); controller.signal.addEventListener("abort", event => event.stopImmediatePropagation());
  const f = await fixture(t, { waitHeaders: true }); const batch = f.map(5, () => assert.fail(), { signal: controller.signal, concurrency: 1 });
  await turn(); controller.abort(); await turn(); assert.equal(f.calls.cancelled.length, 1);
  assert.equal((await batch.result).outcome, "cancelled"); assert.notEqual(f.observers.added[0].target, controller.signal);
});
test("cooperative consumer rethrow preserves owned cancellation rather than inventing panic", { timeout: 3000 }, async t => {
  const controller = new AbortController(); const signals = []; const f = await fixture(t, { idleBody: true });
  const batch = f.map(5, item => { signals.push(item.signal); return new Promise((_, reject) => item.signal.addEventListener("abort", () => reject(item.signal.reason), { once: true })); }, { concurrency: 2, signal: controller.signal });
  await turn(); assert.equal(signals.length, 2); controller.abort(); assert.equal(signals.every(signal => signal.aborted), true);
  assert.equal((await batch.result).outcome, "cancelled"); assert.equal(f.calls.closed.length, 2);
});
test("parent cancellation still waits for an independently parked consumer", { timeout: 3000 }, async t => {
  const controller = new AbortController(), gate = deferred(); const f = await fixture(t); const signals = []; f.releases.push(gate.resolve);
  const batch = f.map(3, async item => { signals.push(item.signal); await gate.promise; return 7; }, { concurrency: 1, signal: controller.signal });
  await turn(); assert.equal(signals.length, 1); controller.abort(); assert.equal(signals[0].aborted, true);
  await pending(batch.result); assert.equal(f.calls.closed.length, 1); gate.resolve(); assert.equal((await batch.result).outcome, "cancelled");
});
test("real late consumer panic remains stronger than parent cancellation", { timeout: 3000 }, async t => {
  const controller = new AbortController(), gate = deferred(); const f = await fixture(t); let signal; f.releases.push(gate.resolve);
  const batch = f.map(3, async item => { signal = item.signal; await gate.promise; throw new Error("private consumer detail"); }, { concurrency: 1, signal: controller.signal });
  await turn(); controller.abort(); assert.equal(signal.aborted, true); gate.resolve(); const result = await batch.result;
  assert.equal(result.outcome, "panicked"); assert.doesNotMatch(result.message, /private consumer detail/);
});
for (const parentFirst of [true, false]) test(`first cancellation reason is stable, parentFirst=${parentFirst}`, { timeout: 3000 }, async t => {
  const controller = new AbortController(), cleanup = [deferred()]; const f = await fixture(t, { cleanup, waitHeaders: true });
  const batch = f.map(3, () => assert.fail(), { concurrency: 1, signal: controller.signal }); await turn();
  if (parentFirst) controller.abort(); const settled = batch.cancel("manual reason"); if (!parentFirst) controller.abort();
  assert.equal(settled, batch.cancel("later reason")); await pending(settled); cleanup[0].resolve();
  const result = await settled; assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.message, parentFirst ? "fetch batch cancelled by signal" : "manual reason");
});
test("cleanup panic outranks parent cancellation without admitting queued work", { timeout: 3000 }, async t => {
  const controller = new AbortController(); const f = await fixture(t, { waitHeaders: true, terminal: () => ({ outcome: "panicked", message: "terminal panic" }) });
  const batch = f.map(3, () => assert.fail(), { concurrency: 1, signal: controller.signal }); await turn(); controller.abort(); await turn();
  assert.equal(f.calls.cancelled.length, 1); const result = await batch.result; assert.equal(result.outcome, "panicked"); assert.equal(result.message, "terminal panic");
});
test("successful results retain input order and detach before late parent abort", { timeout: 3000 }, async t => {
  const controller = new AbortController(); const f = await fixture(t);
  const batch = f.map(17, undefined, { concurrency: 2, signal: controller.signal }); const result = await batch.result;
  assert.equal(result.outcome, "ok"); assert.deepEqual(Array.from(result.value, item => item[0]), Array.from({ length: 17 }, (_, i) => i));
  assert.ok(f.maxActive <= 2); assert.equal(f.observers.added.length, 1); assert.equal(f.observers.removed.length, 1);
  assert.equal(f.observers.removed[0].target, f.observers.added[0].target);
  assert.equal(f.observers.removed[0].args[1], f.observers.added[0].args[1]);
  const before = f.calls.cancelled.length; controller.abort(); assert.equal(await batch.result, result); assert.equal(f.calls.cancelled.length, before);
});
test("manual batch cancellation never aborts the caller's parent", { timeout: 3000 }, async t => {
  const controller = new AbortController(); const f = await fixture(t, { waitHeaders: true });
  const batch = f.map(1, () => assert.fail(), { signal: controller.signal }); await turn(); await batch.cancel();
  assert.equal(controller.signal.aborted, false); assert.equal(f.observers.removed.length, 1);
});
test("listener installation refusal starts no requests", async t => {
  const f = await fixture(t, { globals: { EventTarget: { prototype: {
    addEventListener() { throw new Error("listener admission refused"); }, removeEventListener: EventTarget.prototype.removeEventListener,
  } } } });
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { signal: new AbortController().signal }).outcome, "err");
  assert.equal(f.calls.admitted.length, 0);
});

/** Explicit handle adapter around native fetch, not an SDK task-ABI implementation. */
function nativeScope() {
  const handles = []; let admitted = 0, retired = 0;
  const scope = { fetch(request) {
    admitted++; const abort = new AbortController(), header = deferred(), terminal = deferred(); let reader, retiring;
    const response = fetch(request.url, { signal: abort.signal }).then(value => {
      reader = value.body.getReader(); header.resolve(ok({ status: value.status })); return value;
    }, () => { header.resolve(cancelled()); terminal.resolve(cancelled()); });
    const retire = () => retiring ??= (async () => {
      retired++;
      abort.abort(); await response; try { if (reader) await reader.cancel(); } catch { /* Aborted socket. */ }
      terminal.resolve(cancelled()); return cancelled();
    })();
    const body = new ReadableStream({ async pull(c) {
      await response;
      if (!reader) { c.error(new Error("native fetch stopped")); return; }
      try { const item = await reader.read(); if (item.done) { c.close(); terminal.resolve(ok(undefined)); } else c.enqueue(item.value); }
      catch { c.error(new Error("native fetch stopped")); terminal.resolve(cancelled()); }
    }, cancel() { return retire().then(() => {}); } }, { highWaterMark: 0 });
    const handle = { response: () => header.promise, toReadableStream: () => ok(body), closed: terminal.promise, cancel: retire };
    handles.push(handle); return ok(handle);
  } };
  return { scope, handles, get admitted() { return admitted; }, get retired() { return retired; } };
}
for (const deadline of [false, true]) test(`real HTTP ${deadline ? "caller timeout" : "parent abort"} drains native fetch and stops queued requests`, { timeout: 5000 }, async t => {
  const seen = deferred(), disconnected = deferred(); const server = createServer((_req, res) => {
    res.on("close", () => disconnected.resolve()); res.writeHead(200); res.write("prefix"); seen.resolve();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const bridge = nativeScope(), controller = new AbortController(); let batch;
  t.after(async () => {
    controller.abort(); if (batch) await batch.cancel("test cleanup"); await Promise.all(bridge.handles.map(handle => handle.cancel()));
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  });
  const { mapFetches } = await load(); const consumerStarted = deferred();
  const signal = deadline ? AbortSignal.timeout(500) : controller.signal;
  const admitted = mapFetches(bridge.scope, Array.from({ length: 4 }, () => ({ url: `http://127.0.0.1:${server.address().port}/` })), async item => {
    const reader = item.body.getReader(); const first = await reader.read(); assert.equal(new TextDecoder().decode(first.value), "prefix"); consumerStarted.resolve();
    await reader.read();
  }, { concurrency: 1, signal });
  assert.equal(admitted.outcome, "ok"); batch = admitted.value;
  await seen.promise; await consumerStarted.promise;
  assert.equal(signal.aborted, false, "witness native body progress before triggering cancellation");
  if (!deadline) controller.abort();
  else await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true }));
  await turn(); assert.equal(bridge.admitted, 1); assert.equal(signal.aborted, true);
  assert.equal(bridge.retired, 1, "parent cancellation reached native transport retirement");
  const result = await batch.result; assert.equal(result.outcome, "cancelled");
  await disconnected.promise;
  assert.equal((await bridge.handles[0].closed).outcome, "cancelled");
});
