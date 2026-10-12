/** Bounded scope admission through real SDK fetch/Streams and loopback HTTP.
 * Task ABI is an explicit double, not Rust/WASM integration evidence.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_batch.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const sources = Object.fromEntries(["fetch", "fetch-batch"].map(name => [name, readFileSync(name === "fetch-batch" && process.env.ASUPERSYNC_FETCH_BATCH_SOURCE
  ? process.env.ASUPERSYNC_FETCH_BATCH_SOURCE : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario_id: "browser-fetch-bounded-batch", source_sha256: Object.fromEntries(Object.entries(sources).map(([name, text]) => [name, createHash("sha256").update(text).digest("hex")])),
  evidence_scope: "actual SDK fetch/batch, native Streams and loopback HTTP; explicit task-ABI double" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "permanent", message } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }); await turn(); assert.equal(done, false); }
function bytes(values = [7], gate) {
  let sent = false;
  return new ReadableStream({ pull(c) { if (sent) c.close(); else { sent = true; c.enqueue(Uint8Array.from(values)); } }, cancel() { return gate?.promise; } }, { highWaterMark: 0 });
}
async function fixture(t, options = {}) {
  let next = 0, active = 0, maxActive = 0;
  const calls = { fetch: [], cancel: [], join: [], consume: [] }, handles = [], cleanup = [], batches = [];
  class Handle { constructor(raw) { this.raw = raw; } toJSON() { return { ...this.raw }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }), cancelled: cancellation => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn() { active++; maxActive = Math.max(maxActive, active); return ok(new Handle({ kind: "task", slot: ++next, generation: 1, owner_token: "owner" })); },
    taskCancel(request) { calls.cancel.push(request); return options.cancel?.(request) ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join.push({ task, outcome }); active--; return options.join?.(task, outcome) ?? outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortController, AbortSignal, EventTarget, Request, Blob,
    ReadableStream, ReadableStreamDefaultReader, ...options.globals });
  const abi = new SyntheticModule(Object.keys(exports), function () { for (const [name, value] of Object.entries(exports)) this.setExport(name, value); }, { context });
  const modules = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context, identifier: name })]));
  for (const module of Object.values(modules)) if (module.status === "unlinked") await module.link(name => name === "@asupersync/browser-core" ? abi : modules[name.replace(/^\.\//, "").replace(/\.js$/, "")]);
  await modules["fetch-batch"].evaluate();
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = modules.fetch.namespace;
  const core = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "owner" });
  const scopeKey = browserFetchHandleKey(core.toJSON()), origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "root", authority: prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET", "POST"], maxHeaderCount: 2 }) };
  const host = { AbortController, setTimeout, clearTimeout, fetch(url, init) {
    const index = calls.fetch.length; calls.fetch.push({ url, init });
    if (options.fetch) return options.fetch(url, init, index);
    return new Response(bytes([index % 256]));
  } };
  const manager = createBrowserFetchManager({ lookup: key => key === scopeKey ? grant : null, isClosing: () => false, globalObject: () => host });
  const scope = { fetch(request) {
    assert.equal(this, scope, "scope method keeps its owner");
    options.admit?.(request, calls.fetch.length);
    const outcome = manager.start(core, request, null);
    if (outcome.outcome === "ok") handles.push(outcome.value);
    return outcome;
  } };
  const requests = count => Array.from({ length: count }, (_, index) => ({ url: `${origin}/${index}` }));
  const map = (count, consume = async item => Array.from(await new Response(item.body).bytes()), config) => {
    const admitted = modules["fetch-batch"].namespace.mapFetches(scope, Array.isArray(count) ? count : requests(count), consume, config);
    assert.equal(admitted.outcome, "ok"); batches.push(admitted.value); return admitted.value;
  };
  t.after(async () => {
    for (const release of cleanup) release();
    await Promise.all(batches.map(batch => batch.cancel("test cleanup")));
    manager.closeScopes(new Set([scopeKey]), "test cleanup");
    await Promise.all(handles.map(handle => handle.closed));
  });
  return { scope, manager, scopeKey, calls, handles, cleanup, requests, map, ...modules["fetch-batch"].namespace, get maxActive() { return maxActive; } };
}

for (const concurrency of [0, -1, 1.5, 65, NaN, Infinity, "2", null]) test(`invalid concurrency ${String(concurrency)} refuses before effects`, async t => {
  const f = await fixture(t); assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}, { concurrency }).outcome, "err"); assert.equal(f.calls.fetch.length, 0);
});
test("invalid arrays, consumers and scopes refuse before effects", async t => {
  const f = await fixture(t);
  for (const requests of [null, {}, new Array(100_001)]) assert.equal(f.mapFetches(f.scope, requests, () => {}).outcome, "err");
  assert.equal(f.mapFetches(f.scope, [], null).outcome, "err");
  assert.equal(f.mapFetches({}, [], () => {}).outcome, "err");
  assert.equal(f.calls.fetch.length, 0);
});
test("empty map is a frozen identity without host stream support", async t => {
  const f = await fixture(t, { globals: { ReadableStreamDefaultReader: undefined, AbortController: undefined } });
  const empty = f.map(0); assert.equal((await empty.cancel()).outcome, "ok");
  const result = await empty.result; assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 0); assert.equal(Object.isFrozen(result.value), true);
  assert.equal(f.mapFetches(f.scope, f.requests(1), () => {}).outcome, "err");
});
test("cancellation before scheduling makes zero requests", async t => {
  const f = await fixture(t); const batch = f.map(10);
  const first = batch.cancel("stop before start"); assert.equal(first, batch.cancel("ignored"));
  assert.equal((await first).outcome, "cancelled"); assert.equal((await batch.result).cancellation.message, "stop before start"); assert.equal(f.calls.fetch.length, 0);
});
test("129 requests progress within four admission slots with ordered exact bodies", { timeout: 5000 }, async t => {
  const f = await fixture(t); const result = await f.map(129).result;
  assert.equal(result.outcome, "ok"); assert.deepEqual(Array.from(result.value, v => v[0]), Array.from({ length: 129 }, (_, i) => i));
  assert.equal(f.calls.fetch.length, 129); assert.equal(f.calls.join.length, 129); assert.ok(f.maxActive <= 4); assert.equal(f.maxActive, 4);
});
test("consumer completion, not header arrival, controls admission", { timeout: 3000 }, async t => {
  const gates = [deferred(), deferred()], started = [];
  const f = await fixture(t); f.cleanup.push(...gates.map(x => x.resolve));
  const batch = f.map(3, async item => { started.push(item.index); if (item.index < 2) await gates[item.index].promise; return item.index; }, { concurrency: 2 });
  await pending(batch.result); assert.deepEqual(started, [0, 1]); assert.equal(f.calls.fetch.length, 2);
  gates[1].resolve(); await turn(); assert.equal(f.calls.fetch.length, 3); gates[0].resolve();
  const result = await batch.result; assert.deepEqual(Array.from(result.value), [0, 1, 2]);
});
test("early-return cleanup holds a slot and does not prefetch unread bodies", { timeout: 3000 }, async t => {
  const gate = deferred(); let pulls = 0, cancels = 0;
  const f = await fixture(t, { fetch: (_u, _s, i) => new Response(i ? null : new ReadableStream({ pull() { pulls++; }, cancel() { cancels++; return gate.promise; } }, { highWaterMark: 0 })) });
  f.cleanup.push(gate.resolve); const batch = f.map(2, () => 42, { concurrency: 1 });
  await pending(batch.result); assert.equal(pulls, 0); assert.equal(cancels, 1); assert.equal(f.calls.fetch.length, 1); assert.equal(f.calls.join.length, 0);
  gate.resolve(); assert.equal((await batch.result).outcome, "ok"); assert.equal(f.calls.fetch.length, 2);
});
test("consumer failure cancels siblings but still joins arbitrary consumer settlement", { timeout: 3000 }, async t => {
  const fail = deferred(), linger = deferred(), signals = []; const f = await fixture(t); f.cleanup.push(fail.resolve, linger.resolve);
  const batch = f.map(5, async item => { signals.push(item.signal); if (item.index === 0) { await fail.promise; throw new Error("private payload"); } await linger.promise; return 7; }, { concurrency: 2 });
  await turn(); fail.resolve(); await pending(batch.result); assert.equal(signals.every(s => s.aborted), true); assert.equal(f.calls.fetch.length, 2);
  linger.resolve(); const result = await batch.result; assert.equal(result.outcome, "panicked"); assert.doesNotMatch(result.message, /private payload/); assert.equal(f.calls.join.length, 2);
});
test("caller stop reaches cooperative parked consumers and cancels members in parallel", { timeout: 3000 }, async t => {
  const gates = [deferred(), deferred()]; const cancellations = [];
  const f = await fixture(t, { fetch: (_u, _s, i) => new Response(new ReadableStream({ cancel() { cancellations.push(i); return gates[i].promise; } }, { highWaterMark: 0 })) });
  f.cleanup.push(...gates.map(g => g.resolve));
  const batch = f.map(3, item => new Promise(resolve => item.signal.addEventListener("abort", resolve, { once: true })), { concurrency: 2 });
  await turn(); const stopped = batch.cancel("stop"); await pending(stopped); assert.deepEqual(cancellations, [0, 1]);
  gates[0].resolve(); await pending(stopped); gates[1].resolve(); assert.equal((await stopped).outcome, "cancelled"); assert.equal(f.calls.fetch.length, 2);
});
test("network failure cancels parked-header peers and prevents queued starts", { timeout: 3000 }, async t => {
  const f = await fixture(t, { fetch: (_url, init, index) => index === 0 ? Promise.reject(new Error("network failed")) : new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true })) });
  const result = await f.map(20, () => assert.fail("no headers"), { concurrency: 3 }).result;
  assert.equal(result.outcome, "err"); assert.equal(f.calls.fetch.length, 3); assert.equal(f.calls.join.length, 3);
});
test("idle body failure stops a ready consumer while another header is pending", { timeout: 3000 }, async t => {
  let controller;
  const f = await fixture(t, { fetch: (_url, init, index) => index === 0 ? new Response(new ReadableStream({ start(c) { controller = c; } })) : new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true })) });
  const batch = f.map(10, item => new Promise(resolve => item.signal.addEventListener("abort", resolve, { once: true })), { concurrency: 2 });
  await turn(); controller.error(new Error("idle body")); const result = await batch.result;
  assert.equal(result.outcome, "err"); assert.equal(f.calls.fetch.length, 2); assert.equal(f.calls.join.length, 2);
});
test("early-exit cancellation refusal is not successful batch completion", { timeout: 3000 }, async t => {
  const f = await fixture(t, { cancel: () => err("cancel refused") });
  const result = await f.map(5, () => 42, { concurrency: 1 }).result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "cancel refused"); assert.equal(f.calls.fetch.length, 1);
});
test("terminal publication refusal fences admission instead of recycling a slot", { timeout: 3000 }, async t => {
  const f = await fixture(t, { join: () => err("publication refused") });
  const result = await f.map(5, undefined, { concurrency: 1 }).result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "publication refused"); assert.equal(f.calls.fetch.length, 1);
});
test("cleanup panic outranks a caller cancellation", { timeout: 3000 }, async t => {
  const f = await fixture(t, { join: () => ({ outcome: "panicked", message: "cleanup panic" }) });
  const batch = f.map(2, item => new Promise(resolve => item.signal.addEventListener("abort", resolve, { once: true })));
  await turn(); const result = await batch.cancel(); assert.equal(result.outcome, "panicked"); assert.equal(result.message, "cleanup panic");
});
test("scope cancellation during admission retains and retires the returned handle", { timeout: 3000 }, async t => {
  let batch;
  const f = await fixture(t, { admit() { void batch.cancel("reentrant stop"); } });
  batch = f.map(3, () => assert.fail("consumer must not run"));
  const result = await batch.result; assert.equal(result.outcome, "cancelled"); assert.equal(f.calls.fetch.length, 1); assert.equal(f.calls.join.length, 1);
});
test("unstarted request bodies remain untouched on failure", { timeout: 3000 }, async t => {
  const f = await fixture(t); let reads = 0;
  const requests = f.requests(2); Object.defineProperty(requests[1], "body", { get() { reads++; return bytes(); } });
  const result = await f.map(requests, () => { throw 1; }, { concurrency: 1 }).result; assert.equal(result.outcome, "panicked"); assert.equal(reads, 0);
});
test("HTTP error status is passed to the application and completion cancellation is inert", { timeout: 3000 }, async t => {
  const f = await fixture(t, { fetch: () => new Response(null, { status: 503 }) });
  const batch = f.map(3, item => item.response.status); const result = await batch.result;
  assert.deepEqual(Array.from(result.value), [503, 503, 503]); const n = f.calls.cancel.length; assert.equal((await batch.cancel()).outcome, "ok"); assert.equal(f.calls.cancel.length, n);
});
test("consumer reader cancellation awaits cleanup and preserves bounded progress", { timeout: 3000 }, async t => {
  const f = await fixture(t); const result = await f.map(4, async item => { const reader = item.body.getReader(); await reader.read(); await reader.cancel(); reader.releaseLock(); return item.index; }, { concurrency: 1 }).result;
  assert.equal(result.outcome, "ok"); assert.equal(f.calls.join.length, 4); assert.equal(f.maxActive, 1);
});
test("scope authority refusal stops before any request or consumer", { timeout: 3000 }, async t => {
  const f = await fixture(t); const requests = [{ url: "https://not-authorized.test/" }, ...f.requests(2)];
  const result = await f.map(requests, () => assert.fail("refused"), { concurrency: 2 }).result;
  assert.equal(result.failure.code, "capability_denied"); assert.equal(f.calls.fetch.length, 0);
});
test("original request array is snapshotted before deferred admission", async t => {
  const f = await fixture(t); const requests = f.requests(2); const batch = f.map(requests); requests.length = 0;
  const result = await batch.result; assert.equal(result.value.length, 2); assert.equal(f.calls.fetch.length, 2);
});
test("invalid cancel reason leaves the batch running", async t => {
  const f = await fixture(t); const batch = f.map(2); assert.equal((await batch.cancel(5)).outcome, "err"); assert.equal((await batch.result).outcome, "ok");
});
test("a late response and slow host cleanup cannot be left behind by cancellation", { timeout: 3000 }, async t => {
  const arrived = deferred(), cleanup = deferred(); const response = new Response(bytes([1], cleanup));
  const f = await fixture(t, { fetch: () => arrived.promise }); f.cleanup.push(() => arrived.resolve(response), cleanup.resolve);
  const batch = f.map(4); await turn(); const stop = batch.cancel(); await pending(stop); arrived.resolve(response); await pending(stop); cleanup.resolve();
  assert.equal((await stop).outcome, "cancelled"); assert.equal(f.calls.fetch.length, 4);
});

test("a promise-returning scope is refused and whatever it admits is retired before the result", { timeout: 3000 }, async t => {
  const f = await fixture(t); const scope = { async fetch(request) { return f.scope.fetch(request); } };
  const result = await f.mapFetches(scope, f.requests(3), () => assert.fail("no consumer runs"), { concurrency: 2 }).value.result;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /synchronously/); assert.equal(Object.isFrozen(result), true);
  assert.equal(f.handles.length, 1); assert.equal(f.calls.join.length, 1);
});
test("a rejecting scope promise settles result and cancel with Outcomes", { timeout: 3000 }, async t => {
  const f = await fixture(t); const batch = f.mapFetches({ fetch() { return Promise.reject(new Error("scope down")); } }, f.requests(2), () => assert.fail("no consumer runs")).value;
  const result = await batch.result; assert.equal(result.outcome, "err"); assert.equal((await batch.cancel("after")).outcome, "err"); assert.equal(f.calls.fetch.length, 0);
});
test("a non-Outcome admission fails closed with a frozen internal failure", { timeout: 3000 }, async t => {
  const f = await fixture(t); const result = await f.mapFetches({ fetch() { return 42; } }, f.requests(2), () => assert.fail("no consumer runs")).value.result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure"); assert.equal(Object.isFrozen(result), true);
});
test("a malformed terminal receipt is not a successful member", { timeout: 3000 }, async t => {
  const f = await fixture(t);
  const scope = { fetch(request) {
    const admitted = f.scope.fetch(request); if (admitted.outcome !== "ok") return admitted; const handle = admitted.value;
    return { outcome: "ok", value: { response: () => handle.response(), toReadableStream: () => handle.toReadableStream(), cancel: reason => handle.cancel(reason),
      closed: handle.closed.then(() => ({ outcome: "unknown" })) } };
  } };
  const result = await f.mapFetches(scope, f.requests(2), async item => Array.from(await new Response(item.body).bytes()), { concurrency: 1 }).value.result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure"); assert.equal(f.calls.join.length, f.handles.length);
});

async function serverFixture(t, listener) {
  const server = createServer(listener); await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}
test("real HTTP batches overlap, exceed 64 total requests and preserve result order", { timeout: 10000 }, async t => {
  const waiting = []; let count = 0;
  const origin = await serverFixture(t, (req, res) => { const i = count++; if (i < 4) {
    waiting.push([req, res]); if (waiting.length === 4) for (const [r, s] of waiting.reverse()) s.end(JSON.stringify({ index: Number(r.url.slice(1)) }));
  } else res.end(JSON.stringify({ index: Number(req.url.slice(1)) })); });
  const f = await fixture(t, { origin, fetch });
  const result = await f.map(80, async item => (await new Response(item.body).json()).index).result;
  assert.equal(result.outcome, "ok"); assert.deepEqual(Array.from(result.value), Array.from({ length: 80 }, (_, i) => i)); assert.equal(count, 80); assert.ok(f.maxActive <= 4);
});
test("real peer disconnects for every active body; queued requests never reach the server", { timeout: 5000 }, async t => {
  const ready = deferred(), allClosed = deferred(); let count = 0, closed = 0;
  const origin = await serverFixture(t, (_req, res) => { count++; res.writeHead(200); res.write(Buffer.from([1]));
    res.on("close", () => { if (++closed === 3) allClosed.resolve(); }); if (count === 3) ready.resolve(); });
  const f = await fixture(t, { origin, fetch });
  const batch = f.map(50, item => new Response(item.body).bytes(), { concurrency: 3 });
  await ready.promise; const outcome = await batch.cancel("disconnect"); await allClosed.promise;
  assert.equal(outcome.outcome, "cancelled"); assert.equal(count, 3); assert.equal(closed, 3); assert.equal(f.calls.join.length, 3);
});
