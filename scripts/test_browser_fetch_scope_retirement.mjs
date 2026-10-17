/** Scope-drain cleanup receipts on the complete actual fetch manager.
 * Native Streams and loopback HTTP execute; task ABI and fault-injected host
 * readers/controllers are explicit doubles. No full SDK/Rust/WASM claim.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_scope_retirement.mjs
 * ASUPERSYNC_FETCH_SOURCE selects the unchanged manager for negative controls.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_FETCH_SOURCE ?? new URL("../packages/browser/src/fetch.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "scope-drain-retirement", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "complete actual fetch manager; native Streams/HTTP; explicit task ABI and host-fault doubles" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) {
  let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn(); assert.equal(settled, false, "scope drain must retain admitted pending work");
}
function body(cancel) {
  const counts = { cancel: 0, pull: 0 };
  const stream = new ReadableStream({ pull() { counts.pull++; }, cancel() { counts.cancel++; return cancel?.(); } }, { highWaterMark: 0 });
  return { stream, counts };
}
function responseWithReader(reader) {
  return { status: 200, statusText: "", url: "https://example.test/", headers: new Headers(), body: { getReader: () => reader } };
}
async function fixture(t, options = {}) {
  let taskId = 0; const handles = [], gates = [], calls = { cancel: [], join: [] };
  const gate = () => { const d = deferred(); gates.push(d); return d; };
  class Handle { constructor(raw) { this.raw = raw; } toJSON() { return { ...this.raw }; } }
  const exports = { Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
    cancelled: cancellation => ({ outcome: "cancelled", cancellation }) }, RegionHandle: Handle,
    taskSpawn: () => ok(new Handle({ kind: "task", slot: ++taskId, generation: 1 })),
    taskCancel(request) { calls.cancel.push(request); return options.cancel?.(request) ?? ok(undefined); },
    taskJoin(task, terminal) { calls.join.push(task); return options.join?.(task, terminal) ?? terminal; } };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, Request, Blob });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
  await module.link(name => { assert.equal(name, "@asupersync/browser-core"); return abi; }); await module.evaluate();
  const api = module.namespace, origin = options.origin ?? "https://example.test";
  const scopes = [1, 2].map(slot => new Handle({ kind: "region", slot, generation: 1 }));
  const keys = scopes.map(scope => api.browserFetchHandleKey(scope.toJSON()));
  const grant = { rootKey: "runtime:1", authority: api.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET", "POST"] }) };
  const manager = api.createBrowserFetchManager({ lookup: key => keys.includes(key) ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController: options.Controller ?? AbortController, fetch: options.fetch ?? (() => new Response(null)) }) });
  const start = (path = "/", supplied = {}, scope = 0) => {
    const result = manager.start(scopes[scope], { url: origin + path, ...supplied }, null);
    assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value;
  };
  const drain = (scope = 0) => manager.drainScopes(new Set([keys[scope]]), "scope_close");
  t.after(async () => {
    options.release?.(); gates.forEach(g => g.resolve()); manager.closeScopes(new Set(keys), "test cleanup");
    await Promise.all(handles.map(h => h.closed));
  });
  return { manager, start, drain, keys, gate, calls };
}

test("scope drain reports actual response cancellation failure, not released credit", async t => {
  const input = body(() => { throw new Error("cleanup failed"); });
  const f = await fixture(t, { fetch: () => new Response(input.stream) }), handle = f.start(); await handle.response();
  const result = await f.drain(); assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response cancellation failed/);
  assert.equal((await handle.closed).outcome, "cancelled"); assert.equal((await handle.closed).cancellation.kind, "scope_close");
  assert.equal((await handle.retire()).outcome, "err"); assert.equal(input.counts.cancel, 1); assert.equal(input.counts.pull, 0);
  assert.equal(f.calls.cancel.length, 1); assert.equal(f.calls.join.length, 1);
});
test("healthy scope drain keeps scope cancellation and completes exactly once", async t => {
  const input = body(), f = await fixture(t, { fetch: () => new Response(input.stream) }), handle = f.start(); await handle.response();
  assert.equal((await f.drain()).outcome, "ok"); assert.equal((await handle.retire()).outcome, "ok");
  assert.equal((await handle.closed).cancellation.kind, "scope_close"); assert.equal(input.counts.cancel, 1);
  assert.equal(f.calls.cancel.length, 1); assert.equal(f.calls.join.length, 1); assert.equal(input.counts.pull, 0);
});
test("scope drain observes host abort refusal even when response cancellation succeeds", async t => {
  const input = body(); class BrokenController extends AbortController { abort() { throw new Error("host abort failed"); } }
  const f = await fixture(t, { Controller: BrokenController, fetch: () => new Response(input.stream) }), handle = f.start(); await handle.response();
  const result = await f.drain(); assert.equal(result.outcome, "err"); assert.match(result.failure.message, /host abort failed/);
  assert.equal(input.counts.cancel, 1); assert.equal((await handle.closed).outcome, "cancelled");
});
test("scope drain reports a host reader release failure", async t => {
  let released = 0; const reader = { closed: Promise.resolve(), cancel: async () => {}, releaseLock() { released++; throw new Error("release failed"); } };
  const f = await fixture(t, { fetch: () => responseWithReader(reader) }), handle = f.start(); await handle.response();
  const result = await f.drain(); assert.equal(result.outcome, "err"); assert.match(result.failure.message, /reader release failed/);
  assert.equal(released, 1);
});
test("scope drain waits for late response disposal and reports its cleanup failure", async t => {
  const launch = deferred(), late = body(() => { throw new Error("late disposal failed"); });
  const f = await fixture(t, { fetch: () => launch.promise, release: () => launch.resolve(new Response(null)) });
  const handle = f.start(), drained = f.drain(); await pending(drained); launch.resolve(new Response(late.stream));
  const result = await drained; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /late response disposal failed/);
  assert.equal(late.counts.cancel, 1); assert.equal((await handle.closed).outcome, "cancelled");
});
test("scope drain includes failing unused upload cleanup", async t => {
  const upload = body(() => { throw new Error("upload cleanup failed"); });
  const f = await fixture(t, { fetch: (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
  }) });
  const handle = f.start("/upload", { method: "POST", body: upload.stream }), result = await f.drain();
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /upload cleanup failed/);
  assert.equal(upload.counts.cancel, 1); assert.equal(upload.counts.pull, 0); assert.equal((await handle.closed).outcome, "cancelled");
});
test("failed cleanup still joins every other admitted member before returning", async t => {
  const slow = deferred(), bad = body(() => { throw new Error("cleanup failed"); }), good = body(() => slow.promise);
  const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream), release: slow.resolve });
  const a = f.start("/bad"), b = f.start("/slow"); await Promise.all([a.response(), b.response()]);
  const drained = f.drain(); await pending(drained);
  assert.equal((await a.retire()).outcome, "err"); assert.equal(bad.counts.cancel, 1); assert.equal(good.counts.cancel, 1);
  slow.resolve(); assert.equal((await drained).outcome, "err"); assert.equal((await b.closed).outcome, "cancelled");
});
test("concurrent scope drains join the same retirement without duplicate cleanup", async t => {
  const gate = deferred(), input = body(async () => { await gate.promise; throw new Error("cleanup failed"); });
  const f = await fixture(t, { fetch: () => new Response(input.stream), release: gate.resolve }), handle = f.start(); await handle.response();
  const first = f.drain(), second = f.drain(); await pending(first); await pending(second); gate.resolve();
  assert.equal((await first).outcome, "err"); assert.equal((await second).outcome, "err");
  assert.equal(input.counts.cancel, 1); assert.equal(f.calls.cancel.length, 1); assert.equal(f.calls.join.length, 1);
});
test("scope drain joins an already-started explicit retirement", async t => {
  const gate = deferred(), input = body(async () => { await gate.promise; throw new Error("cleanup failed"); });
  const f = await fixture(t, { fetch: () => new Response(input.stream), release: gate.resolve }), handle = f.start(); await handle.response();
  const retirement = handle.retire("caller retired"), drained = f.drain(); await pending(drained); gate.resolve();
  const result = await drained; assert.equal(result.outcome, "err"); assert.equal(result, await retirement);
  assert.equal(f.calls.cancel.length, 1); assert.equal(f.calls.cancel[0].message, "caller retired");
});
test("cancellation admission refusal remains retryable and does not implicitly stop I/O", async t => {
  let refuse = true; const input = body(), f = await fixture(t, {
    cancel: () => refuse ? err("cancellation refused") : ok(undefined), fetch: () => new Response(input.stream) });
  const handle = f.start(); await handle.response();
  const refused = await f.drain(); assert.equal(refused.outcome, "err"); assert.equal(refused.failure.message, "cancellation refused");
  assert.equal(input.counts.cancel, 0); assert.equal(f.calls.join.length, 0); await pending(handle.closed);
  refuse = false; assert.equal((await f.drain()).outcome, "ok"); assert.equal(input.counts.cancel, 1);
  assert.equal(f.calls.cancel.length, 2); assert.equal((await handle.retire()).outcome, "ok");
});
test("terminal publication refusal still retains the original failure and credit", async t => {
  const input = body(), f = await fixture(t, { join: () => err("publication refused"), fetch: () => new Response(input.stream) });
  const handle = f.start(); await handle.response();
  const result = await f.drain(); assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "publication refused");
  assert.equal((await f.drain()).failure.message, "publication refused"); assert.equal(f.calls.join.length, 1);
  assert.equal((await handle.retire()).outcome, "err");
});
test("an ordinary request failure is not misclassified as a cleanup failure", async t => {
  const f = await fixture(t, { fetch() { throw new Error("transport refused"); } }), handle = f.start();
  const drained = f.drain(); assert.equal((await handle.closed).outcome, "err");
  assert.equal((await drained).outcome, "ok"); assert.equal((await handle.retire()).outcome, "ok");
});
test("stored native stream errors are not cancellation callback failures", async t => {
  const original = new Error("source failed"); let cancels = 0;
  const input = new ReadableStream({ start(c) { c.error(original); }, cancel() { cancels++; } });
  const f = await fixture(t, { fetch: () => new Response(input) }), handle = f.start();
  await turn(); assert.equal((await handle.closed).outcome, "err");
  assert.equal((await handle.retire()).outcome, "ok"); assert.equal((await f.drain()).outcome, "ok"); assert.equal(cancels, 0);
});
test("scope selection isolates unrelated live requests", async t => {
  const bad = body(() => { throw new Error("cleanup failed"); }), good = body();
  const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream) });
  const a = f.start("/bad"), b = f.start("/good", {}, 1); await Promise.all([a.response(), b.response()]);
  assert.equal((await f.drain(0)).outcome, "err"); assert.equal(good.counts.cancel, 0); await pending(b.closed);
  assert.equal((await f.drain(1)).outcome, "ok"); assert.equal(good.counts.cancel, 1);
});
test("historically retired handles retain their receipts without poisoning an empty scope", async t => {
  const input = body(() => { throw new Error("cleanup failed"); }), f = await fixture(t, { fetch: () => new Response(input.stream) });
  const handle = f.start(); await handle.response(); const failed = await handle.retire(); assert.equal(failed.outcome, "err");
  assert.equal((await f.drain()).outcome, "ok"); assert.equal(await handle.retire(), failed);
});
test("pending body reads are joined independently of the source cancellation promise", async t => {
  const read = deferred(); let reads = 0, releases = 0, cancels = 0;
  const reader = { closed: Promise.resolve(), read() { reads++; return read.promise; }, cancel: async () => { cancels++; }, releaseLock() { releases++; } };
  const f = await fixture(t, { fetch: () => responseWithReader(reader), release: () => read.resolve({ done: true }) });
  const handle = f.start(); await handle.response(); const reading = handle.read(); await turn(); assert.equal(reads, 1);
  const drained = f.drain(); await pending(drained); assert.equal(cancels, 1); assert.equal(releases, 0);
  read.resolve({ done: true }); assert.equal((await reading).outcome, "cancelled"); assert.equal((await drained).outcome, "ok");
  assert.equal(releases, 1);
});
test("explicit owner release cannot erase a captured drain's cleanup failure", async t => {
  const gate = deferred(), input = body(async () => { await gate.promise; throw new Error("cleanup failed"); });
  const f = await fixture(t, { fetch: () => new Response(input.stream), release: gate.resolve }), handle = f.start(); await handle.response();
  const drained = f.drain(); await pending(drained); f.manager.closeScopes(new Set([f.keys[0]]), "owner released"); gate.resolve();
  assert.equal((await drained).outcome, "err"); assert.equal(f.calls.join.length, 0);
});
test("empty scope drain has no task or host effects", async t => {
  const f = await fixture(t); assert.equal((await f.drain()).outcome, "ok");
  assert.equal(f.calls.cancel.length + f.calls.join.length, 0);
});
test("real HTTP scope drain closes every admitted native response", { timeout: 5000 }, async t => {
  const disconnected = deferred(); let count = 0;
  const server = createServer((req, res) => {
    req.on("close", () => { if (++count === 2) disconnected.resolve(); }); res.writeHead(200); res.write("prefix");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const f = await fixture(t, { origin: `http://127.0.0.1:${server.address().port}`, fetch });
  const a = f.start("/a"), b = f.start("/b"); await Promise.all([a.response(), b.response()]);
  assert.equal((await f.drain()).outcome, "ok"); await disconnected.promise;
  assert.equal((await a.retire()).outcome, "ok"); assert.equal((await b.retire()).outcome, "ok");
  assert.equal((await a.closed).cancellation.kind, "scope_close"); assert.equal(f.calls.join.length, 2);
});
