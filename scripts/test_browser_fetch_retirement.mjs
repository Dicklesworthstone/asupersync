/** Actual fetch manager and upload implementation, native Streams and loopback
 * fetch. Only the core task ABI is doubled; this is not Rust/WASM proof.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_retirement.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_FETCH_SOURCE
  ?? new URL("../packages/browser/src/fetch.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "independent-fetch-retirement", sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "actual manager/upload; native Streams/fetch; explicit task ABI double" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; }); await turn(); assert.equal(settled, false); }
// Run the same lifecycle expectations against the original cancellation API in
// the pre-feature control; the export test independently requires retire itself.
const retire = (handle, reason) => (handle.retire ?? handle.cancel)(reason);
async function fixture(t, options = {}) {
  const calls = { spawn: 0, cancel: 0, join: 0, fetch: 0 }, live = new Set(), handles = [], gates = [];
  let sequence = 0;
  class Handle { constructor(value) { this.value = value; } toJSON() { return { ...this.value }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
      cancelled: cancellation => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn() { calls.spawn++; const slot = ++sequence; live.add(slot); return ok(new Handle({ kind: "task", slot, generation: 1 })); },
    taskCancel(request) { calls.cancel++; return options.cancel?.(request, calls) ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join++; const result = options.join?.(outcome, calls); if (result) return result;
      live.delete(task.toJSON().slot); return outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, Request, Blob });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
  await module.link(name => { assert.equal(name, "@asupersync/browser-core"); return abi; }); await module.evaluate();
  const api = module.namespace, scope = new Handle({ kind: "region", slot: 1, generation: 1 });
  const scopeKey = api.browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: api.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET", "POST"] }) };
  const manager = api.createBrowserFetchManager({ lookup: key => key === scopeKey ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController: options.Controller ?? AbortController, setTimeout, clearTimeout,
      fetch(url, init) { calls.fetch++; return options.fetch ? options.fetch(url, init) : new Response(null); } }) });
  function start(extra = {}) { const result = manager.start(scope, { url: `${origin}/resource`, ...extra }, null);
    assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value; }
  const gate = () => { const result = deferred(); gates.push(result); return result; };
  t.after(async () => { gates.forEach(g => g.resolve()); options.release?.(); manager.closeScopes(new Set([scopeKey]), "fixture cleanup");
    await Promise.all(handles.map(h => h.closed)); });
  return { start, gate, calls, live, manager, scopeKey };
}
function response(body) { return { status: 200, statusText: "OK", url: "https://example.test/resource", headers: new Headers(), body }; }
function nativeBody(options = {}) {
  let controller; const count = { pulls: 0, cancels: 0 };
  const stream = new ReadableStream({ start(c) { controller = c; },
    pull(c) { count.pulls++; return options.pull?.(c); },
    cancel(reason) { count.cancels++; return options.cancel?.(reason); },
  }, { highWaterMark: 0 });
  return { stream, count, get controller() { return controller; } };
}

test("SDK handles expose retirement without changing the existing interfaces", async t => {
  const f = await fixture(t), h = f.start(); assert.equal(typeof h.retire, "function");
  assert.equal((await h.response()).outcome, "ok"); assert.equal((await h.closed).outcome, "ok");
  assert.equal((await retire(h)).outcome, "ok"); assert.equal(f.calls.cancel, 0); assert.equal(f.calls.join, 1);
});
test("a failed request can retire successfully while its original error remains visible", async t => {
  const f = await fixture(t, { fetch() { throw new Error("connection refused"); } }), h = f.start();
  const head = await h.response(), terminal = await h.closed;
  assert.equal(head.outcome, "err"); assert.equal(terminal.outcome, "err");
  assert.equal((await retire(h)).outcome, "ok"); assert.equal(await h.cancel(), terminal); assert.equal(f.live.size, 0);
  assert.equal(f.calls.spawn, 1); assert.equal(f.calls.join, 1);
});
test("fully consumed bytes and successful EOF need no new cancellation", async t => {
  const f = await fixture(t, { fetch: () => new Response("payload") }), h = f.start();
  const body = h.toReadableStream(); assert.equal(body.outcome, "ok"); assert.equal(await new Response(body.value).text(), "payload");
  assert.equal((await retire(h)).outcome, "ok"); assert.equal((await h.closed).outcome, "ok"); assert.equal(f.calls.cancel, 0);
});
test("invalid retirement reason has no effects and does not invoke presentation hooks", async t => {
  const b = nativeBody(), f = await fixture(t, { fetch: () => response(b.stream) }), h = f.start(); await h.response(); let touched = 0;
  const result = await retire(h, { toString() { touched++; return "invalid"; } });
  assert.equal(result.outcome, "err"); assert.equal(touched, 0); assert.equal(f.calls.cancel, 0); assert.equal(b.count.cancels, 0);
  assert.equal((await retire(h, "valid")).outcome, "ok");
});
test("retirement is idempotent and works while a native output reader holds the lock", async t => {
  const gate = deferred(), b = nativeBody({ cancel: () => gate.promise });
  const f = await fixture(t, { fetch: () => response(b.stream), release: gate.resolve }), h = f.start(); await h.response();
  const converted = h.toReadableStream(); const reader = converted.value.getReader(); t.after(() => reader.releaseLock());
  const read = reader.read(); void read.catch(() => {}); await pending(read);
  const first = retire(h, "first"), second = retire(h, "second"); assert.equal(first, second); await pending(first);
  assert.equal(b.count.cancels, 1); gate.resolve(); assert.equal((await first).outcome, "ok");
  await assert.rejects(read); assert.equal((await h.closed).cancellation.message, "first");
});
test("retirement joins outstanding host reads independently of cancellation callbacks", async t => {
  const readGate = deferred(), cancelGate = deferred(), terminal = deferred(); let reads = 0, cancels = 0, releases = 0;
  const raw = { closed: terminal.promise, read() { reads++; return readGate.promise; },
    async cancel() { cancels++; await cancelGate.promise; terminal.resolve(); }, releaseLock() { releases++; } };
  const f = await fixture(t, { fetch: () => response({ getReader: () => raw }), release() { readGate.resolve({ done: true }); cancelGate.resolve(); } });
  const h = f.start(); await h.response(); const read = h.read(); await pending(read); assert.equal(reads, 1);
  const done = retire(h); await pending(done); assert.equal(cancels, 1); cancelGate.resolve(); await pending(done);
  readGate.resolve({ done: false, value: Uint8Array.of(7) }); assert.equal((await done).outcome, "ok");
  assert.equal((await read).outcome, "cancelled"); assert.equal(releases, 1); assert.equal(f.live.size, 0);
});
test("a native cancellation callback failure is separate from the cancelled operation", async t => {
  let inspected = 0; const thrown = { get message() { inspected++; throw new Error(); }, toString() { inspected++; throw new Error(); } };
  const b = nativeBody({ cancel() { throw thrown; } }), f = await fixture(t, { fetch: () => response(b.stream) }), h = f.start(); await h.response();
  const result = await retire(h); assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response cancellation failed/);
  assert.equal((await h.closed).outcome, "cancelled"); assert.equal(inspected, 0); assert.equal(b.count.cancels, 1);
});
test("already errored native readers do not fabricate a cleanup failure from their stored error", async t => {
  const b = nativeBody(), f = await fixture(t, { fetch: () => response(b.stream) }), h = f.start(); await h.response();
  b.controller.error(new Error("network source error")); const terminal = await h.closed;
  assert.equal(terminal.outcome, "err"); assert.equal((await retire(h)).outcome, "ok"); assert.equal(b.count.cancels, 0);
});
test("different cancellation and source errors are not conflated", async t => {
  const terminal = deferred(); void terminal.promise.catch(() => {});
  const raw = { closed: terminal.promise, read: async () => ({ done: true }), cancel() { throw new Error("cleanup error"); }, releaseLock() {} };
  const f = await fixture(t, { fetch: () => response({ getReader: () => raw }) }), h = f.start(); await h.response();
  terminal.reject(new Error("source error")); await h.closed;
  assert.equal((await retire(h)).outcome, "err"); assert.match((await retire(h)).failure.message, /response cancellation/);
});
test("abort failure is retained even when stream cleanup succeeds", async t => {
  class BadController extends AbortController { abort() { throw new Error("host abort rejected"); } }
  const b = nativeBody(), f = await fixture(t, { Controller: BadController, fetch: () => response(b.stream) }), h = f.start(); await h.response();
  const result = await retire(h); assert.equal(result.outcome, "err"); assert.match(result.failure.message, /host abort failed/); assert.equal(b.count.cancels, 1);
});
test("an EOF release failure cannot disappear behind a successful later release", async t => {
  let releases = 0; const raw = { closed: Promise.resolve(), read: async () => ({ done: true }), cancel: async () => {},
    releaseLock() { if (++releases === 1) throw new Error("release failed once"); } };
  const f = await fixture(t, { fetch: () => response({ getReader: () => raw }) }), h = f.start();
  assert.equal((await h.read()).outcome, "err"); assert.equal((await retire(h)).outcome, "err");
  assert.match((await retire(h)).failure.message, /reader release/); assert.equal(releases, 2);
});
for (const refuse of [false, true]) test(`late response disposal is joined and classified (${refuse})`, async t => {
  const arrived = deferred(), disposed = deferred(); let cancels = 0;
  const f = await fixture(t, { fetch: () => arrived.promise, release() { arrived.resolve(response(null)); disposed.resolve(); } }), h = f.start();
  const done = retire(h); await pending(done);
  arrived.resolve(response({ cancel() { cancels++; return disposed.promise; } })); await pending(done); assert.equal(cancels, 1);
  if (refuse) disposed.reject(new Error("late disposal")); else disposed.resolve();
  const result = await done; assert.equal(result.outcome, refuse ? "err" : "ok");
  if (refuse) assert.match(result.failure.message, /late response disposal/);
  assert.equal((await h.closed).outcome, "cancelled");
});
for (const refuse of [false, true]) test(`upload source cancellation joins independently and reports rejection (${refuse})`, async t => {
  const gate = deferred(), upload = nativeBody({ cancel: () => gate.promise });
  const f = await fixture(t, { fetch: () => new Response(null), release: gate.resolve }), h = f.start({ method: "POST", body: upload.stream });
  // The early response invokes upload retirement before publishing its head.
  await pending(h.response()); assert.equal(upload.count.cancels, 1);
  const done = retire(h); await pending(done); if (refuse) gate.reject(new Error("upload cleanup failed")); else gate.resolve();
  assert.equal((await done).outcome, refuse ? "err" : "ok"); assert.equal(upload.stream.locked, false);
});
test("an errored upload retains its operation error without inventing a cancel callback failure", async t => {
  const upload = nativeBody(), host = deferred();
  const f = await fixture(t, { fetch: () => host.promise, release: () => host.resolve(new Response(null)) }), h = f.start({ method: "POST", body: upload.stream });
  upload.controller.error(new Error("source upload error")); await h.response(); const done = retire(h); await pending(done);
  host.resolve(new Response(null)); assert.equal((await done).outcome, "ok"); assert.equal((await h.closed).outcome, "err"); assert.equal(upload.count.cancels, 0);
});
test("refused one-way cancellation still drains host work and refuses retirement", async t => {
  const gate = deferred(), b = nativeBody({ cancel: () => gate.promise });
  const f = await fixture(t, { fetch: () => response(b.stream), cancel: () => err("ABI cancel refusal"), release: gate.resolve }), h = f.start(); await h.response();
  const done = retire(h); await pending(done); assert.equal(b.count.cancels, 1); gate.resolve();
  assert.equal((await done).outcome, "err"); assert.match((await done).failure.message, /task cancellation refused/);
});
test("a previously refused ordinary cancel does not prevent a new successful retirement attempt", async t => {
  const b = nativeBody(), f = await fixture(t, { fetch: () => response(b.stream), cancel: (_request, calls) => calls.cancel === 1 ? err("try later") : ok(undefined) });
  const h = f.start(); await h.response(); assert.equal((await h.cancel()).outcome, "err"); assert.equal(b.count.cancels, 0);
  assert.equal((await retire(h)).outcome, "ok"); assert.equal(f.calls.cancel, 2); assert.equal(b.count.cancels, 1);
});
for (const throwJoin of [false, true]) test(`terminal publication ${throwJoin ? "throw" : "refusal"} cannot certify retirement`, async t => {
  const f = await fixture(t, { join() { if (throwJoin) throw new Error("join failed"); return err("join refused"); } }), h = f.start();
  await h.closed; const done = retire(h); const result = await done;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /terminal publication/); assert.equal(f.live.size, 1);
  assert.equal(done, retire(h)); assert.equal(f.calls.join, 1);
  f.manager.closeScopes(new Set([f.scopeKey]), "owner teardown"); assert.equal(await retire(h), result);
});
test("publication refusal retains the existing local admission bound", async t => {
  const f = await fixture(t, { join: () => err("publication refused") });
  for (let i = 0; i < 64; i++) { const h = f.start(); assert.equal((await retire(h)).outcome, "err"); }
  assert.equal(f.live.size, 64); assert.throws(() => f.start()); assert.equal(f.calls.spawn, 64);
});
test("task cancellation and native cleanup reentry see the installed retirement promise", async t => {
  let h, fromTask, fromHost; const b = nativeBody({ cancel() { fromHost = retire(h); } });
  const f = await fixture(t, { fetch: () => response(b.stream), cancel() { fromTask = retire(h); return ok(undefined); } });
  h = f.start(); await h.response(); const done = retire(h); assert.equal(done, fromTask); assert.equal(done, fromHost);
  assert.equal((await done).outcome, "ok"); assert.equal(f.calls.cancel, 1); assert.equal(b.count.cancels, 1);
});
test("retiring one request neither cancels peers nor mutates their parent signal", async t => {
  const bodies = [], parent = new AbortController(); const f = await fixture(t, { fetch() { const b = nativeBody(); bodies.push(b); return response(b.stream); } });
  const a = f.start({ signal: parent.signal }), b = f.start({ signal: parent.signal }); await Promise.all([a.response(), b.response()]);
  assert.equal((await retire(a)).outcome, "ok"); assert.equal(bodies[1].count.cancels, 0); assert.equal(parent.signal.aborted, false);
  await retire(b); assert.equal(f.calls.spawn, 2); assert.equal(f.calls.join, 2);
});
test("real network failure and explicit body retirement keep operation and cleanup outcomes distinct", { timeout: 5000 }, async t => {
  const disconnected = deferred(); const server = createServer((req, res) => {
    if (req.url === "/reset") { req.socket.destroy(); return; }
    req.on("close", disconnected.resolve); res.writeHead(200); res.write("prefix");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`, f = await fixture(t, { origin, fetch });
  const reset = f.start({ url: `${origin}/reset` }); assert.equal((await reset.response()).outcome, "err");
  assert.equal((await retire(reset)).outcome, "ok"); assert.equal((await reset.closed).outcome, "err");
  const stream = f.start(); assert.equal((await stream.response()).outcome, "ok"); assert.equal((await stream.read()).value.done, false);
  const read = stream.read(); await pending(read); assert.equal((await retire(stream)).outcome, "ok");
  assert.equal((await read).outcome, "cancelled"); assert.equal((await stream.closed).outcome, "cancelled");
  await disconnected.promise; assert.equal(f.live.size, 0); assert.equal(f.calls.fetch, 2);
});
