/** Execute the complete fetch manager and race/join modules with native Streams
 * and loopback HTTP. The core task ABI and deliberately gated handles are doubles.
 * Not a Rust/WASM, full-package or cross-browser certification.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_group_retirement.mjs
 * ASUPERSYNC_GROUP_SOURCE selects an unchanged pre-fix source for negative controls.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sources = Object.fromEntries(["fetch", "fetch-combinators"].map(name => [name, readFileSync(
  name === "fetch-combinators" && process.env.ASUPERSYNC_GROUP_SOURCE ? process.env.ASUPERSYNC_GROUP_SOURCE
    : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario: "race-join-retirement", source_sha256: Object.fromEntries(
  Object.entries(sources).map(([name, source]) => [name, createHash("sha256").update(source).digest("hex")])),
  evidence: "actual fetch manager and groups; native Streams/HTTP; explicit core task ABI and gated provider doubles" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const panic = message => ({ outcome: "panicked", message });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed", origin_region: "test",
  origin_task: null, timestamp_nanos: 0, message: "source retired", truncated: false } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) {
  let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn(); assert.equal(settled, false, "cleanup must still be pending at its explicit gate");
}
async function fixture(t, options = {}) {
  let id = 0; const handles = [], groups = [], gates = [], calls = { cancel: [], join: [] };
  const gate = () => { const d = deferred(); gates.push(d); return d; };
  class Handle { constructor(raw) { this.raw = raw; } toJSON() { return { ...this.raw }; } }
  const exports = { Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
    cancelled: cancellation => ({ outcome: "cancelled", cancellation }) }, RegionHandle: Handle,
    taskSpawn: () => ok(new Handle({ kind: "task", slot: ++id, generation: 1 })),
    taskCancel(request) { calls.cancel.push(request.task.toJSON().slot); return options.cancel?.(request) ?? ok(undefined); },
    taskJoin(task, terminal) { calls.join.push(task.toJSON().slot); return options.join?.(task, terminal) ?? terminal; } };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, Request, Blob });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
  const modules = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name,
    new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context })]));
  await modules.fetch.link(name => { assert.equal(name, "@asupersync/browser-core"); return abi; });
  await modules["fetch-combinators"].link(name => { assert.equal(name, "./fetch.js"); return modules.fetch; });
  await modules["fetch-combinators"].evaluate();
  const api = modules["fetch-combinators"].namespace, fetchApi = modules.fetch.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1 }), key = fetchApi.browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: fetchApi.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET"] }) };
  const manager = fetchApi.createBrowserFetchManager({ lookup: k => k === key ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController, fetch: options.fetch ?? (() => new Response(null)) }) });
  const start = path => {
    const result = manager.start(scope, { url: origin + path }, null); assert.equal(result.outcome, "ok");
    handles.push(result.value); return result.value;
  };
  const group = (list, mode = "race", opts) => {
    const result = mode === "race" ? api.raceFetchResponses(list, opts) : api.joinFetchResponses(list, opts);
    assert.equal(result.outcome, "ok"); groups.push(result.value); return result.value;
  };
  t.after(async () => {
    gates.forEach(g => g.resolve(ok(undefined))); options.release?.(); manager.closeScopes(new Set([key]), "test cleanup");
    await Promise.all(groups.map(g => g.cancel())); await Promise.all(handles.map(h => h.closed));
  });
  return { api, start, group, gate, calls };
}
function streamBody(options = {}) {
  let sent = false; const counts = { cancel: 0, pull: 0 };
  const stream = new ReadableStream({ pull(c) {
    counts.pull++; if (!sent) { sent = true; c.enqueue(Uint8Array.of(7)); } else c.close();
  }, cancel() { counts.cancel++; return options.cancel?.(); } }, { highWaterMark: 0 });
  return { stream, counts };
}
function provider(t, options = {}) {
  const terminal = deferred(), head = deferred(); const counts = { native: 0, retire: 0, read: 0, response: 0 };
  const stream = new ReadableStream({ pull(c) { counts.read++; c.close(); }, async cancel() {
    counts.native++; await options.native; terminal.resolve(options.terminal ?? cancelled());
    if (options.nativeRefuses) throw new Error("native refused");
  } }, { highWaterMark: 0 });
  const handle = { closed: terminal.promise, response() { counts.response++; return head.promise; }, toReadableStream: () => ok(stream),
    retire() { assert.equal(this, handle); counts.retire++; return options.retire?.() ?? Promise.resolve(ok(undefined)); } };
  if (options.legacy) delete handle.retire;
  if (!options.park) head.resolve(ok({ status: 200, statusText: "", url: "https://example.test/", headers: [] }));
  t.after(() => terminal.resolve(ok(undefined)));
  return { handle, stream, counts, terminal, head };
}

test("actual manager: loser cleanup refusal cannot publish a healthy race winner", async t => {
  const good = streamBody(), bad = streamBody({ cancel() { throw new Error("cleanup failed"); } });
  const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream) });
  const a = f.start("/good"), b = f.start("/bad"); await Promise.all([a.response(), b.response()]);
  const result = await f.group([a, b]).result;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response cancellation failed/);
  assert.equal((await b.closed).outcome, "cancelled"); assert.equal((await b.retire()).outcome, "err");
  assert.equal(good.counts.cancel, 1); assert.equal(bad.counts.cancel, 1); assert.equal(good.counts.pull + bad.counts.pull, 0);
  assert.equal(f.calls.join.length, 2);
});
for (const mode of ["race", "join"]) {
  test(`actual manager: ${mode} success transfers untouched readable bodies`, async t => {
    const bodies = [streamBody(), streamBody()]; const f = await fixture(t, { fetch: url => new Response(bodies[url.endsWith("/b") ? 1 : 0].stream) });
    const a = f.start("/a"), b = f.start("/b"); await Promise.all([a.response(), b.response()]);
    const g = f.group([a, b], mode), result = await g.result; assert.equal(result.outcome, "ok");
    const winners = mode === "race" ? [result.value] : result.value;
    assert.deepEqual(Array.from(winners, w => w.index), mode === "race" ? [0] : [0, 1]);
    assert.equal(bodies[0].counts.cancel, 0); assert.equal(bodies[1].counts.cancel, mode === "race" ? 1 : 0);
    assert.equal(bodies[0].counts.pull + bodies[1].counts.pull, 0);
    assert.equal((await g.cancel()).outcome, "ok"); assert.equal(bodies[0].counts.cancel, 0);
    for (const winner of winners) assert.equal((await new Response(winner.body).arrayBuffer()).byteLength, 1);
    assert.equal((await a.retire()).outcome, "ok"); assert.equal((await b.retire()).outcome, "ok");
  });
  for (const first of ["native", "retirement"]) test(`${mode} cancellation joins both barriers (${first} first)`, async t => {
    const f = await fixture(t), native = f.gate(), retirement = f.gate();
    const a = provider(t, { park: true, native: native.promise, retire: () => retirement.promise });
    const g = f.group([a.handle], mode), done = g.cancel("owner stopped"); await pending(done);
    assert.equal(a.counts.native, 1); assert.equal(a.counts.retire, 1);
    if (first === "native") native.resolve(); else retirement.resolve(ok(undefined));
    await pending(done); native.resolve(); retirement.resolve(ok(undefined));
    assert.equal((await done).outcome, "cancelled"); assert.equal((await g.result).cancellation.message, "owner stopped");
    assert.equal(a.stream.locked, false); assert.equal(a.counts.read, 0);
  });
  test(`${mode} joins a late retirement panic without losing owner cancellation`, async t => {
    const f = await fixture(t), retirement = f.gate(), a = provider(t, { park: true, terminal: err("weaker"), retire: () => retirement.promise });
    const g = f.group([a.handle], mode), done = g.cancel(); await pending(done); retirement.resolve(panic("retirement panic"));
    assert.equal((await done).outcome, "panicked"); assert.equal((await g.result).message, "retirement panic");
  });
  test(`${mode} pre-aborted signal retires every acquired member without calling responses`, async t => {
    const f = await fixture(t), signal = new AbortController(); signal.abort();
    const a = provider(t, { park: true }), b = provider(t, { park: true });
    const result = await f.group([a.handle, b.handle], mode, { signal: signal.signal }).result;
    assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.kind, `fetch_${mode}_signal`);
    assert.equal(a.counts.response + b.counts.response, 0); assert.equal(a.counts.retire + b.counts.retire, 2);
    assert.equal(a.counts.native + b.counts.native, 2);
  });
  test(`${mode} malformed retirement refuses before body acquisition`, async t => {
    const f = await fixture(t), a = provider(t), b = provider(t); b.handle.retire = 7;
    const result = mode === "race" ? f.api.raceFetchResponses([a.handle, b.handle]) : f.api.joinFetchResponses([a.handle, b.handle]);
    assert.equal(result.outcome, "err"); assert.equal(a.stream.locked, false); assert.equal(b.stream.locked, false);
    assert.equal(a.counts.native + a.counts.retire + b.counts.native + b.counts.retire, 0);
  });
  test(`${mode} preserves legacy handles without retirement`, async t => {
    const f = await fixture(t), a = provider(t, { legacy: true }), b = provider(t, { legacy: true });
    assert.equal((await f.group([a.handle, b.handle], mode).result).outcome, "ok");
    assert.equal(a.counts.native, 0); assert.equal(b.counts.native, mode === "race" ? 1 : 0);
  });
  test(`${mode} operation failure is not suppressed by successful retirement`, async t => {
    const f = await fixture(t), a = provider(t, { park: true }), b = provider(t, { park: true, terminal: err("transport failed") });
    const g = f.group([a.handle, b.handle], mode); b.head.resolve(err("transport failed"));
    const result = await g.result; assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "transport failed");
    assert.equal(a.counts.retire, 1); assert.equal(b.counts.retire, 1);
  });
}
for (const first of ["native", "retirement"]) test(`race ownership transfer waits for both loser barriers (${first} first)`, async t => {
  const f = await fixture(t), native = f.gate(), retirement = f.gate(), a = provider(t);
  const b = provider(t, { native: native.promise, retire: () => retirement.promise });
  const g = f.group([a.handle, b.handle]); await pending(g.result);
  assert.equal(b.counts.native, 1); assert.equal(b.counts.retire, 1); assert.equal(a.counts.retire, 0);
  if (first === "native") native.resolve(); else retirement.resolve(ok(undefined));
  await pending(g.result); native.resolve(); retirement.resolve(ok(undefined));
  assert.equal((await g.result).outcome, "ok"); assert.equal(a.counts.read, 0); assert.equal(a.stream.locked, false);
});
test("retirement failure promptly retires the winner while another loser is still gated", async t => {
  const f = await fixture(t), slow = f.gate(), a = provider(t), b = provider(t, { retire: () => Promise.resolve(err("retirement failure")) });
  const c = provider(t, { native: slow.promise }), g = f.group([a.handle, b.handle, c.handle]); await pending(g.result);
  assert.equal(a.counts.native, 1); assert.equal(a.counts.retire, 1); slow.resolve();
  assert.equal((await g.result).outcome, "err");
});
test("same-member terminal error cannot overwrite an earlier retirement panic", async t => {
  const f = await fixture(t), native = f.gate(), a = provider(t), b = provider(t, {
    native: native.promise, terminal: err("weaker terminal"), retire: () => Promise.resolve(panic("strongest")) });
  const g = f.group([a.handle, b.handle]); await pending(g.result); native.resolve();
  const result = await g.result; assert.equal(result.outcome, "panicked"); assert.equal(result.message, "strongest");
});
for (const value of [undefined, {}, { outcome: "ok", value: 7 }, { outcome: "panicked", message: 7 }]) {
  test(`malformed retirement receipt fails closed: ${JSON.stringify(value)}`, async t => {
    const f = await fixture(t), a = provider(t), b = provider(t, { retire: () => Promise.resolve(value) });
    const result = await f.group([a.handle, b.handle]).result;
    assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure"); assert.equal(a.counts.native, 1);
  });
}
for (const rejection of [false, true]) test(`retirement ${rejection ? "reject" : "throw"} ignores hostile presentation hooks`, async t => {
  let touched = 0; const thrown = { get cause() { touched++; return ok(undefined); }, toString() { touched++; return "secret"; } };
  const f = await fixture(t), a = provider(t), b = provider(t, { retire() { if (rejection) return Promise.reject(thrown); throw thrown; } });
  assert.equal((await f.group([a.handle, b.handle]).result).outcome, "err"); assert.equal(touched, 0);
});
test("retirement-only failures keep input-order ties despite opposite completion order", async t => {
  const f = await fixture(t), late = f.gate(), early = f.gate(), a = provider(t);
  const b = provider(t, { retire: () => late.promise }), c = provider(t, { retire: () => early.promise });
  const g = f.group([a.handle, b.handle, c.handle]); await pending(g.result);
  early.resolve(err("retire c")); await pending(g.result); late.resolve(err("retire b"));
  const result = await g.result; assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "retire b");
});
test("retirement panic message is snapshotted exactly once", async t => {
  let reads = 0; const f = await fixture(t), a = provider(t), b = provider(t, { retire: () => Promise.resolve({ outcome: "panicked",
    get message() { reads++; return reads === 1 ? "first" : 7; } }) });
  const result = await f.group([a.handle, b.handle]).result;
  assert.equal(result.outcome, "panicked"); assert.equal(result.message, "first"); assert.equal(reads, 1);
});
test("retirement method snapshot preserves receiver despite later mutation", async t => {
  const f = await fixture(t), a = provider(t, { park: true }), b = provider(t, { park: true });
  const g = f.group([a.handle, b.handle]); b.handle.retire = () => assert.fail("replacement invoked");
  a.head.resolve(ok({ status: 200, statusText: "", url: "https://example.test/", headers: [] }));
  assert.equal((await g.result).outcome, "ok"); assert.equal(b.counts.retire, 1);
});
test("reentrant retirement and repeated cancellation never duplicate owned cleanup", async t => {
  const f = await fixture(t); let g;
  const a = provider(t), b = provider(t, { retire() { void g.cancel("reentrant"); return Promise.resolve(ok(undefined)); } });
  g = f.group([a.handle, b.handle]); assert.equal((await g.result).outcome, "cancelled");
  await Promise.all([g.cancel(), g.cancel()]);
  assert.equal(a.counts.native, 1); assert.equal(a.counts.retire, 1); assert.equal(b.counts.native, 1); assert.equal(b.counts.retire, 1);
});
test("empty join remains a successful identity with a pre-aborted signal", async t => {
  const f = await fixture(t), signal = new AbortController(); signal.abort();
  const result = await f.group([], "join", { signal: signal.signal }).result;
  assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 0);
});
test("real HTTP race joins loser retirement before transferring a readable winner", { timeout: 5000 }, async t => {
  const closed = deferred(), server = createServer((req, res) => {
    if (req.url === "/winner") res.end("winner");
    else { req.on("close", closed.resolve); res.writeHead(200); res.write("loser prefix"); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const f = await fixture(t, { origin: `http://127.0.0.1:${server.address().port}`, fetch });
  const a = f.start("/winner"), b = f.start("/loser"); await Promise.all([a.response(), b.response()]);
  const result = await f.group([a, b]).result; assert.equal(result.outcome, "ok");
  assert.equal(await new Response(result.value.body).text(), "winner"); await closed.promise;
  assert.equal((await b.retire()).outcome, "ok"); assert.equal((await b.closed).outcome, "cancelled");
});
