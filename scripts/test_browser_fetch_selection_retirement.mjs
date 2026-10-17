/** Actual fetch manager plus selection, native Streams/fetch; core task ABI is
 * explicitly doubled. Not Rust/WASM or full SDK integration certification.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_selection_retirement.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const sources = Object.fromEntries(["fetch", "fetch-selection"].map(name => [name, readFileSync(
  name === "fetch-selection" && process.env.ASUPERSYNC_SELECTION_SOURCE ? process.env.ASUPERSYNC_SELECTION_SOURCE
    : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario: "selection-joined-retirement", source_sha256: Object.fromEntries(
  Object.entries(sources).map(([name, source]) => [name, createHash("sha256").update(source).digest("hex")])),
  evidence: "actual fetch/selection; native Streams/HTTP; explicit core task ABI and gated handle doubles" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const panic = message => ({ outcome: "panicked", message });
const cancel = () => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed", origin_region: "test",
  origin_task: null, timestamp_nanos: 0, message: "source retired", truncated: false } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; }); await turn(); assert.equal(settled, false); }
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
  const abi = new SyntheticModule(Object.keys(exports), function () { for (const [key, value] of Object.entries(exports)) this.setExport(key, value); }, { context });
  const modules = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context })]));
  await modules.fetch.link(name => { assert.equal(name, "@asupersync/browser-core"); return abi; });
  await modules["fetch-selection"].link(() => assert.fail("selection added runtime dependency"));
  await modules.fetch.evaluate(); await modules["fetch-selection"].evaluate();
  const api = modules["fetch-selection"].namespace, fetchApi = modules.fetch.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1 }), key = fetchApi.browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: fetchApi.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET"] }) };
  const manager = fetchApi.createBrowserFetchManager({ lookup: k => k === key ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController, fetch: options.fetch ?? (() => new Response(null)) }) });
  const start = path => { const result = manager.start(scope, { url: origin + path }, null); assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value; };
  const select = (list, required = 1, first = false, opts) => {
    const result = first ? api.firstAcceptableFetchResponse(list, opts) : api.quorumFetchResponses(list, required, opts);
    assert.equal(result.outcome, "ok"); groups.push(result.value); return result.value;
  };
  t.after(async () => { gates.forEach(g => g.resolve(ok(undefined))); options.release?.();
    manager.closeScopes(new Set([key]), "test cleanup"); await Promise.all(groups.map(g => g.cancel())); await Promise.all(handles.map(h => h.closed)); });
  return { api, start, select, gate, calls };
}
function streamBody(options = {}) {
  let controller, sent = false; const counts = { cancel: 0, pull: 0 };
  const stream = new ReadableStream({ start(c) { controller = c; }, pull(c) { counts.pull++;
    if (!sent) { sent = true; c.enqueue(Uint8Array.of(7)); } else c.close(); },
    cancel() { counts.cancel++; return options.cancel?.(); } }, { highWaterMark: 0 });
  return { stream, counts, get controller() { return controller; } };
}
function fake(t, options = {}) {
  const terminal = deferred(), head = deferred(); const counts = { native: 0, retire: 0, read: 0 };
  const stream = new ReadableStream({ pull(c) { counts.read++; c.close(); }, async cancel() {
    counts.native++; await options.native;
    terminal.resolve(options.terminal ?? cancel());
    if (options.nativeRefuses) throw new Error("native refused");
  } }, { highWaterMark: 0 });
  const handle = { closed: terminal.promise, response: () => head.promise, toReadableStream: () => ok(stream),
    retire() { assert.equal(this, handle); counts.retire++; return options.retire?.() ?? Promise.resolve(ok(undefined)); } };
  if (options.legacy) delete handle.retire;
  if (!options.park) head.resolve(ok({ status: options.status ?? 200, statusText: "", url: "https://example.test/", headers: [] }));
  t.after(() => terminal.resolve(ok(undefined)));
  return { handle, stream, counts, terminal, head };
}
for (const first of [false, true]) {
  test(`actual loser cleanup failure cannot publish a healthy winner (${first})`, async t => {
    const good = streamBody(), bad = streamBody({ cancel() { throw new Error("cleanup failed"); } });
    const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream) });
    const winner = f.start("/good"), loser = f.start("/bad"); await Promise.all([winner.response(), loser.response()]);
    const result = await f.select([winner, loser], 1, first).result;
    assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response cancellation failed/);
    assert.equal(good.counts.pull + bad.counts.pull, 0); assert.equal(good.counts.cancel, 1); assert.equal(bad.counts.cancel, 1);
    assert.equal((await loser.closed).outcome, "cancelled");
  });
  test(`actual successful loser retirement leaves winner readable and untouched (${first})`, async t => {
    const good = streamBody(), bad = streamBody(); const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream) });
    const winner = f.start("/good"), loser = f.start("/bad"); await Promise.all([winner.response(), loser.response()]);
    const result = await f.select([winner, loser], 1, first).result; assert.equal(result.outcome, "ok");
    const selected = first ? result.value : result.value[0]; assert.equal(selected.fetch, winner); assert.equal(good.counts.cancel, 0);
    assert.equal(bad.counts.cancel, 1); assert.equal(good.counts.pull, 0); assert.equal((await new Response(selected.body).arrayBuffer()).byteLength, 1);
    assert.equal((await loser.retire()).outcome, "ok");
  });
  test(`actual loser publication refusal keeps its own cause over its retirement receipt (${first})`, async t => {
    const good = streamBody(), bad = streamBody();
    const f = await fixture(t, { fetch: url => new Response(url.endsWith("/bad") ? bad.stream : good.stream),
      join: (task, terminal) => task.toJSON().slot === 2 ? err("publication refused") : terminal });
    const winner = f.start("/good"), loser = f.start("/bad"); await Promise.all([winner.response(), loser.response()]);
    const result = await f.select([winner, loser], 1, first).result;
    assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "publication refused");
    assert.equal((await loser.closed).failure.message, "publication refused");
    assert.match((await loser.retire()).failure.message, /terminal publication/);
  });
}
test("independent retirement and native cancellation both start and both gate success", async t => {
  const f = await fixture(t), native = f.gate(), retirement = f.gate();
  const a = fake(t), b = fake(t, { native: native.promise, retire: () => retirement.promise });
  const group = f.select([a.handle, b.handle]); await pending(group.result);
  assert.equal(b.counts.native, 1); assert.equal(b.counts.retire, 1); assert.equal(a.counts.retire, 0);
  native.resolve(); await pending(group.result); retirement.resolve(ok(undefined)); assert.equal((await group.result).outcome, "ok");
  assert.equal(a.counts.read, 0);
});
test("retirement-only failures keep input-order ties despite opposite completion order", async t => {
  const f = await fixture(t), late = f.gate(), early = f.gate(), a = fake(t);
  const b = fake(t, { retire: () => late.promise }), c = fake(t, { retire: () => early.promise });
  const group = f.select([a.handle, b.handle, c.handle]); await pending(group.result);
  early.resolve(err("retire c")); await pending(group.result); late.resolve(err("retire b"));
  const result = await group.result; assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "retire b");
});
test("retirement failure promptly retires a proposed winner while another loser remains gated", async t => {
  const f = await fixture(t), slow = f.gate(), a = fake(t), b = fake(t, { retire: () => Promise.resolve(err("retirement failure")) }), c = fake(t, { native: slow.promise });
  const group = f.select([a.handle, b.handle, c.handle]); await pending(group.result);
  assert.equal(a.counts.native, 1); assert.equal(a.counts.retire, 1); slow.resolve(); assert.equal((await group.result).outcome, "err");
});
for (const returned of [undefined, {}, { outcome: "ok", value: 7 }, { outcome: "panicked", message: 7 }]) {
  test(`invalid retirement receipt ${JSON.stringify(returned)} is not successful cleanup`, async t => {
    const f = await fixture(t), a = fake(t), b = fake(t, { retire: () => Promise.resolve(returned) });
    const result = await f.select([a.handle, b.handle]).result; assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
    assert.equal(a.counts.native, 1);
  });
}
for (const rejected of [false, true]) test(`retirement ${rejected ? "reject" : "throw"} never inspects arbitrary exception hooks`, async t => {
  let touched = 0; const thrown = { get cause() { touched++; return ok(undefined); }, toString() { touched++; return "private"; } };
  const f = await fixture(t), a = fake(t), b = fake(t, { retire() { if (rejected) return Promise.reject(thrown); throw thrown; } });
  const result = await f.select([a.handle, b.handle]).result; assert.equal(result.outcome, "err"); assert.equal(touched, 0);
});
test("late retirement panic outranks owner cancellation and weaker same-member terminal error", async t => {
  const f = await fixture(t), gate = f.gate(), a = fake(t, { park: true, terminal: err("weaker terminal"), retire: () => gate.promise });
  const group = f.select([a.handle]); const done = group.cancel(); await pending(done); gate.resolve(panic("retirement panic"));
  assert.equal((await done).outcome, "panicked"); assert.equal((await group.result).message, "retirement panic");
});
test("retirement panic message is copied once before it is retained", async t => {
  let reads = 0; const f = await fixture(t), a = fake(t), b = fake(t, { retire: () => Promise.resolve({ outcome: "panicked",
    get message() { reads++; return reads === 1 ? "first" : 7; } }) });
  const result = await f.select([a.handle, b.handle]).result; assert.equal(result.outcome, "panicked"); assert.equal(result.message, "first"); assert.equal(reads, 1);
});
test("retirement methods retain their original receiver after source mutation", async t => {
  const f = await fixture(t), a = fake(t, { park: true }), b = fake(t, { park: true });
  const group = f.select([a.handle, b.handle]); b.handle.retire = () => assert.fail("replacement invoked");
  a.head.resolve(ok({ status: 200, statusText: "", url: "https://example.test/", headers: [] }));
  assert.equal((await group.result).outcome, "ok"); assert.equal(b.counts.retire, 1);
});
test("invalid optional retirement method refuses setup before acquiring any body", async t => {
  const f = await fixture(t), a = fake(t), b = fake(t); b.handle.retire = 7;
  assert.equal(f.api.quorumFetchResponses([a.handle, b.handle], 1).outcome, "err");
  assert.equal(a.stream.locked, false); assert.equal(a.counts.native + a.counts.retire, 0);
});
test("legacy handles without retire preserve selection behavior", async t => {
  const f = await fixture(t), a = fake(t, { legacy: true }), b = fake(t, { legacy: true });
  assert.equal((await f.select([a.handle, b.handle]).result).outcome, "ok"); assert.equal(b.counts.native, 1);
});
test("reentrant retirement sees the installed drain and cannot repeat cancellation", async t => {
  const f = await fixture(t); let group;
  const a = fake(t), b = fake(t, { retire() { void group.cancel("reentrant"); return Promise.resolve(ok(undefined)); } });
  group = f.select([a.handle, b.handle]); assert.equal((await group.result).outcome, "cancelled");
  assert.equal(a.counts.native, 1); assert.equal(b.counts.native, 1); assert.equal(a.counts.retire, 1); assert.equal(b.counts.retire, 1);
});
test("successful retirement never suppresses an operation transport failure", async t => {
  const good = streamBody(); const f = await fixture(t, { fetch: url => { if (url.endsWith("/bad")) throw new Error("transport refused"); return new Response(good.stream); } });
  const a = f.start("/good"), b = f.start("/bad"); const result = await f.select([a, b]).result;
  assert.equal(result.outcome, "err"); assert.equal((await b.retire()).outcome, "ok"); assert.equal(good.counts.cancel, 1);
});
test("real HTTP selection drains non-selected native fetches before transferring the winner", { timeout: 5000 }, async t => {
  const closed = deferred(), server = createServer((req, res) => { if (req.url === "/winner") res.end("winner");
    else { req.on("close", closed.resolve); res.writeHead(200); res.write("loser prefix"); } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const f = await fixture(t, { origin: `http://127.0.0.1:${server.address().port}`, fetch });
  const a = f.start("/winner"), b = f.start("/loser"); await Promise.all([a.response(), b.response()]);
  const result = await f.select([a, b]).result; assert.equal(result.outcome, "ok"); assert.equal(await new Response(result.value[0].body).text(), "winner");
  await closed.promise; assert.equal((await b.retire()).outcome, "ok"); assert.equal((await b.closed).outcome, "cancelled");
});
