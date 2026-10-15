/** Actual fetch manager, record parsers and native Streams. Only the task ABI
 * and deliberately gated third-party handles are doubles; not Rust/WASM proof.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_record_retirement.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test as nodeTest } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const test = (name, fn) => nodeTest(name, { timeout: 5000 }, fn);
const names = ["fetch", "fetch-records", "fetch-events", "fetch-request-map"];
const sources = Object.fromEntries(names.map(name => [name, readFileSync(
  name === "fetch-records" && process.env.ASUPERSYNC_FETCH_RECORD_SOURCE
    ? process.env.ASUPERSYNC_FETCH_RECORD_SOURCE
    : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario: "record-fetch-retirement", evidence: "actual fetch/record/pipeline modules; native Streams/HTTP; task ABI double",
  sha256: Object.fromEntries(names.map(name => [name, createHash("sha256").update(sources[name]).digest("hex")])) }));
const ok = value => ({ outcome: "ok", value });
const err = (message = "cleanup refused") => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed", origin_region: "record-owner",
  origin_task: null, timestamp_nanos: 0, message: "source cancelled", truncated: false } });
const panicked = () => ({ outcome: "panicked", message: "cleanup panicked" });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn(); assert.equal(settled, false, "cleanup must remain joined"); }
const text = new TextEncoder();
const formats = [
  { name: "SSE", method: "serverSentEvents", mime: "text/event-stream", wire: "data: first\n\ndata: second\n\n" },
  { name: "NDJSON", method: "jsonLines", mime: "application/x-ndjson", wire: '{"value":1}\n{"value":2}\n' },
];
async function fixture(t, format, options = {}) {
  const calls = { spawn: 0, join: 0, cancel: 0, hostCancel: 0, fetch: 0 }, live = new Set(), handles = [], records = [], gates = [];
  let sequence = 0;
  class Handle { constructor(value) { this.value = value; } toJSON() { return { ...this.value }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }), cancelled: value => ({ outcome: "cancelled", cancellation: value }) },
    RegionHandle: Handle,
    taskSpawn() { calls.spawn++; live.add(++sequence); return ok(new Handle({ kind: "task", slot: sequence, generation: 1 })); },
    taskCancel() { calls.cancel++; return ok(undefined); },
    taskJoin(task, outcome) { calls.join++; live.delete(task.toJSON().slot); return outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortController, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, TextDecoder, Request, Blob });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
  const modules = Object.fromEntries(names.map(name => [name, new SourceTextModule(stripTypeScriptTypes(sources[name], { mode: "transform" }), { context, identifier: name })]));
  for (const module of Object.values(modules)) if (module.status === "unlinked") await module.link(name =>
    name === "@asupersync/browser-core" ? abi : modules[name.slice(2, -3)]);
  for (const module of Object.values(modules)) await module.evaluate();
  const api = modules["fetch-events"].namespace, fetchApi = modules.fetch.namespace, pipeline = modules["fetch-request-map"].namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1 }), scopeKey = fetchApi.browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: fetchApi.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET"] }) };
  const manager = fetchApi.createBrowserFetchManager({ lookup: key => key === scopeKey ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController, fetch(url, init) {
      calls.fetch++;
      if (options.fetch) return options.fetch(url, init);
      let sent = false;
      return new Response(new ReadableStream({ pull(c) {
        if (!sent) { sent = true; c.enqueue(text.encode(options.wire ?? format.wire)); }
        else if (options.eof) c.close();
      }, cancel() { calls.hostCancel++; return options.hostCancel?.(); } }, { highWaterMark: 0 }), { headers: { "content-type": format.mime } });
    } }) });
  const gate = () => { const g = deferred(); gates.push(g); return g; };
  function start() { const admitted = manager.start(scope, { url: `${origin}/feed` }, null); assert.equal(admitted.outcome, "ok"); handles.push(admitted.value); return admitted.value; }
  function decode(handle = start(), config) { const admitted = api[format.method](handle, config); assert.equal(admitted.outcome, "ok");
    records.push(admitted.value); t.after(() => admitted.value.cancel()); return admitted.value; }
  t.after(async () => { gates.forEach(g => g.resolve(ok(undefined))); options.release?.();
    manager.closeScopes(new Set([scopeKey]), "fixture cleanup"); await Promise.all(handles.map(h => h.closed)); });
  return { api, pipeline, calls, live, gate, start, decode };
}
function owned(t, format, options = {}) {
  const calls = { native: 0, retire: 0, convert: 0, reads: 0 }, terminal = deferred(), gates = [], handles = [];
  const gate = () => { const g = deferred(); gates.push(g); return g; };
  let sent = false, controller;
  const body = new ReadableStream({ start(c) { controller = c; }, pull(c) {
    calls.reads++;
    if (options.park) return;
    if (!sent) { sent = true; c.enqueue(text.encode(options.wire ?? format.wire)); }
    else { c.close(); if (!options.holdTerminal) terminal.resolve(ok(undefined)); }
  }, async cancel() { calls.native++; await options.nativeGate?.promise; if (!options.holdTerminal) terminal.resolve(cancelled()); } }, { highWaterMark: 0 });
  const handle = { closed: terminal.promise, response: async () => ok({ status: 200, statusText: "OK", url: "https://example.test/", headers: [["content-type", format.mime]] }),
    toReadableStream() { calls.convert++; return ok(body); },
    retire() { assert.equal(this, handle); calls.retire++; return options.retire?.() ?? Promise.resolve(ok(undefined)); },
  };
  t.after(async () => { gates.forEach(g => g.resolve(ok(undefined))); options.nativeGate?.resolve(); terminal.resolve(ok(undefined));
    await Promise.all(handles.map(h => h.cancel())); if (!body.locked) { try { await body.cancel(); } catch {} } });
  return { handle, body, controller, terminal, gate, calls, handles };
}
for (const format of formats) {
  test(`${format.name}: actual host cleanup refusal is not reported as ordinary cancellation`, async t => {
    let touched = 0;
    const f = await fixture(t, format, { hostCancel() { throw { toString() { touched++; return "secret"; } }; } });
    const h = f.start(); await h.response(); const records = f.decode(h);
    const terminal = await records.cancel(); assert.equal(terminal.outcome, "err"); assert.match(terminal.failure.message, /response cancellation failed/);
    assert.equal((await h.closed).outcome, "cancelled"); assert.equal(f.calls.hostCancel, 1); assert.equal(touched, 0); assert.equal(f.live.size, 0);
  });
  test(`${format.name}: iterator exit reports actual cleanup refusal after an emitted record`, async t => {
    const f = await fixture(t, format, { hostCancel() { throw new Error("cleanup rejected"); } }); const records = f.decode();
    await assert.rejects((async () => { for await (const record of records.readable) { assert.ok(record); break; } })());
    assert.equal((await records.closed).outcome, "err"); assert.equal(f.calls.hostCancel, 1);
  });
  test(`${format.name}: independent native cancellation, terminal and retirement gates are all joined`, async t => {
    const native = deferred(), retired = deferred(); t.after(() => retired.resolve(ok(undefined)));
    const f = await fixture(t, format), source = owned(t, format, { park: true, holdTerminal: true, nativeGate: native, retire: () => retired.promise });
    const records = f.decode(source.handle); source.handles.push(records);
    const stop = records.cancel(); assert.equal(stop, records.cancel()); await pending(stop);
    assert.equal(source.calls.native, 1); assert.equal(source.calls.retire, 1);
    native.resolve(); await pending(stop); source.terminal.resolve(cancelled()); await pending(stop);
    retired.resolve(ok(undefined)); assert.equal((await stop).outcome, "cancelled"); assert.equal(source.body.locked, false);
  });
  test(`${format.name}: clean EOF joins retirement without erasing unread records`, async t => {
    const retired = deferred(); t.after(() => retired.resolve(ok(undefined)));
    const f = await fixture(t, format), source = owned(t, format, { retire: () => retired.promise });
    source.terminal.resolve(ok(undefined)); const records = f.decode(source.handle); source.handles.push(records);
    await turn(); assert.equal(source.calls.retire, 0); const r = records.readable.getReader(); t.after(() => r.releaseLock());
    assert.equal((await r.read()).done, false); assert.equal((await r.read()).done, false); assert.equal(source.calls.retire, 0);
    const end = r.read(); await pending(end); assert.equal(source.calls.retire, 1); await pending(records.closed);
    retired.resolve(ok(undefined)); assert.equal((await end).done, true); assert.equal((await records.closed).outcome, "ok"); assert.equal(source.calls.native, 0);
  });
}
test("NDJSON final unterminated value is withheld until independent EOF retirement succeeds", async t => {
  const retired = deferred(); t.after(() => retired.resolve(ok(undefined)));
  const format = formats[1], f = await fixture(t, format), source = owned(t, format, { wire: '{"tail":1}', retire: () => retired.promise });
  const records = f.decode(source.handle, { allowFinalRecord: true }); source.handles.push(records);
  const r = records.readable.getReader(); t.after(() => r.releaseLock()); const tail = r.read(); await pending(tail);
  assert.equal(source.calls.retire, 1); retired.resolve(ok(undefined)); assert.equal((await tail).value.value.tail, 1); assert.equal((await r.read()).done, true);
});
for (const failure of [err, cancelled, panicked]) {
  test(`successful parsing cannot publish EOF after ${failure.name} retirement`, async t => {
    const format = formats[1], f = await fixture(t, format), source = owned(t, format, { wire: "", retire: () => Promise.resolve(failure()) });
    const records = f.decode(source.handle); source.handles.push(records);
    await assert.rejects((async () => { for await (const _ of records.readable) {} })());
    assert.equal((await records.closed).outcome, failure().outcome); assert.equal(source.calls.retire, 1);
  });
}
for (const failure of [cancelled, panicked]) {
  test(`an independently observed source ${failure.name} is not weakened by a retirement error`, async t => {
    const format = formats[0], f = await fixture(t, format), source = owned(t, format, { holdTerminal: true, retire: () => Promise.resolve(err()) });
    const records = f.decode(source.handle); source.handles.push(records); source.terminal.resolve(failure());
    assert.equal((await records.closed).outcome, failure().outcome); assert.equal(source.calls.retire, 1);
  });
}
test("clean retirement preserves the actual NDJSON decode failure and never converts it to cancellation", async t => {
  const f = await fixture(t, formats[1], { wire: "bad JSON\n" }), h = f.start(), records = f.decode(h);
  await assert.rejects((async () => { for await (const _ of records.readable) {} })());
  assert.equal((await records.closed).failure.code, "decode_failure"); assert.equal((await h.closed).outcome, "cancelled");
});
test("a late retirement panic strengthens a parse failure while native cleanup is pending", async t => {
  const native = deferred(), format = formats[1], f = await fixture(t, format);
  const source = owned(t, format, { wire: "bad JSON\n", nativeGate: native, retire: () => Promise.resolve(panicked()) });
  const records = f.decode(source.handle); source.handles.push(records); const r = records.readable.getReader(); t.after(() => r.releaseLock());
  const read = r.read(); void read.catch(() => {}); await pending(records.closed); native.resolve();
  assert.equal((await records.closed).outcome, "panicked"); await assert.rejects(read);
});
for (const bad of [null, 3, {}]) test(`invalid optional retire method ${JSON.stringify(bad)} refuses before body conversion`, async t => {
  const format = formats[0], f = await fixture(t, format), source = owned(t, format); source.handle.retire = bad;
  assert.equal(f.api.serverSentEvents(source.handle).outcome, "err"); assert.equal(source.calls.convert, 0);
  assert.equal(source.body.locked, false); assert.equal(source.calls.native, 0);
});
for (const bad of [undefined, {}, { outcome: "ok", value: "not void" }, { outcome: "panicked", message: 7 }]) {
  test(`malformed retirement receipt ${JSON.stringify(bad)} cannot certify cleanup`, async t => {
    const format = formats[0], f = await fixture(t, format), source = owned(t, format, { retire: () => Promise.resolve(bad) });
    const records = f.decode(source.handle); source.handles.push(records);
    assert.equal((await records.cancel()).outcome, "err"); assert.equal(source.calls.retire, 1);
  });
}
test("retirement method preserves its receiver and is snapshotted before acquiring the body", async t => {
  const format = formats[0], f = await fixture(t, format), source = owned(t, format); const method = source.handle.retire; let accesses = 0;
  Object.defineProperty(source.handle, "retire", { configurable: true, get() { accesses++; assert.equal(source.body.locked, false); return method; } });
  const records = f.decode(source.handle); source.handles.push(records);
  Object.defineProperty(source.handle, "retire", { value: () => assert.fail("replacement invoked") });
  await records.cancel(); assert.equal(accesses, 1); assert.equal(source.calls.retire, 1);
});
test("reentrant retirement shares record cancellation without duplicate invocation", async t => {
  const format = formats[0], f = await fixture(t, format); let records, reentered;
  const source = owned(t, format, { retire() { reentered = records.cancel(); return Promise.resolve(ok(undefined)); } });
  records = f.decode(source.handle); source.handles.push(records); const first = records.cancel();
  await first; assert.equal(first, reentered); assert.equal(source.calls.retire, 1);
});
test("retirement outcome fields are read once and copied before later mutation", async t => {
  const format = formats[0], f = await fixture(t, format); let tags = 0, messages = 0;
  const source = owned(t, format, { retire: () => Promise.resolve({ get outcome() { tags++; return "panicked"; }, get message() { messages++; return "snapshot"; } }) });
  const records = f.decode(source.handle); source.handles.push(records); const result = await records.cancel();
  assert.equal(result.message, "snapshot"); assert.equal(tags, 1); assert.equal(messages, 1); assert.equal(Object.isFrozen(result), true);
});
test("thrown retirement payloads cannot forge typed outcomes or run presentation hooks", async t => {
  const format = formats[0], f = await fixture(t, format); let touched = 0;
  const source = owned(t, format, { retire() { throw { get cause() { touched++; return ok(undefined); }, toString() { touched++; return "secret"; } }; } });
  const records = f.decode(source.handle); source.handles.push(records); assert.equal((await records.cancel()).outcome, "err"); assert.equal(touched, 0);
});
test("legacy handles without retire retain their original cancellation and EOF contracts", async t => {
  const format = formats[1], f = await fixture(t, format), source = owned(t, format); source.handle.retire = undefined;
  const records = f.decode(source.handle); source.handles.push(records); const rows = [];
  for await (const row of records.readable) rows.push(row.value.value);
  assert.deepEqual(rows, [1, 2]); assert.equal((await records.closed).outcome, "ok");
});
test("a real NDJSON connection is retired through parsing and mapping on iterator exit", async t => {
  const disconnected = deferred(); const seen = [];
  const server = createServer((req, res) => { seen.push(req.url); req.on("close", disconnected.resolve);
    res.writeHead(200, { "content-type": "application/x-ndjson" }); res.write('{"id":"one"}\n'); });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`, f = await fixture(t, formats[1], { origin, fetch });
  const raw = f.start(); let retirementCalls = 0;
  const records = f.decode({ ...raw, retire(reason) { retirementCalls++; return raw.retire(reason); } });
  const mapped = f.pipeline.mapFetchRequests(records, row => ({ url: `${origin}/${row.value.id}` })); assert.equal(mapped.outcome, "ok");
  t.after(() => mapped.value.cancel());
  for await (const descriptor of mapped.value.readable) { assert.equal(descriptor.url, `${origin}/one`); break; }
  assert.equal((await records.closed).outcome, "cancelled"); assert.equal((await mapped.value.closed).outcome, "cancelled");
  assert.equal(retirementCalls, 1); assert.equal(f.live.size, 0); await disconnected.promise; assert.deepEqual(seen, ["/feed"]);
});
