/** Actual batch, fetch manager, parsers and pipeline composition. Native Streams
 * and loopback HTTP execute; the core task ABI and gated handles are doubles.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_batch_retirement.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test as nodeTest } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const test = (name, fn) => nodeTest(name, { timeout: 5000 }, fn);
const names = ["fetch", "fetch-batch", "fetch-records", "fetch-events", "fetch-request-map"];
const sources = Object.fromEntries(names.map(name => [name, readFileSync(name === "fetch-batch" && process.env.ASUPERSYNC_FETCH_BATCH_SOURCE
  ? process.env.ASUPERSYNC_FETCH_BATCH_SOURCE : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario: "batch-fetch-retirement", evidence: "actual batch/fetch/record/pipeline modules; native Streams/HTTP; task ABI double",
  sha256: Object.fromEntries(names.map(name => [name, createHash("sha256").update(sources[name]).digest("hex")])) }));
const ok = value => ({ outcome: "ok", value });
const err = (message = "retirement refused") => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed", origin_region: "batch-source", origin_task: null,
  timestamp_nanos: 0, message: "source cancelled", truncated: false } });
const panic = (message = "retirement panicked") => ({ outcome: "panicked", message });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
const variants = ["mapFetches", "tryMapFetches", "streamMapFetches", "tryStreamMapFetches"];
async function fixture(t, options = {}) {
  const calls = { admitted: 0, cancel: 0, join: 0, retired: 0 }, live = new Set(), handles = [], batches = [], gates = [];
  let sequence = 0;
  class Handle { constructor(raw) { this.raw = raw; } toJSON() { return { ...this.raw }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }), cancelled: value => ({ outcome: "cancelled", cancellation: value }) },
    RegionHandle: Handle,
    taskSpawn() { calls.admitted++; live.add(++sequence); return ok(new Handle({ kind: "task", slot: sequence, generation: 1 })); },
    taskCancel() { calls.cancel++; return ok(undefined); },
    taskJoin(task, outcome) { calls.join++; live.delete(task.toJSON().slot); return outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortController, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, TextDecoder, Request, Blob });
  const abi = new SyntheticModule(Object.keys(exports), function () { for (const [key, value] of Object.entries(exports)) this.setExport(key, value); }, { context });
  const modules = Object.fromEntries(names.map(name => [name, new SourceTextModule(stripTypeScriptTypes(sources[name], { mode: "transform" }), { context, identifier: name })]));
  for (const module of Object.values(modules)) if (module.status === "unlinked") await module.link(name => name === "@asupersync/browser-core" ? abi : modules[name.slice(2, -3)]);
  for (const module of Object.values(modules)) await module.evaluate();
  const api = modules["fetch-batch"].namespace, fetchApi = modules.fetch.namespace, events = modules["fetch-events"].namespace, pipeline = modules["fetch-request-map"].namespace;
  const root = new Handle({ kind: "region", slot: 1, generation: 1 }), scopeKey = fetchApi.browserFetchHandleKey(root.toJSON()), origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: fetchApi.prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET"] }) };
  const manager = fetchApi.createBrowserFetchManager({ lookup: key => key === scopeKey ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController, fetch: options.fetch ?? (() => new Response(null)) }) });
  const scope = { fetch(request) {
    const started = manager.start(root, request, null); if (started.outcome !== "ok") return started;
    handles.push(started.value); const raw = started.value;
    return ok({ ...raw, retire(reason) { calls.retired++; return raw.retire(reason); } });
  } };
  const gate = () => { const g = deferred(); gates.push(g); return g; };
  function start(name, requests = [{ url: `${origin}/one` }], consume = () => 42, config = {}, suppliedScope = scope) {
    const admitted = api[name](suppliedScope, requests, name.startsWith("try") ? async item => ok(await consume(item)) : consume, config);
    assert.equal(admitted.outcome, "ok"); const handle = admitted.value; batches.push(handle);
    const values = [];
    const terminal = handle.results ? (async () => {
      try { for await (const item of handle.results) values.push(item); } catch { /* Inspect the independent typed receipt. */ }
      return handle.closed;
    })() : handle.result;
    return { handle, terminal, values };
  }
  t.after(async () => { gates.forEach(g => g.resolve(ok(undefined))); options.release?.(); manager.closeScopes(new Set([scopeKey]), "fixture cleanup");
    await Promise.all(batches.map(b => b.cancel())); await Promise.all(handles.map(h => h.closed)); });
  return { api, events, pipeline, scope, start, gate, calls, live, batches, origin };
}
function member(f, options = {}) {
  const terminal = f.gate(), calls = { native: 0, cancel: 0, retire: 0, convert: 0 };
  const body = new ReadableStream({ cancel() { calls.native++; if (!options.holdTerminal) terminal.resolve(options.terminal ?? cancelled()); return options.nativeGate?.promise; } }, { highWaterMark: 0 });
  const handle = { closed: terminal.promise, response: async () => ok({ status: 200, statusText: "OK", url: "https://example.test", headers: [] }),
    toReadableStream() { calls.convert++; return options.conversion ?? ok(body); },
    async cancel() { calls.cancel++; if (!body.locked) await body.cancel(); return terminal.promise; },
    retire() { assert.equal(this, handle); calls.retire++; return options.retire?.() ?? Promise.resolve(ok(undefined)); },
  };
  return { handle, body, terminal, calls };
}
for (const name of variants) {
  test(`${name}: actual rejected host cleanup fences queued admission and prevents success`, async t => {
    let cancelledBodies = 0;
    const f = await fixture(t, { fetch: () => new Response(new ReadableStream({ cancel() { cancelledBodies++; throw new Error("host cleanup rejected"); } }, { highWaterMark: 0 })) });
    const b = f.start(name, [{ url: `${f.origin}/one` }, { url: `${f.origin}/never` }], () => "not published", { concurrency: 1 });
    const result = await b.terminal; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response cancellation failed/);
    assert.equal(f.calls.admitted, 1); assert.equal(f.calls.retired, 1); assert.equal(cancelledBodies, 1); assert.equal(f.live.size, 0); assert.deepEqual(b.values, []);
  });
  test(`${name}: worker credit and result publication wait for independent retirement`, async t => {
    const f = await fixture(t), retired = f.gate(), a = member(f, { retire: () => retired.promise }), b = member(f); let admissions = 0;
    const scope = { fetch() { return ok(admissions++ === 0 ? a.handle : b.handle); } };
    const batch = f.start(name, [{ url: "a" }, { url: "b" }], () => 7, { concurrency: 1 }, scope);
    await pending(batch.terminal); assert.equal(a.calls.retire, 1); assert.equal(admissions, 1); assert.deepEqual(batch.values, []);
    retired.resolve(ok(undefined)); assert.equal((await batch.terminal).outcome, "ok"); assert.equal(admissions, 2); assert.equal(b.calls.retire, 1);
  });
}
test("native cancellation, operation terminal and retirement are distinct joined barriers", async t => {
  const f = await fixture(t), native = f.gate(), retired = f.gate(), a = member(f, { nativeGate: native, holdTerminal: true, retire: () => retired.promise });
  const b = f.start("mapFetches", undefined, () => 3, {}, { fetch: () => ok(a.handle) }); await pending(b.terminal);
  assert.equal(a.calls.native, 1); assert.equal(a.calls.retire, 1); retired.resolve(ok(undefined)); await pending(b.terminal);
  native.resolve(); await pending(b.terminal); a.terminal.resolve(cancelled()); assert.equal((await b.terminal).outcome, "ok");
});
test("retirement failure immediately cancels a peer's independently parked consumer", async t => {
  const f = await fixture(t), retired = f.gate(), consumer = f.gate(), entered = f.gate(), a = member(f, { retire: () => retired.promise }), b = member(f); let admissions = 0, peerSignal;
  const batch = f.start("mapFetches", [{ url: "a" }, { url: "b" }, { url: "never" }], async item => {
    if (item.index === 1) { peerSignal = item.signal; entered.resolve(); await consumer.promise; } return item.index;
  }, { concurrency: 2 }, { fetch: () => ok(admissions++ === 0 ? a.handle : b.handle) });
  await entered.promise; retired.resolve(panic()); await pending(batch.terminal); assert.equal(peerSignal.aborted, true); assert.equal(admissions, 2);
  consumer.resolve(); assert.equal((await batch.terminal).outcome, "panicked"); assert.equal(b.calls.retire, 1);
});
test("a malformed method fails closed but still retires the already-admitted handle", async t => {
  for (const invalid of [null, 1, {}]) {
    const f = await fixture(t), a = member(f); a.handle.retire = invalid;
    const b = f.start("mapFetches", undefined, () => assert.fail("consumer must not run"), {}, { fetch: () => ok(a.handle) });
    assert.equal((await b.terminal).outcome, "err"); assert.equal(a.calls.cancel, 1); assert.equal(a.calls.native, 1); assert.equal(a.calls.convert, 0);
  }
});
test("throwing retire getter does not orphan an admitted handle", async t => {
  const f = await fixture(t), a = member(f); let inspected = 0;
  Object.defineProperty(a.handle, "retire", { get() { throw { toString() { inspected++; return "secret"; } }; } });
  const b = f.start("mapFetches", undefined, () => assert.fail("no consumer"), {}, { fetch: () => ok(a.handle) });
  assert.equal((await b.terminal).outcome, "err"); assert.equal(a.calls.cancel, 1); assert.equal(inspected, 0);
});
for (const invalid of [undefined, {}, { outcome: "ok", value: "not void" }, { outcome: "panicked", message: 4 }]) {
  test(`retirement receipt ${JSON.stringify(invalid)} is not successful cleanup`, async t => {
    const f = await fixture(t), a = member(f, { retire: () => Promise.resolve(invalid) });
    const b = f.start("mapFetches", undefined, undefined, {}, { fetch: () => ok(a.handle) }); assert.equal((await b.terminal).outcome, "err");
  });
}
test("retirement rejection is sanitized without inspecting an exception cause", async t => {
  const f = await fixture(t); let inspected = 0;
  const a = member(f, { retire() { throw { get cause() { inspected++; return ok(undefined); }, toString() { inspected++; return "secret"; } }; } });
  const b = f.start("mapFetches", undefined, undefined, {}, { fetch: () => ok(a.handle) }); assert.equal((await b.terminal).outcome, "err"); assert.equal(inspected, 0);
});
test("captured retirement methods preserve receivers and run once after consumer mutation", async t => {
  const f = await fixture(t), a = member(f); const b = f.start("mapFetches", undefined, () => { a.handle.retire = () => assert.fail("mutated callback"); return 1; }, {}, { fetch: () => ok(a.handle) });
  assert.equal((await b.terminal).outcome, "ok"); assert.equal(a.calls.retire, 1);
});
test("late handles from refused asynchronous admission still join independent retirement", async t => {
  const f = await fixture(t), admission = f.gate(), retired = f.gate(), a = member(f, { retire: () => retired.promise });
  const b = f.start("mapFetches", undefined, () => assert.fail("refused scope"), {}, { fetch: () => admission.promise });
  await pending(b.terminal); admission.resolve(ok(a.handle)); await pending(b.terminal); assert.equal(a.calls.retire, 1); assert.equal(a.calls.cancel, 1);
  retired.resolve(panic("late adopted panic")); const result = await b.terminal; assert.equal(result.outcome, "panicked"); assert.equal(result.message, "late adopted panic");
});
test("conversion refusal still joins the captured retirement callback", async t => {
  const f = await fixture(t), retired = f.gate(), a = member(f, { conversion: err("conversion refused"), retire: () => retired.promise });
  const b = f.start("mapFetches", undefined, () => assert.fail("no converted body"), {}, { fetch: () => ok(a.handle) });
  await pending(b.terminal); assert.equal(a.calls.retire, 1); assert.equal(a.calls.cancel, 1);
  retired.resolve(ok(undefined)); assert.equal((await b.terminal).outcome, "err");
});
test("a late retirement panic is not hidden by manual batch cancellation", async t => {
  const f = await fixture(t), retired = f.gate(), a = member(f, { retire: () => retired.promise });
  const b = f.start("mapFetches", undefined, undefined, {}, { fetch: () => ok(a.handle) }); await pending(b.terminal); void b.handle.cancel();
  retired.resolve(panic()); assert.equal((await b.terminal).outcome, "panicked");
});
test("successful retirement never suppresses an independently failed operation", async t => {
  const f = await fixture(t), a = member(f); a.terminal.resolve(err("transport failed"));
  const b = f.start("mapFetches", undefined, undefined, {}, { fetch: () => ok(a.handle) });
  const result = await b.terminal; assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "transport failed"); assert.equal(a.calls.retire, 1);
});
test("stronger retirement survives a weaker operation receipt and snapshots fields once", async t => {
  const f = await fixture(t); let tags = 0, messages = 0;
  const a = member(f, { terminal: err("operation error"), retire: () => Promise.resolve({ get outcome() { tags++; return "panicked"; }, get message() { messages++; return "snapshot"; } }) });
  const b = f.start("mapFetches", undefined, undefined, {}, { fetch: () => ok(a.handle) });
  assert.equal((await b.terminal).message, "snapshot"); assert.equal(tags, 1); assert.equal(messages, 1);
});
test("legacy handles without independent retirement retain existing behavior", async t => {
  const f = await fixture(t), a = member(f); a.handle.retire = undefined;
  const b = f.start("mapFetches", undefined, () => 9, {}, { fetch: () => ok(a.handle) });
  assert.equal((await b.terminal).outcome, "ok"); assert.equal((await b.terminal).value[0], 9); assert.equal(a.calls.native, 1);
});
test("merged real NDJSON feeds and child fetches drain through the complete actual pipeline", async t => {
  const allChildren = deferred(), disconnected = new Set(), allDisconnected = deferred(), seen = [], responses = new Map();
  const server = createServer((req, res) => {
    seen.push(req.url); req.on("close", () => { disconnected.add(req.url); if (["/feed-a", "/feed-b", "/child-b"].every(p => disconnected.has(p))) allDisconnected.resolve(); });
    if (req.url.startsWith("/feed")) { res.writeHead(200, { "content-type": "application/x-ndjson" }); res.write(JSON.stringify({ path: req.url.replace("feed", "child") }) + "\n"); }
    else { responses.set(req.url, res); if (responses.size === 2) { allChildren.resolve(); responses.get("/child-a").end("accepted"); responses.get("/child-b").write("unfinished"); } }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`, f = await fixture(t, { origin, fetch });
  const owners = [];
  for (const suffix of ["a", "b"]) {
    const raw = f.scope.fetch({ url: `${origin}/feed-${suffix}` }); assert.equal(raw.outcome, "ok");
    const records = f.events.jsonLines(raw.value); assert.equal(records.outcome, "ok");
    const mapped = f.pipeline.mapFetchRequests(records.value, row => ({ url: origin + row.value.path })); assert.equal(mapped.outcome, "ok"); owners.push(mapped.value);
  }
  const merged = f.pipeline.mergeFetchRequestSources(owners); assert.equal(merged.outcome, "ok");
  const admitted = f.api.streamMapFetches(f.scope, merged.value, async ({ body }) => new Response(body).text(), { concurrency: 2 });
  assert.equal(admitted.outcome, "ok"); f.batches.push(admitted.value);
  for await (const item of admitted.value.results) { assert.equal(item.value, "accepted"); await allChildren.promise; break; }
  assert.equal((await admitted.value.closed).outcome, "cancelled"); assert.equal((await merged.value.closed).outcome, "cancelled");
  assert.equal(f.calls.retired, 4); assert.equal(f.live.size, 0); await allDisconnected.promise;
  assert.deepEqual([...seen].sort(), ["/child-a", "/child-b", "/feed-a", "/feed-b"]);
});
