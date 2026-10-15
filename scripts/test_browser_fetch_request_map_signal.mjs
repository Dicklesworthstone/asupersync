/** Actual mapping driver, native Streams/signals; explicit producer receipts.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_request_map_signal.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_REQUEST_MAP_SOURCE
  ?? new URL("../packages/browser/src/fetch-request-map.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "parent-owned-request-mapping", sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "actual mapper; native Streams/signals/fetch; explicit producer receipts; no SDK task ABI" }));
async function load(globals = {}) {
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
    context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, AbortSignal, EventTarget, ...globals }),
  });
  await module.link(() => assert.fail("unexpected runtime dependency")); await module.evaluate(); return module.namespace;
}
const api = await load();
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "retirement", phase: "completed",
  origin_region: "source-owner", origin_task: null, timestamp_nanos: 0, message: "source retired", truncated: false } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
const names = ["mapFetchRequests", "tryMapFetchRequests", "flatMapFetchRequests", "tryFlatMapFetchRequests"];
function valueFor(name, index) {
  const value = name.toLowerCase().includes("flat") ? [{ url: `${index}` }] : { url: `${index}` };
  return name.startsWith("try") ? ok(value) : value;
}
function fixture(t, options = {}) {
  const gates = [], handles = [], readers = [], calls = { input: 0, native: 0, owner: 0, mapped: [] };
  const terminal = deferred(); let pos = 0;
  const input = new ReadableStream({
    pull(c) { calls.input++; if (options.park) return; if (pos < (options.count ?? 8)) c.enqueue(pos++); else { c.close(); if (!options.holdTerminal) terminal.resolve(ok(undefined)); } },
    async cancel() { calls.native++; await options.native?.promise; },
  }, { highWaterMark: 0 });
  const owner = { readable: input, closed: terminal.promise, async cancel() {
    assert.equal(this, owner); calls.owner++; await options.owner?.promise;
    if (!options.holdTerminal) terminal.resolve(cancelled()); return ok(undefined);
  } };
  function gate() { const g = deferred(); gates.push(g); return g; }
  function start(name, mapper, config, library = api, selected = owner) {
    const result = library[name](selected, (value, i, signal) => { calls.mapped.push(i); return mapper(value, i, signal); }, config);
    assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value;
  }
  function read(h) { const r = h.readable.getReader(); readers.push(r); const next = r.read(); void next.catch(() => {}); return { r, next }; }
  t.after(async () => {
    gates.forEach(g => g.resolve()); options.native?.resolve(); options.owner?.resolve(); terminal.resolve(ok(undefined));
    await Promise.all(handles.map(h => h.cancel("fixture cleanup")));
    readers.forEach(r => { try { r.releaseLock(); } catch {} });
  });
  return { input, owner, terminal, calls, start, gate, read };
}
for (const name of names) {
  test(`${name}: pre-aborted parent retires owned input without reading or mapping`, async t => {
    const f = fixture(t), parent = new AbortController(); parent.abort();
    const h = f.start(name, () => assert.fail("mapper must not run"), { concurrency: 4, signal: parent.signal });
    await turn(); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1); assert.equal(f.calls.input, 0);
    const result = await h.closed; assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.message, "request mapping cancelled by signal");
    assert.equal(f.input.locked, false);
  });
  test(`${name}: parent abort joins every parallel mapper and producer cleanup`, async t => {
    const native = deferred(), owner = deferred(), f = fixture(t, { native, owner, holdTerminal: true });
    const parent = new AbortController(), gates = [f.gate(), f.gate(), f.gate()], signals = [];
    const h = f.start(name, async (_v, i, signal) => { signals.push(signal); await gates[i].promise; return valueFor(name, i); }, { concurrency: 3, signal: parent.signal });
    const { next } = f.read(h); await turn(); assert.equal(signals.length, 3); parent.abort();
    assert.ok(signals.every(signal => signal.aborted)); await pending(h.closed); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
    gates[0].resolve(); gates[2].resolve(); native.resolve(); owner.resolve(); f.terminal.resolve(cancelled()); await pending(h.closed);
    gates[1].resolve(); assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next);
    assert.equal(f.calls.mapped.length, 3); assert.equal(f.input.locked, false);
  });
}
test("idle parent abort needs no output demand", async t => {
  const f = fixture(t), parent = new AbortController(); const h = f.start("mapFetchRequests", () => null, { signal: parent.signal });
  parent.abort(); await turn(); assert.equal(f.calls.owner, 1); assert.equal(f.calls.input, 0);
  assert.equal((await h.closed).outcome, "cancelled");
});
test("parent abort retires a never-producing native input", async t => {
  const f = fixture(t, { park: true }), parent = new AbortController();
  const h = f.start("mapFetchRequests", () => assert.fail("no input"), { signal: parent.signal, concurrency: 4 }); const { next } = f.read(h);
  await turn(); assert.equal(f.calls.input, 1); parent.abort(); await turn(); assert.equal(f.calls.native, 1);
  assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next);
});
test("parent remains observed during producer retirement after native EOF", async t => {
  const f = fixture(t, { count: 0, holdTerminal: true }), parent = new AbortController();
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }); const { next } = f.read(h);
  await pending(next); parent.abort(); await pending(h.closed); assert.equal(f.calls.owner, 1);
  f.terminal.resolve(cancelled()); assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next);
});
test("parent abort inside a mapper fences its returned request", async t => {
  const f = fixture(t), parent = new AbortController();
  const h = f.start("mapFetchRequests", () => { parent.abort(); return { url: "not emitted" }; }, { signal: parent.signal, concurrency: 4 });
  const { next } = f.read(h); await turn(); assert.equal(f.calls.owner, 1);
  assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next); assert.deepEqual(f.calls.mapped, [0]);
});
test("parent abort during source property snapshot is observed before a read", async t => {
  const f = fixture(t), parent = new AbortController();
  const wrapped = { get readable() { parent.abort(); return f.input; }, closed: f.owner.closed, cancel: () => f.owner.cancel() };
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }, api, wrapped);
  await turn(); assert.equal(f.calls.owner, 1); assert.equal(f.calls.input, 0); assert.equal((await h.closed).outcome, "cancelled");
});
test("earlier stopImmediatePropagation listener cannot suppress mapping cancellation", async t => {
  const f = fixture(t), parent = new AbortController(); parent.signal.addEventListener("abort", event => event.stopImmediatePropagation());
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }); parent.abort();
  await turn(); assert.equal(f.calls.owner, 1); assert.equal((await h.closed).outcome, "cancelled");
});
test("arbitrary abort reasons and parent listener overrides are never invoked", async t => {
  const f = fixture(t), parent = new AbortController(); let touched = 0;
  parent.signal.addEventListener = () => { touched++; throw 1; };
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal });
  parent.abort({ get cause() { touched++; throw 1; }, toString() { touched++; throw 1; } });
  await turn(); assert.equal(f.calls.owner, 1); assert.equal((await h.closed).outcome, "cancelled"); assert.equal(touched, 0);
});
for (const cause of ["err", "panicked"]) {
  test(`late typed ${cause} after parent abort retains severity`, async t => {
    const f = fixture(t), parent = new AbortController(), gates = [f.gate(), f.gate()];
    const h = f.start("tryMapFetchRequests", async (_v, i) => { await gates[i].promise; return i ? cause === "err" ? err("late") : { outcome: "panicked", message: "late" } : ok(null); }, { signal: parent.signal, concurrency: 2 });
    const { next } = f.read(h); await turn(); assert.equal(f.calls.mapped.length, 2); parent.abort(); await pending(h.closed);
    gates.forEach(g => g.resolve()); assert.equal((await h.closed).outcome, cause === "err" ? "cancelled" : "panicked"); await assert.rejects(next);
  });
}
for (const first of ["manual", "parent"]) {
  test(`${first} stop keeps first equal-severity cancellation cause`, async t => {
    const f = fixture(t), parent = new AbortController(); const gate = f.gate();
    const h = f.start("mapFetchRequests", async () => { await gate.promise; return null; }, { signal: parent.signal }); const { next } = f.read(h);
    await turn(); if (first === "manual") { void h.cancel("manual first"); parent.abort(); } else { parent.abort(); void h.cancel("manual later"); }
    gate.resolve(); const result = await h.closed;
    assert.equal(result.cancellation.message, first === "manual" ? "manual first" : "request mapping cancelled by signal"); await assert.rejects(next);
  });
}
for (const ending of ["success", "cancel", "failure"]) {
  test(`parent observer is detached at ${ending} settlement`, async t => {
    let dependent;
    const tracked = await load({ AbortSignal: { prototype: AbortSignal.prototype, any(signals) { dependent = AbortSignal.any(signals); return dependent; } } });
    const f = fixture(t, { count: 1 }), parent = new AbortController();
    const h = f.start("tryMapFetchRequests", () => ending === "failure" ? err("failed") : ok(null), { signal: parent.signal }, tracked);
    assert.equal(getEventListeners(dependent, "abort").length, 1);
    if (ending === "cancel") await h.cancel(); else { const { next } = f.read(h); if (ending === "success") await next; else await assert.rejects(next); }
    await h.closed; assert.equal(getEventListeners(dependent, "abort").length, 0);
    assert.equal(parent.signal.aborted, false); const before = f.calls.owner; parent.abort(); await turn(); assert.equal(f.calls.owner, before);
  });
}
test("unsupported hosts refuse signal use but preserve unsignalled operation", async t => {
  const restricted = await load({ AbortSignal: undefined, EventTarget: undefined }), f = fixture(t, { count: 0 });
  assert.equal(restricted.mapFetchRequests(f.owner, () => null, { signal: new AbortController().signal }).outcome, "err");
  assert.equal(f.input.locked, false); assert.equal(f.calls.owner, 0);
  const h = f.start("mapFetchRequests", () => null, { signal: null }, restricted); assert.equal((await f.read(h).next).done, true);
});
test("customized and fake signals refuse without invoking accessors or acquiring input", async t => {
  const f = fixture(t), parent = new AbortController(); let touched = 0;
  const fake = { get aborted() { touched++; throw 1; } };
  Object.defineProperty(parent.signal, "reason", { get() { touched++; throw 1; } });
  for (const signal of [fake, parent.signal, {}, 7]) assert.equal(api.mapFetchRequests(f.owner, () => null, { signal }).outcome, "err");
  assert.equal(touched, 0); assert.equal(f.input.locked, false); assert.equal(f.calls.native, 0);
});
test("pre-aborted parent leaves invalid or locked source ownership untouched", async t => {
  const f = fixture(t), parent = new AbortController(); parent.abort(); const held = f.input.getReader();
  assert.equal(api.mapFetchRequests(f.owner, () => null, { signal: parent.signal }).outcome, "err"); held.releaseLock();
  assert.equal(api.mapFetchRequests(f.owner, null, { signal: parent.signal }).outcome, "err");
  await turn(); assert.equal(f.calls.owner, 0); assert.equal(f.calls.native, 0);
});
test("refused signal observation disables installed source observers and releases ownership", async t => {
  const broken = await load({ EventTarget: { prototype: { addEventListener() { throw new Error("installation refused"); }, removeEventListener() {} } } });
  const f = fixture(t, { holdTerminal: true });
  const admitted = broken.mapFetchRequests(f.owner, () => null, { signal: new AbortController().signal });
  assert.equal(admitted.outcome, "err"); assert.equal(f.input.locked, false);
  f.terminal.resolve(err("later source failure")); await turn(); assert.equal(f.calls.native, 0); assert.equal(f.calls.owner, 0);
});
test("real HTTP parent cancellation reaches parallel mapper fetches and joins their settlement", { timeout: 5000 }, async t => {
  const seen = [], disconnected = [], retirement = deferred();
  const server = createServer((request, response) => {
    seen.push(request.url); response.writeHead(200); response.write("prefix");
    request.on("close", () => { disconnected.push(request.url); if (disconnected.length === 3) retirement.resolve(); });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const f = fixture(t), parent = new AbortController(), started = [], finished = [];
  const h = f.start("mapFetchRequests", async (_v, i, signal) => {
    try {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/${i}`, { signal }); started.push(i);
      try { await response.text(); } catch (error) { signal.throwIfAborted(); throw error; }
      return { url: `${i}` };
    } finally { finished.push(i); }
  }, { concurrency: 3, signal: parent.signal });
  t.after(async () => { void h.cancel(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const { next } = f.read(h); const deadline = Date.now() + 1500;
  while (started.length < 3 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(started.length, 3); parent.abort(); await turn(); assert.equal(f.calls.owner, 1);
  assert.equal((await h.closed).outcome, "cancelled"); assert.deepEqual(finished.sort(), [0, 1, 2]); await assert.rejects(next);
  await retirement.promise; assert.equal(disconnected.length, 3); assert.equal(seen.length, 3);
});
