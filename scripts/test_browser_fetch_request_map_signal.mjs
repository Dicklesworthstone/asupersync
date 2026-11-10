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
for (const name of names) {
  test(`${name}: ready skipped inputs yield to host cancellation before EOF`, async t => {
    const yielding = await load({ setTimeout, clearTimeout });
    const f = fixture(t, { count: 1024 }), parent = new AbortController();
    const skipped = name.toLowerCase().includes("flat") ? [] : null;
    const h = f.start(name, () => name.startsWith("try") ? ok(skipped) : skipped,
      { concurrency: 4, signal: parent.signal }, yielding);
    const abort = setTimeout(() => parent.abort(), 0);
    t.after(() => clearTimeout(abort));
    const { next } = f.read(h);
    assert.equal((await h.closed).outcome, "cancelled");
    await assert.rejects(next);
    assert.ok(f.calls.mapped.length > 0 && f.calls.mapped.length < 1024);
    assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
    assert.equal(f.input.locked, false);
  });
}
for (const name of ["mapFetchRequests", "flatMapFetchRequests"]) {
  test(`${name}: eager output demand cannot reset the host cancellation budget`, { timeout: 5000 }, async t => {
    const yielding = await load({ setTimeout, clearTimeout }), expanded = name === "flatMapFetchRequests";
    const f = fixture(t, { count: expanded ? 1 : 1024 }), parent = new AbortController();
    const h = f.start(name, (_value, index) => expanded
      ? Array.from({ length: 1024 }, () => ({ url: "expanded" })) : { url: String(index) },
    { maxRequestsPerInput: 1024, signal: parent.signal }, yielding);
    const abort = setTimeout(() => parent.abort(), 0); t.after(() => clearTimeout(abort));
    const { r, next } = f.read(h); let delivered = 0;
    const consume = (async () => {
      let item = await next;
      while (!item.done) { delivered++; item = await r.read(); }
    })();
    void consume.catch(() => {});
    assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(consume);
    assert.ok(delivered > 0 && delivered < 1024);
    assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
    assert.equal(f.input.locked, false);
  });
}
test("ready mapping resumes through bounded host timers and retires every timer at EOF", { timeout: 5000 }, async t => {
  const live = new Set(); let scheduled = 0, peak = 0;
  const yielding = await load({
    setTimeout(callback, delay) {
      const token = setTimeout(() => { live.delete(token); callback(); }, delay);
      live.add(token); scheduled++; peak = Math.max(peak, live.size); return token;
    },
    clearTimeout(token) { live.delete(token); clearTimeout(token); },
  });
  const f = fixture(t, { count: 512 });
  const h = f.start("mapFetchRequests", () => null, { concurrency: 4 }, yielding);
  assert.equal((await f.read(h).next).done, true);
  assert.equal((await h.closed).outcome, "ok");
  assert.ok(scheduled > 1); assert.equal(peak, 1); assert.equal(live.size, 0);
  assert.equal(f.calls.mapped.length, 512); assert.equal(f.calls.owner, 0); assert.equal(f.calls.native, 0);
  assert.equal(f.input.locked, false);
});
for (const mode of ["parent", "caller"]) {
  test(`${mode} cancellation clears a parked host timer and joins producer retirement`, { timeout: 5000 }, async t => {
    const scheduled = deferred(), live = new Set(); let cleared = 0;
    const paused = await load({
      setTimeout(callback) { const token = { callback }; live.add(token); scheduled.resolve(token); return token; },
      clearTimeout(token) { assert.equal(live.delete(token), true); cleared++; },
    });
    const native = deferred(), owner = deferred(), parent = new AbortController();
    const f = fixture(t, { count: 1024, native, owner, holdTerminal: true });
    const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }, paused);
    const { next } = f.read(h), token = await scheduled.promise, mapped = f.calls.mapped.length;
    assert.ok(mapped > 0 && mapped < 1024); assert.equal(live.size, 1);
    const stopping = mode === "caller" ? h.cancel("cancel parked host turn") : (parent.abort(), h.closed);
    assert.equal(cleared, 1); assert.equal(live.size, 0); await pending(h.closed);
    assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
    native.resolve(); owner.resolve(); await pending(h.closed);
    f.terminal.resolve(cancelled()); assert.equal((await stopping).outcome, "cancelled"); await assert.rejects(next);
    assert.equal(f.input.locked, false);
    token.callback(); await turn(); assert.equal(f.calls.mapped.length, mapped);
  });
}
test("producer failure while yielding clears the host timer and preserves its failure", { timeout: 5000 }, async t => {
  const scheduled = deferred(); let cleared = 0;
  const paused = await load({
    setTimeout(callback) { scheduled.resolve(callback); return 1; },
    clearTimeout() { cleared++; },
  });
  const f = fixture(t, { count: 1024, holdTerminal: true });
  const h = f.start("mapFetchRequests", () => null, {}, paused), { next } = f.read(h);
  const callback = await scheduled.promise, mapped = f.calls.mapped.length;
  f.terminal.resolve(err("producer failed during host yield"));
  const receipt = await h.closed; assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.message, "producer failed during host yield"); await assert.rejects(next);
  assert.equal(cleared, 1); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
  assert.equal(f.input.locked, false);
  callback(); await turn(); assert.equal(f.calls.mapped.length, mapped);
});
test("host scheduling refusal settles owned cleanup without admitting more inputs", { timeout: 5000 }, async t => {
  const refused = await load({
    setTimeout() { throw new Error("host scheduling refused"); },
    clearTimeout() { assert.fail("no timer was admitted"); },
  });
  const f = fixture(t, { count: 1024 });
  const h = f.start("mapFetchRequests", () => null, {}, refused), { next } = f.read(h);
  const receipt = await h.closed; assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.code, "compatibility_rejected");
  assert.equal(receipt.failure.message, "request mapping host scheduling failed"); await assert.rejects(next);
  assert.ok(f.calls.mapped.length > 0 && f.calls.mapped.length < 1024);
  assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1); assert.equal(f.input.locked, false);
});
test("host timer cleanup refusal cannot strand a cancelled pull or revive input", { timeout: 5000 }, async t => {
  const scheduled = deferred(); let cleared = 0;
  const paused = await load({
    setTimeout(callback) { scheduled.resolve(callback); return 1; },
    clearTimeout() { cleared++; throw new Error("host cleanup refused"); },
  });
  const parent = new AbortController(), f = fixture(t, { count: 1024 });
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }, paused), { next } = f.read(h);
  const callback = await scheduled.promise, mapped = f.calls.mapped.length; parent.abort();
  const receipt = await h.closed; assert.equal(receipt.outcome, "cancelled"); await assert.rejects(next);
  assert.equal(receipt.cancellation.message, "request mapping cancelled by signal");
  assert.equal(cleared, 1); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
  assert.equal(f.input.locked, false);
  callback(); await turn(); assert.equal(f.calls.mapped.length, mapped);
});
test("abort during host scheduling retires the returned timer before publishing cancellation", { timeout: 5000 }, async t => {
  const parent = new AbortController(); let cleared = 0;
  const reentrant = await load({
    setTimeout() { parent.abort(); return 1; },
    clearTimeout(token) { assert.equal(token, 1); cleared++; },
  });
  const f = fixture(t, { count: 1024 });
  const h = f.start("mapFetchRequests", () => null, { signal: parent.signal }, reentrant), { next } = f.read(h);
  assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next);
  assert.equal(cleared, 1); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
  assert.ok(f.calls.mapped.length > 0 && f.calls.mapped.length < 1024); assert.equal(f.input.locked, false);
});
test("timer-free embedders preserve ready-input mapping", async t => {
  const f = fixture(t, { count: 256 }), h = f.start("mapFetchRequests", () => null, {});
  assert.equal((await f.read(h).next).done, true); assert.equal((await h.closed).outcome, "ok");
  assert.equal(f.calls.mapped.length, 256); assert.equal(f.input.locked, false);
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
